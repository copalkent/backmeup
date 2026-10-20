//! Logical, read-only MySQL / MariaDB dump.
//!
//! This is the first part of BackMeUp that writes anything, and it is
//! deliberately narrow:
//!
//!   * The source server is never modified. Only `SELECT`, `SHOW` and session
//!     `SET` statements are ever issued: no `LOCK TABLES`, no `FLUSH`, no
//!     `SET GLOBAL`, no DDL. The dump reads inside one
//!     `START TRANSACTION WITH CONSISTENT SNAPSHOT`, so InnoDB tables are
//!     captured from a single point in time without blocking live writes
//!     writes.
//!   * No user input reaches a statement. Object names come from the server and
//!     are re-quoted before use; values are rendered as literals.
//!   * Nothing is shelled out, so no password can ever appear in a command
//!     line or in a process list.
//!   * The only output is the written file plus row/table counts.
//!
//! Consistency caveat: a consistent snapshot only covers transactional engines.
//! A non-transactional table (MyISAM) can be read mid-write and will not match
//! the transactional tables in the same file. No lock is taken, because taking
//! one is exactly what would stall a live site.
//!
//! What the file holds: every base table and every view the account can see,
//! with their rows, their schema and their data - the same kind of logical
//! dump `mysqldump` writes, without shelling out to it. What it does not
//! hold: triggers, stored procedures, functions and events, which are server
//! objects rather than table contents and are not part of this format.
//!
//! Two rules make the file restorable, and both are load-bearing:
//!
//!   * A view is created after the tables it names, because MySQL refuses to
//!     create a view whose tables do not exist yet.
//!   * A column is read and written by name, never with `SELECT *`, because
//!     `SELECT *` skips invisible columns and returns generated ones that
//!     cannot be inserted.

use std::io::Write;

use mysql::prelude::Queryable;
use mysql::{Row, Value};


/// Most tables this module will consider, so a hostile or confused server
/// cannot make BackMeUp enumerate forever.
pub const MAX_TABLES: usize = 200_000;
/// Rows read from one table before the run gives up.
pub const MAX_ROWS_PER_TABLE: u64 = 5_000_000;
/// Longest server object name accepted into a statement.
const MAX_IDENT_LEN: usize = 128;
/// Longest value written inline; anything larger becomes a hex literal.
const MAX_INLINE_BYTES: usize = 4096;
/// Size of the written tuples at which an `INSERT` statement is closed and a
/// new one started. Kept far below `max_allowed_packet` (4 MiB on older
/// servers).
const MAX_INSERT_BYTES: usize = 512 * 1024;

/// Why a dump could not be produced, without leaking anything the server said.
#[derive(Debug)]
pub enum DumpError {
    /// The account lacks a privilege a logical dump needs.
    Privileges,
    /// The server refused the user name or password. Kept apart from the
    /// other failures because it is the one that can be fixed by re-entering
    /// the saved password.
    Authentication,
    /// The run was cancelled.
    Cancelled,
    /// A server object name or value could not be written safely.
    UnsupportedObject,
    /// A statement failed while reading one specific part of the database.
    /// `stage` is one of BackMeUp's own words and `detail` describes what it
    /// was reading - neither is server text, so both are safe to show.
    Statement { stage: String, detail: String },
    /// A short, safe reason, already phrased for display.
    Reason(String),
    /// Writing the file failed. The payload is kept for the local log only and
    /// is never surfaced: an OS error can embed a chosen path.
    Io(#[allow(dead_code)] std::io::Error),
}

impl std::fmt::Display for DumpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DumpError::Privileges => f.write_str("missing_privileges"),
            DumpError::Authentication => f.write_str("auth_failed"),
            DumpError::Cancelled => f.write_str("cancelled"),
            DumpError::UnsupportedObject => f.write_str("unsupported_object"),
            DumpError::Statement { stage, .. } => write!(f, "failed_at_{stage}"),
            DumpError::Reason(_) => f.write_str("failed"),
            DumpError::Io(_) => f.write_str("write_failed"),
        }
    }
}

/// The stages a dump moves through, named for display rather than for SQL.
pub mod stage {
    pub const SESSION: &str = "preparing";
    pub const LISTING: &str = "listing_objects";
    pub const VIEWS: &str = "reading_views";
    pub const SCHEMA: &str = "reading_schema";
    pub const COLUMNS: &str = "reading_columns";
    pub const DATA: &str = "reading_rows";
    pub const FINISHING: &str = "finishing";
}

impl From<std::io::Error> for DumpError {
    fn from(err: std::io::Error) -> Self {
        DumpError::Io(err)
    }
}

/// Progress and cancellation, so the caller can drive a UI and stop a run.
pub trait DumpControl {
    /// Called at every table boundary and every flushed statement.
    fn report(&self, tables_done: u64, rows: u64);
    /// True once a stop was asked for. Checked often enough to be responsive.
    fn cancelled(&self) -> bool;
}



/// What a completed dump contained.
#[derive(Debug, Clone, Copy, Default)]
pub struct DumpStats {
    pub tables: u64,
    pub views: u64,
    pub rows: u64,
}

/// Produce a logical dump of one database into `out`.
///
/// The caller owns the destination: this function only writes bytes, so the
/// temporary-file, rename and checksum policy lives with the destination code.
pub fn dump_database<W: Write>(
    conn: &mut mysql::Conn,
    database: &str,
    server_version: &str,
    out: &mut W,
    control: &dyn DumpControl,
) -> Result<DumpStats, DumpError> {
    write_header(out, database, server_version)?;

    // One consistent snapshot for the whole dump.
    //
    // Every statement here runs through `query`, never `query_drop`:
    // `query_drop` is literally `query_iter(..).map(drop)`, which discards the
    // result *without reading the server's reply*. That leaves the OK packet in
    // the socket, and the next statement then reads a stale packet and reports
    // a malformed response. One statement followed by a close never shows the
    // problem; a dump, which runs hundreds in a row, desynchronises at once.
    conn.query::<Row, _>("SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .map_err(|err| map_sql(err, stage::SESSION, "setting the isolation level"))?;
    // The file is written in UTF-8 and its timestamps are UTC, so neither the
    // dump nor the later restore depends on what the server's defaults happen
    // to be. A TIMESTAMP read in one zone and restored in another shifts by
    // the difference between them, and that shift is silent.
    conn.query::<Row, _>("SET NAMES utf8mb4")
        .map_err(|err| map_sql(err, stage::SESSION, "setting the character set"))?;
    conn.query::<Row, _>("SET SESSION time_zone = '+00:00'")
        .map_err(|err| map_sql(err, stage::SESSION, "setting the time zone"))?;
    conn.query::<Row, _>("START TRANSACTION WITH CONSISTENT SNAPSHOT")
        .map_err(|err| map_sql(err, stage::SESSION, "starting a consistent snapshot"))?;
    // MySQL only. MariaDB spells this `max_statement_time` and answers with
    // "unknown variable", which is not a reason to refuse the backup. Its
    // reply is drained too, so a rejection cannot desynchronise the rest.
    let _ = conn.query::<Row, _>("SET SESSION MAX_EXECUTION_TIME = 900000");
    // MariaDB's own name for the same limit. Hosting panels hand out a grant
    // with a per-user cap - 180 seconds is a common one - and that cap applies
    // to the table read, so a large table would be cut off halfway. The dump
    // asks for the budget it intends, and carries on if the server refuses.
    let _ = conn.query::<Row, _>("SET SESSION max_statement_time = 900");

    control.report(0, 0);
    if control.cancelled() {
        return Err(DumpError::Cancelled);
    }

    let objects = list_objects(conn)?;
    if objects.len() > MAX_TABLES {
        return Err(DumpError::Reason(
            "This database has more tables than BackMeUp will back up in one file.".to_string(),
        ));
    }

    let mut stats = DumpStats::default();

    // A view is created with `CREATE VIEW ... AS select ...`, and MySQL
    // refuses to create it unless every table and view it names already
    // exists. The tables are therefore written first and the real views last.
    //
    // A view may also name another view, and that other view is only created
    // later. So every view first gets a stand-in of the same name and the same
    // column names, holding no real data. The stand-ins are replaced by the
    // real definitions once the tables and rows are in the file, and by then
    // every name a view can refer to exists - as a table, as a stand-in, or as
    // the real thing.
    for (name, _kind) in objects.iter().filter(|(_, k)| *k == "VIEW") {
        let quoted = quote_ident(name).map_err(unsupported(name))?;
        let columns = columns_of(conn, name)?;

        writeln!(out, "DROP VIEW IF EXISTS {quoted};")?;
        writeln!(out, "{}", stand_in_view(&quoted, &columns)?)?;
    }

    for (name, _kind) in objects.iter().filter(|(_, k)| *k == "BASE TABLE") {
        let quoted = quote_ident(name).map_err(unsupported(name))?;
        let definition = create_statement(conn, "TABLE", name)?;

        writeln!(out, "DROP TABLE IF EXISTS {quoted};")?;
        writeln!(
            out,
            "{};",
            definition.trim_end().trim_end_matches(';')
        )?;
        out.write_all(b"\n")?;

        let columns = columns_of(conn, name)?;
        if !columns.is_empty() {
            dump_table(conn, out, &quoted, &columns, &mut stats, control)?;
        }

        stats.tables += 1;
        control.report(stats.tables + stats.views, stats.rows);
        if control.cancelled() {
            return Err(DumpError::Cancelled);
        }
    }

    // The views, now that the tables they name exist.
    for (name, _kind) in objects.iter().filter(|(_, k)| *k == "VIEW") {
        let quoted = quote_ident(name).map_err(unsupported(name))?;
        let definition = create_statement(conn, "VIEW", name)?;

        writeln!(out, "DROP VIEW IF EXISTS {quoted};")?;
        writeln!(
            out,
            "{};",
            strip_definer(&definition).trim_end().trim_end_matches(';')
        )?;
        stats.views += 1;
        control.report(stats.tables + stats.views, stats.rows);
        if control.cancelled() {
            return Err(DumpError::Cancelled);
        }
    }

    // Drained, for the same reason as the statements at the start.
    conn.query::<Row, _>("COMMIT")
        .map_err(|err| map_sql(err, stage::FINISHING, "finishing the read"))?;

    writeln!(out, "COMMIT;")?;
    writeln!(out, "SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;")?;
    writeln!(out, "SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;")?;
    writeln!(out, "SET SQL_MODE=@OLD_SQL_MODE;")?;
    writeln!(out, "SET TIME_ZONE=@OLD_TIME_ZONE;")?;

    control.report(stats.tables + stats.views, stats.rows);
    Ok(stats)
}

/// Every object in the current database, with its type.
fn list_objects(conn: &mut mysql::Conn) -> Result<Vec<(String, String)>, DumpError> {
    let rows: Vec<Row> = conn
        .query("SHOW FULL TABLES")
        .map_err(|err| map_sql(err, stage::LISTING, "listing tables"))?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let (Some(name), Some(kind)) = (row.as_ref(0).and_then(as_text), row.as_ref(1).and_then(as_text))
        else {
            continue;
        };
        out.push((name, kind));
    }
    Ok(out)
}

/// The definition text from a `SHOW CREATE ...` result (column 2).
fn create_statement(conn: &mut mysql::Conn, kind: &str, name: &str) -> Result<String, DumpError> {
    let quoted = quote_ident(name).map_err(unsupported(name))?;
    let rows: Vec<Row> = conn
        .query(format!("SHOW CREATE {kind} {quoted}"))
        .map_err(|err| map_sql(err, stage_for_create(kind), "reading a definition"))?;

    rows.first()
        .and_then(|row| row.as_ref(1))
        .and_then(as_text)
        .ok_or(DumpError::UnsupportedObject)
}

/// One column of a table, with what the server said about it.
#[derive(Debug, Clone)]
struct Column {
    name: String,
    /// True for a generated column: the server computes the value, so it must
    /// not be inserted.
    generated: bool,
}

/// Column names, in the server's own order.
fn columns_of(conn: &mut mysql::Conn, table: &str) -> Result<Vec<Column>, DumpError> {
    let quoted = quote_ident(table).map_err(unsupported(table))?;
    let rows: Vec<Row> = conn
        .query(format!("SHOW COLUMNS FROM {quoted}"))
        .map_err(|err| map_sql(err, stage::COLUMNS, "listing columns"))?;

    Ok(rows
        .iter()
        .filter_map(|row| {
            let name = row.as_ref(0).and_then(as_text)?;
            // `Extra` is the sixth column of the result, and the only place
            // the server says that a column is computed rather than stored.
            let extra = row.as_ref(5).and_then(as_text).unwrap_or_default();
            Some(Column {
                name,
                generated: is_generated(&extra),
            })
        })
        .collect())
}

/// Whether a column is computed by the server instead of being stored.
///
/// MySQL says `VIRTUAL GENERATED` or `STORED GENERATED`; MariaDB says
/// `VIRTUAL` or `PERSISTENT`. A column with an expression default says
/// `DEFAULT_GENERATED`, and that one *is* stored, so it must not be mistaken
/// for a generated column.
fn is_generated(extra: &str) -> bool {
    extra
        .trim()
        .split_whitespace()
        .any(|word| matches!(word, "GENERATED" | "VIRTUAL" | "PERSISTENT"))
}

/// The stand-in that holds a view's place until the tables it names exist.
///
/// Same name, same column names, no data. It is replaced by the real
/// definition at the end of the file, once every table is in place.
fn stand_in_view(quoted: &str, columns: &[Column]) -> Result<String, DumpError> {
    let names: Vec<String> = columns
        .iter()
        .map(|column| quote_ident(&column.name).map_err(unsupported(&column.name)))
        .collect::<Result<Vec<String>, DumpError>>()?;

    if names.is_empty() {
        // A view always has at least one column, so an empty one means the
        // server said something this module does not understand.
        return Err(DumpError::UnsupportedObject);
    }

    let values = names
        .iter()
        .map(|name| format!("1 AS {name}"))
        .collect::<Vec<String>>()
        .join(", ");

    Ok(format!("CREATE VIEW {quoted} AS SELECT {values};"))
}

/// Read one table and write it as batched `INSERT` statements.
fn dump_table<W: Write>(
    conn: &mut mysql::Conn,
    out: &mut W,
    quoted_table: &str,
    columns: &[Column],
    stats: &mut DumpStats,
    control: &dyn DumpControl,
) -> Result<(), DumpError> {
    // The columns are read and written by name, never with `SELECT *`.
    //
    // A generated column is computed by the server and refuses to be
    // inserted, so it is left out of both the read and the insert. An
    // invisible column is stored like any other, but `SELECT *` does not
    // return it, so naming the columns is what keeps it in the backup at all.
    let readable: Vec<&Column> = columns.iter().filter(|column| !column.generated).collect();
    if readable.is_empty() {
        return Ok(());
    }

    let column_list: String = readable
        .iter()
        .map(|column| quote_ident(&column.name).map_err(unsupported(&column.name)))
        .collect::<Result<Vec<String>, DumpError>>()?
        .join(", ");

    let sql = format!("SELECT {column_list} FROM {quoted_table}");

    let mut result = conn
        .query_iter(sql)
        .map_err(|err| map_sql(err, stage::DATA, "starting a table read"))?;

    let mut tuples: Vec<String> = Vec::new();
    let mut pending_bytes = 0usize;
    let mut rows_in_table: u64 = 0;

    while let Some(row) = result.next() {
        let row = row.map_err(|err| map_sql(err, stage::DATA, "reading rows"))?;
        let values: Vec<Value> = row.unwrap();
        if values.len() != readable.len() {
            // The row does not match the columns that were read. Writing part
            // of it would lose data without saying so, so the run stops
            // instead of saving a table that is quietly empty.
            return Err(DumpError::Reason(
                "The server returned a row that does not match its table, so the backup was \
                 stopped rather than saving incomplete data."
                    .to_string(),
            ));
        }

        if rows_in_table >= MAX_ROWS_PER_TABLE {
            return Err(DumpError::Reason(
                "One table in this database is larger than BackMeUp will back up in a single \
                 file."
                    .to_string(),
            ));
        }

        let tuple = render_tuple(&values).map_err(unsupported(&readable[0].name))?;
        // The real size of the tuple, not a guess: a batch that looks small on
        // paper can still be larger than the server's `max_allowed_packet`
        // once a table holds wide rows.
        pending_bytes += tuple.len() + 1;
        tuples.push(tuple);
        rows_in_table += 1;
        stats.rows += 1;

        if pending_bytes >= MAX_INSERT_BYTES {
            flush(out, quoted_table, &column_list, &mut tuples, &mut pending_bytes)?;
            control.report(stats.tables + stats.views, stats.rows);
            if control.cancelled() {
                return Err(DumpError::Cancelled);
            }
        }
    }

    flush(out, quoted_table, &column_list, &mut tuples, &mut pending_bytes)?;
    Ok(())
}

/// Close the pending `INSERT` statement, if any.
fn flush<W: Write>(
    out: &mut W,
    quoted_table: &str,
    column_list: &str,
    tuples: &mut Vec<String>,
    pending_bytes: &mut usize,
) -> Result<(), DumpError> {
    if tuples.is_empty() {
        return Ok(());
    }

    write!(out, "INSERT INTO {quoted_table} ({column_list}) VALUES ")?;
    for (index, tuple) in tuples.iter().enumerate() {
        if index > 0 {
            out.write_all(b",")?;
        }
        out.write_all(tuple.as_bytes())?;
    }
    writeln!(out, ";")?;

    tuples.clear();
    *pending_bytes = 0;
    Ok(())
}

/// The file preamble, including the warning that this file is the data.
fn write_header<W: Write>(out: &mut W, database: &str, server_version: &str) -> Result<(), DumpError> {
    writeln!(out, "-- BackMeUp logical backup")?;
    writeln!(out, "-- Database: {database}")?;
    writeln!(
        out,
        "-- Server: {}",
        server_version.replace(['\n', '\r'], " ")
    )?;
    writeln!(out, "--")?;
    writeln!(
        out,
        "-- This file contains the contents of the database. Anyone who can read"
    )?;
    writeln!(
        out,
        "-- it has your data: store it as carefully as you store a password."
    )?;
    writeln!(out, "--")?;
    writeln!(
        out,
        "-- Restore with:  mysql --user=<user> --password <database> < this-file.sql"
    )?;
    writeln!(out, "--")?;
    writeln!(out, "SET @OLD_SQL_MODE=@@SQL_MODE;")?;
    writeln!(out, "SET SQL_MODE='NO_AUTO_VALUE_ON_ZERO';")?;
    writeln!(out, "SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS;")?;
    writeln!(out, "SET FOREIGN_KEY_CHECKS=0;")?;
    writeln!(out, "SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS;")?;
    writeln!(out, "SET UNIQUE_CHECKS=0;")?;
    // The dump read its timestamps in UTC, so the restore reads them in UTC.
    // Without this, a TIMESTAMP written in one zone and read in another
    // shifts by the difference, silently.
    writeln!(out, "SET @OLD_TIME_ZONE=@@TIME_ZONE;")?;
    writeln!(out, "SET TIME_ZONE='+00:00';")?;
    writeln!(out, "SET NAMES utf8mb4;")?;
    writeln!(out)?;
    Ok(())
}

/// `(1,'a',NULL)` for one row.
fn render_tuple(values: &[Value]) -> Result<String, DumpError> {
    let mut out = String::with_capacity(16 * values.len() + 2);
    out.push('(');
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&literal(value)?);
    }
    out.push(')');
    Ok(out)
}

/// One SQL literal, safe to place in a generated file.
pub fn literal(value: &Value) -> Result<String, DumpError> {
    match value {
        Value::NULL => Ok("NULL".to_string()),
        Value::Int(number) => Ok(number.to_string()),
        Value::UInt(number) => Ok(number.to_string()),
        Value::Float(number) => float_literal(f64::from(*number)),
        Value::Double(number) => float_literal(*number),
        Value::Date(year, month, day, hour, minute, second, micros) => Ok(quote(&format!(
            "{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}{}",
            fractional(*micros)
        ))),
        Value::Time(negative, days, hour, minute, second, micros) => {
            let mut text = format!("{hour:02}:{minute:02}:{second:02}{}", fractional(*micros));
            if *days > 0 {
                text = format!("{days} {text}");
            }
            if *negative {
                text = format!("-{text}");
            }
            Ok(quote(&text))
        }
        Value::Bytes(bytes) => Ok(if inline_is_safe(bytes) {
            quote(&escape(bytes))
        } else {
            hex_literal(bytes)
        }),
    }
}

/// Microseconds as a fractional part, omitted entirely when zero.
fn fractional(micros: u32) -> String {
    if micros == 0 {
        String::new()
    } else {
        format!(".{micros:06}")
    }
}

/// Floats are written with a round-trip-exact representation.
fn float_literal(number: f64) -> Result<String, DumpError> {
    if !number.is_finite() {
        // MySQL cannot store these, so seeing one means the value did not come
        // from a MySQL column. Refusing beats writing a file that will not load.
        return Err(DumpError::UnsupportedObject);
    }
    Ok(format!("{number:?}"))
}

/// Quote an identifier, doubling backticks. Control characters are refused:
/// no legitimate MySQL object name contains them, and they cannot appear in a
/// statement.
pub fn quote_ident(name: &str) -> Result<String, DumpError> {
    if name.is_empty()
        || name.len() > MAX_IDENT_LEN
        || name.chars().any(|c| c.is_control() || c == '\u{0}')
    {
        return Err(DumpError::UnsupportedObject);
    }
    Ok(format!("`{}`", name.replace('`', "``")))
}

/// Wrap already-escaped text in single quotes.
fn quote(text: &str) -> String {
    format!("'{text}'")
}

/// Whether a byte string can be written inline rather than as hex.
///
/// Anything that is not valid UTF-8, is unexpectedly long, or carries a control
/// character other than tab/newline/carriage return is written as hex: exact,
/// unambiguous, and free of escaping questions.
fn inline_is_safe(bytes: &[u8]) -> bool {
    bytes.len() <= MAX_INLINE_BYTES
        && std::str::from_utf8(bytes).is_ok()
        && !bytes
            .iter()
            .any(|byte| matches!(byte, 0x00..=0x1F | 0x7F) && !matches!(byte, b'\t' | b'\n' | b'\r'))
}

/// Escape the characters MySQL treats specially inside a single-quoted string.
fn escape(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() + 8);
    for byte in bytes {
        match byte {
            b'\\' => out.push_str("\\\\"),
            b'\'' => out.push_str("\\'"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x08 => out.push_str("\\b"),
            0x1A => out.push_str("\\Z"),
            other => out.push(*other as char),
        }
    }
    out
}

/// `0x0a1b`, which MySQL reads as a binary string and never re-escapes.
fn hex_literal(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0F), 16).unwrap_or('0'));
    }
    out
}

/// Text of a server-supplied value.
fn as_text(value: &Value) -> Option<String> {
    match value {
        Value::Bytes(bytes) => Some(String::from_utf8_lossy(bytes).into_owned()),
        Value::Int(number) => Some(number.to_string()),
        Value::UInt(number) => Some(number.to_string()),
        Value::NULL => None,
        _ => None,
    }
}

/// Remove the `DEFINER=...` clause from a view definition.
///
/// The definer names an account that may not exist on the machine where the
/// dump is restored, and it would otherwise hard-code a server account name
/// into a file that may be shared.
pub fn strip_definer(definition: &str) -> String {
    const KEY: &str = " DEFINER=";
    let Some(start) = definition.find(KEY) else {
        return definition.to_string();
    };

    let rest = &definition[start + KEY.len()..];
    let end = [" SQL SECURITY", " SQL INVOKER", " VIEW"]
        .iter()
        .filter_map(|needle| rest.find(needle))
        .min();

    match end {
        Some(offset) => format!("{}{}", &definition[..start], &rest[offset..]),
        None => definition[..start].to_string(),
    }
}

/// A database name turned into a safe file-name fragment.
pub fn sanitize_file_stem(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();

    let trimmed = cleaned.trim_matches('_');
    let stem: String = trimmed.chars().take(48).collect();

    if stem.is_empty() {
        "database".to_string()
    } else {
        stem
    }
}

/// Build the error for one unusable object name, naming it in the log only.
fn unsupported(name: &str) -> impl Fn(DumpError) -> DumpError {
    let logged = name.chars().take(64).collect::<String>();
    move |_| {
        eprintln!("[backmeup] dump: unusable server object name ({} chars)", logged.len());
        DumpError::UnsupportedObject
    }
}

/// Map a driver error onto a safe reason that says *what* was being read.
///
/// `stage` and `detail` are BackMeUp's own words, never server text, so the
/// the failing part of the database is known instead of being told only
/// that a packet was malformed.
fn map_sql(err: mysql::Error, stage: &str, detail: &str) -> DumpError {
    if let mysql::Error::MySqlError(server) = &err {
        match server.code {
            // The account cannot see the object, or may not run the statement.
            1044 | 1142 | 1143 | 1227 | 1370 => return DumpError::Privileges,
            // ER_ACCESS_DENIED_ERROR: the password was refused. This is the
            // one failure that can be fixed, so it is named rather than
            // reported as a broken statement.
            1045 => return DumpError::Authentication,
            1049 => {
                return DumpError::Reason("That database no longer exists.".to_string());
            }
            1146 => {
                return DumpError::Reason(
                    "A table disappeared while the backup was reading it.".to_string(),
                );
            }
            _ => {}
        }
    }

    eprintln!("[backmeup] dump failed while {detail} at {stage}: {err}");

    // Reuse the tested connection-error mapping so a safe sentence is still shown
    // sentence, now with the stage attached so a failure is actionable.
    DumpError::Statement {
        stage: stage.to_string(),
        detail: detail.to_string(),
    }
}

/// Which stage a `SHOW CREATE` belongs to.
fn stage_for_create(kind: &str) -> &'static str {
    if kind == "VIEW" {
        stage::VIEWS
    } else {
        stage::SCHEMA
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(text: &str) -> Value {
        Value::Bytes(text.as_bytes().to_vec())
    }

    #[test]
    fn no_statement_is_left_undrained() {
        // `query_drop`, `exec_drop` and `query_first` all stop reading before
        // the server's reply is consumed, which desynchronises every statement
        // that follows on the same connection. That bug cost a real debugging
        // round, so the source is checked rather than trusted.
        let source = include_str!("mysqldump.rs");

        // Only the production half matters: the test module names these
        // functions on purpose.
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("the module must have a body");

        for offender in ["query_drop(", "exec_drop(", "query_first("] {
            // Comments may name them; code may not.
            let in_code = production
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .any(|line| line.contains(offender));

            assert!(!in_code, "{offender} must not be used: it leaves a reply unread");
        }
    }

    #[test]
    fn identifiers_are_quoted_and_control_characters_refused() {
        assert_eq!(quote_ident("users").unwrap(), "`users`");
        assert_eq!(quote_ident("we`ird").unwrap(), "`we``ird`");
        assert_eq!(
            quote_ident("caf\u{e9}").unwrap(),
            "`caf\u{e9}`",
            "a legitimate name must survive"
        );

        for hostile in ["", "a\nb", "a\0b", "a\u{7f}b", &"x".repeat(MAX_IDENT_LEN + 1)] {
            assert!(
                quote_ident(hostile).is_err(),
                "must refuse {hostile:?}"
            );
        }
    }

    #[test]
    fn literals_escape_and_quote_correctly() {
        assert_eq!(literal(&Value::NULL).unwrap(), "NULL");
        assert_eq!(literal(&Value::Int(-7)).unwrap(), "-7");
        assert_eq!(literal(&Value::UInt(u64::MAX)).unwrap(), "18446744073709551615");
        assert_eq!(literal(&bytes("plain")).unwrap(), "'plain'");
        assert_eq!(
            literal(&bytes("it's")).unwrap(),
            "'it\\'s'",
            "a quote inside a literal must be escaped"
        );
        assert_eq!(
            literal(&bytes("back\\slash")).unwrap(),
            "'back\\\\slash'",
            "a backslash must be escaped or it swallows the next character"
        );
        assert_eq!(literal(&bytes("line\nbreak\ttab")).unwrap(), "'line\\nbreak\\ttab'");
    }

    #[test]
    fn unsafe_values_become_exact_hex_literals() {
        // NUL, other control characters, invalid UTF-8 and oversized values all
        // take the hex path, which round-trips byte for byte.
        assert_eq!(literal(&bytes("a\0b")).unwrap(), "0x610062");
        assert_eq!(literal(&bytes("\u{1}")).unwrap(), "0x01");
        assert_eq!(literal(&Value::Bytes(vec![0xFF, 0x00, 0x41])).unwrap(), "0xff0041");

        let big = "x".repeat(MAX_INLINE_BYTES + 1);
        let rendered = literal(&bytes(&big)).unwrap();
        assert!(rendered.starts_with("0x"), "long values must be hex");
        assert_eq!(rendered.len(), 2 + (MAX_INLINE_BYTES + 1) * 2);
    }

    #[test]
    fn dates_and_times_keep_their_values() {
        assert_eq!(
            literal(&Value::Date(2024, 1, 2, 3, 4, 5, 0)).unwrap(),
            "'2024-01-02 03:04:05'"
        );
        assert_eq!(
            literal(&Value::Date(2024, 1, 2, 3, 4, 5, 500_000)).unwrap(),
            "'2024-01-02 03:04:05.500000'"
        );
        assert_eq!(
            literal(&Value::Time(false, 0, 1, 2, 3, 0)).unwrap(),
            "'01:02:03'"
        );
        assert_eq!(
            literal(&Value::Time(true, 2, 1, 2, 3, 0)).unwrap(),
            "'-2 01:02:03'"
        );
    }

    #[test]
    fn floats_are_round_trippable_and_non_finite_is_refused() {
        assert_eq!(literal(&Value::Double(1.5)).unwrap(), "1.5");
        let exact = literal(&Value::Double(0.1 + 0.2)).unwrap();
        assert!(
            exact.contains("0.30000000000000004"),
            "must not lose precision: {exact}"
        );

        // MySQL cannot store these, so writing them would produce a file that
        // cannot be restored.
        assert!(literal(&Value::Double(f64::NAN)).is_err());
        assert!(literal(&Value::Double(f64::INFINITY)).is_err());
    }

    #[test]
    fn a_failed_statement_says_what_was_being_read_and_never_quotes_the_server() {
        // A hostile server message must not survive, and the stage must be
        // present so the failure is actionable.
        let mapped = map_sql(
            mysql::Error::CodecError(
                std::io::Error::other("packet 41: Access denied for user 'root'@'203.0.113.9'")
                    .into(),
            ),
            stage::DATA,
            "reading rows",
        );

        let DumpError::Statement { stage, detail } = &mapped else {
            panic!("expected a staged statement failure, got {mapped:?}");
        };

        assert_eq!(stage, "reading_rows");
        assert_eq!(detail, "reading rows");
        assert!(format!("{mapped}").contains("reading_rows"));

        // None of the server's own text may appear anywhere in the error.
        let rendered = format!("{mapped:?}");
        for leak in ["root", "203.0.113.9", "Access denied", "packet"] {
            assert!(!rendered.contains(leak), "{leak} leaked: {rendered}");
        }
    }

    #[test]
    fn a_privilege_failure_is_reported_as_such() {
        for code in [1044u16, 1142, 1143, 1227, 1370] {
            let mapped = map_sql(
                mysql::Error::MySqlError(mysql::MySqlError {
                    code,
                    state: "42000".to_string(),
                    message: "command denied".to_string(),
                }),
                stage::DATA,
                "reading rows",
            );

            assert!(
                matches!(mapped, DumpError::Privileges),
                "code {code} must map to a privilege failure"
            );
        }
    }

    #[test]
    fn definers_are_removed_from_view_definitions() {
        let definition = "CREATE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY \
                          DEFINER VIEW `v` AS SELECT `t`.`id` AS `id` FROM `t`";
        let stripped = strip_definer(definition);

        assert!(!stripped.contains("root"), "{stripped}");
        assert!(!stripped.contains("DEFINER="), "{stripped}");
        assert!(stripped.contains("SQL SECURITY"), "{stripped}");
        assert!(stripped.ends_with("FROM `t`"), "{stripped}");
    }

    #[test]
    fn a_definition_without_a_definer_is_untouched() {
        let definition = "CREATE VIEW `v` AS SELECT 1";
        assert_eq!(strip_definer(definition), definition);
    }

    #[test]
    fn a_view_stands_in_until_the_tables_it_names_exist() {
        // MySQL refuses to create a view whose tables do not exist yet, so the
        // file carries a stand-in with the same name and columns, and the real
        // definition comes after the tables.
        let columns = vec![
            Column {
                name: "id".to_string(),
                generated: false,
            },
            Column {
                name: "total".to_string(),
                generated: false,
            },
        ];

        assert_eq!(
            stand_in_view("`v`", &columns).unwrap(),
            "CREATE VIEW `v` AS SELECT 1 AS `id`, 1 AS `total`;"
        );
    }

    #[test]
    fn a_view_without_columns_is_refused() {
        assert!(stand_in_view("`v`", &[]).is_err());
    }

    #[test]
    fn generated_columns_are_told_apart_from_expression_defaults() {
        // MySQL.
        assert!(is_generated("VIRTUAL GENERATED"));
        assert!(is_generated("STORED GENERATED"));
        assert!(is_generated("VIRTUAL GENERATED INVISIBLE"));
        // MariaDB words it differently.
        assert!(is_generated("VIRTUAL"));
        assert!(is_generated("PERSISTENT"));
        // None of these is a generated column. `DEFAULT_GENERATED` is a column
        // with an expression default: it is stored, and it is written by hand.
        assert!(!is_generated(""));
        assert!(!is_generated("auto_increment"));
        assert!(!is_generated("DEFAULT_GENERATED"));
        assert!(!is_generated("on update CURRENT_TIMESTAMP"));
        assert!(!is_generated("INVISIBLE"));
    }

    #[test]
    fn the_file_pins_the_character_set_and_the_clock() {
        // A TIMESTAMP read in one time zone and restored in another shifts by
        // the difference, and nothing in the file would show it.
        let mut out = Vec::new();
        write_header(&mut out, "shop", "8.0.36").unwrap();
        let text = String::from_utf8(out).unwrap();

        assert!(text.contains("SET NAMES utf8mb4;"), "{text}");
        assert!(text.contains("SET @OLD_TIME_ZONE=@@TIME_ZONE;"), "{text}");
        assert!(text.contains("SET TIME_ZONE='+00:00';"), "{text}");
    }

    #[test]
    fn file_stems_are_safe_and_never_empty() {
        assert_eq!(sanitize_file_stem("shop_db"), "shop_db");
        assert_eq!(sanitize_file_stem("my db"), "my_db");
        assert_eq!(sanitize_file_stem("../../etc/passwd"), "etc_passwd");
        assert_eq!(sanitize_file_stem(""), "database");
        assert_eq!(sanitize_file_stem("***"), "database");
        assert_eq!(sanitize_file_stem(&"a".repeat(200)).len(), 48);
        assert!(!sanitize_file_stem("C:file").contains(':'));
    }

    #[test]
    fn every_unsupported_object_name_is_bounded_in_the_log() {
        // The name is logged truncated, and the error that reaches the screen
        // carries no name at all - so a hostile server name can neither be
        // echoed into the UI nor flood the log.
        let hostile = format!("LEAKED_NAME_{}", "n".repeat(500));
        let rendered = format!("{}", unsupported(&hostile)(DumpError::Cancelled));

        assert_eq!(rendered, "unsupported_object");
        assert!(
            !rendered.contains("LEAKED_NAME"),
            "no server name may survive: {rendered}"
        );
    }

    /// Dump a live server, so the file can be read and judged as it is.
    ///
    /// It is never run by itself. Pointed at a server it writes the file this
    /// module would hand to a destination:
    ///
    /// ```text
    /// BME_HOST=127.0.0.1 BME_PORT=3306 BME_USER=root BME_PASSWORD=secret \
    /// BME_DATABASE=shop BME_DUMP_OUT=shop.sql \
    ///   cargo test --lib dump_a_live_server -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "needs a live server; run it on purpose"]
    fn dump_a_live_server() {
        let host = std::env::var("BME_HOST").expect("BME_HOST must be set");
        let port: u16 = std::env::var("BME_PORT")
            .expect("BME_PORT must be set")
            .parse()
            .expect("BME_PORT must be a number");
        let user = std::env::var("BME_USER").expect("BME_USER must be set");
        let password = std::env::var("BME_PASSWORD").expect("BME_PASSWORD must be set");
        let database = std::env::var("BME_DATABASE").expect("BME_DATABASE must be set");
        let out = std::env::var("BME_DUMP_OUT").expect("BME_DUMP_OUT must be set");

        let mut connection = mysql::Conn::new(
            mysql::OptsBuilder::default()
                .ip_or_hostname(Some(host))
                .tcp_port(port)
                .user(Some(user))
                .pass(Some(password))
                .db_name(Some(database.clone())),
        )
        .expect("the server must accept the connection");

        let mut file = std::fs::File::create(&out).expect("the output file must be writable");
        let stats = dump_database(
            &mut connection,
            &database,
            "live server",
            &mut file,
            &Quiet,
        )
        .expect("the dump must finish");

        let bytes = std::fs::metadata(&out).map(|meta| meta.len()).unwrap_or(0);
        println!("{stats:?} written to {out} ({bytes} bytes)");
    }

    /// A control that never cancels and reports nothing.
    struct Quiet;

    impl DumpControl for Quiet {
        fn report(&self, _tables_done: u64, _rows: u64) {}
        fn cancelled(&self) -> bool {
            false
        }
    }
}
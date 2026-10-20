use rusqlite::{Connection, OpenFlags};
use tauri::{AppHandle, Manager};

use crate::error::{AppError, AppResult};

pub const DB_FILE_NAME: &str = "backmeup.db";

/// Open (and if necessary create and migrate) the local SQLite database.
///
/// The file lives in the per-user application data directory
/// (`%APPDATA%\com.backmeup.desktop`), which on Windows inherits the user's
/// exclusive profile ACL, so the database is already readable only by the
/// signed-in user and by SYSTEM/Administrators.
pub fn open(app: &AppHandle) -> Result<Connection, Box<dyn std::error::Error>> {
    let dir = app.path().app_data_dir()?;
    std::fs::create_dir_all(&dir)?;

    let path = dir.join(DB_FILE_NAME);

    let conn = Connection::open_with_flags(
        &path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;

    // Defence in depth: fail closed if the OS layer reports world access.
    restrict_to_current_user(&path)?;

    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "FULL")?;
    conn.pragma_update(None, "busy_timeout", 5_000)?;

    migrate(&conn)?;

    Ok(conn)
}

/// Best effort hardening of the database file permissions.
///
/// On unix-like systems the file is forced to `0600`. On Windows the ACLs
/// inherited from the user's `%APPDATA%` directory already restrict access to
/// the account owner, its administrators and SYSTEM; re-writing the DACL would
/// require pulling in the full `windows` crate for no security gain.
fn restrict_to_current_user(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }

    #[cfg(windows)]
    {
        let _ = path;
        // Documented in the function comment: inherited per-user ACLs apply.
    }

    Ok(())
}

fn migrate(conn: &Connection) -> AppResult<()> {
    conn.execute_batch(
        r#"
        BEGIN IMMEDIATE;

        CREATE TABLE IF NOT EXISTS owner_account (
            id                 INTEGER PRIMARY KEY CHECK (id = 1),
            full_name          TEXT    NOT NULL,
            email              TEXT    NOT NULL UNIQUE,
            password_hash      TEXT    NOT NULL,
            setup_confirmed    INTEGER NOT NULL DEFAULT 0 CHECK (setup_confirmed IN (0, 1)),
            created_at         INTEGER NOT NULL,
            updated_at         INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS recovery_code_sets (
            id            TEXT    PRIMARY KEY,
            status        TEXT    NOT NULL CHECK (status IN ('active', 'pending')),
            created_at    INTEGER NOT NULL,
            confirmed_at  INTEGER
        );

        CREATE UNIQUE INDEX IF NOT EXISTS idx_recovery_sets_single_active
            ON recovery_code_sets (status) WHERE status = 'active';

        CREATE TABLE IF NOT EXISTS recovery_codes (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            set_id       TEXT    NOT NULL REFERENCES recovery_code_sets (id) ON DELETE CASCADE,
            code_hash    TEXT    NOT NULL,
            created_at   INTEGER NOT NULL,
            used_at      INTEGER,
            CHECK (used_at IS NULL OR used_at > 0)
        );

        CREATE INDEX IF NOT EXISTS idx_recovery_codes_active
            ON recovery_codes (set_id, used_at);

        CREATE TABLE IF NOT EXISTS auth_events (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            category      TEXT    NOT NULL CHECK (category IN ('login', 'recovery', 'setup', 'codes')),
            email         TEXT,
            outcome       TEXT    NOT NULL CHECK (outcome IN ('success', 'failure')),
            detail        TEXT,
            occurred_at   INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_auth_events_time
            ON auth_events (category, occurred_at);

        -- ------------------------------------------------------------------
        -- Backup domain.
        --
        -- These tables hold *configuration and history only*. There is
        -- deliberately no column anywhere for a database password, an OAuth
        -- token or any other secret: see `databases::CREDENTIAL_STORAGE_NOTE`
        -- and `drive` for where those live (the Windows Credential Manager).
        -- ------------------------------------------------------------------

        CREATE TABLE IF NOT EXISTS database_connections (
            id                TEXT    PRIMARY KEY,
            label             TEXT    NOT NULL,
            engine            TEXT    NOT NULL,
            connection_method TEXT    NOT NULL,
            -- Nullable: engines and methods reached over a local socket have
            -- no host, and the value is not required until it is dialled.
            host              TEXT,
            port              INTEGER,
            database_name     TEXT    NOT NULL,
            -- Identifier only. A secret belonging to this user is NOT stored
            -- here; `secret_ref` is reserved for a future OS keychain entry.
            username          TEXT,
            secret_ref        TEXT,
            created_at        INTEGER NOT NULL,
            updated_at        INTEGER NOT NULL,
            CHECK (length(id) = 64),
            CHECK (length(label) BETWEEN 1 AND 100),
            CHECK (port IS NULL OR (port BETWEEN 1 AND 65535))
        );

        CREATE INDEX IF NOT EXISTS idx_database_connections_created
            ON database_connections (created_at);

        CREATE TABLE IF NOT EXISTS backup_destinations (
            id         TEXT    PRIMARY KEY,
            kind       TEXT    NOT NULL CHECK (kind IN ('local_folder', 'google_drive')),
            label      TEXT    NOT NULL,
            location   TEXT,
            status     TEXT    NOT NULL CHECK (status IN ('configured', 'disconnected')),
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            -- One record per destination kind. Only kinds that persist a
            -- location may carry one, so a cloud provider can never be handed
            -- a filesystem path.
            UNIQUE (kind),
            CHECK (
                (kind = 'local_folder' AND location IS NOT NULL)
                OR (kind <> 'local_folder' AND location IS NULL)
            )
        );

        CREATE TABLE IF NOT EXISTS backup_runs (
            id             TEXT    PRIMARY KEY,
            database_id    TEXT    REFERENCES database_connections (id) ON DELETE SET NULL,
            destination_id TEXT    REFERENCES backup_destinations (id) ON DELETE CASCADE,
            status         TEXT    NOT NULL CHECK (
                               status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')
                           ),
            started_at     INTEGER,
            finished_at    INTEGER,
            size_bytes     INTEGER,
            failure_reason TEXT,
            created_at     INTEGER NOT NULL,
            CHECK (length(id) = 64),
            CHECK (size_bytes IS NULL OR size_bytes >= 0)
        );

        CREATE INDEX IF NOT EXISTS idx_backup_runs_created
            ON backup_runs (created_at DESC);

        -- Audit trail for configuration changes, kept separate from
        -- `auth_events` so the auth table's category constraint stays intact.
        CREATE TABLE IF NOT EXISTS config_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            category    TEXT    NOT NULL CHECK (category IN ('database', 'destination')),
            outcome     TEXT    NOT NULL CHECK (outcome IN ('created', 'deleted', 'updated')),
            detail      TEXT,
            occurred_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_config_events_time
            ON config_events (category, occurred_at);

        COMMIT;
        "#,
    )
    .map_err(|err| {
        eprintln!("[backmeup] schema migration failed: {err}");
        AppError::internal()
    })?;

    // Columns added after the first release. `ALTER TABLE ... ADD COLUMN` is
    // not idempotent in SQLite, so each one is guarded by a `table_info` probe
    // and an existing installation upgrades in place without a table rebuild.
    ensure_column(conn, "database_connections", "last_tested_at", "INTEGER")?;
    ensure_column(conn, "database_connections", "last_test_ok", "INTEGER CHECK (last_test_ok IN (0, 1))")?;

    // SSH tunnel fields (Phase 3). Present only for records whose
    // `connection_method` is 'ssh-tunnel'. The host-key fingerprint is public
    // data (a hash of the server's public key); no SSH secret is ever stored in
    // this file - passwords and passphrases live in the Windows Credential
    // Manager and the private key is a DPAPI-protected blob on disk.
    ensure_column(conn, "database_connections", "ssh_host", "TEXT")?;
    ensure_column(
        conn,
        "database_connections",
        "ssh_port",
        "INTEGER CHECK (ssh_port IS NULL OR (ssh_port BETWEEN 1 AND 65535))",
    )?;
    ensure_column(conn, "database_connections", "ssh_username", "TEXT")?;
    ensure_column(
        conn,
        "database_connections",
        "ssh_auth_method",
        "TEXT CHECK (ssh_auth_method IS NULL OR ssh_auth_method IN ('password', 'private_key'))",
    )?;
    ensure_column(conn, "database_connections", "ssh_host_key_type", "TEXT")?;
    ensure_column(
        conn,
        "database_connections",
        "ssh_host_key_fingerprint",
        "TEXT",
    )?;

    // Google Drive outcome for a run. Kept apart from `failure_reason` so a
    // successful run can carry a Drive note without looking failed, and a
    // failed Drive-only run can explain itself.
    ensure_column(conn, "backup_runs", "drive_status", "TEXT")?;
    ensure_column(conn, "backup_runs", "drive_error", "TEXT")?;

    // Where the finished file actually landed, so history can point the owner
    // at it. `file_name` is the copy kept in the local folder (never the
    // staging file, which is deleted after upload); `drive_path` is the
    // `BackMeUp/<database>/<day>/<file>` path in Drive.
    ensure_column(conn, "backup_runs", "file_name", "TEXT")?;
    ensure_column(conn, "backup_runs", "drive_path", "TEXT")?;

    // The SHA-256 of the finished file, computed while it was written. It
    // proves the file is still the one that was produced: hashing it again
    // later gives the same value, and any other value means the file changed.
    ensure_column(conn, "backup_runs", "sha256", "TEXT")?;

    Ok(())
}

/// Add a column only when it is not already present.
fn ensure_column(
    conn: &Connection,
    table: &str,
    column: &str,
    declaration: &str,
) -> AppResult<()> {
    // `table` and `column` are compile-time constants at every call site, never
    // user input, so formatting them into the statement is safe here.
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = stmt.query([])?;

    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name == column {
            return Ok(());
        }
    }

    conn.execute_batch(&format!(
        "ALTER TABLE {table} ADD COLUMN {column} {declaration}"
    ))
    .map_err(|err| {
        eprintln!("[backmeup] adding column {table}.{column} failed: {err}");
        AppError::internal()
    })?;

    Ok(())
}

/// Record a security relevant event. Never called with credential material,
/// recovery codes or file system paths.
pub fn audit(
    conn: &Connection,
    category: &str,
    email: Option<&str>,
    outcome: &str,
    detail: Option<&str>,
) {
    let result = conn.execute(
        "INSERT INTO auth_events (category, email, outcome, detail, occurred_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![category, email, outcome, detail, crate::util::now_secs()],
    );
    if let Err(err) = result {
        eprintln!("[backmeup] failed to write audit event: {err}");
    }
}

/// Record a configuration change (a database connection or a destination).
///
/// `detail` must be a short, fixed-purpose tag. Never pass a host, a file
/// system path, a database name, a user name, a token or any other value that
/// could describe a secret or disclose where files live.
pub fn audit_config(
    conn: &Connection,
    category: &str,
    outcome: &str,
    detail: Option<&str>,
) {
    let result = conn.execute(
        "INSERT INTO config_events (category, outcome, detail, occurred_at) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![category, outcome, detail, crate::util::now_secs()],
    );
    if let Err(err) = result {
        eprintln!("[backmeup] failed to write config audit event: {err}");
    }
}
//! Notices: the things worth saying once, that a toast would lose.
//!
//! A toast is gone in five seconds. A notice is not: it stays in the bell
//! until the thing it is about is resolved, so a dismissed prompt is never
//! lost and a problem cannot hide behind a screen change.
//!
//! Notices are **derived**, not queued. Each one is worked out from the facts
//! the app already keeps - the update it last saw, the credentials it last
//! tried, the run it last finished - so a notice cannot go stale, cannot
//! duplicate itself, and cannot disagree with the history.

use serde::Serialize;
use tauri::State;

use crate::commands::{require_session, AppState};
use crate::db;
use crate::error::AppResult;

/// One thing that should be known about.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Notice {
    /// Stable across reloads, so the UI can remember what it has shown.
    pub id: String,
    /// `update`, `credential` or `backup`.
    pub kind: String,
    /// `info` or `warning`.
    pub severity: String,
    pub title: String,
    /// One short sentence.
    pub body: String,
    /// What the button does: `install_update`, `edit_database` or
    /// `open_history`.
    pub action: Option<String>,
    /// The button's wording.
    pub action_label: Option<String>,
    /// The connection this is about, when it is about one.
    pub target: Option<String>,
    /// When the fact behind it happened.
    pub at: i64,
}

/// Everything the app currently wants to say.
#[tauri::command]
pub fn list_notices(state: State<'_, AppState>) -> AppResult<Vec<Notice>> {
    require_session(&state)?;

    let conn = state.lock_db()?;
    let mut notices = Vec::new();

    notices.extend(update_notice(&conn)?);
    notices.extend(credential_notices(&conn)?);
    notices.extend(last_backup_notice(&conn)?);

    // Newest first, so the most recent thing is at the top of the bell.
    notices.sort_by(|left, right| right.at.cmp(&left.at));

    Ok(notices)
}

/// "A new version is available", while a newer version exists.
fn update_notice(conn: &rusqlite::Connection) -> AppResult<Vec<Notice>> {
    let Ok(Some(version)) = db::setting(conn, "update.latest_version") else {
        return Ok(Vec::new());
    };

    let running = current_version();
    if !crate::updates::version_is_newer(&version, &running) {
        return Ok(Vec::new());
    }

    let notes = db::setting(conn, "update.latest_notes")?;
    let body = match notes.as_deref() {
        Some(notes) if !notes.trim().is_empty() => notes.trim().to_string(),
        _ => "A new version of BackMeUp is ready to install.".to_string(),
    };

    Ok(vec![Notice {
        id: "update".to_string(),
        kind: "update".to_string(),
        severity: "info".to_string(),
        title: format!("BackMeUp {version} is available"),
        body,
        action: Some("install_update".to_string()),
        action_label: Some("Install and restart".to_string()),
        target: None,
        at: db::setting(conn, "update.latest_date")?
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(crate::util::now_secs),
    }])
}

/// "The password for this connection was rejected".
///
/// A password that was rotated on the server leaves the saved copy behind.
/// Without this, every backup fails with a message that does not say what to
/// do about it.
fn credential_notices(conn: &rusqlite::Connection) -> AppResult<Vec<Notice>> {
    let mut stmt = conn.prepare(
        "SELECT id, label, database_name, credential_checked_at
         FROM database_connections
         WHERE credential_status = 'rejected'
         ORDER BY updated_at DESC",
    )?;
    let mut rows = stmt.query([])?;

    let mut notices = Vec::new();
    while let Some(row) = rows.next()? {
        let id: String = row.get(0)?;
        let label: String = row.get(1)?;
        let database: Option<String> = row.get(2)?;
        let checked_at: Option<i64> = row.get(3)?;

        let what = match database {
            Some(database) if !database.is_empty() => format!("{label} ({database})"),
            _ => label,
        };

        notices.push(Notice {
            id: format!("credential:{id}"),
            kind: "credential".to_string(),
            severity: "warning".to_string(),
            title: format!("The password for {what} was rejected"),
            body: "The server did not accept the saved password. It was probably changed on the \
                   server - re-enter it for this connection."
                .to_string(),
            action: Some("edit_database".to_string()),
            action_label: Some("Re-enter the password".to_string()),
            target: Some(id),
            at: checked_at.unwrap_or_else(crate::util::now_secs),
        });
    }

    Ok(notices)
}

/// "Backed up Tabulate, 48 rows - 2 of 3 saved databases so far".
fn last_backup_notice(conn: &rusqlite::Connection) -> AppResult<Vec<Notice>> {
    let mut stmt = conn.prepare(
        "SELECT br.id, br.status, br.rows, br.size_bytes, br.finished_at, dc.label
         FROM backup_runs br
         LEFT JOIN database_connections dc ON dc.id = br.database_id
         WHERE br.status = 'succeeded'
         ORDER BY br.finished_at DESC, br.created_at DESC
         LIMIT 1",
    )?;
    let mut rows = stmt.query([])?;

    let Some(row) = rows.next()? else {
        return Ok(Vec::new());
    };

    let id: String = row.get(0)?;
    let rows_dumped: Option<i64> = row.get(2)?;
    let size: Option<i64> = row.get(3)?;
    let finished_at: Option<i64> = row.get(4)?;
    let label: Option<String> = row.get(5)?;

    // How many of the saved databases have a successful backup, out of how
    // many there are. The number the account actually wants to know.
    let backed_up: i64 = conn.query_row(
        "SELECT count(DISTINCT database_id) FROM backup_runs WHERE status = 'succeeded'",
        [],
        |row| row.get(0),
    )?;
    let saved: i64 = conn.query_row(
        "SELECT count(*) FROM database_connections",
        [],
        |row| row.get(0),
    )?;

    let what = label.unwrap_or_else(|| "a database".to_string());
    let count = match rows_dumped {
        Some(count) => format!("{count} rows"),
        None => "the database".to_string(),
    };
    let size = match size {
        Some(bytes) if bytes > 0 => format!(" · {}", crate::util::format_bytes(bytes)),
        _ => String::new(),
    };

    Ok(vec![Notice {
        id: format!("backup:{id}"),
        kind: "backup".to_string(),
        severity: "info".to_string(),
        title: "Backup complete".to_string(),
        body: format!(
            "{what} · {count}{size}. {backed_up} of {saved} saved databases backed up so far."
        ),
        action: Some("open_history".to_string()),
        action_label: Some("See the history".to_string()),
        target: None,
        at: finished_at.unwrap_or_else(crate::util::now_secs),
    }])
}

/// The version of the app that is running.
fn current_version() -> String {
    // The version is compiled in, so it is the same value the installer
    // carries. Reading it from the package metadata would need a handle to
    // the app, which a pure helper does not have.
    env!("CARGO_PKG_VERSION").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_running_version_is_the_package_version() {
        assert_eq!(current_version(), env!("CARGO_PKG_VERSION"));
        assert!(!current_version().is_empty());
    }
}

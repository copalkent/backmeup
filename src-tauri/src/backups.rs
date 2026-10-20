//! Backup history and the dashboard summary.
//!
//! This module reads and reports backup *records*. The rows themselves are
//! written by `runs`, which performs the dump and the upload; nothing here
//! reads a database or writes a file. Every figure this module returns is read
//! from `backup_runs`. If the table is empty the UI shows an empty state;
//! nothing is ever synthesised, defaulted or seeded.

use rusqlite::{Connection, TransactionBehavior};
use serde::Serialize;
use tauri::State;

use crate::commands::{require_session, AppState};
use crate::databases;
use crate::destinations;
use crate::error::AppResult;

/// Largest page the frontend may request. The cap is applied in the backend so
/// an oversized `limit` from a modified webview cannot pull the whole table.
const MAX_LIMIT: i64 = 200;
const DEFAULT_LIMIT: i64 = 50;

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BackupRunView {
    pub id: String,
    /// Null when the source connection has since been deleted. The run itself
    /// is always preserved.
    pub database_label: Option<String>,
    pub database_name: Option<String>,
    pub engine_label: Option<String>,
    pub destination_label: Option<String>,
    /// The folder the local copy was written to, when that destination is a
    /// local folder. Never present for the cloud destination, which carries no
    /// path.
    pub destination_location: Option<String>,
    pub status: String,
    pub started_at: Option<i64>,
    pub finished_at: Option<i64>,
    pub size_bytes: Option<i64>,
    pub failure_reason: Option<String>,
    /// `uploaded` | `failed` | `skipped`, or null for runs recorded before
    /// Drive existed.
    pub drive_status: Option<String>,
    /// Why a Drive upload did not happen. Separate from `failure_reason` so a
    /// successful local backup is not reported as failed.
    pub drive_error: Option<String>,
    /// Path of the file relative to the chosen backup folder, when one was
    /// kept: `BackMeUp/<database>/<day>/<file>.sql`.
    pub file_name: Option<String>,
    /// `BackMeUp/<database>/<day>/<file>` when the copy reached Drive.
    pub drive_path: Option<String>,
    /// SHA-256 of the finished file. Hash the file again and the value must
    /// match; any other value means the file is not the one this run produced.
    pub sha256: Option<String>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BackupSummary {
    pub status: String,
    /// `finished_at` when the run ended, otherwise `started_at`, otherwise the
    /// time the row was created.
    pub at: i64,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BackupOverview {
    pub database_count: u32,
    pub backup_count: u32,
    /// The most recent recorded run, or `None` when no backup has been recorded.
    pub last_backup: Option<BackupSummary>,
    pub destination_count: u32,
    /// True once a local folder has been chosen.
    pub has_local_folder: bool,
    /// True while a Google Drive sign-in is stored.
    pub has_drive: bool,
}

/// The most recent recorded backup.
///
/// Ordering uses `COALESCE(finished_at, started_at, created_at)` so a queued
/// run still sorts sensibly, and the id breaks ties deterministically.
fn last_backup(conn: &Connection) -> AppResult<Option<BackupSummary>> {
    let row = conn.query_row(
        "SELECT status, COALESCE(finished_at, started_at, created_at) AS happened_at
         FROM backup_runs
         ORDER BY happened_at DESC, id DESC
         LIMIT 1",
        [],
        |row| {
            Ok(BackupSummary {
                status: row.get(0)?,
                at: row.get(1)?,
            })
        },
    );

    match row {
        Ok(summary) => Ok(Some(summary)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(err) => Err(err.into()),
    }
}

fn count_runs(conn: &Connection) -> AppResult<u32> {
    let total: i64 = conn.query_row("SELECT COUNT(*) FROM backup_runs", [], |row| {
        row.get(0)
    })?;
    Ok(total as u32)
}

/// Recorded backup runs, newest first.
#[tauri::command]
pub fn list_backup_runs(state: State<'_, AppState>, limit: Option<i64>) -> AppResult<Vec<BackupRunView>> {
    require_session(&state)?;

    let limit = limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);

    let conn = state.lock_db()?;
    let mut stmt = conn.prepare(
        "SELECT br.id,
                dc.label,
                dc.database_name,
                dc.engine,
                bd.label,
                br.status,
                br.started_at,
                br.finished_at,
                br.size_bytes,
                br.failure_reason,
                br.drive_status,
                br.drive_error,
                bd.location,
                br.file_name,
                br.drive_path,
                br.sha256
         FROM backup_runs br
         LEFT JOIN database_connections dc ON dc.id = br.database_id
         LEFT JOIN backup_destinations   bd ON bd.id = br.destination_id
         ORDER BY br.created_at DESC, br.id DESC
         LIMIT ?1",
    )?;

    let rows = stmt.query_map([limit], |row| {
        let engine_id: Option<String> = row.get(3)?;

        Ok(BackupRunView {
            id: row.get(0)?,
            database_label: row.get(1)?,
            database_name: row.get(2)?,
            engine_label: engine_id
                .as_deref()
                .and_then(crate::engines::find)
                .map(|engine| engine.label.to_string()),
            destination_label: row.get(4)?,
            status: row.get(5)?,
            started_at: row.get(6)?,
            finished_at: row.get(7)?,
            size_bytes: row.get(8)?,
            failure_reason: row.get(9)?,
            drive_status: row.get(10)?,
            drive_error: row.get(11)?,
            destination_location: row.get(12)?,
            file_name: row.get(13)?,
            drive_path: row.get(14)?,
            sha256: row.get(15)?,
        })
    })?;

    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// Forget every recorded run.
///
/// This removes history only. It never touches a backup *file*: a file already
/// written to the chosen folder stays exactly where it is, because deleting
/// someone's backups is not something a history button may do on their behalf.
/// The command is named for what it does and the UI says so before it runs.
#[tauri::command]
pub fn clear_backup_history(state: State<'_, AppState>) -> AppResult<u64> {
    require_session(&state)?;

    let mut conn = state.lock_db()?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

    let removed = tx.execute("DELETE FROM backup_runs", [])?;
    tx.commit()?;

    Ok(removed as u64)
}

/// Counts for the dashboard. Every number is a real count.
#[tauri::command]
pub fn backup_overview(state: State<'_, AppState>) -> AppResult<BackupOverview> {
    require_session(&state)?;

    let conn = state.lock_db()?;

    let has_drive = crate::drive::is_connected();
    let local_count = destinations::configured_count(&conn)?;

    Ok(BackupOverview {
        database_count: databases::count(&conn)?,
        backup_count: count_runs(&conn)?,
        last_backup: last_backup(&conn)?,
        destination_count: local_count + u32::from(has_drive),
        has_local_folder: destinations::local_folder(&conn)?.is_some(),
        has_drive,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_are_clamped_into_a_safe_range() {
        assert_eq!(None.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT), DEFAULT_LIMIT);
        assert_eq!(Some(0).unwrap().clamp(1, MAX_LIMIT), 1);
        assert_eq!(Some(-5).unwrap().clamp(1, MAX_LIMIT), 1);
        assert_eq!(Some(i64::MAX).unwrap().clamp(1, MAX_LIMIT), MAX_LIMIT);
        assert_eq!(Some(25).unwrap().clamp(1, MAX_LIMIT), 25);
    }

    #[test]
    fn default_page_size_is_within_the_cap() {
        assert!(DEFAULT_LIMIT >= 1 && DEFAULT_LIMIT <= MAX_LIMIT);
    }
}
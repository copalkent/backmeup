//! Backup destination management.
//!
//! A destination answers "where does a finished backup file go?". Destinations
//! are deliberately decoupled from database engines: adding storage must never
//! require touching an engine adapter, and adding an engine must never require
//! touching this module.
//!
//! Security posture for this phase:
//!   * The frontend never receives a filesystem capability and never receives a
//!     path it can act on. The folder is chosen through the native Windows
//!     dialog *inside Rust*, then re-validated here.
//!   * Nothing is written, created, overwritten or deleted. `location` is the
//!     only path-like value stored, and it is the owner's own choice.
//!   * No OAuth client id, client secret or refresh token exists anywhere in
//!     this file, in the frontend bundle, or in the database.

use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use serde::Serialize;
use tauri::{AppHandle, State};
use tauri_plugin_dialog::DialogExt;

use crate::commands::{require_session, AppState};
use crate::db;
use crate::drive;
use crate::error::{AppError, AppResult};
use crate::util;

/// The static catalogue of destination kinds this build knows about.
///
/// `available` is false until a real, verified integration exists. The frontend
/// renders an unavailable kind as such and must not present it as connected.
#[derive(Clone, Copy)]
pub struct DestinationKind {
    pub id: &'static str,
    pub label: &'static str,
    pub description: &'static str,
    pub available: bool,
    pub unavailable_reason: &'static str,
    /// True when the configuration lives in the local database as a path.
    pub stores_path: bool,
}

pub const DESTINATION_KINDS: &[DestinationKind] = &[
    DestinationKind {
        id: "local_folder",
        label: "Local folder",
        description: "Save backup files to a folder you choose on this computer.",
        available: true,
        unavailable_reason: "",
        stores_path: true,
    },
    DestinationKind {
        id: "google_drive",
        label: "Google Drive",
        description: "Save backup files to your Google Drive.",
        available: true,
        unavailable_reason: "",
        stores_path: false,
    },
];

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DestinationView {
    pub id: String,
    pub kind: String,
    pub label: String,
    pub description: String,
    pub available: bool,
    pub unavailable_reason: String,
    /// One of `configured`, `not_configured` or `unavailable`.
    pub status: String,
    /// The owner's chosen folder. Never `None` for a configured local folder.
    pub location: Option<String>,
    pub updated_at: Option<i64>,
}

/// Every destination this build supports, with its real state.
///
/// Nothing here is invented: a kind that is not available reports
/// `unavailable`, and a local folder that was never chosen reports
/// `not_configured`.
#[tauri::command]
pub fn list_backup_destinations(state: State<'_, AppState>) -> AppResult<Vec<DestinationView>> {
    require_session(&state)?;

    let conn = state.lock_db()?;
    let mut views = Vec::with_capacity(DESTINATION_KINDS.len());

    for kind in DESTINATION_KINDS {
        let stored: Option<(String, Option<String>, String, i64)> = conn
            .query_row(
                "SELECT id, location, status, updated_at FROM backup_destinations WHERE kind = ?1",
                [kind.id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;

        let stored_id = stored.as_ref().map(|(id, ..)| id.clone());

        let (status, location, updated_at) = if !kind.available {
            ("unavailable".to_string(), None, None)
        } else if !kind.stores_path {
            // Cloud destinations keep their state in the OS credential store,
            // not in SQLite. The token is authoritative: if it is gone, the
            // destination is not connected, whatever a stale row might say.
            let status = if drive::is_connected() {
                "configured"
            } else {
                "not_configured"
            };

            (
                status.to_string(),
                None,
                stored.as_ref().map(|(_, _, _, updated_at)| *updated_at),
            )
        } else {
            match stored {
                Some((_, Some(path), status, updated_at)) if status == "configured" => {
                    (status, Some(path), Some(updated_at))
                }
                Some((_, _, _, updated_at)) => {
                    // Disconnected: the remembered path is not offered, so a
                    // forgotten folder cannot look active.
                    ("not_configured".to_string(), None, Some(updated_at))
                }
                None => ("not_configured".to_string(), None, None),
            }
        };

        views.push(DestinationView {
            id: stored_id.unwrap_or_default(),
            kind: kind.id.to_string(),
            label: kind.label.to_string(),
            description: kind.description.to_string(),
            available: kind.available,
            unavailable_reason: if kind.available {
                String::new()
            } else {
                kind.unavailable_reason.to_string()
            },
            status,
            location,
            updated_at,
        });
    }

    Ok(views)
}

/// How many destinations are actually configured. Used by the dashboard.
///
/// Only destinations that store their state in SQLite are counted here; Drive
/// lives in the OS credential store, so the caller adds it from
/// [`drive::is_connected`] to avoid double counting a stale row.
pub fn configured_count(conn: &Connection) -> AppResult<u32> {
    let total: i64 = conn.query_row(
        "SELECT COUNT(*) FROM backup_destinations
         WHERE status = 'configured' AND kind = 'local_folder'",
        [],
        |row| row.get(0),
    )?;
    Ok(total as u32)
}

/// The row id of the Drive destination, creating it if this is the first
/// connection.
///
/// A row must exist for `backup_runs.destination_id` to reference. It is never
/// deleted afterwards: `backup_runs` cascades on delete, so removing the row
/// would erase the owner's history.
pub fn mark_google_drive_connected(conn: &Connection) -> AppResult<String> {
    let now = util::now_secs();

    conn.execute(
        "INSERT INTO backup_destinations (id, kind, label, location, status, created_at, updated_at)
         VALUES (?1, 'google_drive', 'Google Drive', NULL, 'configured', ?2, ?2)
         ON CONFLICT (kind) DO UPDATE SET status = 'configured',
                                         updated_at = excluded.updated_at",
        rusqlite::params![util::random_id()?.as_str(), now],
    )?;

    Ok(conn.query_row(
        "SELECT id FROM backup_destinations WHERE kind = 'google_drive'",
        [],
        |row| row.get(0),
    )?)
}

/// Mark Drive disconnected without deleting its row or the history that points
/// at it.
pub fn mark_google_drive_disconnected(conn: &Connection) -> AppResult<()> {
    conn.execute(
        "UPDATE backup_destinations
         SET status = 'disconnected', updated_at = ?1
         WHERE kind = 'google_drive'",
        [util::now_secs()],
    )?;

    Ok(())
}

/// The configured local backup folder, if one has been chosen.
pub fn local_folder(conn: &Connection) -> AppResult<Option<String>> {
    Ok(conn
        .query_row(
            "SELECT location FROM backup_destinations WHERE kind = 'local_folder' AND status = 'configured'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?)
}

/// Open the native Windows folder picker and store the chosen directory.
///
/// The path never comes from the webview: it is produced by the operating
/// system dialog and then re-validated here, exactly as
/// `commands::export_recovery_codes` does for its save dialog. Cancelling
/// reports `cancelled` and changes nothing.
#[tauri::command]
pub async fn choose_local_backup_folder(
    app: AppHandle,
    state: State<'_, AppState>,
) -> AppResult<FolderSelection> {
    require_session(&state)?;

    let dialog_handle = app.clone();
    let chosen = tauri::async_runtime::spawn_blocking(move || {
        dialog_handle
            .dialog()
            .file()
            .set_title("Choose a folder for database backups")
            .blocking_pick_folder()
    })
    .await
    .map_err(|_| AppError::internal())?;

    let Some(chosen) = chosen else {
        return Ok(FolderSelection {
            cancelled: true,
            location: None,
        });
    };

    let path = chosen
        .into_path()
        .map_err(|_| AppError::new("invalid_folder", "That folder could not be used."))?;

    // Resolve and re-check the folder. Symlinks and junctions are collapsed by
    // `canonicalize`, so what is stored is the real directory, and anything
    // that is not an existing directory is refused.
    let canonical = path.canonicalize().map_err(|_| {
        AppError::new("invalid_folder", "That folder could not be used.")
    })?;

    if !canonical.is_dir() {
        return Err(AppError::new(
            "invalid_folder",
            "BackMeUp can only save backups to a folder.",
        ));
    }

    let location = canonical.to_string_lossy().into_owned();

    save_local_folder(&state, &location)?;

    Ok(FolderSelection {
        cancelled: false,
        location: Some(location),
    })
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FolderSelection {
    pub cancelled: bool,
    pub location: Option<String>,
}

/// Upsert the single local-folder row.
fn save_local_folder(state: &AppState, location: &str) -> AppResult<()> {
    // Defence in depth: the value arrives from the OS dialog and has already
    // been canonicalised, but it is re-checked before it is persisted so a
    // relative or traversal-bearing path can never reach storage.
    if !is_plausible_location(location) {
        return Err(AppError::new(
            "invalid_folder",
            "That folder could not be used.",
        ));
    }

    let now = util::now_secs();

    let mut conn = state.lock_db()?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

    tx.execute(
        "INSERT INTO backup_destinations (id, kind, label, location, status, created_at, updated_at)
         VALUES (?1, 'local_folder', 'Local folder', ?2, 'configured', ?3, ?3)
         ON CONFLICT (kind) DO UPDATE SET location = excluded.location,
                                         status   = 'configured',
                                         updated_at = excluded.updated_at",
        rusqlite::params![util::random_id()?.as_str(), location, now],
    )?;

    // No path in the audit trail.
    db::audit_config(&tx, "destination", "created", Some("local_folder_configured"));
    tx.commit()?;

    Ok(())
}

/// Forget the local folder. The folder and its contents are untouched.
///
/// The row is marked disconnected rather than deleted: `backup_runs` references
/// it with `ON DELETE CASCADE`, so deleting it would silently erase every backup
/// record that used the folder.
#[tauri::command]
pub fn clear_local_backup_folder(state: State<'_, AppState>) -> AppResult<()> {
    require_session(&state)?;

    let mut conn = state.lock_db()?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

    let existed: Option<String> = tx
        .query_row(
            "SELECT id FROM backup_destinations WHERE kind = 'local_folder'",
            [],
            |row| row.get(0),
        )
        .optional()?;

    if existed.is_none() {
        return Err(AppError::new(
            "not_configured",
            "No local backup folder has been chosen.",
        ));
    }

    tx.execute(
        "UPDATE backup_destinations
         SET status = 'disconnected', updated_at = ?1
         WHERE kind = 'local_folder'",
        [util::now_secs()],
    )?;
    db::audit_config(&tx, "destination", "deleted", Some("local_folder_cleared"));
    tx.commit()?;

    Ok(())
}

/// Guard used on every write path: a stored location must be an absolute path
/// with no parent-directory component.
fn is_plausible_location(location: &str) -> bool {
    let path = std::path::Path::new(location);
    path.is_absolute()
        && !path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destination_ids_are_unique() {
        let mut ids: Vec<&str> = DESTINATION_KINDS.iter().map(|k| k.id).collect();
        ids.sort_unstable();
        let count = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), count, "duplicate destination id");
    }

    #[test]
    fn google_drive_is_available_and_keeps_no_path() {
        let drive = DESTINATION_KINDS
            .iter()
            .find(|k| k.id == "google_drive")
            .expect("google drive must be listed");

        assert!(drive.available, "the OAuth integration is wired up");
        assert!(drive.unavailable_reason.is_empty());
        assert!(!drive.stores_path, "a cloud provider has no local path");
    }

    #[test]
    fn local_folder_is_available_and_stores_a_path() {
        let folder = DESTINATION_KINDS
            .iter()
            .find(|k| k.id == "local_folder")
            .expect("local folder must be listed");

        assert!(folder.available);
        assert!(folder.stores_path);
    }

    #[test]
    fn locations_must_be_absolute_and_traversal_free() {
        assert!(is_plausible_location(r"C:\Backups\daily"));
        assert!(is_plausible_location(r"\\server\share\backups"));
        assert!(!is_plausible_location("relative/path"));
        assert!(!is_plausible_location(r"C:\Backups\..\Windows"));
        assert!(!is_plausible_location(r"..\..\Windows"));
        assert!(!is_plausible_location(""));

        // `Path::is_absolute` is platform dependent, so the POSIX form is only
        // meaningful on a POSIX build.
        #[cfg(unix)]
        assert!(is_plausible_location("/home/user/backups"));
    }
}
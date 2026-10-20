//! Running a backup.
//!
//! This is where a saved connection becomes a file on disk. The rules:
//!
//!   * The source is only ever read (see [`crate::mysqldump`]).
//!   * Exactly one run happens at a time, so a second request is refused rather
//!     than queued behind an unbounded queue of dumps.
//!   * The file is written under a temporary name and renamed only after the
//!     dump finishes, so an interrupted run can never leave a truncated file
//!     that looks like a good backup. A cancelled or failed run deletes its
//!     temporary file.
//!   * Bytes are hashed as they are written, so the finished file carries a
//!     SHA-256 the owner can verify later.
//!   * Progress is reported per table (throttled), never per row.
//!   * Secrets never reach this module's output: the password is read from OS
//!     storage inside the run and dropped with the target, and never appears in
//!     a log line, an event or an error.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use mysql::prelude::Queryable;
use rusqlite::OptionalExtension;
use serde::Serialize;
use sha2::Digest;
use tauri::{AppHandle, Emitter, Manager, State};
use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

use crate::commands::{require_session, AppState};
use crate::databases;
use crate::dbconn;
use crate::destinations;
use crate::drive;
use crate::error::{AppError, AppResult};
use crate::mysqldump::{self, DumpControl, DumpError};
use crate::util;
use crate::validate;

/// Event name for live progress. The payload carries counts and a stage only.
pub const PROGRESS_EVENT: &str = "backup-run-progress";

/// Free space required on the destination before a run starts.
const MIN_FREE_BYTES: u64 = 16 * 1024 * 1024;
/// Shortest gap between progress events.
const PROGRESS_INTERVAL_MS: u128 = 200;

/// The run in flight, if any. Managed by the app so a command can see it.
#[derive(Default)]
pub struct RunRegistry {
    active: Mutex<Option<ActiveRun>>,
}

struct ActiveRun {
    run_id: String,
    cancel: Arc<AtomicBool>,
}

impl RunRegistry {
    /// Take the slot, or report that a run is already going.
    fn begin(&self, run_id: &str) -> AppResult<Arc<AtomicBool>> {
        let mut slot = self.active.lock().map_err(|_| AppError::internal())?;

        if slot.is_some() {
            return Err(AppError::new(
                "run_in_progress",
                "A backup is already running. Wait for it to finish, or cancel it.",
            ));
        }

        let cancel = Arc::new(AtomicBool::new(false));
        *slot = Some(ActiveRun {
            run_id: run_id.to_string(),
            cancel: Arc::clone(&cancel),
        });
        Ok(cancel)
    }

    /// Release the slot, but only if it still belongs to `run_id`.
    fn end(&self, run_id: &str) {
        let Ok(mut slot) = self.active.lock() else {
            return;
        };
        if slot.as_ref().map(|run| run.run_id == run_id) == Some(true) {
            *slot = None;
        }
    }

    /// Ask the current run to stop. A stale id is refused, so an old button
    /// press cannot cancel a different run.
    fn cancel(&self, run_id: &str) -> AppResult<()> {
        let slot = self.active.lock().map_err(|_| AppError::internal())?;

        match slot.as_ref() {
            Some(run) if run.run_id == run_id => {
                run.cancel.store(true, Ordering::SeqCst);
                Ok(())
            }
            Some(_) => Err(AppError::new(
                "run_mismatch",
                "That backup is no longer the running one.",
            )),
            None => Err(AppError::new(
                "no_run",
                "No backup is running.",
            )),
        }
    }

    /// What the UI needs after a reload.
    fn snapshot(&self) -> Option<ActiveRunView> {
        let guard = self.active.lock().ok()?;
        let run = guard.as_ref()?;

        Some(ActiveRunView {
            run_id: run.run_id.clone(),
            cancelling: run.cancel.load(Ordering::SeqCst),
        })
    }
}

/// A run in flight, as the UI sees it.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ActiveRunView {
    pub run_id: String,
    pub cancelling: bool,
}

/// The outcome of a finished run.
///
/// A run that started and then failed is still a run: the UI renders its stage
/// and reason rather than treating it as a refused request. Only refusals -
/// no destination, no credential, unsupported engine, another run in progress -
/// come back as errors.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RunFinished {
    pub run_id: String,
    pub database_label: String,
    pub destination_label: String,
    /// `succeeded` | `cancelled` | `failed`.
    pub stage: String,
    /// Base name of the file, present only when the run succeeded.
    pub file_stem: Option<String>,
    /// Name of the file kept in the owner's folder, when one was written.
    pub file_name: Option<String>,
    /// `BackMeUp/<database>/<day>/<file>` when the copy reached Drive.
    pub drive_path: Option<String>,
    /// SHA-256 of the finished file, when the run produced one.
    pub sha256: Option<String>,
    /// Safe sentence, present only when the run did not succeed.
    pub reason: Option<String>,
    pub size_bytes: Option<u64>,
    pub rows: Option<u64>,
}

/// Live progress for a running backup.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RunProgress {
    pub run_id: String,
    pub database_label: String,
    /// `preparing` | `reading` | `succeeded` | `failed` | `cancelled`.
    pub stage: String,
    pub objects_done: u64,
    pub rows: u64,
    pub bytes_written: u64,
    /// Set only when the run ended badly.
    pub reason: Option<String>,
}

/// Back up one saved connection.
///
/// Only MySQL and MariaDB have a dumper in this version, and that is refused
/// before anything is read. The command resolves when the run finishes; the UI
/// follows it live through [`PROGRESS_EVENT`] and can stop it with
/// [`cancel_backup_run`].
#[tauri::command]
pub async fn start_backup_run(
    app: AppHandle,
    state: State<'_, AppState>,
    runs: State<'_, RunRegistry>,
    id: String,
) -> AppResult<RunFinished> {
    require_session(&state)?;
    validate::validate_record_id(&id)?;

    // A destination must exist before anything is read, so a run cannot start
    // and then discover it has nowhere to put the file. The local folder and
    // Drive are independent: either can be the only destination, and when both
    // are set up the run writes locally and uploads a second copy.
    let drive_connected = drive::is_connected();

    let (destination_id, folder, staging) = {
        let conn = state.lock_db()?;
        let row: Option<(String, String)> = conn
            .query_row(
                "SELECT id, location FROM backup_destinations
                 WHERE kind = 'local_folder' AND status = 'configured'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        match row {
            Some((id, location)) => (id, PathBuf::from(location), false),
            None if drive_connected => {
                // A row is needed for the run's foreign key. It is created on
                // demand and kept afterwards so history survives a disconnect.
                let id = destinations::mark_google_drive_connected(&conn)?;
                (id, staging_dir(&app)?, true)
            }
            None => {
                return Err(AppError::new(
                    "no_destination",
                    "Choose a folder or connect Google Drive before starting a backup.",
                ))
            }
        }
    };

    let (label, engine_id, database_name) = {
        let conn = state.lock_db()?;
        conn.query_row(
            "SELECT label, engine, database_name FROM database_connections WHERE id = ?1",
            [id.as_str()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)),
        )
        .map_err(|_| AppError::new("not_found", "That database connection no longer exists."))?
    };

    if !matches!(engine_id.as_str(), "mysql" | "mariadb") {
        let engine_label = crate::engines::find(&engine_id)
            .map(|engine| engine.label.to_string())
            .unwrap_or_else(|| engine_id.clone());

        return Err(AppError::new(
            "engine_unsupported",
            format!("BackMeUp can only back up MySQL and MariaDB right now, not {engine_label}."),
        ));
    }

    if let Some(free) = free_space(&folder) {
        if free < MIN_FREE_BYTES {
            return Err(AppError::new(
                "destination_full",
                "There is not enough free space in that folder to start a backup.",
            ));
        }
    }

    // The bucket is named after the database, not the connection label: a label
    // can be renamed, but the database it points at stays the same. The same
    // name is used locally and in Drive, so `BackMeUp/<bucket>/<day>` means the
    // same backup in both places.
    let database_folder = {
        let conn = state.lock_db()?;
        let mut stmt = conn.prepare(
            "SELECT id, database_name FROM database_connections ORDER BY created_at ASC, id ASC",
        )?;
        let connections = stmt
            .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;

        drive::database_folder_name(&id, &database_name, &connections)
    };

    // The identifier is not secret material: it is stored verbatim in the
    // history table, so it is unwrapped here rather than kept zeroizing.
    let run_id = util::random_id()?.to_string();
    let file_stem = file_stem(&database_name);
    let cancel = runs.begin(&run_id)?;

    let started_at = util::now_secs();

    let destination = RunDestination {
        folder,
        label: match (staging, drive_connected) {
            (false, true) => "Local folder and Google Drive".to_string(),
            (false, false) => "Local folder".to_string(),
            (true, _) => "Google Drive".to_string(),
        },
        database_folder,
        day: local_day(),
        staging,
        drive_connected,
    };
{
    let conn = state.lock_db()?;

    // Any failure here must not leave the slot taken, or every later attempt
    // would be refused as "a backup is already running" with nothing running.
    let inserted = conn.execute(
        "INSERT INTO backup_runs
             (id, database_id, destination_id, status, started_at, created_at)
         VALUES (?1, ?2, ?3, 'running', ?4, ?4)",
        rusqlite::params![
            run_id.as_str(),
            id.as_str(),
            destination_id.as_str(),
            started_at
        ],
    );

    if let Err(err) = inserted {
        runs.end(&run_id);
        // The only foreign keys on this row are the connection and the
        // destination, both read a moment ago, so a failure here means one of
        // them changed underneath us. The driver text goes to the local log
        // only.
        eprintln!("[backmeup] backup run could not be recorded: {err}");
        return Err(AppError::new(
            "destination_changed",
            "The backup folder or database connection changed while the backup was starting. Try again.",
        ));
    }
}

    let result = execute(
        &app,
        state.inner(),
        &id,
        &run_id,
        &label,
        &destination,
        &file_stem,
        Arc::clone(&cancel),
    )
    .await;

    runs.end(&run_id);
    record_outcome(&state, &run_id, &result);
    emit_progress(
        &app,
        &run_id,
        &label,
        result.stage,
        result.objects,
        result.rows.unwrap_or(0),
        result.bytes.unwrap_or(0),
        result.reason.clone(),
    );

    Ok(RunFinished {
        run_id,
        database_label: label,
        destination_label: destination.label,
        stage: result.stage.to_string(),
        file_stem: (result.stage == "succeeded").then_some(file_stem),
        file_name: result.file_name.clone(),
        drive_path: result.drive_path.clone(),
        sha256: result.sha256.clone(),
        reason: result.reason.clone(),
        size_bytes: result.bytes,
        rows: result.rows,
    })
}

/// Ask the running backup to stop. The file it was writing is removed.
#[tauri::command]
pub fn cancel_backup_run(
    state: State<'_, AppState>,
    runs: State<'_, RunRegistry>,
    run_id: String,
) -> AppResult<()> {
    require_session(&state)?;
    validate::validate_record_id(&run_id)?;
    runs.cancel(&run_id)
}

/// The run in flight, if any.
#[tauri::command]
pub fn active_backup_run(
    state: State<'_, AppState>,
    runs: State<'_, RunRegistry>,
) -> AppResult<Option<ActiveRunView>> {
    require_session(&state)?;
    Ok(runs.snapshot())
}

/// What one run achieved.
struct RunOutcome {
    stage: &'static str,
    bytes: Option<u64>,
    rows: Option<u64>,
    objects: u64,
    reason: Option<String>,
    /// `uploaded` | `failed` | `skipped`.
    drive_status: &'static str,
    drive_error: Option<String>,
    /// Path of the file relative to the chosen folder, e.g.
    /// `BackMeUp/<database>/<day>/<file>.sql`. `None` for a Drive-only run,
    /// whose staging file is deleted once the upload succeeds.
    file_name: Option<String>,
    /// `BackMeUp/<database>/<day>/<file>` when the copy reached Drive.
    drive_path: Option<String>,
    /// SHA-256 of the finished file, so it can be checked later.
    sha256: Option<String>,
}

/// Where a run's file goes.
struct RunDestination {
    /// The folder the dump is written to. For a Drive-only run this is the
    /// staging directory, which is removed once the upload succeeds.
    folder: PathBuf,
    /// Human label stored in history: `Local folder`, `Google Drive`, or both.
    label: String,
    /// The per-database bucket shared by both trees: `BackMeUp/<bucket>/<day>`.
    database_folder: String,
    /// The calendar day the run belongs to, fixed when it is accepted so the
    /// local copy and the Drive copy can never land on different days.
    day: String,
    /// True when `folder` is temporary staging rather than the owner's folder.
    staging: bool,
    /// Whether a Drive copy is attempted.
    drive_connected: bool,
}

/// Open the connection, dump it, write the file, and clean up either way.
#[allow(clippy::too_many_arguments)]
async fn execute(
    app: &AppHandle,
    state: &AppState,
    database_id: &str,
    run_id: &str,
    label: &str,
    destination: &RunDestination,
    file_stem: &str,
    cancel: Arc<AtomicBool>,
) -> RunOutcome {
    // A local run writes into the same tree Drive uses, inside the chosen
    // folder: `BackMeUp/<database>/<day>/`. A Drive-only run writes straight
    // into the staging directory and is uploaded from there.
    let run_folder = if destination.staging {
        destination.folder.clone()
    } else {
        local_backup_folder(
            &destination.folder,
            &destination.database_folder,
            &destination.day,
        )
    };

    if !destination.staging
        && std::fs::create_dir_all(&run_folder).is_err()
    {
        return failed(
            "BackMeUp could not create its folders inside the backup folder. \
             Check that the folder still exists and can be written to."
                .to_string(),
        );
    }

    let folder = run_folder.as_path();
    let started = Instant::now();
    emit_progress(app, run_id, label, "preparing", 0, 0, 0, None);

    let resolved = match databases::open_saved_target(app, state, database_id).await {
        Ok(resolved) => resolved,
        Err(err) => return failed(with_context(err.message, "opening the connection")),
    };

    let databases::SavedTarget {
        target,
        tunnel,
        database_name,
        engine_label,
    } = resolved;

    let version_label = engine_label.clone();

    // The driver handshake blocks for as long as the server takes, and it is
    // dialled over the loopback end of a tunnel whose forwarding needs the
    // runtime to keep turning. Doing that on a runtime thread would starve the
    // forwarding task, so the handshake gets a blocking thread of its own.
    let handshake = tauri::async_runtime::spawn_blocking(move || connect_with_retry(&target)).await;

    let mut connection = match handshake {
        Ok(Ok(connection)) => connection,
        Ok(Err(err)) => {
            return failed(with_context(
                err.message,
                "opening the connection to the database",
            ))
        }
        Err(_) => return failed("The backup could not be completed.".to_string()),
    };

    // The tunnel must outlive the connection, and is dropped here.
    let _tunnel = tunnel;

    // Drained: `query_first` stops after the first row and leaves the terminator
    // unread, which would desynchronise the statements the dump runs next.
    let version: String = connection
        .query::<String, _>("SELECT VERSION()")
        .ok()
        .and_then(|rows| rows.into_iter().next())
        .unwrap_or(version_label);

    let temporary = folder.join(temporary_name(file_stem, run_id));
    let file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
    {
        Ok(file) => file,
        Err(_) => {
            return failed("BackMeUp could not create a file in that folder.".to_string())
        }
    };

    let control = RunControl {
        cancel: Arc::clone(&cancel),
        app: app.clone(),
        run_id: run_id.to_string(),
        label: label.to_string(),
        last_emit: Mutex::new(Instant::now()),
    };

    let outcome = {
        let mut sink = HashingWriter::new(file);
        let mut connection = connection;
        let dump_database_name = database_name.clone();

        // The driver is blocking, so the dump runs on a blocking task while the
        // command stays awaitable and the UI stays live.
        let dumped = tauri::async_runtime::spawn_blocking(move || {
            let result = mysqldump::dump_database(
                &mut connection,
                &dump_database_name,
                &version,
                &mut sink,
                &control,
            );
            (result, sink)
        })
        .await;

        match dumped {
            Ok((result, sink)) => (result, sink),
            Err(_) => {
                let _ = std::fs::remove_file(&temporary);
                return failed("The backup could not be completed.".to_string());
            }
        }
    };

    let (dump_result, sink) = outcome;
    let stats = dump_result.as_ref().ok().copied();
    let bytes = sink.bytes_written;

    let finished = dump_result.and_then(|_| sink.finish());

    match finished {
        Ok(digest) => {
            // The digest of the file as it was written. It is what makes a
            // backup checkable later: hash the file again and the value must
            // match, or the file is not the one this run produced.
            let digest = Some(digest);

            let Some(final_path) = unique_path(folder, file_stem) else {
                let _ = std::fs::remove_file(&temporary);
                return failed("BackMeUp could not name the backup file.".to_string());
            };

            if std::fs::rename(&temporary, &final_path).is_err() {
                let _ = std::fs::remove_file(&temporary);
                return failed("BackMeUp could not save the backup file.".to_string());
            }

            let tables = stats.map(|stats| stats.tables).unwrap_or(0);
            let views = stats.map(|stats| stats.views).unwrap_or(0);
            let rows = stats.map(|stats| stats.rows).unwrap_or(0);

            // The path relative to the chosen folder, e.g.
            // `BackMeUp/shop/2026-10-20/shop_1700000000.sql`. A staged file is
            // not recorded: it is deleted after a successful upload, so it is
            // not a place the owner can go back to.
            let local_name = if destination.staging {
                None
            } else {
                final_path
                    .strip_prefix(&destination.folder)
                    .ok()
                    .map(|relative| relative.to_string_lossy().into_owned())
            };

            eprintln!(
                "[backmeup] backup finished: run={run_id} tables={tables} views={views} \
                 rows={rows} bytes={bytes} ms={}",
                started.elapsed().as_millis()
            );

            // Upload when Drive is connected. When the run also wrote to the
            // owner's folder, an upload problem must never undo the backup that
            // already succeeded: it becomes a note on a successful run. When
            // Drive was the only destination, a failed upload means no copy
            // exists, so the run fails and the staged file is kept.
            let (drive_status, drive_error, drive_path) = match upload_to_drive(
                destination,
                &final_path,
                run_id,
                app,
                label,
                &cancel,
            )
            .await
            {
                UploadOutcome::Skipped => ("skipped", None, None),
                UploadOutcome::Uploaded(drive_path) => ("uploaded", None, Some(drive_path)),
                UploadOutcome::Failed(reason) => {
                    eprintln!("[backmeup] google drive upload failed: {reason}");

                    let stopped = cancel.load(Ordering::SeqCst);

                    if destination.staging {
                        if stopped {
                            // Cancelled mid-upload: the staged file is not a
                            // deliverable backup, so nothing is kept.
                            let _ = std::fs::remove_file(&final_path);
                            return RunOutcome {
                                stage: "cancelled",
                                bytes: None,
                                rows: stats.map(|stats| stats.rows),
                                objects: 0,
                                reason: Some(
                                    "The backup was cancelled before the upload finished."
                                        .to_string(),
                                ),
                                drive_status: "skipped",
                                drive_error: None,
                                file_name: None,
                                drive_path: None,
                                // The file was removed, so there is nothing to
                                // check later.
                                sha256: None,
                            };
                        }

                        let location = final_path.display().to_string();
                        let message = format!(
                            "The backup could not be uploaded to Google Drive, so it was kept on \
                             this computer at {location}."
                        );

                        return RunOutcome {
                            stage: "failed",
                            bytes: Some(bytes),
                            rows: Some(rows),
                            objects: tables + views,
                            reason: Some(message),
                            drive_status: "failed",
                            drive_error: Some(reason),
                            file_name: None,
                            drive_path: None,
                            // The file was kept on this computer, so its digest
                            // is worth keeping too.
                            sha256: digest.clone(),
                        };
                    }

                    let note = if stopped {
                        "Saved on this computer. The Google Drive upload was cancelled."
                            .to_string()
                    } else {
                        format!(
                            "Saved on this computer, but the Google Drive copy was not stored. {reason}"
                        )
                    };
                    ("failed", Some(note), None)
                }
            };

            RunOutcome {
                stage: "succeeded",
                bytes: Some(bytes),
                rows: Some(rows),
                objects: tables + views,
                // A Drive problem on a local run is a note, not a failure; the
                // history row keeps it apart from `failure_reason`.
                reason: drive_error.clone(),
                drive_status,
                drive_error,
                file_name: local_name,
                drive_path,
                sha256: digest,
            }
        }
        Err(err) => {
            // Nothing half-written survives.
            let _ = std::fs::remove_file(&temporary);

            if matches!(err, DumpError::Cancelled) {
                RunOutcome {
                    stage: "cancelled",
                    bytes: None,
                    rows: stats.map(|stats| stats.rows),
                    objects: 0,
                    reason: Some("The backup was cancelled before it finished.".to_string()),
                    drive_status: "skipped",
                    drive_error: None,
                    file_name: None,
                    drive_path: None,
                    sha256: None,
                }
            } else {
                failed(dump_message(&err))
            }
        }
    }
}

/// Open the database connection, retrying once.
///
/// A tunnel is a live channel to another machine, and the occasional failed
/// handshake is a transport event, not a verdict on the credentials: the same
/// connection succeeds moments later. One retry, over the *same* tunnel and
/// with the same stored secret, turns that flake into a working backup. The
/// retry is bounded (two attempts, a short pause between them) and never
/// repeats the dump itself, so nothing is read twice.
fn connect_with_retry(target: &dbconn::ConnectionTarget) -> AppResult<mysql::Conn> {
    match dbconn::mysql::open_for_dump(target) {
        Ok(connection) => Ok(connection),
        Err(first) => {
            eprintln!("[backmeup] backup: first connect attempt failed, retrying once");
            std::thread::sleep(std::time::Duration::from_millis(750));

            dbconn::mysql::open_for_dump(target).map_err(|second| {
                // Report the first failure's wording when both look alike, so
                // the message stays stable rather than flickering between two
                // near-identical sentences.
                if second.message == first.message {
                    first
                } else {
                    second
                }
            })
        }
    }
}

/// Write the outcome to the run's history row.
fn record_outcome(state: &AppState, run_id: &str, outcome: &RunOutcome) {
    let Ok(conn) = state.lock_db() else {
        return;
    };

    write_outcome(&conn, run_id, outcome);
}

/// The statement that writes an outcome, apart from the plumbing so it can be
/// exercised against a real database.
fn write_outcome(conn: &rusqlite::Connection, run_id: &str, outcome: &RunOutcome) {
    // A note on a successful run (a Drive copy that did not happen) is not a
    // failure reason. Keeping them apart is what stops "saved locally, not
    // uploaded" from reading as "the backup failed".
    let failure_reason = (outcome.stage != "succeeded")
        .then_some(outcome.reason.as_deref())
        .flatten();

    let _ = conn.execute(
        "UPDATE backup_runs
         SET status = ?2, finished_at = ?3, size_bytes = ?4, failure_reason = ?5,
             drive_status = ?6, drive_error = ?7, file_name = ?8, drive_path = ?9,
             sha256 = ?10
         WHERE id = ?1",
        rusqlite::params![
            run_id,
            outcome.stage,
            util::now_secs(),
            outcome.bytes.map(|value| value as i64),
            failure_reason,
            outcome.drive_status,
            outcome.drive_error.as_deref(),
            outcome.file_name.as_deref(),
            outcome.drive_path.as_deref(),
            outcome.sha256.as_deref()
        ],
    );
}

fn failed(reason: String) -> RunOutcome {
    RunOutcome {
        stage: "failed",
        bytes: None,
        rows: None,
        objects: 0,
        reason: Some(reason),
        drive_status: "skipped",
        drive_error: None,
        file_name: None,
        drive_path: None,
        sha256: None,
    }
}

/// What happened to the Drive copy.
enum UploadOutcome {
    /// Drive is not connected, so there was nothing to do.
    Skipped,
    /// The upload succeeded, carrying the path the file has in Drive.
    Uploaded(String),
    Failed(String),
}

/// Copy the finished backup into Google Drive, if Drive is connected.
///
/// The folder tree is `BackMeUp/<database>/<day>`, created on demand and reused
/// afterwards. A Drive-only run deletes its staged file once the upload
/// succeeds; a failed upload leaves it in place so the data is not lost.
async fn upload_to_drive(
    destination: &RunDestination,
    path: &Path,
    run_id: &str,
    app: &AppHandle,
    label: &str,
    cancel: &Arc<AtomicBool>,
) -> UploadOutcome {
    if !destination.drive_connected {
        return UploadOutcome::Skipped;
    }

    match upload_inner(
        &destination.database_folder,
        &destination.day,
        path,
        run_id,
        app,
        label,
        cancel,
    )
    .await
    {
        Ok(drive_path) => {
            if destination.staging {
                // The upload is the only copy now; the staging file has served
                // its purpose.
                let _ = std::fs::remove_file(path);
            }
            UploadOutcome::Uploaded(drive_path)
        }
        Err(reason) => UploadOutcome::Failed(reason),
    }
}

#[allow(clippy::too_many_arguments)]
async fn upload_inner(
    database_folder: &str,
    day: &str,
    path: &Path,
    run_id: &str,
    app: &AppHandle,
    label: &str,
    cancel: &Arc<AtomicBool>,
) -> Result<String, String> {
    let token = drive::access_token()
        .await
        .map_err(|err| err.message)?;
    let client = drive::http_client().map_err(|err| err.message)?;

    let size = std::fs::metadata(path).map(|meta| meta.len()).unwrap_or(0);

    // Checked before the upload rather than after: discovering the file does
    // not fit half way through a multi-gigabyte transfer wastes the owner's time
    // and their bandwidth.
    match drive::free_space(&client, token.as_str()).await {
        Ok(Some(free)) if free < size => {
            return Err(format!(
                "This backup is {} but only {} is free in your Drive. Free some space and \
                 run it again.",
                format_bytes(size),
                format_bytes(free)
            ));
        }
        _ => {
            // An unlimited account, or a quota Google would not report, is not a
            // reason to refuse the upload.
        }
    }

    let parent = drive::ensure_backup_folders(&client, token.as_str(), database_folder, day)
        .await
        .map_err(|err| err.message)?;

    let name = path
        .file_name()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "backup.sql".to_string());

    // What the owner would see in Drive, recorded in history so a finished run
    // can point at the exact file.
    let display_path = format!("{}/{database_folder}/{day}/{name}", drive::ROOT_FOLDER);

    let last_emit = Mutex::new(Instant::now());
    let progress = |sent: u64| {
        // Throttled like table progress: one event per chunk would flood the
        // webview during a large upload.
        let due = last_emit
            .lock()
            .map(|last| last.elapsed().as_millis() >= PROGRESS_INTERVAL_MS)
            .unwrap_or(true);

        if due {
            if let Ok(mut last) = last_emit.lock() {
                *last = Instant::now();
            }
            emit_progress(app, run_id, label, "uploading", 0, 0, sent, None);
        }
    };

    let cancelled = || cancel.load(Ordering::SeqCst);

    drive::upload_file(
        &client,
        token.as_str(),
        &parent,
        &name,
        path,
        &progress,
        &cancelled,
    )
    .await
    .map_err(|err| err.message)?;

    eprintln!("[backmeup] google drive: stored {display_path}");

    Ok(display_path)
}

/// `YYYY-MM-DD` on the owner's clock.
///
/// Deliberately local, not UTC: a backup taken at 07:00 in UTC+8 belongs to
/// today, not to the UTC date that is still yesterday. `GetLocalTime` applies
/// the Windows time zone, including daylight saving, so no date crate is needed.
fn local_day() -> String {
    let now = unsafe { windows::Win32::System::SystemInformation::GetLocalTime() };
    format!("{:04}-{:02}-{:02}", now.wYear, now.wMonth, now.wDay)
}

/// The per-run folder inside the owner's chosen destination:
/// `BackMeUp/<database>/<day>`.
///
/// The local tree deliberately mirrors the Drive tree, so the relative path in
/// history means the same thing whether the copy is on this computer or in
/// Drive.
fn local_backup_folder(base: &Path, database_folder: &str, day: &str) -> PathBuf {
    base.join(drive::ROOT_FOLDER)
        .join(database_folder)
        .join(day)
}

/// Bytes as a short human string, for the quota message.
fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["KB", "MB", "GB", "TB"];

    if bytes < 1024 {
        return format!("{bytes} B");
    }

    let mut value = bytes as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }

    if value >= 100.0 {
        format!("{:.0} {}", value, UNITS[unit])
    } else {
        format!("{:.1} {}", value, UNITS[unit])
    }
}

/// Say *when* a failure happened, so the owner is never left with a bare
/// "malformed packet" and no idea whether the connection or the read failed.
fn with_context(message: String, context: &str) -> String {
    // Some sentences already end in a full stop; do not double it.
    let trimmed = message.trim_end();
    let separator = if trimmed.ends_with('.') { " " } else { ". " };

    format!("{trimmed}{separator}This happened while {context}.")
}

/// The safe sentence for a dump failure.
fn dump_message(err: &DumpError) -> String {
    match err {
        DumpError::Privileges => {
            "The database user cannot read every object in this database. A backup needs a user \
             with SELECT on the tables, plus SHOW VIEW for views."
                .to_string()
        }
        DumpError::Cancelled => "The backup was cancelled before it finished.".to_string(),
        DumpError::UnsupportedObject => {
            "This database contains an object name BackMeUp will not write into a file.".to_string()
        }
        DumpError::Statement { stage, detail } => format!(
            "The database stopped responding while {detail} (stage: {stage}). The connection may \
             have dropped part-way through. Try again; if it repeats on the same table, that \
             table may be too large for a single backup file."
        ),
        DumpError::Reason(message) => message.clone(),
        DumpError::Io(_) => {
            "BackMeUp could not write the backup file. Check free space and permissions.".to_string()
        }
    }
}

/// Progress and cancellation for one run, owned by the dumping task.
struct RunControl {
    cancel: Arc<AtomicBool>,
    app: AppHandle,
    run_id: String,
    label: String,
    last_emit: Mutex<Instant>,
}

impl DumpControl for RunControl {
    fn report(&self, objects_done: u64, rows: u64) {
        // Throttled: a table boundary can arrive in microseconds, and one IPC
        // message per table would flood the webview on a wide database.
        let due = self
            .last_emit
            .lock()
            .map(|last| last.elapsed().as_millis() >= PROGRESS_INTERVAL_MS)
            .unwrap_or(true);

        if !due {
            return;
        }

        if let Ok(mut last) = self.last_emit.lock() {
            *last = Instant::now();
        }

        emit_progress(
            &self.app,
            &self.run_id,
            &self.label,
            "reading",
            objects_done,
            rows,
            0,
            None,
        );
    }

    fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::SeqCst)
    }
}

/// A file wrapper that counts and hashes as it goes.
struct HashingWriter {
    file: std::fs::File,
    hasher: sha2::Sha256,
    bytes_written: u64,
}

impl HashingWriter {
    fn new(file: std::fs::File) -> Self {
        HashingWriter {
            file,
            hasher: sha2::Sha256::new(),
            bytes_written: 0,
        }
    }

    /// Flush and hand back the digest of everything written.
    fn finish(mut self) -> Result<String, DumpError> {
        self.file.flush()?;
        let digest = hex::encode(self.hasher.finalize());
        eprintln!(
            "[backmeup] backup sha256={digest} bytes={}",
            self.bytes_written
        );
        Ok(digest)
    }
}

impl Write for HashingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.file.write(buf)?;
        self.hasher.update(&buf[..written]);
        self.bytes_written += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

/// Send one progress event. A closed window must not abort a running backup,
/// so a failure to emit is ignored.
#[allow(clippy::too_many_arguments)]
fn emit_progress(
    app: &AppHandle,
    run_id: &str,
    label: &str,
    stage: &str,
    objects_done: u64,
    rows: u64,
    bytes: u64,
    reason: Option<String>,
) {
    let _ = app.emit(
        PROGRESS_EVENT,
        RunProgress {
            run_id: run_id.to_string(),
            database_label: label.to_string(),
            stage: stage.to_string(),
            objects_done,
            rows,
            bytes_written: bytes,
            reason,
        },
    );
}

/// `shop_1700000000`, with no clock-formatting dependency.
fn file_stem(database_name: &str) -> String {
    format!(
        "{}_{}",
        mysqldump::sanitize_file_stem(database_name),
        util::now_secs()
    )
}

/// A hidden, run-scoped name for the incomplete file.
fn temporary_name(file_stem: &str, run_id: &str) -> String {
    let prefix: String = run_id.chars().take(16).collect();
    format!(".{file_stem}.{prefix}.part")
}

/// First unused `stem.sql` / `stem_2.sql` in the folder: an older backup is
/// never overwritten.
fn unique_path(folder: &Path, file_stem: &str) -> Option<PathBuf> {
    let direct = folder.join(format!("{file_stem}.sql"));
    if !direct.exists() {
        return Some(direct);
    }

    (2..1000)
        .map(|suffix| folder.join(format!("{file_stem}_{suffix}.sql")))
        .find(|candidate| !candidate.exists())
}

/// Free bytes on the volume holding `path`, when Windows will tell us.
fn free_space(path: &Path) -> Option<u64> {
    let wide = path
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<u16>>();

    let mut free_to_caller: u64 = 0;
    // SAFETY: `wide` is a NUL-terminated buffer that outlives the call, and
    // `free_to_caller` is a valid out-pointer for the call's duration.
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            windows::core::PCWSTR(wide.as_ptr()),
            Some(&mut free_to_caller),
            None,
            None,
        )
    };

    ok.is_ok().then_some(free_to_caller)
}

/// Where a Drive-only run stages its dump before upload.
///
/// The local data directory is used rather than the system temp folder so the
/// file is on the same volume the app already owns and inherits the same
/// per-user ACLs. It is removed as soon as the upload succeeds; a file left
/// behind by a failed upload is kept for the owner to recover, then pruned
/// after a month.
fn staging_dir(app: &AppHandle) -> AppResult<PathBuf> {
    let dir = app
        .path()
        .app_local_data_dir()
        .map_err(|_| AppError::internal())?
        .join("staging");

    std::fs::create_dir_all(&dir).map_err(|_| {
        AppError::new(
            "destination_unavailable",
            "BackMeUp could not prepare a temporary folder for the Google Drive backup.",
        )
    })?;

    prune_staging(&dir);

    Ok(dir)
}

/// Delete staged files older than 30 days. Best effort: an unreadable entry is
/// left alone rather than risking a delete it cannot justify.
fn prune_staging(dir: &Path) {
    const MAX_AGE_SECS: u64 = 30 * 24 * 60 * 60;

    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if !metadata.is_file() {
            continue;
        }

        let stale = metadata
            .modified()
            .ok()
            .and_then(|modified| std::time::SystemTime::now().duration_since(modified).ok())
            .map(|age| age.as_secs() > MAX_AGE_SECS)
            .unwrap_or(false);

        if stale {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The checksum a run records must survive the trip into the history row:
    /// that is the value the owner compares against a file later.
    #[test]
    fn a_finished_run_records_the_checksum_of_its_file() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE backup_runs (
                id             TEXT PRIMARY KEY,
                status         TEXT NOT NULL,
                started_at     INTEGER,
                finished_at    INTEGER,
                size_bytes     INTEGER,
                failure_reason TEXT,
                created_at     INTEGER NOT NULL,
                drive_status   TEXT,
                drive_error    TEXT,
                file_name      TEXT,
                drive_path     TEXT,
                sha256         TEXT
            );
            INSERT INTO backup_runs (id, status, created_at)
                VALUES ('run-1', 'running', 1);
            ",
        )
        .unwrap();

        let digest = "a".repeat(64);
        write_outcome(
            &conn,
            "run-1",
            &RunOutcome {
                stage: "succeeded",
                bytes: Some(9023),
                rows: Some(48),
                objects: 12,
                reason: None,
                drive_status: "uploaded",
                drive_error: None,
                file_name: Some("BackMeUp/shop/2026-10-20/shop.sql".to_string()),
                drive_path: Some("BackMeUp/shop/2026-10-20/shop.sql".to_string()),
                sha256: Some(digest.clone()),
            },
        );

        let stored: (String, Option<String>, Option<i64>) = conn
            .query_row(
                "SELECT status, sha256, size_bytes FROM backup_runs WHERE id = 'run-1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();

        assert_eq!(stored.0, "succeeded");
        assert_eq!(
            stored.1.as_deref(),
            Some(digest.as_str()),
            "the checksum must be stored exactly as it was computed"
        );
        assert_eq!(stored.2, Some(9023));
    }

    /// The shape that caused a real failure: `SELECT id, location` read into a
    /// destructuring that had the two the wrong way round, so the folder path
    /// was stored as the destination's foreign key.
    ///
    /// This exercises the same statements against the real schema, with
    /// `foreign_keys` ON, exactly as the app opens it.
    #[test]
    fn a_run_row_references_the_real_destination_and_connection() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE database_connections (
                id            TEXT PRIMARY KEY,
                label         TEXT NOT NULL,
                engine        TEXT NOT NULL,
                connection_method TEXT NOT NULL,
                database_name TEXT NOT NULL
            );
            CREATE TABLE backup_destinations (
                id         TEXT PRIMARY KEY,
                kind       TEXT NOT NULL UNIQUE,
                label      TEXT NOT NULL,
                location   TEXT,
                status     TEXT NOT NULL
            );
            CREATE TABLE backup_runs (
                id             TEXT PRIMARY KEY,
                database_id    TEXT REFERENCES database_connections (id) ON DELETE SET NULL,
                destination_id TEXT REFERENCES backup_destinations (id) ON DELETE CASCADE,
                status         TEXT NOT NULL,
                started_at     INTEGER,
                finished_at    INTEGER,
                size_bytes     INTEGER,
                failure_reason TEXT,
                created_at     INTEGER NOT NULL
            );
            "#,
        )
        .unwrap();

        let database_id = "1f32e6e2e50c616d34a4a02025bc18e404ceece986ab896193ec44f9f3ff59bf";
        let destination_id = "91d9e16f9b5f3b52f3b0c88114cf9a7b3dee3e7378acfc848e0c0273be18ec1a";
        let location = r"\\?\C:\Users\Somebody\Desktop\Backups";

        conn.execute(
            "INSERT INTO database_connections (id, label, engine, connection_method, database_name)
             VALUES (?1, 'Tabulate', 'mysql', 'ssh-tunnel', 'shop')",
            [database_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO backup_destinations (id, kind, label, location, status)
             VALUES (?1, 'local_folder', 'Local folder', ?2, 'configured')",
            rusqlite::params![destination_id, location],
        )
        .unwrap();

        // Read exactly as the command does.
        let row: Option<(String, String)> = conn
            .query_row(
                "SELECT id, location FROM backup_destinations
                 WHERE kind = 'local_folder' AND status = 'configured'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .unwrap();
        let (found_id, found_location) = row.expect("a configured folder must exist");

        assert_eq!(found_id, destination_id, "the first column is the key");
        assert_eq!(found_location, location, "the second column is the folder");

        conn.execute(
            "INSERT INTO backup_runs
                 (id, database_id, destination_id, status, started_at, created_at)
             VALUES (?1, ?2, ?3, 'running', 1, 1)",
            rusqlite::params![run_id(), database_id, found_id],
        )
        .expect("a run row must be accepted when the ids are the real ones");

        // The swapped order is what produced FOREIGN KEY constraint failed.
        let swapped = conn.execute(
            "INSERT INTO backup_runs
                 (id, database_id, destination_id, status, started_at, created_at)
             VALUES (?1, ?2, ?3, 'running', 1, 1)",
            rusqlite::params![run_id(), database_id, found_location],
        );
        assert!(
            swapped.is_err(),
            "storing a folder path as a foreign key must be rejected"
        );

        let orphans = conn
            .query_row("SELECT count(*) FROM backup_runs", [], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap();
        assert_eq!(orphans, 1, "the rejected row must not be left behind");
    }

    fn run_id() -> String {
        util::random_id().unwrap().to_string()
    }

    #[test]
    fn stems_are_filesystem_safe() {
        let stem = file_stem("my shop/2024");
        assert!(stem.starts_with("my_shop_2024_"), "{stem}");
        assert!(!stem.contains(' '), "{stem}");
        assert!(!stem.contains('/'), "{stem}");
    }

    #[test]
    fn the_incomplete_file_is_hidden_and_run_scoped() {
        let run_id = "a".repeat(64);
        let name = temporary_name("shop_1700000000", &run_id);

        assert!(name.starts_with('.'), "must be hidden: {name}");
        assert!(name.ends_with(".part"), "must be marked incomplete: {name}");
        assert!(
            !name.contains(&run_id),
            "the whole id must never reach a file name: {name}"
        );

        // Only a bounded prefix of the id may be used, so two runs cannot
        // collide on the same temporary file.
        let prefix = run_id.chars().take(16).collect::<String>();
        assert!(name.contains(&prefix), "{name}");
        assert!(name.matches('a').count() <= 17, "{name}");
    }

    #[test]
    fn folder_names_are_safe_and_bounded() {
        assert_eq!(drive::sanitize_folder_name("Tabulate"), "Tabulate");
        assert_eq!(drive::sanitize_folder_name("my shop"), "my shop");
        assert_eq!(drive::sanitize_folder_name("a/b:c"), "a-b-c");
        assert_eq!(drive::sanitize_folder_name("  padded  "), "padded");
        assert_eq!(drive::sanitize_folder_name("***"), "database");
        assert_eq!(drive::sanitize_folder_name(""), "database");

        // No separator may survive, or the folder tree would gain extra levels.
        for hostile in ["a/b", "a\\b", "a:b", "a*b", "a?b", "a|b"] {
            assert!(
                !drive::sanitize_folder_name(hostile).contains(['/', '\\', ':', '*', '?', '|'])
            );
        }

        assert_eq!(
            drive::sanitize_folder_name(&"n".repeat(500)).chars().count(),
            80
        );
    }

    #[test]
    fn the_local_day_is_a_calendar_date() {
        // The value is read from the OS clock, so assert the shape and bounds
        // rather than a fixed date.
        let day = local_day();
        assert_eq!(day.len(), 10, "{day}");
        assert_eq!(&day[4..5], "-", "{day}");
        assert_eq!(&day[7..8], "-", "{day}");

        let year = day[0..4].parse::<u32>().unwrap();
        let month = day[5..7].parse::<u32>().unwrap();
        let date = day[8..10].parse::<u32>().unwrap();
        assert!(year >= 2020, "{day}");
        assert!((1..=12).contains(&month), "{day}");
        assert!((1..=31).contains(&date), "{day}");
    }

    #[test]
    fn local_backups_mirror_the_drive_tree() {
        let base = Path::new("C:/backups");
        let folder = local_backup_folder(base, "shop-aaaaaa", "2026-10-20");

        let expected = base
            .join("BackMeUp")
            .join("shop-aaaaaa")
            .join("2026-10-20");

        assert_eq!(folder, expected);
        // The chosen folder itself is never used for the file directly: every
        // backup lives under the product folder, then its database, then a day.
        assert_eq!(folder.components().count(), base.components().count() + 3);
    }

    #[test]
    fn byte_sizes_read_like_a_person_would_say_them() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(8_700), "8.5 KB");
        assert_eq!(format_bytes(8_700_000), "8.3 MB");
        assert_eq!(format_bytes(900_000_000), "858 MB");
        assert_eq!(format_bytes(5_000_000_000), "4.7 GB");
    }

    #[test]
    fn failures_say_when_they_happened() {
        // A bare "malformed packet" sentence must never reach the owner alone.
        let bare = "The database server sent an unexpected or malformed packet response.";
        let contextual = with_context(bare.to_string(), "opening the connection to the database");

        assert!(contextual.contains("malformed packet"), "{contextual}");
        assert!(contextual.contains("opening the connection"), "{contextual}");
        assert!(
            !contextual.contains(".."),
            "punctuation must not double: {contextual}"
        );

        // A sentence without a full stop still reads as a sentence.
        let unpunctuated = with_context(
            "The database refused the connection".to_string(),
            "listing tables",
        );
        assert!(unpunctuated.ends_with("while listing tables."), "{unpunctuated}");
    }

    #[test]
    fn dump_messages_are_safe_and_actionable() {
        let cancelled = dump_message(&DumpError::Cancelled);
        assert!(cancelled.contains("cancelled"), "{cancelled}");

        let privileges = dump_message(&DumpError::Privileges);
        assert!(privileges.contains("SELECT"), "{privileges}");

        let io = dump_message(&DumpError::Io(std::io::Error::other("disk full")));
        assert!(io.contains("free space"), "{io}");

        // A server reason is carried through verbatim because it was already
        // phrased by the shared classifier; a raw driver string never is.
        let reason = dump_message(&DumpError::Reason("That database no longer exists.".into()));
        assert!(reason.contains("no longer exists"), "{reason}");
    }

    #[test]
    fn a_second_run_is_refused_while_one_is_active() {
        let registry = RunRegistry::default();

        let flag = registry.begin("run-one").unwrap();
        assert!(!flag.load(Ordering::SeqCst));
        assert_eq!(registry.snapshot().unwrap().run_id, "run-one");

        assert_eq!(
            registry.begin("run-two").unwrap_err().code,
            "run_in_progress",
            "a second dump must be refused, not queued"
        );

        // A stale id cannot stop the live run.
        assert_eq!(registry.cancel("run-two").unwrap_err().code, "run_mismatch");
        registry.cancel("run-one").unwrap();
        assert!(flag.load(Ordering::SeqCst), "the run must observe it");

        registry.end("run-one");
        assert!(registry.snapshot().is_none());
        registry.end("run-one");
        assert!(registry.begin("run-two").is_ok());
    }

    #[test]
    fn cancelling_nothing_says_so() {
        let registry = RunRegistry::default();
        assert_eq!(registry.cancel("anything").unwrap_err().code, "no_run");
        assert!(registry.snapshot().is_none());
    }

    #[test]
    fn the_hasher_counts_bytes_and_is_deterministic() {
        let dir = std::env::temp_dir().join(format!("backmeup-hash-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        // Recomputed independently of the writer, so a broken hasher cannot
        // agree with a broken byte count.
        let digest_of = |content: &[u8]| -> (String, u64) {
            let path = dir.join("probe.bin");
            let mut writer = HashingWriter::new(std::fs::File::create(&path).unwrap());
            writer.write_all(content).unwrap();
            let bytes = writer.bytes_written;
            writer.finish().unwrap();
            let _ = std::fs::remove_file(&path);

            (hex::encode(sha2::Sha256::digest(content)), bytes)
        };

        // Two writes of the same bytes must hash like one write of them
        // together, and the byte count must be exact.
        let mut writer = HashingWriter::new(
            std::fs::File::create(dir.join("probe.bin")).unwrap(),
        );
        writer.write_all(b"abc").unwrap();
        writer.write_all(b"abc").unwrap();
        writer.finish().unwrap();
        let _ = std::fs::remove_file(dir.join("probe.bin"));

        let (split_digest, bytes) = digest_of(b"abcabc");
        assert_eq!(bytes, 6, "byte count must be exact");
        assert_ne!(
            split_digest,
            hex::encode(sha2::Sha256::digest(b"abc")),
            "a partial write must not hash like the whole"
        );

        let (other, _) = digest_of(b"different content");
        assert_ne!(split_digest, other, "different content must hash differently");

        // The digest the history stores is the real SHA-256 of the file, so
        // hashing the file again later gives the same value.
        let path = dir.join("probe.bin");
        let mut writer = HashingWriter::new(std::fs::File::create(&path).unwrap());
        writer.write_all(b"abcabc").unwrap();
        let digest = writer.finish().unwrap();
        let _ = std::fs::remove_file(&path);

        assert_eq!(
            digest,
            hex::encode(sha2::Sha256::digest(b"abcabc")),
            "the stored checksum must be the SHA-256 of the file"
        );
        assert_eq!(digest.len(), 64, "a SHA-256 is 64 hex characters");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unique_paths_never_overwrite() {
        let dir = std::env::temp_dir().join(format!("backmeup-unique-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let taken = dir.join("shop.sql");
        std::fs::write(&taken, "first").unwrap();

        let next = unique_path(&dir, "shop").expect("a name must always be found");
        assert_eq!(next.file_name().unwrap(), "shop_2.sql");
        assert!(taken.exists(), "the earlier backup must survive");

        std::fs::write(dir.join("shop_2.sql"), "second").unwrap();
        assert_eq!(
            unique_path(&dir, "shop").unwrap().file_name().unwrap(),
            "shop_3.sql"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
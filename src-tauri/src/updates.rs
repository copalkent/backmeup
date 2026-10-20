//! Checking for a new version, and installing it.
//!
//! The check is a single read of one small JSON file that the project
//! publishes with every release. It is quiet by design:
//!
//!   * it happens at most once a day, and never during a backup;
//!   * a failure is silence - an offline machine, or a GitHub that is down,
//!     must not turn into an error the account has to dismiss;
//!   * nothing is sent but the request for that file.
//!
//! The update itself is signed. The public half of the signing key is in
//! `tauri.conf.json`; the private half never leaves the machine that made the
//! release.

use serde::Serialize;
use tauri::{AppHandle, State};
use tauri_plugin_updater::UpdaterExt;

use crate::commands::{require_session, AppState};
use crate::db;
use crate::error::{AppError, AppResult};

/// The version last shown.
const SETTING_LATEST_VERSION: &str = "update.latest_version";
/// The notes that came with it.
const SETTING_LATEST_NOTES: &str = "update.latest_notes";
/// When it was published.
const SETTING_LATEST_DATE: &str = "update.latest_date";
/// When the app last looked.
const SETTING_LAST_CHECK: &str = "update.last_check_at";
/// The version not to be reminded about again.
const SETTING_DISMISSED: &str = "update.dismissed_version";

/// How often the app is allowed to ask.
const CHECK_INTERVAL_SECS: i64 = 24 * 60 * 60;

/// What the app knows about a newer version.
#[derive(Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    /// The newest version published, if one has been seen.
    pub version: Option<String>,
    /// The notes published with it.
    pub notes: Option<String>,
    /// When it was published.
    pub date: Option<String>,
    /// True when a newer version exists than the one running.
    pub available: bool,
    /// True when the prompt for this version was dismissed.
    pub dismissed: bool,
    /// True when the app has never looked, or the last look was too long ago.
    pub due: bool,
}

/// Look for a newer version.
///
/// `force` skips the once-a-day limit; the app uses it when a check is
/// requested, and the automatic check leaves it false.
#[tauri::command]
pub async fn check_for_update(
    app: AppHandle,
    state: State<'_, AppState>,
    force: Option<bool>,
) -> AppResult<UpdateInfo> {
    require_session(&state)?;

    // The database lock is never held across the network call: the guard is
    // not `Send`, and a check must not keep the rest of the app waiting.
    let (due, running) = {
        let conn = state.lock_db()?;
        let last_check: Option<i64> = db::setting(&conn, SETTING_LAST_CHECK)?
            .and_then(|value| value.parse().ok());
        let due = match last_check {
            Some(at) => crate::util::now_secs() - at >= CHECK_INTERVAL_SECS,
            None => true,
        };
        (due, app.package_info().version.to_string())
    };

    if !due && !force.unwrap_or(false) {
        let conn = state.lock_db()?;
        return Ok(stored_info(&conn, running)?);
    }

    // The check itself must never become an error the account has to dismiss:
    // a machine with no network simply has no update to offer.
    let found = match app.updater().map_err(|err| {
        eprintln!("[backmeup] update check could not start: {err}");
    }) {
        Ok(updater) => match updater.check().await {
            Ok(update) => update,
            Err(err) => {
                eprintln!("[backmeup] update check failed: {err}");
                None
            }
        },
        Err(()) => None,
    };

    {
        let conn = state.lock_db()?;
        let now = crate::util::now_secs().to_string();

        match found {
            Some(update) => {
                let version = update.version.to_string();
                let notes = update.body.clone();
                let date = update.date.map(|date| date.to_string());

                db::set_setting(&conn, SETTING_LATEST_VERSION, Some(&version))?;
                db::set_setting(&conn, SETTING_LATEST_NOTES, notes.as_deref())?;
                db::set_setting(&conn, SETTING_LATEST_DATE, date.as_deref())?;
                db::set_setting(&conn, SETTING_LAST_CHECK, Some(&now))?;
            }
            None => {
                db::set_setting(&conn, SETTING_LAST_CHECK, Some(&now))?;
            }
        }
    }

    let conn = state.lock_db()?;
    Ok(stored_info(&conn, running)?)
}

/// What the app already knows, without touching the network.
fn stored_info(conn: &rusqlite::Connection, running: String) -> AppResult<UpdateInfo> {
    let version = db::setting(conn, SETTING_LATEST_VERSION)?;
    let notes = db::setting(conn, SETTING_LATEST_NOTES)?;
    let date = db::setting(conn, SETTING_LATEST_DATE)?;
    let dismissed = db::setting(conn, SETTING_DISMISSED)?;

    let available = match version.as_deref() {
        Some(candidate) => version_is_newer(candidate, &running),
        None => false,
    };

    // Computed before the value is moved into the result.
    let is_dismissed = dismissed.is_some() && dismissed == version;

    Ok(UpdateInfo {
        version,
        notes,
        date,
        available,
        dismissed: is_dismissed,
        due: true,
    })
}
/// Whether `candidate` is a later version than `running`.
pub fn version_is_newer(candidate: &str, running: &str) -> bool {
    match (
        semver::Version::parse(candidate),
        semver::Version::parse(running),
    ) {
        (Ok(candidate), Ok(running)) => candidate > running,
        // A version that cannot be read is not offered: an update the app
        // cannot compare is not one it should install.
        _ => false,
    }
}

/// Stop showing the prompt for a version.
///
/// The notice stays in the bell - it is clear, they simply are not
/// interrupted about it again.
#[tauri::command]
pub fn dismiss_update(state: State<'_, AppState>, version: String) -> AppResult<()> {
    require_session(&state)?;

    let conn = state.lock_db()?;
    db::set_setting(&conn, SETTING_DISMISSED, Some(&version))?;

    Ok(())
}

/// Show the prompt for a version again.
#[tauri::command]
pub fn resume_update_prompt(state: State<'_, AppState>) -> AppResult<()> {
    require_session(&state)?;

    let conn = state.lock_db()?;
    db::clear_setting(&conn, SETTING_DISMISSED)?;

    Ok(())
}

/// Download and install the newer version, then restart.
///
/// The file is checked against the signing key before it is run, so a
/// tampered download is refused rather than installed.
#[tauri::command]
pub async fn install_update(app: AppHandle) -> AppResult<()> {
    let updater = app.updater().map_err(|_| {
        AppError::new(
            "update_unavailable",
            "The update could not be prepared. Try downloading it from the project's releases instead.",
        )
    })?;

    let Some(update) = updater.check().await.map_err(|_| {
        AppError::new(
            "update_unavailable",
            "The update could not be fetched. Check your connection and try again.",
        )
    })? else {
        return Err(AppError::new(
            "update_unavailable",
            "There is no newer version to install.",
        ));
    };

    let mut downloaded = 0u64;
    let mut total = 0u64;

    update
        .download_and_install(
            |chunk, content_length| {
                downloaded += chunk as u64;
                if content_length.is_some() {
                    total = content_length.unwrap_or(total);
                }
            },
            || {},
        )
        .await
        .map_err(|_| {
            AppError::new(
                "update_failed",
                "The update could not be installed. Try again, or download it from the project's releases.",
            )
        })?;

    eprintln!("[backmeup] update installed ({downloaded} of {total} bytes)");

    // The new version takes over from here.
    app.restart();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_later_version_counts_as_an_update() {
        assert!(version_is_newer("0.1.1", "0.1.0"));
        assert!(version_is_newer("0.2.0", "0.1.9"));
        assert!(version_is_newer("1.0.0", "0.9.9"));

        assert!(!version_is_newer("0.1.0", "0.1.0"), "the same version is not an update");
        assert!(!version_is_newer("0.1.0", "0.1.1"), "an older version is not an update");
        assert!(!version_is_newer("0.1.0", "0.2.0"), "a newer running version is not an update");
    }

    #[test]
    fn a_version_that_cannot_be_read_is_never_offered() {
        assert!(!version_is_newer("not-a-version", "0.1.0"));
        assert!(!version_is_newer("0.1.1", "not-a-version"));
        assert!(!version_is_newer("", "0.1.0"));
    }
}

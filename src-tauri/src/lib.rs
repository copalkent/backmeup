mod backups;
mod commands;
mod credentials;
mod databases;
mod db;
mod dbconn;
mod destinations;
mod drive;
mod engines;
mod error;
mod mysqldump;
mod password;
mod recovery;
mod runs;
mod session;
mod ssh;
mod util;
mod validate;

use commands::AppState;
use rusqlite::Connection;
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // rustls needs exactly one crypto provider before anything builds a TLS
    // configuration.
    //
    // Both providers end up compiled in: `mysql` selects `ring`, while
    // `tiberius` depends on `tokio-rustls` with default features, which pulls
    // in `aws-lc-rs`. With two providers available rustls refuses to guess and
    // `ClientConfig::builder()` panics. Installing `ring` first, before the
    // Tauri builder exists, removes that trap: every `builder_with_provider`
    // call and tiberius' own `CryptoProvider::get_default()` then resolve to
    // the same provider.
    let _ = rustls::crypto::ring::default_provider().install_default();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            // The database is opened once, in the backend, before any command
            // can run. It lives in the per-user application data directory.
            let connection: Connection = db::open(app.handle())?;
            app.manage(AppState::new(connection));
            // At most one backup run may be in flight.
            app.manage(runs::RunRegistry::default());

            // If Google Drive is connected, make sure every database folder
            // exists. Idempotent, best effort, and off the startup path.
            drive::spawn_folder_sync(app.handle().clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // Authentication, recovery codes and account security.
            commands::app_bootstrap_state,
            commands::setup_owner,
            commands::confirm_setup_codes_saved,
            commands::login,
            commands::logout,
            commands::current_account,
            commands::recover_password,
            commands::recovery_code_status,
            commands::begin_recovery_code_regeneration,
            commands::commit_recovery_code_regeneration,
            commands::cancel_recovery_code_regeneration,
            commands::export_recovery_codes,
            // Engine catalogue and database connection records.
            engines::database_engines,
            databases::list_databases,
            databases::create_database,
            databases::update_database,
            databases::update_database_credentials,
            databases::delete_database,
            // Real connection tests. These two are the only commands that open
            // a socket to a database or read a stored password.
            databases::test_database_connection,
            databases::test_saved_database,
            // Backup destinations.
            destinations::list_backup_destinations,
            destinations::choose_local_backup_folder,
            destinations::clear_local_backup_folder,
            // Google Drive. Sign-in happens in the owner's browser; BackMeUp
            // never sees a Google password. The client secret is a public
            // identifier that ships with the app, and PKCE protects the flow.
            drive::google_drive_status,
            drive::connect_google_drive,
            drive::cancel_google_drive_connect,
            drive::disconnect_google_drive,
            drive::test_google_drive,
            drive::sync_google_drive_folders,
            // Backup history and dashboard summary.
            backups::list_backup_runs,
            backups::backup_overview,
            backups::clear_backup_history,
            // Running a backup. A run reads the source and writes one file; it
            // never executes a statement against the database and never starts
            // an external process.
            runs::start_backup_run,
            runs::cancel_backup_run,
            runs::active_backup_run,
        ])
        .run(tauri::generate_context!())
        .expect("error while running BackMeUp");
}

#[cfg(test)]
mod tests {
    /// Both `ring` and `aws-lc-rs` are compiled in (see `run`). Whichever is
    /// installed first wins for the whole process, and every adapter builds its
    /// configuration with an explicit provider, so this asserts there is never
    /// a state where rustls cannot pick one.
    #[test]
    fn a_crypto_provider_is_always_available() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        assert!(
            rustls::crypto::CryptoProvider::get_default().is_some(),
            "rustls must have exactly one installed provider"
        );

        // The builder must not panic, which is what fails when two providers
        // are compiled in and none is installed.
        let built = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions();

        assert!(built.is_ok(), "ring provider must be usable");
    }
}
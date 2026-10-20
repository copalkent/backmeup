//! Database connection management.
//!
//! This module owns the *records* that describe where a database lives and
//! routes connection tests to [`crate::dbconn`]. It never opens a socket
//! itself, and it never sees a plaintext password except as a `Zeroizing`
//! value on its way to the credential store or the adapter.
//!
//! Separation of concerns:
//!   * this module - the catalogue of connections and their test history;
//!   * `engines` - what an engine is, as a connection preset;
//!   * `dbconn` - the per-engine adapters that actually connect;
//!   * `credentials` - the Windows Credential Manager, the only place a
//!     password is persisted;
//!   * `backups` - orchestration, once an adapter can produce a dump.
//!
//! Nothing here assumes MySQL, PHP or any hosting provider.

use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, State};
use zeroize::Zeroizing;

use crate::commands::{require_session, AppState};
use crate::credentials;
use crate::db;
use crate::dbconn::{self, ConnectionTarget};
use crate::drive;
use crate::engines;
use crate::error::{AppError, AppResult};
use crate::ssh;
use crate::util;
use crate::validate;

/// Shown whenever credentials cannot be stored, so saving a connection stays
/// disabled rather than falling back to weaker storage.
///
/// Secrets live in the Windows Credential Manager, encrypted with DPAPI under
/// the signed-in user. `database_connections.secret_ref` only ever holds the
/// opaque lookup id; a password must never be written to this SQLite file, to a
/// JSON config, or to `localStorage` in the frontend.
pub const CREDENTIAL_STORAGE_NOTE: &str =
    "Passwords are stored in the Windows Credential Manager, encrypted for your Windows account.";

/// Shown when the credential store cannot be reached.
pub const CREDENTIAL_STORAGE_UNAVAILABLE: &str =
    "BackMeUp cannot reach the Windows Credential Manager on this computer, so connections cannot be saved. No password is stored anywhere else.";

/// Default SSH port, used when the SSH port field is left empty.
const SSH_DEFAULT_PORT: u16 = 22;

/// Bounds for SSH secrets. An SSH password or key passphrase is a secret that
/// must be zeroized; a pasted private key is bounded so a huge payload cannot
/// be used to exhaust memory.
const MAX_SSH_SECRET_LEN: usize = 512;
const MAX_SSH_KEY_LEN: usize = 16 * 1024;

/// Connection-test throttling. Generous enough for genuine troubleshooting,
/// tight enough to stop the command being used as a port scanner.
const TEST_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
const TEST_THRESHOLD: usize = 10;
const TEST_BASE_PENALTY: std::time::Duration = std::time::Duration::from_secs(20);
const TEST_MAX_PENALTY: std::time::Duration = std::time::Duration::from_secs(5 * 60);

/// How a saved connection's last test went.
///
/// `NeverTested` is deliberately distinct from `Failed`: a configuration that
/// has never been dialled must not look like a broken one.
#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub enum TestState {
    NeverTested,
    Succeeded,
    Failed,
}

impl TestState {
    fn from_flag(flag: Option<i64>) -> Self {
        match flag {
            Some(1) => TestState::Succeeded,
            Some(_) => TestState::Failed,
            None => TestState::NeverTested,
        }
    }

    fn as_flag(self) -> i64 {
        match self {
            TestState::Succeeded => 1,
            TestState::Failed => 0,
            TestState::NeverTested => -1,
        }
    }
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseView {
    pub id: String,
    pub label: String,
    pub engine: String,
    pub engine_label: String,
    pub connection_method: String,
    pub connection_method_label: String,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub database_name: String,
    pub username: Option<String>,
    pub created_at: i64,
    /// `never_tested` | `succeeded` | `failed`.
    pub test_state: TestState,
    /// When the last attempt ran. An old success is *history*, not "online".
    pub last_tested_at: Option<i64>,
    /// Whether a usable password is stored. Never carries the secret itself.
    pub has_credentials: bool,
    /// SSH tunnel settings. Present only for `ssh-tunnel` records.
    pub ssh_host: Option<String>,
    pub ssh_port: Option<u16>,
    pub ssh_username: Option<String>,
    /// `password` | `private_key`.
    pub ssh_auth_method: Option<String>,
    /// Whether the SSH half of the credential pair is stored (the SSH password
    /// or the private-key blob, matching the chosen method). Never carries the
    /// secret itself.
    pub has_ssh_credentials: bool,
    /// Verified server host-key fingerprint in display form
    /// (`SHA256:<base64>`). `None` means the key has not been verified yet.
    /// Public data: this is a hash of the server's public key.
    pub ssh_host_key_fingerprint: Option<String>,
    pub ssh_host_key_type: Option<String>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionTestResult {
    /// `success` | `failed` | `unverified`.
    pub outcome: String,
    /// Present only on success.
    pub server_banner: Option<String>,
    pub latency_ms: Option<u128>,
    pub encrypted: bool,
    /// Safe, actionable sentence. Never contains a host, user or password.
    pub message: String,
    /// BackMeUp's own code for the failure, so the app can tell a rejected
    /// password from a network problem. Never server text.
    pub code: Option<String>,
    /// Display-form host-key fingerprint (`SHA256:<base64>`) when the outcome
    /// is `unverified` or `failed` because the server's key changed. Public
    /// data.
    pub host_key_fingerprint: Option<String>,
    pub host_key_type: Option<String>,
}

const SELECT_COLUMNS: &str = "id, label, engine, connection_method, host, port, \
     database_name, username, created_at, last_tested_at, last_test_ok, \
     ssh_host, ssh_port, ssh_username, ssh_auth_method, \
     ssh_host_key_fingerprint, ssh_host_key_type";

struct DatabaseRow {
    id: String,
    label: String,
    engine: String,
    connection_method: String,
    host: Option<String>,
    port: Option<u16>,
    database_name: String,
    username: Option<String>,
    created_at: i64,
    last_tested_at: Option<i64>,
    last_test_ok: Option<i64>,
    ssh_host: Option<String>,
    ssh_port: Option<u16>,
    ssh_username: Option<String>,
    ssh_auth_method: Option<String>,
    ssh_host_key_fingerprint: Option<String>,
    ssh_host_key_type: Option<String>,
}

fn row_to_struct(row: &rusqlite::Row<'_>) -> rusqlite::Result<DatabaseRow> {
    Ok(DatabaseRow {
        id: row.get(0)?,
        label: row.get(1)?,
        engine: row.get(2)?,
        connection_method: row.get(3)?,
        host: row.get(4)?,
        port: row.get::<_, Option<i64>>(5)?.map(|p| p as u16),
        database_name: row.get(6)?,
        username: row.get(7)?,
        created_at: row.get(8)?,
        last_tested_at: row.get(9)?,
        last_test_ok: row.get(10)?,
        ssh_host: row.get(11)?,
        ssh_port: row.get::<_, Option<i64>>(12)?.map(|p| p as u16),
        ssh_username: row.get(13)?,
        ssh_auth_method: row.get(14)?,
        ssh_host_key_fingerprint: row.get(15)?,
        ssh_host_key_type: row.get(16)?,
    })
}

/// Fingerprints cross the IPC boundary in OpenSSH's display form
/// (`SHA256:<base64>`); storage always keeps the bare base64 digest.
fn display_fingerprint(bare: &str) -> String {
    format!("SHA256:{bare}")
}

fn to_view(engine_id: &str, method_id: &str, row: &DatabaseRow, ssh_secret_present: bool) -> DatabaseView {
    // Cannot fail: both ids were validated against these same allowlists on
    // the way in. Falling back to the raw id keeps the command total.
    let (engine_label, method_label) = match (
        engines::find(engine_id),
        engines::find_method(method_id),
    ) {
        (Some(engine), Some(method)) => (engine.label.to_string(), method.label.to_string()),
        _ => (engine_id.to_string(), method_id.to_string()),
    };

    DatabaseView {
        id: row.id.clone(),
        label: row.label.clone(),
        engine: row.engine.clone(),
        engine_label,
        connection_method: row.connection_method.clone(),
        connection_method_label: method_label,
        host: row.host.clone(),
        port: row.port,
        database_name: row.database_name.clone(),
        username: row.username.clone(),
        created_at: row.created_at,
        test_state: TestState::from_flag(row.last_test_ok),
        last_tested_at: row.last_tested_at,
        has_credentials: credentials::exists(&row.id),
        ssh_host: row.ssh_host.clone(),
        ssh_port: row.ssh_port,
        ssh_username: row.ssh_username.clone(),
        ssh_auth_method: row.ssh_auth_method.clone(),
        has_ssh_credentials: ssh_secret_present,
        ssh_host_key_fingerprint: row
            .ssh_host_key_fingerprint
            .as_deref()
            .map(display_fingerprint),
        ssh_host_key_type: row.ssh_host_key_type.clone(),
    }
}

/// Whether this connection's SSH credential (password or key blob) is stored.
///
/// Only meaningful for `ssh-tunnel` records; every other method reports false.
fn ssh_secret_present(app: &AppHandle, row: &DatabaseRow) -> bool {
    if row.connection_method != engines::SSH_TUNNEL_METHOD_ID {
        return false;
    }

    match row.ssh_auth_method.as_deref() {
        Some(validate::SSH_AUTH_PRIVATE_KEY) => {
            credentials::ssh_key_blob_exists(app, &row.id)
        }
        Some(validate::SSH_AUTH_PASSWORD) => credentials::ssh_password_exists(&row.id),
        _ => false,
    }
}

/// Every connection configured.
///
/// Requires a live Rust-side session; the join to `owner_account` inside
/// `require_session` is what makes that authoritative rather than a frontend
/// check.
#[tauri::command]
pub fn list_databases(
    app: AppHandle,
    state: State<'_, AppState>,
) -> AppResult<Vec<DatabaseView>> {
    require_session(&state)?;

    let conn = state.lock_db()?;
    let mut stmt = conn.prepare(&format!(
        "SELECT {SELECT_COLUMNS} FROM database_connections ORDER BY created_at ASC"
    ))?;
    let rows = stmt.query_map([], row_to_struct)?;

    let mut out = Vec::new();
    for row in rows {
        let row = row?;
        let ssh_present = ssh_secret_present(&app, &row);
        out.push(to_view(&row.engine, &row.connection_method, &row, ssh_present));
    }
    Ok(out)
}

/// How many connections are configured. Used by the dashboard summary.
pub fn count(conn: &Connection) -> AppResult<u32> {
    let total: i64 = conn.query_row("SELECT COUNT(*) FROM database_connections", [], |row| {
        row.get(0)
    })?;
    Ok(total as u32)
}

// ---------------------------------------------------------------------------
// Input normalisation
// ---------------------------------------------------------------------------

/// The SSH half of a connection form, as sent by the webview.
///
/// Secrets (`ssh_password`, `ssh_private_key`, `ssh_key_passphrase`) are
/// optional here because the same shape serves three flows: creating a
/// connection (secrets required for the chosen method), editing one (secrets
/// present only when they are re-entered) and testing one from the form
/// (secrets required for the chosen method, and never stored).
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct SshTunnelForm {
    pub ssh_host: String,
    pub ssh_port: Option<i64>,
    pub ssh_username: String,
    /// `password` | `private_key`.
    pub ssh_auth_method: String,
    pub ssh_password: Option<String>,
    pub ssh_private_key: Option<String>,
    pub ssh_key_passphrase: Option<String>,
    /// Fingerprint in either accepted form; normalised to bare base64.
    pub ssh_host_key_fingerprint: Option<String>,
}

/// A fully validated connection request, ready to hand to an adapter.
///
/// Carries no password: the secret is attached only once the adapter is about
/// to use it.
#[derive(Debug)]
struct PreparedTarget {
    engine_id: String,
    engine_label: String,
    host: String,
    port: u16,
    database: String,
    username: String,
}

impl PreparedTarget {
    fn into_connection(self, password: Zeroizing<String>) -> ConnectionTarget {
        ConnectionTarget {
            engine_id: self.engine_id,
            engine_label: self.engine_label,
            host: self.host,
            port: self.port,
            database: self.database,
            username: self.username,
            password,
        }
    }
}

/// Validated SSH addressing plus whatever secrets the form supplied.
///
/// The secrets are `Option` because the same struct serves create, edit and
/// test flows; each caller enforces its own requiredness rules.
struct PreparedSsh {
    host: String,
    port: u16,
    username: String,
    auth_method: &'static str,
    /// Bare base64 digest, as stored.
    fingerprint: Option<String>,
    password: Option<Zeroizing<String>>,
    private_key: Option<Zeroizing<String>>,
    passphrase: Option<Zeroizing<String>>,
}

/// `Debug` must never render a secret, and these structs hold three.
impl std::fmt::Debug for PreparedSsh {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedSsh")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("auth_method", &self.auth_method)
            .field("fingerprint", &self.fingerprint)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("private_key", &self.private_key.as_ref().map(|_| "<redacted>"))
            .field("passphrase", &self.passphrase.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// A fully validated connection form.
#[derive(Debug)]
struct PreparedConnection {
    target: PreparedTarget,
    method_id: String,
    ssh: Option<PreparedSsh>,
}

/// Optional secret: absent and empty both mean "not supplied"; the value is
/// never trimmed because a password may legitimately contain spaces.
fn optional_secret(raw: Option<&str>, too_long: &str) -> AppResult<Option<Zeroizing<String>>> {
    match raw {
        None => Ok(None),
        Some(value) if value.is_empty() => Ok(None),
        Some(value) => {
            if value.chars().count() > MAX_SSH_SECRET_LEN {
                return Err(AppError::invalid_input(too_long));
            }
            Ok(Some(Zeroizing::new(value.to_string())))
        }
    }
}

/// Optional pasted private key. Bounded, and shape-checked so a wrong paste is
/// refused before anything is stored.
fn optional_key_text(raw: Option<&str>) -> AppResult<Option<Zeroizing<String>>> {
    match raw {
        None => Ok(None),
        Some(value) if value.trim().is_empty() => Ok(None),
        Some(value) => {
            if value.len() > MAX_SSH_KEY_LEN {
                return Err(AppError::invalid_input(
                    "That SSH private key is too large. Paste the key file itself, not a bundle.",
                ));
            }
            if !value.contains("PRIVATE KEY") {
                return Err(AppError::invalid_input(
                    "That does not look like an SSH private key. Paste the full contents of the key file.",
                ));
            }
            Ok(Some(Zeroizing::new(value.to_string())))
        }
    }
}

/// Parse a pasted key (and passphrase) locally, so a bad pair is refused before
/// any network attempt or storage write.
fn verify_key_material(
    key: &Zeroizing<String>,
    passphrase: Option<&Zeroizing<String>>,
) -> AppResult<()> {
    ssh::validate_private_key(key.as_str(), passphrase.map(|value| value.as_str())).map_err(|_| {
        AppError::invalid_input(
            "The SSH private key could not be read. Check that the key text is complete and the passphrase, if any, is correct.",
        )
    })
}

/// Validate the SSH half of a form. No network, no storage: pure field checks.
fn prepare_ssh(form: &SshTunnelForm, engine_spec: &engines::Engine) -> AppResult<PreparedSsh> {
    if !engine_spec.supports_ssh_tunnel {
        return Err(AppError::invalid_input(format!(
            "SSH tunnels are available for MySQL and MariaDB connections, not for {}.",
            engine_spec.label
        )));
    }

    let host = validate::validate_host(&form.ssh_host)?;
    let port = validate::validate_port(form.ssh_port)?.unwrap_or(SSH_DEFAULT_PORT);

    let username = validate::validate_username(&form.ssh_username)?
        .ok_or_else(|| AppError::invalid_input("Enter the SSH user name."))?;

    let auth_method = match form.ssh_auth_method.trim() {
        validate::SSH_AUTH_PASSWORD => validate::SSH_AUTH_PASSWORD,
        validate::SSH_AUTH_PRIVATE_KEY => validate::SSH_AUTH_PRIVATE_KEY,
        _ => {
            return Err(AppError::invalid_input(
                "Choose an SSH sign-in method from the list.",
            ))
        }
    };

    let fingerprint = form
        .ssh_host_key_fingerprint
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(validate::validate_fingerprint)
        .transpose()?;

    let password = optional_secret(form.ssh_password.as_deref(), "That SSH password is too long.")?;
    let private_key = optional_key_text(form.ssh_private_key.as_deref())?;
    let passphrase = optional_secret(
        form.ssh_key_passphrase.as_deref(),
        "That SSH key passphrase is too long.",
    )?;

    Ok(PreparedSsh {
        host,
        port,
        username,
        auth_method,
        fingerprint,
        password,
        private_key,
        passphrase,
    })
}

/// Validate every field and resolve the address that will actually be dialled.
///
/// A "This machine" connection substitutes the engine's own loopback address,
/// which is why the local form must not be reused as the stored host. An SSH
/// tunnel resolves its database address from the SSH server, so an omitted
/// host defaults to the same loopback value.
fn prepare(
    label: &str,
    engine: &str,
    connection_method: &str,
    host: Option<String>,
    port: Option<i64>,
    database_name: &str,
    username: Option<String>,
    ssh: Option<&SshTunnelForm>,
) -> AppResult<PreparedConnection> {
    let _label = validate::validate_label(label, "Name")?;
    let database = validate::validate_database_name(database_name)?;

    let username = validate::validate_username(username.as_deref().unwrap_or_default())?
        .ok_or_else(|| AppError::invalid_input("Enter a database user name."))?;

    // Allow-list look-up: an unknown engine or method is refused outright, so a
    // stored id always matches something this build understands.
    let engine_spec = engines::find(engine.trim()).ok_or_else(|| {
        AppError::invalid_input("Choose a database engine from the list.")
    })?;

    if !engine_spec.supported || !dbconn::engine_supported(engine_spec.id) {
        return Err(AppError::new(
            "engine_unsupported",
            format!(
                "BackMeUp has no working connection support for {} in this version.",
                engine_spec.label
            ),
        ));
    }

    let method_spec = engines::find_method(connection_method.trim()).ok_or_else(|| {
        AppError::invalid_input("Choose a connection method from the list.")
    })?;

    let port = validate::validate_port(port)?
        .unwrap_or(engine_spec.default_port);

    let raw_host = host.as_deref().map(str::trim).filter(|h| !h.is_empty());

    // The address that will be dialled depends on the method, and is validated
    // in both branches so a stored host is always well formed.
    let resolved_host = if method_spec.requires_host {
        match raw_host {
            Some(value) => validate::validate_host(value)?,
            None => {
                return Err(AppError::invalid_input(
                    "A host is required for a direct connection.",
                ))
            }
        }
    } else {
        // Local connection or SSH tunnel: the engine decides its own loopback
        // address when none is given. For a tunnel this is the address *as
        // resolved by the SSH server*, which is why it is stored as-is.
        match raw_host {
            Some(value) => validate::validate_host(value)?,
            None => engine_spec.local_host.to_string(),
        }
    };

    if !engine_spec.supports_host && method_spec.requires_host {
        return Err(AppError::invalid_input(format!(
            "{} cannot be reached from another server.",
            engine_spec.label
        )));
    }

    let prepared_ssh = if method_spec.id == engines::SSH_TUNNEL_METHOD_ID {
        let form = ssh.ok_or_else(|| {
            AppError::invalid_input("Enter the SSH server details, or choose another connection method.")
        })?;
        Some(prepare_ssh(form, engine_spec)?)
    } else {
        // SSH fields are only meaningful - and only stored - for the
        // `ssh-tunnel` method.
        None
    };

    Ok(PreparedConnection {
        target: PreparedTarget {
            engine_id: engine_spec.id.to_string(),
            engine_label: engine_spec.label.to_string(),
            host: resolved_host,
            port,
            database,
            username,
        },
        method_id: method_spec.id.to_string(),
        ssh: prepared_ssh,
    })
}

/// Password bounds. Deliberately generous but bounded, because a password is
/// a secret that must be zeroized and a Credential Manager blob is limited.
const MIN_PASSWORD_LEN: usize = 1;
const MAX_PASSWORD_LEN: usize = 512;

fn validate_password_shape(password: &str) -> AppResult<Zeroizing<String>> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(AppError::invalid_input("Enter the database password."));
    }
    if password.chars().count() > MAX_PASSWORD_LEN {
        return Err(AppError::invalid_input("That password is too long."));
    }
    Ok(Zeroizing::new(password.to_string()))
}

fn require_credential_store() -> AppResult<()> {
    if credentials::available() {
        Ok(())
    } else {
        Err(AppError::new(
            "credentials_unavailable",
            CREDENTIAL_STORAGE_UNAVAILABLE,
        ))
    }
}

// ---------------------------------------------------------------------------
// Test connection
// ---------------------------------------------------------------------------

/// Refuse to start a test while a cooldown is active.
fn check_test_budget(state: &AppState) -> AppResult<()> {
    let wait = state
        .lock_auth()?
        .connection_test_throttle_mut()
        .remaining_lockout();

    if wait.is_zero() {
        Ok(())
    } else {
        Err(AppError::rate_limited(wait.as_secs().max(1)))
    }
}

fn record_test_budget(state: &AppState) {
    let mut auth = match state.lock_auth() {
        Ok(auth) => auth,
        Err(_) => return,
    };
    auth.connection_test_throttle_mut().register_failure(
        TEST_THRESHOLD,
        TEST_WINDOW,
        TEST_BASE_PENALTY,
        TEST_MAX_PENALTY,
    );
}

/// Build the result payload for a failure without leaking driver detail.
fn failure(err: AppError) -> AppResult<ConnectionTestResult> {
    let code = if err.code.is_empty() {
        None
    } else {
        Some(err.code.to_string())
    };

    Ok(ConnectionTestResult {
        outcome: "failed".to_string(),
        server_banner: None,
        latency_ms: None,
        // No connection to the database was established, so no transport was
        // established either.
        encrypted: false,
        message: err.message,
        code,
        host_key_fingerprint: None,
        host_key_type: None,
    })
}

fn success(report: dbconn::ConnectionReport) -> ConnectionTestResult {
    ConnectionTestResult {
        outcome: "success".to_string(),
        server_banner: Some(report.server_banner),
        latency_ms: Some(report.latency_ms),
        encrypted: report.encrypted,
        message: "BackMeUp connected and the database accepted these credentials."
            .to_string(),
        code: None,
        host_key_fingerprint: None,
        host_key_type: None,
    }
}

/// The SSH server's key has been read but not verified: nothing was
/// authenticated, and the fingerprint must be compared out of band.
fn unverified(info: &ssh::HostKeyInfo) -> ConnectionTestResult {
    ConnectionTestResult {
        outcome: "unverified".to_string(),
        server_banner: None,
        latency_ms: None,
        // Nothing was authenticated, so nothing was transported.
        encrypted: false,
        message: "The SSH server presented this host key. Compare it with the server itself \
                  before connecting; BackMeUp has not trusted it yet."
            .to_string(),
        code: Some("host_key_unverified".to_string()),
        host_key_fingerprint: Some(display_fingerprint(&info.fingerprint)),
        host_key_type: Some(info.key_type.clone()),
    }
}

/// The server's key no longer matches the verified one. The connection is
/// refused, and the presented fingerprint is reported so a deliberate
/// re-verification is possible after checking out of band.
fn host_key_changed(presented: &ssh::HostKeyInfo, expected: Option<&str>) -> ConnectionTestResult {
    let expected_text = expected
        .map(display_fingerprint)
        .unwrap_or_else(|| "a previously verified key".to_string());

    ConnectionTestResult {
        outcome: "failed".to_string(),
        server_banner: None,
        latency_ms: None,
        // Refused before any connection, so nothing was transported.
        encrypted: false,
        message: format!(
            "The SSH server presented a different host key than the verified one (expected {}, received {}). \
             BackMeUp refused to connect. If the server was rebuilt or migrated, verify the new fingerprint \
             out of band before trusting it.",
            expected_text,
            display_fingerprint(&presented.fingerprint),
        ),
        code: Some("host_key_changed".to_string()),
        host_key_fingerprint: Some(display_fingerprint(&presented.fingerprint)),
        host_key_type: Some(presented.key_type.clone()),
    }
}

/// Map a stage-accurate SSH failure to a test result. A host-key mismatch
/// carries the presented fingerprint; every other failure is one fixed
/// sentence and never carries server-supplied text.
fn ssh_failure(err: ssh::SshError, expected: Option<&str>) -> AppResult<ConnectionTestResult> {
    match err {
        ssh::SshError::HostKeyMismatch { presented } => {
            Ok(host_key_changed(&presented, expected))
        }
        other => failure(AppError::new(other.code(), other.user_message())),
    }
}

/// What to do about the SSH server's host key for one attempt.
#[derive(Debug)]
enum HostKeyPlan {
    /// Nothing has been verified yet: probe the server, report the fingerprint
    /// and authenticate nothing.
    Verify,
    /// Pin this fingerprint (bare base64). `persist` records it once the
    /// tunnel opens, which happens when it differs from what is stored (a
    /// deliberate re-verification after a changed key or a first trust).
    Trust { fingerprint: String, persist: bool },
}

/// Decide from the stored and the explicitly supplied fingerprints.
fn plan_host_key(stored: Option<&str>, supplied: Option<String>) -> HostKeyPlan {
    if let Some(supplied) = supplied {
        let persist = stored != Some(supplied.as_str());
        return HostKeyPlan::Trust {
            fingerprint: supplied,
            persist,
        };
    }

    match stored {
        Some(stored) => HostKeyPlan::Trust {
            fingerprint: stored.to_string(),
            persist: false,
        },
        None => HostKeyPlan::Verify,
    }
}

/// Resolve the SSH credential a form supplied, enforcing the requirement for
/// the chosen method. Used only by the test-from-the-form path; these secrets
/// are never stored.
fn form_ssh_credential(fields: &PreparedSsh) -> AppResult<ssh::SshCredential> {
    match fields.auth_method {
        validate::SSH_AUTH_PASSWORD => fields
            .password
            .clone()
            .map(ssh::SshCredential::Password)
            .ok_or_else(|| AppError::invalid_input("Enter the SSH password.")),
        validate::SSH_AUTH_PRIVATE_KEY => {
            let key = fields
                .private_key
                .clone()
                .ok_or_else(|| AppError::invalid_input("Paste the SSH private key."))?;
            verify_key_material(&key, fields.passphrase.as_ref())?;
            Ok(ssh::SshCredential::PrivateKey {
                key,
                passphrase: fields.passphrase.clone(),
            })
        }
        _ => Err(AppError::internal()),
    }
}

/// Run one database test through an SSH tunnel.
///
/// Returns the result plus, when the host key was explicitly (re)verified and
/// the tunnel really opened, the fingerprint details to persist.
async fn run_tunnel_test(
    fields: &PreparedSsh,
    credential: ssh::SshCredential,
    target: &PreparedTarget,
    password: Zeroizing<String>,
    plan: HostKeyPlan,
) -> AppResult<(ConnectionTestResult, Option<(String, String)>)> {
    let expected = match &plan {
        HostKeyPlan::Verify => {
            // Learn the key on a throwaway session that authenticates nothing.
            return match ssh::probe_host_key(&fields.host, fields.port).await {
                Ok(info) => Ok((unverified(&info), None)),
                Err(err) => ssh_failure(err, None).map(|result| (result, None)),
            };
        }
        HostKeyPlan::Trust { fingerprint, .. } => fingerprint.clone(),
    };

    let request = ssh::SshRequest {
        ssh_host: fields.host.clone(),
        ssh_port: fields.port,
        ssh_username: fields.username.clone(),
        credential,
        expected_host_key: expected.clone(),
        database_host: target.host.clone(),
        database_port: target.port,
    };

    let tunnel = match ssh::open_tunnel(request).await {
        Ok(tunnel) => tunnel,
        Err(err) => return ssh_failure(err, Some(&expected)).map(|result| (result, None)),
    };

    let trusted = match &plan {
        HostKeyPlan::Trust { persist: true, .. } => Some((
            tunnel.host_key().fingerprint.clone(),
            tunnel.host_key().key_type.clone(),
        )),
        _ => None,
    };

    // The adapter dials the loopback end of the tunnel; the SSH server
    // resolves the real database address from `target.host`/`target.port`.
    let loopback_target = ConnectionTarget {
        engine_id: target.engine_id.clone(),
        engine_label: target.engine_label.clone(),
        host: "127.0.0.1".to_string(),
        port: tunnel.local_port(),
        database: target.database.clone(),
        username: target.username.clone(),
        password,
    };

    let report = dbconn::test(loopback_target).await;

    // Ends the SSH session and the loopback listener.
    drop(tunnel);

    match report {
        Ok(mut report) => {
            // Every byte of this connection travels inside the SSH channel, so
            // the transport is encrypted even where the engine reports no
            // driver-level TLS of its own (MySQL).
            report.encrypted = true;
            Ok((success(report), trusted))
        }
        Err(err) => failure(err).map(|result| (result, trusted)),
    }
}

/// Record a newly verified host key. Public data only: the fingerprint (bare
/// base64) and the key algorithm name for display.
fn write_host_key_trust(state: &AppState, id: &str, fingerprint: &str, key_type: &str) {
    if let Ok(mut conn) = state.lock_db() {
        if let Ok(tx) = conn.transaction_with_behavior(TransactionBehavior::Immediate) {
            let _ = tx.execute(
                "UPDATE database_connections
                 SET ssh_host_key_fingerprint = ?2, ssh_host_key_type = ?3, updated_at = ?4
                 WHERE id = ?1",
                rusqlite::params![id, fingerprint, key_type, util::now_secs()],
            );
            let _ = db::audit_config(
                &tx,
                "database",
                "updated",
                Some("ssh_host_key_verified"),
            );
            let _ = tx.commit();
        }
    }
}

/// Test a connection from the form, before anything is saved.
///
/// This command is deliberately narrow: it accepts only connection fields,
/// never a statement, never a file path and never a shell command, so it cannot
/// be turned into arbitrary SQL execution or code execution. Passwords are
/// accepted, used, and wiped; nothing is stored by this command.
///
/// For an SSH tunnel the first result is `unverified`: the server's host key
/// is reported and no credential is sent until the call is repeated with
/// that fingerprint in the form.
#[tauri::command]
pub async fn test_database_connection(
    state: State<'_, AppState>,
    label: String,
    engine: String,
    connection_method: String,
    host: Option<String>,
    port: Option<i64>,
    database_name: String,
    username: String,
    password: String,
    ssh: Option<SshTunnelForm>,
) -> AppResult<ConnectionTestResult> {
    require_session(&state)?;
    check_test_budget(&state)?;

    let password = match validate_password_shape(&password) {
        Ok(value) => value,
        Err(err) => return failure(err),
    };

    let prepared = match prepare(
        &label,
        &engine,
        &connection_method,
        host,
        port,
        &database_name,
        Some(username),
        ssh.as_ref(),
    ) {
        Ok(value) => value,
        Err(err) => return failure(err),
    };

    match prepared.ssh {
        None => {
            record_test_budget(&state);

            match dbconn::test(prepared.target.into_connection(password)).await {
                Ok(report) => Ok(success(report)),
                Err(err) => failure(err),
            }
        }
        Some(fields) => {
            let credential = match form_ssh_credential(&fields) {
                Ok(value) => value,
                Err(err) => return failure(err),
            };
            let plan = plan_host_key(None, fields.fingerprint.clone());

            record_test_budget(&state);

            let (result, _) =
                run_tunnel_test(&fields, credential, &prepared.target, password, plan).await?;
            Ok(result)
        }
    }
}

/// Re-test a connection that is already saved, using its stored credentials.
///
/// Passwords are read from the credential store only for the duration of the
/// attempt and are zeroized immediately afterwards; they are never returned to
/// the frontend and never recorded in the test history.
///
/// For an SSH tunnel, `host_key_fingerprint` is the fingerprint that has
/// just compared out of band (the `SHA256:...` form is accepted). Supplying it
/// pins that key and, once the tunnel opens, records it as verified.
#[tauri::command]
pub async fn test_saved_database(
    app: AppHandle,
    state: State<'_, AppState>,
    id: String,
    host_key_fingerprint: Option<String>,
) -> AppResult<ConnectionTestResult> {
    require_session(&state)?;
    validate::validate_record_id(&id)?;
    check_test_budget(&state)?;

    test_saved_inner(&app, &state, &id, host_key_fingerprint).await
}

/// The work of testing one saved connection.
///
/// Separate from the command so a sweep over every connection can use exactly
/// the same path, rather than a second implementation that could drift.
async fn test_saved_inner(
    app: &AppHandle,
    state: &AppState,
    id: &str,
    host_key_fingerprint: Option<String>,
) -> AppResult<ConnectionTestResult> {
    let row = {
        let conn = state.lock_db()?;
        let row: Option<DatabaseRow> = conn
            .query_row(
                &format!("SELECT {SELECT_COLUMNS} FROM database_connections WHERE id = ?1"),
                [id],
                row_to_struct,
            )
            .optional()?;

        row.ok_or_else(not_found)?
    };

    // An explicitly supplied fingerprint is normalised before any network
    // work, so a malformed value is refused rather than compared loosely.
    let supplied = match host_key_fingerprint
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(value) => match validate::validate_fingerprint(value) {
            Ok(value) => Some(value),
            Err(err) => return failure(err),
        },
        None => None,
    };

    let password = match credentials::load(id) {
        Ok((credentials::CredentialState::Present, Some(secret))) => secret,
        Ok(_) => {
            return failure(AppError::new(
                "credentials_unavailable",
                "No password is stored for this connection. Enter it again before testing.",
            ))
        }
        Err(err) => return failure(err),
    };

    if row.connection_method == engines::SSH_TUNNEL_METHOD_ID {
        return test_saved_tunnel(app, state, id, &row, supplied, password).await;
    }

    let target = ConnectionTarget {
        engine_id: row.engine.clone(),
        // Used only as a fallback banner, so a wrong label could never mislabel
        // a successful connection to a user.
        engine_label: engines::find(&row.engine)
            .map(|engine| engine.label.to_string())
            .unwrap_or_else(|| row.engine.clone()),
        host: row.host.clone().unwrap_or_default(),
        port: row.port.unwrap_or(0),
        database: row.database_name.clone(),
        username: row.username.clone().unwrap_or_default(),
        password,
    };

    // An empty stored host or port means the record predates the current
    // rules; refuse rather than guessing.
    if target.host.is_empty() || target.port == 0 || target.username.is_empty() {
        return failure(AppError::new(
            "incomplete_connection",
            "This connection is missing a host, port or user name. Edit it before testing.",
        ));
    }

    record_test_budget(state);

    let outcome = dbconn::test(target).await;
    let state_value = TestState::from_flag(match &outcome {
        Ok(_) => Some(1),
        Err(_) => Some(0),
    });
    write_test_result(state, id, state_value);
    record_credential_status(state, id, credential_status_from(&outcome));

    match outcome {
        Ok(report) => Ok(success(report)),
        Err(err) => failure(err),
    }
}

/// What a sweep over every saved connection found.
#[derive(Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionCheckSummary {
    /// How many connections were tested.
    pub tested: u32,
    /// How many the server accepted.
    pub ok: u32,
    /// How many were refused.
    pub rejected: u32,
    /// Connections that could not be tested at all.
    pub unreachable: u32,
    /// The connections whose password was refused.
    pub rejected_ids: Vec<String>,
}

/// Test every saved connection and report what the server said.
///
/// A password that was rotated on the server leaves the saved copy behind.
/// Without this, the same failure is met on every run and the connection has to be
/// work out which connection it was. The sweep is quiet about everything it
/// cannot prove: a connection that could not be reached is counted as
/// unreachable, not as refused.
#[tauri::command]
pub async fn check_all_connections(
    app: AppHandle,
    state: State<'_, AppState>,
) -> AppResult<ConnectionCheckSummary> {
    require_session(&state)?;

    let connections: Vec<String> = {
        let conn = state.lock_db()?;
        let mut stmt = conn.prepare(
            "SELECT id FROM database_connections ORDER BY created_at ASC, id ASC",
        )?;
        let ids = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        ids
    };

    let mut summary = ConnectionCheckSummary::default();

    for id in connections {
        // The cooldown still applies. A sweep is a diagnostic, not a licence
        // to try passwords, so a locked-out sweep simply stops and reports
        // what it learned.
        if check_test_budget(&state).is_err() {
            break;
        }

        let result = test_saved_inner(&app, &state, &id, None).await;

        summary.tested += 1;

        match result {
            Ok(result) if result.outcome == "success" => summary.ok += 1,
            Ok(result) => {
                let refused = result
                    .code
                    .as_deref()
                    .map(is_credential_rejection)
                    .unwrap_or(false);
                if refused {
                    summary.rejected += 1;
                    summary.rejected_ids.push(id);
                } else {
                    summary.unreachable += 1;
                }
            }
            Err(_) => summary.unreachable += 1,
        }
    }

    Ok(summary)
}

/// The SSH-tunnel half of `test_saved_database`.
async fn test_saved_tunnel(
    app: &AppHandle,
    state: &AppState,
    id: &str,
    row: &DatabaseRow,
    supplied: Option<String>,
    password: Zeroizing<String>,
) -> AppResult<ConnectionTestResult> {
    let incomplete_ssh = || {
        failure(AppError::new(
            "incomplete_connection",
            "This connection is missing its SSH details. Edit it before testing.",
        ))
    };

    let (ssh_host, ssh_port, ssh_username) =
        match (row.ssh_host.clone(), row.ssh_port, row.ssh_username.clone()) {
            (Some(host), Some(port), Some(username))
                if !host.is_empty() && !username.is_empty() =>
            {
                (host, port, username)
            }
            _ => return incomplete_ssh(),
        };

    let auth_method = match row.ssh_auth_method.as_deref() {
        Some(validate::SSH_AUTH_PASSWORD) => validate::SSH_AUTH_PASSWORD,
        Some(validate::SSH_AUTH_PRIVATE_KEY) => validate::SSH_AUTH_PRIVATE_KEY,
        _ => return incomplete_ssh(),
    };

    if row.host.as_deref().unwrap_or_default().is_empty()
        || row.port.unwrap_or(0) == 0
        || row.username.as_deref().unwrap_or_default().is_empty()
    {
        return failure(AppError::new(
            "incomplete_connection",
            "This connection is missing the database host, port or user name. Edit it before testing.",
        ));
    }

    // The SSH credential comes from OS storage and is wiped with the attempt.
    let credential = match auth_method {
        validate::SSH_AUTH_PASSWORD => match credentials::load_ssh_password(id) {
            Ok((credentials::CredentialState::Present, Some(secret))) => {
                ssh::SshCredential::Password(secret)
            }
            Ok(_) => {
                return failure(AppError::new(
                    "credentials_unavailable",
                    "No SSH password is stored for this connection. Edit it and enter the SSH password again.",
                ))
            }
            Err(err) => return failure(err),
        },
        validate::SSH_AUTH_PRIVATE_KEY => {
            let key = match credentials::load_ssh_key_blob(app, id) {
                Ok(Some(key)) => key,
                Ok(None) => {
                    return failure(AppError::new(
                        "credentials_unavailable",
                        "The SSH private key is no longer stored for this connection. Edit it and paste the key again.",
                    ))
                }
                Err(err) => return failure(err),
            };
            let passphrase = match credentials::load_ssh_passphrase(id) {
                Ok((_, value)) => value,
                Err(err) => return failure(err),
            };
            ssh::SshCredential::PrivateKey { key, passphrase }
        }
        _ => return incomplete_ssh(),
    };

    let fields = PreparedSsh {
        host: ssh_host,
        port: ssh_port,
        username: ssh_username,
        auth_method,
        fingerprint: row.ssh_host_key_fingerprint.clone(),
        password: None,
        private_key: None,
        passphrase: None,
    };

    let target = PreparedTarget {
        engine_id: row.engine.clone(),
        // Used only as a fallback banner, so a wrong label could never
        // mislabel a successful connection to a user.
        engine_label: engines::find(&row.engine)
            .map(|engine| engine.label.to_string())
            .unwrap_or_else(|| row.engine.clone()),
        host: row.host.clone().unwrap_or_default(),
        port: row.port.unwrap_or(0),
        database: row.database_name.clone(),
        username: row.username.clone().unwrap_or_default(),
    };

    let plan = plan_host_key(row.ssh_host_key_fingerprint.as_deref(), supplied);

    record_test_budget(state);

    let (result, trusted) = run_tunnel_test(&fields, credential, &target, password, plan).await?;

    // Persist a freshly verified key only once the tunnel really opened.
    if let Some((fingerprint, key_type)) = trusted {
        write_host_key_trust(state, id, &fingerprint, &key_type);
    }

    // Only a real attempt updates the test history; "unverified" has not
    // connected to the database yet.
    if result.outcome == "success" || result.outcome == "failed" {
        let state_value = if result.outcome == "success" {
            TestState::Succeeded
        } else {
            TestState::Failed
        };
        write_test_result(state, id, state_value);

        // A refused password is worth remembering: it is the one failure the
        // that can be fixed, and the notice says so.
        let status = match result.outcome.as_str() {
            "success" => Some("ok"),
            _ => match result.code.as_deref() {
                Some(code) if is_credential_rejection(code) => Some("rejected"),
                _ => None,
            },
        };
        record_credential_status(state, id, status);
    }

    Ok(result)
}

/// A saved connection, resolved and ready to use by a caller other than the
/// connection tests (today: the backup runner).
pub struct SavedTarget {
    /// Where the driver should connect. For a tunnelled connection this is the
    /// loopback end of the tunnel.
    pub target: dbconn::ConnectionTarget,
    /// Live SSH tunnel, when the connection uses one. Must be held for exactly
    /// as long as the connection is in use; dropping it closes the session.
    pub tunnel: Option<ssh::SshTunnel>,
    pub database_name: String,
    pub engine_label: String,
}

/// Resolve a saved connection into a usable target, opening the SSH tunnel when
/// the record uses one.
///
/// The tunnel is only ever opened against a fingerprint that has already been
/// verified: a backup must not be the thing that decides to trust a host key,
/// so an unverified record is refused here and must go through a connection
/// test first. No host key is persisted by this function.
pub async fn open_saved_target(
    app: &AppHandle,
    state: &AppState,
    id: &str,
) -> AppResult<SavedTarget> {
    validate::validate_record_id(id)?;

    let row: DatabaseRow = {
        let conn = state.lock_db()?;
        conn.query_row(
            &format!("SELECT {SELECT_COLUMNS} FROM database_connections WHERE id = ?1"),
            [id],
            row_to_struct,
        )
        .optional()?
        .ok_or_else(not_found)?
    };

    let engine_spec = engines::find(&row.engine);
    let engine_id = engine_spec.map(|engine| engine.id.to_string()).unwrap_or_else(|| row.engine.clone());
    let engine_label = engine_spec
        .map(|engine| engine.label.to_string())
        .unwrap_or_else(|| row.engine.clone());

    if !engines::find(&row.engine).map(|engine| engine.supported).unwrap_or(false) {
        return Err(AppError::new(
            "engine_unsupported",
            format!("BackMeUp cannot back up {engine_label} in this version."),
        ));
    }

    let host = row.host.clone().unwrap_or_default();
    let port = row.port.unwrap_or(0);
    let username = row.username.clone().unwrap_or_default();

    if host.is_empty() || port == 0 || username.is_empty() {
        return Err(AppError::new(
            "incomplete_connection",
            "This connection is missing its host, port or user name. Edit it before backing up.",
        ));
    }

    let password = match credentials::load(id) {
        Ok((credentials::CredentialState::Present, Some(secret))) => secret,
        Ok(_) => {
            return Err(AppError::new(
                "credentials_unavailable",
                "No password is stored for this connection. Edit it and enter the password again.",
            ))
        }
        Err(err) => return Err(err),
    };

    if row.connection_method != engines::SSH_TUNNEL_METHOD_ID {
        return Ok(SavedTarget {
            target: ConnectionTarget {
                engine_id,
                engine_label: engine_label.clone(),
                host,
                port,
                database: row.database_name.clone(),
                username,
                password,
            },
            tunnel: None,
            database_name: row.database_name,
            engine_label,
        });
    }

    let fields = tunnel_fields_from_row(&row)?;
    let credential = tunnel_credential_from_store(app, id, &fields)?;

    // No `supplied` fingerprint: a backup trusts only what has already been
    // compared out of band during a connection test.
    let fingerprint = row
        .ssh_host_key_fingerprint
        .clone()
        .ok_or_else(|| {
            AppError::new(
                "host_key_unverified",
                "Test this connection first so the SSH host key is verified, then back up.",
            )
        })?;

    let tunnel = ssh::open_tunnel(ssh::SshRequest {
        ssh_host: fields.host.clone(),
        ssh_port: fields.port,
        ssh_username: fields.username.clone(),
        credential,
        expected_host_key: fingerprint,
        database_host: host.clone(),
        database_port: port,
    })
    .await
    .map_err(|err| AppError::new(err.code(), err.user_message()))?;

    Ok(SavedTarget {
        target: ConnectionTarget {
            engine_id,
            engine_label: engine_label.clone(),
            // The driver dials the loopback end; the SSH server resolves the
            // real address from `host`/`port` above.
            host: "127.0.0.1".to_string(),
            port: tunnel.local_port(),
            database: row.database_name.clone(),
            username,
            password,
        },
        tunnel: Some(tunnel),
        database_name: row.database_name,
        engine_label,
    })
}

/// Validate the SSH half of a stored record, with no secrets loaded.
fn tunnel_fields_from_row(row: &DatabaseRow) -> AppResult<PreparedSsh> {
    let host = row
        .ssh_host
        .clone()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            AppError::new(
                "incomplete_connection",
                "This connection is missing its SSH details. Edit it before backing up.",
            )
        })?;

    let username = row
        .ssh_username
        .clone()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            AppError::new(
                "incomplete_connection",
                "This connection is missing its SSH user name. Edit it before backing up.",
            )
        })?;

    let auth_method = match row.ssh_auth_method.as_deref() {
        Some(validate::SSH_AUTH_PASSWORD) => validate::SSH_AUTH_PASSWORD,
        Some(validate::SSH_AUTH_PRIVATE_KEY) => validate::SSH_AUTH_PRIVATE_KEY,
        _ => {
            return Err(AppError::new(
                "incomplete_connection",
                "This connection is missing its SSH sign-in method. Edit it before backing up.",
            ))
        }
    };

    Ok(PreparedSsh {
        host,
        port: row.ssh_port.unwrap_or(SSH_DEFAULT_PORT),
        username,
        auth_method,
        fingerprint: row.ssh_host_key_fingerprint.clone(),
        password: None,
        private_key: None,
        passphrase: None,
    })
}

/// Load the SSH credential a saved record needs, from OS-protected storage.
fn tunnel_credential_from_store(
    app: &AppHandle,
    id: &str,
    fields: &PreparedSsh,
) -> AppResult<ssh::SshCredential> {
    match fields.auth_method {
        validate::SSH_AUTH_PASSWORD => match credentials::load_ssh_password(id) {
            Ok((credentials::CredentialState::Present, Some(secret))) => {
                Ok(ssh::SshCredential::Password(secret))
            }
            Ok(_) => Err(AppError::new(
                "credentials_unavailable",
                "No SSH password is stored for this connection. Edit it and enter it again.",
            )),
            Err(err) => Err(err),
        },
        validate::SSH_AUTH_PRIVATE_KEY => {
            let key = match credentials::load_ssh_key_blob(app, id) {
                Ok(Some(key)) => key,
                Ok(None) => {
                    return Err(AppError::new(
                        "credentials_unavailable",
                        "The SSH private key is no longer stored for this connection. Edit it and paste the key again.",
                    ))
                }
                Err(err) => return Err(err),
            };

            let passphrase = credentials::load_ssh_passphrase(id).map(|(_, value)| value)?;
            Ok(ssh::SshCredential::PrivateKey { key, passphrase })
        }
        _ => Err(AppError::internal()),
    }
}

/// Persist the outcome of a test. Only the flag and a timestamp are stored -
/// never the server banner, the error text or any credential.
fn write_test_result(state: &AppState, id: &str, result: TestState) {
    if let Ok(mut conn) = state.lock_db() {
        if let Ok(tx) = conn.transaction_with_behavior(TransactionBehavior::Immediate) {
            let _ = tx.execute(
                "UPDATE database_connections
                 SET last_tested_at = ?2, last_test_ok = ?3, updated_at = ?2
                 WHERE id = ?1",
                rusqlite::params![id, util::now_secs(), result.as_flag()],
            );
            let _ = tx.commit();
        }
    }
}

/// Whether an error means the server refused the secret that was sent.
///
/// A password that was rotated on the server leaves the saved copy behind,
/// and this is what tells that apart from a network problem or a missing
/// privilege.
pub fn is_credential_rejection(code: &str) -> bool {
    matches!(code, "auth_failed" | "ssh_auth_failed")
}

/// Record what the last attempt said about the saved secret.
///
/// `None` means "not known": a failure that had nothing to do with the
/// password says nothing about it, and the previous answer is cleared rather
/// than guessed at.
pub fn record_credential_status(state: &AppState, id: &str, status: Option<&str>) {
    if let Ok(mut conn) = state.lock_db() {
        if let Ok(tx) = conn.transaction_with_behavior(TransactionBehavior::Immediate) {
            let _ = tx.execute(
                "UPDATE database_connections
                 SET credential_status = ?2, credential_checked_at = ?3
                 WHERE id = ?1",
                rusqlite::params![id, status, util::now_secs()],
            );
            let _ = tx.commit();
        }
    }
}

/// What an outcome says about the saved secret.
fn credential_status_from<T>(outcome: &AppResult<T>) -> Option<&'static str> {
    match outcome {
        Ok(_) => Some("ok"),
        Err(err) if is_credential_rejection(&err.code) => Some("rejected"),
        Err(_) => None,
    }
}

fn not_found() -> AppError {
    AppError::new(
        "not_found",
        "That database connection could not be found.",
    )
}

// ---------------------------------------------------------------------------
// Create / update / delete
// ---------------------------------------------------------------------------

/// Persist every secret a connection needs.
fn store_connection_secrets(
    app: &AppHandle,
    id: &str,
    prepared: &PreparedConnection,
    password: &Zeroizing<String>,
    ssh_credential: Option<ssh::SshCredential>,
) -> AppResult<()> {
    credentials::store(id, prepared.target.username.as_str(), password)?;

    match (&prepared.ssh, ssh_credential) {
        (Some(fields), Some(credential)) => store_ssh_credential(app, id, fields, credential),
        _ => Ok(()),
    }
}

/// Persist the SSH secret a form supplied for one connection.
fn store_ssh_credential(
    app: &AppHandle,
    id: &str,
    fields: &PreparedSsh,
    credential: ssh::SshCredential,
) -> AppResult<()> {
    match credential {
        ssh::SshCredential::Password(password) => {
            credentials::store_ssh_password(id, fields.username.as_str(), &password)
        }
        ssh::SshCredential::PrivateKey { key, passphrase } => {
            credentials::store_ssh_key_blob(app, id, &key)?;
            match passphrase.as_ref() {
                // A key with a passphrase stores it; a key without one clears
                // any passphrase that belonged to the replaced key.
                Some(passphrase) => credentials::store_ssh_passphrase(id, passphrase),
                None => credentials::delete_ssh_passphrase(id),
            }
        }
    }
}

/// Build the replacement SSH credential an update form carried, if any.
///
/// Unlike the test path, an omitted password or key is allowed: the stored
/// secret is kept. A supplied key is always parsed, and a key makes the
/// form's passphrase authoritative.
fn optional_form_ssh_credential(fields: &PreparedSsh) -> AppResult<Option<ssh::SshCredential>> {
    match fields.auth_method {
        validate::SSH_AUTH_PASSWORD => match fields.password.clone() {
            Some(password) => Ok(Some(ssh::SshCredential::Password(password))),
            None => Ok(None),
        },
        validate::SSH_AUTH_PRIVATE_KEY => match fields.private_key.clone() {
            Some(key) => {
                verify_key_material(&key, fields.passphrase.as_ref())?;
                Ok(Some(ssh::SshCredential::PrivateKey {
                    key,
                    passphrase: fields.passphrase.clone(),
                }))
            }
            None => Ok(None),
        },
        _ => Err(AppError::internal()),
    }
}

/// Remove the SSH secrets the new addressing can no longer use.
fn prune_ssh_secrets(app: &AppHandle, id: &str, fields: &PreparedSsh) {
    let report = |result: AppResult<()>| {
        if let Err(err) = result {
            eprintln!("[backmeup] an unused SSH secret could not be removed: {err}");
        }
    };

    if fields.auth_method == validate::SSH_AUTH_PASSWORD {
        credentials::delete_ssh_key_blob(app, id);
        report(credentials::delete_ssh_passphrase(id));
    } else {
        report(credentials::delete_ssh_password(id));
    }
}

/// Remove every SSH secret for one connection, used when a record leaves the
/// tunnel method. The database password is untouched.
fn delete_ssh_secrets(app: &AppHandle, id: &str) {
    let _ = credentials::delete_ssh_password(id);
    let _ = credentials::delete_ssh_passphrase(id);
    credentials::delete_ssh_key_blob(app, id);
}

/// The public SSH columns for a connection, derived from its prepared form.
fn viewable_ssh_fields(
    ssh: &Option<PreparedSsh>,
) -> (Option<String>, Option<u16>, Option<String>, Option<String>) {
    match ssh {
        Some(fields) => (
            Some(fields.host.clone()),
            Some(fields.port),
            Some(fields.username.clone()),
            Some(fields.auth_method.to_string()),
        ),
        None => (None, None, None, None),
    }
}

/// Save a new connection and its credentials.
///
/// Order matters: the record is written first, and only then are the secrets
/// stored under the new id. If a secret write fails the record is removed
/// again, so a connection is never left without the credentials it needs.
#[tauri::command]
pub fn create_database(
    app: AppHandle,
    state: State<'_, AppState>,
    label: String,
    engine: String,
    connection_method: String,
    host: Option<String>,
    port: Option<i64>,
    database_name: String,
    username: String,
    password: String,
    ssh: Option<SshTunnelForm>,
) -> AppResult<DatabaseView> {
    require_session(&state)?;
    require_credential_store()?;

    let password = validate_password_shape(&password)?;

    let prepared = prepare(
        &label,
        &engine,
        &connection_method,
        host,
        port,
        &database_name,
        Some(username),
        ssh.as_ref(),
    )?;

    // Resolve the SSH credential up front, so a malformed key is refused
    // before anything is written.
    let ssh_credential = match &prepared.ssh {
        Some(fields) => Some(form_ssh_credential(fields)?),
        None => None,
    };

    let label = validate::validate_label(&label, "Name")?;
    let id = util::random_id()?;
    let now = util::now_secs();

    let (ssh_host, ssh_port, ssh_username, ssh_auth_method) = viewable_ssh_fields(&prepared.ssh);
    // A fingerprint only exists once a verification has been
    // flow; whatever the form carries was normalised during preparation.
    let ssh_host_key_fingerprint = prepared
        .ssh
        .as_ref()
        .and_then(|fields| fields.fingerprint.clone());

    {
        let mut conn = state.lock_db()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        tx.execute(
            "INSERT INTO database_connections
               (id, label, engine, connection_method, host, port, database_name,
                username, secret_ref, created_at, updated_at,
                ssh_host, ssh_port, ssh_username, ssh_auth_method,
                ssh_host_key_fingerprint)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10, ?11, ?12, ?13, ?14, ?15)",
            rusqlite::params![
                id.as_str(),
                label.as_str(),
                prepared.target.engine_id.as_str(),
                prepared.method_id.as_str(),
                prepared.target.host.as_str(),
                i64::from(prepared.target.port),
                prepared.target.database.as_str(),
                prepared.target.username.as_str(),
                // The reference is the credential id, never the secret.
                id.as_str(),
                now,
                ssh_host.as_deref(),
                ssh_port.map(i64::from),
                ssh_username.as_deref(),
                ssh_auth_method.as_deref(),
                ssh_host_key_fingerprint.as_deref(),
            ],
        )?;

        db::audit_config(&tx, "database", "created", Some("connection_added"));
        tx.commit()?;
    }

    // A credential failure removes the record and every secret already written
    // for it, so the UI never shows a connection it cannot use.
    if let Err(err) = store_connection_secrets(&app, &id, &prepared, &password, ssh_credential) {
        let _ = credentials::delete(&id);
        delete_ssh_secrets(&app, &id);
        if let Ok(conn) = state.lock_db() {
            let _ = conn.execute(
                "DELETE FROM database_connections WHERE id = ?1",
                [id.as_str()],
            );
        }
        return Err(err);
    }

    // Google Drive, when connected, gets a `BackMeUp/<database>` folder for the
    // new connection without being asked. Background and best effort: the
    // folders are also ensured before every upload, so a hiccup here is not
    // worth failing a saved connection over.
    drive::spawn_folder_sync(app);

    Ok(DatabaseView {
        id: id.to_string(),
        label,
        engine: prepared.target.engine_id.clone(),
        engine_label: prepared.target.engine_label.clone(),
        connection_method: prepared.method_id.clone(),
        connection_method_label: engines::find_method(&prepared.method_id)
            .map(|m| m.label.to_string())
            .unwrap_or_default(),
        host: Some(prepared.target.host.clone()),
        port: Some(prepared.target.port),
        database_name: prepared.target.database.clone(),
        username: Some(prepared.target.username.clone()),
        created_at: now,
        test_state: TestState::NeverTested,
        last_tested_at: None,
        has_credentials: true,
        ssh_host,
        ssh_port,
        ssh_username,
        ssh_auth_method,
        has_ssh_credentials: prepared.ssh.is_some(),
        ssh_host_key_fingerprint: ssh_host_key_fingerprint
            .map(|value| display_fingerprint(&value)),
        ssh_host_key_type: None,
    })
}

/// Change the addressing settings of a saved connection.
///
/// Stored secrets are kept unless the command carries replacements: editing a
/// host must not silently discard a credential. Replacement SSH secrets are
/// written before the row is updated, and secrets the new method cannot use
/// are removed only after the update committed.
#[tauri::command]
pub fn update_database(
    app: AppHandle,
    state: State<'_, AppState>,
    id: String,
    label: String,
    engine: String,
    connection_method: String,
    host: Option<String>,
    port: Option<i64>,
    database_name: String,
    username: String,
    ssh: Option<SshTunnelForm>,
) -> AppResult<DatabaseView> {
    require_session(&state)?;
    require_credential_store()?;
    validate::validate_record_id(&id)?;

    let label = validate::validate_label(&label, "Name")?;
    let prepared = prepare(
        &label,
        &engine,
        &connection_method,
        host,
        port,
        &database_name,
        Some(username),
        ssh.as_ref(),
    )?;

    // The current state decides whether secrets are kept and whether the
    // verified host key still applies.
    let existing = {
        let conn = state.lock_db()?;
        let row: Option<DatabaseRow> = conn
            .query_row(
                &format!("SELECT {SELECT_COLUMNS} FROM database_connections WHERE id = ?1"),
                [id.as_str()],
                row_to_struct,
            )
            .optional()?;

        row.ok_or_else(not_found)?
    };

    // A changed SSH endpoint invalidates the verified host key.
    let ssh_endpoint_changed =
        match (existing.ssh_host.as_deref(), existing.ssh_port, prepared.ssh.as_ref()) {
            (Some(old_host), Some(old_port), Some(fields)) => {
                old_host != fields.host || old_port != fields.port
            }
            _ => false,
        };

    // The form may carry a fingerprint that was just verified; otherwise a
    // stored one survives unless the SSH endpoint moved. A supplied
    // fingerprint that differs from the stored one has not been verified
    // against the server yet, so its key type is unknown until the next
    // verified test.
    let (new_fingerprint, new_key_type) = match prepared.ssh.as_ref() {
        Some(fields) => match (fields.fingerprint.clone(), ssh_endpoint_changed) {
            (Some(supplied), _)
                if Some(supplied.as_str()) != existing.ssh_host_key_fingerprint.as_deref() =>
            {
                (Some(supplied), None)
            }
            (_, true) => (None, None),
            _ => (
                existing.ssh_host_key_fingerprint.clone(),
                existing.ssh_host_key_type.clone(),
            ),
        },
        None => (None, None),
    };

    // Replacement secrets go in first: each store replaces its target
    // atomically, and a failure leaves the existing record and secrets
    // untouched.
    let replacement = match &prepared.ssh {
        Some(fields) => optional_form_ssh_credential(fields)?,
        None => None,
    };

    if let (Some(fields), Some(credential)) = (&prepared.ssh, replacement) {
        store_ssh_credential(&app, &id, fields, credential)?;
    }

    let (ssh_host, ssh_port, ssh_username, ssh_auth_method) = viewable_ssh_fields(&prepared.ssh);
    let now = util::now_secs();

    {
        let mut conn = state.lock_db()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let changed = tx.execute(
            "UPDATE database_connections
             SET label = ?2, engine = ?3, connection_method = ?4, host = ?5,
                 port = ?6, database_name = ?7, username = ?8, updated_at = ?9,
                 ssh_host = ?10, ssh_port = ?11, ssh_username = ?12,
                 ssh_auth_method = ?13, ssh_host_key_fingerprint = ?14,
                 ssh_host_key_type = ?15
             WHERE id = ?1",
            rusqlite::params![
                id.as_str(),
                label.as_str(),
                prepared.target.engine_id.as_str(),
                prepared.method_id.as_str(),
                prepared.target.host.as_str(),
                i64::from(prepared.target.port),
                prepared.target.database.as_str(),
                prepared.target.username.as_str(),
                now,
                ssh_host.as_deref(),
                ssh_port.map(i64::from),
                ssh_username.as_deref(),
                ssh_auth_method.as_deref(),
                new_fingerprint.as_deref(),
                new_key_type.as_deref(),
            ],
        )?;

        if changed != 1 {
            return Err(not_found());
        }

        // Addressing changed, so the previous result no longer describes this
        // connection. Reset to "never tested" rather than showing a stale
        // success.
        tx.execute(
            "UPDATE database_connections SET last_tested_at = NULL, last_test_ok = NULL WHERE id = ?1",
            [id.as_str()],
        )?;

        db::audit_config(&tx, "database", "updated", Some("connection_edited"));
        tx.commit()?;
    }

    // Secrets the new method cannot use are removed only after the record was
    // updated successfully.
    match &prepared.ssh {
        Some(fields) => prune_ssh_secrets(&app, &id, fields),
        None if existing.connection_method == engines::SSH_TUNNEL_METHOD_ID => {
            delete_ssh_secrets(&app, &id);
        }
        None => {}
    }

    Ok(DatabaseView {
        id: id.clone(),
        label,
        engine: prepared.target.engine_id.clone(),
        engine_label: prepared.target.engine_label.clone(),
        connection_method: prepared.method_id.clone(),
        connection_method_label: engines::find_method(&prepared.method_id)
            .map(|m| m.label.to_string())
            .unwrap_or_default(),
        host: Some(prepared.target.host.clone()),
        port: Some(prepared.target.port),
        database_name: prepared.target.database.clone(),
        username: Some(prepared.target.username.clone()),
        created_at: existing.created_at,
        test_state: TestState::NeverTested,
        last_tested_at: None,
        has_credentials: credentials::exists(&id),
        has_ssh_credentials: prepared.ssh.is_some()
            && (credentials::ssh_password_exists(&id)
                || credentials::ssh_key_blob_exists(&app, &id)),
        ssh_host,
        ssh_port,
        ssh_username,
        ssh_auth_method,
        ssh_host_key_fingerprint: new_fingerprint.as_deref().map(display_fingerprint),
        ssh_host_key_type: new_key_type,
    })
}

/// Replace the stored password for a saved connection.
///
/// The new secret replaces the old one in the Credential Manager. The previous
/// secret is only removed once the new one is in place, so a failure part-way
/// through cannot leave the account with no credential at all.
#[tauri::command]
pub fn update_database_credentials(
    state: State<'_, AppState>,
    id: String,
    username: String,
    password: String,
) -> AppResult<()> {
    require_session(&state)?;
    require_credential_store()?;
    validate::validate_record_id(&id)?;

    let username = validate::validate_username(&username)?
        .ok_or_else(|| AppError::invalid_input("Enter a database user name."))?;
    let password = validate_password_shape(&password)?;

    // The connection must exist before a secret is written for it.
    {
        let conn = state.lock_db()?;
        let exists: Option<String> = conn
            .query_row(
                "SELECT id FROM database_connections WHERE id = ?1",
                [id.as_str()],
                |row| row.get(0),
            )
            .optional()?;

        if exists.is_none() {
            return Err(not_found());
        }
    }

    // `CredWriteW` replaces the entry for this target atomically, so the old
    // secret does not survive alongside the new one.
    credentials::store(&id, &username, &password)?;

    let now = util::now_secs();
    {
        let mut conn = state.lock_db()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "UPDATE database_connections SET username = ?2, updated_at = ?3 WHERE id = ?1",
            rusqlite::params![id.as_str(), username.as_str(), now],
        )?;
        // New credentials invalidate the previous verdict.
        tx.execute(
            "UPDATE database_connections SET last_tested_at = NULL, last_test_ok = NULL WHERE id = ?1",
            [id.as_str()],
        )?;
        // The notice about a refused password is about the *old* password, so
        // it goes with it. The next test decides again.
        tx.execute(
            "UPDATE database_connections
             SET credential_status = NULL, credential_checked_at = NULL
             WHERE id = ?1",
            [id.as_str()],
        )?;
        db::audit_config(
            &tx,
            "database",
            "updated",
            Some("credentials_changed"),
        );
        tx.commit()?;
    }

    Ok(())
}

/// Remove a connection record and the credential that belongs to it.
///
/// The credential is scoped to this connection's id, so other connections are
/// untouched. Referenced backups keep their history row but lose the link
/// (`ON DELETE SET NULL`), so deleting a database never rewrites past records.
#[tauri::command]
pub fn delete_database(
    app: AppHandle,
    state: State<'_, AppState>,
    id: String,
) -> AppResult<()> {
    require_session(&state)?;
    validate::validate_record_id(&id)?;

    {
        let mut conn = state.lock_db()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let existing: Option<String> = tx
            .query_row(
                "SELECT id FROM database_connections WHERE id = ?1",
                [id.as_str()],
                |row| row.get(0),
            )
            .optional()?;

        if existing.is_none() {
            return Err(not_found());
        }

        tx.execute("DELETE FROM database_connections WHERE id = ?1", [id.as_str()])?;
        db::audit_config(&tx, "database", "deleted", Some("connection_removed"));
        tx.commit()?;
    }

    // Best effort cleanup: a leftover credential is unreachable without the
    // record, and must never fail the deletion.
    if let Err(err) = credentials::delete(&id) {
        eprintln!("[backmeup] orphaned credential could not be removed: {err}");
    }
    delete_ssh_secrets(&app, &id);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ssh_form() -> SshTunnelForm {
        SshTunnelForm {
            ssh_host: "ssh.example.com".into(),
            ssh_port: Some(22),
            ssh_username: "deploy".into(),
            ssh_auth_method: "password".into(),
            ssh_password: Some("secret".into()),
            ssh_private_key: None,
            ssh_key_passphrase: None,
            ssh_host_key_fingerprint: None,
        }
    }

    #[test]
    fn the_friendly_label_is_never_used_as_the_database_name() {
        // This is the Hostinger case: the friendly label is a short human name,
        // while the database is the prefixed schema hPanel created.
        let prepared = prepare(
            "Production",
            "mysql",
            "direct",
            Some("srv123.hosterlive.com".into()),
            Some(3306),
            "u912345678_shop",
            Some("u912345678_admin".into()),
            None,
        )
        .unwrap();

        assert_eq!(
            prepared.target.database, "u912345678_shop",
            "the real schema is used"
        );
        assert_ne!(prepared.target.database, "Production");
        assert_eq!(prepared.target.host, "srv123.hosterlive.com");
        assert_eq!(prepared.target.port, 3306);
        assert_eq!(prepared.target.username, "u912345678_admin");
    }

    #[test]
    fn the_database_name_reaches_the_adapter_as_the_schema() {
        // Proves the value handed to the driver is the schema, not the label.
        let prepared = prepare(
            "Shop live",
            "mariadb",
            "local",
            None,
            None,
            "u123456789_shop",
            Some("root".into()),
            None,
        )
        .unwrap();

        let connection = prepared
            .target
            .into_connection(Zeroizing::new("secret".to_string()));

        assert_eq!(connection.database, "u123456789_shop");
        assert_eq!(connection.engine_id, "mariadb");
        assert_eq!(connection.host, "127.0.0.1");
        assert_eq!(connection.port, 3306);
    }

#[test]
    fn test_states_are_distinct() {
        assert_eq!(TestState::from_flag(None), TestState::NeverTested);
        assert_eq!(TestState::from_flag(Some(1)), TestState::Succeeded);
        assert_eq!(TestState::from_flag(Some(0)), TestState::Failed);
        // A never-tested connection must never look like a failed one.
        assert_ne!(TestState::NeverTested, TestState::Failed);
    }

    #[test]
    fn direct_connections_require_a_valid_host() {
        let err = prepare(
            "Prod",
            "mysql",
            "direct",
            None,
            Some(3306),
            "shop",
            Some("root".into()),
            None,
        )
        .unwrap_err();
        assert_eq!(err.code, "invalid_input");
    }

    #[test]
    fn local_connections_resolve_to_the_engines_loopback() {
        let prepared = prepare(
            "Local",
            "postgresql",
            "local",
            None,
            None,
            "shop",
            Some("postgres".into()),
            None,
        )
        .unwrap();

        assert_eq!(prepared.target.host, "127.0.0.1");
        assert_eq!(prepared.target.port, 5432, "the engine default is applied");
        assert_eq!(prepared.method_id, "local");
    }

    #[test]
    fn ports_default_per_engine_but_stay_editable() {
        let prepared = prepare(
            "P",
            "sqlserver",
            "direct",
            Some("db.example.com".into()),
            None,
            "s",
            Some("sa".into()),
            None,
        )
        .unwrap();
        assert_eq!(prepared.target.port, 1433);

        let custom = prepare(
            "P",
            "sqlserver",
            "direct",
            Some("db.example.com".into()),
            Some(14330),
            "s",
            Some("sa".into()),
            None,
        )
        .unwrap();
        assert_eq!(custom.target.port, 14330, "a custom port must win");
    }

    #[test]
    fn unknown_engines_and_methods_are_refused() {
        assert!(prepare(
            "x",
            "sqlite",
            "direct",
            Some("h".into()),
            Some(1),
            "d",
            Some("u".into()),
            None
        )
        .is_err());
        assert!(prepare(
            "x",
            "mysql",
            "proxy",
            Some("h".into()),
            Some(1),
            "d",
            Some("u".into()),
            None
        )
        .is_err());
    }

    #[test]
    fn a_user_name_is_required() {
        let err = prepare(
            "x",
            "mysql",
            "direct",
            Some("h.example.com".into()),
            Some(1),
            "d",
            None,
            None,
        )
        .unwrap_err();
        assert_eq!(err.code, "invalid_input");
    }

    #[test]
    fn password_shape_is_bounded() {
        assert!(validate_password_shape("").is_err());
        assert!(validate_password_shape("x").is_ok());
        assert!(validate_password_shape(&"x".repeat(513)).is_err());
        assert!(validate_password_shape(&"x".repeat(512)).is_ok());
    }

    #[test]
    fn credential_notes_explain_the_storage_model() {
        assert!(CREDENTIAL_STORAGE_NOTE.contains("Credential Manager"));
        assert!(CREDENTIAL_STORAGE_UNAVAILABLE.contains("No password is stored anywhere else"));
    }

    #[test]
    fn the_tunnel_method_needs_a_well_formed_ssh_form() {
        // ssh-tunnel without a form is refused.
        let err = prepare(
            "T",
            "mysql",
            "ssh-tunnel",
            None,
            None,
            "shop",
            Some("dbuser".into()),
            None,
        )
        .unwrap_err();
        assert_eq!(err.code, "invalid_input");

        // ssh-tunnel is not offered for engines whose adapter cannot tunnel.
        let err = prepare(
            "T",
            "postgresql",
            "ssh-tunnel",
            None,
            None,
            "shop",
            Some("dbuser".into()),
            Some(&sample_ssh_form()),
        )
        .unwrap_err();
        assert_eq!(err.code, "invalid_input");
    }

    #[test]
    fn an_ssh_tunnel_defaults_the_database_address_to_loopback() {
        let prepared = prepare(
            "T",
            "mysql",
            "ssh-tunnel",
            None,
            None,
            "shop",
            Some("dbuser".into()),
            Some(&sample_ssh_form()),
        )
        .unwrap();

        assert_eq!(prepared.method_id, "ssh-tunnel");
        // Dialled from the SSH server's point of view: the engine's own
        // loopback, not the SSH server's address.
        assert_eq!(prepared.target.host, "127.0.0.1");
        assert_eq!(prepared.target.port, 3306);

        let fields = prepared.ssh.expect("the ssh half is prepared");
        assert_eq!(fields.host, "ssh.example.com");
        assert_eq!(fields.port, 22);
        assert_eq!(fields.auth_method, validate::SSH_AUTH_PASSWORD);
    }

    #[test]
    fn ssh_forms_are_validated_before_any_network_or_storage() {
        let valid = sample_ssh_form();

        let mut form = sample_ssh_form();
        form.ssh_host = String::new();
        assert!(prepare(
            "T", "mysql", "ssh-tunnel", None, None, "shop",
            Some("dbuser".into()), Some(&form)
        )
        .is_err());

        let mut form = sample_ssh_form();
        form.ssh_port = Some(0);
        assert!(prepare(
            "T", "mysql", "ssh-tunnel", None, None, "shop",
            Some("dbuser".into()), Some(&form)
        )
        .is_err());

        let mut form = sample_ssh_form();
        form.ssh_auth_method = "agent".into();
        assert!(prepare(
            "T", "mysql", "ssh-tunnel", None, None, "shop",
            Some("dbuser".into()), Some(&form)
        )
        .is_err());

        let mut form = sample_ssh_form();
        form.ssh_host_key_fingerprint = Some("not-a-fingerprint".into());
        assert!(prepare(
            "T", "mysql", "ssh-tunnel", None, None, "shop",
            Some("dbuser".into()), Some(&form)
        )
        .is_err());

        // The valid control case proves the refusals above are about the
        // mutated field, not about the form shape itself.
        assert!(prepare(
            "T", "mysql", "ssh-tunnel", None, None, "shop",
            Some("dbuser".into()), Some(&valid)
        )
        .is_ok());
    }

    #[test]
    fn host_key_plans_only_persist_a_deliberate_change() {
        assert!(matches!(plan_host_key(None, None), HostKeyPlan::Verify));

        assert!(matches!(
            plan_host_key(Some("stored"), None),
            HostKeyPlan::Trust { persist: false, .. }
        ));

        assert!(matches!(
            plan_host_key(None, Some("supplied".into())),
            HostKeyPlan::Trust { persist: true, .. }
        ));

        assert!(matches!(
            plan_host_key(Some("same"), Some("same".into())),
            HostKeyPlan::Trust { persist: false, .. }
        ));

        assert!(matches!(
            plan_host_key(Some("old"), Some("new".into())),
            HostKeyPlan::Trust { persist: true, .. }
        ));
    }

    #[test]
    fn host_key_results_use_the_display_fingerprint() {
        let info = ssh::HostKeyInfo {
            key_type: "ssh-ed25519".to_string(),
            fingerprint: "AAAAC3NzaC1lZDI1NTE5AAAAIAAA".to_string(),
        };

        let result = unverified(&info);
        assert_eq!(result.outcome, "unverified");
        assert_eq!(
            result.host_key_fingerprint.as_deref(),
            Some("SHA256:AAAAC3NzaC1lZDI1NTE5AAAAIAAA")
        );
        assert_eq!(result.host_key_type.as_deref(), Some("ssh-ed25519"));
        assert!(result.server_banner.is_none(), "nothing was connected yet");

        let changed = host_key_changed(&info, Some("AAAAotherkey"));
        assert_eq!(changed.outcome, "failed");
        assert!(changed.message.contains("SHA256:AAAAotherkey"));
        assert!(changed
            .message
            .contains("SHA256:AAAAC3NzaC1lZDI1NTE5AAAAIAAA"));
    }
}
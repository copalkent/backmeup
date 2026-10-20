use std::sync::Mutex;
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use serde::Serialize;
use tauri::{AppHandle, State};
use tauri_plugin_dialog::DialogExt;
use zeroize::Zeroizing;

use crate::db;
use crate::error::{AppError, AppResult};
use crate::password;
use crate::recovery;
use crate::session::AuthState;
use crate::util;
use crate::validate;

/// Login throttling policy.
const LOGIN_WINDOW: Duration = Duration::from_secs(5 * 60);
const LOGIN_THRESHOLD: usize = 5;
const LOGIN_BASE_PENALTY: Duration = Duration::from_secs(30);
const LOGIN_MAX_PENALTY: Duration = Duration::from_secs(15 * 60);

/// Global (all identifiers) login ceiling so attempts cannot be spread across
/// addresses to sidestep the per-account limiter in a single owner app.
const LOGIN_GLOBAL_THRESHOLD: usize = 20;
const LOGIN_GLOBAL_WINDOW: Duration = Duration::from_secs(5 * 60);

/// Upper bound on the number of per-identifier throttles kept in memory.
const MAX_TRACKED_LOGIN_KEYS: usize = 64;

/// Recovery throttling policy. Always temporary - never a permanent lockout.
const RECOVERY_WINDOW: Duration = Duration::from_secs(10 * 60);
const RECOVERY_THRESHOLD: usize = 10;
const RECOVERY_BASE_PENALTY: Duration = Duration::from_secs(30);
const RECOVERY_MAX_PENALTY: Duration = Duration::from_secs(10 * 60);

pub struct AppState {
    pub db: Mutex<Connection>,
    pub auth: Mutex<AuthState>,
}

impl AppState {
    pub fn new(db: Connection) -> Self {
        Self {
            db: Mutex::new(db),
            auth: Mutex::new(AuthState::default()),
        }
    }

    /// Lock order is always `db` then `auth`, and the two guards are never
    /// held at the same time, so the state can not deadlock.
    pub(crate) fn lock_db(&self) -> AppResult<std::sync::MutexGuard<'_, Connection>> {
        self.db.lock().map_err(|_| AppError::internal())
    }

    pub(crate) fn lock_auth(&self) -> AppResult<std::sync::MutexGuard<'_, AuthState>> {
        self.auth.lock().map_err(|_| AppError::internal())
    }
}

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct OwnerProfile {
    pub full_name: String,
    pub email: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BootstrapState {
    /// No owner account exists yet: show the first-run setup screen.
    pub needs_setup: bool,
    /// A verified, unexpired Rust-side session exists.
    pub authenticated: bool,
    /// The owner confirmed that they saved their first recovery code set.
    pub setup_confirmed: bool,
    pub owner: Option<OwnerProfile>,
    pub remaining_recovery_codes: Option<u32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryCodesView {
    /// Plaintext codes, shown exactly once and never persisted.
    pub recovery_codes: Vec<String>,
    pub code_count: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryCodeStatus {
    pub total: u32,
    pub used: u32,
    pub remaining: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportResult {
    pub saved: bool,
    pub file_name: Option<String>,
}

// ---------------------------------------------------------------------------
// Data access helpers - every statement is parameterised, no SQL is built
// from user input.
// ---------------------------------------------------------------------------

fn fetch_owner(conn: &Connection, email: &str) -> AppResult<Option<(i64, String, String)>> {
    let owner = conn
        .query_row(
            "SELECT id, full_name, password_hash FROM owner_account WHERE email = ?1",
            [email],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?;
    Ok(owner)
}

fn fetch_owner_profile(conn: &Connection, id: i64) -> AppResult<Option<OwnerProfile>> {
    let owner = conn
        .query_row(
            "SELECT full_name, email FROM owner_account WHERE id = ?1",
            [id],
            |row| {
                Ok(OwnerProfile {
                    full_name: row.get(0)?,
                    email: row.get(1)?,
                })
            },
        )
        .optional()?;
    Ok(owner)
}

fn fetch_owner_hash(conn: &Connection, id: i64) -> AppResult<Option<String>> {
    let hash = conn
        .query_row(
            "SELECT password_hash FROM owner_account WHERE id = ?1",
            [id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    Ok(hash)
}

fn count_active_codes(conn: &Connection) -> AppResult<(u32, u32)> {
    let total: i64 = conn.query_row(
        "SELECT COUNT(*) FROM recovery_codes rc
         JOIN recovery_code_sets rcs ON rcs.id = rc.set_id
         WHERE rcs.status = 'active'",
        [],
        |row| row.get(0),
    )?;
    let used: i64 = conn.query_row(
        "SELECT COUNT(*) FROM recovery_codes rc
         JOIN recovery_code_sets rcs ON rcs.id = rc.set_id
         WHERE rcs.status = 'active' AND rc.used_at IS NOT NULL",
        [],
        |row| row.get(0),
    )?;
    Ok((total as u32, used as u32))
}

/// Authorisation gate for every privileged command.
///
/// Two independent checks: an unexpired in-memory session **and** a matching
/// owner row in the database. Hiding a screen in the frontend is never part of
/// this decision, so the boundary is enforced in Rust for every privileged
/// command.
///
/// Shared with the backup-domain modules (`databases`, `destinations`,
/// `backups`) so every privileged command goes through the same gate.
pub(crate) fn require_session(state: &AppState) -> AppResult<(i64, OwnerProfile)> {
    let session = state
        .lock_auth()?
        .current_session()
        .ok_or_else(AppError::unauthorized)?;

    let owner = {
        let conn = state.lock_db()?;
        fetch_owner_profile(&conn, session.owner_id)?
    };

    match owner {
        Some(owner) if owner.email == session.email => Ok((session.owner_id, owner)),
        _ => {
            state.lock_auth()?.end_session();
            Err(AppError::unauthorized())
        }
    }
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn app_bootstrap_state(state: State<'_, AppState>) -> AppResult<BootstrapState> {
    let (owner_row, total, used) = {
        let conn = state.lock_db()?;
        let row = conn
            .query_row(
                "SELECT id, full_name, email, setup_confirmed FROM owner_account LIMIT 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?;
        let (total, used) = count_active_codes(&conn)?;
        (row, total, used)
    };

    let Some((id, full_name, email, setup_confirmed)) = owner_row else {
        return Ok(BootstrapState {
            needs_setup: true,
            authenticated: false,
            setup_confirmed: false,
            owner: None,
            remaining_recovery_codes: None,
        });
    };

    let authenticated = state
        .lock_auth()?
        .peek_session()
        .map(|s| s.owner_id == id)
        .unwrap_or(false);

    // Data minimisation: the owner profile and recovery code counters are only
    // disclosed once the backend has confirmed a live session, so the
    // unauthenticated login screen cannot be used to probe for an account.
    if !authenticated {
        return Ok(BootstrapState {
            needs_setup: false,
            authenticated: false,
            setup_confirmed: setup_confirmed == 1,
            owner: None,
            remaining_recovery_codes: None,
        });
    }

    Ok(BootstrapState {
        needs_setup: false,
        authenticated: true,
        setup_confirmed: setup_confirmed == 1,
        owner: Some(OwnerProfile { full_name, email }),
        remaining_recovery_codes: Some(total.saturating_sub(used)),
    })
}

// ---------------------------------------------------------------------------
// First-run setup
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn setup_owner(
    state: State<'_, AppState>,
    full_name: String,
    email: String,
    password: String,
    confirm_password: String,
) -> AppResult<RecoveryCodesView> {
    // All validation runs before any state is touched.
    let full_name = validate::validate_full_name(&full_name)?;
    let email = validate::validate_email(&email)?;
    validate::validate_password_pair(&password, &confirm_password)?;

    let password = Zeroizing::new(password);
    let _confirm_password = Zeroizing::new(confirm_password);

    // Serialise concurrent initialisation inside this process. The single-row
    // constraint on `owner_account` is the authoritative cross-check.
    {
        let mut auth = state.lock_auth()?;
        if !auth.try_lock_setup() {
            return Err(AppError::new(
                "setup_in_progress",
                "Initial setup is already running. Please wait a moment.",
            ));
        }
    }

    let outcome = create_owner(&state, &full_name, &email, &password);

    state.lock_auth()?.unlock_setup();

    let codes = outcome?;
    let code_count = codes.len() as u32;

    {
        let mut auth = state.lock_auth()?;
        auth.store_pending_codes(&codes);
        // The owner has just proven possession of the password, so a session is
        // established here to gate the "codes saved" confirmation step.
        auth.start_session(OWNER_ID, email);
    }

    Ok(RecoveryCodesView {
        recovery_codes: codes,
        code_count,
    })
}

const OWNER_ID: i64 = 1;

fn create_owner(
    state: &AppState,
    full_name: &str,
    email: &str,
    password: &str,
) -> AppResult<Vec<String>> {
    // Argon2id work happens before the write transaction so the database lock
    // is held for the shortest possible time.
    let password_hash = password::hash_password(password)?;
    let bundle = recovery::generate_bundle()?;
    let codes = bundle.codes();
    let set_id = util::random_id()?;

    let mut hashed: Vec<Zeroizing<String>> = Vec::with_capacity(codes.len());
    for code in &codes {
        hashed.push(password::hash_recovery_code(code)?);
    }

    let mut conn = state.lock_db()?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

    // Authoritative duplicate-creation check: `owner_account` is constrained to
    // a single row, so a concurrent second initialisation fails here instead of
    // creating a second owner.
    let inserted = tx.execute(
        "INSERT INTO owner_account (id, full_name, email, password_hash, setup_confirmed, created_at, updated_at)
         VALUES (1, ?1, ?2, ?3, 0, ?4, ?4)",
        rusqlite::params![full_name, email, password_hash.as_str(), util::now_secs()],
    )?;

    if inserted != 1 {
        return Err(AppError::new(
            "already_initialized",
            "BackMeUp has already been set up on this device.",
        ));
    }

    tx.execute(
        "INSERT INTO recovery_code_sets (id, status, created_at) VALUES (?1, 'pending', ?2)",
        rusqlite::params![set_id.as_str(), util::now_secs()],
    )?;

    {
        let mut stmt = tx
            .prepare("INSERT INTO recovery_codes (set_id, code_hash, created_at) VALUES (?1, ?2, ?3)")?;
        for hash in &hashed {
            stmt.execute(rusqlite::params![
                set_id.as_str(),
                hash.as_str(),
                util::now_secs()
            ])?;
        }
    }

    db::audit(&tx, "setup", Some(email), "success", None);
    tx.commit()?;

    Ok(codes)
}

/// Mark the first recovery code set as saved by the owner.
///
/// This is the only gate between displaying the codes and reaching the
/// dashboard, and it is enforced in the backend against the owner's session.
#[tauri::command]
pub fn confirm_setup_codes_saved(state: State<'_, AppState>) -> AppResult<BootstrapState> {
    let (owner_id, _) = require_session(&state)?;

    {
        let mut conn = state.lock_db()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let pending: Option<String> = tx
            .query_row(
                "SELECT id FROM recovery_code_sets WHERE status = 'pending' ORDER BY created_at DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;

        let Some(pending_id) = pending else {
            return Err(AppError::new(
                "no_pending_codes",
                "There are no recovery codes waiting to be confirmed.",
            ));
        };

        tx.execute(
            "UPDATE recovery_code_sets SET status = 'active', confirmed_at = ?2 WHERE id = ?1 AND status = 'pending'",
            rusqlite::params![pending_id, util::now_secs()],
        )?;
        tx.execute(
            "UPDATE owner_account SET setup_confirmed = 1, updated_at = ?2 WHERE id = ?1 AND setup_confirmed = 0",
            rusqlite::params![owner_id, util::now_secs()],
        )?;
        db::audit(&tx, "codes", None, "success", Some("setup_codes_confirmed"));
        tx.commit()?;
    }

    state.lock_auth()?.clear_pending_codes();

    app_bootstrap_state(state)
}

// ---------------------------------------------------------------------------
// Login / logout
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn login(
    state: State<'_, AppState>,
    email: String,
    password: String,
) -> AppResult<BootstrapState> {
    if email.trim().is_empty() || password.is_empty() {
        return Err(AppError::invalid_input("Email and password are required."));
    }

    let email = validate::validate_email(&email)?;
    let password = Zeroizing::new(password);
    let key = util::normalize_identifier(&email);

    {
        let mut auth = state.lock_auth()?;
        let global_wait = auth.global_login_throttle_mut().remaining_lockout();
        if !global_wait.is_zero() {
            return Err(AppError::rate_limited(global_wait.as_secs().max(1)));
        }
        let account_wait = auth
            .login_throttle_mut()
            .get(&key)
            .map(|t| t.remaining_lockout())
            .unwrap_or_default();
        if !account_wait.is_zero() {
            return Err(AppError::rate_limited(account_wait.as_secs().max(1)));
        }
    }

    let stored_hash = {
        let conn = state.lock_db()?;
        fetch_owner(&conn, &email)?.map(|(_, _, hash)| hash)
    };

    // When the account is unknown a throw-away hash is computed anyway so the
    // response time does not disclose whether the email exists.
    let stored_hash: Zeroizing<String> = match stored_hash {
        Some(hash) => Zeroizing::new(hash),
        None => password::hash_password(password.as_str())?,
    };

    if !password::verify_password(password.as_str(), &stored_hash) {
        let (account_wait, global_wait) = {
            let mut auth = state.lock_auth()?;
            let account = auth
                .login_throttle_mut()
                .entry(key)
                .or_default()
                .register_failure(
                    LOGIN_THRESHOLD,
                    LOGIN_WINDOW,
                    LOGIN_BASE_PENALTY,
                    LOGIN_MAX_PENALTY,
                );
            let global = auth.global_login_throttle_mut().register_failure(
                LOGIN_GLOBAL_THRESHOLD,
                LOGIN_GLOBAL_WINDOW,
                LOGIN_BASE_PENALTY,
                LOGIN_MAX_PENALTY,
            );
            // Bound the memory used by the per-identifier throttle table so
            // rotating addresses cannot grow it without limit.
            if auth.login_throttle_mut().len() > MAX_TRACKED_LOGIN_KEYS {
                auth.login_throttle_mut().retain(|_, t| !t.is_idle());
            }
            (account, global)
        };

        {
            let conn = state.lock_db()?;
            db::audit(&conn, "login", Some(email.as_str()), "failure", None);
        }

        let wait = account_wait.max(global_wait);
        if wait.is_zero() {
            // Generic message, identical for unknown account and wrong password.
            return Err(AppError::new(
                "invalid_credentials",
                "Incorrect email or password.",
            ));
        }
        return Err(AppError::rate_limited(wait.as_secs().max(1)));
    }

    let owner_id = {
        let conn = state.lock_db()?;
        let (id, _, _) = fetch_owner(&conn, &email)?.ok_or_else(|| {
            AppError::new("invalid_credentials", "Incorrect email or password.")
        })?;
        db::audit(&conn, "login", Some(email.as_str()), "success", None);
        id
    };

    {
        let mut auth = state.lock_auth()?;
        auth.login_throttle_mut().remove(&key);
        auth.global_login_throttle_mut().reset();
        auth.recovery_throttle_mut().reset();
        auth.reset_connection_test_throttle();
        // A brand new session replaces any previous one (session fixation defence).
        auth.start_session(owner_id, email);
    }

    app_bootstrap_state(state)
}

#[tauri::command]
pub fn logout(state: State<'_, AppState>) -> AppResult<BootstrapState> {
    let email = {
        let mut auth = state.lock_auth()?;
        let email = auth.peek_session().map(|s| s.email.clone());
        // Ends the session and clears any plaintext recovery codes held in
        // memory, so signing out never leaves a usable code set behind.
        auth.end_session();
        email
    };

    if let Some(email) = email {
        let conn = state.lock_db()?;
        db::audit(&conn, "login", Some(email.as_str()), "success", Some("logout"));
    }

    app_bootstrap_state(state)
}

#[tauri::command]
pub fn current_account(state: State<'_, AppState>) -> AppResult<OwnerProfile> {
    let (_, owner) = require_session(&state)?;
    Ok(owner)
}

// ---------------------------------------------------------------------------
// Account recovery
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn recover_password(
    state: State<'_, AppState>,
    email: String,
    recovery_code: String,
    new_password: String,
    confirm_password: String,
) -> AppResult<()> {
    let email = validate::validate_email(&email)?;
    validate::validate_password_pair(&new_password, &confirm_password)?;

    let new_password = Zeroizing::new(new_password);
    let _confirm_password = Zeroizing::new(confirm_password);
    let recovery_code = Zeroizing::new(recovery::normalize(&recovery_code));

    // Throttling is checked before any expensive verification work.
    {
        let mut auth = state.lock_auth()?;
        let wait = auth.recovery_throttle_mut().remaining_lockout();
        if !wait.is_zero() {
            return Err(AppError::rate_limited(wait.as_secs().max(1)));
        }
    }

    if !recovery::has_expected_shape(recovery_code.as_str()) {
        // Shape probing is still counted as an attempt.
        return match register_recovery_failure(&state, &email) {
            Ok(()) => Err(recovery_failed()),
            Err(err) => Err(err),
        };
    }

    // Resolve the owner up front, but do **not** branch on the result yet: the
    // code verification below must run for an unknown address too, otherwise
    // the response time would disclose whether the account exists.
    let owner_id: Option<i64> = {
        let conn = state.lock_db()?;
        conn.query_row(
            "SELECT id FROM owner_account WHERE email = ?1",
            [&email],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
    };

    // Phase 1 - read the candidate unused hashes of the active code set.
    let candidates: Vec<(i64, String)> = {
        let conn = state.lock_db()?;
        let mut stmt = conn.prepare(
            "SELECT rc.id, rc.code_hash
             FROM recovery_codes rc
             JOIN recovery_code_sets rcs ON rcs.id = rc.set_id
             WHERE rcs.status = 'active' AND rc.used_at IS NULL
             ORDER BY rc.id",
        )?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        out
    };

    if candidates.is_empty() {
        return match register_recovery_failure(&state, &email) {
            Ok(()) => Err(no_codes_remaining()),
            Err(err) => Err(err),
        };
    }

    // Phase 2 - verify outside of any write transaction.
    let mut matched: Option<i64> = None;
    for (id, hash) in &candidates {
        if password::verify_recovery_code(recovery_code.as_str(), hash) {
            matched = Some(*id);
            break;
        }
    }

    let Some(code_id) = matched else {
        return match register_recovery_failure(&state, &email) {
            Ok(()) => Err(recovery_failed()),
            Err(err) => Err(err),
        };
    };

    // Only now is it safe to distinguish the two cases. Returning the same
    // generic error for an unknown address keeps the recovery flow free of an
    // account-existence oracle, and the matched code is left untouched because
    // nothing has been written yet.
    let Some(owner_id) = owner_id else {
        return match register_recovery_failure(&state, &email) {
            Ok(()) => Err(recovery_failed()),
            Err(err) => Err(err),
        };
    };

    // Phase 3 - commit atomically. Marking the code used and storing the new
    // password happen in one transaction, so a failure anywhere rolls both
    // back and a code is never consumed without the new password being stored.
    let new_hash = password::hash_password(new_password.as_str())?;

    {
        let mut conn = state.lock_db()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let claimed = tx.execute(
            "UPDATE recovery_codes
             SET used_at = ?2
             WHERE id = ?1
               AND used_at IS NULL
               AND set_id IN (SELECT id FROM recovery_code_sets WHERE status = 'active')",
            rusqlite::params![code_id, util::now_secs()],
        )?;

        if claimed != 1 {
            // Lost a race with a concurrent recovery attempt using the same code.
            return Err(recovery_failed());
        }

        tx.execute(
            "UPDATE owner_account SET password_hash = ?2, updated_at = ?3 WHERE id = ?1",
            rusqlite::params![owner_id, new_hash.as_str(), util::now_secs()],
        )?;

        db::audit(&tx, "recovery", Some(email.as_str()), "success", None);
        tx.commit()?;
    }

    // A password change invalidates every existing authenticated session.
    state.lock_auth()?.invalidate_all_sessions();

    Ok(())
}

fn recovery_failed() -> AppError {
    AppError::new(
        "recovery_failed",
        "Recovery failed. Check your email and try an unused recovery code.",
    )
}

fn no_codes_remaining() -> AppError {
    AppError::new(
        "no_recovery_codes",
        "No unused recovery code remains for this account.",
    )
}

fn register_recovery_failure(state: &AppState, email: &str) -> AppResult<()> {
    let penalty = {
        let mut auth = state.lock_auth()?;
        auth.recovery_throttle_mut().register_failure(
            RECOVERY_THRESHOLD,
            RECOVERY_WINDOW,
            RECOVERY_BASE_PENALTY,
            RECOVERY_MAX_PENALTY,
        )
    };

    {
        let conn = state.lock_db()?;
        db::audit(&conn, "recovery", Some(email), "failure", None);
    }

    if penalty.is_zero() {
        Ok(())
    } else {
        Err(AppError::rate_limited(penalty.as_secs().max(1)))
    }
}

// ---------------------------------------------------------------------------
// Recovery code management
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn recovery_code_status(state: State<'_, AppState>) -> AppResult<RecoveryCodeStatus> {
    require_session(&state)?;

    let (total, used) = {
        let conn = state.lock_db()?;
        count_active_codes(&conn)?
    };

    Ok(RecoveryCodeStatus {
        total,
        used,
        remaining: total.saturating_sub(used),
    })
}

/// Generate a replacement set of recovery codes.
///
/// The new set is stored as `pending`. The previous set stays valid until the
/// owner confirms the replacement, so an interrupted regeneration can never
/// leave the owner without a working code set.
#[tauri::command]
pub fn begin_recovery_code_regeneration(
    state: State<'_, AppState>,
    current_password: String,
) -> AppResult<RecoveryCodesView> {
    let (owner_id, owner) = require_session(&state)?;

    let current_password = Zeroizing::new(current_password);
    if current_password.is_empty() {
        return Err(AppError::invalid_input("Password is required."));
    }

    let key = util::normalize_identifier(&owner.email);

    {
        let mut auth = state.lock_auth()?;
        let wait = auth
            .login_throttle_mut()
            .get(&key)
            .map(|t| t.remaining_lockout())
            .unwrap_or_default();
        if !wait.is_zero() {
            return Err(AppError::rate_limited(wait.as_secs().max(1)));
        }
    }

    let stored_hash = {
        let conn = state.lock_db()?;
        fetch_owner_hash(&conn, owner_id)?.ok_or_else(AppError::unauthorized)?
    };

    // Step-up reauthentication before a security setting is changed.
    if !password::verify_password(current_password.as_str(), &stored_hash) {
        {
            let mut auth = state.lock_auth()?;
            let penalty = auth
                .login_throttle_mut()
                .entry(key)
                .or_default()
                .register_failure(
                    LOGIN_THRESHOLD,
                    LOGIN_WINDOW,
                    LOGIN_BASE_PENALTY,
                    LOGIN_MAX_PENALTY,
                );
            if !penalty.is_zero() {
                return Err(AppError::rate_limited(penalty.as_secs().max(1)));
            }
        }
        {
            let conn = state.lock_db()?;
            db::audit(
                &conn,
                "codes",
                Some(owner.email.as_str()),
                "failure",
                Some("regeneration_step_up_failed"),
            );
        }
        return Err(AppError::invalid_input("Incorrect password."));
    }

    let bundle = recovery::generate_bundle()?;
    let codes = bundle.codes();
    let set_id = util::random_id()?;

    let mut hashed: Vec<Zeroizing<String>> = Vec::with_capacity(codes.len());
    for code in &codes {
        hashed.push(password::hash_recovery_code(code)?);
    }

    {
        let mut conn = state.lock_db()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Discard any abandoned pending set before creating the new one.
        tx.execute("DELETE FROM recovery_code_sets WHERE status = 'pending'", [])?;
        tx.execute(
            "INSERT INTO recovery_code_sets (id, status, created_at) VALUES (?1, 'pending', ?2)",
            rusqlite::params![set_id.as_str(), util::now_secs()],
        )?;
        {
            let mut stmt = tx
                .prepare("INSERT INTO recovery_codes (set_id, code_hash, created_at) VALUES (?1, ?2, ?3)")?;
            for hash in &hashed {
                stmt.execute(rusqlite::params![
                    set_id.as_str(),
                    hash.as_str(),
                    util::now_secs()
                ])?;
            }
        }
        tx.commit()?;
    }

    {
        let mut auth = state.lock_auth()?;
        auth.store_pending_codes(&codes);
    }

    let code_count = codes.len() as u32;
    Ok(RecoveryCodesView {
        recovery_codes: codes,
        code_count,
    })
}

/// Promote the pending code set to active and retire the previous one.
#[tauri::command]
pub fn commit_recovery_code_regeneration(state: State<'_, AppState>) -> AppResult<RecoveryCodeStatus> {
    let (_, owner) = require_session(&state)?;

    {
        let mut conn = state.lock_db()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let pending: Option<String> = tx
            .query_row(
                "SELECT id FROM recovery_code_sets WHERE status = 'pending' LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;

        let Some(pending_id) = pending else {
            return Err(AppError::new(
                "no_pending_codes",
                "There are no recovery codes waiting to be confirmed.",
            ));
        };

        // The previous set is retired only now, i.e. after the new set exists
        // and the owner confirmed the replacement.
        tx.execute("DELETE FROM recovery_code_sets WHERE status = 'active'", [])?;
        tx.execute(
            "UPDATE recovery_code_sets SET status = 'active', confirmed_at = ?2 WHERE id = ?1",
            rusqlite::params![pending_id, util::now_secs()],
        )?;
        db::audit(&tx, "codes", Some(owner.email.as_str()), "success", Some("regenerated"));
        tx.commit()?;
    }

    state.lock_auth()?.clear_pending_codes();

    recovery_code_status(state)
}

/// Discard a pending code set without touching the active one.
#[tauri::command]
pub fn cancel_recovery_code_regeneration(state: State<'_, AppState>) -> AppResult<()> {
    require_session(&state)?;

    {
        let mut conn = state.lock_db()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("DELETE FROM recovery_code_sets WHERE status = 'pending'", [])?;
        tx.commit()?;
    }

    state.lock_auth()?.clear_pending_codes();
    Ok(())
}

// ---------------------------------------------------------------------------
// Recovery code export
// ---------------------------------------------------------------------------

/// Write the pending recovery codes to a text file chosen by the owner in the
/// native Windows save dialog.
///
/// The destination path never comes from the webview: it is produced by the
/// operating system dialog and then re-validated here, so the frontend cannot
/// direct a write to an arbitrary location.
#[tauri::command]
pub async fn export_recovery_codes(
    app: AppHandle,
    state: State<'_, AppState>,
) -> AppResult<ExportResult> {
    let pending = {
        // Exporting is a privileged action: the owner must still hold a live
        // session, not merely have codes pending in memory.
        require_session(&state)?;
        state.lock_auth()?.pending_codes().ok_or_else(|| {
            AppError::new(
                "no_pending_codes",
                "Recovery codes are only available while they are on screen. Generate a new set first.",
            )
        })?
    };

    let dialog_handle = app.clone();
    let chosen = tauri::async_runtime::spawn_blocking(move || {
        dialog_handle
            .dialog()
            .file()
            .set_file_name("backmeup-recovery-codes.txt")
            .add_filter("Text file", &["txt"])
            .blocking_save_file()
    })
    .await
    .map_err(|_| AppError::internal())?;

    let path = match chosen {
        Some(file) => file.into_path().map_err(|_| {
            AppError::new("export_failed", "The recovery codes could not be saved.")
        })?,
        None => {
            return Ok(ExportResult {
                saved: false,
                file_name: None,
            })
        }
    };

    validate_export_path(&path)?;

    let header = "BackMeUp - account recovery codes\n\
                  ======================================\n\
                  Each code can be used once to reset your BackMeUp password.\n\
                  Anyone who holds these codes can take over this BackMeUp account.\n\
                  Keep them somewhere safe and offline. This file is not encrypted.\n\n";

    std::fs::write(&path, format!("{header}{pending}\n")).map_err(|err| {
        eprintln!("[backmeup] recovery code export failed: {err}");
        AppError::new(
            "export_failed",
            "The recovery codes could not be written to that location.",
        )
    })?;

    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "backmeup-recovery-codes.txt".to_string());

    {
        let conn = state.lock_db()?;
        db::audit(&conn, "codes", None, "success", Some("exported_to_file"));
    }

    Ok(ExportResult {
        saved: true,
        file_name: Some(file_name),
    })
}

/// Re-validate a path returned by the native save dialog before writing.
fn validate_export_path(path: &std::path::Path) -> AppResult<()> {
    let rejected = || {
        AppError::new(
            "export_failed",
            "The recovery codes could not be written to that location.",
        )
    };

    let file_name = path.file_name().ok_or_else(rejected)?.to_string_lossy().into_owned();

    // Reject traversal sequences, path separators and NUL bytes in the file
    // name component, and any parent-directory component in the path.
    if file_name.contains("..")
        || file_name.contains('/')
        || file_name.contains('\\')
        || file_name.contains('\0')
        || path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(rejected());
    }

    if !file_name.to_ascii_lowercase().ends_with(".txt") {
        return Err(AppError::new(
            "export_failed",
            "Recovery codes must be saved as a .txt file.",
        ));
    }

    let parent = path.parent().ok_or_else(rejected)?;
    let canonical_parent = parent.canonicalize().map_err(|_| rejected())?;
    if !canonical_parent.is_dir() {
        return Err(rejected());
    }

    // Final guard: the resolved target must stay inside the chosen directory.
    let candidate = canonical_parent.join(&file_name);
    match candidate.parent().and_then(|p| p.canonicalize().ok()) {
        Some(resolved) if resolved == canonical_parent => Ok(()),
        _ => Err(rejected()),
    }
}
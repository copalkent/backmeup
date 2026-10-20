//! OS-protected storage for connection secrets.
//!
//! BackMeUp keeps two kinds of secret for a connection, and both are held by
//! the operating system under the signed-in user's profile:
//!
//!   * Passwords (the database password, an SSH password, an SSH key
//!     passphrase) live in the Windows Credential Manager as
//!     `CRED_TYPE_GENERIC` entries, which Windows encrypts with DPAPI. A
//!     process running as a different user cannot read them back.
//!   * An SSH private key is pasted as text and stored as a DPAPI-protected
//!     blob file (`CryptProtectData`) under the application data directory.
//!     A file is used because a Credential Manager blob is capped at 2560
//!     bytes, which a 4096-bit RSA key exceeds.
//!
//! Secrets are *never* written to SQLite, to a config file, to the frontend,
//! or to `localStorage`. In SQLite only the opaque connection id is recorded
//! (`database_connections.secret_ref`).
//!
//! Design rules enforced here:
//!   * Secrets are accepted as [`Zeroizing`], so the plaintext is wiped from
//!     memory as soon as this module is done with it.
//!   * Errors are sanitised: the raw Win32 error is written only to the local
//!     stderr log, and never contains the target name or the secret.
//!   * Entries are namespaced by connection id, so removing one connection can
//!     never disturb another.
//!   * Blob files are named after the validated 64-hex connection id, so no
//!     user-controlled text ever reaches a path.

use std::ffi::c_void;
use std::path::{Path, PathBuf};

use tauri::Manager;
use windows::core::{HRESULT, PWSTR};
use windows::Win32::Foundation::ERROR_NOT_FOUND;
use windows::Win32::Security::Credentials::{
    CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE,
    CRED_TYPE_GENERIC,
};
use zeroize::Zeroizing;

use crate::error::{AppError, AppResult};

/// Every credential owned by BackMeUp lives under one of these prefixes. They
/// make the entries recognisable in `cmdkey` and impossible to confuse with
/// other apps.
const DATABASE_PREFIX: &str = "BackMeUp:database:";
const SSH_PASSWORD_PREFIX: &str = "BackMeUp:ssh-password:";
const SSH_PASSPHRASE_PREFIX: &str = "BackMeUp:ssh-key-passphrase:";
/// OAuth token sets, one entry per provider. These are secrets with a lifetime:
/// a refresh token is a long-lived credential and is protected the same way as
/// a database password.
const OAUTH_PREFIX: &str = "BackMeUp:oauth:";

/// Credential Manager limits a generic credential blob to 2560 bytes.
const MAX_BLOB_BYTES: usize = 2560;

/// Credential Manager target holding a provider's OAuth token set.
///
/// One entry per provider kind, stored as one JSON document so access token,
/// refresh token and expiry stay together and are replaced atomically.
fn oauth_target(provider: &str) -> String {
    format!("{OAUTH_PREFIX}{provider}")
}

/// Application-specific entropy mixed into DPAPI protection, so a blob can
/// only be unprotected by code that protects it for this purpose.
const BLOB_ENTROPY: &[u8] = b"BackMeUp::ssh-private-key::v1";

/// Hard ceiling accepted for a protected key blob on disk. A pasted key is
/// capped at 16 KiB on the way in (see `databases::validate_ssh_secrets`); the
/// on-disk artefact is a little larger because DPAPI adds a header.
const MAX_PROTECTED_BLOB_BYTES: usize = 64 * 1024;

/// Outcome of a credential read, so callers can tell "absent" from "broken".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialState {
    /// A credential exists and could be read.
    Present,
    /// No credential is stored for this connection.
    Absent,
}

fn database_target(connection_id: &str) -> String {
    format!("{DATABASE_PREFIX}{connection_id}")
}

fn ssh_password_target(connection_id: &str) -> String {
    format!("{SSH_PASSWORD_PREFIX}{connection_id}")
}

fn ssh_passphrase_target(connection_id: &str) -> String {
    format!("{SSH_PASSPHRASE_PREFIX}{connection_id}")
}

fn store_error(action: &str, err: &windows::core::Error) -> AppError {
    // The raw Win32 code is useful to an operator reading the local log and is
    // never surfaced to the UI.
    eprintln!("[backmeup] credential manager {action} failed: {err}");
    AppError::new(
        "credential_store_failed",
        "BackMeUp could not access the Windows Credential Manager. No password was stored.",
    )
}

/// `ERROR_NOT_FOUND` as the `HRESULT` that `CredReadW`/`CredDeleteW` report for
/// a missing credential, so "not stored yet" is not mistaken for a failure.
fn missing_credential() -> HRESULT {
    HRESULT::from_win32(ERROR_NOT_FOUND.0)
}

/// Store or replace a secret under one target name.
///
/// `CRED_PERSIST_LOCAL_MACHINE` keeps the entry encrypted with DPAPI for the
/// signed-in Windows user across sessions without exposing it to other
/// accounts on the machine.
fn store_at_target(
    target_name: &str,
    username: &str,
    secret: &Zeroizing<String>,
) -> AppResult<()> {
    let blob = secret.as_bytes();
    if blob.is_empty() {
        return Err(AppError::invalid_input("Enter a password."));
    }
    if blob.len() > MAX_BLOB_BYTES {
        return Err(AppError::invalid_input("That password is too long to store."));
    }

    // Wide buffers must stay alive for the duration of the FFI call, so they are
    // owned here and the PWSTR values below borrow from them.
    let target: Vec<u16> = wide(target_name);
    let user: Vec<u16> = wide(username);
    let mut secret: Vec<u8> = blob.to_vec();

    let credential = CREDENTIALW {
        Flags: windows::Win32::Security::Credentials::CRED_FLAGS(0),
        Type: CRED_TYPE_GENERIC,
        TargetName: PWSTR(target.as_ptr() as *mut u16),
        Comment: PWSTR::null(),
        LastWritten: windows::Win32::Foundation::FILETIME::default(),
        CredentialBlobSize: secret.len() as u32,
        CredentialBlob: secret.as_mut_ptr(),
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        AttributeCount: 0,
        Attributes: std::ptr::null_mut(),
        TargetAlias: PWSTR::null(),
        UserName: PWSTR(user.as_ptr() as *mut u16),
    };

    // SAFETY: every pointer above borrows from a buffer that is alive and
    // correctly aligned for the duration of this call, the blob length matches
    // the allocation, and `windows` owns no copies of these buffers.
    let result = unsafe { CredWriteW(&credential, 0) };

    // Wipe our copy of the plaintext as early as possible.
    secret.iter_mut().for_each(|byte| *byte = 0);

    result.map_err(|err| store_error("write", &err))
}

/// Read the secret stored under one target name.
///
/// Returns `CredentialState::Absent` rather than an error when nothing is
/// stored, because "no credential yet" is a normal state the UI must render.
fn load_at_target(target_name: &str) -> AppResult<(CredentialState, Option<Zeroizing<String>>)> {
    let target: Vec<u16> = wide(target_name);

    let mut raw: *mut CREDENTIALW = std::ptr::null_mut();

    // SAFETY: `raw` is a valid out-pointer for the lifetime of the call and is
    // only read after a successful return, when the OS guarantees it points at
    // a block that must be released with `CredFree`.
    let read = unsafe {
        CredReadW(
            PWSTR(target.as_ptr() as *mut u16),
            CRED_TYPE_GENERIC,
            None,
            &mut raw,
        )
    };

    if let Err(err) = read {
        if err.code() == missing_credential() {
            return Ok((CredentialState::Absent, None));
        }
        return Err(store_error("read", &err));
    }

    // SAFETY: `raw` was just populated by `CredReadW` and is non-null. The
    // returned block, including the blob inside it, is copied out before
    // `CredFree` releases it.
    let (state, secret) = unsafe {
        let credential = &*raw;

        if credential.CredentialBlob.is_null() || credential.CredentialBlobSize == 0 {
            (CredentialState::Absent, None)
        } else {
            let slice = std::slice::from_raw_parts(
                credential.CredentialBlob,
                credential.CredentialBlobSize as usize,
            );
            let decoded = String::from_utf8(slice.to_vec()).ok();
            match decoded {
                Some(text) => (
                    CredentialState::Present,
                    Some(Zeroizing::new(text.trim_end_matches('\0').to_string())),
                ),
                // A corrupt entry is treated as absent rather than crashing,
                // and is reported so the UI can ask the owner to re-enter it.
                None => (CredentialState::Absent, None),
            }
        }
    };

    // SAFETY: `raw` came from `CredReadW` and is freed exactly once.
    unsafe { CredFree(raw as *const c_void) };

    Ok((state, secret))
}

/// Remove the secret stored under one target name.
///
/// A missing entry is not an error: deleting a secret that is already cleared
/// is the desired end state.
fn delete_at_target(target_name: &str) -> AppResult<()> {
    let target: Vec<u16> = wide(target_name);

    // SAFETY: `target` is alive for the call and is a valid, NUL-terminated
    // wide string as required by the Win32 API.
    match unsafe { CredDeleteW(PWSTR(target.as_ptr() as *mut u16), CRED_TYPE_GENERIC, None) } {
        Ok(()) => Ok(()),
        Err(err) if err.code() == missing_credential() => Ok(()),
        Err(err) => Err(store_error("delete", &err)),
    }
}

/// True when a secret is stored under one target name.
fn exists_at_target(target_name: &str) -> bool {
    matches!(load_at_target(target_name), Ok((CredentialState::Present, _)))
}

// ---------------------------------------------------------------------------
// Database passwords
// ---------------------------------------------------------------------------

/// Store or replace the database password for a connection.
pub fn store(
    connection_id: &str,
    username: &str,
    password: &Zeroizing<String>,
) -> AppResult<()> {
    store_at_target(&database_target(connection_id), username, password)
}

/// Read the stored database password for a connection.
pub fn load(connection_id: &str) -> AppResult<(CredentialState, Option<Zeroizing<String>>)> {
    load_at_target(&database_target(connection_id))
}

/// True when a database password is stored for this connection.
pub fn exists(connection_id: &str) -> bool {
    exists_at_target(&database_target(connection_id))
}

/// Remove the database password for one connection.
pub fn delete(connection_id: &str) -> AppResult<()> {
    delete_at_target(&database_target(connection_id))
}

// ---------------------------------------------------------------------------
// SSH secrets (Credential Manager)
// ---------------------------------------------------------------------------

/// Store or replace the SSH password for a tunnelled connection.
pub fn store_ssh_password(
    connection_id: &str,
    username: &str,
    password: &Zeroizing<String>,
) -> AppResult<()> {
    store_at_target(&ssh_password_target(connection_id), username, password)
}

/// Read the stored SSH password for a tunnelled connection.
pub fn load_ssh_password(
    connection_id: &str,
) -> AppResult<(CredentialState, Option<Zeroizing<String>>)> {
    load_at_target(&ssh_password_target(connection_id))
}

/// True when an SSH password is stored for this connection.
pub fn ssh_password_exists(connection_id: &str) -> bool {
    exists_at_target(&ssh_password_target(connection_id))
}

/// Remove the SSH password for one connection.
pub fn delete_ssh_password(connection_id: &str) -> AppResult<()> {
    delete_at_target(&ssh_password_target(connection_id))
}

/// Store or replace the passphrase for a tunnelled connection's SSH key.
pub fn store_ssh_passphrase(
    connection_id: &str,
    passphrase: &Zeroizing<String>,
) -> AppResult<()> {
    store_at_target(
        &ssh_passphrase_target(connection_id),
        "BackMeUp SSH key",
        passphrase,
    )
}

/// Read the stored SSH key passphrase for a tunnelled connection.
pub fn load_ssh_passphrase(
    connection_id: &str,
) -> AppResult<(CredentialState, Option<Zeroizing<String>>)> {
    load_at_target(&ssh_passphrase_target(connection_id))
}

/// Remove the SSH key passphrase for one connection.
pub fn delete_ssh_passphrase(connection_id: &str) -> AppResult<()> {
    delete_at_target(&ssh_passphrase_target(connection_id))
}

// ---------------------------------------------------------------------------
// SSH private-key blobs (DPAPI-protected files)
// ---------------------------------------------------------------------------

/// The directory that holds DPAPI-protected SSH key blobs.
///
/// It lives inside the per-user application data directory, which on Windows
/// inherits the user's exclusive profile ACL, and each blob is additionally
/// encrypted with DPAPI under the signed-in user.
fn key_blob_dir(app: &tauri::AppHandle) -> AppResult<PathBuf> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|err| {
            eprintln!("[backmeup] application data directory unavailable: {err}");
            AppError::internal()
        })?
        .join("ssh_keys");

    std::fs::create_dir_all(&dir).map_err(|err| {
        eprintln!("[backmeup] ssh key directory could not be created: {err}");
        AppError::internal()
    })?;

    Ok(dir)
}

/// File name for one connection's key blob.
///
/// The id is the 64-hex identifier produced by `util::random_id` and validated
/// on every boundary, and this re-checks that shape so no user-controlled text
/// can ever reach a path.
fn blob_file_name(connection_id: &str) -> AppResult<String> {
    let valid = connection_id.len() == 64
        && connection_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));

    if !valid {
        return Err(AppError::internal());
    }

    Ok(format!("{connection_id}.key"))
}

fn blob_path(dir: &Path, connection_id: &str) -> AppResult<PathBuf> {
    Ok(dir.join(blob_file_name(connection_id)?))
}

/// Store (or replace) the DPAPI-protected key blob for a connection.
///
/// The plaintext key is never written to disk: `CryptProtectData` output is
/// what lands in the file.
pub fn store_ssh_key_blob(
    app: &tauri::AppHandle,
    connection_id: &str,
    key_text: &Zeroizing<String>,
) -> AppResult<()> {
    store_blob_in(&key_blob_dir(app)?, connection_id, key_text)
}

/// Read and unprotect the key blob for a connection.
///
/// `Ok(None)` means no blob is stored, which is a normal state the UI renders.
pub fn load_ssh_key_blob(
    app: &tauri::AppHandle,
    connection_id: &str,
) -> AppResult<Option<Zeroizing<String>>> {
    load_blob_in(&key_blob_dir(app)?, connection_id)
}

/// True when a key blob is stored for this connection.
pub fn ssh_key_blob_exists(app: &tauri::AppHandle, connection_id: &str) -> bool {
    let Ok(dir) = key_blob_dir(app) else {
        return false;
    };
    matches!(blob_path(&dir, connection_id), Ok(path) if path.is_file())
}

/// Remove the key blob for one connection. Best effort by design: callers
/// treat a missing blob as success and must never fail deletion over it.
pub fn delete_ssh_key_blob(app: &tauri::AppHandle, connection_id: &str) {
    let Ok(dir) = key_blob_dir(app) else {
        return;
    };

    match blob_path(&dir, connection_id) {
        Ok(path) => {
            if let Err(err) = std::fs::remove_file(&path) {
                if err.kind() != std::io::ErrorKind::NotFound {
                    eprintln!("[backmeup] ssh key blob could not be removed: {err}");
                }
            }
        }
        Err(_) => {}
    }
}

fn store_blob_in(dir: &Path, connection_id: &str, key_text: &Zeroizing<String>) -> AppResult<()> {
    let path = blob_path(dir, connection_id)?;
    let protected = dpapi_protect(key_text.as_bytes())?;

    std::fs::write(&path, &protected).map_err(|err| {
        eprintln!("[backmeup] ssh key blob could not be written: {err}");
        AppError::new(
            "key_store_failed",
            "BackMeUp could not save the SSH private key on this computer.",
        )
    })
}

fn load_blob_in(dir: &Path, connection_id: &str) -> AppResult<Option<Zeroizing<String>>> {
    let path = blob_path(dir, connection_id)?;

    let protected = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            eprintln!("[backmeup] ssh key blob could not be read: {err}");
            return Err(AppError::internal());
        }
    };

    dpapi_unprotect(&protected).map(Some)
}

/// DPAPI does not encrypt empty payloads usefully and an empty key is invalid
/// anyway; the error stays generic so no blob content can leak.
fn dpapi_error(action: &str, err: &windows::core::Error) -> AppError {
    eprintln!("[backmeup] dpapi {action} failed: {err}");
    AppError::new(
        "key_store_failed",
        "BackMeUp could not use this Windows account to protect the SSH private key.",
    )
}

fn dpapi_protect(plain: &[u8]) -> AppResult<Vec<u8>> {
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    if plain.is_empty() || plain.len() > MAX_PROTECTED_BLOB_BYTES {
        return Err(AppError::invalid_input("That SSH private key is not valid."));
    }

    let input = CRYPT_INTEGER_BLOB {
        cbData: plain.len() as u32,
        pbData: plain.as_ptr() as *mut u8,
    };
    let entropy = CRYPT_INTEGER_BLOB {
        cbData: BLOB_ENTROPY.len() as u32,
        pbData: BLOB_ENTROPY.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();

    // SAFETY: `input` and `entropy` borrow live buffers for the duration of
    // the call; `output` is a valid out-pointer. On success the OS allocates
    // `output.pbData`, which is copied out and then released with `LocalFree`.
    unsafe {
        CryptProtectData(
            &input,
            windows::core::PCWSTR::null(),
            Some(&entropy as *const CRYPT_INTEGER_BLOB),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    }
    .map_err(|err| dpapi_error("protect", &err))?;

    if output.pbData.is_null()
        || output.cbData == 0
        || output.cbData as usize > MAX_PROTECTED_BLOB_BYTES
    {
        if !output.pbData.is_null() {
            let _ = unsafe { LocalFree(Some(HLOCAL(output.pbData as *mut c_void))) };
        }
        return Err(AppError::internal());
    }

    // SAFETY: `output` was populated by a successful `CryptProtectData`; the
    // block is copied before being freed exactly once.
    let protected =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    let _ = unsafe { LocalFree(Some(HLOCAL(output.pbData as *mut c_void))) };

    Ok(protected)
}

fn dpapi_unprotect(protected: &[u8]) -> AppResult<Zeroizing<String>> {
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    if protected.is_empty() || protected.len() > MAX_PROTECTED_BLOB_BYTES {
        return Err(unreadable_key());
    }

    let input = CRYPT_INTEGER_BLOB {
        cbData: protected.len() as u32,
        pbData: protected.as_ptr() as *mut u8,
    };
    let entropy = CRYPT_INTEGER_BLOB {
        cbData: BLOB_ENTROPY.len() as u32,
        pbData: BLOB_ENTROPY.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();

    // SAFETY: same contract as `dpapi_protect`; the description out-pointer is
    // not requested (`None`).
    unsafe {
        CryptUnprotectData(
            &input,
            None,
            Some(&entropy as *const CRYPT_INTEGER_BLOB),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    }
    .map_err(|err| {
        eprintln!("[backmeup] dpapi unprotect failed: {err}");
        unreadable_key()
    })?;

    if output.pbData.is_null()
        || output.cbData == 0
        || output.cbData as usize > MAX_PROTECTED_BLOB_BYTES
    {
        if !output.pbData.is_null() {
            let _ = unsafe { LocalFree(Some(HLOCAL(output.pbData as *mut c_void))) };
        }
        return Err(unreadable_key());
    }

    // SAFETY: `output` was populated by a successful `CryptUnprotectData`; the
    // plaintext is copied into a wiping container before the OS block is
    // released.
    let plain = Zeroizing::new(
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec(),
    );
    let _ = unsafe { LocalFree(Some(HLOCAL(output.pbData as *mut c_void))) };

    match std::str::from_utf8(&plain) {
        Ok(text) => Ok(Zeroizing::new(text.to_string())),
        Err(_) => Err(unreadable_key()),
    }
}

fn unreadable_key() -> AppError {
    AppError::new(
        "key_unreadable",
        "The saved SSH private key could not be read. Edit the connection and paste the key again.",
    )
}

/// Same Windows Credential Manager availability gate as every other secret.
///
/// BackMeUp is Windows-only; this exists so a future non-Windows port fails
/// loudly instead of silently falling back to weaker storage.
pub fn available() -> bool {
    cfg!(target_os = "windows")
}

/// UTF-16LE with a terminating NUL, as the Win32 credential APIs require.
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

// ---------------------------------------------------------------------------
// OAuth token sets (Credential Manager)
// ---------------------------------------------------------------------------

/// Store or replace a provider's token document.
///
/// The document is opaque to this module: the provider module owns its shape.
/// It is stored as one blob so a refresh cannot leave a half-updated set behind.
pub fn store_oauth_tokens(
    provider: &str,
    username: &str,
    document: &Zeroizing<String>,
) -> AppResult<()> {
    store_at_target(&oauth_target(provider), username, document)
}

/// Read a provider's token document, if one is stored.
pub fn load_oauth_tokens(provider: &str) -> AppResult<(CredentialState, Option<Zeroizing<String>>)> {
    load_at_target(&oauth_target(provider))
}

/// Forget a provider's tokens. Idempotent: disconnecting twice is not an error.
pub fn delete_oauth_tokens(provider: &str) -> AppResult<()> {
    delete_at_target(&oauth_target(provider))
}

/// True when a provider's tokens are stored.
pub fn oauth_tokens_exist(provider: &str) -> bool {
    exists_at_target(&oauth_target(provider))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_is_nul_terminated() {
        assert_eq!(wide("ab"), vec![b'a' as u16, b'b' as u16, 0]);
        assert_eq!(wide(""), vec![0]);
        // Non-ASCII becomes UTF-16 code units.
        assert_eq!(wide("\u{e9}"), vec![0x00e9, 0]);
    }

    #[test]
    fn target_names_are_namespaced_by_connection_id_and_kind() {
        assert_eq!(
            database_target("abc"),
            "BackMeUp:database:abc".to_string(),
            "entries must be attributable to BackMeUp"
        );
        assert_eq!(
            ssh_password_target("abc"),
            "BackMeUp:ssh-password:abc".to_string()
        );
        assert_eq!(
            ssh_passphrase_target("abc"),
            "BackMeUp:ssh-key-passphrase:abc".to_string()
        );

        assert_ne!(database_target("one"), database_target("two"));
        assert_ne!(database_target("x"), ssh_password_target("x"));
        assert_ne!(ssh_password_target("x"), ssh_passphrase_target("x"));
    }

    #[test]
    fn deleting_an_absent_credential_is_not_an_error() {
        // Nothing has been stored under this id, so delete must be idempotent.
        let id = "backmeup-test-absent-entry";
        delete(id).unwrap();
        delete(id).unwrap();
        assert_eq!(load(id).unwrap().0, CredentialState::Absent);
    }

    #[test]
    fn round_trips_a_secret_through_the_credential_manager() {
        let id = "backmeup-test-roundtrip";
        let _ = delete(id);

        let secret = Zeroizing::new("s3cr3t-TEST-value".to_string());
        store(id, "tester", &secret).unwrap();
        assert!(exists(id));

        let (state, loaded) = load(id).unwrap();
        assert_eq!(state, CredentialState::Present);
        assert_eq!(loaded.as_deref().map(|s| s.as_str()), Some("s3cr3t-TEST-value"));

        // Replacing must not leave the previous secret behind.
        let replacement = Zeroizing::new("rotated-value-9".to_string());
        store(id, "tester", &replacement).unwrap();
        let (_, loaded) = load(id).unwrap();
        assert_eq!(loaded.as_deref().map(|s| s.as_str()), Some("rotated-value-9"));

        delete(id).unwrap();
        assert_eq!(load(id).unwrap().0, CredentialState::Absent);
    }

    #[test]
    fn round_trips_an_ssh_password_secret() {
        let id = "backmeup-test-ssh-password-roundtrip";
        let _ = delete_ssh_password(id);

        let secret = Zeroizing::new("ssh-s3cr3t".to_string());
        store_ssh_password(id, "tester", &secret).unwrap();
        assert!(ssh_password_exists(id));

        let (state, loaded) = load_ssh_password(id).unwrap();
        assert_eq!(state, CredentialState::Present);
        assert_eq!(loaded.as_deref().map(|s| s.as_str()), Some("ssh-s3cr3t"));

        delete_ssh_password(id).unwrap();
        assert!(!ssh_password_exists(id));
    }

    #[test]
    fn empty_secrets_are_refused_rather_than_stored() {
        let empty = Zeroizing::new(String::new());
        let err = store("backmeup-test-empty", "tester", &empty).unwrap_err();
        assert_eq!(err.code, "invalid_input");
    }

    #[test]
    fn blob_file_names_only_accept_the_record_id_shape() {
        let valid = "a".repeat(64);
        assert_eq!(blob_file_name(&valid).unwrap(), format!("{valid}.key"));

        for hostile in [
            String::new(),
            "short".to_string(),
            "../../../etc/passwd".to_string(),
            "a".repeat(63),
            "A".repeat(64),
            format!("{}\\..\\evil", "a".repeat(58)),
        ] {
            assert!(
                blob_file_name(&hostile).is_err(),
                "must not accept {hostile:?}"
            );
        }
    }

    #[test]
    fn oauth_token_documents_round_trip_and_can_be_removed() {
        let provider = "google-drive";
        let _ = delete_oauth_tokens(provider);
        assert!(!oauth_tokens_exist(provider));

        let document = Zeroizing::new(
            r#"{"access_token":"ya29.a0-test","refresh_token":"1//test","expires_at":1700000000}"#
                .to_string(),
        );

        store_oauth_tokens(provider, "owner@example.test", &document).unwrap();
        assert!(oauth_tokens_exist(provider));

        let (state, loaded) = load_oauth_tokens(provider).unwrap();
        assert_eq!(state, CredentialState::Present);
        assert_eq!(loaded.as_deref().map(String::as_str), Some(document.as_str()));

        // Providers are namespaced, so one cannot read another's tokens.
        assert!(!oauth_tokens_exist("dropbox"));
        assert_eq!(oauth_target("google-drive"), "BackMeUp:oauth:google-drive");

        delete_oauth_tokens(provider).unwrap();
        assert!(!oauth_tokens_exist(provider));
        // Deleting twice must be safe: the UI can offer Disconnect repeatedly.
        delete_oauth_tokens(provider).unwrap();
    }

    #[test]
    fn round_trips_a_key_blob_through_dpapi() {
        let dir = std::env::temp_dir().join(format!("backmeup-test-blobs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let id = "b".repeat(64);
        let key = Zeroizing::new(
            "-----BEGIN OPENSSH PRIVATE KEY-----\ntest-only-key-material\n-----END OPENSSH PRIVATE KEY-----"
                .to_string(),
        );

        // The file on disk must never contain the plaintext.
        store_blob_in(&dir, &id, &key).unwrap();
        let on_disk = std::fs::read(blob_path(&dir, &id).unwrap()).unwrap();
        assert!(
            !String::from_utf8_lossy(&on_disk).contains("test-only-key-material"),
            "plaintext key material reached the disk"
        );

        let loaded = load_blob_in(&dir, &id).unwrap().expect("blob must load");
        assert_eq!(loaded.as_str(), key.as_str());

        // Removing is idempotent from the caller's point of view.
        std::fs::remove_file(blob_path(&dir, &id).unwrap()).unwrap();
        assert!(load_blob_in(&dir, &id).unwrap().is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_corrupt_blob_is_reported_rather_than_decoded() {
        let dir =
            std::env::temp_dir().join(format!("backmeup-test-blobs-corrupt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let id = "c".repeat(64);
        std::fs::write(blob_path(&dir, &id).unwrap(), b"not a dpapi blob").unwrap();

        let err = load_blob_in(&dir, &id).unwrap_err();
        assert_eq!(err.code, "key_unreadable");

        let _ = std::fs::remove_dir_all(&dir);
    }
}

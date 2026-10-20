//! Google Drive as a backup destination.
//!
//! Sign-in is Google's *installed app* flow, which is the only one that fits a
//! desktop program:
//!   * BackMeUp never asks for, stores, or even sees a Google password. The
//!     user's normal browser handles the sign-in.
//!   * The client ID and secret below are **public identifiers**, not
//!     confidential credentials. Google issues a secret for desktop clients and
//!     requires it on the token exchange, but it ships inside every installed
//!     copy of the app, so it cannot be a real secret. PKCE is what protects the
//!     flow: an intercepted authorisation code cannot be replayed without the
//!     per-attempt verifier, which never leaves this process.
//!   * The redirect is caught by a listener bound to `127.0.0.1` on an ephemeral
//!     port, so nothing is exposed off this machine.
//!   * The scope is `drive.file` and nothing else: BackMeUp can see only the
//!     files it created, never the rest of the account.
//!
//! Tokens live in Windows Credential Manager (see `credentials`), never in
//! SQLite, never in the frontend, and never in a log line.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::Digest;
use tauri::{AppHandle, Emitter, Manager, State};
use zeroize::Zeroizing;

use crate::commands::{require_session, AppState};
use crate::credentials;
use crate::error::{AppError, AppResult};
use crate::util;

/// OAuth client ID for BackMeUp.
///
/// Public by design: this value ships inside every installed copy of the app and
/// is not a credential. It is quoted here rather than in a config file so it
/// travels with the code and cannot be edited at runtime.
pub const OAUTH_CLIENT_ID: &str =
    "647737598232-d80b8uau4bigvd7q7hrgnmjb1v2m7e2e.apps.googleusercontent.com";

/// OAuth client secret for BackMeUp, injected when the app is built.
///
/// Google issues a secret for "Desktop app" clients and requires it on both the
/// authorisation-code exchange and every refresh, even though an installed app
/// cannot keep one confidential. It is therefore a public identifier, not a
/// credential: PKCE is the actual protection, because an intercepted code
/// cannot be redeemed without the per-attempt verifier that never leaves this
/// process.
///
/// It is read from the build environment rather than written here, so the value
/// never sits in the repository:
///
/// ```text
/// BACKMEUP_OAUTH_CLIENT_SECRET=... npm run tauri build
/// ```
///
/// A build made without it has no Drive support, and says so plainly instead
/// of failing at the sign-in step.
pub const OAUTH_CLIENT_SECRET: &str = match option_env!("BACKMEUP_OAUTH_CLIENT_SECRET") {
    Some(secret) => secret,
    None => "",
};

/// The client secret, or a clear reason why this build has none.
fn client_secret() -> AppResult<&'static str> {
    if OAUTH_CLIENT_SECRET.is_empty() {
        return Err(AppError::new(
            "drive_not_configured",
            "This copy of BackMeUp was built without Google Drive support.",
        ));
    }

    Ok(OAUTH_CLIENT_SECRET)
}

/// The only scope requested. `drive.file` grants access to files BackMeUp
/// creates and nothing else, which is what keeps this out of Google's
/// restricted-scope review.
const SCOPE: &str = "https://www.googleapis.com/auth/drive.file";

/// Provider key used for credential storage and for the destination kind.
pub const PROVIDER: &str = "google-drive";

/// Event carrying the sign-in URL to the window, so there is always a way
/// to finish signing in even if no browser opened.
pub const SIGNIN_URL_EVENT: &str = "drive-signin-url";

/// Root folder created in the user's Drive. Every backup lands below it.
pub const ROOT_FOLDER: &str = "BackMeUp";

/// How long there is to finish signing in.
///
/// Deliberately short: while this waits, the Connect button is unavailable, so
/// an abandoned attempt must not leave the app looking stuck. The sign-in URL is
/// sent to the window as soon as it exists, so a browser that failed to open is
/// still recoverable.
const AUTHORIZATION_TIMEOUT: Duration = Duration::from_secs(120);
/// How often the wait re-checks whether the sign-in was cancelled. The listener is
/// polled rather than parked for the whole timeout, so pressing Cancel in the
/// window takes effect immediately instead of after two minutes.
const CANCEL_POLL: Duration = Duration::from_millis(250);
/// Ceiling on reading the one HTTP request the redirect sends.
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Ceiling on a single HTTP call to Google.
const HTTP_TIMEOUT: Duration = Duration::from_secs(120);

/// Set while a stop has been asked for an in-flight sign-in.
///
/// One sign-in can be in flight at a time (the Connect button is unavailable
/// while it runs), so a single flag is enough. A new attempt clears it before
/// the browser opens.
static CONNECT_CANCELLED: AtomicBool = AtomicBool::new(false);

/// Longest an authorisation code or token may be, bounding what is parsed.
const MAX_TOKEN_FIELD: usize = 4096;

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------

/// The stored token set. Never rendered: `Debug` is hand-written so a token can
/// appear in a log or a panic message without leaking.
#[derive(Serialize, Deserialize)]
struct TokenSet {
    access_token: String,
    #[serde(default)]
    refresh_token: String,
    expires_at: u64,
}

impl std::fmt::Debug for TokenSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenSet")
            .field("access_token", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl TokenSet {
    fn expired(&self) -> bool {
        now_secs() + 60 >= self.expires_at
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Read the stored token set, if the provider is connected.
fn stored_tokens() -> AppResult<Option<TokenSet>> {
    let (state, document) = credentials::load_oauth_tokens(PROVIDER)?;

    let Some(document) = document else {
        return Ok(None);
    };
    if state != credentials::CredentialState::Present {
        return Ok(None);
    }

    // A corrupt entry is treated as "not connected" rather than crashing, so a
    // damaged credential cannot wedge the app.
    match serde_json::from_str::<TokenSet>(document.as_str()) {
        Ok(tokens) => Ok(Some(tokens)),
        Err(err) => {
            eprintln!("[backmeup] google drive: stored tokens were unreadable ({err})");
            Ok(None)
        }
    }
}

/// Persist a token set.
fn store_tokens(tokens: &TokenSet) -> AppResult<()> {
    let document = serde_json::to_string(tokens).map_err(|_| {
        AppError::new(
            "drive_token_failed",
            "BackMeUp could not prepare your Google Drive sign-in for secure storage.",
        )
    })?;

    credentials::store_oauth_tokens(PROVIDER, "BackMeUp Google Drive", &Zeroizing::new(document))
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

/// One HTTP client for every call: pooled connections, OS trust store, and a
/// ceiling so a stalled Google request cannot hang a backup.
pub fn http_client() -> AppResult<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .map_err(|_| {
            AppError::new(
                "drive_unavailable",
                "BackMeUp could not prepare a secure connection to Google Drive.",
            )
        })
}

/// Whether tokens are stored, i.e. Drive is connected. Never touches the
/// network, so it is safe to call on every backup.
pub fn is_connected() -> bool {
    credentials::oauth_tokens_exist(PROVIDER)
}

fn http() -> AppResult<reqwest::Client> {
    http_client()
}

/// The refresh token endpoint response.
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
}

impl TokenResponse {
    /// Refuse anything implausibly long before it is stored.
    fn into_tokens(self, previous_refresh: &str) -> AppResult<TokenSet> {
        if self.access_token.is_empty() || self.access_token.len() > MAX_TOKEN_FIELD {
            return Err(drive_error());
        }

        // Google only returns a refresh token on first consent; on later
        // refreshes the previous one stays valid and must be carried over.
        let refresh_token = if self.refresh_token.is_empty() {
            previous_refresh.to_string()
        } else {
            self.refresh_token
        };

        if refresh_token.len() > MAX_TOKEN_FIELD {
            return Err(drive_error());
        }

        Ok(TokenSet {
            access_token: self.access_token,
            refresh_token,
            expires_at: now_secs() + self.expires_in.unwrap_or(3600),
        })
    }
}

fn drive_error() -> AppError {
    AppError::new(
        "drive_error",
        "Google Drive could not complete the request. Try again in a moment.",
    )
}

/// The sign-in was stopped before it finished.
fn sign_in_cancelled() -> AppError {
    AppError::new(
        "drive_cancelled",
        "The Google Drive sign-in was cancelled. Nothing was changed.",
    )
}

/// Google's OAuth error body. Only the machine-readable `error` is ever logged;
/// the description can echo account details, so it never reaches a log line.
#[derive(Deserialize)]
struct GoogleErrorBody {
    #[serde(default)]
    error: String,
}

/// Turn a failed token response into an error that can be acted on.
///
/// The distinction matters: `invalid_client` means the app is misconfigured and
/// retrying cannot help, while `invalid_grant` means the grant is gone
/// and only a fresh sign-in can fix it.
fn classify_token_error(status: reqwest::StatusCode, body: &str) -> AppError {
    let parsed = serde_json::from_str::<GoogleErrorBody>(body).unwrap_or(GoogleErrorBody {
        error: String::new(),
    });

    eprintln!(
        "[backmeup] google drive: token endpoint returned {} {}",
        status.as_u16(),
        if parsed.error.is_empty() {
            "without an error code"
        } else {
            parsed.error.as_str()
        }
    );

    match parsed.error.as_str() {
        "invalid_client" | "unauthorized_client" => AppError::new(
            "drive_configuration",
            "BackMeUp's Google Drive sign-in is not configured correctly. Contact whoever built this app.",
        ),
        "redirect_uri_mismatch" => AppError::new(
            "drive_configuration",
            "BackMeUp's Google Drive sign-in is not configured correctly. Contact whoever built this app.",
        ),
        "invalid_grant" => AppError::new(
            "drive_reconnect",
            "Your Google Drive sign-in has expired. Connect Google Drive again.",
        ),
        "access_denied" => AppError::new(
            "drive_denied",
            "Google Drive access was not granted, so nothing was changed.",
        ),
        "invalid_request" => AppError::new(
            "drive_configuration",
            "Google rejected the sign-in request. Connect Google Drive again.",
        ),
        _ => drive_error(),
    }
}

/// Read a response body and map a non-success status, without assuming JSON.
async fn checked_body(response: reqwest::Response) -> AppResult<String> {
    let status = response.status();
    let body = response.text().await.map_err(|_| drive_error())?;

    if status.is_success() {
        Ok(body)
    } else {
        Err(classify_token_error(status, &body))
    }
}

/// Swap a refresh token for a new access token.
async fn refresh(client: &reqwest::Client, refresh_token: &str) -> AppResult<TokenSet> {
    let response = client
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", OAUTH_CLIENT_ID),
            ("client_secret", client_secret()?),
            ("refresh_token", refresh_token),
        ])
        .send()
        .await
        .map_err(|_| drive_error())?;

    let body = checked_body(response).await?;
    let parsed: TokenResponse = serde_json::from_str(&body).map_err(|_| drive_error())?;
    parsed.into_tokens(refresh_token)
}

/// An access token that is valid now, refreshing first if needed.
pub async fn access_token() -> AppResult<Zeroizing<String>> {
    let Some(tokens) = stored_tokens()? else {
        return Err(AppError::new(
            "drive_not_connected",
            "Google Drive is not connected. Connect it in Settings to back up to Drive.",
        ));
    };

    if !tokens.expired() {
        return Ok(Zeroizing::new(tokens.access_token));
    }

    if tokens.refresh_token.is_empty() {
        return Err(AppError::new(
            "drive_reconnect",
            "Your Google Drive sign-in has expired. Connect Google Drive again.",
        ));
    }

    let client = http()?;
    match refresh(&client, &tokens.refresh_token).await {
        Ok(refreshed) => {
            store_tokens(&refreshed)?;
            Ok(Zeroizing::new(refreshed.access_token))
        }
        Err(err) => {
            // A revoked or expired grant can never recover on its own. Clearing
            // the stored tokens makes `is_connected()` honest, so the UI offers
            // Connect again instead of silently failing every future backup.
            if err.code == "drive_reconnect" {
                eprintln!(
                    "[backmeup] google drive: stored sign-in was rejected by Google ({}); \
                     tokens cleared, reconnect required",
                    err.code
                );
                let _ = credentials::delete_oauth_tokens(PROVIDER);
            }
            Err(err)
        }
    }
}

// ---------------------------------------------------------------------------
// PKCE and the sign-in flow
// ---------------------------------------------------------------------------

/// A PKCE verifier with its S256 challenge, and the `state` that ties the
/// redirect back to this attempt.
struct Authorization {
    verifier: Zeroizing<String>,
    challenge: String,
    state: String,
}

impl std::fmt::Debug for Authorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The verifier is the secret half of PKCE.
        f.debug_struct("Authorization")
            .field("verifier", &"<redacted>")
            .field("challenge", &"<redacted>")
            .field("state", &"<redacted>")
            .finish()
    }
}

impl Authorization {
    fn new() -> AppResult<Self> {
        let verifier = Zeroizing::new(base64url(&util::secure_random_bytes::<32>()?));
        let state = base64url(&util::secure_random_bytes::<16>()?);

        let digest = sha2::Sha256::digest(verifier.as_bytes());
        let challenge = base64url(&digest);

        Ok(Authorization {
            verifier,
            challenge,
            state,
        })
    }
}

/// URL-safe base64 without padding, exactly as PKCE requires.
///
/// The challenge must be the base64url form of the SHA-256 digest, because that
/// is what the authorisation server recomputes; any other encoding (hex, for
/// instance) would never match and every sign-in would fail.
fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut chunks = bytes.chunks_exact(3);

    for chunk in chunks.by_ref() {
        let packed = (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]);

        out.push(ALPHABET[(packed >> 18) as usize & 0x3F] as char);
        out.push(ALPHABET[(packed >> 12) as usize & 0x3F] as char);
        out.push(ALPHABET[(packed >> 6) as usize & 0x3F] as char);
        out.push(ALPHABET[packed as usize & 0x3F] as char);
    }

    // The tail carries one or two leftover bytes, so one or two characters are
    // emitted and no padding is added.
    let tail = chunks.remainder();
    match tail.len() {
        1 => {
            let packed = u32::from(tail[0]) << 16;
            out.push(ALPHABET[(packed >> 18) as usize & 0x3F] as char);
            out.push(ALPHABET[(packed >> 12) as usize & 0x3F] as char);
        }
        2 => {
            let packed = (u32::from(tail[0]) << 16) | (u32::from(tail[1]) << 8);
            out.push(ALPHABET[(packed >> 18) as usize & 0x3F] as char);
            out.push(ALPHABET[(packed >> 12) as usize & 0x3F] as char);
            out.push(ALPHABET[(packed >> 6) as usize & 0x3F] as char);
        }
        _ => {}
    }

    out
}

/// The URL the user's browser is sent to.
fn consent_url(redirect: &str, authorization: &Authorization) -> String {
    format!(
        "https://accounts.google.com/o/oauth2/v2/auth\
         ?client_id={OAUTH_CLIENT_ID}\
         &redirect_uri={redirect}\
         &response_type=code\
         &scope={SCOPE}\
         &code_challenge={}\
         &code_challenge_method=S256\
         &access_type=offline\
         &prompt=consent\
         &state={}",
        authorization.challenge, authorization.state,
    )
}

/// Read one HTTP request from a loopback socket and pull the query values out.
///
/// The wait is a poll loop so a cancel is noticed within a quarter second. A
/// browser tab that is simply closed never sends anything, so without the poll
/// a cancelled sign-in would spin until the two-minute timeout.
async fn read_redirect(
    listener: &tokio::net::TcpListener,
    expected_state: &str,
) -> AppResult<(Option<String>, Option<String>, String)> {
    let deadline = tokio::time::Instant::now() + AUTHORIZATION_TIMEOUT;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut socket, _) = loop {
        if CONNECT_CANCELLED.load(Ordering::SeqCst) {
            return Err(sign_in_cancelled());
        }

        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(AppError::new(
                "drive_timeout",
                "The Google sign-in was not completed in time. Try again.",
            ));
        }

        match tokio::time::timeout(remaining.min(CANCEL_POLL), listener.accept()).await {
            Ok(Ok(accepted)) => break accepted,
            Ok(Err(_)) => return Err(drive_error()),
            // The poll window elapsed: loop around and check for a cancel.
            Err(_) => continue,
        }
    };

    let mut buffer = vec![0u8; 8192];
    let read = tokio::time::timeout(REQUEST_READ_TIMEOUT, socket.read(&mut buffer))
        .await
        .map_err(|_| drive_error())?
        .map_err(|_| drive_error())?;
    let request = String::from_utf8_lossy(&buffer[..read]).to_string();

    // A cancel that arrived while the request was being read still wins: the
    // a stop was asked for, and completing the exchange would contradict that.
    if CONNECT_CANCELLED.load(Ordering::SeqCst) {
        return Err(sign_in_cancelled());
    }

    // First line only: "GET /?code=...&state=... HTTP/1.1"
    let target = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");

    let mut code = None;
    let mut state = None;

    if let Some(query) = target.split_once('?').map(|(_, q)| q) {
        for pair in query.split('&') {
            let Some((key, value)) = pair.split_once('=') else {
                continue;
            };
            match key {
                "code" => code = Some(percent_decode(value)),
                "state" => state = Some(percent_decode(value)),
                _ => {}
            }
        }
    }

    // A denied consent screen comes back as `error=access_denied`.
    let denied = target.contains("error=access_denied");

    let body = if denied {
        "Sign-in was cancelled. You can close this tab."
    } else if code.is_some() {
        "BackMeUp is connected. You can close this tab."
    } else {
        "Google sign-in did not return a code. You can close this tab."
    };

    let page = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>BackMeUp</title></head>\
         <body style=\"font-family:system-ui;background:#111;color:#eee;display:grid;\
         place-items:center;height:100vh;margin:0\">\
         <p style=\"font-size:15px\">{body}</p></body></html>"
    );

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{page}",
        page.len()
    );
    let _ = socket.write_all(response.as_bytes()).await;
    let _ = socket.shutdown().await;

    // The state must match, or this response belongs to some other request.
    let state_matches = state.as_deref() == Some(expected_state);
    if !state_matches {
        return Err(AppError::new(
            "drive_state_mismatch",
            "That Google sign-in response did not match this request. Try again.",
        ));
    }

    if denied {
        return Err(AppError::new(
            "drive_denied",
            "Google Drive access was not granted, so nothing was changed.",
        ));
    }

    Ok((code, state, body.to_string()))
}

/// Minimal percent-decoding: Google's codes and errors need nothing more, and
/// this avoids a dependency for three characters.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        index += 3;
                    }
                    Err(_) => {
                        out.push(bytes[index]);
                        index += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            other => {
                out.push(other);
                index += 1;
            }
        }
    }

    String::from_utf8_lossy(&out).into_owned()
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// What the UI needs to know about Google Drive.
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DriveStatus {
    pub connected: bool,
    /// The folder BackMeUp creates in Drive, so it is recognisable.
    pub root_folder: String,
    /// Database folders created inside `root_folder`, one per saved connection.
    pub folders: Vec<String>,
    /// Shown whenever Drive is connected. Storage is shared with the rest of
    /// the account, so a large database may not fit - and that should be known
    /// before they rely on it.
    pub storage_warning: String,
    /// The only scope requested, spelled out so the consent screen can be
    /// checked against it.
    pub scope: String,
}

/// The advisory shown next to a connected Drive.
const STORAGE_WARNING: &str = "Google Drive is a backup destination. Storage is shared with \
     the rest of your Google account, so a large database may not fit - check your free space \
     before relying on Drive as your only copy.";

/// Whether Drive is connected, and what it will do.
#[tauri::command]
pub fn google_drive_status(state: State<'_, AppState>) -> AppResult<DriveStatus> {
    require_session(&state)?;

    let connected = stored_tokens()?.is_some();

    Ok(DriveStatus {
        connected,
        root_folder: ROOT_FOLDER.to_string(),
        folders: if connected {
            stored_folder_names(&state)?
        } else {
            Vec::new()
        },
        storage_warning: STORAGE_WARNING.to_string(),
        scope: SCOPE.to_string(),
    })
}

/// The folder names this account would get, one per saved connection.
///
/// Read from SQLite only; no network call is made, so the Settings screen stays
/// responsive even when Drive is unreachable.
fn stored_folder_names(state: &State<'_, AppState>) -> AppResult<Vec<String>> {
    let conn = state.lock_db()?;

    let mut stmt = conn.prepare(
        "SELECT id, database_name FROM database_connections ORDER BY created_at ASC, id ASC",
    )?;
    let connections = stmt
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(connections
        .iter()
        .map(|(id, name)| database_folder_name(id, name, &connections))
        .collect())
}

/// Sign in to Google Drive.
///
/// Opens the default browser at Google's consent screen and waits on a
/// `127.0.0.1` listener for the redirect. Nothing is sent to Google until the
/// it is approved there, and no Google password ever reaches BackMeUp.
#[tauri::command]
pub async fn connect_google_drive(
    app: AppHandle,
    state: State<'_, AppState>,
) -> AppResult<DriveStatus> {
    require_session(&state)?;

    // Checked before the browser opens: a build without a client secret cannot
    // complete a sign-in, and that should be said now rather than after
    // approving the consent screen.
    client_secret()?;

    // A fresh attempt clears any cancel left over from an earlier one.
    CONNECT_CANCELLED.store(false, Ordering::SeqCst);

    // Bound to loopback on an ephemeral port: the redirect is reachable from
    // this machine only, and only until one request arrives.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|_| {
            AppError::new(
                "drive_unavailable",
                "BackMeUp could not start the local listener that Google signs in through.",
            )
        })?;

    let port = listener
        .local_addr()
        .map_err(|_| AppError::internal())?
        .port();
    let redirect = format!("http://127.0.0.1:{port}");

    let authorization = Authorization::new()?;
    let url = consent_url(&redirect, &authorization);

    // The URL is sent to the window *before* the browser is asked to open it. If
    // the automatic open fails - a locked-down browser policy, a headless
    // machine - the link can still be followed in the UI, so a failed
    // convenience never becomes a dead end.
    let _ = app.emit(SIGNIN_URL_EVENT, url.clone());

    match open_in_browser(&url) {
        Ok(()) => {}
        Err(err) => {
            // Wait anyway: the link in the window is enough to continue, and the
            // listener is already waiting for the redirect.
            eprintln!("[backmeup] google drive: browser did not open automatically ({err})");
        }
    }

    let (code, _state, _page) = read_redirect(&listener, &authorization.state).await?;

    let Some(code) = code else {
        return Err(AppError::new(
            "drive_no_code",
            "Google did not return a sign-in code. Try again.",
        ));
    };

    // Checked before the exchange so a cancel that raced the redirect cannot
    // still produce a stored sign-in.
    if CONNECT_CANCELLED.load(Ordering::SeqCst) {
        return Err(sign_in_cancelled());
    }

    let client = http()?;
    let tokens = exchange_code(&client, &code, &redirect, authorization.verifier.as_str()).await?;

    store_tokens(&tokens)?;

    // The sign-in succeeded, so the destination row exists even if folder
    // creation below fails; a failed upload can then be attributed correctly.
    {
        let conn = state.lock_db()?;
        crate::destinations::mark_google_drive_connected(&conn)?;
    }

    // Create `BackMeUp/<database>` for every saved connection now, rather than
    // waiting for the first upload: the destination is visibly ready.
    // Best effort - a network hiccup here must not throw away a good sign-in,
    // and every upload ensures its folders again. A database list that cannot
    // be read is equally non-fatal; the root folder is still created.
    let folders = stored_folder_names(&state).unwrap_or_default();
    if let Err(err) = ensure_database_folders(&client, tokens.access_token.as_str(), &folders).await {
        eprintln!(
            "[backmeup] google drive: connected, but folder preparation failed ({})",
            err.code
        );
    }

    google_drive_status(state)
}

/// Stop an in-flight sign-in.
///
/// Nothing is waiting on a browser callback, so the connect command notices
/// within a quarter second and returns `drive_cancelled`; no token is stored
/// and nothing is changed at Google. With no sign-in running this only arms the
/// flag, which the next attempt clears.
#[tauri::command]
pub fn cancel_google_drive_connect(state: State<'_, AppState>) -> AppResult<()> {
    require_session(&state)?;
    CONNECT_CANCELLED.store(true, Ordering::SeqCst);
    Ok(())
}

/// Disconnect Google Drive.
///
/// Revokes the grant with Google on a best-effort basis, then deletes the stored
/// tokens. Files already uploaded stay in the Drive account: forgetting a
/// sign-in is not a request to delete anyone's data.
#[tauri::command]
pub async fn disconnect_google_drive(state: State<'_, AppState>) -> AppResult<DriveStatus> {
    require_session(&state)?;

    // Revoking at Google is what actually ends the grant. If it fails (offline,
    // already revoked) the local tokens are still deleted: a disconnect was asked for
    // disconnect, and keeping a usable refresh token would contradict that.
    if let Ok(Some(tokens)) = stored_tokens() {
        if let Ok(client) = http() {
            let revoked = client
                .post("https://oauth2.googleapis.com/revoke")
                .form(&[("token", tokens.refresh_token.as_str())])
                .send()
                .await;

            if let Ok(response) = revoked {
                if !response.status().is_success() {
                    eprintln!(
                        "[backmeup] google drive: revoke returned {}",
                        response.status().as_u16()
                    );
                }
            }
        }
    }

    credentials::delete_oauth_tokens(PROVIDER)?;

    {
        let conn = state.lock_db()?;
        // Never delete the row: backup history references it and would cascade
        // away with it. Marking it disconnected keeps history intact.
        crate::destinations::mark_google_drive_disconnected(&conn)?;
    }

    google_drive_status(state)
}

/// Prove the stored token still works, and report the remaining Drive space.
#[tauri::command]
pub async fn test_google_drive(state: State<'_, AppState>) -> AppResult<Option<u64>> {
    require_session(&state)?;

    let token = access_token().await?;
    let client = http()?;
    free_space(&client, token.as_str()).await
}

/// Create the per-database folders again.
///
/// Useful after adding a connection while Drive was already connected. The
/// operation is idempotent, so calling it when everything exists changes
/// nothing.
#[tauri::command]
pub async fn sync_google_drive_folders(state: State<'_, AppState>) -> AppResult<DriveStatus> {
    require_session(&state)?;

    if !is_connected() {
        return Err(AppError::new(
            "drive_not_connected",
            "Google Drive is not connected. Connect it in Settings to back up to Drive.",
        ));
    }

    let folders = stored_folder_names(&state)?;
    let token = access_token().await?;
    let client = http()?;

    ensure_database_folders(&client, token.as_str(), &folders).await?;

    google_drive_status(state)
}

/// Keep the Drive folder tree in step with the app, in the background.
///
/// Called when a database is added while Drive is connected, so its
/// `BackMeUp/<database>` folder exists without anything being pressed.
/// Best effort by design: a failure is logged only, because every upload
/// ensures its own folders again before writing.
pub fn spawn_folder_sync(app: AppHandle) {
    if !is_connected() {
        return;
    }

    tauri::async_runtime::spawn(async move {
        let state = app.state::<AppState>();

        let Ok(folders) = stored_folder_names(&state) else {
            return;
        };
        let Ok(token) = access_token().await else {
            return;
        };
        let Ok(client) = http() else {
            return;
        };

        if let Err(err) = ensure_database_folders(&client, token.as_str(), &folders).await {
            eprintln!(
                "[backmeup] google drive: background folder sync failed ({})",
                err.code
            );
        }
    });
}

/// Trade an authorisation code for tokens, presenting the PKCE verifier.
async fn exchange_code(
    client: &reqwest::Client,
    code: &str,
    redirect: &str,
    verifier: &str,
) -> AppResult<TokenSet> {
    if code.is_empty() || code.len() > MAX_TOKEN_FIELD {
        return Err(drive_error());
    }

    let response = client
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("code", code),
            ("client_id", OAUTH_CLIENT_ID),
            ("client_secret", client_secret()?),
            ("code_verifier", verifier),
            ("grant_type", "authorization_code"),
            ("redirect_uri", redirect),
        ])
        .send()
        .await
        .map_err(|_| drive_error())?;

    let body = checked_body(response).await?;
    let parsed: TokenResponse = serde_json::from_str(&body).map_err(|_| drive_error())?;

    if parsed.refresh_token.is_empty() {
        // Without a refresh token the connection would last one hour, which is
        // not a usable destination. `access_type=offline` should have prevented
        // this, so treat it as a failure worth reporting.
        return Err(AppError::new(
            "drive_no_refresh_token",
            "Google did not issue a long-lived sign-in for Drive. Try connecting again.",
        ));
    }

    parsed.into_tokens("")
}

/// Open a URL in the default browser.
///
/// Uses the Windows shell protocol handler rather than spawning a shell, so the
/// URL is passed as one argument and nothing in it can be interpreted as a
/// command. The URL is built entirely from BackMeUp's own values - the client
/// ID, a hex state and a base64url challenge - and never contains user input.
fn open_in_browser(url: &str) -> AppResult<()> {
    std::process::Command::new("rundll32.exe")
        .arg("url.dll,FileProtocolHandler")
        .arg(url)
        .spawn()
        .map(|_| ())
        .map_err(|_| {
            AppError::new(
                "browser_unavailable",
                "BackMeUp could not open your browser to sign in to Google Drive.",
            )
        })
}

// ---------------------------------------------------------------------------
// Files: quota, folders and upload
// ---------------------------------------------------------------------------

/// Google's file API.
const FILES_API: &str = "https://www.googleapis.com/drive/v3/files";
const ABOUT_API: &str = "https://www.googleapis.com/drive/v3/about";
const UPLOAD_API: &str = "https://www.googleapis.com/upload/drive/v3/files";
/// Folder mime type.
const FOLDER_MIME: &str = "application/vnd.google-apps.folder";
/// Chunk size for a resumable upload. A multiple of 256 KiB, as the upload
/// protocol requires.
const CHUNK_BYTES: usize = 8 * 1024 * 1024;

/// Free and used space on the Drive account.
#[derive(Deserialize)]
struct StorageQuota {
    #[serde(default)]
    limit: Option<String>,
    #[serde(default)]
    usage: Option<String>,
}

impl StorageQuota {
    /// Bytes still available, or `None` when the account is unlimited (which
    /// Google reports by omitting the limit).
    fn free(&self) -> Option<u64> {
        let limit = self.limit.as_deref().and_then(|v| v.parse::<u64>().ok())?;
        let usage = self.usage.as_deref().and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);

        Some(limit.saturating_sub(usage))
    }
}

/// Map a failed Drive REST response onto an error that can be acted on.
///
/// Drive's error bodies are not the OAuth shape, so only the status is used.
/// Nothing from the body is logged beyond the numeric status.
fn api_error(status: reqwest::StatusCode) -> AppError {
    eprintln!(
        "[backmeup] google drive: API returned {}",
        status.as_u16()
    );

    match status.as_u16() {
        401 => AppError::new(
            "drive_reconnect",
            "Your Google Drive sign-in has expired. Connect Google Drive again.",
        ),
        403 => AppError::new(
            "drive_forbidden",
            "Google Drive refused that request. Your storage may be full, or the sign-in may \
             need renewing. Check Drive and try again.",
        ),
        404 => AppError::new(
            "drive_not_found",
            "A folder BackMeUp needs in Google Drive is no longer there. Run the backup again.",
        ),
        429 => AppError::new(
            "drive_busy",
            "Google Drive is busy right now. Try again in a moment.",
        ),
        _ => drive_error(),
    }
}

/// Read a Drive REST response, rejecting a non-success status before parsing.
async fn api_body(response: reqwest::Response) -> AppResult<String> {
    let status = response.status();
    let body = response.text().await.map_err(|_| drive_error())?;

    if status.is_success() {
        Ok(body)
    } else {
        Err(api_error(status))
    }
}

/// The account's remaining storage, if Google will say.
pub async fn free_space(client: &reqwest::Client, token: &str) -> AppResult<Option<u64>> {
    let response = client
        .get(ABOUT_API)
        .query(&[("fields", "storageQuota")])
        .bearer_auth(token)
        .send()
        .await
        .map_err(|_| drive_error())?;

    let body = api_body(response).await?;
    let parsed: AboutResponse = serde_json::from_str(&body).map_err(|_| drive_error())?;
    Ok(parsed.storage_quota.and_then(|quota| quota.free()))
}

#[derive(Deserialize)]
struct AboutResponse {
    #[serde(rename = "storageQuota")]
    storage_quota: Option<StorageQuota>,
}

/// Body for `files.create` when making a folder.
///
/// `parents` must be a JSON array. Drive v3 silently ignores a bare string,
/// which creates the folder in My Drive root instead of inside `BackMeUp` -
/// exactly the layout the folder tree is meant to avoid.
#[derive(Serialize)]
struct CreateFolder<'a> {
    name: &'a str,
    #[serde(rename = "mimeType")]
    mime_type: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    parents: Option<[&'a str; 1]>,
}

/// The id of `name` inside `parent`, creating it when it is absent.
///
/// Folders are looked up before being created, so repeated backups reuse one
/// folder per database per day instead of scattering duplicates.
async fn find_or_create_folder(
    client: &reqwest::Client,
    token: &str,
    parent: Option<&str>,
    name: &str,
) -> AppResult<String> {
    // The name is a database name or a date, both of which can contain a
    // quote. Escaping it is what keeps the query well formed - Drive's query
    // language uses single quotes.
    let escaped = name.replace('\\', "\\\\").replace('\'', "\\'");

    let mut query = format!("mimeType = '{FOLDER_MIME}' and name = '{escaped}' and trashed = false");
    if let Some(parent) = parent {
        query.push_str(&format!(" and '{parent}' in parents"));
    }

    let response = client
        .get(FILES_API)
        .query(&[
            ("q", query.as_str()),
            ("fields", "files(id,name)"),
            ("pageSize", "10"),
        ])
        .bearer_auth(token)
        .send()
        .await
        .map_err(|_| drive_error())?;

    let body = api_body(response).await?;
    let listed: FileList = serde_json::from_str(&body).map_err(|_| drive_error())?;
    if let Some(existing) = listed.files.and_then(|files| files.into_iter().next()) {
        return Ok(existing.id);
    }

    let body = CreateFolder {
        name,
        mime_type: FOLDER_MIME,
        parents: parent.map(|id| [id]),
    };

    let response = client
        .post(FILES_API)
        .query(&[("fields", "id")])
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .map_err(|_| drive_error())?;

    let body = api_body(response).await?;
    let created: CreatedFile = serde_json::from_str(&body).map_err(|_| drive_error())?;
    Ok(created.id)
}

#[derive(Deserialize)]
struct FileList {
    files: Option<Vec<NamedFile>>,
}

#[derive(Deserialize)]
struct NamedFile {
    id: String,
}

#[derive(Deserialize)]
struct CreatedFile {
    id: String,
}

/// Build the folder path for one backup: `BackMeUp/<database>/<day>`.
pub async fn ensure_backup_folders(
    client: &reqwest::Client,
    token: &str,
    database: &str,
    day: &str,
) -> AppResult<String> {
    let root = find_or_create_folder(client, token, None, ROOT_FOLDER).await?;
    let per_database = find_or_create_folder(client, token, Some(&root), database).await?;
    find_or_create_folder(client, token, Some(&per_database), day).await
}

/// Create `BackMeUp/<database>` for each name, reusing existing folders.
///
/// Called once when Drive is connected and again before each upload, so a
/// database added later still gets its folder. Idempotent: a second call finds
/// every folder and creates nothing.
pub async fn ensure_database_folders(
    client: &reqwest::Client,
    token: &str,
    databases: &[String],
) -> AppResult<usize> {
    let root = find_or_create_folder(client, token, None, ROOT_FOLDER).await?;

    for database in databases {
        find_or_create_folder(client, token, Some(&root), database).await?;
    }

    Ok(databases.len())
}

/// A database name becomes one folder name: no separators, no reserved
/// characters, and bounded so a long name cannot produce an unusable path.
pub fn sanitize_folder_name(label: &str) -> String {
    let cleaned: String = label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == ' ' {
                c
            } else {
                '-'
            }
        })
        .collect();

    let trimmed = cleaned.trim().trim_matches(['-', ' ', '_']);
    let capped: String = trimmed.chars().take(80).collect();

    if capped.is_empty() {
        "database".to_string()
    } else {
        capped
    }
}

/// The folder name for one connection.
///
/// Normally just the database name. When two saved connections point at the
/// same database name, each gets a short suffix derived from its own id, so the
/// two never merge into one folder and the name stays stable across runs.
pub fn database_folder_name(
    connection_id: &str,
    database_name: &str,
    connections: &[(String, String)],
) -> String {
    let base = sanitize_folder_name(database_name);

    let same_name = connections
        .iter()
        .filter(|(_, name)| sanitize_folder_name(name) == base)
        .count();

    if same_name > 1 {
        let suffix: String = connection_id.chars().take(6).collect();
        format!("{base}-{suffix}")
    } else {
        base
    }
}

/// The offset Google has durably stored, parsed from a `Range: bytes=0-N`
/// header. `N` is the last byte accepted, so the next offset is `N + 1`.
fn parse_range(value: &str) -> Option<u64> {
    let (_, rest) = value.trim().strip_prefix("bytes=")?.split_once('-')?;
    // Google sends `bytes=0-N`; tolerate a `/total` suffix too.
    let last = rest.split('/').next()?.trim();

    last.parse::<u64>().ok().map(|last| last + 1)
}

fn range_offset(response: &reqwest::Response) -> Option<u64> {
    let value = response.headers().get("range")?.to_str().ok()?;
    parse_range(value)
}

/// Ask Google how much of the file it already has.
async fn uploaded_offset(
    client: &reqwest::Client,
    token: &str,
    session: &str,
    total: u64,
) -> Option<u64> {
    let response = client
        .put(session)
        .header("Content-Range", format!("bytes */{total}"))
        .bearer_auth(token)
        .body(Vec::new())
        .send()
        .await
        .ok()?;

    // 200/201 here means the upload completed while we were not looking.
    if response.status().is_success() {
        return Some(total);
    }
    if response.status().as_u16() != 308 {
        return None;
    }

    range_offset(&response)
}

/// Upload one finished backup file into a Drive folder.
///
/// Resumable, in chunks, so a dropped connection resumes rather than restarting
/// a multi-gigabyte file. The file is read from disk in slices and never held in
/// memory in full. Every response is checked: a non-final chunk must come back
/// `308 Resume Incomplete`, and the offset Google reports is the one the next
/// chunk starts from, so a partially accepted chunk is never skipped.
pub async fn upload_file(
    client: &reqwest::Client,
    token: &str,
    parent_id: &str,
    name: &str,
    path: &std::path::Path,
    progress: &(dyn Fn(u64) + Send + Sync),
    cancelled: &(dyn Fn() -> bool + Send + Sync),
) -> AppResult<u64> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    const MAX_ATTEMPTS: usize = 4;

    let mut file = tokio::fs::File::open(path).await.map_err(|_| {
        AppError::new(
            "drive_upload_failed",
            "The finished backup file could not be read for upload.",
        )
    })?;

    let total = file
        .metadata()
        .await
        .map_err(|_| AppError::internal())?
        .len();

    /// Metadata for the file being created. It must travel in the body of the
    /// session request: without `parents` Drive would accept the upload but
    /// leave the file loose in the account's root instead of the folder this
    /// backup belongs to.
    #[derive(Serialize)]
    struct Metadata<'a> {
        name: &'a str,
        parents: Vec<&'a str>,
    }

    // 1. Open a resumable session. The session URI comes back in a header.
    let response = client
        .post(UPLOAD_API)
        .query(&[("uploadType", "resumable")])
        .header("X-Upload-Content-Type", "application/sql")
        .header("X-Upload-Content-Length", total)
        .bearer_auth(token)
        .json(&Metadata {
            name,
            parents: vec![parent_id],
        })
        .send()
        .await
        .map_err(|_| upload_error())?;

    let status = response.status();
    if !status.is_success() {
        return Err(api_error(status));
    }

    let session = response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
        .ok_or_else(upload_error)?;

    // 2. Send the bytes in chunks, tracking the offset Google confirms.
    let mut sent: u64 = 0;
    let mut attempt = 0;

    while sent < total {
        if cancelled() {
            return Err(AppError::new(
                "drive_cancelled",
                "The backup upload was cancelled.",
            ));
        }

        let take = CHUNK_BYTES.min((total - sent) as usize);
        let mut buffer = vec![0u8; take];

        file.seek(std::io::SeekFrom::Start(sent))
            .await
            .map_err(|_| upload_error())?;
        file.read_exact(&mut buffer)
            .await
            .map_err(|_| upload_error())?;

        let end = sent + take as u64;
        let content_range = format!("bytes {sent}-{}/{total}", end - 1);

        let response = client
            .put(&session)
            .header("Content-Type", "application/sql")
            .header("Content-Range", content_range)
            .bearer_auth(token)
            .body(buffer)
            .send()
            .await;

        let response = match response {
            Ok(response) => response,
            Err(_) => {
                // A transport failure leaves the session open. Ask Google what
                // it already has and continue from there rather than resending
                // from zero.
                attempt += 1;
                if attempt >= MAX_ATTEMPTS {
                    return Err(upload_error());
                }
                tokio::time::sleep(Duration::from_millis(400 * attempt as u64)).await;
                sent = uploaded_offset(client, token, &session, total)
                    .await
                    .unwrap_or(sent);
                progress(sent);
                continue;
            }
        };

        let status = response.status();

        if status.as_u16() == 308 {
            // Not finished yet. Trust Google's offset when it reports one; a
            // 308 without a Range header means the whole chunk was accepted.
            sent = range_offset(&response).unwrap_or(end).min(total);
            attempt = 0;
            progress(sent);
            continue;
        }

        if status.is_success() {
            let body = api_body(response).await?;
            let created: CreatedFile = serde_json::from_str(&body).map_err(|_| upload_error())?;
            eprintln!("[backmeup] google drive: stored {} as {}", name, created.id);

            sent = end;
            progress(sent);
            continue;
        }

        // 401/403/404 will not fix themselves by retrying. Everything else is
        // transient, so resume after a short backoff.
        if matches!(status.as_u16(), 401 | 403 | 404) {
            return Err(api_error(status));
        }

        attempt += 1;
        if attempt >= MAX_ATTEMPTS {
            return Err(api_error(status));
        }
        tokio::time::sleep(Duration::from_millis(400 * attempt as u64)).await;
        sent = uploaded_offset(client, token, &session, total)
            .await
            .unwrap_or(sent);
        progress(sent);
    }

    Ok(total)
}

fn upload_error() -> AppError {
    AppError::new(
        "drive_upload_failed",
        "The backup could not be uploaded to Google Drive. Try again in a moment.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_never_render_their_secrets() {
        let tokens = TokenSet {
            access_token: "ya29.a0-secret-value".to_string(),
            refresh_token: "1//refresh-secret".to_string(),
            expires_at: 42,
        };

        let rendered = format!("{tokens:?}");
        assert!(!rendered.contains("ya29"), "{rendered}");
        assert!(!rendered.contains("1//refresh"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }

    #[test]
    fn authorization_never_renders_the_verifier() {
        let authorization = Authorization {
            verifier: Zeroizing::new("verifier-secret".to_string()),
            challenge: "challenge".to_string(),
            state: "state-secret".to_string(),
        };

        let rendered = format!("{authorization:?}");
        assert!(!rendered.contains("verifier-secret"), "{rendered}");
        assert!(!rendered.contains("state-secret"), "{rendered}");
    }

    #[test]
    fn folder_creation_sends_its_parent_as_an_array() {
        // Drive v3 expects `"parents": ["id"]`. A bare string is ignored, which
        // silently drops the folder into My Drive root instead of BackMeUp.
        let body = CreateFolder {
            name: "shop",
            mime_type: FOLDER_MIME,
            parents: Some(["parent-id"]),
        };
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["parents"], serde_json::json!(["parent-id"]), "{json}");

        // A root folder carries no parent key at all, so Drive places it in
        // the account's My Drive.
        let root = CreateFolder {
            name: ROOT_FOLDER,
            mime_type: FOLDER_MIME,
            parents: None,
        };
        let json = serde_json::to_value(&root).unwrap();
        assert!(json.get("parents").is_none(), "{json}");
    }

    #[test]
    fn a_refreshed_token_keeps_the_previous_refresh_token() {
        // Google omits the refresh token on refreshes; dropping it would
        // silently un-connect the destination.
        let response = TokenResponse {
            access_token: "ya29.fresh".to_string(),
            refresh_token: String::new(),
            expires_in: Some(3600),
        };

        let tokens = response.into_tokens("1//original").unwrap();
        assert_eq!(tokens.refresh_token, "1//original");
        assert_eq!(tokens.access_token, "ya29.fresh");
        assert!(tokens.expires_at > now_secs());

        // A newly issued refresh token always wins.
        let response = TokenResponse {
            access_token: "ya29.fresh".to_string(),
            refresh_token: "1//rotated".to_string(),
            expires_in: Some(3600),
        };
        assert_eq!(response.into_tokens("1//original").unwrap().refresh_token, "1//rotated");
    }

    #[test]
    fn an_implausible_token_is_refused_before_it_is_stored() {
        for response in [
            TokenResponse {
                access_token: String::new(),
                refresh_token: "1//r".to_string(),
                expires_in: Some(1),
            },
            TokenResponse {
                access_token: "a".repeat(MAX_TOKEN_FIELD + 1),
                refresh_token: "1//r".to_string(),
                expires_in: Some(1),
            },
        ] {
            assert!(response.into_tokens("").is_err());
        }
    }

    #[test]
    fn expiry_is_treated_with_a_margin() {
        let fresh = TokenSet {
            access_token: "a".to_string(),
            refresh_token: "r".to_string(),
            expires_at: now_secs() + 3600,
        };
        assert!(!fresh.expired());

        // Inside the refresh margin: treated as expired so a token cannot lapse
        // mid-upload.
        let marginal = TokenSet {
            access_token: "a".to_string(),
            refresh_token: "r".to_string(),
            expires_at: now_secs() + 30,
        };
        assert!(marginal.expired());
    }

    #[test]
    fn the_consent_url_requests_only_the_files_scope() {
        let authorization = Authorization {
            verifier: Zeroizing::new("v".to_string()),
            challenge: "chal".to_string(),
            state: "st".to_string(),
        };

        let url = consent_url("http://127.0.0.1:1234", &authorization);

        assert!(url.contains(SCOPE), "{url}");
        assert!(url.contains("code_challenge_method=S256"), "{url}");
        assert!(url.contains("access_type=offline"), "{url}");
        assert!(url.contains("response_type=code"), "{url}");
        assert!(!url.contains("client_secret"), "there is no secret to send");
        // Only the scope that was asked for, nothing wider.
        assert_eq!(url.matches("/auth/").count(), 1, "{url}");
    }

    #[test]
    fn free_space_is_computed_from_the_quota_numbers() {
        let quota = StorageQuota {
            limit: Some("1000".to_string()),
            usage: Some("400".to_string()),
        };
        assert_eq!(quota.free(), Some(600));

        // An account with unlimited storage reports no limit: the caller must
        // treat that as "no check needed", not as "no space".
        let unlimited = StorageQuota {
            limit: None,
            usage: Some("400".to_string()),
        };
        assert_eq!(unlimited.free(), None);

        // Usage above the limit cannot underflow.
        let over = StorageQuota {
            limit: Some("100".to_string()),
            usage: Some("150".to_string()),
        };
        assert_eq!(over.free(), Some(0));
    }

    #[test]
    fn drive_status_carries_the_storage_advisory() {
        let status = DriveStatus {
            connected: false,
            root_folder: "BackMeUp".to_string(),
            folders: Vec::new(),
            storage_warning: STORAGE_WARNING.to_string(),
            scope: SCOPE.to_string(),
        };

        assert_eq!(status.root_folder, ROOT_FOLDER);
        assert!(status.storage_warning.contains("large database"), "{status:?}");
        assert!(status.storage_warning.contains("only copy"), "{status:?}");
        assert_eq!(status.scope, "https://www.googleapis.com/auth/drive.file");
    }

    #[test]
    fn a_cancelled_sign_in_says_nothing_was_changed() {
        let err = sign_in_cancelled();

        // The UI keys off this code alone to show a neutral "cancelled" note
        // rather than an error, so both the code and the wording matter.
        assert_eq!(err.code, "drive_cancelled");
        assert!(err.message.contains("cancelled"), "{}", err.message);
        assert!(err.message.contains("Nothing was changed"), "{}", err.message);
    }

    #[test]
    fn folder_names_are_safe_and_bounded() {
        assert_eq!(sanitize_folder_name("Tabulate"), "Tabulate");
        assert_eq!(sanitize_folder_name("my shop"), "my shop");
        assert_eq!(sanitize_folder_name("a/b:c"), "a-b-c");
        assert_eq!(sanitize_folder_name("  padded  "), "padded");
        assert_eq!(sanitize_folder_name("***"), "database");
        assert_eq!(sanitize_folder_name(""), "database");

        // No separator may survive, or the folder tree would gain extra levels.
        for hostile in ["a/b", "a\\b", "a:b", "a*b", "a?b", "a|b"] {
            assert!(!sanitize_folder_name(hostile).contains(['/', '\\', ':', '*', '?', '|']));
        }

        assert_eq!(sanitize_folder_name(&"n".repeat(500)).chars().count(), 80);
    }

    #[test]
    fn duplicate_database_names_get_stable_suffixes() {
        let id_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let id_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let id_c = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

        let connections = vec![
            (id_a.to_string(), "shop".to_string()),
            (id_b.to_string(), "shop".to_string()),
            (id_c.to_string(), "blog".to_string()),
        ];

        let a = database_folder_name(id_a, "shop", &connections);
        let b = database_folder_name(id_b, "shop", &connections);
        let c = database_folder_name(id_c, "blog", &connections);

        assert_eq!(a, "shop-aaaaaa");
        assert_eq!(b, "shop-bbbbbb");
        assert_ne!(a, b, "two databases must not share one folder");
        assert_eq!(c, "blog", "a unique name needs no suffix");

        // The same inputs always produce the same name.
        assert_eq!(a, database_folder_name(id_a, "shop", &connections));
    }

    #[test]
    fn resumable_offsets_come_from_the_range_header() {
        assert_eq!(parse_range("bytes=0-0"), Some(1));
        assert_eq!(parse_range("bytes=0-1048575"), Some(1_048_576));
        assert_eq!(parse_range("bytes=0-0/2000"), Some(1));

        assert_eq!(parse_range("bytes=*"), None);
        assert_eq!(parse_range("items=0-1"), None);
        assert_eq!(parse_range("bytes=0-abc"), None);
    }

    #[test]
    fn base64url_matches_rfc_4648_vectors() {
        // PKCE is only satisfied when the challenge is real base64url of the
        // SHA-256 digest, so these vectors are the difference between working
        // sign-in and an instant failure.
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(base64url(b"foob"), "Zm9vYg");
        assert_eq!(base64url(b"fooba"), "Zm9vYmE");
        assert_eq!(base64url(b"foobar"), "Zm9vYmFy");

        // The alphabet is URL-safe: no '+' or '/' can appear.
        let dense = base64url(&[0xFB, 0xFF, 0xBF, 0xFF, 0xFB, 0xEF]);
        assert!(!dense.contains('+'), "{dense}");
        assert!(!dense.contains('/'), "{dense}");
        assert!(!dense.contains('='), "{dense}");

        // Round trip through a decoder would be ideal; the property that matters
        // is that the length matches base64url of n bytes.
        assert_eq!(base64url(&[0u8; 32]).len(), 43);
        assert_eq!(base64url(&[0u8; 16]).len(), 22);
    }

    #[test]
    fn a_verifier_and_challenge_are_produced_at_the_right_shape() {
        let authorization = Authorization::new().expect("CSPRNG must be available");

        // PKCE requires 43-128 unreserved characters.
        assert!(
            (43..=128).contains(&authorization.verifier.len()),
            "verifier length {}",
            authorization.verifier.len()
        );
        assert_eq!(authorization.challenge.len(), 43, "S256 digest is 32 bytes");
        assert!(authorization.state.len() >= 16);

        // Two attempts must not collide.
        let other = Authorization::new().unwrap();
        assert_ne!(authorization.verifier.as_str(), other.verifier.as_str());
    }

    #[test]
    fn percent_decoding_handles_codes_and_errors() {
        assert_eq!(percent_decode("plain"), "plain");
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(percent_decode("4%2F0Ab"), "4/0Ab");
        assert_eq!(percent_decode("plus+sign"), "plus sign");
        assert_eq!(percent_decode("bad%zz"), "bad%zz");
        assert_eq!(percent_decode("trailing%"), "trailing%");
    }
}
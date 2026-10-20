//! SSH tunnels for database connections.
//!
//! A connection that uses the "SSH tunnel" method is dialled in two steps.
//! BackMeUp first opens one SSH session to the SSH server; the database driver
//! then connects to a listener bound to `127.0.0.1` on an ephemeral port that
//! forwards every accepted connection through that SSH session
//! (`ssh -L` semantics). The database password and the SSH credential are
//! consumed here or by the adapter and are never written anywhere by this
//! module.
//!
//! Design rules enforced here:
//!   * The listener is bound to `127.0.0.1` only and never to `0.0.0.0`, so no
//!     other machine can reach the forwarded port.
//!   * Host keys are pinned by SHA-256 fingerprint. A real connection refuses
//!     to proceed unless the server presents exactly the verified fingerprint;
//!     there is no flag to skip this. The only operation that accepts an
//!     unknown key is [`probe_host_key`], which learns the fingerprint on a
//!     throwaway session that never authenticates and never sees a credential.
//!   * Credentials are wrapped in [`Zeroizing`] and any SSH key text is parsed
//!     locally before a socket is opened, so a bad key or passphrase cannot
//!     consume a network attempt.
//!   * Sign-in mirrors the OpenSSH client rather than a single method: a
//!     password is offered as `password` and, whenever that method does not
//!     succeed, again as `keyboard-interactive` (the PAM method shared hosting
//!     panels advertise); a private key is offered as `publickey`.
//!   * Signing in is never assumed to grant port forwarding. When the server
//!     declines to open the forwarded channel, "forwarding is not permitted" is
//!     reported apart from "the database address is unreachable", because the
//!     two need different remedies.
//!   * Every stage has its own timeout and maps to one fixed, safe sentence.
//!     Server-supplied text is never echoed.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use russh::client::{self, Config, Handle, Handler, KeyboardInteractiveAuthResponse};
use russh::keys::key::PublicKey;
use zeroize::Zeroizing;

/// Budget for the SSH TCP connection and transport setup.
const SSH_CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
/// Budget for SSH authentication once the transport is up.
const SSH_AUTH_TIMEOUT: Duration = Duration::from_secs(10);
/// Budget for the pre-flight channel the server opens towards the database.
const SSH_CHANNEL_TIMEOUT: Duration = Duration::from_secs(8);
/// Keepalive cadence so an idle tunnel is not reaped by a NAT or firewall.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const KEEPALIVE_MAX: usize = 3;

/// How many keyboard-interactive rounds are answered before giving up. Real
/// servers ask once (occasionally twice, with a confirmation); anything more
/// means a single password cannot complete the exchange, so the attempt must
/// end rather than keep answering prompts. The whole exchange is still bounded
/// by [`SSH_AUTH_TIMEOUT`].
const MAX_KEYBOARD_INTERACTIVE_ROUNDS: usize = 4;

/// User name used only by the key probe. It is not a secret and carries no
/// authentication method that could transmit one.
const PROBE_USER: &str = "backmeup-verify";

/// What the SSH server presented as its host key.
///
/// Public data only: the key algorithm name and the SHA-256 fingerprint in
/// base64 without padding (rendered as `SHA256:<value>` in OpenSSH terms).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKeyInfo {
    pub key_type: String,
    pub fingerprint: String,
}

/// Stage-accurate SSH failures.
///
/// Each variant maps to one fixed sentence and a machine-readable code; driver
/// text, host names, user names and any credential material never appear in
/// either.
#[derive(Debug)]
pub enum SshError {
    /// The SSH server could not be reached or the transport did not come up.
    Connect,
    /// The server presented a host key other than the verified fingerprint.
    HostKeyMismatch { presented: HostKeyInfo },
    /// The server rejected the SSH sign-in.
    AuthRejected,
    /// The key text could not be parsed or the passphrase is wrong.
    BadCredential,
    /// The SSH server declined to open a forwarded connection: signing in
    /// succeeded, but this account is not permitted to forward ports.
    TunnelNotPermitted,
    /// The SSH server could not open a connection to the database address.
    ChannelRefused,
    /// The session failed in a way that is not attributable to a later stage.
    Protocol,
}

impl SshError {
    pub fn code(&self) -> &'static str {
        match self {
            SshError::Connect => "ssh_unreachable",
            SshError::HostKeyMismatch { .. } => "ssh_host_key_mismatch",
            SshError::AuthRejected => "ssh_auth_failed",
            SshError::BadCredential => "ssh_key_unreadable",
            SshError::TunnelNotPermitted => "ssh_tunnel_not_permitted",
            SshError::ChannelRefused => "ssh_tunnel_refused",
            SshError::Protocol => "ssh_protocol_error",
        }
    }

    pub fn user_message(&self) -> &'static str {
        match self {
            SshError::Connect => {
                "BackMeUp could not reach the SSH server. Check the SSH host and port, \
                 and that the server accepts SSH connections."
            }
            SshError::HostKeyMismatch { .. } => {
                "The SSH server presented a different host key than the one verified for \
                 this connection, so BackMeUp refused to continue. If the server was \
                 rebuilt or migrated, verify the new fingerprint out of band before \
                 trusting it again."
            }
            SshError::AuthRejected => {
                "The SSH server rejected the sign-in after BackMeUp offered both the \
                 password and keyboard-interactive methods. Check the SSH user name \
                 and password, that the account can sign in over SSH at all, and that \
                 the panel password is the one this account uses."
            }
            SshError::BadCredential => {
                "The SSH private key could not be read. Check that the whole key text \
                 was pasted and that the passphrase, if any, is correct."
            }
            SshError::ChannelRefused => {
                "The SSH server could not reach the database address from its side. \
                 Check the database host and port as the server resolves them, and \
                 that the database accepts connections from the server itself."
            }
            SshError::TunnelNotPermitted => {
                "The SSH sign-in worked, but this server does not allow port \
                 forwarding for the account, so no tunnel could be opened. Signing \
                 in over SSH does not automatically grant forwarding. If your \
                 provider allows external database access, use the direct method \
                 instead; otherwise ask your host whether port forwarding can be \
                 enabled for this account."
            }
            SshError::Protocol => {
                "The SSH session failed during setup. Please try again."
            }
        }
    }
}

/// Error type for the client handler. Kept separate from [`SshError`] so a
/// host-key rejection can travel through `russh`'s error channel and be
/// recognised after `client::connect` returns.
#[derive(Debug)]
enum TofuError {
    HostKeyRejected(HostKeyInfo),
    Transport,
}

impl From<russh::Error> for TofuError {
    fn from(_: russh::Error) -> Self {
        // The transport detail may embed the remote address; the caller maps
        // this to the generic `SshError::Connect` message instead.
        TofuError::Transport
    }
}

impl std::fmt::Display for TofuError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TofuError::HostKeyRejected(_) => f.write_str("host key rejected"),
            TofuError::Transport => f.write_str("ssh transport error"),
        }
    }
}

impl std::error::Error for TofuError {}

/// Host-key policy for one connection.
///
/// `expected == None` is probe mode: the fingerprint is recorded and the key
/// accepted once, and the caller disconnects before any authentication. With
/// `Some(fingerprint)` any other key aborts the connection.
struct TofuHandler {
    expected: Option<String>,
    seen: Arc<Mutex<Option<HostKeyInfo>>>,
}

#[async_trait]
impl Handler for TofuHandler {
    type Error = TofuError;

    /// Called during key exchange, before anything encrypted - and therefore
    /// before any credential - can flow. The default implementation rejects
    /// every key; this one pins the fingerprint.
    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        let presented = HostKeyInfo {
            key_type: server_public_key.name().to_string(),
            fingerprint: server_public_key.fingerprint(),
        };

        if let Ok(mut slot) = self.seen.lock() {
            *slot = Some(presented.clone());
        }

        match &self.expected {
            None => Ok(true),
            Some(expected) if *expected == presented.fingerprint => Ok(true),
            Some(_) => Err(TofuError::HostKeyRejected(presented)),
        }
    }
}

/// Client configuration. Keepalives keep an idle tunnel alive across NAT;
/// nothing here weakens the host-key or cipher policy.
fn client_config() -> Arc<Config> {
    Arc::new(Config {
        keepalive_interval: Some(KEEPALIVE_INTERVAL),
        keepalive_max: KEEPALIVE_MAX,
        ..Default::default()
    })
}

/// Open the SSH transport and run key exchange, bounded by
/// [`SSH_CONNECT_TIMEOUT`]. The handler has already seen - and judged - the
/// server key when this returns.
async fn connect(
    host: &str,
    port: u16,
    handler: TofuHandler,
) -> Result<Handle<TofuHandler>, SshError> {
    tokio::time::timeout(
        SSH_CONNECT_TIMEOUT,
        client::connect(client_config(), (host, port), handler),
    )
    .await
    .map_err(|_| SshError::Connect)?
    .map_err(|err| match err {
        TofuError::HostKeyRejected(presented) => SshError::HostKeyMismatch { presented },
        TofuError::Transport => SshError::Connect,
    })
}

/// Learn the fingerprint of the host key an SSH server presents.
///
/// This is the only operation that accepts a key it has not seen before, and
/// it is safe to do so: the session is used solely to read the public host key
/// during key exchange and is closed again. No authentication method that
/// carries a credential is ever invoked on it.
pub async fn probe_host_key(host: &str, port: u16) -> Result<HostKeyInfo, SshError> {
    let seen = Arc::new(Mutex::new(None));
    let handler = TofuHandler {
        expected: None,
        seen: seen.clone(),
    };

    let mut handle = connect(host, port, handler).await?;

    // The "none" method exists to drive the key exchange to completion; it
    // transmits a user name and nothing else. Its reply only arrives after the
    // encrypted channel is up, so by then the host key has been recorded.
    let reply = tokio::time::timeout(SSH_AUTH_TIMEOUT, handle.authenticate_none(PROBE_USER)).await;

    let info = match seen.lock().ok().and_then(|slot| slot.clone()) {
        Some(info) => info,
        None => {
            return Err(if reply.is_err() {
                SshError::Connect
            } else {
                SshError::Protocol
            })
        }
    };

    let _ = handle
        .disconnect(russh::Disconnect::ByApplication, "host key probe complete", "")
        .await;

    Ok(info)
}

/// Parse a pasted private key (with an optional passphrase) without touching
/// the network.
///
/// Lets callers reject a bad key or passphrase before anything is stored or
/// dialled. Only the stage-accurate code is returned: the parser's own error
/// text is never surfaced.
pub fn validate_private_key(key: &str, passphrase: Option<&str>) -> Result<(), SshError> {
    russh::keys::decode_secret_key(key, passphrase)
        .map(|_| ())
        .map_err(|_| SshError::BadCredential)
}

/// One SSH sign-in method.
pub enum SshCredential {
    Password(Zeroizing<String>),
    PrivateKey {
        key: Zeroizing<String>,
        passphrase: Option<Zeroizing<String>>,
    },
}

impl std::fmt::Debug for SshCredential {
    /// Never renders the secret. Exists so a credential can appear in a log or
    /// panic message without leaking.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SshCredential::Password(_) => f.write_str("SshCredential::Password(<redacted>)"),
            SshCredential::PrivateKey { .. } => {
                f.write_str("SshCredential::PrivateKey(<redacted>)")
            }
        }
    }
}

/// Everything needed to open one tunnel, with secrets already resolved.
pub struct SshRequest {
    pub ssh_host: String,
    pub ssh_port: u16,
    pub ssh_username: String,
    pub credential: SshCredential,
    /// Verified host-key fingerprint (base64, no `SHA256:` prefix). Required:
    /// there is no unverified connection path.
    pub expected_host_key: String,
    /// Address of the database *as resolved by the SSH server*.
    pub database_host: String,
    pub database_port: u16,
}

impl std::fmt::Debug for SshRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshRequest")
            .field("ssh_host", &self.ssh_host)
            .field("ssh_port", &self.ssh_port)
            .field("ssh_username", &self.ssh_username)
            .field("credential", &"<redacted>")
            .field("expected_host_key", &self.expected_host_key)
            .field("database_host", &self.database_host)
            .field("database_port", &self.database_port)
            .finish()
    }
}

/// A running tunnel. Reachable only on `127.0.0.1:<local_port>`.
///
/// Dropping the value shuts the listener down and ends the SSH session; the
/// caller must keep it alive for exactly as long as the database connection
/// that uses it.
pub struct SshTunnel {
    local_port: u16,
    /// The host key the session was pinned to, for the caller to record once
    /// the tunnel is proven to work.
    host_key: HostKeyInfo,
    /// Never read: the field exists for its `Drop` side effect, closing the
    /// oneshot channel that tells the accept loop to stop.
    #[allow(dead_code)]
    shutdown: tokio::sync::oneshot::Sender<()>,
}

impl SshTunnel {
    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    pub fn host_key(&self) -> &HostKeyInfo {
        &self.host_key
    }
}

enum PreparedCredential {
    Password(Zeroizing<String>),
    PrivateKey(Arc<russh::keys::key::KeyPair>),
}

/// Sign in with a password the way the OpenSSH command-line client does.
///
/// Two methods are attempted, in order:
///   1. `password` - the plain method, for servers that advertise it;
///   2. `keyboard-interactive`, answering the password to every prompt - the
///      method PAM-based servers (shared hosting panels among them) advertise
///      instead of `password`, and the one `ssh` falls back to automatically.
///
/// Without step 2 those servers reject a correct password with no explanation,
/// on the wire a bare `USERAUTH_FAILURE`.
///
/// The second method is attempted whenever the first did not succeed - whether
/// the server refused it or the exchange for it failed. A server that does not
/// offer `password` may answer with a plain failure or by dropping the request,
/// and both must still reach the fallback, or a correct password is refused for
/// no visible reason. A dead session fails again below and is reported as a
/// transport problem rather than a rejected credential.
async fn sign_in_with_password(
    handle: &mut Handle<TofuHandler>,
    user: &str,
    password: &str,
) -> Result<bool, SshError> {
    match handle.authenticate_password(user, password).await {
        Ok(true) => return Ok(true),
        Ok(false) | Err(_) => {}
    }

    let mut response = handle
        .authenticate_keyboard_interactive_start(user, None::<String>)
        .await
        .map_err(|_| SshError::Connect)?;

    for _ in 0..MAX_KEYBOARD_INTERACTIVE_ROUNDS {
        match response {
            KeyboardInteractiveAuthResponse::Success => return Ok(true),
            KeyboardInteractiveAuthResponse::Failure => return Ok(false),
            KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                // The password answers every prompt: a password prompt by
                // definition, and a confirmation prompt (some PAM stacks ask
                // twice) with the same value. A prompt demanding something
                // else - a one-time code - simply fails the exchange, which is
                // the correct outcome for a password credential.
                let answers = prompts
                    .iter()
                    .map(|_| password.to_string())
                    .collect::<Vec<_>>();
                response = handle
                    .authenticate_keyboard_interactive_respond(answers)
                    .await
                    .map_err(|_| SshError::Connect)?;
            }
        }
    }

    Ok(false)
}

/// Open a verified SSH session and a loopback listener that forwards into it.
///
/// Order of operations, each independently bounded and reported:
///   1. parse the local credential (no network);
///   2. connect and pin the host key (mismatch is fatal and never retried);
///   3. authenticate;
///   4. prove the SSH server can reach the database address;
///   5. bind the loopback listener and start forwarding.
pub async fn open_tunnel(request: SshRequest) -> Result<SshTunnel, SshError> {
    // A key that cannot be parsed, or a wrong passphrase, is a local problem
    // and must not cost a network attempt.
    let credential = match request.credential {
        SshCredential::Password(password) => PreparedCredential::Password(password),
        SshCredential::PrivateKey { key, passphrase } => {
            let pair = russh::keys::decode_secret_key(
                key.as_str(),
                passphrase.as_ref().map(|value| value.as_str()),
            )
            .map_err(|_| SshError::BadCredential)?;
            PreparedCredential::PrivateKey(Arc::new(pair))
        }
    };

    let seen = Arc::new(Mutex::new(None));
    let handler = TofuHandler {
        expected: Some(request.expected_host_key.clone()),
        seen: seen.clone(),
    };

    let mut handle = connect(&request.ssh_host, request.ssh_port, handler).await?;

    // Belt and braces: the handler has already enforced this, but re-check the
    // recorded fingerprint before any credential is allowed near the session.
    let presented = seen
        .lock()
        .ok()
        .and_then(|slot| slot.clone())
        .ok_or(SshError::Protocol)?;

    if presented.fingerprint != request.expected_host_key {
        let _ = handle
            .disconnect(russh::Disconnect::ByApplication, "host key mismatch", "")
            .await;
        return Err(SshError::HostKeyMismatch { presented });
    }

    let user = request.ssh_username.clone();
    let accepted = tokio::time::timeout(SSH_AUTH_TIMEOUT, async {
        match &credential {
            PreparedCredential::Password(password) => {
                sign_in_with_password(&mut handle, user.as_str(), password.as_str()).await
            }
            PreparedCredential::PrivateKey(pair) => handle
                .authenticate_publickey(user.as_str(), pair.clone())
                .await
                .map_err(|_| SshError::Connect),
        }
    })
    .await
    .map_err(|_| SshError::Connect)??;

    if !accepted {
        let _ = handle
            .disconnect(russh::Disconnect::ByApplication, "sign-in rejected", "")
            .await;
        return Err(SshError::AuthRejected);
    }

    // Pre-flight: prove the SSH server can reach the database address before a
    // database driver is pointed at this tunnel. OpenSSH reports a connect
    // failure (or a forbidden target) at channel-open time, which yields the
    // precise "tunnel refused" stage error instead of a vague driver error.
    let preflight = tokio::time::timeout(
        SSH_CHANNEL_TIMEOUT,
        handle.channel_open_direct_tcpip(
            request.database_host.as_str(),
            u32::from(request.database_port),
            "127.0.0.1",
            0,
        ),
    )
    .await;

    let refusal = match preflight {
Ok(Ok(channel)) => {
            // The proof we wanted is already given: the server accepted the
            // forward. A database server will never send EOF - it sends a
            // greeting and waits for us - so waiting for EOF here would hold
            // this throwaway connection open until the SSH idle timeout and
            // leave a dangling session consuming a connection slot on the
            // host. Closing immediately lets the far end clean up now.
            let _ = channel.close().await;
            None
        }
        // A server with forwarding turned off rejects the channel as
        // administratively prohibited, which is a different problem from a
        // database address the server cannot reach, and needs a different fix.
        Ok(Err(russh::Error::ChannelOpenFailure(
            russh::ChannelOpenFailure::AdministrativelyProhibited,
        ))) => Some(SshError::TunnelNotPermitted),
        Ok(Err(_)) => Some(SshError::ChannelRefused),
        Err(_) => Some(SshError::Connect),
    };

    if let Some(err) = refusal {
        let _ = handle
            .disconnect(russh::Disconnect::ByApplication, "channel refused", "")
            .await;
        return Err(err);
    }

    // Loopback only: an ephemeral port on 127.0.0.1, never 0.0.0.0.
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(|_| SshError::Protocol)?;

    let local_port = listener
        .local_addr()
        .map_err(|_| SshError::Protocol)?
        .port();

    if local_port == 0 {
        return Err(SshError::Protocol);
    }

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    tauri::async_runtime::spawn(accept_connections(
        listener,
        shutdown_rx,
        handle,
        request.database_host,
        request.database_port,
    ));

    Ok(SshTunnel {
        local_port,
        host_key: presented,
        shutdown: shutdown_tx,
    })
}

/// Accept loop for the loopback listener.
///
/// Owns the session handle exclusively (`russh`'s handle is not `Sync`), so
/// each forwarding task receives only a confirmed channel. The loop ends when
/// the owning [`SshTunnel`] is dropped, when the listener fails, or when the
/// SSH session is already closed; the session is then disconnected explicitly.
async fn accept_connections(
    listener: tokio::net::TcpListener,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
    handle: Handle<TofuHandler>,
    database_host: String,
    database_port: u16,
) {
    loop {
        tokio::select! {
            // Resolves with `Err` when the owning `SshTunnel` is dropped.
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let (mut socket, peer) = match accepted {
                    Ok(value) => value,
                    Err(_) => break,
                };

                // The listener is bound to loopback; this is belt and braces.
                if !peer.ip().is_loopback() {
                    continue;
                }

                if handle.is_closed() {
                    break;
                }

                match handle
                    .channel_open_direct_tcpip(
                        database_host.as_str(),
                        u32::from(database_port),
                        "127.0.0.1",
                        0,
                    )
                    .await
                {
                    Ok(channel) => {
                        let mut forwarded = channel.into_stream();
                        tauri::async_runtime::spawn(async move {
                            let _ = tokio::io::copy_bidirectional(&mut socket, &mut forwarded)
                                .await;
                        });
                    }
                    // Dropping the socket ends the driver's connection, which
                    // reports its own bounded, sanitised error.
                    Err(_) => {}
                }
            }
        }
    }

    let _ = handle
        .disconnect(russh::Disconnect::ByApplication, "tunnel closed", "")
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A public key from the `russh_keys::parse_public_key_base64` doc example.
    /// Public data; used only to exercise the policy logic.
    const TEST_KEY: &str =
        "AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ";

    fn test_public_key() -> PublicKey {
        russh::keys::parse_public_key_base64(TEST_KEY).expect("fixture key must parse")
    }

    fn handler_for(expected: Option<String>) -> (TofuHandler, Arc<Mutex<Option<HostKeyInfo>>>) {
        let seen = Arc::new(Mutex::new(None));
        (
            TofuHandler {
                expected,
                seen: seen.clone(),
            },
            seen,
        )
    }

    #[test]
    fn probe_mode_accepts_and_records_the_presented_key() {
        let (mut handler, seen) = handler_for(None);
        let accepted = tauri::async_runtime::block_on(handler.check_server_key(&test_public_key()))
            .expect("probe mode must not error");

        assert!(accepted, "probe mode accepts in order to read the key");
        let recorded = seen.lock().unwrap().clone().expect("key must be recorded");
        assert_eq!(recorded.fingerprint, test_public_key().fingerprint());
        assert_eq!(recorded.key_type, "ssh-ed25519");
    }

    #[test]
    fn a_matching_fingerprint_is_accepted() {
        let (mut handler, _) = handler_for(Some(test_public_key().fingerprint()));
        let accepted = tauri::async_runtime::block_on(handler.check_server_key(&test_public_key()))
            .expect("a pinned key that matches must be accepted");
        assert!(accepted);
    }

    #[test]
    fn a_different_fingerprint_is_rejected_with_the_presented_key() {
        let (mut handler, seen) = handler_for(Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()));
        let outcome = tauri::async_runtime::block_on(handler.check_server_key(&test_public_key()));

        match outcome {
            Err(TofuError::HostKeyRejected(info)) => {
                assert_eq!(info.fingerprint, test_public_key().fingerprint());
            }
            other => panic!("expected a host key rejection, got {other:?}"),
        }

        // The presented key is still recorded so the UI can offer a careful
        // re-verification after the incident.
        assert!(seen.lock().unwrap().is_some());
    }

    #[test]
    fn error_codes_and_messages_are_fixed_and_safe() {
        let cases = [
            SshError::Connect,
            SshError::HostKeyMismatch {
                presented: HostKeyInfo {
                    key_type: "ssh-ed25519".into(),
                    fingerprint: "fingerprint".into(),
                },
            },
            SshError::AuthRejected,
            SshError::BadCredential,
            SshError::TunnelNotPermitted,
            SshError::ChannelRefused,
            SshError::Protocol,
        ];

        for err in cases {
            let message = err.user_message();
            assert!(!message.is_empty());
            assert!(
                message.chars().all(|c| !c.is_control()),
                "messages must be plain single-line text"
            );
            assert!(err.code().starts_with("ssh_"), "code: {}", err.code());
        }
    }

    #[test]
    fn credentials_never_render_their_secret() {
        let credential = SshCredential::PrivateKey {
            key: Zeroizing::new("-----BEGIN OPENSSH PRIVATE KEY-----secret".to_string()),
            passphrase: Some(Zeroizing::new("hunter2-do-not-log".to_string())),
        };

        let rendered = format!("{credential:?}");
        assert!(!rendered.contains("secret"), "secret leaked: {rendered}");
        assert!(!rendered.contains("hunter2-do-not-log"), "secret leaked: {rendered}");
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn requests_never_render_their_secret() {
        let request = SshRequest {
            ssh_host: "ssh.example.com".into(),
            ssh_port: 22,
            ssh_username: "backup".into(),
            credential: SshCredential::Password(Zeroizing::new("s3cr3t-do-not-log".into())),
            expected_host_key: "fingerprint-value".into(),
            database_host: "127.0.0.1".into(),
            database_port: 3306,
        };

        let rendered = format!("{request:?}");
        assert!(!rendered.contains("s3cr3t-do-not-log"), "secret leaked: {rendered}");
        assert!(rendered.contains("<redacted>"));
    }
}

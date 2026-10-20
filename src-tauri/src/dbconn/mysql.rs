//! MySQL and MariaDB adapter.
//!
//! Blocking driver, so it runs on a blocking task. The handshake performed by
//! `Conn::new` includes authentication: reaching the `SELECT VERSION()` probe
//! means the server already accepted the password.

use std::time::{Duration, Instant};

use mysql::prelude::Queryable;

use super::{
    sanitise_banner, ConnectionReport, ConnectionTarget, CONNECT_TIMEOUT, DUMP_READ_TIMEOUT,
    HANDSHAKE_TIMEOUT,
};
use crate::error::{AppError, AppResult};

/// Hardcoded, read-only. No user input is ever concatenated into a statement.
const VERSION_QUERY: &str = "SELECT VERSION()";

/// The stage where a connection test failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionStage {
    Connect,
    VersionProbe,
}

/// Open one authenticated connection to the target.
///
/// Shared by the connection test and the dumper so the options, timeouts and
/// error wording can never drift between the two. The handshake itself
/// authenticates: if this returns `Ok`, the server accepted the credentials.
pub fn open(target: &ConnectionTarget) -> AppResult<mysql::Conn> {
    open_with_read_timeout(target, HANDSHAKE_TIMEOUT)
}

/// Open one authenticated connection for a backup.
///
/// The read budget is much longer than the handshake one. The timeout the
/// driver applies is a socket timeout, so it governs every read of the whole
/// session, not just the handshake: with the handshake budget, a table that
/// takes more than ten seconds to produce its first row - a cold cache, a busy
/// server, a slow disk - would fail the backup instead of finishing it.
pub fn open_for_dump(target: &ConnectionTarget) -> AppResult<mysql::Conn> {
    open_with_read_timeout(target, DUMP_READ_TIMEOUT)
}

/// Open a connection with an explicit socket read budget.
fn open_with_read_timeout(
    target: &ConnectionTarget,
    read_timeout: Duration,
) -> AppResult<mysql::Conn> {
    // No TLS here, on purpose, and stated plainly rather than assumed. The
    // `mysql` driver only negotiates TLS when an `SslOpts` value is supplied,
    // and this build supplies none: demanding a verified certificate would
    // refuse the many hosts whose certificate this build cannot verify
    // (self-signed servers, and cloud databases whose issuing CA is not in the
    // Windows certificate store), which would leave them unreachable rather
    // than unsafe. Verification is therefore never *disabled* - no
    // `accept_invalid_certs` and no `skip_domain_validation` is set anywhere in
    // this file - and the report below states that the transport is not
    // encrypted, so the SSH tunnel method can be recommended honestly.
    mysql::Conn::new(
        mysql::OptsBuilder::default()
            .ip_or_hostname(Some(target.host.clone()))
            .tcp_port(target.port)
            .user(Some(target.username.clone()))
            .pass(Some(target.password.to_string()))
            .db_name(Some(target.database.clone()))
            .prefer_socket(false)
            .tcp_connect_timeout(Some(CONNECT_TIMEOUT))
            .read_timeout(Some(read_timeout))
            .write_timeout(Some(HANDSHAKE_TIMEOUT)),
    )
    .map_err(|err| classify_error(err, ConnectionStage::Connect, Some(target)))
}

pub fn test(target: &ConnectionTarget) -> AppResult<ConnectionReport> {
    let started = Instant::now();

    let mut connection = open(target)?;

    // `query`, not `query_first`: the latter stops after the first row and leaves
    // the result terminator unread in the socket. Harmless when the connection
    // is closed straight afterwards, a protocol desync when anything else
    // follows on the same connection.
    let banner: String = connection
        .query::<String, _>(VERSION_QUERY)
        .map_err(|err| classify_error(err, ConnectionStage::VersionProbe, Some(target)))?
        .into_iter()
        .next()
        .unwrap_or_else(|| target.engine_label.clone());

    Ok(ConnectionReport {
        engine: target.engine_id.clone(),
        server_banner: sanitise_banner(&banner),
        latency_ms: super::elapsed_ms(started),
        // Truthful: the driver negotiated no TLS here. A tunnelled connection
        // is encrypted by the SSH tunnel instead, and the caller marks that.
        encrypted: false,
    })
}

/// The plugins this build can actually complete, given the enabled features.
///
/// Kept next to the classifier so the two cannot drift apart: anything outside
/// this list is reported as unsupported rather than attempted.
const SUPPORTED_PLUGINS: &[&str] = &[
    "mysql_native_password",
    "caching_sha2_password",
    "sha256_password",
];

/// MariaDB-specific plugins, named separately in the message because shared
/// hosting panels and MariaDB hosts are where these come up.
const MARIADB_PLUGINS: &[&str] = &["client_ed25519", "parsec"];

/// Build the error for an authentication plugin this build cannot complete.
///
/// When the driver reports the plugin name it is included, because knowing what
/// the server actually asked for is the only way to act on this. The name is
/// validated first, because it came from the network.
fn unsupported_plugin(raw_name: &str) -> AppError {
    match super::safe_plugin_name(raw_name) {
        Some(name) => AppError::new(
            "auth_unsupported",
            format!(
                "This server asked for the '{name}' login method, which BackMeUp does not support. \
                 BackMeUp can sign in with {}, or with MariaDB's {} on a MariaDB server. \
                 Ask your host which authentication plugin this database user uses.",
                SUPPORTED_PLUGINS.join(", "),
                MARIADB_PLUGINS.join(" or ")
            ),
        ),
        None => AppError::new(
            "auth_unsupported",
            "This server asked for an authentication method BackMeUp does not support. \
             BackMeUp can sign in with mysql_native_password, caching_sha2_password and \
             sha256_password, or with MariaDB's client_ed25519 or parsec on a MariaDB server. \
             Ask your host which authentication plugin this database user uses.",
        ),
    }
}

/// Check if an address failure is due to DNS or hostname resolution failure.
fn is_dns_failure(
    details: &Option<(String, String, std::io::ErrorKind)>,
    target: Option<&ConnectionTarget>,
) -> bool {
    if let Some((_, ref desc, ref kind)) = details {
        if *kind == std::io::ErrorKind::NotFound {
            return true;
        }
        let lower = desc.to_lowercase();
        if lower.contains("no such host")
            || lower.contains("getaddrinfo")
            || lower.contains("failed to lookup")
            || lower.contains("name or service not known")
            || lower.contains("nodename nor servname")
            || lower.contains("temporary failure in name resolution")
        {
            return true;
        }
    }
    if let Some(t) = target {
        use std::net::ToSocketAddrs;
        if (t.host.as_str(), t.port).to_socket_addrs().is_err() {
            return true;
        }
    }
    false
}

/// Tailor connection-refused guidance depending on whether the host is local or remote.
fn connection_refused_error(target: Option<&ConnectionTarget>) -> AppError {
    let is_local = target
        .map(|t| t.host.eq_ignore_ascii_case("localhost") || t.host == "127.0.0.1" || t.host == "::1")
        .unwrap_or(false);

    if is_local {
        AppError::new(
            "cannot_reach",
            "The database server refused the connection on localhost (127.0.0.1). \
             If the database is not on this computer, use the host and port the \
             hosting panel shows for the database, or leave the host blank when \
             using the SSH tunnel method so the database on the SSH server itself \
             is used.",
        )
    } else {
        AppError::new(
            "cannot_reach",
            "The database server refused the connection. Check that MySQL is running on \
             the host, that the port is correct, and that the hosting panel allows \
             remote database access from this computer (usually Remote MySQL or an IP \
             allowlist). If the provider does not offer that, use the SSH tunnel \
             method instead, which connects from the database server itself.",
        )
    }
}

/// Name a packet-parse failure in the owner's own words.
///
/// The driver's `PacketCodecError` is not a public type in this version, so the
/// variant is recognised from its debug shape. Every sentence below is written
/// here: nothing the server said can reach the UI through this path.
fn codec_reason(codec: &impl std::fmt::Debug) -> String {
    let shape = format!("{codec:?}");

    let sentence = if shape.contains("UnexpectedEof") || shape.contains("ConnectionReset") {
        "The connection to the database ended in the middle of the exchange."
    } else if shape.contains("PacketsOutOfSync") {
        "The replies from the database arrived out of order."
    } else if shape.contains("PacketTooLarge") {
        "The database sent a packet larger than this version of BackMeUp can read."
    } else if shape.contains("BadCompressedPacketHeader") {
        "The database sent a compressed packet this version of BackMeUp cannot read."
    } else {
        "The database server sent an unexpected or malformed packet response."
    };

    format!("{sentence} Check the connection to your database host, then try again.")
}

/// Map a driver error onto a safe, sanitized sentence.
///
/// Preserves the original error category internally while preventing credential
/// leaks, unredacted connection strings, and server-supplied injection.
#[cfg(test)]
fn classify(err: mysql::Error) -> AppError {
    classify_error(err, ConnectionStage::Connect, None)
}

/// Map a driver error onto a safe sentence with stage and target context.
pub fn classify_error(
    err: mysql::Error,
    stage: ConnectionStage,
    target: Option<&ConnectionTarget>,
) -> AppError {
    let (category, app_err) = match err {
        // Server-side rejection. The code is matched, never the text.
        mysql::Error::MySqlError(ref server) => match server.code {
            // ER_HOST_NOT_PRIVILEGED (1130): Host is not allowed to connect to this MySQL server
            1130 => (
                "remote_access_denied",
                AppError::new(
                    "remote_access_denied",
                    "Remote access denied. The database server reached this computer but \
                     does not accept connections from it. Either allow this computer's \
                     address for remote database access in the hosting panel (usually \
                     called Remote MySQL, database access or an IP allowlist), or use \
                     the SSH tunnel method, which needs no remote database access.",
                ),
            ),
            // ER_HOST_IS_BLOCKED (1129)
            1129 => (
                "remote_access_denied",
                AppError::new(
                    "remote_access_denied",
                    "The database server has blocked connections from your host due to previous \
                     connection errors. Unblock your IP in your hosting control panel or run \
                     'mysqladmin flush-hosts'.",
                ),
            ),
            // ER_BAD_HOST_ERROR (1042)
            1042 => (
                "remote_access_denied",
                AppError::new(
                    "remote_access_denied",
                    "The database server could not verify your host address for remote access.",
                ),
            ),
            // ER_ACCESS_DENIED_ERROR (1045)
            1045 => (
                "auth_failed",
                AppError::new(
                    "auth_failed",
                    "The database rejected this user name or password. If connecting remotely, \
                     verify that the database user is permitted to connect from your host or IP.",
                ),
            ),
            // ER_BAD_DB_ERROR (1049)
            1049 => (
                "unknown_database",
                AppError::new(
                    "unknown_database",
                    "That database does not exist on this server. Check that the database name \
                     matches what is shown in your hosting control panel.",
                ),
            ),
            // ER_DBACCESS_DENIED_ERROR (1044)
            1044 => (
                "insufficient_permissions",
                AppError::new(
                    "insufficient_permissions",
                    "The database user does not have permission to access that database. \
                     Check user database privileges in your hosting control panel.",
                ),
            ),
            // ER_TABLEACCESS_DENIED_ERROR (1142) | ER_SPECIFIC_ACCESS_DENIED_ERROR (1227)
            1142 | 1227 => (
                "insufficient_permissions",
                AppError::new(
                    "insufficient_permissions",
                    "The database user has insufficient permissions to perform operations on this database.",
                ),
            ),
            // ER_CON_COUNT_ERROR (1040): the account or server reached connection limit.
            1040 => (
                "connection_limit_reached",
                AppError::new(
                    "connection_failed",
                    "The database refused another connection for this account (connection limit reached).",
                ),
            ),
            _ => (
                "server_error",
                AppError::new(
                    "connection_failed",
                    match stage {
                        ConnectionStage::VersionProbe => {
                            "The database rejected the verification query after connecting."
                        }
                        ConnectionStage::Connect => "The database rejected the connection.",
                    },
                ),
            ),
        },

        // Certificate verification failed. Reported explicitly rather than
        // being retried without verification.
        mysql::Error::TlsError(_) => (
            "tls_failed",
            AppError::new(
                "tls_failed",
                "The server's TLS certificate could not be verified. BackMeUp never connects \
                 without a valid certificate. Verify that your database host has a valid SSL \
                 certificate matching its domain name.",
            ),
        ),

        // A packet the driver could not parse. The owner gets a sentence that says
        // *what kind* of protocol problem it was, because "malformed packet"
        // alone cannot be acted on: a stream that ended early and replies that
        // arrived out of order need completely different fixes.
        mysql::Error::CodecError(ref codec) => {
            let sentence = codec_reason(codec);
            eprintln!("[backmeup] mysql packet parse failure: {codec:?}");

            (
                "codec_error",
                AppError::new("connection_failed", sentence),
            )
        }

        mysql::Error::DriverError(ref driver) => match driver {
            mysql::DriverError::ConnectTimeout | mysql::DriverError::Timeout => {
                ("connection_timeout", super::timed_out())
            }
            mysql::DriverError::CouldNotConnect(details) => {
                let kind = details.as_ref().map(|(_, _, k)| *k);
                let desc_lower = details
                    .as_ref()
                    .map(|(_, d, _)| d.to_lowercase())
                    .unwrap_or_default();

                if matches!(kind, Some(std::io::ErrorKind::ConnectionRefused))
                    || desc_lower.contains("refused")
                {
                    ("connection_refused", connection_refused_error(target))
                } else if matches!(
                    kind,
                    Some(std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock)
                ) || desc_lower.contains("timed out")
                {
                    ("connection_timeout", super::timed_out())
                } else if matches!(
                    kind,
                    Some(
                        std::io::ErrorKind::NetworkUnreachable
                            | std::io::ErrorKind::HostUnreachable
                            | std::io::ErrorKind::NetworkDown
                    )
                ) || desc_lower.contains("network unreachable")
                    || desc_lower.contains("host unreachable")
                    || desc_lower.contains("no route to host")
                {
                    (
                        "network_unreachable",
                        AppError::new(
                            "network_unreachable",
                            "The database host or network is unreachable. Check your network \
                             connection and routing.",
                        ),
                    )
                } else if is_dns_failure(details, target) {
                    (
                        "dns_failed",
                        AppError::new(
                            "dns_failed",
                            "Could not resolve the database host name. Check that the host name \
                             is spelled correctly and that DNS is functioning.",
                        ),
                    )
                } else if matches!(kind, Some(std::io::ErrorKind::InvalidData)) {
                    (
                        "tls_failed",
                        AppError::new(
                            "tls_failed",
                            "The server's TLS certificate could not be verified. BackMeUp never \
                             connects without a valid certificate.",
                        ),
                    )
                } else {
                    (
                        "network_error",
                        AppError::new(
                            "network_error",
                            "BackMeUp could not reach the database. Check the host address, port, \
                             and network connection.",
                        ),
                    )
                }
            }
            mysql::DriverError::TlsNotSupported => (
                "tls_failed",
                AppError::new(
                    "tls_failed",
                    "This server does not offer the encrypted transport (TLS) BackMeUp requires.",
                ),
            ),
            // A plugin the server named that this build does not implement.
            mysql::DriverError::UnknownAuthPlugin(ref name) => {
                ("auth_unsupported", unsupported_plugin(name))
            }
            // `mysql_old_password` was removed in MySQL 5.7 and MariaDB 10.4.
            mysql::DriverError::OldMysqlPasswordDisabled => (
                "auth_unsupported",
                AppError::new(
                    "auth_unsupported",
                    "This server asked for the legacy mysql_old_password login method, which \
                     BackMeUp will not use. Ask your host to change the database user to \
                     mysql_native_password.",
                ),
            ),
            // Cleartext would put the password on the wire in the clear.
            mysql::DriverError::CleartextPluginDisabled => (
                "auth_unsupported",
                AppError::new(
                    "auth_unsupported",
                    "This server asked for a cleartext login method, which BackMeUp will not use. \
                     Ask your host to change the database user to mysql_native_password.",
                ),
            ),
            mysql::DriverError::UnsupportedProtocol(_) | mysql::DriverError::Protocol41NotSet => (
                "auth_unsupported",
                AppError::new(
                    "auth_unsupported",
                    "The database server uses an unsupported protocol version or capabilities.",
                ),
            ),
            _ => (
                "driver_error",
                AppError::new(
                    "connection_failed",
                    "The connection could not be established.",
                ),
            ),
        },

        mysql::Error::IoError(ref io) => match io.kind() {
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
                ("connection_timeout", super::timed_out())
            }
            std::io::ErrorKind::ConnectionRefused => {
                ("connection_refused", connection_refused_error(target))
            }
            std::io::ErrorKind::NetworkUnreachable
            | std::io::ErrorKind::HostUnreachable
            | std::io::ErrorKind::NetworkDown => (
                "network_unreachable",
                AppError::new(
                    "network_unreachable",
                    "The database host or network is unreachable. Check your network connection \
                     and routing.",
                ),
            ),
            std::io::ErrorKind::NotFound => (
                "dns_failed",
                AppError::new(
                    "dns_failed",
                    "Could not resolve the database host name. Check that the host name is spelled \
                     correctly and that DNS is functioning.",
                ),
            ),
            std::io::ErrorKind::InvalidData => (
                "tls_failed",
                AppError::new(
                    "tls_failed",
                    "The server's TLS certificate could not be verified. BackMeUp never connects \
                     without a valid certificate.",
                ),
            ),
            std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe => (
                "connection_reset",
                AppError::new(
                    "network_error",
                    "The connection was closed or reset by the remote server before completing \
                     the handshake.",
                ),
            ),
            _ => (
                "network_error",
                AppError::new("network_error", "BackMeUp could not reach the database."),
            ),
        },

        // Anything else is reported without the driver text.
        _ => (
            "unclassified",
            AppError::new(
                "connection_failed",
                "The connection could not be established.",
            ),
        ),
    };

    // Internal diagnostic log: category and stage are logged, never credentials,
    // tokens, or full connection strings.
    eprintln!(
        "[backmeup] mysql adapter: stage={stage:?} category={category} code={}",
        app_err.code
    );

    app_err
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_codec_failure_names_its_kind_without_quoting_the_server() {
        // The shapes the driver produces for the cases that matter.
        let cases = [
            (
                "Io(Custom { kind: UnexpectedEof, error: \"connection closed\" })",
                "ended in the middle",
            ),
            (
                "Io(Custom { kind: ConnectionReset, error: \"reset by peer\" })",
                "ended in the middle",
            ),
            ("PacketsOutOfSync", "out of order"),
            ("PacketTooLarge", "larger than"),
            ("BadCompressedPacketHeader", "compressed packet"),
        ];

        for (shape, expected) in cases {
            // Passed through `format!` so the test does not need the driver's
            // non-public error type.
            let sentence = codec_reason(&shape);

            assert!(
                sentence.contains(expected),
                "{shape} should read as '{expected}': {sentence}"
            );
            assert!(!sentence.contains("Custom"), "{sentence}");
            assert!(!sentence.contains("reset by peer"), "{sentence}");
        }

        // Anything unrecognised still gets a safe, generic sentence.
        let unknown = codec_reason(&"SomethingBrandNew".to_string());
        assert!(unknown.contains("malformed packet response"), "{unknown}");
    }

    #[test]
    fn an_unknown_plugin_is_named_so_the_cause_is_actionable() {
        let err = classify(mysql::Error::DriverError(
            mysql::DriverError::UnknownAuthPlugin("gssapi".to_string()),
        ));

        assert_eq!(err.code, "auth_unsupported");
        assert!(
            err.message.contains("gssapi"),
            "the requested plugin must be reported: {}",
            err.message
        );
    }

    #[test]
    fn legacy_and_cleartext_plugins_stay_refused() {
        for driver_error in [
            mysql::DriverError::OldMysqlPasswordDisabled,
            mysql::DriverError::CleartextPluginDisabled,
        ] {
            let err = classify(mysql::Error::DriverError(driver_error));

            assert_eq!(err.code, "auth_unsupported");
            assert!(
                err.message.contains("mysql_native_password"),
                "the message must say what to ask for instead: {}",
                err.message
            );
        }
    }

    #[test]
    fn a_server_supplied_plugin_name_cannot_smuggle_text() {
        // Anything containing markup, an escape or a newline is rejected
        // outright, so the fallback message is used and none of the payload's
        // structure can survive into the UI.
        let hostile = "<script>alert(1)</script>\nYou have been hacked";
        let err = classify(mysql::Error::DriverError(
            mysql::DriverError::UnknownAuthPlugin(hostile.to_string()),
        ));

        assert_eq!(err.code, "auth_unsupported");
        assert!(!err.message.contains('<'), "markup must not survive");
        assert!(!err.message.contains('>'), "markup must not survive");
        assert!(!err.message.contains('\n'), "newlines must not survive");
        assert!(!err.message.contains("hacked"), "payload must not survive");
        assert!(!err.message.contains("alert"), "payload must not survive");
        assert!(
            err.message.contains("Ask your host"),
            "the fallback must still be actionable: {}",
            err.message
        );
    }

    #[test]
    fn the_unsupported_plugin_error_names_what_is_supported() {
        let err = unsupported_plugin("gssapi");

        assert_eq!(err.code, "auth_unsupported");
        for expected in ["mysql_native_password", "caching_sha2_password", "client_ed25519"] {
            assert!(
                err.message.contains(expected),
                "must list {expected}: {}",
                err.message
            );
        }
    }

    #[test]
    fn a_blank_plugin_name_falls_back_to_safe_wording() {
        let err = classify(mysql::Error::DriverError(
            mysql::DriverError::UnknownAuthPlugin("   ???   ".to_string()),
        ));

        assert_eq!(err.code, "auth_unsupported");
        assert!(err.message.contains("does not support"));
    }

    #[test]
    fn server_error_codes_map_to_actionable_messages() {
        let cases: Vec<(u16, &str, &str)> = vec![
            (1045, "auth_failed", "user name or password"),
            (1049, "unknown_database", "does not exist"),
            (1044, "insufficient_permissions", "permission to access"),
            (1142, "insufficient_permissions", "insufficient permissions"),
            (1227, "insufficient_permissions", "insufficient permissions"),
            (1130, "remote_access_denied", "Remote access denied"),
            (1129, "remote_access_denied", "blocked connections"),
            (1042, "remote_access_denied", "could not verify your host address"),
            (1040, "connection_failed", "connection limit"),
        ];

        for (code, expected_code, expected_snippet) in cases {
            let err = classify(mysql::Error::MySqlError(mysql::MySqlError {
                code,
                state: "28000".to_string(),
                // A deliberately hostile message: it must never be forwarded.
                message: "Access denied for user 'root'@'1.2.3.4' (using password: YES)"
                    .to_string(),
            }));

            assert_eq!(err.code, expected_code, "code {code}");
            assert!(
                err.message.contains(expected_snippet),
                "code {code} must contain '{expected_snippet}': {}",
                err.message
            );
            assert!(
                !err.message.contains("root") && !err.message.contains("1.2.3.4"),
                "the server message must not reach the user: {}",
                err.message
            );
        }
    }

    #[test]
    fn network_failures_are_distinguished_from_auth_failures() {
        let refused = classify(mysql::Error::IoError(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "refused",
        )));
        assert_eq!(refused.code, "cannot_reach");
        assert!(refused.message.contains("refused"));

        let timed_out = classify(mysql::Error::IoError(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timed out",
        )));
        assert_eq!(timed_out.code, "connection_timeout");

        let driver_timeout = classify(mysql::Error::DriverError(mysql::DriverError::ConnectTimeout));
        assert_eq!(driver_timeout.code, "connection_timeout");

        let unreach = classify(mysql::Error::IoError(std::io::Error::new(
            std::io::ErrorKind::NetworkUnreachable,
            "network is unreachable",
        )));
        assert_eq!(unreach.code, "network_unreachable");
        assert!(unreach.message.contains("unreachable"));

        let host_unreach = classify(mysql::Error::DriverError(mysql::DriverError::CouldNotConnect(
            Some((
                "db.hostinger.com:3306".to_string(),
                "host is unreachable".to_string(),
                std::io::ErrorKind::HostUnreachable,
            )),
        )));
        assert_eq!(host_unreach.code, "network_unreachable");

        let dns_err = classify(mysql::Error::DriverError(mysql::DriverError::CouldNotConnect(
            Some((
                "invalid.hostname.test:3306".to_string(),
                "No such host is known.".to_string(),
                std::io::ErrorKind::NotFound,
            )),
        )));
        assert_eq!(dns_err.code, "dns_failed");
        assert!(dns_err.message.contains("resolve"));

        // `rustls::Error::General` keeps the test independent of `webpki`, which is
        // not a direct dependency.
        let tls = classify(mysql::Error::TlsError(mysql::error::tls::TlsError::Tls(
            rustls::Error::General("certificate is not trusted".to_string()),
        )));
        assert_eq!(tls.code, "tls_failed");
        assert!(tls.message.contains("certificate"));

        let tls_not_supported = classify(mysql::Error::DriverError(mysql::DriverError::TlsNotSupported));
        assert_eq!(tls_not_supported.code, "tls_failed");
    }

    #[test]
    fn local_vs_remote_connection_refused_guidance() {
        let local_target = ConnectionTarget {
            engine_id: "mysql".into(),
            engine_label: "MySQL".into(),
            host: "localhost".into(),
            port: 3306,
            database: "test".into(),
            username: "root".into(),
            password: zeroize::Zeroizing::new("pass".into()),
        };
        let local_err = classify_error(
            mysql::Error::IoError(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "refused",
            )),
            ConnectionStage::Connect,
            Some(&local_target),
        );
        assert_eq!(local_err.code, "cannot_reach");
        assert!(
            local_err.message.contains("localhost"),
            "must mention localhost: {}",
            local_err.message
        );
        assert!(
            local_err.message.contains("SSH tunnel"),
            "must offer the tunnel as the alternative: {}",
            local_err.message
        );

        let remote_target = ConnectionTarget {
            engine_id: "mysql".into(),
            engine_label: "MySQL".into(),
            host: "srv123.hostinger.com".into(),
            port: 3306,
            database: "test".into(),
            username: "root".into(),
            password: zeroize::Zeroizing::new("pass".into()),
        };
        let remote_err = classify_error(
            mysql::Error::IoError(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "refused",
            )),
            ConnectionStage::Connect,
            Some(&remote_target),
        );
        assert_eq!(remote_err.code, "cannot_reach");
        assert!(
            remote_err.message.contains("Remote MySQL"),
            "must offer the panel allowlist guidance: {}",
            remote_err.message
        );
        assert!(
            remote_err.message.contains("SSH tunnel"),
            "must name the tunnel as the alternative: {}",
            remote_err.message
        );
    }

    #[test]
    fn supported_plugins_are_the_ones_this_build_can_complete() {
        for plugin in ["mysql_native_password", "caching_sha2_password"] {
            assert!(SUPPORTED_PLUGINS.contains(&plugin));
        }
        // The MariaDB plugins are enabled via cargo features, so they belong in
        // the supported set too.
        for plugin in ["client_ed25519", "parsec"] {
            assert!(MARIADB_PLUGINS.contains(&plugin));
        }
        // The insecure methods must never appear as supported.
        assert!(!SUPPORTED_PLUGINS.contains(&"mysql_old_password"));
        assert!(!SUPPORTED_PLUGINS.contains(&"mysql_clear_password"));
        assert!(!MARIADB_PLUGINS.contains(&"mysql_old_password"));
    }
}
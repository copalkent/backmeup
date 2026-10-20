//! Microsoft SQL Server adapter.
//!
//! Tiberius negotiates TDS encryption itself using the Windows certificate
//! store, so the adapter hands it a connected TCP stream (adapted to the
//! `futures-io` traits tiberius expects) and sets `EncryptionLevel::Required`.
//! Certificate verification stays on: `trust.bypass` is never touched, which is
//! tiberius' equivalent of "accept any certificate".

use std::time::Instant;

use tokio_util::compat::TokioAsyncWriteCompatExt;

use super::{sanitise_banner, ConnectionReport, ConnectionTarget, CONNECT_TIMEOUT};
use crate::error::{AppError, AppResult};

pub async fn test(target: &ConnectionTarget) -> AppResult<ConnectionReport> {
    let started = Instant::now();

    // `format!` over a validated host and an integer port cannot produce a
    // connection string with embedded options.
    let address = format!("{}:{}", target.host, target.port);

    let stream = tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(&address))
        .await
        .map_err(|_| super::timed_out())?
        .map_err(classify_io)?;

    let _ = stream.set_nodelay(true);

    let mut config = tiberius::Config::new();
    config.authentication(tiberius::AuthMethod::sql_server(
        &target.username,
        target.password.as_str(),
    ));
    // The whole session is encrypted, not just the login packet.
    config.encryption(tiberius::EncryptionLevel::Required);
    config.database(&target.database);

    // Keep a per-call ceiling so a stalled server cannot outlive the command,
    // independently of whatever tiberius applies internally.
    let client = tokio::time::timeout(
        super::HANDSHAKE_TIMEOUT,
        tiberius::Client::connect(config, stream.compat_write()),
    )
    .await
    .map_err(|_| super::timed_out())?
    .map_err(classify)?;

    drop(client);

    Ok(ConnectionReport {
        engine: target.engine_id.clone(),
        server_banner: sanitise_banner("Encrypted TDS session established"),
        latency_ms: super::elapsed_ms(started),
        encrypted: true,
    })
}

fn classify_io(err: std::io::Error) -> AppError {
    match err.kind() {
        std::io::ErrorKind::TimedOut => super::timed_out(),
        std::io::ErrorKind::ConnectionRefused => AppError::new(
            "cannot_reach",
            "The database refused the connection. Check that SQL Server is running and that the port is correct.",
        ),
        std::io::ErrorKind::NetworkUnreachable | std::io::ErrorKind::HostUnreachable => {
            AppError::new(
                "network_unreachable",
                "The database host or network is unreachable. Check your network connection and routing.",
            )
        }
        std::io::ErrorKind::NotFound => AppError::new(
            "dns_failed",
            "Could not resolve the database host name. Check that the host name is spelled correctly and that DNS is functioning.",
        ),
        _ => AppError::new("network_error", "BackMeUp could not reach the database."),
    }
}

/// Map a driver error onto a safe sentence.
///
/// Only the numeric server code is inspected; the server's message text can
/// echo connection details and is never forwarded.
fn classify(err: tiberius::error::Error) -> AppError {
    if let Some(code) = err.code() {
        match code {
            // 18456 login failed, 18452 server is in single-user mode.
            18456 | 18452 => {
                return AppError::new(
                    "auth_failed",
                    "The database rejected this user name or password.",
                )
            }
            // 4060 cannot open the database requested by the login.
            4060 => {
                return AppError::new(
                    "unknown_database",
                    "That database does not exist on this server.",
                )
            }
            _ => {
                return AppError::new(
                    "connection_failed",
                    "The database rejected the connection.",
                )
            }
        }
    }

    match err {
        tiberius::error::Error::Tls(_) => AppError::new(
            "tls_failed",
            "The server's TLS certificate could not be verified. BackMeUp never connects without a valid certificate.",
        ),
        tiberius::error::Error::Io { kind, .. } => match kind {
            std::io::ErrorKind::TimedOut => super::timed_out(),
            std::io::ErrorKind::ConnectionRefused => AppError::new(
                "cannot_reach",
                "The database refused the connection. Check that it is running and that the port is correct.",
            ),
            std::io::ErrorKind::NetworkUnreachable | std::io::ErrorKind::HostUnreachable => {
                AppError::new(
                    "network_unreachable",
                    "The database host or network is unreachable. Check your network connection and routing.",
                )
            }
            std::io::ErrorKind::NotFound => AppError::new(
                "dns_failed",
                "Could not resolve the database host name. Check that the host name is spelled correctly and that DNS is functioning.",
            ),
            // A certificate that fails verification surfaces as invalid data.
            std::io::ErrorKind::InvalidData => AppError::new(
                "tls_failed",
                "The server's TLS certificate could not be verified. BackMeUp never connects without a valid certificate.",
            ),
            _ => AppError::new("network_error", "BackMeUp could not reach the database."),
        },
        // SQL Server asks the client to follow a redirect during login. That
        // is not honoured: it is an open-redirect vector and BackMeUp only
        // ever connects to the configured address.
        tiberius::error::Error::Routing { .. } => AppError::new(
            "routing_refused",
            "The server asked BackMeUp to follow a different address, which it will not do.",
        ),
        other => {
            // Only the variant category is logged. The payload is not
            // forwarded: tiberius embeds server-supplied text in it, which
            // would let a hostile server forge log lines.
            let category = match other {
                tiberius::error::Error::Protocol(_) => "protocol",
                tiberius::error::Error::Encoding(_) => "encoding",
                tiberius::error::Error::Conversion(_) => "conversion",
                tiberius::error::Error::Utf8 | tiberius::error::Error::Utf16 => "encoding",
                tiberius::error::Error::ParseInt(_) => "parse",
                tiberius::error::Error::BulkInput(_) => "bulk",
                _ => "other",
            };
            eprintln!(
                "[backmeup] sqlserver adapter error: unclassified ({category})"
            );
            AppError::new(
                "connection_failed",
                "The connection could not be established.",
            )
        }
    }
}
//! PostgreSQL adapter.
//!
//! `postgres::Config::connect` drives its own runtime and therefore blocks, so
//! it runs on a blocking task. TLS is mandatory: `SslMode::Require` combined
//! with `MakeRustlsConnect` means rustls verifies the server chain and the
//! hostname against the Windows certificate store. Plaintext is never
//! negotiated, and the driver's permissive `Prefer` default is not used.

use std::sync::Arc;
use std::time::Instant;

use super::{sanitise_banner, ConnectionReport, ConnectionTarget, CONNECT_TIMEOUT};
use crate::error::{AppError, AppResult};

/// Hardcoded, read-only. No user input reaches a statement.
const VERSION_QUERY: &str = "SELECT version()";

pub fn test(target: &ConnectionTarget) -> AppResult<ConnectionReport> {
    let started = Instant::now();

    let tls = rustls_client_config()?;

    let mut config = postgres::Config::new();
    config
        .host(&target.host)
        .port(target.port)
        .user(&target.username)
        .password(target.password.as_str())
        .dbname(&target.database)
        .application_name("BackMeUp")
        .connect_timeout(CONNECT_TIMEOUT);

    // `Require` means "TLS only". Together with the rustls connector below the
    // certificate is fully verified.
    config.ssl_mode(tokio_postgres::config::SslMode::Require);

    let mut client = config
        .connect(tokio_postgres_rustls::MakeRustlsConnect::new(tls))
        .map_err(classify)?;

    // The startup exchange already proved the credentials were accepted.
    let banner = client
        .simple_query(VERSION_QUERY)
        .map_err(classify)?
        .into_iter()
        .find_map(|message| match message {
            postgres::SimpleQueryMessage::Row(row) => row.get(0).map(str::to_string),
            _ => None,
        })
        .unwrap_or_else(|| target.engine_label.clone());

    Ok(ConnectionReport {
        engine: target.engine_id.clone(),
        server_banner: sanitise_banner(&banner),
        latency_ms: super::elapsed_ms(started),
        encrypted: true,
    })
}

/// Trust anchors from the Windows certificate store.
///
/// The config is built with an explicit crypto provider so it never depends on
/// a process-wide default having been installed.
pub(crate) fn rustls_client_config() -> AppResult<rustls::ClientConfig> {
    let loaded = rustls_native_certs::load_native_certs();

    let mut roots = rustls::RootCertStore::empty();
    for certificate in loaded.certs {
        roots.add(certificate).map_err(|_| trust_store_error())?;
    }

    // A machine with an empty or unreadable root store cannot verify anything.
    // Failing closed is the point: refusing is better than connecting without
    // verifying the server.
    if roots.is_empty() {
        return Err(trust_store_error());
    }

    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| trust_store_error())?
    .with_root_certificates(roots)
    .with_no_client_auth();

    // `with_no_client_auth` yields the finished config directly.
    Ok(config)
}

fn trust_store_error() -> AppError {
    AppError::new(
        "tls_failed",
        "BackMeUp could not read the trusted certificate store on this computer, so it cannot verify a secure connection.",
    )
}

/// Map a driver error onto a safe sentence.
///
/// `tokio_postgres::error::Error` is a newtype over the real cause, so the
/// class is recovered through its public accessors rather than by matching a
/// variant.
fn classify(err: postgres::Error) -> AppError {
    if let Some(db) = err.as_db_error() {
        // SQLSTATE class 28 is "invalid authorization specification": a wrong
        // password, or a user that may not log in.
        let sqlstate = db.code().code();

        if sqlstate.starts_with("28") {
            return AppError::new(
                "auth_failed",
                "The database rejected this user name or password.",
            );
        }
        // 3D000 is "invalid_catalog_name".
        if sqlstate.starts_with("3D") {
            return AppError::new(
                "unknown_database",
                "That database does not exist on this server.",
            );
        }

        return AppError::new(
            "connection_failed",
            "The database rejected the connection.",
        );
    }

    let source = err.into_source();

    if let Some(io) = source.as_ref().and_then(|e| e.downcast_ref::<std::io::Error>()) {
        return match io.kind() {
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => super::timed_out(),
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
            // rustls reports a certificate that fails verification as invalid
            // input data.
            std::io::ErrorKind::InvalidData => AppError::new(
                "tls_failed",
                "The server's TLS certificate could not be verified. BackMeUp never connects without a valid certificate.",
            ),
            _ => AppError::new("network_error", "BackMeUp could not reach the database."),
        };
    }

    // Only the fact that a failure occurred is logged. The driver's payload is
    // deliberately not forwarded: it can embed server-supplied text, which
    // would let a hostile server forge log lines, and it can echo connection
    // details.
    eprintln!("[backmeup] postgres adapter error: unclassified");
    AppError::new(
        "connection_failed",
        "The connection could not be established.",
    )
}
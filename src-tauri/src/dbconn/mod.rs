//! Database connection adapters.
//!
//! This module tree is the **only** place in BackMeUp allowed to open a socket
//! to a database or to read a stored password. Each engine lives in its own
//! file behind the same internal call signature, so supporting another engine
//! means adding one file and one match arm - never changing the screens, the
//! storage layer or the destination code.
//!
//! Guarantees that hold for every adapter:
//!   * Connecting performs authentication. A connection is reported as
//!     successful only after the server has accepted the credentials.
//!   * The only statement ever issued is a hardcoded, read-only version probe.
//!     No user input reaches a query, so a connection test cannot be turned
//!     into arbitrary SQL.
//!   * Transport security is stated honestly and never silently weakened.
//!     PostgreSQL and SQL Server run over TLS with the server certificate
//!     fully verified, and no adapter ever sets `accept_invalid_certs`,
//!     `skip_domain_validation` or tiberius' `trust.bypass`. The MySQL driver
//!     negotiates no TLS (see that adapter for why), so a direct MySQL
//!     connection reports `encrypted: false` rather than claiming protection
//!     it does not have; an SSH-tunnelled connection is encrypted by the
//!     tunnel and is reported as such.
//!   * Every stage is bounded by a timeout so the UI can never hang.
//!   * Driver errors are mapped to short, safe sentences. Connection strings,
//!     hostnames, user names and passwords never reach the UI or the log.

mod postgres;
mod sqlserver;
// Visible to the dumper, which reuses this module's safe error mapping so a
// backup failure reads exactly like a connection failure.
pub(crate) mod mysql;

use std::time::{Duration, Instant};

use serde::Serialize;
use zeroize::Zeroizing;

use crate::error::{AppError, AppResult};

/// TCP connect budget.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
/// TLS handshake and authentication budget.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Socket read budget while a backup is running.
///
/// A table read can legitimately pause for minutes: a cold cache, a busy
/// server, a wide table. The handshake budget is right for a connection test
/// and wrong for a backup, so a dump gets its own.
pub const DUMP_READ_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// Hard ceiling for a whole test, including the read-only version probe.
pub const TOTAL_TIMEOUT: Duration = Duration::from_secs(20);

/// Longest server banner echoed back to the UI.
const MAX_BANNER_LEN: usize = 64;

/// Everything needed to open one connection, already validated and resolved.
///
/// `password` is wrapped in [`Zeroizing`] so it is wiped as soon as the adapter
/// returns, and the type is `Send` so it can cross into a blocking task.
#[derive(Clone)]
pub struct ConnectionTarget {
    pub engine_id: String,
    pub engine_label: String,
    /// A hostname or IP literal, or a loopback address for a local connection.
    pub host: String,
    pub port: u16,
    pub database: String,
    pub username: String,
    pub password: Zeroizing<String>,
}

impl std::fmt::Debug for ConnectionTarget {
    /// Never renders the password. This exists so a target can be logged or
    /// surfaced in a panic message without leaking the secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionTarget")
            .field("engine", &self.engine_id)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("database", &self.database)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// What a successful connection test learned. Deliberately small: the UI must
/// never receive anything that could describe the server's internals.
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionReport {
    pub engine: String,
    /// Server banner, truncated and stripped of control characters.
    pub server_banner: String,
    pub latency_ms: u128,
    /// Whether the transport was encrypted: TLS for PostgreSQL and SQL
    /// Server, the SSH tunnel itself for a tunnelled connection. A direct
    /// MySQL connection is `false`, because the driver negotiates no TLS.
    pub encrypted: bool,
}

/// Attempt one real connection.
///
/// The engine is dispatched from the fixed registry, so an unknown id can never
/// silently fall back to another engine or connection method.
pub async fn test(target: ConnectionTarget) -> AppResult<ConnectionReport> {
    match target.engine_id.as_str() {
        // MariaDB speaks the MySQL wire protocol; the same adapter handles it.
        "mysql" | "mariadb" => run_mysql(target).await,
        "postgresql" => run_postgres(target).await,
        "sqlserver" => run_sqlserver(target).await,
        other => Err(AppError::new(
            "engine_unsupported",
            format!("BackMeUp has no connection support for {other} in this version."),
        )),
    }
}

async fn run_mysql(target: ConnectionTarget) -> AppResult<ConnectionReport> {
    let handle = tauri::async_runtime::spawn_blocking(move || mysql::test(&target));

    // A hard ceiling so a blocked or slow network operation cannot hang the UI indefinitely.
    let outcome = tokio::time::timeout(TOTAL_TIMEOUT, handle)
        .await
        .map_err(|_| timed_out())?
        .map_err(|_| AppError::internal())?;
    outcome
}

async fn run_postgres(target: ConnectionTarget) -> AppResult<ConnectionReport> {
    // `postgres::Config::connect` drives its own runtime and therefore blocks.
    let handle = tauri::async_runtime::spawn_blocking(move || postgres::test(&target));

    let outcome = tokio::time::timeout(TOTAL_TIMEOUT, handle)
        .await
        .map_err(|_| timed_out())?
        .map_err(|_| AppError::internal())?;
    outcome
}

async fn run_sqlserver(target: ConnectionTarget) -> AppResult<ConnectionReport> {
    tokio::time::timeout(TOTAL_TIMEOUT, sqlserver::test(&target))
        .await
        .map_err(|_| timed_out())?
}

/// A hard timeout is reported identically regardless of which stage stalled, so
/// a slow host cannot be distinguished from a hung one.
pub fn timed_out() -> AppError {
    AppError::new(
        "connection_timeout",
        "BackMeUp stopped waiting for the database. Check the host and port, then try again.",
    )
}

/// True when an engine id has a real adapter in this build.
///
/// The UI uses this so it never offers an engine that cannot connect.
pub fn engine_supported(engine_id: &str) -> bool {
    matches!(engine_id, "mysql" | "mariadb" | "postgresql" | "sqlserver")
}

/// Normalise a server banner for display: control characters stripped and the
/// result bounded, so a hostile server cannot inject terminal escapes or blow
/// out the layout.
pub(crate) fn sanitise_banner(raw: &str) -> String {
    let cleaned: String = raw
        .trim()
        .chars()
        .filter(|c| !c.is_control() && *c != '\u{7f}')
        .take(MAX_BANNER_LEN)
        .collect();

    if cleaned.is_empty() {
        "Unknown".to_string()
    } else {
        cleaned
    }
}

/// Elapsed milliseconds, used to report how long a successful test took.
pub(crate) fn elapsed_ms(started: Instant) -> u128 {
    started.elapsed().as_millis()
}

/// Longest authentication-plugin name echoed back in an error.
const MAX_PLUGIN_NAME_LEN: usize = 40;

/// Accept a server-supplied authentication-plugin name for display.
///
/// This validates rather than sanitises: the value must *entirely* match the
/// shape of a MySQL plugin identifier (`[A-Za-z_][A-Za-z0-9_-]*`), bounded in
/// length. Anything else is rejected outright and the caller falls back to
/// wording that names no plugin.
///
/// Stripping disallowed characters instead would be unsound - an attacker
/// could reassemble a misleading sentence out of the surviving letters, since
/// "scriptalert(1)script" contains nothing outside the allowlist once the
/// punctuation is removed. Rejecting the whole value removes that risk and
/// cannot reject a real plugin, since MySQL and MariaDB both name plugins with
/// exactly this shape.
pub(crate) fn safe_plugin_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim_matches(|c: char| c.is_ascii_whitespace() || c == '\0');

    if trimmed.is_empty() || trimmed.len() > MAX_PLUGIN_NAME_LEN {
        return None;
    }

    let mut chars = trimmed.chars();
    let first = chars.next()?;

    if !(first.is_ascii_alphabetic() || first == '_') {
        return None;
    }

    if !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-')) {
        return None;
    }

    Some(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_engines_with_a_real_adapter_are_supported() {
        assert!(engine_supported("mysql"));
        assert!(engine_supported("mariadb"));
        assert!(engine_supported("postgresql"));
        assert!(engine_supported("sqlserver"));

        for bogus in ["sqlite", "oracle", "mongodb", "", "MySQL"] {
            assert!(
                !engine_supported(bogus),
                "must not claim support for {bogus:?}"
            );
        }
    }

    #[test]
    fn banners_are_stripped_and_bounded() {
        assert_eq!(sanitise_banner("  8.0.36  \n"), "8.0.36");
        assert_eq!(sanitise_banner("\u{1b}[31mred\u{7f}"), "[31mred");
        assert_eq!(sanitise_banner(""), "Unknown");
        assert_eq!(sanitise_banner("\n\t"), "Unknown");
        assert_eq!(sanitise_banner(&"9".repeat(500)).len(), MAX_BANNER_LEN);
    }

    #[test]
    fn plugin_names_must_be_a_plain_identifier_or_nothing_at_all() {
        // Real plugin names are accepted verbatim.
        for good in [
            "gssapi",
            "mysql_native_password",
            "caching_sha2_password",
            "sha256_password",
            "client_ed25519",
            "parsec",
            "authentication_kerberos_client",
            "sha256-password",
            "_internal",
        ] {
            assert_eq!(
                super::safe_plugin_name(good).as_deref(),
                Some(good),
                "{good} should be reported"
            );
        }

        // Surrounding whitespace and NUL padding (as sent on the wire) are
        // trimmed, not rejected.
        assert_eq!(
            super::safe_plugin_name("  mysql_native_password\0").as_deref(),
            Some("mysql_native_password")
        );

        // A payload containing ANY character outside the allowlist is rejected
        // wholesale. This is what stops markup, terminal escapes and
        // sentence injection: none of those characters can survive.
        for hostile in [
            "<script>alert(1)</script>",
            "\u{1b}[31mred",
            "gssapi\r\nIgnored: this host is trusted",
            "gss api",
            "gssapi/../etc",
            "gssapi;drop",
            "1plugin",
            "",
            "   ",
            "\u{0}\u{0}",
        ] {
            assert_eq!(
                super::safe_plugin_name(hostile),
                None,
                "{hostile:?} must not be reported"
            );
        }

        // A value made only of allowed characters is a syntactically valid
        // identifier even when it is nonsense. That is acceptable: it cannot
        // introduce markup, an escape, a newline or a second sentence - it can
        // only appear as one quoted, single-line, length-bounded token.
        let nonsense = super::safe_plugin_name("scriptalert1scriptYouhavebeenhacked");
        if let Some(name) = nonsense {
            assert!(name.len() <= super::MAX_PLUGIN_NAME_LEN);
            assert!(name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'));
            assert!(!name.contains(char::is_whitespace));
        }

        assert_eq!(super::safe_plugin_name(&"a".repeat(41)), None, "bounded");
        assert_eq!(
            super::safe_plugin_name(&"a".repeat(40)).map(|s| s.len()),
            Some(40)
        );
    }

#[test]
    fn target_debug_never_prints_the_password() {
        let target = ConnectionTarget {
            engine_id: "mysql".into(),
            engine_label: "MySQL".into(),
            host: "db.example.com".into(),
            port: 3306,
            database: "shop".into(),
            username: "backup".into(),
            password: Zeroizing::new("hunter2-do-not-log".into()),
        };

        let rendered = format!("{target:?}");
        assert!(!rendered.contains("hunter2-do-not-log"), "secret leaked: {rendered}");
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn an_unknown_engine_is_refused_rather_than_defaulted() {
        let target = ConnectionTarget {
            engine_id: "sqlite".into(),
            engine_label: "SQLite".into(),
            host: "127.0.0.1".into(),
            port: 0,
            database: "x".into(),
            username: "x".into(),
            password: Zeroizing::new(String::new()),
        };

        let outcome = tauri::async_runtime::block_on(test(target));
        let err = outcome.expect_err("an unknown engine must not be dialled");
        assert_eq!(err.code, "engine_unsupported");
    }
}
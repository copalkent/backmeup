//! Database engine registry.
//!
//! An engine here is nothing more than a *connection preset*: how a server is
//! addressed and what the sensible defaults are. No driver, client library,
//! query, dump format or backup logic lives in this module, and nothing here
//! opens a network connection.
//!
//! This is the seam that keeps BackMeUp engine-agnostic. Supporting another
//! engine is a matter of adding an entry here plus, in a later phase, a
//! matching adapter behind the backup orchestrator - never a change to the
//! screens, the storage layer or the destination code. No hosting provider is
//! assumed anywhere.

use serde::Serialize;

use crate::error::AppResult;

#[derive(Clone, Copy)]
pub struct Engine {
    pub id: &'static str,
    pub label: &'static str,
    /// Port pre-filled when the owner adds a connection. A suggestion only: the
    /// owner can always change it, and nothing here is ever dialled.
    pub default_port: u16,
    /// False for engines that only ever run on the local machine and therefore
    /// need no host.
    pub supports_host: bool,
    /// Address used for a "This machine" connection.
    ///
    /// Declared per engine rather than assumed to be the same everywhere, so an
    /// engine that is not reached over TCP can carry a different value without
    /// touching any other code.
    pub local_host: &'static str,
    /// Whether this build contains a real adapter for the engine. Kept in step
    /// with `crate::dbconn::engine_supported`.
    pub supported: bool,
    /// Whether this engine may be reached through an SSH tunnel. Only the
    /// MySQL-protocol adapter ships a tunnel-compatible path in this build.
    pub supports_ssh_tunnel: bool,
}

pub const ENGINES: &[Engine] = &[
    Engine {
        id: "mysql",
        label: "MySQL",
        default_port: 3306,
        supports_host: true,
        local_host: "127.0.0.1",
        supported: true,
        supports_ssh_tunnel: true,
    },
    Engine {
        id: "mariadb",
        label: "MariaDB",
        default_port: 3306,
        supports_host: true,
        local_host: "127.0.0.1",
        supported: true,
        supports_ssh_tunnel: true,
    },
    Engine {
        id: "postgresql",
        label: "PostgreSQL",
        default_port: 5432,
        supports_host: true,
        local_host: "127.0.0.1",
        supported: true,
        supports_ssh_tunnel: false,
    },
    Engine {
        id: "sqlserver",
        label: "SQL Server",
        default_port: 1433,
        supports_host: true,
        // SQL Server listens on the loopback interface for its default
        // instance; named instances usually use a dynamic port, which the
        // owner can override.
        local_host: "127.0.0.1",
        supported: true,
        supports_ssh_tunnel: false,
    },
];

/// How BackMeUp reaches the server. Independent of the engine, so a new engine
/// does not require a new set of methods.
#[derive(Clone, Copy)]
pub struct ConnectionMethod {
    pub id: &'static str,
    pub label: &'static str,
    /// True when the server is addressed by host name or IP address.
    pub requires_host: bool,
}

/// The one method id that routes through an SSH session. Referenced by the
/// validation, storage and test paths so the string exists in exactly one
/// place.
pub const SSH_TUNNEL_METHOD_ID: &str = "ssh-tunnel";

pub const CONNECTION_METHODS: &[ConnectionMethod] = &[
    ConnectionMethod {
        id: "direct",
        label: "Direct connection",
        requires_host: true,
    },
    ConnectionMethod {
        id: "local",
        label: "This machine",
        requires_host: false,
    },
    ConnectionMethod {
        id: SSH_TUNNEL_METHOD_ID,
        label: "SSH tunnel",
        // The database address is resolved by the SSH server, so it defaults
        // to the engine's loopback address when the owner leaves it blank.
        requires_host: false,
    },
];

/// Look-up is an exact match against a fixed allowlist. An unknown id is never
/// accepted, so the value stored in the database is always one this build
/// actually knows about.
pub fn find(id: &str) -> Option<&'static Engine> {
    ENGINES.iter().find(|engine| engine.id == id)
}

pub fn find_method(id: &str) -> Option<&'static ConnectionMethod> {
    CONNECTION_METHODS
        .iter()
        .find(|method| method.id == id)
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct EngineView {
    pub id: String,
    pub label: String,
    pub default_port: u16,
    pub supports_host: bool,
    /// Address BackMeUp uses for a "This machine" connection to this engine.
    pub local_host: String,
    /// False when this build has no adapter, so the UI can say so plainly
    /// instead of offering a connection that cannot work.
    pub supported: bool,
    /// Whether the "SSH tunnel" connection method is offered for this engine.
    pub supports_ssh_tunnel: bool,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionMethodView {
    pub id: String,
    pub label: String,
    pub requires_host: bool,
}

/// Everything the "Add database" form needs, so the frontend never hardcodes an
/// engine list or a policy message.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct EngineCatalogue {
    pub engines: Vec<EngineView>,
    pub methods: Vec<ConnectionMethodView>,
    /// True when this build can store credentials in the Windows Credential
    /// Manager. Saving a connection is refused entirely when it is false -
    /// BackMeUp never falls back to weaker storage.
    pub credential_storage_available: bool,
    pub credential_storage_note: String,
}

/// The catalogue the frontend builds its selectors from. Driving these lists
/// from the backend means a new engine needs no frontend change.
#[tauri::command]
pub fn database_engines() -> AppResult<EngineCatalogue> {
    let storage_available = crate::credentials::available();

    Ok(EngineCatalogue {
        engines: ENGINES
            .iter()
            .map(|engine| EngineView {
                id: engine.id.to_string(),
                label: engine.label.to_string(),
                default_port: engine.default_port,
                supports_host: engine.supports_host,
                local_host: engine.local_host.to_string(),
                supported: engine.supported,
                supports_ssh_tunnel: engine.supports_ssh_tunnel,
            })
            .collect(),
        methods: CONNECTION_METHODS
            .iter()
            .map(|method| ConnectionMethodView {
                id: method.id.to_string(),
                label: method.label.to_string(),
                requires_host: method.requires_host,
            })
            .collect(),
        credential_storage_available: storage_available,
        credential_storage_note: crate::databases::CREDENTIAL_STORAGE_NOTE.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookups_only_succeed_for_known_ids() {
        assert!(find("mysql").is_some());
        assert!(find("nonsense").is_none());
        assert!(find("").is_none());
        assert!(find("MySQL").is_none(), "ids are exact and case sensitive");
        assert!(find_method("direct").is_some());
        assert!(find_method("ssh-tunnel").is_some());
        assert!(find_method("http").is_none());
    }

    #[test]
    fn ssh_tunneling_is_offered_only_where_an_adapter_supports_it() {
        for engine in ENGINES {
            if engine.supports_ssh_tunnel {
                assert!(
                    matches!(engine.id, "mysql" | "mariadb"),
                    "{} claims SSH tunnel support without testing it",
                    engine.id
                );
            }
        }

        assert!(find("mysql").unwrap().supports_ssh_tunnel);
        assert!(find("mariadb").unwrap().supports_ssh_tunnel);
        assert!(!find("postgresql").unwrap().supports_ssh_tunnel);
        assert!(!find("sqlserver").unwrap().supports_ssh_tunnel);
    }

    #[test]
    fn engine_ids_and_ports_are_unique_and_sane() {
        let mut ids: Vec<&str> = ENGINES.iter().map(|e| e.id).collect();
        ids.sort_unstable();
        let count = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), count, "duplicate engine id");

        for engine in ENGINES {
            assert!(engine.default_port > 0, "{} has no port", engine.id);
            assert!(!engine.label.is_empty());
            assert!(!engine.local_host.is_empty(), "{} has no local host", engine.id);
        }
    }

    #[test]
    fn support_flag_matches_the_real_adapter_list() {
        // The UI relies on this to avoid offering an engine that cannot
        // connect, so the registry and the dispatcher must never disagree.
        for engine in ENGINES {
            assert_eq!(
                engine.supported,
                crate::dbconn::engine_supported(engine.id),
                "support flag out of sync for {}",
                engine.id
            );
        }

        for supported in ["mysql", "mariadb", "postgresql", "sqlserver"] {
            assert!(
                ENGINES.iter().any(|e| e.id == supported && e.supported),
                "{supported} must be offered"
            );
        }
    }
}
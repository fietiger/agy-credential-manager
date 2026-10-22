//! Multi-client account switching.
//!
//! Switching the active account writes it into every installed
//! Antigravity client on this machine:
//!
//! - **agy CLI** reads the OS keyring (service `antigravity`, entry
//!   `oauth_token`) — handled by [`crate::modules::agy_sync`].
//! - **Antigravity** (classic desktop app) and **Antigravity IDE** are
//!   VS Code-style apps whose sign-in state lives in a SQLite database
//!   `state.vscdb` (table `ItemTable`) under their user-data directory.
//!   Switching means injecting the account's OAuth token into that
//!   database in the "unified state sync" format (see
//!   [`crate::modules::state_proto`]) — the same keys the apps
//!   themselves write when a user signs in.

use crate::error::{AppError, AppResult};
use crate::models::account::Account;
use crate::modules::{logger, state_proto};
use base64::{engine::general_purpose, Engine as _};
use rusqlite::{Connection, OptionalExtension};
use std::path::PathBuf;
use std::time::Duration;

pub const KEY_OAUTH_TOKEN: &str = "antigravityUnifiedStateSync.oauthToken";
pub const KEY_USER_STATUS: &str = "antigravityUnifiedStateSync.userStatus";
pub const KEY_ENTERPRISE_PREFS: &str = "antigravityUnifiedStateSync.enterprisePreferences";
pub const KEY_ONBOARDING: &str = "antigravityOnboarding";
pub const KEY_LEGACY_AGENT_STATE: &str = "jetskiStateSync.agentManagerInitState";

const SENTINEL_OAUTH: &str = "oauthTokenInfoSentinelKey";
const SENTINEL_USER_STATUS: &str = "userStatusSentinelKey";
const SENTINEL_PROJECT: &str = "enterpriseGcpProjectId";

/// A client that can hold the active account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientKind {
    AgyCli,
    Classic,
    Ide,
}

impl ClientKind {
    pub fn name(self) -> &'static str {
        match self {
            ClientKind::AgyCli => "agy CLI",
            ClientKind::Classic => "Antigravity",
            ClientKind::Ide => "Antigravity IDE",
        }
    }

    /// User-data folder names used by this client (per OS app-data root).
    fn folder_names(self) -> &'static [&'static str] {
        match self {
            ClientKind::Classic => &["Antigravity"],
            ClientKind::Ide => &["Antigravity IDE", "antigravity-ide", "antigravity_ide"],
            ClientKind::AgyCli => &[],
        }
    }
}

/// Status of one client, shown in the UI.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ClientStatus {
    pub client: ClientKind,
    pub name: String,
    pub installed: bool,
    pub db_path: Option<String>,
    /// Email currently signed in on this client, when readable.
    pub current_email: Option<String>,
}

/// Outcome of syncing the active account into one client.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ClientSyncResult {
    pub client: ClientKind,
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

/// All candidate `state.vscdb` paths for a database-backed client.
pub fn candidate_db_paths(kind: ClientKind) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    #[cfg(target_os = "linux")]
    if let Some(cfg) = dirs::config_dir() {
        roots.push(cfg);
    }
    #[cfg(target_os = "macos")]
    if let Some(home) = dirs::home_dir() {
        roots.push(home.join("Library").join("Application Support"));
    }
    #[cfg(target_os = "windows")]
    if let Some(cfg) = dirs::config_dir() {
        roots.push(cfg);
    }

    let mut paths = Vec::new();
    for root in &roots {
        for folder in kind.folder_names() {
            paths.push(
                root.join(folder)
                    .join("User")
                    .join("globalStorage")
                    .join("state.vscdb"),
            );
        }
    }
    paths
}

/// The client's state DB path when the client appears installed.
pub fn installed_db_path(kind: ClientKind) -> Option<PathBuf> {
    candidate_db_paths(kind).into_iter().find(|p| p.exists())
}

/// Whether an `agy` executable is on PATH.
pub fn agy_cli_on_path() -> bool {
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths)
                .any(|dir| dir.join("agy").is_file() || dir.join("agy.exe").is_file())
        })
        .unwrap_or(false)
}

/// Read the email currently signed in on a DB-backed client, if readable.
pub fn read_client_email(db_path: &PathBuf) -> Option<String> {
    let conn =
        Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).ok()?;
    let value: Option<String> = conn
        .query_row(
            "SELECT value FROM ItemTable WHERE key = ?1",
            [KEY_USER_STATUS],
            |row| row.get(0),
        )
        .optional()
        .ok()?;
    let payload = state_proto::decode_unified_state_payload(&value?, SENTINEL_USER_STATUS)?;
    state_proto::user_status_email(&payload)
}

fn set_key(conn: &Connection, key: &str, value: &str) -> AppResult<()> {
    conn.execute(
        "INSERT OR REPLACE INTO ItemTable (key, value) VALUES (?1, ?2)",
        [key, value],
    )
    .map_err(|e| AppError::Other(format!("failed to write {}: {}", key, e)))?;
    Ok(())
}

fn get_key(conn: &Connection, key: &str) -> AppResult<Option<String>> {
    let value = conn
        .query_row("SELECT value FROM ItemTable WHERE key = ?1", [key], |row| {
            row.get(0)
        })
        .optional()
        .map_err(|e| AppError::Other(format!("failed to read {}: {}", key, e)))?;
    Ok(value)
}

/// Inject an account into one client's state DB.
///
/// Safe to run while the client app is open: a busy timeout lets SQLite
/// wait out transient write locks instead of failing immediately.
pub fn inject_account(db_path: &PathBuf, account: &Account) -> AppResult<()> {
    let conn = Connection::open(db_path)
        .map_err(|e| AppError::Other(format!("failed to open {}: {}", db_path.display(), e)))?;
    conn.busy_timeout(Duration::from_millis(2000))
        .map_err(|e| AppError::Other(format!("failed to set busy timeout: {}", e)))?;
    conn.execute_batch("CREATE TABLE IF NOT EXISTS ItemTable (key TEXT PRIMARY KEY, value TEXT)")
        .map_err(|e| AppError::Other(format!("failed to ensure ItemTable: {}", e)))?;

    // OAuth token topic: preserve any unrelated entries, replace ours.
    let oauth_info = state_proto::create_oauth_info(
        &account.token.access_token,
        &account.token.refresh_token,
        account.token.expiry_timestamp,
        account.token.is_gcp_tos,
        account.token.id_token.as_deref(),
        Some(&account.email),
    );
    let current_topic = get_key(&conn, KEY_OAUTH_TOKEN)?
        .map(|b64| general_purpose::STANDARD.decode(b64).unwrap_or_default())
        .unwrap_or_default();
    let mut topic = state_proto::remove_unified_topic_entry(&current_topic, SENTINEL_OAUTH)
        .map_err(AppError::Other)?;
    topic.extend(state_proto::create_unified_topic_entry(
        SENTINEL_OAUTH,
        &oauth_info,
    ));
    set_key(
        &conn,
        KEY_OAUTH_TOKEN,
        &general_purpose::STANDARD.encode(&topic),
    )?;

    // User status (drives the account shown in the client UI).
    let status_entry = state_proto::create_unified_state_entry(
        SENTINEL_USER_STATUS,
        &state_proto::create_minimal_user_status_payload(&account.email),
    );
    set_key(&conn, KEY_USER_STATUS, &status_entry)?;

    // Enterprise project preference follows the account's project id.
    match account
        .token
        .project_id
        .as_deref()
        .map(str::trim)
        .filter(|pid| !pid.is_empty())
    {
        Some(pid) => {
            let entry = state_proto::create_unified_state_entry(
                SENTINEL_PROJECT,
                &state_proto::create_string_value_payload(pid),
            );
            set_key(&conn, KEY_ENTERPRISE_PREFS, &entry)?;
        }
        None => {
            conn.execute(
                "DELETE FROM ItemTable WHERE key = ?1",
                [KEY_ENTERPRISE_PREFS],
            )
            .map_err(|e| AppError::Other(format!("failed to clear enterprise prefs: {}", e)))?;
        }
    }

    set_key(&conn, KEY_ONBOARDING, "true")?;

    // Stale legacy state makes the apps read an outdated user id and
    // breaks history/session loading after a switch; drop it.
    conn.execute(
        "DELETE FROM ItemTable WHERE key = ?1",
        [KEY_LEGACY_AGENT_STATE],
    )
    .map_err(|e| AppError::Other(format!("failed to clear legacy state: {}", e)))?;

    logger::log_info(
        "clients",
        &format!("Injected {} into {}", account.email, db_path.display()),
    );
    Ok(())
}

/// Sync an account into ONE DB-backed client (classic or IDE).
/// Switching is per-client: only the selected client is written.
pub fn sync_client_db(kind: ClientKind, account: &Account) -> ClientSyncResult {
    let name = kind.name().to_string();
    match installed_db_path(kind) {
        None => ClientSyncResult {
            client: kind,
            name,
            ok: false,
            detail: "not installed".to_string(),
        },
        Some(path) => match inject_account(&path, account) {
            Ok(()) => ClientSyncResult {
                client: kind,
                name,
                ok: true,
                detail: format!("synced {}", path.display()),
            },
            Err(e) => ClientSyncResult {
                client: kind,
                name,
                ok: false,
                detail: e.to_string(),
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::token::TokenData;

    fn sample_account() -> Account {
        let token = TokenData::new(
            "access-xyz".to_string(),
            "1//refresh-xyz".to_string(),
            3600,
            Some("switcher@example.com".to_string()),
            None,
            None,
            false,
            None,
        );
        Account::new(
            "acc-1".to_string(),
            "switcher@example.com".to_string(),
            token,
        )
    }

    fn temp_db(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "agy-client-sync-test-{}-{}",
            std::process::id(),
            tag
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("state.vscdb")
    }

    #[test]
    fn candidate_paths_cover_client_folder_variants() {
        let classic = candidate_db_paths(ClientKind::Classic);
        assert!(classic
            .iter()
            .any(|p| p.ends_with("Antigravity/User/globalStorage/state.vscdb")));
        let ide = candidate_db_paths(ClientKind::Ide);
        assert!(ide
            .iter()
            .any(|p| p.ends_with("Antigravity IDE/User/globalStorage/state.vscdb")));
        assert!(ide
            .iter()
            .any(|p| p.ends_with("antigravity-ide/User/globalStorage/state.vscdb")));
        // strict isolation: IDE candidates never include the classic folder
        assert!(ide
            .iter()
            .all(|p| !p.ends_with("Antigravity/User/globalStorage/state.vscdb")));
    }

    #[test]
    fn inject_then_read_back() {
        let db = temp_db("roundtrip");
        // Pre-populate like a real client DB: an unrelated topic entry in
        // oauthToken, a legacy key, and the ItemTable itself.
        {
            let conn = Connection::open(&db).unwrap();
            conn.execute_batch("CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value TEXT)")
                .unwrap();
            let mut topic = Vec::new();
            topic.extend(state_proto::create_unified_topic_entry(
                "someOtherSentinel",
                b"keep",
            ));
            conn.execute(
                "INSERT INTO ItemTable (key, value) VALUES (?1, ?2)",
                [KEY_OAUTH_TOKEN, &general_purpose::STANDARD.encode(&topic)],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO ItemTable (key, value) VALUES (?1, 'stale')",
                [KEY_LEGACY_AGENT_STATE],
            )
            .unwrap();
        }

        let account = sample_account();
        inject_account(&db, &account).unwrap();

        // The client now reports the switched account's email.
        assert_eq!(
            read_client_email(&db).as_deref(),
            Some("switcher@example.com")
        );

        let conn = Connection::open(&db).unwrap();
        // oauthToken decodes to our access/refresh tokens...
        let topic_b64 = get_key(&conn, KEY_OAUTH_TOKEN).unwrap().unwrap();
        let info = state_proto::decode_unified_state_payload(&topic_b64, SENTINEL_OAUTH).unwrap();
        assert_eq!(
            state_proto::find_field(&info, 1).unwrap().as_deref(),
            Some(b"access-xyz".as_slice())
        );
        assert_eq!(
            state_proto::find_field(&info, 3).unwrap().as_deref(),
            Some(b"1//refresh-xyz".as_slice())
        );
        // ...the unrelated entry survived...
        assert_eq!(
            state_proto::decode_unified_state_payload(&topic_b64, "someOtherSentinel").as_deref(),
            Some(b"keep".as_slice())
        );
        // ...legacy state was cleared and onboarding set.
        assert!(get_key(&conn, KEY_LEGACY_AGENT_STATE).unwrap().is_none());
        assert_eq!(
            get_key(&conn, KEY_ONBOARDING).unwrap().as_deref(),
            Some("true")
        );

        std::fs::remove_file(&db).ok();
    }
}

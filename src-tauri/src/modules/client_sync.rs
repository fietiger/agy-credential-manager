//! Multi-client account switching.
//!
//! Switching the active account writes it into every installed
//! Antigravity client on this machine:
//!
//! - **agy CLI** reads the OS keyring (service `gemini`, entry `antigravity`)
//!   and keeps a file copy at `~/.gemini/antigravity-cli/antigravity-oauth-token`
//!   — handled by [`crate::modules::agy_sync`].
//! - **Antigravity** (current desktop app) shares that `~/.gemini` sign-in
//!   record; its legacy `state.vscdb` values are stale, so they are only a
//!   fallback for reading and are still updated for VS Code-era builds.
//! - **Antigravity IDE** is a VS Code-style app whose sign-in state lives in
//!   a SQLite database `state.vscdb` (table `ItemTable`) under its user-data
//!   directory. Switching means injecting the account's OAuth token into that
//!   database in the "unified state sync" format (see
//!   [`crate::modules::state_proto`]) — the same keys the apps themselves
//!   write when a user signs in.

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
/// Sign-in state kept in the same topic as the token. A client whose entry
/// still says `signedOut` behaves as logged out even when a token is present,
/// so a switch has to flip this to `signedIn` as well.
const SENTINEL_AUTH_STATE: &str = "authStateWithContextSentinelKey";

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
    /// The client's own sign-in state (`signedIn` / `signedOut` / ...), when
    /// the client keeps one next to its token.
    pub auth_state: Option<String>,
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
    read_email_from_conn(&conn)
}

/// Email a client's state DB points at, if it holds one.
///
/// Two independent records carry it, and either may be the only one a given
/// client version keeps:
/// - `userStatus` — the display payload written on sign-in;
/// - `oauthToken` — the token payload, whose `id_token` claim names the owner.
fn read_email_from_conn(conn: &Connection) -> Option<String> {
    let user_status = get_key(conn, KEY_USER_STATUS).ok().flatten();

    // An entry with an empty row is what the clients leave behind after
    // signing out — treat it as absent instead of failing the whole lookup.
    if let Some(value) = user_status.as_deref() {
        if let Some(payload) =
            state_proto::decode_unified_state_payload(value, SENTINEL_USER_STATUS)
        {
            if let Some(email) = state_proto::user_status_email(&payload) {
                return Some(email);
            }
        }
    }

    let token_entry = get_key(conn, KEY_OAUTH_TOKEN).ok().flatten()?;
    let token_payload = state_proto::decode_unified_state_payload(&token_entry, SENTINEL_OAUTH)?;
    let id_token = state_proto::find_field(&token_payload, 5).ok()??;
    let id_token = String::from_utf8(id_token).ok()?;
    crate::modules::agy_sync::email_from_id_token(&id_token)
}

/// The sign-in state a client records for itself (`signedIn` / `signedOut`).
pub fn read_client_state(db_path: &PathBuf) -> Option<String> {
    let conn =
        Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).ok()?;
    let value = get_key(&conn, KEY_OAUTH_TOKEN).ok().flatten()?;
    let raw = state_proto::decode_unified_state_raw(&value, SENTINEL_AUTH_STATE)?;
    state_proto::auth_state_label(&raw)
}

/// The credential a client currently holds, for importing it into the manager.
#[derive(Debug, Clone)]
pub struct StoredCredential {
    pub access_token: String,
    pub refresh_token: String,
    /// Unix timestamp (seconds) the access token expires at, when recorded.
    pub expiry: Option<i64>,
    pub id_token: Option<String>,
    pub project_id: Option<String>,
    pub is_gcp_tos: bool,
    /// Owner of the credential, as recorded by the client.
    pub email: Option<String>,
}

/// Read the credential a DB-backed client is signed in with.
///
/// Returns `None` when the client is not installed or holds no refresh token —
/// e.g. after it signed out and cleared its own record.
pub fn read_client_credential(kind: ClientKind) -> Option<StoredCredential> {
    let db = installed_db_path(kind)?;
    let conn = Connection::open_with_flags(&db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).ok()?;

    let entry = get_key(&conn, KEY_OAUTH_TOKEN).ok().flatten()?;
    let payload = state_proto::decode_unified_state_payload(&entry, SENTINEL_OAUTH)?;

    let access_token = state_proto::find_field(&payload, 1)
        .ok()
        .flatten()
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_default();
    let refresh_token = state_proto::find_field(&payload, 3)
        .ok()
        .flatten()
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_default();
    if refresh_token.trim().is_empty() {
        logger::log_debug(
            "clients",
            &format!("{} has no refresh token to import", kind.name()),
        );
        return None;
    }

    // field 4 is a Timestamp message: field 1 holds the seconds.
    let expiry = state_proto::find_field(&payload, 4)
        .ok()
        .flatten()
        .and_then(|ts| state_proto::find_varint_field(&ts, 1).ok().flatten())
        .map(|secs| secs as i64);
    let id_token = state_proto::find_field(&payload, 5)
        .ok()
        .flatten()
        .and_then(|b| String::from_utf8(b).ok());
    let is_gcp_tos = state_proto::find_varint_field(&payload, 6)
        .ok()
        .flatten()
        .map(|v| v == 1)
        .unwrap_or(false);
    let email = read_email_from_conn(&conn);
    let project_id = read_project_id(&conn);

    logger::log_info(
        "clients",
        &format!(
            "Read credential from {}: email={} project={}",
            kind.name(),
            email.as_deref().unwrap_or("unknown"),
            project_id.as_deref().unwrap_or("-")
        ),
    );

    Some(StoredCredential {
        access_token: access_token.trim().to_string(),
        refresh_token: refresh_token.trim().to_string(),
        expiry,
        id_token,
        project_id,
        is_gcp_tos,
        email,
    })
}

/// The GCP project bound to the client's current account, if any.
fn read_project_id(conn: &Connection) -> Option<String> {
    let prefs = get_key(conn, KEY_ENTERPRISE_PREFS).ok().flatten()?;
    let payload = state_proto::decode_unified_state_payload(&prefs, SENTINEL_PROJECT)?;
    let raw = state_proto::find_field(&payload, 3).ok()??;
    let project = String::from_utf8(raw).ok()?;
    let project = project.trim().to_string();
    if project.is_empty() {
        None
    } else {
        Some(project)
    }
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
    let project_id = account
        .token
        .project_id
        .as_deref()
        .map(str::trim)
        .filter(|pid| !pid.is_empty())
        .map(str::to_string);

    let current_value = get_key(&conn, KEY_OAUTH_TOKEN)?;
    let current_topic = current_value
        .as_deref()
        .map(|b64| general_purpose::STANDARD.decode(b64).unwrap_or_default())
        .unwrap_or_default();
    // Keep whatever context the client had, only flipping the state.
    let previous_state = current_value
        .as_deref()
        .and_then(|b64| state_proto::decode_unified_state_raw(b64, SENTINEL_AUTH_STATE));
    let auth_state = state_proto::create_auth_state_payload(
        previous_state.as_deref(),
        project_id.as_deref().unwrap_or(""),
    );

    let mut topic = state_proto::remove_unified_topic_entry(&current_topic, SENTINEL_OAUTH)
        .map_err(AppError::Other)?;
    topic = state_proto::remove_unified_topic_entry(&topic, SENTINEL_AUTH_STATE)
        .map_err(AppError::Other)?;
    topic.extend(state_proto::create_unified_topic_entry(
        SENTINEL_OAUTH,
        &oauth_info,
    ));
    topic.extend(state_proto::create_unified_topic_entry_raw(
        SENTINEL_AUTH_STATE,
        &auth_state,
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
    match project_id.as_deref() {
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

    // Read back what the client will actually see. A running client keeps its
    // state in memory and can write it back over ours straight away, which
    // leaves the app reporting success while the client stays signed out — so
    // treat a mismatch as a failed switch instead of a silent one.
    match read_email_from_conn(&conn) {
        Some(email) if email.eq_ignore_ascii_case(&account.email) => {}
        Some(other) => {
            let msg = format!(
                "{} kept its previous account ({}) instead of {} — close the client and retry",
                db_path.display(),
                other,
                account.email
            );
            logger::log_warn("clients", &msg);
            return Err(AppError::Other(msg));
        }
        None => {
            let msg = format!(
                "{} holds no readable account after writing {} — close the client and retry",
                db_path.display(),
                account.email
            );
            logger::log_warn("clients", &msg);
            return Err(AppError::Other(msg));
        }
    }

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

        // The client now reports the switched account's email...
        assert_eq!(
            read_client_email(&db).as_deref(),
            Some("switcher@example.com")
        );
        // ...and its own sign-in state, which the clients check separately,
        // was flipped from signedOut to signedIn.
        assert_eq!(read_client_state(&db).as_deref(), Some("signedIn"));

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

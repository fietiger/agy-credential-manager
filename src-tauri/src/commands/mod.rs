//! Tauri IPC command handlers exposed to the frontend.

use crate::error::{AppError, AppResult};
use crate::models::account::{Account, AccountExportResponse};
use crate::modules::account_store;
use crate::modules::agy_sync;
use crate::modules::client_sync;
use crate::modules::local_import;
use crate::modules::logger;
use crate::modules::oauth;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// ── Shared state for in-flight OAuth tasks ───────────────────────────────

/// Result of a completed OAuth task.
enum OauthTaskResult {
    Pending,
    Success(Box<Account>),
    Failed(String),
}

/// Global map of in-flight OAuth tasks, keyed by port number.
static OAUTH_TASKS: std::sync::OnceLock<Arc<Mutex<HashMap<u16, OauthTaskResult>>>> =
    std::sync::OnceLock::new();

fn oauth_tasks() -> &'static Arc<Mutex<HashMap<u16, OauthTaskResult>>> {
    OAUTH_TASKS.get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
}

/// Channels that let the UI hand a manually pasted authorization code to a
/// running OAuth flow, keyed by the flow's callback port.
static MANUAL_CODES: std::sync::OnceLock<Arc<Mutex<HashMap<u16, tokio::sync::mpsc::Sender<String>>>>> =
    std::sync::OnceLock::new();

fn manual_codes() -> &'static Arc<Mutex<HashMap<u16, tokio::sync::mpsc::Sender<String>>>> {
    MANUAL_CODES.get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
}

// ── DTO types returned to the frontend ───────────────────────────────────

/// A safe (non-sensitive) view of an account for the UI.
#[derive(Debug, Clone, Serialize)]
pub struct AccountView {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub custom_label: Option<String>,
    pub disabled: bool,
    pub disabled_reason: Option<String>,
    pub created_at: i64,
    pub last_used: i64,
    pub access_token_masked: String,
    pub refresh_token_masked: String,
    pub access_token_valid: bool,
    /// Active in the agy CLI slot (kept for the status bar semantics).
    pub is_active: bool,
    /// Every client this account is currently switched into.
    pub active_in: Vec<client_sync::ClientKind>,
}

impl From<&crate::models::account::Account> for AccountView {
    fn from(acc: &crate::models::account::Account) -> Self {
        let (active, active_in) = account_store::load_index()
            .map(|idx| {
                (
                    idx.current_agy_account_id.as_deref() == Some(&acc.id),
                    account_store::active_clients_for(&idx, &acc.id),
                )
            })
            .unwrap_or((false, Vec::new()));
        Self {
            id: acc.id.clone(),
            email: acc.email.clone(),
            name: acc.name.clone(),
            custom_label: acc.custom_label.clone(),
            disabled: acc.disabled,
            disabled_reason: acc.disabled_reason.clone(),
            created_at: acc.created_at,
            last_used: acc.last_used,
            access_token_masked: acc.token.masked_access_token(),
            refresh_token_masked: acc.token.masked_refresh_token(),
            access_token_valid: acc.token.is_access_token_valid(),
            is_active: active,
            active_in,
        }
    }
}

/// Status information returned by `get_status`.
#[derive(Debug, Clone, Serialize)]
pub struct AppStatus {
    pub data_dir: String,
    pub log_dir: String,
    pub keyring_service: &'static str,
    pub keyring_entry: &'static str,
    pub active_account_id: Option<String>,
    pub active_email: Option<String>,
}

// ── IPC commands ───────────────────────────────────────────────────────────

/// List all managed accounts (non-sensitive view).
#[tauri::command]
pub fn list_accounts() -> AppResult<Vec<AccountView>> {
    let idx = account_store::load_index()?;
    let mut views: Vec<AccountView> = Vec::new();
    for summary in &idx.accounts {
        if let Ok(acc) = account_store::get_account(&summary.id) {
            views.push(AccountView::from(&acc));
        }
    }
    Ok(views)
}

/// Get a single account by id.
#[tauri::command]
pub fn get_account(id: String) -> AppResult<AccountView> {
    let acc = account_store::get_account(&id)?;
    Ok(AccountView::from(&acc))
}

/// Delete an account.
#[tauri::command]
pub fn delete_account(id: String) -> AppResult<()> {
    logger::log_info("cmd", &format!("Deleting account id={}", id));
    // If this is the active account, clear the keyring
    let idx = account_store::load_index()?;
    if idx.current_agy_account_id.as_deref() == Some(&id) {
        logger::log_info("cmd", "Account is active – clearing keyring");
        let _ = agy_sync::clear_keyring();
    }
    account_store::delete_account(&id)?;
    logger::log_info("cmd", &format!("Account {} deleted", id));
    Ok(())
}

/// Switch an account into ONE selected client (`target`).
///
/// Each client holds its account independently — the other clients keep
/// whichever account they already have. The result reports that single
/// client's outcome.
#[tauri::command]
pub async fn set_active_account(
    id: String,
    target: client_sync::ClientKind,
) -> AppResult<ActivationResult> {
    logger::log_info(
        "cmd",
        &format!("Activating account id={} into client {}", id, target.name()),
    );
    let mut acc = account_store::get_account_with_refresh(&id).await?;

    let result = match target {
        client_sync::ClientKind::AgyCli => {
            // agy CLI: write the access token to the OS keyring and read
            // it back to verify. Failures are reported as this client's
            // result rather than aborting the command.
            match agy_sync::sync_to_keyring(&acc) {
                Ok(()) => match agy_sync::verify_keyring(&acc.token.access_token) {
                    Ok(true) => client_sync::ClientSyncResult {
                        client: target,
                        name: target.name().to_string(),
                        ok: true,
                        detail: format!(
                            "keyring {}/{} synced + verified",
                            agy_sync::KEYRING_SERVICE,
                            agy_sync::KEYRING_ENTRY
                        ),
                    },
                    Ok(false) => client_sync::ClientSyncResult {
                        client: target,
                        name: target.name().to_string(),
                        ok: false,
                        detail: "keyring verification failed: stored token does not match"
                            .to_string(),
                    },
                    Err(e) => {
                        logger::log_warn(
                            "cmd",
                            &format!("Keyring verification could not be performed: {}", e),
                        );
                        client_sync::ClientSyncResult {
                            client: target,
                            name: target.name().to_string(),
                            ok: true,
                            detail: format!(
                                "keyring {}/{} synced (verify unavailable)",
                                agy_sync::KEYRING_SERVICE,
                                agy_sync::KEYRING_ENTRY
                            ),
                        }
                    }
                },
                Err(e) => client_sync::ClientSyncResult {
                    client: target,
                    name: target.name().to_string(),
                    ok: false,
                    detail: format!("keyring sync failed: {}", e),
                },
            }
        }
        client_sync::ClientKind::Classic => {
            // The desktop app shares the `~/.gemini` sign-in record with the
            // CLI, so the keyring is the store it actually reads. The legacy
            // `state.vscdb` copy is refreshed as well, for the VS Code-era
            // builds that still read it.
            let mut ok = true;
            let mut parts = Vec::new();
            match agy_sync::sync_to_keyring(&acc) {
                Ok(()) => parts.push(format!(
                    "keyring {}/{} synced",
                    agy_sync::KEYRING_SERVICE,
                    agy_sync::KEYRING_ENTRY
                )),
                Err(e) => {
                    ok = false;
                    parts.push(format!("keyring sync failed: {}", e));
                }
            }
            if let Some(db) = client_sync::installed_db_path(target) {
                match client_sync::inject_account(&db, &acc) {
                    Ok(()) => parts.push(format!("state.vscdb updated: {}", db.display())),
                    Err(e) => {
                        ok = false;
                        parts.push(format!("state.vscdb failed: {}", e));
                    }
                }
            }
            client_sync::ClientSyncResult {
                client: target,
                name: target.name().to_string(),
                ok,
                detail: parts.join("; "),
            }
        }
        client_sync::ClientKind::Ide => client_sync::sync_client_db(target, &acc),
    };

    if result.ok {
        acc.update_last_used();
        account_store::set_client_account(&id, target)?;
    }
    logger::log_info(
        "cmd",
        &format!("client {}: ok={} {}", result.name, result.ok, result.detail),
    );
    Ok(ActivationResult {
        account_id: id,
        email: acc.email.clone(),
        clients: vec![result],
    })
}

/// Result of activating an account: which clients received it.
#[derive(serde::Serialize)]
pub struct ActivationResult {
    pub account_id: String,
    pub email: String,
    pub clients: Vec<client_sync::ClientSyncResult>,
}

/// Detect installed Antigravity clients and the account each one is
/// currently signed in with.
#[tauri::command]
pub fn list_clients() -> AppResult<Vec<client_sync::ClientStatus>> {
    let mut out = Vec::new();

    // agy CLI: read the account the CLI itself is signed in with, so an
    // account added outside this app is still reported correctly. Fall back
    // to our own index slot when the CLI credential is unreadable.
    let idx = account_store::load_index()?;
    let cli_email = agy_sync::read_cli_account().map(|a| a.email).or_else(|| {
        idx.current_agy_account_id
            .as_ref()
            .and_then(|id| account_store::get_account(id).ok())
            .map(|a| a.email)
    });
    out.push(client_sync::ClientStatus {
        client: client_sync::ClientKind::AgyCli,
        name: client_sync::ClientKind::AgyCli.name().to_string(),
        installed: client_sync::agy_cli_on_path() || agy_sync::cli_state_present(),
        db_path: None,
        current_email: cli_email,
        auth_state: None,
    });

    for kind in [
        client_sync::ClientKind::Classic,
        client_sync::ClientKind::Ide,
    ] {
        let db_path = client_sync::installed_db_path(kind);
        // The current Antigravity desktop app no longer keeps its sign-in in
        // the legacy `state.vscdb` (that record goes stale and can name an
        // account that signed out long ago). It shares the `~/.gemini`
        // sign-in record with the CLI, so prefer that and only fall back to
        // the database.
        let current_email = match kind {
            client_sync::ClientKind::Classic => agy_sync::active_google_account_email()
                .or_else(|| db_path.as_ref().and_then(client_sync::read_client_email)),
            _ => db_path.as_ref().and_then(client_sync::read_client_email),
        };
        let auth_state = db_path.as_ref().and_then(client_sync::read_client_state);
        out.push(client_sync::ClientStatus {
            client: kind,
            name: kind.name().to_string(),
            installed: db_path.is_some(),
            db_path: db_path.map(|p| p.to_string_lossy().to_string()),
            current_email,
            auth_state,
        });
    }
    Ok(out)
}

/// Start the OAuth flow.
///
/// Returns the authorization URL and the local callback port. The link is not
/// opened here — the UI offers "open in browser" / "copy link" so the user
/// chooses (the link may also be used on another machine). Either the loopback
/// callback or a pasted code (`submit_oauth_code`) completes the flow; the
/// frontend polls `poll_oauth(port)` meanwhile.
#[tauri::command]
pub async fn start_oauth() -> AppResult<OauthStartResponse> {
    // Pick a random available port
    use std::net::TcpListener as StdTcpListener;
    let listener =
        StdTcpListener::bind("127.0.0.1:0").map_err(|e| AppError::Other(e.to_string()))?;
    let port = listener
        .local_addr()
        .map_err(|e| AppError::Other(e.to_string()))?
        .port();
    drop(listener);

    // Register as pending
    {
        let mut tasks = oauth_tasks()
            .lock()
            .map_err(|_| AppError::Other("lock poisoned".into()))?;
        tasks.insert(port, OauthTaskResult::Pending);
    }

    // Channel for a manually pasted code
    let (manual_tx, manual_rx) = tokio::sync::mpsc::channel::<String>(1);
    {
        let mut senders = manual_codes()
            .lock()
            .map_err(|_| AppError::Other("manual_codes lock poisoned".into()))?;
        senders.insert(port, manual_tx);
    }

    // Spawn the OAuth flow
    let _oauth_task = tokio::spawn(async move {
        let result = oauth::start_oauth_flow(port, manual_rx).await;
        let mut tasks = oauth_tasks().lock().expect("oauth_tasks lock poisoned");
        match result {
            Ok(oauth_result) => {
                let email = oauth_result
                    .email
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string());
                let id = uuid::Uuid::new_v4().to_string();
                let account = Account::new(id, email, oauth_result.token);
                match account_store::add_account(account.clone()) {
                    Ok(_) => {
                        tasks.insert(port, OauthTaskResult::Success(Box::new(account)));
                    }
                    Err(e) => {
                        tasks.insert(port, OauthTaskResult::Failed(e.to_string()));
                    }
                }
            }
            Err(e) => {
                tasks.insert(port, OauthTaskResult::Failed(e.to_string()));
            }
        }
        drop(tasks);
        if let Ok(mut senders) = manual_codes().lock() {
            senders.remove(&port);
        }
    });

    Ok(OauthStartResponse {
        port,
        auth_url: oauth::build_auth_url(port),
    })
}

/// Open the authorization URL in the system browser, at the user's request.
#[tauri::command]
pub fn open_auth_url(url: String) -> AppResult<()> {
    let parsed = url::Url::parse(&url)
        .map_err(|e| AppError::Validation(format!("Invalid authorization URL: {}", e)))?;
    let host = parsed.host_str().unwrap_or_default().to_ascii_lowercase();
    let is_google = parsed.scheme() == "https" && (host == "google.com" || host.ends_with(".google.com"));
    let is_loopback =
        parsed.scheme() == "http" && (host == "127.0.0.1" || host == "localhost" || host == "::1");
    if !is_google && !is_loopback {
        return Err(AppError::Validation(
            "Refusing to open a URL that is not a Google authorization page".to_string(),
        ));
    }
    oauth::open_in_browser(&url).map_err(|e| {
        logger::log_error("oauth", &format!("Could not open browser: {}", e));
        AppError::Other(format!("Could not open the browser: {}", e))
    })
}

/// Hand a manually pasted callback URL / authorization code to the running flow.
#[tauri::command]
pub fn submit_oauth_code(port: u16, input: String) -> AppResult<()> {
    let code = oauth::parse_code_input(&input).ok_or_else(|| {
        AppError::Validation(
            "No authorization code found. Paste the full callback URL or the code itself."
                .to_string(),
        )
    })?;

    let sender = manual_codes()
        .lock()
        .map_err(|_| AppError::Other("manual_codes lock poisoned".into()))?
        .get(&port)
        .cloned()
        .ok_or_else(|| AppError::Oauth("No pending OAuth flow on this port".to_string()))?;

    logger::log_info(
        "oauth",
        &format!("Code pasted by the user for port {}", port),
    );
    sender.try_send(code).map_err(|e| {
        AppError::Other(format!("Could not hand the code to the OAuth flow: {}", e))
    })
}

/// Poll for OAuth completion on the given port.
#[tauri::command]
pub fn poll_oauth(port: u16) -> AppResult<OauthPollResponse> {
    let tasks = oauth_tasks()
        .lock()
        .map_err(|_| AppError::Other("oauth_tasks lock poisoned".into()))?;

    match tasks.get(&port) {
        Some(OauthTaskResult::Pending) => Ok(OauthPollResponse {
            done: false,
            success: false,
            message: String::new(),
            error: None,
            account_id: None,
        }),
        Some(OauthTaskResult::Success(account)) => Ok(OauthPollResponse {
            done: true,
            success: true,
            message: format!("Successfully added account: {}", account.email),
            error: None,
            account_id: Some(account.id.clone()),
        }),
        Some(OauthTaskResult::Failed(msg)) => Ok(OauthPollResponse {
            done: true,
            success: false,
            message: String::new(),
            error: Some(msg.clone()),
            account_id: None,
        }),
        None => Ok(OauthPollResponse {
            done: true,
            success: false,
            message: String::new(),
            error: Some("No OAuth task found for this port".to_string()),
            account_id: None,
        }),
    }
}

/// Import an account by pasting a refresh token directly.
#[tauri::command]
pub fn import_refresh_token(
    refresh_token: String,
    access_token: Option<String>,
    expires_in: Option<i64>,
    project_id: Option<String>,
) -> AppResult<AccountView> {
    let acc = account_store::import_from_refresh_token(
        &refresh_token,
        access_token,
        expires_in,
        project_id,
        None,
    )?;
    Ok(AccountView::from(&acc))
}

/// Import accounts from an export file's JSON contents.
/// Compatible with Antigravity-Manager exports (a bare array of
/// `{email, refresh_token}`) and this app's own export format.
#[tauri::command]
pub fn import_accounts_json(content: String) -> AppResult<account_store::ImportSummary> {
    logger::log_info("cmd", "Importing accounts from JSON file content");
    account_store::import_accounts(&content)
}

/// Import the accounts the local clients are already signed in with
/// (agy CLI, Antigravity, Antigravity IDE), skipping duplicates.
#[tauri::command]
pub fn import_local_accounts() -> AppResult<local_import::LocalImportSummary> {
    logger::log_info("cmd", "Importing accounts from local clients");
    local_import::import_local_accounts()
}

/// Get app status.
#[tauri::command]
pub fn get_status() -> AppResult<AppStatus> {
    let idx = account_store::load_index()?;
    let active_email = idx
        .current_agy_account_id
        .as_ref()
        .and_then(|id| account_store::get_account(id).ok())
        .map(|a| a.email);
    Ok(AppStatus {
        data_dir: account_store::data_dir()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default(),
        log_dir: crate::modules::logger::log_dir_display(),
        keyring_service: crate::modules::agy_sync::KEYRING_SERVICE,
        keyring_entry: crate::modules::agy_sync::KEYRING_ENTRY,
        active_account_id: idx.current_agy_account_id,
        active_email,
    })
}

/// Export all accounts as JSON.
#[tauri::command]
pub fn export_accounts() -> AppResult<AccountExportResponse> {
    account_store::export_accounts()
}

/// Open the log directory in the system file manager.
#[tauri::command]
pub fn open_log_dir() -> AppResult<()> {
    logger::log_info("cmd", "Opening log directory");
    logger::open_log_dir().map_err(|e| {
        logger::log_error("cmd", &e);
        AppError::Other(e)
    })
}

// ── supporting types ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OauthStartResponse {
    pub port: u16,
    pub auth_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OauthPollResponse {
    pub done: bool,
    pub success: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
}

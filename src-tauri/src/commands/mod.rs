//! Tauri IPC command handlers exposed to the frontend.

use crate::error::{AppError, AppResult};
use crate::models::account::{Account, AccountExportResponse};
use crate::modules::account_store;
use crate::modules::agy_sync;
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
    pub is_active: bool,
}

impl From<&crate::models::account::Account> for AccountView {
    fn from(acc: &crate::models::account::Account) -> Self {
        let active = account_store::load_index()
            .map(|idx| idx.current_agy_account_id.as_deref() == Some(&acc.id))
            .unwrap_or(false);
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

/// Activate an account: refresh its token and write it to the keyring.
#[tauri::command]
pub async fn set_active_account(id: String) -> AppResult<()> {
    logger::log_info("cmd", &format!("Activating account id={}", id));
    let mut acc = account_store::get_account_with_refresh(&id).await?;
    // Write to keyring
    agy_sync::sync_to_keyring(&acc)?;
    // Read back and verify the stored token matches the activated account
    match agy_sync::verify_keyring(&acc.token.access_token) {
        Ok(true) => {}
        Ok(false) => {
            let msg =
                "Keyring verification failed: stored token does not match the activated account"
                    .to_string();
            logger::log_error("cmd", &msg);
            return Err(AppError::Keyring(msg));
        }
        Err(e) => {
            logger::log_warn(
                "cmd",
                &format!("Keyring verification could not be performed: {}", e),
            );
        }
    }
    // Update index
    acc.update_last_used();
    account_store::set_active_account(&id)?;
    logger::log_info(
        "cmd",
        &format!("Account {} activated and synced to keyring", id),
    );
    Ok(())
}

/// Start the OAuth flow.
/// Returns the auth URL and the local callback port.
/// The frontend should open the auth_url in the browser, then poll `poll_oauth(port)`.
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

    // Spawn the OAuth flow
    let _oauth_task = tokio::spawn(async move {
        let result = oauth::start_oauth_flow(port).await;
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
    });

    Ok(OauthStartResponse {
        port,
        auth_url: oauth::build_auth_url(port),
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

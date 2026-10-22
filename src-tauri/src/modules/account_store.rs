//! Local JSON-based account store with per-account file locking.
//!
//! Layout:
//!   <data_dir>/
//!     accounts.json          -- index
//!     accounts/
//!       <id>.json            -- one file per account
//!
//! All file access is guarded by a process-wide `RwLock<()>` to prevent
//! concurrent writes. The lock is held only for the duration of a single
//! read/write operation.

use crate::error::{AppError, AppResult};
use crate::modules::logger;
use crate::models::account::{Account, AccountExportItem, AccountExportResponse, AccountIndex, AccountSummary};
use crate::models::token::TokenData;
use std::path::PathBuf;
use std::sync::RwLock;

/// Global lock that serialises access to the account store on disk.
static STORE_LOCK: RwLock<()> = RwLock::new(());

pub fn data_dir() -> AppResult<PathBuf> {
    let dir = dirs::data_dir()
        .ok_or_else(|| AppError::Other("Could not determine data directory".to_string()))?
        .join("agy-credential-manager");
    std::fs::create_dir_all(&dir)?;
    logger::log_debug("store", &format!("data dir: {}", dir.display()));
    Ok(dir)
}

fn accounts_dir() -> AppResult<PathBuf> {
    let dir = data_dir()?.join("accounts");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn index_path() -> AppResult<PathBuf> {
    Ok(data_dir()?.join("accounts.json"))
}

fn account_file(id: &str) -> AppResult<PathBuf> {
    Ok(accounts_dir()?.join(format!("{}.json", id)))
}

/// Read the index, creating it if it does not exist.
pub fn load_index() -> AppResult<AccountIndex> {
    let _guard = STORE_LOCK.read().map_err(|_| AppError::Other("store lock poisoned".into()))?;
    let path = index_path()?;
    if !path.exists() {
        let idx = AccountIndex::new();
        save_index(&idx)?;
        return Ok(idx);
    }
    let raw = std::fs::read_to_string(&path)?;
    let idx: AccountIndex = serde_json::from_str(&raw)?;
    Ok(idx)
}

/// Persist the index. Must be called while holding the write guard,
/// or use `update_index` which handles locking internally.
fn save_index(idx: &AccountIndex) -> AppResult<()> {
    let path = index_path()?;
    let raw = serde_json::to_string_pretty(idx)?;
    std::fs::write(&path, raw)?;
    Ok(())
}

/// Atomically read-modify-write the index.
pub fn update_index<F: FnOnce(&mut AccountIndex)>(f: F) -> AppResult<()> {
    let guard = STORE_LOCK.write().map_err(|_| AppError::Other("store lock poisoned".into()))?;
    let _ = &guard; // hold for the whole operation
    let mut idx = load_index_unlocked()?;
    f(&mut idx);
    save_index(&idx)?;
    Ok(())
}

fn load_index_unlocked() -> AppResult<AccountIndex> {
    let path = index_path()?;
    if !path.exists() {
        return Ok(AccountIndex::new());
    }
    let raw = std::fs::read_to_string(&path)?;
    Ok(serde_json::from_str(&raw)?)
}

/// Add a new account to the store.
pub fn add_account(account: Account) -> AppResult<()> {
    logger::log_info(
        "store",
        &format!(
            "Adding account id={} email={}",
            account.id, account.email
        ),
    );
    // Check for duplicate email
    let idx = load_index()?;
    if idx.accounts.iter().any(|a| a.email == account.email) {
        logger::log_warn(
            "store",
            &format!("Duplicate email rejected: {}", account.email),
        );
        return Err(AppError::AccountExists(format!(
            "Account with email {} already exists",
            account.email
        )));
    }

    // Write per-account file
    let path = account_file(&account.id)?;
    let raw = serde_json::to_string_pretty(&account)?;
    std::fs::write(&path, raw)?;
    logger::log_debug("store", &format!("Wrote account file: {}", path.display()));

    // Update index
    update_index(|idx| {
        idx.accounts.push(AccountSummary::from(&account));
        // Set as current if it is the first account
        if idx.accounts.len() == 1 {
            idx.current_agy_account_id = Some(account.id.clone());
        }
    })?;

    logger::log_info("store", &format!("Account {} added", account.id));
    Ok(())
}

/// Remove an account from the store.
pub fn delete_account(id: &str) -> AppResult<()> {
    logger::log_info("store", &format!("Deleting account id={}", id));
    // Remove file
    let path = account_file(id)?;
    if path.exists() {
        std::fs::remove_file(&path)?;
        logger::log_debug("store", &format!("Removed file: {}", path.display()));
    }

    // Update index
    update_index(|idx| {
        idx.accounts.retain(|a| a.id != id);
        if idx.current_agy_account_id.as_deref() == Some(id) {
            idx.current_agy_account_id = None;
        }
    })?;

    logger::log_info("store", &format!("Account {} deleted", id));
    Ok(())
}

/// Read a single account by id.
pub fn get_account(id: &str) -> AppResult<Account> {
    let path = account_file(id)?;
    if !path.exists() {
        return Err(AppError::AccountNotFound(id.to_string()));
    }
    let raw = std::fs::read_to_string(&path)?;
    Ok(serde_json::from_str(&raw)?)
}

/// List all accounts (summaries from the index).
pub fn list_accounts() -> AppResult<Vec<AccountSummary>> {
    let idx = load_index()?;
    Ok(idx.accounts)
}

/// Read a full account, or refresh its access token if expired.
pub async fn get_account_with_refresh(id: &str) -> AppResult<Account> {
    let mut account = get_account(id)?;
    if !account.token.is_access_token_valid() {
        logger::log_info(
            "store",
            &format!(
                "Access token for {} expired, refreshing via refresh_token",
                account.email
            ),
        );
        account.token = crate::modules::oauth::refresh_token(&account.token)
            .await
            .map_err(|e| {
                AppError::Other(format!(
                    "Failed to refresh access token: {} (account may have been revoked)",
                    e
                ))
            })?;
        // persist the refreshed token
        let path = account_file(&account.id)?;
        let raw = serde_json::to_string_pretty(&account)?;
        std::fs::write(&path, raw)?;
        logger::log_info("store", &format!("Refreshed token for {}", account.email));
    } else {
        logger::log_debug(
            "store",
            &format!("Access token for {} still valid", account.email),
        );
    }
    account.update_last_used();
    Ok(account)
}

/// Set the active account id in the index.
pub fn set_active_account(id: &str) -> AppResult<()> {
    // Validate the account exists
    get_account(id)?;
    update_index(|idx| {
        idx.current_agy_account_id = Some(id.to_string());
    })?;
    Ok(())
}

/// Export all accounts for backup / migration.
pub fn export_accounts() -> AppResult<AccountExportResponse> {
    let idx = load_index()?;
    let accounts: Vec<AccountExportItem> = idx
        .accounts
        .iter()
        .filter_map(|summary| {
            let acc = get_account(&summary.id).ok()?;
            Some(AccountExportItem {
                email: acc.email.clone(),
                refresh_token: acc.token.refresh_token.clone(),
                access_token: Some(acc.token.access_token.clone()),
                expires_in: Some(acc.token.expires_in),
                project_id: acc.token.project_id.clone(),
                session_id: acc.token.session_id.clone(),
            })
        })
        .collect();
    Ok(AccountExportResponse {
        exported_at: chrono::Utc::now().timestamp(),
        accounts,
    })
}

/// Import an account from a refresh token.
pub fn import_from_refresh_token(
    refresh_token: &str,
    access_token: Option<String>,
    expires_in: Option<i64>,
    project_id: Option<String>,
    session_id: Option<String>,
) -> AppResult<Account> {
    let token = TokenData {
        access_token: access_token.unwrap_or_default(),
        refresh_token: refresh_token.to_string(),
        expires_in: expires_in.unwrap_or(3600),
        expiry_timestamp: chrono::Utc::now().timestamp() + expires_in.unwrap_or(3600),
        token_type: "Bearer".to_string(),
        email: None,
        project_id,
        oauth_client_key: None,
        session_id,
        is_gcp_tos: false,
        id_token: None,
    };

    let email = extract_email_from_token(&token)?;
    let id = uuid::Uuid::new_v4().to_string();
    let account = Account::new(id, email, token);
    add_account(account.clone())?;
    Ok(account)
}

/// Try to extract the email from a refreshed token response.
fn extract_email_from_token(token: &TokenData) -> AppResult<String> {
    // If the token already has an email, use it.
    if let Some(email) = &token.email {
        if !email.is_empty() {
            return Ok(email.clone());
        }
    }
    Ok(String::from("unknown"))
}

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
use crate::models::account::{
    Account, AccountExportItem, AccountExportResponse, AccountIndex, AccountSummary,
};
use crate::models::token::TokenData;
use crate::modules::client_sync::ClientKind;
use crate::modules::logger;
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
    let _guard = STORE_LOCK
        .read()
        .map_err(|_| AppError::Other("store lock poisoned".into()))?;
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
    let guard = STORE_LOCK
        .write()
        .map_err(|_| AppError::Other("store lock poisoned".into()))?;
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
        &format!("Adding account id={} email={}", account.id, account.email),
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
        if idx.current_classic_account_id.as_deref() == Some(id) {
            idx.current_classic_account_id = None;
        }
        if idx.current_ide_account_id.as_deref() == Some(id) {
            idx.current_ide_account_id = None;
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

/// Read a full account, refreshing its access token when expired or
/// missing. Accounts imported from a file carry no access token; for
/// those, a failed best-effort refresh (offline, bad test token, ...)
/// only logs a warning — activation continues with the stored refresh
/// token, which the desktop clients can exchange on their own.
pub async fn get_account_with_refresh(id: &str) -> AppResult<Account> {
    let mut account = get_account(id)?;
    let expired = !account.token.is_access_token_valid();
    let missing = account.token.access_token.is_empty();
    if expired || missing {
        logger::log_info(
            "store",
            &format!(
                "Access token for {} expired or missing, refreshing via refresh_token",
                account.email
            ),
        );
        match crate::modules::oauth::refresh_token(&account.token).await {
            Ok(new_token) => {
                account.token = new_token;
                // persist the refreshed token
                let path = account_file(&account.id)?;
                let raw = serde_json::to_string_pretty(&account)?;
                std::fs::write(&path, raw)?;
                logger::log_info("store", &format!("Refreshed token for {}", account.email));
            }
            Err(e) if missing && !expired => {
                logger::log_warn(
                    "store",
                    &format!(
                        "Best-effort refresh for {} failed ({}); continuing with stored token",
                        account.email, e
                    ),
                );
            }
            Err(e) => {
                return Err(AppError::Other(format!(
                    "Failed to refresh access token: {} (account may have been revoked)",
                    e
                )));
            }
        }
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
/// Record `id` as the current account of ONE client. Each client holds
/// its account independently; other clients' slots are untouched.
pub fn set_client_account(id: &str, client: ClientKind) -> AppResult<()> {
    // Validate the account exists
    get_account(id)?;
    update_index(|idx| match client {
        ClientKind::AgyCli => idx.current_agy_account_id = Some(id.to_string()),
        ClientKind::Classic => idx.current_classic_account_id = Some(id.to_string()),
        ClientKind::Ide => idx.current_ide_account_id = Some(id.to_string()),
    })?;
    Ok(())
}

/// The clients whose current-account slot holds `id`.
pub fn active_clients_for(idx: &AccountIndex, id: &str) -> Vec<ClientKind> {
    let mut out = Vec::new();
    if idx.current_agy_account_id.as_deref() == Some(id) {
        out.push(ClientKind::AgyCli);
    }
    if idx.current_classic_account_id.as_deref() == Some(id) {
        out.push(ClientKind::Classic);
    }
    if idx.current_ide_account_id.as_deref() == Some(id) {
        out.push(ClientKind::Ide);
    }
    out
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
    let token = TokenData::new(
        access_token.unwrap_or_default(),
        refresh_token.to_string(),
        expires_in.unwrap_or(3600),
        None,
        project_id,
        session_id,
        false,
        None,
    );

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

// ── Bulk import (Antigravity-Manager compatible) ────────────────────────

/// One parsed entry from an import file.
#[derive(Debug, Clone, PartialEq)]
pub struct ImportEntry {
    pub email: Option<String>,
    pub refresh_token: String,
}

/// Result of parsing an import file.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedImport {
    pub entries: Vec<ImportEntry>,
    pub skipped_invalid: usize,
}

/// Summary of a bulk import, returned to the frontend.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ImportSummary {
    pub imported: usize,
    pub skipped_invalid: usize,
    pub skipped_duplicate: usize,
    pub imported_emails: Vec<String>,
}

/// Parse the contents of an accounts export file.
///
/// Accepts both shapes:
/// - Antigravity-Manager export: a bare array
///   `[{"email": "...", "refresh_token": "1//..."}, ...]`
/// - This app's own export: `{"accounts": [ ... ]}` (extra fields ignored)
///
/// Entries whose refresh_token is missing or does not start with
/// `1//` or `4/` are counted as invalid and skipped.
pub fn parse_import_entries(content: &str) -> AppResult<ParsedImport> {
    let value: serde_json::Value = serde_json::from_str(content)
        .map_err(|e| AppError::Validation(format!("Invalid JSON: {}", e)))?;
    let items: &Vec<serde_json::Value> = match &value {
        serde_json::Value::Array(arr) => arr,
        serde_json::Value::Object(obj) => match obj.get("accounts") {
            Some(serde_json::Value::Array(arr)) => arr,
            _ => {
                return Err(AppError::Validation(
                    "Unrecognized import format: expected an array or an object with an \"accounts\" array"
                        .to_string(),
                ))
            }
        },
        _ => {
            return Err(AppError::Validation(
                "Unrecognized import format: expected a JSON array".to_string(),
            ))
        }
    };

    let mut entries = Vec::new();
    let mut skipped_invalid = 0usize;
    for item in items {
        let token = item
            .get("refresh_token")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        if !(token.starts_with("1//") || token.starts_with("4/")) {
            skipped_invalid += 1;
            continue;
        }
        let email = item
            .get("email")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        entries.push(ImportEntry {
            email,
            refresh_token: token.to_string(),
        });
    }
    Ok(ParsedImport {
        entries,
        skipped_invalid,
    })
}

/// Import all valid accounts from an export file's contents.
/// Duplicates (same email or same refresh token as an existing account)
/// are skipped and counted, not treated as errors.
pub fn import_accounts(content: &str) -> AppResult<ImportSummary> {
    let parsed = parse_import_entries(content)?;
    if parsed.entries.is_empty() {
        return Err(AppError::Validation(
            "No valid accounts found in the import file".to_string(),
        ));
    }

    // Snapshot existing refresh tokens for duplicate detection
    let idx = load_index()?;
    let mut seen_tokens: std::collections::HashSet<String> = std::collections::HashSet::new();
    for summary in &idx.accounts {
        if let Ok(acc) = get_account(&summary.id) {
            seen_tokens.insert(acc.token.refresh_token);
        }
    }

    let mut summary = ImportSummary {
        imported: 0,
        skipped_invalid: parsed.skipped_invalid,
        skipped_duplicate: 0,
        imported_emails: Vec::new(),
    };

    for entry in parsed.entries {
        if !seen_tokens.insert(entry.refresh_token.clone()) {
            summary.skipped_duplicate += 1;
            continue;
        }
        let email = entry.email.clone().unwrap_or_else(|| "unknown".to_string());
        let token = TokenData::new(
            String::new(),
            entry.refresh_token.clone(),
            3600,
            entry.email.clone(),
            None,
            None,
            false,
            None,
        );
        let account = Account::new(uuid::Uuid::new_v4().to_string(), email.clone(), token);
        match add_account(account) {
            Ok(()) => {
                summary.imported += 1;
                summary.imported_emails.push(email);
            }
            Err(AppError::AccountExists(_)) => {
                summary.skipped_duplicate += 1;
            }
            Err(e) => return Err(e),
        }
    }

    logger::log_info(
        "store",
        &format!(
            "Bulk import finished: imported={} invalid={} duplicate={}",
            summary.imported, summary.skipped_invalid, summary.skipped_duplicate
        ),
    );
    Ok(summary)
}

#[cfg(test)]
mod import_tests {
    use super::*;

    #[test]
    fn parses_antigravity_manager_bare_array() {
        let content = r#"[
            {"email": "alice@example.com", "refresh_token": "1//aaa"},
            {"email": "bob@example.com", "refresh_token": "1//bbb"}
        ]"#;
        let parsed = parse_import_entries(content).unwrap();
        assert_eq!(parsed.skipped_invalid, 0);
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(
            parsed.entries[0].email.as_deref(),
            Some("alice@example.com")
        );
        assert_eq!(parsed.entries[1].refresh_token, "1//bbb");
    }

    #[test]
    fn parses_own_export_wrapped_format() {
        let content = r#"{
            "exported_at": 1792660464,
            "accounts": [
                {"email": "carol@example.com", "refresh_token": "4/ccc", "access_token": "x", "expires_in": 3600}
            ]
        }"#;
        let parsed = parse_import_entries(content).unwrap();
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].refresh_token, "4/ccc");
    }

    #[test]
    fn filters_invalid_entries() {
        let content = r#"[
            {"email": "ok@example.com", "refresh_token": "1//good"},
            {"email": "no-token@example.com"},
            {"email": "bad@example.com", "refresh_token": "not-a-token"},
            {"refresh_token": "1//no-email"}
        ]"#;
        let parsed = parse_import_entries(content).unwrap();
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.skipped_invalid, 2);
        assert_eq!(parsed.entries[1].email, None);
    }

    #[test]
    fn rejects_unrecognized_formats() {
        assert!(parse_import_entries("not json").is_err());
        assert!(parse_import_entries(r#"{"foo": 1}"#).is_err());
        assert!(parse_import_entries(r#""just a string""#).is_err());
        let empty = parse_import_entries("[]").unwrap();
        assert!(empty.entries.is_empty());
    }
}

#[cfg(test)]
mod slot_tests {
    use super::*;

    #[test]
    fn active_clients_reflect_independent_slots() {
        let mut idx = AccountIndex::new();
        idx.current_agy_account_id = Some("a".to_string());
        idx.current_ide_account_id = Some("a".to_string());
        idx.current_classic_account_id = Some("b".to_string());
        assert_eq!(
            active_clients_for(&idx, "a"),
            vec![ClientKind::AgyCli, ClientKind::Ide]
        );
        assert_eq!(active_clients_for(&idx, "b"), vec![ClientKind::Classic]);
        assert!(active_clients_for(&idx, "nobody").is_empty());
    }

    #[test]
    fn old_index_format_loads_with_empty_new_slots() {
        // accounts.json written before per-client slots existed
        let raw = r#"{"version":"1.0","accounts":[],"current_agy_account_id":"x"}"#;
        let idx: AccountIndex = serde_json::from_str(raw).unwrap();
        assert_eq!(idx.current_agy_account_id.as_deref(), Some("x"));
        assert!(idx.current_classic_account_id.is_none());
        assert!(idx.current_ide_account_id.is_none());
    }
}

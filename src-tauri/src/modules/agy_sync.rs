//! Synchronises the selected account's credentials into the agy CLI store.
//!
//! The agy CLI (Antigravity CLI) keeps its live credentials in the OS
//! keyring under service `gemini`, entry `antigravity`, as a JSON document:
//!
//! ```json
//! {"token": {"access_token": "...", "token_type": "Bearer",
//!            "refresh_token": "...", "expiry": "<RFC3339>",
//!            "expires_in": 3599},
//!  "auth_method": "consumer", "id_token": "..."}
//! ```
//!
//! It also keeps a copy at `~/.gemini/antigravity-cli/antigravity-oauth-token`.
//! Both are written so the CLI sees the same account whichever it reads.
//! Writing is a local operation – no network request is made here.

use crate::error::{AppError, AppResult};
use crate::models::account::Account;
use crate::modules::logger;
use serde_json::{json, Value};
use std::path::PathBuf;

/// The keyring service and entry used by the agy CLI.
pub const KEYRING_SERVICE: &str = "gemini";
pub const KEYRING_ENTRY: &str = "antigravity";

/// The account the agy CLI is currently signed in with.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CliAccount {
    pub email: String,
}

fn entry() -> AppResult<keyring::Entry> {
    keyring::Entry::new(KEYRING_SERVICE, KEYRING_ENTRY).map_err(|e| {
        let msg = format!("Failed to open keyring entry: {}", e);
        logger::log_error("keyring", &msg);
        AppError::Keyring(msg)
    })
}

fn cli_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".gemini").join("antigravity-cli"))
}

/// The CLI's on-disk copy of the credential document.
fn cli_token_file() -> Option<PathBuf> {
    cli_dir().map(|d| d.join("antigravity-oauth-token"))
}

fn google_accounts_file() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".gemini").join("google_accounts.json"))
}

/// Whether the agy CLI has ever left credentials on this machine.
pub fn cli_state_present() -> bool {
    if cli_token_file().map(|p| p.exists()).unwrap_or(false) {
        return true;
    }
    if google_accounts_file().map(|p| p.exists()).unwrap_or(false) {
        return true;
    }
    entry()
        .ok()
        .and_then(|e| e.get_password().ok())
        .is_some()
}

/// Read the stored credential document, preferring the live keyring copy
/// (the CLI refreshes it there; the file can be stale).
fn read_stored_payload() -> Option<Value> {
    if let Ok(e) = entry() {
        if let Ok(stored) = e.get_password() {
            if let Ok(v) = serde_json::from_str::<Value>(&stored) {
                return Some(v);
            }
        }
    }
    let path = cli_token_file()?;
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

/// Build the credential document for `account`, preserving any unrelated
/// fields (`auth_method`, ...) already present in `previous`.
fn build_payload(account: &Account, previous: Option<Value>) -> Value {
    let mut root = previous.unwrap_or_else(|| json!({ "auth_method": "consumer" }));
    if !root.is_object() {
        root = json!({ "auth_method": "consumer" });
    }

    let expires_at = chrono::DateTime::from_timestamp(account.token.expiry_timestamp, 0)
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        .unwrap_or_default();
    let token_type = if account.token.token_type.is_empty() {
        "Bearer".to_string()
    } else {
        account.token.token_type.clone()
    };

    root["token"] = json!({
        "access_token": account.token.access_token,
        "token_type": token_type,
        "refresh_token": account.token.refresh_token,
        "expiry": expires_at,
        "expires_in": account.token.expires_in,
    });
    match &account.token.id_token {
        Some(id_token) => root["id_token"] = json!(id_token),
        // Never leave the previous account's id_token behind: it would make
        // the CLI report the old email for the new token.
        None => {
            if let Some(obj) = root.as_object_mut() {
                obj.remove("id_token");
            }
        }
    }
    root
}

/// Write the account's credentials into the keyring and the CLI's file copy.
pub fn sync_to_keyring(account: &Account) -> AppResult<()> {
    logger::log_info(
        "keyring",
        &format!(
            "Writing agy CLI credentials to keyring ({}/{}) for {}",
            KEYRING_SERVICE, KEYRING_ENTRY, account.email
        ),
    );

    let previous = read_stored_payload();
    logger::log_info(
        "keyring",
        &format!(
            "Existing CLI credential found: {}",
            previous.is_some()
        ),
    );
    let payload = build_payload(account, previous);
    let serialized = serde_json::to_string(&payload).map_err(|e| {
        let msg = format!("Failed to serialise CLI credentials: {}", e);
        logger::log_error("keyring", &msg);
        AppError::Keyring(msg)
    })?;

    entry()?.set_password(&serialized).map_err(|e| {
        let msg = format!("Failed to write keyring entry: {}", e);
        logger::log_error("keyring", &msg);
        AppError::Keyring(msg)
    })?;

    // Keep the CLI's file copy in sync with the keyring.
    if let Some(path) = cli_token_file() {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match std::fs::write(&path, &serialized) {
            Ok(()) => logger::log_debug(
                "keyring",
                &format!("Updated CLI token file: {}", path.display()),
            ),
            Err(e) => logger::log_warn(
                "keyring",
                &format!("Could not update CLI token file {}: {}", path.display(), e),
            ),
        }
    }

    logger::log_info(
        "keyring",
        &format!(
            "Synced credentials for {} to keyring ({}/{})",
            account.email, KEYRING_SERVICE, KEYRING_ENTRY
        ),
    );

    update_active_google_account(&account.email);
    Ok(())
}

/// Keep `~/.gemini/google_accounts.json` pointing at the selected account.
///
/// The CLI uses this file to label the current sign-in; leaving a stale email
/// here makes it report the wrong account after a switch.
fn update_active_google_account(email: &str) {
    let Some(path) = google_accounts_file() else {
        return;
    };
    let mut doc: Value = std::fs::read_to_string(&path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_else(|| json!({ "active": "", "old": [] }));

    let previous = doc
        .get("active")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if previous == email {
        return;
    }

    if !previous.is_empty() {
        match doc.get_mut("old").and_then(|v| v.as_array_mut()) {
            Some(old) => {
                if !old.iter().any(|v| v.as_str() == Some(previous.as_str())) {
                    old.push(json!(previous));
                }
            }
            None => doc["old"] = json!([previous]),
        }
    }
    doc["active"] = json!(email);

    let result = serde_json::to_string_pretty(&doc)
        .map_err(|e| e.to_string())
        .and_then(|raw| std::fs::write(&path, raw).map_err(|e| e.to_string()));
    match result {
        Ok(()) => logger::log_info(
            "keyring",
            &format!("Updated CLI active account -> {}", email),
        ),
        Err(e) => logger::log_warn(
            "keyring",
            &format!("Could not update {}: {}", path.display(), e),
        ),
    }
}

/// Read back the keyring entry and verify it holds `expected_token`.
pub fn verify_keyring(expected_token: &str) -> AppResult<bool> {
    match entry()?.get_password() {
        Ok(stored) => {
            let matches = match serde_json::from_str::<Value>(&stored) {
                Ok(v) => v["token"]["access_token"].as_str() == Some(expected_token),
                // Tolerate a plain token string (older CLI versions).
                Err(_) => stored == expected_token,
            };
            logger::log_info("keyring", &format!("Keyring verification: match={}", matches));
            Ok(matches)
        }
        Err(e) => {
            logger::log_warn("keyring", &format!("Could not read keyring entry: {}", e));
            Ok(false)
        }
    }
}

/// Email of the account the CLI is currently signed in with.
pub fn read_cli_account() -> Option<CliAccount> {
    let email = read_stored_payload()
        .as_ref()
        .and_then(|p| p.get("id_token"))
        .and_then(|v| v.as_str())
        .and_then(email_from_id_token)
        .or_else(active_google_account);

    let email = email?;
    logger::log_debug("keyring", &format!("agy CLI current account: {}", email));
    Some(CliAccount { email })
}

/// Decode the `email` claim from a Google id_token (JWT, no verification –
/// it is only used for display, never for authentication decisions).
fn email_from_id_token(id_token: &str) -> Option<String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    let payload_b64 = id_token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    let claims: Value = serde_json::from_slice(&bytes).ok()?;
    claims
        .get("email")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Fallback: the CLI also records the active account name here.
fn active_google_account() -> Option<String> {
    let path = google_accounts_file()?;
    let raw = std::fs::read_to_string(path).ok()?;
    let v: Value = serde_json::from_str(&raw).ok()?;
    v.get("active")
        .and_then(|a| a.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

/// Clear the CLI credential (used when removing the active account).
pub fn clear_keyring() -> AppResult<()> {
    logger::log_info("keyring", "Clearing agy CLI keyring entry");

    let e = entry()?;
    if e.get_password().is_ok() {
        e.delete_credential().map_err(|err| {
            let msg = format!("Failed to delete keyring entry: {}", err);
            logger::log_error("keyring", &msg);
            AppError::Keyring(msg)
        })?;
        logger::log_info("keyring", "Cleared keyring entry");
    } else {
        logger::log_debug("keyring", "Keyring entry was already empty");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::token::TokenData;

    fn account_with_id_token(id_token: Option<&str>) -> Account {
        let token = TokenData::new(
            "access-xyz".into(),
            "1//refresh-xyz".into(),
            3600,
            Some("cli@example.com".into()),
            None,
            None,
            false,
            id_token.map(|s| s.to_string()),
        );
        Account::new("acc-cli".into(), "cli@example.com".into(), token)
    }

    #[test]
    fn payload_keeps_existing_fields() {
        let acc = account_with_id_token(Some("h.p.s"));
        let previous = json!({ "auth_method": "enterprise", "scope": "cloud" });
        let payload = build_payload(&acc, Some(previous));
        assert_eq!(payload["auth_method"], "enterprise");
        assert_eq!(payload["scope"], "cloud");
        assert_eq!(payload["token"]["access_token"], "access-xyz");
        assert_eq!(payload["token"]["refresh_token"], "1//refresh-xyz");
        assert_eq!(payload["token"]["token_type"], "Bearer");
        assert_eq!(payload["id_token"], "h.p.s");
        // expiry is an RFC3339 string, not a number
        let expiry = payload["token"]["expiry"].as_str().unwrap();
        assert!(expiry.contains('T') && expiry.ends_with('Z'));
    }

    #[test]
    fn payload_defaults_to_consumer_auth() {
        let acc = account_with_id_token(None);
        let payload = build_payload(&acc, None);
        assert_eq!(payload["auth_method"], "consumer");
        assert_eq!(payload["token"]["expires_in"], 3600);
    }

    #[test]
    fn decodes_email_from_id_token() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let claims = json!({"email": "someone@example.com", "sub": "1"});
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let id_token = format!("header.{}.signature", payload);
        assert_eq!(
            email_from_id_token(&id_token).as_deref(),
            Some("someone@example.com")
        );
        assert!(email_from_id_token("not-a-jwt").is_none());
    }
}

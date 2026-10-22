//! Synchronises the selected account's credentials into the agy CLI keyring.
//!
//! The agy CLI (Antigravity CLI) stores its active token in the OS keyring.
//! Writing to the keyring is a local operation – no network request is made
//! on behalf of the user beyond the initial OAuth refresh.

use crate::error::{AppError, AppResult};
use crate::models::account::Account;
use crate::modules::logger;

/// The keyring service and entry used by the agy CLI.
pub const KEYRING_SERVICE: &str = "antigravity";
pub const KEYRING_ENTRY: &str = "oauth_token";

/// Write the account's access token into the system keyring so that the
/// agy CLI picks it up on next launch.
pub fn sync_to_keyring(account: &Account) -> AppResult<()> {
    use keyring::Entry;

    logger::log_info(
        "keyring",
        &format!(
            "Writing access token to keyring ({}/{}) for {}",
            KEYRING_SERVICE, KEYRING_ENTRY, account.email
        ),
    );

    let entry = Entry::new(KEYRING_SERVICE, KEYRING_ENTRY).map_err(|e| {
        let msg = format!("Failed to open keyring entry: {}", e);
        logger::log_error("keyring", &msg);
        AppError::Keyring(msg)
    })?;

    entry
        .set_password(&account.token.access_token)
        .map_err(|e| {
            let msg = format!("Failed to write keyring entry: {}", e);
            logger::log_error("keyring", &msg);
            AppError::Keyring(msg)
        })?;

    logger::log_info(
        "keyring",
        &format!(
            "Synced access token for {} to keyring ({}/{})",
            account.email, KEYRING_SERVICE, KEYRING_ENTRY
        ),
    );

    Ok(())
}

/// Read back the currently active keyring token and verify it matches the
/// expected account's access token.
pub fn verify_keyring(expected_token: &str) -> AppResult<bool> {
    use keyring::Entry;

    let entry = Entry::new(KEYRING_SERVICE, KEYRING_ENTRY).map_err(|e| {
        let msg = format!("Failed to open keyring entry for verification: {}", e);
        logger::log_warn("keyring", &msg);
        AppError::Keyring(msg)
    })?;

    match entry.get_password() {
        Ok(stored) => {
            let match_ = stored == expected_token;
            logger::log_info(
                "keyring",
                &format!("Keyring verification: match={}", match_),
            );
            Ok(match_)
        }
        Err(e) => {
            logger::log_warn("keyring", &format!("Could not read keyring entry: {}", e));
            Ok(false)
        }
    }
}

/// Clear the keyring entry (useful when removing the last account).
pub fn clear_keyring() -> AppResult<()> {
    use keyring::Entry;

    logger::log_info("keyring", "Clearing keyring entry");

    let entry = Entry::new(KEYRING_SERVICE, KEYRING_ENTRY).map_err(|e| {
        let msg = format!("Failed to open keyring entry for clearing: {}", e);
        logger::log_warn("keyring", &msg);
        AppError::Keyring(msg)
    })?;

    if entry.get_password().is_ok() {
        entry.delete_credential().map_err(|e| {
            let msg = format!("Failed to delete keyring entry: {}", e);
            logger::log_error("keyring", &msg);
            AppError::Keyring(msg)
        })?;
        logger::log_info("keyring", "Cleared keyring entry");
    } else {
        logger::log_debug("keyring", "Keyring entry was already empty");
    }

    Ok(())
}

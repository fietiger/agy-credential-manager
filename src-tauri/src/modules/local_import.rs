//! One-click import of the accounts that are already signed in on this
//! machine.
//!
//! Each client keeps its own copy of the credential it is using:
//!
//! - **agy CLI** — the OS keyring (`gemini` / `antigravity`) plus a file copy
//!   in `~/.gemini/antigravity-cli/` (see [`crate::modules::agy_sync`]);
//! - **Antigravity** and **Antigravity IDE** — the unified state topic in
//!   their `state.vscdb` (see [`crate::modules::client_sync`]).
//!
//! The same Google account can therefore show up two or three times, so
//! imports are de-duplicated by refresh token and by email before anything is
//! written to the store.

use crate::error::{AppError, AppResult};
use crate::models::account::Account;
use crate::models::token::TokenData;
use crate::modules::client_sync::ClientKind;
use crate::modules::{account_store, agy_sync, client_sync, logger};
use std::collections::HashSet;

/// A credential read from one client, normalised across storage formats.
#[derive(Debug, Clone, Default)]
struct Credential {
    access_token: String,
    refresh_token: String,
    expiry: Option<i64>,
    id_token: Option<String>,
    project_id: Option<String>,
    is_gcp_tos: bool,
    email: Option<String>,
}

/// Per-client outcome, shown in the UI so a client with nothing to import is
/// distinguishable from a client that was skipped as a duplicate.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ClientImport {
    pub client: String,
    pub email: Option<String>,
    /// `imported` / `duplicate` / `no_credential` / `no_email` / `failed`
    pub status: String,
    pub detail: Option<String>,
}

/// Result of a local import, returned to the frontend.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LocalImportSummary {
    pub imported: usize,
    pub skipped_duplicate: usize,
    pub imported_emails: Vec<String>,
    pub clients: Vec<ClientImport>,
}

fn cli_credential() -> Option<Credential> {
    let cred = agy_sync::read_cli_credential()?;
    Some(Credential {
        access_token: cred.access_token,
        refresh_token: cred.refresh_token,
        expiry: cred.expiry,
        id_token: cred.id_token,
        project_id: None,
        is_gcp_tos: false,
        email: cred.email,
    })
}

fn db_credential(kind: ClientKind) -> Option<Credential> {
    let cred = client_sync::read_client_credential(kind)?;
    Some(Credential {
        access_token: cred.access_token,
        refresh_token: cred.refresh_token,
        expiry: cred.expiry,
        id_token: cred.id_token,
        project_id: cred.project_id,
        is_gcp_tos: cred.is_gcp_tos,
        email: cred.email,
    })
}

/// Every client this machine can import from, in display order.
fn collect_credentials() -> Vec<(ClientKind, Option<Credential>)> {
    let mut out = Vec::new();
    for kind in [
        ClientKind::AgyCli,
        ClientKind::Classic,
        ClientKind::Ide,
    ] {
        let cred = match kind {
            ClientKind::AgyCli => cli_credential(),
            _ => db_credential(kind),
        };
        out.push((kind, cred));
    }
    out
}

/// Build a stored account from an imported credential, keeping the real
/// expiry instead of assuming a freshly issued token.
fn build_account(email: &str, cred: &Credential) -> Account {
    let now = chrono::Utc::now().timestamp();
    let mut token = TokenData::new(
        cred.access_token.clone(),
        cred.refresh_token.clone(),
        3600,
        Some(email.to_string()),
        cred.project_id.clone(),
        None,
        cred.is_gcp_tos,
        cred.id_token.clone(),
    );
    if let Some(expiry) = cred.expiry {
        token.expiry_timestamp = expiry;
        token.expires_in = (expiry - now).max(0);
    }
    Account::new(uuid::Uuid::new_v4().to_string(), email.to_string(), token)
}

fn describe_expiry(cred: &Credential) -> Option<String> {
    let expiry = cred.expiry?;
    if expiry <= chrono::Utc::now().timestamp() {
        Some("access token already expired (refresh token kept)".to_string())
    } else {
        None
    }
}

/// Import every account found on the local clients, skipping duplicates.
pub fn import_local_accounts() -> AppResult<LocalImportSummary> {
    // Snapshot what is already managed, so a re-run adds nothing.
    let idx = account_store::load_index()?;
    let mut known_emails: HashSet<String> = HashSet::new();
    let mut known_tokens: HashSet<String> = HashSet::new();
    for summary in &idx.accounts {
        known_emails.insert(summary.email.trim().to_lowercase());
        if let Ok(acc) = account_store::get_account(&summary.id) {
            known_tokens.insert(acc.token.refresh_token);
        }
    }

    let mut result = LocalImportSummary {
        imported: 0,
        skipped_duplicate: 0,
        imported_emails: Vec::new(),
        clients: Vec::new(),
    };

    for (kind, cred) in collect_credentials() {
        let name = kind.name().to_string();

        let Some(cred) = cred else {
            result.clients.push(ClientImport {
                client: name,
                email: None,
                status: "no_credential".to_string(),
                detail: Some("no signed-in credential on this client".to_string()),
            });
            continue;
        };

        let email = match cred.email.as_deref().map(str::trim).filter(|e| !e.is_empty()) {
            Some(email) => email.to_string(),
            None => {
                result.clients.push(ClientImport {
                    client: name,
                    email: None,
                    status: "no_email".to_string(),
                    detail: Some("credential holds no readable account email".to_string()),
                });
                continue;
            }
        };

        let email_key = email.to_lowercase();
        if known_emails.contains(&email_key) || known_tokens.contains(&cred.refresh_token) {
            result.skipped_duplicate += 1;
            result.clients.push(ClientImport {
                client: name,
                email: Some(email),
                status: "duplicate".to_string(),
                detail: Some("already managed".to_string()),
            });
            continue;
        }
        // Claim the token now so a second client holding the same account in
        // this same run is recognised as a duplicate.
        known_tokens.insert(cred.refresh_token.clone());

        let account = build_account(&email, &cred);
        let id = account.id.clone();
        match account_store::add_account(account) {
            Ok(()) => {
                known_emails.insert(email_key);
                // The client really is using this account right now, so record
                // it in that client's slot as well — the badge then shows which
                // clients the account is live in.
                if let Err(e) = account_store::set_client_account(&id, kind) {
                    logger::log_warn(
                        "import",
                        &format!("Could not record {} for {}: {}", email, kind.name(), e),
                    );
                }
                result.imported += 1;
                result.imported_emails.push(email.clone());
                result.clients.push(ClientImport {
                    client: name,
                    email: Some(email),
                    status: "imported".to_string(),
                    detail: describe_expiry(&cred),
                });
            }
            Err(AppError::AccountExists(_)) => {
                result.skipped_duplicate += 1;
                result.clients.push(ClientImport {
                    client: name,
                    email: Some(email),
                    status: "duplicate".to_string(),
                    detail: Some("already managed".to_string()),
                });
            }
            Err(e) => {
                logger::log_error("import", &format!("Import from {} failed: {}", kind.name(), e));
                result.clients.push(ClientImport {
                    client: name,
                    email: Some(email),
                    status: "failed".to_string(),
                    detail: Some(e.to_string()),
                });
            }
        }
    }

    logger::log_info(
        "import",
        &format!(
            "Local import finished: imported={} duplicate={}",
            result.imported, result.skipped_duplicate
        ),
    );
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential(email: Option<&str>, refresh: &str) -> Credential {
        Credential {
            access_token: "access".to_string(),
            refresh_token: refresh.to_string(),
            expiry: Some(chrono::Utc::now().timestamp() + 600),
            id_token: None,
            project_id: Some("proj-1".to_string()),
            is_gcp_tos: true,
            email: email.map(|e| e.to_string()),
        }
    }

    #[test]
    fn build_account_keeps_imported_expiry_and_project() {
        let cred = credential(Some("User@Example.com"), "1//refresh");
        let acc = build_account("User@Example.com", &cred);
        assert_eq!(acc.email, "User@Example.com");
        assert_eq!(acc.token.refresh_token, "1//refresh");
        assert_eq!(acc.token.project_id.as_deref(), Some("proj-1"));
        assert!(acc.token.is_gcp_tos);
        assert_eq!(acc.token.expiry_timestamp, cred.expiry.unwrap());
        assert!(acc.token.expires_in > 0);
    }

    #[test]
    fn expired_credential_is_reported_but_kept() {
        let mut cred = credential(Some("old@example.com"), "1//old");
        cred.expiry = Some(chrono::Utc::now().timestamp() - 10);
        let acc = build_account("old@example.com", &cred);
        assert_eq!(acc.token.expires_in, 0);
        assert!(describe_expiry(&cred).is_some());
    }
}

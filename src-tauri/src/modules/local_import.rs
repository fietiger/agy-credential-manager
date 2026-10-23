//! One-click import of the accounts that are already signed in on this
//! machine.
//!
//! Each client keeps its own copy of the credential it is using:
//!
//! - **agy CLI** — the OS keyring (`gemini` / `antigravity`) plus a file copy
//!   in `~/.gemini/antigravity-cli/` (see [`crate::modules::agy_sync`]);
//! - **Antigravity IDE** — the unified state topic in its `state.vscdb`
//!   (see [`crate::modules::client_sync`]);
//! - **Antigravity** (classic) — signed in through the shared `~/.gemini`
//!   store, exactly like the CLI, so the shared credential is read first
//!   and its `state.vscdb` is only a fallback: current desktop builds no
//!   longer keep the live login there, and whatever the database still
//!   holds may be a stale, signed-out account.
//!
//! The same Google account can therefore show up two or three times, so
//! imports are de-duplicated by refresh token and by email before anything is
//! written to the store.

use crate::error::{AppError, AppResult};
use crate::models::account::{Account, AccountIndex};
use crate::models::token::TokenData;
use crate::modules::client_sync::ClientKind;
use crate::modules::{account_store, agy_sync, client_sync, logger};
use std::collections::{HashMap, HashSet};

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

/// A credential found on a local client, before anything is imported.
///
/// Detection is read-only; the frontend uses this to let the user pick which
/// accounts to import.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ImportCandidate {
    pub client: ClientKind,
    pub client_name: String,
    /// Owner of the credential, when readable.
    pub email: Option<String>,
    /// `new` / `already_managed` / `no_credential` / `no_email`
    pub state: String,
    pub detail: Option<String>,
}

/// One candidate the user ticked in the import picker.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ImportSelection {
    pub client: ClientKind,
    pub email: String,
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

/// The classic desktop app shares its login with the CLI (one shared
/// `~/.gemini` credential in the keyring plus file copy), which is also
/// what `list_clients` reports for it. Read that first and fall back to
/// the client's own `state.vscdb` only when no shared credential exists.
fn classic_credential() -> Option<Credential> {
    cli_credential().or_else(|| db_credential(ClientKind::Classic))
}

/// Every client this machine can import from, in display order.
fn collect_credentials() -> Vec<(ClientKind, Option<Credential>)> {
    let mut out = Vec::new();
    for kind in [ClientKind::AgyCli, ClientKind::Classic, ClientKind::Ide] {
        let cred = match kind {
            ClientKind::AgyCli => cli_credential(),
            ClientKind::Classic => classic_credential(),
            ClientKind::Ide => db_credential(kind),
        };
        out.push((kind, cred));
    }
    out
}

fn credential_email(cred: &Credential) -> Option<String> {
    cred.email
        .as_deref()
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .map(str::to_string)
}

fn managed_email_keys(idx: &AccountIndex) -> HashSet<String> {
    idx.accounts
        .iter()
        .map(|summary| summary.email.trim().to_lowercase())
        .collect()
}

fn managed_refresh_tokens(idx: &AccountIndex) -> HashSet<String> {
    idx.accounts
        .iter()
        .filter_map(|summary| account_store::get_account(&summary.id).ok())
        .map(|account| account.token.refresh_token)
        .collect()
}

/// Detect the credentials the local clients hold without importing anything.
///
/// Clients are resolved exactly like the import does (the classic desktop app
/// prefers the shared `~/.gemini` store), then each credential is classified
/// as `new` or `already_managed`; clients without a usable sign-in report
/// `no_credential` / `no_email`.
pub fn preview_local_import() -> AppResult<Vec<ImportCandidate>> {
    let idx = account_store::load_index()?;
    let known_emails = managed_email_keys(&idx);
    let known_tokens = managed_refresh_tokens(&idx);

    let mut out = Vec::new();
    for (kind, cred) in collect_credentials() {
        let client_name = kind.name().to_string();

        let Some(cred) = cred else {
            out.push(ImportCandidate {
                client: kind,
                client_name,
                email: None,
                state: "no_credential".to_string(),
                detail: Some("no signed-in credential on this client".to_string()),
            });
            continue;
        };

        let Some(email) = credential_email(&cred) else {
            out.push(ImportCandidate {
                client: kind,
                client_name,
                email: None,
                state: "no_email".to_string(),
                detail: Some("credential holds no readable account email".to_string()),
            });
            continue;
        };

        let managed = known_emails.contains(&email.to_lowercase())
            || known_tokens.contains(&cred.refresh_token);
        out.push(ImportCandidate {
            client: kind,
            client_name,
            email: Some(email),
            state: if managed { "already_managed" } else { "new" }.to_string(),
            detail: managed.then(|| "already in library".to_string()),
        });
    }
    Ok(out)
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
    import_local_accounts_selected(None)
}

/// Import the local clients' accounts, optionally restricted to the
/// client/email rows the user picked in the import picker. `None` imports
/// everything, preserving the original one-shot behaviour.
pub fn import_local_accounts_selected(
    selected: Option<&[ImportSelection]>,
) -> AppResult<LocalImportSummary> {
    // Snapshot what is already managed, so a re-run adds nothing.
    let idx = account_store::load_index()?;
    let mut email_to_id: HashMap<String, String> = HashMap::new();
    for summary in &idx.accounts {
        email_to_id.insert(summary.email.trim().to_lowercase(), summary.id.clone());
    }
    let mut known_emails = managed_email_keys(&idx);
    let mut known_tokens = managed_refresh_tokens(&idx);

    let mut result = LocalImportSummary {
        imported: 0,
        skipped_duplicate: 0,
        imported_emails: Vec::new(),
        clients: Vec::new(),
    };

    for (kind, cred) in collect_credentials() {
        let name = kind.name().to_string();

        // A client the user did not pick produces no result row at all, so
        // the picker's results mirror the selection.
        if let Some(selected) = selected {
            if !selected.iter().any(|s| s.client == kind) {
                continue;
            }
        }

        let Some(cred) = cred else {
            result.clients.push(ClientImport {
                client: name,
                email: None,
                status: "no_credential".to_string(),
                detail: Some("no signed-in credential on this client".to_string()),
            });
            continue;
        };

        let email = match credential_email(&cred) {
            Some(email) => email,
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

        // Only rows the user ticked are imported. A credential that changed
        // between detection and import simply matches nothing.
        if let Some(selected) = selected {
            let picked = selected
                .iter()
                .any(|s| s.client == kind && s.email.trim().eq_ignore_ascii_case(&email));
            if !picked {
                continue;
            }
        }

        let email_key = email.to_lowercase();
        if known_emails.contains(&email_key) || known_tokens.contains(&cred.refresh_token) {
            result.skipped_duplicate += 1;
            // Already managed is not a reason to skip the slot: when the
            // same account is live in another client as well (the classic
            // desktop app shares the CLI credential), record this client
            // on the account so its badge reflects reality.
            if let Some(existing_id) = email_to_id.get(&email_key) {
                if let Err(e) = account_store::set_client_account(existing_id, kind) {
                    logger::log_warn(
                        "import",
                        &format!("Could not record {} for {}: {}", email, kind.name(), e),
                    );
                }
            }
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
                email_to_id.insert(email_key.clone(), id.clone());
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
                logger::log_error(
                    "import",
                    &format!("Import from {} failed: {}", kind.name(), e),
                );
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
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::sync::{Mutex, MutexGuard};

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

    // ── Import fixtures ────────────────────────────────────────────────
    //
    // The import code resolves the shared `~/.gemini` store through
    // `dirs::home_dir` and the client databases through the platform config
    // dir, so each test points those env vars at a throwaway tree. The lock
    // serialises the process-wide variables between tests.

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct IsolatedEnv {
        root: PathBuf,
        saved: Vec<(&'static str, Option<OsString>)>,
        _lock: MutexGuard<'static, ()>,
    }

    impl IsolatedEnv {
        fn new(tag: &str) -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let root = std::env::temp_dir().join(format!(
                "agy-local-import-test-{}-{}",
                std::process::id(),
                tag
            ));
            let _ = std::fs::remove_dir_all(&root);
            let home = root.join("home");
            let config = root.join("config");
            let data = root.join("data");
            for dir in [&home, &config, &data] {
                std::fs::create_dir_all(dir).unwrap();
            }

            let mut saved = Vec::new();
            let vars = [
                ("HOME", home.clone()),
                ("USERPROFILE", home),
                ("XDG_CONFIG_HOME", config.clone()),
                ("XDG_DATA_HOME", data.clone()),
                ("APPDATA", config),
                ("LOCALAPPDATA", data),
            ];
            for (key, value) in vars {
                saved.push((key, std::env::var_os(key)));
                std::env::set_var(key, value);
            }

            Self {
                root,
                saved,
                _lock: lock,
            }
        }
    }

    impl Drop for IsolatedEnv {
        fn drop(&mut self) {
            for (key, value) in &self.saved {
                match value {
                    Some(v) => std::env::set_var(key, v),
                    None => std::env::remove_var(key),
                }
            }
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    /// Write the shared `~/.gemini` login the CLI and the classic desktop app
    /// both use: the token file plus the active-account record.
    fn write_shared_credential(email: &str, refresh_token: &str) {
        let home = dirs::home_dir().expect("home dir");
        let cli_dir = home.join(".gemini").join("antigravity-cli");
        std::fs::create_dir_all(&cli_dir).unwrap();

        let expiry = (chrono::Utc::now() + chrono::Duration::hours(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let doc = serde_json::json!({
            "token": {
                "access_token": "access-shared",
                "token_type": "Bearer",
                "refresh_token": refresh_token,
                "expiry": expiry,
                "expires_in": 3599,
            },
            "auth_method": "consumer",
        });
        std::fs::write(
            cli_dir.join("antigravity-oauth-token"),
            serde_json::to_string_pretty(&doc).unwrap(),
        )
        .unwrap();

        // The fixtures carry no id_token, so the email comes from here.
        let accounts = serde_json::json!({ "active": email, "old": [] });
        std::fs::write(
            home.join(".gemini").join("google_accounts.json"),
            serde_json::to_string_pretty(&accounts).unwrap(),
        )
        .unwrap();
    }

    /// Write a credential into a client's `state.vscdb` using the same
    /// serializer the real clients use.
    fn write_db_credential(kind: ClientKind, email: &str, refresh_token: &str) {
        let db = client_sync::candidate_db_paths(kind)
            .into_iter()
            .next()
            .expect("client db candidate path");
        std::fs::create_dir_all(db.parent().unwrap()).unwrap();

        let token = TokenData::new(
            format!("access-{}", kind.name()),
            refresh_token.to_string(),
            3600,
            Some(email.to_string()),
            Some("proj-db".to_string()),
            None,
            false,
            None,
        );
        let account = Account::new(format!("fixture-{}", kind.name()), email.to_string(), token);
        client_sync::inject_account(&db, &account).expect("write client db fixture");
    }

    fn status_of(summary: &LocalImportSummary, kind: ClientKind) -> &str {
        summary
            .clients
            .iter()
            .find(|c| c.client == kind.name())
            .map(|c| c.status.as_str())
            .unwrap_or_else(|| panic!("no import row for {}", kind.name()))
    }

    #[test]
    fn shared_credential_imports_once_and_records_both_clients() {
        let _env = IsolatedEnv::new("shared-only");
        write_shared_credential("shared@example.com", "1//shared");

        let summary = import_local_accounts().unwrap();

        assert_eq!(summary.imported, 1);
        assert_eq!(summary.imported_emails, vec!["shared@example.com"]);
        assert_eq!(summary.skipped_duplicate, 1);
        assert_eq!(status_of(&summary, ClientKind::AgyCli), "imported");
        assert_eq!(status_of(&summary, ClientKind::Classic), "duplicate");
        assert_eq!(status_of(&summary, ClientKind::Ide), "no_credential");

        let idx = account_store::load_index().unwrap();
        assert_eq!(idx.accounts.len(), 1);
        let slots = account_store::active_clients_for(&idx, &idx.accounts[0].id);
        assert!(slots.contains(&ClientKind::AgyCli));
        assert!(slots.contains(&ClientKind::Classic));
        assert!(!slots.contains(&ClientKind::Ide));
    }

    #[test]
    fn shared_credential_wins_over_stale_classic_db_account() {
        let _env = IsolatedEnv::new("shared-vs-stale");
        write_shared_credential("shared@example.com", "1//shared");
        // The desktop database still holds a different, signed-out account.
        write_db_credential(ClientKind::Classic, "stale@example.com", "1//stale");

        let summary = import_local_accounts().unwrap();

        assert_eq!(summary.imported, 1);
        assert_eq!(summary.imported_emails, vec!["shared@example.com"]);
        assert_eq!(status_of(&summary, ClientKind::AgyCli), "imported");
        assert_eq!(status_of(&summary, ClientKind::Classic), "duplicate");
        assert_eq!(status_of(&summary, ClientKind::Ide), "no_credential");

        let idx = account_store::load_index().unwrap();
        assert_eq!(idx.accounts.len(), 1);
        assert_eq!(idx.accounts[0].email, "shared@example.com");
        assert!(idx.accounts.iter().all(|a| a.email != "stale@example.com"));

        let slots = account_store::active_clients_for(&idx, &idx.accounts[0].id);
        assert!(slots.contains(&ClientKind::AgyCli));
        assert!(slots.contains(&ClientKind::Classic));
    }

    #[test]
    fn ide_db_credential_still_imports() {
        let _env = IsolatedEnv::new("ide-only");
        write_db_credential(ClientKind::Ide, "ide@example.com", "1//ide");

        let summary = import_local_accounts().unwrap();

        assert_eq!(summary.imported, 1);
        assert_eq!(summary.imported_emails, vec!["ide@example.com"]);
        assert_eq!(status_of(&summary, ClientKind::AgyCli), "no_credential");
        assert_eq!(status_of(&summary, ClientKind::Classic), "no_credential");
        assert_eq!(status_of(&summary, ClientKind::Ide), "imported");

        let idx = account_store::load_index().unwrap();
        assert_eq!(idx.accounts.len(), 1);
        let slots = account_store::active_clients_for(&idx, &idx.accounts[0].id);
        assert!(slots.contains(&ClientKind::Ide));
    }

    #[test]
    fn classic_db_credential_is_used_as_fallback() {
        let _env = IsolatedEnv::new("classic-only");
        write_db_credential(ClientKind::Classic, "classic@example.com", "1//classic");

        let summary = import_local_accounts().unwrap();

        assert_eq!(summary.imported, 1);
        assert_eq!(summary.imported_emails, vec!["classic@example.com"]);
        assert_eq!(status_of(&summary, ClientKind::AgyCli), "no_credential");
        assert_eq!(status_of(&summary, ClientKind::Classic), "imported");
        assert_eq!(status_of(&summary, ClientKind::Ide), "no_credential");

        let idx = account_store::load_index().unwrap();
        assert_eq!(idx.accounts.len(), 1);
        assert_eq!(idx.accounts[0].email, "classic@example.com");
        let slots = account_store::active_clients_for(&idx, &idx.accounts[0].id);
        assert!(slots.contains(&ClientKind::Classic));
    }

    fn library_account(email: &str, refresh_token: &str) -> Account {
        let token = TokenData::new(
            "access".to_string(),
            refresh_token.to_string(),
            3600,
            Some(email.to_string()),
            None,
            None,
            false,
            None,
        );
        Account::new(format!("acc-{}", email), email.to_string(), token)
    }

    fn candidate_for(candidates: &[ImportCandidate], kind: ClientKind) -> &ImportCandidate {
        candidates
            .iter()
            .find(|c| c.client == kind)
            .unwrap_or_else(|| panic!("no candidate for {}", kind.name()))
    }

    #[test]
    fn preview_lists_states_without_writing() {
        let _env = IsolatedEnv::new("preview-states");
        write_shared_credential("shared@example.com", "1//shared");
        write_db_credential(ClientKind::Classic, "stale@example.com", "1//stale");

        let candidates = preview_local_import().unwrap();

        let cli = candidate_for(&candidates, ClientKind::AgyCli);
        assert_eq!(cli.state, "new");
        assert_eq!(cli.email.as_deref(), Some("shared@example.com"));

        // Detection resolves the shared store first, like the import does, so
        // the stale database account is never offered.
        let classic = candidate_for(&candidates, ClientKind::Classic);
        assert_eq!(classic.state, "new");
        assert_eq!(classic.email.as_deref(), Some("shared@example.com"));

        let ide = candidate_for(&candidates, ClientKind::Ide);
        assert_eq!(ide.state, "no_credential");
        assert!(ide.email.is_none());

        // Detection must not write any account.
        assert!(account_store::load_index().unwrap().accounts.is_empty());
    }

    #[test]
    fn preview_marks_accounts_already_in_library() {
        let _env = IsolatedEnv::new("preview-managed");
        account_store::add_account(library_account("shared@example.com", "1//shared")).unwrap();
        write_shared_credential("shared@example.com", "1//shared");

        let candidates = preview_local_import().unwrap();

        for kind in [ClientKind::AgyCli, ClientKind::Classic] {
            let row = candidate_for(&candidates, kind);
            assert_eq!(row.state, "already_managed");
            assert_eq!(row.email.as_deref(), Some("shared@example.com"));
            assert_eq!(row.detail.as_deref(), Some("already in library"));
        }
        assert_eq!(
            candidate_for(&candidates, ClientKind::Ide).state,
            "no_credential"
        );

        // Detection did not add the account again.
        assert_eq!(account_store::load_index().unwrap().accounts.len(), 1);
    }

    #[test]
    fn import_selected_imports_only_checked_clients() {
        let _env = IsolatedEnv::new("selected-subset");
        write_shared_credential("shared@example.com", "1//shared");
        write_db_credential(ClientKind::Ide, "ide@example.com", "1//ide");

        let selection = [ImportSelection {
            client: ClientKind::Ide,
            email: "ide@example.com".to_string(),
        }];
        let summary = import_local_accounts_selected(Some(&selection)).unwrap();

        assert_eq!(summary.imported, 1);
        assert_eq!(summary.imported_emails, vec!["ide@example.com"]);
        assert_eq!(summary.clients.len(), 1);
        assert_eq!(summary.clients[0].client, ClientKind::Ide.name());
        assert_eq!(summary.clients[0].status, "imported");

        let idx = account_store::load_index().unwrap();
        assert_eq!(idx.accounts.len(), 1);
        assert_eq!(idx.accounts[0].email, "ide@example.com");
    }

    #[test]
    fn empty_selection_imports_nothing() {
        let _env = IsolatedEnv::new("empty-selection");
        write_shared_credential("shared@example.com", "1//shared");

        let summary = import_local_accounts_selected(Some(&[])).unwrap();

        assert_eq!(summary.imported, 0);
        assert_eq!(summary.skipped_duplicate, 0);
        assert!(summary.clients.is_empty());
        assert!(account_store::load_index().unwrap().accounts.is_empty());
    }
}

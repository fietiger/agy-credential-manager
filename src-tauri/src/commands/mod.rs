//! Tauri IPC command handlers exposed to the frontend.

use crate::error::{AppError, AppResult};
use crate::models::account::{Account, AccountExportResponse, DeviceProfile};
use crate::modules::account_store;
use crate::modules::agy_sync;
use crate::modules::client_sync;
use crate::modules::device;
use crate::modules::local_import;
use crate::modules::logger;
use crate::modules::oauth;
use serde::Serialize;
use tauri::Manager;

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

    let mut result = match target {
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
        // Re-apply the account's bound device fingerprint, if any, so an
        // account and its fingerprint always travel together (VS Code
        // clients only; the CLI has no storage.json fingerprint).
        if target != client_sync::ClientKind::AgyCli {
            if let Some(profile) = &acc.device_profile {
                match device::apply_profile(target, profile) {
                    Ok(()) => result.detail.push_str("; device fingerprint applied"),
                    Err(e) => result
                        .detail
                        .push_str(&format!("; device fingerprint failed: {}", e)),
                }
            }
        }
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

/// Prepare the OAuth flow and return the authorization URL.
/// The URL is shown in the UI (with a Copy button) before anything opens, so
/// the user can authorize in any browser where they are signed in to Google.
/// Listeners start now, so an early authorization is not lost.
#[tauri::command]
pub async fn oauth_prepare() -> AppResult<String> {
    oauth::prepare_oauth().await
}

/// Start OAuth: opens the default browser and waits for the code (via the
/// loopback callback or a manual submission), then stores the account.
#[tauri::command]
pub async fn oauth_start() -> AppResult<AccountView> {
    finish_oauth(oauth::wait_for_oauth(true).await?)
}

/// Complete OAuth without opening the browser: the user authorized through
/// the copied link in their preferred browser; just wait for the code.
#[tauri::command]
pub async fn oauth_complete() -> AppResult<AccountView> {
    finish_oauth(oauth::wait_for_oauth(false).await?)
}

/// Manually submit an authorization code (or a full callback link) — for
/// when the browser redirect could not reach this machine.
#[tauri::command]
pub async fn oauth_submit_code(code: String) -> AppResult<()> {
    oauth::submit_oauth_code(&code).await
}

/// Cancel the active OAuth flow.
#[tauri::command]
pub fn oauth_cancel() -> AppResult<()> {
    oauth::cancel_oauth();
    Ok(())
}

fn finish_oauth(result: oauth::OAuthResult) -> AppResult<AccountView> {
    let email = result
        .email
        .clone()
        .unwrap_or_else(|| "unknown".to_string());
    let id = uuid::Uuid::new_v4().to_string();
    let account = Account::new(id, email, result.token);
    account_store::add_account(account.clone())?;
    Ok(AccountView::from(&account))
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

// ---------------------------------------------------------------------------
// Device fingerprints
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn device_overview(id: String) -> AppResult<device::DeviceOverview> {
    // Logged so a window that stays blank can be told apart from a window whose
    // page never loaded at all.
    logger::log_info("device", "device overview requested by a window");
    device::overview(&id)
}

#[tauri::command]
pub fn device_capture_bind(
    id: String,
    source: client_sync::ClientKind,
) -> AppResult<DeviceProfile> {
    device::capture_and_bind(&id, source)
}

#[tauri::command]
pub fn device_generate_profile() -> DeviceProfile {
    device::generate_profile()
}

#[tauri::command]
pub fn device_bind_profile(
    id: String,
    profile: DeviceProfile,
    label: String,
) -> AppResult<DeviceProfile> {
    device::bind_profile(&id, profile, &label)
}

#[tauri::command]
pub fn device_generate_and_bind(id: String) -> AppResult<DeviceProfile> {
    device::generate_and_bind(&id)
}

#[tauri::command]
pub fn device_apply(id: String, target: client_sync::ClientKind) -> AppResult<DeviceProfile> {
    device::apply_bound(&id, target)
}

#[tauri::command]
pub fn device_restore_version(id: String, version_id: String) -> AppResult<DeviceProfile> {
    device::restore_version(&id, &version_id)
}

#[tauri::command]
pub fn device_delete_version(id: String, version_id: String) -> AppResult<()> {
    device::delete_version(&id, &version_id)
}

#[tauri::command]
pub fn device_restore_original(id: String) -> AppResult<DeviceProfile> {
    device::restore_original(&id)
}

/// Open the fingerprint window for one account, or focus it if it is already
/// open (one window per account).
#[tauri::command]
pub fn open_fingerprint_window(app: tauri::AppHandle, id: String) -> AppResult<()> {
    let label = format!("fp-{}", id);
    if let Some(win) = app.get_webview_window(&label) {
        let _ = win.unminimize();
        let _ = win.set_focus();
        return Ok(());
    }

    let email = account_store::get_account(&id)
        .map(|a| a.email)
        .unwrap_or_else(|_| "unknown account".to_string());

    // The account id is injected as a global instead of a `?id=` query, because
    // the asset resolver treats the URI as a file path and a query string there
    // gives a blank page.
    let init_script = format!(
        "window.__ACCOUNT_ID__ = {};",
        serde_json::to_string(&id).unwrap_or_else(|_| "\"\"".to_string())
    );

    let mut builder = tauri::WebviewWindowBuilder::new(
        &app,
        &label,
        tauri::WebviewUrl::App("fingerprint.html".into()),
    )
    .title(format!("Device fingerprint — {}", email))
    .initialization_script(&init_script)
    .inner_size(680.0, 820.0)
    .min_inner_size(520.0, 480.0)
    .center();

    // The main window needs `--in-process-gpu` where the WebView2 GPU process
    // cannot start (virtual displays); a window created at runtime does not
    // inherit that config, so reuse it instead of hard-coding a second copy.
    if let Some(args) = app
        .config()
        .app
        .windows
        .first()
        .and_then(|w| w.additional_browser_args.clone())
    {
        builder = builder.additional_browser_args(&args);
    }

    builder
        .build()
        .map_err(|e| AppError::Other(format!("failed to open fingerprint window: {}", e)))?;
    Ok(())
}

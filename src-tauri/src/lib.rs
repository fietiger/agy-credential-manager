mod commands;
mod error;
mod models;
mod modules;

use crate::modules::logger;
use commands::*;

pub fn run() {
    // Initialise logger (verbose if AGY_LOG_DEBUG=1)
    let verbose = std::env::var("AGY_LOG_DEBUG").is_ok();
    logger::init(verbose);
    logger::log_info(
        "app",
        &format!(
            "agy-credential-manager {} starting",
            env!("CARGO_PKG_VERSION")
        ),
    );
    logger::log_info("app", &format!("log file: {}", logger::log_dir_display()));

    let result = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            // account ops
            list_accounts,
            get_account,
            delete_account,
            set_active_account,
            // oauth
            oauth_prepare,
            oauth_start,
            oauth_complete,
            oauth_submit_code,
            oauth_cancel,
            import_refresh_token,
            import_accounts_json,
            preview_local_import,
            import_local_accounts,
            list_clients,
            // device fingerprints
            device_overview,
            device_capture_bind,
            device_generate_profile,
            device_bind_profile,
            device_generate_and_bind,
            device_apply,
            device_restore_version,
            device_delete_version,
            device_restore_original,
            // status
            get_status,
            // export
            export_accounts,
            default_export_path,
            choose_export_path,
            save_export_file,
            // logs
            open_log_dir,
        ])
        .run(tauri::generate_context!());

    if let Err(e) = result {
        logger::log_error("app", &format!("Tauri runtime exited with error: {}", e));
    }
}

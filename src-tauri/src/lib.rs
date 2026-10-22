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
        .invoke_handler(tauri::generate_handler![
            // account ops
            list_accounts,
            get_account,
            delete_account,
            set_active_account,
            // oauth
            start_oauth,
            poll_oauth,
            import_refresh_token,
            import_accounts_json,
            import_local_accounts,
            list_clients,
            // status
            get_status,
            // export
            export_accounts,
            // logs
            open_log_dir,
        ])
        .run(tauri::generate_context!());

    if let Err(e) = result {
        logger::log_error("app", &format!("Tauri runtime exited with error: {}", e));
    }
}

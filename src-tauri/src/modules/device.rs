//! Device fingerprint management, modeled on Antigravity-Manager.
//!
//! A device fingerprint is the set of telemetry identifiers a VS Code based
//! client keeps in `storage.json` (next to `state.vscdb`):
//! `machineId`, `macMachineId`, `devDeviceId`, `sqmId`, plus the mirrored
//! `storage.serviceMachineId` (also synced into `state.vscdb`).
//!
//! Fingerprints can be bound to an account: the account stores its bound
//! profile plus a history of versions, and switching the account into a
//! client re-applies the bound fingerprint. The first fingerprint ever
//! captured from this machine is kept as the global "original" baseline
//! (`device_original.json` in the data dir) and is never overwritten.

use std::path::{Path, PathBuf};

use rusqlite::Connection;
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::models::account::{Account, DeviceProfile, DeviceProfileVersion};
use crate::modules::{account_store, client_sync, logger};

const BASELINE_FILE: &str = "device_original.json";

fn other(msg: impl Into<String>) -> AppError {
    AppError::Other(msg.into())
}

/// `storage.json` living next to a client's `state.vscdb`, if installed.
pub fn storage_path_for(kind: client_sync::ClientKind) -> Option<PathBuf> {
    client_sync::installed_db_path(kind)
        .and_then(|db| db.parent().map(|dir| dir.join("storage.json")))
}

/// Read the fingerprint from a `storage.json` (nested or flat telemetry keys).
pub fn read_profile(storage_path: &Path) -> AppResult<DeviceProfile> {
    let content = std::fs::read_to_string(storage_path)
        .map_err(|e| other(format!("read {}: {}", storage_path.display(), e)))?;
    let json: Value = serde_json::from_str(&content)
        .map_err(|e| other(format!("parse {}: {}", storage_path.display(), e)))?;

    let get_field = |key: &str| -> Option<String> {
        if let Some(obj) = json.get("telemetry").and_then(|v| v.as_object()) {
            if let Some(v) = obj.get(key).and_then(|v| v.as_str()) {
                return Some(v.to_string());
            }
        }
        json.get(format!("telemetry.{key}"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    };

    Ok(DeviceProfile {
        machine_id: get_field("machineId")
            .ok_or_else(|| other("storage.json is missing telemetry.machineId"))?,
        mac_machine_id: get_field("macMachineId")
            .ok_or_else(|| other("storage.json is missing telemetry.macMachineId"))?,
        dev_device_id: get_field("devDeviceId")
            .ok_or_else(|| other("storage.json is missing telemetry.devDeviceId"))?,
        sqm_id: get_field("sqmId")
            .ok_or_else(|| other("storage.json is missing telemetry.sqmId"))?,
    })
}

/// Write a fingerprint into `storage.json`, creating the file if needed, and
/// sync `storage.serviceMachineId` into the sibling `state.vscdb`.
pub fn write_profile(storage_path: &Path, profile: &DeviceProfile) -> AppResult<()> {
    let mut json: Value = if storage_path.exists() {
        let content = std::fs::read_to_string(storage_path)
            .map_err(|e| other(format!("read {}: {}", storage_path.display(), e)))?;
        serde_json::from_str(&content)
            .map_err(|e| other(format!("parse {}: {}", storage_path.display(), e)))?
    } else {
        if let Some(parent) = storage_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        serde_json::json!({})
    };

    if !json
        .get("telemetry")
        .map(|v| v.is_object())
        .unwrap_or(false)
    {
        if json.as_object_mut().is_some() {
            json["telemetry"] = serde_json::json!({});
        } else {
            return Err(other("storage.json top level is not an object"));
        }
    }
    if let Some(telemetry) = json.get_mut("telemetry").and_then(|v| v.as_object_mut()) {
        telemetry.insert(
            "machineId".into(),
            Value::String(profile.machine_id.clone()),
        );
        telemetry.insert(
            "macMachineId".into(),
            Value::String(profile.mac_machine_id.clone()),
        );
        telemetry.insert(
            "devDeviceId".into(),
            Value::String(profile.dev_device_id.clone()),
        );
        telemetry.insert("sqmId".into(), Value::String(profile.sqm_id.clone()));
    }
    if let Some(map) = json.as_object_mut() {
        map.insert(
            "telemetry.machineId".into(),
            Value::String(profile.machine_id.clone()),
        );
        map.insert(
            "telemetry.macMachineId".into(),
            Value::String(profile.mac_machine_id.clone()),
        );
        map.insert(
            "telemetry.devDeviceId".into(),
            Value::String(profile.dev_device_id.clone()),
        );
        map.insert(
            "telemetry.sqmId".into(),
            Value::String(profile.sqm_id.clone()),
        );
        map.insert(
            "storage.serviceMachineId".into(),
            Value::String(profile.dev_device_id.clone()),
        );
    }

    let updated = serde_json::to_string_pretty(&json)?;
    std::fs::write(storage_path, updated)
        .map_err(|e| other(format!("write {}: {}", storage_path.display(), e)))?;
    logger::log_info(
        "device",
        &format!("fingerprint written to {}", storage_path.display()),
    );

    let _ = sync_state_service_machine_id(storage_path, &profile.dev_device_id);
    Ok(())
}

fn sync_state_service_machine_id(storage_path: &Path, service_id: &str) -> AppResult<()> {
    let dir = storage_path
        .parent()
        .ok_or_else(|| other("storage.json has no parent dir"))?;
    let db_path = dir.join("state.vscdb");
    if !db_path.exists() {
        logger::log_warn(
            "device",
            &format!("state.vscdb missing next to {}", storage_path.display()),
        );
        return Ok(());
    }
    let conn = Connection::open(&db_path).map_err(|e| other(format!("open state.vscdb: {}", e)))?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ItemTable (key TEXT PRIMARY KEY, value TEXT)",
        [],
    )
    .map_err(|e| other(format!("create ItemTable: {}", e)))?;
    conn.execute(
        "INSERT OR REPLACE INTO ItemTable (key, value) VALUES ('storage.serviceMachineId', ?1)",
        [service_id],
    )
    .map_err(|e| other(format!("write serviceMachineId: {}", e)))?;
    Ok(())
}

/// Generate a fresh fingerprint in the formats the clients use.
pub fn generate_profile() -> DeviceProfile {
    DeviceProfile {
        machine_id: format!("auth0|user_{}", random_alnum_lower(32)),
        mac_machine_id: Uuid::new_v4().to_string(),
        dev_device_id: Uuid::new_v4().to_string(),
        sqm_id: format!("{{{}}}", Uuid::new_v4().to_string().to_uppercase()),
    }
}

fn random_alnum_lower(len: usize) -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut out = String::with_capacity(len);
    while out.len() < len {
        for b in Uuid::new_v4().as_bytes() {
            if out.len() >= len {
                break;
            }
            out.push(CHARS[(b % 36) as usize] as char);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Global original baseline
// ---------------------------------------------------------------------------

fn baseline_path() -> AppResult<PathBuf> {
    Ok(account_store::data_dir()?.join(BASELINE_FILE))
}

pub fn load_baseline() -> Option<DeviceProfile> {
    let path = baseline_path().ok()?;
    let content = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
}

fn save_baseline_if_absent(profile: &DeviceProfile) -> AppResult<()> {
    let path = baseline_path()?;
    if path.exists() {
        return Ok(());
    }
    std::fs::write(&path, serde_json::to_string_pretty(profile)?)?;
    logger::log_info("device", "original fingerprint baseline saved");
    Ok(())
}

// ---------------------------------------------------------------------------
// Account-bound profiles
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct ClientFingerprint {
    pub client: client_sync::ClientKind,
    pub client_name: String,
    pub installed: bool,
    pub profile: Option<DeviceProfile>,
}

#[derive(Debug, Serialize)]
pub struct DeviceOverview {
    pub clients: Vec<ClientFingerprint>,
    pub bound_profile: Option<DeviceProfile>,
    pub history: Vec<DeviceProfileVersion>,
    pub baseline: Option<DeviceProfile>,
}

/// Everything the UI needs: each VS Code client's live fingerprint, the
/// account's bound profile and history, and the global original baseline.
pub fn overview(account_id: &str) -> AppResult<DeviceOverview> {
    let account = account_store::get_account(account_id)?;
    let mut clients = Vec::new();
    for kind in [
        client_sync::ClientKind::Classic,
        client_sync::ClientKind::Ide,
    ] {
        let path = storage_path_for(kind);
        let profile = path.as_deref().and_then(|p| read_profile(p).ok());
        clients.push(ClientFingerprint {
            client: kind,
            client_name: kind.name().to_string(),
            installed: path.is_some(),
            profile,
        });
    }
    Ok(DeviceOverview {
        clients,
        bound_profile: account.device_profile.clone(),
        history: account.device_history.clone(),
        baseline: load_baseline(),
    })
}

/// Pure binding step (unit tested): set the account's bound profile and
/// append a history version flagged current.
pub fn bind_to_account(account: &mut Account, profile: DeviceProfile, label: &str) {
    for h in account.device_history.iter_mut() {
        h.is_current = false;
    }
    account.device_history.push(DeviceProfileVersion {
        id: Uuid::new_v4().to_string(),
        created_at: chrono::Utc::now().timestamp(),
        label: label.to_string(),
        profile: profile.clone(),
        is_current: true,
    });
    account.device_profile = Some(profile);
}

/// Capture a client's live fingerprint and bind it to the account. The first
/// capture ever also becomes the global original baseline.
pub fn capture_and_bind(
    account_id: &str,
    source: client_sync::ClientKind,
) -> AppResult<DeviceProfile> {
    let path = storage_path_for(source)
        .ok_or_else(|| other(format!("{} is not installed", source.name())))?;
    let profile = read_profile(&path)?;
    save_baseline_if_absent(&profile)?;
    let mut account = account_store::get_account(account_id)?;
    bind_to_account(&mut account, profile.clone(), "capture");
    account_store::save_account(&account)?;
    Ok(profile)
}

/// Bind a profile prepared elsewhere (generated preview or manual values).
pub fn bind_profile(
    account_id: &str,
    profile: DeviceProfile,
    label: &str,
) -> AppResult<DeviceProfile> {
    let mut account = account_store::get_account(account_id)?;
    bind_to_account(&mut account, profile.clone(), label);
    account_store::save_account(&account)?;
    Ok(profile)
}

/// Generate a fresh fingerprint and bind it in one step.
pub fn generate_and_bind(account_id: &str) -> AppResult<DeviceProfile> {
    bind_profile(account_id, generate_profile(), "generated")
}

/// Write the account's bound fingerprint into a client's `storage.json`.
pub fn apply_bound(account_id: &str, target: client_sync::ClientKind) -> AppResult<DeviceProfile> {
    let account = account_store::get_account(account_id)?;
    let profile = account
        .device_profile
        .clone()
        .ok_or_else(|| other("account has no bound device fingerprint"))?;
    apply_profile(target, &profile)?;
    Ok(profile)
}

/// Write a profile into a client's `storage.json` (used on account switch).
pub fn apply_profile(target: client_sync::ClientKind, profile: &DeviceProfile) -> AppResult<()> {
    let path = storage_path_for(target)
        .ok_or_else(|| other(format!("{} is not installed", target.name())))?;
    write_profile(&path, profile)
}

/// Make a history version (or "baseline") the account's bound profile.
/// Does not write to any client until applied.
pub fn restore_version(account_id: &str, version_id: &str) -> AppResult<DeviceProfile> {
    let mut account = account_store::get_account(account_id)?;
    let profile = if version_id == "baseline" {
        load_baseline().ok_or_else(|| other("no original fingerprint has been captured yet"))?
    } else if let Some(v) = account.device_history.iter().find(|v| v.id == version_id) {
        v.profile.clone()
    } else {
        return Err(other("device fingerprint version not found"));
    };
    for h in account.device_history.iter_mut() {
        h.is_current = h.id == version_id;
    }
    account.device_profile = Some(profile.clone());
    account_store::save_account(&account)?;
    Ok(profile)
}

/// Delete a history version. The baseline and the currently bound version
/// cannot be deleted.
pub fn delete_version(account_id: &str, version_id: &str) -> AppResult<()> {
    if version_id == "baseline" {
        return Err(other("the original fingerprint cannot be deleted"));
    }
    let mut account = account_store::get_account(account_id)?;
    if account
        .device_history
        .iter()
        .any(|v| v.id == version_id && v.is_current)
    {
        return Err(other("the currently bound fingerprint cannot be deleted"));
    }
    let before = account.device_history.len();
    account.device_history.retain(|v| v.id != version_id);
    if account.device_history.len() == before {
        return Err(other("device fingerprint version not found"));
    }
    account_store::save_account(&account)?;
    Ok(())
}

/// Reset the account's bound profile to the global original baseline.
pub fn restore_original(account_id: &str) -> AppResult<DeviceProfile> {
    restore_version(account_id, "baseline")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::token::TokenData;

    /// Minimal temp dir (avoids a tempfile dev-dependency).
    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("agy-device-test-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn sample_account() -> Account {
        Account::new(
            "id-1".into(),
            "a@example.com".into(),
            TokenData::new(
                "at".into(),
                "rt".into(),
                3600,
                None,
                None,
                None,
                false,
                None,
            ),
        )
    }

    #[test]
    fn generated_profile_formats() {
        let p = generate_profile();
        assert!(p.machine_id.starts_with("auth0|user_"));
        assert_eq!(p.machine_id.len(), "auth0|user_".len() + 32);
        assert!(p
            .machine_id
            .chars()
            .skip("auth0|user_".len())
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
        assert_eq!(p.mac_machine_id.len(), 36);
        assert_eq!(p.dev_device_id.len(), 36);
        assert!(p.sqm_id.starts_with('{') && p.sqm_id.ends_with('}'));
        assert_ne!(generate_profile().dev_device_id, p.dev_device_id);
    }

    #[test]
    fn write_then_read_roundtrip_and_state_sync() {
        let dir = TestDir::new();
        let storage = dir.path().join("storage.json");
        std::fs::write(&storage, "{}").unwrap();
        Connection::open(dir.path().join("state.vscdb")).unwrap();

        let profile = generate_profile();
        write_profile(&storage, &profile).unwrap();
        let back = read_profile(&storage).unwrap();
        assert_eq!(back, profile);

        let stored: String = Connection::open(dir.path().join("state.vscdb"))
            .unwrap()
            .query_row(
                "SELECT value FROM ItemTable WHERE key = 'storage.serviceMachineId'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored, profile.dev_device_id);
    }

    #[test]
    fn write_creates_missing_storage_json() {
        let dir = TestDir::new();
        let storage = dir.path().join("nested").join("storage.json");
        let profile = generate_profile();
        write_profile(&storage, &profile).unwrap();
        assert_eq!(read_profile(&storage).unwrap(), profile);
    }

    #[test]
    fn bind_marks_latest_current_and_keeps_history() {
        let mut acc = sample_account();
        let p1 = generate_profile();
        bind_to_account(&mut acc, p1.clone(), "capture");
        let p2 = generate_profile();
        bind_to_account(&mut acc, p2.clone(), "generated");
        assert_eq!(acc.device_profile.as_ref().unwrap(), &p2);
        assert_eq!(acc.device_history.len(), 2);
        assert!(!acc.device_history[0].is_current);
        assert!(acc.device_history[1].is_current);
        assert_eq!(acc.device_history[0].profile, p1);
    }
}

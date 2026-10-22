use crate::models::token::TokenData;
use serde::{Deserialize, Serialize};

/// A managed Antigravity account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    /// Stable unique identifier.
    pub id: String,
    /// Google account email.
    pub email: String,
    /// Optional display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The credential payload.
    pub token: TokenData,
    /// Unix timestamp when the account was added.
    pub created_at: i64,
    /// Unix timestamp of the last time this account was activated.
    pub last_used: i64,
    /// User-defined label / remark.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_label: Option<String>,
    /// Whether this account is disabled (e.g. revoked refresh_token).
    #[serde(default)]
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled_reason: Option<String>,
}

impl Account {
    pub fn new(id: String, email: String, token: TokenData) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            id,
            email,
            name: None,
            token,
            created_at: now,
            last_used: now,
            custom_label: None,
            disabled: false,
            disabled_reason: None,
        }
    }

    pub fn update_last_used(&mut self) {
        self.last_used = chrono::Utc::now().timestamp();
    }
}

/// Index file: `accounts.json` at the root of the store.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AccountIndex {
    pub version: String,
    pub accounts: Vec<AccountSummary>,
    /// The currently active account id for the agy CLI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_agy_account_id: Option<String>,
}

impl AccountIndex {
    pub fn new() -> Self {
        Self {
            version: "1.0".to_string(),
            accounts: Vec::new(),
            current_agy_account_id: None,
        }
    }
}

/// A summary view of an account, stored in the index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountSummary {
    pub id: String,
    pub email: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_label: Option<String>,
    pub created_at: i64,
    pub last_used: i64,
}

impl From<&Account> for AccountSummary {
    fn from(acc: &Account) -> Self {
        Self {
            id: acc.id.clone(),
            email: acc.email.clone(),
            name: acc.name.clone(),
            disabled: acc.disabled,
            custom_label: acc.custom_label.clone(),
            created_at: acc.created_at,
            last_used: acc.last_used,
        }
    }
}

/// Export item for backup / migration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountExportItem {
    pub email: String,
    pub refresh_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

/// Export response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountExportResponse {
    pub exported_at: i64,
    pub accounts: Vec<AccountExportItem>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::token::TokenData;

    fn account() -> Account {
        let token = TokenData::new(
            "access".into(),
            "refresh".into(),
            3600,
            None,
            None,
            None,
            false,
            None,
        );
        Account::new("id-1".into(), "user@example.com".into(), token)
    }

    #[test]
    fn new_account_defaults() {
        let acc = account();
        assert_eq!(acc.id, "id-1");
        assert!(!acc.disabled);
        assert!(acc.disabled_reason.is_none());
        assert!(acc.custom_label.is_none());
        assert_eq!(acc.created_at, acc.last_used);
    }

    #[test]
    fn summary_maps_fields() {
        let acc = account();
        let s = AccountSummary::from(&acc);
        assert_eq!(s.id, acc.id);
        assert_eq!(s.email, "user@example.com");
        assert_eq!(s.disabled, acc.disabled);
        assert_eq!(s.created_at, acc.created_at);
        assert_eq!(s.last_used, acc.last_used);
    }

    #[test]
    fn index_defaults() {
        let idx = AccountIndex::new();
        assert_eq!(idx.version, "1.0");
        assert!(idx.accounts.is_empty());
        assert!(idx.current_agy_account_id.is_none());
    }

    #[test]
    fn account_serde_roundtrip() {
        let acc = account();
        let json = serde_json::to_string(&acc).unwrap();
        let back: Account = serde_json::from_str(&json).unwrap();
        assert_eq!(back.email, "user@example.com");
        assert_eq!(back.token.refresh_token, "refresh");
        // optional fields are omitted when None
        assert!(!json.contains("custom_label"));
    }
}

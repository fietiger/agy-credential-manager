use serde::{Deserialize, Serialize};

/// Credentials for a single Antigravity / Google account.
///
/// This struct is stored as plain JSON in the local account store.
/// The `access_token` is short-lived and can be refreshed via `refresh_token`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenData {
    /// Google OAuth access token (Bearer).
    pub access_token: String,
    /// Long-lived refresh token. This is the most critical field.
    pub refresh_token: String,
    /// Lifetime of `access_token` in seconds (typically 3600).
    pub expires_in: i64,
    /// Unix timestamp when `access_token` expires.
    pub expiry_timestamp: i64,
    /// Always "Bearer".
    pub token_type: String,
    /// Google account email.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Google Cloud project id (if available).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    /// OAuth client key identifier (used by the refresh logic).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_client_key: Option<String>,
    /// Antigravity session id (if present).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Whether this token was obtained via GCP terms of service.
    #[serde(default)]
    pub is_gcp_tos: bool,
    /// OAuth id_token (JWT) if returned by Google.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
}

impl TokenData {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        access_token: String,
        refresh_token: String,
        expires_in: i64,
        email: Option<String>,
        project_id: Option<String>,
        session_id: Option<String>,
        is_gcp_tos: bool,
        id_token: Option<String>,
    ) -> Self {
        let expiry_timestamp = chrono::Utc::now().timestamp() + expires_in;
        Self {
            access_token,
            refresh_token,
            expires_in,
            expiry_timestamp,
            token_type: "Bearer".to_string(),
            email,
            project_id,
            oauth_client_key: None,
            session_id,
            is_gcp_tos,
            id_token,
        }
    }

    /// Mask the access token for safe display.
    pub fn masked_access_token(&self) -> String {
        let t = &self.access_token;
        if t.len() <= 8 {
            return "****".to_string();
        }
        format!("{}...{}", &t[..4], &t[t.len() - 4..])
    }

    /// Mask the refresh token for safe display.
    pub fn masked_refresh_token(&self) -> String {
        let t = &self.refresh_token;
        if t.len() <= 8 {
            return "****".to_string();
        }
        format!("{}...{}", &t[..4], &t[t.len() - 4..])
    }

    /// Whether the access token is still valid.
    pub fn is_access_token_valid(&self) -> bool {
        chrono::Utc::now().timestamp() < self.expiry_timestamp - 60
    }
}

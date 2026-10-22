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

#[cfg(test)]
mod tests {
    use super::*;

    fn token(access: &str, refresh: &str, expires_in: i64) -> TokenData {
        TokenData::new(
            access.to_string(),
            refresh.to_string(),
            expires_in,
            None,
            None,
            None,
            false,
            None,
        )
    }

    #[test]
    fn new_sets_bearer_and_expiry() {
        let before = chrono::Utc::now().timestamp();
        let t = token("access", "refresh", 3600);
        assert_eq!(t.token_type, "Bearer");
        assert!(t.expiry_timestamp >= before + 3600);
        assert!(t.expiry_timestamp <= chrono::Utc::now().timestamp() + 3600);
    }

    #[test]
    fn masks_long_tokens() {
        let t = token("abcd1234wxyz", "refr5678qwer", 3600);
        assert_eq!(t.masked_access_token(), "abcd...wxyz");
        assert_eq!(t.masked_refresh_token(), "refr...qwer");
    }

    #[test]
    fn masks_short_tokens_fully() {
        let t = token("short", "tiny", 3600);
        assert_eq!(t.masked_access_token(), "****");
        assert_eq!(t.masked_refresh_token(), "****");
        // exactly 8 chars is still fully masked
        let edge = token("12345678", "87654321", 3600);
        assert_eq!(edge.masked_access_token(), "****");
    }

    #[test]
    fn validity_respects_expiry_and_buffer() {
        assert!(token("a", "r", 3600).is_access_token_valid());
        assert!(!token("a", "r", -10).is_access_token_valid());
        // inside the 60-second safety buffer counts as invalid
        assert!(!token("a", "r", 30).is_access_token_valid());
    }

    #[test]
    fn serde_roundtrip() {
        let t = token("access-token", "refresh-token", 3600);
        let json = serde_json::to_string(&t).unwrap();
        let back: TokenData = serde_json::from_str(&json).unwrap();
        assert_eq!(back.access_token, "access-token");
        assert_eq!(back.refresh_token, "refresh-token");
        // optional fields are omitted when None
        assert!(!json.contains("project_id"));
    }
}

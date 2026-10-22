//! Google OAuth 2.0 local loopback callback server.
//!
//! This module implements the authorization-code flow:
//!
//!   1. Build an auth URL pointing to `accounts.google.com`
//!   2. Start a one-shot HTTP server on `127.0.0.1:<random_port>`
//!   3. Open the auth URL in the user's browser
//!   4. After the user grants consent, Google redirects to
//!      `http://127.0.0.1:<port>/callback?code=...&state=...`
//!   5. Exchange the code for tokens at `oauth2.googleapis.com/token`
//!   6. Stop the server and return the `TokenData`
//!
//! No third-party relay server is involved at any point.

use crate::error::{AppError, AppResult};
use crate::models::token::TokenData;
use crate::modules::logger;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use uuid::Uuid;

// ── Google OAuth constants ────────────────────────────────────────────────
// These are the public Antigravity OAuth client credentials, embedded in the
// official Antigravity CLI distribution. They are not secret.
const CLIENT_ID: &str = "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const USERINFO_URL: &str = "https://www.googleapis.com/oauth2/v2/userinfo";

const SCOPES: &str = "openid https://www.googleapis.com/auth/cloud-platform \
https://www.googleapis.com/auth/userinfo.email \
https://www.googleapis.com/auth/userinfo.profile \
https://www.googleapis.com/auth/cclog \
https://www.googleapis.com/auth/experimentsandconfigs";

// ── Token response shape ──────────────────────────────────────────────────
#[derive(serde::Deserialize)]
struct RawTokenResponse {
    access_token: String,
    expires_in: i64,
    #[serde(default)]
    token_type: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
}

/// Result of a completed OAuth exchange.
pub struct OAuthResult {
    pub token: TokenData,
    pub email: Option<String>,
}

/// Generate the authorization URL that should be opened in the user's browser.
pub fn build_auth_url(port: u16) -> String {
    let state = Uuid::new_v4().to_string();
    let redirect_uri = format!("http://127.0.0.1:{}/callback", port);
    let params = [
        ("client_id", CLIENT_ID),
        ("redirect_uri", redirect_uri.as_str()),
        ("response_type", "code"),
        ("scope", SCOPES),
        ("access_type", "offline"),
        ("prompt", "consent"),
        ("include_granted_scopes", "true"),
        ("state", state.as_str()),
    ];
    let url = url::Url::parse_with_params(AUTH_URL, &params).unwrap();
    url.to_string()
}

/// Start the local loopback OAuth server and wait for the callback.
///
/// This blocks the current async task until the user completes the flow.
pub async fn start_oauth_flow(port: u16) -> AppResult<OAuthResult> {
    let redirect_uri = format!("http://127.0.0.1:{}/callback", port);
    let auth_url = build_auth_url(port);

    logger::log_info(
        "oauth",
        &format!(
            "Starting OAuth flow on 127.0.0.1:{} (redirect_uri={})",
            port, redirect_uri
        ),
    );

    // Bind the listener before opening the browser, otherwise a very fast
    // callback could arrive while no one is listening on the port.
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .map_err(|e| {
            let msg = format!("Failed to bind to port {}: {}", port, e);
            logger::log_error("oauth", &msg);
            AppError::Http(msg)
        })?;
    logger::log_info(
        "oauth",
        &format!("Bound OAuth listener to 127.0.0.1:{}", port),
    );

    // Open the browser (best effort – the user can copy the URL manually).
    if let Err(e) = open(&auth_url) {
        logger::log_warn(
            "oauth",
            &format!("Could not open browser: {}. Auth URL: {}", e, auth_url),
        );
    } else {
        logger::log_info("oauth", "Browser opened with auth URL");
    }

    let code_rx: Arc<(tokio::sync::Mutex<Option<String>>, AtomicBool)> =
        Arc::new((tokio::sync::Mutex::new(None), AtomicBool::new(false)));

    let code_rx_clone = Arc::clone(&code_rx);
    let listener_task = tokio::spawn(async move {
        loop {
            let (mut stream, _addr) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };

            // Read just enough bytes for the request line + headers
            use tokio::io::AsyncReadExt;
            let mut buf = [0u8; 8192];
            let n = match stream.read(&mut buf).await {
                Ok(n) if n > 0 => n,
                _ => continue,
            };
            let request = String::from_utf8_lossy(&buf[..n]);
            let first_line = request.lines().next().unwrap_or("");

            if first_line.contains("/callback") {
                // Parse query string from the first line
                let query = first_line.split('?').nth(1).unwrap_or("");
                let code_opt = extract_param(query, "code");
                let state_opt = extract_param(query, "state");
                let error_opt = extract_param(query, "error");

                if let Some(err) = error_opt {
                    let body = format!(
                        "<html><body><h1>OAuth Error</h1><pre>{}</pre></body></html>",
                        err
                    );
                    // Signal the waiting task so it does not hang for 10 minutes.
                    *code_rx_clone.0.lock().await = Some(format!("@error:{}", err));
                    code_rx_clone.1.store(true, Ordering::SeqCst);
                    send_http_response(&mut stream, 400, "text/plain", &body).await;
                    break;
                }

                if let Some(code) = code_opt {
                    let _ = state_opt; // state validation could be added here
                    *code_rx_clone.0.lock().await = Some(code);
                    code_rx_clone.1.store(true, Ordering::SeqCst);
                    let body = "<html><body><h1>✅ Authorization complete</h1>\
                            <p>You can close this window and return to the app.</p>\
                            </body></html>";
                    send_http_response(&mut stream, 200, "text/html", body).await;
                    break;
                } else {
                    let body = "<html><body><h1>Missing code</h1></body></html>";
                    send_http_response(&mut stream, 400, "text/html", body).await;
                }
            } else {
                // Non-callback request – respond 404
                let body = "<html><body><h1>404 Not Found</h1></body></html>";
                send_http_response(&mut stream, 404, "text/html", body).await;
            }
        }
    });

    // Wait for the code to arrive (with a 10-minute timeout)
    logger::log_info("oauth", "Waiting for OAuth callback (timeout: 10 min)…");
    let code = wait_for_code(&code_rx).await?;
    listener_task.abort();

    if let Some(reason) = code.strip_prefix("@error:") {
        let msg = format!("Google returned an OAuth error: {}", reason);
        logger::log_error("oauth", &msg);
        return Err(AppError::Oauth(msg));
    }

    logger::log_info(
        "oauth",
        &format!("Received auth code: {}…", &code[..code.len().min(8)]),
    );

    // Exchange code for tokens
    let raw = exchange_code(&code, &redirect_uri).await?;
    logger::log_info("oauth", "Code exchanged successfully");

    // Resolve email
    let email = fetch_email(&raw.access_token).await;
    logger::log_info("oauth", &format!("Resolved email: {:?}", email));

    let token = TokenData {
        access_token: raw.access_token,
        refresh_token: raw.refresh_token.unwrap_or_default(),
        expires_in: raw.expires_in,
        expiry_timestamp: chrono::Utc::now().timestamp() + raw.expires_in,
        token_type: if raw.token_type.is_empty() {
            "Bearer".to_string()
        } else {
            raw.token_type
        },
        email: email.clone(),
        project_id: None,
        oauth_client_key: None,
        session_id: None,
        is_gcp_tos: false,
        id_token: raw.id_token,
    };

    if token.refresh_token.is_empty() {
        logger::log_warn(
            "oauth",
            "Google did not return a refresh_token. \
             The access token will expire without the ability to refresh. \
             Try revoking access in Google account settings and retry.",
        );
    } else {
        logger::log_info("oauth", "refresh_token received ✓");
    }

    logger::log_info("oauth", "OAuth flow completed");
    Ok(OAuthResult { token, email })
}

// ── helpers ────────────────────────────────────────────────────────────────

async fn wait_for_code(
    rx: &Arc<(tokio::sync::Mutex<Option<String>>, AtomicBool)>,
) -> AppResult<String> {
    for _ in 0..600 {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let guard = rx.0.lock().await;
        if let Some(code) = guard.clone() {
            return Ok(code);
        }
    }
    Err(AppError::Oauth(
        "Timed out waiting for OAuth callback (10 minutes)".to_string(),
    ))
}

async fn send_http_response(
    stream: &mut tokio::net::TcpStream,
    status_code: u16,
    content_type: &str,
    body: &str,
) {
    let reason = match status_code {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "Unknown",
    };
    let resp =
        format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status_code, reason, content_type, body.len(), body
    );
    use tokio::io::AsyncWriteExt;
    let _ = stream.write_all(resp.as_bytes()).await;
    let _ = stream.flush().await;
}

fn extract_param(query: &str, key: &str) -> Option<String> {
    for part in query.split('&') {
        let kv: Vec<&str> = part.splitn(2, '=').collect();
        if kv.len() == 2 && kv[0] == key {
            // URL-decode basic percent-encoding
            let decoded = percent_decode(kv[1]);
            return Some(decoded);
        }
    }
    None
}

/// Minimal percent-decoding without extra crate dependencies.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

async fn exchange_code(code: &str, redirect_uri: &str) -> AppResult<RawTokenResponse> {
    logger::log_info("oauth", "Exchanging authorization code for token…");
    let client = reqwest::Client::new();
    let form = [
        ("client_id", CLIENT_ID),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("grant_type", "authorization_code"),
    ];
    let resp = client
        .post(TOKEN_URL)
        .header("User-Agent", "AntigravityCLI/1.0 (agy-credential-manager)")
        .form(&form)
        .send()
        .await
        .map_err(|e| {
            let msg = format!("Token exchange request failed: {}", e);
            logger::log_error("oauth", &msg);
            AppError::Oauth(msg)
        })?;

    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        let msg = format!("Token exchange failed ({}): {}", status, text);
        logger::log_error("oauth", &msg);
        return Err(AppError::Oauth(msg));
    }

    let raw: RawTokenResponse = resp.json().await.map_err(|e| {
        let msg = format!("Failed to parse token response: {}", e);
        logger::log_error("oauth", &msg);
        AppError::Oauth(msg)
    })?;
    logger::log_debug(
        "oauth",
        &format!(
            "Token exchange OK: access_token={}…, refresh_token present={}",
            raw.access_token.chars().take(8).collect::<String>(),
            raw.refresh_token.is_some()
        ),
    );
    Ok(raw)
}

async fn fetch_email(access_token: &str) -> Option<String> {
    let client = reqwest::Client::new();
    #[derive(serde::Deserialize)]
    struct UserInfo {
        email: Option<String>,
    }
    let resp: UserInfo = client
        .get(USERINFO_URL)
        .header("Authorization", format!("Bearer {}", access_token))
        .send()
        .await
        .ok()?
        .json()
        .await
        .ok()?;
    resp.email
}

/// Refresh an access token using the refresh_token.
pub async fn refresh_token(token: &TokenData) -> Result<TokenData, String> {
    let rt_preview = token.refresh_token.chars().take(12).collect::<String>();
    logger::log_info(
        "oauth",
        &format!("Refreshing access token (refresh_token={}…)", rt_preview),
    );

    let client = reqwest::Client::new();
    let form = [
        ("client_id", CLIENT_ID),
        ("grant_type", "refresh_token"),
        ("refresh_token", token.refresh_token.as_str()),
    ];
    let resp = client
        .post(TOKEN_URL)
        .header("User-Agent", "AntigravityCLI/1.0 (agy-credential-manager)")
        .form(&form)
        .send()
        .await
        .map_err(|e| {
            let msg = format!("Refresh request failed: {}", e);
            logger::log_error("oauth", &msg);
            msg
        })?;

    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        let msg = format!("Refresh failed ({}): {}", status, text);
        logger::log_error("oauth", &msg);
        return Err(msg);
    }

    let raw: RawTokenResponse = resp.json().await.map_err(|e| {
        let msg = format!("Failed to parse refresh response: {}", e);
        logger::log_error("oauth", &msg);
        msg
    })?;

    let email = fetch_email(&raw.access_token).await;
    logger::log_info(
        "oauth",
        &format!(
            "Token refresh OK: email={:?}, new expires_in={}",
            email, raw.expires_in
        ),
    );

    Ok(TokenData {
        access_token: raw.access_token,
        refresh_token: raw.refresh_token.unwrap_or(token.refresh_token.clone()),
        expires_in: raw.expires_in,
        expiry_timestamp: chrono::Utc::now().timestamp() + raw.expires_in,
        token_type: if raw.token_type.is_empty() {
            "Bearer".to_string()
        } else {
            raw.token_type
        },
        email,
        project_id: token.project_id.clone(),
        oauth_client_key: token.oauth_client_key.clone(),
        session_id: token.session_id.clone(),
        is_gcp_tos: token.is_gcp_tos,
        id_token: raw.id_token.or_else(|| token.id_token.clone()),
    })
}

/// Open a URL in the default browser (best effort).
fn open(url: &str) -> std::io::Result<()> {
    if url.is_empty() {
        return Ok(());
    }
    let mut cmd = if cfg!(target_os = "macos") {
        let mut c = std::process::Command::new("open");
        c.arg(url);
        c
    } else if cfg!(target_os = "windows") {
        let mut c = std::process::Command::new("cmd");
        c.args(["/C", "start", "", url]);
        c
    } else {
        let mut c = std::process::Command::new("xdg-open");
        c.arg(url);
        c
    };
    cmd.spawn()?;
    Ok(())
}

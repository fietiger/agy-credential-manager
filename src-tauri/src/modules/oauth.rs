//! Google OAuth 2.0 flow, modelled on lbjlaq/Antigravity-Manager's design.
//!
//! prepare_oauth binds loopback listeners (IPv6 ::1 and IPv4 127.0.0.1 on
//! the same port) and builds the auth URL with redirect
//! http://localhost:<port>/oauth-callback. The UI shows the URL with a Copy
//! button before anything is opened, so the user can authorize in any
//! browser where they are already signed in to Google.
//!
//! The authorization code reaches us through whichever path works: the
//! loopback callback (browser on this machine), or manual submission - the
//! user pastes the callback link (or the bare code) into the app, which also
//! works when the redirect could not reach this machine (different browser
//! profile, remote machine...). Both paths feed one mpsc channel.
//!
//! wait_for_oauth(open_browser) consumes the channel: Start passes true
//! (also opens the default browser), "I've authorized, continue" passes
//! false. The code is then exchanged for tokens.
//!
//! The token exchange includes the Antigravity client's embedded secret,
//! like the official client (and Antigravity-Manager) do; without it Google
//! rejects the exchange for this client. The callback validates state.

use crate::error::{AppError, AppResult};
use crate::models::token::TokenData;
use crate::modules::logger;
use std::sync::{Mutex, OnceLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
use uuid::Uuid;

// ── Google OAuth constants ────────────────────────────────────────────────
// These are the public Antigravity OAuth client credentials, embedded in the
// official Antigravity CLI distribution. They are not secret.
const CLIENT_ID: &str = "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com";
const CLIENT_SECRET: &str = "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";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const USERINFO_URL: &str = "https://www.googleapis.com/oauth2/v2/userinfo";

const SCOPES: &str = "openid https://www.googleapis.com/auth/cloud-platform \
https://www.googleapis.com/auth/userinfo.email \
https://www.googleapis.com/auth/userinfo.profile \
https://www.googleapis.com/auth/cclog \
https://www.googleapis.com/auth/experimentsandconfigs";

const WAIT_TIMEOUT_SECS: u64 = 600;

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

/// Generate the authorization URL for the given redirect URI and state.
pub fn build_auth_url(redirect_uri: &str, state: &str) -> String {
    let params = [
        ("client_id", CLIENT_ID),
        ("redirect_uri", redirect_uri),
        ("response_type", "code"),
        ("scope", SCOPES),
        ("access_type", "offline"),
        ("prompt", "consent"),
        ("include_granted_scopes", "true"),
        ("state", state),
    ];
    let url = url::Url::parse_with_params(AUTH_URL, &params).unwrap();
    url.to_string()
}

// ── Flow state ────────────────────────────────────────────────────────────

struct OAuthFlow {
    auth_url: String,
    redirect_uri: String,
    state: String,
    cancel_tx: watch::Sender<bool>,
    code_tx: mpsc::Sender<Result<String, String>>,
    code_rx: Option<mpsc::Receiver<Result<String, String>>>,
}

static FLOW: OnceLock<Mutex<Option<OAuthFlow>>> = OnceLock::new();

fn flow_state() -> &'static Mutex<Option<OAuthFlow>> {
    FLOW.get_or_init(|| Mutex::new(None))
}

fn lock_flow() -> AppResult<std::sync::MutexGuard<'static, Option<OAuthFlow>>> {
    flow_state()
        .lock()
        .map_err(|_| AppError::Other("oauth flow lock poisoned".into()))
}

const SUCCESS_HTML: &str = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n\
<html><body style='font-family: sans-serif; text-align: center; padding: 50px;'>\
<h1 style='color: green;'>✅ Authorization Successful!</h1>\
<p>You can close this window and return to the application.</p>\
<script>setTimeout(function() { window.close(); }, 2000);</script>\
</body></html>";

const FAIL_HTML: &str =
    "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html; charset=utf-8\r\n\r\n\
<html><body style='font-family: sans-serif; text-align: center; padding: 50px;'>\
<h1 style='color: red;'>❌ Authorization Failed</h1>\
<p>Failed to obtain Authorization Code. Please return to the app and try again.</p>\
</body></html>";

/// Prepare a flow (listeners + auth URL) without opening the browser.
/// Idempotent: while a flow exists its URL is returned as-is. Listeners start
/// immediately, so a user who authorizes before clicking Start is not lost.
pub async fn prepare_oauth() -> AppResult<String> {
    {
        let guard = lock_flow()?;
        if let Some(f) = guard.as_ref() {
            return Ok(f.auth_url.clone());
        }
    }
    let flow = build_flow().await?;
    let url = flow.auth_url.clone();
    let mut guard = lock_flow()?;
    if let Some(existing) = guard.as_ref() {
        // Another prepare won the race; discard ours.
        let _ = flow.cancel_tx.send(true);
        return Ok(existing.auth_url.clone());
    }
    *guard = Some(flow);
    logger::log_info("oauth", &format!("Prepared OAuth flow: {}", url));
    Ok(url)
}

async fn build_flow() -> AppResult<OAuthFlow> {
    // Bind both stacks on one port when possible: some browsers resolve
    // `localhost` to ::1 first, and a v4-only listener would refuse them.
    let mut listeners: Vec<TcpListener> = Vec::new();
    let port: u16;
    match TcpListener::bind("[::1]:0").await {
        Ok(l6) => {
            port = l6
                .local_addr()
                .map_err(|e| AppError::Other(e.to_string()))?
                .port();
            match TcpListener::bind(format!("127.0.0.1:{}", port)).await {
                Ok(l4) => listeners.push(l4),
                Err(e) => logger::log_warn(
                    "oauth",
                    &format!("Could not bind IPv4 callback port {}: {}", port, e),
                ),
            }
            listeners.push(l6);
        }
        Err(_) => {
            let l4 = TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|e| AppError::Http(format!("Failed to bind callback port: {}", e)))?;
            port = l4
                .local_addr()
                .map_err(|e| AppError::Other(e.to_string()))?
                .port();
            match TcpListener::bind(format!("[::1]:{}", port)).await {
                Ok(l6) => listeners.push(l6),
                Err(e) => logger::log_warn(
                    "oauth",
                    &format!("Could not bind IPv6 callback port {}: {}", port, e),
                ),
            }
            listeners.push(l4);
        }
    }
    let has_v4 = listeners
        .iter()
        .any(|l| l.local_addr().is_ok_and(|a| a.is_ipv4()));
    let has_v6 = listeners
        .iter()
        .any(|l| l.local_addr().is_ok_and(|a| a.is_ipv6()));
    let redirect_uri = if has_v4 && has_v6 {
        format!("http://localhost:{}/oauth-callback", port)
    } else if has_v4 {
        format!("http://127.0.0.1:{}/oauth-callback", port)
    } else {
        format!("http://[::1]:{}/oauth-callback", port)
    };

    let state = Uuid::new_v4().to_string();
    let auth_url = build_auth_url(&redirect_uri, &state);
    let (cancel_tx, cancel_rx) = watch::channel(false);
    let (code_tx, code_rx) = mpsc::channel::<Result<String, String>>(1);
    for listener in listeners {
        spawn_callback_listener(listener, state.clone(), code_tx.clone(), cancel_rx.clone());
    }
    Ok(OAuthFlow {
        auth_url,
        redirect_uri,
        state,
        cancel_tx,
        code_tx,
        code_rx: Some(code_rx),
    })
}

/// One-shot loopback callback listener: accepts a single connection, parses
/// the code, validates `state`, answers the browser, feeds the channel.
fn spawn_callback_listener(
    listener: TcpListener,
    expected_state: String,
    code_tx: mpsc::Sender<Result<String, String>>,
    mut cancel_rx: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let mut stream = tokio::select! {
            res = listener.accept() => match res {
                Ok((s, _)) => s,
                Err(_) => return,
            },
            _ = cancel_rx.changed() => return,
        };
        let mut buf = [0u8; 8192];
        let n = stream.read(&mut buf).await.unwrap_or(0);
        let request = String::from_utf8_lossy(&buf[..n]).to_string();
        let target = request
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or("")
            .to_string();

        let mut code: Option<String> = None;
        let mut state: Option<String> = None;
        let mut error: Option<String> = None;
        if let Ok(url) = url::Url::parse(&format!("http://localhost{}", target)) {
            for (k, v) in url.query_pairs() {
                match k.as_ref() {
                    "code" => code = Some(v.into_owned()),
                    "state" => state = Some(v.into_owned()),
                    "error" => error = Some(v.into_owned()),
                    _ => {}
                }
            }
        }

        let state_ok = state.as_deref() == Some(expected_state.as_str());
        let (result, ok) = match (error, code) {
            (Some(e), _) => (Err(format!("Google returned an OAuth error: {}", e)), false),
            (None, None) => (
                Err("Failed to get authorization code in callback".to_string()),
                false,
            ),
            (None, Some(_)) if !state_ok => (Err("OAuth state mismatch".to_string()), false),
            (None, Some(c)) => (Ok(c), true),
        };
        if !ok {
            logger::log_error("oauth", &format!("Callback rejected: {:?}", result));
        }
        let html = if ok { SUCCESS_HTML } else { FAIL_HTML };
        let _ = stream.write_all(html.as_bytes()).await;
        let _ = stream.flush().await;
        let _ = code_tx.try_send(result);
    });
}

/// Wait for the authorization code (however it arrives), then exchange it.
/// `open_browser` also opens the auth URL in the default browser (Start).
pub async fn wait_for_oauth(open_browser: bool) -> AppResult<OAuthResult> {
    let auth_url = prepare_oauth().await?;
    if open_browser {
        if let Err(e) = open(&auth_url) {
            logger::log_warn(
                "oauth",
                &format!("Could not open browser: {}. Auth URL: {}", e, auth_url),
            );
        } else {
            logger::log_info("oauth", "Browser opened with auth URL");
        }
    }

    let (mut rx, redirect_uri) = {
        let mut guard = lock_flow()?;
        let flow = guard
            .as_mut()
            .ok_or_else(|| AppError::Oauth("No active OAuth flow".to_string()))?;
        let rx = flow.code_rx.take().ok_or_else(|| {
            AppError::Oauth("OAuth authorization already in progress".to_string())
        })?;
        (rx, flow.redirect_uri.clone())
    };

    logger::log_info("oauth", "Waiting for OAuth code (callback or manual)…");
    let code =
        match tokio::time::timeout(std::time::Duration::from_secs(WAIT_TIMEOUT_SECS), rx.recv())
            .await
        {
            Ok(Some(Ok(code))) => code,
            Ok(Some(Err(e))) => {
                clear_flow();
                return Err(AppError::Oauth(e));
            }
            Ok(None) => {
                clear_flow();
                return Err(AppError::Oauth("OAuth flow was cancelled".to_string()));
            }
            Err(_) => {
                cancel_oauth();
                return Err(AppError::Oauth(
                    "Timed out waiting for OAuth authorization (10 minutes)".to_string(),
                ));
            }
        };
    clear_flow();

    logger::log_info(
        "oauth",
        &format!("Received auth code: {}…", &code[..code.len().min(8)]),
    );
    let raw = exchange_code(&code, &redirect_uri).await?;
    logger::log_info("oauth", "Code exchanged successfully");
    let email = fetch_email(&raw.access_token).await;
    logger::log_info("oauth", &format!("Resolved email: {:?}", email));
    let token = build_token(raw, email.clone(), None);
    if token.refresh_token.is_empty() {
        logger::log_warn(
            "oauth",
            "Google did not return a refresh_token. The access token will expire \
             without the ability to refresh. Try revoking access in Google \
             account settings and retry.",
        );
    }
    logger::log_info("oauth", "OAuth flow completed");
    Ok(OAuthResult { token, email })
}

/// Manually submit an authorization code (or a full callback link containing
/// one) into the active flow. Used when the browser redirect could not reach
/// this machine. The code is consumed by `wait_for_oauth`.
pub async fn submit_oauth_code(input: &str) -> AppResult<()> {
    let (code, state_in) = extract_code_from_input(input)?;
    let tx = {
        let guard = lock_flow()?;
        let flow = guard.as_ref().ok_or_else(|| {
            AppError::Oauth("No active OAuth flow found — open the OAuth panel first".to_string())
        })?;
        if let Some(s) = &state_in {
            if s != &flow.state {
                return Err(AppError::Oauth(
                    "OAuth state mismatch (CSRF protection)".to_string(),
                ));
            }
        }
        flow.code_tx.clone()
    };
    logger::log_info("oauth", "Received manual OAuth code submission");
    tx.try_send(Ok(code)).map_err(|e| match e {
        mpsc::error::TrySendError::Full(_) => {
            AppError::Oauth("A code has already been submitted for this flow".to_string())
        }
        mpsc::error::TrySendError::Closed(_) => {
            AppError::Oauth("OAuth flow is no longer waiting for a code".to_string())
        }
    })
}

/// Cancel the active flow (if any): stops the listeners and unblocks a
/// pending `wait_for_oauth` with a cancellation error.
pub fn cancel_oauth() {
    if let Ok(mut guard) = flow_state().lock() {
        if let Some(flow) = guard.take() {
            let _ = flow.cancel_tx.send(true);
            logger::log_info("oauth", "OAuth flow cancelled");
        }
    }
}

fn clear_flow() {
    if let Ok(mut guard) = flow_state().lock() {
        *guard = None;
    }
}

/// Extract the authorization code (and state, when present) from user input:
/// a bare code, a full callback URL, or a bare query string.
pub fn extract_code_from_input(input: &str) -> AppResult<(String, Option<String>)> {
    let input = input.trim();
    if input.is_empty() {
        return Err(AppError::Oauth("Nothing was pasted".to_string()));
    }
    let query_src: Option<String> = if input.starts_with("http://") || input.starts_with("https://")
    {
        Some(input.to_string())
    } else if input.contains("code=") {
        Some(format!(
            "http://localhost/?{}",
            input.trim_start_matches('?')
        ))
    } else {
        None
    };
    if let Some(src) = query_src {
        let url = url::Url::parse(&src)
            .map_err(|e| AppError::Oauth(format!("Could not parse the pasted link: {}", e)))?;
        let mut code = None;
        let mut state = None;
        let mut error = None;
        for (k, v) in url.query_pairs() {
            match k.as_ref() {
                "code" => code = Some(v.into_owned()),
                "state" => state = Some(v.into_owned()),
                "error" => error = Some(v.into_owned()),
                _ => {}
            }
        }
        if let Some(e) = error {
            return Err(AppError::Oauth(format!(
                "Google returned an OAuth error: {}",
                e
            )));
        }
        return match code {
            Some(c) => Ok((c, state)),
            None => Err(AppError::Oauth(
                "No code= parameter found in the pasted link".to_string(),
            )),
        };
    }
    if input.chars().any(|c| c.is_whitespace()) {
        return Err(AppError::Oauth(
            "That looks like neither an authorization code nor a callback link".to_string(),
        ));
    }
    Ok((input.to_string(), None))
}

// ── Token endpoint ────────────────────────────────────────────────────────

fn build_token(
    raw: RawTokenResponse,
    email: Option<String>,
    previous: Option<&TokenData>,
) -> TokenData {
    TokenData {
        access_token: raw.access_token,
        refresh_token: match raw.refresh_token {
            Some(rt) if !rt.is_empty() => rt,
            _ => previous
                .map(|p| p.refresh_token.clone())
                .unwrap_or_default(),
        },
        expires_in: raw.expires_in,
        expiry_timestamp: chrono::Utc::now().timestamp() + raw.expires_in,
        token_type: if raw.token_type.is_empty() {
            "Bearer".to_string()
        } else {
            raw.token_type
        },
        email,
        project_id: previous.and_then(|p| p.project_id.clone()),
        oauth_client_key: previous.and_then(|p| p.oauth_client_key.clone()),
        session_id: previous.and_then(|p| p.session_id.clone()),
        is_gcp_tos: previous.is_some_and(|p| p.is_gcp_tos),
        id_token: raw.id_token,
    }
}

async fn exchange_code(code: &str, redirect_uri: &str) -> AppResult<RawTokenResponse> {
    logger::log_info("oauth", "Exchanging authorization code for token…");
    let client = reqwest::Client::new();
    let form = [
        ("client_id", CLIENT_ID),
        ("client_secret", CLIENT_SECRET),
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
    logger::log_info("oauth", "Token exchange OK");
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
    logger::log_info("oauth", "Refreshing access token…");
    let client = reqwest::Client::new();
    let form = [
        ("client_id", CLIENT_ID),
        ("client_secret", CLIENT_SECRET),
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
    Ok(build_token(raw, email, Some(token)))
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

#[cfg(test)]
mod tests {
    use super::extract_code_from_input;

    #[test]
    fn bare_code() {
        let (code, state) = extract_code_from_input("4/0AbCdEfGh").unwrap();
        assert_eq!(code, "4/0AbCdEfGh");
        assert!(state.is_none());
    }

    #[test]
    fn bare_code_trimmed() {
        let (code, _) = extract_code_from_input("  4/0AbCdEfGh \n").unwrap();
        assert_eq!(code, "4/0AbCdEfGh");
    }

    #[test]
    fn full_callback_url() {
        let (code, state) = extract_code_from_input(
            "http://localhost:54321/oauth-callback?state=abc-123&code=4/0AAAA&scope=openid",
        )
        .unwrap();
        assert_eq!(code, "4/0AAAA");
        assert_eq!(state.as_deref(), Some("abc-123"));
    }

    #[test]
    fn url_encoded_code() {
        let (code, _) =
            extract_code_from_input("http://127.0.0.1:9/oauth-callback?code=4%2F0BBBB").unwrap();
        assert_eq!(code, "4/0BBBB");
    }

    #[test]
    fn bare_query_string() {
        let (code, state) = extract_code_from_input("?code=4/0CCCC&state=xyz").unwrap();
        assert_eq!(code, "4/0CCCC");
        assert_eq!(state.as_deref(), Some("xyz"));
    }

    #[test]
    fn error_url() {
        let err = extract_code_from_input(
            "http://localhost:1/oauth-callback?error=access_denied&state=abc",
        )
        .unwrap_err();
        assert!(err.to_string().contains("access_denied"), "{}", err);
    }

    #[test]
    fn url_without_code() {
        assert!(extract_code_from_input("http://localhost:1/oauth-callback?state=abc").is_err());
    }

    #[test]
    fn empty_and_garbage() {
        assert!(extract_code_from_input("").is_err());
        assert!(extract_code_from_input("hello world foo").is_err());
    }
}

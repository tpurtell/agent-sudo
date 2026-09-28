//! Browser authentication: users, passwords, opaque server-side sessions, devices,
//! CSRF protection and step-up freshness.

use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{HeaderMap, Method, StatusCode};
use rusqlite::{OptionalExtension, params};
use serde::Serialize;

use crate::error::ApiError;
use crate::state::{AppState, Shared};
use crate::util::{new_id, new_token, now_ms, sha256_hex};

pub const CSRF_HEADER: &str = "x-csrf-token";

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct User {
    pub id: String,
    pub name: String,
    pub display_name: String,
    pub role: String,
    pub webauthn_id: String,
    #[serde(skip)]
    pub password_hash: Option<String>,
    pub created_at: i64,
    pub disabled: bool,
}

impl User {
    pub fn can_decide(&self) -> bool {
        matches!(self.role.as_str(), "admin" | "approver")
    }
    pub fn is_admin(&self) -> bool {
        self.role == "admin"
    }
}

#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    pub user: User,
    pub device_id: String,
    pub device_label: String,
    pub csrf: String,
    pub strong_auth_at: Option<i64>,
    pub auth_method: String,
}

impl Session {
    pub fn strong_within(&self, minutes: u32) -> bool {
        self.strong_auth_at
            .is_some_and(|t| now_ms() - t <= minutes as i64 * 60_000)
    }
}

fn row_user(r: &rusqlite::Row) -> rusqlite::Result<User> {
    Ok(User {
        id: r.get("id")?,
        name: r.get("name")?,
        display_name: r.get("display_name")?,
        role: r.get("role")?,
        webauthn_id: r.get("webauthn_id")?,
        password_hash: r.get("password_hash")?,
        created_at: r.get("created_at")?,
        disabled: r.get::<_, Option<i64>>("disabled_at")?.is_some(),
    })
}

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::encode_b64(&crate::util::random_bytes::<16>())
        .map_err(|e| anyhow::anyhow!("salt: {e}"))?;
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("hash: {e}"))?
        .to_string())
}

pub fn verify_password(hash: &str, password: &str) -> bool {
    PasswordHash::new(hash)
        .map(|parsed| {
            Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok()
        })
        .unwrap_or(false)
}

pub fn validate_new_password(password: &str) -> Result<(), ApiError> {
    if password.chars().count() < 12 {
        return Err(ApiError::bad_request("Use at least 12 characters."));
    }
    Ok(())
}

pub fn validate_username(name: &str) -> Result<(), ApiError> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-@".contains(c));
    if ok {
        Ok(())
    } else {
        Err(ApiError::bad_request(
            "Usernames use letters, digits, and . _ - @",
        ))
    }
}

pub fn user_by_name(state: &AppState, name: &str) -> anyhow::Result<Option<User>> {
    Ok(state
        .db
        .lock()
        .query_row("SELECT * FROM users WHERE name = ?", [name], row_user)
        .optional()?)
}

pub fn user_by_id(state: &AppState, id: &str) -> anyhow::Result<Option<User>> {
    Ok(state
        .db
        .lock()
        .query_row("SELECT * FROM users WHERE id = ?", [id], row_user)
        .optional()?)
}

pub fn user_by_webauthn_id(state: &AppState, id: &str) -> anyhow::Result<Option<User>> {
    Ok(state
        .db
        .lock()
        .query_row("SELECT * FROM users WHERE webauthn_id = ?", [id], row_user)
        .optional()?)
}

pub fn list_users(state: &AppState) -> anyhow::Result<Vec<User>> {
    let db = state.db.lock();
    let mut stmt = db.prepare("SELECT * FROM users ORDER BY created_at")?;
    let users = stmt
        .query_map([], row_user)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(users)
}

pub fn user_count(state: &AppState) -> anyhow::Result<i64> {
    Ok(state
        .db
        .lock()
        .query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?)
}

pub fn create_user(
    state: &AppState,
    name: &str,
    display_name: &str,
    role: &str,
    password: Option<&str>,
) -> anyhow::Result<User> {
    let hash = password.map(hash_password).transpose()?;
    let id = new_id("usr");
    let webauthn_id = webauthn_rs::prelude::Uuid::new_v4().to_string();
    state.db.lock().execute(
        "INSERT INTO users (id, name, display_name, password_hash, webauthn_id, role, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![id, name, display_name, hash, webauthn_id, role, now_ms()],
    )?;
    Ok(user_by_id(state, &id)?.expect("just inserted"))
}

pub fn passkey_count(state: &AppState, user_id: &str) -> anyhow::Result<i64> {
    Ok(state.db.lock().query_row(
        "SELECT COUNT(*) FROM passkeys WHERE user_id = ?",
        [user_id],
        |r| r.get(0),
    )?)
}

/// A readable device label from a User-Agent string.
pub fn device_label(user_agent: &str) -> (String, String) {
    let ua = user_agent;
    let os = if ua.contains("iPhone") {
        "iPhone"
    } else if ua.contains("iPad") {
        "iPad"
    } else if ua.contains("Android") {
        "Android"
    } else if ua.contains("Windows") {
        "Windows"
    } else if ua.contains("Mac OS X") || ua.contains("Macintosh") {
        "Mac"
    } else if ua.contains("CrOS") {
        "ChromeOS"
    } else if ua.contains("Linux") {
        "Linux"
    } else {
        "Browser"
    };
    let browser = if ua.contains("Edg/") {
        "Edge"
    } else if ua.contains("Firefox/") || ua.contains("FxiOS") {
        "Firefox"
    } else if ua.contains("Chrome/") || ua.contains("CriOS") {
        "Chrome"
    } else if ua.contains("Safari/") {
        "Safari"
    } else {
        "Browser"
    };
    let kind = match os {
        "iPhone" | "iPad" | "Android" => "mobile",
        _ => "desktop",
    };
    (format!("{browser} on {os}"), kind.to_string())
}

pub struct NewSession {
    pub token: String,
    pub device_id: String,
}

/// Create a session, reusing the browser's device record when it belongs to this user.
pub fn create_session(
    state: &AppState,
    user: &User,
    existing_device: Option<&str>,
    user_agent: &str,
    method: &str,
    strong: bool,
) -> anyhow::Result<NewSession> {
    let now = now_ms();
    let db = state.db.lock();
    let device_id = existing_device
        .and_then(|d| {
            db.query_row(
                "SELECT id FROM devices WHERE id = ?1 AND user_id = ?2 AND revoked_at IS NULL",
                params![d, user.id],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .ok()
            .flatten()
        })
        .map(Ok)
        .unwrap_or_else(|| -> anyhow::Result<String> {
            let id = new_id("dev");
            let (label, kind) = device_label(user_agent);
            db.execute(
                "INSERT INTO devices (id, user_id, label, kind, user_agent, created_at, last_seen_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
                params![id, user.id, label, kind, user_agent.chars().take(300).collect::<String>(), now],
            )?;
            Ok(id)
        })?;
    let token = new_token();
    let absolute = now + state.cfg.sessions.absolute_days as i64 * 86_400_000;
    db.execute(
        "INSERT INTO web_sessions (id, token_hash, user_id, device_id, csrf, auth_method, created_at, last_used_at, strong_auth_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, ?8, ?9)",
        params![
            new_id("ses"),
            sha256_hex(&token),
            user.id,
            device_id,
            new_token(),
            method,
            now,
            strong.then_some(now),
            absolute
        ],
    )?;
    db.execute(
        "UPDATE devices SET last_seen_at = ?1, user_agent = ?2 WHERE id = ?3",
        params![
            now,
            user_agent.chars().take(300).collect::<String>(),
            device_id
        ],
    )?;
    Ok(NewSession { token, device_id })
}

pub fn cookie_name(state: &AppState) -> &'static str {
    if state.cfg.secure_cookies() {
        "__Host-asudo"
    } else {
        "asudo"
    }
}

pub fn device_cookie_name(state: &AppState) -> &'static str {
    if state.cfg.secure_cookies() {
        "__Host-asudo-device"
    } else {
        "asudo-device"
    }
}

pub fn session_cookie(state: &AppState, token: &str) -> String {
    let secure = if state.cfg.secure_cookies() {
        "; Secure"
    } else {
        ""
    };
    let max_age = state.cfg.sessions.absolute_days as i64 * 86_400;
    format!(
        "{}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}",
        cookie_name(state)
    )
}

pub fn device_cookie(state: &AppState, device_id: &str) -> String {
    let secure = if state.cfg.secure_cookies() {
        "; Secure"
    } else {
        ""
    };
    format!(
        "{}={device_id}; Path=/; HttpOnly; SameSite=Strict; Max-Age=31536000{secure}",
        device_cookie_name(state)
    )
}

pub fn clear_session_cookie(state: &AppState) -> String {
    let secure = if state.cfg.secure_cookies() {
        "; Secure"
    } else {
        ""
    };
    format!(
        "{}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{secure}",
        cookie_name(state)
    )
}

pub fn read_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
}

/// Resolve the session for a request, enforcing idle and absolute expiry.
pub fn session_from_headers(
    state: &AppState,
    headers: &HeaderMap,
) -> anyhow::Result<Option<Session>> {
    let Some(token) = read_cookie(headers, cookie_name(state)) else {
        return Ok(None);
    };
    let now = now_ms();
    let idle = state.cfg.sessions.idle_days as i64 * 86_400_000;
    let db = state.db.lock();
    let row = db
        .query_row(
            "SELECT s.id, s.user_id, s.device_id, s.csrf, s.strong_auth_at, s.last_used_at, s.expires_at, s.auth_method, d.label, d.revoked_at
             FROM web_sessions s JOIN devices d ON d.id = s.device_id
             WHERE s.token_hash = ?1 AND s.revoked_at IS NULL",
            [sha256_hex(&token)],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, Option<i64>>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, i64>(6)?,
                    r.get::<_, String>(7)?,
                    r.get::<_, String>(8)?,
                    r.get::<_, Option<i64>>(9)?,
                ))
            },
        )
        .optional()?;
    let Some((
        id,
        user_id,
        device_id,
        csrf,
        strong,
        last_used,
        expires,
        method,
        label,
        device_revoked,
    )) = row
    else {
        return Ok(None);
    };
    if now > expires || now - last_used > idle || device_revoked.is_some() {
        db.execute(
            "UPDATE web_sessions SET revoked_at = ?1 WHERE id = ?2",
            params![now, id],
        )?;
        return Ok(None);
    }
    if now - last_used > 60_000 {
        db.execute(
            "UPDATE web_sessions SET last_used_at = ?1 WHERE id = ?2",
            params![now, id],
        )?;
        db.execute(
            "UPDATE devices SET last_seen_at = ?1 WHERE id = ?2",
            params![now, device_id],
        )?;
    }
    let user = db.query_row("SELECT * FROM users WHERE id = ?", [&user_id], row_user)?;
    if user.disabled {
        return Ok(None);
    }
    Ok(Some(Session {
        id,
        user,
        device_id,
        device_label: label,
        csrf,
        strong_auth_at: strong,
        auth_method: method,
    }))
}

pub fn mark_strong(state: &AppState, session_id: &str) -> anyhow::Result<()> {
    state.db.lock().execute(
        "UPDATE web_sessions SET strong_auth_at = ?1 WHERE id = ?2",
        params![now_ms(), session_id],
    )?;
    Ok(())
}

/// Rate limiting for login attempts: at most 10 failures per key per 15 minutes.
pub fn check_login_allowed(state: &AppState, keys: &[String]) -> Result<(), ApiError> {
    let now = now_ms();
    let map = state.login_failures.lock().unwrap();
    for k in keys {
        if let Some((count, start)) = map.get(k)
            && now - start < 15 * 60_000
            && *count >= 10
        {
            return Err(ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "Too many attempts. Try again in a few minutes.",
            ));
        }
    }
    Ok(())
}

pub fn record_login_failure(state: &AppState, keys: &[String]) {
    let now = now_ms();
    let mut map = state.login_failures.lock().unwrap();
    for k in keys {
        let entry = map.entry(k.clone()).or_insert((0, now));
        if now - entry.1 > 15 * 60_000 {
            *entry = (0, now);
        }
        entry.0 += 1;
    }
}

pub fn clear_login_failures(state: &AppState, keys: &[String]) {
    let mut map = state.login_failures.lock().unwrap();
    for k in keys {
        map.remove(k);
    }
}

/// Reject cross-origin state changes even when a cookie is present.
pub fn check_origin(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let expected = state.cfg.base_url();
    match headers
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
    {
        Some(origin) if origin.trim_end_matches('/') == expected => Ok(()),
        Some(_) => Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "bad_origin",
            "Cross-origin request refused.",
        )),
        // Same-origin fetches from Safari may omit Origin on some requests; fall back
        // to Sec-Fetch-Site when available.
        None => match headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
            Some("same-origin") | None => Ok(()),
            Some(_) => Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "bad_origin",
                "Cross-site request refused.",
            )),
        },
    }
}

/// Extractor for any logged-in browser session. State-changing methods also require
/// the per-session CSRF token and a same-origin request.
pub struct Authed(pub Session);

impl FromRequestParts<Shared> for Authed {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Shared,
    ) -> Result<Self, Self::Rejection> {
        let session = session_from_headers(state, &parts.headers)
            .map_err(ApiError::internal)?
            .ok_or_else(|| {
                ApiError::new(
                    StatusCode::UNAUTHORIZED,
                    "unauthenticated",
                    "Please sign in.",
                )
            })?;
        if parts.method != Method::GET && parts.method != Method::HEAD {
            check_origin(state, &parts.headers)?;
            let sent = parts
                .headers
                .get(CSRF_HEADER)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if !crate::util::ct_eq(sent.as_bytes(), session.csrf.as_bytes()) {
                return Err(ApiError::new(
                    StatusCode::FORBIDDEN,
                    "csrf",
                    "Session check failed. Reload the page.",
                ));
            }
        }
        Ok(Authed(session))
    }
}

pub fn require_admin(session: &Session) -> Result<(), ApiError> {
    if session.user.is_admin() {
        Ok(())
    } else {
        Err(ApiError::forbidden("Only administrators can do that."))
    }
}

pub fn require_strong(
    state: &AppState,
    session: &Session,
    minutes: Option<u32>,
) -> Result<(), ApiError> {
    let minutes = minutes.unwrap_or(state.cfg.sessions.strong_auth_minutes);
    if session.strong_within(minutes) {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "step_up_required",
            "Confirm with your passkey to continue.",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_roundtrip() {
        let h = hash_password("correct horse battery").unwrap();
        assert!(verify_password(&h, "correct horse battery"));
        assert!(!verify_password(&h, "wrong"));
        assert!(!verify_password("garbage", "x"));
    }

    #[test]
    fn labels_devices() {
        let iphone = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1";
        assert_eq!(
            device_label(iphone),
            ("Safari on iPhone".into(), "mobile".into())
        );
        let edge = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36 Edg/140.0";
        assert_eq!(device_label(edge).0, "Edge on Windows");
        let mac = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15";
        assert_eq!(device_label(mac).0, "Safari on Mac");
    }

    #[test]
    fn reads_cookies() {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::COOKIE,
            "a=1; __Host-asudo=tok; b=2".parse().unwrap(),
        );
        assert_eq!(read_cookie(&h, "__Host-asudo").as_deref(), Some("tok"));
        assert_eq!(read_cookie(&h, "c"), None);
    }
}

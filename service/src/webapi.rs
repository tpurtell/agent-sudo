//! Browser-facing JSON API. Cookie sessions, CSRF header, same-origin checks.

use std::convert::Infallible;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::header::{SET_COOKIE, USER_AGENT};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::sse::{KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use futures_util::Stream;
use rusqlite::{OptionalExtension, params};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

use crate::audit;
use crate::auth::{self, Authed, require_admin, require_strong};
use crate::engine::{self, DecideInput, DelegateInput, ListFilter};
use crate::error::{ApiError, ApiResult};
use crate::events::Event;
use crate::passkeys;
use crate::push;
use crate::state::{AppState, Shared};
use crate::util::{new_id, new_token, now_ms, sha256_hex};

pub fn router() -> Router<Shared> {
    Router::new()
        .route("/api/health", get(|| async { Json(json!({"ok": true})) }))
        .route("/api/session", get(session_info))
        .route("/api/setup", post(setup))
        .route("/api/invite/inspect", post(invite_inspect))
        .route("/api/invite/accept", post(invite_accept))
        .route("/api/login/password", post(login_password))
        .route("/api/login/passkey/start", post(login_passkey_start))
        .route("/api/login/passkey/finish", post(login_passkey_finish))
        .route("/api/logout", post(logout))
        .route("/api/stepup/start", post(stepup_start))
        .route("/api/stepup/finish", post(stepup_finish))
        .route("/api/passkeys", get(passkeys_list))
        .route("/api/passkeys/register/start", post(passkey_register_start))
        .route(
            "/api/passkeys/register/finish",
            post(passkey_register_finish),
        )
        .route(
            "/api/passkeys/{id}",
            delete(passkey_delete).patch(passkey_rename),
        )
        .route("/api/account", patch(account_update))
        .route("/api/account/password", post(account_password))
        .route("/api/requests", get(requests_list))
        .route("/api/requests/{id}", get(request_get))
        .route("/api/requests/{id}/decision", post(request_decide))
        .route("/api/requests/{id}/assess", post(request_assess))
        .route("/api/requests/{id}/flag", post(request_flag))
        .route("/api/grants", get(grants_list))
        .route("/api/grants/{id}/revoke", post(grant_revoke))
        .route("/api/grants/{id}/pause", post(grant_pause))
        .route("/api/grants/{id}/resume", post(grant_resume))
        .route("/api/delegations", post(delegation_create))
        .route("/api/hosts", get(hosts_list))
        .route("/api/hosts/tokens", post(host_token))
        .route("/api/hosts/{id}", patch(host_update))
        .route("/api/hosts/{id}/revoke", post(host_revoke))
        .route("/api/devices", get(devices_list))
        .route("/api/devices/{id}", patch(device_update))
        .route("/api/devices/{id}/revoke", post(device_revoke))
        .route("/api/push/subscribe", post(push_subscribe))
        .route("/api/push/unsubscribe", post(push_unsubscribe))
        .route("/api/push/test", post(push_test))
        .route("/api/users", get(users_list).post(user_create))
        .route("/api/users/{id}", patch(user_update))
        .route("/api/users/{id}/invite", post(user_invite))
        .route("/api/settings", get(settings_get))
        .route("/api/settings/automation", post(settings_automation))
        .route("/api/audit", get(audit_list))
        .route("/api/audit/export", get(audit_export))
        .route("/api/events", get(events))
}

fn ua(headers: &HeaderMap) -> String {
    headers
        .get(USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

fn client_ip(state: &AppState, headers: &HeaderMap) -> String {
    // Only meaningful behind a trusted proxy; used for rate limiting keys.
    if !state.cfg.trusted_proxies.is_empty()
        && let Some(v) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok())
    {
        return v.split(',').next().unwrap_or("").trim().to_string();
    }
    "direct".into()
}

fn with_cookies(body: Value, cookies: &[String]) -> Response {
    let mut resp = Json(body).into_response();
    for c in cookies {
        if let Ok(v) = HeaderValue::from_str(c) {
            resp.headers_mut().append(SET_COOKIE, v);
        }
    }
    resp
}

fn start_session(
    state: &AppState,
    headers: &HeaderMap,
    user: &auth::User,
    method: &str,
    strong: bool,
) -> ApiResult<Response> {
    let existing = auth::read_cookie(headers, auth::device_cookie_name(state));
    let s = auth::create_session(
        state,
        user,
        existing.as_deref(),
        &ua(headers),
        method,
        strong,
    )?;
    audit::record(
        &state.db,
        &user.name,
        "session.created",
        Some(&s.device_id),
        json!({"method": method, "user_agent": ua(headers)}),
    );
    state.emit(Event::Devices);
    Ok(with_cookies(
        json!({"ok": true}),
        &[
            auth::session_cookie(state, &s.token),
            auth::device_cookie(state, &s.device_id),
        ],
    ))
}

// ---------------------------------------------------------------------------
// Session and bootstrap

async fn session_info(State(state): State<Shared>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let setup_required = auth::user_count(&state)? == 0;
    let advisor = state.advisor.as_ref().map(|a| {
        json!({"model": a.config.model, "backend": a.config.backend, "auto_assess": a.config.auto_assess})
    });
    let base = json!({
        "name": state.cfg.name,
        "version": env!("CARGO_PKG_VERSION"),
        "setup_required": setup_required,
        "vapid_public_key": state.push.public_key_b64,
        "push_enabled": state.push.enabled(),
        "advisor": advisor,
        "automation": {"configured": state.cfg.policy.automation.enabled, "enabled": state.automation_enabled()},
        "strong_auth_minutes": state.cfg.sessions.strong_auth_minutes,
    });
    let Some(s) = auth::session_from_headers(&state, &headers)? else {
        let mut v = base;
        v["authenticated"] = json!(false);
        return Ok(Json(v));
    };
    let mut v = base;
    v["authenticated"] = json!(true);
    v["user"] = json!({"id": s.user.id, "name": s.user.name, "display_name": s.user.display_name, "role": s.user.role});
    v["device"] = json!({"id": s.device_id, "label": s.device_label});
    v["csrf"] = json!(s.csrf);
    v["strong_auth_at"] = json!(s.strong_auth_at);
    v["auth_method"] = json!(s.auth_method);
    v["passkeys"] = json!(auth::passkey_count(&state, &s.user.id)?);
    v["has_push"] = json!(!push::subscriptions_for_device(&state.db, &s.device_id)?.is_empty());
    v["counts"] = engine::quick_counts(&state)?;
    Ok(Json(v))
}

#[derive(Deserialize)]
struct SetupInput {
    token: String,
    name: String,
    display_name: String,
    password: String,
}

async fn setup(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(input): Json<SetupInput>,
) -> ApiResult<Response> {
    auth::check_origin(&state, &headers)?;
    if auth::user_count(&state)? > 0 {
        return Err(ApiError::conflict("Setup is already complete."));
    }
    let expected = state
        .db
        .setting("setup_token_hash")?
        .ok_or_else(|| ApiError::forbidden("No setup token is active."))?;
    if !crate::util::ct_eq(
        sha256_hex(input.token.trim()).as_bytes(),
        expected.as_bytes(),
    ) {
        return Err(ApiError::forbidden(
            "That setup link is not valid. Check the service log for the current one.",
        ));
    }
    auth::validate_username(&input.name)?;
    auth::validate_new_password(&input.password)?;
    let display = if input.display_name.trim().is_empty() {
        input.name.clone()
    } else {
        input.display_name.trim().to_string()
    };
    let pw = input.password.clone();
    let user = tokio::task::spawn_blocking({
        let state = state.clone();
        let name = input.name.clone();
        move || auth::create_user(&state, &name, &display, "admin", Some(&pw))
    })
    .await
    .map_err(ApiError::internal)??;
    state
        .db
        .lock()
        .execute("DELETE FROM settings WHERE key = 'setup_token_hash'", [])?;
    audit::record(
        &state.db,
        &user.name,
        "user.bootstrap",
        Some(&user.id),
        json!({"role": "admin"}),
    );
    start_session(&state, &headers, &user, "setup", false)
}

#[derive(Deserialize)]
struct TokenInput {
    token: String,
}

fn invite_lookup(state: &AppState, token: &str) -> ApiResult<(String, auth::User)> {
    let now = now_ms();
    let row = state
        .db
        .lock()
        .query_row(
            "SELECT id, user_id FROM invites WHERE token_hash = ?1 AND used_at IS NULL AND expires_at > ?2",
            params![sha256_hex(token.trim()), now],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )
        .optional()?;
    let (invite_id, user_id) =
        row.ok_or_else(|| ApiError::forbidden("This invitation is invalid or has expired."))?;
    let user = auth::user_by_id(state, &user_id)?
        .ok_or_else(|| ApiError::forbidden("This invitation is no longer valid."))?;
    Ok((invite_id, user))
}

async fn invite_inspect(
    State(state): State<Shared>,
    Json(input): Json<TokenInput>,
) -> ApiResult<Json<Value>> {
    let (_, user) = invite_lookup(&state, &input.token)?;
    Ok(Json(
        json!({"name": user.name, "display_name": user.display_name, "role": user.role}),
    ))
}

#[derive(Deserialize)]
struct InviteAccept {
    token: String,
    password: String,
}

async fn invite_accept(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(input): Json<InviteAccept>,
) -> ApiResult<Response> {
    auth::check_origin(&state, &headers)?;
    let (invite_id, user) = invite_lookup(&state, &input.token)?;
    auth::validate_new_password(&input.password)?;
    let hash = tokio::task::spawn_blocking(move || auth::hash_password(&input.password))
        .await
        .map_err(ApiError::internal)??;
    {
        let db = state.db.lock();
        db.execute(
            "UPDATE users SET password_hash = ?1 WHERE id = ?2",
            params![hash, user.id],
        )?;
        db.execute(
            "UPDATE invites SET used_at = ?1 WHERE id = ?2",
            params![now_ms(), invite_id],
        )?;
    }
    audit::record(
        &state.db,
        &user.name,
        "user.invite_accepted",
        Some(&user.id),
        json!({}),
    );
    start_session(&state, &headers, &user, "invite", false)
}

#[derive(Deserialize)]
struct PasswordLogin {
    name: String,
    password: String,
}

async fn login_password(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(input): Json<PasswordLogin>,
) -> ApiResult<Response> {
    auth::check_origin(&state, &headers)?;
    let keys = vec![
        format!("user:{}", input.name.to_lowercase()),
        format!("ip:{}", client_ip(&state, &headers)),
    ];
    auth::check_login_allowed(&state, &keys)?;
    let user = auth::user_by_name(&state, &input.name)?;
    let hash = user.as_ref().and_then(|u| u.password_hash.clone());
    let password = input.password.clone();
    let ok = tokio::task::spawn_blocking(move || match hash {
        Some(h) => auth::verify_password(&h, &password),
        None => {
            // Spend comparable time for unknown users.
            let _ = auth::hash_password(&password);
            false
        }
    })
    .await
    .map_err(ApiError::internal)?;
    let Some(user) = user.filter(|u| ok && !u.disabled) else {
        auth::record_login_failure(&state, &keys);
        audit::record(
            &state.db,
            &input.name,
            "login.failed",
            None,
            json!({"method": "password"}),
        );
        return Err(ApiError::unauthorized(
            "That username and password don't match.",
        ));
    };
    if !state.cfg.sessions.password_after_passkey && auth::passkey_count(&state, &user.id)? > 0 {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "passkey_required",
            "This account uses a passkey. Choose “Sign in with a passkey”.",
        ));
    }
    auth::clear_login_failures(&state, &keys);
    start_session(&state, &headers, &user, "password", false)
}

#[derive(Deserialize)]
struct PasskeyStart {
    #[serde(default)]
    name: Option<String>,
}

async fn login_passkey_start(
    State(state): State<Shared>,
    Json(input): Json<PasskeyStart>,
) -> ApiResult<Json<Value>> {
    let user = match input
        .name
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty())
    {
        Some(name) => Some(
            auth::user_by_name(&state, name)?
                .filter(|u| !u.disabled)
                .ok_or_else(|| ApiError::unauthorized("No passkey is registered for that name."))?,
        ),
        None => None,
    };
    let (ceremony, options) = passkeys::start_authentication(&state, user.as_ref())
        .map_err(|e| ApiError::bad_request(format!("{e}")))?;
    Ok(Json(json!({"ceremony": ceremony, "options": options})))
}

#[derive(Deserialize)]
struct PasskeyFinish {
    ceremony: String,
    credential: PublicKeyCredential,
}

async fn login_passkey_finish(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(input): Json<PasskeyFinish>,
) -> ApiResult<Response> {
    auth::check_origin(&state, &headers)?;
    let keys = vec![format!("ip:{}", client_ip(&state, &headers))];
    auth::check_login_allowed(&state, &keys)?;
    let user_id = match passkeys::finish_authentication(&state, &input.ceremony, &input.credential)
    {
        Ok(id) => id,
        Err(e) => {
            auth::record_login_failure(&state, &keys);
            audit::record(
                &state.db,
                "anonymous",
                "login.failed",
                None,
                json!({"method": "passkey", "error": e.to_string()}),
            );
            return Err(ApiError::unauthorized(format!(
                "Passkey sign-in failed: {e}"
            )));
        }
    };
    let user = auth::user_by_id(&state, &user_id)?
        .filter(|u| !u.disabled)
        .ok_or_else(|| ApiError::unauthorized("Account disabled."))?;
    start_session(&state, &headers, &user, "passkey", true)
}

async fn logout(State(state): State<Shared>, Authed(s): Authed) -> ApiResult<Response> {
    state.db.lock().execute(
        "UPDATE web_sessions SET revoked_at = ?1 WHERE id = ?2",
        params![now_ms(), s.id],
    )?;
    audit::record(
        &state.db,
        &s.user.name,
        "session.ended",
        Some(&s.device_id),
        json!({}),
    );
    Ok(with_cookies(
        json!({"ok": true}),
        &[auth::clear_session_cookie(&state)],
    ))
}

async fn stepup_start(State(state): State<Shared>, Authed(s): Authed) -> ApiResult<Json<Value>> {
    let (ceremony, options) = passkeys::start_authentication(&state, Some(&s.user))
        .map_err(|_| ApiError::bad_request("Register a passkey first (Account → Passkeys)."))?;
    Ok(Json(json!({"ceremony": ceremony, "options": options})))
}

async fn stepup_finish(
    State(state): State<Shared>,
    Authed(s): Authed,
    Json(input): Json<PasskeyFinish>,
) -> ApiResult<Json<Value>> {
    let user_id = passkeys::finish_authentication(&state, &input.ceremony, &input.credential)
        .map_err(|e| ApiError::unauthorized(format!("Passkey check failed: {e}")))?;
    if user_id != s.user.id {
        return Err(ApiError::unauthorized(
            "That passkey belongs to a different account.",
        ));
    }
    auth::mark_strong(&state, &s.id)?;
    audit::record(
        &state.db,
        &s.user.name,
        "session.step_up",
        Some(&s.device_id),
        json!({}),
    );
    Ok(Json(json!({"ok": true, "strong_auth_at": now_ms()})))
}

// ---------------------------------------------------------------------------
// Passkeys and account

async fn passkeys_list(State(state): State<Shared>, Authed(s): Authed) -> ApiResult<Json<Value>> {
    Ok(Json(json!({"items": passkeys::list(&state, &s.user.id)?})))
}

#[derive(Deserialize)]
struct NameInput {
    name: String,
}

async fn passkey_register_start(
    State(state): State<Shared>,
    Authed(s): Authed,
    Json(input): Json<NameInput>,
) -> ApiResult<Json<Value>> {
    if auth::passkey_count(&state, &s.user.id)? > 0 {
        require_strong(&state, &s, None)?;
    }
    let name = if input.name.trim().is_empty() {
        s.device_label.clone()
    } else {
        input.name.trim().chars().take(60).collect()
    };
    let (ceremony, options) = passkeys::start_registration(&state, &s.user, &name)?;
    Ok(Json(json!({"ceremony": ceremony, "options": options})))
}

#[derive(Deserialize)]
struct RegisterFinish {
    ceremony: String,
    credential: RegisterPublicKeyCredential,
}

async fn passkey_register_finish(
    State(state): State<Shared>,
    Authed(s): Authed,
    Json(input): Json<RegisterFinish>,
) -> ApiResult<Json<Value>> {
    let info =
        passkeys::finish_registration(&state, &s.user, &input.ceremony, &input.credential)
            .map_err(|e| ApiError::bad_request(format!("Could not register the passkey: {e}")))?;
    // Registering a key is not an assertion: it does not count as step-up.

    audit::record(
        &state.db,
        &s.user.name,
        "passkey.registered",
        Some(&info.id),
        json!({"name": info.name, "device": s.device_label}),
    );
    Ok(Json(json!(info)))
}

async fn passkey_delete(
    State(state): State<Shared>,
    Authed(s): Authed,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    require_strong(&state, &s, None)?;
    let n = state.db.lock().execute(
        "DELETE FROM passkeys WHERE id = ?1 AND user_id = ?2",
        params![id, s.user.id],
    )?;
    if n == 0 {
        return Err(ApiError::not_found("No such passkey."));
    }
    audit::record(
        &state.db,
        &s.user.name,
        "passkey.deleted",
        Some(&id),
        json!({}),
    );
    Ok(Json(json!({"ok": true})))
}

async fn passkey_rename(
    State(state): State<Shared>,
    Authed(s): Authed,
    Path(id): Path<String>,
    Json(input): Json<NameInput>,
) -> ApiResult<Json<Value>> {
    let name: String = input.name.trim().chars().take(60).collect();
    if name.is_empty() {
        return Err(ApiError::bad_request("Name cannot be empty."));
    }
    state.db.lock().execute(
        "UPDATE passkeys SET name = ?1 WHERE id = ?2 AND user_id = ?3",
        params![name, id, s.user.id],
    )?;
    Ok(Json(json!({"ok": true})))
}

#[derive(Deserialize)]
struct AccountUpdate {
    display_name: String,
}

async fn account_update(
    State(state): State<Shared>,
    Authed(s): Authed,
    Json(input): Json<AccountUpdate>,
) -> ApiResult<Json<Value>> {
    let name: String = input.display_name.trim().chars().take(80).collect();
    if name.is_empty() {
        return Err(ApiError::bad_request("Display name cannot be empty."));
    }
    state.db.lock().execute(
        "UPDATE users SET display_name = ?1 WHERE id = ?2",
        params![name, s.user.id],
    )?;
    Ok(Json(json!({"ok": true})))
}

#[derive(Deserialize)]
struct PasswordChange {
    password: String,
}

async fn account_password(
    State(state): State<Shared>,
    Authed(s): Authed,
    Json(input): Json<PasswordChange>,
) -> ApiResult<Json<Value>> {
    if auth::passkey_count(&state, &s.user.id)? > 0 {
        require_strong(&state, &s, None)?;
    }
    auth::validate_new_password(&input.password)?;
    let hash = tokio::task::spawn_blocking(move || auth::hash_password(&input.password))
        .await
        .map_err(ApiError::internal)??;
    state.db.lock().execute(
        "UPDATE users SET password_hash = ?1 WHERE id = ?2",
        params![hash, s.user.id],
    )?;
    audit::record(
        &state.db,
        &s.user.name,
        "user.password_changed",
        Some(&s.user.id),
        json!({}),
    );
    Ok(Json(json!({"ok": true})))
}

// ---------------------------------------------------------------------------
// Requests

#[derive(Deserialize)]
struct ListQuery {
    #[serde(default)]
    view: Option<String>,
    #[serde(default)]
    before: Option<i64>,
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    quiet: Option<bool>,
    #[serde(default)]
    host: Option<String>,
}

async fn requests_list(
    State(state): State<Shared>,
    Authed(_s): Authed,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Value>> {
    let filter = ListFilter {
        pending_only: q.view.as_deref() == Some("pending"),
        include_quiet: q.quiet.unwrap_or(false),
        before: q.before,
        limit: q.limit.unwrap_or(50).clamp(1, 200),
        host_id: q.host,
    };
    let rows = engine::requests(&state, &filter)?;
    let items: Vec<Value> = rows
        .iter()
        .map(|r| engine::request_view(&state, r, false))
        .collect();
    Ok(Json(
        json!({"items": items, "counts": engine::quick_counts(&state)?}),
    ))
}

async fn request_get(
    State(state): State<Shared>,
    Authed(_s): Authed,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let row =
        engine::request(&state, &id)?.ok_or_else(|| ApiError::not_found("No such request."))?;
    Ok(Json(engine::request_view(&state, &row, true)))
}

async fn request_decide(
    State(state): State<Shared>,
    Authed(s): Authed,
    Path(id): Path<String>,
    Json(input): Json<DecideInput>,
) -> ApiResult<Json<Value>> {
    Ok(Json(engine::decide(&state, &s, &id, input)?))
}

async fn request_assess(
    State(state): State<Shared>,
    Authed(s): Authed,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    if !s.user.can_decide() {
        return Err(ApiError::forbidden("Not allowed."));
    }
    if state.advisor.is_none() {
        return Err(ApiError::bad_request("No decision model is configured."));
    }
    let row =
        engine::request(&state, &id)?.ok_or_else(|| ApiError::not_found("No such request."))?;
    if row.assessment.running {
        return Ok(Json(json!({"ok": true})));
    }
    let st = state.clone();
    tokio::spawn(async move { engine::assess_in_background(&st, &id).await });
    Ok(Json(json!({"ok": true})))
}

async fn request_flag(
    State(state): State<Shared>,
    Authed(s): Authed,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    engine::flag(&state, &s, &id)?;
    Ok(Json(json!({"ok": true})))
}

// ---------------------------------------------------------------------------
// Grants and delegations

async fn grants_list(State(state): State<Shared>, Authed(_s): Authed) -> ApiResult<Json<Value>> {
    let now = now_ms();
    let items: Vec<Value> = engine::grants_recent(&state)?
        .iter()
        .map(|g| {
            let mut v = json!(g);
            v["active"] = json!(g.active(now));
            v["summary"] = json!(engine::grant_summary_with(&state, g, false));
            v
        })
        .collect();
    Ok(Json(
        json!({"items": items, "automation": {"enabled": state.automation_enabled(), "configured": state.cfg.policy.automation.enabled}}),
    ))
}

async fn grant_revoke(
    State(state): State<Shared>,
    Authed(s): Authed,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    if !s.user.can_decide() {
        return Err(ApiError::forbidden("Not allowed."));
    }
    let n = state.db.lock().execute(
        "UPDATE grants SET revoked_at = ?1, revoked_by = ?2 WHERE id = ?3 AND revoked_at IS NULL",
        params![now_ms(), s.user.name, id],
    )?;
    if n > 0 {
        audit::record(
            &state.db,
            &s.user.name,
            "grant.revoked",
            Some(&id),
            json!({"device": s.device_label}),
        );
        state.emit(Event::Grants);
    }
    Ok(Json(json!({"ok": true})))
}

async fn grant_pause(
    State(state): State<Shared>,
    Authed(s): Authed,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    if !s.user.can_decide() {
        return Err(ApiError::forbidden("Not allowed."));
    }
    engine::pause(
        &state,
        &id,
        &format!("paused by {}", s.user.name),
        &s.user.name,
    )?;
    Ok(Json(json!({"ok": true})))
}

async fn grant_resume(
    State(state): State<Shared>,
    Authed(s): Authed,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    if !s.user.can_decide() {
        return Err(ApiError::forbidden("Not allowed."));
    }
    let g = engine::grant(&state, &id)?.ok_or_else(|| ApiError::not_found("No such grant."))?;
    if g.kind == "delegation" {
        require_strong(&state, &s, None)?;
    }
    if g.max_uses.is_some_and(|m| g.uses >= m) {
        return Err(ApiError::bad_request(
            "This delegation has used all its approvals. Create a new one.",
        ));
    }
    state.db.lock().execute("UPDATE grants SET paused_at = NULL, pause_reason = NULL WHERE id = ?1 AND revoked_at IS NULL", [&id])?;
    state.delegation_declines.lock().unwrap().remove(&id);
    audit::record(
        &state.db,
        &s.user.name,
        "delegation.resumed",
        Some(&id),
        json!({}),
    );
    state.emit(Event::Grants);
    Ok(Json(json!({"ok": true})))
}

#[derive(Deserialize)]
struct DelegationCreate {
    #[serde(flatten)]
    delegate: DelegateInput,
    #[serde(default)]
    host_id: Option<String>,
}

async fn delegation_create(
    State(state): State<Shared>,
    Authed(s): Authed,
    Json(input): Json<DelegationCreate>,
) -> ApiResult<Json<Value>> {
    if !s.user.can_decide() {
        return Err(ApiError::forbidden("Not allowed."));
    }
    require_strong(&state, &s, None)?;
    if !state.automation_enabled() {
        return Err(ApiError::bad_request("Automation is switched off."));
    }
    if state.advisor.is_none() {
        return Err(ApiError::bad_request("No decision model is configured."));
    }
    // A host is only needed for host-scoped delegations; otherwise use a placeholder.
    let host = match &input.host_id {
        Some(id) => {
            engine::host(&state, id)?.ok_or_else(|| ApiError::not_found("Unknown host."))?
        }
        None => {
            if input.delegate.hosts == "host" {
                return Err(ApiError::bad_request("Choose a host."));
            }
            engine::HostRow {
                id: String::new(),
                name: String::new(),
                hostname: String::new(),
                public_key: String::new(),
                groups: input.delegate.groups.clone(),
                hostd_version: String::new(),
                created_at: 0,
                last_seen_at: None,
                revoked_at: None,
            }
        }
    };
    let (id, spec) = engine::create_delegation(&state, &s, &host, &input.delegate)?;
    Ok(Json(json!({"id": id, "spec": spec})))
}

// ---------------------------------------------------------------------------
// Hosts

async fn hosts_list(State(state): State<Shared>, Authed(_s): Authed) -> ApiResult<Json<Value>> {
    let now = now_ms();
    let hosts = engine::hosts(&state)?;
    let mut groups: Vec<String> = hosts.iter().flat_map(|h| h.groups.clone()).collect();
    groups.sort();
    groups.dedup();
    let items: Vec<Value> = hosts
        .iter()
        .map(|h| {
            let mut v = json!(h);
            v["online"] =
                json!(h.revoked_at.is_none() && h.last_seen_at.is_some_and(|t| now - t < 150_000));
            v
        })
        .collect();
    let tokens: Vec<Value> = {
        let db = state.db.lock();
        let mut stmt = db.prepare("SELECT id, name_hint, groups_json, created_at, expires_at FROM enrollment_tokens WHERE used_at IS NULL AND expires_at > ? ORDER BY created_at DESC")?;
        stmt.query_map([now], |r| {
            Ok(json!({"id": r.get::<_, String>(0)?, "name": r.get::<_, Option<String>>(1)?, "groups": serde_json::from_str::<Value>(&r.get::<_, String>(2)?).unwrap_or_default(), "created_at": r.get::<_, i64>(3)?, "expires_at": r.get::<_, i64>(4)?}))
        })?
        .collect::<Result<Vec<_>, _>>()?
    };
    Ok(Json(
        json!({"items": items, "groups": groups, "pending_tokens": tokens}),
    ))
}

fn clean_groups(groups: &[String]) -> ApiResult<Vec<String>> {
    let mut out: Vec<String> = groups
        .iter()
        .map(|g| g.trim().to_lowercase())
        .filter(|g| !g.is_empty())
        .collect();
    if out.iter().any(|g| {
        g.len() > 40
            || !g
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
    }) {
        return Err(ApiError::bad_request(
            "Group names use letters, digits, - _ .",
        ));
    }
    out.sort();
    out.dedup();
    Ok(out)
}

#[derive(Deserialize)]
struct TokenCreate {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    groups: Vec<String>,
    #[serde(default)]
    ttl_minutes: Option<u32>,
}

async fn host_token(
    State(state): State<Shared>,
    Authed(s): Authed,
    Json(input): Json<TokenCreate>,
) -> ApiResult<Json<Value>> {
    require_admin(&s)?;
    require_strong(&state, &s, None)?;
    let groups = clean_groups(&input.groups)?;
    let token = new_token();
    let id = new_id("enr");
    let now = now_ms();
    let expires = now + input.ttl_minutes.unwrap_or(60).clamp(5, 7 * 24 * 60) as i64 * 60_000;
    let name = input
        .name
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty());
    state.db.lock().execute(
        "INSERT INTO enrollment_tokens (id, token_hash, created_by, name_hint, groups_json, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![id, sha256_hex(&token), s.user.name, name, serde_json::to_string(&groups).unwrap(), now, expires],
    )?;
    audit::record(
        &state.db,
        &s.user.name,
        "host.token_created",
        Some(&id),
        json!({"name": name, "groups": groups}),
    );
    state.emit(Event::Hosts);
    // Enroll and start the relay in one paste (binaries installed by install.sh).
    let command = format!(
        "sudo agent-sudo-hostd enroll --service {} --token {} && sudo systemctl enable --now agent-sudo-hostd",
        state.cfg.base_url(),
        token
    );
    Ok(Json(
        json!({"id": id, "token": token, "expires_at": expires, "command": command}),
    ))
}

#[derive(Deserialize)]
struct HostUpdate {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    groups: Option<Vec<String>>,
}

async fn host_update(
    State(state): State<Shared>,
    Authed(s): Authed,
    Path(id): Path<String>,
    Json(input): Json<HostUpdate>,
) -> ApiResult<Json<Value>> {
    require_admin(&s)?;
    let host = engine::host(&state, &id)?.ok_or_else(|| ApiError::not_found("No such host."))?;
    if let Some(name) = input.name.map(|n| n.trim().to_string()) {
        if name.is_empty() || name.len() > 64 {
            return Err(ApiError::bad_request("Host names need 1-64 characters."));
        }
        state
            .db
            .lock()
            .execute(
                "UPDATE hosts SET name = ?1 WHERE id = ?2",
                params![name, id],
            )
            .map_err(|_| ApiError::conflict("Another host already has that name."))?;
    }
    if let Some(groups) = input.groups {
        let groups = clean_groups(&groups)?;
        state.db.lock().execute(
            "UPDATE hosts SET groups_json = ?1 WHERE id = ?2",
            params![serde_json::to_string(&groups).unwrap(), id],
        )?;
    }
    audit::record(
        &state.db,
        &s.user.name,
        "host.updated",
        Some(&id),
        json!({"previous_name": host.name}),
    );
    state.emit(Event::Hosts);
    Ok(Json(json!({"ok": true})))
}

async fn host_revoke(
    State(state): State<Shared>,
    Authed(s): Authed,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    require_admin(&s)?;
    require_strong(&state, &s, None)?;
    state.db.lock().execute(
        "UPDATE hosts SET revoked_at = ?1 WHERE id = ?2 AND revoked_at IS NULL",
        params![now_ms(), id],
    )?;
    audit::record(
        &state.db,
        &s.user.name,
        "host.revoked",
        Some(&id),
        json!({}),
    );
    state.emit(Event::Hosts);
    Ok(Json(json!({"ok": true})))
}

// ---------------------------------------------------------------------------
// Devices and push

async fn devices_list(State(state): State<Shared>, Authed(s): Authed) -> ApiResult<Json<Value>> {
    let db = state.db.lock();
    let mut stmt = db.prepare(
        "SELECT d.id, d.label, d.kind, d.user_agent, d.created_at, d.last_seen_at,
            (SELECT COUNT(*) FROM push_subscriptions p WHERE p.device_id = d.id),
            (SELECT COUNT(*) FROM web_sessions w WHERE w.device_id = d.id AND w.revoked_at IS NULL AND w.expires_at > ?2)
         FROM devices d WHERE d.user_id = ?1 AND d.revoked_at IS NULL ORDER BY d.last_seen_at DESC",
    )?;
    let items: Vec<Value> = stmt
        .query_map(params![s.user.id, now_ms()], |r| {
            let id: String = r.get(0)?;
            Ok(json!({
                "id": id,
                "label": r.get::<_, String>(1)?,
                "kind": r.get::<_, String>(2)?,
                "user_agent": r.get::<_, String>(3)?,
                "created_at": r.get::<_, i64>(4)?,
                "last_seen_at": r.get::<_, i64>(5)?,
                "push": r.get::<_, i64>(6)? > 0,
                "signed_in": r.get::<_, i64>(7)? > 0,
                "current": id == s.device_id,
            }))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(json!({"items": items})))
}

#[derive(Deserialize)]
struct LabelInput {
    label: String,
}

async fn device_update(
    State(state): State<Shared>,
    Authed(s): Authed,
    Path(id): Path<String>,
    Json(input): Json<LabelInput>,
) -> ApiResult<Json<Value>> {
    let label: String = input.label.trim().chars().take(60).collect();
    if label.is_empty() {
        return Err(ApiError::bad_request("Name cannot be empty."));
    }
    state.db.lock().execute(
        "UPDATE devices SET label = ?1 WHERE id = ?2 AND user_id = ?3",
        params![label, id, s.user.id],
    )?;
    state.emit(Event::Devices);
    Ok(Json(json!({"ok": true})))
}

async fn device_revoke(
    State(state): State<Shared>,
    Authed(s): Authed,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    let now = now_ms();
    {
        let db = state.db.lock();
        let n = db.execute("UPDATE devices SET revoked_at = ?1 WHERE id = ?2 AND user_id = ?3 AND revoked_at IS NULL", params![now, id, s.user.id])?;
        if n == 0 {
            return Err(ApiError::not_found("No such device."));
        }
        db.execute(
            "UPDATE web_sessions SET revoked_at = ?1 WHERE device_id = ?2 AND revoked_at IS NULL",
            params![now, id],
        )?;
        db.execute("DELETE FROM push_subscriptions WHERE device_id = ?", [&id])?;
    }
    audit::record(
        &state.db,
        &s.user.name,
        "device.revoked",
        Some(&id),
        json!({"from": s.device_label}),
    );
    state.emit(Event::Devices);
    if id == s.device_id {
        return Ok(with_cookies(
            json!({"ok": true, "signed_out": true}),
            &[auth::clear_session_cookie(&state)],
        ));
    }
    Ok(Json(json!({"ok": true})).into_response())
}

#[derive(Deserialize)]
struct PushKeys {
    p256dh: String,
    auth: String,
}

#[derive(Deserialize)]
struct PushSubscribe {
    endpoint: String,
    keys: PushKeys,
}

async fn push_subscribe(
    State(state): State<Shared>,
    Authed(s): Authed,
    Json(input): Json<PushSubscribe>,
) -> ApiResult<Json<Value>> {
    let url = url::Url::parse(&input.endpoint)
        .map_err(|_| ApiError::bad_request("Invalid push endpoint."))?;
    if url.scheme() != "https" {
        return Err(ApiError::bad_request("Push endpoints must be https."));
    }
    // Only real browser push services: approver subscriptions receive every command.
    let host = url.host_str().unwrap_or("");
    if !state.cfg.push.allowed_hosts.iter().any(|allowed| {
        allowed
            .strip_prefix("*.")
            .map_or(host == allowed, |suffix| {
                host.ends_with(&format!(".{suffix}"))
            })
    }) {
        return Err(ApiError::bad_request(format!(
            "{host} is not a recognised push service."
        )));
    }
    // Validate the keys now rather than failing silently at send time.
    push::encrypt(b"{}", &input.keys.p256dh, &input.keys.auth)
        .map_err(|_| ApiError::bad_request("Invalid push keys."))?;
    {
        let db = state.db.lock();
        db.execute(
            "DELETE FROM push_subscriptions WHERE device_id = ?1 OR endpoint = ?2",
            params![s.device_id, input.endpoint],
        )?;
        db.execute(
            "INSERT INTO push_subscriptions (id, device_id, endpoint, p256dh, auth, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![new_id("psh"), s.device_id, input.endpoint, input.keys.p256dh, input.keys.auth, now_ms()],
        )?;
    }
    audit::record(
        &state.db,
        &s.user.name,
        "push.subscribed",
        Some(&s.device_id),
        json!({"service": url.host_str()}),
    );
    state.emit(Event::Devices);
    Ok(Json(json!({"ok": true})))
}

#[derive(Deserialize)]
struct PushUnsubscribe {
    #[serde(default)]
    endpoint: Option<String>,
}

async fn push_unsubscribe(
    State(state): State<Shared>,
    Authed(s): Authed,
    Json(input): Json<PushUnsubscribe>,
) -> ApiResult<Json<Value>> {
    let db = state.db.lock();
    match input.endpoint {
        Some(e) => db.execute(
            "DELETE FROM push_subscriptions WHERE endpoint = ?1 AND device_id = ?2",
            params![e, s.device_id],
        )?,
        None => db.execute(
            "DELETE FROM push_subscriptions WHERE device_id = ?1",
            [&s.device_id],
        )?,
    };
    drop(db);
    state.emit(Event::Devices);
    Ok(Json(json!({"ok": true})))
}

async fn push_test(State(state): State<Shared>, Authed(s): Authed) -> ApiResult<Json<Value>> {
    let subs = push::subscriptions_for_device(&state.db, &s.device_id)?;
    if subs.is_empty() {
        return Err(ApiError::bad_request(
            "Notifications are not enabled on this device.",
        ));
    }
    let payload = json!({"t": "test", "title": "Notifications are working", "body": format!("{} will alert this device when an agent needs sudo.", state.cfg.name), "url": "/"});
    let mut results = vec![];
    for sub in &subs {
        let r = state.push.send(sub, &payload, 60, None).await;
        push::record_delivery(&state.db, sub, &r);
        results.push(format!("{r:?}"));
    }
    let ok = results.iter().any(|r| r == "Sent");
    if !ok {
        return Err(ApiError::new(
            StatusCode::BAD_GATEWAY,
            "push_failed",
            format!(
                "The push service refused the message: {}",
                results.join("; ")
            ),
        ));
    }
    Ok(Json(json!({"ok": true})))
}

// ---------------------------------------------------------------------------
// Users

async fn users_list(State(state): State<Shared>, Authed(s): Authed) -> ApiResult<Json<Value>> {
    require_admin(&s)?;
    let users = auth::list_users(&state)?;
    let items: Vec<Value> = users
        .iter()
        .map(|u| {
            let mut v = json!(u);
            v["passkeys"] = json!(auth::passkey_count(&state, &u.id).unwrap_or(0));
            v["has_password"] = json!(u.password_hash.is_some());
            v
        })
        .collect();
    Ok(Json(json!({"items": items})))
}

fn make_invite(state: &AppState, user: &auth::User, by: &str) -> ApiResult<String> {
    let token = new_token();
    let now = now_ms();
    state.db.lock().execute(
        "INSERT INTO invites (id, token_hash, user_id, created_by, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![new_id("inv"), sha256_hex(&token), user.id, by, now, now + 48 * 3_600_000],
    )?;
    Ok(format!("{}/invite#{}", state.cfg.base_url(), token))
}

#[derive(Deserialize)]
struct UserCreate {
    name: String,
    #[serde(default)]
    display_name: String,
    role: String,
}

async fn user_create(
    State(state): State<Shared>,
    Authed(s): Authed,
    Json(input): Json<UserCreate>,
) -> ApiResult<Json<Value>> {
    require_admin(&s)?;
    require_strong(&state, &s, None)?;
    auth::validate_username(&input.name)?;
    if !["admin", "approver", "viewer"].contains(&input.role.as_str()) {
        return Err(ApiError::bad_request(
            "Role must be admin, approver, or viewer.",
        ));
    }
    if auth::user_by_name(&state, &input.name)?.is_some() {
        return Err(ApiError::conflict("That username is taken."));
    }
    let display = if input.display_name.trim().is_empty() {
        input.name.clone()
    } else {
        input.display_name.trim().to_string()
    };
    let user = auth::create_user(&state, &input.name, &display, &input.role, None)?;
    let invite = make_invite(&state, &user, &s.user.name)?;
    audit::record(
        &state.db,
        &s.user.name,
        "user.created",
        Some(&user.id),
        json!({"name": user.name, "role": user.role}),
    );
    state.emit(Event::Users);
    Ok(Json(json!({"user": user, "invite_url": invite})))
}

#[derive(Deserialize)]
struct UserUpdate {
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    disabled: Option<bool>,
}

async fn user_update(
    State(state): State<Shared>,
    Authed(s): Authed,
    Path(id): Path<String>,
    Json(input): Json<UserUpdate>,
) -> ApiResult<Json<Value>> {
    require_admin(&s)?;
    require_strong(&state, &s, None)?;
    let user =
        auth::user_by_id(&state, &id)?.ok_or_else(|| ApiError::not_found("No such user."))?;
    if id == s.user.id
        && (input.disabled == Some(true) || input.role.as_deref().is_some_and(|r| r != "admin"))
    {
        return Err(ApiError::bad_request(
            "You cannot demote or disable yourself.",
        ));
    }
    let db = state.db.lock();
    if let Some(role) = &input.role {
        if !["admin", "approver", "viewer"].contains(&role.as_str()) {
            return Err(ApiError::bad_request("Unknown role."));
        }
        db.execute(
            "UPDATE users SET role = ?1 WHERE id = ?2",
            params![role, id],
        )?;
    }
    if let Some(name) = &input.display_name {
        db.execute(
            "UPDATE users SET display_name = ?1 WHERE id = ?2",
            params![name.trim(), id],
        )?;
    }
    if let Some(disabled) = input.disabled {
        let now = now_ms();
        db.execute(
            "UPDATE users SET disabled_at = ?1 WHERE id = ?2",
            params![disabled.then_some(now), id],
        )?;
        if disabled {
            db.execute(
                "UPDATE web_sessions SET revoked_at = ?1 WHERE user_id = ?2 AND revoked_at IS NULL",
                params![now, id],
            )?;
        }
    }
    drop(db);
    audit::record(
        &state.db,
        &s.user.name,
        "user.updated",
        Some(&id),
        json!({"name": user.name, "role": input.role, "disabled": input.disabled}),
    );
    state.emit(Event::Users);
    Ok(Json(json!({"ok": true})))
}

async fn user_invite(
    State(state): State<Shared>,
    Authed(s): Authed,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    require_admin(&s)?;
    require_strong(&state, &s, None)?;
    let user =
        auth::user_by_id(&state, &id)?.ok_or_else(|| ApiError::not_found("No such user."))?;
    let invite = make_invite(&state, &user, &s.user.name)?;
    audit::record(
        &state.db,
        &s.user.name,
        "user.invited",
        Some(&id),
        json!({"name": user.name}),
    );
    Ok(Json(json!({"invite_url": invite})))
}

// ---------------------------------------------------------------------------
// Settings, audit, events

async fn settings_get(State(state): State<Shared>, Authed(_s): Authed) -> ApiResult<Json<Value>> {
    let classes: Vec<Value> = state
        .cfg
        .policy
        .effective_classes()
        .iter()
        .map(|c| {
            let mut v = engine::class_view(c);
            v["executables"] = json!(c.executables);
            v["argv_prefix"] = json!(c.argv_prefix);
            v["features"] = json!(c.features);
            v["modes"] = json!(c.modes);
            v["always_deny"] = json!(c.always_deny);
            v
        })
        .collect();
    let advisor = state.advisor.as_ref().map(|a| {
        json!({
            "backend": a.config.backend,
            "model": a.config.model,
            "url": a.config.url,
            "auto_assess": a.config.auto_assess,
            "history_max_requests": a.config.history_max_requests,
            "history_max_age_minutes": a.config.history_max_age_minutes,
            "max_suggested_ttl_minutes": a.config.max_suggested_ttl_minutes,
        })
    });
    Ok(Json(json!({
        "name": state.cfg.name,
        "public_url": state.cfg.base_url(),
        "classes": classes,
        "advisor": advisor,
        "automation": {
            "configured": state.cfg.policy.automation.enabled,
            "enabled": state.automation_enabled(),
            "max_ttl_minutes": state.cfg.policy.automation.max_ttl_minutes,
            "max_decisions": state.cfg.policy.automation.max_decisions,
            "pause_after_declines": state.cfg.policy.automation.pause_after_declines,
            "forbidden_features": state.cfg.policy.automation.forbidden_features,
            "default_limits": state.cfg.policy.automation.default_limits,
        },
        "sessions": state.cfg.sessions,
    })))
}

#[derive(Deserialize)]
struct AutomationToggle {
    enabled: bool,
}

async fn settings_automation(
    State(state): State<Shared>,
    Authed(s): Authed,
    Json(input): Json<AutomationToggle>,
) -> ApiResult<Json<Value>> {
    if !s.user.can_decide() {
        return Err(ApiError::forbidden("Not allowed."));
    }
    // Anyone who can approve can stop automation; turning it back on needs an admin passkey.
    if input.enabled {
        require_admin(&s)?;
        require_strong(&state, &s, None)?;
    }
    state.db.set_setting(
        "automation_enabled",
        if input.enabled { "true" } else { "false" },
    )?;
    audit::record(
        &state.db,
        &s.user.name,
        if input.enabled {
            "automation.enabled"
        } else {
            "automation.disabled"
        },
        None,
        json!({"device": s.device_label}),
    );
    state.emit(Event::Settings);
    state.emit(Event::Grants);
    Ok(Json(json!({"enabled": state.automation_enabled()})))
}

#[derive(Deserialize)]
struct AuditQuery {
    #[serde(default)]
    before: Option<i64>,
    #[serde(default)]
    limit: Option<i64>,
}

fn audit_rows(state: &AppState, before: i64, limit: i64) -> ApiResult<Vec<Value>> {
    let db = state.db.lock();
    let mut stmt = db.prepare("SELECT seq, at, actor, kind, subject, detail_json FROM audit WHERE seq < ?1 ORDER BY seq DESC LIMIT ?2")?;
    let rows = stmt
        .query_map(params![before, limit], |r| {
            Ok(json!({
                "seq": r.get::<_, i64>(0)?,
                "at": r.get::<_, i64>(1)?,
                "actor": r.get::<_, String>(2)?,
                "kind": r.get::<_, String>(3)?,
                "subject": r.get::<_, Option<String>>(4)?,
                "detail": serde_json::from_str::<Value>(&r.get::<_, String>(5)?).unwrap_or(Value::Null),
            }))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

async fn audit_list(
    State(state): State<Shared>,
    Authed(_s): Authed,
    Query(q): Query<AuditQuery>,
) -> ApiResult<Json<Value>> {
    let items = audit_rows(
        &state,
        q.before.unwrap_or(i64::MAX),
        q.limit.unwrap_or(100).clamp(1, 500),
    )?;
    Ok(Json(json!({"items": items})))
}

async fn audit_export(State(state): State<Shared>, Authed(s): Authed) -> ApiResult<Response> {
    require_admin(&s)?;
    let rows = audit_rows(&state, i64::MAX, 1_000_000)?;
    let mut body = String::new();
    for r in rows.iter().rev() {
        body.push_str(&r.to_string());
        body.push('\n');
    }
    audit::record(
        &state.db,
        &s.user.name,
        "audit.exported",
        None,
        json!({"rows": rows.len()}),
    );
    Ok((
        [
            (axum::http::header::CONTENT_TYPE, "application/x-ndjson"),
            (
                axum::http::header::CONTENT_DISPOSITION,
                "attachment; filename=\"agent-sudo-audit.jsonl\"",
            ),
        ],
        body,
    )
        .into_response())
}

async fn events(
    State(state): State<Shared>,
    Authed(_s): Authed,
) -> Sse<impl Stream<Item = Result<axum::response::sse::Event, Infallible>>> {
    let stream = BroadcastStream::new(state.events.subscribe()).filter_map(|e| {
        e.ok().map(|event| {
            Ok(axum::response::sse::Event::default()
                .event(event.name())
                .data(serde_json::to_string(&event).unwrap_or_default()))
        })
    });
    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("ping"),
    )
}

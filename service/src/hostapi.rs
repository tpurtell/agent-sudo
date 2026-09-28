//! Host-facing API. Every call except enrollment is signed by the host's Ed25519 key.

use std::time::Duration;

use agent_sudo_protocol::api::{
    CancelRequest, EnrollRequest, EnrollResponse, HeartbeatRequest, HeartbeatResponse,
    RequestEnvelope,
};
use agent_sudo_protocol::signing;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::routing::{get, post};
use axum::{Json, Router};
use rusqlite::{OptionalExtension, params};
use serde::Deserialize;
use serde_json::json;

use crate::audit;
use crate::engine::{self, HostRow};
use crate::error::{ApiError, ApiResult};
use crate::events::Event;
use crate::state::{AppState, Shared};
use crate::util::{new_id, now_ms, now_secs, sha256_hex};

pub fn router() -> Router<Shared> {
    Router::new()
        .route("/api/v1/enroll", post(enroll))
        .route("/api/v1/requests", post(submit))
        .route("/api/v1/requests/{id}/decision", get(decision))
        .route("/api/v1/requests/{id}/cancel", post(cancel))
        .route("/api/v1/heartbeat", post(heartbeat))
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> ApiResult<&'a str> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::unauthorized(format!("missing {name}")))
}

/// Verify the request signature and return the host.
pub fn verify(
    state: &AppState,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
) -> ApiResult<HostRow> {
    let host_id = header(headers, signing::HEADER_HOST)?;
    let time: i64 = header(headers, signing::HEADER_TIME)?
        .parse()
        .map_err(|_| ApiError::unauthorized("bad timestamp"))?;
    let nonce = header(headers, signing::HEADER_NONCE)?;
    let signature = header(headers, signing::HEADER_SIGNATURE)?;
    if (now_secs() - time).abs() > signing::MAX_SKEW_SECS {
        return Err(ApiError::unauthorized(
            "clock skew too large; check NTP on the host",
        ));
    }
    if nonce.len() < 16 || nonce.len() > 64 {
        return Err(ApiError::unauthorized("bad nonce"));
    }
    let host =
        engine::host(state, host_id)?.ok_or_else(|| ApiError::unauthorized("unknown host"))?;
    if host.revoked_at.is_some() {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "host_revoked",
            "this host has been revoked",
        ));
    }
    let key = signing::decode_public_key(&host.public_key)
        .map_err(|_| ApiError::internal("stored host key is invalid"))?;
    let path = uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or(uri.path());
    let message = signing::canonical(method.as_str(), path, host_id, time, nonce, body);
    signing::verify(&key, &message, signature)
        .map_err(|_| ApiError::unauthorized("bad signature"))?;
    let replay_key = format!("{host_id}:{nonce}");
    {
        let mut nonces = state.nonces.lock().unwrap();
        if nonces.contains_key(&replay_key) {
            return Err(ApiError::unauthorized("replayed request"));
        }
        nonces.insert(replay_key, now_ms());
    }
    Ok(host)
}

fn touch(state: &AppState, host: &HostRow) {
    let now = now_ms();
    if host.last_seen_at.is_none_or(|t| now - t > 30_000) {
        let _ = state.db.lock().execute(
            "UPDATE hosts SET last_seen_at = ?1 WHERE id = ?2",
            params![now, host.id],
        );
        if host.last_seen_at.is_none_or(|t| now - t > 180_000) {
            state.emit(Event::Hosts);
        }
    }
}

async fn enroll(
    State(state): State<Shared>,
    Json(req): Json<EnrollRequest>,
) -> ApiResult<Json<EnrollResponse>> {
    signing::decode_public_key(&req.public_key)
        .map_err(|_| ApiError::bad_request("invalid public key"))?;
    let now = now_ms();
    let token_hash = sha256_hex(req.token.trim());
    let token = state
        .db
        .lock()
        .query_row(
            "SELECT id, name_hint, groups_json, created_by FROM enrollment_tokens WHERE token_hash = ?1 AND used_at IS NULL AND expires_at > ?2",
            params![token_hash, now],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, String>(2)?, r.get::<_, Option<String>>(3)?)),
        )
        .optional()?;
    let Some((token_id, name_hint, groups, created_by)) = token else {
        audit::record(
            &state.db,
            "anonymous",
            "host.enroll_failed",
            None,
            json!({"hostname": req.hostname}),
        );
        return Err(ApiError::unauthorized(
            "enrollment token is invalid, used, or expired",
        ));
    };
    let base_name = name_hint
        .filter(|n| !n.trim().is_empty())
        .unwrap_or_else(|| req.hostname.split('.').next().unwrap_or("host").to_string());
    let host_id = new_id("hst");
    let name = {
        let db = state.db.lock();
        let mut name = base_name.clone();
        let mut n = 2;
        while db
            .query_row("SELECT 1 FROM hosts WHERE name = ?", [&name], |_| Ok(()))
            .optional()?
            .is_some()
        {
            name = format!("{base_name}-{n}");
            n += 1;
        }
        db.execute(
            "INSERT INTO hosts (id, name, hostname, public_key, groups_json, hostd_version, enrolled_by, created_at, last_seen_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)",
            params![host_id, name, req.hostname, req.public_key, groups, req.hostd_version, created_by, now],
        )?;
        db.execute(
            "UPDATE enrollment_tokens SET used_at = ?1, used_by_host = ?2 WHERE id = ?3",
            params![now, host_id, token_id],
        )?;
        name
    };
    audit::record(
        &state.db,
        &format!("host:{name}"),
        "host.enrolled",
        Some(&host_id),
        json!({"hostname": req.hostname, "token": token_id}),
    );
    state.emit(Event::Hosts);
    Ok(Json(EnrollResponse {
        host_id,
        name,
        service_name: state.cfg.name.clone(),
    }))
}

async fn submit(
    State(state): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<agent_sudo_protocol::api::SubmitResponse>> {
    let host = verify(&state, &method, &uri, &headers, &body)?;
    touch(&state, &host);
    let env: RequestEnvelope = serde_json::from_slice(&body)
        .map_err(|e| ApiError::bad_request(format!("invalid request: {e}")))?;
    if env.client_request_id.is_empty() || env.client_request_id.len() > 64 {
        return Err(ApiError::bad_request("invalid client_request_id"));
    }
    if env.argv.len() > 4096
        || env
            .untrusted
            .context
            .as_ref()
            .is_some_and(|c| c.len() > 16_000)
    {
        return Err(ApiError::bad_request("request too large"));
    }
    Ok(Json(engine::submit(&state, &host, env).await?))
}

#[derive(Deserialize)]
struct WaitQuery {
    #[serde(default)]
    wait: u64,
}

async fn decision(
    State(state): State<Shared>,
    Path(id): Path<String>,
    Query(q): Query<WaitQuery>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> ApiResult<Json<agent_sudo_protocol::api::DecisionResponse>> {
    let host = verify(&state, &method, &uri, &headers, b"")?;
    touch(&state, &host);
    let wait = Duration::from_secs(q.wait.min(55));
    engine::wait_decision(&state, &host.id, &id, wait)
        .await?
        .map(Json)
        .ok_or_else(|| ApiError::not_found("no such request"))
}

async fn cancel(
    State(state): State<Shared>,
    Path(id): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<agent_sudo_protocol::api::DecisionResponse>> {
    let host = verify(&state, &method, &uri, &headers, &body)?;
    let req: CancelRequest =
        serde_json::from_slice(&body).map_err(|e| ApiError::bad_request(e.to_string()))?;
    engine::cancel(&state, &host, &id, &req.reason)?
        .map(Json)
        .ok_or_else(|| ApiError::not_found("no such request"))
}

async fn heartbeat(
    State(state): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<HeartbeatResponse>> {
    let host = verify(&state, &method, &uri, &headers, &body)?;
    let req: HeartbeatRequest =
        serde_json::from_slice(&body).map_err(|e| ApiError::bad_request(e.to_string()))?;
    let now = now_ms();
    let was_offline = host.last_seen_at.is_none_or(|t| now - t > 180_000);
    state.db.lock().execute(
        "UPDATE hosts SET last_seen_at = ?1, hostd_version = ?2, hostname = ?3 WHERE id = ?4",
        params![now, req.hostd_version, req.hostname, host.id],
    )?;
    if was_offline {
        state.emit(Event::Hosts);
    }
    Ok(Json(HeartbeatResponse {
        host_id: host.id,
        name: host.name,
        groups: host.groups,
        server_time: now_secs(),
    }))
}

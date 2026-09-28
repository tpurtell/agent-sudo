//! Serves the host installer and host binaries, so enrolling a machine needs only
//! `curl -fsSL <service>/install.sh | sudo sh -s -- --token …`.

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use crate::state::Shared;

const ARCHES: &[&str] = &["amd64", "arm64"];
const FILES: &[&str] = &[
    "agent-sudo",
    "agent-sudo-hostd",
    "agent-sudo-hostd.service",
    "install.sh",
];

pub fn router() -> Router<Shared> {
    Router::new()
        .route("/install.sh", get(installer))
        .route("/dist/SHA256SUMS", get(sums))
        .route("/dist/{arch}/{file}", get(file))
}

fn bytes(body: Vec<u8>, content_type: &'static str) -> Response {
    let mut resp = (StatusCode::OK, body).into_response();
    resp.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    resp
}

fn missing() -> Response {
    (
        StatusCode::NOT_FOUND,
        "This service was built without host binaries.\n",
    )
        .into_response()
}

async fn installer(State(state): State<Shared>) -> Response {
    match std::fs::read_to_string(state.cfg.host_dist_dir.join("install.sh")) {
        Ok(script) => bytes(
            script
                .replace("__AGENT_SUDO_URL__", &state.cfg.base_url())
                .into_bytes(),
            "text/x-shellscript; charset=utf-8",
        ),
        Err(_) => missing(),
    }
}

async fn sums(State(state): State<Shared>) -> Response {
    match std::fs::read(state.cfg.host_dist_dir.join("dist/SHA256SUMS")) {
        Ok(b) => bytes(b, "text/plain; charset=utf-8"),
        Err(_) => missing(),
    }
}

async fn file(State(state): State<Shared>, Path((arch, file)): Path<(String, String)>) -> Response {
    // Fixed allowlists: no path from the request reaches the filesystem unchecked.
    let (Some(arch), Some(file)) = (
        ARCHES.iter().find(|a| **a == arch),
        FILES.iter().find(|f| **f == file),
    ) else {
        return (StatusCode::NOT_FOUND, "not found\n").into_response();
    };
    match std::fs::read(state.cfg.host_dist_dir.join("dist").join(arch).join(file)) {
        Ok(b) => bytes(b, "application/octet-stream"),
        Err(_) => missing(),
    }
}

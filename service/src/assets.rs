//! The web UI, embedded at build time, plus security headers.

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderValue, Request, StatusCode, Uri, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;

use crate::state::Shared;

#[derive(RustEmbed)]
#[folder = "$CARGO_MANIFEST_DIR/web/dist"]
struct Dist;

fn cache_control(path: &str) -> &'static str {
    if path.starts_with("assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    }
}

fn file_response(path: &str, bytes: Vec<u8>) -> Response {
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    let mut resp = (StatusCode::OK, bytes).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(mime.as_ref()).unwrap(),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(cache_control(path)),
    );
    if path == "sw.js" {
        h.insert("service-worker-allowed", HeaderValue::from_static("/"));
    }
    resp
}

fn load(state: &Shared, path: &str) -> Option<Vec<u8>> {
    if let Some(dir) = &state.cfg.web_dir {
        let full = dir.join(path);
        // Refuse traversal outside the directory.
        if path.split('/').any(|seg| seg == "..") {
            return None;
        }
        return std::fs::read(full).ok();
    }
    Dist::get(path).map(|f| f.data.into_owned())
}

/// Serve a UI file, or index.html for client-side routes.
pub async fn serve(State(state): State<Shared>, uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    if path.starts_with("api/") {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    let path = if path.is_empty() { "index.html" } else { path };
    if let Some(bytes) = load(&state, path) {
        return file_response(path, bytes);
    }
    // Unknown file-like paths are 404; everything else is an app route.
    if path
        .rsplit('/')
        .next()
        .is_some_and(|last| last.contains('.'))
    {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    match load(&state, "index.html") {
        Some(bytes) => file_response("index.html", bytes),
        None => (StatusCode::NOT_FOUND, "UI not built").into_response(),
    }
}

const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; \
connect-src 'self'; font-src 'self' data:; manifest-src 'self'; worker-src 'self'; frame-ancestors 'none'; \
base-uri 'none'; form-action 'self'; object-src 'none'";

pub async fn security_headers(
    State(state): State<Shared>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let is_api = req.uri().path().starts_with("/api/");
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert("content-security-policy", HeaderValue::from_static(CSP));
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    h.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    h.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), publickey-credentials-get=(self), publickey-credentials-create=(self)"),
    );
    if state.cfg.secure_cookies() {
        h.insert(
            "strict-transport-security",
            HeaderValue::from_static("max-age=31536000"),
        );
    }
    if is_api && !h.contains_key(header::CACHE_CONTROL) {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    resp
}

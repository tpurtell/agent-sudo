//! Integration tests: the real router, an in-memory database, signed host calls,
//! cookie-authenticated browser calls, and a mock decision model.

use std::time::Duration;

use agent_sudo_protocol::api::*;
use agent_sudo_protocol::signing;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::config::ServiceConfig;
use crate::state::Shared;

const ORIGIN: &str = "https://sudo.test";

struct Harness {
    state: Shared,
    app: axum::Router,
    host_id: String,
    key: SigningKey,
    cookie: String,
    csrf: String,
}

fn config(extra: &str) -> ServiceConfig {
    // Top-level keys must come before the [push] table.
    let (top, rest): (Vec<&str>, Vec<&str>) =
        extra.lines().partition(|l| l.starts_with("host_dist_dir"));
    let cfg: ServiceConfig = toml::from_str(&format!(
        "public_url = \"{ORIGIN}\"\n{}\n[push]\nenabled = false\n{}",
        top.join("\n"),
        rest.join("\n")
    ))
    .unwrap();
    cfg.validate().unwrap();
    cfg
}

async fn call(app: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

impl Harness {
    async fn new(extra: &str) -> Harness {
        let state = crate::build_state(config(extra), crate::db::Db::memory().unwrap()).unwrap();
        let app = crate::app(state.clone());
        // An admin with a session that has recently used a passkey.
        let user =
            crate::auth::create_user(&state, "tj", "TJ", "admin", Some("correct horse battery"))
                .unwrap();
        let s = crate::auth::create_session(
            &state,
            &user,
            None,
            "Mozilla/5.0 (iPhone)",
            "passkey",
            true,
        )
        .unwrap();
        let csrf: String = state
            .db
            .lock()
            .query_row("SELECT csrf FROM web_sessions", [], |r| r.get(0))
            .unwrap();
        let mut h = Harness {
            state,
            app,
            host_id: String::new(),
            key: signing::generate_key(),
            cookie: format!("__Host-asudo={}", s.token),
            csrf,
        };
        let (status, token) = h
            .web(
                "POST",
                "/api/hosts/tokens",
                json!({"name": "moa", "groups": ["sparks"]}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{token}");
        let (status, enrolled) = call(
            &h.app,
            Request::post("/api/v1/enroll")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "token": token["token"],
                        "hostname": "moa.local",
                        "public_key": signing::encode_public_key(&h.key.verifying_key()),
                        "hostd_version": "test"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{enrolled}");
        assert_eq!(enrolled["name"], "moa");
        h.host_id = enrolled["host_id"].as_str().unwrap().to_string();
        h
    }

    fn signed(&self, method: &str, path: &str, body: Option<Value>) -> Request<Body> {
        let bytes = body.map(|b| b.to_string().into_bytes()).unwrap_or_default();
        let time = crate::util::now_secs();
        let nonce = signing::new_nonce();
        let msg = signing::canonical(method, path, &self.host_id, time, &nonce, &bytes);
        Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .header(signing::HEADER_HOST, &self.host_id)
            .header(signing::HEADER_TIME, time.to_string())
            .header(signing::HEADER_NONCE, nonce)
            .header(signing::HEADER_SIGNATURE, signing::sign(&self.key, &msg))
            .body(Body::from(bytes))
            .unwrap()
    }

    async fn host(&self, method: &str, path: &str, body: Option<Value>) -> (StatusCode, Value) {
        call(&self.app, self.signed(method, path, body)).await
    }

    async fn web(&self, method: &str, path: &str, body: Value) -> (StatusCode, Value) {
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header("cookie", &self.cookie)
            .header("origin", ORIGIN)
            .header("x-csrf-token", &self.csrf);
        let body = if method == "GET" {
            Body::empty()
        } else {
            req = req.header("content-type", "application/json");
            Body::from(body.to_string())
        };
        call(&self.app, req.body(body).unwrap()).await
    }

    async fn submit(
        &self,
        cmd: &str,
        args: &[&str],
        tweak: impl FnOnce(&mut RequestEnvelope),
    ) -> (StatusCode, Value) {
        let mut env = crate::policy::tests::env(cmd, args);
        env.client_request_id = ulid::Ulid::new().to_string();
        tweak(&mut env);
        self.host(
            "POST",
            "/api/v1/requests",
            Some(serde_json::to_value(&env).unwrap()),
        )
        .await
    }
}

#[tokio::test]
async fn full_approval_flow_with_grant_reuse() {
    let h = Harness::new("").await;
    let (status, sub) = h
        .submit("/usr/bin/apt", &["install", "-y", "jq"], |_| {})
        .await;
    assert_eq!(status, StatusCode::OK, "{sub}");
    assert_eq!(sub["state"], "pending");
    assert!(
        sub["url"]
            .as_str()
            .unwrap()
            .starts_with("https://sudo.test/r/req_")
    );
    let id = sub["id"].as_str().unwrap().to_string();

    // The UI sees it.
    let (_, list) = h
        .web("GET", "/api/requests?view=pending", Value::Null)
        .await;
    assert_eq!(list["items"].as_array().unwrap().len(), 1);
    assert_eq!(list["items"][0]["class"]["name"], "packages");
    let version = list["items"][0]["version"].as_i64().unwrap();

    // A host long-poll wakes up when the approver decides.
    let waiter = {
        let app = h.app.clone();
        let req = h.signed(
            "GET",
            &format!("/api/v1/requests/{id}/decision?wait=10"),
            None,
        );
        tokio::spawn(async move { call(&app, req).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (status, decided) = h
        .web(
            "POST",
            &format!("/api/requests/{id}/decision"),
            json!({"version": version, "decision": "approve",
                   "scope": {"command": "exact", "hosts": "group", "requester": "session", "ttl_minutes": 30}}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{decided}");
    assert_eq!(decided["state"], "approved");
    let (status, waited) = tokio::time::timeout(Duration::from_secs(5), waiter)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(waited["state"], "approved");
    assert_eq!(waited["decision"]["via"], "user");
    assert_eq!(waited["decision"]["refresh_timestamp"], false);

    // A stale second decision is refused.
    let (status, _) = h
        .web(
            "POST",
            &format!("/api/requests/{id}/decision"),
            json!({"version": version, "decision": "deny"}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // The same command from the same session is now approved by the grant, immediately.
    let (_, again) = h
        .submit("/usr/bin/apt", &["install", "-y", "jq"], |_| {})
        .await;
    assert_eq!(again["state"], "approved");
    assert_eq!(again["decision"]["via"], "grant");
    // A different command, or a different session, still asks.
    let (_, other) = h
        .submit("/usr/bin/apt", &["install", "-y", "curl"], |_| {})
        .await;
    assert_eq!(other["state"], "pending");
    let (_, other_session) = h
        .submit("/usr/bin/apt", &["install", "-y", "jq"], |e| {
            e.session.fingerprint = "b:99:1".into()
        })
        .await;
    assert_eq!(other_session["state"], "pending");

    let (_, grants) = h.web("GET", "/api/grants", Value::Null).await;
    assert_eq!(grants["items"][0]["uses"], 1);
}

#[tokio::test]
async fn idempotent_submission_and_nonblocking() {
    let h = Harness::new("").await;
    let mut env = crate::policy::tests::env("/usr/bin/systemctl", &["restart", "docker"]);
    env.client_request_id = "fixed-id".into();
    let body = serde_json::to_value(&env).unwrap();
    let (_, a) = h.host("POST", "/api/v1/requests", Some(body.clone())).await;
    let (_, b) = h.host("POST", "/api/v1/requests", Some(body)).await;
    assert_eq!(a["id"], b["id"]);

    let (_, n) = h
        .submit("/usr/bin/systemctl", &["restart", "nginx"], |e| {
            e.nonblocking = true
        })
        .await;
    assert_eq!(n["state"], "expired");
    let (_, list) = h.web("GET", "/api/requests", Value::Null).await;
    assert_eq!(
        list["items"].as_array().unwrap().len(),
        1,
        "sudo -n misses are hidden by default"
    );
}

#[tokio::test]
async fn cancellation_and_expiry() {
    let h = Harness::new("").await;
    let (_, sub) = h.submit("/usr/bin/apt", &["update"], |_| {}).await;
    let id = sub["id"].as_str().unwrap();
    let (status, c) = h
        .host(
            "POST",
            &format!("/api/v1/requests/{id}/cancel"),
            Some(json!({"reason": "password"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(c["state"], "withdrawn");

    let (_, sub) = h
        .submit("/usr/bin/apt", &["upgrade"], |e| e.timeout_secs = 0)
        .await;
    let id = sub["id"].as_str().unwrap();
    crate::engine::expire_due(&h.state).unwrap();
    let (_, r) = h
        .web("GET", &format!("/api/requests/{id}"), Value::Null)
        .await;
    assert_eq!(r["state"], "expired");
}

#[tokio::test]
async fn host_signatures_are_enforced() {
    let h = Harness::new("").await;
    // Replay the exact same signed request.
    let req = h.signed(
        "POST",
        "/api/v1/heartbeat",
        Some(json!({"hostd_version": "t", "hostname": "moa"})),
    );
    let (parts, body) = req.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    let first = Request::from_parts(parts.clone(), Body::from(bytes.clone()));
    let (status, hb) = call(&h.app, first).await;
    assert_eq!(status, StatusCode::OK, "{hb}");
    assert_eq!(hb["groups"], json!(["sparks"]));
    let (status, _) = call(
        &h.app,
        Request::from_parts(parts.clone(), Body::from(bytes)),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "replay must fail");

    // Tampered body.
    let req = h.signed(
        "POST",
        "/api/v1/heartbeat",
        Some(json!({"hostd_version": "t", "hostname": "moa"})),
    );
    let (parts, _) = req.into_parts();
    let (status, _) = call(
        &h.app,
        Request::from_parts(
            parts,
            Body::from("{\"hostd_version\":\"x\",\"hostname\":\"evil\"}"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Unknown key.
    let mut other = Harness::new("").await;
    other.key = signing::generate_key();
    let (status, _) = other
        .host(
            "POST",
            "/api/v1/heartbeat",
            Some(json!({"hostd_version": "t", "hostname": "moa"})),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Revoked host.
    let (status, _) = h
        .web(
            "POST",
            &format!("/api/hosts/{}/revoke", h.host_id),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = h.submit("/usr/bin/apt", &["update"], |_| {}).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn browser_protections() {
    let h = Harness::new("").await;
    let (_, sub) = h.submit("/usr/bin/apt", &["update"], |_| {}).await;
    let id = sub["id"].as_str().unwrap();
    let decide = |csrf: &str, origin: &str| {
        Request::post(format!("/api/requests/{id}/decision"))
            .header("cookie", &h.cookie)
            .header("origin", origin)
            .header("x-csrf-token", csrf)
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"version": 1, "decision": "approve"}).to_string(),
            ))
            .unwrap()
    };
    let (status, _) = call(&h.app, decide("wrong", ORIGIN)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = call(&h.app, decide(&h.csrf, "https://evil.example")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = call(
        &h.app,
        Request::get("/api/requests").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = call(&h.app, decide(&h.csrf, ORIGIN)).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn policy_blocks_grants_for_root_shells_and_requires_step_up() {
    let h = Harness::new("").await;
    let (_, sub) = h
        .submit("/usr/bin/bash", &[], |e| e.launch = Launch::Login)
        .await;
    let id = sub["id"].as_str().unwrap();
    let (_, r) = h
        .web("GET", &format!("/api/requests/{id}"), Value::Null)
        .await;
    assert_eq!(r["class"]["name"], "root-shell");
    let (status, err) = h
        .web("POST", &format!("/api/requests/{id}/decision"),
             json!({"version": 1, "decision": "approve", "scope": {"command": "executable", "ttl_minutes": 10}}))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{err}");
    // Expire the strong authentication: a root shell now needs a fresh passkey.
    h.state
        .db
        .lock()
        .execute("UPDATE web_sessions SET strong_auth_at = 0", [])
        .unwrap();
    let (status, err) = h
        .web(
            "POST",
            &format!("/api/requests/{id}/decision"),
            json!({"version": 1, "decision": "approve"}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(err["error"], "step_up_required");
    // Denial never needs step-up.
    let (status, _) = h
        .web(
            "POST",
            &format!("/api/requests/{id}/decision"),
            json!({"version": 1, "decision": "deny", "hard": true}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
}

/// A tiny OpenAI-compatible server that returns a canned assessment.
async fn mock_model(risk: u8, decision: &'static str, relevance: f32) -> String {
    mock_model_slow(risk, decision, relevance, 0).await
}

async fn mock_model_slow(
    risk: u8,
    decision: &'static str,
    relevance: f32,
    delay_ms: u64,
) -> String {
    use axum::routing::post;
    let app = axum::Router::new().route(
        "/v1/chat/completions",
        post(move |axum::Json(body): axum::Json<Value>| async move {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            // The prompt must carry the untrusted context and the delegation intent.
            let state = body["messages"][1]["content"].as_str().unwrap_or_default().to_string();
            assert!(state.contains("requester_supplied_UNTRUSTED"));
            assert!(!state.contains("sk-live-secret-value-123456"), "secrets must be redacted");
            let content = json!({
                "risk": risk, "confidence": 0.9,
                "dimensions": {"destructive": 0.05, "privilege_escape": 0.02, "persistence": 0.3,
                               "credential_access": 0.0, "network_security": 0.0, "availability": 0.1, "unusual": 0.1},
                "relevance": relevance,
                "suggestion": {"decision": decision, "command": "exact", "hosts": "group", "requester": "session", "ttl_minutes": 30},
                "summary": "Installs a named package.", "reasons": ["matches the intent"]
            });
            axum::Json(json!({"model": "mock", "choices": [{"message": {"content": content.to_string()}}]}))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}/v1")
}

#[tokio::test]
async fn delegation_approves_within_limits_and_falls_back_otherwise() {
    let url = mock_model(12, "approve", 0.9).await;
    let h = Harness::new(&format!(
        "[advisor]\nurl = \"{url}\"\nmodel = \"mock\"\nauto_assess = false\n"
    ))
    .await;

    // First request: a human approves and delegates similar work.
    let (_, sub) = h
        .submit(
            "/usr/bin/apt",
            &["install", "-y", "nvidia-driver-580"],
            |e| {
                e.untrusted.context =
                    Some("Installing drivers; token sk-live-secret-value-123456".into())
            },
        )
        .await;
    let id = sub["id"].as_str().unwrap();
    let (status, d) = h
        .web("POST", &format!("/api/requests/{id}/decision"), json!({
            "version": 1, "decision": "approve",
            "delegate": {"intent": "Install and configure NVIDIA drivers on the sparks", "ttl_minutes": 30, "hosts": "group", "requester": "user"}
        }))
        .await;
    assert_eq!(status, StatusCode::OK, "{d}");

    // Next package install is approved by the delegation, synchronously.
    let (_, auto) = h
        .submit(
            "/usr/bin/apt",
            &["install", "-y", "nvidia-utils-580"],
            |_| {},
        )
        .await;
    assert_eq!(auto["state"], "approved", "{auto}");
    assert_eq!(auto["decision"]["via"], "delegation");

    // A root shell is never delegable: it waits for a human.
    let (_, shell) = h.submit("/usr/bin/bash", &["-c", "id"], |_| {}).await;
    assert_eq!(shell["state"], "pending");

    // The kill switch stops automation immediately.
    let (_, _) = h
        .web(
            "POST",
            "/api/settings/automation",
            json!({"enabled": false}),
        )
        .await;
    let (_, manual) = h
        .submit(
            "/usr/bin/apt",
            &["install", "-y", "nvidia-settings"],
            |_| {},
        )
        .await;
    assert_eq!(manual["state"], "pending");
    let (_, _) = h
        .web("POST", "/api/settings/automation", json!({"enabled": true}))
        .await;

    // Flagging an automated approval pauses the delegation.
    let auto_id = auto["id"].as_str().unwrap();
    let (status, _) = h
        .web("POST", &format!("/api/requests/{auto_id}/flag"), json!({}))
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, after) = h
        .submit(
            "/usr/bin/apt",
            &["install", "-y", "nvidia-cuda-toolkit"],
            |_| {},
        )
        .await;
    assert_eq!(after["state"], "pending");
    let (_, grants) = h.web("GET", "/api/grants", Value::Null).await;
    let delegation = grants["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["kind"] == "delegation")
        .unwrap();
    assert!(delegation["paused_at"].is_i64());
}

#[tokio::test]
async fn delegation_declines_high_risk_and_records_why() {
    let url = mock_model(80, "approve", 0.9).await;
    let h = Harness::new(&format!(
        "[advisor]\nurl = \"{url}\"\nmodel = \"mock\"\nauto_assess = false\n"
    ))
    .await;
    let (status, _) = h
        .web("POST", "/api/delegations", json!({"intent": "Routine package maintenance", "ttl_minutes": 30, "hosts": "all", "requester": "any"}))
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, sub) = h
        .submit("/usr/bin/apt", &["install", "-y", "jq"], |_| {})
        .await;
    assert_eq!(sub["state"], "pending");
    let (_, r) = h
        .web(
            "GET",
            &format!("/api/requests/{}", sub["id"].as_str().unwrap()),
            Value::Null,
        )
        .await;
    let check = &r["assessment"]["delegation_check"];
    assert_eq!(check["approved"], false);
    assert!(check["reasons"].to_string().contains("risk 80"), "{check}");
}

#[tokio::test]
async fn background_assessment_is_stored() {
    let url = mock_model(20, "approve", 0.0).await;
    let h = Harness::new(&format!("[advisor]\nurl = \"{url}\"\nmodel = \"mock\"\n")).await;
    let (_, sub) = h
        .submit("/usr/bin/systemctl", &["restart", "docker"], |_| {})
        .await;
    let id = sub["id"].as_str().unwrap().to_string();
    for _ in 0..50 {
        let (_, r) = h
            .web("GET", &format!("/api/requests/{id}"), Value::Null)
            .await;
        if r["assessment"]["assessment"]["risk"].is_number() {
            // Service control has an availability dimension but no floor; stays 20.
            assert_eq!(r["assessment"]["assessment"]["risk"], 20);
            assert_eq!(
                r["assessment"]["assessment"]["suggestion"]["hosts"],
                "group"
            );
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("assessment never arrived");
}

#[tokio::test]
async fn environment_overrides_are_visible_and_bind_grants() {
    let h = Harness::new("").await;
    // A code-loading variable makes any command a root shell.
    let (_, sub) = h
        .submit("/usr/bin/apt", &["update"], |e| {
            e.env = vec!["LD_PRELOAD=/tmp/x.so".into()]
        })
        .await;
    let (_, r) = h
        .web(
            "GET",
            &format!("/api/requests/{}", sub["id"].as_str().unwrap()),
            Value::Null,
        )
        .await;
    assert_eq!(r["class"]["name"], "root-shell");
    assert_eq!(r["env"][0], "LD_PRELOAD=/tmp/x.so");

    // A benign variable is shown and becomes part of the grant.
    let (_, sub) = h
        .submit("/usr/bin/apt", &["install", "-y", "jq"], |e| {
            e.env = vec!["DEBIAN_FRONTEND=noninteractive".into()]
        })
        .await;
    let id = sub["id"].as_str().unwrap();
    let (status, _) = h
        .web("POST", &format!("/api/requests/{id}/decision"),
             json!({"version": 1, "decision": "approve", "scope": {"command": "exact", "requester": "user", "ttl_minutes": 30}}))
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, same) = h
        .submit("/usr/bin/apt", &["install", "-y", "jq"], |e| {
            e.env = vec!["DEBIAN_FRONTEND=noninteractive".into()]
        })
        .await;
    assert_eq!(same["state"], "approved");
    let (_, bare) = h
        .submit("/usr/bin/apt", &["install", "-y", "jq"], |_| {})
        .await;
    assert_eq!(
        bare["state"], "pending",
        "a grant with env must not cover a different environment"
    );
    let (_, other) = h
        .submit("/usr/bin/apt", &["install", "-y", "jq"], |e| {
            e.env = vec!["APT_CONFIG=/tmp/evil".into()]
        })
        .await;
    assert_eq!(other["state"], "pending");
}

#[tokio::test]
async fn requests_whose_target_can_change_are_never_granted() {
    let h = Harness::new("").await;
    let (_, sub) = h
        .submit("/usr/bin/cat", &["notes"], |e| {
            e.paths = vec![PathFact {
                index: 0,
                given: "notes".into(),
                resolved: "/var/log/syslog".into(),
                user_symlink: true,
            }];
        })
        .await;
    let id = sub["id"].as_str().unwrap();
    let (status, err) = h
        .web("POST", &format!("/api/requests/{id}/decision"),
             json!({"version": 1, "decision": "approve", "scope": {"command": "exact", "requester": "user", "ttl_minutes": 30}}))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{err}");
    // Unverified executables (no facts from hostd) likewise.
    let (_, sub) = h
        .submit("/usr/bin/true", &[], |e| e.executable = None)
        .await;
    let (_, r) = h
        .web(
            "GET",
            &format!("/api/requests/{}", sub["id"].as_str().unwrap()),
            Value::Null,
        )
        .await;
    assert!(r["features"].to_string().contains("unverified_executable"));
}

#[tokio::test]
async fn a_losing_decision_creates_no_grant() {
    let h = Harness::new("").await;
    let (_, sub) = h.submit("/usr/bin/apt", &["update"], |_| {}).await;
    let id = sub["id"].as_str().unwrap();
    // The host withdraws first (the password won the race).
    h.host(
        "POST",
        &format!("/api/v1/requests/{id}/cancel"),
        Some(json!({"reason": "password"})),
    )
    .await;
    let (status, _) = h
        .web("POST", &format!("/api/requests/{id}/decision"),
             json!({"version": 1, "decision": "approve", "scope": {"command": "executable", "requester": "user", "ttl_minutes": 30}}))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (_, grants) = h.web("GET", "/api/grants", Value::Null).await;
    assert_eq!(grants["items"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn pausing_during_the_model_call_stops_the_approval() {
    let url = mock_model_slow(10, "approve", 0.9, 600).await;
    let h = Harness::new(&format!(
        "[advisor]\nurl = \"{url}\"\nmodel = \"mock\"\nauto_assess = false\n"
    ))
    .await;
    let (_, created) = h
        .web("POST", "/api/delegations", json!({"intent": "Routine package maintenance", "ttl_minutes": 30, "hosts": "all", "requester": "any"}))
        .await;
    let did = created["id"].as_str().unwrap().to_string();
    let submit = {
        let app = h.app.clone();
        let mut env = crate::policy::tests::env("/usr/bin/apt", &["install", "-y", "jq"]);
        env.client_request_id = "slow".into();
        let req = h.signed(
            "POST",
            "/api/v1/requests",
            Some(serde_json::to_value(&env).unwrap()),
        );
        tokio::spawn(async move { call(&app, req).await })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    let (status, _) = h
        .web("POST", &format!("/api/grants/{did}/pause"), json!({}))
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, sub) = submit.await.unwrap();
    assert_eq!(sub["state"], "pending", "{sub}");
    let (_, r) = h
        .web(
            "GET",
            &format!("/api/requests/{}", sub["id"].as_str().unwrap()),
            Value::Null,
        )
        .await;
    assert!(
        r["assessment"]["delegation_check"]["reasons"]
            .to_string()
            .contains("stopped while the model was deciding")
    );
}

#[tokio::test]
async fn enrollment_tokens_are_single_use_under_concurrency() {
    let h = Harness::new("").await;
    let (_, token) = h
        .web("POST", "/api/hosts/tokens", json!({"name": "twin"}))
        .await;
    let enroll = |key: String| {
        let app = h.app.clone();
        let token = token["token"].clone();
        async move {
            call(
                &app,
                Request::post("/api/v1/enroll")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"token": token, "hostname": "twin", "public_key": key, "hostd_version": "t"}).to_string()))
                    .unwrap(),
            )
            .await
            .0
        }
    };
    let k1 = signing::encode_public_key(&signing::generate_key().verifying_key());
    let k2 = signing::encode_public_key(&signing::generate_key().verifying_key());
    let (a, b) = tokio::join!(tokio::spawn(enroll(k1)), tokio::spawn(enroll(k2)));
    let ok = [a.unwrap(), b.unwrap()]
        .iter()
        .filter(|s| **s == StatusCode::OK)
        .count();
    assert_eq!(ok, 1);
}

#[tokio::test]
async fn push_subscriptions_must_use_a_real_push_service() {
    let h = Harness::new("").await;
    // A valid P-256 point and auth secret so only the endpoint is being judged.
    let secret = p256::SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    use base64::Engine;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let keys = json!({"p256dh": b64.encode(secret.public_key().to_encoded_point(false).as_bytes()), "auth": b64.encode([7u8; 16])});
    let (status, _) = h
        .web(
            "POST",
            "/api/push/subscribe",
            json!({"endpoint": "https://collector.evil.example/x", "keys": keys}),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = h
        .web(
            "POST",
            "/api/push/subscribe",
            json!({"endpoint": "https://fcm.googleapis.com/fcm/send/abc", "keys": keys}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = h
        .web(
            "POST",
            "/api/push/subscribe",
            json!({"endpoint": "https://wns2-par02p.notify.windows.com/w/?token=x", "keys": keys}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn standalone_delegations_cannot_silently_widen() {
    let url = mock_model(10, "approve", 0.9).await;
    let h = Harness::new(&format!("[advisor]\nurl = \"{url}\"\nmodel = \"mock\"\n")).await;
    let (status, _) = h
        .web("POST", "/api/delegations", json!({"intent": "Routine package maintenance", "ttl_minutes": 30, "hosts": "all", "requester": "session"}))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = h
        .web("POST", "/api/delegations", json!({"intent": "Routine package maintenance", "ttl_minutes": 30, "hosts": "all", "requester": "user"}))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "user scope needs a unix user"
    );
    let (status, d) = h
        .web("POST", "/api/delegations", json!({"intent": "Routine package maintenance", "ttl_minutes": 30, "hosts": "all", "requester": "user", "unix_user": "tj"}))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(d["spec"]["requester"]["user"], "tj");
}

#[tokio::test]
async fn serves_the_installer_and_host_binaries() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("install.sh"),
        "SERVICE=\"__AGENT_SUDO_URL__\"\n",
    )
    .unwrap();
    std::fs::create_dir_all(dir.path().join("dist/arm64")).unwrap();
    std::fs::write(dir.path().join("dist/arm64/agent-sudo"), "binary").unwrap();
    std::fs::write(
        dir.path().join("dist/SHA256SUMS"),
        "abc  arm64/agent-sudo\n",
    )
    .unwrap();
    std::fs::write(dir.path().join("secret"), "nope").unwrap();
    let h = Harness::new(&format!("host_dist_dir = \"{}\"\n", dir.path().display())).await;
    let get = |path: &str| {
        let app = h.app.clone();
        let path = path.to_string();
        async move {
            let resp = app
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            (
                status,
                String::from_utf8(
                    resp.into_body()
                        .collect()
                        .await
                        .unwrap()
                        .to_bytes()
                        .to_vec(),
                )
                .unwrap(),
            )
        }
    };
    let (status, script) = get("/install.sh").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(script, "SERVICE=\"https://sudo.test\"\n");
    assert_eq!(
        get("/dist/arm64/agent-sudo").await,
        (StatusCode::OK, "binary".into())
    );
    assert_eq!(get("/dist/SHA256SUMS").await.0, StatusCode::OK);
    assert_eq!(
        get("/dist/arm64/..%2F..%2Fsecret").await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(get("/dist/riscv/agent-sudo").await.0, StatusCode::NOT_FOUND);
    assert_eq!(get("/dist/amd64/agent-sudo").await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn group_scope_means_the_smallest_group() {
    let h = Harness::new("").await;
    // Every host is in "all"; moa is also in "sparks". "Group" must not mean the fleet.
    {
        let db = h.state.db.lock();
        db.execute(
            "UPDATE hosts SET groups_json = '[\"all\",\"sparks\"]' WHERE id = ?1",
            [&h.host_id],
        )
        .unwrap();
        for (id, name) in [("hst_a", "raptor"), ("hst_b", "aviary")] {
            db.execute(
                "INSERT INTO hosts (id, name, hostname, public_key, groups_json, created_at) VALUES (?1, ?2, ?2, 'k', '[\"all\"]', 0)",
                [id, name],
            )
            .unwrap();
        }
    }
    let (_, sub) = h.submit("/usr/bin/apt", &["update"], |_| {}).await;
    let id = sub["id"].as_str().unwrap();
    let (_, r) = h
        .web("GET", &format!("/api/requests/{id}"), Value::Null)
        .await;
    assert_eq!(r["host"]["default_group"], "sparks");
    let (status, d) = h
        .web("POST", &format!("/api/requests/{id}/decision"),
             json!({"version": 1, "decision": "approve", "scope": {"command": "executable", "hosts": "group", "requester": "user", "ttl_minutes": 30}}))
        .await;
    assert_eq!(status, StatusCode::OK, "{d}");
    let (_, grants) = h.web("GET", "/api/grants", Value::Null).await;
    let g = &grants["items"][0];
    assert_eq!(g["spec"]["hosts"]["groups"], json!(["sparks"]), "{g}");
    // The label says the grant covers any arguments.
    assert_eq!(g["label"], "/usr/bin/apt (any arguments)");
}

#[tokio::test]
async fn delegations_can_last_forever() {
    let url = mock_model(10, "approve", 0.9).await;
    let h = Harness::new(&format!(
        "[advisor]\nurl = \"{url}\"\nmodel = \"mock\"\nauto_assess = false\n"
    ))
    .await;
    let (status, created) = h
        .web("POST", "/api/delegations", json!({"intent": "Routine package maintenance", "ttl_minutes": 0, "hosts": "all", "requester": "any"}))
        .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    let (_, month) = h
        .web("POST", "/api/delegations", json!({"intent": "Routine package maintenance", "ttl_minutes": 43200, "hosts": "all", "requester": "any"}))
        .await;
    let (_, grants) = h.web("GET", "/api/grants", Value::Null).await;
    let find = |id: &Value| {
        grants["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|g| g["id"] == *id)
            .cloned()
            .unwrap()
    };
    assert!(find(&created["id"])["expires_at"].is_null());
    let m = find(&month["id"]);
    let days = (m["expires_at"].as_i64().unwrap() - m["created_at"].as_i64().unwrap()) / 86_400_000;
    assert_eq!(days, 30);
    let (_, sub) = h
        .submit("/usr/bin/apt", &["install", "-y", "jq"], |_| {})
        .await;
    assert_eq!(sub["state"], "approved", "{sub}");
}

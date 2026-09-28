//! Signed HTTPS client for the approval service.

use std::time::Duration;

use agent_sudo_protocol::api::{
    ApiError, CancelRequest, DecisionResponse, EnrollRequest, EnrollResponse, HeartbeatRequest,
    HeartbeatResponse, RequestEnvelope, SubmitResponse,
};
use agent_sudo_protocol::signing;
use anyhow::{Context, Result, anyhow, bail};
use ed25519_dalek::SigningKey;
use reqwest::{Method, StatusCode};
use serde::Serialize;
use serde::de::DeserializeOwned;

pub struct ServiceClient {
    http: reqwest::Client,
    base: String,
    host_id: String,
    key: Option<SigningKey>,
}

pub fn build_http(ca_file: Option<&std::path::Path>) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .user_agent(concat!("agent-sudo-hostd/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(60))
        .https_only(false);
    if let Some(ca) = ca_file {
        let pem = std::fs::read(ca).with_context(|| format!("reading {}", ca.display()))?;
        for cert in reqwest::Certificate::from_pem_bundle(&pem)
            .with_context(|| format!("parsing {}", ca.display()))?
        {
            builder = builder.add_root_certificate(cert);
        }
    }
    Ok(builder.build()?)
}

impl ServiceClient {
    pub fn new(http: reqwest::Client, base: &str, host_id: &str, key: Option<SigningKey>) -> Self {
        ServiceClient {
            http,
            base: base.trim_end_matches('/').to_string(),
            host_id: host_id.to_string(),
            key,
        }
    }

    async fn call<B: Serialize, R: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
        timeout: Option<Duration>,
    ) -> Result<R> {
        let body_bytes = match body {
            Some(b) => serde_json::to_vec(b)?,
            None => Vec::new(),
        };
        let url = format!("{}{}", self.base, path);
        let mut req = self.http.request(method.clone(), &url);
        if let Some(t) = timeout {
            req = req.timeout(t);
        }
        if let Some(key) = &self.key {
            let time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs() as i64;
            let nonce = signing::new_nonce();
            let msg = signing::canonical(
                method.as_str(),
                path,
                &self.host_id,
                time,
                &nonce,
                &body_bytes,
            );
            req = req
                .header(signing::HEADER_HOST, &self.host_id)
                .header(signing::HEADER_TIME, time.to_string())
                .header(signing::HEADER_NONCE, nonce)
                .header(signing::HEADER_SIGNATURE, signing::sign(key, &msg));
        }
        if body.is_some() {
            req = req
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body_bytes);
        }
        let resp = req
            .send()
            .await
            .with_context(|| format!("{method} {url}"))?;
        let status = resp.status();
        let bytes = resp.bytes().await?;
        if !status.is_success() {
            let detail = serde_json::from_slice::<ApiError>(&bytes)
                .map(|e| e.message)
                .unwrap_or_else(|_| String::from_utf8_lossy(&bytes).chars().take(200).collect());
            if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                bail!("service rejected this host ({status}): {detail}");
            }
            bail!("service returned {status}: {detail}");
        }
        serde_json::from_slice(&bytes).map_err(|e| anyhow!("bad response from service: {e}"))
    }

    pub async fn enroll(&self, req: &EnrollRequest) -> Result<EnrollResponse> {
        self.call(Method::POST, "/api/v1/enroll", Some(req), None)
            .await
    }

    pub async fn submit(&self, envelope: &RequestEnvelope) -> Result<SubmitResponse> {
        // Delegated decisions may call a model synchronously; allow for it.
        self.call(
            Method::POST,
            "/api/v1/requests",
            Some(envelope),
            Some(Duration::from_secs(90)),
        )
        .await
    }

    pub async fn wait_decision(&self, id: &str, wait_secs: u64) -> Result<DecisionResponse> {
        self.call::<(), _>(
            Method::GET,
            &format!("/api/v1/requests/{id}/decision?wait={wait_secs}"),
            None,
            Some(Duration::from_secs(wait_secs + 20)),
        )
        .await
    }

    pub async fn cancel(&self, id: &str, reason: &str) -> Result<DecisionResponse> {
        self.call(
            Method::POST,
            &format!("/api/v1/requests/{id}/cancel"),
            Some(&CancelRequest {
                reason: reason.to_string(),
            }),
            None,
        )
        .await
    }

    pub async fn heartbeat(&self, req: &HeartbeatRequest) -> Result<HeartbeatResponse> {
        self.call(
            Method::POST,
            "/api/v1/heartbeat",
            Some(req),
            Some(Duration::from_secs(15)),
        )
        .await
    }
}

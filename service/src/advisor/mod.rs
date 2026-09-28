//! Decision assistance: risk scoring, suggested scope, and (for delegations) a
//! relevance judgement against the approver's stated intent.
//!
//! The advisor returns an [`Assessment`]. It has no way to approve anything: the
//! engine applies deterministic rules (the class envelope and delegation limits) to
//! the clamped assessment.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::policy::{ClassConfig, Features};

pub mod decisions;
pub mod openai;
pub mod sanitize;

pub const DIMENSIONS: &[(&str, &str)] = &[
    (
        "destructive",
        "Could this cause substantial destructive or hard-to-reverse changes?",
    ),
    (
        "privilege_escape",
        "Could this give the requester unrestricted root execution beyond the stated command?",
    ),
    (
        "persistence",
        "Does this install persistent changes (services, cron, startup, packages, config)?",
    ),
    (
        "credential_access",
        "Could this read, change or exfiltrate credentials, keys or secrets?",
    ),
    (
        "network_security",
        "Does this change network exposure, firewall, SSH or remote access?",
    ),
    (
        "availability",
        "Could this interrupt services or make the machine unavailable?",
    ),
    (
        "unusual",
        "Is this unusual compared with the recent activity provided?",
    ),
];

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    /// Any OpenAI-compatible chat completions endpoint (LiteLLM, OpenRouter, vLLM, ...).
    #[default]
    Openai,
    /// OpenRouter's Decisions API: typed questions with calibrated probabilities.
    Decisions,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ResponseFormat {
    /// `response_format: {type: json_schema}` (strict structured output).
    JsonSchema,
    /// `response_format: {type: json_object}` plus the schema in the prompt.
    #[default]
    JsonObject,
    /// No response_format; rely on the prompt.
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdvisorConfig {
    #[serde(default)]
    pub backend: Backend,
    /// For `openai`: base URL ending in `/v1` (we append `/chat/completions`).
    /// For `decisions`: the full endpoint URL.
    pub url: String,
    pub model: String,
    #[serde(default)]
    pub api_key: String,
    #[serde(default)]
    pub response_format: ResponseFormat,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub temperature: f32,
    /// Assess every pending request automatically (otherwise on demand).
    #[serde(default = "yes")]
    pub auto_assess: bool,
    #[serde(default = "default_history")]
    pub history_max_requests: usize,
    #[serde(default = "default_history_age")]
    pub history_max_age_minutes: u32,
    /// Upper bound on the suggested grant duration.
    #[serde(default = "default_suggested_ttl")]
    pub max_suggested_ttl_minutes: u32,
    #[serde(default)]
    pub extra_headers: BTreeMap<String, String>,
}

fn default_timeout() -> u64 {
    30
}
fn yes() -> bool {
    true
}
fn default_history() -> usize {
    20
}
fn default_history_age() -> u32 {
    120
}
fn default_suggested_ttl() -> u32 {
    120
}

impl AdvisorConfig {
    pub fn validate(&self) -> Result<()> {
        if !(self.url.starts_with("https://") || self.url.starts_with("http://")) {
            bail!("advisor.url must be an http(s) URL");
        }
        if self.model.trim().is_empty() {
            bail!("advisor.model is required");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Suggestion {
    /// approve | deny | ask
    pub decision: String,
    /// once | exact | prefix | executable
    pub command: String,
    /// host | group | all
    pub hosts: String,
    /// session | user
    pub requester: String,
    pub ttl_minutes: u32,
    /// Choice probabilities when the backend provides them.
    #[serde(default)]
    pub probabilities: BTreeMap<String, BTreeMap<String, f32>>,
}

impl Default for Suggestion {
    fn default() -> Self {
        Suggestion {
            decision: "ask".into(),
            command: "once".into(),
            hosts: "host".into(),
            requester: "session".into(),
            ttl_minutes: 0,
            probabilities: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Assessment {
    /// 0 (routine) to 100 (critical).
    pub risk: u8,
    /// 0..1
    pub confidence: f32,
    /// Per-dimension probabilities (0..1), see [`DIMENSIONS`].
    pub dimensions: BTreeMap<String, f32>,
    /// How consistent the request is with a delegation's intent (0..1).
    pub relevance: Option<f32>,
    pub suggestion: Suggestion,
    pub summary: String,
    pub reasons: Vec<String>,
    pub model: String,
    pub backend: String,
    pub latency_ms: u64,
    pub cost_usd: Option<f64>,
    /// What the deterministic clamp changed.
    pub clamped: Vec<String>,
    pub created_at: i64,
    /// The risk the model gave before the deterministic floor was applied.
    pub model_risk: u8,
}

impl Assessment {
    pub fn placeholder() -> Self {
        Assessment {
            risk: 50,
            confidence: 0.0,
            dimensions: BTreeMap::new(),
            relevance: None,
            suggestion: Suggestion::default(),
            summary: String::new(),
            reasons: vec![],
            model: String::new(),
            backend: String::new(),
            latency_ms: 0,
            cost_usd: None,
            clamped: vec![],
            created_at: crate::util::now_ms(),
            model_risk: 50,
        }
    }
}

/// Stored when an assessment could not be produced.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AssessmentFailure {
    pub error: String,
    pub model: String,
    pub at: i64,
}

/// Everything the model sees. Built by the engine; already sanitized.
#[derive(Debug, Clone, Serialize)]
pub struct AdvisorInput {
    pub request: Value,
    pub class: Value,
    pub deterministic_features: Value,
    pub recent_history: Vec<Value>,
    pub fleet_summary: Value,
    pub active_grants: Vec<Value>,
    pub delegation: Option<Value>,
    /// Untrusted free text from the requester.
    pub requester_supplied: Value,
}

impl AdvisorInput {
    pub fn to_state(&self) -> Value {
        json!({
            "request": self.request,
            "policy_class": self.class,
            "deterministic_features": self.deterministic_features,
            "recent_history": self.recent_history,
            "fleet_summary": self.fleet_summary,
            "active_grants": self.active_grants,
            "delegation": self.delegation,
            "requester_supplied_UNTRUSTED": self.requester_supplied,
        })
    }
}

pub struct Advisor {
    pub config: AdvisorConfig,
    http: reqwest::Client,
}

impl Advisor {
    pub fn new(config: AdvisorConfig) -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("agent-sudo/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(config.timeout_secs.max(5)))
            .build()?;
        Ok(Advisor { config, http })
    }

    pub async fn assess(&self, input: &AdvisorInput) -> Result<Assessment> {
        let started = Instant::now();
        let mut assessment = match self.config.backend {
            Backend::Openai => openai::assess(&self.http, &self.config, input).await?,
            Backend::Decisions => decisions::assess(&self.http, &self.config, input).await?,
        };
        assessment.latency_ms = started.elapsed().as_millis() as u64;
        assessment.model_risk = assessment.risk;
        assessment.created_at = crate::util::now_ms();
        Ok(assessment)
    }
}

/// Minimum risk implied by deterministic features. Protects against a model that has
/// been talked into calling a root shell "routine" by requester-supplied text.
pub fn risk_floor(features: &Features) -> (u8, Option<&'static str>) {
    let floors: &[(&str, u8)] = &[
        ("approval_system", 90),
        ("validate", 80),
        ("root_shell", 75),
        ("credential_access", 65),
        ("destructive", 60),
        ("network_security", 35),
        ("kernel", 30),
    ];
    floors
        .iter()
        .filter(|(k, _)| features.has(k))
        .max_by_key(|(_, v)| *v)
        .map(|(k, v)| (*v, Some(*k)))
        .unwrap_or((0, None))
}

/// Apply the deterministic envelope to a model assessment.
pub fn clamp(
    mut a: Assessment,
    class: &ClassConfig,
    features: &Features,
    max_suggested_ttl: u32,
) -> Assessment {
    let (floor, why) = risk_floor(features);
    if a.risk < floor {
        a.clamped.push(format!(
            "risk raised from {} to {} because the request has `{}`",
            a.risk,
            floor,
            why.unwrap_or("?")
        ));
        a.risk = floor;
    }
    let max_ttl = class.max_ttl_minutes.min(max_suggested_ttl);
    if class.require_each_time || max_ttl == 0 {
        if a.suggestion.command != "once" {
            a.clamped.push(format!(
                "class `{}` requires a decision each time",
                class.name
            ));
        }
        a.suggestion.command = "once".into();
        a.suggestion.ttl_minutes = 0;
    } else if a.suggestion.ttl_minutes > max_ttl {
        a.clamped.push(format!(
            "duration limited to {max_ttl} minutes by class `{}`",
            class.name
        ));
        a.suggestion.ttl_minutes = max_ttl;
    }
    if a.suggestion.command != "once" && a.suggestion.ttl_minutes == 0 {
        a.suggestion.ttl_minutes = max_ttl.min(30);
    }
    if !["approve", "deny", "ask"].contains(&a.suggestion.decision.as_str()) {
        a.suggestion.decision = "ask".into();
    }
    if !["once", "exact", "prefix", "executable"].contains(&a.suggestion.command.as_str()) {
        a.suggestion.command = "once".into();
    }
    if !["host", "group", "all"].contains(&a.suggestion.hosts.as_str()) {
        a.suggestion.hosts = "host".into();
    }
    if !["session", "user"].contains(&a.suggestion.requester.as_str()) {
        a.suggestion.requester = "session".into();
    }
    // Sessions are per host: a multi-host approval bound to one session would never
    // match anywhere else.
    if a.suggestion.hosts != "host" {
        a.suggestion.requester = "user".into();
    }
    // A request the model rates high-risk should not be pre-filled as "approve".
    if a.risk >= 70 && a.suggestion.decision == "approve" {
        a.suggestion.decision = "ask".into();
        a.clamped
            .push("high-risk requests are never pre-filled as approve".into());
    }
    a.confidence = a.confidence.clamp(0.0, 1.0);
    for v in a.dimensions.values_mut() {
        *v = v.clamp(0.0, 1.0);
    }
    if let Some(r) = a.relevance.as_mut() {
        *r = r.clamp(0.0, 1.0);
    }
    a.summary = a.summary.chars().take(400).collect();
    a.reasons = a
        .reasons
        .into_iter()
        .take(6)
        .map(|r| r.chars().take(240).collect())
        .collect();
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::tests::env;
    use crate::policy::{PolicyConfig, features};

    #[test]
    fn clamp_enforces_floor_and_class_limits() {
        let e = env("/usr/bin/bash", &["-c", "id"]);
        let f = features(&e);
        let class = PolicyConfig::default().classify(&e, &f);
        let mut a = Assessment::placeholder();
        a.risk = 5;
        a.suggestion = Suggestion {
            decision: "approve".into(),
            command: "executable".into(),
            hosts: "all".into(),
            requester: "user".into(),
            ttl_minutes: 600,
            probabilities: Default::default(),
        };
        let a = clamp(a, &class, &f, 120);
        assert_eq!(a.risk, 75);
        assert_eq!(a.suggestion.command, "once");
        assert_eq!(a.suggestion.decision, "ask");
        assert!(a.clamped.len() >= 2);
    }

    #[test]
    fn clamp_limits_ttl() {
        let e = env("/usr/bin/apt", &["install", "jq"]);
        let f = features(&e);
        let class = PolicyConfig::default().classify(&e, &f);
        let mut a = Assessment::placeholder();
        a.risk = 10;
        a.suggestion.command = "exact".into();
        a.suggestion.ttl_minutes = 9999;
        a.suggestion.hosts = "galaxy".into();
        let a = clamp(a, &class, &f, 120);
        assert_eq!(a.suggestion.ttl_minutes, 120);
        assert_eq!(a.suggestion.hosts, "host");
        assert_eq!(a.risk, 10);
    }
}

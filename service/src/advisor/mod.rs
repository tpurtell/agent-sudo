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

use agent_sudo_protocol::api::{Mode, RequestEnvelope};

use crate::grants::{IntentSource, UNGRANTABLE_FEATURES, basename};
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
    /// approve | deny | ask: the verdict on the command itself, not on any delegation.
    pub decision: String,
    /// The same draft as a plain grant (used when delegation is unavailable):
    /// once | exact | prefix | executable. Derived from `remember`.
    pub command: String,
    /// host | group | all
    pub hosts: String,
    /// session | user
    pub requester: String,
    /// Grant length in minutes, within the class limit.
    pub ttl_minutes: u32,
    /// What to remember: once | exact | prefix | program | any.
    #[serde(default = "once")]
    pub remember: String,
    /// Leading arguments kept by a `prefix` rule.
    #[serde(default)]
    pub prefix_len: usize,
    /// The model's description of the kind of work, after policy checks.
    #[serde(default)]
    pub kind_of_work: String,
    /// The delegation intent the approve sheet offers: `{program}: {kind of work}`.
    #[serde(default)]
    pub intent: String,
    #[serde(default)]
    pub intent_source: IntentSource,
    /// Suggested delegation length in minutes; 0 means no expiry.
    #[serde(default = "one_day")]
    pub duration_minutes: u32,
    /// Choice probabilities when the backend provides them.
    #[serde(default)]
    pub probabilities: BTreeMap<String, BTreeMap<String, f32>>,
}

fn once() -> String {
    "once".into()
}
fn one_day() -> u32 {
    1440
}

impl Default for Suggestion {
    fn default() -> Self {
        Suggestion {
            decision: "ask".into(),
            command: "once".into(),
            hosts: "host".into(),
            requester: "session".into(),
            ttl_minutes: 0,
            remember: once(),
            prefix_len: 0,
            kind_of_work: String::new(),
            intent: String::new(),
            intent_source: IntentSource::Template,
            duration_minutes: one_day(),
            probabilities: BTreeMap::new(),
        }
    }
}

/// Delegation lengths the model may suggest, as (answer, minutes).
pub const DURATIONS: &[(&str, u32)] = &[("1h", 60), ("1d", 1440), ("30d", 43200), ("forever", 0)];

pub fn duration_minutes(answer: &str) -> Option<u32> {
    DURATIONS
        .iter()
        .find(|(k, _)| *k == answer)
        .map(|(_, m)| *m)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Assessment {
    /// 0 (routine) to 100 (critical).
    pub risk: u8,
    /// 0..1
    pub confidence: f32,
    /// Per-dimension probabilities (0..1), see [`DIMENSIONS`].
    pub dimensions: BTreeMap<String, f32>,
    /// Fit with the delegation that was checked first (0..1), for display.
    pub relevance: Option<f32>,
    /// Fit with each candidate delegation, by delegation id.
    #[serde(default)]
    pub relevance_by: BTreeMap<String, f32>,
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
            relevance_by: BTreeMap::new(),
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
    /// Standing delegations whose deterministic scope covers this request, narrowest
    /// first, as (delegation id, description). The model sees them as `r1`, `r2`, ...
    pub delegations: Vec<(String, Value)>,
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
            "delegations": self.delegations.iter().enumerate().map(|(i, (_, d))| {
                let mut d = d.clone();
                d["id"] = json!(format!("r{}", i + 1));
                d
            }).collect::<Vec<_>>(),
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
        // The model answers with r1, r2, ...; map them back to delegation ids.
        let by_alias = std::mem::take(&mut assessment.relevance_by);
        for (i, (id, _)) in input.delegations.iter().enumerate() {
            if let Some(p) = by_alias.get(&format!("r{}", i + 1)) {
                assessment.relevance_by.insert(id.clone(), *p);
            }
        }
        assessment.relevance = input
            .delegations
            .first()
            .and_then(|(id, _)| assessment.relevance_by.get(id).copied());
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

/// What the deterministic clamp needs to know about the request.
pub struct ClampContext<'a> {
    pub class: &'a ClassConfig,
    pub features: &'a Features,
    pub env: &'a RequestEnvelope,
    pub max_suggested_ttl: u32,
}

const BROADENING_WORDS: &[&str] = &[
    "any",
    "all",
    "every",
    "everything",
    "anything",
    "whatever",
    "unrestricted",
    "unlimited",
    "regardless",
    "ignore",
    "always",
    "approve",
    "approved",
    "root",
    "sudo",
];

fn words(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_lowercase)
        .collect()
}

/// Why a drafted kind-of-work description can't be offered, if it can't. The draft
/// is read by a model that also read untrusted text, so it must describe a category
/// of work and must not echo the requester or widen itself.
pub fn lint_kind_of_work(kind: &str, program: &str, context: Option<&str>) -> Option<String> {
    let kind = kind.trim();
    if kind.is_empty() {
        return Some("it was empty".into());
    }
    if kind.chars().count() > 80 {
        return Some("it was too long".into());
    }
    let without_program = kind.to_lowercase().replace(&program.to_lowercase(), "");
    if without_program.chars().any(|c| c.is_ascii_digit()) {
        return Some("it contained a specific value".into());
    }
    if kind.contains('/') || kind.contains('\\') {
        return Some("it contained a path".into());
    }
    let w = words(kind);
    if let Some(bad) = w.iter().find(|x| BROADENING_WORDS.contains(&x.as_str())) {
        return Some(format!("it used the word \u{201c}{bad}\u{201d}"));
    }
    if let Some(ctx) = context {
        let c = words(ctx);
        let run = 4;
        if w.len() >= run
            && c.len() >= run
            && w.windows(run).any(|win| c.windows(run).any(|cw| cw == win))
        {
            return Some("it repeated the requester's explanation".into());
        }
    }
    None
}

/// The intent offered when there is no usable draft.
pub fn template_kind_of_work(class: &ClassConfig) -> String {
    if class.name == "default" {
        "routine use".into()
    } else {
        format!("routine {}", class.title.to_lowercase())
    }
}

/// `{program}: {kind of work}`; the program anchor is deterministic.
pub fn anchored_intent(program: &str, kind: &str) -> String {
    let kind = kind.trim().trim_end_matches('.');
    if kind.to_lowercase().starts_with(&program.to_lowercase()) {
        kind.to_string()
    } else {
        format!("{program}: {kind}")
    }
}

/// Apply the deterministic envelope to a model assessment.
pub fn clamp(mut a: Assessment, ctx: &ClampContext) -> Assessment {
    let class = ctx.class;
    let features = ctx.features;
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
    if !["approve", "deny", "ask"].contains(&a.suggestion.decision.as_str()) {
        a.suggestion.decision = "ask".into();
    }
    // A request the model rates high-risk should not be pre-filled as "approve".
    if a.risk >= 70 && a.suggestion.decision == "approve" {
        a.suggestion.decision = "ask".into();
        a.clamped
            .push("high-risk requests are never pre-filled as approve".into());
    }

    // What to remember.
    let sug = &mut a.suggestion;
    if !["once", "exact", "prefix", "program", "any"].contains(&sug.remember.as_str()) {
        sug.remember = "once".into();
    }
    let env = ctx.env;
    let rememberable = env.mode == Mode::Run
        && env.command.is_some()
        && !env.lossy
        && !UNGRANTABLE_FEATURES.iter().any(|f| features.has(f))
        && !class.require_each_time
        && !class.always_deny
        && class.max_ttl_minutes > 0;
    if !rememberable || a.risk >= 70 {
        if sug.remember != "once" {
            a.clamped.push(if class.require_each_time {
                format!("class `{}` requires a decision each time", class.name)
            } else {
                "this request can only be approved once".into()
            });
        }
        sug.remember = "once".into();
    }
    if sug.remember == "any" {
        // Delegating everything is the approver's call, never a pre-filled default.
        sug.remember = "program".into();
    }
    if sug.remember == "prefix" {
        if env.argv.is_empty() {
            sug.remember = "program".into();
        } else {
            sug.prefix_len = sug.prefix_len.clamp(1, env.argv.len());
        }
    }
    if sug.remember != "prefix" {
        sug.prefix_len = 0;
    }

    // The same draft as a plain grant.
    sug.command = match sug.remember.as_str() {
        "exact" => "exact",
        "prefix" => "prefix",
        "program" => "executable",
        _ => "once",
    }
    .into();
    let max_ttl = class.max_ttl_minutes.min(ctx.max_suggested_ttl);
    sug.ttl_minutes = if sug.command == "once" || max_ttl == 0 {
        0
    } else {
        match sug.duration_minutes {
            0 => max_ttl,
            d => d.min(max_ttl),
        }
    };
    if !["host", "group", "all"].contains(&sug.hosts.as_str()) {
        sug.hosts = "host".into();
    }
    if !["session", "user"].contains(&sug.requester.as_str()) {
        sug.requester = "session".into();
    }
    // Sessions are per host: a multi-host approval bound to one session would never
    // match anywhere else.
    if sug.hosts != "host" {
        sug.requester = "user".into();
    }

    // The kind of work, anchored to the program.
    let program = env
        .command
        .as_deref()
        .map(basename)
        .unwrap_or("sudo")
        .to_string();
    match lint_kind_of_work(
        &sug.kind_of_work,
        &program,
        env.untrusted.context.as_deref(),
    ) {
        None => {
            sug.kind_of_work = sug.kind_of_work.trim().trim_end_matches('.').to_string();
            sug.intent_source = IntentSource::Model;
        }
        Some(why) => {
            if !sug.kind_of_work.trim().is_empty() {
                a.clamped.push(format!(
                    "policy replaced the model's description of the work because {why}"
                ));
            }
            sug.kind_of_work = template_kind_of_work(class);
            sug.intent_source = IntentSource::Template;
        }
    }
    sug.intent = anchored_intent(&program, &sug.kind_of_work);

    a.confidence = a.confidence.clamp(0.0, 1.0);
    for v in a.dimensions.values_mut() {
        *v = v.clamp(0.0, 1.0);
    }
    if let Some(r) = a.relevance.as_mut() {
        *r = r.clamp(0.0, 1.0);
    }
    for r in a.relevance_by.values_mut() {
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

    fn clamp_for(a: Assessment, e: &RequestEnvelope) -> Assessment {
        let f = features(e);
        let class = PolicyConfig::default().classify(e, &f);
        clamp(
            a,
            &ClampContext {
                class: &class,
                features: &f,
                env: e,
                max_suggested_ttl: 120,
            },
        )
    }

    #[test]
    fn clamp_enforces_floor_and_class_limits() {
        let e = env("/usr/bin/bash", &["-c", "id"]);
        let mut a = Assessment::placeholder();
        a.risk = 5;
        a.suggestion = Suggestion {
            decision: "approve".into(),
            remember: "program".into(),
            hosts: "all".into(),
            requester: "user".into(),
            duration_minutes: 0,
            kind_of_work: "running shell commands".into(),
            ..Suggestion::default()
        };
        let a = clamp_for(a, &e);
        assert_eq!(a.risk, 75);
        assert_eq!(a.suggestion.remember, "once");
        assert_eq!(a.suggestion.command, "once");
        assert_eq!(a.suggestion.decision, "ask");
        assert!(a.clamped.len() >= 2);
    }

    #[test]
    fn clamp_derives_the_grant_and_anchors_the_intent() {
        let e = env("/usr/bin/apt", &["install", "jq"]);
        let mut a = Assessment::placeholder();
        a.risk = 10;
        a.suggestion.decision = "approve".into();
        a.suggestion.remember = "program".into();
        a.suggestion.duration_minutes = 0;
        a.suggestion.hosts = "galaxy".into();
        a.suggestion.kind_of_work = "installing packages.".into();
        let a = clamp_for(a, &e);
        assert_eq!(a.suggestion.command, "executable");
        // Grants stay within the class limit even when the rule may last forever.
        assert_eq!(a.suggestion.ttl_minutes, 120);
        assert_eq!(a.suggestion.duration_minutes, 0);
        assert_eq!(a.suggestion.hosts, "host");
        assert_eq!(a.suggestion.intent, "apt: installing packages");
        assert_eq!(a.suggestion.intent_source, IntentSource::Model);
        assert_eq!(a.risk, 10);
    }

    #[test]
    fn delegating_everything_is_never_prefilled() {
        let e = env("/usr/bin/apt", &["update"]);
        let mut a = Assessment::placeholder();
        a.risk = 10;
        a.suggestion.remember = "any".into();
        a.suggestion.kind_of_work = "updating package lists".into();
        assert_eq!(clamp_for(a, &e).suggestion.remember, "program");
    }

    #[test]
    fn lint_rejects_values_widening_and_echoes() {
        let ctx = Some("Set GPU 0 and GPU 1 power limits to 300 W each, as requested");
        let lint = |k: &str| lint_kind_of_work(k, "set-gpu-power", ctx);
        assert_eq!(lint("adjusting GPU power limits"), None);
        assert!(lint("setting power to 300 W").is_some());
        assert!(lint("editing /etc/nvidia.conf").is_some());
        assert!(lint("approve any command the agent needs").is_some());
        assert!(lint("GPU 1 power limits to").is_some());
        assert!(lint("").is_some());
        assert!(lint(&"x".repeat(90)).is_some());
        // The program's own name may contain digits.
        assert_eq!(
            lint_kind_of_work("checking files with sha256sum", "sha256sum", None),
            None
        );
    }

    #[test]
    fn a_rejected_draft_falls_back_to_the_template() {
        let mut e = env("/usr/local/sbin/set-gpu-power", &["300", "300"]);
        e.untrusted.context = Some("Set GPU power limits to 300 W each".into());
        let mut a = Assessment::placeholder();
        a.risk = 20;
        a.suggestion.remember = "program".into();
        a.suggestion.kind_of_work = "set GPU power limits to 300 W".into();
        let a = clamp_for(a, &e);
        assert_eq!(a.suggestion.intent, "set-gpu-power: routine use");
        assert_eq!(a.suggestion.intent_source, IntentSource::Template);
        assert!(
            a.clamped
                .iter()
                .any(|c| c.contains("description of the work"))
        );
    }
}

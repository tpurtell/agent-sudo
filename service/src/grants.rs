//! Grants (standing approvals) and delegations (bounded authority for the decision model).
//!
//! Matching is exact and deterministic. A grant never matches a request whose arguments
//! were rendered lossily, and never matches a class that requires a decision each time.

use std::collections::BTreeMap;

use agent_sudo_protocol::api::RequestEnvelope;
use serde::{Deserialize, Serialize};

use crate::advisor::Assessment;
use crate::policy::{ClassConfig, Features};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CommandMatch {
    /// Same executable and identical arguments.
    Exact,
    /// Same executable, arguments starting with `argv`.
    Prefix,
    /// Same executable, any arguments.
    Executable,
    /// Any command (delegations only).
    Any,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandScope {
    #[serde(rename = "match")]
    pub kind: CommandMatch,
    #[serde(default)]
    pub mode: Option<agent_sudo_protocol::api::Mode>,
    #[serde(default)]
    pub executable: Option<String>,
    #[serde(default)]
    pub argv: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "scope", rename_all = "snake_case")]
pub enum HostScope {
    Host { host_id: String },
    Groups { groups: Vec<String> },
    All,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "scope", rename_all = "snake_case")]
pub enum RequesterScope {
    /// One agent session (fingerprint established by hostd).
    Session { fingerprint: String, label: String },
    /// Any session of this unix user.
    User { user: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrantSpec {
    pub command: CommandScope,
    pub hosts: HostScope,
    pub requester: RequesterScope,
    pub target_uid: u32,
    #[serde(default)]
    pub refresh_timestamp: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct DelegationLimits {
    /// Highest overall risk (0-100) the model may approve.
    pub max_risk: u8,
    /// Lowest model confidence (0-1) accepted.
    pub min_confidence: f32,
    /// Per-dimension probability ceilings (0-1), e.g. `destructive = 0.2`.
    #[serde(default)]
    pub max_dimensions: BTreeMap<String, f32>,
    /// Minimum relevance (0-1) of the request to the stated intent.
    #[serde(default = "default_relevance")]
    pub min_relevance: f32,
    /// Features that always fall back to a human.
    #[serde(default)]
    pub forbidden_features: Vec<String>,
}

fn default_relevance() -> f32 {
    0.5
}

impl Default for DelegationLimits {
    fn default() -> Self {
        // Chat models report these as rough likelihoods, not calibrated probabilities.
        // They are backstops; relevance, overall risk, and the deterministic forbidden
        // features do most of the gating. Tuned against DeepSeek V4 Flash.
        let mut dims = BTreeMap::new();
        for (k, v) in [
            ("destructive", 0.4),
            ("privilege_escape", 0.4),
            ("persistence", 0.9),
            ("credential_access", 0.3),
            ("network_security", 0.6),
        ] {
            dims.insert(k.to_string(), v);
        }
        Self {
            max_risk: 35,
            min_confidence: 0.55,
            max_dimensions: dims,
            min_relevance: default_relevance(),
            forbidden_features: vec!["root_shell".into(), "destructive".into()],
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum NotifyMode {
    #[default]
    Each,
    Digest,
    Silent,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DelegationSpec {
    /// The approver's own words about the expected work. Given to the model as intent.
    pub intent: String,
    pub hosts: HostScope,
    /// `None` means any unix user on the scoped hosts.
    #[serde(default)]
    pub requester: Option<RequesterScope>,
    #[serde(default)]
    pub target_uids: Vec<u32>,
    /// Only these classes (empty = any delegable class).
    #[serde(default)]
    pub classes: Vec<String>,
    #[serde(default)]
    pub limits: DelegationLimits,
    #[serde(default)]
    pub notify: NotifyMode,
}

/// Facts about the host a request came from.
pub struct HostFacts<'a> {
    pub host_id: &'a str,
    pub groups: &'a [String],
}

pub fn host_in_scope(scope: &HostScope, host: &HostFacts) -> bool {
    match scope {
        HostScope::Host { host_id } => host_id == host.host_id,
        HostScope::Groups { groups } => groups.iter().any(|g| host.groups.contains(g)),
        HostScope::All => true,
    }
}

pub fn requester_in_scope(scope: &RequesterScope, env: &RequestEnvelope) -> bool {
    match scope {
        RequesterScope::Session { fingerprint, .. } => *fingerprint == env.session.fingerprint,
        RequesterScope::User { user } => *user == env.user.name,
    }
}

pub fn command_in_scope(scope: &CommandScope, env: &RequestEnvelope) -> bool {
    if let Some(mode) = scope.mode
        && mode != env.mode
    {
        return false;
    }
    match scope.kind {
        CommandMatch::Any => true,
        CommandMatch::Executable => scope.executable.is_some() && scope.executable == env.command,
        CommandMatch::Exact => scope.executable == env.command && scope.argv == env.argv,
        CommandMatch::Prefix => {
            scope.executable.is_some()
                && scope.executable == env.command
                && env.argv.len() >= scope.argv.len()
                && env.argv[..scope.argv.len()] == scope.argv[..]
        }
    }
}

/// Does a standing grant cover this request?
pub fn grant_matches(
    spec: &GrantSpec,
    env: &RequestEnvelope,
    host: &HostFacts,
    class: &ClassConfig,
) -> bool {
    !env.lossy
        && !class.require_each_time
        && !class.always_deny
        && spec.target_uid == env.target.uid
        && host_in_scope(&spec.hosts, host)
        && requester_in_scope(&spec.requester, env)
        && command_in_scope(&spec.command, env)
}

/// Does a delegation's scope (before consulting the model) cover this request?
pub fn delegation_scope_matches(
    spec: &DelegationSpec,
    env: &RequestEnvelope,
    host: &HostFacts,
    class: &ClassConfig,
) -> bool {
    class.delegable
        && !class.always_deny
        && !class.require_each_time
        && !env.lossy
        && host_in_scope(&spec.hosts, host)
        && spec
            .requester
            .as_ref()
            .is_none_or(|r| requester_in_scope(r, env))
        && (spec.target_uids.is_empty() || spec.target_uids.contains(&env.target.uid))
        && (spec.classes.is_empty() || spec.classes.contains(&class.name))
}

/// The deterministic envelope check applied to a model assessment. Returns the list of
/// reasons the delegation may *not* approve; empty means approve.
pub fn delegation_verdict(
    spec: &DelegationSpec,
    features: &Features,
    global_forbidden: &[String],
    assessment: &Assessment,
) -> Vec<String> {
    let mut reasons = Vec::new();
    for f in spec
        .limits
        .forbidden_features
        .iter()
        .chain(global_forbidden)
    {
        if features.has(f) {
            reasons.push(format!("request has forbidden feature `{f}`"));
        }
    }
    if assessment.risk > spec.limits.max_risk {
        reasons.push(format!(
            "risk {} is above the limit {}",
            assessment.risk, spec.limits.max_risk
        ));
    }
    if assessment.confidence < spec.limits.min_confidence {
        reasons.push(format!(
            "confidence {:.0}% is below {:.0}%",
            assessment.confidence * 100.0,
            spec.limits.min_confidence * 100.0
        ));
    }
    for (dim, ceiling) in &spec.limits.max_dimensions {
        if let Some(p) = assessment.dimensions.get(dim)
            && p > ceiling
        {
            reasons.push(format!(
                "{} {:.0}% is above {:.0}%",
                dim.replace('_', " "),
                p * 100.0,
                ceiling * 100.0
            ));
        }
    }
    match assessment.relevance {
        Some(r) if r < spec.limits.min_relevance => {
            reasons.push(format!(
                "relevance to the delegation intent is only {:.0}%",
                r * 100.0
            ));
        }
        None if !spec.intent.trim().is_empty() => {
            reasons.push("no relevance judgement available".into())
        }
        _ => {}
    }
    if assessment.suggestion.decision != "approve" {
        reasons.push(format!(
            "the model suggested `{}`",
            assessment.suggestion.decision
        ));
    }
    reasons
}

pub fn describe_grant(spec: &GrantSpec, host_name: impl Fn(&str) -> String) -> String {
    let command = match spec.command.kind {
        CommandMatch::Exact => "exact command",
        CommandMatch::Prefix => "command prefix",
        CommandMatch::Executable => "any arguments",
        CommandMatch::Any => "any command",
    };
    let hosts = match &spec.hosts {
        HostScope::Host { host_id } => host_name(host_id),
        HostScope::Groups { groups } => groups.join(", "),
        HostScope::All => "all hosts".into(),
    };
    let who = match &spec.requester {
        RequesterScope::Session { label, .. } => label.clone(),
        RequesterScope::User { user } => format!("user {user}"),
    };
    format!("{command} · {hosts} · {who}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advisor::{Assessment, Suggestion};
    use crate::policy::tests::env;
    use crate::policy::{PolicyConfig, features};

    fn spec(kind: CommandMatch, exe: &str, argv: &[&str]) -> GrantSpec {
        GrantSpec {
            command: CommandScope {
                kind,
                mode: None,
                executable: Some(exe.into()),
                argv: argv.iter().map(|s| s.to_string()).collect(),
            },
            hosts: HostScope::Groups {
                groups: vec!["sparks".into()],
            },
            requester: RequesterScope::User { user: "tj".into() },
            target_uid: 0,
            refresh_timestamp: false,
        }
    }

    fn class_of(e: &RequestEnvelope) -> ClassConfig {
        PolicyConfig::default().classify(e, &features(e))
    }

    #[test]
    fn exact_prefix_and_executable() {
        let groups = vec!["sparks".to_string()];
        let host = HostFacts {
            host_id: "h1",
            groups: &groups,
        };
        let e = env("/usr/bin/systemctl", &["restart", "nvidia-persistenced"]);
        let c = class_of(&e);
        assert!(grant_matches(
            &spec(
                CommandMatch::Exact,
                "/usr/bin/systemctl",
                &["restart", "nvidia-persistenced"]
            ),
            &e,
            &host,
            &c
        ));
        assert!(!grant_matches(
            &spec(CommandMatch::Exact, "/usr/bin/systemctl", &["restart"]),
            &e,
            &host,
            &c
        ));
        assert!(grant_matches(
            &spec(CommandMatch::Prefix, "/usr/bin/systemctl", &["restart"]),
            &e,
            &host,
            &c
        ));
        assert!(grant_matches(
            &spec(CommandMatch::Executable, "/usr/bin/systemctl", &[]),
            &e,
            &host,
            &c
        ));
        assert!(!grant_matches(
            &spec(CommandMatch::Executable, "/usr/bin/apt", &[]),
            &e,
            &host,
            &c
        ));
        let other = HostFacts {
            host_id: "h2",
            groups: &[],
        };
        assert!(!grant_matches(
            &spec(CommandMatch::Executable, "/usr/bin/systemctl", &[]),
            &e,
            &other,
            &c
        ));
    }

    #[test]
    fn never_matches_each_time_classes_or_lossy() {
        let groups = vec!["sparks".to_string()];
        let host = HostFacts {
            host_id: "h1",
            groups: &groups,
        };
        let e = env("/usr/bin/bash", &[]);
        assert!(!grant_matches(
            &spec(CommandMatch::Executable, "/usr/bin/bash", &[]),
            &e,
            &host,
            &class_of(&e)
        ));
        let mut e = env("/usr/bin/apt", &["update"]);
        e.lossy = true;
        assert!(!grant_matches(
            &spec(CommandMatch::Exact, "/usr/bin/apt", &["update"]),
            &e,
            &host,
            &class_of(&e)
        ));
    }

    #[test]
    fn session_scope() {
        let host = HostFacts {
            host_id: "h1",
            groups: &[],
        };
        let e = env("/usr/bin/apt", &["update"]);
        let mut s = spec(CommandMatch::Exact, "/usr/bin/apt", &["update"]);
        s.hosts = HostScope::Host {
            host_id: "h1".into(),
        };
        s.requester = RequesterScope::Session {
            fingerprint: "b:1:2".into(),
            label: "x".into(),
        };
        assert!(grant_matches(&s, &e, &host, &class_of(&e)));
        s.requester = RequesterScope::Session {
            fingerprint: "b:9:9".into(),
            label: "x".into(),
        };
        assert!(!grant_matches(&s, &e, &host, &class_of(&e)));
    }

    fn assessment(risk: u8, decision: &str) -> Assessment {
        let mut a = Assessment::placeholder();
        a.risk = risk;
        a.confidence = 0.9;
        a.relevance = Some(0.9);
        a.suggestion = Suggestion {
            decision: decision.into(),
            ..Suggestion::default()
        };
        a
    }

    #[test]
    fn delegation_verdicts() {
        let spec = DelegationSpec {
            intent: "install drivers".into(),
            hosts: HostScope::All,
            requester: None,
            target_uids: vec![],
            classes: vec![],
            limits: DelegationLimits::default(),
            notify: NotifyMode::Each,
        };
        let e = env("/usr/bin/apt", &["install", "nvidia-driver-580"]);
        let f = features(&e);
        assert!(delegation_verdict(&spec, &f, &[], &assessment(10, "approve")).is_empty());
        assert!(!delegation_verdict(&spec, &f, &[], &assessment(80, "approve")).is_empty());
        assert!(!delegation_verdict(&spec, &f, &[], &assessment(10, "ask")).is_empty());
        let mut a = assessment(10, "approve");
        a.dimensions.insert("destructive".into(), 0.9);
        assert!(!delegation_verdict(&spec, &f, &[], &a).is_empty());
        assert!(
            !delegation_verdict(
                &spec,
                &f,
                &["package_manager".into()],
                &assessment(10, "approve")
            )
            .is_empty()
        );
    }

    #[test]
    fn delegation_scope_respects_class() {
        let host = HostFacts {
            host_id: "h1",
            groups: &[],
        };
        let spec = DelegationSpec {
            intent: String::new(),
            hosts: HostScope::All,
            requester: None,
            target_uids: vec![],
            classes: vec![],
            limits: DelegationLimits::default(),
            notify: NotifyMode::Each,
        };
        let e = env("/usr/bin/apt", &["install", "x"]);
        assert!(delegation_scope_matches(&spec, &e, &host, &class_of(&e)));
        let e = env("/usr/bin/bash", &[]);
        assert!(!delegation_scope_matches(&spec, &e, &host, &class_of(&e)));
    }
}

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
    /// The invocation details a grant is bound to, beyond the command line.
    #[serde(default)]
    pub target_gid: Option<u32>,
    #[serde(default)]
    pub launch: agent_sudo_protocol::api::Launch,
    #[serde(default)]
    pub chdir: Option<String>,
    #[serde(default)]
    pub env: Vec<String>,
}

/// Features whose presence means the approved thing could differ from what runs
/// later: such requests never become or match standing grants.
pub const UNGRANTABLE_FEATURES: &[&str] = &["user_symlink", "unverified_executable", "lossy"];

pub fn grantable(env: &RequestEnvelope, features: &Features) -> bool {
    !env.lossy && !UNGRANTABLE_FEATURES.iter().any(|f| features.has(f))
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

/// Who wrote a delegation's intent. The requesting agent never does.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum IntentSource {
    /// Typed or edited by the approver.
    #[default]
    Approver,
    /// Drafted by the decision model from the command, then accepted by the approver.
    Model,
    /// Built by policy from the program name when the model's draft was rejected.
    Template,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DelegationSpec {
    /// The kind of work the model judges requests against, e.g.
    /// `set-gpu-power: adjusting GPU power limits`. Never the requester's own text.
    pub intent: String,
    #[serde(default)]
    pub intent_source: IntentSource,
    /// Programs this delegation covers, checked deterministically before the model is
    /// asked anything. Empty means any program, which only the approver can choose.
    #[serde(default)]
    pub commands: Vec<CommandScope>,
    /// Most automatic approvals in any 24 hours; `None` uses the service default and
    /// 0 means no limit.
    #[serde(default)]
    pub per_day: Option<u32>,
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
    features: &Features,
    host: &HostFacts,
    class: &ClassConfig,
) -> bool {
    grantable(env, features)
        && !class.require_each_time
        && !class.always_deny
        && spec.target_uid == env.target.uid
        && spec.target_gid == Some(env.target.gid)
        && spec.launch == env.launch
        && spec.chdir == env.chdir
        && spec.env == env.env
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
        && (spec.commands.is_empty() || spec.commands.iter().any(|c| command_in_scope(c, env)))
}

/// Order for trying delegations: the narrowest command filter first, then the
/// narrowest hosts. A narrow rule owns the requests it was made for.
pub fn delegation_specificity(spec: &DelegationSpec) -> (u8, u8, u8) {
    let command = spec
        .commands
        .iter()
        .map(|c| match c.kind {
            CommandMatch::Exact => 0,
            CommandMatch::Prefix => 1,
            CommandMatch::Executable => 2,
            CommandMatch::Any => 3,
        })
        .max()
        .unwrap_or(3);
    let hosts = match spec.hosts {
        HostScope::Host { .. } => 0,
        HostScope::Groups { .. } => 1,
        HostScope::All => 2,
    };
    let who = match spec.requester {
        Some(RequesterScope::Session { .. }) => 0,
        Some(RequesterScope::User { .. }) => 1,
        None => 2,
    };
    (command, hosts, who)
}

/// A program's file name, used to anchor intents and labels.
pub fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Short human form of a command filter, e.g. `set-gpu-power (any arguments)`.
pub fn describe_commands(commands: &[CommandScope]) -> String {
    if commands.is_empty() {
        return "any command".into();
    }
    commands
        .iter()
        .map(|c| {
            let name = c.executable.as_deref().map(basename).unwrap_or("?");
            match c.kind {
                CommandMatch::Exact if c.argv.is_empty() => format!("{name} (no arguments)"),
                CommandMatch::Exact => format!("{name} {}", c.argv.join(" ")),
                CommandMatch::Prefix => format!("{name} {} …", c.argv.join(" ")),
                CommandMatch::Executable => format!("{name} (any arguments)"),
                CommandMatch::Any => "any command".into(),
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// The deterministic envelope check applied to a model assessment. Returns the list of
/// reasons the delegation may *not* approve; empty means approve.
pub fn delegation_verdict(
    spec: &DelegationSpec,
    features: &Features,
    global_forbidden: &[String],
    assessment: &Assessment,
    relevance: Option<f32>,
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
        match assessment.dimensions.get(dim) {
            Some(p) if p > ceiling => reasons.push(format!(
                "{} {:.0}% is above {:.0}%",
                dim.replace('_', " "),
                p * 100.0,
                ceiling * 100.0
            )),
            Some(_) => {}
            // A missing judgement can't pass a ceiling.
            None => reasons.push(format!(
                "the model gave no {} judgement",
                dim.replace('_', " ")
            )),
        }
    }
    // Without a command filter the intent is the only anchor, so it must fit better.
    let min_relevance = if spec.commands.is_empty() {
        spec.limits.min_relevance.max(0.7)
    } else {
        spec.limits.min_relevance
    };
    match relevance {
        Some(r) if r < min_relevance => {
            reasons.push(format!(
                "not the same kind of work (fit {:.0}%, needs {:.0}%)",
                r * 100.0,
                min_relevance * 100.0
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
            target_gid: Some(0),
            launch: Default::default(),
            chdir: None,
            env: vec![],
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
            &features(&e),
            &host,
            &c
        ));
        assert!(!grant_matches(
            &spec(CommandMatch::Exact, "/usr/bin/systemctl", &["restart"]),
            &e,
            &features(&e),
            &host,
            &c
        ));
        assert!(grant_matches(
            &spec(CommandMatch::Prefix, "/usr/bin/systemctl", &["restart"]),
            &e,
            &features(&e),
            &host,
            &c
        ));
        assert!(grant_matches(
            &spec(CommandMatch::Executable, "/usr/bin/systemctl", &[]),
            &e,
            &features(&e),
            &host,
            &c
        ));
        assert!(!grant_matches(
            &spec(CommandMatch::Executable, "/usr/bin/apt", &[]),
            &e,
            &features(&e),
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
            &features(&e),
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
            &features(&e),
            &host,
            &class_of(&e)
        ));
        let mut e = env("/usr/bin/apt", &["update"]);
        e.lossy = true;
        assert!(!grant_matches(
            &spec(CommandMatch::Exact, "/usr/bin/apt", &["update"]),
            &e,
            &features(&e),
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
        assert!(grant_matches(&s, &e, &features(&e), &host, &class_of(&e)));
        s.requester = RequesterScope::Session {
            fingerprint: "b:9:9".into(),
            label: "x".into(),
        };
        assert!(!grant_matches(&s, &e, &features(&e), &host, &class_of(&e)));
    }

    fn assessment(risk: u8, decision: &str) -> Assessment {
        let mut a = Assessment::placeholder();
        a.risk = risk;
        a.confidence = 0.9;
        a.relevance = Some(0.9);
        for (k, _) in crate::advisor::DIMENSIONS {
            a.dimensions.insert(k.to_string(), 0.05);
        }
        a.suggestion = Suggestion {
            decision: decision.into(),
            ..Suggestion::default()
        };
        a
    }

    fn dspec(intent: &str, commands: Vec<CommandScope>) -> DelegationSpec {
        DelegationSpec {
            intent: intent.into(),
            intent_source: IntentSource::Approver,
            commands,
            per_day: None,
            hosts: HostScope::All,
            requester: None,
            target_uids: vec![],
            classes: vec![],
            limits: DelegationLimits::default(),
            notify: NotifyMode::Each,
        }
    }

    fn program(exe: &str) -> CommandScope {
        CommandScope {
            kind: CommandMatch::Executable,
            mode: Some(agent_sudo_protocol::api::Mode::Run),
            executable: Some(exe.into()),
            argv: vec![],
        }
    }

    #[test]
    fn delegation_program_filter() {
        let host = HostFacts {
            host_id: "h1",
            groups: &[],
        };
        let spec = dspec(
            "set-gpu-power: adjusting GPU power limits",
            vec![program("/usr/local/sbin/set-gpu-power")],
        );
        for argv in [&["300", "300"][..], &[][..], &["400"][..]] {
            let e = env("/usr/local/sbin/set-gpu-power", argv);
            assert!(delegation_scope_matches(&spec, &e, &host, &class_of(&e)));
        }
        let e = env("/usr/bin/nvidia-smi", &["-pl", "300"]);
        assert!(!delegation_scope_matches(&spec, &e, &host, &class_of(&e)));

        let mut prefix = program("/usr/bin/systemctl");
        prefix.kind = CommandMatch::Prefix;
        prefix.argv = vec!["restart".into()];
        let spec = dspec("systemctl: restarting services", vec![prefix]);
        let e = env("/usr/bin/systemctl", &["restart", "docker"]);
        assert!(delegation_scope_matches(&spec, &e, &host, &class_of(&e)));
        let e = env("/usr/bin/systemctl", &["disable", "docker"]);
        assert!(!delegation_scope_matches(&spec, &e, &host, &class_of(&e)));
    }

    #[test]
    fn unfiltered_delegations_need_a_closer_fit() {
        let e = env("/usr/bin/apt", &["install", "jq"]);
        let f = features(&e);
        let a = assessment(10, "approve");
        let open = dspec("apt: routine package management", vec![]);
        let filtered = dspec(
            "apt: routine package management",
            vec![program("/usr/bin/apt")],
        );
        assert!(delegation_verdict(&filtered, &f, &[], &a, Some(0.6)).is_empty());
        assert!(!delegation_verdict(&open, &f, &[], &a, Some(0.6)).is_empty());
        assert!(delegation_verdict(&open, &f, &[], &a, Some(0.8)).is_empty());
    }

    #[test]
    fn narrower_delegations_come_first() {
        let mut exact = program("/usr/bin/apt");
        exact.kind = CommandMatch::Exact;
        let mut specs = [
            dspec("any", vec![]),
            dspec("program", vec![program("/usr/bin/apt")]),
            dspec("exact", vec![exact]),
        ];
        specs.sort_by_key(delegation_specificity);
        let order: Vec<&str> = specs.iter().map(|s| s.intent.as_str()).collect();
        assert_eq!(order, ["exact", "program", "any"]);
    }

    #[test]
    fn delegations_stored_before_filters_still_parse() {
        let old = r#"{"intent":"GPU POWER CONFIG","hosts":{"scope":"host","host_id":"h"},"requester":null,
            "target_uids":[],"classes":[],"limits":{"max_risk":30},"notify":"each"}"#;
        let spec: DelegationSpec = serde_json::from_str(old).unwrap();
        assert!(spec.commands.is_empty());
        assert_eq!(spec.intent_source, IntentSource::Approver);
        assert_eq!(spec.per_day, None);
    }

    #[test]
    fn delegation_verdicts() {
        let spec = dspec("install drivers", vec![]);
        let e = env("/usr/bin/apt", &["install", "nvidia-driver-580"]);
        let f = features(&e);
        assert!(
            delegation_verdict(&spec, &f, &[], &assessment(10, "approve"), Some(0.9)).is_empty()
        );
        assert!(
            !delegation_verdict(&spec, &f, &[], &assessment(80, "approve"), Some(0.9)).is_empty()
        );
        assert!(!delegation_verdict(&spec, &f, &[], &assessment(10, "ask"), Some(0.9)).is_empty());
        let mut a = assessment(10, "approve");
        a.dimensions.insert("destructive".into(), 0.9);
        assert!(!delegation_verdict(&spec, &f, &[], &a, Some(0.9)).is_empty());
        assert!(
            !delegation_verdict(
                &spec,
                &f,
                &["package_manager".into()],
                &assessment(10, "approve"),
                Some(0.9)
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
        let spec = dspec("", vec![]);
        let e = env("/usr/bin/apt", &["install", "x"]);
        assert!(delegation_scope_matches(&spec, &e, &host, &class_of(&e)));
        let e = env("/usr/bin/bash", &[]);
        assert!(!delegation_scope_matches(&spec, &e, &host, &class_of(&e)));
    }
}

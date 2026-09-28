//! Request lifecycle.
//!
//! ```text
//! submitted ─┬─ class always denies ───────────────> denied (policy)
//!            ├─ a grant matches ───────────────────> approved (grant)
//!            ├─ a delegation matches ─> model ─> limits pass ─> approved (delegation)
//!            │                                  └─ otherwise falls through with the assessment
//!            ├─ sudo -n and nothing matched ───────> expired (quiet)
//!            └─ pending ─> push + live UI; advisor runs in the background
//!                   ├─ approver decides ──> approved | denied
//!                   ├─ host withdraws ───> withdrawn
//!                   └─ deadline passes ──> expired
//! ```

use std::collections::BTreeMap;
use std::time::Duration;

use agent_sudo_protocol::api::{
    DecidedVia, Decision, DecisionResponse, RequestEnvelope, RequestState, SubmitResponse,
};
use rusqlite::{OptionalExtension, Row, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::advisor::{self, AdvisorInput, Assessment, AssessmentFailure, sanitize};
use crate::audit;
use crate::auth::Session;
use crate::error::{ApiError, ApiResult};
use crate::events::Event;
use crate::grants::{
    self, CommandMatch, CommandScope, DelegationSpec, GrantSpec, HostFacts, HostScope, NotifyMode,
    RequesterScope,
};
use crate::policy::{self, ClassConfig, Features, StepUp};
use crate::push;
use crate::state::{AppState, Shared};
use crate::util::{human_duration, new_id, now_ms, short_code};

// ---------------------------------------------------------------------------
// Rows

#[derive(Debug, Clone, Serialize)]
pub struct HostRow {
    pub id: String,
    pub name: String,
    pub hostname: String,
    #[serde(skip)]
    pub public_key: String,
    pub groups: Vec<String>,
    pub hostd_version: String,
    pub created_at: i64,
    pub last_seen_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

fn row_host(r: &Row) -> rusqlite::Result<HostRow> {
    Ok(HostRow {
        id: r.get("id")?,
        name: r.get("name")?,
        hostname: r.get("hostname")?,
        public_key: r.get("public_key")?,
        groups: serde_json::from_str(&r.get::<_, String>("groups_json")?).unwrap_or_default(),
        hostd_version: r.get("hostd_version")?,
        created_at: r.get("created_at")?,
        last_seen_at: r.get("last_seen_at")?,
        revoked_at: r.get("revoked_at")?,
    })
}

pub fn host(state: &AppState, id: &str) -> anyhow::Result<Option<HostRow>> {
    Ok(state
        .db
        .lock()
        .query_row("SELECT * FROM hosts WHERE id = ?", [id], row_host)
        .optional()?)
}

pub fn hosts(state: &AppState) -> anyhow::Result<Vec<HostRow>> {
    let db = state.db.lock();
    let mut stmt = db.prepare("SELECT * FROM hosts ORDER BY revoked_at IS NOT NULL, name")?;
    let rows = stmt
        .query_map([], row_host)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn host_name(state: &AppState, id: &str) -> String {
    host(state, id)
        .ok()
        .flatten()
        .map(|h| h.name)
        .unwrap_or_else(|| id.to_string())
}

/// Assessment data stored with a request.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StoredAssessment {
    pub assessment: Option<Assessment>,
    pub failure: Option<AssessmentFailure>,
    /// Outcome of the delegation check, when a delegation's scope matched.
    pub delegation_check: Option<DelegationCheck>,
    /// True while an assessment is being computed.
    #[serde(default)]
    pub running: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationCheck {
    pub id: String,
    pub label: String,
    pub approved: bool,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionRecord {
    pub decision: Decision,
    pub user_id: Option<String>,
    pub device_id: Option<String>,
    pub device_label: Option<String>,
    /// session | passkey
    pub auth: Option<String>,
    pub note: Option<String>,
    pub grant: Option<String>,
    pub delegation: Option<String>,
    /// Whether the approver kept the advisor's suggested decision and scope.
    pub followed_suggestion: Option<bool>,
    pub at: i64,
}

#[derive(Debug, Clone)]
pub struct RequestRow {
    pub id: String,
    pub code: String,
    pub host_id: String,
    pub state: RequestState,
    pub version: i64,
    pub created_at: i64,
    pub updated_at: i64,
    pub deadline_at: i64,
    pub envelope: RequestEnvelope,
    pub class: String,
    pub features: Features,
    pub assessment: StoredAssessment,
    pub decision: Option<DecisionRecord>,
    pub grant_id: Option<String>,
    pub delegation_id: Option<String>,
    pub quiet: bool,
    pub flagged_at: Option<i64>,
    pub command_key: String,
}

fn row_request(r: &Row) -> rusqlite::Result<RequestRow> {
    let json_err = |e: serde_json::Error| rusqlite::Error::ToSqlConversionFailure(Box::new(e));
    Ok(RequestRow {
        id: r.get("id")?,
        code: r.get("code")?,
        host_id: r.get("host_id")?,
        state: RequestState::parse(&r.get::<_, String>("state")?).unwrap_or(RequestState::Expired),
        version: r.get("version")?,
        created_at: r.get("created_at")?,
        updated_at: r.get("updated_at")?,
        deadline_at: r.get("deadline_at")?,
        envelope: serde_json::from_str(&r.get::<_, String>("envelope_json")?).map_err(json_err)?,
        class: r.get("class")?,
        features: serde_json::from_str(&r.get::<_, String>("features_json")?).unwrap_or_default(),
        assessment: r
            .get::<_, Option<String>>("assessment_json")?
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default(),
        decision: r
            .get::<_, Option<String>>("decision_json")?
            .and_then(|s| serde_json::from_str(&s).ok()),
        grant_id: r.get("grant_id")?,
        delegation_id: r.get("delegation_id")?,
        quiet: r.get::<_, i64>("quiet")? != 0,
        flagged_at: r.get("flagged_at")?,
        command_key: r.get("command_key")?,
    })
}

pub fn request(state: &AppState, id: &str) -> anyhow::Result<Option<RequestRow>> {
    Ok(state
        .db
        .lock()
        .query_row("SELECT * FROM requests WHERE id = ?", [id], row_request)
        .optional()?)
}

pub struct ListFilter {
    pub pending_only: bool,
    pub include_quiet: bool,
    pub before: Option<i64>,
    pub limit: i64,
    pub host_id: Option<String>,
}

pub fn requests(state: &AppState, f: &ListFilter) -> anyhow::Result<Vec<RequestRow>> {
    let db = state.db.lock();
    let mut stmt = db.prepare(
        "SELECT * FROM requests
         WHERE (?1 = 0 OR state = 'pending')
           AND (?2 = 1 OR quiet = 0)
           AND created_at < ?3
           AND (?4 IS NULL OR host_id = ?4)
         ORDER BY created_at DESC LIMIT ?5",
    )?;
    let rows = stmt
        .query_map(
            params![
                f.pending_only as i64,
                f.include_quiet as i64,
                f.before.unwrap_or(i64::MAX),
                f.host_id,
                f.limit
            ],
            row_request,
        )?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

#[derive(Debug, Clone, Serialize)]
pub struct GrantRow {
    pub id: String,
    pub kind: String,
    pub label: String,
    pub spec: Value,
    pub created_by: String,
    pub created_from_request: Option<String>,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub revoked_by: Option<String>,
    pub uses: i64,
    pub max_uses: Option<i64>,
    pub last_used_at: Option<i64>,
    pub paused_at: Option<i64>,
    pub pause_reason: Option<String>,
}

impl GrantRow {
    pub fn active(&self, now: i64) -> bool {
        self.revoked_at.is_none()
            && self.paused_at.is_none()
            && self.expires_at.is_none_or(|e| e > now)
            && self.max_uses.is_none_or(|m| self.uses < m)
    }
}

fn row_grant(r: &Row) -> rusqlite::Result<GrantRow> {
    Ok(GrantRow {
        id: r.get("id")?,
        kind: r.get("kind")?,
        label: r.get("label")?,
        spec: serde_json::from_str(&r.get::<_, String>("spec_json")?).unwrap_or(Value::Null),
        created_by: r.get("created_by")?,
        created_from_request: r.get("created_from_request")?,
        created_at: r.get("created_at")?,
        expires_at: r.get("expires_at")?,
        revoked_at: r.get("revoked_at")?,
        revoked_by: r.get("revoked_by")?,
        uses: r.get("uses")?,
        max_uses: r.get("max_uses")?,
        last_used_at: r.get("last_used_at")?,
        paused_at: r.get("paused_at")?,
        pause_reason: r.get("pause_reason")?,
    })
}

pub fn grant(state: &AppState, id: &str) -> anyhow::Result<Option<GrantRow>> {
    Ok(state
        .db
        .lock()
        .query_row("SELECT * FROM grants WHERE id = ?", [id], row_grant)
        .optional()?)
}

/// Grants and delegations that are live or ended within the last day.
pub fn grants_recent(state: &AppState) -> anyhow::Result<Vec<GrantRow>> {
    let cutoff = now_ms() - 86_400_000;
    let db = state.db.lock();
    let mut stmt = db.prepare(
        "SELECT * FROM grants WHERE (revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?1))
            OR COALESCE(revoked_at, expires_at, 0) > ?1 ORDER BY created_at DESC LIMIT 200",
    )?;
    let rows = stmt
        .query_map([cutoff], row_grant)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn live_grants(state: &AppState, kind: &str) -> anyhow::Result<Vec<GrantRow>> {
    let now = now_ms();
    let db = state.db.lock();
    let mut stmt = db.prepare(
        "SELECT * FROM grants WHERE kind = ?1 AND revoked_at IS NULL AND paused_at IS NULL
           AND (expires_at IS NULL OR expires_at > ?2) AND (max_uses IS NULL OR uses < max_uses)
         ORDER BY created_at DESC",
    )?;
    let rows = stmt
        .query_map(params![kind, now], row_grant)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

// ---------------------------------------------------------------------------
// Views for the browser

pub fn class_view(c: &ClassConfig) -> Value {
    json!({
        "name": c.name,
        "title": c.title,
        "max_ttl_minutes": c.max_ttl_minutes,
        "require_each_time": c.require_each_time,
        "step_up": c.step_up,
        "hard_deny": c.hard_deny,
        "delegable": c.delegable,
        "quick_approve": c.quick_approve,
    })
}

pub fn class_named(state: &AppState, name: &str) -> ClassConfig {
    let classes = state.cfg.policy.effective_classes();
    classes
        .iter()
        .find(|c| c.name == name)
        .cloned()
        .unwrap_or_else(|| classes.last().cloned().expect("catch-all"))
}

pub fn request_view(state: &AppState, row: &RequestRow, detail: bool) -> Value {
    let class = class_named(state, &row.class);
    let host = host(state, &row.host_id).ok().flatten();
    let env = &row.envelope;
    let mut v = json!({
        "id": row.id,
        "code": row.code,
        "state": row.state.as_str(),
        "version": row.version,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
        "deadline_at": row.deadline_at,
        "host": host.as_ref().map(|h| json!({"id": h.id, "name": h.name, "groups": h.groups})),
        "user": env.user.name,
        "target": env.target.user,
        "target_uid": env.target.uid,
        "mode": env.mode,
        "launch": env.launch,
        "command": env.command,
        "argv": env.argv,
        "display": policy::display_command(env),
        "cwd": env.cwd,
        "chdir": env.chdir,
        "tty": env.tty,
        "interactive": env.interactive,
        "nonblocking": env.nonblocking,
        "lossy": env.lossy,
        "session": {
            "label": env.session.label,
            "agent": env.session.agent,
            "fingerprint": env.session.fingerprint,
            "ssh": env.session.ssh,
        },
        "context": env.untrusted.context,
        "claimed_session": env.untrusted.session,
        "class": class_view(&class),
        "features": row.features.0,
        "assessment": row.assessment,
        "decision": row.decision,
        "grant_id": row.grant_id,
        "delegation_id": row.delegation_id,
        "flagged_at": row.flagged_at,
        "quiet": row.quiet,
    });
    if detail {
        v["session"]["chain"] = json!(env.session.chain);
        v["related"] = json!(related(state, row));
    }
    v
}

/// Recent requests for the same command (any host), newest first.
fn related(state: &AppState, row: &RequestRow) -> Vec<Value> {
    let cutoff = now_ms() - 24 * 3_600_000;
    let rows: Vec<RequestRow> = {
        let db = state.db.lock();
        let Ok(mut stmt) = db.prepare(
            "SELECT * FROM requests WHERE command_key = ?1 AND id != ?2 AND created_at > ?3 AND quiet = 0
             ORDER BY created_at DESC LIMIT 8",
        ) else {
            return vec![];
        };
        stmt.query_map(params![row.command_key, row.id, cutoff], row_request)
            .map(|it| it.filter_map(Result::ok).collect())
            .unwrap_or_default()
    };
    rows.iter()
        .map(|r| {
            json!({
                "id": r.id,
                "host": host_name(state, &r.host_id),
                "state": r.state.as_str(),
                "via": r.decision.as_ref().map(|d| d.decision.via),
                "by": r.decision.as_ref().map(|d| d.decision.by.clone()),
                "created_at": r.created_at,
                "same_session": r.envelope.session.fingerprint == row.envelope.session.fingerprint,
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Submission

fn response_for(state: &AppState, row: &RequestRow) -> SubmitResponse {
    SubmitResponse {
        id: row.id.clone(),
        code: row.code.clone(),
        url: format!("{}/r/{}", state.cfg.base_url(), row.id),
        state: row.state,
        decision: row.decision.as_ref().map(|d| d.decision.clone()),
    }
}

fn existing(
    state: &AppState,
    host_id: &str,
    client_id: &str,
) -> anyhow::Result<Option<RequestRow>> {
    Ok(state
        .db
        .lock()
        .query_row(
            "SELECT * FROM requests WHERE host_id = ?1 AND client_request_id = ?2",
            params![host_id, client_id],
            row_request,
        )
        .optional()?)
}

fn automatic_decision(
    state: RequestState,
    via: DecidedVia,
    by: &str,
    label: &str,
) -> DecisionRecord {
    DecisionRecord {
        decision: Decision {
            state,
            via,
            by: by.to_string(),
            label: label.to_string(),
            hard: false,
            refresh_timestamp: false,
            reason: None,
        },
        user_id: None,
        device_id: None,
        device_label: None,
        auth: None,
        note: None,
        grant: None,
        delegation: None,
        followed_suggestion: None,
        at: now_ms(),
    }
}

pub async fn submit(
    state: &Shared,
    host: &HostRow,
    env: RequestEnvelope,
) -> anyhow::Result<SubmitResponse> {
    if let Some(row) = existing(state, &host.id, &env.client_request_id)? {
        return Ok(response_for(state, &row));
    }
    let features = policy::features(&env);
    let class = state.cfg.policy.classify(&env, &features);
    let now = now_ms();
    let facts = HostFacts {
        host_id: &host.id,
        groups: &host.groups,
    };
    let mut row = RequestRow {
        id: new_id("req"),
        code: short_code(),
        host_id: host.id.clone(),
        state: RequestState::Pending,
        version: 1,
        created_at: now,
        updated_at: now,
        deadline_at: now + env.timeout_secs as i64 * 1000,
        command_key: policy::command_key(&env),
        class: class.name.clone(),
        features: features.clone(),
        assessment: StoredAssessment::default(),
        decision: None,
        grant_id: None,
        delegation_id: None,
        quiet: false,
        flagged_at: None,
        envelope: env,
    };

    let mut auto_delegation: Option<GrantRow> = None;
    if class.always_deny {
        let mut d = automatic_decision(
            RequestState::Denied,
            DecidedVia::Policy,
            "policy",
            &class.title,
        );
        d.decision.hard = true;
        d.decision.reason = Some(format!("{} is always denied by policy", class.title));
        row.state = RequestState::Denied;
        row.decision = Some(d);
    } else if let Some(g) = matching_grant(state, &row, &facts, &class)? {
        let spec: GrantSpec = serde_json::from_value(g.spec.clone())?;
        let mut d = automatic_decision(
            RequestState::Approved,
            DecidedVia::Grant,
            &g.created_by,
            &grant_summary(state, &g),
        );
        d.decision.refresh_timestamp = spec.refresh_timestamp;
        d.grant = Some(g.id.clone());
        row.state = RequestState::Approved;
        row.grant_id = Some(g.id.clone());
        row.decision = Some(d);
        use_grant(state, &g)?;
    } else if let Some((delegation, stored)) =
        evaluate_delegations(state, &row, host, &facts, &class).await?
    {
        let approved = stored.delegation_check.as_ref().is_some_and(|c| c.approved);
        row.assessment = stored;
        if approved {
            let mut d = automatic_decision(
                RequestState::Approved,
                DecidedVia::Delegation,
                &delegation.created_by,
                &delegation.label,
            );
            d.delegation = Some(delegation.id.clone());
            row.state = RequestState::Approved;
            row.delegation_id = Some(delegation.id.clone());
            row.decision = Some(d);
            use_grant(state, &delegation)?;
            auto_delegation = Some(delegation);
        }
    }
    if row.state == RequestState::Pending && row.envelope.nonblocking {
        let mut d = automatic_decision(
            RequestState::Expired,
            DecidedVia::Policy,
            "policy",
            "sudo -n",
        );
        d.decision.reason = Some("non-interactive request and no standing approval".into());
        row.state = RequestState::Expired;
        row.quiet = true;
        row.decision = Some(d);
    }
    if row.state.is_final() {
        row.decision.as_mut().unwrap().at = now;
    }

    insert(state, &row)?;
    audit::record(
        &state.db,
        &format!("host:{}", host.name),
        "request.submitted",
        Some(&row.id),
        json!({
            "command": policy::display_command(&row.envelope),
            "user": row.envelope.user.name,
            "class": row.class,
            "state": row.state.as_str(),
            "via": row.decision.as_ref().map(|d| d.decision.via),
            "grant": row.grant_id,
            "delegation": row.delegation_id,
            "session": row.envelope.session.label,
        }),
    );
    state.emit(Event::Request {
        id: row.id.clone(),
        state: row.state.as_str().into(),
        version: row.version,
    });

    if row.state == RequestState::Pending {
        let s = state.clone();
        let r = row.clone();
        tokio::spawn(async move { notify_pending(&s, &r).await });
        let needs_assessment = row.assessment.assessment.is_none()
            && state.advisor.as_ref().is_some_and(|a| a.config.auto_assess);
        if needs_assessment {
            let s = state.clone();
            let id = row.id.clone();
            tokio::spawn(async move { assess_in_background(&s, &id).await });
        }
    } else if let Some(delegation) = auto_delegation {
        let s = state.clone();
        let r = row.clone();
        tokio::spawn(async move { notify_automated(&s, &r, &delegation).await });
    }
    Ok(response_for(state, &row))
}

fn insert(state: &AppState, row: &RequestRow) -> anyhow::Result<()> {
    state.db.lock().execute(
        "INSERT INTO requests (id, code, host_id, client_request_id, state, version, created_at, updated_at, deadline_at,
            envelope_json, class, features_json, assessment_json, decision_json, decided_at, grant_id, delegation_id,
            user_name, fingerprint, command_key, quiet)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
        params![
            row.id,
            row.code,
            row.host_id,
            row.envelope.client_request_id,
            row.state.as_str(),
            row.version,
            row.created_at,
            row.deadline_at,
            serde_json::to_string(&row.envelope)?,
            row.class,
            serde_json::to_string(&row.features)?,
            serde_json::to_string(&row.assessment)?,
            row.decision.as_ref().map(serde_json::to_string).transpose()?,
            row.decision.as_ref().map(|d| d.at),
            row.grant_id,
            row.delegation_id,
            row.envelope.user.name,
            row.envelope.session.fingerprint,
            row.command_key,
            row.quiet as i64,
        ],
    )?;
    Ok(())
}

fn matching_grant(
    state: &AppState,
    row: &RequestRow,
    facts: &HostFacts,
    class: &ClassConfig,
) -> anyhow::Result<Option<GrantRow>> {
    Ok(live_grants(state, "grant")?.into_iter().find(|g| {
        serde_json::from_value::<GrantSpec>(g.spec.clone())
            .is_ok_and(|spec| grants::grant_matches(&spec, &row.envelope, facts, class))
    }))
}

fn use_grant(state: &AppState, g: &GrantRow) -> anyhow::Result<()> {
    let now = now_ms();
    let db = state.db.lock();
    db.execute(
        "UPDATE grants SET uses = uses + 1, last_used_at = ?1 WHERE id = ?2",
        params![now, g.id],
    )?;
    if let Some(max) = g.max_uses
        && g.uses + 1 >= max
    {
        db.execute(
            "UPDATE grants SET paused_at = ?1, pause_reason = ?2 WHERE id = ?3 AND paused_at IS NULL",
            params![now, format!("reached its limit of {max} approvals"), g.id],
        )?;
    }
    drop(db);
    state.emit(Event::Grants);
    Ok(())
}

pub fn grant_summary(state: &AppState, g: &GrantRow) -> String {
    grant_summary_with(state, g, true)
}

pub fn grant_summary_with(state: &AppState, g: &GrantRow, with_remaining: bool) -> String {
    let remaining = g
        .expires_at
        .filter(|_| with_remaining)
        .map(|e| format!(", {} left", human_duration((e - now_ms()) / 1000)))
        .unwrap_or_default();
    if g.kind == "delegation"
        && let Ok(spec) = serde_json::from_value::<DelegationSpec>(g.spec.clone())
    {
        let hosts = match &spec.hosts {
            HostScope::Host { host_id } => host_name(state, host_id),
            HostScope::Groups { groups } => groups.join(", "),
            HostScope::All => "all hosts".into(),
        };
        let who = match &spec.requester {
            Some(RequesterScope::Session { label, .. }) => label.clone(),
            Some(RequesterScope::User { user }) => format!("user {user}"),
            None => "any requester".into(),
        };
        return format!(
            "{hosts} · {who} · risk ≤ {}{remaining}",
            spec.limits.max_risk
        );
    }
    match serde_json::from_value::<GrantSpec>(g.spec.clone()) {
        Ok(spec) => format!(
            "{}{remaining}",
            grants::describe_grant(&spec, |id| host_name(state, id))
        ),
        Err(_) => g.label.clone(),
    }
}

async fn evaluate_delegations(
    state: &Shared,
    row: &RequestRow,
    host: &HostRow,
    facts: &HostFacts<'_>,
    class: &ClassConfig,
) -> anyhow::Result<Option<(GrantRow, StoredAssessment)>> {
    if !state.automation_enabled() {
        return Ok(None);
    }
    let Some(advisor) = state.advisor.clone() else {
        return Ok(None);
    };
    let candidate = live_grants(state, "delegation")?.into_iter().find_map(|g| {
        let spec: DelegationSpec = serde_json::from_value(g.spec.clone()).ok()?;
        grants::delegation_scope_matches(&spec, &row.envelope, facts, class).then_some((g, spec))
    });
    let Some((delegation, spec)) = candidate else {
        return Ok(None);
    };
    let input = advisor_input(state, row, host, class, Some((&delegation, &spec)));
    let mut stored = StoredAssessment::default();
    let result = tokio::time::timeout(
        Duration::from_secs(advisor.config.timeout_secs.max(5)),
        advisor.assess(&input),
    )
    .await;
    let reasons = match result {
        Ok(Ok(a)) => {
            let a = advisor::clamp(
                a,
                class,
                &row.features,
                advisor.config.max_suggested_ttl_minutes,
            );
            let reasons = grants::delegation_verdict(
                &spec,
                &row.features,
                &state.cfg.policy.automation.forbidden_features,
                &a,
            );
            stored.assessment = Some(a);
            reasons
        }
        Ok(Err(e)) => {
            stored.failure = Some(AssessmentFailure {
                error: format!("{e:#}"),
                model: advisor.config.model.clone(),
                at: now_ms(),
            });
            vec![format!("the decision model failed: {e}")]
        }
        Err(_) => {
            stored.failure = Some(AssessmentFailure {
                error: "timed out".into(),
                model: advisor.config.model.clone(),
                at: now_ms(),
            });
            vec!["the decision model timed out".into()]
        }
    };
    let approved = reasons.is_empty();
    audit::record(
        &state.db,
        &format!("delegation:{}", delegation.id),
        if approved {
            "delegation.approved"
        } else {
            "delegation.declined"
        },
        Some(&row.id),
        json!({"reasons": reasons, "assessment": stored.assessment, "failure": stored.failure}),
    );
    track_declines(state, &delegation, approved);
    stored.delegation_check = Some(DelegationCheck {
        id: delegation.id.clone(),
        label: delegation.label.clone(),
        approved,
        reasons,
    });
    Ok(Some((delegation, stored)))
}

fn track_declines(state: &AppState, delegation: &GrantRow, approved: bool) {
    let limit = state.cfg.policy.automation.pause_after_declines;
    let count = {
        let mut map = state.delegation_declines.lock().unwrap();
        let entry = map.entry(delegation.id.clone()).or_insert(0);
        if approved {
            *entry = 0
        } else {
            *entry += 1
        }
        *entry
    };
    if limit > 0 && count >= limit {
        let _ = pause(
            state,
            &delegation.id,
            &format!("paused after {count} requests in a row fell outside its limits"),
            "system",
        );
        state
            .delegation_declines
            .lock()
            .unwrap()
            .remove(&delegation.id);
    }
}

pub fn pause(state: &AppState, id: &str, reason: &str, actor: &str) -> anyhow::Result<()> {
    let changed = state.db.lock().execute(
        "UPDATE grants SET paused_at = ?1, pause_reason = ?2 WHERE id = ?3 AND paused_at IS NULL AND revoked_at IS NULL",
        params![now_ms(), reason, id],
    )?;
    if changed > 0 {
        audit::record(
            &state.db,
            actor,
            "delegation.paused",
            Some(id),
            json!({"reason": reason}),
        );
        state.emit(Event::Grants);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Advisor input and background assessment

pub fn advisor_input(
    state: &AppState,
    row: &RequestRow,
    host: &HostRow,
    class: &ClassConfig,
    delegation: Option<(&GrantRow, &DelegationSpec)>,
) -> AdvisorInput {
    let env = &row.envelope;
    let cfg = state.advisor.as_ref().map(|a| a.config.clone());
    let (max_n, max_age) = cfg
        .map(|c| (c.history_max_requests, c.history_max_age_minutes))
        .unwrap_or((20, 120));
    let cutoff = now_ms() - max_age as i64 * 60_000;
    let history: Vec<RequestRow> = {
        let db = state.db.lock();
        db.prepare(
            "SELECT * FROM requests WHERE id != ?1 AND created_at > ?2 AND quiet = 0
               AND (user_name = ?3 OR command_key = ?4 OR fingerprint = ?5)
             ORDER BY created_at DESC LIMIT ?6",
        )
        .and_then(|mut stmt| {
            stmt.query_map(
                params![
                    row.id,
                    cutoff,
                    env.user.name,
                    row.command_key,
                    env.session.fingerprint,
                    max_n as i64
                ],
                row_request,
            )
            .map(|it| it.filter_map(Result::ok).collect())
        })
        .unwrap_or_default()
    };
    let now = now_ms();
    let recent_history: Vec<Value> = history
        .iter()
        .map(|h| {
            json!({
                "minutes_ago": (now - h.created_at) / 60_000,
                "host": host_name(state, &h.host_id),
                "command": sanitize::redact(&policy::display_command(&h.envelope)),
                "class": h.class,
                "outcome": h.state.as_str(),
                "decided_by": h.decision.as_ref().map(|d| d.decision.via),
                "flagged_by_human_as_mistake": h.flagged_at.is_some(),
                "same_command": h.command_key == row.command_key,
                "same_session": h.envelope.session.fingerprint == env.session.fingerprint,
            })
        })
        .collect();
    let same: Vec<&RequestRow> = history
        .iter()
        .filter(|h| h.command_key == row.command_key)
        .collect();
    let mut approved_hosts: Vec<String> = same
        .iter()
        .filter(|h| h.state == RequestState::Approved)
        .map(|h| host_name(state, &h.host_id))
        .collect();
    approved_hosts.sort();
    approved_hosts.dedup();
    let fleet_summary = json!({
        "same_command_approved_on_hosts": approved_hosts,
        "same_command_denied_count": same.iter().filter(|h| h.state == RequestState::Denied).count(),
        "requests_from_this_session": history.iter().filter(|h| h.envelope.session.fingerprint == env.session.fingerprint).count(),
        "history_window_minutes": max_age,
    });
    let active_grants: Vec<Value> = live_grants(state, "grant")
        .unwrap_or_default()
        .iter()
        .take(10)
        .map(|g| json!({"label": sanitize::redact(&g.label), "scope": grant_summary(state, g)}))
        .collect();
    let request = json!({
        "host": host.name,
        "host_groups": host.groups,
        "user": env.user.name,
        "run_as": env.target.user,
        "mode": env.mode,
        "launch": env.launch,
        "command": env.command.as_deref().map(sanitize::redact),
        "arguments": sanitize::redact_argv(&env.argv),
        "cwd": env.cwd.as_deref().map(sanitize::redact),
        "chdir": env.chdir,
        "interactive_terminal": env.interactive,
        "session": {"label": env.session.label, "agent": env.session.agent, "over_ssh": env.session.ssh},
        "process_ancestry": env.session.chain.iter().take(5).map(|p| json!({"name": p.name, "cmdline": sanitize::redact(&p.cmdline.chars().take(160).collect::<String>())})).collect::<Vec<_>>(),
    });
    AdvisorInput {
        request,
        class: json!({"name": class.name, "title": class.title, "require_each_time": class.require_each_time, "max_ttl_minutes": class.max_ttl_minutes}),
        deterministic_features: json!(row.features.0),
        recent_history,
        fleet_summary,
        active_grants,
        delegation: delegation.map(|(g, spec)| {
            json!({
                "intent": sanitize::redact(&spec.intent),
                "created_minutes_ago": (now - g.created_at) / 60_000,
                "approvals_so_far": g.uses,
                "max_risk": spec.limits.max_risk,
            })
        }),
        requester_supplied: json!({
            "context": env.untrusted.context.as_deref().map(sanitize::redact),
            "session_label": env.untrusted.session,
        }),
    }
}

pub async fn assess_in_background(state: &Shared, id: &str) {
    let Some(advisor) = state.advisor.clone() else {
        return;
    };
    let Ok(Some(row)) = request(state, id) else {
        return;
    };
    let Ok(Some(host)) = host(state, &row.host_id) else {
        return;
    };
    let class = class_named(state, &row.class);
    set_assessment(state, id, |s| s.running = true);
    let input = advisor_input(state, &row, &host, &class, None);
    let result = advisor.assess(&input).await;
    set_assessment(state, id, |s| {
        s.running = false;
        match result {
            Ok(a) => {
                s.assessment = Some(advisor::clamp(
                    a,
                    &class,
                    &row.features,
                    advisor.config.max_suggested_ttl_minutes,
                ));
                s.failure = None;
            }
            Err(e) => {
                tracing::warn!(request = id, "assessment failed: {e:#}");
                s.failure = Some(AssessmentFailure {
                    error: format!("{e:#}"),
                    model: advisor.config.model.clone(),
                    at: now_ms(),
                });
            }
        }
    });
}

fn set_assessment(state: &AppState, id: &str, f: impl FnOnce(&mut StoredAssessment)) {
    let Ok(Some(row)) = request(state, id) else {
        return;
    };
    let mut stored = row.assessment;
    f(&mut stored);
    let json = serde_json::to_string(&stored).unwrap_or_default();
    // Assessment updates bump the version so open UIs refresh, but decisions check the
    // version only for the state/scope they display, so this never races a decision
    // into a 409 for the approver unless the suggestion changed under them.
    let _ = state.db.lock().execute(
        "UPDATE requests SET assessment_json = ?1, updated_at = ?2 WHERE id = ?3",
        params![json, now_ms(), id],
    );
    state.emit(Event::Request {
        id: id.to_string(),
        state: row.state.as_str().into(),
        version: row.version,
    });
}

// ---------------------------------------------------------------------------
// Decisions

#[derive(Debug, Clone, Deserialize)]
pub struct ScopeInput {
    /// once | exact | prefix | executable
    pub command: String,
    #[serde(default)]
    pub prefix_len: Option<usize>,
    /// host | group | all
    #[serde(default = "host_scope")]
    pub hosts: String,
    #[serde(default)]
    pub groups: Vec<String>,
    /// session | user
    #[serde(default = "session_scope")]
    pub requester: String,
    #[serde(default)]
    pub ttl_minutes: u32,
}
fn host_scope() -> String {
    "host".into()
}
fn session_scope() -> String {
    "session".into()
}

#[derive(Debug, Clone, Deserialize)]
pub struct DelegateInput {
    pub intent: String,
    pub ttl_minutes: u32,
    #[serde(default = "host_scope")]
    pub hosts: String,
    #[serde(default)]
    pub groups: Vec<String>,
    /// session | user | any
    #[serde(default = "session_scope")]
    pub requester: String,
    #[serde(default)]
    pub max_risk: Option<u8>,
    #[serde(default)]
    pub notify: NotifyMode,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DecideInput {
    pub version: i64,
    /// approve | deny
    pub decision: String,
    #[serde(default)]
    pub scope: Option<ScopeInput>,
    #[serde(default)]
    pub refresh_timestamp: bool,
    #[serde(default)]
    pub hard: bool,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub delegate: Option<DelegateInput>,
}

fn host_scope_for(hosts: &str, groups: &[String], host: &HostRow) -> ApiResult<HostScope> {
    Ok(match hosts {
        "host" => HostScope::Host {
            host_id: host.id.clone(),
        },
        "group" => {
            let groups: Vec<String> = if groups.is_empty() {
                host.groups.clone()
            } else {
                groups.to_vec()
            };
            if groups.is_empty() {
                return Err(ApiError::bad_request("This host is not in any group."));
            }
            HostScope::Groups { groups }
        }
        "all" => HostScope::All,
        _ => return Err(ApiError::bad_request("Unknown host scope.")),
    })
}

fn requester_scope_for(
    requester: &str,
    env: &RequestEnvelope,
) -> ApiResult<Option<RequesterScope>> {
    Ok(match requester {
        "session" => Some(RequesterScope::Session {
            fingerprint: env.session.fingerprint.clone(),
            label: env.session.label.clone(),
        }),
        "user" => Some(RequesterScope::User {
            user: env.user.name.clone(),
        }),
        "any" => None,
        _ => return Err(ApiError::bad_request("Unknown requester scope.")),
    })
}

pub fn decide(state: &Shared, session: &Session, id: &str, input: DecideInput) -> ApiResult<Value> {
    if !session.user.can_decide() {
        return Err(ApiError::forbidden(
            "Your account can view requests but not decide them.",
        ));
    }
    let row = request(state, id)?.ok_or_else(|| ApiError::not_found("No such request."))?;
    if row.state != RequestState::Pending {
        return Err(ApiError::conflict(format!(
            "This request was already {}.",
            row.state.as_str()
        )));
    }
    if row.version != input.version {
        return Err(ApiError::conflict(
            "This request changed while you were looking at it.",
        ));
    }
    let class = class_named(state, &row.class);
    let host = host(state, &row.host_id)?.ok_or_else(|| ApiError::not_found("Unknown host."))?;
    let approve = match input.decision.as_str() {
        "approve" => true,
        "deny" => false,
        _ => return Err(ApiError::bad_request("Decision must be approve or deny.")),
    };
    let strong_minutes = state.cfg.sessions.strong_auth_minutes;
    if approve {
        match class.step_up {
            StepUp::None => {}
            StepUp::Recent => crate::auth::require_strong(state, session, Some(strong_minutes))?,
            StepUp::Always => crate::auth::require_strong(state, session, Some(1))?,
        }
        if input.refresh_timestamp || input.delegate.is_some() {
            crate::auth::require_strong(state, session, Some(strong_minutes))?;
        }
    }

    let now = now_ms();
    let mut grant_id = None;
    let mut delegation_id = None;
    let scope = input.scope.clone().unwrap_or(ScopeInput {
        command: "once".into(),
        prefix_len: None,
        hosts: "host".into(),
        groups: vec![],
        requester: "session".into(),
        ttl_minutes: 0,
    });
    let env = &row.envelope;

    if approve && scope.command != "once" {
        if class.require_each_time || class.max_ttl_minutes == 0 {
            return Err(ApiError::bad_request(format!(
                "{} requires a decision each time.",
                class.title
            )));
        }
        if env.lossy {
            return Err(ApiError::bad_request(
                "Requests with non-UTF-8 arguments cannot become standing approvals.",
            ));
        }
        let ttl = scope.ttl_minutes.clamp(1, class.max_ttl_minutes);
        let command = match scope.command.as_str() {
            "exact" => CommandScope {
                kind: CommandMatch::Exact,
                mode: Some(env.mode),
                executable: env.command.clone(),
                argv: env.argv.clone(),
            },
            "prefix" => {
                let n = scope.prefix_len.unwrap_or(1).min(env.argv.len());
                CommandScope {
                    kind: CommandMatch::Prefix,
                    mode: Some(env.mode),
                    executable: env.command.clone(),
                    argv: env.argv[..n].to_vec(),
                }
            }
            "executable" => CommandScope {
                kind: CommandMatch::Executable,
                mode: Some(env.mode),
                executable: env.command.clone(),
                argv: vec![],
            },
            _ => return Err(ApiError::bad_request("Unknown command scope.")),
        };
        if command.executable.is_none() {
            return Err(ApiError::bad_request(
                "This request has no command to grant.",
            ));
        }
        let spec = GrantSpec {
            command,
            hosts: host_scope_for(&scope.hosts, &scope.groups, &host)?,
            requester: requester_scope_for(&scope.requester, env)?
                .ok_or_else(|| ApiError::bad_request("Grants need a session or user scope."))?,
            target_uid: env.target.uid,
            refresh_timestamp: false,
        };
        let gid = new_id("grt");
        let label = policy::display_command(env)
            .chars()
            .take(120)
            .collect::<String>();
        state.db.lock().execute(
            "INSERT INTO grants (id, kind, label, spec_json, created_by, created_from_request, created_at, expires_at)
             VALUES (?1, 'grant', ?2, ?3, ?4, ?5, ?6, ?7)",
            params![gid, label, serde_json::to_string(&spec).map_err(anyhow::Error::from)?, session.user.name, row.id, now, now + ttl as i64 * 60_000],
        )?;
        audit::record(
            &state.db,
            &session.user.name,
            "grant.created",
            Some(&gid),
            json!({"spec": spec, "ttl_minutes": ttl, "request": row.id}),
        );
        grant_id = Some(gid);
    }

    if approve && let Some(del) = &input.delegate {
        if !state.automation_enabled() {
            return Err(ApiError::bad_request("Automation is switched off."));
        }
        if state.advisor.is_none() {
            return Err(ApiError::bad_request("No decision model is configured."));
        }
        let (did, _) = create_delegation(state, session, &host, Some(&row), del)?;
        delegation_id = Some(did);
    }

    let followed = row.assessment.assessment.as_ref().map(|a| {
        a.suggestion.decision == input.decision
            && (!approve || a.suggestion.command == scope.command)
    });
    let label = match &grant_id {
        Some(_) => format!("{} · {}", session.device_label, scope_words(&scope)),
        None => session.device_label.clone(),
    };
    let record = DecisionRecord {
        decision: Decision {
            state: if approve {
                RequestState::Approved
            } else {
                RequestState::Denied
            },
            via: DecidedVia::User,
            by: session.user.name.clone(),
            label,
            hard: !approve && (input.hard || class.hard_deny),
            refresh_timestamp: approve && input.refresh_timestamp,
            reason: input
                .note
                .clone()
                .filter(|n| !n.trim().is_empty())
                .map(|n| n.chars().take(500).collect()),
        },
        user_id: Some(session.user.id.clone()),
        device_id: Some(session.device_id.clone()),
        device_label: Some(session.device_label.clone()),
        auth: Some(if session.strong_within(strong_minutes) {
            "passkey".into()
        } else {
            "session".into()
        }),
        note: input.note.clone(),
        grant: grant_id.clone(),
        delegation: delegation_id.clone(),
        followed_suggestion: followed,
        at: now,
    };
    let changed = state.db.lock().execute(
        "UPDATE requests SET state = ?1, version = version + 1, updated_at = ?2, decision_json = ?3, decided_at = ?2,
            grant_id = COALESCE(?4, grant_id), delegation_id = COALESCE(?5, delegation_id)
         WHERE id = ?6 AND state = 'pending' AND version = ?7",
        params![
            record.decision.state.as_str(),
            now,
            serde_json::to_string(&record).map_err(anyhow::Error::from)?,
            grant_id,
            delegation_id,
            row.id,
            input.version
        ],
    )?;
    if changed == 0 {
        return Err(ApiError::conflict(
            "Someone else decided this request first.",
        ));
    }
    audit::record(
        &state.db,
        &session.user.name,
        if approve {
            "request.approved"
        } else {
            "request.denied"
        },
        Some(&row.id),
        json!({
            "command": policy::display_command(env),
            "host": host.name,
            "device": session.device_label,
            "scope": scope_words(&scope),
            "grant": grant_id,
            "delegation": delegation_id,
            "hard": record.decision.hard,
            "refresh_timestamp": record.decision.refresh_timestamp,
            "followed_suggestion": followed,
            "assessment_risk": row.assessment.assessment.as_ref().map(|a| a.risk),
        }),
    );
    state.emit(Event::Request {
        id: row.id.clone(),
        state: record.decision.state.as_str().into(),
        version: row.version + 1,
    });
    if grant_id.is_some() || delegation_id.is_some() {
        state.emit(Event::Grants);
    }
    let updated = request(state, &row.id)?.ok_or_else(|| ApiError::not_found("gone"))?;
    Ok(request_view(state, &updated, true))
}

fn scope_words(scope: &ScopeInput) -> String {
    let what = match scope.command.as_str() {
        "exact" => "this command",
        "prefix" => "command prefix",
        "executable" => "any arguments",
        _ => "once",
    };
    if scope.command == "once" {
        return "once".into();
    }
    let hosts = match scope.hosts.as_str() {
        "group" => "group",
        "all" => "all hosts",
        _ => "this host",
    };
    format!("{what}, {hosts}, {}m", scope.ttl_minutes)
}

pub fn create_delegation(
    state: &AppState,
    session: &Session,
    host: &HostRow,
    from: Option<&RequestRow>,
    input: &DelegateInput,
) -> ApiResult<(String, DelegationSpec)> {
    let intent = input.intent.trim();
    if intent.len() < 8 {
        return Err(ApiError::bad_request(
            "Describe the expected work in a sentence; the model uses it to judge relevance.",
        ));
    }
    let auto = &state.cfg.policy.automation;
    let ttl = input.ttl_minutes.clamp(1, auto.max_ttl_minutes);
    let requester = match (from, input.requester.as_str()) {
        (_, "any") => None,
        (Some(row), r) => requester_scope_for(r, &row.envelope)?,
        (None, "user") => Some(RequesterScope::User {
            user: session.user.name.clone(),
        }),
        (None, _) => None,
    };
    let mut limits = auto.default_limits.clone();
    if let Some(r) = input.max_risk {
        limits.max_risk = r.min(60);
    }
    if limits.max_risk > 60 {
        limits.max_risk = 60;
    }
    let spec = DelegationSpec {
        intent: intent.chars().take(600).collect(),
        hosts: host_scope_for(&input.hosts, &input.groups, host)?,
        requester,
        target_uids: from
            .map(|r| vec![r.envelope.target.uid])
            .unwrap_or_default(),
        classes: vec![],
        limits,
        notify: input.notify,
    };
    let id = new_id("dlg");
    let now = now_ms();
    let label = if intent.chars().count() <= 80 {
        intent.to_string()
    } else {
        let cut: String = intent.chars().take(79).collect();
        let cut = cut.rsplit_once(' ').map(|(head, _)| head).unwrap_or(&cut);
        format!("{}…", cut.trim_end_matches([',', '.', ';', ':']))
    };
    state.db.lock().execute(
        "INSERT INTO grants (id, kind, label, spec_json, created_by, created_from_request, created_at, expires_at, max_uses)
         VALUES (?1, 'delegation', ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![id, label, serde_json::to_string(&spec).map_err(anyhow::Error::from)?, session.user.name, from.map(|r| r.id.clone()), now, now + ttl as i64 * 60_000, auto.max_decisions as i64],
    )?;
    audit::record(
        &state.db,
        &session.user.name,
        "delegation.created",
        Some(&id),
        json!({"spec": spec, "ttl_minutes": ttl, "device": session.device_label}),
    );
    state.emit(Event::Grants);
    Ok((id, spec))
}

/// A human marks an automated approval as a mistake: pause the delegation.
pub fn flag(state: &AppState, session: &Session, id: &str) -> ApiResult<()> {
    let row = request(state, id)?.ok_or_else(|| ApiError::not_found("No such request."))?;
    let Some(delegation) = row.delegation_id.clone().filter(|_| {
        row.decision
            .as_ref()
            .is_some_and(|d| d.decision.via == DecidedVia::Delegation)
    }) else {
        return Err(ApiError::bad_request(
            "Only automated approvals can be flagged.",
        ));
    };
    state.db.lock().execute(
        "UPDATE requests SET flagged_at = ?1, version = version + 1 WHERE id = ?2",
        params![now_ms(), id],
    )?;
    pause(
        state,
        &delegation,
        &format!("{} flagged an automated approval", session.user.name),
        &session.user.name,
    )?;
    audit::record(
        &state.db,
        &session.user.name,
        "request.flagged",
        Some(id),
        json!({"delegation": delegation}),
    );
    state.emit(Event::Request {
        id: id.to_string(),
        state: row.state.as_str().into(),
        version: row.version + 1,
    });
    Ok(())
}

// ---------------------------------------------------------------------------
// Host-side waiting and cancellation

pub fn decision_response(row: &RequestRow) -> DecisionResponse {
    DecisionResponse {
        id: row.id.clone(),
        state: row.state,
        decision: row.decision.as_ref().map(|d| d.decision.clone()),
    }
}

pub async fn wait_decision(
    state: &Shared,
    host_id: &str,
    id: &str,
    wait: Duration,
) -> anyhow::Result<Option<DecisionResponse>> {
    let mut rx = state.events.subscribe();
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let Some(row) = request(state, id)? else {
            return Ok(None);
        };
        if row.host_id != host_id {
            return Ok(None);
        }
        if row.state.is_final() {
            return Ok(Some(decision_response(&row)));
        }
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Err(_) => return Ok(Some(decision_response(&row))),
            Ok(Ok(Event::Request { id: ev, .. })) if ev != id => {}
            Ok(_) => {}
        }
    }
}

pub fn cancel(
    state: &Shared,
    host: &HostRow,
    id: &str,
    reason: &str,
) -> anyhow::Result<Option<DecisionResponse>> {
    let Some(row) = request(state, id)? else {
        return Ok(None);
    };
    if row.host_id != host.id {
        return Ok(None);
    }
    if row.state.is_final() {
        return Ok(Some(decision_response(&row)));
    }
    let label = match reason {
        "password" => "authenticated locally with a password",
        "timeout" => "the command stopped waiting",
        "client disconnected" | "cancelled" => "the command was interrupted",
        _ => reason,
    };
    let mut d = automatic_decision(
        RequestState::Withdrawn,
        DecidedVia::Policy,
        &host.name,
        label,
    );
    d.decision.reason = Some(reason.chars().take(200).collect());
    let now = now_ms();
    state.db.lock().execute(
        "UPDATE requests SET state = 'withdrawn', version = version + 1, updated_at = ?1, decided_at = ?1, decision_json = ?2
         WHERE id = ?3 AND state = 'pending'",
        params![now, serde_json::to_string(&d)?, id],
    )?;
    audit::record(
        &state.db,
        &format!("host:{}", host.name),
        "request.withdrawn",
        Some(id),
        json!({"reason": reason}),
    );
    state.emit(Event::Request {
        id: id.to_string(),
        state: "withdrawn".into(),
        version: row.version + 1,
    });
    Ok(request(state, id)?.map(|r| decision_response(&r)))
}

/// Expire pending requests whose deadline has passed.
pub fn expire_due(state: &AppState) -> anyhow::Result<usize> {
    let now = now_ms();
    let due: Vec<(String, i64)> = {
        let db = state.db.lock();
        let mut stmt = db.prepare(
            "SELECT id, version FROM requests WHERE state = 'pending' AND deadline_at <= ?",
        )?;
        stmt.query_map([now], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<Vec<_>, _>>()?
    };
    for (id, version) in &due {
        let mut d = automatic_decision(
            RequestState::Expired,
            DecidedVia::Policy,
            "policy",
            "no decision in time",
        );
        d.decision.reason = Some("no decision before the deadline".into());
        state.db.lock().execute(
            "UPDATE requests SET state = 'expired', version = version + 1, updated_at = ?1, decided_at = ?1, decision_json = ?2
             WHERE id = ?3 AND state = 'pending'",
            params![now, serde_json::to_string(&d)?, id],
        )?;
        audit::record(&state.db, "system", "request.expired", Some(id), json!({}));
        state.emit(Event::Request {
            id: id.clone(),
            state: "expired".into(),
            version: version + 1,
        });
    }
    Ok(due.len())
}

pub fn spawn_background(state: Shared) {
    let s = state.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(2));
        loop {
            tick.tick().await;
            if let Err(e) = expire_due(&s) {
                tracing::warn!("expiry sweep: {e:#}");
            }
        }
    });
    let s = state.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(600));
        tick.tick().await;
        loop {
            tick.tick().await;
            send_digests(&s).await;
            let cutoff = now_ms() - 120_000;
            s.nonces.lock().unwrap().retain(|_, at| *at > cutoff);
        }
    });
}

// ---------------------------------------------------------------------------
// Notifications

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n - 1).collect::<String>())
    }
}

pub async fn notify_pending(state: &Shared, row: &RequestRow) {
    if !state.push.enabled() {
        return;
    }
    let Ok(subs) = push::subscriptions_for_approvers(&state.db) else {
        return;
    };
    if subs.is_empty() {
        return;
    }
    let class = class_named(state, &row.class);
    let env = &row.envelope;
    let host = host_name(state, &row.host_id);
    let who = env
        .session
        .agent
        .clone()
        .unwrap_or_else(|| env.user.name.clone());
    let mut body = truncate(&policy::display_command(env), 140);
    if let Some(ctx) = env.untrusted.context.as_deref() {
        body.push('\n');
        body.push_str(&truncate(ctx, 120));
    }
    let payload = json!({
        "t": "request",
        "id": row.id,
        "v": row.version,
        "code": row.code,
        "title": format!("{who} on {host} wants sudo"),
        "body": body,
        "quick": class.quick_approve && class.step_up == StepUp::None,
        "danger": row.features.0.iter().any(|f| f.level == "danger"),
        "url": format!("/r/{}", row.id),
    });
    let ttl = ((row.deadline_at - now_ms()) / 1000).clamp(30, 3600) as u32;
    let topic = row
        .id
        .replace('_', "")
        .chars()
        .rev()
        .take(30)
        .collect::<String>();
    push::fan_out(&state.push, &state.db, subs, &payload, ttl, Some(&topic)).await;
}

async fn notify_automated(state: &Shared, row: &RequestRow, delegation: &GrantRow) {
    let spec: Option<DelegationSpec> = serde_json::from_value(delegation.spec.clone()).ok();
    let mode = spec.map(|s| s.notify).unwrap_or_default();
    let host = host_name(state, &row.host_id);
    match mode {
        NotifyMode::Silent => {}
        NotifyMode::Digest => {
            state
                .digests
                .lock()
                .unwrap()
                .entry(delegation.id.clone())
                .or_default()
                .push(format!(
                    "{host}: {}",
                    truncate(&policy::display_command(&row.envelope), 60)
                ));
        }
        NotifyMode::Each => {
            let Ok(subs) = push::subscriptions_for_approvers(&state.db) else {
                return;
            };
            let payload = json!({
                "t": "auto",
                "id": row.id,
                "delegation": delegation.id,
                "title": format!("Approved automatically on {host}"),
                "body": format!("{}\n{}", truncate(&policy::display_command(&row.envelope), 120), truncate(&delegation.label, 80)),
                "url": format!("/r/{}", row.id),
            });
            push::fan_out(&state.push, &state.db, subs, &payload, 600, None).await;
        }
    }
}

async fn send_digests(state: &Shared) {
    let pending: BTreeMap<String, Vec<String>> =
        std::mem::take(&mut *state.digests.lock().unwrap())
            .into_iter()
            .collect();
    for (id, items) in pending {
        if items.is_empty() {
            continue;
        }
        let label = grant(state, &id)
            .ok()
            .flatten()
            .map(|g| g.label)
            .unwrap_or_default();
        let Ok(subs) = push::subscriptions_for_approvers(&state.db) else {
            return;
        };
        let payload = json!({
            "t": "digest",
            "delegation": id,
            "title": format!("{} automated approval{}", items.len(), if items.len() == 1 { "" } else { "s" }),
            "body": format!("{}\n{}", truncate(&label, 80), items.iter().take(3).cloned().collect::<Vec<_>>().join("\n")),
            "url": "/activity",
        });
        push::fan_out(&state.push, &state.db, subs, &payload, 3600, None).await;
    }
}

pub fn quick_counts(state: &AppState) -> anyhow::Result<Value> {
    let db = state.db.lock();
    let pending: i64 = db.query_row(
        "SELECT COUNT(*) FROM requests WHERE state = 'pending'",
        [],
        |r| r.get(0),
    )?;
    let day = now_ms() - 86_400_000;
    let (approved, denied, automated): (i64, i64, i64) = db.query_row(
        "SELECT
            COALESCE(SUM(state = 'approved'), 0),
            COALESCE(SUM(state = 'denied'), 0),
            COALESCE(SUM(delegation_id IS NOT NULL AND state = 'approved'), 0)
         FROM requests WHERE created_at > ? AND quiet = 0",
        [day],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    Ok(
        json!({"pending": pending, "approved_24h": approved, "denied_24h": denied, "automated_24h": automated}),
    )
}

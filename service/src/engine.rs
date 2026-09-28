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
    DecidedVia, Decision, DecisionResponse, Mode, RequestEnvelope, RequestState, SubmitResponse,
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
    /// The delegation that decided, or the narrowest one that declined.
    pub delegation_check: Option<DelegationCheck>,
    /// Every delegation whose scope matched, narrowest first.
    #[serde(default)]
    pub delegation_checks: Vec<DelegationCheck>,
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
    /// How well the request fit this delegation's kind of work (0..1).
    #[serde(default)]
    pub relevance: Option<f32>,
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
        "host": host.as_ref().map(|h| json!({"id": h.id, "name": h.name, "groups": h.groups, "default_group": default_group(state, h)})),
        "user": env.user.name,
        "target": env.target.user,
        "target_uid": env.target.uid,
        "mode": env.mode,
        "launch": env.launch,
        "command": env.command,
        "argv": env.argv,
        "display": policy::display_command(env),
        "cwd": env.cwd,
        "chdir": env.chdir.as_deref().map(sanitize::redact),
        "tty": env.tty,
        "interactive": env.interactive,
        "nonblocking": env.nonblocking,
        "lossy": env.lossy,
        "env": env.env,
        "executable": env.executable,
        "paths": env.paths,
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
        if row.state == RequestState::Pending
            && let Some(h) = &host
            && let Some((g, spec)) = widen_candidate(state, row, h)
        {
            v["widen"] = json!({
                "id": g.id,
                "label": g.label,
                "intent": spec.intent,
                "covers": grants::describe_commands(&spec.commands),
                "summary": grant_summary(state, &g),
                "paused": g.paused_at.is_some() || g.max_uses.is_some_and(|m| g.uses >= m),
                "expires_at": g.expires_at,
                "max_risk": spec.limits.max_risk,
            });
        }
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
    } else if let Some((winner, stored)) =
        evaluate_delegations(state, &row, host, &facts, &class).await?
    {
        row.assessment = stored;
        if let Some(delegation) = winner {
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

/// Find a matching grant and claim one use of it atomically.
fn matching_grant(
    state: &AppState,
    row: &RequestRow,
    facts: &HostFacts,
    class: &ClassConfig,
) -> anyhow::Result<Option<GrantRow>> {
    for g in live_grants(state, "grant")? {
        let matches = serde_json::from_value::<GrantSpec>(g.spec.clone()).is_ok_and(|spec| {
            grants::grant_matches(&spec, &row.envelope, &row.features, facts, class)
        });
        if matches && claim_use(state, &g)? {
            return Ok(Some(g));
        }
    }
    Ok(None)
}

/// Count one use of a grant or delegation, but only if it is still live. Returns
/// false when it was revoked, paused, expired or used up since it was read.
fn claim_use(state: &AppState, g: &GrantRow) -> anyhow::Result<bool> {
    let now = now_ms();
    let db = state.db.lock();
    let changed = db.execute(
        "UPDATE grants SET uses = uses + 1, last_used_at = ?1
         WHERE id = ?2 AND revoked_at IS NULL AND paused_at IS NULL
           AND (expires_at IS NULL OR expires_at > ?1)
           AND (max_uses IS NULL OR uses < max_uses)",
        params![now, g.id],
    )?;
    if changed == 1 {
        db.execute(
            "UPDATE grants SET paused_at = ?1, pause_reason = 'reached its approval limit'
             WHERE id = ?2 AND paused_at IS NULL AND max_uses IS NOT NULL AND uses >= max_uses",
            params![now, g.id],
        )?;
    }
    drop(db);
    state.emit(Event::Grants);
    Ok(changed == 1)
}

/// Claim one automatic approval for a delegation: it must still be live and within
/// its 24-hour budget. Returns why not, if not.
fn claim_delegation_use(
    state: &AppState,
    g: &GrantRow,
    spec: &DelegationSpec,
) -> anyhow::Result<Option<String>> {
    let per_day = spec
        .per_day
        .unwrap_or(state.cfg.policy.automation.max_decisions_per_day);
    let now = now_ms();
    // Count and claim under one lock, so concurrent requests can't both take the
    // last approval of the day.
    let claimed = {
        let db = state.db.lock();
        if per_day > 0 {
            let used: i64 = db.query_row(
                "SELECT COUNT(*) FROM requests WHERE delegation_id = ?1 AND state = 'approved'
                   AND decided_at > ?2 AND json_extract(decision_json, '$.decision.via') = 'delegation'",
                params![g.id, now - 86_400_000],
                |r| r.get(0),
            )?;
            if used >= per_day as i64 {
                return Ok(Some(format!(
                    "it already approved {per_day} requests in the last 24 hours"
                )));
            }
        }
        let changed = db.execute(
            "UPDATE grants SET uses = uses + 1, last_used_at = ?1
             WHERE id = ?2 AND revoked_at IS NULL AND paused_at IS NULL
               AND (expires_at IS NULL OR expires_at > ?1)
               AND (max_uses IS NULL OR uses < max_uses)",
            params![now, g.id],
        )?;
        if changed == 1 {
            db.execute(
                "UPDATE grants SET paused_at = ?1, pause_reason = 'reached its approval limit'
                 WHERE id = ?2 AND paused_at IS NULL AND max_uses IS NOT NULL AND uses >= max_uses",
                params![now, g.id],
            )?;
        }
        changed == 1
    };
    state.emit(Event::Grants);
    Ok((!claimed).then(|| "it stopped while the model was deciding".into()))
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
            "{} · {hosts} · {who} · risk ≤ {}{remaining}",
            grants::describe_commands(&spec.commands),
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

/// Live delegations whose deterministic scope covers this request, narrowest first.
fn candidate_delegations(
    state: &AppState,
    row: &RequestRow,
    facts: &HostFacts,
    class: &ClassConfig,
) -> anyhow::Result<Vec<(GrantRow, DelegationSpec)>> {
    let mut found: Vec<(GrantRow, DelegationSpec)> = live_grants(state, "delegation")?
        .into_iter()
        .filter_map(|g| {
            let spec: DelegationSpec = serde_json::from_value(g.spec.clone()).ok()?;
            grants::delegation_scope_matches(&spec, &row.envelope, facts, class)
                .then_some((g, spec))
        })
        .collect();
    found.sort_by_key(|(g, spec)| (grants::delegation_specificity(spec), -g.created_at));
    found.truncate(5);
    Ok(found)
}

pub fn clamp_context<'a>(
    state: &AppState,
    row: &'a RequestRow,
    class: &'a ClassConfig,
) -> advisor::ClampContext<'a> {
    advisor::ClampContext {
        class,
        features: &row.features,
        env: &row.envelope,
        max_suggested_ttl: state
            .advisor
            .as_ref()
            .map(|a| a.config.max_suggested_ttl_minutes)
            .unwrap_or(120),
    }
}

/// Ask the model once about every delegation that could cover this request, then
/// apply each one's deterministic limits, narrowest first. The first that passes and
/// can claim a use approves.
async fn evaluate_delegations(
    state: &Shared,
    row: &RequestRow,
    host: &HostRow,
    facts: &HostFacts<'_>,
    class: &ClassConfig,
) -> anyhow::Result<Option<(Option<GrantRow>, StoredAssessment)>> {
    if !state.automation_enabled() {
        return Ok(None);
    }
    let Some(advisor) = state.advisor.clone() else {
        return Ok(None);
    };
    let candidates = candidate_delegations(state, row, facts, class)?;
    if candidates.is_empty() {
        return Ok(None);
    }
    let input = advisor_input(state, row, host, class, &candidates);
    let mut stored = StoredAssessment::default();
    let result = tokio::time::timeout(
        Duration::from_secs(advisor.config.timeout_secs.max(5)),
        advisor.assess(&input),
    )
    .await;
    let failure = match result {
        Ok(Ok(a)) => {
            stored.assessment = Some(advisor::clamp(a, &clamp_context(state, row, class)));
            None
        }
        Ok(Err(e)) => {
            stored.failure = Some(AssessmentFailure {
                error: format!("{e:#}"),
                model: advisor.config.model.clone(),
                at: now_ms(),
            });
            Some(format!("the decision model failed: {e}"))
        }
        Err(_) => {
            stored.failure = Some(AssessmentFailure {
                error: "timed out".into(),
                model: advisor.config.model.clone(),
                at: now_ms(),
            });
            Some("the decision model timed out".into())
        }
    };

    let mut winner: Option<GrantRow> = None;
    // Whether the narrowest rule turned the request away on the model's judgement or
    // its limits, as opposed to its budget, the kill switch or a model failure.
    let mut narrowest_verdict_declined = false;
    for (i, (g, spec)) in candidates.iter().enumerate() {
        let relevance = stored
            .assessment
            .as_ref()
            .and_then(|a| a.relevance_by.get(&g.id).copied());
        let mut reasons = match (&stored.assessment, &failure) {
            (Some(a), None) if winner.is_none() => grants::delegation_verdict(
                spec,
                &row.features,
                &state.cfg.policy.automation.forbidden_features,
                a,
                relevance,
            ),
            (_, Some(f)) => vec![f.clone()],
            _ => vec!["a narrower delegation approved it".into()],
        };
        if i == 0 && failure.is_none() && !reasons.is_empty() {
            narrowest_verdict_declined = true;
        }
        let mut approved = false;
        if winner.is_none() && reasons.is_empty() {
            // The model call took time: re-check the kill switch and claim a use
            // atomically, so a pause, revoke, expiry or budget in the meantime wins.
            if !state.automation_enabled() {
                reasons.push("automation was switched off while the model was deciding".into());
            } else if let Some(why) = claim_delegation_use(state, g, spec)? {
                reasons.push(why);
            } else {
                approved = true;
                winner = Some(g.clone());
            }
        }
        stored.delegation_checks.push(DelegationCheck {
            id: g.id.clone(),
            label: g.label.clone(),
            approved,
            reasons,
            relevance,
        });
    }
    stored.delegation_check = stored
        .delegation_checks
        .iter()
        .find(|c| c.approved)
        .or_else(|| stored.delegation_checks.first())
        .cloned();

    // Only the narrowest candidate's streak counts: a broad rule is not paused by
    // requests a narrower rule owns.
    if let Some((first, _)) = candidates.first() {
        match &winner {
            Some(w) if w.id == first.id => track_declines(state, first, true),
            None if narrowest_verdict_declined => track_declines(state, first, false),
            _ => {}
        }
    }
    let decided = winner.is_some();
    for check in &stored.delegation_checks {
        // Rules behind the one that approved were never really consulted.
        if decided
            && !check.approved
            && check
                .reasons
                .iter()
                .any(|r| r.contains("narrower delegation"))
        {
            continue;
        }
        audit::record(
            &state.db,
            &format!("delegation:{}", check.id),
            if check.approved {
                "delegation.approved"
            } else {
                "delegation.declined"
            },
            Some(&row.id),
            json!({"reasons": check.reasons, "relevance": check.relevance,
                   "assessment": stored.assessment, "failure": stored.failure}),
        );
    }
    Ok(Some((winner, stored)))
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
    delegations: &[(GrantRow, DelegationSpec)],
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
        "arguments": sanitize::redact_argv(env.command.as_deref(), &env.argv),
        "cwd": env.cwd.as_deref().map(sanitize::redact),
        "chdir": env.chdir,
        "interactive_terminal": env.interactive,
        "session": {"label": sanitize::redact(&env.session.label), "agent": env.session.agent, "over_ssh": env.session.ssh},
        "process_ancestry": env.session.chain.iter().take(5).map(|p| json!({"name": p.name, "cmdline": sanitize::redact(&p.cmdline.chars().take(160).collect::<String>())})).collect::<Vec<_>>(),
    });
    AdvisorInput {
        request,
        class: json!({"name": class.name, "title": class.title, "require_each_time": class.require_each_time, "max_ttl_minutes": class.max_ttl_minutes}),
        deterministic_features: json!(row.features.0),
        recent_history,
        fleet_summary,
        active_grants,
        delegations: delegations
            .iter()
            .map(|(g, spec)| {
                (
                    g.id.clone(),
                    json!({
                        "intent": sanitize::redact(&spec.intent),
                        "covers": grants::describe_commands(&spec.commands),
                        "created_minutes_ago": (now - g.created_at) / 60_000,
                        "approvals_so_far": g.uses,
                    }),
                )
            })
            .collect(),
        requester_supplied: json!({
            "context": env.untrusted.context.as_deref().map(sanitize::redact),
            "session_label": env.untrusted.session.as_deref().map(sanitize::redact),
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
    let input = advisor_input(state, &row, &host, &class, &[]);
    let result = advisor.assess(&input).await;
    set_assessment(state, id, |s| {
        s.running = false;
        match result {
            Ok(a) => {
                s.assessment = Some(advisor::clamp(a, &clamp_context(state, &row, &class)));
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
    notify_suggestion(state, id).await;
}

fn set_assessment(state: &AppState, id: &str, f: impl FnOnce(&mut StoredAssessment)) {
    let Ok(Some(row)) = request(state, id) else {
        return;
    };
    let mut stored = row.assessment;
    f(&mut stored);
    let json = serde_json::to_string(&stored).unwrap_or_default();
    // Assessment updates don't bump the version, so a decision made while the model
    // was still thinking isn't refused. Open pages refresh from the event instead,
    // and `apply_suggestion` checks which assessment the approver saw.
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

#[derive(Debug, Clone, Deserialize, Default)]
pub struct DelegateInput {
    pub intent: String,
    /// 0 means no expiry (subject to `automation.max_ttl_minutes`).
    #[serde(default)]
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
    /// For delegations created outside a request with requester "user".
    #[serde(default)]
    pub unix_user: Option<String>,
    /// Which commands a delegation made from a request covers: program (default),
    /// prefix, exact, or any.
    #[serde(default)]
    pub filter: Option<String>,
    #[serde(default)]
    pub prefix_len: Option<usize>,
    /// For delegations created outside a request: absolute program paths it covers.
    /// Empty means any program.
    #[serde(default)]
    pub programs: Vec<String>,
    /// Widen this existing delegation instead of creating another one.
    #[serde(default)]
    pub widen: Option<String>,
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
    /// Approve with the decision model's suggestion, built on the server (used by the
    /// notification action). Explicit `scope` and `delegate` are ignored.
    #[serde(default)]
    pub apply_suggestion: bool,
    /// The `created_at` of the assessment whose suggestion the approver saw.
    #[serde(default)]
    pub suggestion_at: Option<i64>,
}

/// The group a "group" scope means by default: the host's smallest group. A group
/// that every host shares (say "all") would silently widen a "group" approval to the
/// whole fleet, so the most specific one wins.
pub fn default_group(state: &AppState, host: &HostRow) -> Option<String> {
    let all = hosts(state).unwrap_or_default();
    host.groups
        .iter()
        .min_by_key(|g| all.iter().filter(|h| h.groups.contains(g)).count())
        .cloned()
}

fn host_scope_for(
    state: &AppState,
    hosts: &str,
    groups: &[String],
    host: &HostRow,
) -> ApiResult<HostScope> {
    Ok(match hosts {
        "host" => HostScope::Host {
            host_id: host.id.clone(),
        },
        "group" => {
            let groups: Vec<String> = if groups.is_empty() {
                default_group(state, host).into_iter().collect()
            } else if host.id.is_empty() {
                // A delegation made outside a request names its groups directly.
                groups.to_vec()
            } else {
                // From a request: only groups the requesting host is in.
                groups
                    .iter()
                    .filter(|g| host.groups.contains(g))
                    .cloned()
                    .collect()
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
        if input.refresh_timestamp {
            crate::auth::require_strong(state, session, Some(strong_minutes))?;
        }
    }
    let mut input = input;
    if approve && input.apply_suggestion {
        let seen = row.assessment.assessment.as_ref().map(|a| a.created_at);
        if input.suggestion_at.is_some() && input.suggestion_at != seen {
            return Err(ApiError::conflict(
                "The suggestion changed after the notification was sent.",
            ));
        }
        let (scope, delegate) = suggested_decision(state, &row, &host, &class)?;
        input.scope = scope;
        input.delegate = delegate;
    }

    let now = now_ms();
    let mut grant_new: Option<(String, String, GrantSpec, u32)> = None;
    let mut delegation_new: Option<PreparedDelegation> = None;
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
        if !grants::grantable(env, &row.features) {
            return Err(ApiError::bad_request(
                "This request can only be approved once: what it runs could change after approval.",
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
            hosts: host_scope_for(state, &scope.hosts, &scope.groups, &host)?,
            requester: requester_scope_for(&scope.requester, env)?
                .ok_or_else(|| ApiError::bad_request("Grants need a session or user scope."))?,
            target_uid: env.target.uid,
            refresh_timestamp: false,
            target_gid: Some(env.target.gid),
            launch: env.launch,
            chdir: env.chdir.clone(),
            env: env.env.clone(),
        };
        let label = grant_label(env, &spec.command);
        grant_new = Some((new_id("grt"), label, spec, ttl));
    }

    let mut widening: Option<PreparedWiden> = None;
    if approve && let Some(del) = &input.delegate {
        if !state.automation_enabled() {
            return Err(ApiError::bad_request("Automation is switched off."));
        }
        if state.advisor.is_none() {
            return Err(ApiError::bad_request("No decision model is configured."));
        }
        let needs_passkey = if let Some(target) = &del.widen {
            // Only a rule whose hosts, requester and target already cover this request
            // can be widened by it, so widening never moves a rule away from its owner.
            if !widen_covers(state, &row, &host, &class, target) {
                return Err(ApiError::bad_request(
                    "That delegation can't be widened from this request.",
                ));
            }
            let w = prepare_widen(state, &host, &row, target, del)?;
            let needs = w.needs_passkey;
            widening = Some(w);
            needs
        } else {
            let d = prepare_delegation(state, &host, Some(&row), del)?;
            let needs = delegation_needs_passkey(state, &d.spec, d.ttl);
            delegation_new = Some(d);
            needs
        };
        if needs_passkey {
            crate::auth::require_strong(state, session, Some(strong_minutes))?;
        }
    }
    let grant_id = grant_new.as_ref().map(|g| g.0.clone());
    let delegation_id = delegation_new
        .as_ref()
        .map(|d| d.id.clone())
        .or_else(|| widening.as_ref().map(|w| w.id.clone()));

    let followed = row.assessment.assessment.as_ref().map(|a| {
        let chosen = match &input.delegate {
            Some(d) if approve => d.filter.clone().unwrap_or_else(|| "program".into()),
            _ => match scope.command.as_str() {
                "executable" => "program".into(),
                c => c.to_string(),
            },
        };
        a.suggestion.decision == input.decision && (!approve || a.suggestion.remember == chosen)
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
    // Claim the request and create any grant or delegation in one transaction, so a
    // decision that lost a race leaves nothing behind.
    {
        let mut conn = state.db.lock();
        let tx = conn.transaction()?;
        let changed = tx.execute(
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
        if let Some((gid, label, spec, ttl)) = &grant_new {
            tx.execute(
                "INSERT INTO grants (id, kind, label, spec_json, created_by, created_from_request, created_at, expires_at)
                 VALUES (?1, 'grant', ?2, ?3, ?4, ?5, ?6, ?7)",
                params![gid, label, serde_json::to_string(spec).map_err(anyhow::Error::from)?, session.user.name, row.id, now, now + *ttl as i64 * 60_000],
            )?;
        }
        if let Some(d) = &delegation_new {
            insert_delegation(&tx, session, d)?;
        }
        if let Some(w) = &widening {
            let changed = tx.execute(
                "UPDATE grants SET spec_json = ?1, label = ?2, expires_at = ?3,
                    paused_at = CASE WHEN ?4 THEN NULL ELSE paused_at END,
                    pause_reason = CASE WHEN ?4 THEN NULL ELSE pause_reason END,
                    max_uses = CASE WHEN ?4 AND max_uses IS NOT NULL AND uses >= max_uses THEN NULL ELSE max_uses END
                 WHERE id = ?5 AND kind = 'delegation' AND revoked_at IS NULL",
                params![
                    serde_json::to_string(&w.after).map_err(anyhow::Error::from)?,
                    w.label,
                    w.expires_at,
                    w.resume,
                    w.id
                ],
            )?;
            if changed == 0 {
                return Err(ApiError::conflict(
                    "That delegation was revoked while you were deciding.",
                ));
            }
        }
        tx.commit()?;
    }
    if let Some(w) = &widening {
        if w.resume {
            state.delegation_declines.lock().unwrap().remove(&w.id);
        }
        audit::record(
            &state.db,
            &session.user.name,
            "delegation.widened",
            Some(&w.id),
            json!({"before": w.before, "after": w.after, "expires_at": w.expires_at,
                   "resumed": w.resume, "device": session.device_label, "request": row.id}),
        );
    }
    if let Some((gid, _, spec, ttl)) = &grant_new {
        audit::record(
            &state.db,
            &session.user.name,
            "grant.created",
            Some(gid),
            json!({"spec": spec, "ttl_minutes": ttl, "request": row.id}),
        );
    }
    if let Some(d) = &delegation_new {
        audit::record(
            &state.db,
            &session.user.name,
            "delegation.created",
            Some(&d.id),
            json!({"spec": d.spec, "ttl_minutes": (d.ttl > 0).then_some(d.ttl), "device": session.device_label, "request": row.id}),
        );
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

/// What a grant covers, in command form: the label must not suggest a grant is
/// narrower than it is.
fn grant_label(env: &RequestEnvelope, command: &CommandScope) -> String {
    let mut shown = env.clone();
    shown.argv = command.argv.clone();
    let line = policy::display_command(&shown);
    let line = match command.kind {
        CommandMatch::Exact => line,
        CommandMatch::Prefix => format!("{line} …"),
        CommandMatch::Executable => format!("{line} (any arguments)"),
        CommandMatch::Any => "any command".into(),
    };
    line.chars().take(120).collect()
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

pub struct PreparedDelegation {
    pub id: String,
    pub label: String,
    pub spec: DelegationSpec,
    /// Minutes; 0 means no expiry.
    pub ttl: u32,
    pub max_uses: u32,
    pub from_request: Option<String>,
    pub created_at: i64,
}

pub fn prepare_delegation(
    state: &AppState,
    host: &HostRow,
    from: Option<&RequestRow>,
    input: &DelegateInput,
) -> ApiResult<PreparedDelegation> {
    let intent = input.intent.trim();
    if intent.chars().count() < 8 {
        return Err(ApiError::bad_request(
            "Describe the kind of work in a few words; the model judges requests against it.",
        ));
    }
    let auto = &state.cfg.policy.automation;
    let ttl = delegation_ttl(state, input.ttl_minutes);
    let requester = match (from, input.requester.as_str()) {
        (_, "any") => None,
        (Some(row), r) => requester_scope_for(r, &row.envelope)?,
        // Without a source request, "user" must name the unix user explicitly.
        (None, "user") => match input
            .unix_user
            .as_deref()
            .map(str::trim)
            .filter(|u| !u.is_empty())
        {
            Some(user) => Some(RequesterScope::User {
                user: user.to_string(),
            }),
            None => {
                return Err(ApiError::bad_request(
                    "Name the unix user this delegation covers.",
                ));
            }
        },
        (None, _) => {
            return Err(ApiError::bad_request(
                "A delegation that is not created from a request covers a unix user or any requester.",
            ));
        }
    };
    let mut limits = auto.default_limits.clone();
    if let Some(r) = input.max_risk {
        limits.max_risk = r;
    }
    limits.max_risk = limits.max_risk.min(60);
    let commands = delegation_commands(from, input)?;
    // Who wrote the intent: the model's accepted draft, the policy template, or the
    // approver. The requester's own explanation is never offered as a draft.
    let intent_source = from
        .and_then(|r| r.assessment.assessment.as_ref())
        .filter(|a| a.suggestion.intent == intent)
        .map(|a| a.suggestion.intent_source)
        .unwrap_or(grants::IntentSource::Approver);
    let spec = DelegationSpec {
        intent: intent.chars().take(600).collect(),
        intent_source,
        commands,
        per_day: None,
        hosts: host_scope_for(state, &input.hosts, &input.groups, host)?,
        requester,
        target_uids: from
            .map(|r| vec![r.envelope.target.uid])
            .unwrap_or_default(),
        classes: vec![],
        limits,
        notify: input.notify,
    };
    Ok(PreparedDelegation {
        id: new_id("dlg"),
        label: delegation_label(intent),
        spec,
        ttl,
        max_uses: auto.max_decisions,
        from_request: from.map(|r| r.id.clone()),
        created_at: now_ms(),
    })
}

fn delegation_label(intent: &str) -> String {
    if intent.chars().count() <= 80 {
        intent.to_string()
    } else {
        let cut: String = intent.chars().take(79).collect();
        let cut = cut.rsplit_once(' ').map(|(head, _)| head).unwrap_or(&cut);
        format!("{}…", cut.trim_end_matches([',', '.', ';', ':']))
    }
}

/// Minutes a new delegation lasts: 0 means no expiry; the operator's
/// `max_ttl_minutes` (0 = none) caps both.
fn delegation_ttl(state: &AppState, requested: u32) -> u32 {
    match (requested, state.cfg.policy.automation.max_ttl_minutes) {
        (0, max) => max,
        (t, 0) => t,
        (t, max) => t.min(max),
    }
}

/// The command filter for a new delegation.
fn delegation_commands(
    from: Option<&RequestRow>,
    input: &DelegateInput,
) -> ApiResult<Vec<CommandScope>> {
    let Some(row) = from else {
        return input
            .programs
            .iter()
            .map(|p| p.trim())
            .filter(|p| !p.is_empty())
            .map(|p| {
                if !p.starts_with('/') || p.contains(char::is_whitespace) {
                    return Err(ApiError::bad_request(
                        "Programs are absolute paths, like /usr/bin/apt.",
                    ));
                }
                Ok(CommandScope {
                    kind: CommandMatch::Executable,
                    mode: Some(Mode::Run),
                    executable: Some(p.to_string()),
                    argv: vec![],
                })
            })
            .collect();
    };
    let env = &row.envelope;
    let filter = input.filter.as_deref().unwrap_or("program");
    if filter == "any" {
        return Ok(vec![]);
    }
    let Some(exe) = env.command.clone().filter(|_| env.mode == Mode::Run) else {
        return Err(ApiError::bad_request(
            "This request has no program to delegate; choose any command instead.",
        ));
    };
    let scope = |kind, argv| CommandScope {
        kind,
        mode: Some(Mode::Run),
        executable: Some(exe.clone()),
        argv,
    };
    Ok(vec![match filter {
        "program" => scope(CommandMatch::Executable, vec![]),
        "exact" => scope(CommandMatch::Exact, env.argv.clone()),
        "prefix" if env.argv.is_empty() => scope(CommandMatch::Executable, vec![]),
        "prefix" => {
            let n = input.prefix_len.unwrap_or(1).clamp(1, env.argv.len());
            scope(CommandMatch::Prefix, env.argv[..n].to_vec())
        }
        _ => return Err(ApiError::bad_request("Unknown command filter.")),
    }])
}

/// A delegation needs a passkey when it is broader than a passkey-free grant: no
/// command filter, anyone as requester, every host, longer than a day, or a raised
/// risk ceiling.
pub fn delegation_needs_passkey(state: &AppState, spec: &DelegationSpec, ttl: u32) -> bool {
    spec.commands.is_empty()
        || spec.requester.is_none()
        || spec.hosts == HostScope::All
        || ttl == 0
        || ttl > 1440
        || spec.limits.max_risk > state.cfg.policy.automation.default_limits.max_risk
}

pub struct PreparedWiden {
    pub id: String,
    pub before: DelegationSpec,
    pub after: DelegationSpec,
    pub label: String,
    pub expires_at: Option<i64>,
    pub resume: bool,
    pub needs_passkey: bool,
}

fn host_breadth(h: &HostScope) -> u8 {
    match h {
        HostScope::Host { .. } => 0,
        HostScope::Groups { .. } => 1,
        HostScope::All => 2,
    }
}

/// Widen an existing delegation so it also covers this request: union the command
/// filters, take the broader hosts and requester, the new intent, and the later
/// expiry. Never narrows anything.
fn prepare_widen(
    state: &AppState,
    host: &HostRow,
    row: &RequestRow,
    target: &str,
    input: &DelegateInput,
) -> ApiResult<PreparedWiden> {
    let g = grant(state, target)?
        .filter(|g| g.kind == "delegation" && g.revoked_at.is_none())
        .ok_or_else(|| ApiError::not_found("That delegation no longer exists."))?;
    let before: DelegationSpec = serde_json::from_value(g.spec.clone())
        .map_err(|_| ApiError::bad_request("That delegation can't be widened."))?;
    let intent = input.intent.trim();
    if intent.chars().count() < 8 {
        return Err(ApiError::bad_request(
            "Describe the kind of work in a few words; the model judges requests against it.",
        ));
    }
    let mut after = before.clone();
    after.intent = intent.chars().take(600).collect();
    after.intent_source = row
        .assessment
        .assessment
        .as_ref()
        // The model's (or template's) words only if the joined text was kept as offered.
        .filter(|a| {
            !a.suggestion.intent.is_empty()
                && intent == combine_intents(&before.intent, &a.suggestion.intent)
        })
        .map(|a| a.suggestion.intent_source)
        .filter(|_| before.intent_source != grants::IntentSource::Approver)
        .unwrap_or(grants::IntentSource::Approver);

    let added = delegation_commands(Some(row), input)?;
    if before.commands.is_empty() || added.is_empty() {
        after.commands = vec![];
    } else {
        for c in added {
            let covered = after.commands.iter().any(|have| {
                have.executable == c.executable
                    && (have.kind == CommandMatch::Executable || *have == c)
            });
            if !covered {
                if c.kind == CommandMatch::Executable {
                    after
                        .commands
                        .retain(|have| have.executable != c.executable);
                }
                after.commands.push(c);
            }
        }
    }

    let wanted = host_scope_for(state, &input.hosts, &input.groups, host)?;
    after.hosts = match (&before.hosts, wanted) {
        (HostScope::Groups { groups: a }, HostScope::Groups { groups: b }) => {
            let mut all = a.clone();
            all.extend(b.into_iter().filter(|g| !a.contains(g)));
            HostScope::Groups { groups: all }
        }
        (old, new) if host_breadth(&new) > host_breadth(old) => new,
        (old, _) => old.clone(),
    };
    let wanted_requester = match input.requester.as_str() {
        "any" => None,
        r => requester_scope_for(r, &row.envelope)?,
    };
    after.requester = match (&before.requester, wanted_requester) {
        (None, _) | (_, None) => None,
        (Some(RequesterScope::Session { fingerprint, .. }), Some(new)) if !matches!(&new, RequesterScope::Session { fingerprint: f, .. } if f == fingerprint) => {
            Some(RequesterScope::User {
                user: row.envelope.user.name.clone(),
            })
        }
        (Some(old), _) => Some(old.clone()),
    };
    if !after.target_uids.is_empty() && !after.target_uids.contains(&row.envelope.target.uid) {
        after.target_uids.push(row.envelope.target.uid);
    }
    if let Some(r) = input.max_risk {
        after.limits.max_risk = after.limits.max_risk.max(r.min(60));
    }
    let now = now_ms();
    let ttl = delegation_ttl(state, input.ttl_minutes);
    let wanted_expiry = (ttl > 0).then(|| now + ttl as i64 * 60_000);
    let expires_at = match (g.expires_at, wanted_expiry) {
        (None, _) | (_, None) => None,
        (Some(a), Some(b)) => Some(a.max(b)),
    };
    let resume = g.paused_at.is_some() || g.max_uses.is_some_and(|m| g.uses >= m);
    let default_risk = state.cfg.policy.automation.default_limits.max_risk;
    let needs_passkey = resume
        || after.commands.is_empty()
        || (after.requester.is_none() && before.requester.is_some())
        || (after.hosts == HostScope::All && before.hosts != HostScope::All)
        || (expires_at.is_none() && g.expires_at.is_some())
        || expires_at.is_some_and(|e| e > now + 86_400_000 && Some(e) != g.expires_at)
        || (after.limits.max_risk > before.limits.max_risk && after.limits.max_risk > default_risk);
    Ok(PreparedWiden {
        id: g.id.clone(),
        label: delegation_label(&after.intent),
        before,
        after,
        expires_at,
        resume,
        needs_passkey,
    })
}

/// A delegation the approver could widen to cover this request instead of creating
/// another: one that checked it and handed it over, or one (live or paused) whose
/// filter names the same program.
pub fn widen_candidate(
    state: &AppState,
    row: &RequestRow,
    host: &HostRow,
) -> Option<(GrantRow, DelegationSpec)> {
    let class = class_named(state, &row.class);
    let facts = HostFacts {
        host_id: &host.id,
        groups: &host.groups,
    };
    let now = now_ms();
    let checked: Vec<&str> = row
        .assessment
        .delegation_checks
        .iter()
        .filter(|c| !c.approved)
        .map(|c| c.id.as_str())
        .collect();
    type Ranked = (u8, (u8, u8, u8), GrantRow, DelegationSpec);
    let mut found: Vec<Ranked> = grants_recent(state)
        .ok()?
        .into_iter()
        .filter(|g| {
            g.kind == "delegation" && g.revoked_at.is_none() && g.expires_at.is_none_or(|e| e > now)
        })
        .filter_map(|g| {
            let spec: DelegationSpec = serde_json::from_value(g.spec.clone()).ok()?;
            let mut open = spec.clone();
            open.commands.clear();
            let rank = if checked.contains(&g.id.as_str()) {
                0
            } else if grants::delegation_scope_matches(&open, &row.envelope, &facts, &class)
                && spec
                    .commands
                    .iter()
                    .any(|c| c.executable.is_some() && c.executable == row.envelope.command)
            {
                1
            } else {
                return None;
            };
            Some((rank, grants::delegation_specificity(&spec), g, spec))
        })
        .collect();
    found.sort_by_key(|(rank, specificity, g, _)| (*rank, *specificity, -g.created_at));
    found.into_iter().next().map(|(_, _, g, spec)| (g, spec))
}

/// Whether a delegation's scope, apart from its command filter, covers this request.
fn widen_covers(
    state: &AppState,
    row: &RequestRow,
    host: &HostRow,
    class: &ClassConfig,
    target: &str,
) -> bool {
    let Ok(Some(g)) = grant(state, target) else {
        return false;
    };
    let Ok(mut open) = serde_json::from_value::<DelegationSpec>(g.spec.clone()) else {
        return false;
    };
    open.commands.clear();
    let facts = HostFacts {
        host_id: &host.id,
        groups: &host.groups,
    };
    g.kind == "delegation"
        && g.revoked_at.is_none()
        && grants::delegation_scope_matches(&open, &row.envelope, &facts, class)
}

/// Join two kinds of work into one intent without repeating either.
pub fn combine_intents(old: &str, new: &str) -> String {
    let (o, n) = (old.trim(), new.trim());
    if n.is_empty() || o.to_lowercase().contains(&n.to_lowercase()) {
        return o.to_string();
    }
    if o.is_empty() || n.to_lowercase().contains(&o.to_lowercase()) {
        return n.to_string();
    }
    // Same program anchor: `apt: installing packages; removing packages`.
    let joined = match (o.split_once(": "), n.split_once(": ")) {
        (Some((pa, _)), Some((pb, kind))) if pa.eq_ignore_ascii_case(pb) => {
            format!("{o}; {kind}")
        }
        _ => format!("{o}; {n}"),
    };
    joined.chars().take(600).collect()
}

/// The decision the model suggested, as the explicit scope or delegation it stands
/// for, so it goes through exactly the same checks as a hand-made choice.
fn suggested_decision(
    state: &AppState,
    row: &RequestRow,
    host: &HostRow,
    class: &ClassConfig,
) -> ApiResult<(Option<ScopeInput>, Option<DelegateInput>)> {
    let Some(a) = row.assessment.assessment.as_ref() else {
        return Err(ApiError::conflict("There is no suggestion to apply yet."));
    };
    let sug = &a.suggestion;
    if sug.decision != "approve" || sug.remember == "once" {
        return Ok((None, None));
    }
    let can_delegate = state.advisor.is_some()
        && state.automation_enabled()
        && class.delegable
        && !row.envelope.lossy;
    if sug.remember == "exact" || !can_delegate {
        let command = if sug.command == "once" {
            return Ok((None, None));
        } else {
            sug.command.clone()
        };
        return Ok((
            Some(ScopeInput {
                command,
                prefix_len: Some(sug.prefix_len.max(1)),
                hosts: sug.hosts.clone(),
                groups: vec![],
                requester: sug.requester.clone(),
                ttl_minutes: sug.ttl_minutes,
            }),
            None,
        ));
    }
    let widen = widen_candidate(state, row, host);
    let intent = match &widen {
        Some((_, spec)) => combine_intents(&spec.intent, &sug.intent),
        None => sug.intent.clone(),
    };
    Ok((
        None,
        Some(DelegateInput {
            intent,
            ttl_minutes: sug.duration_minutes,
            hosts: sug.hosts.clone(),
            // Rules follow the unix user across agent sessions, as on the sheet.
            requester: "user".into(),
            filter: Some(sug.remember.clone()),
            prefix_len: Some(sug.prefix_len.max(1)),
            widen: widen.map(|(g, _)| g.id),
            ..DelegateInput::default()
        }),
    ))
}

fn insert_delegation(
    conn: &rusqlite::Connection,
    session: &Session,
    d: &PreparedDelegation,
) -> ApiResult<()> {
    conn.execute(
        "INSERT INTO grants (id, kind, label, spec_json, created_by, created_from_request, created_at, expires_at, max_uses)
         VALUES (?1, 'delegation', ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            d.id,
            d.label,
            serde_json::to_string(&d.spec).map_err(anyhow::Error::from)?,
            session.user.name,
            d.from_request,
            d.created_at,
            (d.ttl > 0).then(|| d.created_at + d.ttl as i64 * 60_000),
            (d.max_uses > 0).then_some(d.max_uses as i64)
        ],
    )?;
    Ok(())
}

/// Create a delegation that is not tied to a request decision.
pub fn create_delegation(
    state: &AppState,
    session: &Session,
    host: &HostRow,
    input: &DelegateInput,
) -> ApiResult<(String, DelegationSpec)> {
    let d = prepare_delegation(state, host, None, input)?;
    insert_delegation(&state.db.lock(), session, &d)?;
    audit::record(
        &state.db,
        &session.user.name,
        "delegation.created",
        Some(&d.id),
        json!({"spec": d.spec, "ttl_minutes": (d.ttl > 0).then_some(d.ttl), "device": session.device_label}),
    );
    state.emit(Event::Grants);
    Ok((d.id, d.spec))
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
            // Keep nonces longer than any timestamp could remain acceptable (skew both ways).
            let cutoff = now_ms() - (2 * agent_sudo_protocol::signing::MAX_SKEW_SECS + 60) * 1000;
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

/// The model's suggestion as one line for a notification, and whether it can be
/// applied from the notification without a passkey.
fn suggestion_for_push(state: &AppState, row: &RequestRow) -> Option<(String, bool)> {
    let a = row.assessment.assessment.as_ref()?;
    let sug = &a.suggestion;
    if sug.decision != "approve" || sug.remember == "once" {
        return None;
    }
    let host = host(state, &row.host_id).ok()??;
    let class = class_named(state, &row.class);
    let (scope, delegate) = suggested_decision(state, row, &host, &class).ok()?;
    let length = |m: u32| match m {
        0 => "for good".to_string(),
        60 => "for an hour".into(),
        1440 => "for a day".into(),
        43200 => "for a month".into(),
        m => format!("for {}", human_duration(m as i64 * 60)),
    };
    let (text, passkey) = match (scope, delegate) {
        (Some(scope), _) => (
            format!(
                "Suggested: remember this command {}",
                length(scope.ttl_minutes)
            ),
            false,
        ),
        (None, Some(d)) => {
            let passkey = match &d.widen {
                Some(target) => prepare_widen(state, &host, row, target, &d)
                    .map(|w| w.needs_passkey)
                    .unwrap_or(true),
                None => prepare_delegation(state, &host, Some(row), &d)
                    .map(|p| delegation_needs_passkey(state, &p.spec, p.ttl))
                    .unwrap_or(true),
            };
            let verb = if d.widen.is_some() {
                "widen the rule to"
            } else {
                "allow"
            };
            let hosts = match d.hosts.as_str() {
                "group" => format!(
                    "on the {} group",
                    default_group(state, &host).unwrap_or_default()
                ),
                "all" => "on all hosts".into(),
                _ => format!("on {}", host.name),
            };
            (
                format!(
                    "Suggested: {verb} {} {hosts}, any {} session, {}",
                    sug.intent,
                    row.envelope.user.name,
                    length(d.ttl_minutes)
                ),
                passkey,
            )
        }
        _ => return None,
    };
    Some((text, !passkey && class.step_up == StepUp::None))
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
    notify_pending_to(state, row, subs, false).await;
}

async fn notify_pending_to(
    state: &Shared,
    row: &RequestRow,
    subs: Vec<push::Subscription>,
    update: bool,
) {
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
        body.push_str("\nagent: ");
        body.push_str(&truncate(ctx, 120));
    }
    let suggestion = suggestion_for_push(state, row);
    if let Some((text, _)) = &suggestion {
        body.push('\n');
        body.push_str(&truncate(text, 140));
    }
    let payload = json!({
        "t": "request",
        "id": row.id,
        "v": row.version,
        "code": row.code,
        "title": format!("{who} on {host} wants sudo"),
        "body": body,
        "quick": class.quick_approve && class.step_up == StepUp::None,
        "remember": suggestion.as_ref().is_some_and(|(_, one_tap)| *one_tap),
        "suggestion_at": row.assessment.assessment.as_ref().map(|a| a.created_at),
        "update": update,
        "danger": row.features.0.iter().any(|f| f.level == "danger"),
        "url": format!("/r/{}", row.id),
    });
    let ttl = ((row.deadline_at - now_ms()) / 1000).clamp(30, 3600) as u32;
    // No Topic header: Apple's push service rejects values other services accept
    // (BadWebPushTopic), and notifications already collapse by tag on the device.
    push::fan_out(&state.push, &state.db, subs, &payload, ttl, None).await;
}

/// When the background assessment suggests remembering the request, update the
/// notification in place so it can be approved that way with one tap. Only for
/// browsers that show notification buttons: elsewhere a second push would only buzz
/// again without adding anything.
async fn notify_suggestion(state: &Shared, id: &str) {
    if !state.push.enabled() {
        return;
    }
    let Ok(Some(row)) = request(state, id) else {
        return;
    };
    if row.state != RequestState::Pending {
        return;
    }
    let Some((_, true)) = suggestion_for_push(state, &row) else {
        return;
    };
    let Ok(subs) = push::subscriptions_for_approvers(&state.db) else {
        return;
    };
    let subs: Vec<_> = subs
        .into_iter()
        .filter(|s| push::shows_actions(&s.endpoint))
        .collect();
    if subs.is_empty() {
        return;
    }
    notify_pending_to(state, &row, subs, true).await;
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

// Shapes returned by the service API.

export interface Feature {
  key: string;
  label: string;
  level: "info" | "warn" | "danger";
}

export type Remember = "once" | "exact" | "prefix" | "program" | "any";

export interface Suggestion {
  decision: "approve" | "deny" | "ask";
  /** The same draft as a plain grant. */
  command: "once" | "exact" | "prefix" | "executable";
  hosts: "host" | "group" | "all";
  requester: "session" | "user";
  ttl_minutes: number;
  remember?: Remember;
  prefix_len?: number;
  kind_of_work?: string;
  /** `{program}: {kind of work}`, drafted by the model or the policy template. */
  intent?: string;
  intent_source?: "approver" | "model" | "template";
  /** 0 means no expiry. */
  duration_minutes?: number;
  probabilities?: Record<string, Record<string, number>>;
}

export interface Assessment {
  risk: number;
  model_risk: number;
  confidence: number;
  dimensions: Record<string, number>;
  relevance: number | null;
  relevance_by?: Record<string, number>;
  suggestion: Suggestion;
  summary: string;
  reasons: string[];
  model: string;
  backend: string;
  latency_ms: number;
  cost_usd: number | null;
  clamped: string[];
  created_at: number;
}

export interface DelegationCheck {
  id: string;
  label: string;
  approved: boolean;
  reasons: string[];
  relevance?: number | null;
}

export interface StoredAssessment {
  assessment: Assessment | null;
  failure: { error: string; model: string; at: number } | null;
  delegation_check: DelegationCheck | null;
  delegation_checks?: DelegationCheck[];
  running: boolean;
}

export interface DecisionRecord {
  decision: {
    state: string;
    via: "user" | "grant" | "delegation" | "policy";
    by: string;
    label: string;
    hard: boolean;
    refresh_timestamp: boolean;
    reason: string | null;
  };
  device_label: string | null;
  auth: string | null;
  note: string | null;
  grant: string | null;
  delegation: string | null;
  followed_suggestion: boolean | null;
  at: number;
}

export interface ClassView {
  name: string;
  title: string;
  max_ttl_minutes: number;
  require_each_time: boolean;
  step_up: "none" | "recent" | "always";
  hard_deny: boolean;
  delegable: boolean;
  quick_approve: boolean;
}

export interface RequestView {
  id: string;
  code: string;
  state: "pending" | "approved" | "denied" | "expired" | "withdrawn";
  version: number;
  created_at: number;
  updated_at: number;
  deadline_at: number;
  host: { id: string; name: string; groups: string[]; default_group?: string | null } | null;
  user: string;
  target: string;
  target_uid: number;
  mode: "run" | "edit" | "list" | "validate";
  launch: "direct" | "shell" | "login";
  command: string | null;
  argv: string[];
  display: string;
  cwd: string | null;
  chdir: string | null;
  tty: string | null;
  interactive: boolean;
  nonblocking: boolean;
  lossy: boolean;
  env: string[];
  executable: { real_path: string; owner_uid: number; mode: number; writable_by_requester: boolean } | null;
  paths: { index: number; given: string; resolved: string; user_symlink: boolean }[];
  session: {
    label: string;
    agent: string | null;
    fingerprint: string;
    ssh: boolean;
    chain?: { pid: number; name: string; cmdline: string }[];
  };
  context: string | null;
  claimed_session: string | null;
  class: ClassView;
  features: Feature[];
  assessment: StoredAssessment;
  decision: DecisionRecord | null;
  grant_id: string | null;
  delegation_id: string | null;
  flagged_at: number | null;
  /** An existing delegation the approver can widen to cover this request. */
  widen?: { id: string; label: string; intent: string; covers: string; summary: string; paused: boolean; expires_at: number | null; max_risk: number } | null;
  related?: { id: string; host: string; state: string; via: string | null; by: string | null; created_at: number; same_session: boolean }[];
}

export interface GrantView {
  id: string;
  kind: "grant" | "delegation";
  label: string;
  spec: any;
  created_by: string;
  created_from_request: string | null;
  created_at: number;
  expires_at: number | null;
  revoked_at: number | null;
  revoked_by: string | null;
  uses: number;
  max_uses: number | null;
  last_used_at: number | null;
  paused_at: number | null;
  pause_reason: string | null;
  active: boolean;
  summary: string;
}

export interface HostView {
  id: string;
  name: string;
  hostname: string;
  groups: string[];
  hostd_version: string;
  created_at: number;
  last_seen_at: number | null;
  revoked_at: number | null;
  online: boolean;
}

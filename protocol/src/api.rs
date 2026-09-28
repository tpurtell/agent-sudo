//! JSON bodies exchanged between agent-sudo-hostd and the approval service.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Run,
    Edit,
    List,
    Validate,
}

impl Mode {
    pub fn parse(s: &str) -> Option<Mode> {
        Some(match s {
            "run" => Mode::Run,
            "edit" => Mode::Edit,
            "list" => Mode::List,
            "validate" => Mode::Validate,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Launch {
    #[default]
    Direct,
    Shell,
    Login,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Principal {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Target {
    pub user: String,
    pub uid: u32,
    pub group: Option<String>,
    pub gid: u32,
}

/// One ancestor of the requesting process, as seen by hostd in /proc.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,
}

/// Session identity established by hostd from /proc, never claimed by the caller.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SessionInfo {
    /// Stable for the lifetime of the session: boot id + pid + start time.
    pub fingerprint: String,
    /// Human label, e.g. "claude (pid 4121)".
    pub label: String,
    /// Detected agent kind ("claude", "codex", ...) when an ancestor matches.
    pub agent: Option<String>,
    /// Nearest ancestors first, starting with the parent of sudo.
    pub chain: Vec<ProcessInfo>,
    /// Whether the requesting session arrived over SSH.
    pub ssh: bool,
}

/// Text supplied by the requester. Display-only; never used for decisions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Untrusted {
    pub context: Option<String>,
    pub session: Option<String>,
}

/// Facts about the executable, established by hostd with `stat` as root.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutableFacts {
    /// Canonical path with symlinks resolved.
    pub real_path: String,
    pub owner_uid: u32,
    pub mode: u32,
    /// The requester could change the file or replace it (it or a parent directory
    /// is writable by them). Such commands are treated as arbitrary code.
    pub writable_by_requester: bool,
}

/// A path-like argument, resolved by hostd against the working directory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathFact {
    pub index: usize,
    pub given: String,
    /// Canonical path (symlinks resolved; a missing final component is appended).
    pub resolved: String,
    /// The path passes through a symlink the requester owns, so its target can change
    /// after approval.
    pub user_symlink: bool,
}

/// The authoritative description of a privilege request, built by hostd.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestEnvelope {
    /// Idempotency key chosen by hostd.
    pub client_request_id: String,
    pub mode: Mode,
    pub nonblocking: bool,
    pub interactive: bool,
    pub hostname: String,
    pub user: Principal,
    pub target: Target,
    pub launch: Launch,
    /// Resolved absolute path of the command (empty for list/validate).
    pub command: Option<String>,
    /// Arguments after the command.
    pub argv: Vec<String>,
    /// True when some argument or path was not valid UTF-8 and was rendered lossily.
    /// Such requests never match grants.
    #[serde(default)]
    pub lossy: bool,
    pub cwd: Option<String>,
    pub chdir: Option<String>,
    pub tty: Option<String>,
    /// Environment overrides requested on the command line (`NAME=value`).
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub executable: Option<ExecutableFacts>,
    #[serde(default)]
    pub paths: Vec<PathFact>,
    pub session: SessionInfo,
    pub untrusted: Untrusted,
    pub timeout_secs: u64,
    pub hostd_version: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequestState {
    Pending,
    Approved,
    Denied,
    Expired,
    Withdrawn,
}

impl RequestState {
    pub fn is_final(self) -> bool {
        !matches!(self, RequestState::Pending)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            RequestState::Pending => "pending",
            RequestState::Approved => "approved",
            RequestState::Denied => "denied",
            RequestState::Expired => "expired",
            RequestState::Withdrawn => "withdrawn",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "pending" => RequestState::Pending,
            "approved" => RequestState::Approved,
            "denied" => RequestState::Denied,
            "expired" => RequestState::Expired,
            "withdrawn" => RequestState::Withdrawn,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DecidedVia {
    /// A person decided in the UI.
    User,
    /// An existing grant matched.
    Grant,
    /// A delegation let the decision model approve.
    Delegation,
    /// Deterministic policy (e.g. a class that always denies, or expiry).
    Policy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Decision {
    pub state: RequestState,
    pub via: DecidedVia,
    /// Who decided: a username, or the grant/delegation label.
    pub by: String,
    /// Short extra label, e.g. device name or grant scope summary.
    pub label: String,
    #[serde(default)]
    pub hard: bool,
    #[serde(default)]
    pub refresh_timestamp: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubmitResponse {
    pub id: String,
    /// Short code shown in the terminal and on the phone to match them up.
    pub code: String,
    pub url: String,
    pub state: RequestState,
    pub decision: Option<Decision>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionResponse {
    pub id: String,
    pub state: RequestState,
    pub decision: Option<Decision>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CancelRequest {
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnrollRequest {
    pub token: String,
    pub hostname: String,
    /// Base64 (standard) Ed25519 public key.
    pub public_key: String,
    pub hostd_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnrollResponse {
    pub host_id: String,
    pub name: String,
    pub service_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeartbeatRequest {
    pub hostd_version: String,
    pub hostname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeartbeatResponse {
    pub host_id: String,
    pub name: String,
    pub groups: Vec<String>,
    pub server_time: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiError {
    pub error: String,
    pub message: String,
}

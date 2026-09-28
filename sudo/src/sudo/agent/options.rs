//! Command line options added by agent-sudo. They are parsed by the regular sudo-rs
//! parser (see `cli/mod.rs`) and parked here so the rest of the pipeline stays untouched.
#![forbid(unsafe_code)]

use std::sync::OnceLock;
use std::time::Duration;

/// Hard cap on the size of agent-supplied text forwarded to the service.
pub(crate) const MAX_CONTEXT_BYTES: usize = 4000;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct AgentOptions {
    /// `--agent-context TEXT` (or `SUDO_AGENT_CONTEXT`): display-only explanation.
    pub context: Option<String>,
    /// `--agent-session ID` (or `SUDO_AGENT_SESSION`): display-only session label.
    pub session: Option<String>,
    /// `--approval-timeout DURATION`: may only shorten the configured timeout.
    pub timeout: Option<Duration>,
    /// `--no-remote`: behave exactly like upstream sudo-rs for this invocation.
    pub no_remote: bool,
}

impl AgentOptions {
    pub(crate) fn is_empty(&self) -> bool {
        *self == AgentOptions::default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Run,
    Edit,
    List,
    Validate,
}

impl Mode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Mode::Run => "run",
            Mode::Edit => "edit",
            Mode::List => "list",
            Mode::Validate => "validate",
        }
    }
}

static OPTIONS: OnceLock<AgentOptions> = OnceLock::new();
static MODE: OnceLock<Mode> = OnceLock::new();
static ENV_OVERRIDES: OnceLock<Vec<(String, String)>> = OnceLock::new();

/// Environment variables requested on the command line (`VAR=value`, `--preserve-env`).
pub(crate) fn set_env_overrides(vars: &[(String, String)]) {
    let _ = ENV_OVERRIDES.set(vars.to_vec());
}

pub(crate) fn env_overrides() -> &'static [(String, String)] {
    ENV_OVERRIDES.get().map(Vec::as_slice).unwrap_or(&[])
}

pub(crate) fn set_options(options: AgentOptions) {
    let _ = OPTIONS.set(options);
}

pub(crate) fn set_mode(mode: Mode) {
    let _ = MODE.set(mode);
}

pub(crate) fn mode() -> Mode {
    MODE.get().copied().unwrap_or(Mode::Run)
}

fn truncate(mut text: String) -> String {
    if text.len() > MAX_CONTEXT_BYTES {
        let mut cut = MAX_CONTEXT_BYTES;
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        text.truncate(cut);
        text.push('…');
    }
    text
}

/// The effective options: CLI flags first, then environment fallbacks.
pub(crate) fn effective() -> AgentOptions {
    let mut options = OPTIONS.get().cloned().unwrap_or_default();
    if options.context.is_none() {
        options.context = std::env::var("SUDO_AGENT_CONTEXT").ok();
    }
    if options.session.is_none() {
        options.session = std::env::var("SUDO_AGENT_SESSION").ok();
    }
    options.context = options
        .context
        .filter(|c| !c.trim().is_empty())
        .map(truncate);
    options.session = options
        .session
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.chars().take(200).collect());
    options
}

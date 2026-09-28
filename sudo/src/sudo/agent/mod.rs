//! agent-sudo: remote approval as one additional authentication outcome.
//!
//! This module only runs after sudoers has already decided that the request is
//! *allowed but requires authentication*. It can replace authentication, never
//! authorization. Everything here is compiled only with the `agent-approval` feature.
//!
//! Flow, once sudoers asks for authentication:
//! - no `/etc/agent-sudo/client.conf`, or `--no-remote`: upstream behaviour.
//! - `-n`: ask hostd without blocking (existing grants and delegations only).
//! - no way to type a password (no tty, no -S, no -A): wait for the remote decision.
//! - otherwise: show the normal password prompt and race it against the remote decision.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::time::{Duration, Instant};

use crate::common::{Context, Error};
use crate::pam::{PamContext, PamError, remote_wake};
use crate::system::term::current_tty_name;

mod client;
pub(crate) mod config;
pub(crate) mod options;
pub(crate) mod wire;

use client::Connection;
use config::{ClientConfig, Unavailable};
pub(crate) use options::{AgentOptions, Mode, set_env_overrides, set_mode, set_options};
use wire::{Line, RequestBlock};

/// How the request ended up authenticated.
pub(crate) enum Outcome {
    /// Upstream PAM authentication succeeded: record the timestamp as usual.
    Password,
    /// Approved by the service. Only touch the timestamp if the approver asked for it.
    Remote { refresh_timestamp: bool },
}

impl Outcome {
    pub(crate) fn creates_record(&self) -> bool {
        match self {
            Outcome::Password => true,
            Outcome::Remote { refresh_timestamp } => *refresh_timestamp,
        }
    }
}

/// A final decision received from hostd.
enum Decision {
    Approved { refresh: bool },
    Denied { hard: bool },
    Expired,
    Unavailable(String),
}

fn say(cfg: &ClientConfig, message: &str) {
    if cfg.notice {
        eprintln_ignore_io_error!("agent-sudo: {message}");
    }
}

fn fail(message: impl Into<String>) -> Error {
    Error::Approval(message.into())
}

fn describe_approval(line: &Line) -> String {
    let by = line.get_str("by").unwrap_or_default();
    let label = line.get_str("label").unwrap_or_default();
    match line.get_str("via").as_deref() {
        Some("grant") if !label.is_empty() => format!("approved by standing grant ({label})"),
        Some("grant") => "approved by standing grant".to_string(),
        Some("delegation") if !label.is_empty() => {
            format!("approved by delegation \u{201c}{label}\u{201d}")
        }
        Some("delegation") => "approved by delegation".to_string(),
        _ if !label.is_empty() => format!("approved by {by} \u{b7} {label}"),
        _ => format!("approved by {by}"),
    }
}

/// Interpret a final line. `Ok(None)` for non-final lines (e.g. `pending`).
fn decision(cfg: &ClientConfig, line: &Line) -> Option<Decision> {
    match line.verb.as_str() {
        "approved" => {
            say(cfg, &describe_approval(line));
            Some(Decision::Approved {
                refresh: line.flag("refresh"),
            })
        }
        "denied" => {
            let by = line.get_str("by").unwrap_or_else(|| "policy".into());
            let reason = line.get_str("reason").filter(|r| !r.is_empty());
            let msg = match reason {
                Some(reason) => format!("denied by {by}: {reason}"),
                None => format!("denied by {by}"),
            };
            say(cfg, &msg);
            Some(Decision::Denied {
                hard: line.flag("hard"),
            })
        }
        "expired" => {
            say(cfg, "request expired without a decision");
            Some(Decision::Expired)
        }
        "unavailable" | "error" => Some(Decision::Unavailable(
            line.get_str("reason")
                .or_else(|| line.get_str("message"))
                .unwrap_or_else(|| "approval service unavailable".into()),
        )),
        _ => None,
    }
}

fn build_request(
    context: &Context,
    opts: &AgentOptions,
    timeout: Duration,
    nonblocking: bool,
    interactive: bool,
) -> RequestBlock {
    let mut req = RequestBlock::new();
    let flag = |b: bool| if b { "1" } else { "0" };
    req.field("mode", options::mode().as_str())
        .field("nonblocking", flag(nonblocking))
        .field("interactive", flag(interactive))
        .field("pid", std::process::id().to_string())
        .field("hostname", context.hostname.to_string())
        .field("user", context.current_user.name.as_str())
        .field("uid", context.current_user.uid.to_string())
        .field("gid", context.current_user.gid.to_string())
        .field("target_user", context.target_user.name.as_str())
        .field("target_uid", context.target_user.uid.to_string())
        .field("target_gid", context.target_group.gid.to_string())
        .field("timeout_secs", timeout.as_secs().to_string())
        .field(
            "launch",
            match context.launch {
                crate::common::context::LaunchType::Direct => "direct",
                crate::common::context::LaunchType::Shell => "shell",
                crate::common::context::LaunchType::Login => "login",
            },
        );
    if let Some(name) = &context.target_group.name {
        req.field("target_group", name.as_str());
    }
    let command = context.command.command.as_os_str();
    if !command.is_empty() {
        req.field("command", command.as_bytes());
    }
    for arg in &context.command.arguments {
        req.field("arg", arg.as_bytes());
    }
    for (name, value) in options::env_overrides() {
        req.field("env", format!("{name}={value}"));
    }
    if let Some(chdir) = &context.chdir {
        req.field("chdir", chdir.as_os_str().as_bytes());
    }
    if let Ok(cwd) = std::env::current_dir() {
        req.field("cwd", cwd.as_os_str().as_bytes());
    }
    if let Ok(tty) = current_tty_name() {
        req.field("tty", OsStr::as_bytes(&tty));
    }
    if let Some(ctx) = &opts.context {
        req.field("context", ctx.as_bytes());
    }
    if let Some(session) = &opts.session {
        req.field("session", session.as_bytes());
    }
    req
}

/// Can this invocation read a password at all?
fn can_prompt(context: &Context) -> bool {
    context.stdin
        || context.askpass
        || std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .is_ok()
}

/// Wait for a final decision with no password path.
fn wait_for_decision(
    cfg: &ClientConfig,
    conn: &mut Connection,
    deadline: Instant,
) -> Result<Decision, Error> {
    loop {
        match conn.read_line(Some(deadline)) {
            Ok(Some(line)) => {
                if let Some(decision) = decision(cfg, &line) {
                    return Ok(decision);
                }
            }
            Ok(None) => {
                let _ = conn.send_line("cancel reason=timeout");
                say(cfg, "timed out waiting for approval");
                return Ok(Decision::Expired);
            }
            Err(e) => return Ok(Decision::Unavailable(e.to_string())),
        }
    }
}

fn finish(decision: Decision) -> Result<Outcome, Error> {
    match decision {
        Decision::Approved { refresh } => Ok(Outcome::Remote {
            refresh_timestamp: refresh,
        }),
        Decision::Denied { .. } => Err(fail("request denied")),
        Decision::Expired => Err(fail("request was not approved in time")),
        Decision::Unavailable(reason) => {
            Err(fail(format!("approval service unavailable: {reason}")))
        }
    }
}

/// Entry point used by `auth_and_update_record_file` when sudoers requires authentication.
///
/// `password` runs the unmodified upstream authentication (including its `-n` check).
pub(crate) fn authenticate(
    context: &Context,
    pam: &mut PamContext,
    mut password: impl FnMut(&mut PamContext) -> Result<(), Error>,
) -> Result<Outcome, Error> {
    let cfg = match ClientConfig::load() {
        Ok(Some(cfg)) => cfg,
        Ok(None) => return password(pam).map(|()| Outcome::Password),
        Err(e) => return Err(Error::Configuration(e)),
    };
    let opts = options::effective();
    if opts.no_remote {
        return password(pam).map(|()| Outcome::Password);
    }

    let timeout = opts.timeout.map_or(cfg.timeout, |t| t.min(cfg.timeout));
    let nonblocking = context.non_interactive;
    let interactive = !nonblocking && can_prompt(context);
    let deadline = Instant::now() + timeout;

    let unavailable = |pam: &mut PamContext,
                       password: &mut dyn FnMut(&mut PamContext) -> Result<(), Error>,
                       reason: String| {
        if (interactive || nonblocking) && cfg.on_unavailable == Unavailable::Password {
            if interactive {
                say(
                    &cfg,
                    &format!("approval service unavailable ({reason}); falling back to password"),
                );
            }
            password(pam).map(|()| Outcome::Password)
        } else {
            Err(fail(format!("approval service unavailable: {reason}")))
        }
    };

    let mut conn = match Connection::connect(&cfg.socket) {
        Ok(conn) => conn,
        Err(e) => {
            let reason = match e.kind() {
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
                    format!("agent-sudo-hostd is not running ({})", cfg.socket.display())
                }
                _ => e.to_string(),
            };
            return unavailable(pam, &mut password, reason);
        }
    };
    let request = build_request(context, &opts, timeout, nonblocking, interactive);
    if let Err(e) = conn.send(request) {
        return unavailable(pam, &mut password, e.to_string());
    }

    // hostd answers quickly with either `pending` or a final decision.
    let first = match conn.read_line_within(Duration::from_secs(30)) {
        Ok(Some(line)) => line,
        Ok(None) => {
            return unavailable(pam, &mut password, "no answer from agent-sudo-hostd".into());
        }
        Err(e) => return unavailable(pam, &mut password, e.to_string()),
    };
    match decision(&cfg, &first) {
        Some(Decision::Approved { refresh }) => {
            return Ok(Outcome::Remote {
                refresh_timestamp: refresh,
            });
        }
        Some(Decision::Denied { hard: true }) => return Err(fail("request denied")),
        Some(Decision::Unavailable(reason)) => return unavailable(pam, &mut password, reason),
        // A soft denial or no match for `-n`: continue with upstream behaviour, which
        // refuses `-n` unless sudoers allows non-interactive authentication.
        Some(Decision::Denied { hard: false } | Decision::Expired)
            if nonblocking || interactive =>
        {
            return password(pam).map(|()| Outcome::Password);
        }
        Some(other) => return finish(other),
        None if first.verb == "pending" => {}
        None => return Err(fail(format!("unexpected reply from hostd: {}", first.verb))),
    }
    if nonblocking {
        // hostd must never leave a non-blocking request pending.
        return password(pam).map(|()| Outcome::Password);
    }

    let code = first.get_str("code").unwrap_or_default();
    let url = first.get_str("url").unwrap_or_default();

    if !interactive {
        let mins = timeout.as_secs().div_ceil(60);
        if url.is_empty() {
            say(
                &cfg,
                &format!("waiting for approval [{code}] (up to {mins}m, Ctrl-C to cancel)"),
            );
        } else {
            say(
                &cfg,
                &format!("waiting for approval [{code}] {url} (up to {mins}m, Ctrl-C to cancel)"),
            );
        }
        return finish(wait_for_decision(&cfg, &mut conn, deadline)?);
    }

    say(
        &cfg,
        &format!("approval requested [{code}]; enter your password or approve remotely"),
    );
    loop {
        remote_wake::arm(conn.fd());
        let result = password(pam);
        let woken = remote_wake::disarm();
        match result {
            Ok(()) => {
                let _ = conn.send_line("cancel reason=password");
                return Ok(Outcome::Password);
            }
            Err(_) if woken => {
                match conn.read_line_within(Duration::from_secs(5)) {
                    Ok(Some(line)) => match decision(&cfg, &line) {
                        Some(Decision::Approved { refresh }) => {
                            return Ok(Outcome::Remote {
                                refresh_timestamp: refresh,
                            });
                        }
                        Some(Decision::Denied { hard: true }) => {
                            return Err(fail("request denied"));
                        }
                        Some(_) => {
                            say(&cfg, "you can still authenticate with your password");
                            return password(pam).map(|()| Outcome::Password);
                        }
                        None => continue,
                    },
                    // hostd went away: keep the password path alive.
                    _ => return password(pam).map(|()| Outcome::Password),
                }
            }
            // Password path gave up (Ctrl-D, attempts exhausted, prompt timeout):
            // keep waiting for the remote decision instead of failing outright.
            Err(Error::MaxAuthAttempts(_))
            | Err(Error::Pam(PamError::NoPasswordProvided | PamError::TimedOut)) => {
                say(
                    &cfg,
                    &format!("still waiting for remote approval [{code}] (Ctrl-C to cancel)"),
                );
                return finish(wait_for_decision(&cfg, &mut conn, deadline)?);
            }
            Err(e) => {
                let _ = conn.send_line("cancel reason=error");
                return Err(e);
            }
        }
    }
}

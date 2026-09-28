//! The local socket server: one sudo request per connection.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use agent_sudo_protocol::api::{
    DecidedVia, Decision, Launch, Mode, Principal, RequestEnvelope, RequestState, Target, Untrusted,
};
use agent_sudo_protocol::local::LocalRequest;
use agent_sudo_protocol::wire::Line;
use anyhow::{Context, Result, bail};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::procinfo::Proc;
use crate::service::ServiceClient;

const MAX_REQUEST: usize = 256 * 1024;
const LONG_POLL_SECS: u64 = 25;

pub struct Relay {
    pub client: ServiceClient,
    pub proc: Proc,
    pub allow_peer_uids: Vec<u32>,
    pub hostd_version: String,
}

pub fn bind(socket: &Path) -> Result<UnixListener> {
    if let Some(dir) = socket.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        // Only root may reach the socket; the setuid binary runs with euid 0.
        if nix_is_root() {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    match std::fs::remove_file(socket) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("removing stale {}", socket.display())),
    }
    let listener =
        UnixListener::bind(socket).with_context(|| format!("binding {}", socket.display()))?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

fn nix_is_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

fn lossy(bytes: &[u8], lossy_flag: &mut bool) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => {
            *lossy_flag = true;
            String::from_utf8_lossy(bytes).into_owned()
        }
    }
}

pub fn envelope_from(req: &LocalRequest, proc: &Proc, hostd_version: &str) -> RequestEnvelope {
    let mut is_lossy = false;
    let command = req.command.as_deref().map(|c| lossy(c, &mut is_lossy));
    let argv = req.args.iter().map(|a| lossy(a, &mut is_lossy)).collect();
    let cwd = req.cwd.as_deref().map(|c| lossy(c, &mut is_lossy));
    let chdir = req.chdir.as_deref().map(|c| lossy(c, &mut is_lossy));
    RequestEnvelope {
        client_request_id: ulid::Ulid::new().to_string(),
        mode: Mode::parse(&req.mode).unwrap_or(Mode::Run),
        nonblocking: req.nonblocking,
        interactive: req.interactive,
        hostname: req.hostname.clone(),
        user: Principal {
            name: req.user.clone(),
            uid: req.uid,
            gid: req.gid,
        },
        target: Target {
            user: req.target_user.clone(),
            uid: req.target_uid,
            group: req.target_group.clone(),
            gid: req.target_gid,
        },
        launch: match req.launch.as_str() {
            "shell" => Launch::Shell,
            "login" => Launch::Login,
            _ => Launch::Direct,
        },
        command,
        argv,
        lossy: is_lossy,
        cwd,
        chdir,
        tty: req.tty.clone(),
        session: proc.session_of(req.pid),
        untrusted: Untrusted {
            context: req.context.clone(),
            session: req.session.clone(),
        },
        timeout_secs: req.timeout_secs.clamp(5, 24 * 3600),
        hostd_version: hostd_version.to_string(),
    }
}

/// Render a final decision as the line the setuid binary understands.
pub fn decision_line(id: &str, decision: &Decision) -> Line {
    let via = match decision.via {
        DecidedVia::User => "user",
        DecidedVia::Grant => "grant",
        DecidedVia::Delegation => "delegation",
        DecidedVia::Policy => "policy",
    };
    match decision.state {
        RequestState::Approved => Line::new("approved")
            .with("id", id)
            .with("by", &decision.by)
            .with("via", via)
            .with("label", &decision.label)
            .with(
                "refresh",
                if decision.refresh_timestamp { "1" } else { "0" },
            ),
        RequestState::Denied => Line::new("denied")
            .with("id", id)
            .with("by", &decision.by)
            .with("via", via)
            .with("reason", decision.reason.clone().unwrap_or_default())
            .with("hard", if decision.hard { "1" } else { "0" }),
        RequestState::Expired | RequestState::Withdrawn | RequestState::Pending => {
            Line::new("expired").with("id", id)
        }
    }
}

async fn write_line(stream: &mut (impl AsyncWriteExt + Unpin), line: &Line) -> Result<()> {
    stream.write_all(line.render().as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

impl Relay {
    pub async fn serve(self: Arc<Self>, listener: UnixListener) -> Result<()> {
        loop {
            let (stream, _) = listener.accept().await?;
            let relay = self.clone();
            tokio::spawn(async move {
                if let Err(e) = relay.handle(stream).await {
                    tracing::warn!("request failed: {e:#}");
                }
            });
        }
    }

    async fn handle(&self, stream: UnixStream) -> Result<()> {
        let cred = stream.peer_cred()?;
        if !self.allow_peer_uids.contains(&cred.uid()) {
            bail!("rejected connection from uid {}", cred.uid());
        }
        let peer_pid = cred.pid().unwrap_or(0) as u32;
        let (read, mut write) = stream.into_split();
        let mut reader = BufReader::new(read);

        // Read the request block, bounded in size and time.
        let block = tokio::time::timeout(Duration::from_secs(10), async {
            let mut block = String::new();
            loop {
                let mut line = String::new();
                let n = (&mut reader)
                    .take(MAX_REQUEST as u64)
                    .read_line(&mut line)
                    .await?;
                if n == 0 {
                    bail!("connection closed before the request was complete");
                }
                block.push_str(&line);
                if block.len() > MAX_REQUEST {
                    bail!("request too large");
                }
                if line == "\n" {
                    return Ok(block);
                }
            }
        })
        .await
        .context("timed out reading request")??;

        let req = match LocalRequest::parse(&block) {
            Ok(req) => req,
            Err(e) => {
                write_line(
                    &mut write,
                    &Line::new("error").with("message", e.to_string()),
                )
                .await?;
                bail!("malformed request: {e}");
            }
        };
        if peer_pid != 0 && req.pid != peer_pid {
            write_line(
                &mut write,
                &Line::new("error").with("message", "pid mismatch"),
            )
            .await?;
            bail!("request pid {} does not match peer pid {peer_pid}", req.pid);
        }
        if let Some(real) = self.proc.real_uid(req.pid)
            && real != req.uid
        {
            write_line(
                &mut write,
                &Line::new("error").with("message", "uid mismatch"),
            )
            .await?;
            bail!("request uid {} does not match real uid {real}", req.uid);
        }

        let envelope = envelope_from(&req, &self.proc, &self.hostd_version);
        tracing::info!(
            user = %envelope.user.name,
            command = envelope.command.as_deref().unwrap_or("-"),
            session = %envelope.session.label,
            "submitting request"
        );
        let submitted = match self.client.submit(&envelope).await {
            Ok(r) => r,
            Err(e) => {
                write_line(
                    &mut write,
                    &Line::new("unavailable").with("reason", format!("{e:#}")),
                )
                .await?;
                return Err(e);
            }
        };
        let id = submitted.id.clone();
        if let Some(decision) = submitted.decision.filter(|d| d.state.is_final()) {
            write_line(&mut write, &decision_line(&id, &decision)).await?;
            return Ok(());
        }
        if envelope.nonblocking {
            // The service must answer non-blocking requests immediately.
            write_line(&mut write, &Line::new("expired").with("id", &id)).await?;
            return Ok(());
        }
        write_line(
            &mut write,
            &Line::new("pending")
                .with("id", &id)
                .with("code", &submitted.code)
                .with("url", &submitted.url),
        )
        .await?;

        let deadline =
            tokio::time::Instant::now() + Duration::from_secs(envelope.timeout_secs + 30);
        let mut client_line = String::new();
        loop {
            tokio::select! {
                read = reader.read_line(&mut client_line) => {
                    let reason = match read {
                        Ok(0) | Err(_) => "client disconnected".to_string(),
                        Ok(_) => Line::parse(&client_line)
                            .filter(|l| l.verb == "cancel")
                            .and_then(|l| l.get_str("reason"))
                            .unwrap_or_else(|| "cancelled".into()),
                    };
                    tracing::info!(%id, %reason, "request withdrawn by client");
                    if let Err(e) = self.client.cancel(&id, &reason).await {
                        tracing::warn!(%id, "cancel failed: {e:#}");
                    }
                    return Ok(());
                }
                polled = self.client.wait_decision(&id, LONG_POLL_SECS) => {
                    match polled {
                        Ok(resp) => {
                            if let Some(decision) = resp.decision.filter(|d| d.state.is_final()) {
                                write_line(&mut write, &decision_line(&id, &decision)).await?;
                                return Ok(());
                            }
                            if resp.state.is_final() {
                                write_line(&mut write, &Line::new("expired").with("id", &id)).await?;
                                return Ok(());
                            }
                        }
                        Err(e) => {
                            tracing::warn!(%id, "waiting for decision: {e:#}");
                            tokio::time::sleep(Duration::from_secs(3)).await;
                        }
                    }
                    if tokio::time::Instant::now() > deadline {
                        let _ = self.client.cancel(&id, "timeout").await;
                        write_line(&mut write, &Line::new("expired").with("id", &id)).await?;
                        return Ok(());
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_decisions_for_the_binary() {
        let d = Decision {
            state: RequestState::Approved,
            via: DecidedVia::Delegation,
            by: "delegation".into(),
            label: "NVIDIA driver work".into(),
            hard: false,
            refresh_timestamp: false,
            reason: None,
        };
        assert_eq!(
            decision_line("r1", &d).render(),
            "approved id=r1 by=delegation via=delegation label=NVIDIA%20driver%20work refresh=0\n"
        );
        let d = Decision {
            state: RequestState::Denied,
            via: DecidedVia::User,
            by: "tj".into(),
            label: String::new(),
            hard: true,
            refresh_timestamp: false,
            reason: Some("no".into()),
        };
        assert!(decision_line("r1", &d).render().ends_with("hard=1\n"));
    }

    #[test]
    fn marks_lossy_arguments() {
        let req = LocalRequest {
            mode: "run".into(),
            pid: 1,
            args: vec![b"ok".to_vec(), vec![0xff, 0xfe]],
            ..Default::default()
        };
        let env = envelope_from(&req, &Proc::new("/nonexistent", &[]), "t");
        assert!(env.lossy);
        assert_eq!(env.argv[0], "ok");
    }
}

//! Facts about the requesting process tree, read from /proc by root.
//!
//! These are what "approve for this agent session" binds to. The requester cannot
//! choose them: they come from the kernel, not from arguments or environment.

use std::path::{Path, PathBuf};

use agent_sudo_protocol::api::{ProcessInfo, SessionInfo};

/// Executable names that identify a coding agent, mapped to a display kind.
pub const DEFAULT_AGENTS: &[(&str, &str)] = &[
    ("claude", "claude"),
    ("claude-code", "claude"),
    ("codex", "codex"),
    ("codex-cli", "codex"),
    ("opencode", "opencode"),
    ("aider", "aider"),
    ("gemini", "gemini"),
    ("goose", "goose"),
    ("cursor-agent", "cursor"),
    ("amp", "amp"),
    ("crush", "crush"),
    ("qwen", "qwen"),
    ("zcode", "zcode"),
    ("dsh", "dsh"),
    ("hermes", "hermes"),
];

const MAX_DEPTH: usize = 24;
const MAX_CHAIN: usize = 8;
const MAX_CMDLINE: usize = 300;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stat {
    pub pid: u32,
    pub comm: String,
    pub ppid: u32,
    pub sid: u32,
    pub starttime: u64,
}

pub struct Proc {
    root: PathBuf,
    agents: Vec<(String, String)>,
}

fn basename(s: &str) -> &str {
    s.rsplit('/').next().unwrap_or(s)
}

fn clean(s: &str, max: usize) -> String {
    let mut out: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(max)
        .collect();
    if s.chars().count() > max {
        out.push('…');
    }
    out
}

impl Proc {
    pub fn new(root: impl Into<PathBuf>, extra_agents: &[String]) -> Self {
        let mut agents: Vec<(String, String)> = DEFAULT_AGENTS
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect();
        agents.extend(extra_agents.iter().map(|a| (a.clone(), a.clone())));
        Proc {
            root: root.into(),
            agents,
        }
    }

    fn path(&self, pid: u32, file: &str) -> PathBuf {
        self.root.join(pid.to_string()).join(file)
    }

    pub fn stat(&self, pid: u32) -> Option<Stat> {
        let text = std::fs::read_to_string(self.path(pid, "stat")).ok()?;
        // comm may contain spaces and parentheses: split at the last ')'.
        let open = text.find('(')?;
        let close = text.rfind(')')?;
        let comm = text.get(open + 1..close)?.to_string();
        let rest: Vec<&str> = text.get(close + 2..)?.split_whitespace().collect();
        // rest[0] = state (field 3), so field N is rest[N - 3].
        Some(Stat {
            pid,
            comm,
            ppid: rest.get(1)?.parse().ok()?,
            sid: rest.get(3)?.parse().ok()?,
            starttime: rest.get(19)?.parse().ok()?,
        })
    }

    pub fn cmdline(&self, pid: u32) -> Vec<String> {
        std::fs::read(self.path(pid, "cmdline"))
            .map(|bytes| {
                bytes
                    .split(|&b| b == 0)
                    .filter(|a| !a.is_empty())
                    .map(|a| String::from_utf8_lossy(a).into_owned())
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn exe(&self, pid: u32) -> Option<String> {
        std::fs::read_link(self.path(pid, "exe")).ok().map(|p| {
            p.to_string_lossy()
                .trim_end_matches(" (deleted)")
                .to_string()
        })
    }

    pub fn environ(&self, pid: u32) -> Vec<(String, String)> {
        std::fs::read(self.path(pid, "environ"))
            .map(|bytes| {
                bytes
                    .split(|&b| b == 0)
                    .filter_map(|kv| {
                        let kv = String::from_utf8_lossy(kv);
                        kv.split_once('=')
                            .map(|(k, v)| (k.to_string(), v.to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Primary and supplementary groups of a process, from /proc/<pid>/status.
    pub fn groups(&self, pid: u32) -> Vec<u32> {
        let Ok(text) = std::fs::read_to_string(self.path(pid, "status")) else {
            return vec![];
        };
        let mut out = Vec::new();
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("Gid:") {
                out.extend(
                    rest.split_whitespace()
                        .next()
                        .and_then(|g| g.parse::<u32>().ok()),
                );
            } else if let Some(rest) = line.strip_prefix("Groups:") {
                out.extend(
                    rest.split_whitespace()
                        .filter_map(|g| g.parse::<u32>().ok()),
                );
            }
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Real uid of a process, from /proc/<pid>/status.
    pub fn real_uid(&self, pid: u32) -> Option<u32> {
        let text = std::fs::read_to_string(self.path(pid, "status")).ok()?;
        text.lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|l| l.split_whitespace().next())
            .and_then(|u| u.parse().ok())
    }

    fn boot_id(&self) -> String {
        std::fs::read_to_string(self.root.join("sys/kernel/random/boot_id"))
            .map(|s| s.trim().replace('-', "").chars().take(12).collect())
            .unwrap_or_else(|_| "noboot".into())
    }

    fn agent_kind(&self, pid: u32, stat: &Stat) -> Option<String> {
        let argv = self.cmdline(pid);
        let mut names: Vec<String> = vec![stat.comm.clone()];
        if let Some(exe) = self.exe(pid) {
            names.push(basename(&exe).to_string());
        }
        // Interpreters (node, bun, python) running an agent script.
        for arg in argv.iter().take(2) {
            names.push(basename(arg).to_string());
        }
        for name in &names {
            let name = name.trim_end_matches(".js").trim_end_matches(".mjs");
            if let Some((_, kind)) = self.agents.iter().find(|(n, _)| n == name) {
                return Some(kind.clone());
            }
        }
        if argv
            .iter()
            .take(3)
            .any(|a| a.contains("@anthropic-ai/claude-code"))
        {
            return Some("claude".into());
        }
        if argv.iter().take(3).any(|a| a.contains("@openai/codex")) {
            return Some("codex".into());
        }
        None
    }

    /// Describe the session of the sudo process `pid`.
    pub fn session_of(&self, pid: u32) -> SessionInfo {
        let boot = self.boot_id();
        let own = self.stat(pid);
        let env = self.environ(pid);
        let env_has = |k: &str| env.iter().any(|(key, _)| key == k);
        let mut ssh = env_has("SSH_CONNECTION");

        let mut chain = Vec::new();
        let mut agent: Option<(String, Stat)> = None;
        let mut cursor = own.as_ref().map(|s| s.ppid).unwrap_or(0);
        for _ in 0..MAX_DEPTH {
            if cursor <= 1 {
                break;
            }
            let Some(stat) = self.stat(cursor) else { break };
            if chain.len() < MAX_CHAIN {
                chain.push(ProcessInfo {
                    pid: stat.pid,
                    name: clean(&stat.comm, 64),
                    cmdline: clean(&self.cmdline(cursor).join(" "), MAX_CMDLINE),
                });
            }
            if stat.comm == "sshd" || stat.comm.starts_with("sshd-") {
                ssh = true;
            }
            if agent.is_none()
                && let Some(kind) = self.agent_kind(cursor, &stat)
            {
                agent = Some((kind, stat.clone()));
            }
            cursor = stat.ppid;
        }

        // Environment markers set by agents on the processes they spawn.
        if agent.is_none() && env.iter().any(|(k, v)| k == "CLAUDECODE" && v == "1") {
            // Attribute to the session leader; the env is inherited, not verifiable.
            if let Some(leader) = own.as_ref().and_then(|s| self.stat(s.sid)) {
                agent = Some(("claude".into(), leader));
            }
        }

        match (agent, own) {
            (Some((kind, stat)), _) => SessionInfo {
                fingerprint: format!("{boot}:{}:{}", stat.pid, stat.starttime),
                label: format!("{kind} (pid {})", stat.pid),
                agent: Some(kind),
                chain,
                ssh,
            },
            (None, Some(own)) => {
                let leader = self.stat(own.sid);
                let (pid, start, comm) = leader.map(|l| (l.pid, l.starttime, l.comm)).unwrap_or((
                    own.sid,
                    0,
                    "session".into(),
                ));
                SessionInfo {
                    fingerprint: format!("{boot}:{pid}:{start}"),
                    label: format!("{} session (pid {pid})", clean(&comm, 32)),
                    agent: None,
                    chain,
                    ssh,
                }
            }
            (None, None) => SessionInfo {
                fingerprint: format!("{boot}:unknown:{pid}"),
                label: "unknown session".into(),
                agent: None,
                chain,
                ssh,
            },
        }
    }
}

pub fn proc_root() -> &'static Path {
    Path::new("/proc")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fake(root: &Path, pid: u32, comm: &str, ppid: u32, sid: u32, start: u64, argv: &[&str]) {
        let dir = root.join(pid.to_string());
        fs::create_dir_all(&dir).unwrap();
        // Fields after comm: state ppid pgrp session tty tpgid flags minflt cminflt majflt
        // cmajflt utime stime cutime cstime priority nice threads itrealvalue starttime
        fs::write(
            dir.join("stat"),
            format!(
                "{pid} ({comm}) S {ppid} {pid} {sid} 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 {start} 0 0"
            ),
        )
        .unwrap();
        fs::write(dir.join("cmdline"), argv.join("\0")).unwrap();
        fs::write(dir.join("status"), "Name:\tx\nUid:\t1000\t0\t0\t0\n").unwrap();
    }

    fn tree() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::create_dir_all(root.join("sys/kernel/random")).unwrap();
        fs::write(
            root.join("sys/kernel/random/boot_id"),
            "0123abcd-4567-89ef-0000-000000000000\n",
        )
        .unwrap();
        fake(root, 100, "tmux: server", 1, 100, 10, &["tmux"]);
        fake(root, 200, "bash", 100, 200, 20, &["-bash"]);
        fake(
            root,
            300,
            "node",
            200,
            200,
            30,
            &[
                "node",
                "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js",
            ],
        );
        fake(
            root,
            400,
            "bash",
            300,
            200,
            40,
            &["/bin/bash", "-c", "sudo apt install x"],
        );
        fake(
            root,
            500,
            "sudo",
            400,
            200,
            50,
            &["sudo", "apt", "install", "x"],
        );
        tmp
    }

    #[test]
    fn parses_stat_with_odd_comm() {
        let tmp = tempfile::tempdir().unwrap();
        fake(tmp.path(), 7, "we(ird) name", 1, 7, 99, &["x"]);
        let stat = Proc::new(tmp.path(), &[]).stat(7).unwrap();
        assert_eq!(stat.comm, "we(ird) name");
        assert_eq!(stat.ppid, 1);
        assert_eq!(stat.starttime, 99);
    }

    #[test]
    fn detects_agent_ancestor() {
        let tmp = tree();
        let info = Proc::new(tmp.path(), &[]).session_of(500);
        assert_eq!(info.agent.as_deref(), Some("claude"));
        assert_eq!(info.fingerprint, "0123abcd4567:300:30");
        assert_eq!(info.label, "claude (pid 300)");
        assert_eq!(info.chain[0].pid, 400);
        assert_eq!(info.chain.len(), 4);
        assert_eq!(Proc::new(tmp.path(), &[]).real_uid(500), Some(1000));
    }

    #[test]
    fn falls_back_to_session_leader() {
        let tmp = tree();
        fs::write(tmp.path().join("300/cmdline"), "node\0server.js").unwrap();
        let info = Proc::new(tmp.path(), &[]).session_of(500);
        assert_eq!(info.agent, None);
        assert_eq!(info.fingerprint, "0123abcd4567:200:20");
        assert_eq!(info.label, "bash session (pid 200)");
    }

    #[test]
    fn extra_agents_from_config() {
        let tmp = tree();
        fs::write(tmp.path().join("300/cmdline"), "mybot\0--serve").unwrap();
        fs::write(
            tmp.path().join("300/stat"),
            "300 (mybot) S 200 300 200 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 30 0 0",
        )
        .unwrap();
        let info = Proc::new(tmp.path(), &["mybot".into()]).session_of(500);
        assert_eq!(info.agent.as_deref(), Some("mybot"));
    }
}

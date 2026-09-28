//! Deterministic policy: command classes, request features, and scope envelopes.
//!
//! Everything here is pure and testable. The advisor and the UI consume its output;
//! nothing here depends on a model.

use std::collections::BTreeSet;

use agent_sudo_protocol::api::{Launch, Mode, RequestEnvelope};
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum StepUp {
    /// Any logged-in approver session.
    #[default]
    None,
    /// A passkey assertion within `sessions.strong_auth_minutes`.
    Recent,
    /// A fresh passkey assertion for this decision.
    Always,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClassConfig {
    pub name: String,
    #[serde(default)]
    pub title: String,
    /// Absolute paths or basenames. Empty matches any command.
    #[serde(default)]
    pub executables: Vec<String>,
    /// Leading arguments that must match exactly.
    #[serde(default)]
    pub argv_prefix: Vec<String>,
    /// Match requests that carry any of these features.
    #[serde(default)]
    pub features: Vec<String>,
    /// Restrict to these modes (run, edit, list, validate).
    #[serde(default)]
    pub modes: Vec<Mode>,
    /// Longest grant an approver may create for this class, in minutes.
    #[serde(default = "default_max_ttl")]
    pub max_ttl_minutes: u32,
    /// Grants are not allowed: every request needs its own decision.
    #[serde(default)]
    pub require_each_time: bool,
    #[serde(default)]
    pub step_up: StepUp,
    /// A remote denial also blocks the local password path.
    #[serde(default)]
    pub hard_deny: bool,
    /// Delegations may approve requests in this class.
    #[serde(default = "yes")]
    pub delegable: bool,
    /// Deny without asking anyone.
    #[serde(default)]
    pub always_deny: bool,
    /// Quick-approve from a notification action is allowed.
    #[serde(default = "yes")]
    pub quick_approve: bool,
}

fn default_max_ttl() -> u32 {
    240
}
fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AutomationConfig {
    /// Master switch for delegated decisions. The UI kill switch is stored separately
    /// and can only further disable automation.
    pub enabled: bool,
    /// Longest delegation an approver may create, in minutes.
    pub max_ttl_minutes: u32,
    /// Most requests one delegation may approve before pausing.
    pub max_decisions: u32,
    /// Pause a delegation after this many consecutive declined evaluations.
    pub pause_after_declines: u32,
    /// Features no delegation may approve, whatever its own settings say.
    pub forbidden_features: Vec<String>,
}

impl Default for AutomationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_ttl_minutes: 8 * 60,
            max_decisions: 100,
            pause_after_declines: 5,
            forbidden_features: vec![
                "approval_system".into(),
                "credential_access".into(),
                "validate".into(),
                "lossy".into(),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PolicyConfig {
    /// Classes are evaluated in order; the first match wins. When empty, the built-in
    /// classes are used. Set `builtin_classes = false` to use only your own.
    pub classes: Vec<ClassConfig>,
    pub builtin_classes: bool,
    pub default_max_ttl_minutes: u32,
    pub automation: AutomationConfig,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            classes: vec![],
            builtin_classes: true,
            default_max_ttl_minutes: 240,
            automation: AutomationConfig::default(),
        }
    }
}

fn class(name: &str, title: &str) -> ClassConfig {
    ClassConfig {
        name: name.into(),
        title: title.into(),
        executables: vec![],
        argv_prefix: vec![],
        features: vec![],
        modes: vec![],
        max_ttl_minutes: 240,
        require_each_time: false,
        step_up: StepUp::None,
        hard_deny: false,
        delegable: true,
        always_deny: false,
        quick_approve: true,
    }
}

pub fn builtin_classes() -> Vec<ClassConfig> {
    vec![
        ClassConfig {
            features: vec!["approval_system".into()],
            max_ttl_minutes: 0,
            require_each_time: true,
            step_up: StepUp::Always,
            hard_deny: true,
            delegable: false,
            quick_approve: false,
            ..class("approval-system", "Changes to sudo or agent-sudo itself")
        },
        ClassConfig {
            modes: vec![Mode::Validate],
            max_ttl_minutes: 0,
            require_each_time: true,
            step_up: StepUp::Recent,
            delegable: false,
            quick_approve: false,
            ..class("sudo-session", "Unlock ordinary sudo (sudo -v)")
        },
        ClassConfig {
            features: vec!["credential_access".into()],
            max_ttl_minutes: 15,
            require_each_time: true,
            step_up: StepUp::Recent,
            delegable: false,
            quick_approve: false,
            ..class("credentials", "Accounts, passwords and keys")
        },
        ClassConfig {
            features: vec!["root_shell".into()],
            max_ttl_minutes: 15,
            require_each_time: true,
            step_up: StepUp::Recent,
            delegable: false,
            quick_approve: false,
            ..class("root-shell", "Unrestricted root execution")
        },
        ClassConfig {
            features: vec!["destructive".into()],
            max_ttl_minutes: 30,
            step_up: StepUp::Recent,
            quick_approve: false,
            ..class(
                "destructive",
                "Potentially destructive disk or data operations",
            )
        },
        ClassConfig {
            features: vec!["package_manager".into()],
            max_ttl_minutes: 240,
            ..class("packages", "Package management")
        },
        ClassConfig {
            features: vec!["service_control".into()],
            max_ttl_minutes: 240,
            ..class("services", "Service control")
        },
        ClassConfig {
            modes: vec![Mode::List],
            max_ttl_minutes: 480,
            ..class("inspect", "List sudo privileges")
        },
        class("default", "Privileged command"),
    ]
}

impl PolicyConfig {
    pub fn validate(&self) -> Result<()> {
        let mut names = BTreeSet::new();
        for c in &self.classes {
            if c.name.is_empty() || !names.insert(c.name.clone()) {
                bail!(
                    "policy class names must be unique and non-empty ({:?})",
                    c.name
                );
            }
        }
        Ok(())
    }

    pub fn effective_classes(&self) -> Vec<ClassConfig> {
        let mut classes = self.classes.clone();
        if self.builtin_classes || classes.is_empty() {
            let own: BTreeSet<String> = classes.iter().map(|c| c.name.clone()).collect();
            classes.extend(
                builtin_classes()
                    .into_iter()
                    .filter(|c| !own.contains(&c.name)),
            );
        }
        // Guarantee a catch-all at the end.
        if !classes.iter().any(|c| {
            c.executables.is_empty()
                && c.features.is_empty()
                && c.modes.is_empty()
                && c.argv_prefix.is_empty()
        }) {
            classes.push(ClassConfig {
                max_ttl_minutes: self.default_max_ttl_minutes,
                ..class("default", "Privileged command")
            });
        }
        classes
    }

    pub fn classify(&self, env: &RequestEnvelope, features: &Features) -> ClassConfig {
        self.effective_classes()
            .into_iter()
            .find(|c| class_matches(c, env, features))
            .expect("catch-all class exists")
    }
}

fn basename(s: &str) -> &str {
    s.rsplit('/').next().unwrap_or(s)
}

fn class_matches(c: &ClassConfig, env: &RequestEnvelope, features: &Features) -> bool {
    if !c.modes.is_empty() && !c.modes.contains(&env.mode) {
        return false;
    }
    if !c.executables.is_empty() {
        let Some(cmd) = env.command.as_deref() else {
            return false;
        };
        let hit = c.executables.iter().any(|e| {
            if e.contains('/') {
                e == cmd
            } else {
                e == basename(cmd)
            }
        });
        if !hit {
            return false;
        }
    }
    if !c.argv_prefix.is_empty()
        && (env.argv.len() < c.argv_prefix.len()
            || env.argv[..c.argv_prefix.len()] != c.argv_prefix[..])
    {
        return false;
    }
    if !c.features.is_empty() && !c.features.iter().any(|f| features.has(f)) {
        return false;
    }
    true
}

/// A deterministic observation about a request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Feature {
    pub key: String,
    pub label: String,
    /// info | warn | danger
    pub level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Features(pub Vec<Feature>);

impl Features {
    pub fn has(&self, key: &str) -> bool {
        self.0.iter().any(|f| f.key == key)
    }

    fn add(&mut self, key: &str, level: &str, label: impl Into<String>) {
        if !self.has(key) {
            self.0.push(Feature {
                key: key.into(),
                label: label.into(),
                level: level.into(),
            });
        }
    }

    pub fn keys(&self) -> Vec<String> {
        self.0.iter().map(|f| f.key.clone()).collect()
    }
}

const SHELLS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "fish",
    "ksh",
    "csh",
    "tcsh",
    "su",
    "sudo",
    "doas",
    "busybox",
    "script",
    "tmux",
    "screen",
    "nsenter",
    "chroot",
    "unshare",
    "systemd-run",
    "machinectl",
    "pkexec",
    "runuser",
    "setpriv",
];
const INTERPRETERS: &[&str] = &[
    "python", "python3", "python2", "perl", "ruby", "node", "nodejs", "bun", "deno", "lua", "php",
    "tclsh", "expect", "gdb", "awk", "gawk", "mawk", "julia", "Rscript", "irb", "ipython",
];
const EDITORS_WITH_ESCAPES: &[&str] = &[
    "vi", "vim", "nvim", "emacs", "less", "more", "man", "nano", "ed", "view",
];
const EXEC_WRAPPERS: &[&str] = &[
    "env", "xargs", "find", "nice", "nohup", "timeout", "stdbuf", "ionice", "taskset", "watch",
    "flock", "strace", "ltrace", "time",
];
const CONTAINERS: &[&str] = &[
    "docker", "podman", "ctr", "nerdctl", "crictl", "kubectl", "lxc", "incus", "virsh",
];
const PACKAGE_MANAGERS: &[&str] = &[
    "apt",
    "apt-get",
    "aptitude",
    "dpkg",
    "snap",
    "dnf",
    "yum",
    "rpm",
    "zypper",
    "pacman",
    "apk",
    "flatpak",
    "pip",
    "pip3",
    "pipx",
    "npm",
    "pnpm",
    "yarn",
    "gem",
    "cargo",
    "brew",
    "nix-env",
    "ubuntu-drivers",
];
const SERVICE_CONTROL: &[&str] = &[
    "systemctl",
    "service",
    "rc-service",
    "journalctl",
    "loginctl",
    "supervisorctl",
];
const DESTRUCTIVE: &[&str] = &[
    "dd",
    "mkfs",
    "wipefs",
    "fdisk",
    "sfdisk",
    "gdisk",
    "sgdisk",
    "parted",
    "shred",
    "blkdiscard",
    "truncate",
    "lvremove",
    "vgremove",
    "pvremove",
    "mdadm",
    "cryptsetup",
];
const NETWORK: &[&str] = &[
    "iptables",
    "ip6tables",
    "iptables-restore",
    "nft",
    "ufw",
    "firewall-cmd",
    "ip",
    "route",
    "tailscale",
    "wg",
    "wg-quick",
    "nmcli",
    "netplan",
    "resolvectl",
    "ethtool",
    "tc",
];
const KERNEL: &[&str] = &[
    "modprobe",
    "insmod",
    "rmmod",
    "dkms",
    "sysctl",
    "update-initramfs",
    "update-grub",
    "grub-install",
    "kexec",
    "mokutil",
    "nvidia-smi",
];
const AVAILABILITY: &[&str] = &[
    "reboot", "shutdown", "poweroff", "halt", "kill", "killall", "pkill", "init", "telinit",
];
const ACCOUNTS: &[&str] = &[
    "passwd",
    "chpasswd",
    "useradd",
    "usermod",
    "userdel",
    "adduser",
    "deluser",
    "groupadd",
    "groupmod",
    "gpasswd",
    "chage",
    "vipw",
    "vigr",
    "newusers",
    "ssh-keygen",
];
const WRITERS: &[&str] = &[
    "tee", "cp", "mv", "install", "ln", "rsync", "chmod", "chown", "chgrp", "chattr", "rm",
    "mkdir", "touch", "sed", "patch", "tar", "unzip",
];

const APPROVAL_PATHS: &[&str] = &[
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/etc/agent-sudo",
    "/etc/pam.d",
    "/usr/local/bin/agent-sudo",
    "/usr/local/sbin/agent-sudo",
    "/etc/systemd/system/agent-sudo",
    "agent-sudo-hostd",
    "/etc/security",
    "/usr/bin/sudo",
    "/usr/lib/cargo/bin/sudo",
    "/etc/alternatives/sudo",
];
const APPROVAL_COMMANDS: &[&str] = &[
    "visudo",
    "update-alternatives",
    "sudoedit",
    "agent-sudo-hostd",
];
const CREDENTIAL_PATHS: &[&str] = &[
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/passwd",
    "/etc/group",
    "/.ssh",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "authorized_keys",
    ".gnupg",
    "/etc/ssl/private",
    "/var/lib/tailscale",
    ".kube/config",
    ".aws/credentials",
    ".docker/config.json",
    "/etc/ssh/ssh_host_",
];

fn name_in(cmd: &str, list: &[&str]) -> bool {
    let name = basename(cmd);
    list.iter().any(|n| {
        name == *n
            || (name.starts_with(n)
                && name[n.len()..]
                    .chars()
                    .all(|c| c.is_ascii_digit() || c == '.'))
            || (*n == "mkfs" && name.starts_with("mkfs."))
    })
}

/// Compute deterministic features for a request.
pub fn features(env: &RequestEnvelope) -> Features {
    let mut f = Features::default();
    let cmd = env.command.clone().unwrap_or_default();
    let all_text: Vec<&str> = std::iter::once(cmd.as_str())
        .chain(env.argv.iter().map(String::as_str))
        .chain(env.chdir.iter().map(String::as_str))
        .collect();
    let mentions = |needle: &str| all_text.iter().any(|a| a.contains(needle));

    match env.mode {
        Mode::Validate => f.add(
            "validate",
            "danger",
            "Refreshes the ordinary sudo timestamp, unlocking any sudo command",
        ),
        Mode::List => f.add("inspect", "info", "Only lists sudo privileges"),
        Mode::Edit => f.add(
            "file_write",
            "warn",
            "Edits files as the target user (sudoedit)",
        ),
        Mode::Run => {}
    }
    if env.lossy {
        f.add(
            "lossy",
            "warn",
            "Some arguments are not valid UTF-8; shown approximately",
        );
    }
    if matches!(env.launch, Launch::Shell | Launch::Login) {
        f.add("root_shell", "danger", "Opens an interactive root shell");
    }
    if !cmd.is_empty() {
        if name_in(&cmd, SHELLS) || name_in(&cmd, INTERPRETERS) {
            f.add(
                "root_shell",
                "danger",
                "Runs a shell or interpreter: arbitrary code as root",
            );
        } else if name_in(&cmd, EDITORS_WITH_ESCAPES) {
            f.add("root_shell", "danger", "Editor or pager with shell escapes");
        } else if name_in(&cmd, EXEC_WRAPPERS) {
            let execs = basename(&cmd) != "find"
                || env
                    .argv
                    .iter()
                    .any(|a| a.starts_with("-exec") || a.starts_with("-ok") || a == "-delete");
            if execs {
                f.add(
                    "root_shell",
                    "danger",
                    "Wrapper that can execute other commands",
                );
            }
        }
        if name_in(&cmd, CONTAINERS) {
            f.add(
                "root_shell",
                "danger",
                "Container runtimes are root-equivalent",
            );
        }
        if name_in(&cmd, PACKAGE_MANAGERS) {
            f.add(
                "package_manager",
                "warn",
                "Installs or changes system packages",
            );
        }
        if name_in(&cmd, SERVICE_CONTROL) {
            f.add("service_control", "warn", "Controls system services");
        }
        if name_in(&cmd, DESTRUCTIVE) {
            f.add("destructive", "danger", "Can destroy data or disks");
        }
        if basename(&cmd) == "rm"
            && env.argv.iter().any(|a| {
                a.starts_with('-') && !a.starts_with("--") && (a.contains('r') || a.contains('R'))
                    || a == "--recursive"
            })
        {
            f.add("destructive", "danger", "Recursive delete");
        }
        if name_in(&cmd, NETWORK) {
            f.add(
                "network_security",
                "warn",
                "Changes network or firewall configuration",
            );
        }
        if name_in(&cmd, KERNEL) {
            f.add(
                "kernel",
                "warn",
                "Kernel modules, boot or kernel parameters",
            );
        }
        if name_in(&cmd, AVAILABILITY)
            || (basename(&cmd) == "systemctl"
                && env.argv.first().is_some_and(|a| {
                    matches!(
                        a.as_str(),
                        "stop"
                            | "restart"
                            | "reboot"
                            | "poweroff"
                            | "halt"
                            | "kill"
                            | "isolate"
                            | "rescue"
                            | "emergency"
                    )
                }))
        {
            f.add(
                "availability",
                "warn",
                "Stops, restarts or signals processes or the machine",
            );
        }
        if name_in(&cmd, ACCOUNTS) {
            f.add(
                "credential_access",
                "danger",
                "Changes accounts, passwords or keys",
            );
        }
        if name_in(&cmd, WRITERS) {
            f.add("file_write", "info", "Writes or changes files");
        }
        if name_in(&cmd, APPROVAL_COMMANDS) {
            f.add(
                "approval_system",
                "danger",
                "Touches sudo or agent-sudo configuration",
            );
        }
    }
    if APPROVAL_PATHS.iter().any(|p| mentions(p)) {
        f.add(
            "approval_system",
            "danger",
            "Touches sudo or agent-sudo configuration",
        );
    }
    let root_home = all_text
        .iter()
        .any(|a| *a == "/root" || a.starts_with("/root/"));
    if root_home || CREDENTIAL_PATHS.iter().any(|p| mentions(p)) {
        f.add(
            "credential_access",
            "danger",
            "Reads or writes credentials or keys",
        );
    }
    if env.argv.iter().any(|a| {
        a.starts_with("/etc/")
            || a.starts_with("/boot/")
            || a.starts_with("/usr/lib/systemd/")
            || a.starts_with("/lib/modules/")
    }) {
        f.add(
            "system_config",
            "warn",
            "Mentions system configuration paths",
        );
    }
    if env.target.uid != 0 {
        f.add(
            "non_root_target",
            "info",
            format!("Runs as {} rather than root", env.target.user),
        );
    }
    f
}

/// Canonical key for "the same command": mode, target, command, and arguments.
pub fn command_key(env: &RequestEnvelope) -> String {
    serde_json::json!([
        env.mode,
        env.target.uid,
        env.command.clone().unwrap_or_default(),
        env.argv,
    ])
    .to_string()
}

/// Human-readable rendering of the command line, shell-quoted.
pub fn display_command(env: &RequestEnvelope) -> String {
    fn quote(s: &str) -> String {
        if !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_./=:,+@%^".contains(c))
        {
            s.to_string()
        } else {
            format!("'{}'", s.replace('\'', "'\\''"))
        }
    }
    match env.mode {
        Mode::Validate => "sudo -v".into(),
        Mode::List => "sudo -l".into(),
        Mode::Edit => format!(
            "sudoedit {}",
            env.argv
                .iter()
                .map(|a| quote(a))
                .collect::<Vec<_>>()
                .join(" ")
        ),
        Mode::Run => {
            let mut parts = vec![quote(env.command.as_deref().unwrap_or("?"))];
            parts.extend(env.argv.iter().map(|a| quote(a)));
            let line = parts.join(" ");
            match env.launch {
                Launch::Login => format!("sudo -i {line}"),
                Launch::Shell => format!("sudo -s {line}"),
                Launch::Direct => line,
            }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use agent_sudo_protocol::api::{Principal, SessionInfo, Target, Untrusted};

    pub fn env(cmd: &str, args: &[&str]) -> RequestEnvelope {
        RequestEnvelope {
            client_request_id: "c1".into(),
            mode: Mode::Run,
            nonblocking: false,
            interactive: false,
            hostname: "moa".into(),
            user: Principal {
                name: "tj".into(),
                uid: 1000,
                gid: 1000,
            },
            target: Target {
                user: "root".into(),
                uid: 0,
                group: Some("root".into()),
                gid: 0,
            },
            launch: Launch::Direct,
            command: Some(cmd.into()),
            argv: args.iter().map(|s| s.to_string()).collect(),
            lossy: false,
            cwd: Some("/home/tj".into()),
            chdir: None,
            tty: None,
            session: SessionInfo {
                fingerprint: "b:1:2".into(),
                label: "claude (pid 1)".into(),
                agent: Some("claude".into()),
                chain: vec![],
                ssh: false,
            },
            untrusted: Untrusted::default(),
            timeout_secs: 600,
            hostd_version: "t".into(),
        }
    }

    #[test]
    fn classifies_common_commands() {
        let p = PolicyConfig::default();
        let check = |cmd: &str, args: &[&str]| {
            let e = env(cmd, args);
            p.classify(&e, &features(&e)).name
        };
        assert_eq!(check("/usr/bin/apt", &["install", "-y", "jq"]), "packages");
        assert_eq!(
            check("/usr/bin/systemctl", &["restart", "docker"]),
            "services"
        );
        assert_eq!(check("/usr/bin/bash", &["-c", "id"]), "root-shell");
        assert_eq!(check("/usr/bin/python3", &["x.py"]), "root-shell");
        assert_eq!(
            check("/usr/bin/docker", &["run", "-it", "ubuntu"]),
            "root-shell"
        );
        assert_eq!(
            check("/usr/bin/tee", &["/etc/sudoers.d/x"]),
            "approval-system"
        );
        assert_eq!(check("/usr/bin/cat", &["/etc/shadow"]), "credentials");
        assert_eq!(check("/usr/bin/rm", &["-rf", "/var/tmp/x"]), "destructive");
        assert_eq!(check("/usr/sbin/mkfs.ext4", &["/dev/sdb1"]), "destructive");
        assert_eq!(check("/usr/bin/ls", &["/root"]), "credentials");
        assert_eq!(check("/usr/bin/ls", &["/var/log"]), "default");
        assert_eq!(
            check("/usr/bin/find", &["/var/log", "-name", "x"]),
            "default"
        );
        assert_eq!(
            check("/usr/bin/find", &["/", "-exec", "sh", ";"]),
            "root-shell"
        );
    }

    #[test]
    fn modes_classify() {
        let p = PolicyConfig::default();
        let mut e = env("", &[]);
        e.command = None;
        e.mode = Mode::Validate;
        assert_eq!(p.classify(&e, &features(&e)).name, "sudo-session");
        e.mode = Mode::List;
        assert_eq!(p.classify(&e, &features(&e)).name, "inspect");
    }

    #[test]
    fn custom_classes_come_first() {
        let p: PolicyConfig = toml::from_str(
            r#"
            [[classes]]
            name = "nvidia"
            executables = ["/usr/bin/systemctl"]
            argv_prefix = ["restart", "nvidia-persistenced"]
            max_ttl_minutes = 60
            "#,
        )
        .unwrap();
        let e = env("/usr/bin/systemctl", &["restart", "nvidia-persistenced"]);
        assert_eq!(p.classify(&e, &features(&e)).name, "nvidia");
        let e = env("/usr/bin/systemctl", &["restart", "docker"]);
        assert_eq!(p.classify(&e, &features(&e)).name, "services");
    }

    #[test]
    fn displays_commands() {
        let e = env("/usr/bin/apt", &["install", "linux-headers-6.17", "it's"]);
        assert_eq!(
            display_command(&e),
            "/usr/bin/apt install linux-headers-6.17 'it'\\''s'"
        );
    }

    #[test]
    fn command_key_distinguishes_arguments() {
        assert_ne!(
            command_key(&env("/bin/x", &["a b"])),
            command_key(&env("/bin/x", &["a", "b"]))
        );
    }
}

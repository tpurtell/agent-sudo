//! `/etc/agent-sudo/client.conf`: the only local configuration the setuid binary reads.
//!
//! When the file does not exist the broker is disabled and `agent-sudo` behaves exactly
//! like upstream sudo-rs. Installing the binary alone therefore changes nothing.
#![forbid(unsafe_code)]

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub(crate) const CONFIG_PATH: &str = "/etc/agent-sudo/client.conf";
const DEFAULT_SOCKET: &str = "/run/agent-sudo/hostd.sock";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unavailable {
    /// Fall back to the normal password prompt when a terminal is available.
    Password,
    /// Refuse, even when a terminal is available.
    Deny,
}

#[derive(Debug, Clone)]
pub(crate) struct ClientConfig {
    pub socket: PathBuf,
    pub timeout: Duration,
    pub on_unavailable: Unavailable,
    pub notice: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            socket: PathBuf::from(DEFAULT_SOCKET),
            timeout: Duration::from_secs(600),
            on_unavailable: Unavailable::Password,
            notice: true,
        }
    }
}

pub(crate) fn parse_duration(value: &str) -> Option<Duration> {
    let value = value.trim();
    let (digits, unit) = match value.find(|c: char| !c.is_ascii_digit()) {
        Some(i) => value.split_at(i),
        None => (value, "s"),
    };
    let n: u64 = digits.parse().ok()?;
    let secs = match unit {
        "s" => n,
        "m" => n.checked_mul(60)?,
        "h" => n.checked_mul(3600)?,
        _ => return None,
    };
    Some(Duration::from_secs(secs))
}

impl ClientConfig {
    /// Load the config. `Ok(None)` means the broker is not configured on this host.
    pub(crate) fn load() -> Result<Option<Self>, String> {
        Self::load_from(Path::new(CONFIG_PATH), true)
    }

    pub(crate) fn load_from(path: &Path, check_owner: bool) -> Result<Option<Self>, String> {
        let meta = match fs::symlink_metadata(path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        if check_owner && (!meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0) {
            return Err(format!(
                "{}: must be a regular file owned by root and not group/world writable",
                path.display()
            ));
        }
        let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::parse(&text).map(Some)
    }

    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        let mut cfg = ClientConfig::default();
        for (n, raw) in text.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                return Err(format!("line {}: expected key = value", n + 1));
            };
            let (key, value) = (key.trim(), value.trim());
            match key {
                "socket" => {
                    let path = PathBuf::from(value);
                    if !path.is_absolute() {
                        return Err(format!("line {}: socket must be absolute", n + 1));
                    }
                    cfg.socket = path;
                }
                "timeout" => {
                    cfg.timeout = parse_duration(value)
                        .ok_or_else(|| format!("line {}: invalid duration", n + 1))?;
                }
                "on_unavailable" => {
                    cfg.on_unavailable = match value {
                        "password" => Unavailable::Password,
                        "deny" => Unavailable::Deny,
                        _ => return Err(format!("line {}: expected password or deny", n + 1)),
                    }
                }
                "notice" => {
                    cfg.notice = match value {
                        "true" | "yes" | "on" => true,
                        "false" | "no" | "off" => false,
                        _ => return Err(format!("line {}: expected true or false", n + 1)),
                    }
                }
                // Unknown keys are ignored so hostd-side tooling can add keys safely.
                _ => {}
            }
        }
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_config() {
        let cfg = ClientConfig::parse(
            "# comment\nsocket = /run/x.sock\ntimeout = 5m\non_unavailable = deny # trailing\nnotice=false\nfuture = 1\n",
        )
        .unwrap();
        assert_eq!(cfg.socket, PathBuf::from("/run/x.sock"));
        assert_eq!(cfg.timeout, Duration::from_secs(300));
        assert_eq!(cfg.on_unavailable, Unavailable::Deny);
        assert!(!cfg.notice);
    }

    #[test]
    fn rejects_bad_values() {
        assert!(ClientConfig::parse("socket = relative").is_err());
        assert!(ClientConfig::parse("timeout = 5x").is_err());
        assert!(ClientConfig::parse("garbage").is_err());
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("90"), Some(Duration::from_secs(90)));
        assert_eq!(parse_duration("2h"), Some(Duration::from_secs(7200)));
        assert_eq!(parse_duration("m"), None);
    }

    #[test]
    fn missing_file_disables_broker() {
        assert!(
            ClientConfig::load_from(Path::new("/nonexistent/agent-sudo.conf"), true)
                .unwrap()
                .is_none()
        );
    }
}

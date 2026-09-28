//! `/etc/agent-sudo/hostd.toml`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

pub const DEFAULT_CONFIG: &str = "/etc/agent-sudo/hostd.toml";
pub const DEFAULT_KEY: &str = "/etc/agent-sudo/host.key";
pub const DEFAULT_SOCKET: &str = "/run/agent-sudo/hostd.sock";
pub const CLIENT_CONF: &str = "/etc/agent-sudo/client.conf";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostdConfig {
    /// Base URL of the approval service, e.g. `https://sudo.example.ts.net`.
    pub service_url: String,
    /// Assigned by the service at enrollment.
    pub host_id: String,
    #[serde(default = "default_key")]
    pub key_file: PathBuf,
    #[serde(default = "default_socket")]
    pub socket: PathBuf,
    /// Extra PEM trust anchor for the service (self-hosted CA, tests).
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    /// Additional executable names that identify a coding agent session.
    #[serde(default)]
    pub agent_executables: Vec<String>,
    /// Peer uids allowed on the socket. Only root in production; tests may add their uid.
    #[serde(default = "default_peers")]
    pub allow_peer_uids: Vec<u32>,
    /// Heartbeat interval in seconds.
    #[serde(default = "default_heartbeat")]
    pub heartbeat_secs: u64,
}

fn default_key() -> PathBuf {
    PathBuf::from(DEFAULT_KEY)
}
fn default_socket() -> PathBuf {
    PathBuf::from(DEFAULT_SOCKET)
}
fn default_peers() -> Vec<u32> {
    vec![0]
}
fn default_heartbeat() -> u64 {
    60
}

impl HostdConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let cfg: HostdConfig =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        let url = self.service_url.trim_end_matches('/');
        if !(url.starts_with("https://")
            || url.starts_with("http://127.0.0.1")
            || url.starts_with("http://localhost"))
        {
            bail!("service_url must use https (plain http is only allowed for localhost)");
        }
        if self.host_id.is_empty() {
            bail!("host_id is empty; run `agent-sudo-hostd enroll` first");
        }
        if !self.socket.is_absolute() {
            bail!("socket must be an absolute path");
        }
        Ok(())
    }

    pub fn service_base(&self) -> &str {
        self.service_url.trim_end_matches('/')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_config() {
        let cfg: HostdConfig =
            toml::from_str("service_url = \"https://sudo.example.net/\"\nhost_id = \"h1\"\n")
                .unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.service_base(), "https://sudo.example.net");
        assert_eq!(cfg.allow_peer_uids, vec![0]);
        assert_eq!(cfg.socket, PathBuf::from(DEFAULT_SOCKET));
    }

    #[test]
    fn rejects_plain_http() {
        let cfg: HostdConfig =
            toml::from_str("service_url = \"http://sudo.example.net\"\nhost_id = \"h1\"\n")
                .unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_unknown_keys() {
        assert!(
            toml::from_str::<HostdConfig>(
                "service_url = \"https://x\"\nhost_id = \"h\"\nbogus = 1\n"
            )
            .is_err()
        );
    }
}

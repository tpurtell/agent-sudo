//! Service configuration (`agent-sudo.toml`).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::advisor::AdvisorConfig;
use crate::policy::PolicyConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    /// Public origin used for WebAuthn, cookies, links, and push, e.g.
    /// `https://agent-sudo.tailnet.ts.net`. Must be the exact URL browsers use.
    pub public_url: String,
    /// Display name shown in the UI and in passkey prompts.
    #[serde(default = "default_name")]
    pub name: String,
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    #[serde(default = "default_db")]
    pub database: PathBuf,
    /// Addresses of reverse proxies whose X-Forwarded-For is trusted.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    #[serde(default)]
    pub sessions: SessionConfig,
    #[serde(default)]
    pub push: PushConfig,
    #[serde(default)]
    pub advisor: Option<AdvisorConfig>,
    #[serde(default)]
    pub policy: PolicyConfig,
    /// Serve the UI from this directory instead of the embedded copy (development).
    #[serde(default)]
    pub web_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SessionConfig {
    pub idle_days: u32,
    pub absolute_days: u32,
    /// How long a passkey assertion counts as "recent" for ordinary step-up.
    pub strong_auth_minutes: u32,
    /// Allow password login for users who have registered a passkey.
    pub password_after_passkey: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            idle_days: 7,
            absolute_days: 30,
            strong_auth_minutes: 5,
            password_after_passkey: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PushConfig {
    pub enabled: bool,
    /// VAPID subject, a mailto: or https: URL identifying the operator.
    pub subject: String,
}

impl Default for PushConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            subject: "mailto:admin@localhost".into(),
        }
    }
}

fn default_name() -> String {
    "agent-sudo".into()
}
fn default_listen() -> SocketAddr {
    "0.0.0.0:8080".parse().unwrap()
}
fn default_db() -> PathBuf {
    PathBuf::from("/data/agent-sudo.db")
}

impl ServiceConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let text = expand_env(&text)?;
        let cfg: ServiceConfig =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        let url = url::Url::parse(&self.public_url).context("public_url is not a URL")?;
        if url.scheme() != "https" && url.host_str() != Some("localhost") {
            bail!("public_url must be https (passkeys and push require a secure origin)");
        }
        if url.path() != "/" || url.query().is_some() {
            bail!("public_url must be an origin without a path");
        }
        self.policy.validate()?;
        if let Some(advisor) = &self.advisor {
            advisor.validate()?;
        }
        Ok(())
    }

    pub fn origin(&self) -> url::Url {
        url::Url::parse(&self.public_url).expect("validated")
    }

    pub fn base_url(&self) -> String {
        self.public_url.trim_end_matches('/').to_string()
    }

    pub fn rp_id(&self) -> String {
        self.origin().host_str().unwrap_or("localhost").to_string()
    }

    pub fn secure_cookies(&self) -> bool {
        self.origin().scheme() == "https"
    }
}

/// Replace `${VAR}` with environment values so secrets can stay out of the file.
fn expand_env(text: &str) -> Result<String> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after.find('}').context("unterminated ${ in config")?;
        let name = &after[..end];
        let value =
            std::env::var(name).with_context(|| format!("config references unset ${{{name}}}"))?;
        out.push_str(&value);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_config() {
        let cfg: ServiceConfig =
            toml::from_str("public_url = \"https://sudo.example.net\"\n").unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.rp_id(), "sudo.example.net");
        assert_eq!(cfg.base_url(), "https://sudo.example.net");
        assert!(cfg.advisor.is_none());
    }

    #[test]
    fn rejects_insecure_origin() {
        let cfg: ServiceConfig =
            toml::from_str("public_url = \"http://sudo.example.net\"\n").unwrap();
        assert!(cfg.validate().is_err());
        let cfg: ServiceConfig = toml::from_str("public_url = \"https://x.net/app\"\n").unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn expands_env() {
        unsafe { std::env::set_var("AGENT_SUDO_TEST_KEY", "sekrit") };
        assert_eq!(
            expand_env("key = \"${AGENT_SUDO_TEST_KEY}\"").unwrap(),
            "key = \"sekrit\""
        );
        assert!(expand_env("${AGENT_SUDO_UNSET_VAR_X}").is_err());
    }
}

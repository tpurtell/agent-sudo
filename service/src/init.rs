//! `agent-sudo-service init`: generate a ready-to-run deployment directory.
//!
//! Asks for the front door (Tailscale or your own certificate), the admin contact and
//! an optional decision model, then writes docker-compose.yml, service.toml, .env
//! (mode 600) and the proxy config, validated by the service's own config parser.
//! Every question has a flag, and `--yes` makes it fully non-interactive.

use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::Args;
use dialoguer::{Confirm, Input, Password, Select};

const COMPOSE: &str = include_str!("../../deploy/service/docker-compose.yml");
const NGINX: &str = include_str!("../../deploy/service/nginx.conf");
const TS_SERVE: &str = include_str!("../../deploy/service/tailscale-serve.json");

#[derive(Debug, Args, Default)]
pub struct InitArgs {
    /// Directory to create the deployment in.
    #[arg(default_value = "agent-sudo")]
    pub dir: PathBuf,
    /// tailscale or nginx
    #[arg(long)]
    pub front_door: Option<String>,
    /// Tailscale machine name (becomes https://NAME.<tailnet>.ts.net).
    #[arg(long)]
    pub ts_hostname: Option<String>,
    /// Tailnet DNS suffix, e.g. tail1234.ts.net (detected from `tailscale status` when possible).
    #[arg(long)]
    pub tailnet: Option<String>,
    /// Tailscale auth key; leave empty to approve the device through a login link.
    #[arg(long)]
    pub ts_authkey: Option<String>,
    /// nginx: the exact https:// URL browsers will use.
    #[arg(long)]
    pub public_url: Option<String>,
    /// nginx: published HTTPS port.
    #[arg(long)]
    pub https_port: Option<u16>,
    /// nginx: certificate chain and key paths.
    #[arg(long)]
    pub tls_cert: Option<String>,
    #[arg(long)]
    pub tls_key: Option<String>,
    /// Contact for push services (VAPID subject).
    #[arg(long)]
    pub admin_email: Option<String>,
    /// none, openai (any OpenAI-compatible /v1) or decisions (OpenRouter Decisions API)
    #[arg(long)]
    pub advisor: Option<String>,
    #[arg(long)]
    pub advisor_url: Option<String>,
    #[arg(long)]
    pub advisor_model: Option<String>,
    #[arg(long)]
    pub advisor_key: Option<String>,
    /// Container image to run.
    #[arg(long)]
    pub image: Option<String>,
    /// Don't ask; use flags and defaults, fail if something required is missing.
    #[arg(long)]
    pub yes: bool,
    /// Overwrite existing files in DIR.
    #[arg(long)]
    pub force: bool,
    /// Skip the live decision-model test.
    #[arg(long)]
    pub no_test: bool,
}

struct Asker {
    interactive: bool,
}

impl Asker {
    fn text(&self, prompt: &str, given: Option<String>, default: Option<&str>) -> Result<String> {
        if let Some(v) = given {
            return Ok(v);
        }
        if !self.interactive {
            return default
                .map(str::to_string)
                .with_context(|| format!("missing --{}", flag_for(prompt)));
        }
        let mut input = Input::<String>::new().with_prompt(prompt);
        if let Some(d) = default {
            input = input.default(d.to_string());
        }
        Ok(input.interact_text()?)
    }

    fn secret(&self, prompt: &str, given: Option<String>, allow_empty: bool) -> Result<String> {
        if let Some(v) = given {
            return Ok(v);
        }
        if !self.interactive {
            return Ok(String::new());
        }
        Ok(Password::new()
            .with_prompt(prompt)
            .allow_empty_password(allow_empty)
            .interact()?)
    }

    fn choose(
        &self,
        prompt: &str,
        given: Option<String>,
        options: &[(&str, &str)],
        default: usize,
    ) -> Result<String> {
        if let Some(v) = given {
            if options.iter().any(|(k, _)| *k == v) {
                return Ok(v);
            }
            bail!(
                "{prompt}: expected one of {}",
                options
                    .iter()
                    .map(|(k, _)| *k)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        if !self.interactive {
            return Ok(options[default].0.to_string());
        }
        let labels: Vec<&str> = options.iter().map(|(_, l)| *l).collect();
        let i = Select::new()
            .with_prompt(prompt)
            .items(&labels)
            .default(default)
            .interact()?;
        Ok(options[i].0.to_string())
    }

    fn confirm(&self, prompt: &str, default: bool) -> Result<bool> {
        if !self.interactive {
            return Ok(default);
        }
        Ok(Confirm::new()
            .with_prompt(prompt)
            .default(default)
            .interact()?)
    }
}

fn flag_for(prompt: &str) -> String {
    prompt
        .to_lowercase()
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join("-")
}

/// The tailnet's MagicDNS suffix, from a local `tailscale` if there is one.
fn detect_tailnet() -> Option<String> {
    let out = std::process::Command::new("tailscale")
        .args(["status", "--json"])
        .output()
        .ok()?;
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    v["MagicDNSSuffix"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn quote_env(v: &str) -> String {
    if !v.is_empty()
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./:@+=,".contains(c))
    {
        v.to_string()
    } else {
        format!("'{}'", v.replace('\'', "'\\''"))
    }
}

fn write(path: &Path, contents: &str, mode: u32, force: bool) -> Result<()> {
    if path.exists() && !force {
        bail!(
            "{} already exists (use --force to overwrite)",
            path.display()
        );
    }
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;
    f.write_all(contents.as_bytes())?;
    Ok(())
}

pub async fn run(args: InitArgs) -> Result<()> {
    let ask = Asker {
        interactive: !args.yes && std::io::stdin().is_terminal(),
    };
    if ask.interactive {
        println!(
            "agent-sudo service setup: answers go into {}/\n",
            args.dir.display()
        );
    }
    let mut env: BTreeMap<&str, String> = BTreeMap::new();

    let front = ask.choose(
        "How will devices reach the service over HTTPS?",
        args.front_door.clone(),
        &[
            (
                "tailscale",
                "Tailscale (recommended): tailnet-only, automatic certificate",
            ),
            ("nginx", "My own certificate and hostname (nginx)"),
        ],
        0,
    )?;
    let public_url;
    if front == "tailscale" {
        let host = ask.text(
            "Tailscale machine name",
            args.ts_hostname.clone(),
            Some("agent-sudo"),
        )?;
        let detected = detect_tailnet();
        let tailnet = ask.text(
            "Tailnet DNS suffix (Admin console → DNS)",
            args.tailnet.clone(),
            detected.as_deref(),
        )?;
        public_url = format!("https://{host}.{}", tailnet.trim_start_matches('.'));
        if ask.interactive {
            println!("  Passkeys will be tied to {public_url}; choose the final name now.");
        }
        let key = ask.secret(
            "Tailscale auth key (empty = approve with a login link)",
            args.ts_authkey.clone(),
            true,
        )?;
        env.insert("COMPOSE_PROFILES", "tailscale".into());
        env.insert("TS_HOSTNAME", host);
        env.insert("TS_AUTHKEY", key);
    } else {
        public_url = ask.text(
            "Public URL (https://host[:port])",
            args.public_url.clone(),
            None,
        )?;
        let port = match args.https_port {
            Some(p) => p.to_string(),
            None => ask.text(
                "HTTPS port to publish",
                None,
                Some(
                    url::Url::parse(&public_url)
                        .ok()
                        .and_then(|u| u.port())
                        .map(|p| p.to_string())
                        .as_deref()
                        .unwrap_or("443"),
                ),
            )?,
        };
        let cert = ask.text(
            "Certificate chain (PEM)",
            args.tls_cert.clone(),
            Some("./certs/fullchain.pem"),
        )?;
        let key = ask.text(
            "Certificate key (PEM)",
            args.tls_key.clone(),
            Some("./certs/privkey.pem"),
        )?;
        env.insert("COMPOSE_PROFILES", "nginx".into());
        env.insert("HTTPS_PORT", port);
        env.insert("TLS_CERT", cert);
        env.insert("TLS_KEY", key);
    }
    env.insert("AGENT_SUDO_PUBLIC_URL", public_url.clone());
    let email = ask.text(
        "Admin email (contact for push services)",
        args.admin_email.clone(),
        Some("admin@example.com"),
    )?;
    env.insert("AGENT_SUDO_ADMIN_EMAIL", email);

    let advisor = ask.choose(
        "Decision model for risk scores and delegations",
        args.advisor.clone(),
        &[
            (
                "openai",
                "Any OpenAI-compatible endpoint (OpenRouter, LiteLLM, vLLM, …)",
            ),
            ("decisions", "OpenRouter Decisions API"),
            ("none", "None for now"),
        ],
        if args.advisor_url.is_some() { 0 } else { 2 },
    )?;
    if advisor != "none" {
        let (url_default, model_default) = if advisor == "decisions" {
            (
                "https://openrouter.ai/api/alpha/decisions",
                "typesafe/jev-1.13",
            )
        } else {
            ("https://openrouter.ai/api/v1", "deepseek/deepseek-v4-flash")
        };
        env.insert(
            "AGENT_SUDO_ADVISOR_URL",
            ask.text(
                "Model endpoint URL",
                args.advisor_url.clone(),
                Some(url_default),
            )?,
        );
        env.insert(
            "AGENT_SUDO_ADVISOR_MODEL",
            ask.text(
                "Model name",
                args.advisor_model.clone(),
                Some(model_default),
            )?,
        );
        env.insert(
            "AGENT_SUDO_ADVISOR_KEY",
            ask.secret("API key", args.advisor_key.clone(), true)?,
        );
    }
    let image = args.image.clone().unwrap_or_else(|| {
        format!(
            "ghcr.io/tpurtell/agent-sudo-service:{}",
            env!("CARGO_PKG_VERSION")
        )
    });
    env.insert("AGENT_SUDO_IMAGE", image);
    if let Ok(token) = std::env::var("AGENT_SUDO_SETUP_TOKEN") {
        env.insert("AGENT_SUDO_SETUP_TOKEN", token);
    }

    let service_toml = service_toml(&advisor);
    // Validate with the real parser, substituting the answers as the container will.
    for (k, v) in &env {
        // SAFETY: single-threaded at this point of a CLI command.
        unsafe { std::env::set_var(k, v) };
    }
    let dir = args.dir.clone();
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    for f in [".env", "service.toml", "docker-compose.yml"] {
        if dir.join(f).exists() && !args.force {
            bail!(
                "{} already exists (use --force to overwrite)",
                dir.join(f).display()
            );
        }
    }
    // Validate before writing anything, so a failed run leaves nothing behind.
    let check = dir.join(".service.toml.check");
    std::fs::write(&check, &service_toml)?;
    let loaded = crate::config::ServiceConfig::load(&check);
    let _ = std::fs::remove_file(&check);
    let cfg = loaded.context("the generated configuration is invalid")?;

    if advisor != "none"
        && !args.no_test
        && ask.confirm("Test the decision model with a sample request now?", true)?
    {
        print!("  asking {} … ", env["AGENT_SUDO_ADVISOR_MODEL"]);
        use std::io::Write;
        std::io::stdout().flush().ok();
        match crate::advisor_sample(cfg).await {
            Ok(a) => println!(
                "ok: risk {} ({}), {:.1}s",
                a.risk,
                a.summary,
                a.latency_ms as f64 / 1000.0
            ),
            Err(e) => {
                println!("failed");
                eprintln!("  {e:#}");
                if !ask.confirm("Keep this model configuration anyway?", false)? {
                    bail!("stopped; fix the model settings and run init again");
                }
            }
        }
    }

    let env_text: String = env
        .iter()
        .map(|(k, v)| format!("{k}={}\n", quote_env(v)))
        .collect();
    write(&dir.join(".env"), &env_text, 0o600, args.force)?;
    write(&dir.join("service.toml"), &service_toml, 0o644, args.force)?;
    write(&dir.join("docker-compose.yml"), COMPOSE, 0o644, args.force)?;
    if front == "tailscale" {
        write(
            &dir.join("tailscale-serve.json"),
            TS_SERVE,
            0o644,
            args.force,
        )?;
    } else {
        write(&dir.join("nginx.conf"), NGINX, 0o644, args.force)?;
    }

    println!(
        "\nWrote {}/ (docker-compose.yml, service.toml, .env).",
        dir.display()
    );
    println!("Start it:\n  cd {} && docker compose up -d", dir.display());
    if front == "tailscale" && env.get("TS_AUTHKEY").is_some_and(|k| k.is_empty()) {
        println!("Approve the device:\n  docker compose logs tailscale | grep login.tailscale.com");
    }
    println!("Then open the one-time setup link:\n  docker compose logs service | grep setup");
    println!("\nService URL: {public_url}");
    Ok(())
}

fn service_toml(advisor: &str) -> String {
    let mut s = String::from(
        "# Generated by `agent-sudo-service init`. Values in dollar-braces come from .env.\n\
         public_url = \"${AGENT_SUDO_PUBLIC_URL}\"\n\
         name = \"agent-sudo\"\n\
         listen = \"0.0.0.0:8080\"\n\
         database = \"/data/agent-sudo.db\"\n\n\
         [push]\n\
         enabled = true\n\
         subject = \"mailto:${AGENT_SUDO_ADMIN_EMAIL}\"\n",
    );
    if advisor != "none" {
        s.push_str(&format!(
            "\n[advisor]\n\
             backend = \"{}\"\n\
             url = \"${{AGENT_SUDO_ADVISOR_URL}}\"\n\
             model = \"${{AGENT_SUDO_ADVISOR_MODEL}}\"\n\
             api_key = \"${{AGENT_SUDO_ADVISOR_KEY}}\"\n\
             response_format = \"json_object\"\n\
             timeout_secs = 30\n",
            if advisor == "decisions" {
                "decisions"
            } else {
                "openai"
            }
        ));
    }
    s.push_str("\n[policy.automation]\nenabled = true\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn non_interactive_tailscale_init_writes_a_valid_deployment() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("deploy");
        run(InitArgs {
            dir: out.clone(),
            front_door: Some("tailscale".into()),
            ts_hostname: Some("sudo".into()),
            tailnet: Some("tail1234.ts.net".into()),
            admin_email: Some("me@example.com".into()),
            advisor: Some("openai".into()),
            advisor_url: Some("http://gateway:4000/v1".into()),
            advisor_model: Some("m".into()),
            advisor_key: Some("k'ey".into()),
            yes: true,
            no_test: true,
            ..Default::default()
        })
        .await
        .unwrap();
        let env = std::fs::read_to_string(out.join(".env")).unwrap();
        assert!(env.contains("AGENT_SUDO_PUBLIC_URL=https://sudo.tail1234.ts.net\n"));
        assert!(env.contains("COMPOSE_PROFILES=tailscale\n"));
        assert!(env.contains("AGENT_SUDO_ADVISOR_KEY='k'\\''ey'\n"));
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(out.join(".env"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(out.join("tailscale-serve.json").exists());
        assert!(out.join("docker-compose.yml").exists());
        // Refuses to clobber without --force.
        let again = run(InitArgs {
            dir: out,
            front_door: Some("tailscale".into()),
            ts_hostname: Some("x".into()),
            tailnet: Some("t.ts.net".into()),
            yes: true,
            no_test: true,
            advisor: Some("none".into()),
            ..Default::default()
        })
        .await;
        assert!(again.is_err());
    }
}

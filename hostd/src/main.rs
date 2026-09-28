//! agent-sudo-hostd: per-host relay between the setuid `agent-sudo` binary and the
//! approval service. It owns the host identity (an Ed25519 key) and all networking,
//! so the setuid binary never has to speak TLS or HTTP.

use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use agent_sudo_protocol::api::{EnrollRequest, HeartbeatRequest};
use agent_sudo_protocol::signing;
use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

mod config;
mod facts;
mod procinfo;
mod relay;
mod service;

use config::HostdConfig;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(name = "agent-sudo-hostd", version, about = "agent-sudo host relay")]
struct Cli {
    /// Path to hostd.toml
    #[arg(long, global = true, default_value = config::DEFAULT_CONFIG, env = "AGENT_SUDO_HOSTD_CONFIG")]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the relay (normally started by systemd).
    Run,
    /// Register this host with the approval service using a one-time token.
    Enroll {
        /// Service base URL, e.g. https://sudo.example.ts.net
        #[arg(long)]
        service: String,
        /// One-time enrollment token minted in the web UI.
        #[arg(long, env = "AGENT_SUDO_ENROLL_TOKEN")]
        token: String,
        /// Extra PEM trust anchor for a self-hosted CA.
        #[arg(long)]
        ca_file: Option<PathBuf>,
        /// Name to register (defaults to the hostname).
        #[arg(long)]
        name: Option<String>,
        /// Where to write the host key.
        #[arg(long, default_value = config::DEFAULT_KEY)]
        key_file: PathBuf,
        /// Where to write the client config for the setuid binary.
        #[arg(long, default_value = config::CLIENT_CONF)]
        client_conf: PathBuf,
        /// Replace an existing enrollment.
        #[arg(long)]
        force: bool,
    },
    /// Check configuration and connectivity.
    Status,
    /// Manage the per-environment PATH shim that makes `sudo` mean agent-sudo.
    Shim {
        #[command(subcommand)]
        action: ShimAction,
    },
}

#[derive(Subcommand)]
enum ShimAction {
    /// Create DIR/sudo and DIR/sudoedit symlinks to the agent-sudo binary.
    Install {
        #[arg(default_value = "~/.agent-tools")]
        dir: String,
        #[arg(long, default_value = "/usr/local/bin/agent-sudo")]
        binary: PathBuf,
    },
    /// Remove the shim symlinks (only if they point at agent-sudo).
    Uninstall {
        #[arg(default_value = "~/.agent-tools")]
        dir: String,
    },
}

fn expand_home(dir: &str) -> PathBuf {
    match dir.strip_prefix("~/") {
        Some(rest) => std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/"))
            .join(rest),
        None => PathBuf::from(dir),
    }
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".into())
}

fn write_private(path: &Path, contents: &str, mode: u32) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)
            .with_context(|| format!("writing {}", tmp.display()))?;
        f.write_all(contents.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn load_key(path: &Path) -> Result<ed25519_dalek::SigningKey> {
    let meta = std::fs::metadata(path).with_context(|| format!("reading {}", path.display()))?;
    if meta.permissions().mode() & 0o077 != 0 {
        bail!("{} must not be readable by group or others", path.display());
    }
    let text = std::fs::read_to_string(path)?;
    Ok(signing::decode_signing_key(&text)?)
}

async fn run(cfg: HostdConfig) -> Result<()> {
    let key = load_key(&cfg.key_file)?;
    let http = service::build_http(cfg.ca_file.as_deref())?;
    let client = service::ServiceClient::new(
        http.clone(),
        cfg.service_base(),
        &cfg.host_id,
        Some(key.clone()),
    );
    let relay = Arc::new(relay::Relay {
        client,
        proc: procinfo::Proc::new(procinfo::proc_root(), &cfg.agent_executables),
        allow_peer_uids: cfg.allow_peer_uids.clone(),
        hostd_version: VERSION.to_string(),
    });
    let listener = relay::bind(&cfg.socket)?;
    tracing::info!(socket = %cfg.socket.display(), service = cfg.service_base(), "agent-sudo-hostd listening");

    // Heartbeat so the UI can show which hosts are online.
    let heartbeat = service::ServiceClient::new(http, cfg.service_base(), &cfg.host_id, Some(key));
    let interval = Duration::from_secs(cfg.heartbeat_secs.max(10));
    tokio::spawn(async move {
        let req = HeartbeatRequest {
            hostd_version: VERSION.to_string(),
            hostname: hostname(),
        };
        let mut failing = false;
        loop {
            match heartbeat.heartbeat(&req).await {
                Ok(_) if failing => {
                    tracing::info!("approval service reachable again");
                    failing = false;
                }
                Ok(_) => {}
                Err(e) if !failing => {
                    tracing::warn!("heartbeat failed: {e:#}");
                    failing = true;
                }
                Err(_) => {}
            }
            tokio::time::sleep(interval).await;
        }
    });

    tokio::select! {
        r = relay.serve(listener) => r,
        _ = tokio::signal::ctrl_c() => {
            let _ = std::fs::remove_file(&cfg.socket);
            Ok(())
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn enroll(
    config_path: &Path,
    service_url: String,
    token: String,
    ca_file: Option<PathBuf>,
    name: Option<String>,
    key_file: PathBuf,
    client_conf: PathBuf,
    force: bool,
) -> Result<()> {
    if config_path.exists() && !force {
        bail!(
            "{} already exists; pass --force to enroll again",
            config_path.display()
        );
    }
    let base = service_url.trim_end_matches('/').to_string();
    let key = signing::generate_key();
    let http = service::build_http(ca_file.as_deref())?;
    let client = service::ServiceClient::new(http, &base, "", None);
    let resp = client
        .enroll(&EnrollRequest {
            token,
            hostname: name.unwrap_or_else(hostname),
            public_key: signing::encode_public_key(&key.verifying_key()),
            hostd_version: VERSION.to_string(),
        })
        .await?;

    write_private(
        &key_file,
        &format!("{}\n", signing::encode_signing_key(&key)),
        0o600,
    )?;
    let cfg = HostdConfig {
        service_url: base.clone(),
        host_id: resp.host_id.clone(),
        key_file: key_file.clone(),
        socket: PathBuf::from(config::DEFAULT_SOCKET),
        ca_file,
        agent_executables: vec![],
        allow_peer_uids: vec![0],
        heartbeat_secs: 60,
    };
    let text = format!(
        "# Written by `agent-sudo-hostd enroll` for {}\n{}",
        resp.service_name,
        toml::to_string_pretty(&cfg)?
    );
    write_private(config_path, &text, 0o600)?;
    if !client_conf.exists() {
        write_private(
            &client_conf,
            &format!(
                "# agent-sudo client settings (read by the setuid binary)\nsocket = {}\ntimeout = 10m\non_unavailable = password\nnotice = true\n",
                config::DEFAULT_SOCKET
            ),
            0o644,
        )?;
    }
    println!(
        "Enrolled as \"{}\" ({}) with {}",
        resp.name, resp.host_id, base
    );
    println!("Start the relay:  systemctl enable --now agent-sudo-hostd");
    Ok(())
}

async fn status(cfg_path: &Path) -> Result<()> {
    let cfg = HostdConfig::load(cfg_path)?;
    println!("config:   {}", cfg_path.display());
    println!("service:  {}", cfg.service_base());
    println!("host id:  {}", cfg.host_id);
    println!(
        "socket:   {} ({})",
        cfg.socket.display(),
        if cfg.socket.exists() {
            "present"
        } else {
            "missing"
        }
    );
    let key = load_key(&cfg.key_file)?;
    let http = service::build_http(cfg.ca_file.as_deref())?;
    let client = service::ServiceClient::new(http, cfg.service_base(), &cfg.host_id, Some(key));
    match client
        .heartbeat(&HeartbeatRequest {
            hostd_version: VERSION.to_string(),
            hostname: hostname(),
        })
        .await
    {
        Ok(r) => {
            println!("service:  reachable, registered as \"{}\"", r.name);
            if !r.groups.is_empty() {
                println!("groups:   {}", r.groups.join(", "));
            }
            Ok(())
        }
        Err(e) => bail!("service unreachable: {e:#}"),
    }
}

fn shim(action: ShimAction) -> Result<()> {
    match action {
        ShimAction::Install { dir, binary } => {
            let dir = expand_home(&dir);
            if !binary.exists() {
                eprintln!("warning: {} does not exist yet", binary.display());
            }
            std::fs::create_dir_all(&dir)?;
            for name in ["sudo", "sudoedit"] {
                let link = dir.join(name);
                if link.symlink_metadata().is_ok() {
                    std::fs::remove_file(&link)?;
                }
                std::os::unix::fs::symlink(&binary, &link)?;
                println!("{} -> {}", link.display(), binary.display());
            }
            println!("\nAdd this to the agent's environment (not your own shell):");
            println!("  export PATH=\"{}:$PATH\"", dir.display());
            Ok(())
        }
        ShimAction::Uninstall { dir } => {
            let dir = expand_home(&dir);
            for name in ["sudo", "sudoedit"] {
                let link = dir.join(name);
                if let Ok(target) = std::fs::read_link(&link)
                    && target.to_string_lossy().contains("agent-sudo")
                {
                    std::fs::remove_file(&link)?;
                    println!("removed {}", link.display());
                }
            }
            Ok(())
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "agent_sudo_hostd=info".into()),
        )
        .with_target(false)
        .init();
    let cli = Cli::parse();
    match cli.command {
        Command::Run => run(HostdConfig::load(&cli.config)?).await,
        Command::Enroll {
            service,
            token,
            ca_file,
            name,
            key_file,
            client_conf,
            force,
        } => {
            enroll(
                &cli.config,
                service,
                token,
                ca_file,
                name,
                key_file,
                client_conf,
                force,
            )
            .await
        }
        Command::Status => status(&cli.config).await,
        Command::Shim { action } => shim(action),
    }
}

//! agent-sudo approval service.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use axum::Router;
use clap::{Parser, Subcommand};

mod advisor;
mod assets;
mod audit;
mod auth;
mod config;
mod db;
mod engine;
mod error;
mod events;
mod grants;
mod hostapi;
mod passkeys;
mod policy;
mod push;
mod state;
mod util;
mod webapi;

#[cfg(test)]
mod tests;

use config::ServiceConfig;
use state::{AppState, Shared};

#[derive(Parser)]
#[command(
    name = "agent-sudo-service",
    version,
    about = "agent-sudo approval service"
)]
struct Cli {
    #[arg(
        long,
        short,
        global = true,
        default_value = "/etc/agent-sudo/service.toml",
        env = "AGENT_SUDO_CONFIG"
    )]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the service (default).
    Serve,
    /// Exit 0 if the service answers on URL (for container health checks).
    Health {
        #[arg(default_value = "http://127.0.0.1:8080/api/health")]
        url: String,
    },
    /// Validate the configuration and exit.
    CheckConfig,
    /// Print a fresh first-run setup link (only while no users exist).
    SetupLink,
    /// Recovery: print an invitation link that lets USER set a new password.
    ResetUser {
        name: String,
        /// Also remove the user's passkeys (for a lost device).
        #[arg(long)]
        remove_passkeys: bool,
    },
    /// Run the decision model against a sample request and print the assessment.
    AdvisorTest {
        /// Command line to assess.
        #[arg(default_value = "/usr/bin/apt install -y linux-headers-generic")]
        command: String,
        /// Requester-supplied context.
        #[arg(long)]
        context: Option<String>,
    },
}

pub fn build_state(cfg: ServiceConfig, db: db::Db) -> Result<Shared> {
    let advisor = cfg
        .advisor
        .clone()
        .map(advisor::Advisor::new)
        .transpose()?
        .map(Arc::new);
    let push = push::Push::load(&db, &cfg.push.subject, cfg.push.enabled)?;
    let webauthn = passkeys::build(&cfg)?;
    let (events, _) = tokio::sync::broadcast::channel(256);
    Ok(Arc::new(AppState {
        cfg,
        db,
        events,
        advisor,
        webauthn,
        ceremonies: Mutex::new(HashMap::new()),
        push,
        nonces: Mutex::new(HashMap::new()),
        login_failures: Mutex::new(HashMap::new()),
        delegation_declines: Mutex::new(HashMap::new()),
        digests: Mutex::new(HashMap::new()),
    }))
}

pub fn app(state: Shared) -> Router {
    Router::new()
        .merge(hostapi::router())
        .merge(webapi::router())
        .fallback(assets::serve)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            assets::security_headers,
        ))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(1024 * 1024))
        .layer(tower_http::compression::CompressionLayer::new())
        .with_state(state)
}

fn ensure_setup_link(state: &AppState) -> Result<Option<String>> {
    if auth::user_count(state)? > 0 {
        return Ok(None);
    }
    let token = match std::env::var("AGENT_SUDO_SETUP_TOKEN") {
        Ok(t) if t.len() >= 16 => t,
        _ => util::new_token(),
    };
    state
        .db
        .set_setting("setup_token_hash", &util::sha256_hex(&token))?;
    Ok(Some(format!("{}/setup#{}", state.cfg.base_url(), token)))
}

async fn serve(state: Shared) -> Result<()> {
    if let Some(link) = ensure_setup_link(&state)? {
        tracing::warn!("No users yet. Finish setup in a browser: {link}");
    }
    engine::spawn_background(state.clone());
    let listener = tokio::net::TcpListener::bind(state.cfg.listen)
        .await
        .with_context(|| format!("binding {}", state.cfg.listen))?;
    tracing::info!(
        listen = %state.cfg.listen,
        url = %state.cfg.base_url(),
        advisor = state.advisor.as_ref().map(|a| a.config.model.as_str()).unwrap_or("off"),
        "agent-sudo service ready"
    );
    axum::serve(listener, app(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

async fn advisor_test(state: Shared, command: String, context: Option<String>) -> Result<()> {
    let advisor = state
        .advisor
        .clone()
        .context("no [advisor] section in the config")?;
    let mut parts = command.split_whitespace().map(str::to_string);
    let env = agent_sudo_protocol::api::RequestEnvelope {
        client_request_id: "advisor-test".into(),
        mode: agent_sudo_protocol::api::Mode::Run,
        nonblocking: false,
        interactive: false,
        hostname: "example".into(),
        user: agent_sudo_protocol::api::Principal {
            name: "dev".into(),
            uid: 1000,
            gid: 1000,
        },
        target: agent_sudo_protocol::api::Target {
            user: "root".into(),
            uid: 0,
            group: None,
            gid: 0,
        },
        launch: Default::default(),
        command: parts.next(),
        argv: parts.collect(),
        lossy: false,
        cwd: Some("/home/dev/project".into()),
        chdir: None,
        tty: None,
        session: agent_sudo_protocol::api::SessionInfo {
            fingerprint: "test".into(),
            label: "claude (pid 1)".into(),
            agent: Some("claude".into()),
            chain: vec![],
            ssh: false,
        },
        untrusted: agent_sudo_protocol::api::Untrusted {
            context,
            session: None,
        },
        timeout_secs: 600,
        hostd_version: "test".into(),
    };
    let features = policy::features(&env);
    let class = state.cfg.policy.classify(&env, &features);
    let row = engine::RequestRow {
        id: "req_test".into(),
        code: "TEST".into(),
        host_id: "hst_test".into(),
        state: agent_sudo_protocol::api::RequestState::Pending,
        version: 1,
        created_at: util::now_ms(),
        updated_at: util::now_ms(),
        deadline_at: util::now_ms(),
        command_key: policy::command_key(&env),
        class: class.name.clone(),
        features: features.clone(),
        assessment: Default::default(),
        decision: None,
        grant_id: None,
        delegation_id: None,
        quiet: false,
        flagged_at: None,
        envelope: env,
    };
    let host = engine::HostRow {
        id: "hst_test".into(),
        name: "example".into(),
        hostname: "example".into(),
        public_key: String::new(),
        groups: vec![],
        hostd_version: String::new(),
        created_at: 0,
        last_seen_at: None,
        revoked_at: None,
    };
    let input = engine::advisor_input(&state, &row, &host, &class, None);
    println!("class: {} ({})", class.name, class.title);
    println!("features: {}", features.keys().join(", "));
    let a = advisor.assess(&input).await?;
    let a = advisor::clamp(
        a,
        &class,
        &features,
        advisor.config.max_suggested_ttl_minutes,
    );
    println!("{}", serde_json::to_string_pretty(&a)?);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "agent_sudo_service=info,audit=info,tower_http=warn".into()),
        )
        .with_target(false)
        .init();
    let cli = Cli::parse();
    if let Some(Command::Health { url }) = &cli.command {
        let ok = reqwest::Client::new()
            .get(url)
            .timeout(std::time::Duration::from_secs(4))
            .send()
            .await
            .is_ok_and(|r| r.status().is_success());
        std::process::exit(if ok { 0 } else { 1 });
    }
    let cfg = ServiceConfig::load(&cli.config)?;
    match cli.command.unwrap_or(Command::Serve) {
        Command::CheckConfig => {
            println!(
                "{} is valid ({} classes)",
                cli.config.display(),
                cfg.policy.effective_classes().len()
            );
            Ok(())
        }
        command => {
            let db = db::Db::open(&cfg.database)?;
            let state = build_state(cfg, db)?;
            match command {
                Command::Serve => serve(state).await,
                Command::SetupLink => {
                    match ensure_setup_link(&state)? {
                        Some(link) => println!("{link}"),
                        None => {
                            println!("Setup is complete; use `reset-user` to recover an account.")
                        }
                    }
                    Ok(())
                }
                Command::ResetUser {
                    name,
                    remove_passkeys,
                } => {
                    let user = auth::user_by_name(&state, &name)?
                        .with_context(|| format!("no user named {name}"))?;
                    let token = util::new_token();
                    let now = util::now_ms();
                    {
                        let db = state.db.lock();
                        db.execute(
                            "INSERT INTO invites (id, token_hash, user_id, created_by, created_at, expires_at) VALUES (?1, ?2, ?3, 'cli', ?4, ?5)",
                            rusqlite::params![util::new_id("inv"), util::sha256_hex(&token), user.id, now, now + 3_600_000],
                        )?;
                        if remove_passkeys {
                            db.execute("DELETE FROM passkeys WHERE user_id = ?", [&user.id])?;
                        }
                        db.execute(
                            "UPDATE users SET disabled_at = NULL WHERE id = ?",
                            [&user.id],
                        )?;
                    }
                    audit::record(
                        &state.db,
                        "cli",
                        "user.reset",
                        Some(&user.id),
                        serde_json::json!({"remove_passkeys": remove_passkeys}),
                    );
                    println!("{}/invite#{token}", state.cfg.base_url());
                    Ok(())
                }
                Command::AdvisorTest { command, context } => {
                    advisor_test(state, command, context).await
                }
                Command::CheckConfig | Command::Health { .. } => unreachable!(),
            }
        }
    }
}

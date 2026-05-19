#![allow(dead_code)]

mod agent;
mod cli;
mod config;
mod context;
mod event;
mod extras;
mod pentest;
mod permission;
mod provider;
mod sandbox;
mod session;
mod ui;

use std::io::IsTerminal;

use cli::{Cli, RuntimeMode};
use config::Config;
use permission::ask::AskSender;
use permission::checker::{PermCheck, PermissionChecker};
use permission::{PermissionConfig, SecurityMode};

fn resolve_mode(cli: &Cli, cfg: &Config) -> SecurityMode {
    cli.resolve_security_mode(cfg)
}

fn build_permission_checker(
    cli: &Cli,
    cfg: &Config,
) -> (
    Option<PermCheck>,
    Option<AskSender>,
    Option<tokio::sync::mpsc::Receiver<crate::permission::ask::AskRequest>>,
) {
    if cli.resolve_no_tools(cfg) {
        return (None, None, None);
    }

    let perm_config: PermissionConfig = cfg
        .permission
        .as_ref()
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    let checker = PermissionChecker::new(&perm_config, resolve_mode(cli, cfg), None);
    let perm: PermCheck = std::sync::Arc::new(std::sync::Mutex::new(checker));
    let (ask_tx, ask_rx) = tokio::sync::mpsc::channel(64);
    (Some(perm), Some(ask_tx), Some(ask_rx))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn,rig=off")),
        )
        .init();

    let cli = Cli::parse();
    let config = Config::load();

    if cli.print_config {
        print_config(&cli, &config);
        return Ok(());
    }

    let provider = cli.resolve_provider(&config);
    let model = cli.resolve_model(&config);
    let security_mode = cli.resolve_security_mode(&config);

    println!("hex bootstrap");
    println!("mode: {}", cli.mode.label());
    println!("provider: {}", provider.label());
    println!("model: {}", model);
    println!("security_mode: {}", security_mode);
    println!(
        "authorized_pentest: {}",
        if cli.authorized_pentest {
            "true"
        } else {
            "false"
        }
    );

    if matches!(cli.mode, RuntimeMode::Print) {
        if let Err(e) = run_print_mode(&cli, &config).await {
            eprintln!("error: {e:#}");
            std::process::exit(1);
        }
        return Ok(());
    }

    if matches!(cli.mode, RuntimeMode::Pentest) {
        if let Err(e) = pentest::run_pentest_mode(&cli, &config).await {
            eprintln!("pentest error: {e:#}");
            std::process::exit(1);
        }
        return Ok(());
    }

    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Ok(());
    }

    if matches!(cli.mode, RuntimeMode::Loop) {
        return Ok(());
    }

    let mut context = context::load(cli.resolve_no_context_files(&config));
    let default_prompt = config.default_prompt.as_deref().unwrap_or("code");
    if let Some(content) = context.prompts.get(default_prompt) {
        context.current_prompt = Some(content.clone());
        context.current_prompt_name = Some(default_prompt.to_string());
    }

    let mut session =
        session::Session::new(provider.label(), &model, config.resolve_context_window());

    if cli.resume && cli.session.is_none() && !cli.continue_session {
        if let Ok(sessions) = session::storage::find_recent_sessions(10) {
            if let Some(s) = sessions.into_iter().next() {
                session = s;
            }
        }
    }

    if cli.continue_session
        && cli.session.is_none()
        && let Ok(sessions) = session::storage::find_recent_sessions(1)
        && let Some(s) = sessions.into_iter().next()
    {
        session = s;
    }

    if let Some(session_id) = &cli.session {
        session = session::storage::load_session(session_id)?;
    }

    let client = provider::create_client(provider, cli.api_key.as_deref())?;
    let completion_model = client.completion_model(model.clone());
    let sandbox = sandbox::Sandbox::new(cli.resolve_sandbox(&config), cli.resolve_shell(&config));
    let (permission, ask_tx, ask_rx) = build_permission_checker(&cli, &config);

    if let Some(perm) = &permission {
        let allowlist: Vec<(String, String)> = session
            .permission_allowlist
            .iter()
            .map(|e| (e.tool.clone(), e.pattern.clone()))
            .collect();
        perm.lock()
            .unwrap_or_else(|e| e.into_inner())
            .load_session_allowlist(&allowlist);
    }

    let agent = provider::build_agent(
        completion_model,
        &cli,
        &config,
        &context,
        permission.clone(),
        ask_tx.clone(),
        sandbox.clone(),
        true,
    )
    .await;

    if let Some(perm) = &permission {
        perm.lock()
            .unwrap_or_else(|e| e.into_inner())
            .set_mode(resolve_mode(&cli, &config));
    }

    let initial_msg = cli.message.join(" ");
    if !initial_msg.is_empty() {
        session.add_message(session::MessageRole::User, &initial_msg);
    }

    ui::run_interactive(
        client,
        agent,
        &cli,
        &config,
        &mut session,
        &mut context,
        permission,
        ask_tx,
        ask_rx,
        sandbox,
    )
    .await?;

    Ok(())
}

async fn run_print_mode(cli: &Cli, cfg: &Config) -> anyhow::Result<()> {
    let prompt = cli
        .prompt
        .clone()
        .or_else(|| {
            if cli.message.is_empty() {
                None
            } else {
                Some(cli.message.join(" "))
            }
        })
        .ok_or_else(|| {
            anyhow::anyhow!("--print requires --prompt \"...\" or a trailing message")
        })?;

    let provider = cli.resolve_provider(cfg);
    let model_name = cli.resolve_model(cfg);
    let max_turns = cli.resolve_max_agent_turns(cfg);
    let security_mode = cli.resolve_security_mode(cfg);
    let sandbox_enabled = cli.resolve_sandbox(cfg);
    let shell = cli.resolve_shell(cfg);

    let context = context::load(cli.resolve_no_context_files(cfg));

    let perm_cfg: PermissionConfig = cfg
        .permission
        .as_ref()
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let perm_checker = PermissionChecker::new(&perm_cfg, security_mode, None);
    let permission: PermCheck = std::sync::Arc::new(std::sync::Mutex::new(perm_checker));

    let sandbox_inst = sandbox::Sandbox::new(sandbox_enabled, shell);
    let client = provider::create_client(provider, cli.api_key.as_deref())?;
    let model = client.completion_model(model_name);
    let agent = agent::builder::build_agent(
        model,
        cli,
        cfg,
        &context,
        Some(permission),
        None,
        sandbox_inst,
        true,
    );
    let _ = agent::runner::run_print_any(&agent, &prompt, max_turns).await?;
    Ok(())
}

fn print_section(title: &str, entries: &[(&str, String)]) {
    println!("{}:", title);
    let width = entries.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    for (k, v) in entries {
        println!("  {k:<width$}  {v}");
    }
    println!();
}

fn print_config(cli: &Cli, cfg: &Config) {
    let config_dir = session::storage::config_path();
    let data_dir = session::storage::data_dir();
    let sessions_dir = data_dir.join("sessions");
    let config_file = config::config_file_path();

    print_section(
        "Directories",
        &[
            ("config", config_dir.display().to_string()),
            ("data", data_dir.display().to_string()),
            ("sessions", sessions_dir.display().to_string()),
            ("config file", config_file.display().to_string()),
        ],
    );

    print_section(
        "Model",
        &[
            ("provider", cli.resolve_provider(cfg).to_string()),
            ("model", cli.resolve_model(cfg)),
        ],
    );

    print_section(
        "Limits",
        &[
            ("max-tokens", cli.resolve_max_tokens(cfg).to_string()),
            (
                "max-agent-turns",
                cli.resolve_max_agent_turns(cfg).to_string(),
            ),
            ("context-window", cfg.resolve_context_window().to_string()),
            ("reserve-tokens", cfg.resolve_reserve_tokens().to_string()),
        ],
    );

    print_section(
        "Behavior",
        &[
            (
                "permission-mode",
                cli.resolve_security_mode(cfg).to_string(),
            ),
            ("shell", cli.resolve_shell(cfg)),
            ("sandbox", cli.resolve_sandbox(cfg).to_string()),
            ("no-tools", cli.resolve_no_tools(cfg).to_string()),
            (
                "no-context-files",
                cli.resolve_no_context_files(cfg).to_string(),
            ),
            ("compact", cfg.resolve_compact_enabled().to_string()),
        ],
    );
}

use rig::agent::{Agent, AgentBuilder};
use rig::completion::CompletionModel;

use crate::agent::prompt::{PENTEST_SYSTEM_PROMPT, SYSTEM_PROMPT, TODO_TOOLS_PROMPT};
use crate::agent::tools;
use crate::cli::Cli;
use crate::config::Config;
use crate::context::ContextFiles;
use crate::permission::ask::AskSender;
use crate::permission::checker::PermCheck;
use crate::provider::{AnyModel, ProviderKind};
use crate::sandbox::Sandbox;

use super::runner::AnyAgent;

pub fn compose_preamble(context: &ContextFiles, reasoning_enabled: bool) -> String {
    let mut preamble = if reasoning_enabled {
        "You reason carefully and think step-by-step.\n\n".to_string()
    } else {
        "You respond concisely without showing your reasoning.\n\n".to_string()
    };
    preamble.push_str(SYSTEM_PROMPT);
    preamble.push('\n');
    preamble.push_str(TODO_TOOLS_PROMPT);

    if let Some(agents) = &context.agents {
        preamble.push_str("\n\n");
        preamble.push_str(agents);
    }

    if let Some(prompt) = &context.current_prompt {
        preamble.push_str("\n\n---\n\n");
        preamble.push_str(prompt);
    }

    if let Ok(cwd) = std::env::current_dir() {
        preamble.push_str(&format!("\n\nCurrent working directory: {}", cwd.display()));
    }

    preamble
}

fn build_inner<M: CompletionModel + 'static>(
    model: M,
    cli: &Cli,
    cfg: &Config,
    preamble: &str,
    permission: Option<PermCheck>,
    ask_tx: Option<AskSender>,
    sandbox: Sandbox,
    sec_ctx: Option<tools::sec::SecContext>,
) -> Agent<M> {
    let mut builder = AgentBuilder::new(model).preamble(preamble);

    builder = builder.max_tokens(cli.resolve_max_tokens(cfg));

    let max_turns = cli.resolve_max_agent_turns(cfg);
    builder = builder.default_max_turns(max_turns);

    if let Some(temp) = cli.temperature.or(cfg.temperature) {
        builder = builder.temperature(temp.clamp(0.0, 2.0));
    }

    if cli.resolve_no_tools(cfg) {
        return builder.build();
    }

    let mut base_tools: Vec<Box<dyn rig::tool::ToolDyn>> = vec![
        Box::new(tools::ReadTool::new(permission.clone(), ask_tx.clone())),
        Box::new(tools::WriteTool::new(permission.clone(), ask_tx.clone())),
        Box::new(tools::EditTool::new(permission.clone(), ask_tx.clone())),
        Box::new(tools::BashTool::new(
            permission.clone(),
            ask_tx.clone(),
            sandbox.clone(),
        )),
        Box::new(tools::GrepTool::new(permission.clone(), ask_tx.clone())),
        Box::new(tools::FindFilesTool::new(
            permission.clone(),
            ask_tx.clone(),
        )),
        Box::new(tools::ListDirTool::new(permission.clone(), ask_tx.clone())),
        Box::new(tools::WriteTodoList::new(
            permission.clone(),
            ask_tx.clone(),
        )),
    ];

    if let Some(ctx) = sec_ctx {
        base_tools.push(Box::new(tools::sec::NmapTool::new(ctx.clone())));
        base_tools.push(Box::new(tools::sec::MasscanTool::new(ctx.clone())));
        base_tools.push(Box::new(tools::sec::SubfinderTool::new(ctx.clone())));
        base_tools.push(Box::new(tools::sec::DnsxTool::new(ctx.clone())));
        base_tools.push(Box::new(tools::sec::HttpxTool::new(ctx.clone())));
        base_tools.push(Box::new(tools::sec::NucleiTool::new(ctx.clone())));
        base_tools.push(Box::new(tools::sec::FfufTool::new(ctx.clone())));
        base_tools.push(Box::new(tools::sec::NiktoTool::new(ctx.clone())));
        base_tools.push(Box::new(tools::sec::WhatwebTool::new(ctx.clone())));
        base_tools.push(Box::new(tools::sec::SemgrepTool::new(ctx.clone())));
        base_tools.push(Box::new(tools::sec::TrivyTool::new(ctx.clone())));
        base_tools.push(Box::new(tools::sec::GitleaksTool::new(ctx.clone())));
        base_tools.push(Box::new(tools::sec::NxcTool::new(ctx.clone())));
        base_tools.push(Box::new(tools::sec::ImpacketTool::new(ctx.clone())));
        base_tools.push(Box::new(tools::sec::BloodhoundTool::new(ctx.clone())));
        base_tools.push(Box::new(tools::sec::HydraTool::new(ctx.clone())));
        base_tools.push(Box::new(tools::sec::HashcatTool::new(ctx.clone())));
        base_tools.push(Box::new(tools::sec::JohnTool::new(ctx.clone())));
        base_tools.push(Box::new(tools::sec::KerbruteTool::new(ctx.clone())));
        base_tools.push(Box::new(tools::sec::TestsslTool::new(ctx.clone())));
        base_tools.push(Box::new(tools::sec::SslyzeTool::new(ctx.clone())));
        base_tools.push(Box::new(tools::sec::SearchsploitTool::new(ctx.clone())));
        base_tools.push(Box::new(tools::sec::ChecksecTool::new(ctx.clone())));
        base_tools.push(Box::new(tools::sec::RopperTool::new(ctx.clone())));
        base_tools.push(Box::new(tools::sec::R2Tool::new(ctx.clone())));
        base_tools.push(Box::new(tools::sec::AflFuzzTool::new(ctx.clone())));
        base_tools.push(Box::new(tools::sec::ProwlerTool::new(ctx.clone())));
        base_tools.push(Box::new(tools::sec::ScoutsuiteTool::new(ctx.clone())));
        base_tools.push(Box::new(tools::sec::TsharkTool::new(ctx.clone())));
        base_tools.push(Box::new(tools::sec::SuricataEveTool::new(ctx.clone())));
        base_tools.push(Box::new(tools::sec::ZeekLogTool::new(ctx)));
    }

    let _ = sandbox;
    let _ = (permission, ask_tx);
    builder.tools(base_tools).build()
}

pub fn compose_pentest_preamble(
    context: &ContextFiles,
    scope: &[String],
    rules: &[String],
) -> String {
    let mut preamble = String::from("You reason carefully and think step-by-step.\n\n");
    preamble.push_str(PENTEST_SYSTEM_PROMPT);
    preamble.push('\n');
    preamble.push_str(TODO_TOOLS_PROMPT);

    preamble.push_str("\n\n## Engagement scope (authoritative)\n");
    if scope.is_empty() {
        preamble.push_str("- (none provided — refuse to act)\n");
    } else {
        for s in scope {
            preamble.push_str(&format!("- {}\n", s));
        }
    }

    preamble.push_str("\n## Rules of engagement (authoritative)\n");
    if rules.is_empty() {
        preamble.push_str("- (none provided)\n");
    } else {
        for r in rules {
            preamble.push_str(&format!("- {}\n", r));
        }
    }

    if let Some(agents) = &context.agents {
        preamble.push_str("\n\n");
        preamble.push_str(agents);
    }

    if let Ok(cwd) = std::env::current_dir() {
        preamble.push_str(&format!("\n\nCurrent working directory: {}", cwd.display()));
    }

    preamble
}

pub fn build_agent_with_preamble(
    model: AnyModel,
    cli: &Cli,
    cfg: &Config,
    preamble: &str,
    permission: Option<PermCheck>,
    ask_tx: Option<AskSender>,
    sandbox: Sandbox,
    sec_ctx: Option<tools::sec::SecContext>,
) -> AnyAgent {
    match model {
        AnyModel::OpenRouter(m) => AnyAgent::OpenRouter(build_inner(
            m, cli, cfg, preamble, permission, ask_tx, sandbox, sec_ctx,
        )),
        AnyModel::OpenAI(m) => AnyAgent::OpenAI(build_inner(
            m, cli, cfg, preamble, permission, ask_tx, sandbox, sec_ctx,
        )),
        AnyModel::Anthropic(m) => AnyAgent::Anthropic(build_inner(
            m, cli, cfg, preamble, permission, ask_tx, sandbox, sec_ctx,
        )),
        AnyModel::Gemini(m) => AnyAgent::Gemini(build_inner(
            m, cli, cfg, preamble, permission, ask_tx, sandbox, sec_ctx,
        )),
        AnyModel::Ollama(m) => AnyAgent::Ollama(build_inner(
            m, cli, cfg, preamble, permission, ask_tx, sandbox, sec_ctx,
        )),
        AnyModel::Groq(m) => AnyAgent::Groq(build_inner(
            m, cli, cfg, preamble, permission, ask_tx, sandbox, sec_ctx,
        )),
        AnyModel::Custom(m) => AnyAgent::Custom(build_inner(
            m, cli, cfg, preamble, permission, ask_tx, sandbox, sec_ctx,
        )),
    }
}

pub fn build_agent(
    model: AnyModel,
    cli: &Cli,
    cfg: &Config,
    context: &ContextFiles,
    permission: Option<PermCheck>,
    ask_tx: Option<AskSender>,
    sandbox: Sandbox,
    reasoning_enabled: bool,
) -> AnyAgent {
    let (preamble, sec_ctx) = if cli.authorized_pentest {
        let preamble = compose_pentest_preamble(context, &cli.scope, &[]);
        let policy_handle = tools::sec::new_policy_handle();
        if !cli.scope.is_empty() {
            if let Ok(policy) =
                crate::pentest::engagement::EngagementPolicy::from_parts(&cli.scope, &[])
            {
                *policy_handle.write().unwrap() = Some(policy);
            }
        }
        let evidence_path = std::env::current_dir()
            .unwrap_or_else(|_| std::path::PathBuf::from("."))
            .join("hex-pentest.evidence.jsonl");
        let evidence_sink = tools::sec::EvidenceSink::with_path(evidence_path);
        let sec_ctx = tools::sec::SecContext::new(
            policy_handle,
            evidence_sink,
            sandbox.clone(),
            permission.clone(),
            ask_tx.clone(),
        );
        (preamble, Some(sec_ctx))
    } else {
        (compose_preamble(context, reasoning_enabled), None)
    };
    match model {
        AnyModel::OpenRouter(m) => AnyAgent::OpenRouter(build_inner(
            m, cli, cfg, &preamble, permission, ask_tx, sandbox, sec_ctx,
        )),
        AnyModel::OpenAI(m) => AnyAgent::OpenAI(build_inner(
            m, cli, cfg, &preamble, permission, ask_tx, sandbox, sec_ctx,
        )),
        AnyModel::Anthropic(m) => AnyAgent::Anthropic(build_inner(
            m, cli, cfg, &preamble, permission, ask_tx, sandbox, sec_ctx,
        )),
        AnyModel::Gemini(m) => AnyAgent::Gemini(build_inner(
            m, cli, cfg, &preamble, permission, ask_tx, sandbox, sec_ctx,
        )),
        AnyModel::Ollama(m) => AnyAgent::Ollama(build_inner(
            m, cli, cfg, &preamble, permission, ask_tx, sandbox, sec_ctx,
        )),
        AnyModel::Groq(m) => AnyAgent::Groq(build_inner(
            m, cli, cfg, &preamble, permission, ask_tx, sandbox, sec_ctx,
        )),
        AnyModel::Custom(m) => AnyAgent::Custom(build_inner(
            m, cli, cfg, &preamble, permission, ask_tx, sandbox, sec_ctx,
        )),
    }
}

#[derive(Debug, Clone)]
pub struct BuiltAgentMeta {
    pub provider: ProviderKind,
    pub model: String,
    pub preamble_len: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_context() -> ContextFiles {
        ContextFiles {
            agents: None,
            prompts: std::collections::HashMap::new(),
            current_prompt: None,
            current_prompt_name: None,
        }
    }

    #[test]
    fn preamble_includes_system_prompt_agents_and_active() {
        let mut ctx = empty_context();
        ctx.agents = Some("AGENTS-CONTEXT".to_string());
        ctx.current_prompt_name = Some("code".to_string());
        ctx.current_prompt = Some("ACTIVE-CONTEXT".to_string());
        let p = compose_preamble(&ctx, false);
        assert!(p.contains("hex-agent"));
        assert!(p.contains("AGENTS-CONTEXT"));
        assert!(p.contains("ACTIVE-CONTEXT"));
        assert!(p.contains("---"));
        assert!(p.contains("Current working directory:"));
        assert!(p.starts_with("You respond concisely"));
    }

    #[test]
    fn preamble_reasoning_preface_when_enabled() {
        let ctx = empty_context();
        let p = compose_preamble(&ctx, true);
        assert!(p.starts_with("You reason carefully"));
    }

    #[test]
    fn preamble_uses_default_system_prompt() {
        let ctx = empty_context();
        let p = compose_preamble(&ctx, false);
        assert!(p.contains("hex-agent"));
        assert!(p.contains("offensive-security operator"));
    }
}

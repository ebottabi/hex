use std::path::PathBuf;

use crate::config::Config;
use crate::permission::SecurityMode;
use crate::provider::ProviderKind;

#[derive(Debug, Clone)]
pub struct Cli {
    pub print: bool,
    pub print_config: bool,
    pub continue_session: bool,
    pub resume: bool,
    pub session: Option<String>,
    pub no_session: bool,
    pub mode: RuntimeMode,
    pub provider: Option<ProviderKind>,
    pub model: Option<String>,
    pub api_key: Option<String>,
    pub max_tokens: Option<u64>,
    pub max_agent_turns: Option<usize>,
    pub temperature: Option<f64>,
    pub tools: Vec<String>,
    pub no_tools: bool,
    pub no_color: bool,
    pub restrictive: bool,
    pub accept_all: bool,
    pub yolo: bool,
    pub sandbox: bool,
    pub shell: Option<String>,
    pub no_context_files: bool,
    pub authorized_pentest: bool,
    pub scope: Vec<String>,
    pub rules_of_engagement: Vec<String>,
    pub report_path: Option<PathBuf>,
    pub max_cost: Option<f64>,
    pub prompt: Option<String>,
    pub message: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
pub enum RuntimeMode {
    Interactive,
    Print,
    Loop,
    Pentest,
}

impl RuntimeMode {
    pub fn label(self) -> &'static str {
        match self {
            RuntimeMode::Interactive => "interactive",
            RuntimeMode::Print => "print",
            RuntimeMode::Loop => "loop",
            RuntimeMode::Pentest => "pentest",
        }
    }
}

impl Cli {
    pub fn parse() -> Self {
        let args: Vec<String> = std::env::args().skip(1).collect();
        Self::parse_from(args)
    }

    pub fn parse_from<I, S>(args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut print = false;
        let mut print_config = false;
        let mut continue_session = false;
        let mut resume = false;
        let mut session = None;
        let mut no_session = false;
        let mut mode = RuntimeMode::Interactive;
        let mut provider = None;
        let mut model = None;
        let mut api_key = None;
        let mut max_tokens = None;
        let mut max_agent_turns = None;
        let mut temperature = None;
        let mut tools = Vec::new();
        let mut no_tools = false;
        let mut no_color = false;
        let mut restrictive = false;
        let mut accept_all = false;
        let mut yolo = false;
        let mut sandbox = false;
        let mut shell = None;
        let mut no_context_files = false;
        let mut authorized_pentest = false;
        let mut scope: Vec<String> = Vec::new();
        let mut rules_of_engagement: Vec<String> = Vec::new();
        let mut report_path: Option<PathBuf> = None;
        let mut max_cost: Option<f64> = None;
        let mut prompt = None;
        let mut message = Vec::new();

        let owned: Vec<String> = args.into_iter().map(Into::into).collect();
        let mut args = owned.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "-V" | "--version" => {
                    println!("hex {}", env!("CARGO_PKG_VERSION"));
                    std::process::exit(0);
                }
                "-h" | "--help" => {
                    print_help();
                    std::process::exit(0);
                }
                "-p" | "--print" => {
                    print = true;
                    mode = RuntimeMode::Print;
                }
                "--print-config" => print_config = true,
                "-c" | "--continue" => continue_session = true,
                "-r" | "--resume" => resume = true,
                "--session" => {
                    if let Some(value) = args.next() {
                        session = Some(value);
                    }
                }
                "--no-session" => no_session = true,
                "--loop" => mode = RuntimeMode::Loop,
                "--pentest" => mode = RuntimeMode::Pentest,
                "--authorized-pentest" => authorized_pentest = true,
                "--scope" => {
                    if let Some(value) = args.next() {
                        scope.extend(
                            value
                                .split(',')
                                .map(|s| s.trim().to_string())
                                .filter(|s| !s.is_empty()),
                        );
                    }
                }
                "--rules-of-engagement" | "--roe" => {
                    if let Some(value) = args.next() {
                        rules_of_engagement.push(value);
                    }
                }
                "--report" => {
                    if let Some(value) = args.next() {
                        report_path = Some(PathBuf::from(value));
                    }
                }
                "--max-cost" => {
                    if let Some(value) = args.next() {
                        max_cost = value.parse::<f64>().ok();
                    }
                }
                "--provider" => {
                    if let Some(value) = args.next() {
                        provider = ProviderKind::from_str(&value);
                    }
                }
                "--model" => {
                    if let Some(value) = args.next() {
                        model = Some(value);
                    }
                }
                "--prompt" => {
                    if let Some(value) = args.next() {
                        prompt = Some(value);
                    }
                }
                "--api-key" => {
                    if let Some(value) = args.next() {
                        api_key = Some(value);
                    }
                }
                "--max-tokens" => {
                    if let Some(value) = args.next() {
                        max_tokens = value.parse::<u64>().ok();
                    }
                }
                "--max-agent-turns" => {
                    if let Some(value) = args.next() {
                        max_agent_turns = value.parse::<usize>().ok();
                    }
                }
                "--temperature" => {
                    if let Some(value) = args.next() {
                        temperature = value.parse::<f64>().ok();
                    }
                }
                "-t" | "--tools" => {
                    if let Some(value) = args.next() {
                        tools.push(value);
                    }
                }
                "--no-tools" => no_tools = true,
                "--no-color" => no_color = true,
                "--restrictive" | "-R" => restrictive = true,
                "--accept-all" => accept_all = true,
                "--yolo" => yolo = true,
                "--sandbox" => sandbox = true,
                "--shell" => {
                    if let Some(value) = args.next() {
                        shell = Some(value);
                    }
                }
                "--no-context-files" | "-n" => no_context_files = true,
                token if token.starts_with('-') => {}
                _ => {
                    message.push(arg);
                    message.extend(args);
                    break;
                }
            }
        }

        Cli {
            print,
            print_config,
            continue_session,
            resume,
            session,
            no_session,
            mode,
            provider,
            model,
            api_key,
            max_tokens,
            max_agent_turns,
            temperature,
            tools,
            no_tools,
            no_color,
            restrictive,
            accept_all,
            yolo,
            sandbox,
            shell,
            no_context_files,
            authorized_pentest,
            scope,
            rules_of_engagement,
            report_path,
            max_cost,
            prompt,
            message,
        }
    }

    pub fn version() -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    pub fn resolve_model(&self, cfg: &Config) -> String {
        self.model
            .clone()
            .or_else(|| cfg.model.clone())
            .unwrap_or_else(|| "deepseek/deepseek-v4-flash".to_string())
    }

    pub fn resolve_provider(&self, cfg: &Config) -> ProviderKind {
        self.provider
            .or(cfg.provider)
            .unwrap_or(ProviderKind::OpenRouter)
    }

    pub fn resolve_max_tokens(&self, cfg: &Config) -> u64 {
        self.max_tokens.or(cfg.max_tokens).unwrap_or(8192)
    }

    pub fn resolve_max_agent_turns(&self, cfg: &Config) -> usize {
        self.max_agent_turns.or(cfg.max_agent_turns).unwrap_or(100)
    }

    pub fn resolve_no_context_files(&self, cfg: &Config) -> bool {
        self.no_context_files || cfg.no_context_files.unwrap_or(false)
    }

    pub fn resolve_no_tools(&self, cfg: &Config) -> bool {
        self.no_tools || cfg.no_tools.unwrap_or(false)
    }

    pub fn resolve_sandbox(&self, cfg: &Config) -> bool {
        self.sandbox || cfg.sandbox.unwrap_or(false)
    }

    pub fn resolve_shell(&self, cfg: &Config) -> String {
        self.shell
            .clone()
            .or_else(|| cfg.shell.clone())
            .unwrap_or_else(|| "bash".to_string())
    }

    pub fn resolve_report_path(&self, _cfg: &Config) -> PathBuf {
        self.report_path
            .clone()
            .unwrap_or_else(|| PathBuf::from("pentest-report.md"))
    }

    pub fn resolve_security_mode(&self, cfg: &Config) -> SecurityMode {
        if self.yolo || cfg.yolo.unwrap_or(false) {
            SecurityMode::Yolo
        } else if self.accept_all || cfg.accept_all.unwrap_or(false) {
            SecurityMode::Accept
        } else if self.restrictive || cfg.restrictive.unwrap_or(false) {
            SecurityMode::Restrictive
        } else if let Some(mode) = &cfg.default_permission_mode {
            match mode.as_str() {
                "yolo" => SecurityMode::Yolo,
                "accept" => SecurityMode::Accept,
                "restrictive" => SecurityMode::Restrictive,
                _ => SecurityMode::Standard,
            }
        } else {
            SecurityMode::Standard
        }
    }
}

fn print_help() {
    println!(
        "hex {version}
A senior coding assistant and authorized offensive-security operator.

USAGE:
    hex [OPTIONS] [MESSAGE...]

GENERAL:
    -h, --help                 Show this help and exit
    -V, --version              Show version and exit
    -p, --print                Single-shot: send MESSAGE, print reply, exit
        --print-config         Print effective configuration and exit
    -c, --continue             Continue the most recent session
    -r, --resume               Pick a session to resume
        --session <id>         Resume a specific session id
        --no-session           Do not persist this session
        --no-color             Disable ANSI colour
    -n, --no-context-files     Do not auto-load AGENTS.md / CLAUDE.md / etc.

PROVIDER / MODEL:
        --provider <name>      openai | anthropic | gemini | groq |
                               openrouter | ollama | custom
        --model <name>         Model id for the chosen provider
        --api-key <key>        Override the env-var API key
        --max-tokens <n>       Cap response tokens (default 8192)
        --max-agent-turns <n>  Tool-call loop cap (default 100)
        --temperature <f>      Sampling temperature
        --prompt <name>        Named prompt preset under prompts/

TOOLS / PERMISSIONS:
    -t, --tools <name>         Restrict tools to this set (repeatable)
        --no-tools             Disable tool calling
    -R, --restrictive          Ask before every tool call
        --accept-all           Auto-approve safe tool calls
        --yolo                 Auto-approve everything (dangerous)
        --sandbox              Run in sandboxed cwd
        --shell <bin>          Shell used for the bash tool (default bash)

PENTEST (authorized only):
        --authorized-pentest   Enable security tool registry + pentest prompt
        --pentest              One-shot pentest pipeline mode
        --scope <a,b,c>        Comma-separated targets (hosts/CIDRs/domains)
        --roe <text>           Rule of engagement note (repeatable)
        --report <path>        Output markdown report path
        --max-cost <usd>       Spend cap (default unlimited)

EXAMPLES:
    hex                                                    # interactive
    hex --provider groq --model llama-3.3-70b-versatile
    hex -p \"refactor src/foo.rs to remove unwrap()\"
    hex --authorized-pentest --scope example.com \\
        --report ./report.md --max-cost 5.00

See README.md for the full agent architecture.",
        version = env!("CARGO_PKG_VERSION")
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_provider_and_model() {
        let cli = Cli::parse_from(["--provider", "openai", "--model", "gpt-4.1"]);
        assert_eq!(cli.provider, Some(ProviderKind::OpenAI));
        assert_eq!(cli.model.as_deref(), Some("gpt-4.1"));
    }

    #[test]
    fn parse_print_mode_and_prompt() {
        let cli = Cli::parse_from(["--print", "--prompt", "hello"]);
        assert!(cli.print);
        assert!(matches!(cli.mode, RuntimeMode::Print));
        assert_eq!(cli.prompt.as_deref(), Some("hello"));
    }

    #[test]
    fn cli_values_override_config() {
        let cli = Cli::parse_from(["--model", "cli-model", "--no-tools", "--yolo"]);
        let cfg = Config {
            model: Some("cfg-model".to_string()),
            no_tools: Some(false),
            yolo: Some(false),
            ..Config::default()
        };

        assert_eq!(cli.resolve_model(&cfg), "cli-model");
        assert!(cli.resolve_no_tools(&cfg));
        assert_eq!(cli.resolve_security_mode(&cfg), SecurityMode::Yolo);
    }

    #[test]
    fn config_values_used_when_cli_missing() {
        let cli = Cli::parse_from(std::iter::empty::<&str>());
        let cfg = Config {
            provider: Some(ProviderKind::Anthropic),
            model: Some("claude".to_string()),
            max_tokens: Some(2222),
            max_agent_turns: Some(22),
            no_context_files: Some(true),
            shell: Some("zsh".to_string()),
            ..Config::default()
        };

        assert_eq!(cli.resolve_provider(&cfg), ProviderKind::Anthropic);
        assert_eq!(cli.resolve_model(&cfg), "claude");
        assert_eq!(cli.resolve_max_tokens(&cfg), 2222);
        assert_eq!(cli.resolve_max_agent_turns(&cfg), 22);
        assert!(cli.resolve_no_context_files(&cfg));
        assert_eq!(cli.resolve_shell(&cfg), "zsh");
    }

    #[test]
    fn fallback_defaults_applied() {
        let cli = Cli::parse_from(std::iter::empty::<&str>());
        let cfg = Config::default();

        assert_eq!(cli.resolve_provider(&cfg), ProviderKind::OpenRouter);
        assert_eq!(cli.resolve_model(&cfg), "deepseek/deepseek-v4-flash");
        assert_eq!(cli.resolve_max_tokens(&cfg), 8192);
        assert_eq!(cli.resolve_max_agent_turns(&cfg), 100);
        assert_eq!(cli.resolve_shell(&cfg), "bash");
        assert_eq!(cli.resolve_security_mode(&cfg), SecurityMode::Standard);
    }

    #[test]
    fn security_mode_precedence_matches_zerostack() {
        let cli = Cli::parse_from(["--accept-all"]);
        let cfg = Config {
            yolo: Some(true),
            ..Config::default()
        };
        assert_eq!(cli.resolve_security_mode(&cfg), SecurityMode::Yolo);

        let cli = Cli::parse_from(std::iter::empty::<&str>());
        let cfg = Config {
            default_permission_mode: Some("restrictive".to_string()),
            ..Config::default()
        };
        assert_eq!(cli.resolve_security_mode(&cfg), SecurityMode::Restrictive);
    }

    #[test]
    fn parses_pentest_flags_with_scope_and_report() {
        let cli = Cli::parse_from([
            "--pentest",
            "--authorized-pentest",
            "--scope",
            "host-a.example",
            "--scope",
            "host-b.example,host-c.example",
            "--roe",
            "no DoS",
            "--rules-of-engagement",
            "business hours only",
            "--report",
            "/tmp/x.md",
        ]);
        assert!(matches!(cli.mode, RuntimeMode::Pentest));
        assert!(cli.authorized_pentest);
        assert_eq!(
            cli.scope,
            vec!["host-a.example", "host-b.example", "host-c.example"]
        );
        assert_eq!(
            cli.rules_of_engagement,
            vec!["no DoS", "business hours only"]
        );
        assert_eq!(
            cli.resolve_report_path(&Config::default()),
            PathBuf::from("/tmp/x.md")
        );
    }

    #[test]
    fn default_report_path_when_not_provided() {
        let cli = Cli::parse_from(std::iter::empty::<&str>());
        assert_eq!(
            cli.resolve_report_path(&Config::default()),
            PathBuf::from("pentest-report.md")
        );
    }
}

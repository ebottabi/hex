use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};

use crate::agent::tools::ToolError;
use crate::agent::tools::sec::{
    SecContext, check_targets_in_scope, preflight, record, require_policy, run_shell, shq,
};

#[derive(Deserialize)]
pub struct SubfinderArgs {
    pub domain: String,
    #[serde(default)]
    pub all_sources: Option<bool>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubfinderOutput {
    pub domain: String,
    pub subdomains: Vec<String>,
    pub raw_command: String,
    pub exit_code: i32,
    pub stderr_tail: String,
}

pub struct SubfinderTool {
    ctx: SecContext,
}

impl SubfinderTool {
    pub fn new(ctx: SecContext) -> Self {
        SubfinderTool { ctx }
    }
}

impl Tool for SubfinderTool {
    const NAME: &'static str = "subfinder";
    type Error = ToolError;
    type Args = SubfinderArgs;
    type Output = SubfinderOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: "Passive subdomain enumeration via subfinder. Requires the root domain \
                          to be inside the engagement scope."
                .to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "domain": { "type": "string", "description": "Root domain, e.g. example.com" },
                    "all_sources": { "type": "boolean", "description": "Use all subfinder sources (slower, broader)" },
                    "timeout_secs": { "type": "integer" }
                },
                "required": ["domain"]
            }),
        }
    }

    async fn call(&self, args: SubfinderArgs) -> Result<SubfinderOutput, ToolError> {
        let policy = require_policy(&self.ctx)?;
        check_targets_in_scope(&policy, std::slice::from_ref(&args.domain))?;
        preflight("subfinder").await?;

        let mut argv: Vec<String> = vec![
            "subfinder".into(),
            "-silent".into(),
            "-d".into(),
            args.domain.clone(),
        ];
        if args.all_sources.unwrap_or(false) {
            argv.push("-all".into());
        }
        let cmd = argv.iter().map(|s| shq(s)).collect::<Vec<_>>().join(" ");
        let outcome = run_shell(&self.ctx, &cmd, args.timeout_secs.unwrap_or(300)).await?;
        let subs = parse_subfinder_lines(&outcome.stdout);

        let summary = format!("subfinder: {} subdomain(s) for {}", subs.len(), args.domain);
        record(&self.ctx, "subfinder", &argv, &outcome, &summary);

        Ok(SubfinderOutput {
            domain: args.domain,
            subdomains: subs,
            raw_command: cmd,
            exit_code: outcome.exit_code,
            stderr_tail: tail(&outcome.stderr, 500),
        })
    }
}

fn tail(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        s[s.len() - n..].to_string()
    }
}

pub fn parse_subfinder_lines(s: &str) -> Vec<String> {
    let mut out: Vec<String> = s
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('['))
        .map(|l| l.to_string())
        .collect();
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_dedups_lines() {
        let sample = "api.example.com\nwww.example.com\napi.example.com\n\n";
        let subs = parse_subfinder_lines(sample);
        assert_eq!(subs.len(), 2);
        assert_eq!(subs[0], "api.example.com");
        assert_eq!(subs[1], "www.example.com");
    }

    #[test]
    fn skips_banner_lines() {
        let sample = "[INF] starting\napi.example.com\n";
        let subs = parse_subfinder_lines(sample);
        assert_eq!(subs, vec!["api.example.com".to_string()]);
    }
}

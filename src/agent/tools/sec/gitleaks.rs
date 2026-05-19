use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};

use crate::agent::tools::ToolError;
use crate::agent::tools::sec::{SecContext, preflight, record, require_policy, run_shell, shq};

#[derive(Deserialize)]
pub struct GitleaksArgs {
    pub source: String,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub config: Option<String>,
    #[serde(default)]
    pub redact: Option<bool>,
    #[serde(default)]
    pub log_opts: Option<String>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GitleaksFinding {
    pub rule_id: String,
    pub description: Option<String>,
    pub file: String,
    pub start_line: u64,
    pub end_line: u64,
    pub commit: Option<String>,
    pub author: Option<String>,
    pub email: Option<String>,
    pub date: Option<String>,
    pub secret_redacted: Option<String>,
    pub entropy: Option<f64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GitleaksOutput {
    pub findings: Vec<GitleaksFinding>,
    pub raw_command: String,
    pub exit_code: i32,
    pub stderr_tail: String,
}

pub struct GitleaksTool {
    ctx: SecContext,
}

impl GitleaksTool {
    pub fn new(ctx: SecContext) -> Self {
        GitleaksTool { ctx }
    }
}

impl Tool for GitleaksTool {
    const NAME: &'static str = "gitleaks";
    type Error = ToolError;
    type Args = GitleaksArgs;
    type Output = GitleaksOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: "Scan a directory or git repo for committed secrets via gitleaks. \
                          Returns typed findings (rule id, file, line range, optional commit \
                          metadata, redacted secret). Requires an active pentest engagement."
                .to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "source": { "type": "string", "description": "Path to directory or git repo" },
                    "mode": { "type": "string",
                              "description": "Subcommand: detect (git history, default), dir (filesystem only)" },
                    "config": { "type": "string", "description": "Path to .gitleaks.toml" },
                    "redact": { "type": "boolean", "description": "Redact secret values (default true)" },
                    "log_opts": { "type": "string",
                                  "description": "Pass-through to git log, e.g. '--since=2024-01-01'" },
                    "timeout_secs": { "type": "integer" }
                },
                "required": ["source"]
            }),
        }
    }

    async fn call(&self, args: GitleaksArgs) -> Result<GitleaksOutput, ToolError> {
        let _policy = require_policy(&self.ctx)?;
        preflight("gitleaks").await?;

        let mode = args.mode.clone().unwrap_or_else(|| "detect".to_string());
        let mut argv: Vec<String> = vec![
            "gitleaks".into(),
            mode,
            "--source".into(),
            args.source.clone(),
            "--report-format".into(),
            "json".into(),
            "--report-path".into(),
            "/dev/stdout".into(),
            "--no-banner".into(),
            "--exit-code".into(),
            "0".into(),
        ];
        if args.redact.unwrap_or(true) {
            argv.push("--redact".into());
        }
        if let Some(c) = &args.config {
            argv.push("--config".into());
            argv.push(c.clone());
        }
        if let Some(lo) = &args.log_opts {
            argv.push("--log-opts".into());
            argv.push(lo.clone());
        }

        let cmd = argv.iter().map(|s| shq(s)).collect::<Vec<_>>().join(" ");
        let outcome = run_shell(&self.ctx, &cmd, args.timeout_secs.unwrap_or(600)).await?;
        let findings = parse_gitleaks_json(&outcome.stdout);

        let summary = format!("gitleaks: {} finding(s)", findings.len());
        record(&self.ctx, "gitleaks", &argv, &outcome, &summary);

        Ok(GitleaksOutput {
            findings,
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

pub fn parse_gitleaks_json(s: &str) -> Vec<GitleaksFinding> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let v: serde_json::Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let arr = match v.as_array() {
        Some(a) => a,
        None => return Vec::new(),
    };
    let mut out = Vec::with_capacity(arr.len());
    for f in arr {
        let rule_id = f
            .get("RuleID")
            .or_else(|| f.get("ruleID"))
            .or_else(|| f.get("rule_id"))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if rule_id.is_empty() {
            continue;
        }
        out.push(GitleaksFinding {
            rule_id,
            description: f
                .get("Description")
                .or_else(|| f.get("description"))
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
            file: f
                .get("File")
                .or_else(|| f.get("file"))
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            start_line: f
                .get("StartLine")
                .or_else(|| f.get("startLine"))
                .and_then(|x| x.as_u64())
                .unwrap_or(0),
            end_line: f
                .get("EndLine")
                .or_else(|| f.get("endLine"))
                .and_then(|x| x.as_u64())
                .unwrap_or(0),
            commit: f
                .get("Commit")
                .or_else(|| f.get("commit"))
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
            author: f
                .get("Author")
                .or_else(|| f.get("author"))
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
            email: f
                .get("Email")
                .or_else(|| f.get("email"))
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
            date: f
                .get("Date")
                .or_else(|| f.get("date"))
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
            secret_redacted: f
                .get("Secret")
                .or_else(|| f.get("secret"))
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
            entropy: f
                .get("Entropy")
                .or_else(|| f.get("entropy"))
                .and_then(|x| x.as_f64()),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typical_array() {
        let sample = r#"[
          {"RuleID":"aws-access-token","Description":"AWS","File":"src/config.js",
           "StartLine":12,"EndLine":12,"Commit":"abc123","Author":"alice",
           "Email":"a@b","Date":"2024-01-01","Secret":"REDACTED","Entropy":4.5},
          {"RuleID":"slack-webhook","File":"deploy.sh","StartLine":1,"EndLine":1}
        ]"#;
        let r = parse_gitleaks_json(sample);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].rule_id, "aws-access-token");
        assert_eq!(r[0].commit.as_deref(), Some("abc123"));
        assert_eq!(r[0].entropy, Some(4.5));
        assert_eq!(r[1].rule_id, "slack-webhook");
    }

    #[test]
    fn empty_and_invalid_yield_empty() {
        assert_eq!(parse_gitleaks_json("").len(), 0);
        assert_eq!(parse_gitleaks_json("[]").len(), 0);
        assert_eq!(parse_gitleaks_json("{not json").len(), 0);
    }
}

use rig::completion::ToolDefinition;
use rig::tool::Tool;
use schemars::JsonSchema;
use crate::agent::tools::schema::append_output_schema;
use serde::{Deserialize, Serialize};

use crate::agent::tools::ToolError;
use crate::agent::tools::sec::{SecContext, preflight, record, require_policy, run_shell, shq};

#[derive(Deserialize, JsonSchema)]
pub struct JohnArgs {
    pub hash_file: String,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub wordlist: Option<String>,
    #[serde(default)]
    pub rules: Option<String>,
    #[serde(default)]
    pub incremental: Option<bool>,
    #[serde(default)]
    pub session: Option<String>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct JohnCracked {
    pub user: String,
    pub plaintext: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct JohnOutput {
    pub cracked: Vec<JohnCracked>,
    pub raw_command: String,
    pub exit_code: i32,
    pub stdout_tail: String,
    pub stderr_tail: String,
}

pub struct JohnTool {
    ctx: SecContext,
}

impl JohnTool {
    pub fn new(ctx: SecContext) -> Self {
        JohnTool { ctx }
    }
}

impl Tool for JohnTool {
    const NAME: &'static str = "john";
    type Error = ToolError;
    type Args = JohnArgs;
    type Output = JohnOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: append_output_schema::<JohnOutput>("John the Ripper offline cracker. Runs the cracker, then `john --show` \
                          to enumerate recovered credentials. Returns user:plaintext pairs."),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "hash_file": { "type": "string" },
                    "format": { "type": "string", "description": "John format string (--format=)" },
                    "wordlist": { "type": "string" },
                    "rules": { "type": "string", "description": "Rule set name, e.g. 'best64'" },
                    "incremental": { "type": "boolean", "description": "Use --incremental" },
                    "session": { "type": "string" },
                    "timeout_secs": { "type": "integer" }
                },
                "required": ["hash_file"]
            }),
        }
    }

    async fn call(&self, args: JohnArgs) -> Result<JohnOutput, ToolError> {
        let _policy = require_policy(&self.ctx)?;
        preflight("john").await?;

        let mut crack_argv: Vec<String> = vec!["john".into()];
        if let Some(f) = &args.format {
            crack_argv.push(format!("--format={}", f));
        }
        if let Some(w) = &args.wordlist {
            crack_argv.push(format!("--wordlist={}", w));
        }
        if let Some(r) = &args.rules {
            crack_argv.push(format!("--rules={}", r));
        }
        if args.incremental.unwrap_or(false) {
            crack_argv.push("--incremental".into());
        }
        if let Some(s) = &args.session {
            crack_argv.push(format!("--session={}", s));
        }
        crack_argv.push(args.hash_file.clone());

        let mut show_argv: Vec<String> = vec!["john".into(), "--show".into()];
        if let Some(f) = &args.format {
            show_argv.push(format!("--format={}", f));
        }
        show_argv.push(args.hash_file.clone());

        let crack_cmd = crack_argv
            .iter()
            .map(|s| shq(s))
            .collect::<Vec<_>>()
            .join(" ");
        let show_cmd = show_argv
            .iter()
            .map(|s| shq(s))
            .collect::<Vec<_>>()
            .join(" ");
        let cmd = format!("{} ; {}", crack_cmd, show_cmd);

        let outcome = run_shell(&self.ctx, &cmd, args.timeout_secs.unwrap_or(1800)).await?;
        let cracked = parse_john_show(&outcome.stdout);

        let summary = format!("john: {} cracked hash(es)", cracked.len());
        record(&self.ctx, "john", &crack_argv, &outcome, &summary);

        Ok(JohnOutput {
            cracked,
            raw_command: cmd,
            exit_code: outcome.exit_code,
            stdout_tail: tail(&outcome.stdout, 2000),
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

pub fn parse_john_show(stdout: &str) -> Vec<JohnCracked> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        // Skip footer like "2 password hashes cracked, 0 left"
        if line.contains(" password hashes ") || line.starts_with("No password hashes") {
            continue;
        }
        // Format: user:plaintext[:remainder]
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() < 2 {
            continue;
        }
        let user = parts[0];
        let plaintext = parts[1];
        if user.is_empty() || plaintext.is_empty() {
            continue;
        }
        out.push(JohnCracked {
            user: user.to_string(),
            plaintext: plaintext.to_string(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_show_output() {
        let sample = "admin:hunter2:::::\n\
                      jdoe:Welcome1:::::\n\
                      \n\
                      2 password hashes cracked, 0 left\n";
        let r = parse_john_show(sample);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].user, "admin");
        assert_eq!(r[0].plaintext, "hunter2");
        assert_eq!(r[1].user, "jdoe");
    }

    #[test]
    fn ignores_empty_and_footer() {
        let sample = "No password hashes loaded\n\n";
        let r = parse_john_show(sample);
        assert_eq!(r.len(), 0);
    }
}

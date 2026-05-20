use crate::agent::tools::schema::append_output_schema;
use rig::completion::ToolDefinition;
use rig::tool::Tool;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::agent::tools::ToolError;
use crate::agent::tools::sec::{SecContext, preflight, record, require_policy, run_shell, shq};

#[derive(Deserialize, JsonSchema)]
pub struct R2Args {
    pub file: String,
    pub commands: String,
    #[serde(default)]
    pub analyze: Option<bool>,
    #[serde(default)]
    pub write: Option<bool>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct R2Output {
    pub file: String,
    pub stdout: String,
    pub json: Option<serde_json::Value>,
    pub raw_command: String,
    pub exit_code: i32,
    pub stderr_tail: String,
}

pub struct R2Tool {
    ctx: SecContext,
}

impl R2Tool {
    pub fn new(ctx: SecContext) -> Self {
        R2Tool { ctx }
    }
}

impl Tool for R2Tool {
    const NAME: &'static str = "r2";
    type Error = ToolError;
    type Args = R2Args;
    type Output = R2Output;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: append_output_schema::<R2Output>(
                "radare2 batch executor. Runs r2 -q with the given commands against \
                          a binary. Use `aaa` for analysis, `iIj`/`aflj`/`izzj` for JSON output \
                          (those will be parsed into the `json` field if the final stdout is \
                          JSON). Local only. Use `write=true` for `-w` (write mode). ",
            ),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "file": { "type": "string", "description": "Path to binary" },
                    "commands": { "type": "string",
                                  "description": "Semicolon-separated r2 commands, e.g. 'aaa; aflj'" },
                    "analyze": { "type": "boolean", "description": "Prepend `aaa;` (auto analyze)" },
                    "write": { "type": "boolean", "description": "Open in write mode (-w)" },
                    "timeout_secs": { "type": "integer" }
                },
                "required": ["file", "commands"]
            }),
        }
    }

    async fn call(&self, args: R2Args) -> Result<R2Output, ToolError> {
        let _ = require_policy(&self.ctx)?;
        let binary = if which_available("r2").await {
            "r2"
        } else {
            "radare2"
        };
        preflight(binary).await?;

        let mut commands = args.commands.clone();
        if args.analyze.unwrap_or(false) && !commands.trim_start().starts_with("aaa") {
            commands = format!("aaa; {}", commands);
        }

        let mut argv: Vec<String> = vec![binary.into(), "-q".into()];
        if args.write.unwrap_or(false) {
            argv.push("-w".into());
        }
        argv.push("-c".into());
        argv.push(commands.clone());
        argv.push(args.file.clone());

        let cmd = argv.iter().map(|s| shq(s)).collect::<Vec<_>>().join(" ");
        let outcome = run_shell(&self.ctx, &cmd, args.timeout_secs.unwrap_or(120)).await?;
        let json = serde_json::from_str::<serde_json::Value>(outcome.stdout.trim()).ok();

        let summary = format!(
            "r2 {}: {} bytes stdout, json={}",
            args.file,
            outcome.stdout.len(),
            json.is_some()
        );
        record(&self.ctx, "r2", &argv, &outcome, &summary);

        Ok(R2Output {
            file: args.file,
            stdout: outcome.stdout.clone(),
            json,
            raw_command: cmd,
            exit_code: outcome.exit_code,
            stderr_tail: tail(&outcome.stderr, 500),
        })
    }
}

async fn which_available(binary: &str) -> bool {
    tokio::process::Command::new("which")
        .arg(binary)
        .output()
        .await
        .map(|o| o.status.success() && !o.stdout.is_empty())
        .unwrap_or(false)
}

fn tail(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        s[s.len() - n..].to_string()
    }
}

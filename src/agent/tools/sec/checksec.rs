use crate::agent::tools::schema::append_output_schema;
use rig::completion::ToolDefinition;
use rig::tool::Tool;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::agent::tools::ToolError;
use crate::agent::tools::sec::{SecContext, preflight, record, require_policy, run_shell, shq};

#[derive(Deserialize, JsonSchema)]
pub struct ChecksecArgs {
    pub file: String,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ChecksecOutput {
    pub file: String,
    pub relro: Option<String>,
    pub canary: Option<String>,
    pub nx: Option<String>,
    pub pie: Option<String>,
    pub rpath: Option<String>,
    pub runpath: Option<String>,
    pub symbols: Option<String>,
    pub fortify_source: Option<String>,
    pub fortified: Option<String>,
    pub fortify_able: Option<String>,
    pub raw_command: String,
    pub exit_code: i32,
    pub stderr_tail: String,
}

pub struct ChecksecTool {
    ctx: SecContext,
}

impl ChecksecTool {
    pub fn new(ctx: SecContext) -> Self {
        ChecksecTool { ctx }
    }
}

impl Tool for ChecksecTool {
    const NAME: &'static str = "checksec";
    type Error = ToolError;
    type Args = ChecksecArgs;
    type Output = ChecksecOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: append_output_schema::<ChecksecOutput>(
                "checksec.sh binary hardening checker. Returns RELRO, stack canary, \
                          NX, PIE, RPATH/RUNPATH, symbols, and FORTIFY_SOURCE status for an \
                          ELF/Mach-O binary. Local only.",
            ),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "file": { "type": "string", "description": "Path to binary" },
                    "timeout_secs": { "type": "integer" }
                },
                "required": ["file"]
            }),
        }
    }

    async fn call(&self, args: ChecksecArgs) -> Result<ChecksecOutput, ToolError> {
        let _ = require_policy(&self.ctx)?;
        preflight("checksec").await?;

        let argv: Vec<String> = vec![
            "checksec".into(),
            "--output=json".into(),
            "--file".into(),
            args.file.clone(),
        ];
        let cmd = argv.iter().map(|s| shq(s)).collect::<Vec<_>>().join(" ");
        let outcome = run_shell(&self.ctx, &cmd, args.timeout_secs.unwrap_or(60)).await?;
        let parsed = parse_checksec_json(&outcome.stdout);

        let summary = format!(
            "checksec {}: relro={} canary={} nx={} pie={}",
            args.file,
            parsed.relro.as_deref().unwrap_or("?"),
            parsed.canary.as_deref().unwrap_or("?"),
            parsed.nx.as_deref().unwrap_or("?"),
            parsed.pie.as_deref().unwrap_or("?"),
        );
        record(&self.ctx, "checksec", &argv, &outcome, &summary);

        Ok(ChecksecOutput {
            file: args.file,
            relro: parsed.relro,
            canary: parsed.canary,
            nx: parsed.nx,
            pie: parsed.pie,
            rpath: parsed.rpath,
            runpath: parsed.runpath,
            symbols: parsed.symbols,
            fortify_source: parsed.fortify_source,
            fortified: parsed.fortified,
            fortify_able: parsed.fortify_able,
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

#[derive(Default)]
pub struct ParsedChecksec {
    pub relro: Option<String>,
    pub canary: Option<String>,
    pub nx: Option<String>,
    pub pie: Option<String>,
    pub rpath: Option<String>,
    pub runpath: Option<String>,
    pub symbols: Option<String>,
    pub fortify_source: Option<String>,
    pub fortified: Option<String>,
    pub fortify_able: Option<String>,
}

pub fn parse_checksec_json(s: &str) -> ParsedChecksec {
    let trimmed = s.trim();
    let v: serde_json::Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(_) => return ParsedChecksec::default(),
    };
    // Top-level is {"<file_path>": {...fields...}} OR sometimes the fields directly.
    let obj = if let Some(map) = v.as_object() {
        if map.len() == 1 {
            let only = map.values().next().unwrap();
            if only.is_object() {
                only.clone()
            } else {
                v.clone()
            }
        } else {
            v.clone()
        }
    } else {
        return ParsedChecksec::default();
    };
    let g =
        |k: &str| -> Option<String> { obj.get(k).and_then(|x| x.as_str()).map(|s| s.to_string()) };
    ParsedChecksec {
        relro: g("relro"),
        canary: g("canary"),
        nx: g("nx"),
        pie: g("pie"),
        rpath: g("rpath"),
        runpath: g("runpath"),
        symbols: g("symbols"),
        fortify_source: g("fortify_source"),
        fortified: g("fortified"),
        fortify_able: g("fortify-able").or_else(|| g("fortify_able")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_wrapped_json() {
        let sample = r#"{"/bin/ls":{"relro":"full","canary":"yes","nx":"yes","pie":"yes","rpath":"no","runpath":"no","symbols":"no","fortify_source":"yes","fortified":"4","fortify-able":"10"}}"#;
        let r = parse_checksec_json(sample);
        assert_eq!(r.relro.as_deref(), Some("full"));
        assert_eq!(r.canary.as_deref(), Some("yes"));
        assert_eq!(r.fortify_able.as_deref(), Some("10"));
    }

    #[test]
    fn parses_flat_json() {
        let sample = r#"{"relro":"partial","nx":"yes"}"#;
        let r = parse_checksec_json(sample);
        assert_eq!(r.relro.as_deref(), Some("partial"));
        assert_eq!(r.canary, None);
    }
}

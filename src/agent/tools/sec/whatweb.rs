use crate::agent::tools::schema::append_output_schema;
use rig::completion::ToolDefinition;
use rig::tool::Tool;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::agent::tools::ToolError;
use crate::agent::tools::sec::{
    SecContext, check_targets_in_scope, preflight, record, require_policy, run_shell, shq,
};

#[derive(Deserialize, JsonSchema)]
pub struct WhatwebArgs {
    pub targets: Vec<String>,
    #[serde(default)]
    pub aggression: Option<u8>,
    #[serde(default)]
    pub user_agent: Option<String>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct WhatwebResult {
    pub target: String,
    pub http_status: Option<u16>,
    pub plugins: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct WhatwebOutput {
    pub results: Vec<WhatwebResult>,
    pub raw_command: String,
    pub exit_code: i32,
    pub stderr_tail: String,
}

pub struct WhatwebTool {
    ctx: SecContext,
}

impl WhatwebTool {
    pub fn new(ctx: SecContext) -> Self {
        WhatwebTool { ctx }
    }
}

impl Tool for WhatwebTool {
    const NAME: &'static str = "whatweb";
    type Error = ToolError;
    type Args = WhatwebArgs;
    type Output = WhatwebOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: append_output_schema::<WhatwebOutput>(
                "Identify web technologies via whatweb. Returns typed plugin/tech \
                          fingerprints per in-scope target.",
            ),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "targets": { "type": "array", "items": {"type": "string"} },
                    "aggression": { "type": "integer",
                                    "description": "Aggression level 1-4 (-a). 1=passive, 3=aggressive, 4=heavy" },
                    "user_agent": { "type": "string" },
                    "timeout_secs": { "type": "integer" }
                },
                "required": ["targets"]
            }),
        }
    }

    async fn call(&self, args: WhatwebArgs) -> Result<WhatwebOutput, ToolError> {
        let policy = require_policy(&self.ctx)?;
        if args.targets.is_empty() {
            return Err(ToolError::Msg("whatweb: targets required".into()));
        }
        let hosts: Vec<String> = args.targets.iter().map(|u| host_of(u)).collect();
        check_targets_in_scope(&policy, &hosts)?;
        preflight("whatweb").await?;

        let mut argv: Vec<String> = vec![
            "whatweb".into(),
            "--no-errors".into(),
            "--log-json=/dev/stdout".into(),
            "--quiet".into(),
        ];
        if let Some(a) = args.aggression {
            argv.push(format!("-a{}", a.min(4).max(1)));
        }
        if let Some(ua) = &args.user_agent {
            argv.push("-U".into());
            argv.push(ua.clone());
        }
        for t in &args.targets {
            argv.push(t.clone());
        }

        let cmd = argv.iter().map(|s| shq(s)).collect::<Vec<_>>().join(" ");
        let outcome = run_shell(&self.ctx, &cmd, args.timeout_secs.unwrap_or(300)).await?;
        let results = parse_whatweb_jsonl(&outcome.stdout);

        let summary = format!("whatweb: fingerprinted {} target(s)", results.len());
        record(&self.ctx, "whatweb", &argv, &outcome, &summary);

        Ok(WhatwebOutput {
            results,
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

fn host_of(url: &str) -> String {
    let s = url.trim();
    let no_scheme = s.splitn(2, "://").nth(1).unwrap_or(s);
    no_scheme.split('/').next().unwrap_or(no_scheme).to_string()
}

pub fn parse_whatweb_jsonl(s: &str) -> Vec<WhatwebResult> {
    let mut out = Vec::new();
    for line in s.lines() {
        let line = line.trim().trim_end_matches(',');
        if line.is_empty() || line == "[" || line == "]" {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let target = v
            .get("target")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if target.is_empty() {
            continue;
        }
        let http_status = v
            .get("http_status")
            .and_then(|x| {
                x.as_u64()
                    .or_else(|| x.as_str().and_then(|s| s.parse().ok()))
            })
            .map(|n| n as u16);
        let mut plugins = BTreeMap::new();
        if let Some(obj) = v.get("plugins").and_then(|x| x.as_object()) {
            for (name, pv) in obj {
                let mut vals: Vec<String> = Vec::new();
                if let Some(versions) = pv.get("version").and_then(|x| x.as_array()) {
                    for ver in versions {
                        if let Some(s) = ver.as_str() {
                            vals.push(format!("version:{}", s));
                        }
                    }
                }
                if let Some(strings) = pv.get("string").and_then(|x| x.as_array()) {
                    for sv in strings {
                        if let Some(s) = sv.as_str() {
                            vals.push(s.to_string());
                        }
                    }
                }
                plugins.insert(name.clone(), vals);
            }
        }
        out.push(WhatwebResult {
            target,
            http_status,
            plugins,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_log_json_line() {
        let sample = "{\"target\":\"https://example.com\",\"http_status\":200,\"plugins\":{\"nginx\":{\"version\":[\"1.18.0\"]},\"HTML5\":{},\"Title\":{\"string\":[\"Example Domain\"]}}}\n";
        let r = parse_whatweb_jsonl(sample);
        assert_eq!(r.len(), 1);
        let row = &r[0];
        assert_eq!(row.target, "https://example.com");
        assert_eq!(row.http_status, Some(200));
        assert_eq!(
            row.plugins.get("nginx").unwrap(),
            &vec!["version:1.18.0".to_string()]
        );
        assert!(row.plugins.contains_key("HTML5"));
    }

    #[test]
    fn parses_array_jsonl_with_commas() {
        let sample = "[\n{\"target\":\"https://a\",\"plugins\":{\"x\":{}}},\n{\"target\":\"https://b\",\"plugins\":{\"y\":{}}}\n]\n";
        let r = parse_whatweb_jsonl(sample);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].target, "https://a");
        assert_eq!(r[1].target, "https://b");
    }
}

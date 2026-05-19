use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};

use crate::agent::tools::ToolError;
use crate::agent::tools::sec::{
    SecContext, check_targets_in_scope, preflight, record, require_policy, run_shell, shq,
};

#[derive(Deserialize)]
pub struct NucleiArgs {
    pub targets: Vec<String>,
    #[serde(default)]
    pub templates: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub tags: Option<String>,
    #[serde(default)]
    pub rate_limit: Option<u32>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NucleiFinding {
    pub template_id: String,
    pub name: Option<String>,
    pub severity: Option<String>,
    pub host: Option<String>,
    pub matched_at: Option<String>,
    pub type_: Option<String>,
    pub tags: Vec<String>,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NucleiOutput {
    pub findings: Vec<NucleiFinding>,
    pub raw_command: String,
    pub exit_code: i32,
    pub stderr_tail: String,
}

pub struct NucleiTool {
    ctx: SecContext,
}

impl NucleiTool {
    pub fn new(ctx: SecContext) -> Self {
        NucleiTool { ctx }
    }
}

impl Tool for NucleiTool {
    const NAME: &'static str = "nuclei";
    type Error = ToolError;
    type Args = NucleiArgs;
    type Output = NucleiOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: "Run ProjectDiscovery nuclei against in-scope HTTP(S) targets with \
                          templated vulnerability checks. Returns typed findings (template id, \
                          severity, matched URL). All targets must be in scope."
                .to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "targets": { "type": "array", "items": {"type": "string"},
                                 "description": "URLs or hosts to scan" },
                    "templates": { "type": "string",
                                   "description": "Template path, ID, or comma-separated list (-t)" },
                    "severity": { "type": "string",
                                  "description": "Comma-separated severities: info,low,medium,high,critical" },
                    "tags": { "type": "string",
                              "description": "Comma-separated template tags filter (-tags)" },
                    "rate_limit": { "type": "integer", "description": "Requests per second (-rl)" },
                    "timeout_secs": { "type": "integer" }
                },
                "required": ["targets"]
            }),
        }
    }

    async fn call(&self, args: NucleiArgs) -> Result<NucleiOutput, ToolError> {
        let policy = require_policy(&self.ctx)?;
        if args.targets.is_empty() {
            return Err(ToolError::Msg("nuclei: targets required".into()));
        }
        let hosts: Vec<String> = args.targets.iter().map(|u| host_of(u)).collect();
        check_targets_in_scope(&policy, &hosts)?;
        preflight("nuclei").await?;

        let mut argv: Vec<String> = vec![
            "nuclei".into(),
            "-silent".into(),
            "-jsonl".into(),
            "-no-color".into(),
            "-disable-update-check".into(),
        ];
        if let Some(t) = &args.templates {
            argv.push("-t".into());
            argv.push(t.clone());
        }
        if let Some(s) = &args.severity {
            argv.push("-severity".into());
            argv.push(s.clone());
        }
        if let Some(t) = &args.tags {
            argv.push("-tags".into());
            argv.push(t.clone());
        }
        if let Some(rl) = args.rate_limit {
            argv.push("-rl".into());
            argv.push(rl.to_string());
        }

        let stdin = args.targets.join("\n");
        let cmd = format!(
            "printf {} | {}",
            shq(&stdin),
            argv.iter().map(|s| shq(s)).collect::<Vec<_>>().join(" ")
        );
        let outcome = run_shell(&self.ctx, &cmd, args.timeout_secs.unwrap_or(600)).await?;
        let findings = parse_nuclei_jsonl(&outcome.stdout);

        let summary = format!("nuclei: {} finding(s)", findings.len());
        record(&self.ctx, "nuclei", &argv, &outcome, &summary);

        Ok(NucleiOutput {
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

fn host_of(url: &str) -> String {
    let s = url.trim();
    let no_scheme = s.splitn(2, "://").nth(1).unwrap_or(s);
    no_scheme.split('/').next().unwrap_or(no_scheme).to_string()
}

pub fn parse_nuclei_jsonl(s: &str) -> Vec<NucleiFinding> {
    let mut out = Vec::new();
    for line in s.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let template_id = v
            .get("template-id")
            .or_else(|| v.get("templateID"))
            .or_else(|| v.get("template_id"))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if template_id.is_empty() {
            continue;
        }
        let info = v.get("info");
        let name = info
            .and_then(|i| i.get("name"))
            .and_then(|x| x.as_str())
            .map(|s| s.to_string());
        let severity = info
            .and_then(|i| i.get("severity"))
            .and_then(|x| x.as_str())
            .map(|s| s.to_string());
        let description = info
            .and_then(|i| i.get("description"))
            .and_then(|x| x.as_str())
            .map(|s| s.to_string());
        let tags = info
            .and_then(|i| i.get("tags"))
            .and_then(|t| {
                if let Some(arr) = t.as_array() {
                    Some(
                        arr.iter()
                            .filter_map(|e| e.as_str().map(|s| s.to_string()))
                            .collect::<Vec<_>>(),
                    )
                } else {
                    t.as_str().map(|s| {
                        s.split(',')
                            .map(|x| x.trim().to_string())
                            .filter(|x| !x.is_empty())
                            .collect::<Vec<_>>()
                    })
                }
            })
            .unwrap_or_default();
        let host = v
            .get("host")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string());
        let matched_at = v
            .get("matched-at")
            .or_else(|| v.get("matched_at"))
            .or_else(|| v.get("matched"))
            .and_then(|x| x.as_str())
            .map(|s| s.to_string());
        let type_ = v
            .get("type")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string());
        out.push(NucleiFinding {
            template_id,
            name,
            severity,
            host,
            matched_at,
            type_,
            tags,
            description,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typical_finding() {
        let sample = "{\"template-id\":\"http-missing-security-headers\",\"info\":{\"name\":\"Missing Security Headers\",\"severity\":\"info\",\"tags\":[\"misconfig\",\"headers\"]},\"host\":\"https://example.com\",\"matched-at\":\"https://example.com\",\"type\":\"http\"}\n";
        let findings = parse_nuclei_jsonl(sample);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.template_id, "http-missing-security-headers");
        assert_eq!(f.severity.as_deref(), Some("info"));
        assert_eq!(f.name.as_deref(), Some("Missing Security Headers"));
        assert_eq!(f.tags, vec!["misconfig".to_string(), "headers".to_string()]);
    }

    #[test]
    fn skips_invalid_lines() {
        let sample = "not json\n{\"template-id\":\"x\",\"info\":{\"severity\":\"high\"}}\n";
        let findings = parse_nuclei_jsonl(sample);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity.as_deref(), Some("high"));
    }
}

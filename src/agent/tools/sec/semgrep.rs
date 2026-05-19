use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};

use crate::agent::tools::ToolError;
use crate::agent::tools::sec::{SecContext, preflight, record, require_policy, run_shell, shq};

#[derive(Deserialize)]
pub struct SemgrepArgs {
    pub path: String,
    #[serde(default)]
    pub config: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub exclude: Option<Vec<String>>,
    #[serde(default)]
    pub include: Option<Vec<String>>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SemgrepFinding {
    pub check_id: String,
    pub path: String,
    pub start_line: u64,
    pub end_line: u64,
    pub severity: String,
    pub message: String,
    pub cwe: Vec<String>,
    pub owasp: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SemgrepOutput {
    pub findings: Vec<SemgrepFinding>,
    pub errors: Vec<String>,
    pub raw_command: String,
    pub exit_code: i32,
    pub stderr_tail: String,
}

pub struct SemgrepTool {
    ctx: SecContext,
}

impl SemgrepTool {
    pub fn new(ctx: SecContext) -> Self {
        SemgrepTool { ctx }
    }
}

impl Tool for SemgrepTool {
    const NAME: &'static str = "semgrep";
    type Error = ToolError;
    type Args = SemgrepArgs;
    type Output = SemgrepOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: "Static analysis via semgrep. Scans a local code path and returns typed \
                          findings with check id, file, line range, severity, and CWE/OWASP tags. \
                          Requires an active pentest engagement."
                .to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Local path to scan" },
                    "config": { "type": "string",
                                "description": "Ruleset (-c). Defaults to 'auto'. Examples: 'p/ci', 'p/owasp-top-ten', path to .yml" },
                    "severity": { "type": "string",
                                  "description": "Filter: INFO|WARNING|ERROR (--severity)" },
                    "exclude": { "type": "array", "items": {"type": "string"} },
                    "include": { "type": "array", "items": {"type": "string"} },
                    "timeout_secs": { "type": "integer" }
                },
                "required": ["path"]
            }),
        }
    }

    async fn call(&self, args: SemgrepArgs) -> Result<SemgrepOutput, ToolError> {
        let _policy = require_policy(&self.ctx)?;
        preflight("semgrep").await?;

        let config = args.config.clone().unwrap_or_else(|| "auto".to_string());
        let mut argv: Vec<String> = vec![
            "semgrep".into(),
            "scan".into(),
            "--json".into(),
            "--quiet".into(),
            "--metrics=off".into(),
            "--config".into(),
            config,
        ];
        if let Some(s) = &args.severity {
            argv.push("--severity".into());
            argv.push(s.clone());
        }
        if let Some(ex) = &args.exclude {
            for e in ex {
                argv.push("--exclude".into());
                argv.push(e.clone());
            }
        }
        if let Some(inc) = &args.include {
            for i in inc {
                argv.push("--include".into());
                argv.push(i.clone());
            }
        }
        argv.push(args.path.clone());

        let cmd = argv.iter().map(|s| shq(s)).collect::<Vec<_>>().join(" ");
        let outcome = run_shell(&self.ctx, &cmd, args.timeout_secs.unwrap_or(900)).await?;
        let (findings, errors) = parse_semgrep_json(&outcome.stdout);

        let summary = format!("semgrep: {} finding(s)", findings.len());
        record(&self.ctx, "semgrep", &argv, &outcome, &summary);

        Ok(SemgrepOutput {
            findings,
            errors,
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

pub fn parse_semgrep_json(s: &str) -> (Vec<SemgrepFinding>, Vec<String>) {
    let trimmed = s.trim();
    let v: serde_json::Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(_) => return (Vec::new(), Vec::new()),
    };
    let mut findings = Vec::new();
    if let Some(arr) = v.get("results").and_then(|x| x.as_array()) {
        for r in arr {
            let check_id = r.get("check_id").and_then(|x| x.as_str()).unwrap_or("").to_string();
            if check_id.is_empty() {
                continue;
            }
            let path = r.get("path").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let start_line = r
                .get("start")
                .and_then(|x| x.get("line"))
                .and_then(|x| x.as_u64())
                .unwrap_or(0);
            let end_line = r
                .get("end")
                .and_then(|x| x.get("line"))
                .and_then(|x| x.as_u64())
                .unwrap_or(start_line);
            let extra = r.get("extra");
            let severity = extra
                .and_then(|e| e.get("severity"))
                .and_then(|x| x.as_str())
                .unwrap_or("INFO")
                .to_string();
            let message = extra
                .and_then(|e| e.get("message"))
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let meta = extra.and_then(|e| e.get("metadata"));
            let cwe = string_list(meta.and_then(|m| m.get("cwe")));
            let owasp = string_list(meta.and_then(|m| m.get("owasp")));
            findings.push(SemgrepFinding {
                check_id,
                path,
                start_line,
                end_line,
                severity,
                message,
                cwe,
                owasp,
            });
        }
    }
    let errors = v
        .get("errors")
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|e| {
                    e.get("message")
                        .and_then(|m| m.as_str())
                        .map(|s| s.to_string())
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    (findings, errors)
}

fn string_list(v: Option<&serde_json::Value>) -> Vec<String> {
    let Some(v) = v else { return Vec::new() };
    if let Some(arr) = v.as_array() {
        arr.iter()
            .filter_map(|e| e.as_str().map(|s| s.to_string()))
            .collect()
    } else if let Some(s) = v.as_str() {
        vec![s.to_string()]
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typical_results() {
        let sample = r#"{
          "results": [
            {"check_id":"python.lang.security.audit.exec-use","path":"app.py",
             "start":{"line":10,"col":1},"end":{"line":10,"col":20},
             "extra":{"severity":"ERROR","message":"exec() is dangerous",
                      "metadata":{"cwe":["CWE-95"],"owasp":["A03:2021"]}}}
          ],
          "errors": []
        }"#;
        let (f, e) = parse_semgrep_json(sample);
        assert_eq!(f.len(), 1);
        assert_eq!(e.len(), 0);
        assert_eq!(f[0].check_id, "python.lang.security.audit.exec-use");
        assert_eq!(f[0].severity, "ERROR");
        assert_eq!(f[0].start_line, 10);
        assert_eq!(f[0].cwe, vec!["CWE-95".to_string()]);
    }

    #[test]
    fn handles_string_metadata_fields() {
        let sample = r#"{"results":[{"check_id":"x","path":"a","start":{"line":1},"end":{"line":1},"extra":{"severity":"WARNING","message":"m","metadata":{"cwe":"CWE-22"}}}]}"#;
        let (f, _) = parse_semgrep_json(sample);
        assert_eq!(f[0].cwe, vec!["CWE-22".to_string()]);
    }
}

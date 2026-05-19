use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};

use crate::agent::tools::ToolError;
use crate::agent::tools::sec::{SecContext, preflight, record, require_policy, run_shell, shq};

#[derive(Deserialize)]
pub struct TrivyArgs {
    pub target: String,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub ignore_unfixed: Option<bool>,
    #[serde(default)]
    pub scanners: Option<String>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrivyVuln {
    pub vulnerability_id: String,
    pub pkg_name: String,
    pub installed_version: Option<String>,
    pub fixed_version: Option<String>,
    pub severity: String,
    pub title: Option<String>,
    pub primary_url: Option<String>,
    pub target: String,
    pub class: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrivySecret {
    pub rule_id: String,
    pub category: Option<String>,
    pub severity: String,
    pub title: String,
    pub target: String,
    pub start_line: u64,
    pub end_line: u64,
    pub match_: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrivyMisconfig {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub message: Option<String>,
    pub target: String,
    pub resolution: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct TrivyParsed {
    pub vulnerabilities: Vec<TrivyVuln>,
    pub secrets: Vec<TrivySecret>,
    pub misconfigurations: Vec<TrivyMisconfig>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrivyOutput {
    pub vulnerabilities: Vec<TrivyVuln>,
    pub secrets: Vec<TrivySecret>,
    pub misconfigurations: Vec<TrivyMisconfig>,
    pub raw_command: String,
    pub exit_code: i32,
    pub stderr_tail: String,
}

pub struct TrivyTool {
    ctx: SecContext,
}

impl TrivyTool {
    pub fn new(ctx: SecContext) -> Self {
        TrivyTool { ctx }
    }
}

impl Tool for TrivyTool {
    const NAME: &'static str = "trivy";
    type Error = ToolError;
    type Args = TrivyArgs;
    type Output = TrivyOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: "Run trivy (vulns, secrets, misconfig) against a filesystem path, image, \
                          or repo. Returns typed vulnerabilities, secrets, and misconfigurations. \
                          Requires an active pentest engagement."
                .to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Path, image ref, or repo URL" },
                    "mode": { "type": "string",
                              "description": "Subcommand: fs (default), image, repo, config, rootfs" },
                    "severity": { "type": "string",
                                  "description": "Comma-separated severities: UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL" },
                    "ignore_unfixed": { "type": "boolean" },
                    "scanners": { "type": "string",
                                  "description": "Comma-separated: vuln,secret,misconfig,license" },
                    "timeout_secs": { "type": "integer" }
                },
                "required": ["target"]
            }),
        }
    }

    async fn call(&self, args: TrivyArgs) -> Result<TrivyOutput, ToolError> {
        let _policy = require_policy(&self.ctx)?;
        preflight("trivy").await?;

        let mode = args.mode.clone().unwrap_or_else(|| "fs".to_string());
        let mut argv: Vec<String> = vec![
            "trivy".into(),
            mode,
            "--format".into(),
            "json".into(),
            "--quiet".into(),
            "--no-progress".into(),
        ];
        if let Some(s) = &args.severity {
            argv.push("--severity".into());
            argv.push(s.clone());
        }
        if args.ignore_unfixed.unwrap_or(false) {
            argv.push("--ignore-unfixed".into());
        }
        if let Some(sc) = &args.scanners {
            argv.push("--scanners".into());
            argv.push(sc.clone());
        }
        argv.push(args.target.clone());

        let cmd = argv.iter().map(|s| shq(s)).collect::<Vec<_>>().join(" ");
        let outcome = run_shell(&self.ctx, &cmd, args.timeout_secs.unwrap_or(900)).await?;
        let p = parse_trivy_json(&outcome.stdout);

        let summary = format!(
            "trivy: {} vuln(s), {} secret(s), {} misconfig(s)",
            p.vulnerabilities.len(),
            p.secrets.len(),
            p.misconfigurations.len()
        );
        record(&self.ctx, "trivy", &argv, &outcome, &summary);

        Ok(TrivyOutput {
            vulnerabilities: p.vulnerabilities,
            secrets: p.secrets,
            misconfigurations: p.misconfigurations,
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

pub fn parse_trivy_json(s: &str) -> TrivyParsed {
    let trimmed = s.trim();
    let v: serde_json::Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(_) => return TrivyParsed::default(),
    };
    let mut out = TrivyParsed::default();
    let results = match v.get("Results").and_then(|x| x.as_array()) {
        Some(a) => a.clone(),
        None => return out,
    };
    for r in &results {
        let target = r.get("Target").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let class = r.get("Class").and_then(|x| x.as_str()).map(|s| s.to_string());
        if let Some(arr) = r.get("Vulnerabilities").and_then(|x| x.as_array()) {
            for vuln in arr {
                let id = vuln.get("VulnerabilityID").and_then(|x| x.as_str()).unwrap_or("").to_string();
                if id.is_empty() {
                    continue;
                }
                out.vulnerabilities.push(TrivyVuln {
                    vulnerability_id: id,
                    pkg_name: vuln.get("PkgName").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                    installed_version: vuln.get("InstalledVersion").and_then(|x| x.as_str()).map(|s| s.to_string()),
                    fixed_version: vuln.get("FixedVersion").and_then(|x| x.as_str()).map(|s| s.to_string()),
                    severity: vuln.get("Severity").and_then(|x| x.as_str()).unwrap_or("UNKNOWN").to_string(),
                    title: vuln.get("Title").and_then(|x| x.as_str()).map(|s| s.to_string()),
                    primary_url: vuln.get("PrimaryURL").and_then(|x| x.as_str()).map(|s| s.to_string()),
                    target: target.clone(),
                    class: class.clone(),
                });
            }
        }
        if let Some(arr) = r.get("Secrets").and_then(|x| x.as_array()) {
            for sec in arr {
                let rule_id = sec.get("RuleID").and_then(|x| x.as_str()).unwrap_or("").to_string();
                if rule_id.is_empty() {
                    continue;
                }
                out.secrets.push(TrivySecret {
                    rule_id,
                    category: sec.get("Category").and_then(|x| x.as_str()).map(|s| s.to_string()),
                    severity: sec.get("Severity").and_then(|x| x.as_str()).unwrap_or("UNKNOWN").to_string(),
                    title: sec.get("Title").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                    target: target.clone(),
                    start_line: sec.get("StartLine").and_then(|x| x.as_u64()).unwrap_or(0),
                    end_line: sec.get("EndLine").and_then(|x| x.as_u64()).unwrap_or(0),
                    match_: sec.get("Match").and_then(|x| x.as_str()).map(|s| s.to_string()),
                });
            }
        }
        if let Some(arr) = r.get("Misconfigurations").and_then(|x| x.as_array()) {
            for m in arr {
                let id = m.get("ID").and_then(|x| x.as_str()).unwrap_or("").to_string();
                if id.is_empty() {
                    continue;
                }
                out.misconfigurations.push(TrivyMisconfig {
                    id,
                    title: m.get("Title").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                    severity: m.get("Severity").and_then(|x| x.as_str()).unwrap_or("UNKNOWN").to_string(),
                    message: m.get("Message").and_then(|x| x.as_str()).map(|s| s.to_string()),
                    target: target.clone(),
                    resolution: m.get("Resolution").and_then(|x| x.as_str()).map(|s| s.to_string()),
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_vulnerabilities() {
        let sample = r#"{
          "Results":[
            {"Target":"package.json","Class":"lang-pkgs",
             "Vulnerabilities":[
               {"VulnerabilityID":"CVE-2021-44228","PkgName":"log4j",
                "InstalledVersion":"2.14.0","FixedVersion":"2.17.0",
                "Severity":"CRITICAL","Title":"Log4Shell","PrimaryURL":"https://nvd.nist.gov/x"}
             ]}
          ]}"#;
        let r = parse_trivy_json(sample);
        assert_eq!(r.vulnerabilities.len(), 1);
        assert_eq!(r.vulnerabilities[0].vulnerability_id, "CVE-2021-44228");
        assert_eq!(r.vulnerabilities[0].severity, "CRITICAL");
        assert_eq!(r.vulnerabilities[0].target, "package.json");
    }

    #[test]
    fn parses_secrets_and_misconfig() {
        let sample = r#"{
          "Results":[
            {"Target":".env",
             "Secrets":[{"RuleID":"aws-access-key","Category":"AWS","Severity":"CRITICAL","Title":"AWS Access Key","StartLine":3,"EndLine":3,"Match":"AKIA..."}]},
            {"Target":"Dockerfile",
             "Misconfigurations":[{"ID":"DS002","Title":"Image runs as root","Severity":"HIGH","Message":"USER directive missing"}]}
          ]}"#;
        let r = parse_trivy_json(sample);
        assert_eq!(r.secrets.len(), 1);
        assert_eq!(r.secrets[0].rule_id, "aws-access-key");
        assert_eq!(r.misconfigurations.len(), 1);
        assert_eq!(r.misconfigurations[0].id, "DS002");
    }
}

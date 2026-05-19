use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};

use crate::agent::tools::ToolError;
use crate::agent::tools::sec::{SecContext, preflight, record, require_policy, run_shell, shq};

#[derive(Deserialize)]
pub struct ProwlerArgs {
    pub provider: String,
    #[serde(default)]
    pub services: Option<Vec<String>>,
    #[serde(default)]
    pub checks: Option<Vec<String>>,
    #[serde(default)]
    pub severity: Option<Vec<String>>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub compliance: Option<Vec<String>>,
    #[serde(default)]
    pub max_findings: Option<usize>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProwlerFinding {
    pub check_id: String,
    pub status: String,
    pub severity: String,
    pub service: Option<String>,
    pub region: Option<String>,
    pub resource_id: Option<String>,
    pub resource_arn: Option<String>,
    pub message: Option<String>,
    pub remediation: Option<String>,
    pub compliance: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProwlerOutput {
    pub provider: String,
    pub findings: Vec<ProwlerFinding>,
    pub total_findings: usize,
    pub by_status: std::collections::BTreeMap<String, usize>,
    pub by_severity: std::collections::BTreeMap<String, usize>,
    pub raw_command: String,
    pub exit_code: i32,
    pub stderr_tail: String,
}

pub struct ProwlerTool {
    ctx: SecContext,
}

impl ProwlerTool {
    pub fn new(ctx: SecContext) -> Self {
        ProwlerTool { ctx }
    }
}

impl Tool for ProwlerTool {
    const NAME: &'static str = "prowler";
    type Error = ToolError;
    type Args = ProwlerArgs;
    type Output = ProwlerOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: "Prowler cloud security posture scanner (AWS / Azure / GCP / \
                          Kubernetes). Requires the provider's credentials to be configured in \
                          the environment. Returns typed findings with check_id, status, \
                          severity, resource, and compliance mappings. Use `services` / `checks` \
                          / `severity` / `compliance` to narrow scope."
                .to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "provider": { "type": "string", "description": "aws|azure|gcp|kubernetes" },
                    "services": { "type": "array", "items": {"type": "string"},
                                  "description": "Limit to services (e.g. ['s3','iam'])" },
                    "checks": { "type": "array", "items": {"type": "string"},
                                "description": "Specific check IDs" },
                    "severity": { "type": "array", "items": {"type": "string"},
                                  "description": "Filter: critical|high|medium|low|informational" },
                    "region": { "type": "string", "description": "AWS region (e.g. us-east-1)" },
                    "profile": { "type": "string", "description": "AWS profile name" },
                    "compliance": { "type": "array", "items": {"type": "string"},
                                    "description": "e.g. ['cis_2.0','soc2','nist_800_53_5']" },
                    "max_findings": { "type": "integer", "description": "Cap returned findings (default 1000)" },
                    "timeout_secs": { "type": "integer" }
                },
                "required": ["provider"]
            }),
        }
    }

    async fn call(&self, args: ProwlerArgs) -> Result<ProwlerOutput, ToolError> {
        let _ = require_policy(&self.ctx)?;
        preflight("prowler").await?;

        let mut argv: Vec<String> = vec![
            "prowler".into(),
            args.provider.clone(),
            "--output-formats".into(),
            "json-ocsf".into(),
            "--output-directory".into(),
            "/tmp/prowler-out".into(),
        ];
        if let Some(s) = &args.services {
            argv.push("--services".into());
            for x in s {
                argv.push(x.clone());
            }
        }
        if let Some(c) = &args.checks {
            argv.push("--checks".into());
            for x in c {
                argv.push(x.clone());
            }
        }
        if let Some(s) = &args.severity {
            argv.push("--severity".into());
            for x in s {
                argv.push(x.clone());
            }
        }
        if let Some(r) = &args.region {
            argv.push("--region".into());
            argv.push(r.clone());
        }
        if let Some(p) = &args.profile {
            argv.push("--profile".into());
            argv.push(p.clone());
        }
        if let Some(c) = &args.compliance {
            argv.push("--compliance".into());
            for x in c {
                argv.push(x.clone());
            }
        }

        // Use a marker so we know where the JSON file ends up; prowler emits a file in -o dir.
        let inner_cmd = argv.iter().map(|s| shq(s)).collect::<Vec<_>>().join(" ");
        let cmd = format!(
            "mkdir -p /tmp/prowler-out && {} ; cat /tmp/prowler-out/*.ocsf.json 2>/dev/null || cat /tmp/prowler-out/*.json 2>/dev/null || true",
            inner_cmd
        );
        let outcome = run_shell(&self.ctx, &cmd, args.timeout_secs.unwrap_or(1800)).await?;

        let mut findings = parse_prowler_ocsf(&outcome.stdout);
        let total = findings.len();
        let cap = args.max_findings.unwrap_or(1000);
        if findings.len() > cap {
            findings.truncate(cap);
        }

        let mut by_status: std::collections::BTreeMap<String, usize> = Default::default();
        let mut by_severity: std::collections::BTreeMap<String, usize> = Default::default();
        for f in &findings {
            *by_status.entry(f.status.clone()).or_default() += 1;
            *by_severity.entry(f.severity.clone()).or_default() += 1;
        }

        let summary = format!(
            "prowler {}: {} finding(s) ({} returned)",
            args.provider,
            total,
            findings.len()
        );
        record(&self.ctx, "prowler", &argv, &outcome, &summary);

        Ok(ProwlerOutput {
            provider: args.provider,
            findings,
            total_findings: total,
            by_status,
            by_severity,
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

pub fn parse_prowler_ocsf(s: &str) -> Vec<ProwlerFinding> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let arr: Vec<serde_json::Value> = serde_json::from_str(trimmed)
        .ok()
        .and_then(|v: serde_json::Value| v.as_array().cloned())
        .or_else(|| {
            // jsonl fallback
            let mut out = Vec::new();
            for line in trimmed.lines() {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                    out.push(v);
                }
            }
            if out.is_empty() { None } else { Some(out) }
        })
        .unwrap_or_default();

    let mut findings = Vec::with_capacity(arr.len());
    for f in arr {
        // OCSF schema field paths
        let check_id = f
            .pointer("/finding_info/uid")
            .and_then(|x| x.as_str())
            .or_else(|| f.get("check_id").and_then(|x| x.as_str()))
            .unwrap_or("")
            .to_string();
        if check_id.is_empty() {
            continue;
        }
        let status = f
            .get("status")
            .and_then(|x| x.as_str())
            .or_else(|| f.get("status_code").and_then(|x| x.as_str()))
            .unwrap_or("UNKNOWN")
            .to_string();
        let severity = f
            .get("severity")
            .and_then(|x| x.as_str())
            .unwrap_or("Informational")
            .to_string();
        let service = f
            .pointer("/resources/0/group/name")
            .and_then(|x| x.as_str())
            .or_else(|| f.get("service").and_then(|x| x.as_str()))
            .map(|s| s.to_string());
        let region = f
            .pointer("/cloud/region")
            .and_then(|x| x.as_str())
            .or_else(|| f.get("region").and_then(|x| x.as_str()))
            .map(|s| s.to_string());
        let resource_id = f
            .pointer("/resources/0/uid")
            .and_then(|x| x.as_str())
            .or_else(|| f.get("resource_id").and_then(|x| x.as_str()))
            .map(|s| s.to_string());
        let resource_arn = f
            .pointer("/resources/0/name")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string());
        let message = f
            .pointer("/finding_info/desc")
            .and_then(|x| x.as_str())
            .or_else(|| f.get("status_detail").and_then(|x| x.as_str()))
            .map(|s| s.to_string());
        let remediation = f
            .pointer("/remediation/desc")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string());
        let compliance = f
            .pointer("/unmapped/compliance")
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str())
                    .map(String::from)
                    .collect()
            });

        findings.push(ProwlerFinding {
            check_id,
            status,
            severity,
            service,
            region,
            resource_id,
            resource_arn,
            message,
            remediation,
            compliance,
        });
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ocsf_array() {
        let sample = r#"[
          {"finding_info":{"uid":"iam_password_policy_minimum_length_14","desc":"Password policy too lax"},
           "status":"FAIL","severity":"Medium",
           "resources":[{"uid":"arn:aws:iam::1:policy","name":"main","group":{"name":"iam"}}],
           "cloud":{"region":"us-east-1"}},
          {"finding_info":{"uid":"s3_bucket_public_access"},"status":"PASS","severity":"Low"}
        ]"#;
        let r = parse_prowler_ocsf(sample);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].check_id, "iam_password_policy_minimum_length_14");
        assert_eq!(r[0].status, "FAIL");
        assert_eq!(r[0].service.as_deref(), Some("iam"));
        assert_eq!(r[0].region.as_deref(), Some("us-east-1"));
    }

    #[test]
    fn parses_jsonl_fallback() {
        let sample = "{\"check_id\":\"x\",\"status\":\"FAIL\",\"severity\":\"High\"}\n{\"check_id\":\"y\",\"status\":\"PASS\",\"severity\":\"Low\"}\n";
        let r = parse_prowler_ocsf(sample);
        assert_eq!(r.len(), 2);
        assert_eq!(r[1].check_id, "y");
    }
}

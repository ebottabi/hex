use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};

use crate::agent::tools::ToolError;
use crate::agent::tools::sec::{SecContext, preflight, record, require_policy, run_shell, shq};

#[derive(Deserialize)]
pub struct ScoutsuiteArgs {
    pub provider: String,
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub report_dir: Option<String>,
    #[serde(default)]
    pub services: Option<Vec<String>>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScoutsuiteFinding {
    pub service: String,
    pub finding_id: String,
    pub description: String,
    pub level: String,
    pub flagged_items: u64,
    pub checked_items: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScoutsuiteOutput {
    pub provider: String,
    pub account_id: Option<String>,
    pub report_dir: String,
    pub findings: Vec<ScoutsuiteFinding>,
    pub services_scanned: Vec<String>,
    pub raw_command: String,
    pub exit_code: i32,
    pub stderr_tail: String,
}

pub struct ScoutsuiteTool {
    ctx: SecContext,
}

impl ScoutsuiteTool {
    pub fn new(ctx: SecContext) -> Self {
        ScoutsuiteTool { ctx }
    }
}

impl Tool for ScoutsuiteTool {
    const NAME: &'static str = "scoutsuite";
    type Error = ToolError;
    type Args = ScoutsuiteArgs;
    type Output = ScoutsuiteOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: "Scout Suite multi-cloud security auditor (AWS / Azure / GCP / \
                          AliCloud / OCI). Provider credentials must be configured. Returns \
                          typed findings per service with severity (danger/warning) and counts \
                          of flagged vs checked items."
                .to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "provider": { "type": "string",
                                  "description": "aws|azure|gcp|aliyun|oci" },
                    "profile": { "type": "string", "description": "AWS profile name" },
                    "report_dir": { "type": "string",
                                    "description": "Where to write the report (default /tmp/scoutsuite-report)" },
                    "services": { "type": "array", "items": {"type": "string"},
                                  "description": "Limit to services" },
                    "timeout_secs": { "type": "integer" }
                },
                "required": ["provider"]
            }),
        }
    }

    async fn call(&self, args: ScoutsuiteArgs) -> Result<ScoutsuiteOutput, ToolError> {
        let _ = require_policy(&self.ctx)?;
        preflight("scout").await?;

        let report_dir = args
            .report_dir
            .clone()
            .unwrap_or_else(|| "/tmp/scoutsuite-report".to_string());

        let mut argv: Vec<String> = vec![
            "scout".into(),
            args.provider.clone(),
            "--no-browser".into(),
            "--force".into(),
            "--report-dir".into(),
            report_dir.clone(),
        ];
        if let Some(p) = &args.profile {
            argv.push("--profile".into());
            argv.push(p.clone());
        }
        if let Some(s) = &args.services {
            argv.push("--services".into());
            for x in s {
                argv.push(x.clone());
            }
        }

        let inner = argv.iter().map(|s| shq(s)).collect::<Vec<_>>().join(" ");
        // After scan, locate the results JS file, strip the JS prefix, and cat as JSON.
        let cmd = format!(
            "mkdir -p {dir} && {inner} ; \
             f=$(ls {dir}/scoutsuite-results/scoutsuite_results_*.js 2>/dev/null | head -n1); \
             if [ -n \"$f\" ]; then sed -e 's/^scoutsuite_results = //' -e 's/;$//' \"$f\"; fi",
            dir = shq(&report_dir),
            inner = inner
        );
        let outcome = run_shell(&self.ctx, &cmd, args.timeout_secs.unwrap_or(1800)).await?;
        let parsed = parse_scoutsuite_report(&outcome.stdout);

        let summary = format!(
            "scoutsuite {}: {} finding(s) across {} service(s)",
            args.provider,
            parsed.findings.len(),
            parsed.services_scanned.len()
        );
        record(&self.ctx, "scoutsuite", &argv, &outcome, &summary);

        Ok(ScoutsuiteOutput {
            provider: args.provider,
            account_id: parsed.account_id,
            report_dir,
            findings: parsed.findings,
            services_scanned: parsed.services_scanned,
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
pub struct ParsedScout {
    pub account_id: Option<String>,
    pub findings: Vec<ScoutsuiteFinding>,
    pub services_scanned: Vec<String>,
}

pub fn parse_scoutsuite_report(s: &str) -> ParsedScout {
    let trimmed = s.trim();
    let v: serde_json::Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(_) => return ParsedScout::default(),
    };
    let mut out = ParsedScout::default();
    out.account_id = v
        .get("account_id")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());

    let services = match v.get("services").and_then(|x| x.as_object()) {
        Some(m) => m,
        None => return out,
    };
    for (svc_name, svc) in services {
        out.services_scanned.push(svc_name.clone());
        let findings = match svc.get("findings").and_then(|x| x.as_object()) {
            Some(f) => f,
            None => continue,
        };
        for (fid, f) in findings {
            let flagged = f
                .get("flagged_items")
                .and_then(|x| x.as_u64())
                .unwrap_or(0);
            if flagged == 0 {
                continue;
            }
            out.findings.push(ScoutsuiteFinding {
                service: svc_name.clone(),
                finding_id: fid.clone(),
                description: f
                    .get("description")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                level: f
                    .get("level")
                    .and_then(|x| x.as_str())
                    .unwrap_or("warning")
                    .to_string(),
                flagged_items: flagged,
                checked_items: f
                    .get("checked_items")
                    .and_then(|x| x.as_u64())
                    .unwrap_or(0),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_scoutsuite_findings() {
        let sample = r#"{
          "account_id":"123456789012",
          "services":{
            "s3":{"findings":{
              "s3-bucket-public-read":{"description":"S3 buckets with public read","level":"danger","flagged_items":2,"checked_items":10},
              "s3-no-flag":{"description":"x","level":"warning","flagged_items":0,"checked_items":10}
            }},
            "iam":{"findings":{
              "iam-no-mfa":{"description":"User without MFA","level":"warning","flagged_items":1,"checked_items":5}
            }}
          }
        }"#;
        let r = parse_scoutsuite_report(sample);
        assert_eq!(r.account_id.as_deref(), Some("123456789012"));
        assert_eq!(r.findings.len(), 2);
        assert!(r.services_scanned.contains(&"s3".to_string()));
        let s3 = r
            .findings
            .iter()
            .find(|f| f.finding_id == "s3-bucket-public-read")
            .unwrap();
        assert_eq!(s3.level, "danger");
        assert_eq!(s3.flagged_items, 2);
    }
}

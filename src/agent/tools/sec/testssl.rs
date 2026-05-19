use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};

use crate::agent::tools::ToolError;
use crate::agent::tools::sec::{
    SecContext, check_targets_in_scope, preflight, record, require_policy, run_shell, shq,
};

#[derive(Deserialize)]
pub struct TestsslArgs {
    pub target: String,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub fast: Option<bool>,
    #[serde(default)]
    pub starttls: Option<String>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TestsslFinding {
    pub id: String,
    pub ip: Option<String>,
    pub port: Option<String>,
    pub severity: String,
    pub finding: String,
    pub cve: Option<String>,
    pub cwe: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TestsslOutput {
    pub findings: Vec<TestsslFinding>,
    pub raw_command: String,
    pub exit_code: i32,
    pub stderr_tail: String,
}

pub struct TestsslTool {
    ctx: SecContext,
}

impl TestsslTool {
    pub fn new(ctx: SecContext) -> Self {
        TestsslTool { ctx }
    }
}

impl Tool for TestsslTool {
    const NAME: &'static str = "testssl";
    type Error = ToolError;
    type Args = TestsslArgs;
    type Output = TestsslOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: "TLS/SSL posture scan via testssl.sh. Returns typed findings with \
                          severity (OK/INFO/LOW/MEDIUM/HIGH/CRITICAL), CVE/CWE references, and \
                          per-check IDs. Target host must be in scope."
                .to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "host[:port] or URI" },
                    "severity": { "type": "string",
                                  "description": "Filter: LOW|MEDIUM|HIGH|CRITICAL (--severity)" },
                    "fast": { "type": "boolean", "description": "Use --fast for a quick scan" },
                    "starttls": { "type": "string",
                                  "description": "STARTTLS protocol: smtp|imap|pop3|ftp|xmpp|..." },
                    "timeout_secs": { "type": "integer" }
                },
                "required": ["target"]
            }),
        }
    }

    async fn call(&self, args: TestsslArgs) -> Result<TestsslOutput, ToolError> {
        let policy = require_policy(&self.ctx)?;
        let host = host_only(&args.target);
        check_targets_in_scope(&policy, std::slice::from_ref(&host))?;
        let binary = if which_available("testssl.sh").await {
            "testssl.sh"
        } else {
            "testssl"
        };
        preflight(binary).await?;

        let mut argv: Vec<String> = vec![
            binary.into(),
            "--jsonfile-pretty".into(),
            "/dev/stdout".into(),
            "--quiet".into(),
            "--color".into(),
            "0".into(),
            "--warnings".into(),
            "off".into(),
        ];
        if let Some(s) = &args.severity {
            argv.push("--severity".into());
            argv.push(s.clone());
        }
        if args.fast.unwrap_or(false) {
            argv.push("--fast".into());
        }
        if let Some(st) = &args.starttls {
            argv.push("--starttls".into());
            argv.push(st.clone());
        }
        argv.push(args.target.clone());

        let cmd = argv.iter().map(|s| shq(s)).collect::<Vec<_>>().join(" ");
        let outcome = run_shell(&self.ctx, &cmd, args.timeout_secs.unwrap_or(900)).await?;
        let findings = parse_testssl_json(&outcome.stdout);

        let summary = format!("testssl: {} finding(s)", findings.len());
        record(&self.ctx, "testssl", &argv, &outcome, &summary);

        Ok(TestsslOutput {
            findings,
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

fn host_only(s: &str) -> String {
    let no_scheme = s.splitn(2, "://").nth(1).unwrap_or(s);
    let no_path = no_scheme.split('/').next().unwrap_or(no_scheme);
    no_path.rsplit_once(':').map(|(h, _)| h).unwrap_or(no_path).to_string()
}

pub fn parse_testssl_json(s: &str) -> Vec<TestsslFinding> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let v: serde_json::Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let arr = if let Some(a) = v.as_array() {
        a.clone()
    } else if let Some(a) = v.get("scanResult").and_then(|x| x.as_array()) {
        a.clone()
    } else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(arr.len());
    for f in arr {
        let id = f
            .get("id")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if id.is_empty() {
            continue;
        }
        out.push(TestsslFinding {
            id,
            ip: f.get("ip").and_then(|x| x.as_str()).map(|s| s.to_string()),
            port: f.get("port").and_then(|x| x.as_str()).map(|s| s.to_string()),
            severity: f
                .get("severity")
                .and_then(|x| x.as_str())
                .unwrap_or("INFO")
                .to_string(),
            finding: f
                .get("finding")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            cve: f.get("cve").and_then(|x| x.as_str()).map(|s| s.to_string()),
            cwe: f.get("cwe").and_then(|x| x.as_str()).map(|s| s.to_string()),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_array_findings() {
        let sample = r#"[
          {"id":"protocol_negotiated","ip":"10.0.0.1","port":"443","severity":"INFO","finding":"TLSv1.2"},
          {"id":"BREACH","ip":"10.0.0.1","port":"443","severity":"MEDIUM","finding":"VULNERABLE","cve":"CVE-2013-3587","cwe":"CWE-310"}
        ]"#;
        let r = parse_testssl_json(sample);
        assert_eq!(r.len(), 2);
        assert_eq!(r[1].severity, "MEDIUM");
        assert_eq!(r[1].cve.as_deref(), Some("CVE-2013-3587"));
    }

    #[test]
    fn parses_scanresult_wrapper() {
        let sample = r#"{"scanResult":[{"id":"x","severity":"LOW","finding":"weak"}]}"#;
        let r = parse_testssl_json(sample);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].id, "x");
    }
}

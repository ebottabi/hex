use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};

use crate::agent::tools::ToolError;
use crate::agent::tools::sec::{
    SecContext, check_targets_in_scope, preflight, record, require_policy, run_shell, shq,
};

#[derive(Deserialize)]
pub struct NiktoArgs {
    pub target: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub ssl: Option<bool>,
    #[serde(default)]
    pub tuning: Option<String>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NiktoFinding {
    pub id: Option<String>,
    pub osvdb: Option<String>,
    pub method: Option<String>,
    pub uri: Option<String>,
    pub message: String,
    pub references: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NiktoOutput {
    pub host: String,
    pub ip: Option<String>,
    pub port: Option<u16>,
    pub banner: Option<String>,
    pub findings: Vec<NiktoFinding>,
    pub raw_command: String,
    pub exit_code: i32,
    pub stderr_tail: String,
}

pub struct NiktoTool {
    ctx: SecContext,
}

impl NiktoTool {
    pub fn new(ctx: SecContext) -> Self {
        NiktoTool { ctx }
    }
}

impl Tool for NiktoTool {
    const NAME: &'static str = "nikto";
    type Error = ToolError;
    type Args = NiktoArgs;
    type Output = NiktoOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: "Run nikto web server scanner against a single in-scope host. Returns \
                          typed findings with OSVDB IDs, URIs, and references. Target host must \
                          be in scope."
                .to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Hostname, IP, or URL" },
                    "port": { "type": "integer" },
                    "ssl": { "type": "boolean", "description": "Force SSL (-ssl)" },
                    "tuning": { "type": "string",
                                "description": "Tuning string, e.g. '1234567890abcde' to limit checks" },
                    "timeout_secs": { "type": "integer" }
                },
                "required": ["target"]
            }),
        }
    }

    async fn call(&self, args: NiktoArgs) -> Result<NiktoOutput, ToolError> {
        let policy = require_policy(&self.ctx)?;
        let host = host_of(&args.target);
        check_targets_in_scope(&policy, std::slice::from_ref(&host))?;
        preflight("nikto").await?;

        let mut argv: Vec<String> = vec![
            "nikto".into(),
            "-h".into(),
            args.target.clone(),
            "-Format".into(),
            "json".into(),
            "-output".into(),
            "/dev/stdout".into(),
            "-ask".into(),
            "no".into(),
            "-nointeractive".into(),
        ];
        if let Some(p) = args.port {
            argv.push("-p".into());
            argv.push(p.to_string());
        }
        if args.ssl.unwrap_or(false) {
            argv.push("-ssl".into());
        }
        if let Some(t) = &args.tuning {
            argv.push("-Tuning".into());
            argv.push(t.clone());
        }

        let cmd = argv.iter().map(|s| shq(s)).collect::<Vec<_>>().join(" ");
        let outcome = run_shell(&self.ctx, &cmd, args.timeout_secs.unwrap_or(900)).await?;
        let parsed = parse_nikto_json(&outcome.stdout);

        let summary = format!("nikto: {} finding(s)", parsed.findings.len());
        record(&self.ctx, "nikto", &argv, &outcome, &summary);

        Ok(NiktoOutput {
            host: parsed.host.unwrap_or(host),
            ip: parsed.ip,
            port: parsed.port,
            banner: parsed.banner,
            findings: parsed.findings,
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

#[derive(Default)]
struct ParsedNikto {
    host: Option<String>,
    ip: Option<String>,
    port: Option<u16>,
    banner: Option<String>,
    findings: Vec<NiktoFinding>,
}

pub fn parse_nikto_json(s: &str) -> ParsedNiktoPub {
    // Nikto sometimes emits an array with one report, sometimes a single object.
    let trimmed = s.trim();
    let v: serde_json::Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(_) => return ParsedNiktoPub::default(),
    };
    let report = if v.is_array() {
        v.as_array().and_then(|a| a.first()).cloned().unwrap_or(serde_json::Value::Null)
    } else {
        v
    };
    if !report.is_object() {
        return ParsedNiktoPub::default();
    }
    let host = report
        .get("host")
        .or_else(|| report.get("target"))
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());
    let ip = report
        .get("ip")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());
    let port = report
        .get("port")
        .and_then(|x| x.as_u64().or_else(|| x.as_str().and_then(|s| s.parse().ok())))
        .map(|n| n as u16);
    let banner = report
        .get("banner")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());

    let mut findings = Vec::new();
    if let Some(arr) = report
        .get("vulnerabilities")
        .or_else(|| report.get("findings"))
        .and_then(|x| x.as_array())
    {
        for f in arr {
            let message = f
                .get("msg")
                .or_else(|| f.get("message"))
                .or_else(|| f.get("description"))
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            if message.is_empty() {
                continue;
            }
            let references = f
                .get("references")
                .and_then(|x| x.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|e| e.as_str().map(|s| s.to_string()))
                        .collect::<Vec<_>>()
                })
                .or_else(|| {
                    f.get("references")
                        .and_then(|x| x.as_str())
                        .map(|s| vec![s.to_string()])
                })
                .unwrap_or_default();
            findings.push(NiktoFinding {
                id: f.get("id").and_then(|x| x.as_str()).map(|s| s.to_string()),
                osvdb: f
                    .get("OSVDB")
                    .or_else(|| f.get("osvdb"))
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string()),
                method: f.get("method").and_then(|x| x.as_str()).map(|s| s.to_string()),
                uri: f.get("uri").or_else(|| f.get("url")).and_then(|x| x.as_str()).map(|s| s.to_string()),
                message,
                references,
            });
        }
    }
    ParsedNiktoPub {
        host,
        ip,
        port,
        banner,
        findings,
    }
}

#[derive(Default)]
pub struct ParsedNiktoPub {
    pub host: Option<String>,
    pub ip: Option<String>,
    pub port: Option<u16>,
    pub banner: Option<String>,
    pub findings: Vec<NiktoFinding>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_object_report() {
        let sample = r#"{
          "host":"example.com","ip":"93.184.216.34","port":443,"banner":"nginx",
          "vulnerabilities":[
            {"id":"000001","OSVDB":"3092","method":"GET","uri":"/admin/","msg":"Admin login found","references":["http://cve.mitre.org/x"]},
            {"id":"000002","msg":"Server may leak inodes via ETags"}
          ]
        }"#;
        let p = parse_nikto_json(sample);
        assert_eq!(p.host.as_deref(), Some("example.com"));
        assert_eq!(p.port, Some(443));
        assert_eq!(p.findings.len(), 2);
        assert_eq!(p.findings[0].uri.as_deref(), Some("/admin/"));
        assert_eq!(p.findings[0].references.len(), 1);
    }

    #[test]
    fn parses_array_wrapper() {
        let sample = r#"[{"host":"h","vulnerabilities":[{"msg":"x"}]}]"#;
        let p = parse_nikto_json(sample);
        assert_eq!(p.host.as_deref(), Some("h"));
        assert_eq!(p.findings.len(), 1);
    }
}

// shut linter up about the private struct we no longer use
#[allow(dead_code)]
fn _unused(_p: ParsedNikto) {}

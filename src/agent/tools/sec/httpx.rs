use crate::agent::tools::schema::append_output_schema;
use rig::completion::ToolDefinition;
use rig::tool::Tool;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::agent::tools::ToolError;
use crate::agent::tools::sec::{
    SecContext, check_targets_in_scope, preflight, record, require_policy, run_shell, shq,
};

#[derive(Deserialize, JsonSchema)]
pub struct HttpxArgs {
    pub urls: Vec<String>,
    #[serde(default)]
    pub tech_detect: Option<bool>,
    #[serde(default)]
    pub follow_redirects: Option<bool>,
    #[serde(default)]
    pub ports: Option<String>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct HttpxProbe {
    pub url: String,
    pub status: Option<u16>,
    pub title: Option<String>,
    pub server: Option<String>,
    pub tech: Vec<String>,
    pub content_length: Option<u64>,
    pub final_url: Option<String>,
    pub tls_subject: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct HttpxOutput {
    pub probes: Vec<HttpxProbe>,
    pub raw_command: String,
    pub exit_code: i32,
    pub stderr_tail: String,
}

pub struct HttpxTool {
    ctx: SecContext,
}

impl HttpxTool {
    pub fn new(ctx: SecContext) -> Self {
        HttpxTool { ctx }
    }
}

impl Tool for HttpxTool {
    const NAME: &'static str = "httpx";
    type Error = ToolError;
    type Args = HttpxArgs;
    type Output = HttpxOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: append_output_schema::<HttpxOutput>(
                "HTTP probe via httpx (ProjectDiscovery). Returns status, title, server, \
                          detected tech, and final URL per target. All targets must be in scope.",
            ),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "urls": { "type": "array", "items": {"type": "string"},
                              "description": "Hosts or URLs to probe" },
                    "tech_detect": { "type": "boolean", "description": "Enable -tech-detect" },
                    "follow_redirects": { "type": "boolean", "description": "Follow redirects (-fr)" },
                    "ports": { "type": "string", "description": "Comma-separated ports, e.g. '80,443,8080'" },
                    "timeout_secs": { "type": "integer" }
                },
                "required": ["urls"]
            }),
        }
    }

    async fn call(&self, args: HttpxArgs) -> Result<HttpxOutput, ToolError> {
        let policy = require_policy(&self.ctx)?;
        if args.urls.is_empty() {
            return Err(ToolError::Msg("httpx: urls required".into()));
        }
        let hosts: Vec<String> = args.urls.iter().map(|u| host_of(u)).collect();
        check_targets_in_scope(&policy, &hosts)?;
        preflight("httpx").await?;

        let mut argv: Vec<String> = vec![
            "httpx".into(),
            "-silent".into(),
            "-json".into(),
            "-no-color".into(),
            "-title".into(),
            "-server".into(),
            "-status-code".into(),
            "-content-length".into(),
            "-tls-grab".into(),
        ];
        if args.tech_detect.unwrap_or(true) {
            argv.push("-tech-detect".into());
        }
        if args.follow_redirects.unwrap_or(false) {
            argv.push("-fr".into());
        }
        if let Some(p) = &args.ports {
            argv.push("-ports".into());
            argv.push(p.clone());
        }
        let stdin = args.urls.join("\n");
        let cmd = format!(
            "printf {} | {}",
            shq(&stdin),
            argv.iter().map(|s| shq(s)).collect::<Vec<_>>().join(" ")
        );
        let outcome = run_shell(&self.ctx, &cmd, args.timeout_secs.unwrap_or(180)).await?;
        let probes = parse_httpx_jsonl(&outcome.stdout);

        let summary = format!("httpx: {} probe(s)", probes.len());
        record(&self.ctx, "httpx", &argv, &outcome, &summary);

        Ok(HttpxOutput {
            probes,
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

pub fn parse_httpx_jsonl(s: &str) -> Vec<HttpxProbe> {
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
        let url = v
            .get("url")
            .or_else(|| v.get("input"))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if url.is_empty() {
            continue;
        }
        let status = v
            .get("status_code")
            .or_else(|| v.get("status-code"))
            .and_then(|x| x.as_u64())
            .map(|n| n as u16);
        let title = v
            .get("title")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string());
        let server = v
            .get("webserver")
            .or_else(|| v.get("server"))
            .and_then(|x| x.as_str())
            .map(|s| s.to_string());
        let content_length = v
            .get("content_length")
            .or_else(|| v.get("content-length"))
            .and_then(|x| x.as_u64());
        let final_url = v
            .get("final_url")
            .or_else(|| v.get("final-url"))
            .and_then(|x| x.as_str())
            .map(|s| s.to_string());
        let tls_subject = v
            .get("tls")
            .and_then(|t| t.get("subject_cn").or_else(|| t.get("subject_dn")))
            .and_then(|x| x.as_str())
            .map(|s| s.to_string());
        let tech = v
            .get("tech")
            .or_else(|| v.get("technologies"))
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|e| e.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        out.push(HttpxProbe {
            url,
            status,
            title,
            server,
            tech,
            content_length,
            final_url,
            tls_subject,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typical_probe() {
        let sample = "{\"url\":\"https://example.com\",\"status_code\":200,\"title\":\"Example\",\"webserver\":\"ECS\",\"tech\":[\"Nginx\",\"jQuery\"],\"content_length\":1256}\n";
        let probes = parse_httpx_jsonl(sample);
        assert_eq!(probes.len(), 1);
        let p = &probes[0];
        assert_eq!(p.url, "https://example.com");
        assert_eq!(p.status, Some(200));
        assert_eq!(p.title.as_deref(), Some("Example"));
        assert_eq!(p.server.as_deref(), Some("ECS"));
        assert_eq!(p.tech, vec!["Nginx".to_string(), "jQuery".to_string()]);
        assert_eq!(p.content_length, Some(1256));
    }

    #[test]
    fn host_of_strips_scheme_and_path() {
        assert_eq!(host_of("https://api.example.com/v1"), "api.example.com");
        assert_eq!(host_of("api.example.com"), "api.example.com");
        assert_eq!(host_of("http://10.0.0.1:8080/foo"), "10.0.0.1:8080");
    }
}

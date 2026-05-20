use rig::completion::ToolDefinition;
use rig::tool::Tool;
use schemars::JsonSchema;
use crate::agent::tools::schema::append_output_schema;
use serde::{Deserialize, Serialize};

use crate::agent::tools::ToolError;
use crate::agent::tools::sec::{
    SecContext, check_targets_in_scope, preflight, record, require_policy, run_shell, shq,
};

#[derive(Deserialize, JsonSchema)]
pub struct MasscanArgs {
    pub targets: Vec<String>,
    pub ports: String,
    #[serde(default)]
    pub rate: Option<u64>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct MasscanHit {
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    pub timestamp: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct MasscanOutput {
    pub hits: Vec<MasscanHit>,
    pub raw_command: String,
    pub exit_code: i32,
    pub stderr_tail: String,
}

pub struct MasscanTool {
    ctx: SecContext,
}

impl MasscanTool {
    pub fn new(ctx: SecContext) -> Self {
        MasscanTool { ctx }
    }
}

impl Tool for MasscanTool {
    const NAME: &'static str = "masscan";
    type Error = ToolError;
    type Args = MasscanArgs;
    type Output = MasscanOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: append_output_schema::<MasscanOutput>("High-rate TCP port sweep with masscan. Returns parsed hits as JSON. Requires \
                 root and an active engagement policy; all targets must be in scope."),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "targets": { "type": "array", "items": {"type": "string"} },
                    "ports": { "type": "string", "description": "Port spec, e.g. '80,443,8000-9000'" },
                    "rate": { "type": "integer", "description": "Packets per second (default 1000)" },
                    "timeout_secs": { "type": "integer" }
                },
                "required": ["targets", "ports"]
            }),
        }
    }

    async fn call(&self, args: MasscanArgs) -> Result<MasscanOutput, ToolError> {
        let policy = require_policy(&self.ctx)?;
        if args.targets.is_empty() {
            return Err(ToolError::Msg("masscan: targets required".into()));
        }
        check_targets_in_scope(&policy, &args.targets)?;
        preflight("masscan").await?;

        let rate = args.rate.unwrap_or(1000);
        let mut argv: Vec<String> = vec![
            "masscan".into(),
            "-p".into(),
            args.ports.clone(),
            "--rate".into(),
            rate.to_string(),
            "-oJ".into(),
            "-".into(),
        ];
        argv.extend(args.targets.iter().cloned());
        let cmd = argv.iter().map(|s| shq(s)).collect::<Vec<_>>().join(" ");

        let outcome = run_shell(&self.ctx, &cmd, args.timeout_secs.unwrap_or(600)).await?;
        let hits = parse_masscan_json(&outcome.stdout);

        let summary = format!("masscan: {} hit(s)", hits.len());
        record(&self.ctx, "masscan", &argv, &outcome, &summary);

        Ok(MasscanOutput {
            hits,
            raw_command: cmd,
            exit_code: outcome.exit_code,
            stderr_tail: tail(&outcome.stderr, 1000),
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

pub fn parse_masscan_json(s: &str) -> Vec<MasscanHit> {
    // Masscan -oJ produces an array of records; sometimes prefixed/suffixed by junk.
    // We be lenient and pull objects with serde_json::Value.
    let trimmed = s.trim();
    let value: serde_json::Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(_) => {
            // Try wrapping if it's a trailing-comma list.
            let candidate = format!(
                "[{}]",
                trimmed.trim_start_matches('[').trim_end_matches(']')
            );
            match serde_json::from_str(&candidate) {
                Ok(v) => v,
                Err(_) => return Vec::new(),
            }
        }
    };
    let arr = match value {
        serde_json::Value::Array(a) => a,
        _ => return Vec::new(),
    };
    let mut out = Vec::new();
    for record in arr {
        let ip = record
            .get("ip")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let ts = record.get("timestamp").and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        });
        if let Some(ports) = record.get("ports").and_then(|v| v.as_array()) {
            for p in ports {
                let port = p.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                let proto = p
                    .get("proto")
                    .and_then(|v| v.as_str())
                    .unwrap_or("tcp")
                    .to_string();
                if let Some(ipv) = ip.clone() {
                    out.push(MasscanHit {
                        ip: ipv,
                        port,
                        protocol: proto,
                        timestamp: ts,
                    });
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typical_output() {
        let sample = r#"[
            {"ip":"93.184.216.34","timestamp":"1700000000","ports":[{"port":80,"proto":"tcp","status":"open"}]},
            {"ip":"93.184.216.34","timestamp":"1700000001","ports":[{"port":443,"proto":"tcp","status":"open"}]}
        ]"#;
        let hits = parse_masscan_json(sample);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].port, 80);
        assert_eq!(hits[1].port, 443);
        assert_eq!(hits[0].protocol, "tcp");
    }

    #[test]
    fn empty_or_junk_returns_empty() {
        assert!(parse_masscan_json("").is_empty());
        assert!(parse_masscan_json("not json").is_empty());
    }
}

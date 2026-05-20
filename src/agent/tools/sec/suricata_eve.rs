use rig::completion::ToolDefinition;
use rig::tool::Tool;
use schemars::JsonSchema;
use crate::agent::tools::schema::append_output_schema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::agent::tools::ToolError;
use crate::agent::tools::sec::{SecContext, record, require_policy, run_shell, shq};

#[derive(Deserialize, JsonSchema)]
pub struct SuricataEveArgs {
    pub eve_path: String,
    #[serde(default)]
    pub event_types: Option<Vec<String>>,
    #[serde(default)]
    pub min_severity: Option<u32>,
    #[serde(default)]
    pub max_events: Option<usize>,
    #[serde(default)]
    pub since: Option<String>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct SuricataAlert {
    pub timestamp: String,
    pub src_ip: String,
    pub src_port: Option<u16>,
    pub dest_ip: String,
    pub dest_port: Option<u16>,
    pub proto: String,
    pub signature: String,
    pub signature_id: u64,
    pub category: String,
    pub severity: u32,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct SuricataEveOutput {
    pub eve_path: String,
    pub total_events: usize,
    pub by_event_type: BTreeMap<String, usize>,
    pub alerts: Vec<SuricataAlert>,
    pub events_sample: Vec<serde_json::Value>,
    pub raw_command: String,
    pub exit_code: i32,
    pub stderr_tail: String,
}

pub struct SuricataEveTool {
    ctx: SecContext,
}

impl SuricataEveTool {
    pub fn new(ctx: SecContext) -> Self {
        SuricataEveTool { ctx }
    }
}

impl Tool for SuricataEveTool {
    const NAME: &'static str = "suricata_eve";
    type Error = ToolError;
    type Args = SuricataEveArgs;
    type Output = SuricataEveOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: append_output_schema::<SuricataEveOutput>("Parse a Suricata eve.json log (JSONL). Returns alert list with \
                          signature/category/severity, an event-type histogram, and a sample \
                          of non-alert events (HTTP/DNS/TLS/...). Filter via `event_types`, \
                          `min_severity` (1=high..3=low), or `since` (ISO8601 prefix match)."),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "eve_path": { "type": "string" },
                    "event_types": { "type": "array", "items": {"type": "string"},
                                     "description": "Limit to types: alert|http|dns|tls|flow|ssh|fileinfo|..." },
                    "min_severity": { "type": "integer",
                                      "description": "Minimum alert severity (1=high, 2=med, 3=low)" },
                    "max_events": { "type": "integer", "description": "Cap returned events (default 1000)" },
                    "since": { "type": "string", "description": "Filter timestamps starting with this prefix" },
                    "timeout_secs": { "type": "integer" }
                },
                "required": ["eve_path"]
            }),
        }
    }

    async fn call(&self, args: SuricataEveArgs) -> Result<SuricataEveOutput, ToolError> {
        let _ = require_policy(&self.ctx)?;
        let cmd = format!("cat {}", shq(&args.eve_path));
        let outcome = run_shell(&self.ctx, &cmd, args.timeout_secs.unwrap_or(120)).await?;
        let parsed = parse_eve_jsonl(
            &outcome.stdout,
            args.event_types.as_deref(),
            args.min_severity,
            args.max_events.unwrap_or(1000),
            args.since.as_deref(),
        );

        let summary = format!(
            "suricata_eve {}: {} event(s), {} alert(s)",
            args.eve_path,
            parsed.total_events,
            parsed.alerts.len()
        );
        record(&self.ctx, "suricata_eve", &[], &outcome, &summary);

        Ok(SuricataEveOutput {
            eve_path: args.eve_path,
            total_events: parsed.total_events,
            by_event_type: parsed.by_event_type,
            alerts: parsed.alerts,
            events_sample: parsed.events_sample,
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
pub struct ParsedEve {
    pub total_events: usize,
    pub by_event_type: BTreeMap<String, usize>,
    pub alerts: Vec<SuricataAlert>,
    pub events_sample: Vec<serde_json::Value>,
}

pub fn parse_eve_jsonl(
    s: &str,
    event_types: Option<&[String]>,
    min_severity: Option<u32>,
    max_events: usize,
    since: Option<&str>,
) -> ParsedEve {
    let mut out = ParsedEve::default();
    for line in s.lines() {
        let trim = line.trim();
        if trim.is_empty() {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(trim) {
            Ok(v) => v,
            Err(_) => continue,
        };
        out.total_events += 1;
        let etype = v
            .get("event_type")
            .and_then(|x| x.as_str())
            .unwrap_or("unknown")
            .to_string();
        *out.by_event_type.entry(etype.clone()).or_default() += 1;

        if let Some(prefix) = since {
            if let Some(ts) = v.get("timestamp").and_then(|x| x.as_str()) {
                if !ts.starts_with(prefix) {
                    continue;
                }
            }
        }
        if let Some(types) = event_types {
            if !types.iter().any(|t| t == &etype) {
                continue;
            }
        }

        if etype == "alert" {
            let alert_obj = v.get("alert");
            let sev = alert_obj
                .and_then(|a| a.get("severity"))
                .and_then(|x| x.as_u64())
                .unwrap_or(3) as u32;
            if let Some(min) = min_severity {
                if sev > min {
                    continue;
                }
            }
            out.alerts.push(SuricataAlert {
                timestamp: v
                    .get("timestamp")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                src_ip: v
                    .get("src_ip")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                src_port: v.get("src_port").and_then(|x| x.as_u64()).map(|n| n as u16),
                dest_ip: v
                    .get("dest_ip")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                dest_port: v
                    .get("dest_port")
                    .and_then(|x| x.as_u64())
                    .map(|n| n as u16),
                proto: v
                    .get("proto")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                signature: alert_obj
                    .and_then(|a| a.get("signature"))
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                signature_id: alert_obj
                    .and_then(|a| a.get("signature_id"))
                    .and_then(|x| x.as_u64())
                    .unwrap_or(0),
                category: alert_obj
                    .and_then(|a| a.get("category"))
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                severity: sev,
            });
            if out.alerts.len() >= max_events {
                break;
            }
        } else if out.events_sample.len() < max_events.min(200) {
            out.events_sample.push(v);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_alerts_and_histogram() {
        let sample = r#"{"timestamp":"2024-01-01T12:00:00.000Z","event_type":"alert","src_ip":"1.1.1.1","src_port":1024,"dest_ip":"2.2.2.2","dest_port":443,"proto":"TCP","alert":{"signature":"ET MALWARE Foo","signature_id":2031234,"category":"Malware","severity":1}}
{"timestamp":"2024-01-01T12:00:01.000Z","event_type":"dns","dns":{"rrname":"example.com"}}
{"timestamp":"2024-01-01T12:00:02.000Z","event_type":"alert","src_ip":"3.3.3.3","src_port":53000,"dest_ip":"4.4.4.4","dest_port":80,"proto":"TCP","alert":{"signature":"Low sev","signature_id":1,"category":"Info","severity":3}}"#;
        let r = parse_eve_jsonl(sample, None, Some(2), 1000, None);
        assert_eq!(r.total_events, 3);
        assert_eq!(*r.by_event_type.get("alert").unwrap(), 2);
        assert_eq!(*r.by_event_type.get("dns").unwrap(), 1);
        // min_severity=2 should drop severity=3
        assert_eq!(r.alerts.len(), 1);
        assert_eq!(r.alerts[0].signature_id, 2031234);
    }
}

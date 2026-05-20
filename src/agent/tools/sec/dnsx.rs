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
pub struct DnsxArgs {
    pub hosts: Vec<String>,
    #[serde(default)]
    pub record_types: Option<Vec<String>>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct DnsxRecord {
    pub host: String,
    #[serde(default)]
    pub a: Vec<String>,
    #[serde(default)]
    pub aaaa: Vec<String>,
    #[serde(default)]
    pub cname: Vec<String>,
    #[serde(default)]
    pub mx: Vec<String>,
    #[serde(default)]
    pub ns: Vec<String>,
    #[serde(default)]
    pub txt: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct DnsxOutput {
    pub records: Vec<DnsxRecord>,
    pub raw_command: String,
    pub exit_code: i32,
    pub stderr_tail: String,
}

pub struct DnsxTool {
    ctx: SecContext,
}

impl DnsxTool {
    pub fn new(ctx: SecContext) -> Self {
        DnsxTool { ctx }
    }
}

impl Tool for DnsxTool {
    const NAME: &'static str = "dnsx";
    type Error = ToolError;
    type Args = DnsxArgs;
    type Output = DnsxOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: append_output_schema::<DnsxOutput>(
                "Batch DNS resolution via dnsx. Returns A/AAAA/CNAME/MX/NS/TXT per host. \
                          All hosts must be in scope.",
            ),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "hosts": { "type": "array", "items": {"type": "string"} },
                    "record_types": { "type": "array", "items": {"type": "string"},
                                      "description": "e.g. ['a','aaaa','cname','mx','ns','txt']. Defaults to ['a']." },
                    "timeout_secs": { "type": "integer" }
                },
                "required": ["hosts"]
            }),
        }
    }

    async fn call(&self, args: DnsxArgs) -> Result<DnsxOutput, ToolError> {
        let policy = require_policy(&self.ctx)?;
        if args.hosts.is_empty() {
            return Err(ToolError::Msg("dnsx: hosts required".into()));
        }
        check_targets_in_scope(&policy, &args.hosts)?;
        preflight("dnsx").await?;

        let types = args
            .record_types
            .clone()
            .unwrap_or_else(|| vec!["a".into()]);
        let host_list = args.hosts.join("\n");
        let mut argv: Vec<String> = vec![
            "dnsx".into(),
            "-silent".into(),
            "-json".into(),
            "-resp".into(),
        ];
        for t in &types {
            argv.push(format!("-{}", t.to_lowercase()));
        }
        let cmd = format!(
            "printf {} | {}",
            shq(&host_list),
            argv.iter().map(|s| shq(s)).collect::<Vec<_>>().join(" ")
        );
        let outcome = run_shell(&self.ctx, &cmd, args.timeout_secs.unwrap_or(120)).await?;
        let records = parse_dnsx_jsonl(&outcome.stdout);

        let summary = format!("dnsx: resolved {} record set(s)", records.len());
        record(&self.ctx, "dnsx", &argv, &outcome, &summary);

        Ok(DnsxOutput {
            records,
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

pub fn parse_dnsx_jsonl(s: &str) -> Vec<DnsxRecord> {
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
        let host = v
            .get("host")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if host.is_empty() {
            continue;
        }
        let arr = |k: &str| -> Vec<String> {
            v.get(k)
                .and_then(|x| x.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|e| e.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default()
        };
        out.push(DnsxRecord {
            host,
            a: arr("a"),
            aaaa: arr("aaaa"),
            cname: arr("cname"),
            mx: arr("mx"),
            ns: arr("ns"),
            txt: arr("txt"),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typical_jsonl() {
        let sample = "{\"host\":\"example.com\",\"a\":[\"93.184.216.34\"]}\n\
                      {\"host\":\"api.example.com\",\"a\":[\"1.2.3.4\"],\"cname\":[\"lb.example.com\"]}\n";
        let recs = parse_dnsx_jsonl(sample);
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].host, "example.com");
        assert_eq!(recs[0].a, vec!["93.184.216.34".to_string()]);
        assert_eq!(recs[1].cname, vec!["lb.example.com".to_string()]);
    }

    #[test]
    fn skips_malformed_lines() {
        let sample = "garbage\n{\"host\":\"example.com\",\"a\":[\"1.2.3.4\"]}\n";
        let recs = parse_dnsx_jsonl(sample);
        assert_eq!(recs.len(), 1);
    }
}

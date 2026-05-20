use crate::agent::tools::schema::append_output_schema;
use rig::completion::ToolDefinition;
use rig::tool::Tool;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::agent::tools::ToolError;
use crate::agent::tools::sec::{SecContext, record, require_policy, run_shell, shq};

#[derive(Deserialize, JsonSchema)]
pub struct ZeekLogArgs {
    pub log_path: String,
    #[serde(default)]
    pub max_records: Option<usize>,
    #[serde(default)]
    pub filter_field: Option<String>,
    #[serde(default)]
    pub filter_value: Option<String>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ZeekLogOutput {
    pub log_path: String,
    pub path: Option<String>,
    pub fields: Vec<String>,
    pub record_count: usize,
    pub records: Vec<BTreeMap<String, String>>,
    pub raw_command: String,
    pub exit_code: i32,
    pub stderr_tail: String,
}

pub struct ZeekLogTool {
    ctx: SecContext,
}

impl ZeekLogTool {
    pub fn new(ctx: SecContext) -> Self {
        ZeekLogTool { ctx }
    }
}

impl Tool for ZeekLogTool {
    const NAME: &'static str = "zeek_log";
    type Error = ToolError;
    type Args = ZeekLogArgs;
    type Output = ZeekLogOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: append_output_schema::<ZeekLogOutput>(
                "Parse a Zeek TSV log file (conn.log, dns.log, http.log, ssl.log, \
                          notice.log, etc.). Returns the field list from the header and each \
                          record as a field->value map. Use `filter_field`+`filter_value` to \
                          narrow (substring match). Caps at 1000 records by default.",
            ),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "log_path": { "type": "string", "description": "Path to Zeek .log file" },
                    "max_records": { "type": "integer", "description": "Cap returned records (default 1000)" },
                    "filter_field": { "type": "string", "description": "Field name to filter on" },
                    "filter_value": { "type": "string", "description": "Substring to match in filter_field" },
                    "timeout_secs": { "type": "integer" }
                },
                "required": ["log_path"]
            }),
        }
    }

    async fn call(&self, args: ZeekLogArgs) -> Result<ZeekLogOutput, ToolError> {
        let _ = require_policy(&self.ctx)?;
        let cmd = format!("cat {}", shq(&args.log_path));
        let outcome = run_shell(&self.ctx, &cmd, args.timeout_secs.unwrap_or(60)).await?;
        let parsed = parse_zeek_tsv(
            &outcome.stdout,
            args.filter_field.as_deref(),
            args.filter_value.as_deref(),
            args.max_records.unwrap_or(1000),
        );

        let summary = format!(
            "zeek_log {}: {} record(s)",
            args.log_path,
            parsed.records.len()
        );
        record(&self.ctx, "zeek_log", &[], &outcome, &summary);

        Ok(ZeekLogOutput {
            log_path: args.log_path,
            path: parsed.path,
            fields: parsed.fields,
            record_count: parsed.records.len(),
            records: parsed.records,
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
pub struct ParsedZeek {
    pub path: Option<String>,
    pub fields: Vec<String>,
    pub records: Vec<BTreeMap<String, String>>,
}

pub fn parse_zeek_tsv(
    s: &str,
    filter_field: Option<&str>,
    filter_value: Option<&str>,
    cap: usize,
) -> ParsedZeek {
    let mut out = ParsedZeek::default();
    let mut sep = '\t';
    let mut empty = "(empty)".to_string();
    let mut unset = "-".to_string();
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("#separator") {
            let val = rest.trim();
            if let Some(hex) = val.strip_prefix("\\x") {
                if let Ok(n) = u8::from_str_radix(hex, 16) {
                    sep = n as char;
                }
            } else if let Some(ch) = val.chars().next() {
                sep = ch;
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("#path") {
            out.path = Some(rest.trim_start_matches(sep).trim().to_string());
            continue;
        }
        if let Some(rest) = line.strip_prefix("#fields") {
            out.fields = rest
                .trim_start_matches(sep)
                .split(sep)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            continue;
        }
        if let Some(rest) = line.strip_prefix("#empty_field") {
            empty = rest.trim_start_matches(sep).trim().to_string();
            continue;
        }
        if let Some(rest) = line.strip_prefix("#unset_field") {
            unset = rest.trim_start_matches(sep).trim().to_string();
            continue;
        }
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split(sep).collect();
        let mut rec: BTreeMap<String, String> = BTreeMap::new();
        for (i, f) in out.fields.iter().enumerate() {
            let raw = parts.get(i).copied().unwrap_or("");
            let val = if raw == unset || raw == empty {
                String::new()
            } else {
                raw.to_string()
            };
            rec.insert(f.clone(), val);
        }
        if let (Some(ff), Some(fv)) = (filter_field, filter_value) {
            match rec.get(ff) {
                Some(v) if v.contains(fv) => {}
                _ => continue,
            }
        }
        out.records.push(rec);
        if out.records.len() >= cap {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_conn_log() {
        let sample = "#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n#open\t2024-01-01-12-00-00\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\n1700000000.0\tCabcd1\t10.0.0.1\t1024\t8.8.8.8\t53\tudp\tdns\n1700000001.0\tCabcd2\t10.0.0.2\t2048\t1.1.1.1\t443\ttcp\tssl\n";
        let r = parse_zeek_tsv(sample, None, None, 100);
        assert_eq!(r.path.as_deref(), Some("conn"));
        assert!(r.fields.contains(&"id.orig_h".to_string()));
        assert_eq!(r.records.len(), 2);
        assert_eq!(r.records[0].get("id.resp_h").unwrap(), "8.8.8.8");
        assert_eq!(r.records[1].get("service").unwrap(), "ssl");
    }

    #[test]
    fn filters_records() {
        let sample = "#separator \\x09\n#path\tconn\n#fields\tts\tip\n1\t1.1.1.1\n2\t2.2.2.2\n";
        let r = parse_zeek_tsv(sample, Some("ip"), Some("2.2"), 100);
        assert_eq!(r.records.len(), 1);
        assert_eq!(r.records[0].get("ip").unwrap(), "2.2.2.2");
    }
}

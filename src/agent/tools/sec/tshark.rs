use crate::agent::tools::schema::append_output_schema;
use rig::completion::ToolDefinition;
use rig::tool::Tool;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::agent::tools::ToolError;
use crate::agent::tools::sec::{SecContext, preflight, record, require_policy, run_shell, shq};

#[derive(Deserialize, JsonSchema)]
pub struct TsharkArgs {
    pub pcap: String,
    #[serde(default)]
    pub filter: Option<String>,
    #[serde(default)]
    pub fields: Option<Vec<String>>,
    #[serde(default)]
    pub max_packets: Option<usize>,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct TsharkOutput {
    pub pcap: String,
    pub format: String,
    pub packet_count: usize,
    pub packets: Vec<serde_json::Value>,
    pub raw_command: String,
    pub exit_code: i32,
    pub stderr_tail: String,
}

pub struct TsharkTool {
    ctx: SecContext,
}

impl TsharkTool {
    pub fn new(ctx: SecContext) -> Self {
        TsharkTool { ctx }
    }
}

impl Tool for TsharkTool {
    const NAME: &'static str = "tshark";
    type Error = ToolError;
    type Args = TsharkArgs;
    type Output = TsharkOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: append_output_schema::<TsharkOutput>(
                "tshark pcap reader. Parses a capture file with optional display \
                          filter (-Y) and field selection (-e). Default format is `ek` \
                          (Elasticsearch JSONL, one JSON object per packet). Use `format: \
                          'fields'` with `fields: ['ip.src','tcp.dstport',...]` for tabular \
                          extraction. Caps at 5000 packets by default.",
            ),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "pcap": { "type": "string", "description": "Path to .pcap/.pcapng file" },
                    "filter": { "type": "string", "description": "Wireshark display filter (-Y)" },
                    "fields": { "type": "array", "items": {"type": "string"},
                                "description": "Field names for tabular output (-e), e.g. ['ip.src','tcp.dstport']" },
                    "max_packets": { "type": "integer", "description": "Cap returned packets (default 5000)" },
                    "format": { "type": "string", "description": "ek|fields|json (default ek)" },
                    "timeout_secs": { "type": "integer" }
                },
                "required": ["pcap"]
            }),
        }
    }

    async fn call(&self, args: TsharkArgs) -> Result<TsharkOutput, ToolError> {
        let _ = require_policy(&self.ctx)?;
        preflight("tshark").await?;

        let format = args.format.clone().unwrap_or_else(|| {
            if args.fields.is_some() {
                "fields".into()
            } else {
                "ek".into()
            }
        });

        let mut argv: Vec<String> = vec!["tshark".into(), "-r".into(), args.pcap.clone()];
        if let Some(f) = &args.filter {
            argv.push("-Y".into());
            argv.push(f.clone());
        }
        match format.as_str() {
            "fields" => {
                argv.push("-T".into());
                argv.push("fields".into());
                if let Some(fs) = &args.fields {
                    for f in fs {
                        argv.push("-e".into());
                        argv.push(f.clone());
                    }
                }
                argv.push("-E".into());
                argv.push("header=y".into());
                argv.push("-E".into());
                argv.push("separator=,".into());
                argv.push("-E".into());
                argv.push("quote=d".into());
            }
            "json" => {
                argv.push("-T".into());
                argv.push("json".into());
            }
            _ => {
                argv.push("-T".into());
                argv.push("ek".into());
            }
        }

        let cmd = argv.iter().map(|s| shq(s)).collect::<Vec<_>>().join(" ");
        let outcome = run_shell(&self.ctx, &cmd, args.timeout_secs.unwrap_or(300)).await?;
        let cap = args.max_packets.unwrap_or(5000);
        let packets = match format.as_str() {
            "fields" => parse_tshark_fields(&outcome.stdout, cap),
            "json" => parse_tshark_json(&outcome.stdout, cap),
            _ => parse_tshark_ek(&outcome.stdout, cap),
        };

        let summary = format!("tshark {}: {} packet(s)", args.pcap, packets.len());
        record(&self.ctx, "tshark", &argv, &outcome, &summary);

        Ok(TsharkOutput {
            pcap: args.pcap,
            format,
            packet_count: packets.len(),
            packets,
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

pub fn parse_tshark_ek(s: &str, cap: usize) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    let mut skip_next = false;
    for line in s.lines() {
        let trim = line.trim();
        if trim.is_empty() {
            continue;
        }
        // EK output alternates index header lines and packet body lines.
        let v: serde_json::Value = match serde_json::from_str(trim) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if v.get("index").is_some() {
            skip_next = false;
            continue;
        }
        if skip_next {
            continue;
        }
        out.push(v);
        if out.len() >= cap {
            break;
        }
    }
    out
}

pub fn parse_tshark_json(s: &str, cap: usize) -> Vec<serde_json::Value> {
    let trimmed = s.trim();
    let v: serde_json::Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    v.as_array()
        .map(|a| a.iter().take(cap).cloned().collect())
        .unwrap_or_default()
}

pub fn parse_tshark_fields(s: &str, cap: usize) -> Vec<serde_json::Value> {
    let mut lines = s.lines();
    let header = match lines.next() {
        Some(h) => h,
        None => return Vec::new(),
    };
    let cols: Vec<&str> = parse_csv_line(header);
    let mut out = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let vals = parse_csv_line(line);
        let mut map = serde_json::Map::new();
        for (i, c) in cols.iter().enumerate() {
            map.insert(
                c.to_string(),
                serde_json::Value::String(vals.get(i).copied().unwrap_or("").to_string()),
            );
        }
        out.push(serde_json::Value::Object(map));
        if out.len() >= cap {
            break;
        }
    }
    out
}

fn parse_csv_line(line: &str) -> Vec<&str> {
    // Cheap CSV with quote=d: fields are either bare or "double-quoted".
    let mut out = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() && bytes[j] != b'"' {
                j += 1;
            }
            out.push(&line[start..j]);
            i = j + 1;
            if i < bytes.len() && bytes[i] == b',' {
                i += 1;
            }
        } else {
            let start = i;
            while i < bytes.len() && bytes[i] != b',' {
                i += 1;
            }
            out.push(&line[start..i]);
            if i < bytes.len() {
                i += 1;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fields_csv() {
        let sample = "\"ip.src\",\"tcp.dstport\"\n\"10.0.0.1\",\"443\"\n\"10.0.0.2\",\"80\"\n";
        let r = parse_tshark_fields(sample, 100);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0]["ip.src"], "10.0.0.1");
        assert_eq!(r[1]["tcp.dstport"], "80");
    }

    #[test]
    fn parses_ek_packets() {
        let sample = r#"{"index":{"_index":"packets-2024-01-01","_type":"doc"}}
{"timestamp":"1234","layers":{"ip":{"ip_ip_src":"1.2.3.4"}}}
{"index":{"_index":"packets-2024-01-01","_type":"doc"}}
{"timestamp":"1235","layers":{"ip":{"ip_ip_src":"5.6.7.8"}}}"#;
        let r = parse_tshark_ek(sample, 100);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0]["timestamp"], "1234");
    }
}

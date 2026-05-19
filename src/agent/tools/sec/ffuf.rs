use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};

use crate::agent::tools::ToolError;
use crate::agent::tools::sec::{
    SecContext, check_targets_in_scope, preflight, record, require_policy, run_shell, shq,
};

#[derive(Deserialize)]
pub struct FfufArgs {
    pub url: String,
    pub wordlist: String,
    #[serde(default)]
    pub extensions: Option<String>,
    #[serde(default)]
    pub match_codes: Option<String>,
    #[serde(default)]
    pub filter_codes: Option<String>,
    #[serde(default)]
    pub threads: Option<u32>,
    #[serde(default)]
    pub headers: Option<Vec<String>>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FfufHit {
    pub url: String,
    pub input: Option<String>,
    pub status: u16,
    pub length: u64,
    pub words: u64,
    pub lines: u64,
    pub content_type: Option<String>,
    pub redirect_location: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FfufOutput {
    pub hits: Vec<FfufHit>,
    pub raw_command: String,
    pub exit_code: i32,
    pub stderr_tail: String,
}

pub struct FfufTool {
    ctx: SecContext,
}

impl FfufTool {
    pub fn new(ctx: SecContext) -> Self {
        FfufTool { ctx }
    }
}

impl Tool for FfufTool {
    const NAME: &'static str = "ffuf";
    type Error = ToolError;
    type Args = FfufArgs;
    type Output = FfufOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: "Fast web fuzzer (ffuf). Use FUZZ keyword in the URL to mark the \
                          injection point (e.g. https://target/FUZZ). Target host must be in \
                          scope. Returns typed hits with status, length, and content type."
                .to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "url": { "type": "string", "description": "URL containing FUZZ keyword" },
                    "wordlist": { "type": "string", "description": "Path to wordlist file" },
                    "extensions": { "type": "string", "description": "Comma-separated extensions, e.g. '.php,.bak'" },
                    "match_codes": { "type": "string", "description": "Match HTTP status codes (-mc), default 200,204,301,302,307,401,403,405" },
                    "filter_codes": { "type": "string", "description": "Filter HTTP status codes (-fc)" },
                    "threads": { "type": "integer", "description": "Concurrency (-t)" },
                    "headers": { "type": "array", "items": {"type": "string"},
                                 "description": "Extra HTTP headers, e.g. ['Cookie: x=1']" },
                    "timeout_secs": { "type": "integer" }
                },
                "required": ["url", "wordlist"]
            }),
        }
    }

    async fn call(&self, args: FfufArgs) -> Result<FfufOutput, ToolError> {
        let policy = require_policy(&self.ctx)?;
        if !args.url.contains("FUZZ") {
            return Err(ToolError::Msg(
                "ffuf: url must contain the FUZZ keyword".into(),
            ));
        }
        let host = host_of(&args.url);
        check_targets_in_scope(&policy, std::slice::from_ref(&host))?;
        preflight("ffuf").await?;

        let mut argv: Vec<String> = vec![
            "ffuf".into(),
            "-u".into(),
            args.url.clone(),
            "-w".into(),
            args.wordlist.clone(),
            "-of".into(),
            "json".into(),
            "-o".into(),
            "/dev/stdout".into(),
            "-s".into(),
            "-noninteractive".into(),
        ];
        if let Some(e) = &args.extensions {
            argv.push("-e".into());
            argv.push(e.clone());
        }
        if let Some(mc) = &args.match_codes {
            argv.push("-mc".into());
            argv.push(mc.clone());
        }
        if let Some(fc) = &args.filter_codes {
            argv.push("-fc".into());
            argv.push(fc.clone());
        }
        if let Some(t) = args.threads {
            argv.push("-t".into());
            argv.push(t.to_string());
        }
        if let Some(hs) = &args.headers {
            for h in hs {
                argv.push("-H".into());
                argv.push(h.clone());
            }
        }

        let cmd = argv.iter().map(|s| shq(s)).collect::<Vec<_>>().join(" ");
        let outcome = run_shell(&self.ctx, &cmd, args.timeout_secs.unwrap_or(600)).await?;
        let hits = parse_ffuf_json(&outcome.stdout);

        let summary = format!("ffuf: {} hit(s)", hits.len());
        record(&self.ctx, "ffuf", &argv, &outcome, &summary);

        Ok(FfufOutput {
            hits,
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

pub fn parse_ffuf_json(s: &str) -> Vec<FfufHit> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let v: serde_json::Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let arr = match v.get("results").and_then(|x| x.as_array()) {
        Some(a) => a,
        None => return Vec::new(),
    };
    let mut out = Vec::with_capacity(arr.len());
    for r in arr {
        let url = r
            .get("url")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if url.is_empty() {
            continue;
        }
        out.push(FfufHit {
            url,
            input: r
                .get("input")
                .and_then(|i| {
                    i.get("FUZZ")
                        .or_else(|| i.as_object().and_then(|m| m.values().next()))
                })
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
            status: r.get("status").and_then(|x| x.as_u64()).unwrap_or(0) as u16,
            length: r.get("length").and_then(|x| x.as_u64()).unwrap_or(0),
            words: r.get("words").and_then(|x| x.as_u64()).unwrap_or(0),
            lines: r.get("lines").and_then(|x| x.as_u64()).unwrap_or(0),
            content_type: r
                .get("content-type")
                .or_else(|| r.get("content_type"))
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
            redirect_location: r
                .get("redirectlocation")
                .or_else(|| r.get("redirect_location"))
                .and_then(|x| x.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string()),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_results_array() {
        let sample = r#"{
          "commandline": "ffuf ...",
          "results": [
            {"input":{"FUZZ":"admin"},"url":"https://t/admin","status":401,"length":12,"words":2,"lines":1,"content-type":"text/html"},
            {"input":{"FUZZ":"backup.zip"},"url":"https://t/backup.zip","status":200,"length":1024,"words":10,"lines":3,"content-type":"application/zip"}
          ]
        }"#;
        let hits = parse_ffuf_json(sample);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].status, 401);
        assert_eq!(hits[0].input.as_deref(), Some("admin"));
        assert_eq!(hits[1].length, 1024);
        assert_eq!(hits[1].content_type.as_deref(), Some("application/zip"));
    }

    #[test]
    fn empty_input_yields_empty() {
        assert_eq!(parse_ffuf_json("").len(), 0);
        assert_eq!(parse_ffuf_json("{\"results\":[]}").len(), 0);
    }
}

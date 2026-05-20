use crate::agent::tools::schema::append_output_schema;
use rig::completion::ToolDefinition;
use rig::tool::Tool;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::agent::tools::ToolError;
use crate::agent::tools::sec::{SecContext, preflight, record, require_policy, run_shell, shq};

#[derive(Deserialize, JsonSchema)]
pub struct SearchsploitArgs {
    pub query: String,
    #[serde(default)]
    pub exact: Option<bool>,
    #[serde(default)]
    pub case_sensitive: Option<bool>,
    #[serde(default)]
    pub title_only: Option<bool>,
    #[serde(default)]
    pub include_paths: Option<bool>,
    #[serde(default)]
    pub cve: Option<String>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ExploitEntry {
    pub edb_id: String,
    pub title: String,
    pub path: String,
    pub date: Option<String>,
    pub author: Option<String>,
    pub type_: Option<String>,
    pub platform: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct SearchsploitOutput {
    pub exploits: Vec<ExploitEntry>,
    pub shellcodes: Vec<ExploitEntry>,
    pub raw_command: String,
    pub exit_code: i32,
    pub stderr_tail: String,
}

pub struct SearchsploitTool {
    ctx: SecContext,
}

impl SearchsploitTool {
    pub fn new(ctx: SecContext) -> Self {
        SearchsploitTool { ctx }
    }
}

impl Tool for SearchsploitTool {
    const NAME: &'static str = "searchsploit";
    type Error = ToolError;
    type Args = SearchsploitArgs;
    type Output = SearchsploitOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: append_output_schema::<SearchsploitOutput>(
                "Local offline ExploitDB search via searchsploit -j (JSON). Returns \
                          typed entries with EDB ID, title, path, date, author, platform, type. \
                          Local only; no scope check (queries the local exploit database).",
            ),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "Search terms (e.g. 'apache 2.4 rce')" },
                    "exact": { "type": "boolean", "description": "-e exact match" },
                    "case_sensitive": { "type": "boolean", "description": "-c case sensitive" },
                    "title_only": { "type": "boolean", "description": "-t search title only" },
                    "include_paths": { "type": "boolean", "description": "-p include full paths" },
                    "cve": { "type": "string", "description": "Filter by CVE (e.g. 2021-44228)" },
                    "timeout_secs": { "type": "integer" }
                },
                "required": ["query"]
            }),
        }
    }

    async fn call(&self, args: SearchsploitArgs) -> Result<SearchsploitOutput, ToolError> {
        let _ = require_policy(&self.ctx)?;
        preflight("searchsploit").await?;

        let mut argv: Vec<String> = vec!["searchsploit".into(), "-j".into()];
        if args.exact.unwrap_or(false) {
            argv.push("-e".into());
        }
        if args.case_sensitive.unwrap_or(false) {
            argv.push("-c".into());
        }
        if args.title_only.unwrap_or(false) {
            argv.push("-t".into());
        }
        if args.include_paths.unwrap_or(false) {
            argv.push("-p".into());
        }
        if let Some(c) = &args.cve {
            argv.push("--cve".into());
            argv.push(c.clone());
        }
        for term in args.query.split_whitespace() {
            argv.push(term.to_string());
        }

        let cmd = argv.iter().map(|s| shq(s)).collect::<Vec<_>>().join(" ");
        let outcome = run_shell(&self.ctx, &cmd, args.timeout_secs.unwrap_or(60)).await?;
        let (exploits, shellcodes) = parse_searchsploit_json(&outcome.stdout);

        let summary = format!(
            "searchsploit: {} exploit(s), {} shellcode(s)",
            exploits.len(),
            shellcodes.len()
        );
        record(&self.ctx, "searchsploit", &argv, &outcome, &summary);

        Ok(SearchsploitOutput {
            exploits,
            shellcodes,
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

pub fn parse_searchsploit_json(s: &str) -> (Vec<ExploitEntry>, Vec<ExploitEntry>) {
    let trimmed = s.trim();
    let v: serde_json::Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(_) => return (Vec::new(), Vec::new()),
    };
    let exploits = v
        .get("RESULTS_EXPLOIT")
        .and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(parse_entry).collect())
        .unwrap_or_default();
    let shellcodes = v
        .get("RESULTS_SHELLCODE")
        .and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(parse_entry).collect())
        .unwrap_or_default();
    (exploits, shellcodes)
}

fn parse_entry(v: &serde_json::Value) -> Option<ExploitEntry> {
    let edb_id = v
        .get("EDB-ID")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .or_else(|| {
            v.get("EDB-ID")
                .and_then(|x| x.as_u64())
                .map(|n| n.to_string())
        })?;
    let title = v
        .get("Title")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let path = v
        .get("Path")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    Some(ExploitEntry {
        edb_id,
        title,
        path,
        date: v
            .get("Date")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        author: v
            .get("Author")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        type_: v
            .get("Type")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        platform: v
            .get("Platform")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typical_json() {
        let sample = r#"{
          "SEARCH":"apache",
          "RESULTS_EXPLOIT":[
            {"Title":"Apache 2.4.49 Path Traversal","EDB-ID":"50383","Path":"linux/webapps/50383.py","Date":"2021-10-05","Author":"hacker","Type":"webapps","Platform":"linux"},
            {"Title":"Apache mod_rewrite","EDB-ID":"764","Path":"unix/remote/764.txt"}
          ],
          "RESULTS_SHELLCODE":[]
        }"#;
        let (ex, sh) = parse_searchsploit_json(sample);
        assert_eq!(ex.len(), 2);
        assert_eq!(ex[0].edb_id, "50383");
        assert_eq!(ex[0].platform.as_deref(), Some("linux"));
        assert!(sh.is_empty());
    }

    #[test]
    fn handles_numeric_edb_id() {
        let sample = r#"{"RESULTS_EXPLOIT":[{"Title":"x","EDB-ID":1234,"Path":"p"}],"RESULTS_SHELLCODE":[]}"#;
        let (ex, _) = parse_searchsploit_json(sample);
        assert_eq!(ex.len(), 1);
        assert_eq!(ex[0].edb_id, "1234");
    }
}

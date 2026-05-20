use crate::agent::tools::schema::append_output_schema;
use rig::completion::ToolDefinition;
use rig::tool::Tool;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::agent::tools::ToolError;
use crate::agent::tools::sec::{SecContext, preflight, record, require_policy, run_shell, shq};

#[derive(Deserialize, JsonSchema)]
pub struct AflFuzzArgs {
    pub input_dir: String,
    pub output_dir: String,
    pub target: String,
    #[serde(default)]
    pub target_args: Option<Vec<String>>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    #[serde(default)]
    pub memory_mb: Option<u32>,
    #[serde(default)]
    pub dictionary: Option<String>,
    #[serde(default)]
    pub fuzzer_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct AflFuzzOutput {
    pub output_dir: String,
    pub crashes_dir: String,
    pub hangs_dir: String,
    pub queue_dir: String,
    pub crash_count: usize,
    pub hang_count: usize,
    pub queue_count: usize,
    pub crash_files: Vec<String>,
    pub fuzzer_stats: Option<serde_json::Value>,
    pub raw_command: String,
    pub exit_code: i32,
    pub stderr_tail: String,
}

pub struct AflFuzzTool {
    ctx: SecContext,
}

impl AflFuzzTool {
    pub fn new(ctx: SecContext) -> Self {
        AflFuzzTool { ctx }
    }
}

impl Tool for AflFuzzTool {
    const NAME: &'static str = "afl_fuzz";
    type Error = ToolError;
    type Args = AflFuzzArgs;
    type Output = AflFuzzOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: append_output_schema::<AflFuzzOutput>(
                "Bounded AFL++ fuzz harness. Runs afl-fuzz against an instrumented \
                          binary for `timeout_secs` (default 60s), then enumerates crashes/, \
                          hangs/, queue/ and parses fuzzer_stats. The target binary must already \
                          be instrumented (afl-cc/afl-clang-fast). Local only.",
            ),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "input_dir": { "type": "string", "description": "Seed corpus directory (-i)" },
                    "output_dir": { "type": "string", "description": "AFL output dir (-o)" },
                    "target": { "type": "string", "description": "Path to instrumented binary" },
                    "target_args": { "type": "array", "items": {"type": "string"},
                                     "description": "Args for target (use '@@' for input file path)" },
                    "memory_mb": { "type": "integer", "description": "-m memory limit" },
                    "dictionary": { "type": "string", "description": "-x dictionary path" },
                    "fuzzer_id": { "type": "string", "description": "-S secondary fuzzer name" },
                    "timeout_secs": { "type": "integer", "description": "Wall-clock budget; default 60s" }
                },
                "required": ["input_dir", "output_dir", "target"]
            }),
        }
    }

    async fn call(&self, args: AflFuzzArgs) -> Result<AflFuzzOutput, ToolError> {
        let _ = require_policy(&self.ctx)?;
        preflight("afl-fuzz").await?;

        let budget = args.timeout_secs.unwrap_or(60);
        let mut inner: Vec<String> = vec![
            "afl-fuzz".into(),
            "-i".into(),
            args.input_dir.clone(),
            "-o".into(),
            args.output_dir.clone(),
        ];
        if let Some(m) = args.memory_mb {
            inner.push("-m".into());
            inner.push(m.to_string());
        }
        if let Some(d) = &args.dictionary {
            inner.push("-x".into());
            inner.push(d.clone());
        }
        if let Some(id) = &args.fuzzer_id {
            inner.push("-S".into());
            inner.push(id.clone());
        }
        inner.push("--".into());
        inner.push(args.target.clone());
        if let Some(ta) = &args.target_args {
            inner.extend(ta.iter().cloned());
        }

        let inner_cmd = inner.iter().map(|s| shq(s)).collect::<Vec<_>>().join(" ");
        // Wrap with `timeout` so afl-fuzz exits cleanly; exit 124 = timed out (expected).
        let cmd = format!("timeout --preserve-status {} {}", budget, inner_cmd);
        let outcome = run_shell(&self.ctx, &cmd, budget + 30).await?;

        let crashes_dir = format!("{}/default/crashes", args.output_dir.trim_end_matches('/'));
        let hangs_dir = format!("{}/default/hangs", args.output_dir.trim_end_matches('/'));
        let queue_dir = format!("{}/default/queue", args.output_dir.trim_end_matches('/'));
        let crash_files = list_dir_non_readme(&crashes_dir);
        let hang_count = list_dir_non_readme(&hangs_dir).len();
        let queue_count = list_dir_non_readme(&queue_dir).len();
        let stats_path = format!(
            "{}/default/fuzzer_stats",
            args.output_dir.trim_end_matches('/')
        );
        let fuzzer_stats = std::fs::read_to_string(&stats_path)
            .ok()
            .map(|s| parse_fuzzer_stats(&s));

        let summary = format!(
            "afl-fuzz {}s: {} crashes, {} hangs, {} queue",
            budget,
            crash_files.len(),
            hang_count,
            queue_count
        );
        record(&self.ctx, "afl_fuzz", &inner, &outcome, &summary);

        Ok(AflFuzzOutput {
            output_dir: args.output_dir,
            crashes_dir,
            hangs_dir,
            queue_dir,
            crash_count: crash_files.len(),
            hang_count,
            queue_count,
            crash_files,
            fuzzer_stats,
            raw_command: cmd,
            exit_code: outcome.exit_code,
            stderr_tail: tail(&outcome.stderr, 500),
        })
    }
}

fn list_dir_non_readme(dir: &str) -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    rd.filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with("README") || name.starts_with('.') {
                None
            } else {
                Some(e.path().to_string_lossy().to_string())
            }
        })
        .collect()
}

fn tail(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        s[s.len() - n..].to_string()
    }
}

pub fn parse_fuzzer_stats(s: &str) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for line in s.lines() {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim();
            let val = v.trim();
            if !key.is_empty() {
                map.insert(key.to_string(), serde_json::Value::String(val.to_string()));
            }
        }
    }
    serde_json::Value::Object(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fuzzer_stats() {
        let sample =
            "start_time        : 1700000000\nexecs_done        : 12345\nunique_crashes    : 3\n";
        let v = parse_fuzzer_stats(sample);
        assert_eq!(v["execs_done"], "12345");
        assert_eq!(v["unique_crashes"], "3");
    }
}

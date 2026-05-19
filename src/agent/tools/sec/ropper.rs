use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};

use crate::agent::tools::ToolError;
use crate::agent::tools::sec::{SecContext, preflight, record, require_policy, run_shell, shq};

#[derive(Deserialize)]
pub struct RopperArgs {
    pub file: String,
    #[serde(default)]
    pub search: Option<String>,
    #[serde(default)]
    pub badbytes: Option<String>,
    #[serde(default)]
    pub depth: Option<u32>,
    #[serde(default)]
    pub quality: Option<u32>,
    #[serde(default)]
    pub max_gadgets: Option<usize>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Gadget {
    pub address: String,
    pub instructions: String,
    pub bytes: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RopperOutput {
    pub file: String,
    pub arch: Option<String>,
    pub gadgets: Vec<Gadget>,
    pub total_found: usize,
    pub raw_command: String,
    pub exit_code: i32,
    pub stderr_tail: String,
}

pub struct RopperTool {
    ctx: SecContext,
}

impl RopperTool {
    pub fn new(ctx: SecContext) -> Self {
        RopperTool { ctx }
    }
}

impl Tool for RopperTool {
    const NAME: &'static str = "ropper";
    type Error = ToolError;
    type Args = RopperArgs;
    type Output = RopperOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: "Ropper ROP gadget finder. Returns address+instructions for gadgets \
                          discovered in an ELF/Mach-O/PE binary. Use `search` to filter (e.g. \
                          'pop rdi; ret'). Local only."
                .to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "file": { "type": "string" },
                    "search": { "type": "string", "description": "Gadget search pattern" },
                    "badbytes": { "type": "string", "description": "Hex bytes to exclude, e.g. '00 0a 0d'" },
                    "depth": { "type": "integer", "description": "Max instructions per gadget" },
                    "quality": { "type": "integer", "description": "Filter quality 1-5" },
                    "max_gadgets": { "type": "integer", "description": "Cap returned gadgets (default 500)" },
                    "timeout_secs": { "type": "integer" }
                },
                "required": ["file"]
            }),
        }
    }

    async fn call(&self, args: RopperArgs) -> Result<RopperOutput, ToolError> {
        let _ = require_policy(&self.ctx)?;
        preflight("ropper").await?;

        let mut argv: Vec<String> = vec![
            "ropper".into(),
            "--nocolor".into(),
            "--file".into(),
            args.file.clone(),
        ];
        if let Some(s) = &args.search {
            argv.push("--search".into());
            argv.push(s.clone());
        }
        if let Some(b) = &args.badbytes {
            argv.push("--badbytes".into());
            argv.push(b.clone());
        }
        if let Some(d) = args.depth {
            argv.push("--inst-count".into());
            argv.push(d.to_string());
        }
        if let Some(q) = args.quality {
            argv.push("--quality".into());
            argv.push(q.to_string());
        }

        let cmd = argv.iter().map(|s| shq(s)).collect::<Vec<_>>().join(" ");
        let outcome = run_shell(&self.ctx, &cmd, args.timeout_secs.unwrap_or(120)).await?;
        let mut parsed = parse_ropper_text(&outcome.stdout);
        let total = parsed.gadgets.len();
        let cap = args.max_gadgets.unwrap_or(500);
        if parsed.gadgets.len() > cap {
            parsed.gadgets.truncate(cap);
        }

        let summary = format!(
            "ropper {}: {} gadget(s) (returned {})",
            args.file, total, parsed.gadgets.len()
        );
        record(&self.ctx, "ropper", &argv, &outcome, &summary);

        Ok(RopperOutput {
            file: args.file,
            arch: parsed.arch,
            gadgets: parsed.gadgets,
            total_found: total,
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
pub struct ParsedRopper {
    pub arch: Option<String>,
    pub gadgets: Vec<Gadget>,
}

pub fn parse_ropper_text(s: &str) -> ParsedRopper {
    let mut out = ParsedRopper::default();
    for line in s.lines() {
        let trim = line.trim();
        if let Some(rest) = trim.strip_prefix("Arch:") {
            out.arch = Some(rest.trim().to_string());
            continue;
        }
        // Format: "0x0000000000401234: pop rdi; ret;"
        if let Some((addr, instr)) = trim.split_once(": ") {
            let addr_clean = addr.trim();
            if addr_clean.starts_with("0x")
                && addr_clean.len() > 2
                && addr_clean[2..].chars().all(|c| c.is_ascii_hexdigit())
            {
                out.gadgets.push(Gadget {
                    address: addr_clean.to_string(),
                    instructions: instr.trim().trim_end_matches(';').to_string(),
                    bytes: None,
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_gadget_listing() {
        let sample = "\
Gadgets\n\
=======\n\
\n\
Arch: x86_64\n\
0x0000000000401234: pop rdi; ret;\n\
0x0000000000401abc: pop rsi; pop r15; ret;\n\
\n\
2 gadgets found\n";
        let r = parse_ropper_text(sample);
        assert_eq!(r.arch.as_deref(), Some("x86_64"));
        assert_eq!(r.gadgets.len(), 2);
        assert_eq!(r.gadgets[0].address, "0x0000000000401234");
        assert_eq!(r.gadgets[0].instructions, "pop rdi; ret");
    }
}

use crate::agent::tools::schema::append_output_schema;
use rig::completion::ToolDefinition;
use rig::tool::Tool;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::agent::tools::ToolError;
use crate::agent::tools::sec::{
    SecContext, check_targets_in_scope, preflight, record, require_policy, run_shell, shq,
};

#[derive(Deserialize, JsonSchema)]
pub struct BloodhoundArgs {
    pub domain: String,
    pub domain_controller: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub hashes: Option<String>,
    #[serde(default)]
    pub collection_method: Option<String>,
    #[serde(default)]
    pub output_dir: Option<String>,
    #[serde(default)]
    pub use_kerberos: Option<bool>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct BloodhoundOutput {
    pub output_dir: String,
    pub files: Vec<String>,
    pub counts: BTreeMap<String, u64>,
    pub raw_command: String,
    pub exit_code: i32,
    pub stdout_tail: String,
    pub stderr_tail: String,
}

pub struct BloodhoundTool {
    ctx: SecContext,
}

impl BloodhoundTool {
    pub fn new(ctx: SecContext) -> Self {
        BloodhoundTool { ctx }
    }
}

impl Tool for BloodhoundTool {
    const NAME: &'static str = "bloodhound_python";
    type Error = ToolError;
    type Args = BloodhoundArgs;
    type Output = BloodhoundOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: append_output_schema::<BloodhoundOutput>(
                "Run bloodhound-python (BloodHound.py) AD collector against an in-scope \
                          domain controller. Writes JSON files (users, computers, groups, \
                          domains, gpos, ous) and returns per-category object counts.",
            ),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "domain": { "type": "string", "description": "FQDN of the AD domain" },
                    "domain_controller": { "type": "string",
                                           "description": "Hostname or IP of the DC (must be in scope)" },
                    "username": { "type": "string" },
                    "password": { "type": "string" },
                    "hashes": { "type": "string", "description": "LM:NT for pass-the-hash" },
                    "collection_method": { "type": "string",
                                           "description": "Default 'All'. Examples: Default, Group, LocalAdmin, RDP, DCOnly, ACL, Trusts, Session" },
                    "output_dir": { "type": "string",
                                    "description": "Directory to write JSON outputs (default: ./bloodhound-<domain>)" },
                    "use_kerberos": { "type": "boolean" },
                    "timeout_secs": { "type": "integer" }
                },
                "required": ["domain", "domain_controller"]
            }),
        }
    }

    async fn call(&self, args: BloodhoundArgs) -> Result<BloodhoundOutput, ToolError> {
        let policy = require_policy(&self.ctx)?;
        let dc = args.domain_controller.clone();
        check_targets_in_scope(&policy, std::slice::from_ref(&dc))?;
        preflight("bloodhound-python").await?;

        let output_dir = args
            .output_dir
            .clone()
            .unwrap_or_else(|| format!("./bloodhound-{}", args.domain));
        if std::fs::create_dir_all(&output_dir).is_err() {
            return Err(ToolError::Msg(format!(
                "bloodhound: failed to create output_dir '{}'",
                output_dir
            )));
        }

        let collection = args
            .collection_method
            .clone()
            .unwrap_or_else(|| "All".to_string());

        let mut argv: Vec<String> = vec![
            "bloodhound-python".into(),
            "-d".into(),
            args.domain.clone(),
            "-dc".into(),
            args.domain_controller.clone(),
            "-c".into(),
            collection,
            "--zip".into(),
        ];
        if let Some(u) = &args.username {
            argv.push("-u".into());
            argv.push(u.clone());
        }
        if let Some(p) = &args.password {
            argv.push("-p".into());
            argv.push(p.clone());
        }
        if let Some(h) = &args.hashes {
            argv.push("--hashes".into());
            argv.push(h.clone());
        }
        if args.use_kerberos.unwrap_or(false) {
            argv.push("-k".into());
        }

        // bloodhound-python writes to cwd. Run it in output_dir.
        let cmd_str = argv.iter().map(|s| shq(s)).collect::<Vec<_>>().join(" ");
        let cmd = format!("cd {} && {}", shq(&output_dir), cmd_str);

        let outcome = run_shell(&self.ctx, &cmd, args.timeout_secs.unwrap_or(1800)).await?;

        let (files, counts) = scan_outputs(&output_dir);
        let summary = format!(
            "bloodhound: {} file(s), {} total objects",
            files.len(),
            counts.values().sum::<u64>()
        );
        record(&self.ctx, "bloodhound_python", &argv, &outcome, &summary);

        Ok(BloodhoundOutput {
            output_dir,
            files,
            counts,
            raw_command: cmd,
            exit_code: outcome.exit_code,
            stdout_tail: tail(&outcome.stdout, 2000),
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

fn scan_outputs(dir: &str) -> (Vec<String>, BTreeMap<String, u64>) {
    let mut files: Vec<String> = Vec::new();
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return (files, counts),
    };
    for entry in entries.flatten() {
        let path: PathBuf = entry.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        if !name.ends_with(".json") {
            continue;
        }
        files.push(name.clone());
        if let Some(category) = category_from_name(&name) {
            if let Ok(text) = std::fs::read_to_string(&path) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                    let n = v
                        .get("data")
                        .and_then(|x| x.as_array())
                        .map(|a| a.len() as u64)
                        .unwrap_or(0);
                    *counts.entry(category).or_insert(0) += n;
                }
            }
        }
    }
    files.sort();
    (files, counts)
}

fn category_from_name(name: &str) -> Option<String> {
    for cat in [
        "users",
        "computers",
        "groups",
        "domains",
        "gpos",
        "ous",
        "containers",
    ] {
        if name.contains(cat) {
            return Some(cat.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn scan_outputs_reads_data_arrays() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let p = dir.path();
        for (file, count) in [("users_20240101.json", 3), ("computers_20240101.json", 2)] {
            let mut f = std::fs::File::create(p.join(file)).unwrap();
            let items: Vec<serde_json::Value> =
                (0..count).map(|i| serde_json::json!({"i": i})).collect();
            writeln!(f, "{}", serde_json::json!({"data": items})).unwrap();
        }
        let (files, counts) = scan_outputs(p.to_str().unwrap());
        assert_eq!(files.len(), 2);
        assert_eq!(counts.get("users"), Some(&3));
        assert_eq!(counts.get("computers"), Some(&2));
    }

    #[test]
    fn category_lookup() {
        assert_eq!(category_from_name("users_x.json").as_deref(), Some("users"));
        assert_eq!(category_from_name("gpos_x.json").as_deref(), Some("gpos"));
        assert_eq!(category_from_name("random.json"), None);
    }
}

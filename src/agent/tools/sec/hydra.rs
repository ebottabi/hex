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
pub struct HydraArgs {
    pub target: String,
    pub service: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub user_list: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub password_list: Option<String>,
    #[serde(default)]
    pub tasks: Option<u32>,
    #[serde(default)]
    pub stop_on_first: Option<bool>,
    #[serde(default)]
    pub service_path: Option<String>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct HydraCred {
    pub host: String,
    pub port: Option<u16>,
    pub service: String,
    pub login: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct HydraOutput {
    pub credentials: Vec<HydraCred>,
    pub attempts: Option<u64>,
    pub raw_command: String,
    pub exit_code: i32,
    pub stderr_tail: String,
}

pub struct HydraTool {
    ctx: SecContext,
}

impl HydraTool {
    pub fn new(ctx: SecContext) -> Self {
        HydraTool { ctx }
    }
}

impl Tool for HydraTool {
    const NAME: &'static str = "hydra";
    type Error = ToolError;
    type Args = HydraArgs;
    type Output = HydraOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: append_output_schema::<HydraOutput>("Online password attack via hydra. Supports ssh, ftp, http-get, \
                          http-post-form, smb, rdp, mysql, postgres, etc. Returns typed found \
                          credentials. Target host must be in scope and the engagement RoE must \
                          permit online password attempts."),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string" },
                    "service": { "type": "string",
                                 "description": "ssh|ftp|http-get|http-post-form|smb|rdp|mysql|postgres|..." },
                    "port": { "type": "integer" },
                    "user": { "type": "string", "description": "Single login (-l)" },
                    "user_list": { "type": "string", "description": "Path to login list (-L)" },
                    "password": { "type": "string", "description": "Single password (-p)" },
                    "password_list": { "type": "string", "description": "Path to password list (-P)" },
                    "tasks": { "type": "integer", "description": "Parallel tasks (-t), default 4" },
                    "stop_on_first": { "type": "boolean", "description": "Stop after first valid (-f)" },
                    "service_path": { "type": "string",
                                      "description": "Required for http-form services, e.g. '/login.php:user=^USER^&pass=^PASS^:F=invalid'" },
                    "timeout_secs": { "type": "integer" }
                },
                "required": ["target", "service"]
            }),
        }
    }

    async fn call(&self, args: HydraArgs) -> Result<HydraOutput, ToolError> {
        let policy = require_policy(&self.ctx)?;
        check_targets_in_scope(&policy, std::slice::from_ref(&args.target))?;
        preflight("hydra").await?;

        let mut argv: Vec<String> = vec!["hydra".into()];
        if let Some(u) = &args.user {
            argv.push("-l".into());
            argv.push(u.clone());
        } else if let Some(ul) = &args.user_list {
            argv.push("-L".into());
            argv.push(ul.clone());
        }
        if let Some(p) = &args.password {
            argv.push("-p".into());
            argv.push(p.clone());
        } else if let Some(pl) = &args.password_list {
            argv.push("-P".into());
            argv.push(pl.clone());
        }
        if let Some(t) = args.tasks {
            argv.push("-t".into());
            argv.push(t.to_string());
        }
        if args.stop_on_first.unwrap_or(true) {
            argv.push("-f".into());
        }
        if let Some(port) = args.port {
            argv.push("-s".into());
            argv.push(port.to_string());
        }
        argv.push("-I".into());
        argv.push(args.target.clone());

        let service_arg = if let Some(sp) = &args.service_path {
            format!("{}{}", args.service, sp)
        } else {
            args.service.clone()
        };
        argv.push(service_arg);

        let cmd = argv.iter().map(|s| shq(s)).collect::<Vec<_>>().join(" ");
        let outcome = run_shell(&self.ctx, &cmd, args.timeout_secs.unwrap_or(900)).await?;
        let credentials = parse_hydra_output(&outcome.stdout, &args.target, &args.service);

        let summary = format!("hydra: {} credential(s) found", credentials.len());
        record(&self.ctx, "hydra", &argv, &outcome, &summary);

        Ok(HydraOutput {
            credentials,
            attempts: extract_attempts(&outcome.stdout),
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

fn extract_attempts(stdout: &str) -> Option<u64> {
    for line in stdout.lines() {
        if let Some(idx) = line.find("tries:") {
            let after = &line[idx + 6..];
            let n: String = after
                .chars()
                .skip_while(|c| !c.is_ascii_digit())
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if let Ok(v) = n.parse::<u64>() {
                return Some(v);
            }
        }
    }
    None
}

pub fn parse_hydra_output(
    stdout: &str,
    default_host: &str,
    default_service: &str,
) -> Vec<HydraCred> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        // Example: [22][ssh] host: 10.0.0.1   login: admin   password: hunter2
        if !line.starts_with('[') {
            continue;
        }
        let close = match line.find(']') {
            Some(i) => i,
            None => continue,
        };
        let port: Option<u16> = line[1..close].parse().ok();
        let rest = &line[close + 1..];
        let svc_close = match rest.find(']') {
            Some(i) => i,
            None => continue,
        };
        let service = rest[1..svc_close].to_string();
        let after = &rest[svc_close + 1..];

        let host = extract_field(after, "host:").unwrap_or_else(|| default_host.to_string());
        let login = match extract_field(after, "login:") {
            Some(v) => v,
            None => continue,
        };
        let password = match extract_field(after, "password:") {
            Some(v) => v,
            None => continue,
        };
        out.push(HydraCred {
            host,
            port,
            service: if service.is_empty() {
                default_service.to_string()
            } else {
                service
            },
            login,
            password,
        });
    }
    out
}

fn extract_field(s: &str, key: &str) -> Option<String> {
    let idx = s.find(key)?;
    let after = &s[idx + key.len()..];
    let trimmed = after.trim_start();
    // Field ends at the next whitespace+known-key or end of line.
    let mut end = trimmed.len();
    for k in ["host:", "login:", "password:"] {
        if k == key {
            continue;
        }
        if let Some(p) = trimmed.find(k) {
            end = end.min(p);
        }
    }
    Some(trimmed[..end].trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_successful_login_lines() {
        let sample = "[DATA] attacking ssh://10.0.0.1:22\n\
                      [22][ssh] host: 10.0.0.1   login: admin   password: hunter2\n\
                      [80][http-get] host: target.local   login: root   password: toor\n\
                      [STATUS] tries: 12 try/login: 1\n";
        let r = parse_hydra_output(sample, "10.0.0.1", "ssh");
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].port, Some(22));
        assert_eq!(r[0].login, "admin");
        assert_eq!(r[0].password, "hunter2");
        assert_eq!(r[1].service, "http-get");
        assert_eq!(r[1].host, "target.local");
    }

    #[test]
    fn extract_attempts_works() {
        let s = "[STATUS] 100.00 tries: 250 try/login: 1\n";
        assert_eq!(extract_attempts(s), Some(250));
    }
}

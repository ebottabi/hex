use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};

use crate::agent::tools::ToolError;
use crate::agent::tools::sec::{
    SecContext, check_targets_in_scope, preflight, record, require_policy, run_shell, shq,
};

#[derive(Deserialize)]
pub struct NxcArgs {
    pub protocol: String,
    pub targets: Vec<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub hash: Option<String>,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub module: Option<String>,
    #[serde(default)]
    pub local_auth: Option<bool>,
    #[serde(default)]
    pub kerberos: Option<bool>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NxcResult {
    pub protocol: String,
    pub host: String,
    pub port: Option<u16>,
    pub hostname: Option<String>,
    pub status: String,
    pub pwn3d: bool,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NxcOutput {
    pub results: Vec<NxcResult>,
    pub raw_command: String,
    pub exit_code: i32,
    pub stderr_tail: String,
}

pub struct NxcTool {
    ctx: SecContext,
}

impl NxcTool {
    pub fn new(ctx: SecContext) -> Self {
        NxcTool { ctx }
    }
}

impl Tool for NxcTool {
    const NAME: &'static str = "nxc";
    type Error = ToolError;
    type Args = NxcArgs;
    type Output = NxcOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: "NetExec (nxc / crackmapexec) — authenticate, enumerate, and run modules \
                          across SMB/WinRM/LDAP/MSSQL/SSH/RDP/FTP. Returns typed per-host results \
                          with success/info/fail status and Pwn3d! detection. Targets must be in \
                          scope."
                .to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "protocol": { "type": "string",
                                  "description": "smb | winrm | ldap | mssql | ssh | rdp | ftp" },
                    "targets": { "type": "array", "items": {"type": "string"} },
                    "username": { "type": "string" },
                    "password": { "type": "string" },
                    "hash": { "type": "string", "description": "NTLM hash (uses -H)" },
                    "domain": { "type": "string" },
                    "module": { "type": "string", "description": "Module to run (-M)" },
                    "local_auth": { "type": "boolean", "description": "--local-auth" },
                    "kerberos": { "type": "boolean", "description": "-k (use Kerberos)" },
                    "timeout_secs": { "type": "integer" }
                },
                "required": ["protocol", "targets"]
            }),
        }
    }

    async fn call(&self, args: NxcArgs) -> Result<NxcOutput, ToolError> {
        let policy = require_policy(&self.ctx)?;
        if args.targets.is_empty() {
            return Err(ToolError::Msg("nxc: targets required".into()));
        }
        check_targets_in_scope(&policy, &args.targets)?;
        let binary = if which_available("nxc").await { "nxc" } else { "crackmapexec" };
        preflight(binary).await?;

        let mut argv: Vec<String> = vec![binary.into(), args.protocol.clone()];
        for t in &args.targets {
            argv.push(t.clone());
        }
        if let Some(u) = &args.username {
            argv.push("-u".into());
            argv.push(u.clone());
        }
        if let Some(p) = &args.password {
            argv.push("-p".into());
            argv.push(p.clone());
        }
        if let Some(h) = &args.hash {
            argv.push("-H".into());
            argv.push(h.clone());
        }
        if let Some(d) = &args.domain {
            argv.push("-d".into());
            argv.push(d.clone());
        }
        if let Some(m) = &args.module {
            argv.push("-M".into());
            argv.push(m.clone());
        }
        if args.local_auth.unwrap_or(false) {
            argv.push("--local-auth".into());
        }
        if args.kerberos.unwrap_or(false) {
            argv.push("-k".into());
        }

        let cmd = argv.iter().map(|s| shq(s)).collect::<Vec<_>>().join(" ");
        let outcome = run_shell(&self.ctx, &cmd, args.timeout_secs.unwrap_or(600)).await?;
        let results = parse_nxc_output(&outcome.stdout, &args.protocol);

        let pwn3d = results.iter().filter(|r| r.pwn3d).count();
        let summary = format!("nxc: {} line(s), {} pwn3d", results.len(), pwn3d);
        record(&self.ctx, "nxc", &argv, &outcome, &summary);

        Ok(NxcOutput {
            results,
            raw_command: cmd,
            exit_code: outcome.exit_code,
            stderr_tail: tail(&outcome.stderr, 500),
        })
    }
}

async fn which_available(binary: &str) -> bool {
    tokio::process::Command::new("which")
        .arg(binary)
        .output()
        .await
        .map(|o| o.status.success() && !o.stdout.is_empty())
        .unwrap_or(false)
}

fn tail(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        s[s.len() - n..].to_string()
    }
}

/// Strip ANSI escape sequences (CSI). Used because nxc colorises stdout by default.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                while let Some(nc) = chars.next() {
                    if ('@'..='~').contains(&nc) {
                        break;
                    }
                }
                continue;
            }
        }
        out.push(c);
    }
    out
}

pub fn parse_nxc_output(stdout: &str, default_proto: &str) -> Vec<NxcResult> {
    let cleaned = strip_ansi(stdout);
    let mut out = Vec::new();
    for line in cleaned.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        // Typical nxc line:
        //   SMB         10.0.0.1   445    DC01      [+] DOMAIN\user:pass (Pwn3d!)
        //   SMB         10.0.0.1   445    DC01      [*] Windows 10 ...
        //   WINRM       10.0.0.2   5985   SRV01     [-] DOMAIN\user:wrong
        let mut fields = line.split_whitespace();
        let proto = fields.next().unwrap_or("").to_string();
        if proto.is_empty()
            || !proto
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        {
            continue;
        }
        let host = fields.next().unwrap_or("").to_string();
        let port = fields.next().and_then(|s| s.parse::<u16>().ok());
        let hostname_raw = fields.next().unwrap_or("");
        let hostname = if hostname_raw.starts_with('[') {
            None
        } else {
            Some(hostname_raw.to_string())
        };

        // Find the [X] marker.
        let rest_start = if hostname.is_some() {
            line.find(hostname_raw)
                .map(|i| i + hostname_raw.len())
                .unwrap_or(0)
        } else {
            line.find(hostname_raw).unwrap_or(0)
        };
        let rest = line[rest_start..].trim_start();
        let (status, message) = if let Some(s) = rest.strip_prefix("[+]") {
            ("success".to_string(), s.trim().to_string())
        } else if let Some(s) = rest.strip_prefix("[-]") {
            ("fail".to_string(), s.trim().to_string())
        } else if let Some(s) = rest.strip_prefix("[*]") {
            ("info".to_string(), s.trim().to_string())
        } else if let Some(s) = rest.strip_prefix("[!]") {
            ("warn".to_string(), s.trim().to_string())
        } else {
            continue;
        };

        let pwn3d = message.contains("Pwn3d!") || message.contains("(Pwn3d!)");
        out.push(NxcResult {
            protocol: if proto.is_empty() {
                default_proto.to_ascii_uppercase()
            } else {
                proto
            },
            host,
            port,
            hostname,
            status,
            pwn3d,
            message,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_smb_lines() {
        let sample = "SMB         10.0.0.1   445    DC01      [*] Windows Server 2019\n\
                      SMB         10.0.0.1   445    DC01      [+] CORP\\administrator:P@ss (Pwn3d!)\n\
                      SMB         10.0.0.2   445    SRV01     [-] CORP\\bob:wrong STATUS_LOGON_FAILURE\n";
        let r = parse_nxc_output(sample, "smb");
        assert_eq!(r.len(), 3);
        assert_eq!(r[0].status, "info");
        assert_eq!(r[0].protocol, "SMB");
        assert_eq!(r[0].host, "10.0.0.1");
        assert_eq!(r[0].port, Some(445));
        assert_eq!(r[0].hostname.as_deref(), Some("DC01"));
        assert_eq!(r[1].status, "success");
        assert!(r[1].pwn3d);
        assert_eq!(r[2].status, "fail");
    }

    #[test]
    fn strips_ansi_color_escapes() {
        let raw = "\x1b[34mSMB\x1b[0m         10.0.0.1   445    DC01      \x1b[32m[+]\x1b[0m hit\n";
        let r = parse_nxc_output(raw, "smb");
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].status, "success");
        assert_eq!(r[0].message, "hit");
    }
}

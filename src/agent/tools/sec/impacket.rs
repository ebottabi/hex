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
pub struct ImpacketArgs {
    pub action: String,
    pub target: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub hashes: Option<String>,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub dc_ip: Option<String>,
    #[serde(default)]
    pub users_file: Option<String>,
    #[serde(default)]
    pub extra_args: Option<Vec<String>>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct DumpedCredential {
    pub user: String,
    pub domain: Option<String>,
    pub rid: Option<u64>,
    pub lm_hash: Option<String>,
    pub nt_hash: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct SpnEntry {
    pub spn: String,
    pub user: Option<String>,
    pub kerberoast_hash: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct AsRepEntry {
    pub user: String,
    pub asrep_hash: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ImpacketOutput {
    pub action: String,
    pub credentials: Vec<DumpedCredential>,
    pub spns: Vec<SpnEntry>,
    pub asrep: Vec<AsRepEntry>,
    pub raw_command: String,
    pub exit_code: i32,
    pub stdout_tail: String,
    pub stderr_tail: String,
}

pub struct ImpacketTool {
    ctx: SecContext,
}

impl ImpacketTool {
    pub fn new(ctx: SecContext) -> Self {
        ImpacketTool { ctx }
    }
}

impl Tool for ImpacketTool {
    const NAME: &'static str = "impacket";
    type Error = ToolError;
    type Args = ImpacketArgs;
    type Output = ImpacketOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: append_output_schema::<ImpacketOutput>(
                "Impacket suite dispatcher. Supported actions: secretsdump (dump NTDS / \
                          LSA / SAM hashes), getuserspns (Kerberoasting), getnpusers (ASREP \
                          roasting). Returns typed credentials / SPN tickets / ASREP hashes. \
                          Target host must be in scope.",
            ),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "action": { "type": "string",
                                "description": "secretsdump | getuserspns | getnpusers" },
                    "target": { "type": "string",
                                "description": "Target host or DC (IP or FQDN)" },
                    "username": { "type": "string" },
                    "password": { "type": "string" },
                    "hashes": { "type": "string",
                                "description": "LM:NT pass-the-hash, used with -hashes" },
                    "domain": { "type": "string" },
                    "dc_ip": { "type": "string" },
                    "users_file": { "type": "string", "description": "Path to users list (getnpusers)" },
                    "extra_args": { "type": "array", "items": {"type": "string"} },
                    "timeout_secs": { "type": "integer" }
                },
                "required": ["action", "target"]
            }),
        }
    }

    async fn call(&self, args: ImpacketArgs) -> Result<ImpacketOutput, ToolError> {
        let policy = require_policy(&self.ctx)?;
        let host = args.target.clone();
        check_targets_in_scope(&policy, std::slice::from_ref(&host))?;

        let (binary, target_arg) = match args.action.to_ascii_lowercase().as_str() {
            "secretsdump" => ("secretsdump.py", impacket_target(&args, false)),
            "getuserspns" => ("GetUserSPNs.py", impacket_target(&args, true)),
            "getnpusers" => ("GetNPUsers.py", impacket_target(&args, true)),
            other => {
                return Err(ToolError::Msg(format!(
                    "impacket: unknown action '{}'. Supported: secretsdump, getuserspns, getnpusers",
                    other
                )));
            }
        };
        preflight(binary).await?;

        let mut argv: Vec<String> = vec![binary.into(), target_arg];
        if let Some(h) = &args.hashes {
            argv.push("-hashes".into());
            argv.push(h.clone());
        }
        if let Some(dc) = &args.dc_ip {
            argv.push("-dc-ip".into());
            argv.push(dc.clone());
        }
        if args.action.eq_ignore_ascii_case("getuserspns") {
            argv.push("-request".into());
        }
        if args.action.eq_ignore_ascii_case("getnpusers") {
            argv.push("-no-pass".into());
            argv.push("-request".into());
            if let Some(uf) = &args.users_file {
                argv.push("-usersfile".into());
                argv.push(uf.clone());
            }
        }
        if let Some(extra) = &args.extra_args {
            for e in extra {
                argv.push(e.clone());
            }
        }

        let cmd = argv.iter().map(|s| shq(s)).collect::<Vec<_>>().join(" ");
        let outcome = run_shell(&self.ctx, &cmd, args.timeout_secs.unwrap_or(600)).await?;

        let (credentials, spns, asrep) = match args.action.to_ascii_lowercase().as_str() {
            "secretsdump" => (parse_secretsdump(&outcome.stdout), Vec::new(), Vec::new()),
            "getuserspns" => (Vec::new(), parse_getuserspns(&outcome.stdout), Vec::new()),
            "getnpusers" => (Vec::new(), Vec::new(), parse_getnpusers(&outcome.stdout)),
            _ => (Vec::new(), Vec::new(), Vec::new()),
        };

        let summary = format!(
            "impacket/{}: {} cred(s), {} spn(s), {} asrep",
            args.action,
            credentials.len(),
            spns.len(),
            asrep.len()
        );
        record(&self.ctx, "impacket", &argv, &outcome, &summary);

        Ok(ImpacketOutput {
            action: args.action,
            credentials,
            spns,
            asrep,
            raw_command: cmd,
            exit_code: outcome.exit_code,
            stdout_tail: tail(&outcome.stdout, 4000),
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

fn impacket_target(args: &ImpacketArgs, require_domain: bool) -> String {
    let user = args.username.clone().unwrap_or_default();
    let domain = args.domain.clone().unwrap_or_default();
    let pass = args.password.clone().unwrap_or_default();

    if require_domain {
        if !pass.is_empty() {
            format!("{}/{}:{}", domain, user, pass)
        } else {
            format!("{}/{}", domain, user)
        }
    } else if !user.is_empty() {
        if !domain.is_empty() && !pass.is_empty() {
            format!("{}/{}:{}@{}", domain, user, pass, args.target)
        } else if !domain.is_empty() {
            format!("{}/{}@{}", domain, user, args.target)
        } else if !pass.is_empty() {
            format!("{}:{}@{}", user, pass, args.target)
        } else {
            format!("{}@{}", user, args.target)
        }
    } else {
        args.target.clone()
    }
}

pub fn parse_secretsdump(stdout: &str) -> Vec<DumpedCredential> {
    // Format: DOMAIN\user:rid:lmhash:nthash:::
    //         user:rid:lmhash:nthash:::
    let mut out = Vec::new();
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 4 {
            continue;
        }
        let lm = parts[2];
        let nt = parts[3];
        if !is_hex_hash(lm) || !is_hex_hash(nt) {
            continue;
        }
        let (domain, user) = if let Some((d, u)) = parts[0].split_once('\\') {
            (Some(d.to_string()), u.to_string())
        } else {
            (None, parts[0].to_string())
        };
        let rid = parts[1].parse::<u64>().ok();
        out.push(DumpedCredential {
            user,
            domain,
            rid,
            lm_hash: Some(lm.to_string()),
            nt_hash: Some(nt.to_string()),
        });
    }
    out
}

fn is_hex_hash(s: &str) -> bool {
    s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit())
}

pub fn parse_getuserspns(stdout: &str) -> Vec<SpnEntry> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("$krb5tgs$") {
            let hash = format!("$krb5tgs${}", rest);
            let user = hash
                .split('$')
                .nth(3)
                .and_then(|s| s.split('*').nth(1))
                .map(|s| s.to_string());
            out.push(SpnEntry {
                spn: String::new(),
                user,
                kerberoast_hash: Some(hash),
            });
        }
    }
    out
}

pub fn parse_getnpusers(stdout: &str) -> Vec<AsRepEntry> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("$krb5asrep$") {
            let hash = format!("$krb5asrep${}", rest);
            let user = hash
                .split('$')
                .nth(3)
                .and_then(|s| s.split('@').next())
                .unwrap_or("")
                .to_string();
            if !user.is_empty() {
                out.push(AsRepEntry {
                    user,
                    asrep_hash: hash,
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
    fn parses_secretsdump_lines() {
        let sample = "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n\
                      CORP\\jdoe:1103:aad3b435b51404eeaad3b435b51404ee:1234567890abcdef1234567890abcdef:::\n\
                      [*] Cleaning up...\n";
        let r = parse_secretsdump(sample);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].user, "Administrator");
        assert_eq!(r[0].rid, Some(500));
        assert_eq!(r[1].domain.as_deref(), Some("CORP"));
        assert_eq!(r[1].user, "jdoe");
    }

    #[test]
    fn parses_getnpusers_asrep() {
        let sample = "[-] User svc_account doesn't have UF_DONT_REQUIRE_PREAUTH set\n\
                      $krb5asrep$23$svc_legacy@CORP.LOCAL:abc123$def456\n";
        let r = parse_getnpusers(sample);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].user, "svc_legacy");
        assert!(r[0].asrep_hash.starts_with("$krb5asrep$"));
    }
}

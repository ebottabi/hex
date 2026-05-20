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
pub struct KerbruteArgs {
    pub mode: String,
    pub domain: String,
    pub domain_controller: String,
    #[serde(default)]
    pub users_file: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub password_file: Option<String>,
    #[serde(default)]
    pub safe: Option<bool>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct KerbruteResult {
    pub kind: String,
    pub user: String,
    pub password: Option<String>,
    pub domain: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct KerbruteOutput {
    pub results: Vec<KerbruteResult>,
    pub raw_command: String,
    pub exit_code: i32,
    pub stdout_tail: String,
    pub stderr_tail: String,
}

pub struct KerbruteTool {
    ctx: SecContext,
}

impl KerbruteTool {
    pub fn new(ctx: SecContext) -> Self {
        KerbruteTool { ctx }
    }
}

impl Tool for KerbruteTool {
    const NAME: &'static str = "kerbrute";
    type Error = ToolError;
    type Args = KerbruteArgs;
    type Output = KerbruteOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: append_output_schema::<KerbruteOutput>("Kerbrute — Kerberos username enumeration and password spraying against \
                          an AD domain controller. Modes: userenum, passwordspray, bruteuser. \
                          DC must be in scope."),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "mode": { "type": "string",
                              "description": "userenum | passwordspray | bruteuser" },
                    "domain": { "type": "string" },
                    "domain_controller": { "type": "string" },
                    "users_file": { "type": "string", "description": "Path to users wordlist" },
                    "user": { "type": "string", "description": "Single username (bruteuser)" },
                    "password": { "type": "string", "description": "Single password (passwordspray)" },
                    "password_file": { "type": "string", "description": "Path to password list (bruteuser)" },
                    "safe": { "type": "boolean", "description": "Skip locked-out accounts (--safe)" },
                    "timeout_secs": { "type": "integer" }
                },
                "required": ["mode", "domain", "domain_controller"]
            }),
        }
    }

    async fn call(&self, args: KerbruteArgs) -> Result<KerbruteOutput, ToolError> {
        let policy = require_policy(&self.ctx)?;
        let dc = args.domain_controller.clone();
        check_targets_in_scope(&policy, std::slice::from_ref(&dc))?;
        preflight("kerbrute").await?;

        let mode = args.mode.to_ascii_lowercase();
        let mut argv: Vec<String> = vec![
            "kerbrute".into(),
            mode.clone(),
            "-d".into(),
            args.domain.clone(),
            "--dc".into(),
            args.domain_controller.clone(),
            "-o".into(),
            "/dev/null".into(),
        ];
        if args.safe.unwrap_or(true) {
            argv.push("--safe".into());
        }

        match mode.as_str() {
            "userenum" => {
                let uf = args.users_file.clone().ok_or_else(|| {
                    ToolError::Msg("kerbrute userenum: users_file required".into())
                })?;
                argv.push(uf);
            }
            "passwordspray" => {
                let uf = args.users_file.clone().ok_or_else(|| {
                    ToolError::Msg("kerbrute passwordspray: users_file required".into())
                })?;
                let pw = args.password.clone().ok_or_else(|| {
                    ToolError::Msg("kerbrute passwordspray: password required".into())
                })?;
                argv.push(uf);
                argv.push(pw);
            }
            "bruteuser" => {
                let pf = args.password_file.clone().ok_or_else(|| {
                    ToolError::Msg("kerbrute bruteuser: password_file required".into())
                })?;
                let u = args
                    .user
                    .clone()
                    .ok_or_else(|| ToolError::Msg("kerbrute bruteuser: user required".into()))?;
                argv.push(pf);
                argv.push(u);
            }
            other => {
                return Err(ToolError::Msg(format!(
                    "kerbrute: unknown mode '{}'. Supported: userenum, passwordspray, bruteuser",
                    other
                )));
            }
        }

        let cmd = argv.iter().map(|s| shq(s)).collect::<Vec<_>>().join(" ");
        let outcome = run_shell(&self.ctx, &cmd, args.timeout_secs.unwrap_or(900)).await?;
        let results = parse_kerbrute_output(&outcome.stdout, &args.domain);

        let summary = format!("kerbrute/{}: {} result(s)", mode, results.len());
        record(&self.ctx, "kerbrute", &argv, &outcome, &summary);

        Ok(KerbruteOutput {
            results,
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

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            while let Some(nc) = chars.next() {
                if ('@'..='~').contains(&nc) {
                    break;
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

pub fn parse_kerbrute_output(stdout: &str, default_domain: &str) -> Vec<KerbruteResult> {
    let cleaned = strip_ansi(stdout);
    let mut out = Vec::new();
    for line in cleaned.lines() {
        let line = line.trim();
        if !line.contains("[+]") {
            continue;
        }
        // Examples:
        //   2024/01/01 12:00:00 >  [+] VALID USERNAME:       jdoe@corp.local
        //   2024/01/01 12:00:00 >  [+] VALID LOGIN:          jdoe@corp.local:Welcome1
        let idx = match line.find("[+]") {
            Some(i) => i,
            None => continue,
        };
        let after = line[idx + 3..].trim();
        if let Some(rest) = after.strip_prefix("VALID USERNAME:") {
            let cred = rest.trim();
            let (user, domain) = split_user_domain(cred, default_domain);
            out.push(KerbruteResult {
                kind: "valid_user".into(),
                user,
                password: None,
                domain: Some(domain),
            });
        } else if let Some(rest) = after.strip_prefix("VALID LOGIN:") {
            let cred = rest.trim();
            let (left, password) = match cred.rsplit_once(':') {
                Some((a, b)) => (a.to_string(), Some(b.to_string())),
                None => (cred.to_string(), None),
            };
            let (user, domain) = split_user_domain(&left, default_domain);
            out.push(KerbruteResult {
                kind: "valid_login".into(),
                user,
                password,
                domain: Some(domain),
            });
        }
    }
    out
}

fn split_user_domain(s: &str, default_domain: &str) -> (String, String) {
    if let Some((u, d)) = s.split_once('@') {
        (u.to_string(), d.to_string())
    } else {
        (s.to_string(), default_domain.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_users() {
        let sample = "2024/01/01 12:00:00 >  [+] VALID USERNAME:       jdoe@corp.local\n\
                      2024/01/01 12:00:01 >  [+] VALID USERNAME:       svc1@corp.local\n";
        let r = parse_kerbrute_output(sample, "corp.local");
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].kind, "valid_user");
        assert_eq!(r[0].user, "jdoe");
        assert_eq!(r[0].domain.as_deref(), Some("corp.local"));
    }

    #[test]
    fn parses_valid_logins() {
        let sample = "2024/01/01 12:00:00 >  [+] VALID LOGIN:          jdoe@corp.local:Welcome1\n";
        let r = parse_kerbrute_output(sample, "corp.local");
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].kind, "valid_login");
        assert_eq!(r[0].user, "jdoe");
        assert_eq!(r[0].password.as_deref(), Some("Welcome1"));
    }
}

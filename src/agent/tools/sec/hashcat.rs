use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};

use crate::agent::tools::ToolError;
use crate::agent::tools::sec::{SecContext, preflight, record, require_policy, run_shell, shq};

#[derive(Deserialize)]
pub struct HashcatArgs {
    pub hash_file: String,
    pub hash_mode: u32,
    #[serde(default)]
    pub attack_mode: Option<u32>,
    #[serde(default)]
    pub wordlist: Option<String>,
    #[serde(default)]
    pub rules: Option<String>,
    #[serde(default)]
    pub mask: Option<String>,
    #[serde(default)]
    pub workload_profile: Option<u8>,
    #[serde(default)]
    pub session: Option<String>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CrackedHash {
    pub hash: String,
    pub plaintext: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HashcatOutput {
    pub cracked: Vec<CrackedHash>,
    pub outfile_path: String,
    pub raw_command: String,
    pub exit_code: i32,
    pub stdout_tail: String,
    pub stderr_tail: String,
}

pub struct HashcatTool {
    ctx: SecContext,
}

impl HashcatTool {
    pub fn new(ctx: SecContext) -> Self {
        HashcatTool { ctx }
    }
}

impl Tool for HashcatTool {
    const NAME: &'static str = "hashcat";
    type Error = ToolError;
    type Args = HashcatArgs;
    type Output = HashcatOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: "Offline password cracker (hashcat). Specify hash mode (-m), attack mode \
                          (0=straight, 1=combination, 3=brute-force, 6=hybrid-wordlist-mask, \
                          7=hybrid-mask-wordlist), and wordlist or mask. Returns hash:plaintext \
                          pairs. Requires an active pentest engagement."
                .to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "hash_file": { "type": "string", "description": "Path to hash list" },
                    "hash_mode": { "type": "integer",
                                   "description": "Hashcat -m mode (e.g. 0=MD5, 1000=NTLM, 5600=NetNTLMv2, 1800=sha512crypt, 22000=WPA-PBKDF2)" },
                    "attack_mode": { "type": "integer", "description": "-a, default 0" },
                    "wordlist": { "type": "string" },
                    "rules": { "type": "string", "description": "Rule file (-r)" },
                    "mask": { "type": "string", "description": "Mask for brute-force (-a 3)" },
                    "workload_profile": { "type": "integer", "description": "-w 1..4" },
                    "session": { "type": "string", "description": "Session name (--session)" },
                    "timeout_secs": { "type": "integer" }
                },
                "required": ["hash_file", "hash_mode"]
            }),
        }
    }

    async fn call(&self, args: HashcatArgs) -> Result<HashcatOutput, ToolError> {
        let _policy = require_policy(&self.ctx)?;
        preflight("hashcat").await?;

        let attack = args.attack_mode.unwrap_or(0);
        let outfile_path = tmp_outfile("hashcat");

        let mut argv: Vec<String> = vec![
            "hashcat".into(),
            "-m".into(),
            args.hash_mode.to_string(),
            "-a".into(),
            attack.to_string(),
            "--quiet".into(),
            "--outfile-format=2".into(),
            "--outfile".into(),
            outfile_path.clone(),
            "--potfile-disable".into(),
            args.hash_file.clone(),
        ];

        match attack {
            0 | 1 => {
                if let Some(w) = &args.wordlist {
                    argv.push(w.clone());
                } else {
                    return Err(ToolError::Msg(
                        "hashcat: wordlist required for attack mode 0/1".into(),
                    ));
                }
                if let Some(w2) = args.wordlist.as_ref().filter(|_| attack == 1).cloned() {
                    argv.push(w2);
                }
            }
            3 => {
                if let Some(m) = &args.mask {
                    argv.push(m.clone());
                } else {
                    return Err(ToolError::Msg(
                        "hashcat: mask required for attack mode 3".into(),
                    ));
                }
            }
            6 => {
                let w = args.wordlist.clone().ok_or_else(|| {
                    ToolError::Msg("hashcat: wordlist required for attack mode 6".into())
                })?;
                let m = args.mask.clone().ok_or_else(|| {
                    ToolError::Msg("hashcat: mask required for attack mode 6".into())
                })?;
                argv.push(w);
                argv.push(m);
            }
            7 => {
                let m = args.mask.clone().ok_or_else(|| {
                    ToolError::Msg("hashcat: mask required for attack mode 7".into())
                })?;
                let w = args.wordlist.clone().ok_or_else(|| {
                    ToolError::Msg("hashcat: wordlist required for attack mode 7".into())
                })?;
                argv.push(m);
                argv.push(w);
            }
            _ => {}
        }

        if let Some(r) = &args.rules {
            argv.push("-r".into());
            argv.push(r.clone());
        }
        if let Some(w) = args.workload_profile {
            argv.push("-w".into());
            argv.push(w.to_string());
        }
        if let Some(s) = &args.session {
            argv.push("--session".into());
            argv.push(s.clone());
        }

        let cmd = argv.iter().map(|s| shq(s)).collect::<Vec<_>>().join(" ");
        let outcome = run_shell(&self.ctx, &cmd, args.timeout_secs.unwrap_or(1800)).await?;

        let cracked = read_hashcat_outfile(&outfile_path);
        let summary = format!("hashcat: {} cracked hash(es)", cracked.len());
        record(&self.ctx, "hashcat", &argv, &outcome, &summary);

        Ok(HashcatOutput {
            cracked,
            outfile_path,
            raw_command: cmd,
            exit_code: outcome.exit_code,
            stdout_tail: tail(&outcome.stdout, 1500),
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

fn tmp_outfile(prefix: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("/tmp/hex-{}-{}.out", prefix, nanos)
}

fn read_hashcat_outfile(path: &str) -> Vec<CrackedHash> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    parse_outfile_format2(&content)
}

pub fn parse_outfile_format2(s: &str) -> Vec<CrackedHash> {
    let mut out = Vec::new();
    for line in s.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        // outfile-format=2 → hash:plain (last : separates)
        if let Some(idx) = line.rfind(':') {
            let (hash, plain) = line.split_at(idx);
            out.push(CrackedHash {
                hash: hash.to_string(),
                plaintext: plain[1..].to_string(),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_format2_lines() {
        let sample = "5f4dcc3b5aa765d61d8327deb882cf99:password\n\
                      098f6bcd4621d373cade4e832627b4f6:test\n";
        let r = parse_outfile_format2(sample);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].hash, "5f4dcc3b5aa765d61d8327deb882cf99");
        assert_eq!(r[0].plaintext, "password");
        assert_eq!(r[1].plaintext, "test");
    }

    #[test]
    fn handles_colon_in_plaintext_via_rsplit() {
        let sample = "abc123:has:colons\n";
        let r = parse_outfile_format2(sample);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].hash, "abc123:has");
        assert_eq!(r[0].plaintext, "colons");
    }
}

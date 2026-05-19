use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};

use crate::agent::tools::ToolError;
use crate::agent::tools::sec::{
    SecContext, check_targets_in_scope, preflight, record, require_policy, run_shell, shq,
};

#[derive(Deserialize)]
pub struct SslyzeArgs {
    pub target: String,
    #[serde(default)]
    pub scans: Option<Vec<String>>,
    #[serde(default)]
    pub starttls: Option<String>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SslyzeCert {
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub not_valid_before: Option<String>,
    pub not_valid_after: Option<String>,
    pub public_key_algorithm: Option<String>,
    pub signature_algorithm: Option<String>,
    pub sha256_fingerprint: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SslyzeProtocolSupport {
    pub protocol: String,
    pub supported: bool,
    pub cipher_count: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SslyzeVuln {
    pub name: String,
    pub is_vulnerable: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SslyzeOutput {
    pub hostname: String,
    pub ip: Option<String>,
    pub port: Option<u16>,
    pub certificates: Vec<SslyzeCert>,
    pub protocols: Vec<SslyzeProtocolSupport>,
    pub vulnerabilities: Vec<SslyzeVuln>,
    pub raw_command: String,
    pub exit_code: i32,
    pub stderr_tail: String,
}

pub struct SslyzeTool {
    ctx: SecContext,
}

impl SslyzeTool {
    pub fn new(ctx: SecContext) -> Self {
        SslyzeTool { ctx }
    }
}

impl Tool for SslyzeTool {
    const NAME: &'static str = "sslyze";
    type Error = ToolError;
    type Args = SslyzeArgs;
    type Output = SslyzeOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: "sslyze TLS scanner. Returns typed certificate chain, protocol support \
                          matrix, and known-vulnerability checks (HEARTBLEED, ROBOT, CCS \
                          injection, OpenSSL renegotiation). Target host must be in scope."
                .to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "host:port (default port 443)" },
                    "scans": { "type": "array", "items": {"type": "string"},
                               "description": "Specific scans to run. Default runs the regular preset." },
                    "starttls": { "type": "string" },
                    "timeout_secs": { "type": "integer" }
                },
                "required": ["target"]
            }),
        }
    }

    async fn call(&self, args: SslyzeArgs) -> Result<SslyzeOutput, ToolError> {
        let policy = require_policy(&self.ctx)?;
        let host = host_only(&args.target);
        check_targets_in_scope(&policy, std::slice::from_ref(&host))?;
        preflight("sslyze").await?;

        let mut argv: Vec<String> = vec![
            "sslyze".into(),
            "--json_out".into(),
            "/dev/stdout".into(),
            "--quiet".into(),
        ];
        if let Some(scans) = &args.scans {
            for s in scans {
                argv.push(format!("--{}", s));
            }
        }
        if let Some(st) = &args.starttls {
            argv.push(format!("--starttls={}", st));
        }
        argv.push(args.target.clone());

        let cmd = argv.iter().map(|s| shq(s)).collect::<Vec<_>>().join(" ");
        let outcome = run_shell(&self.ctx, &cmd, args.timeout_secs.unwrap_or(600)).await?;
        let parsed = parse_sslyze_json(&outcome.stdout);

        let summary = format!(
            "sslyze: {} cert(s), {} protocol(s), {} vuln check(s)",
            parsed.certificates.len(),
            parsed.protocols.len(),
            parsed.vulnerabilities.len()
        );
        record(&self.ctx, "sslyze", &argv, &outcome, &summary);

        Ok(SslyzeOutput {
            hostname: if parsed.hostname.is_empty() {
                host
            } else {
                parsed.hostname
            },
            ip: parsed.ip,
            port: parsed.port,
            certificates: parsed.certificates,
            protocols: parsed.protocols,
            vulnerabilities: parsed.vulnerabilities,
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

fn host_only(s: &str) -> String {
    let no_scheme = s.splitn(2, "://").nth(1).unwrap_or(s);
    let no_path = no_scheme.split('/').next().unwrap_or(no_scheme);
    no_path
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(no_path)
        .to_string()
}

#[derive(Default)]
pub struct ParsedSslyze {
    pub hostname: String,
    pub ip: Option<String>,
    pub port: Option<u16>,
    pub certificates: Vec<SslyzeCert>,
    pub protocols: Vec<SslyzeProtocolSupport>,
    pub vulnerabilities: Vec<SslyzeVuln>,
}

pub fn parse_sslyze_json(s: &str) -> ParsedSslyze {
    let trimmed = s.trim();
    let v: serde_json::Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(_) => return ParsedSslyze::default(),
    };
    let mut out = ParsedSslyze::default();
    let server = v
        .get("server_scan_results")
        .and_then(|x| x.as_array())
        .and_then(|a| a.first());
    let Some(server) = server else {
        return out;
    };
    out.hostname = server
        .get("server_location")
        .and_then(|sl| sl.get("hostname"))
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    out.ip = server
        .get("server_location")
        .and_then(|sl| sl.get("ip_address"))
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());
    out.port = server
        .get("server_location")
        .and_then(|sl| sl.get("port"))
        .and_then(|x| x.as_u64())
        .map(|n| n as u16);

    let scan_result = server.get("scan_result");

    for proto in [
        "ssl_2_0_cipher_suites",
        "ssl_3_0_cipher_suites",
        "tls_1_0_cipher_suites",
        "tls_1_1_cipher_suites",
        "tls_1_2_cipher_suites",
        "tls_1_3_cipher_suites",
    ] {
        let r = match scan_result
            .and_then(|sr| sr.get(proto))
            .and_then(|p| p.get("result"))
        {
            Some(r) => r,
            None => continue,
        };
        let accepted = r
            .get("accepted_cipher_suites")
            .and_then(|x| x.as_array())
            .map(|a| a.len() as u64)
            .unwrap_or(0);
        out.protocols.push(SslyzeProtocolSupport {
            protocol: proto.trim_end_matches("_cipher_suites").to_string(),
            supported: accepted > 0,
            cipher_count: accepted,
        });
    }

    if let Some(deployment) = scan_result
        .and_then(|sr| sr.get("certificate_info"))
        .and_then(|ci| ci.get("result"))
        .and_then(|r| r.get("certificate_deployments"))
        .and_then(|x| x.as_array())
    {
        for dep in deployment {
            if let Some(chain) = dep
                .get("received_certificate_chain")
                .and_then(|x| x.as_array())
            {
                for cert in chain {
                    out.certificates.push(SslyzeCert {
                        subject: cert
                            .get("subject")
                            .and_then(|x| x.as_str())
                            .map(|s| s.to_string()),
                        issuer: cert
                            .get("issuer")
                            .and_then(|x| x.as_str())
                            .map(|s| s.to_string()),
                        not_valid_before: cert
                            .get("not_valid_before")
                            .and_then(|x| x.as_str())
                            .map(|s| s.to_string()),
                        not_valid_after: cert
                            .get("not_valid_after")
                            .and_then(|x| x.as_str())
                            .map(|s| s.to_string()),
                        public_key_algorithm: cert
                            .get("public_key")
                            .and_then(|pk| pk.get("algorithm"))
                            .and_then(|x| x.as_str())
                            .map(|s| s.to_string()),
                        signature_algorithm: cert
                            .get("signature_hash_algorithm")
                            .and_then(|sh| sh.get("name"))
                            .and_then(|x| x.as_str())
                            .map(|s| s.to_string()),
                        sha256_fingerprint: cert
                            .get("fingerprint_sha256")
                            .and_then(|x| x.as_str())
                            .map(|s| s.to_string()),
                    });
                }
            }
        }
    }

    for (name, key) in [
        ("HEARTBLEED", "heartbleed"),
        ("ROBOT", "robot"),
        ("CCS_INJECTION", "openssl_ccs_injection"),
        ("SESSION_RENEGOTIATION", "session_renegotiation"),
    ] {
        let is_vuln = scan_result
            .and_then(|sr| sr.get(key))
            .and_then(|p| p.get("result"))
            .and_then(|r| {
                r.get("is_vulnerable_to_heartbleed")
                    .or_else(|| r.get("robot_result"))
                    .or_else(|| r.get("is_vulnerable_to_ccs_injection"))
                    .or_else(|| r.get("supports_secure_renegotiation"))
            });
        if let Some(v) = is_vuln {
            let flag = match key {
                "session_renegotiation" => v.as_bool().map(|b| !b).unwrap_or(false),
                "robot" => v
                    .as_str()
                    .map(|s| s.contains("VULNERABLE"))
                    .unwrap_or(false),
                _ => v.as_bool().unwrap_or(false),
            };
            out.vulnerabilities.push(SslyzeVuln {
                name: name.to_string(),
                is_vulnerable: flag,
            });
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_protocol_support_and_certs() {
        let sample = r#"{
          "server_scan_results":[{
            "server_location":{"hostname":"example.com","ip_address":"1.2.3.4","port":443},
            "scan_result":{
              "tls_1_2_cipher_suites":{"result":{"accepted_cipher_suites":[{},{},{}]}},
              "tls_1_3_cipher_suites":{"result":{"accepted_cipher_suites":[{}]}},
              "ssl_3_0_cipher_suites":{"result":{"accepted_cipher_suites":[]}},
              "certificate_info":{"result":{"certificate_deployments":[
                {"received_certificate_chain":[
                  {"subject":"CN=example.com","issuer":"CN=Let's Encrypt R3","not_valid_after":"2099-01-01","fingerprint_sha256":"abc"}
                ]}
              ]}},
              "heartbleed":{"result":{"is_vulnerable_to_heartbleed":false}}
            }
          }]
        }"#;
        let r = parse_sslyze_json(sample);
        assert_eq!(r.hostname, "example.com");
        assert_eq!(r.port, Some(443));
        let tls12 = r
            .protocols
            .iter()
            .find(|p| p.protocol == "tls_1_2")
            .unwrap();
        assert!(tls12.supported);
        assert_eq!(tls12.cipher_count, 3);
        let ssl3 = r
            .protocols
            .iter()
            .find(|p| p.protocol == "ssl_3_0")
            .unwrap();
        assert!(!ssl3.supported);
        assert_eq!(r.certificates.len(), 1);
        assert_eq!(r.certificates[0].subject.as_deref(), Some("CN=example.com"));
        let hb = r
            .vulnerabilities
            .iter()
            .find(|v| v.name == "HEARTBLEED")
            .unwrap();
        assert!(!hb.is_vulnerable);
    }
}

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
pub struct NmapArgs {
    pub targets: Vec<String>,
    #[serde(default)]
    pub ports: Option<String>,
    #[serde(default)]
    pub scan_type: Option<String>,
    #[serde(default)]
    pub version_detect: Option<bool>,
    #[serde(default)]
    pub scripts: Option<String>,
    #[serde(default)]
    pub timing: Option<u8>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct Port {
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub service: Option<String>,
    pub version: Option<String>,
    pub product: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct Host {
    pub address: String,
    pub hostname: Option<String>,
    pub status: String,
    pub ports: Vec<Port>,
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct NmapOutput {
    pub hosts: Vec<Host>,
    pub raw_command: String,
    pub exit_code: i32,
    pub stderr_tail: String,
}

pub struct NmapTool {
    ctx: SecContext,
}

impl NmapTool {
    pub fn new(ctx: SecContext) -> Self {
        NmapTool { ctx }
    }
}

impl Tool for NmapTool {
    const NAME: &'static str = "nmap";
    type Error = ToolError;
    type Args = NmapArgs;
    type Output = NmapOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: append_output_schema::<NmapOutput>(
                "Run nmap against in-scope targets. Returns parsed hosts/ports/services. \
                 Requires an active pentest engagement policy and all targets must be in scope.",
            ),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "targets": { "type": "array", "items": {"type": "string"},
                                 "description": "Hosts, IPs, or CIDRs to scan" },
                    "ports": { "type": "string",
                               "description": "Port spec like '22,80,443' or '1-1000' (optional)" },
                    "scan_type": { "type": "string",
                                   "enum": ["syn", "connect", "udp"],
                                   "description": "syn (default, requires root), connect, or udp" },
                    "version_detect": { "type": "boolean",
                                        "description": "Enable -sV service/version detection" },
                    "scripts": { "type": "string",
                                 "description": "NSE scripts (e.g. 'default,vuln'). Optional." },
                    "timing": { "type": "integer",
                                "description": "0-5 (-T0..-T5). Defaults to 4." },
                    "timeout_secs": { "type": "integer",
                                      "description": "Hard timeout in seconds (default 300)" }
                },
                "required": ["targets"]
            }),
        }
    }

    async fn call(&self, args: NmapArgs) -> Result<NmapOutput, ToolError> {
        let policy = require_policy(&self.ctx)?;
        if args.targets.is_empty() {
            return Err(ToolError::Msg("nmap: at least one target required".into()));
        }
        check_targets_in_scope(&policy, &args.targets)?;
        preflight("nmap").await?;

        let mut flags: Vec<String> = Vec::new();
        flags.push("-oX".into());
        flags.push("-".into());
        match args.scan_type.as_deref() {
            Some("connect") => flags.push("-sT".into()),
            Some("udp") => flags.push("-sU".into()),
            Some("syn") | None => flags.push("-sS".into()),
            Some(other) => {
                return Err(ToolError::Msg(format!(
                    "nmap: unknown scan_type '{}'",
                    other
                )));
            }
        }
        if args.version_detect.unwrap_or(false) {
            flags.push("-sV".into());
        }
        if let Some(p) = &args.ports {
            flags.push("-p".into());
            flags.push(p.clone());
        }
        if let Some(s) = &args.scripts {
            flags.push(format!("--script={}", s));
        }
        let timing = args.timing.unwrap_or(4).min(5);
        flags.push(format!("-T{}", timing));

        let mut argv: Vec<String> = vec!["nmap".into()];
        argv.extend(flags.iter().cloned());
        argv.extend(args.targets.iter().cloned());

        let cmd_str = argv.iter().map(|s| shq(s)).collect::<Vec<_>>().join(" ");
        let outcome = run_shell(&self.ctx, &cmd_str, args.timeout_secs.unwrap_or(300)).await?;

        let hosts = parse_nmap_xml(&outcome.stdout).unwrap_or_default();
        let summary = format!(
            "nmap scanned {} target(s), {} host(s) reported",
            args.targets.len(),
            hosts.len()
        );
        record(&self.ctx, "nmap", &argv, &outcome, &summary);

        Ok(NmapOutput {
            hosts,
            raw_command: cmd_str,
            exit_code: outcome.exit_code,
            stderr_tail: tail(&outcome.stderr, 1000),
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

pub fn parse_nmap_xml(xml: &str) -> Result<Vec<Host>, ToolError> {
    use quick_xml::Reader;
    use quick_xml::events::Event;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut hosts: Vec<Host> = Vec::new();
    let mut buf = Vec::new();

    let mut current_host: Option<Host> = None;
    let mut current_port: Option<Port> = None;

    loop {
        match reader.read_event_into(&mut buf) {
            Err(e) => return Err(ToolError::Msg(format!("nmap xml parse: {}", e))),
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                match name.as_str() {
                    "host" => current_host = Some(Host::default()),
                    "address" => {
                        if let Some(host) = current_host.as_mut() {
                            let mut addr = None;
                            for a in e.attributes().flatten() {
                                if a.key.as_ref() == b"addr" {
                                    addr = Some(
                                        String::from_utf8_lossy(a.value.as_ref()).into_owned(),
                                    );
                                }
                            }
                            if let Some(a) = addr {
                                if host.address.is_empty() {
                                    host.address = a;
                                }
                            }
                        }
                    }
                    "hostname" => {
                        if let Some(host) = current_host.as_mut() {
                            for a in e.attributes().flatten() {
                                if a.key.as_ref() == b"name" {
                                    host.hostname = Some(
                                        String::from_utf8_lossy(a.value.as_ref()).into_owned(),
                                    );
                                }
                            }
                        }
                    }
                    "status" => {
                        if let Some(host) = current_host.as_mut() {
                            for a in e.attributes().flatten() {
                                if a.key.as_ref() == b"state" {
                                    host.status =
                                        String::from_utf8_lossy(a.value.as_ref()).into_owned();
                                }
                            }
                        }
                    }
                    "port" => {
                        let mut p = Port::default();
                        for a in e.attributes().flatten() {
                            match a.key.as_ref() {
                                b"portid" => {
                                    p.port = String::from_utf8_lossy(a.value.as_ref())
                                        .parse()
                                        .unwrap_or(0);
                                }
                                b"protocol" => {
                                    p.protocol =
                                        String::from_utf8_lossy(a.value.as_ref()).into_owned();
                                }
                                _ => {}
                            }
                        }
                        current_port = Some(p);
                    }
                    "state" => {
                        if let Some(p) = current_port.as_mut() {
                            for a in e.attributes().flatten() {
                                if a.key.as_ref() == b"state" {
                                    p.state =
                                        String::from_utf8_lossy(a.value.as_ref()).into_owned();
                                }
                            }
                        }
                    }
                    "service" => {
                        if let Some(p) = current_port.as_mut() {
                            for a in e.attributes().flatten() {
                                match a.key.as_ref() {
                                    b"name" => {
                                        p.service = Some(
                                            String::from_utf8_lossy(a.value.as_ref()).into_owned(),
                                        );
                                    }
                                    b"product" => {
                                        p.product = Some(
                                            String::from_utf8_lossy(a.value.as_ref()).into_owned(),
                                        );
                                    }
                                    b"version" => {
                                        p.version = Some(
                                            String::from_utf8_lossy(a.value.as_ref()).into_owned(),
                                        );
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::End(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                match name.as_str() {
                    "port" => {
                        if let (Some(host), Some(port)) =
                            (current_host.as_mut(), current_port.take())
                        {
                            host.ports.push(port);
                        }
                    }
                    "host" => {
                        if let Some(h) = current_host.take() {
                            hosts.push(h);
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
        buf.clear();
    }
    Ok(hosts)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <status state="up" />
    <address addr="93.184.216.34" addrtype="ipv4" />
    <hostnames>
      <hostname name="example.com" type="user" />
    </hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" />
        <service name="http" product="ECAcc" version="(EdgeSuite)" />
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" />
        <service name="https" />
      </port>
    </ports>
  </host>
</nmaprun>"#;

    #[test]
    fn parses_host_and_ports() {
        let hosts = parse_nmap_xml(SAMPLE).expect("parse");
        assert_eq!(hosts.len(), 1);
        let h = &hosts[0];
        assert_eq!(h.address, "93.184.216.34");
        assert_eq!(h.hostname.as_deref(), Some("example.com"));
        assert_eq!(h.status, "up");
        assert_eq!(h.ports.len(), 2);
        assert_eq!(h.ports[0].port, 80);
        assert_eq!(h.ports[0].state, "open");
        assert_eq!(h.ports[0].service.as_deref(), Some("http"));
        assert_eq!(h.ports[1].port, 443);
    }

    #[test]
    fn empty_xml_returns_empty_hosts() {
        let hosts = parse_nmap_xml("<nmaprun></nmaprun>").expect("parse");
        assert!(hosts.is_empty());
    }
}

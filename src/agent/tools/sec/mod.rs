#![allow(dead_code)]

pub mod afl_fuzz;
pub mod bloodhound;
pub mod checksec;
pub mod dnsx;
pub mod ffuf;
pub mod gitleaks;
pub mod hashcat;
pub mod httpx;
pub mod hydra;
pub mod impacket;
pub mod john;
pub mod kerbrute;
pub mod masscan;
pub mod nikto;
pub mod nmap;
pub mod nuclei;
pub mod nxc;
pub mod prowler;
pub mod r2;
pub mod ropper;
pub mod scoutsuite;
pub mod searchsploit;
pub mod semgrep;
pub mod sslyze;
pub mod subfinder;
pub mod suricata_eve;
pub mod testssl;
pub mod trivy;
pub mod tshark;
pub mod whatweb;
pub mod zeek_log;

pub use bloodhound::BloodhoundTool;
pub use checksec::ChecksecTool;
pub use afl_fuzz::AflFuzzTool;
pub use dnsx::DnsxTool;
pub use ffuf::FfufTool;
pub use gitleaks::GitleaksTool;
pub use hashcat::HashcatTool;
pub use httpx::HttpxTool;
pub use hydra::HydraTool;
pub use impacket::ImpacketTool;
pub use john::JohnTool;
pub use kerbrute::KerbruteTool;
pub use masscan::MasscanTool;
pub use nikto::NiktoTool;
pub use nmap::NmapTool;
pub use nuclei::NucleiTool;
pub use nxc::NxcTool;
pub use prowler::ProwlerTool;
pub use r2::R2Tool;
pub use ropper::RopperTool;
pub use scoutsuite::ScoutsuiteTool;
pub use searchsploit::SearchsploitTool;
pub use semgrep::SemgrepTool;
pub use sslyze::SslyzeTool;
pub use subfinder::SubfinderTool;
pub use suricata_eve::SuricataEveTool;
pub use testssl::TestsslTool;
pub use trivy::TrivyTool;
pub use tshark::TsharkTool;
pub use whatweb::WhatwebTool;
pub use zeek_log::ZeekLogTool;

use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex, RwLock};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tokio::time::{Duration, timeout};

use crate::agent::tools::ToolError;
use crate::pentest::engagement::EngagementPolicy;
use crate::permission::ask::AskSender;
use crate::permission::checker::PermCheck;
use crate::sandbox::Sandbox;

/// Shared handle to the currently-active engagement policy.
/// `None` means no pentest session is active and security tools must refuse.
pub type PolicyHandle = Arc<RwLock<Option<EngagementPolicy>>>;

pub fn new_policy_handle() -> PolicyHandle {
    Arc::new(RwLock::new(None))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ToolInvocation {
    pub ts: String,
    pub tool: String,
    pub args: Vec<String>,
    pub exit_code: i32,
    pub summary: String,
}

#[derive(Clone)]
pub struct EvidenceSink {
    inner: Arc<Mutex<Option<PathBuf>>>,
}

impl EvidenceSink {
    pub fn empty() -> Self {
        EvidenceSink {
            inner: Arc::new(Mutex::new(None)),
        }
    }

    pub fn with_path(path: PathBuf) -> Self {
        EvidenceSink {
            inner: Arc::new(Mutex::new(Some(path))),
        }
    }

    pub fn set_path(&self, path: PathBuf) {
        *self.inner.lock().unwrap_or_else(|e| e.into_inner()) = Some(path);
    }

    pub fn clear(&self) {
        *self.inner.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    pub fn log(&self, record: ToolInvocation) {
        let path = {
            let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            guard.clone()
        };
        let Some(path) = path else { return };
        let Ok(line) = serde_json::to_string(&record) else {
            return;
        };
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            let _ = writeln!(f, "{}", line);
        }
    }
}

#[derive(Clone)]
pub struct SecContext {
    pub policy: PolicyHandle,
    pub evidence: EvidenceSink,
    pub sandbox: Sandbox,
    pub permission: Option<PermCheck>,
    pub ask_tx: Option<AskSender>,
}

impl SecContext {
    pub fn new(
        policy: PolicyHandle,
        evidence: EvidenceSink,
        sandbox: Sandbox,
        permission: Option<PermCheck>,
        ask_tx: Option<AskSender>,
    ) -> Self {
        SecContext {
            policy,
            evidence,
            sandbox,
            permission,
            ask_tx,
        }
    }
}

pub fn require_policy(ctx: &SecContext) -> Result<EngagementPolicy, ToolError> {
    let guard = ctx.policy.read().unwrap_or_else(|e| e.into_inner());
    guard.clone().ok_or_else(|| {
        ToolError::Msg(
            "no active pentest engagement policy. Launch with --authorized-pentest \
             or use /pentest <scope> to activate."
                .to_string(),
        )
    })
}

/// Returns Ok if every supplied target is covered by the policy scope.
pub fn check_targets_in_scope(
    policy: &EngagementPolicy,
    targets: &[String],
) -> Result<(), ToolError> {
    for t in targets {
        if !target_in_scope(policy, t) {
            return Err(ToolError::Msg(format!(
                "target '{}' is outside the authorised engagement scope ({}).",
                t,
                policy.target_scope.join(", ")
            )));
        }
    }
    Ok(())
}

fn target_in_scope(policy: &EngagementPolicy, target: &str) -> bool {
    let target = target.trim().trim_end_matches('.').to_ascii_lowercase();
    if target.is_empty() {
        return false;
    }
    let target_ip = IpAddr::from_str(strip_port(&target)).ok();
    let target_cidr = IpNet::from_str(&target).ok();

    for entry in &policy.target_scope {
        let entry = entry.trim().trim_end_matches('.').to_ascii_lowercase();
        if entry.is_empty() {
            continue;
        }
        if entry == target {
            return true;
        }
        if let Ok(net) = IpNet::from_str(&entry) {
            if let Some(ip) = target_ip {
                if net.contains(&ip) {
                    return true;
                }
            }
            if let Some(t_net) = target_cidr {
                if net.contains(&t_net) {
                    return true;
                }
            }
            continue;
        }
        if !looks_like_ip(&entry)
            && (target == entry || target.ends_with(&format!(".{}", entry)))
        {
            return true;
        }
    }
    false
}

fn strip_port(s: &str) -> &str {
    s.rsplit_once(':').map(|(h, _)| h).unwrap_or(s)
}

fn looks_like_ip(s: &str) -> bool {
    IpAddr::from_str(strip_port(s)).is_ok() || IpNet::from_str(s).is_ok()
}

pub async fn preflight(binary: &str) -> Result<(), ToolError> {
    let probe = Command::new("which").arg(binary).output().await;
    match probe {
        Ok(o) if o.status.success() && !o.stdout.is_empty() => Ok(()),
        _ => Err(ToolError::Msg(format!(
            "tool '{}' not found in PATH. Install it (e.g. via apt/brew/pkg manager) and retry.",
            binary
        ))),
    }
}

pub struct ExecOutcome {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

pub async fn run_shell(
    ctx: &SecContext,
    command: &str,
    timeout_secs: u64,
) -> Result<ExecOutcome, ToolError> {
    let fut = ctx.sandbox.wrap_command(command).output();
    let out = timeout(Duration::from_secs(timeout_secs), fut)
        .await
        .map_err(|_| ToolError::Msg(format!("command timed out after {}s", timeout_secs)))??;
    Ok(ExecOutcome {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        exit_code: out.status.code().unwrap_or(-1),
    })
}

pub fn record(ctx: &SecContext, tool: &str, args: &[String], outcome: &ExecOutcome, summary: &str) {
    ctx.evidence.log(ToolInvocation {
        ts: chrono::Utc::now().to_rfc3339(),
        tool: tool.to_string(),
        args: args.to_vec(),
        exit_code: outcome.exit_code,
        summary: summary.to_string(),
    });
}

/// Shell-quote a single arg for safe embedding into a `bash -c` string.
pub fn shq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_with(scope: &[&str]) -> EngagementPolicy {
        EngagementPolicy {
            authorized: true,
            target_scope: scope.iter().map(|s| s.to_string()).collect(),
            rules_of_engagement: vec![],
        }
    }

    #[test]
    fn host_exact_match_in_scope() {
        let p = policy_with(&["example.com"]);
        assert!(target_in_scope(&p, "example.com"));
    }

    #[test]
    fn subdomain_in_scope() {
        let p = policy_with(&["example.com"]);
        assert!(target_in_scope(&p, "api.example.com"));
        assert!(target_in_scope(&p, "deep.api.example.com"));
    }

    #[test]
    fn sibling_domain_not_in_scope() {
        let p = policy_with(&["example.com"]);
        assert!(!target_in_scope(&p, "evil-example.com"));
        assert!(!target_in_scope(&p, "exampleXcom"));
    }

    #[test]
    fn cidr_membership() {
        let p = policy_with(&["10.0.0.0/24"]);
        assert!(target_in_scope(&p, "10.0.0.5"));
        assert!(target_in_scope(&p, "10.0.0.5:443"));
        assert!(!target_in_scope(&p, "10.0.1.5"));
    }

    #[test]
    fn cidr_contains_subnet() {
        let p = policy_with(&["10.0.0.0/16"]);
        assert!(target_in_scope(&p, "10.0.5.0/24"));
        assert!(!target_in_scope(&p, "10.1.0.0/24"));
    }

    #[test]
    fn empty_scope_blocks_everything() {
        let p = policy_with(&[]);
        assert!(!target_in_scope(&p, "example.com"));
    }

    #[test]
    fn check_targets_returns_error_for_outsider() {
        let p = policy_with(&["example.com"]);
        let err = check_targets_in_scope(&p, &["other.com".to_string()]).unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("outside"));
    }

    #[test]
    fn shq_escapes_single_quotes() {
        assert_eq!(shq("a"), "'a'");
        assert_eq!(shq("a'b"), "'a'\\''b'");
    }

    #[test]
    fn evidence_sink_writes_and_reads() {
        let dir = std::env::temp_dir().join(format!(
            "hex-evidence-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("evidence.jsonl");
        let sink = EvidenceSink::with_path(path.clone());
        sink.log(ToolInvocation {
            ts: "now".into(),
            tool: "nmap".into(),
            args: vec!["example.com".into()],
            exit_code: 0,
            summary: "ok".into(),
        });
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("\"tool\":\"nmap\""));
        assert!(body.contains("\"summary\":\"ok\""));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn policy_handle_requires_active_engagement() {
        let handle = new_policy_handle();
        let ctx = SecContext::new(
            handle.clone(),
            EvidenceSink::empty(),
            crate::sandbox::Sandbox::default(),
            None,
            None,
        );
        assert!(require_policy(&ctx).is_err());
        *handle.write().unwrap() = Some(policy_with(&["example.com"]));
        assert!(require_policy(&ctx).is_ok());
    }
}

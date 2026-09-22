use rig::completion::ToolDefinition;
use rig::tool::Tool;
use tokio::time::{Duration, timeout};

use crate::agent::tools::{
    AskSender, BashArgs, PermCheck, ToolError, check_perm, check_perm_allowlisted,
};
use crate::sandbox::Sandbox;

pub struct BashTool {
    pub permission: Option<PermCheck>,
    pub ask_tx: Option<AskSender>,
    pub sandbox: Sandbox,
    /// When true the tool is locked to the conservative permission allowlist:
    /// any command that no explicit rule allows is refused. Set while an
    /// authorized pentest session is active so the general shell cannot reach
    /// the network or run offensive binaries around the scope-checked wrappers.
    pub restrict_to_allowlist: bool,
}

impl BashTool {
    pub fn new(
        permission: Option<PermCheck>,
        ask_tx: Option<AskSender>,
        sandbox: Sandbox,
        restrict_to_allowlist: bool,
    ) -> Self {
        BashTool {
            permission,
            ask_tx,
            sandbox,
            restrict_to_allowlist,
        }
    }
}

impl Tool for BashTool {
    const NAME: &'static str = "bash";

    type Error = ToolError;
    type Args = BashArgs;
    type Output = String;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: "bash".to_string(),
            description: "Execute a bash command in the current working directory. Returns stdout and stderr.".to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "command": { "type": "string", "description": "Bash command to execute" },
                    "timeout": { "type": "integer", "description": "Timeout in seconds (optional)" }
                },
                "required": ["command"]
            }),
        }
    }

    async fn call(&self, args: BashArgs) -> Result<String, ToolError> {
        if self.restrict_to_allowlist {
            check_perm_allowlisted(&self.permission, &self.ask_tx, "bash", &args.command).await?;
        } else {
            check_perm(&self.permission, &self.ask_tx, "bash", &args.command).await?;
        }

        let output = if let Some(secs) = args.timeout {
            timeout(
                Duration::from_secs(secs),
                self.sandbox.wrap_command(&args.command).output(),
            )
            .await
            .map_err(|_| ToolError::Msg("Command timed out".to_string()))?
        } else {
            self.sandbox.wrap_command(&args.command).output().await
        }?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let exit_code = output.status.code().unwrap_or(-1);

        let mut result = String::new();
        if !stdout.is_empty() {
            result.push_str(&stdout);
        }
        if !stderr.is_empty() {
            if !result.is_empty() {
                result.push('\n');
            }
            result.push_str(&stderr);
        }
        if exit_code != 0 {
            result.push_str(&format!("\nExit code: {}", exit_code));
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permission::checker::PermissionChecker;
    use crate::permission::{PermissionConfig, SecurityMode};
    use std::sync::{Arc, Mutex};

    fn permission() -> Option<PermCheck> {
        Some(Arc::new(Mutex::new(PermissionChecker::new(
            &PermissionConfig::default(),
            SecurityMode::Standard,
            Some(std::path::PathBuf::from("/home/user/project")),
        ))))
    }

    fn tool(restrict_to_allowlist: bool) -> BashTool {
        BashTool::new(
            permission(),
            None,
            Sandbox::new(false, "bash"),
            restrict_to_allowlist,
        )
    }

    fn args(command: &str) -> BashArgs {
        BashArgs {
            command: command.to_string(),
            timeout: None,
        }
    }

    #[tokio::test]
    async fn restrict_to_allowlist_refuses_unclassified_command() {
        let err = tool(true).call(args("printf hi")).await.unwrap_err();
        assert!(format!("{err}").contains("Permission denied"));
    }

    #[tokio::test]
    async fn restrict_to_allowlist_refuses_offensive_binary() {
        let err = tool(true).call(args("nmap 10.0.0.5")).await.unwrap_err();
        assert!(format!("{err}").contains("Permission denied"));
    }

    #[tokio::test]
    async fn restrict_to_allowlist_still_allows_allowlisted_command() {
        let out = tool(true).call(args("pwd")).await.unwrap();
        assert!(!out.trim().is_empty());
    }

    #[tokio::test]
    async fn unrestricted_bash_keeps_default_allow() {
        let out = tool(false).call(args("printf hi")).await.unwrap();
        assert_eq!(out, "hi");
    }
}

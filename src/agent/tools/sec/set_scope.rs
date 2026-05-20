use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};

use crate::agent::tools::ToolError;
use crate::agent::tools::sec::SecContext;
use crate::pentest::engagement::EngagementPolicy;

#[derive(Deserialize)]
pub struct SetScopeArgs {
    pub targets: Vec<String>,
    #[serde(default)]
    pub rules_of_engagement: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SetScopeOutput {
    pub ok: bool,
    pub active_scope: Vec<String>,
    pub rules_of_engagement: Vec<String>,
    pub message: String,
}

pub struct SetScopeTool {
    ctx: SecContext,
}

impl SetScopeTool {
    pub fn new(ctx: SecContext) -> Self {
        SetScopeTool { ctx }
    }
}

impl Tool for SetScopeTool {
    const NAME: &'static str = "set_engagement_scope";
    type Error = ToolError;
    type Args = SetScopeArgs;
    type Output = SetScopeOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: "Set or update the authorized engagement scope for this session. Call \
                          this when the user grants targets in natural language (e.g. 'the target \
                          is api.example.com' or 'scope: 10.0.0.0/24'). Once set, every subsequent \
                          security tool call (nmap, httpx, nuclei, searchsploit, ...) will use \
                          this scope. Pass an array of hostnames, IPs, or CIDRs. Idempotent — \
                          calling again replaces the scope."
                .to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "targets": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Authorized targets: hostnames, IPs, or CIDR blocks."
                    },
                    "rules_of_engagement": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Optional additional rules of engagement strings."
                    }
                },
                "required": ["targets"]
            }),
        }
    }

    async fn call(&self, args: SetScopeArgs) -> Result<SetScopeOutput, ToolError> {
        let policy = EngagementPolicy::from_parts(&args.targets, &args.rules_of_engagement)
            .map_err(|e| ToolError::Msg(format!("invalid scope: {e}")))?;
        {
            let h = self.ctx.policy.clone();
            *h.write().unwrap_or_else(|e| e.into_inner()) = Some(policy.clone());
        }
        Ok(SetScopeOutput {
            ok: true,
            active_scope: policy.target_scope.clone(),
            rules_of_engagement: policy.rules_of_engagement.clone(),
            message: format!(
                "engagement scope active: {}",
                policy.target_scope.join(", ")
            ),
        })
    }
}

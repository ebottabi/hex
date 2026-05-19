pub mod builder;
pub mod prompt;
pub mod runner;
pub mod tools;

#[derive(Debug, Clone)]
pub struct AgentIdentity {
    pub name: String,
    pub version: String,
}

impl AgentIdentity {
    pub fn default_identity() -> Self {
        AgentIdentity {
            name: "hex".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

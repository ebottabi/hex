pub mod ask;
pub mod checker;

use std::collections::HashMap;

use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Ask,
    Deny,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ToolPerm {
    Simple(Action),
    Granular(HashMap<String, Action>),
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PermissionConfig {
    #[serde(rename = "*")]
    pub default: Option<Action>,
    pub bash: Option<ToolPerm>,
    pub read: Option<ToolPerm>,
    pub write: Option<ToolPerm>,
    pub edit: Option<ToolPerm>,
    pub grep: Option<ToolPerm>,
    pub find_files: Option<ToolPerm>,
    pub list_dir: Option<ToolPerm>,
    pub write_todo_list: Option<ToolPerm>,
    pub external_directory: Option<HashMap<String, Action>>,
    pub doom_loop: Option<Action>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityMode {
    Standard,
    Restrictive,
    Accept,
    Yolo,
}

impl std::fmt::Display for SecurityMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityMode::Standard => f.write_str("standard"),
            SecurityMode::Restrictive => f.write_str("restrictive"),
            SecurityMode::Accept => f.write_str("accept"),
            SecurityMode::Yolo => f.write_str("yolo"),
        }
    }
}

pub fn default_bash_rules() -> Vec<(&'static str, Action)> {
    vec![
        ("ls **", Action::Allow),
        ("cd **", Action::Allow),
        ("pwd", Action::Allow),
        ("echo **", Action::Allow),
        ("cat **", Action::Allow),
        ("head **", Action::Allow),
        ("tail **", Action::Allow),
        ("grep **", Action::Allow),
        ("find **", Action::Allow),
        ("git status", Action::Allow),
        ("git log **", Action::Allow),
        ("git diff **", Action::Allow),
        ("git show **", Action::Allow),
        ("cargo check", Action::Allow),
        ("cargo build", Action::Allow),
        ("cargo test", Action::Allow),
        ("cargo fmt", Action::Allow),
        ("rm -rf /**", Action::Deny),
        ("sudo rm -rf /**", Action::Deny),
        ("dd **", Action::Deny),
        ("mkfs **", Action::Deny),
    ]
}

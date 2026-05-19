use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::permission::{Action, PermissionConfig, SecurityMode, ToolPerm, default_bash_rules};

pub type PermCheck = Arc<Mutex<PermissionChecker>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckResult {
    Allowed,
    Ask,
    Denied(String),
}

#[derive(Debug, Clone)]
struct Pattern {
    original: String,
}

impl Pattern {
    fn new(pattern: &str) -> Self {
        Pattern {
            original: expand_home(pattern),
        }
    }

    fn matches(&self, input: &str) -> bool {
        glob_matches(&self.original, input)
    }
}

#[derive(Debug, Clone)]
pub struct PermissionChecker {
    rules: HashMap<String, Vec<(Pattern, Action)>>,
    default_action: Action,
    ext_dir_rules: Vec<(Pattern, Action)>,
    doom_loop_action: Action,
    working_dir: String,
    session_allowlist: Vec<(String, Pattern)>,
    recent_calls: VecDeque<(String, String)>,
    mode: SecurityMode,
}

impl PermissionChecker {
    pub fn new(
        config: &PermissionConfig,
        mode: SecurityMode,
        working_dir: Option<PathBuf>,
    ) -> Self {
        let default_action = config.default.unwrap_or(Action::Allow);
        let doom_loop_action = config.doom_loop.unwrap_or(Action::Ask);

        let mut rules: HashMap<String, Vec<(Pattern, Action)>> = HashMap::new();
        for (tool_name, tool_perm) in [
            ("bash", &config.bash),
            ("read", &config.read),
            ("write", &config.write),
            ("edit", &config.edit),
            ("grep", &config.grep),
            ("find_files", &config.find_files),
            ("list_dir", &config.list_dir),
            ("write_todo_list", &config.write_todo_list),
        ] {
            let Some(tp) = tool_perm else { continue };
            let mut entries = Vec::new();
            match tp {
                ToolPerm::Simple(action) => entries.push((Pattern::new("*"), *action)),
                ToolPerm::Granular(map) => {
                    for (pat, action) in map {
                        entries.push((Pattern::new(pat), *action));
                    }
                }
            }
            rules.insert(tool_name.to_string(), entries);
        }

        if !rules.contains_key("bash") {
            let entries = default_bash_rules()
                .into_iter()
                .map(|(pat, action)| (Pattern::new(pat), action))
                .collect();
            rules.insert("bash".to_string(), entries);
        }

        let ext_dir_rules = config
            .external_directory
            .as_ref()
            .map(|map| {
                map.iter()
                    .map(|(pat, action)| (Pattern::new(pat), *action))
                    .collect()
            })
            .unwrap_or_default();

        let working_dir = working_dir
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_default())
            .display()
            .to_string();

        PermissionChecker {
            rules,
            default_action,
            ext_dir_rules,
            doom_loop_action,
            working_dir,
            session_allowlist: Vec::new(),
            recent_calls: VecDeque::with_capacity(16),
            mode,
        }
    }

    pub fn check(&mut self, tool: &str, input: &str) -> CheckResult {
        if self.mode == SecurityMode::Yolo {
            return CheckResult::Allowed;
        }

        if self.is_session_allowed(tool, input) {
            return CheckResult::Allowed;
        }

        let base = self.base_action_for(tool, input, input);
        let action = match self.mode {
            SecurityMode::Restrictive => {
                let has_match = self.has_any_rule_match(tool, input, input);
                if !has_match && self.default_action == Action::Allow {
                    Action::Ask
                } else {
                    base
                }
            }
            SecurityMode::Accept => match base {
                Action::Ask => {
                    if self.is_path_tool(tool) && self.is_external_path(input) {
                        self.match_ext_dir(input).unwrap_or(Action::Ask)
                    } else {
                        Action::Allow
                    }
                }
                other => other,
            },
            SecurityMode::Standard => base,
            SecurityMode::Yolo => Action::Allow,
        };

        self.finalize_check(tool, input, action)
    }

    pub fn check_path(&mut self, tool: &str, path: &str) -> CheckResult {
        if self.mode == SecurityMode::Yolo {
            return CheckResult::Allowed;
        }

        if self.is_session_allowed(tool, path) {
            return CheckResult::Allowed;
        }

        let abs = resolve_absolute(path, &self.working_dir);
        let base = self.base_action_for(tool, &abs, path);
        let has_match = self.has_any_rule_match(tool, &abs, path);

        let action = match self.mode {
            SecurityMode::Restrictive => {
                if !has_match && self.default_action == Action::Allow {
                    Action::Ask
                } else {
                    base
                }
            }
            SecurityMode::Accept => match base {
                Action::Ask => {
                    if self.is_external_path(&abs) {
                        self.match_ext_dir(&abs).unwrap_or(Action::Ask)
                    } else {
                        Action::Allow
                    }
                }
                other => other,
            },
            SecurityMode::Standard => base,
            SecurityMode::Yolo => Action::Allow,
        };

        let action = if !has_match && action == Action::Allow && self.is_external_path(&abs) {
            Action::Ask
        } else {
            action
        };

        self.finalize_check(tool, path, action)
    }

    pub fn add_session_allowlist(&mut self, tool: String, pattern: &str) {
        self.session_allowlist.push((tool, Pattern::new(pattern)));
    }

    pub fn load_session_allowlist(&mut self, entries: &[(String, String)]) {
        for (tool, pat) in entries {
            self.session_allowlist
                .push((tool.clone(), Pattern::new(pat.as_str())));
        }
    }

    pub fn set_mode(&mut self, mode: SecurityMode) {
        self.mode = mode;
    }

    pub fn mode(&self) -> SecurityMode {
        self.mode
    }

    fn finalize_check(&mut self, tool: &str, input: &str, action: Action) -> CheckResult {
        if action != Action::Deny {
            self.track_doom_loop(tool, input);
            if self.is_doom_loop(tool, input) {
                match self.doom_loop_action {
                    Action::Deny => {
                        return CheckResult::Denied(
                            "Doom loop: repeated identical tool call".to_string(),
                        );
                    }
                    Action::Ask => return CheckResult::Ask,
                    Action::Allow => {}
                }
            }
        }

        match action {
            Action::Allow => CheckResult::Allowed,
            Action::Ask => CheckResult::Ask,
            Action::Deny => CheckResult::Denied("Blocked by permission rules".to_string()),
        }
    }

    fn base_action_for(&self, tool: &str, input_primary: &str, input_alt: &str) -> Action {
        let mut matched = Vec::new();
        if let Some(rules) = self.rules.get(tool) {
            for (pattern, action) in rules {
                if pattern.matches(input_primary) || pattern.matches(input_alt) {
                    matched.push(*action);
                }
            }
        }
        matched.last().copied().unwrap_or(self.default_action)
    }

    fn has_any_rule_match(&self, tool: &str, input_primary: &str, input_alt: &str) -> bool {
        self.rules.get(tool).is_some_and(|rules| {
            rules
                .iter()
                .any(|(pattern, _)| pattern.matches(input_primary) || pattern.matches(input_alt))
        })
    }

    fn is_session_allowed(&self, tool: &str, input: &str) -> bool {
        self.session_allowlist
            .iter()
            .any(|(t, p)| t == tool && p.matches(input))
    }

    fn is_path_tool(&self, tool: &str) -> bool {
        matches!(tool, "read" | "write" | "edit" | "list_dir")
    }

    fn is_external_path(&self, path_str: &str) -> bool {
        let p = Path::new(path_str);
        if !p.is_absolute() {
            return false;
        }
        let cwd = Path::new(&self.working_dir);
        !p.starts_with(cwd)
    }

    fn match_ext_dir(&self, path_str: &str) -> Option<Action> {
        for (pattern, action) in &self.ext_dir_rules {
            if pattern.matches(path_str) {
                return Some(*action);
            }
        }
        None
    }

    fn track_doom_loop(&mut self, tool: &str, input: &str) {
        self.recent_calls
            .push_back((tool.to_string(), input.to_string()));
        if self.recent_calls.len() > 16 {
            self.recent_calls.pop_front();
        }
    }

    fn is_doom_loop(&self, tool: &str, input: &str) -> bool {
        self.recent_calls
            .iter()
            .filter(|(t, i)| t == tool && i == input)
            .count()
            >= 3
    }
}

fn resolve_absolute(path: &str, working_dir: &str) -> String {
    let p = Path::new(path);
    if p.is_absolute() {
        p.display().to_string()
    } else {
        Path::new(working_dir).join(p).display().to_string()
    }
}

fn expand_home(pattern: &str) -> String {
    let home = std::env::var("HOME").ok();
    match pattern {
        "~" | "$HOME" => home.unwrap_or_else(|| pattern.to_string()),
        _ => {
            if let Some(rest) = pattern.strip_prefix("~/") {
                if let Some(home) = home {
                    return format!("{home}/{rest}");
                }
            }
            if let Some(rest) = pattern.strip_prefix("$HOME/")
                && let Ok(home) = std::env::var("HOME")
            {
                return format!("{home}/{rest}");
            }
            pattern.to_string()
        }
    }
}

fn glob_matches(pattern: &str, input: &str) -> bool {
    let pat = collapse_stars(pattern);
    wildcard_match(&pat, input)
}

fn collapse_stars(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len());
    let mut prev_star = false;
    for ch in pattern.chars() {
        if ch == '*' {
            if !prev_star {
                out.push(ch);
            }
            prev_star = true;
        } else {
            prev_star = false;
            out.push(ch);
        }
    }
    out
}

fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let s: Vec<char> = text.chars().collect();

    let mut dp = vec![vec![false; s.len() + 1]; p.len() + 1];
    dp[0][0] = true;

    for i in 1..=p.len() {
        if p[i - 1] == '*' {
            dp[i][0] = dp[i - 1][0];
        }
    }

    for i in 1..=p.len() {
        for j in 1..=s.len() {
            match p[i - 1] {
                '*' => {
                    dp[i][j] = dp[i - 1][j] || dp[i][j - 1];
                }
                '?' => {
                    dp[i][j] = dp[i - 1][j - 1];
                }
                c => {
                    dp[i][j] = c == s[j - 1] && dp[i - 1][j - 1];
                }
            }
        }
    }

    dp[p.len()][s.len()]
}

#[cfg(test)]
mod tests {
    use crate::permission::{Action, PermissionConfig, SecurityMode, ToolPerm};

    use super::{CheckResult, PermissionChecker};

    fn make_checker(mode: SecurityMode) -> PermissionChecker {
        PermissionChecker::new(
            &PermissionConfig::default(),
            mode,
            Some(std::path::PathBuf::from("/home/user/project")),
        )
    }

    #[test]
    fn yolo_allows_everything() {
        let mut checker = make_checker(SecurityMode::Yolo);
        assert_eq!(checker.check("bash", "rm -rf /"), CheckResult::Allowed);
        assert_eq!(checker.check("write", "/etc/passwd"), CheckResult::Allowed);
    }

    #[test]
    fn restrictive_makes_unconfigured_tool_ask() {
        let mut checker = make_checker(SecurityMode::Restrictive);
        assert!(matches!(
            checker.check("some_tool", "any input"),
            CheckResult::Ask
        ));
    }

    #[test]
    fn standard_allows_unknown_tool_with_default() {
        let mut checker = make_checker(SecurityMode::Standard);
        assert!(matches!(
            checker.check("some_tool", "any input"),
            CheckResult::Allowed
        ));
    }

    #[test]
    fn accept_auto_allows_inside_working_dir() {
        let config = PermissionConfig {
            write: Some(ToolPerm::Simple(Action::Ask)),
            ..PermissionConfig::default()
        };
        let mut checker = PermissionChecker::new(
            &config,
            SecurityMode::Accept,
            Some(std::path::PathBuf::from("/home/user/project")),
        );
        assert!(matches!(
            checker.check_path("write", "/home/user/project/src/main.rs"),
            CheckResult::Allowed
        ));
    }

    #[test]
    fn accept_asks_for_external_path() {
        let mut checker = make_checker(SecurityMode::Accept);
        assert!(matches!(
            checker.check_path("write", "/etc/config.conf"),
            CheckResult::Ask
        ));
    }

    #[test]
    fn deny_rule_blocks_regardless_of_mode() {
        let mut checker = make_checker(SecurityMode::Standard);
        assert!(matches!(
            checker.check("bash", "rm -rf /home/user/project"),
            CheckResult::Denied(_)
        ));
    }

    #[test]
    fn deny_rule_not_blocked_by_yolo() {
        let mut checker = make_checker(SecurityMode::Yolo);
        assert!(matches!(
            checker.check("bash", "rm -rf /home/user/project"),
            CheckResult::Allowed
        ));
    }

    #[test]
    fn doom_loop_triggers_after_three_repeated_calls() {
        let mut checker = make_checker(SecurityMode::Standard);
        checker.check("bash", "ls");
        checker.check("bash", "ls");
        assert!(matches!(checker.check("bash", "ls"), CheckResult::Ask));
    }

    #[test]
    fn doom_loop_does_not_trigger_before_three() {
        let mut checker = make_checker(SecurityMode::Standard);
        checker.check("bash", "ls");
        assert!(matches!(checker.check("bash", "ls"), CheckResult::Allowed));
    }

    #[test]
    fn session_allowlist_bypasses_rules() {
        let mut checker = make_checker(SecurityMode::Restrictive);
        checker.add_session_allowlist("bash".into(), "cargo test *");
        assert!(matches!(
            checker.check("bash", "cargo test --all"),
            CheckResult::Allowed
        ));
    }

    #[test]
    fn external_absolute_path_outside_cwd_is_detected() {
        let mut checker = make_checker(SecurityMode::Standard);
        assert!(matches!(
            checker.check_path("write", "/etc/shadow"),
            CheckResult::Ask
        ));
    }

    #[test]
    fn relative_path_is_not_external() {
        let mut checker = make_checker(SecurityMode::Accept);
        assert!(matches!(
            checker.check_path("read", "src/lib.rs"),
            CheckResult::Allowed
        ));
    }

    #[test]
    fn explicit_granular_rules_take_effect() {
        let config = PermissionConfig {
            read: Some(ToolPerm::Granular(
                [
                    ("*.md".to_string(), Action::Allow),
                    ("*.rs".to_string(), Action::Ask),
                ]
                .into(),
            )),
            ..PermissionConfig::default()
        };
        let mut checker = PermissionChecker::new(&config, SecurityMode::Standard, None);
        assert_eq!(checker.check("read", "README.md"), CheckResult::Allowed);
        assert_eq!(checker.check("read", "main.rs"), CheckResult::Ask);
    }
}

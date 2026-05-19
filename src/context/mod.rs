use std::collections::HashMap;
use std::path::PathBuf;

use smallvec::SmallVec;

use crate::session::storage;

pub mod prompts;

pub struct ContextFiles {
    pub agents: Option<String>,
    pub prompts: HashMap<String, String>,
    pub current_prompt: Option<String>,
    pub current_prompt_name: Option<String>,
}

impl ContextFiles {
    #[allow(dead_code)]
    pub fn reload(&mut self) {
        self.agents = load_agents();
        self.prompts = prompts::load();
        if let Some(name) = &self.current_prompt_name {
            self.current_prompt = self.prompts.get(name).cloned();
        }
    }
}

pub fn load(no_context_files: bool) -> ContextFiles {
    let _ = prompts::ensure_global();
    let agents = if no_context_files {
        None
    } else {
        load_agents()
    };
    let prompt_map = prompts::load();
    ContextFiles {
        agents,
        prompts: prompt_map,
        current_prompt: None,
        current_prompt_name: None,
    }
}

fn load_file(path: &PathBuf) -> Option<String> {
    if path.exists() {
        std::fs::read_to_string(path).ok()
    } else {
        None
    }
}

fn load_agents() -> Option<String> {
    let mut parts: SmallVec<[String; 4]> = SmallVec::new();

    let global = storage::agents_path();
    if let Some(content) = load_file(&global)
        && !content.trim().is_empty()
    {
        parts.push(format!("# Global AGENTS.md\n{}", content));
    }

    let cwd = std::env::current_dir().ok();
    if let Some(cwd) = cwd {
        let mut current = Some(cwd.as_path());
        while let Some(dir) = current {
            for name in &["AGENTS.md", "CLAUDE.md"] {
                let path = dir.join(name);
                if let Some(content) = load_file(&path)
                    && !content.trim().is_empty()
                {
                    parts.push(format!("# {} ({})\n{}", name, dir.display(), content));
                }
            }
            current = dir.parent();
        }
    }

    if parts.is_empty() {
        None
    } else {
        Some(parts.join("\n\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::Mutex;

    static CWD_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn finds_agents_md_in_cwd() {
        let _guard = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!("hex-agents-test-{}", std::process::id()));
        fs::create_dir_all(&tmp).unwrap();
        fs::write(tmp.join("AGENTS.md"), "# Hex rules\n- be precise").unwrap();
        let orig = std::env::current_dir().unwrap();
        std::env::set_current_dir(&tmp).unwrap();
        let ctx = load(false);
        std::env::set_current_dir(&orig).unwrap();
        fs::remove_dir_all(&tmp).ok();
        assert!(ctx.agents.is_some(), "AGENTS.md from cwd should be loaded");
        let content = ctx.agents.unwrap();
        assert!(
            content.contains("be precise"),
            "expected file content in context"
        );
        assert!(
            content.contains("AGENTS.md"),
            "expected file header in context"
        );
    }

    #[test]
    fn no_context_files_flag_skips_agents() {
        let _guard = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!("hex-no-ctx-test-{}", std::process::id()));
        fs::create_dir_all(&tmp).unwrap();
        fs::write(tmp.join("AGENTS.md"), "should be ignored").unwrap();
        let orig = std::env::current_dir().unwrap();
        std::env::set_current_dir(&tmp).unwrap();
        let ctx = load(true);
        std::env::set_current_dir(&orig).unwrap();
        fs::remove_dir_all(&tmp).ok();
        assert!(
            ctx.agents.is_none(),
            "--no-context-files must skip AGENTS.md"
        );
    }
}

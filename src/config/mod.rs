use std::path::PathBuf;

use serde::Deserialize;

use crate::provider::ProviderKind;

#[derive(Debug, Clone, Default)]
pub struct Config {
    pub provider: Option<ProviderKind>,
    pub model: Option<String>,
    pub max_tokens: Option<u64>,
    pub max_agent_turns: Option<usize>,
    pub temperature: Option<f64>,
    pub no_tools: Option<bool>,
    pub no_context_files: Option<bool>,
    pub restrictive: Option<bool>,
    pub accept_all: Option<bool>,
    pub yolo: Option<bool>,
    pub sandbox: Option<bool>,
    pub default_permission_mode: Option<String>,
    pub shell: Option<String>,
    pub context_window: Option<u64>,
    pub reserve_tokens: Option<u64>,
    pub keep_recent_tokens: Option<u64>,
    pub compact_enabled: Option<bool>,
    pub permission: Option<serde_json::Value>,
    pub show_tool_details: Option<bool>,
    pub default_prompt: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct RawConfig {
    provider: Option<String>,
    model: Option<String>,
    max_tokens: Option<u64>,
    max_agent_turns: Option<usize>,
    temperature: Option<f64>,
    no_tools: Option<bool>,
    no_context_files: Option<bool>,
    restrictive: Option<bool>,
    accept_all: Option<bool>,
    yolo: Option<bool>,
    sandbox: Option<bool>,
    default_permission_mode: Option<String>,
    shell: Option<String>,
    context_window: Option<u64>,
    reserve_tokens: Option<u64>,
    keep_recent_tokens: Option<u64>,
    compact_enabled: Option<bool>,
    permission: Option<serde_json::Value>,
    show_tool_details: Option<bool>,
    default_prompt: Option<String>,
}

impl Config {
    pub fn load() -> Self {
        let mut cfg = Config::default();

        let path = config_file_path();
        if path.exists()
            && let Ok(content) = std::fs::read_to_string(path)
            && let Ok(raw) = serde_json::from_str::<RawConfig>(&content)
        {
            cfg.provider = raw.provider.as_deref().and_then(ProviderKind::from_str);
            cfg.model = raw.model;
            cfg.max_tokens = raw.max_tokens;
            cfg.max_agent_turns = raw.max_agent_turns;
            cfg.temperature = raw.temperature;
            cfg.no_tools = raw.no_tools;
            cfg.no_context_files = raw.no_context_files;
            cfg.restrictive = raw.restrictive;
            cfg.accept_all = raw.accept_all;
            cfg.yolo = raw.yolo;
            cfg.sandbox = raw.sandbox;
            cfg.default_permission_mode = raw.default_permission_mode;
            cfg.shell = raw.shell;
            cfg.context_window = raw.context_window;
            cfg.reserve_tokens = raw.reserve_tokens;
            cfg.keep_recent_tokens = raw.keep_recent_tokens;
            cfg.compact_enabled = raw.compact_enabled;
            cfg.permission = raw.permission;
            cfg.show_tool_details = raw.show_tool_details;
            cfg.default_prompt = raw.default_prompt;
        }

        cfg
    }

    pub fn resolve_context_window(&self) -> u64 {
        self.context_window.unwrap_or(128_000)
    }

    pub fn resolve_reserve_tokens(&self) -> u64 {
        self.reserve_tokens.unwrap_or(16_384)
    }

    pub fn resolve_keep_recent_tokens(&self) -> u64 {
        self.keep_recent_tokens.unwrap_or(20_000)
    }

    pub fn resolve_compact_enabled(&self) -> bool {
        self.compact_enabled.unwrap_or(true)
    }
}

pub fn config_file_path() -> PathBuf {
    if let Some(path) = std::env::var_os("HEX_CONFIG_FILE") {
        return PathBuf::from(path);
    }
    if let Some(dir) = std::env::var_os("HEX_CONFIG_DIR") {
        return PathBuf::from(dir).join("config.json");
    }
    let base = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join("hex").join("config.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_default_context_window() {
        let cfg = Config::default();
        assert_eq!(cfg.resolve_context_window(), 128_000);
    }

    #[test]
    fn loads_config_from_hex_config_file() {
        let path =
            std::env::temp_dir().join(format!("hex-config-test-{}.json", std::process::id()));
        let json = r#"{
            "provider": "openai",
            "model": "gpt-4.1-mini",
            "max_tokens": 4096,
            "no_tools": true,
            "default_permission_mode": "restrictive",
            "shell": "zsh"
        }"#;
        std::fs::write(&path, json).expect("failed to write temp config");

        // SAFETY: test-only mutation of process env, scoped to this test.
        unsafe {
            std::env::set_var("HEX_CONFIG_FILE", &path);
        }
        let cfg = Config::load();
        // SAFETY: test-only cleanup.
        unsafe {
            std::env::remove_var("HEX_CONFIG_FILE");
        }
        let _ = std::fs::remove_file(&path);

        assert_eq!(cfg.provider, Some(ProviderKind::OpenAI));
        assert_eq!(cfg.model.as_deref(), Some("gpt-4.1-mini"));
        assert_eq!(cfg.max_tokens, Some(4096));
        assert_eq!(cfg.no_tools, Some(true));
        assert_eq!(cfg.default_permission_mode.as_deref(), Some("restrictive"));
        assert_eq!(cfg.shell.as_deref(), Some("zsh"));
    }
}

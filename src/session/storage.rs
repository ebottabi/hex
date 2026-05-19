use std::path::PathBuf;

use crate::session::Session;

fn session_dir() -> PathBuf {
    dirs_path().join("sessions")
}

fn home_fallback() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

fn dirs_path() -> PathBuf {
    data_dir()
}

pub fn data_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("HEX_DATA_DIR") {
        return PathBuf::from(dir);
    }
    let base = dirs::data_dir().unwrap_or_else(home_fallback);
    base.join("hex")
}

pub(crate) fn config_path() -> PathBuf {
    if let Some(dir) = std::env::var_os("HEX_CONFIG_DIR") {
        return PathBuf::from(dir);
    }
    let base = dirs::config_dir().unwrap_or_else(|| home_fallback().join(".config"));
    base.join("hex")
}

pub fn save_session(session: &Session) -> anyhow::Result<()> {
    let dir = session_dir();
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.json", session.id));
    let json = serde_json::to_string_pretty(session)?;
    std::fs::write(path, json)?;
    Ok(())
}

pub fn load_session(id: &str) -> anyhow::Result<Session> {
    let dir = session_dir();
    let path = dir.join(format!("{}.json", id));
    let json = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&json)?)
}

pub fn delete_session(id: &str) -> anyhow::Result<()> {
    let dir = session_dir();
    let path = dir.join(format!("{}.json", id));
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

pub fn find_sessions_by_prefix(prefix: &str) -> anyhow::Result<Vec<Session>> {
    let dir = session_dir();
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut sessions: Vec<Session> = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "json")
            && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
            && stem.starts_with(prefix)
            && let Ok(json) = std::fs::read_to_string(&path)
            && let Ok(session) = serde_json::from_str::<Session>(&json)
        {
            sessions.push(session);
        }
    }
    sessions.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    Ok(sessions)
}

pub fn find_recent_sessions(limit: usize) -> anyhow::Result<Vec<Session>> {
    let dir = session_dir();
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut sessions: Vec<Session> = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "json")
            && let Ok(json) = std::fs::read_to_string(&path)
            && let Ok(session) = serde_json::from_str::<Session>(&json)
        {
            sessions.push(session);
        }
    }
    sessions.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    sessions.truncate(limit);
    Ok(sessions)
}

pub fn agents_path() -> PathBuf {
    config_path().join("agent").join("AGENTS.md")
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::{LazyLock, Mutex};

    use crate::session::MessageRole;

    use super::*;

    static ENV_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    fn temp_data_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "hex-session-storage-{}-{}",
            name,
            std::process::id()
        ))
    }

    #[test]
    fn saves_and_loads_session_roundtrip() {
        let _guard = ENV_LOCK.lock().expect("lock poisoned");
        let root = temp_data_root("roundtrip");
        let _ = std::fs::remove_dir_all(&root);

        unsafe {
            std::env::set_var("HEX_DATA_DIR", &root);
        }

        let mut session =
            crate::session::Session::new("openrouter", "deepseek/deepseek-v4-flash", 128_000);
        session.add_message(MessageRole::User, "hello session");
        session.add_message(MessageRole::Assistant, "hi there");

        save_session(&session).expect("failed to save session");
        let loaded = load_session(&session.id).expect("failed to load session");

        assert_eq!(loaded.id, session.id);
        assert_eq!(loaded.model.as_str(), "deepseek/deepseek-v4-flash");
        assert_eq!(loaded.provider.as_str(), "openrouter");
        assert_eq!(loaded.messages.len(), 2);
        assert_eq!(loaded.messages[0].role, MessageRole::User);
        assert_eq!(loaded.messages[1].role, MessageRole::Assistant);

        unsafe {
            std::env::remove_var("HEX_DATA_DIR");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn recent_sessions_are_sorted_descending() {
        let _guard = ENV_LOCK.lock().expect("lock poisoned");
        let root = temp_data_root("recent");
        let _ = std::fs::remove_dir_all(&root);

        unsafe {
            std::env::set_var("HEX_DATA_DIR", &root);
        }

        let mut old = crate::session::Session::new("openrouter", "m1", 128_000);
        old.id = compact_str::CompactString::new("hex-old");
        old.updated_at = compact_str::CompactString::new("10.000000000Z");
        save_session(&old).expect("save old failed");

        let mut new = crate::session::Session::new("openrouter", "m2", 128_000);
        new.id = compact_str::CompactString::new("hex-new");
        new.updated_at = compact_str::CompactString::new("20.000000000Z");
        save_session(&new).expect("save new failed");

        let recent = find_recent_sessions(10).expect("find recent failed");
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].id.as_str(), "hex-new");
        assert_eq!(recent[1].id.as_str(), "hex-old");

        unsafe {
            std::env::remove_var("HEX_DATA_DIR");
        }
        let _ = std::fs::remove_dir_all(&root);
    }
}

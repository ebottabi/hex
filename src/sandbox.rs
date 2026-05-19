use std::path::PathBuf;

use tokio::process::Command;

#[derive(Debug, Clone, Default)]
pub struct Sandbox {
    pub enabled: bool,
    pub shell: String,
    pub cwd: PathBuf,
}

impl Sandbox {
    pub fn new(enabled: bool, shell: impl Into<String>) -> Self {
        Sandbox {
            enabled,
            shell: shell.into(),
            cwd: std::env::current_dir().unwrap_or_default(),
        }
    }

    pub fn wrap_command(&self, command: &str) -> Command {
        let shell = if self.shell.is_empty() {
            "bash"
        } else {
            &self.shell
        };

        if !self.enabled {
            let mut cmd = Command::new(shell);
            cmd.arg("-c").arg(command);
            return cmd;
        }

        let mut cmd = Command::new("bwrap");
        cmd.args(["--ro-bind", "/", "/", "--bind"]);
        cmd.arg(self.cwd.as_os_str());
        cmd.arg(self.cwd.as_os_str());
        cmd.args([
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--unshare-all",
            "--die-with-parent",
            shell,
            "-c",
            command,
        ]);
        cmd
    }
}

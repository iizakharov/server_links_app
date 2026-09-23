//! Running commands on a server as root. `SshRemote` is the real thing; tests use fakes.
use std::future::Future;
use std::time::Duration;

use anyhow::Result;

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(900);

/// Progress lines shown to the user (Russian, same as the panel).
pub type Log<'a> = &'a (dyn Fn(String) + Send + Sync);

pub trait Remote: Send {
    fn host(&self) -> &str;

    /// Runs `cmd` through bash as root. Returns stdout; fails on non-zero exit if `check`.
    fn exec(&mut self, cmd: &str, input: Option<&str>, check: bool, timeout: Duration)
        -> impl Future<Output = Result<String>> + Send;

    fn reconnect(&mut self) -> impl Future<Output = Result<()>> + Send;

    /// SSH host key fingerprint seen on connect (`SHA256:...`), if known.
    fn host_key(&self) -> Option<String> {
        None
    }

    fn run(&mut self, cmd: &str) -> impl Future<Output = Result<String>> + Send {
        self.exec(cmd, None, true, DEFAULT_TIMEOUT)
    }

    /// Like `run`, but a non-zero exit is not an error.
    fn run_ok(&mut self, cmd: &str) -> impl Future<Output = Result<String>> + Send {
        self.exec(cmd, None, false, DEFAULT_TIMEOUT)
    }

    fn put(&mut self, path: &str, content: &str, mode: &str) -> impl Future<Output = Result<()>> + Send {
        let cmd = format!("cat > {p} && chmod {mode} {p}", p = quote(path));
        async move {
            self.exec(&cmd, Some(content), true, DEFAULT_TIMEOUT).await?;
            Ok(())
        }
    }
}

/// Python's `shlex.quote`, so generated commands are identical to the reference panel's.
pub fn quote(s: &str) -> String {
    if s.is_empty() {
        return "''".into();
    }
    if s.chars().all(|c| c.is_ascii_alphanumeric() || "@%+=:,./-_".contains(c)) {
        return s.into();
    }
    format!("'{}'", s.replace('\'', "'\"'\"'"))
}

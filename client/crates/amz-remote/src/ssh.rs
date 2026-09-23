//! SSH connection (russh): commands run as root, directly or via `sudo -n`.
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use russh::client::{self, Handle};
use russh::keys::{load_secret_key, HashAlg, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{ChannelMsg, Disconnect};

use crate::remote::{quote, Remote};

/// How to reach a server.
#[derive(Debug, Clone, Default)]
pub struct SshTarget {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: Option<String>,
    pub key_path: Option<String>,
    /// Fingerprint remembered from the first connection; a different key is refused.
    pub host_key: Option<String>,
    pub timeout: Duration,
}

impl SshTarget {
    pub fn from_server(s: &amz_core::model::Server) -> Self {
        SshTarget {
            host: s.host.clone(),
            port: if s.ssh_port == 0 { 22 } else { s.ssh_port },
            user: if s.user.is_empty() { "root".into() } else { s.user.clone() },
            password: s.password.clone().filter(|p| !p.is_empty()),
            key_path: s.key_path.clone().filter(|p| !p.is_empty()),
            host_key: s.extra.get("host_key").and_then(|v| v.as_str()).map(String::from),
            timeout: Duration::from_secs(15),
        }
    }
}

struct Handler {
    expected: Option<String>,
    seen: Arc<Mutex<Option<String>>>,
}

impl client::Handler for Handler {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let fp = match key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key.fingerprint(HashAlg::Sha256).to_string(),
            PublicKeyOrCertificate::Certificate(c) => c.public_key().fingerprint(HashAlg::Sha256).to_string(),
        };
        let ok = self.expected.as_deref().is_none_or(|e| e == fp);
        *self.seen.lock().unwrap() = Some(fp);
        Ok(ok)
    }
}

pub struct SshRemote {
    target: SshTarget,
    handle: Handle<Handler>,
    seen_key: Arc<Mutex<Option<String>>>,
}

impl SshRemote {
    pub async fn connect(target: SshTarget) -> Result<Self> {
        let seen_key = Arc::new(Mutex::new(None));
        let handle = open(&target, seen_key.clone()).await?;
        Ok(SshRemote { target, handle, seen_key })
    }

    pub async fn close(self) {
        let _ = self.handle.disconnect(Disconnect::ByApplication, "", "en").await;
    }
}

fn default_keys() -> Vec<PathBuf> {
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).map(PathBuf::from);
    home.map(|h| ["id_ed25519", "id_ecdsa", "id_rsa"].iter().map(|n| h.join(".ssh").join(n)).collect())
        .unwrap_or_default()
}

fn expand_home(p: &str) -> PathBuf {
    match (p.strip_prefix("~/"), std::env::var_os("HOME")) {
        (Some(rest), Some(home)) => PathBuf::from(home).join(rest),
        _ => PathBuf::from(p),
    }
}

async fn open(t: &SshTarget, seen: Arc<Mutex<Option<String>>>) -> Result<Handle<Handler>> {
    let config = Arc::new(client::Config {
        keepalive_interval: Some(Duration::from_secs(15)),
        keepalive_max: 4,
        ..Default::default()
    });
    let handler = Handler { expected: t.host_key.clone(), seen: seen.clone() };
    let mut h = tokio::time::timeout(t.timeout, client::connect(config, (t.host.as_str(), t.port), handler))
        .await
        .map_err(|_| anyhow!("[{}] SSH: нет ответа за {} с", t.host, t.timeout.as_secs()))?
        .map_err(|e| {
            let seen = seen.lock().unwrap().clone();
            match (&t.host_key, seen) {
                (Some(exp), Some(got)) if *exp != got => anyhow!(
                    "[{}] SSH-ключ сервера изменился ({got}, ожидался {exp}). Если сервер переустановлен — \
                     сбросьте сохранённый ключ в настройках сервера", t.host),
                _ => anyhow!("[{}] SSH: {e}", t.host),
            }
        })?;

    if let Some(pw) = &t.password {
        if h.authenticate_password(&t.user, pw).await?.success() {
            return Ok(h);
        }
        bail!("[{}] SSH: неверный логин или пароль", t.host);
    }
    let paths = match &t.key_path {
        Some(p) => vec![expand_home(p)],
        None => default_keys().into_iter().filter(|p| p.exists()).collect(),
    };
    for path in &paths {
        let key = load_secret_key(path, None).with_context(|| format!("не удалось прочитать ключ {}", path.display()))?;
        let hash = h.best_supported_rsa_hash().await?.flatten();
        if h.authenticate_publickey(&t.user, PrivateKeyWithHashAlg::new(Arc::new(key), hash)).await?.success() {
            return Ok(h);
        }
    }
    bail!("[{}] SSH: сервер не принял ни пароль, ни ключ ({} шт.)", t.host, paths.len())
}

impl Remote for SshRemote {
    fn host(&self) -> &str {
        &self.target.host
    }

    fn host_key(&self) -> Option<String> {
        self.seen_key.lock().unwrap().clone()
    }

    async fn reconnect(&mut self) -> Result<()> {
        self.handle = open(&self.target, self.seen_key.clone()).await?;
        Ok(())
    }

    async fn exec(&mut self, cmd: &str, input: Option<&str>, check: bool, timeout: Duration) -> Result<String> {
        let mut wrapped = format!("bash -c {}", quote(cmd));
        if self.target.user != "root" {
            wrapped = format!("sudo -n {wrapped}");
        }
        let host = self.target.host.clone();
        let short: String = cmd.chars().take(120).collect();
        let run = async {
            let mut ch = self.handle.channel_open_session().await?;
            ch.exec(true, wrapped.as_bytes()).await?;
            if let Some(data) = input {
                ch.data(data.as_bytes()).await?;
            }
            ch.eof().await?;
            let (mut out, mut err, mut code) = (Vec::new(), Vec::new(), None);
            while let Some(msg) = ch.wait().await {
                match msg {
                    ChannelMsg::Data { data } => out.extend_from_slice(&data),
                    ChannelMsg::ExtendedData { data, .. } => err.extend_from_slice(&data),
                    ChannelMsg::ExitStatus { exit_status } => code = Some(exit_status),
                    _ => {}
                }
            }
            anyhow::Ok((out, err, code))
        };
        let (out, err, code) = tokio::time::timeout(timeout, run)
            .await
            .map_err(|_| anyhow!("[{host}] `{short}`: не завершилось за {} с", timeout.as_secs()))??;
        let out = String::from_utf8_lossy(&out).into_owned();
        let code = code.ok_or_else(|| anyhow!("[{host}] `{short}`: соединение оборвалось"))?;
        if check && code != 0 {
            let err = String::from_utf8_lossy(&err);
            let msg = if err.trim().is_empty() { out.trim() } else { err.trim() };
            bail!("[{host}] `{short}` exit {code}: {msg}");
        }
        Ok(out)
    }
}

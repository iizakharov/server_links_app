//! Local state in `<dir>/state.json` (contains SSH credentials and keys -> mode 600),
//! with the last `BACKUPS` versions kept in `<dir>/backups/`.
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::model::State;

const BACKUPS: usize = 30;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("state file i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("state file is not valid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("keychain: {0}")]
    Secrets(String),
}

/// Where secrets go instead of the file (the app uses the system keychain).
/// Keys: `server:<id>` (SSH password), `client:<id>` (client private key).
pub trait Secrets: Send + Sync {
    fn get(&self, key: &str) -> Option<String>;
    fn set(&self, key: &str, value: &str) -> Result<(), String>;
}

pub struct Storage {
    dir: PathBuf,
    secrets: Option<Arc<dyn Secrets>>,
}

impl Storage {
    /// Plain file, compatible with the reference panel (secrets inside, mode 600).
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Storage { dir: dir.into(), secrets: None }
    }

    /// SSH passwords and client private keys are kept in `secrets`, the file has everything else.
    pub fn with_secrets(dir: impl Into<PathBuf>, secrets: Arc<dyn Secrets>) -> Self {
        Storage { dir: dir.into(), secrets: Some(secrets) }
    }

    fn fill_secrets(&self, state: &mut State) {
        let Some(sec) = &self.secrets else { return };
        for s in &mut state.servers {
            if s.password.as_deref().unwrap_or_default().is_empty() {
                s.password = sec.get(&format!("server:{}", s.id));
            }
        }
        for c in &mut state.clients {
            if c.private_key.is_empty() {
                c.private_key = sec.get(&format!("client:{}", c.id)).unwrap_or_default();
            }
        }
    }

    fn strip_secrets(&self, state: &State) -> Result<State, StorageError> {
        let Some(sec) = &self.secrets else { return Ok(state.clone()) };
        let mut out = state.clone();
        for s in &mut out.servers {
            if let Some(pw) = s.password.take().filter(|p| !p.is_empty()) {
                sec.set(&format!("server:{}", s.id), &pw).map_err(StorageError::Secrets)?;
            }
        }
        for c in &mut out.clients {
            if !c.private_key.is_empty() {
                sec.set(&format!("client:{}", c.id), &c.private_key).map_err(StorageError::Secrets)?;
                c.private_key.clear();
            }
        }
        Ok(out)
    }

    fn state_file(&self) -> PathBuf {
        self.dir.join("state.json")
    }

    pub fn load(&self) -> Result<State, StorageError> {
        let mut state: State = match fs::read(self.state_file()) {
            Ok(raw) => serde_json::from_slice(&raw)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(State::default()),
            Err(e) => return Err(e.into()),
        };
        self.fill_secrets(&mut state);
        Ok(state)
    }

    pub fn save(&self, state: &State) -> Result<(), StorageError> {
        fs::create_dir_all(&self.dir)?;
        let file = self.state_file();
        let tmp = file.with_extension("tmp");
        write_private(&tmp, &serde_json::to_vec_pretty(&self.strip_secrets(state)?)?)?;
        if file.exists() {
            self.backup(&file)?;
        }
        fs::rename(tmp, file)?;
        Ok(())
    }

    /// A mistaken edit can be rolled back from here.
    fn backup(&self, file: &Path) -> Result<(), StorageError> {
        let bdir = self.dir.join("backups");
        fs::create_dir_all(&bdir)?;
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_micros();
        write_private(&bdir.join(format!("state-{ts:020}.json")), &fs::read(file)?)?;
        let mut old: Vec<_> = fs::read_dir(&bdir)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("state-")))
            .collect();
        old.sort();
        for p in old.iter().take(old.len().saturating_sub(BACKUPS)) {
            fs::remove_file(p)?;
        }
        Ok(())
    }
}

fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    opts.open(path)?.write_all(data)
}

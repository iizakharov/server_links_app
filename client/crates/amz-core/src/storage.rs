//! Local state in `<dir>/state.json` (contains SSH credentials and keys -> mode 600),
//! with the last `BACKUPS` versions kept in `<dir>/backups/`.
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::model::State;

const BACKUPS: usize = 30;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("state file i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("state file is not valid: {0}")]
    Json(#[from] serde_json::Error),
}

pub struct Storage {
    dir: PathBuf,
}

impl Storage {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Storage { dir: dir.into() }
    }

    fn state_file(&self) -> PathBuf {
        self.dir.join("state.json")
    }

    pub fn load(&self) -> Result<State, StorageError> {
        match fs::read(self.state_file()) {
            Ok(raw) => Ok(serde_json::from_slice(&raw)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self, state: &State) -> Result<(), StorageError> {
        fs::create_dir_all(&self.dir)?;
        let file = self.state_file();
        let tmp = file.with_extension("tmp");
        write_private(&tmp, &serde_json::to_vec_pretty(state)?)?;
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

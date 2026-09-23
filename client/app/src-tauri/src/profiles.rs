//! Connections of this device ("servers" in the UI): imported `vpn://` keys and `.conf` files.
//! Stored in the app data dir as JSON, mode 600 (contains private keys).
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use amz_core::tunnel::tunnel_config;
use amz_core::{awg, import_vpn_key, parse_conf};
use anyhow::{bail, Result};
use rand::Rng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub conf: String,
    pub created: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// system | dark | light
    pub theme: String,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { theme: "system".into() }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Data {
    pub profiles: Vec<Profile>,
    pub selected: Option<String>,
    pub settings: Settings,
}

/// What the UI shows for a profile (no keys).
#[derive(Debug, Clone, Serialize)]
pub struct ProfileView {
    pub id: String,
    pub name: String,
    pub endpoint: String,
    pub address: String,
    pub awg_version: String,
}

impl Profile {
    pub fn view(&self) -> ProfileView {
        let (iface, peers) = parse_conf(&self.conf);
        let get = |s: &amz_core::Section, k: &str| s.iter().find(|(key, _)| key.eq_ignore_ascii_case(k))
            .map(|(_, v)| v.clone()).unwrap_or_default();
        ProfileView {
            id: self.id.clone(),
            name: self.name.clone(),
            endpoint: peers.first().map(|p| get(p, "Endpoint")).unwrap_or_default(),
            address: get(&iface, "Address"),
            awg_version: awg::awg_version(&amz_core::obfuscation_params(&iface)).into(),
        }
    }
}

pub struct Store {
    path: PathBuf,
}

impl Store {
    pub fn new(dir: &Path) -> Self {
        Store { path: dir.join("profiles.json") }
    }

    pub fn load(&self) -> Result<Data> {
        match fs::read(&self.path) {
            Ok(raw) => Ok(serde_json::from_slice(&raw)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Data::default()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self, data: &Data) -> Result<()> {
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        let tmp = self.path.with_extension("tmp");
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        opts.open(&tmp)?.write_all(&serde_json::to_vec_pretty(data)?)?;
        fs::rename(tmp, &self.path)?;
        Ok(())
    }
}

/// A `vpn://` key or `.conf` text -> (name, conf). The config must be one the tunnel can use.
pub fn parse_import(text: &str, fallback_name: &str) -> Result<(String, String)> {
    let text = text.trim();
    let (name, conf) = if text.starts_with("vpn://") {
        let k = import_vpn_key(text)?;
        (k.name, k.conf)
    } else if text.contains("[Interface]") {
        (String::new(), format!("{text}\n"))
    } else {
        bail!("Это не ключ vpn:// и не конфиг AmneziaWG");
    };
    // endpoint may be a DNS name: it is resolved on connect, here only the format matters
    tunnel_config(&conf, |_, port| Some(([192, 0, 2, 1], port).into()))?;
    let name = if name.trim().is_empty() { fallback_name.to_string() } else { name.trim().to_string() };
    Ok((name, conf))
}

pub fn new_profile(name: String, conf: String) -> Profile {
    Profile {
        id: format!("{:08x}", rand::thread_rng().gen::<u32>()),
        name,
        conf,
        created: chrono::Local::now().format("%Y-%m-%d %H:%M").to_string(),
    }
}

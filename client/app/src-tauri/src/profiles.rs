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
    /// kept in the system keychain; read into memory on load, never written to the JSON file
    #[serde(default, skip_serializing)]
    pub conf: String,
    pub created: String,
}

const KEYCHAIN_SERVICE: &str = "com.amnezinu.vpn";

fn secret(id: &str) -> Result<keyring::Entry> {
    Ok(keyring::Entry::new(KEYCHAIN_SERVICE, id)?)
}

/// Windows Credential Manager keeps at most 2560 bytes (1280 characters as a password), an AWG 3 config is
/// longer: it is stored compressed there. Elsewhere the keychain item is the plain config.
#[cfg(windows)]
fn read_conf(e: &keyring::Entry) -> Option<String> {
    String::from_utf8(amz_core::vpnkey::quncompress(&e.get_secret().ok()?).ok()?).ok()
}

#[cfg(windows)]
fn write_conf(e: &keyring::Entry, conf: &str) -> Result<()> {
    Ok(e.set_secret(&amz_core::vpnkey::qcompress(conf.as_bytes()))?)
}

#[cfg(not(windows))]
fn read_conf(e: &keyring::Entry) -> Option<String> {
    e.get_password().ok()
}

#[cfg(not(windows))]
fn write_conf(e: &keyring::Entry, conf: &str) -> Result<()> {
    Ok(e.set_password(conf)?)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// system | dark | light
    pub theme: String,
    pub kill_switch: bool,
    pub allow_lan: bool,
    /// connect to the selected server when the app starts
    pub autoconnect: bool,
    pub split: amz_ipc::Split,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { theme: "system".into(), kill_switch: false, allow_lan: true, autoconnect: false,
                   split: Default::default() }
    }
}

impl Settings {
    pub fn up_options(&self) -> amz_ipc::UpOptions {
        amz_ipc::UpOptions { kill_switch: self.kill_switch, allow_lan: self.allow_lan, split: self.split.clone() }
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

    /// Loads profiles and their configs from the keychain. Configs still stored in the file by an older
    /// version are moved to the keychain.
    pub fn load(&self) -> Result<Data> {
        let raw = match fs::read(&self.path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Data::default()),
            Err(e) => return Err(e.into()),
        };
        let file: serde_json::Value = serde_json::from_slice(&raw)?;
        let mut data: Data = serde_json::from_value(file.clone())?;
        let mut migrate = false;
        for (i, p) in data.profiles.iter_mut().enumerate() {
            match file["profiles"][i]["conf"].as_str() {
                Some(conf) => {
                    p.conf = conf.to_string();
                    migrate = true;
                }
                None => p.conf = read_conf(&secret(&p.id)?).unwrap_or_default(),
            }
        }
        if migrate {
            self.save(&data)?;
        }
        Ok(data)
    }

    pub fn save(&self, data: &Data) -> Result<()> {
        for p in &data.profiles {
            let entry = secret(&p.id)?;
            if read_conf(&entry).as_deref() != Some(p.conf.as_str()) {
                write_conf(&entry, &p.conf)?;
            }
        }
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

    pub fn forget(&self, id: &str) {
        if let Ok(e) = secret(id) {
            let _ = e.delete_credential();
        }
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

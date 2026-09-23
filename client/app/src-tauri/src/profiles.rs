//! Connections of this device ("servers" in the UI): imported `vpn://` keys and `.conf` files.
//! Stored in the app data dir as JSON, mode 600 (contains private keys).
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use amz_core::tunnel::tunnel_config;
use amz_core::vpnkey::KeyExit;
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
    /// profiles imported from one multi-exit key share a group; `exit` names this one's exit server
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit: Option<String>,
}

const KEYCHAIN_SERVICE: &str = "com.amnezinu.vpn";

#[cfg(not(target_os = "macos"))]
fn secret(id: &str) -> Result<keyring::Entry> {
    Ok(keyring::Entry::new(KEYCHAIN_SERVICE, id)?)
}

/// macOS: all secrets in one keychain item (see vault.rs).
#[cfg(target_os = "macos")]
fn load_conf(id: &str) -> Option<String> {
    crate::vault::get(KEYCHAIN_SERVICE, id)
}

#[cfg(target_os = "macos")]
fn save_conf(id: &str, conf: &str) -> Result<()> {
    crate::vault::set(KEYCHAIN_SERVICE, id, conf).map_err(anyhow::Error::msg)
}

#[cfg(target_os = "macos")]
fn forget_conf(id: &str) {
    crate::vault::delete(KEYCHAIN_SERVICE, id)
}

/// Windows Credential Manager keeps at most 2560 bytes (1280 characters as a password), an AWG 3 config is
/// longer: it is stored compressed there.
#[cfg(windows)]
fn load_conf(id: &str) -> Option<String> {
    String::from_utf8(amz_core::vpnkey::quncompress(&secret(id).ok()?.get_secret().ok()?).ok()?).ok()
}

#[cfg(windows)]
fn save_conf(id: &str, conf: &str) -> Result<()> {
    Ok(secret(id)?.set_secret(&amz_core::vpnkey::qcompress(conf.as_bytes()))?)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn load_conf(id: &str) -> Option<String> {
    secret(id).ok()?.get_password().ok()
}

#[cfg(all(unix, not(target_os = "macos")))]
fn save_conf(id: &str, conf: &str) -> Result<()> {
    Ok(secret(id)?.set_password(conf)?)
}

#[cfg(not(target_os = "macos"))]
fn forget_conf(id: &str) {
    if let Ok(e) = secret(id) {
        let _ = e.delete_credential();
    }
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
    pub group: Option<String>,
    pub exit: Option<String>,
    /// "name · exit" (what the status and the menu bar show)
    pub title: String,
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
            group: self.group.clone(),
            exit: self.exit.clone(),
            title: self.title(),
        }
    }

    pub fn title(&self) -> String {
        match &self.exit {
            Some(exit) => format!("{} · {exit}", self.name),
            None => self.name.clone(),
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
                None => p.conf = load_conf(&p.id).unwrap_or_default(),
            }
        }
        if migrate {
            self.save(&data)?;
        }
        Ok(data)
    }

    pub fn save(&self, data: &Data) -> Result<()> {
        for p in &data.profiles {
            // an empty config means it could not be read (keychain access denied): never overwrite with it
            if !p.conf.is_empty() && load_conf(&p.id).as_deref() != Some(p.conf.as_str()) {
                save_conf(&p.id, &p.conf)?;
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
        forget_conf(id);
    }
}

/// A `vpn://` key or `.conf` text -> (name, conf, all exits if the key has several). Every config must be
/// one the tunnel can use.
pub fn parse_import(text: &str, fallback_name: &str) -> Result<(String, String, Vec<KeyExit>)> {
    let text = text.trim();
    let (name, conf, exits) = if text.starts_with("vpn://") {
        let k = import_vpn_key(text)?;
        (k.name, k.conf, if k.exits.len() > 1 { k.exits } else { vec![] })
    } else if text.contains("[Interface]") {
        (String::new(), format!("{text}\n"), vec![])
    } else {
        bail!("Это не ключ vpn:// и не конфиг AmneziaWG");
    };
    // endpoint may be a DNS name: it is resolved on connect, here only the format matters
    for c in std::iter::once(&conf).chain(exits.iter().map(|e| &e.conf)) {
        tunnel_config(c, |_, port| Some(([192, 0, 2, 1], port).into()))?;
    }
    let name = if name.trim().is_empty() { fallback_name.to_string() } else { name.trim().to_string() };
    Ok((name, conf, exits))
}

/// Profiles for a multi-exit key: one per exit, in one group.
pub fn new_group(name: &str, exits: Vec<KeyExit>) -> Vec<Profile> {
    let group = format!("{:08x}", rand::thread_rng().gen::<u32>());
    exits.into_iter().map(|e| Profile {
        group: Some(group.clone()),
        exit: Some(e.name),
        ..new_profile(name.to_string(), e.conf)
    }).collect()
}

pub fn new_profile(name: String, conf: String) -> Profile {
    Profile {
        id: format!("{:08x}", rand::thread_rng().gen::<u32>()),
        name,
        conf,
        created: chrono::Local::now().format("%Y-%m-%d %H:%M").to_string(),
        group: None,
        exit: None,
    }
}

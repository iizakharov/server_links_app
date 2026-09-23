//! macOS: all secrets of the app (profile configs, SSH passwords, client keys) in ONE keychain item.
//! An unsigned build is a new app for the keychain after every update, and macOS asks about each item
//! separately: one item means one prompt per update. Items of older versions (one per secret) are read
//! once and copied in; they are left in place, deleting them would prompt again.
use std::collections::BTreeMap;
use std::sync::Mutex;

const SERVICE: &str = "com.amnezinu.vpn";
const ACCOUNT: &str = "vault";

/// secrets by "<service>/<key>", loaded on first use
static CACHE: Mutex<Option<BTreeMap<String, String>>> = Mutex::new(None);

fn entry() -> Result<keyring::Entry, String> {
    keyring::Entry::new(SERVICE, ACCOUNT).map_err(|e| e.to_string())
}

/// Runs `f` on the loaded secrets. Access denied is an error (not "empty"): nothing may be overwritten then.
fn with<T>(f: impl FnOnce(&mut BTreeMap<String, String>) -> Result<T, String>) -> Result<T, String> {
    let mut cache = CACHE.lock().unwrap();
    if cache.is_none() {
        *cache = Some(match entry()?.get_password() {
            Ok(json) => serde_json::from_str(&json).map_err(|e| format!("хранилище ключей повреждено: {e}"))?,
            Err(keyring::Error::NoEntry) => BTreeMap::new(),
            Err(e) => return Err(format!("нет доступа к связке ключей: {e}")),
        });
    }
    f(cache.as_mut().unwrap())
}

fn persist(map: &BTreeMap<String, String>) -> Result<(), String> {
    entry()?.set_password(&serde_json::to_string(map).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}

pub fn get(service: &str, key: &str) -> Option<String> {
    with(|m| {
        let k = format!("{service}/{key}");
        if let Some(v) = m.get(&k) {
            return Ok(Some(v.clone()));
        }
        // an item of an older version: copy it in
        let Some(v) = keyring::Entry::new(service, key).ok().and_then(|e| e.get_password().ok()) else { return Ok(None) };
        m.insert(k, v.clone());
        persist(m)?;
        Ok(Some(v))
    }).ok().flatten()
}

pub fn set(service: &str, key: &str, value: &str) -> Result<(), String> {
    with(|m| {
        let k = format!("{service}/{key}");
        if m.get(&k).map(String::as_str) == Some(value) {
            return Ok(());
        }
        m.insert(k, value.into());
        persist(m)
    })
}

pub fn delete(service: &str, key: &str) {
    let _ = with(|m| if m.remove(&format!("{service}/{key}")).is_some() { persist(m) } else { Ok(()) });
}

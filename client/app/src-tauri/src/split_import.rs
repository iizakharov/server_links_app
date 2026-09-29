//! Import Amnezia site lists without changing the saved split-tunnel settings.
use std::{collections::HashSet, net::IpAddr};
use serde::Deserialize;
use crate::Res;

#[derive(Deserialize)]
struct Site {
    #[serde(default)]
    hostname: String,
    #[serde(default)]
    ip: String,
    #[serde(default)]
    ips: Vec<String>,
}

fn address(value: &str) -> bool {
    if let Some((ip, prefix)) = value.split_once('/') {
        return ip.parse::<IpAddr>().ok().zip(prefix.parse::<u8>().ok())
            .is_some_and(|(ip, prefix)| prefix <= if ip.is_ipv4() { 32 } else { 128 });
    }
    value.parse::<IpAddr>().is_ok()
}

fn hostname(value: &str) -> bool {
    if address(value) { return true; }
    let domain = value.trim_end_matches('.');
    // Numeric dotted strings must be valid IP addresses, not domain names.
    domain.len() <= 253 && domain.contains('.')
        && !domain.chars().all(|c| c.is_ascii_digit() || c == '.')
        && domain.split('.').all(|label| !label.is_empty() && label.len() <= 63
            && !label.starts_with('-') && !label.ends_with('-')
            && label.chars().all(|c| c.is_alphanumeric() || c == '-'))
}

fn parse(text: &str) -> Res<Vec<String>> {
    let sites: Vec<Site> = serde_json::from_str(text.trim_start_matches('\u{feff}'))
        .map_err(|e| format!("Не удалось прочитать список JSON Amnezia: {e}"))?;
    let mut entries = Vec::new();
    let mut seen = HashSet::new();
    for (index, site) in sites.into_iter().enumerate() {
        let mut values = Vec::new();
        let host = site.hostname.trim();
        if !host.is_empty() {
            if !hostname(host) { return Err(format!("Запись {}: неверный домен, IP-адрес или сеть", index + 1)); }
            values.push(host.to_lowercase());
        }
        for ip in std::iter::once(site.ip).chain(site.ips) {
            let ip = ip.trim();
            if ip.is_empty() { continue; }
            if !address(ip) { return Err(format!("Запись {}: неверный IP-адрес или сеть в ip/ips", index + 1)); }
            values.push(ip.to_lowercase());
        }
        if values.is_empty() { return Err(format!("Запись {}: нет домена или адреса", index + 1)); }
        for value in values {
            if seen.insert(value.clone()) { entries.push(value); }
        }
    }
    Ok(entries)
}

#[tauri::command]
pub async fn split_import_file(path: String) -> Res<Vec<String>> {
    tauri::async_runtime::spawn_blocking(move || {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("Не удалось открыть JSON-файл: {e}"))?;
        parse(&text)
    }).await.map_err(|e| e.to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_and_current_preserve_hosts_and_addresses() {
        assert_eq!(parse(r#"[
            {"hostname":"Example.COM", "ip":"1.2.3.4"},
            {"hostname":"example.com", "ips":["1.2.3.4", "2001:db8::1", "10.0.0.0/8"]},
            {"hostname":"2001:db8::/32", "ip":""},
            {"hostname":"пример.рф", "ips":[]}
        ]"#).unwrap(), ["example.com", "1.2.3.4", "2001:db8::1", "10.0.0.0/8", "2001:db8::/32", "пример.рф"]);
        assert_eq!(parse(r#"[{"ips":["::1", "0.0.0.0/0"]}]"#).unwrap(), ["::1", "0.0.0.0/0"]);
    }

    #[test]
    fn empty_list_and_bom() {
        assert!(parse("[]").unwrap().is_empty());
        assert!(parse("\u{feff}[]").unwrap().is_empty());
        assert!(parse("").is_err());
    }

    #[test]
    fn imported_and_manual_entries_survive_reload() {
        let dir = std::env::temp_dir().join(format!("amnezinu-split-test-{}", rand::random::<u64>()));
        let store = crate::profiles::Store::new(&dir);
        let mut data = crate::profiles::Data::default();
        data.settings.split.entries = parse(r#"[{"hostname":"example.com","ip":"1.2.3.4"}]"#).unwrap();
        data.settings.split.entries.push("manual.example".into());
        data.settings.split.mode = amz_ipc::SplitMode::Except;
        store.save(&data).unwrap();
        let loaded = crate::profiles::Store::new(&dir).load().unwrap();
        assert_eq!(loaded.settings.split.entries, data.settings.split.entries);
        assert!(matches!(loaded.settings.split.mode, amz_ipc::SplitMode::Except));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejects_whole_file_if_any_record_is_invalid() {
        for invalid in [r#"{}"#, r#""example.com""#, r#"{"hostname":12}"#,
            r#"{"hostname":"https://example.com/path"}"#, r#"{"hostname":"999.1.2.3"}"#,
            r#"{"hostname":"example.com", "ips":["1.2.3.4/33"]}"#,
            r#"{"ip":"2001:db8::/129"}"#, r#"{"ips":"1.2.3.4"}"#,
            r#"{"ip":"not-an-ip"}"#] {
            assert!(parse(&format!(r#"[{{"hostname":"valid.com"}}, {invalid}]"#)).is_err(), "{invalid}");
        }
        assert!(parse("{}").is_err());
        assert!(parse("[broken").is_err());
    }
}

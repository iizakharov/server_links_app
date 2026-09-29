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

// Split routes apply to the whole host. Keep bare IPv6 intact; discard only explicit ports.
fn normalize_hostname(value: &str) -> Option<String> {
    if hostname(value) { return Some(value.to_lowercase()); }
    let (host, port) = value.rsplit_once(':')?;
    if !port.bytes().all(|c| c.is_ascii_digit()) || port.parse::<u16>().ok()? == 0 {
        return None;
    }
    let host = if let Some(bracketed) = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        bracketed.parse::<std::net::Ipv6Addr>().ok()?;
        bracketed
    } else {
        if host.contains(':') || host.contains('/') { return None; }
        host
    };
    hostname(host).then(|| host.to_lowercase())
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
            let host = normalize_hostname(host)
                .ok_or_else(|| format!("Запись {}: неверный домен, IP-адрес или сеть", index + 1))?;
            values.push(host);
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
    fn imports_hosts_with_ports_without_losing_ipv6_or_networks() {
        assert_eq!(parse(r#"[
            {"hostname":"app-123.games.s3.example.net:443", "ip":""},
            {"hostname":"EXAMPLE.COM:8443", "ip":""},
            {"hostname":"example.com", "ip":""},
            {"hostname":"192.0.2.1:80", "ip":""},
            {"hostname":"[2001:db8::1]:443", "ip":""},
            {"hostname":"2001:db8::2", "ip":""},
            {"hostname":"2001:db8::/32", "ip":""}
        ]"#).unwrap(), ["app-123.games.s3.example.net", "example.com", "192.0.2.1",
            "2001:db8::1", "2001:db8::2", "2001:db8::/32"]);
        for host in ["example.com:0", "example.com:65536", "example.com:https",
            "example.com:", "example.com:443:80", "[invalid]:443"] {
            assert!(parse(&serde_json::json!([{"hostname":host}]).to_string()).is_err());
        }
    }

    #[test]
    #[ignore = "requires AMZ_SPLIT_IMPORT_TEST_FILE pointing to a local Amnezia list"]
    fn imports_external_site_list() {
        let path = std::env::var("AMZ_SPLIT_IMPORT_TEST_FILE").unwrap();
        let text = std::fs::read_to_string(path).unwrap();
        let entries = parse(&text).unwrap();
        println!("Imported {} unique entries", entries.len());
        assert!(!entries.is_empty());
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

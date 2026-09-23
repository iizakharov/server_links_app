//! Client `.conf` -> what the tunnel needs: UAPI settings for amneziawg-go, plus addresses, DNS, MTU
//! and routes for the OS side.
use std::net::{IpAddr, SocketAddr};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use crate::conf::{parse_conf, Section, MTU};

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ConfError {
    #[error("в конфиге нет {0}")]
    Missing(&'static str),
    #[error("в конфиге должен быть ровно один [Peer], найдено {0}")]
    Peers(usize),
    #[error("неверное значение {key}: {value}")]
    Invalid { key: String, value: String },
    #[error("неизвестный параметр [Interface]: {0}")]
    UnknownKey(String),
    #[error("не удалось определить адрес сервера {0}")]
    Resolve(String),
}

/// Everything needed to bring a tunnel up.
#[derive(Debug, Clone, PartialEq)]
pub struct TunnelConfig {
    /// UAPI `set` text for amneziawg-go (without the trailing empty line)
    pub uapi: String,
    /// interface addresses, e.g. "10.9.3.2/32"
    pub addresses: Vec<String>,
    pub dns: Vec<IpAddr>,
    pub mtu: u32,
    /// networks routed into the tunnel
    pub allowed_ips: Vec<String>,
    /// server address (resolved), must stay routed outside the tunnel
    pub endpoint: SocketAddr,
}

/// `[Interface]` keys handled by the OS side, not by amneziawg-go.
const OS_KEYS: &[&str] = &["address", "dns", "mtu", "table", "preup", "postup", "predown", "postdown", "saveconfig", "fwmark"];

/// AWG obfuscation keys: `.conf` name (lowercase) -> UAPI name.
const AWG_KEYS: &[(&str, &str)] = &[
    ("jc", "jc"), ("jmin", "jmin"), ("jmax", "jmax"),
    ("s1", "s1"), ("s2", "s2"), ("s3", "s3"), ("s4", "s4"),
    ("h1", "h1"), ("h2", "h2"), ("h3", "h3"), ("h4", "h4"),
    ("i1", "i1"), ("i2", "i2"), ("i3", "i3"), ("i4", "i4"), ("i5", "i5"),
    ("contentpaddingaddition", "content_padding_addition"),
];

fn key_hex(key: &str, value: &str) -> Result<String, ConfError> {
    let invalid = || ConfError::Invalid { key: key.into(), value: value.into() };
    let raw = STANDARD.decode(value.trim()).map_err(|_| invalid())?;
    if raw.len() != 32 {
        return Err(invalid());
    }
    Ok(raw.iter().map(|b| format!("{b:02x}")).collect())
}

fn get<'a>(sec: &'a Section, key: &'static str) -> Option<&'a str> {
    sec.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)).map(|(_, v)| v.as_str())
}

fn list(value: Option<&str>) -> Vec<String> {
    value.unwrap_or_default().split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect()
}

/// Parses a client config. `resolve` turns the Endpoint host into an address (DNS, done by the caller).
pub fn tunnel_config(text: &str, resolve: impl Fn(&str, u16) -> Option<SocketAddr>) -> Result<TunnelConfig, ConfError> {
    let (iface, peers) = parse_conf(text);
    let peer = match peers.as_slice() {
        [p] => p,
        other => return Err(ConfError::Peers(other.len())),
    };
    let mut uapi = vec![format!("private_key={}", key_hex("PrivateKey", get(&iface, "PrivateKey").ok_or(ConfError::Missing("PrivateKey"))?)?)];
    for (k, v) in &iface {
        let lk = k.to_lowercase();
        if lk == "privatekey" || lk == "listenport" || OS_KEYS.contains(&lk.as_str()) {
            continue;
        }
        if lk == "headerprotectionkey" {
            uapi.push(format!("header_protection_key={}", key_hex(k, v)?));
        } else if let Some((_, u)) = AWG_KEYS.iter().find(|(c, _)| *c == lk) {
            uapi.push(format!("{u}={v}"));
        } else {
            return Err(ConfError::UnknownKey(k.clone()));
        }
    }

    let endpoint_raw = get(peer, "Endpoint").ok_or(ConfError::Missing("Endpoint"))?;
    let invalid = || ConfError::Invalid { key: "Endpoint".into(), value: endpoint_raw.into() };
    let (host, port) = endpoint_raw.rsplit_once(':').ok_or_else(invalid)?;
    let port: u16 = port.parse().map_err(|_| invalid())?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let endpoint = match host.parse::<IpAddr>() {
        Ok(ip) => SocketAddr::new(ip, port),
        Err(_) => resolve(host, port).ok_or_else(|| ConfError::Resolve(host.into()))?,
    };

    uapi.push("replace_peers=true".into());
    uapi.push(format!("public_key={}", key_hex("PublicKey", get(peer, "PublicKey").ok_or(ConfError::Missing("PublicKey"))?)?));
    if let Some(psk) = get(peer, "PresharedKey").filter(|p| !p.is_empty()) {
        uapi.push(format!("preshared_key={}", key_hex("PresharedKey", psk)?));
    }
    uapi.push(format!("endpoint={endpoint}"));
    if let Some(ka) = get(peer, "PersistentKeepalive") {
        uapi.push(format!("persistent_keepalive_interval={ka}"));
    }
    uapi.push("replace_allowed_ips=true".into());
    let allowed_ips = list(get(peer, "AllowedIPs"));
    uapi.extend(allowed_ips.iter().map(|a| format!("allowed_ip={a}")));

    let dns = list(get(&iface, "DNS")).iter()
        .map(|d| d.parse().map_err(|_| ConfError::Invalid { key: "DNS".into(), value: d.clone() }))
        .collect::<Result<_, _>>()?;
    let mtu = match get(&iface, "MTU") {
        Some(m) => m.parse().map_err(|_| ConfError::Invalid { key: "MTU".into(), value: m.into() })?,
        None => MTU,
    };
    let addresses = list(get(&iface, "Address"));
    if addresses.is_empty() {
        return Err(ConfError::Missing("Address"));
    }
    Ok(TunnelConfig { uapi: uapi.join("\n"), addresses, dns, mtu, allowed_ips, endpoint })
}

/// Counters from the UAPI `get` output.
#[derive(Debug, Clone, Copy, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TunnelStats {
    pub rx: u64,
    pub tx: u64,
    /// unix seconds, 0 = no handshake yet
    pub handshake: i64,
}

pub fn parse_stats(uapi_get: &str) -> TunnelStats {
    let mut s = TunnelStats::default();
    for line in uapi_get.lines() {
        match line.split_once('=') {
            Some(("rx_bytes", v)) => s.rx += v.parse().unwrap_or(0),
            Some(("tx_bytes", v)) => s.tx += v.parse().unwrap_or(0),
            Some(("last_handshake_time_sec", v)) => s.handshake = s.handshake.max(v.parse().unwrap_or(0)),
            _ => {}
        }
    }
    s
}

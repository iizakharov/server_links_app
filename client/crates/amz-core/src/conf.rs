//! Parsing server configs and generating client `.conf` files.
use indexmap::IndexMap;

use crate::model::{AwgServer, ClientKeys};

/// One `[Interface]` or `[Peer]` section; keys keep their original case and order.
pub type Section = IndexMap<String, String>;

/// `[Interface]` keys that are not obfuscation parameters (everything else — Jc, Jmin, S1, H1, I1... — is copied to clients).
const STANDARD_IFACE_KEYS: &[&str] = &[
    "privatekey", "address", "listenport", "postup", "postdown", "preup", "predown",
    "dns", "mtu", "saveconfig", "table", "fwmark",
];
pub const MTU: u32 = 1280;

/// Returns (`[Interface]`, list of `[Peer]`).
pub fn parse_conf(text: &str) -> (Section, Vec<Section>) {
    let (mut iface, mut peers) = (Section::new(), Vec::<Section>::new());
    // None = before any section, Some(None) = interface, Some(Some(i)) = peer i
    let mut cur: Option<Option<usize>> = None;
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            let section = line.trim_matches(|c| c == '[' || c == ']').trim().to_lowercase();
            cur = if section == "interface" {
                Some(None)
            } else {
                peers.push(Section::new());
                Some(Some(peers.len() - 1))
            };
            continue;
        }
        if let (Some(target), Some((k, v))) = (cur, line.split_once('=')) {
            let sec = match target {
                None => &mut iface,
                Some(i) => &mut peers[i],
            };
            sec.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    (iface, peers)
}

/// Removes the `[Peer]` block with this PublicKey (with its comment lines) from a server config.
pub fn drop_peer(text: &str, public_key: &str) -> String {
    let needle = format!("PublicKey={public_key}");
    let (mut out, mut block, mut keep) = (String::new(), String::new(), true);
    for line in text.split_inclusive('\n') {
        if line.trim().starts_with('[') {
            if keep {
                out.push_str(&block);
            }
            block = line.to_string();
            keep = true;
        } else {
            block.push_str(line);
            if line.split('#').next().unwrap_or("").trim().replace(' ', "") == needle {
                keep = false;
            }
        }
    }
    if keep {
        out.push_str(&block);
    }
    out
}

pub fn obfuscation_params(iface: &Section) -> Section {
    iface
        .iter()
        .filter(|(k, _)| !STANDARD_IFACE_KEYS.contains(&k.to_lowercase().as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

pub fn client_conf(client: &ClientKeys, server: &AwgServer, endpoint_host: &str, endpoint_port: u16,
                   dns1: &str, dns2: &str) -> String {
    let mut lines = vec![
        "[Interface]".to_string(),
        format!("PrivateKey = {}", client.private_key),
        format!("Address = {}/32", client.ip),
        format!("DNS = {dns1}, {dns2}"),
        format!("MTU = {MTU}"),
    ];
    lines.extend(server.params.iter().map(|(k, v)| format!("{k} = {v}")));
    lines.extend(["".to_string(), "[Peer]".to_string(), format!("PublicKey = {}", server.public_key)]);
    if let Some(psk) = client.psk.as_deref().filter(|p| !p.is_empty()) {
        lines.push(format!("PresharedKey = {psk}"));
    }
    lines.extend([
        "AllowedIPs = 0.0.0.0/0, ::/0".to_string(),
        format!("Endpoint = {endpoint_host}:{endpoint_port}"),
        "PersistentKeepalive = 25".to_string(),
    ]);
    lines.join("\n") + "\n"
}

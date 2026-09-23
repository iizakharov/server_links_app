//! Split tunneling entries (sites and networks) -> addresses. Shared by the macOS and Windows sides.
use std::net::{IpAddr, ToSocketAddrs};

/// Split-tunnel entries -> networks. Domains are resolved now (IPv4); addresses and networks are taken as is.
pub fn resolve_entries(entries: &[String], resolve: impl Fn(&str) -> Vec<IpAddr>) -> (Vec<String>, Vec<String>) {
    let (mut nets, mut failed) = (vec![], vec![]);
    for e in entries.iter().map(|e| e.trim()).filter(|e| !e.is_empty() && !e.starts_with('#')) {
        let host = e.trim_start_matches("https://").trim_start_matches("http://").split('/').next().unwrap_or(e);
        if e.split('/').next().is_some_and(|ip| ip.parse::<IpAddr>().is_ok()) {
            nets.push(if e.contains('/') { e.to_string() } else { host.to_string() });
            continue;
        }
        let ips: Vec<IpAddr> = resolve(host).into_iter().filter(|ip| ip.is_ipv4()).collect();
        if ips.is_empty() {
            failed.push(host.to_string());
        }
        nets.extend(ips.iter().map(|ip| ip.to_string()));
    }
    nets.sort();
    nets.dedup();
    (nets, failed)
}

pub fn system_resolve(host: &str) -> Vec<IpAddr> {
    (host, 0).to_socket_addrs().map(|a| a.map(|a| a.ip()).collect()).unwrap_or_default()
}

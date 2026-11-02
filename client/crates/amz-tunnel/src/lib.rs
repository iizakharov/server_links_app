//! AMneZinu tunnel: amneziawg-go device + OS routes and DNS. Runs inside the privileged helper.

pub mod awg;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub mod macos_dns;
pub mod split;
pub mod preparation;
pub mod windows;

/// Local destinations must keep the OS route, including routes owned by another VPN.
pub const LOCAL_NETWORKS: &[&str] = &[
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
    "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32",
    "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
];

/// Local networks minus `keep`: what the user asked into the tunnel (our DNS, explicit "only" entries).
pub fn local_exclusions(keep: &[String]) -> Vec<String> {
    windows::routes(&LOCAL_NETWORKS.iter().map(|n| n.to_string()).collect::<Vec<_>>(), keep)
}

pub fn exclude_local(entries: &[String], allow_lan: bool, keep: &[String]) -> Vec<String> {
    if !allow_lan { return entries.to_vec(); }
    windows::routes(entries, &local_exclusions(keep))
}

/// Addresses that stay in the tunnel despite `allow_lan`. Resolved domains are not here on purpose:
/// a corporate name resolving to 10.x must keep the other VPN's route.
pub fn keep_in_tunnel(dns: &[std::net::IpAddr], split: &amz_ipc::Split) -> Vec<String> {
    let mut keep: Vec<String> = dns.iter().map(ToString::to_string).collect();
    if split.mode == amz_ipc::SplitMode::Only {
        keep.extend(preparation::known_entries(&split.entries));
    }
    keep
}

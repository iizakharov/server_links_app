//! Parsing of macOS tool output (captured from a real Mac with another VPN connected).
#![cfg(target_os = "macos")]
use amz_tunnel::macos::{parse_gateway, parse_services, tunnel_routes};

#[test]
fn gateway_skips_other_vpn_defaults() {
    let netstat = "Routing tables\n\nInternet:\nDestination        Gateway            Flags               Netif Expire\n\
                   default            link#23            UCSg                utun8       \n\
                   default            10.28.32.1         UGScIg                en0       \n\
                   10.28.32/22        link#14            UCS                   en0      !\n";
    assert_eq!(parse_gateway(netstat).unwrap(), ["-gateway", "10.28.32.1"]);
    assert_eq!(parse_gateway("default            link#5            UCS    en1\n").unwrap(), ["-interface", "en1"]);
    assert_eq!(parse_gateway("default fe80::1%en0 UGcIg en0\n").unwrap(), ["-gateway", "fe80::1"]);
    assert!(parse_gateway("default link#23 UCSg utun8\n").is_none());
}

#[test]
fn services_are_hardware_only() {
    let order = "An asterisk (*) denotes that a network service is disabled.\n\
                 (1) Realtek LAN\n(Hardware Port: Realtek LAN, Device: en5)\n\n\
                 (2) Thunderbolt Bridge\n(Hardware Port: Thunderbolt Bridge, Device: bridge0)\n\n\
                 (3) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n\n\
                 (4) MyPraga (192.124.172.19) awg\n(Hardware Port: com.amnezia.awg, Device: )\n\n\
                 (*) Old LAN\n(Hardware Port: USB LAN, Device: en7)\n";
    assert_eq!(parse_services(order), ["Realtek LAN", "Thunderbolt Bridge", "Wi-Fi"]);
}

#[test]
fn full_tunnel_routes_are_split_in_halves() {
    let r = tunnel_routes(&["0.0.0.0/0".into(), "::/0".into(), "10.0.0.0/8".into()]);
    assert_eq!(r, [(false, "0.0.0.0/1".into()), (false, "128.0.0.0/1".into()), (true, "::/1".into()),
                   (true, "8000::/1".into()), (false, "10.0.0.0/8".into())]);
}

#[test]
fn split_entries_accept_domains_addresses_and_networks() {
    use amz_tunnel::macos::resolve_entries;
    let entries: Vec<String> = ["youtube.com", "https://kinopoisk.ru/film/1", "1.2.3.4", "10.0.0.0/8", "", "# comment", "nx.invalid", "2001:db8::1"]
        .map(String::from).to_vec();
    let (nets, failed) = resolve_entries(&entries, |host| match host {
        "youtube.com" => vec!["142.250.1.1".parse().unwrap(), "2a00::1".parse().unwrap()],
        "kinopoisk.ru" => vec!["93.158.134.1".parse().unwrap(), "142.250.1.1".parse().unwrap()],
        _ => vec![],
    });
    assert_eq!(nets, ["1.2.3.4", "10.0.0.0/8", "142.250.1.1", "2001:db8::1", "93.158.134.1"]);
    assert_eq!(failed, ["nx.invalid"]);
}

#[test]
fn kill_switch_lets_out_only_tunnel_server_dhcp_and_lan() {
    use amz_tunnel::macos::kill_switch_rules;
    let r = kill_switch_rules("utun9", "198.51.100.1:60006".parse().unwrap(), true);
    assert!(r.contains("pass out quick on utun9 all"));
    assert!(r.contains("to 198.51.100.1 port 60006"));
    assert!(r.contains("192.168.0.0/16"));
    assert!(r.trim_end().ends_with("block drop out all"));
    assert!(!kill_switch_rules("utun9", "198.51.100.1:60006".parse().unwrap(), false).contains("192.168"));
    // pf itself accepts the rules (parse only)
    let path = std::env::temp_dir().join("amz-ks-test.pf");
    std::fs::write(&path, &r).unwrap();
    let out = std::process::Command::new("pfctl").args(["-n", "-f"]).arg(&path).output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success() || err.contains("Permission denied") || err.contains("Operation not permitted"), "{err}");
    let _ = std::fs::remove_file(path);
}

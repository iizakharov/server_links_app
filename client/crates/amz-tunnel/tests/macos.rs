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

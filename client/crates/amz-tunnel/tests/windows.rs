//! Windows routes: the tunnel covers AllowedIPs minus the server and the "except" sites.
use amz_core::tunnel::tunnel_config;
use amz_ipc::{Split, SplitMode, UpOptions};
use amz_tunnel::windows::{plan, routes};

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

fn v4_size(routes: &[String]) -> u64 {
    routes.iter().filter(|n| !n.contains(':'))
        .map(|n| 1u64 << (32 - n.split('/').nth(1).unwrap().parse::<u32>().unwrap())).sum()
}

#[test]
fn whole_internet_is_split_in_halves() {
    assert_eq!(routes(&s(&["0.0.0.0/0", "::/0"]), &[]), s(&["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"]));
    assert_eq!(routes(&s(&["10.0.0.0/8", "1.2.3.4"]), &[]), s(&["10.0.0.0/8", "1.2.3.4/32"]));
}

#[test]
fn excluded_address_is_cut_out() {
    let r = routes(&s(&["0.0.0.0/0"]), &s(&["5.6.7.8"]));
    assert_eq!(r.len(), 32);
    assert!(r.contains(&"0.0.0.0/6".to_string()) && r.contains(&"5.6.7.9/32".to_string()));
    assert!(!r.iter().any(|n| n == "5.6.7.8/32"));
    // what is left covers exactly 2^32 - 1 addresses
    assert_eq!(v4_size(&r), (1u64 << 32) - 1);
    // IPv6 is untouched by an IPv4 exclusion; a network inside an excluded one disappears
    assert_eq!(routes(&s(&["::/0"]), &s(&["5.6.7.8"])), s(&["::/1", "8000::/1"]));
    assert_eq!(routes(&s(&["10.1.0.0/16"]), &s(&["10.0.0.0/8"])), Vec::<String>::new());
    assert_eq!(routes(&s(&["10.0.0.0/8"]), &s(&["10.128.0.0/9", "junk"])), s(&["10.0.0.0/9"]));
}

const CONF: &str = "[Interface]\nPrivateKey = aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd28=\nAddress = 10.9.3.2/32\n\
DNS = 1.1.1.1, 1.0.0.1\n\n[Peer]\nPublicKey = aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd28=\n\
Endpoint = 5.6.7.8:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n";

#[test]
fn plan_by_split_mode() {
    let cfg = tunnel_config(CONF, |_, _| None).unwrap();
    let opts = |mode, kill| UpOptions { kill_switch: kill, allow_lan: false, split: Split { mode, entries: vec![] } };

    let all = plan(&cfg, &opts(SplitMode::All, true), &[]);
    assert!(all.kill_switch && !all.allow_lan);
    assert_eq!((all.addresses.clone(), all.dns.clone(), all.mtu), (s(&["10.9.3.2/32"]), s(&["1.1.1.1", "1.0.0.1"]), 1280));
    assert_eq!(all.routes.len(), 32 + 2);
    assert!(!all.routes.contains(&"5.6.7.8/32".to_string()));

    let only = plan(&cfg, &opts(SplitMode::Only, true), &s(&["9.9.9.9", "5.6.7.8"]));
    assert_eq!((only.routes, only.dns, only.kill_switch), (s(&["9.9.9.9/32"]), vec![], false));

    let except = plan(&cfg, &opts(SplitMode::Except, false), &s(&["9.9.9.9"]));
    assert_eq!(v4_size(&except.routes), (1u64 << 32) - 2);
    assert!(!except.routes.iter().any(|r| r == "9.9.9.9/32" || r == "5.6.7.8/32"));
}

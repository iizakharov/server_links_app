use amz_tunnel::{exclude_local, keep_in_tunnel, windows::routes};
use amz_ipc::{Split, SplitMode};

fn s(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| s.to_string()).collect()
}

#[test]
fn local_destinations_keep_the_os_route_even_inside_broad_entries() {
    let all = s(&["0.0.0.0/0", "::/0"]);
    let public = exclude_local(&all, true, &[]);
    for local in ["10.2.3.3", "10.2.3.1", "172.16.1.1", "192.168.1.1", "169.254.1.1", "127.0.0.1", "fd00::1", "fe80::1", "::1", "ff02::1"] {
        // Subtracting any local host from the result must not change it.
        assert_eq!(routes(&public, &s(&[local])), public, "{local}");
    }
    for public_host in ["1.1.1.1", "172.32.0.1", "192.169.1.1", "2606:4700:4700::1111"] {
        assert_ne!(routes(&public, &s(&[public_host])), public, "{public_host}");
    }
    assert_eq!(exclude_local(&all, false, &[]), all);
    assert!(exclude_local(&s(&["10.0.0.0/8", "10.2.3.3", "fd00::1"]), true, &[]).is_empty());
}

#[test]
fn tunnel_dns_and_explicit_only_entries_stay_in_the_tunnel() {
    let dns = ["172.29.172.254".parse().unwrap()];
    let only = Split { mode: SplitMode::Only, entries: s(&["10.0.5.0/24", "nas.home.example"]) };
    let keep = keep_in_tunnel(&dns, &only);
    assert_eq!(keep, s(&["172.29.172.254", "10.0.5.0/24"]), "resolved names are never kept");
    let public = exclude_local(&s(&["0.0.0.0/0"]), true, &keep);
    for kept in ["172.29.172.254", "10.0.5.7"] {
        assert_ne!(routes(&public, &s(&[kept])), public, "{kept} must stay routed");
    }
    for local in ["10.0.6.1", "172.29.172.253", "192.168.1.1"] {
        assert_eq!(routes(&public, &s(&[local])), public, "{local}");
    }
    let except = Split { mode: SplitMode::Except, entries: s(&["10.0.5.0/24"]) };
    assert_eq!(keep_in_tunnel(&[], &except), Vec::<String>::new());
}

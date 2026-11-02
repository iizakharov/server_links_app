#![cfg(target_os = "macos")]
use std::{io::Write, process::{Command, Stdio}};
use amz_tunnel::macos_dns::{clear_script, install_script, other_vpn};

#[test]
fn corporate_dns_comes_from_other_vpn_not_wifi_or_our_tunnel() {
    let output = "DNS configuration\n\nresolver #1\n nameserver[0] : 8.8.8.8\n search domain[0] : home.lan\n if_index : 11 (en0)\n\
                  resolver #2\n nameserver[0] : 1.1.1.1\n domain : ours.example\n if_index : 24 (utun9)\n\
                  resolver #3\n nameserver[0] : 10.208.3.190\n nameserver[1] : 10.209.3.190\n search domain[0] : Corp.Example.\n if_index : 23 (utun8)\n\
                  resolver #4\n domain : 3.208.10.in-addr.arpa\n nameserver[0] : 10.208.3.190\n if_index : 23 (utun8)\n\
                  resolver #5\n domain : dev.corp.example\n nameserver[0] : 10.208.3.190\n if_index : 23 (utun8)\n\
                  resolver #6\n domain : other.example\n nameserver[0] : 10.7.0.1\n if_index : 30 (ppp0)\n\
                  DNS configuration (for scoped queries)\n\nresolver #1\n nameserver[0] : 10.208.3.190\n search domain[0] : corp.example\n if_index : 23 (utun8)\n";
    let found = other_vpn(output, "utun9");
    assert_eq!(found.servers.iter().map(ToString::to_string).collect::<Vec<_>>(), ["10.208.3.190", "10.209.3.190"]);
    assert_eq!(found.domains, ["corp.example", "dev.corp.example"]);
    let ours = other_vpn("resolver #1\n nameserver[0] : 1.1.1.1\n domain : ours.example\n if_index : 24 (utun9)\n", "utun9");
    assert!(ours.servers.is_empty() && ours.domains.is_empty());
    // A catch-all corporate resolver announces no domains: the caller must leave it alone.
    let bare = other_vpn("resolver #1\n nameserver[0] : 10.2.3.1\n if_index : 24 (utun8)\n", "utun9");
    assert!(!bare.servers.is_empty() && bare.domains.is_empty());
}

#[test]
fn scutil_accepts_typed_resolvers_without_modifying_system_state() {
    let domains = ["corp.example".to_string(), "dev.corp.example".into(), "corp2.example".into()];
    let script = install_script(&["1.1.1.1".parse().unwrap()], &["10.208.3.190".parse().unwrap()], &domains);
    // Exercise the real scutil parser but only display dictionaries, never install them.
    let preview = script.lines().map(|line| if line.starts_with("set ") { "d.show" } else { line })
        .collect::<Vec<_>>().join("\n") + "\n";
    let mut child = Command::new("scutil").stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(preview.as_bytes()).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(text.matches("SearchOrder : 1").count(), 2, "{text}");
    assert_eq!(text.matches("SupplementalMatchOrders : <array>").count(), 2, "{text}");
    assert!(text.contains("SupplementalMatchOrders : <array> {\n    0 : 1\n    1 : 1\n    2 : 1\n  }"), "one order per domain: {text}");
    assert!(!text.contains("*#"), "scutil requires separate array and number flags: {text}");
    assert!(text.contains("0 : corp.example") && text.contains("1 : dev.corp.example") && text.contains("2 : corp2.example"), "{text}");
    assert!(text.contains("0 : \n"), "the default resolver must have an empty match domain: {text}");
    assert!(text.contains("0 : 10.208.3.190") && text.contains("0 : 1.1.1.1"));
}

#[test]
fn cleanup_removes_only_our_two_resolvers_and_old_state_still_loads() {
    let clear = clear_script();
    assert_eq!(clear.lines().filter(|l| l.starts_with("remove ")).count(), 2);
    assert!(clear.lines().filter(|l| l.starts_with("remove ")).all(|l| l.starts_with("remove State:/Network/Service/com.amnezinu.vpn.")));
    let mut old = serde_json::to_value(amz_tunnel::macos::NetState::default()).unwrap();
    old.as_object_mut().unwrap().remove("split_dns");
    let old: amz_tunnel::macos::NetState = serde_json::from_value(old).unwrap();
    assert!(!old.split_dns);
}

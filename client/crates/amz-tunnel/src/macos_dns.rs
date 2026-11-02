//! Temporary resolvers owned by AMneZinu; never rewrite another VPN's DNS state.
use std::{io::Write, net::IpAddr, process::{Command, Stdio}};
use anyhow::{bail, Result};

const PUBLIC_KEY: &str = "State:/Network/Service/com.amnezinu.vpn.public/DNS";
const CORPORATE_KEY: &str = "State:/Network/Service/com.amnezinu.vpn.corporate/DNS";

/// Resolvers of another VPN interface: its servers and the domains it announces.
#[derive(Debug, Default, PartialEq)]
pub struct OtherVpn {
    pub servers: Vec<IpAddr>,
    pub domains: Vec<String>,
}

pub fn other_vpn(output: &str, iface: &str) -> OtherVpn {
    let value = |line: &str, key: &str| line.trim().strip_prefix(key)
        .and_then(|rest| rest.split_once(':')).map(|(_, v)| v.trim().to_string());
    let mut found = OtherVpn::default();
    let mut found_dev: Option<String> = None;
    for resolver in output.split("resolver #") {
        let Some(dev) = resolver.lines().find_map(|line| {
            let (_, rest) = line.trim().strip_prefix("if_index")?.split_once('(')?;
            let dev = rest.trim_end_matches(')').trim();
            (dev != iface && ["utun", "ipsec", "ppp"].iter().any(|p| dev.starts_with(p))).then(|| dev.to_string())
        }) else { continue };
        match &found_dev {
            // The same interface repeats in the scoped section; never mix two other VPNs.
            Some(d) if *d != dev => continue,
            Some(_) => {}
            None => {
                let servers: Vec<IpAddr> = resolver.lines()
                    .filter_map(|line| value(line, "nameserver[")?.parse().ok()).collect();
                if servers.is_empty() { continue; }
                found.servers = servers;
                found_dev = Some(dev);
            }
        }
        for line in resolver.lines() {
            let Some(domain) = value(line, "domain").or_else(|| value(line, "search domain[")) else { continue };
            if let Some(domain) = normalize_domain(&domain) {
                if !found.domains.contains(&domain) { found.domains.push(domain); }
            }
        }
    }
    found
}

/// `Corp.Example.` -> `corp.example`; empty and reverse-lookup zones are skipped.
pub fn normalize_domain(domain: &str) -> Option<String> {
    let d = domain.trim().trim_matches('.').to_lowercase();
    (!d.is_empty() && !d.contains(char::is_whitespace) && !d.ends_with(".arpa")).then_some(d)
}

pub fn install_script(public: &[IpAddr], corporate: &[IpAddr], domains: &[String]) -> String {
    let servers = |ips: &[IpAddr]| ips.iter().map(ToString::to_string).collect::<Vec<_>>().join(" ");
    // Empty match domain is the default. Exact suffixes take precedence over it.
    // Order 1 beats the corporate VPN's catch-all resolver without editing it.
    format!("d.init\nd.add ServerAddresses * {}\nd.add SupplementalMatchDomains * {}\nd.add SearchOrder # 1\nd.add SupplementalMatchOrders * # {}\nd.add SupplementalMatchDomainsNoSearch # 1\nset {CORPORATE_KEY}\n\
             d.init\nd.add ServerAddresses * {}\nd.add SupplementalMatchDomains * \"\"\nd.add SearchOrder # 1\nd.add SupplementalMatchOrders * # 1\nd.add SupplementalMatchDomainsNoSearch # 1\nset {PUBLIC_KEY}\nquit\n",
            servers(corporate), domains.join(" "), vec!["1"; domains.len()].join(" "), servers(public))
}

pub fn clear_script() -> String {
    format!("remove {PUBLIC_KEY}\nremove {CORPORATE_KEY}\nquit\n")
}

fn scutil(script: &str, clearing: bool) -> Result<String> {
    let mut child = Command::new("scutil").stdin(Stdio::piped())
        .stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    child.stdin.take().unwrap().write_all(script.as_bytes())?;
    let output = child.wait_with_output()?;
    let messages = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    // scutil can report a failed command on stdout while exiting successfully.
    if !output.status.success() || messages.lines().any(|l| {
        !l.trim().is_empty() && !(clearing && l.trim() == "No such key")
    }) {
        bail!("scutil DNS: {}", messages.trim());
    }
    Ok(messages)
}

pub fn install(public: &[IpAddr], corporate: &[IpAddr], domains: &[String]) -> Result<()> {
    if public.is_empty() || corporate.is_empty() { bail!("Для раздельного DNS нужны обе группы серверов"); }
    if domains.is_empty() { bail!("Для раздельного DNS нужны корпоративные домены"); }
    scutil(&install_script(public, corporate, domains), false)?;
    refresh_cache();
    Ok(())
}

pub fn clear() -> Result<()> {
    let messages = scutil(&clear_script(), true)?;
    // Both keys missing: nothing changed, keep the cache.
    if messages.lines().filter(|l| l.trim() == "No such key").count() < 2 { refresh_cache(); }
    Ok(())
}

fn refresh_cache() {
    // Discard NXDOMAIN cached before the resolver changed. A cache flush failure
    // must not prevent cleanup of an otherwise disconnected tunnel.
    for (cmd, args) in [("dscacheutil", &["-flushcache"][..]), ("killall", &["-HUP", "mDNSResponder"][..])] {
        match Command::new(cmd).args(args).output() {
            Ok(out) if out.status.success() => {},
            other => eprintln!("amz-helper: не удалось обновить DNS-кеш ({cmd}): {other:?}"),
        }
    }
}

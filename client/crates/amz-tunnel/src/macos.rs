//! macOS network side of a tunnel: interface address, routes, DNS. Everything that is changed is
//! recorded in `NetState`, so it can be undone on Down or after a crash.
use std::io::Write;
use std::net::{IpAddr, ToSocketAddrs};
use std::process::{Command, Stdio};

use amz_core::tunnel::TunnelConfig;
use amz_ipc::{SplitMode, UpOptions};
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct NetState {
    pub iface: String,
    /// host route to the server outside the tunnel: (ip, "-gateway x" or "-interface enX")
    pub endpoint_route: Option<(String, Vec<String>)>,
    /// DNS of network services before we changed them (empty list = were not set)
    pub dns_backup: Vec<(String, Vec<String>)>,
    /// networks sent around the tunnel via the physical gateway (split tunneling "except")
    pub bypass: Vec<String>,
    /// kill switch rules loaded in our pf anchor; token from `pfctl -E`
    pub kill_switch: bool,
    pub pf_token: Option<String>,
    /// split tunneling as requested, to re-resolve domains later (their addresses change)
    #[serde(default)]
    pub split: amz_ipc::Split,
    /// networks routed into the tunnel in "only" mode
    #[serde(default)]
    pub only_routes: Vec<String>,
}

const PF_ANCHOR: &str = "com.apple/amnezinu";

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

/// pf rules: only the tunnel, the server itself, DHCP and (optionally) the local network get out.
pub fn kill_switch_rules(iface: &str, endpoint: std::net::SocketAddr, allow_lan: bool) -> String {
    let fam = if endpoint.is_ipv6() { "inet6" } else { "inet" };
    let mut r = vec![
        "pass out quick on lo0 all".to_string(),
        format!("pass out quick on {iface} all"),
        format!("pass out quick {fam} proto udp from any to {} port {}", endpoint.ip(), endpoint.port()),
        "pass out quick inet proto udp from any port 68 to any port 67".into(),
    ];
    if allow_lan {
        r.push("pass out quick inet from any to { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255 }".into());
        r.push("pass out quick inet6 from any to { fe80::/10, ff00::/8 }".into());
    }
    r.push("block drop out all".into());
    r.join("\n") + "\n"
}

fn pf_load(rules: &str) -> Result<()> {
    let mut child = Command::new("pfctl").args(["-a", PF_ANCHOR, "-f", "-"])
        .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn()?;
    child.stdin.take().unwrap().write_all(rules.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("pfctl: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

fn pf_enable() -> Result<String> {
    let out = Command::new("pfctl").arg("-E").output()?;
    let text = String::from_utf8_lossy(&out.stderr).to_string() + &String::from_utf8_lossy(&out.stdout);
    text.lines().find_map(|l| l.strip_prefix("Token : ").map(|t| t.trim().to_string()))
        .ok_or_else(|| anyhow!("pfctl -E: {}", text.trim()))
}

/// Blocks everything except the tunnel (kill switch). Records what to undo in `state`.
pub fn kill_switch_on(iface: &str, endpoint: std::net::SocketAddr, allow_lan: bool, state: &mut NetState) -> Result<()> {
    pf_load(&kill_switch_rules(iface, endpoint, allow_lan))?;
    state.kill_switch = true;
    state.pf_token = Some(pf_enable()?);
    Ok(())
}

fn kill_switch_off(state: &NetState) -> Vec<String> {
    let mut errors = vec![];
    if state.kill_switch {
        if let Err(e) = run("pfctl", &["-a", PF_ANCHOR, "-F", "all"]) {
            errors.push(e.to_string());
        }
    }
    if let Some(token) = &state.pf_token {
        if let Err(e) = run("pfctl", &["-X", token]) {
            errors.push(e.to_string());
        }
    }
    errors
}

/// After a crash with the kill switch on: keep traffic blocked, but drop what pointed to the dead tunnel.
pub fn restore_keep_block(state: &NetState) -> Vec<String> {
    let rest = NetState { kill_switch: false, pf_token: None, ..state.clone() };
    restore(&rest)
}

/// Domains of split tunneling resolve to new addresses over time (CDN): route the new ones too.
/// Old routes stay, a stale address costs nothing. Returns how many routes were added.
pub fn refresh_split(state: &mut NetState) -> Result<usize> {
    if state.split.mode == SplitMode::All {
        return Ok(0);
    }
    let (listed, _) = resolve_entries(&state.split.entries, system_resolve);
    let mut added = 0;
    for net in listed.iter().filter(|n| !n.contains(':')) {
        match state.split.mode {
            SplitMode::Only if !state.only_routes.contains(net) => {
                run("route", &["-q", "-n", "add", "-inet", net, "-interface", &state.iface])?;
                state.only_routes.push(net.clone());
            }
            SplitMode::Except if !state.bypass.contains(net) => {
                let Some((_, gw)) = &state.endpoint_route else { continue };
                let mut args = vec!["-q", "-n", "add", "-inet", net.as_str()];
                args.extend(gw.iter().map(String::as_str));
                run("route", &args)?;
                state.bypass.push(net.clone());
            }
            _ => continue,
        }
        added += 1;
    }
    Ok(added)
}

/// The physical network changed (other Wi-Fi, cable, wake from sleep): re-point routes that go around
/// the tunnel to the new gateway. Returns true if something was changed.
pub fn follow_gateway(state: &mut NetState) -> Result<bool> {
    let Some((ep, old)) = state.endpoint_route.clone() else { return Ok(false) };
    let v6 = ep.contains(':');
    let Ok(gw) = physical_gateway(v6) else { return Ok(false) };
    if gw == old {
        return Ok(false);
    }
    let fam = if v6 { "-inet6" } else { "-inet" };
    for net in std::iter::once(&ep).chain(state.bypass.iter()) {
        let _ = run("route", &["-q", "-n", "delete", fam, net]);
        let mut args = vec!["-q", "-n", "add", fam, net.as_str()];
        args.extend(gw.iter().map(String::as_str));
        run("route", &args)?;
    }
    state.endpoint_route = Some((ep, gw));
    Ok(true)
}

fn run(cmd: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(cmd).args(args).output().map_err(|e| anyhow!("{cmd}: {e}"))?;
    if !out.status.success() {
        bail!("{cmd} {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Default gateway of a physical interface (other VPNs' utun defaults are skipped).
/// Returns route arguments: ["-gateway", ip] or ["-interface", if].
pub fn physical_gateway(v6: bool) -> Result<Vec<String>> {
    let table = run("netstat", &["-rn", "-f", if v6 { "inet6" } else { "inet" }])?;
    parse_gateway(&table).ok_or_else(|| anyhow!("не найден маршрут по умолчанию через сетевой интерфейс"))
}

pub fn parse_gateway(netstat: &str) -> Option<Vec<String>> {
    netstat.lines().filter(|l| l.starts_with("default ")).find_map(|l| {
        let cols: Vec<&str> = l.split_whitespace().collect();
        let (gw, netif) = (*cols.get(1)?, *cols.last()?);
        if ["utun", "ipsec", "ppp", "gif", "stf"].iter().any(|p| netif.starts_with(p)) {
            return None;
        }
        let gw = gw.split('%').next().unwrap_or(gw);
        Some(if gw.parse::<IpAddr>().is_ok() {
            vec!["-gateway".into(), gw.into()]
        } else {
            vec!["-interface".into(), netif.into()]
        })
    })
}

/// Network services backed by real hardware (VPN profiles and disabled services are skipped).
pub fn hardware_services() -> Result<Vec<String>> {
    Ok(parse_services(&run("networksetup", &["-listnetworkserviceorder"])?))
}

pub fn parse_services(order: &str) -> Vec<String> {
    let lines: Vec<&str> = order.lines().collect();
    lines.windows(2).filter_map(|w| {
        let name = w[0].strip_prefix('(')?.split_once(") ")?.1;
        let dev = w[1].split("Device: ").nth(1)?.trim_end_matches(')');
        (!dev.is_empty() && !w[0].starts_with("(*)")).then(|| name.to_string())
    }).collect()
}

fn get_dns(service: &str) -> Result<Vec<String>> {
    let out = run("networksetup", &["-getdnsservers", service])?;
    Ok(out.lines().filter(|l| l.parse::<IpAddr>().is_ok()).map(String::from).collect())
}

fn set_dns(service: &str, servers: &[String]) -> Result<()> {
    let mut args = vec!["-setdnsservers", service];
    if servers.is_empty() {
        args.push("Empty");
    } else {
        args.extend(servers.iter().map(String::as_str));
    }
    run("networksetup", &args).map(|_| ())
}

/// Routes for AllowedIPs: whole-internet networks are split in halves so they win over the default route
/// without replacing it.
pub fn tunnel_routes(allowed: &[String]) -> Vec<(bool, String)> {
    allowed.iter().flat_map(|a| match a.as_str() {
        "0.0.0.0/0" => vec![(false, "0.0.0.0/1".to_string()), (false, "128.0.0.0/1".into())],
        "::/0" => vec![(true, "::/1".to_string()), (true, "8000::/1".into())],
        other => vec![(other.contains(':'), other.to_string())],
    }).collect()
}

pub fn configure(iface: &str, cfg: &TunnelConfig, opts: &UpOptions, state: &mut NetState) -> Result<()> {
    state.iface = iface.into();
    for addr in &cfg.addresses {
        let ip = addr.split('/').next().unwrap_or(addr);
        if addr.contains(':') {
            run("ifconfig", &[iface, "inet6", addr, "alias"])?;
        } else {
            run("ifconfig", &[iface, "inet", addr, ip, "alias"])?;
        }
    }
    run("ifconfig", &[iface, "up"])?;

    let ep = cfg.endpoint.ip();
    let gw = physical_gateway(ep.is_ipv6())?;
    let fam = if ep.is_ipv6() { "-inet6" } else { "-inet" };
    let ep_s = ep.to_string();
    let _ = run("route", &["-q", "-n", "delete", fam, &ep_s]);
    let mut args = vec!["-q", "-n", "add", fam, &ep_s];
    args.extend(gw.iter().map(String::as_str));
    run("route", &args)?;
    state.endpoint_route = Some((ep_s.clone(), gw.clone()));

    let (listed, failed) = resolve_entries(&opts.split.entries, system_resolve);
    if opts.split.mode != SplitMode::All && !failed.is_empty() {
        eprintln!("amz-helper: не удалось найти адреса: {}", failed.join(", "));
    }
    state.split = opts.split.clone();
    if opts.split.mode == SplitMode::Only {
        state.only_routes = listed.clone();
    }
    let routes: Vec<(bool, String)> = match opts.split.mode {
        // only the listed sites (and our DNS servers, so names resolve the same way) go into the tunnel
        SplitMode::Only => listed.iter().map(|n| (n.contains(':'), n.clone())).collect(),
        _ => tunnel_routes(&cfg.allowed_ips),
    };
    for (v6, net) in routes {
        if net.split('/').next() == Some(ep_s.as_str()) {
            continue;
        }
        run("route", &["-q", "-n", "add", if v6 { "-inet6" } else { "-inet" }, &net, "-interface", iface])?;
    }
    if opts.split.mode == SplitMode::Except {
        for net in listed.iter().filter(|n| !n.contains(':')) {
            let _ = run("route", &["-q", "-n", "delete", "-inet", net]);
            let mut args = vec!["-q", "-n", "add", "-inet", net.as_str()];
            args.extend(gw.iter().map(String::as_str));
            run("route", &args)?;
            state.bypass.push(net.clone());
        }
    }

    if opts.kill_switch && opts.split.mode == SplitMode::All {
        kill_switch_on(iface, cfg.endpoint, opts.allow_lan, state)?;
    }

    // in "only" mode the rest of the traffic is not ours: leave the system DNS alone
    if !cfg.dns.is_empty() && opts.split.mode != SplitMode::Only {
        let dns: Vec<String> = cfg.dns.iter().map(|d| d.to_string()).collect();
        for svc in hardware_services()? {
            let before = get_dns(&svc)?;
            state.dns_backup.push((svc.clone(), before));
            set_dns(&svc, &dns)?;
        }
    }
    Ok(())
}

/// Undoes what `configure` did; tunnel routes go away with the interface. Best effort: collects errors.
pub fn restore(state: &NetState) -> Vec<String> {
    let mut errors = kill_switch_off(state);
    for net in &state.bypass {
        let _ = run("route", &["-q", "-n", "delete", "-inet", net]);
    }
    for (svc, servers) in &state.dns_backup {
        if let Err(e) = set_dns(svc, servers) {
            errors.push(e.to_string());
        }
    }
    if let Some((ip, _)) = &state.endpoint_route {
        let fam = if ip.contains(':') { "-inet6" } else { "-inet" };
        if let Err(e) = run("route", &["-q", "-n", "delete", fam, ip]) {
            errors.push(e.to_string());
        }
    }
    errors
}

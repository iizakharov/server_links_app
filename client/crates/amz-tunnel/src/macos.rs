//! macOS network side of a tunnel: interface address, routes, DNS. Everything that is changed is
//! recorded in `NetState`, so it can be undone on Down or after a crash.
use std::net::IpAddr;
use std::process::Command;

use amz_core::tunnel::TunnelConfig;
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct NetState {
    pub iface: String,
    /// host route to the server outside the tunnel: (ip, "-gateway x" or "-interface enX")
    pub endpoint_route: Option<(String, Vec<String>)>,
    /// DNS of network services before we changed them (empty list = were not set)
    pub dns_backup: Vec<(String, Vec<String>)>,
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

pub fn configure(iface: &str, cfg: &TunnelConfig, state: &mut NetState) -> Result<()> {
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

    for (v6, net) in tunnel_routes(&cfg.allowed_ips) {
        if net.split('/').next() == Some(ep_s.as_str()) {
            continue;
        }
        run("route", &["-q", "-n", "add", if v6 { "-inet6" } else { "-inet" }, &net, "-interface", iface])?;
    }

    if !cfg.dns.is_empty() {
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
    let mut errors = vec![];
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

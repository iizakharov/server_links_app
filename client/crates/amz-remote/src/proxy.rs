//! Proxy side: read-only scan of existing NAT forwards, conflict checks, and our own UDP DNAT rules.
//! Our rules live only in chains CASCADE_PRE/CASCADE_POST/CASCADE_FWD; rules of other tools are never modified.
//! Port of `app/proxy.py`.
use std::collections::HashSet;
use std::time::Duration;

use amz_core::awg::INSTANCES;
use amz_core::model::{NatRule, Scan, Server};
use anyhow::{bail, Result};

use crate::foreign;
use crate::remote::{Log, Remote};

pub const SCRIPT_PATH: &str = "/usr/local/sbin/cascade-rules.sh";
pub const UNIT_PATH: &str = "/etc/systemd/system/cascade-rules.service";
const OUR_CHAIN: &str = "CASCADE_PRE";

// netfilter-persistent/ufw restore whole tables on boot, so our rules must be added after them
pub const UNIT: &str = "[Unit]
Description=AmneziaWG cascade UDP forwarding rules
After=network-online.target docker.service netfilter-persistent.service ufw.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/cascade-rules.sh

[Install]
WantedBy=multi-user.target
";

// ---------- scan (read-only) ----------

/// DNAT rules from `iptables-save -t nat` in PREROUTING (external) and CASCADE_PRE (ours).
pub fn parse_nat(text: &str) -> Vec<NatRule> {
    text.lines().filter(|l| l.starts_with("-A ")).filter_map(parse_rule).collect()
}

fn parse_rule(line: &str) -> Option<NatRule> {
    let t = shlex::split(line)?;
    let chain = t.get(1)?.as_str();
    if !(chain == "PREROUTING" || chain == OUR_CHAIN) || !t.iter().any(|x| x == "DNAT") || t.iter().any(|x| x == "!") {
        return None;
    }
    let mut rule = NatRule { chain: chain.into(), ours: chain == OUR_CHAIN, raw: line.into(), ..Default::default() };
    for w in t.windows(2) {
        let (tok, nxt) = (w[0].as_str(), w[1].as_str());
        match tok {
            "-p" => rule.proto = Some(nxt.into()),
            "-d" => rule.dst = Some(nxt.strip_suffix("/32").unwrap_or(nxt).into()),
            "--dport" | "--dports" | "--destination-port" | "--destination-ports" => {
                let ranges: Option<Vec<(u32, u32)>> = nxt.split(',').map(|p| {
                    let (a, b) = p.split_once(':').unwrap_or((p, ""));
                    let a: u32 = a.parse().ok()?;
                    Some((a, if b.is_empty() { a } else { b.parse().ok()? }))
                }).collect();
                rule.dports = Some(ranges?);
            }
            "--to-destination" => {
                let (ip, port) = nxt.split_once(':').unwrap_or((nxt, ""));
                rule.to_ip = Some(ip.into());
                rule.to_port = if port.is_empty() { None } else { Some(port.split('-').next()?.parse().ok()?) };
            }
            "--comment" => rule.comment = Some(nxt.into()),
            _ => {}
        }
    }
    rule.to_ip.as_deref().is_some_and(|ip| !ip.is_empty()).then_some(rule)
}

pub async fn scan<R: Remote>(r: &mut R) -> Result<Scan> {
    let mut s = Scan {
        os: r.run_ok(". /etc/os-release 2>/dev/null; echo $PRETTY_NAME").await?.trim().into(),
        awg: foreign::detect(r).await?,
        ..Default::default()
    };
    for inst in INSTANCES {
        let info = foreign::detect_instance(r, inst.key).await?;
        s.set_awg(inst.key, info);
    }
    s.nat = parse_nat(&r.run_ok("iptables-save -t nat 2>/dev/null || true").await?);
    s.udp_listen = foreign::parse_udp_listen(&r.run_ok("ss -Huln 2>/dev/null || true").await?);
    s.at = chrono::Local::now().format("%Y-%m-%d %H:%M").to_string();
    Ok(s)
}

// ---------- analysis ----------

pub fn covers(rule: &NatRule, proto: &str, port: u32) -> bool {
    if !matches!(rule.proto.as_deref(), None | Some("all")) && rule.proto.as_deref() != Some(proto) {
        return false;
    }
    match &rule.dports {
        None => true,
        Some(ranges) => ranges.iter().any(|&(lo, hi)| lo <= port && port <= hi),
    }
}

pub fn forwarded_port(rule: &NatRule, port: u32) -> u32 {
    rule.to_port.unwrap_or(port)
}

pub fn describe(rule: &NatRule) -> String {
    let ports = rule.dports.as_deref().unwrap_or_default().iter()
        .map(|&(lo, hi)| if lo == hi { lo.to_string() } else { format!("{lo}:{hi}") })
        .collect::<Vec<_>>().join(",");
    let ports = if ports.is_empty() { "все порты".to_string() } else { ports };
    let mut target = rule.to_ip.clone().unwrap_or_default();
    if let Some(p) = rule.to_port {
        target += &format!(":{p}");
    }
    let note = rule.comment.as_ref().map(|c| format!(" ({c})")).unwrap_or_default();
    format!("{} {ports} → {target}{note}", rule.proto.as_deref().unwrap_or("all"))
}

/// Why `port` cannot be used for a new managed UDP forward on this proxy, or None if it is free.
pub fn port_conflict(port: u32, scan: &Scan, taken: &HashSet<u32>) -> Option<String> {
    if !(1..=65535).contains(&port) {
        return Some(format!("Некорректный порт {port}"));
    }
    if taken.contains(&port) {
        return Some(format!("UDP {port} уже занят другим каскадом этого прокси"));
    }
    if let Some(rule) = scan.nat.iter().find(|r| !r.ours && covers(r, "udp", port)) {
        return Some(format!("UDP {port} уже пробрасывается существующим правилом: {}", describe(rule)));
    }
    if scan.udp_listen.contains(&port) {
        return Some(format!("UDP {port} занят процессом на прокси"));
    }
    None
}

pub fn pick_port(scan: &Scan, taken: &HashSet<u32>, start: u32) -> Result<u32> {
    match (start..65536).chain(1024..start).find(|&p| port_conflict(p, scan, taken).is_none()) {
        Some(p) => Ok(p),
        None => bail!("Нет свободных UDP-портов на прокси"),
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ExternalCascade {
    pub proxy_id: String,
    pub exit_id: String,
    pub port: u32,
    pub rule: String,
}

/// Existing (not ours) forwards proxy -> AmneziaWG port of a known server.
pub fn external_cascades(servers: &[Server], ip_of: impl Fn(&Server) -> String) -> Vec<ExternalCascade> {
    let mut found = vec![];
    for (pi, p) in servers.iter().enumerate() {
        let nat: Vec<&NatRule> = p.scan.iter().flat_map(|s| &s.nat).filter(|r| !r.ours).collect();
        for (ei, e) in servers.iter().enumerate() {
            let Some(awg) = e.scan.as_ref().and_then(|s| s.awg.as_ref()) else { continue };
            if ei == pi {
                continue;
            }
            let (eip, aport) = (ip_of(e), awg.listen_port as u32);
            let cands: Vec<&NatRule> = nat.iter().copied()
                .filter(|r| r.to_ip.as_deref() == Some(eip.as_str()) && matches!(r.proto.as_deref(), None | Some("all") | Some("udp")))
                .collect();
            // explicit single-port relay first
            let hit = cands.iter().find_map(|r| match r.dports.as_deref() {
                Some([(lo, hi)]) if lo == hi && forwarded_port(r, *lo) == aport => Some((*lo, *r)),
                _ => None,
            }).or_else(|| cands.iter().find(|r| r.to_port.is_none() && covers(r, "udp", aport)).map(|r| (aport, *r)));
            if let Some((port, rule)) = hit {
                found.push(ExternalCascade { proxy_id: p.id.clone(), exit_id: e.id.clone(), port, rule: describe(rule) });
            }
        }
    }
    found
}

/// applied | missing | conflict | unknown (proxy not scanned yet).
pub fn managed_status(port: u32, proxy_scan: Option<&Scan>, exit_ip: &str) -> &'static str {
    let Some(scan) = proxy_scan else { return "unknown" };
    if scan.nat.iter().any(|r| !r.ours && covers(r, "udp", port)) {
        return "conflict";
    }
    let ok = scan.nat.iter().any(|r| r.ours && covers(r, "udp", port) && r.to_ip.as_deref() == Some(exit_ip));
    if ok { "applied" } else { "missing" }
}

// ---------- link check ----------

const PROBE_CHAIN: &str = "CASCADE_PROBE";
pub const PROBES: u32 = 5;
pub const PROBE_WAIT: Duration = Duration::from_secs(2);

/// Counting-only rule in raw/PREROUTING: it sees every incoming packet (also ones docker DNATs away)
/// and never changes what happens to it.
async fn probe_begin<R: Remote>(r: &mut R, src_ip: &str, port: u32) -> Result<()> {
    r.run(&format!(
        "iptables -t raw -N {c} 2>/dev/null; iptables -t raw -F {c}; \
         iptables -t raw -A {c} -p udp -s {src_ip} --dport {port} -j RETURN; \
         iptables -t raw -C PREROUTING -j {c} 2>/dev/null || iptables -t raw -I PREROUTING 1 -j {c}", c = PROBE_CHAIN)).await?;
    Ok(())
}

async fn probe_end<R: Remote>(r: &mut R) -> Result<u32> {
    let out = r.run_ok(&format!("iptables -t raw -L {PROBE_CHAIN} -n -v -x 2>/dev/null || true")).await?;
    r.run_ok(&format!(
        "iptables -t raw -D PREROUTING -j {c} 2>/dev/null; iptables -t raw -F {c} 2>/dev/null; \
         iptables -t raw -X {c} 2>/dev/null; true", c = PROBE_CHAIN)).await?;
    Ok(out.lines()
        .filter(|l| l.contains("RETURN"))
        .find_map(|l| l.split_whitespace().next()?.parse().ok())
        .unwrap_or(0))
}

/// Sends PROBES UDP packets sender -> receiver_ip:port and returns how many arrived.
pub async fn udp_reaches<S: Remote, R: Remote>(sender: &mut S, receiver: &mut R, receiver_ip: &str, port: u32) -> Result<u32> {
    probe_begin(receiver, sender.host(), port).await?;
    let sent = sender.run_ok(&format!(
        "for i in $(seq {PROBES}); do echo cascade-probe > /dev/udp/{receiver_ip}/{port} 2>/dev/null || true; done")).await;
    if sent.is_ok() {
        tokio::time::sleep(PROBE_WAIT).await;
    }
    let got = probe_end(receiver).await;
    sent?;
    got
}

/// None if UDP flows both ways, otherwise a human-readable reason the cascade would not work.
pub async fn check_link<P: Remote, E: Remote>(rp: &mut P, re: &mut E, exit_ip: &str, exit_port: u32, back_port: u32,
                                              log: Log<'_>) -> Result<Option<String>> {
    let (ph, eh) = (rp.host().to_string(), re.host().to_string());
    let got = udp_reaches(rp, re, exit_ip, exit_port).await?;
    log(format!("проверка связи: прокси → {eh}:{exit_port} — дошло {got} из {PROBES}"));
    if got == 0 {
        return Ok(Some(format!(
            "UDP с прокси {ph} не доходит до {eh}:{exit_port} (0 из {PROBES}). Трафик блокируется между этими сетями — \
             каскад работать не будет. Нужен другой адрес сервера выхода или другой прокси")));
    }
    let back = udp_reaches(re, rp, &ph, back_port).await?;
    log(format!("проверка связи: {eh} → прокси:{back_port} — дошло {back} из {PROBES}"));
    if back == 0 {
        return Ok(Some(format!(
            "UDP от {eh} не доходит до прокси {ph} (0 из {PROBES}). Ответы сервера выхода не вернутся к клиентам — \
             проверьте firewall хостера прокси")));
    }
    Ok(None)
}

// ---------- apply ----------

/// A route: (proxy_port, exit_ip, exit_port).
pub type Route = (u32, String, u32);

/// Chains are flushed and refilled, so reruns are idempotent.
pub fn rules_script(routes: &[Route]) -> String {
    let mut lines: Vec<String> = [
        "#!/bin/sh",
        "# generated by vpn_service — do not edit, manage cascades in the app instead",
        "sysctl -q -w net.ipv4.ip_forward=1",
        "iptables -t nat -N CASCADE_PRE 2>/dev/null; iptables -t nat -F CASCADE_PRE",
        "iptables -t nat -N CASCADE_POST 2>/dev/null; iptables -t nat -F CASCADE_POST",
        "iptables -N CASCADE_FWD 2>/dev/null; iptables -F CASCADE_FWD",
        "iptables -t nat -C PREROUTING -j CASCADE_PRE 2>/dev/null || iptables -t nat -I PREROUTING -j CASCADE_PRE",
        "iptables -t nat -C POSTROUTING -j CASCADE_POST 2>/dev/null || iptables -t nat -I POSTROUTING -j CASCADE_POST",
        "iptables -C FORWARD -j CASCADE_FWD 2>/dev/null || iptables -I FORWARD -j CASCADE_FWD",
        "iptables -A CASCADE_FWD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
    ].map(String::from).to_vec();
    for (pport, fip, fport) in routes {
        lines.push(format!("iptables -t nat -A CASCADE_PRE -p udp --dport {pport} -j DNAT --to-destination {fip}:{fport}"));
        lines.push(format!("iptables -t nat -A CASCADE_POST -p udp -d {fip} --dport {fport} -j MASQUERADE"));
        lines.push(format!("iptables -A CASCADE_FWD -p udp -d {fip} --dport {fport} -j ACCEPT"));
    }
    lines.join("\n") + "\n"
}

pub async fn setup<R: Remote>(r: &mut R, routes: &[Route], log: Log<'_>) -> Result<()> {
    r.run("command -v iptables >/dev/null || (apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q iptables)").await?;
    r.run("echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-cascade.conf").await?;
    r.put(SCRIPT_PATH, &rules_script(routes), "700").await?;
    r.put(UNIT_PATH, UNIT, "644").await?;
    r.run("systemctl daemon-reload && systemctl enable cascade-rules.service >/dev/null 2>&1 && systemctl restart cascade-rules.service").await?;
    let host = r.host().to_string();
    for (pport, fip, fport) in routes {
        log(format!("[{host}] UDP {pport} → {fip}:{fport}"));
    }
    log(format!("[{host}] правила приложения обновлены ({} маршрутов); чужие правила не тронуты", routes.len()));
    Ok(())
}

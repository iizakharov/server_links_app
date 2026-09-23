//! Windows network side of a tunnel: what the Wintun interface gets (addresses, routes, DNS, kill switch).
//! libawg applies it (winipcfg + WFP). Tunnel routes never cover the server itself, so its traffic keeps
//! following whatever network Windows is on: nothing to re-point when Wi-Fi changes.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use amz_core::tunnel::TunnelConfig;
use amz_ipc::{SplitMode, UpOptions};
use serde::{Deserialize, Serialize};

/// Interface name of the tunnel (a Wintun adapter).
pub const IFACE: &str = "AmnezinuVPN";

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NetPlan {
    pub addresses: Vec<String>,
    pub routes: Vec<String>,
    pub dns: Vec<String>,
    pub mtu: u32,
    /// block everything outside the tunnel (WFP; lifted automatically if the helper dies)
    pub kill_switch: bool,
    /// with the kill switch: still allow the local network
    pub allow_lan: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Net {
    addr: u128,
    len: u8,
    v6: bool,
}

impl Net {
    fn bits(v6: bool) -> u8 {
        if v6 { 128 } else { 32 }
    }

    fn mask(len: u8, v6: bool) -> u128 {
        let full = if v6 { u128::MAX } else { u32::MAX as u128 };
        if len == 0 { 0 } else { (full << (Self::bits(v6) - len)) & full }
    }

    fn parse(s: &str) -> Option<Net> {
        let (ip, len) = match s.trim().split_once('/') {
            Some((ip, len)) => (ip.parse::<IpAddr>().ok()?, Some(len.parse::<u8>().ok()?)),
            None => (s.trim().parse::<IpAddr>().ok()?, None),
        };
        let (addr, v6) = match ip {
            IpAddr::V4(a) => (u32::from(a) as u128, false),
            IpAddr::V6(a) => (u128::from(a), true),
        };
        let len = len.unwrap_or(Self::bits(v6));
        (len <= Self::bits(v6)).then(|| Net { addr: addr & Self::mask(len, v6), len, v6 })
    }

    fn contains(&self, o: &Net) -> bool {
        self.v6 == o.v6 && self.len <= o.len && o.addr & Self::mask(self.len, self.v6) == self.addr
    }

    fn halves(&self) -> [Net; 2] {
        let len = self.len + 1;
        let bit = 1u128 << (Self::bits(self.v6) - len);
        [Net { len, ..*self }, Net { addr: self.addr | bit, len, ..*self }]
    }
}

impl std::fmt::Display for Net {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let ip: IpAddr = if self.v6 { Ipv6Addr::from(self.addr).into() } else { Ipv4Addr::from(self.addr as u32).into() };
        write!(f, "{ip}/{}", self.len)
    }
}

fn subtract(net: Net, exclude: &[Net]) -> Vec<Net> {
    if exclude.iter().any(|e| e.contains(&net)) {
        return vec![];
    }
    if !exclude.iter().any(|e| net.contains(e)) {
        return vec![net];
    }
    net.halves().into_iter().flat_map(|h| subtract(h, exclude)).collect()
}

/// `allowed` minus `exclude`, as the fewest networks. A whole-internet /0 is split in halves, so it wins
/// over the default route of the physical interface. Unparseable entries are skipped.
pub fn routes(allowed: &[String], exclude: &[String]) -> Vec<String> {
    let ex: Vec<Net> = exclude.iter().filter_map(|e| Net::parse(e)).collect();
    allowed.iter().filter_map(|a| Net::parse(a))
        .flat_map(|n| subtract(n, &ex))
        .flat_map(|n| if n.len == 0 { n.halves().to_vec() } else { vec![n] })
        .map(|n| n.to_string())
        .collect()
}

/// `listed`: split-tunnel entries resolved to addresses (see `split::resolve_entries`).
pub fn plan(cfg: &TunnelConfig, opts: &UpOptions, listed: &[String]) -> NetPlan {
    let (allowed, mut exclude) = match opts.split.mode {
        SplitMode::All => (cfg.allowed_ips.clone(), vec![]),
        SplitMode::Only => (listed.to_vec(), vec![]),
        SplitMode::Except => (cfg.allowed_ips.clone(), listed.to_vec()),
    };
    exclude.push(cfg.endpoint.ip().to_string());
    NetPlan {
        addresses: cfg.addresses.clone(),
        routes: routes(&allowed, &exclude),
        // in "only" mode the rest of the traffic is not ours: leave the system DNS alone
        dns: if opts.split.mode == SplitMode::Only { vec![] } else { cfg.dns.iter().map(|d| d.to_string()).collect() },
        mtu: cfg.mtu,
        kill_switch: opts.kill_switch && opts.split.mode == SplitMode::All,
        allow_lan: opts.allow_lan,
    }
}

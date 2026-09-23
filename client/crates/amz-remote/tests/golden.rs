//! Replays SSH transcripts recorded from the reference Python code (tests/golden/gen.py):
//! the Rust port must send exactly the same commands and reach the same results.
use std::collections::{HashSet, VecDeque};
use std::time::Duration;

use amz_core::model::{AwgInfo, Scan, Server};
use amz_remote::{foreign, proxy, Remote};
use anyhow::{anyhow, Result};
use serde_json::Value;

fn fixture(name: &str) -> Value {
    let path = format!("{}/../../fixtures/{name}.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

struct Replay {
    host: String,
    case: String,
    steps: VecDeque<Value>,
    compare_input: bool,
}

impl Replay {
    fn new(case: &Value, i: usize) -> Self {
        let r = &case["remotes"][i];
        Replay {
            host: r["host"].as_str().unwrap().into(),
            case: case["name"].as_str().unwrap().into(),
            steps: r["steps"].as_array().unwrap().iter().cloned().collect(),
            compare_input: case["compare_input"].as_bool().unwrap(),
        }
    }

    fn done(&self) {
        assert!(self.steps.is_empty(), "{}: Rust did not send {:?}", self.case, self.steps.front());
    }
}

impl Remote for Replay {
    fn host(&self) -> &str {
        &self.host
    }

    async fn exec(&mut self, cmd: &str, input: Option<&str>, check: bool, _t: Duration) -> Result<String> {
        let step = self.steps.pop_front().unwrap_or_else(|| panic!("{}: unexpected extra command {cmd}", self.case));
        assert_eq!(cmd, step["cmd"].as_str().unwrap(), "{}", self.case);
        assert_eq!(check, step["check"].as_bool().unwrap(), "{}: check flag of {cmd}", self.case);
        assert_eq!(input.is_some(), !step["input"].is_null(), "{}: stdin of {cmd}", self.case);
        if self.compare_input {
            assert_eq!(input, step["input"].as_str(), "{}: stdin of {cmd}", self.case);
        }
        match step.get("error") {
            Some(e) => Err(anyhow!("{}", e.as_str().unwrap())),
            None => Ok(step["out"].as_str().unwrap().into()),
        }
    }

    async fn reconnect(&mut self) -> Result<()> {
        Ok(())
    }
}

fn case(name: &str) -> Value {
    fixture("transcripts").as_array().unwrap().iter().find(|c| c["name"] == name).unwrap().clone()
}

fn json<T: serde::Serialize>(v: T) -> Value {
    serde_json::to_value(v).unwrap()
}

fn nolog(_: String) {}

#[tokio::test]
async fn detect_matches_python() {
    for name in ["detect_amnezia", "detect_native"] {
        let c = case(name);
        let mut r = Replay::new(&c, 0);
        let info = foreign::detect(&mut r).await.unwrap();
        r.done();
        assert_eq!(json(info), c["result"], "{name}");
    }
    let c = case("detect_instance_v2");
    let mut r = Replay::new(&c, 0);
    let info = foreign::detect_instance(&mut r, "v2").await.unwrap();
    r.done();
    assert_eq!(json(info), c["result"]);
}

#[tokio::test]
async fn add_and_remove_peer_match_python() {
    let info: AwgInfo = serde_json::from_value(case("detect_amnezia")["result"].clone()).unwrap();
    let c = case("add_peer");
    let mut r = Replay::new(&c, 0);
    let mut ips = vec![];
    for name in ["phone", "laptop"] {
        let keys = foreign::add_peer(&mut r, &info, name).await.unwrap();
        assert_eq!(keys.psk.as_deref(), Some("SHAREDPSK"));
        ips.push(keys.ip);
    }
    r.done();
    assert_eq!(json(ips), c["result"]);

    let c = case("remove_peer");
    let mut r = Replay::new(&c, 0);
    foreign::remove_peer(&mut r, &info, "AAA").await.unwrap();
    r.done();
}

#[tokio::test]
async fn peer_stats_match_python() {
    let c = case("peer_stats");
    let mut r = Replay::new(&c, 0);
    let info = AwgInfo { tool: "awg".into(), iface: "awg0".into(), ..Default::default() };
    let stats = foreign::peer_stats(&mut r, &info).await.unwrap();
    r.done();
    assert_eq!(json(stats), c["result"]);
}

#[tokio::test]
async fn proxy_scan_matches_python() {
    let c = case("proxy_scan");
    let mut r = Replay::new(&c, 0);
    let mut scan = json(proxy::scan(&mut r).await.unwrap());
    r.done();
    scan.as_object_mut().unwrap().remove("at");
    // Python writes absent instances as null, Rust leaves them out: the panel reads both the same way
    let mut expected = c["result"].clone();
    expected.as_object_mut().unwrap().retain(|_, v| !v.is_null());
    assert_eq!(scan, expected);
}

#[tokio::test(start_paused = true)]
async fn detached_install_matches_python() {
    let c = case("run_install_reconnects");
    let mut r = Replay::new(&c, 0);
    foreign::run_install(&mut r, &nolog).await.unwrap();
    r.done();

    let c = case("run_install_fails");
    let mut r = Replay::new(&c, 0);
    let err = foreign::run_install(&mut r, &nolog).await.unwrap_err();
    r.done();
    assert_eq!(err.to_string(), c["result"].as_str().unwrap());
}

#[tokio::test(start_paused = true)]
async fn proxy_setup_and_link_check_match_python() {
    let c = case("proxy_setup");
    let mut r = Replay::new(&c, 0);
    let routes = vec![(51820, "1.2.3.4".to_string(), 43210), (51821, "5.6.7.8".to_string(), 40000)];
    proxy::setup(&mut r, &routes, &nolog).await.unwrap();
    r.done();

    for name in ["check_link_ok", "check_link_blocked", "check_link_no_reply"] {
        let c = case(name);
        let (mut rp, mut re) = (Replay::new(&c, 0), Replay::new(&c, 1));
        let res = proxy::check_link(&mut rp, &mut re, "203.0.113.9", 48303, 60001, &nolog).await.unwrap();
        rp.done();
        re.done();
        assert_eq!(json(res), c["result"], "{name}");
    }
}

#[test]
fn proxy_analysis_matches_python() {
    let f = fixture("proxy");
    let text = |k: &str| f[k].as_str().unwrap().to_string();
    assert_eq!(json(proxy::parse_nat(&text("nat_text"))), f["nat"]);
    let extra: Vec<amz_core::model::NatRule> = serde_json::from_value(f["nat_extra"].clone()).unwrap();
    let described: Vec<String> = extra.iter().map(proxy::describe).collect();
    assert_eq!(json(described), f["describe"]);

    let scan = Scan { nat: serde_json::from_value(f["nat"].clone()).unwrap(), udp_listen: vec![60002], ..Default::default() };
    for (port, expected) in f["conflicts"].as_object().unwrap() {
        let got = proxy::port_conflict(port.parse().unwrap(), &scan, &HashSet::from([60003]));
        assert_eq!(json(got), *expected, "port {port}");
    }
    let picks = [
        proxy::pick_port(&scan, &HashSet::new(), 51820).unwrap(),
        proxy::pick_port(&scan, &HashSet::from([60003]), 51820).unwrap(),
        proxy::pick_port(&scan, &HashSet::new(), 500).unwrap(),
    ];
    assert_eq!(json(picks), f["pick_port"]);
    let statuses: Vec<&str> = [60001, 60005, 50000].iter().map(|&p| proxy::managed_status(p, Some(&scan), "203.0.113.9")).collect();
    assert_eq!(json(statuses), f["managed_status"]);
    assert_eq!(proxy::managed_status(60001, None, "203.0.113.9"), "unknown");

    let servers: Vec<Server> = f["servers"].as_array().unwrap().iter().map(|s| {
        let mut s = s.clone();
        s["scan"] = json(serde_json::from_value::<Scan>(s["scan"].clone()).unwrap());
        serde_json::from_value(s).unwrap()
    }).collect();
    assert_eq!(json(proxy::external_cascades(&servers, |s| s.host.clone())), f["external"]);

    let routes = vec![(51820, "1.2.3.4".to_string(), 43210), (51821, "5.6.7.8".to_string(), 40000)];
    assert_eq!(proxy::rules_script(&routes), text("rules_script"));
    assert_eq!(json(foreign::parse_udp_listen(&text("udp_listen_text"))), f["udp_listen"]);
    assert_eq!(foreign::start_script(amz_core::awg::instance("v2").unwrap()), text("start_script_v2"));
}

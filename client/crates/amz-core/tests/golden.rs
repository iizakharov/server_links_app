//! Checks the Rust port against fixtures produced by the reference Python code (tests/golden/gen.py).
use amz_core::model::{AwgServer, ClientKeys, Params, State};
use amz_core::storage::Storage;
use amz_core::{awg, keys, vpnkey};
use serde_json::Value;

fn fixture(name: &str) -> Value {
    let path = format!("{}/../../fixtures/{name}.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap()
}

#[test]
fn client_conf_and_vpn_key_match_python() {
    for case in fixture("configs").as_array().unwrap() {
        let server: AwgServer = serde_json::from_value(case["server"].clone()).unwrap();
        let client: ClientKeys = serde_json::from_value(case["client"].clone()).unwrap();
        let port = case["endpoint_port"].as_u64().unwrap() as u16;
        let args = (s(case, "endpoint_host"), port, s(case, "dns1"), s(case, "dns2"));
        let ctx = format!("{} / {}", s(case, "version"), s(case, "name"));

        let conf = amz_core::client_conf(&client, &server, args.0, args.1, args.2, args.3);
        assert_eq!(conf, s(case, "conf"), "{ctx}");

        // the JSON inside the key is byte-for-byte what Python writes
        let json = vpnkey::vpn_json(s(case, "name"), &client, &server, args.0, args.1, args.2, args.3);
        assert_eq!(json, s(case, "vpn_json"), "{ctx}");

        // Python key decodes in Rust; Rust key decodes to the same document
        assert_eq!(vpnkey::decode_vpn_key(s(case, "vpn_key")).unwrap(), case["vpn_doc"], "{ctx}");
        let key = amz_core::vpn_key(s(case, "name"), &client, &server, args.0, args.1, args.2, args.3);
        assert!(key.starts_with("vpn://") && !key.contains('='));
        assert_eq!(vpnkey::decode_vpn_key(&key).unwrap(), case["vpn_doc"], "{ctx}");
    }
}

#[test]
fn parse_and_drop_peer_match_python() {
    let f = fixture("parse");
    let (iface, peers) = amz_core::parse_conf(s(&f, "text"));
    assert_eq!(serde_json::to_value(&iface).unwrap(), f["iface"]);
    assert_eq!(serde_json::to_value(&peers).unwrap(), f["peers"]);
    assert_eq!(serde_json::to_value(amz_core::obfuscation_params(&iface)).unwrap(), f["obfuscation"]);
    for (pk, expected) in [("AAA", "drop_AAA"), ("CCC", "drop_CCC"), ("ZZZ", "drop_missing")] {
        assert_eq!(amz_core::drop_peer(s(&f, "text"), pk), s(&f, expected), "{pk}");
    }
}

#[test]
fn awg_versions_match_python() {
    for case in fixture("versions").as_array().unwrap() {
        let server: AwgServer = serde_json::from_value(serde_json::json!({"public_key": "", "params": case["params"]})).unwrap();
        assert_eq!(awg::is_legacy(&server.params), case["is_legacy"].as_bool().unwrap(), "{}", case["params"]);
        assert_eq!(awg::awg_version(&server.params), s(case, "awg_version"), "{}", case["params"]);
    }
}

#[test]
fn public_keys_match_python() {
    for case in fixture("keys").as_array().unwrap() {
        assert_eq!(keys::public_key(s(case, "private_key")).unwrap(), s(case, "public_key"));
    }
    let priv_key = keys::gen_private_key();
    assert_eq!(keys::public_key(&priv_key).unwrap().len(), 44);
    assert!(keys::public_key("nope").is_err());
}

#[test]
fn random_params_have_the_right_version() {
    for (ver, expected) in [("v1", "1.0"), ("v2", "2.0"), ("v3", "3.x")] {
        let p: Params = awg::random_params(ver);
        assert_eq!(awg::awg_version(&p), expected, "{p:?}");
        let n = |k: &str| p[k].parse::<u32>().unwrap();
        assert!(n("S1") != n("S2") && n("S1") + 56 != n("S2") && n("S2") + 56 != n("S1"));
    }
}

#[test]
fn state_round_trip_keeps_unknown_fields() {
    let dir = std::env::temp_dir().join(format!("amz-core-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let store = Storage::new(&dir);
    assert_eq!(store.load().unwrap(), State::default());
    let raw = serde_json::json!({
        "servers": [{"id": "a1", "name": "proxy", "host": "1.2.3.4", "ssh_port": 22, "user": "root",
                     "password": "", "key_path": "", "scan": {"os": "Ubuntu"}, "future": 1}],
        "cascades": [{"id": "c1", "proxy_id": "a1", "exit_id": "b2", "port": 51820, "mode": "v2"}],
        "clients": [{"id": "k1", "name": "phone", "cascade_id": "c1", "created": "2026-09-22",
                     "private_key": "x", "public_key": "y", "psk": "z", "ip": "10.9.2.2",
                     "traffic": {"rx": 1, "tx": 2}, "raw": {"rx": 1, "tx": 2}, "handshake": 5, "stats_at": "t"}],
        "settings": {"dns1": "1.1.1.1", "dns2": "1.0.0.1"},
    });
    let state: State = serde_json::from_value(raw.clone()).unwrap();
    store.save(&state).unwrap();
    store.save(&state).unwrap();
    assert_eq!(serde_json::to_value(store.load().unwrap()).unwrap(), raw);
    assert_eq!(std::fs::read_dir(dir.join("backups")).unwrap().count(), 1);
    std::fs::remove_dir_all(&dir).unwrap();
}

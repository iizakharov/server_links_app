//! Our `.conf` -> UAPI conversion, checked by the real amneziawg-go parser.
use amz_core::tunnel::{tunnel_config, ConfError};
use amz_tunnel::awg;
use serde_json::Value;

fn configs() -> Vec<Value> {
    let path = format!("{}/../../fixtures/configs.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str::<Value>(&std::fs::read_to_string(path).unwrap()).unwrap().as_array().unwrap().clone()
}

#[test]
fn awg_accepts_configs_of_every_version() {
    for case in configs() {
        let conf = case["conf"].as_str().unwrap();
        let t = tunnel_config(conf, |_, _| None).unwrap();
        awg::validate(&t.uapi).unwrap_or_else(|e| panic!("{}: {e}\n{}", case["version"], t.uapi));
        assert_eq!(t.endpoint.to_string(), "5.5.5.5:51820");
        assert_eq!(t.allowed_ips, ["0.0.0.0/0", "::/0"]);
        assert_eq!((t.mtu, t.dns.len()), (1280, 2));
        let v3 = case["version"] == "v3";
        assert_eq!(t.uapi.contains("header_protection_key="), v3);
        assert_eq!(t.uapi.contains("content_padding_addition=8-64"), v3);
    }
}

#[test]
fn bad_settings_are_rejected() {
    assert!(awg::validate("private_key=zz").is_err());
    assert!(awg::validate("h1=5-2").is_err() || awg::validate("h1=nope").is_err());
    let conf = configs()[0]["conf"].as_str().unwrap().replace("Jc = ", "Jx = ");
    assert_eq!(tunnel_config(&conf, |_, _| None).unwrap_err(), ConfError::UnknownKey("Jx".into()));
    let conf = configs()[0]["conf"].as_str().unwrap().replace("5.5.5.5", "vpn.example.invalid");
    assert_eq!(tunnel_config(&conf, |_, _| None).unwrap_err(), ConfError::Resolve("vpn.example.invalid".into()));
    let t = tunnel_config(&conf, |_, port| Some(([9, 9, 9, 9], port).into())).unwrap();
    assert_eq!(t.endpoint.to_string(), "9.9.9.9:51820");
}

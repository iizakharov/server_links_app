//! AmneziaWG versions: detection from server params and generation of new obfuscation params.
use rand::seq::{index, SliceRandom};
use rand::Rng;

use crate::keys::gen_psk;
use crate::model::Params;

/// Our own containers on an exit server, one per AmneziaWG version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Instance {
    pub key: &'static str,
    pub container: &'static str,
    pub dir: &'static str,
    pub iface: &'static str,
    pub subnet: &'static str,
    pub version: &'static str,
    pub label: &'static str,
}

pub const INSTANCES: [Instance; 3] = [
    Instance { key: "legacy", container: "cascade-awg-legacy", dir: "/opt/cascade-awg-legacy", iface: "awgl0",
               subnet: "10.9.0.1/24", version: "v1", label: "AmneziaWG 1.0 (роутеры)" },
    Instance { key: "v2", container: "cascade-awg-v2", dir: "/opt/cascade-awg-v2", iface: "awgv2",
               subnet: "10.9.2.1/24", version: "v2", label: "AmneziaWG 2.0" },
    Instance { key: "v3", container: "cascade-awg-v3", dir: "/opt/cascade-awg-v3", iface: "awgv3",
               subnet: "10.9.3.1/24", version: "v3", label: "AmneziaWG 3.x" },
];

pub fn instance(key: &str) -> Option<&'static Instance> {
    INSTANCES.iter().find(|i| i.key == key)
}

/// pinned on purpose: this build runs 1.0/2.0/3.x configs, newer images may change defaults
pub const AWG_IMAGE: &str = "amneziavpn/amneziawg-go:3.1.20260828";
const AWG1_KEYS: &[&str] = &["jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4"];

/// True if the server speaks plain AmneziaWG 1.0 (no S3/S4/I*, single-number H1-H4), i.e. routers can connect.
pub fn is_legacy(params: &Params) -> bool {
    params.iter().all(|(k, v)| {
        let k = k.to_lowercase();
        if (k == "s3" || k == "s4") && v == "0" {
            return true;
        }
        AWG1_KEYS.contains(&k.as_str())
            && !(k.starts_with('h') && (v.is_empty() || !v.chars().all(|c| c.is_ascii_digit())))
    })
}

/// Protocol version a client needs: 1.0 (routers), 2.0, or 3.x (header protection).
pub fn awg_version(params: &Params) -> &'static str {
    if params.keys().any(|k| k.eq_ignore_ascii_case("headerprotectionkey")) {
        "3.x"
    } else if is_legacy(params) {
        "1.0"
    } else {
        "2.0"
    }
}

/// Four non-overlapping H ranges (AWG 2.0+), one per bucket of the uint32 space.
fn header_ranges(rng: &mut impl Rng) -> Vec<String> {
    let step: u64 = ((1u64 << 31) - 5) / 4;
    (0..4)
        .map(|i| {
            let lo = 5 + i * step + rng.gen_range(0..=step / 2);
            format!("{lo}-{}", lo + rng.gen_range(100_000..=10_000_000))
        })
        .collect()
}

/// Obfuscation parameters, per the amneziawg-go README recommendations. `version` is "v1", "v2" or "v3".
pub fn random_params(version: &str) -> Params {
    let mut rng = rand::thread_rng();
    let s1: u32 = rng.gen_range(15..=150);
    let s2 = *(15..=150u32)
        .filter(|&s| s != s1 && s1 + 56 != s && s + 56 != s1)
        .collect::<Vec<_>>()
        .choose(&mut rng)
        .expect("range is never empty");
    let mut p = Params::new();
    p.insert("Jc".into(), rng.gen_range(4..=12u32).to_string());
    p.insert("Jmin".into(), "8".into());
    p.insert("Jmax".into(), "80".into());
    p.insert("S1".into(), s1.to_string());
    p.insert("S2".into(), s2.to_string());
    if version == "v1" {
        // single-number headers, no S3/S4 — what routers understand
        let h = index::sample(&mut rng, (1 << 31) - 1 - 5, 4);
        for (i, v) in h.iter().enumerate() {
            p.insert(format!("H{}", i + 1), (v + 5).to_string());
        }
    } else {
        p.insert("S3".into(), rng.gen_range(15..=150u32).to_string());
        p.insert("S4".into(), rng.gen_range(15..=150u32).to_string());
        for (i, r) in header_ranges(&mut rng).into_iter().enumerate() {
            p.insert(format!("H{}", i + 1), r);
        }
    }
    if version == "v3" {
        // header protection is symmetric, so clients get the same key
        p.insert("HeaderProtectionKey".into(), gen_psk());
        p.insert("ContentPaddingAddition".into(),
                 format!("{}-{}", rng.gen_range(8..=32u32), rng.gen_range(64..=160u32)));
    }
    p
}

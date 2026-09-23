//! Data model, compatible with the reference panel's `data/state.json`.
//! Unknown fields are kept in `extra`, so a state written by the panel survives a load/save round-trip.
use indexmap::IndexMap;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

/// Obfuscation parameters (Jc, S1, H1, I1, ...). The panel stores numbers and strings; we keep text.
pub type Params = IndexMap<String, String>;

fn de_params<'de, D: Deserializer<'de>>(d: D) -> Result<Params, D::Error> {
    let raw = IndexMap::<String, Value>::deserialize(d)?;
    Ok(raw
        .into_iter()
        .map(|(k, v)| {
            let v = match v {
                Value::String(s) => s,
                other => other.to_string(),
            };
            (k, v)
        })
        .collect())
}

/// AmneziaWG interface on an exit server (result of a scan): where it runs and what clients need to connect.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct AwgInfo {
    /// "amnezia" (AmneziaVPN container), "native", or one of our instances ("legacy", "v2", "v3")
    pub mode: String,
    pub container: Option<String>,
    pub conf_path: String,
    /// "awg" or "wg" (old AmneziaVPN containers)
    pub tool: String,
    /// shared PSK of an AmneziaVPN container, reused for new clients
    pub psk: Option<String>,
    pub iface: String,
    pub listen_port: u16,
    pub address: String,
    pub public_key: String,
    #[serde(deserialize_with = "de_params")]
    pub params: Params,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// DNAT rule found on a server (`iptables-save -t nat`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct NatRule {
    pub chain: String,
    /// in our own chain CASCADE_PRE
    pub ours: bool,
    pub proto: Option<String>,
    /// inclusive ranges; None = all ports
    pub dports: Option<Vec<(u32, u32)>>,
    pub dst: Option<String>,
    pub to_ip: Option<String>,
    pub to_port: Option<u32>,
    pub comment: Option<String>,
    pub raw: String,
}

/// Read-only scan of a server.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Scan {
    pub os: String,
    /// the server's own AmneziaWG (AmneziaVPN container or native install)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub awg: Option<AwgInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub awg_legacy: Option<AwgInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub awg_v2: Option<AwgInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub awg_v3: Option<AwgInfo>,
    pub nat: Vec<NatRule>,
    pub udp_listen: Vec<u32>,
    pub at: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Scan {
    /// AmneziaWG instance by cascade instance name: "main" (the server's own) or "legacy"/"v2"/"v3".
    pub fn awg_for(&self, instance: &str) -> Option<&AwgInfo> {
        match instance {
            "main" => self.awg.as_ref(),
            "legacy" => self.awg_legacy.as_ref(),
            "v2" => self.awg_v2.as_ref(),
            "v3" => self.awg_v3.as_ref(),
            _ => None,
        }
    }

    pub fn set_awg(&mut self, instance: &str, info: Option<AwgInfo>) {
        match instance {
            "main" => self.awg = info,
            "legacy" => self.awg_legacy = info,
            "v2" => self.awg_v2 = info,
            "v3" => self.awg_v3 = info,
            _ => {}
        }
    }
}

/// A client's own keys and tunnel address.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ClientKeys {
    pub ip: String,
    pub private_key: String,
    pub public_key: String,
    #[serde(default)]
    pub psk: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Server {
    pub id: String,
    pub name: String,
    pub host: String,
    #[serde(default = "default_ssh_port")]
    pub ssh_port: u16,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub key_path: Option<String>,
    #[serde(default)]
    pub scan: Option<Scan>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

fn default_ssh_port() -> u16 {
    22
}

/// proxy server `:port` -> DNAT -> AmneziaWG on the exit server.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Cascade {
    pub id: String,
    pub proxy_id: String,
    pub exit_id: String,
    pub port: u16,
    /// "managed" (our DNAT rule) or "external" (someone else's forward, adopted as is)
    #[serde(default)]
    pub mode: String,
    /// AmneziaWG instance on the exit server: "main", "legacy", "v2", "v3" (absent in old states = "main")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Cascade {
    pub fn instance(&self) -> &str {
        self.instance.as_deref().unwrap_or("main")
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
pub struct Traffic {
    pub rx: u64,
    pub tx: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Client {
    pub id: String,
    pub name: String,
    pub cascade_id: String,
    #[serde(default)]
    pub created: Option<String>,
    pub ip: String,
    pub private_key: String,
    pub public_key: String,
    #[serde(default)]
    pub psk: Option<String>,
    /// accumulated since creation; absent until the first traffic refresh
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traffic: Option<Traffic>,
    /// counters seen at the last refresh (to compute deltas)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<Traffic>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handshake: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stats_at: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Client {
    pub fn keys(&self) -> ClientKeys {
        ClientKeys { ip: self.ip.clone(), private_key: self.private_key.clone(),
                     public_key: self.public_key.clone(), psk: self.psk.clone() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Settings {
    pub dns1: String,
    pub dns2: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { dns1: "1.1.1.1".into(), dns2: "1.0.0.1".into(), extra: Map::new() }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct State {
    #[serde(default)]
    pub servers: Vec<Server>,
    #[serde(default)]
    pub cascades: Vec<Cascade>,
    #[serde(default)]
    pub clients: Vec<Client>,
    #[serde(default)]
    pub settings: Settings,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

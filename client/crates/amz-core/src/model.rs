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

/// AmneziaWG interface on an exit server (result of a scan): what clients need to connect.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AwgServer {
    pub public_key: String,
    #[serde(deserialize_with = "de_params", default)]
    pub params: Params,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
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
    pub scan: Option<Value>,
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
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
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
    #[serde(default)]
    pub traffic: Traffic,
    #[serde(default)]
    pub raw: Traffic,
    #[serde(default)]
    pub handshake: Option<i64>,
    #[serde(default)]
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

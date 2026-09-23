//! AmneziaVPN share key: `vpn://` + base64url(qCompress(json)).
use std::io::{Read, Write};

use base64::alphabet::URL_SAFE;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::DecodePaddingMode;
use base64::Engine;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use serde_json::{json, Map, Value};

use crate::conf::{client_conf, MTU};
use crate::model::{AwgServer, ClientKeys};
use crate::pyjson;

const B64: GeneralPurpose = GeneralPurpose::new(
    &URL_SAFE,
    GeneralPurposeConfig::new().with_encode_padding(false).with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("not a vpn:// key: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("corrupted vpn:// payload: {0}")]
    Io(#[from] std::io::Error),
    #[error("vpn:// payload is not JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("vpn:// payload is too short")]
    Short,
}

/// Qt `qCompress()`: 4-byte big-endian uncompressed length + zlib stream.
pub fn qcompress(data: &[u8]) -> Vec<u8> {
    let mut enc = ZlibEncoder::new((data.len() as u32).to_be_bytes().to_vec(), Compression::new(8));
    enc.write_all(data).expect("writing to Vec cannot fail");
    enc.finish().expect("writing to Vec cannot fail")
}

pub fn quncompress(data: &[u8]) -> Result<Vec<u8>, KeyError> {
    let body = data.get(4..).ok_or(KeyError::Short)?;
    let mut out = Vec::new();
    ZlibDecoder::new(body).read_to_end(&mut out)?;
    Ok(out)
}

/// The JSON document inside a key (pretty-printed the way Python/AmneziaVPN do).
pub fn vpn_json(name: &str, client: &ClientKeys, server: &AwgServer, endpoint_host: &str, endpoint_port: u16,
                dns1: &str, dns2: &str) -> String {
    let conf = client_conf(client, server, endpoint_host, endpoint_port, dns1, dns2);
    let params: Map<String, Value> =
        server.params.iter().map(|(k, v)| (k.clone(), Value::String(v.clone()))).collect();
    // AmneziaVPN names the AWG container "amnezia-awg" regardless of the version running on the server
    let container = "amnezia-awg";
    let mut last_config = params.clone();
    last_config.extend(json!({
        "client_ip": client.ip,
        "client_priv_key": client.private_key,
        "client_pub_key": client.public_key,
        "clientId": client.public_key,
        "config": conf,
        "hostName": endpoint_host,
        "mtu": MTU.to_string(),
        "persistent_keep_alive": "25",
        "port": endpoint_port,
        "psk_key": client.psk.clone().unwrap_or_default(),
        "server_pub_key": server.public_key,
        "allowed_ips": ["0.0.0.0/0", "::/0"],
    }).as_object().unwrap().clone());
    let mut awg = params;
    awg.extend(json!({
        // without this flag AmneziaVPN treats the entry as its own server and offers to install containers
        "isThirdPartyConfig": true,
        "last_config": pyjson::dumps(&Value::Object(last_config), 4),
        "port": endpoint_port.to_string(),
        "transport_proto": "udp",
    }).as_object().unwrap().clone());
    let doc = json!({
        "containers": [{"container": container, "awg": awg}],
        "defaultContainer": container,
        "description": name,
        "dns1": dns1,
        "dns2": dns2,
        "hostName": endpoint_host,
    });
    pyjson::dumps(&doc, 4)
}

pub fn vpn_key(name: &str, client: &ClientKeys, server: &AwgServer, endpoint_host: &str, endpoint_port: u16,
               dns1: &str, dns2: &str) -> String {
    let raw = vpn_json(name, client, server, endpoint_host, endpoint_port, dns1, dns2);
    format!("vpn://{}", B64.encode(qcompress(raw.as_bytes())))
}

pub fn decode_vpn_key(key: &str) -> Result<Value, KeyError> {
    let b64 = key.trim();
    let b64 = b64.strip_prefix("vpn://").unwrap_or(b64);
    Ok(serde_json::from_slice(&quncompress(&B64.decode(b64)?)?)?)
}

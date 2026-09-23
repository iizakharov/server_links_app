//! АМнеЗинуVPN core: a Rust port of the reference Python panel (`app/configs.py`, `app/keys.py`,
//! the pure parts of `app/foreign.py`, `app/storage.py`). Outputs are checked against
//! golden fixtures generated from the Python code (`tests/golden/gen.py` -> `client/fixtures/`).

pub mod awg;
pub mod conf;
pub mod keys;
pub mod model;
pub mod pyjson;
pub mod storage;
pub mod tunnel;
pub mod vpnkey;

pub use conf::{client_conf, drop_peer, obfuscation_params, parse_conf, Section};
pub use vpnkey::{decode_vpn_key, vpn_key};

//! WireGuard/AmneziaWG keys generated locally (no awg binary needed).
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug, thiserror::Error)]
#[error("invalid private key: expected 32 bytes of base64")]
pub struct BadKey;

fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    b
}

/// Same as `wg genkey`: random 32 bytes, clamped.
pub fn gen_private_key() -> String {
    let mut b = random32();
    b[0] &= 248;
    b[31] = (b[31] & 127) | 64;
    STANDARD.encode(b)
}

pub fn public_key(private_key: &str) -> Result<String, BadKey> {
    let raw: [u8; 32] = STANDARD.decode(private_key.trim()).map_err(|_| BadKey)?.try_into().map_err(|_| BadKey)?;
    Ok(STANDARD.encode(PublicKey::from(&StaticSecret::from(raw)).as_bytes()))
}

pub fn gen_psk() -> String {
    STANDARD.encode(random32())
}

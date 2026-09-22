"""WireGuard/AmneziaWG keys generated locally (no awg binary needed)."""
import base64
import os

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def gen_private_key() -> str:
    key = X25519PrivateKey.generate()
    return _b64(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))


def public_key(private_key: str) -> str:
    key = X25519PrivateKey.from_private_bytes(base64.b64decode(private_key))
    return _b64(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


def gen_psk() -> str:
    return _b64(os.urandom(32))

"""Parsing server configs and generating client configs (.conf and AmneziaVPN vpn:// key)."""
import base64
import json
import struct
import zlib

# [Interface] keys that are not obfuscation parameters (everything else — Jc, Jmin, S1, H1, I1... — is copied to clients)
STANDARD_IFACE_KEYS = {
    "privatekey", "address", "listenport", "postup", "postdown", "preup", "predown",
    "dns", "mtu", "saveconfig", "table", "fwmark",
}
MTU = 1280


def parse_conf(text: str) -> tuple[dict, list[dict]]:
    """Returns ([Interface] dict, list of [Peer] dicts). Keys keep original case."""
    iface, peers, cur = {}, [], None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("["):
            section = line.strip("[]").strip().lower()
            if section == "interface":
                cur = iface
            else:
                cur = {}
                peers.append(cur)
            continue
        if "=" in line and cur is not None:
            k, v = line.split("=", 1)
            cur[k.strip()] = v.strip()
    return iface, peers


def drop_peer(text: str, public_key: str) -> str:
    """Removes the [Peer] block with this PublicKey (with its comment lines) from a server config."""
    out, block, keep = [], [], True
    for line in text.splitlines(keepends=True):
        if line.strip().startswith("["):
            out += block if keep else []
            block, keep = [line], True
        else:
            block.append(line)
            if line.split("#", 1)[0].strip().replace(" ", "") == f"PublicKey={public_key}":
                keep = False
    out += block if keep else []
    return "".join(out)


def obfuscation_params(iface: dict) -> dict:
    return {k: v for k, v in iface.items() if k.lower() not in STANDARD_IFACE_KEYS}


def client_conf(client: dict, server: dict, endpoint_host: str, endpoint_port: int, dns1: str, dns2: str) -> str:
    lines = [
        "[Interface]",
        f"PrivateKey = {client['private_key']}",
        f"Address = {client['ip']}/32",
        f"DNS = {dns1}, {dns2}",
        f"MTU = {MTU}",
    ]
    lines += [f"{k} = {v}" for k, v in server["params"].items()]
    lines += [
        "",
        "[Peer]",
        f"PublicKey = {server['public_key']}",
    ]
    if client.get("psk"):
        lines.append(f"PresharedKey = {client['psk']}")
    lines += [
        "AllowedIPs = 0.0.0.0/0, ::/0",
        f"Endpoint = {endpoint_host}:{endpoint_port}",
        "PersistentKeepalive = 25",
    ]
    return "\n".join(lines) + "\n"


def qcompress(data: bytes) -> bytes:
    """Qt qCompress(): 4-byte big-endian uncompressed length + zlib stream."""
    return struct.pack(">I", len(data)) + zlib.compress(data, 8)


def quncompress(data: bytes) -> bytes:
    return zlib.decompress(data[4:])


def vpn_key(name: str, client: dict, server: dict, endpoint_host: str, endpoint_port: int,
            dns1: str, dns2: str) -> str:
    """AmneziaVPN share key: vpn:// + base64url(qCompress(json)), same as the app's own export."""
    conf = client_conf(client, server, endpoint_host, endpoint_port, dns1, dns2)
    params = {k: str(v) for k, v in server["params"].items()}
    container = server.get("container") or "amnezia-awg"
    last_config = {
        **params,
        "client_ip": client["ip"],
        "client_priv_key": client["private_key"],
        "client_pub_key": client["public_key"],
        "clientId": client["public_key"],
        "config": conf,
        "hostName": endpoint_host,
        "mtu": str(MTU),
        "persistent_keep_alive": "25",
        "port": int(endpoint_port),
        "psk_key": client.get("psk") or "",
        "server_pub_key": server["public_key"],
        "allowed_ips": ["0.0.0.0/0", "::/0"],
    }
    doc = {
        "containers": [{
            "container": container,
            "awg": {
                **params,
                "last_config": json.dumps(last_config, indent=4),
                "port": str(endpoint_port),
                "transport_proto": "udp",
            },
        }],
        "defaultContainer": container,
        "description": name,
        "dns1": dns1,
        "dns2": dns2,
        "hostName": endpoint_host,
    }
    raw = json.dumps(doc, indent=4).encode()
    return "vpn://" + base64.urlsafe_b64encode(qcompress(raw)).decode().rstrip("=")


def decode_vpn_key(key: str) -> dict:
    b64 = key.removeprefix("vpn://")
    b64 += "=" * (-len(b64) % 4)
    return json.loads(quncompress(base64.urlsafe_b64decode(b64)))

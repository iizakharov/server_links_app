"""Golden fixtures for the Rust port (client/): runs the reference Python code and writes {input, output} pairs.

Run: .venv/bin/python -m tests.golden.gen   (CI checks that client/fixtures/ is up to date)
"""
import json
import random
from pathlib import Path

from app import configs, foreign, keys

OUT = Path(__file__).resolve().parents[2] / "client" / "fixtures"

# fixed keys so the output is deterministic
PRIV = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
CLIENT_PRIV = "QOmpv2x9XXXvF5Bz3ZX1+fjJvP9j8ixn8gRkcM9m60E="
PSK = "FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE="

SERVER_CONF = f"""[Interface]
PrivateKey = {PRIV}
Address = 10.8.1.0/24
ListenPort = 43210
Jc = 4
Jmin = 10
Jmax = 50
S1 = 97
S2 = 34
H1 = 111
H2 = 222
H3 = 333
H4 = 444
PostUp = iptables -A FORWARD -i %i -j ACCEPT # comment

# client: phone
[Peer]
PublicKey = AAA
PresharedKey = BBB
AllowedIPs = 10.8.1.1/32

[Peer]
PublicKey = CCC
AllowedIPs = 10.8.1.2/32
"""

SERVERS = {
    "v1": {"public_key": keys.public_key(PRIV),
           "params": {"Jc": 4, "Jmin": 8, "Jmax": 80, "S1": 97, "S2": 34,
                      "H1": 111, "H2": 222, "H3": 333, "H4": 444}},
    "v2": {"public_key": keys.public_key(PRIV),
           "params": {"Jc": "5", "Jmin": "8", "Jmax": "80", "S1": "20", "S2": "90", "S3": "30", "S4": "40",
                      "H1": "5-100005", "H2": "600000000-600100000", "H3": "1100000000-1100200000",
                      "H4": "1700000000-1700300000"}},
    "v3": {"public_key": keys.public_key(PRIV),
           "params": {"Jc": "5", "Jmin": "8", "Jmax": "80", "S1": "20", "S2": "90", "S3": "30", "S4": "40",
                      "H1": "5-100005", "H2": "600000000-600100000", "H3": "1100000000-1100200000",
                      "H4": "1700000000-1700300000", "HeaderProtectionKey": PSK,
                      "ContentPaddingAddition": "8-64", "I1": "<b 0xf6ab3267fa><c><b 0xf6ab><t><r 10><wt 10>"}},
}
CLIENTS = [
    {"ip": "10.8.1.5", "private_key": CLIENT_PRIV, "public_key": keys.public_key(CLIENT_PRIV), "psk": PSK},
    {"ip": "10.9.0.7", "private_key": CLIENT_PRIV, "public_key": keys.public_key(CLIENT_PRIV), "psk": ""},
]


def configs_cases():
    out = []
    for ver, server in SERVERS.items():
        for client in CLIENTS:
            for name in ("phone", "Мама (Прокси → Германия)"):
                args = dict(client=client, server=server, endpoint_host="5.5.5.5", endpoint_port=51820,
                            dns1="1.1.1.1", dns2="1.0.0.1")
                key = configs.vpn_key(name, **args)
                out.append({"version": ver, "name": name, **args,
                            "conf": configs.client_conf(**args),
                            "vpn_key": key, "vpn_doc": configs.decode_vpn_key(key),
                            "vpn_json": configs.quncompress(__import__("base64").urlsafe_b64decode(
                                key[6:] + "=" * (-len(key[6:]) % 4))).decode()})
    return out


def parse_cases():
    iface, peers = configs.parse_conf(SERVER_CONF)
    return {"text": SERVER_CONF, "iface": iface, "peers": peers,
            "obfuscation": configs.obfuscation_params(iface),
            "drop_AAA": configs.drop_peer(SERVER_CONF, "AAA"),
            "drop_CCC": configs.drop_peer(SERVER_CONF, "CCC"),
            "drop_missing": configs.drop_peer(SERVER_CONF, "ZZZ")}


def version_cases():
    out = [{"params": s["params"], "is_legacy": foreign.is_legacy(s), "awg_version": foreign.awg_version(s)}
           for s in SERVERS.values()]
    extra = [{"Jc": "4", "S3": "0", "S4": "0", "H1": "1"}, {"Jc": "4", "S3": "12"}, {"jc": "4", "h1": "1-5"}, {}]
    out += [{"params": p, "is_legacy": foreign.is_legacy({"params": p}),
             "awg_version": foreign.awg_version({"params": p})} for p in extra]
    return out


def key_cases():
    random.seed(1)
    return [{"private_key": k, "public_key": keys.public_key(k)} for k in (PRIV, CLIENT_PRIV)]


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for name, data in {"configs": configs_cases(), "parse": parse_cases(),
                       "versions": version_cases(), "keys": key_cases()}.items():
        (OUT / f"{name}.json").write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    print(f"fixtures written to {OUT}")


if __name__ == "__main__":
    main()

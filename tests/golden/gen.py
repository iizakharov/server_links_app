"""Golden fixtures for the Rust port (client/): runs the reference Python code and writes {input, output} pairs.

Run: .venv/bin/python -m tests.golden.gen   (CI checks that client/fixtures/ is up to date)
"""
import json
import random
import shlex
from pathlib import Path

from app import configs, foreign, keys, proxy

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


# ---------- SSH transcripts: every command the reference code sends, with the fake server's answers ----------

class Rec:
    """Wraps a fake server and records the conversation; Rust replays it and must send the same commands."""

    def __init__(self, inner):
        self.inner, self.host, self.steps = inner, inner.host, []

    def run(self, cmd, input=None, check=True, timeout=None):
        step = {"cmd": cmd, "check": check, "input": input}
        self.steps.append(step)
        try:
            step["out"] = self.inner.run(cmd, input, check)
        except Exception as e:
            step["error"] = str(e)
            raise
        return step["out"]

    def put(self, path, content, mode="600"):
        self.run(f"cat > {shlex.quote(path)} && chmod {mode} {shlex.quote(path)}", input=content)

    def reconnect(self):
        pass


def amnezia_remote():
    from tests.test_configs import FakeRemote, SERVER_CONF
    r = FakeRemote()
    r.priv = PRIV
    r.files["/opt/amnezia/awg/wg0.conf"] = SERVER_CONF.format(priv=PRIV)
    return r


class NativeRemote:
    host = "native"
    files = {foreign.NATIVE_CONF: SERVER_CONF}

    def run(self, cmd, input=None, check=True, timeout=None):
        if cmd.startswith("test -f"):
            return "yes\n"
        if cmd.startswith("cat "):
            return self.files[cmd.split()[1]]
        return ""


def v2_remote():
    r = amnezia_remote()
    base = r.run
    conf = SERVER_CONF.replace("H1 = 111", "S3 = 53\nS4 = 16\nH1 = 100-200").replace("10.8.1.0/24", "10.9.2.1/24")
    r.files["/opt/cascade/awgv2.conf"] = conf

    def run(cmd, input=None, check=True, timeout=None):
        if cmd.startswith("command -v docker"):
            return "amnezia-awg\ncascade-awg-v2\n"
        if cmd.startswith("docker exec -i cascade-awg-v2"):
            return base(cmd.replace("cascade-awg-v2", "amnezia-awg", 1), input, check)
        return base(cmd, input, check)
    r.run = run
    return r


class StatsRemote:
    host = "stats"

    def run(self, cmd, input=None, check=True, timeout=None):
        if cmd.endswith("transfer"):
            return "AAA\t100\t200\nBBB\t5\t6\nbroken line\nCCC\tx\t1\n"
        if cmd.endswith("latest-handshakes"):
            return "AAA\t1790000000\nZZZ\t1\nBBB\t0\n"
        return ""


class ProbeRemote:
    """Answers the probe counter with `arrived` packets."""

    def __init__(self, host, arrived):
        self.host, self.arrived = host, arrived

    def run(self, cmd, input=None, check=True, timeout=None):
        if cmd.startswith("iptables -t raw -L CASCADE_PROBE"):
            return f"Chain CASCADE_PROBE (1 references)\n pkts bytes target\n {self.arrived} 100 RETURN udp\n"
        return ""


def transcripts():
    from tests.test_configs import InstallRemote
    from tests.test_proxy_scan import NAT
    import datetime as dt
    foreign.POLL_SECONDS, proxy.PROBE_WAIT = 0, 0
    # deterministic output: fixed client keys and clock
    fixed_keys = iter([CLIENT_PRIV, PRIV] * 10)
    foreign.keys.gen_private_key = lambda: next(fixed_keys)

    class FixedClock(dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return dt.datetime(2026, 9, 23, 12, 0, 0, tzinfo=tz)
    foreign.datetime = FixedClock
    out = []

    def case(name, remotes, result, compare_input=True):
        out.append({"name": name, "compare_input": compare_input, "result": result,
                    "remotes": [{"host": r.host, "steps": r.steps} for r in remotes]})

    r = Rec(amnezia_remote())
    case("detect_amnezia", [r], foreign.detect(r))
    r = Rec(NativeRemote())
    case("detect_native", [r], foreign.detect(r))
    r = Rec(v2_remote())
    case("detect_instance_v2", [r], foreign.detect_instance(r, "v2"))

    fake = amnezia_remote()
    info = foreign.detect(fake)
    r = Rec(fake)
    ips = [foreign.add_peer(r, info, n)["ip"] for n in ("phone", "laptop")]
    case("add_peer", [r], ips, compare_input=False)
    r = Rec(amnezia_remote())
    foreign.remove_peer(r, info, "AAA")
    case("remove_peer", [r], None)

    r = Rec(StatsRemote())
    case("peer_stats", [r], foreign.peer_stats(r, {"tool": "awg", "iface": "awg0", "container": None}))

    fake = amnezia_remote()
    base = fake.run
    fake.run = lambda cmd, input=None, check=True, timeout=None: NAT if cmd.startswith("iptables-save") else (
        "UNCONN 0 0 0.0.0.0:51820 0.0.0.0:*\nUNCONN 0 0 [::]:53 [::]:*\n" if cmd.startswith("ss ") else base(cmd, input, check))
    r = Rec(fake)
    scan = proxy.scan(r)
    scan.pop("at")
    case("proxy_scan", [r], scan)

    r = Rec(InstallRemote())
    foreign.run_install(r, lambda _: None)
    case("run_install_reconnects", [r], None)
    r = Rec(InstallRemote(final="failed"))
    try:
        foreign.run_install(r, lambda _: None)
    except RuntimeError as e:
        case("run_install_fails", [r], str(e))

    r = Rec(ProbeRemote("proxy", 0))
    proxy.setup(r, [(51820, "1.2.3.4", 43210), (51821, "5.6.7.8", 40000)], lambda _: None)
    case("proxy_setup", [r], None)

    for name, (a, b) in {"check_link_ok": (5, 5), "check_link_blocked": (5, 0), "check_link_no_reply": (0, 5)}.items():
        rp, re_ = Rec(ProbeRemote("198.51.100.1", a)), Rec(ProbeRemote("203.0.113.9", b))
        case(name, [rp, re_], proxy.check_link(rp, re_, "203.0.113.9", 48303, 60001, lambda _: None))
    return out


def proxy_cases():
    from tests.test_proxy_scan import NAT
    ours = "-A CASCADE_PRE -p udp -m udp --dport 60001 -j DNAT --to-destination 203.0.113.9:48303\n"
    nat = proxy.parse_nat(NAT + ours + "-A PREROUTING ! -s 1.1.1.1 -p udp -j DNAT --to-destination 9.9.9.9\n"
                                     "-A PREROUTING -p udp -m comment --comment \"a b\" -j DNAT --to-destination 8.8.8.8:1-9\n")
    scan = {"nat": proxy.parse_nat(NAT + ours), "udp_listen": [60002]}
    servers = [
        {"id": "p", "name": "p", "host": "198.51.100.1", "scan": {"nat": proxy.parse_nat(NAT)}},
        {"id": "e", "name": "e", "host": "203.0.113.9", "scan": {"awg": {"listen_port": 48303}}},
        {"id": "x", "name": "x", "host": "192.0.2.5", "scan": {"awg": {"listen_port": 40000}}},
        {"id": "y", "name": "y", "host": "203.0.113.10", "scan": {"awg": {"listen_port": 50000}}},
    ]
    return {
        "nat_text": NAT + ours, "nat": proxy.parse_nat(NAT + ours), "nat_extra": nat,
        "describe": [proxy.describe(r) for r in nat],
        "conflicts": {str(p): proxy.port_conflict(p, scan, {60003}) for p in
                      (0, 70000, 2222, 51820, 60001, 60002, 60003, 60004, 443, 9999)},
        "pick_port": [proxy.pick_port(scan, set()), proxy.pick_port(scan, {60003}), proxy.pick_port(scan, set(), 500)],
        "servers": servers, "external": proxy.external_cascades(servers, lambda s: s["host"]),
        "managed_status": [proxy.managed_status({"port": p}, scan, "203.0.113.9") for p in (60001, 60005, 50000)],
        "rules_script": proxy.rules_script([(51820, "1.2.3.4", 43210), (51821, "5.6.7.8", 40000)]),
        "udp_listen_text": "UNCONN 0 0 0.0.0.0:51820 0.0.0.0:*\nUNCONN 0 0 [::]:53 [::]:*\nUNCONN 0 0 *:51820 *:*\nbad\n",
        "udp_listen": foreign.parse_udp_listen("UNCONN 0 0 0.0.0.0:51820 0.0.0.0:*\nUNCONN 0 0 [::]:53 [::]:*\n"
                                               "UNCONN 0 0 *:51820 *:*\nbad\n"),
        "start_script_v2": foreign.start_script(foreign.INSTANCES["v2"]),
    }


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for name, data in {"configs": configs_cases(), "parse": parse_cases(), "versions": version_cases(),
                       "keys": key_cases(), "transcripts": transcripts(), "proxy": proxy_cases()}.items():
        (OUT / f"{name}.json").write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    print(f"fixtures written to {OUT}")


if __name__ == "__main__":
    main()

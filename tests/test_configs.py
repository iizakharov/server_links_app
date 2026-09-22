import json
import shlex

from app import configs, foreign, keys, proxy

SERVER_CONF = """[Interface]
PrivateKey = {priv}
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

[Peer]
PublicKey = AAA
PresharedKey = BBB
AllowedIPs = 10.8.1.1/32
"""


class FakeRemote:
    """Emulates an Amnezia docker server: a tiny in-memory filesystem."""
    host = "fake"

    def __init__(self):
        self.priv = keys.gen_private_key()
        self.files = {
            "/opt/amnezia/awg/wg0.conf": SERVER_CONF.format(priv=self.priv),
            "/opt/amnezia/awg/wireguard_psk.key": "SHAREDPSK\n",
        }
        self.cmds = []

    def run(self, cmd, input=None, check=True, timeout=None):
        self.cmds.append(cmd)
        if cmd.startswith("iptables -t raw -L CASCADE_PROBE"):  # link check: probes arrive
            return f" {proxy.PROBES} 100 RETURN udp\n"
        if cmd.startswith("command -v docker >/dev/null && echo yes"):
            return "yes\n"
        if cmd.startswith("command -v docker"):
            return "amnezia-awg\namnezia-dns\n"
        if cmd.startswith("docker exec"):
            inner = shlex.split(cmd)[-1]
            if inner.startswith("ls "):
                return "/opt/amnezia/awg/wg0.conf\n"
            if inner.startswith("command -v awg"):
                return "wg\n"
            if inner.startswith("cat >> "):
                self.files[inner.split()[2]] += input
                return ""
            if inner.startswith("cat > "):
                self.files[inner.split()[2]] = input
                return ""
            if inner.startswith("cat "):
                return self.files.get(inner.split()[1], "")
            return ""
        return ""


def test_keys():
    priv = keys.gen_private_key()
    assert len(keys.public_key(priv)) == 44
    assert keys.public_key(priv) == keys.public_key(priv)


def test_detect_and_add_peer_amnezia():
    r = FakeRemote()
    info = foreign.detect(r)
    assert info["mode"] == "amnezia" and info["iface"] == "wg0" and info["tool"] == "wg"
    assert info["listen_port"] == 43210
    assert info["public_key"] == keys.public_key(r.priv)
    assert info["params"] == {"Jc": "4", "Jmin": "10", "Jmax": "50", "S1": "97", "S2": "34",
                              "H1": "111", "H2": "222", "H3": "333", "H4": "444"}
    assert info["psk"] == "SHAREDPSK"

    c1 = foreign.add_peer(r, info, "phone")
    c2 = foreign.add_peer(r, info, "laptop")
    assert (c1["ip"], c2["ip"]) == ("10.8.1.2", "10.8.1.3")  # .0 server, .1 existing peer
    assert c1["psk"] == "SHAREDPSK"
    _, peers = configs.parse_conf(r.files["/opt/amnezia/awg/wg0.conf"])
    assert [p["AllowedIPs"] for p in peers] == ["10.8.1.1/32", "10.8.1.2/32", "10.8.1.3/32"]
    table = json.loads(r.files["/opt/amnezia/awg/clientsTable"])
    assert [t["userData"]["clientName"] for t in table] == ["phone", "laptop"]
    assert any("wg syncconf wg0" in c for c in r.cmds)


def test_client_conf_and_vpn_key_use_proxy_endpoint():
    r = FakeRemote()
    info = foreign.detect(r)
    client = foreign.add_peer(r, info, "phone")
    conf = configs.client_conf(client, info, "5.5.5.5", 51820, "1.1.1.1", "1.0.0.1")
    iface, peers = configs.parse_conf(conf)
    assert iface["Address"] == "10.8.1.2/32" and iface["S1"] == "97" and iface["H4"] == "444"
    assert peers[0]["Endpoint"] == "5.5.5.5:51820"
    assert peers[0]["PublicKey"] == info["public_key"]

    key = configs.vpn_key("phone", client, info, "5.5.5.5", 51820, "1.1.1.1", "1.0.0.1")
    assert key.startswith("vpn://") and "=" not in key
    doc = configs.decode_vpn_key(key)
    assert doc["hostName"] == "5.5.5.5" and doc["defaultContainer"] == "amnezia-awg"
    awg = doc["containers"][0]["awg"]
    assert awg["port"] == "51820" and awg["H1"] == "111"
    last = json.loads(awg["last_config"])
    assert last["config"] == conf and last["client_ip"] == "10.8.1.2"


def test_random_params_valid():
    for _ in range(200):
        p = foreign.random_params()
        assert p["S1"] + 56 != p["S2"] and p["S2"] + 56 != p["S1"]
        assert len({p["H1"], p["H2"], p["H3"], p["H4"]}) == 4 and min(p["H1"], p["H2"], p["H3"], p["H4"]) > 4
        assert "S3" not in p and "HeaderProtectionKey" not in p  # AWG 1.0: routers understand only these


def test_random_params_v2_and_v3():
    import base64
    for _ in range(50):
        p2 = foreign.random_params("v2")
        assert 12 <= p2["S3"] and 12 <= p2["S4"]  # header protection needs S1-S4 >= 12
        bounds = []
        for i in (1, 2, 3, 4):
            lo, hi = (int(x) for x in p2[f"H{i}"].split("-"))
            assert 4 < lo < hi < 2**32
            bounds.append((lo, hi))
        for (_, hi), (lo, _) in zip(bounds, bounds[1:]):
            assert hi < lo  # ranges must not overlap

        p3 = foreign.random_params("v3")
        assert len(base64.b64decode(p3["HeaderProtectionKey"])) == 32
        lo, hi = (int(x) for x in p3["ContentPaddingAddition"].split("-"))
        assert 0 < lo < hi


def test_awg_version_from_params():
    assert foreign.awg_version({"params": {"Jc": "4", "H1": "5"}}) == "1.0"
    assert foreign.awg_version({"params": {"Jc": "4", "S3": "53", "H1": "10-20"}}) == "2.0"
    assert foreign.awg_version({"params": {"S3": "53", "H1": "10-20", "HeaderProtectionKey": "x"}}) == "3.x"


def test_proxy_rules_script():
    script = proxy.rules_script([(51820, "1.2.3.4", 43210), (51821, "5.6.7.8", 40000)])
    assert "--dport 51820 -j DNAT --to-destination 1.2.3.4:43210" in script
    assert "--dport 51821 -j DNAT --to-destination 5.6.7.8:40000" in script
    assert script.count("MASQUERADE") == 2


class InstallRemote:
    """Detached install: first poll drops the connection, then 'active', then done."""
    host = "fake"

    def __init__(self, final="ok"):
        self.polls, self.final, self.cmds, self.reconnects = 0, final, [], 0

    def run(self, cmd, input=None, check=True, timeout=None):
        self.cmds.append(cmd)
        if cmd.startswith("systemctl is-active --quiet"):
            return ""
        if cmd.startswith("test -f"):
            self.polls += 1
            if self.polls == 1:
                raise EOFError("connection dropped")
            return "active\n" if self.polls == 2 else self.final + "\n"
        if cmd.startswith("tail"):
            return "E: something broke"
        return ""

    def put(self, path, content, mode="600"):
        self.script = content

    def reconnect(self):
        self.reconnects += 1


def test_install_survives_ssh_drop(monkeypatch):
    monkeypatch.setattr(foreign, "POLL_SECONDS", 0)
    r, log = InstallRemote(), []
    foreign.run_install(r, log.append)
    assert r.reconnects == 1 and r.polls == 3
    assert any("systemd-run --unit=cascade-awg-install" in c for c in r.cmds)
    assert "DPkg::Lock::Timeout" in r.script and "touch /var/log/cascade-awg-install.ok" in r.script


def test_install_failure_reports_log(monkeypatch):
    monkeypatch.setattr(foreign, "POLL_SECONDS", 0)
    import pytest
    with pytest.raises(RuntimeError, match="something broke"):
        foreign.run_install(InstallRemote(final="failed"), lambda _: None)


def test_remove_peer_revokes_only_that_client():
    r = FakeRemote()
    info = foreign.detect(r)
    a = foreign.add_peer(r, info, "phone")
    b = foreign.add_peer(r, info, "laptop")
    foreign.remove_peer(r, info, a["public_key"])
    conf = r.files["/opt/amnezia/awg/wg0.conf"]
    _, peers = configs.parse_conf(conf)
    assert [p["AllowedIPs"] for p in peers] == ["10.8.1.1/32", "10.8.1.3/32"]  # server's own peer stays
    assert a["public_key"] not in conf and b["public_key"] in conf
    assert "# phone" not in conf and "# laptop" in conf
    assert [t["userData"]["clientName"] for t in json.loads(r.files["/opt/amnezia/awg/clientsTable"])] == ["laptop"]
    assert sum("syncconf" in c for c in r.cmds) == 3  # two adds + one removal applied live

    foreign.add_peer(r, info, "tablet")  # freed IP is reused
    _, peers = configs.parse_conf(r.files["/opt/amnezia/awg/wg0.conf"])
    assert [p["AllowedIPs"] for p in peers] == ["10.8.1.1/32", "10.8.1.3/32", "10.8.1.2/32"]


def test_drop_peer_keeps_interface_and_unknown_peers():
    text = "[Interface]\nPrivateKey = X\n\n[Peer]\nPublicKey = AAA\n\n[Peer]\nPublicKey = BBB\n"
    assert configs.drop_peer(text, "ZZZ") == text
    out = configs.drop_peer(text, "AAA")
    assert "[Interface]" in out and "AAA" not in out and "BBB" in out

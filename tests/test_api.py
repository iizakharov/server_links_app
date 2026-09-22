import json
from contextlib import contextmanager

from fastapi.testclient import TestClient

from app import configs, main, proxy, storage
from tests.test_configs import FakeRemote
from tests.test_proxy_scan import NAT

PROXY_IP, EXIT_IP, EXIT2_IP = "198.51.100.1", "203.0.113.9", "192.0.2.5"


class FakeProxy:
    """Proxy with an existing external cascade; applying our script appends CASCADE_PRE rules to iptables-save."""
    host = PROXY_IP

    def __init__(self):
        self.files = {}

    def run(self, cmd, input=None, check=True, timeout=None):
        if cmd.startswith("iptables -t raw -L CASCADE_PROBE"):
            return f" {proxy.PROBES} 100 RETURN udp\n"
        if cmd.startswith("iptables-save"):
            script = self.files.get(proxy.SCRIPT_PATH, "")
            ours = [l.replace("iptables -t nat -A", "-A") for l in script.splitlines()
                    if l.startswith("iptables -t nat -A CASCADE_PRE")]
            return NAT + "\n".join(ours) + "\n"
        return ""

    def put(self, path, content, mode="600"):
        self.files[path] = content


def setup_env(tmp_path, monkeypatch):
    monkeypatch.setattr(proxy, "PROBE_WAIT", 0)
    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)
    monkeypatch.setattr(storage, "STATE_FILE", tmp_path / "state.json")
    hosts = {PROXY_IP: FakeProxy(), EXIT_IP: FakeRemote(), EXIT2_IP: FakeRemote()}
    hosts[EXIT_IP].files["/opt/amnezia/awg/wg0.conf"] = hosts[EXIT_IP].files["/opt/amnezia/awg/wg0.conf"].replace(
        "ListenPort = 43210", "ListenPort = 48303")

    @contextmanager
    def fake_remote(server):
        yield hosts[server["host"]]

    monkeypatch.setattr(main, "Remote", fake_remote)
    api = TestClient(main.app)
    ids = {}
    for name, host in (("proxy", PROXY_IP), ("praga", EXIT_IP), ("nl", EXIT2_IP)):
        ids[name] = api.post("/api/servers", json={"name": name, "host": host, "password": "pw"}).json()["id"]
        assert api.post(f"/api/servers/{ids[name]}/scan").json()["ok"]
    return api, ids, hosts


def test_existing_cascade_is_highlighted_and_adoptable(tmp_path, monkeypatch):
    api, ids, hosts = setup_env(tmp_path, monkeypatch)
    st = api.get("/api/state").json()
    assert st["external"] == [{"proxy_id": ids["proxy"], "exit_id": ids["praga"], "port": 48303,
                               "rule": "udp 48303 → 203.0.113.9:48303 (amnezia-relay-48303)"}]
    fw = next(s for s in st["servers"] if s["id"] == ids["proxy"])["forwards"]
    assert len(fw) == 4 and all(f["known"] for f in fw)
    assert "password" not in st["servers"][0]

    assert api.post("/api/cascades/adopt", json={"proxy_id": ids["proxy"], "exit_id": ids["praga"], "port": 48303}).json()["ok"]
    st = api.get("/api/state").json()
    assert st["external"] == [] and st["cascades"][0]["status"] == "external"
    assert proxy.SCRIPT_PATH not in hosts[PROXY_IP].files  # nothing written to the proxy

    cid = st["cascades"][0]["id"]
    client = api.post("/api/clients", json={"name": "phone", "cascade_ids": [cid]}).json()["ids"][0]
    assert "Endpoint = 198.51.100.1:48303" in api.get(f"/api/clients/{client}/conf").text


def test_managed_cascade_avoids_existing_ports(tmp_path, monkeypatch):
    api, ids, hosts = setup_env(tmp_path, monkeypatch)
    r = api.post("/api/cascades", json={"proxy_id": ids["proxy"], "exit_ids": [ids["nl"]], "port": 51820}).json()
    assert not r["ok"] and "10000:60000" in r["log"][-1]
    assert proxy.SCRIPT_PATH not in hosts[PROXY_IP].files

    r = api.post("/api/cascades", json={"proxy_id": ids["proxy"], "exit_ids": [ids["nl"], ids["praga"]]}).json()
    assert r["ok"], r["log"]
    assert any("уже есть существующий каскад" in l for l in r["log"])  # praga already relayed via 48303
    script = hosts[PROXY_IP].files[proxy.SCRIPT_PATH]
    assert "--dport 60001 -j DNAT --to-destination 192.0.2.5:43210" in script
    assert "--dport 60002 -j DNAT --to-destination 203.0.113.9:48303" in script
    st = api.get("/api/state").json()
    assert [c["status"] for c in st["cascades"]] == ["applied", "applied"]

    ids_c = api.post("/api/clients", json={"name": "phone", "cascade_ids": [c["id"] for c in st["cascades"]]}).json()["ids"]
    doc = configs.decode_vpn_key(api.get(f"/api/clients/{ids_c[0]}/vpnkey").text)
    assert doc["hostName"] == PROXY_IP and doc["containers"][0]["awg"]["port"] == "60001"

    first = st["cascades"][0]["id"]
    assert api.delete(f"/api/cascades/{first}").json()["ok"]
    script = hosts[PROXY_IP].files[proxy.SCRIPT_PATH]
    assert "60001" not in script and "60002" in script
    assert len(api.get("/api/state").json()["clients"]) == 1


def test_migration_from_v1(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)
    monkeypatch.setattr(storage, "STATE_FILE", tmp_path / "state.json")
    (tmp_path / "state.json").write_text(json.dumps({
        "proxy": {"id": None, "name": "", "host": "1.1.1.1", "password": "pw", "user": "root", "ssh_port": 22},
        "foreign": [{"id": "f1", "name": "A", "host": "2.2.2.2", "info": {"listen_port": 1}, "proxy_port": 51820}],
        "clients": [], "settings": {"dns1": "8.8.8.8", "dns2": "8.8.4.4"},
    }))
    s1, s2 = storage.load(), storage.load()
    assert [x["host"] for x in s1["servers"]] == ["1.1.1.1", "2.2.2.2"]
    assert s1["servers"][0]["id"] == s2["servers"][0]["id"]  # stable after migration
    assert s1["servers"][1]["scan"] == {"awg": {"listen_port": 1}}
    assert s1["cascades"] == [] and s1["settings"]["dns1"] == "8.8.8.8"
    assert storage.DEFAULT_STATE["cascades"] == []


class Awg2Remote(FakeRemote):
    """AmneziaVPN AWG 2.0 container (S3/S4, H ranges) + docker able to start the legacy container."""

    def __init__(self):
        super().__init__()
        conf = self.files["/opt/amnezia/awg/wg0.conf"]
        self.files["/opt/amnezia/awg/wg0.conf"] = conf.replace("H1 = 111", "S3 = 53\nS4 = 16\nH1 = 100-200")
        self.legacy_started = False

    def run(self, cmd, input=None, check=True, timeout=None):
        if cmd.startswith("command -v docker >/dev/null && echo yes"):
            return "yes\n"
        if cmd.startswith("command -v docker"):
            return "amnezia-awg2\n" + ("cascade-awg-legacy\n" if self.legacy_started else "")
        if cmd.startswith("docker inspect"):
            return "amnezia-awg2\n"
        if "docker run" in cmd:
            assert "amnezia-awg2" in cmd and "--cap-add NET_ADMIN" in cmd
            self.legacy_started = True
            return ""
        if "iptables -t nat -S POSTROUTING" in cmd:
            return "-A POSTROUTING -s 10.9.0.0/24 -o eth0 -j MASQUERADE\n"
        if "awg show awgl0 listen-port" in cmd:
            return configs.parse_conf(self.files["/opt/cascade/awgl0.conf"])[0]["ListenPort"]
        if cmd.startswith("docker exec -i amnezia-awg2"):
            cmd = cmd.replace("amnezia-awg2", "amnezia-awg", 1)
        return super().run(cmd, input, check)

    def put(self, path, content, mode="600"):
        self.files[path.replace("/opt/cascade-awg-legacy", "/opt/cascade")] = content


def test_legacy_cascade_for_awg2_exit(tmp_path, monkeypatch):
    from app import foreign
    monkeypatch.setattr(foreign, "POLL_SECONDS", 0)
    monkeypatch.setattr(proxy, "PROBE_WAIT", 0)
    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)
    monkeypatch.setattr(storage, "STATE_FILE", tmp_path / "state.json")
    hosts = {PROXY_IP: FakeProxy(), EXIT_IP: Awg2Remote(), EXIT2_IP: FakeRemote()}

    @contextmanager
    def fake_remote(server):
        yield hosts[server["host"]]

    monkeypatch.setattr(main, "Remote", fake_remote)
    api = TestClient(main.app)
    ids = {n: api.post("/api/servers", json={"name": n, "host": h}).json()["id"]
           for n, h in (("proxy", PROXY_IP), ("praga", EXIT_IP), ("corp", EXIT2_IP))}

    r = api.post("/api/cascades", json={"proxy_id": ids["proxy"], "exit_ids": [ids["praga"], ids["corp"]],
                                        "instance": "legacy"}).json()
    assert r["ok"], r["log"]
    assert any("cascade-awg-legacy" in l and "amnezia-awg2" in l for l in r["log"])
    assert any("уже версии 1.0" in l for l in r["log"])  # corp: main instance is AWG 1.0 already
    st = api.get("/api/state").json()
    by_exit = {c["exit_id"]: c for c in st["cascades"]}
    assert by_exit[ids["praga"]]["instance"] == "legacy" and by_exit[ids["praga"]]["awg_version"] == "1.0"
    assert by_exit[ids["corp"]]["instance"] == "main" and by_exit[ids["corp"]]["awg_version"] == "1.0"

    legacy_port = configs.parse_conf(hosts[EXIT_IP].files["/opt/cascade/awgl0.conf"])[0]["ListenPort"]
    assert f"--to-destination {EXIT_IP}:{legacy_port}" in hosts[PROXY_IP].files[proxy.SCRIPT_PATH]

    cid = api.post("/api/clients", json={"name": "router", "cascade_ids": [by_exit[ids["praga"]]["id"]]}).json()["ids"][0]
    conf = api.get(f"/api/clients/{cid}/conf").text
    iface, peers = configs.parse_conf(conf)
    assert iface["Address"] == "10.9.0.2/32"
    assert {k.lower() for k in iface} >= {"jc", "s1", "h4"} and "S3" not in iface and "-" not in iface["H1"]
    assert "10.9.0.2/32" in hosts[EXIT_IP].files["/opt/cascade/awgl0.conf"]
    assert "clientsTable" not in str(hosts[EXIT_IP].files.keys())  # AmneziaVPN user list untouched
    assert "10.9.0.2" not in hosts[EXIT_IP].files["/opt/amnezia/awg/wg0.conf"]  # AWG 2.0 instance untouched

    # second request reuses the running legacy container
    r = api.post("/api/cascades", json={"proxy_id": ids["proxy"], "exit_ids": [ids["praga"]], "instance": "legacy"}).json()
    assert r["ok"] and any("каскад уже есть" in l for l in r["log"])


def test_is_legacy():
    from app import foreign
    assert foreign.is_legacy({"params": {"Jc": "4", "S1": "10", "H1": "5"}})
    assert foreign.is_legacy({"params": {"Jc": "4", "S3": "0", "S4": "0", "H1": "5"}})
    assert not foreign.is_legacy({"params": {"Jc": "4", "S3": "53", "H1": "5"}})
    assert not foreign.is_legacy({"params": {"Jc": "4", "H1": "100-200"}})
    assert not foreign.is_legacy({"params": {"Jc": "4", "I1": "<b 0x01>"}})


def test_state_backups_rotate(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)
    monkeypatch.setattr(storage, "STATE_FILE", tmp_path / "state.json")
    monkeypatch.setattr(storage, "BACKUPS", 3)
    for i in range(6):
        storage.save({**storage.DEFAULT_STATE, "n": i})
    backups = sorted((tmp_path / "backups").glob("state-*.json"))
    assert [json.loads(b.read_text())["n"] for b in backups] == [2, 3, 4]
    assert json.loads((tmp_path / "state.json").read_text())["n"] == 5
    assert oct((tmp_path / "state.json").stat().st_mode)[-3:] == "600" and oct(backups[0].stat().st_mode)[-3:] == "600"


def test_cascade_refused_when_udp_blocked(tmp_path, monkeypatch):
    api, ids, hosts = setup_env(tmp_path, monkeypatch)
    blocked = hosts[EXIT2_IP]
    blocked.run = lambda cmd, input=None, check=True, timeout=None: (
        " 0 0 RETURN udp\n" if cmd.startswith("iptables -t raw -L CASCADE_PROBE") else FakeRemote.run(blocked, cmd, input, check))
    r = api.post("/api/cascades", json={"proxy_id": ids["proxy"], "exit_ids": [ids["nl"]]}).json()
    assert not r["ok"] and "не доходит" in r["log"][-1]
    assert proxy.SCRIPT_PATH not in hosts[PROXY_IP].files  # nothing applied to the proxy
    assert api.get("/api/state").json()["cascades"] == []


def test_delete_client_revokes_peer(tmp_path, monkeypatch):
    api, ids, hosts = setup_env(tmp_path, monkeypatch)
    api.post("/api/cascades/adopt", json={"proxy_id": ids["proxy"], "exit_id": ids["praga"], "port": 48303})
    cid = api.get("/api/state").json()["cascades"][0]["id"]
    made = api.post("/api/clients", json={"name": "phone", "cascade_ids": [cid]}).json()["ids"][0]
    conf = hosts[EXIT_IP].files["/opt/amnezia/awg/wg0.conf"]
    assert "10.8.1.2/32" in conf

    r = api.delete(f"/api/clients/{made}").json()
    assert r["ok"] and "отозван" in r["log"][0]
    assert "10.8.1.2/32" not in hosts[EXIT_IP].files["/opt/amnezia/awg/wg0.conf"]
    assert api.get("/api/state").json()["clients"] == []
    assert api.delete(f"/api/clients/{made}").status_code == 404


def test_delete_client_keeps_it_when_server_fails(tmp_path, monkeypatch):
    api, ids, hosts = setup_env(tmp_path, monkeypatch)
    api.post("/api/cascades/adopt", json={"proxy_id": ids["proxy"], "exit_id": ids["praga"], "port": 48303})
    cid = api.get("/api/state").json()["cascades"][0]["id"]
    made = api.post("/api/clients", json={"name": "phone", "cascade_ids": [cid]}).json()["ids"][0]

    def boom(cmd, input=None, check=True, timeout=None):
        raise RuntimeError("ssh down")

    hosts[EXIT_IP].run = boom
    r = api.delete(f"/api/clients/{made}").json()
    assert not r["ok"] and "ssh down" in r["log"][-1]
    assert len(api.get("/api/state").json()["clients"]) == 1  # not lost from the list


def test_traffic_accumulates_and_survives_counter_reset(tmp_path, monkeypatch):
    api, ids, hosts = setup_env(tmp_path, monkeypatch)
    api.post("/api/cascades/adopt", json={"proxy_id": ids["proxy"], "exit_id": ids["praga"], "port": 48303})
    cid = api.get("/api/state").json()["cascades"][0]["id"]
    made = api.post("/api/clients", json={"name": "phone", "cascade_ids": [cid]}).json()["ids"][0]
    pub = next(c for c in storage.load()["clients"] if c["id"] == made)["public_key"]

    exit_host, counters = hosts[EXIT_IP], {"rx": 1000, "tx": 2000, "hs": 1790000000}
    base_run = exit_host.run

    def run(cmd, input=None, check=True, timeout=None):
        if "show wg0 transfer" in cmd:
            return f"{pub}\t{counters['rx']}\t{counters['tx']}\nOTHERKEY\t5\t5\n"
        if "show wg0 latest-handshakes" in cmd:
            return f"{pub}\t{counters['hs']}\n"
        return base_run(cmd, input, check)

    exit_host.run = run
    assert api.post("/api/traffic").json() == {"ok": True, "log": ["praga: обновлено клиентов 1"]}
    c = api.get("/api/state").json()["clients"][0]
    assert c["traffic"] == {"rx": 1000, "tx": 2000} and c["handshake"] == 1790000000 and c["stats_at"]

    counters.update(rx=1500, tx=2500)  # more traffic
    api.post("/api/traffic")
    assert api.get("/api/state").json()["clients"][0]["traffic"] == {"rx": 1500, "tx": 2500}

    counters.update(rx=100, tx=200)  # interface restarted: counters start over
    api.post("/api/traffic")
    assert api.get("/api/state").json()["clients"][0]["traffic"] == {"rx": 1600, "tx": 2700}


def test_traffic_reports_unreachable_exit(tmp_path, monkeypatch):
    api, ids, hosts = setup_env(tmp_path, monkeypatch)
    api.post("/api/cascades/adopt", json={"proxy_id": ids["proxy"], "exit_id": ids["praga"], "port": 48303})
    cid = api.get("/api/state").json()["cascades"][0]["id"]
    api.post("/api/clients", json={"name": "phone", "cascade_ids": [cid]})

    def boom(cmd, input=None, check=True, timeout=None):
        raise RuntimeError("ssh down")

    hosts[EXIT_IP].run = boom
    r = api.post("/api/traffic").json()
    assert not r["ok"] and "ssh down" in r["log"][0]
    assert api.get("/api/state").json()["clients"][0]["traffic"] is None


def test_cascade_with_awg3_container(tmp_path, monkeypatch):
    from app import foreign
    monkeypatch.setattr(foreign, "POLL_SECONDS", 0)
    api, ids, hosts = setup_env(tmp_path, monkeypatch)
    exit_host = hosts[EXIT2_IP]
    started, base_run = {"v3": False}, exit_host.run

    def run(cmd, input=None, check=True, timeout=None):
        if cmd.startswith("command -v docker >/dev/null && echo yes"):
            return "yes\n"
        if cmd.startswith("command -v docker"):
            return "cascade-awg-v3\n" if started["v3"] else ""
        if "docker run" in cmd:
            assert foreign.AWG_IMAGE in cmd
            started["v3"] = True
            return ""
        if "awg show awgv3 listen-port" in cmd:
            return configs.parse_conf(exit_host.files["/opt/cascade/awgv3.conf"])[0]["ListenPort"]
        if "iptables -t nat -S POSTROUTING" in cmd:
            return "-A POSTROUTING -s 10.9.3.0/24 -o eth0 -j MASQUERADE\n"
        return base_run(cmd, input, check)

    exit_host.run = run
    exit_host.put = lambda path, content, mode="600": exit_host.files.__setitem__(
        path.replace("/opt/cascade-awg-v3", "/opt/cascade"), content)

    r = api.post("/api/cascades", json={"proxy_id": ids["proxy"], "exit_ids": [ids["nl"]], "instance": "v3"}).json()
    assert r["ok"], r["log"]
    cas = next(c for c in api.get("/api/state").json()["cascades"] if c["exit_id"] == ids["nl"])
    assert cas["instance"] == "v3" and cas["awg_version"] == "3.x"

    iface, _ = configs.parse_conf(exit_host.files["/opt/cascade/awgv3.conf"])
    assert iface["Address"] == "10.9.3.1/24" and "HeaderProtectionKey" in iface

    cid = api.post("/api/clients", json={"name": "phone", "cascade_ids": [cas["id"]]}).json()["ids"][0]
    conf, _peers = configs.parse_conf(api.get(f"/api/clients/{cid}/conf").text)
    assert conf["HeaderProtectionKey"] == iface["HeaderProtectionKey"]  # symmetric: the client needs the same key
    assert conf["ContentPaddingAddition"] == iface["ContentPaddingAddition"] and conf["Address"] == "10.9.3.2/32"

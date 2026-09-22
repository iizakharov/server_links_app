"""Proxy side: read-only scan of existing NAT forwards, conflict checks, and our own UDP DNAT rules.

Our rules live only in chains CASCADE_PRE/CASCADE_POST/CASCADE_FWD; rules of other tools are never modified.
"""
import shlex
import time
from datetime import datetime

from . import foreign
from .ssh import Remote

SCRIPT_PATH = "/usr/local/sbin/cascade-rules.sh"
UNIT_PATH = "/etc/systemd/system/cascade-rules.service"
OUR_CHAIN = "CASCADE_PRE"

# netfilter-persistent/ufw restore whole tables on boot, so our rules must be added after them
UNIT = f"""[Unit]
Description=AmneziaWG cascade UDP forwarding rules
After=network-online.target docker.service netfilter-persistent.service ufw.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={SCRIPT_PATH}

[Install]
WantedBy=multi-user.target
"""


# ---------- scan (read-only) ----------

def parse_nat(text: str) -> list[dict]:
    """DNAT rules from `iptables-save -t nat` in PREROUTING (external) and CASCADE_PRE (ours)."""
    rules = []
    for line in text.splitlines():
        if not line.startswith("-A "):
            continue
        try:
            t = shlex.split(line)
        except ValueError:
            continue
        chain = t[1]
        if chain not in ("PREROUTING", OUR_CHAIN) or "DNAT" not in t or "!" in t:
            continue
        rule = {"chain": chain, "ours": chain == OUR_CHAIN, "proto": None, "dports": None,
                "dst": None, "to_ip": None, "to_port": None, "comment": None, "raw": line}
        for i, tok in enumerate(t[:-1]):
            nxt = t[i + 1]
            if tok == "-p":
                rule["proto"] = nxt
            elif tok == "-d":
                rule["dst"] = nxt.removesuffix("/32")
            elif tok in ("--dport", "--dports", "--destination-port", "--destination-ports"):
                rule["dports"] = [
                    (int(a), int(b or a)) for a, _, b in (p.partition(":") for p in nxt.split(","))
                ]
            elif tok == "--to-destination":
                ip, _, port = nxt.partition(":")
                rule["to_ip"] = ip
                rule["to_port"] = int(port.split("-")[0]) if port else None
            elif tok == "--comment":
                rule["comment"] = nxt
        if rule["to_ip"]:
            rules.append(rule)
    return rules


def scan(r: Remote) -> dict:
    return {
        "os": r.run(". /etc/os-release 2>/dev/null; echo $PRETTY_NAME", check=False).strip(),
        "awg": foreign.detect(r),
        **{f"awg_{name}": foreign.detect_instance(r, name) for name in foreign.INSTANCES},
        "nat": parse_nat(r.run("iptables-save -t nat 2>/dev/null || true", check=False)),
        "udp_listen": foreign.parse_udp_listen(r.run("ss -Huln 2>/dev/null || true", check=False)),
        "at": datetime.now().strftime("%Y-%m-%d %H:%M"),
    }


# ---------- analysis ----------

def covers(rule: dict, proto: str, port: int) -> bool:
    if rule["proto"] not in (None, "all", proto):
        return False
    if rule["dports"] is None:
        return True
    return any(lo <= port <= hi for lo, hi in rule["dports"])


def forwarded_port(rule: dict, port: int) -> int:
    return rule["to_port"] or port


def describe(rule: dict) -> str:
    ports = ",".join(f"{lo}" if lo == hi else f"{lo}:{hi}" for lo, hi in rule["dports"] or []) or "все порты"
    target = rule["to_ip"] + (f":{rule['to_port']}" if rule["to_port"] else "")
    note = f" ({rule['comment']})" if rule["comment"] else ""
    return f"{rule['proto'] or 'all'} {ports} → {target}{note}"


def port_conflict(port: int, scan_: dict, taken: set[int]) -> str | None:
    """Why `port` cannot be used for a new managed UDP forward on this proxy, or None if it is free."""
    if not 1 <= port <= 65535:
        return f"Некорректный порт {port}"
    if port in taken:
        return f"UDP {port} уже занят другим каскадом этого прокси"
    for rule in scan_.get("nat") or []:
        if not rule["ours"] and covers(rule, "udp", port):
            return f"UDP {port} уже пробрасывается существующим правилом: {describe(rule)}"
    if port in (scan_.get("udp_listen") or []):
        return f"UDP {port} занят процессом на прокси"
    return None


def pick_port(scan_: dict, taken: set[int], start: int = 51820) -> int:
    for port in [*range(start, 65536), *range(1024, start)]:
        if port_conflict(port, scan_, taken) is None:
            return port
    raise RuntimeError("Нет свободных UDP-портов на прокси")


def external_cascades(servers: list[dict], ip_of) -> list[dict]:
    """Existing (not ours) forwards proxy -> AmneziaWG port of a known server."""
    found = []
    for p in servers:
        nat = [r for r in (p.get("scan") or {}).get("nat") or [] if not r["ours"]]
        for e in servers:
            awg = (e.get("scan") or {}).get("awg")
            if e is p or not awg:
                continue
            eip, aport = ip_of(e), awg["listen_port"]
            cands = [r for r in nat if r["to_ip"] == eip and r["proto"] in (None, "all", "udp")]
            hit = None
            for r in cands:  # explicit single-port relay first
                if r["dports"] and len(r["dports"]) == 1 and r["dports"][0][0] == r["dports"][0][1] \
                        and forwarded_port(r, r["dports"][0][0]) == aport:
                    hit = (r["dports"][0][0], r)
                    break
            if not hit:
                hit = next(((aport, r) for r in cands if r["to_port"] is None and covers(r, "udp", aport)), None)
            if hit:
                found.append({"proxy_id": p["id"], "exit_id": e["id"], "port": hit[0], "rule": describe(hit[1])})
    return found


def managed_status(cascade: dict, proxy_scan: dict | None, exit_ip: str) -> str:
    """applied | missing | conflict | unknown (proxy not scanned yet)."""
    if not proxy_scan:
        return "unknown"
    nat = proxy_scan.get("nat") or []
    if any(not r["ours"] and covers(r, "udp", cascade["port"]) for r in nat):
        return "conflict"
    ok = any(r["ours"] and covers(r, "udp", cascade["port"]) and r["to_ip"] == exit_ip for r in nat)
    return "applied" if ok else "missing"


# ---------- link check ----------

PROBE_CHAIN = "CASCADE_PROBE"
PROBES = 5
PROBE_WAIT = 2

def _probe_begin(r: Remote, src_ip: str, port: int) -> None:
    """Counting-only rule in raw/PREROUTING: it sees every incoming packet (also ones docker DNATs away)
    and never changes what happens to it."""
    r.run(f"iptables -t raw -N {PROBE_CHAIN} 2>/dev/null; iptables -t raw -F {PROBE_CHAIN}; "
          f"iptables -t raw -A {PROBE_CHAIN} -p udp -s {src_ip} --dport {port} -j RETURN; "
          f"iptables -t raw -C PREROUTING -j {PROBE_CHAIN} 2>/dev/null || iptables -t raw -I PREROUTING 1 -j {PROBE_CHAIN}")


def _probe_end(r: Remote) -> int:
    out = r.run(f"iptables -t raw -L {PROBE_CHAIN} -n -v -x 2>/dev/null || true", check=False)
    r.run(f"iptables -t raw -D PREROUTING -j {PROBE_CHAIN} 2>/dev/null; iptables -t raw -F {PROBE_CHAIN} 2>/dev/null; "
          f"iptables -t raw -X {PROBE_CHAIN} 2>/dev/null; true", check=False)
    for line in out.splitlines():
        cols = line.split()
        if "RETURN" in line and cols and cols[0].isdigit():
            return int(cols[0])
    return 0


def udp_reaches(sender: Remote, receiver: Remote, receiver_ip: str, port: int) -> int:
    """Sends PROBES UDP packets sender -> receiver_ip:port and returns how many arrived."""
    _probe_begin(receiver, sender.host, port)
    try:
        sender.run(f"for i in $(seq {PROBES}); do echo cascade-probe > /dev/udp/{receiver_ip}/{port} 2>/dev/null || true; done",
                   check=False)
        time.sleep(PROBE_WAIT)
    finally:
        got = _probe_end(receiver)
    return got


def check_link(rp: Remote, re_: Remote, exit_ip: str, exit_port: int, back_port: int, log) -> str | None:
    """None if UDP flows both ways, otherwise a human-readable reason the cascade would not work."""
    got = udp_reaches(rp, re_, exit_ip, exit_port)
    log(f"проверка связи: прокси → {re_.host}:{exit_port} — дошло {got} из {PROBES}")
    if not got:
        return (f"UDP с прокси {rp.host} не доходит до {re_.host}:{exit_port} (0 из {PROBES}). "
                f"Трафик блокируется между этими сетями — каскад работать не будет. Нужен другой адрес сервера выхода или другой прокси")
    back = udp_reaches(re_, rp, rp.host, back_port)
    log(f"проверка связи: {re_.host} → прокси:{back_port} — дошло {back} из {PROBES}")
    if not back:
        return (f"UDP от {re_.host} не доходит до прокси {rp.host} (0 из {PROBES}). "
                f"Ответы сервера выхода не вернутся к клиентам — проверьте firewall хостера прокси")
    return None


# ---------- apply ----------

def rules_script(routes: list[tuple[int, str, int]]) -> str:
    """routes: (proxy_port, foreign_ip, foreign_port). Chains are flushed and refilled, so reruns are idempotent."""
    lines = [
        "#!/bin/sh",
        "# generated by vpn_service — do not edit, manage cascades in the app instead",
        "sysctl -q -w net.ipv4.ip_forward=1",
        "iptables -t nat -N CASCADE_PRE 2>/dev/null; iptables -t nat -F CASCADE_PRE",
        "iptables -t nat -N CASCADE_POST 2>/dev/null; iptables -t nat -F CASCADE_POST",
        "iptables -N CASCADE_FWD 2>/dev/null; iptables -F CASCADE_FWD",
        "iptables -t nat -C PREROUTING -j CASCADE_PRE 2>/dev/null || iptables -t nat -I PREROUTING -j CASCADE_PRE",
        "iptables -t nat -C POSTROUTING -j CASCADE_POST 2>/dev/null || iptables -t nat -I POSTROUTING -j CASCADE_POST",
        "iptables -C FORWARD -j CASCADE_FWD 2>/dev/null || iptables -I FORWARD -j CASCADE_FWD",
        "iptables -A CASCADE_FWD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
    ]
    for pport, fip, fport in routes:
        lines += [
            f"iptables -t nat -A CASCADE_PRE -p udp --dport {pport} -j DNAT --to-destination {fip}:{fport}",
            f"iptables -t nat -A CASCADE_POST -p udp -d {fip} --dport {fport} -j MASQUERADE",
            f"iptables -A CASCADE_FWD -p udp -d {fip} --dport {fport} -j ACCEPT",
        ]
    return "\n".join(lines) + "\n"


def setup(r: Remote, routes: list[tuple[int, str, int]], log) -> None:
    r.run("command -v iptables >/dev/null || (apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q iptables)")
    r.run("echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-cascade.conf")
    r.put(SCRIPT_PATH, rules_script(routes), mode="700")
    r.put(UNIT_PATH, UNIT, mode="644")
    r.run("systemctl daemon-reload && systemctl enable cascade-rules.service >/dev/null 2>&1 && systemctl restart cascade-rules.service")
    for pport, fip, fport in routes:
        log(f"[{r.host}] UDP {pport} → {fip}:{fport}")
    log(f"[{r.host}] правила приложения обновлены ({len(routes)} маршрутов); чужие правила не тронуты")

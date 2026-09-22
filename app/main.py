"""Local web UI: server inventory, cascades (proxy -> exit) built from it, client configs."""
import re
import socket
import uuid
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel

from . import configs, foreign, proxy, storage
from .ssh import Remote

app = FastAPI(title="AmneziaWG cascade")
INDEX = Path(__file__).parent / "static" / "index.html"


class ServerIn(BaseModel):
    id: str | None = None
    name: str = ""
    host: str
    ssh_port: int = 22
    user: str = "root"
    password: str = ""
    key_path: str = ""


class CascadeIn(BaseModel):
    proxy_id: str
    exit_ids: list[str]
    port: int | None = None
    instance: str = "auto"  # auto (что стоит на сервере) | legacy (1.0) | v2 | v3


class AdoptIn(BaseModel):
    proxy_id: str
    exit_id: str
    port: int


class ClientIn(BaseModel):
    name: str
    cascade_ids: list[str]


class OpError(Exception):
    pass


def _find(items: list[dict], id_: str) -> dict:
    for it in items:
        if it["id"] == id_:
            return it
    raise HTTPException(404, "not found")


def ip_of(server: dict) -> str:
    try:
        return socket.gethostbyname(server["host"])
    except OSError:
        return server["host"]


def _public(server: dict) -> dict:
    out = {k: v for k, v in server.items() if k != "password"}
    out["has_password"] = bool(server.get("password"))
    return out


def scan_key(instance: str) -> str:
    """Where a scan keeps this AmneziaWG instance: the server's own one, or one of our containers."""
    return "awg" if instance == "main" else f"awg_{instance}"


def exit_awg(e: dict, cascade: dict) -> dict:
    """AmneziaWG instance of the exit server this cascade leads to."""
    return (e.get("scan") or {}).get(scan_key(cascade.get("instance", "main")))


def detect_instance(r, instance: str) -> dict | None:
    return foreign.detect(r) if instance == "main" else foreign.detect_instance(r, instance)


def _managed_routes(s: dict, proxy_id: str) -> list[tuple[int, str, int]]:
    routes = []
    for c in s["cascades"]:
        if c["proxy_id"] == proxy_id and c["mode"] == "managed":
            e = _find(s["servers"], c["exit_id"])
            routes.append((c["port"], ip_of(e), exit_awg(e, c)["listen_port"]))
    return routes


def _apply_proxy(s: dict, p: dict, log) -> None:
    with Remote(p) as r:
        proxy.setup(r, _managed_routes(s, p["id"]), log)
        p["scan"] = proxy.scan(r)


@app.get("/")
def index():
    return FileResponse(INDEX)


@app.get("/api/state")
def get_state():
    s = storage.load()
    by_id = {x["id"]: x for x in s["servers"]}
    cascades = []
    for c in s["cascades"]:
        p, e = by_id[c["proxy_id"]], by_id[c["exit_id"]]
        status = "external" if c["mode"] == "external" else proxy.managed_status(c, p.get("scan"), ip_of(e))
        awg = exit_awg(e, c)
        cascades.append({"instance": "main", **c, "status": status,
                         "awg_version": foreign.awg_version(awg) if awg else None})
    adopted = {(c["proxy_id"], c["exit_id"], c["port"]) for c in s["cascades"]}
    external = [x for x in proxy.external_cascades(s["servers"], ip_of)
                if (x["proxy_id"], x["exit_id"], x["port"]) not in adopted]
    known_ips = {ip_of(x) for x in s["servers"]}
    servers = []
    for x in s["servers"]:
        pub = _public(x)
        nat = [r for r in ((x.get("scan") or {}).get("nat") or []) if not r["ours"]]
        pub["forwards"] = [{"rule": proxy.describe(r), "known": r["to_ip"] in known_ips} for r in nat]
        servers.append(pub)
    return {
        "servers": servers,
        "cascades": cascades,
        "external": external,
        "clients": [{**{k: c[k] for k in ("id", "name", "cascade_id", "ip", "created")},
                     "traffic": c.get("traffic"), "handshake": c.get("handshake"), "stats_at": c.get("stats_at")}
                    for c in s["clients"]],
    }


@app.post("/api/servers")
def upsert_server(body: ServerIn):
    s = storage.load()
    old = next((x for x in s["servers"] if x["id"] == body.id), None) if body.id else None
    data = body.model_dump()
    if not data["password"] and old and old["host"] == data["host"]:
        data["password"] = old.get("password", "")
    data["id"] = old["id"] if old else uuid.uuid4().hex[:8]
    data["name"] = data["name"] or data["host"]
    data["scan"] = old.get("scan") if old and old["host"] == data["host"] else None
    if old:
        s["servers"][s["servers"].index(old)] = data
    else:
        s["servers"].append(data)
    storage.save(s)
    return {"ok": True, "id": data["id"]}


@app.delete("/api/servers/{sid}")
def delete_server(sid: str):
    s = storage.load()
    if any(sid in (c["proxy_id"], c["exit_id"]) for c in s["cascades"]):
        raise HTTPException(400, "Сервер используется в каскаде — сначала удалите каскад")
    s["servers"].remove(_find(s["servers"], sid))
    storage.save(s)
    return {"ok": True}


@app.post("/api/servers/{sid}/scan")
def scan_server(sid: str):
    """Read-only: OS, AmneziaWG, existing NAT forwards, busy UDP ports."""
    s = storage.load()
    x = _find(s["servers"], sid)
    try:
        with Remote(x) as r:
            x["scan"] = proxy.scan(r)
    except Exception as e:
        return {"ok": False, "message": f"{x['name']}: {e}"}
    storage.save(s)
    return {"ok": True, "message": f"{x['name']}: {x['scan']['os']}"}


@app.post("/api/cascades")
def create_cascades(body: CascadeIn):
    s = storage.load()
    log: list[str] = []
    try:
        p = _find(s["servers"], body.proxy_id)
        if not body.exit_ids:
            raise OpError("Выберите хотя бы один сервер выхода")
        if body.proxy_id in body.exit_ids:
            raise OpError("Прокси не может быть выходом сам для себя")
        if body.port and len(body.exit_ids) > 1:
            raise OpError("Порт можно задать вручную только для одного выхода")

        log.append(f"[{p['host']}] сканирование прокси…")
        with Remote(p) as r:
            p["scan"] = proxy.scan(r)
        storage.save(s)

        new, taken = [], {c["port"] for c in s["cascades"] if c["proxy_id"] == p["id"]}
        for eid in body.exit_ids:
            e = _find(s["servers"], eid)
            log.append(f"[{e['host']}] проверка AmneziaWG ({e['name']})…")
            with Remote(e) as r:
                want = body.instance
                if want not in ("auto", *foreign.INSTANCES):
                    raise OpError(f"Неизвестная версия AmneziaWG: {want}")
                main_awg = foreign.detect(r)
                if want == "legacy" and main_awg and foreign.is_legacy(main_awg):
                    awg, instance = main_awg, "main"
                    log.append(f"{e['name']}: основной AmneziaWG уже версии 1.0 — отдельный контейнер не нужен")
                elif want == "auto":
                    awg, instance = foreign.ensure(r, log.append), "main"
                else:
                    awg = foreign.detect_instance(r, want) or foreign.install_instance(r, want, main_awg, log.append)
                    instance = want
                e["scan"] = {**(e.get("scan") or {}), scan_key(instance): awg}
                if main_awg:
                    e["scan"]["awg"] = main_awg
            storage.save(s)
            if any(c["proxy_id"] == p["id"] and c["exit_id"] == eid and c["mode"] == "managed"
                   and c.get("instance", "main") == instance for c in s["cascades"]):
                log.append(f"{p['name']} → {e['name']}: каскад уже есть, пропущен")
                continue
            if instance == "main":
                for x in proxy.external_cascades([p, e], ip_of):
                    log.append(f"ВНИМАНИЕ: уже есть существующий каскад {p['name']} → {e['name']} через UDP {x['port']} "
                               f"({x['rule']}); его можно просто «Использовать»")
            port = body.port or proxy.pick_port(p["scan"], taken)
            if err := proxy.port_conflict(port, p["scan"], taken):
                raise OpError(err)
            with Remote(p) as rp, Remote(e) as re_:
                back = proxy.pick_port(p["scan"], taken | {port})
                if err := proxy.check_link(rp, re_, ip_of(e), awg["listen_port"], back, log.append):
                    raise OpError(err)
            taken.add(port)
            new.append({"id": uuid.uuid4().hex[:8], "proxy_id": p["id"], "exit_id": eid, "port": port,
                        "mode": "managed", "instance": instance})

        if new:
            s["cascades"] += new
            log.append(f"[{p['host']}] применение правил…")
            _apply_proxy(s, p, log.append)
            storage.save(s)
        return {"ok": True, "log": log}
    except HTTPException:
        raise
    except Exception as e:
        log.append(f"ОШИБКА: {e}")
        return {"ok": False, "log": log}


@app.post("/api/cascades/adopt")
def adopt_cascade(body: AdoptIn):
    s = storage.load()
    match = [x for x in proxy.external_cascades(s["servers"], ip_of)
             if (x["proxy_id"], x["exit_id"], x["port"]) == (body.proxy_id, body.exit_id, body.port)]
    if not match:
        raise HTTPException(400, "Такой существующий каскад не найден — пересканируйте серверы")
    s["cascades"].append({"id": uuid.uuid4().hex[:8], **body.model_dump(), "mode": "external", "instance": "main"})
    storage.save(s)
    return {"ok": True}


@app.delete("/api/cascades/{cid}")
def delete_cascade(cid: str):
    s = storage.load()
    c = _find(s["cascades"], cid)
    s["cascades"].remove(c)
    s["clients"] = [x for x in s["clients"] if x["cascade_id"] != cid]
    log: list[str] = []
    if c["mode"] == "managed":
        try:
            _apply_proxy(s, _find(s["servers"], c["proxy_id"]), log.append)
        except Exception as e:
            return {"ok": False, "log": log + [f"ОШИБКА: {e}"]}
    else:
        log.append("Существующий каскад убран из приложения; правила на прокси не тронуты")
    storage.save(s)
    return {"ok": True, "log": log}


@app.post("/api/cascades/{cid}/check")
def check_cascade(cid: str):
    """Sends UDP probes proxy <-> exit and reports whether the cascade can work at all."""
    s = storage.load()
    c = _find(s["cascades"], cid)
    p, e = _find(s["servers"], c["proxy_id"]), _find(s["servers"], c["exit_id"])
    awg = exit_awg(e, c)
    if not awg:
        raise HTTPException(400, f"{e['name']} не сканирован")
    log: list[str] = []
    try:
        with Remote(p) as rp, Remote(e) as re_:
            back = proxy.pick_port(p.get("scan") or {}, {x["port"] for x in s["cascades"]})
            err = proxy.check_link(rp, re_, ip_of(e), awg["listen_port"], back, log.append)
    except Exception as exc:
        return {"ok": False, "log": log + [f"ОШИБКА: {exc}"]}
    return {"ok": not err, "log": log + ([err] if err else ["связь в обе стороны работает"])}


@app.post("/api/clients")
def create_clients(body: ClientIn):
    s = storage.load()
    name = re.sub(r"[^\w\-. ]", "", body.name).strip()[:40] or "client"
    if not body.cascade_ids:
        raise HTTPException(400, "Выберите хотя бы один каскад")
    created = []
    try:
        for cid in body.cascade_ids:
            cas = _find(s["cascades"], cid)
            e = _find(s["servers"], cas["exit_id"])
            inst = cas.get("instance", "main")
            with Remote(e) as r:
                awg = detect_instance(r, inst)
                if not awg:
                    raise RuntimeError(f"На {e['name']} не найден AmneziaWG ({inst})")
                e["scan"] = {**(e.get("scan") or {}), scan_key(inst): awg}
                keys = foreign.add_peer(r, awg, name)
            client = {"id": uuid.uuid4().hex[:8], "name": name, "cascade_id": cid,
                      "created": datetime.now().strftime("%Y-%m-%d %H:%M"), **keys}
            s["clients"].append(client)
            storage.save(s)
            created.append(client["id"])
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))
    return {"ok": True, "ids": created}


def _accumulate(client: dict, raw: dict) -> None:
    """Adds the delta since the last poll; a counter that went backwards means the interface was restarted."""
    prev, total = client.get("raw") or {"rx": 0, "tx": 0}, client.get("traffic") or {"rx": 0, "tx": 0}
    for k in ("rx", "tx"):
        delta = raw[k] - prev[k]
        total[k] += raw[k] if delta < 0 else delta
    client["traffic"] = total
    client["raw"] = {"rx": raw["rx"], "tx": raw["tx"]}
    client["handshake"] = raw["handshake"]
    client["stats_at"] = datetime.now().strftime("%Y-%m-%d %H:%M")


@app.post("/api/traffic")
def refresh_traffic():
    """Reads per-peer counters from every exit server and accumulates them per client."""
    s = storage.load()
    log: list[str] = []
    groups: dict[tuple[str, str], list[dict]] = {}
    for c in s["clients"]:
        cas = _find(s["cascades"], c["cascade_id"])
        groups.setdefault((cas["exit_id"], cas.get("instance", "main")), []).append(c)
    for (eid, instance), clients in groups.items():
        e = _find(s["servers"], eid)
        try:
            with Remote(e) as r:
                awg = detect_instance(r, instance)
                if not awg:
                    raise RuntimeError("AmneziaWG не найден")
                stats = foreign.peer_stats(r, awg)
        except Exception as exc:
            log.append(f"ОШИБКА ({e['name']}): {exc}")
            continue
        missing = 0
        for c in clients:
            raw = stats.get(c["public_key"])
            if raw:
                _accumulate(c, raw)
            else:
                missing += 1
        log.append(f"{e['name']}: обновлено клиентов {len(clients) - missing}"
                   + (f", не найдено на сервере {missing}" if missing else ""))
    storage.save(s)
    return {"ok": not any(l.startswith("ОШИБКА") for l in log), "log": log}


@app.delete("/api/clients/{cid}")
def delete_client(cid: str):
    """Revokes the client on the exit server and removes it from the list."""
    s = storage.load()
    c = _find(s["clients"], cid)
    cas = _find(s["cascades"], c["cascade_id"])
    e = _find(s["servers"], cas["exit_id"])
    log: list[str] = []
    try:
        with Remote(e) as r:
            awg = detect_instance(r, cas.get("instance", "main"))
            if not awg:
                raise RuntimeError(f"На {e['name']} не найден AmneziaWG ({cas.get('instance', 'main')})")
            foreign.remove_peer(r, awg, c["public_key"])
        log.append(f"[{e['host']}] доступ клиента {c['name']} ({c['ip']}) отозван")
    except Exception as exc:
        return {"ok": False, "log": log + [f"ОШИБКА: {exc}"]}
    s["clients"].remove(c)
    storage.save(s)
    return {"ok": True, "log": log}


def _render(cid: str):
    s = storage.load()
    c = _find(s["clients"], cid)
    cas = _find(s["cascades"], c["cascade_id"])
    p, e = _find(s["servers"], cas["proxy_id"]), _find(s["servers"], cas["exit_id"])
    args = (c, exit_awg(e, cas), p["host"], cas["port"], s["settings"]["dns1"], s["settings"]["dns2"])
    return c, p, e, args


@app.get("/api/clients/{cid}/conf")
def client_conf(cid: str):
    c, p, e, args = _render(cid)
    filename = re.sub(r"[^A-Za-z0-9_\-]", "_", f"{c['name']}_{p['name']}_{e['name']}") + ".conf"
    return PlainTextResponse(configs.client_conf(*args),
                             headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@app.get("/api/clients/{cid}/vpnkey")
def client_vpnkey(cid: str):
    c, p, e, args = _render(cid)
    return PlainTextResponse(configs.vpn_key(f"{c['name']} ({p['name']} → {e['name']})", *args))

"""Local state in data/state.json (contains SSH credentials and keys -> chmod 600)."""
import json
import os
import threading
import uuid
from datetime import datetime
from pathlib import Path

DATA_DIR = Path(os.environ.get("CASCADE_DATA_DIR", Path(__file__).resolve().parent.parent / "data"))
STATE_FILE = DATA_DIR / "state.json"

_lock = threading.Lock()
BACKUPS = 30

DEFAULT_STATE = {
    "servers": [],
    "cascades": [],
    "clients": [],
    "settings": {"dns1": "1.1.1.1", "dns2": "1.0.0.1"},
}
SERVER_KEYS = ("id", "name", "host", "ssh_port", "user", "password", "key_path")


def migrate(state: dict) -> dict:
    """v1 (one proxy + foreign list) -> v2 (server inventory + cascades)."""
    if "servers" in state:
        return state
    servers = []
    if state.get("proxy"):
        p = state["proxy"]
        servers.append({**{k: p.get(k) for k in SERVER_KEYS}, "id": uuid.uuid4().hex[:8],
                        "name": p.get("name") or p["host"], "scan": None})
    for f in state.get("foreign", []):
        scan = {"awg": f["info"]} if f.get("info") else None
        servers.append({**{k: f.get(k) for k in SERVER_KEYS}, "scan": scan})
    new = json.loads(json.dumps(DEFAULT_STATE))
    new["servers"] = servers
    new["settings"] = state.get("settings", new["settings"])
    return new


def load() -> dict:
    with _lock:
        if not STATE_FILE.exists():
            return json.loads(json.dumps(DEFAULT_STATE))
        raw = json.loads(STATE_FILE.read_text())
    state = migrate(raw)
    if state is not raw:
        save(state)  # persist once so generated ids stay stable
    return state


def save(state: dict) -> None:
    with _lock:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        tmp = STATE_FILE.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(state, f, indent=2, ensure_ascii=False)
        if STATE_FILE.exists():
            _backup()
        os.replace(tmp, STATE_FILE)


def _backup() -> None:
    """Keeps the last BACKUPS versions of state.json in data/backups/ (a mistaken edit can be rolled back)."""
    bdir = DATA_DIR / "backups"
    bdir.mkdir(mode=0o700, exist_ok=True)
    dst = bdir / f"state-{datetime.now().strftime('%Y%m%d-%H%M%S-%f')}.json"
    fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(STATE_FILE.read_bytes())
    for old in sorted(bdir.glob("state-*.json"))[:-BACKUPS]:
        old.unlink()

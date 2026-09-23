// In-browser stand-in for the Rust side (development / UI checks only).
import type { HelperState, Share, Status, View } from "./api";

const SAMPLE = `[Interface]
PrivateKey = QOmpv2x9XXXvF5Bz3ZX1+fjJvP9j8ixn8gRkcM9m60E=
Address = 10.9.3.2/32
DNS = 1.1.1.1, 1.0.0.1
MTU = 1280
Jc = 5
S3 = 30
H1 = 5-100005
HeaderProtectionKey = FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=

[Peer]
PublicKey = k8r3m0ZcY2JQdO4kxyKq3yE1m6h8nT2gQ3v3m0Zc1Xo=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 198.51.100.1:60006
PersistentKeepalive = 25
`;

let view: View = {
  profiles: [
    { id: "p1", name: "Прага (каскад)", endpoint: "198.51.100.1:60006", address: "10.9.3.2/32", awg_version: "3.x" },
    { id: "p2", name: "Рига", endpoint: "203.0.113.20:48303", address: "10.8.1.5/32", awg_version: "2.0" },
  ],
  selected: "p1",
  settings: { theme: "system", kill_switch: false, allow_lan: true, autoconnect: false, split: { mode: "all", entries: [] } },
};
let status: Status = { connected: false, name: "", iface: "", endpoint: "", since: 0, stats: { rx: 0, tx: 0, handshake: 0 },
                      blocked: false, kill_switch: false, helper_version: "0.1.1+mock" };
let helper: HelperState = { installed: true, running: true, outdated: false };
const manageView = {
  servers: [
    { id: "s1", name: "Прокси", host: "198.51.100.1", ssh_port: 22, user: "root", key_path: "", has_password: true,
      os: "Debian GNU/Linux 12", scanned_at: "2026-09-23 12:00", awg: [], forwards: ["udp 48303 → 203.0.113.9:48303"] },
    { id: "s2", name: "Прага", host: "203.0.113.9", ssh_port: 22, user: "root", key_path: "", has_password: true,
      os: "Ubuntu 24.04", scanned_at: "2026-09-23 12:00",
      awg: [{ instance: "main", version: "2.0", port: 48303 }, { instance: "v3", version: "3.x", port: 56508 }], forwards: [] },
  ],
  cascades: [
    { id: "c1", proxy_id: "s1", exit_id: "s2", port: 48303, mode: "external", status: "external", awg_version: "2.0" },
    { id: "c2", proxy_id: "s1", exit_id: "s2", port: 60006, mode: "managed", instance: "v3", status: "applied", awg_version: "3.x" },
  ],
  external: [],
  clients: [
    { id: "k1", name: "phone", cascade_id: "c2", ip: "10.9.3.2", created: "2026-09-22 20:58",
      traffic: { rx: 42_000_000, tx: 1_500_000_000 }, handshake: Math.floor(Date.now() / 1000) - 60, stats_at: "2026-09-23 12:00" },
  ],
  busy: false,
};
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));
const now = () => Math.floor(Date.now() / 1000);
const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v));

export async function mock(cmd: string, a: Record<string, any>): Promise<unknown> {
  await wait(120);
  const p = view.profiles.find((x) => x.id === a.id);
  switch (cmd) {
    case "get_view": return clone(view);
    case "check_update": return { current: "0.1.1", version: "0.1.2", notes: "Пример: что нового" };
    case "install_update": throw "В браузере обновление не устанавливается";
    case "import_text": {
      const text = String(a.text).trim();
      if (!text.startsWith("vpn://") && !text.includes("[Interface]")) throw "Это не ключ vpn:// и не конфиг AmneziaWG";
      const id = Math.random().toString(16).slice(2, 10);
      view.profiles.push({ id, name: a.name || `Сервер ${view.profiles.length + 1}`, endpoint: "192.0.2.7:51820", address: "10.8.1.9/32", awg_version: "2.0" });
      view.selected = id;
      return clone(view);
    }
    case "rename_profile": if (p) p.name = a.name; return clone(view);
    case "remove_profile":
      view.profiles = view.profiles.filter((x) => x.id !== a.id);
      if (view.selected === a.id) view.selected = view.profiles[0]?.id ?? null;
      return clone(view);
    case "select_profile": view.selected = a.id; return clone(view);
    case "set_settings": view.settings = a.settings; return clone(view);
    case "share": {
      const cells = Array.from({ length: 29 * 29 }, (_, i) => ((i * 7919) % 13 < 6 ? 1 : 0));
      const rects = cells.map((c, i) => c ? `<rect x="${i % 29}" y="${Math.floor(i / 29)}" width="1" height="1"/>` : "").join("");
      const qr = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="-2 -2 33 33"><rect x="-2" y="-2" width="33" height="33" fill="#fff"/><g fill="#000">${rects}</g></svg>`;
      return { name: p?.name ?? "", conf: SAMPLE, vpn_key: "vpn://AAAHnnjapVRNj9owEL3vr4hy7yHBCQl7s0SQUsAVJb1s5ZUTG7AaOSk2S7cV_71jhxSQCmp3fYlm3sy8mfFYfnh6enrU", qr_svg: qr } satisfies Share;
    }
    case "save_text": return;
    case "connect":
      if (!helper.running) throw "служба АМнеЗинуVPN не запущена";
      await wait(900);
      status = { ...status, connected: true, name: p?.name ?? "", iface: "utun9", endpoint: p?.endpoint ?? "", since: now(),
                 stats: { rx: 0, tx: 0, handshake: now() }, kill_switch: view.settings.kill_switch };
      return clone(status);
    case "disconnect":
      await wait(300);
      status = { ...status, connected: false };
      return clone(status);
    case "status":
      if (!helper.running) throw "служба АМнеЗинуVPN не запущена";
      if (status.connected) { status.stats.rx += 180_000 + Math.random() * 90_000; status.stats.tx += 22_000; }
      return clone(status);
    case "helper_state": return clone(helper);
    case "install_helper": await wait(800); helper = { installed: true, running: true, outdated: false }; return clone(helper);
    case "uninstall_helper": helper = { installed: false, running: false, outdated: false }; return clone(helper);
  }
  if (cmd === "manage_view") return clone(manageView);
  if (["manage_server_scan", "manage_traffic", "manage_cascade_check"].includes(cmd)) {
    await wait(700);
    return { ok: true, log: ["проверка связи: прокси → 203.0.113.9:48303 — дошло 5 из 5", "связь в обе стороны работает"] };
  }
  throw `В браузере управление серверами недоступно (${cmd})`;
}

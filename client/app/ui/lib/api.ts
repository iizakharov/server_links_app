// Calls into the Rust side (Tauri commands). Outside Tauri (plain browser) a mock is used,
// so the UI can be developed and checked without the app shell.
export const isWindows = navigator.userAgent.includes("Windows");
/** where the app keeps keys and passwords, for texts in the UI */
export const secretStore = isWindows ? "диспетчере учётных данных Windows" : "связке ключей macOS";

export type ProfileView = {
  id: string; name: string; endpoint: string; address: string; awg_version: string;
  /** profiles of one multi-exit key share a group; exit = where the traffic leaves */
  group: string | null; exit: string | null; title: string;
};
export type SplitMode = "all" | "only" | "except";
export type Settings = {
  theme: string;
  kill_switch: boolean;
  allow_lan: boolean;
  autoconnect: boolean;
  split: { mode: SplitMode; entries: string[] };
};
export type View = { profiles: ProfileView[]; selected: string | null; settings: Settings };
export type Stats = { rx: number; tx: number; handshake: number };
export type Status = {
  connected: boolean; name: string; iface: string; endpoint: string; since: number; stats: Stats;
  blocked: boolean; kill_switch: boolean; helper_version: string;
};
export type Share = { name: string; conf: string; vpn_key: string; qr_svg: string };
export type HelperState = { installed: boolean; running: boolean; outdated: boolean };
export type UpdateInfo = { current: string; version: string | null; notes: string | null };

export const inTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (inTauri) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<T>(cmd, args);
  }
  const { mock } = await import("./mock");
  return mock(cmd, args ?? {}) as Promise<T>;
}

export type AwgView = { instance: string; version: string; port: number };
export type MServer = {
  id: string; name: string; host: string; ssh_port: number; user: string; key_path: string; has_password: boolean;
  os: string; scanned_at: string; awg: AwgView[]; forwards: string[];
};
export type MCascade = {
  id: string; proxy_id: string; exit_id: string; port: number; mode: string; instance?: string;
  status: string; awg_version: string | null;
};
export type MExternal = { proxy_id: string; exit_id: string; port: number; rule: string };
export type MClient = {
  id: string; name: string; cascade_id: string; ip: string; created: string;
  traffic: { rx: number; tx: number } | null; handshake: number | null; stats_at: string | null;
};
export type ManageView = { servers: MServer[]; cascades: MCascade[]; external: MExternal[]; clients: MClient[]; busy: boolean };
export type OpLog = { ok: boolean; log: string[] };
export type ServerIn = { id: string | null; name: string; host: string; ssh_port: number; user: string; password: string; key_path: string };

export const manage = {
  view: () => call<ManageView>("manage_view"),
  saveServer: (server: ServerIn) => call<string>("manage_server_save", { server }),
  deleteServer: (id: string) => call<void>("manage_server_delete", { id }),
  scan: (id: string) => call<string>("manage_server_scan", { id }),
  createCascades: (req: { proxy_id: string; exit_ids: string[]; port: number | null; instance: string }) =>
    call<OpLog>("manage_cascade_create", { req }),
  adopt: (proxy_id: string, exit_id: string, port: number) => call<void>("manage_cascade_adopt", { proxyId: proxy_id, exitId: exit_id, port }),
  deleteCascade: (id: string) => call<OpLog>("manage_cascade_delete", { id }),
  check: (id: string) => call<OpLog>("manage_cascade_check", { id }),
  createClient: (name: string, cascade_ids: string[]) => call<string[]>("manage_client_create", { name, cascadeIds: cascade_ids }),
  deleteClient: (id: string) => call<OpLog>("manage_client_delete", { id }),
  traffic: () => call<OpLog>("manage_traffic"),
  share: (id: string) => call<Share>("manage_client_share", { id }),
  toDevice: (id: string) => call<View>("manage_client_to_device", { id }),
  importPanel: (path: string) => call<number>("manage_import_panel", { path }),
};

/** Live progress lines of management operations. */
export async function onManageLog(cb: (line: string) => void): Promise<() => void> {
  if (!inTauri) return () => {};
  const { listen } = await import("@tauri-apps/api/event");
  return listen<string>("manage-log", (e) => cb(e.payload));
}

export async function pickFile(filters: { name: string; extensions: string[] }[]): Promise<string | null> {
  if (!inTauri) return null;
  const { open } = await import("@tauri-apps/plugin-dialog");
  const r = await open({ multiple: false, filters });
  return typeof r === "string" ? r : null;
}

export const api = {
  view: () => call<View>("get_view"),
  importText: (text: string, name?: string) => call<View>("import_text", { text, name: name || null }),
  rename: (id: string, name: string) => call<View>("rename_profile", { id, name }),
  remove: (id: string) => call<View>("remove_profile", { id }),
  select: (id: string) => call<View>("select_profile", { id }),
  setSettings: (settings: Settings) => call<View>("set_settings", { settings }),
  share: (id: string) => call<Share>("share", { id }),
  saveText: (path: string, text: string) => call<void>("save_text", { path, text }),
  connect: (id: string) => call<Status>("connect", { id }),
  disconnect: () => call<Status>("disconnect"),
  status: () => call<Status>("status"),
  helperState: () => call<HelperState>("helper_state"),
  installHelper: () => call<HelperState>("install_helper"),
  uninstallHelper: () => call<HelperState>("uninstall_helper"),
  checkUpdate: () => call<UpdateInfo>("check_update"),
  qrFromFile: (path: string) => call<string>("qr_from_file", { path }),
  qrFromClipboard: () => call<string>("qr_from_clipboard"),
  installUpdate: () => call<void>("install_update"),
};

/** Download progress of an update: (bytes so far, total if known). */
export async function onUpdateProgress(cb: (got: number, total: number | null) => void): Promise<() => void> {
  if (!inTauri) return () => {};
  const { listen } = await import("@tauri-apps/api/event");
  return listen<[number, number | null]>("update-progress", (e) => cb(e.payload[0], e.payload[1]));
}

export async function readClipboard(): Promise<string> {
  if (inTauri) {
    const { readText } = await import("@tauri-apps/plugin-clipboard-manager");
    return readText();
  }
  return navigator.clipboard.readText();
}

export async function writeClipboard(text: string): Promise<void> {
  if (inTauri) {
    const { writeText } = await import("@tauri-apps/plugin-clipboard-manager");
    return writeText(text);
  }
  return navigator.clipboard.writeText(text);
}

/** Asks where to save and writes the file; false if the user cancelled. */
export async function saveFile(defaultName: string, text: string): Promise<boolean> {
  if (!inTauri) {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
    a.download = defaultName;
    a.click();
    return true;
  }
  const { save } = await import("@tauri-apps/plugin-dialog");
  const path = await save({ defaultPath: defaultName });
  if (!path) return false;
  await api.saveText(path, text);
  return true;
}

export function errorText(e: unknown): string {
  return typeof e === "string" ? e : e instanceof Error ? e.message : JSON.stringify(e);
}

export function bytes(n: number): string {
  const units = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
  let v = n, i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${i === 0 ? v : v.toFixed(1)} ${units[i]}`;
}

/** Start the app at login (hidden, in the menu bar). */
export async function autostart(enable?: boolean): Promise<boolean> {
  if (!inTauri) return false;
  const a = await import("@tauri-apps/plugin-autostart");
  if (enable !== undefined) await (enable ? a.enable() : a.disable());
  return a.isEnabled();
}

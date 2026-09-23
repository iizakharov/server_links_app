// Calls into the Rust side (Tauri commands). Outside Tauri (plain browser) a mock is used,
// so the UI can be developed and checked without the app shell.
export type ProfileView = { id: string; name: string; endpoint: string; address: string; awg_version: string };
export type View = { profiles: ProfileView[]; selected: string | null; settings: { theme: string } };
export type Stats = { rx: number; tx: number; handshake: number };
export type Status = { connected: boolean; name: string; iface: string; endpoint: string; since: number; stats: Stats };
export type Share = { name: string; conf: string; vpn_key: string; qr_svg: string };
export type HelperState = { installed: boolean; running: boolean };

export const inTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (inTauri) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<T>(cmd, args);
  }
  const { mock } = await import("./mock");
  return mock(cmd, args ?? {}) as Promise<T>;
}

export const api = {
  view: () => call<View>("get_view"),
  importText: (text: string, name?: string) => call<View>("import_text", { text, name: name || null }),
  rename: (id: string, name: string) => call<View>("rename_profile", { id, name }),
  remove: (id: string) => call<View>("remove_profile", { id }),
  select: (id: string) => call<View>("select_profile", { id }),
  setTheme: (theme: string) => call<View>("set_theme", { theme }),
  share: (id: string) => call<Share>("share", { id }),
  saveText: (path: string, text: string) => call<void>("save_text", { path, text }),
  connect: (id: string) => call<Status>("connect", { id }),
  disconnect: () => call<Status>("disconnect"),
  status: () => call<Status>("status"),
  helperState: () => call<HelperState>("helper_state"),
  installHelper: () => call<HelperState>("install_helper"),
  uninstallHelper: () => call<HelperState>("uninstall_helper"),
};

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

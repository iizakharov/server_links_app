// App-wide state shared by the screens.
import { api, errorText, type HelperState, type Settings, type Status, type View } from "./api";

export type Tab = "home" | "servers" | "share" | "settings" | "add" | "split" | "manage";

export const app = $state({
  tab: "home" as Tab,
  view: { profiles: [], selected: null,
          settings: { theme: "system", kill_switch: false, allow_lan: true, autoconnect: false, split: { mode: "all", entries: [] } } } as View,
  status: null as Status | null,
  /** connecting | disconnecting while a request is in flight */
  busy: "" as "" | "connecting" | "disconnecting",
  error: "",
  helper: { installed: false, running: false, outdated: false } as HelperState,
  shareId: null as string | null,
});

export function applyTheme(theme: string) {
  if (theme === "system") document.documentElement.removeAttribute("data-theme");
  else document.documentElement.setAttribute("data-theme", theme);
}

export async function refreshView() {
  app.view = await api.view();
  applyTheme(app.view.settings.theme);
}

/** Saves settings; a change that affects the tunnel applies on the next connect. */
export async function saveSettings(patch: Partial<Settings>) {
  app.view = await api.setSettings({ ...app.view.settings, ...patch });
  applyTheme(app.view.settings.theme);
}

export async function refreshStatus() {
  try {
    app.status = await api.status();
    app.helper = { ...app.helper, running: true };
  } catch {
    app.status = null;
    app.helper = await api.helperState();
  }
}

export function selectedProfile() {
  return app.view.profiles.find((p) => p.id === app.view.selected) ?? null;
}

export async function toggleConnection() {
  app.error = "";
  const p = selectedProfile();
  try {
    if (app.status?.connected || app.status?.blocked) {
      app.busy = "disconnecting";
      app.status = await api.disconnect();
    } else if (p) {
      app.busy = "connecting";
      app.status = await api.connect(p.id);
    }
  } catch (e) {
    app.error = errorText(e);
    await refreshStatus();
  } finally {
    app.busy = "";
  }
}

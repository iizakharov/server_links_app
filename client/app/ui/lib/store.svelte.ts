// App-wide state shared by the screens.
import { api, errorText, onUpdateProgress, type HelperState, type Settings, type Status, type UpdateInfo, type View } from "./api";

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
  update: null as UpdateInfo | null,
  /** "" | "checking" | "installing"; progress text while downloading */
  updating: "" as "" | "checking" | "installing",
  updateProgress: "",
  updateError: "",
});

/** Asks GitHub for a newer version; quiet unless `manual` (then errors are shown). */
export async function checkUpdate(manual = false) {
  if (app.updating) return;
  app.updating = "checking";
  if (manual) app.updateError = "";
  try {
    app.update = await api.checkUpdate();
  } catch (e) {
    if (manual) app.updateError = errorText(e);
  } finally {
    app.updating = "";
  }
}

/** Downloads and installs the update; the app restarts when done. */
export async function installUpdate() {
  app.updating = "installing";
  app.updateError = "";
  const stop = await onUpdateProgress((got, total) => {
    app.updateProgress = total ? `${Math.round((got / total) * 100)}%` : `${(got / 1048576).toFixed(1)} МБ`;
  });
  try {
    await api.installUpdate();
  } catch (e) {
    app.updateError = errorText(e);
  } finally {
    stop();
    app.updating = "";
    app.updateProgress = "";
  }
}

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

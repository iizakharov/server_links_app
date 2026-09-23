//! АМнеЗинуVPN desktop app: Tauri commands over the device's profiles and the helper.
mod helper;
mod manage;
mod profiles;
mod tray;

use std::sync::Mutex;

use amz_core::vpnkey::conf_to_vpn_key;
use amz_ipc::{Request, Status};
use profiles::{new_profile, parse_import, Data, ProfileView, Settings, Store};
use serde::Serialize;
use tauri::{Emitter, Manager, State};

pub(crate) struct AppState {
    pub(crate) store: Store,
    pub(crate) data: Mutex<Data>,
    pub(crate) manage: manage::Manage,
}

pub(crate) type Res<T> = Result<T, String>;

pub(crate) fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

#[derive(Serialize)]
pub(crate) struct View {
    profiles: Vec<ProfileView>,
    selected: Option<String>,
    settings: Settings,
}

fn view(d: &Data) -> View {
    View { profiles: d.profiles.iter().map(|p| p.view()).collect(), selected: d.selected.clone(), settings: d.settings.clone() }
}

pub(crate) fn change(st: &State<AppState>, f: impl FnOnce(&mut Data) -> Res<()>) -> Res<View> {
    let mut d = st.data.lock().unwrap();
    let mut next = d.clone();
    f(&mut next)?;
    st.store.save(&next).map_err(err)?;
    *d = next;
    Ok(view(&d))
}

#[tauri::command]
fn get_view(st: State<AppState>) -> View {
    view(&st.data.lock().unwrap())
}

#[tauri::command]
fn import_text(st: State<AppState>, text: String, name: Option<String>) -> Res<View> {
    change(&st, |d| {
        let fallback = format!("Сервер {}", d.profiles.len() + 1);
        let (key_name, conf) = parse_import(&text, &fallback).map_err(err)?;
        let p = new_profile(name.filter(|n| !n.trim().is_empty()).unwrap_or(key_name), conf);
        d.selected = Some(p.id.clone());
        d.profiles.push(p);
        Ok(())
    })
}

#[tauri::command]
fn rename_profile(st: State<AppState>, id: String, name: String) -> Res<View> {
    change(&st, |d| {
        let p = d.profiles.iter_mut().find(|p| p.id == id).ok_or("Нет такого сервера")?;
        p.name = name.trim().to_string();
        Ok(())
    })
}

#[tauri::command]
fn remove_profile(st: State<AppState>, id: String) -> Res<View> {
    let view = change(&st, |d| {
        d.profiles.retain(|p| p.id != id);
        if d.selected.as_deref() == Some(id.as_str()) {
            d.selected = d.profiles.first().map(|p| p.id.clone());
        }
        Ok(())
    })?;
    st.store.forget(&id);
    Ok(view)
}

#[tauri::command]
fn select_profile(st: State<AppState>, id: String) -> Res<View> {
    change(&st, |d| {
        d.selected = Some(id);
        Ok(())
    })
}

#[tauri::command]
fn set_settings(st: State<AppState>, settings: Settings) -> Res<View> {
    change(&st, |d| {
        d.settings = settings;
        Ok(())
    })
}

#[derive(Serialize)]
pub(crate) struct Share {
    name: String,
    conf: String,
    vpn_key: String,
    qr_svg: String,
}

/// Key (given, or built from the config), QR and config for sharing a connection.
pub(crate) fn share_of(name: &str, conf: &str, vpn_key: Option<String>) -> Res<Share> {
    let vpn_key = match vpn_key {
        Some(k) => k,
        None => conf_to_vpn_key(name, conf).map_err(err)?,
    };
    let qr = qrcode::QrCode::with_error_correction_level(vpn_key.as_bytes(), qrcode::EcLevel::L)
        .map_err(|_| "Ключ слишком длинный для одного QR-кода".to_string())?;
    let qr_svg = qr.render::<qrcode::render::svg::Color>().quiet_zone(true).min_dimensions(240, 240).build();
    Ok(Share { name: name.into(), conf: conf.into(), vpn_key, qr_svg })
}

#[tauri::command]
fn share(st: State<AppState>, id: String) -> Res<Share> {
    let d = st.data.lock().unwrap();
    let p = d.profiles.iter().find(|p| p.id == id).ok_or("Нет такого сервера")?;
    share_of(&p.name, &p.conf, None)
}

#[tauri::command]
fn save_text(path: String, text: String) -> Res<()> {
    std::fs::write(path, text).map_err(err)
}

async fn helper_call(req: Request) -> Res<Status> {
    tauri::async_runtime::spawn_blocking(move || amz_ipc::call(&req)).await.map_err(err)?.map_err(|e| format!("{e:#}"))
}

#[tauri::command]
async fn connect(st: State<'_, AppState>, id: String) -> Res<Status> {
    let req = up_request(&st.data.lock().unwrap(), &id)?;
    helper_call(req).await
}

pub(crate) fn up_request(d: &Data, id: &str) -> Res<Request> {
    let p = d.profiles.iter().find(|p| p.id == id).ok_or("Нет такого сервера")?;
    Ok(Request::Up { conf: p.conf.clone(), name: p.name.clone(), options: d.settings.up_options() })
}

#[tauri::command]
async fn disconnect() -> Res<Status> {
    helper_call(Request::Down).await
}

#[tauri::command]
async fn status() -> Res<Status> {
    helper_call(Request::Status).await
}

#[tauri::command]
fn helper_state() -> helper::HelperState {
    helper::state()
}

#[tauri::command]
async fn install_helper(app: tauri::AppHandle) -> Res<helper::HelperState> {
    let bin = helper::bundled(app.path().resource_dir().ok()).map_err(err)?;
    tauri::async_runtime::spawn_blocking(move || helper::install(&bin)).await.map_err(err)?.map_err(err)?;
    Ok(helper::state())
}

#[tauri::command]
async fn uninstall_helper() -> Res<helper::HelperState> {
    tauri::async_runtime::spawn_blocking(helper::uninstall).await.map_err(err)?.map_err(err)?;
    Ok(helper::state())
}

#[derive(Serialize)]
struct UpdateInfo {
    current: String,
    /// newer version published on GitHub, if any
    version: Option<String>,
    notes: Option<String>,
}

#[tauri::command]
async fn check_update(app: tauri::AppHandle) -> Res<UpdateInfo> {
    use tauri_plugin_updater::UpdaterExt;
    let current = app.package_info().version.to_string();
    let update = app.updater().map_err(err)?.check().await.map_err(err)?;
    Ok(UpdateInfo { current, version: update.as_ref().map(|u| u.version.clone()), notes: update.and_then(|u| u.body) })
}

/// Downloads the new version (signature checked against the key in tauri.conf.json), installs it and restarts.
/// The VPN service keeps the tunnel meanwhile; if its version changed, the app offers to update it.
#[tauri::command]
async fn install_update(app: tauri::AppHandle) -> Res<()> {
    use tauri_plugin_updater::UpdaterExt;
    let update = app.updater().map_err(err)?.check().await.map_err(err)?.ok_or("Обновлений нет")?;
    let (progress, mut got) = (app.clone(), 0u64);
    update.download_and_install(move |chunk, total| {
        got += chunk as u64;
        let _ = progress.emit("update-progress", (got, total));
    }, || {}).await.map_err(err)?;
    app.restart()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_autostart::init(tauri_plugin_autostart::MacosLauncher::LaunchAgent, Some(vec!["--hidden"])))
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            let store = Store::new(&dir);
            let data = store.load()?;
            let manage = manage::Manage::open(&dir)?;
            let autoconnect = data.settings.autoconnect.then(|| data.selected.clone()).flatten();
            let req = autoconnect.and_then(|id| up_request(&data, &id).ok());
            app.manage(AppState { store, data: Mutex::new(data), manage });
            tray::setup(app.handle())?;
            // started at login: stay in the menu bar
            if std::env::args().any(|a| a == "--hidden") {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.hide();
                }
            }
            if let Some(req) = req {
                std::thread::spawn(move || {
                    // do not replace a tunnel that is already up
                    if amz_ipc::call(&Request::Status).is_ok_and(|s| !s.connected) {
                        let _ = amz_ipc::call(&req);
                    }
                });
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // closing the window keeps the app (and the VPN control) in the menu bar
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_view, import_text, rename_profile, remove_profile, select_profile, set_settings,
            share, save_text, connect, disconnect, status, helper_state, install_helper, uninstall_helper,
            check_update, install_update,
            manage::manage_view, manage::manage_server_save, manage::manage_server_delete, manage::manage_server_scan,
            manage::manage_cascade_create, manage::manage_cascade_adopt, manage::manage_cascade_delete,
            manage::manage_cascade_check, manage::manage_client_create, manage::manage_client_delete,
            manage::manage_traffic, manage::manage_client_share, manage::manage_client_to_device,
            manage::manage_import_panel
        ])
        .run(tauri::generate_context!())
        .expect("error while running АМнеЗинуVPN");
}

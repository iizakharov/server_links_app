//! АМнеЗинуVPN desktop app: Tauri commands over the device's profiles and the helper.
mod helper;
mod profiles;

use std::sync::Mutex;

use amz_core::vpnkey::conf_to_vpn_key;
use amz_ipc::{Request, Status};
use profiles::{new_profile, parse_import, Data, ProfileView, Settings, Store};
use serde::Serialize;
use tauri::{Manager, State};

struct AppState {
    store: Store,
    data: Mutex<Data>,
}

type Res<T> = Result<T, String>;

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

#[derive(Serialize)]
struct View {
    profiles: Vec<ProfileView>,
    selected: Option<String>,
    settings: Settings,
}

fn view(d: &Data) -> View {
    View { profiles: d.profiles.iter().map(|p| p.view()).collect(), selected: d.selected.clone(), settings: d.settings.clone() }
}

fn change(st: &State<AppState>, f: impl FnOnce(&mut Data) -> Res<()>) -> Res<View> {
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
    change(&st, |d| {
        d.profiles.retain(|p| p.id != id);
        if d.selected.as_deref() == Some(id.as_str()) {
            d.selected = d.profiles.first().map(|p| p.id.clone());
        }
        Ok(())
    })
}

#[tauri::command]
fn select_profile(st: State<AppState>, id: String) -> Res<View> {
    change(&st, |d| {
        d.selected = Some(id);
        Ok(())
    })
}

#[tauri::command]
fn set_theme(st: State<AppState>, theme: String) -> Res<View> {
    change(&st, |d| {
        d.settings.theme = theme;
        Ok(())
    })
}

#[derive(Serialize)]
struct Share {
    name: String,
    conf: String,
    vpn_key: String,
    qr_svg: String,
}

#[tauri::command]
fn share(st: State<AppState>, id: String) -> Res<Share> {
    let d = st.data.lock().unwrap();
    let p = d.profiles.iter().find(|p| p.id == id).ok_or("Нет такого сервера")?;
    let vpn_key = conf_to_vpn_key(&p.name, &p.conf).map_err(err)?;
    let qr = qrcode::QrCode::with_error_correction_level(vpn_key.as_bytes(), qrcode::EcLevel::L)
        .map_err(|_| "Ключ слишком длинный для одного QR-кода".to_string())?;
    let qr_svg = qr.render::<qrcode::render::svg::Color>().quiet_zone(true).min_dimensions(240, 240).build();
    Ok(Share { name: p.name.clone(), conf: p.conf.clone(), vpn_key, qr_svg })
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
    let (conf, name) = {
        let d = st.data.lock().unwrap();
        let p = d.profiles.iter().find(|p| p.id == id).ok_or("Нет такого сервера")?;
        (p.conf.clone(), p.name.clone())
    };
    helper_call(Request::Up { conf, name }).await
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .setup(|app| {
            let store = Store::new(&app.path().app_data_dir()?);
            let data = store.load()?;
            app.manage(AppState { store, data: Mutex::new(data) });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_view, import_text, rename_profile, remove_profile, select_profile, set_theme,
            share, save_text, connect, disconnect, status, helper_state, install_helper, uninstall_helper
        ])
        .run(tauri::generate_context!())
        .expect("error while running АМнеЗинуVPN");
}

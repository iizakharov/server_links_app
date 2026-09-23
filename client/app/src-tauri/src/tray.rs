//! Menu bar icon: status, connect/disconnect, open window, quit. The app keeps running here
//! when its window is closed.
use std::time::Duration;

use amz_ipc::Request;
use tauri::image::Image;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Manager};

use crate::{up_request, AppState};

const ICON_OFF: &[u8] = include_bytes!("../icons/tray/off@2x.png");
const ICON_ON: &[u8] = include_bytes!("../icons/tray/on@2x.png");

fn show_window(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.set_focus();
    }
}

fn toggle(app: &AppHandle) {
    let req = match amz_ipc::call(&Request::Status) {
        Ok(s) if s.connected || s.blocked => Some(Request::Down),
        Ok(_) => {
            let st = app.state::<AppState>();
            let d = st.data.lock().unwrap();
            d.selected.as_deref().and_then(|id| up_request(&d, id).ok())
        }
        Err(_) => {
            show_window(app);
            None
        }
    };
    if let Some(req) = req {
        std::thread::spawn(move || {
            let _ = amz_ipc::call(&req);
        });
    }
}

pub fn setup(app: &AppHandle) -> tauri::Result<()> {
    let status = MenuItem::with_id(app, "status", "Отключено", false, None::<&str>)?;
    let toggle_item = MenuItem::with_id(app, "toggle", "Подключить", true, None::<&str>)?;
    let open = MenuItem::with_id(app, "open", "Открыть АМнеЗинуVPN", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Отключить и выйти", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&status, &toggle_item, &PredefinedMenuItem::separator(app)?, &open,
                                       &PredefinedMenuItem::separator(app)?, &quit])?;
    let tray = TrayIconBuilder::with_id("main")
        .icon(Image::from_bytes(ICON_OFF)?)
        .icon_as_template(true)
        .tooltip("АМнеЗинуVPN")
        .menu(&menu)
        .show_menu_on_left_click(true)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "toggle" => toggle(app),
            "open" => show_window(app),
            "quit" => {
                let _ = amz_ipc::call(&Request::Down);
                app.exit(0);
            }
            _ => {}
        })
        .build(app)?;

    // keep the menu in sync with the tunnel (it may be changed from the window or the CLI)
    std::thread::spawn(move || {
        let mut last = None;
        loop {
            let s = amz_ipc::call(&Request::Status).ok();
            let key = s.as_ref().map(|s| (s.connected, s.blocked, s.name.clone()));
            if key != last {
                let (text, action, on) = match &s {
                    None => ("Служба VPN не запущена".to_string(), "Открыть настройки", false),
                    Some(s) if s.connected => (format!("Подключено: {}", s.name), "Отключить", true),
                    Some(s) if s.blocked => ("Интернет заблокирован (kill switch)".into(), "Снять блокировку", false),
                    Some(_) => ("Отключено".into(), "Подключить", false),
                };
                let _ = status.set_text(text);
                let _ = toggle_item.set_text(action);
                if let Ok(img) = Image::from_bytes(if on { ICON_ON } else { ICON_OFF }) {
                    let _ = tray.set_icon(Some(img));
                    let _ = tray.set_icon_as_template(true);
                }
                last = key;
            }
            std::thread::sleep(Duration::from_secs(2));
        }
    });
    Ok(())
}

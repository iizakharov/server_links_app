//! Managing own servers from the app (what the Python panel did): servers over SSH, cascades,
//! clients with traffic. State lives in the app data dir; SSH passwords and client keys in the keychain.
use std::path::Path;
use std::sync::{Arc, Mutex};

use amz_core::awg::awg_version;
use amz_core::model::{Server, State, Traffic};
use amz_core::storage::{Secrets, Storage};
use amz_remote::ops::{self, CascadeRequest, CascadeView, Connector, OpLog, Ssh};
use amz_remote::proxy::{self, ExternalCascade};
use amz_remote::{SshRemote, SshTarget};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager};

use crate::profiles::{new_group, new_profile};
use crate::{err, AppState, Res};

pub struct Keychain;

impl Secrets for Keychain {
    fn get(&self, key: &str) -> Option<String> {
        keyring::Entry::new("com.amnezinu.vpn.manage", key).ok()?.get_password().ok()
    }
    fn set(&self, key: &str, value: &str) -> Result<(), String> {
        let e = keyring::Entry::new("com.amnezinu.vpn.manage", key).map_err(err)?;
        if e.get_password().ok().as_deref() == Some(value) {
            return Ok(());
        }
        e.set_password(value).map_err(err)
    }
    fn delete(&self, key: &str) {
        if let Ok(e) = keyring::Entry::new("com.amnezinu.vpn.manage", key) {
            let _ = e.delete_credential();
        }
    }
}

/// SSH to real servers; every log line also goes to the window as a `manage-log` event.
pub struct AppConn(pub AppHandle);

impl Connector for AppConn {
    type R = SshRemote;
    fn connect(&self, server: &Server) -> impl std::future::Future<Output = anyhow::Result<SshRemote>> + Send {
        SshRemote::connect(SshTarget::from_server(server))
    }
    fn ip_of(&self, server: &Server) -> String {
        Ssh.ip_of(server)
    }
    fn progress(&self, line: &str) {
        let _ = self.0.emit("manage-log", line);
    }
}

pub struct Manage {
    store: Storage,
    /// the working state, held for the whole of an operation (one at a time)
    state: tokio::sync::Mutex<State>,
    /// last saved state, for reading while an operation runs
    snapshot: Mutex<State>,
}

impl Manage {
    pub fn open(dir: &Path) -> anyhow::Result<Self> {
        let store = Storage::with_secrets(dir.join("manage"), Arc::new(Keychain));
        let state = store.load()?;
        Ok(Manage { store, snapshot: Mutex::new(state.clone()), state: tokio::sync::Mutex::new(state) })
    }
}

#[derive(Serialize)]
pub struct AwgView {
    instance: String,
    version: String,
    port: u16,
}

#[derive(Serialize)]
pub struct ServerView {
    id: String,
    name: String,
    host: String,
    ssh_port: u16,
    user: String,
    key_path: String,
    has_password: bool,
    os: String,
    scanned_at: String,
    awg: Vec<AwgView>,
    /// forwards of other tools on this server (proxy side)
    forwards: Vec<String>,
}

#[derive(Serialize)]
pub struct ClientView {
    id: String,
    name: String,
    cascade_id: String,
    ip: String,
    created: String,
    traffic: Option<Traffic>,
    handshake: Option<i64>,
    stats_at: Option<String>,
}

#[derive(Serialize)]
pub struct ManageView {
    servers: Vec<ServerView>,
    cascades: Vec<CascadeView>,
    external: Vec<ExternalCascade>,
    clients: Vec<ClientView>,
    busy: bool,
}

fn view(s: &State, busy: bool) -> ManageView {
    let conn = Ssh;
    let servers = s.servers.iter().map(|x| {
        let scan = x.scan.as_ref();
        ServerView {
            id: x.id.clone(), name: x.name.clone(), host: x.host.clone(), ssh_port: x.ssh_port, user: x.user.clone(),
            key_path: x.key_path.clone().unwrap_or_default(),
            has_password: x.password.as_deref().is_some_and(|p| !p.is_empty()),
            os: scan.map(|s| s.os.clone()).unwrap_or_default(),
            scanned_at: scan.map(|s| s.at.clone()).unwrap_or_default(),
            awg: ["main", "legacy", "v2", "v3"].iter().filter_map(|i| {
                let a = scan?.awg_for(i)?;
                Some(AwgView { instance: i.to_string(), version: awg_version(&a.params).into(), port: a.listen_port })
            }).collect(),
            forwards: scan.map(|s| s.nat.iter().filter(|r| !r.ours).map(proxy::describe).collect()).unwrap_or_default(),
        }
    }).collect();
    ManageView {
        servers,
        cascades: ops::cascade_views(&conn, s),
        external: ops::external_not_adopted(&conn, s),
        clients: s.clients.iter().map(|c| ClientView {
            id: c.id.clone(), name: c.name.clone(), cascade_id: c.cascade_id.clone(), ip: c.ip.clone(),
            created: c.created.clone().unwrap_or_default(), traffic: c.traffic, handshake: c.handshake,
            stats_at: c.stats_at.clone(),
        }).collect(),
        busy,
    }
}

/// Runs an operation on the working state, then publishes it as the snapshot.
async fn with_state<T>(app: &AppHandle, f: impl AsyncFnOnce(&AppConn, &Storage, &mut State) -> Res<T>) -> Res<T> {
    let st = app.state::<AppState>();
    let m = &st.manage;
    let mut state = m.state.try_lock().map_err(|_| "Уже выполняется другая операция — дождитесь её окончания")?;
    let conn = AppConn(app.clone());
    let res = f(&conn, &m.store, &mut state).await;
    *m.snapshot.lock().unwrap() = state.clone();
    res
}

#[tauri::command]
pub fn manage_view(st: tauri::State<AppState>) -> ManageView {
    let busy = st.manage.state.try_lock().is_err();
    view(&st.manage.snapshot.lock().unwrap(), busy)
}

#[derive(Deserialize)]
pub struct ServerIn {
    id: Option<String>,
    name: String,
    host: String,
    ssh_port: u16,
    user: String,
    /// empty = keep the saved one (same host)
    password: String,
    key_path: String,
}

#[tauri::command]
pub async fn manage_server_save(app: AppHandle, server: ServerIn) -> Res<String> {
    with_state(&app, async |_, store, s| {
        let host = server.host.trim().to_string();
        if host.is_empty() {
            return Err("Укажите адрес сервера".into());
        }
        let old = server.id.as_ref().and_then(|id| s.servers.iter().position(|x| &x.id == id));
        let same_host = old.is_some_and(|i| s.servers[i].host == host);
        let mut x = match old {
            Some(i) => s.servers[i].clone(),
            None => Server { id: ops::new_id(), ..Default::default() },
        };
        if !same_host {
            // another machine: forget what we knew about the old one
            x.scan = None;
            x.extra.remove("host_key");
        }
        x.name = if server.name.trim().is_empty() { host.clone() } else { server.name.trim().into() };
        x.host = host;
        x.ssh_port = if server.ssh_port == 0 { 22 } else { server.ssh_port };
        x.user = if server.user.trim().is_empty() { "root".into() } else { server.user.trim().into() };
        if !server.password.is_empty() || !same_host {
            x.password = Some(server.password).filter(|p| !p.is_empty());
        }
        x.key_path = Some(server.key_path.trim().to_string()).filter(|p| !p.is_empty());
        let id = x.id.clone();
        match old {
            Some(i) => s.servers[i] = x,
            None => s.servers.push(x),
        }
        store.save(s).map_err(err)?;
        Ok(id)
    }).await
}

#[tauri::command]
pub async fn manage_server_delete(app: AppHandle, id: String) -> Res<()> {
    with_state(&app, async |_, store, s| ops::delete_server(store, s, &id).map_err(err)).await
}

#[tauri::command]
pub async fn manage_server_scan(app: AppHandle, id: String) -> Res<String> {
    with_state(&app, async |conn, store, s| ops::scan_server(conn, store, s, &id).await.map_err(|e| format!("{e:#}"))).await
}

#[tauri::command]
pub async fn manage_cascade_create(app: AppHandle, req: CascadeRequest) -> Res<OpLog> {
    with_state(&app, async |conn, store, s| Ok(ops::create_cascades(conn, store, s, &req).await)).await
}

#[tauri::command]
pub async fn manage_cascade_adopt(app: AppHandle, proxy_id: String, exit_id: String, port: u16) -> Res<()> {
    with_state(&app, async |conn, store, s| ops::adopt_cascade(conn, store, s, &proxy_id, &exit_id, port).map_err(err)).await
}

#[tauri::command]
pub async fn manage_cascade_delete(app: AppHandle, id: String) -> Res<OpLog> {
    with_state(&app, async |conn, store, s| Ok(ops::delete_cascade(conn, store, s, &id).await)).await
}

#[tauri::command]
pub async fn manage_cascade_check(app: AppHandle, id: String) -> Res<OpLog> {
    with_state(&app, async |conn, _, s| Ok(ops::check_cascade(conn, s, &id).await)).await
}

#[tauri::command]
pub async fn manage_client_create(app: AppHandle, name: String, cascade_ids: Vec<String>) -> Res<Vec<String>> {
    with_state(&app, async |conn, store, s| {
        ops::create_clients(conn, store, s, &name, &cascade_ids).await.map_err(|e| format!("{e:#}"))
    }).await
}

#[tauri::command]
pub async fn manage_client_delete(app: AppHandle, id: String) -> Res<OpLog> {
    with_state(&app, async |conn, store, s| Ok(ops::delete_client(conn, store, s, &id).await)).await
}

#[tauri::command]
pub async fn manage_traffic(app: AppHandle) -> Res<OpLog> {
    with_state(&app, async |conn, store, s| Ok(ops::refresh_traffic(conn, store, s).await)).await
}

#[tauri::command]
pub fn manage_client_share(st: tauri::State<AppState>, id: String) -> Res<crate::Share> {
    let s = st.manage.snapshot.lock().unwrap().clone();
    let (r, exits) = ops::render_all(&s, &id).map_err(err)?;
    // a key with several exits is named after the person; a single-route one shows the route
    let title = if exits.is_empty() { client_title(&s, &id)? } else { client_name(&s, &id)? };
    crate::share_of(&title, &r.conf, Some(r.vpn_key))
}

fn client_name(s: &State, id: &str) -> Res<String> {
    Ok(s.clients.iter().find(|c| c.id == id).ok_or("Нет такого клиента")?.name.clone())
}

/// "phone (Proxy → Praga)"
fn client_title(s: &State, id: &str) -> Res<String> {
    let c = s.clients.iter().find(|c| c.id == id).ok_or("Нет такого клиента")?;
    let cas = s.cascades.iter().find(|x| x.id == c.cascade_id).ok_or("Нет такого каскада")?;
    let name_of = |sid: &str| s.servers.iter().find(|x| x.id == sid).map(|x| x.name.clone()).unwrap_or_default();
    Ok(format!("{} ({} → {})", c.name, name_of(&cas.proxy_id), name_of(&cas.exit_id)))
}

/// Puts a managed client onto this device as a connection ("server" on the home screen).
#[tauri::command]
pub fn manage_client_to_device(st: tauri::State<AppState>, id: String) -> Res<crate::View> {
    let s = st.manage.snapshot.lock().unwrap().clone();
    let (r, exits) = ops::render_all(&s, &id).map_err(err)?;
    let profiles = if exits.is_empty() {
        vec![new_profile(client_title(&s, &id)?, r.conf)]
    } else {
        new_group(&client_name(&s, &id)?, exits)
    };
    crate::change(&st, |d| {
        crate::add_profiles(d, profiles);
        Ok(())
    })
}

/// Takes over the Python panel's data/state.json (only into an empty app).
#[tauri::command]
pub async fn manage_import_panel(app: AppHandle, path: String) -> Res<usize> {
    with_state(&app, async |_, store, s| {
        if !s.servers.is_empty() {
            return Err("В приложении уже есть серверы — импорт возможен только в пустое".into());
        }
        let raw = std::fs::read(&path).map_err(err)?;
        let imported: State = serde_json::from_slice(&raw).map_err(|e| format!("Это не state.json панели: {e}"))?;
        let n = imported.servers.len();
        *s = imported;
        store.save(s).map_err(err)?;
        Ok(n)
    }).await
}

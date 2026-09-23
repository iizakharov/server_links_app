//! Windows: the helper is a service (LocalSystem) that owns the tunnel; the app talks to it over a named pipe
//! that only SYSTEM, administrators and the users given on install may open.
//!
//! amz-helper install --allow-sid <SID>   copy itself + wintun.dll to Program Files, register and start the service
//! amz-helper uninstall                   stop and remove the service
//! amz-helper run --allow-sid <SID>       the same service loop in a console (development, as administrator)
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::net::ToSocketAddrs;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use amz_core::tunnel::{parse_stats, tunnel_config, TunnelConfig};
use amz_ipc::{read_line, write_line, Request, Response, SplitMode, Status, UpOptions, BUILD, SOCKET};
use amz_tunnel::awg::{block, unblock, Device};
use amz_tunnel::split::{resolve_entries, system_resolve};
use amz_tunnel::windows::{plan, NetPlan, IFACE};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept, ServiceErrorControl,
    ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState,
    ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, LocalFree, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{FlushFileBuffers, FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
use windows_sys::Win32::System::Console::{SetStdHandle, STD_ERROR_HANDLE};
use windows_sys::Win32::System::SystemInformation::GetTickCount64;
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};

pub const SERVICE: &str = "AmnezinuVPN";

fn install_dir() -> PathBuf {
    PathBuf::from(std::env::var_os("ProgramFiles").unwrap_or_else(|| r"C:\Program Files".into())).join("AmnezinuVPN")
}

fn log_path() -> PathBuf {
    PathBuf::from(std::env::var_os("ProgramData").unwrap_or_else(|| r"C:\ProgramData".into())).join(r"AmnezinuVPN\helper.log")
}

/// The kill switch was on: if the service dies, it restores the block when Windows restarts it.
fn state_path() -> PathBuf {
    log_path().with_file_name("state.json")
}

fn log(msg: impl AsRef<str>) {
    eprintln!("amz-helper: {}", msg.as_ref());
}

/// A service has no console: send stderr (all `log` lines) to the log file.
fn log_to_file() -> Result<()> {
    let path = log_path();
    fs::create_dir_all(path.parent().unwrap())?;
    // keep the log small: start over past 1 MB
    if fs::metadata(&path).is_ok_and(|m| m.len() > 1 << 20) {
        let _ = fs::remove_file(&path);
    }
    let file = fs::OpenOptions::new().create(true).append(true).open(&path)?;
    // SAFETY: a valid file handle; it is leaked, so it stays open for the life of the process
    unsafe { SetStdHandle(STD_ERROR_HANDLE, file.as_raw_handle() as HANDLE) };
    std::mem::forget(file);
    Ok(())
}

// ---- tunnel ----

struct Active {
    dev: Device,
    cfg: TunnelConfig,
    opts: UpOptions,
    /// split-tunnel addresses seen so far (domains get new ones over time; old ones are kept)
    listed: Vec<String>,
    plan: NetPlan,
    status: Status,
}

#[derive(Default)]
struct Helper {
    active: Option<Active>,
    /// kill switch holding traffic blocked after a crash (allow_lan): lifted by the next Up or Down
    blocked: Option<bool>,
}

#[derive(Serialize, Deserialize)]
struct Saved {
    kill_switch: bool,
    allow_lan: bool,
}

type Shared = Arc<Mutex<Helper>>;

fn stop_tunnel(h: &mut Helper) {
    if let Some(a) = h.active.take() {
        log(format!("отключение {}", a.status.name));
        // closing the device removes the adapter with its routes and DNS, and lifts the kill switch
        drop(a.dev);
    }
}

fn down(h: &mut Helper) {
    stop_tunnel(h);
    if h.blocked.take().is_some() {
        log("снимаю блокировку kill switch");
        unblock();
    }
    let _ = fs::remove_file(state_path());
}

/// Service start: the previous run died with the kill switch on (not a reboot) -> keep the internet blocked.
fn restore_block(h: &mut Helper) {
    let path = state_path();
    let Ok(raw) = fs::read(&path) else { return };
    // SAFETY: plain call
    let boot = SystemTime::now() - Duration::from_millis(unsafe { GetTickCount64() });
    let after_boot = fs::metadata(&path).and_then(|m| m.modified()).is_ok_and(|t| t > boot);
    match serde_json::from_slice::<Saved>(&raw) {
        Ok(saved) if saved.kill_switch && after_boot => match block(saved.allow_lan) {
            Ok(()) => {
                log("прошлый запуск завершился аварийно: kill switch держит интернет заблокированным до отключения");
                h.blocked = Some(saved.allow_lan);
            }
            Err(e) => log(format!("{e:#}")),
        },
        _ => {
            let _ = fs::remove_file(&path);
        }
    }
}

fn up(h: &mut Helper, conf: &str, name: &str, opts: &UpOptions) -> Result<()> {
    let cfg = tunnel_config(conf, |host, port| {
        let addrs: Vec<_> = (host, port).to_socket_addrs().ok()?.collect();
        addrs.iter().find(|a| a.is_ipv4()).or(addrs.first()).copied()
    })?;
    // a crash block stays until the new tunnel is up: no gap without protection
    stop_tunnel(h);
    let listed = if opts.split.mode == SplitMode::All {
        vec![]
    } else {
        let (listed, failed) = resolve_entries(&opts.split.entries, system_resolve);
        if !failed.is_empty() {
            log(format!("не удалось найти адреса: {}", failed.join(", ")));
        }
        listed
    };
    let dev = Device::up(IFACE, cfg.mtu, &cfg.uapi)?;
    let net = plan(&cfg, opts, &listed);
    dev.set_net(&net)?;
    // with the kill switch the tunnel's rules have replaced the block; without it, lift the block
    if h.blocked.take().is_some() && !net.kill_switch {
        unblock();
    }
    if net.kill_switch {
        let saved = Saved { kill_switch: true, allow_lan: net.allow_lan };
        if let Err(e) = fs::write(state_path(), serde_json::to_vec(&saved)?) {
            log(format!("{}: {e}", state_path().display()));
        }
    } else {
        let _ = fs::remove_file(state_path());
    }
    let since = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    log(format!("подключено {name}: {} → {} (kill switch: {}, раздельное: {:?} {} шт., маршрутов {})", dev.name(),
                cfg.endpoint, net.kill_switch, opts.split.mode, opts.split.entries.len(), net.routes.len()));
    let status = Status { connected: true, name: name.into(), iface: dev.name().into(), endpoint: cfg.endpoint.to_string(),
                          since, kill_switch: net.kill_switch, ..Default::default() };
    h.active = Some(Active { dev, cfg, opts: opts.clone(), listed, plan: net, status });
    Ok(())
}

fn status(h: &Helper) -> Status {
    let s = match &h.active {
        Some(a) => Status { stats: parse_stats(&a.dev.config()), ..a.status.clone() },
        None => Status { blocked: h.blocked.is_some(), kill_switch: h.blocked.is_some(), ..Default::default() },
    };
    Status { helper_version: BUILD.into(), ..s }
}

/// Every 10 minutes: new addresses of split-tunnel domains.
fn watch_split(shared: Shared) {
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(600));
        let mut h = shared.lock().unwrap();
        let Some(a) = h.active.as_mut() else { continue };
        if a.opts.split.mode == SplitMode::All {
            continue;
        }
        let (fresh, _) = resolve_entries(&a.opts.split.entries, system_resolve);
        let before = a.listed.len();
        for n in fresh {
            if !a.listed.contains(&n) {
                a.listed.push(n);
            }
        }
        if a.listed.len() == before {
            continue;
        }
        let net = plan(&a.cfg, &a.opts, &a.listed);
        match a.dev.set_net(&net) {
            Ok(()) => {
                log(format!("раздельное туннелирование: добавлено новых адресов {}", a.listed.len() - before));
                a.plan = net;
            }
            Err(e) => log(format!("обновление адресов сайтов: {e:#}")),
        }
    });
}

// ---- pipe ----

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// Full access for SYSTEM and administrators, read/write for the allowed users; nothing for anyone else.
fn pipe_sddl(allowed: &[String]) -> String {
    let users: String = allowed.iter().map(|sid| format!("(A;;GRGW;;;{sid})")).collect();
    format!("D:P(A;;GA;;;SY)(A;;GA;;;BA){users}")
}

struct Pipe {
    sddl: Vec<u16>,
}

impl Pipe {
    fn create(&self, first: bool) -> Result<HANDLE> {
        let mut sd = std::ptr::null_mut();
        // SAFETY: NUL-terminated SDDL; the descriptor is freed with LocalFree below
        if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(self.sddl.as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut()) } == 0 {
            bail!("права канала: {}", std::io::Error::last_os_error());
        }
        let sa = SECURITY_ATTRIBUTES { nLength: size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: sd, bInheritHandle: 0 };
        let name = wide(SOCKET);
        // the first instance must be ours: nobody may squat the name before the service starts
        let flags = PIPE_ACCESS_DUPLEX | if first { FILE_FLAG_FIRST_PIPE_INSTANCE } else { 0 };
        // SAFETY: valid name and security attributes for the duration of the call
        let h = unsafe {
            CreateNamedPipeW(name.as_ptr(), flags, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                             PIPE_UNLIMITED_INSTANCES, 64 * 1024, 64 * 1024, 0, &sa)
        };
        let err = std::io::Error::last_os_error();
        unsafe { LocalFree(sd) };
        if h == INVALID_HANDLE_VALUE {
            bail!("{SOCKET}: {err}");
        }
        Ok(h)
    }
}

fn handle(pipe: &File, shared: &Shared) -> Result<()> {
    let mut w = pipe;
    let mut reader = BufReader::new(pipe);
    // the app probes the pipe by connecting and closing: nothing to answer or log
    if reader.fill_buf()?.is_empty() {
        return Ok(());
    }
    let req: Request = read_line(&mut reader)?;
    let mut h = shared.lock().unwrap();
    let res = match &req {
        Request::Up { conf, name, options } => up(&mut h, conf, name, options),
        Request::Down => {
            down(&mut h);
            Ok(())
        }
        Request::Status => Ok(()),
    };
    let resp = match res {
        Ok(()) => Response::Ok { status: status(&h) },
        Err(e) => {
            log(format!("ошибка: {e:#}"));
            Response::Error { message: format!("{e:#}") }
        }
    };
    write_line(&mut w, resp)
}

fn serve(shared: Shared, allowed: &[String]) -> Result<()> {
    let pipe = Pipe { sddl: wide(&pipe_sddl(allowed)) };
    let mut next = pipe.create(true)?;
    log(format!("слушаю {SOCKET}, разрешены {allowed:?}, SYSTEM и администраторы"));
    loop {
        let h = next;
        // SAFETY: h is a pipe handle created above
        let ok = unsafe { ConnectNamedPipe(h, std::ptr::null_mut()) } != 0 || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED;
        // keep an instance listening while this client is served
        next = pipe.create(false)?;
        if !ok {
            log(format!("подключение к каналу: {}", std::io::Error::last_os_error()));
            unsafe { CloseHandle(h) };
            continue;
        }
        // SAFETY: we own h; the File closes it on drop
        let file = unsafe { File::from_raw_handle(h as _) };
        if let Err(e) = handle(&file, &shared) {
            log(format!("{e:#}"));
        }
        unsafe {
            FlushFileBuffers(h);
            DisconnectNamedPipe(h);
        }
    }
}

// ---- service ----

static ALLOWED: OnceLock<Vec<String>> = OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        log(format!("служба: {e:#}"));
    }
}

fn set_state(handle: &ServiceStatusHandle, state: ServiceState) {
    let _ = handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running { ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN } else { ServiceControlAccept::empty() },
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(5),
        process_id: None,
    });
}

fn run_service() -> Result<()> {
    let mut helper = Helper::default();
    restore_block(&mut helper);
    let shared: Shared = Arc::new(Mutex::new(helper));
    let on_stop = shared.clone();
    let status_handle: Arc<OnceLock<ServiceStatusHandle>> = Arc::new(OnceLock::new());
    let for_handler = status_handle.clone();
    let handle = service_control_handler::register(SERVICE, move |ctrl| match ctrl {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            down(&mut on_stop.lock().unwrap());
            if let Some(h) = for_handler.get() {
                set_state(h, ServiceState::Stopped);
            }
            std::process::exit(0);
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    let _ = status_handle.set(handle);
    set_state(&handle, ServiceState::Running);
    watch_split(shared.clone());
    let res = serve(shared, ALLOWED.get().map(Vec::as_slice).unwrap_or_default());
    set_state(&handle, ServiceState::Stopped);
    res
}

fn wait_state(svc: &windows_service::service::Service, want: ServiceState) {
    for _ in 0..100 {
        if svc.query_status().is_ok_and(|s| s.current_state == want) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Stops and deletes the service if it exists, waiting until Windows has really removed it.
fn remove_service(manager: &ServiceManager) -> Result<()> {
    let Ok(svc) = manager.open_service(SERVICE, ServiceAccess::STOP | ServiceAccess::QUERY_STATUS | ServiceAccess::DELETE) else {
        return Ok(());
    };
    if svc.stop().is_ok() {
        wait_state(&svc, ServiceState::Stopped);
    }
    svc.delete().context("удаление службы")?;
    drop(svc);
    for _ in 0..50 {
        if manager.open_service(SERVICE, ServiceAccess::QUERY_STATUS).is_err() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

fn manager() -> Result<ServiceManager> {
    ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)
        .map_err(|e| anyhow!("нужны права администратора ({e})"))
}

fn install(allowed: &[String]) -> Result<()> {
    if allowed.is_empty() {
        bail!("укажите --allow-sid");
    }
    let manager = manager()?;
    remove_service(&manager)?;
    // the service runs from Program Files (only administrators may change files there),
    // not from the app folder, which the user can write to
    let dir = install_dir();
    fs::create_dir_all(&dir)?;
    let exe = std::env::current_exe()?;
    let src = exe.parent().ok_or_else(|| anyhow!("нет папки {}", exe.display()))?;
    let target = dir.join("amz-helper.exe");
    if !exe.eq(&target) {
        fs::copy(&exe, &target).with_context(|| format!("копирование в {}", target.display()))?;
        fs::copy(src.join("wintun.dll"), dir.join("wintun.dll")).context("копирование wintun.dll")?;
    }
    let mut args: Vec<OsString> = vec!["service".into()];
    for sid in allowed {
        args.extend(["--allow-sid".into(), sid.into()]);
    }
    let info = ServiceInfo {
        name: SERVICE.into(),
        display_name: "АМнеЗинуVPN".into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: target,
        launch_arguments: args,
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };
    let svc = manager.create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS)
        .context("создание службы")?;
    let _ = svc.set_description("Управляет VPN-подключением АМнеЗинуVPN");
    let restart = ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(2) };
    svc.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![restart.clone(), restart.clone(), restart]),
    })?;
    svc.start::<&str>(&[]).context("запуск службы")?;
    wait_state(&svc, ServiceState::Running);
    log(format!("служба установлена в {}", dir.display()));
    Ok(())
}

fn uninstall() -> Result<()> {
    remove_service(&manager()?)?;
    let dir = install_dir();
    for f in ["amz-helper.exe", "wintun.dll"] {
        let _ = fs::remove_file(dir.join(f));
    }
    let _ = fs::remove_dir(&dir);
    log("служба удалена");
    Ok(())
}

fn valid_sid(s: &str) -> bool {
    s.starts_with("S-1-") && s[4..].split('-').all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

pub fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().unwrap_or_default();
    let mut allowed = vec![];
    while let Some(a) = args.next() {
        match a.as_str() {
            "--allow-sid" => {
                let sid = args.next().ok_or_else(|| anyhow!("--allow-sid S-1-5-..."))?;
                if !valid_sid(&sid) {
                    bail!("неверный SID {sid}");
                }
                allowed.push(sid);
            }
            other => bail!("неизвестный аргумент {other}"),
        }
    }
    match cmd.as_str() {
        "install" => {
            log_to_file()?;
            install(&allowed)
        }
        "uninstall" => {
            log_to_file()?;
            uninstall()
        }
        "service" => {
            log_to_file()?;
            let _ = ALLOWED.set(allowed);
            service_dispatcher::start(SERVICE, ffi_service_main).context("запуск как службы Windows")?;
            Ok(())
        }
        "run" => {
            let mut helper = Helper::default();
            restore_block(&mut helper);
            let shared: Shared = Arc::new(Mutex::new(helper));
            let on_exit = shared.clone();
            ctrlc::set_handler(move || {
                down(&mut on_exit.lock().unwrap());
                std::process::exit(0);
            })?;
            watch_split(shared.clone());
            serve(shared, &allowed)
        }
        _ => bail!("использование: amz-helper install|uninstall|run --allow-sid <SID>"),
    }
}

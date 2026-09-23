//! Privileged helper (runs as root): brings the AmneziaWG tunnel up/down on request of allowed users.
//! Usage (development): sudo amz-helper --allow-uid $(id -u)
#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("amz-helper: пока поддерживается только macOS");
    std::process::exit(1);
}

#[cfg(target_os = "macos")]
fn main() {
    if let Err(e) = macos::main() {
        eprintln!("amz-helper: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::fs;
    use std::io::{BufRead, BufReader};
    use std::net::ToSocketAddrs;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::Path;
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    use amz_core::tunnel::{parse_stats, tunnel_config};
    use amz_ipc::{read_line, write_line, Request, Response, Status, UpOptions, BUILD, SOCKET};
    use amz_tunnel::awg::Device;
    use amz_tunnel::macos::{configure, follow_gateway, restore, restore_keep_block, NetState};
    use anyhow::{anyhow, bail, Result};

    /// What was changed in the system, kept on disk to undo it after a crash.
    const STATE_FILE: &str = "/var/run/amnezinu-vpn.net.json";

    struct Active {
        dev: Device,
        net: NetState,
        status: Status,
    }

    #[derive(Default)]
    struct Helper {
        active: Option<Active>,
        /// kill switch left blocking after a crash: undone by the next Down or Up
        blocked: Option<NetState>,
    }

    type Shared = Arc<Mutex<Helper>>;

    fn log(msg: impl AsRef<str>) {
        eprintln!("amz-helper: {}", msg.as_ref());
    }

    fn peer_uid(s: &UnixStream) -> Result<u32> {
        let (mut uid, mut gid) = (0, 0);
        // SAFETY: valid socket fd and out-pointers
        if unsafe { libc::getpeereid(s.as_raw_fd(), &mut uid, &mut gid) } != 0 {
            bail!("getpeereid: {}", std::io::Error::last_os_error());
        }
        Ok(uid)
    }

    fn undo(net: &NetState) {
        for e in restore(net) {
            log(format!("восстановление сети: {e}"));
        }
        let _ = fs::remove_file(STATE_FILE);
    }

    fn down(h: &mut Helper) {
        if let Some(a) = h.active.take() {
            log(format!("отключение {} ({})", a.status.name, a.status.iface));
            drop(a.dev);
            undo(&a.net);
        }
        if let Some(net) = h.blocked.take() {
            log("снимаю блокировку kill switch");
            undo(&net);
        }
    }

    fn up(h: &mut Helper, conf: &str, name: &str, opts: &UpOptions) -> Result<()> {
        let cfg = tunnel_config(conf, |host, port| {
            let addrs: Vec<_> = (host, port).to_socket_addrs().ok()?.collect();
            addrs.iter().find(|a| a.is_ipv4()).or(addrs.first()).copied()
        })?;
        down(h);
        let dev = Device::up("utun", cfg.mtu, &cfg.uapi)?;
        let mut net = NetState::default();
        if let Err(e) = configure(dev.name(), &cfg, opts, &mut net) {
            drop(dev);
            undo(&net);
            return Err(e);
        }
        fs::write(STATE_FILE, serde_json::to_vec(&net)?)?;
        let since = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        log(format!("подключено {name}: {} → {} (kill switch: {}, раздельное: {:?} {} шт.)", dev.name(), cfg.endpoint,
                    net.kill_switch, opts.split.mode, opts.split.entries.len()));
        let status = Status { connected: true, name: name.into(), iface: dev.name().into(),
                              endpoint: cfg.endpoint.to_string(), since, kill_switch: net.kill_switch,
                              ..Default::default() };
        h.active = Some(Active { dev, net, status });
        Ok(())
    }

    fn status(h: &Helper) -> Status {
        let s = match &h.active {
            Some(a) => Status { stats: parse_stats(&a.dev.config()), ..a.status.clone() },
            None => Status { blocked: h.blocked.is_some(), kill_switch: h.blocked.is_some(), ..Default::default() },
        };
        Status { helper_version: BUILD.into(), ..s }
    }

    /// Laptops change networks: keep the route to the server on the current physical gateway.
    fn watch_network(shared: Shared) {
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(5));
            let mut h = shared.lock().unwrap();
            if let Some(a) = h.active.as_mut() {
                match follow_gateway(&mut a.net) {
                    Ok(true) => {
                        log(format!("сеть сменилась, маршрут до сервера через {:?}", a.net.endpoint_route.as_ref().map(|r| &r.1)));
                        let _ = fs::write(STATE_FILE, serde_json::to_vec(&a.net).unwrap_or_default());
                    }
                    Ok(false) => {}
                    Err(e) => log(format!("смена сети: {e:#}")),
                }
            }
        });
    }

    fn handle(stream: UnixStream, shared: &Shared, allowed: &[u32]) -> Result<()> {
        let uid = peer_uid(&stream)?;
        let mut w = stream.try_clone()?;
        if uid != 0 && !allowed.contains(&uid) {
            write_line(&mut w, Response::Error { message: format!("пользователю uid={uid} управление VPN не разрешено") })?;
            bail!("отказано uid={uid}");
        }
        let mut reader = BufReader::new(stream);
        // the app probes the socket by connecting and closing: nothing to answer or log
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

    pub fn main() -> Result<()> {
        let mut allowed = vec![];
        let mut args = std::env::args().skip(1);
        while let Some(a) = args.next() {
            match a.as_str() {
                "--allow-uid" => allowed.push(args.next().ok_or_else(|| anyhow!("--allow-uid N"))?.parse()?),
                other => bail!("неизвестный аргумент {other}"),
            }
        }
        if unsafe { libc::geteuid() } != 0 {
            bail!("нужны права root: sudo amz-helper --allow-uid $(id -u)");
        }
        // a previous run died with the tunnel up: undo its routes and DNS;
        // with the kill switch on, traffic stays blocked until the user connects or disconnects
        let mut helper = Helper::default();
        if let Ok(raw) = fs::read(STATE_FILE) {
            if let Ok(net) = serde_json::from_slice::<NetState>(&raw) {
                if net.kill_switch {
                    log("прошлый запуск завершился аварийно: kill switch держит интернет заблокированным до отключения");
                    for e in restore_keep_block(&net) {
                        log(format!("восстановление сети: {e}"));
                    }
                    helper.blocked = Some(NetState { endpoint_route: None, dns_backup: vec![], bypass: vec![], ..net });
                } else {
                    log("восстанавливаю сеть после прошлого аварийного завершения");
                    undo(&net);
                }
            }
        }
        let shared: Shared = Arc::new(Mutex::new(helper));
        watch_network(shared.clone());
        let on_exit = shared.clone();
        ctrlc::set_handler(move || {
            down(&mut on_exit.lock().unwrap());
            let _ = fs::remove_file(SOCKET);
            std::process::exit(0);
        })?;

        let _ = fs::remove_file(SOCKET);
        let listener = UnixListener::bind(SOCKET)?;
        // access is checked per connection by peer uid
        fs::set_permissions(Path::new(SOCKET), fs::Permissions::from_mode(0o666))?;
        log(format!("слушаю {SOCKET}, разрешены uid {allowed:?} и root"));
        for stream in listener.incoming() {
            match stream {
                Ok(s) => {
                    if let Err(e) = handle(s, &shared, &allowed) {
                        log(format!("{e:#}"));
                    }
                }
                Err(e) => log(format!("accept: {e}")),
            }
        }
        Ok(())
    }
}

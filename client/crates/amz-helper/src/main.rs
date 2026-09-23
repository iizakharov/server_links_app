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
    use std::io::BufReader;
    use std::net::ToSocketAddrs;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::Path;
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    use amz_core::tunnel::{parse_stats, tunnel_config};
    use amz_ipc::{read_line, write_line, Request, Response, Status, SOCKET};
    use amz_tunnel::awg::Device;
    use amz_tunnel::macos::{configure, restore, NetState};
    use anyhow::{anyhow, bail, Result};

    /// What was changed in the system, kept on disk to undo it after a crash.
    const STATE_FILE: &str = "/var/run/amnezinu-vpn.net.json";

    struct Active {
        dev: Device,
        net: NetState,
        status: Status,
    }

    type Shared = Arc<Mutex<Option<Active>>>;

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

    fn down(active: &mut Option<Active>) {
        if let Some(a) = active.take() {
            log(format!("отключение {} ({})", a.status.name, a.status.iface));
            drop(a.dev);
            undo(&a.net);
        }
    }

    fn up(active: &mut Option<Active>, conf: &str, name: &str) -> Result<()> {
        let cfg = tunnel_config(conf, |host, port| {
            let addrs: Vec<_> = (host, port).to_socket_addrs().ok()?.collect();
            addrs.iter().find(|a| a.is_ipv4()).or(addrs.first()).copied()
        })?;
        down(active);
        let dev = Device::up("utun", cfg.mtu, &cfg.uapi)?;
        let mut net = NetState::default();
        if let Err(e) = configure(dev.name(), &cfg, &mut net) {
            drop(dev);
            undo(&net);
            return Err(e);
        }
        fs::write(STATE_FILE, serde_json::to_vec(&net)?)?;
        let since = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        log(format!("подключено {name}: {} → {}", dev.name(), cfg.endpoint));
        let status = Status { connected: true, name: name.into(), iface: dev.name().into(),
                              endpoint: cfg.endpoint.to_string(), since, stats: Default::default() };
        *active = Some(Active { dev, net, status });
        Ok(())
    }

    fn status(active: &Option<Active>) -> Status {
        match active {
            Some(a) => Status { stats: parse_stats(&a.dev.config()), ..a.status.clone() },
            None => Status::default(),
        }
    }

    fn handle(stream: UnixStream, shared: &Shared, allowed: &[u32]) -> Result<()> {
        let uid = peer_uid(&stream)?;
        let mut w = stream.try_clone()?;
        if uid != 0 && !allowed.contains(&uid) {
            write_line(&mut w, Response::Error { message: format!("пользователю uid={uid} управление VPN не разрешено") })?;
            bail!("отказано uid={uid}");
        }
        let req: Request = read_line(&mut BufReader::new(stream))?;
        let mut active = shared.lock().unwrap();
        let res = match &req {
            Request::Up { conf, name } => up(&mut active, conf, name),
            Request::Down => {
                down(&mut active);
                Ok(())
            }
            Request::Status => Ok(()),
        };
        let resp = match res {
            Ok(()) => Response::Ok { status: status(&active) },
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
        // a previous run died with the tunnel up: undo its routes and DNS
        if let Ok(raw) = fs::read(STATE_FILE) {
            if let Ok(net) = serde_json::from_slice::<NetState>(&raw) {
                log("восстанавливаю сеть после прошлого аварийного завершения");
                undo(&net);
            }
        }
        let shared: Shared = Arc::new(Mutex::new(None));
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

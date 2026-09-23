//! Debug CLI over the same operations the app uses. State lives in `--data` (state.json compatible with the panel).
use std::path::PathBuf;

use amz_core::awg::awg_version;
use amz_core::model::{Server, State};
use amz_core::storage::Storage;
use amz_remote::ops::{self, CascadeRequest, OpLog, Ssh};
use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "amz", about = "АМнеЗинуVPN: серверы, каскады и клиенты AmneziaWG")]
struct Cli {
    /// Directory with state.json
    #[arg(long, env = "AMZ_DATA", default_value = "data")]
    data: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List servers, cascades and clients
    Ls,
    /// Add a server (by SSH password or key)
    AddServer {
        host: String,
        #[arg(long, default_value = "")]
        name: String,
        #[arg(long, default_value_t = 22)]
        port: u16,
        #[arg(long, default_value = "root")]
        user: String,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        key: Option<String>,
    },
    RmServer { id: String },
    /// Read-only scan: OS, AmneziaWG, NAT forwards, busy UDP ports
    Scan { id: String },
    /// Create cascades proxy -> exit(s)
    Cascade {
        #[arg(long)]
        proxy: String,
        #[arg(long = "exit", required = true)]
        exits: Vec<String>,
        #[arg(long)]
        port: Option<u16>,
        /// auto | legacy | v2 | v3
        #[arg(long, default_value = "auto")]
        instance: String,
    },
    /// Adopt an existing forward on the proxy as a cascade
    Adopt { proxy: String, exit: String, port: u16 },
    RmCascade { id: String },
    /// UDP probes proxy <-> exit
    Check { id: String },
    /// Create a client on one or more cascades
    AddClient { name: String, #[arg(required = true)] cascades: Vec<String> },
    /// Revoke a client on its exit server
    RmClient { id: String },
    /// Poll exit servers and accumulate traffic per client
    Traffic,
    /// Print the client's .conf
    Conf { id: String },
    /// Print the client's vpn:// key
    Key { id: String },
    /// Connect this device: a client from state, or a .conf file (needs amz-helper running)
    Up {
        /// client id from state
        id: Option<String>,
        #[arg(long)]
        conf: Option<PathBuf>,
        /// block traffic outside the tunnel
        #[arg(long)]
        kill_switch: bool,
        /// with --kill-switch: allow the local network
        #[arg(long)]
        allow_lan: bool,
        /// only these sites/networks through the VPN (comma separated)
        #[arg(long, value_delimiter = ',', conflicts_with = "except")]
        only: Vec<String>,
        /// everything except these sites/networks through the VPN (comma separated)
        #[arg(long, value_delimiter = ',')]
        except: Vec<String>,
    },
    /// Check client configs with the built-in amneziawg-go (all clients if no id)
    Validate { id: Option<String> },
    /// Disconnect this device
    Down,
    /// Tunnel status of this device
    Status,
}

fn print_status(st: &amz_ipc::Status) {
    if !st.connected {
        println!("не подключено");
        return;
    }
    let hs = match st.stats.handshake {
        0 => "ещё не было".to_string(),
        t => format!("{} с назад", (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64).unwrap_or(t) - t).max(0)),
    };
    println!("подключено: {} через {} → {}", st.name, st.iface, st.endpoint);
    println!("handshake: {hs}; получено {}, отправлено {}", human(st.stats.rx), human(st.stats.tx));
}

fn print_log(r: OpLog) -> Result<()> {
    for l in &r.log {
        println!("{l}");
    }
    if r.ok { Ok(()) } else { Err(anyhow!("операция не выполнена")) }
}

fn human(bytes: u64) -> String {
    let mut v = bytes as f64;
    for unit in ["B", "KB", "MB", "GB"] {
        if v < 1024.0 {
            return format!("{v:.1} {unit}");
        }
        v /= 1024.0;
    }
    format!("{v:.1} TB")
}

fn ls(s: &State) {
    let conn = Ssh;
    println!("Серверы:");
    for x in &s.servers {
        let scan = x.scan.as_ref();
        let awg: Vec<String> = ["main", "legacy", "v2", "v3"].iter()
            .filter_map(|i| scan?.awg_for(i).map(|a| format!("{i}:{}@{}", awg_version(&a.params), a.listen_port)))
            .collect();
        println!("  {}  {:<16} {}:{}  {}  {}", x.id, x.name, x.host, x.ssh_port,
                 scan.map(|s| s.os.as_str()).unwrap_or("не сканирован"), awg.join(" "));
    }
    println!("Каскады:");
    let name = |id: &str| s.servers.iter().find(|x| x.id == id).map(|x| x.name.clone()).unwrap_or_default();
    for v in ops::cascade_views(&conn, s) {
        let c = &v.cascade;
        println!("  {}  {} → {}  UDP {}  {}  {}  AWG {}", c.id, name(&c.proxy_id), name(&c.exit_id), c.port,
                 c.instance(), v.status, v.awg_version.unwrap_or_default());
    }
    for x in ops::external_not_adopted(&conn, s) {
        println!("  (существующий) {} → {}  UDP {}  {}  — amz adopt {} {} {}", name(&x.proxy_id), name(&x.exit_id),
                 x.port, x.rule, x.proxy_id, x.exit_id, x.port);
    }
    println!("Клиенты:");
    for c in &s.clients {
        let traffic = c.traffic.map(|t| format!("↓{} ↑{}", human(t.tx), human(t.rx))).unwrap_or("—".into());
        println!("  {}  {:<12} {:<12} каскад {}  {traffic}", c.id, c.name, c.ip, c.cascade_id);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let store = Storage::new(&cli.data);
    let mut s = store.load()?;
    let conn = Ssh;
    match cli.cmd {
        Cmd::Ls => ls(&s),
        Cmd::AddServer { host, name, port, user, password, key } => {
            let id = ops::new_id();
            s.servers.push(Server { id: id.clone(), name: if name.is_empty() { host.clone() } else { name }, host,
                                    ssh_port: port, user, password, key_path: key, ..Default::default() });
            store.save(&s)?;
            println!("{id}");
        }
        Cmd::RmServer { id } => ops::delete_server(&store, &mut s, &id)?,
        Cmd::Scan { id } => println!("{}", ops::scan_server(&conn, &store, &mut s, &id).await?),
        Cmd::Cascade { proxy, exits, port, instance } => {
            let req = CascadeRequest { proxy_id: proxy, exit_ids: exits, port, instance };
            print_log(ops::create_cascades(&conn, &store, &mut s, &req).await)?
        }
        Cmd::Adopt { proxy, exit, port } => ops::adopt_cascade(&conn, &store, &mut s, &proxy, &exit, port)?,
        Cmd::RmCascade { id } => print_log(ops::delete_cascade(&conn, &store, &mut s, &id).await)?,
        Cmd::Check { id } => print_log(ops::check_cascade(&conn, &mut s, &id).await)?,
        Cmd::AddClient { name, cascades } => {
            for id in ops::create_clients(&conn, &store, &mut s, &name, &cascades).await? {
                println!("{id}");
            }
        }
        Cmd::RmClient { id } => print_log(ops::delete_client(&conn, &store, &mut s, &id).await)?,
        Cmd::Traffic => print_log(ops::refresh_traffic(&conn, &store, &mut s).await)?,
        Cmd::Conf { id } => print!("{}", ops::render(&s, &id)?.conf),
        Cmd::Key { id } => println!("{}", ops::render(&s, &id)?.vpn_key),
        Cmd::Up { id, conf, kill_switch, allow_lan, only, except } => {
            let (conf, name) = match (id, conf) {
                (Some(id), None) => {
                    let r = ops::render(&s, &id)?;
                    (r.conf, r.filename.trim_end_matches(".conf").to_string())
                }
                (None, Some(path)) => (std::fs::read_to_string(&path)?,
                                       path.file_stem().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()),
                _ => return Err(anyhow!("укажите id клиента или --conf файл")),
            };
            let split = match (only.is_empty(), except.is_empty()) {
                (false, _) => amz_ipc::Split { mode: amz_ipc::SplitMode::Only, entries: only },
                (_, false) => amz_ipc::Split { mode: amz_ipc::SplitMode::Except, entries: except },
                _ => Default::default(),
            };
            let options = amz_ipc::UpOptions { kill_switch, allow_lan, split };
            print_status(&amz_ipc::call(&amz_ipc::Request::Up { conf, name, options })?);
        }
        Cmd::Validate { id } => {
            let ids: Vec<String> = match id {
                Some(id) => vec![id],
                None => s.clients.iter().map(|c| c.id.clone()).collect(),
            };
            let mut bad = 0;
            for id in &ids {
                let res = ops::render(&s, id).and_then(|r| {
                    let cfg = amz_core::tunnel::tunnel_config(&r.conf, |_, port| Some(([192, 0, 2, 1], port).into()))?;
                    amz_tunnel::awg::validate(&cfg.uapi)
                });
                if let Err(e) = res {
                    bad += 1;
                    println!("{id}: {e:#}");
                }
            }
            println!("проверено {}, ошибок {bad}", ids.len());
            if bad > 0 {
                return Err(anyhow!("есть конфиги, которые amneziawg не принимает"));
            }
        }
        Cmd::Down => print_status(&amz_ipc::call(&amz_ipc::Request::Down)?),
        Cmd::Status => print_status(&amz_ipc::call(&amz_ipc::Request::Status)?),
    }
    Ok(())
}

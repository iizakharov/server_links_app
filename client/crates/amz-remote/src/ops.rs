//! Operations on the whole setup (servers -> cascades -> clients), ported from the endpoints of `app/main.py`.
//! Each operation works on the in-memory `State` and saves it after every step that changed a server,
//! so a failure halfway keeps what was already done.
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::ToSocketAddrs;
use std::sync::Mutex;

use amz_core::awg::{awg_version, instance as awg_instance, is_legacy};
use amz_core::model::{AwgInfo, Cascade, Client, Server, State, Traffic};
use amz_core::storage::Storage;
use amz_core::{client_conf, vpn_key};
use anyhow::{anyhow, bail, Result};
use rand::Rng;
use serde::Serialize;

use crate::foreign::{self, PeerStat};
use crate::proxy::{self, ExternalCascade, Route};
use crate::remote::Remote;
use crate::ssh::{SshRemote, SshTarget};

/// Opens connections to servers; tests plug in fakes.
pub trait Connector: Sync {
    type R: Remote;
    fn connect(&self, server: &Server) -> impl Future<Output = Result<Self::R>> + Send;
    /// IP address of a server (its host may be a DNS name).
    fn ip_of(&self, server: &Server) -> String;
}

pub struct Ssh;

impl Connector for Ssh {
    type R = SshRemote;

    fn connect(&self, server: &Server) -> impl Future<Output = Result<SshRemote>> + Send {
        SshRemote::connect(SshTarget::from_server(server))
    }

    fn ip_of(&self, server: &Server) -> String {
        (server.host.as_str(), 0).to_socket_addrs().ok()
            .and_then(|mut a| a.find(|a| a.is_ipv4()))
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|| server.host.clone())
    }
}

/// Result of an operation with its progress log (shown to the user as is).
#[derive(Debug, Clone, Default, Serialize)]
pub struct OpLog {
    pub ok: bool,
    pub log: Vec<String>,
}

struct Logger(Mutex<Vec<String>>);

impl Logger {
    fn new() -> Self {
        Logger(Mutex::new(vec![]))
    }
    fn push(&self, line: impl Into<String>) {
        self.0.lock().unwrap().push(line.into());
    }
    fn finish(self, res: Result<()>) -> OpLog {
        let mut log = self.0.into_inner().unwrap();
        if let Err(e) = &res {
            log.push(format!("ОШИБКА: {e:#}"));
        }
        OpLog { ok: res.is_ok(), log }
    }
}

pub fn new_id() -> String {
    format!("{:08x}", rand::thread_rng().gen::<u32>())
}

fn now() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M").to_string()
}

fn find<'a, T>(items: &'a [T], id: &str, what: &str, id_of: impl Fn(&T) -> &str) -> Result<&'a T> {
    items.iter().find(|x| id_of(x) == id).ok_or_else(|| anyhow!("{what} {id} не найден"))
}

fn server<'a>(s: &'a State, id: &str) -> Result<&'a Server> {
    find(&s.servers, id, "Сервер", |x| &x.id)
}

fn server_mut<'a>(s: &'a mut State, id: &str) -> Result<&'a mut Server> {
    s.servers.iter_mut().find(|x| x.id == id).ok_or_else(|| anyhow!("Сервер {id} не найден"))
}

fn cascade<'a>(s: &'a State, id: &str) -> Result<&'a Cascade> {
    find(&s.cascades, id, "Каскад", |x| &x.id)
}

/// Connects and remembers the server's SSH host key on first use (trust on first use).
async fn open<C: Connector>(conn: &C, s: &mut State, sid: &str) -> Result<C::R> {
    let srv = server(s, sid)?.clone();
    let r = conn.connect(&srv).await?;
    if let (None, Some(fp)) = (srv.extra.get("host_key"), r.host_key()) {
        server_mut(s, sid)?.extra.insert("host_key".into(), fp.into());
    }
    Ok(r)
}

/// AmneziaWG instance of the exit server this cascade leads to.
pub fn exit_awg<'a>(exit: &'a Server, c: &Cascade) -> Option<&'a AwgInfo> {
    exit.scan.as_ref()?.awg_for(c.instance())
}

fn set_awg(s: &mut State, sid: &str, instance: &str, awg: Option<AwgInfo>) -> Result<()> {
    server_mut(s, sid)?.scan.get_or_insert_with(Default::default).set_awg(instance, awg);
    Ok(())
}

fn managed_routes<C: Connector>(conn: &C, s: &State, proxy_id: &str) -> Result<Vec<Route>> {
    s.cascades.iter().filter(|c| c.proxy_id == proxy_id && c.mode == "managed").map(|c| {
        let e = server(s, &c.exit_id)?;
        let awg = exit_awg(e, c).ok_or_else(|| anyhow!("{} не сканирован", e.name))?;
        Ok((c.port as u32, conn.ip_of(e), awg.listen_port as u32))
    }).collect()
}

async fn apply_proxy<C: Connector>(conn: &C, s: &mut State, proxy_id: &str, log: &Logger) -> Result<()> {
    let routes = managed_routes(conn, s, proxy_id)?;
    let mut r = open(conn, s, proxy_id).await?;
    proxy::setup(&mut r, &routes, &|l| log.push(l)).await?;
    let scan = proxy::scan(&mut r).await?;
    server_mut(s, proxy_id)?.scan = Some(scan);
    Ok(())
}

// ---------- overview (GET /api/state) ----------

#[derive(Debug, Clone, Serialize)]
pub struct CascadeView {
    #[serde(flatten)]
    pub cascade: Cascade,
    /// applied | missing | conflict | unknown | external
    pub status: String,
    pub awg_version: Option<String>,
}

pub fn cascade_views<C: Connector>(conn: &C, s: &State) -> Vec<CascadeView> {
    s.cascades.iter().filter_map(|c| {
        let (p, e) = (server(s, &c.proxy_id).ok()?, server(s, &c.exit_id).ok()?);
        let status = if c.mode == "external" {
            "external"
        } else {
            proxy::managed_status(c.port as u32, p.scan.as_ref(), &conn.ip_of(e))
        };
        Some(CascadeView { cascade: c.clone(), status: status.into(),
                           awg_version: exit_awg(e, c).map(|a| awg_version(&a.params).to_string()) })
    }).collect()
}

/// Existing forwards on proxies that are not adopted yet.
pub fn external_not_adopted<C: Connector>(conn: &C, s: &State) -> Vec<ExternalCascade> {
    let adopted: HashSet<(&str, &str, u32)> =
        s.cascades.iter().map(|c| (c.proxy_id.as_str(), c.exit_id.as_str(), c.port as u32)).collect();
    proxy::external_cascades(&s.servers, |x| conn.ip_of(x)).into_iter()
        .filter(|x| !adopted.contains(&(x.proxy_id.as_str(), x.exit_id.as_str(), x.port)))
        .collect()
}

// ---------- servers ----------

pub fn delete_server(store: &Storage, s: &mut State, sid: &str) -> Result<()> {
    if s.cascades.iter().any(|c| c.proxy_id == sid || c.exit_id == sid) {
        bail!("Сервер используется в каскаде — сначала удалите каскад");
    }
    server(s, sid)?;
    s.servers.retain(|x| x.id != sid);
    store.save(s)?;
    Ok(())
}

/// Read-only: OS, AmneziaWG, existing NAT forwards, busy UDP ports.
pub async fn scan_server<C: Connector>(conn: &C, store: &Storage, s: &mut State, sid: &str) -> Result<String> {
    let name = server(s, sid)?.name.clone();
    let run = async {
        let mut r = open(conn, s, sid).await?;
        proxy::scan(&mut r).await
    };
    let scan = run.await.map_err(|e| anyhow!("{name}: {e:#}"))?;
    let os = scan.os.clone();
    server_mut(s, sid)?.scan = Some(scan);
    store.save(s)?;
    Ok(format!("{name}: {os}"))
}

// ---------- cascades ----------

#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct CascadeRequest {
    pub proxy_id: String,
    pub exit_ids: Vec<String>,
    pub port: Option<u16>,
    /// auto (what is on the server) | legacy (1.0) | v2 | v3
    pub instance: String,
}

pub async fn create_cascades<C: Connector>(conn: &C, store: &Storage, s: &mut State, req: &CascadeRequest) -> OpLog {
    let log = Logger::new();
    let res = create_cascades_inner(conn, store, s, req, &log).await;
    log.finish(res)
}

async fn create_cascades_inner<C: Connector>(conn: &C, store: &Storage, s: &mut State, req: &CascadeRequest,
                                             log: &Logger) -> Result<()> {
    let want = if req.instance.is_empty() { "auto" } else { req.instance.as_str() };
    let p = server(s, &req.proxy_id)?.clone();
    if req.exit_ids.is_empty() {
        bail!("Выберите хотя бы один сервер выхода");
    }
    if req.exit_ids.contains(&req.proxy_id) {
        bail!("Прокси не может быть выходом сам для себя");
    }
    if req.port.is_some() && req.exit_ids.len() > 1 {
        bail!("Порт можно задать вручную только для одного выхода");
    }
    if want != "auto" && awg_instance(want).is_none() {
        bail!("Неизвестная версия AmneziaWG: {want}");
    }

    log.push(format!("[{}] сканирование прокси…", p.host));
    let scan = proxy::scan(&mut open(conn, s, &p.id).await?).await?;
    server_mut(s, &p.id)?.scan = Some(scan);
    store.save(s)?;

    let (mut new, mut taken): (Vec<Cascade>, HashSet<u32>) =
        (vec![], s.cascades.iter().filter(|c| c.proxy_id == p.id).map(|c| c.port as u32).collect());
    for eid in &req.exit_ids {
        let e = server(s, eid)?.clone();
        log.push(format!("[{}] проверка AmneziaWG ({})…", e.host, e.name));
        let (awg, instance) = {
            let mut r = open(conn, s, eid).await?;
            let main = foreign::detect(&mut r).await?;
            let l = |x: String| log.push(x);
            let (awg, instance) = match (want, &main) {
                ("legacy", Some(m)) if is_legacy(&m.params) => {
                    log.push(format!("{}: основной AmneziaWG уже версии 1.0 — отдельный контейнер не нужен", e.name));
                    (m.clone(), "main".to_string())
                }
                ("auto", _) => (foreign::ensure(&mut r, &l).await?, "main".to_string()),
                _ => {
                    let found = foreign::detect_instance(&mut r, want).await?;
                    let awg = match found {
                        Some(a) => a,
                        None => foreign::install_instance(&mut r, want, main.as_ref(), &l).await?,
                    };
                    (awg, want.to_string())
                }
            };
            set_awg(s, eid, &instance, Some(awg.clone()))?;
            if let Some(m) = main {
                set_awg(s, eid, "main", Some(m))?;
            }
            (awg, instance)
        };
        store.save(s)?;
        if s.cascades.iter().any(|c| c.proxy_id == p.id && c.exit_id == *eid && c.mode == "managed" && c.instance() == instance) {
            log.push(format!("{} → {}: каскад уже есть, пропущен", p.name, e.name));
            continue;
        }
        let (p_now, e_now) = (server(s, &p.id)?.clone(), server(s, eid)?.clone());
        if instance == "main" {
            for x in proxy::external_cascades(&[p_now.clone(), e_now.clone()], |x| conn.ip_of(x)) {
                log.push(format!("ВНИМАНИЕ: уже есть существующий каскад {} → {} через UDP {} ({}); его можно просто «Использовать»",
                                 p.name, e.name, x.port, x.rule));
            }
        }
        let pscan = p_now.scan.clone().unwrap_or_default();
        let port = match req.port {
            Some(port) => port as u32,
            None => proxy::pick_port(&pscan, &taken, 51820)?,
        };
        if let Some(err) = proxy::port_conflict(port, &pscan, &taken) {
            bail!(err);
        }
        {
            let mut rp = open(conn, s, &p.id).await?;
            let mut re = open(conn, s, eid).await?;
            let back = proxy::pick_port(&pscan, &taken.iter().copied().chain([port]).collect(), 51820)?;
            let l = |x: String| log.push(x);
            if let Some(err) = proxy::check_link(&mut rp, &mut re, &conn.ip_of(&e_now), awg.listen_port as u32, back, &l).await? {
                bail!(err);
            }
        }
        taken.insert(port);
        new.push(Cascade { id: new_id(), proxy_id: p.id.clone(), exit_id: eid.clone(), port: port as u16,
                           mode: "managed".into(), instance: Some(instance), extra: Default::default() });
    }
    if !new.is_empty() {
        s.cascades.extend(new);
        log.push(format!("[{}] применение правил…", p.host));
        apply_proxy(conn, s, &p.id, log).await?;
        store.save(s)?;
    }
    Ok(())
}

pub fn adopt_cascade<C: Connector>(conn: &C, store: &Storage, s: &mut State, proxy_id: &str, exit_id: &str, port: u16) -> Result<()> {
    let found = proxy::external_cascades(&s.servers, |x| conn.ip_of(x)).into_iter()
        .any(|x| x.proxy_id == proxy_id && x.exit_id == exit_id && x.port == port as u32);
    if !found {
        bail!("Такой существующий каскад не найден — пересканируйте серверы");
    }
    s.cascades.push(Cascade { id: new_id(), proxy_id: proxy_id.into(), exit_id: exit_id.into(), port,
                              mode: "external".into(), instance: Some("main".into()), extra: Default::default() });
    store.save(s)?;
    Ok(())
}

pub async fn delete_cascade<C: Connector>(conn: &C, store: &Storage, s: &mut State, cid: &str) -> OpLog {
    let log = Logger::new();
    let res = async {
        let c = cascade(s, cid)?.clone();
        s.cascades.retain(|x| x.id != cid);
        s.clients.retain(|x| x.cascade_id != cid);
        if c.mode == "managed" {
            apply_proxy(conn, s, &c.proxy_id, &log).await?;
        } else {
            log.push("Существующий каскад убран из приложения; правила на прокси не тронуты");
        }
        store.save(s)?;
        Ok(())
    }.await;
    if res.is_err() {
        // nothing was saved: reload so the in-memory state matches the file
        if let Ok(saved) = store.load() {
            *s = saved;
        }
    }
    log.finish(res)
}

/// Sends UDP probes proxy <-> exit and reports whether the cascade can work at all.
pub async fn check_cascade<C: Connector>(conn: &C, s: &mut State, cid: &str) -> OpLog {
    let log = Logger::new();
    let res = async {
        let c = cascade(s, cid)?.clone();
        let (p, e) = (server(s, &c.proxy_id)?.clone(), server(s, &c.exit_id)?.clone());
        let awg = exit_awg(&e, &c).ok_or_else(|| anyhow!("{} не сканирован", e.name))?.clone();
        let mut rp = open(conn, s, &p.id).await?;
        let mut re = open(conn, s, &e.id).await?;
        let taken = s.cascades.iter().map(|x| x.port as u32).collect();
        let back = proxy::pick_port(&p.scan.clone().unwrap_or_default(), &taken, 51820)?;
        let l = |x: String| log.push(x);
        match proxy::check_link(&mut rp, &mut re, &conn.ip_of(&e), awg.listen_port as u32, back, &l).await? {
            Some(err) => bail!(err),
            None => log.push("связь в обе стороны работает"),
        }
        Ok(())
    }.await;
    log.finish(res)
}

// ---------- clients ----------

/// Letters, digits, `_-. `, at most 40 chars (same as the panel).
pub fn clean_name(name: &str) -> String {
    let n: String = name.chars().filter(|c| c.is_alphanumeric() || "_-. ".contains(*c)).collect();
    let n: String = n.trim().chars().take(40).collect();
    if n.is_empty() { "client".into() } else { n }
}

/// Creates a client on each cascade (one record per cascade). Returns the new ids.
pub async fn create_clients<C: Connector>(conn: &C, store: &Storage, s: &mut State, name: &str,
                                          cascade_ids: &[String]) -> Result<Vec<String>> {
    let name = clean_name(name);
    if cascade_ids.is_empty() {
        bail!("Выберите хотя бы один каскад");
    }
    let mut created = vec![];
    for cid in cascade_ids {
        let cas = cascade(s, cid)?.clone();
        let e = server(s, &cas.exit_id)?.clone();
        let inst = cas.instance().to_string();
        let mut r = open(conn, s, &e.id).await?;
        let awg = foreign::detect_any(&mut r, &inst).await?
            .ok_or_else(|| anyhow!("На {} не найден AmneziaWG ({inst})", e.name))?;
        set_awg(s, &e.id, &inst, Some(awg.clone()))?;
        let keys = foreign::add_peer(&mut r, &awg, &name).await?;
        let client = Client {
            id: new_id(), name: name.clone(), cascade_id: cid.clone(), created: Some(now()),
            ip: keys.ip, private_key: keys.private_key, public_key: keys.public_key, psk: keys.psk,
            ..Default::default()
        };
        created.push(client.id.clone());
        s.clients.push(client);
        store.save(s)?;
    }
    Ok(created)
}

/// Adds the delta since the last poll; a counter that went backwards means the interface was restarted.
pub fn accumulate(c: &mut Client, raw: &PeerStat) {
    let add = |total: u64, prev: u64, now: u64| total + if now < prev { now } else { now - prev };
    let (total, prev) = (c.traffic.unwrap_or_default(), c.raw.unwrap_or_default());
    c.traffic = Some(Traffic { rx: add(total.rx, prev.rx, raw.rx), tx: add(total.tx, prev.tx, raw.tx) });
    c.raw = Some(Traffic { rx: raw.rx, tx: raw.tx });
    c.handshake = Some(raw.handshake);
    c.stats_at = Some(now());
}

/// Reads per-peer counters from every exit server and accumulates them per client.
pub async fn refresh_traffic<C: Connector>(conn: &C, store: &Storage, s: &mut State) -> OpLog {
    let mut log = vec![];
    let mut groups: Vec<((String, String), Vec<usize>)> = vec![];
    for (i, c) in s.clients.iter().enumerate() {
        let Ok(cas) = cascade(s, &c.cascade_id) else { continue };
        let key = (cas.exit_id.clone(), cas.instance().to_string());
        match groups.iter_mut().find(|(k, _)| *k == key) {
            Some((_, v)) => v.push(i),
            None => groups.push((key, vec![i])),
        }
    }
    for ((eid, instance), idx) in groups {
        let Ok(e) = server(s, &eid).cloned() else { continue };
        let stats: Result<HashMap<String, PeerStat>> = async {
            let mut r = open(conn, s, &eid).await?;
            let awg = foreign::detect_any(&mut r, &instance).await?.ok_or_else(|| anyhow!("AmneziaWG не найден"))?;
            foreign::peer_stats(&mut r, &awg).await
        }.await;
        let stats = match stats {
            Ok(st) => st,
            Err(err) => {
                log.push(format!("ОШИБКА ({}): {err:#}", e.name));
                continue;
            }
        };
        let mut missing = 0;
        for &i in &idx {
            match stats.get(&s.clients[i].public_key) {
                Some(raw) => accumulate(&mut s.clients[i], raw),
                None => missing += 1,
            }
        }
        let mut line = format!("{}: обновлено клиентов {}", e.name, idx.len() - missing);
        if missing > 0 {
            line += &format!(", не найдено на сервере {missing}");
        }
        log.push(line);
    }
    let saved = store.save(s);
    if let Err(e) = saved {
        log.push(format!("ОШИБКА: {e}"));
    }
    OpLog { ok: !log.iter().any(|l| l.starts_with("ОШИБКА")), log }
}

/// Revokes the client on the exit server and removes it from the list.
pub async fn delete_client<C: Connector>(conn: &C, store: &Storage, s: &mut State, cid: &str) -> OpLog {
    let log = Logger::new();
    let res = async {
        let c = find(&s.clients, cid, "Клиент", |x| &x.id)?.clone();
        let cas = cascade(s, &c.cascade_id)?.clone();
        let e = server(s, &cas.exit_id)?.clone();
        let mut r = open(conn, s, &e.id).await?;
        let awg = foreign::detect_any(&mut r, cas.instance()).await?
            .ok_or_else(|| anyhow!("На {} не найден AmneziaWG ({})", e.name, cas.instance()))?;
        foreign::remove_peer(&mut r, &awg, &c.public_key).await?;
        log.push(format!("[{}] доступ клиента {} ({}) отозван", e.host, c.name, c.ip));
        s.clients.retain(|x| x.id != cid);
        store.save(s)?;
        Ok(())
    }.await;
    log.finish(res)
}

// ---------- configs ----------

pub struct Rendered {
    /// `<client>_<proxy>_<exit>.conf`
    pub filename: String,
    pub conf: String,
    pub vpn_key: String,
}

pub fn render(s: &State, cid: &str) -> Result<Rendered> {
    let c = find(&s.clients, cid, "Клиент", |x| &x.id)?;
    let cas = cascade(s, &c.cascade_id)?;
    let (p, e) = (server(s, &cas.proxy_id)?, server(s, &cas.exit_id)?);
    let awg = exit_awg(e, cas).ok_or_else(|| anyhow!("{} не сканирован", e.name))?;
    let (d1, d2) = (&s.settings.dns1, &s.settings.dns2);
    let safe: String = format!("{}_{}_{}", c.name, p.name, e.name).chars()
        .map(|ch| if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' { ch } else { '_' }).collect();
    Ok(Rendered {
        filename: format!("{safe}.conf"),
        conf: client_conf(&c.keys(), awg, &p.host, cas.port, d1, d2),
        vpn_key: vpn_key(&format!("{} ({} → {})", c.name, p.name, e.name), &c.keys(), awg, &p.host, cas.port, d1, d2),
    })
}

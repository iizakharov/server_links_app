//! App <-> helper protocol: one JSON request line, one JSON response line, over a Unix socket
//! (Windows: a named pipe). The helper only accepts this narrow set of commands.
use std::io::{BufRead, BufReader, Write};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::time::Duration;

use amz_core::tunnel::TunnelStats;
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

pub const VERSION: u32 = 1;
#[cfg(unix)]
pub const SOCKET: &str = "/var/run/amnezinu-vpn.sock";
#[cfg(windows)]
pub const SOCKET: &str = r"\\.\pipe\amnezinu-vpn";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Bring the tunnel up with a client `.conf` (replaces a running one).
    Up {
        conf: String,
        name: String,
        #[serde(default)]
        options: UpOptions,
    },
    /// Disconnect; also lifts a kill-switch block left after a crash.
    Down,
    Status,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct UpOptions {
    /// block all traffic outside the tunnel while connected (and after a crash, until Down)
    pub kill_switch: bool,
    /// with the kill switch: still allow the local network (printers, NAS, router page)
    pub allow_lan: bool,
    pub split: Split,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SplitMode {
    /// everything goes through the VPN
    #[default]
    All,
    /// only the listed sites go through the VPN
    Only,
    /// everything except the listed sites goes through the VPN
    Except,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Split {
    pub mode: SplitMode,
    /// domains (example.com) or IP addresses / networks (1.2.3.4, 10.0.0.0/8)
    pub entries: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Status {
    pub connected: bool,
    /// profile name given on Up
    pub name: String,
    pub iface: String,
    pub endpoint: String,
    /// unix seconds
    pub since: i64,
    pub stats: TunnelStats,
    /// kill switch is holding traffic blocked (the tunnel went away without Down)
    #[serde(default)]
    pub blocked: bool,
    #[serde(default)]
    pub kill_switch: bool,
    /// helper build, so the app can offer to update an outdated service
    #[serde(default)]
    pub helper_version: String,
}

/// Version of this protocol crate's build (the app compares it with the helper's).
pub const BUILD: &str = concat!(env!("CARGO_PKG_VERSION"), "+", env!("AMZ_BUILD_ID"));

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Envelope<T> {
    pub v: u32,
    #[serde(flatten)]
    pub body: T,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    Ok { status: Status },
    Error { message: String },
}

pub fn write_line<T: Serialize>(w: &mut impl Write, body: T) -> Result<()> {
    let mut line = serde_json::to_vec(&Envelope { v: VERSION, body })?;
    line.push(b'\n');
    w.write_all(&line)?;
    w.flush()?;
    Ok(())
}

pub fn read_line<T: for<'de> Deserialize<'de>>(r: &mut impl BufRead) -> Result<T> {
    let mut line = String::new();
    if r.read_line(&mut line)? == 0 {
        bail!("соединение закрыто");
    }
    let env: Envelope<T> = serde_json::from_str(&line).context("неверное сообщение")?;
    if env.v != VERSION {
        bail!("версии приложения и службы не совпадают ({} и {VERSION})", env.v);
    }
    Ok(env.body)
}

/// Sends one request to the helper.
#[cfg(unix)]
pub fn call(req: &Request) -> Result<Status> {
    let stream = UnixStream::connect(SOCKET)
        .map_err(|e| anyhow!("служба AMneZinu не запущена ({SOCKET}: {e})"))?;
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;
    exchange(stream.try_clone()?, stream, req)
}

/// Sends one request to the helper.
#[cfg(windows)]
pub fn call(req: &Request) -> Result<Status> {
    const ERROR_PIPE_BUSY: i32 = 231;
    let mut tries = 0;
    let pipe = loop {
        match std::fs::OpenOptions::new().read(true).write(true).open(SOCKET) {
            Ok(p) => break p,
            // another client is being served: the helper opens the next instance right away
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && tries < 50 => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(40));
            }
            Err(e) => bail!("служба AMneZinu не запущена ({SOCKET}: {e})"),
        }
    };
    exchange(pipe.try_clone()?, pipe, req)
}

fn exchange(mut w: impl Write, r: impl std::io::Read, req: &Request) -> Result<Status> {
    write_line(&mut w, req)?;
    match read_line(&mut BufReader::new(r))? {
        Response::Ok { status } => Ok(status),
        Response::Error { message } => Err(anyhow!(message)),
    }
}

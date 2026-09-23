//! App <-> helper protocol: one JSON request line, one JSON response line, over a Unix socket.
//! The helper only accepts this narrow set of commands.
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use amz_core::tunnel::TunnelStats;
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

pub const VERSION: u32 = 1;
pub const SOCKET: &str = "/var/run/amnezinu-vpn.sock";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Bring the tunnel up with a client `.conf` (replaces a running one).
    Up { conf: String, name: String },
    Down,
    Status,
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
}

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
pub fn call(req: &Request) -> Result<Status> {
    let stream = UnixStream::connect(SOCKET)
        .map_err(|e| anyhow!("служба АМнеЗинуVPN не запущена ({SOCKET}: {e})"))?;
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;
    let mut w = stream.try_clone()?;
    write_line(&mut w, req)?;
    match read_line(&mut BufReader::new(stream))? {
        Response::Ok { status } => Ok(status),
        Response::Error { message } => Err(anyhow!(message)),
    }
}

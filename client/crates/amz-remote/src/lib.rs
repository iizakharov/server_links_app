//! АМнеЗинуVPN server management over SSH: a Rust port of the reference panel's
//! `app/ssh.py`, `app/foreign.py`, `app/proxy.py` and the orchestration in `app/main.py`.

pub mod foreign;
pub mod ops;
pub mod proxy;
pub mod remote;
pub mod ssh;

pub use remote::{quote, Log, Remote};
pub use ssh::{SshRemote, SshTarget};

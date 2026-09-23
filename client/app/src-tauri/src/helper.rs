//! Installing the privileged helper as a system service (macOS: LaunchDaemon), with the standard
//! administrator password prompt. Until the app is signed (SMAppService) this is how it runs without a terminal.
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, Result};
use serde::Serialize;

pub const LABEL: &str = "com.amnezinu.vpn.helper";
const INSTALLED: &str = "/Library/PrivilegedHelperTools/com.amnezinu.vpn.helper";
const PLIST: &str = "/Library/LaunchDaemons/com.amnezinu.vpn.helper.plist";
pub const LOG: &str = "/var/log/amnezinu-vpn-helper.log";

#[derive(Debug, Clone, Serialize)]
pub struct HelperState {
    pub installed: bool,
    pub running: bool,
}

pub fn state() -> HelperState {
    HelperState {
        installed: Path::new(PLIST).exists(),
        running: std::os::unix::net::UnixStream::connect(amz_ipc::SOCKET).is_ok(),
    }
}

/// The helper binary shipped next to the app (bundle resources) or, in development, in the cargo target dir.
pub fn bundled(resource_dir: Option<PathBuf>) -> Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let candidates = [
        resource_dir.map(|d| d.join("amz-helper")),
        exe.parent().map(|d| d.join("amz-helper")),
        exe.parent().map(|d| d.join("../release/amz-helper")),
    ];
    candidates.into_iter().flatten().find(|p| p.is_file())
        .ok_or_else(|| anyhow!("в сборке нет amz-helper (cargo build --release -p amz-helper)"))
}

fn plist(uid: u32) -> String {
    format!(r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key>
  <array><string>{INSTALLED}</string><string>--allow-uid</string><string>{uid}</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>{LOG}</string>
</dict>
</plist>
"#)
}

/// Shell single-quoting.
fn sq(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Runs a shell script as root after the macOS administrator prompt.
fn run_as_admin(script: &str, prompt: &str) -> Result<()> {
    let escape = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    let apple = format!("do shell script \"{}\" with prompt \"{}\" with administrator privileges",
                        escape(script), escape(prompt));
    let out = Command::new("osascript").args(["-e", &apple]).output()?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        if err.contains("-128") {
            bail!("Установка отменена");
        }
        bail!("Не удалось установить службу: {}", err.trim());
    }
    Ok(())
}

pub fn install(helper: &Path) -> Result<()> {
    let uid = unsafe { libc::getuid() };
    let script = format!(
        "set -e; mkdir -p /Library/PrivilegedHelperTools; \
         launchctl bootout system/{LABEL} 2>/dev/null || true; \
         cp {src} {INSTALLED}; chown root:wheel {INSTALLED}; chmod 755 {INSTALLED}; \
         printf %s {plist} > {PLIST}; chown root:wheel {PLIST}; chmod 644 {PLIST}; \
         launchctl bootstrap system {PLIST}",
        src = sq(&helper.to_string_lossy()), plist = sq(&plist(uid)));
    run_as_admin(&script, "АМнеЗинуVPN устанавливает службу, которая управляет VPN-подключением.")?;
    // the service needs a moment to open its socket
    for _ in 0..30 {
        if state().running {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    bail!("Служба установлена, но не отвечает; журнал: {LOG}")
}

pub fn uninstall() -> Result<()> {
    let script = format!("launchctl bootout system/{LABEL} 2>/dev/null || true; rm -f {PLIST} {INSTALLED}");
    run_as_admin(&script, "АМнеЗинуVPN удаляет свою службу.")
}

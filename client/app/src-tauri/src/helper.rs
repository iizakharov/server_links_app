//! Installing the privileged helper as a system service (macOS: LaunchDaemon; Windows: a service), with the
//! standard administrator prompt. Until the app is signed (SMAppService) this is how it runs without a terminal.
#[cfg(target_os = "macos")]
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{anyhow, bail, Result};
use serde::Serialize;

#[cfg(target_os = "macos")]
pub const LABEL: &str = "com.amnezinu.vpn.helper";
#[cfg(target_os = "macos")]
const INSTALLED: &str = "/Library/PrivilegedHelperTools/com.amnezinu.vpn.helper";
#[cfg(target_os = "macos")]
const PLIST: &str = "/Library/LaunchDaemons/com.amnezinu.vpn.helper.plist";
#[cfg(target_os = "macos")]
pub const LOG: &str = "/var/log/amnezinu-vpn-helper.log";
#[cfg(windows)]
pub const LOG: &str = r"C:\ProgramData\AmnezinuVPN\helper.log";

#[cfg(windows)]
const HELPER_EXE: &str = "amz-helper.exe";
#[cfg(not(windows))]
const HELPER_EXE: &str = "amz-helper";

#[derive(Debug, Clone, Serialize)]
pub struct HelperState {
    pub installed: bool,
    pub running: bool,
    /// the running service is an older build than the one inside the app
    pub outdated: bool,
}

pub fn state() -> HelperState {
    let status = amz_ipc::call(&amz_ipc::Request::Status);
    HelperState {
        installed: installed(),
        running: status.is_ok(),
        outdated: status.is_ok_and(|s| s.helper_version != amz_ipc::BUILD),
    }
}

/// The helper binary shipped next to the app (bundle resources) or, in development, in the cargo target dir.
pub fn bundled(resource_dir: Option<PathBuf>) -> Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let candidates = [
        resource_dir.map(|d| d.join(HELPER_EXE)),
        exe.parent().map(|d| d.join(HELPER_EXE)),
        exe.parent().map(|d| d.join("../release").join(HELPER_EXE)),
    ];
    candidates.into_iter().flatten().find(|p| p.is_file())
        .ok_or_else(|| anyhow!("в сборке нет amz-helper (cargo build --release -p amz-helper)"))
}

#[cfg(target_os = "macos")]
fn installed() -> bool {
    Path::new(PLIST).exists()
}

#[cfg(target_os = "macos")]
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
#[cfg(target_os = "macos")]
fn sq(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Runs a shell script as root after the macOS administrator prompt.
#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
pub fn uninstall() -> Result<()> {
    let script = format!("launchctl bootout system/{LABEL} 2>/dev/null || true; rm -f {PLIST} {INSTALLED}");
    run_as_admin(&script, "АМнеЗинуVPN удаляет свою службу.")
}

#[cfg(windows)]
const SERVICE: &str = "AmnezinuVPN";

#[cfg(windows)]
fn hidden(cmd: &str) -> Command {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let mut c = Command::new(cmd);
    c.creation_flags(CREATE_NO_WINDOW);
    c
}

#[cfg(windows)]
fn installed() -> bool {
    hidden("sc.exe").args(["query", SERVICE]).output().is_ok_and(|o| o.status.success())
}

/// SID of the user running the app: only this user (and administrators) may control the VPN.
#[cfg(windows)]
fn user_sid() -> Result<String> {
    let out = hidden("whoami.exe").args(["/user", "/fo", "csv", "/nh"]).output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    text.trim().rsplit(',').next().map(|s| s.trim_matches('"').to_string()).filter(|s| s.starts_with("S-1-"))
        .ok_or_else(|| anyhow!("не удалось определить пользователя Windows: {}", text.trim()))
}

/// Runs the helper elevated (the Windows UAC prompt) and waits for it.
#[cfg(windows)]
fn run_elevated(helper: &std::path::Path, args: &[&str]) -> Result<()> {
    let ps_quote = |s: &str| format!("'{}'", s.replace('\'', "''"));
    let arglist: Vec<String> = args.iter().map(|a| ps_quote(a)).collect();
    let script = format!(
        "$p = Start-Process -FilePath {} -ArgumentList {} -Verb RunAs -WindowStyle Hidden -Wait -PassThru; exit $p.ExitCode",
        ps_quote(&helper.to_string_lossy()), arglist.join(","));
    let out = hidden("powershell.exe").args(["-NoProfile", "-NonInteractive", "-Command", &script]).output()?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        if err.is_empty() {
            bail!("Служба сообщила об ошибке, подробности в журнале: {LOG}");
        }
        // UAC declined: Start-Process fails with "The operation was canceled by the user"
        bail!("Установка отменена или не удалась: {}", err.lines().next().unwrap_or_default().trim());
    }
    Ok(())
}

#[cfg(windows)]
pub fn install(helper: &std::path::Path) -> Result<()> {
    let sid = user_sid()?;
    run_elevated(helper, &["install", "--allow-sid", &sid])?;
    for _ in 0..50 {
        if state().running {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    bail!("Служба установлена, но не отвечает; журнал: {LOG}")
}

#[cfg(windows)]
pub fn uninstall() -> Result<()> {
    // the copy in the app folder removes the service (the installed one could not delete its own file)
    let exe = match bundled(None) {
        Ok(exe) => exe,
        Err(_) => PathBuf::from(std::env::var_os("ProgramFiles").unwrap_or_else(|| r"C:\Program Files".into()))
            .join(r"AmnezinuVPN\amz-helper.exe"),
    };
    run_elevated(&exe, &["uninstall"])
}

//! Safe wrappers over the C API of go/libawg.
use std::ffi::{c_char, CStr, CString};

use anyhow::{anyhow, Result};

extern "C" {
    fn awgTurnOn(ifname: *const c_char, mtu: i32, settings: *const c_char) -> i32;
    fn awgIfName(handle: i32) -> *mut c_char;
    fn awgTurnOff(handle: i32);
    fn awgGetConfig(handle: i32) -> *mut c_char;
    fn awgValidate(settings: *const c_char) -> *mut c_char;
    fn awgLastError() -> *mut c_char;
    fn awgFree(p: *mut c_char);
}

#[cfg(windows)]
extern "C" {
    fn awgNetSet(handle: i32, plan: *const c_char) -> i32;
    fn awgBlock(allow_lan: i32) -> i32;
    fn awgUnblock();
}

/// Windows: kill switch without a tunnel (after the helper was restarted following a crash): everything
/// but this process, loopback, DHCP and optionally the local network is blocked until `unblock`.
#[cfg(windows)]
pub fn block(allow_lan: bool) -> Result<()> {
    if unsafe { awgBlock(allow_lan as i32) } < 0 {
        return Err(anyhow!("блокировка: {}", take(unsafe { awgLastError() }).unwrap_or_default()));
    }
    Ok(())
}

#[cfg(windows)]
pub fn unblock() {
    unsafe { awgUnblock() }
}

/// Takes ownership of a string returned by libawg.
fn take(p: *mut c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    // SAFETY: libawg returns NUL-terminated strings from C.CString, freed exactly once here
    let s = unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
    unsafe { awgFree(p) };
    Some(s)
}

fn cstr(s: &str) -> Result<CString> {
    CString::new(s).map_err(|_| anyhow!("строка содержит NUL"))
}

/// A running AmneziaWG device with its TUN interface; closed on drop.
pub struct Device {
    handle: i32,
    name: String,
}

impl Device {
    /// `ifname` is "utun" on macOS (the system picks the number), the adapter name on Windows.
    pub fn up(ifname: &str, mtu: u32, uapi: &str) -> Result<Device> {
        let (ifname, settings) = (cstr(ifname)?, cstr(&format!("{uapi}\n"))?);
        // SAFETY: both pointers are valid NUL-terminated strings for the duration of the call
        let handle = unsafe { awgTurnOn(ifname.as_ptr(), mtu as i32, settings.as_ptr()) };
        if handle < 0 {
            return Err(anyhow!("amneziawg: {}", take(unsafe { awgLastError() }).unwrap_or_default()));
        }
        let name = take(unsafe { awgIfName(handle) }).unwrap_or_default();
        Ok(Device { handle, name })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// UAPI `get` output.
    pub fn config(&self) -> String {
        take(unsafe { awgGetConfig(self.handle) }).unwrap_or_default()
    }

    /// Windows: addresses, routes, DNS and kill switch of the adapter (may be called again to change routes).
    #[cfg(windows)]
    pub fn set_net(&self, plan: &crate::windows::NetPlan) -> Result<()> {
        let plan = cstr(&serde_json::to_string(plan)?)?;
        // SAFETY: valid handle of this device and a NUL-terminated string for the duration of the call
        if unsafe { awgNetSet(self.handle, plan.as_ptr()) } < 0 {
            return Err(anyhow!("сеть туннеля: {}", take(unsafe { awgLastError() }).unwrap_or_default()));
        }
        Ok(())
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        unsafe { awgTurnOff(self.handle) };
    }
}

/// Checks UAPI settings against the real amneziawg-go parser (in-memory TUN, no root).
pub fn validate(uapi: &str) -> Result<()> {
    let settings = cstr(&format!("{uapi}\n"))?;
    match take(unsafe { awgValidate(settings.as_ptr()) }) {
        None => Ok(()),
        Some(err) => Err(anyhow!("amneziawg не принял настройки: {err}")),
    }
}

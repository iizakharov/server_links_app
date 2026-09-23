//! АМнеЗинуVPN tunnel: amneziawg-go device + OS routes and DNS. Runs inside the privileged helper.

pub mod awg;
#[cfg(target_os = "macos")]
pub mod macos;

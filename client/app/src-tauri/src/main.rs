// no console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    amnezinu_vpn_lib::run()
}

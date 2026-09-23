//! Builds go/libawg (amneziawg-go) as a static C archive and links it.
//! Windows (x86_64-pc-windows-gnu) is cross-built with mingw-w64 (`brew install mingw-w64`).
use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let go_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../../go/libawg");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let goarch = match env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_str() {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => panic!("unsupported arch {other}"),
    };
    let goos = if os == "macos" { "darwin" } else { os.as_str() };

    for f in ["libawg.go", "libawg_other.go", "libawg_windows.go", "go.mod", "go.sum"] {
        println!("cargo:rerun-if-changed={}", go_dir.join(f).display());
    }
    let mut go = Command::new(env::var("GO").unwrap_or_else(|_| "go".into()));
    if os == "windows" && !cfg!(windows) {
        go.env("CC", env::var("AMZ_WINDOWS_CC").unwrap_or_else(|_| format!("{}-w64-mingw32-gcc", env::var("CARGO_CFG_TARGET_ARCH").unwrap())));
    }
    let status = go
        .current_dir(&go_dir)
        .env("CGO_ENABLED", "1")
        .env("GOOS", goos)
        .env("GOARCH", goarch)
        .args(["build", "-trimpath", "-buildmode=c-archive", "-o"])
        .arg(out.join("libawg.a"))
        .arg(".")
        .status()
        .expect("Go toolchain is required to build libawg (https://go.dev/dl/)");
    assert!(status.success(), "go build of libawg failed");

    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=awg");
    if os == "macos" {
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
        println!("cargo:rustc-link-lib=framework=Security");
        println!("cargo:rustc-link-lib=resolv");
    }
}

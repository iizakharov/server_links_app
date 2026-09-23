#!/bin/sh
# Windows x64 build of AMneZinu, cross-compiled on macOS: helper + wintun.dll, then the app and the NSIS installer.
# Needs: brew install mingw-w64 makensis; rustup target add x86_64-pc-windows-gnu
set -e
# updates are signed with this key (the app checks it against the public key in tauri.conf.json)
KEY="${TAURI_SIGNING_PRIVATE_KEY_PATH:-$HOME/.tauri/amnezinu-vpn.key}"
if [ -z "$TAURI_SIGNING_PRIVATE_KEY" ] && [ -f "$KEY" ]; then
  export TAURI_SIGNING_PRIVATE_KEY="$(cat "$KEY")" TAURI_SIGNING_PRIVATE_KEY_PASSWORD="${TAURI_SIGNING_PRIVATE_KEY_PASSWORD:-}"
fi
cd "$(dirname "$0")/../.."
T=x86_64-pc-windows-gnu
export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc
# SSH crypto (aws-lc): its prebuilt assembly instead of requiring nasm
export AWS_LC_SYS_PREBUILT_NASM=1
# makensis crashes (std::bad_alloc) when the locale is not set
export LC_ALL=en_US.UTF-8

# Wintun (the TUN driver of WireGuard, distributed unmodified), checked against the published hash
WINTUN=wintun-0.14.1.zip
if [ ! -f target/wintun/bin/amd64/wintun.dll ]; then
  mkdir -p target
  curl -fsSL -o "target/$WINTUN" "https://www.wintun.net/builds/$WINTUN"
  echo "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51  target/$WINTUN" | shasum -a 256 -c -
  unzip -q -o "target/$WINTUN" -d target
fi

cargo build --release -p amz-helper --target $T
cd app
npx tauri build --target $T --bundles nsis
ls ../target/$T/release/bundle/nsis/*.exe

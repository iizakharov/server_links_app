#!/bin/sh
# Universal (Apple Silicon + Intel) build of AMneZinu: helper for both archs, then the app and .dmg.
set -e
# updates are signed with this key (the app checks it against the public key in tauri.conf.json)
KEY="${TAURI_SIGNING_PRIVATE_KEY_PATH:-$HOME/.tauri/amnezinu-vpn.key}"
if [ -z "$TAURI_SIGNING_PRIVATE_KEY" ] && [ -f "$KEY" ]; then
  export TAURI_SIGNING_PRIVATE_KEY="$(cat "$KEY")" TAURI_SIGNING_PRIVATE_KEY_PASSWORD="${TAURI_SIGNING_PRIVATE_KEY_PASSWORD:-}"
fi
cd "$(dirname "$0")/../.."
for t in aarch64-apple-darwin x86_64-apple-darwin; do
  rustup target add "$t" >/dev/null
  cargo build --release -p amz-helper --target "$t"
done
# the bundle picks the helper up from target/release (see tauri.conf.json "resources")
lipo -create -output target/release/amz-helper \
  target/aarch64-apple-darwin/release/amz-helper target/x86_64-apple-darwin/release/amz-helper
cd app
npx tauri build --target universal-apple-darwin --bundles app,dmg
ls ../target/universal-apple-darwin/release/bundle/dmg/*.dmg

#!/bin/sh
# Universal (Apple Silicon + Intel) build of АМнеЗинуVPN: helper for both archs, then the app and .dmg.
set -e
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

#!/bin/sh
# Builds macOS (universal) and Windows (x64), signs the updates and publishes a GitHub release with latest.json,
# which installed apps check for new versions. Usage: sh scripts/release.sh notes.md
# The version comes from src-tauri/tauri.conf.json; the current commit must be pushed.
set -e
NOTES="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
cd "$(dirname "$0")/.."
REPO=iizakharov/server_links_app
V=$(python3 -c 'import json;print(json.load(open("src-tauri/tauri.conf.json"))["version"])')
COMMIT=$(git rev-parse HEAD)
git fetch -q origin
git branch -r --contains "$COMMIT" | grep -q . || { echo "коммит $COMMIT не отправлен на GitHub"; exit 1; }
gh release view "v$V" -R $REPO >/dev/null 2>&1 && { echo "релиз v$V уже есть — поднимите версию"; exit 1; }

sh scripts/build-mac.sh
sh scripts/build-windows.sh

T=../target
OUT=$T/release-$V
rm -rf "$OUT" && mkdir -p "$OUT"
cp "$T/universal-apple-darwin/release/bundle/dmg/"*"_${V}_universal.dmg" "$OUT/AmnezinuVPN_${V}_macos_universal.dmg"
cp "$T/universal-apple-darwin/release/bundle/macos/"*.app.tar.gz "$OUT/AmnezinuVPN_${V}_macos_universal.app.tar.gz"
cp "$T/universal-apple-darwin/release/bundle/macos/"*.app.tar.gz.sig "$OUT/mac.sig"
cp "$T/x86_64-pc-windows-gnu/release/bundle/nsis/"*"_${V}_x64-setup.exe" "$OUT/AmnezinuVPN_${V}_windows_x64-setup.exe"
cp "$T/x86_64-pc-windows-gnu/release/bundle/nsis/"*"_${V}_x64-setup.exe.sig" "$OUT/win.sig"

python3 - "$OUT" "$V" "$REPO" "$NOTES" <<'PY'
import datetime, json, sys
out, v, repo, notes = sys.argv[1:]
url = f"https://github.com/{repo}/releases/download/v{v}/"
mac = {"signature": open(f"{out}/mac.sig").read(), "url": url + f"AmnezinuVPN_{v}_macos_universal.app.tar.gz"}
latest = {
    "version": v,
    # the first section of the notes (before the first "## " after it) is shown in the app
    "notes": open(notes).read().split("\n## ")[0].strip(),
    "pub_date": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "platforms": {
        "darwin-aarch64": mac, "darwin-x86_64": mac,
        "windows-x86_64": {"signature": open(f"{out}/win.sig").read(), "url": url + f"AmnezinuVPN_{v}_windows_x64-setup.exe"},
    },
}
json.dump(latest, open(f"{out}/latest.json", "w"), ensure_ascii=False, indent=2)
PY
rm "$OUT/mac.sig" "$OUT/win.sig"
(cd "$OUT" && shasum -a 256 *.dmg *.tar.gz *.exe > SHA256SUMS.txt)

gh release create "v$V" -R $REPO --target "$COMMIT" --title "АМнеЗинуVPN $V" --notes-file "$NOTES" "$OUT"/*

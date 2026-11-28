#!/bin/sh
# Builds dist/panic-button-<version>.dmg: the app (PyInstaller, unsigned) and an Applications shortcut.
set -eu
cd "$(dirname "$0")/.."
ROOT=$(pwd)
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' pyproject.toml)
WORK="$ROOT/dist/build"
rm -rf "$WORK" "$ROOT/dist/app"
mkdir -p "$WORK"

ICON=""
if command -v sips >/dev/null && command -v iconutil >/dev/null; then
  SET="$WORK/icon.iconset"
  mkdir -p "$SET"
  sips -s format png -z 1024 1024 panic/app/web/icon.svg --out "$WORK/icon.png" >/dev/null
  for s in 16 32 128 256 512; do
    sips -z $s $s "$WORK/icon.png" --out "$SET/icon_${s}x${s}.png" >/dev/null
    sips -z $((s * 2)) $((s * 2)) "$WORK/icon.png" --out "$SET/icon_${s}x${s}@2x.png" >/dev/null
  done
  iconutil -c icns "$SET" -o "$WORK/icon.icns"
  ICON="--icon=$WORK/icon.icns"
fi

uv sync --group app --quiet
uv run --group app pyinstaller --noconfirm --clean --windowed --log-level WARN \
  --name "panic button" --osx-bundle-identifier com.panicbutton.app ${ICON:+"$ICON"} \
  --add-data "$ROOT/panic/app/web:panic/app/web" \
  --add-data "$ROOT/panic/guided_services.json:panic" \
  --add-data "$ROOT/panic/oauth_clients.json:panic" \
  --collect-submodules panic --collect-data googleapiclient \
  --hidden-import keyring.backends.macOS \
  --distpath "$ROOT/dist/app" --workpath "$WORK" --specpath "$WORK" \
  "$ROOT/panic/app/__main__.py"

STAGE="$WORK/dmg"
mkdir -p "$STAGE"
cp -R "$ROOT/dist/app/panic button.app" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
DMG="$ROOT/dist/panic-button-$VERSION.dmg"
hdiutil create -volname "panic button" -srcfolder "$STAGE" -ov -format UDZO "$DMG" >/dev/null
echo "$DMG"

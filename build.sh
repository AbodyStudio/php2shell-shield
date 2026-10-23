#!/usr/bin/env bash
# Build an installable WordPress plugin zip for PHP2Shell Shield.
# Usage: ./build.sh   (reads the version from the plugin header)
set -euo pipefail

cd "$(dirname "$0")"
SLUG="php2shell-shield"
VERSION=$(grep -m1 "Version:" "${SLUG}.php" | sed -E 's/.*Version:[[:space:]]*([0-9.]+).*/\1/')
OUT="dist/${SLUG}-v${VERSION}.zip"

mkdir -p dist
rm -f "$OUT"

# Stage into a folder named exactly after the slug (WordPress requires this).
TMP=$(mktemp -d)
DEST="$TMP/$SLUG"
mkdir -p "$DEST"

# Copy only shipping files.
cp -R \
  "${SLUG}.php" \
  uninstall.php \
  readme.txt \
  index.php \
  includes \
  admin \
  assets \
  packs \
  "$DEST/" 2>/dev/null || true

# Drop dev-only files from the staged copy.
rm -f "$DEST/assets/banner.png.license" 2>/dev/null || true

( cd "$TMP" && zip -rq "$OLDPWD/$OUT" "$SLUG" -x '*.DS_Store' )
rm -rf "$TMP"

echo "Built $OUT"

# Sign the zip for the GitHub auto-updater (detached RSA-SHA256, single-line
# base64) when the private key is present. The matching "<zip>.sig" is attached
# to the GitHub release; the plugin verifies it before installing an update.
KEY="keys/p2s-private.pem"
if [ -f "$KEY" ]; then
  openssl dgst -sha256 -sign "$KEY" "$OUT" | openssl base64 -A > "$OUT.sig"
  echo "Signed  $OUT.sig"
else
  echo "NOTE: $KEY not found — zip not signed (auto-update verification needs the .sig)."
fi

unzip -l "$OUT" | awk 'NR>3 && $4 {print "  "$4}' | grep -v '^\s*$' | sed '/^  -*$/d;/Archive/d' || true

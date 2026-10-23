#!/usr/bin/env bash
# Build an installable WordPress plugin zip for PHP2Shell Shield.
#
#   ./build.sh           GitHub build (includes the signed self-updater; signs the zip)
#   ./build.sh dotorg    WordPress.org build (omits the self-updater; no signature)
#
set -euo pipefail

cd "$(dirname "$0")"
SLUG="php2shell-shield"
MODE="${1:-github}"
VERSION=$(grep -m1 "Version:" "${SLUG}.php" | sed -E 's/.*Version:[[:space:]]*([0-9.]+).*/\1/')

OUT="dist/${SLUG}-v${VERSION}.zip"
if [ "$MODE" = "dotorg" ]; then
  OUT="dist/${SLUG}-v${VERSION}-wporg.zip"
fi

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

# WordPress.org build: remove the GitHub self-updater (not permitted on .org;
# updates come from WordPress.org). The main file loads it only if present.
if [ "$MODE" = "dotorg" ]; then
  rm -f "$DEST/includes/class-updater.php"
fi

( cd "$TMP" && zip -rq "$OLDPWD/$OUT" "$SLUG" -x '*.DS_Store' )
rm -rf "$TMP"

echo "Built $OUT ($MODE)"

# Sign the GitHub build so its self-updater can verify downloads. The .org build
# is served by WordPress.org and needs no signature.
KEY="keys/p2s-private.pem"
if [ "$MODE" != "dotorg" ]; then
  if [ -f "$KEY" ]; then
    openssl dgst -sha256 -sign "$KEY" "$OUT" | openssl base64 -A > "$OUT.sig"
    echo "Signed  $OUT.sig"
  else
    echo "NOTE: $KEY not found — zip not signed (auto-update verification needs the .sig)."
  fi
fi

unzip -l "$OUT" | awk 'NR>3 && $4 {print "  "$4}' | grep -v '^\s*$' | sed '/^  -*$/d;/Archive/d' || true

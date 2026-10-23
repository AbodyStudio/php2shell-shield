#!/usr/bin/env bash
# Generate the PHP2Shell Shield rule-pack signing keypair.
#
#   keys/p2s-private.pem   -> STAYS OFFLINE. Never commit. Never ship.
#   packs/signing-key.pub  -> ships inside the plugin; verifies packs.
#
# Regenerating the keypair means you must re-sign every pack and ship the
# new public key in a plugin update, or existing packs will stop verifying.
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p keys packs
if [ -f keys/p2s-private.pem ]; then
  echo "keys/p2s-private.pem already exists. Refusing to overwrite."
  echo "Delete it yourself if you really mean to rotate the key."
  exit 1
fi

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out keys/p2s-private.pem
chmod 600 keys/p2s-private.pem
openssl rsa -in keys/p2s-private.pem -pubout -out packs/signing-key.pub

echo "Wrote keys/p2s-private.pem (keep offline) and packs/signing-key.pub (ships)."
echo "Now sign your packs:  php tools/sign-pack.php packs/<id>.pack.json keys/p2s-private.pem"

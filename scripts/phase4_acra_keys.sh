#!/usr/bin/env bash
# Phase 4: generate the Acra keystore for transparent encryption.
#
# Why this is a script and not a bind mount:
#   - Acra requires the keystore dir to be chmod 700. WSL2 bind mounts from the Windows
#     filesystem are stuck at 0777, which Acra rejects (see problem.md #2). So keys live
#     in a Docker named volume, prepared by a busybox helper.
#   - The Acra images are distroless (no shell), so all key ops run via separate
#     short-lived containers.
#
# Output: storage keys land in the acra_keys volume; the base64 master key is written
# into .env as ACRA_MASTER_KEY (consumed by acra-server via compose).
#
# Run from the project root:
#   bash scripts/phase4_acra_keys.sh

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

VOLUME="database-security_acra_keys"
KEYMAKER="cossacklabs/acra-keymaker:0.96.0"
BUSYBOX="busybox:1.37"
CLIENT_ID="dbsec_client"

echo "== 1. Ensure acra_keys volume exists and is chmod 700 =="
docker volume create "$VOLUME" >/dev/null
# Acra requires keys_dir to be 0700 *before* it touches the keystore.
docker run --rm -v "$VOLUME:/keys" "$BUSYBOX" chmod 700 /keys
echo "volume: $VOLUME (chmod 700)"

echo
echo "== 2. Generate master key and base64-encode it =="
# acra-keymaker writes the RAW key bytes to the file; ACRA_MASTER_KEY must be the
# base64 encoding of those bytes (see problem.md #6).
docker run --rm -v "$VOLUME:/keys" "$KEYMAKER" --keystore=v1 --generate_master_key=/keys/master.key
MASTER="$(docker run --rm -v "$VOLUME:/keys" "$BUSYBOX" sh -c "base64 /keys/master.key | tr -d '\n'")"
if [ -z "$MASTER" ]; then
  echo "[FATAL] master key generation produced empty output" >&2
  exit 1
fi
echo "master key generated (${#MASTER} chars base64)"

echo
echo "== 3. Generate storage keys for client_id=$CLIENT_ID (keystore v1) =="
docker run --rm -e ACRA_MASTER_KEY="$MASTER" -v "$VOLUME:/keys" "$KEYMAKER" \
  --client_id="$CLIENT_ID" \
  --keys_output_dir=/keys \
  --keys_public_output_dir=/keys \
  --keystore=v1

echo
echo "== 4. Lock down keystore perms and remove master key file =="
# acra-server wants directories at 0700 and private key FILES at 0600.
docker run --rm -v "$VOLUME:/keys" "$BUSYBOX" sh -c \
  "rm -f /keys/master.key && find /keys -type d -exec chmod 700 {} + && find /keys -type f -exec chmod 600 {} + && ls -laR /keys"

echo
echo "== 5. Persist ACRA_MASTER_KEY into .env =="
# Remove any existing line, then append the fresh key.
if grep -q '^ACRA_MASTER_KEY=' .env 2>/dev/null; then
  grep -v '^ACRA_MASTER_KEY=' .env > .env.tmp && mv .env.tmp .env
fi
printf 'ACRA_MASTER_KEY=%s\n' "$MASTER" >> .env
echo "ACRA_MASTER_KEY written to .env"

echo
echo "Acra keystore ready. Now (re)create acra-server:  docker compose up -d acra-server"

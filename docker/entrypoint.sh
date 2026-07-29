#!/bin/sh
set -euo pipefail

SIGNING_KEY_DIR=$(dirname "$SSSO_SIGNING_KEY_PATH")
if [ ! -f "$SSSO_SIGNING_KEY_PATH" ]; then
    echo "[entrypoint] Generating RSA signing key at $SSSO_SIGNING_KEY_PATH..."
    mkdir -p "$SIGNING_KEY_DIR"
    openssl genrsa -out "$SSSO_SIGNING_KEY_PATH" 2048
    echo "[entrypoint] RSA signing key generated successfully."
else
    echo "[entrypoint] RSA signing key already exists at $SSSO_SIGNING_KEY_PATH — skipping generation."
fi

exec ssso "$@"

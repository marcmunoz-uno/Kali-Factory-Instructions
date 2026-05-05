#!/usr/bin/env bash
# Generate and permission-lock the bearer token. Idempotent — refuses to
# overwrite an existing token file unless --force is passed.

set -euo pipefail

cd "$(dirname "$0")/.."
SECRETS_DIR=".secrets"
TOKEN_FILE="$SECRETS_DIR/api_token"

mkdir -p "$SECRETS_DIR"
chmod 0700 "$SECRETS_DIR"

if [[ -f "$TOKEN_FILE" && "${1:-}" != "--force" ]]; then
    echo "Token already exists at $TOKEN_FILE"
    echo "Pass --force to regenerate (will invalidate existing clients)."
    exit 0
fi

# 48 chars of url-safe base64 = ~36 bytes of entropy. Plenty.
python3 -c "import secrets; print(secrets.token_urlsafe(48))" > "$TOKEN_FILE"
chmod 0600 "$TOKEN_FILE"

echo "Bearer token written to $TOKEN_FILE"
echo "  size: $(wc -c < "$TOKEN_FILE") bytes"
echo "  perms: $(stat -c '%a' "$TOKEN_FILE" 2>/dev/null || stat -f '%Lp' "$TOKEN_FILE")"
echo
echo "Add to your .env:"
echo "  KALI_FACTORY_API_TOKEN_FILE=$(realpath "$TOKEN_FILE" 2>/dev/null || echo "$PWD/$TOKEN_FILE")"

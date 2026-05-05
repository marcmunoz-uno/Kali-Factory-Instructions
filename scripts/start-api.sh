#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ -f .env ]]; then
    set -a; source .env; set +a
fi

if [[ -z "${KALI_FACTORY_API_TOKEN_FILE:-}" ]]; then
    echo "KALI_FACTORY_API_TOKEN_FILE not set. Source .env or run scripts/bootstrap-secrets.sh."
    exit 1
fi

exec python3 -m kali_factory.api.main

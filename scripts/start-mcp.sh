#!/usr/bin/env bash
# MCP server — meant to be spawned by an MCP client over stdio, NOT a service.
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ -f .env ]]; then
    set -a; source .env; set +a
fi

exec python3 -m kali_factory.mcp.server

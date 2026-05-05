#!/usr/bin/env bash
# Install user-level systemd units for the API + worker on Linux hosts.
# macOS users: ignore this; use launchd or just keep the processes in tmux.

set -euo pipefail
cd "$(dirname "$0")/.."

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "user services are Linux-only; skipping (host: $(uname -s))"
    exit 0
fi

REPO_ROOT="$(realpath "$PWD")"
UNIT_DIR="$HOME/.config/systemd/user"
mkdir -p "$UNIT_DIR"

for tmpl in api worker; do
    src="systemd/kali-factory-${tmpl}.service.template"
    dst="$UNIT_DIR/kali-factory-${tmpl}.service"
    if [[ ! -f "$src" ]]; then
        echo "missing template: $src"; exit 1
    fi
    sed "s|{{REPO_ROOT}}|$REPO_ROOT|g" "$src" > "$dst"
    echo "installed $dst"
done

systemctl --user daemon-reload
echo
echo "Enable + start with:"
echo "  systemctl --user enable --now kali-factory-api.service"
echo "  systemctl --user enable --now kali-factory-worker.service"
echo
echo "Logs:"
echo "  journalctl --user -u kali-factory-api -f"
echo "  journalctl --user -u kali-factory-worker -f"

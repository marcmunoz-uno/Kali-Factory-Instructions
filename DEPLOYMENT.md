# Deployment

This guide covers running Kali Factory on the same DGX Spark (or comparable Linux host) that already runs GPU Factory. The two services coexist on non-overlapping ports.

## Prerequisites

- Linux x86_64 or ARM64 (Ubuntu 22.04+ tested)
- Docker 24+
- Docker can run rootless containers with `--cap-drop=ALL`
- Python 3.11+
- Redis (via `docker compose up -d redis`)
- ~2 GB free disk for the Kali runtime image
- Network egress allowed from the host (the container needs to reach OSINT targets)

## First-time install

```bash
git clone https://github.com/marcmunoz-uno/Kali-Factory-Instructions.git
cd Kali-Factory-Instructions

# Generate bearer token
./scripts/bootstrap-secrets.sh

# Wire env
cp .env.example .env
# Edit .env to point KALI_FACTORY_API_TOKEN_FILE at the absolute path of .secrets/api_token

# Build the runtime image
docker build -t kali-factory/recon:latest runtimes/kali/

# Python env
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# Start Redis sidecar
docker compose up -d redis
```

## Running

Manually (foreground, for testing):

```bash
# Terminal 1
./scripts/start-api.sh

# Terminal 2
./scripts/start-worker.sh
```

As user-level systemd services (Linux):

```bash
./scripts/install-user-services.sh
systemctl --user enable --now kali-factory-api.service
systemctl --user enable --now kali-factory-worker.service
```

Tail logs:

```bash
journalctl --user -u kali-factory-api -f
journalctl --user -u kali-factory-worker -f
```

## Coexistence with GPU Factory

| Service | Port | Notes |
|---|---|---|
| GPU Factory API | 8080 | uvicorn, persistent service |
| Kali Factory API | 8081 | uvicorn, persistent service |
| Redis | 6379 | shared between Factories — different DBs (`/0` for GPU, `/1` for Kali) |

If you want to fully isolate, change `KALI_FACTORY_REDIS_URL` to `redis://localhost:6379/1` (default DB index 0 collides with GPU Factory).

## Putting it behind Tailscale / Caddy

The API binds `127.0.0.1:8081` by default. To expose it to a Tailnet:

```bash
# In .env
KALI_FACTORY_API_HOST=100.x.y.z   # your Tailscale IP
```

Or front it with Caddy with a stricter ACL if you want HTTPS + access logging.

## Verify

```bash
# Health
curl http://localhost:8081/health

# List allowlisted tools
curl http://localhost:8081/tools

# Submit a kali_probe job (no token required for /tools, required for /jobs)
TOKEN=$(cat .secrets/api_token)
curl -X POST http://localhost:8081/jobs \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"type":"kali_probe"}'

# Poll for result
JOB_ID=...   # from previous response
curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/jobs/$JOB_ID
```

## Hardening checklist

- [ ] Bearer token regenerated and rotated regularly
- [ ] API behind Tailscale / VPN, not exposed publicly
- [ ] Audit log written to file or SQLite (TODO in v0.0.2)
- [ ] Per-tool rate limits enforced
- [ ] Per-target allowlist (only recon domains you own / have authorization for)
- [ ] Disk-space monitoring on the host (mitmproxy captures and trufflehog
      output can grow fast)
- [ ] Container egress logged at the network layer (iptables NFLOG or eBPF)

## Uninstall

```bash
systemctl --user disable --now kali-factory-api kali-factory-worker
rm -f ~/.config/systemd/user/kali-factory-*.service
docker compose down
docker rmi kali-factory/recon:latest
```

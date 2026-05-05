# Kali Factory Instructions

Safer host-local control plane for AI agents that need access to Kali Linux OSINT tooling.

This package mirrors the GPU Factory shape — typed job submission with bearer auth, queued worker execution, allowlisted Docker image runs — but applied to a different problem: distributing access to Kali's reconnaissance and traffic-analysis tooling without giving agents an unauthenticated shell.

- FastAPI control API
- Redis queue
- RQ worker
- Docker-first container execution against a hardened Kali image
- Typed jobs (osint, traffic capture, JS analysis, leak hunting) instead of raw shell
- Bearer token auth
- Local MCP server for MCP-capable agents
- Optional ChromaDB sidecar for retaining recon findings across runs

## Why This Exists

Kali ships hundreds of tools, many of which are useful for legitimate competitive intelligence and security research, and some of which are not appropriate for agent-driven automation. The naïve approach — drop an agent into a Kali shell and let it figure things out — produces three problems:

1. The agent has access to *every* tool, including exploitation frameworks (`metasploit`, `sqlmap`, `hashcat`, `john`, `aircrack-ng`, `exploitdb`) that should never be reachable from an automation context.
2. Tool invocations are unstructured shell strings, which is both prone to argument-injection bugs and impossible to audit cleanly.
3. There is no rate-limit, time-limit, or output-budget on what the agent can do — a single misbehaving agent can hammer a target or fill the disk.

This package solves all three by exposing Kali through a typed-job API where every callable tool is declared in a manifest, every argument is validated by Pydantic, every container run is allowlisted by image prefix, and every call requires a bearer token.

## Core Safety Properties

- No `shell=True`
- No generic "run whatever command" endpoint
- Jobs are validated with explicit schemas
- Container execution is allowlisted by image prefix
- Tool execution inside the container is allowlisted by binary name
- API requires a bearer token
- Worker and API are separate processes
- Exploitation/credential-cracking/wireless tools explicitly purged at image build
- Egress logging on every tool that touches the network

## Job Types

- `kali_probe`
  - validates the Kali container is reachable and the tool allowlist is intact
- `osint_run`
  - executes a typed OSINT tool from the allowlist (amass, whatweb, gobuster, dnsenum, etc.) with structured args
- `traffic_capture`
  - runs `mitmdump` for a bounded duration, returns a capture file
- `js_analysis`
  - runs `linkfinder` / `secretfinder` / `arjun` against a JavaScript URL
- `leak_scan`
  - runs `trufflehog` against a GitHub org / repo for committed credentials
- `subdomain_enum`
  - runs `amass enum` (passive sources only) against a target domain
- `web_fingerprint`
  - runs `whatweb` to identify a target's tech stack
- `nuclei_exposures`
  - runs `nuclei` against a target with the `exposures/` template subset only
  - `cves/`, `vulnerabilities/`, `default-logins/`, `fuzzing/` template directories are explicitly blocked

## Quick Start

1. Copy environment variables:

```bash
cp .env.example .env
./scripts/bootstrap-secrets.sh
```

2. The API token is stored in:

```text
.secrets/api_token
```

and `.env` points at it through `KALI_FACTORY_API_TOKEN_FILE`.

3. Start Redis:

```bash
docker compose up -d redis
```

4. Build the Kali runtime image:

```bash
docker build -t kali-factory/recon:latest runtimes/kali/
```

5. Create the Python env:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

6. Run the API:

```bash
./scripts/start-api.sh
```

7. Run the worker:

```bash
./scripts/start-worker.sh
```

8. Run the MCP server:

```bash
./scripts/start-mcp.sh
```

## Example Requests

Health:

```bash
curl http://localhost:8081/health
```

Kali probe:

```bash
curl -X POST http://localhost:8081/jobs \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"type":"kali_probe"}'
```

Subdomain enumeration:

```bash
curl -X POST http://localhost:8081/jobs \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type":"subdomain_enum",
    "domain":"example.com",
    "max_runtime_sec": 300
  }'
```

Web fingerprint:

```bash
curl -X POST http://localhost:8081/jobs \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type":"web_fingerprint",
    "url":"https://example.com"
  }'
```

GitHub leak scan:

```bash
curl -X POST http://localhost:8081/jobs \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type":"leak_scan",
    "github_org":"example-org"
  }'
```

## Files

- `START_HERE_FOR_AGENTS.md` — single-entrypoint guide for agents using this control plane
- `runtimes/kali/Dockerfile` — Kali container image with the allowlisted tools installed
- `runtimes/kali/tools.json` — declarative tool manifest (allowlist + arg templates)
- `scripts/bootstrap-secrets.sh` — create and permission-lock the API token file
- `scripts/start-api.sh` — launch wrapper for the API
- `scripts/start-worker.sh` — launch wrapper for the worker
- `scripts/start-mcp.sh` — launch wrapper for the local MCP server
- `scripts/install-user-services.sh` — install user-level systemd units
- `src/kali_factory/api/` — API server (FastAPI)
- `src/kali_factory/worker/` — RQ-based job execution
- `src/kali_factory/models/` — Pydantic job schemas
- `src/kali_factory/jobs/` — per-job-type handlers
- `src/kali_factory/policy/` — auth, allowlist enforcement, rate limiting
- `src/kali_factory/mcp/server.py` — stdio MCP adapter over the local Kali Factory API
- `compose.yaml` — Redis (and optional ChromaDB) sidecars
- `Dockerfile` — app container for API/worker
- `.env.example` — required settings
- `DEPLOYMENT.md` — host-specific run and service guidance

## Recommended Next Hardening

- Put the API behind Tailscale, Caddy, or another internal-only gateway
- Rotate API tokens
- Add audit logging to a file or SQLite
- Add explicit job quotas and per-tool rate limits
- Add per-target allowlist (only let agents recon domains you own or have authorization to test)
- Wire egress logging on the Kali container so every outbound request is captured

## Service Model

- `kali-factory-api.service` should run persistently
- `kali-factory-worker.service` should run persistently
- the MCP server should **not** run as a persistent service
- MCP clients should spawn `scripts/start-mcp.sh` on demand over stdio

## Relationship to Other Factory Packages

| Factory | Distributes | Job examples |
|---|---|---|
| GPU Factory | CUDA / GPU compute | `gpu_probe`, `run_container --gpus all`, `python_probe` |
| Kali Factory | OSINT / recon tooling | `subdomain_enum`, `web_fingerprint`, `leak_scan`, `nuclei_exposures` |

The two packages share the same architectural shape (FastAPI + Redis + RQ + bearer auth + typed jobs + allowlisted Docker exec) and are designed to coexist on the same host with non-overlapping ports (`8080` for GPU Factory, `8081` for Kali Factory).

A future `parallel-OS` orchestrator can route agent requests to whichever Factory matches the runtime they need.

## What Kali Factory Is Not

- **Not a vulnerability scanner.** `nuclei` is included but limited to `exposures/` templates. CVE / exploit / default-login / fuzzing templates are explicitly blocked.
- **Not an exploitation framework.** Metasploit, sqlmap, hashcat, john, aircrack-ng, exploitdb, hydra, medusa, ncrack, nikto, wpscan, responder, impacket, crackmapexec are all purged from the runtime image at build time.
- **Not an unauthorized testing tool.** Use only against targets you own or have explicit authorization to test. The API logs every job; misuse is your responsibility.

## License

Apache 2.0 (see `LICENSE`).

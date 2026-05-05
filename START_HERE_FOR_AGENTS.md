# Start Here — Agent's Guide to Kali Factory

You're an agent that wants to run Kali OSINT tooling. You want results, not a shell. This package gives you typed jobs over a local API.

## The contract

1. **You don't get a shell.** You submit typed jobs to the API.
2. **Every job is bounded.** Time limits, output size limits, image allowlist, tool allowlist.
3. **Every call needs a bearer token.** The token is in `.secrets/api_token` on the host running the Factory.
4. **Forbidden tools will be rejected.** Even if you guess the right HTTP shape, the worker re-validates against the allowlist.

## Available jobs

| Job type | What it does | Typical use |
|---|---|---|
| `kali_probe` | Validate the runtime is healthy | Sanity check before a recon run |
| `subdomain_enum` | Passive amass enumeration | Find a target's full domain footprint |
| `web_fingerprint` | whatweb against a single URL | Identify a site's tech stack |
| `leak_scan` | trufflehog against a GitHub org | Find committed credentials in public repos |
| `nuclei_exposures` | nuclei with `exposures/` templates only | Find leaked swagger.json, .git/, etc. |
| `traffic_capture` *(v0.0.2)* | mitmdump for a bounded window | Capture API calls a browser session makes |
| `osint_run` *(v0.0.2)* | Generic typed-tool dispatch | Call any allowlisted manifest tool |

## What is NEVER allowed

These will be rejected at the API and again at the worker, even if you craft a valid payload:

- `metasploit`, `msfvenom`, `msfconsole`
- `sqlmap`
- `hashcat`, `john`
- `aircrack-ng`, `airmon-ng`
- `hydra`, `medusa`, `ncrack`
- `nikto`, `wpscan`
- `responder`, `crackmapexec`
- `nuclei` with `cves/`, `vulnerabilities/`, `default-logins/`, `fuzzing/`, or `exploits/` template directories
- Arbitrary shell — there is no "run this command" endpoint

## Workflow

1. Read `/tools` to discover what's available.
2. Submit a job to `POST /jobs` with the right `type` and args. Get back a `job_id`.
3. Poll `GET /jobs/{job_id}` until status is `finished`, `failed`, `timed_out`, or `rejected`.
4. Read `output_summary` for the structured result.

## Example

```python
import requests, time

BASE = "http://localhost:8081"
TOKEN = open("/path/to/.secrets/api_token").read().strip()
H = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}

# Submit
r = requests.post(f"{BASE}/jobs", headers=H, json={
    "type": "subdomain_enum",
    "domain": "example.com",
    "passive_only": True,
    "max_runtime_sec": 300,
})
job_id = r.json()["job_id"]

# Poll
while True:
    r = requests.get(f"{BASE}/jobs/{job_id}", headers=H)
    result = r.json()
    if result["status"] in ("finished", "failed", "timed_out", "rejected"):
        break
    time.sleep(2)

print(result["output_summary"])
# {"domain": "example.com", "count": 42, "subdomains": [...]}
```

## If you're MCP-native

Run `scripts/start-mcp.sh` over stdio. The MCP server exposes the same job types as MCP tools and handles polling for you.

## When something fails

- `status: rejected` — your payload violated an allowlist (image, tool, template). Read `error` for the specific constraint.
- `status: failed` — the tool ran but exited non-zero. Read `error` for stderr (truncated to 500 chars).
- `status: timed_out` — the job exceeded `max_runtime_sec`. Increase it or narrow the scope.

## Don't do this

- Don't submit recon jobs against targets you don't own or have explicit authorization to test.
- Don't try to bypass the allowlist by guessing image names or tool names. The worker rejects unknown ones.
- Don't pile up jobs. Respect concurrency limits (default: 5 active jobs per agent).
- Don't store the bearer token in plaintext anywhere checked into git.

# Network Scan CLI (Containerized)

English is the primary documentation language.  
For a Russian version with extra operational recommendations, see [README.ru.md](README.ru.md).

Reproducible CLI pipeline for scanning large networks:
- input: `CIDR + IP + FQDN`
- stages: `resolve -> discovery -> fast ports -> Nmap NSE`
- output: `JSON/JSONL/CSV` + `Markdown/HTML` summary

## What It Implements

- Input contract with validation and normalization.
- Speed profiles: `safe`, `balanced`, `fast`.
- DNS resolve for FQDN via `dnsx`.
- Host discovery and fast TCP port scan via `naabu`.
- Enrichment with Nmap `-sV`, OS detection (`-O`) and NSE profiles (incl. `vuln`).
- Parallel NSE/OS stage (configurable `nse_concurrency`) for faster large scans.
- Retry + timeout handling per external command (with a separate per-host `nse_timeout_seconds`).
- Checkpoint/resume support.
- Report exports with summary, parsed Nmap service data, OS matches and vulnerability findings.

## Project Layout

- `Dockerfile`
- `docker-compose.yml`
- `scanner/config/default.yaml`
- `scanner/inputs/{ranges.txt,domains.txt,ports.txt}`
- `scanner/main.py`
- `scanner/pipeline/*`
- `scanner/output/*` (generated)
- `scanner/state/checkpoint.json` (generated)

## Input Contract

### `scanner/inputs/ranges.txt`

One target per line:
- CIDR (`10.0.0.0/16`)
- single IP (`10.0.1.10`, `2001:db8::1`)

### `scanner/inputs/domains.txt`

One FQDN per line:
- `api.example.com`
- `db01.corp.local`

### `scanner/inputs/ports.txt` (optional)

Custom port selectors (one per line).  
If empty, `top-ports` from selected profile are used.

Examples:
- `22`
- `80,443,8443`
- `1-1024`

Invalid lines are written to `scanner/output/normalized/contract_validation.json`.

## Usage

### 1) Build

```bash
docker compose build
```

### 2) Prepare targets

Edit:
- `scanner/inputs/ranges.txt`
- `scanner/inputs/domains.txt`
- optional `scanner/inputs/ports.txt`

### 3) Run standard scan

```bash
docker compose run --rm scanner --config scanner/config/default.yaml --mode balanced
```

### 4) Resume after interruption

```bash
docker compose run --rm scanner --config scanner/config/default.yaml --mode balanced --resume
```

## Validation Helpers

- `scripts/smoke.sh`:
  - compiles Python sources;
  - runs pipeline with current input files.
- `scripts/load-test.sh <cidr>`:
  - writes a temporary CIDR target;
  - runs `fast` profile in container.

## Tests

Unit tests cover the pure helpers (input validation, port grouping, custom port parsing):

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

## Profiles

- `safe`: lower packet rate, `top-100`, conservative timing, `baseline` NSE (no `vuln`), `nse_concurrency: 2`.
- `balanced`: default profile, `top-1000`, `vuln` NSE + OS detection, `nse_concurrency: 4`.
- `fast`: higher discovery/scan rate, `top-1000`, `vuln` NSE + OS detection, `nse_concurrency: 8`.

### Vulnerability checking

The NSE stage performs CVE/vulnerability checks driven by `nse_profiles`:

- `vuln`: Nmap `vuln` category **plus** `vulners` — maps detected service versions (`-sV`) to CVEs via the vulners.com API. Wired to `balanced`/`fast`. **Requires outbound internet** for the vulners lookups.
- `vuln-offline`: Nmap `vuln` category **plus** `vulscan` — offline CVE matching against bundled local databases (no internet). Select with `--mode` after setting it as a profile's `nse_profile`, or edit the profile.
- `baseline`: non-intrusive `default,safe` only (used by `safe`).

The `nmap-vulners` and `vulscan` scripts are installed into the image at build time
(see `Dockerfile`; pin via `NMAP_VULNERS_REF` / `VULSCAN_REF` build args).

Findings are parsed into structured results: each `CVE` gets a `cvss` score and a derived
`severity` (`critical >= 9.0`, `high >= 7.0`, `medium >= 4.0`, `low > 0`, else `unknown`).
Scripts reporting `State: VULNERABLE` without a CVE are also captured (severity `unknown`).

Tune profile parameters in `scanner/config/default.yaml`.

### NSE / OS detection

- `nse_profiles.<name>.scripts`: Nmap `--script` selector (e.g. `default,safe,vuln`).
- `nse_profiles.<name>.os_detection`: enables `nmap -O --osscan-guess`.
- `runtime.nse_concurrency` / `profiles.<name>.nse_concurrency`: number of nmap processes run in parallel.
- `runtime.nse_max_rate` / `profiles.<name>.nse_max_rate`: global packets/sec budget for the NSE/OS stage. It is split across the parallel nmap processes (each gets `nse_max_rate / nse_concurrency` via `nmap --max-rate`). `0` means unlimited (rely on the timing template). This keeps aggregate scan noise bounded regardless of concurrency.
- `runtime.nse_timeout_seconds`: per-host nmap timeout (independent of the global command timeout).

OS detection and SYN/ICMP probing require raw sockets. The container is granted
`NET_RAW`/`NET_ADMIN` via `docker-compose.yml`; outside compose run with equivalent capabilities.

## Output Artifacts

- `scanner/output/normalized/ip_targets.txt`
- `scanner/output/normalized/fqdn_targets.txt`
- `scanner/output/resolved_ips.txt`
- `scanner/output/all_targets.txt`
- `scanner/output/alive_ips.txt`
- `scanner/output/open_ports.txt`
- `scanner/output/nse_targets.txt`
- `scanner/output/nmap/*` (`.nmap`, `.gnmap`, `.xml`)
- `scanner/output/findings.{json,jsonl,csv}`
- `scanner/output/os_findings.json` (parsed Nmap OS matches)
- `scanner/output/script_findings.json` (all NSE script output)
- `scanner/output/vulnerabilities.json` (structured CVE findings with `cvss`/`severity`, severity-ranked)
- `scanner/output/vulnerabilities.csv` (same findings, flat CSV)
- `scanner/output/summary.{json,md,html}` (includes severity breakdown)
- `scanner/output/logs/pipeline.log`

## Notes

- Use only in environments where you are authorized to scan.
- Prefer running from a Linux host/network where raw scanning is allowed.
- High-rate profiles can trigger IDS/IPS and impact network stability.
- If `docker compose build` fails with Docker socket errors, start Docker daemon/Desktop first.

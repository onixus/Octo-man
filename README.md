# Network Scan CLI (Containerized)

Reproducible CLI pipeline for scanning large networks:
- input: `CIDR + IP + FQDN`
- stages: resolve -> discovery -> fast ports -> Nmap NSE
- output: JSON/JSONL/CSV + Markdown/HTML summary

## What It Implements

- Input contract with validation and normalization.
- Speed profiles: `safe`, `balanced`, `fast`.
- DNS resolve for FQDN (`dnsx`).
- Host discovery and fast TCP port scan (`naabu`).
- Enrichment with Nmap `-sV` and NSE profiles.
- Retry + timeout handling per command.
- Checkpoint/resume support.
- Report exports with summary and parsed Nmap services.

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

Supports one target per line:
- CIDR (`10.0.0.0/16`)
- single IP (`10.0.1.10`, `2001:db8::1`)

### `scanner/inputs/domains.txt`

One FQDN per line:
- `api.example.com`
- `db01.corp.local`

### `scanner/inputs/ports.txt` (optional)

Custom port selectors (one per line). If empty, `top-ports` from profile is used.
Examples:
- `22`
- `80,443,8443`
- `1-1024`

Invalid lines are collected in `scanner/output/normalized/contract_validation.json`.

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

## Validation helpers

- `scripts/smoke.sh`:
  - compiles Python sources
  - runs pipeline with current inputs
- `scripts/load-test.sh <cidr>`:
  - writes a temporary CIDR target
  - runs the `fast` profile in container

## Modes

- `safe`: lower packet rate, `top-100`, conservative timing
- `balanced`: default, `top-1000`
- `fast`: high-rate discovery/scan, `top-1000`

Tune in `scanner/config/default.yaml`.

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
- `scanner/output/summary.{json,md,html}`
- `scanner/output/logs/pipeline.log`

## Notes

- Intended for authorized environments only.
- Run from Linux host/network where raw scanning is permitted.
- High-rate profiles can trigger IDS/IPS and impact network stability.
- If `docker compose build` fails with Docker socket errors, start Docker daemon/Desktop first.

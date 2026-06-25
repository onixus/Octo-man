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
- Enrichment with Nmap `-sV` and NSE profiles.
- Retry + timeout handling per external command.
- Checkpoint/resume support.
- Report exports with summary and parsed Nmap service data.

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

## Profiles

- `safe`: lower packet rate, `top-100`, conservative timing.
- `balanced`: default profile, `top-1000`.
- `fast`: higher discovery/scan rate, `top-1000`.

Tune profile parameters in `scanner/config/default.yaml`.

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

- Use only in environments where you are authorized to scan.
- Prefer running from a Linux host/network where raw scanning is allowed.
- High-rate profiles can trigger IDS/IPS and impact network stability.
- If `docker compose build` fails with Docker socket errors, start Docker daemon/Desktop first.

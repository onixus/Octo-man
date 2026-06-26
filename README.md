# Network Scan CLI (Containerized)

[![CI](https://github.com/onixus/Octo-man/actions/workflows/ci.yml/badge.svg)](https://github.com/onixus/Octo-man/actions/workflows/ci.yml)

English is the primary documentation language.  
For a Russian version with extra operational recommendations, see [README.ru.md](README.ru.md).

Reproducible CLI pipeline for scanning large networks:
- input: `CIDR + IP + FQDN`
- stages: `resolve -> discovery -> fast ports -> Nmap NSE (service/OS detection + vuln/CVE)`
- output: `JSON/JSONL/CSV` + `Markdown/HTML` summary

## What It Implements

- Input contract with validation and normalization.
- Speed profiles: `safe`, `balanced`, `fast`.
- DNS resolve for FQDN via `dnsx`.
- Host discovery and fast TCP port scan via `naabu`.
- Enrichment with Nmap `-sV`, OS detection (`-O`) and NSE profiles (incl. `vuln`).
- Parallel NSE/OS stage (configurable `nse_concurrency`) for faster large scans.
- Retry + timeout handling per external command (with a separate per-host `nse_timeout_seconds`).
- Range batching + fine-grained checkpoint/resume (per discovery/port batch and per NSE host).
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

### 3) Run a scan

```bash
docker compose run --rm scanner --config scanner/config/default.yaml --mode balanced
```

### 4) Resume after interruption

```bash
docker compose run --rm scanner --config scanner/config/default.yaml --mode balanced --resume
```

With per-run output enabled (default), resume continues the latest run recorded in
`scanner/state/latest_run.json`, or pass an explicit id:

```bash
docker compose run --rm scanner --config scanner/config/default.yaml --mode balanced \
  --resume --run-id 20260626T104530Z
```

## Configuration validation

The YAML config is validated at startup with **Pydantic** (`scanner/pipeline/config_schema.py`).
Unknown keys, invalid profile references, out-of-range values, and missing required profiles
(`safe`/`balanced`/`fast`) fail fast with a readable error (exit code `2`).

## Per-run output directories

When `runtime.per_run_output: true` (default), each scan writes to isolated directories:

- `scanner/output/runs/<run_id>/` — artifacts and `run_meta.json`
- `scanner/state/runs/<run_id>/` — checkpoint for that run
- `scanner/state/latest_run.json` — pointer to the most recent run id

`run_id` defaults to a UTC timestamp (`20260626T104530Z`) or can be set via `--run-id`.
Set `per_run_output: false` to keep the legacy flat layout (`scanner/output/`).

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Unexpected internal error |
| `2` | Configuration validation error |
| `3` | No valid input targets after contract validation |
| `4` | External tool stage failed after retries |
| `130` | Interrupted (Ctrl+C) |

## Logging

Pipeline logs use a **rotating file** at `logs_dir/pipeline.log` (defaults:
`log_max_bytes: 10485760`, `log_backup_count: 5`). Tune under `runtime:` in the config.

## Resource limits (Docker Compose)

`docker-compose.yml` sets container limits to reduce the risk of host exhaustion during large
scans: `mem_limit: 4g`, `cpus: "4.0"`, and raised `nproc`/`nofile` ulimits. Adjust for your
host capacity.

## Validation Helpers

- `scripts/smoke.sh`:
  - compiles Python sources;
  - runs pipeline with current input files.
- `scripts/load-test.sh <cidr>`:
  - writes a temporary CIDR target;
  - runs `fast` profile in container.

## Tests

Unit tests cover the pure helpers and parsers: input validation, port grouping,
custom port parsing, IPv6 `host:port` handling, NSE rate-budget split, the nmap
command builder, report extraction (services, OS matches, CVE/CVSS + severity ranking),
config schema validation, and per-run directory resolution.

```bash
pip install -r requirements-dev.txt
python -m pytest -q
ruff check scanner tests
```

## Continuous Integration

`.github/workflows/ci.yml` runs on every push to `master` and on pull requests:

- **lint**: `ruff check`.
- **test**: `compileall` + `pytest` on Python 3.11 and 3.12.
- **image**: builds the image, smoke-checks the toolchain, runs an **end-to-end scan**
  against a throwaway target container, scans the image with **Trivy**, and generates a
  **SBOM** artifact.

### End-to-end test

`tests/e2e/run.sh` builds nothing itself — given the built image it spins up a target
container (`nginx:alpine`) on a private docker network, runs the scanner against it with a
minimal offline config (`tests/e2e/config.yaml`), and asserts (via
`tests/e2e/check_results.py`) that the host is found alive, port `80` is open, an Nmap
service is detected, and the report artifacts exist. Run locally:

```bash
docker build -t network-scan-cli:ci .
tests/e2e/run.sh network-scan-cli:ci
```

### Image scanning & SBOM

- **Trivy** scans the built image: a non-blocking report (CRITICAL/HIGH/MEDIUM) plus a gate
  that fails only on **fixable CRITICAL** vulnerabilities. Documented, accepted exceptions
  (e.g. a CVE in an upstream tool binary with no fixed release yet) are listed in
  `.trivyignore` — the report still shows them, only the gate skips them.
- A **CycloneDX/SPDX SBOM** is generated (Syft) and uploaded as the `sbom` CI artifact.
- The publish workflow additionally attaches **SBOM + SLSA provenance attestations** to the
  image pushed to GHCR (`sbom: true`, `provenance: mode=max`).

## Container Image (GHCR)

`.github/workflows/docker-publish.yml` builds a multi-arch image (`linux/amd64`, `linux/arm64`)
and pushes it to GitHub Container Registry. It runs when a `v*` tag is pushed, when a GitHub
release is published, or manually via **workflow_dispatch**.

Published as `ghcr.io/onixus/octo-man` (image name is the lowercased `owner/repo`). Tagging:

- a version tag `vX.Y.Z` produces image tags `X.Y.Z`, `X.Y`, `X`, the commit `sha-<...>` and `latest`;
- non-semver tags (e.g. `v0.0.1a`) are published verbatim as the image tag (plus `latest`);
- `workflow_dispatch` can publish an extra ad-hoc tag via the `tag` input.

Pull and run:

```bash
docker pull ghcr.io/onixus/octo-man:latest
docker run --rm \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  -v "$PWD/scanner/inputs:/app/scanner/inputs" \
  -v "$PWD/scanner/output:/app/scanner/output" \
  -v "$PWD/scanner/config:/app/scanner/config" \
  -v "$PWD/scanner/state:/app/scanner/state" \
  ghcr.io/onixus/octo-man:latest --config scanner/config/default.yaml --mode balanced
```

To cut a release build, push a tag:

```bash
git tag v0.1.0 && git push origin v0.1.0
```

> The GHCR package may be **private** by default; make it public (or authenticate
> with a token) to pull it from other hosts.

## Reproducible & Pinned Builds

The image is pinned end-to-end so a rebuild is byte-reproducible and protected from
upstream/MITM tampering:

- **Base image** pinned by multi-arch **index digest** (`python:3.12-slim@sha256:...`).
- **dnsx / naabu** pinned by version **and** per-arch **sha256** (`*_SHA256_AMD64/ARM64`
  build args); the downloaded archive is verified with `sha256sum -c` during build.
- **nmap-vulners / vulscan** pinned to specific **commit SHAs** (`NMAP_VULNERS_REF`,
  `VULSCAN_REF`).

Upgrading a pin:

```bash
# base image digest
docker manifest inspect python:3.12-slim | grep -m1 digest
# tool sha256 (from the release checksums file)
curl -fsSL https://github.com/projectdiscovery/dnsx/releases/download/vX.Y.Z/dnsx_X.Y.Z_checksums.txt
# NSE script commit
git ls-remote https://github.com/vulnersCom/nmap-vulners.git HEAD
```

Then update the corresponding `FROM ... @sha256` / `ARG` defaults in the `Dockerfile`
(or override them via `--build-arg`). Because the digest is frozen, re-pin periodically to
pick up base-image security updates (see image scanning in the production hardening backlog).

## Profiles

- `safe`: lower packet rate, `top-100`, conservative timing, `baseline` NSE (no `vuln`), `nse_concurrency: 2`, `nse_max_rate: 500`.
- `balanced`: default profile, `top-1000`, `vuln` NSE + OS detection, `nse_concurrency: 4`, `nse_max_rate: 2000`.
- `fast`: higher discovery/scan rate, `top-1000`, `vuln` NSE + OS detection, `nse_concurrency: 8`, `nse_max_rate: 5000`.

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

## Batching & Resume

Large inputs are split into independent, resumable batches so a single huge
`naabu`/`nmap` run can't hit the global timeout, a failed batch doesn't abort the
whole scan, and `--resume` only redoes what's left.

- IPv4 networks larger than `batching.ipv4_prefix` are split into `/ipv4_prefix`
  batches (e.g. a `/16` becomes 16 × `/20`). Single IPs, IPv6 and smaller nets are
  grouped into chunks of `batching.max_targets_per_batch`.
- Discovery and port-scan run **per batch**; alive hosts and open ports are
  aggregated incrementally into `alive_ips.txt` / `open_ports.txt`.
- The NSE/OS stage is checkpointed **per host** — `--resume` skips hosts whose
  scan already completed.
- Progress is tracked in `scanner/state/checkpoint.json` with stage flags and
  per-item sets (`discover`/`ports` batch ids, `nse` hosts). Writes are atomic
  per item and thread-safe.

Tune or disable batching under `batching:` in `scanner/config/default.yaml`
(`enabled`, `ipv4_prefix`, `max_targets_per_batch`). Smaller `ipv4_prefix` means
finer resume granularity at the cost of more tool invocations.

## Output Artifacts

- `scanner/output/normalized/ip_targets.txt`
- `scanner/output/normalized/fqdn_targets.txt`
- `scanner/output/normalized/contract_validation.json` (counts + rejected inputs)
- `scanner/output/dns_resolution.json` / `scanner/output/dnsx_records.jsonl` (DNS resolve data)
- `scanner/output/resolved_ips.txt`
- `scanner/output/all_targets.txt`
- `scanner/output/alive_ips.txt` (aggregated; per-batch files under `scanner/output/discover/`)
- `scanner/output/open_ports.txt` (aggregated; per-batch files under `scanner/output/ports/`)
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

## Licenses

This project's own source code (the `scanner/` package, `scripts/`, configs and docs)
has **no license declared yet**. Until a license is added, default copyright applies and
others have no redistribution rights — add a license (e.g. `MIT` or `Apache-2.0`) at the
repository root before publishing.

The container image **bundles third-party tools**, each under its own license. The Python
code only invokes them as separate executables / NSE scripts ("mere aggregation"), so it is
not a derivative work of them. However, **redistributing the built Docker image** must comply
with every license below.

### Runtime tools (bundled in the image)

| Component | Pinned version | License | Notes |
|---|---|---|---|
| Nmap | Debian package | Nmap Public Source License (NPSL) v0.95 | GPLv2-derived custom license with restrictions on certain commercial/OEM redistribution — see <https://nmap.org/npsl/> |
| naabu | `2.6.1` | MIT | ProjectDiscovery |
| dnsx | `1.2.3` | MIT | ProjectDiscovery |
| nmap-vulners | `NMAP_VULNERS_REF` | GPL-3.0 | NSE CVE-lookup script |
| vulscan | `VULSCAN_REF` | GPL-3.0 | NSE script + local CVE databases |

### Base image & OS packages (`python:3.12-slim`, Debian)

| Component | License |
|---|---|
| Python (CPython) | PSF License Agreement |
| ca-certificates (Mozilla CA bundle) | MPL-2.0 |
| curl | curl license (MIT/X11-style) |
| git | GPL-2.0 |
| jq | MIT |
| unzip (build-time only, removed from final image) | Info-ZIP License |

### Python dependencies

| Package | License | Scope |
|---|---|---|
| PyYAML | MIT | runtime |
| pytest | MIT | dev/test |
| ruff | MIT | dev/lint |

### Compliance notes

- The image ships **GPL-3.0** components (`nmap-vulners`, `vulscan`) and **NPSL**-licensed Nmap.
  When distributing the image, provide the corresponding source or a written offer as required
  by the GPL, and observe NPSL terms (notably commercial/OEM redistribution restrictions; the
  Nmap Project offers a separate OEM license for such cases).
- The scanner orchestrates these tools via subprocess / NSE and does not statically link them,
  so your own code may use a different license.
- This summary is informational and **not legal advice**; verify the full license texts shipped
  with each component before redistribution.

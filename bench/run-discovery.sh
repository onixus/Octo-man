#!/usr/bin/env bash
# Run discovery benchmark against the emulated bench network.
#
# Usage:
#   bench/run-discovery.sh [alive_hosts] [target_count] [cidr|list]
#
# Prerequisites: docker compose, image built (script builds if missing).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=bench/env.defaults
source "${ROOT_DIR}/bench/env.defaults"

RUN_ID="bench-$(date -u +%Y%m%dT%H%M%SZ)"
LOG_DIR="${ROOT_DIR}/scanner/output/bench/logs"
METRICS_FILE="${ROOT_DIR}/scanner/output/bench/${RUN_ID}-metrics.json"

mkdir -p "${LOG_DIR}"

echo "[bench] bringing up emulated network"
"${ROOT_DIR}/bench/up.sh" "${1:-}" "${2:-}" "${3:-}"

cd "${ROOT_DIR}"
if ! docker image inspect network-scan-cli:latest >/dev/null 2>&1; then
  echo "[bench] building scanner image"
  docker compose build scanner
fi

RANGES="${ROOT_DIR}/scanner/inputs/bench/ranges.txt"
TARGET_LINES="$(wc -l < "${RANGES}" | tr -d ' ')"

echo "[bench] running discovery benchmark (mode=${BENCH_MODE}, targets=${TARGET_LINES}, run_id=${RUN_ID})"
START_TS="$(date +%s)"

set +e
docker compose run --rm --no-TTY \
  --network "${BENCH_NET_NAME}" \
  scanner \
  --config "${BENCH_CONFIG}" \
  --mode "${BENCH_MODE}" \
  --ranges scanner/inputs/bench/ranges.txt \
  --domains scanner/inputs/bench/domains.txt \
  --run-id "${RUN_ID}"
SCAN_RC=$?
set -e

END_TS="$(date +%s)"
DURATION=$((END_TS - START_TS))

OUTPUT_DIR="${ROOT_DIR}/scanner/output/bench"
ALIVE_FILE="${OUTPUT_DIR}/alive_ips.txt"
OPEN_FILE="${OUTPUT_DIR}/open_ports.txt"
PIPE_LOG="${OUTPUT_DIR}/logs/pipeline.log"

python3 - "${METRICS_FILE}" "${RUN_ID}" "${DURATION}" "${SCAN_RC}" "${TARGET_LINES}" "${ALIVE_FILE}" "${OPEN_FILE}" "${PIPE_LOG}" <<'PY'
import json, re, sys
from pathlib import Path

metrics_path = Path(sys.argv[1])
run_id, duration, rc = sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
target_lines = int(sys.argv[5])
alive_file, open_file, pipe_log = map(Path, sys.argv[6:])

alive = len(alive_file.read_text(encoding="utf-8").splitlines()) if alive_file.exists() else 0
open_ports = len(open_file.read_text(encoding="utf-8").splitlines()) if open_file.exists() else 0

discover_sec = None
if pipe_log.exists():
    text = pipe_log.read_text(encoding="utf-8", errors="replace")
    starts = [m.group(1) for m in re.finditer(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+ INFO discover:", text, re.M)]
    ends = [m.group(1) for m in re.finditer(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+ INFO ports:", text, re.M)]
    if starts and ends:
        from datetime import datetime

        fmt = "%Y-%m-%d %H:%M:%S"
        discover_sec = (datetime.strptime(ends[0], fmt) - datetime.strptime(starts[0], fmt)).total_seconds()

payload = {
    "run_id": run_id,
    "duration_sec": duration,
    "exit_code": rc,
    "target_count": target_lines,
    "alive_hosts": alive,
    "open_ports": open_ports,
    "discover_stage_sec": discover_sec,
    "targets_per_sec": round(target_lines / discover_sec, 1) if discover_sec and discover_sec > 0 else None,
}
metrics_path.parent.mkdir(parents=True, exist_ok=True)
metrics_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
print(json.dumps(payload, indent=2))
PY

echo "[bench] metrics: ${METRICS_FILE}"
exit "${SCAN_RC}"

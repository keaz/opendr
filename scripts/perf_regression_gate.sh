#!/usr/bin/env bash
#
# Production-readiness performance regression gate.
#
# Smoke mode runs a small isolated LMDB benchmark and enforces basic failure and
# latency thresholds. Release mode runs the Docker regression profile and
# requires a preserved baseline JSON unless explicitly disabled.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/.." && pwd)

PERF_GATE_MODE="${PERF_GATE_MODE:-smoke}"
PERF_GATE_OUTPUT_DIR="${PERF_GATE_OUTPUT_DIR:-${REPO_ROOT}/target/perf/regression-gate-$(date +%Y%m%d-%H%M%S)}"
PERF_GATE_THRESHOLD_PERCENT="${PERF_GATE_THRESHOLD_PERCENT:-10}"
PERF_GATE_MAX_FAILURE_RATE_PERCENT="${PERF_GATE_MAX_FAILURE_RATE_PERCENT:-0}"
PERF_GATE_MAX_P95_MS="${PERF_GATE_MAX_P95_MS:-5000}"
PERF_GATE_BASELINE_JSON="${PERF_GATE_BASELINE_JSON:-}"
PERF_GATE_REQUIRE_BASELINE="${PERF_GATE_REQUIRE_BASELINE:-1}"
PERF_GATE_PRODUCTS="${PERF_GATE_PRODUCTS:-opendr}"
PERF_GATE_PROFILE_SET="${PERF_GATE_PROFILE_SET:-regression}"
PERF_GATE_BENCHMARK_TIMEOUT="${PERF_GATE_BENCHMARK_TIMEOUT:-900}"

PERF_GATE_SMOKE_PROFILE="${PERF_GATE_SMOKE_PROFILE:-debug}"
PERF_GATE_SMOKE_USERS="${PERF_GATE_SMOKE_USERS:-200}"
PERF_GATE_SMOKE_READ_ITERATIONS="${PERF_GATE_SMOKE_READ_ITERATIONS:-50}"
PERF_GATE_SMOKE_WRITE_ITERATIONS="${PERF_GATE_SMOKE_WRITE_ITERATIONS:-25}"
PERF_GATE_SMOKE_WARMUP_ITERATIONS="${PERF_GATE_SMOKE_WARMUP_ITERATIONS:-2}"
PERF_GATE_PORT="${PERF_GATE_PORT:-}"

usage() {
  cat <<'EOF'
Usage: scripts/perf_regression_gate.sh

Environment:
  PERF_GATE_MODE                   smoke or release (default: smoke)
  PERF_GATE_OUTPUT_DIR             Artifact directory
  PERF_GATE_MAX_FAILURE_RATE_PERCENT
                                   Max allowed failure rate in smoke mode (default: 0)
  PERF_GATE_MAX_P95_MS             Max allowed p95 latency in smoke mode; set -1 to disable (default: 5000)
  PERF_GATE_BASELINE_JSON          Baseline ldap_perf_client JSON for release comparison
  PERF_GATE_THRESHOLD_PERCENT      Allowed release regression percentage (default: 10)
  PERF_GATE_REQUIRE_BASELINE       Require baseline in release mode, 1 or 0 (default: 1)
  PERF_GATE_PRODUCTS               Products for Docker matrix release mode (default: opendr)
  PERF_GATE_PROFILE_SET            Docker matrix profile set (default: regression)
  PERF_GATE_BENCHMARK_TIMEOUT      Docker matrix per-profile timeout seconds (default: 900)
  PERF_GATE_SMOKE_PROFILE          Cargo profile for smoke mode: debug or release (default: debug)
  PERF_GATE_SMOKE_USERS            Smoke fixture users (default: 200)
  PERF_GATE_SMOKE_READ_ITERATIONS  Smoke read-heavy iterations (default: 50)
  PERF_GATE_SMOKE_WRITE_ITERATIONS Smoke write-heavy iterations (default: 25)
  PERF_GATE_SMOKE_WARMUP_ITERATIONS
                                   Smoke warmup iterations (default: 2)
  PERF_GATE_PORT                   Optional LDAP port for smoke mode
EOF
}

if [[ $# -gt 0 ]]; then
  case "$1" in
    --help|-h|help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
fi

log() {
  printf '[perf-gate] %s\n' "$*"
}

case "${PERF_GATE_OUTPUT_DIR}" in
  /*) ;;
  *) PERF_GATE_OUTPUT_DIR="${REPO_ROOT}/${PERF_GATE_OUTPUT_DIR}" ;;
esac

mkdir -p "${PERF_GATE_OUTPUT_DIR}"

validate_smoke_json() {
  local json_path="$1"
  local report_path="$2"

  python3 - "${json_path}" "${PERF_GATE_MAX_FAILURE_RATE_PERCENT}" "${PERF_GATE_MAX_P95_MS}" "${report_path}" <<'PY'
import json
import sys
from pathlib import Path

json_path = Path(sys.argv[1])
max_failure_rate = float(sys.argv[2])
max_p95_ms = float(sys.argv[3])
report_path = Path(sys.argv[4])

if not json_path.exists():
    raise SystemExit(f"missing benchmark JSON: {json_path}")

data = json.loads(json_path.read_text())
benchmarks = data.get("benchmarks")
if not isinstance(benchmarks, list) or not benchmarks:
    raise SystemExit("benchmark JSON is missing non-empty benchmarks array")

failures = []
lines = [
    "# Performance Smoke Gate",
    "",
    f"Source JSON: `{json_path}`",
    f"Max failure rate: `{max_failure_rate:.3f}%`",
    f"Max p95 latency: `{max_p95_ms:.3f} ms`" if max_p95_ms >= 0 else "Max p95 latency: disabled",
    "",
    "| Operation | Successes | Failures | Failure % | P95 ms | Status |",
    "|---|---:|---:|---:|---:|---|",
]

for item in benchmarks:
    operation = str(item.get("operation", "unknown"))
    successes = int(item.get("successes", 0) or 0)
    failures_count = int(item.get("failures", 0) or 0)
    failure_rate = float(item.get("failure_rate_percent", 0.0) or 0.0)
    p95_ms = item.get("p95_ms")
    p95_value = float(p95_ms) if isinstance(p95_ms, (int, float)) else None

    status = "pass"
    if successes <= 0:
        status = "fail"
        failures.append(f"{operation}: no successful operations")
    if failure_rate > max_failure_rate:
        status = "fail"
        failures.append(
            f"{operation}: failure rate {failure_rate:.3f}% > {max_failure_rate:.3f}%"
        )
    if max_p95_ms >= 0 and p95_value is not None and p95_value > max_p95_ms:
        status = "fail"
        failures.append(f"{operation}: p95 {p95_value:.3f} ms > {max_p95_ms:.3f} ms")

    p95_display = f"{p95_value:.3f}" if p95_value is not None else "n/a"
    lines.append(
        f"| {operation} | {successes} | {failures_count} | {failure_rate:.3f} | "
        f"{p95_display} | {status} |"
    )

lines.append("")
report = "\n".join(lines)
report_path.parent.mkdir(parents=True, exist_ok=True)
report_path.write_text(report)
print(report)

if failures:
    raise SystemExit("\n".join(failures))
PY
}

run_smoke() {
  local smoke_dir="${PERF_GATE_OUTPUT_DIR}/smoke-single-instance"
  local report_path="${PERF_GATE_OUTPUT_DIR}/perf-smoke-gate-report.md"
  local args=(
    --output-dir "${smoke_dir}"
    --profile "${PERF_GATE_SMOKE_PROFILE}"
    --preloaded-users "${PERF_GATE_SMOKE_USERS}"
    --read-iterations "${PERF_GATE_SMOKE_READ_ITERATIONS}"
    --write-iterations "${PERF_GATE_SMOKE_WRITE_ITERATIONS}"
    --warmup-iterations "${PERF_GATE_SMOKE_WARMUP_ITERATIONS}"
  )

  if [[ -n "${PERF_GATE_PORT}" ]]; then
    args+=(--port "${PERF_GATE_PORT}")
  fi

  log "Running smoke performance gate into ${smoke_dir}"
  "${SCRIPT_DIR}/perf_single_instance_lmdb.sh" "${args[@]}"
  validate_smoke_json "${smoke_dir}/ldap-benchmark-results.json" "${report_path}"
}

find_candidate_json() {
  find "$1" -path '*/ldap-benchmark-results.json' -type f | sort | head -n 1
}

run_release() {
  local candidate_dir="${PERF_GATE_OUTPUT_DIR}/regression-candidate"
  local compare_report="${PERF_GATE_OUTPUT_DIR}/perf-regression-report.md"

  log "Running release performance profile ${PERF_GATE_PROFILE_SET} into ${candidate_dir}"
  "${SCRIPT_DIR}/perf_docker_matrix.sh" \
    --products "${PERF_GATE_PRODUCTS}" \
    --profile-set "${PERF_GATE_PROFILE_SET}" \
    --output-dir "${candidate_dir}" \
    --benchmark-timeout "${PERF_GATE_BENCHMARK_TIMEOUT}"

  local candidate_json
  candidate_json=$(find_candidate_json "${candidate_dir}")
  if [[ -z "${candidate_json}" ]]; then
    echo "No candidate ldap-benchmark-results.json found under ${candidate_dir}" >&2
    exit 1
  fi

  if [[ -z "${PERF_GATE_BASELINE_JSON}" ]]; then
    if [[ "${PERF_GATE_REQUIRE_BASELINE}" == "1" ]]; then
      echo "PERF_GATE_BASELINE_JSON is required in release mode" >&2
      exit 1
    fi
    log "No baseline provided; candidate JSON retained at ${candidate_json}"
    return 0
  fi

  python3 "${SCRIPT_DIR}/compare_perf_run.py" \
    --baseline-json "${PERF_GATE_BASELINE_JSON}" \
    --candidate-json "${candidate_json}" \
    --threshold-percent "${PERF_GATE_THRESHOLD_PERCENT}" \
    --report-out "${compare_report}"
}

case "${PERF_GATE_MODE}" in
  smoke)
    run_smoke
    ;;
  release)
    run_release
    ;;
  --help|-h|help)
    usage
    ;;
  *)
    echo "PERF_GATE_MODE must be smoke or release, got ${PERF_GATE_MODE}" >&2
    usage >&2
    exit 1
    ;;
esac

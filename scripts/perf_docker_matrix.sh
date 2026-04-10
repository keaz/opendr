#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/.." && pwd)

OUTPUT_DIR=""
PROFILE_SET="full"
SAMPLE_INTERVAL="0.25"
CPU_LIMIT="2"
MEMORY_LIMIT="4g"
BENCHMARK_TIMEOUT_SECONDS="180"
BASE_DN="dc=example,dc=com"
ROOT_PASSWORD="PerfRootSecret123!"
OPENDR_IMAGE="opendr:docker-perf"
OPENDJ_IMAGE="openidentityplatform/opendj:5.0.4"
PRODUCTS="opendr,opendj"

CURRENT_CONTAINER=""
CURRENT_OUTPUT_DIR=""
CURRENT_DATA_DIR=""
SAMPLER_PID=""

usage() {
  cat <<'EOF'
Usage: scripts/perf_docker_matrix.sh [options]

Options:
  --output-dir PATH         Output directory for the matrix run
  --profile-set VALUE      One of: smoke, standard, full (default: full)
  --products LIST          Comma-separated subset of: opendr,opendj
  --sample-interval SEC    Container stats sample interval (default: 0.25)
  --cpu VALUE              Docker CPU limit for each server container (default: 2)
  --memory VALUE           Docker memory limit for each server container (default: 4g)
  --benchmark-timeout SEC  Max seconds to allow each benchmark profile (default: 180)
  --base-dn DN             Benchmark base DN (default: dc=example,dc=com)
  --root-password VALUE    Root password used for both products
  --opendr-image TAG       Local OpenDR image tag (default: opendr:docker-perf)
  --opendj-image TAG       OpenDJ image tag (default: openidentityplatform/opendj:5.0.4)
  --help                   Show this help text
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --profile-set)
      PROFILE_SET="$2"
      shift 2
      ;;
    --products)
      PRODUCTS="$2"
      shift 2
      ;;
    --sample-interval)
      SAMPLE_INTERVAL="$2"
      shift 2
      ;;
    --cpu)
      CPU_LIMIT="$2"
      shift 2
      ;;
    --memory)
      MEMORY_LIMIT="$2"
      shift 2
      ;;
    --benchmark-timeout)
      BENCHMARK_TIMEOUT_SECONDS="$2"
      shift 2
      ;;
    --base-dn)
      BASE_DN="$2"
      shift 2
      ;;
    --root-password)
      ROOT_PASSWORD="$2"
      shift 2
      ;;
    --opendr-image)
      OPENDR_IMAGE="$2"
      shift 2
      ;;
    --opendj-image)
      OPENDJ_IMAGE="$2"
      shift 2
      ;;
    --help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "${OUTPUT_DIR}" ]]; then
  timestamp=$(date +"%Y%m%d-%H%M%S")
  OUTPUT_DIR="${REPO_ROOT}/target/perf/docker-matrix-${timestamp}"
fi

case "${OUTPUT_DIR}" in
  /*) ;;
  *) OUTPUT_DIR="${REPO_ROOT}/${OUTPUT_DIR}" ;;
esac

declare -a LOAD_PROFILES
case "${PROFILE_SET}" in
  smoke)
    LOAD_PROFILES=(
      "smoke:100:20:10:2"
    )
    ;;
  standard)
    LOAD_PROFILES=(
      "light:100:50:25:5"
      "moderate:500:10:10:2"
      "heavy:1000:5:5:2"
    )
    ;;
  full)
    LOAD_PROFILES=(
      "light:100:50:25:5"
      "moderate:500:10:10:2"
      "heavy:1000:5:5:2"
      "stress:2500:3:3:1"
    )
    ;;
  *)
    echo "--profile-set must be one of: smoke, standard, full" >&2
    exit 1
    ;;
esac

mkdir -p "${OUTPUT_DIR}"

cleanup() {
  if [[ -n "${SAMPLER_PID}" ]] && kill -0 "${SAMPLER_PID}" >/dev/null 2>&1; then
    kill "${SAMPLER_PID}" >/dev/null 2>&1 || true
    wait "${SAMPLER_PID}" >/dev/null 2>&1 || true
  fi

  if [[ -n "${CURRENT_CONTAINER}" ]]; then
    docker rm -f "${CURRENT_CONTAINER}" >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT

contains_product() {
  local product="$1"
  case ",${PRODUCTS}," in
    *",${product},"*) return 0 ;;
    *) return 1 ;;
  esac
}

pick_free_port() {
  local port
  while true; do
    port=$(( (RANDOM % 10000) + 20000 ))
    if ! lsof -nP -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1; then
      echo "${port}"
      return 0
    fi
  done
}

human_bytes() {
  local bytes="${1:-0}"
  awk -v bytes="${bytes}" '
    BEGIN {
      split("B KiB MiB GiB TiB", units, " ");
      value = bytes + 0;
      unit = 1;
      while (value >= 1024 && unit < 5) {
        value /= 1024;
        unit++;
      }
      printf "%.2f %s", value, units[unit];
    }
  '
}

dir_size_bytes() {
  local dir="$1"
  if [[ ! -d "${dir}" ]]; then
    echo 0
    return 0
  fi
  du -sk "${dir}" 2>/dev/null | awk '{print $1 * 1024}'
}

to_bytes() {
  local raw="${1:-0B}"
  python3 - "$raw" <<'PY'
import re
import sys

raw = sys.argv[1]
match = re.fullmatch(r"([0-9.]+)([A-Za-z]+)", raw)
if not match:
    print("0")
    raise SystemExit(0)

value = float(match.group(1))
unit = match.group(2)
factors = {
    "B": 1,
    "kB": 1000,
    "KB": 1000,
    "MB": 1000 ** 2,
    "GB": 1000 ** 3,
    "TB": 1000 ** 4,
    "KiB": 1024,
    "MiB": 1024 ** 2,
    "GiB": 1024 ** 3,
    "TiB": 1024 ** 4,
}
print(int(value * factors.get(unit, 1)))
PY
}

sample_container_stats() {
  local container="$1"
  local benchmark_pid="$2"
  local output_file="$3"

  : > "${output_file}"
  while kill -0 "${benchmark_pid}" >/dev/null 2>&1 && docker inspect "${container}" >/dev/null 2>&1; do
    local sample
    sample=$(docker stats --no-stream --format '{{.CPUPerc}},{{.MemUsage}}' "${container}" 2>/dev/null || true)
    if [[ -n "${sample}" ]]; then
      local cpu_raw mem_raw mem_used mem_limit
      cpu_raw=${sample%%,*}
      mem_raw=${sample#*,}
      mem_used=${mem_raw%% / *}
      mem_limit=${mem_raw##* / }
      printf '%s,%s,%s\n' \
        "${cpu_raw%%%}" \
        "$(to_bytes "${mem_used}")" \
        "$(to_bytes "${mem_limit}")" \
        >> "${output_file}"
    fi
    sleep "${SAMPLE_INTERVAL}"
  done
}

summarize_container_stats() {
  local samples_file="$1"
  local json_file="$2"
  local markdown_file="$3"

  if [[ ! -s "${samples_file}" ]]; then
    cat > "${json_file}" <<'EOF'
{"samples":0,"cpu_avg_percent":0,"cpu_max_percent":0,"memory_avg_bytes":0,"memory_max_bytes":0,"memory_limit_bytes":0}
EOF
    cat > "${markdown_file}" <<'EOF'
## Container Resource Summary

- Samples captured: 0
- CPU usage: no samples captured
- Memory usage: no samples captured
EOF
    return 0
  fi

  awk -F',' '
    BEGIN {
      samples = 0;
      cpu_sum = 0;
      cpu_max = 0;
      mem_sum = 0;
      mem_max = 0;
      mem_limit = 0;
    }
    NF >= 3 {
      samples++;
      cpu = $1 + 0;
      mem = $2 + 0;
      limit = $3 + 0;
      cpu_sum += cpu;
      mem_sum += mem;
      if (cpu > cpu_max) cpu_max = cpu;
      if (mem > mem_max) mem_max = mem;
      if (limit > mem_limit) mem_limit = limit;
    }
    END {
      cpu_avg = samples > 0 ? cpu_sum / samples : 0;
      mem_avg = samples > 0 ? mem_sum / samples : 0;
      printf "{\"samples\":%d,\"cpu_avg_percent\":%.4f,\"cpu_max_percent\":%.4f,\"memory_avg_bytes\":%.0f,\"memory_max_bytes\":%.0f,\"memory_limit_bytes\":%.0f}\n", samples, cpu_avg, cpu_max, mem_avg, mem_max, mem_limit;
    }
  ' "${samples_file}" > "${json_file}"

  python3 - "${json_file}" "${markdown_file}" <<'PY'
import json
import sys
from pathlib import Path

def human_bytes(value: int) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    size = float(value)
    unit = 0
    while size >= 1024 and unit < len(units) - 1:
        size /= 1024
        unit += 1
    return f"{size:.2f} {units[unit]}"

data = json.loads(Path(sys.argv[1]).read_text())
lines = [
    "## Container Resource Summary",
    "",
    f"- Samples captured: {data['samples']}",
]
if data["samples"] == 0:
    lines.extend([
        "- CPU usage: no samples captured",
        "- Memory usage: no samples captured",
    ])
else:
    lines.extend([
        f"- CPU usage: avg {data['cpu_avg_percent']:.2f}%, max {data['cpu_max_percent']:.2f}%",
        f"- Memory usage: avg {human_bytes(int(data['memory_avg_bytes']))}, max {human_bytes(int(data['memory_max_bytes']))}, limit {human_bytes(int(data['memory_limit_bytes']))}",
    ])
Path(sys.argv[2]).write_text("\n".join(lines) + "\n")
PY
}

wait_for_container_ready() {
  local product="$1"
  local container="$2"
  local port="$3"
  local attempts=0

  while (( attempts < 240 )); do
    if ! docker inspect "${container}" >/dev/null 2>&1; then
      echo "Container ${container} exited unexpectedly" >&2
      return 1
    fi

    if nc -z 127.0.0.1 "${port}" >/dev/null 2>&1; then
      case "${product}" in
        opendr)
          sleep 2
          return 0
          ;;
        opendj)
          if docker logs "${container}" 2>&1 | rg -q 'Starting Directory Server \.* Done\.'; then
            sleep 8
            return 0
          fi
          ;;
      esac
    fi

    attempts=$((attempts + 1))
    sleep 1
  done

  echo "Timed out waiting for ${product} container ${container} on port ${port}" >&2
  return 1
}

build_dependencies() {
  echo "Building release benchmark client..."
  cargo build --release --bin ldap_perf_client

  if contains_product "opendr"; then
    echo "Building OpenDR Docker image ${OPENDR_IMAGE}..."
    docker build -t "${OPENDR_IMAGE}" "${REPO_ROOT}"
  fi

  if contains_product "opendj"; then
    echo "Pulling OpenDJ image ${OPENDJ_IMAGE}..."
    docker pull "${OPENDJ_IMAGE}"
  fi
}

write_run_metadata() {
  local file="$1"
  local product="$2"
  local profile_name="$3"
  local image="$4"
  local ldap_port="$5"
  local bind_dn="$6"
  local admin_whoami_expected="$7"
  local preloaded_users="$8"
  local read_iterations="$9"
  local write_iterations="${10}"
  local warmup_iterations="${11}"

  cat > "${file}" <<EOF
{
  "product": "${product}",
  "profile": "${profile_name}",
  "image": "${image}",
  "ldap_port": ${ldap_port},
  "base_dn": "${BASE_DN}",
  "bind_dn": "${bind_dn}",
  "admin_whoami_expected": "${admin_whoami_expected}",
  "preloaded_users": ${preloaded_users},
  "read_iterations": ${read_iterations},
  "write_iterations": ${write_iterations},
  "warmup_iterations": ${warmup_iterations},
  "cpu_limit": "${CPU_LIMIT}",
  "memory_limit": "${MEMORY_LIMIT}",
  "sample_interval_seconds": ${SAMPLE_INTERVAL}
}
EOF
}

write_run_status() {
  local file="$1"
  local status="$2"
  local exit_code="$3"
  local timeout_seconds="$4"

  cat > "${file}" <<EOF
{
  "status": "${status}",
  "exit_code": ${exit_code},
  "timeout_seconds": ${timeout_seconds}
}
EOF
}

write_disk_footprint() {
  local file="$1"
  local db_before_bytes="$2"
  local db_after_bytes="$3"
  local data_before_bytes="$4"
  local data_after_bytes="$5"

  cat > "${file}" <<EOF
{
  "db_before_bytes": ${db_before_bytes},
  "db_after_bytes": ${db_after_bytes},
  "data_before_bytes": ${data_before_bytes},
  "data_after_bytes": ${data_after_bytes}
}
EOF
}

write_incomplete_benchmark_summary() {
  local file="$1"
  local status="$2"
  local exit_code="$3"

  cat > "${file}" <<EOF
# LDAP Single-Instance Perf Summary

## Benchmark Status
- Status: \`${status}\`
- Exit code: \`${exit_code}\`
- Timeout budget: \`${BENCHMARK_TIMEOUT_SECONDS}\` seconds
- Result: benchmark did not complete; see \`container.log\` and \`benchmark.stderr.log\`
EOF
}

write_run_report() {
  local file="$1"
  local product="$2"
  local profile_name="$3"
  local db_before_bytes="$4"
  local db_after_bytes="$5"
  local data_before_bytes="$6"
  local data_after_bytes="$7"
  local stats_markdown="$8"
  local benchmark_summary="$9"
  local product_title

  product_title=$(printf '%s' "${product}" | awk '{print toupper(substr($0,1,1)) substr($0,2)}')

  cat > "${file}" <<EOF
# ${product_title} Docker Perf Run

## Run Context

- Product: \`${product}\`
- Profile: \`${profile_name}\`
- CPU limit: \`${CPU_LIMIT}\`
- Memory limit: \`${MEMORY_LIMIT}\`
- Base DN: \`${BASE_DN}\`

## Disk Footprint

- Database size before benchmark: ${db_before_bytes} bytes ($(human_bytes "${db_before_bytes}"))
- Database size after benchmark: ${db_after_bytes} bytes ($(human_bytes "${db_after_bytes}"))
- Data directory size before benchmark: ${data_before_bytes} bytes ($(human_bytes "${data_before_bytes}"))
- Data directory size after benchmark: ${data_after_bytes} bytes ($(human_bytes "${data_after_bytes}"))

EOF
  cat "${stats_markdown}" >> "${file}"
  printf '\n' >> "${file}"
  cat "${benchmark_summary}" >> "${file}"
}

run_profile() {
  local product="$1"
  local profile_name="$2"
  local preloaded_users="$3"
  local read_iterations="$4"
  local write_iterations="$5"
  local warmup_iterations="$6"

  local run_dir="${OUTPUT_DIR}/${product}/${profile_name}"
  local data_dir="${run_dir}/data"
  local ldap_port
  local image
  local bind_dn
  local admin_whoami_expected
  local benchmark_cmd=()
  local benchmark_status="success"
  local benchmark_exit_code=0
  local benchmark_pid=""
  local watchdog_pid=""
  local timeout_flag="${run_dir}/benchmark-timeout.flag"

  mkdir -p "${run_dir}" "${data_dir}"
  chmod 0777 "${data_dir}"
  rm -f "${timeout_flag}"

  ldap_port=$(pick_free_port)
  CURRENT_OUTPUT_DIR="${run_dir}"
  CURRENT_DATA_DIR="${data_dir}"
  CURRENT_CONTAINER="perf-${product}-${profile_name}-$$"

  case "${product}" in
    opendr)
      image="${OPENDR_IMAGE}"
      bind_dn="cn=admin,${BASE_DN}"
      admin_whoami_expected="dn:${bind_dn}"
      docker run -d --rm \
        --name "${CURRENT_CONTAINER}" \
        --cpus="${CPU_LIMIT}" \
        --memory="${MEMORY_LIMIT}" \
        -p "127.0.0.1:${ldap_port}:1389" \
        -v "${data_dir}:/var/lib/opendr/data" \
        -e OPENDR_BASE_DN="${BASE_DN}" \
        -e OPENDR_ROOT_USER_DN="cn=admin" \
        -e OPENDR_ROOT_PASSWORD="${ROOT_PASSWORD}" \
        "${image}" \
        >/dev/null
      ;;
    opendj)
      image="${OPENDJ_IMAGE}"
      bind_dn="cn=admin"
      admin_whoami_expected="dn:cn=Directory Manager,cn=Root DNs,cn=config"
      docker run -d --rm \
        --name "${CURRENT_CONTAINER}" \
        --cpus="${CPU_LIMIT}" \
        --memory="${MEMORY_LIMIT}" \
        -p "127.0.0.1:${ldap_port}:1389" \
        -v "${data_dir}:/opt/opendj/data" \
        -e BASE_DN="${BASE_DN}" \
        -e ROOT_USER_DN="cn=admin" \
        -e ROOT_PASSWORD="${ROOT_PASSWORD}" \
        -e ADD_BASE_ENTRY="--addBaseEntry" \
        "${image}" \
        >/dev/null
      ;;
    *)
      echo "Unsupported product ${product}" >&2
      exit 1
      ;;
  esac

  echo "Running ${product} profile ${profile_name} on port ${ldap_port}..."
  if ! wait_for_container_ready "${product}" "${CURRENT_CONTAINER}" "${ldap_port}"; then
    local startup_db_bytes startup_data_bytes
    case "${product}" in
      opendr)
        startup_db_bytes=$(dir_size_bytes "${data_dir}")
        startup_data_bytes=$(dir_size_bytes "${data_dir}")
        ;;
      opendj)
        startup_db_bytes=$(( $(dir_size_bytes "${data_dir}/db") + $(dir_size_bytes "${data_dir}/changelogDb") ))
        startup_data_bytes=$(dir_size_bytes "${data_dir}")
        ;;
    esac

    docker logs "${CURRENT_CONTAINER}" > "${run_dir}/container.log" 2>&1 || true
    : > "${run_dir}/container-stats-samples.csv"
    : > "${run_dir}/benchmark.stderr.log"
    summarize_container_stats \
      "${run_dir}/container-stats-samples.csv" \
      "${run_dir}/container-stats-summary.json" \
      "${run_dir}/container-stats-summary.md"
    write_run_status "${run_dir}/run-status.json" "startup_failed" 1 "${BENCHMARK_TIMEOUT_SECONDS}"
    write_disk_footprint \
      "${run_dir}/disk-footprint.json" \
      "${startup_db_bytes}" \
      "${startup_db_bytes}" \
      "${startup_data_bytes}" \
      "${startup_data_bytes}"
    write_incomplete_benchmark_summary "${run_dir}/ldap-benchmark-summary.md" "startup_failed" 1
    write_run_report \
      "${run_dir}/report.md" \
      "${product}" \
      "${profile_name}" \
      "${startup_db_bytes}" \
      "${startup_db_bytes}" \
      "${startup_data_bytes}" \
      "${startup_data_bytes}" \
      "${run_dir}/container-stats-summary.md" \
      "${run_dir}/ldap-benchmark-summary.md"
    docker rm -f "${CURRENT_CONTAINER}" >/dev/null 2>&1 || true
    CURRENT_CONTAINER=""
    return 0
  fi

  local db_before_bytes data_before_bytes db_after_bytes data_after_bytes
  case "${product}" in
    opendr)
      db_before_bytes=$(dir_size_bytes "${data_dir}")
      data_before_bytes=$(dir_size_bytes "${data_dir}")
      ;;
    opendj)
      db_before_bytes=$(( $(dir_size_bytes "${data_dir}/db") + $(dir_size_bytes "${data_dir}/changelogDb") ))
      data_before_bytes=$(dir_size_bytes "${data_dir}")
      ;;
  esac

  write_run_metadata \
    "${run_dir}/run-metadata.json" \
    "${product}" \
    "${profile_name}" \
    "${image}" \
    "${ldap_port}" \
    "${bind_dn}" \
    "${admin_whoami_expected}" \
    "${preloaded_users}" \
    "${read_iterations}" \
    "${write_iterations}" \
    "${warmup_iterations}"

  benchmark_cmd=(
    "${REPO_ROOT}/target/release/ldap_perf_client"
    --url "ldap://127.0.0.1:${ldap_port}"
    --starttls
    --insecure
    --bind-dn "${bind_dn}"
    --admin-whoami-expected "${admin_whoami_expected}"
    --password "${ROOT_PASSWORD}"
    --base-dn "${BASE_DN}"
    --preloaded-users "${preloaded_users}"
    --read-iterations "${read_iterations}"
    --write-iterations "${write_iterations}"
    --warmup-iterations "${warmup_iterations}"
    --name-prefix "${product}-${profile_name}"
    --json-out "${run_dir}/ldap-benchmark-results.json"
  )

  "${benchmark_cmd[@]}" > "${run_dir}/ldap-benchmark-summary.md" 2> "${run_dir}/benchmark.stderr.log" &
  benchmark_pid=$!

  (
    sleep "${BENCHMARK_TIMEOUT_SECONDS}"
    if kill -0 "${benchmark_pid}" >/dev/null 2>&1; then
      : > "${timeout_flag}"
      kill "${benchmark_pid}" >/dev/null 2>&1 || true
      sleep 5
      kill -9 "${benchmark_pid}" >/dev/null 2>&1 || true
    fi
  ) &
  watchdog_pid=$!

  sample_container_stats "${CURRENT_CONTAINER}" "${benchmark_pid}" "${run_dir}/container-stats-samples.csv" &
  SAMPLER_PID=$!

  if wait "${benchmark_pid}"; then
    benchmark_exit_code=0
  else
    benchmark_exit_code=$?
  fi

  kill "${watchdog_pid}" >/dev/null 2>&1 || true
  wait "${watchdog_pid}" >/dev/null 2>&1 || true

  wait "${SAMPLER_PID}" >/dev/null 2>&1 || true
  SAMPLER_PID=""

  if [[ -f "${timeout_flag}" ]]; then
    benchmark_status="timeout"
  elif (( benchmark_exit_code != 0 )); then
    benchmark_status="error"
  fi

  case "${product}" in
    opendr)
      db_after_bytes=$(dir_size_bytes "${data_dir}")
      data_after_bytes=$(dir_size_bytes "${data_dir}")
      ;;
    opendj)
      db_after_bytes=$(( $(dir_size_bytes "${data_dir}/db") + $(dir_size_bytes "${data_dir}/changelogDb") ))
      data_after_bytes=$(dir_size_bytes "${data_dir}")
      ;;
  esac

  summarize_container_stats \
    "${run_dir}/container-stats-samples.csv" \
    "${run_dir}/container-stats-summary.json" \
    "${run_dir}/container-stats-summary.md"

  docker logs "${CURRENT_CONTAINER}" > "${run_dir}/container.log" 2>&1 || true

  if [[ "${benchmark_status}" != "success" ]]; then
    rm -f "${run_dir}/ldap-benchmark-results.json"
    write_incomplete_benchmark_summary \
      "${run_dir}/ldap-benchmark-summary.md" \
      "${benchmark_status}" \
      "${benchmark_exit_code}"
  fi

  write_run_status \
    "${run_dir}/run-status.json" \
    "${benchmark_status}" \
    "${benchmark_exit_code}" \
    "${BENCHMARK_TIMEOUT_SECONDS}"
  write_disk_footprint \
    "${run_dir}/disk-footprint.json" \
    "${db_before_bytes}" \
    "${db_after_bytes}" \
    "${data_before_bytes}" \
    "${data_after_bytes}"

  write_run_report \
    "${run_dir}/report.md" \
    "${product}" \
    "${profile_name}" \
    "${db_before_bytes}" \
    "${db_after_bytes}" \
    "${data_before_bytes}" \
    "${data_after_bytes}" \
    "${run_dir}/container-stats-summary.md" \
    "${run_dir}/ldap-benchmark-summary.md"

  docker rm -f "${CURRENT_CONTAINER}" >/dev/null 2>&1 || true
  CURRENT_CONTAINER=""
}

build_matrix_summary() {
  python3 - "${OUTPUT_DIR}" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
runs = []

for metadata_file in sorted(root.glob("*/*/run-metadata.json")):
    run_dir = metadata_file.parent
    benchmark_file = run_dir / "ldap-benchmark-results.json"
    stats_file = run_dir / "container-stats-summary.json"

    metadata = json.loads(metadata_file.read_text())
    status_file = run_dir / "run-status.json"
    footprint_file = run_dir / "disk-footprint.json"
    status = (
        json.loads(status_file.read_text())
        if status_file.exists()
        else {"status": "success", "exit_code": 0, "timeout_seconds": 0}
    )
    stats = (
        json.loads(stats_file.read_text())
        if stats_file.exists()
        else {
            "samples": 0,
            "cpu_avg_percent": 0,
            "cpu_max_percent": 0,
            "memory_avg_bytes": 0,
            "memory_max_bytes": 0,
            "memory_limit_bytes": 0,
        }
    )
    footprint = (
        json.loads(footprint_file.read_text())
        if footprint_file.exists()
        else {
            "db_before_bytes": 0,
            "db_after_bytes": 0,
            "data_before_bytes": 0,
            "data_after_bytes": 0,
        }
    )

    benchmark = None
    bench_map = {}
    if benchmark_file.exists():
        try:
            benchmark = json.loads(benchmark_file.read_text())
            bench_map = {item["operation"]: item for item in benchmark["benchmarks"]}
        except json.JSONDecodeError:
            benchmark = None
            if status["status"] == "success":
                status["status"] = "error"
                status["exit_code"] = 1

    def bench_value(operation: str, field: str):
        item = bench_map.get(operation)
        if item is None:
            return None
        return item[field]

    runs.append(
        {
            "product": metadata["product"],
            "profile": metadata["profile"],
            "status": status["status"],
            "exit_code": status["exit_code"],
            "timeout_seconds": status["timeout_seconds"],
            "preloaded_users": metadata["preloaded_users"],
            "read_iterations": metadata["read_iterations"],
            "write_iterations": metadata["write_iterations"],
            "warmup_iterations": metadata["warmup_iterations"],
            "cpu_limit": metadata["cpu_limit"],
            "memory_limit": metadata["memory_limit"],
            "records_before_setup": benchmark["fixture"]["records_before_setup"] if benchmark else None,
            "records_after_setup": benchmark["fixture"]["records_after_setup"] if benchmark else None,
            "records_after_benchmark": benchmark["fixture"]["records_after_benchmark"] if benchmark else None,
            "total_elapsed_ms": benchmark["total_elapsed_ms"] if benchmark else None,
            "cpu_avg_percent": stats["cpu_avg_percent"],
            "cpu_max_percent": stats["cpu_max_percent"],
            "memory_avg_bytes": stats["memory_avg_bytes"],
            "memory_max_bytes": stats["memory_max_bytes"],
            "db_before_bytes": footprint["db_before_bytes"],
            "db_after_bytes": footprint["db_after_bytes"],
            "data_before_bytes": footprint["data_before_bytes"],
            "data_after_bytes": footprint["data_after_bytes"],
            "root_dse_mean_ms": bench_value("root_dse_search", "mean_ms"),
            "bind_admin_mean_ms": bench_value("bind_admin", "mean_ms"),
            "search_subtree_mean_ms": bench_value("search_subtree_fixture_users", "mean_ms"),
            "search_subtree_throughput": bench_value("search_subtree_fixture_users", "throughput_ops_per_sec"),
            "add_mean_ms": bench_value("add_entries", "mean_ms"),
            "modify_mean_ms": bench_value("modify_entries", "mean_ms"),
            "modifydn_mean_ms": bench_value("modifydn_entries", "mean_ms"),
            "delete_mean_ms": bench_value("delete_entries", "mean_ms"),
            "password_modify_mean_ms": bench_value("password_modify_fixture_user", "mean_ms"),
        }
    )

def human_bytes(value: int) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    size = float(value)
    unit = 0
    while size >= 1024 and unit < len(units) - 1:
        size /= 1024
        unit += 1
    return f"{size:.2f} {units[unit]}"

def fmt_number(value, decimals: int = 3) -> str:
    if value is None:
        return "n/a"
    return f"{value:.{decimals}f}"

def fmt_int(value) -> str:
    if value is None:
        return "n/a"
    return str(value)

def csv_value(value, decimals: int = 3) -> str:
    if value is None:
        return ""
    return f"{value:.{decimals}f}"

runs.sort(key=lambda item: (item["preloaded_users"], item["product"]))
summary_md = root / "comparison-summary.md"
summary_csv = root / "comparison-summary.csv"

csv_lines = [
    "product,profile,status,exit_code,timeout_seconds,preloaded_users,read_iterations,write_iterations,records_before_setup,records_after_setup,records_after_benchmark,total_elapsed_ms,cpu_avg_percent,cpu_max_percent,memory_avg_bytes,memory_max_bytes,db_before_bytes,db_after_bytes,data_before_bytes,data_after_bytes,root_dse_mean_ms,bind_admin_mean_ms,search_subtree_mean_ms,search_subtree_throughput,add_mean_ms,modify_mean_ms,modifydn_mean_ms,delete_mean_ms,password_modify_mean_ms"
]
for run in runs:
    csv_lines.append(
        ",".join(
            [
                run["product"],
                run["profile"],
                run["status"],
                str(run["exit_code"]),
                str(run["timeout_seconds"]),
                str(run["preloaded_users"]),
                str(run["read_iterations"]),
                str(run["write_iterations"]),
                fmt_int(run["records_before_setup"]),
                fmt_int(run["records_after_setup"]),
                fmt_int(run["records_after_benchmark"]),
                csv_value(run["total_elapsed_ms"]),
                f"{run['cpu_avg_percent']:.3f}",
                f"{run['cpu_max_percent']:.3f}",
                str(int(run["memory_avg_bytes"])),
                str(int(run["memory_max_bytes"])),
                str(int(run["db_before_bytes"])),
                str(int(run["db_after_bytes"])),
                str(int(run["data_before_bytes"])),
                str(int(run["data_after_bytes"])),
                csv_value(run["root_dse_mean_ms"]),
                csv_value(run["bind_admin_mean_ms"]),
                csv_value(run["search_subtree_mean_ms"]),
                csv_value(run["search_subtree_throughput"]),
                csv_value(run["add_mean_ms"]),
                csv_value(run["modify_mean_ms"]),
                csv_value(run["modifydn_mean_ms"]),
                csv_value(run["delete_mean_ms"]),
                csv_value(run["password_modify_mean_ms"]),
            ]
        )
    )
summary_csv.write_text("\n".join(csv_lines) + "\n")

lines = [
    "# Dockerized LDAP Performance Comparison",
    "",
    "## Test Configuration",
    "",
]
if runs:
    reference = runs[0]
    lines.extend(
        [
            f"- CPU limit per container: `{reference['cpu_limit']}`",
            f"- Memory limit per container: `{reference['memory_limit']}`",
            f"- Base DN: `dc=example,dc=com`",
            f"- StartTLS: enabled for both products",
            f"- Benchmark client: `target/release/ldap_perf_client`",
            f"- Timeout budget per profile: `{reference['timeout_seconds']}` seconds",
            "",
            "## Load Profiles",
            "",
            "| Profile | Preloaded Users | Read Iterations | Write Iterations |",
            "|---|---:|---:|---:|",
        ]
    )
    seen_profiles = set()
    for run in runs:
        if run["profile"] in seen_profiles:
            continue
        seen_profiles.add(run["profile"])
        lines.append(
            f"| {run['profile']} | {run['preloaded_users']} | {run['read_iterations']} | {run['write_iterations']} |"
        )

    lines.extend(
        [
            "",
            "## Top-Line Comparison",
            "",
            "| Product | Profile | Status | Total Runtime ms | Records After Setup | DB After | CPU Avg % | CPU Max % | Memory Avg | Memory Max | Subtree Search Mean ms | Subtree Search ops/s | Add Mean ms | Modify Mean ms | Delete Mean ms | Password Modify Mean ms |",
            "|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for run in runs:
        lines.append(
            f"| {run['product']} | {run['profile']} | {run['status']} | {fmt_number(run['total_elapsed_ms'])} | {fmt_int(run['records_after_setup'])} | {human_bytes(int(run['db_after_bytes']))} | {run['cpu_avg_percent']:.2f} | {run['cpu_max_percent']:.2f} | {human_bytes(int(run['memory_avg_bytes']))} | {human_bytes(int(run['memory_max_bytes']))} | {fmt_number(run['search_subtree_mean_ms'])} | {fmt_number(run['search_subtree_throughput'], 2)} | {fmt_number(run['add_mean_ms'])} | {fmt_number(run['modify_mean_ms'])} | {fmt_number(run['delete_mean_ms'])} | {fmt_number(run['password_modify_mean_ms'])} |"
        )

    incomplete_runs = [run for run in runs if run["status"] != "success"]
    if incomplete_runs:
        lines.extend(
            [
                "",
                "## Incomplete Profiles",
                "",
                "| Product | Profile | Status | Exit Code | Timeout Seconds | Notes |",
                "|---|---|---|---:|---:|---|",
            ]
        )
        for run in incomplete_runs:
            lines.append(
                f"| {run['product']} | {run['profile']} | {run['status']} | {run['exit_code']} | {run['timeout_seconds']} | No complete benchmark JSON was produced for this run. |"
            )

    lines.extend(
        [
            "",
            "## Per-Profile Winner Snapshot",
            "",
            "| Profile | Faster Subtree Search | Faster Add | Faster Modify | Faster Delete |",
            "|---|---|---|---|---|",
        ]
    )
    profiles = [
        profile
        for _, profile in sorted(
            {(run["preloaded_users"], run["profile"]) for run in runs}
        )
    ]
    for profile in profiles:
        subset = {run["product"]: run for run in runs if run["profile"] == profile}
        if "opendr" not in subset or "opendj" not in subset:
            continue
        if subset["opendr"]["status"] != "success" or subset["opendj"]["status"] != "success":
            continue
        lines.append(
            "| {profile} | {search} | {add} | {modify} | {delete} |".format(
                profile=profile,
                search=min(subset.values(), key=lambda r: r["search_subtree_mean_ms"])["product"],
                add=min(subset.values(), key=lambda r: r["add_mean_ms"])["product"],
                modify=min(subset.values(), key=lambda r: r["modify_mean_ms"])["product"],
                delete=min(subset.values(), key=lambda r: r["delete_mean_ms"])["product"],
            )
        )

summary_md.write_text("\n".join(lines) + "\n")
PY
}

build_dependencies

for product in opendr opendj; do
  if ! contains_product "${product}"; then
    continue
  fi

  for profile in "${LOAD_PROFILES[@]}"; do
    IFS=':' read -r profile_name preloaded_users read_iterations write_iterations warmup_iterations <<< "${profile}"
    run_profile "${product}" "${profile_name}" "${preloaded_users}" "${read_iterations}" "${write_iterations}" "${warmup_iterations}"
  done
done

build_matrix_summary

echo "Docker perf matrix completed."
echo "Summary: ${OUTPUT_DIR}/comparison-summary.md"

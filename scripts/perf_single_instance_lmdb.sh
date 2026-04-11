#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/.." && pwd)

BASE_DN="dc=example,dc=com"
ROOT_RDN="cn=admin"
ROOT_PASSWORD="PerfRootSecret123!"
PRELOADED_USERS=1000
READ_ITERATIONS=200
WRITE_ITERATIONS=100
WARMUP_ITERATIONS=10
SAMPLE_INTERVAL="0.25"
PROFILE="release"
NAME_PREFIX="perfbench"
LDAP_PORT=""
OUTPUT_DIR=""
SERVER_RUNTIME="fsm"

SERVER_PID=""
SAMPLER_PID=""

usage() {
  cat <<'EOF'
Usage: scripts/perf_single_instance_lmdb.sh [options]

Options:
  --output-dir PATH         Directory for reports and runtime artifacts
  --base-dn DN              Base DN to benchmark (default: dc=example,dc=com)
  --root-password VALUE     Plain-text root password used by the benchmark client
  --preloaded-users N       Fixture users created before read benchmarks (default: 1000)
  --read-iterations N       Iterations for bind/search/compare/read-heavy ops (default: 200)
  --write-iterations N      Iterations for modify/add/delete/write-heavy ops (default: 100)
  --warmup-iterations N     Warmup iterations for read-heavy ops (default: 10)
  --sample-interval SEC     CPU/RSS sampling interval while benchmark runs (default: 0.25)
  --name-prefix VALUE       Prefix for benchmark DNs (default: perfbench)
  --port PORT               LDAP port for the temporary single instance
  --profile VALUE           Cargo profile to build/use: release or debug (default: release)
  --runtime VALUE           Server runtime to benchmark: legacy or fsm (default: fsm)
  --help                    Show this help text
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir)
      OUTPUT_DIR="$2"
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
    --preloaded-users)
      PRELOADED_USERS="$2"
      shift 2
      ;;
    --read-iterations)
      READ_ITERATIONS="$2"
      shift 2
      ;;
    --write-iterations)
      WRITE_ITERATIONS="$2"
      shift 2
      ;;
    --warmup-iterations)
      WARMUP_ITERATIONS="$2"
      shift 2
      ;;
    --sample-interval)
      SAMPLE_INTERVAL="$2"
      shift 2
      ;;
    --name-prefix)
      NAME_PREFIX="$2"
      shift 2
      ;;
    --port)
      LDAP_PORT="$2"
      shift 2
      ;;
    --profile)
      PROFILE="$2"
      shift 2
      ;;
    --runtime)
      SERVER_RUNTIME="$2"
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
  OUTPUT_DIR="${REPO_ROOT}/target/perf/single-instance-lmdb-${timestamp}"
fi

case "${OUTPUT_DIR}" in
  /*) ;;
  *) OUTPUT_DIR="${REPO_ROOT}/${OUTPUT_DIR}" ;;
esac

if [[ "${PROFILE}" != "release" && "${PROFILE}" != "debug" ]]; then
  echo "--profile must be release or debug" >&2
  exit 1
fi

if [[ "${SERVER_RUNTIME}" != "legacy" && "${SERVER_RUNTIME}" != "fsm" ]]; then
  echo "--runtime must be legacy or fsm" >&2
  exit 1
fi

if [[ -z "${LDAP_PORT}" ]]; then
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
  LDAP_PORT=$(pick_free_port)
fi

LDAPS_PORT=$((LDAP_PORT + 1))
RUNTIME_DIR="${OUTPUT_DIR}/runtime"
CONFIG_DIR="${RUNTIME_DIR}/config"
DATA_DIR="${RUNTIME_DIR}/data"
CERT_DIR="${RUNTIME_DIR}/certs"
BIN_DIR="${REPO_ROOT}/target/${PROFILE}"

SERVER_LOG="${OUTPUT_DIR}/server.log"
CLIENT_SUMMARY="${OUTPUT_DIR}/ldap-benchmark-summary.md"
CLIENT_JSON="${OUTPUT_DIR}/ldap-benchmark-results.json"
RESOURCE_SAMPLES="${OUTPUT_DIR}/server-resource-samples.csv"
RESOURCE_SUMMARY="${OUTPUT_DIR}/server-resource-summary.md"
REPORT_MD="${OUTPUT_DIR}/report.md"

ROOT_DN="${ROOT_RDN},${BASE_DN}"

mkdir -p "${CONFIG_DIR}" "${DATA_DIR}" "${CERT_DIR}"

cleanup() {
  if [[ -n "${SAMPLER_PID}" ]] && kill -0 "${SAMPLER_PID}" >/dev/null 2>&1; then
    kill "${SAMPLER_PID}" >/dev/null 2>&1 || true
    wait "${SAMPLER_PID}" >/dev/null 2>&1 || true
  fi

  if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" >/dev/null 2>&1; then
    kill "${SERVER_PID}" >/dev/null 2>&1 || true
    wait "${SERVER_PID}" >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT

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

file_size_bytes() {
  local file="$1"
  if [[ ! -f "${file}" ]]; then
    echo 0
    return 0
  fi

  if stat -f%z "${file}" >/dev/null 2>&1; then
    stat -f%z "${file}"
  else
    stat -c%s "${file}"
  fi
}

dir_size_bytes() {
  local dir="$1"
  if [[ ! -d "${dir}" ]]; then
    echo 0
    return 0
  fi

  du -sk "${dir}" 2>/dev/null | awk '{print $1 * 1024}'
}

write_server_config() {
  local hashed_root_password="$1"

  cat > "${CONFIG_DIR}/server.toml" <<EOF
[server]
runtime = "${SERVER_RUNTIME}"
bind_address = "127.0.0.1"
ldap_port = ${LDAP_PORT}
ldaps_port = ${LDAPS_PORT}
base_dn = "${BASE_DN}"
root_user_dn = "${ROOT_RDN}"
root_password = "${hashed_root_password}"
organization_name = "OpenDR Perf Benchmark"

[backend]
backend_type = "lmdb"
data_directory = "./data"
lmdb_max_size = 1073741824
lmdb_max_readers = 126

[tls]
enabled = true
cert_file = "certs/server.crt"
key_file = "certs/server.key"
require_client_cert = false
min_tls_version = "1.2"

[replication]
enabled = false

[monitoring]
enabled = false

[audit]
enabled = false

[access_control]
enabled = false

[rate_limit]
enabled = false
EOF

  cat > "${CONFIG_DIR}/log4rs.yml" <<'EOF'
appenders:
  stdout:
    kind: console
root:
  level: error
  appenders:
    - stdout
EOF
}

generate_tls_fixture() {
  openssl req \
    -x509 \
    -newkey rsa:2048 \
    -keyout "${CERT_DIR}/server.key" \
    -out "${CERT_DIR}/server.crt" \
    -days 1 \
    -nodes \
    -subj "/CN=localhost" \
    >/dev/null 2>&1
}

sample_server_resources() {
  local server_pid="$1"
  local benchmark_pid="$2"
  local output_file="$3"

  : > "${output_file}"
  while kill -0 "${server_pid}" >/dev/null 2>&1 && kill -0 "${benchmark_pid}" >/dev/null 2>&1; do
    local sample
    sample=$(ps -o %cpu= -o rss= -p "${server_pid}" | awk 'NF >= 2 {print $1 "," $2}')
    if [[ -n "${sample}" ]]; then
      echo "${sample}" >> "${output_file}"
    fi
    sleep "${SAMPLE_INTERVAL}"
  done
}

summarize_resources() {
  local input_file="$1"
  local output_file="$2"

  if [[ ! -s "${input_file}" ]]; then
    cat > "${output_file}" <<'EOF'
## Server Resource Summary

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
      rss_sum = 0;
      rss_max = 0;
    }
    NF >= 2 {
      samples++;
      cpu = $1 + 0;
      rss = $2 + 0;
      cpu_sum += cpu;
      rss_sum += rss;
      if (cpu > cpu_max) cpu_max = cpu;
      if (rss > rss_max) rss_max = rss;
    }
    END {
      printf "## Server Resource Summary\n\n";
      printf "- Samples captured: %d\n", samples;
      if (samples == 0) {
        printf "- CPU usage: no samples captured\n";
        printf "- Memory usage: no samples captured\n";
      } else {
        printf "- CPU usage: avg %.2f%%, max %.2f%%\n", cpu_sum / samples, cpu_max;
        printf "- Memory usage: avg %.2f MiB RSS, max %.2f MiB RSS\n", (rss_sum / samples) / 1024, rss_max / 1024;
      }
    }
  ' "${input_file}" > "${output_file}"
}

wait_for_server() {
  local attempts=0
  while (( attempts < 200 )); do
    if ! kill -0 "${SERVER_PID}" >/dev/null 2>&1; then
      echo "Server exited before becoming ready. Tail of ${SERVER_LOG}:" >&2
      tail -n 40 "${SERVER_LOG}" >&2 || true
      exit 1
    fi

    if nc -z 127.0.0.1 "${LDAP_PORT}" >/dev/null 2>&1; then
      return 0
    fi

    attempts=$((attempts + 1))
    sleep 0.1
  done

  echo "Timed out waiting for LDAP server on port ${LDAP_PORT}. Tail of ${SERVER_LOG}:" >&2
  tail -n 40 "${SERVER_LOG}" >&2 || true
  exit 1
}

echo "Building benchmark binaries (${PROFILE})..."
BUILD_ARGS=(build --bin opendr --bin opendr-setup --bin ldap_perf_client)
if [[ "${PROFILE}" == "release" ]]; then
  BUILD_ARGS+=(--release)
fi
cargo "${BUILD_ARGS[@]}"

OPENDR_BIN="${BIN_DIR}/opendr"
SETUP_BIN="${BIN_DIR}/opendr-setup"
CLIENT_BIN="${BIN_DIR}/ldap_perf_client"

HASHED_ROOT_PASSWORD=$("${SETUP_BIN}" hash-password "${ROOT_PASSWORD}" | tail -n 1)
generate_tls_fixture
write_server_config "${HASHED_ROOT_PASSWORD}"

echo "Starting isolated LMDB-backed OpenDR instance in ${RUNTIME_DIR}..."
(
  cd "${RUNTIME_DIR}"
  "${OPENDR_BIN}" > "${SERVER_LOG}" 2>&1
) &
SERVER_PID=$!

wait_for_server

DB_SIZE_BEFORE_BYTES=$(dir_size_bytes "${DATA_DIR}")
DATA_MDB_BEFORE_BYTES=$(file_size_bytes "${DATA_DIR}/data.mdb")
LOCK_MDB_BEFORE_BYTES=$(file_size_bytes "${DATA_DIR}/lock.mdb")

echo "Running LDAP operation benchmark against ldap://127.0.0.1:${LDAP_PORT}..."
"${CLIENT_BIN}" \
  --url "ldap://127.0.0.1:${LDAP_PORT}" \
  --starttls \
  --insecure \
  --bind-dn "${ROOT_DN}" \
  --password "${ROOT_PASSWORD}" \
  --base-dn "${BASE_DN}" \
  --preloaded-users "${PRELOADED_USERS}" \
  --read-iterations "${READ_ITERATIONS}" \
  --write-iterations "${WRITE_ITERATIONS}" \
  --warmup-iterations "${WARMUP_ITERATIONS}" \
  --name-prefix "${NAME_PREFIX}" \
  --json-out "${CLIENT_JSON}" \
  > "${CLIENT_SUMMARY}" 2>&1 &
CLIENT_PID=$!

sample_server_resources "${SERVER_PID}" "${CLIENT_PID}" "${RESOURCE_SAMPLES}" &
SAMPLER_PID=$!

if ! wait "${CLIENT_PID}"; then
  wait "${SAMPLER_PID}" >/dev/null 2>&1 || true
  SAMPLER_PID=""
  echo "Benchmark client failed. See ${CLIENT_SUMMARY} and ${SERVER_LOG}." >&2
  exit 1
fi

wait "${SAMPLER_PID}" >/dev/null 2>&1 || true
SAMPLER_PID=""

summarize_resources "${RESOURCE_SAMPLES}" "${RESOURCE_SUMMARY}"

DB_SIZE_AFTER_BYTES=$(dir_size_bytes "${DATA_DIR}")
DATA_MDB_AFTER_BYTES=$(file_size_bytes "${DATA_DIR}/data.mdb")
LOCK_MDB_AFTER_BYTES=$(file_size_bytes "${DATA_DIR}/lock.mdb")

cat > "${REPORT_MD}" <<EOF
# OpenDR Single-Instance LMDB Performance Report

## Run Configuration

- Output directory: \`${OUTPUT_DIR}\`
- Runtime directory: \`${RUNTIME_DIR}\`
- Server log: \`${SERVER_LOG}\`
- LDAP URL: \`ldap://127.0.0.1:${LDAP_PORT}\`
- Server runtime: \`${SERVER_RUNTIME}\`
- Base DN: \`${BASE_DN}\`
- Root DN: \`${ROOT_DN}\`
- Preloaded users: ${PRELOADED_USERS}
- Read iterations: ${READ_ITERATIONS}
- Write iterations: ${WRITE_ITERATIONS}
- Warmup iterations: ${WARMUP_ITERATIONS}
- Resource sample interval: ${SAMPLE_INTERVAL} s

## Database Footprint

- Data directory size before benchmark: ${DB_SIZE_BEFORE_BYTES} bytes ($(human_bytes "${DB_SIZE_BEFORE_BYTES}"))
- Data directory size after benchmark: ${DB_SIZE_AFTER_BYTES} bytes ($(human_bytes "${DB_SIZE_AFTER_BYTES}"))
- \`data.mdb\` apparent size before benchmark: ${DATA_MDB_BEFORE_BYTES} bytes ($(human_bytes "${DATA_MDB_BEFORE_BYTES}"))
- \`data.mdb\` apparent size after benchmark: ${DATA_MDB_AFTER_BYTES} bytes ($(human_bytes "${DATA_MDB_AFTER_BYTES}"))
- \`lock.mdb\` apparent size before benchmark: ${LOCK_MDB_BEFORE_BYTES} bytes ($(human_bytes "${LOCK_MDB_BEFORE_BYTES}"))
- \`lock.mdb\` apparent size after benchmark: ${LOCK_MDB_AFTER_BYTES} bytes ($(human_bytes "${LOCK_MDB_AFTER_BYTES}"))

EOF

cat "${RESOURCE_SUMMARY}" >> "${REPORT_MD}"
printf "\n" >> "${REPORT_MD}"
cat "${CLIENT_SUMMARY}" >> "${REPORT_MD}"

echo "Report written to ${REPORT_MD}"
echo "Raw LDAP metrics: ${CLIENT_JSON}"
echo "Resource samples: ${RESOURCE_SAMPLES}"

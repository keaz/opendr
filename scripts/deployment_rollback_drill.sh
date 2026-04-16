#!/usr/bin/env bash
#
# Deployment rollback drill for OpenDR.
#
# The drill creates an isolated provider/consumer pair, proves replication,
# takes a provider backup, simulates a failed deployment write, restores the
# provider from the backup, reboots the consumer from a clean state, and verifies
# that restored data and live replication both work.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/.." && pwd)

DEPLOYMENT_DRILL_MODE="${DEPLOYMENT_DRILL_MODE:-smoke}"
case "${DEPLOYMENT_DRILL_MODE}" in
  smoke)
    DEFAULT_PROFILE=debug
    DEFAULT_LMDB_MAX_SIZE_BYTES=536870912
    ;;
  release)
    DEFAULT_PROFILE=release
    DEFAULT_LMDB_MAX_SIZE_BYTES=2147483648
    ;;
  --help|-h|help)
    DEFAULT_PROFILE=debug
    DEFAULT_LMDB_MAX_SIZE_BYTES=536870912
    ;;
  *)
    echo "DEPLOYMENT_DRILL_MODE must be smoke or release, got ${DEPLOYMENT_DRILL_MODE}" >&2
    exit 1
    ;;
esac

DEPLOYMENT_DRILL_OUTPUT_DIR="${DEPLOYMENT_DRILL_OUTPUT_DIR:-${REPO_ROOT}/target/deployment-rollback-drill/$(date +%Y%m%d-%H%M%S)}"
DEPLOYMENT_DRILL_PROFILE="${DEPLOYMENT_DRILL_PROFILE:-${DEFAULT_PROFILE}}"
DEPLOYMENT_DRILL_BASE_DN="${DEPLOYMENT_DRILL_BASE_DN:-dc=example,dc=org}"
DEPLOYMENT_DRILL_ROOT_RDN="${DEPLOYMENT_DRILL_ROOT_RDN:-cn=manager}"
DEPLOYMENT_DRILL_PROVIDER_ROOT_PASSWORD="${DEPLOYMENT_DRILL_PROVIDER_ROOT_PASSWORD:-DeploymentProviderSecret-${RANDOM}-$$}"
DEPLOYMENT_DRILL_CONSUMER_ROOT_PASSWORD="${DEPLOYMENT_DRILL_CONSUMER_ROOT_PASSWORD:-DeploymentConsumerSecret-${RANDOM}-$$}"
DEPLOYMENT_DRILL_LMDB_MAX_SIZE_BYTES="${DEPLOYMENT_DRILL_LMDB_MAX_SIZE_BYTES:-${DEFAULT_LMDB_MAX_SIZE_BYTES}}"
DEPLOYMENT_DRILL_PROVIDER_PORT="${DEPLOYMENT_DRILL_PROVIDER_PORT:-}"
DEPLOYMENT_DRILL_CONSUMER_PORT="${DEPLOYMENT_DRILL_CONSUMER_PORT:-}"
DEPLOYMENT_DRILL_WAIT_SECS="${DEPLOYMENT_DRILL_WAIT_SECS:-45}"
DEPLOYMENT_DRILL_BUILD="${DEPLOYMENT_DRILL_BUILD:-1}"

usage() {
  cat <<'EOF'
Usage: scripts/deployment_rollback_drill.sh

Environment:
  DEPLOYMENT_DRILL_MODE                    smoke or release (default: smoke)
  DEPLOYMENT_DRILL_OUTPUT_DIR              Artifact directory
  DEPLOYMENT_DRILL_PROFILE                 Cargo profile: debug or release
  DEPLOYMENT_DRILL_BASE_DN                 Naming context (default: dc=example,dc=org)
  DEPLOYMENT_DRILL_ROOT_RDN                Root RDN under base DN (default: cn=manager)
  DEPLOYMENT_DRILL_PROVIDER_ROOT_PASSWORD  Provider root bind password
  DEPLOYMENT_DRILL_CONSUMER_ROOT_PASSWORD  Consumer root bind password
  DEPLOYMENT_DRILL_LMDB_MAX_SIZE_BYTES     LMDB map size for both nodes
  DEPLOYMENT_DRILL_PROVIDER_PORT           Optional provider LDAP port
  DEPLOYMENT_DRILL_CONSUMER_PORT           Optional consumer LDAP port
  DEPLOYMENT_DRILL_WAIT_SECS               Server and replication timeout
  DEPLOYMENT_DRILL_BUILD                   Build required binaries, 1 or 0
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

if [[ "${DEPLOYMENT_DRILL_PROFILE}" != "debug" && "${DEPLOYMENT_DRILL_PROFILE}" != "release" ]]; then
  echo "DEPLOYMENT_DRILL_PROFILE must be debug or release" >&2
  exit 1
fi

case "${DEPLOYMENT_DRILL_OUTPUT_DIR}" in
  /*) ;;
  *) DEPLOYMENT_DRILL_OUTPUT_DIR="${REPO_ROOT}/${DEPLOYMENT_DRILL_OUTPUT_DIR}" ;;
esac

TARGET_ROOT="${CARGO_TARGET_DIR:-${REPO_ROOT}/target}"
case "${TARGET_ROOT}" in
  /*) ;;
  *) TARGET_ROOT="${REPO_ROOT}/${TARGET_ROOT}" ;;
esac

ARTIFACT_DIR="${DEPLOYMENT_DRILL_OUTPUT_DIR}"
CONFIG_DIR="${ARTIFACT_DIR}/config"
LOG_DIR="${ARTIFACT_DIR}/logs"
PROVIDER_DIR="${ARTIFACT_DIR}/provider"
CONSUMER_DIR="${ARTIFACT_DIR}/consumer"
PROVIDER_DATA_DIR="${PROVIDER_DIR}/data"
CONSUMER_DATA_DIR="${CONSUMER_DIR}/data"
PROVIDER_STATE_DIR="${PROVIDER_DIR}/replication_state"
CONSUMER_STATE_DIR="${CONSUMER_DIR}/replication_state"
BACKUP_DIR="${ARTIFACT_DIR}/provider-full-backup"
FAILED_PROVIDER_DATA_DIR="${ARTIFACT_DIR}/failed-provider-data"
FAILED_CONSUMER_DATA_DIR="${ARTIFACT_DIR}/failed-consumer-data"
FAILED_PROVIDER_STATE_DIR="${ARTIFACT_DIR}/failed-provider-replication-state"
FAILED_CONSUMER_STATE_DIR="${ARTIFACT_DIR}/failed-consumer-replication-state"
VALIDATION_DIR="${ARTIFACT_DIR}/validation"
SUMMARY_MD="${ARTIFACT_DIR}/summary.md"
LOG_CONFIG="${CONFIG_DIR}/log4rs.yml"
PROVIDER_CONFIG="${CONFIG_DIR}/provider.toml"
CONSUMER_CONFIG="${CONFIG_DIR}/consumer.toml"

ROOT_DN="${DEPLOYMENT_DRILL_ROOT_RDN},${DEPLOYMENT_DRILL_BASE_DN}"
PEOPLE_DN="ou=people,${DEPLOYMENT_DRILL_BASE_DN}"
BASELINE_UID="rollback-baseline"
FAILED_UID="failed-deployment-marker"
POST_ROLLBACK_UID="post-rollback-live"
BASELINE_DN="uid=${BASELINE_UID},${PEOPLE_DN}"
FAILED_DN="uid=${FAILED_UID},${PEOPLE_DN}"
POST_ROLLBACK_DN="uid=${POST_ROLLBACK_UID},${PEOPLE_DN}"

STATUS="running"
PROVIDER_PID=""
CONSUMER_PID=""
PROVIDER_PORT=""
CONSUMER_PORT=""
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

log() {
  printf '[deployment-drill] %s\n' "$*"
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

reserve_port() {
  python3 - <<'PY'
import socket
sock = socket.socket()
sock.bind(("127.0.0.1", 0))
print(sock.getsockname()[1])
sock.close()
PY
}

toml_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

write_summary() {
  mkdir -p "${ARTIFACT_DIR}"
  cat > "${SUMMARY_MD}" <<EOF
# OpenDR Deployment Rollback Drill

## Status

- Status: ${STATUS}
- Started at: ${STARTED_AT}
- Updated at: $(date -u +%Y-%m-%dT%H:%M:%SZ)
- Mode: ${DEPLOYMENT_DRILL_MODE}
- Cargo profile: ${DEPLOYMENT_DRILL_PROFILE}
- Cargo target directory: \`${TARGET_ROOT}\`

## Topology

- Provider URL: ldap://127.0.0.1:${PROVIDER_PORT}
- Consumer URL: ldap://127.0.0.1:${CONSUMER_PORT}
- Base DN: \`${DEPLOYMENT_DRILL_BASE_DN}\`
- Root DN: \`${ROOT_DN}\`

## Rollback Scenario

- Backup directory: \`${BACKUP_DIR}\`
- Failed provider data moved to: \`${FAILED_PROVIDER_DATA_DIR}\`
- Failed consumer data moved to: \`${FAILED_CONSUMER_DATA_DIR}\`
- Failed provider replication state moved to: \`${FAILED_PROVIDER_STATE_DIR}\`
- Failed consumer replication state moved to: \`${FAILED_CONSUMER_STATE_DIR}\`
- Baseline DN restored: \`${BASELINE_DN}\`
- Failed deployment marker rejected after rollback: \`${FAILED_DN}\`
- Post-rollback live replication DN: \`${POST_ROLLBACK_DN}\`
- Validation artifacts: \`${VALIDATION_DIR}\`
- Logs: \`${LOG_DIR}\`
EOF
}

stop_pid() {
  local pid="$1"
  local name="$2"

  if [[ -z "${pid}" ]] || ! kill -0 "${pid}" >/dev/null 2>&1; then
    return 0
  fi

  log "Stopping ${name} (${pid})"
  kill "${pid}" >/dev/null 2>&1 || true
  local deadline=$((SECONDS + 10))
  while kill -0 "${pid}" >/dev/null 2>&1; do
    if (( SECONDS >= deadline )); then
      kill -9 "${pid}" >/dev/null 2>&1 || true
      break
    fi
    sleep 0.2
  done
  wait "${pid}" >/dev/null 2>&1 || true
}

cleanup() {
  stop_pid "${CONSUMER_PID}" "consumer"
  stop_pid "${PROVIDER_PID}" "provider"
}

finish() {
  local code=$?
  if [[ "${code}" -eq 0 && "${STATUS}" == "running" ]]; then
    STATUS="passed"
  elif [[ "${code}" -ne 0 ]]; then
    STATUS="failed"
  fi
  write_summary || true
  if [[ "${code}" -ne 0 ]]; then
    log "Drill failed. Summary: ${SUMMARY_MD}"
    for log_file in "${LOG_DIR}"/*.log; do
      [[ -f "${log_file}" ]] || continue
      log "Tail of ${log_file}:"
      tail -n 30 "${log_file}" || true
    done
  fi
  cleanup
  exit "${code}"
}
trap finish EXIT

run_logged() {
  local label="$1"
  shift

  log "Running ${label}"
  if ! "$@" > "${LOG_DIR}/${label}.stdout.log" 2> "${LOG_DIR}/${label}.stderr.log"; then
    echo "${label} failed. stdout:" >&2
    cat "${LOG_DIR}/${label}.stdout.log" >&2 || true
    echo "${label} failed. stderr:" >&2
    cat "${LOG_DIR}/${label}.stderr.log" >&2 || true
    exit 1
  fi
}

write_log_config() {
  cat > "${LOG_CONFIG}" <<'EOF'
appenders:
  stdout:
    kind: console
root:
  level: info
  appenders:
    - stdout
EOF
}

write_provider_config() {
  local hashed_root_password="$1"
  local root_password_file="${PROVIDER_CONFIG}.root-password.hash"

  printf '%s\n' "${hashed_root_password}" > "${root_password_file}"
  chmod 600 "${root_password_file}"

  cat > "${PROVIDER_CONFIG}" <<EOF
[server]
runtime = "fsm"
bind_address = "127.0.0.1"
ldap_port = ${PROVIDER_PORT}
base_dn = "${DEPLOYMENT_DRILL_BASE_DN}"
root_user_dn = "${DEPLOYMENT_DRILL_ROOT_RDN}"
root_password_file = "$(toml_escape "${root_password_file}")"
organization_name = "OpenDR Deployment Rollback Drill Provider"
replica_id = 1

[backend]
backend_type = "lmdb"
data_directory = "$(toml_escape "${PROVIDER_DATA_DIR}")"
lmdb_max_size = ${DEPLOYMENT_DRILL_LMDB_MAX_SIZE_BYTES}
lmdb_max_readers = 256
indexed_attributes = ["cn", "uid", "mail", "objectClass"]

[schema]
enabled = true
schema_dir = "$(toml_escape "${REPO_ROOT}/config/schema")"
load_builtin = ["core"]
strict_validation = true
allow_online_updates = false

[tls]
enabled = false

[replication]
enabled = true
mode = "provider"
changelog_enabled = true
changelog_capacity = 1000
max_concurrent_consumers = 10
consumer_timeout_secs = 60
state_storage_path = "$(toml_escape "${PROVIDER_STATE_DIR}")"

[monitoring]
enabled = false

[audit]
enabled = false

[access_control]
enabled = false

[rate_limit]
enabled = false

[performance]
schema_validation = true
indexing_enabled = true
cache_size = 1000
query_optimization = true
EOF
}

write_consumer_config() {
  local hashed_root_password="$1"
  local root_password_file="${CONSUMER_CONFIG}.root-password.hash"

  printf '%s\n' "${hashed_root_password}" > "${root_password_file}"
  chmod 600 "${root_password_file}"

  cat > "${CONSUMER_CONFIG}" <<EOF
[server]
runtime = "fsm"
bind_address = "127.0.0.1"
ldap_port = ${CONSUMER_PORT}
base_dn = "${DEPLOYMENT_DRILL_BASE_DN}"
root_user_dn = "${DEPLOYMENT_DRILL_ROOT_RDN}"
root_password_file = "$(toml_escape "${root_password_file}")"
organization_name = "OpenDR Deployment Rollback Drill Consumer"
replica_id = 2

[backend]
backend_type = "lmdb"
data_directory = "$(toml_escape "${CONSUMER_DATA_DIR}")"
lmdb_max_size = ${DEPLOYMENT_DRILL_LMDB_MAX_SIZE_BYTES}
lmdb_max_readers = 256
indexed_attributes = ["cn", "uid", "mail", "objectClass"]

[schema]
enabled = true
schema_dir = "$(toml_escape "${REPO_ROOT}/config/schema")"
load_builtin = ["core"]
strict_validation = true
allow_online_updates = false

[tls]
enabled = false

[replication]
enabled = true
mode = "consumer"
provider_url = "ldap://127.0.0.1:${PROVIDER_PORT}"
allow_insecure_provider_bind = true
bind_dn = "${ROOT_DN}"
bind_password = "${DEPLOYMENT_DRILL_PROVIDER_ROOT_PASSWORD}"
sync_interval_secs = 1
max_batch_size = 100
enable_change_listening = true
provider_timeout_secs = 15
state_storage_path = "$(toml_escape "${CONSUMER_STATE_DIR}")"

[monitoring]
enabled = false

[audit]
enabled = false

[access_control]
enabled = false

[rate_limit]
enabled = false

[performance]
schema_validation = true
indexing_enabled = true
cache_size = 1000
query_optimization = true
EOF
}

start_server() {
  local name="$1"
  local config="$2"
  local stdout_log="${LOG_DIR}/${name}.stdout.log"
  local stderr_log="${LOG_DIR}/${name}.stderr.log"

  log "Starting ${name}"
  "${OPENDR_BIN}" --config "${config}" --log-config "${LOG_CONFIG}" \
    > "${stdout_log}" 2> "${stderr_log}" &
  local pid=$!

  if [[ "${name}" == "provider" ]]; then
    PROVIDER_PID="${pid}"
  else
    CONSUMER_PID="${pid}"
  fi
}

wait_for_ldap() {
  local port="$1"
  local password="$2"
  local label="$3"
  local deadline=$((SECONDS + DEPLOYMENT_DRILL_WAIT_SECS))

  while (( SECONDS < deadline )); do
    if ldapsearch -LLL -o ldif-wrap=no -x -H "ldap://127.0.0.1:${port}" \
      -D "${ROOT_DN}" -w "${password}" -b "" -s base "(objectClass=*)" namingContexts \
      >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done

  echo "timed out waiting for ${label} LDAP listener on port ${port}" >&2
  exit 1
}

ldapsearch_root() {
  local port="$1"
  local password="$2"
  shift 2
  ldapsearch -LLL -o ldif-wrap=no -x -H "ldap://127.0.0.1:${port}" \
    -D "${ROOT_DN}" -w "${password}" "$@"
}

ldapadd_root() {
  local port="$1"
  local password="$2"
  local ldif="$3"

  ldapadd -x -H "ldap://127.0.0.1:${port}" -D "${ROOT_DN}" -w "${password}" \
    -f "${ldif}"
}

entry_exists() {
  local port="$1"
  local password="$2"
  local uid="$3"

  ldapsearch_root "${port}" "${password}" -b "${DEPLOYMENT_DRILL_BASE_DN}" -s sub \
    "(uid=${uid})" dn 2>/dev/null | grep -qi "^dn: uid=${uid},"
}

wait_for_entry() {
  local port="$1"
  local password="$2"
  local uid="$3"
  local label="$4"
  local deadline=$((SECONDS + DEPLOYMENT_DRILL_WAIT_SECS))

  while (( SECONDS < deadline )); do
    if entry_exists "${port}" "${password}" "${uid}"; then
      return 0
    fi
    sleep 0.5
  done

  echo "timed out waiting for ${label} (${uid}) on port ${port}" >&2
  exit 1
}

require_entry_absent() {
  local port="$1"
  local password="$2"
  local uid="$3"
  local label="$4"

  if entry_exists "${port}" "${password}" "${uid}"; then
    echo "${label}: unexpected uid=${uid} was present after rollback" >&2
    exit 1
  fi
}

ensure_base_tree() {
  local base_ldif="${VALIDATION_DIR}/base.ldif"
  local people_ldif="${VALIDATION_DIR}/people.ldif"
  local dc_value
  dc_value=$(printf '%s' "${DEPLOYMENT_DRILL_BASE_DN}" | sed -n 's/^dc=\([^,]*\).*/\1/p')

  cat > "${base_ldif}" <<EOF
dn: ${DEPLOYMENT_DRILL_BASE_DN}
objectClass: top
objectClass: domain
dc: ${dc_value}
EOF

  cat > "${people_ldif}" <<EOF
dn: ${PEOPLE_DN}
objectClass: top
objectClass: organizationalUnit
ou: people
EOF

  ldapadd_root "${PROVIDER_PORT}" "${DEPLOYMENT_DRILL_PROVIDER_ROOT_PASSWORD}" "${base_ldif}" \
    > "${LOG_DIR}/ldapadd-base.stdout.log" 2> "${LOG_DIR}/ldapadd-base.stderr.log" || true
  ldapadd_root "${PROVIDER_PORT}" "${DEPLOYMENT_DRILL_PROVIDER_ROOT_PASSWORD}" "${people_ldif}" \
    > "${LOG_DIR}/ldapadd-people.stdout.log" 2> "${LOG_DIR}/ldapadd-people.stderr.log" || true
}

write_marker_ldif() {
  local uid="$1"
  local cn="$2"
  local description="$3"
  local output="$4"

  cat > "${output}" <<EOF
dn: uid=${uid},${PEOPLE_DN}
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: ${cn}
sn: ${uid}
uid: ${uid}
mail: ${uid}@example.org
description: ${description}
userPassword: MarkerPassword123!
EOF
}

mkdir -p "${CONFIG_DIR}" "${LOG_DIR}" "${PROVIDER_DATA_DIR}" "${CONSUMER_DATA_DIR}" \
  "${PROVIDER_STATE_DIR}" "${CONSUMER_STATE_DIR}" "${VALIDATION_DIR}"

require_command cargo
require_command python3
require_command ldapadd
require_command ldapsearch

if [[ -z "${DEPLOYMENT_DRILL_PROVIDER_PORT}" ]]; then
  PROVIDER_PORT=$(reserve_port)
else
  PROVIDER_PORT="${DEPLOYMENT_DRILL_PROVIDER_PORT}"
fi

if [[ -z "${DEPLOYMENT_DRILL_CONSUMER_PORT}" ]]; then
  CONSUMER_PORT=$(reserve_port)
else
  CONSUMER_PORT="${DEPLOYMENT_DRILL_CONSUMER_PORT}"
fi

log "Artifacts: ${ARTIFACT_DIR}"
write_summary

BUILD_ARGS=(build --bin opendr --bin opendr-setup --bin opendr-backup --bin opendr-restore)
if [[ "${DEPLOYMENT_DRILL_PROFILE}" == "release" ]]; then
  BUILD_ARGS+=(--release)
fi
if [[ "${DEPLOYMENT_DRILL_BUILD}" == "1" ]]; then
  run_logged build cargo "${BUILD_ARGS[@]}"
fi

BIN_DIR="${TARGET_ROOT}/${DEPLOYMENT_DRILL_PROFILE}"
OPENDR_BIN="${BIN_DIR}/opendr"
SETUP_BIN="${BIN_DIR}/opendr-setup"
BACKUP_BIN="${BIN_DIR}/opendr-backup"
RESTORE_BIN="${BIN_DIR}/opendr-restore"

for bin in "${OPENDR_BIN}" "${SETUP_BIN}" "${BACKUP_BIN}" "${RESTORE_BIN}"; do
  if [[ ! -x "${bin}" ]]; then
    echo "required binary is missing or not executable: ${bin}" >&2
    exit 1
  fi
done

PROVIDER_HASHED_PASSWORD=$("${SETUP_BIN}" hash-password "${DEPLOYMENT_DRILL_PROVIDER_ROOT_PASSWORD}" | tail -n 1)
CONSUMER_HASHED_PASSWORD=$("${SETUP_BIN}" hash-password "${DEPLOYMENT_DRILL_CONSUMER_ROOT_PASSWORD}" | tail -n 1)

write_log_config
write_provider_config "${PROVIDER_HASHED_PASSWORD}"
write_consumer_config "${CONSUMER_HASHED_PASSWORD}"

start_server provider "${PROVIDER_CONFIG}"
wait_for_ldap "${PROVIDER_PORT}" "${DEPLOYMENT_DRILL_PROVIDER_ROOT_PASSWORD}" "provider"
ensure_base_tree

BASELINE_LDIF="${VALIDATION_DIR}/baseline.ldif"
FAILED_LDIF="${VALIDATION_DIR}/failed-marker.ldif"
POST_ROLLBACK_LDIF="${VALIDATION_DIR}/post-rollback.ldif"
write_marker_ldif "${BASELINE_UID}" "Rollback Baseline" "entry created before backup and expected after rollback" "${BASELINE_LDIF}"
write_marker_ldif "${FAILED_UID}" "Failed Deployment Marker" "entry created after backup and expected to disappear after rollback" "${FAILED_LDIF}"
write_marker_ldif "${POST_ROLLBACK_UID}" "Post Rollback Live" "entry created after rollback to prove live replication still works" "${POST_ROLLBACK_LDIF}"

run_logged ldapadd-baseline ldapadd -x -H "ldap://127.0.0.1:${PROVIDER_PORT}" \
  -D "${ROOT_DN}" -w "${DEPLOYMENT_DRILL_PROVIDER_ROOT_PASSWORD}" -f "${BASELINE_LDIF}"
wait_for_entry "${PROVIDER_PORT}" "${DEPLOYMENT_DRILL_PROVIDER_ROOT_PASSWORD}" "${BASELINE_UID}" "provider baseline"

run_logged provider-full-backup "${BACKUP_BIN}" --config "${PROVIDER_CONFIG}" --json full \
  --target "${BACKUP_DIR}"
run_logged provider-backup-inspect "${BACKUP_BIN}" --config "${PROVIDER_CONFIG}" --json inspect \
  --backup "${BACKUP_DIR}"
run_logged provider-restore-dry-run "${RESTORE_BIN}" --backup "${BACKUP_DIR}" \
  --target-data-dir "${ARTIFACT_DIR}/dry-run-target" --dry-run --json

start_server consumer "${CONSUMER_CONFIG}"
wait_for_ldap "${CONSUMER_PORT}" "${DEPLOYMENT_DRILL_CONSUMER_ROOT_PASSWORD}" "consumer"
wait_for_entry "${CONSUMER_PORT}" "${DEPLOYMENT_DRILL_CONSUMER_ROOT_PASSWORD}" "${BASELINE_UID}" "consumer baseline replication"

run_logged ldapadd-failed-marker ldapadd -x -H "ldap://127.0.0.1:${PROVIDER_PORT}" \
  -D "${ROOT_DN}" -w "${DEPLOYMENT_DRILL_PROVIDER_ROOT_PASSWORD}" -f "${FAILED_LDIF}"
wait_for_entry "${PROVIDER_PORT}" "${DEPLOYMENT_DRILL_PROVIDER_ROOT_PASSWORD}" "${FAILED_UID}" "provider failed marker"
wait_for_entry "${CONSUMER_PORT}" "${DEPLOYMENT_DRILL_CONSUMER_ROOT_PASSWORD}" "${FAILED_UID}" "consumer failed marker"

log "Simulating rollback by stopping both nodes and restoring the provider backup"
stop_pid "${CONSUMER_PID}" "consumer"
CONSUMER_PID=""
stop_pid "${PROVIDER_PID}" "provider"
PROVIDER_PID=""

mv "${PROVIDER_DATA_DIR}" "${FAILED_PROVIDER_DATA_DIR}"
mv "${CONSUMER_DATA_DIR}" "${FAILED_CONSUMER_DATA_DIR}"
mv "${PROVIDER_STATE_DIR}" "${FAILED_PROVIDER_STATE_DIR}"
mv "${CONSUMER_STATE_DIR}" "${FAILED_CONSUMER_STATE_DIR}"
mkdir -p "${CONSUMER_DATA_DIR}" "${CONSUMER_STATE_DIR}" "${PROVIDER_STATE_DIR}"

run_logged provider-rollback-restore "${RESTORE_BIN}" --backup "${BACKUP_DIR}" \
  --target-data-dir "${PROVIDER_DATA_DIR}" --json

start_server provider "${PROVIDER_CONFIG}"
wait_for_ldap "${PROVIDER_PORT}" "${DEPLOYMENT_DRILL_PROVIDER_ROOT_PASSWORD}" "restored provider"
wait_for_entry "${PROVIDER_PORT}" "${DEPLOYMENT_DRILL_PROVIDER_ROOT_PASSWORD}" "${BASELINE_UID}" "restored provider baseline"
require_entry_absent "${PROVIDER_PORT}" "${DEPLOYMENT_DRILL_PROVIDER_ROOT_PASSWORD}" "${FAILED_UID}" "restored provider validation"

start_server consumer "${CONSUMER_CONFIG}"
wait_for_ldap "${CONSUMER_PORT}" "${DEPLOYMENT_DRILL_CONSUMER_ROOT_PASSWORD}" "rebootstrapped consumer"
wait_for_entry "${CONSUMER_PORT}" "${DEPLOYMENT_DRILL_CONSUMER_ROOT_PASSWORD}" "${BASELINE_UID}" "rebootstrapped consumer baseline"
require_entry_absent "${CONSUMER_PORT}" "${DEPLOYMENT_DRILL_CONSUMER_ROOT_PASSWORD}" "${FAILED_UID}" "rebootstrapped consumer validation"

run_logged ldapadd-post-rollback ldapadd -x -H "ldap://127.0.0.1:${PROVIDER_PORT}" \
  -D "${ROOT_DN}" -w "${DEPLOYMENT_DRILL_PROVIDER_ROOT_PASSWORD}" -f "${POST_ROLLBACK_LDIF}"
wait_for_entry "${PROVIDER_PORT}" "${DEPLOYMENT_DRILL_PROVIDER_ROOT_PASSWORD}" "${POST_ROLLBACK_UID}" "provider post-rollback marker"
wait_for_entry "${CONSUMER_PORT}" "${DEPLOYMENT_DRILL_CONSUMER_ROOT_PASSWORD}" "${POST_ROLLBACK_UID}" "consumer post-rollback live replication"

ldapsearch_root "${PROVIDER_PORT}" "${DEPLOYMENT_DRILL_PROVIDER_ROOT_PASSWORD}" \
  -b "${BASELINE_DN}" -s base "(objectClass=inetOrgPerson)" uid cn description \
  > "${VALIDATION_DIR}/restored-provider-baseline.ldif"
ldapsearch_root "${CONSUMER_PORT}" "${DEPLOYMENT_DRILL_CONSUMER_ROOT_PASSWORD}" \
  -b "${POST_ROLLBACK_DN}" -s base "(objectClass=inetOrgPerson)" uid cn description \
  > "${VALIDATION_DIR}/consumer-post-rollback-live.ldif"

STATUS="passed"
write_summary

log "Deployment rollback drill passed"
log "Summary: ${SUMMARY_MD}"

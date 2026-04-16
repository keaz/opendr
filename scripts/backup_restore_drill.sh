#!/usr/bin/env bash
#
# Production-readiness backup/restore drill for LMDB deployments.
#
# Smoke mode creates a modest fixture and proves backup, restore, and restored
# LDAP behavior. Release mode uses the same flow with larger defaults intended
# to be overridden to match the target production data volume.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/.." && pwd)

BACKUP_DRILL_MODE="${BACKUP_DRILL_MODE:-smoke}"
case "${BACKUP_DRILL_MODE}" in
  smoke)
    DEFAULT_USERS=500
    DEFAULT_LMDB_MAX_SIZE_BYTES=1073741824
    DEFAULT_BATCH_SIZE=500
    DEFAULT_PROFILE=debug
    ;;
  release)
    DEFAULT_USERS=100000
    DEFAULT_LMDB_MAX_SIZE_BYTES=8589934592
    DEFAULT_BATCH_SIZE=10000
    DEFAULT_PROFILE=release
    ;;
  --help|-h|help)
    DEFAULT_USERS=500
    DEFAULT_LMDB_MAX_SIZE_BYTES=1073741824
    DEFAULT_BATCH_SIZE=500
    DEFAULT_PROFILE=debug
    ;;
  *)
    echo "BACKUP_DRILL_MODE must be smoke or release, got ${BACKUP_DRILL_MODE}" >&2
    exit 1
    ;;
esac

BACKUP_DRILL_OUTPUT_DIR="${BACKUP_DRILL_OUTPUT_DIR:-${REPO_ROOT}/target/backup-restore-drill/$(date +%Y%m%d-%H%M%S)}"
BACKUP_DRILL_PROFILE="${BACKUP_DRILL_PROFILE:-${DEFAULT_PROFILE}}"
BACKUP_DRILL_USERS="${BACKUP_DRILL_USERS:-${DEFAULT_USERS}}"
BACKUP_DRILL_BATCH_SIZE="${BACKUP_DRILL_BATCH_SIZE:-${DEFAULT_BATCH_SIZE}}"
BACKUP_DRILL_LMDB_MAX_SIZE_BYTES="${BACKUP_DRILL_LMDB_MAX_SIZE_BYTES:-${DEFAULT_LMDB_MAX_SIZE_BYTES}}"
BACKUP_DRILL_BASE_DN="${BACKUP_DRILL_BASE_DN:-dc=example,dc=com}"
BACKUP_DRILL_ROOT_RDN="${BACKUP_DRILL_ROOT_RDN:-cn=admin}"
BACKUP_DRILL_ROOT_PASSWORD="${BACKUP_DRILL_ROOT_PASSWORD:-BackupRestoreRootSecret123!}"
BACKUP_DRILL_USER_PASSWORD="${BACKUP_DRILL_USER_PASSWORD:-BackupRestoreUserSecret123!}"
BACKUP_DRILL_NAME_PREFIX="${BACKUP_DRILL_NAME_PREFIX:-restoredrill}"
BACKUP_DRILL_RUNTIME="${BACKUP_DRILL_RUNTIME:-fsm}"
BACKUP_DRILL_PORT="${BACKUP_DRILL_PORT:-}"
BACKUP_DRILL_COMPACT="${BACKUP_DRILL_COMPACT:-0}"
BACKUP_DRILL_WAIT_SECS="${BACKUP_DRILL_WAIT_SECS:-30}"

usage() {
  cat <<'EOF'
Usage: scripts/backup_restore_drill.sh

Environment:
  BACKUP_DRILL_MODE                 smoke or release (default: smoke)
  BACKUP_DRILL_OUTPUT_DIR           Artifact directory
  BACKUP_DRILL_PROFILE              Cargo profile: debug or release
  BACKUP_DRILL_USERS                Fixture user count
  BACKUP_DRILL_BATCH_SIZE           Offline loader batch size
  BACKUP_DRILL_LMDB_MAX_SIZE_BYTES  LMDB map size for fixture and restored server
  BACKUP_DRILL_BASE_DN              Fixture naming context (default: dc=example,dc=com)
  BACKUP_DRILL_ROOT_RDN             Root RDN under base DN (default: cn=admin)
  BACKUP_DRILL_ROOT_PASSWORD        Root bind password for validation
  BACKUP_DRILL_USER_PASSWORD        Fixture user bind password for validation
  BACKUP_DRILL_NAME_PREFIX          Fixture OU and user prefix (default: restoredrill)
  BACKUP_DRILL_RUNTIME              Server runtime for restored validation: fsm or legacy
  BACKUP_DRILL_PORT                 Optional restored LDAP port
  BACKUP_DRILL_COMPACT              Use compact LMDB full backup, 1 or 0 (default: 0)
  BACKUP_DRILL_WAIT_SECS            Restored server readiness timeout (default: 30)
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

if [[ "${BACKUP_DRILL_PROFILE}" != "debug" && "${BACKUP_DRILL_PROFILE}" != "release" ]]; then
  echo "BACKUP_DRILL_PROFILE must be debug or release" >&2
  exit 1
fi

if [[ "${BACKUP_DRILL_RUNTIME}" != "fsm" && "${BACKUP_DRILL_RUNTIME}" != "legacy" ]]; then
  echo "BACKUP_DRILL_RUNTIME must be fsm or legacy" >&2
  exit 1
fi

case "${BACKUP_DRILL_OUTPUT_DIR}" in
  /*) ;;
  *) BACKUP_DRILL_OUTPUT_DIR="${REPO_ROOT}/${BACKUP_DRILL_OUTPUT_DIR}" ;;
esac

ROOT_DN="${BACKUP_DRILL_ROOT_RDN},${BACKUP_DRILL_BASE_DN}"
USERS_OU_DN="ou=users,ou=${BACKUP_DRILL_NAME_PREFIX},${BACKUP_DRILL_BASE_DN}"
FIRST_UID="${BACKUP_DRILL_NAME_PREFIX}-user-000000"
FIRST_USER_DN="uid=${FIRST_UID},${USERS_OU_DN}"
FIRST_USER_MAIL="${FIRST_UID}@example.com"
LAST_INDEX=$((BACKUP_DRILL_USERS - 1))
LAST_UID=$(printf "%s-user-%06d" "${BACKUP_DRILL_NAME_PREFIX}" "${LAST_INDEX}")
LAST_USER_DN="uid=${LAST_UID},${USERS_OU_DN}"

ARTIFACT_DIR="${BACKUP_DRILL_OUTPUT_DIR}"
RUNTIME_DIR="${ARTIFACT_DIR}/runtime"
CONFIG_DIR="${RUNTIME_DIR}/config"
SOURCE_DATA_DIR="${RUNTIME_DIR}/source-data"
SOURCE_STATE_DIR="${RUNTIME_DIR}/source-state"
RESTORED_DATA_DIR="${RUNTIME_DIR}/restored-data"
RESTORED_STATE_DIR="${RUNTIME_DIR}/restored-state"
BACKUP_DIR="${ARTIFACT_DIR}/full-backup"
VALIDATION_DIR="${ARTIFACT_DIR}/validation"
LOG_DIR="${ARTIFACT_DIR}/logs"
SUMMARY_MD="${ARTIFACT_DIR}/summary.md"

SOURCE_CONFIG="${CONFIG_DIR}/source-server.toml"
RESTORED_CONFIG="${CONFIG_DIR}/restored-server.toml"
LOG_CONFIG="${CONFIG_DIR}/log4rs.yml"

STATUS="running"
SERVER_PID=""
SOURCE_LDAP_PORT=""
SOURCE_LDAPS_PORT=""
RESTORED_LDAP_PORT=""
RESTORED_LDAPS_PORT=""
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
BUILD_DURATION_SECS="n/a"
LOAD_DURATION_SECS="n/a"
BACKUP_DURATION_SECS="n/a"
RESTORE_DRY_RUN_DURATION_SECS="n/a"
RESTORE_DURATION_SECS="n/a"
VALIDATION_DURATION_SECS="n/a"
SOURCE_SIZE_BYTES="0"
BACKUP_SIZE_BYTES="0"
RESTORED_SIZE_BYTES="0"
FINAL_CONTEXT_CSN="n/a"

log() {
  printf '[backup-drill] %s\n' "$*"
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
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

format_duration() {
  local value="$1"
  if [[ "${value}" == "n/a" ]]; then
    printf 'n/a'
  else
    printf '%ss' "${value}"
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

write_log_config() {
  cat > "${LOG_CONFIG}" <<'EOF'
appenders:
  stdout:
    kind: console
root:
  level: error
  appenders:
    - stdout
EOF
}

write_server_config() {
  local path="$1"
  local data_dir="$2"
  local state_dir="$3"
  local ldap_port="$4"
  local ldaps_port="$5"
  local hashed_root_password="$6"

  cat > "${path}" <<EOF
[server]
runtime = "${BACKUP_DRILL_RUNTIME}"
bind_address = "127.0.0.1"
ldap_port = ${ldap_port}
ldaps_port = ${ldaps_port}
base_dn = "${BACKUP_DRILL_BASE_DN}"
root_user_dn = "${BACKUP_DRILL_ROOT_RDN}"
root_password = "${hashed_root_password}"
organization_name = "OpenDR Backup Restore Drill"
replica_id = 1

[backend]
backend_type = "lmdb"
data_directory = "$(toml_escape "${data_dir}")"
lmdb_max_size = ${BACKUP_DRILL_LMDB_MAX_SIZE_BYTES}
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
changelog_capacity = 10000
state_storage_path = "$(toml_escape "${state_dir}")"

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

write_summary() {
  mkdir -p "${ARTIFACT_DIR}"
  cat > "${SUMMARY_MD}" <<EOF
# OpenDR Backup/Restore Drill

## Status

- Status: ${STATUS}
- Started at: ${STARTED_AT}
- Updated at: $(date -u +%Y-%m-%dT%H:%M:%SZ)
- Mode: ${BACKUP_DRILL_MODE}
- Runtime: ${BACKUP_DRILL_RUNTIME}
- Cargo profile: ${BACKUP_DRILL_PROFILE}

## Fixture

- Base DN: \`${BACKUP_DRILL_BASE_DN}\`
- Root DN: \`${ROOT_DN}\`
- Fixture users: ${BACKUP_DRILL_USERS}
- Loader batch size: ${BACKUP_DRILL_BATCH_SIZE}
- LMDB map size: ${BACKUP_DRILL_LMDB_MAX_SIZE_BYTES} bytes ($(human_bytes "${BACKUP_DRILL_LMDB_MAX_SIZE_BYTES}"))
- Source data size: ${SOURCE_SIZE_BYTES} bytes ($(human_bytes "${SOURCE_SIZE_BYTES}"))
- Backup size: ${BACKUP_SIZE_BYTES} bytes ($(human_bytes "${BACKUP_SIZE_BYTES}"))
- Restored data size: ${RESTORED_SIZE_BYTES} bytes ($(human_bytes "${RESTORED_SIZE_BYTES}"))

## Timing

- Build duration: $(format_duration "${BUILD_DURATION_SECS}")
- Fixture load duration: $(format_duration "${LOAD_DURATION_SECS}")
- Full backup duration: $(format_duration "${BACKUP_DURATION_SECS}")
- Restore dry-run duration: $(format_duration "${RESTORE_DRY_RUN_DURATION_SECS}")
- Restore duration: $(format_duration "${RESTORE_DURATION_SECS}")
- Restored LDAP validation duration: $(format_duration "${VALIDATION_DURATION_SECS}")

## Validation

- Restored LDAP URL: ldap://127.0.0.1:${RESTORED_LDAP_PORT}
- First fixture user: \`${FIRST_USER_DN}\`
- Last fixture user: \`${LAST_USER_DN}\`
- Final contextCSN: \`${FINAL_CONTEXT_CSN}\`
- Validation artifacts: \`${VALIDATION_DIR}\`
- Server logs: \`${LOG_DIR}\`
EOF
}

cleanup() {
  if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" >/dev/null 2>&1; then
    kill "${SERVER_PID}" >/dev/null 2>&1 || true
    wait "${SERVER_PID}" >/dev/null 2>&1 || true
  fi
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
    if [[ -f "${LOG_DIR}/restored-server.stdout.log" ]]; then
      log "Restored server stdout tail:"
      tail -n 40 "${LOG_DIR}/restored-server.stdout.log" || true
    fi
    if [[ -f "${LOG_DIR}/restored-server.stderr.log" ]]; then
      log "Restored server stderr tail:"
      tail -n 40 "${LOG_DIR}/restored-server.stderr.log" || true
    fi
  fi
  cleanup
  exit "${code}"
}
trap finish EXIT

run_logged() {
  local label="$1"
  shift
  local stdout="${LOG_DIR}/${label}.stdout.log"
  local stderr="${LOG_DIR}/${label}.stderr.log"

  log "Running ${label}"
  if ! "$@" > "${stdout}" 2> "${stderr}"; then
    echo "${label} failed. stdout:" >&2
    cat "${stdout}" >&2 || true
    echo "${label} failed. stderr:" >&2
    cat "${stderr}" >&2 || true
    exit 1
  fi
}

wait_for_restored_server() {
  local url="ldap://127.0.0.1:${RESTORED_LDAP_PORT}"
  local deadline=$((SECONDS + BACKUP_DRILL_WAIT_SECS))
  while (( SECONDS < deadline )); do
    if [[ -n "${SERVER_PID}" ]] && ! kill -0 "${SERVER_PID}" >/dev/null 2>&1; then
      echo "restored server exited before readiness" >&2
      return 1
    fi

    if ldapsearch -LLL -o ldif-wrap=no -x -H "${url}" -D "${ROOT_DN}" \
      -w "${BACKUP_DRILL_ROOT_PASSWORD}" -b "" -s base "(objectClass=*)" namingContexts \
      >/dev/null 2>&1; then
      return 0
    fi

    sleep 0.25
  done

  echo "timed out waiting for restored LDAP server on ${url}" >&2
  return 1
}

ldapsearch_root() {
  ldapsearch -LLL -o ldif-wrap=no -x -H "ldap://127.0.0.1:${RESTORED_LDAP_PORT}" \
    -D "${ROOT_DN}" -w "${BACKUP_DRILL_ROOT_PASSWORD}" "$@"
}

ldapsearch_as_user() {
  ldapsearch -LLL -o ldif-wrap=no -x -H "ldap://127.0.0.1:${RESTORED_LDAP_PORT}" \
    -D "${FIRST_USER_DN}" -w "${BACKUP_DRILL_USER_PASSWORD}" "$@"
}

count_dns() {
  grep -c '^dn:' "$1" || true
}

require_count() {
  local file="$1"
  local expected="$2"
  local label="$3"
  local actual
  actual=$(count_dns "${file}")
  if [[ "${actual}" != "${expected}" ]]; then
    echo "${label}: expected ${expected} entries, got ${actual}. See ${file}" >&2
    exit 1
  fi
}

require_ldif_line() {
  local file="$1"
  local expected="$2"
  local label="$3"
  if ! awk -v expected="${expected}" 'tolower($0) == tolower(expected) { found = 1 } END { exit found ? 0 : 1 }' "${file}"; then
    echo "${label}: expected LDIF line ${expected}. See ${file}" >&2
    exit 1
  fi
}

require_ldif_attr_present() {
  local file="$1"
  local attr="$2"
  local label="$3"
  if ! awk -v attr="${attr}" 'index(tolower($0), tolower(attr) ":") == 1 { found = 1 } END { exit found ? 0 : 1 }' "${file}"; then
    echo "${label}: expected LDIF attribute ${attr}. See ${file}" >&2
    exit 1
  fi
}

validate_context_csn() {
  python3 - "${LOG_DIR}/full-backup.stdout.log" "${LOG_DIR}/restore.stdout.log" "${VALIDATION_DIR}/context-csn.json" <<'PY'
import json
import sys
from pathlib import Path

manifest_path = Path(sys.argv[1])
restore_path = Path(sys.argv[2])
output_path = Path(sys.argv[3])

manifest = json.loads(manifest_path.read_text())
restore = json.loads(restore_path.read_text())
checkpoint = manifest.get("checkpoint") or {}
expected = (
    checkpoint.get("snapshot_context_csn")
    or checkpoint.get("end_context_csn")
    or checkpoint.get("start_context_csn")
)
actual = restore.get("final_context_csn")

payload = {
    "expected_context_csn": expected,
    "restored_final_context_csn": actual,
    "backup_id": manifest.get("backup_id"),
    "full_backup_id": restore.get("full_backup_id"),
}
output_path.write_text(json.dumps(payload, indent=2) + "\n")
print(actual or "n/a")

if expected and actual != expected:
    raise SystemExit(
        f"restored final_context_csn mismatch: expected {expected!r}, got {actual!r}"
    )
PY
}

validate_restored_ldap() {
  local started=$SECONDS
  local rootdse_ldif="${VALIDATION_DIR}/rootdse.ldif"
  local base_ldif="${VALIDATION_DIR}/base-entry.ldif"
  local first_user_ldif="${VALIDATION_DIR}/first-user.ldif"
  local last_user_ldif="${VALIDATION_DIR}/last-user.ldif"
  local uid_search_ldif="${VALIDATION_DIR}/uid-index-search.ldif"
  local mail_search_ldif="${VALIDATION_DIR}/mail-index-search.ldif"
  local count_search_ldif="${VALIDATION_DIR}/objectclass-count-search.ldif"
  local user_bind_ldif="${VALIDATION_DIR}/user-bind-search.ldif"
  local operational_ldif="${VALIDATION_DIR}/operational-attrs.ldif"

  log "Validating restored LDAP instance"
  ldapsearch_root -b "" -s base "(objectClass=*)" namingContexts contextCSN > "${rootdse_ldif}"
  ldapsearch_root -b "${BACKUP_DRILL_BASE_DN}" -s base "(objectClass=organization)" o description > "${base_ldif}"
  ldapsearch_root -b "${FIRST_USER_DN}" -s base "(objectClass=inetOrgPerson)" uid cn sn mail > "${first_user_ldif}"
  ldapsearch_root -b "${LAST_USER_DN}" -s base "(objectClass=inetOrgPerson)" uid cn sn mail > "${last_user_ldif}"
  ldapsearch_root -b "${BACKUP_DRILL_BASE_DN}" -s sub "(uid=${FIRST_UID})" dn uid > "${uid_search_ldif}"
  ldapsearch_root -b "${BACKUP_DRILL_BASE_DN}" -s sub "(mail=${FIRST_USER_MAIL})" dn mail > "${mail_search_ldif}"
  ldapsearch_root -b "${USERS_OU_DN}" -s one "(objectClass=inetOrgPerson)" dn > "${count_search_ldif}"
  ldapsearch_as_user -b "${FIRST_USER_DN}" -s base "(objectClass=inetOrgPerson)" uid > "${user_bind_ldif}"
  ldapsearch_root -b "${FIRST_USER_DN}" -s base "(objectClass=inetOrgPerson)" "+" > "${operational_ldif}"

  require_count "${base_ldif}" 1 "base entry restore validation"
  require_count "${first_user_ldif}" 1 "first user restore validation"
  require_count "${last_user_ldif}" 1 "last user restore validation"
  require_count "${uid_search_ldif}" 1 "uid indexed search validation"
  require_count "${mail_search_ldif}" 1 "mail indexed search validation"
  require_count "${count_search_ldif}" "${BACKUP_DRILL_USERS}" "objectClass search count validation"
  require_count "${user_bind_ldif}" 1 "restored fixture user bind validation"
  require_count "${operational_ldif}" 1 "operational attribute validation"

  require_ldif_line "${first_user_ldif}" "uid: ${FIRST_UID}" "first user uid validation"
  require_ldif_line "${first_user_ldif}" "mail: ${FIRST_USER_MAIL}" "first user mail validation"
  require_ldif_line "${last_user_ldif}" "uid: ${LAST_UID}" "last user uid validation"
  require_ldif_line "${operational_ldif}" "creatorsName: ${ROOT_DN}" "creator operational attribute validation"

  require_ldif_attr_present "${rootdse_ldif}" "contextCSN" "Root DSE contextCSN validation"

  VALIDATION_DURATION_SECS=$((SECONDS - started))
}

mkdir -p "${CONFIG_DIR}" "${SOURCE_DATA_DIR}" "${SOURCE_STATE_DIR}" \
  "${RESTORED_STATE_DIR}" "${VALIDATION_DIR}" "${LOG_DIR}"

require_command cargo
require_command python3
require_command ldapsearch

if [[ "${BACKUP_DRILL_USERS}" -le 0 ]]; then
  echo "BACKUP_DRILL_USERS must be greater than zero" >&2
  exit 1
fi

if [[ -z "${BACKUP_DRILL_PORT}" ]]; then
  RESTORED_LDAP_PORT=$(reserve_port)
else
  RESTORED_LDAP_PORT="${BACKUP_DRILL_PORT}"
fi
SOURCE_LDAP_PORT=$(reserve_port)
SOURCE_LDAPS_PORT=$(reserve_port)
RESTORED_LDAPS_PORT=$(reserve_port)

log "Artifacts: ${ARTIFACT_DIR}"
write_summary

build_started=$SECONDS
BUILD_ARGS=(build --bin opendr --bin opendr-setup --bin opendr-backup --bin opendr-restore --bin opendr_perf_fixture_loader)
if [[ "${BACKUP_DRILL_PROFILE}" == "release" ]]; then
  BUILD_ARGS+=(--release)
fi
run_logged build cargo "${BUILD_ARGS[@]}"
BUILD_DURATION_SECS=$((SECONDS - build_started))

BIN_DIR="${REPO_ROOT}/target/${BACKUP_DRILL_PROFILE}"
OPENDR_BIN="${BIN_DIR}/opendr"
SETUP_BIN="${BIN_DIR}/opendr-setup"
BACKUP_BIN="${BIN_DIR}/opendr-backup"
RESTORE_BIN="${BIN_DIR}/opendr-restore"
FIXTURE_LOADER_BIN="${BIN_DIR}/opendr_perf_fixture_loader"

HASHED_ROOT_PASSWORD=$("${SETUP_BIN}" hash-password "${BACKUP_DRILL_ROOT_PASSWORD}" | tail -n 1)
write_log_config
write_server_config "${SOURCE_CONFIG}" "${SOURCE_DATA_DIR}" "${SOURCE_STATE_DIR}" \
  "${SOURCE_LDAP_PORT}" "${SOURCE_LDAPS_PORT}" "${HASHED_ROOT_PASSWORD}"
write_server_config "${RESTORED_CONFIG}" "${RESTORED_DATA_DIR}" "${RESTORED_STATE_DIR}" \
  "${RESTORED_LDAP_PORT}" "${RESTORED_LDAPS_PORT}" "${HASHED_ROOT_PASSWORD}"

load_started=$SECONDS
run_logged fixture-load "${FIXTURE_LOADER_BIN}" \
  --data-dir "${SOURCE_DATA_DIR}" \
  --base-dn "${BACKUP_DRILL_BASE_DN}" \
  --root-dn "${ROOT_DN}" \
  --root-password "${BACKUP_DRILL_ROOT_PASSWORD}" \
  --user-password "${BACKUP_DRILL_USER_PASSWORD}" \
  --name-prefix "${BACKUP_DRILL_NAME_PREFIX}" \
  --preloaded-users "${BACKUP_DRILL_USERS}" \
  --lmdb-max-size-bytes "${BACKUP_DRILL_LMDB_MAX_SIZE_BYTES}" \
  --batch-size "${BACKUP_DRILL_BATCH_SIZE}"
LOAD_DURATION_SECS=$((SECONDS - load_started))
SOURCE_SIZE_BYTES=$(dir_size_bytes "${SOURCE_DATA_DIR}")
write_summary

backup_started=$SECONDS
BACKUP_ARGS=(--config "${SOURCE_CONFIG}" --json full --target "${BACKUP_DIR}")
if [[ "${BACKUP_DRILL_COMPACT}" == "1" ]]; then
  BACKUP_ARGS+=(--compact)
fi
run_logged full-backup "${BACKUP_BIN}" "${BACKUP_ARGS[@]}"
BACKUP_DURATION_SECS=$((SECONDS - backup_started))
BACKUP_SIZE_BYTES=$(dir_size_bytes "${BACKUP_DIR}")
write_summary

run_logged backup-inspect "${BACKUP_BIN}" --config "${SOURCE_CONFIG}" --json inspect --backup "${BACKUP_DIR}"

dry_run_started=$SECONDS
run_logged restore-dry-run "${RESTORE_BIN}" --backup "${BACKUP_DIR}" \
  --target-data-dir "${RUNTIME_DIR}/dry-run-target" --dry-run --json
RESTORE_DRY_RUN_DURATION_SECS=$((SECONDS - dry_run_started))
write_summary

restore_started=$SECONDS
run_logged restore "${RESTORE_BIN}" --backup "${BACKUP_DIR}" \
  --target-data-dir "${RESTORED_DATA_DIR}" --json
RESTORE_DURATION_SECS=$((SECONDS - restore_started))
RESTORED_SIZE_BYTES=$(dir_size_bytes "${RESTORED_DATA_DIR}")
FINAL_CONTEXT_CSN=$(validate_context_csn)
write_summary

log "Starting restored OpenDR instance on ldap://127.0.0.1:${RESTORED_LDAP_PORT}"
"${OPENDR_BIN}" --config "${RESTORED_CONFIG}" --log-config "${LOG_CONFIG}" \
  > "${LOG_DIR}/restored-server.stdout.log" 2> "${LOG_DIR}/restored-server.stderr.log" &
SERVER_PID=$!

wait_for_restored_server
validate_restored_ldap

STATUS="passed"
write_summary

log "Backup/restore drill passed"
log "Summary: ${SUMMARY_MD}"

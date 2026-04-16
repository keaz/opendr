#!/usr/bin/env zsh
#
# Test: Replication Failure Drills
#
# Exercises live provider/consumer recovery paths that operators must validate
# before a production-ready release.
#

set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${DIR}/.." && pwd)"

: "${PROVIDER_PORT:=43940}"
: "${CONSUMER_PORT:=43941}"
: "${SYNC_INTERVAL_SECS:=1}"
: "${BATCH_SIZE:=25}"
: "${REPL_TIMEOUT_SECS:=60}"
: "${FAILURE_DRILL_MODE:=smoke}"
: "${FAILURE_DRILL_ARTIFACT_DIR:=${PROJECT_ROOT}/target/replication-failure-drills/$(date +%Y%m%d%H%M%S)}"

case "${FAILURE_DRILL_MODE}" in
  smoke)
    : "${FAILURE_NETWORK_DOWN_SECS:=2}"
    : "${FAILURE_DIAGNOSTIC_TIMEOUT_SECS:=15}"
    : "${FAILURE_RESTART_SETTLE_SECS:=1}"
    ;;
  release)
    : "${FAILURE_NETWORK_DOWN_SECS:=15}"
    : "${FAILURE_DIAGNOSTIC_TIMEOUT_SECS:=60}"
    : "${FAILURE_RESTART_SETTLE_SECS:=5}"
    ;;
  *)
    echo "FAILURE_DRILL_MODE must be smoke or release, got ${FAILURE_DRILL_MODE}" >&2
    exit 1
    ;;
esac

export E2E_ARTIFACT_DIR="${FAILURE_DRILL_ARTIFACT_DIR}"

source "${DIR}/helpers.sh"

PV_DIR="${RUN_ROOT}/provider"
CS_DIR="${RUN_ROOT}/consumer"
PV_STATE_DIR="${PV_DIR}/repl/state"
CS_STATE_DIR="${CS_DIR}/repl/state"
PV_CHANGELOG="${PV_STATE_DIR}/provider_changelog.json"
CS_COOKIE="${CS_STATE_DIR}/replication_cookie.txt"
SUMMARY_FILE="${FAILURE_DRILL_ARTIFACT_DIR}/summary.txt"

PV_CFG=""
CS_CFG=""
PV_PID=""
CS_PID=""
EXPECTED_ACTIVE=0
NEXT_ID=1
LAST_DN=""
LAST_DESCRIPTION=""
DRILL_STATUS="running"
DRILL_STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
typeset -a SCENARIO_RESULTS

write_drill_summary() {
  mkdir -p "${FAILURE_DRILL_ARTIFACT_DIR}"
  cat > "${SUMMARY_FILE}" <<EOF
status: ${DRILL_STATUS}
started_at: ${DRILL_STARTED_AT}
updated_at: $(date -u +%Y-%m-%dT%H:%M:%SZ)
mode: ${FAILURE_DRILL_MODE}
provider_port: ${PROVIDER_PORT}
consumer_port: ${CONSUMER_PORT}
sync_interval_secs: ${SYNC_INTERVAL_SECS}
replication_timeout_secs: ${REPL_TIMEOUT_SECS}
network_down_secs: ${FAILURE_NETWORK_DOWN_SECS}
diagnostic_timeout_secs: ${FAILURE_DIAGNOSTIC_TIMEOUT_SECS}
expected_active_entries: ${EXPECTED_ACTIVE}
provider_changelog: ${PV_CHANGELOG}
consumer_cookie: ${CS_COOKIE}
scenario_results:
EOF

  local result
  for result in "${SCENARIO_RESULTS[@]}"; do
    print "  - ${result}" >> "${SUMMARY_FILE}"
  done
}

cleanup_failure_drills() {
  local exit_code=$?
  if [[ ${exit_code} -eq 0 && ${FAIL_COUNT} -eq 0 ]]; then
    DRILL_STATUS="passed"
  else
    DRILL_STATUS="failed"
  fi
  write_drill_summary || true
  cleanup_all
}
trap cleanup_failure_drills EXIT INT TERM

record_scenario() {
  local name="$1"
  local scenario_status="$2"
  local detail="${3:-}"
  SCENARIO_RESULTS+=("${name}: ${scenario_status}${detail:+ - ${detail}}")
  write_drill_summary
}

copy_state_artifacts() {
  local label="$1"
  mkdir -p "${FAILURE_DRILL_ARTIFACT_DIR}/state"

  if [[ -f "${CS_COOKIE}" ]]; then
    cp -f "${CS_COOKIE}" "${FAILURE_DRILL_ARTIFACT_DIR}/state/${label}.consumer_cookie.txt" || true
  fi
  if [[ -f "${PV_CHANGELOG}" ]]; then
    cp -f "${PV_CHANGELOG}" "${FAILURE_DRILL_ARTIFACT_DIR}/state/${label}.provider_changelog.json" || true
  fi
}

start_provider_instance() {
  local label="$1"
  local log="${PV_DIR}/${label}.log"
  local pidfile="${PV_DIR}/server.pid"

  start_server "provider:${label}:${PROVIDER_PORT}" "${PV_CFG}" "${log}" "${pidfile}"
  PV_PID=$(cat "${pidfile}")
  wait_for_server "${LDAP_HOST}" "${PROVIDER_PORT}" 20
  if [[ "${FAILURE_RESTART_SETTLE_SECS}" != "0" ]]; then
    sleep "${FAILURE_RESTART_SETTLE_SECS}"
  fi
}

start_consumer_instance() {
  local label="$1"
  local log="${CS_DIR}/${label}.log"
  local pidfile="${CS_DIR}/server.pid"

  start_server "consumer:${label}:${CONSUMER_PORT}" "${CS_CFG}" "${log}" "${pidfile}"
  CS_PID=$(cat "${pidfile}")
  wait_for_server "${LDAP_HOST}" "${CONSUMER_PORT}" 20
  if [[ "${FAILURE_RESTART_SETTLE_SECS}" != "0" ]]; then
    sleep "${FAILURE_RESTART_SETTLE_SECS}"
  fi
}

restart_provider() {
  local label="$1"
  stop_server "${PV_PID}" "provider:${PROVIDER_PORT}"
  start_provider_instance "${label}"
}

restart_consumer() {
  local label="$1"
  stop_server "${CS_PID}" "consumer:${CONSUMER_PORT}"
  start_consumer_instance "${label}"
}

drill_uid() {
  printf "failure%06d" "$1"
}

drill_dn() {
  local uid="$1"
  echo "uid=${uid},ou=people,${BASE_DN}"
}

add_drill_entry() {
  local scenario="$1"
  local id="${NEXT_ID}"
  local uid
  uid=$(drill_uid "${id}")
  LAST_DN=$(drill_dn "${uid}")
  LAST_DESCRIPTION="${scenario} entry ${id}"

  cat <<LDIF | add_ldif "${LDAP_HOST}" "${PROVIDER_PORT}" >/dev/null
dn: ${LAST_DN}
objectClass: top
objectClass: inetOrgPerson
cn: Failure Drill User ${id}
sn: ${id}
uid: ${uid}
mail: ${uid}@example.org
description: ${LAST_DESCRIPTION}
LDIF

  NEXT_ID=$((NEXT_ID + 1))
  EXPECTED_ACTIVE=$((EXPECTED_ACTIVE + 1))
}

wait_for_attribute() {
  local host="$1"
  local port="$2"
  local dn="$3"
  local attr="$4"
  local value="$5"
  local timeout="$6"
  local deadline=$(($(date +%s) + timeout))

  while true; do
    if verify_entry_attributes "${host}" "${port}" "${dn}" "${attr}=${value}" >/dev/null 2>&1; then
      return 0
    fi

    if [[ $(date +%s) -ge ${deadline} ]]; then
      log_error "Timed out waiting for ${attr}=${value} on ${dn} at ${host}:${port}"
      return 1
    fi

    sleep 0.5
  done
}

assert_converged() {
  local scenario="$1"
  if wait_for_replication "${LDAP_HOST}" "${PROVIDER_PORT}" "${LDAP_HOST}" "${CONSUMER_PORT}" \
    "ou=people,${BASE_DN}" "(objectClass=inetOrgPerson)" "${EXPECTED_ACTIVE}" "${REPL_TIMEOUT_SECS}"; then
    assert_eq "${EXPECTED_ACTIVE}" "$(count_entries "${LDAP_HOST}" "${CONSUMER_PORT}" "ou=people,${BASE_DN}" "(objectClass=inetOrgPerson)")" \
      "${scenario}: consumer converged to expected entry count"
    record_scenario "${scenario}" "passed" "converged=${EXPECTED_ACTIVE}"
  else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    record_scenario "${scenario}" "failed" "consumer did not converge"
    return 1
  fi
}

wait_for_log_pattern() {
  local log_file="$1"
  local pattern="$2"
  local timeout="$3"
  local deadline=$(($(date +%s) + timeout))

  while true; do
    if [[ -f "${log_file}" ]] && grep -E "${pattern}" "${log_file}" >/dev/null 2>&1; then
      return 0
    fi

    if [[ $(date +%s) -ge ${deadline} ]]; then
      return 1
    fi

    sleep 0.5
  done
}

begin_test "replication_failure_drills" "Live provider/consumer restart, interruption, stale cookie, and changelog truncation drills"

log_info "Failure drill mode: ${FAILURE_DRILL_MODE}"
log_info "Failure drill artifacts: ${FAILURE_DRILL_ARTIFACT_DIR}"

write_drill_summary

build_server
ensure_tools
mkdir -p "${PV_STATE_DIR}" "${CS_STATE_DIR}"

provider_extra=$(cat <<EOF
changelog_capacity = 25
state_storage_path = "${PV_STATE_DIR}"
max_retry_attempts = 20
retry_delay_secs = 1
EOF
)

consumer_extra=$(cat <<EOF
state_storage_path = "${CS_STATE_DIR}"
max_retry_attempts = 20
retry_delay_secs = 1
provider_timeout_secs = 5
state_persistence_timeout_secs = 10
EOF
)

log_step "Creating provider and consumer configurations"
PV_CFG=$(create_provider_config "${PV_DIR}" "${PROVIDER_PORT}" "${BASE_DN}" "${BIND_RDN}" "${BIND_PW_HASH}" "${provider_extra}")
CS_CFG=$(create_consumer_config "${CS_DIR}" "${CONSUMER_PORT}" "${PROVIDER_PORT}" "${BASE_DN}" "${BIND_RDN}" \
  "${BIND_PW_HASH}" "${SYNC_INTERVAL_SECS}" "${BATCH_SIZE}" "${consumer_extra}")

log_step "Starting provider and initializing base tree"
start_provider_instance "initial"
ensure_base_tree "${LDAP_HOST}" "${PROVIDER_PORT}"

log_step "Starting consumer"
start_consumer_instance "initial"
assert_converged "initial_sync"
copy_state_artifacts "initial_sync"

log_step "Scenario: provider restart"
restart_provider "provider_restart"
add_drill_entry "provider_restart"
assert_converged "provider_restart"
wait_for_attribute "${LDAP_HOST}" "${CONSUMER_PORT}" "${LAST_DN}" "description" "${LAST_DESCRIPTION}" "${REPL_TIMEOUT_SECS}"
copy_state_artifacts "provider_restart"

log_step "Scenario: consumer restart with persisted cookie resume"
stop_server "${CS_PID}" "consumer:${CONSUMER_PORT}"
add_drill_entry "consumer_restart"
start_consumer_instance "consumer_restart"
assert_converged "consumer_restart"
wait_for_attribute "${LDAP_HOST}" "${CONSUMER_PORT}" "${LAST_DN}" "description" "${LAST_DESCRIPTION}" "${REPL_TIMEOUT_SECS}"
copy_state_artifacts "consumer_restart"

log_step "Scenario: provider unreachable and reconnect"
stop_server "${PV_PID}" "provider:${PROVIDER_PORT}"
sleep "${FAILURE_NETWORK_DOWN_SECS}"
if kill -0 "${CS_PID}" >/dev/null 2>&1; then
  assert_true "true" "network_interruption: consumer process stays running while provider is unreachable"
else
  FAIL_COUNT=$((FAIL_COUNT + 1))
  record_scenario "network_interruption" "failed" "consumer process exited while provider was unreachable"
fi
start_provider_instance "network_recovery"
add_drill_entry "network_recovery"
assert_converged "network_interruption"
wait_for_attribute "${LDAP_HOST}" "${CONSUMER_PORT}" "${LAST_DN}" "description" "${LAST_DESCRIPTION}" "${REPL_TIMEOUT_SECS}"
copy_state_artifacts "network_interruption"

log_step "Scenario: stale cookie and truncated changelog"
local_stale_cookie=""
if [[ -f "${CS_COOKIE}" ]]; then
  local_stale_cookie=$(cat "${CS_COOKIE}")
fi
if [[ -z "${local_stale_cookie}" ]]; then
  log_error "Expected consumer cookie before stale-cookie drill"
  FAIL_COUNT=$((FAIL_COUNT + 1))
  record_scenario "stale_cookie_changelog_truncation" "failed" "missing consumer cookie before truncation"
else
  cp -f "${CS_COOKIE}" "${FAILURE_DRILL_ARTIFACT_DIR}/state/stale.original_cookie.txt" || true
fi

stop_server "${CS_PID}" "consumer:${CONSUMER_PORT}"
add_drill_entry "post_truncation"
copy_state_artifacts "pre_truncation"
stop_server "${PV_PID}" "provider:${PROVIDER_PORT}"
if [[ -f "${PV_CHANGELOG}" ]]; then
  cp -f "${PV_CHANGELOG}" "${FAILURE_DRILL_ARTIFACT_DIR}/state/pre_truncation.provider_changelog.json" || true
fi
rm -f "${PV_CHANGELOG}"

start_provider_instance "truncated_changelog"
start_consumer_instance "stale_cookie"

STALE_LOG="${CS_DIR}/stale_cookie.log"
if wait_for_log_pattern "${STALE_LOG}" "Stale replication cookie|requires a full refresh|full refresh required|replay gap" "${FAILURE_DIAGNOSTIC_TIMEOUT_SECS}"; then
  assert_true "true" "stale_cookie_changelog_truncation: full-refresh-required diagnostic is visible"
  record_scenario "stale_cookie_changelog_truncation" "passed" "diagnostic visible"
else
  log_error "Expected stale-cookie/full-refresh diagnostic in ${STALE_LOG}"
  FAIL_COUNT=$((FAIL_COUNT + 1))
  record_scenario "stale_cookie_changelog_truncation" "failed" "missing stale-cookie diagnostic"
fi
copy_state_artifacts "stale_cookie_failure"

log_step "Operator recovery: delete stale consumer cookie and restart consumer for full refresh"
stop_server "${CS_PID}" "consumer:${CONSUMER_PORT}"
rm -f "${CS_COOKIE}"
start_consumer_instance "full_refresh_recovery"
assert_converged "full_refresh_recovery"
wait_for_attribute "${LDAP_HOST}" "${CONSUMER_PORT}" "${LAST_DN}" "description" "${LAST_DESCRIPTION}" "${REPL_TIMEOUT_SECS}"
copy_state_artifacts "full_refresh_recovery"

DRILL_STATUS="passed"
write_drill_summary
end_test

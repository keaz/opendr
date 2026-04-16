#!/usr/bin/env zsh
#
# Test: Replication Soak
#
# Starts one provider and one consumer, then continuously applies LDAP writes to
# the provider and verifies consumer convergence. Defaults are short enough for
# local smoke runs; release candidates should override SOAK_DURATION_SECS.
#

set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${DIR}/.." && pwd)"

: "${PROVIDER_PORT:=43900}"
: "${CONSUMER_PORT:=43901}"
: "${SYNC_INTERVAL_SECS:=5}"
: "${BATCH_SIZE:=100}"
: "${REPL_TIMEOUT_SECS:=60}"
: "${SOAK_DURATION_SECS:=60}"
: "${SOAK_BATCH_SIZE:=5}"
: "${SOAK_MODIFY_PER_ROUND:=2}"
: "${SOAK_DELETE_EVERY_ROUNDS:=3}"
: "${SOAK_MIN_ACTIVE_BEFORE_DELETE:=${SOAK_BATCH_SIZE}}"
: "${SOAK_ROUND_SLEEP_SECS:=0}"
: "${SOAK_ARTIFACT_DIR:=${PROJECT_ROOT}/target/replication-soak/$(date +%Y%m%d%H%M%S)}"

export E2E_ARTIFACT_DIR="${SOAK_ARTIFACT_DIR}"

source "${DIR}/helpers.sh"

TOTAL_ADDS=0
TOTAL_MODIFIES=0
TOTAL_DELETES=0
ROUND_COUNT=0
ACTIVE_EXPECTED=0
NEXT_ID=1
DELETE_ID=1
LAST_MODIFIED_DN=""
LAST_MODIFIED_MAIL=""
LAST_MODIFIED_DESCRIPTION=""
SOAK_STATUS="running"
SOAK_STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
PROVIDER_AUDIT_LOG=""
CONSUMER_AUDIT_LOG=""
FINAL_PROVIDER_COUNT=""
FINAL_CONSUMER_COUNT=""

write_soak_summary() {
  mkdir -p "${SOAK_ARTIFACT_DIR}"
  cat > "${SOAK_ARTIFACT_DIR}/summary.txt" <<EOF
status: ${SOAK_STATUS}
started_at: ${SOAK_STARTED_AT}
updated_at: $(date -u +%Y-%m-%dT%H:%M:%SZ)
duration_secs: ${SOAK_DURATION_SECS}
rounds: ${ROUND_COUNT}
adds: ${TOTAL_ADDS}
modifies: ${TOTAL_MODIFIES}
deletes: ${TOTAL_DELETES}
expected_active_entries: ${ACTIVE_EXPECTED}
provider_port: ${PROVIDER_PORT}
consumer_port: ${CONSUMER_PORT}
final_provider_entries: ${FINAL_PROVIDER_COUNT}
final_consumer_entries: ${FINAL_CONSUMER_COUNT}
sync_interval_secs: ${SYNC_INTERVAL_SECS}
replication_timeout_secs: ${REPL_TIMEOUT_SECS}
artifact_dir: ${SOAK_ARTIFACT_DIR}
run_root: ${RUN_ROOT}
provider_server_log_artifact: ${SOAK_ARTIFACT_DIR}/provider_${PROVIDER_PORT}.log
consumer_server_log_artifact: ${SOAK_ARTIFACT_DIR}/consumer_${CONSUMER_PORT}.log
provider_config_artifact: ${SOAK_ARTIFACT_DIR}/provider_${PROVIDER_PORT}.server.toml
consumer_config_artifact: ${SOAK_ARTIFACT_DIR}/consumer_${CONSUMER_PORT}.server.toml
provider_audit_log: ${PROVIDER_AUDIT_LOG}
consumer_audit_log: ${CONSUMER_AUDIT_LOG}
provider_audit_log_artifact: ${SOAK_ARTIFACT_DIR}/provider_${PROVIDER_PORT}.audit.log
consumer_audit_log_artifact: ${SOAK_ARTIFACT_DIR}/consumer_${CONSUMER_PORT}.audit.log
EOF
}

append_soak_audit_config() {
  local cfg="$1"
  local audit_file="$2"

  cat >> "${cfg}" <<EOF

[audit]
enabled = true
log_file = "${audit_file}"
format = "json"
level = "info"
log_authentication = true
log_authorization = true
log_modifications = true
log_connections = true
log_replication = true
EOF
}

soak_uid() {
  printf "soak%06d" "$1"
}

soak_dn() {
  local uid="$1"
  echo "uid=${uid},ou=people,${BASE_DN}"
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

wait_for_deleted() {
  local host="$1"
  local port="$2"
  local dn="$3"
  local timeout="$4"
  local deadline=$(($(date +%s) + timeout))

  while true; do
    if ! verify_entry_exists "${host}" "${port}" "${dn}"; then
      return 0
    fi

    if [[ $(date +%s) -ge ${deadline} ]]; then
      log_error "Timed out waiting for deletion of ${dn} at ${host}:${port}"
      return 1
    fi

    sleep 0.5
  done
}

add_soak_entry() {
  local id="$1"
  local uid
  uid=$(soak_uid "${id}")

  cat <<LDIF | add_ldif "${LDAP_HOST}" "${PROVIDER_PORT}" >/dev/null
dn: $(soak_dn "${uid}")
objectClass: top
objectClass: inetOrgPerson
cn: Soak User ${id}
sn: ${id}
uid: ${uid}
mail: ${uid}@example.org
description: Added in soak round ${ROUND_COUNT}
LDIF

  TOTAL_ADDS=$((TOTAL_ADDS + 1))
  ACTIVE_EXPECTED=$((ACTIVE_EXPECTED + 1))
}

modify_soak_entry() {
  local id="$1"
  local uid="" dn="" mail="" description=""
  uid=$(soak_uid "${id}")
  dn=$(soak_dn "${uid}")
  mail="${uid}.round${ROUND_COUNT}@example.com"
  description="Modified ${uid} in soak round ${ROUND_COUNT}"

  cat <<LDIF | ldapmodify -x -H "ldap://${LDAP_HOST}:${PROVIDER_PORT}" -D "${BIND_DN}" -w "${BIND_PW}" >/dev/null
dn: ${dn}
changetype: modify
replace: mail
mail: ${mail}
-
replace: description
description: ${description}
LDIF

  TOTAL_MODIFIES=$((TOTAL_MODIFIES + 1))
  LAST_MODIFIED_DN="${dn}"
  LAST_MODIFIED_MAIL="${mail}"
  LAST_MODIFIED_DESCRIPTION="${description}"
}

delete_soak_entry() {
  local id="$1"
  local uid="" dn=""
  uid=$(soak_uid "${id}")
  dn=$(soak_dn "${uid}")

  ldapdelete -x -H "ldap://${LDAP_HOST}:${PROVIDER_PORT}" -D "${BIND_DN}" -w "${BIND_PW}" "${dn}" >/dev/null

  TOTAL_DELETES=$((TOTAL_DELETES + 1))
  ACTIVE_EXPECTED=$((ACTIVE_EXPECTED - 1))
  DELETE_ID=$((DELETE_ID + 1))
  wait_for_deleted "${LDAP_HOST}" "${CONSUMER_PORT}" "${dn}" "${REPL_TIMEOUT_SECS}"
}

verify_convergence() {
  wait_for_replication "${LDAP_HOST}" "${PROVIDER_PORT}" "${LDAP_HOST}" "${CONSUMER_PORT}" \
    "ou=people,${BASE_DN}" "(objectClass=inetOrgPerson)" "${ACTIVE_EXPECTED}" "${REPL_TIMEOUT_SECS}"
}

begin_test "replication_soak" "Sustained provider-consumer replication with convergence checks"

log_info "Soak duration: ${SOAK_DURATION_SECS}s"
log_info "Soak artifacts: ${SOAK_ARTIFACT_DIR}"

write_soak_summary

build_server
ensure_tools

PV_DIR="${RUN_ROOT}/provider"
CS_DIR="${RUN_ROOT}/consumer"
mkdir -p "${PV_DIR}" "${CS_DIR}"

log_step "Creating provider and consumer configurations"
PV_CFG=$(create_provider_config "${PV_DIR}" "${PROVIDER_PORT}" "${BASE_DN}" "${BIND_RDN}" "${BIND_PW_HASH}")
CS_CFG=$(create_consumer_config "${CS_DIR}" "${CONSUMER_PORT}" "${PROVIDER_PORT}" "${BASE_DN}" "${BIND_RDN}" \
  "${BIND_PW_HASH}" "${SYNC_INTERVAL_SECS}" "${BATCH_SIZE}")
PROVIDER_AUDIT_LOG="${PV_DIR}/audit.log"
CONSUMER_AUDIT_LOG="${CS_DIR}/audit.log"
append_soak_audit_config "${PV_CFG}" "${PROVIDER_AUDIT_LOG}"
append_soak_audit_config "${CS_CFG}" "${CONSUMER_AUDIT_LOG}"
write_soak_summary

log_step "Starting provider server on port ${PROVIDER_PORT}"
start_server "provider:${PROVIDER_PORT}" "${PV_CFG}" "${PV_DIR}/server.log" "${PV_DIR}/server.pid"
wait_for_server "${LDAP_HOST}" "${PROVIDER_PORT}" 15

log_step "Initializing base directory structure"
ensure_base_tree "${LDAP_HOST}" "${PROVIDER_PORT}"

log_step "Starting consumer server on port ${CONSUMER_PORT}"
start_server "consumer:${CONSUMER_PORT}" "${CS_CFG}" "${CS_DIR}/server.log" "${CS_DIR}/server.pid"
wait_for_server "${LDAP_HOST}" "${CONSUMER_PORT}" 15

verify_convergence

deadline=$(($(date +%s) + SOAK_DURATION_SECS))
first_round=true

while [[ "${first_round}" == "true" || $(date +%s) -lt ${deadline} ]]; do
  first_round=false
  ROUND_COUNT=$((ROUND_COUNT + 1))
  log_step "Soak round ${ROUND_COUNT}"

  for ((i = 1; i <= SOAK_BATCH_SIZE; i++)); do
    add_soak_entry "${NEXT_ID}"
    NEXT_ID=$((NEXT_ID + 1))
  done
  verify_convergence

  for ((i = 0; i < SOAK_MODIFY_PER_ROUND && i < ACTIVE_EXPECTED; i++)); do
    target_id=$((NEXT_ID - 1 - i))
    if [[ ${target_id} -ge ${DELETE_ID} ]]; then
      modify_soak_entry "${target_id}"
    fi
  done

  if [[ -n "${LAST_MODIFIED_DN}" ]]; then
    wait_for_attribute "${LDAP_HOST}" "${CONSUMER_PORT}" "${LAST_MODIFIED_DN}" "mail" \
      "${LAST_MODIFIED_MAIL}" "${REPL_TIMEOUT_SECS}"
    wait_for_attribute "${LDAP_HOST}" "${CONSUMER_PORT}" "${LAST_MODIFIED_DN}" "description" \
      "${LAST_MODIFIED_DESCRIPTION}" "${REPL_TIMEOUT_SECS}"
  fi

  if [[ ${SOAK_DELETE_EVERY_ROUNDS} -gt 0 && $((ROUND_COUNT % SOAK_DELETE_EVERY_ROUNDS)) -eq 0 \
    && ${ACTIVE_EXPECTED} -gt ${SOAK_MIN_ACTIVE_BEFORE_DELETE} ]]; then
    delete_soak_entry "${DELETE_ID}"
    verify_convergence
  fi

  write_soak_summary

  if [[ "${SOAK_ROUND_SLEEP_SECS}" != "0" ]]; then
    sleep "${SOAK_ROUND_SLEEP_SECS}"
  fi
done

log_step "Final convergence verification"
verify_convergence

FINAL_PROVIDER_COUNT=$(count_entries "${LDAP_HOST}" "${PROVIDER_PORT}" "ou=people,${BASE_DN}" "(objectClass=inetOrgPerson)")
FINAL_CONSUMER_COUNT=$(count_entries "${LDAP_HOST}" "${CONSUMER_PORT}" "ou=people,${BASE_DN}" "(objectClass=inetOrgPerson)")
assert_eq "${FINAL_PROVIDER_COUNT}" "${FINAL_CONSUMER_COUNT}" "Final provider and consumer entry counts match"
assert_eq "${ACTIVE_EXPECTED}" "${FINAL_CONSUMER_COUNT}" "Final consumer count matches expected active entries"

SOAK_STATUS="passed"
write_soak_summary

end_test

#!/usr/bin/env zsh
#
# Test: Single Provider, Single Consumer
#
# Validates basic replication functionality including ADD, MODIFY, and DELETE operations.
# Creates entries on the provider and verifies they are correctly replicated to the consumer.
#

set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
source "${DIR}/helpers.sh"

# Configuration
: "${PROVIDER_PORT:=3890}"
: "${CONSUMER_PORT:=3891}"

# Start test
begin_test "single_provider_single_consumer" "Basic replication: ADD, MODIFY, DELETE operations"

# Build and check tools
build_server
ensure_tools

# Create directories
PV_DIR="${RUN_ROOT}/provider"
CS_DIR="${RUN_ROOT}/consumer"
mkdir -p "${PV_DIR}" "${CS_DIR}"

# Generate configs
log_step "Creating provider and consumer configurations"
PV_CFG=$(create_provider_config "${PV_DIR}" "${PROVIDER_PORT}" "${BASE_DN}" "${BIND_RDN}" "${BIND_PW_HASH}")
CS_CFG=$(create_consumer_config "${CS_DIR}" "${CONSUMER_PORT}" "${PROVIDER_PORT}" "${BASE_DN}" "${BIND_RDN}" "${BIND_PW_HASH}" "${SYNC_INTERVAL_SECS}" "${BATCH_SIZE}")

# Start provider
log_step "Starting provider server on port ${PROVIDER_PORT}"
start_server "provider:${PROVIDER_PORT}" "${PV_CFG}" "${PV_DIR}/server.log" "${PV_DIR}/server.pid"
wait_for_server "${LDAP_HOST}" "${PROVIDER_PORT}" 15

# Initialize base tree
log_step "Initializing base directory structure"
ensure_base_tree "${LDAP_HOST}" "${PROVIDER_PORT}"

# Start consumer
log_step "Starting consumer server on port ${CONSUMER_PORT}"
start_server "consumer:${CONSUMER_PORT}" "${CS_CFG}" "${CS_DIR}/server.log" "${CS_DIR}/server.pid"
wait_for_server "${LDAP_HOST}" "${CONSUMER_PORT}" 15

# Wait a moment for initial replication setup
sleep 2

# ============================================================================
# Test 1: ADD Operations
# ============================================================================

log_step "Test 1: Adding 5 entries to provider"

for i in 1 2 3 4 5; do
  uid=$(printf "user%04d" "${i}")
  log_debug "Adding ${uid}"
  
  cat <<LDIF | add_ldif "${LDAP_HOST}" "${PROVIDER_PORT}" >/dev/null
dn: uid=${uid},ou=people,${BASE_DN}
objectClass: top
objectClass: inetOrgPerson
cn: User ${i}
sn: $(printf "%04d" "${i}")
uid: ${uid}
mail: ${uid}@example.org
LDIF
done

log_info "Waiting for replication to complete..."
wait_for_replication "${LDAP_HOST}" "${PROVIDER_PORT}" "${LDAP_HOST}" "${CONSUMER_PORT}" \
  "ou=people,${BASE_DN}" "(objectClass=inetOrgPerson)" 5 "${REPL_TIMEOUT_SECS}"

# Verify entry counts match
pc=$(count_entries "${LDAP_HOST}" "${PROVIDER_PORT}" "ou=people,${BASE_DN}" "(objectClass=inetOrgPerson)")
cc=$(count_entries "${LDAP_HOST}" "${CONSUMER_PORT}" "ou=people,${BASE_DN}" "(objectClass=inetOrgPerson)")
assert_eq "${pc}" "${cc}" "Consumer entry count matches provider"

# Verify specific entry exists
if verify_entry_exists "${LDAP_HOST}" "${CONSUMER_PORT}" "uid=user0001,ou=people,${BASE_DN}"; then
  log_success "✓ Entry uid=user0001 exists on consumer"
  PASS_COUNT=$((PASS_COUNT + 1))
else
  log_error "✗ Entry uid=user0001 not found on consumer"
  FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# Verify attributes match
log_debug "Verifying attributes for uid=user0001"
if verify_entry_attributes "${LDAP_HOST}" "${CONSUMER_PORT}" "uid=user0001,ou=people,${BASE_DN}" \
  "cn=User 1" "sn=0001" "uid=user0001" "mail=user0001@example.org"; then
  log_success "✓ Attributes match for uid=user0001"
  PASS_COUNT=$((PASS_COUNT + 1))
else
  FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# ============================================================================
# Test 2: MODIFY Operations
# ============================================================================

log_step "Test 2: Modifying 2 entries on provider"

for uid in user0002 user0004; do
  log_debug "Modifying ${uid}"
  
  cat <<LDIF | ldapmodify -x -H "ldap://${LDAP_HOST}:${PROVIDER_PORT}" -D "${BIND_DN}" -w "${BIND_PW}" 2>/dev/null
dn: uid=${uid},ou=people,${BASE_DN}
changetype: modify
replace: mail
mail: ${uid}@example.com
-
add: description
description: Modified ${uid}
LDIF
done

# Wait for modifications to replicate
log_info "Waiting for modifications to replicate..."
sleep $((SYNC_INTERVAL_SECS + 2))

# Verify modifications on consumer
for uid in user0002 user0004; do
  log_debug "Verifying modifications for ${uid}"
  if verify_entry_attributes "${LDAP_HOST}" "${CONSUMER_PORT}" "uid=${uid},ou=people,${BASE_DN}" \
    "mail=${uid}@example.com" "description=Modified ${uid}"; then
    log_success "✓ Modifications replicated for ${uid}"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    log_error "✗ Modifications not replicated for ${uid}"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
done

# ============================================================================
# Test 3: DELETE Operations
# ============================================================================

log_step "Test 3: Deleting 1 entry from provider"

log_debug "Deleting uid=user0005"
ldapdelete -x -H "ldap://${LDAP_HOST}:${PROVIDER_PORT}" \
  -D "${BIND_DN}" -w "${BIND_PW}" \
  "uid=user0005,ou=people,${BASE_DN}" 2>/dev/null

# Wait for deletion to replicate
log_info "Waiting for deletion to replicate..."
deadline=$(($(date +%s) + REPL_TIMEOUT_SECS))
deleted=false

while [[ $(date +%s) -lt ${deadline} ]]; do
  if ! search_entry "${LDAP_HOST}" "${CONSUMER_PORT}" "uid=user0005,ou=people,${BASE_DN}" "(objectClass=*)" dn >/dev/null 2>&1; then
    deleted=true
    break
  fi
  sleep 0.5
done

if [[ "${deleted}" == "true" ]]; then
  log_success "✓ Deletion replicated successfully"
  PASS_COUNT=$((PASS_COUNT + 1))
else
  log_error "✗ Deletion not replicated within timeout"
  FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# Verify final count
fc=$(count_entries "${LDAP_HOST}" "${CONSUMER_PORT}" "ou=people,${BASE_DN}" "(objectClass=inetOrgPerson)")
assert_eq "4" "${fc}" "Final consumer count is 4 (5 added - 1 deleted)"

# ============================================================================
# Summary
# ============================================================================

end_test

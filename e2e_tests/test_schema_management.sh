#!/usr/bin/env zsh
#
# Test: Schema Management
#
# Validates external schema loading, subschema publication, entry validation,
# modify validation, ModifyDN validation, online schema updates, and schema-aware
# index configuration checks through the public LDAP surface.
#

set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
source "${DIR}/helpers.sh"

if [[ -z "${SCHEMA_PORT:-}" ]]; then
  SCHEMA_PORT="$(get_random_port)"
fi

begin_test "schema_management" "External and online LDAP schema definition lifecycle"

if [[ -z "${SERVER_BIN:-}" && -f Cargo.toml ]]; then
  log_step "Building current OpenDR binary for schema e2e coverage"
  cargo build --release --bin opendr
fi
build_server
ensure_tools

SCHEMA_DIR="${RUN_ROOT}/schema-server/config/schema"
SERVER_DIR="${RUN_ROOT}/schema-server"
mkdir -p "${SCHEMA_DIR}"

cat > "${SCHEMA_DIR}/10-example-employee.ldif" <<'LDIF'
dn: cn=schema
matchingRules: ( 1.3.6.1.4.1.55555.20.7 NAME 'exampleEmployeeNumberMatch' DESC 'Example employee number equality' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )
matchingRuleUse: ( 1.3.6.1.4.1.55555.20.7 NAME 'exampleEmployeeNumberMatchUse' APPLIES exampleEmployeeNumber )
attributeTypes: ( 1.3.6.1.4.1.55555.20.1 NAME 'exampleEmployeeNumber' DESC 'Example employee number' EQUALITY exampleEmployeeNumberMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.55555.20.2 NAME 'exampleAccessCode' DESC 'Example access code' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.55555.20.3 NAME 'exampleStartTime' DESC 'Example start timestamp' EQUALITY generalizedTimeMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.55555.20.4 NAME 'exampleInternalNote' DESC 'Example prohibited internal note' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeTypes: ( 1.3.6.1.4.1.55555.20.5 NAME 'exampleLooseAttribute' DESC 'Defined but not allowed by exampleEmployee' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeTypes: ( 1.3.6.1.4.1.55555.20.6 NAME 'exampleScore' DESC 'Example integer score' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.55555.20.8 NAME 'exampleExactCode' DESC 'Example case exact code' EQUALITY caseExactMatch SUBSTR caseExactSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
objectClasses: ( 1.3.6.1.4.1.55555.20.100 NAME 'exampleEmployee' DESC 'Example employee entry' SUP inetOrgPerson STRUCTURAL MUST ( exampleEmployeeNumber $ exampleAccessCode ) MAY ( exampleStartTime $ exampleInternalNote $ exampleScore $ exampleExactCode ) )
dITContentRules: ( 1.3.6.1.4.1.55555.20.100 NAME 'exampleEmployeeContentRule' NOT exampleInternalNote )
nameForms: ( 1.3.6.1.4.1.55555.20.101 NAME 'exampleEmployeeNameForm' OC exampleEmployee MUST cn )
dITStructureRules: ( 555201 NAME 'exampleEmployeeStructureRule' FORM exampleEmployeeNameForm )
LDIF

log_step "Creating schema-enabled server configuration"
CFG=$(create_provider_config "${SERVER_DIR}" "${SCHEMA_PORT}" "${BASE_DN}" "${BIND_RDN}" "${BIND_PW_HASH}")
cat >> "${CFG}" <<EOF

[schema]
enabled = true
schema_dir = "${SCHEMA_DIR}"
load_builtin = ["core"]
strict_validation = true
allow_online_updates = true

[rate_limit]
enabled = false

[[backend.indexes]]
attribute = "exampleScore"
types = ["equality", "ordering"]

[[backend.indexes]]
attribute = "exampleExactCode"
types = ["substring"]
EOF

log_step "Validating startup-loaded schema with the CLI"
if "${SERVER_BIN}" --config "${CFG}" schema validate >"${RUN_ROOT}/schema-validate.out" 2>"${RUN_ROOT}/schema-validate.err"; then
  log_success "✓ schema validate accepts external schema definitions"
  PASS_COUNT=$((PASS_COUNT + 1))
else
  log_error "✗ schema validate rejected external schema definitions"
  cat "${RUN_ROOT}/schema-validate.err" >&2 || true
  FAIL_COUNT=$((FAIL_COUNT + 1))
fi

if "${SERVER_BIN}" --config "${CFG}" schema explain exampleEmployeeNumber | grep -q "SINGLE-VALUE"; then
  log_success "✓ schema explain resolves custom attribute definitions"
  PASS_COUNT=$((PASS_COUNT + 1))
else
  log_error "✗ schema explain did not resolve custom attribute definitions"
  FAIL_COUNT=$((FAIL_COUNT + 1))
fi

log_step "Validating schema-aware index configuration checks"
BAD_INDEX_CFG="${RUN_ROOT}/bad-index-server.toml"
awk '
  { print }
  /^lmdb_max_readers = / { print "indexed_attributes = [\"exampleDoesNotExist\"]" }
' "${CFG}" > "${BAD_INDEX_CFG}"

if "${SERVER_BIN}" --config "${BAD_INDEX_CFG}" schema validate >"${RUN_ROOT}/bad-index.out" 2>"${RUN_ROOT}/bad-index.err"; then
  log_error "✗ schema validate accepted an index on an unknown attribute"
  FAIL_COUNT=$((FAIL_COUNT + 1))
else
  if grep -q "unknown schema attribute" "${RUN_ROOT}/bad-index.err"; then
    log_success "✓ schema validate rejects indexes for unknown attributes"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    log_error "✗ schema validate failed for the wrong reason"
    cat "${RUN_ROOT}/bad-index.err" >&2 || true
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
fi

log_step "Starting schema-enabled server on port ${SCHEMA_PORT}"
start_server "schema:${SCHEMA_PORT}" "${CFG}" "${SERVER_DIR}/server.log" "${SERVER_DIR}/server.pid"
wait_for_server "${LDAP_HOST}" "${SCHEMA_PORT}" 15

log_step "Initializing base directory structure"
ensure_base_tree "${LDAP_HOST}" "${SCHEMA_PORT}"

ldap_url="ldap://${LDAP_HOST}:${SCHEMA_PORT}"

expect_add_success() {
  local name="$1"
  local ldif="$2"
  if print -r -- "${ldif}" | ldapadd -x -H "${ldap_url}" -D "${BIND_DN}" -w "${BIND_PW}" >"${RUN_ROOT}/${name}.out" 2>"${RUN_ROOT}/${name}.err"; then
    log_success "✓ ${name}"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    log_error "✗ ${name}"
    cat "${RUN_ROOT}/${name}.err" >&2 || true
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
}

expect_add_failure() {
  local name="$1"
  local ldif="$2"
  if print -r -- "${ldif}" | ldapadd -x -H "${ldap_url}" -D "${BIND_DN}" -w "${BIND_PW}" >"${RUN_ROOT}/${name}.out" 2>"${RUN_ROOT}/${name}.err"; then
    log_error "✗ ${name}: add succeeded but should have failed"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  else
    log_success "✓ ${name}"
    PASS_COUNT=$((PASS_COUNT + 1))
  fi
}

expect_modify_success() {
  local name="$1"
  local ldif="$2"
  if print -r -- "${ldif}" | ldapmodify -x -H "${ldap_url}" -D "${BIND_DN}" -w "${BIND_PW}" >"${RUN_ROOT}/${name}.out" 2>"${RUN_ROOT}/${name}.err"; then
    log_success "✓ ${name}"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    log_error "✗ ${name}"
    cat "${RUN_ROOT}/${name}.err" >&2 || true
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
}

expect_modify_failure() {
  local name="$1"
  local ldif="$2"
  if print -r -- "${ldif}" | ldapmodify -x -H "${ldap_url}" -D "${BIND_DN}" -w "${BIND_PW}" >"${RUN_ROOT}/${name}.out" 2>"${RUN_ROOT}/${name}.err"; then
    log_error "✗ ${name}: modify succeeded but should have failed"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  else
    log_success "✓ ${name}"
    PASS_COUNT=$((PASS_COUNT + 1))
  fi
}

expect_search_success() {
  local name="$1"
  local base="$2"
  local filter="$3"
  local expected="$4"
  shift 4
  if ldapsearch -LLL -o ldif-wrap=no -x -H "${ldap_url}" -D "${BIND_DN}" -w "${BIND_PW}" \
    -b "${base}" "${filter}" "$@" >"${RUN_ROOT}/${name}.out" 2>"${RUN_ROOT}/${name}.err" &&
    grep -qi -- "${expected}" "${RUN_ROOT}/${name}.out"; then
    log_success "✓ ${name}"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    log_error "✗ ${name}"
    cat "${RUN_ROOT}/${name}.out" >&2 || true
    cat "${RUN_ROOT}/${name}.err" >&2 || true
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
}

expect_search_no_entries() {
  local name="$1"
  local base="$2"
  local filter="$3"
  local forbidden="$4"
  shift 4
  if ldapsearch -LLL -o ldif-wrap=no -x -H "${ldap_url}" -D "${BIND_DN}" -w "${BIND_PW}" \
    -b "${base}" "${filter}" "$@" >"${RUN_ROOT}/${name}.out" 2>"${RUN_ROOT}/${name}.err" &&
    ! grep -qi -- "${forbidden}" "${RUN_ROOT}/${name}.out"; then
    log_success "✓ ${name}"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    log_error "✗ ${name}"
    cat "${RUN_ROOT}/${name}.out" >&2 || true
    cat "${RUN_ROOT}/${name}.err" >&2 || true
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
}

expect_search_failure() {
  local name="$1"
  local base="$2"
  local filter="$3"
  shift 3
  if ldapsearch -LLL -o ldif-wrap=no -x -H "${ldap_url}" -D "${BIND_DN}" -w "${BIND_PW}" \
    -b "${base}" "${filter}" "$@" >"${RUN_ROOT}/${name}.out" 2>"${RUN_ROOT}/${name}.err"; then
    log_error "✗ ${name}: search succeeded but should have failed"
    cat "${RUN_ROOT}/${name}.out" >&2 || true
    FAIL_COUNT=$((FAIL_COUNT + 1))
  else
    log_success "✓ ${name}"
    PASS_COUNT=$((PASS_COUNT + 1))
  fi
}

verify_entry_attributes_ci() {
  local dn="$1"
  shift

  local all_match=0
  for kv in "$@"; do
    local k="${kv%%=*}"
    local v="${kv#*=}"
    if ! search_entry "${LDAP_HOST}" "${SCHEMA_PORT}" "${dn}" "(objectClass=*)" "${k}" | grep -qi -- "^${k}: ${v}$"; then
      log_error "Attribute mismatch on ${dn}: expected ${k}=${v}"
      all_match=1
    fi
  done

  return ${all_match}
}

log_step "Checking subschema publication"
subschema_out="${RUN_ROOT}/subschema.out"
ldapsearch -LLL -o ldif-wrap=no -x -H "${ldap_url}" -D "${BIND_DN}" -w "${BIND_PW}" \
  -b "cn=Subschema" -s base "(objectClass=*)" \
  attributeTypes objectClasses matchingRules matchingRuleUse dITContentRules nameForms dITStructureRules \
  > "${subschema_out}"

for token in exampleEmployeeNumber exampleEmployee exampleEmployeeNumberMatch exampleEmployeeContentRule exampleEmployeeNameForm exampleEmployeeStructureRule; do
  if grep -qi "${token}" "${subschema_out}"; then
    log_success "✓ subschema publishes ${token}"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    log_error "✗ subschema does not publish ${token}"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
done

log_step "Adding entries against startup-defined schema"
expect_add_success "valid_custom_employee_add" "dn: cn=Schema E2E One,ou=people,${BASE_DN}
objectClass: top
objectClass: exampleEmployee
cn: Schema E2E One
sn: One
uid: schemae2e1
mail: schemae2e1@example.org
exampleEmployeeNumber: 1001
exampleAccessCode: blue
exampleStartTime: 20260413010101Z
exampleScore: 010
exampleExactCode: CaseToken"

if verify_entry_attributes_ci "cn=Schema E2E One,ou=people,${BASE_DN}" \
  "exampleEmployeeNumber=1001" "exampleAccessCode=blue" "exampleStartTime=20260413010101Z" "exampleScore=010" "exampleExactCode=CaseToken"; then
  log_success "✓ stored custom schema attributes are searchable"
  PASS_COUNT=$((PASS_COUNT + 1))
else
  FAIL_COUNT=$((FAIL_COUNT + 1))
fi

log_step "Validating schema-aware matching-rule filters and index-backed candidates"
expect_search_success "case_ignore_equality_filter_matches" "ou=people,${BASE_DN}" \
  "(exampleAccessCode=BLUE)" "dn: cn=Schema E2E One,ou=people,${BASE_DN}" cn
expect_search_success "integer_ordering_filter_matches" "ou=people,${BASE_DN}" \
  "(exampleScore>=9)" "dn: cn=Schema E2E One,ou=people,${BASE_DN}" cn
expect_search_success "case_exact_substring_filter_matches_exact_case" "ou=people,${BASE_DN}" \
  "(exampleExactCode=*Case*)" "dn: cn=Schema E2E One,ou=people,${BASE_DN}" cn
expect_search_no_entries "case_exact_substring_filter_rejects_wrong_case" "ou=people,${BASE_DN}" \
  "(exampleExactCode=*case*)" "dn: cn=Schema E2E One,ou=people,${BASE_DN}" cn
expect_search_failure "ordering_filter_rejects_attribute_without_ordering_rule" "ou=people,${BASE_DN}" \
  "(exampleAccessCode>=blue)" cn

expect_add_failure "missing_custom_required_attribute" "dn: cn=Missing Employee Number,ou=people,${BASE_DN}
objectClass: top
objectClass: exampleEmployee
cn: Missing Employee Number
sn: Missing
uid: missingEmployeeNumber
mail: missingEmployeeNumber@example.org
exampleAccessCode: blue"

expect_add_failure "invalid_custom_integer_syntax" "dn: cn=Invalid Integer,ou=people,${BASE_DN}
objectClass: top
objectClass: exampleEmployee
cn: Invalid Integer
sn: Integer
uid: invalidInteger
mail: invalidInteger@example.org
exampleEmployeeNumber: not-a-number
exampleAccessCode: blue"

expect_add_failure "custom_single_value_violation" "dn: cn=Duplicate Access Code,ou=people,${BASE_DN}
objectClass: top
objectClass: exampleEmployee
cn: Duplicate Access Code
sn: Code
uid: duplicateAccessCode
mail: duplicateAccessCode@example.org
exampleEmployeeNumber: 1002
exampleAccessCode: blue
exampleAccessCode: green"

expect_add_failure "defined_attribute_not_allowed_by_object_class" "dn: cn=Loose Attribute,ou=people,${BASE_DN}
objectClass: top
objectClass: exampleEmployee
cn: Loose Attribute
sn: Attribute
uid: looseAttribute
mail: looseAttribute@example.org
exampleEmployeeNumber: 1003
exampleAccessCode: blue
exampleLooseAttribute: should-fail"

expect_add_failure "dit_content_rule_prohibits_attribute" "dn: cn=Internal Note,ou=people,${BASE_DN}
objectClass: top
objectClass: exampleEmployee
cn: Internal Note
sn: Note
uid: internalNote
mail: internalNote@example.org
exampleEmployeeNumber: 1004
exampleAccessCode: blue
exampleInternalNote: should-fail"

log_step "Validating modify and ModifyDN schema checks"
expect_modify_failure "modify_rejects_invalid_syntax" "dn: cn=Schema E2E One,ou=people,${BASE_DN}
changetype: modify
replace: exampleEmployeeNumber
exampleEmployeeNumber: invalid-modify"

expect_modify_success "modify_accepts_valid_schema_change" "dn: cn=Schema E2E One,ou=people,${BASE_DN}
changetype: modify
replace: exampleEmployeeNumber
exampleEmployeeNumber: 2001
-
replace: exampleStartTime
exampleStartTime: 20260414010101Z"

if verify_entry_attributes_ci "cn=Schema E2E One,ou=people,${BASE_DN}" \
  "exampleEmployeeNumber=2001" "exampleStartTime=20260414010101Z"; then
  log_success "✓ valid modify persisted custom schema attributes"
  PASS_COUNT=$((PASS_COUNT + 1))
else
  FAIL_COUNT=$((FAIL_COUNT + 1))
fi

expect_modify_failure "modifydn_rejects_name_form_violation" "dn: cn=Schema E2E One,ou=people,${BASE_DN}
changetype: modrdn
newrdn: exampleEmployeeNumber=2002
deleteoldrdn: 1"

expect_modify_success "modifydn_accepts_name_form_rdn" "dn: cn=Schema E2E One,ou=people,${BASE_DN}
changetype: modrdn
newrdn: cn=Schema E2E Renamed
deleteoldrdn: 1"

if verify_entry_exists "${LDAP_HOST}" "${SCHEMA_PORT}" "cn=Schema E2E Renamed,ou=people,${BASE_DN}"; then
  log_success "✓ ModifyDN result exists at the schema-valid RDN"
  PASS_COUNT=$((PASS_COUNT + 1))
else
  log_error "✗ ModifyDN result was not found"
  FAIL_COUNT=$((FAIL_COUNT + 1))
fi

log_step "Validating online schema update controls"
anonymous_schema_change="dn: cn=Subschema
changetype: modify
add: attributeTypes
attributeTypes: ( 1.3.6.1.4.1.55555.21.1 NAME 'anonymousShouldFail' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"

if print -r -- "${anonymous_schema_change}" | ldapmodify -x -H "${ldap_url}" >"${RUN_ROOT}/anonymous-schema.out" 2>"${RUN_ROOT}/anonymous-schema.err"; then
  log_error "✗ anonymous schema modify succeeded"
  FAIL_COUNT=$((FAIL_COUNT + 1))
else
  log_success "✓ anonymous schema modify is rejected"
  PASS_COUNT=$((PASS_COUNT + 1))
fi

expect_modify_success "online_schema_modify_adds_definition" "dn: cn=Subschema
changetype: modify
add: attributeTypes
attributeTypes: ( 1.3.6.1.4.1.55555.21.1 NAME 'exampleContractorCode' DESC 'Example contractor code' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
-
add: objectClasses
objectClasses: ( 1.3.6.1.4.1.55555.21.2 NAME 'exampleContractor' DESC 'Example contractor entry' SUP inetOrgPerson STRUCTURAL MUST exampleContractorCode )"

if [[ -f "${SCHEMA_DIR}/99-online.ldif" ]] && grep -q "exampleContractor" "${SCHEMA_DIR}/99-online.ldif"; then
  log_success "✓ online schema update is persisted"
  PASS_COUNT=$((PASS_COUNT + 1))
else
  log_error "✗ online schema update was not persisted"
  FAIL_COUNT=$((FAIL_COUNT + 1))
fi

expect_add_success "valid_online_schema_record_add" "dn: cn=Schema Contractor One,ou=people,${BASE_DN}
objectClass: top
objectClass: exampleContractor
cn: Schema Contractor One
sn: Contractor
uid: schemacontractor1
mail: schemacontractor1@example.org
exampleContractorCode: contract-blue"

log_step "Restarting server to verify online schema persistence"
stop_server "$(cat "${SERVER_DIR}/server.pid")" "schema:${SCHEMA_PORT}"
start_server "schema-restart:${SCHEMA_PORT}" "${CFG}" "${SERVER_DIR}/server-restart.log" "${SERVER_DIR}/server-restart.pid"
wait_for_server "${LDAP_HOST}" "${SCHEMA_PORT}" 15

if ldapsearch -LLL -o ldif-wrap=no -x -H "${ldap_url}" -D "${BIND_DN}" -w "${BIND_PW}" \
  -b "cn=Subschema" -s base "(objectClass=*)" objectClasses | grep -qi "exampleContractor"; then
  log_success "✓ persisted online schema reloads after restart"
  PASS_COUNT=$((PASS_COUNT + 1))
else
  log_error "✗ persisted online schema was not published after restart"
  FAIL_COUNT=$((FAIL_COUNT + 1))
fi

expect_add_success "valid_online_schema_record_add_after_restart" "dn: cn=Schema Contractor Two,ou=people,${BASE_DN}
objectClass: top
objectClass: exampleContractor
cn: Schema Contractor Two
sn: Contractor
uid: schemacontractor2
mail: schemacontractor2@example.org
exampleContractorCode: contract-green"

end_test

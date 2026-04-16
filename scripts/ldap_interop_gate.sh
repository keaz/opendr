#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

BASE_DN="${OPENDR_BASE_DN:-dc=example,dc=org}"
BIND_DN="${OPENDR_BIND_DN:-cn=admin,${BASE_DN}}"
BIND_PW="${OPENDR_BIND_PW:-InteropSecret-${RANDOM}-$$}"
RUNTIME="${OPENDR_RUNTIME:-fsm}"
START_SERVER="${OPENDR_INTEROP_START_SERVER:-1}"
LDAP_URL="${OPENDR_LDAP_URL:-}"
STARTTLS="${OPENDR_INTEROP_STARTTLS:-1}"
PREFIX="${OPENDR_INTEROP_PREFIX:-interop-$$}"
WORK_DIR=""
SERVER_PID=""
LDAP_BIND_ARGS=()

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

wait_for_port() {
  local host="$1"
  local port="$2"
  for _ in $(seq 1 120); do
    if (echo >"/dev/tcp/${host}/${port}") >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  echo "server did not open ${host}:${port}" >&2
  return 1
}

cleanup() {
  if [[ -n "${SERVER_PID}" ]]; then
    kill "${SERVER_PID}" >/dev/null 2>&1 || true
    wait "${SERVER_PID}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${WORK_DIR}" ]]; then
    rm -rf "${WORK_DIR}"
  fi
}
trap cleanup EXIT

set_ldap_bind_args() {
  LDAP_BIND_ARGS=(-x -H "${LDAP_URL}" -D "${BIND_DN}" -w "${BIND_PW}")
  if [[ "${STARTTLS}" == "1" ]]; then
    LDAP_BIND_ARGS=(-ZZ "${LDAP_BIND_ARGS[@]}")
  fi
}

run_ldapadd() {
  LDAPTLS_REQCERT=never ldapadd "$@"
}

run_ldapmodify() {
  LDAPTLS_REQCERT=never ldapmodify "$@"
}

run_ldapdelete() {
  LDAPTLS_REQCERT=never ldapdelete "$@"
}

run_ldapsearch() {
  LDAPTLS_REQCERT=never ldapsearch "$@"
}

run_ldapcompare() {
  LDAPTLS_REQCERT=never ldapcompare "$@"
}

expect_ldapcompare_true() {
  set +e
  run_ldapcompare "$@" >/dev/null
  local status=$?
  set -e
  if [[ "${status}" -ne 6 ]]; then
    echo "ldapcompare expected compareTrue result code 6, got ${status}" >&2
    return "${status}"
  fi
}

run_ldapmodrdn() {
  LDAPTLS_REQCERT=never ldapmodrdn "$@"
}

start_temp_server() {
  require_command openssl
  cargo build --bin opendr --bin ldap_ops_client >/dev/null

  local ldap_port ldaps_port
  ldap_port="$(reserve_port)"
  ldaps_port="$(reserve_port)"
  WORK_DIR="$(mktemp -d)"
  mkdir -p "${WORK_DIR}/config" "${WORK_DIR}/certs" "${WORK_DIR}/data"

  openssl req -x509 -newkey rsa:2048 -nodes \
    -subj "/CN=localhost" \
    -keyout "${WORK_DIR}/certs/server.key" \
    -out "${WORK_DIR}/certs/server.crt" \
    -days 1 >/dev/null 2>&1

  cat >"${WORK_DIR}/config/server.toml" <<EOF
[server]
runtime = "${RUNTIME}"
bind_address = "127.0.0.1"
ldap_port = ${ldap_port}
ldaps_port = ${ldaps_port}
base_dn = "${BASE_DN}"
root_user_dn = "cn=admin"
# Gate-local inline credential; production profile rejects inline root_password.
root_password = "${BIND_PW}"

[backend]
backend_type = "memory"
data_directory = "./data"

[schema]
enabled = true
load_builtin = ["core"]
strict_validation = true
allow_online_updates = false

[tls]
enabled = true
cert_file = "certs/server.crt"
key_file = "certs/server.key"
require_client_cert = false
min_tls_version = "1.2"

[monitoring]
enabled = false

[replication]
enabled = false

[audit]
enabled = false

[access_control]
enabled = false

[rate_limit]
enabled = false
EOF

  cat >"${WORK_DIR}/config/log4rs.yml" <<'EOF'
appenders:
  stdout:
    kind: console
root:
  level: error
  appenders:
    - stdout
EOF

  (
    cd "${WORK_DIR}"
    "${ROOT_DIR}/target/debug/opendr" >"${WORK_DIR}/server.stdout.log" 2>"${WORK_DIR}/server.stderr.log"
  ) &
  SERVER_PID="$!"
  LDAP_URL="ldap://127.0.0.1:${ldap_port}"
  wait_for_port "127.0.0.1" "${ldap_port}"
}

run_openldap_cli_checks() {
  set_ldap_bind_args

  local source_ou="ou=${PREFIX}-source,${BASE_DN}"
  local target_ou="ou=${PREFIX}-target,${BASE_DN}"
  local user_dn="cn=${PREFIX}-user,${source_ou}"
  local renamed_dn="cn=${PREFIX}-renamed,${target_ou}"

  echo "== OpenLDAP CLI: Root DSE"
  run_ldapsearch -LLL -o ldif-wrap=no "${LDAP_BIND_ARGS[@]}" -b "" -s base "(objectClass=*)" \
    namingContexts supportedControl supportedFeatures supportedExtension supportedSASLMechanisms >/dev/null

  echo "== OpenLDAP CLI: Add"
  run_ldapadd "${LDAP_BIND_ARGS[@]}" >/dev/null <<EOF
dn: ${source_ou}
objectClass: top
objectClass: organizationalUnit
ou: ${PREFIX}-source

dn: ${target_ou}
objectClass: top
objectClass: organizationalUnit
ou: ${PREFIX}-target

dn: ${user_dn}
objectClass: top
objectClass: person
objectClass: inetOrgPerson
cn: ${PREFIX}-user
sn: Initial
givenName: Interop
description: OpenLDAP CLI interop fixture
userPassword: InitialSecret123!
EOF

  echo "== OpenLDAP CLI: Search, paged results, and server-side sort"
  run_ldapsearch -LLL -o ldif-wrap=no "${LDAP_BIND_ARGS[@]}" -b "${source_ou}" -s one "(objectClass=inetOrgPerson)" cn sn >/dev/null
  run_ldapsearch -LLL -o ldif-wrap=no "${LDAP_BIND_ARGS[@]}" -E pr=1/noprompt -b "${source_ou}" -s one "(objectClass=inetOrgPerson)" cn >/dev/null
  run_ldapsearch -LLL -o ldif-wrap=no "${LDAP_BIND_ARGS[@]}" -E sss=cn -b "${source_ou}" -s one "(objectClass=inetOrgPerson)" cn >/dev/null

  echo "== OpenLDAP CLI: Modify and Compare"
  run_ldapmodify "${LDAP_BIND_ARGS[@]}" >/dev/null <<EOF
dn: ${user_dn}
changetype: modify
replace: sn
sn: Updated
-
add: displayName
displayName: OpenLDAP Interop User
-
delete: givenName
givenName: Interop
EOF
  expect_ldapcompare_true "${LDAP_BIND_ARGS[@]}" "${user_dn}" "sn:Updated"

  echo "== OpenLDAP CLI: ModifyDN"
  run_ldapmodrdn "${LDAP_BIND_ARGS[@]}" -r -s "${target_ou}" "${user_dn}" "cn=${PREFIX}-renamed" >/dev/null

  echo "== OpenLDAP CLI: Operational attributes and subschema"
  run_ldapsearch -LLL -o ldif-wrap=no "${LDAP_BIND_ARGS[@]}" -b "${renamed_dn}" -s base "(objectClass=inetOrgPerson)" "*" "+" >/dev/null
  run_ldapsearch -LLL -o ldif-wrap=no "${LDAP_BIND_ARGS[@]}" -b "cn=Subschema" -s base "(objectClass=*)" attributeTypes objectClasses >/dev/null

  echo "== OpenLDAP CLI: Delete"
  run_ldapdelete "${LDAP_BIND_ARGS[@]}" "${renamed_dn}" "${target_ou}" "${source_ou}" >/dev/null
}

run_python_ldap3_checks() {
  echo "== Python ldap3: Bind, Root DSE, schema search"
  OPENDR_LDAP_URL="${LDAP_URL}" \
  OPENDR_BASE_DN="${BASE_DN}" \
  OPENDR_BIND_DN="${BIND_DN}" \
  OPENDR_BIND_PW="${BIND_PW}" \
  OPENDR_STARTTLS="${STARTTLS}" \
  python3 - <<'PY'
import os
import ssl
from urllib.parse import urlparse

from ldap3 import BASE, Connection, Server, Tls

url = urlparse(os.environ["OPENDR_LDAP_URL"])
host = url.hostname or "127.0.0.1"
port = url.port or 389
use_ssl = url.scheme == "ldaps"
tls = Tls(validate=ssl.CERT_NONE)
server = Server(host, port=port, use_ssl=use_ssl, tls=tls, get_info=None)
conn = Connection(server, user=os.environ["OPENDR_BIND_DN"], password=os.environ["OPENDR_BIND_PW"])
conn.open()
if os.environ.get("OPENDR_STARTTLS") == "1" and not use_ssl:
    assert conn.start_tls(), conn.result
assert conn.bind(), conn.result
assert conn.search("", "(objectClass=*)", BASE, attributes=["namingContexts", "supportedControl", "supportedFeatures"])
assert conn.entries, "Root DSE search returned no entries"
assert conn.search("cn=Subschema", "(objectClass=*)", BASE, attributes=["attributeTypes", "objectClasses"])
assert conn.entries, "Subschema search returned no entries"
conn.unbind()
PY
}

run_rust_client_checks() {
  echo "== Rust ldap_ops_client: supported operation scenario"
  local args=(
    --url "${LDAP_URL}"
    --bind-dn "${BIND_DN}"
    --password "${BIND_PW}"
    --base-dn "${BASE_DN}"
    --name-prefix "${PREFIX}-rust"
  )
  if [[ "${STARTTLS}" == "1" ]]; then
    args+=(--starttls --insecure)
  fi
  cargo run --quiet --bin ldap_ops_client -- "${args[@]}"
}

main() {
  require_command cargo
  require_command ldapadd
  require_command ldapcompare
  require_command ldapdelete
  require_command ldapmodrdn
  require_command ldapmodify
  require_command ldapsearch
  require_command python3

  python3 - <<'PY'
try:
    import ldap3  # noqa: F401
except ModuleNotFoundError as exc:
    raise SystemExit("missing Python package ldap3; install it with `python3 -m pip install ldap3`") from exc
PY

  if [[ "${START_SERVER}" == "1" ]]; then
    start_temp_server
  elif [[ -z "${LDAP_URL}" ]]; then
    echo "OPENDR_LDAP_URL is required when OPENDR_INTEROP_START_SERVER=0" >&2
    exit 1
  fi

  run_openldap_cli_checks
  run_python_ldap3_checks
  run_rust_client_checks

  echo "LDAP interoperability gate completed successfully for ${LDAP_URL}"
}

main "$@"

#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

BASE_DN="${OPENDR_BASE_DN:-dc=example,dc=org}"
BIND_DN="${OPENDR_BIND_DN:-cn=admin,${BASE_DN}}"
BIND_PW="${OPENDR_BIND_PW:-InteropSecret-${RANDOM}-$$}"
SASL_AUTHCID="${OPENDR_SASL_AUTHCID:-${BIND_DN%%,*}}"
SASL_AUTHCID="${SASL_AUTHCID#*=}"
PROXY_AGENT_DN="${OPENDR_PROXY_AGENT_DN:-cn=proxy-agent,${BASE_DN}}"
PROXY_AGENT_PW="${OPENDR_PROXY_AGENT_PW:-ProxyAgentSecret-${RANDOM}-$$}"
PROXY_AUTHCID="${OPENDR_PROXY_AUTHCID:-${PROXY_AGENT_DN%%,*}}"
PROXY_AUTHCID="${PROXY_AUTHCID#*=}"
PROXY_TARGET_DN="${OPENDR_PROXY_TARGET_DN:-cn=proxy-target,${BASE_DN}}"
PROXY_TARGET_AUTHCID="${OPENDR_PROXY_TARGET_AUTHCID:-${PROXY_TARGET_DN%%,*}}"
PROXY_TARGET_AUTHCID="${PROXY_TARGET_AUTHCID#*=}"
PROXY_DENIED_DN="${OPENDR_PROXY_DENIED_DN:-cn=proxy-denied,${BASE_DN}}"
PROXY_DENIED_AUTHCID="${OPENDR_PROXY_DENIED_AUTHCID:-${PROXY_DENIED_DN%%,*}}"
PROXY_DENIED_AUTHCID="${PROXY_DENIED_AUTHCID#*=}"
RUNTIME="${OPENDR_RUNTIME:-fsm}"
START_SERVER="${OPENDR_INTEROP_START_SERVER:-1}"
LDAP_URL="${OPENDR_LDAP_URL:-}"
LDAPS_URL="${OPENDR_LDAPS_URL:-}"
STARTTLS="${OPENDR_INTEROP_STARTTLS:-1}"
PREFIX="${OPENDR_INTEROP_PREFIX:-interop-$$}"
ARTIFACT_DIR="${OPENDR_INTEROP_ARTIFACT_DIR:-${ROOT_DIR}/target/ldap-interop-gate/$(date -u +%Y%m%dT%H%M%SZ)}"
SKIP_LDAP3="${OPENDR_INTEROP_SKIP_LDAP3:-0}"
RUN_MTLS="${OPENDR_INTEROP_RUN_MTLS:-1}"
REQUIRE_OPENLDAP_MTLS="${OPENDR_INTEROP_REQUIRE_OPENLDAP_MTLS:-0}"
WORK_DIR=""
MTLS_WORK_DIR=""
SERVER_PID=""
MTLS_SERVER_PID=""
MTLS_LDAP_URL="${OPENDR_MTLS_LDAP_URL:-}"
MTLS_LDAPS_URL="${OPENDR_MTLS_LDAPS_URL:-}"
MTLS_CLIENT_CERT="${OPENDR_MTLS_CLIENT_CERT:-}"
MTLS_CLIENT_KEY="${OPENDR_MTLS_CLIENT_KEY:-}"
MTLS_CA_CERT="${OPENDR_MTLS_CA_CERT:-}"
MTLS_LDAP_CONF="${OPENDR_MTLS_LDAP_CONF:-}"
LDAP_BIND_ARGS=()
TRANSCRIPT_FILE=""

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

init_artifacts() {
  mkdir -p "${ARTIFACT_DIR}"
  TRANSCRIPT_FILE="${ARTIFACT_DIR}/transcript.log"
  : >"${TRANSCRIPT_FILE}"
}

redact_text() {
  local text="$1"
  text="${text//${BIND_PW}/<redacted-password>}"
  text="${text//${PROXY_AGENT_PW}/<redacted-password>}"
  printf '%s' "${text}"
}

log_step() {
  echo "== $*"
  if [[ -n "${TRANSCRIPT_FILE}" ]]; then
    printf 'STEP %s\n' "$*" >>"${TRANSCRIPT_FILE}"
  fi
}

log_command() {
  if [[ -z "${TRANSCRIPT_FILE}" ]]; then
    return 0
  fi

  local redact_next=0
  local rendered=()
  local arg
  for arg in "$@"; do
    if [[ "${redact_next}" == "1" ]]; then
      rendered+=("<redacted-password>")
      redact_next=0
      continue
    fi
    if [[ "${arg}" == "-w" ]]; then
      rendered+=("${arg}")
      redact_next=1
      continue
    fi
    rendered+=("$(redact_text "${arg}")")
  done

  {
    printf '$'
    printf ' %q' "${rendered[@]}"
    printf '\n'
  } >>"${TRANSCRIPT_FILE}"
}

record_command_result() {
  local label="$1"
  local status="$2"
  local output="$3"
  if [[ -n "${TRANSCRIPT_FILE}" ]]; then
    {
      printf 'RESULT %s status=%s\n' "${label}" "${status}"
      redact_text "${output}"
      printf '\n'
    } >>"${TRANSCRIPT_FILE}"
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
  if [[ -n "${MTLS_SERVER_PID}" ]]; then
    kill "${MTLS_SERVER_PID}" >/dev/null 2>&1 || true
    wait "${MTLS_SERVER_PID}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${WORK_DIR}" && -d "${WORK_DIR}" && -n "${ARTIFACT_DIR}" ]]; then
    cp "${WORK_DIR}/server.stdout.log" "${ARTIFACT_DIR}/server.stdout.log" 2>/dev/null || true
    cp "${WORK_DIR}/server.stderr.log" "${ARTIFACT_DIR}/server.stderr.log" 2>/dev/null || true
  fi
  if [[ -n "${MTLS_WORK_DIR}" && -d "${MTLS_WORK_DIR}" && -n "${ARTIFACT_DIR}" ]]; then
    cp "${MTLS_WORK_DIR}/server.stdout.log" "${ARTIFACT_DIR}/mtls-server.stdout.log" 2>/dev/null || true
    cp "${MTLS_WORK_DIR}/server.stderr.log" "${ARTIFACT_DIR}/mtls-server.stderr.log" 2>/dev/null || true
  fi
  if [[ -n "${WORK_DIR}" ]]; then
    rm -rf "${WORK_DIR}"
  fi
  if [[ -n "${MTLS_WORK_DIR}" ]]; then
    rm -rf "${MTLS_WORK_DIR}"
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
  log_command LDAPTLS_REQCERT=never ldapadd "$@"
  LDAPTLS_REQCERT=never ldapadd "$@"
}

run_ldapmodify() {
  log_command LDAPTLS_REQCERT=never ldapmodify "$@"
  LDAPTLS_REQCERT=never ldapmodify "$@"
}

run_ldapdelete() {
  log_command LDAPTLS_REQCERT=never ldapdelete "$@"
  LDAPTLS_REQCERT=never ldapdelete "$@"
}

run_ldapsearch() {
  log_command LDAPTLS_REQCERT=never ldapsearch "$@"
  LDAPTLS_REQCERT=never ldapsearch "$@"
}

run_ldapcompare() {
  log_command LDAPTLS_REQCERT=never ldapcompare "$@"
  LDAPTLS_REQCERT=never ldapcompare "$@"
}

run_ldapwhoami() {
  log_command LDAPTLS_REQCERT=never ldapwhoami "$@"
  LDAPTLS_REQCERT=never ldapwhoami "$@"
}

run_mtls_ldapsearch() {
  log_command LDAPCONF="${MTLS_LDAP_CONF}" LDAPTLS_REQCERT=never LDAPTLS_CERT="${MTLS_CLIENT_CERT}" LDAPTLS_KEY="${MTLS_CLIENT_KEY}" LDAPTLS_CACERT="${MTLS_CA_CERT}" ldapsearch "$@"
  LDAPCONF="${MTLS_LDAP_CONF}" LDAPTLS_REQCERT=never LDAPTLS_CERT="${MTLS_CLIENT_CERT}" LDAPTLS_KEY="${MTLS_CLIENT_KEY}" LDAPTLS_CACERT="${MTLS_CA_CERT}" ldapsearch "$@"
}

run_mtls_ldapwhoami() {
  log_command LDAPCONF="${MTLS_LDAP_CONF}" LDAPTLS_REQCERT=never LDAPTLS_CERT="${MTLS_CLIENT_CERT}" LDAPTLS_KEY="${MTLS_CLIENT_KEY}" LDAPTLS_CACERT="${MTLS_CA_CERT}" ldapwhoami "$@"
  LDAPCONF="${MTLS_LDAP_CONF}" LDAPTLS_REQCERT=never LDAPTLS_CERT="${MTLS_CLIENT_CERT}" LDAPTLS_KEY="${MTLS_CLIENT_KEY}" LDAPTLS_CACERT="${MTLS_CA_CERT}" ldapwhoami "$@"
}

expect_ldapwhoami_failure() {
  local label="$1"
  shift
  local output status
  set +e
  output="$(run_ldapwhoami "$@" 2>&1)"
  status=$?
  set -e
  record_command_result "${label}" "${status}" "${output}"
  if [[ "${status}" -eq 0 ]]; then
    echo "${label}: expected ldapwhoami to fail" >&2
    return 1
  fi
}

expect_whoami() {
  local label="$1"
  local expected="$2"
  shift 2
  local output
  output="$(run_ldapwhoami "$@")"
  record_command_result "${label}" "0" "${output}"
  if [[ "$(tail -n 1 <<<"${output}")" != "${expected}" ]]; then
    echo "${label}: got '${output}', expected '${expected}'" >&2
    return 1
  fi
}

expect_mtls_whoami() {
  local label="$1"
  local expected="$2"
  shift 2
  local output
  output="$(run_mtls_ldapwhoami "$@")"
  record_command_result "${label}" "0" "${output}"
  if [[ "$(tail -n 1 <<<"${output}")" != "${expected}" ]]; then
    echo "${label}: got '${output}', expected '${expected}'" >&2
    return 1
  fi
}

expect_mtls_ldapwhoami_failure() {
  local label="$1"
  shift
  local output status
  set +e
  output="$(run_mtls_ldapwhoami "$@" 2>&1)"
  status=$?
  set -e
  record_command_result "${label}" "${status}" "${output}"
  if [[ "${status}" -eq 0 ]]; then
    echo "${label}: expected ldapwhoami to fail" >&2
    return 1
  fi
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
  log_command LDAPTLS_REQCERT=never ldapmodrdn "$@"
  LDAPTLS_REQCERT=never ldapmodrdn "$@"
}

assert_no_sasl_mechanisms() {
  local output="$1"
  if grep -q '^supportedSASLMechanisms:' <<<"${output}"; then
    echo "Root DSE advertised SASL mechanisms before transport confidentiality" >&2
    return 1
  fi
}

assert_sasl_mechanisms() {
  local output="$1"
  shift
  local mechanism count expected_count
  for mechanism in "$@"; do
    if ! grep -q "^supportedSASLMechanisms: ${mechanism}$" <<<"${output}"; then
      echo "Root DSE did not advertise expected SASL mechanism ${mechanism}" >&2
      return 1
    fi
  done
  count="$(grep -c '^supportedSASLMechanisms:' <<<"${output}" || true)"
  expected_count="$#"
  if [[ "${count}" -ne "${expected_count}" ]]; then
    echo "Root DSE advertised ${count} SASL mechanisms, expected ${expected_count}" >&2
    return 1
  fi
}

start_temp_server() {
  require_command openssl
  cargo build --bin opendr --bin ldap_ops_client >/dev/null

  local ldap_port ldaps_port
  ldap_port="$(reserve_port)"
  ldaps_port="$(reserve_port)"
  WORK_DIR="$(mktemp -d)"
  mkdir -p "${WORK_DIR}/config" "${WORK_DIR}/certs" "${WORK_DIR}/data"
  printf '%s' "${BIND_PW}" >"${WORK_DIR}/config/root_password.txt"
  chmod 600 "${WORK_DIR}/config/root_password.txt"
  cat >"${WORK_DIR}/config/base.ldif" <<EOF
dn: ${BASE_DN}
objectClass: top
objectClass: domain
dc: example
EOF
  cat >"${WORK_DIR}/config/admin.ldif" <<EOF
dn: ${BIND_DN}
objectClass: top
objectClass: person
cn: ${SASL_AUTHCID}
sn: Administrator
userPassword: ${BIND_PW}

dn: ${PROXY_AGENT_DN}
objectClass: top
objectClass: person
cn: ${PROXY_AUTHCID}
sn: Agent
userPassword: ${PROXY_AGENT_PW}

dn: ${PROXY_TARGET_DN}
objectClass: top
objectClass: person
cn: ${PROXY_TARGET_AUTHCID}
sn: Target
userPassword: ProxyTargetSecret123!

dn: ${PROXY_DENIED_DN}
objectClass: top
objectClass: person
cn: ${PROXY_DENIED_AUTHCID}
sn: Denied
userPassword: ProxyDeniedSecret123!
EOF
  cat >"${WORK_DIR}/config/aci.toml" <<EOF
[[rules]]
name = "proxy-agent-may-proxy-target"
effect = "grant"
priority = 100
permissions = ["proxy"]
target = { dn = "${PROXY_TARGET_DN}" }
subject = { user = "${PROXY_AGENT_DN}" }
EOF

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
root_password_file = "config/root_password.txt"

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

[security]
profile = "production"
allow_anonymous_bind = true
allow_sasl_plain = true
allow_sasl_external = true

[monitoring]
enabled = false

[replication]
enabled = false

[audit]
enabled = false

[access_control]
enabled = true
default_policy = "deny"
rules_file = "config/aci.toml"

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
  LDAPS_URL="ldaps://127.0.0.1:${ldaps_port}"
  wait_for_port "127.0.0.1" "${ldap_port}"
}

generate_mtls_certificates() {
  local cert_dir="$1"
  cat >"${cert_dir}/server.ext" <<'EOF'
subjectAltName=DNS:localhost,IP:127.0.0.1
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EOF
  cat >"${cert_dir}/client.ext" <<'EOF'
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
EOF

  openssl req -x509 -newkey rsa:2048 -nodes \
    -subj "/CN=OpenDR Interop CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "${cert_dir}/ca.key" \
    -out "${cert_dir}/ca.crt" \
    -days 1 >/dev/null 2>&1

  openssl req -newkey rsa:2048 -nodes \
    -subj "/CN=localhost" \
    -keyout "${cert_dir}/server.key" \
    -out "${cert_dir}/server.csr" >/dev/null 2>&1
  openssl x509 -req \
    -in "${cert_dir}/server.csr" \
    -CA "${cert_dir}/ca.crt" \
    -CAkey "${cert_dir}/ca.key" \
    -CAcreateserial \
    -out "${cert_dir}/server.crt" \
    -days 1 \
    -sha256 \
    -extfile "${cert_dir}/server.ext" >/dev/null 2>&1

  openssl req -newkey rsa:2048 -nodes \
    -subj "/CN=opendr-client" \
    -keyout "${cert_dir}/client.key" \
    -out "${cert_dir}/client.csr" >/dev/null 2>&1
  openssl x509 -req \
    -in "${cert_dir}/client.csr" \
    -CA "${cert_dir}/ca.crt" \
    -CAkey "${cert_dir}/ca.key" \
    -CAcreateserial \
    -out "${cert_dir}/client.crt" \
    -days 1 \
    -sha256 \
    -extfile "${cert_dir}/client.ext" >/dev/null 2>&1
}

start_mtls_temp_server() {
  require_command openssl

  local ldap_port ldaps_port
  ldap_port="$(reserve_port)"
  ldaps_port="$(reserve_port)"
  MTLS_WORK_DIR="$(mktemp -d)"
  mkdir -p "${MTLS_WORK_DIR}/config" "${MTLS_WORK_DIR}/certs" "${MTLS_WORK_DIR}/data"
  printf '%s' "${BIND_PW}" >"${MTLS_WORK_DIR}/config/root_password.txt"
  chmod 600 "${MTLS_WORK_DIR}/config/root_password.txt"
  cat >"${MTLS_WORK_DIR}/config/base.ldif" <<EOF
dn: ${BASE_DN}
objectClass: top
objectClass: domain
dc: example
EOF
  cat >"${MTLS_WORK_DIR}/config/admin.ldif" <<EOF
dn: ${BIND_DN}
objectClass: top
objectClass: person
cn: ${SASL_AUTHCID}
sn: Administrator
userPassword: ${BIND_PW}

dn: ${PROXY_AGENT_DN}
objectClass: top
objectClass: person
cn: ${PROXY_AUTHCID}
sn: Agent
userPassword: ${PROXY_AGENT_PW}

dn: ${PROXY_TARGET_DN}
objectClass: top
objectClass: person
cn: ${PROXY_TARGET_AUTHCID}
sn: Target
userPassword: ProxyTargetSecret123!

dn: ${PROXY_DENIED_DN}
objectClass: top
objectClass: person
cn: ${PROXY_DENIED_AUTHCID}
sn: Denied
userPassword: ProxyDeniedSecret123!
EOF
  cat >"${MTLS_WORK_DIR}/config/aci.toml" <<EOF
[[rules]]
name = "proxy-agent-may-proxy-target"
effect = "grant"
priority = 100
permissions = ["proxy"]
target = { dn = "${PROXY_TARGET_DN}" }
subject = { user = "${PROXY_AGENT_DN}" }
EOF
  generate_mtls_certificates "${MTLS_WORK_DIR}/certs"

  cat >"${MTLS_WORK_DIR}/config/server.toml" <<EOF
[server]
runtime = "${RUNTIME}"
bind_address = "127.0.0.1"
ldap_port = ${ldap_port}
ldaps_port = ${ldaps_port}
base_dn = "${BASE_DN}"
root_user_dn = "cn=admin"
root_password_file = "config/root_password.txt"

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
ca_file = "certs/ca.crt"
require_client_cert = true
min_tls_version = "1.2"

[security]
profile = "production"
allow_anonymous_bind = true
allow_sasl_plain = true
allow_sasl_external = true
sasl_external_identity_map = { "opendr-client" = "${PROXY_AGENT_DN}" }

[monitoring]
enabled = false

[replication]
enabled = false

[audit]
enabled = false

[access_control]
enabled = true
default_policy = "deny"
rules_file = "config/aci.toml"

[rate_limit]
enabled = false
EOF

  cat >"${MTLS_WORK_DIR}/config/log4rs.yml" <<'EOF'
appenders:
  stdout:
    kind: console
root:
  level: error
  appenders:
    - stdout
EOF

  (
    cd "${MTLS_WORK_DIR}"
    "${ROOT_DIR}/target/debug/opendr" >"${MTLS_WORK_DIR}/server.stdout.log" 2>"${MTLS_WORK_DIR}/server.stderr.log"
  ) &
  MTLS_SERVER_PID="$!"
  MTLS_LDAP_URL="ldap://127.0.0.1:${ldap_port}"
  MTLS_LDAPS_URL="ldaps://127.0.0.1:${ldaps_port}"
  MTLS_CLIENT_CERT="${MTLS_WORK_DIR}/certs/client.crt"
  MTLS_CLIENT_KEY="${MTLS_WORK_DIR}/certs/client.key"
  MTLS_CA_CERT="${MTLS_WORK_DIR}/certs/ca.crt"
  MTLS_LDAP_CONF="${MTLS_WORK_DIR}/ldap.conf"
  cat >"${MTLS_LDAP_CONF}" <<EOF
TLS_CERT ${MTLS_CLIENT_CERT}
TLS_KEY ${MTLS_CLIENT_KEY}
TLS_CACERT ${MTLS_CA_CERT}
TLS_REQCERT never
EOF
  wait_for_port "127.0.0.1" "${ldap_port}"
}

run_raw_malformed_sasl_plain_check() {
  local label="$1"
  local url="$2"
  local starttls="$3"

  log_step "${label}"
  log_command OPENDR_LDAP_URL="${url}" OPENDR_STARTTLS="${starttls}" python3 "<raw-malformed-sasl-plain-check>"
  OPENDR_LDAP_URL="${url}" OPENDR_STARTTLS="${starttls}" python3 - <<'PY'
import os
import socket
import ssl
from urllib.parse import urlparse


def ber_len(length):
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def tlv(tag, value):
    return bytes([tag]) + ber_len(len(value)) + value


def integer(value):
    return tlv(0x02, bytes([value]))


def octet(value):
    return tlv(0x04, value)


def ldap_message(message_id, protocol_op):
    return tlv(0x30, integer(message_id) + protocol_op)


def read_ldap_message(stream):
    header = stream.recv(2)
    if len(header) != 2 or header[0] != 0x30:
        raise AssertionError(f"invalid LDAP response header: {header!r}")
    length = header[1]
    if length & 0x80:
        width = length & 0x7F
        raw = stream.recv(width)
        if len(raw) != width:
            raise AssertionError("short LDAP response length")
        length = int.from_bytes(raw, "big")
    body = bytearray()
    while len(body) < length:
        chunk = stream.recv(length - len(body))
        if not chunk:
            raise AssertionError("short LDAP response body")
        body.extend(chunk)
    return bytes(body)


def result_code(response_body):
    marker = response_body.find(b"\x0a\x01")
    if marker == -1 or marker + 2 >= len(response_body):
        raise AssertionError(f"LDAP response had no result code: {response_body!r}")
    return response_body[marker + 2]


url = urlparse(os.environ["OPENDR_LDAP_URL"])
host = url.hostname or "127.0.0.1"
port = url.port or (636 if url.scheme == "ldaps" else 389)
sock = socket.create_connection((host, port), timeout=5)
try:
    if url.scheme == "ldaps":
        sock = ssl._create_unverified_context().wrap_socket(sock, server_hostname=host)
    elif os.environ.get("OPENDR_STARTTLS") == "1":
        starttls = ldap_message(
            1,
            tlv(0x77, tlv(0x80, b"1.3.6.1.4.1.1466.20037")),
        )
        sock.sendall(starttls)
        response = read_ldap_message(sock)
        assert result_code(response) == 0, response
        sock = ssl._create_unverified_context().wrap_socket(sock, server_hostname=host)

    malformed_bind = ldap_message(
        2,
        tlv(
            0x60,
            integer(3)
            + octet(b"")
            + tlv(0xA3, octet(b"PLAIN") + octet(b"malformed")),
        ),
    )
    sock.sendall(malformed_bind)
    response = read_ldap_message(sock)
    code = result_code(response)
    if code == 0:
        raise AssertionError("malformed SASL PLAIN bind unexpectedly succeeded")
finally:
    sock.close()
PY
}

run_rfc4513_auth_cli_checks() {
  log_step "OpenLDAP CLI: RFC 4513 Root DSE and authentication security"

  if [[ "${STARTTLS}" == "1" && "${LDAP_URL}" == ldap://* ]]; then
    local insecure_root_dse
    insecure_root_dse="$(run_ldapsearch -LLL -o ldif-wrap=no -x -H "${LDAP_URL}" -b "" -s base "(objectClass=*)" supportedSASLMechanisms)"
    assert_no_sasl_mechanisms "${insecure_root_dse}"
  fi

  local root_dse
  root_dse="$(run_ldapsearch -LLL -o ldif-wrap=no "${LDAP_BIND_ARGS[@]}" -b "" -s base "(objectClass=*)" \
    namingContexts supportedControl supportedFeatures supportedExtension supportedSASLMechanisms)"
  if [[ "${STARTTLS}" == "1" || "${LDAP_URL}" == ldaps://* ]]; then
    assert_sasl_mechanisms "${root_dse}" PLAIN
  fi

  if [[ "${LDAP_URL}" == ldap://* ]]; then
    expect_ldapwhoami_failure \
      "cleartext simple bind rejected by production profile" \
      -x -H "${LDAP_URL}" -D "${BIND_DN}" -w "${BIND_PW}"
    expect_ldapwhoami_failure \
      "SASL PLAIN rejected before transport confidentiality" \
      -Q -Y PLAIN -D "${BIND_DN}" -U "${SASL_AUTHCID}" -w "${BIND_PW}" -H "${LDAP_URL}"
  fi

  if [[ "${STARTTLS}" == "1" || "${LDAP_URL}" == ldaps://* ]]; then
    expect_whoami \
      "simple bind WhoAmI over confidential transport" \
      "dn:${BIND_DN}" \
      "${LDAP_BIND_ARGS[@]}"
    local failed_simple_args=(-x -H "${LDAP_URL}" -D "${BIND_DN}" -w "${BIND_PW}-wrong")
    if [[ "${STARTTLS}" == "1" ]]; then
      failed_simple_args=(-ZZ "${failed_simple_args[@]}")
    fi
    expect_ldapwhoami_failure \
      "failed simple bind over confidential transport" \
      "${failed_simple_args[@]}"

    local sasl_plain_args=(-Q -Y PLAIN -D "${BIND_DN}" -U "${SASL_AUTHCID}" -w "${BIND_PW}" -H "${LDAP_URL}")
    if [[ "${STARTTLS}" == "1" ]]; then
      sasl_plain_args=(-ZZ "${sasl_plain_args[@]}")
    fi
    expect_whoami \
      "SASL PLAIN WhoAmI over StartTLS" \
      "dn:${BIND_DN}" \
      "${sasl_plain_args[@]}"
    local sasl_plain_proxy_args=(-Q -Y PLAIN -D "cn=ignored,${BASE_DN}" -U "${PROXY_AUTHCID}" -w "${PROXY_AGENT_PW}" -H "${LDAP_URL}")
    if [[ "${STARTTLS}" == "1" ]]; then
      sasl_plain_proxy_args=(-ZZ "${sasl_plain_proxy_args[@]}")
    fi
    expect_ldapwhoami_failure \
      "SASL PLAIN proxy authzid denied over StartTLS" \
      "${sasl_plain_proxy_args[@]}" -X "u:${PROXY_DENIED_AUTHCID}"
    expect_whoami \
      "SASL PLAIN proxy authzid granted over StartTLS" \
      "dn:${PROXY_TARGET_DN}" \
      "${sasl_plain_proxy_args[@]}" -X "u:${PROXY_TARGET_AUTHCID}"
    run_raw_malformed_sasl_plain_check \
      "Python raw LDAP: malformed SASL PLAIN over StartTLS" \
      "${LDAP_URL}" \
      "${STARTTLS}"
  fi

  if [[ -n "${LDAPS_URL}" ]]; then
    expect_whoami \
      "simple bind WhoAmI over LDAPS" \
      "dn:${BIND_DN}" \
      -x -H "${LDAPS_URL}" -D "${BIND_DN}" -w "${BIND_PW}"
    expect_whoami \
      "SASL PLAIN WhoAmI over LDAPS" \
      "dn:${BIND_DN}" \
      -Q -Y PLAIN -D "${BIND_DN}" -U "${SASL_AUTHCID}" -w "${BIND_PW}" -H "${LDAPS_URL}"
    expect_ldapwhoami_failure \
      "SASL PLAIN proxy authzid denied over LDAPS" \
      -Q -Y PLAIN -D "cn=ignored,${BASE_DN}" -U "${PROXY_AUTHCID}" -w "${PROXY_AGENT_PW}" -H "${LDAPS_URL}" -X "u:${PROXY_DENIED_AUTHCID}"
    expect_whoami \
      "SASL PLAIN proxy authzid granted over LDAPS" \
      "dn:${PROXY_TARGET_DN}" \
      -Q -Y PLAIN -D "cn=ignored,${BASE_DN}" -U "${PROXY_AUTHCID}" -w "${PROXY_AGENT_PW}" -H "${LDAPS_URL}" -X "u:${PROXY_TARGET_AUTHCID}"
    run_raw_malformed_sasl_plain_check \
      "Python raw LDAP: malformed SASL PLAIN over LDAPS" \
      "${LDAPS_URL}" \
      "0"
  fi
}

run_mtls_external_cli_checks() {
  if [[ "${RUN_MTLS}" != "1" ]]; then
    log_step "OpenLDAP CLI: SASL EXTERNAL mTLS checks skipped"
    return 0
  fi

  if [[ "${START_SERVER}" == "1" && -z "${MTLS_LDAP_URL}" ]]; then
    start_mtls_temp_server
  fi

  if [[ -z "${MTLS_LDAP_URL}" || -z "${MTLS_LDAPS_URL}" || -z "${MTLS_CLIENT_CERT}" || -z "${MTLS_CLIENT_KEY}" ]]; then
    echo "mTLS checks require OPENDR_MTLS_LDAP_URL, OPENDR_MTLS_LDAPS_URL, OPENDR_MTLS_CLIENT_CERT, and OPENDR_MTLS_CLIENT_KEY" >&2
    return 1
  fi
  if [[ -z "${MTLS_LDAP_CONF}" ]]; then
    MTLS_LDAP_CONF="/dev/null"
  fi

  log_step "OpenLDAP CLI: SASL EXTERNAL over mutual TLS"

  local insecure_root_dse
  insecure_root_dse="$(run_ldapsearch -LLL -o ldif-wrap=no -x -H "${MTLS_LDAP_URL}" -b "" -s base "(objectClass=*)" supportedSASLMechanisms)"
  assert_no_sasl_mechanisms "${insecure_root_dse}"

  expect_ldapwhoami_failure \
    "SASL EXTERNAL rejected before transport confidentiality" \
    -Q -Y EXTERNAL -H "${MTLS_LDAP_URL}"

  if run_openldap_mtls_external_checks; then
    return 0
  fi

  if [[ "${REQUIRE_OPENLDAP_MTLS}" == "1" ]]; then
    echo "OpenLDAP mTLS checks failed and OPENDR_INTEROP_REQUIRE_OPENLDAP_MTLS=1" >&2
    return 1
  fi

  log_step "OpenLDAP CLI mTLS client certificate unavailable; running raw TLS fallback"
  run_raw_mtls_external_check "Python raw LDAP: SASL EXTERNAL over StartTLS mTLS" "${MTLS_LDAP_URL}" "1"
  run_raw_mtls_external_check "Python raw LDAP: SASL EXTERNAL over LDAPS mTLS" "${MTLS_LDAPS_URL}" "0"
}

run_openldap_mtls_external_checks() {
  local mtls_starttls_root_dse
  local status
  set +e
  mtls_starttls_root_dse="$(run_mtls_ldapsearch -LLL -o ldif-wrap=no -x -ZZ -H "${MTLS_LDAP_URL}" -b "" -s base "(objectClass=*)" supportedSASLMechanisms 2>&1)"
  status=$?
  set -e
  if [[ "${status}" -ne 0 ]]; then
    record_command_result "OpenLDAP mTLS StartTLS Root DSE" "${status}" "${mtls_starttls_root_dse}"
    return 1
  fi
  assert_sasl_mechanisms "${mtls_starttls_root_dse}" PLAIN EXTERNAL || return 1

  local mtls_ldaps_root_dse
  set +e
  mtls_ldaps_root_dse="$(run_mtls_ldapsearch -LLL -o ldif-wrap=no -x -H "${MTLS_LDAPS_URL}" -b "" -s base "(objectClass=*)" supportedSASLMechanisms 2>&1)"
  status=$?
  set -e
  if [[ "${status}" -ne 0 ]]; then
    record_command_result "OpenLDAP mTLS LDAPS Root DSE" "${status}" "${mtls_ldaps_root_dse}"
    return 1
  fi
  assert_sasl_mechanisms "${mtls_ldaps_root_dse}" PLAIN EXTERNAL || return 1

  expect_mtls_whoami \
    "SASL EXTERNAL WhoAmI over StartTLS" \
    "dn:${PROXY_AGENT_DN}" \
    -Q -Y EXTERNAL -ZZ -H "${MTLS_LDAP_URL}" || return 1
  expect_mtls_whoami \
    "SASL EXTERNAL WhoAmI over LDAPS" \
    "dn:${PROXY_AGENT_DN}" \
    -Q -Y EXTERNAL -H "${MTLS_LDAPS_URL}" || return 1
  expect_mtls_whoami \
    "SASL EXTERNAL explicit authzid over StartTLS" \
    "dn:${PROXY_AGENT_DN}" \
    -Q -Y EXTERNAL -X "dn:${PROXY_AGENT_DN}" -ZZ -H "${MTLS_LDAP_URL}" || return 1
  expect_mtls_ldapwhoami_failure \
    "SASL EXTERNAL proxy authzid denied over StartTLS" \
    -Q -Y EXTERNAL -X "dn:${PROXY_DENIED_DN}" -ZZ -H "${MTLS_LDAP_URL}" || return 1
  expect_mtls_whoami \
    "SASL EXTERNAL proxy authzid granted over StartTLS" \
    "dn:${PROXY_TARGET_DN}" \
    -Q -Y EXTERNAL -X "dn:${PROXY_TARGET_DN}" -ZZ -H "${MTLS_LDAP_URL}" || return 1
  expect_mtls_whoami \
    "SASL EXTERNAL proxy authzid granted over LDAPS" \
    "dn:${PROXY_TARGET_DN}" \
    -Q -Y EXTERNAL -X "dn:${PROXY_TARGET_DN}" -H "${MTLS_LDAPS_URL}" || return 1
}

run_raw_mtls_external_check() {
  local label="$1"
  local url="$2"
  local starttls="$3"

  log_step "${label}"
  log_command OPENDR_LDAP_URL="${url}" OPENDR_STARTTLS="${starttls}" OPENDR_MTLS_CLIENT_CERT="${MTLS_CLIENT_CERT}" OPENDR_MTLS_CLIENT_KEY="${MTLS_CLIENT_KEY}" python3 "<raw-mtls-sasl-external-check>"
  OPENDR_LDAP_URL="${url}" \
  OPENDR_STARTTLS="${starttls}" \
  OPENDR_BASE_DN="${BASE_DN}" \
  OPENDR_PROXY_AGENT_DN="${PROXY_AGENT_DN}" \
  OPENDR_PROXY_TARGET_DN="${PROXY_TARGET_DN}" \
  OPENDR_PROXY_DENIED_DN="${PROXY_DENIED_DN}" \
  OPENDR_MTLS_CLIENT_CERT="${MTLS_CLIENT_CERT}" \
  OPENDR_MTLS_CLIENT_KEY="${MTLS_CLIENT_KEY}" \
  OPENDR_MTLS_CA_CERT="${MTLS_CA_CERT}" \
  python3 - <<'PY'
import os
import socket
import ssl
from urllib.parse import urlparse


def ber_len(length):
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def tlv(tag, value):
    return bytes([tag]) + ber_len(len(value)) + value


def integer(value):
    return tlv(0x02, bytes([value]))


def enum(value):
    return tlv(0x0A, bytes([value]))


def boolean(value):
    return tlv(0x01, b"\xff" if value else b"\x00")


def octet(value):
    return tlv(0x04, value)


def sequence(value):
    return tlv(0x30, value)


def ldap_message(message_id, protocol_op):
    return sequence(integer(message_id) + protocol_op)


def read_ldap_message(stream):
    header = stream.recv(2)
    if len(header) != 2 or header[0] != 0x30:
        raise AssertionError(f"invalid LDAP response header: {header!r}")
    length = header[1]
    if length & 0x80:
        width = length & 0x7F
        raw = stream.recv(width)
        if len(raw) != width:
            raise AssertionError("short LDAP response length")
        length = int.from_bytes(raw, "big")
    body = bytearray()
    while len(body) < length:
        chunk = stream.recv(length - len(body))
        if not chunk:
            raise AssertionError("short LDAP response body")
        body.extend(chunk)
    return bytes(body)


def result_code(response_body):
    marker = response_body.find(b"\x0a\x01")
    if marker == -1 or marker + 2 >= len(response_body):
        raise AssertionError(f"LDAP response had no result code: {response_body!r}")
    return response_body[marker + 2]


def tls_context():
    ctx = ssl._create_unverified_context()
    ctx.load_cert_chain(
        os.environ["OPENDR_MTLS_CLIENT_CERT"],
        os.environ["OPENDR_MTLS_CLIENT_KEY"],
    )
    ca = os.environ.get("OPENDR_MTLS_CA_CERT")
    if ca:
        ctx.load_verify_locations(cafile=ca)
    return ctx


def connect():
    url = urlparse(os.environ["OPENDR_LDAP_URL"])
    host = url.hostname or "127.0.0.1"
    port = url.port or (636 if url.scheme == "ldaps" else 389)
    sock = socket.create_connection((host, port), timeout=5)
    if url.scheme == "ldaps":
        return tls_context().wrap_socket(sock, server_hostname=host)
    if os.environ.get("OPENDR_STARTTLS") == "1":
        starttls = ldap_message(
            1,
            tlv(0x77, tlv(0x80, b"1.3.6.1.4.1.1466.20037")),
        )
        sock.sendall(starttls)
        response = read_ldap_message(sock)
        assert result_code(response) == 0, response
        return tls_context().wrap_socket(sock, server_hostname=host)
    return sock


def search_root_dse(stream):
    search = ldap_message(
        2,
        tlv(
            0x63,
            octet(b"")
            + enum(0)
            + enum(0)
            + integer(0)
            + integer(0)
            + boolean(False)
            + tlv(0x87, b"objectClass")
            + sequence(octet(b"supportedSASLMechanisms")),
        ),
    )
    stream.sendall(search)
    entry = read_ldap_message(stream)
    done = read_ldap_message(stream)
    assert result_code(done) == 0, done
    for expected in (b"supportedSASLMechanisms", b"PLAIN", b"EXTERNAL"):
        if expected not in entry:
            raise AssertionError(f"Root DSE response missing {expected!r}: {entry!r}")


def sasl_external_bind(stream, authzid=None):
    credentials = octet(authzid.encode()) if authzid is not None else b""
    bind = ldap_message(
        3,
        tlv(0x60, integer(3) + octet(b"") + tlv(0xA3, octet(b"EXTERNAL") + credentials)),
    )
    stream.sendall(bind)
    return result_code(read_ldap_message(stream))


def whoami(stream):
    request = ldap_message(
        4,
        tlv(0x77, tlv(0x80, b"1.3.6.1.4.1.4203.1.11.3")),
    )
    stream.sendall(request)
    return read_ldap_message(stream)


expected = f"dn:{os.environ['OPENDR_PROXY_AGENT_DN']}".encode()
proxy_target = f"dn:{os.environ['OPENDR_PROXY_TARGET_DN']}".encode()
with connect() as stream:
    search_root_dse(stream)
    assert sasl_external_bind(stream) == 0
    response = whoami(stream)
    if expected not in response:
        raise AssertionError(f"WhoAmI response {response!r} did not include {expected!r}")

with connect() as stream:
    assert sasl_external_bind(stream, f"dn:{os.environ['OPENDR_PROXY_AGENT_DN']}") == 0

with connect() as stream:
    assert sasl_external_bind(stream, f"dn:{os.environ['OPENDR_PROXY_TARGET_DN']}") == 0
    response = whoami(stream)
    if proxy_target not in response:
        raise AssertionError(f"WhoAmI response {response!r} did not include {proxy_target!r}")

with connect() as stream:
    code = sasl_external_bind(stream, f"dn:{os.environ['OPENDR_PROXY_DENIED_DN']}")
    if code == 0:
        raise AssertionError("SASL EXTERNAL denied proxy authzid unexpectedly succeeded")
PY
}

run_openldap_cli_checks() {
  set_ldap_bind_args

  local source_ou="ou=${PREFIX}-source,${BASE_DN}"
  local target_ou="ou=${PREFIX}-target,${BASE_DN}"
  local user_dn="cn=${PREFIX}-user,${source_ou}"
  local renamed_dn="cn=${PREFIX}-renamed,${target_ou}"

  run_rfc4513_auth_cli_checks

  log_step "OpenLDAP CLI: Add"
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

  log_step "OpenLDAP CLI: Search, paged results, and server-side sort"
  run_ldapsearch -LLL -o ldif-wrap=no "${LDAP_BIND_ARGS[@]}" -b "${source_ou}" -s one "(objectClass=inetOrgPerson)" cn sn >/dev/null
  run_ldapsearch -LLL -o ldif-wrap=no "${LDAP_BIND_ARGS[@]}" -E pr=1/noprompt -b "${source_ou}" -s one "(objectClass=inetOrgPerson)" cn >/dev/null
  run_ldapsearch -LLL -o ldif-wrap=no "${LDAP_BIND_ARGS[@]}" -E sss=cn -b "${source_ou}" -s one "(objectClass=inetOrgPerson)" cn >/dev/null

  log_step "OpenLDAP CLI: Modify and Compare"
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

  log_step "OpenLDAP CLI: ModifyDN"
  run_ldapmodrdn "${LDAP_BIND_ARGS[@]}" -r -s "${target_ou}" "${user_dn}" "cn=${PREFIX}-renamed" >/dev/null

  log_step "OpenLDAP CLI: Operational attributes and subschema"
  run_ldapsearch -LLL -o ldif-wrap=no "${LDAP_BIND_ARGS[@]}" -b "${renamed_dn}" -s base "(objectClass=inetOrgPerson)" "*" "+" >/dev/null
  run_ldapsearch -LLL -o ldif-wrap=no "${LDAP_BIND_ARGS[@]}" -b "cn=Subschema" -s base "(objectClass=*)" attributeTypes objectClasses >/dev/null

  log_step "OpenLDAP CLI: Delete"
  run_ldapdelete "${LDAP_BIND_ARGS[@]}" "${renamed_dn}" "${target_ou}" "${source_ou}" >/dev/null
}

run_python_ldap3_checks() {
  if [[ "${SKIP_LDAP3}" == "1" ]]; then
    log_step "Python ldap3: skipped by OPENDR_INTEROP_SKIP_LDAP3=1"
    return 0
  fi
  log_step "Python ldap3: Bind, Root DSE, schema search"
  log_command OPENDR_LDAP_URL="${LDAP_URL}" OPENDR_BASE_DN="${BASE_DN}" OPENDR_BIND_DN="${BIND_DN}" OPENDR_BIND_PW="<redacted-password>" OPENDR_STARTTLS="${STARTTLS}" python3 "<ldap3-check>"
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
  log_step "Rust ldap_ops_client: supported operation scenario"
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
  log_command cargo run --quiet --bin ldap_ops_client -- "${args[@]}"
  cargo run --quiet --bin ldap_ops_client -- "${args[@]}"
}

main() {
  init_artifacts

  require_command cargo
  require_command ldapadd
  require_command ldapcompare
  require_command ldapdelete
  require_command ldapmodrdn
  require_command ldapmodify
  require_command ldapsearch
  require_command ldapwhoami
  require_command python3

  if [[ "${SKIP_LDAP3}" != "1" ]]; then
    python3 - <<'PY'
try:
    import ldap3  # noqa: F401
except ModuleNotFoundError as exc:
    raise SystemExit("missing Python package ldap3; install it with `python3 -m pip install ldap3`") from exc
PY
  fi

  if [[ "${START_SERVER}" == "1" ]]; then
    start_temp_server
  elif [[ -z "${LDAP_URL}" ]]; then
    echo "OPENDR_LDAP_URL is required when OPENDR_INTEROP_START_SERVER=0" >&2
    exit 1
  fi

  run_openldap_cli_checks
  run_mtls_external_cli_checks
  run_python_ldap3_checks
  run_rust_client_checks

  echo "LDAP interoperability gate completed successfully for ${LDAP_URL}"
  echo "Artifact directory: ${ARTIFACT_DIR}"
}

main "$@"

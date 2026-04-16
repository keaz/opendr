#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

BASE_DN="${TLS_ROTATION_BASE_DN:-dc=example,dc=org}"
BIND_DN="${TLS_ROTATION_BIND_DN:-cn=admin,${BASE_DN}}"
BIND_PW="${TLS_ROTATION_BIND_PW:-secret}"
RUNTIME="${TLS_ROTATION_RUNTIME:-fsm}"
PYTHON_BIN="${TLS_ROTATION_PYTHON:-python3}"
ARTIFACT_DIR="${TLS_ROTATION_ARTIFACT_DIR:-${ROOT_DIR}/target/tls-rotation-gate/$(date +%Y%m%d-%H%M%S)}"
if [[ "${ARTIFACT_DIR}" != /* ]]; then
  ARTIFACT_DIR="${ROOT_DIR}/${ARTIFACT_DIR}"
fi

SERVER_DIR="${ARTIFACT_DIR}/server"
CERT_SOURCE_DIR="${ARTIFACT_DIR}/generated-certs"
ACTIVE_CERT_DIR="${SERVER_DIR}/certs"
CONFIG_DIR="${SERVER_DIR}/config"
DATA_DIR="${SERVER_DIR}/data"
LOG_DIR="${ARTIFACT_DIR}/logs"
SUMMARY_FILE="${ARTIFACT_DIR}/summary.md"

SERVER_PID=""
LDAP_PORT=""
LDAPS_PORT=""

usage() {
  cat <<'EOF'
Usage: scripts/tls_rotation_gate.sh

Validates the supported OpenDR TLS certificate rotation model.

Environment:
  TLS_ROTATION_ARTIFACT_DIR   Artifact directory. Defaults to target/tls-rotation-gate/<timestamp>.
  TLS_ROTATION_RUNTIME        Server runtime to test. Defaults to fsm.
  TLS_ROTATION_BASE_DN        LDAP base DN. Defaults to dc=example,dc=org.
  TLS_ROTATION_BIND_DN        Bind DN. Defaults to cn=admin,<base DN>.
  TLS_ROTATION_BIND_PW        Bind password. Defaults to secret.
  TLS_ROTATION_PYTHON         Python executable with ldap3 installed. Defaults to python3.
EOF
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

record() {
  echo "$*"
  echo "$*" >>"${SUMMARY_FILE}"
}

tail_server_logs() {
  if [[ -d "${LOG_DIR}" ]]; then
    for log_file in "${LOG_DIR}"/server-*.stderr.log "${LOG_DIR}"/server-*.stdout.log; do
      [[ -f "${log_file}" ]] || continue
      {
        echo
        echo "## Tail: ${log_file#${ARTIFACT_DIR}/}"
        tail -n 80 "${log_file}" || true
      } >>"${SUMMARY_FILE}"
    done
  fi
}

fail() {
  record ""
  record "Result: FAIL"
  record "Failure: $*"
  tail_server_logs
  echo "TLS rotation gate failed: $*" >&2
  echo "Artifacts retained in ${ARTIFACT_DIR}" >&2
  exit 1
}

cleanup() {
  if [[ -n "${SERVER_PID}" ]]; then
    kill "${SERVER_PID}" >/dev/null 2>&1 || true
    wait "${SERVER_PID}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

reserve_port() {
  "${PYTHON_BIN}" - <<'PY'
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
    if [[ -n "${SERVER_PID}" ]] && ! kill -0 "${SERVER_PID}" >/dev/null 2>&1; then
      fail "server process exited before opening ${host}:${port}"
    fi
    if (echo >"/dev/tcp/${host}/${port}") >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done

  fail "server did not open ${host}:${port}"
}

safe_name() {
  local raw="$1"
  raw="${raw// /_}"
  raw="${raw//\//_}"
  raw="${raw//:/_}"
  echo "${raw}"
}

generate_cert() {
  local version="$1"
  local ca_cert_file="${CERT_SOURCE_DIR}/${version}-ca.crt"
  local ca_key_file="${CERT_SOURCE_DIR}/${version}-ca.key"
  local cert_file="${CERT_SOURCE_DIR}/${version}.crt"
  local key_file="${CERT_SOURCE_DIR}/${version}.key"
  local csr_file="${CERT_SOURCE_DIR}/${version}.csr"
  local ext_file="${CERT_SOURCE_DIR}/${version}.ext"

  openssl req -x509 -newkey rsa:2048 -nodes -sha256 \
    -subj "/CN=OpenDR TLS Rotation CA ${version}" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "${ca_key_file}" \
    -out "${ca_cert_file}" \
    -days 2 >/dev/null 2>&1

  cat >"${ext_file}" <<'EOF'
subjectAltName=DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth
keyUsage=digitalSignature,keyEncipherment
EOF

  openssl req -newkey rsa:2048 -nodes -sha256 \
    -subj "/CN=localhost" \
    -keyout "${key_file}" \
    -out "${csr_file}" >/dev/null 2>&1

  openssl x509 -req \
    -in "${csr_file}" \
    -CA "${ca_cert_file}" \
    -CAkey "${ca_key_file}" \
    -CAcreateserial \
    -out "${cert_file}" \
    -days 2 \
    -sha256 \
    -extfile "${ext_file}" >/dev/null 2>&1

  chmod 0600 "${ca_key_file}"
  chmod 0600 "${key_file}"
}

install_cert() {
  local version="$1"
  cp "${CERT_SOURCE_DIR}/${version}.crt" "${ACTIVE_CERT_DIR}/server.crt"
  cp "${CERT_SOURCE_DIR}/${version}.key" "${ACTIVE_CERT_DIR}/server.key"
  chmod 0600 "${ACTIVE_CERT_DIR}/server.key"
  record "- Installed ${version} certificate material at server cert paths."
}

write_config() {
  cat >"${CONFIG_DIR}/server.toml" <<EOF
[server]
runtime = "${RUNTIME}"
bind_address = "127.0.0.1"
ldap_port = ${LDAP_PORT}
ldaps_port = ${LDAPS_PORT}
base_dn = "${BASE_DN}"
root_user_dn = "cn=admin"
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

  cat >"${CONFIG_DIR}/log4rs.yml" <<'EOF'
appenders:
  stdout:
    kind: console
root:
  level: info
  appenders:
    - stdout
EOF
}

start_server() {
  local phase="$1"
  local stdout_log="${LOG_DIR}/server-${phase}.stdout.log"
  local stderr_log="${LOG_DIR}/server-${phase}.stderr.log"

  pushd "${SERVER_DIR}" >/dev/null
  "${ROOT_DIR}/target/debug/opendr" --config config/server.toml --log-config config/log4rs.yml \
    >"${stdout_log}" 2>"${stderr_log}" &
  SERVER_PID="$!"
  popd >/dev/null

  wait_for_port "127.0.0.1" "${LDAP_PORT}"
  wait_for_port "127.0.0.1" "${LDAPS_PORT}"
  record "- Started OpenDR (${phase}) with PID ${SERVER_PID}; LDAP ${LDAP_PORT}, LDAPS ${LDAPS_PORT}."
}

record_presented_ldaps_certificate() {
  local label="$1"
  local output

  output="$(
    openssl s_client -connect "127.0.0.1:${LDAPS_PORT}" -servername localhost -showcerts \
      </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256 -issuer -subject
  )"
  {
    echo
    echo "## Presented LDAPS certificate: ${label}"
    echo "${output}"
  } >>"${SUMMARY_FILE}"
  echo "${output}" >"${LOG_DIR}/$(safe_name "${label}")_presented_ldaps_cert.log"
}

stop_server() {
  if [[ -z "${SERVER_PID}" ]]; then
    return 0
  fi

  kill "${SERVER_PID}" >/dev/null 2>&1 || true
  wait "${SERVER_PID}" >/dev/null 2>&1 || true
  record "- Stopped OpenDR PID ${SERVER_PID}."
  SERVER_PID=""
}

ldap_tls_check() {
  local ca_file="$1"
  local mode="$2"
  local output_file="$3"
  local url

  case "${mode}" in
    ldaps)
      url="ldaps://localhost:${LDAPS_PORT}"
      ;;
    starttls)
      url="ldap://localhost:${LDAP_PORT}"
      ;;
    *)
      fail "unknown TLS validation mode: ${mode}"
      ;;
  esac

  OPENDR_TLS_ROTATION_CA_FILE="${ca_file}" \
  OPENDR_TLS_ROTATION_MODE="${mode}" \
  OPENDR_TLS_ROTATION_URL="${url}" \
  OPENDR_TLS_ROTATION_BIND_DN="${BIND_DN}" \
  OPENDR_TLS_ROTATION_BIND_PW="${BIND_PW}" \
  OPENDR_TLS_ROTATION_BASE_DN="${BASE_DN}" \
    "${PYTHON_BIN}" - <<'PY' >"${output_file}" 2>&1
import os
import ssl
from urllib.parse import urlparse

from ldap3 import BASE, Connection, Server, Tls

ca_file = os.environ["OPENDR_TLS_ROTATION_CA_FILE"]
mode = os.environ["OPENDR_TLS_ROTATION_MODE"]
url = urlparse(os.environ["OPENDR_TLS_ROTATION_URL"])
host = url.hostname or "127.0.0.1"
port = url.port or (636 if mode == "ldaps" else 389)
base_dn = os.environ["OPENDR_TLS_ROTATION_BASE_DN"]

tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=ca_file)
server = Server(host, port=port, use_ssl=(mode == "ldaps"), tls=tls, get_info=None)
conn = Connection(
    server,
    user=os.environ["OPENDR_TLS_ROTATION_BIND_DN"],
    password=os.environ["OPENDR_TLS_ROTATION_BIND_PW"],
    raise_exceptions=True,
)
conn.open()
if mode == "starttls":
    if not conn.start_tls():
        raise RuntimeError(f"StartTLS failed: {conn.result}")
if not conn.bind():
    raise RuntimeError(f"bind failed: {conn.result}")
if not conn.search("", "(objectClass=*)", BASE, attributes=["namingContexts", "supportedExtension"]):
    raise RuntimeError(f"Root DSE search failed: {conn.result}")
entries = conn.response
if not entries:
    raise RuntimeError("Root DSE search returned no entries")
attrs = entries[0].get("attributes", {})
naming_contexts = attrs.get("namingContexts") or []
if base_dn not in naming_contexts:
    raise RuntimeError(f"Root DSE missing namingContexts {base_dn!r}: {naming_contexts!r}")
print(f"{mode} bind/search succeeded with {ca_file}")
print(f"namingContexts: {base_dn}")
conn.unbind()
PY
}

openssl_tls_check() {
  local ca_file="$1"
  local mode="$2"
  local output_file="$3"
  local args=(-servername localhost -verify_return_error -CAfile "${ca_file}" -brief)

  case "${mode}" in
    ldaps)
      openssl s_client -connect "127.0.0.1:${LDAPS_PORT}" "${args[@]}" \
        </dev/null >"${output_file}" 2>&1
      ;;
    starttls)
      openssl s_client -starttls ldap -connect "127.0.0.1:${LDAP_PORT}" "${args[@]}" \
        </dev/null >"${output_file}" 2>&1
      ;;
    *)
      fail "unknown TLS validation mode: ${mode}"
      ;;
  esac
}

expect_success() {
  local label="$1"
  local ca_file="$2"
  local mode="$3"
  local output_file="${LOG_DIR}/$(safe_name "${label}").log"
  local trust_output_file="${LOG_DIR}/$(safe_name "${label}")_openssl.log"

  if ! openssl_tls_check "${ca_file}" "${mode}" "${trust_output_file}"; then
    {
      echo
      echo "## Failed OpenSSL trust output: ${label}"
      cat "${trust_output_file}"
    } >>"${SUMMARY_FILE}"
    fail "${label} failed certificate trust verification"
  fi

  if ! ldap_tls_check "${ca_file}" "${mode}" "${output_file}"; then
    {
      echo
      echo "## Failed command output: ${label}"
      cat "${output_file}"
    } >>"${SUMMARY_FILE}"
    fail "${label} was expected to succeed"
  fi

  if ! grep -F "namingContexts: ${BASE_DN}" "${output_file}" >/dev/null; then
    {
      echo
      echo "## Unexpected successful output: ${label}"
      cat "${output_file}"
    } >>"${SUMMARY_FILE}"
    fail "${label} succeeded without expected Root DSE namingContexts"
  fi

  record "- PASS: ${label}"
}

expect_failure() {
  local label="$1"
  local ca_file="$2"
  local mode="$3"
  local output_file="${LOG_DIR}/$(safe_name "${label}")_openssl.log"

  set +e
  openssl_tls_check "${ca_file}" "${mode}" "${output_file}"
  local status=$?
  set -e

  if [[ "${status}" -eq 0 ]]; then
    {
      echo
      echo "## Unexpected successful output: ${label}"
      cat "${output_file}"
    } >>"${SUMMARY_FILE}"
    fail "${label} unexpectedly succeeded; trust validation may be bypassed"
  fi

  record "- PASS: ${label} failed as expected (exit ${status})."
}

main() {
  require_command cargo
  require_command openssl
  require_command "${PYTHON_BIN}"

  "${PYTHON_BIN}" - <<'PY'
try:
    import ldap3  # noqa: F401
except ModuleNotFoundError as exc:
    raise SystemExit("missing Python package ldap3; install it with `python3 -m pip install ldap3`") from exc
PY

  rm -rf "${ARTIFACT_DIR}"
  mkdir -p "${CERT_SOURCE_DIR}" "${ACTIVE_CERT_DIR}" "${CONFIG_DIR}" "${DATA_DIR}" "${LOG_DIR}"
  : >"${SUMMARY_FILE}"

  LDAP_PORT="$(reserve_port)"
  LDAPS_PORT="$(reserve_port)"

  record "# TLS Certificate Rotation Gate"
  record ""
  record "- Artifact directory: ${ARTIFACT_DIR}"
  record "- Runtime: ${RUNTIME}"
  record "- Rotation model under validation: certificate file replacement requires OpenDR restart."

  cargo build --bin opendr >/dev/null
  generate_cert "v1"
  generate_cert "v2"
  write_config

  install_cert "v1"
  start_server "before-rotation"
  record_presented_ldaps_certificate "before rotation"

  expect_success "v1 LDAPS with v1 trust" "${CERT_SOURCE_DIR}/v1-ca.crt" "ldaps"
  expect_success "v1 StartTLS with v1 trust" "${CERT_SOURCE_DIR}/v1-ca.crt" "starttls"
  expect_failure "v1 LDAPS with v2 trust" "${CERT_SOURCE_DIR}/v2-ca.crt" "ldaps"
  expect_failure "v1 StartTLS with v2 trust" "${CERT_SOURCE_DIR}/v2-ca.crt" "starttls"

  install_cert "v2"
  record "- Replaced certificate files while the process remained running; hot reload is not supported."
  expect_success "pre-restart LDAPS still presents v1" "${CERT_SOURCE_DIR}/v1-ca.crt" "ldaps"
  expect_success "pre-restart StartTLS still presents v1" "${CERT_SOURCE_DIR}/v1-ca.crt" "starttls"
  expect_failure "pre-restart LDAPS does not present v2" "${CERT_SOURCE_DIR}/v2-ca.crt" "ldaps"
  expect_failure "pre-restart StartTLS does not present v2" "${CERT_SOURCE_DIR}/v2-ca.crt" "starttls"

  stop_server
  start_server "after-rotation"
  record_presented_ldaps_certificate "after rotation"

  expect_failure "post-restart LDAPS rejects stale v1 trust" "${CERT_SOURCE_DIR}/v1-ca.crt" "ldaps"
  expect_failure "post-restart StartTLS rejects stale v1 trust" "${CERT_SOURCE_DIR}/v1-ca.crt" "starttls"
  expect_success "post-restart LDAPS accepts v2 trust" "${CERT_SOURCE_DIR}/v2-ca.crt" "ldaps"
  expect_success "post-restart StartTLS accepts v2 trust" "${CERT_SOURCE_DIR}/v2-ca.crt" "starttls"

  stop_server

  record ""
  record "Result: PASS"
  record "Artifacts retained in ${ARTIFACT_DIR}"
}

main "$@"

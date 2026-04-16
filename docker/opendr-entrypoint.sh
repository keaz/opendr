#!/usr/bin/env bash

set -euo pipefail

WORKDIR=/var/lib/opendr
CONFIG_DIR="${WORKDIR}/config"
CERT_DIR="${WORKDIR}/certs"
DATA_DIR="${WORKDIR}/data"

mkdir -p "${CONFIG_DIR}" "${CERT_DIR}" "${DATA_DIR}"

: "${OPENDR_BIND_ADDRESS:=0.0.0.0}"
: "${OPENDR_LDAP_PORT:=1389}"
: "${OPENDR_LDAPS_PORT:=1636}"
: "${OPENDR_RUNTIME:=legacy}"
: "${OPENDR_BASE_DN:=dc=example,dc=com}"
: "${OPENDR_ROOT_USER_DN:=cn=admin}"
: "${OPENDR_ROOT_PASSWORD:=}"
: "${OPENDR_ROOT_PASSWORD_HASH_FILE:=}"
: "${OPENDR_ORGANIZATION_NAME:=OpenDR Docker}"
: "${OPENDR_LMDB_MAX_SIZE:=1073741824}"
: "${OPENDR_LMDB_MAX_READERS:=256}"
: "${OPENDR_MAX_CONNECTIONS:=512}"
: "${OPENDR_MAX_CONNECTIONS_PER_IP:=256}"
: "${OPENDR_MAX_OPERATIONS_PER_CONNECTION:=200}"
: "${OPENDR_MAX_MEMORY_PER_CONNECTION:=10485760}"
: "${OPENDR_MAX_TOTAL_MEMORY:=2147483648}"
: "${OPENDR_CONNECTION_IDLE_TIMEOUT_SECS:=600}"
: "${OPENDR_WORKER_THREADS:=0}"
: "${OPENDR_SCHEMA_VALIDATION:=true}"
: "${OPENDR_INDEXING_ENABLED:=true}"
: "${OPENDR_CACHE_SIZE:=1000}"
: "${OPENDR_QUERY_OPTIMIZATION:=true}"
: "${OPENDR_AUTH_METADATA_UPDATE_MODE:=sync}"
: "${OPENDR_AUTH_METADATA_QUEUE_CAPACITY:=100000}"
: "${OPENDR_AUTH_METADATA_FLUSH_INTERVAL_MS:=100}"
: "${OPENDR_AUTH_METADATA_BATCH_SIZE:=1000}"
: "${OPENDR_AUTH_METADATA_OVERFLOW_POLICY:=fallback_sync}"
: "${OPENDR_LOG_LEVEL:=info}"
: "${OPENDR_BACKEND_INDEXES_TOML:=}"
: "${OPENDR_SCHEMA_LDIF:=}"

if [[ ! -f "${CERT_DIR}/server.crt" || ! -f "${CERT_DIR}/server.key" ]]; then
  openssl req \
    -x509 \
    -newkey rsa:2048 \
    -keyout "${CERT_DIR}/server.key" \
    -out "${CERT_DIR}/server.crt" \
    -days 30 \
    -nodes \
    -subj "/CN=localhost" \
    >/dev/null 2>&1
fi

ROOT_PASSWORD_FILE="${CONFIG_DIR}/root-password.hash"
if [[ -n "${OPENDR_ROOT_PASSWORD_HASH_FILE}" ]]; then
  ROOT_PASSWORD_HASH="$(<"${OPENDR_ROOT_PASSWORD_HASH_FILE}")"
elif [[ -n "${OPENDR_ROOT_PASSWORD}" ]]; then
  ROOT_PASSWORD_HASH=$(/usr/local/bin/opendr-setup hash-password "${OPENDR_ROOT_PASSWORD}" | tail -n 1)
else
  echo "OPENDR_ROOT_PASSWORD or OPENDR_ROOT_PASSWORD_HASH_FILE must be set" >&2
  exit 1
fi
umask 077
printf '%s\n' "${ROOT_PASSWORD_HASH}" > "${ROOT_PASSWORD_FILE}"

cat > "${CONFIG_DIR}/server.toml" <<EOF
[server]
runtime = "${OPENDR_RUNTIME}"
bind_address = "${OPENDR_BIND_ADDRESS}"
ldap_port = ${OPENDR_LDAP_PORT}
ldaps_port = ${OPENDR_LDAPS_PORT}
base_dn = "${OPENDR_BASE_DN}"
root_user_dn = "${OPENDR_ROOT_USER_DN}"
root_password_file = "${ROOT_PASSWORD_FILE}"
organization_name = "${OPENDR_ORGANIZATION_NAME}"

[backend]
backend_type = "lmdb"
data_directory = "./data"
lmdb_max_size = ${OPENDR_LMDB_MAX_SIZE}
lmdb_max_readers = ${OPENDR_LMDB_MAX_READERS}

[resources]
max_connections = ${OPENDR_MAX_CONNECTIONS}
max_connections_per_ip = ${OPENDR_MAX_CONNECTIONS_PER_IP}
max_operations_per_connection = ${OPENDR_MAX_OPERATIONS_PER_CONNECTION}
max_memory_per_connection = ${OPENDR_MAX_MEMORY_PER_CONNECTION}
max_total_memory = ${OPENDR_MAX_TOTAL_MEMORY}
connection_idle_timeout_secs = ${OPENDR_CONNECTION_IDLE_TIMEOUT_SECS}

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

[auth_metadata]
update_mode = "${OPENDR_AUTH_METADATA_UPDATE_MODE}"
queue_capacity = ${OPENDR_AUTH_METADATA_QUEUE_CAPACITY}
flush_interval_ms = ${OPENDR_AUTH_METADATA_FLUSH_INTERVAL_MS}
batch_size = ${OPENDR_AUTH_METADATA_BATCH_SIZE}
overflow_policy = "${OPENDR_AUTH_METADATA_OVERFLOW_POLICY}"

[performance]
worker_threads = ${OPENDR_WORKER_THREADS}
schema_validation = ${OPENDR_SCHEMA_VALIDATION}
indexing_enabled = ${OPENDR_INDEXING_ENABLED}
cache_size = ${OPENDR_CACHE_SIZE}
query_optimization = ${OPENDR_QUERY_OPTIMIZATION}
EOF

if [[ -n "${OPENDR_BACKEND_INDEXES_TOML}" ]]; then
  printf '\n%s\n' "${OPENDR_BACKEND_INDEXES_TOML}" >> "${CONFIG_DIR}/server.toml"
fi

if [[ -n "${OPENDR_SCHEMA_LDIF}" ]]; then
  mkdir -p "${CONFIG_DIR}/schema"
  printf '%s\n' "${OPENDR_SCHEMA_LDIF}" > "${CONFIG_DIR}/schema/99-env-schema.ldif"
fi

cat > "${CONFIG_DIR}/log4rs.yml" <<EOF
appenders:
  stdout:
    kind: console
root:
  level: ${OPENDR_LOG_LEVEL}
  appenders:
    - stdout
EOF

cd "${WORKDIR}"
exec /usr/local/bin/opendr

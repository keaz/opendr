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
: "${OPENDR_ROOT_PASSWORD:=PerfRootSecret123!}"
: "${OPENDR_ORGANIZATION_NAME:=OpenDR Docker}"
: "${OPENDR_LMDB_MAX_SIZE:=1073741824}"
: "${OPENDR_LMDB_MAX_READERS:=256}"
: "${OPENDR_MAX_CONNECTIONS:=512}"
: "${OPENDR_MAX_CONNECTIONS_PER_IP:=256}"
: "${OPENDR_MAX_OPERATIONS_PER_CONNECTION:=200}"
: "${OPENDR_MAX_MEMORY_PER_CONNECTION:=10485760}"
: "${OPENDR_MAX_TOTAL_MEMORY:=2147483648}"
: "${OPENDR_CONNECTION_IDLE_TIMEOUT_SECS:=600}"

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

ROOT_PASSWORD_HASH=$(/usr/local/bin/opendr-setup hash-password "${OPENDR_ROOT_PASSWORD}" | tail -n 1)

cat > "${CONFIG_DIR}/server.toml" <<EOF
[server]
runtime = "${OPENDR_RUNTIME}"
bind_address = "${OPENDR_BIND_ADDRESS}"
ldap_port = ${OPENDR_LDAP_PORT}
ldaps_port = ${OPENDR_LDAPS_PORT}
base_dn = "${OPENDR_BASE_DN}"
root_user_dn = "${OPENDR_ROOT_USER_DN}"
root_password = "${ROOT_PASSWORD_HASH}"
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
EOF

cat > "${CONFIG_DIR}/log4rs.yml" <<'EOF'
appenders:
  stdout:
    kind: console
root:
  level: info
  appenders:
    - stdout
EOF

cd "${WORKDIR}"
exec /usr/local/bin/opendr

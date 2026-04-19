#!/usr/bin/env zsh
#
# OpenDR E2E Test Helper Library
#
# Provides reusable functions for end-to-end testing of LDAP replication
# and server functionality.
#
# Usage:
#   source ./helpers.sh
#   build_server
#   ensure_tools
#   # ... use helper functions
#

set -euo pipefail

# ============================================================================
# Colors and Formatting
# ============================================================================

if [[ -t 1 ]]; then
  RED=$(tput setaf 1)
  GREEN=$(tput setaf 2)
  YELLOW=$(tput setaf 3)
  BLUE=$(tput setaf 4)
  MAGENTA=$(tput setaf 5)
  CYAN=$(tput setaf 6)
  BOLD=$(tput bold)
  RESET=$(tput sgr0)
else
  RED=""
  GREEN=""
  YELLOW=""
  BLUE=""
  MAGENTA=""
  CYAN=""
  BOLD=""
  RESET=""
fi

# ============================================================================
# Logging Functions
# ============================================================================

log_info() {
  echo "${BLUE}[INFO]${RESET} $*"
}

log_success() {
  echo "${GREEN}[SUCCESS]${RESET} $*"
}

log_warning() {
  echo "${YELLOW}[WARN]${RESET} $*"
}

log_error() {
  echo "${RED}[ERROR]${RESET} $*" >&2
}

log_debug() {
  if [[ "${DEBUG:-0}" == "1" ]]; then
    echo "${MAGENTA}[DEBUG]${RESET} $*" >&2
  fi
}

log_step() {
  echo "${CYAN}${BOLD}▶${RESET} $*"
}

# ============================================================================
# Global Variables and Defaults
# ============================================================================

# Environment variable defaults
: "${LDAP_HOST:=127.0.0.1}"
: "${BASE_DN:=dc=example,dc=org}"
: "${BIND_RDN:=cn=manager}"  # Just the RDN for config file
: "${BIND_DN:=${BIND_RDN},${BASE_DN}}"  # Full DN for LDAP operations
: "${BIND_PW:=admin}"
# Password hash (SSHA512) for 'admin' password - matches the working config
# Must use separate assignment to avoid brace expansion issues
if [[ -z "${BIND_PW_HASH:-}" ]]; then
  BIND_PW_HASH='{SSHA512}p/daj2F70DN5WvWL+q67EabZjn8ESfIgZ0NVm+/r6KGHmZ125/jN3nqz4BzukIyIzBcYVHZgd/iLnwAw57spPouWItDgdfeonDduOFGqt3I='
fi
: "${SYNC_INTERVAL_SECS:=5}"
: "${BATCH_SIZE:=100}"
: "${REPL_TIMEOUT_SECS:=30}"
: "${RUN_ROOT:=$(mktemp -d /tmp/opendr_e2e.XXXXXX)}"
: "${SERVER_BIN:=}"
: "${SERVER_BIN_HINTS:=target/release/opendr target/debug/opendr bin/opendr opendr}"
: "${NC:=nc}"
: "${E2E_ARTIFACT_DIR:=}"

# Test state
PASS_COUNT=0
FAIL_COUNT=0
START_TS=$(date +%s)
TEST_NAME=""
TEST_DESCRIPTION=""

# Server tracking
typeset -a SERVER_PIDS SERVER_NAMES SERVER_LOGS SERVER_DIRS

# ============================================================================
# Utility Functions
# ============================================================================

# Extract DC value from DN
extract_dc() {
  local dn="$1"
  echo "${dn}" | sed -n 's/^dc=\([^,]*\).*/\1/p'
}

# Generate a unique port number
get_random_port() {
  echo $((3800 + RANDOM % 200))
}

# ============================================================================
# Preflight Checks
# ============================================================================

ensure_tools() {
  log_step "Checking required tools..."
  
  local missing_tools=()
  
  for tool in ldapsearch ldapadd ldapmodify ldapdelete "${NC}"; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
      missing_tools+=("${tool}")
    fi
  done
  
  if [[ ${#missing_tools[@]} -gt 0 ]]; then
    log_error "Missing required tools: ${missing_tools[*]}"
    log_error "Install with: brew install openldap"
    exit 1
  fi
  
  log_success "All required tools available"
}

# ============================================================================
# Server Build and Detection
# ============================================================================

build_server() {
  log_step "Locating or building server binary..."
  
  # Check if SERVER_BIN is already set and executable
  if [[ -n "${SERVER_BIN}" && -x "${SERVER_BIN}" ]]; then
    # Convert to absolute path
    SERVER_BIN="$(cd "$(dirname "${SERVER_BIN}")" && pwd)/$(basename "${SERVER_BIN}")"
    log_success "Using provided SERVER_BIN=${SERVER_BIN}"
    return 0
  fi
  
  # Try to find existing binary
  # Split SERVER_BIN_HINTS into array (bash/zsh compatible)
  local -a hints
  hints=(${=SERVER_BIN_HINTS})
  for hint in "${hints[@]}"; do
    if [[ -x "${hint}" ]]; then
      # Convert to absolute path
      SERVER_BIN="$(cd "$(dirname "${hint}")" && pwd)/$(basename "${hint}")"
      log_success "Found server binary at ${SERVER_BIN}"
      return 0
    fi
  done
  
  # Build if Cargo.toml exists
  if [[ -f Cargo.toml ]]; then
    log_info "Building via cargo (release mode)..."
    cargo build --release
    local rel_path="target/release/opendr"
    if [[ ! -x "${rel_path}" ]]; then
      log_error "Build completed but binary not found at ${rel_path}"
      exit 1
    fi
    # Convert to absolute path
    SERVER_BIN="$(cd "$(dirname "${rel_path}")" && pwd)/$(basename "${rel_path}")"
    log_success "Build complete: ${SERVER_BIN}"
    return 0
  fi
  
  log_error "Unable to locate or build server binary. Set SERVER_BIN environment variable."
  exit 1
}

# ============================================================================
# Server Management
# ============================================================================

wait_for_server() {
  local host="$1"
  local port="$2"
  local timeout="$3"
  local deadline=$(($(date +%s) + timeout))
  
  log_debug "Waiting for server ${host}:${port} (timeout: ${timeout}s)"
  
  while true; do
    if "${NC}" -z -w 1 "${host}" "${port}" >/dev/null 2>&1; then
      log_debug "Server ${host}:${port} is ready"
      return 0
    fi
    
    if [[ $(date +%s) -ge ${deadline} ]]; then
      log_error "Server ${host}:${port} not ready after ${timeout}s"
      return 1
    fi
    
    sleep 0.25
  done
}

create_provider_config() {
  local dir="$1"
  local port="$2"
  local base="$3"
  local rootrdn="$4"  # Should be just RDN like "cn=manager"
  local rootpw="$5"   # Should be hashed password
  local extra="${6:-}"
  
  mkdir -p "${dir}/data" "${dir}/logs" "${dir}/repl"
  
  local dc_value
  dc_value=$(extract_dc "${base}")
  
  cat > "${dir}/server.toml" <<'EOF'
[server]
bind_address = "127.0.0.1"
ldap_port = PORT_PLACEHOLDER
base_dn = "BASE_DN_PLACEHOLDER"
root_user_dn = "ROOT_RDN_PLACEHOLDER"
# E2E-only inline credential; production configs use root_password_file/env.
root_password = "ROOT_PW_PLACEHOLDER"
organization_name = "Test Organization"

[backend]
backend_type = "lmdb"
data_directory = "DIR_PLACEHOLDER/data"
lmdb_max_size = 536870912
lmdb_max_readers = 126

[replication]
enabled = true
mode = "provider"
changelog_enabled = true
EXTRA_PLACEHOLDER

[monitoring]
enabled = false

[access_control]
enabled = false
EOF

  # Now do the replacements using awk to avoid shell interpretation issues
  EXTRA_CONTENT="${extra}" awk -v port="${port}" -v base="${base}" -v rootrdn="${rootrdn}" -v rootpw="${rootpw}" -v dir="${dir}" '
  BEGIN {
    extra = ENVIRON["EXTRA_CONTENT"]
  }
  {
    gsub(/PORT_PLACEHOLDER/, port)
    gsub(/BASE_DN_PLACEHOLDER/, base)
    gsub(/ROOT_RDN_PLACEHOLDER/, rootrdn)
    gsub(/ROOT_PW_PLACEHOLDER/, rootpw)
    gsub(/DIR_PLACEHOLDER/, dir)
    if ($0 ~ /EXTRA_PLACEHOLDER/) {
      gsub(/EXTRA_PLACEHOLDER/, "")
      if (length($0) > 0) {
        print
      }
      if (length(extra) > 0) {
        printf "%s\n", extra
      }
      next
    }
    print
  }' "${dir}/server.toml" > "${dir}/server.toml.tmp" && mv "${dir}/server.toml.tmp" "${dir}/server.toml"
  
  echo "${dir}/server.toml"
}

create_consumer_config() {
  local dir="$1"
  local port="$2"
  local provider_port="$3"
  local base="$4"
  local rootrdn="$5"  # Should be just RDN like "cn=manager"
  local rootpw="$6"   # Should be hashed password
  local sync_int="${7:-${SYNC_INTERVAL_SECS}}"
  local batch="${8:-${BATCH_SIZE}}"
  local extra="${9:-}"
  
  mkdir -p "${dir}/data" "${dir}/logs" "${dir}/repl/state"
  
  local dc_value
  dc_value=$(extract_dc "${base}")
  
  cat > "${dir}/server.toml" <<'EOF'
[server]
bind_address = "127.0.0.1"
ldap_port = PORT_PLACEHOLDER
base_dn = "BASE_DN_PLACEHOLDER"
root_user_dn = "ROOT_RDN_PLACEHOLDER"
# E2E-only inline credential; production configs use root_password_file/env.
root_password = "ROOT_PW_PLACEHOLDER"
organization_name = "Test Organization"

[backend]
backend_type = "lmdb"
data_directory = "DIR_PLACEHOLDER/data"
lmdb_max_size = 536870912
lmdb_max_readers = 126

[replication]
enabled = true
mode = "consumer"
provider_url = "ldap://127.0.0.1:PROVIDER_PORT_PLACEHOLDER"
allow_insecure_provider_bind = true
sync_interval_secs = SYNC_INT_PLACEHOLDER
EXTRA_PLACEHOLDER

[monitoring]
enabled = false

[access_control]
enabled = false
EOF

  # Now do the replacements using awk to avoid shell interpretation issues
  EXTRA_CONTENT="${extra}" awk -v port="${port}" -v base="${base}" -v rootrdn="${rootrdn}" -v rootpw="${rootpw}" -v dir="${dir}" -v provider_port="${provider_port}" -v sync_int="${sync_int}" '
  BEGIN {
    extra = ENVIRON["EXTRA_CONTENT"]
  }
  {
    gsub(/PROVIDER_PORT_PLACEHOLDER/, provider_port)
    gsub(/PORT_PLACEHOLDER/, port)
    gsub(/BASE_DN_PLACEHOLDER/, base)
    gsub(/ROOT_RDN_PLACEHOLDER/, rootrdn)
    gsub(/ROOT_PW_PLACEHOLDER/, rootpw)
    gsub(/DIR_PLACEHOLDER/, dir)
    gsub(/SYNC_INT_PLACEHOLDER/, sync_int)
    if ($0 ~ /EXTRA_PLACEHOLDER/) {
      gsub(/EXTRA_PLACEHOLDER/, "")
      if (length($0) > 0) {
        print
      }
      if (length(extra) > 0) {
        printf "%s\n", extra
      }
      next
    }
    print
  }' "${dir}/server.toml" > "${dir}/server.toml.tmp" && mv "${dir}/server.toml.tmp" "${dir}/server.toml"
  
  echo "${dir}/server.toml"
}

start_server() {
  local name="$1"
  local cfg="$2"
  local log="$3"
  local pidfile="$4"
  
  log_info "Starting ${name} with config ${cfg}"
  
  # Ensure log directory exists
  mkdir -p "$(dirname "${log}")"
  
  # Server expects config at config/server.toml relative to CWD
  # Create a symlink in the instance directory
  local instance_dir="$(dirname "${cfg}")"
  mkdir -p "${instance_dir}/config"
  ln -sf "${cfg}" "${instance_dir}/config/server.toml"
  
  # Create a minimal log4rs.yml if it doesn't exist
  if [[ ! -f "${instance_dir}/config/log4rs.yml" ]]; then
    cat > "${instance_dir}/config/log4rs.yml" <<'LOGEOF'
refresh_rate: 30 seconds
appenders:
  stdout:
    kind: console
root:
  level: info
  appenders:
    - stdout
LOGEOF
  fi
  
  # Start server in background from the instance directory
  (cd "${instance_dir}" && RUST_LOG=info nohup "${SERVER_BIN}" > "${log}" 2>&1 &
   echo $! > "${pidfile}")
  
  local pid=$(cat "${pidfile}")
  
  # Track server
  SERVER_PIDS+=("${pid}")
  SERVER_NAMES+=("${name}")
  SERVER_LOGS+=("${log}")
  SERVER_DIRS+=("${instance_dir}")
  
  log_debug "${name} started with PID ${pid}"
}

stop_server() {
  local pid="$1"
  local name="$2"
  
  if ! kill -0 "${pid}" >/dev/null 2>&1; then
    log_debug "${name} (PID ${pid}) already stopped"
    return 0
  fi
  
  log_info "Stopping ${name} (PID ${pid})"
  
  # Try graceful shutdown first
  kill "${pid}" 2>/dev/null || true
  
  # Wait up to 5 seconds for graceful shutdown
  local deadline=$(($(date +%s) + 5))
  while kill -0 "${pid}" >/dev/null 2>&1; do
    if [[ $(date +%s) -ge ${deadline} ]]; then
      log_warning "${name} did not stop gracefully, forcing..."
      kill -9 "${pid}" 2>/dev/null || true
      break
    fi
    sleep 0.1
  done
  
  log_debug "${name} stopped"
}

# ============================================================================
# LDAP Helper Functions
# ============================================================================

ensure_base_tree() {
  local host="$1"
  local port="$2"
  local url="ldap://${host}:${port}"
  
  log_debug "Ensuring base tree exists at ${url}"
  
  # Try to add base DN (ignore if exists)
  local dc_value
  dc_value=$(extract_dc "${BASE_DN}")
  
  cat <<LDIF | ldapadd -x -H "${url}" -D "${BIND_DN}" -w "${BIND_PW}" 2>/dev/null || true
dn: ${BASE_DN}
objectClass: top
objectClass: domain
dc: ${dc_value}

dn: ou=people,${BASE_DN}
objectClass: top
objectClass: organizationalUnit
ou: people
LDIF
  
  log_debug "Base tree initialized"
}

add_ldif() {
  local host="$1"
  local port="$2"
  local url="ldap://${host}:${port}"
  
  ldapadd -x -H "${url}" -D "${BIND_DN}" -w "${BIND_PW}" 2>&1
}

search_entry() {
  local host="$1"
  local port="$2"
  local base="$3"
  local filter="$4"
  shift 4
  local url="ldap://${host}:${port}"
  
  ldapsearch -LLL -o ldif-wrap=no -x -H "${url}" -D "${BIND_DN}" -w "${BIND_PW}" \
    -b "${base}" "${filter}" "$@" 2>/dev/null
}

verify_entry_exists() {
  local host="$1"
  local port="$2"
  local dn="$3"
  
  search_entry "${host}" "${port}" "${dn}" "(objectClass=*)" dn | grep -qi "^dn: ${dn}$"
}

verify_entry_attributes() {
  local host="$1"
  local port="$2"
  local dn="$3"
  shift 3
  
  local all_match=0
  
  for kv in "$@"; do
    local k="${kv%%=*}"
    local v="${kv#*=}"
    
    if ! search_entry "${host}" "${port}" "${dn}" "(objectClass=*)" "${k}" | \
         grep -qE "^${k}: ${v}$"; then
      log_error "Attribute mismatch on ${dn}: expected ${k}=${v}"
      all_match=1
    fi
  done
  
  return ${all_match}
}

count_entries() {
  local host="$1"
  local port="$2"
  local base="$3"
  local filter="$4"

  local search_output="" search_status=0 count=""
  set +e
  search_output=$(search_entry "${host}" "${port}" "${base}" "${filter}" dn 2>/dev/null)
  search_status=$?
  set -e

  if [[ ${search_status} -ne 0 ]]; then
    log_debug "Count search failed for ${base} ${filter} at ${host}:${port} with status ${search_status}"
    echo "-1"
    return 0
  fi

  count=$(printf "%s\n" "${search_output}" | awk '/^dn: / { count++ } END { print count + 0 }')
  # Remove any newlines or whitespace
  count=$(echo "$count" | tr -d '\n\r ' | head -c 10)
  echo "${count}"
}

# ============================================================================
# Replication Utilities
# ============================================================================

wait_for_replication() {
  local ph="$1"      # provider host
  local pp="$2"      # provider port
  local ch="$3"      # consumer host
  local cp="$4"      # consumer port
  local base="$5"    # base DN
  local filter="$6"  # LDAP filter
  local expected="$7" # expected count
  local timeout="$8"  # timeout in seconds
  
  local deadline=$(($(date +%s) + timeout))
  
  log_debug "Waiting for replication: ${expected} entries matching '${filter}' in ${base}"
  
  while true; do
    local pc="" cc=""
    pc=$(count_entries "${ph}" "${pp}" "${base}" "${filter}")
    cc=$(count_entries "${ch}" "${cp}" "${base}" "${filter}")
    
    if [[ "${cc}" -eq "${expected}" && "${cc}" -eq "${pc}" ]]; then
      log_debug "Replication complete: ${cc} entries"
      return 0
    fi
    
    if [[ $(date +%s) -ge ${deadline} ]]; then
      log_error "Replication timeout: provider=${pc}, consumer=${cc}, expected=${expected}"
      return 1
    fi
    
    sleep 0.5
  done
}

measure_replication_time() {
  local ph="$1"
  local pp="$2"
  local ch="$3"
  local cp="$4"
  local dn="$5"
  local timeout="$6"
  
  local start_ts
  start_ts=$(date +%s)
  local deadline=$((start_ts + timeout))
  
  while ! verify_entry_exists "${ch}" "${cp}" "${dn}" 2>/dev/null; do
    if [[ $(date +%s) -ge ${deadline} ]]; then
      echo "-1"
      return 1
    fi
    sleep 0.1
  done
  
  local end_ts
  end_ts=$(date +%s)
  echo $((end_ts - start_ts))
}

# ============================================================================
# Test Framework
# ============================================================================

begin_test() {
  TEST_NAME="$1"
  TEST_DESCRIPTION="$2"
  
  echo ""
  echo "${BOLD}${CYAN}========================================${RESET}"
  echo "${BOLD}${CYAN}Test: ${TEST_NAME}${RESET}"
  echo "${CYAN}${TEST_DESCRIPTION}${RESET}"
  echo "${BOLD}${CYAN}========================================${RESET}"
  echo ""
  
  log_info "Test started at $(date)"
  log_info "Run directory: ${RUN_ROOT}"
}

end_test() {
  local end_ts
  end_ts=$(date +%s)
  local duration=$((end_ts - START_TS))
  
  echo ""
  echo "${BOLD}${CYAN}========================================${RESET}"
  echo "${BOLD}Test Results${RESET}"
  echo "${CYAN}========================================${RESET}"
  echo "Test: ${TEST_NAME}"
  echo "Duration: ${duration}s"
  echo "Passed: ${GREEN}${PASS_COUNT}${RESET}"
  echo "Failed: ${RED}${FAIL_COUNT}${RESET}"
  echo "${BOLD}${CYAN}========================================${RESET}"
  echo ""
  
  if [[ ${FAIL_COUNT} -gt 0 ]]; then
    log_error "Test FAILED with ${FAIL_COUNT} failure(s)"
  else
    log_success "Test PASSED - all ${PASS_COUNT} assertion(s) succeeded"
  fi
}

assert_eq() {
  local expected="$1"
  local actual="$2"
  local message="$3"
  
  if [[ "${expected}" == "${actual}" ]]; then
    log_success "✓ ${message} [${actual}]"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    log_error "✗ ${message}: expected='${expected}' actual='${actual}'"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
}

assert_true() {
  local condition="$1"
  local message="$2"
  
  if eval "${condition}"; then
    log_success "✓ ${message}"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    log_error "✗ ${message}: condition failed: ${condition}"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
}

# ============================================================================
# Cleanup and Shutdown
# ============================================================================

cleanup_all() {
  local exit_status=$?
  
  echo ""
  log_step "Cleaning up test environment..."
  
  # Dump logs on failure
  if [[ ${exit_status} -ne 0 || ${FAIL_COUNT} -gt 0 ]]; then
    log_warning "Test failed or encountered errors. Dumping server logs:"
    echo ""
    
    for ((i = 1; i <= ${#SERVER_LOGS[@]}; i++)); do
      local log="${SERVER_LOGS[$i]}"
      local name="${SERVER_NAMES[$i]}"
      [[ -n "${name}" ]] || name="unknown"
      
      if [[ -f "${log}" ]]; then
        echo "${BOLD}${YELLOW}──── ${name} log (last 50 lines) ────${RESET}"
        tail -50 "${log}" || true
        echo ""
      fi
    done
  fi

  # Preserve logs/configs for long-running gates when requested. Copy before
  # removing RUN_ROOT so release artifacts survive normal cleanup.
  if [[ -n "${E2E_ARTIFACT_DIR}" ]]; then
    mkdir -p "${E2E_ARTIFACT_DIR}"

    for ((i = 1; i <= ${#SERVER_LOGS[@]}; i++)); do
      local log="${SERVER_LOGS[$i]}"
      local name="${SERVER_NAMES[$i]}"
      local dir="${SERVER_DIRS[$i]}"
      [[ -n "${name}" ]] || name="unknown"

      local safe_name="${name//:/_}"
      safe_name="${safe_name//\//_}"

      if [[ -f "${log}" ]]; then
        cp -f "${log}" "${E2E_ARTIFACT_DIR}/${safe_name}.log" || true
      fi
      if [[ -f "${dir}/config/server.toml" ]]; then
        cp -f "${dir}/config/server.toml" "${E2E_ARTIFACT_DIR}/${safe_name}.server.toml" || true
      fi

      local audit_log=""
      for audit_log in "${dir}"/*audit*.log(N) "${dir}"/logs/*audit*.log(N); do
        cp -f "${audit_log}" "${E2E_ARTIFACT_DIR}/${safe_name}.$(basename "${audit_log}")" || true
      done
    done
  fi
  
  # Stop all servers
  for ((i = 1; i <= ${#SERVER_PIDS[@]}; i++)); do
    local pid="${SERVER_PIDS[$i]}"
    local name="${SERVER_NAMES[$i]}"
    [[ -n "${name}" ]] || name="unknown"
    stop_server "${pid}" "${name}"
  done
  
  # Remove temporary directory
  if [[ -d "${RUN_ROOT}" ]]; then
    log_info "Removing temporary directory: ${RUN_ROOT}"
    rm -rf "${RUN_ROOT}"
  fi
  
  local end_ts
  end_ts=$(date +%s)
  local duration=$((end_ts - START_TS))
  log_info "Total execution time: ${duration}s"
  
  # Exit with proper code
  if [[ ${FAIL_COUNT} -gt 0 || ${exit_status} -ne 0 ]]; then
    exit 1
  else
    exit 0
  fi
}

# Install cleanup trap
trap cleanup_all EXIT INT TERM

# ============================================================================
# Initialization
# ============================================================================

log_debug "Helper library loaded"
log_debug "RUN_ROOT: ${RUN_ROOT}"
log_debug "SERVER_BIN: ${SERVER_BIN:-<not set>}"

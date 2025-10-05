#!/bin/bash
#
# Replication Test Script
#
# This script spawns two LDAP servers (provider and consumer) and tests
# the replication functionality between them.
#
# Usage: ./scripts/test_replication.sh
#
# Description:
#   1. Builds the OpenDR LDAP server
#   2. Creates temporary directories for provider and consumer
#   3. Generates configuration files for both servers
#   4. Starts provider server on port 3890
#   5. Starts consumer server on port 3891
#   6. Adds test data to the provider
#   7. Waits for replication to occur
#   8. Verifies data was replicated to consumer
#   9. Displays server logs and keeps servers running for 5 minutes
#   10. Cleans up on exit
#
# Customization:
#   - Change PROVIDER_PORT and CONSUMER_PORT to use different ports
#   - Modify PROVIDER_DIR and CONSUMER_DIR to use different storage locations
#   - Adjust TEST_RUNTIME to change how long servers run
#   - Edit create_provider_config() to customize provider settings
#   - Edit create_consumer_config() to customize consumer settings
#
# Requirements:
#   - Rust and Cargo installed
#   - Optional: ldapsearch, ldapadd (openldap-clients) for LDAP queries
#   - Optional: nc (netcat) for connection testing
#
# See also: docs/REPLICATION_GUIDE.md for detailed replication documentation
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# ============================================================================
# Configuration - Customize these variables as needed
# ============================================================================

PROVIDER_PORT=3890              # Port for provider LDAP server
CONSUMER_PORT=3891              # Port for consumer LDAP server
PROVIDER_DIR="/tmp/opendr_provider"   # Provider data and config directory
CONSUMER_DIR="/tmp/opendr_consumer"   # Consumer data and config directory
TEST_RUNTIME=300                # How long to keep servers running (seconds)

# Internal variables (no need to modify)
PROVIDER_PID=""
CONSUMER_PID=""

# Cleanup function
cleanup() {
    log_info "Cleaning up..."

    # Kill provider server if running
    if [ -n "$PROVIDER_PID" ]; then
        log_info "Stopping provider server (PID: $PROVIDER_PID)"
        kill $PROVIDER_PID 2>/dev/null || true
        wait $PROVIDER_PID 2>/dev/null || true
    fi

    # Kill consumer server if running
    if [ -n "$CONSUMER_PID" ]; then
        log_info "Stopping consumer server (PID: $CONSUMER_PID)"
        kill $CONSUMER_PID 2>/dev/null || true
        wait $CONSUMER_PID 2>/dev/null || true
    fi

    # Clean up temporary directories
    log_info "Removing temporary directories"
    rm -rf "$PROVIDER_DIR" "$CONSUMER_DIR"

    log_success "Cleanup complete"
}

# Set up trap to cleanup on exit
trap cleanup EXIT INT TERM

# Check if ldapsearch is available
check_dependencies() {
    log_info "Checking dependencies..."

    if ! command -v ldapsearch &> /dev/null; then
        log_warning "ldapsearch not found. Install openldap-clients to run LDAP queries."
    fi

    if ! command -v cargo &> /dev/null; then
        log_error "cargo not found. Please install Rust."
        exit 1
    fi

    log_success "Dependencies OK"
}

# Build the project
build_project() {
    log_info "Building opendr..."
    cargo build --release
    log_success "Build complete"
}

# Create configuration for provider server
create_provider_config() {
    log_info "Creating provider server configuration..."

    mkdir -p "$PROVIDER_DIR/config"

    cat > "$PROVIDER_DIR/config/server.toml" <<EOF
[server]
bind_address = "127.0.0.1:${PROVIDER_PORT}"
base_dn = "dc=provider,dc=example,dc=org"
admin_dn = "cn=admin,dc=provider,dc=example,dc=org"
admin_password = "admin_password"

[backend]
backend_type = "Lmdb"
lmdb_path = "${PROVIDER_DIR}/data"
lmdb_map_size = 1073741824
max_readers = 126

[replication]
role = "provider"
changelog_enabled = true
changelog_max_entries = 10000
EOF

    log_success "Provider configuration created"
}

# Create configuration for consumer server
create_consumer_config() {
    log_info "Creating consumer server configuration..."

    mkdir -p "$CONSUMER_DIR/config"

    cat > "$CONSUMER_DIR/config/server.toml" <<EOF
[server]
bind_address = "127.0.0.1:${CONSUMER_PORT}"
base_dn = "dc=consumer,dc=example,dc=org"
admin_dn = "cn=admin,dc=consumer,dc=example,dc=org"
admin_password = "admin_password"

[backend]
backend_type = "Lmdb"
lmdb_path = "${CONSUMER_DIR}/data"
lmdb_map_size = 1073741824
max_readers = 126

[replication]
role = "consumer"
provider_url = "ldap://127.0.0.1:${PROVIDER_PORT}"
sync_interval_secs = 30
retry_attempts = 3
EOF

    log_success "Consumer configuration created"
}

# Start provider server
start_provider() {
    log_info "Starting provider server on port ${PROVIDER_PORT}..."

    mkdir -p "$PROVIDER_DIR/data"
    mkdir -p "$PROVIDER_DIR/logs"

    # Start provider in background
    RUST_LOG=info cargo run --release -- \
        --config "$PROVIDER_DIR/config/server.toml" \
        > "$PROVIDER_DIR/logs/server.log" 2>&1 &

    PROVIDER_PID=$!

    log_info "Provider server started with PID: $PROVIDER_PID"

    # Wait for server to be ready
    log_info "Waiting for provider server to be ready..."
    for i in {1..10}; do
        if nc -z 127.0.0.1 $PROVIDER_PORT 2>/dev/null; then
            log_success "Provider server is ready"
            return 0
        fi
        sleep 1
    done

    log_error "Provider server failed to start"
    cat "$PROVIDER_DIR/logs/server.log"
    exit 1
}

# Start consumer server
start_consumer() {
    log_info "Starting consumer server on port ${CONSUMER_PORT}..."

    mkdir -p "$CONSUMER_DIR/data"
    mkdir -p "$CONSUMER_DIR/logs"

    # Start consumer in background
    RUST_LOG=info cargo run --release -- \
        --config "$CONSUMER_DIR/config/server.toml" \
        > "$CONSUMER_DIR/logs/server.log" 2>&1 &

    CONSUMER_PID=$!

    log_info "Consumer server started with PID: $CONSUMER_PID"

    # Wait for server to be ready
    log_info "Waiting for consumer server to be ready..."
    for i in {1..10}; do
        if nc -z 127.0.0.1 $CONSUMER_PORT 2>/dev/null; then
            log_success "Consumer server is ready"
            return 0
        fi
        sleep 1
    done

    log_error "Consumer server failed to start"
    cat "$CONSUMER_DIR/logs/server.log"
    exit 1
}

# Add test data to provider
add_test_data() {
    log_info "Adding test data to provider..."

    if ! command -v ldapadd &> /dev/null; then
        log_warning "ldapadd not available, skipping data population"
        return 0
    fi

    # Create LDIF file
    cat > /tmp/test_data.ldif <<EOF
dn: dc=provider,dc=example,dc=org
objectClass: top
objectClass: domain
dc: provider

dn: cn=user1,dc=provider,dc=example,dc=org
objectClass: person
cn: user1
sn: User One
description: Test user 1

dn: cn=user2,dc=provider,dc=example,dc=org
objectClass: person
cn: user2
sn: User Two
description: Test user 2

dn: cn=user3,dc=provider,dc=example,dc=org
objectClass: person
cn: user3
sn: User Three
description: Test user 3
EOF

    # Add entries
    ldapadd -x -H "ldap://127.0.0.1:${PROVIDER_PORT}" \
        -D "cn=admin,dc=provider,dc=example,dc=org" \
        -w "admin_password" \
        -f /tmp/test_data.ldif || true

    rm /tmp/test_data.ldif

    log_success "Test data added to provider"
}

# Verify replication
verify_replication() {
    log_info "Verifying replication..."

    if ! command -v ldapsearch &> /dev/null; then
        log_warning "ldapsearch not available, skipping verification"
        return 0
    fi

    # Wait for replication to occur
    log_info "Waiting for replication (30 seconds)..."
    sleep 30

    # Search provider
    log_info "Searching provider..."
    PROVIDER_COUNT=$(ldapsearch -x -H "ldap://127.0.0.1:${PROVIDER_PORT}" \
        -D "cn=admin,dc=provider,dc=example,dc=org" \
        -w "admin_password" \
        -b "dc=provider,dc=example,dc=org" \
        "(objectClass=person)" | grep -c "^dn:" || echo "0")

    log_info "Provider has $PROVIDER_COUNT entries"

    # Search consumer
    log_info "Searching consumer..."
    CONSUMER_COUNT=$(ldapsearch -x -H "ldap://127.0.0.1:${CONSUMER_PORT}" \
        -D "cn=admin,dc=consumer,dc=example,dc=org" \
        -w "admin_password" \
        -b "dc=consumer,dc=example,dc=org" \
        "(objectClass=person)" | grep -c "^dn:" || echo "0")

    log_info "Consumer has $CONSUMER_COUNT entries"

    if [ "$PROVIDER_COUNT" -eq "$CONSUMER_COUNT" ] && [ "$PROVIDER_COUNT" -gt "0" ]; then
        log_success "Replication verified: $CONSUMER_COUNT entries replicated"
        return 0
    else
        log_warning "Replication mismatch: Provider=$PROVIDER_COUNT, Consumer=$CONSUMER_COUNT"
        return 1
    fi
}

# Display server logs
show_logs() {
    log_info "===== Provider Server Logs ====="
    tail -n 50 "$PROVIDER_DIR/logs/server.log" || echo "No provider logs"

    echo ""
    log_info "===== Consumer Server Logs ====="
    tail -n 50 "$CONSUMER_DIR/logs/server.log" || echo "No consumer logs"
}

# Main execution
main() {
    echo "========================================"
    echo "   OpenDR Replication Test Script"
    echo "========================================"
    echo ""

    check_dependencies
    build_project

    echo ""
    log_info "Setting up test environment..."
    create_provider_config
    create_consumer_config

    echo ""
    start_provider
    start_consumer

    echo ""
    add_test_data

    echo ""
    verify_replication

    echo ""
    log_info "Test servers running. Press Ctrl+C to stop."
    log_info "Provider: ldap://127.0.0.1:${PROVIDER_PORT}"
    log_info "Consumer: ldap://127.0.0.1:${CONSUMER_PORT}"

    echo ""
    show_logs

    # Keep script running
    echo ""
    log_info "Servers will run for $TEST_RUNTIME seconds ($((TEST_RUNTIME/60)) minutes) for manual testing..."
    log_info "Press Ctrl+C at any time to stop the servers and exit"
    sleep $TEST_RUNTIME

    log_success "Test complete"
}

# Run main function
main

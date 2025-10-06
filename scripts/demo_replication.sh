#!/usr/bin/env bash
#
# OpenDR Replication Demo Script
#
# This script demonstrates OpenDR LDAP replication by:
# 1. Building the OpenDR server
# 2. Starting a provider server
# 3. Starting a consumer server
# 4. Adding test data to the provider
# 5. Verifying replication to the consumer
# 6. Testing various LDAP operations
# 7. Cleanup and shutdown
#
# Usage: ./demo_replication.sh [options]
#
# Options:
#   --skip-build    Skip cargo build step
#   --keep-running  Keep servers running (don't cleanup)
#   --verbose       Enable verbose output
#   --help          Show this help message

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TEMP_DIR="/tmp/opendr-replication-demo-$$"
PROVIDER_PORT=3890
CONSUMER_PORT=3891
SKIP_BUILD=false
KEEP_RUNNING=false
VERBOSE=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --keep-running)
            KEEP_RUNNING=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --help)
            grep '^#' "$0" | grep -v '#!/' | sed 's/^# //g'
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Helper functions
log() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

step() {
    echo ""
    echo -e "${BLUE}==>${NC} ${YELLOW}$*${NC}"
}

verbose() {
    if [ "$VERBOSE" = true ]; then
        echo -e "${BLUE}[DEBUG]${NC} $*"
    fi
}

cleanup() {
    step "Cleaning up..."
    
    # Kill provider server
    if [ -f "$TEMP_DIR/provider.pid" ]; then
        PROVIDER_PID=$(cat "$TEMP_DIR/provider.pid")
        if kill -0 "$PROVIDER_PID" 2>/dev/null; then
            log "Stopping provider server (PID: $PROVIDER_PID)"
            kill -TERM "$PROVIDER_PID" 2>/dev/null || true
            sleep 2
            kill -KILL "$PROVIDER_PID" 2>/dev/null || true
        fi
    fi
    
    # Kill consumer server
    if [ -f "$TEMP_DIR/consumer.pid" ]; then
        CONSUMER_PID=$(cat "$TEMP_DIR/consumer.pid")
        if kill -0 "$CONSUMER_PID" 2>/dev/null; then
            log "Stopping consumer server (PID: $CONSUMER_PID)"
            kill -TERM "$CONSUMER_PID" 2>/dev/null || true
            sleep 2
            kill -KILL "$CONSUMER_PID" 2>/dev/null || true
        fi
    fi
    
    # Remove temp directory
    if [ "$KEEP_RUNNING" = false ]; then
        if [ -d "$TEMP_DIR" ]; then
            log "Removing temporary directory: $TEMP_DIR"
            rm -rf "$TEMP_DIR"
        fi
        log "Cleanup complete"
    else
        warn "Keeping temporary directory for inspection: $TEMP_DIR"
        warn "Provider log: $TEMP_DIR/provider/server.log"
        warn "Consumer log: $TEMP_DIR/consumer/server.log"
    fi
}

# Set trap for cleanup
trap cleanup EXIT INT TERM

# Main execution
main() {
    step "OpenDR Replication Demo"
    log "Project root: $PROJECT_ROOT"
    log "Temporary directory: $TEMP_DIR"
    
    # Check dependencies
    step "Checking dependencies..."
    if ! command -v ldapadd &> /dev/null; then
        error "ldapadd not found. Please install openldap-clients"
        exit 1
    fi
    if ! command -v ldapsearch &> /dev/null; then
        error "ldapsearch not found. Please install openldap-clients"
        exit 1
    fi
    log "All dependencies found"
    
    # Build OpenDR
    if [ "$SKIP_BUILD" = false ]; then
        step "Building OpenDR..."
        cd "$PROJECT_ROOT"
        cargo build --release
        log "Build complete"
    else
        warn "Skipping build step"
    fi
    
    # Create temporary directory structure
    step "Creating temporary directory structure..."
    mkdir -p "$TEMP_DIR"/{provider,consumer}/{data,config}
    mkdir -p "$TEMP_DIR/consumer/replication_state"
    log "Directory structure created"
    
    # Create provider configuration
    step "Creating provider configuration..."
    cat > "$TEMP_DIR/provider/config/server.toml" <<EOF
[server]
bind_address = "127.0.0.1:$PROVIDER_PORT"
base_dn = "dc=example,dc=com"
admin_dn = "cn=admin,dc=example,dc=com"
admin_password = "provider_admin"
server_id = "provider-demo"

[backend]
backend_type = "Lmdb"
lmdb_path = "$TEMP_DIR/provider/data"
lmdb_map_size = 1073741824
max_readers = 126

[replication]
enabled = true
mode = "provider"
changelog_capacity = 1000
max_batch_size = 100

[monitoring]
enabled = false

[audit]
enabled = false

[rate_limit]
enabled = false
EOF
    log "Provider configuration created"
    
    # Create consumer configuration
    step "Creating consumer configuration..."
    cat > "$TEMP_DIR/consumer/config/server.toml" <<EOF
[server]
bind_address = "127.0.0.1:$CONSUMER_PORT"
base_dn = "dc=example,dc=com"
admin_dn = "cn=admin,dc=example,dc=com"
admin_password = "consumer_admin"
server_id = "consumer-demo"

[backend]
backend_type = "Lmdb"
lmdb_path = "$TEMP_DIR/consumer/data"
lmdb_map_size = 1073741824
max_readers = 126

[replication]
enabled = true
mode = "consumer"
provider_url = "ldap://127.0.0.1:$PROVIDER_PORT"
sync_interval_secs = 5
state_storage_path = "$TEMP_DIR/consumer/replication_state"

[monitoring]
enabled = false

[audit]
enabled = false

[rate_limit]
enabled = false
EOF
    log "Consumer configuration created"
    
    # Start provider server
    step "Starting provider server on port $PROVIDER_PORT..."
    "$PROJECT_ROOT/target/release/opendr" \
        --config "$TEMP_DIR/provider/config/server.toml" \
        > "$TEMP_DIR/provider/server.log" 2>&1 &
    PROVIDER_PID=$!
    echo $PROVIDER_PID > "$TEMP_DIR/provider.pid"
    log "Provider server started (PID: $PROVIDER_PID)"
    
    # Wait for provider to be ready
    log "Waiting for provider to be ready..."
    sleep 3
    if ! kill -0 $PROVIDER_PID 2>/dev/null; then
        error "Provider server failed to start"
        cat "$TEMP_DIR/provider/server.log"
        exit 1
    fi
    log "Provider server is ready"
    
    # Add base entries to provider
    step "Adding base entries to provider..."
    ldapadd -x -H "ldap://127.0.0.1:$PROVIDER_PORT" \
        -D "cn=admin,dc=example,dc=com" \
        -w "provider_admin" <<EOF
dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

dn: ou=people,dc=example,dc=com
objectClass: organizationalUnit
ou: people

dn: ou=groups,dc=example,dc=com
objectClass: organizationalUnit
ou: groups

dn: cn=Alice Smith,ou=people,dc=example,dc=com
objectClass: person
cn: Alice Smith
sn: Smith

dn: cn=Bob Jones,ou=people,dc=example,dc=com
objectClass: person
cn: Bob Jones
sn: Jones
EOF
    log "Base entries added to provider"
    
    # Start consumer server
    step "Starting consumer server on port $CONSUMER_PORT..."
    "$PROJECT_ROOT/target/release/opendr" \
        --config "$TEMP_DIR/consumer/config/server.toml" \
        > "$TEMP_DIR/consumer/server.log" 2>&1 &
    CONSUMER_PID=$!
    echo $CONSUMER_PID > "$TEMP_DIR/consumer.pid"
    log "Consumer server started (PID: $CONSUMER_PID)"
    
    # Wait for consumer to be ready and sync
    log "Waiting for consumer to be ready and perform initial sync..."
    sleep 10
    if ! kill -0 $CONSUMER_PID 2>/dev/null; then
        error "Consumer server failed to start"
        cat "$TEMP_DIR/consumer/server.log"
        exit 1
    fi
    log "Consumer server is ready"
    
    # Verify replication
    step "Verifying initial replication..."
    PROVIDER_COUNT=$(ldapsearch -x -H "ldap://127.0.0.1:$PROVIDER_PORT" \
        -b "dc=example,dc=com" -D "cn=admin,dc=example,dc=com" \
        -w "provider_admin" "(objectClass=*)" dn 2>/dev/null | grep "^dn:" | wc -l)
    
    CONSUMER_COUNT=$(ldapsearch -x -H "ldap://127.0.0.1:$CONSUMER_PORT" \
        -b "dc=example,dc=com" -D "cn=admin,dc=example,dc=com" \
        -w "consumer_admin" "(objectClass=*)" dn 2>/dev/null | grep "^dn:" | wc -l)
    
    log "Provider entry count: $PROVIDER_COUNT"
    log "Consumer entry count: $CONSUMER_COUNT"
    
    if [ "$PROVIDER_COUNT" -eq "$CONSUMER_COUNT" ] && [ "$PROVIDER_COUNT" -gt 0 ]; then
        log "✓ Initial replication successful!"
    else
        error "✗ Initial replication failed (counts don't match)"
        exit 1
    fi
    
    # Test add operation replication
    step "Testing add operation replication..."
    ldapadd -x -H "ldap://127.0.0.1:$PROVIDER_PORT" \
        -D "cn=admin,dc=example,dc=com" \
        -w "provider_admin" <<EOF
dn: cn=Charlie Brown,ou=people,dc=example,dc=com
objectClass: person
cn: Charlie Brown
sn: Brown
EOF
    log "Added Charlie Brown to provider"
    
    # Wait for replication
    log "Waiting for replication..."
    sleep 6
    
    # Verify on consumer
    if ldapsearch -x -H "ldap://127.0.0.1:$CONSUMER_PORT" \
        -b "ou=people,dc=example,dc=com" \
        -D "cn=admin,dc=example,dc=com" \
        -w "consumer_admin" \
        "(cn=Charlie Brown)" dn 2>/dev/null | grep -q "cn=Charlie Brown"; then
        log "✓ Add operation replicated successfully!"
    else
        error "✗ Add operation replication failed"
        exit 1
    fi
    
    # Test modify operation replication
    step "Testing modify operation replication..."
    ldapmodify -x -H "ldap://127.0.0.1:$PROVIDER_PORT" \
        -D "cn=admin,dc=example,dc=com" \
        -w "provider_admin" <<EOF
dn: cn=Alice Smith,ou=people,dc=example,dc=com
changetype: modify
add: description
description: Modified via replication test
EOF
    log "Modified Alice Smith on provider"
    
    # Wait for replication
    log "Waiting for replication..."
    sleep 6
    
    # Verify on consumer
    if ldapsearch -x -H "ldap://127.0.0.1:$CONSUMER_PORT" \
        -b "ou=people,dc=example,dc=com" \
        -D "cn=admin,dc=example,dc=com" \
        -w "consumer_admin" \
        "(cn=Alice Smith)" description 2>/dev/null | \
        grep -q "Modified via replication test"; then
        log "✓ Modify operation replicated successfully!"
    else
        error "✗ Modify operation replication failed"
        exit 1
    fi
    
    # Test delete operation replication
    step "Testing delete operation replication..."
    ldapdelete -x -H "ldap://127.0.0.1:$PROVIDER_PORT" \
        -D "cn=admin,dc=example,dc=com" \
        -w "provider_admin" \
        "cn=Bob Jones,ou=people,dc=example,dc=com"
    log "Deleted Bob Jones from provider"
    
    # Wait for replication
    log "Waiting for replication..."
    sleep 6
    
    # Verify on consumer (should not exist)
    if ! ldapsearch -x -H "ldap://127.0.0.1:$CONSUMER_PORT" \
        -b "ou=people,dc=example,dc=com" \
        -D "cn=admin,dc=example,dc=com" \
        -w "consumer_admin" \
        "(cn=Bob Jones)" dn 2>/dev/null | grep -q "cn=Bob Jones"; then
        log "✓ Delete operation replicated successfully!"
    else
        error "✗ Delete operation replication failed"
        exit 1
    fi
    
    # Final verification
    step "Final verification..."
    FINAL_PROVIDER_COUNT=$(ldapsearch -x -H "ldap://127.0.0.1:$PROVIDER_PORT" \
        -b "dc=example,dc=com" -D "cn=admin,dc=example,dc=com" \
        -w "provider_admin" "(objectClass=*)" dn 2>/dev/null | grep "^dn:" | wc -l)
    
    FINAL_CONSUMER_COUNT=$(ldapsearch -x -H "ldap://127.0.0.1:$CONSUMER_PORT" \
        -b "dc=example,dc=com" -D "cn=admin,dc=example,dc=com" \
        -w "consumer_admin" "(objectClass=*)" dn 2>/dev/null | grep "^dn:" | wc -l)
    
    log "Final provider entry count: $FINAL_PROVIDER_COUNT"
    log "Final consumer entry count: $FINAL_CONSUMER_COUNT"
    
    if [ "$FINAL_PROVIDER_COUNT" -eq "$FINAL_CONSUMER_COUNT" ]; then
        log "✓ Final synchronization verified!"
    else
        error "✗ Final synchronization failed (counts don't match)"
        exit 1
    fi
    
    # Summary
    step "Demo Complete!"
    echo ""
    log "✓ Provider-consumer replication working correctly"
    log "✓ All CRUD operations replicated successfully"
    log "✓ Entry counts match between provider and consumer"
    echo ""
    
    if [ "$KEEP_RUNNING" = true ]; then
        warn "Servers are still running:"
        warn "  Provider: ldap://127.0.0.1:$PROVIDER_PORT"
        warn "  Consumer: ldap://127.0.0.1:$CONSUMER_PORT"
        warn ""
        warn "To stop servers manually:"
        warn "  kill $PROVIDER_PID  # Provider"
        warn "  kill $CONSUMER_PID  # Consumer"
        warn ""
        warn "Press Ctrl+C to stop all servers and cleanup"
        wait
    fi
}

# Run main function
main "$@"

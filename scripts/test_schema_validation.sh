#!/bin/bash
#
# Schema Validation End-to-End Test Script
# This script tests that schema validation is working correctly by:
# 1. Resetting the server (clean state)
# 2. Starting the server
# 3. Adding valid entries (should succeed)
# 4. Adding invalid entries (should fail with schema errors)
#
# Usage: ./scripts/test_schema_validation.sh

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SERVER_PORT=1389
SERVER_URL="ldap://localhost:$SERVER_PORT"
ADMIN_DN="cn=manager,dc=example,dc=com"
ADMIN_PW="Admin@123"
BASE_DN="dc=example,dc=com"

# Counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((PASSED_TESTS++))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((FAILED_TESTS++))
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Function to wait for server to be ready
wait_for_server() {
    log_info "Waiting for server to be ready..."
    local max_attempts=30
    local attempt=0

    while [ $attempt -lt $max_attempts ]; do
        # Try to connect - just check if port is listening
        if nc -z localhost $SERVER_PORT 2>/dev/null; then
            log_success "Server is ready"
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 1
    done

    log_fail "Server did not become ready in time"
    return 1
}

# Function to test adding an entry
test_add_entry() {
    local test_name="$1"
    local ldif_content="$2"
    local should_succeed="$3"

    ((TOTAL_TESTS++))

    log_info "Test: $test_name"

    # Create temporary LDIF file
    local temp_ldif=$(mktemp)
    echo "$ldif_content" > "$temp_ldif"

    # Try to add entry
    if ldapadd -x -H "$SERVER_URL" -D "$ADMIN_DN" -w "$ADMIN_PW" -f "$temp_ldif" >/dev/null 2>&1; then
        # Entry added successfully
        if [ "$should_succeed" = "true" ]; then
            log_success "$test_name: Entry added successfully (as expected)"
        else
            log_fail "$test_name: Entry added successfully (should have FAILED)"
        fi
    else
        # Entry add failed
        if [ "$should_succeed" = "false" ]; then
            log_success "$test_name: Entry rejected (as expected)"
        else
            log_fail "$test_name: Entry rejected (should have SUCCEEDED)"
        fi
    fi

    # Clean up
    rm -f "$temp_ldif"
}

# Function to cleanup test entries
cleanup_entry() {
    local dn="$1"
    ldapdelete -x -H "$SERVER_URL" -D "$ADMIN_DN" -w "$ADMIN_PW" "$dn" >/dev/null 2>&1 || true
}

# Main script
main() {
    echo "========================================="
    echo "Schema Validation End-to-End Test"
    echo "========================================="
    echo ""

    # Step 1: Stop any running server
    log_info "Step 1: Stopping any running server..."
    pkill -9 -f "cargo run --bin opendr" 2>/dev/null || true
    sleep 2

    # Step 2: Clean data directory
    log_info "Step 2: Cleaning data directory..."
    rm -rf data
    mkdir -p data

    # Step 3: Start server in background
    log_info "Step 3: Starting LDAP server..."
    cargo run --bin opendr > /tmp/ldap_server.log 2>&1 &
    SERVER_PID=$!
    log_info "Server started with PID: $SERVER_PID"

    # Step 4: Wait for server to be ready
    if ! wait_for_server; then
        log_fail "Server failed to start"
        kill $SERVER_PID 2>/dev/null || true
        exit 1
    fi

    echo ""
    echo "========================================="
    echo "Setting up base directory structure"
    echo "========================================="
    echo ""

    # Add base entries first
    log_info "Adding base directory structure..."
    ldapadd -x -H "$SERVER_URL" -D "$ADMIN_DN" -w "$ADMIN_PW" -f config/base.ldif >/dev/null 2>&1 || {
        log_warn "Base structure already exists or failed to add (continuing anyway)"
    }

    echo ""
    echo "========================================="
    echo "Running Schema Validation Tests"
    echo "========================================="
    echo ""

    # Test 1: Valid person entry (should succeed)
    test_add_entry "Valid person entry" \
"dn: cn=John Doe,ou=People,dc=example,dc=com
objectClass: top
objectClass: person
cn: John Doe
sn: Doe
userPassword: secret123" \
        "true"

    # Test 2: Person missing required 'sn' (should fail)
    test_add_entry "Person missing required 'sn' attribute" \
"dn: cn=Jane Smith,ou=People,dc=example,dc=com
objectClass: top
objectClass: person
cn: Jane Smith
userPassword: secret123" \
        "false"

    # Test 3: Person missing required 'cn' (should fail)
    test_add_entry "Person missing required 'cn' attribute" \
"dn: cn=Missing CN,ou=People,dc=example,dc=com
objectClass: top
objectClass: person
sn: Smith" \
        "false"

    # Test 4: Unknown object class (should fail)
    test_add_entry "Unknown object class" \
"dn: cn=Test User,ou=People,dc=example,dc=com
objectClass: top
objectClass: unknownClass
cn: Test User
sn: User" \
        "false"

    # Test 5: Only abstract object class (should fail)
    test_add_entry "Only abstract object class" \
"dn: cn=Abstract Only,ou=People,dc=example,dc=com
objectClass: top
cn: Abstract Only" \
        "false"

    # Test 6: Valid inetOrgPerson entry (should succeed)
    test_add_entry "Valid inetOrgPerson entry" \
"dn: uid=ajohnson,ou=People,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: Alice Johnson
sn: Johnson
uid: ajohnson
mail: ajohnson@example.com" \
        "true"

    # Test 7: Valid organizationalUnit entry (should succeed)
    test_add_entry "Valid organizationalUnit entry" \
"dn: ou=Engineering,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
ou: Engineering
description: Engineering Department" \
        "true"

    # Test 8: Valid organization entry (should succeed)
    test_add_entry "Valid organization entry" \
"dn: o=Test Org,dc=example,dc=com
objectClass: top
objectClass: organization
o: Test Org
description: Test Organization" \
        "true"

    # Test 9: Organization missing required 'o' (should fail)
    test_add_entry "Organization missing required 'o' attribute" \
"dn: o=Missing O,dc=example,dc=com
objectClass: top
objectClass: organization
description: Missing required attribute" \
        "false"

    # Test 10: OrganizationalUnit missing required 'ou' (should fail)
    test_add_entry "OrganizationalUnit missing required 'ou' attribute" \
"dn: ou=Missing OU,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
description: Missing required attribute" \
        "false"

    echo ""
    echo "========================================="
    echo "Cleanup"
    echo "========================================="
    echo ""

    # Cleanup successfully added entries
    log_info "Cleaning up test entries..."
    cleanup_entry "cn=John Doe,ou=People,dc=example,dc=com"
    cleanup_entry "uid=ajohnson,ou=People,dc=example,dc=com"
    cleanup_entry "ou=Engineering,dc=example,dc=com"
    cleanup_entry "o=Test Org,dc=example,dc=com"

    # Stop server
    log_info "Stopping server..."
    kill $SERVER_PID 2>/dev/null || true
    sleep 1

    echo ""
    echo "========================================="
    echo "Test Results"
    echo "========================================="
    echo ""
    echo "Total Tests:  $TOTAL_TESTS"
    echo -e "${GREEN}Passed Tests: $PASSED_TESTS${NC}"
    echo -e "${RED}Failed Tests: $FAILED_TESTS${NC}"
    echo ""

    if [ $FAILED_TESTS -eq 0 ]; then
        echo -e "${GREEN}✓ ALL TESTS PASSED!${NC}"
        echo "Schema validation is working correctly!"
        return 0
    else
        echo -e "${RED}✗ SOME TESTS FAILED${NC}"
        echo "Please check the server logs at /tmp/ldap_server.log"
        return 1
    fi
}

# Run main function
main
exit $?

# Test Scripts

This directory contains test scripts for validating the opendr LDAP server functionality.

## Available Scripts

### test_schema_validation.sh

**Purpose**: End-to-end test for LDAP schema validation

**What it does**:
1. Stops any running server
2. Cleans the data directory
3. Starts a fresh server
4. Tests 10 scenarios (4 valid, 6 invalid entries)
5. Verifies schema validation is working
6. Cleans up test data
7. Shows test results

**Usage**:
```bash
./scripts/test_schema_validation.sh
```

**Prerequisites**:
- Rust and Cargo installed
- `ldap-utils` package installed (for ldapadd, ldapsearch, ldapdelete)
  ```bash
  # Ubuntu/Debian
  sudo apt-get install ldap-utils

  # macOS
  brew install openldap
  ```

**Test Scenarios**:

| # | Test | Type | Expected |
|---|------|------|----------|
| 1 | Valid person entry | Valid | ✅ Success |
| 2 | Person missing 'sn' | Invalid | ❌ Rejected |
| 3 | Person missing 'cn' | Invalid | ❌ Rejected |
| 4 | Unknown object class | Invalid | ❌ Rejected |
| 5 | Only abstract class | Invalid | ❌ Rejected |
| 6 | Valid inetOrgPerson | Valid | ✅ Success |
| 7 | Valid organizationalUnit | Valid | ✅ Success |
| 8 | Valid organization | Valid | ✅ Success |
| 9 | Organization missing 'o' | Invalid | ❌ Rejected |
| 10 | OrganizationalUnit missing 'ou' | Invalid | ❌ Rejected |

**Expected Output**:
```
=========================================
Schema Validation End-to-End Test
=========================================

[INFO] Step 1: Stopping any running server...
[INFO] Step 2: Cleaning data directory...
[INFO] Step 3: Starting LDAP server...
[INFO] Server started with PID: 12345
[INFO] Waiting for server to be ready...
[PASS] Server is ready

=========================================
Running Schema Validation Tests
=========================================

[INFO] Test: Valid person entry
[PASS] Valid person entry: Entry added successfully (as expected)
[INFO] Test: Person missing required 'sn' attribute
[PASS] Person missing required 'sn' attribute: Entry rejected (as expected)
...

=========================================
Test Results
=========================================

Total Tests:  10
Passed Tests: 10
Failed Tests: 0

✓ ALL TESTS PASSED!
Schema validation is working correctly!
```

**Troubleshooting**:

If tests fail:
1. Check server logs: `cat /tmp/ldap_server.log`
2. Verify server is running: `ps aux | grep opendr`
3. Check LDAP connection: `ldapsearch -x -H ldap://localhost:3389 -b "dc=example,dc=com"`
4. Ensure port 3389 is available: `lsof -i :3389`

**What This Validates**:

✅ Schema validation is enabled
✅ Valid entries are accepted
✅ Invalid entries are rejected with specific errors
✅ Required attributes are enforced
✅ Object class validation works
✅ Structural class requirements work

## Installing ldap-utils

### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install ldap-utils
```

### macOS
```bash
brew install openldap
```

### Verify Installation
```bash
ldapsearch -VV
```

## Running Tests

### Quick Test
```bash
# Run the schema validation test
./scripts/test_schema_validation.sh
```

### Manual Testing
```bash
# Start server manually
cargo run --bin opendr

# In another terminal, add a valid entry
ldapadd -x -H ldap://localhost:3389 \
    -D "cn=admin,dc=example,dc=com" -w admin123 <<EOF
dn: cn=Test User,ou=People,dc=example,dc=com
objectClass: top
objectClass: person
cn: Test User
sn: User
EOF

# Try to add an invalid entry (should fail)
ldapadd -x -H ldap://localhost:3389 \
    -D "cn=admin,dc=example,dc=com" -w admin123 <<EOF
dn: cn=Bad Entry,ou=People,dc=example,dc=com
objectClass: top
objectClass: person
cn: Bad Entry
# Missing required 'sn' - should fail
EOF
```

## Exit Codes

- `0` - All tests passed
- `1` - Some tests failed

## Logs

Test logs are written to:
- Server log: `/tmp/ldap_server.log`
- Contains detailed server output and error messages

## Future Scripts

Planned test scripts:
- `test_employee_schema.sh` - Test employee schema (when implemented)
- `test_application_schema.sh` - Test application schema (when implemented)
- `test_performance.sh` - Performance and load testing
- `test_replication.sh` - Replication testing

## See Also

- [Schema Definition Guide](../docs/SCHEMA_DEFINITION_GUIDE.md)
- [Schema Quick Start](../docs/SCHEMA_QUICK_START.md)
- [Schema Validation Examples](../examples/schema_validation_test.rs)

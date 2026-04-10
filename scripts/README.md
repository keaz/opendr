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

### perf_single_instance_lmdb.sh

**Purpose**: End-to-end performance run for a single OpenDR instance backed by LMDB.

**What it measures**:
1. LDAP operation latency and throughput for bind, search, compare, modify, password modify, add, modifyDN, and delete
2. Server CPU usage sampled during the benchmark run
3. Server memory usage (RSS) sampled during the benchmark run
4. LMDB database size on disk before and after the run
5. Number of LDAP records before fixture setup, after preload, and after the benchmark sequence

**Implementation notes**:
- Starts an isolated OpenDR runtime under `target/perf/...`
- Uses the `lmdb` backend
- Enables StartTLS automatically so Password Modify can be exercised without disabling confidentiality checks
- Writes a combined markdown report plus raw JSON metrics

**Usage**:
```bash
# Default single-instance LMDB run
./scripts/perf_single_instance_lmdb.sh

# Smaller smoke run
./scripts/perf_single_instance_lmdb.sh \
  --preloaded-users 200 \
  --read-iterations 50 \
  --write-iterations 25
```

**Artifacts**:
- Markdown report: `target/perf/.../report.md`
- Raw LDAP metrics: `target/perf/.../ldap-benchmark-results.json`
- Resource samples: `target/perf/.../server-resource-samples.csv`
- Server log: `target/perf/.../server.log`

### perf_docker_matrix.sh

**Purpose**: Run the same LDAP benchmark suite against Dockerized OpenDR and OpenDJ instances under fixed container limits.

**What it does**:
1. Builds the local OpenDR Docker image from `Dockerfile`
2. Pulls `openidentityplatform/opendj:5.0.4`
3. Runs both servers with `--cpus=2` and `--memory=4g`
4. Executes the same StartTLS-enabled benchmark client against each load profile
5. Captures latency, throughput, CPU, memory, database size, and record-count artifacts per run
6. Produces a matrix-wide markdown and CSV comparison summary

**Usage**:
```bash
# Full OpenDR vs OpenDJ matrix
./scripts/perf_docker_matrix.sh

# Smoke-only comparison
./scripts/perf_docker_matrix.sh \
  --profile-set smoke \
  --output-dir target/perf/docker-matrix-smoke

# OpenDR only, with a shorter timeout budget
./scripts/perf_docker_matrix.sh \
  --products opendr \
  --benchmark-timeout 120
```

**Profiles**:
- `smoke`: very small validation run
- `standard`: light, moderate, heavy
- `full`: light, moderate, heavy, stress

**Key options**:
- `--cpu`: container CPU limit, default `2`
- `--memory`: container memory limit, default `4g`
- `--benchmark-timeout`: per-profile timeout budget in seconds, default `180`
- `--products`: comma-separated subset of `opendr,opendj`

**Artifacts**:
- Matrix summary: `target/perf/.../comparison-summary.md`
- Matrix CSV: `target/perf/.../comparison-summary.csv`
- Per-run report: `target/perf/.../<product>/<profile>/report.md`
- Per-run raw metrics: `target/perf/.../<product>/<profile>/ldap-benchmark-results.json`
- Per-run container stats: `target/perf/.../<product>/<profile>/container-stats-summary.json`
- Per-run status: `target/perf/.../<product>/<profile>/run-status.json`

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

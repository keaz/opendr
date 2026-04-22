# Test Scripts

This directory contains test scripts for validating the opendr LDAP server functionality.

## Available Scripts

### referral_alias_interop.sh

**Purpose**: Manual interoperability checks for LDAP referrals, aliases, and
ManageDsaIT using `ldapsearch` plus Python `ldap3` when available.

**Usage**:
```bash
OPENDR_LDAP_URL=ldap://127.0.0.1:1389 \
OPENDR_BASE_DN=dc=example,dc=org \
OPENDR_REFERRAL_DN=ou=remote,dc=example,dc=org \
OPENDR_ALIAS_DN=cn=alias,dc=example,dc=org \
./scripts/referral_alias_interop.sh
```

**Prerequisites**:
- A running OpenDR server with referral and alias fixtures loaded.
- `ldapsearch` from OpenLDAP client tools.
- Optional: Python `ldap3` for SDK/client verification.

### ldap_interop_gate.sh

**Purpose**: Production-readiness interoperability gate for the advertised LDAP
surface. The script can start an isolated OpenDR server, then runs OpenLDAP CLI,
Python `ldap3`, and the Rust `ldap_ops_client` against the same StartTLS
endpoint. It writes a sanitized transcript, server stdout, and server stderr to
`target/ldap-interop-gate/<timestamp>` by default.

**What it covers**:
1. OpenLDAP CLI Bind, StartTLS, Root DSE, Search, Add, Modify, Delete,
   ModifyDN, Compare, paged results, server-side sort, subschema, operational
   attribute reads, RFC 4513 cleartext-bind rejection, SASL PLAIN over StartTLS
   and LDAPS, granted and denied SASL proxy authzid policy, and WhoAmI after
   simple and SASL bind.
2. Python `ldap3` Bind, StartTLS, Root DSE, and subschema reads.
3. Rust `ldap_ops_client` Bind, Root DSE, Search, Add, Modify, Delete,
   ModifyDN, Compare, WhoAmI, and Password Modify.
4. Generated mTLS fixtures for SASL EXTERNAL Root DSE advertising and bind over
   StartTLS and LDAPS. OpenLDAP mTLS is attempted first; on SecureTransport
   clients that cannot use PEM `TLS_CERT`/`TLS_KEY`, the script falls back to a
   raw Python TLS client-cert LDAP check. Set
   `OPENDR_INTEROP_REQUIRE_OPENLDAP_MTLS=1` to require OpenLDAP mTLS support.

**Usage**:
```bash
python3 -m pip install ldap3
./scripts/ldap_interop_gate.sh
```

To run the OpenLDAP/Rust checks without Python `ldap3`:

```bash
OPENDR_INTEROP_SKIP_LDAP3=1 ./scripts/ldap_interop_gate.sh
```

To run against an already running server:

```bash
OPENDR_INTEROP_START_SERVER=0 \
OPENDR_LDAP_URL=ldap://127.0.0.1:1389 \
OPENDR_BASE_DN=dc=example,dc=org \
OPENDR_BIND_DN=cn=admin,dc=example,dc=org \
OPENDR_BIND_PW="$LOCAL_TEST_BIND_PASSWORD" \
./scripts/ldap_interop_gate.sh
```

**Prerequisites**:
- Rust and Cargo.
- OpenLDAP command-line tools: `ldapsearch`, `ldapadd`, `ldapmodify`,
  `ldapdelete`, `ldapcompare`, `ldapmodrdn`, and `ldapwhoami`.
- Python 3 with the `ldap3` package.
- `openssl` when the script starts its own temporary server.

### production_config_gate.sh

**Purpose**: Production-readiness gate for finalized OpenDR server TOML files.
It validates the hardening baseline before a config is used as deployment
evidence.

**What it covers**:
1. `security.profile = "production"` and `tls.enabled = true`.
2. Audit, access control, and rate limiting are enabled.
3. Access control is deny-by-default and points at a rules file.
4. Root and replication secrets use `_env` or `_file` sources, not inline TOML.
5. LMDB data and replication state paths are absolute production paths outside
   the source tree.
6. Cleartext simple bind, anonymous bind, insecure replication provider bind,
   and `ldap://` replication provider URLs are rejected.

**Usage**:
```bash
./scripts/production_config_gate.sh /etc/opendr/provider/server.toml
./scripts/production_config_gate.sh /etc/opendr/consumer/server.toml
```

**Prerequisites**:
- Python 3.11 or newer uses the standard-library `tomllib` parser. Older
  Python 3 runtimes use the script's fallback parser for the simple OpenDR
  server TOML shape checked by this gate.

### tls_rotation_gate.sh

**Purpose**: Production-readiness TLS certificate rotation gate. The script
starts an isolated OpenDR server, rotates temporary certificate material, and
proves the documented restart-required rotation model for LDAPS and StartTLS.

**What it covers**:
1. LDAPS and StartTLS bind/search succeeds with the active trust anchor.
2. LDAPS and StartTLS fails with the inactive or stale trust anchor.
3. Replacing `tls.cert_file` and `tls.key_file` while the process is running
   does not hot reload the certificate.
4. Restarting OpenDR activates the new certificate for new LDAPS connections
   and new StartTLS upgrades.

**Usage**:
```bash
TLS_ROTATION_ARTIFACT_DIR=target/tls-rotation-gate/readiness-smoke \
./scripts/tls_rotation_gate.sh
```

Use `TLS_ROTATION_PYTHON=/path/to/venv/bin/python` when `ldap3` is installed in
a virtual environment.

For release evidence:

```bash
TLS_ROTATION_ARTIFACT_DIR=target/tls-rotation-gate/release-candidate \
./scripts/tls_rotation_gate.sh
```

**Artifacts**:
- Summary: `target/tls-rotation-gate/.../summary.md`
- Server logs: `target/tls-rotation-gate/.../logs/server-*.log`
- LDAP client logs: `target/tls-rotation-gate/.../logs/*LDAPS*.log` and
  `target/tls-rotation-gate/.../logs/*StartTLS*.log`
- Temporary test certificates and keys:
  `target/tls-rotation-gate/.../generated-certs/`

**Prerequisites**:
- Rust and Cargo.
- Python 3 with the `ldap3` package for client validation and local port
  allocation.
- `openssl`.

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
1. LDAP operation latency, throughput, success counts, failure counts, and failure rate for bind, search, compare, modify, password modify, add, modifyDN, and delete
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
5. Captures latency, throughput, failure rate, CPU, memory, database size, record-count, and concurrent bind artifacts per run
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

# Targeted auth-concurrency comparison for high-login workloads
./scripts/perf_docker_matrix.sh \
  --profile-set concurrency \
  --concurrent-bind-clients 1,4,8,16,32,64,128 \
  --concurrent-bind-iterations 100 \
  --concurrent-bind-valid-percent 90 \
  --concurrent-bind-wrong-password-percent 5 \
  --concurrent-bind-hot-user-percent 80 \
  --concurrent-bind-hot-user-count 100 \
  --concurrent-bind-operation-timeout-ms 5000

# SASL PLAIN fixture-user comparison
./scripts/perf_docker_matrix.sh \
  --profile-set sasl \
  --products opendr,opendj \
  --sasl-plain-authcid-format rdn-value \
  --skip-sasl-plain-admin-benchmark \
  --concurrent-bind-clients 1,4,8,16,32,64,128

# CI-friendly OpenDR regression profile with 100k fixture users
./scripts/perf_docker_matrix.sh \
  --products opendr \
  --profile-set regression \
  --output-dir target/perf/regression-candidate
```

**Profiles**:
- `smoke`: very small validation run
- `standard`: light, moderate, heavy
- `full`: light, moderate, heavy, stress
- `concurrency`: single `auth-concurrency` profile for focused concurrent bind comparison
- `index`: single `index` profile for equality, presence, substring, ordering, and concurrent mixed index-search probes
- `sasl`: single `sasl-auth` profile for SASL PLAIN fixture-user bind latency and concurrent throughput/failure probes
- `regression`: single `regression-100k` profile for OpenDR perf gates with a 100k fixture, indexed probes, and moderate concurrent bind/index-search levels
- `ldapcon-ten-million`: OpenDR 10M LDAPCon-style profile with shared client levels `8,128,256,1000`
- `ldapcon-openldap-ten-million`: OpenDR 10M LDAPCon-style profile shaped like the public LDAPCon 2013 OpenLDAP LMDB rows, using search `96`, auth `84`, modify `8`, and mixed `96` clients

**Key options**:
- `--cpu`: container CPU limit, default `2`
- `--memory`: container memory limit, default `4g`
- `--benchmark-timeout`: per-profile timeout budget in seconds, default `180`
- `--concurrent-bind-clients`: comma-separated concurrent bind client levels, default disabled except `--profile-set concurrency`
- `--concurrent-bind-iterations`: bind operations per concurrent client level, default `20`
- `--concurrent-bind-warmup-iterations`: warmup binds per concurrent client before timed measurement, default `1`
- `--concurrent-bind-operation-timeout-ms`: timeout for each concurrent probe connect or bind operation, default `5000`
- `--concurrent-bind-valid-percent`: percent of auth-concurrency attempts using valid credentials, default `100`
- `--concurrent-bind-wrong-password-percent`: percent of auth-concurrency attempts using wrong passwords; the remainder is unknown DN, default `0`
- `--concurrent-bind-hot-user-percent`: percent of auth-concurrency attempts targeting the hot-user set, default `80`
- `--concurrent-bind-hot-user-count`: number of hot users used by the auth-concurrency distribution, default `1`
- `--sasl-plain-benchmark`: enable serial and, when concurrent bind clients are configured, concurrent SASL PLAIN fixture-user bind probes
- `--sasl-plain-authcid-format`: SASL PLAIN authcid format, `dn` or `rdn-value`; use `rdn-value` for the OpenDJ fixture-user comparison
- `--skip-sasl-plain-admin-benchmark`: skip the admin/root SASL PLAIN probe for products that do not accept SASL PLAIN for the directory-manager account
- `--ldapcon-clients`: shared LDAPCon-style client levels used for search, auth, modify, and mixed probes
- `--ldapcon-search-clients`, `--ldapcon-auth-clients`, `--ldapcon-modify-clients`, `--ldapcon-mixed-clients`: operation-specific LDAPCon-style client levels; unset operations fall back to `--ldapcon-clients`
- `--products`: comma-separated subset of `opendr,opendj`

**Artifacts**:
- Matrix summary: `target/perf/.../comparison-summary.md`
- Matrix CSV: `target/perf/.../comparison-summary.csv`
- Per-run report: `target/perf/.../<product>/<profile>/report.md`
- Per-run raw metrics: `target/perf/.../<product>/<profile>/ldap-benchmark-results.json`
- Per-run container stats: `target/perf/.../<product>/<profile>/container-stats-summary.json`
- Per-run status: `target/perf/.../<product>/<profile>/run-status.json`

### perf_regression_gate.sh

**Purpose**: Production-readiness wrapper for LDAP load and performance
regression validation.

**What it does**:
1. `PERF_GATE_MODE=smoke` runs a small isolated LMDB benchmark through
   `perf_single_instance_lmdb.sh`.
2. Smoke mode enforces a maximum failure rate and optional p95 latency
   threshold against the generated `ldap-benchmark-results.json`.
3. `PERF_GATE_MODE=release` runs the Docker `regression` profile through
   `perf_docker_matrix.sh`.
4. Release mode requires `PERF_GATE_BASELINE_JSON` by default and uses
   `compare_perf_run.py` to fail when throughput, latency, or failure-rate
   metrics regress beyond `PERF_GATE_THRESHOLD_PERCENT`.

**Usage**:
```bash
# Fast local smoke gate
PERF_GATE_MODE=smoke \
PERF_GATE_OUTPUT_DIR=target/perf/readiness-smoke \
./scripts/perf_regression_gate.sh

# Release-candidate regression gate
PERF_GATE_MODE=release \
PERF_GATE_BASELINE_JSON=target/perf/regression-baseline/opendr/regression-100k/ldap-benchmark-results.json \
PERF_GATE_OUTPUT_DIR=target/perf/regression-candidate \
./scripts/perf_regression_gate.sh
```

**Artifacts**:
- Smoke report: `target/perf/.../perf-smoke-gate-report.md`
- Smoke raw metrics: `target/perf/.../smoke-single-instance/ldap-benchmark-results.json`
- Release comparison report: `target/perf/.../perf-regression-report.md`
- Release matrix artifacts under `target/perf/.../regression-candidate`

### backup_restore_drill.sh

**Purpose**: Production-readiness backup/restore drill for LMDB deployments.

**What it does**:
1. Builds the OpenDR server, setup, backup, restore, and fixture-loader
   binaries.
2. Creates an isolated LMDB fixture with indexed LDAP users.
3. Runs a full backup, backup inspect, restore dry-run, and clean restore.
4. Starts a restored OpenDR instance and validates admin bind, fixture user
   bind, base-object search, indexed `uid` and `mail` searches, objectClass
   count, operational attributes, and contextCSN evidence.

**Usage**:
```bash
# Fast local smoke drill
BACKUP_DRILL_MODE=smoke \
BACKUP_DRILL_USERS=50 \
BACKUP_DRILL_OUTPUT_DIR=target/backup-restore-drill/readiness-smoke \
./scripts/backup_restore_drill.sh

# Release-candidate drill
BACKUP_DRILL_MODE=release \
BACKUP_DRILL_USERS=100000 \
BACKUP_DRILL_OUTPUT_DIR=target/backup-restore-drill/release-candidate \
./scripts/backup_restore_drill.sh
```

**Artifacts**:
- Drill summary: `target/backup-restore-drill/.../summary.md`
- Full backup: `target/backup-restore-drill/.../full-backup`
- Command and server logs: `target/backup-restore-drill/.../logs`
- Validation LDIF and contextCSN evidence:
  `target/backup-restore-drill/.../validation`

### deployment_rollback_drill.sh

**Purpose**: Production-readiness deployment rollback drill for a provider and
consumer pair.

**What it does**:
1. Builds the OpenDR server, setup, backup, and restore binaries.
2. Starts an isolated provider and consumer with separate LMDB data and
   replication state directories.
3. Adds a baseline entry, takes a provider full backup, and validates backup
   inspect plus restore dry-run.
4. Adds a failed-deployment marker and proves it replicates to the consumer.
5. Stops both nodes, moves failed data and replication state aside, restores the
   provider backup, and reboots the consumer from a clean state.
6. Verifies the baseline entry exists, the failed marker is absent, and a new
   post-rollback entry replicates live.

**Usage**:
```bash
# Fast local smoke drill
DEPLOYMENT_DRILL_OUTPUT_DIR=target/deployment-rollback-drill/readiness-smoke \
./scripts/deployment_rollback_drill.sh

# Release-candidate drill
DEPLOYMENT_DRILL_MODE=release \
DEPLOYMENT_DRILL_OUTPUT_DIR=target/deployment-rollback-drill/release-candidate \
./scripts/deployment_rollback_drill.sh
```

**Artifacts**:
- Drill summary: `target/deployment-rollback-drill/.../summary.md`
- Provider backup: `target/deployment-rollback-drill/.../provider-full-backup`
- Failed data and replication state moved aside under the artifact directory
- Command and server logs: `target/deployment-rollback-drill/.../logs`
- Validation LDIF files: `target/deployment-rollback-drill/.../validation`

### fuzz_gate.sh

**Purpose**: Production-readiness fuzz wrapper for LDAP BER parsing and request
handling.

**What it does**:
1. Runs `ber_decoder` and `ldap_request_handler` through `cargo-fuzz`.
2. Uses the pinned `nightly-2026-03-01` toolchain.
3. Supports short smoke runs for local/CI validation.
4. Supports release-candidate runs with a long per-target time budget or run
   count.
5. Captures logs, corpus, dictionaries, crash artifacts, and reproduction
   commands under one output directory.

**Usage**:
```bash
# Fast local smoke gate
FUZZ_GATE_MODE=smoke \
FUZZ_GATE_OUTPUT_DIR=target/fuzz-gate/readiness-smoke \
./scripts/fuzz_gate.sh

# Release-candidate gate: six hours per target by default
FUZZ_GATE_MODE=release \
FUZZ_GATE_OUTPUT_DIR=target/fuzz-gate/release-candidate \
./scripts/fuzz_gate.sh

# Release-candidate gate using a run-count budget instead
FUZZ_GATE_MODE=release \
FUZZ_GATE_RELEASE_RUNS=1000000 \
FUZZ_GATE_RELEASE_MAX_TOTAL_TIME_SECS= \
FUZZ_GATE_OUTPUT_DIR=target/fuzz-gate/release-candidate \
./scripts/fuzz_gate.sh
```

**Prerequisites**:
```bash
rustup toolchain install nightly-2026-03-01 --profile minimal
cargo install cargo-fuzz --locked
```

**Artifacts**:
- Summary and reproduction commands: `target/fuzz-gate/.../summary.md`
- Per-target logs: `target/fuzz-gate/.../logs/<target>.log`
- Per-target corpus: `target/fuzz-gate/.../corpus/<target>/`
- Crash/timeout artifacts: `target/fuzz-gate/.../artifacts/<target>/`
- Dictionaries used by the run: `target/fuzz-gate/.../dictionaries/`

See `docs/FUZZING.md` for failure triage and minimization commands.

### compare_perf_run.py

**Purpose**: Compare two `ldap_perf_client` JSON reports and fail when key
metrics regress beyond a configured threshold. Use this with the `regression`
profile or a preserved 1M fixture; do not make CI depend on the 10M artifact.

**Usage**:
```bash
python3 scripts/compare_perf_run.py \
  --baseline-json target/perf/regression-baseline/opendr/regression-100k/ldap-benchmark-results.json \
  --candidate-json target/perf/regression-candidate/opendr/regression-100k/ldap-benchmark-results.json \
  --threshold-percent 10 \
  --report-out target/perf/regression-candidate/perf-regression-report.md
```

The default comparison checks successful throughput, mean latency, p95 latency,
and failure rate for operations present in both reports. `ldap_perf_client`
also emits `failure_reasons` buckets for concurrent and LDAPCon-style rows so
c128/c256/c1000 failures can be separated into timeout, worker, and operation
failure categories.

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

# OpenDR E2E Replication Tests

Comprehensive end-to-end test suite for validating LDAP replication scenarios in OpenDR.

## Overview

This test suite validates the complete replication functionality of OpenDR LDAP server, including:

- **Basic replication**: ADD, MODIFY, DELETE operations
- **Multi-consumer scenarios**: One provider serving multiple consumers
- **Failover testing**: Provider and consumer restart/recovery scenarios
- **Performance measurement**: Replication lag under various configurations
- **Conflict resolution**: Divergence and synchronization behavior
- **State management**: Cookie persistence and full resynchronization

## Requirements

### System Requirements
- **OS**: macOS (tests are optimized for macOS/zsh)
- **Shell**: zsh 5.x or later
- **Rust**: 1.70+ (for building the server)

### Tool Dependencies

Install required LDAP client tools:

```bash
# Install OpenLDAP client tools
brew install openldap

# Optional: Install jq for JSON parsing (future use)
brew install jq
```

Verify installation:

```bash
ldapsearch -V
ldapadd -V
nc -h
```

## Quick Start

### Run All Tests

```bash
# From project root
./e2e_tests/run_all.sh
```

### Run a Single Test

```bash
# Basic replication test
./e2e_tests/test_single_provider_single_consumer.sh

# Schema management test
./e2e_tests/test_schema_management.sh

# Multi-consumer test
./e2e_tests/test_multi_consumer.sh

# Failover tests
./e2e_tests/test_provider_failover.sh
./e2e_tests/test_consumer_failover.sh
```

## Configuration

All tests support environment variable overrides for customization:

### Server Configuration

```bash
# Specify custom server binary
export SERVER_BIN=/path/to/custom/opendr

# Or let the tests find/build automatically
unset SERVER_BIN
```

### Port Configuration

```bash
# Override default ports (useful to avoid conflicts)
export PROVIDER_PORT=4000
export CONSUMER_PORT=4001

# For multi-consumer tests
export CONSUMER_PORTS="4001 4002 4003"
```

### LDAP Configuration

```bash
# Custom base DN
export BASE_DN="dc=myorg,dc=com"
export BIND_DN="cn=admin,dc=myorg,dc=com"
export BIND_PW="mypassword"
```

### Replication Tuning

```bash
# Sync interval (seconds)
export SYNC_INTERVAL_SECS=10

# Batch size for replication
export BATCH_SIZE=200

# Timeout for replication operations
export REPL_TIMEOUT_SECS=60
```

### Debugging

```bash
# Enable debug logging
export DEBUG=1

# Keep temporary files after test (for inspection)
export RUN_ROOT=/tmp/my_test_dir
# (Note: Auto-cleanup will be skipped if you set this manually)
```

## Test Descriptions

### test_single_provider_single_consumer.sh

**Purpose**: Validate basic replication operations

**Tests**:
- ADD: Creates 5 entries on provider, verifies on consumer
- MODIFY: Updates 2 entries, verifies changes replicate
- DELETE: Removes 1 entry, verifies deletion replicates

**Duration**: ~30-45 seconds

**Example**:
```bash
./e2e_tests/test_single_provider_single_consumer.sh
```

### test_replication_soak.sh

**Purpose**: Validate sustained provider-consumer convergence over repeated
LDAP writes.

**Tests**:
- Starts one provider and one consumer in isolated temporary directories
- Repeatedly adds batches of `inetOrgPerson` entries to the provider
- Modifies recently added entries and waits for replicated attributes
- Periodically deletes the oldest active entries and waits for deletion on the
  consumer
- Verifies provider and consumer entry counts during the run and at the end
- Writes a summary plus provider/consumer logs/configs to an artifact directory

**Default duration**: 60 seconds

**Smoke example**:
```bash
SOAK_DURATION_SECS=15 \
SOAK_BATCH_SIZE=2 \
SOAK_DELETE_EVERY_ROUNDS=1 \
SOAK_MIN_ACTIVE_BEFORE_DELETE=1 \
./e2e_tests/test_replication_soak.sh
```

**Release-candidate example**:
```bash
SOAK_DURATION_SECS=86400 \
SOAK_BATCH_SIZE=10 \
SOAK_ARTIFACT_DIR=target/replication-soak/release-candidate \
./e2e_tests/test_replication_soak.sh
```

The release-candidate run should retain `summary.txt`, server logs, and
generated configs from `SOAK_ARTIFACT_DIR` with the release evidence.

### test_replication_failure_drills.sh

**Purpose**: Validate operator recovery paths for provider/consumer failures and
stale replication state.

**Tests**:
- Provider restart with persisted backend and changelog state
- Consumer restart with persisted cookie resume
- Provider network interruption while the consumer keeps running
- Stale consumer cookie with a truncated provider changelog
- Operator recovery by deleting the stale consumer cookie and forcing a full
  refresh

**Default mode**: `smoke`

**Smoke example**:
```bash
FAILURE_DRILL_MODE=smoke \
FAILURE_DRILL_ARTIFACT_DIR=target/replication-failure-drills/local-smoke \
./e2e_tests/test_replication_failure_drills.sh
```

**Release-candidate example**:
```bash
FAILURE_DRILL_MODE=release \
FAILURE_DRILL_ARTIFACT_DIR=target/replication-failure-drills/release-candidate \
./e2e_tests/test_replication_failure_drills.sh
```

The release-candidate run should retain `summary.txt`, server logs, consumer
cookies, and provider changelog excerpts from `FAILURE_DRILL_ARTIFACT_DIR`.

### test_schema_management.sh

**Purpose**: Validate schema definition and validation behavior through LDAP clients

**Tests**:
- CLI validation and explanation of startup-loaded external schema definitions
- Schema-aware index config rejection for unknown attributes
- `cn=Subschema` publication of custom attribute types, object classes, matching rules, content rules, name forms, and structure rules
- ADD validation for required attributes, syntax checks, single-value attributes, allowed attribute sets, and DIT content rules
- MODIFY validation against the post-modification entry image
- ModifyDN validation against name-form RDN rules
- Authenticated online schema additions persisted to `99-online.ldif`
- Restart reload of online schema definitions

**Duration**: ~30-60 seconds

**Example**:
```bash
./e2e_tests/test_schema_management.sh
```

### test_multi_consumer.sh

**Purpose**: Validate one provider serving multiple consumers

**Tests**:
- Simultaneous replication to 3 consumers
- Independent catch-up when one consumer is offline
- Cookie persistence and incremental sync

**Duration**: ~60-90 seconds

**Example**:
```bash
CONSUMER_PORTS="3891 3892 3893" ./e2e_tests/test_multi_consumer.sh
```

### test_provider_failover.sh

**Purpose**: Validate provider crash/restart scenarios

**Tests**:
- Provider restarts with same data directory
- Consumer reconnects automatically
- Replication continues after provider recovery

**Duration**: ~45-60 seconds

**Example**:
```bash
./e2e_tests/test_provider_failover.sh
```

### test_consumer_failover.sh

**Purpose**: Validate consumer catch-up after downtime

**Tests**:
- Consumer offline while provider receives writes
- Consumer restarts and catches up
- All changes are eventually synchronized

**Duration**: ~45-60 seconds

**Example**:
```bash
./e2e_tests/test_consumer_failover.sh
```

### test_replication_lag.sh

**Purpose**: Measure replication performance

**Tests**:
- Various sync intervals (5s, 30s, 60s)
- Various batch sizes (50, 100, 500)
- Outputs CSV with timing metrics

**Duration**: ~3-5 minutes

**Output**: `${RUN_ROOT}/lag_results.csv`

**Example**:
```bash
SYNC_INTERVALS="5 15 30" BATCH_SIZES="100 200" ./e2e_tests/test_replication_lag.sh
```

### test_conflict_resolution.sh

**Purpose**: Test divergence and conflict scenarios

**Tests**:
- Consumer divergence with replication disabled
- Provider-wins conflict resolution
- Changelog overflow handling

**Duration**: ~60-90 seconds

**Note**: Experimental; behavior depends on server implementation

### test_full_resync.sh

**Purpose**: Validate full refresh after state loss

**Tests**:
- Consumer loses replication state
- Full resynchronization occurs
- All data is recovered

**Duration**: ~45-60 seconds

## Directory Structure

```
e2e_tests/
├── README.md                                 # This file
├── helpers.sh                                # Shared utility library
├── test_single_provider_single_consumer.sh  # Basic replication
├── test_replication_soak.sh                 # Sustained convergence
├── test_replication_failure_drills.sh       # Failure and recovery drills
├── test_multi_consumer.sh                   # Multi-consumer
├── test_provider_failover.sh                # Provider restart
├── test_consumer_failover.sh                # Consumer restart
├── test_replication_lag.sh                  # Performance metrics
├── test_conflict_resolution.sh              # Conflict handling
├── test_full_resync.sh                      # State recovery
└── run_all.sh                               # Run all tests
```

## Troubleshooting

### Tests Fail to Start

**Issue**: `Missing required tools`

**Solution**:
```bash
brew install openldap
```

### Port Already in Use

**Issue**: `Server 127.0.0.1:3890 not ready after 15s`

**Solution**: Override ports
```bash
PROVIDER_PORT=4000 CONSUMER_PORT=4001 ./e2e_tests/test_single_provider_single_consumer.sh
```

### Server Binary Not Found

**Issue**: `Unable to locate or build server binary`

**Solution**:
```bash
# Build the server first
cargo build --release

# Or specify path explicitly
SERVER_BIN=./target/release/opendr ./e2e_tests/test_single_provider_single_consumer.sh
```

### Replication Timeout

**Issue**: `Replication timeout: provider=5, consumer=3, expected=5`

**Possible causes**:
1. Network issues (unlikely on localhost)
2. Server performance (try increasing timeout)
3. Actual replication bug

**Solution**:
```bash
# Increase timeout
REPL_TIMEOUT_SECS=60 ./e2e_tests/test_single_provider_single_consumer.sh

# Enable debug logging
DEBUG=1 ./e2e_tests/test_single_provider_single_consumer.sh
```

### Inspecting Server Logs

Tests automatically dump server logs on failure. To manually inspect:

```bash
# Set a custom run directory
export RUN_ROOT=/tmp/my_opendr_test
./e2e_tests/test_single_provider_single_consumer.sh

# After test completes (or fails), check logs:
ls -la /tmp/my_opendr_test/
tail -f /tmp/my_opendr_test/provider/server.log
tail -f /tmp/my_opendr_test/consumer/server.log
```

## Configuration File Format

The tests generate TOML configuration files matching the OpenDR schema:

### Provider Config Example

```toml
[server]
bind_address = "127.0.0.1"
ldap_port = 3890
base_dn = "dc=example,dc=org"
root_user_dn = "cn=manager,dc=example,dc=org"
# E2E-only inline credential; production configs use root_password_file/env.
root_password = "admin"
organization_name = "Test Organization"

[backend]
backend_type = "lmdb"
data_directory = "/tmp/opendr_e2e.XXXXX/provider/data"
lmdb_max_size = 536870912
lmdb_max_readers = 126

[replication]
enabled = true
mode = "provider"
changelog_enabled = true
```

### Consumer Config Example

```toml
[server]
bind_address = "127.0.0.1"
ldap_port = 3891
base_dn = "dc=example,dc=org"
root_user_dn = "cn=manager,dc=example,dc=org"
# E2E-only inline credential; production configs use root_password_file/env.
root_password = "admin"
organization_name = "Test Organization"

[backend]
backend_type = "lmdb"
data_directory = "/tmp/opendr_e2e.XXXXX/consumer/data"
lmdb_max_size = 536870912
lmdb_max_readers = 126

[replication]
enabled = true
mode = "consumer"
provider_url = "ldap://127.0.0.1:3890"
sync_interval_secs = 5
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: E2E Replication Tests

on: [push, pull_request]

jobs:
  e2e-tests:
    runs-on: macos-latest
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Install dependencies
        run: |
          brew install openldap
      
      - name: Setup Rust
        uses: actions-rust-lang/setup-rust-toolchain@v1
      
      - name: Build server
        run: cargo build --release
      
      - name: Run E2E tests
        run: ./e2e_tests/run_all.sh
      
      - name: Upload artifacts on failure
        if: failure()
        uses: actions/upload-artifact@v3
        with:
          name: test-logs
          path: /tmp/opendr_e2e.*
```

## Development

### Adding New Tests

1. Create a new test script in `e2e_tests/`:
   ```bash
   cp test_single_provider_single_consumer.sh test_my_new_test.sh
   ```

2. Edit the script:
   - Update `begin_test` with name and description
   - Implement test logic using helper functions
   - Call `end_test` at the end

3. Make it executable:
   ```bash
   chmod +x e2e_tests/test_my_new_test.sh
   ```

4. Add to `run_all.sh` if desired

### Helper Functions

See `helpers.sh` for available functions:

- **Server management**: `build_server`, `start_server`, `stop_server`, `wait_for_server`
- **Config generation**: `create_provider_config`, `create_consumer_config`
- **LDAP operations**: `add_ldif`, `search_entry`, `verify_entry_exists`, `count_entries`
- **Replication**: `wait_for_replication`, `measure_replication_time`
- **Assertions**: `assert_eq`, `assert_true`
- **Logging**: `log_info`, `log_success`, `log_warning`, `log_error`, `log_step`, `log_debug`

## Contributing

When adding tests, ensure they:

1. Use the `helpers.sh` library
2. Support environment variable overrides
3. Clean up resources via `cleanup_all` (automatic via trap)
4. Provide clear, actionable error messages
5. Include detailed test descriptions in comments

## License

Same as OpenDR project

## Support

For issues or questions:
- Check the troubleshooting section above
- Review server logs in the run directory
- File an issue on GitHub with test output and logs

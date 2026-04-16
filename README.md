# OpenDR LDAP Server

A high-performance, production-ready LDAP v3 server implementation in Rust. The shipped `opendr` binary supports both the `fsm` and `legacy` runtimes; `fsm` is the default rollout path in `config/server.toml`.

## Features

### Core LDAP Operations
- ✅ **LDAP v3 Protocol**: Full RFC 4511 compliance
- ✅ **Authentication**: Simple bind, SASL (PLAIN, DIGEST-MD5, CRAM-MD5)
- ✅ **Operations**: Search, Add, Modify, Delete, ModifyDN, Compare
- ✅ **Extended Operations**: StartTLS, Password Modify, WhoAmI, Cancel
- ✅ **Controls**: Paged results, server-side sorting, persistent search

### Storage & Performance
- ✅ **LMDB Backend**: Memory-mapped I/O for ultra-fast reads (1.17 µs)
- ✅ **Attribute Indexing**: Configurable indexes for fast searches
- ✅ **Schema Validation**: RFC 4512 compliant schema enforcement
- ✅ **ACID Transactions**: Full transactional safety with crash recovery

### Security
- ✅ **TLS/SSL**: TLS 1.2/1.3 support with certificate validation
- ✅ **Access Control**: Fine-grained ACI (Access Control Information) system
- ✅ **Rate Limiting**: Per-client and global rate limiting with DoS protection
- ✅ **Audit Logging**: Comprehensive security event logging (JSON, syslog, text)

### Replication ⭐ NEW
- ✅ **RFC 4533 Alignment**: LDAP Content Synchronization semantics for refresh and persist phases
- ✅ **Provider-Consumer**: Master-slave replication with automatic changelog tracking
- ✅ **Multi-Master**: Bidirectional replication (both mode)
- ✅ **Cookie-Based Resume**: Consumers can resume from last known state
- ✅ **Real-Time Updates**: Listening-based change delivery after the initial refresh
- ✅ **State Persistence**: Automatic state saving for reliable recovery

### Enterprise Features
- ✅ **Referrals & Chaining**: Distributed directory support (RFC 4516)
- ✅ **Monitoring**: Prometheus-compatible metrics export
- ✅ **Health Checks**: Component-level health status with JSON export
- ✅ **Resource Management**: Connection pooling, memory limits, idle timeout
- ✅ **Graceful Shutdown**: Signal handling with connection draining

### Operations
- ✅ **Configuration**: TOML files with environment variable overrides
- ✅ **Service Management**: systemd integration with automatic restart
- ✅ **Performance Tuning**: Configurable worker threads, cache sizes, timeouts
- ✅ **Comprehensive Testing**: 433 tests with 97%+ pass rate

## Quick Start

### Prerequisites

```bash
# LDAP client tools (for testing)
# Ubuntu/Debian
sudo apt-get install ldap-utils

# macOS
brew install openldap

# RHEL/CentOS
sudo yum install openldap-clients
```

### Operator Path

Use this path for a new install or a fresh validation run:

1. Set up the runtime with `opendr-setup --config-dir ./config interactive`.
2. Review `config/server.toml`, TLS material, replication settings, and index settings.
3. Start the server with `opendr --config ./config/server.toml --log-config ./config/log4rs.yml`.
4. Validate bind, search, add, modify, delete, StartTLS, and monitoring endpoints.
5. Maintain the instance with systemd, logs, backup/restore, rollback, and index rebuilds.
6. Prove release readiness with the gates in `docs/PRODUCTION_READINESS_CHECKLIST.md`.

### Set Up OpenDR

```bash
mkdir -p ./config ./logs
opendr-setup --config-dir ./config interactive
```

The setup wizard writes `config/server.toml`, setup state, LDIF scaffolding,
and the configured data directories. Provide a log4rs YAML file at
`config/log4rs.yml`, or point `--log-config` at the packaged logging config.

### Run OpenDR

```bash
opendr --config ./config/server.toml --log-config ./config/log4rs.yml
```

### Test Operations

```bash
# Search
ldapsearch -x -H ldap://127.0.0.1:1389 \
  -D "cn=admin,dc=example,dc=com" -w "$OPENDR_ADMIN_PASSWORD" \
  -b "dc=example,dc=com" "(objectClass=*)"

# Add entry
ldapadd -x -H ldap://127.0.0.1:1389 \
  -D "cn=admin,dc=example,dc=com" -w "$OPENDR_ADMIN_PASSWORD" <<EOF
dn: cn=John Doe,dc=example,dc=com
objectClass: person
cn: John Doe
sn: Doe
EOF

# Modify entry
ldapmodify -x -H ldap://127.0.0.1:1389 \
  -D "cn=admin,dc=example,dc=com" -w "$OPENDR_ADMIN_PASSWORD" <<EOF
dn: cn=John Doe,dc=example,dc=com
changetype: modify
add: description
description: Test user
EOF

# Delete entry
ldapdelete -x -H ldap://127.0.0.1:1389 \
    -D "cn=admin,dc=example,dc=com" -w "$OPENDR_ADMIN_PASSWORD" \
    "cn=John Doe,dc=example,dc=com"
```

### Build From Source

Use this path only when developing OpenDR or testing a local branch.

```bash
# Rust 1.70+
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

git clone https://github.com/keaz/opendr.git
cd opendr
cargo build --release

./target/release/opendr-setup --config-dir ./config interactive
./target/release/opendr \
  --config ./config/server.toml \
  --log-config ./config/log4rs.yml
```

## Replication Quick Start

OpenDR supports provider-consumer replication for high availability and load distribution.
After the initial refresh, consumers keep a live LDAP search open for change delivery. Poll-based consumer replication has been removed; `enable_change_listening` must be `true` for `consumer` and `both` modes.
The canonical runtime keys are `mode`, `bind_dn`, `bind_password`, `changelog_capacity`, and `enable_change_listening`. Current `opendr-setup` output writes those canonical keys in `server.toml`; if you are using config generated by older setup builds, normalize legacy replication keys such as `role`, `provider_bind_dn`, or `changelog_max_entries` before launching the binary.

### 1. Create Per-Instance Runtime Directories

The `opendr` binary loads `config/server.toml` and `config/log4rs.yml` from its current working directory.
Run each instance from its own directory so the provider and consumer do not share ports, logs, or data files.

```
/srv/opendr-provider/
  config/server.toml
  config/log4rs.yml
  data/
  log/

/srv/opendr-consumer/
  config/server.toml
  config/log4rs.yml
  data/
  log/
```

### 2. Configure the Provider

Place this in `/srv/opendr-provider/config/server.toml`:

```toml
[server]
bind_address = "0.0.0.0"
ldap_port = 1389
replica_id = 1
base_dn = "dc=example,dc=com"
root_user_dn = "cn=manager"
root_password_file = "/run/secrets/opendr-provider-root-password-hash"
organization_name = "Example Org"

[backend]
backend_type = "lmdb"
data_directory = "./data"
lmdb_max_size = 10737418240
lmdb_max_readers = 126

[replication]
enabled = true
mode = "provider"
changelog_capacity = 100000
heartbeat_interval_secs = 60
```

### 3. Configure the Consumer

Place this in `/srv/opendr-consumer/config/server.toml`:

```toml
[server]
bind_address = "0.0.0.0"
ldap_port = 2389
replica_id = 2
base_dn = "dc=example,dc=com"
root_user_dn = "cn=manager"
root_password_file = "/run/secrets/opendr-consumer-root-password-hash"
organization_name = "Example Org Replica"

[backend]
backend_type = "lmdb"
data_directory = "./data"
lmdb_max_size = 10737418240
lmdb_max_readers = 126

[replication]
enabled = true
mode = "consumer"
provider_url = "ldap://provider-server:1389"
bind_dn = "cn=manager,dc=example,dc=com"
bind_password_file = "/run/secrets/opendr-replication-bind-password"
max_retry_attempts = 3
retry_delay_secs = 5
enable_change_listening = true
heartbeat_interval_secs = 60
state_storage_path = "./data/replication_state"
```

`bind_dn` and `bind_password` are the canonical consumer authentication keys. `provider_bind_dn` and `provider_bind_password` are still accepted as aliases. In production, point them at a dedicated read-only replication account on the provider and inject the actual secret with `bind_password_env` or `bind_password_file`. `replica_id` must be unique per replicated node so CSNs remain globally ordered.

The minimal runtime config surface for a quick start uses the block shown above. Current `opendr-setup` output is also loadable by the shipped runtime and includes additional supported defaults such as `changelog_enabled`, `max_batch_size`, `enable_streaming`, and TLS fields when relevant. TLS setup expects the configured certificate, key, and optional CA files to exist before the server starts.

### 4. Start Both Servers

```bash
cp config/log4rs.yml /srv/opendr-provider/config/log4rs.yml
cp config/log4rs.yml /srv/opendr-consumer/config/log4rs.yml

cd /srv/opendr-provider && opendr
cd /srv/opendr-consumer && opendr
```

For LMDB-backed instances, generate the `{SSHA512}` root password with `opendr-setup` or reuse the generated hash from an existing server config, then mount it through `root_password_file` or export it via `root_password_env`.

LMDB index configuration supports the legacy shortcut and typed indexes. `indexed_attributes = ["cn", "uid"]` maintains equality and presence keys. Use typed entries when a custom attribute needs substring or ordering candidates:

```toml
[backend]
indexed_attributes = ["cn", "uid", "mail", "objectClass", "ou"]

[[backend.indexes]]
attribute = "cn"
types = ["substring"]

[[backend.indexes]]
attribute = "entryCSN"
types = ["ordering"]
```

When a new index is configured after data already exists, the LMDB backend rebuilds the configured attribute index keys during startup without modifying LDAP entries, operational attributes, or CSNs. Attribute indexes use `idx3_<attribute>` databases with fixed-width duplicate LMDB values, storing compact entry IDs instead of repeating full DNs in every index row. Legacy DN-key and `idx2_*` index databases are cleared during rebuild so LMDB can reuse those pages. Approximate-match filters currently use the equality index path because OpenDR's approximate-match semantics are case-insensitive equality.

For bind-heavy workloads, LMDB stores compact decoded SSHA512 hash/salt records in `credentials_by_entry_id`, keyed by the same 8-byte entry IDs used by the primary entry table and attribute indexes. Fresh stores no longer populate the legacy `passwords`, `dn_index`, or `credentials_by_normalized_dn` databases.

### 5. Verify Listener-Based Replication

Add data to the provider:

```bash
ldapadd -x -H ldap://provider-server:1389 \
  -D "cn=manager,dc=example,dc=com" -w '<provider-root-password>' <<EOF
dn: uid=replication-test,ou=People,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: replication-test
sn: Test
uid: replication-test
EOF
```

Verify on the consumer:

```bash
ldapsearch -x -H ldap://consumer-server:2389 \
  -D "cn=manager,dc=example,dc=com" -w '<consumer-root-password>' \
  -b "ou=People,dc=example,dc=com" "(uid=replication-test)"
```

Listener mode is active when the consumer logs `Replication consumer entered listening mode` and subsequent writes produce `Replicated ADD:` / `Replicated MODIFY:` immediately over the live stream.

### Run Demo Script

```bash
# Automated replication demo
./scripts/demo_replication.sh

# Keep servers running for testing
./scripts/demo_replication.sh --keep-running

# Skip build step
./scripts/demo_replication.sh --skip-build
```

## Documentation

### Core Documentation
- [Documentation Website](https://keaz.github.io/opendr/) - GitHub Pages developer documentation
- [Documentation Site Source](site/) - React and Vite source for the GitHub Pages site
- [Developer Operations Guide](docs/DEVELOPER_GUIDE.md) - Setup, runtime, TLS, replication, indexing, backup, and troubleshooting
- [Production Readiness Checklist](docs/PRODUCTION_READINESS_CHECKLIST.md) - Canonical release gates, commands, and artifact paths
- [Architecture Overview](docs/architecture-overview.md) - Current runtime and component architecture
- [Configuration Guide](docs/CONFIGURATION.md) - Complete runtime configuration reference
- [Performance Comparison](docs/PERFORMANCE_COMPARISON.md) - Benchmark methodology and retained comparison artifacts
- [LDAP RFC Compliance Matrix](docs/LDAP_RFC_COMPLIANCE_MATRIX.md) - Protocol coverage and advertised capabilities

### Replication
- [Replication Guide](docs/REPLICATION_GUIDE.md) - Listener-based replication setup and verification
- [Consumer FSM](docs/replication_consumer_fsm.md) - Consumer replication state machine details
- [Replication Production Guarantees](docs/REPLICATION_PRODUCTION_GUARANTEES.md) - Failure modes, audit expectations, and operational guarantees

### Operations
- [Troubleshooting](docs/TROUBLESHOOTING.md) - Startup, bind, search, TLS, replication, backup, and monitoring diagnostics
- [Backup and Restore](docs/BACKUP_RESTORE.md) - Online LMDB backup and offline restore runbook
- [TLS Rotation](docs/TLS_ROTATION.md) - Restart-required certificate rotation procedure and validation gate
- [Fuzzing](docs/FUZZING.md) - Smoke and release fuzz budgets with artifact retention
- [Deployment Runbook](docs/DEPLOYMENT_RUNBOOK.md) - Release rollback and incident response procedure
- [GitHub Pages Deployment](docs/GITHUB_PAGES.md) - Publishing the Vite docs site with GitHub Actions

### Development
- [FSM Architecture](docs/README.md) - Finite state machine design

## Configuration

### Basic Configuration

```toml
[server]
bind_address = "0.0.0.0"
ldap_port = 389
replica_id = 1
base_dn = "dc=example,dc=com"
root_user_dn = "cn=manager"
root_password_file = "/run/secrets/opendr-root-password-hash"
organization_name = "Example Org"

[backend]
backend_type = "lmdb"
data_directory = "/var/lib/opendr/data"
lmdb_max_size = 10737418240  # 10GB
lmdb_max_readers = 126

[tls]
enabled = true
cert_file = "/etc/opendr/cert.pem"
key_file = "/etc/opendr/key.pem"
min_tls_version = "1.2"

[replication]
enabled = true
mode = "provider"  # or "consumer" or "both"
changelog_capacity = 100000

[monitoring]
enabled = true
metrics_port = 9090
console_enabled = true
console_path = "/console"

[rate_limit]
enabled = true
per_client_requests_per_second = 100
```

### Example Configurations

- [Provider Configuration](config/examples/replication/provider.toml)
- [Consumer Configuration](config/examples/replication/consumer.toml)
- [Multi-Master Configuration](config/examples/replication/multi-master.toml)

### Environment Variables

Override any configuration value with environment variables:

```bash
OPENDR_SERVER__BIND_ADDRESS=0.0.0.0:389 \
OPENDR_REPLICATION__ENABLED=true \
OPENDR_REPLICATION__MODE=provider \
./target/release/opendr
```

## Performance

### Benchmarks

- **Read Operations**: 1.17 µs per entry lookup (LMDB)
- **Authentication**: 393 ns per SSHA512 password verification
- **Indexed Search**: < 10ms for 1000 entries
- **Concurrent Reads**: Up to 126 simultaneous readers
- **Replication**: < 1s sync latency for small datasets

### Optimization Tips

```toml
[performance]
indexing_enabled = true
cache_size = 50000           # Entry/auth credential cache capacity

[backend]
lmdb_max_size = 21474836480  # 20GB for large directories
lmdb_max_readers = 256       # Increase for high concurrency

[replication]
enable_change_listening = true
max_retry_attempts = 3
retry_delay_secs = 5
state_storage_path = "/var/lib/opendr/consumer/state"
```

See the [Developer Operations Guide](docs/DEVELOPER_GUIDE.md) and
[Configuration Guide](docs/CONFIGURATION.md) for runtime tuning details.

## Monitoring

### Prometheus Metrics

OpenDR exports Prometheus-compatible metrics:

```bash
curl http://localhost:9090/metrics
```

**Key Metrics:**
- `ldap_operations_total{operation="search"}` - Operation counts
- `ldap_operation_duration_seconds{operation="bind"}` - Latency
- `ldap_connections_active` - Active connections
- `ldap_replication_lag_seconds` - Replication lag
- `ldap_changelog_size` - Changelog entry count

### Health Checks

```bash
curl http://localhost:9090/health
```

Response:

```json
{
  "status": "healthy",
  "components": {
    "backend": "healthy",
    "replication_provider": "healthy",
    "replication_consumer": "healthy"
  },
  "uptime_seconds": 3600
}
```

### Management Console

OpenDR serves a read-only management console from the monitoring listener when
monitoring is enabled:

```bash
open http://127.0.0.1:9090/console
```

The console accepts the configured root DN and password, for example
`cn=admin,dc=example,dc=com` when `root_user_dn = "cn=admin"` and
`base_dn = "dc=example,dc=com"`. Sessions are process-local, use HttpOnly
SameSite cookies, and expire on restart or after the configured TTL.
See [`docs/MANAGEMENT_CONSOLE.md`](docs/MANAGEMENT_CONSOLE.md) for the endpoint
map, overview payload, and operating notes.

## Operations

Use the following commands for day-2 maintenance:

```bash
sudo systemctl stop opendr
sudo systemctl restart opendr
sudo systemctl status opendr
sudo journalctl -u opendr -f
```

Monitor the runtime through the health and metrics endpoints:

```bash
curl http://127.0.0.1:9090/health
curl http://127.0.0.1:9090/metrics
open http://127.0.0.1:9090/console
```

Back up and restore LMDB data with the dedicated tools:

```bash
opendr-backup --config /etc/opendr/server.toml full \
  --target /var/backups/opendr/full-20260412

opendr-backup inspect --backup /var/backups/opendr/full-20260412

opendr-restore \
  --backup /var/backups/opendr/full-20260412 \
  --target-data-dir /var/lib/opendr/data-restored \
  --dry-run
```

For rollback, stop the provider and consumers, restore the last known-good
provider backup, then re-bootstrap the consumers from a fresh full refresh.
See [`docs/DEPLOYMENT_RUNBOOK.md`](docs/DEPLOYMENT_RUNBOOK.md) for the full
procedure and [`docs/BACKUP_RESTORE.md`](docs/BACKUP_RESTORE.md) for the
backup and restore workflow.

Tune indexing in configuration, then restart the server to apply the new index
set:

```toml
[backend]
indexed_attributes = ["cn", "uid", "mail", "objectClass", "ou"]

[[backend.indexes]]
attribute = "exampleScore"
types = ["ordering"]
```

For production-readiness evidence, use
[`docs/PRODUCTION_READINESS_CHECKLIST.md`](docs/PRODUCTION_READINESS_CHECKLIST.md).

## Release Readiness

The table below records the release gates and the artifact locations used by the
current release candidate workflow. The main agent can update the status cells
after the long-running gates finish.

| Gate | Command | Status | Artifact |
| --- | --- | --- | --- |
| Performance regression `regression-100k` | `PERF_GATE_MODE=release PERF_GATE_BASELINE_JSON=target/perf/regression-baseline/opendr/regression-100k/ldap-benchmark-results.json PERF_GATE_OUTPUT_DIR=target/perf/regression-candidate ./scripts/perf_regression_gate.sh` | pending | `target/perf/regression-candidate/regression-candidate/comparison-summary.md` |
| 1-hour replication soak | `SOAK_DURATION_SECS=3600 SOAK_ARTIFACT_DIR=target/replication-soak/release-candidate ./e2e_tests/test_replication_soak.sh` | pending | `target/replication-soak/release-candidate/summary.txt` |
| Full release fuzz budget | `FUZZ_GATE_MODE=release FUZZ_GATE_OUTPUT_DIR=target/fuzz-gate/release-candidate ./scripts/fuzz_gate.sh` | pending | `target/fuzz-gate/release-candidate/summary.md` |
| TLS rotation | `TLS_ROTATION_ARTIFACT_DIR=target/tls-rotation-gate/release-candidate ./scripts/tls_rotation_gate.sh` | retained locally | `target/tls-rotation-gate/release-candidate/summary.md` |
| Failure drills | `FAILURE_DRILL_MODE=release FAILURE_DRILL_ARTIFACT_DIR=target/replication-failure-drills/release-candidate ./e2e_tests/test_replication_failure_drills.sh` | retained locally | `target/replication-failure-drills/release-candidate/summary.txt` |
| Backup/restore drill | `BACKUP_DRILL_MODE=release BACKUP_DRILL_USERS=100000 BACKUP_DRILL_OUTPUT_DIR=target/backup-restore-drill/release-candidate ./scripts/backup_restore_drill.sh` | retained locally | `target/backup-restore-drill/release-candidate/summary.md` |
| Deployment rollback drill | `DEPLOYMENT_DRILL_MODE=release DEPLOYMENT_DRILL_OUTPUT_DIR=target/deployment-rollback-drill/release-candidate ./scripts/deployment_rollback_drill.sh` | retained locally | `target/deployment-rollback-drill/release-candidate/summary.md` |

For the full release policy and pass criteria, keep `docs/PRODUCTION_READINESS_CHECKLIST.md`
as the source of truth. Use the retained artifacts in `target/` to update the
status column once the current long-running gates complete.

## Production Deployment

### systemd Service

Create `/etc/systemd/system/opendr.service`:

```ini
[Unit]
Description=OpenDR LDAP Server
After=network.target

[Service]
Type=simple
User=opendr
Group=opendr
WorkingDirectory=/etc/opendr
ExecStart=/usr/local/bin/opendr
Restart=always
RestartSec=10
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
```

Manage service:

```bash
sudo systemctl enable opendr
sudo systemctl start opendr
sudo systemctl status opendr
sudo journalctl -u opendr -f
```

### Security Hardening

```toml
[tls]
enabled = true
ca_file = "/etc/opendr/ca.pem"
require_client_cert = true
min_tls_version = "1.3"

[rate_limit]
enabled = true
global_requests_per_second = 10000
per_client_requests_per_second = 100
auto_ban_enabled = true
auto_ban_threshold = 1000
auto_ban_duration_secs = 3600

[access_control]
enabled = true
default_policy = "deny"
rules_file = "/etc/opendr/aci.toml"

[resources]
max_connections = 1000
max_connections_per_ip = 10
max_memory_per_connection = 10485760
connection_idle_timeout_secs = 300
```

Example `/etc/opendr/aci.toml`:

```toml
[[rules]]
name = "operators-search"
effect = "grant"
priority = 50
permissions = ["search"]
target = { subtree = "dc=example,dc=com" }
subject = { group = "cn=directory-operators,ou=groups,dc=example,dc=com" }

[[rules]]
name = "operators-read-visible-attrs"
effect = "grant"
priority = 40
permissions = ["read"]
target = { subtree = "dc=example,dc=com", attributes = ["cn", "mail", "objectClass"] }
subject = { group = "cn=directory-operators,ou=groups,dc=example,dc=com" }
```

## Testing

```bash
# Run all tests
cargo test

# Run replication tests only
cargo test replication

# Run integration tests
cargo test --test '*_integration'

# Run benchmarks
cargo bench

# Run E2E tests
cargo test --test e2e_tests
```

**Test Statistics:**
- 433 total tests
- 422 passing (97.5%)
- 84 replication-specific tests
- 100% pass rate for replication

## Architecture

OpenDR includes a **Finite State Machine (FSM)** architecture in the codebase, and the shipped `opendr` binary can run either the legacy runtime in `src/server.rs` or the FSM runtime in `src/fsm_server.rs`:

```
Client Connection
      │
      ▼
┌──────────────┐
│ Connection   │
│     FSM      │
└──────┬───────┘
       │
       ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│ BerDecoder   │───>│    Auth      │───>│  Operation   │
│     FSM      │    │     FSM      │    │     FSM      │
└──────────────┘    └──────────────┘    └──────┬───────┘
                                                │
                    ┌───────────────────────────┼───────────┐
                    │                           │           │
                    ▼                           ▼           ▼
            ┌──────────────┐          ┌──────────────┐  ┌──────────────┐
            │   Search     │          │    Write     │  │   Compare    │
            │     FSM      │          │     FSM      │  │     FSM      │
            └──────────────┘          └──────────────┘  └──────────────┘
```

### Key Components

- **12 FSMs**: Connection, BerDecoder, Auth, SASL, Search, Write, Compare, ExtendedOp, Referral, ReplicationProvider, ReplicationConsumer, BackendTxn
- **FSM Runtime**: ConnectionFsmSet manages FSM lifecycle and message routing
- **Backend Adapters**: Pluggable storage backends (LMDB, in-memory)
- **Replication Service**: High-level API for provider/consumer management

See [Architecture Overview](docs/architecture-overview.md) for details.

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Run tests (`cargo test`)
4. Commit changes (`git commit -m 'Add amazing feature'`)
5. Push to branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

## Support

- **Issues**: [GitHub Issues](https://github.com/keaz/opendr/issues)
- **Documentation**: [https://keaz.github.io/opendr/](https://keaz.github.io/opendr/)
- **Discussions**: [GitHub Discussions](https://github.com/keaz/opendr/discussions)

## Acknowledgments

- Built with [Rust](https://www.rust-lang.org/)
- Uses [Tokio](https://tokio.rs/) for async runtime
- Uses [LMDB](https://www.symas.com/lmdb) for storage
- Implements [RFC 4511](https://datatracker.ietf.org/doc/html/rfc4511) (LDAP v3)
- Implements [RFC 4533](https://datatracker.ietf.org/doc/html/rfc4533) (Content Synchronization)

## Status

OpenDR is actively maintained as a release candidate with the operator and
release evidence documented above. Keep `docs/PRODUCTION_READINESS_CHECKLIST.md`
and the retained `target/` artifacts aligned with the current release run before
claiming production readiness for a specific deployment.

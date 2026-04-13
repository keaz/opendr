# OpenDR Developer Operations Guide

This guide is for developers who need to set up, run, troubleshoot, and extend
the OpenDR LDAP server. It is based on the current Rust implementation in this
repository, not on the older design notes.

## What OpenDR Starts

The shipped `opendr` binary loads:

```bash
opendr --config config/server.toml --log-config config/log4rs.yml
```

Startup flow:

1. Initialize logging from `config/log4rs.yml`.
2. Load `ServerConfig` from TOML and `OPENDR_*` environment overrides.
3. Validate runtime, TLS, secret sources, replication, resources, audit, and
   access-control settings.
4. Resolve the root password from `root_password`, `root_password_env`, or
   `root_password_file`.
5. Initialize the backend, usually LMDB.
6. Wrap the backend with replication changelog support when provider mode is
   enabled.
7. Start provider and/or consumer replication tasks when configured.
8. Start monitoring HTTP endpoints when enabled.
9. Start LDAP and, when TLS is enabled, LDAPS listeners.
10. Drain and stop listeners, monitoring, and replication tasks on shutdown.

Default paths are relative to the current working directory. Run each OpenDR
instance from its own directory, or pass absolute config, log, data, audit, and
replication state paths.

## Architecture

OpenDR has two server runtimes behind the same binary:

- `fsm`: the current default runtime and the recommended path for new work.
- `legacy`: the older listener path retained for compatibility and targeted
  debugging.

The runtime is selected with:

```toml
[server]
runtime = "fsm"
```

High-level flow:

```text
TCP or TLS listener
  -> connection/resource checks
  -> BER decoder
  -> LDAP message parser
  -> control validation
  -> bind/search/write/compare/extended operation dispatch
  -> DirectoryBackend
  -> LMDB or in-memory backend
  -> LDAP response encoder
```

Core modules:

| Area | Main files | Notes |
| --- | --- | --- |
| Entrypoint | `src/main.rs` | Runtime selection, backend setup, monitoring, TLS, shutdown |
| Config | `src/config.rs` | TOML/env loading, defaults, validation, secret resolution |
| Setup | `src/setup.rs`, `src/bin/setup.rs` | Interactive and non-interactive setup |
| FSM runtime | `src/fsm_server.rs`, `src/fsm_runtime.rs`, `src/fsm.rs` | Connection-level FSM set and operation FSM dispatch |
| Legacy runtime | `src/server.rs` | Older direct handler path, also reused by FSM for shared helpers |
| Backend | `src/backend.rs`, `src/backend_lmdb.rs` | Backend trait, in-memory mock, LMDB implementation |
| Replication | `src/replication*.rs`, `src/backend_changelog_wrapper.rs` | LDAP Sync, changelog, provider/consumer services |
| TLS | `src/tls.rs`, `src/connection_fsm.rs` | Rustls LDAPS and StartTLS transport upgrade |
| Controls | `src/ldap_controls.rs`, `src/search_controls.rs`, `src/sync_controls.rs` | Request validation and control codecs |
| Backup | `src/backup.rs`, `src/bin/opendr_backup.rs`, `src/bin/opendr_restore.rs` | LMDB full/incremental backup and offline restore |

Per FSM connection, OpenDR creates a `ConnectionFsmSet` with a connection FSM,
BER decoder FSM, authentication FSM, and independent operation FSMs. Search,
write, compare, and extended operations are correlated by LDAP message ID.

## Choosing A Runtime

Use `fsm` for new deployments and development. It integrates connection pooling,
resource limits, rate limiting, metrics, audit, TLS transport, and graceful
shutdown with the current runtime model.

Use `legacy` when you need to compare behavior against the older handler path.
The shipped binary rejects non-default `rate_limit.burst_size` in legacy mode,
so keep that default if you switch runtime.

Current runtime caveats:

- FSM bind supports simple bind, anonymous bind, and SASL PLAIN over
  confidential transport.
- SASL DIGEST-MD5 and CRAM-MD5 are not production-enabled.
- Both runtimes share backend, TLS, metrics, audit, and many protocol helper
  modules.

## Quickstart

Use this path when the OpenDR binaries are already installed or available on
`PATH`. It intentionally avoids building from source.

Prepare a working directory:

```bash
mkdir -p ./config ./logs
```

Run the setup wizard:

```bash
opendr-setup --config-dir ./config interactive
```

Start the server:

```bash
opendr --config ./config/server.toml --log-config ./config/log4rs.yml
```

The setup command writes `server.toml`, setup state, LDIF scaffolding, and data
directories. The server still needs a log4rs YAML file; use the packaged file or
copy the repository `config/log4rs.yml` beside the generated server config.

Validate with LDAP tools:

```bash
ldapsearch -x -H ldap://127.0.0.1:1389 \
  -D "cn=admin,dc=example,dc=com" -w "$OPENDR_ADMIN_PASSWORD" \
  -b "dc=example,dc=com" "(objectClass=*)"
```

## Setup Command

Generate a password hash when you need a file-backed LMDB root secret:

```bash
opendr-setup hash-password 'StrongPass123'
```

The command prints a complete `{SSHA512}...` value. For LMDB,
`root_password_file` should contain that complete value, not the cleartext
password.

Run interactive setup:

```bash
opendr-setup --config-dir ./config interactive
```

Or generate a setup input file and run non-interactively:

```bash
opendr-setup generate-config --output setup-config.toml
opendr-setup --config-dir ./config non-interactive --config setup-config.toml
```

Check setup status:

```bash
opendr-setup --config-dir ./config status
```

Reset setup state:

```bash
opendr-setup --config-dir ./config reset
opendr-setup --config-dir ./config reset --force
```

Setup writes:

- `server.toml`
- `setup.state`
- `admin.ldif`
- `base.ldif`
- optional `sample.ldif`
- the configured data directory
- the configured replication state directory when replication is enabled

Setup maps its setup-time replication fields to runtime fields. For example,
setup `role` becomes runtime `mode`, `provider_bind_dn` becomes `bind_dn`, and
`changelog_max_entries` becomes `changelog_capacity`.

Setup caveats:

- Setup selects `server.runtime = "fsm"`.
- The LMDB setup step creates directories and runtime config; actual base
  entries are initialized by `opendr` at server startup when the base DN is
  absent.
- `import_sample_data` in setup creates `sample.ldif`; the current server
  startup path does not import that LDIF automatically.
- Setup password validation requires at least 8 characters with uppercase,
  lowercase, and numeric characters.

## Build From Source

Use this path when you are developing OpenDR itself or testing a local branch.
Runtime configuration should still be created by `opendr-setup`.

```bash
git clone https://github.com/keaz/opendr.git
cd opendr
cargo build --release
```

Run setup from the built binary:

```bash
./target/release/opendr-setup --config-dir ./config interactive
```

Start the built server:

```bash
./target/release/opendr \
  --config ./config/server.toml \
  --log-config ./config/log4rs.yml
```

## Configuration

The full runtime configuration reference is in `docs/CONFIGURATION.md`.

Important rules:

- Environment overrides use the `OPENDR` prefix and double underscore
  separators, for example `OPENDR_SERVER__LDAP_PORT=1389`.
- Secret fields allow only one source at a time: inline, `_env`, or `_file`.
- `bind_address` is a host/address only. Do not include the port there.
- `ldap_port` and `ldaps_port` must differ.
- TLS validates certificate, key, and required CA file existence before startup.
- Consumer and both replication modes require `provider_url` and
  `enable_change_listening = true`.
- Poll-based consumer replication has been removed.
- `access_control.rules_file` is loaded at startup when access control is
  enabled. See `docs/CONFIGURATION.md` for the TOML rule format.
- Byte-based resource fields are `max_memory_per_connection` and
  `max_total_memory`.

Runtime fields that are parsed but currently limited:

- `performance.worker_threads` and `performance.query_optimization` are parsed.
  Current startup wiring actively uses `performance.indexing_enabled`,
  `performance.cache_size`, and the `[schema]` section for schema loading and
  validation.
- `backend.import_sample_data` is parsed; setup writes sample LDIF, but server
  startup does not import sample LDIF automatically.

## TLS And StartTLS

Enable TLS to start the LDAPS listener and allow StartTLS upgrades:

```toml
[tls]
enabled = true
cert_file = "/etc/opendr/certs/server.crt"
key_file = "/etc/opendr/certs/server.key"
ca_file = "/etc/opendr/certs/ca.crt"
require_client_cert = false
min_tls_version = "1.2"
```

TLS uses rustls. Supported minimum versions are `1.2` and `1.3`. The maximum
runtime version is TLS 1.3.

LDAPS accepts TLS at connection start on `server.ldaps_port`.

StartTLS runs on the plain LDAP listener. The FSM path sends StartTLS success,
upgrades the transport, resets authentication state, and clears paged-search
state. Clients must bind again after StartTLS.

For mutual TLS, set `require_client_cert = true` and provide `ca_file`.

Troubleshooting TLS:

- `TLS certificate file not found`: fix `tls.cert_file` or the process working
  directory.
- `TLS key file not found`: fix `tls.key_file`.
- `Client certificate verification requires a CA file`: set `ca_file`.
- StartTLS already secure: the connection was already TLS/LDAPS.
- Client bind fails after StartTLS: bind again after the upgrade.

## LDAP Operations And Controls

FSM runtime supports:

- LDAPv3 simple bind, anonymous bind, and SASL PLAIN over LDAPS or StartTLS
- search
- add, modify, delete, ModifyDN
- compare
- abandon and unbind
- extended operations: StartTLS, Password Modify, WhoAmI, Cancel
- Root DSE and subschema searches
- referrals and ManageDsaIT handling
- paged results
- server-side sort
- LDAP Sync controls for replication

Controls:

- Unknown noncritical request controls are ignored.
- Unknown critical controls return `unavailableCriticalExtension`.
- Duplicate singleton controls are rejected.
- Paged search cookies are scoped to the search sequence and cleaned on cancel
  or abandon.
- Server-side sort rejects unsupported ordering rules.

Schema validation:

- The registry loads configured built-in schema and RFC-style LDIF files from
  `[schema].schema_dir`.
- The core schema includes common LDAP classes such as `top`, `person`,
  `organizationalPerson`, `inetOrgPerson`, `organization`, and
  `organizationalUnit`.
- Adds require `objectClass`, required attributes, a valid structural class, and
  no single-value or syntax violations.
- Modify and ModifyDN validate the resulting entry or RDN against the active
  registry.
- Attributes outside object class MAY/MUST sets are rejected.
- If `[schema].allow_online_updates = true`, authenticated and authorized Modify
  operations against `cn=Subschema` update the shared registry and persist
  accepted online definitions to `schema_dir/99-online.ldif`.
- Online schema deletes and replaces are rejected when they would break schema
  dependencies or invalidate existing entries.

Access control:

- ACI permissions include read, write, search, compare, add, delete, modify, and
  proxy.
- Rules can target DNs, subtrees, attributes, or combined targets.
- Subjects can be users, groups, authenticated users, all users, or self.
- The runtime defaults to deny unless configured otherwise.

## Storage And Indexing

Use LMDB for persistent deployments:

```toml
[backend]
backend_type = "lmdb"
data_directory = "/var/lib/opendr/data"
lmdb_max_size = 10737418240
lmdb_max_readers = 256
indexed_attributes = ["cn", "uid", "mail", "objectClass", "ou"]
```

The in-memory backend is useful for tests and local experiments only.

LMDB databases include:

- `entries`: primary serialized directory entries
- `passwords`: password hashes
- `dn_index`: case-insensitive DN lookup
- `metadata`: contextCSN and index metadata
- `idx_<attribute>`: per-attribute indexes

Legacy `indexed_attributes` entries get equality and presence indexes. Typed
indexes add explicit LDAP search categories:

```toml
[[backend.indexes]]
attribute = "cn"
types = ["substring"]

[[backend.indexes]]
attribute = "exampleScore"
types = ["ordering"]
```

Supported typed names are `equality`/`eq`, `presence`/`pres`,
`substring`/`sub`, and `ordering`/`ord`.

Index behavior:

- Schema validation decides whether equality, substring, or ordering
  comparisons are legal for an attribute.
- Equality indexes store values normalized by the attribute equality matching
  rule.
- Presence indexes use a sentinel.
- Substring indexes store 3-character windows from the substring matching-rule
  normalized value and fall back to full scan when the query cannot produce a
  3-character token.
- Ordering indexes store ordering keys produced by the attribute ordering
  matching rule, for example integer ordering keys sort numerically rather than
  lexicographically.
- Indexes are maintained on add, modify, and delete.
- Startup backfills index DBs when configured index types or their resolved
  matching-rule OIDs change.
- `performance.indexing_enabled = false` disables configured runtime indexes.

## Replication

OpenDR replication is listener-based LDAP Sync-style replication. A provider
records writes in a bounded changelog and serves sync searches. A consumer
performs an initial refresh, stores a cookie, then keeps a long-lived
refresh-and-persist search open for live changes.

Provider:

```toml
[server]
replica_id = 1

[replication]
enabled = true
mode = "provider"
changelog_enabled = true
changelog_capacity = 100000
max_batch_size = 100
enable_streaming = true
heartbeat_interval_secs = 60
state_storage_path = "/var/lib/opendr/provider/replication_state"
```

Consumer:

```toml
[server]
replica_id = 2

[replication]
enabled = true
mode = "consumer"
provider_url = "ldap://provider.example.com:1389"
bind_dn = "cn=replication,dc=example,dc=com"
bind_password_file = "/run/secrets/opendr-replication-bind-password"
max_retry_attempts = 5
retry_delay_secs = 10
enable_change_listening = true
provider_timeout_secs = 30
state_persistence_timeout_secs = 10
change_buffer_size = 1000
state_storage_path = "/var/lib/opendr/consumer/replication_state"
```

State files:

- Provider changelog: `<state_storage_path>/provider_changelog.json`
- Consumer cookie: `<state_storage_path>/replication_cookie.txt`

Operational notes:

- `replica_id` must be unique per node.
- `enable_change_listening` must be true for `consumer` and `both`.
- `sync_interval_secs` remains as a compatibility field, not the live change
  cadence.
- `local://` and `in-memory://` provider URLs are rejected by the shipped
  consumer service.
- Stale cookies require a full refresh. Delete the consumer cookie to force one
  or increase `changelog_capacity`.
- `both` mode starts provider and consumer roles in the same process. General
  multi-master conflict resolution is not implemented; deploy an external
  conflict strategy if more than one node accepts writes.
- Compatibility/test modules such as `push_manager`, `persistent_connection`,
  `provider_push_integration`, and `consumer_persist_mode` are not the active
  shipped streaming path.

Verify replication:

```bash
ldapadd -x -H ldap://provider.example.com:1389 \
  -D "cn=manager,dc=example,dc=com" -w "$PROVIDER_PASSWORD" <<'LDIF'
dn: uid=replication-test,ou=People,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: replication-test
sn: Test
uid: replication-test
LDIF

ldapsearch -x -H ldap://consumer.example.com:2389 \
  -D "cn=manager,dc=example,dc=com" -w "$CONSUMER_PASSWORD" \
  -b "ou=People,dc=example,dc=com" "(uid=replication-test)"
```

## Backup And Restore

Backup and restore support the LMDB backend only.

Create a full online backup:

```bash
opendr-backup --config /etc/opendr/server.toml full \
  --target /var/backups/opendr/full-20260412
```

Create an incremental changelog backup:

```bash
opendr-backup --config /etc/opendr/server.toml incremental \
  --parent /var/backups/opendr/full-20260412 \
  --target /var/backups/opendr/inc-20260412-01
```

Inspect a backup:

```bash
opendr-backup inspect --backup /var/backups/opendr/full-20260412
```

Dry-run restore:

```bash
opendr-restore \
  --backup /var/backups/opendr/full-20260412 \
  --incremental /var/backups/opendr/inc-20260412-01 \
  --target-data-dir /var/lib/opendr/data-restored \
  --dry-run
```

Restore:

```bash
opendr-restore \
  --backup /var/backups/opendr/full-20260412 \
  --incremental /var/backups/opendr/inc-20260412-01 \
  --target-data-dir /var/lib/opendr/data-restored
```

Backup notes:

- Full backup uses LMDB online copy and can run while the source server is
  running.
- Incremental backup is changelog-based, not page-level LMDB incremental.
- Incremental backup requires provider or both replication mode and a retained
  `provider_changelog.json`.
- Target backup directories must be empty or absent.
- Manifests include checksums and checkpoint CSNs.
- Restore must run while the target server is stopped.
- Restore refuses to replace non-empty target directories unless `--force` is
  provided.
- Restore opens the restored target with default index configuration while
  applying incrementals; keep the runtime `server.toml` index config aligned and
  allow startup backfill when using custom indexes.

See `docs/BACKUP_RESTORE.md` for the full runbook.

## Monitoring, Audit, Rate Limits, And Resources

Monitoring defaults:

```toml
[monitoring]
enabled = true
metrics_address = "127.0.0.1"
metrics_port = 9090
metrics_path = "/metrics"
health_path = "/health"
console_enabled = true
console_path = "/console"
console_session_ttl_secs = 3600
```

Endpoints:

```bash
curl http://127.0.0.1:9090/metrics
curl http://127.0.0.1:9090/health
open http://127.0.0.1:9090/console
```

The management console is read-only and uses LDAP authentication against the
configured root DN. If `root_user_dn` is an RDN, OpenDR combines it with
`base_dn` for console login, for example `cn=admin,dc=example,dc=com`.
Sessions use HttpOnly SameSite cookies, live only in the server process, and
expire on restart or after `console_session_ttl_secs`.
See [`MANAGEMENT_CONSOLE.md`](./MANAGEMENT_CONSOLE.md) for the route map and
overview payload fields.

Audit defaults to JSON format at `./logs/audit.log` and can log
authentication, authorization, modifications, and connection events.

Rate limiting uses global, per-client, and per-operation sliding windows, with
whitelist/blacklist, adaptive throttling, and auto-ban.

Resource management limits:

- total connections
- connections per IP
- operations per connection
- memory per connection
- total tracked memory
- idle connection timeout

## Troubleshooting Checklist

Startup fails:

- Confirm the process can read `config/log4rs.yml`; the entrypoint currently
  unwraps logging initialization.
- Confirm the config path passed to `--config` exists.
- Confirm secret source exclusivity for root and replication passwords.
- Confirm TLS files exist when TLS is enabled.
- Confirm LDAP and LDAPS ports differ.

Bind fails:

- For LMDB file-backed root passwords, confirm the file contains a full
  `{SSHA512}...` hash.
- Confirm the bind DN includes the base DN if needed, for example
  `cn=manager,dc=example,dc=com`.
- After StartTLS, bind again because the auth state is reset.
- SASL PLAIN requires LDAPS or StartTLS. Other SASL mechanisms are not
  production-enabled.

Search fails:

- Unknown critical controls are rejected.
- Bad paged cookies are rejected.
- Subtree and one-level scope depend on DN normalization by lowercasing and
  trimming, not full LDAP DN canonicalization.
- Request `+` or explicit operational attributes for `entryCSN`, `entryUUID`,
  and other operational values.

Write fails:

- Check authentication first; mutations require an authenticated session.
- Check schema errors: missing `objectClass`, missing `cn`/`sn` for `person`,
  unknown attributes, missing structural class, and single-value violations.
- Check access-control default policy and any in-memory ACI rules.

Replication stalls:

- Confirm provider mode is `provider` or `both` and `changelog_enabled = true`.
- Confirm consumer mode has `provider_url`, bind credentials, and
  `enable_change_listening = true`.
- Inspect provider `provider_changelog.json`.
- Inspect or remove consumer `replication_cookie.txt` for stale-cookie recovery.
- Check consumer logs for entered listening mode, stream termination, and retry
  loops.

Backup fails:

- Confirm `[backend].backend_type = "lmdb"`.
- Use an empty backup target directory.
- For incrementals, confirm provider changelog persistence and sufficient
  `changelog_capacity`.
- If the changelog window was pruned, take a new full backup.

## Tests

Useful targeted suites:

```bash
cargo test --test config_integration
cargo test --test runtime_selection_integration
cargo test --test tls_runtime_integration
cargo test --test indexing_integration
cargo test --test backup_restore_integration
cargo test --test backup_restore_server_integration
cargo test --test replication_integration
cargo test --test replication_consumer_integration
cargo test --test replication_provider_integration
cargo test --test replication_e2e
./e2e_tests/test_schema_management.sh
```

The shell e2e area includes replication coverage and schema-management coverage
through real LDAP client commands. Some broader scenarios in the e2e summary
remain pending.

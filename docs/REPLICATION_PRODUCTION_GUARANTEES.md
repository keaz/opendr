# OpenDR Replication Production Guarantees

This document defines the production contract for OpenDR replication. It maps
OpenDR behavior to LDAP Content Synchronization from RFC 4533 and to the LDAP
model and control semantics from RFC 4511 and RFC 4512.

## Supported Topologies

Supported:

- One writable provider with one consumer.
- One writable provider with multiple consumers, bounded by
  `replication.max_concurrent_consumers`, network capacity, and
  `replication.changelog_capacity`.
- Fan-out from the same writable provider to independent consumers.

Not production-supported:

- Multi-provider or multi-master writes.
- Conflict resolution between concurrent writes on different nodes.
- Cascading consumers as a high-availability topology.
- Replication of server configuration, schema files, ACL policy files, TLS
  material, indexes, logs, or local setup state.

`mode = "both"` starts provider and consumer roles in one process, but it does
not provide multi-master conflict resolution. Use it only when a deployment has
a clear single writable upstream and accepts the operational limitations.

## Data Contract

OpenDR replicates directory entries under the configured replication base DN.
The supported write operations in a single-provider topology are:

- Add
- Modify
- Delete
- ModifyDN / rename

OpenDR preserves server-managed entry state needed for synchronization, including
`entryCSN`, `entryUUID`, and the provider `contextCSN`. Operational attributes
are visible to LDAP clients only when requested according to the normal OpenDR
search rules.

OpenDR does not replicate:

- Schema definitions or schema validation configuration.
- Access-control rule files or local authorization configuration.
- Backend index configuration or index databases as a replication stream.
- `server.toml`, `setup.state`, TLS keys/certificates, log configuration, logs,
  or local runtime state outside the replication state files.

Operators must deploy schema, ACL, TLS, index, and configuration changes through
their normal configuration management process before relying on replicated data
that depends on those changes.

## Cookie And Replay Semantics

OpenDR sync cookies are CSN cookies in this form:

```text
csn-<ldap-context-csn>
```

The special cookie `csn-empty`, or an absent cookie, means full refresh.

Provider behavior:

- A valid retained cookie replays only changes newer than that cookie.
- A cookie older than the retained changelog window is rejected as requiring a
  full refresh.
- A cookie that cannot be parsed or is newer than the provider context is
  rejected as invalid.
- If the backend `contextCSN` is newer than the available provider changelog,
  incremental replay is rejected as a missing replay segment. This can happen
  after restore or after an operator starts a provider without the matching
  `provider_changelog.json`.

Consumer behavior:

- On first start, or when `replication_cookie.txt` is absent, the consumer does a
  full refresh and persists a new cookie.
- On reconnect, the consumer resumes from the persisted cookie.
- If the provider rejects the cookie because a full refresh is required, the
  failure is deterministic and visible in replication health. Delete the
  consumer `replication_cookie.txt` to force a full refresh, or restore a
  provider changelog that still contains the requested window.

## Failure Recovery

Provider restart:

- The provider reloads `<state_storage_path>/provider_changelog.json`.
- Consumers reconnect and resume from persisted cookies when the cookie is still
  inside the retained window.

Consumer restart:

- The consumer reloads `<state_storage_path>/replication_cookie.txt`.
- A missing cookie forces a full refresh.

Network interruption:

- The consumer retries according to `max_retry_attempts` and
  `retry_delay_secs`.
- A successful reconnect uses the last persisted cookie.

Missing changelog segment:

- The provider rejects incremental replay with a stale-cookie/full-refresh
  required error.
- The consumer health snapshot increments `replay_gap_errors` and
  `full_refresh_required`.
- Operators must retain the provider and consumer logs, consumer cookie, and
  provider changelog excerpt from `test_replication_failure_drills.sh` as release
  evidence when validating this path.

Unsupported conflicts:

- Concurrent writes on more than one node are outside the production contract.
- The supported conflict policy is single-writer CSN ordering on the provider.

## Failure Drill Gate

Run the smoke drill in CI and the release drill before declaring a production
candidate:

```bash
FAILURE_DRILL_MODE=release \
FAILURE_DRILL_ARTIFACT_DIR=target/replication-failure-drills/release-candidate \
./e2e_tests/test_replication_failure_drills.sh
```

The drill starts isolated provider and consumer instances, verifies convergence
after provider restart, consumer restart, provider network interruption, stale
consumer cookie with truncated provider changelog, and operator full-refresh
recovery. A release candidate fails the replication gate if any scenario lacks
a diagnostic, if the consumer exits unexpectedly while the provider is
unreachable, or if the final full refresh does not converge.

## Health Signals

The monitoring console overview API exposes replication status at:

```text
GET <monitoring.console_path>/api/overview
```

Relevant JSON fields include:

- `replication.provider.running`
- `replication.provider.active_sessions`
- `replication.provider.retained_changelog_entries`
- `replication.provider.oldest_retained_csn`
- `replication.provider.latest_context_csn`
- `replication.provider.last_error`
- `replication.consumer.running`
- `replication.consumer.listening`
- `replication.consumer.persisted_cookie`
- `replication.consumer.last_applied_cookie`
- `replication.consumer.last_applied_csn`
- `replication.consumer.last_successful_sync_unix_secs`
- `replication.consumer.seconds_since_last_successful_sync`
- `replication.consumer.last_sync_entries`
- `replication.consumer.failed_sessions`
- `replication.consumer.full_refreshes`
- `replication.consumer.full_refresh_required`
- `replication.consumer.replay_gap_errors`
- `replication.consumer.last_error`

Alert when consumers stop listening, `seconds_since_last_successful_sync`
exceeds the deployment recovery objective, `failed_sessions` increases, or
`replay_gap_errors` / `full_refresh_required` is non-zero.

## Backup And Restore

The backup tooling supports LMDB full backup and changelog incremental backup.
The restored backend receives the final `contextCSN` from the backup chain.

Production restore rules:

- Restore provider data into an isolated data directory.
- Use a fresh `replication.state_storage_path` unless you also restore a matching
  provider changelog window.
- Expect consumers whose cookies predate restored changes to perform a full
  refresh.
- Delete the consumer cookie to force the full refresh after provider restore.
- Keep schema, ACL, TLS, index, and server configuration in sync separately.

OpenDR intentionally treats a restored backend with a newer `contextCSN` than
the available provider changelog as a replay gap. Incremental replay from an old
cookie fails clearly instead of silently losing changes.

## Rolling Upgrades

Recommended order:

1. Upgrade consumers one at a time. Each consumer reconnects with its persisted
   cookie.
2. Upgrade the provider during a maintenance window sized for consumer reconnect
   and changelog retention.
3. Keep `changelog_capacity` large enough to cover the longest consumer outage
   and the provider upgrade window.

Compatibility rules:

- Run the same OpenDR minor version across a replication set when possible.
- Do not introduce schema, ACL, or configuration-dependent data until all nodes
  have received the matching local configuration.
- If a consumer cannot resume after upgrade, force a full refresh by deleting
  its consumer cookie.

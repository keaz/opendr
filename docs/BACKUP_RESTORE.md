# OpenDR Backup and Restore Design

This document defines the first backup and restore path for OpenDR's LMDB backend.

## Goals

- Support a full backup of an LMDB-backed OpenDR instance while the LDAP server is running.
- Support incremental backups from a previous backup checkpoint when the provider changelog is enabled and retained.
- Restore into a stopped, empty data directory.
- Make every backup self-describing through a manifest that restore tooling can validate.

## Backend Constraints

OpenDR stores persistent entries in a single LMDB environment. The environment contains the entries database, password database, DN index, metadata database, and optional attribute index databases.

LMDB provides online environment copy APIs such as `mdb_env_copy2`. Those APIs create a consistent copy using a read-only transaction. This is suitable for full online backup, with the usual LMDB caveat that long-running read transactions can increase source file growth while writers continue.

LMDB does not provide a native incremental backup API. Page-level incremental backup is not selected for the first implementation because it would require tracking LMDB pages outside the safe abstractions currently used by OpenDR.

## Selected Strategy

### Full Backup

A full backup opens the source LMDB environment read-only and copies it with `mdb_env_copy2` into an empty backup data directory. The backup tool then opens the copied environment and reads the copied `contextCSN`. The manifest uses that copied checkpoint as the backup's end checkpoint, so concurrent writes after the LMDB snapshot are not accidentally included in the manifest.

The backup output layout is:

```text
backup-dir/
  manifest.json
  data/
    data.mdb
```

`lock.mdb` is intentionally not required in the backup; LMDB recreates it when the restored environment is opened.

### Incremental Backup

An incremental backup is a changelog segment from the previous backup's `end_context_csn` to the latest retained provider changelog entry.

The source of truth is the persisted provider changelog at:

```text
<replication.state_storage_path>/provider_changelog.json
```

The backup tool validates the chain before writing an incremental backup:

- the parent manifest exists and belongs to the same backup format;
- the parent manifest has an `end_context_csn`;
- the persisted changelog still contains a complete window after the parent checkpoint;
- if the LMDB backend's current `contextCSN` is newer than the latest retained changelog entry, the backup fails because a concurrent write may not yet be present in the changelog snapshot.

The backup output layout is:

```text
backup-dir/
  manifest.json
  changes.json
```

This makes incremental backup safe for provider or both-mode deployments that persist the changelog and retain enough entries. If replication/changelog is disabled or the parent checkpoint has been pruned, incremental backup is rejected with an explicit error. Operators should take a new full backup in that case.

### Deferred Alternatives

Page-level incrementals and filesystem snapshot integration are deferred. They would require platform-specific behavior or tighter LMDB page tracking than OpenDR currently exposes.

## Manifest

Each backup has a `manifest.json` with:

- backup format version;
- backup ID;
- backup type: `full` or `incremental`;
- parent backup ID for incrementals;
- source backend type;
- source data directory;
- source base DN;
- source replica ID;
- source LMDB map size;
- start and end context CSNs;
- creation timestamp;
- OpenDR crate version;
- file paths, sizes, and SHA-256 checksums.

The manifest stores both a `snapshot_context_csn` and an `end_context_csn`. For full backups, `snapshot_context_csn` is read from the copied LMDB snapshot. When a provider changelog is available, `end_context_csn` is the pre-copy changelog high-water mark used as the incremental chain checkpoint. This can be older than the copied snapshot; later incremental replay may therefore reapply an already-copied operation, and the replay path treats duplicate add/delete/rename operations idempotently.

Restore treats the manifest as authoritative and validates checksums before copying or applying data.

## CLI Usage

Create a full online backup:

```bash
cargo run --bin opendr-backup -- full \
  --config config/server.toml \
  --target /var/backups/opendr/full-20260411
```

Create an incremental backup from a previous full or incremental backup:

```bash
cargo run --bin opendr-backup -- incremental \
  --config config/server.toml \
  --parent /var/backups/opendr/full-20260411 \
  --target /var/backups/opendr/inc-20260411-01
```

Inspect and verify a backup manifest:

```bash
cargo run --bin opendr-backup -- inspect \
  --backup /var/backups/opendr/full-20260411
```

Dry-run a restore:

```bash
cargo run --bin opendr-restore -- \
  --backup /var/backups/opendr/full-20260411 \
  --incremental /var/backups/opendr/inc-20260411-01 \
  --target-data-dir /var/lib/opendr/data-restored \
  --dry-run
```

Restore offline into an empty target data directory:

```bash
cargo run --bin opendr-restore -- \
  --backup /var/backups/opendr/full-20260411 \
  --incremental /var/backups/opendr/inc-20260411-01 \
  --target-data-dir /var/lib/opendr/data-restored
```

## Restore Model

Restore is offline in the first implementation. The target server must be stopped, and the target data directory must be empty unless the operator uses an explicit force flag.

For a full restore, the restore tool validates the manifest and copies the `data/` directory to the target data directory.

For incremental restore, the restore tool first restores the full backup and then applies each incremental manifest in order. Incrementals must form a continuous parent chain. Changelog replay uses the same change payload shape as OpenDR replication, then sets the restored backend's `contextCSN` to the final manifest checkpoint.

The first implementation does not support hot restore, partial subtree restore, or cross-version data migration beyond manifest compatibility checks.

## Operational Notes

- Full online backup can run while the LDAP server is serving reads and writes.
- Full online backup may increase source LMDB file growth if it overlaps heavy write traffic.
- Incremental backup requires provider changelog persistence and adequate changelog retention.
- A stale or incomplete changelog window is a hard failure for incremental backup.
- Restore should be validated before use with `--dry-run` where possible.

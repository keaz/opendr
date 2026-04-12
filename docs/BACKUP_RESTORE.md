# OpenDR Backup and Restore

This guide describes how to back up and restore OpenDR when the server uses the
LMDB backend.

## Support Matrix

| Operation | Supported | Server state |
| --- | --- | --- |
| Full LMDB backup | Yes | Source server may keep running |
| Incremental LMDB backup | Yes, with provider changelog retention | Source server may keep running |
| Full restore | Yes | Target server must be stopped |
| Full plus incremental restore | Yes | Target server must be stopped |
| Hot restore into a running server | No | Stop the target server first |
| In-memory backend backup | No | Use LMDB for durable backups |

Full backup uses LMDB's online copy API (`mdb_env_copy2`) through a read-only
source environment. It produces a consistent LMDB snapshot while the LDAP server
continues serving traffic.

Incremental backup is changelog-based. It records the provider changelog entries
after the parent backup checkpoint. It is not a page-level LMDB incremental.

## Required Configuration

Backup and restore only support the `lmdb` backend:

```toml
[backend]
backend_type = "lmdb"
data_directory = "/var/lib/opendr/data"
lmdb_max_size = 10737418240
lmdb_max_readers = 256
```

For full backups, no replication setting is required.

For incremental backups, configure the server as a replication provider or both
mode and keep the provider changelog on persistent storage:

```toml
[server]
replica_id = 1

[replication]
enabled = true
mode = "provider"
changelog_capacity = 100000
state_storage_path = "/var/lib/opendr/replication_state"
```

For `mode = "both"`, also provide the consumer fields required by replication,
such as `provider_url`, `bind_dn`, and one of `bind_password`,
`bind_password_env`, or `bind_password_file`.

The incremental backup tool reads:

```text
<replication.state_storage_path>/provider_changelog.json
```

If that file is missing, disabled, or pruned past the parent backup checkpoint,
the incremental backup fails. Take a new full backup in that case.

## Backup Layout

A full backup directory contains:

```text
full-20260412/
  manifest.json
  data/
    data.mdb
```

`lock.mdb` is not required in the backup. LMDB recreates it when the restored
environment is opened.

An incremental backup directory contains:

```text
inc-20260412-01/
  manifest.json
  changes.json
```

Every `manifest.json` includes:

- backup format version
- backup ID and parent backup ID
- backup type: `full` or `incremental`
- source backend type and source data directory
- source base DN and replica ID
- LMDB map size
- OpenDR crate version
- creation timestamp
- checkpoint CSNs
- file paths, sizes, and SHA-256 checksums

Restore validates the manifest and file checksums before copying data or
applying incremental changes.

## Create A Full Online Backup

Use this while OpenDR is running:

```bash
opendr-backup --config /etc/opendr/server.toml full \
  --target /var/backups/opendr/full-20260412
```

For development builds:

```bash
cargo run --bin opendr-backup -- --config config/server.toml full \
  --target /tmp/opendr-backups/full-20260412
```

The target directory must be empty or absent. The command creates it if needed.

Use `--json` when automation needs the backup ID and checkpoint values:

```bash
opendr-backup --config /etc/opendr/server.toml --json full \
  --target /var/backups/opendr/full-20260412
```

Optional compact mode:

```bash
opendr-backup --config /etc/opendr/server.toml full \
  --target /var/backups/opendr/full-20260412-compact \
  --compact
```

Compact mode can reduce backup size but may take longer.

## Create Incremental Backups

Start with a full backup:

```bash
opendr-backup --config /etc/opendr/server.toml full \
  --target /var/backups/opendr/full-20260412
```

Create the first incremental from that full backup:

```bash
opendr-backup --config /etc/opendr/server.toml incremental \
  --parent /var/backups/opendr/full-20260412 \
  --target /var/backups/opendr/inc-20260412-01
```

Create the next incremental from the previous incremental:

```bash
opendr-backup --config /etc/opendr/server.toml incremental \
  --parent /var/backups/opendr/inc-20260412-01 \
  --target /var/backups/opendr/inc-20260412-02
```

Keep the full backup and all incrementals in order. A restore chain is valid only
when each incremental points to the backup ID from the previous manifest.

## Inspect A Backup

Verify checksums and print manifest metadata:

```bash
opendr-backup inspect --backup /var/backups/opendr/full-20260412
```

JSON output:

```bash
opendr-backup --json inspect --backup /var/backups/opendr/full-20260412
```

Run this after copying backups to remote storage to confirm the transfer did not
corrupt files.

## Restore To A New Data Directory

Restores are offline. Stop the target OpenDR server before restoring into its
configured data directory.

Dry-run first:

```bash
opendr-restore \
  --backup /var/backups/opendr/full-20260412 \
  --incremental /var/backups/opendr/inc-20260412-01 \
  --incremental /var/backups/opendr/inc-20260412-02 \
  --target-data-dir /var/lib/opendr/data-restored \
  --dry-run
```

Run the restore:

```bash
opendr-restore \
  --backup /var/backups/opendr/full-20260412 \
  --incremental /var/backups/opendr/inc-20260412-01 \
  --incremental /var/backups/opendr/inc-20260412-02 \
  --target-data-dir /var/lib/opendr/data-restored
```

Point OpenDR at the restored directory:

```toml
[backend]
backend_type = "lmdb"
data_directory = "/var/lib/opendr/data-restored"
lmdb_max_size = 10737418240
lmdb_max_readers = 256
```

Then start the server and validate a known entry:

```bash
ldapsearch -x \
  -H ldap://127.0.0.1:1389 \
  -D "cn=admin,dc=example,dc=org" \
  -w "$OPENDR_ADMIN_PASSWORD" \
  -b "dc=example,dc=org" \
  "(objectClass=*)"
```

## Restore In Place

Use this when replacing the configured production data directory. Keep the
server stopped for the entire procedure.

1. Stop OpenDR.
2. Move the current data directory aside:

   ```bash
   mv /var/lib/opendr/data /var/lib/opendr/data.before-restore
   mkdir -p /var/lib/opendr/data
   ```

3. Dry-run the restore:

   ```bash
   opendr-restore \
     --backup /var/backups/opendr/full-20260412 \
     --incremental /var/backups/opendr/inc-20260412-01 \
     --target-data-dir /var/lib/opendr/data \
     --dry-run
   ```

4. Restore:

   ```bash
   opendr-restore \
     --backup /var/backups/opendr/full-20260412 \
     --incremental /var/backups/opendr/inc-20260412-01 \
     --target-data-dir /var/lib/opendr/data
   ```

5. Start OpenDR.
6. Validate LDAP bind and search.
7. Remove `/var/lib/opendr/data.before-restore` only after validation and any
   operational hold period.

If you intentionally want restore to replace a non-empty target directory, pass
`--force`:

```bash
opendr-restore \
  --backup /var/backups/opendr/full-20260412 \
  --target-data-dir /var/lib/opendr/data \
  --force
```

Prefer the move-aside flow above for production because it gives an immediate
rollback path.

## Validation Checklist

Before backup:

- Confirm `[backend].backend_type = "lmdb"`.
- Confirm `data_directory` points at the active LMDB directory.
- For incrementals, confirm provider or both replication mode is enabled and
  `state_storage_path` is persistent.
- Confirm the backup target filesystem has enough free space.

After backup:

- Run `opendr-backup inspect --backup <backup-dir>`.
- Copy the backup directory to remote storage.
- Run `opendr-backup inspect` again on the copied backup.
- Record the backup ID, parent backup ID, and checkpoint CSN from the manifest.

Before restore:

- Stop the target OpenDR server.
- Verify the restore chain order: full, then each incremental in sequence.
- Run `opendr-restore --dry-run`.
- Restore into a new or empty directory unless using `--force` deliberately.

After restore:

- Start OpenDR with the restored `data_directory`.
- Verify admin bind succeeds.
- Search for known entries that existed at the backup point.
- For restored incrementals, verify entries modified after the full backup are
  present.
- Monitor startup logs for LMDB or schema errors.

## Operational Notes

- Full online backup can run while the LDAP server is serving reads and writes.
- A full online backup is a point-in-time LMDB snapshot. Writes committed after
  the LMDB copy snapshot are not included in that full backup.
- Full online backup may increase source LMDB file growth if it overlaps heavy
  write traffic, because LMDB must preserve pages visible to the read
  transaction.
- Incremental backup requires provider changelog persistence and adequate
  changelog retention.
- If `changelog_capacity` is too small for the write volume between backups,
  the required window may be pruned. Increase `changelog_capacity` or take full
  backups more often.
- Restore does not perform cross-version migrations. Treat manifest format and
  OpenDR version changes as compatibility boundaries.
- Restore does not merge with existing data. It restores a full LMDB data
  directory and then applies an ordered incremental chain.

## Troubleshooting

### `backup only supports the lmdb backend`

The configured backend is not `lmdb`. Change `[backend].backend_type` to `lmdb`
and use a persistent `data_directory`.

### `<target> must be empty`

The backup target directory already contains files. Use a new directory or
remove the incomplete backup target after confirming it is safe to delete.

### `provider changelog not found`

Incremental backup cannot find
`<replication.state_storage_path>/provider_changelog.json`. Enable replication
provider or both mode, keep changelog persistence on durable storage, and take a
new full backup before retrying incrementals.

### `persisted changelog is behind backend contextCSN`

The current LMDB backend contains changes newer than the persisted changelog
snapshot. Retry after the provider changelog is persisted, or take a new full
backup.

### `is not empty; pass --force to replace it`

Restore refuses to overwrite the target data directory by default. Prefer moving
the current directory aside and restoring into a new empty directory. Use
`--force` only when replacement is intentional.

## Test Coverage

Backup/restore behavior is covered by:

```bash
cargo test --test backup_restore_integration
cargo test --test backup_restore_server_integration
```

The server integration test starts OpenDR with LMDB, writes data through LDAP,
creates a full backup while the source server is still running, restores the
backup into another data directory, starts a second OpenDR server, and verifies
the LDAP data from the restored server.

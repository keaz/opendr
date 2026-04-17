# OpenDR Troubleshooting Guide

Use this guide when the server fails to start, clients cannot bind or search,
replication does not progress, or backup and restore commands fail.

## Startup

### `Failed to load configuration`

Check that the path passed to `--config` exists and is readable:

```bash
opendr --config /etc/opendr/server.toml --log-config /etc/opendr/log4rs.yml
```

The default is `config/server.toml` relative to the current working directory.

### Logging exits at startup

The entrypoint initializes `log4rs` from `--log-config`. Check that the log
config path exists, is readable, and points to valid log4rs YAML.

### Secret source validation fails

For root and replication passwords, configure only one source:

- inline value
- `_env`
- `_file`

Example:

```toml
[server]
root_password_file = "/run/secrets/opendr-root-password-hash"
```

Do not also set `root_password` or `root_password_env`.

### TLS file validation fails

When `[tls].enabled = true`, the configured certificate and key files must exist.
When `require_client_cert = true`, `ca_file` must be set and must exist.

## Bind

### Root bind fails on LMDB

For LMDB, a file-backed root password should contain the complete `{SSHA512}`
hash:

```bash
cargo run --bin opendr-setup -- hash-password 'StrongPass123'
```

Put the printed value into the file referenced by `root_password_file`.

### Bind DN mismatch

The server initializes the root user at:

```text
<root_user_dn>,<base_dn>
```

If config contains:

```toml
root_user_dn = "cn=manager"
base_dn = "dc=example,dc=com"
```

bind as:

```text
cn=manager,dc=example,dc=com
```

### SASL PLAIN fails in `fsm`

SASL PLAIN in the FSM runtime requires confidential transport. Use LDAPS or run
StartTLS before binding. DIGEST-MD5, CRAM-MD5, and other SASL mechanisms are not
production-enabled.

### Bind fails after StartTLS

StartTLS resets the authentication state. Bind again after the TLS upgrade.

## Search

### Unknown critical control

Unknown noncritical controls are ignored. Unknown critical controls are rejected
with `unavailableCriticalExtension`.

### Bad paged results cookie

Paged search cookies are tied to a search sequence and are cleaned up on cancel,
abandon, and completion. Re-run the search from the first page.

### Operational attributes are missing

Operational attributes are hidden by default. Request `+` or specific attributes:

```bash
ldapsearch -x -H ldap://127.0.0.1:1389 \
  -b "dc=example,dc=com" "(uid=alice)" "+" "*"
```

Common operational attributes include `entryCSN`, `entryUUID`, timestamps,
creators/modifiers, `contextCSN`, `lastSuccessfulLogin`, `lastFailedLogin`, and
`failedLoginCount`. Failed user binds increment `failedLoginCount`; successful
user binds reset it to `0`.

### Indexed search still scans

The LMDB backend falls back to full scans when a required index type is absent.
Substring indexes also fall back when a query cannot produce a 3-character token.

Check:

```toml
[performance]
indexing_enabled = true

[[backend.indexes]]
attribute = "description"
types = ["substring"]
```

## Writes

### `objectClass` or schema errors

The core schema requires:

- `objectClass`
- valid object classes
- required attributes for the selected object class
- a valid structural class
- no single-value violations

For `person`, provide at least `cn` and `sn`.

### Mutations are rejected

Add, modify, delete, and ModifyDN require an authenticated session. Check the
bind result first, then inspect access-control default policy.

## TLS

### StartTLS fails

Check:

- `[tls].enabled = true`
- `cert_file` and `key_file` exist
- key format is accepted by rustls
- connection is not already secure
- client trusts the configured certificate chain

### Client certificates fail

Check:

- `require_client_cert = true`
- `ca_file` points to the issuing CA certificate
- the client presents a certificate chained to that CA

## Replication

### Consumer never enters listening mode

Check:

```toml
[replication]
enabled = true
mode = "consumer"
provider_url = "ldaps://provider.example.com:1636"
enable_change_listening = true
```

Consumer and both modes reject `enable_change_listening = false`.

### Credentialed `ldap://` replication provider URL is rejected

Check:

```toml
[replication]
enabled = true
mode = "consumer"
provider_url = "ldaps://provider.example.com:1636"
bind_password_file = "/run/secrets/opendr-replication-bind-password"
```

Use `ldaps://` for replication binds. The
`allow_insecure_provider_bind = true` option is only for local development and
loopback tests, and is rejected when `security.profile = "production"`.

### Provider URL is rejected

Use `ldap://` or `ldaps://`. The shipped consumer rejects `local://` and
`in-memory://` provider URLs.

### Stale cookie

If the consumer cookie is older than the retained provider changelog window,
force a full refresh:

```bash
rm /var/lib/opendr/consumer/replication_state/replication_cookie.txt
```

Then restart the consumer. Increase `changelog_capacity` if this happens during
normal operations.

### Incremental changes are missing

Inspect:

```bash
ls -l /var/lib/opendr/provider/replication_state/provider_changelog.json
cat /var/lib/opendr/consumer/replication_state/replication_cookie.txt
```

Check provider logs for broadcast lag or shutdown draining, and consumer logs
for stream termination and retry loops.

### Multi-master conflict behavior

`mode = "both"` runs provider and consumer roles in one process. General
multi-master conflict resolution is not implemented; deploy an external
conflict strategy if multiple nodes accept writes.

## Backup And Restore

### `backup only supports the lmdb backend`

Set:

```toml
[backend]
backend_type = "lmdb"
```

### `<target> must be empty`

Use a new backup target directory or remove an incomplete failed backup target
after confirming it is safe to delete.

### `provider changelog not found`

Incremental backup requires provider or both replication mode with persisted
changelog state:

```toml
[replication]
enabled = true
mode = "provider"
changelog_enabled = true
state_storage_path = "/var/lib/opendr/replication_state"
```

Take a new full backup before retrying incremental backup.

### `persisted changelog is behind backend contextCSN`

The backend contains changes newer than the persisted changelog snapshot. Retry
after the provider persists the changelog, or take a new full backup.

### Restore target is not empty

Prefer a move-aside flow:

```bash
systemctl stop opendr
mv /var/lib/opendr/data /var/lib/opendr/data.before-restore
mkdir -p /var/lib/opendr/data
opendr-restore --backup /var/backups/opendr/full --target-data-dir /var/lib/opendr/data
```

Use `--force` only when intentional.

## Monitoring

Default endpoints:

```bash
curl http://127.0.0.1:9090/metrics
curl http://127.0.0.1:9090/health
open http://127.0.0.1:9090/console
```

If these fail, check `[monitoring] metrics_address`, `metrics_port`,
`metrics_path`, `health_path`, and `console_path`, and confirm no other process
owns the port. Console login requires the configured root DN and password.
Use `docs/MANAGEMENT_CONSOLE.md` for the console route map and login details.

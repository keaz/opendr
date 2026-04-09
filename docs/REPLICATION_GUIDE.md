# OpenDR LDAP Replication Guide

This guide covers the implemented OpenDR replication path: provider-consumer replication over LDAP with a refresh phase, cookie-based resume, and an optional long-lived listener for live updates after refresh.

## Overview

OpenDR replication has two roles:

- **Provider**: accepts normal LDAP writes, records them in the changelog, and exposes replication data through the LDAP server path.
- **Consumer**: refreshes from the provider, persists a replication cookie, and optionally keeps a live search open for post-refresh changes.

When `enable_change_listening = true`, steady-state replication is listener-based rather than timer-based polling. `sync_interval_secs` then controls refresh and reconnect cadence, not normal change latency. If listening is disabled, the consumer falls back to periodic refreshes.

## How to Enable Replication

1. Run each instance from its own working directory.
2. Put `config/server.toml` and `config/log4rs.yml` under that directory.
3. Enable `[replication]` in the provider and consumer configs.
4. Use distinct `ldap_port`, `data_directory`, and `state_storage_path` values when both instances run on the same host.
5. For LMDB-backed servers, use a `{SSHA512}` `root_password`.

OpenDR loads `config/server.toml` and `config/log4rs.yml` from the current working directory. A typical layout looks like:

```text
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

## Provider Configuration

Create `/srv/opendr-provider/config/server.toml`:

```toml
[server]
bind_address = "0.0.0.0"
ldap_port = 1389
base_dn = "dc=example,dc=com"
root_user_dn = "cn=manager"
root_password = "{SSHA512}<generated-hash>"
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

Notes:

- The provider automatically wraps the backend with changelog tracking in `provider` and `both` modes.
- `root_user_dn` is the relative DN. The full bind DN is `cn=manager,dc=example,dc=com`.
- The provider serves replication data through the normal LDAP server. There is no separate polling service to start.

## Consumer Configuration

Create `/srv/opendr-consumer/config/server.toml`:

```toml
[server]
bind_address = "0.0.0.0"
ldap_port = 2389
base_dn = "dc=example,dc=com"
root_user_dn = "cn=manager"
root_password = "{SSHA512}<generated-hash>"
organization_name = "Example Org Replica"

[backend]
backend_type = "lmdb"
data_directory = "./data"
lmdb_max_size = 10737418240
lmdb_max_readers = 126

[replication]
enabled = true
mode = "consumer"
provider_url = "ldap://provider.example.com:1389"
bind_dn = "cn=replication,dc=example,dc=com"
bind_password = "replication_password"
sync_interval_secs = 3600
max_retry_attempts = 3
retry_delay_secs = 5
enable_change_listening = true
heartbeat_interval_secs = 60
state_storage_path = "./data/replication_state"
```

Notes:

- `bind_dn` and `bind_password` are the canonical consumer authentication keys.
- `provider_bind_dn` and `provider_bind_password` are still accepted as aliases for backward compatibility.
- `state_storage_path` stores the last replication cookie so a restart can resume instead of forcing a full refresh.
- If you want refresh-only behavior, set `enable_change_listening = false`.

## Replication Settings Reference

These are the runtime settings that matter for replication:

- `enabled`: turns replication on.
- `mode`: `provider`, `consumer`, or `both`.
- `provider_url`: LDAP URL of the upstream provider in consumer mode.
- `bind_dn` / `bind_password`: optional credentials used by the consumer to bind to the provider.
- `changelog_capacity`: number of retained provider-side change records.
- `sync_interval_secs`: refresh and reconnect cadence for the consumer.
- `max_retry_attempts`: number of retry attempts for consumer reconnects.
- `retry_delay_secs`: delay between retry attempts.
- `enable_change_listening`: enables the long-lived listener after refresh.
- `heartbeat_interval_secs`: keepalive interval used for replication sessions.
- `state_storage_path`: consumer cookie storage path.

## Starting the Provider and Consumer

Copy the logging config into each working directory and start each server from that directory:

```bash
cp config/log4rs.yml /srv/opendr-provider/config/log4rs.yml
cp config/log4rs.yml /srv/opendr-consumer/config/log4rs.yml

cd /srv/opendr-provider && opendr
cd /srv/opendr-consumer && opendr
```

On startup:

1. The provider enables changelog tracking and begins serving replication requests.
2. The consumer loads its cookie from `state_storage_path` if one exists.
3. The consumer performs a refresh from the provider.
4. If `enable_change_listening = true`, the consumer starts a long-lived listener from the refreshed cookie and stays connected for live changes.

Expected consumer log signals include:

- `Replication consumer entered listening mode`
- `Replicated ADD: ...`
- `Replicated MODIFY: ...`
- `Replicated DELETE: ...`

## systemd Example

Because OpenDR loads config relative to the working directory, set `WorkingDirectory` instead of passing a config path:

**Provider**

```ini
[Unit]
Description=OpenDR LDAP Provider
After=network.target

[Service]
Type=simple
User=opendr
Group=opendr
WorkingDirectory=/etc/opendr/provider
ExecStart=/usr/local/bin/opendr
Restart=always
RestartSec=10
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
```

**Consumer**

```ini
[Unit]
Description=OpenDR LDAP Consumer
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=opendr
Group=opendr
WorkingDirectory=/etc/opendr/consumer
ExecStart=/usr/local/bin/opendr
Restart=always
RestartSec=10
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
```

## Verifying Listener-Based Replication

The server initializes the base DN, the root user, `ou=People`, and `ou=Groups` automatically. After both servers are up, add an entry on the provider:

```bash
ldapadd -x -H ldap://provider.example.com:1389 \
  -D "cn=manager,dc=example,dc=com" -w '<provider-root-password>' <<EOF
dn: uid=listener-proof,ou=People,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: listener-proof
sn: Proof
uid: listener-proof
EOF
```

Then query the consumer:

```bash
ldapsearch -x -H ldap://consumer.example.com:2389 \
  -D "cn=manager,dc=example,dc=com" -w '<consumer-root-password>' \
  -b "ou=People,dc=example,dc=com" "(uid=listener-proof)"
```

Listener mode is working when:

- the consumer already logged `Replication consumer entered listening mode`
- the new entry appears immediately on the consumer
- the update arrives without waiting for `sync_interval_secs`

To force polling-only behavior for comparison:

```toml
[replication]
enabled = true
mode = "consumer"
provider_url = "ldap://provider.example.com:1389"
sync_interval_secs = 30
enable_change_listening = false
```

## Multiple Consumers

One provider can feed multiple consumers. Each consumer needs its own:

- `ldap_port`
- `data_directory`
- `state_storage_path`

Only `provider_url` points to the shared provider:

```toml
[replication]
enabled = true
mode = "consumer"
provider_url = "ldap://provider.example.com:1389"
bind_dn = "cn=replication,dc=example,dc=com"
bind_password = "replication_password"
enable_change_listening = true
state_storage_path = "./data/replication_state"
```

## Both Mode

`mode = "both"` starts the provider and consumer services inside the same process. Use it when a node must consume from an upstream provider and also serve downstream consumers.

```toml
[replication]
enabled = true
mode = "both"
provider_url = "ldap://other-master.example.com:1389"
bind_dn = "cn=replication,dc=example,dc=com"
bind_password = "replication_password"
changelog_capacity = 100000
sync_interval_secs = 3600
enable_change_listening = true
state_storage_path = "./data/replication_state"
```

This is still a provider-consumer model. If more than one node accepts writes, you need an external conflict strategy.

## Testing

Useful validation commands:

```bash
cargo test --test config_integration --test replication_consumer_integration --test replication_e2e -- --nocapture
```

Focused listener-stream verification:

```bash
cargo test --test replication_e2e test_e2e_listening_replication_stream_emits_live_change -- --nocapture
```

There is also a manual helper script:

```bash
./scripts/test_replication.sh
```

## Troubleshooting

### Consumer Never Enters Listening Mode

- Verify `enable_change_listening = true`.
- Check that the consumer can bind to `provider_url`.
- Check consumer logs for listener startup errors.
- Confirm the provider is running the listener-capable build and not an older polling-only binary.

### Updates Only Arrive on Refresh Boundaries

- Listener mode is disabled or failing.
- Confirm the consumer logged `Replication consumer entered listening mode`.
- Increase `sync_interval_secs` temporarily during testing. If changes still arrive quickly, you are on the listener path rather than polling.

### Full Resync Needed

Stop the consumer, clear the persisted state, and restart:

```bash
rm -rf /srv/opendr-consumer/data/replication_state/*
```

Use the actual `state_storage_path` from your config if it differs.

### Provider and Consumer Conflict on One Host

- Use different `ldap_port` values.
- Use different `data_directory` values.
- Run each instance from a different working directory so they do not share `config/` or `log/`.

### Authentication Failures

Test the consumer credentials directly against the provider:

```bash
ldapsearch -x -H ldap://provider.example.com:1389 \
  -D "cn=replication,dc=example,dc=com" -w replication_password \
  -b "dc=example,dc=com" "(objectClass=*)"
```

## Security Notes

- Prefer `ldaps://...` provider URLs in production.
- Use dedicated read-only replication credentials when possible.
- Store `state_storage_path` on persistent storage.
- Keep provider and consumer logs separate when running multiple instances on one host.

## References

- [Replication Quick Start](REPLICATION_QUICKSTART.md)
- [Configuration Reference](CONFIGURATION.md)
- [Consumer FSM Architecture](replication_consumer_fsm.md)
- [RFC 4533: LDAP Content Synchronization Operation](https://datatracker.ietf.org/doc/html/rfc4533)

# OpenDR Replication Quick Start

This guide shows the shortest working path for provider-consumer replication with listener-based updates.
Use the canonical runtime keys shown below: `mode`, `bind_dn`, `bind_password(_env|_file)`, `changelog_capacity`, and `enable_change_listening`. If you start from `opendr-setup` output, normalize older fields such as `role`, `provider_bind_dn`, and `changelog_max_entries` before launching the binary.

## Before You Start

- Run each instance from its own working directory.
- The `opendr` binary loads `config/server.toml` and `config/log4rs.yml` from the current working directory.
- If you run provider and consumer on the same host, give them different `ldap_port` and `data_directory` values.
- For LMDB-backed servers, `root_password` must be the generated `{SSHA512}` hash from `opendr-setup` or another existing OpenDR config.

Example layout:

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

## 1. Provider Configuration

Create `/srv/opendr-provider/config/server.toml`:

```toml
[server]
bind_address = "0.0.0.0"
ldap_port = 1389
replica_id = 1
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

## 2. Consumer Configuration

Create `/srv/opendr-consumer/config/server.toml`:

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
provider_url = "ldap://provider.example.com:1389"
bind_dn = "cn=manager,dc=example,dc=com"
bind_password_file = "/run/secrets/opendr-replication-bind-password"
sync_interval_secs = 3600
max_retry_attempts = 5
retry_delay_secs = 1
enable_change_listening = true
heartbeat_interval_secs = 60
state_storage_path = "./data/replication_state"
```

`bind_dn` and `bind_password` are the canonical consumer authentication keys. `provider_bind_dn` and `provider_bind_password` remain supported as aliases. In production, use a dedicated read-only replication account on the provider and inject the secret through `bind_password_env` or `bind_password_file`.

Legacy setup/template fields such as `role`, `changelog_enabled`, `changelog_max_entries`, `max_batch_size`, and `enable_streaming` are not the canonical documented runtime surface for these examples.

## 3. Start Both Servers

Copy the logging config into each runtime directory, then start each process from that directory:

```bash
cp config/log4rs.yml /srv/opendr-provider/config/log4rs.yml
cp config/log4rs.yml /srv/opendr-consumer/config/log4rs.yml

cd /srv/opendr-provider && opendr
cd /srv/opendr-consumer && opendr
```

## 4. Verify Listener-Based Replication

Add an entry on the provider:

```bash
ldapadd -x -H ldap://provider.example.com:1389 \
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

Query the consumer:

```bash
ldapsearch -x -H ldap://consumer.example.com:2389 \
  -D "cn=manager,dc=example,dc=com" -w '<consumer-root-password>' \
  -b "ou=People,dc=example,dc=com" "(uid=replication-test)"
```

The consumer is in listener mode when its log contains:

- `Replication consumer entered listening mode`
- `Replicated ADD: ...` or `Replicated MODIFY: ...`

With `enable_change_listening = true`, those updates arrive over the live LDAP stream instead of waiting for `sync_interval_secs`.

## 5. Polling-Only Mode

If you want periodic refreshes instead of the live stream:

```toml
[replication]
enabled = true
mode = "consumer"
provider_url = "ldap://provider.example.com:1389"
sync_interval_secs = 30
enable_change_listening = false
```

In that mode, the consumer uses scheduled refresh cycles and does not hold the long-lived replication search open.

## Common Settings

- `enabled`: turns replication on
- `mode`: `provider`, `consumer`, or `both`
- `changelog_capacity`: provider-side number of retained change records
- `provider_url`: consumer-side LDAP endpoint of the provider
- `bind_dn` / `bind_password`: canonical consumer authentication keys
- `sync_interval_secs`: refresh and reconnect cadence
- `enable_change_listening`: enables the long-lived listener after refresh
- `state_storage_path`: filesystem path for the persisted replication cookie
- `heartbeat_interval_secs`: keepalive interval for replication sessions

## Quick Validation

Run the focused live-stream integration test:

```bash
cargo test --test replication_e2e test_e2e_listening_replication_stream_emits_live_change -- --nocapture
```

## Troubleshooting

- If the consumer never enters listener mode, verify `enable_change_listening = true`.
- If the consumer cannot connect, verify `provider_url`, `bind_dn`, and `bind_password`.
- If provider and consumer run on the same machine, verify the two instances do not share the same `ldap_port` or `data_directory`.
- If you need a fresh refresh, stop the consumer and remove the contents of `state_storage_path`.

## Next Steps

- Read the full [Replication Guide](REPLICATION_GUIDE.md)
- Review the replication configuration section in [Configuration](CONFIGURATION.md)
- Use the setup flow in [Setup Wizard Guide](SETUP_WIZARD_GUIDE.md)

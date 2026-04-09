# OpenDR Setup Wizard Guide

The `opendr-setup` utility helps create an initial OpenDR configuration and data directory layout. This guide focuses on the replication choices that matter for provider and consumer deployments.

## Quick Start

Interactive setup:

```bash
opendr-setup interactive
```

Non-interactive setup:

```bash
opendr-setup generate-config --output setup-config.toml
opendr-setup non-interactive --config setup-config.toml
```

For non-interactive mode, start from the generated template instead of inventing the file format manually.

## Replication Choices in the Wizard

The wizard asks whether to enable replication and then collects role-specific values.

### Provider Flow

Current prompts include:

- `Enable replication?`
- `Select replication role`
- `Enable changelog tracking?`
- `Maximum changelog entries`
- `Maximum batch size (entries per sync)`
- `Enable real-time streaming?`

For provider deployments, the important runtime outcome is a `[replication]` block like this:

```toml
[replication]
enabled = true
mode = "provider"
changelog_capacity = 100000
heartbeat_interval_secs = 60
```

### Consumer Flow

Current prompts include:

- `Enable replication?`
- `Select replication role`
- `Provider URL`
- `Authenticate to provider?`
- `Provider bind DN`
- `Provider bind password`
- `Synchronization interval (seconds)`
- `Maximum retry attempts`
- `Enable continuous change listening?`
- `Replication state storage path`

For consumer deployments, the important runtime outcome is a `[replication]` block like this:

```toml
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

`bind_dn` and `bind_password` are the canonical runtime keys. `provider_bind_dn` and `provider_bind_password` remain accepted as aliases. In production, point them at a dedicated read-only replication account on the provider.

## Recommended Runtime Layout

Run each server from its own working directory because `opendr` loads `config/server.toml` and `config/log4rs.yml` from the current working directory:

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

When both instances run on the same host:

- use different `ldap_port` values
- use different `data_directory` values
- use different `state_storage_path` values

## Example Provider Runtime Config

After setup, verify the provider runtime config looks like this:

```toml
[server]
bind_address = "0.0.0.0"
ldap_port = 1389
base_dn = "dc=company,dc=com"
root_user_dn = "cn=manager"
root_password = "{SSHA512}<generated-hash>"
organization_name = "Company Directory"

[backend]
backend_type = "lmdb"
data_directory = "./data"
lmdb_max_size = 10737418240
lmdb_max_readers = 126

[replication]
enabled = true
mode = "provider"
changelog_capacity = 200000
heartbeat_interval_secs = 60
```

## Example Consumer Runtime Config

After setup, verify the consumer runtime config looks like this:

```toml
[server]
bind_address = "0.0.0.0"
ldap_port = 2389
base_dn = "dc=company,dc=com"
root_user_dn = "cn=manager"
root_password = "{SSHA512}<generated-hash>"
organization_name = "Company Directory Replica"

[backend]
backend_type = "lmdb"
data_directory = "./data"
lmdb_max_size = 10737418240
lmdb_max_readers = 126

[replication]
enabled = true
mode = "consumer"
provider_url = "ldap://10.0.1.100:1389"
bind_dn = "cn=replication,dc=company,dc=com"
bind_password = "replication_password"
sync_interval_secs = 3600
max_retry_attempts = 5
retry_delay_secs = 5
enable_change_listening = true
heartbeat_interval_secs = 60
state_storage_path = "/var/lib/opendr/repl_state"
```

`root_user_dn` is the relative DN. The full bind DN is `cn=manager,dc=company,dc=com`.

## End-to-End Setup Example

### 1. Configure the Provider

Run the wizard on the provider host, then copy the logging config into place:

```bash
opendr-setup interactive
cp config/log4rs.yml /srv/opendr-provider/config/log4rs.yml
cd /srv/opendr-provider && opendr
```

### 2. Configure the Consumer

Run the wizard on the consumer host, then copy the logging config into place:

```bash
opendr-setup interactive
cp config/log4rs.yml /srv/opendr-consumer/config/log4rs.yml
cd /srv/opendr-consumer && opendr
```

### 3. Verify Listener-Based Replication

Add a user on the provider:

```bash
ldapadd -x -H ldap://10.0.1.100:1389 \
  -D "cn=manager,dc=company,dc=com" -w '<provider-root-password>' <<EOF
dn: uid=wizard-test,ou=People,dc=company,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: wizard-test
sn: Test
uid: wizard-test
EOF
```

Query it from the consumer:

```bash
ldapsearch -x -H ldap://10.0.1.101:2389 \
  -D "cn=manager,dc=company,dc=com" -w '<consumer-root-password>' \
  -b "ou=People,dc=company,dc=com" "(uid=wizard-test)"
```

The consumer is using the listener path when its log contains `Replication consumer entered listening mode` before the write and then logs `Replicated ADD:` for the new entry.

## Validation and Recovery

Check setup state:

```bash
opendr-setup status
cat ./config/setup.state
```

Generate a password hash for `root_password`:

```bash
opendr-setup hash-password "MySecurePassword123"
```

Reset setup state if you need to start over:

```bash
opendr-setup reset
opendr-setup reset --force
```

If you need the consumer to do a full refresh again, stop it, clear `state_storage_path`, and restart.

## Best Practices

- Keep `enable_change_listening = true` unless you intentionally want polling-style refreshes.
- Use a persistent `state_storage_path` so the consumer can resume from its last cookie.
- Use dedicated replication credentials in production when the provider requires authentication.
- Prefer `ldaps://...` for provider URLs outside local test environments.
- Verify provider and consumer do not share the same `ldap_port` or `data_directory`.

## Next Steps

- [Replication Quick Start](REPLICATION_QUICKSTART.md)
- [Replication Guide](REPLICATION_GUIDE.md)
- [Configuration Reference](CONFIGURATION.md)

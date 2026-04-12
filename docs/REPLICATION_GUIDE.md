# OpenDR Replication Guide

OpenDR replication is listener-based provider-consumer replication over LDAP. A consumer performs an initial refresh from the provider, persists its replication cookie, and then keeps a long-lived LDAP listener open for live changes.

Poll-based consumer replication has been removed. `enable_change_listening = false` is invalid for `consumer` and `both` modes.

## Runtime Layout

Run each OpenDR instance from its own working directory because the server loads `config/server.toml` and `config/log4rs.yml` relative to the current directory:

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

When provider and consumer run on the same host, use different `ldap_port`, `replica_id`, `data_directory`, and `state_storage_path` values.

## Provider Config

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

## Consumer Config

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
bind_dn = "cn=replication,dc=example,dc=com"
bind_password_file = "/run/secrets/opendr-replication-bind-password"
max_retry_attempts = 3
retry_delay_secs = 5
enable_change_listening = true
heartbeat_interval_secs = 60
state_storage_path = "./data/replication_state"
```

`bind_dn` and `bind_password` are the canonical consumer authentication keys. The aliases `provider_bind_dn`, `provider_bind_password`, `replication_bind_dn`, and `replication_bind_password` are still accepted for older configs. Prefer `bind_password_env` or `bind_password_file` for production secrets.

## Start Instances

```bash
cp config/log4rs.yml /srv/opendr-provider/config/log4rs.yml
cp config/log4rs.yml /srv/opendr-consumer/config/log4rs.yml

cd /srv/opendr-provider && opendr
cd /srv/opendr-consumer && opendr
```

The consumer is on the listener path when it logs `Replication consumer entered listening mode`.

## Verify Replication

Add an entry on the provider:

```bash
ldapadd -x -H ldap://provider.example.com:1389 \
  -D "cn=manager,dc=example,dc=com" -w '<provider-root-password>' <<EOF
dn: uid=listener-test,ou=People,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: listener-test
sn: Test
uid: listener-test
EOF
```

Query the consumer:

```bash
ldapsearch -x -H ldap://consumer.example.com:2389 \
  -D "cn=manager,dc=example,dc=com" -w '<consumer-root-password>' \
  -b "ou=People,dc=example,dc=com" "(uid=listener-test)"
```

If `sync_interval_secs` appears in an older config, it is no longer a polling cadence. Listener reconnect behavior is controlled by `max_retry_attempts` and `retry_delay_secs`.

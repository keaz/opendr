# OpenDR Replication Quick Start

A quick reference guide for setting up LDAP replication with OpenDR.

## 5-Minute Setup

### 1. Provider Configuration

Create `/etc/opendr/provider.toml`:

```toml
[server]
bind_address = "0.0.0.0:389"
base_dn = "dc=example,dc=com"
admin_dn = "cn=admin,dc=example,dc=com"
admin_password = "change_me"

[backend]
backend_type = "Lmdb"
lmdb_path = "/var/lib/opendr/provider/data"
lmdb_map_size = 10737418240

[replication]
role = "provider"
changelog_enabled = true
changelog_max_entries = 100000
```

### 2. Consumer Configuration

Create `/etc/opendr/consumer.toml`:

```toml
[server]
bind_address = "0.0.0.0:389"
base_dn = "dc=example,dc=com"
admin_dn = "cn=admin,dc=example,dc=com"
admin_password = "change_me"

[backend]
backend_type = "Lmdb"
lmdb_path = "/var/lib/opendr/consumer/data"
lmdb_map_size = 10737418240

[replication]
role = "consumer"
provider_url = "ldap://provider.example.com:389"
sync_interval_secs = 30
enable_change_listening = true
state_storage_path = "/var/lib/opendr/consumer/state"
```

### 3. Start Servers

```bash
# On provider machine
opendr --config /etc/opendr/provider.toml

# On consumer machine
opendr --config /etc/opendr/consumer.toml
```

### 4. Verify Replication

```bash
# Add entry to provider
ldapadd -x -H ldap://provider.example.com:389 \
    -D "cn=admin,dc=example,dc=com" -w change_me <<EOF
dn: cn=Test User,dc=example,dc=com
objectClass: person
cn: Test User
sn: User
EOF

# Check on consumer (wait ~30 seconds)
ldapsearch -x -H ldap://consumer.example.com:389 \
    -b "dc=example,dc=com" "(cn=Test User)"
```

## Quick Test

Run the automated test script:

```bash
./scripts/test_replication.sh
```

This will:
- Build OpenDR
- Start provider on port 3890
- Start consumer on port 3891
- Add test data
- Verify replication
- Display logs

## Common Configuration Options

### Provider Settings

```toml
[replication]
role = "provider"
changelog_enabled = true           # Enable change tracking
changelog_max_entries = 100000     # Max entries in memory
max_batch_size = 100               # Entries per batch
consumer_timeout_secs = 30         # Consumer operation timeout
enable_streaming = true            # Real-time updates
heartbeat_interval_secs = 60       # Connection keepalive
```

### Consumer Settings

```toml
[replication]
role = "consumer"
provider_url = "ldap://provider:389"         # Provider URL
provider_bind_dn = "cn=repl,dc=example,dc=com"  # Optional auth
provider_bind_password = "secret"            # Optional auth
sync_interval_secs = 30                      # Sync frequency
max_retry_attempts = 3                       # Retry on failure
retry_delay_secs = 5                         # Delay between retries
enable_change_listening = true               # Real-time listening
state_storage_path = "/var/lib/opendr/state" # State file location
```

## Monitoring Commands

```bash
# Check provider entry count
ldapsearch -x -H ldap://provider:389 -b "dc=example,dc=com" \
    "(objectClass=*)" | grep -c "^dn:"

# Check consumer entry count
ldapsearch -x -H ldap://consumer:389 -b "dc=example,dc=com" \
    "(objectClass=*)" | grep -c "^dn:"

# Test connectivity
nc -zv provider.example.com 389

# View consumer replication state
cat /var/lib/opendr/consumer/state/cookie
```

## Troubleshooting

### Consumer not syncing?

1. **Check connectivity**: `nc -zv provider.example.com 389`
2. **Verify credentials**: Test LDAP bind manually
3. **Check logs**: Look for errors in consumer logs
4. **Reset state**: Delete `/var/lib/opendr/consumer/state/*` and restart

### Replication lag?

1. **Reduce sync interval**: Set `sync_interval_secs = 10`
2. **Increase batch size**: Set `max_batch_size = 500`
3. **Check network**: `ping provider.example.com`

### Changelog growing too large?

1. **Increase capacity**: `changelog_max_entries = 500000`
2. **More frequent syncs**: Reduce consumer `sync_interval_secs`

## Architecture

```
┌──────────────┐                  ┌──────────────┐
│   Provider   │                  │   Consumer   │
│   (Master)   │                  │  (Replica)   │
│              │                  │              │
│  Directory   │                  │  Directory   │
│     +        │  ──Replication──>│              │
│  Changelog   │                  │              │
└──────────────┘                  └──────────────┘
```

**Replication Flow:**
1. **Refresh Phase**: Consumer requests all entries
2. **Present Phase**: Provider sends changelog entries
3. **Persist Phase**: Consumer persists state
4. **Listen Phase**: Consumer listens for real-time changes

## Next Steps

- Read the full [Replication Guide](REPLICATION_GUIDE.md)
- Configure [TLS encryption](REPLICATION_GUIDE.md#security-considerations)
- Set up [monitoring](REPLICATION_GUIDE.md#monitoring)
- Review [performance tuning](REPLICATION_GUIDE.md#performance-tuning)

## Key Files

- Provider FSM: `src/replication_provider_fsm.rs`
- Consumer FSM: `src/replication_consumer_fsm.rs`
- Implementation: `src/replication.rs`
- Tests: `tests/replication_integration.rs`
- Test Script: `scripts/test_replication.sh`

## RFC Reference

OpenDR implements [RFC 4533: LDAP Content Synchronization Operation](https://datatracker.ietf.org/doc/html/rfc4533)

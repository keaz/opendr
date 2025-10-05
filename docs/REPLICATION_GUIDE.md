# OpenDR LDAP Replication Guide

This guide explains how to configure and use the replication feature in OpenDR LDAP server, which implements RFC 4533 (LDAP Content Synchronization Operation).

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Configuration](#configuration)
  - [Provider Configuration](#provider-configuration)
  - [Consumer Configuration](#consumer-configuration)
- [Setup Examples](#setup-examples)
  - [Single Provider, Single Consumer](#single-provider-single-consumer)
  - [Multiple Consumers](#multiple-consumers)
- [Testing Replication](#testing-replication)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)
- [Advanced Topics](#advanced-topics)

## Overview

OpenDR supports LDAP replication using a **provider-consumer** (master-slave) model:

- **Provider (Master)**: The authoritative source of directory data that tracks all changes
- **Consumer (Replica)**: Receives and applies changes from the provider to maintain a synchronized copy

### Key Features

- **RFC 4533 Compliance**: Implements LDAP Content Synchronization Operation
- **Changelog Tracking**: Maintains a persistent log of all directory modifications
- **Cookie-Based Resume**: Consumers can resume synchronization from their last known state
- **Real-Time Updates**: Supports both refresh (initial sync) and persist (continuous updates) phases
- **State Management**: Automatic state persistence for reliable recovery

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Provider Server                            │
│                                                                 │
│  ┌──────────────┐      ┌──────────────┐      ┌──────────────┐   │
│  │  Directory   │──┬──>│  Changelog   │─────>│ Replication  │   │
│  │  Backend     │  │   │  Tracker     │      │ Provider FSM │   │
│  └──────────────┘  │   └──────────────┘      └──────┬───────┘   │
│                    │                                 │          │
│                    └─────────────────────────────────┘          │
└─────────────────────────────────────────┬───────────────────────┘
                                          │
                                          │ TCP Connection
                                          │ (LDAP Protocol)
                                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Consumer Server                            │
│                                                                 │
│  ┌──────────────┐      ┌──────────────┐      ┌──────────────┐   │
│  │ Replication  │─────>│    Batch     │─────>│  Directory   │   │
│  │ Consumer FSM │      │  Processor   │      │  Backend     │   │
│  └──────┬───────┘      └──────────────┘      └──────────────┘   │
│         │                                                       │
│         │              ┌──────────────┐                         │
│         └─────────────>│    State     │                         │
│                        │   Manager    │                         │
│                        └──────────────┘                         │
└─────────────────────────────────────────────────────────────────┘
```

## Configuration

### Provider Configuration

Create a configuration file for your provider server (e.g., `provider.toml`):

```toml
[server]
bind_address = "0.0.0.0:389"
base_dn = "dc=example,dc=com"
admin_dn = "cn=admin,dc=example,dc=com"
admin_password = "provider_admin_password"

[backend]
backend_type = "Lmdb"
lmdb_path = "/var/lib/opendr/provider/data"
lmdb_map_size = 10737418240  # 10GB
max_readers = 126

[replication]
# Role: provider (master) or consumer (replica)
role = "provider"

# Enable changelog tracking
changelog_enabled = true

# Maximum number of changelog entries to keep in memory
# Older entries are pruned when this limit is exceeded
changelog_max_entries = 100000

# Maximum number of entries to send in a single batch
max_batch_size = 100

# Timeout for consumer operations (in seconds)
consumer_timeout_secs = 30

# Enable real-time change notifications
enable_streaming = true

# Heartbeat interval for maintaining connections (in seconds)
heartbeat_interval_secs = 60
```

### Consumer Configuration

Create a configuration file for your consumer server (e.g., `consumer.toml`):

```toml
[server]
bind_address = "0.0.0.0:389"
base_dn = "dc=example,dc=com"
admin_dn = "cn=admin,dc=example,dc=com"
admin_password = "consumer_admin_password"

[backend]
backend_type = "Lmdb"
lmdb_path = "/var/lib/opendr/consumer/data"
lmdb_map_size = 10737418240  # 10GB
max_readers = 126

[replication]
# Role: consumer (replica)
role = "consumer"

# Provider server URL
provider_url = "ldap://provider.example.com:389"

# Provider credentials (if authentication required)
provider_bind_dn = "cn=replication,dc=example,dc=com"
provider_bind_password = "replication_password"

# Synchronization interval (in seconds)
# How often to check for changes from provider
sync_interval_secs = 30

# Retry attempts for failed operations
max_retry_attempts = 3

# Delay between retry attempts (in seconds)
retry_delay_secs = 5

# Enable continuous listening for changes (persist mode)
enable_change_listening = true

# Maximum time to wait for state persistence (in seconds)
state_persistence_timeout_secs = 10

# Path to store replication state and cookies
state_storage_path = "/var/lib/opendr/consumer/replication_state"
```

## Setup Examples

### Single Provider, Single Consumer

This is the most common replication setup.

#### Step 1: Set Up Provider Server

1. Create provider data directory:
```bash
mkdir -p /var/lib/opendr/provider/data
```

2. Create provider configuration (`/etc/opendr/provider.toml`) as shown above.

3. Initialize the provider with base data:
```bash
# Start the provider server
opendr --config /etc/opendr/provider.toml

# In another terminal, add base entries
ldapadd -x -H ldap://localhost:389 \
    -D "cn=admin,dc=example,dc=com" \
    -w provider_admin_password \
    -f base_entries.ldif
```

Example `base_entries.ldif`:
```ldif
dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

dn: ou=people,dc=example,dc=com
objectClass: organizationalUnit
ou: people

dn: ou=groups,dc=example,dc=com
objectClass: organizationalUnit
ou: groups
```

#### Step 2: Set Up Consumer Server

1. Create consumer data directory:
```bash
mkdir -p /var/lib/opendr/consumer/data
mkdir -p /var/lib/opendr/consumer/replication_state
```

2. Create consumer configuration (`/etc/opendr/consumer.toml`) as shown above.

3. Start the consumer server:
```bash
opendr --config /etc/opendr/consumer.toml
```

The consumer will automatically:
- Connect to the provider
- Perform initial synchronization (refresh phase)
- Enter continuous listening mode (persist phase)

#### Step 3: Verify Replication

1. Add an entry to the provider:
```bash
ldapadd -x -H ldap://provider.example.com:389 \
    -D "cn=admin,dc=example,dc=com" \
    -w provider_admin_password <<EOF
dn: cn=John Doe,ou=people,dc=example,dc=com
objectClass: person
cn: John Doe
sn: Doe
EOF
```

2. Verify the entry appears on the consumer:
```bash
ldapsearch -x -H ldap://consumer.example.com:389 \
    -b "ou=people,dc=example,dc=com" \
    "(cn=John Doe)"
```

### Multiple Consumers

You can have multiple consumers replicating from a single provider.

```
                    ┌─────────────┐
                    │  Provider   │
                    │ (Master)    │
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
              ▼            ▼            ▼
         ┌─────────┐  ┌─────────┐  ┌─────────┐
         │Consumer1│  │Consumer2│  │Consumer3│
         │(Replica)│  │(Replica)│  │(Replica)│
         └─────────┘  └─────────┘  └─────────┘
```

Each consumer should have its own configuration file pointing to the same provider:

**consumer1.toml**, **consumer2.toml**, **consumer3.toml**:
```toml
[replication]
role = "consumer"
provider_url = "ldap://provider.example.com:389"
# ... other settings
```

## Testing Replication

### Using the Test Script

OpenDR includes a comprehensive test script that automatically sets up two servers:

```bash
# Make the script executable (if not already)
chmod +x scripts/test_replication.sh

# Run the test script
./scripts/test_replication.sh
```

The script will:
1. Build the OpenDR binary
2. Create provider and consumer configurations
3. Start both servers
4. Add test data to the provider
5. Wait for replication to occur
6. Verify that data was replicated to the consumer
7. Display server logs

### Manual Testing

#### 1. Monitor Changelog on Provider

Check the provider's changelog entries:
```bash
# This requires admin access to the provider's internal state
# (Implementation-specific; consult provider API/tools)
```

#### 2. Check Consumer State

View the consumer's replication state (cookie):
```bash
# Check the state file
cat /var/lib/opendr/consumer/replication_state/cookie
```

#### 3. Test Different Operations

**Add Operation:**
```bash
ldapadd -x -H ldap://provider.example.com:389 \
    -D "cn=admin,dc=example,dc=com" -w password \
    -f new_entry.ldif
```

**Modify Operation:**
```bash
ldapmodify -x -H ldap://provider.example.com:389 \
    -D "cn=admin,dc=example,dc=com" -w password <<EOF
dn: cn=John Doe,ou=people,dc=example,dc=com
changetype: modify
replace: mail
mail: john.doe@example.com
EOF
```

**Delete Operation:**
```bash
ldapdelete -x -H ldap://provider.example.com:389 \
    -D "cn=admin,dc=example,dc=com" -w password \
    "cn=John Doe,ou=people,dc=example,dc=com"
```

After each operation, verify the change appears on the consumer.

## Monitoring

### Replication Metrics

Monitor these key metrics to ensure healthy replication:

1. **Replication Lag**: Time difference between provider changes and consumer application
2. **Changelog Size**: Number of entries in the provider's changelog
3. **Consumer State**: Current replication cookie/sequence number
4. **Connection Status**: Whether consumer is connected to provider
5. **Error Rate**: Number of failed replication operations

### Log Files

Check server logs for replication events:

**Provider Logs:**
```
[INFO] Replication consumer 'consumer1' connected
[INFO] Starting sync replication for consumer 'consumer1' from cookie 'seq-1234'
[INFO] Sent 150 entries to consumer 'consumer1' during refresh phase
[INFO] Streaming 5 changelog entries to consumer 'consumer1'
```

**Consumer Logs:**
```
[INFO] Connecting to provider 'ldap://provider.example.com:389'
[INFO] Starting consumption from cookie 'seq-1234'
[INFO] Received batch of 150 entries
[INFO] Applied 150 entries successfully
[INFO] State persisted with cookie 'seq-1384'
[INFO] Listening for real-time changes
```

### Health Checks

Implement health checks for both servers:

```bash
# Check if provider is responding
ldapsearch -x -H ldap://provider.example.com:389 \
    -b "" -s base "(objectClass=*)" namingContexts

# Check if consumer is responding
ldapsearch -x -H ldap://consumer.example.com:389 \
    -b "" -s base "(objectClass=*)" namingContexts

# Compare entry counts (should be identical when synced)
PROVIDER_COUNT=$(ldapsearch -x -H ldap://provider.example.com:389 \
    -b "dc=example,dc=com" "(objectClass=*)" | grep -c "^dn:")

CONSUMER_COUNT=$(ldapsearch -x -H ldap://consumer.example.com:389 \
    -b "dc=example,dc=com" "(objectClass=*)" | grep -c "^dn:")

echo "Provider entries: $PROVIDER_COUNT"
echo "Consumer entries: $CONSUMER_COUNT"
```

## Troubleshooting

### Consumer Not Syncing

**Symptoms:** Consumer is running but not receiving updates from provider.

**Solutions:**

1. **Check network connectivity:**
```bash
# From consumer server
nc -zv provider.example.com 389
```

2. **Verify provider URL in consumer config:**
```bash
# Ensure provider_url is correct
grep provider_url /etc/opendr/consumer.toml
```

3. **Check authentication credentials:**
```bash
# Test manual connection from consumer to provider
ldapsearch -x -H ldap://provider.example.com:389 \
    -D "cn=replication,dc=example,dc=com" \
    -w replication_password \
    -b "dc=example,dc=com" "(objectClass=*)"
```

4. **Review consumer logs for errors:**
```bash
tail -f /var/log/opendr/consumer.log
```

### Replication Lag

**Symptoms:** Changes appear on consumer with significant delay.

**Solutions:**

1. **Reduce sync interval:**
```toml
# In consumer.toml
sync_interval_secs = 10  # Reduce from 30 to 10 seconds
```

2. **Increase batch size (if network allows):**
```toml
# In provider.toml
max_batch_size = 500  # Increase from 100
```

3. **Check network latency:**
```bash
ping -c 10 provider.example.com
```

### Changelog Overflow

**Symptoms:** Provider's changelog is growing too large or old entries are being pruned before consumers can sync.

**Solutions:**

1. **Increase changelog capacity:**
```toml
# In provider.toml
changelog_max_entries = 500000  # Increase from 100000
```

2. **Ensure consumers sync more frequently:**
```toml
# In consumer.toml
sync_interval_secs = 10
```

3. **Monitor changelog size and adjust accordingly**

### State Corruption

**Symptoms:** Consumer reports invalid cookie or state errors.

**Solutions:**

1. **Reset consumer state (full resync):**
```bash
# Stop consumer
systemctl stop opendr-consumer

# Delete replication state
rm -rf /var/lib/opendr/consumer/replication_state/*

# Restart consumer (will perform full sync)
systemctl start opendr-consumer
```

2. **Verify state file permissions:**
```bash
ls -la /var/lib/opendr/consumer/replication_state/
```

### Connection Timeouts

**Symptoms:** Consumer frequently disconnects from provider.

**Solutions:**

1. **Increase heartbeat frequency:**
```toml
# In provider.toml
heartbeat_interval_secs = 30  # Reduce from 60
```

2. **Increase consumer timeout:**
```toml
# In provider.toml
consumer_timeout_secs = 60  # Increase from 30
```

## Advanced Topics

### Custom Changelog Persistence

By default, the changelog is stored in memory. For production deployments, you may want to persist it to disk:

```rust
// Example: Implement custom ChangelogTracker with LMDB backend
use opendr::replication::ChangelogTracker;

let tracker = ChangelogTracker::with_persistence(
    "/var/lib/opendr/provider/changelog",
    500000, // max_entries
)?;
```

### Filtered Replication

You can configure consumers to replicate only specific subtrees or entries:

```toml
# In consumer.toml (future feature)
[replication]
role = "consumer"
provider_url = "ldap://provider.example.com:389"

# Only replicate this subtree
base_dn = "ou=people,dc=example,dc=com"

# Optional filter
filter = "(objectClass=person)"
```

### Multi-Master Replication

While OpenDR currently supports provider-consumer (master-slave) replication, multi-master replication can be achieved by:

1. Running multiple providers
2. Configuring each provider as a consumer of the others
3. Implementing conflict resolution (future feature)

**Note:** Multi-master replication is experimental and not recommended for production use without proper conflict resolution mechanisms.

### Monitoring with Prometheus

Export replication metrics to Prometheus:

```toml
# In server configuration
[metrics]
enabled = true
bind_address = "0.0.0.0:9090"

[metrics.replication]
# Export these metrics
changelog_size = true
consumer_count = true
replication_lag_seconds = true
entries_replicated_total = true
replication_errors_total = true
```

Access metrics:
```bash
curl http://localhost:9090/metrics | grep replication
```

### Security Considerations

1. **Use TLS for replication connections:**
```toml
[replication]
provider_url = "ldaps://provider.example.com:636"
tls_enabled = true
tls_cert_path = "/etc/opendr/certs/cert.pem"
tls_key_path = "/etc/opendr/certs/key.pem"
tls_ca_cert_path = "/etc/opendr/certs/ca.pem"
```

2. **Create dedicated replication user:**
```bash
ldapadd -x -H ldap://provider.example.com:389 \
    -D "cn=admin,dc=example,dc=com" -w password <<EOF
dn: cn=replication,dc=example,dc=com
objectClass: simpleSecurityObject
objectClass: organizationalRole
cn: replication
userPassword: {SSHA}replication_hashed_password
description: Replication service account
EOF
```

3. **Restrict replication user permissions:**
   - Grant read-only access on provider
   - Limit access to only necessary subtrees
   - Use separate credentials for each consumer

### Performance Tuning

1. **Optimize batch size based on network:**
```toml
# High-bandwidth, low-latency network
max_batch_size = 1000

# Low-bandwidth or high-latency network
max_batch_size = 50
```

2. **Adjust LMDB settings:**
```toml
[backend]
lmdb_map_size = 21474836480  # 20GB for large directories
max_readers = 256  # Increase for high concurrency
```

3. **Enable compression (future feature):**
```toml
[replication]
enable_compression = true
compression_level = 6  # 1-9, higher = more compression
```

## References

- [RFC 4533: LDAP Content Synchronization Operation](https://datatracker.ietf.org/doc/html/rfc4533)
- [OpenDR Replication Architecture](../src/replication.rs)
- [Provider FSM Implementation](../src/replication_provider_fsm.rs)
- [Consumer FSM Implementation](../src/replication_consumer_fsm.rs)

## Support

For issues or questions:
- GitHub Issues: https://github.com/yourusername/opendr/issues
- Documentation: https://docs.opendr.io
- Community: https://community.opendr.io

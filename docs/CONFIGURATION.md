# OpenDR LDAP Server - Configuration Guide

This document provides comprehensive information about configuring the OpenDR LDAP server.

## Table of Contents

1. [Overview](#overview)
2. [Configuration File Format](#configuration-file-format)
3. [Environment Variables](#environment-variables)
4. [Configuration Sections](#configuration-sections)
5. [Validation](#validation)
6. [Examples](#examples)
7. [Best Practices](#best-practices)

## Overview

OpenDR uses TOML (Tom's Obvious, Minimal Language) for configuration files. The configuration system provides:

- **Human-readable format**: Easy to read and edit
- **Environment variable overrides**: Any setting can be overridden via environment variables
- **Validation**: Configuration is validated on startup to catch errors early
- **Sensible defaults**: Works out-of-the-box with minimal configuration
- **Hot reload support**: Configuration can be reloaded without server restart (future feature)

## Configuration File Format

Configuration files use TOML format and are organized into sections:

```toml
[server]
ldap_port = 1389
base_dn = "dc=example,dc=com"

[backend]
backend_type = "lmdb"
data_directory = "./data"

[rate_limit]
enabled = true
global_requests_per_second = 1000
```

### File Locations

The server looks for configuration in the following order:

1. `./config/server.toml` (current working directory)
2. Built-in defaults

The binary also expects `config/log4rs.yml` in the same working directory tree.

## Environment Variables

Any configuration value can be overridden using environment variables with the prefix `OPENDR_` and double underscores (`__`) as separators:

```bash
# Override server settings
export OPENDR_SERVER__LDAP_PORT=389
export OPENDR_SERVER__BASE_DN="dc=myorg,dc=com"

# Override backend settings
export OPENDR_BACKEND__BACKEND_TYPE="lmdb"
export OPENDR_BACKEND__DATA_DIRECTORY="/var/lib/opendr"

# Override rate limit settings
export OPENDR_RATE_LIMIT__ENABLED=true
export OPENDR_RATE_LIMIT__GLOBAL_REQUESTS_PER_SECOND=5000

# Nested settings use additional underscores
export OPENDR_RATE_LIMIT__OPERATION_LIMITS__BIND=20
export OPENDR_RATE_LIMIT__OPERATION_LIMITS__SEARCH=100
```

Environment variables take precedence over file configuration.

## Configuration Sections

### 1. Server Settings

Basic server configuration including ports, DNS, and timeouts.

```toml
[server]
bind_address = "127.0.0.1"          # Address to bind to
ldap_port = 1389                     # LDAP port (non-TLS)
ldaps_port = 1636                    # LDAPS port (TLS/SSL)
hostname = "localhost"               # Server hostname
runtime = "fsm"                      # Listener runtime: "fsm" or "legacy"
replica_id = 1                       # Unique CSN replica ID for this server
base_dn = "dc=example,dc=com"        # Base DN for directory
root_user_dn = "cn=admin"            # Admin user DN
root_password_file = "/run/secrets/opendr-root-password" # Admin secret source
organization_name = "Example Org"    # Organization name
read_buffer_size = 4096             # Socket read buffer size (bytes)
operation_timeout_secs = 300        # Operation timeout (seconds)
cleanup_interval_secs = 60          # Cleanup interval (seconds)
max_concurrent_operations = 100     # Max operations per connection
```

**Key Settings:**
- `ldap_port` and `ldaps_port` must be different
- `runtime` accepts `"fsm"` and `"legacy"`; `fsm` is the default production listener runtime
- `replica_id` must be non-zero, and must be unique per replicated node
- `base_dn` cannot be empty
- `root_password_env` and `root_password_file` let you inject the admin secret without storing it inline
- `root_password` is still supported for local development, but production deployments should avoid committing it

### 2. Backend Settings

Database backend configuration for persistent storage.

```toml
[backend]
backend_type = "lmdb"                                    # Backend: "memory" or "lmdb"
data_directory = "./data"                                # Data directory path
lmdb_max_size = 10737418240                             # Max DB size (10 GB)
lmdb_max_readers = 126                                  # Max concurrent readers
import_sample_data = false                              # Import sample data on startup
indexed_attributes = ["cn", "uid", "mail", "objectClass"]  # Indexed attributes
```

**Backend Types:**
- `memory`: In-memory storage (no persistence, for testing)
- `lmdb`: Lightning Memory-Mapped Database (production-ready)

**LMDB Settings:**
- `lmdb_max_size`: Maximum database size in bytes
- `lmdb_max_readers`: Maximum concurrent read transactions (up to 126)
- `indexed_attributes`: Attributes to index for faster searches

### 3. TLS/SSL Settings

TLS/SSL configuration for encrypted connections.

```toml
[tls]
enabled = false                      # Enable TLS/SSL
cert_file = "certs/server.crt"      # Certificate file path
key_file = "certs/server.key"       # Private key file path
ca_file = "certs/ca.crt"            # CA certificate (optional)
require_client_cert = false         # Require client certificates
min_tls_version = "1.2"             # Minimum TLS version: "1.2" or "1.3"
```

**Important:**
- Certificate and key files must exist when TLS is enabled
- Use TLS 1.3 for best security
- Client certificate verification is optional

### 4. Resource Management Settings

Control resource limits to prevent abuse and ensure stability.

```toml
[resources]
max_connections = 1000                # Maximum total connections
max_connections_per_ip = 10           # Maximum connections per IP
max_operations_per_connection = 100   # Maximum operations per connection
max_memory_per_connection = 10485760  # Max memory per connection (10 MB)
max_total_memory = 1073741824         # Max total memory (1 GB)
connection_idle_timeout_secs = 600    # Idle timeout (10 minutes)
```

**Best Practices:**
- Set `max_connections_per_ip` lower than `max_connections`
- Adjust memory limits based on available system memory
- Monitor resource usage and adjust limits accordingly

### 5. Rate Limiting Settings

Protect against denial-of-service attacks and abusive clients.

```toml
[rate_limit]
enabled = true                          # Enable rate limiting
global_requests_per_second = 1000       # Global limit (all clients)
per_client_requests_per_second = 100    # Per-client limit
burst_size = 50                         # Burst allowance
window_duration_secs = 1                # Rate limit window
adaptive_enabled = true                 # Enable adaptive limiting
adaptive_threshold = 0.8                # Adaptation threshold (80%)
adaptive_multiplier = 0.5               # Reduction factor (50%)
auto_ban_threshold = 100                # Violations before auto-ban
auto_ban_duration_secs = 300            # Ban duration (5 minutes)
blacklist = []                          # Blocked IPs
whitelist = []                          # Allowed IPs (bypass limits)

[rate_limit.operation_limits]
bind = 10        # Auth attempts per second
search = 50      # Searches per second
modify = 20      # Modifications per second
add = 20         # Adds per second
delete = 10      # Deletes per second
modifydn = 10    # Renames per second
compare = 30     # Compares per second
extended = 20    # Extended ops per second
```

**Adaptive Rate Limiting:**
- When server load exceeds `adaptive_threshold`, limits are reduced by `adaptive_multiplier`
- Helps maintain service during attack or high load
- Returns to normal when load decreases

**Auto-Ban:**
- Clients exceeding rate limits `auto_ban_threshold` times are temporarily banned
- Ban duration is `auto_ban_duration_secs`
- Helps protect against persistent abusers

### 6. Replication Settings

Configure multi-server replication for high availability.

```toml
[replication]
enabled = false                                 # Enable replication
mode = "provider"                               # Mode: "provider", "consumer", "both"
provider_url = "ldap://provider.example.com"    # Provider URL (consumer mode)
bind_dn = "cn=replicator,dc=example,dc=com"     # Canonical consumer bind key
bind_password_file = "/run/secrets/opendr-replication-bind-password" # Canonical consumer bind secret source
changelog_capacity = 10000                      # Provider changelog size
sync_interval_secs = 3600                       # Refresh/reconnect cadence (consumer mode)
max_retry_attempts = 3                          # Consumer retry attempts
retry_delay_secs = 5                            # Consumer retry delay
enable_change_listening = true                  # Keep a live LDAP stream open
heartbeat_interval_secs = 60                    # Provider/consumer keepalive interval
state_storage_path = "./data/replication_state" # Consumer cookie/state storage
```

**Replication Modes:**
- `provider`: Provides data to consumers (source)
- `consumer`: Receives data from provider (replica)
- `both`: Acts as both provider and consumer (multi-master)

**Consumer Configuration:**
- Requires `provider_url`; `bind_dn` and `bind_password` are optional
- `bind_dn` / `bind_password` are the canonical keys; `provider_bind_dn` / `provider_bind_password` are accepted as aliases
- `bind_password_env` and `bind_password_file` let you inject consumer credentials without storing them inline
- `server.replica_id` must be unique per replicated node so generated CSNs do not collide
- `sync_interval_secs` controls refresh and reconnect cadence; it is not the steady-state live update latency when listening is enabled
- `enable_change_listening` keeps a long-lived LDAP search open for live updates after refresh
- `state_storage_path` stores the replication cookie between restarts
- When running multiple instances on the same host, use distinct `ldap_port` and `data_directory` values
- `mode` is the canonical role selector for the shipped runtime. Older setup/template fields such as `role`, `changelog_enabled`, `changelog_max_entries`, `max_batch_size`, and `enable_streaming` are not part of the supported runtime config surface and should be normalized before launch

**Provider Behavior:**
- The provider exposes live replication data through the normal LDAP server path
- Internally, the server intercepts replication stream searches and forwards changelog changes as streaming search results
- This keeps the replication path inside the LDAP protocol instead of requiring a separate transport

### 7. Monitoring and Metrics Settings

Expose metrics for monitoring and observability.

```toml
[monitoring]
enabled = true                # Enable metrics collection
metrics_address = "127.0.0.1" # Metrics bind address
metrics_port = 9090           # Metrics port
metrics_path = "/metrics"     # Prometheus metrics endpoint
health_path = "/health"       # Health check endpoint
```

**Prometheus Integration:**
- Metrics are exported in Prometheus text format
- Access metrics at `http://<metrics_address>:<metrics_port>/metrics`
- Health check at `http://<metrics_address>:<metrics_port>/health`

### 8. Audit Logging Settings

Security audit trail configuration.

```toml
[audit]
enabled = true                      # Enable audit logging
log_file = "./logs/audit.log"       # Log file path
format = "json"                     # Format: "json", "syslog", "text"
level = "info"                      # Level: "debug", "info", "warning", "error", "critical"
log_authentication = true           # Log auth events
log_authorization = true            # Log authz events
log_modifications = true            # Log data changes
log_connections = true              # Log connections
```

**Log Formats:**
- `json`: Structured JSON (best for log aggregation)
- `syslog`: RFC 5424 syslog format
- `text`: Human-readable plain text

**Audit Levels:**
- `debug`: All events including verbose details
- `info`: Normal operational events
- `warning`: Potential issues
- `error`: Errors and failures
- `critical`: Critical security events

### 9. Access Control Settings

Fine-grained access control configuration.

```toml
[access_control]
enabled = true                          # Enable access control
default_policy = "deny"                 # Default: "allow" or "deny"
rules_file = "./config/aci_rules.toml"  # ACI rules file (optional)
```

**Default Policies:**
- `deny`: Deny all access unless explicitly allowed (recommended)
- `allow`: Allow all access unless explicitly denied (less secure)

### 10. Performance Tuning Settings

Optimize server performance for your workload.

```toml
[performance]
worker_threads = 0              # Worker threads (0 = auto-detect)
schema_validation = true        # Enable schema validation
indexing_enabled = true         # Enable indexing
cache_size = 1000              # Entry cache size
query_optimization = true       # Enable query optimization
```

**Worker Threads:**
- `0`: Auto-detect based on CPU cores (recommended)
- `1-N`: Explicit number of worker threads

**Performance vs. Correctness:**
- Disable `schema_validation` for better performance (not recommended)
- Disable `indexing_enabled` to save memory (slower searches)
- Disable `query_optimization` for debugging

## Validation

Configuration is validated on server startup. Common validation errors:

### Port Conflicts
```
Error: LDAP and LDAPS ports must be different
```
**Solution:** Use different port numbers for `ldap_port` and `ldaps_port`

### Invalid Backend
```
Error: Invalid backend type: postgresql
```
**Solution:** Use "memory" or "lmdb"

### TLS Certificate Not Found
```
Error: TLS certificate file not found: certs/server.crt
```
**Solution:** Create certificate file or disable TLS

### Invalid IP Address
```
Error: Invalid blacklist IP: not-an-ip
```
**Solution:** Use valid IPv4 or IPv6 addresses

### Replication Configuration
```
Error: provider_url required for consumer mode
```
**Solution:** Set `provider_url` when using consumer mode. Enable `enable_change_listening` if you want the consumer to keep a live stream open after the initial refresh. If the provider requires authentication, configure `bind_dn` and `bind_password` as well.

## Examples

### Minimal Configuration

```toml
[server]
base_dn = "dc=myorg,dc=com"
root_password_env = "OPENDR_ROOT_PASSWORD"
```

All other settings use defaults.

### Development Configuration

```toml
[server]
bind_address = "127.0.0.1"
ldap_port = 1389
base_dn = "dc=dev,dc=local"
root_password_env = "OPENDR_DEV_ROOT_PASSWORD"

[backend]
backend_type = "memory"
import_sample_data = true

[rate_limit]
enabled = false

[audit]
format = "text"
level = "debug"
```

### Production Configuration

```toml
[server]
bind_address = "0.0.0.0"
ldap_port = 389
ldaps_port = 636
hostname = "ldap.example.com"
base_dn = "dc=example,dc=com"
root_user_dn = "cn=admin,dc=example,dc=com"
root_password_file = "/run/secrets/opendr-root-password"

[backend]
backend_type = "lmdb"
data_directory = "/var/lib/opendr/data"
lmdb_max_size = 21474836480  # 20 GB
indexed_attributes = ["cn", "uid", "mail", "sn", "givenName", "objectClass"]

[tls]
enabled = true
cert_file = "/etc/opendr/certs/server.crt"
key_file = "/etc/opendr/certs/server.key"
min_tls_version = "1.3"

[resources]
max_connections = 2000
max_connections_per_ip = 50

[rate_limit]
enabled = true
global_requests_per_second = 5000
adaptive_enabled = true

[monitoring]
enabled = true
metrics_address = "0.0.0.0"

[audit]
enabled = true
log_file = "/var/log/opendr/audit.log"
format = "json"
level = "info"

[access_control]
enabled = true
default_policy = "deny"
```

### High-Availability Replication

**Provider Server:**
```toml
[server]
bind_address = "0.0.0.0"
base_dn = "dc=example,dc=com"

[replication]
enabled = true
mode = "provider"
changelog_capacity = 50000
heartbeat_interval_secs = 60
```

**Consumer Server:**
```toml
[server]
bind_address = "0.0.0.0"
base_dn = "dc=example,dc=com"

[replication]
enabled = true
mode = "consumer"
provider_url = "ldap://provider.example.com:389"
bind_dn = "cn=replicator,dc=example,dc=com"
bind_password_file = "/run/secrets/opendr-replication-bind-password"
sync_interval_secs = 30
enable_change_listening = true
max_retry_attempts = 3
retry_delay_secs = 5
state_storage_path = "/var/lib/opendr/replication_state"
```

## Best Practices

### Security

1. **Use Strong Passwords**: Use a strong admin secret and inject it through `root_password_env` or `root_password_file`
2. **Enable TLS**: Use TLS 1.3 for encrypted connections
3. **Enable Rate Limiting**: Protect against DoS attacks
4. **Enable Audit Logging**: Track security events
5. **Use Default Deny**: Set `access_control.default_policy = "deny"`
6. **Whitelist Trusted IPs**: Add monitoring systems to rate limit whitelist

### Performance

1. **Auto-detect Worker Threads**: Use `worker_threads = 0`
2. **Enable Indexing**: Index frequently searched attributes
3. **Tune Cache Size**: Set based on entry count and available memory
4. **Monitor Metrics**: Use Prometheus integration for monitoring
5. **Adjust Resource Limits**: Based on actual usage patterns

### Reliability

1. **Use LMDB Backend**: For persistence and durability
2. **Set Appropriate Timeouts**: Balance responsiveness and stability
3. **Enable Replication**: For high availability
4. **Monitor Resource Usage**: Prevent exhaustion
5. **Regular Backups**: Backup data directory periodically

### Operations

1. **Use Environment Variables or Secret Files**: Prefer `*_env` or `*_file` for credentials and keep the committed TOML secret-free
2. **Version Control**: Keep configuration in version control
3. **Test Changes**: Validate configuration before deployment
4. **Monitor Logs**: Check audit and application logs regularly
5. **Document Customizations**: Note why settings deviate from defaults

## Configuration Migration

### From Previous Versions

If migrating from an older configuration format:

1. Review the example configuration files
2. Map old settings to new configuration sections
3. Validate the new configuration
4. Test in a development environment
5. Deploy to production

### Environment-Specific Configurations

Create separate configuration files for each environment:

- `config/server.development.toml` - Development settings
- `config/server.staging.toml` - Staging settings
- `config/server.production.toml` - Production settings

Use environment variables or per-environment working directories to select the appropriate file:

```bash
# Development
mkdir -p /srv/opendr-dev/config
cp config/server.development.toml /srv/opendr-dev/config/server.toml
cp config/log4rs.yml /srv/opendr-dev/config/log4rs.yml
cd /srv/opendr-dev && opendr

# Production
mkdir -p /srv/opendr-prod/config
cp config/server.production.toml /srv/opendr-prod/config/server.toml
cp config/log4rs.yml /srv/opendr-prod/config/log4rs.yml
cd /srv/opendr-prod && opendr
```

## Troubleshooting

### Configuration Not Loaded

**Problem:** Server uses default values instead of configuration file

**Solutions:**
- Verify file path is correct
- Check file permissions (must be readable)
- Ensure TOML syntax is valid
- Check for environment variable overrides

### Validation Errors

**Problem:** Configuration validation fails on startup

**Solutions:**
- Read the error message carefully
- Fix the specific validation issue
- Check value ranges and types
- Ensure required values are set

### Performance Issues

**Problem:** Server performance is poor

**Solutions:**
- Enable indexing for searched attributes
- Increase `cache_size`
- Add more `worker_threads`
- Check resource limits
- Monitor metrics for bottlenecks

## Additional Resources

- [Installation Guide](INSTALLATION.md)
- [Operations Guide](OPERATIONS.md)
- [Monitoring Guide](MONITORING.md)
- [Replication Guide](REPLICATION_GUIDE.md)
- [Security Best Practices](SECURITY.md)

## Support

For questions or issues:

1. Check this documentation
2. Review example configuration files
3. Check server logs
4. Open an issue on GitHub

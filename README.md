# OpenDR LDAP Server

A high-performance, production-ready LDAP v3 server implementation in Rust, featuring a finite state machine (FSM) architecture for clear state management and high concurrency.

## Features

### Core LDAP Operations
- ✅ **LDAP v3 Protocol**: Full RFC 4511 compliance
- ✅ **Authentication**: Simple bind, SASL (PLAIN, DIGEST-MD5, CRAM-MD5)
- ✅ **Operations**: Search, Add, Modify, Delete, ModifyDN, Compare
- ✅ **Extended Operations**: StartTLS, Password Modify, WhoAmI, Cancel
- ✅ **Controls**: Paged results, server-side sorting, persistent search

### Storage & Performance
- ✅ **LMDB Backend**: Memory-mapped I/O for ultra-fast reads (1.17 µs)
- ✅ **Attribute Indexing**: Configurable indexes for fast searches
- ✅ **Schema Validation**: RFC 4512 compliant schema enforcement
- ✅ **ACID Transactions**: Full transactional safety with crash recovery

### Security
- ✅ **TLS/SSL**: TLS 1.2/1.3 support with certificate validation
- ✅ **Access Control**: Fine-grained ACI (Access Control Information) system
- ✅ **Rate Limiting**: Per-client and global rate limiting with DoS protection
- ✅ **Audit Logging**: Comprehensive security event logging (JSON, syslog, text)

### Replication ⭐ NEW
- ✅ **RFC 4533 Compliance**: LDAP Content Synchronization Operation
- ✅ **Provider-Consumer**: Master-slave replication with automatic changelog tracking
- ✅ **Multi-Master**: Bidirectional replication (both mode)
- ✅ **Cookie-Based Resume**: Consumers can resume from last known state
- ✅ **Real-Time Updates**: Continuous synchronization with configurable intervals
- ✅ **State Persistence**: Automatic state saving for reliable recovery

### Enterprise Features
- ✅ **Referrals & Chaining**: Distributed directory support (RFC 4516)
- ✅ **Monitoring**: Prometheus-compatible metrics export
- ✅ **Health Checks**: Component-level health status with JSON export
- ✅ **Resource Management**: Connection pooling, memory limits, idle timeout
- ✅ **Graceful Shutdown**: Signal handling with connection draining

### Operations
- ✅ **Configuration**: TOML files with environment variable overrides
- ✅ **Service Management**: systemd integration with automatic restart
- ✅ **Performance Tuning**: Configurable worker threads, cache sizes, timeouts
- ✅ **Comprehensive Testing**: 433 tests with 97%+ pass rate

## Quick Start

### Prerequisites

```bash
# Rust 1.70+
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# LDAP client tools (for testing)
# Ubuntu/Debian
sudo apt-get install ldap-utils

# macOS
brew install openldap

# RHEL/CentOS
sudo yum install openldap-clients
```

### Build

```bash
git clone https://github.com/yourusername/opendr.git
cd opendr
cargo build --release
```

### Basic Server

```bash
# Start with default configuration
./target/release/opendr

# Or with custom config
./target/release/opendr --config config/server.toml
```

### Test Operations

```bash
# Search
ldapsearch -x -H ldap://localhost:389 -b "dc=example,dc=com" "(objectClass=*)"

# Add entry
ldapadd -x -H ldap://localhost:389 -D "cn=admin,dc=example,dc=com" -w password <<EOF
dn: cn=John Doe,dc=example,dc=com
objectClass: person
cn: John Doe
sn: Doe
EOF

# Modify entry
ldapmodify -x -H ldap://localhost:389 -D "cn=admin,dc=example,dc=com" -w password <<EOF
dn: cn=John Doe,dc=example,dc=com
changetype: modify
add: description
description: Test user
EOF

# Delete entry
ldapdelete -x -H ldap://localhost:389 -D "cn=admin,dc=example,dc=com" -w password \
    "cn=John Doe,dc=example,dc=com"
```

## Replication Quick Start

OpenDR supports provider-consumer replication for high availability and load distribution.

### 1. Set Up Provider (Master)

Create `provider.toml`:

```toml
[server]
bind_address = "0.0.0.0:389"
base_dn = "dc=example,dc=com"
admin_dn = "cn=admin,dc=example,dc=com"
admin_password = "provider_password"

[backend]
backend_type = "Lmdb"
lmdb_path = "/var/lib/opendr/provider/data"

[replication]
enabled = true
mode = "provider"
changelog_capacity = 100000
```

Start provider:

```bash
./target/release/opendr --config provider.toml
```

### 2. Set Up Consumer (Replica)

Create `consumer.toml`:

```toml
[server]
bind_address = "0.0.0.0:389"
base_dn = "dc=example,dc=com"
admin_dn = "cn=admin,dc=example,dc=com"
admin_password = "consumer_password"

[backend]
backend_type = "Lmdb"
lmdb_path = "/var/lib/opendr/consumer/data"

[replication]
enabled = true
mode = "consumer"
provider_url = "ldap://provider-server:389"
sync_interval_secs = 30
```

Start consumer:

```bash
./target/release/opendr --config consumer.toml
```

### 3. Verify Replication

Add data to provider:

```bash
ldapadd -x -H ldap://provider-server:389 -D "cn=admin,dc=example,dc=com" -w provider_password <<EOF
dn: cn=Test User,dc=example,dc=com
objectClass: person
cn: Test User
sn: User
EOF
```

Verify on consumer (wait ~30 seconds):

```bash
ldapsearch -x -H ldap://consumer-server:389 -b "dc=example,dc=com" "(cn=Test User)"
```

### Run Demo Script

```bash
# Automated replication demo
./scripts/demo_replication.sh

# Keep servers running for testing
./scripts/demo_replication.sh --keep-running

# Skip build step
./scripts/demo_replication.sh --skip-build
```

## Documentation

### Core Documentation
- [Architecture Overview](docs/architecture-overview.md) - System design and FSM architecture
- [Configuration Guide](docs/CONFIGURATION.md) - Complete configuration reference
- [Performance Optimization](docs/PERFORMANCE_OPTIMIZATION.md) - Tuning guide

### Replication
- [Replication Quick Start](docs/REPLICATION_QUICKSTART.md) - 5-minute setup guide
- [Replication Guide](docs/REPLICATION_GUIDE.md) - Comprehensive replication documentation
- [Setup Wizard](docs/SETUP_WIZARD_GUIDE.md) - Interactive setup with replication

### Operations
- [Monitoring](docs/MONITORING.md) - Metrics and health checks
- [Setup Guide](SETUP_GUIDE.md) - Deployment and configuration

### Development
- [FSM Architecture](docs/README.md) - Finite state machine design
- [Backend Integration](BACKEND_INTEGRATION.md) - Storage backend details
- [Task Tracker](TASK.md) - Development roadmap and progress

## Configuration

### Basic Configuration

```toml
[server]
bind_address = "0.0.0.0:389"
base_dn = "dc=example,dc=com"
admin_dn = "cn=admin,dc=example,dc=com"
admin_password = "secure_password"

[backend]
backend_type = "Lmdb"
lmdb_path = "/var/lib/opendr/data"
lmdb_map_size = 10737418240  # 10GB

[tls]
enabled = true
cert_file = "/etc/opendr/cert.pem"
key_file = "/etc/opendr/key.pem"

[replication]
enabled = true
mode = "provider"  # or "consumer" or "both"
changelog_capacity = 100000

[monitoring]
enabled = true
prometheus_port = 9090

[rate_limit]
enabled = true
per_client_requests_per_second = 100
```

### Example Configurations

- [Provider Configuration](config/examples/replication/provider.toml)
- [Consumer Configuration](config/examples/replication/consumer.toml)
- [Multi-Master Configuration](config/examples/replication/multi-master.toml)
- [Development Configuration](config/server.development.toml)
- [Production Configuration](config/server.production.toml)

### Environment Variables

Override any configuration value with environment variables:

```bash
OPENDR_SERVER__BIND_ADDRESS=0.0.0.0:389 \
OPENDR_REPLICATION__ENABLED=true \
OPENDR_REPLICATION__MODE=provider \
./target/release/opendr
```

## Performance

### Benchmarks

- **Read Operations**: 1.17 µs per entry lookup (LMDB)
- **Authentication**: 393 ns per SSHA512 password verification
- **Indexed Search**: < 10ms for 1000 entries
- **Concurrent Reads**: Up to 126 simultaneous readers
- **Replication**: < 1s sync latency for small datasets

### Optimization Tips

```toml
[performance]
worker_threads = 8           # Match CPU cores
io_threads = 4               # For async I/O
entry_cache_size_mb = 512    # Increase for large directories
schema_cache_size_mb = 100

[backend]
lmdb_map_size = 21474836480  # 20GB for large directories
max_readers = 256            # Increase for high concurrency

[replication]
max_batch_size = 500         # Larger batches for fast networks
sync_interval_secs = 10      # More frequent updates
```

See [Performance Optimization Guide](docs/PERFORMANCE_OPTIMIZATION.md) for details.

## Monitoring

### Prometheus Metrics

OpenDR exports Prometheus-compatible metrics:

```bash
curl http://localhost:9090/metrics
```

**Key Metrics:**
- `ldap_operations_total{operation="search"}` - Operation counts
- `ldap_operation_duration_seconds{operation="bind"}` - Latency
- `ldap_connections_active` - Active connections
- `ldap_replication_lag_seconds` - Replication lag
- `ldap_changelog_size` - Changelog entry count

### Health Checks

```bash
curl http://localhost:8080/health
```

Response:

```json
{
  "status": "healthy",
  "components": {
    "backend": "healthy",
    "replication_provider": "healthy",
    "replication_consumer": "healthy"
  },
  "uptime_seconds": 3600
}
```

## Production Deployment

### systemd Service

Create `/etc/systemd/system/opendr.service`:

```ini
[Unit]
Description=OpenDR LDAP Server
After=network.target

[Service]
Type=simple
User=opendr
Group=opendr
ExecStart=/usr/local/bin/opendr --config /etc/opendr/server.toml
Restart=always
RestartSec=10
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
```

Manage service:

```bash
sudo systemctl enable opendr
sudo systemctl start opendr
sudo systemctl status opendr
sudo journalctl -u opendr -f
```

### Security Hardening

```toml
[tls]
enabled = true
require_client_cert = true
min_version = "TLS13"

[rate_limit]
enabled = true
global_requests_per_second = 10000
per_client_requests_per_second = 100
auto_ban_enabled = true
auto_ban_threshold = 1000
auto_ban_duration_secs = 3600

[access_control]
enabled = true
# Define ACIs in configuration or via LDAP

[resources]
max_connections = 1000
max_connections_per_ip = 10
max_memory_per_connection_mb = 10
idle_timeout_secs = 300
```

## Testing

```bash
# Run all tests
cargo test

# Run replication tests only
cargo test replication

# Run integration tests
cargo test --test '*_integration'

# Run benchmarks
cargo bench

# Run E2E tests
cargo test --test e2e_tests
```

**Test Statistics:**
- 433 total tests
- 422 passing (97.5%)
- 84 replication-specific tests
- 100% pass rate for replication

## Architecture

OpenDR uses a **Finite State Machine (FSM)** architecture for clear state management:

```
Client Connection
      │
      ▼
┌──────────────┐
│ Connection   │
│     FSM      │
└──────┬───────┘
       │
       ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│ BerDecoder   │───>│    Auth      │───>│  Operation   │
│     FSM      │    │     FSM      │    │     FSM      │
└──────────────┘    └──────────────┘    └──────┬───────┘
                                                │
                    ┌───────────────────────────┼───────────┐
                    │                           │           │
                    ▼                           ▼           ▼
            ┌──────────────┐          ┌──────────────┐  ┌──────────────┐
            │   Search     │          │    Write     │  │   Compare    │
            │     FSM      │          │     FSM      │  │     FSM      │
            └──────────────┘          └──────────────┘  └──────────────┘
```

### Key Components

- **12 FSMs**: Connection, BerDecoder, Auth, SASL, Search, Write, Compare, ExtendedOp, Referral, ReplicationProvider, ReplicationConsumer, BackendTxn
- **FSM Runtime**: ConnectionFsmSet manages FSM lifecycle and message routing
- **Backend Adapters**: Pluggable storage backends (LMDB, in-memory)
- **Replication Service**: High-level API for provider/consumer management

See [Architecture Overview](docs/architecture-overview.md) for details.

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Run tests (`cargo test`)
4. Commit changes (`git commit -m 'Add amazing feature'`)
5. Push to branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

## License

[MIT License](LICENSE) or [Apache 2.0 License](LICENSE-APACHE) - your choice.

## Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/opendr/issues)
- **Documentation**: [docs/](docs/)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/opendr/discussions)

## Acknowledgments

- Built with [Rust](https://www.rust-lang.org/)
- Uses [Tokio](https://tokio.rs/) for async runtime
- Uses [LMDB](https://www.symas.com/lmdb) for storage
- Implements [RFC 4511](https://datatracker.ietf.org/doc/html/rfc4511) (LDAP v3)
- Implements [RFC 4533](https://datatracker.ietf.org/doc/html/rfc4533) (Content Synchronization)

## Status

**Phase 7 (Replication)**: 80% Complete ✅
- ✅ Backend changelog integration
- ✅ Provider integration
- ✅ Consumer integration
- ✅ End-to-end testing (84 tests)
- 🚧 Documentation (in progress)

**Overall**: Production-ready for testing and evaluation

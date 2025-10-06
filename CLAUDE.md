# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

OpenDR is a **Rust-based LDAP v3 server** implementing the full LDAP protocol with a **finite state machine (FSM) architecture**. It features asynchronous I/O using Tokio, pluggable backends (LMDB and in-memory), and enterprise features including replication, rate limiting, and schema validation.

## Build & Development Commands

```bash
# Build the project
cargo build

# Run the LDAP server (default: 127.0.0.1:1389)
cargo run

# Run the setup wizard
cargo run --bin opendr-setup interactive

# Run all tests
cargo test

# Run specific test module
cargo test <module_name>
cargo test server_handlers

# Run single test
cargo test <test_name>

# Run tests with output
cargo test -- --nocapture

# Run benchmarks
cargo bench

# Specific benchmarks
cargo bench --bench backend_benchmarks
cargo bench --bench fsm_benchmarks
cargo bench --bench schema_benchmarks
cargo bench --bench server_benchmarks

# Run with debug logging
RUST_LOG=debug cargo run

# Build for release
cargo build --release

# Check code without building
cargo check
```

## Architecture Overview

### FSM-Based Design

The server uses **12 finite state machine (FSM) traits** for concurrent operation handling:

**Transport Layer:**
- `ConnectionFsm` - TCP/TLS lifecycle management
- `BerDecoderFsm` - LDAP message parsing

**Authentication Layer:**
- `AuthFsm` - Simple authentication
- `SaslFsm` - SASL authentication

**Operations Layer:**
- `SearchFsm` - Search operations
- `WriteFsm` - Add/Modify/Delete operations
- `CompareFsm` - Compare operations
- `ExtendedOpFsm` - Extended operations (StartTLS, Password Modify, WhoAmI, Cancel)

**Distribution Layer:**
- `ReferralFsm` - Referral handling
- `ReplicationProviderFsm` - Master replication
- `ReplicationConsumerFsm` - Replica replication

**Storage Layer:**
- `BackendTxnFsm` - Transaction management

### Per-Connection FSM Pattern

Each LDAP connection maintains:
- 1× Connection FSM
- 1× BER Decoder FSM
- 1× Auth FSM (Simple or SASL)
- N× Operation FSMs (parallel operations)
- ≤2× Replication FSMs (optional)
- 1 per operation Backend Txn FSM

## Key Components & Files

### Core FSM Layer
- `src/fsm.rs` - All FSM trait definitions (start here for architecture)
- `src/fsm_runtime.rs` - FSM runtime management
- `src/fsm_server.rs` - FSM-based server implementation
- FSM implementations: `src/*_fsm.rs` (auth_fsm, search_fsm, write_fsm, etc.)

### Server & Backend
- `src/main.rs` - Server entry point, backend initialization
- `src/server.rs` - TCP connection handling and request routing
- `src/backend.rs` - `DirectoryBackend` trait and `MockBackend` implementation
- `src/backend_lmdb.rs` - LMDB persistent backend
- `src/backend_adapters.rs` - Adapters connecting FSMs to backends

### Configuration & Setup
- `src/config.rs` - TOML configuration system with validation
- `src/setup.rs` - Interactive setup wizard logic
- `src/bin/setup.rs` - Setup CLI entry point
- `config/server.toml` - Server configuration file
- `config/log4rs.yml` - Logging configuration

### Schema & Validation
- `src/schema.rs` - LDAP schema parser and validator (RFC 4512/4519)
- `src/schema_adapter.rs` - Schema validation adapter for Write FSM
- Custom schemas: `config copy/schema/*.schema` files

### Enterprise Features
- `src/replication.rs` - Replication configuration
- `src/rate_limit.rs` - Rate limiting with token bucket algorithm
- `src/metrics.rs` - Prometheus-compatible metrics
- `src/audit.rs` - Audit logging
- `src/aci.rs` - Access Control Information (ACI)
- `src/connection_pool.rs` - Connection pooling
- `src/shutdown.rs` - Graceful shutdown coordination

### Other Components
- `src/parser.rs` - LDAP message encoding/decoding (ASN.1)
- `src/extended_ops.rs` - Extended operation handlers
- `src/tls.rs` - TLS configuration
- `src/index.rs` - B-tree indexing

## Configuration System

The server uses TOML configuration files with environment variable overrides:

**Main config:** `config/server.toml`
- Server settings (base DN, ports, admin credentials)
- Backend configuration (LMDB or in-memory)
- TLS settings
- Resource limits
- Rate limiting
- Replication (provider/consumer)
- Metrics and monitoring

**Setup workflow:**
1. Run `cargo run --bin opendr-setup interactive` for first-time setup
2. Wizard creates `config/server.toml`, `config/base.ldif`, `config/admin.ldif`
3. Modify config as needed
4. Run `cargo run` to start server

## Backend System

### DirectoryBackend Trait
Core abstraction for directory storage operations:
- `authenticate()` - Bind authentication
- `get_entry()`, `add_entry()`, `modify_entry()`, `delete_entry()` - CRUD
- `search_entries()` - Search with filter support
- `rename_entry()` - ModifyDN operations
- `compare_attribute()` - Compare operations

### Available Backends
1. **LmdbBackend** (`src/backend_lmdb.rs`) - Persistent LMDB storage
2. **MockBackend** (`src/backend.rs`) - In-memory for testing

### Backend Adapters
`src/backend_adapters.rs` provides adapters connecting FSM-specific backend traits to `DirectoryBackend`:
- `SearchBackendAdapter`
- `WriteBackendAdapter`
- `CompareBackendAdapter`

## Schema Validation

Schema validation is **fully integrated** with Write FSM:

**Core validation checks:**
- Object class existence and structural class requirement
- Required attributes presence
- Unknown attributes rejection
- Single-value constraints

**Testing schema:**
```bash
# Run schema validation demo
cargo run --example schema_validation_test

# Run schema-specific tests
cargo test schema
./scripts/test_schema_validation.sh
```

**Custom schemas:**
Place `.schema` files in `config/schema/` - see `config copy/schema/employee.schema` for examples.

## Testing Strategy

### Test Organization
- `tests/*_integration.rs` - Integration tests
- `tests/*_unit_tests.rs` - Unit tests
- `tests/fsm_test_utils.rs` - FSM testing utilities
- `benches/*.rs` - Performance benchmarks

### Key Test Suites
- `tests/server_handlers.rs` - LDAP protocol operations
- `tests/fsm_integration_tests.rs` - FSM integration
- `tests/fsm_unit_tests.rs` - FSM state transitions
- `tests/backend_lmdb_integration.rs` - LMDB backend
- `tests/replication_integration.rs` - Replication logic
- `tests/schema_integration.rs` - Schema validation
- `tests/e2e_tests.rs` - End-to-end scenarios

### E2E Testing
E2E tests with real `ldapsearch`/`ldapadd` clients:
```bash
cd e2e_tests
./test_single_provider_single_consumer.sh
```

## Replication System

**Provider (Master) Setup:**
```bash
opendr-setup interactive
# Select replication → Provider
# Configure changelog tracking, batch size, streaming
```

**Consumer (Replica) Setup:**
```bash
opendr-setup interactive
# Select replication → Consumer
# Provide provider URL and credentials
```

**Testing replication:**
```bash
./scripts/test_replication.sh
```

## Common Development Patterns

### Adding a New FSM Operation
1. Define state/event enums in the FSM trait
2. Create FSM implementation in `src/<operation>_fsm.rs`
3. Add backend adapter in `src/backend_adapters.rs` if needed
4. Integrate into `src/fsm_runtime.rs` ConnectionFsmSet
5. Add comprehensive tests in `tests/`

### Adding a New Backend
1. Implement `DirectoryBackend` trait
2. Handle async methods with proper error mapping
3. Add to `src/main.rs` backend selection
4. Create integration tests

### Modifying Configuration
1. Update structs in `src/config.rs`
2. Add validation logic in `validate()` methods
3. Update `config/server.toml` example
4. Update setup wizard in `src/setup.rs` if needed

## Documentation

**Architecture docs:** `docs/`
- `docs/README.md` - Documentation index
- `docs/class-diagram.md` - FSM trait relationships
- `docs/*_fsm.md` - Individual FSM documentation
- `docs/schema_integration.md` - Schema validation guide
- `docs/SETUP_WIZARD_GUIDE.md` - Setup wizard walkthrough

**Project status files:**
- `WARP.md` - Development guide (legacy)
- `PHASE*.md` - Development phase summaries
- `BACKEND_INTEGRATION.md` - Backend adapter integration

## Key Dependencies

- `tokio` - Async runtime
- `ldap-parser` - LDAP message parsing
- `rasn-ldap` - ASN.1 encoding
- `lmdb` - LMDB storage engine
- `log4rs` - Structured logging
- `mockall` - Test mocking
- `clap` - CLI argument parsing
- `serde` + `toml` - Configuration serialization

## Important Notes

- Server binds to `127.0.0.1:1389` by default (configurable in `server.toml`)
- Default admin credentials set during setup wizard
- LMDB database stored in `data/` directory (configurable)
- Logs written to `log/server.log` (configurable via `log4rs.yml`)
- FSM traits are in `src/fsm.rs` - read this first to understand architecture
- Extended operations support delegation (see ExtendedOpFsm)
- Schema validation happens in Write FSM before backend storage

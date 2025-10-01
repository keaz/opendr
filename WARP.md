# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

`opendr` is a Rust-based LDAP (Lightweight Directory Access Protocol) server implementation. It's designed as an experimental/learning project that implements the full LDAP v3 protocol with asynchronous I/O using Tokio. The server features a pluggable backend architecture with a disk-backed `FileBackend` for production use and a lightweight mock backend for testing.

## Architecture

The project follows a **finite state machine (FSM) based architecture** designed for high concurrency and clear state management:

- **FSM Layer** (`src/fsm.rs`): Comprehensive FSM traits for all LDAP operations and connection management
- **Server Layer** (`src/server.rs`): Handles TCP connections, LDAP message parsing, and protocol operations
- **Backend Layer** (`src/backend.rs`): Provides a trait-based abstraction for directory storage with both persistent (`FileBackend`) and in-memory (`MockBackend`) implementations
- **Parser Layer** (`src/parser.rs`): Handles LDAP message encoding/decoding using ASN.1 DER encoding
- **Data Layer** (`src/data.rs`): Serialization structures for persistent storage (currently unused)
- **Schema Layer** (`src/schema.rs`): LDAP schema parsing and validation (work in progress)
- **Index Layer** (`src/index.rs`): B-tree indexing implementation for efficient searching

### FSM Architecture
The server uses 12 FSM traits covering:
- **Transport**: ConnectionFsm, BerDecoderFsm
- **Authentication**: AuthFsm, SaslFsm  
- **Operations**: SearchFsm, WriteFsm, CompareFsm, ExtendedOpFsm
- **Distribution**: ReferralFsm, ReplicationProviderFsm, ReplicationConsumerFsm
- **Storage**: BackendTxnFsm

#### Extended Operation FSM
The ExtendedOpFsm handles LDAP extended operations with advanced features:
- **Operation Support**: StartTLS, Password Modify, WhoAmI, Cancel, and custom operations
- **Delegation System**: Can delegate operations to external handlers (e.g., TLS negotiation)
- **Access Control**: Per-operation permission checking
- **Metrics Collection**: Operation timing and success/failure tracking
- **Error Handling**: Comprehensive error propagation with custom error types
- **State Management**: Parsing → Processing/Delegating → Responding → Completed
- **Implementation**: `src/extended_op_fsm.rs` with trait abstractions for external dependencies

📊 **See [docs/](docs/) for detailed architecture diagrams and design documentation.**

## Key Components

### DirectoryBackend Trait
The core abstraction that defines all directory operations:
- Authentication (`authenticate`)
- CRUD operations (`add_entry`, `get_entry`, `modify_entry`, `delete_entry`)
- Search operations (`search_entries`) 
- DN operations (`rename_entry`, `compare_attribute`)

### LDAP Operations Supported
All major LDAP v3 operations are implemented:
- Bind (simple authentication)
- Search (with filter support)
- Add, Modify, Delete
- ModifyDN (rename/move entries)
- Compare
- Extended operations (StartTLS, Password Modify, WhoAmI, Cancel, custom operations)

### Protocol Implementation
- Uses `ldap-parser` crate for parsing incoming LDAP messages
- Uses `rasn-ldap` crate for ASN.1 encoding of responses
- Full LDAP filter support including complex boolean expressions
- Proper DN parsing and component handling

## Development Commands

```bash
# Build the project
cargo build

# Run the server (listens on 127.0.0.1:1389)
cargo run

# Run tests
cargo test

# Run specific test module
cargo test server_handlers

# Run with debug logging
RUST_LOG=debug cargo run

# Build for release
cargo build --release
```

## Configuration

- **Logging**: Configured via `config/log4rs.yml` (log4rs configuration)
- **Server**: Hardcoded to bind on `127.0.0.1:1389` in `main.rs`
- **Backend**: Uses the persistent FileBackend that stores data under the `data/` directory by default

## Testing Strategy

Tests are located in `tests/server_handlers.rs` and use:
- `mockall` for mocking the DirectoryBackend trait
- Integration tests that create TCP streams and test full LDAP message flows
- Comprehensive coverage of all LDAP operations and error conditions

### Running Individual Tests
```bash
cargo test simple_bind_success
cargo test search_returns_entries
cargo test modify_success_returns_success_response
```

## Key LDAP Concepts

- **DN (Distinguished Name)**: Unique identifier for entries (e.g., `cn=user,dc=example,dc=org`)
- **RDN (Relative Distinguished Name)**: Single component of a DN (e.g., `cn=user`)
- **Search Scope**: Base (0), One Level (1), Subtree (2)
- **Filters**: Boolean expressions for searching entries
- **Attributes**: Key-value pairs that make up directory entries

## Code Navigation Tips

- **FSM Traits**: All state machine definitions in `src/fsm.rs`
- **Server request handlers**: Look in `src/server.rs` for `handle_*_request` functions
- **Backend implementations**: `FileBackend` and `MockBackend` in `src/backend.rs`
- **LDAP message encoding**: `src/parser.rs` - `encode_*` functions
- **Filter matching logic**: `entry_matches_filter` function in `src/server.rs`
- **DN manipulation**: Helper functions at bottom of `src/backend.rs`
- **Extended Operations**: `src/extended_op_fsm.rs` - comprehensive FSM with trait abstractions
- **Architecture docs**: Complete diagrams and design in `docs/` directory

## Common Development Tasks

### Adding a New Backend
1. Implement the `DirectoryBackend` trait
2. Handle all async methods with proper error mapping
3. Add to main.rs backend selection

### Extending LDAP Operations
1. Add parsing in `src/server.rs` `process_message`
2. Create handler function following existing pattern
3. Add response encoding in `src/parser.rs` if needed
4. Add comprehensive tests

### Testing LDAP Client Connectivity
```bash
# Using ldapsearch (if available)
ldapsearch -H ldap://127.0.0.1:1389 -D "cn=admin,dc=example,dc=org" -w secret -b "dc=example,dc=org" "(objectClass=*)"
```

## Dependencies

Key external crates:
- `tokio`: Async runtime and TCP handling  
- `ldap-parser`: LDAP message parsing
- `rasn-ldap`: ASN.1 encoding for LDAP responses
- `log4rs`: Structured logging
- `mockall`: Test mocking framework
- `serde` + `bincode`: Serialization (for future persistent storage)

## Areas of Complexity

- **DN Parsing**: Complex string manipulation with case-insensitive comparisons
- **Search Scopes**: Base, OneLevel, and Subtree have different matching logic  
- **Filter Evaluation**: Recursive filter matching with proper attribute value handling
- **ASN.1 Encoding**: Proper LDAP message structure encoding using rasn crate
- **ModifyDN Operations**: Complex rename logic that can affect multiple entries
# ConnectionFsm Implementation

## Overview

The `ConnectionFsmImpl` is a concrete implementation of the `ConnectionFsm` trait that manages the lifecycle of TCP connections in the LDAP server, including optional StartTLS upgrades. It follows a finite state machine pattern to ensure proper state transitions and prevent invalid operations.

## Architecture

```
┌─────────────┐
│ Connecting  │
└─────────────┘
       │ ConnectionEstablished
       ▼
┌─────────────┐  StartTlsRequest   ┌──────────────────┐
│  Connected  ├──────────────────► │StartTlsNegotiation│
└─────────────┘                    └──────────────────┘
       │                                      │ TlsHandshakeComplete
       │                                      ▼
       │                           ┌─────────────┐
       │                           │   Secure    │
       │                           └─────────────┘
       │ Close                               │ Close
       ▼                                     ▼
┌─────────────┐                    ┌─────────────┐
│   Closing   │                    │   Closing   │
└─────────────┘                    └─────────────┘
       │                                     │
       ▼                                     ▼
┌─────────────┐                    ┌─────────────┐
│   Closed    │                    │   Closed    │
└─────────────┘                    └─────────────┘
```

## States

- **Connecting**: Initial state, waiting for connection establishment
- **Connected**: TCP connection is established but not secured
- **StartTlsNegotiation**: StartTLS has been requested, performing TLS handshake  
- **Secure**: TLS connection is established and encrypted
- **Closing**: Connection is being closed
- **Closed**: Connection is terminated (terminal state)
- **Error**: An error occurred (terminal state)

## Events

- **ConnectionEstablished**: TCP connection successfully established
- **StartTlsRequest**: Client/server requests TLS upgrade
- **TlsHandshakeComplete**: TLS handshake completed successfully
- **TlsHandshakeFailed**: TLS handshake failed
- **Close**: Request to close the connection
- **ConnectionLost**: Network connection lost unexpectedly
- **Error**: Generic error occurred

## Features

### ✅ State Management
- Enforces valid state transitions at compile time where possible
- Provides clear error messages for invalid transitions
- Supports both secure and non-secure connections

### ✅ Dependency Abstraction
- Uses `TlsHandler` trait for TLS operations (can be mocked for testing)
- Uses `NetworkHandler` trait for network operations (can be mocked for testing)
- No direct dependencies on specific TLS or networking libraries

### ✅ Connection Metadata
- Tracks remote and local addresses
- Indicates whether connection is secure
- Provides protocol version information
- Returns `ConnectionInfo` struct with complete connection details

### ✅ Async Support
- All operations are fully async using `async_trait`
- Compatible with Tokio runtime
- Non-blocking state transitions

### ✅ Error Handling
- Custom error types with detailed error messages
- Graceful handling of network failures
- Proper error propagation through the FSM

## Usage

### Basic Usage

```rust
use opendr::connection_fsm::{ConnectionFsmImpl, TlsHandler, NetworkHandler};
use opendr::fsm::{StateMachine, ConnectionEvent, ConnectionFsm};

// Create FSM with handlers
let tls_handler = Box::new(MyTlsHandler::new());
let network_handler = Box::new(MyNetworkHandler::new());

let mut fsm = ConnectionFsmImpl::with_network_handler(
    "127.0.0.1:1389",
    tls_handler,
    network_handler,
);

// Handle connection establishment
match fsm.handle_event(ConnectionEvent::ConnectionEstablished).await {
    Ok(Some(info)) => {
        println!("Connected to {}", info.remote_addr);
    }
    Err(e) => eprintln!("Connection failed: {}", e),
}
```

### StartTLS Upgrade

```rust
// Request TLS upgrade
fsm.handle_event(ConnectionEvent::StartTlsRequest).await?;

// Complete TLS handshake
match fsm.handle_event(ConnectionEvent::TlsHandshakeComplete).await {
    Ok(Some(info)) => {
        assert!(info.is_secure);
        println!("Secure connection established");
    }
    Err(e) => eprintln!("TLS handshake failed: {}", e),
}
```

### Connection Information

```rust
// Get connection metadata
let info = fsm.connection_info();
println!("Remote: {}", info.remote_addr);
println!("Local: {}", info.local_addr); 
println!("Secure: {}", info.is_secure);
println!("Protocol: {}", info.protocol_version);

// Check security status
if fsm.is_secure() {
    println!("Connection is encrypted");
}
```

## Implementation Details

### Thread Safety
- The FSM itself is not `Send + Sync` because it contains `TcpStream`
- Each connection should have its own FSM instance
- Multiple FSMs can run concurrently for different connections

### Memory Management
- FSM holds ownership of the TCP stream and handlers
- Handlers are boxed trait objects for dynamic dispatch
- Connection info is cloned when returned to avoid borrowing issues

### Error Recovery
- Most errors transition the FSM to the `Error` terminal state
- `reset()` can be called to return to initial `Connecting` state
- Network errors are properly propagated and don't panic

## Testing

The implementation includes comprehensive tests covering:

- All state transitions and event handling
- Error conditions and invalid transitions
- Mock handlers for TLS and network operations
- Timeout scenarios
- Connection metadata accuracy

### Running Tests

```bash
# Run all ConnectionFsm tests
cargo test connection_fsm

# Run with output
cargo test connection_fsm -- --nocapture
```

### Examples

Two demonstration programs are included:

```bash
# Basic usage with realistic state transitions
cargo run --example connection_fsm_simple

# Advanced demo showing full connection lifecycle  
cargo run --example connection_fsm_demo
```

## Integration with LDAP Server

The ConnectionFsm is designed to be used alongside other FSMs in the LDAP server:

```rust
struct LdapConnection {
    connection_fsm: ConnectionFsmImpl,
    auth_fsm: AuthFsmImpl,
    operations: Vec<Box<dyn OperationFsm>>,
}

impl LdapConnection {
    async fn handle_client(&mut self) -> Result<(), LdapError> {
        // Connection lifecycle managed by ConnectionFsm
        // Authentication managed by AuthFsm  
        // Operations managed by operation-specific FSMs
    }
}
```

## Performance Characteristics

- **State transitions**: O(1) time complexity
- **Memory usage**: ~200 bytes per FSM instance (excluding stream)
- **Network overhead**: None - only manages state, doesn't perform I/O
- **Async overhead**: Minimal - uses zero-copy state transitions where possible

## Future Enhancements

- [ ] Support for connection pooling integration
- [ ] Metrics collection (connection count, TLS upgrade rate, etc.)
- [ ] Integration with OpenTelemetry for distributed tracing
- [ ] Support for mutual TLS authentication
- [ ] IPv6 address handling improvements
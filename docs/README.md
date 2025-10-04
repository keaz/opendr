# opendr LDAP Server Documentation

Welcome to the opendr LDAP server documentation. This directory contains comprehensive documentation for the FSM-based architecture and design.

## Documentation Overview

### 📊 [Architecture Overview](./architecture-overview.md)
High-level system architecture showing the layered FSM design, component relationships, and key design principles. Start here for understanding the overall system structure.

### 🔧 [Complete Class Diagram](./class-diagram.md)
Detailed class diagrams showing all FSM traits, their relationships, state definitions, and runtime management structures. Essential for developers implementing the FSM traits.

### 🔐 [Schema Integration Guide](./schema_integration.md)
Comprehensive guide for LDAP schema validation integration. Covers schema validation rules, custom schema extensions, and integration with the Write FSM.

### 📋 [Schema Definition Guide](./SCHEMA_DEFINITION_GUIDE.md)
Complete guide for defining custom LDAP schemas. Covers OID management, schema file formats, attribute and object class definitions, and best practices.

### ⚡ [Schema Quick Start](./SCHEMA_QUICK_START.md)
Quick start guide for schema definition. Get started with custom schemas in 5 minutes.

### 📘 [WARP.md](../WARP.md)
Development guide for working with the codebase, including build commands, testing strategies, and code navigation tips.

## Quick Start Guide

1. **Understanding the Architecture**: Read the [Architecture Overview](./architecture-overview.md) to understand the FSM-based design
2. **Implementation Details**: Study the [Class Diagram](./class-diagram.md) for detailed trait specifications  
3. **Development Setup**: Follow the [WARP.md](../WARP.md) guide for local development
4. **Code Exploration**: The FSM traits are defined in `src/fsm.rs`

## Architecture Summary

The opendr LDAP server uses a **finite state machine (FSM) architecture** where each concurrent process is modeled as a separate state machine:

### Core Components
- **12 FSM Traits**: Covering all aspects from connection management to replication
- **Layered Architecture**: Transport, Authentication, Operations, and Storage layers
- **Concurrent Operations**: Multiple LDAP operations can run in parallel per connection
- **Type-Safe Design**: Rust traits ensure compile-time correctness

### Per-Connection FSM Instances
```
ConnectionFsmSet {
    connection: ConnectionFsm         // TCP/TLS lifecycle
    decoder: BerDecoderFsm           // Message parsing
    auth: AuthFsm | SaslFsm          // Authentication
    operations: Vec<OperationFsm>    // N parallel operations
    replication: ReplicationFsm      // Optional sync
}
```

### FSM Categories

| Layer | FSMs | Purpose |
|-------|------|---------|
| **Transport** | ConnectionFsm, BerDecoderFsm | TCP/TLS and message framing |
| **Authentication** | AuthFsm, SaslFsm | Session identity management |
| **Operations** | SearchFsm, WriteFsm, CompareFsm, ExtendedOpFsm | LDAP protocol operations |
| **Distribution** | ReferralFsm, ReplicationProviderFsm, ReplicationConsumerFsm | Cross-server coordination |
| **Storage** | BackendTxnFsm | Transaction management |

## Benefits of FSM Architecture

1. **🔄 Clear State Management**: Explicit states and transitions prevent invalid states
2. **⚡ Concurrency**: Multiple operations execute in parallel safely  
3. **🛡️ Error Handling**: Consistent error propagation across all components
4. **⏱️ Timeout Support**: Built-in timeout and abandonment capabilities
5. **🔧 Extensibility**: Easy to add new operation types and protocols
6. **🦀 Type Safety**: Rust's type system ensures correctness at compile time

## Implementation Status

- ✅ **FSM Traits Defined**: All 12 FSM traits with comprehensive state/event definitions
- ✅ **Architecture Designed**: Complete system architecture with clear component relationships
- ✅ **Documentation Created**: Full documentation with diagrams and examples
- 🚧 **Concrete Implementations**: Next phase - implement concrete FSM structs
- 🚧 **Integration**: Integrate FSMs with existing server infrastructure
- 🚧 **Testing**: Comprehensive testing of FSM behavior and transitions

## Next Steps for Development

1. **Implement Concrete FSMs**: Create struct implementations for each trait
2. **Server Integration**: Modify existing server to use FSM architecture  
3. **Message Routing**: Implement message ID correlation and FSM dispatch
4. **Backend Integration**: Connect FSMs to DirectoryBackend implementations
5. **Testing Framework**: Create FSM testing utilities and comprehensive test suite
6. **Performance Optimization**: Profile and optimize FSM transitions and memory usage

This architecture provides a robust foundation for building a production-quality LDAP server with enterprise features and high performance.
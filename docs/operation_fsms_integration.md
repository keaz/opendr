# Operation FSMs Integration Implementation

## Overview

This document describes the implementation of the FSM configuration and factory system for integrating operation FSMs (Search, Write, Compare, ExtendedOp) with the LDAP server message processing.

## Architecture

### Core Components

1. **FsmRoutingConfig**: Configures which operation types should use FSM routing
2. **OperationFsmConfig**: Combined configuration for all operation FSMs  
3. **FsmFactory**: Factory for creating FSM instances with appropriate backends
4. **OperationFsmInstance**: Enum for storing different FSM instances
5. **Backend Adapters**: Bridge DirectoryBackend to FSM-specific backend traits

### Extended ConnectionFsmSet

The `ConnectionFsmSet` has been extended to support operation FSMs:

- **operation_fsms**: HashMap mapping message IDs to FSM instances
- **fsm_factory**: Factory for creating new FSM instances
- **routing_config**: Configuration for FSM routing behavior
- **fsm_config**: Configuration for individual FSM types
- **fsm_start_times**: Tracking for FSM timeout management

## Configuration

### FsmRoutingConfig

```rust
pub struct FsmRoutingConfig {
    pub enable_search_fsm: bool,
    pub enable_write_fsm: bool, 
    pub enable_compare_fsm: bool,
    pub enable_extended_op_fsm: bool,
    pub fallback_to_direct: bool,
}
```

**Default**: All FSMs disabled, fallback enabled for backward compatibility.

### OperationFsmConfig

```rust  
pub struct OperationFsmConfig {
    pub search: SearchFsmConfig,
    pub write: WriteFsmConfig,
    pub compare: CompareFsmConfig,
    pub extended_op: ExtendedOpFsmConfig,
    pub max_concurrent_operations: usize,
    pub operation_timeout: Duration,
}
```

**Default**: 10 max concurrent operations, 60-second timeout.

## Factory System

### FsmFactory

The factory creates FSM instances with properly configured backend adapters:

- **SearchFsm**: Currently placeholder (to be implemented)
- **WriteFsm**: Fully implemented with WriteFsmImpl
- **CompareFsm**: Fully implemented with CompareFsmImpl  
- **ExtendedOpFsm**: Fully implemented with ExtendedOpFsmImpl

### Backend Adapters

Each FSM type has a dedicated adapter that bridges the common DirectoryBackend to the FSM-specific backend interface:

- **SearchBackendAdapter**: DirectoryBackend → SearchBackend
- **WriteBackendAdapter**: DirectoryBackend → WriteBackend
- **CompareBackendAdapter**: DirectoryBackend → CompareBackend
- **ExtendedOpBackendAdapter**: DirectoryBackend → ExtendedOpBackend

## FSM Lifecycle Management

### ConnectionFsmSet Methods

#### Configuration
- `configure_operation_fsms()`: Set up FSM factory and configurations
- `is_fsm_enabled()`: Check if FSM routing is enabled for operation type

#### FSM Creation
- `create_search_fsm()`: Create SearchFsm instance (placeholder)
- `create_write_fsm()`: Create WriteFsm instance
- `create_compare_fsm()`: Create CompareFsm instance
- `create_extended_op_fsm()`: Create ExtendedOpFsm instance

#### FSM Management
- `get_operation_fsm()`: Get FSM instance by message ID
- `get_operation_fsm_mut()`: Get mutable FSM instance by message ID
- `remove_operation_fsm()`: Remove and return FSM instance
- `cleanup_timed_out_fsms()`: Remove expired FSM instances
- `active_operation_count()`: Get count of active FSMs

## Default Implementations

### Traits Implemented

- **FilterMatcher**: Basic LDAP filter matching for search operations
- **EntryFormatter**: LDIF formatting for search results
- **SchemaValidator**: Basic entry and modification validation
- **AciChecker**: Allow-all access control implementation
- **WriteMetrics**: Debug logging for write operation metrics
- **AttributeComparator**: Case-sensitive/insensitive attribute comparison
- **CompareAccessControl**: Allow-all compare permissions
- **CompareMetrics**: Debug logging for compare operation metrics
- **ExtendedOpParser**: Basic parsing for WhoAmI operation
- **ExtendedOpDelegator**: Placeholder delegation (not implemented)
- **ExtendedOpAccessControl**: Allow-all extended operation permissions
- **ExtendedOpMetrics**: Debug logging for extended operation metrics

## Usage Example

```rust
// Create FSM routing configuration
let mut routing_config = FsmRoutingConfig::default();
routing_config.enable_write_fsm = true;
routing_config.enable_compare_fsm = true;

// Create operation FSM configuration
let fsm_config = OperationFsmConfig::default();

// Configure ConnectionFsmSet with FSM support
let mut fsm_set = ConnectionFsmSet::new_with_fsm_routing(
    stream,
    backend.clone(),
    routing_config,
    fsm_config
)?;

// Create FSM for specific operation
fsm_set.create_write_fsm(message_id)?;

// Process operation through FSM
if let Some(fsm) = fsm_set.get_operation_fsm_mut(message_id) {
    // Drive FSM state transitions
}

// Clean up completed FSMs
fsm_set.remove_operation_fsm(message_id);
```

## Implementation Status

### Completed
✅ FsmRoutingConfig and OperationFsmConfig structures  
✅ FsmFactory with backend adapters  
✅ Extended ConnectionFsmSet with operation FSM support  
✅ WriteFsm integration (WriteFsmImpl)  
✅ CompareFsm integration (CompareFsmImpl)  
✅ ExtendedOpFsm integration (ExtendedOpFsmImpl)  
✅ FSM lifecycle management methods  
✅ Timeout and cleanup functionality  
✅ Default implementations for FSM-specific traits  

### Pending
🔄 SearchFsm integration (placeholder currently)  
🔄 Message processing integration with FSM routing  
🔄 FSM-based request handlers (search, write, compare, extended)  
🔄 Error handling and fallback mechanisms  
🔄 Integration testing  

## Next Steps

1. **Implement SearchFsm**: Complete the search FSM implementation and integration
2. **Message Processing Integration**: Modify server message processing to route through FSMs
3. **FSM Request Handlers**: Implement handlers that drive FSM state transitions
4. **Error Handling**: Add proper error handling and fallback to direct handlers
5. **Testing**: Create comprehensive tests for FSM routing and lifecycle

## Benefits

- **Backward Compatibility**: Existing direct handlers remain functional as fallback
- **Incremental Migration**: FSMs can be enabled per operation type
- **Configurability**: Extensive configuration options for different deployment scenarios
- **Extensibility**: Plugin architecture for custom FSM behaviors
- **Monitoring**: Built-in metrics and timeout management
- **State Management**: Complex stateful operations with proper lifecycle tracking

This architecture provides a solid foundation for migrating LDAP operations to FSM-based processing while maintaining system reliability and performance.
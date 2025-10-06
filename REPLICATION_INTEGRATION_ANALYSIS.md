# Replication Integration Analysis

## Status: ❌ NOT INTEGRATED

The replication implementation exists but is **not integrated** with the main server.

## What Exists

### ✅ Complete Implementation
1. **Replication Provider FSM** (`src/replication_provider_fsm.rs`)
   - Full state machine for serving replication data to consumers
   - Changelog tracking and streaming
   - Consumer registry and management

2. **Replication Consumer FSM** (`src/replication_consumer_fsm.rs`)
   - Full state machine for consuming replication data
   - Connection to providers
   - Batch processing and state management

3. **Replication Module** (`src/replication.rs`)
   - ChangelogTracker implementation
   - Provider/Consumer connection implementations
   - Batch processor and state manager

4. **Configuration** (`src/config.rs`)
   - ReplicationSettings struct with all necessary fields
   - Validation logic for replication config
   - Support for provider/consumer modes

5. **Setup/Configuration** (`src/setup.rs`)
   - Setup wizard with replication configuration
   - TOML config generation

### ❌ Missing Integration

1. **Main Server (`src/main.rs`)**
   - No replication initialization
   - No provider/consumer FSM creation
   - No changelog tracker setup

2. **Server Module (`src/server.rs`)**
   - No replication-aware request handling
   - No integration with changelog for tracking changes
   - No replication protocol operations

3. **Backend Integration**
   - Backend operations (add, modify, delete) don't record to changelog
   - No hook for change tracking

## Required Integration Steps

### 1. Initialize Replication in Main Server

Need to add to `main.rs`:
```rust
// Create changelog tracker if replication enabled
let changelog = if config.replication.enabled {
    Some(Arc::new(ChangelogTracker::with_capacity(
        config.replication.changelog_capacity
    )))
} else {
    None
};

// Initialize provider if mode is "provider" or "both"
if config.replication.enabled && 
   (config.replication.mode == "provider" || config.replication.mode == "both") {
    // Create and spawn provider FSM
}

// Initialize consumer if mode is "consumer" or "both"
if config.replication.enabled && 
   (config.replication.mode == "consumer" || config.replication.mode == "both") {
    // Create and spawn consumer FSM
}
```

### 2. Integrate Changelog with Backend Operations

Need to:
- Pass changelog tracker to backend
- Record changes in add_entry, modify_entry, delete_entry, rename_entry
- Generate sequence numbers for each change

### 3. Add Replication Protocol Support

Need to add to server:
- LDAP Sync Request control (RFC 4533)
- Sync Done control
- Entry sync state control
- Refresh delete phase handling

### 4. Provider Management

Need to:
- Accept consumer connections
- Stream changelog entries
- Handle consumer disconnects
- Maintain consumer registry

### 5. Consumer Management

Need to:
- Connect to provider periodically
- Request changes from last known state
- Apply received changes to local backend
- Persist replication state (cookie)

## Recommendation

Implement integration in this order:

1. **Phase 1**: Basic changelog integration
   - Add changelog to backend wrapper
   - Record all modifications
   - Test changelog tracking

2. **Phase 2**: Provider integration
   - Initialize provider FSM in main.rs
   - Add sync request handling to server
   - Enable changelog streaming

3. **Phase 3**: Consumer integration
   - Initialize consumer FSM in main.rs
   - Add periodic sync task
   - Test provider-consumer flow

4. **Phase 4**: Testing
   - End-to-end replication tests
   - Multi-master scenarios (if mode="both")
   - Failure recovery tests

## Files That Need Modification

1. `src/main.rs` - Add replication initialization
2. `src/server.rs` - Add sync protocol support (or use existing FSM server)
3. `src/backend.rs` or wrapper - Add changelog integration
4. `src/lib.rs` - Ensure replication modules are exported
5. Create `src/replication_service.rs` - High-level replication service

## Impact

**Current State**: Replication is completely non-functional in running server
**After Integration**: Full provider-consumer replication support with changelog tracking

## Testing Status

- ✅ Unit tests for FSMs exist
- ✅ Integration tests exist (`tests/replication_integration.rs`)
- ❌ End-to-end tests with actual server not possible (not integrated)
- ❌ E2E test scripts exist but won't work (`scripts/test_replication.sh`)

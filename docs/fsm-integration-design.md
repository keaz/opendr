# FSM Integration Architecture Design

## Overview

This document outlines the design for integrating operation FSMs (SearchFsm, WriteFsm, CompareFsm, ExtendedOpFsm) into the existing LDAP server message processing while maintaining backward compatibility.

## Current State

### Existing Architecture
- **ConnectionFsmSet**: Contains Auth and SASL FSMs for connection-level state
- **Direct Handlers**: `handle_*_request` functions call backend directly
- **FSM Routing**: `process_message_with_fsm` routes bind requests through FSMs, others to direct handlers

### FSM Implementations Available
- ✅ **SearchFsm** (`search_fsm.rs`) - Complete with traits and comprehensive tests
- ✅ **WriteFsm** (`write_fsm.rs`) - Unified FSM for Add/Modify/Delete/ModifyDN operations  
- ✅ **CompareFsm** (`compare_fsm.rs`) - Lightweight comparison operations
- ✅ **ExtendedOpFsm** (`extended_op_fsm.rs`) - Advanced extended operations with delegation

## Integration Strategy

### 1. Extend ConnectionFsmSet

Add operation FSM management to the existing `ConnectionFsmSet`:

```rust
pub struct ConnectionFsmSet {
    // Existing fields
    connection: ConnectionFsmImpl,
    decoder: BerDecoderFsmImpl, 
    auth: AuthFsmImpl,
    sasl: Option<SaslFsmImpl>,
    
    // New operation FSM storage
    operation_fsms: HashMap<u32, OperationFsmInstance>, // message_id -> FSM
    next_operation_id: u32,
    
    // Configuration
    fsm_config: OperationFsmConfig,
    use_fsm_routing: FsmRoutingConfig,
    
    // Session management
    last_activity: Instant,
    session_timeout: Duration,
}

enum OperationFsmInstance {
    Search(Box<dyn SearchFsm<...>>),
    Write(Box<dyn WriteFsm<...>>),
    Compare(Box<dyn CompareFsm<...>>),
    ExtendedOp(Box<dyn ExtendedOpFsm<...>>),
}
```

### 2. Configuration Structure

Add configuration to control FSM routing behavior:

```rust
#[derive(Debug, Clone)]
pub struct FsmRoutingConfig {
    pub enable_search_fsm: bool,
    pub enable_write_fsm: bool,
    pub enable_compare_fsm: bool,
    pub enable_extended_op_fsm: bool,
    pub fallback_to_direct: bool, // Use direct handlers if FSM fails
}

#[derive(Debug, Clone)]
pub struct OperationFsmConfig {
    pub search: SearchFsmConfig,
    pub write: WriteFsmConfig,
    pub compare: CompareFsmConfig,
    pub extended_op: ExtendedOpFsmConfig,
    
    pub max_concurrent_operations: usize,
    pub operation_timeout: Duration,
}
```

### 3. FSM Factory and Backend Adapters

Create factory functions to instantiate FSMs with proper backend adapters:

```rust
pub struct FsmFactory {
    backend: Arc<dyn DirectoryBackend>,
}

impl FsmFactory {
    pub fn create_search_fsm(&self) -> Box<dyn SearchFsm<...>> {
        let backend = Box::new(SearchBackendAdapter::new(self.backend.clone()));
        let filter_matcher = Box::new(DefaultFilterMatcher::new());
        let entry_formatter = Box::new(DefaultEntryFormatter::new());
        Box::new(SearchFsmImpl::new(backend, filter_matcher, entry_formatter))
    }
    
    pub fn create_write_fsm(&self) -> Box<dyn WriteFsm<...>> {
        let backend = Box::new(WriteBackendAdapter::new(self.backend.clone()));
        let schema_validator = Box::new(DefaultSchemaValidator::new());
        let aci_checker = Box::new(DefaultAciChecker::new());
        Box::new(WriteFsmImpl::new(backend, schema_validator, aci_checker))
    }
    
    // Similar for Compare and ExtendedOp...
}
```

### 4. Backend Adapter Pattern

Create adapters that bridge DirectoryBackend to FSM-specific backend traits:

```rust
// Search Backend Adapter
struct SearchBackendAdapter {
    backend: Arc<dyn DirectoryBackend>,
}

#[async_trait]
impl SearchBackend for SearchBackendAdapter {
    async fn find_candidates(&self, base_dn: &str, scope: i32, filter: &str) -> Result<Vec<String>, String> {
        // Convert DirectoryBackend search_entries to candidate list
        let scope_enum = match scope {
            0 => ldap_parser::ldap::SearchScope(0), // Base
            1 => ldap_parser::ldap::SearchScope(1), // OneLevel  
            2 => ldap_parser::ldap::SearchScope(2), // Subtree
            _ => return Err("Invalid search scope".to_string()),
        };
        
        match self.backend.search_entries(base_dn, scope_enum).await {
            Ok(entries) => {
                // Apply filter and return DNs
                let candidates: Vec<String> = entries.into_iter()
                    .filter(|entry| self.entry_matches_filter(entry, filter))
                    .map(|entry| entry.dn)
                    .collect();
                Ok(candidates)
            }
            Err(e) => Err(e.to_string()),
        }
    }
    
    async fn get_entry(&self, dn: &str, attributes: &[String]) -> Result<Option<SearchEntry>, String> {
        match self.backend.get_entry(dn).await {
            Ok(Some(entry)) => {
                let search_entry = self.convert_to_search_entry(entry, attributes);
                Ok(Some(search_entry))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }
}

// Similar adapters for Write, Compare, and ExtendedOp backends...
```

### 5. Enhanced Message Processing

Update `process_message_with_fsm` to route operations through FSMs:

```rust
pub async fn process_message_with_fsm(
    socket: &mut TcpStream,
    backend: &dyn DirectoryBackend,
    fsm_set: Option<&mut ConnectionFsmSet>,
    message: LdapMessage<'_>,
) -> Result<(), ServerError> {
    let message_id = message.message_id.0;
    
    // Session timeout and activity updates (existing logic)...
    
    match message.protocol_op {
        ProtocolOp::BindRequest(bind_request) => {
            // Existing FSM bind logic...
        }
        ProtocolOp::SearchRequest(search_request) => {
            if let Some(fsms) = fsm_set {
                if fsms.use_fsm_routing.enable_search_fsm {
                    handle_search_request_fsm(fsms, socket, message_id, search_request).await?;
                } else {
                    handle_search_request(socket, backend, message_id, search_request).await?;
                }
            } else {
                handle_search_request(socket, backend, message_id, search_request).await?;
            }
        }
        ProtocolOp::ModifyRequest(modify_request) => {
            if let Some(fsms) = fsm_set {
                if fsms.use_fsm_routing.enable_write_fsm {
                    handle_write_request_fsm(fsms, socket, message_id, WriteOperation::Modify { 
                        dn: modify_request.object.0.to_string(), 
                        changes: convert_modifications(modify_request.changes) 
                    }).await?;
                } else {
                    handle_modify_request(socket, backend, message_id, modify_request).await?;
                }
            } else {
                handle_modify_request(socket, backend, message_id, modify_request).await?;
            }
        }
        // Similar routing for Add, Delete, ModifyDN, Compare, Extended operations...
    }
    
    Ok(())
}
```

### 6. FSM Operation Handlers

Create new FSM-based handlers that follow the same pattern as `handle_bind_request_fsm`:

```rust
pub async fn handle_search_request_fsm(
    fsm_set: &mut ConnectionFsmSet,
    socket: &mut TcpStream,
    message_id: u32,
    request: SearchRequest<'_>,
) -> Result<(), ServerError> {
    // Create search FSM instance
    let mut search_fsm = fsm_set.create_search_fsm();
    
    // Convert LDAP request to FSM event
    let search_event = SearchEvent::StartSearch {
        base_dn: request.base_object.0.to_string(),
        scope: request.scope.0,
        filter: format_filter(&request.filter), // Convert filter to string
        attributes: request.attributes.iter().map(|a| a.0.to_string()).collect(),
        size_limit: request.size_limit,
        time_limit: request.time_limit,
    };
    
    // Process through FSM states
    match search_fsm.handle_event(search_event).await {
        Ok(None) => {
            // Continue FSM processing through states
            while !search_fsm.is_terminal() {
                match search_fsm.current_state() {
                    SearchState::FindingCandidates => {
                        // Trigger candidate finding
                        let _ = search_fsm.handle_event(SearchEvent::CandidatesFound(/* count */)).await?;
                    }
                    SearchState::Iterating { .. } => {
                        // Process entries and emit them
                        // Send search entry responses to socket
                        // Handle SearchEvent::EntryFound, SearchEvent::EntryEmitted
                    }
                    SearchState::Completed { result_code, .. } => {
                        // Send final SearchResultDone response
                        break;
                    }
                    _ => {
                        // Handle other states or errors
                    }
                }
            }
        }
        Err(e) => {
            // Send error response
            send_search_error_response(socket, message_id, &e).await?;
        }
    }
    
    Ok(())
}

pub async fn handle_write_request_fsm(
    fsm_set: &mut ConnectionFsmSet, 
    socket: &mut TcpStream,
    message_id: u32,
    operation: WriteOperation,
) -> Result<(), ServerError> {
    // Similar FSM processing for write operations
    // The WriteFsm handles Add, Modify, Delete, ModifyDN uniformly
}

pub async fn handle_compare_request_fsm(
    fsm_set: &mut ConnectionFsmSet,
    socket: &mut TcpStream, 
    message_id: u32,
    request: CompareRequest<'_>,
) -> Result<(), ServerError> {
    // Similar FSM processing for compare operations
}

pub async fn handle_extended_request_fsm(
    fsm_set: &mut ConnectionFsmSet,
    socket: &mut TcpStream,
    message_id: u32, 
    request: ExtendedRequest<'_>,
) -> Result<(), ServerError> {
    // Similar FSM processing for extended operations
}
```

### 7. FSM Lifecycle Management

Add methods to ConnectionFsmSet for FSM lifecycle:

```rust
impl ConnectionFsmSet {
    pub fn create_search_fsm(&self) -> Box<dyn SearchFsm<...>> {
        self.fsm_factory.create_search_fsm()
    }
    
    pub fn create_write_fsm(&self) -> Box<dyn WriteFsm<...>> {
        self.fsm_factory.create_write_fsm()  
    }
    
    pub fn store_operation_fsm(&mut self, message_id: u32, fsm: OperationFsmInstance) {
        self.operation_fsms.insert(message_id, fsm);
    }
    
    pub fn remove_operation_fsm(&mut self, message_id: u32) -> Option<OperationFsmInstance> {
        self.operation_fsms.remove(&message_id)
    }
    
    pub fn cleanup_timed_out_operations(&mut self) {
        let timeout = self.fsm_config.operation_timeout;
        let now = Instant::now();
        
        self.operation_fsms.retain(|_, fsm| {
            // Check FSM timeout and remove expired ones
            !fsm.is_timed_out(timeout, now)
        });
    }
}
```

## Implementation Benefits

### 1. **Backward Compatibility**
- Existing direct handlers remain functional
- FSM routing can be enabled/disabled per operation type
- Fallback mechanisms for FSM failures

### 2. **Concurrent Operations**
- Each LDAP operation gets its own FSM instance
- Multiple operations can run in parallel per connection  
- Proper lifecycle management prevents resource leaks

### 3. **State Management**
- Clear state transitions for complex operations
- Timeout and abandonment support
- Error state handling and recovery

### 4. **Extensibility**
- Easy to add new FSM types
- Backend abstraction allows different storage engines
- Plugin architecture for operation-specific logic

### 5. **Testing**
- FSMs have comprehensive unit tests
- Integration tests verify end-to-end functionality
- Mock backend support for isolated testing

## Migration Strategy

### Phase 1: Infrastructure
1. Extend ConnectionFsmSet with operation FSM support
2. Create backend adapter interfaces
3. Add configuration structures

### Phase 2: Search FSM Integration  
1. Implement SearchBackendAdapter
2. Add handle_search_request_fsm
3. Update process_message_with_fsm routing

### Phase 3: Write FSM Integration
1. Implement WriteBackendAdapter  
2. Add handle_write_request_fsm for all write operations
3. Update routing for Add/Modify/Delete/ModifyDN

### Phase 4: Compare and Extended FSM Integration
1. Implement remaining backend adapters
2. Add corresponding FSM handlers
3. Complete routing integration

### Phase 5: Testing and Optimization
1. Comprehensive integration tests
2. Performance benchmarking
3. Configuration tuning

This design maintains the existing functionality while gradually introducing FSM-based processing, ensuring a smooth transition and enabling the advanced features provided by the FSM architecture.
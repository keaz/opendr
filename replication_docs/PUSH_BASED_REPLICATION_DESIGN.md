# Push-Based Replication Implementation Design

**Status:** Planning Phase  
**Date:** October 8, 2025  
**RFC Reference:** RFC 4533 (LDAP Content Synchronization Operation)  
**Goal:** Transition from pull-based to push-based replication to enable true multi-master topology

---

## Executive Summary

The current OpenDR replication implementation uses a **consumer-pull model** where consumers periodically request changes from the provider. We are transitioning to a **provider-push model** where the provider actively pushes changes to registered consumers. This enables:

1. **Real-time replication** with minimal latency
2. **True multi-master** replication topology support
3. **Better RFC 4533 compliance** (refreshAndPersist mode)
4. **Reduced network overhead** (no polling)
5. **Conflict detection and resolution** for concurrent updates

---

## RFC 4533 Analysis

### Current Implementation: refreshOnly Mode (Pull)

RFC 4533 Section 3.3 - The consumer polls for changes:
```
1. Consumer connects to provider
2. Consumer sends SearchRequest with Sync Control + cookie
3. Provider returns matching entries
4. Consumer disconnects
5. Repeat after interval
```

**Issues:**
- High latency (based on sync_interval_secs)
- Wasted resources if no changes
- Not suitable for multi-master (delayed conflict detection)

### Target Implementation: refreshAndPersist Mode (Push)

RFC 4533 Section 3.4 - The provider pushes changes:
```
1. Consumer connects to provider
2. Consumer sends SearchRequest with mode=refreshAndPersist
3. Provider returns initial content (refresh stage)
4. Provider sends Sync Info Message (refreshDone=TRUE)
5. Connection PERSISTS - Provider pushes changes as they occur
6. Consumer applies changes in real-time
```

**Benefits:**
- Immediate change propagation
- Persistent connection reduces overhead
- Better for multi-master topologies
- RFC 4533 compliant

---

## Architecture Comparison

### Current: Pull-Based (refreshOnly)

```
┌─────────────┐                    ┌─────────────┐
│  Provider   │                    │  Consumer   │
│  (Master)   │                    │  (Replica)  │
│             │                    │             │
│  Changelog  │                    │   Timer     │
│             │◄───────────────────┤   (30s)     │
│             │  Request Changes   │             │
│             │────────────────────►│             │
│             │  Return Batch      │   Apply     │
│             │                    │   Changes   │
└─────────────┘                    └─────────────┘
     (Passive)                         (Active)
```

### Target: Push-Based (refreshAndPersist)

```
┌─────────────┐                    ┌─────────────┐
│  Provider   │◄───────────────────┤  Consumer   │
│  (Master)   │  Connect+Subscribe │  (Replica)  │
│             │────────────────────►│             │
│  Changelog  │  Refresh Content   │             │
│             │────────────────────►│             │
│  Observer   │  Enter Persist     │   Apply     │
│             │════════════════════►│   Changes   │
│  Push on    │  Push Changes      │   (Real-    │
│  Change     │────────────────────►│    time)    │
└─────────────┘                    └─────────────┘
     (Active)                          (Passive)
```

---

## Multi-Master Topology Support

### Topology Example: 3-Way Multi-Master

```
         ┌─────────────┐
         │   Master A  │
         │  (Provider  │
         │     +       │
         │  Consumer)  │
         └──────┬──────┘
                │
       ┌────────┴────────┐
       │                 │
       ▼                 ▼
┌─────────────┐   ┌─────────────┐
│   Master B  │◄─►│   Master C  │
│  (Provider  │   │  (Provider  │
│     +       │   │     +       │
│  Consumer)  │   │  Consumer)  │
└─────────────┘   └─────────────┘
```

Each master:
- Acts as **Provider**: Pushes its local changes to other masters
- Acts as **Consumer**: Receives changes from other masters
- Maintains **persistent connections** to all other masters
- Detects and resolves **conflicts** using CSN ordering

---

## Key Components

### 1. Change Observer

**Purpose:** Monitor local directory changes and notify replication system

**Implementation:**
```rust
pub trait ChangeObserver: Send + Sync {
    /// Register a callback for directory changes
    fn register_callback(&self, callback: Arc<dyn ChangeCallback>);
    
    /// Notify observers of a change
    async fn notify_change(&self, change: ChangelogEntry);
}

pub trait ChangeCallback: Send + Sync {
    /// Called when a change occurs
    async fn on_change(&self, change: &ChangelogEntry) -> Result<(), String>;
}
```

**Location:** `src/change_observer.rs` (new file)

---

### 2. Consumer Registry

**Purpose:** Track active consumer connections and their state

**Enhancement:**
```rust
pub struct ConsumerConnection {
    pub consumer_id: String,
    pub connection_handle: Arc<Mutex<Option<ConnectionHandle>>>,
    pub sync_mode: SyncMode,  // NEW: refreshOnly or refreshAndPersist
    pub is_persistent: bool,   // NEW: Is connection persistent?
    pub last_cookie: Option<String>,
    pub connected_at: Instant,
    pub last_activity: Instant,
}

pub enum SyncMode {
    RefreshOnly,
    RefreshAndPersist,
}
```

**Location:** `src/replication_provider_fsm.rs` (enhance existing)

---

### 3. Push Manager

**Purpose:** Manage persistent connections and push changes to consumers

**Implementation:**
```rust
pub struct PushManager {
    /// Active persistent consumer connections
    persistent_consumers: Arc<RwLock<HashMap<String, PersistentConsumer>>>,
    
    /// Change observer for local changes
    change_observer: Arc<dyn ChangeObserver>,
    
    /// Changelog provider
    changelog_provider: Arc<dyn ChangelogProvider>,
}

impl PushManager {
    /// Start listening for changes and push to consumers
    pub async fn start(&self) -> Result<(), String>;
    
    /// Register a consumer for persistent updates
    pub async fn register_persistent_consumer(
        &self,
        consumer_id: String,
        connection: PersistentConsumer,
    ) -> Result<(), String>;
    
    /// Push a change to all persistent consumers
    async fn push_change(&self, change: &ChangelogEntry);
    
    /// Push change to specific consumer
    async fn push_to_consumer(
        &self,
        consumer_id: &str,
        change: &ChangelogEntry,
    ) -> Result<(), String>;
}
```

**Location:** `src/push_manager.rs` (new file)

---

### 4. Persistent Connection Handler

**Purpose:** Maintain persistent LDAP connections for push updates

**Implementation:**
```rust
pub struct PersistentConsumer {
    pub consumer_id: String,
    pub ldap_connection: Arc<Mutex<Option<ldap3::Ldap>>>,
    pub last_cookie: Arc<Mutex<String>>,
    pub filter: Option<String>,
    pub base_dn: String,
    pub attributes: Vec<String>,
    pub heartbeat_interval: Duration,
    pub last_heartbeat: Arc<Mutex<Instant>>,
}

impl PersistentConsumer {
    /// Send a SearchResultEntry with Sync State Control
    pub async fn send_entry(
        &self,
        entry: &DirectoryEntry,
        state: SyncState,
        cookie: Option<String>,
    ) -> Result<(), String>;
    
    /// Send Sync Info Message
    pub async fn send_sync_info(
        &self,
        info: SyncInfo,
    ) -> Result<(), String>;
    
    /// Send heartbeat to keep connection alive
    pub async fn send_heartbeat(&self) -> Result<(), String>;
    
    /// Check if connection is still alive
    pub async fn is_alive(&self) -> bool;
}

pub enum SyncState {
    Present,
    Add,
    Modify,
    Delete,
}

pub enum SyncInfo {
    NewCookie(String),
    RefreshDelete { cookie: Option<String>, refresh_done: bool },
    RefreshPresent { cookie: Option<String>, refresh_done: bool },
    SyncIdSet { cookie: Option<String>, refresh_deletes: bool, uuids: Vec<String> },
}
```

**Location:** `src/persistent_connection.rs` (new file)

---

### 5. Conflict Detection and Resolution

**Purpose:** Handle concurrent updates in multi-master scenario

**Implementation:**
```rust
pub struct ConflictResolver {
    resolution_strategy: ConflictResolutionStrategy,
}

pub enum ConflictResolutionStrategy {
    /// Last Write Wins (based on CSN timestamp)
    LastWriteWins,
    
    /// Highest Replica ID Wins
    ReplicaIdPrecedence,
    
    /// Custom conflict handler
    Custom(Arc<dyn ConflictHandler>),
}

pub trait ConflictHandler: Send + Sync {
    /// Resolve conflict between two versions of an entry
    async fn resolve(
        &self,
        local: &DirectoryEntry,
        remote: &DirectoryEntry,
        local_csn: &Csn,
        remote_csn: &Csn,
    ) -> Result<DirectoryEntry, ConflictError>;
}

impl ConflictResolver {
    /// Detect if an incoming change conflicts with local state
    pub async fn detect_conflict(
        &self,
        entry_dn: &str,
        incoming_csn: &Csn,
        local_csn: Option<&Csn>,
    ) -> Result<bool, String>;
    
    /// Resolve a detected conflict
    pub async fn resolve_conflict(
        &self,
        entry_dn: &str,
        local_entry: &DirectoryEntry,
        remote_entry: &DirectoryEntry,
        local_csn: &Csn,
        remote_csn: &Csn,
    ) -> Result<DirectoryEntry, String>;
}
```

**Location:** `src/conflict_resolution.rs` (new file)

---

## Implementation Tasks

### Phase 1: Foundation (1-2 weeks)

#### Task 1.1: Change Observer Implementation
- [ ] Create `src/change_observer.rs`
- [ ] Implement `ChangeObserver` trait
- [ ] Implement in-memory `ChangeObserverImpl`
- [ ] Add observer pattern to `ChangelogBackendWrapper`
- [ ] Write unit tests for observer pattern

**Files to modify:**
- `src/lib.rs` - Add new module
- `src/backend.rs` - Integrate observer into wrapper
- `src/change_observer.rs` - New file

---

#### Task 1.2: Enhanced Consumer Registry
- [ ] Add `SyncMode` enum to `ConsumerConnection`
- [ ] Add `is_persistent` flag
- [ ] Add connection handle storage
- [ ] Implement consumer persistence tracking
- [ ] Add tests for persistent consumer tracking

**Files to modify:**
- `src/replication_provider_fsm.rs`

---

#### Task 1.3: Persistent Connection Handler
- [ ] Create `src/persistent_connection.rs`
- [ ] Implement `PersistentConsumer` struct
- [ ] Implement LDAP message sending methods
- [ ] Add heartbeat mechanism
- [ ] Add connection health checks
- [ ] Write tests for connection management

**Files to modify:**
- `src/lib.rs` - Add new module
- `src/persistent_connection.rs` - New file

---

### Phase 2: Push Manager (1-2 weeks)

#### Task 2.1: Push Manager Core
- [ ] Create `src/push_manager.rs`
- [ ] Implement `PushManager` struct
- [ ] Add consumer registration
- [ ] Add change notification routing
- [ ] Write tests for push logic

**Files to modify:**
- `src/lib.rs` - Add new module
- `src/push_manager.rs` - New file

---

#### Task 2.2: Integration with Provider FSM
- [ ] Modify provider FSM to support refreshAndPersist
- [ ] Add persist stage after refresh
- [ ] Add connection keep-alive logic
- [ ] Integrate PushManager with provider
- [ ] Update tests for persist mode

**Files to modify:**
- `src/replication_provider_fsm.rs`
- `src/replication.rs`

---

#### Task 2.3: Real-time Change Propagation
- [ ] Connect ChangeObserver to PushManager
- [ ] Implement change filtering per consumer
- [ ] Add batching for multiple changes
- [ ] Add error handling and retry logic
- [ ] Test end-to-end push flow

**Files to modify:**
- `src/replication_provider_fsm.rs`
- `src/push_manager.rs`
- `src/backend.rs`

---

### Phase 3: Consumer Updates (1 week)

#### Task 3.1: Consumer Persist Mode
- [ ] Update consumer FSM to support persist mode
- [ ] Implement persistent connection maintenance
- [ ] Add real-time change reception
- [ ] Update state management for persist mode
- [ ] Test consumer in persist mode

**Files to modify:**
- `src/replication_consumer_fsm.rs`
- `src/replication.rs`

---

#### Task 3.2: Connection Lifecycle Management
- [ ] Implement graceful connection closure
- [ ] Add reconnection logic
- [ ] Handle network interruptions
- [ ] Implement connection timeout handling
- [ ] Test various failure scenarios

**Files to modify:**
- `src/replication_consumer_fsm.rs`
- `src/persistent_connection.rs`

---

### Phase 4: Conflict Resolution (2 weeks)

#### Task 4.1: Conflict Detection
- [ ] Create `src/conflict_resolution.rs`
- [ ] Implement conflict detection logic
- [ ] Add CSN comparison for conflicts
- [ ] Test various conflict scenarios
- [ ] Document conflict detection rules

**Files to modify:**
- `src/lib.rs` - Add new module
- `src/conflict_resolution.rs` - New file

---

#### Task 4.2: Conflict Resolution Strategies
- [ ] Implement Last Write Wins strategy
- [ ] Implement Replica ID precedence
- [ ] Add conflict logging
- [ ] Create conflict resolution configuration
- [ ] Test resolution strategies

**Files to modify:**
- `src/conflict_resolution.rs`
- `src/config.rs` - Add conflict resolution config

---

#### Task 4.3: Integration with Consumer
- [ ] Integrate conflict resolver in consumer FSM
- [ ] Add conflict resolution on entry application
- [ ] Log conflicts and resolutions
- [ ] Add metrics for conflict tracking
- [ ] Test multi-master conflicts

**Files to modify:**
- `src/replication_consumer_fsm.rs`
- `src/replication.rs`

---

### Phase 5: Multi-Master Support (1-2 weeks)

#### Task 5.1: Multi-Master Configuration
- [ ] Add multi-master topology config
- [ ] Support multiple provider URLs
- [ ] Add peer discovery mechanism
- [ ] Configure bidirectional replication
- [ ] Document multi-master setup

**Files to modify:**
- `src/config.rs`
- `docs/MULTI_MASTER_SETUP.md` - New file

---

#### Task 5.2: Topology Management
- [ ] Implement replication topology tracking
- [ ] Add peer health monitoring
- [ ] Implement cascade prevention
- [ ] Add loop detection
- [ ] Test various topologies

**Files to modify:**
- `src/replication.rs`
- `src/topology_manager.rs` - New file

---

#### Task 5.3: Multi-Master Testing
- [ ] Create 3-node multi-master test
- [ ] Test concurrent updates
- [ ] Test conflict scenarios
- [ ] Test network partition recovery
- [ ] Performance testing

**Files to create:**
- `tests/multi_master_integration.rs`
- `scripts/test_multi_master.sh`

---

### Phase 6: Performance and Optimization (1 week)

#### Task 6.1: Performance Optimization
- [ ] Optimize change notification routing
- [ ] Add connection pooling
- [ ] Implement change batching
- [ ] Add compression support
- [ ] Performance benchmarks

**Files to modify:**
- `src/push_manager.rs`
- `benches/replication_benchmarks.rs`

---

#### Task 6.2: Monitoring and Metrics
- [ ] Add replication lag metrics
- [ ] Track push success/failure rates
- [ ] Monitor connection health
- [ ] Add conflict metrics
- [ ] Create monitoring dashboard

**Files to modify:**
- `src/metrics.rs`
- `src/replication.rs`

---

### Phase 7: Documentation and Testing (1 week)

#### Task 7.1: Documentation
- [ ] Update REPLICATION_GUIDE.md
- [ ] Create MULTI_MASTER_GUIDE.md
- [ ] Document conflict resolution
- [ ] Add troubleshooting guide
- [ ] Update API documentation

**Files to create/modify:**
- `docs/REPLICATION_GUIDE.md`
- `docs/MULTI_MASTER_GUIDE.md`
- `docs/CONFLICT_RESOLUTION.md`
- `docs/TROUBLESHOOTING.md`

---

#### Task 7.2: End-to-End Testing
- [ ] Create comprehensive E2E tests
- [ ] Test all replication modes
- [ ] Test failure scenarios
- [ ] Test performance under load
- [ ] Create test automation

**Files to create:**
- `tests/replication_e2e.rs`
- `scripts/test_push_replication.sh`

---

## Migration Strategy

### Backward Compatibility

The implementation will maintain backward compatibility:

1. **Default Mode:** refreshOnly (current behavior)
2. **Opt-in:** refreshAndPersist (new push mode)
3. **Configuration:** `sync_mode = "persist"` to enable push

### Migration Path

```toml
# Old configuration (still works)
[replication]
role = "consumer"
provider_url = "ldap://provider:389"
sync_interval_secs = 30  # Pull every 30 seconds

# New configuration (push-based)
[replication]
role = "consumer"
provider_url = "ldap://provider:389"
sync_mode = "persist"  # NEW: Use persistent push mode
heartbeat_interval_secs = 60

# Multi-master configuration
[replication]
role = "both"
provider_urls = [
    "ldap://master1:389",
    "ldap://master2:389"
]
sync_mode = "persist"
conflict_resolution = "last_write_wins"
```

---

## Testing Strategy

### Unit Tests
- Change observer notifications
- Push manager routing
- Conflict detection logic
- Connection management

### Integration Tests
- Provider push to consumer
- Multi-consumer scenarios
- Conflict resolution
- Connection failures

### End-to-End Tests
- Single provider, multiple consumers
- 3-way multi-master topology
- Network partition scenarios
- Performance under load

### Test Scenarios

1. **Basic Push**
   - Provider pushes changes
   - Consumer receives in real-time
   - Verify correctness

2. **Multi-Consumer**
   - 1 provider, 3 consumers
   - All consumers receive changes
   - Verify consistency

3. **Multi-Master**
   - 3 masters (full mesh)
   - Concurrent updates
   - Conflict resolution
   - Eventual consistency

4. **Failure Recovery**
   - Network partition
   - Consumer crash/restart
   - Provider crash/restart
   - Graceful reconnection

5. **Performance**
   - 1000 changes/second
   - 10 consumers
   - Measure latency
   - Measure throughput

---

## Success Criteria

### Functional Requirements
- ✅ Provider pushes changes to consumers in real-time
- ✅ Persistent connections maintained with heartbeat
- ✅ Consumers receive changes within 1 second
- ✅ Multi-master replication works with 3+ nodes
- ✅ Conflicts detected and resolved automatically
- ✅ Backward compatible with pull-based mode

### Performance Requirements
- ✅ Replication latency < 1 second (99th percentile)
- ✅ Support 100+ concurrent consumers per provider
- ✅ Handle 1000 changes/second throughput
- ✅ Connection overhead < 1MB/hour per consumer

### RFC Compliance
- ✅ RFC 4533 refreshAndPersist mode implemented
- ✅ Sync State Control messages correct
- ✅ Sync Info Messages correct
- ✅ Cookie management RFC compliant

---

## Timeline Estimate

| Phase | Duration | Dependencies |
|-------|----------|--------------|
| Phase 1: Foundation | 2 weeks | None |
| Phase 2: Push Manager | 2 weeks | Phase 1 |
| Phase 3: Consumer Updates | 1 week | Phase 2 |
| Phase 4: Conflict Resolution | 2 weeks | Phase 3 |
| Phase 5: Multi-Master | 2 weeks | Phase 4 |
| Phase 6: Optimization | 1 week | Phase 5 |
| Phase 7: Documentation | 1 week | Phase 6 |
| **Total** | **11 weeks** | |

---

## Risks and Mitigation

### Risk 1: Connection Management Complexity
**Impact:** High  
**Probability:** Medium  
**Mitigation:** 
- Use battle-tested connection pooling libraries
- Implement comprehensive reconnection logic
- Add extensive logging and monitoring

### Risk 2: Conflict Resolution Bugs
**Impact:** High  
**Probability:** Medium  
**Mitigation:**
- Start with simple Last Write Wins strategy
- Add extensive conflict testing
- Log all conflicts for analysis
- Make resolution strategy pluggable

### Risk 3: Performance Degradation
**Impact:** Medium  
**Probability:** Low  
**Mitigation:**
- Performance benchmarks at each phase
- Optimize hot paths early
- Use async/await throughout
- Connection pooling and batching

### Risk 4: RFC Compliance Issues
**Impact:** Medium  
**Probability:** Low  
**Mitigation:**
- Detailed RFC 4533 compliance matrix
- Test against other LDAP implementations
- Comprehensive protocol testing

---

## Next Steps

1. **Review and Approval**
   - Review this design document
   - Get stakeholder approval
   - Clarify any questions

2. **Setup Tracking**
   - Create GitHub issues for each task
   - Setup project board
   - Assign tasks

3. **Start Implementation**
   - Begin with Phase 1, Task 1.1
   - Follow task order
   - Regular progress updates

4. **Continuous Testing**
   - Run tests after each task
   - Integration testing after each phase
   - E2E testing at major milestones

---

## References

- **RFC 4533:** LDAP Content Synchronization Operation
  - Section 3.4: refreshAndPersist Mode
  - Appendix A: CSN-based Implementation
- **Current Implementation:** 
  - `REPLICATION_INTEGRATION_COMPLETE_7.1_7.4.md`
  - `docs/REPLICATION_GUIDE.md`
- **OpenLDAP syncrepl:** Reference implementation

---

## Questions for Discussion

1. **Conflict Resolution:** Should we support custom conflict handlers from the start, or just Last Write Wins?
2. **Performance:** What are the target metrics for replication latency and throughput?
3. **Multi-Master:** Should we support full mesh or star topology initially?
4. **Monitoring:** What metrics are most important to track?
5. **Migration:** How do we handle migrating existing deployments?

---

**Document Status:** Draft for Review  
**Last Updated:** October 8, 2025  
**Next Review:** After stakeholder feedback

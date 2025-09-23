//! Backend Transaction/Index FSM Implementation
//!
//! This module implements the Backend Txn/Index FSM following the pattern:
//! open txn → read/write → update indexes → commit/rollback
//!
//! Scope: This FSM only manages the transaction lifecycle and index update
//! coordination for a backend storage layer. Any external behavior (IO, DB,
//! index engine) is abstracted behind trait dependencies defined here. Do not
//! extend beyond this scope.

use async_trait::async_trait;
use std::time::{Duration, Instant};

use crate::fsm::{
    BackendOperation, BackendTxnEvent, BackendTxnFsm, BackendTxnState, StateMachine,
};

// ================================================================================================
// Error Types
// ================================================================================================

/// Errors that can occur in the Backend Transaction FSM
#[derive(Debug)]
pub enum BackendTxnError {
    /// Invalid state transition attempted
    InvalidStateTransition { from: BackendTxnState, to: BackendTxnState },
    /// Transaction manager error
    TransactionError(String),
    /// Data store error
    DataStoreError(String),
    /// Index manager error
    IndexError(String),
    /// No transaction ID when one is required
    NoTransactionId,
    /// Generic error
    Generic(String),
}

impl std::fmt::Display for BackendTxnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendTxnError::InvalidStateTransition { from, to } => {
                write!(f, "Invalid state transition from {:?} to {:?}", from, to)
            }
            BackendTxnError::TransactionError(msg) => write!(f, "Transaction error: {}", msg),
            BackendTxnError::DataStoreError(msg) => write!(f, "Data store error: {}", msg),
            BackendTxnError::IndexError(msg) => write!(f, "Index error: {}", msg),
            BackendTxnError::NoTransactionId => write!(f, "No transaction ID present"),
            BackendTxnError::Generic(msg) => write!(f, "Backend transaction error: {}", msg),
        }
    }
}

impl std::error::Error for BackendTxnError {}

impl From<String> for BackendTxnError {
    fn from(s: String) -> Self {
        BackendTxnError::Generic(s)
    }
}

// ================================================================================================
// External Trait Dependencies (Abstracted)
// ================================================================================================

/// Abstraction for transaction lifecycle management
#[async_trait]
pub trait TransactionManager: Send + Sync {
    /// Open a new transaction; returns transaction id
    async fn open_transaction(&self) -> Result<String, String>;

    /// Commit a transaction by id
    async fn commit(&self, txn_id: &str) -> Result<(), String>;

    /// Rollback a transaction by id with a reason
    async fn rollback(&self, txn_id: &str, reason: &str) -> Result<(), String>;

    /// Get current nesting level (1 for top-level, >1 for nested/child txns)
    fn nesting_level(&self) -> u32;
}

/// Abstraction for backend data store reads/writes
#[async_trait]
pub trait DataStore: Send + Sync {
    /// Perform a read request; returns bytes read (opaque to FSM)
    async fn read(&self, key: &str) -> Result<Option<Vec<u8>>, String>;

    /// Perform a write operation
    async fn write(&self, txn_id: &str, op: BackendOperation) -> Result<(), String>;
}

/// Abstraction for index maintenance/update operations
#[async_trait]
pub trait IndexManager: Send + Sync {
    /// Request index update for the given transaction context
    async fn update_indexes(&self, txn_id: &str) -> Result<usize, String>;
}

/// Optional metrics collection for the backend txn FSM
pub trait TxnMetrics: Send + Sync {
    fn record_txn_open(&self, took: Duration);
    fn record_read(&self, took: Duration);
    fn record_write(&self, took: Duration);
    fn record_index_update(&self, took: Duration, indexes: usize);
    fn record_commit(&self, took: Duration);
    fn record_rollback(&self, took: Duration, reason: &str);
    fn record_error(&self, context: &str, message: &str);
}

// ================================================================================================
// FSM Implementation
// ================================================================================================

/// Backend transaction FSM implementation
pub struct BackendTxnFsmImpl {
    state: BackendTxnState,
    txn_id: Option<String>,
    reads_performed: usize,
    writes_performed: usize,
    indexes_updated: usize,
    start_time: Instant,

    // Dependencies
    txn_mgr: Box<dyn TransactionManager>,
    store: Box<dyn DataStore>,
    indexer: Box<dyn IndexManager>,
    metrics: Option<Box<dyn TxnMetrics>>,
}

impl BackendTxnFsmImpl {
    /// Create a new FSM instance
    pub fn new(
        txn_mgr: Box<dyn TransactionManager>,
        store: Box<dyn DataStore>,
        indexer: Box<dyn IndexManager>,
    ) -> Self {
        Self {
            state: BackendTxnState::Opening,
            txn_id: None,
            reads_performed: 0,
            writes_performed: 0,
            indexes_updated: 0,
            start_time: Instant::now(),
            txn_mgr,
            store,
            indexer,
            metrics: None,
        }
    }

    /// Attach metrics collector
    pub fn with_metrics(mut self, metrics: Box<dyn TxnMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    fn can_transition(&self, from: &BackendTxnState, to: &BackendTxnState) -> bool {
        use BackendTxnState as S;
        match (from, to) {
            (S::Opening, S::Reading { .. }) => true,
            (S::Opening, S::Writing { .. }) => true,
            (S::Reading { .. }, S::Reading { .. }) => true,
            (S::Writing { .. }, S::Writing { .. }) => true,
            (S::Reading { .. }, S::Writing { .. }) => true,
            (S::Writing { .. }, S::Reading { .. }) => true,
            (S::Reading { .. }, S::UpdatingIndexes { .. }) => true,
            (S::Writing { .. }, S::UpdatingIndexes { .. }) => true,
            (S::UpdatingIndexes { .. }, S::Reading { .. }) => true,
            (S::UpdatingIndexes { .. }, S::Writing { .. }) => true,
            (S::Reading { .. }, S::Committing) => true,
            (S::Writing { .. }, S::Committing) => true,
            (S::UpdatingIndexes { .. }, S::Committing) => true,
            (_, S::RollingBack { .. }) => true,
            (S::Committing, S::Completed { .. }) => true,
            (S::RollingBack { .. }, S::Completed { .. }) => true,
            (_, S::Failed { .. }) => true,
            _ => false,
        }
    }
}

#[async_trait]
impl StateMachine for BackendTxnFsmImpl {
    type State = BackendTxnState;
    type Event = BackendTxnEvent;
    type Error = BackendTxnError;
    type Output = bool; // committed: true, rolled back: false

    fn current_state(&self) -> &Self::State {
        &self.state
    }

    fn is_terminal(&self) -> bool {
        matches!(self.state, BackendTxnState::Completed { .. } | BackendTxnState::Failed { .. })
    }

    async fn handle_event(
        &mut self,
        event: Self::Event,
    ) -> Result<Option<Self::Output>, Self::Error> {
        use BackendTxnEvent as E;
        use BackendTxnState as S;

        match event {
            E::OpenTransaction => {
                // Only valid from Opening state
                if !matches!(self.state, S::Opening) {
                    let msg = format!("Invalid transition: {:?} -> OpenTransaction", self.state);
                    if let Some(m) = &self.metrics { m.record_error("open", &msg) }
                    self.state = S::Failed { error: msg.clone() };
                    return Err(msg.into());
                }
                let t0 = Instant::now();
                let txn_id = self
                    .txn_mgr
                    .open_transaction()
                    .await
                    .map_err(|e| {
                        if let Some(m) = &self.metrics { m.record_error("open", &e) }
                        e
                    })?;
                self.txn_id = Some(txn_id);
                if let Some(m) = &self.metrics { m.record_txn_open(t0.elapsed()) }
                // After open, we allow reads/writes; default to Reading state with zero reads
                let next = S::Reading { reads_performed: 0 };
                if !self.can_transition(&self.state, &next) {
                    let msg = "Illegal state transition after open".to_string();
                    self.state = S::Failed { error: msg.clone() };
                    return Err(msg.into());
                }
                self.state = next;
                Ok(None)
            }
            E::TransactionOpened { .. } => {
                // This event is not needed as we perform open synchronously above; reject if used
                let msg = "TransactionOpened event is not used in this FSM".to_string();
                if let Some(m) = &self.metrics { m.record_error("opened_evt", &msg) }
                self.state = S::Failed { error: msg.clone() };
                Err(msg.into())
            }
            E::ReadRequest => {
                // Valid from Reading or Writing (allow switching back to reading)
                let next = S::Reading {
                    reads_performed: self.reads_performed,
                };
                if !self.can_transition(&self.state, &next) {
                    let msg = format!("Invalid transition: {:?} -> ReadRequest", self.state);
                    if let Some(m) = &self.metrics { m.record_error("read_req", &msg) }
                    self.state = S::Failed { error: msg.clone() };
                    return Err(msg.into());
                }
                self.state = next;
                Ok(None)
            }
            E::ReadComplete => {
                // Simulate a read via store.read on a fixed key to validate path
                let t0 = Instant::now();
                // We use a static key for init tests; real integration would supply via event payload
                let _ = self
                    .store
                    .read("_health_check_")
                    .await
                    .map_err(|e| {
                        if let Some(m) = &self.metrics { m.record_error("read", &e) }
                        e
                    })?;
                self.reads_performed += 1;
                if let S::Reading { reads_performed: rp } = &mut self.state {
                    *rp = self.reads_performed;
                }
                if let Some(m) = &self.metrics { m.record_read(t0.elapsed()) }
                Ok(Some(false)) // operation complete signal not used for read; false placeholder
            }
            E::WriteRequest { operation } => {
                // Move to Writing state and perform the write
                let next = S::Writing {
                    writes_performed: self.writes_performed,
                };
                if !self.can_transition(&self.state, &next) {
                    let msg = format!("Invalid transition: {:?} -> WriteRequest", self.state);
                    if let Some(m) = &self.metrics { m.record_error("write_req", &msg) }
                    self.state = S::Failed { error: msg.clone() };
                    return Err(msg.into());
                }
                self.state = next;
                // Execute write
                let t0 = Instant::now();
                let txn_id = self
                    .txn_id
                    .as_deref()
                    .ok_or_else(|| "No transaction id present".to_string())?;
                self.store.write(txn_id, operation).await.map_err(|e| {
                    if let Some(m) = &self.metrics { m.record_error("write", &e) }
                    e
                })?;
                if let Some(m) = &self.metrics { m.record_write(t0.elapsed()) }
                Ok(None)
            }
            E::WriteComplete => {
                if !matches!(self.state, S::Writing { .. }) {
                    let msg = format!("Invalid transition: {:?} -> WriteComplete", self.state);
                    if let Some(m) = &self.metrics { m.record_error("write_complete", &msg) }
                    self.state = S::Failed { error: msg.clone() };
                    return Err(msg.into());
                }
                self.writes_performed += 1;
                if let S::Writing { writes_performed } = &mut self.state {
                    *writes_performed = self.writes_performed;
                }
                Ok(Some(false))
            }
            E::IndexUpdateRequest => {
                // Allow index update from Reading or Writing
                let next = S::UpdatingIndexes {
                    indexes_updated: self.indexes_updated,
                };
                if !self.can_transition(&self.state, &next) {
                    let msg = format!("Invalid transition: {:?} -> IndexUpdateRequest", self.state);
                    if let Some(m) = &self.metrics { m.record_error("index_req", &msg) }
                    self.state = S::Failed { error: msg.clone() };
                    return Err(msg.into());
                }
                self.state = next;
                Ok(None)
            }
            E::IndexUpdateComplete => {
                // Perform index update call
                let t0 = Instant::now();
                let txn_id = self
                    .txn_id
                    .as_deref()
                    .ok_or_else(|| "No transaction id present".to_string())?;
                let updated = self.indexer.update_indexes(txn_id).await.map_err(|e| {
                    if let Some(m) = &self.metrics { m.record_error("index_update", &e) }
                    e
                })?;
                self.indexes_updated += updated;
                if let S::UpdatingIndexes { indexes_updated } = &mut self.state {
                    *indexes_updated = self.indexes_updated;
                }
                if let Some(m) = &self.metrics { m.record_index_update(t0.elapsed(), updated) }
                // Return to Reading by default
                let next = S::Reading {
                    reads_performed: self.reads_performed,
                };
                self.state = next;
                Ok(Some(false))
            }
            E::CommitRequest => {
                let next = S::Committing;
                if !self.can_transition(&self.state, &next) {
                    let msg = format!("Invalid transition: {:?} -> CommitRequest", self.state);
                    if let Some(m) = &self.metrics { m.record_error("commit_req", &msg) }
                    self.state = S::Failed { error: msg.clone() };
                    return Err(msg.into());
                }
                self.state = next;
                Ok(None)
            }
            E::CommitComplete => {
                // Perform commit action
                let t0 = Instant::now();
                if !matches!(self.state, S::Committing) {
                    let msg = format!("Invalid transition: {:?} -> CommitComplete", self.state);
                    if let Some(m) = &self.metrics { m.record_error("commit_complete", &msg) }
                    self.state = S::Failed { error: msg.clone() };
                    return Err(msg.into());
                }
                let txn_id = self
                    .txn_id
                    .as_deref()
                    .ok_or_else(|| "No transaction id present".to_string())?;
                self.txn_mgr.commit(txn_id).await.map_err(|e| {
                    if let Some(m) = &self.metrics { m.record_error("commit", &e) }
                    e
                })?;
                if let Some(m) = &self.metrics { m.record_commit(t0.elapsed()) }
                self.state = S::Completed { committed: true };
                Ok(Some(true))
            }
            E::RollbackRequest { reason } => {
                let next = S::RollingBack { reason: reason.clone() };
                if !self.can_transition(&self.state, &next) {
                    let msg = format!("Invalid transition: {:?} -> RollbackRequest", self.state);
                    if let Some(m) = &self.metrics { m.record_error("rollback_req", &msg) }
                    self.state = S::Failed { error: msg.clone() };
                    return Err(msg.into());
                }
                self.state = next;
                Ok(None)
            }
            E::RollbackComplete => {
                // Perform rollback action
                let t0 = Instant::now();
                let txn_id = self
                    .txn_id
                    .as_deref()
                    .ok_or_else(|| "No transaction id present".to_string())?;
                let reason = match &self.state {
                    S::RollingBack { reason } => reason.as_str(),
                    _ => "unspecified",
                };
                self.txn_mgr.rollback(txn_id, reason).await.map_err(|e| {
                    if let Some(m) = &self.metrics { m.record_error("rollback", &e) }
                    e
                })?;
                if let Some(m) = &self.metrics { m.record_rollback(t0.elapsed(), reason) }
                self.state = S::Completed { committed: false };
                Ok(Some(false))
            }
            E::Error(message) => {
                if let Some(m) = &self.metrics { m.record_error("event_error", &message) }
                self.state = S::Failed { error: message.clone() };
                Err(message.into())
            }
        }
    }

    async fn reset(&mut self) -> Result<(), Self::Error> {
        self.state = BackendTxnState::Opening;
        self.txn_id = None;
        self.reads_performed = 0;
        self.writes_performed = 0;
        self.indexes_updated = 0;
        self.start_time = Instant::now();
        Ok(())
    }
}

#[async_trait]
impl BackendTxnFsm for BackendTxnFsmImpl {
    fn transaction_id(&self) -> Option<&str> {
        self.txn_id.as_deref()
    }

    fn reads_performed(&self) -> usize {
        self.reads_performed
    }

    fn writes_performed(&self) -> usize {
        self.writes_performed
    }

    fn can_commit(&self) -> bool {
        use BackendTxnState as S;
        matches!(
            self.state,
            S::Reading { .. } | S::Writing { .. } | S::UpdatingIndexes { .. } | S::Committing
        ) && self.txn_id.is_some()
    }

    fn can_rollback(&self) -> bool {
        !matches!(self.state, BackendTxnState::Completed { .. }) && self.txn_id.is_some()
    }

    fn nesting_level(&self) -> u32 {
        self.txn_mgr.nesting_level()
    }
}

// ================================================================================================
// Unit Tests (with Mocks)
// ================================================================================================

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    // ----------------------------
    // Mocks
    // ----------------------------

    pub struct MockTxnMgr {
        pub next_id: Arc<Mutex<u64>>,
        pub commit_calls: Arc<Mutex<usize>>,
        pub rollback_calls: Arc<Mutex<usize>>,
        pub level: u32,
        pub fail_mode: bool,
    }

    impl MockTxnMgr {
        pub fn new() -> Self {
            Self {
                next_id: Arc::new(Mutex::new(1)),
                commit_calls: Arc::new(Mutex::new(0)),
                rollback_calls: Arc::new(Mutex::new(0)),
                level: 1,
                fail_mode: false,
            }
        }
        pub fn with_fail(mut self) -> Self { self.fail_mode = true; self }
        pub fn with_level(mut self, level: u32) -> Self { self.level = level; self }
    }

    #[async_trait]
    impl TransactionManager for MockTxnMgr {
        async fn open_transaction(&self) -> Result<String, String> {
            if self.fail_mode { return Err("open fail".into()); }
            let mut id = self.next_id.lock().unwrap();
            let s = format!("txn-{}", *id);
            *id += 1;
            Ok(s)
        }
        async fn commit(&self, _txn_id: &str) -> Result<(), String> {
            if self.fail_mode { return Err("commit fail".into()); }
            *self.commit_calls.lock().unwrap() += 1;
            Ok(())
        }
        async fn rollback(&self, _txn_id: &str, _reason: &str) -> Result<(), String> {
            if self.fail_mode { return Err("rollback fail".into()); }
            *self.rollback_calls.lock().unwrap() += 1;
            Ok(())
        }
        fn nesting_level(&self) -> u32 { self.level }
    }

    pub struct MockStore {
        pub reads: Arc<Mutex<usize>>,
        pub writes: Arc<Mutex<usize>>,
        pub fail_mode: bool,
    }
    impl MockStore { pub fn new() -> Self { Self { reads: Arc::new(Mutex::new(0)), writes: Arc::new(Mutex::new(0)), fail_mode: false } } pub fn with_fail(mut self) -> Self { self.fail_mode = true; self } }

    #[async_trait]
    impl DataStore for MockStore {
        async fn read(&self, _key: &str) -> Result<Option<Vec<u8>>, String> {
            if self.fail_mode { return Err("read fail".into()); }
            *self.reads.lock().unwrap() += 1;
            Ok(Some(b"value".to_vec()))
        }
        async fn write(&self, _txn_id: &str, _op: BackendOperation) -> Result<(), String> {
            if self.fail_mode { return Err("write fail".into()); }
            *self.writes.lock().unwrap() += 1;
            Ok(())
        }
    }

    pub struct MockIndexer {
        pub updates: Arc<Mutex<usize>>,
        pub fail_mode: bool,
    }
    impl MockIndexer { pub fn new() -> Self { Self { updates: Arc::new(Mutex::new(0)), fail_mode: false } } pub fn with_fail(mut self) -> Self { self.fail_mode = true; self } }

    #[async_trait]
    impl IndexManager for MockIndexer {
        async fn update_indexes(&self, _txn_id: &str) -> Result<usize, String> {
            if self.fail_mode { return Err("index fail".into()); }
            *self.updates.lock().unwrap() += 1;
            Ok(1)
        }
    }

    pub struct MockMetrics { pub events: Arc<Mutex<Vec<String>>> }
    impl MockMetrics { pub fn new() -> Self { Self { events: Arc::new(Mutex::new(vec![])) } } }
    impl TxnMetrics for MockMetrics {
        fn record_txn_open(&self, _t: Duration) { self.events.lock().unwrap().push("open".into()); }
        fn record_read(&self, _t: Duration) { self.events.lock().unwrap().push("read".into()); }
        fn record_write(&self, _t: Duration) { self.events.lock().unwrap().push("write".into()); }
        fn record_index_update(&self, _t: Duration, _i: usize) { self.events.lock().unwrap().push("index".into()); }
        fn record_commit(&self, _t: Duration) { self.events.lock().unwrap().push("commit".into()); }
        fn record_rollback(&self, _t: Duration, _r: &str) { self.events.lock().unwrap().push("rollback".into()); }
        fn record_error(&self, ctx: &str, _m: &str) { self.events.lock().unwrap().push(format!("error:{ctx}")); }
    }

    fn make_fsm() -> BackendTxnFsmImpl {
        BackendTxnFsmImpl::new(
            Box::new(MockTxnMgr::new()),
            Box::new(MockStore::new()),
            Box::new(MockIndexer::new()),
        )
    }

    // ----------------------------
    // Init tests for each method and basic transitions
    // ----------------------------

    #[tokio::test]
    async fn test_open_transaction_flow() {
        let mut fsm = make_fsm();
        assert!(matches!(fsm.current_state(), BackendTxnState::Opening));
        fsm.handle_event(BackendTxnEvent::OpenTransaction).await.unwrap();
        assert!(matches!(fsm.current_state(), BackendTxnState::Reading { .. }));
        assert!(fsm.transaction_id().is_some());
        assert_eq!(fsm.nesting_level(), 1);
    }

    #[tokio::test]
    async fn test_read_flow() {
        let mut fsm = make_fsm();
        fsm.handle_event(BackendTxnEvent::OpenTransaction).await.unwrap();
        fsm.handle_event(BackendTxnEvent::ReadRequest).await.unwrap();
        let res = fsm.handle_event(BackendTxnEvent::ReadComplete).await.unwrap();
        assert_eq!(res, Some(false));
        assert_eq!(fsm.reads_performed(), 1);
    }

    #[tokio::test]
    async fn test_write_flow() {
        let mut fsm = make_fsm();
        fsm.handle_event(BackendTxnEvent::OpenTransaction).await.unwrap();
        fsm
            .handle_event(BackendTxnEvent::WriteRequest { operation: BackendOperation::Insert { key: "k".into(), value: b"v".to_vec() } })
            .await
            .unwrap();
        let res = fsm.handle_event(BackendTxnEvent::WriteComplete).await.unwrap();
        assert_eq!(res, Some(false));
        assert_eq!(fsm.writes_performed(), 1);
    }

    #[tokio::test]
    async fn test_index_update_flow() {
        let mut fsm = make_fsm();
        fsm.handle_event(BackendTxnEvent::OpenTransaction).await.unwrap();
        fsm.handle_event(BackendTxnEvent::IndexUpdateRequest).await.unwrap();
        let res = fsm.handle_event(BackendTxnEvent::IndexUpdateComplete).await.unwrap();
        assert_eq!(res, Some(false));
        assert!(matches!(fsm.current_state(), BackendTxnState::Reading { .. }));
    }

    #[tokio::test]
    async fn test_commit_flow() {
        let mut fsm = make_fsm();
        fsm.handle_event(BackendTxnEvent::OpenTransaction).await.unwrap();
        assert!(fsm.can_commit());
        fsm.handle_event(BackendTxnEvent::CommitRequest).await.unwrap();
        let res = fsm.handle_event(BackendTxnEvent::CommitComplete).await.unwrap();
        assert_eq!(res, Some(true));
        assert!(matches!(fsm.current_state(), BackendTxnState::Completed { committed: true }));
    }

    #[tokio::test]
    async fn test_rollback_flow() {
        let mut fsm = make_fsm();
        fsm.handle_event(BackendTxnEvent::OpenTransaction).await.unwrap();
        assert!(fsm.can_rollback());
        fsm
            .handle_event(BackendTxnEvent::RollbackRequest { reason: "test".into() })
            .await
            .unwrap();
        let res = fsm.handle_event(BackendTxnEvent::RollbackComplete).await.unwrap();
        assert_eq!(res, Some(false));
        assert!(matches!(fsm.current_state(), BackendTxnState::Completed { committed: false }));
    }

    #[tokio::test]
    async fn test_invalid_transition_rejected() {
        let mut fsm = make_fsm();
        // Cannot commit before opening transaction
        let err = fsm.handle_event(BackendTxnEvent::CommitRequest).await.unwrap_err();
        let _ = err; // just ensure it errored
        assert!(matches!(fsm.current_state(), BackendTxnState::Failed { .. }));
    }

    #[tokio::test]
    async fn test_reset() {
        let mut fsm = make_fsm();
        let _ = fsm.handle_event(BackendTxnEvent::OpenTransaction).await.unwrap();
        fsm.reset().await.unwrap();
        assert!(matches!(fsm.current_state(), BackendTxnState::Opening));
        assert!(fsm.transaction_id().is_none());
        assert_eq!(fsm.reads_performed(), 0);
        assert_eq!(fsm.writes_performed(), 0);
    }

    // ----------------------------
    // Additional comprehensive tests
    // ----------------------------

    #[tokio::test]
    async fn test_fsm_with_metrics() {
        let txn_mgr = Box::new(MockTxnMgr::new());
        let store = Box::new(MockStore::new());
        let indexer = Box::new(MockIndexer::new());
        let metrics = Box::new(MockMetrics::new());
        
        let mut fsm = BackendTxnFsmImpl::new(txn_mgr, store, indexer).with_metrics(metrics);
        
        fsm.handle_event(BackendTxnEvent::OpenTransaction).await.unwrap();
        fsm.handle_event(BackendTxnEvent::ReadRequest).await.unwrap();
        fsm.handle_event(BackendTxnEvent::ReadComplete).await.unwrap();
        fsm.handle_event(BackendTxnEvent::CommitRequest).await.unwrap();
        fsm.handle_event(BackendTxnEvent::CommitComplete).await.unwrap();
        
        assert!(matches!(fsm.current_state(), BackendTxnState::Completed { committed: true }));
    }

    #[tokio::test]
    async fn test_transaction_opened_event_rejected() {
        let mut fsm = make_fsm();
        let err = fsm.handle_event(BackendTxnEvent::TransactionOpened { txn_id: "test".into() }).await.unwrap_err();
        assert!(err.to_string().contains("TransactionOpened event is not used"));
        assert!(matches!(fsm.current_state(), BackendTxnState::Failed { .. }));
    }

    #[tokio::test]
    async fn test_multiple_read_write_cycle() {
        let mut fsm = make_fsm();
        fsm.handle_event(BackendTxnEvent::OpenTransaction).await.unwrap();
        
        // Read -> Write -> Read -> Write
        fsm.handle_event(BackendTxnEvent::ReadRequest).await.unwrap();
        fsm.handle_event(BackendTxnEvent::ReadComplete).await.unwrap();
        
        fsm.handle_event(BackendTxnEvent::WriteRequest { 
            operation: BackendOperation::Insert { key: "k1".into(), value: b"v1".to_vec() } 
        }).await.unwrap();
        fsm.handle_event(BackendTxnEvent::WriteComplete).await.unwrap();
        
        fsm.handle_event(BackendTxnEvent::ReadRequest).await.unwrap();
        fsm.handle_event(BackendTxnEvent::ReadComplete).await.unwrap();
        
        fsm.handle_event(BackendTxnEvent::WriteRequest { 
            operation: BackendOperation::Update { key: "k1".into(), value: b"v2".to_vec() } 
        }).await.unwrap();
        fsm.handle_event(BackendTxnEvent::WriteComplete).await.unwrap();
        
        assert_eq!(fsm.reads_performed(), 2);
        assert_eq!(fsm.writes_performed(), 2);
        assert!(fsm.can_commit());
        assert!(fsm.can_rollback());
    }

    #[tokio::test]
    async fn test_index_update_between_operations() {
        let mut fsm = make_fsm();
        fsm.handle_event(BackendTxnEvent::OpenTransaction).await.unwrap();
        
        // Write -> Index Update -> Read -> Index Update -> Commit
        fsm.handle_event(BackendTxnEvent::WriteRequest { 
            operation: BackendOperation::Insert { key: "k".into(), value: b"v".to_vec() } 
        }).await.unwrap();
        fsm.handle_event(BackendTxnEvent::WriteComplete).await.unwrap();
        
        fsm.handle_event(BackendTxnEvent::IndexUpdateRequest).await.unwrap();
        fsm.handle_event(BackendTxnEvent::IndexUpdateComplete).await.unwrap();
        
        fsm.handle_event(BackendTxnEvent::ReadRequest).await.unwrap();
        fsm.handle_event(BackendTxnEvent::ReadComplete).await.unwrap();
        
        fsm.handle_event(BackendTxnEvent::IndexUpdateRequest).await.unwrap();
        fsm.handle_event(BackendTxnEvent::IndexUpdateComplete).await.unwrap();
        
        fsm.handle_event(BackendTxnEvent::CommitRequest).await.unwrap();
        fsm.handle_event(BackendTxnEvent::CommitComplete).await.unwrap();
        
        assert_eq!(fsm.reads_performed(), 1);
        assert_eq!(fsm.writes_performed(), 1);
        assert!(matches!(fsm.current_state(), BackendTxnState::Completed { committed: true }));
    }

    #[tokio::test]
    async fn test_error_event_handling() {
        let mut fsm = make_fsm();
        fsm.handle_event(BackendTxnEvent::OpenTransaction).await.unwrap();
        
        let err = fsm.handle_event(BackendTxnEvent::Error("Test error".into())).await.unwrap_err();
        assert_eq!(err.to_string(), "Backend transaction error: Test error");
        assert!(matches!(fsm.current_state(), BackendTxnState::Failed { .. }));
    }

    #[tokio::test]
    async fn test_terminal_state_detection() {
        let mut fsm = make_fsm();
        assert!(!fsm.is_terminal()); // Opening
        
        fsm.handle_event(BackendTxnEvent::OpenTransaction).await.unwrap();
        assert!(!fsm.is_terminal()); // Reading
        
        fsm.handle_event(BackendTxnEvent::CommitRequest).await.unwrap();
        assert!(!fsm.is_terminal()); // Committing
        
        fsm.handle_event(BackendTxnEvent::CommitComplete).await.unwrap();
        assert!(fsm.is_terminal()); // Completed
    }

    #[tokio::test]
    async fn test_failed_state_is_terminal() {
        let mut fsm = make_fsm();
        let _ = fsm.handle_event(BackendTxnEvent::CommitRequest).await.unwrap_err(); // Invalid transition
        assert!(fsm.is_terminal());
    }

    #[tokio::test]
    async fn test_write_complete_in_wrong_state() {
        let mut fsm = make_fsm();
        fsm.handle_event(BackendTxnEvent::OpenTransaction).await.unwrap();
        
        let err = fsm.handle_event(BackendTxnEvent::WriteComplete).await.unwrap_err();
        assert!(err.to_string().contains("Invalid transition"));
        assert!(matches!(fsm.current_state(), BackendTxnState::Failed { .. }));
    }

    #[tokio::test]
    async fn test_rollback_with_reason() {
        let mut fsm = make_fsm();
        fsm.handle_event(BackendTxnEvent::OpenTransaction).await.unwrap();
        
        fsm.handle_event(BackendTxnEvent::RollbackRequest { reason: "User requested".into() }).await.unwrap();
        assert!(matches!(fsm.current_state(), BackendTxnState::RollingBack { .. }));
        
        let res = fsm.handle_event(BackendTxnEvent::RollbackComplete).await.unwrap();
        assert_eq!(res, Some(false));
        assert!(matches!(fsm.current_state(), BackendTxnState::Completed { committed: false }));
    }

    #[tokio::test]
    async fn test_different_write_operations() {
        let mut fsm = make_fsm();
        fsm.handle_event(BackendTxnEvent::OpenTransaction).await.unwrap();
        
        // Insert
        fsm.handle_event(BackendTxnEvent::WriteRequest { 
            operation: BackendOperation::Insert { key: "k1".into(), value: b"v1".to_vec() } 
        }).await.unwrap();
        fsm.handle_event(BackendTxnEvent::WriteComplete).await.unwrap();
        
        // Update
        fsm.handle_event(BackendTxnEvent::WriteRequest { 
            operation: BackendOperation::Update { key: "k1".into(), value: b"v2".to_vec() } 
        }).await.unwrap();
        fsm.handle_event(BackendTxnEvent::WriteComplete).await.unwrap();
        
        // Delete
        fsm.handle_event(BackendTxnEvent::WriteRequest { 
            operation: BackendOperation::Delete { key: "k1".into() } 
        }).await.unwrap();
        fsm.handle_event(BackendTxnEvent::WriteComplete).await.unwrap();
        
        assert_eq!(fsm.writes_performed(), 3);
    }

    #[tokio::test]
    async fn test_can_commit_can_rollback_logic() {
        let mut fsm = make_fsm();
        
        // Before transaction
        assert!(!fsm.can_commit());
        assert!(!fsm.can_rollback());
        
        fsm.handle_event(BackendTxnEvent::OpenTransaction).await.unwrap();
        
        // After transaction open
        assert!(fsm.can_commit());
        assert!(fsm.can_rollback());
        
        // After write
        fsm.handle_event(BackendTxnEvent::WriteRequest { 
            operation: BackendOperation::Insert { key: "k".into(), value: b"v".to_vec() } 
        }).await.unwrap();
        assert!(fsm.can_commit());
        assert!(fsm.can_rollback());
        
        // After index update
        fsm.handle_event(BackendTxnEvent::IndexUpdateRequest).await.unwrap();
        fsm.handle_event(BackendTxnEvent::IndexUpdateComplete).await.unwrap();
        assert!(fsm.can_commit());
        assert!(fsm.can_rollback());
        
        // After commit
        fsm.handle_event(BackendTxnEvent::CommitRequest).await.unwrap();
        fsm.handle_event(BackendTxnEvent::CommitComplete).await.unwrap();
        assert!(!fsm.can_commit());
        assert!(!fsm.can_rollback());
    }

    #[tokio::test]
    async fn test_nesting_level() {
        let txn_mgr = Box::new(MockTxnMgr::new().with_level(2));
        let store = Box::new(MockStore::new());
        let indexer = Box::new(MockIndexer::new());
        
        let fsm = BackendTxnFsmImpl::new(txn_mgr, store, indexer);
        assert_eq!(fsm.nesting_level(), 2);
    }

    // ----------------------------
    // Mock behavior tests
    // ----------------------------

    #[tokio::test]
    async fn test_mock_txn_mgr_behavior() {
        let mock = MockTxnMgr::new();
        
        let txn_id = mock.open_transaction().await.unwrap();
        assert_eq!(txn_id, "txn-1");
        
        let txn_id2 = mock.open_transaction().await.unwrap();
        assert_eq!(txn_id2, "txn-2");
        
        mock.commit(&txn_id).await.unwrap();
        assert_eq!(*mock.commit_calls.lock().unwrap(), 1);
        
        mock.rollback(&txn_id2, "test reason").await.unwrap();
        assert_eq!(*mock.rollback_calls.lock().unwrap(), 1);
        
        assert_eq!(mock.nesting_level(), 1);
    }

    #[tokio::test]
    async fn test_mock_txn_mgr_failure() {
        let mock = MockTxnMgr::new().with_fail();
        
        let err = mock.open_transaction().await.unwrap_err();
        assert_eq!(err, "open fail");
        
        let err = mock.commit("test").await.unwrap_err();
        assert_eq!(err, "commit fail");
        
        let err = mock.rollback("test", "reason").await.unwrap_err();
        assert_eq!(err, "rollback fail");
    }

    #[tokio::test]
    async fn test_mock_store_behavior() {
        let mock = MockStore::new();
        
        let value = mock.read("test-key").await.unwrap();
        assert_eq!(value, Some(b"value".to_vec()));
        assert_eq!(*mock.reads.lock().unwrap(), 1);
        
        mock.write("txn-1", BackendOperation::Insert { key: "k".into(), value: b"v".to_vec() }).await.unwrap();
        assert_eq!(*mock.writes.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn test_mock_store_failure() {
        let mock = MockStore::new().with_fail();
        
        let err = mock.read("test-key").await.unwrap_err();
        assert_eq!(err, "read fail");
        
        let err = mock.write("txn-1", BackendOperation::Insert { key: "k".into(), value: b"v".to_vec() }).await.unwrap_err();
        assert_eq!(err, "write fail");
    }

    #[tokio::test]
    async fn test_mock_indexer_behavior() {
        let mock = MockIndexer::new();
        
        let updated = mock.update_indexes("txn-1").await.unwrap();
        assert_eq!(updated, 1);
        assert_eq!(*mock.updates.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn test_mock_indexer_failure() {
        let mock = MockIndexer::new().with_fail();
        
        let err = mock.update_indexes("txn-1").await.unwrap_err();
        assert_eq!(err, "index fail");
    }

    #[tokio::test]
    async fn test_mock_metrics_behavior() {
        let mock = MockMetrics::new();
        
        mock.record_txn_open(Duration::from_millis(1));
        mock.record_read(Duration::from_millis(2));
        mock.record_write(Duration::from_millis(3));
        mock.record_index_update(Duration::from_millis(4), 2);
        mock.record_commit(Duration::from_millis(5));
        mock.record_rollback(Duration::from_millis(6), "test");
        mock.record_error("test_context", "test message");
        
        let events = mock.events.lock().unwrap();
        assert_eq!(events.len(), 7);
        assert!(events.contains(&"open".to_string()));
        assert!(events.contains(&"read".to_string()));
        assert!(events.contains(&"write".to_string()));
        assert!(events.contains(&"index".to_string()));
        assert!(events.contains(&"commit".to_string()));
        assert!(events.contains(&"rollback".to_string()));
        assert!(events.contains(&"error:test_context".to_string()));
    }

    #[tokio::test]
    async fn test_error_display() {
        let error = BackendTxnError::Generic("Test error".into());
        assert_eq!(error.to_string(), "Backend transaction error: Test error");
        
        let error = BackendTxnError::TransactionError("Txn error".into());
        assert_eq!(error.to_string(), "Transaction error: Txn error");
        
        let error = BackendTxnError::NoTransactionId;
        assert_eq!(error.to_string(), "No transaction ID present");
    }
}
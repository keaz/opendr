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
    BackendOperation, BackendTxnEvent, BackendTxnFsm, BackendTxnOutput, BackendTxnState,
    StateMachine,
};

// ================================================================================================
// Error Types
// ================================================================================================

/// Errors that can occur in the Backend Transaction FSM
#[derive(Debug)]
pub enum BackendTxnError {
    /// Invalid state transition attempted
    InvalidStateTransition {
        from: BackendTxnState,
        to: BackendTxnState,
    },
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
    async fn update_indexes(&self, txn_id: &str, index_keys: &[String]) -> Result<usize, String>;
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

    fn invalid_transition(&self, to: BackendTxnState) -> BackendTxnError {
        BackendTxnError::InvalidStateTransition {
            from: self.state.clone(),
            to,
        }
    }

    fn fail(&mut self, context: &str, err: BackendTxnError) -> BackendTxnError {
        if let Some(metrics) = &self.metrics {
            metrics.record_error(context, &err.to_string());
        }
        self.state = BackendTxnState::Failed {
            error: err.to_string(),
        };
        err
    }

    fn require_txn_id(&mut self, context: &str) -> Result<String, BackendTxnError> {
        self.txn_id
            .clone()
            .ok_or_else(|| self.fail(context, BackendTxnError::NoTransactionId))
    }

    fn in_active_transaction(&self) -> bool {
        matches!(
            self.state,
            BackendTxnState::Reading { .. }
                | BackendTxnState::Writing { .. }
                | BackendTxnState::UpdatingIndexes { .. }
        )
    }
}

#[async_trait]
impl StateMachine for BackendTxnFsmImpl {
    type State = BackendTxnState;
    type Event = BackendTxnEvent;
    type Error = BackendTxnError;
    type Output = BackendTxnOutput;

    fn current_state(&self) -> &Self::State {
        &self.state
    }

    fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            BackendTxnState::Completed { .. } | BackendTxnState::Failed { .. }
        )
    }

    async fn handle_event(
        &mut self,
        event: Self::Event,
    ) -> Result<Option<Self::Output>, Self::Error> {
        use BackendTxnEvent as E;
        use BackendTxnState as S;

        match event {
            E::OpenTransaction => {
                if !matches!(self.state, S::Opening) {
                    return Err(self.invalid_transition(S::Opening));
                }

                let t0 = Instant::now();
                let txn_id = match self.txn_mgr.open_transaction().await {
                    Ok(txn_id) => txn_id,
                    Err(err) => {
                        return Err(self.fail("open", BackendTxnError::TransactionError(err)));
                    }
                };

                self.txn_id = Some(txn_id);
                if let Some(m) = &self.metrics {
                    m.record_txn_open(t0.elapsed())
                }

                let txn_id = self.txn_id.clone().expect("txn_id set after open");
                self.state = S::Reading { reads_performed: 0 };
                Ok(Some(BackendTxnOutput::TransactionOpened { txn_id }))
            }
            E::ReadRequest { key } => {
                if !self.in_active_transaction() {
                    return Err(self.invalid_transition(S::Reading {
                        reads_performed: self.reads_performed,
                    }));
                }

                let _txn_id = self.require_txn_id("read_txn")?;
                let t0 = Instant::now();
                let value = match self.store.read(&key).await {
                    Ok(value) => value,
                    Err(err) => {
                        return Err(self.fail("read", BackendTxnError::DataStoreError(err)));
                    }
                };

                self.reads_performed += 1;
                self.state = S::Reading {
                    reads_performed: self.reads_performed,
                };
                if let Some(m) = &self.metrics {
                    m.record_read(t0.elapsed())
                }

                Ok(Some(BackendTxnOutput::ReadResult { value }))
            }
            E::WriteRequest { operation } => {
                if !self.in_active_transaction() {
                    return Err(self.invalid_transition(S::Writing {
                        writes_performed: self.writes_performed,
                    }));
                }

                let t0 = Instant::now();
                let txn_id = self.require_txn_id("write_txn")?;
                if let Err(err) = self.store.write(&txn_id, operation).await {
                    return Err(self.fail("write", BackendTxnError::DataStoreError(err)));
                }

                self.writes_performed += 1;
                self.state = S::Writing {
                    writes_performed: self.writes_performed,
                };
                if let Some(m) = &self.metrics {
                    m.record_write(t0.elapsed())
                }

                Ok(Some(BackendTxnOutput::WriteApplied {
                    writes_performed: self.writes_performed,
                }))
            }
            E::IndexUpdateRequest { index_keys } => {
                if !self.in_active_transaction() {
                    return Err(self.invalid_transition(S::UpdatingIndexes {
                        indexes_updated: self.indexes_updated,
                    }));
                }

                let t0 = Instant::now();
                let txn_id = self.require_txn_id("index_txn")?;
                let updated = match self.indexer.update_indexes(&txn_id, &index_keys).await {
                    Ok(updated) => updated,
                    Err(err) => {
                        return Err(self.fail("index_update", BackendTxnError::IndexError(err)));
                    }
                };

                self.indexes_updated += updated;
                self.state = S::UpdatingIndexes {
                    indexes_updated: self.indexes_updated,
                };
                if let Some(m) = &self.metrics {
                    m.record_index_update(t0.elapsed(), updated)
                }

                Ok(Some(BackendTxnOutput::IndexesUpdated {
                    updated,
                    total: self.indexes_updated,
                }))
            }
            E::CommitRequest => {
                if !self.in_active_transaction() {
                    return Err(self.invalid_transition(S::Committing));
                }

                let t0 = Instant::now();
                let txn_id = self.require_txn_id("commit_txn")?;
                self.state = S::Committing;
                if let Err(err) = self.txn_mgr.commit(&txn_id).await {
                    return Err(self.fail("commit", BackendTxnError::TransactionError(err)));
                }
                if let Some(m) = &self.metrics {
                    m.record_commit(t0.elapsed())
                }
                self.state = S::Completed { committed: true };
                Ok(Some(BackendTxnOutput::Finished { committed: true }))
            }
            E::RollbackRequest { reason } => {
                if !self.in_active_transaction() {
                    return Err(self.invalid_transition(S::RollingBack {
                        reason: reason.clone(),
                    }));
                }

                let t0 = Instant::now();
                let txn_id = self.require_txn_id("rollback_txn")?;
                self.state = S::RollingBack {
                    reason: reason.clone(),
                };
                if let Err(err) = self.txn_mgr.rollback(&txn_id, &reason).await {
                    return Err(self.fail("rollback", BackendTxnError::TransactionError(err)));
                }
                if let Some(m) = &self.metrics {
                    m.record_rollback(t0.elapsed(), &reason)
                }
                self.state = S::Completed { committed: false };
                Ok(Some(BackendTxnOutput::Finished { committed: false }))
            }
            E::Error(message) => Err(self.fail("event_error", BackendTxnError::Generic(message))),
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
        self.in_active_transaction() && self.txn_id.is_some()
    }

    fn can_rollback(&self) -> bool {
        self.in_active_transaction() && self.txn_id.is_some()
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

    pub struct MockTxnMgr {
        pub next_id: Arc<Mutex<u64>>,
        pub commit_calls: Arc<Mutex<usize>>,
        pub rollback_calls: Arc<Mutex<usize>>,
        pub rollback_reasons: Arc<Mutex<Vec<String>>>,
        pub level: u32,
        pub open_fail: bool,
        pub commit_fail: bool,
        pub rollback_fail: bool,
    }

    impl MockTxnMgr {
        pub fn new() -> Self {
            Self {
                next_id: Arc::new(Mutex::new(1)),
                commit_calls: Arc::new(Mutex::new(0)),
                rollback_calls: Arc::new(Mutex::new(0)),
                rollback_reasons: Arc::new(Mutex::new(Vec::new())),
                level: 1,
                open_fail: false,
                commit_fail: false,
                rollback_fail: false,
            }
        }

        pub fn with_open_fail(mut self) -> Self {
            self.open_fail = true;
            self
        }

        pub fn with_commit_fail(mut self) -> Self {
            self.commit_fail = true;
            self
        }

        pub fn with_rollback_fail(mut self) -> Self {
            self.rollback_fail = true;
            self
        }

        pub fn with_level(mut self, level: u32) -> Self {
            self.level = level;
            self
        }
    }

    #[async_trait]
    impl TransactionManager for MockTxnMgr {
        async fn open_transaction(&self) -> Result<String, String> {
            if self.open_fail {
                return Err("open fail".into());
            }
            let mut id = self.next_id.lock().unwrap();
            let txn_id = format!("txn-{}", *id);
            *id += 1;
            Ok(txn_id)
        }

        async fn commit(&self, _txn_id: &str) -> Result<(), String> {
            if self.commit_fail {
                return Err("commit fail".into());
            }
            *self.commit_calls.lock().unwrap() += 1;
            Ok(())
        }

        async fn rollback(&self, _txn_id: &str, reason: &str) -> Result<(), String> {
            if self.rollback_fail {
                return Err("rollback fail".into());
            }
            *self.rollback_calls.lock().unwrap() += 1;
            self.rollback_reasons
                .lock()
                .unwrap()
                .push(reason.to_string());
            Ok(())
        }

        fn nesting_level(&self) -> u32 {
            self.level
        }
    }

    pub struct MockStore {
        pub read_keys: Arc<Mutex<Vec<String>>>,
        pub write_ops: Arc<Mutex<Vec<BackendOperation>>>,
        pub read_fail: bool,
        pub write_fail: bool,
    }

    impl MockStore {
        pub fn new() -> Self {
            Self {
                read_keys: Arc::new(Mutex::new(Vec::new())),
                write_ops: Arc::new(Mutex::new(Vec::new())),
                read_fail: false,
                write_fail: false,
            }
        }

        pub fn with_read_fail(mut self) -> Self {
            self.read_fail = true;
            self
        }

        pub fn with_write_fail(mut self) -> Self {
            self.write_fail = true;
            self
        }
    }

    #[async_trait]
    impl DataStore for MockStore {
        async fn read(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
            if self.read_fail {
                return Err("read fail".into());
            }
            self.read_keys.lock().unwrap().push(key.to_string());
            Ok(Some(format!("value:{key}").into_bytes()))
        }

        async fn write(&self, _txn_id: &str, op: BackendOperation) -> Result<(), String> {
            if self.write_fail {
                return Err("write fail".into());
            }
            self.write_ops.lock().unwrap().push(op);
            Ok(())
        }
    }

    pub struct MockIndexer {
        pub update_calls: Arc<Mutex<Vec<Vec<String>>>>,
        pub fail_mode: bool,
    }

    impl MockIndexer {
        pub fn new() -> Self {
            Self {
                update_calls: Arc::new(Mutex::new(Vec::new())),
                fail_mode: false,
            }
        }

        pub fn with_fail(mut self) -> Self {
            self.fail_mode = true;
            self
        }
    }

    #[async_trait]
    impl IndexManager for MockIndexer {
        async fn update_indexes(
            &self,
            _txn_id: &str,
            index_keys: &[String],
        ) -> Result<usize, String> {
            if self.fail_mode {
                return Err("index fail".into());
            }
            self.update_calls.lock().unwrap().push(index_keys.to_vec());
            Ok(index_keys.len())
        }
    }

    pub struct MockMetrics {
        pub events: Arc<Mutex<Vec<String>>>,
    }

    impl MockMetrics {
        pub fn new() -> Self {
            Self {
                events: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl TxnMetrics for MockMetrics {
        fn record_txn_open(&self, _t: Duration) {
            self.events.lock().unwrap().push("open".into());
        }
        fn record_read(&self, _t: Duration) {
            self.events.lock().unwrap().push("read".into());
        }
        fn record_write(&self, _t: Duration) {
            self.events.lock().unwrap().push("write".into());
        }
        fn record_index_update(&self, _t: Duration, _i: usize) {
            self.events.lock().unwrap().push("index".into());
        }
        fn record_commit(&self, _t: Duration) {
            self.events.lock().unwrap().push("commit".into());
        }
        fn record_rollback(&self, _t: Duration, _r: &str) {
            self.events.lock().unwrap().push("rollback".into());
        }
        fn record_error(&self, ctx: &str, _m: &str) {
            self.events.lock().unwrap().push(format!("error:{ctx}"));
        }
    }

    fn make_fsm() -> BackendTxnFsmImpl {
        BackendTxnFsmImpl::new(
            Box::new(MockTxnMgr::new()),
            Box::new(MockStore::new()),
            Box::new(MockIndexer::new()),
        )
    }

    #[tokio::test]
    async fn test_open_transaction_returns_txn_id_and_enters_reading() {
        let mut fsm = make_fsm();

        let result = fsm
            .handle_event(BackendTxnEvent::OpenTransaction)
            .await
            .unwrap();

        assert_eq!(
            result,
            Some(BackendTxnOutput::TransactionOpened {
                txn_id: "txn-1".to_string(),
            })
        );
        assert_eq!(fsm.transaction_id(), Some("txn-1"));
        assert!(matches!(
            fsm.current_state(),
            BackendTxnState::Reading { reads_performed: 0 }
        ));
    }

    #[tokio::test]
    async fn test_read_request_uses_explicit_key_and_returns_store_value() {
        let store = MockStore::new();
        let read_keys = store.read_keys.clone();
        let mut fsm = BackendTxnFsmImpl::new(
            Box::new(MockTxnMgr::new()),
            Box::new(store),
            Box::new(MockIndexer::new()),
        );

        fsm.handle_event(BackendTxnEvent::OpenTransaction)
            .await
            .unwrap();

        let result = fsm
            .handle_event(BackendTxnEvent::ReadRequest {
                key: "user:42".into(),
            })
            .await
            .unwrap();

        assert_eq!(
            result,
            Some(BackendTxnOutput::ReadResult {
                value: Some(b"value:user:42".to_vec()),
            })
        );
        assert_eq!(read_keys.lock().unwrap().as_slice(), ["user:42"]);
        assert_eq!(fsm.reads_performed(), 1);
        assert!(matches!(
            fsm.current_state(),
            BackendTxnState::Reading { reads_performed: 1 }
        ));
    }

    #[tokio::test]
    async fn test_write_request_executes_side_effect_once_and_updates_count() {
        let store = MockStore::new();
        let write_ops = store.write_ops.clone();
        let mut fsm = BackendTxnFsmImpl::new(
            Box::new(MockTxnMgr::new()),
            Box::new(store),
            Box::new(MockIndexer::new()),
        );

        fsm.handle_event(BackendTxnEvent::OpenTransaction)
            .await
            .unwrap();

        let operation = BackendOperation::Insert {
            key: "k".into(),
            value: b"v".to_vec(),
        };
        let result = fsm
            .handle_event(BackendTxnEvent::WriteRequest {
                operation: operation.clone(),
            })
            .await
            .unwrap();

        assert_eq!(
            result,
            Some(BackendTxnOutput::WriteApplied {
                writes_performed: 1,
            })
        );
        assert_eq!(write_ops.lock().unwrap().as_slice(), &[operation]);
        assert_eq!(fsm.writes_performed(), 1);
        assert!(matches!(
            fsm.current_state(),
            BackendTxnState::Writing {
                writes_performed: 1
            }
        ));
    }

    #[tokio::test]
    async fn test_index_update_request_uses_explicit_keys_and_returns_updated_count() {
        let indexer = MockIndexer::new();
        let update_calls = indexer.update_calls.clone();
        let mut fsm = BackendTxnFsmImpl::new(
            Box::new(MockTxnMgr::new()),
            Box::new(MockStore::new()),
            Box::new(indexer),
        );

        fsm.handle_event(BackendTxnEvent::OpenTransaction)
            .await
            .unwrap();

        let result = fsm
            .handle_event(BackendTxnEvent::IndexUpdateRequest {
                index_keys: vec!["cn".into(), "mail".into()],
            })
            .await
            .unwrap();

        assert_eq!(
            result,
            Some(BackendTxnOutput::IndexesUpdated {
                updated: 2,
                total: 2,
            })
        );
        assert_eq!(
            update_calls.lock().unwrap().as_slice(),
            &[vec!["cn".to_string(), "mail".to_string()]]
        );
        assert!(matches!(
            fsm.current_state(),
            BackendTxnState::UpdatingIndexes { indexes_updated: 2 }
        ));
    }

    #[tokio::test]
    async fn test_commit_request_performs_commit_and_finishes() {
        let txn_mgr = MockTxnMgr::new();
        let commit_calls = txn_mgr.commit_calls.clone();
        let mut fsm = BackendTxnFsmImpl::new(
            Box::new(txn_mgr),
            Box::new(MockStore::new()),
            Box::new(MockIndexer::new()),
        );

        fsm.handle_event(BackendTxnEvent::OpenTransaction)
            .await
            .unwrap();

        let result = fsm
            .handle_event(BackendTxnEvent::CommitRequest)
            .await
            .unwrap();

        assert_eq!(result, Some(BackendTxnOutput::Finished { committed: true }));
        assert_eq!(*commit_calls.lock().unwrap(), 1);
        assert!(matches!(
            fsm.current_state(),
            BackendTxnState::Completed { committed: true }
        ));
    }

    #[tokio::test]
    async fn test_rollback_request_performs_rollback_and_finishes() {
        let txn_mgr = MockTxnMgr::new();
        let rollback_calls = txn_mgr.rollback_calls.clone();
        let rollback_reasons = txn_mgr.rollback_reasons.clone();
        let mut fsm = BackendTxnFsmImpl::new(
            Box::new(txn_mgr),
            Box::new(MockStore::new()),
            Box::new(MockIndexer::new()),
        );

        fsm.handle_event(BackendTxnEvent::OpenTransaction)
            .await
            .unwrap();

        let result = fsm
            .handle_event(BackendTxnEvent::RollbackRequest {
                reason: "user_cancelled".into(),
            })
            .await
            .unwrap();

        assert_eq!(
            result,
            Some(BackendTxnOutput::Finished { committed: false })
        );
        assert_eq!(*rollback_calls.lock().unwrap(), 1);
        assert_eq!(
            rollback_reasons.lock().unwrap().as_slice(),
            &["user_cancelled".to_string()]
        );
        assert!(matches!(
            fsm.current_state(),
            BackendTxnState::Completed { committed: false }
        ));
    }

    #[tokio::test]
    async fn test_missing_txn_id_moves_to_failed_on_read_request() {
        let mut fsm = make_fsm();
        fsm.state = BackendTxnState::Reading { reads_performed: 0 };
        fsm.txn_id = None;

        let err = fsm
            .handle_event(BackendTxnEvent::ReadRequest { key: "k".into() })
            .await
            .unwrap_err();

        assert!(matches!(err, BackendTxnError::NoTransactionId));
        assert!(matches!(
            fsm.current_state(),
            BackendTxnState::Failed { .. }
        ));
    }

    #[tokio::test]
    async fn test_missing_txn_id_moves_to_failed_on_write_request() {
        let mut fsm = make_fsm();
        fsm.state = BackendTxnState::Writing {
            writes_performed: 0,
        };
        fsm.txn_id = None;

        let err = fsm
            .handle_event(BackendTxnEvent::WriteRequest {
                operation: BackendOperation::Delete { key: "k".into() },
            })
            .await
            .unwrap_err();

        assert!(matches!(err, BackendTxnError::NoTransactionId));
        assert!(matches!(
            fsm.current_state(),
            BackendTxnState::Failed { .. }
        ));
    }

    #[tokio::test]
    async fn test_missing_txn_id_moves_to_failed_on_index_update_request() {
        let mut fsm = make_fsm();
        fsm.state = BackendTxnState::UpdatingIndexes { indexes_updated: 0 };
        fsm.txn_id = None;

        let err = fsm
            .handle_event(BackendTxnEvent::IndexUpdateRequest {
                index_keys: vec!["cn".into()],
            })
            .await
            .unwrap_err();

        assert!(matches!(err, BackendTxnError::NoTransactionId));
        assert!(matches!(
            fsm.current_state(),
            BackendTxnState::Failed { .. }
        ));
    }

    #[tokio::test]
    async fn test_missing_txn_id_moves_to_failed_on_commit_request() {
        let mut fsm = make_fsm();
        fsm.state = BackendTxnState::Reading { reads_performed: 0 };
        fsm.txn_id = None;

        let err = fsm
            .handle_event(BackendTxnEvent::CommitRequest)
            .await
            .unwrap_err();

        assert!(matches!(err, BackendTxnError::NoTransactionId));
        assert!(matches!(
            fsm.current_state(),
            BackendTxnState::Failed { .. }
        ));
    }

    #[tokio::test]
    async fn test_missing_txn_id_moves_to_failed_on_rollback_request() {
        let mut fsm = make_fsm();
        fsm.state = BackendTxnState::Reading { reads_performed: 0 };
        fsm.txn_id = None;

        let err = fsm
            .handle_event(BackendTxnEvent::RollbackRequest {
                reason: "missing".into(),
            })
            .await
            .unwrap_err();

        assert!(matches!(err, BackendTxnError::NoTransactionId));
        assert!(matches!(
            fsm.current_state(),
            BackendTxnState::Failed { .. }
        ));
    }

    #[tokio::test]
    async fn test_open_failure_moves_to_failed() {
        let mut fsm = BackendTxnFsmImpl::new(
            Box::new(MockTxnMgr::new().with_open_fail()),
            Box::new(MockStore::new()),
            Box::new(MockIndexer::new()),
        );

        let err = fsm
            .handle_event(BackendTxnEvent::OpenTransaction)
            .await
            .unwrap_err();

        assert!(matches!(err, BackendTxnError::TransactionError(_)));
        assert!(matches!(
            fsm.current_state(),
            BackendTxnState::Failed { .. }
        ));
    }

    #[tokio::test]
    async fn test_store_read_failure_moves_to_failed() {
        let mut fsm = BackendTxnFsmImpl::new(
            Box::new(MockTxnMgr::new()),
            Box::new(MockStore::new().with_read_fail()),
            Box::new(MockIndexer::new()),
        );
        fsm.handle_event(BackendTxnEvent::OpenTransaction)
            .await
            .unwrap();

        let err = fsm
            .handle_event(BackendTxnEvent::ReadRequest { key: "k".into() })
            .await
            .unwrap_err();

        assert!(matches!(err, BackendTxnError::DataStoreError(_)));
        assert!(matches!(
            fsm.current_state(),
            BackendTxnState::Failed { .. }
        ));
    }

    #[tokio::test]
    async fn test_store_write_failure_moves_to_failed() {
        let mut fsm = BackendTxnFsmImpl::new(
            Box::new(MockTxnMgr::new()),
            Box::new(MockStore::new().with_write_fail()),
            Box::new(MockIndexer::new()),
        );
        fsm.handle_event(BackendTxnEvent::OpenTransaction)
            .await
            .unwrap();

        let err = fsm
            .handle_event(BackendTxnEvent::WriteRequest {
                operation: BackendOperation::Insert {
                    key: "k".into(),
                    value: b"v".to_vec(),
                },
            })
            .await
            .unwrap_err();

        assert!(matches!(err, BackendTxnError::DataStoreError(_)));
        assert!(matches!(
            fsm.current_state(),
            BackendTxnState::Failed { .. }
        ));
    }

    #[tokio::test]
    async fn test_index_update_failure_moves_to_failed() {
        let mut fsm = BackendTxnFsmImpl::new(
            Box::new(MockTxnMgr::new()),
            Box::new(MockStore::new()),
            Box::new(MockIndexer::new().with_fail()),
        );
        fsm.handle_event(BackendTxnEvent::OpenTransaction)
            .await
            .unwrap();

        let err = fsm
            .handle_event(BackendTxnEvent::IndexUpdateRequest {
                index_keys: vec!["cn".into()],
            })
            .await
            .unwrap_err();

        assert!(matches!(err, BackendTxnError::IndexError(_)));
        assert!(matches!(
            fsm.current_state(),
            BackendTxnState::Failed { .. }
        ));
    }

    #[tokio::test]
    async fn test_commit_failure_moves_to_failed() {
        let mut fsm = BackendTxnFsmImpl::new(
            Box::new(MockTxnMgr::new().with_commit_fail()),
            Box::new(MockStore::new()),
            Box::new(MockIndexer::new()),
        );
        fsm.handle_event(BackendTxnEvent::OpenTransaction)
            .await
            .unwrap();

        let err = fsm
            .handle_event(BackendTxnEvent::CommitRequest)
            .await
            .unwrap_err();

        assert!(matches!(err, BackendTxnError::TransactionError(_)));
        assert!(matches!(
            fsm.current_state(),
            BackendTxnState::Failed { .. }
        ));
    }

    #[tokio::test]
    async fn test_rollback_failure_moves_to_failed() {
        let mut fsm = BackendTxnFsmImpl::new(
            Box::new(MockTxnMgr::new().with_rollback_fail()),
            Box::new(MockStore::new()),
            Box::new(MockIndexer::new()),
        );
        fsm.handle_event(BackendTxnEvent::OpenTransaction)
            .await
            .unwrap();

        let err = fsm
            .handle_event(BackendTxnEvent::RollbackRequest {
                reason: "failed".into(),
            })
            .await
            .unwrap_err();

        assert!(matches!(err, BackendTxnError::TransactionError(_)));
        assert!(matches!(
            fsm.current_state(),
            BackendTxnState::Failed { .. }
        ));
    }

    #[tokio::test]
    async fn test_completed_state_rejects_follow_up_write_without_side_effect() {
        let store = MockStore::new();
        let write_ops = store.write_ops.clone();
        let mut fsm = BackendTxnFsmImpl::new(
            Box::new(MockTxnMgr::new()),
            Box::new(store),
            Box::new(MockIndexer::new()),
        );
        fsm.handle_event(BackendTxnEvent::OpenTransaction)
            .await
            .unwrap();
        fsm.handle_event(BackendTxnEvent::CommitRequest)
            .await
            .unwrap();

        let err = fsm
            .handle_event(BackendTxnEvent::WriteRequest {
                operation: BackendOperation::Delete { key: "k".into() },
            })
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            BackendTxnError::InvalidStateTransition { .. }
        ));
        assert!(write_ops.lock().unwrap().is_empty());
        assert!(matches!(
            fsm.current_state(),
            BackendTxnState::Completed { committed: true }
        ));
    }

    #[tokio::test]
    async fn test_failed_state_rejects_follow_up_commit_without_side_effect() {
        let txn_mgr = MockTxnMgr::new();
        let commit_calls = txn_mgr.commit_calls.clone();
        let mut fsm = BackendTxnFsmImpl::new(
            Box::new(txn_mgr.with_open_fail()),
            Box::new(MockStore::new()),
            Box::new(MockIndexer::new()),
        );

        let _ = fsm.handle_event(BackendTxnEvent::OpenTransaction).await;
        let err = fsm
            .handle_event(BackendTxnEvent::CommitRequest)
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            BackendTxnError::InvalidStateTransition { .. }
        ));
        assert_eq!(*commit_calls.lock().unwrap(), 0);
        assert!(matches!(
            fsm.current_state(),
            BackendTxnState::Failed { .. }
        ));
    }

    #[tokio::test]
    async fn test_reset_restores_opening_state() {
        let mut fsm = make_fsm();
        fsm.handle_event(BackendTxnEvent::OpenTransaction)
            .await
            .unwrap();
        fsm.handle_event(BackendTxnEvent::WriteRequest {
            operation: BackendOperation::Delete { key: "k".into() },
        })
        .await
        .unwrap();

        fsm.reset().await.unwrap();

        assert!(matches!(fsm.current_state(), BackendTxnState::Opening));
        assert!(fsm.transaction_id().is_none());
        assert_eq!(fsm.reads_performed(), 0);
        assert_eq!(fsm.writes_performed(), 0);
    }

    #[tokio::test]
    async fn test_metrics_collect_request_driven_operations() {
        let metrics = Box::new(MockMetrics::new());
        let events = metrics.events.clone();
        let mut fsm = BackendTxnFsmImpl::new(
            Box::new(MockTxnMgr::new()),
            Box::new(MockStore::new()),
            Box::new(MockIndexer::new()),
        )
        .with_metrics(metrics);

        fsm.handle_event(BackendTxnEvent::OpenTransaction)
            .await
            .unwrap();
        fsm.handle_event(BackendTxnEvent::ReadRequest { key: "k".into() })
            .await
            .unwrap();
        fsm.handle_event(BackendTxnEvent::WriteRequest {
            operation: BackendOperation::Delete { key: "k".into() },
        })
        .await
        .unwrap();
        fsm.handle_event(BackendTxnEvent::IndexUpdateRequest {
            index_keys: vec!["cn".into()],
        })
        .await
        .unwrap();
        fsm.handle_event(BackendTxnEvent::CommitRequest)
            .await
            .unwrap();

        assert_eq!(
            events.lock().unwrap().as_slice(),
            &[
                "open".to_string(),
                "read".to_string(),
                "write".to_string(),
                "index".to_string(),
                "commit".to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn test_nesting_level() {
        let fsm = BackendTxnFsmImpl::new(
            Box::new(MockTxnMgr::new().with_level(2)),
            Box::new(MockStore::new()),
            Box::new(MockIndexer::new()),
        );

        assert_eq!(fsm.nesting_level(), 2);
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

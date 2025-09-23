# Backend Transaction/Index FSM

This document describes the Backend Txn/Index FSM which coordinates short-lived backend transactions and index maintenance within the LDAP server.

Pattern: open txn → read/write → update indexes → commit/rollback

- Opening: create a transaction via TransactionManager
- Reading/Writing: perform datastore reads and writes within the transaction
- UpdatingIndexes: trigger index rebuild/maintenance safely within transaction context
- Committing/RollingBack: finalize the transaction with commit or rollback

Key properties
- Strict scope: FSM only handles backend transaction/index orchestration
- External dependencies are abstracted via traits:
  - TransactionManager: open/commit/rollback
  - DataStore: read/write operations
  - IndexManager: index updates
  - TxnMetrics: optional metrics collection
- Async: all IO interactions are async via async_trait

States
- Opening
- Reading { reads_performed }
- Writing { writes_performed }
- UpdatingIndexes { indexes_updated }
- Committing
- RollingBack { reason }
- Completed { committed }
- Failed { error }

Events
- OpenTransaction
- ReadRequest → ReadComplete
- WriteRequest { operation } → WriteComplete
- IndexUpdateRequest → IndexUpdateComplete
- CommitRequest → CommitComplete
- RollbackRequest { reason } → RollbackComplete
- Error(String)

Transitions
- Opening → Reading | Writing (default to Reading after open)
- Reading ↔ Writing
- Reading|Writing → UpdatingIndexes → Reading (default)
- Reading|Writing|UpdatingIndexes → Committing → Completed(committed=true)
- Any → RollingBack → Completed(committed=false)
- Any → Failed on invalid transitions or dependency errors

Integration
- The FSM is implemented in src/backend_txn_fsm.rs
- Traits must be implemented by the concrete backend. For unit tests, mocks are provided
- The module is registered from src/lib.rs

Testing
- Unit tests cover initialization of each method and core flows:
  - Open, Read, Write, Index update, Commit, Rollback, Reset
  - Invalid transitions
  - Metrics hooks

Notes
- If additional backend behaviors are required, introduce a new trait and wire it into the FSM rather than expanding the FSM’s scope.
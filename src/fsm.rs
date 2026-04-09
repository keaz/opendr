//! Finite State Machine (FSM) traits and definitions for LDAP server operations
//!
//! This module defines a comprehensive set of state machines that model the various
//! concurrent processes in an LDAP server, from connection handling to replication.
//!
//! ## Architecture Overview
//!
//! The LDAP server uses a state machine-based architecture where each concurrent
//! operation is modeled as a separate FSM. This provides:
//!
//! - **Clear state transitions**: Each operation has well-defined states and transitions
//! - **Concurrent operations**: Multiple FSMs can run in parallel on a single connection
//! - **Timeout and abandonment**: Operations can be cancelled or timed out gracefully
//! - **Error handling**: Consistent error propagation across all operations
//!
//! ## Runtime Instance Pattern
//!
//! For each LDAP connection, you typically have:
//!
//! - **1× Connection FSM**: TCP lifecycle and TLS management
//! - **1× BER Decoder FSM**: Streaming message decoder
//! - **1× Auth FSM**: Either Simple or SASL authentication
//! - **N× Operation FSMs**: Search, Write, Compare operations (can run in parallel)
//! - **≤2× Replication FSMs**: Provider or Consumer for sync sessions
//! - **1 per operation Backend Txn FSM**: Short-lived transaction management
//!
//! ## FSM Categories
//!
//! 1. **Transport Layer**: ConnectionFsm, BerDecoderFsm
//! 2. **Authentication**: AuthFsm, SaslFsm
//! 3. **Operations**: SearchFsm, WriteFsm, CompareFsm, ExtendedOpFsm
//! 4. **Distribution**: ReferralFsm, ReplicationProviderFsm, ReplicationConsumerFsm
//! 5. **Storage**: BackendTxnFsm

use async_trait::async_trait;
use std::fmt::Debug;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};

/// Base trait for all finite state machines in the LDAP server
#[async_trait]
pub trait StateMachine {
    type State: Debug + Clone + PartialEq;
    type Event: Debug;
    type Error: std::error::Error + Send + Sync + 'static;
    type Output;

    /// Get the current state of the FSM
    fn current_state(&self) -> &Self::State;

    /// Process an event and potentially transition to a new state
    async fn handle_event(
        &mut self,
        event: Self::Event,
    ) -> Result<Option<Self::Output>, Self::Error>;

    /// Check if the FSM is in a terminal state
    fn is_terminal(&self) -> bool;

    /// Reset the FSM to its initial state
    async fn reset(&mut self) -> Result<(), Self::Error>;
}

/// Trait for FSMs that can be abandoned/cancelled
#[async_trait]
pub trait AbandonableFsm: StateMachine {
    /// Abandon the current operation and transition to abandoned state
    async fn abandon(&mut self) -> Result<(), Self::Error>;

    /// Check if the FSM has been abandoned
    fn is_abandoned(&self) -> bool;
}

/// Trait for FSMs that have timeouts
pub trait TimeoutFsm: StateMachine {
    /// Get the timeout duration for this FSM
    fn timeout(&self) -> Option<Duration>;

    /// Get the start time of the current operation
    fn start_time(&self) -> Instant;

    /// Check if the FSM has timed out
    fn is_timed_out(&self) -> bool {
        if let Some(timeout) = self.timeout() {
            self.start_time().elapsed() > timeout
        } else {
            false
        }
    }
}

// ================================================================================================
// Connection/Transport FSM - TCP lifecycle, StartTLS upgrade, close
// ================================================================================================

#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionState {
    Connecting,
    Connected,
    StartTlsNegotiation,
    Secure,
    Closing,
    Closed,
    Error,
}

#[derive(Debug)]
pub enum ConnectionEvent {
    Connect,
    ConnectionEstablished,
    StartTlsRequest,
    TlsHandshakeComplete,
    TlsHandshakeFailed(String),
    Close,
    ConnectionLost,
    Error(String),
}

#[async_trait]
pub trait ConnectionFsm: StateMachine<State = ConnectionState, Event = ConnectionEvent> {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send;

    /// Get the underlying stream if available
    fn stream(&self) -> Option<&Self::Stream>;

    /// Get the mutable stream if available
    fn stream_mut(&mut self) -> Option<&mut Self::Stream>;

    /// Check if the connection is secure (TLS)
    fn is_secure(&self) -> bool;

    /// Get connection information (remote address, etc.)
    fn connection_info(&self) -> ConnectionInfo;
}

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub remote_addr: String,
    pub local_addr: String,
    pub is_secure: bool,
    pub protocol_version: String,
}

// ================================================================================================
// Streaming BER Decoder FSM - tag/length/value over a split TCP stream
// ================================================================================================

#[derive(Debug, Clone, PartialEq)]
pub enum BerDecoderState {
    WaitingTag,
    WaitingLength,
    WaitingValue { tag: u8, length: usize },
    MessageComplete,
    Error,
}

#[derive(Debug)]
pub enum BerDecoderEvent {
    DataReceived(Vec<u8>),
    Reset,
    Error(String),
}

#[async_trait]
pub trait BerDecoderFsm: StateMachine<State = BerDecoderState, Event = BerDecoderEvent> {
    /// Get the current buffer contents
    fn buffer(&self) -> &[u8];

    /// Get the bytes needed to complete the current state
    fn bytes_needed(&self) -> Option<usize>;

    /// Extract a complete message if available
    fn extract_message(&mut self) -> Option<Vec<u8>>;

    /// Get the current message progress
    fn progress(&self) -> BerDecodingProgress;
}

#[derive(Debug, Clone)]
pub struct BerDecodingProgress {
    pub tag: Option<u8>,
    pub length: Option<usize>,
    pub bytes_received: usize,
    pub bytes_needed: Option<usize>,
}

// ================================================================================================
// AuthZ State FSM (Simple Bind) - anonymous ↔ simple-bound
// ================================================================================================

#[derive(Debug, Clone, PartialEq)]
pub enum AuthState {
    Anonymous,
    Authenticating { dn: String },
    SimpleBound { dn: String },
    AuthenticationFailed,
}

#[derive(Debug)]
pub enum AuthEvent {
    BindRequest { dn: String, password: Vec<u8> },
    AuthenticationSuccess,
    AuthenticationFailure,
    Unbind,
    Reset,
}

#[async_trait]
pub trait AuthFsm: StateMachine<State = AuthState, Event = AuthEvent> {
    /// Get the authenticated DN if bound
    fn authenticated_dn(&self) -> Option<&str>;

    /// Check if the session is authenticated
    fn is_authenticated(&self) -> bool;

    /// Get the authentication level
    fn auth_level(&self) -> AuthLevel;
}

#[derive(Debug, Clone, PartialEq)]
pub enum AuthLevel {
    Anonymous,
    Simple,
    Sasl(String), // mechanism name
}

// ================================================================================================
// SASL Bind FSM - multi-roundtrip challenge/response steps
// ================================================================================================

#[derive(Debug, Clone, PartialEq)]
pub enum SaslState {
    Initial,
    Challenge { mechanism: String, step: u32 },
    Response { mechanism: String, step: u32 },
    Authenticated { mechanism: String, dn: String },
    Failed,
}

#[derive(Debug)]
pub enum SaslEvent {
    InitiateBind {
        mechanism: String,
        initial_data: Option<Vec<u8>>,
    },
    ChallengeGenerated(Vec<u8>),
    ResponseReceived(Vec<u8>),
    AuthenticationComplete {
        dn: String,
    },
    AuthenticationFailed,
    Reset,
}

#[async_trait]
pub trait SaslFsm: StateMachine<State = SaslState, Event = SaslEvent> {
    /// Get the current SASL mechanism
    fn mechanism(&self) -> Option<&str>;

    /// Get the current step number
    fn step(&self) -> u32;

    /// Get the authenticated identity
    fn authenticated_identity(&self) -> Option<&str>;

    /// Check if more steps are needed
    fn needs_more_steps(&self) -> bool;
}

// ================================================================================================
// Search FSM - candidates → iterate → emit entries; handles abandon/time/size
// ================================================================================================

#[derive(Debug, Clone, PartialEq)]
pub enum SearchState {
    Initializing,
    FindingCandidates,
    Iterating {
        candidates_found: usize,
        entries_sent: usize,
    },
    EmittingEntries,
    Completed {
        entries_sent: usize,
        result_code: SearchResultCode,
    },
    Abandoned,
    TimeLimitExceeded,
    SizeLimitExceeded,
}

#[derive(Debug)]
pub enum SearchEvent {
    StartSearch {
        base_dn: String,
        scope: i32,
        filter: String,
        attributes: Vec<String>,
        size_limit: u32,
        time_limit: u32,
    },
    CandidatesFound(usize),
    EntryFound(Vec<u8>), // encoded entry
    EntryEmitted,
    SearchComplete,
    Abandon,
    TimeLimit,
    SizeLimit,
    Error(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum SearchResultCode {
    Success,
    TimeLimitExceeded,
    SizeLimitExceeded,
    Other(u32),
}

#[async_trait]
pub trait SearchFsm:
    StateMachine<State = SearchState, Event = SearchEvent> + AbandonableFsm + TimeoutFsm
{
    /// Get search parameters
    fn search_params(&self) -> Option<&SearchParams>;

    /// Get current entry count
    fn entries_sent(&self) -> usize;

    /// Get size limit
    fn size_limit(&self) -> u32;

    /// Check if size limit would be exceeded
    fn would_exceed_size_limit(&self) -> bool;
}

#[derive(Debug, Clone)]
pub struct SearchParams {
    pub base_dn: String,
    pub scope: i32,
    pub filter: String,
    pub attributes: Vec<String>,
    pub size_limit: u32,
    pub time_limit: u32,
}

// ================================================================================================
// Write FSM (Add/Modify/ModifyDN/Delete) - schema/ACI checks, txn, commit/rollback
// ================================================================================================

#[derive(Debug, Clone, PartialEq)]
pub enum WriteState {
    Validating,
    CheckingSchema,
    CheckingAci, // Access Control Information
    InTransaction,
    Committing,
    Rollback { reason: String },
    Completed { result_code: WriteResultCode },
    Failed { error: String },
}

#[derive(Debug)]
pub enum WriteEvent {
    StartWrite(WriteOperation),
    ValidationComplete,
    SchemaCheckComplete,
    AciCheckComplete,
    TransactionStarted,
    WriteComplete,
    CommitInitiated,
    CommitComplete,
    RollbackInitiated { reason: String },
    RollbackComplete,
    Error(String),
}

#[derive(Debug, Clone)]
pub enum WriteOperation {
    Add {
        dn: String,
        entry: Vec<u8>,
    },
    Modify {
        dn: String,
        changes: Vec<u8>,
    },
    ModifyDn {
        dn: String,
        new_rdn: String,
        delete_old: bool,
        new_superior: Option<String>,
    },
    Delete {
        dn: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum WriteResultCode {
    Success,
    InsufficientAccessRights,
    ConstraintViolation,
    EntryAlreadyExists,
    NoSuchObject,
    Other(u32),
}

#[async_trait]
pub trait WriteFsm: StateMachine<State = WriteState, Event = WriteEvent> {
    /// Get the write operation being performed
    fn operation(&self) -> Option<&WriteOperation>;

    /// Get transaction ID if in transaction
    fn transaction_id(&self) -> Option<&str>;

    /// Check if rollback is possible
    fn can_rollback(&self) -> bool;
}

// ================================================================================================
// Compare FSM - tiny read/evaluate/emit boolean
// ================================================================================================

#[derive(Debug, Clone, PartialEq)]
pub enum CompareState {
    Reading,
    Evaluating,
    Emitting { result: bool },
    Completed { result: bool },
}

#[derive(Debug)]
pub enum CompareEvent {
    StartCompare {
        dn: String,
        attribute: String,
        value: Vec<u8>,
    },
    EntryRead,
    ComparisonComplete(bool),
    ResultEmitted,
    Error(String),
}

#[async_trait]
pub trait CompareFsm: StateMachine<State = CompareState, Event = CompareEvent> {
    /// Get the comparison parameters
    fn compare_params(&self) -> Option<&CompareParams>;

    /// Get the comparison result if available
    fn result(&self) -> Option<bool>;
}

#[derive(Debug, Clone)]
pub struct CompareParams {
    pub dn: String,
    pub attribute: String,
    pub value: Vec<u8>,
}

// ================================================================================================
// Extended-Op FSM(s) - e.g., StartTLS, Password Modify, etc.
// ================================================================================================

#[derive(Debug, Clone, PartialEq)]
pub enum ExtendedOpState {
    Parsing,
    Processing { operation: String },
    Delegating { operation: String, delegate: String },
    Responding,
    Completed { result_code: ExtendedOpResultCode },
}

#[derive(Debug, Clone)]
pub enum ExtendedOpEvent {
    StartExtendedOp { oid: String, value: Option<Vec<u8>> },
    ParseComplete,
    ProcessingComplete,
    DelegationComplete,
    ResponseReady(Vec<u8>),
    OperationComplete,
    Error(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExtendedOpResultCode {
    Success,
    ProtocolError,
    UnavailableCriticalExtension,
    Other(u32),
}

#[async_trait]
pub trait ExtendedOpFsm: StateMachine<State = ExtendedOpState, Event = ExtendedOpEvent> {
    /// Get the operation OID
    fn operation_oid(&self) -> Option<&str>;

    /// Get the operation value
    fn operation_value(&self) -> Option<&[u8]>;

    /// Get the response value if ready
    fn response_value(&self) -> Option<&[u8]>;

    /// Check if this operation requires delegation
    fn requires_delegation(&self) -> bool;
}

// ================================================================================================
// Referral/Chaining FSM - referrals, hop limits, proxying to other DSAs
// ================================================================================================

#[derive(Debug, Clone, PartialEq)]
pub enum ReferralState {
    EvaluatingReferral,
    ChainRequest { target: String, hop_count: u32 },
    ProxyRequest { target: String },
    AwaitingResponse,
    ProcessingResponse,
    Completed { result_code: ReferralResultCode },
    HopLimitExceeded,
}

#[derive(Debug)]
pub enum ReferralEvent {
    ReferralReceived { urls: Vec<String> },
    ChainDecision { target: String },
    ProxyDecision { target: String },
    RequestSent,
    ResponseReceived(Vec<u8>),
    ProcessingComplete,
    HopLimitReached,
    Error(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ReferralResultCode {
    Success,
    Referral,
    HopLimitExceeded,
    Unavailable,
    Other(u32),
}

#[async_trait]
pub trait ReferralFsm: StateMachine<State = ReferralState, Event = ReferralEvent> {
    /// Get current hop count
    fn hop_count(&self) -> u32;

    /// Get maximum hop limit
    fn hop_limit(&self) -> u32;

    /// Get current target DSA
    fn current_target(&self) -> Option<&str>;

    /// Get referral URLs
    fn referral_urls(&self) -> Option<&[String]>;

    /// Check if more hops are allowed
    fn can_hop(&self) -> bool {
        self.hop_count() < self.hop_limit()
    }
}

// ================================================================================================
// Replication Provider FSM (RFC 4533) - refresh → present → persist streaming
// ================================================================================================

#[derive(Debug, Clone, PartialEq)]
pub enum ReplicationProviderState {
    /// Initial state waiting for sync request
    Initializing,
    /// Refresh phase - sending existing entries
    Refresh {
        entries_sent: usize,
        total_entries: usize,
    },
    /// Present phase - streaming changelog entries  
    Present { entries_streamed: usize },
    /// Persist phase - maintaining replication cookie
    Persist { cookie: String },
    /// Streaming mode - continuously sending changes
    Streaming { active_consumers: usize },
    /// Replication completed successfully
    Completed,
    /// Error state
    Error { message: String },
}

#[derive(Debug, Clone)]
pub enum ReplicationProviderEvent {
    /// Consumer requests sync replication from cookie
    StartSyncReplication {
        consumer_id: String,
        cookie: Option<String>,
    },
    /// Refresh phase completed, ready to stream changes
    RefreshComplete {
        consumer_id: String,
        entries_sent: usize,
    },
    /// Present phase completed, ready to persist
    PresentComplete {
        consumer_id: String,
        entries_streamed: usize,
    },
    /// New changelog entry available for streaming (CSN-based)
    ChangelogEntry {
        entry: Vec<u8>,
        csn: crate::csn::Csn,
    },
    /// Entry successfully streamed to consumer
    EntryStreamed { consumer_id: String },
    /// Consumer disconnected
    ConsumerDisconnected { consumer_id: String },
    /// Cookie updated/persisted
    CookiePersisted {
        consumer_id: String,
        new_cookie: String,
    },
    /// Error occurred
    Error(String),
}

#[async_trait]
pub trait ReplicationProviderFsm:
    StateMachine<State = ReplicationProviderState, Event = ReplicationProviderEvent>
{
    /// Get the representative consumer identifier for the current summary state.
    /// Returns `None` when multiple active sessions would make that ambiguous.
    fn consumer_id(&self) -> Option<&str>;

    /// Get the representative replication cookie for the current summary state.
    /// Returns `None` when multiple active sessions would make that ambiguous.
    fn cookie(&self) -> Option<&str>;

    /// Get entries sent count during refresh phase
    fn entries_sent(&self) -> usize;

    /// Get entries streamed count during present phase
    fn entries_streamed(&self) -> usize;

    /// Check if in streaming mode
    fn is_streaming(&self) -> bool;

    /// Get active consumer count
    fn active_consumers(&self) -> usize;

    /// Get the summary replication phase across active sessions
    fn current_phase(&self) -> ReplicationPhase;

    /// Get sync replication statistics
    fn sync_stats(&self) -> (usize, usize, usize); // (refresh_entries, present_entries, total_consumers)
}

/// RFC 4533 Replication phases
#[derive(Debug, Clone, PartialEq)]
pub enum ReplicationPhase {
    /// Initial phase
    Initialize,
    /// Refresh phase - sending existing entries
    Refresh,
    /// Present phase - streaming changelog entries
    Present,
    /// Persist phase - maintaining cookie state
    Persist,
    /// Streaming phase - continuous replication
    Stream,
    /// Completed phase
    Complete,
    /// Error phase
    Error,
}

// ================================================================================================
// Replication Consumer FSM - request from cookie → apply batches → persist listen
// ================================================================================================

#[derive(Debug, Clone, PartialEq)]
pub enum ReplicationConsumerState {
    RequestingFromCookie { cookie: Option<String> },
    ReceivingBatches { entries_received: usize },
    ApplyingChanges { entries_applied: usize },
    PersistingState { new_cookie: String },
    Listening,
    Completed,
    Error,
}

#[derive(Debug)]
pub enum ReplicationConsumerEvent {
    StartConsumption {
        provider_url: String,
        cookie: Option<String>,
    },
    BatchReceived {
        entries: Vec<Vec<u8>>,
    },
    EntryApplied,
    StatePersisted {
        cookie: String,
    },
    ChangeReceived(Vec<u8>),
    ProviderDisconnected,
    Error(String),
}

#[async_trait]
pub trait ReplicationConsumerFsm:
    StateMachine<State = ReplicationConsumerState, Event = ReplicationConsumerEvent>
{
    /// Get provider URL
    fn provider_url(&self) -> Option<&str>;

    /// Get current cookie
    fn current_cookie(&self) -> Option<&str>;

    /// Get entries applied count
    fn entries_applied(&self) -> usize;

    /// Check if listening for changes
    fn is_listening(&self) -> bool;
}

// ================================================================================================
// Backend Txn/Index FSM - open txn → read/write → update indexes → commit/rollback
// ================================================================================================

#[derive(Debug, Clone, PartialEq)]
pub enum BackendTxnState {
    Opening,
    Reading { reads_performed: usize },
    Writing { writes_performed: usize },
    UpdatingIndexes { indexes_updated: usize },
    Committing,
    RollingBack { reason: String },
    Completed { committed: bool },
    Failed { error: String },
}

#[derive(Debug)]
pub enum BackendTxnEvent {
    OpenTransaction,
    ReadRequest { key: String },
    WriteRequest { operation: BackendOperation },
    IndexUpdateRequest { index_keys: Vec<String> },
    CommitRequest,
    RollbackRequest { reason: String },
    Error(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum BackendTxnOutput {
    TransactionOpened { txn_id: String },
    ReadResult { value: Option<Vec<u8>> },
    WriteApplied { writes_performed: usize },
    IndexesUpdated { updated: usize, total: usize },
    Finished { committed: bool },
}

#[derive(Debug, Clone, PartialEq)]
pub enum BackendOperation {
    Insert { key: String, value: Vec<u8> },
    Update { key: String, value: Vec<u8> },
    Delete { key: String },
}

#[async_trait]
pub trait BackendTxnFsm: StateMachine<State = BackendTxnState, Event = BackendTxnEvent> {
    /// Get transaction ID
    fn transaction_id(&self) -> Option<&str>;

    /// Get read count
    fn reads_performed(&self) -> usize;

    /// Get write count
    fn writes_performed(&self) -> usize;

    /// Check if transaction can be committed
    fn can_commit(&self) -> bool;

    /// Check if transaction can be rolled back
    fn can_rollback(&self) -> bool;

    /// Get nested transaction level
    fn nesting_level(&self) -> u32;
}

// Connection-scoped runtime composition lives in `crate::fsm_runtime`.
// This module intentionally defines shared FSM contracts, events, states, and
// standalone FSM traits only. Replication provider/consumer FSMs are public
// standalone modules, while backend transaction handling remains internal to the
// storage/runtime layer.

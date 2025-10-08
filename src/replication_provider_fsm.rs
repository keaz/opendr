//! Replication Provider FSM Implementation (RFC 4533)
//!
//! This module implements the LDAP Content Synchronization Operation as defined in RFC 4533.
//! The FSM manages the three phases of sync replication:
//!
//! 1. **Refresh Phase**: Send all existing entries to consumer
//! 2. **Present Phase**: Stream changelog entries since consumer's cookie
//! 3. **Persist Phase**: Maintain streaming connection for ongoing changes
//!
//! ## Architecture Overview
//!
//! The ReplicationProviderFsm follows the RFC 4533 specification for sync replication:
//!
//! ```text
//! Consumer Request → Refresh → Present → Persist → Streaming
//!                      ↓         ↓        ↓         ↓
//!                  Send all   Stream     Maintain  Continuous
//!                  entries   changes    cookie    updates
//! ```
//!
//! ## State Transitions
//!
//! - **Initializing**: Waiting for sync request from consumer
//! - **Refresh**: Sending existing directory entries to consumer  
//! - **Present**: Streaming changelog entries since consumer's last cookie
//! - **Persist**: Maintaining replication state and cookie
//! - **Streaming**: Continuously sending new changes to consumer
//! - **Completed**: Sync operation completed successfully
//! - **Error**: Error state for failed operations
//!
//! ## External Dependencies
//!
//! This FSM uses trait abstractions for external dependencies:
//!
//! - **ChangelogProvider**: Access to directory changelog entries
//! - **ConsumerRegistry**: Managing connected consumer sessions
//! - **StreamingManager**: Handling real-time change streaming
//! - **ReplicationMetrics**: Performance monitoring and statistics
//! - **SyncRequestHandler**: Processing sync replication requests

use crate::fsm::{
    ReplicationPhase, ReplicationProviderEvent, ReplicationProviderFsm, ReplicationProviderState,
    StateMachine,
};
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

// ================================================================================================
// External Trait Dependencies
// ================================================================================================

/// Provides access to directory changelog entries for replication
///
/// This trait abstracts the underlying changelog storage mechanism and provides
/// methods to retrieve directory changes for sync replication operations.
#[async_trait]
pub trait ChangelogProvider: Send + Sync {
    /// Get all directory entries for refresh phase
    ///
    /// # Arguments
    /// * `base_dn` - Base DN to start replication from
    /// * `filter` - Optional filter for entries to replicate
    ///
    /// # Returns
    /// * `Ok(Vec<DirectoryEntry>)` - List of directory entries
    /// * `Err(String)` - Error message if operation fails
    async fn get_all_entries(
        &self,
        base_dn: &str,
        filter: Option<&str>,
    ) -> Result<Vec<DirectoryEntry>, String>;

    /// Get changelog entries since a specific cookie
    ///
    /// # Arguments
    /// * `cookie` - Replication cookie representing last sync point (CSN-based)
    /// * `limit` - Maximum number of entries to return
    ///
    /// # Returns  
    /// * `Ok(Vec<ChangelogEntry>)` - List of changelog entries
    /// * `Err(String)` - Error message if operation fails
    async fn get_changelog_since(
        &self,
        cookie: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ChangelogEntry>, String>;

    /// Generate new replication cookie from CSN
    ///
    /// # Arguments
    /// * `last_csn` - Last CSN processed (for cookie generation)
    ///
    /// # Returns
    /// * `Ok(String)` - New replication cookie
    /// * `Err(String)` - Error message if generation fails
    async fn generate_cookie(&self, last_csn: &crate::csn::Csn) -> Result<String, String>;

    /// Get current contextCSN (highest CSN in changelog)
    ///
    /// # Returns
    /// * `Ok(Some(Csn))` - Current contextCSN if any changes exist
    /// * `Ok(None)` - No changes recorded yet
    /// * `Err(String)` - Error message if retrieval fails
    async fn get_context_csn(&self) -> Result<Option<crate::csn::Csn>, String>;

    /// Validate if a replication cookie is still valid
    ///
    /// # Arguments  
    /// * `cookie` - Cookie to validate (CSN-based format)
    ///
    /// # Returns
    /// * `Ok(bool)` - True if cookie is valid, false otherwise
    /// * `Err(String)` - Error message if validation fails
    async fn validate_cookie(&self, cookie: &str) -> Result<bool, String>;
}

/// Manages connected consumer sessions and their replication state
///
/// This trait provides methods to register consumers, track their connection
/// status, and manage their replication sessions.
#[async_trait]
pub trait ConsumerRegistry: Send + Sync {
    /// Register a new consumer for sync replication
    ///
    /// # Arguments
    /// * `consumer_id` - Unique identifier for the consumer
    /// * `connection_info` - Consumer connection details
    ///
    /// # Returns
    /// * `Ok(())` - Consumer registered successfully
    /// * `Err(String)` - Error message if registration fails
    async fn register_consumer(
        &mut self,
        consumer_id: &str,
        connection_info: ConsumerConnection,
    ) -> Result<(), String>;

    /// Remove a consumer from the registry
    ///
    /// # Arguments
    /// * `consumer_id` - Consumer identifier to remove
    ///
    /// # Returns
    /// * `Ok(bool)` - True if consumer was removed, false if not found
    /// * `Err(String)` - Error message if removal fails
    async fn unregister_consumer(&mut self, consumer_id: &str) -> Result<bool, String>;

    /// Check if a consumer is currently connected
    ///
    /// # Arguments
    /// * `consumer_id` - Consumer identifier to check
    ///
    /// # Returns
    /// * `Ok(bool)` - True if connected, false otherwise
    /// * `Err(String)` - Error message if check fails
    async fn is_consumer_connected(&self, consumer_id: &str) -> Result<bool, String>;

    /// Get list of all active consumers
    ///
    /// # Returns
    /// * `Ok(Vec<String>)` - List of active consumer IDs
    /// * `Err(String)` - Error message if retrieval fails
    async fn get_active_consumers(&self) -> Result<Vec<String>, String>;

    /// Update consumer's last activity timestamp
    ///
    /// # Arguments
    /// * `consumer_id` - Consumer identifier
    ///
    /// # Returns
    /// * `Ok(())` - Timestamp updated successfully
    /// * `Err(String)` - Error message if update fails
    async fn update_consumer_activity(&mut self, consumer_id: &str) -> Result<(), String>;

    /// Get list of persistent consumers (refreshAndPersist mode)
    ///
    /// # Returns
    /// * `Ok(Vec<String>)` - List of persistent consumer IDs
    /// * `Err(String)` - Error message if retrieval fails
    async fn get_persistent_consumers(&self) -> Result<Vec<String>, String>;

    /// Get consumer connection details
    ///
    /// # Arguments
    /// * `consumer_id` - Consumer identifier
    ///
    /// # Returns
    /// * `Ok(Option<ConsumerConnection>)` - Connection details if found
    /// * `Err(String)` - Error message if retrieval fails
    async fn get_consumer(&self, consumer_id: &str) -> Result<Option<ConsumerConnection>, String>;

    /// Update consumer's cookie
    ///
    /// # Arguments
    /// * `consumer_id` - Consumer identifier
    /// * `cookie` - New cookie value
    ///
    /// # Returns
    /// * `Ok(())` - Cookie updated successfully
    /// * `Err(String)` - Error message if update fails
    async fn update_consumer_cookie(
        &mut self,
        consumer_id: &str,
        cookie: String,
    ) -> Result<(), String>;
}

/// Handles real-time streaming of directory changes to consumers
///
/// This trait manages the continuous streaming of directory changes to
/// registered consumers during the persist/streaming phase.
#[async_trait]
pub trait StreamingManager: Send + Sync {
    /// Start streaming changes to a consumer
    ///
    /// # Arguments
    /// * `consumer_id` - Consumer to stream to
    /// * `start_cookie` - Starting point for streaming
    ///
    /// # Returns  
    /// * `Ok(())` - Streaming started successfully
    /// * `Err(String)` - Error message if streaming fails to start
    async fn start_streaming(
        &mut self,
        consumer_id: &str,
        start_cookie: Option<&str>,
    ) -> Result<(), String>;

    /// Stop streaming changes to a consumer
    ///
    /// # Arguments
    /// * `consumer_id` - Consumer to stop streaming to
    ///
    /// # Returns
    /// * `Ok(())` - Streaming stopped successfully  
    /// * `Err(String)` - Error message if stopping fails
    async fn stop_streaming(&mut self, consumer_id: &str) -> Result<(), String>;

    /// Send a changelog entry to a specific consumer
    ///
    /// # Arguments
    /// * `consumer_id` - Target consumer
    /// * `entry` - Changelog entry to send
    ///
    /// # Returns
    /// * `Ok(())` - Entry sent successfully
    /// * `Err(String)` - Error message if sending fails
    async fn send_entry(&self, consumer_id: &str, entry: &ChangelogEntry) -> Result<(), String>;

    /// Check if streaming is active for a consumer
    ///
    /// # Arguments
    /// * `consumer_id` - Consumer to check
    ///
    /// # Returns
    /// * `Ok(bool)` - True if streaming is active
    /// * `Err(String)` - Error message if check fails
    async fn is_streaming_active(&self, consumer_id: &str) -> Result<bool, String>;

    /// Get streaming statistics for a consumer
    ///
    /// # Arguments
    /// * `consumer_id` - Consumer to get stats for
    ///
    /// # Returns
    /// * `Ok(StreamingStats)` - Current streaming statistics
    /// * `Err(String)` - Error message if retrieval fails
    async fn get_streaming_stats(&self, consumer_id: &str) -> Result<StreamingStats, String>;
}

/// Provides performance monitoring and metrics collection for replication
///
/// This trait enables monitoring of replication performance, tracking metrics
/// like entries processed, processing times, and error rates.
pub trait ReplicationMetrics: Send + Sync {
    /// Record the start of a sync replication session
    ///
    /// # Arguments
    /// * `consumer_id` - Consumer identifier
    /// * `operation_type` - Type of sync operation (refresh, present, etc.)
    fn record_sync_start(&self, consumer_id: &str, operation_type: &str);

    /// Record the completion of a sync phase
    ///
    /// # Arguments
    /// * `consumer_id` - Consumer identifier
    /// * `phase` - Completed phase (refresh, present, persist)
    /// * `entries_processed` - Number of entries processed
    /// * `duration` - Time taken to complete the phase
    fn record_phase_complete(
        &self,
        consumer_id: &str,
        phase: &str,
        entries_processed: usize,
        duration: Duration,
    );

    /// Record streaming of an entry to a consumer
    ///
    /// # Arguments
    /// * `consumer_id` - Consumer identifier  
    /// * `entry_size` - Size of streamed entry in bytes
    /// * `processing_time` - Time taken to process the entry
    fn record_entry_streamed(
        &self,
        consumer_id: &str,
        entry_size: usize,
        processing_time: Duration,
    );

    /// Record replication error
    ///
    /// # Arguments
    /// * `consumer_id` - Consumer identifier
    /// * `error_type` - Type of error encountered
    /// * `error_message` - Detailed error message
    fn record_replication_error(&self, consumer_id: &str, error_type: &str, error_message: &str);

    /// Record consumer disconnection
    ///
    /// # Arguments
    /// * `consumer_id` - Disconnected consumer identifier
    /// * `reason` - Reason for disconnection
    /// * `session_duration` - Total session duration
    fn record_consumer_disconnection(
        &self,
        consumer_id: &str,
        reason: &str,
        session_duration: Duration,
    );

    /// Get current replication statistics
    ///
    /// # Returns
    /// * Current replication metrics and statistics
    fn get_replication_stats(&self) -> ReplicationStats;
}

/// Handles processing of sync replication requests from consumers
///
/// This trait processes incoming sync replication requests and coordinates
/// the response according to RFC 4533 specifications.
#[async_trait]
pub trait SyncRequestHandler: Send + Sync {
    /// Process a sync replication request
    ///
    /// # Arguments
    /// * `request` - Incoming sync request details
    ///
    /// # Returns
    /// * `Ok(SyncResponse)` - Response to send to consumer
    /// * `Err(String)` - Error message if processing fails
    async fn process_sync_request(&self, request: &SyncRequest) -> Result<SyncResponse, String>;

    /// Validate sync request parameters
    ///
    /// # Arguments
    /// * `request` - Request to validate
    ///
    /// # Returns
    /// * `Ok(())` - Request is valid
    /// * `Err(String)` - Validation error message
    async fn validate_sync_request(&self, request: &SyncRequest) -> Result<(), String>;

    /// Generate sync response for completed operation
    ///
    /// # Arguments
    /// * `consumer_id` - Consumer identifier
    /// * `result_code` - Operation result code
    /// * `cookie` - New replication cookie
    /// * `entries_sent` - Number of entries sent
    ///
    /// # Returns
    /// * `Ok(SyncResponse)` - Generated response
    /// * `Err(String)` - Error generating response
    async fn generate_sync_response(
        &self,
        consumer_id: &str,
        result_code: u32,
        cookie: Option<&str>,
        entries_sent: usize,
    ) -> Result<SyncResponse, String>;
}

// ================================================================================================
// Data Structures
// ================================================================================================

/// Represents a directory entry for replication
#[derive(Debug, Clone)]
pub struct DirectoryEntry {
    /// Distinguished name of the entry
    pub dn: String,
    /// Entry attributes as key-value pairs
    pub attributes: HashMap<String, Vec<String>>,
    /// Entry modification timestamp
    pub modification_time: Instant,
    /// Entry UUID (if available)
    pub uuid: Option<String>,
}

impl DirectoryEntry {
    /// Create a new directory entry
    ///
    /// # Arguments
    /// * `dn` - Distinguished name
    /// * `attributes` - Entry attributes
    ///
    /// # Returns
    /// * New DirectoryEntry instance
    pub fn new(dn: String, attributes: HashMap<String, Vec<String>>) -> Self {
        Self {
            dn,
            attributes,
            modification_time: Instant::now(),
            uuid: None,
        }
    }

    /// Set entry UUID
    ///
    /// # Arguments
    /// * `uuid` - Entry UUID to set
    pub fn with_uuid(mut self, uuid: String) -> Self {
        self.uuid = Some(uuid);
        self
    }

    /// Get entry size in bytes (approximate)
    ///
    /// # Returns
    /// * Estimated entry size in bytes
    pub fn estimated_size(&self) -> usize {
        let mut size = self.dn.len();
        for (key, values) in &self.attributes {
            size += key.len();
            for value in values {
                size += value.len();
            }
        }
        if let Some(ref uuid) = self.uuid {
            size += uuid.len();
        }
        size
    }
}

/// Represents a changelog entry for replication  
#[derive(Debug, Clone)]
pub struct ChangelogEntry {
    /// Change Sequence Number (CSN) - unique identifier for this change
    pub csn: crate::csn::Csn,
    /// Type of change (add, modify, delete, rename)
    pub change_type: ChangeType,
    /// Distinguished name of affected entry
    pub dn: String,
    /// Change data (entry content, modifications, etc.)
    pub change_data: Vec<u8>,
    /// Timestamp when change occurred
    pub timestamp: Instant,
    /// Change originator (if available)
    pub originator: Option<String>,
}

impl ChangelogEntry {
    /// Create a new changelog entry
    ///
    /// # Arguments
    /// * `csn` - Change Sequence Number for this change
    /// * `change_type` - Type of directory change
    /// * `dn` - Distinguished name of affected entry
    /// * `change_data` - Serialized change data
    ///
    /// # Returns
    /// * New ChangelogEntry instance
    pub fn new(
        csn: crate::csn::Csn,
        change_type: ChangeType,
        dn: String,
        change_data: Vec<u8>,
    ) -> Self {
        Self {
            csn,
            change_type,
            dn,
            change_data,
            timestamp: Instant::now(),
            originator: None,
        }
    }

    /// Set change originator
    ///
    /// # Arguments
    /// * `originator` - System or user that originated the change
    pub fn with_originator(mut self, originator: String) -> Self {
        self.originator = Some(originator);
        self
    }

    /// Get change data size
    ///
    /// # Returns
    /// * Size of change data in bytes
    pub fn data_size(&self) -> usize {
        self.change_data.len()
    }
}

/// Types of directory changes in changelog
#[derive(Debug, Clone, PartialEq)]
pub enum ChangeType {
    /// Entry was added
    Add,
    /// Entry was modified
    Modify,
    /// Entry was deleted
    Delete,
    /// Entry was renamed/moved
    Rename,
}

/// Consumer connection information
#[derive(Debug, Clone)]
pub struct ConsumerConnection {
    /// Consumer endpoint address
    pub address: String,
    /// Connection establishment time
    pub connected_at: Instant,
    /// Last activity timestamp
    pub last_activity: Instant,
    /// Consumer capabilities
    pub capabilities: HashSet<String>,
    /// Consumer version information
    pub version: Option<String>,
    /// Sync mode for this consumer (refreshOnly or refreshAndPersist)
    pub sync_mode: SyncMode,
    /// Whether this is a persistent connection
    pub is_persistent: bool,
    /// Last synchronization cookie sent to this consumer
    pub last_cookie: Option<String>,
    /// Unique consumer identifier for tracking
    pub consumer_id: String,
}

impl ConsumerConnection {
    /// Create new consumer connection info
    ///
    /// # Arguments
    /// * `address` - Consumer network address
    ///
    /// # Returns
    /// * New ConsumerConnection instance with default sync mode (RefreshOnly)
    pub fn new(address: String) -> Self {
        let now = Instant::now();
        let consumer_id = format!("consumer-{}", uuid::Uuid::new_v4());
        Self {
            address: address.clone(),
            connected_at: now,
            last_activity: now,
            capabilities: HashSet::new(),
            version: None,
            sync_mode: SyncMode::RefreshOnly,
            is_persistent: false,
            last_cookie: None,
            consumer_id,
        }
    }

    /// Create new consumer connection with specified sync mode
    ///
    /// # Arguments
    /// * `address` - Consumer network address
    /// * `sync_mode` - Requested sync mode
    ///
    /// # Returns
    /// * New ConsumerConnection instance
    pub fn with_sync_mode(address: String, sync_mode: SyncMode) -> Self {
        let now = Instant::now();
        let consumer_id = format!("consumer-{}", uuid::Uuid::new_v4());
        let is_persistent = sync_mode == SyncMode::RefreshAndPersist;
        Self {
            address,
            connected_at: now,
            last_activity: now,
            capabilities: HashSet::new(),
            version: None,
            sync_mode,
            is_persistent,
            last_cookie: None,
            consumer_id,
        }
    }

    /// Add consumer capability
    ///
    /// # Arguments
    /// * `capability` - Capability to add
    pub fn add_capability(&mut self, capability: String) {
        self.capabilities.insert(capability);
    }

    /// Update last activity timestamp
    pub fn update_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Get connection duration
    ///
    /// # Returns
    /// * Duration since connection was established
    pub fn connection_duration(&self) -> Duration {
        self.connected_at.elapsed()
    }

    /// Set sync mode for this consumer
    ///
    /// # Arguments
    /// * `mode` - New sync mode
    pub fn set_sync_mode(&mut self, mode: SyncMode) {
        self.is_persistent = mode == SyncMode::RefreshAndPersist;
        self.sync_mode = mode;
    }

    /// Update last cookie sent to consumer
    ///
    /// # Arguments
    /// * `cookie` - New cookie value
    pub fn update_cookie(&mut self, cookie: String) {
        self.last_cookie = Some(cookie);
        self.update_activity();
    }

    /// Check if consumer is in persistent mode
    ///
    /// # Returns
    /// * True if consumer is in refreshAndPersist mode
    pub fn is_persistent_mode(&self) -> bool {
        self.is_persistent
    }

    /// Get last cookie sent to this consumer
    ///
    /// # Returns
    /// * Option with cookie if available
    pub fn get_last_cookie(&self) -> Option<&String> {
        self.last_cookie.as_ref()
    }
}

/// Streaming statistics for a consumer
#[derive(Debug, Clone)]
pub struct StreamingStats {
    /// Number of entries streamed
    pub entries_streamed: usize,
    /// Total bytes streamed
    pub bytes_streamed: usize,
    /// Streaming start time
    pub streaming_start: Instant,
    /// Last entry streamed time
    pub last_entry_time: Option<Instant>,
    /// Number of streaming errors
    pub error_count: usize,
}

impl StreamingStats {
    /// Create new streaming statistics
    ///
    /// # Returns
    /// * New StreamingStats instance
    pub fn new() -> Self {
        Self {
            entries_streamed: 0,
            bytes_streamed: 0,
            streaming_start: Instant::now(),
            last_entry_time: None,
            error_count: 0,
        }
    }

    /// Record an entry being streamed
    ///
    /// # Arguments
    /// * `entry_size` - Size of streamed entry in bytes
    pub fn record_entry(&mut self, entry_size: usize) {
        self.entries_streamed += 1;
        self.bytes_streamed += entry_size;
        self.last_entry_time = Some(Instant::now());
    }

    /// Record a streaming error
    pub fn record_error(&mut self) {
        self.error_count += 1;
    }

    /// Get streaming duration
    ///
    /// # Returns
    /// * Duration since streaming started
    pub fn streaming_duration(&self) -> Duration {
        self.streaming_start.elapsed()
    }
}

/// Sync replication request from consumer
#[derive(Debug, Clone)]
pub struct SyncRequest {
    /// Consumer identifier
    pub consumer_id: String,
    /// Base DN for replication
    pub base_dn: String,
    /// Replication cookie (if resuming)
    pub cookie: Option<String>,
    /// Search filter (if any)
    pub filter: Option<String>,
    /// Request timestamp
    pub timestamp: Instant,
    /// Requested sync mode
    pub sync_mode: SyncMode,
}

impl SyncRequest {
    /// Create new sync request
    ///
    /// # Arguments
    /// * `consumer_id` - Consumer identifier
    /// * `base_dn` - Base DN for sync
    ///
    /// # Returns
    /// * New SyncRequest instance
    pub fn new(consumer_id: String, base_dn: String) -> Self {
        Self {
            consumer_id,
            base_dn,
            cookie: None,
            filter: None,
            timestamp: Instant::now(),
            sync_mode: SyncMode::RefreshAndPersist,
        }
    }

    /// Set replication cookie
    ///
    /// # Arguments
    /// * `cookie` - Replication cookie
    pub fn with_cookie(mut self, cookie: String) -> Self {
        self.cookie = Some(cookie);
        self
    }

    /// Set search filter
    ///
    /// # Arguments  
    /// * `filter` - LDAP search filter
    pub fn with_filter(mut self, filter: String) -> Self {
        self.filter = Some(filter);
        self
    }

    /// Set sync mode
    ///
    /// # Arguments
    /// * `mode` - Sync replication mode
    pub fn with_sync_mode(mut self, mode: SyncMode) -> Self {
        self.sync_mode = mode;
        self
    }
}

/// Sync replication response to consumer
#[derive(Debug, Clone)]
pub struct SyncResponse {
    /// Response result code
    pub result_code: u32,
    /// New replication cookie
    pub cookie: Option<String>,
    /// Number of entries included
    pub entry_count: usize,
    /// Response message (if any)
    pub message: Option<String>,
    /// Response generation time
    pub timestamp: Instant,
}

impl SyncResponse {
    /// Create new sync response
    ///
    /// # Arguments
    /// * `result_code` - LDAP result code
    ///
    /// # Returns
    /// * New SyncResponse instance
    pub fn new(result_code: u32) -> Self {
        Self {
            result_code,
            cookie: None,
            entry_count: 0,
            message: None,
            timestamp: Instant::now(),
        }
    }

    /// Set response cookie
    ///
    /// # Arguments
    /// * `cookie` - Replication cookie
    pub fn with_cookie(mut self, cookie: String) -> Self {
        self.cookie = Some(cookie);
        self
    }

    /// Set entry count
    ///
    /// # Arguments
    /// * `count` - Number of entries sent
    pub fn with_entry_count(mut self, count: usize) -> Self {
        self.entry_count = count;
        self
    }

    /// Set response message
    ///
    /// # Arguments
    /// * `message` - Response message
    pub fn with_message(mut self, message: String) -> Self {
        self.message = Some(message);
        self
    }
}

/// Sync replication modes (RFC 4533)
#[derive(Debug, Clone, PartialEq)]
pub enum SyncMode {
    /// Refresh only - send current entries
    RefreshOnly,
    /// Refresh and persist - send entries then stream changes
    RefreshAndPersist,
    /// Present only - stream changes from cookie
    PresentOnly,
}

/// Overall replication statistics
#[derive(Debug, Clone)]
pub struct ReplicationStats {
    /// Total sync sessions started
    pub total_sessions: usize,
    /// Currently active sessions  
    pub active_sessions: usize,
    /// Total entries sent across all sessions
    pub total_entries_sent: usize,
    /// Total bytes sent across all sessions
    pub total_bytes_sent: usize,
    /// Total errors encountered
    pub total_errors: usize,
    /// Average session duration
    pub average_session_duration: Duration,
    /// Statistics collection start time
    pub stats_start_time: Instant,
}

impl ReplicationStats {
    /// Create new replication statistics
    ///
    /// # Returns
    /// * New ReplicationStats instance
    pub fn new() -> Self {
        Self {
            total_sessions: 0,
            active_sessions: 0,
            total_entries_sent: 0,
            total_bytes_sent: 0,
            total_errors: 0,
            average_session_duration: Duration::from_secs(0),
            stats_start_time: Instant::now(),
        }
    }

    /// Get statistics collection duration
    ///
    /// # Returns
    /// * Duration since statistics collection started
    pub fn collection_duration(&self) -> Duration {
        self.stats_start_time.elapsed()
    }

    /// Calculate throughput in entries per second
    ///
    /// # Returns
    /// * Entries per second throughput
    pub fn entries_per_second(&self) -> f64 {
        let duration_secs = self.collection_duration().as_secs_f64();
        if duration_secs > 0.0 {
            self.total_entries_sent as f64 / duration_secs
        } else {
            0.0
        }
    }
}

// ================================================================================================
// Error Types
// ================================================================================================

/// Errors that can occur in the Replication Provider FSM
#[derive(Debug)]
pub enum ReplicationProviderError {
    /// Invalid state transition attempted
    InvalidStateTransition {
        from: ReplicationProviderState,
        to: ReplicationProviderState,
    },
    /// No active consumer session
    NoActiveConsumer,
    /// Consumer not found
    ConsumerNotFound { consumer_id: String },
    /// Invalid replication cookie
    InvalidCookie { cookie: String },
    /// Changelog access error
    ChangelogError { message: String },
    /// Consumer registry error
    RegistryError { message: String },
    /// Streaming error
    StreamingError { message: String },
    /// Sync request processing error
    SyncRequestError { message: String },
    /// Generic error
    Generic { message: String },
}

impl std::fmt::Display for ReplicationProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReplicationProviderError::InvalidStateTransition { from, to } => {
                write!(f, "Invalid state transition from {:?} to {:?}", from, to)
            }
            ReplicationProviderError::NoActiveConsumer => {
                write!(f, "No active consumer session")
            }
            ReplicationProviderError::ConsumerNotFound { consumer_id } => {
                write!(f, "Consumer not found: {}", consumer_id)
            }
            ReplicationProviderError::InvalidCookie { cookie } => {
                write!(f, "Invalid replication cookie: {}", cookie)
            }
            ReplicationProviderError::ChangelogError { message } => {
                write!(f, "Changelog error: {}", message)
            }
            ReplicationProviderError::RegistryError { message } => {
                write!(f, "Registry error: {}", message)
            }
            ReplicationProviderError::StreamingError { message } => {
                write!(f, "Streaming error: {}", message)
            }
            ReplicationProviderError::SyncRequestError { message } => {
                write!(f, "Sync request error: {}", message)
            }
            ReplicationProviderError::Generic { message } => {
                write!(f, "Replication provider error: {}", message)
            }
        }
    }
}

impl std::error::Error for ReplicationProviderError {}

// ================================================================================================
// Configuration
// ================================================================================================

/// Configuration for the Replication Provider FSM
#[derive(Debug, Clone)]
pub struct ReplicationProviderConfig {
    /// Maximum number of entries to send in refresh phase batch
    pub refresh_batch_size: usize,
    /// Maximum number of changelog entries to process at once
    pub changelog_batch_size: usize,
    /// Timeout for consumer operations
    pub consumer_timeout: Duration,
    /// Maximum number of concurrent consumers
    pub max_concurrent_consumers: u32,
    /// Enable streaming compression
    pub enable_compression: bool,
    /// Streaming heartbeat interval
    pub heartbeat_interval: Duration,
    /// Cookie expiration time
    pub cookie_expiry: Duration,
    /// Maximum retry attempts for failed operations
    pub max_retry_attempts: u32,
}

impl Default for ReplicationProviderConfig {
    fn default() -> Self {
        Self {
            refresh_batch_size: 100,
            changelog_batch_size: 50,
            consumer_timeout: Duration::from_secs(300), // 5 minutes
            max_concurrent_consumers: 10,
            enable_compression: true,
            heartbeat_interval: Duration::from_secs(30),
            cookie_expiry: Duration::from_secs(3600), // 1 hour
            max_retry_attempts: 3,
        }
    }
}

// ================================================================================================
// Session Management
// ================================================================================================

/// Represents an active replication session with a consumer
#[derive(Debug, Clone)]
pub struct ReplicationSession {
    /// Consumer identifier
    pub consumer_id: String,
    /// Session start time
    pub start_time: Instant,
    /// Consumer connection info
    pub connection: ConsumerConnection,
    /// Current sync request being processed
    pub sync_request: Option<SyncRequest>,
    /// Last replication cookie sent
    pub last_cookie: Option<String>,
    /// Entries sent during refresh phase
    pub refresh_entries_sent: usize,
    /// Entries streamed during present phase
    pub present_entries_sent: usize,
    /// Total bytes sent to consumer
    pub total_bytes_sent: usize,
    /// Last activity timestamp
    pub last_activity: Instant,
    /// Session error count
    pub error_count: usize,
    /// Current phase being processed
    pub current_phase: ReplicationPhase,
}

impl ReplicationSession {
    /// Create new replication session
    ///
    /// # Arguments
    /// * `consumer_id` - Consumer identifier
    /// * `connection` - Consumer connection info
    ///
    /// # Returns
    /// * New ReplicationSession instance
    pub fn new(consumer_id: String, connection: ConsumerConnection) -> Self {
        let now = Instant::now();
        Self {
            consumer_id,
            start_time: now,
            connection,
            sync_request: None,
            last_cookie: None,
            refresh_entries_sent: 0,
            present_entries_sent: 0,
            total_bytes_sent: 0,
            last_activity: now,
            error_count: 0,
            current_phase: ReplicationPhase::Initialize,
        }
    }

    /// Set sync request for this session
    ///
    /// # Arguments
    /// * `request` - Sync request to process
    pub fn set_sync_request(&mut self, request: SyncRequest) {
        self.sync_request = Some(request);
        self.last_activity = Instant::now();
    }

    /// Update session activity timestamp
    pub fn update_activity(&mut self) {
        self.last_activity = Instant::now();
        self.connection.update_activity();
    }

    /// Record entry sent during refresh phase
    ///
    /// # Arguments
    /// * `entry_size` - Size of entry in bytes
    pub fn record_refresh_entry(&mut self, entry_size: usize) {
        self.refresh_entries_sent += 1;
        self.total_bytes_sent += entry_size;
        self.update_activity();
    }

    /// Record entry sent during present phase
    ///
    /// # Arguments
    /// * `entry_size` - Size of entry in bytes
    pub fn record_present_entry(&mut self, entry_size: usize) {
        self.present_entries_sent += 1;
        self.total_bytes_sent += entry_size;
        self.update_activity();
    }

    /// Record session error
    pub fn record_error(&mut self) {
        self.error_count += 1;
        self.update_activity();
    }

    /// Get session duration
    ///
    /// # Returns
    /// * Duration since session started
    pub fn session_duration(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Get total entries sent (refresh + present)
    ///
    /// # Returns
    /// * Total number of entries sent
    pub fn total_entries_sent(&self) -> usize {
        self.refresh_entries_sent + self.present_entries_sent
    }

    /// Check if session has timed out
    ///
    /// # Arguments
    /// * `timeout` - Timeout duration
    ///
    /// # Returns
    /// * True if session has timed out
    pub fn is_timed_out(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }
}

// ================================================================================================
// Main FSM Implementation
// ================================================================================================

/// Main implementation of the Replication Provider FSM
///
/// This struct implements the RFC 4533 sync replication provider functionality
/// with support for refresh → present → persist streaming pattern.
pub struct ReplicationProviderFsmImpl {
    /// Current FSM state
    state: ReplicationProviderState,
    /// FSM configuration
    config: ReplicationProviderConfig,
    /// Active replication sessions
    sessions: HashMap<String, ReplicationSession>,
    /// Statistics counters
    total_sessions: u64,
    successful_sessions: u64,
    failed_sessions: u64,
    total_entries_sent: u64,
    total_bytes_sent: u64,

    /// External dependencies
    changelog_provider: Box<dyn ChangelogProvider>,
    consumer_registry: Box<dyn ConsumerRegistry>,
    streaming_manager: Box<dyn StreamingManager>,
    sync_request_handler: Box<dyn SyncRequestHandler>,
    metrics: Option<Box<dyn ReplicationMetrics>>,
}

impl ReplicationProviderFsmImpl {
    /// Create a new Replication Provider FSM instance
    ///
    /// # Arguments
    /// * `changelog_provider` - Changelog data provider
    /// * `consumer_registry` - Consumer session registry
    /// * `streaming_manager` - Change streaming manager
    /// * `sync_request_handler` - Sync request processor
    ///
    /// # Returns
    /// * New ReplicationProviderFsmImpl instance
    pub fn new(
        changelog_provider: Box<dyn ChangelogProvider>,
        consumer_registry: Box<dyn ConsumerRegistry>,
        streaming_manager: Box<dyn StreamingManager>,
        sync_request_handler: Box<dyn SyncRequestHandler>,
    ) -> Self {
        Self {
            state: ReplicationProviderState::Initializing,
            config: ReplicationProviderConfig::default(),
            sessions: HashMap::new(),
            total_sessions: 0,
            successful_sessions: 0,
            failed_sessions: 0,
            total_entries_sent: 0,
            total_bytes_sent: 0,
            changelog_provider,
            consumer_registry,
            streaming_manager,
            sync_request_handler,
            metrics: None,
        }
    }

    /// Create FSM with custom configuration
    ///
    /// # Arguments  
    /// * `changelog_provider` - Changelog data provider
    /// * `consumer_registry` - Consumer session registry
    /// * `streaming_manager` - Change streaming manager
    /// * `sync_request_handler` - Sync request processor
    /// * `config` - Custom FSM configuration
    ///
    /// # Returns
    /// * New ReplicationProviderFsmImpl instance with custom config
    pub fn with_config(
        changelog_provider: Box<dyn ChangelogProvider>,
        consumer_registry: Box<dyn ConsumerRegistry>,
        streaming_manager: Box<dyn StreamingManager>,
        sync_request_handler: Box<dyn SyncRequestHandler>,
        config: ReplicationProviderConfig,
    ) -> Self {
        Self {
            state: ReplicationProviderState::Initializing,
            config,
            sessions: HashMap::new(),
            total_sessions: 0,
            successful_sessions: 0,
            failed_sessions: 0,
            total_entries_sent: 0,
            total_bytes_sent: 0,
            changelog_provider,
            consumer_registry,
            streaming_manager,
            sync_request_handler,
            metrics: None,
        }
    }

    /// Set metrics collector
    ///
    /// # Arguments
    /// * `metrics` - Metrics collector instance
    ///
    /// # Returns
    /// * Self for method chaining
    pub fn with_metrics(mut self, metrics: Box<dyn ReplicationMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Get current configuration
    ///
    /// # Returns
    /// * Reference to current configuration
    pub fn config(&self) -> &ReplicationProviderConfig {
        &self.config
    }

    /// Get replication statistics
    ///
    /// # Returns
    /// * (total_sessions, successful, failed, entries_sent, bytes_sent)
    pub fn get_stats(&self) -> (u64, u64, u64, u64, u64) {
        (
            self.total_sessions,
            self.successful_sessions,
            self.failed_sessions,
            self.total_entries_sent,
            self.total_bytes_sent,
        )
    }

    /// Get active session count
    ///
    /// # Returns
    /// * Number of currently active sessions
    pub fn active_session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Get session for consumer
    ///
    /// # Arguments
    /// * `consumer_id` - Consumer identifier
    ///
    /// # Returns
    /// * Reference to consumer session if found
    pub fn get_session(&self, consumer_id: &str) -> Option<&ReplicationSession> {
        self.sessions.get(consumer_id)
    }

    /// Handle sync replication start event
    ///
    /// # Arguments
    /// * `consumer_id` - Consumer identifier
    /// * `cookie` - Optional replication cookie
    ///
    /// # Returns
    /// * Result indicating success or error
    async fn handle_start_sync_replication(
        &mut self,
        consumer_id: String,
        cookie: Option<String>,
    ) -> Result<Option<usize>, ReplicationProviderError> {
        // Validate current state - should be Initializing
        if !matches!(self.state, ReplicationProviderState::Initializing) {
            return Err(ReplicationProviderError::InvalidStateTransition {
                from: self.state.clone(),
                to: ReplicationProviderState::Refresh {
                    entries_sent: 0,
                    total_entries: 0,
                },
            });
        }

        // Check if we're at consumer limit
        if self.sessions.len() >= self.config.max_concurrent_consumers as usize {
            return Err(ReplicationProviderError::Generic {
                message: format!(
                    "Maximum consumer limit ({}) reached",
                    self.config.max_concurrent_consumers
                ),
            });
        }

        // Create consumer connection info
        let connection = ConsumerConnection::new(format!("consumer-{}", consumer_id));

        // Register consumer
        self.consumer_registry
            .register_consumer(&consumer_id, connection.clone())
            .await
            .map_err(|e| ReplicationProviderError::RegistryError { message: e })?;

        // Create sync request
        let sync_request = SyncRequest::new(consumer_id.clone(), "dc=example,dc=org".to_string())
            .with_sync_mode(SyncMode::RefreshAndPersist);

        let sync_request = if let Some(cookie) = cookie {
            sync_request.with_cookie(cookie)
        } else {
            sync_request
        };

        // Validate sync request
        self.sync_request_handler
            .validate_sync_request(&sync_request)
            .await
            .map_err(|e| ReplicationProviderError::SyncRequestError { message: e })?;

        // Create session
        let mut session = ReplicationSession::new(consumer_id.clone(), connection);
        session.set_sync_request(sync_request);
        session.current_phase = ReplicationPhase::Refresh;

        // Get total entries for refresh phase
        let base_dn = session.sync_request.as_ref().unwrap().base_dn.clone();
        let entries = self
            .changelog_provider
            .get_all_entries(&base_dn, None)
            .await
            .map_err(|e| ReplicationProviderError::ChangelogError { message: e })?;

        let total_entries = entries.len();

        // Store session
        self.sessions.insert(consumer_id.clone(), session);

        // Update statistics
        self.total_sessions += 1;

        // Update state to refresh phase
        self.state = ReplicationProviderState::Refresh {
            entries_sent: 0,
            total_entries,
        };

        // Record metrics
        if let Some(ref metrics) = self.metrics {
            metrics.record_sync_start(&consumer_id, "refresh_and_persist");
        }

        Ok(Some(total_entries))
    }

    /// Handle refresh phase completion
    ///
    /// # Arguments
    /// * `entries_sent` - Number of entries sent during refresh
    ///
    /// # Returns
    /// * Result indicating success or error
    async fn handle_refresh_complete(
        &mut self,
        entries_sent: usize,
    ) -> Result<Option<usize>, ReplicationProviderError> {
        // Validate current state
        if !matches!(self.state, ReplicationProviderState::Refresh { .. }) {
            return Err(ReplicationProviderError::InvalidStateTransition {
                from: self.state.clone(),
                to: ReplicationProviderState::Present {
                    entries_streamed: 0,
                },
            });
        }

        // Update statistics
        self.total_entries_sent += entries_sent as u64;

        // Get first active session (simplified for single consumer)
        let consumer_id = self
            .sessions
            .keys()
            .next()
            .ok_or(ReplicationProviderError::NoActiveConsumer)?
            .clone();

        // Update session
        if let Some(session) = self.sessions.get_mut(&consumer_id) {
            session.refresh_entries_sent = entries_sent;
            session.current_phase = ReplicationPhase::Present;

            // Record metrics
            if let Some(ref metrics) = self.metrics {
                metrics.record_phase_complete(
                    &consumer_id,
                    "refresh",
                    entries_sent,
                    session.session_duration(),
                );
            }
        }

        // Transition to present phase
        self.state = ReplicationProviderState::Present {
            entries_streamed: 0,
        };

        Ok(Some(entries_sent))
    }

    /// Handle present phase completion
    ///
    /// # Arguments
    /// * `entries_streamed` - Number of entries streamed during present
    ///
    /// # Returns
    /// * Result indicating success or error
    async fn handle_present_complete(
        &mut self,
        entries_streamed: usize,
    ) -> Result<Option<usize>, ReplicationProviderError> {
        // Validate current state
        if !matches!(self.state, ReplicationProviderState::Present { .. }) {
            return Err(ReplicationProviderError::InvalidStateTransition {
                from: self.state.clone(),
                to: ReplicationProviderState::Persist {
                    cookie: String::new(),
                },
            });
        }

        // Get first active session (simplified for single consumer)
        let consumer_id = self
            .sessions
            .keys()
            .next()
            .ok_or(ReplicationProviderError::NoActiveConsumer)?
            .clone();

        // Get contextCSN and generate new replication cookie
        let context_csn = self
            .changelog_provider
            .get_context_csn()
            .await
            .map_err(|e| ReplicationProviderError::ChangelogError { message: e })?;

        let new_cookie = if let Some(csn) = context_csn {
            self.changelog_provider
                .generate_cookie(&csn)
                .await
                .map_err(|e| ReplicationProviderError::ChangelogError { message: e })?
        } else {
            // No CSN yet - use empty cookie
            "csn-empty".to_string()
        };

        // Update session
        if let Some(session) = self.sessions.get_mut(&consumer_id) {
            session.present_entries_sent = entries_streamed;
            session.last_cookie = Some(new_cookie.clone());
            session.current_phase = ReplicationPhase::Persist;

            // Record metrics
            if let Some(ref metrics) = self.metrics {
                metrics.record_phase_complete(
                    &consumer_id,
                    "present",
                    entries_streamed,
                    session.session_duration(),
                );
            }
        }

        // Update statistics
        self.total_entries_sent += entries_streamed as u64;

        // Transition to persist phase
        self.state = ReplicationProviderState::Persist { cookie: new_cookie };

        Ok(Some(entries_streamed))
    }

    /// Handle changelog entry streaming (CSN-based)
    ///
    /// # Arguments
    /// * `entry` - Changelog entry data
    /// * `csn` - Change Sequence Number for this entry
    ///
    /// # Returns
    /// * Result indicating success or error
    async fn handle_changelog_entry(
        &mut self,
        entry: Vec<u8>,
        csn: crate::csn::Csn,
    ) -> Result<Option<usize>, ReplicationProviderError> {
        // Validate we're in streaming-capable state
        if !matches!(
            self.state,
            ReplicationProviderState::Present { .. } | ReplicationProviderState::Streaming { .. }
        ) {
            return Err(ReplicationProviderError::InvalidStateTransition {
                from: self.state.clone(),
                to: ReplicationProviderState::Streaming {
                    active_consumers: 1,
                },
            });
        }

        // Get active consumers
        let consumer_ids: Vec<String> = self.sessions.keys().cloned().collect();

        if consumer_ids.is_empty() {
            return Err(ReplicationProviderError::NoActiveConsumer);
        }

        // Create changelog entry with CSN
        let changelog_entry = ChangelogEntry::new(
            csn,
            ChangeType::Modify, // Default to modify
            "cn=example,dc=example,dc=org".to_string(),
            entry,
        );

        let entry_size = changelog_entry.data_size();
        let mut successful_streams = 0;

        // Stream to all active consumers
        for consumer_id in &consumer_ids {
            match self
                .streaming_manager
                .send_entry(consumer_id, &changelog_entry)
                .await
            {
                Ok(()) => {
                    successful_streams += 1;

                    // Update session
                    if let Some(session) = self.sessions.get_mut(consumer_id) {
                        session.record_present_entry(entry_size);
                    }

                    // Record metrics
                    if let Some(ref metrics) = self.metrics {
                        metrics.record_entry_streamed(
                            consumer_id,
                            entry_size,
                            Duration::from_millis(1),
                        );
                    }
                }
                Err(e) => {
                    // Record streaming error
                    if let Some(session) = self.sessions.get_mut(consumer_id) {
                        session.record_error();
                    }

                    if let Some(ref metrics) = self.metrics {
                        metrics.record_replication_error(consumer_id, "streaming", &e);
                    }
                }
            }
        }

        // Update statistics
        self.total_entries_sent += successful_streams;
        self.total_bytes_sent += (entry_size * successful_streams as usize) as u64;

        // Update state if necessary
        if matches!(self.state, ReplicationProviderState::Present { .. }) {
            self.state = ReplicationProviderState::Streaming {
                active_consumers: self.sessions.len(),
            };
        }

        Ok(Some(successful_streams as usize))
    }

    /// Handle entry streamed confirmation
    ///
    /// # Arguments
    /// * `consumer_id` - Consumer that received the entry
    ///
    /// # Returns
    /// * Result indicating success or error
    async fn handle_entry_streamed(
        &mut self,
        consumer_id: String,
    ) -> Result<Option<usize>, ReplicationProviderError> {
        // Validate consumer exists
        if !self.sessions.contains_key(&consumer_id) {
            return Err(ReplicationProviderError::ConsumerNotFound { consumer_id });
        }

        // Update session activity
        if let Some(session) = self.sessions.get_mut(&consumer_id) {
            session.update_activity();
        }

        Ok(Some(1))
    }

    /// Handle consumer disconnection
    ///
    /// # Arguments
    /// * `consumer_id` - Disconnected consumer identifier
    ///
    /// # Returns
    /// * Result indicating success or error
    async fn handle_consumer_disconnected(
        &mut self,
        consumer_id: String,
    ) -> Result<Option<usize>, ReplicationProviderError> {
        // Remove from sessions
        let session = self.sessions.remove(&consumer_id);

        if let Some(session) = session {
            // Stop streaming for this consumer
            let _ = self.streaming_manager.stop_streaming(&consumer_id).await;

            // Unregister consumer
            let _ = self
                .consumer_registry
                .unregister_consumer(&consumer_id)
                .await;

            // Record metrics
            if let Some(ref metrics) = self.metrics {
                metrics.record_consumer_disconnection(
                    &consumer_id,
                    "client_disconnect",
                    session.session_duration(),
                );
            }

            // Update session statistics
            self.successful_sessions += 1;
        }

        // Update state if no more consumers
        if self.sessions.is_empty() {
            self.state = ReplicationProviderState::Completed;
        } else {
            // Update streaming state with current consumer count
            if matches!(self.state, ReplicationProviderState::Streaming { .. }) {
                self.state = ReplicationProviderState::Streaming {
                    active_consumers: self.sessions.len(),
                };
            }
        }

        Ok(Some(self.sessions.len()))
    }

    /// Handle cookie persistence
    ///
    /// # Arguments
    /// * `new_cookie` - New replication cookie to persist
    ///
    /// # Returns
    /// * Result indicating success or error
    async fn handle_cookie_persisted(
        &mut self,
        new_cookie: String,
    ) -> Result<Option<usize>, ReplicationProviderError> {
        // Update state if in persist phase
        if matches!(self.state, ReplicationProviderState::Persist { .. }) {
            self.state = ReplicationProviderState::Persist {
                cookie: new_cookie.clone(),
            };
        }

        // Update all sessions with new cookie
        for session in self.sessions.values_mut() {
            session.last_cookie = Some(new_cookie.clone());
            session.update_activity();
        }

        Ok(Some(self.sessions.len()))
    }

    /// Handle FSM error
    ///
    /// # Arguments
    /// * `error_message` - Error message description
    ///
    /// # Returns
    /// * Result containing error
    async fn handle_error(
        &mut self,
        error_message: String,
    ) -> Result<Option<usize>, ReplicationProviderError> {
        // Update state to error
        self.state = ReplicationProviderState::Error {
            message: error_message.clone(),
        };

        // Update failed sessions count
        self.failed_sessions += self.sessions.len() as u64;

        // Record errors for all active sessions
        for (consumer_id, session) in &mut self.sessions {
            session.record_error();

            if let Some(ref metrics) = self.metrics {
                metrics.record_replication_error(consumer_id, "fsm_error", &error_message);
            }
        }

        // Return error
        Err(ReplicationProviderError::Generic {
            message: error_message,
        })
    }
}

// ================================================================================================
// FSM Trait Implementation
// ================================================================================================

#[async_trait]
impl StateMachine for ReplicationProviderFsmImpl {
    type State = ReplicationProviderState;
    type Event = ReplicationProviderEvent;
    type Error = ReplicationProviderError;
    type Output = usize; // Number of entries processed

    fn current_state(&self) -> &Self::State {
        &self.state
    }

    fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            ReplicationProviderState::Completed | ReplicationProviderState::Error { .. }
        )
    }

    async fn handle_event(
        &mut self,
        event: Self::Event,
    ) -> Result<Option<Self::Output>, Self::Error> {
        match event {
            ReplicationProviderEvent::StartSyncReplication {
                consumer_id,
                cookie,
            } => {
                self.handle_start_sync_replication(consumer_id, cookie)
                    .await
            }
            ReplicationProviderEvent::RefreshComplete { entries_sent } => {
                self.handle_refresh_complete(entries_sent).await
            }
            ReplicationProviderEvent::PresentComplete { entries_streamed } => {
                self.handle_present_complete(entries_streamed).await
            }
            ReplicationProviderEvent::ChangelogEntry { entry, csn } => {
                self.handle_changelog_entry(entry, csn).await
            }
            ReplicationProviderEvent::EntryStreamed { consumer_id } => {
                self.handle_entry_streamed(consumer_id).await
            }
            ReplicationProviderEvent::ConsumerDisconnected { consumer_id } => {
                self.handle_consumer_disconnected(consumer_id).await
            }
            ReplicationProviderEvent::CookiePersisted { new_cookie } => {
                self.handle_cookie_persisted(new_cookie).await
            }
            ReplicationProviderEvent::Error(message) => self.handle_error(message).await,
        }
    }

    async fn reset(&mut self) -> Result<(), Self::Error> {
        // Clear all sessions
        self.sessions.clear();

        // Reset state
        self.state = ReplicationProviderState::Initializing;

        // Reset streaming for all consumers
        let active_consumers = self
            .consumer_registry
            .get_active_consumers()
            .await
            .map_err(|e| ReplicationProviderError::RegistryError { message: e })?;

        for consumer_id in active_consumers {
            let _ = self.streaming_manager.stop_streaming(&consumer_id).await;
            let _ = self
                .consumer_registry
                .unregister_consumer(&consumer_id)
                .await;
        }

        Ok(())
    }
}

#[async_trait]
impl ReplicationProviderFsm for ReplicationProviderFsmImpl {
    fn consumer_id(&self) -> Option<&str> {
        // Return first active consumer (simplified for single consumer case)
        self.sessions.keys().next().map(|s| s.as_str())
    }

    fn cookie(&self) -> Option<&str> {
        match &self.state {
            ReplicationProviderState::Persist { cookie } => Some(cookie),
            _ => {
                // Try to get cookie from active session
                self.sessions
                    .values()
                    .next()
                    .and_then(|session| session.last_cookie.as_deref())
            }
        }
    }

    fn entries_sent(&self) -> usize {
        match &self.state {
            ReplicationProviderState::Refresh { entries_sent, .. } => *entries_sent,
            _ => {
                // Sum refresh entries from all sessions
                self.sessions
                    .values()
                    .map(|session| session.refresh_entries_sent)
                    .sum()
            }
        }
    }

    fn entries_streamed(&self) -> usize {
        match &self.state {
            ReplicationProviderState::Present { entries_streamed } => *entries_streamed,
            _ => {
                // Sum present entries from all sessions
                self.sessions
                    .values()
                    .map(|session| session.present_entries_sent)
                    .sum()
            }
        }
    }

    fn is_streaming(&self) -> bool {
        matches!(self.state, ReplicationProviderState::Streaming { .. })
    }

    fn active_consumers(&self) -> usize {
        match &self.state {
            ReplicationProviderState::Streaming { active_consumers } => *active_consumers,
            _ => self.sessions.len(),
        }
    }

    fn current_phase(&self) -> ReplicationPhase {
        match &self.state {
            ReplicationProviderState::Initializing => ReplicationPhase::Initialize,
            ReplicationProviderState::Refresh { .. } => ReplicationPhase::Refresh,
            ReplicationProviderState::Present { .. } => ReplicationPhase::Present,
            ReplicationProviderState::Persist { .. } => ReplicationPhase::Persist,
            ReplicationProviderState::Streaming { .. } => ReplicationPhase::Stream,
            ReplicationProviderState::Completed => ReplicationPhase::Complete,
            ReplicationProviderState::Error { .. } => ReplicationPhase::Error,
        }
    }

    fn sync_stats(&self) -> (usize, usize, usize) {
        let refresh_entries = self.entries_sent();
        let present_entries = self.entries_streamed();
        let total_consumers = self.sessions.len();

        (refresh_entries, present_entries, total_consumers)
    }
}

// ================================================================================================
// Unit Tests
// ================================================================================================

#[cfg(test)]
pub mod tests {
    use super::*;
    use tokio;

    // Mock implementations for testing
    pub struct MockChangelogProvider {
        should_fail: bool,
        entries: Vec<DirectoryEntry>,
        changelog: Vec<ChangelogEntry>,
    }

    impl MockChangelogProvider {
        pub fn new() -> Self {
            Self {
                should_fail: false,
                entries: vec![
                    DirectoryEntry::new("cn=user1,dc=example,dc=org".to_string(), HashMap::new()),
                    DirectoryEntry::new("cn=user2,dc=example,dc=org".to_string(), HashMap::new()),
                ],
                changelog: vec![ChangelogEntry::new(
                    crate::csn::Csn::new(1),
                    ChangeType::Add,
                    "cn=user3,dc=example,dc=org".to_string(),
                    b"entry data".to_vec(),
                )],
            }
        }

        pub fn with_failure(mut self) -> Self {
            self.should_fail = true;
            self
        }

        pub fn with_entries(mut self, entries: Vec<DirectoryEntry>) -> Self {
            self.entries = entries;
            self
        }
    }

    #[async_trait]
    impl ChangelogProvider for MockChangelogProvider {
        async fn get_all_entries(
            &self,
            _base_dn: &str,
            _filter: Option<&str>,
        ) -> Result<Vec<DirectoryEntry>, String> {
            if self.should_fail {
                Err("Mock changelog provider failure".to_string())
            } else {
                Ok(self.entries.clone())
            }
        }

        async fn get_changelog_since(
            &self,
            _cookie: Option<&str>,
            _limit: usize,
        ) -> Result<Vec<ChangelogEntry>, String> {
            if self.should_fail {
                Err("Mock changelog provider failure".to_string())
            } else {
                Ok(self.changelog.clone())
            }
        }

        async fn generate_cookie(&self, last_csn: &crate::csn::Csn) -> Result<String, String> {
            if self.should_fail {
                Err("Mock cookie generation failure".to_string())
            } else {
                Ok(format!("csn-{}", last_csn))
            }
        }

        async fn get_context_csn(&self) -> Result<Option<crate::csn::Csn>, String> {
            if self.should_fail {
                Err("Mock context CSN retrieval failure".to_string())
            } else if let Some(entry) = self.changelog.last() {
                Ok(Some(entry.csn.clone()))
            } else {
                Ok(None)
            }
        }

        async fn validate_cookie(&self, _cookie: &str) -> Result<bool, String> {
            if self.should_fail {
                Err("Mock cookie validation failure".to_string())
            } else {
                Ok(true)
            }
        }
    }

    pub struct MockConsumerRegistry {
        should_fail: bool,
        consumers: HashMap<String, ConsumerConnection>,
    }

    impl MockConsumerRegistry {
        pub fn new() -> Self {
            Self {
                should_fail: false,
                consumers: HashMap::new(),
            }
        }

        pub fn with_failure(mut self) -> Self {
            self.should_fail = true;
            self
        }
    }

    #[async_trait]
    impl ConsumerRegistry for MockConsumerRegistry {
        async fn register_consumer(
            &mut self,
            consumer_id: &str,
            connection_info: ConsumerConnection,
        ) -> Result<(), String> {
            if self.should_fail {
                Err("Mock registry failure".to_string())
            } else {
                self.consumers
                    .insert(consumer_id.to_string(), connection_info);
                Ok(())
            }
        }

        async fn unregister_consumer(&mut self, consumer_id: &str) -> Result<bool, String> {
            if self.should_fail {
                Err("Mock registry failure".to_string())
            } else {
                Ok(self.consumers.remove(consumer_id).is_some())
            }
        }

        async fn is_consumer_connected(&self, consumer_id: &str) -> Result<bool, String> {
            if self.should_fail {
                Err("Mock registry failure".to_string())
            } else {
                Ok(self.consumers.contains_key(consumer_id))
            }
        }

        async fn get_active_consumers(&self) -> Result<Vec<String>, String> {
            if self.should_fail {
                Err("Mock registry failure".to_string())
            } else {
                Ok(self.consumers.keys().cloned().collect())
            }
        }

        async fn update_consumer_activity(&mut self, consumer_id: &str) -> Result<(), String> {
            if self.should_fail {
                Err("Mock registry failure".to_string())
            } else {
                if let Some(connection) = self.consumers.get_mut(consumer_id) {
                    connection.update_activity();
                }
                Ok(())
            }
        }

        async fn get_persistent_consumers(&self) -> Result<Vec<String>, String> {
            if self.should_fail {
                Err("Mock registry failure".to_string())
            } else {
                Ok(self
                    .consumers
                    .iter()
                    .filter(|(_, conn)| conn.is_persistent_mode())
                    .map(|(id, _)| id.clone())
                    .collect())
            }
        }

        async fn get_consumer(
            &self,
            consumer_id: &str,
        ) -> Result<Option<ConsumerConnection>, String> {
            if self.should_fail {
                Err("Mock registry failure".to_string())
            } else {
                Ok(self.consumers.get(consumer_id).cloned())
            }
        }

        async fn update_consumer_cookie(
            &mut self,
            consumer_id: &str,
            cookie: String,
        ) -> Result<(), String> {
            if self.should_fail {
                Err("Mock registry failure".to_string())
            } else {
                if let Some(connection) = self.consumers.get_mut(consumer_id) {
                    connection.update_cookie(cookie);
                }
                Ok(())
            }
        }
    }

    pub struct MockStreamingManager {
        should_fail: bool,
        active_streams: HashSet<String>,
    }

    impl MockStreamingManager {
        pub fn new() -> Self {
            Self {
                should_fail: false,
                active_streams: HashSet::new(),
            }
        }

        pub fn with_failure(mut self) -> Self {
            self.should_fail = true;
            self
        }
    }

    #[async_trait]
    impl StreamingManager for MockStreamingManager {
        async fn start_streaming(
            &mut self,
            consumer_id: &str,
            _start_cookie: Option<&str>,
        ) -> Result<(), String> {
            if self.should_fail {
                Err("Mock streaming failure".to_string())
            } else {
                self.active_streams.insert(consumer_id.to_string());
                Ok(())
            }
        }

        async fn stop_streaming(&mut self, consumer_id: &str) -> Result<(), String> {
            if self.should_fail {
                Err("Mock streaming failure".to_string())
            } else {
                self.active_streams.remove(consumer_id);
                Ok(())
            }
        }

        async fn send_entry(
            &self,
            _consumer_id: &str,
            _entry: &ChangelogEntry,
        ) -> Result<(), String> {
            if self.should_fail {
                Err("Mock streaming failure".to_string())
            } else {
                Ok(())
            }
        }

        async fn is_streaming_active(&self, consumer_id: &str) -> Result<bool, String> {
            if self.should_fail {
                Err("Mock streaming failure".to_string())
            } else {
                Ok(self.active_streams.contains(consumer_id))
            }
        }

        async fn get_streaming_stats(&self, _consumer_id: &str) -> Result<StreamingStats, String> {
            if self.should_fail {
                Err("Mock streaming failure".to_string())
            } else {
                Ok(StreamingStats::new())
            }
        }
    }

    pub struct MockSyncRequestHandler {
        should_fail: bool,
    }

    impl MockSyncRequestHandler {
        pub fn new() -> Self {
            Self { should_fail: false }
        }

        pub fn with_failure(mut self) -> Self {
            self.should_fail = true;
            self
        }
    }

    #[async_trait]
    impl SyncRequestHandler for MockSyncRequestHandler {
        async fn process_sync_request(
            &self,
            _request: &SyncRequest,
        ) -> Result<SyncResponse, String> {
            if self.should_fail {
                Err("Mock sync handler failure".to_string())
            } else {
                Ok(SyncResponse::new(0).with_entry_count(2))
            }
        }

        async fn validate_sync_request(&self, _request: &SyncRequest) -> Result<(), String> {
            if self.should_fail {
                Err("Mock sync handler failure".to_string())
            } else {
                Ok(())
            }
        }

        async fn generate_sync_response(
            &self,
            _consumer_id: &str,
            result_code: u32,
            cookie: Option<&str>,
            entries_sent: usize,
        ) -> Result<SyncResponse, String> {
            if self.should_fail {
                Err("Mock sync handler failure".to_string())
            } else {
                let mut response = SyncResponse::new(result_code).with_entry_count(entries_sent);
                if let Some(cookie) = cookie {
                    response = response.with_cookie(cookie.to_string());
                }
                Ok(response)
            }
        }
    }

    pub struct MockReplicationMetrics;

    impl ReplicationMetrics for MockReplicationMetrics {
        fn record_sync_start(&self, _consumer_id: &str, _operation_type: &str) {}
        fn record_phase_complete(
            &self,
            _consumer_id: &str,
            _phase: &str,
            _entries_processed: usize,
            _duration: Duration,
        ) {
        }
        fn record_entry_streamed(
            &self,
            _consumer_id: &str,
            _entry_size: usize,
            _processing_time: Duration,
        ) {
        }
        fn record_replication_error(
            &self,
            _consumer_id: &str,
            _error_type: &str,
            _error_message: &str,
        ) {
        }
        fn record_consumer_disconnection(
            &self,
            _consumer_id: &str,
            _reason: &str,
            _session_duration: Duration,
        ) {
        }
        fn get_replication_stats(&self) -> ReplicationStats {
            ReplicationStats::new()
        }
    }

    // Helper function to create test FSM
    fn create_test_fsm() -> ReplicationProviderFsmImpl {
        let changelog_provider = Box::new(MockChangelogProvider::new());
        let consumer_registry = Box::new(MockConsumerRegistry::new());
        let streaming_manager = Box::new(MockStreamingManager::new());
        let sync_request_handler = Box::new(MockSyncRequestHandler::new());

        ReplicationProviderFsmImpl::new(
            changelog_provider,
            consumer_registry,
            streaming_manager,
            sync_request_handler,
        )
    }

    fn create_test_fsm_with_metrics() -> ReplicationProviderFsmImpl {
        create_test_fsm().with_metrics(Box::new(MockReplicationMetrics))
    }

    // Basic FSM creation and initialization tests
    #[tokio::test]
    async fn test_new_replication_provider_fsm() {
        let fsm = create_test_fsm();

        assert!(matches!(
            fsm.current_state(),
            ReplicationProviderState::Initializing
        ));
        assert_eq!(fsm.consumer_id(), None);
        assert_eq!(fsm.cookie(), None);
        assert_eq!(fsm.entries_sent(), 0);
        assert_eq!(fsm.entries_streamed(), 0);
        assert!(!fsm.is_streaming());
        assert_eq!(fsm.active_consumers(), 0);
        assert_eq!(fsm.current_phase(), ReplicationPhase::Initialize);

        let (total, successful, failed, entries, bytes) = fsm.get_stats();
        assert_eq!(total, 0);
        assert_eq!(successful, 0);
        assert_eq!(failed, 0);
        assert_eq!(entries, 0);
        assert_eq!(bytes, 0);
    }

    #[tokio::test]
    async fn test_replication_fsm_with_config() {
        let config = ReplicationProviderConfig {
            refresh_batch_size: 200,
            changelog_batch_size: 100,
            consumer_timeout: Duration::from_secs(600),
            max_concurrent_consumers: 5,
            enable_compression: false,
            heartbeat_interval: Duration::from_secs(60),
            cookie_expiry: Duration::from_secs(7200),
            max_retry_attempts: 5,
        };

        let changelog_provider = Box::new(MockChangelogProvider::new());
        let consumer_registry = Box::new(MockConsumerRegistry::new());
        let streaming_manager = Box::new(MockStreamingManager::new());
        let sync_request_handler = Box::new(MockSyncRequestHandler::new());

        let fsm = ReplicationProviderFsmImpl::with_config(
            changelog_provider,
            consumer_registry,
            streaming_manager,
            sync_request_handler,
            config,
        );

        assert_eq!(fsm.config().refresh_batch_size, 200);
        assert_eq!(fsm.config().max_concurrent_consumers, 5);
        assert!(!fsm.config().enable_compression);
    }

    // State transition tests
    #[tokio::test]
    async fn test_start_sync_replication_success() {
        let mut fsm = create_test_fsm();

        let result = fsm
            .handle_event(ReplicationProviderEvent::StartSyncReplication {
                consumer_id: "consumer1".to_string(),
                cookie: None,
            })
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some(2)); // MockChangelogProvider returns 2 entries
        assert!(matches!(
            fsm.current_state(),
            ReplicationProviderState::Refresh {
                entries_sent: 0,
                total_entries: 2
            }
        ));
        assert_eq!(fsm.active_consumers(), 1);
        assert_eq!(fsm.current_phase(), ReplicationPhase::Refresh);

        let (total, _, _, _, _) = fsm.get_stats();
        assert_eq!(total, 1);
    }

    #[tokio::test]
    async fn test_start_sync_replication_with_cookie() {
        let mut fsm = create_test_fsm();

        let result = fsm
            .handle_event(ReplicationProviderEvent::StartSyncReplication {
                consumer_id: "consumer1".to_string(),
                cookie: Some("existing-cookie-123".to_string()),
            })
            .await;

        assert!(result.is_ok());
        assert!(matches!(
            fsm.current_state(),
            ReplicationProviderState::Refresh { .. }
        ));
    }

    #[tokio::test]
    async fn test_start_sync_replication_registry_error() {
        let changelog_provider = Box::new(MockChangelogProvider::new());
        let consumer_registry = Box::new(MockConsumerRegistry::new().with_failure());
        let streaming_manager = Box::new(MockStreamingManager::new());
        let sync_request_handler = Box::new(MockSyncRequestHandler::new());

        let mut fsm = ReplicationProviderFsmImpl::new(
            changelog_provider,
            consumer_registry,
            streaming_manager,
            sync_request_handler,
        );

        let result = fsm
            .handle_event(ReplicationProviderEvent::StartSyncReplication {
                consumer_id: "consumer1".to_string(),
                cookie: None,
            })
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ReplicationProviderError::RegistryError { .. }
        ));
    }

    #[tokio::test]
    async fn test_refresh_complete_success() {
        let mut fsm = create_test_fsm();

        // First start sync replication
        fsm.handle_event(ReplicationProviderEvent::StartSyncReplication {
            consumer_id: "consumer1".to_string(),
            cookie: None,
        })
        .await
        .unwrap();

        // Then complete refresh phase
        let result = fsm
            .handle_event(ReplicationProviderEvent::RefreshComplete { entries_sent: 2 })
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some(2));
        assert!(matches!(
            fsm.current_state(),
            ReplicationProviderState::Present {
                entries_streamed: 0
            }
        ));
        assert_eq!(fsm.entries_sent(), 2);
        assert_eq!(fsm.current_phase(), ReplicationPhase::Present);

        let (_, _, _, entries, _) = fsm.get_stats();
        assert_eq!(entries, 2);
    }

    #[tokio::test]
    async fn test_refresh_complete_invalid_state() {
        let mut fsm = create_test_fsm();

        // Try to complete refresh without starting sync replication
        let result = fsm
            .handle_event(ReplicationProviderEvent::RefreshComplete { entries_sent: 2 })
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ReplicationProviderError::InvalidStateTransition { .. }
        ));
    }

    #[tokio::test]
    async fn test_present_complete_success() {
        let mut fsm = create_test_fsm();

        // Setup: start sync and complete refresh
        fsm.handle_event(ReplicationProviderEvent::StartSyncReplication {
            consumer_id: "consumer1".to_string(),
            cookie: None,
        })
        .await
        .unwrap();

        fsm.handle_event(ReplicationProviderEvent::RefreshComplete { entries_sent: 2 })
            .await
            .unwrap();

        // Complete present phase
        let result = fsm
            .handle_event(ReplicationProviderEvent::PresentComplete {
                entries_streamed: 1,
            })
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some(1));
        assert!(matches!(
            fsm.current_state(),
            ReplicationProviderState::Persist { .. }
        ));
        assert_eq!(fsm.entries_streamed(), 1);
        assert_eq!(fsm.current_phase(), ReplicationPhase::Persist);
    }

    #[tokio::test]
    async fn test_present_complete_invalid_state() {
        let mut fsm = create_test_fsm();

        // Try to complete present without being in present state
        let result = fsm
            .handle_event(ReplicationProviderEvent::PresentComplete {
                entries_streamed: 1,
            })
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ReplicationProviderError::InvalidStateTransition { .. }
        ));
    }

    #[tokio::test]
    async fn test_changelog_entry_streaming() {
        let mut fsm = create_test_fsm();

        // Setup: start sync and reach present phase
        fsm.handle_event(ReplicationProviderEvent::StartSyncReplication {
            consumer_id: "consumer1".to_string(),
            cookie: None,
        })
        .await
        .unwrap();

        fsm.handle_event(ReplicationProviderEvent::RefreshComplete { entries_sent: 2 })
            .await
            .unwrap();

        // Stream changelog entry with CSN
        let csn = crate::csn::Csn::new(1);
        let result = fsm
            .handle_event(ReplicationProviderEvent::ChangelogEntry {
                entry: b"test entry data".to_vec(),
                csn,
            })
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some(1)); // 1 successful stream
        assert!(matches!(
            fsm.current_state(),
            ReplicationProviderState::Streaming {
                active_consumers: 1
            }
        ));
        assert!(fsm.is_streaming());
        assert_eq!(fsm.current_phase(), ReplicationPhase::Stream);
    }

    #[tokio::test]
    async fn test_changelog_entry_no_consumers() {
        let mut fsm = create_test_fsm();

        // Try to stream changelog entry without any consumers
        fsm.state = ReplicationProviderState::Present {
            entries_streamed: 0,
        };

        let csn = crate::csn::Csn::new(1);
        let result = fsm
            .handle_event(ReplicationProviderEvent::ChangelogEntry {
                entry: b"test entry data".to_vec(),
                csn,
            })
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ReplicationProviderError::NoActiveConsumer
        ));
    }

    #[tokio::test]
    async fn test_entry_streamed_confirmation() {
        let mut fsm = create_test_fsm();

        // Setup: start sync
        fsm.handle_event(ReplicationProviderEvent::StartSyncReplication {
            consumer_id: "consumer1".to_string(),
            cookie: None,
        })
        .await
        .unwrap();

        // Confirm entry streamed
        let result = fsm
            .handle_event(ReplicationProviderEvent::EntryStreamed {
                consumer_id: "consumer1".to_string(),
            })
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some(1));
    }

    #[tokio::test]
    async fn test_entry_streamed_consumer_not_found() {
        let mut fsm = create_test_fsm();

        // Try to confirm entry for non-existent consumer
        let result = fsm
            .handle_event(ReplicationProviderEvent::EntryStreamed {
                consumer_id: "nonexistent".to_string(),
            })
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ReplicationProviderError::ConsumerNotFound { .. }
        ));
    }

    #[tokio::test]
    async fn test_consumer_disconnected() {
        let mut fsm = create_test_fsm();

        // Setup: start sync
        fsm.handle_event(ReplicationProviderEvent::StartSyncReplication {
            consumer_id: "consumer1".to_string(),
            cookie: None,
        })
        .await
        .unwrap();

        assert_eq!(fsm.active_consumers(), 1);

        // Disconnect consumer
        let result = fsm
            .handle_event(ReplicationProviderEvent::ConsumerDisconnected {
                consumer_id: "consumer1".to_string(),
            })
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some(0)); // 0 remaining consumers
        assert!(matches!(
            fsm.current_state(),
            ReplicationProviderState::Completed
        ));
        assert_eq!(fsm.active_consumers(), 0);
        assert_eq!(fsm.current_phase(), ReplicationPhase::Complete);

        let (_, successful, _, _, _) = fsm.get_stats();
        assert_eq!(successful, 1);
    }

    #[tokio::test]
    async fn test_cookie_persisted() {
        let mut fsm = create_test_fsm();

        // Set to persist state
        fsm.state = ReplicationProviderState::Persist {
            cookie: "old-cookie".to_string(),
        };

        let result = fsm
            .handle_event(ReplicationProviderEvent::CookiePersisted {
                new_cookie: "new-cookie-456".to_string(),
            })
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some(0)); // 0 active sessions in this test
        assert!(matches!(
            fsm.current_state(),
            ReplicationProviderState::Persist { .. }
        ));

        if let ReplicationProviderState::Persist { cookie } = fsm.current_state() {
            assert_eq!(cookie, "new-cookie-456");
        }
    }

    #[tokio::test]
    async fn test_error_event() {
        let mut fsm = create_test_fsm();
        let error_message = "Test error occurred";

        let result = fsm
            .handle_event(ReplicationProviderEvent::Error(error_message.to_string()))
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ReplicationProviderError::Generic { .. }
        ));
        assert!(matches!(
            fsm.current_state(),
            ReplicationProviderState::Error { .. }
        ));
        assert_eq!(fsm.current_phase(), ReplicationPhase::Error);

        if let ReplicationProviderState::Error { message } = fsm.current_state() {
            assert_eq!(message, error_message);
        }
    }

    #[tokio::test]
    async fn test_fsm_reset() {
        let mut fsm = create_test_fsm();

        // Setup: start sync and progress through states
        fsm.handle_event(ReplicationProviderEvent::StartSyncReplication {
            consumer_id: "consumer1".to_string(),
            cookie: None,
        })
        .await
        .unwrap();

        assert_eq!(fsm.active_consumers(), 1);
        assert!(matches!(
            fsm.current_state(),
            ReplicationProviderState::Refresh { .. }
        ));

        // Reset FSM
        let result = fsm.reset().await;

        assert!(result.is_ok());
        assert!(matches!(
            fsm.current_state(),
            ReplicationProviderState::Initializing
        ));
        assert_eq!(fsm.active_consumers(), 0);
        assert_eq!(fsm.current_phase(), ReplicationPhase::Initialize);
    }

    #[tokio::test]
    async fn test_is_terminal_states() {
        let mut fsm = create_test_fsm();

        // Initial state should not be terminal
        assert!(!fsm.is_terminal());

        // Set to completed state
        fsm.state = ReplicationProviderState::Completed;
        assert!(fsm.is_terminal());

        // Set to error state
        fsm.state = ReplicationProviderState::Error {
            message: "test error".to_string(),
        };
        assert!(fsm.is_terminal());

        // Non-terminal states
        fsm.state = ReplicationProviderState::Refresh {
            entries_sent: 0,
            total_entries: 10,
        };
        assert!(!fsm.is_terminal());

        fsm.state = ReplicationProviderState::Streaming {
            active_consumers: 1,
        };
        assert!(!fsm.is_terminal());
    }

    #[tokio::test]
    async fn test_replication_fsm_with_metrics() {
        let mut fsm = create_test_fsm_with_metrics();

        // Test that operations work with metrics enabled
        let result = fsm
            .handle_event(ReplicationProviderEvent::StartSyncReplication {
                consumer_id: "consumer1".to_string(),
                cookie: None,
            })
            .await;

        assert!(result.is_ok());
        assert!(matches!(
            fsm.current_state(),
            ReplicationProviderState::Refresh { .. }
        ));
    }

    // Data structure tests
    #[tokio::test]
    async fn test_directory_entry_methods() {
        let mut attributes = HashMap::new();
        attributes.insert("cn".to_string(), vec!["testuser".to_string()]);
        attributes.insert("mail".to_string(), vec!["test@example.com".to_string()]);

        let entry = DirectoryEntry::new("cn=testuser,dc=example,dc=org".to_string(), attributes)
            .with_uuid("123e4567-e89b-12d3-a456-426614174000".to_string());

        assert_eq!(entry.dn, "cn=testuser,dc=example,dc=org");
        assert_eq!(
            entry.uuid,
            Some("123e4567-e89b-12d3-a456-426614174000".to_string())
        );
        assert!(entry.estimated_size() > 0);
    }

    #[tokio::test]
    async fn test_changelog_entry_methods() {
        let csn = crate::csn::Csn::new(1);
        let entry = ChangelogEntry::new(
            csn.clone(),
            ChangeType::Add,
            "cn=newuser,dc=example,dc=org".to_string(),
            b"entry data content".to_vec(),
        )
        .with_originator("admin".to_string());

        assert_eq!(entry.csn, csn);
        assert_eq!(entry.change_type, ChangeType::Add);
        assert_eq!(entry.dn, "cn=newuser,dc=example,dc=org");
        assert_eq!(entry.originator, Some("admin".to_string()));
        assert_eq!(entry.data_size(), 18); // Length of "entry data content"
    }

    #[tokio::test]
    async fn test_consumer_connection_methods() {
        let mut connection = ConsumerConnection::new("10.0.0.1:389".to_string());
        connection.add_capability("sync-replication".to_string());
        connection.add_capability("compression".to_string());

        assert_eq!(connection.address, "10.0.0.1:389");
        assert!(connection.capabilities.contains("sync-replication"));
        assert!(connection.capabilities.contains("compression"));
        assert!(connection.connection_duration().as_nanos() > 0);

        connection.update_activity();
        // Activity timestamp should be updated
    }

    #[tokio::test]
    async fn test_streaming_stats_methods() {
        let mut stats = StreamingStats::new();

        stats.record_entry(100);
        stats.record_entry(200);
        stats.record_error();

        assert_eq!(stats.entries_streamed, 2);
        assert_eq!(stats.bytes_streamed, 300);
        assert_eq!(stats.error_count, 1);
        assert!(stats.last_entry_time.is_some());
        assert!(stats.streaming_duration().as_nanos() > 0);
    }

    #[tokio::test]
    async fn test_sync_request_methods() {
        let request = SyncRequest::new("consumer1".to_string(), "dc=example,dc=org".to_string())
            .with_cookie("test-cookie".to_string())
            .with_filter("(objectClass=person)".to_string())
            .with_sync_mode(SyncMode::RefreshOnly);

        assert_eq!(request.consumer_id, "consumer1");
        assert_eq!(request.base_dn, "dc=example,dc=org");
        assert_eq!(request.cookie, Some("test-cookie".to_string()));
        assert_eq!(request.filter, Some("(objectClass=person)".to_string()));
        assert_eq!(request.sync_mode, SyncMode::RefreshOnly);
    }

    #[tokio::test]
    async fn test_sync_response_methods() {
        let response = SyncResponse::new(0)
            .with_cookie("response-cookie".to_string())
            .with_entry_count(42)
            .with_message("Sync completed successfully".to_string());

        assert_eq!(response.result_code, 0);
        assert_eq!(response.cookie, Some("response-cookie".to_string()));
        assert_eq!(response.entry_count, 42);
        assert_eq!(
            response.message,
            Some("Sync completed successfully".to_string())
        );
    }

    #[tokio::test]
    async fn test_replication_stats_methods() {
        let stats = ReplicationStats::new();

        assert_eq!(stats.total_sessions, 0);
        assert_eq!(stats.active_sessions, 0);
        assert_eq!(stats.entries_per_second(), 0.0);
        assert!(stats.collection_duration().as_nanos() > 0);
    }

    #[tokio::test]
    async fn test_replication_session_methods() {
        let connection = ConsumerConnection::new("consumer1".to_string());
        let mut session = ReplicationSession::new("consumer1".to_string(), connection);

        session.record_refresh_entry(100);
        session.record_present_entry(200);
        session.record_error();

        assert_eq!(session.refresh_entries_sent, 1);
        assert_eq!(session.present_entries_sent, 1);
        assert_eq!(session.total_entries_sent(), 2);
        assert_eq!(session.total_bytes_sent, 300);
        assert_eq!(session.error_count, 1);
        assert!(session.session_duration().as_nanos() > 0);

        // Test timeout
        assert!(!session.is_timed_out(Duration::from_secs(1)));
    }

    // Error tests
    #[tokio::test]
    async fn test_error_display() {
        let errors = vec![
            ReplicationProviderError::InvalidStateTransition {
                from: ReplicationProviderState::Initializing,
                to: ReplicationProviderState::Completed,
            },
            ReplicationProviderError::NoActiveConsumer,
            ReplicationProviderError::ConsumerNotFound {
                consumer_id: "test".to_string(),
            },
            ReplicationProviderError::InvalidCookie {
                cookie: "invalid".to_string(),
            },
            ReplicationProviderError::ChangelogError {
                message: "test".to_string(),
            },
            ReplicationProviderError::RegistryError {
                message: "test".to_string(),
            },
            ReplicationProviderError::StreamingError {
                message: "test".to_string(),
            },
            ReplicationProviderError::SyncRequestError {
                message: "test".to_string(),
            },
            ReplicationProviderError::Generic {
                message: "test".to_string(),
            },
        ];

        for error in errors {
            let display = format!("{}", error);
            assert!(!display.is_empty());

            // Test that error implements std::error::Error
            let _: &dyn std::error::Error = &error;
        }
    }
}

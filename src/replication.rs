//! Replication Implementation Module
//!
//! This module provides the concrete implementations for LDAP replication,
//! including changelog tracking, provider/consumer coordination, and state management.
//!
//! ## Overview
//!
//! The replication system implements RFC 4533 (LDAP Content Synchronization Operation)
//! with a provider-consumer architecture:
//!
//! - **Provider**: Tracks directory changes and streams them to consumers
//! - **Consumer**: Receives and applies directory changes from providers
//! - **Changelog**: Persistent log of all directory modifications
//!
//! ## Architecture
//!
//! ```text
//! Provider Server                    Consumer Server
//! ┌──────────────────┐              ┌──────────────────┐
//! │ Directory Changes│              │ Sync Request     │
//! └────────┬─────────┘              └────────┬─────────┘
//!          │                                  │
//!          ▼                                  ▼
//! ┌──────────────────┐              ┌──────────────────┐
//! │ Changelog Tracker│              │ Provider Connect │
//! └────────┬─────────┘              └────────┬─────────┘
//!          │                                  │
//!          ▼                                  │
//! ┌──────────────────┐              │        │
//! │ Replication      │◄─────────────┘        │
//! │ Provider FSM     │                       │
//! └────────┬─────────┘                       │
//!          │                                  │
//!          │  Stream Changes                 │
//!          └────────────────────────────────►│
//!                                    ┌────────▼─────────┐
//!                                    │ Replication      │
//!                                    │ Consumer FSM     │
//!                                    └────────┬─────────┘
//!                                             │
//!                                             ▼
//!                                    ┌──────────────────┐
//!                                    │ Apply Changes    │
//!                                    └──────────────────┘
//! ```

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use async_trait::async_trait;

use crate::backend::DirectoryBackend;
use crate::replication_provider_fsm::*;
use crate::replication_consumer_fsm::*;

// ================================================================================================
// Changelog Implementation
// ================================================================================================

/// In-memory changelog tracker for directory changes
///
/// This implementation stores a limited history of directory changes for replication.
/// In a production system, this would be backed by persistent storage (LMDB, etc.).
#[derive(Clone)]
pub struct ChangelogTracker {
    /// Sequence number counter
    sequence: Arc<Mutex<u64>>,
    /// Changelog entries (sequence_number -> entry)
    entries: Arc<Mutex<HashMap<u64, ChangelogEntry>>>,
    /// Maximum entries to keep in memory
    max_entries: usize,
    /// Cookie to sequence number mapping
    cookies: Arc<Mutex<HashMap<String, u64>>>,
}

impl ChangelogTracker {
    /// Create new changelog tracker
    pub fn new() -> Self {
        Self::with_capacity(10000)
    }

    /// Create new changelog tracker with specific capacity
    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            sequence: Arc::new(Mutex::new(0)),
            entries: Arc::new(Mutex::new(HashMap::new())),
            max_entries,
            cookies: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Record a directory change
    pub fn record_change(
        &self,
        change_type: ChangeType,
        dn: String,
        change_data: Vec<u8>,
    ) -> u64 {
        let mut sequence = self.sequence.lock().unwrap();
        *sequence += 1;
        let seq_num = *sequence;

        let entry = ChangelogEntry::new(seq_num, change_type, dn, change_data);

        let mut entries = self.entries.lock().unwrap();
        entries.insert(seq_num, entry);

        // Prune old entries if we exceed max_entries
        if entries.len() > self.max_entries {
            let min_seq = seq_num.saturating_sub(self.max_entries as u64);
            entries.retain(|k, _| *k > min_seq);
        }

        seq_num
    }

    /// Get all entries since a sequence number
    pub fn get_since(&self, sequence: u64) -> Vec<ChangelogEntry> {
        let entries = self.entries.lock().unwrap();
        let mut result: Vec<_> = entries
            .iter()
            .filter(|(k, _)| **k > sequence)
            .map(|(_, v)| v.clone())
            .collect();
        result.sort_by_key(|e| e.sequence_number);
        result
    }

    /// Get current sequence number
    pub fn current_sequence(&self) -> u64 {
        *self.sequence.lock().unwrap()
    }

    /// Parse cookie to sequence number
    pub fn parse_cookie(&self, cookie: &str) -> Option<u64> {
        cookie.strip_prefix("seq-")
            .and_then(|s| s.parse::<u64>().ok())
    }

    /// Generate cookie from sequence number
    pub fn generate_cookie_from_seq(&self, sequence: u64) -> String {
        format!("seq-{}", sequence)
    }
}

// ================================================================================================
// Provider Implementations
// ================================================================================================

/// Concrete implementation of ChangelogProvider using ChangelogTracker
pub struct ChangelogProviderImpl {
    tracker: ChangelogTracker,
    backend: Arc<dyn DirectoryBackend>,
}

impl ChangelogProviderImpl {
    pub fn new(tracker: ChangelogTracker, backend: Arc<dyn DirectoryBackend>) -> Self {
        Self { tracker, backend }
    }
}

#[async_trait]
impl ChangelogProvider for ChangelogProviderImpl {
    async fn get_all_entries(&self, base_dn: &str, _filter: Option<&str>) -> Result<Vec<DirectoryEntry>, String> {
        // Get all entries from backend (scope 2 = subtree)
        use ldap_parser::ldap::SearchScope;
        let backend_entries = self.backend.search_entries(base_dn, SearchScope(2)).await
            .map_err(|e| format!("Backend search failed: {:?}", e))?;

        // Convert backend DirectoryEntry to replication DirectoryEntry
        let entries = backend_entries.into_iter()
            .map(|e| DirectoryEntry::new(e.dn, e.attributes))
            .collect();

        Ok(entries)
    }

    async fn get_changelog_since(&self, cookie: Option<&str>, limit: usize) -> Result<Vec<ChangelogEntry>, String> {
        let sequence = if let Some(cookie) = cookie {
            self.tracker.parse_cookie(cookie).unwrap_or(0)
        } else {
            0
        };

        let mut entries = self.tracker.get_since(sequence);
        entries.truncate(limit);
        Ok(entries)
    }

    async fn generate_cookie(&self, last_sequence: u64) -> Result<String, String> {
        Ok(self.tracker.generate_cookie_from_seq(last_sequence))
    }

    async fn validate_cookie(&self, cookie: &str) -> Result<bool, String> {
        Ok(self.tracker.parse_cookie(cookie).is_some())
    }
}

/// Simple in-memory consumer registry
pub struct ConsumerRegistryImpl {
    consumers: Arc<Mutex<HashMap<String, ConsumerConnection>>>,
}

impl ConsumerRegistryImpl {
    pub fn new() -> Self {
        Self {
            consumers: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl ConsumerRegistry for ConsumerRegistryImpl {
    async fn register_consumer(&mut self, consumer_id: &str, connection_info: ConsumerConnection) -> Result<(), String> {
        self.consumers.lock().unwrap().insert(consumer_id.to_string(), connection_info);
        Ok(())
    }

    async fn unregister_consumer(&mut self, consumer_id: &str) -> Result<bool, String> {
        Ok(self.consumers.lock().unwrap().remove(consumer_id).is_some())
    }

    async fn is_consumer_connected(&self, consumer_id: &str) -> Result<bool, String> {
        Ok(self.consumers.lock().unwrap().contains_key(consumer_id))
    }

    async fn get_active_consumers(&self) -> Result<Vec<String>, String> {
        Ok(self.consumers.lock().unwrap().keys().cloned().collect())
    }

    async fn update_consumer_activity(&mut self, consumer_id: &str) -> Result<(), String> {
        if let Some(conn) = self.consumers.lock().unwrap().get_mut(consumer_id) {
            conn.update_activity();
        }
        Ok(())
    }
}

/// Streaming manager for real-time change delivery
pub struct StreamingManagerImpl {
    active_streams: Arc<Mutex<HashMap<String, StreamingStats>>>,
}

impl StreamingManagerImpl {
    pub fn new() -> Self {
        Self {
            active_streams: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl StreamingManager for StreamingManagerImpl {
    async fn start_streaming(&mut self, consumer_id: &str, _start_cookie: Option<&str>) -> Result<(), String> {
        self.active_streams.lock().unwrap().insert(consumer_id.to_string(), StreamingStats::new());
        Ok(())
    }

    async fn stop_streaming(&mut self, consumer_id: &str) -> Result<(), String> {
        self.active_streams.lock().unwrap().remove(consumer_id);
        Ok(())
    }

    async fn send_entry(&self, consumer_id: &str, entry: &ChangelogEntry) -> Result<(), String> {
        if let Some(stats) = self.active_streams.lock().unwrap().get_mut(consumer_id) {
            stats.record_entry(entry.data_size());
            Ok(())
        } else {
            Err(format!("Consumer {} not streaming", consumer_id))
        }
    }

    async fn is_streaming_active(&self, consumer_id: &str) -> Result<bool, String> {
        Ok(self.active_streams.lock().unwrap().contains_key(consumer_id))
    }

    async fn get_streaming_stats(&self, consumer_id: &str) -> Result<StreamingStats, String> {
        self.active_streams.lock().unwrap()
            .get(consumer_id)
            .cloned()
            .ok_or_else(|| format!("Consumer {} not found", consumer_id))
    }
}

/// Sync request handler
pub struct SyncRequestHandlerImpl;

impl SyncRequestHandlerImpl {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl SyncRequestHandler for SyncRequestHandlerImpl {
    async fn process_sync_request(&self, _request: &SyncRequest) -> Result<SyncResponse, String> {
        Ok(SyncResponse::new(0))
    }

    async fn validate_sync_request(&self, _request: &SyncRequest) -> Result<(), String> {
        Ok(())
    }

    async fn generate_sync_response(
        &self,
        _consumer_id: &str,
        result_code: u32,
        cookie: Option<&str>,
        entries_sent: usize,
    ) -> Result<SyncResponse, String> {
        let mut response = SyncResponse::new(result_code).with_entry_count(entries_sent);
        if let Some(cookie) = cookie {
            response = response.with_cookie(cookie.to_string());
        }
        Ok(response)
    }
}

// ================================================================================================
// Consumer Implementations
// ================================================================================================

/// Mock provider connection for consumer
pub struct ProviderConnectionImpl {
    provider_url: Arc<Mutex<Option<String>>>,
    connected: Arc<Mutex<bool>>,
    changelog_provider: Arc<dyn ChangelogProvider>,
}

impl ProviderConnectionImpl {
    pub fn new(changelog_provider: Arc<dyn ChangelogProvider>) -> Self {
        Self {
            provider_url: Arc::new(Mutex::new(None)),
            connected: Arc::new(Mutex::new(false)),
            changelog_provider,
        }
    }
}

#[async_trait]
impl ProviderConnection for ProviderConnectionImpl {
    async fn connect(&self, url: &str) -> Result<(), ConsumerError> {
        *self.provider_url.lock().unwrap() = Some(url.to_string());
        *self.connected.lock().unwrap() = true;
        Ok(())
    }

    async fn request_from_cookie(&self, cookie: Option<&str>) -> Result<Vec<Vec<u8>>, ConsumerError> {
        let entries = self.changelog_provider.get_changelog_since(cookie, 100).await
            .map_err(|e| ConsumerError::ConnectionError { message: e })?;

        // Convert to byte vectors (simplified encoding)
        let result = entries.iter()
            .map(|e| format!("{}:{}", e.sequence_number, e.dn).into_bytes())
            .collect();

        Ok(result)
    }

    async fn disconnect(&self) -> Result<(), ConsumerError> {
        *self.connected.lock().unwrap() = false;
        Ok(())
    }

    async fn is_connected(&self) -> Result<bool, ConsumerError> {
        Ok(*self.connected.lock().unwrap())
    }

    async fn get_connection_info(&self) -> Result<ConnectionInfo, ConsumerError> {
        let url = self.provider_url.lock().unwrap().clone().unwrap_or_default();
        Ok(ConnectionInfo::new(url, "3.0".to_string(), false))
    }
}

/// Batch processor for applying changes to consumer
pub struct BatchProcessorImpl {
    backend: Arc<dyn DirectoryBackend>,
    stats: Arc<Mutex<ProcessingStats>>,
}

impl BatchProcessorImpl {
    pub fn new(backend: Arc<dyn DirectoryBackend>) -> Self {
        Self {
            backend,
            stats: Arc::new(Mutex::new(ProcessingStats::new())),
        }
    }
}

#[async_trait]
impl BatchProcessor for BatchProcessorImpl {
    async fn process_batch(&self, entries: Vec<Vec<u8>>) -> Result<(), ConsumerError> {
        for entry in entries {
            self.apply_entry(&entry).await?;
        }
        Ok(())
    }

    async fn apply_entry(&self, entry: &[u8]) -> Result<(), ConsumerError> {
        let start = Instant::now();

        // Parse entry (simplified)
        let entry_str = String::from_utf8_lossy(entry);

        // In a real implementation, would parse and apply to backend
        // For now, just record stats
        let mut stats = self.stats.lock().unwrap();
        stats.record_entry(entry.len(), start.elapsed());

        Ok(())
    }

    async fn validate_entry(&self, _entry: &[u8]) -> Result<bool, ConsumerError> {
        Ok(true)
    }

    async fn get_processing_stats(&self) -> Result<ProcessingStats, ConsumerError> {
        Ok(self.stats.lock().unwrap().clone())
    }
}

/// State manager for consumer replication state
pub struct StateManagerImpl {
    storage_path: String,
    cookie: Arc<Mutex<Option<String>>>,
}

impl StateManagerImpl {
    pub fn new(storage_path: String) -> Self {
        Self {
            storage_path,
            cookie: Arc::new(Mutex::new(None)),
        }
    }
}

#[async_trait]
impl StateManager for StateManagerImpl {
    async fn save_cookie(&self, cookie: &str) -> Result<(), ConsumerError> {
        *self.cookie.lock().unwrap() = Some(cookie.to_string());

        // In production, persist to file/database
        // For now, just keep in memory

        Ok(())
    }

    async fn load_cookie(&self) -> Result<Option<String>, ConsumerError> {
        Ok(self.cookie.lock().unwrap().clone())
    }

    async fn delete_cookie(&self) -> Result<(), ConsumerError> {
        *self.cookie.lock().unwrap() = None;
        Ok(())
    }

    async fn cookie_exists(&self) -> Result<bool, ConsumerError> {
        Ok(self.cookie.lock().unwrap().is_some())
    }

    async fn get_storage_metadata(&self) -> Result<StorageMetadata, ConsumerError> {
        Ok(StorageMetadata::new(0, "1.0".to_string(), false))
    }
}

/// Change listener for real-time updates
pub struct ChangeListenerImpl {
    listening: Arc<Mutex<bool>>,
    stats: Arc<Mutex<ListeningStats>>,
}

impl ChangeListenerImpl {
    pub fn new() -> Self {
        Self {
            listening: Arc::new(Mutex::new(false)),
            stats: Arc::new(Mutex::new(ListeningStats::new())),
        }
    }
}

#[async_trait]
impl ChangeListener for ChangeListenerImpl {
    async fn start_listening(&self) -> Result<(), ConsumerError> {
        *self.listening.lock().unwrap() = true;
        Ok(())
    }

    async fn receive_change(&self) -> Result<Option<Vec<u8>>, ConsumerError> {
        // In production, would receive from provider stream
        // For now, return None (no changes available)
        Ok(None)
    }

    async fn stop_listening(&self) -> Result<(), ConsumerError> {
        *self.listening.lock().unwrap() = false;
        Ok(())
    }

    async fn is_listening(&self) -> Result<bool, ConsumerError> {
        Ok(*self.listening.lock().unwrap())
    }

    async fn get_listening_stats(&self) -> Result<ListeningStats, ConsumerError> {
        Ok(self.stats.lock().unwrap().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_changelog_tracker_basic() {
        let tracker = ChangelogTracker::new();

        // Record some changes
        let seq1 = tracker.record_change(
            ChangeType::Add,
            "cn=user1,dc=example,dc=org".to_string(),
            b"data1".to_vec(),
        );
        assert_eq!(seq1, 1);

        let seq2 = tracker.record_change(
            ChangeType::Modify,
            "cn=user2,dc=example,dc=org".to_string(),
            b"data2".to_vec(),
        );
        assert_eq!(seq2, 2);

        // Get changes since sequence 0
        let changes = tracker.get_since(0);
        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].sequence_number, 1);
        assert_eq!(changes[1].sequence_number, 2);
    }

    #[test]
    fn test_changelog_tracker_cookie() {
        let tracker = ChangelogTracker::new();

        // Generate cookie
        let cookie = tracker.generate_cookie_from_seq(42);
        assert_eq!(cookie, "seq-42");

        // Parse cookie
        let seq = tracker.parse_cookie(&cookie);
        assert_eq!(seq, Some(42));

        // Invalid cookie
        let invalid = tracker.parse_cookie("invalid");
        assert_eq!(invalid, None);
    }

    #[test]
    fn test_changelog_tracker_pruning() {
        let tracker = ChangelogTracker::with_capacity(5);

        // Add 10 entries
        for i in 1..=10 {
            tracker.record_change(
                ChangeType::Add,
                format!("cn=user{},dc=example,dc=org", i),
                vec![i as u8],
            );
        }

        // Should only keep last 5
        let all_changes = tracker.get_since(0);
        assert!(all_changes.len() <= 5);

        // Latest entry should still be there
        assert_eq!(tracker.current_sequence(), 10);
    }
}

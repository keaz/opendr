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

use async_trait::async_trait;
use base64::Engine;
use ldap3::{LdapConnAsync, LdapConnSettings};
use log::{error, info, warn};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::{broadcast, mpsc, oneshot, Mutex as AsyncMutex};
use tokio::task::JoinHandle;

use crate::backend::DirectoryBackend;
use crate::csn::{Csn, CsnGenerator};
use crate::replication_consumer_fsm::*;
use crate::replication_provider_fsm::*;

// ================================================================================================
// Changelog Implementation
// ================================================================================================

/// In-memory changelog tracker for directory changes
///
/// This implementation stores a limited history of directory changes for replication.
/// In a production system, this would be backed by persistent storage (LMDB, etc.).
///
/// Uses CSN (Change Sequence Number) per RFC 4533 for change identification.
#[derive(Clone)]
pub struct ChangelogTracker {
    /// CSN generator for creating unique change identifiers
    csn_generator: Arc<CsnGenerator>,
    /// Changelog entries (CSN string -> entry)
    entries: Arc<Mutex<HashMap<String, ChangelogEntry>>>,
    /// Maximum entries to keep in memory
    max_entries: usize,
    /// Most recent CSN (for contextCSN)
    latest_csn: Arc<Mutex<Option<Csn>>>,
}

impl ChangelogTracker {
    /// Create new changelog tracker with default replica ID (1)
    pub fn new() -> Self {
        Self::with_replica_id(1)
    }

    /// Create new changelog tracker with specific replica ID
    pub fn with_replica_id(replica_id: u16) -> Self {
        Self::with_capacity_and_replica(10000, replica_id)
    }

    /// Create new changelog tracker with specific capacity (uses default replica ID 1)
    pub fn with_capacity(max_entries: usize) -> Self {
        Self::with_capacity_and_replica(max_entries, 1)
    }

    /// Create new changelog tracker with specific capacity and replica ID
    pub fn with_capacity_and_replica(max_entries: usize, replica_id: u16) -> Self {
        Self {
            csn_generator: Arc::new(CsnGenerator::new(replica_id)),
            entries: Arc::new(Mutex::new(HashMap::new())),
            max_entries,
            latest_csn: Arc::new(Mutex::new(None)),
        }
    }

    /// Record a directory change
    ///
    /// # Arguments
    /// * `change_type` - Type of directory change
    /// * `dn` - Distinguished name of affected entry
    /// * `change_data` - Serialized change data
    ///
    /// # Returns
    /// * CSN assigned to this change
    pub fn record_change(&self, change_type: ChangeType, dn: String, change_data: Vec<u8>) -> Csn {
        // Generate new CSN for this change
        let csn = self.csn_generator.generate();
        let csn_str = csn.to_string();

        let entry = ChangelogEntry::new(csn.clone(), change_type, dn, change_data);

        let mut entries = self.entries.lock().unwrap();
        entries.insert(csn_str, entry);

        // Update latest CSN
        let mut latest = self.latest_csn.lock().unwrap();
        *latest = Some(csn.clone());

        // Prune old entries if we exceed max_entries
        if entries.len() > self.max_entries {
            // Remove oldest entries (smallest CSNs)
            let mut csn_list: Vec<_> = entries.keys().cloned().collect();
            csn_list.sort();
            let to_remove = csn_list.len() - self.max_entries;
            for csn_key in csn_list.iter().take(to_remove) {
                entries.remove(csn_key);
            }
        }

        csn
    }

    /// Get all entries since a CSN
    ///
    /// # Arguments
    /// * `csn` - Starting CSN (exclusive - returns entries after this CSN)
    ///
    /// # Returns
    /// * Vector of changelog entries after the given CSN, sorted by CSN
    pub fn get_since_csn(&self, csn: &Csn) -> Vec<ChangelogEntry> {
        let entries = self.entries.lock().unwrap();
        let mut result: Vec<_> = entries.values().filter(|e| e.csn > *csn).cloned().collect();
        result.sort_by(|a, b| a.csn.cmp(&b.csn));
        result
    }

    /// Get all entries (for full refresh)
    pub fn get_all(&self) -> Vec<ChangelogEntry> {
        let entries = self.entries.lock().unwrap();
        let mut result: Vec<_> = entries.values().cloned().collect();
        result.sort_by(|a, b| a.csn.cmp(&b.csn));
        result
    }

    /// Get current contextCSN (latest CSN)
    pub fn get_context_csn(&self) -> Option<Csn> {
        self.latest_csn.lock().unwrap().clone()
    }

    /// Parse cookie to CSN
    ///
    /// Cookie format: "csn-<csn_string>"
    /// Example: "csn-20251007123456789012#001#000001#000000"
    pub fn parse_cookie(&self, cookie: &str) -> Option<Csn> {
        cookie.strip_prefix("csn-").and_then(|s| Csn::parse(s).ok())
    }

    /// Generate cookie from CSN
    ///
    /// Creates a replication cookie from a CSN for state tracking
    pub fn generate_cookie_from_csn(&self, csn: &Csn) -> String {
        format!("csn-{}", csn)
    }

    /// Generate cookie from contextCSN (latest CSN)
    pub fn generate_context_cookie(&self) -> String {
        if let Some(csn) = self.get_context_csn() {
            self.generate_cookie_from_csn(&csn)
        } else {
            // No changes yet - return empty state cookie
            "csn-empty".to_string()
        }
    }
}

pub const REPLICATION_STREAM_ATTRIBUTE: &str = "opendrReplicationStream";
pub const REPLICATION_COOKIE_ATTRIBUTE_PREFIX: &str = "opendrReplicationCookie=";
pub const REPLICATION_EVENT_OBJECT_CLASS: &str = "opendrReplicationEvent";
pub const REPLICATION_CHANGE_TYPE_ATTRIBUTE: &str = "opendrChangeType";
pub const REPLICATION_CHANGE_DATA_ATTRIBUTE: &str = "opendrChangeData";
pub const REPLICATION_CSN_ATTRIBUTE: &str = "opendrChangeCsn";

fn encode_change_bytes(change_type: &ChangeType, dn: &str, change_data: &[u8]) -> Vec<u8> {
    let change_type_str = match change_type {
        ChangeType::Add => "add",
        ChangeType::Modify => "modify",
        ChangeType::Delete => "delete",
        ChangeType::Rename => "rename",
    };

    let header = format!("0|{}|{}|{}|", change_type_str, dn, change_data.len());
    let mut result = header.into_bytes();
    result.extend_from_slice(change_data);
    result
}

fn encode_directory_entry_as_change(entry: crate::backend::DirectoryEntry) -> Option<Vec<u8>> {
    match serde_json::to_vec(&entry) {
        Ok(change_data) => Some(encode_change_bytes(
            &ChangeType::Add,
            &entry.dn,
            &change_data,
        )),
        Err(e) => {
            error!("Failed to serialize replication entry {}: {}", entry.dn, e);
            None
        }
    }
}

pub fn changelog_entry_to_replication_attrs(
    entry: &ChangelogEntry,
) -> Vec<(String, Vec<String>)> {
    let encoded_data = base64::engine::general_purpose::STANDARD.encode(&entry.change_data);
    vec![
        (
            "objectClass".to_string(),
            vec![REPLICATION_EVENT_OBJECT_CLASS.to_string()],
        ),
        (
            REPLICATION_CHANGE_TYPE_ATTRIBUTE.to_string(),
            vec![match entry.change_type {
                ChangeType::Add => "add",
                ChangeType::Modify => "modify",
                ChangeType::Delete => "delete",
                ChangeType::Rename => "rename",
            }
            .to_string()],
        ),
        (
            REPLICATION_CHANGE_DATA_ATTRIBUTE.to_string(),
            vec![encoded_data],
        ),
        (
            REPLICATION_CSN_ATTRIBUTE.to_string(),
            vec![entry.csn.to_string()],
        ),
    ]
}

pub fn parse_replication_stream_entry(entry: &ldap3::SearchEntry) -> Result<Vec<u8>, ConsumerError> {
    let find_attr = |name: &str| {
        entry.attrs.iter().find_map(|(key, values)| {
            if key.eq_ignore_ascii_case(name) {
                values.first()
            } else {
                None
            }
        })
    };

    let change_type = find_attr(REPLICATION_CHANGE_TYPE_ATTRIBUTE)
        .ok_or_else(|| ConsumerError::ListeningError {
            message: "Replication stream entry missing change type".to_string(),
        })?;

    let encoded_change = find_attr(REPLICATION_CHANGE_DATA_ATTRIBUTE)
        .ok_or_else(|| ConsumerError::ListeningError {
            message: "Replication stream entry missing change payload".to_string(),
        })?;

    let change_data = base64::engine::general_purpose::STANDARD
        .decode(encoded_change)
        .map_err(|e| ConsumerError::ListeningError {
            message: format!("Failed to decode replication payload: {}", e),
        })?;

    let change_type = match change_type.to_lowercase().as_str() {
        "add" => ChangeType::Add,
        "modify" => ChangeType::Modify,
        "delete" => ChangeType::Delete,
        "rename" => ChangeType::Rename,
        other => {
            return Err(ConsumerError::ListeningError {
                message: format!("Unknown replication change type: {}", other),
            })
        }
    };

    Ok(encode_change_bytes(&change_type, &entry.dn, &change_data))
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
    async fn get_all_entries(
        &self,
        base_dn: &str,
        _filter: Option<&str>,
    ) -> Result<Vec<DirectoryEntry>, String> {
        // Get all entries from backend (scope 2 = subtree)
        use ldap_parser::ldap::SearchScope;
        let backend_entries = self
            .backend
            .search_entries(base_dn, SearchScope(2))
            .await
            .map_err(|e| format!("Backend search failed: {:?}", e))?;

        // Convert backend DirectoryEntry to replication DirectoryEntry
        let entries = backend_entries
            .into_iter()
            .map(|e| DirectoryEntry::new(e.dn, e.attributes))
            .collect();

        Ok(entries)
    }

    async fn get_changelog_since(
        &self,
        cookie: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ChangelogEntry>, String> {
        let entries = if let Some(cookie_str) = cookie {
            // Parse cookie to get starting CSN
            if cookie_str == "csn-empty" {
                // Empty state - return all entries
                self.tracker.get_all()
            } else if let Some(csn) = self.tracker.parse_cookie(cookie_str) {
                // Get entries since this CSN
                self.tracker.get_since_csn(&csn)
            } else {
                // Invalid cookie - return empty
                return Err(format!("Invalid replication cookie: {}", cookie_str));
            }
        } else {
            // No cookie - return all entries (full refresh)
            self.tracker.get_all()
        };

        // Apply limit
        let mut limited_entries = entries;
        limited_entries.truncate(limit);
        Ok(limited_entries)
    }

    async fn generate_cookie(&self, last_csn: &Csn) -> Result<String, String> {
        Ok(self.tracker.generate_cookie_from_csn(last_csn))
    }

    async fn get_context_csn(&self) -> Result<Option<Csn>, String> {
        Ok(self.tracker.get_context_csn())
    }

    async fn validate_cookie(&self, cookie: &str) -> Result<bool, String> {
        if cookie == "csn-empty" {
            Ok(true)
        } else {
            Ok(self.tracker.parse_cookie(cookie).is_some())
        }
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
    async fn register_consumer(
        &mut self,
        consumer_id: &str,
        connection_info: ConsumerConnection,
    ) -> Result<(), String> {
        self.consumers
            .lock()
            .unwrap()
            .insert(consumer_id.to_string(), connection_info);
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

    async fn get_persistent_consumers(&self) -> Result<Vec<String>, String> {
        let consumers = self.consumers.lock().unwrap();
        Ok(consumers
            .iter()
            .filter(|(_, conn)| conn.is_persistent_mode())
            .map(|(id, _)| id.clone())
            .collect())
    }

    async fn get_consumer(&self, consumer_id: &str) -> Result<Option<ConsumerConnection>, String> {
        Ok(self.consumers.lock().unwrap().get(consumer_id).cloned())
    }

    async fn update_consumer_cookie(
        &mut self,
        consumer_id: &str,
        cookie: String,
    ) -> Result<(), String> {
        if let Some(conn) = self.consumers.lock().unwrap().get_mut(consumer_id) {
            conn.update_cookie(cookie);
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
    async fn start_streaming(
        &mut self,
        consumer_id: &str,
        _start_cookie: Option<&str>,
    ) -> Result<(), String> {
        self.active_streams
            .lock()
            .unwrap()
            .insert(consumer_id.to_string(), StreamingStats::new());
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
        Ok(self
            .active_streams
            .lock()
            .unwrap()
            .contains_key(consumer_id))
    }

    async fn get_streaming_stats(&self, consumer_id: &str) -> Result<StreamingStats, String> {
        self.active_streams
            .lock()
            .unwrap()
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
    ldap_connection: Arc<Mutex<Option<ldap3::Ldap>>>,
    bind_dn: Option<String>,
    bind_password: Option<String>,
    base_dn: String,
}

impl ProviderConnectionImpl {
    pub fn new(changelog_provider: Arc<dyn ChangelogProvider>) -> Self {
        Self::with_credentials_and_base(
            changelog_provider,
            None,
            None,
            "dc=example,dc=com".to_string(),
        )
    }

    pub fn with_credentials(
        changelog_provider: Arc<dyn ChangelogProvider>,
        bind_dn: Option<String>,
        bind_password: Option<String>,
    ) -> Self {
        Self::with_credentials_and_base(
            changelog_provider,
            bind_dn,
            bind_password,
            "dc=example,dc=com".to_string(),
        )
    }

    pub fn with_credentials_and_base(
        changelog_provider: Arc<dyn ChangelogProvider>,
        bind_dn: Option<String>,
        bind_password: Option<String>,
        base_dn: String,
    ) -> Self {
        Self {
            provider_url: Arc::new(Mutex::new(None)),
            connected: Arc::new(Mutex::new(false)),
            changelog_provider,
            ldap_connection: Arc::new(Mutex::new(None)),
            bind_dn,
            bind_password,
            base_dn,
        }
    }
}

#[async_trait]
impl ProviderConnection for ProviderConnectionImpl {
    async fn connect(&self, url: &str) -> Result<(), ConsumerError> {
        if url.starts_with("local://") || url.starts_with("in-memory://") {
            *self.provider_url.lock().unwrap() = Some(url.to_string());
            *self.connected.lock().unwrap() = true;
            return Ok(());
        }

        // Parse URL to ensure it's valid
        if !url.starts_with("ldap://") && !url.starts_with("ldaps://") {
            return Err(ConsumerError::ConnectionError {
                message: format!("Invalid provider URL: {}", url),
            });
        }

        // Attempt to establish LDAP connection
        let settings = LdapConnSettings::new().set_conn_timeout(std::time::Duration::from_secs(5));

        match LdapConnAsync::with_settings(settings, url).await {
            Ok((conn, mut ldap)) => {
                // Spawn connection driver in background
                tokio::spawn(async move {
                    if let Err(e) = conn.drive().await {
                        error!("LDAP connection driver error: {}", e);
                    }
                });

                // Bind with provided credentials or anonymous if none provided
                let bind_dn = self.bind_dn.as_deref().unwrap_or("");
                let bind_password = self.bind_password.as_deref().unwrap_or("");

                if bind_dn.is_empty() {
                    warn!(
                        "Attempting anonymous bind to provider {} (no credentials configured)",
                        url
                    );
                } else {
                    info!("Binding to provider {} as {}", url, bind_dn);
                }

                match ldap.simple_bind(bind_dn, bind_password).await {
                    Ok(bind_result) => {
                        if let Err(e) = bind_result.success() {
                            error!("LDAP bind failed for {}: {}", bind_dn, e);
                            return Err(ConsumerError::ConnectionError {
                                message: format!("Failed to bind to provider {}: {}", url, e),
                            });
                        }
                    }
                    Err(e) => {
                        error!("LDAP bind operation failed for {}: {}", bind_dn, e);
                        return Err(ConsumerError::ConnectionError {
                            message: format!("Failed to bind to provider {}: {}", url, e),
                        });
                    }
                }

                // Store connection
                *self.ldap_connection.lock().unwrap() = Some(ldap);
                *self.provider_url.lock().unwrap() = Some(url.to_string());
                *self.connected.lock().unwrap() = true;

                info!("Successfully connected to replication provider: {}", url);
                Ok(())
            }
            Err(e) => {
                error!("Failed to connect to provider {}: {}", url, e);
                Err(ConsumerError::ConnectionError {
                    message: format!("Failed to connect to provider {}: {}", url, e),
                })
            }
        }
    }

    async fn request_from_cookie(
        &self,
        cookie: Option<&str>,
    ) -> Result<Vec<Vec<u8>>, ConsumerError> {
        // Check if we have an LDAP connection
        let has_ldap = self.ldap_connection.lock().unwrap().is_some();

        if !has_ldap {
            if cookie.is_none() || matches!(cookie, Some("csn-empty")) {
                let entries = self
                    .changelog_provider
                    .get_all_entries(&self.base_dn, None)
                    .await
                    .map_err(|e| ConsumerError::ConnectionError { message: e })?;

                return Ok(entries
                    .into_iter()
                    .filter(|entry| entry.dn != self.base_dn && !entry.dn.starts_with("ou="))
                    .filter_map(|entry| {
                        let backend_entry = crate::backend::DirectoryEntry {
                            dn: entry.dn,
                            attributes: entry.attributes,
                            operational_attributes: crate::backend::OperationalAttributes::new(),
                        };
                        encode_directory_entry_as_change(backend_entry)
                    })
                    .collect());
            }

            let entries = self
                .changelog_provider
                .get_changelog_since(cookie, 100)
                .await
                .map_err(|e| ConsumerError::ConnectionError { message: e })?;

            return Ok(entries
                .iter()
                .map(|entry| encode_change_bytes(&entry.change_type, &entry.dn, &entry.change_data))
                .collect());
        }

        // Query remote provider via LDAP
        // Parse cookie to get CSN if provided
        let cookie_csn = if let Some(cookie_str) = cookie {
            if let Some(csn_str) = cookie_str.strip_prefix("csn-") {
                Some(csn_str.to_string())
            } else {
                None
            }
        } else {
            None
        };

        info!(
            "Requesting changelog entries from remote provider (cookie: {:?}, parsed CSN: {:?})",
            cookie, cookie_csn
        );

        // Get all entries from the provider
        use ldap3::Scope;

        // Clone the LDAP connection to avoid holding the lock across await
        let mut ldap = {
            let mut guard = self.ldap_connection.lock().unwrap();
            guard.take().ok_or_else(|| ConsumerError::ConnectionError {
                message: "LDAP connection not available".to_string(),
            })?
        };

        // Build search filter
        // NOTE: entryCSN comparison via LDAP filter is complex and not well-supported
        // We fetch all entries and filter on the consumer side based on entryCSN
        let filter = "(objectClass=*)";

        let (rs, _res) = ldap
            .search(
                &self.base_dn,
                Scope::Subtree,
                filter,
                vec!["*", "entryCSN"], // Request all attributes including entryCSN
            )
            .await
            .map_err(|e| ConsumerError::ConnectionError {
                message: format!("LDAP search failed: {}", e),
            })?
            .success()
            .map_err(|e| ConsumerError::ConnectionError {
                message: format!("LDAP search failed: {}", e),
            })?;

        // Restore the connection for future use
        *self.ldap_connection.lock().unwrap() = Some(ldap);

        info!("Retrieved {} entries from provider", rs.len());

        // Convert LDAP search results to changelog format
        use ldap3::SearchEntry;

        let result: Vec<Vec<u8>> = rs
            .into_iter()
            .filter_map(|entry| {
                let search_entry = SearchEntry::construct(entry);
                let dn = search_entry.dn.clone();

                // DEBUG: Log all attributes received for first few entries
                if dn.contains("user0000") || dn.contains("user0001") {
                    info!("DEBUG - Entry: {}", dn);
                    info!(
                        "DEBUG - Attributes: {:?}",
                        search_entry.attrs.keys().collect::<Vec<_>>()
                    );
                }

                // Skip base DN and organizational units (they should already exist)
                if dn == self.base_dn || dn.starts_with("ou=") {
                    return None;
                }

                // Filter by entryCSN if we have a cookie
                if let Some(ref cookie_csn_str) = cookie_csn {
                    // Get entryCSN from the entry
                    if let Some(entry_csn_values) = search_entry.attrs.get("entryCSN").or_else(|| search_entry.attrs.get("entrycsn")) {
                        if let Some(entry_csn_str) = entry_csn_values.first() {
                            // Compare CSNs as strings (they are formatted to be sortable)
                            // Cookie CSN format: timestamp#replica_id#seq#mod
                            // EntryCSN format: timestamp#replica_id#seq#mod (same format)

                            info!(
                                "CSN compare: entry='{}' entryCSN='{}' vs cookie='{}'",
                                dn, entry_csn_str, cookie_csn_str
                            );

                            if entry_csn_str <= cookie_csn_str {
                                // Entry is older than or equal to cookie, skip it
                                return None;
                            } else {
                                info!("Including new entry: {}", dn);
                            }
                        }
                    } else {
                        // No entryCSN means this entry can't be compared, skip it
                        warn!(
                            "Entry {} has no entryCSN, skipping during incremental sync",
                            dn
                        );
                        return None;
                    }
                }

                // Create a DirectoryEntry from the LDAP search result
                let dir_entry = crate::backend::DirectoryEntry {
                    dn: dn.clone(),
                    attributes: search_entry.attrs.clone(),
                    operational_attributes: crate::backend::OperationalAttributes::new(),
                };

                encode_directory_entry_as_change(dir_entry)
            })
            .collect();

        info!(
            "Prepared {} entries for replication (filtered by CSN)",
            result.len()
        );
        Ok(result)
    }

    async fn disconnect(&self) -> Result<(), ConsumerError> {
        // Close LDAP connection if exists
        let ldap_opt = {
            // Extract ldap from mutex and immediately drop the guard
            self.ldap_connection.lock().unwrap().take()
        };

        if let Some(mut ldap) = ldap_opt {
            if let Err(e) = ldap.unbind().await {
                warn!("Error unbinding LDAP connection: {}", e);
            }
        }

        *self.connected.lock().unwrap() = false;
        info!("Disconnected from replication provider");
        Ok(())
    }

    async fn is_connected(&self) -> Result<bool, ConsumerError> {
        Ok(*self.connected.lock().unwrap())
    }

    async fn get_connection_info(&self) -> Result<ConnectionInfo, ConsumerError> {
        let url = self
            .provider_url
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_default();
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

        // Parse entry format: sequence|change_type|dn|change_data_len|change_data
        // Find the header (ends with the 4th pipe)
        let header_end = entry
            .iter()
            .enumerate()
            .filter(|(_, &b)| b == b'|')
            .nth(3)
            .map(|(i, _)| i + 1)
            .ok_or_else(|| ConsumerError::ProcessingError {
                message: "Invalid entry format: missing header".to_string(),
            })?;

        let header = String::from_utf8_lossy(&entry[..header_end - 1]);
        let parts: Vec<&str> = header.split('|').collect();

        if parts.len() != 4 {
            return Err(ConsumerError::ProcessingError {
                message: format!("Invalid entry header format: {}", header),
            });
        }

        let sequence_str = parts[0];
        let change_type_str = parts[1];
        let dn = parts[2];
        let data_len_str = parts[3];

        let _sequence: u64 = sequence_str
            .parse()
            .map_err(|e| ConsumerError::ProcessingError {
                message: format!("Invalid sequence number: {}", e),
            })?;

        let data_len: usize = data_len_str
            .parse()
            .map_err(|e| ConsumerError::ProcessingError {
                message: format!("Invalid data length: {}", e),
            })?;

        // Extract change data
        let change_data = if data_len > 0 {
            if entry.len() < header_end + data_len {
                return Err(ConsumerError::ProcessingError {
                    message: "Entry data truncated".to_string(),
                });
            }
            &entry[header_end..header_end + data_len]
        } else {
            &[]
        };

        // Apply the change to backend based on change type
        use log::{info, warn};

        match change_type_str {
            "add" => {
                // Deserialize entry data and add to backend
                if let Ok(entry_json) = std::str::from_utf8(change_data) {
                    if let Ok(dir_entry) =
                        serde_json::from_str::<crate::backend::DirectoryEntry>(entry_json)
                    {
                        // Use empty password for replicated entries
                        // TODO: Proper password handling in replication
                        match self.backend.add_entry(dir_entry, vec![]).await {
                            Ok(_) => {
                                info!("Replicated ADD: {}", dn);
                            }
                            Err(e) => {
                                warn!("Failed to replicate ADD for {}: {:?}", dn, e);
                            }
                        }
                    } else {
                        warn!("Failed to deserialize entry data for: {}", dn);
                    }
                } else {
                    warn!("Invalid UTF-8 in entry data for: {}", dn);
                }
            }
            "modify" => {
                // For modify, we need to apply modifications
                if let Ok(entry_json) = std::str::from_utf8(change_data) {
                    if let Ok(dir_entry) =
                        serde_json::from_str::<crate::backend::DirectoryEntry>(entry_json)
                    {
                        // Convert attributes to Modification format
                        use crate::backend::{Modification, ModifyOperation};
                        let modifications: Vec<Modification> = dir_entry
                            .attributes
                            .iter()
                            .map(|(attr, values)| Modification {
                                operation: ModifyOperation::Replace,
                                attribute: attr.clone(),
                                values: values.clone(),
                            })
                            .collect();

                        match self.backend.modify_entry(dn, modifications).await {
                            Ok(_) => {
                                info!("Replicated MODIFY: {}", dn);
                            }
                            Err(e) => {
                                warn!("Failed to replicate MODIFY for {}: {:?}", dn, e);
                            }
                        }
                    }
                }
            }
            "delete" => match self.backend.delete_entry(dn).await {
                Ok(_) => {
                    info!("Replicated DELETE: {}", dn);
                }
                Err(e) => {
                    warn!("Failed to replicate DELETE for {}: {:?}", dn, e);
                }
            },
            "rename" => {
                // Rename / ModifyDN operation
                warn!("Rename operation not yet fully implemented for: {}", dn);
                // TODO: Implement proper rename/modifyDN handling
            }
            unknown => {
                return Err(ConsumerError::ProcessingError {
                    message: format!("Unknown change type: {}", unknown),
                });
            }
        }

        // Record stats
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

    async fn get_context_csn(&self) -> Result<Option<crate::csn::Csn>, ConsumerError> {
        // Get the contextCSN from the backend
        self.backend
            .get_context_csn()
            .await
            .map_err(|e| ConsumerError::ProcessingError {
                message: format!("Failed to get contextCSN from backend: {:?}", e),
            })
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

    /// Get the path to the cookie file
    fn cookie_file_path(&self) -> std::path::PathBuf {
        std::path::Path::new(&self.storage_path).join("replication_cookie.txt")
    }

    /// Ensure the storage directory exists
    fn ensure_storage_dir(&self) -> Result<(), ConsumerError> {
        let path = std::path::Path::new(&self.storage_path);
        if !path.exists() {
            std::fs::create_dir_all(path).map_err(|e| ConsumerError::StateError {
                message: format!(
                    "Failed to create storage directory {}: {}",
                    self.storage_path, e
                ),
            })?;
        }
        Ok(())
    }
}

#[async_trait]
impl StateManager for StateManagerImpl {
    async fn save_cookie(&self, cookie: &str) -> Result<(), ConsumerError> {
        // Update in-memory cache
        *self.cookie.lock().unwrap() = Some(cookie.to_string());

        // Ensure storage directory exists
        self.ensure_storage_dir()?;

        // Persist to disk using atomic write
        let cookie_path = self.cookie_file_path();
        let temp_path = cookie_path.with_extension("tmp");

        // Write to temporary file
        tokio::fs::write(&temp_path, cookie)
            .await
            .map_err(|e| ConsumerError::StateError {
                message: format!("Failed to write cookie to temp file: {}", e),
            })?;

        // Atomically rename temp file to actual cookie file
        tokio::fs::rename(&temp_path, &cookie_path)
            .await
            .map_err(|e| ConsumerError::StateError {
                message: format!("Failed to rename cookie file: {}", e),
            })?;

        log::info!("Saved replication cookie to {}", cookie_path.display());
        Ok(())
    }

    async fn load_cookie(&self) -> Result<Option<String>, ConsumerError> {
        let cookie_path = self.cookie_file_path();

        // Check if file exists
        if !cookie_path.exists() {
            log::info!("No cookie file found at {}", cookie_path.display());
            return Ok(None);
        }

        // Read cookie from file
        let cookie = tokio::fs::read_to_string(&cookie_path).await.map_err(|e| {
            ConsumerError::StateError {
                message: format!(
                    "Failed to read cookie from {}: {}",
                    cookie_path.display(),
                    e
                ),
            }
        })?;

        let cookie = cookie.trim().to_string();

        if cookie.is_empty() {
            log::warn!("Cookie file is empty at {}", cookie_path.display());
            return Ok(None);
        }

        // Update in-memory cache
        *self.cookie.lock().unwrap() = Some(cookie.clone());

        log::info!(
            "Loaded replication cookie from {}: {}",
            cookie_path.display(),
            cookie
        );
        Ok(Some(cookie))
    }

    async fn delete_cookie(&self) -> Result<(), ConsumerError> {
        // Clear in-memory cache
        *self.cookie.lock().unwrap() = None;

        // Delete file if it exists
        let cookie_path = self.cookie_file_path();
        if cookie_path.exists() {
            tokio::fs::remove_file(&cookie_path)
                .await
                .map_err(|e| ConsumerError::StateError {
                    message: format!("Failed to delete cookie file: {}", e),
                })?;
            log::info!(
                "Deleted replication cookie file at {}",
                cookie_path.display()
            );
        }

        Ok(())
    }

    async fn cookie_exists(&self) -> Result<bool, ConsumerError> {
        let cookie_path = self.cookie_file_path();
        Ok(cookie_path.exists())
    }

    async fn get_storage_metadata(&self) -> Result<StorageMetadata, ConsumerError> {
        let cookie_path = self.cookie_file_path();
        let size_bytes = if cookie_path.exists() {
            tokio::fs::metadata(&cookie_path)
                .await
                .map(|m| m.len())
                .unwrap_or(0)
        } else {
            0
        };

        Ok(StorageMetadata::new(
            size_bytes,
            "1.0".to_string(),
            cookie_path.exists(),
        ))
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
    async fn start_listening(&self, _cookie: Option<&str>) -> Result<(), ConsumerError> {
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

/// Change listener backed by an in-process broadcast stream.
pub struct BroadcastChangeListener {
    listening: Arc<Mutex<bool>>,
    stats: Arc<Mutex<ListeningStats>>,
    receiver: Arc<AsyncMutex<broadcast::Receiver<ChangelogEntry>>>,
}

impl BroadcastChangeListener {
    pub fn new(receiver: broadcast::Receiver<ChangelogEntry>) -> Self {
        Self {
            listening: Arc::new(Mutex::new(false)),
            stats: Arc::new(Mutex::new(ListeningStats::new())),
            receiver: Arc::new(AsyncMutex::new(receiver)),
        }
    }
}

#[async_trait]
impl ChangeListener for BroadcastChangeListener {
    async fn start_listening(&self, _cookie: Option<&str>) -> Result<(), ConsumerError> {
        *self.listening.lock().unwrap() = true;
        Ok(())
    }

    async fn receive_change(&self) -> Result<Option<Vec<u8>>, ConsumerError> {
        if !*self.listening.lock().unwrap() {
            return Ok(None);
        }

        let mut receiver = self.receiver.lock().await;
        match tokio::time::timeout(std::time::Duration::from_millis(250), receiver.recv()).await {
            Ok(Ok(change)) => {
                let encoded = encode_change_bytes(&change.change_type, &change.dn, &change.change_data);
                self.stats.lock().unwrap().record_change(encoded.len());
                Ok(Some(encoded))
            }
            Ok(Err(broadcast::error::RecvError::Lagged(_))) => {
                self.stats.lock().unwrap().record_error();
                Ok(None)
            }
            Ok(Err(broadcast::error::RecvError::Closed)) => Ok(None),
            Err(_) => Ok(None),
        }
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

/// Change listener backed by a long-lived LDAP search stream.
pub struct LdapChangeListener {
    provider_url: String,
    base_dn: String,
    bind_dn: Option<String>,
    bind_password: Option<String>,
    listening: Arc<Mutex<bool>>,
    stats: Arc<Mutex<ListeningStats>>,
    last_error: Arc<Mutex<Option<String>>>,
    change_rx: Arc<AsyncMutex<mpsc::Receiver<Vec<u8>>>>,
    change_tx: mpsc::Sender<Vec<u8>>,
    task_handle: Arc<Mutex<Option<JoinHandle<()>>>>,
}

impl LdapChangeListener {
    pub fn new(
        provider_url: String,
        base_dn: String,
        bind_dn: Option<String>,
        bind_password: Option<String>,
        buffer_size: usize,
    ) -> Self {
        let (change_tx, change_rx) = mpsc::channel(buffer_size);
        Self {
            provider_url,
            base_dn,
            bind_dn,
            bind_password,
            listening: Arc::new(Mutex::new(false)),
            stats: Arc::new(Mutex::new(ListeningStats::new())),
            last_error: Arc::new(Mutex::new(None)),
            change_rx: Arc::new(AsyncMutex::new(change_rx)),
            change_tx,
            task_handle: Arc::new(Mutex::new(None)),
        }
    }
}

#[async_trait]
impl ChangeListener for LdapChangeListener {
    async fn start_listening(&self, cookie: Option<&str>) -> Result<(), ConsumerError> {
        if *self.listening.lock().unwrap() {
            return Ok(());
        }

        *self.last_error.lock().unwrap() = None;

        let provider_url = self.provider_url.clone();
        let base_dn = self.base_dn.clone();
        let bind_dn = self.bind_dn.clone();
        let bind_password = self.bind_password.clone();
        let listening = self.listening.clone();
        let stats = self.stats.clone();
        let last_error = self.last_error.clone();
        let change_tx = self.change_tx.clone();
        let cookie = cookie.map(str::to_string);
        let (ready_tx, ready_rx) = oneshot::channel::<Result<(), String>>();

        let handle = tokio::spawn(async move {
            let mut ready_tx = Some(ready_tx);
            let settings =
                LdapConnSettings::new().set_conn_timeout(std::time::Duration::from_secs(5));
            let (conn, mut ldap) = match LdapConnAsync::with_settings(settings, &provider_url).await
            {
                Ok(connection) => connection,
                Err(e) => {
                    let message =
                        format!("Failed to create LDAP change listener connection: {}", e);
                    *last_error.lock().unwrap() = Some(message.clone());
                    error!("{}", message);
                    if let Some(sender) = ready_tx.take() {
                        let _ = sender.send(Err(message));
                    }
                    return;
                }
            };

            tokio::spawn(async move {
                if let Err(e) = conn.drive().await {
                    error!("LDAP change listener driver error: {}", e);
                }
            });

            let bind_dn = bind_dn.as_deref().unwrap_or("");
            let bind_password = bind_password.as_deref().unwrap_or("");
            if let Err(e) = ldap
                .simple_bind(bind_dn, bind_password)
                .await
                .and_then(|result| result.success())
            {
                let message = format!("Failed to bind LDAP change listener: {}", e);
                *last_error.lock().unwrap() = Some(message.clone());
                error!("{}", message);
                if let Some(sender) = ready_tx.take() {
                    let _ = sender.send(Err(message));
                }
                return;
            }

            let mut attrs = vec![REPLICATION_STREAM_ATTRIBUTE.to_string()];
            if let Some(cookie) = cookie {
                attrs.push(format!("{}{}", REPLICATION_COOKIE_ATTRIBUTE_PREFIX, cookie));
            }

            let mut search = match ldap
                .streaming_search(&base_dn, ldap3::Scope::Base, "(objectClass=*)", attrs)
                .await
            {
                Ok(search) => search,
                Err(e) => {
                    let message = format!("Failed to start LDAP replication stream: {}", e);
                    *last_error.lock().unwrap() = Some(message.clone());
                    error!("{}", message);
                    if let Some(sender) = ready_tx.take() {
                        let _ = sender.send(Err(message));
                    }
                    return;
                }
            };

            *listening.lock().unwrap() = true;
            if let Some(sender) = ready_tx.take() {
                let _ = sender.send(Ok(()));
            }

            loop {
                if !*listening.lock().unwrap() {
                    break;
                }

                match search.next().await {
                    Ok(Some(entry)) => match parse_replication_stream_entry(&ldap3::SearchEntry::construct(entry)) {
                        Ok(change) => {
                            if change_tx.send(change).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            stats.lock().unwrap().record_error();
                            warn!("Skipping invalid replication stream entry: {}", e);
                        }
                    },
                    Ok(None) => break,
                    Err(e) => {
                        stats.lock().unwrap().record_error();
                        let message = format!("LDAP replication stream ended with error: {}", e);
                        *last_error.lock().unwrap() = Some(message.clone());
                        warn!("{}", message);
                        break;
                    }
                }
            }

            *listening.lock().unwrap() = false;
            if last_error.lock().unwrap().is_none() {
                *last_error.lock().unwrap() = Some("LDAP replication stream ended".to_string());
            }
            let _ = search.finish().await;
            let _ = ldap.unbind().await;
        });

        *self.task_handle.lock().unwrap() = Some(handle);
        match tokio::time::timeout(std::time::Duration::from_secs(5), ready_rx).await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(message))) => Err(ConsumerError::ListeningError { message }),
            Ok(Err(_)) => Err(ConsumerError::ListeningError {
                message: "LDAP change listener startup channel closed".to_string(),
            }),
            Err(_) => Err(ConsumerError::ListeningError {
                message: "Timed out waiting for LDAP change listener startup".to_string(),
            }),
        }
    }

    async fn receive_change(&self) -> Result<Option<Vec<u8>>, ConsumerError> {
        if let Some(message) = self.last_error.lock().unwrap().take() {
            return Err(ConsumerError::ListeningError { message });
        }

        if !*self.listening.lock().unwrap() {
            return Ok(None);
        }

        let mut receiver = self.change_rx.lock().await;
        let received =
            tokio::time::timeout(std::time::Duration::from_millis(250), receiver.recv()).await;

        if let Some(message) = self.last_error.lock().unwrap().take() {
            return Err(ConsumerError::ListeningError { message });
        }

        match received {
            Ok(Some(change)) => {
                self.stats.lock().unwrap().record_change(change.len());
                Ok(Some(change))
            }
            Ok(None) => Err(ConsumerError::ListeningError {
                message: "LDAP replication stream closed".to_string(),
            }),
            Err(_) => Ok(None),
        }
    }

    async fn stop_listening(&self) -> Result<(), ConsumerError> {
        *self.listening.lock().unwrap() = false;
        *self.last_error.lock().unwrap() = None;
        if let Some(handle) = self.task_handle.lock().unwrap().take() {
            handle.abort();
        }
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
    use std::collections::HashMap;
    use tokio::sync::broadcast;

    #[test]
    fn test_changelog_tracker_basic() {
        let tracker = ChangelogTracker::new();

        // Record some changes
        let csn1 = tracker.record_change(
            ChangeType::Add,
            "cn=user1,dc=example,dc=org".to_string(),
            b"data1".to_vec(),
        );

        let csn2 = tracker.record_change(
            ChangeType::Modify,
            "cn=user2,dc=example,dc=org".to_string(),
            b"data2".to_vec(),
        );

        // Get all changes
        let changes = tracker.get_all();
        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].csn, csn1);
        assert_eq!(changes[1].csn, csn2);

        // Verify CSNs are ordered
        assert!(csn2 > csn1);
    }

    #[test]
    fn test_changelog_tracker_cookie() {
        let tracker = ChangelogTracker::new();

        // Record a change to get a CSN
        let csn = tracker.record_change(
            ChangeType::Add,
            "cn=user1,dc=example,dc=org".to_string(),
            b"data1".to_vec(),
        );

        // Generate cookie from CSN
        let cookie = tracker.generate_cookie_from_csn(&csn);
        assert!(cookie.starts_with("csn-"));

        // Parse cookie
        let parsed_csn = tracker.parse_cookie(&cookie);
        assert_eq!(parsed_csn, Some(csn));

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
        let all_changes = tracker.get_all();
        assert!(all_changes.len() <= 5);

        // Latest entry should still be there (check contextCSN exists)
        assert!(tracker.get_context_csn().is_some());
    }

    #[test]
    fn test_parse_replication_stream_entry_round_trip() {
        let change = ChangelogEntry::new(
            crate::csn::CsnGenerator::new(7).generate(),
            ChangeType::Modify,
            "cn=stream-user,dc=example,dc=org".to_string(),
            br#"{"op":"modify"}"#.to_vec(),
        );

        let attrs = changelog_entry_to_replication_attrs(&change)
            .into_iter()
            .map(|(name, values)| (name.to_lowercase(), values))
            .collect::<HashMap<_, _>>();
        let entry = ldap3::SearchEntry {
            dn: change.dn.clone(),
            attrs,
            bin_attrs: HashMap::new(),
        };

        let encoded = parse_replication_stream_entry(&entry).unwrap();

        assert_eq!(
            encoded,
            encode_change_bytes(&change.change_type, &change.dn, &change.change_data)
        );
    }

    #[test]
    fn test_parse_replication_stream_entry_preserves_mixed_case_attrs() {
        let change = ChangelogEntry::new(
            crate::csn::CsnGenerator::new(9).generate(),
            ChangeType::Add,
            "cn=case-user,dc=example,dc=org".to_string(),
            br#"{"op":"add"}"#.to_vec(),
        );

        let attrs = changelog_entry_to_replication_attrs(&change)
            .into_iter()
            .collect::<HashMap<_, _>>();
        let entry = ldap3::SearchEntry {
            dn: change.dn.clone(),
            attrs,
            bin_attrs: HashMap::new(),
        };

        let encoded = parse_replication_stream_entry(&entry).unwrap();

        assert_eq!(
            encoded,
            encode_change_bytes(&change.change_type, &change.dn, &change.change_data)
        );
    }

    #[tokio::test]
    async fn test_broadcast_change_listener_yields_encoded_changes() {
        let (sender, receiver) = broadcast::channel(8);
        let listener = BroadcastChangeListener::new(receiver);
        let change = ChangelogEntry::new(
            crate::csn::CsnGenerator::new(3).generate(),
            ChangeType::Add,
            "cn=live-user,dc=example,dc=org".to_string(),
            br#"{"dn":"cn=live-user,dc=example,dc=org"}"#.to_vec(),
        );

        listener
            .start_listening(Some("csn-previous-cookie"))
            .await
            .unwrap();
        sender.send(change.clone()).unwrap();

        let encoded = listener.receive_change().await.unwrap().unwrap();
        let stats = listener.get_listening_stats().await.unwrap();

        assert_eq!(
            encoded,
            encode_change_bytes(&change.change_type, &change.dn, &change.change_data)
        );
        assert_eq!(stats.changes_received, 1);
        assert!(stats.bytes_received >= change.change_data.len());
    }
}

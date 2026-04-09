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
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
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
    entries: Arc<Mutex<BTreeMap<String, ChangelogEntry>>>,
    /// Maximum entries to keep in memory
    max_entries: usize,
    /// Most recent CSN (for contextCSN)
    latest_csn: Arc<Mutex<Option<Csn>>>,
    /// Optional directory used for durable changelog persistence
    storage_dir: Option<PathBuf>,
}

const PROVIDER_CHANGELOG_FILE: &str = "provider_changelog.json";

#[derive(Debug, Serialize, Deserialize)]
struct PersistedChangelogSnapshot {
    entries: Vec<PersistedChangelogEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedChangelogEntry {
    csn: Csn,
    change_type: ChangeType,
    dn: String,
    change_data: Vec<u8>,
    originator: Option<String>,
}

impl From<&ChangelogEntry> for PersistedChangelogEntry {
    fn from(entry: &ChangelogEntry) -> Self {
        Self {
            csn: entry.csn.clone(),
            change_type: entry.change_type.clone(),
            dn: entry.dn.clone(),
            change_data: entry.change_data.clone(),
            originator: entry.originator.clone(),
        }
    }
}

impl PersistedChangelogEntry {
    fn into_runtime(self) -> ChangelogEntry {
        let mut entry = ChangelogEntry::new(self.csn, self.change_type, self.dn, self.change_data);
        entry.originator = self.originator;
        entry
    }
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
        Self::new_with_storage(max_entries, replica_id, None)
    }

    /// Create a changelog tracker backed by durable storage in the given directory.
    pub fn with_capacity_replica_and_storage(
        max_entries: usize,
        replica_id: u16,
        storage_dir: impl Into<PathBuf>,
    ) -> Self {
        Self::new_with_storage(max_entries, replica_id, Some(storage_dir.into()))
    }

    fn new_with_storage(max_entries: usize, replica_id: u16, storage_dir: Option<PathBuf>) -> Self {
        let tracker = Self {
            csn_generator: Arc::new(CsnGenerator::new(replica_id)),
            entries: Arc::new(Mutex::new(BTreeMap::new())),
            max_entries,
            latest_csn: Arc::new(Mutex::new(None)),
            storage_dir,
        };
        tracker.load_persisted_snapshot();
        tracker
    }

    fn snapshot_path(&self) -> Option<PathBuf> {
        self.storage_dir
            .as_ref()
            .map(|dir| dir.join(PROVIDER_CHANGELOG_FILE))
    }

    fn load_persisted_snapshot(&self) {
        let Some(path) = self.snapshot_path() else {
            return;
        };

        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return,
            Err(err) => {
                warn!(
                    "Failed to read persisted changelog {}: {}",
                    path.display(),
                    err
                );
                return;
            }
        };

        let snapshot = match serde_json::from_slice::<PersistedChangelogSnapshot>(&bytes) {
            Ok(snapshot) => snapshot,
            Err(err) => {
                warn!(
                    "Failed to deserialize persisted changelog {}: {}",
                    path.display(),
                    err
                );
                return;
            }
        };

        let retained_entries = if snapshot.entries.len() > self.max_entries {
            snapshot
                .entries
                .into_iter()
                .rev()
                .take(self.max_entries)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
        } else {
            snapshot.entries
        };

        let latest_csn = retained_entries.last().map(|entry| entry.csn.clone());
        let mut entries = self.entries.lock().unwrap();
        entries.clear();
        for entry in retained_entries {
            let runtime_entry = entry.into_runtime();
            entries.insert(runtime_entry.csn.to_string(), runtime_entry);
        }
        drop(entries);
        *self.latest_csn.lock().unwrap() = latest_csn;
    }

    fn persist_snapshot(&self) -> Result<(), std::io::Error> {
        let Some(path) = self.snapshot_path() else {
            return Ok(());
        };

        let snapshot = {
            let mut entries: Vec<_> = self.entries.lock().unwrap().values().cloned().collect();
            entries.sort_by(|a, b| a.csn.cmp(&b.csn));
            PersistedChangelogSnapshot {
                entries: entries.iter().map(PersistedChangelogEntry::from).collect(),
            }
        };

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let temp_path = path.with_extension("tmp");
        let payload = serde_json::to_vec_pretty(&snapshot).map_err(std::io::Error::other)?;
        std::fs::write(&temp_path, payload)?;
        std::fs::rename(&temp_path, &path)?;
        Ok(())
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
        self.record_change_with_originator(change_type, dn, change_data, None)
    }

    pub fn record_change_with_originator(
        &self,
        change_type: ChangeType,
        dn: String,
        change_data: Vec<u8>,
        originator: Option<String>,
    ) -> Csn {
        // Generate new CSN for this change
        let csn = self.csn_generator.generate();
        let csn_str = csn.to_string();

        let mut entry = ChangelogEntry::new(csn.clone(), change_type, dn, change_data);
        if let Some(originator) = originator {
            entry = entry.with_originator(originator);
        }

        let mut entries = self.entries.lock().unwrap();
        entries.insert(csn_str, entry);

        // Update latest CSN
        let mut latest = self.latest_csn.lock().unwrap();
        *latest = Some(csn.clone());

        // Prune old entries if we exceed max_entries
        while entries.len() > self.max_entries {
            let Some(oldest_csn) = entries.keys().next().cloned() else {
                break;
            };
            entries.remove(&oldest_csn);
        }
        drop(latest);
        drop(entries);

        if let Err(err) = self.persist_snapshot() {
            warn!("Failed to persist provider changelog: {}", err);
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
        self.get_since_csn_batch(csn, 0, usize::MAX)
    }

    /// Get all entries (for full refresh)
    pub fn get_all(&self) -> Vec<ChangelogEntry> {
        self.get_all_batch(0, usize::MAX)
    }

    /// Get a bounded page of changelog entries after a CSN.
    pub fn get_since_csn_batch(
        &self,
        csn: &Csn,
        offset: usize,
        limit: usize,
    ) -> Vec<ChangelogEntry> {
        if limit == 0 {
            return Vec::new();
        }

        self.entries
            .lock()
            .unwrap()
            .values()
            .filter(|entry| entry.csn > *csn)
            .skip(offset)
            .take(limit)
            .cloned()
            .collect()
    }

    /// Count retained changelog entries after a CSN.
    pub fn count_since_csn(&self, csn: &Csn) -> usize {
        self.entries
            .lock()
            .unwrap()
            .values()
            .filter(|entry| entry.csn > *csn)
            .count()
    }

    /// Get a bounded page of retained changelog entries.
    pub fn get_all_batch(&self, offset: usize, limit: usize) -> Vec<ChangelogEntry> {
        if limit == 0 {
            return Vec::new();
        }

        self.entries
            .lock()
            .unwrap()
            .values()
            .skip(offset)
            .take(limit)
            .cloned()
            .collect()
    }

    /// Count retained changelog entries.
    pub fn count_all(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    /// Get current contextCSN (latest CSN)
    pub fn get_context_csn(&self) -> Option<Csn> {
        self.latest_csn.lock().unwrap().clone()
    }

    /// Get the oldest retained CSN in the current changelog window.
    pub fn get_oldest_csn(&self) -> Option<Csn> {
        self.entries
            .lock()
            .unwrap()
            .values()
            .map(|entry| entry.csn.clone())
            .min()
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

    fn classify_cookie(&self, cookie: &str) -> ChangelogCookieStatus {
        if cookie == "csn-empty" {
            return ChangelogCookieStatus::Valid(None);
        }

        let Some(csn) = self.parse_cookie(cookie) else {
            return ChangelogCookieStatus::Invalid;
        };

        let Some(latest_csn) = self.get_context_csn() else {
            return ChangelogCookieStatus::Valid(Some(csn));
        };

        if let Some(oldest_csn) = self.get_oldest_csn() {
            if csn < oldest_csn {
                return ChangelogCookieStatus::Stale;
            }
        }

        if csn > latest_csn {
            return ChangelogCookieStatus::Invalid;
        }

        ChangelogCookieStatus::Valid(Some(csn))
    }
}

impl Default for ChangelogTracker {
    fn default() -> Self {
        Self::new()
    }
}

enum ChangelogCookieStatus {
    Valid(Option<Csn>),
    Stale,
    Invalid,
}

pub const REPLICATION_STREAM_ATTRIBUTE: &str = "opendrReplicationStream";
pub const REPLICATION_COOKIE_ATTRIBUTE_PREFIX: &str = "opendrReplicationCookie=";
pub const REPLICATION_EVENT_OBJECT_CLASS: &str = "opendrReplicationEvent";
pub const REPLICATION_CHANGE_TYPE_ATTRIBUTE: &str = "opendrChangeType";
pub const REPLICATION_CHANGE_DATA_ATTRIBUTE: &str = "opendrChangeData";
pub const REPLICATION_CSN_ATTRIBUTE: &str = "opendrChangeCsn";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RenameChange {
    pub new_rdn: String,
    pub delete_old: bool,
    pub new_superior: Option<String>,
    #[serde(default)]
    pub actor_dn: Option<String>,
}

#[cfg(test)]
pub(crate) fn encode_rename_change(
    new_rdn: &str,
    delete_old: bool,
    new_superior: Option<&str>,
) -> Vec<u8> {
    encode_rename_change_with_actor(new_rdn, delete_old, new_superior, None)
}

pub(crate) fn encode_rename_change_with_actor(
    new_rdn: &str,
    delete_old: bool,
    new_superior: Option<&str>,
    actor_dn: Option<&str>,
) -> Vec<u8> {
    serde_json::to_vec(&RenameChange {
        new_rdn: new_rdn.to_string(),
        delete_old,
        new_superior: new_superior.map(str::to_string),
        actor_dn: actor_dn.map(str::to_string),
    })
    .unwrap_or_default()
}

fn decode_rename_change(change_data: &[u8]) -> Result<RenameChange, ConsumerError> {
    serde_json::from_slice(change_data).map_err(|e| ConsumerError::ProcessingError {
        message: format!("Invalid rename change payload: {}", e),
    })
}

fn replicated_password(entry: &crate::backend::DirectoryEntry) -> Vec<u8> {
    entry
        .attributes
        .get("userpassword")
        .and_then(|values| values.first())
        .map(|value| value.as_bytes().to_vec())
        .unwrap_or_default()
}

fn replication_entries_match(
    existing: &crate::backend::DirectoryEntry,
    desired: &crate::backend::DirectoryEntry,
) -> bool {
    existing.dn == desired.dn && existing.attributes == desired.attributes
}

fn replication_target_dn(dn: &str, new_rdn: &str, new_superior: Option<&str>) -> String {
    if let Some(superior) = new_superior {
        format!("{new_rdn},{superior}")
    } else if let Some((_, rest)) = dn.split_once(',') {
        format!("{new_rdn},{rest}")
    } else {
        new_rdn.to_string()
    }
}

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

pub fn changelog_entry_to_replication_attrs(entry: &ChangelogEntry) -> Vec<(String, Vec<String>)> {
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

pub fn parse_replication_stream_entry(
    entry: &ldap3::SearchEntry,
) -> Result<Vec<u8>, ConsumerError> {
    let find_attr = |name: &str| {
        entry.attrs.iter().find_map(|(key, values)| {
            if key.eq_ignore_ascii_case(name) {
                values.first()
            } else {
                None
            }
        })
    };

    let change_type = find_attr(REPLICATION_CHANGE_TYPE_ATTRIBUTE).ok_or_else(|| {
        ConsumerError::ListeningError {
            message: "Replication stream entry missing change type".to_string(),
        }
    })?;

    let encoded_change = find_attr(REPLICATION_CHANGE_DATA_ATTRIBUTE).ok_or_else(|| {
        ConsumerError::ListeningError {
            message: "Replication stream entry missing change payload".to_string(),
        }
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
            match self.tracker.classify_cookie(cookie_str) {
                ChangelogCookieStatus::Valid(None) => self.tracker.get_all(),
                ChangelogCookieStatus::Valid(Some(csn)) => self.tracker.get_since_csn(&csn),
                ChangelogCookieStatus::Stale => {
                    return Err(format!("Stale replication cookie: {}", cookie_str));
                }
                ChangelogCookieStatus::Invalid => {
                    return Err(format!("Invalid replication cookie: {}", cookie_str));
                }
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

    async fn count_all_entries(
        &self,
        base_dn: &str,
        _filter: Option<&str>,
    ) -> Result<usize, String> {
        use ldap_parser::ldap::SearchScope;
        self.backend
            .count_entries(base_dn, SearchScope(2))
            .await
            .map_err(|e| format!("Backend search failed: {:?}", e))
    }

    async fn get_all_entries_batch(
        &self,
        base_dn: &str,
        _filter: Option<&str>,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<DirectoryEntry>, String> {
        use ldap_parser::ldap::SearchScope;
        let backend_entries = self
            .backend
            .search_entries_paginated(base_dn, SearchScope(2), offset, limit)
            .await
            .map_err(|e| format!("Backend search failed: {:?}", e))?;

        Ok(backend_entries
            .into_iter()
            .map(|entry| DirectoryEntry::new(entry.dn, entry.attributes))
            .collect())
    }

    async fn count_changelog_since(&self, cookie: Option<&str>) -> Result<usize, String> {
        let count = if let Some(cookie_str) = cookie {
            match self.tracker.classify_cookie(cookie_str) {
                ChangelogCookieStatus::Valid(None) => self.tracker.count_all(),
                ChangelogCookieStatus::Valid(Some(csn)) => self.tracker.count_since_csn(&csn),
                ChangelogCookieStatus::Stale => {
                    return Err(format!("Stale replication cookie: {}", cookie_str));
                }
                ChangelogCookieStatus::Invalid => {
                    return Err(format!("Invalid replication cookie: {}", cookie_str));
                }
            }
        } else {
            self.tracker.count_all()
        };

        Ok(count)
    }

    async fn get_changelog_batch(
        &self,
        cookie: Option<&str>,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<ChangelogEntry>, String> {
        let entries = if let Some(cookie_str) = cookie {
            match self.tracker.classify_cookie(cookie_str) {
                ChangelogCookieStatus::Valid(None) => self.tracker.get_all_batch(offset, limit),
                ChangelogCookieStatus::Valid(Some(csn)) => {
                    self.tracker.get_since_csn_batch(&csn, offset, limit)
                }
                ChangelogCookieStatus::Stale => {
                    return Err(format!("Stale replication cookie: {}", cookie_str));
                }
                ChangelogCookieStatus::Invalid => {
                    return Err(format!("Invalid replication cookie: {}", cookie_str));
                }
            }
        } else {
            self.tracker.get_all_batch(offset, limit)
        };

        Ok(entries)
    }

    async fn generate_cookie(&self, last_csn: &Csn) -> Result<String, String> {
        Ok(self.tracker.generate_cookie_from_csn(last_csn))
    }

    async fn get_context_csn(&self) -> Result<Option<Csn>, String> {
        Ok(self.tracker.get_context_csn())
    }

    async fn validate_cookie(&self, cookie: &str) -> Result<bool, String> {
        match self.tracker.classify_cookie(cookie) {
            ChangelogCookieStatus::Valid(_) => Ok(true),
            ChangelogCookieStatus::Stale => Err(format!("Stale replication cookie: {}", cookie)),
            ChangelogCookieStatus::Invalid => Ok(false),
        }
    }
}

/// Simple in-memory consumer registry
pub struct ConsumerRegistryImpl {
    consumers: Arc<Mutex<HashMap<String, ConsumerConnection>>>,
}

impl Default for ConsumerRegistryImpl {
    fn default() -> Self {
        Self::new()
    }
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

impl Default for StreamingManagerImpl {
    fn default() -> Self {
        Self::new()
    }
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

impl Default for SyncRequestHandlerImpl {
    fn default() -> Self {
        Self::new()
    }
}

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

    fn include_refresh_entry(&self, entry: &DirectoryEntry) -> bool {
        entry.dn != self.base_dn && !entry.dn.starts_with("ou=")
    }

    async fn request_local_refresh_batch(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<Vec<u8>>, ConsumerError> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let mut raw_offset = 0usize;
        let mut filtered_offset = 0usize;
        let mut encoded_entries = Vec::with_capacity(limit);

        while encoded_entries.len() < limit {
            let remaining = limit - encoded_entries.len();
            let batch = self
                .changelog_provider
                .get_all_entries_batch(&self.base_dn, None, raw_offset, limit.max(remaining))
                .await
                .map_err(|message| ConsumerError::ConnectionError { message })?;

            if batch.is_empty() {
                break;
            }

            raw_offset += batch.len();
            let batch_len = batch.len();
            for entry in batch {
                if !self.include_refresh_entry(&entry) {
                    continue;
                }

                if filtered_offset < offset {
                    filtered_offset += 1;
                    continue;
                }

                let backend_entry = crate::backend::DirectoryEntry {
                    dn: entry.dn,
                    attributes: entry.attributes,
                    operational_attributes: crate::backend::OperationalAttributes::new(),
                };
                if let Some(encoded) = encode_directory_entry_as_change(backend_entry) {
                    encoded_entries.push(encoded);
                }
                if encoded_entries.len() == limit {
                    break;
                }
            }

            if batch_len < limit.max(remaining) {
                break;
            }
        }

        Ok(encoded_entries)
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
            cookie_str
                .strip_prefix("csn-")
                .map(|csn_str| csn_str.to_string())
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
                    if let Some(entry_csn_values) = search_entry
                        .attrs
                        .get("entryCSN")
                        .or_else(|| search_entry.attrs.get("entrycsn"))
                    {
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

    async fn request_batch_from_cookie(
        &self,
        cookie: Option<&str>,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<Vec<u8>>, ConsumerError> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let has_ldap = self.ldap_connection.lock().unwrap().is_some();
        if !has_ldap {
            if cookie.is_none() || matches!(cookie, Some("csn-empty")) {
                return self.request_local_refresh_batch(offset, limit).await;
            }

            let entries = self
                .changelog_provider
                .get_changelog_batch(cookie, offset, limit)
                .await
                .map_err(|message| ConsumerError::ConnectionError { message })?;

            return Ok(entries
                .iter()
                .map(|entry| encode_change_bytes(&entry.change_type, &entry.dn, &entry.change_data))
                .collect());
        }

        Ok(self
            .request_from_cookie(cookie)
            .await?
            .into_iter()
            .skip(offset)
            .take(limit)
            .collect())
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
        use log::info;

        match change_type_str {
            "add" => {
                let entry_json = std::str::from_utf8(change_data).map_err(|e| {
                    ConsumerError::ProcessingError {
                        message: format!("Invalid UTF-8 in entry data for {dn}: {e}"),
                    }
                })?;
                let dir_entry = serde_json::from_str::<crate::backend::DirectoryEntry>(entry_json)
                    .map_err(|e| ConsumerError::ProcessingError {
                        message: format!("Failed to deserialize entry data for {dn}: {e}"),
                    })?;
                let password = replicated_password(&dir_entry);
                match self
                    .backend
                    .add_entry_with_actor(
                        dir_entry.clone(),
                        password,
                        dir_entry.operational_attributes.creators_name.clone(),
                    )
                    .await
                {
                    Ok(_) => {
                        info!("Replicated ADD: {}", dn);
                    }
                    Err(crate::backend::BackendError::AlreadyExists) => {
                        let existing = self.backend.get_entry(dn).await.map_err(|e| {
                            ConsumerError::ProcessingError {
                                message: format!(
                                    "Failed to verify existing ADD target for {dn}: {e}"
                                ),
                            }
                        })?;
                        match existing {
                            Some(existing_entry)
                                if replication_entries_match(&existing_entry, &dir_entry) =>
                            {
                                info!("Replicated ADD already applied: {}", dn);
                            }
                            Some(_) => {
                                return Err(ConsumerError::ProcessingError {
                                    message: format!(
                                        "Conflicting entry already exists while replaying ADD for {dn}"
                                    ),
                                });
                            }
                            None => {
                                return Err(ConsumerError::ProcessingError {
                                    message: format!(
                                        "Backend reported existing ADD target for {dn}, but no entry was found"
                                    ),
                                });
                            }
                        }
                    }
                    Err(e) => {
                        return Err(ConsumerError::ProcessingError {
                            message: format!("Failed to replicate ADD for {dn}: {e}"),
                        });
                    }
                }
            }
            "modify" => {
                let entry_json = std::str::from_utf8(change_data).map_err(|e| {
                    ConsumerError::ProcessingError {
                        message: format!("Invalid UTF-8 in modify data for {dn}: {e}"),
                    }
                })?;
                let dir_entry = serde_json::from_str::<crate::backend::DirectoryEntry>(entry_json)
                    .map_err(|e| ConsumerError::ProcessingError {
                        message: format!("Failed to deserialize modify data for {dn}: {e}"),
                    })?;
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

                match self
                    .backend
                    .modify_entry_with_actor(
                        dn,
                        modifications,
                        dir_entry.operational_attributes.modifiers_name.clone(),
                    )
                    .await
                {
                    Ok(_) => {
                        info!("Replicated MODIFY: {}", dn);
                    }
                    Err(e) => {
                        return Err(ConsumerError::ProcessingError {
                            message: format!("Failed to replicate MODIFY for {dn}: {e}"),
                        });
                    }
                }
            }
            "delete" => match self.backend.delete_entry(dn).await {
                Ok(_) => {
                    info!("Replicated DELETE: {}", dn);
                }
                Err(crate::backend::BackendError::NotFound) => {
                    info!("Replicated DELETE already applied: {}", dn);
                }
                Err(e) => {
                    return Err(ConsumerError::ProcessingError {
                        message: format!("Failed to replicate DELETE for {dn}: {e}"),
                    });
                }
            },
            "rename" => {
                let rename = decode_rename_change(change_data)?;
                let target_dn =
                    replication_target_dn(dn, &rename.new_rdn, rename.new_superior.as_deref());
                match self
                    .backend
                    .rename_entry_with_actor(
                        dn,
                        &rename.new_rdn,
                        rename.delete_old,
                        rename.new_superior.clone(),
                        rename.actor_dn.clone(),
                    )
                    .await
                {
                    Ok(_) => {
                        info!("Replicated RENAME: {}", dn);
                    }
                    Err(crate::backend::BackendError::NotFound)
                    | Err(crate::backend::BackendError::AlreadyExists) => {
                        let old_entry = self.backend.get_entry(dn).await.map_err(|e| {
                            ConsumerError::ProcessingError {
                                message: format!(
                                    "Failed to verify replayed RENAME source for {dn}: {e}"
                                ),
                            }
                        })?;
                        let new_entry = self.backend.get_entry(&target_dn).await.map_err(|e| {
                            ConsumerError::ProcessingError {
                                message: format!(
                                    "Failed to verify replayed RENAME target for {target_dn}: {e}"
                                ),
                            }
                        })?;
                        if old_entry.is_none() && new_entry.is_some() {
                            info!("Replicated RENAME already applied: {} -> {}", dn, target_dn);
                        } else {
                            return Err(ConsumerError::ProcessingError {
                                message: format!(
                                    "Failed to replicate RENAME for {dn}: target state does not match replay expectations"
                                ),
                            });
                        }
                    }
                    Err(e) => {
                        return Err(ConsumerError::ProcessingError {
                            message: format!("Failed to replicate RENAME for {dn}: {e}"),
                        });
                    }
                }
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

        *self.cookie.lock().unwrap() = Some(cookie.to_string());
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

impl Default for ChangeListenerImpl {
    fn default() -> Self {
        Self::new()
    }
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
                let encoded =
                    encode_change_bytes(&change.change_type, &change.dn, &change.change_data);
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
                    Ok(Some(entry)) => {
                        match parse_replication_stream_entry(&ldap3::SearchEntry::construct(entry))
                        {
                            Ok(change) => {
                                if change_tx.send(change).await.is_err() {
                                    break;
                                }
                            }
                            Err(e) => {
                                stats.lock().unwrap().record_error();
                                warn!("Skipping invalid replication stream entry: {}", e);
                            }
                        }
                    }
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
    use crate::backend::{
        BackendError, DirectoryBackend, DirectoryEntry, MockBackend, OperationalAttributes,
    };
    use ldap_parser::ldap::SearchScope;
    use std::collections::HashMap;
    use tokio::sync::broadcast;

    struct DeleteFailingBackend {
        inner: MockBackend,
        fail_dn: String,
    }

    #[async_trait]
    impl DirectoryBackend for DeleteFailingBackend {
        async fn authenticate(&self, dn: &str, password: &[u8]) -> Result<bool, BackendError> {
            self.inner.authenticate(dn, password).await
        }

        async fn get_entry(&self, dn: &str) -> Result<Option<DirectoryEntry>, BackendError> {
            self.inner.get_entry(dn).await
        }

        async fn add_entry(
            &self,
            entry: DirectoryEntry,
            password: Vec<u8>,
        ) -> Result<(), BackendError> {
            self.inner.add_entry(entry, password).await
        }

        async fn delete_entry(&self, dn: &str) -> Result<(), BackendError> {
            if dn == self.fail_dn {
                Err(BackendError::Storage("forced delete failure".to_string()))
            } else {
                self.inner.delete_entry(dn).await
            }
        }

        async fn modify_entry(
            &self,
            dn: &str,
            modifications: Vec<crate::backend::Modification>,
        ) -> Result<(), BackendError> {
            self.inner.modify_entry(dn, modifications).await
        }

        async fn compare_attribute(
            &self,
            dn: &str,
            attribute: &str,
            value: &str,
        ) -> Result<bool, BackendError> {
            self.inner.compare_attribute(dn, attribute, value).await
        }

        async fn rename_entry(
            &self,
            dn: &str,
            new_rdn: &str,
            delete_old: bool,
            new_superior: Option<String>,
        ) -> Result<(), BackendError> {
            self.inner
                .rename_entry(dn, new_rdn, delete_old, new_superior)
                .await
        }

        async fn search_entries(
            &self,
            base_dn: &str,
            scope: SearchScope,
        ) -> Result<Vec<DirectoryEntry>, BackendError> {
            self.inner.search_entries(base_dn, scope).await
        }

        async fn get_context_csn(&self) -> Result<Option<crate::csn::Csn>, BackendError> {
            self.inner.get_context_csn().await
        }

        async fn set_context_csn(&self, csn: crate::csn::Csn) -> Result<(), BackendError> {
            self.inner.set_context_csn(csn).await
        }
    }

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

    #[tokio::test]
    async fn test_batch_processor_add_already_applied_is_idempotent() {
        let backend = Arc::new(MockBackend::new());
        let batch_processor = BatchProcessorImpl::new(backend.clone());
        let entry = DirectoryEntry::new(
            "cn=user1,dc=example,dc=org",
            HashMap::from([
                ("cn".to_string(), vec!["user1".to_string()]),
                ("sn".to_string(), vec!["User".to_string()]),
            ]),
        );
        backend
            .add_entry(entry.clone(), b"secret".to_vec())
            .await
            .unwrap();

        let encoded = encode_change_bytes(
            &ChangeType::Add,
            &entry.dn,
            serde_json::to_vec(&entry).unwrap().as_slice(),
        );
        batch_processor.apply_entry(&encoded).await.unwrap();
    }

    #[tokio::test]
    async fn test_batch_processor_add_conflict_returns_error() {
        let backend = Arc::new(MockBackend::new());
        let batch_processor = BatchProcessorImpl::new(backend.clone());
        let existing = DirectoryEntry::new(
            "cn=user1,dc=example,dc=org",
            HashMap::from([("cn".to_string(), vec!["local".to_string()])]),
        );
        backend.add_entry(existing, Vec::new()).await.unwrap();

        let replicated = DirectoryEntry::new(
            "cn=user1,dc=example,dc=org",
            HashMap::from([("cn".to_string(), vec!["provider".to_string()])]),
        );
        let encoded = encode_change_bytes(
            &ChangeType::Add,
            &replicated.dn,
            serde_json::to_vec(&replicated).unwrap().as_slice(),
        );

        let err = batch_processor.apply_entry(&encoded).await.unwrap_err();
        assert!(matches!(err, ConsumerError::ProcessingError { .. }));
        assert_eq!(
            backend
                .get_entry("cn=user1,dc=example,dc=org")
                .await
                .unwrap()
                .unwrap()
                .attributes
                .get("cn"),
            Some(&vec!["local".to_string()])
        );
    }

    #[tokio::test]
    async fn test_batch_processor_add_replays_creator_metadata() {
        let backend = Arc::new(MockBackend::new());
        let batch_processor = BatchProcessorImpl::new(backend.clone());
        let creator = "cn=creator,dc=example,dc=org".to_string();
        let csn = crate::csn::CsnGenerator::new(11).generate();
        let replicated = DirectoryEntry::with_operational_attrs(
            "cn=user1,dc=example,dc=org",
            HashMap::from([
                ("cn".to_string(), vec!["user1".to_string()]),
                ("sn".to_string(), vec!["User".to_string()]),
            ]),
            OperationalAttributes::for_new_entry(csn, Some(creator.clone())),
        );
        let encoded = encode_change_bytes(
            &ChangeType::Add,
            &replicated.dn,
            serde_json::to_vec(&replicated).unwrap().as_slice(),
        );

        batch_processor.apply_entry(&encoded).await.unwrap();

        let stored = backend
            .get_entry("cn=user1,dc=example,dc=org")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.operational_attributes.creators_name,
            Some(creator.clone())
        );
        assert_eq!(stored.operational_attributes.modifiers_name, Some(creator));
    }

    #[tokio::test]
    async fn test_batch_processor_modify_replays_modifier_metadata() {
        let backend = Arc::new(MockBackend::new());
        let batch_processor = BatchProcessorImpl::new(backend.clone());
        let creator = "cn=creator,dc=example,dc=org".to_string();
        let modifier = "cn=modifier,dc=example,dc=org".to_string();
        backend
            .add_entry_with_actor(
                DirectoryEntry::new(
                    "cn=user1,dc=example,dc=org",
                    HashMap::from([
                        ("cn".to_string(), vec!["user1".to_string()]),
                        ("sn".to_string(), vec!["User".to_string()]),
                    ]),
                ),
                Vec::new(),
                Some(creator.clone()),
            )
            .await
            .unwrap();

        let updated = DirectoryEntry::with_operational_attrs(
            "cn=user1,dc=example,dc=org",
            HashMap::from([
                ("cn".to_string(), vec!["user1-updated".to_string()]),
                ("sn".to_string(), vec!["User".to_string()]),
            ]),
            OperationalAttributes {
                entry_csn: Some(crate::csn::CsnGenerator::new(12).generate()),
                create_timestamp: Some("20260409000000Z".to_string()),
                modify_timestamp: Some("20260409000001Z".to_string()),
                creators_name: Some(creator.clone()),
                modifiers_name: Some(modifier.clone()),
            },
        );
        let encoded = encode_change_bytes(
            &ChangeType::Modify,
            &updated.dn,
            serde_json::to_vec(&updated).unwrap().as_slice(),
        );

        batch_processor.apply_entry(&encoded).await.unwrap();

        let stored = backend
            .get_entry("cn=user1,dc=example,dc=org")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.operational_attributes.creators_name, Some(creator));
        assert_eq!(stored.operational_attributes.modifiers_name, Some(modifier));
    }

    #[tokio::test]
    async fn test_batch_processor_delete_missing_entry_is_idempotent() {
        let backend = Arc::new(MockBackend::new());
        let batch_processor = BatchProcessorImpl::new(backend);
        let encoded = encode_change_bytes(&ChangeType::Delete, "cn=missing,dc=example,dc=org", &[]);

        batch_processor.apply_entry(&encoded).await.unwrap();
    }

    #[tokio::test]
    async fn test_batch_processor_delete_backend_failure_returns_error() {
        let backend = Arc::new(DeleteFailingBackend {
            inner: MockBackend::new(),
            fail_dn: "cn=fail,dc=example,dc=org".to_string(),
        });
        backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=fail,dc=example,dc=org",
                    HashMap::from([("cn".to_string(), vec!["fail".to_string()])]),
                ),
                Vec::new(),
            )
            .await
            .unwrap();
        let batch_processor = BatchProcessorImpl::new(backend);
        let encoded = encode_change_bytes(&ChangeType::Delete, "cn=fail,dc=example,dc=org", &[]);

        let err = batch_processor.apply_entry(&encoded).await.unwrap_err();
        assert!(matches!(err, ConsumerError::ProcessingError { .. }));
    }

    #[tokio::test]
    async fn test_batch_processor_rename_already_applied_is_idempotent() {
        let backend = Arc::new(MockBackend::new());
        let batch_processor = BatchProcessorImpl::new(backend.clone());
        backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=renamed,dc=example,dc=org",
                    HashMap::from([("cn".to_string(), vec!["renamed".to_string()])]),
                ),
                Vec::new(),
            )
            .await
            .unwrap();

        let encoded = encode_change_bytes(
            &ChangeType::Rename,
            "cn=original,dc=example,dc=org",
            &encode_rename_change("cn=renamed", true, None),
        );

        batch_processor.apply_entry(&encoded).await.unwrap();
    }

    #[tokio::test]
    async fn test_batch_processor_rename_replays_modifier_metadata() {
        let backend = Arc::new(MockBackend::new());
        let batch_processor = BatchProcessorImpl::new(backend.clone());
        backend
            .add_entry_with_actor(
                DirectoryEntry::new(
                    "cn=original,dc=example,dc=org",
                    HashMap::from([("cn".to_string(), vec!["original".to_string()])]),
                ),
                Vec::new(),
                Some("cn=creator,dc=example,dc=org".to_string()),
            )
            .await
            .unwrap();

        let encoded = encode_change_bytes(
            &ChangeType::Rename,
            "cn=original,dc=example,dc=org",
            &encode_rename_change_with_actor(
                "cn=renamed",
                true,
                None,
                Some("cn=renamer,dc=example,dc=org"),
            ),
        );

        batch_processor.apply_entry(&encoded).await.unwrap();

        let stored = backend
            .get_entry("cn=renamed,dc=example,dc=org")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.operational_attributes.modifiers_name.as_deref(),
            Some("cn=renamer,dc=example,dc=org")
        );
        assert_eq!(
            stored.operational_attributes.creators_name.as_deref(),
            Some("cn=creator,dc=example,dc=org")
        );
    }

    #[tokio::test]
    async fn test_state_manager_save_cookie_failure_does_not_update_cache() {
        let tempdir = tempfile::tempdir().unwrap();
        let invalid_storage_path = tempdir.path().join("state-file");
        std::fs::write(&invalid_storage_path, "not-a-directory").unwrap();

        let manager = StateManagerImpl::new(invalid_storage_path.to_string_lossy().into_owned());
        let result = manager.save_cookie("csn-1").await;

        assert!(result.is_err());
        assert_eq!(*manager.cookie.lock().unwrap(), None);
    }
}

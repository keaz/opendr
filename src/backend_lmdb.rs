//! LMDB-Based Persistent Backend
//!
//! This module provides a high-performance, read-optimized persistent storage backend
//! using LMDB (Lightning Memory-Mapped Database). LMDB is chosen for its:
//! - Excellent read performance (memory-mapped files)
//! - ACID transactions
//! - Zero-copy reads
//! - Crash-proof design
//!
//! ## Design
//!
//! The backend uses multiple LMDB databases (tables):
//! - `entries`: DN → Entry data (primary storage)
//! - `passwords`: DN → Password hash (separate for security)
//! - `dn_index`: Normalized DN → Original DN (case-insensitive lookups)
//! - `attr_index_{name}`: Attribute value → DN (attribute indexing)
//!
//! ## Read Optimization
//!
//! - Memory-mapped I/O for zero-copy reads
//! - Multi-reader support (no blocking on reads)
//! - Cached read transactions
//! - Indexed attribute lookups
//! - DN normalization for fast case-insensitive searches

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::Engine;
use ldap_parser::ldap::SearchScope;
use lmdb::{Cursor, Database, Environment, Transaction, WriteFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use tokio::sync::RwLock;

use crate::backend::{
    BackendError, DirectoryBackend, DirectoryEntry, Modification, ModifyOperation,
    OperationalAttributes, SearchCandidateHint, SearchEntriesWithHintReport, SearchSubstringPart,
};
use crate::csn::{Csn, CsnGenerator};
use crate::metrics::MetricsCollector;
use crate::schema::{LdapSchema, ResolvedMatchingRule};

const LMDB_SET_RANGE_OP: u32 = 17;
const DEFAULT_ENTRY_CACHE_CAPACITY: usize = 1000;
const PRESENCE_INDEX_VALUE_SENTINEL: &str = "\0present";
const SUBSTRING_INDEX_KEY_PREFIX: &str = "\0sub\0";
const ORDERING_INDEX_KEY_PREFIX: &str = "\0ord\0";
const SUBSTRING_INDEX_TOKEN_LEN: usize = 3;
const SUBSTRING_QUERY_MAX_TOKENS: usize = 2;
const ATTRIBUTE_INDEX_VERSION: &[u8] = b"1";
const ATTRIBUTE_INDEX_CONFIG_METADATA_KEY: &str = "attribute_indexes_v1:configured";

/// Serialized entry structure for LMDB storage
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredEntry {
    /// Distinguished name
    pub dn: String,
    /// Entry attributes
    pub attributes: HashMap<String, Vec<String>>,
    /// Creation timestamp (Unix timestamp)
    pub created_at: u64,
    /// Last modification timestamp
    pub modified_at: u64,
    /// Operational attributes (entryCSN, timestamps, etc.)
    #[serde(default)]
    pub operational_attributes: crate::backend::OperationalAttributes,
}

#[derive(Debug, Clone, Deserialize)]
struct StoredEntryV1 {
    pub dn: String,
    pub attributes: HashMap<String, Vec<String>>,
    pub created_at: u64,
    pub modified_at: u64,
    #[serde(default)]
    pub operational_attributes: OperationalAttributesV1,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct OperationalAttributesV1 {
    pub entry_csn: Option<Csn>,
    pub entry_uuid: Option<String>,
    pub create_timestamp: Option<String>,
    pub modify_timestamp: Option<String>,
    pub creators_name: Option<String>,
    pub modifiers_name: Option<String>,
}

impl From<OperationalAttributesV1> for OperationalAttributes {
    fn from(value: OperationalAttributesV1) -> Self {
        Self {
            entry_csn: value.entry_csn,
            entry_uuid: value.entry_uuid,
            create_timestamp: value.create_timestamp,
            modify_timestamp: value.modify_timestamp,
            creators_name: value.creators_name,
            modifiers_name: value.modifiers_name,
            last_successful_login: None,
            last_failed_login: None,
            failed_login_count: None,
        }
    }
}

impl From<StoredEntryV1> for StoredEntry {
    fn from(value: StoredEntryV1) -> Self {
        Self {
            dn: value.dn,
            attributes: value.attributes,
            created_at: value.created_at,
            modified_at: value.modified_at,
            operational_attributes: value.operational_attributes.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryCacheStats {
    pub capacity: usize,
    pub len: usize,
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthCredentialCacheStats {
    pub capacity: usize,
    pub len: usize,
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
}

#[derive(Default)]
struct EntryCacheState {
    entries: HashMap<String, StoredEntry>,
    lru: VecDeque<String>,
}

struct EntryCache {
    capacity: usize,
    state: Mutex<EntryCacheState>,
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
}

impl EntryCache {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            state: Mutex::new(EntryCacheState::default()),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
        }
    }

    fn get(&self, normalized_dn: &str) -> Option<StoredEntry> {
        if self.capacity == 0 {
            self.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let entry = state.entries.get(normalized_dn).cloned();
        match entry {
            Some(entry) => {
                Self::touch_key(&mut state.lru, normalized_dn);
                self.hits.fetch_add(1, Ordering::Relaxed);
                Some(entry)
            }
            None => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    fn insert(&self, entry: StoredEntry) {
        if self.capacity == 0 {
            return;
        }

        let normalized_dn = entry.dn.to_lowercase().trim().to_string();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());

        if !state.entries.contains_key(&normalized_dn) && state.entries.len() == self.capacity {
            while let Some(oldest_key) = state.lru.pop_front() {
                if oldest_key == normalized_dn {
                    continue;
                }
                if state.entries.remove(&oldest_key).is_some() {
                    self.evictions.fetch_add(1, Ordering::Relaxed);
                    break;
                }
            }
        }

        state.entries.insert(normalized_dn.clone(), entry);
        Self::touch_key(&mut state.lru, &normalized_dn);
    }

    fn invalidate(&self, normalized_dn: &str) {
        if self.capacity == 0 {
            return;
        }

        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if state.entries.remove(normalized_dn).is_some() {
            Self::remove_key(&mut state.lru, normalized_dn);
        }
    }

    fn stats(&self) -> EntryCacheStats {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        EntryCacheStats {
            capacity: self.capacity,
            len: state.entries.len(),
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
        }
    }

    fn touch_key(lru: &mut VecDeque<String>, normalized_dn: &str) {
        Self::remove_key(lru, normalized_dn);
        lru.push_back(normalized_dn.to_string());
    }

    fn remove_key(lru: &mut VecDeque<String>, normalized_dn: &str) {
        if let Some(position) = lru.iter().position(|existing| existing == normalized_dn) {
            lru.remove(position);
        }
    }
}

#[derive(Debug)]
struct AuthCredentialRecord {
    hash: [u8; 64],
    salt: Vec<u8>,
}

#[derive(Default)]
struct AuthCredentialCacheShard {
    capacity: usize,
    records: HashMap<String, Arc<AuthCredentialRecord>>,
    lru: VecDeque<String>,
}

struct AuthCredentialCache {
    capacity: usize,
    shards: Vec<Mutex<AuthCredentialCacheShard>>,
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
}

impl AuthCredentialCache {
    const MAX_SHARDS: usize = 64;

    fn new(capacity: usize) -> Self {
        let shard_count = if capacity == 0 {
            1
        } else {
            capacity.min(Self::MAX_SHARDS)
        };
        let base_capacity = capacity / shard_count;
        let extra_capacity = capacity % shard_count;
        let mut shards = Vec::with_capacity(shard_count);

        for index in 0..shard_count {
            shards.push(Mutex::new(AuthCredentialCacheShard {
                capacity: base_capacity + usize::from(index < extra_capacity),
                ..AuthCredentialCacheShard::default()
            }));
        }

        Self {
            capacity,
            shards,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
        }
    }

    fn get(&self, normalized_dn: &str) -> Option<Arc<AuthCredentialRecord>> {
        if self.capacity == 0 {
            self.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        let mut shard = self.lock_shard(normalized_dn);
        let record = shard.records.get(normalized_dn).cloned();
        match record {
            Some(record) => {
                Self::touch_key(&mut shard.lru, normalized_dn);
                self.hits.fetch_add(1, Ordering::Relaxed);
                Some(record)
            }
            None => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    fn insert(&self, normalized_dn: &str, record: Arc<AuthCredentialRecord>) {
        if self.capacity == 0 {
            return;
        }

        let mut shard = self.lock_shard(normalized_dn);
        if shard.capacity == 0 {
            return;
        }

        if !shard.records.contains_key(normalized_dn) && shard.records.len() == shard.capacity {
            while let Some(oldest_key) = shard.lru.pop_front() {
                if oldest_key == normalized_dn {
                    continue;
                }
                if shard.records.remove(&oldest_key).is_some() {
                    self.evictions.fetch_add(1, Ordering::Relaxed);
                    break;
                }
            }
        }

        shard.records.insert(normalized_dn.to_string(), record);
        Self::touch_key(&mut shard.lru, normalized_dn);
    }

    fn invalidate(&self, normalized_dn: &str) {
        if self.capacity == 0 {
            return;
        }

        let mut shard = self.lock_shard(normalized_dn);
        if shard.records.remove(normalized_dn).is_some() {
            Self::remove_key(&mut shard.lru, normalized_dn);
        }
    }

    fn stats(&self) -> AuthCredentialCacheStats {
        let mut len = 0;
        for shard in &self.shards {
            len += shard
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .records
                .len();
        }

        AuthCredentialCacheStats {
            capacity: self.capacity,
            len,
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
        }
    }

    fn lock_shard(
        &self,
        normalized_dn: &str,
    ) -> std::sync::MutexGuard<'_, AuthCredentialCacheShard> {
        self.shards[self.shard_index(normalized_dn)]
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    fn shard_index(&self, normalized_dn: &str) -> usize {
        let mut hash = 0xcbf2_9ce4_8422_2325_u64;
        for byte in normalized_dn.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        (hash as usize) % self.shards.len()
    }

    fn touch_key(lru: &mut VecDeque<String>, normalized_dn: &str) {
        Self::remove_key(lru, normalized_dn);
        lru.push_back(normalized_dn.to_string());
    }

    fn remove_key(lru: &mut VecDeque<String>, normalized_dn: &str) {
        if let Some(position) = lru.iter().position(|existing| existing == normalized_dn) {
            lru.remove(position);
        }
    }
}

impl StoredEntry {
    fn to_directory_entry(&self) -> DirectoryEntry {
        let mut entry = DirectoryEntry::new(self.dn.clone(), self.attributes.clone());
        entry.operational_attributes = self.operational_attributes.clone();
        entry
    }
}

/// Configuration for indexed attributes
#[derive(Debug, Clone)]
pub struct IndexConfig {
    /// Legacy attributes that should get equality and presence indexes.
    pub indexed_attributes: Vec<String>,
    /// Typed attribute indexes. These are merged with `indexed_attributes`.
    pub attribute_indexes: Vec<AttributeIndexConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeIndexConfig {
    pub attribute: String,
    pub index_types: Vec<IndexType>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IndexType {
    Equality,
    Presence,
    Substring,
    Ordering,
}

impl IndexType {
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "equality" | "eq" => Some(Self::Equality),
            "presence" | "pres" => Some(Self::Presence),
            "substring" | "sub" => Some(Self::Substring),
            "ordering" | "ord" => Some(Self::Ordering),
            _ => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Equality => "equality",
            Self::Presence => "presence",
            Self::Substring => "substring",
            Self::Ordering => "ordering",
        }
    }
}

impl Default for IndexConfig {
    fn default() -> Self {
        Self {
            // Default indexed attributes for common LDAP operations
            indexed_attributes: vec![
                "cn".to_string(),
                "uid".to_string(),
                "mail".to_string(),
                "objectclass".to_string(),
                "ou".to_string(),
            ],
            attribute_indexes: Vec::new(),
        }
    }
}

impl IndexConfig {
    pub fn disabled() -> Self {
        Self {
            indexed_attributes: Vec::new(),
            attribute_indexes: Vec::new(),
        }
    }

    fn effective_index_types(&self) -> BTreeMap<String, BTreeSet<IndexType>> {
        let mut indexes = BTreeMap::new();

        for attribute in &self.indexed_attributes {
            let attribute = ldap_attribute_key(attribute).into_owned();
            if attribute.is_empty() {
                continue;
            }
            let index_types = indexes.entry(attribute).or_insert_with(BTreeSet::new);
            index_types.insert(IndexType::Equality);
            index_types.insert(IndexType::Presence);
        }

        for configured in &self.attribute_indexes {
            let attribute = ldap_attribute_key(&configured.attribute).into_owned();
            if attribute.is_empty() {
                continue;
            }
            let index_types = indexes.entry(attribute).or_insert_with(BTreeSet::new);
            for index_type in &configured.index_types {
                index_types.insert(*index_type);
            }
        }

        indexes.retain(|_, index_types| !index_types.is_empty());
        indexes
    }
}

#[derive(Debug, Clone)]
struct IndexPlan {
    attributes: BTreeMap<String, AttributeIndexPlan>,
}

#[derive(Debug, Clone)]
struct AttributeIndexPlan {
    attribute: String,
    index_types: BTreeSet<IndexType>,
    equality_rule: Option<ResolvedMatchingRule>,
    substring_rule: Option<ResolvedMatchingRule>,
    ordering_rule: Option<ResolvedMatchingRule>,
}

struct SubstringIndexCandidates {
    attribute: String,
    normalized_parts: Vec<SearchSubstringPart>,
    dns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeIndexReadiness {
    pub attribute: String,
    pub index_types: Vec<IndexType>,
    pub ready: bool,
}

impl IndexPlan {
    fn from_config(
        index_config: &IndexConfig,
        schema: Option<&LdapSchema>,
    ) -> Result<Self, BackendError> {
        if schema.is_none() {
            return Ok(Self::legacy_from_config(index_config));
        }

        let mut attributes = BTreeMap::new();

        for (attribute, index_types) in index_config.effective_index_types() {
            if let Some(schema) = schema
                && schema.get_attribute_type(&attribute).is_none()
            {
                return Err(BackendError::Storage(format!(
                    "invalid index plan for {}: attribute is not defined in schema",
                    attribute
                )));
            }
            let equality_rule = if index_types.contains(&IndexType::Equality) {
                Some(Self::resolve_index_rule(
                    schema,
                    &attribute,
                    IndexType::Equality,
                )?)
            } else {
                None
            };
            let substring_rule = if index_types.contains(&IndexType::Substring) {
                Some(Self::resolve_index_rule(
                    schema,
                    &attribute,
                    IndexType::Substring,
                )?)
            } else {
                None
            };
            let ordering_rule = if index_types.contains(&IndexType::Ordering) {
                Some(Self::resolve_index_rule(
                    schema,
                    &attribute,
                    IndexType::Ordering,
                )?)
            } else {
                None
            };

            attributes.insert(
                attribute.clone(),
                AttributeIndexPlan {
                    attribute,
                    index_types,
                    equality_rule,
                    substring_rule,
                    ordering_rule,
                },
            );
        }

        Ok(Self { attributes })
    }

    fn resolve_index_rule(
        schema: Option<&LdapSchema>,
        attribute: &str,
        index_type: IndexType,
    ) -> Result<ResolvedMatchingRule, BackendError> {
        let Some(schema) = schema else {
            return Err(BackendError::Storage(
                "schema is required to resolve matching-rule index plans".to_string(),
            ));
        };

        let rule = match index_type {
            IndexType::Equality => schema.equality_rule_for_attribute(attribute),
            IndexType::Substring => schema.substring_rule_for_attribute(attribute),
            IndexType::Ordering => schema.ordering_rule_for_attribute(attribute),
            IndexType::Presence => unreachable!("presence indexes do not use matching rules"),
        }
        .map_err(|err| {
            BackendError::Storage(format!(
                "invalid {} index plan for {}: {}",
                index_type.label(),
                attribute,
                err
            ))
        })?;

        if !rule.is_supported() {
            return Err(BackendError::Storage(format!(
                "unsupported matching rule {} for {} {} index",
                rule.primary_name,
                attribute,
                index_type.label()
            )));
        }

        Ok(rule)
    }

    fn legacy_from_config(index_config: &IndexConfig) -> Self {
        Self {
            attributes: index_config
                .effective_index_types()
                .into_iter()
                .map(|(attribute, index_types)| {
                    (
                        attribute.clone(),
                        AttributeIndexPlan {
                            attribute,
                            index_types,
                            equality_rule: None,
                            substring_rule: None,
                            ordering_rule: None,
                        },
                    )
                })
                .collect(),
        }
    }

    fn attribute_names(&self) -> impl Iterator<Item = &String> {
        self.attributes.keys()
    }

    fn attribute_plan(&self, attribute: &str) -> Option<&AttributeIndexPlan> {
        let attribute = ldap_attribute_key(attribute);
        self.attributes.get(attribute.as_ref())
    }

    fn attribute_plan_normalized(&self, attribute: &str) -> Option<&AttributeIndexPlan> {
        self.attributes.get(attribute)
    }

    fn has_index_type(&self, attribute: &str, index_type: IndexType) -> bool {
        self.attribute_plan(attribute)
            .is_some_and(|plan| plan.index_types.contains(&index_type))
    }

    fn config_value(&self) -> String {
        self.attributes
            .iter()
            .map(|(attribute, plan)| {
                let labels = plan
                    .index_types
                    .iter()
                    .map(|index_type| match index_type {
                        IndexType::Equality => format!(
                            "{}={}",
                            index_type.label(),
                            plan.equality_rule
                                .as_ref()
                                .map(|rule| rule.oid.as_str())
                                .unwrap_or("legacy")
                        ),
                        IndexType::Substring => format!(
                            "{}={}",
                            index_type.label(),
                            plan.substring_rule
                                .as_ref()
                                .map(|rule| rule.oid.as_str())
                                .unwrap_or("legacy")
                        ),
                        IndexType::Ordering => format!(
                            "{}={}",
                            index_type.label(),
                            plan.ordering_rule
                                .as_ref()
                                .map(|rule| rule.oid.as_str())
                                .unwrap_or("legacy")
                        ),
                        IndexType::Presence => index_type.label().to_string(),
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                format!("{attribute}:{labels}")
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl AttributeIndexPlan {
    fn normalize_equality_value(&self, value: &str) -> Result<String, BackendError> {
        normalize_index_value(self.equality_rule.as_ref(), value)
    }

    fn normalize_substring_value(&self, value: &str) -> Result<String, BackendError> {
        normalize_index_value(self.substring_rule.as_ref(), value)
    }

    fn normalize_ordering_value(&self, value: &str) -> Result<String, BackendError> {
        if let Some(rule) = self.ordering_rule.as_ref() {
            rule.ordering_key(value).map_err(|err| {
                BackendError::Storage(format!(
                    "invalid ordering index value for {}: {}",
                    self.attribute, err
                ))
            })
        } else {
            Ok(value.to_lowercase())
        }
    }
}

fn normalize_index_value(
    rule: Option<&ResolvedMatchingRule>,
    value: &str,
) -> Result<String, BackendError> {
    if let Some(rule) = rule {
        rule.normalize_value(value).map_err(|err| {
            BackendError::Storage(format!("invalid matching-rule index value: {}", err))
        })
    } else {
        Ok(value.to_lowercase())
    }
}

fn ldap_attribute_key(attribute: &str) -> Cow<'_, str> {
    if attribute.bytes().any(|byte| byte.is_ascii_uppercase()) {
        Cow::Owned(attribute.to_ascii_lowercase())
    } else {
        Cow::Borrowed(attribute)
    }
}

/// LMDB-based persistent backend optimized for read performance
pub struct LmdbBackend {
    /// LMDB environment
    env: Arc<Environment>,
    /// Main entries database
    entries_db: Database,
    /// Passwords database (separate for security)
    passwords_db: Database,
    /// DN index for case-insensitive lookups
    dn_index_db: Database,
    /// Metadata database (for contextCSN, etc.)
    metadata_db: Database,
    /// Attribute indexes: one database per indexed attribute
    attr_indexes: Arc<RwLock<HashMap<String, Database>>>,
    /// Effective schema-aware index plan.
    index_plan: IndexPlan,
    /// Lock for write operations (reads are lock-free in LMDB)
    write_lock: Arc<RwLock<()>>,
    /// Bounded cache for hot exact-DN reads.
    entry_cache: Arc<EntryCache>,
    /// Bounded cache for hot bind password hashes. Cleartext passwords and auth decisions are never cached.
    auth_cache: Arc<AuthCredentialCache>,
    /// Optional production metrics collector for auth-cache snapshots.
    metrics: Option<Arc<MetricsCollector>>,
    /// Database directory path
    _db_path: PathBuf,
    /// Configured maximum reader slots
    max_readers: u32,
    /// CSN generator for operational attributes
    csn_generator: Arc<CsnGenerator>,
}

impl LmdbBackend {
    /// Create a new LMDB backend with default index configuration
    ///
    /// # Arguments
    /// * `path` - Directory path for LMDB database files
    /// * `max_size_mb` - Maximum database size in megabytes
    /// * `replica_id` - Replica ID for CSN generation (1-4095)
    ///
    /// # Returns
    /// * `Result<Self, BackendError>` - New backend instance or error
    pub fn new<P: AsRef<Path>>(
        path: P,
        max_size_mb: usize,
        replica_id: u16,
    ) -> Result<Self, BackendError> {
        Self::new_with_runtime_config(path, max_size_mb, replica_id, IndexConfig::default(), 126)
    }

    /// Create a new LMDB backend with custom index configuration
    ///
    /// # Arguments
    /// * `path` - Directory path for LMDB database files
    /// * `max_size_mb` - Maximum database size in megabytes
    /// * `replica_id` - Replica ID for CSN generation (1-4095)
    /// * `index_config` - Configuration for attribute indexing
    ///
    /// # Returns
    /// * `Result<Self, BackendError>` - New backend instance or error
    pub fn new_with_config<P: AsRef<Path>>(
        path: P,
        max_size_mb: usize,
        replica_id: u16,
        index_config: IndexConfig,
    ) -> Result<Self, BackendError> {
        Self::new_with_runtime_config(path, max_size_mb, replica_id, index_config, 126)
    }

    pub fn new_with_schema_config<P: AsRef<Path>>(
        path: P,
        max_size_mb: usize,
        replica_id: u16,
        index_config: IndexConfig,
        schema: &LdapSchema,
    ) -> Result<Self, BackendError> {
        Self::new_with_runtime_and_cache_config_with_schema(
            path,
            max_size_mb,
            replica_id,
            index_config,
            126,
            DEFAULT_ENTRY_CACHE_CAPACITY,
            schema,
        )
    }

    pub fn new_with_runtime_config<P: AsRef<Path>>(
        path: P,
        max_size_mb: usize,
        replica_id: u16,
        index_config: IndexConfig,
        max_readers: u32,
    ) -> Result<Self, BackendError> {
        Self::new_with_runtime_and_cache_config(
            path,
            max_size_mb,
            replica_id,
            index_config,
            max_readers,
            DEFAULT_ENTRY_CACHE_CAPACITY,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_runtime_and_cache_config_with_schema<P: AsRef<Path>>(
        path: P,
        max_size_mb: usize,
        replica_id: u16,
        index_config: IndexConfig,
        max_readers: u32,
        entry_cache_capacity: usize,
        schema: &LdapSchema,
    ) -> Result<Self, BackendError> {
        Self::new_with_runtime_and_cache_config_internal(
            path,
            max_size_mb,
            replica_id,
            index_config,
            max_readers,
            entry_cache_capacity,
            Some(schema),
        )
    }

    pub fn new_with_runtime_and_cache_config<P: AsRef<Path>>(
        path: P,
        max_size_mb: usize,
        replica_id: u16,
        index_config: IndexConfig,
        max_readers: u32,
        entry_cache_capacity: usize,
    ) -> Result<Self, BackendError> {
        Self::new_with_runtime_and_cache_config_internal(
            path,
            max_size_mb,
            replica_id,
            index_config,
            max_readers,
            entry_cache_capacity,
            None,
        )
    }

    fn new_with_runtime_and_cache_config_internal<P: AsRef<Path>>(
        path: P,
        max_size_mb: usize,
        replica_id: u16,
        index_config: IndexConfig,
        max_readers: u32,
        entry_cache_capacity: usize,
        schema: Option<&LdapSchema>,
    ) -> Result<Self, BackendError> {
        let db_path = path.as_ref().to_path_buf();
        let index_plan = IndexPlan::from_config(&index_config, schema)?;

        // Create directory if it doesn't exist
        std::fs::create_dir_all(&db_path)
            .map_err(|e| BackendError::Storage(format!("Failed to create db directory: {}", e)))?;

        // Create LMDB environment with read-optimized settings
        // Increased max_dbs to accommodate attribute indexes
        let env = Environment::new()
            .set_max_dbs(50) // Increased for attribute indexes
            .set_map_size(max_size_mb * 1024 * 1024) // Set max size
            .set_max_readers(max_readers)
            .open(&db_path)
            .map_err(|e| BackendError::Storage(format!("Failed to open LMDB env: {}", e)))?;

        let env = Arc::new(env);

        // Create databases
        let entries_db = env
            .create_db(Some("entries"), lmdb::DatabaseFlags::empty())
            .map_err(|e| BackendError::Storage(format!("Failed to create entries db: {}", e)))?;

        let passwords_db = env
            .create_db(Some("passwords"), lmdb::DatabaseFlags::empty())
            .map_err(|e| BackendError::Storage(format!("Failed to create passwords db: {}", e)))?;

        let dn_index_db = env
            .create_db(Some("dn_index"), lmdb::DatabaseFlags::empty())
            .map_err(|e| BackendError::Storage(format!("Failed to create dn_index db: {}", e)))?;

        let metadata_db = env
            .create_db(Some("metadata"), lmdb::DatabaseFlags::empty())
            .map_err(|e| BackendError::Storage(format!("Failed to create metadata db: {}", e)))?;

        // Create attribute index databases.
        let mut attr_indexes = HashMap::new();
        for attr in index_plan.attribute_names() {
            let db_name = format!("idx_{}", attr);
            let db = env
                .create_db(Some(&db_name), lmdb::DatabaseFlags::empty())
                .map_err(|e| {
                    BackendError::Storage(format!("Failed to create index for {}: {}", attr, e))
                })?;
            attr_indexes.insert(attr.clone(), db);
        }

        Self::ensure_attribute_indexes_backfilled(
            &env,
            entries_db,
            metadata_db,
            &attr_indexes,
            &index_plan,
        )?;

        // Initialize CSN generator with replica ID
        let csn_generator = Arc::new(CsnGenerator::new(replica_id));

        Ok(Self {
            env,
            entries_db,
            passwords_db,
            dn_index_db,
            metadata_db,
            attr_indexes: Arc::new(RwLock::new(attr_indexes)),
            index_plan,
            write_lock: Arc::new(RwLock::new(())),
            entry_cache: Arc::new(EntryCache::new(entry_cache_capacity)),
            auth_cache: Arc::new(AuthCredentialCache::new(entry_cache_capacity)),
            metrics: None,
            _db_path: db_path,
            max_readers,
            csn_generator,
        })
    }

    async fn add_entry_internal(
        &self,
        mut entry: DirectoryEntry,
        password: Vec<u8>,
        actor_dn: Option<&str>,
    ) -> Result<(), BackendError> {
        let _lock = self.write_lock.write().await;

        let mut txn = self
            .env
            .begin_rw_txn()
            .map_err(|e| BackendError::Storage(format!("Failed to begin write txn: {}", e)))?;

        let normalized_dn = Self::normalize_dn(&entry.dn);

        if txn.get(self.dn_index_db, &normalized_dn.as_bytes()).is_ok() {
            return Err(BackendError::AlreadyExists);
        }

        let csn = self.csn_generator.generate();
        entry.operational_attributes = crate::backend::OperationalAttributes::for_new_entry(
            csn.clone(),
            actor_dn.map(str::to_string),
        );

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let stored_entry = StoredEntry {
            dn: entry.dn.clone(),
            attributes: entry.attributes,
            created_at: now,
            modified_at: now,
            operational_attributes: entry.operational_attributes.clone(),
        };

        let entry_bytes = bincode::serialize(&stored_entry)
            .map_err(|e| BackendError::Storage(format!("Failed to serialize entry: {}", e)))?;

        txn.put(
            self.entries_db,
            &entry.dn.as_bytes(),
            &entry_bytes,
            WriteFlags::empty(),
        )
        .map_err(|e| BackendError::Storage(format!("Failed to write entry: {}", e)))?;

        if let Some(password_hash) = Self::password_hash_from_bytes(&password) {
            txn.put(
                self.passwords_db,
                &entry.dn.as_bytes(),
                &password_hash.as_bytes(),
                WriteFlags::empty(),
            )
            .map_err(|e| BackendError::Storage(format!("Failed to write password: {}", e)))?;
        }

        txn.put(
            self.dn_index_db,
            &normalized_dn.as_bytes(),
            &entry.dn.as_bytes(),
            WriteFlags::empty(),
        )
        .map_err(|e| BackendError::Storage(format!("Failed to update DN index: {}", e)))?;

        self.update_attribute_indexes(&mut txn, &entry.dn, &stored_entry.attributes)?;

        let csn_string = csn.to_ldap_string();
        txn.put(
            self.metadata_db,
            &b"context_csn",
            &csn_string.as_bytes(),
            WriteFlags::empty(),
        )
        .map_err(|e| BackendError::Storage(format!("Failed to update contextCSN: {}", e)))?;

        txn.commit()
            .map_err(|e| BackendError::Storage(format!("Failed to commit txn: {}", e)))?;

        self.auth_cache.invalidate(&normalized_dn);
        self.record_auth_cache_metrics();
        Ok(())
    }

    /// Create an SSHA512 password hash suitable for direct storage in the password database.
    pub fn create_ssha512_password_hash(password: &[u8]) -> String {
        Self::create_ssha512(password)
    }

    /// Add many entries using batched LMDB write transactions.
    ///
    /// This is intended for offline fixture/import workflows. It preserves the same stored entry,
    /// DN index, password database, attribute-index, and contextCSN formats used by normal adds,
    /// while avoiding one LMDB transaction per entry.
    pub async fn bulk_add_entries<I, F>(
        &self,
        entries: I,
        batch_size: usize,
        actor_dn: Option<&str>,
        mut on_progress: F,
    ) -> Result<usize, BackendError>
    where
        I: IntoIterator<Item = (DirectoryEntry, Vec<u8>)>,
        F: FnMut(usize),
    {
        let _lock = self.write_lock.write().await;
        let mut entries = entries.into_iter();
        let batch_size = batch_size.max(1);
        let mut total_added = 0_usize;

        loop {
            let mut txn = self
                .env
                .begin_rw_txn()
                .map_err(|e| BackendError::Storage(format!("Failed to begin write txn: {}", e)))?;
            let mut batch_added = 0_usize;
            let mut last_csn = None;

            while batch_added < batch_size {
                let Some((mut entry, password)) = entries.next() else {
                    break;
                };

                let normalized_dn = Self::normalize_dn(&entry.dn);
                if txn.get(self.dn_index_db, &normalized_dn.as_bytes()).is_ok() {
                    return Err(BackendError::AlreadyExists);
                }

                let csn = self.csn_generator.generate();
                entry.operational_attributes = crate::backend::OperationalAttributes::for_new_entry(
                    csn.clone(),
                    actor_dn.map(str::to_string),
                );

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                let stored_entry = StoredEntry {
                    dn: entry.dn.clone(),
                    attributes: entry.attributes,
                    created_at: now,
                    modified_at: now,
                    operational_attributes: entry.operational_attributes.clone(),
                };

                let entry_bytes = bincode::serialize(&stored_entry).map_err(|e| {
                    BackendError::Storage(format!("Failed to serialize entry: {}", e))
                })?;

                txn.put(
                    self.entries_db,
                    &entry.dn.as_bytes(),
                    &entry_bytes,
                    WriteFlags::empty(),
                )
                .map_err(|e| BackendError::Storage(format!("Failed to write entry: {}", e)))?;

                if let Some(password_hash) = Self::password_hash_from_bytes(&password) {
                    txn.put(
                        self.passwords_db,
                        &entry.dn.as_bytes(),
                        &password_hash.as_bytes(),
                        WriteFlags::empty(),
                    )
                    .map_err(|e| {
                        BackendError::Storage(format!("Failed to write password: {}", e))
                    })?;
                }

                txn.put(
                    self.dn_index_db,
                    &normalized_dn.as_bytes(),
                    &entry.dn.as_bytes(),
                    WriteFlags::empty(),
                )
                .map_err(|e| BackendError::Storage(format!("Failed to update DN index: {}", e)))?;

                self.update_attribute_indexes(&mut txn, &entry.dn, &stored_entry.attributes)?;

                last_csn = Some(csn.to_ldap_string());
                total_added += 1;
                batch_added += 1;
                on_progress(total_added);
            }

            if batch_added == 0 {
                break;
            }

            if let Some(csn_string) = last_csn {
                txn.put(
                    self.metadata_db,
                    &b"context_csn",
                    &csn_string.as_bytes(),
                    WriteFlags::empty(),
                )
                .map_err(|e| {
                    BackendError::Storage(format!("Failed to update contextCSN: {}", e))
                })?;
            }

            txn.commit()
                .map_err(|e| BackendError::Storage(format!("Failed to commit txn: {}", e)))?;
        }

        self.mark_attribute_indexes_ready()?;
        self.record_auth_cache_metrics();
        Ok(total_added)
    }

    fn mark_attribute_indexes_ready(&self) -> Result<(), BackendError> {
        let mut txn = self.env.begin_rw_txn().map_err(|e| {
            BackendError::Storage(format!(
                "Failed to begin attribute index metadata write txn: {}",
                e
            ))
        })?;

        for attribute in self.index_plan.attributes.keys() {
            let metadata_key = Self::attribute_index_metadata_key(attribute);
            txn.put(
                self.metadata_db,
                &metadata_key.as_bytes(),
                &ATTRIBUTE_INDEX_VERSION,
                WriteFlags::empty(),
            )
            .map_err(|e| {
                BackendError::Storage(format!(
                    "Failed to mark attribute index ready for {}: {}",
                    attribute, e
                ))
            })?;
        }

        let configured_attributes = self.index_plan.config_value();
        txn.put(
            self.metadata_db,
            &ATTRIBUTE_INDEX_CONFIG_METADATA_KEY.as_bytes(),
            &configured_attributes.as_bytes(),
            WriteFlags::empty(),
        )
        .map_err(|e| {
            BackendError::Storage(format!(
                "Failed to mark attribute index config metadata: {}",
                e
            ))
        })?;

        txn.commit().map_err(|e| {
            BackendError::Storage(format!("Failed to commit attribute index metadata: {}", e))
        })?;

        Ok(())
    }

    async fn modify_entry_internal(
        &self,
        dn: &str,
        modifications: Vec<Modification>,
        actor_dn: Option<&str>,
    ) -> Result<(), BackendError> {
        let _lock = self.write_lock.write().await;

        let mut txn = self
            .env
            .begin_rw_txn()
            .map_err(|e| BackendError::Storage(format!("Failed to begin write txn: {}", e)))?;

        let normalized_dn = Self::normalize_dn(dn);
        let actual_dn = match txn.get(self.dn_index_db, &normalized_dn.as_bytes()) {
            Ok(bytes) => String::from_utf8_lossy(bytes).to_string(),
            Err(lmdb::Error::NotFound) => return Err(BackendError::NotFound),
            Err(e) => return Err(BackendError::Storage(format!("DN lookup failed: {}", e))),
        };
        let entry_bytes = txn
            .get(self.entries_db, &actual_dn.as_bytes())
            .map_err(|e| BackendError::Storage(format!("Failed to get entry: {}", e)))?;
        let mut entry = Self::deserialize_stored_entry(entry_bytes)?;
        let indexed_modified_attributes = modifications
            .iter()
            .map(|modification| ldap_attribute_key(&modification.attribute).into_owned())
            .filter(|attribute| {
                self.index_plan
                    .attribute_plan_normalized(attribute)
                    .is_some()
            })
            .collect::<HashSet<_>>();
        let old_attributes =
            (!indexed_modified_attributes.is_empty()).then(|| entry.attributes.clone());
        let mut password_touched = false;

        for modification in modifications {
            let attribute = ldap_attribute_key(&modification.attribute).into_owned();
            if attribute == "userpassword" {
                password_touched = true;
            }
            match modification.operation {
                ModifyOperation::Add => {
                    let existing = entry.attributes.entry(attribute).or_default();
                    for value in modification.values {
                        if !existing.contains(&value) {
                            existing.push(value);
                        }
                    }
                }
                ModifyOperation::Delete => {
                    if modification.values.is_empty() {
                        entry.attributes.remove(&attribute);
                    } else if let Some(existing) = entry.attributes.get_mut(&attribute) {
                        existing.retain(|v| !modification.values.contains(v));
                        if existing.is_empty() {
                            entry.attributes.remove(&attribute);
                        }
                    }
                }
                ModifyOperation::Replace => {
                    if modification.values.is_empty() {
                        entry.attributes.remove(&attribute);
                    } else {
                        entry.attributes.insert(attribute, modification.values);
                    }
                }
            }
        }

        entry.modified_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let csn = self.csn_generator.generate();
        entry
            .operational_attributes
            .for_modified_entry(csn.clone(), actor_dn.map(str::to_string));

        let entry_bytes = bincode::serialize(&entry)
            .map_err(|e| BackendError::Storage(format!("Failed to serialize entry: {}", e)))?;

        txn.put(
            self.entries_db,
            &entry.dn.as_bytes(),
            &entry_bytes,
            WriteFlags::empty(),
        )
        .map_err(|e| BackendError::Storage(format!("Failed to write entry: {}", e)))?;

        let mut updated_auth_record = None;
        if password_touched {
            if let Some(password_value) = entry
                .attributes
                .get("userpassword")
                .and_then(|values| values.first())
            {
                let password_hash = Self::password_hash_from_value(password_value);
                updated_auth_record = Self::decode_ssha512_hash(&password_hash).map(Arc::new);
                txn.put(
                    self.passwords_db,
                    &entry.dn.as_bytes(),
                    &password_hash.as_bytes(),
                    WriteFlags::empty(),
                )
                .map_err(|e| BackendError::Storage(format!("Failed to write password: {}", e)))?;
            } else {
                txn.del(self.passwords_db, &entry.dn.as_bytes(), None)
                    .or_else(|e| match e {
                        lmdb::Error::NotFound => Ok(()),
                        _ => Err(BackendError::Storage(
                            "Failed to delete password".to_string(),
                        )),
                    })?;
            }
        }

        if let Some(old_attributes) = old_attributes.as_ref() {
            self.remove_attribute_indexes_for_filter(
                &mut txn,
                &entry.dn,
                old_attributes,
                Some(&indexed_modified_attributes),
            )?;
            self.update_attribute_indexes_for_filter(
                &mut txn,
                &entry.dn,
                &entry.attributes,
                Some(&indexed_modified_attributes),
            )?;
        }

        let csn_string = csn.to_ldap_string();
        txn.put(
            self.metadata_db,
            &b"context_csn",
            &csn_string.as_bytes(),
            WriteFlags::empty(),
        )
        .map_err(|e| BackendError::Storage(format!("Failed to update contextCSN: {}", e)))?;

        txn.commit()
            .map_err(|e| BackendError::Storage(format!("Failed to commit txn: {}", e)))?;

        self.entry_cache.invalidate(&normalized_dn);
        if password_touched {
            if let Some(record) = updated_auth_record {
                self.auth_cache.insert(&normalized_dn, record);
            } else {
                self.auth_cache.invalidate(&normalized_dn);
            }
            self.record_auth_cache_metrics();
        }
        Ok(())
    }

    async fn rename_entry_internal(
        &self,
        dn: &str,
        new_rdn: &str,
        delete_old: bool,
        new_superior: Option<String>,
        actor_dn: Option<&str>,
    ) -> Result<(), BackendError> {
        let _lock = self.write_lock.write().await;
        let mut txn = self
            .env
            .begin_rw_txn()
            .map_err(|e| BackendError::Storage(format!("Failed to begin write txn: {}", e)))?;
        let normalized_dn = Self::normalize_dn(dn);
        let actual_dn = match txn.get(self.dn_index_db, &normalized_dn.as_bytes()) {
            Ok(bytes) => String::from_utf8_lossy(bytes).to_string(),
            Err(lmdb::Error::NotFound) => return Err(BackendError::NotFound),
            Err(e) => return Err(BackendError::Storage(format!("DN lookup failed: {}", e))),
        };
        let entry_bytes = txn
            .get(self.entries_db, &actual_dn.as_bytes())
            .map_err(|e| BackendError::Storage(format!("Failed to get entry: {}", e)))?;
        let entry = Self::deserialize_stored_entry(entry_bytes)?;

        let new_dn = if let Some(superior) = new_superior {
            format!("{},{}", new_rdn, superior)
        } else if let Some((_, rest)) = actual_dn.split_once(',') {
            format!("{},{}", new_rdn, rest)
        } else {
            new_rdn.to_string()
        };
        let normalized_new_dn = Self::normalize_dn(&new_dn);

        if txn
            .get(self.dn_index_db, &normalized_new_dn.as_bytes())
            .is_ok()
        {
            return Err(BackendError::AlreadyExists);
        }

        let password_hash = txn
            .get(self.passwords_db, &actual_dn.as_bytes())
            .map(|password| String::from_utf8_lossy(password).to_string())
            .ok();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let csn = self.csn_generator.generate();

        let mut new_entry = entry.to_directory_entry();
        new_entry.dn = new_dn.clone();
        new_entry
            .operational_attributes
            .for_modified_entry(csn.clone(), actor_dn.map(str::to_string));

        if delete_old && let Some((attr, _)) = actual_dn.split_once('=') {
            let attr = ldap_attribute_key(attr.trim());
            new_entry.attributes.remove(attr.as_ref());
        }

        if let Some((attr, val)) = new_rdn.split_once('=') {
            let attr_lower = ldap_attribute_key(attr.trim()).into_owned();
            let val_str = val.trim().to_string();
            new_entry
                .attributes
                .entry(attr_lower)
                .or_default()
                .push(val_str);
        }
        let new_stored_entry = StoredEntry {
            dn: new_dn.clone(),
            attributes: new_entry.attributes.clone(),
            created_at: entry.created_at,
            modified_at: now,
            operational_attributes: new_entry.operational_attributes,
        };
        let new_entry_bytes = bincode::serialize(&new_stored_entry)
            .map_err(|e| BackendError::Storage(format!("Failed to serialize entry: {}", e)))?;

        self.remove_attribute_indexes(&mut txn, &actual_dn, &entry.attributes)?;
        txn.del(self.entries_db, &actual_dn.as_bytes(), None)
            .map_err(|e| BackendError::Storage(format!("Failed to delete entry: {}", e)))?;
        txn.del(self.dn_index_db, &normalized_dn.as_bytes(), None)
            .map_err(|e| BackendError::Storage(format!("Failed to delete DN index: {}", e)))?;
        txn.del(self.passwords_db, &actual_dn.as_bytes(), None)
            .or_else(|e| match e {
                lmdb::Error::NotFound => Ok(()),
                _ => Err(BackendError::Storage(
                    "Failed to delete password".to_string(),
                )),
            })?;

        txn.put(
            self.entries_db,
            &new_dn.as_bytes(),
            &new_entry_bytes,
            WriteFlags::empty(),
        )
        .map_err(|e| BackendError::Storage(format!("Failed to write entry: {}", e)))?;
        txn.put(
            self.dn_index_db,
            &normalized_new_dn.as_bytes(),
            &new_dn.as_bytes(),
            WriteFlags::empty(),
        )
        .map_err(|e| BackendError::Storage(format!("Failed to update DN index: {}", e)))?;
        let updated_auth_record = password_hash
            .as_deref()
            .and_then(Self::decode_ssha512_hash)
            .map(Arc::new);
        if let Some(password_hash) = password_hash.as_deref() {
            txn.put(
                self.passwords_db,
                &new_dn.as_bytes(),
                &password_hash.as_bytes(),
                WriteFlags::empty(),
            )
            .map_err(|e| BackendError::Storage(format!("Failed to write password: {}", e)))?;
        }
        self.update_attribute_indexes(&mut txn, &new_dn, &new_stored_entry.attributes)?;
        let csn_string = csn.to_ldap_string();
        txn.put(
            self.metadata_db,
            &b"context_csn",
            &csn_string.as_bytes(),
            WriteFlags::empty(),
        )
        .map_err(|e| BackendError::Storage(format!("Failed to update contextCSN: {}", e)))?;

        txn.commit()
            .map_err(|e| BackendError::Storage(format!("Failed to commit txn: {}", e)))?;

        self.entry_cache.invalidate(&normalized_dn);
        self.entry_cache.invalidate(&normalized_new_dn);
        self.auth_cache.invalidate(&normalized_dn);
        if let Some(record) = updated_auth_record {
            self.auth_cache.insert(&normalized_new_dn, record);
        } else {
            self.auth_cache.invalidate(&normalized_new_dn);
        }
        self.record_auth_cache_metrics();
        Ok(())
    }

    /// Set a pre-hashed password for an entry (used during initialization)
    ///
    /// # Arguments
    /// * `dn` - Distinguished name of the entry
    /// * `hashed_password` - Pre-hashed password (e.g., {SSHA512}...)
    ///
    /// # Returns
    /// * `Result<(), BackendError>` - Success or error
    pub async fn set_prehashed_password(
        &self,
        dn: &str,
        hashed_password: &str,
    ) -> Result<(), BackendError> {
        let _lock = self.write_lock.write().await;

        let mut txn = self
            .env
            .begin_rw_txn()
            .map_err(|e| BackendError::Storage(format!("Failed to begin write txn: {}", e)))?;

        let normalized_dn = Self::normalize_dn(dn);

        // Get actual DN from index
        let actual_dn = match txn.get(self.dn_index_db, &normalized_dn.as_bytes()) {
            Ok(bytes) => String::from_utf8_lossy(bytes).to_string(),
            Err(lmdb::Error::NotFound) => return Err(BackendError::NotFound),
            Err(e) => return Err(BackendError::Storage(format!("DN lookup failed: {}", e))),
        };

        // Write the pre-hashed password directly
        txn.put(
            self.passwords_db,
            &actual_dn.as_bytes(),
            &hashed_password.as_bytes(),
            WriteFlags::empty(),
        )
        .map_err(|e| BackendError::Storage(format!("Failed to write password: {}", e)))?;

        txn.commit()
            .map_err(|e| BackendError::Storage(format!("Failed to commit txn: {}", e)))?;

        if let Some(record) = Self::decode_ssha512_hash(hashed_password).map(Arc::new) {
            self.auth_cache.insert(&normalized_dn, record);
        } else {
            self.auth_cache.invalidate(&normalized_dn);
        }
        self.record_auth_cache_metrics();
        Ok(())
    }

    async fn record_account_authentication<F>(
        &self,
        dn: &str,
        update: F,
    ) -> Result<bool, BackendError>
    where
        F: FnOnce(&mut OperationalAttributes, Csn) -> bool,
    {
        let _lock = self.write_lock.write().await;

        let mut txn = self
            .env
            .begin_rw_txn()
            .map_err(|e| BackendError::Storage(format!("Failed to begin write txn: {}", e)))?;

        let normalized_dn = Self::normalize_dn(dn);
        let actual_dn = match txn.get(self.dn_index_db, &normalized_dn.as_bytes()) {
            Ok(bytes) => String::from_utf8_lossy(bytes).to_string(),
            Err(lmdb::Error::NotFound) => return Ok(false),
            Err(e) => return Err(BackendError::Storage(format!("DN lookup failed: {}", e))),
        };
        let entry_bytes = match txn.get(self.entries_db, &actual_dn.as_bytes()) {
            Ok(bytes) => bytes,
            Err(lmdb::Error::NotFound) => {
                return Err(BackendError::Storage(format!(
                    "DN index references missing entry: {actual_dn}"
                )));
            }
            Err(e) => return Err(BackendError::Storage(format!("Failed to get entry: {}", e))),
        };
        let mut entry = Self::deserialize_stored_entry(entry_bytes)?;

        let csn = self.csn_generator.generate();
        if !update(&mut entry.operational_attributes, csn.clone()) {
            return Ok(false);
        }
        entry.modified_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let entry_bytes = bincode::serialize(&entry)
            .map_err(|e| BackendError::Storage(format!("Failed to serialize entry: {}", e)))?;
        txn.put(
            self.entries_db,
            &actual_dn.as_bytes(),
            &entry_bytes,
            WriteFlags::empty(),
        )
        .map_err(|e| BackendError::Storage(format!("Failed to write entry: {}", e)))?;

        let csn_string = csn.to_ldap_string();
        txn.put(
            self.metadata_db,
            &b"context_csn",
            &csn_string.as_bytes(),
            WriteFlags::empty(),
        )
        .map_err(|e| BackendError::Storage(format!("Failed to update contextCSN: {}", e)))?;

        txn.commit()
            .map_err(|e| BackendError::Storage(format!("Failed to commit txn: {}", e)))?;

        self.entry_cache.invalidate(&normalized_dn);
        Ok(true)
    }

    /// Normalize DN for case-insensitive comparison
    fn normalize_dn(dn: &str) -> String {
        dn.to_lowercase().trim().to_string()
    }

    fn deserialize_stored_entry(bytes: &[u8]) -> Result<StoredEntry, BackendError> {
        match bincode::deserialize(bytes) {
            Ok(entry) => Ok(entry),
            Err(current_err) => bincode::deserialize::<StoredEntryV1>(bytes)
                .map(StoredEntry::from)
                .map_err(|legacy_err| {
                    BackendError::Storage(format!(
                        "Failed to deserialize entry: {current_err}; legacy decode failed: {legacy_err}"
                    ))
                }),
        }
    }

    /// Get entry by DN with read transaction (optimized for concurrency)
    fn get_entry_internal(&self, dn: &str) -> Result<Option<StoredEntry>, BackendError> {
        let normalized_dn = Self::normalize_dn(dn);
        if let Some(entry) = self.entry_cache.get(&normalized_dn) {
            return Ok(Some(entry));
        }

        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| BackendError::Storage(format!("Failed to begin read txn: {}", e)))?;

        // Check DN index for actual DN
        let actual_dn = match txn.get(self.dn_index_db, &normalized_dn.as_bytes()) {
            Ok(bytes) => String::from_utf8_lossy(bytes).to_string(),
            Err(lmdb::Error::NotFound) => return Ok(None),
            Err(e) => {
                return Err(BackendError::Storage(format!(
                    "DN index lookup failed: {}",
                    e
                )));
            }
        };

        // Get entry data
        match txn.get(self.entries_db, &actual_dn.as_bytes()) {
            Ok(bytes) => {
                let entry = Self::deserialize_stored_entry(bytes)?;
                self.entry_cache.insert(entry.clone());
                Ok(Some(entry))
            }
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(BackendError::Storage(format!("Entry lookup failed: {}", e))),
        }
    }

    /// Search entries with scope filtering (optimized with cursor iteration)
    fn search_entries_internal(
        &self,
        base_dn: &str,
        scope: SearchScope,
    ) -> Result<Vec<StoredEntry>, BackendError> {
        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| BackendError::Storage(format!("Failed to begin read txn: {}", e)))?;

        let mut results = Vec::new();
        // Use cursor for efficient iteration
        let mut cursor = txn
            .open_ro_cursor(self.entries_db)
            .map_err(|e| BackendError::Storage(format!("Failed to open cursor: {}", e)))?;

        for (key, value) in cursor.iter() {
            let dn = String::from_utf8_lossy(key).to_string();

            if Self::entry_in_scope(&dn, base_dn, scope) {
                let entry = Self::deserialize_stored_entry(value)?;
                results.push(entry);
            }
        }

        Ok(results)
    }

    fn search_entries_paginated_internal(
        &self,
        base_dn: &str,
        scope: SearchScope,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<StoredEntry>, BackendError> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| BackendError::Storage(format!("Failed to begin read txn: {}", e)))?;

        let mut results = Vec::with_capacity(limit);
        let mut matched = 0usize;

        let mut cursor = txn
            .open_ro_cursor(self.entries_db)
            .map_err(|e| BackendError::Storage(format!("Failed to open cursor: {}", e)))?;

        for (key, value) in cursor.iter() {
            let dn = String::from_utf8_lossy(key).to_string();
            if !Self::entry_in_scope(&dn, base_dn, scope) {
                continue;
            }

            if matched < offset {
                matched += 1;
                continue;
            }

            let entry = Self::deserialize_stored_entry(value)?;
            results.push(entry);
            matched += 1;

            if results.len() == limit {
                break;
            }
        }

        Ok(results)
    }

    fn count_entries_internal(
        &self,
        base_dn: &str,
        scope: SearchScope,
    ) -> Result<usize, BackendError> {
        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| BackendError::Storage(format!("Failed to begin read txn: {}", e)))?;

        let mut count = 0usize;
        let mut cursor = txn
            .open_ro_cursor(self.entries_db)
            .map_err(|e| BackendError::Storage(format!("Failed to open cursor: {}", e)))?;

        for (key, _) in cursor.iter() {
            let dn = String::from_utf8_lossy(key).to_string();
            if Self::entry_in_scope(&dn, base_dn, scope) {
                count += 1;
            }
        }

        Ok(count)
    }

    /// Check if DN is in search scope
    fn entry_in_scope(dn: &str, base_dn: &str, scope: SearchScope) -> bool {
        if scope == SearchScope(2) {
            return Self::entry_in_subtree_scope(dn, base_dn);
        }

        let base_components = Self::scope_base_components(base_dn);
        Self::entry_in_scope_with_base_components(dn, &base_components, scope)
    }

    fn entry_in_subtree_scope(dn: &str, base_dn: &str) -> bool {
        let base_dn = base_dn.trim();
        if base_dn.is_empty() {
            return true;
        }

        let dn = dn.trim();
        let dn_bytes = dn.as_bytes();
        let base_bytes = base_dn.as_bytes();
        if dn_bytes.len() < base_bytes.len() {
            return false;
        }

        let suffix_start = dn_bytes.len() - base_bytes.len();
        if !dn_bytes[suffix_start..].eq_ignore_ascii_case(base_bytes) {
            return false;
        }

        suffix_start == 0 || dn_bytes.get(suffix_start - 1) == Some(&b',')
    }

    fn scope_base_components(base_dn: &str) -> Vec<&str> {
        base_dn
            .split(',')
            .rev()
            .map(str::trim)
            .filter(|component| !component.is_empty())
            .collect()
    }

    fn entry_in_scope_with_base_components(
        dn: &str,
        base_components: &[&str],
        scope: SearchScope,
    ) -> bool {
        let mut dn_components = dn.split(',').rev().map(str::trim).filter(|c| !c.is_empty());

        for base_component in base_components {
            let Some(dn_component) = dn_components.next() else {
                return false;
            };
            if !dn_component.eq_ignore_ascii_case(base_component) {
                return false;
            }
        }

        match scope {
            SearchScope(0) => dn_components.next().is_none(),
            SearchScope(1) => dn_components.next().is_some() && dn_components.next().is_none(),
            SearchScope(2) => true,
            _ => false,
        }
    }

    /// Create SSHA512 password hash
    /// Format: {SSHA512}base64(SHA512(password + salt) + salt)
    fn create_ssha512(password: &[u8]) -> String {
        use rand::RngExt;

        // Generate random 16-byte salt
        let salt: [u8; 16] = rand::rng().random();

        // Hash password with salt
        let mut hasher = Sha512::new();
        hasher.update(password);
        hasher.update(salt);
        let hash = hasher.finalize();

        // Combine hash and salt
        let mut combined = Vec::with_capacity(64 + 16);
        combined.extend_from_slice(&hash);
        combined.extend_from_slice(&salt);

        // Encode to base64 with prefix
        format!(
            "{{SSHA512}}{}",
            base64::engine::general_purpose::STANDARD.encode(&combined)
        )
    }

    fn decode_ssha512_hash(stored_hash: &str) -> Option<AuthCredentialRecord> {
        // Remove {SSHA512} prefix if present
        let hash_b64 = if let Some(stripped) = stored_hash.strip_prefix("{SSHA512}") {
            stripped
        } else {
            stored_hash
        };

        // Decode base64
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(hash_b64)
            .ok()?;

        // SSHA512: first 64 bytes are SHA512 hash, remaining bytes are salt
        if decoded.len() < 64 {
            return None;
        }

        let (stored_hash, salt) = decoded.split_at(64);
        let mut hash = [0; 64];
        hash.copy_from_slice(stored_hash);

        Some(AuthCredentialRecord {
            hash,
            salt: salt.to_vec(),
        })
    }

    fn verify_ssha512_record(password: &[u8], record: &AuthCredentialRecord) -> bool {
        // Hash the provided password with the stored salt
        let mut hasher = Sha512::new();
        hasher.update(password);
        hasher.update(&record.salt);
        let computed_hash = hasher.finalize();

        Self::constant_time_eq(&computed_hash, &record.hash)
    }

    fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
        if left.len() != right.len() {
            return false;
        }

        let mut diff = 0;
        for (left_byte, right_byte) in left.iter().zip(right) {
            diff |= left_byte ^ right_byte;
        }
        diff == 0
    }

    fn password_hash_from_bytes(password: &[u8]) -> Option<String> {
        if password.is_empty() {
            return None;
        }

        Some(
            std::str::from_utf8(password)
                .ok()
                .filter(|password| password.starts_with("{SSHA512}"))
                .map(str::to_string)
                .unwrap_or_else(|| Self::create_ssha512(password)),
        )
    }

    fn password_hash_from_value(password: &str) -> String {
        if password.starts_with("{SSHA512}") {
            password.to_string()
        } else {
            Self::create_ssha512(password.as_bytes())
        }
    }

    fn equality_index_key(value: &str, dn: &str) -> String {
        format!("{}:{}", value, dn)
    }

    fn equality_index_prefix(value: &str) -> String {
        format!("{}:", value)
    }

    fn presence_index_key(dn: &str) -> String {
        Self::equality_index_key(PRESENCE_INDEX_VALUE_SENTINEL, dn)
    }

    fn presence_index_prefix() -> String {
        Self::equality_index_prefix(PRESENCE_INDEX_VALUE_SENTINEL)
    }

    fn substring_index_key(token: &str, dn: &str) -> String {
        format!("{SUBSTRING_INDEX_KEY_PREFIX}{token}\0{dn}")
    }

    fn substring_index_prefix(token: &str) -> String {
        format!("{SUBSTRING_INDEX_KEY_PREFIX}{token}\0")
    }

    fn ordering_index_key(value: &str, dn: &str) -> String {
        format!("{ORDERING_INDEX_KEY_PREFIX}{value}\0{dn}")
    }

    fn ordering_index_prefix() -> &'static str {
        ORDERING_INDEX_KEY_PREFIX
    }

    fn ordering_index_key_parts(key: &[u8]) -> Result<Option<(&str, &str)>, BackendError> {
        let key = std::str::from_utf8(key)
            .map_err(|e| BackendError::Storage(format!("Invalid UTF-8 in index key: {}", e)))?;
        Ok(key
            .strip_prefix(ORDERING_INDEX_KEY_PREFIX)
            .and_then(|suffix| suffix.split_once('\0')))
    }

    fn attribute_index_keys(
        index_db: Database,
        dn: &str,
        values: &[String],
        plan: &AttributeIndexPlan,
    ) -> Result<Vec<(Database, String)>, BackendError> {
        let mut index_keys = Vec::new();
        Self::for_each_attribute_index_key(dn, values, plan, |index_key| {
            index_keys.push((index_db, index_key));
            Ok(())
        })?;

        Ok(index_keys)
    }

    fn for_each_attribute_index_key<F>(
        dn: &str,
        values: &[String],
        plan: &AttributeIndexPlan,
        mut visit: F,
    ) -> Result<(), BackendError>
    where
        F: FnMut(String) -> Result<(), BackendError>,
    {
        let has_presence = plan.index_types.contains(&IndexType::Presence);
        let has_equality = plan.index_types.contains(&IndexType::Equality);
        let has_substring = plan.index_types.contains(&IndexType::Substring);
        let has_ordering = plan.index_types.contains(&IndexType::Ordering);

        if has_presence && !values.is_empty() {
            visit(Self::presence_index_key(dn))?;
        }

        for value in values {
            if has_equality {
                let normalized_value = plan.normalize_equality_value(value)?;
                visit(Self::equality_index_key(&normalized_value, dn))?;
            }

            if has_substring {
                let normalized_value = plan.normalize_substring_value(value)?;
                for token in Self::substring_index_tokens(&normalized_value) {
                    visit(Self::substring_index_key(&token, dn))?;
                }
            }

            if has_ordering {
                let normalized_value = plan.normalize_ordering_value(value)?;
                visit(Self::ordering_index_key(&normalized_value, dn))?;
            }
        }

        Ok(())
    }

    fn substring_index_tokens(value: &str) -> BTreeSet<String> {
        let chars = value.chars().collect::<Vec<_>>();
        if chars.len() < SUBSTRING_INDEX_TOKEN_LEN {
            return BTreeSet::new();
        }

        chars
            .windows(SUBSTRING_INDEX_TOKEN_LEN)
            .map(|window| window.iter().collect::<String>())
            .collect()
    }

    fn substring_query_tokens(parts: &[SearchSubstringPart]) -> Vec<String> {
        let mut segments = parts
            .iter()
            .filter_map(|part| {
                let value = match part {
                    SearchSubstringPart::Initial(value)
                    | SearchSubstringPart::Any(value)
                    | SearchSubstringPart::Final(value) => value,
                };
                let char_len = value.chars().count();
                (char_len >= SUBSTRING_INDEX_TOKEN_LEN).then_some((char_len, value.as_str()))
            })
            .collect::<Vec<_>>();
        segments.sort_by(|left, right| right.0.cmp(&left.0));

        let mut unique = HashSet::new();
        let mut tokens = Vec::new();
        for (_, segment) in segments {
            Self::push_bounded_substring_query_tokens(segment, &mut unique, &mut tokens);
            if tokens.len() >= SUBSTRING_QUERY_MAX_TOKENS {
                break;
            }
        }
        tokens
    }

    fn push_bounded_substring_query_tokens(
        segment: &str,
        unique: &mut HashSet<String>,
        tokens: &mut Vec<String>,
    ) {
        let segment_tokens = Self::substring_segment_tokens(segment);
        if segment_tokens.is_empty() {
            return;
        }

        let mut candidate_indexes = Vec::with_capacity(segment_tokens.len().min(4));
        candidate_indexes.push(segment_tokens.len() - 1);
        candidate_indexes.push(0);
        candidate_indexes.push(segment_tokens.len() / 2);
        if segment_tokens.len() > 3 {
            candidate_indexes.push(segment_tokens.len() / 3);
        }

        for index in candidate_indexes {
            if tokens.len() >= SUBSTRING_QUERY_MAX_TOKENS {
                break;
            }
            let token = &segment_tokens[index];
            if unique.insert(token.clone()) {
                tokens.push(token.clone());
            }
        }
    }

    fn substring_segment_tokens(value: &str) -> Vec<String> {
        let chars = value.chars().collect::<Vec<_>>();
        if chars.len() < SUBSTRING_INDEX_TOKEN_LEN {
            return Vec::new();
        }

        let mut unique = HashSet::new();
        let mut tokens = Vec::new();
        for window in chars.windows(SUBSTRING_INDEX_TOKEN_LEN) {
            let token = window.iter().collect::<String>();
            if unique.insert(token.clone()) {
                tokens.push(token);
            }
        }
        tokens
    }

    fn attribute_index_metadata_key(attribute: &str) -> String {
        format!("attribute_index_v1:{}", attribute)
    }

    fn ensure_attribute_indexes_backfilled(
        env: &Arc<Environment>,
        entries_db: Database,
        metadata_db: Database,
        attr_indexes: &HashMap<String, Database>,
        index_plan: &IndexPlan,
    ) -> Result<(), BackendError> {
        let configured_attributes = index_plan.config_value();
        let pending_indexes = {
            let txn = env.begin_ro_txn().map_err(|e| {
                BackendError::Storage(format!(
                    "Failed to begin attribute index metadata read txn: {}",
                    e
                ))
            })?;
            let config_changed =
                match txn.get(metadata_db, &ATTRIBUTE_INDEX_CONFIG_METADATA_KEY.as_bytes()) {
                    Ok(value) => value != configured_attributes.as_bytes(),
                    Err(lmdb::Error::NotFound) => true,
                    Err(e) => {
                        return Err(BackendError::Storage(format!(
                            "Failed to read attribute index config metadata: {}",
                            e
                        )));
                    }
                };

            if config_changed {
                attr_indexes
                    .iter()
                    .filter_map(|(attr, index_db)| {
                        index_plan
                            .attributes
                            .get(attr)
                            .map(|plan| (attr.clone(), *index_db, plan.clone()))
                    })
                    .collect::<Vec<_>>()
            } else {
                let mut pending = Vec::new();
                for (attr, index_db) in attr_indexes {
                    let metadata_key = Self::attribute_index_metadata_key(attr);
                    match txn.get(metadata_db, &metadata_key.as_bytes()) {
                        Ok(value) if value == ATTRIBUTE_INDEX_VERSION => {}
                        Ok(_) | Err(lmdb::Error::NotFound) => {
                            if let Some(plan) = index_plan.attributes.get(attr) {
                                pending.push((attr.clone(), *index_db, plan.clone()));
                            }
                        }
                        Err(e) => {
                            return Err(BackendError::Storage(format!(
                                "Failed to read attribute index metadata for {}: {}",
                                attr, e
                            )));
                        }
                    }
                }
                pending
            }
        };

        if pending_indexes.is_empty() {
            let mut txn = env.begin_rw_txn().map_err(|e| {
                BackendError::Storage(format!(
                    "Failed to begin attribute index config metadata write txn: {}",
                    e
                ))
            })?;
            txn.put(
                metadata_db,
                &ATTRIBUTE_INDEX_CONFIG_METADATA_KEY.as_bytes(),
                &configured_attributes.as_bytes(),
                WriteFlags::empty(),
            )
            .map_err(|e| {
                BackendError::Storage(format!(
                    "Failed to mark attribute index config metadata: {}",
                    e
                ))
            })?;
            txn.commit().map_err(|e| {
                BackendError::Storage(format!(
                    "Failed to commit attribute index config metadata: {}",
                    e
                ))
            })?;
            return Ok(());
        }

        let pending_by_attr = pending_indexes
            .iter()
            .map(|(attr, index_db, plan)| (attr.clone(), (*index_db, plan.clone())))
            .collect::<HashMap<_, _>>();
        let index_entries = {
            let txn = env.begin_ro_txn().map_err(|e| {
                BackendError::Storage(format!(
                    "Failed to begin attribute index backfill read txn: {}",
                    e
                ))
            })?;
            let mut cursor = txn.open_ro_cursor(entries_db).map_err(|e| {
                BackendError::Storage(format!(
                    "Failed to open entries cursor for attribute index backfill: {}",
                    e
                ))
            })?;

            let mut index_entries = Vec::new();
            for (_, entry_bytes) in cursor.iter() {
                let entry = Self::deserialize_stored_entry(entry_bytes).map_err(|e| {
                    BackendError::Storage(format!(
                        "Failed to deserialize entry during attribute index backfill: {}",
                        e
                    ))
                })?;

                for (attr_name, values) in &entry.attributes {
                    if values.is_empty() {
                        continue;
                    }

                    let attr_lower = ldap_attribute_key(attr_name);
                    if let Some((index_db, plan)) = pending_by_attr.get(attr_lower.as_ref()) {
                        index_entries.extend(Self::attribute_index_keys(
                            *index_db, &entry.dn, values, plan,
                        )?);
                    }
                }
            }

            index_entries
        };

        let mut txn = env.begin_rw_txn().map_err(|e| {
            BackendError::Storage(format!(
                "Failed to begin attribute index backfill write txn: {}",
                e
            ))
        })?;

        for (_, index_db, _) in &pending_indexes {
            txn.clear_db(*index_db).map_err(|e| {
                BackendError::Storage(format!("Failed to clear attribute index: {}", e))
            })?;
        }

        for (index_db, index_key) in index_entries {
            txn.put(index_db, &index_key.as_bytes(), &[], WriteFlags::empty())
                .map_err(|e| {
                    BackendError::Storage(format!(
                        "Failed to write backfilled attribute index key: {}",
                        e
                    ))
                })?;
        }

        for (attr, _, _) in pending_indexes {
            let metadata_key = Self::attribute_index_metadata_key(&attr);
            txn.put(
                metadata_db,
                &metadata_key.as_bytes(),
                &ATTRIBUTE_INDEX_VERSION,
                WriteFlags::empty(),
            )
            .map_err(|e| {
                BackendError::Storage(format!(
                    "Failed to mark attribute index backfill complete for {}: {}",
                    attr, e
                ))
            })?;
        }

        txn.put(
            metadata_db,
            &ATTRIBUTE_INDEX_CONFIG_METADATA_KEY.as_bytes(),
            &configured_attributes.as_bytes(),
            WriteFlags::empty(),
        )
        .map_err(|e| {
            BackendError::Storage(format!(
                "Failed to mark attribute index config metadata: {}",
                e
            ))
        })?;

        txn.commit().map_err(|e| {
            BackendError::Storage(format!("Failed to commit attribute index backfill: {}", e))
        })?;

        Ok(())
    }

    fn collect_index_dns_by_prefix(
        cursor: &mut lmdb::RoCursor<'_>,
        prefix: &[u8],
    ) -> Result<Vec<String>, BackendError> {
        let prefix_bytes = prefix;
        let first_key = match cursor.get(Some(prefix), None, LMDB_SET_RANGE_OP) {
            Ok((Some(key), _)) => key,
            Ok((None, _)) => return Ok(Vec::new()),
            Err(lmdb::Error::NotFound) => return Ok(Vec::new()),
            Err(e) => {
                return Err(BackendError::Storage(format!(
                    "Failed to seek attribute index cursor: {}",
                    e
                )));
            }
        };

        if !first_key.starts_with(prefix_bytes) {
            return Ok(Vec::new());
        }

        let prefix = std::str::from_utf8(prefix)
            .map_err(|e| BackendError::Storage(format!("Invalid index prefix encoding: {}", e)))?;
        let mut results = Vec::new();
        let first_key = std::str::from_utf8(first_key)
            .map_err(|e| BackendError::Storage(format!("Invalid UTF-8 in index key: {}", e)))?;
        if let Some(dn) = first_key.strip_prefix(prefix) {
            results.push(dn.to_string());
        }

        for (key, _value) in cursor.iter() {
            if !key.starts_with(prefix_bytes) {
                break;
            }
            let key = std::str::from_utf8(key)
                .map_err(|e| BackendError::Storage(format!("Invalid UTF-8 in index key: {}", e)))?;
            if let Some(dn) = key.strip_prefix(prefix) {
                results.push(dn.to_string());
            }
        }

        Ok(results)
    }

    /// Update attribute indexes for an entry
    ///
    /// This method updates the attribute indexes when an entry is added or modified.
    /// For each indexed attribute, it creates the configured equality, presence,
    /// substring, and ordering keys.
    fn update_attribute_indexes(
        &self,
        txn: &mut lmdb::RwTransaction,
        dn: &str,
        attributes: &HashMap<String, Vec<String>>,
    ) -> Result<(), BackendError> {
        self.update_attribute_indexes_for_filter(txn, dn, attributes, None)
    }

    fn update_attribute_indexes_for_filter(
        &self,
        txn: &mut lmdb::RwTransaction,
        dn: &str,
        attributes: &HashMap<String, Vec<String>>,
        attribute_filter: Option<&HashSet<String>>,
    ) -> Result<(), BackendError> {
        let indexes = self
            .attr_indexes
            .try_read()
            .map_err(|e| BackendError::Storage(format!("Failed to acquire index lock: {}", e)))?;

        for (attr_name, values) in attributes {
            let attr_lower = ldap_attribute_key(attr_name);
            if attribute_filter.is_some_and(|filter| !filter.contains(attr_lower.as_ref())) {
                continue;
            }

            // Check if this attribute is indexed
            if let Some(index_db) = indexes.get(attr_lower.as_ref())
                && let Some(plan) = self
                    .index_plan
                    .attribute_plan_normalized(attr_lower.as_ref())
            {
                Self::for_each_attribute_index_key(dn, values, plan, |index_key| {
                    txn.put(*index_db, &index_key.as_bytes(), &[], WriteFlags::empty())
                        .map_err(|e| {
                            BackendError::Storage(format!(
                                "Failed to update index for {}: {}",
                                attr_name, e
                            ))
                        })?;
                    Ok(())
                })?;
            }
        }

        Ok(())
    }

    /// Remove attribute indexes for an entry
    ///
    /// This method removes index entries when an entry is deleted.
    fn remove_attribute_indexes(
        &self,
        txn: &mut lmdb::RwTransaction,
        dn: &str,
        attributes: &HashMap<String, Vec<String>>,
    ) -> Result<(), BackendError> {
        self.remove_attribute_indexes_for_filter(txn, dn, attributes, None)
    }

    fn remove_attribute_indexes_for_filter(
        &self,
        txn: &mut lmdb::RwTransaction,
        dn: &str,
        attributes: &HashMap<String, Vec<String>>,
        attribute_filter: Option<&HashSet<String>>,
    ) -> Result<(), BackendError> {
        let indexes = self
            .attr_indexes
            .try_read()
            .map_err(|e| BackendError::Storage(format!("Failed to acquire index lock: {}", e)))?;

        for (attr_name, values) in attributes {
            let attr_lower = ldap_attribute_key(attr_name);
            if attribute_filter.is_some_and(|filter| !filter.contains(attr_lower.as_ref())) {
                continue;
            }

            // Check if this attribute is indexed
            if let Some(index_db) = indexes.get(attr_lower.as_ref())
                && let Some(plan) = self
                    .index_plan
                    .attribute_plan_normalized(attr_lower.as_ref())
            {
                Self::for_each_attribute_index_key(dn, values, plan, |index_key| {
                    txn.del(*index_db, &index_key.as_bytes(), None)
                        .or_else(|e| match e {
                            lmdb::Error::NotFound => Ok(()), // Already removed, that's OK
                            _ => Err(BackendError::Storage(format!(
                                "Failed to remove index for {}: {}",
                                attr_name, e
                            ))),
                        })?;
                    Ok(())
                })?;
            }
        }

        Ok(())
    }

    /// Search using attribute indexes
    ///
    /// This method performs an indexed lookup for a specific attribute value.
    /// Returns a list of DNs that have the specified attribute value.
    pub fn search_by_index(
        &self,
        attribute: &str,
        value: &str,
    ) -> Result<Vec<String>, BackendError> {
        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| BackendError::Storage(format!("Failed to begin read txn: {}", e)))?;
        Ok(self
            .search_by_index_in_txn(&txn, attribute, value)?
            .unwrap_or_default())
    }

    fn search_by_index_in_txn(
        &self,
        txn: &lmdb::RoTransaction<'_>,
        attribute: &str,
        value: &str,
    ) -> Result<Option<Vec<String>>, BackendError> {
        let attr_lower = ldap_attribute_key(attribute);

        let Some(plan) = self
            .index_plan
            .attribute_plan_normalized(attr_lower.as_ref())
        else {
            return Ok(None);
        };
        if !plan.index_types.contains(&IndexType::Equality) {
            return Ok(None);
        }
        let normalized_value = plan.normalize_equality_value(value)?;

        let indexes = self
            .attr_indexes
            .try_read()
            .map_err(|e| BackendError::Storage(format!("Failed to acquire index lock: {}", e)))?;

        // Check if this attribute has an index
        let index_db = match indexes.get(attr_lower.as_ref()) {
            Some(db) => *db,
            None => return Ok(None),
        };

        let mut cursor = txn
            .open_ro_cursor(index_db)
            .map_err(|e| BackendError::Storage(format!("Failed to open cursor: {}", e)))?;
        let search_prefix = Self::equality_index_prefix(&normalized_value);
        Self::collect_index_dns_by_prefix(&mut cursor, search_prefix.as_bytes()).map(Some)
    }

    #[cfg(test)]
    fn search_present_by_index(&self, attribute: &str) -> Result<Vec<String>, BackendError> {
        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| BackendError::Storage(format!("Failed to begin read txn: {}", e)))?;
        Ok(self
            .search_present_by_index_in_txn(&txn, attribute)?
            .unwrap_or_default())
    }

    fn search_present_by_index_in_txn(
        &self,
        txn: &lmdb::RoTransaction<'_>,
        attribute: &str,
    ) -> Result<Option<Vec<String>>, BackendError> {
        let attr_lower = ldap_attribute_key(attribute);

        let Some(plan) = self
            .index_plan
            .attribute_plan_normalized(attr_lower.as_ref())
        else {
            return Ok(None);
        };
        if !plan.index_types.contains(&IndexType::Presence) {
            return Ok(None);
        }

        let indexes = self
            .attr_indexes
            .try_read()
            .map_err(|e| BackendError::Storage(format!("Failed to acquire index lock: {}", e)))?;
        let index_db = match indexes.get(attr_lower.as_ref()) {
            Some(db) => *db,
            None => return Ok(None),
        };

        let mut cursor = txn
            .open_ro_cursor(index_db)
            .map_err(|e| BackendError::Storage(format!("Failed to open cursor: {}", e)))?;
        let search_prefix = Self::presence_index_prefix();
        Self::collect_index_dns_by_prefix(&mut cursor, search_prefix.as_bytes()).map(Some)
    }

    fn search_substring_by_index_in_txn(
        &self,
        txn: &lmdb::RoTransaction<'_>,
        attribute: &str,
        parts: &[SearchSubstringPart],
    ) -> Result<Option<SubstringIndexCandidates>, BackendError> {
        let attr_lower = ldap_attribute_key(attribute);

        let Some(plan) = self
            .index_plan
            .attribute_plan_normalized(attr_lower.as_ref())
        else {
            return Ok(None);
        };
        if !plan.index_types.contains(&IndexType::Substring) {
            return Ok(None);
        }
        let normalized_parts = parts
            .iter()
            .map(|part| match part {
                SearchSubstringPart::Initial(value) => plan
                    .normalize_substring_value(value)
                    .map(SearchSubstringPart::Initial),
                SearchSubstringPart::Any(value) => plan
                    .normalize_substring_value(value)
                    .map(SearchSubstringPart::Any),
                SearchSubstringPart::Final(value) => plan
                    .normalize_substring_value(value)
                    .map(SearchSubstringPart::Final),
            })
            .collect::<Result<Vec<_>, _>>()?;

        let tokens = Self::substring_query_tokens(&normalized_parts);
        if tokens.is_empty() {
            return Ok(None);
        }

        let indexes = self
            .attr_indexes
            .try_read()
            .map_err(|e| BackendError::Storage(format!("Failed to acquire index lock: {}", e)))?;
        let index_db = match indexes.get(attr_lower.as_ref()) {
            Some(db) => *db,
            None => return Ok(None),
        };

        let mut cursor = txn
            .open_ro_cursor(index_db)
            .map_err(|e| BackendError::Storage(format!("Failed to open cursor: {}", e)))?;

        let mut candidate_dns: Option<Vec<String>> = None;
        for token in tokens {
            let search_prefix = Self::substring_index_prefix(&token);
            let token_dns =
                Self::collect_index_dns_by_prefix(&mut cursor, search_prefix.as_bytes())?;
            if token_dns.is_empty() {
                return Ok(Some(SubstringIndexCandidates {
                    attribute: attr_lower.into_owned(),
                    normalized_parts,
                    dns: Vec::new(),
                }));
            }
            candidate_dns = Some(match candidate_dns {
                Some(existing) => {
                    let token_dns = token_dns.into_iter().collect::<HashSet<_>>();
                    existing
                        .into_iter()
                        .filter(|dn| token_dns.contains(dn))
                        .collect()
                }
                None => token_dns,
            });
            if candidate_dns.as_ref().is_some_and(Vec::is_empty) {
                break;
            }
        }

        Ok(Some(SubstringIndexCandidates {
            attribute: attr_lower.into_owned(),
            normalized_parts,
            dns: candidate_dns.unwrap_or_default(),
        }))
    }

    fn search_ordering_by_index_in_txn(
        &self,
        txn: &lmdb::RoTransaction<'_>,
        attribute: &str,
        value: &str,
        greater_or_equal: bool,
    ) -> Result<Option<Vec<String>>, BackendError> {
        let attr_lower = ldap_attribute_key(attribute);

        let Some(plan) = self
            .index_plan
            .attribute_plan_normalized(attr_lower.as_ref())
        else {
            return Ok(None);
        };
        if !plan.index_types.contains(&IndexType::Ordering) {
            return Ok(None);
        }
        let normalized_value = plan.normalize_ordering_value(value)?;

        let indexes = self
            .attr_indexes
            .try_read()
            .map_err(|e| BackendError::Storage(format!("Failed to acquire index lock: {}", e)))?;
        let index_db = match indexes.get(attr_lower.as_ref()) {
            Some(db) => *db,
            None => return Ok(None),
        };

        let mut cursor = txn
            .open_ro_cursor(index_db)
            .map_err(|e| BackendError::Storage(format!("Failed to open cursor: {}", e)))?;

        let seek_key = if greater_or_equal {
            Self::ordering_index_key(&normalized_value, "")
        } else {
            Self::ordering_index_prefix().to_string()
        };
        let first_key = match cursor.get(Some(seek_key.as_bytes()), None, LMDB_SET_RANGE_OP) {
            Ok((Some(key), _)) => key,
            Ok((None, _)) | Err(lmdb::Error::NotFound) => return Ok(Some(Vec::new())),
            Err(e) => {
                return Err(BackendError::Storage(format!(
                    "Failed to seek ordering index cursor: {}",
                    e
                )));
            }
        };

        if !first_key.starts_with(Self::ordering_index_prefix().as_bytes()) {
            return Ok(Some(Vec::new()));
        }

        let mut results = Vec::new();
        if Self::push_ordering_candidate(
            first_key,
            &normalized_value,
            greater_or_equal,
            &mut results,
        )? {
            for (key, _value) in cursor.iter() {
                if !key.starts_with(Self::ordering_index_prefix().as_bytes()) {
                    break;
                }
                if !Self::push_ordering_candidate(
                    key,
                    &normalized_value,
                    greater_or_equal,
                    &mut results,
                )? {
                    break;
                }
            }
        }

        Ok(Some(results))
    }

    fn push_ordering_candidate(
        key: &[u8],
        target_value: &str,
        greater_or_equal: bool,
        results: &mut Vec<String>,
    ) -> Result<bool, BackendError> {
        let Some((value, dn)) = Self::ordering_index_key_parts(key)? else {
            return Ok(false);
        };

        let in_range = if greater_or_equal {
            value >= target_value
        } else {
            value <= target_value
        };

        if in_range {
            results.push(dn.to_string());
            Ok(true)
        } else {
            Ok(greater_or_equal)
        }
    }

    fn load_entries_by_dns_in_txn(
        &self,
        txn: &lmdb::RoTransaction<'_>,
        dns: &[String],
        base_dn: &str,
        scope: SearchScope,
        dedupe_dns: bool,
    ) -> Result<Vec<DirectoryEntry>, BackendError> {
        self.load_entries_by_dns_in_txn_filtering(txn, dns, base_dn, scope, dedupe_dns, |_| {
            Ok(true)
        })
    }

    fn load_entries_by_dns_in_txn_filtering<F>(
        &self,
        txn: &lmdb::RoTransaction<'_>,
        dns: &[String],
        base_dn: &str,
        scope: SearchScope,
        dedupe_dns: bool,
        mut include_entry: F,
    ) -> Result<Vec<DirectoryEntry>, BackendError>
    where
        F: FnMut(&StoredEntry) -> Result<bool, BackendError>,
    {
        let base_components =
            (scope != SearchScope(2)).then(|| Self::scope_base_components(base_dn));
        let mut results = Vec::with_capacity(dns.len());
        let mut seen_dns = dedupe_dns.then(|| HashSet::with_capacity(dns.len()));

        for dn in dns {
            if seen_dns
                .as_mut()
                .is_some_and(|seen_dns| !seen_dns.insert(dn.as_str()))
            {
                continue;
            }
            let in_scope = if scope == SearchScope(2) {
                Self::entry_in_subtree_scope(dn, base_dn)
            } else {
                Self::entry_in_scope_with_base_components(
                    dn,
                    base_components.as_deref().unwrap_or(&[]),
                    scope,
                )
            };
            if !in_scope {
                continue;
            }
            let entry_bytes = match txn.get(self.entries_db, &dn.as_bytes()) {
                Ok(bytes) => bytes,
                Err(lmdb::Error::NotFound) => continue,
                Err(e) => return Err(BackendError::Storage(format!("Failed to get entry: {}", e))),
            };
            let entry = Self::deserialize_stored_entry(entry_bytes)?;
            if !include_entry(&entry)? {
                continue;
            }
            results.push(entry.to_directory_entry());
        }

        Ok(results)
    }

    fn stored_entry_matches_normalized_substring(
        entry: &StoredEntry,
        attribute: &str,
        normalized_parts: &[SearchSubstringPart],
        plan: &AttributeIndexPlan,
    ) -> Result<bool, BackendError> {
        let Some(values) = entry.attributes.get(attribute) else {
            return Ok(false);
        };

        for value in values {
            let normalized_value = plan.normalize_substring_value(value)?;
            if Self::normalized_substring_matches(&normalized_value, normalized_parts) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn normalized_substring_matches(value: &str, parts: &[SearchSubstringPart]) -> bool {
        let mut remainder = value;

        for part in parts {
            match part {
                SearchSubstringPart::Initial(segment) => {
                    let Some(next_remainder) = remainder.strip_prefix(segment) else {
                        return false;
                    };
                    remainder = next_remainder;
                }
                SearchSubstringPart::Any(segment) => {
                    if segment.is_empty() {
                        continue;
                    }
                    let Some(index) = remainder.find(segment) else {
                        return false;
                    };
                    remainder = &remainder[index + segment.len()..];
                }
                SearchSubstringPart::Final(segment) => return remainder.ends_with(segment),
            }
        }

        true
    }

    fn search_entries_uncovered_report(
        &self,
        base_dn: &str,
        scope: SearchScope,
    ) -> Result<SearchEntriesWithHintReport, BackendError> {
        Ok(SearchEntriesWithHintReport {
            entries: self
                .search_entries_internal(base_dn, scope)?
                .into_iter()
                .map(|entry| entry.to_directory_entry())
                .collect(),
            hint_covers_filter: false,
        })
    }

    /// Check if an attribute is indexed
    pub fn is_indexed(&self, attribute: &str) -> bool {
        self.index_plan.attribute_plan(attribute).is_some()
    }

    /// Check if an attribute has a specific index type configured.
    pub fn has_attribute_index(&self, attribute: &str, index_type: IndexType) -> bool {
        self.has_index_type(attribute, index_type)
    }

    fn has_index_type(&self, attribute: &str, index_type: IndexType) -> bool {
        self.index_plan.has_index_type(attribute, index_type)
    }

    pub fn attribute_index_readiness(&self) -> Result<Vec<AttributeIndexReadiness>, BackendError> {
        let txn = self.env.begin_ro_txn().map_err(|e| {
            BackendError::Storage(format!(
                "Failed to begin attribute index readiness txn: {}",
                e
            ))
        })?;
        let configured_attributes = self.index_plan.config_value();
        let config_ready = match txn.get(
            self.metadata_db,
            &ATTRIBUTE_INDEX_CONFIG_METADATA_KEY.as_bytes(),
        ) {
            Ok(value) => value == configured_attributes.as_bytes(),
            Err(lmdb::Error::NotFound) => false,
            Err(e) => {
                return Err(BackendError::Storage(format!(
                    "Failed to read attribute index config metadata: {}",
                    e
                )));
            }
        };

        let mut readiness = Vec::new();
        for (attribute, plan) in &self.index_plan.attributes {
            let metadata_key = Self::attribute_index_metadata_key(attribute);
            let attribute_ready = match txn.get(self.metadata_db, &metadata_key.as_bytes()) {
                Ok(value) => value == ATTRIBUTE_INDEX_VERSION,
                Err(lmdb::Error::NotFound) => false,
                Err(e) => {
                    return Err(BackendError::Storage(format!(
                        "Failed to read attribute index readiness for {}: {}",
                        attribute, e
                    )));
                }
            };
            readiness.push(AttributeIndexReadiness {
                attribute: attribute.clone(),
                index_types: plan.index_types.iter().copied().collect(),
                ready: config_ready && attribute_ready,
            });
        }

        Ok(readiness)
    }

    pub fn configured_max_readers(&self) -> u32 {
        self.max_readers
    }

    pub fn configured_entry_cache_capacity(&self) -> usize {
        self.entry_cache.stats().capacity
    }

    pub fn entry_cache_stats(&self) -> EntryCacheStats {
        self.entry_cache.stats()
    }

    pub fn auth_cache_stats(&self) -> AuthCredentialCacheStats {
        self.auth_cache.stats()
    }

    pub fn set_metrics(&mut self, metrics: Option<Arc<MetricsCollector>>) {
        self.metrics = metrics;
        self.record_auth_cache_metrics();
    }

    fn record_auth_cache_metrics(&self) {
        if let Some(metrics) = self.metrics.as_ref() {
            let stats = self.auth_cache.stats();
            metrics.record_auth_cache_stats(
                stats.capacity as u64,
                stats.len as u64,
                stats.hits,
                stats.misses,
                stats.evictions,
            );
        }
    }
}

#[async_trait]
impl DirectoryBackend for LmdbBackend {
    async fn authenticate(&self, dn: &str, password: &[u8]) -> Result<bool, BackendError> {
        let normalized_dn = Self::normalize_dn(dn);

        if let Some(record) = self.auth_cache.get(&normalized_dn) {
            let result = Self::verify_ssha512_record(password, &record);
            self.record_auth_cache_metrics();
            return Ok(result);
        }

        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| BackendError::Storage(format!("Failed to begin read txn: {}", e)))?;

        log::debug!("Authentication cache miss - DN: {dn}, Normalized: {normalized_dn}");

        // Get actual DN from index
        let actual_dn = match txn.get(self.dn_index_db, &normalized_dn.as_bytes()) {
            Ok(bytes) => String::from_utf8_lossy(bytes).to_string(),
            Err(lmdb::Error::NotFound) => {
                log::debug!("DN not found in index: {}", normalized_dn);
                self.record_auth_cache_metrics();
                return Ok(false);
            }
            Err(e) => return Err(BackendError::Storage(format!("DN lookup failed: {}", e))),
        };

        // Get password hash
        match txn.get(self.passwords_db, &actual_dn.as_bytes()) {
            Ok(stored_password_bytes) => {
                let stored_password_str = String::from_utf8_lossy(stored_password_bytes);
                let Some(record) = Self::decode_ssha512_hash(&stored_password_str) else {
                    log::debug!("Unsupported password hash format for DN: {}", actual_dn);
                    self.record_auth_cache_metrics();
                    return Ok(false);
                };
                let record = Arc::new(record);
                self.auth_cache.insert(&normalized_dn, Arc::clone(&record));
                let result = Self::verify_ssha512_record(password, &record);
                self.record_auth_cache_metrics();
                Ok(result)
            }
            Err(lmdb::Error::NotFound) => {
                log::debug!("Password not found for DN: {}", actual_dn);
                self.record_auth_cache_metrics();
                Ok(false)
            }
            Err(e) => Err(BackendError::Storage(format!(
                "Password lookup failed: {}",
                e
            ))),
        }
    }

    async fn record_authentication_success(&self, dn: &str) -> Result<bool, BackendError> {
        self.record_account_authentication(dn, |attrs, csn| attrs.record_successful_login(csn))
            .await
    }

    async fn record_authentication_failure(&self, dn: &str) -> Result<bool, BackendError> {
        self.record_account_authentication(dn, |attrs, csn| attrs.record_failed_login(csn))
            .await
    }

    async fn replace_operational_attributes(
        &self,
        dn: &str,
        operational_attributes: OperationalAttributes,
    ) -> Result<(), BackendError> {
        let _lock = self.write_lock.write().await;
        let mut txn = self
            .env
            .begin_rw_txn()
            .map_err(|e| BackendError::Storage(format!("Failed to begin write txn: {}", e)))?;
        let normalized_dn = Self::normalize_dn(dn);
        let actual_dn = match txn.get(self.dn_index_db, &normalized_dn.as_bytes()) {
            Ok(bytes) => String::from_utf8_lossy(bytes).to_string(),
            Err(lmdb::Error::NotFound) => return Err(BackendError::NotFound),
            Err(e) => return Err(BackendError::Storage(format!("DN lookup failed: {}", e))),
        };
        let entry_bytes = txn
            .get(self.entries_db, &actual_dn.as_bytes())
            .map_err(|e| BackendError::Storage(format!("Failed to get entry: {}", e)))?;
        let mut entry = Self::deserialize_stored_entry(entry_bytes)?;
        entry.operational_attributes = operational_attributes;
        entry.modified_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let entry_bytes = bincode::serialize(&entry)
            .map_err(|e| BackendError::Storage(format!("Failed to serialize entry: {}", e)))?;
        txn.put(
            self.entries_db,
            &actual_dn.as_bytes(),
            &entry_bytes,
            WriteFlags::empty(),
        )
        .map_err(|e| BackendError::Storage(format!("Failed to write entry: {}", e)))?;

        txn.commit()
            .map_err(|e| BackendError::Storage(format!("Failed to commit txn: {}", e)))?;
        self.entry_cache.invalidate(&normalized_dn);
        Ok(())
    }

    async fn get_entry(&self, dn: &str) -> Result<Option<DirectoryEntry>, BackendError> {
        Ok(self.get_entry_internal(dn)?.map(|e| e.to_directory_entry()))
    }

    async fn add_entry(
        &self,
        entry: DirectoryEntry,
        password: Vec<u8>,
    ) -> Result<(), BackendError> {
        self.add_entry_internal(entry, password, None).await
    }

    async fn add_entry_with_actor(
        &self,
        entry: DirectoryEntry,
        password: Vec<u8>,
        actor_dn: Option<String>,
    ) -> Result<(), BackendError> {
        self.add_entry_internal(entry, password, actor_dn.as_deref())
            .await
    }

    async fn delete_entry(&self, dn: &str) -> Result<(), BackendError> {
        let _lock = self.write_lock.write().await;

        let mut txn = self
            .env
            .begin_rw_txn()
            .map_err(|e| BackendError::Storage(format!("Failed to begin write txn: {}", e)))?;

        let normalized_dn = Self::normalize_dn(dn);

        // Get actual DN
        let actual_dn = match txn.get(self.dn_index_db, &normalized_dn.as_bytes()) {
            Ok(bytes) => String::from_utf8_lossy(bytes).to_string(),
            Err(lmdb::Error::NotFound) => return Err(BackendError::NotFound),
            Err(e) => return Err(BackendError::Storage(format!("DN lookup failed: {}", e))),
        };

        // Get entry to remove from attribute indexes
        let entry_bytes = txn
            .get(self.entries_db, &actual_dn.as_bytes())
            .map_err(|e| BackendError::Storage(format!("Failed to get entry: {}", e)))?;
        let stored_entry = Self::deserialize_stored_entry(entry_bytes)?;

        // Remove from attribute indexes
        self.remove_attribute_indexes(&mut txn, &actual_dn, &stored_entry.attributes)?;

        // Delete entry
        txn.del(self.entries_db, &actual_dn.as_bytes(), None)
            .map_err(|e| BackendError::Storage(format!("Failed to delete entry: {}", e)))?;

        // Delete password (if it exists)
        txn.del(self.passwords_db, &actual_dn.as_bytes(), None)
            .or_else(|e| match e {
                lmdb::Error::NotFound => Ok(()), // No password, that's fine
                _ => Err(BackendError::Storage(
                    "Failed to delete password".to_string(),
                )),
            })?;

        // Delete DN index
        txn.del(self.dn_index_db, &normalized_dn.as_bytes(), None)
            .map_err(|e| BackendError::Storage(format!("Failed to delete DN index: {}", e)))?;

        txn.commit()
            .map_err(|e| BackendError::Storage(format!("Failed to commit txn: {}", e)))?;

        self.entry_cache.invalidate(&normalized_dn);
        self.auth_cache.invalidate(&normalized_dn);
        self.record_auth_cache_metrics();
        Ok(())
    }

    async fn modify_entry(
        &self,
        dn: &str,
        modifications: Vec<Modification>,
    ) -> Result<(), BackendError> {
        self.modify_entry_internal(dn, modifications, None).await
    }

    async fn modify_entry_with_actor(
        &self,
        dn: &str,
        modifications: Vec<Modification>,
        actor_dn: Option<String>,
    ) -> Result<(), BackendError> {
        self.modify_entry_internal(dn, modifications, actor_dn.as_deref())
            .await
    }

    async fn compare_attribute(
        &self,
        dn: &str,
        attribute: &str,
        value: &str,
    ) -> Result<bool, BackendError> {
        let entry = self.get_entry_internal(dn)?.ok_or(BackendError::NotFound)?;

        let attribute = ldap_attribute_key(attribute);
        Ok(entry
            .attributes
            .get(attribute.as_ref())
            .map(|values| values.iter().any(|v| v == value))
            .unwrap_or(false))
    }

    async fn rename_entry(
        &self,
        dn: &str,
        new_rdn: &str,
        delete_old: bool,
        new_superior: Option<String>,
    ) -> Result<(), BackendError> {
        self.rename_entry_internal(dn, new_rdn, delete_old, new_superior, None)
            .await
    }

    async fn rename_entry_with_actor(
        &self,
        dn: &str,
        new_rdn: &str,
        delete_old: bool,
        new_superior: Option<String>,
        actor_dn: Option<String>,
    ) -> Result<(), BackendError> {
        self.rename_entry_internal(dn, new_rdn, delete_old, new_superior, actor_dn.as_deref())
            .await
    }

    async fn search_entries(
        &self,
        base_dn: &str,
        scope: SearchScope,
    ) -> Result<Vec<DirectoryEntry>, BackendError> {
        Ok(self
            .search_entries_internal(base_dn, scope)?
            .into_iter()
            .map(|e| e.to_directory_entry())
            .collect())
    }

    async fn search_entries_paginated(
        &self,
        base_dn: &str,
        scope: SearchScope,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<DirectoryEntry>, BackendError> {
        let entries = self.search_entries_paginated_internal(base_dn, scope, offset, limit)?;
        Ok(entries
            .into_iter()
            .map(|entry| entry.to_directory_entry())
            .collect())
    }

    async fn count_entries(
        &self,
        base_dn: &str,
        scope: SearchScope,
    ) -> Result<usize, BackendError> {
        self.count_entries_internal(base_dn, scope)
    }

    async fn search_entries_with_hint(
        &self,
        base_dn: &str,
        scope: SearchScope,
        hint: Option<SearchCandidateHint>,
    ) -> Result<Vec<DirectoryEntry>, BackendError> {
        Ok(self
            .search_entries_with_hint_report(base_dn, scope, hint)
            .await?
            .entries)
    }

    async fn search_entries_with_hint_report(
        &self,
        base_dn: &str,
        scope: SearchScope,
        hint: Option<SearchCandidateHint>,
    ) -> Result<SearchEntriesWithHintReport, BackendError> {
        let Some(hint) = hint else {
            return self.search_entries_uncovered_report(base_dn, scope);
        };

        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| BackendError::Storage(format!("Failed to begin read txn: {}", e)))?;

        let (candidates, hint_covers_filter, dedupe_dns) = match hint {
            SearchCandidateHint::Equality { attribute, value } => {
                let Some(candidates) = self.search_by_index_in_txn(&txn, &attribute, &value)?
                else {
                    drop(txn);
                    return self.search_entries_uncovered_report(base_dn, scope);
                };
                (candidates, true, false)
            }
            SearchCandidateHint::Present { attribute } => {
                let Some(candidates) = self.search_present_by_index_in_txn(&txn, &attribute)?
                else {
                    drop(txn);
                    return self.search_entries_uncovered_report(base_dn, scope);
                };
                (candidates, true, false)
            }
            SearchCandidateHint::Substring { attribute, parts } => {
                let Some(candidates) =
                    self.search_substring_by_index_in_txn(&txn, &attribute, &parts)?
                else {
                    drop(txn);
                    return self.search_entries_uncovered_report(base_dn, scope);
                };
                let Some(plan) = self
                    .index_plan
                    .attribute_plan_normalized(&candidates.attribute)
                else {
                    drop(txn);
                    return self.search_entries_uncovered_report(base_dn, scope);
                };
                return Ok(SearchEntriesWithHintReport {
                    entries: self.load_entries_by_dns_in_txn_filtering(
                        &txn,
                        &candidates.dns,
                        base_dn,
                        scope,
                        false,
                        |entry| {
                            Self::stored_entry_matches_normalized_substring(
                                entry,
                                &candidates.attribute,
                                &candidates.normalized_parts,
                                plan,
                            )
                        },
                    )?,
                    hint_covers_filter: false,
                });
            }
            SearchCandidateHint::GreaterOrEqual { attribute, value } => {
                let Some(candidates) =
                    self.search_ordering_by_index_in_txn(&txn, &attribute, &value, true)?
                else {
                    drop(txn);
                    return self.search_entries_uncovered_report(base_dn, scope);
                };
                (candidates, true, true)
            }
            SearchCandidateHint::LessOrEqual { attribute, value } => {
                let Some(candidates) =
                    self.search_ordering_by_index_in_txn(&txn, &attribute, &value, false)?
                else {
                    drop(txn);
                    return self.search_entries_uncovered_report(base_dn, scope);
                };
                (candidates, true, true)
            }
        };

        Ok(SearchEntriesWithHintReport {
            entries: self.load_entries_by_dns_in_txn(
                &txn,
                &candidates,
                base_dn,
                scope,
                dedupe_dns,
            )?,
            hint_covers_filter,
        })
    }

    async fn get_context_csn(&self) -> Result<Option<crate::csn::Csn>, BackendError> {
        let txn = self.env.begin_ro_txn().map_err(|e| {
            BackendError::Storage(format!("Failed to begin read transaction: {}", e))
        })?;

        match txn.get(self.metadata_db, &b"context_csn") {
            Ok(bytes) => {
                // Deserialize CSN from stored bytes
                let csn_string = std::str::from_utf8(bytes).map_err(|e| {
                    BackendError::Storage(format!("Invalid UTF-8 in contextCSN: {}", e))
                })?;
                let csn = crate::csn::Csn::parse(csn_string).map_err(|e| {
                    BackendError::Storage(format!("Failed to parse contextCSN: {}", e))
                })?;
                Ok(Some(csn))
            }
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(BackendError::Storage(format!(
                "Failed to read contextCSN: {}",
                e
            ))),
        }
    }

    async fn set_context_csn(&self, csn: crate::csn::Csn) -> Result<(), BackendError> {
        let _lock = self.write_lock.write().await;

        let mut txn = self.env.begin_rw_txn().map_err(|e| {
            BackendError::Storage(format!("Failed to begin write transaction: {}", e))
        })?;

        // Serialize CSN to LDAP string format
        let csn_string = csn.to_ldap_string();

        txn.put(
            self.metadata_db,
            &b"context_csn",
            &csn_string.as_bytes(),
            lmdb::WriteFlags::empty(),
        )
        .map_err(|e| BackendError::Storage(format!("Failed to write contextCSN: {}", e)))?;

        txn.commit()
            .map_err(|e| BackendError::Storage(format!("Failed to commit contextCSN: {}", e)))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn schema_with_matching_rule_attrs() -> LdapSchema {
        let mut schema = LdapSchema::with_core_schema();
        schema
            .load_ldif_str(
                "
dn: cn=schema
attributeTypes: ( 1.3.6.1.4.1.55555.40.1 NAME 'exampleNumber' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.55555.40.2 NAME 'exampleExactCode' EQUALITY caseExactMatch SUBSTR caseExactSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeTypes: ( 1.3.6.1.4.1.55555.40.3 NAME 'exampleFlexibleCode' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
",
            )
            .unwrap();
        schema
    }

    #[test]
    fn substring_query_tokens_use_bounded_spread_across_long_segments() {
        let tokens = LmdbBackend::substring_query_tokens(&[SearchSubstringPart::Any(
            "fixture user 000000".to_string(),
        )]);

        assert!(tokens.len() <= SUBSTRING_QUERY_MAX_TOKENS);
        assert!(tokens.contains(&"fix".to_string()));
        assert!(tokens.contains(&"000".to_string()));
    }

    #[tokio::test]
    async fn test_lmdb_backend_create() {
        let dir = tempdir().unwrap();
        let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();
        assert!(backend._db_path.exists());
    }

    #[tokio::test]
    async fn test_lmdb_backend_add_and_get() {
        let dir = tempdir().unwrap();
        let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

        let mut attributes = HashMap::new();
        attributes.insert("cn".to_string(), vec!["test".to_string()]);
        let entry = DirectoryEntry::new("cn=test,dc=example,dc=org", attributes);

        backend
            .add_entry(entry.clone(), b"password".to_vec())
            .await
            .unwrap();

        let retrieved = backend
            .get_entry("cn=test,dc=example,dc=org")
            .await
            .unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().dn, "cn=test,dc=example,dc=org");
    }

    #[tokio::test]
    async fn test_lmdb_backend_case_insensitive_lookup() {
        let dir = tempdir().unwrap();
        let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

        let mut attributes = HashMap::new();
        attributes.insert("cn".to_string(), vec!["test".to_string()]);
        let entry = DirectoryEntry::new("cn=test,dc=example,dc=org", attributes);

        backend
            .add_entry(entry, b"password".to_vec())
            .await
            .unwrap();

        // Test case-insensitive lookup
        let retrieved = backend
            .get_entry("CN=TEST,DC=EXAMPLE,DC=ORG")
            .await
            .unwrap();
        assert!(retrieved.is_some());
    }

    #[tokio::test]
    async fn test_lmdb_backend_authenticate() {
        let dir = tempdir().unwrap();
        let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

        let mut attributes = HashMap::new();
        attributes.insert("cn".to_string(), vec!["test".to_string()]);
        let entry = DirectoryEntry::new("cn=test,dc=example,dc=org", attributes);

        backend.add_entry(entry, b"secret".to_vec()).await.unwrap();

        assert!(
            backend
                .authenticate("cn=test,dc=example,dc=org", b"secret")
                .await
                .unwrap()
        );
        assert!(
            !backend
                .authenticate("cn=test,dc=example,dc=org", b"wrong")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_auth_cache_records_hits_on_repeated_binds() {
        let dir = tempdir().unwrap();
        let backend = LmdbBackend::new_with_runtime_and_cache_config(
            dir.path(),
            100,
            1,
            IndexConfig::default(),
            126,
            2,
        )
        .unwrap();

        let mut attributes = HashMap::new();
        attributes.insert("cn".to_string(), vec!["cached".to_string()]);
        let entry = DirectoryEntry::new("cn=cached,dc=example,dc=org", attributes);
        backend.add_entry(entry, b"secret".to_vec()).await.unwrap();

        assert_eq!(backend.auth_cache_stats().len, 0);
        assert!(
            backend
                .authenticate("cn=cached,dc=example,dc=org", b"secret")
                .await
                .unwrap()
        );
        let after_first_bind = backend.auth_cache_stats();
        assert_eq!(after_first_bind.hits, 0);
        assert_eq!(after_first_bind.misses, 1);
        assert_eq!(after_first_bind.len, 1);

        assert!(
            backend
                .authenticate("CN=CACHED,DC=EXAMPLE,DC=ORG", b"secret")
                .await
                .unwrap()
        );
        let after_second_bind = backend.auth_cache_stats();
        assert_eq!(after_second_bind.hits, 1);
        assert_eq!(after_second_bind.misses, 1);
    }

    #[tokio::test]
    async fn test_auth_cache_invalidates_after_password_modify() {
        let dir = tempdir().unwrap();
        let backend = LmdbBackend::new_with_runtime_and_cache_config(
            dir.path(),
            100,
            1,
            IndexConfig::default(),
            126,
            2,
        )
        .unwrap();

        let mut attributes = HashMap::new();
        attributes.insert("cn".to_string(), vec!["cached".to_string()]);
        let entry = DirectoryEntry::new("cn=cached,dc=example,dc=org", attributes);
        backend
            .add_entry(entry, b"old-secret".to_vec())
            .await
            .unwrap();

        assert!(
            backend
                .authenticate("cn=cached,dc=example,dc=org", b"old-secret")
                .await
                .unwrap()
        );
        backend
            .modify_entry(
                "cn=cached,dc=example,dc=org",
                vec![Modification {
                    operation: ModifyOperation::Replace,
                    attribute: "userPassword".to_string(),
                    values: vec!["new-secret".to_string()],
                }],
            )
            .await
            .unwrap();

        assert!(
            !backend
                .authenticate("cn=cached,dc=example,dc=org", b"old-secret")
                .await
                .unwrap()
        );
        assert!(
            backend
                .authenticate("cn=cached,dc=example,dc=org", b"new-secret")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_non_password_modify_preserves_auth_cache_and_credentials() {
        let dir = tempdir().unwrap();
        let backend = LmdbBackend::new_with_runtime_and_cache_config(
            dir.path(),
            100,
            1,
            IndexConfig::default(),
            126,
            2,
        )
        .unwrap();

        let mut attributes = HashMap::new();
        attributes.insert("cn".to_string(), vec!["cached".to_string()]);
        let entry = DirectoryEntry::new("cn=cached,dc=example,dc=org", attributes);
        backend.add_entry(entry, b"secret".to_vec()).await.unwrap();

        assert!(
            backend
                .authenticate("cn=cached,dc=example,dc=org", b"secret")
                .await
                .unwrap()
        );
        backend
            .modify_entry(
                "cn=cached,dc=example,dc=org",
                vec![Modification {
                    operation: ModifyOperation::Replace,
                    attribute: "description".to_string(),
                    values: vec!["non-password update".to_string()],
                }],
            )
            .await
            .unwrap();

        assert!(
            backend
                .authenticate("cn=cached,dc=example,dc=org", b"secret")
                .await
                .unwrap()
        );
        let stats = backend.auth_cache_stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.len, 1);
    }

    #[tokio::test]
    async fn test_auth_cache_invalidates_after_delete() {
        let dir = tempdir().unwrap();
        let backend = LmdbBackend::new_with_runtime_and_cache_config(
            dir.path(),
            100,
            1,
            IndexConfig::default(),
            126,
            2,
        )
        .unwrap();

        let mut attributes = HashMap::new();
        attributes.insert("cn".to_string(), vec!["cached".to_string()]);
        let entry = DirectoryEntry::new("cn=cached,dc=example,dc=org", attributes);
        backend.add_entry(entry, b"secret".to_vec()).await.unwrap();
        assert!(
            backend
                .authenticate("cn=cached,dc=example,dc=org", b"secret")
                .await
                .unwrap()
        );

        backend
            .delete_entry("cn=cached,dc=example,dc=org")
            .await
            .unwrap();

        assert_eq!(backend.auth_cache_stats().len, 0);
        assert!(
            !backend
                .authenticate("cn=cached,dc=example,dc=org", b"secret")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_auth_cache_invalidates_after_rename() {
        let dir = tempdir().unwrap();
        let backend = LmdbBackend::new_with_runtime_and_cache_config(
            dir.path(),
            100,
            1,
            IndexConfig::default(),
            126,
            2,
        )
        .unwrap();

        let mut attributes = HashMap::new();
        attributes.insert("cn".to_string(), vec!["old".to_string()]);
        let entry = DirectoryEntry::new("cn=old,dc=example,dc=org", attributes);
        backend.add_entry(entry, b"secret".to_vec()).await.unwrap();
        assert!(
            backend
                .authenticate("cn=old,dc=example,dc=org", b"secret")
                .await
                .unwrap()
        );

        backend
            .rename_entry("cn=old,dc=example,dc=org", "cn=new", true, None)
            .await
            .unwrap();

        assert!(
            !backend
                .authenticate("cn=old,dc=example,dc=org", b"secret")
                .await
                .unwrap()
        );
        assert!(
            backend
                .authenticate("cn=new,dc=example,dc=org", b"secret")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_auth_cache_invalidates_after_prehashed_password_update() {
        let dir = tempdir().unwrap();
        let backend = LmdbBackend::new_with_runtime_and_cache_config(
            dir.path(),
            100,
            1,
            IndexConfig::default(),
            126,
            2,
        )
        .unwrap();

        let mut attributes = HashMap::new();
        attributes.insert("cn".to_string(), vec!["cached".to_string()]);
        let entry = DirectoryEntry::new("cn=cached,dc=example,dc=org", attributes);
        backend
            .add_entry(entry, b"old-secret".to_vec())
            .await
            .unwrap();
        assert!(
            backend
                .authenticate("cn=cached,dc=example,dc=org", b"old-secret")
                .await
                .unwrap()
        );

        let new_hash = LmdbBackend::create_ssha512(b"new-secret");
        backend
            .set_prehashed_password("cn=cached,dc=example,dc=org", &new_hash)
            .await
            .unwrap();

        assert!(
            !backend
                .authenticate("cn=cached,dc=example,dc=org", b"old-secret")
                .await
                .unwrap()
        );
        assert!(
            backend
                .authenticate("cn=cached,dc=example,dc=org", b"new-secret")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_index_config_defaults() {
        let config = IndexConfig::default();
        assert!(config.indexed_attributes.contains(&"cn".to_string()));
        assert!(config.indexed_attributes.contains(&"uid".to_string()));
        assert!(config.indexed_attributes.contains(&"mail".to_string()));
    }

    #[tokio::test]
    async fn test_is_indexed() {
        let dir = tempdir().unwrap();
        let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

        // Default indexed attributes
        assert!(backend.is_indexed("cn"));
        assert!(backend.is_indexed("CN")); // Case insensitive
        assert!(backend.is_indexed("uid"));
        assert!(backend.is_indexed("mail"));

        // Not indexed by default
        assert!(!backend.is_indexed("description"));
    }

    #[tokio::test]
    async fn test_attribute_index_on_add() {
        let dir = tempdir().unwrap();
        let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

        // Add entry with indexed attributes
        let mut attributes = HashMap::new();
        attributes.insert("cn".to_string(), vec!["John Doe".to_string()]);
        attributes.insert("uid".to_string(), vec!["jdoe".to_string()]);
        let entry = DirectoryEntry::new("uid=jdoe,dc=example,dc=org", attributes);

        backend.add_entry(entry, vec![]).await.unwrap();

        // Search by indexed attribute
        let results = backend.search_by_index("cn", "John Doe").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "uid=jdoe,dc=example,dc=org");

        // Search by uid
        let results = backend.search_by_index("uid", "jdoe").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "uid=jdoe,dc=example,dc=org");
    }

    #[tokio::test]
    async fn test_attribute_index_multiple_values() {
        let dir = tempdir().unwrap();
        let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

        // Add entry with multiple values for indexed attribute
        let mut attributes = HashMap::new();
        attributes.insert(
            "cn".to_string(),
            vec!["John Doe".to_string(), "J. Doe".to_string()],
        );
        let entry = DirectoryEntry::new("uid=jdoe,dc=example,dc=org", attributes);

        backend.add_entry(entry, vec![]).await.unwrap();

        // Search by first value
        let results = backend.search_by_index("cn", "John Doe").unwrap();
        assert_eq!(results.len(), 1);

        // Search by second value
        let results = backend.search_by_index("cn", "J. Doe").unwrap();
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn test_attribute_index_case_insensitive() {
        let dir = tempdir().unwrap();
        let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

        let mut attributes = HashMap::new();
        attributes.insert("cn".to_string(), vec!["John Doe".to_string()]);
        let entry = DirectoryEntry::new("uid=jdoe,dc=example,dc=org", attributes);

        backend.add_entry(entry, vec![]).await.unwrap();

        // Search with different case
        let results = backend.search_by_index("cn", "john doe").unwrap();
        assert_eq!(results.len(), 1);

        let results = backend.search_by_index("CN", "JOHN DOE").unwrap();
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn test_attribute_index_exact_value_prefix_boundary() {
        let dir = tempdir().unwrap();
        let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

        let mut john_attributes = HashMap::new();
        john_attributes.insert("cn".to_string(), vec!["john".to_string()]);
        let john = DirectoryEntry::new("uid=john,dc=example,dc=org", john_attributes);
        backend.add_entry(john, vec![]).await.unwrap();

        let mut johnny_attributes = HashMap::new();
        johnny_attributes.insert("cn".to_string(), vec!["johnny".to_string()]);
        let johnny = DirectoryEntry::new("uid=johnny,dc=example,dc=org", johnny_attributes);
        backend.add_entry(johnny, vec![]).await.unwrap();

        let results = backend.search_by_index("cn", "john").unwrap();
        assert_eq!(results, vec!["uid=john,dc=example,dc=org".to_string()]);

        let results = backend.search_by_index("cn", "johnny").unwrap();
        assert_eq!(results, vec!["uid=johnny,dc=example,dc=org".to_string()]);
    }

    #[tokio::test]
    async fn test_attribute_index_multiple_entries() {
        let dir = tempdir().unwrap();
        let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

        // Add multiple entries with same attribute value
        for i in 1..=3 {
            let mut attributes = HashMap::new();
            attributes.insert("cn".to_string(), vec![format!("User {}", i)]);
            attributes.insert("ou".to_string(), vec!["Engineering".to_string()]);
            let entry = DirectoryEntry::new(format!("uid=user{},dc=example,dc=org", i), attributes);
            backend.add_entry(entry, vec![]).await.unwrap();
        }

        // Search should return all entries with ou=Engineering
        let results = backend.search_by_index("ou", "Engineering").unwrap();
        assert_eq!(results.len(), 3);
    }

    #[tokio::test]
    async fn test_presence_index_returns_each_dn_once_for_multivalue_attributes() {
        let dir = tempdir().unwrap();
        let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

        let mut alice_attributes = HashMap::new();
        alice_attributes.insert(
            "mail".to_string(),
            vec![
                "alice@example.org".to_string(),
                "alice.secondary@example.org".to_string(),
            ],
        );
        let alice = DirectoryEntry::new("uid=alice,dc=example,dc=org", alice_attributes);
        backend.add_entry(alice, vec![]).await.unwrap();

        let mut bob_attributes = HashMap::new();
        bob_attributes.insert("mail".to_string(), vec!["bob@example.org".to_string()]);
        let bob = DirectoryEntry::new("uid=bob,dc=example,dc=org", bob_attributes);
        backend.add_entry(bob, vec![]).await.unwrap();

        let mut results = backend.search_present_by_index("mail").unwrap();
        results.sort();

        assert_eq!(
            results,
            vec![
                "uid=alice,dc=example,dc=org".to_string(),
                "uid=bob,dc=example,dc=org".to_string(),
            ]
        );

        let indexes = backend.attr_indexes.try_read().unwrap();
        let index_db = *indexes.get("mail").unwrap();
        drop(indexes);
        let txn = backend.env.begin_ro_txn().unwrap();
        let mut cursor = txn.open_ro_cursor(index_db).unwrap();
        let presence_prefix = LmdbBackend::presence_index_prefix();
        let mut marker_results =
            LmdbBackend::collect_index_dns_by_prefix(&mut cursor, presence_prefix.as_bytes())
                .unwrap();
        marker_results.sort();
        assert_eq!(marker_results, results);
    }

    #[tokio::test]
    async fn test_attribute_index_update_on_modify() {
        let dir = tempdir().unwrap();
        let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

        // Add entry
        let mut attributes = HashMap::new();
        attributes.insert("cn".to_string(), vec!["Old Name".to_string()]);
        let entry = DirectoryEntry::new("uid=test,dc=example,dc=org", attributes);
        backend.add_entry(entry, vec![]).await.unwrap();

        // Verify old index
        let results = backend.search_by_index("cn", "Old Name").unwrap();
        assert_eq!(results.len(), 1);

        // Modify entry
        let modifications = vec![Modification {
            operation: ModifyOperation::Replace,
            attribute: "cn".to_string(),
            values: vec!["New Name".to_string()],
        }];
        backend
            .modify_entry("uid=test,dc=example,dc=org", modifications)
            .await
            .unwrap();

        // Old value should not be in index
        let results = backend.search_by_index("cn", "Old Name").unwrap();
        assert_eq!(results.len(), 0);

        // New value should be in index
        let results = backend.search_by_index("cn", "New Name").unwrap();
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn test_attribute_index_removed_on_delete() {
        let dir = tempdir().unwrap();
        let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

        // Add entry
        let mut attributes = HashMap::new();
        attributes.insert("cn".to_string(), vec!["Test User".to_string()]);
        let entry = DirectoryEntry::new("uid=test,dc=example,dc=org", attributes);
        backend.add_entry(entry, vec![]).await.unwrap();

        // Verify index exists
        let results = backend.search_by_index("cn", "Test User").unwrap();
        assert_eq!(results.len(), 1);

        // Delete entry
        backend
            .delete_entry("uid=test,dc=example,dc=org")
            .await
            .unwrap();

        // Index should be removed
        let results = backend.search_by_index("cn", "Test User").unwrap();
        assert_eq!(results.len(), 0);
    }

    #[tokio::test]
    async fn test_search_nonindexed_attribute() {
        let dir = tempdir().unwrap();
        let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

        // Add entry with non-indexed attribute
        let mut attributes = HashMap::new();
        attributes.insert("description".to_string(), vec!["Test".to_string()]);
        let entry = DirectoryEntry::new("uid=test,dc=example,dc=org", attributes);
        backend.add_entry(entry, vec![]).await.unwrap();

        // Searching non-indexed attribute returns empty
        let results = backend.search_by_index("description", "Test").unwrap();
        assert_eq!(results.len(), 0);
    }

    #[tokio::test]
    async fn test_custom_index_config() {
        let dir = tempdir().unwrap();
        let config = IndexConfig {
            indexed_attributes: vec!["custom".to_string(), "special".to_string()],
            attribute_indexes: Vec::new(),
        };
        let backend = LmdbBackend::new_with_config(dir.path(), 100, 1, config).unwrap();

        assert!(backend.is_indexed("custom"));
        assert!(backend.is_indexed("special"));
        assert!(!backend.is_indexed("cn")); // Not in custom config

        // Add entry and verify custom index works
        let mut attributes = HashMap::new();
        attributes.insert("custom".to_string(), vec!["value".to_string()]);
        let entry = DirectoryEntry::new("uid=test,dc=example,dc=org", attributes);
        backend.add_entry(entry, vec![]).await.unwrap();

        let results = backend.search_by_index("custom", "value").unwrap();
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn test_custom_index_backfilled_for_existing_entries_on_reopen() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().to_path_buf();

        {
            let backend = LmdbBackend::new_with_config(
                &db_path,
                100,
                1,
                IndexConfig {
                    indexed_attributes: Vec::new(),
                    attribute_indexes: Vec::new(),
                },
            )
            .unwrap();

            let mut attributes = HashMap::new();
            attributes.insert("employeeNumber".to_string(), vec!["12345".to_string()]);
            attributes.insert("cn".to_string(), vec!["Alice".to_string()]);
            let entry = DirectoryEntry::new("uid=alice,dc=example,dc=org", attributes);
            backend.add_entry(entry, vec![]).await.unwrap();

            let results = backend.search_by_index("employeeNumber", "12345").unwrap();
            assert!(results.is_empty());
        }

        let backend = LmdbBackend::new_with_config(
            &db_path,
            100,
            1,
            IndexConfig {
                indexed_attributes: vec!["employeeNumber".to_string()],
                attribute_indexes: Vec::new(),
            },
        )
        .unwrap();

        let results = backend.search_by_index("employeeNumber", "12345").unwrap();
        assert_eq!(results, vec!["uid=alice,dc=example,dc=org".to_string()]);

        let present_results = backend.search_present_by_index("employeeNumber").unwrap();
        assert_eq!(
            present_results,
            vec!["uid=alice,dc=example,dc=org".to_string()]
        );
    }

    #[tokio::test]
    async fn test_custom_index_backfill_handles_attribute_without_existing_values() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().to_path_buf();

        {
            let backend = LmdbBackend::new_with_config(
                &db_path,
                100,
                1,
                IndexConfig {
                    indexed_attributes: Vec::new(),
                    attribute_indexes: Vec::new(),
                },
            )
            .unwrap();

            let mut attributes = HashMap::new();
            attributes.insert("cn".to_string(), vec!["Alice".to_string()]);
            let entry = DirectoryEntry::new("uid=alice,dc=example,dc=org", attributes);
            backend.add_entry(entry, vec![]).await.unwrap();
        }

        let backend = LmdbBackend::new_with_config(
            &db_path,
            100,
            1,
            IndexConfig {
                indexed_attributes: vec!["employeeNumber".to_string()],
                attribute_indexes: Vec::new(),
            },
        )
        .unwrap();

        assert!(backend.is_indexed("employeeNumber"));
        assert!(
            backend
                .search_by_index("employeeNumber", "12345")
                .unwrap()
                .is_empty()
        );
        assert!(
            backend
                .search_present_by_index("employeeNumber")
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn test_reenabled_index_rebuilds_after_disabled_changes() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().to_path_buf();

        {
            let backend = LmdbBackend::new_with_config(
                &db_path,
                100,
                1,
                IndexConfig {
                    indexed_attributes: vec!["custom".to_string()],
                    attribute_indexes: Vec::new(),
                },
            )
            .unwrap();

            let mut attributes = HashMap::new();
            attributes.insert("custom".to_string(), vec!["old".to_string()]);
            let entry = DirectoryEntry::new("uid=test,dc=example,dc=org", attributes);
            backend.add_entry(entry, vec![]).await.unwrap();
            assert_eq!(backend.search_by_index("custom", "old").unwrap().len(), 1);
        }

        {
            let backend = LmdbBackend::new_with_config(
                &db_path,
                100,
                1,
                IndexConfig {
                    indexed_attributes: Vec::new(),
                    attribute_indexes: Vec::new(),
                },
            )
            .unwrap();

            backend
                .modify_entry(
                    "uid=test,dc=example,dc=org",
                    vec![Modification {
                        operation: ModifyOperation::Replace,
                        attribute: "custom".to_string(),
                        values: vec!["new".to_string()],
                    }],
                )
                .await
                .unwrap();

            assert!(backend.search_by_index("custom", "new").unwrap().is_empty());
        }

        let backend = LmdbBackend::new_with_config(
            &db_path,
            100,
            1,
            IndexConfig {
                indexed_attributes: vec!["custom".to_string()],
                attribute_indexes: Vec::new(),
            },
        )
        .unwrap();

        assert!(backend.search_by_index("custom", "old").unwrap().is_empty());
        assert_eq!(
            backend.search_by_index("custom", "new").unwrap(),
            vec!["uid=test,dc=example,dc=org".to_string()]
        );
    }

    #[tokio::test]
    async fn test_runtime_config_applies_indexes_and_max_readers() {
        let dir = tempdir().unwrap();
        let config = IndexConfig {
            indexed_attributes: vec!["departmentnumber".to_string()],
            attribute_indexes: Vec::new(),
        };
        let backend = LmdbBackend::new_with_runtime_config(dir.path(), 100, 1, config, 64).unwrap();

        assert_eq!(backend.configured_max_readers(), 64);
        assert_eq!(
            backend.configured_entry_cache_capacity(),
            DEFAULT_ENTRY_CACHE_CAPACITY
        );
        assert!(backend.is_indexed("departmentNumber"));
        assert!(!backend.is_indexed("cn"));

        let mut attributes = HashMap::new();
        attributes.insert("departmentNumber".to_string(), vec!["42".to_string()]);
        let entry = DirectoryEntry::new("uid=test,dc=example,dc=org", attributes);
        backend.add_entry(entry, vec![]).await.unwrap();

        let results = backend.search_by_index("departmentNumber", "42").unwrap();
        assert_eq!(results, vec!["uid=test,dc=example,dc=org".to_string()]);
    }

    #[tokio::test]
    async fn test_schema_index_plan_normalizes_integer_equality_and_ordering_keys() {
        let dir = tempdir().unwrap();
        let schema = schema_with_matching_rule_attrs();
        let backend = LmdbBackend::new_with_schema_config(
            dir.path(),
            100,
            1,
            IndexConfig {
                indexed_attributes: Vec::new(),
                attribute_indexes: vec![AttributeIndexConfig {
                    attribute: "exampleNumber".to_string(),
                    index_types: vec![IndexType::Equality, IndexType::Ordering],
                }],
            },
            &schema,
        )
        .unwrap();

        for (uid, value) in [("negative", "-1"), ("two", "0002"), ("ten", "10")] {
            let mut attributes = HashMap::new();
            attributes.insert("exampleNumber".to_string(), vec![value.to_string()]);
            let entry = DirectoryEntry::new(format!("uid={uid},dc=example,dc=org"), attributes);
            backend.add_entry(entry, vec![]).await.unwrap();
        }

        assert_eq!(
            backend.search_by_index("exampleNumber", "2").unwrap(),
            vec!["uid=two,dc=example,dc=org".to_string()]
        );

        let greater_or_equal = backend
            .search_entries_with_hint(
                "dc=example,dc=org",
                SearchScope(2),
                Some(SearchCandidateHint::GreaterOrEqual {
                    attribute: "exampleNumber".to_string(),
                    value: "2".to_string(),
                }),
            )
            .await
            .unwrap()
            .into_iter()
            .map(|entry| entry.dn)
            .collect::<Vec<_>>();
        assert_eq!(
            greater_or_equal,
            vec![
                "uid=two,dc=example,dc=org".to_string(),
                "uid=ten,dc=example,dc=org".to_string()
            ]
        );
    }

    #[tokio::test]
    async fn test_schema_index_plan_preserves_case_exact_substring_keys() {
        let dir = tempdir().unwrap();
        let schema = schema_with_matching_rule_attrs();
        let backend = LmdbBackend::new_with_schema_config(
            dir.path(),
            100,
            1,
            IndexConfig {
                indexed_attributes: Vec::new(),
                attribute_indexes: vec![AttributeIndexConfig {
                    attribute: "exampleExactCode".to_string(),
                    index_types: vec![IndexType::Substring],
                }],
            },
            &schema,
        )
        .unwrap();

        for (uid, value) in [("upper", "CaseToken"), ("lower", "casetoken")] {
            let mut attributes = HashMap::new();
            attributes.insert("exampleExactCode".to_string(), vec![value.to_string()]);
            let entry = DirectoryEntry::new(format!("uid={uid},dc=example,dc=org"), attributes);
            backend.add_entry(entry, vec![]).await.unwrap();
        }

        let results = backend
            .search_entries_with_hint(
                "dc=example,dc=org",
                SearchScope(2),
                Some(SearchCandidateHint::Substring {
                    attribute: "exampleExactCode".to_string(),
                    parts: vec![SearchSubstringPart::Any("Case".to_string())],
                }),
            )
            .await
            .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].dn, "uid=upper,dc=example,dc=org");
    }

    #[tokio::test]
    async fn test_attribute_index_readiness_reports_backfilled_schema_indexes() {
        let dir = tempdir().unwrap();
        let schema = schema_with_matching_rule_attrs();
        let backend = LmdbBackend::new_with_schema_config(
            dir.path(),
            100,
            1,
            IndexConfig {
                indexed_attributes: Vec::new(),
                attribute_indexes: vec![AttributeIndexConfig {
                    attribute: "exampleNumber".to_string(),
                    index_types: vec![IndexType::Equality, IndexType::Ordering],
                }],
            },
            &schema,
        )
        .unwrap();

        let readiness = backend.attribute_index_readiness().unwrap();
        assert_eq!(readiness.len(), 1);
        assert_eq!(readiness[0].attribute, "examplenumber");
        assert_eq!(
            readiness[0].index_types,
            vec![IndexType::Equality, IndexType::Ordering]
        );
        assert!(readiness[0].ready);
    }

    #[tokio::test]
    async fn test_bulk_add_entries_marks_attribute_indexes_ready() {
        let dir = tempdir().unwrap();
        let schema = schema_with_matching_rule_attrs();
        let index_config = IndexConfig {
            indexed_attributes: Vec::new(),
            attribute_indexes: vec![AttributeIndexConfig {
                attribute: "exampleNumber".to_string(),
                index_types: vec![IndexType::Equality],
            }],
        };

        {
            let backend = LmdbBackend::new_with_schema_config(
                dir.path(),
                100,
                1,
                index_config.clone(),
                &schema,
            )
            .unwrap();
            let mut attributes = HashMap::new();
            attributes.insert("cn".to_string(), vec!["bulk".to_string()]);
            attributes.insert("exampleNumber".to_string(), vec!["7".to_string()]);
            let entry = DirectoryEntry::new("cn=bulk,dc=example,dc=org", attributes);

            let added = backend
                .bulk_add_entries(vec![(entry, Vec::new())], 100, None, |_| {})
                .await
                .unwrap();

            assert_eq!(added, 1);
            assert!(
                backend
                    .attribute_index_readiness()
                    .unwrap()
                    .into_iter()
                    .all(|index| index.ready)
            );
        }

        let reopened =
            LmdbBackend::new_with_schema_config(dir.path(), 100, 1, index_config, &schema).unwrap();
        assert_eq!(
            reopened.search_by_index("exampleNumber", "7").unwrap(),
            vec!["cn=bulk,dc=example,dc=org".to_string()]
        );
        assert!(
            reopened
                .attribute_index_readiness()
                .unwrap()
                .into_iter()
                .all(|index| index.ready)
        );
    }

    #[tokio::test]
    async fn test_matching_rule_change_rebuilds_existing_index_keys() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().to_path_buf();
        let mut case_ignore_schema = LdapSchema::with_core_schema();
        case_ignore_schema
            .load_ldif_str(
                "
dn: cn=schema
attributeTypes: ( 1.3.6.1.4.1.55555.41.1 NAME 'exampleRuleShift' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
",
            )
            .unwrap();
        let mut case_exact_schema = LdapSchema::with_core_schema();
        case_exact_schema
            .load_ldif_str(
                "
dn: cn=schema
attributeTypes: ( 1.3.6.1.4.1.55555.41.1 NAME 'exampleRuleShift' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
",
            )
            .unwrap();
        let index_config = IndexConfig {
            indexed_attributes: Vec::new(),
            attribute_indexes: vec![AttributeIndexConfig {
                attribute: "exampleRuleShift".to_string(),
                index_types: vec![IndexType::Equality],
            }],
        };

        {
            let backend = LmdbBackend::new_with_schema_config(
                &db_path,
                100,
                1,
                index_config.clone(),
                &case_ignore_schema,
            )
            .unwrap();
            let mut attributes = HashMap::new();
            attributes.insert("exampleRuleShift".to_string(), vec!["Alpha".to_string()]);
            backend
                .add_entry(
                    DirectoryEntry::new("uid=alpha,dc=example,dc=org", attributes),
                    vec![],
                )
                .await
                .unwrap();
            assert_eq!(
                backend
                    .search_by_index("exampleRuleShift", "alpha")
                    .unwrap(),
                vec!["uid=alpha,dc=example,dc=org".to_string()]
            );
        }

        let backend =
            LmdbBackend::new_with_schema_config(&db_path, 100, 1, index_config, &case_exact_schema)
                .unwrap();

        assert!(
            backend
                .search_by_index("exampleRuleShift", "alpha")
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            backend
                .search_by_index("exampleRuleShift", "Alpha")
                .unwrap(),
            vec!["uid=alpha,dc=example,dc=org".to_string()]
        );
    }

    #[tokio::test]
    async fn test_typed_substring_index_hint_uses_index_candidates() {
        let dir = tempdir().unwrap();
        let backend = LmdbBackend::new_with_config(
            dir.path(),
            100,
            1,
            IndexConfig {
                indexed_attributes: Vec::new(),
                attribute_indexes: vec![AttributeIndexConfig {
                    attribute: "description".to_string(),
                    index_types: vec![IndexType::Substring],
                }],
            },
        )
        .unwrap();

        let mut alice_attributes = HashMap::new();
        alice_attributes.insert("description".to_string(), vec!["alpha marker".to_string()]);
        let alice = DirectoryEntry::new("uid=alice,dc=example,dc=org", alice_attributes);
        backend.add_entry(alice, vec![]).await.unwrap();

        let mut bob_attributes = HashMap::new();
        bob_attributes.insert("description".to_string(), vec!["omega".to_string()]);
        let bob = DirectoryEntry::new("uid=bob,dc=example,dc=org", bob_attributes);
        backend.add_entry(bob, vec![]).await.unwrap();

        let mut multi_value_attributes = HashMap::new();
        multi_value_attributes.insert(
            "description".to_string(),
            vec!["plain".to_string(), "zebra finish".to_string()],
        );
        let multi_value =
            DirectoryEntry::new("uid=multi,dc=example,dc=org", multi_value_attributes);
        backend.add_entry(multi_value, vec![]).await.unwrap();

        assert!(
            backend
                .search_by_index("description", "alpha marker")
                .unwrap()
                .is_empty()
        );

        let results = backend
            .search_entries_with_hint(
                "dc=example,dc=org",
                SearchScope(2),
                Some(SearchCandidateHint::Substring {
                    attribute: "description".to_string(),
                    parts: vec![SearchSubstringPart::Any("pha".to_string())],
                }),
            )
            .await
            .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].dn, "uid=alice,dc=example,dc=org");

        let initial_results = backend
            .search_entries_with_hint(
                "dc=example,dc=org",
                SearchScope(2),
                Some(SearchCandidateHint::Substring {
                    attribute: "description".to_string(),
                    parts: vec![SearchSubstringPart::Initial("ALP".to_string())],
                }),
            )
            .await
            .unwrap();

        assert_eq!(initial_results.len(), 1);
        assert_eq!(initial_results[0].dn, "uid=alice,dc=example,dc=org");

        let final_results = backend
            .search_entries_with_hint(
                "dc=example,dc=org",
                SearchScope(2),
                Some(SearchCandidateHint::Substring {
                    attribute: "description".to_string(),
                    parts: vec![SearchSubstringPart::Final("KER".to_string())],
                }),
            )
            .await
            .unwrap();

        assert_eq!(final_results.len(), 1);
        assert_eq!(final_results[0].dn, "uid=alice,dc=example,dc=org");

        let multi_value_results = backend
            .search_entries_with_hint(
                "dc=example,dc=org",
                SearchScope(2),
                Some(SearchCandidateHint::Substring {
                    attribute: "description".to_string(),
                    parts: vec![SearchSubstringPart::Any("BRA".to_string())],
                }),
            )
            .await
            .unwrap();

        assert_eq!(multi_value_results.len(), 1);
        assert_eq!(multi_value_results[0].dn, "uid=multi,dc=example,dc=org");
    }

    #[tokio::test]
    async fn test_typed_substring_index_hint_intersects_multiple_tokens() {
        let dir = tempdir().unwrap();
        let backend = LmdbBackend::new_with_config(
            dir.path(),
            100,
            1,
            IndexConfig {
                indexed_attributes: Vec::new(),
                attribute_indexes: vec![AttributeIndexConfig {
                    attribute: "description".to_string(),
                    index_types: vec![IndexType::Substring],
                }],
            },
        )
        .unwrap();

        for (uid, description) in [
            ("target", "fixture user 000000 alpha"),
            ("same_prefix", "fixture user 999999 alpha"),
            ("same_suffix", "archive user 000000 alpha"),
        ] {
            let mut attributes = HashMap::new();
            attributes.insert("description".to_string(), vec![description.to_string()]);
            backend
                .add_entry(
                    DirectoryEntry::new(format!("uid={uid},dc=example,dc=org"), attributes),
                    vec![],
                )
                .await
                .unwrap();
        }

        let results = backend
            .search_entries_with_hint(
                "dc=example,dc=org",
                SearchScope(2),
                Some(SearchCandidateHint::Substring {
                    attribute: "description".to_string(),
                    parts: vec![SearchSubstringPart::Any("fixture user 000000".to_string())],
                }),
            )
            .await
            .unwrap()
            .into_iter()
            .map(|entry| entry.dn)
            .collect::<Vec<_>>();

        assert_eq!(results, vec!["uid=target,dc=example,dc=org".to_string()]);
    }

    #[tokio::test]
    async fn test_typed_ordering_index_backfilled_for_existing_entries() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().to_path_buf();

        {
            let backend = LmdbBackend::new_with_config(
                &db_path,
                100,
                1,
                IndexConfig {
                    indexed_attributes: Vec::new(),
                    attribute_indexes: Vec::new(),
                },
            )
            .unwrap();

            for (uid, serial) in [("low", "010"), ("mid", "020"), ("high", "030")] {
                let mut attributes = HashMap::new();
                attributes.insert("serialNumber".to_string(), vec![serial.to_string()]);
                let entry = DirectoryEntry::new(format!("uid={uid},dc=example,dc=org"), attributes);
                backend.add_entry(entry, vec![]).await.unwrap();
            }
        }

        let backend = LmdbBackend::new_with_config(
            &db_path,
            100,
            1,
            IndexConfig {
                indexed_attributes: Vec::new(),
                attribute_indexes: vec![AttributeIndexConfig {
                    attribute: "serialNumber".to_string(),
                    index_types: vec![IndexType::Ordering],
                }],
            },
        )
        .unwrap();

        let greater_or_equal = backend
            .search_entries_with_hint(
                "dc=example,dc=org",
                SearchScope(2),
                Some(SearchCandidateHint::GreaterOrEqual {
                    attribute: "serialNumber".to_string(),
                    value: "020".to_string(),
                }),
            )
            .await
            .unwrap()
            .into_iter()
            .map(|entry| entry.dn)
            .collect::<Vec<_>>();
        assert_eq!(
            greater_or_equal,
            vec![
                "uid=mid,dc=example,dc=org".to_string(),
                "uid=high,dc=example,dc=org".to_string()
            ]
        );

        let less_or_equal = backend
            .search_entries_with_hint(
                "dc=example,dc=org",
                SearchScope(2),
                Some(SearchCandidateHint::LessOrEqual {
                    attribute: "serialNumber".to_string(),
                    value: "020".to_string(),
                }),
            )
            .await
            .unwrap()
            .into_iter()
            .map(|entry| entry.dn)
            .collect::<Vec<_>>();
        assert_eq!(
            less_or_equal,
            vec![
                "uid=low,dc=example,dc=org".to_string(),
                "uid=mid,dc=example,dc=org".to_string()
            ]
        );
    }

    #[tokio::test]
    async fn test_typed_ordering_index_handles_multivalue_scope_and_case() {
        let dir = tempdir().unwrap();
        let backend = LmdbBackend::new_with_config(
            dir.path(),
            100,
            1,
            IndexConfig {
                indexed_attributes: Vec::new(),
                attribute_indexes: vec![AttributeIndexConfig {
                    attribute: "code".to_string(),
                    index_types: vec![IndexType::Ordering],
                }],
            },
        )
        .unwrap();

        let mut alpha_attributes = HashMap::new();
        alpha_attributes.insert("code".to_string(), vec!["Alpha".to_string()]);
        let alpha = DirectoryEntry::new("uid=alpha,ou=people,dc=example,dc=org", alpha_attributes);
        backend.add_entry(alpha, vec![]).await.unwrap();

        let mut multi_value_attributes = HashMap::new();
        multi_value_attributes.insert(
            "code".to_string(),
            vec!["Lima".to_string(), "Zulu".to_string()],
        );
        let multi_value = DirectoryEntry::new(
            "uid=multi,ou=people,dc=example,dc=org",
            multi_value_attributes,
        );
        backend.add_entry(multi_value, vec![]).await.unwrap();

        let mut out_of_scope_attributes = HashMap::new();
        out_of_scope_attributes.insert("code".to_string(), vec!["Zulu".to_string()]);
        let out_of_scope = DirectoryEntry::new(
            "uid=outside,ou=ops,dc=example,dc=org",
            out_of_scope_attributes,
        );
        backend.add_entry(out_of_scope, vec![]).await.unwrap();

        let scoped_ge = backend
            .search_entries_with_hint(
                "ou=people,dc=example,dc=org",
                SearchScope(2),
                Some(SearchCandidateHint::GreaterOrEqual {
                    attribute: "code".to_string(),
                    value: "YANKEE".to_string(),
                }),
            )
            .await
            .unwrap();

        assert_eq!(scoped_ge.len(), 1);
        assert_eq!(scoped_ge[0].dn, "uid=multi,ou=people,dc=example,dc=org");

        let broad_scoped_ge = backend
            .search_entries_with_hint(
                "ou=people,dc=example,dc=org",
                SearchScope(2),
                Some(SearchCandidateHint::GreaterOrEqual {
                    attribute: "code".to_string(),
                    value: "ALPHA".to_string(),
                }),
            )
            .await
            .unwrap()
            .into_iter()
            .map(|entry| entry.dn)
            .collect::<Vec<_>>();

        assert_eq!(
            broad_scoped_ge,
            vec![
                "uid=alpha,ou=people,dc=example,dc=org".to_string(),
                "uid=multi,ou=people,dc=example,dc=org".to_string()
            ]
        );

        let less_or_equal = backend
            .search_entries_with_hint(
                "dc=example,dc=org",
                SearchScope(2),
                Some(SearchCandidateHint::LessOrEqual {
                    attribute: "code".to_string(),
                    value: "BRAVO".to_string(),
                }),
            )
            .await
            .unwrap();

        assert_eq!(less_or_equal.len(), 1);
        assert_eq!(less_or_equal[0].dn, "uid=alpha,ou=people,dc=example,dc=org");
    }

    #[tokio::test]
    async fn test_entry_cache_records_hits_on_repeated_exact_dn_reads() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().to_path_buf();

        {
            let backend = LmdbBackend::new(&db_path, 100, 1).unwrap();
            let mut attributes = HashMap::new();
            attributes.insert("cn".to_string(), vec!["cached".to_string()]);
            let entry = DirectoryEntry::new("uid=cached,dc=example,dc=org", attributes);
            backend.add_entry(entry, vec![]).await.unwrap();
        }

        let backend = LmdbBackend::new_with_runtime_and_cache_config(
            &db_path,
            100,
            1,
            IndexConfig::default(),
            126,
            2,
        )
        .unwrap();

        assert_eq!(backend.entry_cache_stats().len, 0);

        backend
            .get_entry("uid=cached,dc=example,dc=org")
            .await
            .unwrap()
            .unwrap();
        let after_first_read = backend.entry_cache_stats();
        assert_eq!(after_first_read.hits, 0);
        assert_eq!(after_first_read.misses, 1);
        assert_eq!(after_first_read.len, 1);

        backend
            .get_entry("UID=CACHED,DC=EXAMPLE,DC=ORG")
            .await
            .unwrap()
            .unwrap();
        let after_second_read = backend.entry_cache_stats();
        assert_eq!(after_second_read.hits, 1);
        assert_eq!(after_second_read.misses, 1);
    }

    #[tokio::test]
    async fn test_entry_cache_updates_after_modify() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().to_path_buf();

        {
            let backend = LmdbBackend::new(&db_path, 100, 1).unwrap();
            let mut attributes = HashMap::new();
            attributes.insert("cn".to_string(), vec!["before".to_string()]);
            let entry = DirectoryEntry::new("uid=modify,dc=example,dc=org", attributes);
            backend.add_entry(entry, vec![]).await.unwrap();
        }

        let backend = LmdbBackend::new_with_runtime_and_cache_config(
            &db_path,
            100,
            1,
            IndexConfig::default(),
            126,
            2,
        )
        .unwrap();

        backend
            .get_entry("uid=modify,dc=example,dc=org")
            .await
            .unwrap()
            .unwrap();
        backend
            .modify_entry(
                "uid=modify,dc=example,dc=org",
                vec![Modification {
                    operation: ModifyOperation::Replace,
                    attribute: "cn".to_string(),
                    values: vec!["after".to_string()],
                }],
            )
            .await
            .unwrap();

        let updated = backend
            .get_entry("uid=modify,dc=example,dc=org")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.attributes["cn"], vec!["after".to_string()]);

        let stats = backend.entry_cache_stats();
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 2);
        assert_eq!(stats.len, 1);
    }

    #[tokio::test]
    async fn test_entry_cache_evicts_oldest_entry_when_capacity_is_reached() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().to_path_buf();

        {
            let backend = LmdbBackend::new(&db_path, 100, 1).unwrap();
            for uid in ["one", "two"] {
                let mut attributes = HashMap::new();
                attributes.insert("cn".to_string(), vec![uid.to_string()]);
                let entry = DirectoryEntry::new(format!("uid={uid},dc=example,dc=org"), attributes);
                backend.add_entry(entry, vec![]).await.unwrap();
            }
        }

        let backend = LmdbBackend::new_with_runtime_and_cache_config(
            &db_path,
            100,
            1,
            IndexConfig::default(),
            126,
            1,
        )
        .unwrap();

        backend
            .get_entry("uid=one,dc=example,dc=org")
            .await
            .unwrap()
            .unwrap();
        backend
            .get_entry("uid=two,dc=example,dc=org")
            .await
            .unwrap()
            .unwrap();
        let stats_after_fill = backend.entry_cache_stats();
        assert_eq!(stats_after_fill.len, 1);
        assert_eq!(stats_after_fill.evictions, 1);

        backend
            .get_entry("uid=one,dc=example,dc=org")
            .await
            .unwrap()
            .unwrap();
        let stats_after_reload = backend.entry_cache_stats();
        assert_eq!(stats_after_reload.misses, 3);
        assert_eq!(stats_after_reload.evictions, 2);
    }

    #[tokio::test]
    async fn test_search_paths_do_not_populate_exact_dn_entry_cache() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().to_path_buf();

        {
            let backend = LmdbBackend::new(&db_path, 100, 1).unwrap();
            for uid in ["alice", "bob"] {
                let mut attributes = HashMap::new();
                attributes.insert("cn".to_string(), vec![uid.to_string()]);
                let entry = DirectoryEntry::new(
                    format!("uid={uid},ou=people,dc=example,dc=org"),
                    attributes,
                );
                backend.add_entry(entry, vec![]).await.unwrap();
            }
        }

        let backend = LmdbBackend::new_with_runtime_and_cache_config(
            &db_path,
            100,
            1,
            IndexConfig::default(),
            126,
            4,
        )
        .unwrap();

        let subtree_entries = backend
            .search_entries("ou=people,dc=example,dc=org", SearchScope(2))
            .await
            .unwrap();
        assert_eq!(subtree_entries.len(), 2);
        assert_eq!(backend.entry_cache_stats().len, 0);

        let hinted_entries = backend
            .search_entries_with_hint(
                "ou=people,dc=example,dc=org",
                SearchScope(2),
                Some(SearchCandidateHint::Equality {
                    attribute: "cn".to_string(),
                    value: "alice".to_string(),
                }),
            )
            .await
            .unwrap();
        assert_eq!(hinted_entries.len(), 1);
        assert_eq!(backend.entry_cache_stats().len, 0);
    }

    #[tokio::test]
    async fn test_search_entries_with_equality_hint_uses_index_candidates() {
        let dir = tempdir().unwrap();
        let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

        let mut alice_attributes = HashMap::new();
        alice_attributes.insert("cn".to_string(), vec!["Alice".to_string()]);
        let alice = DirectoryEntry::new("uid=alice,ou=people,dc=example,dc=org", alice_attributes);
        backend.add_entry(alice, vec![]).await.unwrap();

        let mut bob_attributes = HashMap::new();
        bob_attributes.insert("cn".to_string(), vec!["Bob".to_string()]);
        let bob = DirectoryEntry::new("uid=bob,ou=people,dc=example,dc=org", bob_attributes);
        backend.add_entry(bob, vec![]).await.unwrap();

        let results = backend
            .search_entries_with_hint(
                "ou=people,dc=example,dc=org",
                SearchScope(2),
                Some(SearchCandidateHint::Equality {
                    attribute: "cn".to_string(),
                    value: "Alice".to_string(),
                }),
            )
            .await
            .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].dn, "uid=alice,ou=people,dc=example,dc=org");
    }

    #[tokio::test]
    async fn test_search_entries_with_present_hint_respects_scope() {
        let dir = tempdir().unwrap();
        let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

        let mut in_scope_attributes = HashMap::new();
        in_scope_attributes.insert("mail".to_string(), vec!["alice@example.org".to_string()]);
        let in_scope =
            DirectoryEntry::new("uid=alice,ou=people,dc=example,dc=org", in_scope_attributes);
        backend.add_entry(in_scope, vec![]).await.unwrap();

        let mut out_of_scope_attributes = HashMap::new();
        out_of_scope_attributes.insert("mail".to_string(), vec!["bob@example.org".to_string()]);
        let out_of_scope =
            DirectoryEntry::new("uid=bob,ou=ops,dc=example,dc=org", out_of_scope_attributes);
        backend.add_entry(out_of_scope, vec![]).await.unwrap();

        let results = backend
            .search_entries_with_hint(
                "ou=people,dc=example,dc=org",
                SearchScope(2),
                Some(SearchCandidateHint::Present {
                    attribute: "mail".to_string(),
                }),
            )
            .await
            .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].dn, "uid=alice,ou=people,dc=example,dc=org");
    }

    #[tokio::test]
    async fn test_search_entries_with_hint_report_marks_exact_index_coverage() {
        let dir = tempdir().unwrap();
        let schema = schema_with_matching_rule_attrs();
        let backend = LmdbBackend::new_with_schema_config(
            dir.path(),
            100,
            1,
            IndexConfig {
                indexed_attributes: vec!["cn".to_string(), "mail".to_string()],
                attribute_indexes: vec![AttributeIndexConfig {
                    attribute: "exampleNumber".to_string(),
                    index_types: vec![IndexType::Ordering],
                }],
            },
            &schema,
        )
        .unwrap();

        let mut alice_attributes = HashMap::new();
        alice_attributes.insert("cn".to_string(), vec!["Alice".to_string()]);
        alice_attributes.insert("mail".to_string(), vec!["alice@example.org".to_string()]);
        alice_attributes.insert("exampleNumber".to_string(), vec!["42".to_string()]);
        backend
            .add_entry(
                DirectoryEntry::new("uid=alice,ou=people,dc=example,dc=org", alice_attributes),
                vec![],
            )
            .await
            .unwrap();

        let mut bob_attributes = HashMap::new();
        bob_attributes.insert("cn".to_string(), vec!["Bob".to_string()]);
        bob_attributes.insert("mail".to_string(), vec!["bob@example.org".to_string()]);
        bob_attributes.insert("exampleNumber".to_string(), vec!["7".to_string()]);
        backend
            .add_entry(
                DirectoryEntry::new("uid=bob,ou=people,dc=example,dc=org", bob_attributes),
                vec![],
            )
            .await
            .unwrap();

        let equality_report = backend
            .search_entries_with_hint_report(
                "ou=people,dc=example,dc=org",
                SearchScope(2),
                Some(SearchCandidateHint::Equality {
                    attribute: "cn".to_string(),
                    value: "alice".to_string(),
                }),
            )
            .await
            .unwrap();
        assert!(equality_report.hint_covers_filter);
        assert_eq!(equality_report.entries.len(), 1);
        assert_eq!(
            equality_report.entries[0].dn,
            "uid=alice,ou=people,dc=example,dc=org"
        );

        let presence_report = backend
            .search_entries_with_hint_report(
                "ou=people,dc=example,dc=org",
                SearchScope(2),
                Some(SearchCandidateHint::Present {
                    attribute: "mail".to_string(),
                }),
            )
            .await
            .unwrap();
        assert!(presence_report.hint_covers_filter);
        assert_eq!(presence_report.entries.len(), 2);

        let ordering_report = backend
            .search_entries_with_hint_report(
                "ou=people,dc=example,dc=org",
                SearchScope(2),
                Some(SearchCandidateHint::GreaterOrEqual {
                    attribute: "exampleNumber".to_string(),
                    value: "42".to_string(),
                }),
            )
            .await
            .unwrap();
        assert!(ordering_report.hint_covers_filter);
        assert_eq!(ordering_report.entries.len(), 1);
        assert_eq!(
            ordering_report.entries[0].dn,
            "uid=alice,ou=people,dc=example,dc=org"
        );
    }

    #[tokio::test]
    async fn test_search_entries_with_hint_report_keeps_partial_and_fallback_uncovered() {
        let dir = tempdir().unwrap();
        let backend = LmdbBackend::new_with_config(
            dir.path(),
            100,
            1,
            IndexConfig {
                indexed_attributes: Vec::new(),
                attribute_indexes: vec![AttributeIndexConfig {
                    attribute: "description".to_string(),
                    index_types: vec![IndexType::Substring],
                }],
            },
        )
        .unwrap();

        for (uid, description) in [
            ("alice", "fixture user 000000 alpha"),
            ("bob", "fixture user 000001 beta"),
        ] {
            let mut attributes = HashMap::new();
            attributes.insert("description".to_string(), vec![description.to_string()]);
            backend
                .add_entry(
                    DirectoryEntry::new(
                        format!("uid={uid},ou=people,dc=example,dc=org"),
                        attributes,
                    ),
                    vec![],
                )
                .await
                .unwrap();
        }

        let substring_report = backend
            .search_entries_with_hint_report(
                "ou=people,dc=example,dc=org",
                SearchScope(2),
                Some(SearchCandidateHint::Substring {
                    attribute: "description".to_string(),
                    parts: vec![SearchSubstringPart::Any("fixture user 000000".to_string())],
                }),
            )
            .await
            .unwrap();
        assert!(!substring_report.hint_covers_filter);
        assert_eq!(substring_report.entries.len(), 1);
        assert_eq!(
            substring_report.entries[0].dn,
            "uid=alice,ou=people,dc=example,dc=org"
        );

        let fallback_report = backend
            .search_entries_with_hint_report(
                "ou=people,dc=example,dc=org",
                SearchScope(2),
                Some(SearchCandidateHint::Present {
                    attribute: "description".to_string(),
                }),
            )
            .await
            .unwrap();
        assert!(!fallback_report.hint_covers_filter);
        assert_eq!(fallback_report.entries.len(), 2);
    }

    #[tokio::test]
    async fn test_search_entries_with_nonindexed_hint_falls_back_to_full_scan() {
        let dir = tempdir().unwrap();
        let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

        let mut attributes = HashMap::new();
        attributes.insert(
            "description".to_string(),
            vec!["indexed-by-scan".to_string()],
        );
        let entry = DirectoryEntry::new("uid=test,dc=example,dc=org", attributes);
        backend.add_entry(entry, vec![]).await.unwrap();

        let results = backend
            .search_entries_with_hint(
                "dc=example,dc=org",
                SearchScope(2),
                Some(SearchCandidateHint::Present {
                    attribute: "description".to_string(),
                }),
            )
            .await
            .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].dn, "uid=test,dc=example,dc=org");
    }

    #[tokio::test]
    async fn test_context_csn_initially_none() {
        let dir = tempdir().unwrap();
        let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

        // Initially, contextCSN should be None
        let csn = backend.get_context_csn().await.unwrap();
        assert!(csn.is_none());
    }

    #[tokio::test]
    async fn test_context_csn_set_and_get() {
        let dir = tempdir().unwrap();
        let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

        // Create a CSN
        let csn = crate::csn::Csn::with_values(1696680896789012, 1, 0, 0);

        // Set contextCSN
        backend.set_context_csn(csn.clone()).await.unwrap();

        // Retrieve contextCSN
        let retrieved = backend.get_context_csn().await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), csn);
    }

    #[tokio::test]
    async fn test_context_csn_update() {
        let dir = tempdir().unwrap();
        let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

        // Set initial CSN
        let csn1 = crate::csn::Csn::with_values(1696680896789012, 1, 0, 0);
        backend.set_context_csn(csn1).await.unwrap();

        // Update to newer CSN
        let csn2 = crate::csn::Csn::with_values(1696680896789013, 1, 1, 0);
        backend.set_context_csn(csn2.clone()).await.unwrap();

        // Should retrieve the newer CSN
        let retrieved = backend.get_context_csn().await.unwrap();
        assert_eq!(retrieved.unwrap(), csn2);
    }

    #[tokio::test]
    async fn test_context_csn_persistence() {
        let dir = tempdir().unwrap();
        let path = dir.path().to_path_buf();

        // Create backend and set CSN
        {
            let backend = LmdbBackend::new(&path, 100, 1).unwrap();
            let csn = crate::csn::Csn::with_values(1696680896789012, 1, 0, 0);
            backend.set_context_csn(csn).await.unwrap();
        }

        // Reopen backend and verify CSN persisted
        {
            let backend = LmdbBackend::new(&path, 100, 1).unwrap();
            let retrieved = backend.get_context_csn().await.unwrap();
            assert!(retrieved.is_some());
            let csn = retrieved.unwrap();
            assert_eq!(csn.timestamp_us(), 1696680896789012);
            assert_eq!(csn.replica_id(), 1);
        }
    }
}

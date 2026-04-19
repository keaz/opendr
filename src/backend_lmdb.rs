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
//! - `entries_by_entry_id`: Compact entry id → Entry data (primary storage)
//! - `credentials_by_entry_id`: Compact entry id → compact credential record (bind hot path)
//! - `entry_id_by_normalized_dn`: Normalized DN → compact entry id
//! - `dn_by_entry_id`: Compact entry id → Original DN
//! - `idx3_{name}`: Normalized index key → duplicate fixed-width compact entry ids
//!
//! ## Read Optimization
//!
//! - Memory-mapped I/O for zero-copy reads
//! - Multi-reader support (no blocking on reads)
//! - Cached read transactions
//! - Indexed attribute lookups
//! - DN normalization for fast case-insensitive searches

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
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
    AuthenticationMetadataUpdate, AuthenticationOutcome, BackendError,
    DirectoryAttributeProjection, DirectoryBackend, DirectoryEntry, Modification,
    NativeModifyError, OperationalAttributes, ProjectedDirectoryEntry,
    ProjectedSearchEntriesStreamReport, SearchCandidateHint, SearchEntriesStreamReport,
    SearchEntriesWithHintReport, SearchPlanFallbackReason, SearchPlanType, SearchSubstringPart,
    apply_modifications_to_attributes, referral_urls_from_attributes,
};
use crate::csn::{Csn, CsnGenerator};
use crate::dn::{
    LdapDn, canonicalize_dn, dn_is_in_scope, parse_dn, rdn_attribute_values, replace_dn_rdn,
};
use crate::metrics::MetricsCollector;
use crate::perf_profile::PerfPhase;
use crate::schema::{LdapSchema, ResolvedMatchingRule};

const LMDB_SET_RANGE_OP: u32 = 17;
const LMDB_GET_BOTH_OP: u32 = 2;
const DEFAULT_ENTRY_CACHE_CAPACITY: usize = 1000;
const EQUALITY_INDEX_KEY_PREFIX: &str = "\0eq\0";
const PRESENCE_INDEX_KEY: &str = "\0pres";
const SUBSTRING_INDEX_KEY_PREFIX: &str = "\0sub\0";
const ORDERING_INDEX_KEY_PREFIX: &str = "\0ord\0";
const SUBSTRING_INDEX_TOKEN_LEN: usize = 3;
const SUBSTRING_QUERY_MAX_TOKENS: usize = 2;
const ATTRIBUTE_INDEX_VERSION: &[u8] = b"3";
const ATTRIBUTE_INDEX_CONFIG_METADATA_KEY: &str = "attribute_indexes_v1:configured";
const ATTRIBUTE_INDEX_DB_PREFIX: &str = "idx3_";
const ATTRIBUTE_INDEX_BACKFILL_BATCH_SIZE: usize = 10_000;
const CREDENTIAL_INDEX_VERSION: &[u8] = b"3";
const CREDENTIAL_INDEX_METADATA_KEY: &str = "credential_index_v2:ready";
const CREDENTIAL_RECORD_FORMAT_VERSION: u8 = 1;
const CREDENTIAL_INDEX_BACKFILL_BATCH_SIZE: usize = 10_000;
const ENTRY_ID_INDEX_VERSION: &[u8] = b"1";
const ENTRY_ID_INDEX_METADATA_KEY: &str = "entry_ids_v1:ready";
const NEXT_ENTRY_ID_METADATA_KEY: &str = "entry_ids_v1:next";
const ENTRY_ID_BACKFILL_BATCH_SIZE: usize = 10_000;
const ENTRY_STORAGE_VERSION: &[u8] = b"1";
const ENTRY_STORAGE_METADATA_KEY: &str = "entries_by_entry_id_v1:ready";
const ENTRY_STORAGE_BACKFILL_BATCH_SIZE: usize = 10_000;
const FIRST_ENTRY_ID: u64 = 1;
const LEGACY_ENTRIES_DB_NAME: &str = "entries";
const LEGACY_PASSWORDS_DB_NAME: &str = "passwords";
const LEGACY_CREDENTIALS_BY_NORMALIZED_DN_DB_NAME: &str = "credentials_by_normalized_dn";
const LEGACY_DN_INDEX_DB_NAME: &str = "dn_index";
const ENTRIES_BY_ENTRY_ID_DB_NAME: &str = "entries_by_entry_id";
const CREDENTIALS_BY_ENTRY_ID_DB_NAME: &str = "credentials_by_entry_id";

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

struct DnRenamePlan {
    entry_id: u64,
    old_dn: String,
    new_dn: String,
    old_normalized_dn: String,
    new_normalized_dn: String,
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

/// Compact serialized entry structure for the ID-keyed primary table.
///
/// The DN is stored once in `dn_by_entry_id`, so primary entry values avoid
/// repeating it for every row.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredEntryRecord {
    pub attributes: HashMap<String, Vec<String>>,
    pub created_at: u64,
    pub modified_at: u64,
    #[serde(default)]
    pub operational_attributes: crate::backend::OperationalAttributes,
}

impl From<&StoredEntry> for StoredEntryRecord {
    fn from(value: &StoredEntry) -> Self {
        Self {
            attributes: value.attributes.clone(),
            created_at: value.created_at,
            modified_at: value.modified_at,
            operational_attributes: value.operational_attributes.clone(),
        }
    }
}

impl StoredEntryRecord {
    fn into_stored_entry(self, dn: String) -> StoredEntry {
        StoredEntry {
            dn,
            attributes: self.attributes,
            created_at: self.created_at,
            modified_at: self.modified_at,
            operational_attributes: self.operational_attributes,
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

struct LruNode<T> {
    key: Arc<str>,
    value: T,
    previous: Option<Arc<str>>,
    next: Option<Arc<str>>,
}

struct BoundedLruCache<T> {
    capacity: usize,
    entries: HashMap<Arc<str>, LruNode<T>>,
    oldest: Option<Arc<str>>,
    newest: Option<Arc<str>>,
}

impl<T> BoundedLruCache<T> {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity,
            entries: HashMap::with_capacity(capacity),
            oldest: None,
            newest: None,
        }
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn get_cloned(&mut self, key: &str) -> Option<T>
    where
        T: Clone,
    {
        let (key, value) = self
            .entries
            .get(key)
            .map(|node| (Arc::clone(&node.key), node.value.clone()))?;
        self.move_to_newest(&key);
        Some(value)
    }

    fn insert(&mut self, key: String, value: T) -> Option<T> {
        if self.capacity == 0 {
            return None;
        }

        if let Some(node) = self.entries.get_mut(key.as_str()) {
            node.value = value;
            let key = Arc::clone(&node.key);
            self.move_to_newest(&key);
            return None;
        }

        let evicted = (self.entries.len() == self.capacity)
            .then(|| self.pop_oldest())
            .flatten();
        let key: Arc<str> = Arc::from(key);

        self.entries.insert(
            Arc::clone(&key),
            LruNode {
                key: Arc::clone(&key),
                value,
                previous: None,
                next: None,
            },
        );
        self.attach_newest(key);
        evicted
    }

    fn remove(&mut self, key: &str) -> Option<T> {
        let key = self.entries.get(key).map(|node| Arc::clone(&node.key))?;
        self.remove_key(&key)
    }

    fn pop_oldest(&mut self) -> Option<T> {
        let oldest = Arc::clone(self.oldest.as_ref()?);
        self.remove_key(&oldest)
    }

    fn remove_key(&mut self, key: &Arc<str>) -> Option<T> {
        self.detach(key);
        self.entries.remove(key).map(|node| node.value)
    }

    fn move_to_newest(&mut self, key: &Arc<str>) {
        if self.newest.as_deref() == Some(key.as_ref()) {
            return;
        }
        self.detach(key);
        self.attach_newest(Arc::clone(key));
    }

    fn detach(&mut self, key: &Arc<str>) {
        let Some((previous, next)) = self
            .entries
            .get(key)
            .map(|node| (node.previous.clone(), node.next.clone()))
        else {
            return;
        };

        if let Some(previous_key) = previous.as_ref() {
            if let Some(previous_node) = self.entries.get_mut(previous_key) {
                previous_node.next = next.clone();
            }
        } else {
            self.oldest = next.clone();
        }

        if let Some(next_key) = next.as_ref() {
            if let Some(next_node) = self.entries.get_mut(next_key) {
                next_node.previous = previous.clone();
            }
        } else {
            self.newest = previous.clone();
        }

        if let Some(node) = self.entries.get_mut(key) {
            node.previous = None;
            node.next = None;
        }
    }

    fn attach_newest(&mut self, key: Arc<str>) {
        let previous_newest = self.newest.clone();
        if let Some(previous_key) = previous_newest.as_ref() {
            if let Some(previous_node) = self.entries.get_mut(previous_key) {
                previous_node.next = Some(Arc::clone(&key));
            }
        } else {
            self.oldest = Some(Arc::clone(&key));
        }

        if let Some(node) = self.entries.get_mut(&key) {
            node.previous = previous_newest;
            node.next = None;
        }
        self.newest = Some(key);
    }
}

struct EntryCacheShard {
    cache: BoundedLruCache<Arc<StoredEntry>>,
}

struct EntryCache {
    capacity: usize,
    shards: Vec<Mutex<EntryCacheShard>>,
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
}

impl EntryCache {
    fn new(capacity: usize) -> Self {
        let shard_count = cache_shard_count(capacity);
        let mut shards = Vec::with_capacity(shard_count);
        for index in 0..shard_count {
            shards.push(Mutex::new(EntryCacheShard {
                cache: BoundedLruCache::with_capacity(cache_shard_capacity(
                    capacity,
                    shard_count,
                    index,
                )),
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

    fn get(&self, normalized_dn: &str) -> Option<Arc<StoredEntry>> {
        if self.capacity == 0 {
            self.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        let mut shard = self.lock_shard(normalized_dn);
        let entry = shard.cache.get_cloned(normalized_dn);
        if entry.is_some() {
            self.hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
        }
        entry
    }

    fn insert(&self, normalized_dn: &str, entry: Arc<StoredEntry>) {
        if self.capacity == 0 {
            return;
        }

        let mut shard = self.lock_shard(normalized_dn);
        if shard
            .cache
            .insert(normalized_dn.to_string(), entry)
            .is_some()
        {
            self.evictions.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn invalidate(&self, normalized_dn: &str) {
        if self.capacity == 0 {
            return;
        }

        let mut shard = self.lock_shard(normalized_dn);
        shard.cache.remove(normalized_dn);
    }

    fn stats(&self) -> EntryCacheStats {
        EntryCacheStats {
            capacity: self.capacity,
            len: self.shards.iter().map(lock_shard_len).sum(),
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
        }
    }

    fn lock_shard(&self, normalized_dn: &str) -> std::sync::MutexGuard<'_, EntryCacheShard> {
        self.shards[cache_shard_index(normalized_dn, self.shards.len())]
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

#[derive(Debug)]
struct AuthCredentialRecord {
    hash: [u8; 64],
    salt: Vec<u8>,
}

struct AuthCredentialCacheShard {
    cache: BoundedLruCache<Arc<AuthCredentialRecord>>,
}

struct AuthCredentialCache {
    capacity: usize,
    shards: Vec<Mutex<AuthCredentialCacheShard>>,
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
}

impl AuthCredentialCache {
    fn new(capacity: usize) -> Self {
        let shard_count = cache_shard_count(capacity);
        let mut shards = Vec::with_capacity(shard_count);
        for index in 0..shard_count {
            shards.push(Mutex::new(AuthCredentialCacheShard {
                cache: BoundedLruCache::with_capacity(cache_shard_capacity(
                    capacity,
                    shard_count,
                    index,
                )),
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
        let record = shard.cache.get_cloned(normalized_dn);
        if record.is_some() {
            self.hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
        }
        record
    }

    fn insert(&self, normalized_dn: &str, record: Arc<AuthCredentialRecord>) {
        if self.capacity == 0 {
            return;
        }

        let mut shard = self.lock_shard(normalized_dn);
        if shard
            .cache
            .insert(normalized_dn.to_string(), record)
            .is_some()
        {
            self.evictions.fetch_add(1, Ordering::Relaxed);
        };
    }

    fn invalidate(&self, normalized_dn: &str) {
        if self.capacity == 0 {
            return;
        }

        let mut shard = self.lock_shard(normalized_dn);
        shard.cache.remove(normalized_dn);
    }

    fn stats(&self) -> AuthCredentialCacheStats {
        AuthCredentialCacheStats {
            capacity: self.capacity,
            len: self.shards.iter().map(lock_shard_len).sum(),
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
}

const CACHE_MAX_SHARDS: usize = 64;
const CACHE_ENTRIES_PER_SHARD_TARGET: usize = 1024;

fn cache_shard_count(capacity: usize) -> usize {
    if capacity == 0 {
        return 1;
    }

    let target_shards = capacity.div_ceil(CACHE_ENTRIES_PER_SHARD_TARGET);
    target_shards.clamp(1, CACHE_MAX_SHARDS).min(capacity)
}

fn cache_shard_capacity(capacity: usize, shard_count: usize, shard_index: usize) -> usize {
    let base_capacity = capacity / shard_count;
    let extra_capacity = capacity % shard_count;
    base_capacity + usize::from(shard_index < extra_capacity)
}

fn cache_shard_index(normalized_dn: &str, shard_count: usize) -> usize {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in normalized_dn.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    (hash as usize) % shard_count
}

fn lock_shard_len<T>(shard: &Mutex<T>) -> usize
where
    T: CacheShardLen,
{
    shard
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .len()
}

trait CacheShardLen {
    fn len(&self) -> usize;
}

impl CacheShardLen for EntryCacheShard {
    fn len(&self) -> usize {
        self.cache.len()
    }
}

impl CacheShardLen for AuthCredentialCacheShard {
    fn len(&self) -> usize {
        self.cache.len()
    }
}

#[doc(hidden)]
pub struct LmdbEntryCacheBenchmarkHarness {
    cache: EntryCache,
    keys: Vec<String>,
}

impl LmdbEntryCacheBenchmarkHarness {
    pub fn new(capacity: usize) -> Self {
        let cache = EntryCache::new(capacity);
        let keys = (0..capacity)
            .map(|index| benchmark_cache_dn("entry", index))
            .collect::<Vec<_>>();

        for key in &keys {
            cache.insert(key, Arc::new(benchmark_stored_entry(key.clone())));
        }

        Self { cache, keys }
    }

    pub fn get_hit(&self, index: usize) -> bool {
        let Some(key) = self.keys.get(index % self.keys.len().max(1)) else {
            return false;
        };
        self.cache.get(key).is_some()
    }

    pub fn insert_new(&self, sequence: usize) -> EntryCacheStats {
        let dn = benchmark_cache_dn("entry-new", sequence);
        self.cache
            .insert(&dn, Arc::new(benchmark_stored_entry(dn.clone())));
        self.cache.stats()
    }

    pub fn invalidate_and_reinsert(&self, index: usize) -> EntryCacheStats {
        let Some(key) = self.keys.get(index % self.keys.len().max(1)) else {
            return self.cache.stats();
        };
        self.cache.invalidate(key);
        self.cache
            .insert(key, Arc::new(benchmark_stored_entry(key.clone())));
        self.cache.stats()
    }
}

#[doc(hidden)]
pub struct LmdbAuthCacheBenchmarkHarness {
    cache: AuthCredentialCache,
    keys: Vec<String>,
}

impl LmdbAuthCacheBenchmarkHarness {
    pub fn new(capacity: usize) -> Self {
        let cache = AuthCredentialCache::new(capacity);
        let keys = (0..capacity)
            .map(|index| benchmark_cache_dn("auth", index))
            .collect::<Vec<_>>();

        for (index, key) in keys.iter().enumerate() {
            cache.insert(key, benchmark_auth_record(index));
        }

        Self { cache, keys }
    }

    pub fn get_hit(&self, index: usize) -> bool {
        let Some(key) = self.keys.get(index % self.keys.len().max(1)) else {
            return false;
        };
        self.cache.get(key).is_some()
    }

    pub fn insert_new(&self, sequence: usize) -> AuthCredentialCacheStats {
        let dn = benchmark_cache_dn("auth-new", sequence);
        self.cache.insert(&dn, benchmark_auth_record(sequence));
        self.cache.stats()
    }

    pub fn invalidate_and_reinsert(&self, index: usize) -> AuthCredentialCacheStats {
        let Some(key) = self.keys.get(index % self.keys.len().max(1)) else {
            return self.cache.stats();
        };
        self.cache.invalidate(key);
        self.cache.insert(key, benchmark_auth_record(index));
        self.cache.stats()
    }
}

fn benchmark_cache_dn(prefix: &str, index: usize) -> String {
    format!("uid={prefix}-{index},ou=people,dc=example,dc=org")
}

fn benchmark_stored_entry(dn: String) -> StoredEntry {
    StoredEntry {
        dn,
        attributes: HashMap::new(),
        created_at: 0,
        modified_at: 0,
        operational_attributes: OperationalAttributes::default(),
    }
}

fn benchmark_auth_record(seed: usize) -> Arc<AuthCredentialRecord> {
    Arc::new(AuthCredentialRecord {
        hash: [seed as u8; 64],
        salt: vec![seed as u8],
    })
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

#[derive(Debug, Clone)]
enum SearchStreamPlan {
    Uncovered {
        base_dn: String,
        scope: SearchScope,
        fallback_reason: SearchPlanFallbackReason,
    },
    Equality {
        base_dn: String,
        scope: SearchScope,
        attribute: String,
        value: String,
    },
    Present {
        base_dn: String,
        scope: SearchScope,
        attribute: String,
    },
    Substring {
        base_dn: String,
        scope: SearchScope,
        attribute: String,
        parts: Vec<SearchSubstringPart>,
    },
    Ordering {
        base_dn: String,
        scope: SearchScope,
        attribute: String,
        value: String,
        greater_or_equal: bool,
    },
}

impl SearchStreamPlan {
    fn hint_covers_filter(&self) -> bool {
        matches!(
            self,
            SearchStreamPlan::Equality { .. }
                | SearchStreamPlan::Present { .. }
                | SearchStreamPlan::Ordering { .. }
        )
    }

    fn plan_type(&self) -> SearchPlanType {
        match self {
            SearchStreamPlan::Uncovered { .. } => SearchPlanType::FullScan,
            SearchStreamPlan::Equality { .. } => SearchPlanType::EqualityIndex,
            SearchStreamPlan::Present { .. } => SearchPlanType::PresenceIndex,
            SearchStreamPlan::Substring { .. } => SearchPlanType::SubstringIndex,
            SearchStreamPlan::Ordering { .. } => SearchPlanType::OrderingIndex,
        }
    }

    fn fallback_reason(&self) -> Option<SearchPlanFallbackReason> {
        match self {
            SearchStreamPlan::Uncovered {
                fallback_reason, ..
            } => Some(*fallback_reason),
            _ => None,
        }
    }
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

        if !rule.is_index_supported() {
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

fn update_entry_rdn_attributes(
    entry: &mut DirectoryEntry,
    old_dn: &str,
    new_rdn: &str,
    delete_old: bool,
) {
    if delete_old
        && let Some(old_rdn) = parse_dn(old_dn)
            .ok()
            .and_then(|dn| dn.rdns().first().cloned())
    {
        for ava in old_rdn.avas() {
            let attr = ldap_attribute_key(ava.attribute()).into_owned();
            if let Some(values) = entry.attributes.get_mut(&attr) {
                values.retain(|candidate| candidate != ava.value());
                if values.is_empty() {
                    entry.attributes.remove(&attr);
                }
            }
        }
    }

    for (attribute, value) in rdn_attribute_values(new_rdn).unwrap_or_default() {
        let attr = ldap_attribute_key(&attribute).into_owned();
        let values = entry.attributes.entry(attr).or_default();
        if !values.contains(&value) {
            values.push(value);
        }
    }
}

/// LMDB-based persistent backend optimized for read performance
#[derive(Clone)]
pub struct LmdbBackend {
    /// LMDB environment
    env: Arc<Environment>,
    /// Primary entries keyed by compact entry id.
    entries_by_entry_id_db: Database,
    /// Compact credential records keyed by compact entry id for the bind hot path.
    credentials_by_entry_id_db: Database,
    /// Normalized DN to compact entry id.
    entry_id_by_normalized_dn_db: Database,
    /// Compact entry id to original DN, used by attribute indexes.
    dn_by_entry_id_db: Database,
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

        // Create current storage databases. Legacy DBs are opened only if they
        // already exist so fresh stores do not grow empty compatibility tables.
        let entries_by_entry_id_db = env
            .create_db(
                Some(ENTRIES_BY_ENTRY_ID_DB_NAME),
                lmdb::DatabaseFlags::empty(),
            )
            .map_err(|e| BackendError::Storage(format!("Failed to create entries db: {}", e)))?;

        let credentials_by_entry_id_db = env
            .create_db(
                Some(CREDENTIALS_BY_ENTRY_ID_DB_NAME),
                lmdb::DatabaseFlags::empty(),
            )
            .map_err(|e| {
                BackendError::Storage(format!("Failed to create credential index db: {}", e))
            })?;

        let legacy_entries_db = Self::open_optional_db(&env, LEGACY_ENTRIES_DB_NAME)?;
        let legacy_passwords_db = Self::open_optional_db(&env, LEGACY_PASSWORDS_DB_NAME)?;
        let legacy_credentials_by_normalized_dn_db =
            Self::open_optional_db(&env, LEGACY_CREDENTIALS_BY_NORMALIZED_DN_DB_NAME)?;
        let legacy_dn_index_db = Self::open_optional_db(&env, LEGACY_DN_INDEX_DB_NAME)?;

        let entry_id_by_normalized_dn_db = env
            .create_db(
                Some("entry_id_by_normalized_dn"),
                lmdb::DatabaseFlags::empty(),
            )
            .map_err(|e| {
                BackendError::Storage(format!("Failed to create entry id index db: {}", e))
            })?;

        let dn_by_entry_id_db = env
            .create_db(Some("dn_by_entry_id"), lmdb::DatabaseFlags::empty())
            .map_err(|e| {
                BackendError::Storage(format!("Failed to create entry id DN db: {}", e))
            })?;

        let metadata_db = env
            .create_db(Some("metadata"), lmdb::DatabaseFlags::empty())
            .map_err(|e| BackendError::Storage(format!("Failed to create metadata db: {}", e)))?;

        // Create attribute index databases.
        let mut attr_indexes = HashMap::new();
        for attr in index_plan.attribute_names() {
            let db_name = format!("{ATTRIBUTE_INDEX_DB_PREFIX}{}", attr);
            let db = env
                .create_db(
                    Some(&db_name),
                    lmdb::DatabaseFlags::DUP_SORT | lmdb::DatabaseFlags::DUP_FIXED,
                )
                .map_err(|e| {
                    BackendError::Storage(format!("Failed to create index for {}: {}", attr, e))
                })?;
            attr_indexes.insert(attr.clone(), db);
        }

        Self::ensure_entry_ids_backfilled(
            &env,
            legacy_entries_db,
            metadata_db,
            entry_id_by_normalized_dn_db,
            dn_by_entry_id_db,
        )?;
        Self::ensure_entries_by_entry_id_backfilled(
            &env,
            legacy_entries_db,
            entries_by_entry_id_db,
            metadata_db,
            entry_id_by_normalized_dn_db,
        )?;
        Self::ensure_attribute_indexes_backfilled(
            &env,
            entries_by_entry_id_db,
            dn_by_entry_id_db,
            metadata_db,
            &attr_indexes,
            &index_plan,
        )?;
        Self::ensure_credential_index_backfilled(
            &env,
            legacy_passwords_db,
            legacy_credentials_by_normalized_dn_db,
            metadata_db,
            entry_id_by_normalized_dn_db,
            credentials_by_entry_id_db,
        )?;
        Self::clear_legacy_databases(
            &env,
            &[
                legacy_entries_db,
                legacy_passwords_db,
                legacy_credentials_by_normalized_dn_db,
                legacy_dn_index_db,
            ],
        )?;

        // Initialize CSN generator with replica ID
        let csn_generator = Arc::new(CsnGenerator::new(replica_id));

        Ok(Self {
            env,
            entries_by_entry_id_db,
            credentials_by_entry_id_db,
            entry_id_by_normalized_dn_db,
            dn_by_entry_id_db,
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

        let normalized_dn = Self::normalize_dn(&entry.dn)?;

        if Self::entry_id_for_normalized_dn(
            &txn,
            self.entry_id_by_normalized_dn_db,
            &normalized_dn,
        )?
        .is_some()
        {
            return Err(BackendError::AlreadyExists);
        }
        let mut next_entry_id = Self::read_next_entry_id(&txn, self.metadata_db)?;
        let entry_id = Self::allocate_entry_id(
            &mut txn,
            self.entry_id_by_normalized_dn_db,
            self.dn_by_entry_id_db,
            &normalized_dn,
            &entry.dn,
            &mut next_entry_id,
        )?;

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

        Self::put_entry_by_id(
            &mut txn,
            self.entries_by_entry_id_db,
            entry_id,
            &stored_entry,
        )?;

        if let Some(password_hash) = Self::password_hash_from_bytes(&password) {
            self.put_credential_index(&mut txn, entry_id, &password_hash)?;
        }

        self.update_attribute_indexes(&mut txn, entry_id, &stored_entry.attributes)?;

        let csn_string = csn.to_ldap_string();
        txn.put(
            self.metadata_db,
            &b"context_csn",
            &csn_string.as_bytes(),
            WriteFlags::empty(),
        )
        .map_err(|e| BackendError::Storage(format!("Failed to update contextCSN: {}", e)))?;
        Self::put_next_entry_id(&mut txn, self.metadata_db, next_entry_id)?;

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
        let mut next_entry_id = {
            let txn = self.env.begin_ro_txn().map_err(|e| {
                BackendError::Storage(format!("Failed to begin entry id read txn: {}", e))
            })?;
            Self::read_next_entry_id(&txn, self.metadata_db)?
        };

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

                let normalized_dn = Self::normalize_dn(&entry.dn)?;
                if Self::entry_id_for_normalized_dn(
                    &txn,
                    self.entry_id_by_normalized_dn_db,
                    &normalized_dn,
                )?
                .is_some()
                {
                    return Err(BackendError::AlreadyExists);
                }
                let entry_id = Self::allocate_entry_id(
                    &mut txn,
                    self.entry_id_by_normalized_dn_db,
                    self.dn_by_entry_id_db,
                    &normalized_dn,
                    &entry.dn,
                    &mut next_entry_id,
                )?;

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

                Self::put_entry_by_id(
                    &mut txn,
                    self.entries_by_entry_id_db,
                    entry_id,
                    &stored_entry,
                )?;

                if let Some(password_hash) = Self::password_hash_from_bytes(&password) {
                    self.put_credential_index(&mut txn, entry_id, &password_hash)?;
                }

                self.update_attribute_indexes(&mut txn, entry_id, &stored_entry.attributes)?;

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
            Self::put_next_entry_id(&mut txn, self.metadata_db, next_entry_id)?;

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
        self.modify_entry_internal_validated(dn, modifications, actor_dn, None)
            .await
            .map_err(NativeModifyError::into_backend_error)
    }

    async fn modify_entry_internal_validated(
        &self,
        dn: &str,
        modifications: Vec<Modification>,
        actor_dn: Option<&str>,
        schema: Option<&LdapSchema>,
    ) -> Result<(), NativeModifyError> {
        let _lock = self.write_lock.write().await;

        let mut txn = self
            .env
            .begin_rw_txn()
            .map_err(|e| BackendError::Storage(format!("Failed to begin write txn: {}", e)))?;

        let normalized_dn = Self::normalize_dn(dn).map_err(NativeModifyError::Backend)?;
        let entry_id = match Self::entry_id_for_normalized_dn(
            &txn,
            self.entry_id_by_normalized_dn_db,
            &normalized_dn,
        )? {
            Some(entry_id) => entry_id,
            None => return Err(BackendError::NotFound.into()),
        };
        let mut entry = Self::required_entry_by_id(
            &txn,
            self.entries_by_entry_id_db,
            self.dn_by_entry_id_db,
            entry_id,
        )?;
        let indexed_modified_attributes = modifications
            .iter()
            .map(|modification| ldap_attribute_key(&modification.attribute).into_owned())
            .filter(|attribute| {
                self.index_plan
                    .attribute_plan_normalized(attribute)
                    .is_some()
            })
            .collect::<HashSet<_>>();
        let old_attributes = (schema.is_some() || !indexed_modified_attributes.is_empty())
            .then(|| entry.attributes.clone());
        let password_touched = modifications.iter().any(|modification| {
            ldap_attribute_key(&modification.attribute).as_ref() == "userpassword"
        });

        apply_modifications_to_attributes(&mut entry.attributes, &modifications)?;

        if let Some(schema) = schema {
            let original_attributes = old_attributes
                .as_ref()
                .expect("old attributes are captured when schema validation is enabled");
            schema
                .validate_modified_entry(original_attributes, &entry.attributes)
                .map_err(|err| {
                    NativeModifyError::schema_violation(format!(
                        "Schema validation failed: {}",
                        err
                    ))
                })?;
        }

        entry.modified_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let csn = self.csn_generator.generate();
        entry
            .operational_attributes
            .for_modified_entry(csn.clone(), actor_dn.map(str::to_string));

        Self::put_entry_by_id(&mut txn, self.entries_by_entry_id_db, entry_id, &entry)?;

        let mut updated_auth_record = None;
        if password_touched {
            if let Some(password_value) = entry
                .attributes
                .get("userpassword")
                .and_then(|values| values.first())
            {
                let password_hash = Self::password_hash_from_value(password_value);
                updated_auth_record = Self::decode_ssha512_hash(&password_hash).map(Arc::new);
                self.put_credential_index(&mut txn, entry_id, &password_hash)?;
            } else {
                txn.del(
                    self.credentials_by_entry_id_db,
                    &Self::entry_id_bytes(entry_id),
                    None,
                )
                .or_else(|e| match e {
                    lmdb::Error::NotFound => Ok(()),
                    _ => Err(BackendError::Storage(
                        "Failed to delete credential index".to_string(),
                    )),
                })?;
            }
        }

        if let Some(old_attributes) = old_attributes.as_ref() {
            self.remove_attribute_indexes_for_filter(
                &mut txn,
                entry_id,
                old_attributes,
                Some(&indexed_modified_attributes),
            )?;
            self.update_attribute_indexes_for_filter(
                &mut txn,
                entry_id,
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
        let normalized_dn = Self::normalize_dn(dn)?;
        let entry_id = match Self::entry_id_for_normalized_dn(
            &txn,
            self.entry_id_by_normalized_dn_db,
            &normalized_dn,
        )? {
            Some(entry_id) => entry_id,
            None => return Err(BackendError::NotFound),
        };
        let entry = Self::required_entry_by_id(
            &txn,
            self.entries_by_entry_id_db,
            self.dn_by_entry_id_db,
            entry_id,
        )?;

        let new_dn = replace_dn_rdn(&entry.dn, new_rdn, new_superior.as_deref())
            .map_err(|err| BackendError::InvalidDn(err.to_string()))?;
        let normalized_new_dn = Self::normalize_dn(&new_dn)?;

        if Self::entry_id_for_normalized_dn(
            &txn,
            self.entry_id_by_normalized_dn_db,
            &normalized_new_dn,
        )?
        .is_some_and(|existing_entry_id| existing_entry_id != entry_id)
        {
            return Err(BackendError::AlreadyExists);
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let csn = self.csn_generator.generate();
        let plans = Self::plan_dn_renames_in_txn(
            &txn,
            self.dn_by_entry_id_db,
            self.entry_id_by_normalized_dn_db,
            &entry.dn,
            &new_dn,
        )?;

        for plan in &plans {
            let entry_id_bytes = Self::entry_id_bytes(plan.entry_id);
            let stored_entry = Self::required_entry_by_id(
                &txn,
                self.entries_by_entry_id_db,
                self.dn_by_entry_id_db,
                plan.entry_id,
            )?;
            let mut new_entry = stored_entry.to_directory_entry();
            new_entry.dn = plan.new_dn.clone();
            new_entry
                .operational_attributes
                .for_modified_entry(csn.clone(), actor_dn.map(str::to_string));

            if plan.entry_id == entry_id {
                update_entry_rdn_attributes(&mut new_entry, &plan.old_dn, new_rdn, delete_old);
            }

            let new_stored_entry = StoredEntry {
                dn: plan.new_dn.clone(),
                attributes: new_entry.attributes.clone(),
                created_at: stored_entry.created_at,
                modified_at: now,
                operational_attributes: new_entry.operational_attributes,
            };
            self.remove_attribute_indexes(&mut txn, plan.entry_id, &stored_entry.attributes)?;
            txn.del(
                self.entry_id_by_normalized_dn_db,
                &plan.old_normalized_dn.as_bytes(),
                None,
            )
            .map_err(|e| {
                BackendError::Storage(format!("Failed to delete entry id index: {}", e))
            })?;
            txn.put(
                self.entry_id_by_normalized_dn_db,
                &plan.new_normalized_dn.as_bytes(),
                &entry_id_bytes,
                WriteFlags::empty(),
            )
            .map_err(|e| {
                BackendError::Storage(format!("Failed to update entry id index: {}", e))
            })?;
            txn.put(
                self.dn_by_entry_id_db,
                &entry_id_bytes,
                &plan.new_dn.as_bytes(),
                WriteFlags::empty(),
            )
            .map_err(|e| BackendError::Storage(format!("Failed to update entry id DN: {}", e)))?;
            Self::put_entry_by_id(
                &mut txn,
                self.entries_by_entry_id_db,
                plan.entry_id,
                &new_stored_entry,
            )?;
            self.update_attribute_indexes(&mut txn, plan.entry_id, &new_stored_entry.attributes)?;
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

        for plan in &plans {
            self.entry_cache.invalidate(&plan.old_normalized_dn);
            self.entry_cache.invalidate(&plan.new_normalized_dn);
            self.auth_cache.invalidate(&plan.old_normalized_dn);
            self.auth_cache.invalidate(&plan.new_normalized_dn);
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

        let normalized_dn = Self::normalize_dn(dn)?;

        let entry_id = match Self::entry_id_for_normalized_dn(
            &txn,
            self.entry_id_by_normalized_dn_db,
            &normalized_dn,
        )? {
            Some(entry_id) => entry_id,
            None => return Err(BackendError::NotFound),
        };

        self.put_credential_index(&mut txn, entry_id, hashed_password)?;

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

        let normalized_dn = Self::normalize_dn(dn)?;
        let Some((entry_id, mut entry)) = Self::get_entry_by_normalized_dn(
            &txn,
            self.entries_by_entry_id_db,
            self.entry_id_by_normalized_dn_db,
            self.dn_by_entry_id_db,
            &normalized_dn,
        )?
        else {
            return Ok(false);
        };

        let csn = self.csn_generator.generate();
        if !update(&mut entry.operational_attributes, csn.clone()) {
            return Ok(false);
        }
        entry.modified_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self::put_entry_by_id(&mut txn, self.entries_by_entry_id_db, entry_id, &entry)?;

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

    /// Normalize DN for RFC 4514-aware case-insensitive comparison.
    fn normalize_dn(dn: &str) -> Result<String, BackendError> {
        canonicalize_dn(dn).map_err(|err| BackendError::InvalidDn(err.to_string()))
    }

    fn plan_dn_renames_in_txn(
        txn: &lmdb::RwTransaction<'_>,
        dn_by_entry_id_db: Database,
        entry_id_by_normalized_dn_db: Database,
        old_dn: &str,
        new_dn: &str,
    ) -> Result<Vec<DnRenamePlan>, BackendError> {
        let old_dn = parse_dn(old_dn).map_err(|err| BackendError::InvalidDn(err.to_string()))?;
        let new_dn = parse_dn(new_dn).map_err(|err| BackendError::InvalidDn(err.to_string()))?;
        let mut cursor = txn.open_ro_cursor(dn_by_entry_id_db).map_err(|e| {
            BackendError::Storage(format!("Failed to open entry id DN cursor: {}", e))
        })?;
        let mut plans = Vec::new();

        for (entry_id_bytes, current_dn_bytes) in cursor.iter() {
            let entry_id = Self::entry_id_from_bytes(entry_id_bytes, "dn_by_entry_id")?;
            let current_dn = std::str::from_utf8(current_dn_bytes).map_err(|err| {
                BackendError::Storage(format!("Invalid UTF-8 DN in entry id map: {}", err))
            })?;
            let parsed_current =
                parse_dn(current_dn).map_err(|err| BackendError::InvalidDn(err.to_string()))?;
            if !parsed_current.is_descendant_or_equal_of(&old_dn) {
                continue;
            }

            let prefix_len = parsed_current.rdns().len() - old_dn.rdns().len();
            let mut next_rdns = parsed_current.rdns()[..prefix_len].to_vec();
            next_rdns.extend(new_dn.rdns().to_vec());
            let next_dn = LdapDn::from_rdns(next_rdns).to_canonical_string();
            plans.push(DnRenamePlan {
                entry_id,
                old_dn: current_dn.to_string(),
                new_normalized_dn: Self::normalize_dn(&next_dn)?,
                old_normalized_dn: Self::normalize_dn(current_dn)?,
                new_dn: next_dn,
            });
        }

        for plan in &plans {
            if let Some(existing_entry_id) = Self::entry_id_for_normalized_dn(
                txn,
                entry_id_by_normalized_dn_db,
                &plan.new_normalized_dn,
            )? && !plans
                .iter()
                .any(|candidate| candidate.entry_id == existing_entry_id)
            {
                return Err(BackendError::AlreadyExists);
            }
        }

        plans.sort_by_key(|plan| plan.old_dn.len());
        Ok(plans)
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

    fn serialize_stored_entry_record(entry: &StoredEntry) -> Result<Vec<u8>, BackendError> {
        let record = StoredEntryRecord::from(entry);
        bincode::serialize(&record)
            .map_err(|e| BackendError::Storage(format!("Failed to serialize entry: {}", e)))
    }

    fn deserialize_stored_entry_record(
        dn: String,
        bytes: &[u8],
    ) -> Result<StoredEntry, BackendError> {
        match bincode::deserialize::<StoredEntryRecord>(bytes) {
            Ok(record) => Ok(record.into_stored_entry(dn)),
            Err(record_err) => Self::deserialize_stored_entry(bytes).map_err(|legacy_err| {
                BackendError::Storage(format!(
                    "Failed to deserialize compact entry: {record_err}; legacy decode failed: {legacy_err}"
                ))
            }),
        }
    }

    fn get_entry_by_id<T: Transaction>(
        txn: &T,
        entries_by_entry_id_db: Database,
        dn_by_entry_id_db: Database,
        entry_id: u64,
    ) -> Result<Option<StoredEntry>, BackendError> {
        let Some(dn) = Self::dn_for_entry_id(txn, dn_by_entry_id_db, entry_id)? else {
            return Ok(None);
        };
        let entry_id_bytes = Self::entry_id_bytes(entry_id);
        match txn.get(entries_by_entry_id_db, &entry_id_bytes) {
            Ok(entry_bytes) => Self::deserialize_stored_entry_record(dn, entry_bytes).map(Some),
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(BackendError::Storage(format!(
                "Failed to read entry for id {}: {}",
                entry_id, e
            ))),
        }
    }

    fn required_entry_by_id<T: Transaction>(
        txn: &T,
        entries_by_entry_id_db: Database,
        dn_by_entry_id_db: Database,
        entry_id: u64,
    ) -> Result<StoredEntry, BackendError> {
        Self::get_entry_by_id(txn, entries_by_entry_id_db, dn_by_entry_id_db, entry_id)?
            .ok_or_else(|| BackendError::Storage(format!("entry id {entry_id} has no entry row")))
    }

    fn get_entry_by_normalized_dn<T: Transaction>(
        txn: &T,
        entries_by_entry_id_db: Database,
        entry_id_by_normalized_dn_db: Database,
        dn_by_entry_id_db: Database,
        normalized_dn: &str,
    ) -> Result<Option<(u64, StoredEntry)>, BackendError> {
        let Some(entry_id) =
            Self::entry_id_for_normalized_dn(txn, entry_id_by_normalized_dn_db, normalized_dn)?
        else {
            return Ok(None);
        };
        let Some(entry) =
            Self::get_entry_by_id(txn, entries_by_entry_id_db, dn_by_entry_id_db, entry_id)?
        else {
            return Ok(None);
        };
        Ok(Some((entry_id, entry)))
    }

    fn put_entry_by_id(
        txn: &mut lmdb::RwTransaction<'_>,
        entries_by_entry_id_db: Database,
        entry_id: u64,
        entry: &StoredEntry,
    ) -> Result<(), BackendError> {
        let entry_bytes = Self::serialize_stored_entry_record(entry)?;
        txn.put(
            entries_by_entry_id_db,
            &Self::entry_id_bytes(entry_id),
            &entry_bytes,
            WriteFlags::empty(),
        )
        .map_err(|e| BackendError::Storage(format!("Failed to write entry: {}", e)))
    }

    /// Get entry by DN with read transaction (optimized for concurrency)
    fn get_entry_internal(&self, dn: &str) -> Result<Option<Arc<StoredEntry>>, BackendError> {
        let _profile_total = PerfPhase::start("lmdb_get_entry", "total", None);
        let normalized_dn = Self::normalize_dn(dn)?;
        if let Some(entry) = self.entry_cache.get(&normalized_dn) {
            return Ok(Some(entry));
        }

        let txn = {
            let _profile_phase = PerfPhase::start("lmdb_get_entry", "read_txn", None);
            self.env
                .begin_ro_txn()
                .map_err(|e| BackendError::Storage(format!("Failed to begin read txn: {}", e)))?
        };

        {
            let _profile_phase = PerfPhase::start("lmdb_get_entry", "entry_id_lookup", None);
            let Some((_, entry)) = Self::get_entry_by_normalized_dn(
                &txn,
                self.entries_by_entry_id_db,
                self.entry_id_by_normalized_dn_db,
                self.dn_by_entry_id_db,
                &normalized_dn,
            )?
            else {
                return Ok(None);
            };
            let entry = Arc::new(entry);
            self.entry_cache.insert(&normalized_dn, Arc::clone(&entry));
            Ok(Some(entry))
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
            .open_ro_cursor(self.entries_by_entry_id_db)
            .map_err(|e| BackendError::Storage(format!("Failed to open cursor: {}", e)))?;

        for (key, value) in cursor.iter() {
            let entry_id = Self::entry_id_from_bytes(key, ENTRIES_BY_ENTRY_ID_DB_NAME)?;
            let Some(dn) = Self::dn_for_entry_id(&txn, self.dn_by_entry_id_db, entry_id)? else {
                continue;
            };

            if Self::entry_in_scope(&dn, base_dn, scope) {
                let entry = Self::deserialize_stored_entry_record(dn, value)?;
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
            .open_ro_cursor(self.entries_by_entry_id_db)
            .map_err(|e| BackendError::Storage(format!("Failed to open cursor: {}", e)))?;

        for (key, value) in cursor.iter() {
            let entry_id = Self::entry_id_from_bytes(key, ENTRIES_BY_ENTRY_ID_DB_NAME)?;
            let Some(dn) = Self::dn_for_entry_id(&txn, self.dn_by_entry_id_db, entry_id)? else {
                continue;
            };
            if !Self::entry_in_scope(&dn, base_dn, scope) {
                continue;
            }

            if matched < offset {
                matched += 1;
                continue;
            }

            let entry = Self::deserialize_stored_entry_record(dn, value)?;
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
            .open_ro_cursor(self.entries_by_entry_id_db)
            .map_err(|e| BackendError::Storage(format!("Failed to open cursor: {}", e)))?;

        for (key, _) in cursor.iter() {
            let entry_id = Self::entry_id_from_bytes(key, ENTRIES_BY_ENTRY_ID_DB_NAME)?;
            let Some(dn) = Self::dn_for_entry_id(&txn, self.dn_by_entry_id_db, entry_id)? else {
                continue;
            };
            if Self::entry_in_scope(&dn, base_dn, scope) {
                count += 1;
            }
        }

        Ok(count)
    }

    /// Check if DN is in search scope
    fn entry_in_scope(dn: &str, base_dn: &str, scope: SearchScope) -> bool {
        dn_is_in_scope(dn, base_dn, scope)
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

    fn encode_credential_record(record: &AuthCredentialRecord) -> Option<Vec<u8>> {
        let salt_len = u16::try_from(record.salt.len()).ok()?;
        let mut bytes = Vec::with_capacity(1 + 2 + record.hash.len() + record.salt.len());
        bytes.push(CREDENTIAL_RECORD_FORMAT_VERSION);
        bytes.extend_from_slice(&salt_len.to_be_bytes());
        bytes.extend_from_slice(&record.hash);
        bytes.extend_from_slice(&record.salt);
        Some(bytes)
    }

    fn credential_index_value_from_hash(stored_hash: &str) -> Vec<u8> {
        Self::decode_ssha512_hash(stored_hash)
            .and_then(|record| Self::encode_credential_record(&record))
            .unwrap_or_else(|| stored_hash.as_bytes().to_vec())
    }

    fn credential_index_value_from_password_bytes(stored_hash: &[u8]) -> Vec<u8> {
        std::str::from_utf8(stored_hash)
            .map(Self::credential_index_value_from_hash)
            .unwrap_or_else(|_| stored_hash.to_vec())
    }

    fn decode_credential_index_value(bytes: &[u8]) -> Option<AuthCredentialRecord> {
        if let Some((&version, rest)) = bytes.split_first()
            && version == CREDENTIAL_RECORD_FORMAT_VERSION
        {
            if rest.len() < 2 + 64 {
                return None;
            }
            let salt_len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
            let credential = &rest[2..];
            if credential.len() != 64 + salt_len {
                return None;
            }
            let mut hash = [0; 64];
            hash.copy_from_slice(&credential[..64]);
            return Some(AuthCredentialRecord {
                hash,
                salt: credential[64..].to_vec(),
            });
        }

        let stored_hash = String::from_utf8_lossy(bytes);
        Self::decode_ssha512_hash(&stored_hash)
    }

    fn put_credential_index(
        &self,
        txn: &mut lmdb::RwTransaction<'_>,
        entry_id: u64,
        password_hash: &str,
    ) -> Result<(), BackendError> {
        let credential_value = Self::credential_index_value_from_hash(password_hash);
        txn.put(
            self.credentials_by_entry_id_db,
            &Self::entry_id_bytes(entry_id),
            &credential_value,
            WriteFlags::empty(),
        )
        .map_err(|e| BackendError::Storage(format!("Failed to write credential index: {}", e)))
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

    fn equality_index_key(value: &str) -> String {
        format!("{EQUALITY_INDEX_KEY_PREFIX}{value}")
    }

    fn equality_index_prefix(value: &str) -> String {
        Self::equality_index_key(value)
    }

    fn presence_index_key() -> &'static str {
        PRESENCE_INDEX_KEY
    }

    fn presence_index_prefix() -> &'static str {
        Self::presence_index_key()
    }

    fn substring_index_key(token: &str) -> String {
        format!("{SUBSTRING_INDEX_KEY_PREFIX}{token}")
    }

    fn substring_index_prefix(token: &str) -> String {
        Self::substring_index_key(token)
    }

    fn ordering_index_key(value: &str) -> String {
        format!("{ORDERING_INDEX_KEY_PREFIX}{value}")
    }

    fn ordering_index_prefix() -> &'static str {
        ORDERING_INDEX_KEY_PREFIX
    }

    fn ordering_index_key_value(key: &[u8]) -> Result<Option<&str>, BackendError> {
        let key = std::str::from_utf8(key)
            .map_err(|e| BackendError::Storage(format!("Invalid UTF-8 in index key: {}", e)))?;
        Ok(key.strip_prefix(ORDERING_INDEX_KEY_PREFIX))
    }

    fn legacy_attribute_index_db_name(attr: &str) -> String {
        format!("idx_{attr}")
    }

    fn legacy_attribute_index_db_names(attr: &str) -> [String; 2] {
        [
            Self::legacy_attribute_index_db_name(attr),
            format!("idx2_{attr}"),
        ]
    }

    fn attribute_index_keys(
        index_db: Database,
        entry_id: u64,
        values: &[String],
        plan: &AttributeIndexPlan,
    ) -> Result<Vec<(Database, String, [u8; 8])>, BackendError> {
        let mut index_keys = Vec::new();
        let entry_id_bytes = Self::entry_id_bytes(entry_id);
        Self::for_each_attribute_index_key(values, plan, |index_key| {
            index_keys.push((index_db, index_key, entry_id_bytes));
            Ok(())
        })?;

        Ok(index_keys)
    }

    fn for_each_attribute_index_key<F>(
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
            visit(Self::presence_index_key().to_string())?;
        }

        for value in values {
            if has_equality {
                let normalized_value = plan.normalize_equality_value(value)?;
                visit(Self::equality_index_key(&normalized_value))?;
            }

            if has_substring {
                let normalized_value = plan.normalize_substring_value(value)?;
                for token in Self::substring_index_tokens(&normalized_value) {
                    visit(Self::substring_index_key(&token))?;
                }
            }

            if has_ordering {
                let normalized_value = plan.normalize_ordering_value(value)?;
                visit(Self::ordering_index_key(&normalized_value))?;
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
        segments.sort_by_key(|segment| std::cmp::Reverse(segment.0));

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

    fn entry_id_bytes(entry_id: u64) -> [u8; 8] {
        entry_id.to_be_bytes()
    }

    fn entry_id_from_bytes(bytes: &[u8], context: &str) -> Result<u64, BackendError> {
        let bytes: [u8; 8] = bytes.try_into().map_err(|_| {
            BackendError::Storage(format!(
                "invalid entry id length for {context}: expected 8 bytes, got {}",
                bytes.len()
            ))
        })?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn read_next_entry_id<T: Transaction>(
        txn: &T,
        metadata_db: Database,
    ) -> Result<u64, BackendError> {
        match txn.get(metadata_db, &NEXT_ENTRY_ID_METADATA_KEY.as_bytes()) {
            Ok(bytes) => Self::entry_id_from_bytes(bytes, NEXT_ENTRY_ID_METADATA_KEY),
            Err(lmdb::Error::NotFound) => Ok(FIRST_ENTRY_ID),
            Err(e) => Err(BackendError::Storage(format!(
                "Failed to read next entry id metadata: {}",
                e
            ))),
        }
    }

    fn put_next_entry_id(
        txn: &mut lmdb::RwTransaction<'_>,
        metadata_db: Database,
        next_entry_id: u64,
    ) -> Result<(), BackendError> {
        txn.put(
            metadata_db,
            &NEXT_ENTRY_ID_METADATA_KEY.as_bytes(),
            &Self::entry_id_bytes(next_entry_id),
            WriteFlags::empty(),
        )
        .map_err(|e| BackendError::Storage(format!("Failed to write next entry id: {}", e)))
    }

    fn entry_id_for_normalized_dn<T: Transaction>(
        txn: &T,
        entry_id_by_normalized_dn_db: Database,
        normalized_dn: &str,
    ) -> Result<Option<u64>, BackendError> {
        match txn.get(entry_id_by_normalized_dn_db, &normalized_dn.as_bytes()) {
            Ok(bytes) => Self::entry_id_from_bytes(bytes, normalized_dn).map(Some),
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(BackendError::Storage(format!(
                "Failed to read entry id for {}: {}",
                normalized_dn, e
            ))),
        }
    }

    fn required_entry_id_for_normalized_dn<T: Transaction>(
        txn: &T,
        entry_id_by_normalized_dn_db: Database,
        normalized_dn: &str,
    ) -> Result<u64, BackendError> {
        Self::entry_id_for_normalized_dn(txn, entry_id_by_normalized_dn_db, normalized_dn)?
            .ok_or_else(|| {
                BackendError::Storage(format!(
                    "entry id index is missing normalized DN {}",
                    normalized_dn
                ))
            })
    }

    fn allocate_entry_id(
        txn: &mut lmdb::RwTransaction<'_>,
        entry_id_by_normalized_dn_db: Database,
        dn_by_entry_id_db: Database,
        normalized_dn: &str,
        dn: &str,
        next_entry_id: &mut u64,
    ) -> Result<u64, BackendError> {
        let entry_id = *next_entry_id;
        *next_entry_id = next_entry_id
            .checked_add(1)
            .ok_or_else(|| BackendError::Storage("entry id counter overflowed".to_string()))?;
        let entry_id_bytes = Self::entry_id_bytes(entry_id);

        txn.put(
            entry_id_by_normalized_dn_db,
            &normalized_dn.as_bytes(),
            &entry_id_bytes,
            WriteFlags::NO_OVERWRITE,
        )
        .map_err(|e| BackendError::Storage(format!("Failed to write entry id index: {}", e)))?;
        txn.put(
            dn_by_entry_id_db,
            &entry_id_bytes,
            &dn.as_bytes(),
            WriteFlags::NO_OVERWRITE,
        )
        .map_err(|e| BackendError::Storage(format!("Failed to write entry id DN: {}", e)))?;

        Ok(entry_id)
    }

    fn dn_for_entry_id<T: Transaction>(
        txn: &T,
        dn_by_entry_id_db: Database,
        entry_id: u64,
    ) -> Result<Option<String>, BackendError> {
        let entry_id_bytes = Self::entry_id_bytes(entry_id);
        match txn.get(dn_by_entry_id_db, &entry_id_bytes) {
            Ok(bytes) => std::str::from_utf8(bytes)
                .map(|dn| Some(dn.to_string()))
                .map_err(|e| BackendError::Storage(format!("Invalid UTF-8 in entry id DN: {}", e))),
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(BackendError::Storage(format!(
                "Failed to read DN for entry id {}: {}",
                entry_id, e
            ))),
        }
    }

    fn dn_for_entry_id_bytes<T: Transaction>(
        txn: &T,
        dn_by_entry_id_db: Database,
        entry_id_bytes: &[u8],
    ) -> Result<Option<String>, BackendError> {
        let entry_id = Self::entry_id_from_bytes(entry_id_bytes, "attribute index value")?;
        Self::dn_for_entry_id(txn, dn_by_entry_id_db, entry_id)
    }

    fn max_entry_id_in_txn(
        txn: &lmdb::RoTransaction<'_>,
        dn_by_entry_id_db: Database,
    ) -> Result<u64, BackendError> {
        let mut cursor = txn
            .open_ro_cursor(dn_by_entry_id_db)
            .map_err(|e| BackendError::Storage(format!("Failed to open entry id cursor: {}", e)))?;
        let mut max_entry_id = 0;
        for (key, _) in cursor.iter() {
            max_entry_id = max_entry_id.max(Self::entry_id_from_bytes(key, "dn_by_entry_id")?);
        }
        Ok(max_entry_id)
    }

    fn open_optional_db(
        env: &Arc<Environment>,
        name: &str,
    ) -> Result<Option<Database>, BackendError> {
        match env.open_db(Some(name)) {
            Ok(db) => Ok(Some(db)),
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(BackendError::Storage(format!(
                "Failed to open optional LMDB database {name}: {e}"
            ))),
        }
    }

    fn clear_legacy_databases(
        env: &Arc<Environment>,
        databases: &[Option<Database>],
    ) -> Result<(), BackendError> {
        let legacy_dbs = databases.iter().flatten().copied().collect::<Vec<_>>();
        if legacy_dbs.is_empty() {
            return Ok(());
        }

        let mut txn = env.begin_rw_txn().map_err(|e| {
            BackendError::Storage(format!(
                "Failed to begin legacy database cleanup txn: {}",
                e
            ))
        })?;
        for db in legacy_dbs {
            txn.clear_db(db).map_err(|e| {
                BackendError::Storage(format!("Failed to clear legacy database: {}", e))
            })?;
        }
        txn.commit().map_err(|e| {
            BackendError::Storage(format!("Failed to commit legacy database cleanup: {}", e))
        })
    }

    fn ensure_entry_ids_backfilled(
        env: &Arc<Environment>,
        legacy_entries_db: Option<Database>,
        metadata_db: Database,
        entry_id_by_normalized_dn_db: Database,
        dn_by_entry_id_db: Database,
    ) -> Result<(), BackendError> {
        {
            let txn = env.begin_ro_txn().map_err(|e| {
                BackendError::Storage(format!("Failed to begin entry id metadata read txn: {}", e))
            })?;
            match txn.get(metadata_db, &ENTRY_ID_INDEX_METADATA_KEY.as_bytes()) {
                Ok(value) if value == ENTRY_ID_INDEX_VERSION => return Ok(()),
                Ok(_) | Err(lmdb::Error::NotFound) => {}
                Err(e) => {
                    return Err(BackendError::Storage(format!(
                        "Failed to read entry id metadata: {}",
                        e
                    )));
                }
            }
        }

        let read_txn = env.begin_ro_txn().map_err(|e| {
            BackendError::Storage(format!("Failed to begin entry id backfill read txn: {}", e))
        })?;
        let max_existing_id = Self::max_entry_id_in_txn(&read_txn, dn_by_entry_id_db)?;
        let metadata_next_id = Self::read_next_entry_id(&read_txn, metadata_db)?;
        let mut next_entry_id = metadata_next_id.max(max_existing_id.saturating_add(1));
        let mut txn = env.begin_rw_txn().map_err(|e| {
            BackendError::Storage(format!("Failed to begin entry id backfill txn: {}", e))
        })?;
        let mut pending_writes = 0usize;

        if let Some(entries_db) = legacy_entries_db {
            let mut cursor = read_txn.open_ro_cursor(entries_db).map_err(|e| {
                BackendError::Storage(format!(
                    "Failed to open entries cursor for entry id backfill: {}",
                    e
                ))
            })?;

            for (dn_bytes, _) in cursor.iter() {
                let dn = std::str::from_utf8(dn_bytes).map_err(|e| {
                    BackendError::Storage(format!(
                        "Invalid UTF-8 DN in entries database during entry id backfill: {}",
                        e
                    ))
                })?;
                let normalized_dn = Self::normalize_dn(dn)?;
                if Self::entry_id_for_normalized_dn(
                    &read_txn,
                    entry_id_by_normalized_dn_db,
                    &normalized_dn,
                )?
                .is_some()
                {
                    continue;
                }

                Self::allocate_entry_id(
                    &mut txn,
                    entry_id_by_normalized_dn_db,
                    dn_by_entry_id_db,
                    &normalized_dn,
                    dn,
                    &mut next_entry_id,
                )?;
                pending_writes += 1;
                if pending_writes >= ENTRY_ID_BACKFILL_BATCH_SIZE {
                    Self::put_next_entry_id(&mut txn, metadata_db, next_entry_id)?;
                    txn.commit().map_err(|e| {
                        BackendError::Storage(format!(
                            "Failed to commit entry id backfill batch: {}",
                            e
                        ))
                    })?;
                    txn = env.begin_rw_txn().map_err(|e| {
                        BackendError::Storage(format!(
                            "Failed to begin entry id backfill batch txn: {}",
                            e
                        ))
                    })?;
                    pending_writes = 0;
                }
            }
            drop(cursor);
        }
        drop(read_txn);

        Self::put_next_entry_id(&mut txn, metadata_db, next_entry_id)?;
        txn.put(
            metadata_db,
            &ENTRY_ID_INDEX_METADATA_KEY.as_bytes(),
            &ENTRY_ID_INDEX_VERSION,
            WriteFlags::empty(),
        )
        .map_err(|e| BackendError::Storage(format!("Failed to mark entry ids ready: {}", e)))?;
        txn.commit().map_err(|e| {
            BackendError::Storage(format!("Failed to commit entry id backfill: {}", e))
        })?;

        Ok(())
    }

    fn ensure_entries_by_entry_id_backfilled(
        env: &Arc<Environment>,
        legacy_entries_db: Option<Database>,
        entries_by_entry_id_db: Database,
        metadata_db: Database,
        entry_id_by_normalized_dn_db: Database,
    ) -> Result<(), BackendError> {
        {
            let txn = env.begin_ro_txn().map_err(|e| {
                BackendError::Storage(format!(
                    "Failed to begin entry storage metadata read txn: {}",
                    e
                ))
            })?;
            match txn.get(metadata_db, &ENTRY_STORAGE_METADATA_KEY.as_bytes()) {
                Ok(value) if value == ENTRY_STORAGE_VERSION => return Ok(()),
                Ok(_) | Err(lmdb::Error::NotFound) => {}
                Err(e) => {
                    return Err(BackendError::Storage(format!(
                        "Failed to read entry storage metadata: {}",
                        e
                    )));
                }
            }
        }

        let mut txn = env.begin_rw_txn().map_err(|e| {
            BackendError::Storage(format!("Failed to begin entry storage clear txn: {}", e))
        })?;
        txn.clear_db(entries_by_entry_id_db).map_err(|e| {
            BackendError::Storage(format!("Failed to clear ID-keyed entries: {}", e))
        })?;
        txn.commit().map_err(|e| {
            BackendError::Storage(format!("Failed to commit entry storage clear: {}", e))
        })?;

        let read_txn = env.begin_ro_txn().map_err(|e| {
            BackendError::Storage(format!(
                "Failed to begin entry storage backfill read txn: {}",
                e
            ))
        })?;
        let mut txn = env.begin_rw_txn().map_err(|e| {
            BackendError::Storage(format!("Failed to begin entry storage backfill txn: {}", e))
        })?;
        let mut pending_writes = 0usize;

        if let Some(entries_db) = legacy_entries_db {
            let mut cursor = read_txn.open_ro_cursor(entries_db).map_err(|e| {
                BackendError::Storage(format!(
                    "Failed to open legacy entries cursor for ID-keyed entry backfill: {}",
                    e
                ))
            })?;

            for (dn_bytes, entry_bytes) in cursor.iter() {
                let dn = std::str::from_utf8(dn_bytes).map_err(|e| {
                    BackendError::Storage(format!(
                        "Invalid UTF-8 DN in legacy entries database during backfill: {}",
                        e
                    ))
                })?;
                let normalized_dn = Self::normalize_dn(dn)?;
                let entry_id = Self::required_entry_id_for_normalized_dn(
                    &read_txn,
                    entry_id_by_normalized_dn_db,
                    &normalized_dn,
                )?;
                let mut entry = Self::deserialize_stored_entry(entry_bytes)?;
                entry.dn = dn.to_string();
                Self::put_entry_by_id(&mut txn, entries_by_entry_id_db, entry_id, &entry)?;

                pending_writes += 1;
                if pending_writes >= ENTRY_STORAGE_BACKFILL_BATCH_SIZE {
                    txn.commit().map_err(|e| {
                        BackendError::Storage(format!(
                            "Failed to commit entry storage backfill batch: {}",
                            e
                        ))
                    })?;
                    txn = env.begin_rw_txn().map_err(|e| {
                        BackendError::Storage(format!(
                            "Failed to begin entry storage backfill batch txn: {}",
                            e
                        ))
                    })?;
                    pending_writes = 0;
                }
            }
            drop(cursor);
        }
        drop(read_txn);

        txn.put(
            metadata_db,
            &ENTRY_STORAGE_METADATA_KEY.as_bytes(),
            &ENTRY_STORAGE_VERSION,
            WriteFlags::empty(),
        )
        .map_err(|e| {
            BackendError::Storage(format!(
                "Failed to mark ID-keyed entry storage ready: {}",
                e
            ))
        })?;
        txn.commit().map_err(|e| {
            BackendError::Storage(format!("Failed to commit entry storage backfill: {}", e))
        })?;

        Ok(())
    }

    fn ensure_credential_index_backfilled(
        env: &Arc<Environment>,
        legacy_passwords_db: Option<Database>,
        legacy_credentials_by_normalized_dn_db: Option<Database>,
        metadata_db: Database,
        entry_id_by_normalized_dn_db: Database,
        credentials_by_entry_id_db: Database,
    ) -> Result<(), BackendError> {
        {
            let txn = env.begin_ro_txn().map_err(|e| {
                BackendError::Storage(format!(
                    "Failed to begin credential index metadata read txn: {}",
                    e
                ))
            })?;
            match txn.get(metadata_db, &CREDENTIAL_INDEX_METADATA_KEY.as_bytes()) {
                Ok(value) if value == CREDENTIAL_INDEX_VERSION => return Ok(()),
                Ok(_) | Err(lmdb::Error::NotFound) => {}
                Err(e) => {
                    return Err(BackendError::Storage(format!(
                        "Failed to read credential index metadata: {}",
                        e
                    )));
                }
            }
        }

        let mut txn = env.begin_rw_txn().map_err(|e| {
            BackendError::Storage(format!(
                "Failed to begin credential index backfill txn: {}",
                e
            ))
        })?;
        txn.clear_db(credentials_by_entry_id_db).map_err(|e| {
            BackendError::Storage(format!("Failed to clear ID-keyed credential index: {}", e))
        })?;
        txn.commit().map_err(|e| {
            BackendError::Storage(format!("Failed to commit credential index clear: {}", e))
        })?;

        let read_txn = env.begin_ro_txn().map_err(|e| {
            BackendError::Storage(format!(
                "Failed to begin credential index backfill read txn: {}",
                e
            ))
        })?;
        let mut txn = env.begin_rw_txn().map_err(|e| {
            BackendError::Storage(format!(
                "Failed to begin credential index backfill txn: {}",
                e
            ))
        })?;
        let mut pending_writes = 0usize;

        if let Some(credentials_db) = legacy_credentials_by_normalized_dn_db {
            let mut cursor = read_txn.open_ro_cursor(credentials_db).map_err(|e| {
                BackendError::Storage(format!(
                    "Failed to open normalized-DN credential cursor for backfill: {}",
                    e
                ))
            })?;
            for (normalized_dn_bytes, credential_value) in cursor.iter() {
                let normalized_dn = std::str::from_utf8(normalized_dn_bytes).map_err(|e| {
                    BackendError::Storage(format!(
                        "Invalid UTF-8 normalized DN in credential database during backfill: {}",
                        e
                    ))
                })?;
                let Some(entry_id) = Self::entry_id_for_normalized_dn(
                    &read_txn,
                    entry_id_by_normalized_dn_db,
                    normalized_dn,
                )?
                else {
                    continue;
                };
                txn.put(
                    credentials_by_entry_id_db,
                    &Self::entry_id_bytes(entry_id),
                    &credential_value,
                    WriteFlags::empty(),
                )
                .map_err(|e| {
                    BackendError::Storage(format!(
                        "Failed to backfill credential index for {}: {}",
                        normalized_dn, e
                    ))
                })?;
                pending_writes += 1;
                if pending_writes >= CREDENTIAL_INDEX_BACKFILL_BATCH_SIZE {
                    txn.commit().map_err(|e| {
                        BackendError::Storage(format!(
                            "Failed to commit credential index backfill batch: {}",
                            e
                        ))
                    })?;
                    txn = env.begin_rw_txn().map_err(|e| {
                        BackendError::Storage(format!(
                            "Failed to begin credential index backfill batch txn: {}",
                            e
                        ))
                    })?;
                    pending_writes = 0;
                }
            }
            drop(cursor);
        }

        if let Some(passwords_db) = legacy_passwords_db {
            let mut cursor = read_txn.open_ro_cursor(passwords_db).map_err(|e| {
                BackendError::Storage(format!(
                    "Failed to open passwords cursor for credential index backfill: {}",
                    e
                ))
            })?;
            for (dn_bytes, password_hash) in cursor.iter() {
                let dn = std::str::from_utf8(dn_bytes).map_err(|e| {
                    BackendError::Storage(format!(
                        "Invalid UTF-8 DN in password database during credential index backfill: {}",
                        e
                    ))
                })?;
                let normalized_dn = Self::normalize_dn(dn)?;
                let Some(entry_id) = Self::entry_id_for_normalized_dn(
                    &read_txn,
                    entry_id_by_normalized_dn_db,
                    &normalized_dn,
                )?
                else {
                    continue;
                };
                let credential_value =
                    Self::credential_index_value_from_password_bytes(password_hash);
                txn.put(
                    credentials_by_entry_id_db,
                    &Self::entry_id_bytes(entry_id),
                    &credential_value,
                    WriteFlags::empty(),
                )
                .map_err(|e| {
                    BackendError::Storage(format!(
                        "Failed to backfill credential index for {}: {}",
                        dn, e
                    ))
                })?;
                pending_writes += 1;
                if pending_writes >= CREDENTIAL_INDEX_BACKFILL_BATCH_SIZE {
                    txn.commit().map_err(|e| {
                        BackendError::Storage(format!(
                            "Failed to commit credential index backfill batch: {}",
                            e
                        ))
                    })?;
                    txn = env.begin_rw_txn().map_err(|e| {
                        BackendError::Storage(format!(
                            "Failed to begin credential index backfill batch txn: {}",
                            e
                        ))
                    })?;
                    pending_writes = 0;
                }
            }
            drop(cursor);
        }
        drop(read_txn);
        txn.put(
            metadata_db,
            &CREDENTIAL_INDEX_METADATA_KEY.as_bytes(),
            &CREDENTIAL_INDEX_VERSION,
            WriteFlags::empty(),
        )
        .map_err(|e| {
            BackendError::Storage(format!("Failed to mark credential index ready: {}", e))
        })?;
        txn.commit().map_err(|e| {
            BackendError::Storage(format!("Failed to commit credential index backfill: {}", e))
        })?;

        Ok(())
    }

    fn ensure_attribute_indexes_backfilled(
        env: &Arc<Environment>,
        entries_by_entry_id_db: Database,
        dn_by_entry_id_db: Database,
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
        let legacy_index_dbs = Self::open_legacy_attribute_index_databases(env, &pending_indexes)?;
        {
            let mut txn = env.begin_rw_txn().map_err(|e| {
                BackendError::Storage(format!("Failed to begin attribute index clear txn: {}", e))
            })?;
            for (attr, legacy_index_db) in &legacy_index_dbs {
                txn.clear_db(*legacy_index_db).map_err(|e| {
                    BackendError::Storage(format!(
                        "Failed to clear legacy attribute index for {}: {}",
                        attr, e
                    ))
                })?;
            }
            for (_, index_db, _) in &pending_indexes {
                txn.clear_db(*index_db).map_err(|e| {
                    BackendError::Storage(format!("Failed to clear attribute index: {}", e))
                })?;
            }
            txn.commit().map_err(|e| {
                BackendError::Storage(format!("Failed to commit attribute index clear: {}", e))
            })?;
        }

        let read_txn = env.begin_ro_txn().map_err(|e| {
            BackendError::Storage(format!(
                "Failed to begin attribute index backfill read txn: {}",
                e
            ))
        })?;
        let mut cursor = read_txn
            .open_ro_cursor(entries_by_entry_id_db)
            .map_err(|e| {
                BackendError::Storage(format!(
                    "Failed to open entries cursor for attribute index backfill: {}",
                    e
                ))
            })?;
        let mut txn = env.begin_rw_txn().map_err(|e| {
            BackendError::Storage(format!(
                "Failed to begin attribute index backfill write txn: {}",
                e
            ))
        })?;
        let mut pending_writes = 0usize;

        for (entry_id_bytes, entry_bytes) in cursor.iter() {
            let entry_id = Self::entry_id_from_bytes(entry_id_bytes, ENTRIES_BY_ENTRY_ID_DB_NAME)?;
            let Some(dn) = Self::dn_for_entry_id(&read_txn, dn_by_entry_id_db, entry_id)? else {
                continue;
            };
            let entry = Self::deserialize_stored_entry_record(dn, entry_bytes).map_err(|e| {
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
                    for (index_db, index_key, entry_id_bytes) in
                        Self::attribute_index_keys(*index_db, entry_id, values, plan)?
                    {
                        Self::put_attribute_index_entry(
                            &mut txn,
                            index_db,
                            &index_key,
                            &entry_id_bytes,
                            attr_name,
                        )?;
                        pending_writes += 1;
                        if pending_writes >= ATTRIBUTE_INDEX_BACKFILL_BATCH_SIZE {
                            txn.commit().map_err(|e| {
                                BackendError::Storage(format!(
                                    "Failed to commit attribute index backfill batch: {}",
                                    e
                                ))
                            })?;
                            txn = env.begin_rw_txn().map_err(|e| {
                                BackendError::Storage(format!(
                                    "Failed to begin attribute index backfill batch txn: {}",
                                    e
                                ))
                            })?;
                            pending_writes = 0;
                        }
                    }
                }
            }
        }
        drop(cursor);
        drop(read_txn);

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

    fn open_legacy_attribute_index_databases(
        env: &Arc<Environment>,
        pending_indexes: &[(String, Database, AttributeIndexPlan)],
    ) -> Result<Vec<(String, Database)>, BackendError> {
        let mut legacy_index_dbs = Vec::new();

        for (attr, _, _) in pending_indexes {
            for db_name in Self::legacy_attribute_index_db_names(attr) {
                match env.open_db(Some(&db_name)) {
                    Ok(db) => legacy_index_dbs.push((attr.clone(), db)),
                    Err(lmdb::Error::NotFound) => {}
                    Err(e) => {
                        return Err(BackendError::Storage(format!(
                            "Failed to open legacy attribute index for {}: {}",
                            attr, e
                        )));
                    }
                }
            }
        }

        Ok(legacy_index_dbs)
    }

    fn collect_index_dns_by_key(
        txn: &lmdb::RoTransaction<'_>,
        cursor: &mut lmdb::RoCursor<'_>,
        dn_by_entry_id_db: Database,
        key: &[u8],
    ) -> Result<Vec<String>, BackendError> {
        let duplicates = match cursor.iter_dup_of(&key) {
            Ok(duplicates) => duplicates,
            Err(lmdb::Error::NotFound) => return Ok(Vec::new()),
            Err(e) => {
                return Err(BackendError::Storage(format!(
                    "Failed to seek attribute index duplicates: {}",
                    e
                )));
            }
        };

        let mut results = Vec::new();
        for (_, entry_id_bytes) in duplicates {
            if let Some(dn) = Self::dn_for_entry_id_bytes(txn, dn_by_entry_id_db, entry_id_bytes)? {
                results.push(dn);
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
        entry_id: u64,
        attributes: &HashMap<String, Vec<String>>,
    ) -> Result<(), BackendError> {
        self.update_attribute_indexes_for_filter(txn, entry_id, attributes, None)
    }

    fn update_attribute_indexes_for_filter(
        &self,
        txn: &mut lmdb::RwTransaction,
        entry_id: u64,
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
                let entry_id_bytes = Self::entry_id_bytes(entry_id);
                Self::for_each_attribute_index_key(values, plan, |index_key| {
                    Self::put_attribute_index_entry(
                        txn,
                        *index_db,
                        &index_key,
                        &entry_id_bytes,
                        attr_name,
                    )?;
                    Ok(())
                })?;
            }
        }

        Ok(())
    }

    fn put_attribute_index_entry(
        txn: &mut lmdb::RwTransaction<'_>,
        index_db: Database,
        index_key: &str,
        entry_id_bytes: &[u8; 8],
        attribute_name: &str,
    ) -> Result<(), BackendError> {
        txn.put(
            index_db,
            &index_key.as_bytes(),
            entry_id_bytes,
            WriteFlags::NO_DUP_DATA,
        )
        .or_else(|e| match e {
            lmdb::Error::KeyExist => Ok(()),
            _ => Err(BackendError::Storage(format!(
                "Failed to update index for {}: {}",
                attribute_name, e
            ))),
        })
    }

    fn delete_attribute_index_entry(
        txn: &mut lmdb::RwTransaction<'_>,
        index_db: Database,
        index_key: &str,
        entry_id_bytes: &[u8; 8],
        attribute_name: &str,
    ) -> Result<(), BackendError> {
        let mut cursor = txn.open_rw_cursor(index_db).map_err(|e| {
            BackendError::Storage(format!(
                "Failed to open index cursor for {}: {}",
                attribute_name, e
            ))
        })?;
        match cursor.get(
            Some(index_key.as_bytes()),
            Some(entry_id_bytes),
            LMDB_GET_BOTH_OP,
        ) {
            Ok(_) => cursor.del(WriteFlags::empty()).map_err(|e| {
                BackendError::Storage(format!(
                    "Failed to remove index for {}: {}",
                    attribute_name, e
                ))
            }),
            Err(lmdb::Error::NotFound) => Ok(()),
            Err(e) => Err(BackendError::Storage(format!(
                "Failed to seek index for {}: {}",
                attribute_name, e
            ))),
        }
    }

    /// Remove attribute indexes for an entry
    ///
    /// This method removes index entries when an entry is deleted.
    fn remove_attribute_indexes(
        &self,
        txn: &mut lmdb::RwTransaction,
        entry_id: u64,
        attributes: &HashMap<String, Vec<String>>,
    ) -> Result<(), BackendError> {
        self.remove_attribute_indexes_for_filter(txn, entry_id, attributes, None)
    }

    fn remove_attribute_indexes_for_filter(
        &self,
        txn: &mut lmdb::RwTransaction,
        entry_id: u64,
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
                let entry_id_bytes = Self::entry_id_bytes(entry_id);
                Self::for_each_attribute_index_key(values, plan, |index_key| {
                    Self::delete_attribute_index_entry(
                        txn,
                        *index_db,
                        &index_key,
                        &entry_id_bytes,
                        attr_name,
                    )?;
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
        let search_key = Self::equality_index_prefix(&normalized_value);
        Self::collect_index_dns_by_key(
            txn,
            &mut cursor,
            self.dn_by_entry_id_db,
            search_key.as_bytes(),
        )
        .map(Some)
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
        let search_key = Self::presence_index_prefix();
        Self::collect_index_dns_by_key(
            txn,
            &mut cursor,
            self.dn_by_entry_id_db,
            search_key.as_bytes(),
        )
        .map(Some)
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
            let search_key = Self::substring_index_prefix(&token);
            let token_dns = Self::collect_index_dns_by_key(
                txn,
                &mut cursor,
                self.dn_by_entry_id_db,
                search_key.as_bytes(),
            )?;
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
            Self::ordering_index_key(&normalized_value)
        } else {
            Self::ordering_index_prefix().to_string()
        };
        let (first_key, first_entry_id) =
            match cursor.get(Some(seek_key.as_bytes()), None, LMDB_SET_RANGE_OP) {
                Ok((Some(key), entry_id)) => (key, entry_id),
                Ok((None, entry_id)) => (seek_key.as_bytes(), entry_id),
                Err(lmdb::Error::NotFound) => return Ok(Some(Vec::new())),
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
            txn,
            self.dn_by_entry_id_db,
            first_key,
            first_entry_id,
            &normalized_value,
            greater_or_equal,
            &mut results,
        )? {
            for (key, entry_id) in cursor.iter() {
                if !key.starts_with(Self::ordering_index_prefix().as_bytes()) {
                    break;
                }
                if !Self::push_ordering_candidate(
                    txn,
                    self.dn_by_entry_id_db,
                    key,
                    entry_id,
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
        txn: &lmdb::RoTransaction<'_>,
        dn_by_entry_id_db: Database,
        key: &[u8],
        entry_id_bytes: &[u8],
        target_value: &str,
        greater_or_equal: bool,
        results: &mut Vec<String>,
    ) -> Result<bool, BackendError> {
        let Some(value) = Self::ordering_index_key_value(key)? else {
            return Ok(false);
        };

        let in_range = if greater_or_equal {
            value >= target_value
        } else {
            value <= target_value
        };

        if in_range {
            if let Some(dn) = Self::dn_for_entry_id_bytes(txn, dn_by_entry_id_db, entry_id_bytes)? {
                results.push(dn);
            }
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
        let mut results = Vec::with_capacity(dns.len());
        let mut seen_dns = dedupe_dns.then(|| HashSet::with_capacity(dns.len()));

        for dn in dns {
            if seen_dns
                .as_mut()
                .is_some_and(|seen_dns| !seen_dns.insert(dn.as_str()))
            {
                continue;
            }
            if !Self::entry_in_scope(dn, base_dn, scope) {
                continue;
            }
            let normalized_dn = Self::normalize_dn(dn)?;
            let Some((_, entry)) = Self::get_entry_by_normalized_dn(
                txn,
                self.entries_by_entry_id_db,
                self.entry_id_by_normalized_dn_db,
                self.dn_by_entry_id_db,
                &normalized_dn,
            )?
            else {
                continue;
            };
            if !include_entry(&entry)? {
                continue;
            }
            results.push(entry.to_directory_entry());
        }

        Ok(results)
    }

    fn search_stream_plan(
        &self,
        base_dn: &str,
        scope: SearchScope,
        hint: Option<SearchCandidateHint>,
    ) -> Result<SearchStreamPlan, BackendError> {
        let uncovered = |fallback_reason| SearchStreamPlan::Uncovered {
            base_dn: base_dn.to_string(),
            scope,
            fallback_reason,
        };

        let Some(hint) = hint else {
            return Ok(uncovered(SearchPlanFallbackReason::MissingHint));
        };

        match hint {
            SearchCandidateHint::Equality { attribute, value } => {
                if self.index_ready_for_search(&attribute, IndexType::Equality)? {
                    Ok(SearchStreamPlan::Equality {
                        base_dn: base_dn.to_string(),
                        scope,
                        attribute,
                        value,
                    })
                } else {
                    Ok(uncovered(SearchPlanFallbackReason::IndexUnavailable))
                }
            }
            SearchCandidateHint::Present { attribute } => {
                if self.index_ready_for_search(&attribute, IndexType::Presence)? {
                    Ok(SearchStreamPlan::Present {
                        base_dn: base_dn.to_string(),
                        scope,
                        attribute,
                    })
                } else {
                    Ok(uncovered(SearchPlanFallbackReason::IndexUnavailable))
                }
            }
            SearchCandidateHint::Substring { attribute, parts } => {
                if self.index_ready_for_search(&attribute, IndexType::Substring)? {
                    Ok(SearchStreamPlan::Substring {
                        base_dn: base_dn.to_string(),
                        scope,
                        attribute,
                        parts,
                    })
                } else {
                    Ok(uncovered(SearchPlanFallbackReason::IndexUnavailable))
                }
            }
            SearchCandidateHint::GreaterOrEqual { attribute, value } => {
                if self.index_ready_for_search(&attribute, IndexType::Ordering)? {
                    Ok(SearchStreamPlan::Ordering {
                        base_dn: base_dn.to_string(),
                        scope,
                        attribute,
                        value,
                        greater_or_equal: true,
                    })
                } else {
                    Ok(uncovered(SearchPlanFallbackReason::IndexUnavailable))
                }
            }
            SearchCandidateHint::LessOrEqual { attribute, value } => {
                if self.index_ready_for_search(&attribute, IndexType::Ordering)? {
                    Ok(SearchStreamPlan::Ordering {
                        base_dn: base_dn.to_string(),
                        scope,
                        attribute,
                        value,
                        greater_or_equal: false,
                    })
                } else {
                    Ok(uncovered(SearchPlanFallbackReason::IndexUnavailable))
                }
            }
        }
    }

    fn index_ready_for_search(
        &self,
        attribute: &str,
        index_type: IndexType,
    ) -> Result<bool, BackendError> {
        let attr_lower = ldap_attribute_key(attribute);
        if !self.has_index_type(attr_lower.as_ref(), index_type) {
            return Ok(false);
        }

        let indexes = self
            .attr_indexes
            .try_read()
            .map_err(|e| BackendError::Storage(format!("Failed to acquire index lock: {}", e)))?;
        Ok(indexes.contains_key(attr_lower.as_ref()))
    }

    fn stream_search_entries_plan<F>(
        &self,
        plan: SearchStreamPlan,
        mut send_entry: F,
    ) -> Result<(), BackendError>
    where
        F: FnMut(DirectoryEntry) -> bool,
    {
        match plan {
            SearchStreamPlan::Uncovered { base_dn, scope, .. } => {
                self.stream_uncovered_entries(&base_dn, scope, &mut send_entry)
            }
            SearchStreamPlan::Equality {
                base_dn,
                scope,
                attribute,
                value,
            } => self.stream_equality_index_entries(
                &base_dn,
                scope,
                &attribute,
                &value,
                &mut send_entry,
            ),
            SearchStreamPlan::Present {
                base_dn,
                scope,
                attribute,
            } => self.stream_presence_index_entries(&base_dn, scope, &attribute, &mut send_entry),
            SearchStreamPlan::Substring {
                base_dn,
                scope,
                attribute,
                parts,
            } => self.stream_substring_index_entries(
                &base_dn,
                scope,
                &attribute,
                &parts,
                &mut send_entry,
            ),
            SearchStreamPlan::Ordering {
                base_dn,
                scope,
                attribute,
                value,
                greater_or_equal,
            } => self.stream_ordering_index_entries(
                &base_dn,
                scope,
                &attribute,
                &value,
                greater_or_equal,
                &mut send_entry,
            ),
        }
    }

    fn stream_projected_search_entries_plan<F>(
        &self,
        plan: SearchStreamPlan,
        requested_attributes: &[String],
        mut send_entry: F,
    ) -> Result<(), BackendError>
    where
        F: FnMut(ProjectedDirectoryEntry) -> bool,
    {
        match plan {
            SearchStreamPlan::Equality {
                base_dn,
                scope,
                attribute,
                value,
            } => self.stream_projected_equality_index_entries(
                &base_dn,
                scope,
                &attribute,
                &value,
                requested_attributes,
                &mut send_entry,
            ),
            other => {
                let projection = DirectoryAttributeProjection::new(requested_attributes);
                self.stream_search_entries_plan(other, |entry| {
                    send_entry(ProjectedDirectoryEntry::from_entry(&entry, &projection))
                })
            }
        }
    }

    fn stream_uncovered_entries<F>(
        &self,
        base_dn: &str,
        scope: SearchScope,
        send_entry: &mut F,
    ) -> Result<(), BackendError>
    where
        F: FnMut(DirectoryEntry) -> bool,
    {
        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| BackendError::Storage(format!("Failed to begin read txn: {}", e)))?;

        let mut cursor = txn
            .open_ro_cursor(self.entries_by_entry_id_db)
            .map_err(|e| BackendError::Storage(format!("Failed to open cursor: {}", e)))?;

        for (key, value) in cursor.iter() {
            let entry_id = Self::entry_id_from_bytes(key, ENTRIES_BY_ENTRY_ID_DB_NAME)?;
            let Some(dn) = Self::dn_for_entry_id(&txn, self.dn_by_entry_id_db, entry_id)? else {
                continue;
            };
            if !Self::entry_in_scope_with_prepared_base(&dn, base_dn, (), scope) {
                continue;
            }
            let entry = Self::deserialize_stored_entry_record(dn, value)?;
            if !send_entry(entry.to_directory_entry()) {
                break;
            }
        }

        Ok(())
    }

    fn stream_equality_index_entries<F>(
        &self,
        base_dn: &str,
        scope: SearchScope,
        attribute: &str,
        value: &str,
        send_entry: &mut F,
    ) -> Result<(), BackendError>
    where
        F: FnMut(DirectoryEntry) -> bool,
    {
        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| BackendError::Storage(format!("Failed to begin read txn: {}", e)))?;
        let attr_lower = ldap_attribute_key(attribute);
        let Some(plan) = self
            .index_plan
            .attribute_plan_normalized(attr_lower.as_ref())
        else {
            return self.stream_uncovered_entries(base_dn, scope, send_entry);
        };
        if !plan.index_types.contains(&IndexType::Equality) {
            return self.stream_uncovered_entries(base_dn, scope, send_entry);
        }
        let normalized_value = plan.normalize_equality_value(value)?;
        let Some(index_db) = self.index_db_for_attribute(attr_lower.as_ref())? else {
            return self.stream_uncovered_entries(base_dn, scope, send_entry);
        };
        let search_prefix = Self::equality_index_prefix(&normalized_value);
        self.stream_entries_by_index_prefix_in_txn(
            &txn,
            index_db,
            search_prefix.as_bytes(),
            base_dn,
            scope,
            false,
            Self::include_all_stored_entry,
            send_entry,
        )
    }

    fn stream_projected_equality_index_entries<F>(
        &self,
        base_dn: &str,
        scope: SearchScope,
        attribute: &str,
        value: &str,
        requested_attributes: &[String],
        send_entry: &mut F,
    ) -> Result<(), BackendError>
    where
        F: FnMut(ProjectedDirectoryEntry) -> bool,
    {
        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| BackendError::Storage(format!("Failed to begin read txn: {}", e)))?;
        let attr_lower = ldap_attribute_key(attribute);
        let Some(plan) = self
            .index_plan
            .attribute_plan_normalized(attr_lower.as_ref())
        else {
            return self.stream_projected_entries_via_directory_entries(
                SearchStreamPlan::Uncovered {
                    base_dn: base_dn.to_string(),
                    scope,
                    fallback_reason: SearchPlanFallbackReason::IndexUnavailable,
                },
                requested_attributes,
                send_entry,
            );
        };
        if !plan.index_types.contains(&IndexType::Equality) {
            return self.stream_projected_entries_via_directory_entries(
                SearchStreamPlan::Uncovered {
                    base_dn: base_dn.to_string(),
                    scope,
                    fallback_reason: SearchPlanFallbackReason::IndexUnavailable,
                },
                requested_attributes,
                send_entry,
            );
        }
        let normalized_value = plan.normalize_equality_value(value)?;
        let Some(index_db) = self.index_db_for_attribute(attr_lower.as_ref())? else {
            return self.stream_projected_entries_via_directory_entries(
                SearchStreamPlan::Uncovered {
                    base_dn: base_dn.to_string(),
                    scope,
                    fallback_reason: SearchPlanFallbackReason::IndexUnavailable,
                },
                requested_attributes,
                send_entry,
            );
        };

        let projection = DirectoryAttributeProjection::new(requested_attributes);
        let search_prefix = Self::equality_index_prefix(&normalized_value);
        self.stream_projected_entries_by_index_prefix_in_txn(
            &txn,
            index_db,
            search_prefix.as_bytes(),
            base_dn,
            scope,
            &projection,
            send_entry,
        )
    }

    fn stream_projected_entries_via_directory_entries<F>(
        &self,
        plan: SearchStreamPlan,
        requested_attributes: &[String],
        send_entry: &mut F,
    ) -> Result<(), BackendError>
    where
        F: FnMut(ProjectedDirectoryEntry) -> bool,
    {
        let projection = DirectoryAttributeProjection::new(requested_attributes);
        self.stream_search_entries_plan(plan, |entry| {
            send_entry(ProjectedDirectoryEntry::from_entry(&entry, &projection))
        })
    }

    fn stream_presence_index_entries<F>(
        &self,
        base_dn: &str,
        scope: SearchScope,
        attribute: &str,
        send_entry: &mut F,
    ) -> Result<(), BackendError>
    where
        F: FnMut(DirectoryEntry) -> bool,
    {
        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| BackendError::Storage(format!("Failed to begin read txn: {}", e)))?;
        let attr_lower = ldap_attribute_key(attribute);
        let Some(plan) = self
            .index_plan
            .attribute_plan_normalized(attr_lower.as_ref())
        else {
            return self.stream_uncovered_entries(base_dn, scope, send_entry);
        };
        if !plan.index_types.contains(&IndexType::Presence) {
            return self.stream_uncovered_entries(base_dn, scope, send_entry);
        }
        let Some(index_db) = self.index_db_for_attribute(attr_lower.as_ref())? else {
            return self.stream_uncovered_entries(base_dn, scope, send_entry);
        };
        let search_key = Self::presence_index_prefix();
        self.stream_entries_by_index_prefix_in_txn(
            &txn,
            index_db,
            search_key.as_bytes(),
            base_dn,
            scope,
            false,
            Self::include_all_stored_entry,
            send_entry,
        )
    }

    fn stream_substring_index_entries<F>(
        &self,
        base_dn: &str,
        scope: SearchScope,
        attribute: &str,
        parts: &[SearchSubstringPart],
        send_entry: &mut F,
    ) -> Result<(), BackendError>
    where
        F: FnMut(DirectoryEntry) -> bool,
    {
        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| BackendError::Storage(format!("Failed to begin read txn: {}", e)))?;
        let Some(candidates) = self.search_substring_by_index_in_txn(&txn, attribute, parts)?
        else {
            return self.stream_uncovered_entries(base_dn, scope, send_entry);
        };
        let Some(plan) = self
            .index_plan
            .attribute_plan_normalized(&candidates.attribute)
        else {
            return self.stream_uncovered_entries(base_dn, scope, send_entry);
        };

        self.stream_entries_by_dns_in_txn_filtering(
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
            send_entry,
        )
    }

    fn stream_ordering_index_entries<F>(
        &self,
        base_dn: &str,
        scope: SearchScope,
        attribute: &str,
        value: &str,
        greater_or_equal: bool,
        send_entry: &mut F,
    ) -> Result<(), BackendError>
    where
        F: FnMut(DirectoryEntry) -> bool,
    {
        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| BackendError::Storage(format!("Failed to begin read txn: {}", e)))?;
        let attr_lower = ldap_attribute_key(attribute);
        let Some(plan) = self
            .index_plan
            .attribute_plan_normalized(attr_lower.as_ref())
        else {
            return self.stream_uncovered_entries(base_dn, scope, send_entry);
        };
        if !plan.index_types.contains(&IndexType::Ordering) {
            return self.stream_uncovered_entries(base_dn, scope, send_entry);
        }
        let normalized_value = plan.normalize_ordering_value(value)?;
        let Some(index_db) = self.index_db_for_attribute(attr_lower.as_ref())? else {
            return self.stream_uncovered_entries(base_dn, scope, send_entry);
        };

        let mut cursor = txn
            .open_ro_cursor(index_db)
            .map_err(|e| BackendError::Storage(format!("Failed to open cursor: {}", e)))?;
        let seek_key = if greater_or_equal {
            Self::ordering_index_key(&normalized_value)
        } else {
            Self::ordering_index_prefix().to_string()
        };
        let (first_key, first_entry_id) =
            match cursor.get(Some(seek_key.as_bytes()), None, LMDB_SET_RANGE_OP) {
                Ok((Some(key), entry_id)) => (key, entry_id),
                Ok((None, entry_id)) => (seek_key.as_bytes(), entry_id),
                Err(lmdb::Error::NotFound) => return Ok(()),
                Err(e) => {
                    return Err(BackendError::Storage(format!(
                        "Failed to seek ordering index cursor: {}",
                        e
                    )));
                }
            };
        if !first_key.starts_with(Self::ordering_index_prefix().as_bytes()) {
            return Ok(());
        }

        let mut seen_dns = HashSet::new();
        let mut keep_streaming = self.stream_ordering_index_key(
            &txn,
            first_key,
            first_entry_id,
            &normalized_value,
            greater_or_equal,
            base_dn,
            (),
            scope,
            &mut seen_dns,
            send_entry,
        )?;

        if keep_streaming {
            for (key, entry_id) in cursor.iter() {
                if !key.starts_with(Self::ordering_index_prefix().as_bytes()) {
                    break;
                }
                keep_streaming = self.stream_ordering_index_key(
                    &txn,
                    key,
                    entry_id,
                    &normalized_value,
                    greater_or_equal,
                    base_dn,
                    (),
                    scope,
                    &mut seen_dns,
                    send_entry,
                )?;
                if !keep_streaming {
                    break;
                }
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn stream_ordering_index_key<F>(
        &self,
        txn: &lmdb::RoTransaction<'_>,
        key: &[u8],
        entry_id_bytes: &[u8],
        target_value: &str,
        greater_or_equal: bool,
        base_dn: &str,
        _base_components: (),
        scope: SearchScope,
        seen_dns: &mut HashSet<String>,
        send_entry: &mut F,
    ) -> Result<bool, BackendError>
    where
        F: FnMut(DirectoryEntry) -> bool,
    {
        let Some(value) = Self::ordering_index_key_value(key)? else {
            return Ok(false);
        };

        let in_range = if greater_or_equal {
            value >= target_value
        } else {
            value <= target_value
        };
        if !in_range {
            return Ok(greater_or_equal);
        }
        let Some(dn) = Self::dn_for_entry_id_bytes(txn, self.dn_by_entry_id_db, entry_id_bytes)?
        else {
            return Ok(true);
        };
        if !seen_dns.insert(dn.to_string()) {
            return Ok(true);
        }

        let mut include_all = Self::include_all_stored_entry;
        self.stream_entry_by_dn_in_txn(txn, &dn, base_dn, (), scope, &mut include_all, send_entry)
    }

    fn index_db_for_attribute(&self, attribute: &str) -> Result<Option<Database>, BackendError> {
        let indexes = self
            .attr_indexes
            .try_read()
            .map_err(|e| BackendError::Storage(format!("Failed to acquire index lock: {}", e)))?;
        Ok(indexes.get(attribute).copied())
    }

    fn include_all_stored_entry(_: &StoredEntry) -> Result<bool, BackendError> {
        Ok(true)
    }

    #[allow(clippy::too_many_arguments)]
    fn stream_projected_entries_by_index_prefix_in_txn<F>(
        &self,
        txn: &lmdb::RoTransaction<'_>,
        index_db: Database,
        key: &[u8],
        base_dn: &str,
        scope: SearchScope,
        projection: &DirectoryAttributeProjection,
        send_entry: &mut F,
    ) -> Result<(), BackendError>
    where
        F: FnMut(ProjectedDirectoryEntry) -> bool,
    {
        let mut cursor = txn
            .open_ro_cursor(index_db)
            .map_err(|e| BackendError::Storage(format!("Failed to open cursor: {}", e)))?;
        let duplicates = match cursor.iter_dup_of(&key) {
            Ok(duplicates) => duplicates,
            Err(lmdb::Error::NotFound) => return Ok(()),
            Err(e) => {
                return Err(BackendError::Storage(format!(
                    "Failed to seek attribute index duplicates: {}",
                    e
                )));
            }
        };

        for (_, entry_id_bytes) in duplicates {
            let Some(dn) =
                Self::dn_for_entry_id_bytes(txn, self.dn_by_entry_id_db, entry_id_bytes)?
            else {
                continue;
            };
            if !self.stream_projected_entry_by_dn_in_txn(
                txn,
                &dn,
                base_dn,
                (),
                scope,
                projection,
                send_entry,
            )? {
                break;
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn stream_projected_entry_by_dn_in_txn<F>(
        &self,
        txn: &lmdb::RoTransaction<'_>,
        dn: &str,
        base_dn: &str,
        _base_components: (),
        scope: SearchScope,
        projection: &DirectoryAttributeProjection,
        send_entry: &mut F,
    ) -> Result<bool, BackendError>
    where
        F: FnMut(ProjectedDirectoryEntry) -> bool,
    {
        if !Self::entry_in_scope_with_prepared_base(dn, base_dn, (), scope) {
            return Ok(true);
        }
        let normalized_dn = Self::normalize_dn(dn)?;
        let Some((_, entry)) = Self::get_entry_by_normalized_dn(
            txn,
            self.entries_by_entry_id_db,
            self.entry_id_by_normalized_dn_db,
            self.dn_by_entry_id_db,
            &normalized_dn,
        )?
        else {
            return Ok(true);
        };
        let virtual_operational_attributes = HashMap::new();
        let projected = ProjectedDirectoryEntry {
            dn: entry.dn.clone(),
            attributes: projection.project_attributes(
                &entry.dn,
                &entry.attributes,
                &entry.operational_attributes,
                &virtual_operational_attributes,
            ),
            referral_urls: referral_urls_from_attributes(&entry.attributes),
        };
        Ok(send_entry(projected))
    }

    #[allow(clippy::too_many_arguments)]
    fn stream_entries_by_index_prefix_in_txn<I, F>(
        &self,
        txn: &lmdb::RoTransaction<'_>,
        index_db: Database,
        key: &[u8],
        base_dn: &str,
        scope: SearchScope,
        dedupe_dns: bool,
        mut include_entry: I,
        send_entry: &mut F,
    ) -> Result<(), BackendError>
    where
        I: FnMut(&StoredEntry) -> Result<bool, BackendError>,
        F: FnMut(DirectoryEntry) -> bool,
    {
        let mut cursor = txn
            .open_ro_cursor(index_db)
            .map_err(|e| BackendError::Storage(format!("Failed to open cursor: {}", e)))?;
        let duplicates = match cursor.iter_dup_of(&key) {
            Ok(duplicates) => duplicates,
            Err(lmdb::Error::NotFound) => return Ok(()),
            Err(e) => {
                return Err(BackendError::Storage(format!(
                    "Failed to seek attribute index duplicates: {}",
                    e
                )));
            }
        };

        let mut seen_dns = dedupe_dns.then(HashSet::new);
        for (_, entry_id_bytes) in duplicates {
            let Some(dn) =
                Self::dn_for_entry_id_bytes(txn, self.dn_by_entry_id_db, entry_id_bytes)?
            else {
                continue;
            };
            if seen_dns
                .as_mut()
                .is_some_and(|seen_dns| !seen_dns.insert(dn.clone()))
            {
                continue;
            }
            if !self.stream_entry_by_dn_in_txn(
                txn,
                &dn,
                base_dn,
                (),
                scope,
                &mut include_entry,
                send_entry,
            )? {
                break;
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn stream_entries_by_dns_in_txn_filtering<I, F>(
        &self,
        txn: &lmdb::RoTransaction<'_>,
        dns: &[String],
        base_dn: &str,
        scope: SearchScope,
        dedupe_dns: bool,
        mut include_entry: I,
        send_entry: &mut F,
    ) -> Result<(), BackendError>
    where
        I: FnMut(&StoredEntry) -> Result<bool, BackendError>,
        F: FnMut(DirectoryEntry) -> bool,
    {
        let mut seen_dns = dedupe_dns.then(|| HashSet::with_capacity(dns.len()));

        for dn in dns {
            if seen_dns
                .as_mut()
                .is_some_and(|seen_dns| !seen_dns.insert(dn.clone()))
            {
                continue;
            }
            if !self.stream_entry_by_dn_in_txn(
                txn,
                dn,
                base_dn,
                (),
                scope,
                &mut include_entry,
                send_entry,
            )? {
                break;
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn stream_entry_by_dn_in_txn<I, F>(
        &self,
        txn: &lmdb::RoTransaction<'_>,
        dn: &str,
        base_dn: &str,
        _base_components: (),
        scope: SearchScope,
        include_entry: &mut I,
        send_entry: &mut F,
    ) -> Result<bool, BackendError>
    where
        I: FnMut(&StoredEntry) -> Result<bool, BackendError>,
        F: FnMut(DirectoryEntry) -> bool,
    {
        if !Self::entry_in_scope_with_prepared_base(dn, base_dn, (), scope) {
            return Ok(true);
        }
        let normalized_dn = Self::normalize_dn(dn)?;
        let Some((_, entry)) = Self::get_entry_by_normalized_dn(
            txn,
            self.entries_by_entry_id_db,
            self.entry_id_by_normalized_dn_db,
            self.dn_by_entry_id_db,
            &normalized_dn,
        )?
        else {
            return Ok(true);
        };
        if !include_entry(&entry)? {
            return Ok(true);
        }
        Ok(send_entry(entry.to_directory_entry()))
    }

    fn entry_in_scope_with_prepared_base(
        dn: &str,
        base_dn: &str,
        _base_components: (),
        scope: SearchScope,
    ) -> bool {
        Self::entry_in_scope(dn, base_dn, scope)
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
        fallback_reason: SearchPlanFallbackReason,
    ) -> Result<SearchEntriesWithHintReport, BackendError> {
        self.record_search_plan(SearchPlanType::FullScan, Some(fallback_reason));
        Ok(SearchEntriesWithHintReport {
            entries: self
                .search_entries_internal(base_dn, scope)?
                .into_iter()
                .map(|entry| entry.to_directory_entry())
                .collect(),
            hint_covers_filter: false,
            plan_type: SearchPlanType::FullScan,
            fallback_reason: Some(fallback_reason),
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

    fn record_search_plan(
        &self,
        plan_type: SearchPlanType,
        fallback_reason: Option<SearchPlanFallbackReason>,
    ) {
        if let Some(metrics) = self.metrics.as_ref() {
            metrics.increment_counter(
                &format!("ldap_search_plan_{}_total", plan_type.metric_suffix()),
                1,
            );
            if let Some(reason) = fallback_reason {
                metrics.increment_counter(
                    &format!("ldap_search_full_scan_{}_total", reason.metric_suffix()),
                    1,
                );
            }
        }
    }
}

#[async_trait]
impl DirectoryBackend for LmdbBackend {
    async fn authenticate(&self, dn: &str, password: &[u8]) -> Result<bool, BackendError> {
        let _profile_total = PerfPhase::start("lmdb_authenticate", "total", None);
        let normalized_dn = Self::normalize_dn(dn)?;

        if let Some(record) = self.auth_cache.get(&normalized_dn) {
            let result = {
                let _profile_phase = PerfPhase::start("lmdb_authenticate", "verify_hash", None);
                Self::verify_ssha512_record(password, &record)
            };
            self.record_auth_cache_metrics();
            return Ok(result);
        }

        let txn = {
            let _profile_phase = PerfPhase::start("lmdb_authenticate", "read_txn", None);
            self.env
                .begin_ro_txn()
                .map_err(|e| BackendError::Storage(format!("Failed to begin read txn: {}", e)))?
        };

        log::debug!("Authentication cache miss - DN: {dn}, Normalized: {normalized_dn}");

        // Resolve the bind DN through the compact entry-id maps, then load the
        // ID-keyed credential record.
        let stored_credential_bytes = {
            let _profile_phase = PerfPhase::start("lmdb_authenticate", "password_lookup", None);
            let Some(entry_id) = Self::entry_id_for_normalized_dn(
                &txn,
                self.entry_id_by_normalized_dn_db,
                &normalized_dn,
            )?
            else {
                log::debug!("DN not found in entry id index: {}", normalized_dn);
                self.record_auth_cache_metrics();
                return Ok(false);
            };
            match txn.get(
                self.credentials_by_entry_id_db,
                &Self::entry_id_bytes(entry_id),
            ) {
                Ok(stored_credential_bytes) => stored_credential_bytes,
                Err(lmdb::Error::NotFound) => {
                    log::debug!("Credential not found for DN: {}", normalized_dn);
                    self.record_auth_cache_metrics();
                    return Ok(false);
                }
                Err(e) => {
                    return Err(BackendError::Storage(format!(
                        "Credential index lookup failed: {}",
                        e
                    )));
                }
            }
        };
        {
            let _profile_phase = PerfPhase::start("lmdb_authenticate", "verify_hash", None);
            let Some(record) = Self::decode_credential_index_value(stored_credential_bytes) else {
                log::debug!("Unsupported password hash format for DN: {}", normalized_dn);
                self.record_auth_cache_metrics();
                return Ok(false);
            };
            let record = Arc::new(record);
            self.auth_cache.insert(&normalized_dn, Arc::clone(&record));
            let result = Self::verify_ssha512_record(password, &record);
            self.record_auth_cache_metrics();
            Ok(result)
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

    async fn record_authentication_updates(
        &self,
        updates: &[AuthenticationMetadataUpdate],
    ) -> Result<usize, BackendError> {
        if updates.is_empty() {
            return Ok(0);
        }

        let _lock = self.write_lock.write().await;
        let mut txn = self
            .env
            .begin_rw_txn()
            .map_err(|e| BackendError::Storage(format!("Failed to begin write txn: {}", e)))?;

        let mut changed_dns = Vec::new();
        let mut last_csn = None;
        let mut written = 0usize;

        for update in updates {
            let normalized_dn = Self::normalize_dn(&update.dn)?;
            let Some((entry_id, mut entry)) = Self::get_entry_by_normalized_dn(
                &txn,
                self.entries_by_entry_id_db,
                self.entry_id_by_normalized_dn_db,
                self.dn_by_entry_id_db,
                &normalized_dn,
            )?
            else {
                continue;
            };

            let csn = self.csn_generator.generate();
            let changed = match update.outcome {
                AuthenticationOutcome::Success => entry
                    .operational_attributes
                    .record_successful_login(csn.clone()),
                AuthenticationOutcome::Failure => entry
                    .operational_attributes
                    .record_failed_login(csn.clone()),
            };
            if !changed {
                continue;
            }

            entry.modified_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            Self::put_entry_by_id(&mut txn, self.entries_by_entry_id_db, entry_id, &entry)?;

            changed_dns.push(normalized_dn);
            last_csn = Some(csn);
            written += 1;
        }

        let Some(csn) = last_csn else {
            return Ok(0);
        };

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

        for normalized_dn in changed_dns {
            self.entry_cache.invalidate(&normalized_dn);
        }

        Ok(written)
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
        let normalized_dn = Self::normalize_dn(dn)?;
        let Some((entry_id, mut entry)) = Self::get_entry_by_normalized_dn(
            &txn,
            self.entries_by_entry_id_db,
            self.entry_id_by_normalized_dn_db,
            self.dn_by_entry_id_db,
            &normalized_dn,
        )?
        else {
            return Err(BackendError::NotFound);
        };
        entry.operational_attributes = operational_attributes;
        entry.modified_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self::put_entry_by_id(&mut txn, self.entries_by_entry_id_db, entry_id, &entry)?;

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

        let normalized_dn = Self::normalize_dn(dn)?;

        let entry_id = match Self::entry_id_for_normalized_dn(
            &txn,
            self.entry_id_by_normalized_dn_db,
            &normalized_dn,
        )? {
            Some(entry_id) => entry_id,
            None => return Err(BackendError::NotFound),
        };
        let entry_id_bytes = Self::entry_id_bytes(entry_id);

        // Get entry to remove from attribute indexes
        let stored_entry = Self::required_entry_by_id(
            &txn,
            self.entries_by_entry_id_db,
            self.dn_by_entry_id_db,
            entry_id,
        )?;

        // Remove from attribute indexes
        self.remove_attribute_indexes(&mut txn, entry_id, &stored_entry.attributes)?;

        // Delete entry
        txn.del(self.entries_by_entry_id_db, &entry_id_bytes, None)
            .map_err(|e| BackendError::Storage(format!("Failed to delete entry: {}", e)))?;

        txn.del(self.credentials_by_entry_id_db, &entry_id_bytes, None)
            .or_else(|e| match e {
                lmdb::Error::NotFound => Ok(()),
                _ => Err(BackendError::Storage(
                    "Failed to delete credential index".to_string(),
                )),
            })?;

        txn.del(
            self.entry_id_by_normalized_dn_db,
            &normalized_dn.as_bytes(),
            None,
        )
        .map_err(|e| BackendError::Storage(format!("Failed to delete entry id index: {}", e)))?;
        txn.del(self.dn_by_entry_id_db, &entry_id_bytes, None)
            .map_err(|e| BackendError::Storage(format!("Failed to delete entry id DN: {}", e)))?;

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

    async fn modify_entry_validated_with_actor(
        &self,
        dn: &str,
        modifications: Vec<Modification>,
        actor_dn: Option<String>,
        schema: &LdapSchema,
    ) -> Result<(), NativeModifyError> {
        self.modify_entry_internal_validated(dn, modifications, actor_dn.as_deref(), Some(schema))
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
            return self.search_entries_uncovered_report(
                base_dn,
                scope,
                SearchPlanFallbackReason::MissingHint,
            );
        };

        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| BackendError::Storage(format!("Failed to begin read txn: {}", e)))?;

        let (candidates, hint_covers_filter, dedupe_dns, plan_type) = match hint {
            SearchCandidateHint::Equality { attribute, value } => {
                let Some(candidates) = self.search_by_index_in_txn(&txn, &attribute, &value)?
                else {
                    drop(txn);
                    return self.search_entries_uncovered_report(
                        base_dn,
                        scope,
                        SearchPlanFallbackReason::IndexUnavailable,
                    );
                };
                (candidates, true, false, SearchPlanType::EqualityIndex)
            }
            SearchCandidateHint::Present { attribute } => {
                let Some(candidates) = self.search_present_by_index_in_txn(&txn, &attribute)?
                else {
                    drop(txn);
                    return self.search_entries_uncovered_report(
                        base_dn,
                        scope,
                        SearchPlanFallbackReason::IndexUnavailable,
                    );
                };
                (candidates, true, false, SearchPlanType::PresenceIndex)
            }
            SearchCandidateHint::Substring { attribute, parts } => {
                let Some(candidates) =
                    self.search_substring_by_index_in_txn(&txn, &attribute, &parts)?
                else {
                    drop(txn);
                    return self.search_entries_uncovered_report(
                        base_dn,
                        scope,
                        SearchPlanFallbackReason::IndexUnavailable,
                    );
                };
                let Some(plan) = self
                    .index_plan
                    .attribute_plan_normalized(&candidates.attribute)
                else {
                    drop(txn);
                    return self.search_entries_uncovered_report(
                        base_dn,
                        scope,
                        SearchPlanFallbackReason::IndexUnavailable,
                    );
                };
                self.record_search_plan(SearchPlanType::SubstringIndex, None);
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
                    plan_type: SearchPlanType::SubstringIndex,
                    fallback_reason: None,
                });
            }
            SearchCandidateHint::GreaterOrEqual { attribute, value } => {
                let Some(candidates) =
                    self.search_ordering_by_index_in_txn(&txn, &attribute, &value, true)?
                else {
                    drop(txn);
                    return self.search_entries_uncovered_report(
                        base_dn,
                        scope,
                        SearchPlanFallbackReason::IndexUnavailable,
                    );
                };
                (candidates, true, true, SearchPlanType::OrderingIndex)
            }
            SearchCandidateHint::LessOrEqual { attribute, value } => {
                let Some(candidates) =
                    self.search_ordering_by_index_in_txn(&txn, &attribute, &value, false)?
                else {
                    drop(txn);
                    return self.search_entries_uncovered_report(
                        base_dn,
                        scope,
                        SearchPlanFallbackReason::IndexUnavailable,
                    );
                };
                (candidates, true, true, SearchPlanType::OrderingIndex)
            }
        };

        self.record_search_plan(plan_type, None);
        Ok(SearchEntriesWithHintReport {
            entries: self.load_entries_by_dns_in_txn(
                &txn,
                &candidates,
                base_dn,
                scope,
                dedupe_dns,
            )?,
            hint_covers_filter,
            plan_type,
            fallback_reason: None,
        })
    }

    fn supports_search_entry_streaming(&self) -> bool {
        true
    }

    async fn stream_search_entries_with_hint_report(
        &self,
        base_dn: &str,
        scope: SearchScope,
        hint: Option<SearchCandidateHint>,
    ) -> Result<SearchEntriesStreamReport, BackendError> {
        let plan = self.search_stream_plan(base_dn, scope, hint)?;
        let hint_covers_filter = plan.hint_covers_filter();
        let plan_type = plan.plan_type();
        let fallback_reason = plan.fallback_reason();
        self.record_search_plan(plan_type, fallback_reason);
        let backend = self.clone();
        let (sender, entries) = tokio::sync::mpsc::channel(128);

        tokio::task::spawn_blocking(move || {
            let result = backend
                .stream_search_entries_plan(plan, |entry| sender.blocking_send(Ok(entry)).is_ok());
            if let Err(err) = result {
                let _ = sender.blocking_send(Err(err));
            }
        });

        Ok(SearchEntriesStreamReport {
            entries,
            hint_covers_filter,
            plan_type,
            fallback_reason,
        })
    }

    async fn stream_projected_search_entries_with_hint_report(
        &self,
        base_dn: &str,
        scope: SearchScope,
        hint: Option<SearchCandidateHint>,
        requested_attributes: Vec<String>,
    ) -> Result<ProjectedSearchEntriesStreamReport, BackendError> {
        let plan = self.search_stream_plan(base_dn, scope, hint)?;
        let hint_covers_filter = plan.hint_covers_filter();
        let plan_type = plan.plan_type();
        let fallback_reason = plan.fallback_reason();
        self.record_search_plan(plan_type, fallback_reason);
        let backend = self.clone();
        let (sender, entries) = tokio::sync::mpsc::channel(128);

        tokio::task::spawn_blocking(move || {
            let result = backend.stream_projected_search_entries_plan(
                plan,
                &requested_attributes,
                |entry| sender.blocking_send(Ok(entry)).is_ok(),
            );
            if let Err(err) = result {
                let _ = sender.blocking_send(Err(err));
            }
        });

        Ok(ProjectedSearchEntriesStreamReport {
            entries,
            hint_covers_filter,
            plan_type,
            fallback_reason,
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
    use crate::backend::ModifyOperation;
    use tempfile::tempdir;

    async fn collect_stream_dns(
        mut report: SearchEntriesStreamReport,
    ) -> Result<Vec<String>, BackendError> {
        let mut dns = Vec::new();
        while let Some(entry) = report.entries.recv().await {
            dns.push(entry?.dn);
        }
        Ok(dns)
    }

    async fn collect_projected_stream(
        mut report: ProjectedSearchEntriesStreamReport,
    ) -> Result<Vec<ProjectedDirectoryEntry>, BackendError> {
        let mut entries = Vec::new();
        while let Some(entry) = report.entries.recv().await {
            entries.push(entry?);
        }
        Ok(entries)
    }

    fn credential_index_value(backend: &LmdbBackend, dn: &str) -> Option<Vec<u8>> {
        let txn = backend.env.begin_ro_txn().unwrap();
        let normalized_dn = LmdbBackend::normalize_dn(dn).ok()?;
        let entry_id = LmdbBackend::entry_id_for_normalized_dn(
            &txn,
            backend.entry_id_by_normalized_dn_db,
            &normalized_dn,
        )
        .unwrap()?;
        txn.get(
            backend.credentials_by_entry_id_db,
            &LmdbBackend::entry_id_bytes(entry_id),
        )
        .ok()
        .map(|bytes| bytes.to_vec())
    }

    fn credential_index_record(backend: &LmdbBackend, dn: &str) -> Option<AuthCredentialRecord> {
        credential_index_value(backend, dn)
            .and_then(|bytes| LmdbBackend::decode_credential_index_value(&bytes))
    }

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
    fn bounded_lru_cache_moves_hits_to_newest_and_evicts_oldest() {
        let mut cache = BoundedLruCache::with_capacity(2);
        assert!(cache.insert("one".to_string(), 1).is_none());
        assert!(cache.insert("two".to_string(), 2).is_none());
        assert_eq!(cache.get_cloned("one"), Some(1));

        let evicted = cache.insert("three".to_string(), 3);
        assert_eq!(evicted, Some(2));
        assert_eq!(cache.get_cloned("one"), Some(1));
        assert_eq!(cache.get_cloned("two"), None);
        assert_eq!(cache.get_cloned("three"), Some(3));
    }

    #[test]
    fn bounded_lru_cache_moves_replaced_key_to_newest_without_growing() {
        let mut cache = BoundedLruCache::with_capacity(2);
        assert!(cache.insert("one".to_string(), 1).is_none());
        assert!(cache.insert("two".to_string(), 2).is_none());
        assert!(cache.insert("one".to_string(), 10).is_none());

        let evicted = cache.insert("three".to_string(), 3);
        assert_eq!(evicted, Some(2));
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get_cloned("one"), Some(10));
        assert_eq!(cache.get_cloned("two"), None);
        assert_eq!(cache.get_cloned("three"), Some(3));
    }

    #[test]
    fn entry_cache_hit_returns_shared_stored_entry() {
        let cache = EntryCache::new(8);
        let key = "uid=shared,dc=example,dc=org";
        let entry = Arc::new(benchmark_stored_entry(key.to_string()));

        cache.insert(key, Arc::clone(&entry));
        let cached = cache.get(key).unwrap();

        assert!(Arc::ptr_eq(&entry, &cached));
        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 0);
    }

    #[test]
    fn caches_keep_capacity_zero_behavior() {
        let entry_cache = EntryCache::new(0);
        let key = "uid=zero,dc=example,dc=org";
        entry_cache.insert(key, Arc::new(benchmark_stored_entry(key.to_string())));
        assert!(entry_cache.get(key).is_none());
        assert_eq!(
            entry_cache.stats(),
            EntryCacheStats {
                capacity: 0,
                len: 0,
                hits: 0,
                misses: 1,
                evictions: 0,
            }
        );

        let auth_cache = AuthCredentialCache::new(0);
        auth_cache.insert(key, benchmark_auth_record(1));
        assert!(auth_cache.get(key).is_none());
        assert_eq!(
            auth_cache.stats(),
            AuthCredentialCacheStats {
                capacity: 0,
                len: 0,
                hits: 0,
                misses: 1,
                evictions: 0,
            }
        );
    }

    #[test]
    fn entry_cache_concurrent_access_remains_bounded_and_correct() {
        let cache = Arc::new(EntryCache::new(16_384));
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let mut workers = Vec::new();

        for worker_id in 0..8 {
            let cache = Arc::clone(&cache);
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                for iteration in 0..1_000 {
                    let key = format!(
                        "uid=entry-worker-{worker_id}-{iteration},ou=people,dc=example,dc=org"
                    );
                    cache.insert(&key, Arc::new(benchmark_stored_entry(key.clone())));
                    assert!(cache.get(&key).is_some());
                    if iteration % 3 == 0 {
                        cache.invalidate(&key);
                        assert!(cache.get(&key).is_none());
                    }
                }
            }));
        }

        for worker in workers {
            worker.join().unwrap();
        }

        let stats = cache.stats();
        assert!(stats.len <= stats.capacity);
        assert!(stats.hits > 0);
        assert!(stats.misses > 0);
    }

    #[test]
    fn auth_cache_concurrent_access_remains_bounded_and_correct() {
        let cache = Arc::new(AuthCredentialCache::new(16_384));
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let mut workers = Vec::new();

        for worker_id in 0..8 {
            let cache = Arc::clone(&cache);
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                for iteration in 0..1_000 {
                    let key = format!(
                        "uid=auth-worker-{worker_id}-{iteration},ou=people,dc=example,dc=org"
                    );
                    cache.insert(&key, benchmark_auth_record(iteration));
                    assert!(cache.get(&key).is_some());
                    if iteration % 3 == 0 {
                        cache.invalidate(&key);
                        assert!(cache.get(&key).is_none());
                    }
                }
            }));
        }

        for worker in workers {
            worker.join().unwrap();
        }

        let stats = cache.stats();
        assert!(stats.len <= stats.capacity);
        assert!(stats.hits > 0);
        assert!(stats.misses > 0);
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
    async fn test_fresh_store_uses_compact_current_lmdb_tables() {
        let dir = tempdir().unwrap();
        let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

        assert!(
            backend
                .env
                .open_db(Some(ENTRIES_BY_ENTRY_ID_DB_NAME))
                .is_ok()
        );
        assert!(
            backend
                .env
                .open_db(Some(CREDENTIALS_BY_ENTRY_ID_DB_NAME))
                .is_ok()
        );
        assert!(backend.env.open_db(Some("idx3_cn")).is_ok());

        assert!(matches!(
            backend.env.open_db(Some(LEGACY_ENTRIES_DB_NAME)),
            Err(lmdb::Error::NotFound)
        ));
        assert!(matches!(
            backend.env.open_db(Some(LEGACY_PASSWORDS_DB_NAME)),
            Err(lmdb::Error::NotFound)
        ));
        assert!(matches!(
            backend
                .env
                .open_db(Some(LEGACY_CREDENTIALS_BY_NORMALIZED_DN_DB_NAME)),
            Err(lmdb::Error::NotFound)
        ));
        assert!(matches!(
            backend.env.open_db(Some(LEGACY_DN_INDEX_DB_NAME)),
            Err(lmdb::Error::NotFound)
        ));
        assert!(matches!(
            backend.env.open_db(Some("idx2_cn")),
            Err(lmdb::Error::NotFound)
        ));
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
    async fn test_lmdb_record_authentication_updates_batches_events() {
        let dir = tempdir().unwrap();
        let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();
        let dn = "cn=batch-auth,dc=example,dc=org";

        let mut attributes = HashMap::new();
        attributes.insert("objectClass".to_string(), vec!["person".to_string()]);
        attributes.insert("cn".to_string(), vec!["batch-auth".to_string()]);
        let entry = DirectoryEntry::new(dn, attributes);

        backend
            .add_entry(entry, b"password".to_vec())
            .await
            .unwrap();

        let written = backend
            .record_authentication_updates(&[
                AuthenticationMetadataUpdate::new(dn, AuthenticationOutcome::Failure),
                AuthenticationMetadataUpdate::new(dn, AuthenticationOutcome::Success),
            ])
            .await
            .unwrap();

        assert_eq!(written, 2);
        let entry = backend.get_entry(dn).await.unwrap().unwrap();
        assert!(entry.operational_attributes.last_failed_login.is_some());
        assert!(entry.operational_attributes.last_successful_login.is_some());
        assert_eq!(entry.operational_attributes.failed_login_count, Some(0));
        assert!(backend.get_context_csn().await.unwrap().is_some());
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
    async fn test_credential_index_tracks_add_modify_rename_and_delete() {
        let dir = tempdir().unwrap();
        let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

        let mut attributes = HashMap::new();
        attributes.insert("cn".to_string(), vec!["Credential User".to_string()]);
        let entry = DirectoryEntry::new("cn=credential,dc=example,dc=org", attributes);
        backend.add_entry(entry, b"secret".to_vec()).await.unwrap();

        let credential_value =
            credential_index_value(&backend, "CN=CREDENTIAL,dc=example,dc=org").unwrap();
        assert_eq!(
            credential_value.first().copied(),
            Some(CREDENTIAL_RECORD_FORMAT_VERSION)
        );
        assert!(credential_index_record(&backend, "CN=CREDENTIAL,dc=example,dc=org").is_some());
        assert!(
            backend
                .authenticate("CN=CREDENTIAL,dc=example,dc=org", b"secret")
                .await
                .unwrap()
        );

        backend
            .modify_entry(
                "cn=credential,dc=example,dc=org",
                vec![Modification {
                    operation: ModifyOperation::Replace,
                    attribute: "userPassword".to_string(),
                    values: vec!["new-secret".to_string()],
                }],
            )
            .await
            .unwrap();
        assert!(
            backend
                .authenticate("cn=credential,dc=example,dc=org", b"new-secret")
                .await
                .unwrap()
        );
        assert!(
            !backend
                .authenticate("cn=credential,dc=example,dc=org", b"secret")
                .await
                .unwrap()
        );

        backend
            .rename_entry("cn=credential,dc=example,dc=org", "cn=renamed", true, None)
            .await
            .unwrap();
        assert!(credential_index_record(&backend, "cn=credential,dc=example,dc=org").is_none());
        assert!(credential_index_record(&backend, "cn=renamed,dc=example,dc=org").is_some());
        assert!(
            backend
                .authenticate("CN=RENAMED,dc=example,dc=org", b"new-secret")
                .await
                .unwrap()
        );

        backend
            .delete_entry("cn=renamed,dc=example,dc=org")
            .await
            .unwrap();
        assert!(credential_index_record(&backend, "cn=renamed,dc=example,dc=org").is_none());
        assert!(
            !backend
                .authenticate("cn=renamed,dc=example,dc=org", b"new-secret")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_credentials_are_keyed_by_entry_id_on_reopen() {
        let dir = tempdir().unwrap();
        {
            let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();
            let mut attributes = HashMap::new();
            attributes.insert("cn".to_string(), vec!["Credential User".to_string()]);
            let entry = DirectoryEntry::new("cn=credential,dc=example,dc=org", attributes);
            backend.add_entry(entry, b"secret".to_vec()).await.unwrap();
            assert!(credential_index_record(&backend, "cn=credential,dc=example,dc=org").is_some());
        }

        let reopened = LmdbBackend::new(dir.path(), 100, 1).unwrap();
        let credential_value =
            credential_index_value(&reopened, "cn=credential,dc=example,dc=org").unwrap();
        assert_eq!(
            credential_value.first().copied(),
            Some(CREDENTIAL_RECORD_FORMAT_VERSION)
        );
        assert!(credential_index_record(&reopened, "cn=credential,dc=example,dc=org").is_some());
        assert!(
            reopened
                .authenticate("cn=credential,dc=example,dc=org", b"secret")
                .await
                .unwrap()
        );
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
    async fn test_native_modify_preserves_auth_cache_for_non_password_modify() {
        let dir = tempdir().unwrap();
        let schema = LdapSchema::with_core_schema();
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
        attributes.insert(
            "objectClass".to_string(),
            vec!["top".to_string(), "person".to_string()],
        );
        attributes.insert("cn".to_string(), vec!["cached".to_string()]);
        attributes.insert("sn".to_string(), vec!["cached".to_string()]);
        let entry = DirectoryEntry::new("cn=cached,dc=example,dc=org", attributes);
        backend.add_entry(entry, b"secret".to_vec()).await.unwrap();

        assert!(
            backend
                .authenticate("cn=cached,dc=example,dc=org", b"secret")
                .await
                .unwrap()
        );
        backend
            .modify_entry_validated_with_actor(
                "cn=cached,dc=example,dc=org",
                vec![Modification {
                    operation: ModifyOperation::Replace,
                    attribute: "telephoneNumber".to_string(),
                    values: vec!["555-0100".to_string()],
                }],
                None,
                &schema,
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
    async fn test_native_modify_updates_auth_cache_after_password_modify() {
        let dir = tempdir().unwrap();
        let schema = LdapSchema::with_core_schema();
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
        attributes.insert(
            "objectClass".to_string(),
            vec!["top".to_string(), "person".to_string()],
        );
        attributes.insert("cn".to_string(), vec!["cached".to_string()]);
        attributes.insert("sn".to_string(), vec!["cached".to_string()]);
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
            .modify_entry_validated_with_actor(
                "cn=cached,dc=example,dc=org",
                vec![Modification {
                    operation: ModifyOperation::Replace,
                    attribute: "userPassword".to_string(),
                    values: vec!["new-secret".to_string()],
                }],
                None,
                &schema,
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
    async fn test_attribute_index_stores_compact_entry_ids() {
        let dir = tempdir().unwrap();
        let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

        let dn = "uid=compact,dc=example,dc=org";
        let mut attributes = HashMap::new();
        attributes.insert("cn".to_string(), vec!["Compact User".to_string()]);
        backend
            .add_entry(DirectoryEntry::new(dn, attributes), vec![])
            .await
            .unwrap();

        let indexes = backend.attr_indexes.try_read().unwrap();
        let index_db = *indexes.get("cn").unwrap();
        drop(indexes);

        let txn = backend.env.begin_ro_txn().unwrap();
        let mut cursor = txn.open_ro_cursor(index_db).unwrap();
        let index_key = LmdbBackend::equality_index_prefix("compact user");
        let rows = cursor
            .iter_dup_of(&index_key.as_bytes())
            .unwrap()
            .collect::<Vec<_>>();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, index_key.as_bytes());
        assert_eq!(rows[0].1.len(), 8);
        assert_ne!(rows[0].1, dn.as_bytes());
        assert_eq!(
            LmdbBackend::dn_for_entry_id_bytes(&txn, backend.dn_by_entry_id_db, rows[0].1).unwrap(),
            Some(dn.to_string())
        );
    }

    #[tokio::test]
    async fn test_attribute_index_backfill_clears_legacy_dn_indexes() {
        let dir = tempdir().unwrap();
        let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

        let dn = "uid=legacy,dc=example,dc=org";
        let mut attributes = HashMap::new();
        attributes.insert("cn".to_string(), vec!["Legacy User".to_string()]);
        backend
            .add_entry(DirectoryEntry::new(dn, attributes), vec![])
            .await
            .unwrap();

        let legacy_db = backend
            .env
            .create_db(
                Some(&LmdbBackend::legacy_attribute_index_db_name("cn")),
                lmdb::DatabaseFlags::empty(),
            )
            .unwrap();
        let metadata_key = LmdbBackend::attribute_index_metadata_key("cn");
        let stale_version = b"1".to_vec();
        let legacy_key = format!("legacy user:{dn}");
        let mut txn = backend.env.begin_rw_txn().unwrap();
        txn.put(
            legacy_db,
            &legacy_key.as_bytes(),
            &dn.as_bytes(),
            WriteFlags::empty(),
        )
        .unwrap();
        txn.put(
            backend.metadata_db,
            &metadata_key.as_bytes(),
            &stale_version,
            WriteFlags::empty(),
        )
        .unwrap();
        txn.commit().unwrap();
        drop(backend);

        let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();
        assert_eq!(
            backend.search_by_index("cn", "Legacy User").unwrap(),
            vec![dn.to_string()]
        );

        let legacy_db = backend
            .env
            .open_db(Some(&LmdbBackend::legacy_attribute_index_db_name("cn")))
            .unwrap();
        let txn = backend.env.begin_ro_txn().unwrap();
        let mut cursor = txn.open_ro_cursor(legacy_db).unwrap();
        assert_eq!(cursor.iter().count(), 0);
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
        let mut marker_results = LmdbBackend::collect_index_dns_by_key(
            &txn,
            &mut cursor,
            backend.dn_by_entry_id_db,
            presence_prefix.as_bytes(),
        )
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

        for (uid, value) in [("negative", "-1"), ("two", "2"), ("ten", "10")] {
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
    async fn test_schema_index_plan_rejects_partial_certificate_pair_matching_rule() {
        let dir = tempdir().unwrap();
        let mut schema = LdapSchema::with_core_schema();
        schema.load_builtin_schema("x509").unwrap();

        let result = LmdbBackend::new_with_schema_config(
            dir.path(),
            100,
            1,
            IndexConfig {
                indexed_attributes: Vec::new(),
                attribute_indexes: vec![AttributeIndexConfig {
                    attribute: "crossCertificatePair".to_string(),
                    index_types: vec![IndexType::Equality],
                }],
            },
            &schema,
        );
        let err = match result {
            Ok(_) => panic!("crossCertificatePair equality index should be rejected"),
            Err(err) => err,
        };

        assert!(
            err.to_string()
                .contains("unsupported matching rule certificatePairExactMatch")
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
    async fn test_search_entry_stream_matches_vector_for_equality_hint() {
        let dir = tempdir().unwrap();
        let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

        for (dn, uid) in [
            ("uid=alice,dc=example,dc=org", "alice"),
            ("uid=bob,dc=example,dc=org", "bob"),
            ("uid=alice,dc=other,dc=org", "alice"),
        ] {
            let mut attributes = HashMap::new();
            attributes.insert("uid".to_string(), vec![uid.to_string()]);
            attributes.insert("cn".to_string(), vec![uid.to_string()]);
            backend
                .add_entry(DirectoryEntry::new(dn, attributes), vec![])
                .await
                .unwrap();
        }

        let hint = Some(SearchCandidateHint::Equality {
            attribute: "uid".to_string(),
            value: "alice".to_string(),
        });
        let vector_report = backend
            .search_entries_with_hint_report("dc=example,dc=org", SearchScope(2), hint.clone())
            .await
            .unwrap();
        let stream_report = backend
            .stream_search_entries_with_hint_report("dc=example,dc=org", SearchScope(2), hint)
            .await
            .unwrap();

        assert!(vector_report.hint_covers_filter);
        assert!(stream_report.hint_covers_filter);
        let vector_dns = vector_report
            .entries
            .into_iter()
            .map(|entry| entry.dn)
            .collect::<Vec<_>>();
        let stream_dns = collect_stream_dns(stream_report).await.unwrap();
        assert_eq!(stream_dns, vector_dns);
        assert_eq!(stream_dns, vec!["uid=alice,dc=example,dc=org".to_string()]);
    }

    #[tokio::test]
    async fn test_projected_search_entry_stream_matches_generic_projection_for_exact_equality() {
        let dir = tempdir().unwrap();
        let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();
        let requested_attributes = vec!["uid".to_string(), "mail".to_string()];

        for (dn, uid, mail, object_class) in [
            (
                "uid=alice,dc=example,dc=org",
                "alice",
                "alice@example.org",
                "inetOrgPerson",
            ),
            (
                "uid=bob,dc=example,dc=org",
                "bob",
                "bob@example.org",
                "inetOrgPerson",
            ),
            (
                "cn=ref,dc=example,dc=org",
                "ref",
                "ref@example.org",
                "referral",
            ),
        ] {
            let mut attributes = HashMap::new();
            attributes.insert("objectClass".to_string(), vec![object_class.to_string()]);
            attributes.insert("uid".to_string(), vec![uid.to_string()]);
            attributes.insert("cn".to_string(), vec![uid.to_string()]);
            attributes.insert("mail".to_string(), vec![mail.to_string()]);
            attributes.insert("description".to_string(), vec!["not requested".repeat(16)]);
            if object_class == "referral" {
                attributes.insert(
                    "ref".to_string(),
                    vec!["ldap://ldap.example.org/dc=example,dc=org".to_string()],
                );
            }
            backend
                .add_entry(DirectoryEntry::new(dn, attributes), vec![])
                .await
                .unwrap();
        }

        for hint in [
            SearchCandidateHint::Equality {
                attribute: "uid".to_string(),
                value: "alice".to_string(),
            },
            SearchCandidateHint::Equality {
                attribute: "mail".to_string(),
                value: "bob@example.org".to_string(),
            },
            SearchCandidateHint::Equality {
                attribute: "objectClass".to_string(),
                value: "inetOrgPerson".to_string(),
            },
        ] {
            let vector_report = backend
                .search_entries_with_hint_report(
                    "dc=example,dc=org",
                    SearchScope(2),
                    Some(hint.clone()),
                )
                .await
                .unwrap();
            let projection = DirectoryAttributeProjection::new(&requested_attributes);
            let expected = vector_report
                .entries
                .iter()
                .map(|entry| {
                    let projected = ProjectedDirectoryEntry::from_entry(entry, &projection);
                    (
                        projected.dn,
                        projected.attributes.into_iter().collect::<BTreeMap<_, _>>(),
                        projected.referral_urls,
                    )
                })
                .collect::<Vec<_>>();

            let projected_report = backend
                .stream_projected_search_entries_with_hint_report(
                    "dc=example,dc=org",
                    SearchScope(2),
                    Some(hint),
                    requested_attributes.clone(),
                )
                .await
                .unwrap();
            assert!(projected_report.hint_covers_filter);
            let actual = collect_projected_stream(projected_report)
                .await
                .unwrap()
                .into_iter()
                .map(|entry| {
                    (
                        entry.dn,
                        entry.attributes.into_iter().collect::<BTreeMap<_, _>>(),
                        entry.referral_urls,
                    )
                })
                .collect::<Vec<_>>();

            assert_eq!(actual, expected);
        }
    }

    #[tokio::test]
    async fn test_search_entry_stream_falls_back_for_unindexed_hint() {
        let dir = tempdir().unwrap();
        let backend =
            LmdbBackend::new_with_config(dir.path(), 100, 1, IndexConfig::disabled()).unwrap();

        for (uid, description) in [("alice", "alpha"), ("bob", "beta")] {
            let mut attributes = HashMap::new();
            attributes.insert("uid".to_string(), vec![uid.to_string()]);
            attributes.insert("description".to_string(), vec![description.to_string()]);
            backend
                .add_entry(
                    DirectoryEntry::new(format!("uid={uid},dc=example,dc=org"), attributes),
                    vec![],
                )
                .await
                .unwrap();
        }

        let hint = Some(SearchCandidateHint::Equality {
            attribute: "description".to_string(),
            value: "alpha".to_string(),
        });
        let vector_report = backend
            .search_entries_with_hint_report("dc=example,dc=org", SearchScope(2), hint.clone())
            .await
            .unwrap();
        let stream_report = backend
            .stream_search_entries_with_hint_report("dc=example,dc=org", SearchScope(2), hint)
            .await
            .unwrap();

        assert!(!vector_report.hint_covers_filter);
        assert!(!stream_report.hint_covers_filter);
        let vector_dns = vector_report
            .entries
            .into_iter()
            .map(|entry| entry.dn)
            .collect::<Vec<_>>();
        let stream_dns = collect_stream_dns(stream_report).await.unwrap();
        assert_eq!(stream_dns, vector_dns);
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
    async fn test_native_modify_invalidates_entry_cache_after_commit() {
        let dir = tempdir().unwrap();
        let schema = LdapSchema::with_core_schema();
        let db_path = dir.path().to_path_buf();

        {
            let backend = LmdbBackend::new(&db_path, 100, 1).unwrap();
            let mut attributes = HashMap::new();
            attributes.insert(
                "objectClass".to_string(),
                vec!["top".to_string(), "person".to_string()],
            );
            attributes.insert("cn".to_string(), vec!["before".to_string()]);
            attributes.insert("sn".to_string(), vec!["Person".to_string()]);
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
            .modify_entry_validated_with_actor(
                "uid=modify,dc=example,dc=org",
                vec![Modification {
                    operation: ModifyOperation::Replace,
                    attribute: "cn".to_string(),
                    values: vec!["after".to_string()],
                }],
                None,
                &schema,
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
    async fn test_native_modify_updates_attribute_indexes() {
        let dir = tempdir().unwrap();
        let schema = LdapSchema::with_core_schema();
        let backend = LmdbBackend::new_with_schema_config(
            dir.path(),
            100,
            1,
            IndexConfig {
                indexed_attributes: vec!["cn".to_string()],
                attribute_indexes: Vec::new(),
            },
            &schema,
        )
        .unwrap();

        let mut attributes = HashMap::new();
        attributes.insert(
            "objectClass".to_string(),
            vec!["top".to_string(), "person".to_string()],
        );
        attributes.insert("cn".to_string(), vec!["before".to_string()]);
        attributes.insert("sn".to_string(), vec!["Person".to_string()]);
        let dn = "uid=indexed,dc=example,dc=org";
        backend
            .add_entry(DirectoryEntry::new(dn, attributes), vec![])
            .await
            .unwrap();

        assert_eq!(
            backend.search_by_index("cn", "before").unwrap(),
            vec![dn.to_string()]
        );
        backend
            .modify_entry_validated_with_actor(
                dn,
                vec![Modification {
                    operation: ModifyOperation::Replace,
                    attribute: "cn".to_string(),
                    values: vec!["after".to_string()],
                }],
                None,
                &schema,
            )
            .await
            .unwrap();

        assert!(backend.search_by_index("cn", "before").unwrap().is_empty());
        assert_eq!(
            backend.search_by_index("cn", "after").unwrap(),
            vec![dn.to_string()]
        );
    }

    #[tokio::test]
    async fn test_native_modify_schema_violation_does_not_change_entry_or_cache() {
        let dir = tempdir().unwrap();
        let schema = LdapSchema::with_core_schema();
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
        attributes.insert(
            "objectClass".to_string(),
            vec!["top".to_string(), "person".to_string()],
        );
        attributes.insert("cn".to_string(), vec!["cached".to_string()]);
        attributes.insert("sn".to_string(), vec!["cached".to_string()]);
        let dn = "cn=cached,dc=example,dc=org";
        backend
            .add_entry(DirectoryEntry::new(dn, attributes), b"secret".to_vec())
            .await
            .unwrap();

        backend.get_entry(dn).await.unwrap().unwrap();
        let err = backend
            .modify_entry_validated_with_actor(
                dn,
                vec![Modification {
                    operation: ModifyOperation::Delete,
                    attribute: "sn".to_string(),
                    values: Vec::new(),
                }],
                None,
                &schema,
            )
            .await
            .unwrap_err();

        assert!(matches!(err, NativeModifyError::Schema(_)));
        let unchanged = backend.get_entry(dn).await.unwrap().unwrap();
        assert_eq!(unchanged.attributes["sn"], vec!["cached".to_string()]);
        let stats = backend.entry_cache_stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
    }

    #[tokio::test]
    async fn test_native_modify_matches_backend_modify_for_valid_add_delete_replace() {
        let legacy_dir = tempdir().unwrap();
        let native_dir = tempdir().unwrap();
        let schema = LdapSchema::with_core_schema();
        let legacy_backend = LmdbBackend::new(legacy_dir.path(), 100, 1).unwrap();
        let native_backend = LmdbBackend::new(native_dir.path(), 100, 1).unwrap();
        let dn = "cn=compare,dc=example,dc=org";

        for backend in [&legacy_backend, &native_backend] {
            let mut attributes = HashMap::new();
            attributes.insert(
                "objectClass".to_string(),
                vec!["top".to_string(), "person".to_string()],
            );
            attributes.insert("cn".to_string(), vec!["before".to_string()]);
            attributes.insert("sn".to_string(), vec!["Person".to_string()]);
            attributes.insert("telephoneNumber".to_string(), vec!["555-0100".to_string()]);
            backend
                .add_entry(DirectoryEntry::new(dn, attributes), b"secret".to_vec())
                .await
                .unwrap();
        }

        let modifications = vec![
            Modification {
                operation: ModifyOperation::Delete,
                attribute: "telephoneNumber".to_string(),
                values: vec!["555-0100".to_string()],
            },
            Modification {
                operation: ModifyOperation::Add,
                attribute: "telephoneNumber".to_string(),
                values: vec!["555-0101".to_string()],
            },
            Modification {
                operation: ModifyOperation::Replace,
                attribute: "cn".to_string(),
                values: vec!["after".to_string()],
            },
        ];

        legacy_backend
            .modify_entry(dn, modifications.clone())
            .await
            .unwrap();
        native_backend
            .modify_entry_validated_with_actor(dn, modifications, None, &schema)
            .await
            .unwrap();

        let legacy_entry = legacy_backend.get_entry(dn).await.unwrap().unwrap();
        let native_entry = native_backend.get_entry(dn).await.unwrap().unwrap();
        assert_eq!(legacy_entry.attributes, native_entry.attributes);
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
        assert_eq!(equality_report.plan_type, SearchPlanType::EqualityIndex);
        assert_eq!(equality_report.fallback_reason, None);
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
        assert_eq!(presence_report.plan_type, SearchPlanType::PresenceIndex);
        assert_eq!(presence_report.fallback_reason, None);
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
        assert_eq!(ordering_report.plan_type, SearchPlanType::OrderingIndex);
        assert_eq!(ordering_report.fallback_reason, None);
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
        assert_eq!(substring_report.plan_type, SearchPlanType::SubstringIndex);
        assert_eq!(substring_report.fallback_reason, None);
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
        assert_eq!(fallback_report.plan_type, SearchPlanType::FullScan);
        assert_eq!(
            fallback_report.fallback_reason,
            Some(SearchPlanFallbackReason::IndexUnavailable)
        );
        assert_eq!(fallback_report.entries.len(), 2);

        let missing_hint_report = backend
            .search_entries_with_hint_report("ou=people,dc=example,dc=org", SearchScope(2), None)
            .await
            .unwrap();
        assert_eq!(missing_hint_report.plan_type, SearchPlanType::FullScan);
        assert_eq!(
            missing_hint_report.fallback_reason,
            Some(SearchPlanFallbackReason::MissingHint)
        );
    }

    #[tokio::test]
    async fn test_search_plan_metrics_record_index_and_full_scan_paths() {
        let dir = tempdir().unwrap();
        let mut backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();
        let metrics = MetricsCollector::new();
        backend.set_metrics(Some(metrics.clone()));

        let mut attributes = HashMap::new();
        attributes.insert("cn".to_string(), vec!["Alice".to_string()]);
        attributes.insert("description".to_string(), vec!["fixture".to_string()]);
        backend
            .add_entry(
                DirectoryEntry::new("uid=alice,ou=people,dc=example,dc=org", attributes),
                vec![],
            )
            .await
            .unwrap();

        backend
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
        backend
            .search_entries_with_hint_report(
                "ou=people,dc=example,dc=org",
                SearchScope(2),
                Some(SearchCandidateHint::Present {
                    attribute: "description".to_string(),
                }),
            )
            .await
            .unwrap();
        backend
            .search_entries_with_hint_report("ou=people,dc=example,dc=org", SearchScope(2), None)
            .await
            .unwrap();

        assert_eq!(
            metrics.get_counter("ldap_search_plan_equality_index_total"),
            Some(1)
        );
        assert_eq!(
            metrics.get_counter("ldap_search_plan_full_scan_total"),
            Some(2)
        );
        assert_eq!(
            metrics.get_counter("ldap_search_full_scan_index_unavailable_total"),
            Some(1)
        );
        assert_eq!(
            metrics.get_counter("ldap_search_full_scan_missing_hint_total"),
            Some(1)
        );
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

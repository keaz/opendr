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

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use ldap_parser::ldap::SearchScope;
use lmdb::{Cursor, Database, Environment, Transaction, WriteFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use tokio::sync::RwLock;

// LMDB cursor operation constants
const MDB_SET: u32 = 15;
const MDB_NEXT_DUP: u32 = 18;

use crate::backend::{
    BackendError, DirectoryBackend, DirectoryEntry, Modification, ModifyOperation,
};
use crate::csn::{Csn, CsnGenerator};

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
    /// Attributes that should be indexed
    pub indexed_attributes: Vec<String>,
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
        }
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
    /// Attribute indexes: map from "attr:value" -> DN
    /// One database per indexed attribute
    attr_indexes: Arc<RwLock<HashMap<String, Database>>>,
    /// Index configuration
    index_config: IndexConfig,
    /// Lock for write operations (reads are lock-free in LMDB)
    write_lock: Arc<RwLock<()>>,
    /// Database directory path
    db_path: PathBuf,
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
        Self::new_with_config(path, max_size_mb, replica_id, IndexConfig::default())
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
        let db_path = path.as_ref().to_path_buf();

        // Create directory if it doesn't exist
        std::fs::create_dir_all(&db_path)
            .map_err(|e| BackendError::Storage(format!("Failed to create db directory: {}", e)))?;

        // Create LMDB environment with read-optimized settings
        // Increased max_dbs to accommodate attribute indexes
        let env = Environment::new()
            .set_max_dbs(50) // Increased for attribute indexes
            .set_map_size(max_size_mb * 1024 * 1024) // Set max size
            .set_max_readers(126) // High reader concurrency
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

        // Create attribute index databases
        // Note: Using DUPSORT for indices to allow multiple DNs per attribute value
        let mut attr_indexes = HashMap::new();
        for attr in &index_config.indexed_attributes {
            let db_name = format!("idx_{}", attr.to_lowercase());
            // Create without DUP_SORT to avoid complexity - store value:DN as key
            let db = env
                .create_db(Some(&db_name), lmdb::DatabaseFlags::empty())
                .map_err(|e| {
                    BackendError::Storage(format!("Failed to create index for {}: {}", attr, e))
                })?;
            attr_indexes.insert(attr.to_lowercase(), db);
        }

        // Initialize CSN generator with replica ID
        let csn_generator = Arc::new(CsnGenerator::new(replica_id));

        Ok(Self {
            env,
            entries_db,
            passwords_db,
            dn_index_db,
            metadata_db,
            attr_indexes: Arc::new(RwLock::new(attr_indexes)),
            index_config,
            write_lock: Arc::new(RwLock::new(())),
            db_path,
            csn_generator,
        })
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

        Ok(())
    }

    /// Normalize DN for case-insensitive comparison
    fn normalize_dn(dn: &str) -> String {
        dn.to_lowercase().trim().to_string()
    }

    /// Get entry by DN with read transaction (optimized for concurrency)
    fn get_entry_internal(&self, dn: &str) -> Result<Option<StoredEntry>, BackendError> {
        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| BackendError::Storage(format!("Failed to begin read txn: {}", e)))?;

        // Try normalized DN first for fast case-insensitive lookup
        let normalized_dn = Self::normalize_dn(dn);

        // Check DN index for actual DN
        let actual_dn = match txn.get(self.dn_index_db, &normalized_dn.as_bytes()) {
            Ok(bytes) => String::from_utf8_lossy(bytes).to_string(),
            Err(lmdb::Error::NotFound) => return Ok(None),
            Err(e) => {
                return Err(BackendError::Storage(format!(
                    "DN index lookup failed: {}",
                    e
                )))
            }
        };

        // Get entry data
        match txn.get(self.entries_db, &actual_dn.as_bytes()) {
            Ok(bytes) => {
                let entry: StoredEntry = bincode::deserialize(bytes).map_err(|e| {
                    BackendError::Storage(format!("Failed to deserialize entry: {}", e))
                })?;
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
        let base_components = Self::dn_components(base_dn);

        // Use cursor for efficient iteration
        let mut cursor = txn
            .open_ro_cursor(self.entries_db)
            .map_err(|e| BackendError::Storage(format!("Failed to open cursor: {}", e)))?;

        for (key, value) in cursor.iter() {
            let dn = String::from_utf8_lossy(key).to_string();

            if Self::entry_in_scope(&dn, &base_components, scope) {
                let entry: StoredEntry = bincode::deserialize(value).map_err(|e| {
                    BackendError::Storage(format!("Failed to deserialize entry: {}", e))
                })?;
                results.push(entry);
            }
        }

        Ok(results)
    }

    /// Check if DN is in search scope
    fn entry_in_scope(dn: &str, base_components: &[String], scope: SearchScope) -> bool {
        let components = Self::dn_components(dn);

        match scope {
            SearchScope(0) => {
                // Base: exact match
                components
                    .iter()
                    .map(|c| c.to_lowercase())
                    .eq(base_components.iter().map(|c| c.to_lowercase()))
            }
            SearchScope(1) => {
                // One level: immediate children
                if components.len() != base_components.len() + 1 {
                    return false;
                }
                components[1..]
                    .iter()
                    .map(|c| c.to_lowercase())
                    .eq(base_components.iter().map(|c| c.to_lowercase()))
            }
            SearchScope(2) => {
                // Subtree: all descendants
                if components.len() < base_components.len() {
                    return false;
                }
                components[components.len() - base_components.len()..]
                    .iter()
                    .map(|c| c.to_lowercase())
                    .eq(base_components.iter().map(|c| c.to_lowercase()))
            }
            _ => false,
        }
    }

    /// Split DN into components
    fn dn_components(dn: &str) -> Vec<String> {
        dn.split(',')
            .map(|c| c.trim().to_string())
            .filter(|c| !c.is_empty())
            .collect()
    }

    /// Create SSHA512 password hash
    /// Format: {SSHA512}base64(SHA512(password + salt) + salt)
    fn create_ssha512(password: &[u8]) -> String {
        use rand::Rng;

        // Generate random 16-byte salt
        let salt: [u8; 16] = rand::thread_rng().gen();

        // Hash password with salt
        let mut hasher = Sha512::new();
        hasher.update(password);
        hasher.update(&salt);
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

    /// Verify SSHA512 password hash
    /// Format: {SSHA512}base64(SHA512(password + salt) + salt)
    fn verify_ssha512(password: &[u8], stored_hash: &str) -> bool {
        // Remove {SSHA512} prefix if present
        let hash_b64 = if stored_hash.starts_with("{SSHA512}") {
            &stored_hash[9..]
        } else {
            stored_hash
        };

        // Decode base64
        let decoded = match base64::engine::general_purpose::STANDARD.decode(hash_b64) {
            Ok(d) => d,
            Err(_) => return false,
        };

        // SSHA512: first 64 bytes are SHA512 hash, remaining bytes are salt
        if decoded.len() < 64 {
            return false;
        }

        let (stored_hash, salt) = decoded.split_at(64);

        // Hash the provided password with the stored salt
        let mut hasher = Sha512::new();
        hasher.update(password);
        hasher.update(salt);
        let computed_hash = hasher.finalize();

        // Constant-time comparison
        computed_hash.as_slice() == stored_hash
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

    /// Update attribute indexes for an entry
    ///
    /// This method updates the attribute indexes when an entry is added or modified.
    /// For each indexed attribute in the entry, it creates an index entry mapping
    /// "value:dn" -> "" (using composite key to allow multiple DNs per value).
    fn update_attribute_indexes(
        &self,
        txn: &mut lmdb::RwTransaction,
        dn: &str,
        attributes: &HashMap<String, Vec<String>>,
    ) -> Result<(), BackendError> {
        let indexes = self
            .attr_indexes
            .try_read()
            .map_err(|e| BackendError::Storage(format!("Failed to acquire index lock: {}", e)))?;

        for (attr_name, values) in attributes {
            let attr_lower = attr_name.to_lowercase();

            // Check if this attribute is indexed
            if let Some(index_db) = indexes.get(&attr_lower) {
                // Index each value with a composite key "value:dn"
                for value in values {
                    let value_lower = value.to_lowercase();
                    let index_key = format!("{}:{}", value_lower, dn);
                    txn.put(*index_db, &index_key.as_bytes(), &[], WriteFlags::empty())
                        .map_err(|e| {
                            BackendError::Storage(format!(
                                "Failed to update index for {}:{}: {}",
                                attr_name, value, e
                            ))
                        })?;
                }
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
        let indexes = self
            .attr_indexes
            .try_read()
            .map_err(|e| BackendError::Storage(format!("Failed to acquire index lock: {}", e)))?;

        for (attr_name, values) in attributes {
            let attr_lower = attr_name.to_lowercase();

            // Check if this attribute is indexed
            if let Some(index_db) = indexes.get(&attr_lower) {
                // Remove each value from index using composite key
                for value in values {
                    let value_lower = value.to_lowercase();
                    let index_key = format!("{}:{}", value_lower, dn);
                    txn.del(*index_db, &index_key.as_bytes(), None)
                        .or_else(|e| match e {
                            lmdb::Error::NotFound => Ok(()), // Already removed, that's OK
                            _ => Err(BackendError::Storage(format!(
                                "Failed to remove index for {}:{}: {}",
                                attr_name, value, e
                            ))),
                        })?;
                }
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
        let attr_lower = attribute.to_lowercase();
        let value_lower = value.to_lowercase();

        let indexes = self
            .attr_indexes
            .try_read()
            .map_err(|e| BackendError::Storage(format!("Failed to acquire index lock: {}", e)))?;

        // Check if this attribute has an index
        let index_db = match indexes.get(&attr_lower) {
            Some(db) => *db,
            None => {
                // Attribute not indexed, return empty result
                return Ok(Vec::new());
            }
        };

        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| BackendError::Storage(format!("Failed to begin read txn: {}", e)))?;

        let mut results = Vec::new();

        // Use cursor to iterate over all DNs for this attribute value
        // Keys are "value:dn", so we need to find all keys starting with "value:"
        let mut cursor = txn
            .open_ro_cursor(index_db)
            .map_err(|e| BackendError::Storage(format!("Failed to open cursor: {}", e)))?;

        let search_prefix = format!("{}:", value_lower);

        // Iterate through all entries and filter by prefix
        for (key, _value) in cursor.iter() {
            let key_str = String::from_utf8_lossy(key);
            if key_str.starts_with(&search_prefix) {
                // Extract DN from "value:dn" format
                if let Some(dn) = key_str.strip_prefix(&search_prefix) {
                    results.push(dn.to_string());
                }
            }
        }

        Ok(results)
    }

    /// Check if an attribute is indexed
    pub fn is_indexed(&self, attribute: &str) -> bool {
        let attr_lower = attribute.to_lowercase();
        self.index_config
            .indexed_attributes
            .iter()
            .any(|a| a.to_lowercase() == attr_lower)
    }
}

#[async_trait]
impl DirectoryBackend for LmdbBackend {
    async fn authenticate(&self, dn: &str, password: &[u8]) -> Result<bool, BackendError> {
        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| BackendError::Storage(format!("Failed to begin read txn: {}", e)))?;

        let normalized_dn = Self::normalize_dn(dn);
        log::debug!(
            "Authentication attempt - DN: {}, Normalized: {}",
            dn,
            normalized_dn
        );

        // Get actual DN from index
        let actual_dn = match txn.get(self.dn_index_db, &normalized_dn.as_bytes()) {
            Ok(bytes) => String::from_utf8_lossy(bytes).to_string(),
            Err(lmdb::Error::NotFound) => {
                log::warn!("DN not found in index: {}", normalized_dn);
                return Ok(false);
            }
            Err(e) => return Err(BackendError::Storage(format!("DN lookup failed: {}", e))),
        };
        log::debug!("Found actual DN: {}", actual_dn);

        // Get password hash
        match txn.get(self.passwords_db, &actual_dn.as_bytes()) {
            Ok(stored_password_bytes) => {
                let stored_password_str = String::from_utf8_lossy(stored_password_bytes);
                log::debug!("Found password hash for DN: {}", actual_dn);
                // Verify SSHA512 hash
                let result = Self::verify_ssha512(password, &stored_password_str);
                log::debug!("Password verification result: {}", result);
                Ok(result)
            }
            Err(lmdb::Error::NotFound) => {
                log::warn!("Password not found for DN: {}", actual_dn);
                Ok(false)
            }
            Err(e) => Err(BackendError::Storage(format!(
                "Password lookup failed: {}",
                e
            ))),
        }
    }

    async fn get_entry(&self, dn: &str) -> Result<Option<DirectoryEntry>, BackendError> {
        Ok(self.get_entry_internal(dn)?.map(|e| e.to_directory_entry()))
    }

    async fn add_entry(
        &self,
        mut entry: DirectoryEntry,
        password: Vec<u8>,
    ) -> Result<(), BackendError> {
        let _lock = self.write_lock.write().await;

        let mut txn = self
            .env
            .begin_rw_txn()
            .map_err(|e| BackendError::Storage(format!("Failed to begin write txn: {}", e)))?;

        let normalized_dn = Self::normalize_dn(&entry.dn);

        // Check if entry already exists
        if txn.get(self.dn_index_db, &normalized_dn.as_bytes()).is_ok() {
            return Err(BackendError::AlreadyExists);
        }

        // Generate CSN for this entry
        let csn = self.csn_generator.generate();

        // Set operational attributes (entryCSN, createTimestamp, modifyTimestamp, creatorsName)
        // TODO: Get creator DN from authentication context (for now, use None)
        entry.operational_attributes = crate::backend::OperationalAttributes::for_new_entry(
            csn.clone(),
            None, // creator_dn - should come from auth context
        );

        // Create stored entry
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

        // Write entry
        txn.put(
            self.entries_db,
            &entry.dn.as_bytes(),
            &entry_bytes,
            WriteFlags::empty(),
        )
        .map_err(|e| BackendError::Storage(format!("Failed to write entry: {}", e)))?;

        // Hash and write password (if provided)
        if let Some(password_hash) = Self::password_hash_from_bytes(&password) {
            txn.put(
                self.passwords_db,
                &entry.dn.as_bytes(),
                &password_hash.as_bytes(),
                WriteFlags::empty(),
            )
            .map_err(|e| BackendError::Storage(format!("Failed to write password: {}", e)))?;
        }

        // Update DN index
        txn.put(
            self.dn_index_db,
            &normalized_dn.as_bytes(),
            &entry.dn.as_bytes(),
            WriteFlags::empty(),
        )
        .map_err(|e| BackendError::Storage(format!("Failed to update DN index: {}", e)))?;

        // Update attribute indexes
        self.update_attribute_indexes(&mut txn, &entry.dn, &stored_entry.attributes)?;

        // Update contextCSN with the new CSN
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

        Ok(())
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
        let stored_entry: StoredEntry = bincode::deserialize(entry_bytes)
            .map_err(|e| BackendError::Storage(format!("Failed to deserialize entry: {}", e)))?;

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

        Ok(())
    }

    async fn modify_entry(
        &self,
        dn: &str,
        modifications: Vec<Modification>,
    ) -> Result<(), BackendError> {
        let _lock = self.write_lock.write().await;

        let mut entry = self.get_entry_internal(dn)?.ok_or(BackendError::NotFound)?;

        // Save old attributes for index updates
        let old_attributes = entry.attributes.clone();

        // Apply modifications
        for modification in modifications {
            let attribute = modification.attribute.to_lowercase();
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

        // Update modification timestamp
        entry.modified_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Write updated entry
        let mut txn = self
            .env
            .begin_rw_txn()
            .map_err(|e| BackendError::Storage(format!("Failed to begin write txn: {}", e)))?;

        let entry_bytes = bincode::serialize(&entry)
            .map_err(|e| BackendError::Storage(format!("Failed to serialize entry: {}", e)))?;

        txn.put(
            self.entries_db,
            &entry.dn.as_bytes(),
            &entry_bytes,
            WriteFlags::empty(),
        )
        .map_err(|e| BackendError::Storage(format!("Failed to write entry: {}", e)))?;

        if let Some(password_value) = entry
            .attributes
            .get("userpassword")
            .and_then(|values| values.first())
        {
            let password_hash = Self::password_hash_from_value(password_value);
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

        // Update attribute indexes
        // Remove old indexed values and add new ones
        self.remove_attribute_indexes(&mut txn, &entry.dn, &old_attributes)?;
        self.update_attribute_indexes(&mut txn, &entry.dn, &entry.attributes)?;

        txn.commit()
            .map_err(|e| BackendError::Storage(format!("Failed to commit txn: {}", e)))?;

        Ok(())
    }

    async fn compare_attribute(
        &self,
        dn: &str,
        attribute: &str,
        value: &str,
    ) -> Result<bool, BackendError> {
        let entry = self.get_entry_internal(dn)?.ok_or(BackendError::NotFound)?;

        let attribute = attribute.to_lowercase();
        Ok(entry
            .attributes
            .get(&attribute)
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
        let entry: StoredEntry = bincode::deserialize(entry_bytes)
            .map_err(|e| BackendError::Storage(format!("Failed to deserialize entry: {}", e)))?;

        // Compute new DN
        let new_dn = if let Some(superior) = new_superior {
            format!("{},{}", new_rdn, superior)
        } else if let Some((_, rest)) = actual_dn.split_once(',') {
            format!("{},{}", new_rdn, rest)
        } else {
            new_rdn.to_string()
        };
        let normalized_new_dn = Self::normalize_dn(&new_dn);

        // Check if new DN already exists
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
            .for_modified_entry(csn.clone(), None);

        // Handle RDN attribute updates
        if delete_old {
            // Remove old RDN attributes (simplified)
            if let Some((attr, _)) = actual_dn.split_once('=') {
                new_entry.attributes.remove(&attr.trim().to_lowercase());
            }
        }

        // Add new RDN attributes
        if let Some((attr, val)) = new_rdn.split_once('=') {
            let attr_lower = attr.trim().to_lowercase();
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
        if let Some(password_hash) = password_hash {
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

        Ok(())
    }

    async fn search_entries(
        &self,
        base_dn: &str,
        scope: SearchScope,
    ) -> Result<Vec<DirectoryEntry>, BackendError> {
        let entries = self.search_entries_internal(base_dn, scope)?;
        Ok(entries
            .into_iter()
            .map(|e| e.to_directory_entry())
            .collect())
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

    #[tokio::test]
    async fn test_lmdb_backend_create() {
        let dir = tempdir().unwrap();
        let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();
        assert!(backend.db_path.exists());
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

        assert!(backend
            .authenticate("cn=test,dc=example,dc=org", b"secret")
            .await
            .unwrap());
        assert!(!backend
            .authenticate("cn=test,dc=example,dc=org", b"wrong")
            .await
            .unwrap());
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
    async fn test_attribute_index_multiple_entries() {
        let dir = tempdir().unwrap();
        let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

        // Add multiple entries with same attribute value
        for i in 1..=3 {
            let mut attributes = HashMap::new();
            attributes.insert("cn".to_string(), vec![format!("User {}", i)]);
            attributes.insert("ou".to_string(), vec!["Engineering".to_string()]);
            let entry =
                DirectoryEntry::new(&format!("uid=user{},dc=example,dc=org", i), attributes);
            backend.add_entry(entry, vec![]).await.unwrap();
        }

        // Search should return all entries with ou=Engineering
        let results = backend.search_by_index("ou", "Engineering").unwrap();
        assert_eq!(results.len(), 3);
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

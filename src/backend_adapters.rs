//! Backend Adapters for FSM Integration
//!
//! This module provides adapter implementations that connect the main DirectoryBackend
//! trait to the specific backend traits required by individual FSMs (SearchBackend,
//! WriteBackend, CompareBackend, etc.).
//!
//! These adapters enable FSM implementations to work with any DirectoryBackend
//! implementation without tight coupling.

use std::sync::Arc;
use std::collections::HashMap;
use async_trait::async_trait;
use ldap_parser::ldap::SearchScope;

use crate::backend::{DirectoryBackend, DirectoryEntry, Modification as BackendMod, ModifyOperation};
use crate::search_fsm::{SearchBackend, SearchEntry};
use crate::write_fsm::{WriteBackend, Modification as WriteMod};
use crate::compare_fsm::{CompareBackend, CompareEntry};

/// Adapter that implements SearchBackend using a DirectoryBackend
pub struct SearchBackendAdapter {
    backend: Arc<dyn DirectoryBackend>,
}

impl SearchBackendAdapter {
    pub fn new(backend: Arc<dyn DirectoryBackend>) -> Self {
        Self { backend }
    }
}

#[async_trait]
impl SearchBackend for SearchBackendAdapter {
    async fn find_candidates(&self, base_dn: &str, scope: i32, _filter: &str) -> Result<Vec<String>, String> {
        // Convert scope to SearchScope
        let search_scope = SearchScope(scope as u32);

        let entries = self.backend.search_entries(base_dn, search_scope)
            .await
            .map_err(|e| format!("Backend search error: {}", e))?;

        Ok(entries.into_iter().map(|e| e.dn).collect())
    }

    async fn get_entry(&self, dn: &str, _attributes: &[String]) -> Result<Option<SearchEntry>, String> {
        let entry = self.backend.get_entry(dn)
            .await
            .map_err(|e| format!("Backend get_entry error: {}", e))?;

        Ok(entry.map(|e| SearchEntry {
            dn: e.dn.clone(),
            attributes: e.attributes.clone(),
            object_classes: e.attributes.get("objectclass")
                .cloned()
                .unwrap_or_default(),
        }))
    }

    async fn entry_exists(&self, dn: &str) -> Result<bool, String> {
        let entry = self.backend.get_entry(dn)
            .await
            .map_err(|e| format!("Backend entry_exists error: {}", e))?;
        Ok(entry.is_some())
    }

    async fn get_search_stats(&self, _base_dn: &str) -> Result<(usize, usize), String> {
        // Return dummy stats for now (total_entries, indexed_entries)
        Ok((0, 0))
    }
}

/// Adapter that implements WriteBackend using a DirectoryBackend
pub struct WriteBackendAdapter {
    backend: Arc<dyn DirectoryBackend>,
}

impl WriteBackendAdapter {
    pub fn new(backend: Arc<dyn DirectoryBackend>) -> Self {
        Self { backend }
    }
}

#[async_trait]
impl WriteBackend for WriteBackendAdapter {
    async fn begin_transaction(&self) -> Result<String, String> {
        // For now, generate a simple transaction ID
        // Real implementation would use backend transaction support
        Ok(uuid::Uuid::new_v4().to_string())
    }

    async fn commit_transaction(&self, _txn_id: &str) -> Result<(), String> {
        // No-op for now - real implementation would commit backend transaction
        Ok(())
    }

    async fn rollback_transaction(&self, _txn_id: &str, _reason: &str) -> Result<(), String> {
        // No-op for now - real implementation would rollback backend transaction
        Ok(())
    }

    async fn validate_entry(&self, _dn: &str, _entry: &[u8]) -> Result<(), String> {
        // Basic validation - real implementation would do schema validation
        Ok(())
    }

    async fn add_entry(&self, _txn_id: &str, dn: &str, entry: &[u8]) -> Result<(), String> {
        // Parse entry from LDIF-like format (simplified)
        let entry_str = String::from_utf8_lossy(entry);
        let mut attributes = HashMap::new();

        for line in entry_str.lines() {
            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim().to_lowercase();
                let value = value.trim().to_string();
                attributes.entry(key).or_insert_with(Vec::new).push(value);
            }
        }

        let dir_entry = DirectoryEntry::new(dn, attributes);

        self.backend.add_entry(dir_entry, Vec::new())
            .await
            .map_err(|e| format!("Backend add_entry error: {}", e))
    }

    async fn modify_entry(&self, _txn_id: &str, dn: &str, modifications: &[WriteMod]) -> Result<(), String> {
        // Convert WriteMod enum to BackendMod struct
        let mods: Vec<BackendMod> = modifications.iter().map(|m| {
            match m {
                WriteMod::Add { name, values } => BackendMod {
                    operation: ModifyOperation::Add,
                    attribute: name.clone(),
                    values: values.clone(),
                },
                WriteMod::Delete { name, values } => BackendMod {
                    operation: ModifyOperation::Delete,
                    attribute: name.clone(),
                    values: values.clone(),
                },
                WriteMod::Replace { name, values } => BackendMod {
                    operation: ModifyOperation::Replace,
                    attribute: name.clone(),
                    values: values.clone(),
                },
            }
        }).collect();

        self.backend.modify_entry(dn, mods)
            .await
            .map_err(|e| format!("Backend modify_entry error: {}", e))
    }

    async fn modify_dn(
        &self,
        _txn_id: &str,
        dn: &str,
        new_rdn: &str,
        delete_old: bool,
        new_superior: Option<&str>,
    ) -> Result<(), String> {
        self.backend.rename_entry(dn, new_rdn, delete_old, new_superior.map(String::from))
            .await
            .map_err(|e| format!("Backend rename_entry error: {}", e))
    }

    async fn delete_entry(&self, _txn_id: &str, dn: &str) -> Result<(), String> {
        self.backend.delete_entry(dn)
            .await
            .map_err(|e| format!("Backend delete_entry error: {}", e))
    }

    async fn entry_exists(&self, dn: &str) -> Result<bool, String> {
        let entry = self.backend.get_entry(dn)
            .await
            .map_err(|e| format!("Backend entry_exists error: {}", e))?;
        Ok(entry.is_some())
    }
}

/// Adapter that implements CompareBackend using a DirectoryBackend
pub struct CompareBackendAdapter {
    backend: Arc<dyn DirectoryBackend>,
}

impl CompareBackendAdapter {
    pub fn new(backend: Arc<dyn DirectoryBackend>) -> Self {
        Self { backend }
    }
}

#[async_trait]
impl CompareBackend for CompareBackendAdapter {
    async fn get_entry_attributes(&self, dn: &str, attributes: &[String]) -> Result<Option<CompareEntry>, String> {
        let entry = self.backend.get_entry(dn)
            .await
            .map_err(|e| format!("Backend get_entry error: {}", e))?;

        Ok(entry.map(|e| {
            // Convert string attributes to binary format
            let binary_attrs: HashMap<String, Vec<Vec<u8>>> = e.attributes.iter()
                .map(|(k, v)| {
                    (k.clone(), v.iter().map(|s| s.as_bytes().to_vec()).collect())
                })
                .collect();

            CompareEntry {
                dn: e.dn.clone(),
                attributes: binary_attrs,
                object_classes: e.attributes.get("objectclass")
                    .cloned()
                    .unwrap_or_default(),
            }
        }))
    }

    async fn entry_exists(&self, dn: &str) -> Result<bool, String> {
        let entry = self.backend.get_entry(dn)
            .await
            .map_err(|e| format!("Backend entry_exists error: {}", e))?;
        Ok(entry.is_some())
    }

    async fn get_compare_stats(&self, _dn: &str) -> Result<(u64, u64), String> {
        // Return dummy stats for now (successful_compares, failed_compares)
        Ok((0, 0))
    }
}

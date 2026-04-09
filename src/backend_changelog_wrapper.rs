//! Backend Changelog Wrapper
//!
//! This module provides a wrapper around DirectoryBackend that automatically
//! records all write operations to a changelog for replication purposes.
//!
//! ## Overview
//!
//! The `ChangelogBackendWrapper` intercepts all backend operations and:
//! - Forwards read operations directly to the underlying backend
//! - Records write operations to the changelog after successful completion
//! - Maintains sequence numbers for changelog entries
//! - Supports optional changelog (can be disabled)
//!
//! ## Usage
//!
//! ```rust,ignore
//! use opendr::backend_changelog_wrapper::ChangelogBackendWrapper;
//! use opendr::replication::ChangelogTracker;
//!
//! // Create backend with changelog tracking
//! let changelog = Arc::new(ChangelogTracker::new());
//! let backend = Arc::new(LmdbBackend::new("./data", 100)?);
//! let wrapper = ChangelogBackendWrapper::new(backend, Some(changelog));
//!
//! // All write operations now recorded to changelog
//! wrapper.add_entry(entry, password).await?;
//! ```

use async_trait::async_trait;
use ldap_parser::ldap::SearchScope as Scope;
use std::sync::Arc;
use tokio::sync::broadcast;

use crate::backend::{
    BackendError, DirectoryBackend, DirectoryEntry, Modification, SearchCandidateHint,
};
use crate::change_observer::ChangeObserver;
use crate::replication::{encode_rename_change, ChangelogTracker};
use crate::replication_provider_fsm::{ChangeType, ChangelogEntry};

#[cfg(test)]
use crate::replication::RenameChange;

/// Wrapper around DirectoryBackend that records changes to a changelog
///
/// This wrapper forwards all operations to the underlying backend and records
/// write operations to the changelog after successful completion.
pub struct ChangelogBackendWrapper {
    /// Underlying directory backend
    backend: Arc<dyn DirectoryBackend>,

    /// Optional changelog tracker for replication
    changelog: Option<Arc<ChangelogTracker>>,

    /// Optional change observer for push-based replication notifications
    observer: Option<Arc<dyn ChangeObserver>>,

    /// Optional broadcast channel for live replication stream subscribers
    replication_sender: Option<broadcast::Sender<ChangelogEntry>>,
}

impl ChangelogBackendWrapper {
    /// Create a new changelog wrapper
    ///
    /// # Arguments
    /// * `backend` - The underlying directory backend
    /// * `changelog` - Optional changelog tracker (None disables changelog)
    ///
    /// # Returns
    /// New `ChangelogBackendWrapper` instance
    pub fn new(
        backend: Arc<dyn DirectoryBackend>,
        changelog: Option<Arc<ChangelogTracker>>,
    ) -> Self {
        Self {
            backend,
            changelog,
            observer: None,
            replication_sender: None,
        }
    }

    /// Set the change observer for push-based replication
    ///
    /// # Arguments
    /// * `observer` - Change observer to notify on directory changes
    pub fn set_observer(&mut self, observer: Arc<dyn ChangeObserver>) {
        self.observer = Some(observer);
    }

    /// Set the broadcast sender for live replication stream subscribers.
    pub fn set_replication_sender(&mut self, sender: broadcast::Sender<ChangelogEntry>) {
        self.replication_sender = Some(sender);
    }

    /// Record a change to the changelog
    ///
    /// # Arguments
    /// * `change_type` - Type of change (Add, Modify, Delete, ModifyDN)
    /// * `dn` - Distinguished name of the entry
    /// * `change_data` - Serialized entry data
    ///
    /// # Returns
    /// CSN assigned to the change, or None if changelog disabled
    fn record_change(
        &self,
        change_type: ChangeType,
        dn: String,
        change_data: Vec<u8>,
    ) -> Option<crate::csn::Csn> {
        if let Some(ref changelog) = self.changelog {
            let csn = changelog.record_change(change_type.clone(), dn.clone(), change_data.clone());

            // Notify observer if present (for push-based replication)
            if let Some(ref observer) = self.observer {
                let changelog_entry = crate::replication_provider_fsm::ChangelogEntry::new(
                    csn.clone(),
                    change_type,
                    dn,
                    change_data,
                );
                let observer_entry = changelog_entry.clone();

                // Spawn async task to notify observer without blocking
                let observer = observer.clone();
                tokio::spawn(async move {
                    if let Err(e) = observer.notify_change(&observer_entry).await {
                        use log::error;
                        error!("Failed to notify change observer: {}", e);
                    }
                });
                if let Some(ref sender) = self.replication_sender {
                    let _ = sender.send(changelog_entry);
                }
            } else if let Some(ref sender) = self.replication_sender {
                let changelog_entry = crate::replication_provider_fsm::ChangelogEntry::new(
                    csn.clone(),
                    change_type,
                    dn,
                    change_data,
                );
                let _ = sender.send(changelog_entry);
            }

            Some(csn)
        } else {
            None
        }
    }

    /// Serialize an entry to bytes for changelog storage
    fn serialize_entry(entry: &DirectoryEntry) -> Vec<u8> {
        // Serialize the entire entry as JSON for easy deserialization
        // This includes DN and all attributes
        match serde_json::to_vec(entry) {
            Ok(data) => data,
            Err(e) => {
                use log::error;
                error!("Failed to serialize entry {}: {:?}", entry.dn, e);
                Vec::new()
            }
        }
    }
}

#[async_trait]
impl DirectoryBackend for ChangelogBackendWrapper {
    async fn authenticate(&self, dn: &str, password: &[u8]) -> Result<bool, BackendError> {
        // Authentication is read-only, no changelog recording needed
        self.backend.authenticate(dn, password).await
    }

    async fn add_entry(
        &self,
        entry: DirectoryEntry,
        password: Vec<u8>,
    ) -> Result<(), BackendError> {
        // Record DN and serialized entry before adding
        let dn = entry.dn.clone();
        let entry_data = Self::serialize_entry(&entry);

        // Perform the add operation
        self.backend.add_entry(entry, password).await?;

        // Record to changelog after successful add
        self.record_change(ChangeType::Add, dn, entry_data);

        Ok(())
    }

    async fn get_entry(&self, dn: &str) -> Result<Option<DirectoryEntry>, BackendError> {
        // Read operation, no changelog recording needed
        self.backend.get_entry(dn).await
    }

    async fn modify_entry(
        &self,
        dn: &str,
        modifications: Vec<Modification>,
    ) -> Result<(), BackendError> {
        // Perform the modify operation
        self.backend.modify_entry(dn, modifications.clone()).await?;

        // Get the updated entry for changelog
        if let Ok(Some(entry)) = self.backend.get_entry(dn).await {
            let entry_data = Self::serialize_entry(&entry);
            self.record_change(ChangeType::Modify, dn.to_string(), entry_data);
        }

        Ok(())
    }

    async fn delete_entry(&self, dn: &str) -> Result<(), BackendError> {
        // Get entry before deletion for changelog
        let entry_data = if let Ok(Some(entry)) = self.backend.get_entry(dn).await {
            Self::serialize_entry(&entry)
        } else {
            Vec::new()
        };

        // Perform the delete operation
        self.backend.delete_entry(dn).await?;

        // Record to changelog after successful delete
        self.record_change(ChangeType::Delete, dn.to_string(), entry_data);

        Ok(())
    }

    async fn search_entries(
        &self,
        base_dn: &str,
        scope: Scope,
    ) -> Result<Vec<DirectoryEntry>, BackendError> {
        // Read operation, no changelog recording needed
        self.backend.search_entries(base_dn, scope).await
    }

    async fn search_entries_with_hint(
        &self,
        base_dn: &str,
        scope: Scope,
        hint: Option<SearchCandidateHint>,
    ) -> Result<Vec<DirectoryEntry>, BackendError> {
        self.backend
            .search_entries_with_hint(base_dn, scope, hint)
            .await
    }

    async fn get_context_csn(&self) -> Result<Option<crate::csn::Csn>, BackendError> {
        // Delegate to underlying backend
        self.backend.get_context_csn().await
    }

    async fn set_context_csn(&self, csn: crate::csn::Csn) -> Result<(), BackendError> {
        // Delegate to underlying backend
        self.backend.set_context_csn(csn).await
    }

    fn replication_changelog(&self) -> Option<Arc<ChangelogTracker>> {
        self.changelog.clone()
    }

    fn subscribe_to_replication_changes(&self) -> Option<broadcast::Receiver<ChangelogEntry>> {
        self.replication_sender
            .as_ref()
            .map(|sender| sender.subscribe())
    }

    async fn rename_entry(
        &self,
        dn: &str,
        new_rdn: &str,
        delete_old: bool,
        new_superior: Option<String>,
    ) -> Result<(), BackendError> {
        // Perform the rename operation
        self.backend
            .rename_entry(dn, new_rdn, delete_old, new_superior.clone())
            .await?;

        // Record to changelog after successful rename
        self.record_change(
            ChangeType::Rename,
            dn.to_string(),
            encode_rename_change(new_rdn, delete_old, new_superior.as_deref()),
        );

        Ok(())
    }

    async fn compare_attribute(
        &self,
        dn: &str,
        attribute: &str,
        value: &str,
    ) -> Result<bool, BackendError> {
        // Read operation, no changelog recording needed
        self.backend.compare_attribute(dn, attribute, value).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MockBackend;
    use std::collections::HashMap;

    fn create_test_entry(dn: &str) -> DirectoryEntry {
        let mut attributes = HashMap::new();
        attributes.insert("cn".to_string(), vec!["Test User".to_string()]);
        attributes.insert("objectclass".to_string(), vec!["person".to_string()]);
        DirectoryEntry::new(dn, attributes)
    }

    #[tokio::test]
    async fn test_add_entry_records_to_changelog() {
        let backend = Arc::new(MockBackend::new());
        let changelog = Arc::new(ChangelogTracker::new());
        let wrapper = ChangelogBackendWrapper::new(backend, Some(changelog.clone()));

        let entry = create_test_entry("cn=test,dc=example,dc=com");
        wrapper.add_entry(entry, vec![]).await.unwrap();

        // Verify changelog recorded the add (get all entries)
        let entries = changelog.get_all();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].dn, "cn=test,dc=example,dc=com");
        assert!(matches!(entries[0].change_type, ChangeType::Add));
        // Verify CSN was assigned
        assert_eq!(entries[0].csn.replica_id(), 1); // Default replica ID
    }

    #[tokio::test]
    async fn test_modify_entry_records_to_changelog() {
        let backend = MockBackend::new();
        let entry = create_test_entry("cn=test,dc=example,dc=com");
        backend.add_entry(entry.clone(), vec![]).await.unwrap();

        let backend = Arc::new(backend);
        let changelog = Arc::new(ChangelogTracker::new());
        let wrapper = ChangelogBackendWrapper::new(backend, Some(changelog.clone()));

        let modifications = vec![Modification {
            operation: crate::backend::ModifyOperation::Replace,
            attribute: "cn".to_string(),
            values: vec!["Modified User".to_string()],
        }];
        wrapper
            .modify_entry("cn=test,dc=example,dc=com", modifications)
            .await
            .unwrap();

        // Verify changelog recorded the modify
        let entries = changelog.get_all();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].dn, "cn=test,dc=example,dc=com");
        assert!(matches!(entries[0].change_type, ChangeType::Modify));
    }

    #[tokio::test]
    async fn test_delete_entry_records_to_changelog() {
        let backend = MockBackend::new();
        let entry = create_test_entry("cn=test,dc=example,dc=com");
        backend.add_entry(entry, vec![]).await.unwrap();

        let backend = Arc::new(backend);
        let changelog = Arc::new(ChangelogTracker::new());
        let wrapper = ChangelogBackendWrapper::new(backend, Some(changelog.clone()));

        wrapper
            .delete_entry("cn=test,dc=example,dc=com")
            .await
            .unwrap();

        // Verify changelog recorded the delete
        let entries = changelog.get_all();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].dn, "cn=test,dc=example,dc=com");
        assert!(matches!(entries[0].change_type, ChangeType::Delete));
    }

    #[tokio::test]
    async fn test_rename_entry_records_to_changelog() {
        let backend = MockBackend::new();
        let entry = create_test_entry("cn=test,dc=example,dc=com");
        backend.add_entry(entry, vec![]).await.unwrap();

        let backend = Arc::new(backend);
        let changelog = Arc::new(ChangelogTracker::new());
        let wrapper = ChangelogBackendWrapper::new(backend, Some(changelog.clone()));

        wrapper
            .rename_entry("cn=test,dc=example,dc=com", "cn=renamed", true, None)
            .await
            .unwrap();

        // Verify changelog recorded the rename
        let entries = changelog.get_all();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].dn, "cn=test,dc=example,dc=com");
        assert!(matches!(entries[0].change_type, ChangeType::Rename));
        let payload: RenameChange = serde_json::from_slice(&entries[0].change_data).unwrap();
        assert_eq!(
            payload,
            RenameChange {
                new_rdn: "cn=renamed".to_string(),
                delete_old: true,
                new_superior: None,
            }
        );
    }

    #[tokio::test]
    async fn test_operations_without_changelog() {
        let backend = Arc::new(MockBackend::new());
        let wrapper = ChangelogBackendWrapper::new(backend, None);

        let entry = create_test_entry("cn=test,dc=example,dc=com");
        wrapper.add_entry(entry, vec![]).await.unwrap();

        // Should not panic, operations work without changelog
    }

    #[tokio::test]
    async fn test_csn_generation() {
        let backend = Arc::new(MockBackend::new());
        let changelog = Arc::new(ChangelogTracker::with_replica_id(5));
        let wrapper = ChangelogBackendWrapper::new(backend, Some(changelog.clone()));

        // Add multiple entries
        for i in 0..5 {
            let entry = create_test_entry(&format!("cn=test{},dc=example,dc=com", i));
            wrapper.add_entry(entry, vec![]).await.unwrap();
        }

        // Verify CSNs are assigned and ordered
        let entries = changelog.get_all();
        assert_eq!(entries.len(), 5);

        // Verify all have the correct replica ID
        for entry in &entries {
            assert_eq!(entry.csn.replica_id(), 5);
        }

        // Verify CSNs are in increasing order
        for i in 1..entries.len() {
            assert!(
                entries[i].csn > entries[i - 1].csn,
                "CSN {} should be greater than CSN {}",
                entries[i].csn,
                entries[i - 1].csn
            );
        }
    }

    #[tokio::test]
    async fn test_concurrent_changelog_recording() {
        let backend = Arc::new(MockBackend::new());
        let changelog = Arc::new(ChangelogTracker::new());
        let wrapper = Arc::new(ChangelogBackendWrapper::new(
            backend,
            Some(changelog.clone()),
        ));

        // Spawn multiple concurrent add operations
        let mut handles = vec![];
        for i in 0..10 {
            let wrapper = wrapper.clone();
            let handle = tokio::spawn(async move {
                let entry = create_test_entry(&format!("cn=test{},dc=example,dc=com", i));
                wrapper.add_entry(entry, vec![]).await.unwrap();
            });
            handles.push(handle);
        }

        // Wait for all operations to complete
        for handle in handles {
            handle.await.unwrap();
        }

        // Verify all entries recorded
        let entries = changelog.get_all();
        assert_eq!(entries.len(), 10);
    }
}

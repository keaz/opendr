//! CSN Replication Server Integration Tests
//!
//! End-to-end tests verifying CSN-based replication in full server context,
//! including provider-consumer replication with contextCSN tracking.

use opendr::backend::MockBackend;
use opendr::backend::{DirectoryBackend, DirectoryEntry, Modification, ModifyOperation};
use opendr::backend_changelog_wrapper::ChangelogBackendWrapper;
use opendr::csn::Csn;
use opendr::replication::{ChangelogProviderImpl, ChangelogTracker};
use opendr::replication_provider_fsm::ChangelogProvider;
use std::collections::HashMap;
use std::sync::Arc;

fn create_test_entry(dn: &str, cn: &str, sn: &str) -> DirectoryEntry {
    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec![cn.to_string()]);
    attributes.insert("sn".to_string(), vec![sn.to_string()]);
    attributes.insert("objectClass".to_string(), vec!["person".to_string()]);
    DirectoryEntry::new(dn, attributes)
}

#[tokio::test]
async fn test_csn_replication_full_workflow() {
    // Setup provider with CSN-based changelog
    let provider_backend = Arc::new(MockBackend::new());
    let provider_changelog = ChangelogTracker::with_replica_id(1);
    let provider_wrapper = Arc::new(ChangelogBackendWrapper::new(
        provider_backend.clone(),
        Some(Arc::new(provider_changelog.clone())),
    ));

    // Setup consumer backend
    let consumer_backend = Arc::new(MockBackend::new());

    // Phase 1: Add entries to provider
    let entry1 = create_test_entry("cn=john,dc=example,dc=org", "John", "Doe");
    provider_wrapper.add_entry(entry1, vec![]).await.unwrap();

    let entry2 = create_test_entry("cn=jane,dc=example,dc=org", "Jane", "Smith");
    provider_wrapper.add_entry(entry2, vec![]).await.unwrap();

    // Verify provider has changelog entries with CSNs
    let provider_changes = provider_changelog.get_all();
    assert_eq!(provider_changes.len(), 2);
    let csn1 = &provider_changes[0].csn;
    let csn2 = &provider_changes[1].csn;
    assert!(
        csn2 > csn1,
        "CSN ordering: csn2 should be greater than csn1"
    );

    // Phase 2: Consumer performs initial sync (full refresh)
    let provider_impl =
        ChangelogProviderImpl::new(provider_changelog.clone(), provider_backend.clone());

    // Get all entries for full refresh (cookie is empty)
    let refresh_entries = provider_impl
        .get_all_entries("dc=example,dc=org", None)
        .await
        .unwrap();
    assert_eq!(refresh_entries.len(), 2);

    // Apply to consumer
    for entry in refresh_entries {
        consumer_backend
            .add_entry(DirectoryEntry::new(entry.dn, entry.attributes), vec![])
            .await
            .unwrap();
    }

    // Get contextCSN and generate cookie
    let context_csn = provider_impl.get_context_csn().await.unwrap();
    assert!(context_csn.is_some());
    let context_csn_value = context_csn.clone().unwrap();
    let sync_cookie = provider_impl
        .generate_cookie(&context_csn_value)
        .await
        .unwrap();

    // Phase 3: Provider gets more changes
    let entry3 = create_test_entry("cn=bob,dc=example,dc=org", "Bob", "Johnson");
    provider_wrapper.add_entry(entry3, vec![]).await.unwrap();

    // Modify existing entry
    let modifications = vec![Modification {
        operation: ModifyOperation::Replace,
        attribute: "sn".to_string(),
        values: vec!["DOE".to_string()],
    }];
    provider_wrapper
        .modify_entry("cn=john,dc=example,dc=org", modifications)
        .await
        .unwrap();

    // Delete an entry
    provider_wrapper
        .delete_entry("cn=jane,dc=example,dc=org")
        .await
        .unwrap();

    // Phase 4: Consumer performs incremental sync
    let incremental_changes = provider_impl
        .get_changelog_since(Some(&sync_cookie), 100)
        .await
        .unwrap();

    // Should get 3 new changes: add bob, modify john, delete jane
    assert_eq!(incremental_changes.len(), 3);

    // Verify all changes have CSNs greater than the sync cookie CSN
    let sync_csn = provider_changelog.parse_cookie(&sync_cookie).unwrap();
    for change in &incremental_changes {
        assert!(
            change.csn > sync_csn,
            "Change CSN {} should be greater than sync CSN {}",
            change.csn,
            sync_csn
        );
    }

    // Phase 5: Verify contextCSN is updated
    let new_context_csn = provider_impl.get_context_csn().await.unwrap().unwrap();
    assert!(
        new_context_csn > context_csn_value,
        "New contextCSN should be greater than previous"
    );

    // Verify it matches the last change CSN
    assert_eq!(new_context_csn, incremental_changes.last().unwrap().csn);
}

#[tokio::test]
async fn test_csn_multi_replica_replication() {
    // Simulate two replicas with different replica IDs
    let replica1_backend = Arc::new(MockBackend::new());
    let replica1_changelog = ChangelogTracker::with_replica_id(1);
    let replica1_wrapper = ChangelogBackendWrapper::new(
        replica1_backend.clone(),
        Some(Arc::new(replica1_changelog.clone())),
    );

    let replica2_backend = Arc::new(MockBackend::new());
    let replica2_changelog = ChangelogTracker::with_replica_id(2);
    let replica2_wrapper = ChangelogBackendWrapper::new(
        replica2_backend.clone(),
        Some(Arc::new(replica2_changelog.clone())),
    );

    // Add entries to replica 1
    let entry1 = create_test_entry("cn=user1,dc=example,dc=org", "User", "One");
    replica1_wrapper.add_entry(entry1, vec![]).await.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    // Add entries to replica 2
    let entry2 = create_test_entry("cn=user2,dc=example,dc=org", "User", "Two");
    replica2_wrapper.add_entry(entry2, vec![]).await.unwrap();

    // Get changes from both replicas
    let replica1_changes = replica1_changelog.get_all();
    let replica2_changes = replica2_changelog.get_all();

    assert_eq!(replica1_changes.len(), 1);
    assert_eq!(replica2_changes.len(), 1);

    // Verify replica IDs are different
    assert_eq!(replica1_changes[0].csn.replica_id(), 1);
    assert_eq!(replica2_changes[0].csn.replica_id(), 2);

    // Verify CSNs can be properly ordered by timestamp
    assert!(
        replica2_changes[0].csn > replica1_changes[0].csn,
        "Replica 2 CSN should be greater due to later timestamp"
    );
}

#[tokio::test]
async fn test_csn_replication_resume_after_disconnect() {
    // Setup provider
    let backend = Arc::new(MockBackend::new());
    let changelog = ChangelogTracker::with_replica_id(5);
    let wrapper = Arc::new(ChangelogBackendWrapper::new(
        backend.clone(),
        Some(Arc::new(changelog.clone())),
    ));
    let provider = ChangelogProviderImpl::new(changelog.clone(), backend.clone());

    // Initial changes
    for i in 1..=5 {
        let entry = create_test_entry(
            &format!("cn=user{},dc=example,dc=org", i),
            &format!("User{}", i),
            "Test",
        );
        wrapper.add_entry(entry, vec![]).await.unwrap();
    }

    // Consumer syncs and saves cookie at position 3
    let changes = changelog.get_all();
    let csn_at_3 = &changes[2].csn; // 3rd entry (index 2)
    let saved_cookie = changelog.generate_cookie_from_csn(csn_at_3);

    // Add more changes while consumer is disconnected
    for i in 6..=10 {
        let entry = create_test_entry(
            &format!("cn=user{},dc=example,dc=org", i),
            &format!("User{}", i),
            "Test",
        );
        wrapper.add_entry(entry, vec![]).await.unwrap();
    }

    // Consumer reconnects and resumes from saved cookie
    let resumed_changes = provider
        .get_changelog_since(Some(&saved_cookie), 100)
        .await
        .unwrap();

    // Should get entries 4-10 (7 entries)
    assert_eq!(resumed_changes.len(), 7);

    // Verify all resumed changes are after the saved cookie CSN
    for change in &resumed_changes {
        assert!(
            change.csn > *csn_at_3,
            "Resumed change CSN should be after saved cookie CSN"
        );
    }
}

#[tokio::test]
async fn test_csn_replication_with_operations() {
    // Setup
    let backend = Arc::new(MockBackend::new());
    let changelog = ChangelogTracker::with_replica_id(3);
    let wrapper = Arc::new(ChangelogBackendWrapper::new(
        backend.clone(),
        Some(Arc::new(changelog.clone())),
    ));

    // Test various operations
    // 1. Add
    let entry = create_test_entry("cn=test,dc=example,dc=org", "Test", "User");
    wrapper.add_entry(entry, vec![]).await.unwrap();

    // 2. Modify
    let modifications = vec![Modification {
        operation: ModifyOperation::Replace,
        attribute: "sn".to_string(),
        values: vec!["Modified".to_string()],
    }];
    wrapper
        .modify_entry("cn=test,dc=example,dc=org", modifications)
        .await
        .unwrap();

    // 3. Rename
    wrapper
        .rename_entry("cn=test,dc=example,dc=org", "cn=renamed", true, None)
        .await
        .unwrap();

    // 4. Delete
    wrapper
        .delete_entry("cn=renamed,dc=example,dc=org")
        .await
        .unwrap();

    // Verify all operations recorded with unique CSNs
    let changes = changelog.get_all();
    assert_eq!(changes.len(), 4);

    // Verify CSNs are strictly increasing
    for i in 1..changes.len() {
        assert!(
            changes[i].csn > changes[i - 1].csn,
            "CSN {} should be greater than CSN {}",
            changes[i].csn,
            changes[i - 1].csn
        );
    }

    // Verify contextCSN matches last operation
    let context_csn = changelog.get_context_csn().unwrap();
    assert_eq!(context_csn, changes[3].csn);
}

#[tokio::test]
async fn test_csn_cookie_validation() {
    let backend = Arc::new(MockBackend::new());
    let changelog = ChangelogTracker::with_replica_id(4);
    let provider = ChangelogProviderImpl::new(changelog.clone(), backend.clone());

    // Record a change
    let csn = changelog.record_change(
        opendr::replication_provider_fsm::ChangeType::Add,
        "cn=test,dc=example,dc=org".to_string(),
        b"test data".to_vec(),
    );

    // Valid cookie
    let valid_cookie = changelog.generate_cookie_from_csn(&csn);
    assert!(provider.validate_cookie(&valid_cookie).await.unwrap());

    // Empty cookie (special case for initial sync)
    assert!(provider.validate_cookie("csn-empty").await.unwrap());

    // Invalid cookie format
    assert!(!provider.validate_cookie("invalid-cookie").await.unwrap());

    // Invalid CSN format
    assert!(!provider.validate_cookie("csn-invalid").await.unwrap());
}

#[tokio::test]
async fn test_csn_contextcsn_in_backend() {
    // This test verifies that backends can track contextCSN via backend trait
    let backend = Arc::new(MockBackend::new());

    // Initial contextCSN should be None
    let initial_csn = backend.get_context_csn().await.unwrap();
    assert!(initial_csn.is_none());

    // Set contextCSN
    let csn1 = Csn::new(1);
    backend.set_context_csn(csn1.clone()).await.unwrap();

    // Retrieve and verify
    let retrieved_csn = backend.get_context_csn().await.unwrap();
    assert_eq!(retrieved_csn, Some(csn1.clone()));

    // Update to newer CSN
    tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
    let csn2 = Csn::new(1);
    backend.set_context_csn(csn2.clone()).await.unwrap();

    // Should have updated
    let new_csn = backend.get_context_csn().await.unwrap();
    assert_eq!(new_csn, Some(csn2));
    assert!(new_csn.unwrap() > csn1);
}

//! Integration tests for backend adapters
//!
//! This test suite verifies that the backend adapters correctly connect
//! DirectoryBackend to the FSM-specific backend traits.

use opendr::backend::{DirectoryBackend, DirectoryEntry, MockBackend};
use opendr::backend_adapters::{CompareBackendAdapter, SearchBackendAdapter, WriteBackendAdapter};
use opendr::compare_fsm::CompareBackend;
use opendr::search_fsm::SearchBackend;
use opendr::write_fsm::{Modification, WriteBackend};
use std::collections::HashMap;
use std::sync::Arc;

#[tokio::test]
async fn test_search_backend_adapter() {
    // Create mock backend with test data
    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["testuser".to_string()]);
    attributes.insert("objectclass".to_string(), vec!["person".to_string()]);

    let backend = Arc::new(MockBackend::default());

    // Add test entry
    let entry = DirectoryEntry::new("cn=testuser,dc=example,dc=org", attributes.clone());
    backend
        .add_entry(entry, b"password".to_vec())
        .await
        .unwrap();

    // Create adapter
    let adapter = SearchBackendAdapter::new(backend.clone());

    // Test find_candidates
    let candidates = adapter
        .find_candidates("dc=example,dc=org", 2, "(cn=testuser)")
        .await
        .unwrap();
    assert!(!candidates.is_empty(), "Should find at least one candidate");

    // Test get_entry
    let entry = adapter
        .get_entry("cn=testuser,dc=example,dc=org", &["cn".to_string()])
        .await
        .unwrap();
    assert!(entry.is_some(), "Entry should exist");
    let entry = entry.unwrap();
    assert_eq!(entry.dn, "cn=testuser,dc=example,dc=org");
    assert!(entry.attributes.contains_key("cn"));

    // Test entry_exists
    let exists = adapter
        .entry_exists("cn=testuser,dc=example,dc=org")
        .await
        .unwrap();
    assert!(exists, "Entry should exist");

    let not_exists = adapter
        .entry_exists("cn=nonexistent,dc=example,dc=org")
        .await
        .unwrap();
    assert!(!not_exists, "Non-existent entry should not exist");

    // Test get_search_stats
    let stats = adapter.get_search_stats("dc=example,dc=org").await.unwrap();
    assert_eq!(stats, (0, 0), "Stats should return (0, 0) for now");
}

#[tokio::test]
async fn test_write_backend_adapter() {
    let backend = Arc::new(MockBackend::default());
    let adapter = WriteBackendAdapter::new(backend.clone());

    // Test begin/commit transaction
    let txn_id = adapter.begin_transaction().await.unwrap();
    assert!(!txn_id.is_empty(), "Transaction ID should not be empty");

    adapter.commit_transaction(&txn_id).await.unwrap();

    // Test rollback transaction
    let txn_id = adapter.begin_transaction().await.unwrap();
    adapter
        .rollback_transaction(&txn_id, "test rollback")
        .await
        .unwrap();

    // Test validate_entry
    let entry_data = b"dn: cn=newuser,dc=example,dc=org\ncn: newuser\nobjectClass: person\n";
    adapter
        .validate_entry("cn=newuser,dc=example,dc=org", entry_data)
        .await
        .unwrap();

    // Test add_entry
    let txn_id = adapter.begin_transaction().await.unwrap();
    adapter
        .add_entry(&txn_id, "cn=newuser,dc=example,dc=org", entry_data)
        .await
        .unwrap();

    // Test entry_exists
    let exists = adapter
        .entry_exists("cn=newuser,dc=example,dc=org")
        .await
        .unwrap();
    assert!(exists, "Added entry should exist");

    // Test modify_entry
    let txn_id = adapter.begin_transaction().await.unwrap();
    let modifications = vec![Modification::Add {
        name: "mail".to_string(),
        values: vec!["newuser@example.org".to_string()],
    }];
    adapter
        .modify_entry(&txn_id, "cn=newuser,dc=example,dc=org", &modifications)
        .await
        .unwrap();

    // Test delete_entry
    let txn_id = adapter.begin_transaction().await.unwrap();
    adapter
        .delete_entry(&txn_id, "cn=newuser,dc=example,dc=org")
        .await
        .unwrap();

    let exists = adapter
        .entry_exists("cn=newuser,dc=example,dc=org")
        .await
        .unwrap();
    assert!(!exists, "Deleted entry should not exist");
}

#[tokio::test]
async fn test_compare_backend_adapter() {
    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["testuser".to_string()]);
    attributes.insert("mail".to_string(), vec!["test@example.org".to_string()]);
    attributes.insert("objectclass".to_string(), vec!["person".to_string()]);

    let backend = Arc::new(MockBackend::default());

    // Add test entry
    let entry = DirectoryEntry::new("cn=testuser,dc=example,dc=org", attributes.clone());
    backend
        .add_entry(entry, b"password".to_vec())
        .await
        .unwrap();

    let adapter = CompareBackendAdapter::new(backend.clone());

    // Test get_entry_attributes
    let entry = adapter
        .get_entry_attributes(
            "cn=testuser,dc=example,dc=org",
            &["cn".to_string(), "mail".to_string()],
        )
        .await
        .unwrap();

    assert!(entry.is_some(), "Entry should be found");
    let entry = entry.unwrap();
    assert_eq!(entry.dn, "cn=testuser,dc=example,dc=org");
    assert!(entry.attributes.contains_key("cn"));
    assert!(entry.attributes.contains_key("mail"));
    assert_eq!(entry.object_classes, vec!["person".to_string()]);

    // Test entry_exists
    let exists = adapter
        .entry_exists("cn=testuser,dc=example,dc=org")
        .await
        .unwrap();
    assert!(exists, "Entry should exist");

    let not_exists = adapter
        .entry_exists("cn=nonexistent,dc=example,dc=org")
        .await
        .unwrap();
    assert!(!not_exists, "Non-existent entry should not exist");

    // Test get_compare_stats
    let stats = adapter
        .get_compare_stats("cn=testuser,dc=example,dc=org")
        .await
        .unwrap();
    assert_eq!(stats, (0, 0), "Stats should return (0, 0) for now");
}

#[tokio::test]
async fn test_write_backend_adapter_modify_dn() {
    let backend = Arc::new(MockBackend::default());
    let adapter = WriteBackendAdapter::new(backend.clone());

    // Add test entry
    let entry_data = b"dn: cn=oldname,dc=example,dc=org\ncn: oldname\nobjectClass: person\n";
    let txn_id = adapter.begin_transaction().await.unwrap();
    adapter
        .add_entry(&txn_id, "cn=oldname,dc=example,dc=org", entry_data)
        .await
        .unwrap();

    // Test modify_dn (rename)
    let txn_id = adapter.begin_transaction().await.unwrap();
    adapter
        .modify_dn(
            &txn_id,
            "cn=oldname,dc=example,dc=org",
            "cn=newname",
            true,
            None,
        )
        .await
        .unwrap();

    // Verify old entry doesn't exist
    let old_exists = adapter
        .entry_exists("cn=oldname,dc=example,dc=org")
        .await
        .unwrap();
    assert!(!old_exists, "Old entry should not exist after rename");

    // Verify new entry exists
    let new_exists = adapter
        .entry_exists("cn=newname,dc=example,dc=org")
        .await
        .unwrap();
    assert!(new_exists, "New entry should exist after rename");
}

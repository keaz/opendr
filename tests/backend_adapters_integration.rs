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
    let entry_data = b"dn: cn=newuser,dc=example,dc=org\ncn: newuser\nsn: User\nobjectClass: person\nuserPassword: password\n";
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

    // Staged mutation should not be visible before commit.
    let exists = adapter
        .entry_exists("cn=newuser,dc=example,dc=org")
        .await
        .unwrap();
    assert!(!exists, "Staged add should not exist before commit");
    adapter.commit_transaction(&txn_id).await.unwrap();

    let exists = adapter
        .entry_exists("cn=newuser,dc=example,dc=org")
        .await
        .unwrap();
    assert!(exists, "Committed add should exist");
    assert!(
        backend
            .authenticate("cn=newuser,dc=example,dc=org", b"password")
            .await
            .unwrap()
    );

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
    let staged = backend
        .get_entry("cn=newuser,dc=example,dc=org")
        .await
        .unwrap()
        .unwrap();
    assert!(
        !staged.attributes.contains_key("mail"),
        "Staged modify should not be visible before commit"
    );
    adapter.commit_transaction(&txn_id).await.unwrap();

    let modified = backend
        .get_entry("cn=newuser,dc=example,dc=org")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        modified.attributes.get("mail"),
        Some(&vec!["newuser@example.org".to_string()])
    );

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
    assert!(exists, "Staged delete should not be visible before commit");
    adapter.commit_transaction(&txn_id).await.unwrap();

    let exists = adapter
        .entry_exists("cn=newuser,dc=example,dc=org")
        .await
        .unwrap();
    assert!(!exists, "Deleted entry should not exist");
}

#[tokio::test]
async fn test_write_backend_adapter_rejects_server_managed_operational_attrs() {
    let backend = Arc::new(MockBackend::default());
    let adapter = WriteBackendAdapter::new(backend.clone());
    let dn = "cn=protected,dc=example,dc=org";

    let txn_id = adapter.begin_transaction().await.unwrap();
    let add_result = adapter
        .add_entry(
            &txn_id,
            dn,
            b"dn: cn=protected,dc=example,dc=org\ncn: protected\nobjectClass: person\nlastSuccessfulLogin: 20260413000000Z\n",
        )
        .await;
    assert!(
        add_result
            .unwrap_err()
            .contains("lastsuccessfullogin is server-managed")
    );
    adapter
        .rollback_transaction(&txn_id, "rejected operational attribute")
        .await
        .unwrap();

    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["protected".to_string()]);
    attributes.insert("objectclass".to_string(), vec!["person".to_string()]);
    backend
        .add_entry(DirectoryEntry::new(dn, attributes), b"password".to_vec())
        .await
        .unwrap();

    let txn_id = adapter.begin_transaction().await.unwrap();
    let modifications = vec![Modification::Replace {
        name: "failedLoginCount".to_string(),
        values: vec!["9".to_string()],
    }];
    let modify_result = adapter.modify_entry(&txn_id, dn, &modifications).await;
    assert!(
        modify_result
            .unwrap_err()
            .contains("failedLoginCount is server-managed")
    );
    adapter
        .rollback_transaction(&txn_id, "rejected operational attribute")
        .await
        .unwrap();
}

#[tokio::test]
async fn test_write_backend_adapter_rollback_discards_staged_add() {
    let backend = Arc::new(MockBackend::default());
    let adapter = WriteBackendAdapter::new(backend.clone());
    let entry_data = b"dn: cn=rolledback,dc=example,dc=org\ncn: rolledback\nobjectClass: person\n";

    let txn_id = adapter.begin_transaction().await.unwrap();
    adapter
        .add_entry(&txn_id, "cn=rolledback,dc=example,dc=org", entry_data)
        .await
        .unwrap();
    adapter
        .rollback_transaction(&txn_id, "discard staged add")
        .await
        .unwrap();

    let exists = adapter
        .entry_exists("cn=rolledback,dc=example,dc=org")
        .await
        .unwrap();
    assert!(!exists, "Rolled back staged add should not exist");
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
    adapter.commit_transaction(&txn_id).await.unwrap();

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
    adapter.commit_transaction(&txn_id).await.unwrap();

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

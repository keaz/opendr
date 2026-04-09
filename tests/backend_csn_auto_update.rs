//! Integration tests for automatic CSN updates in backend operations
//!
//! These tests verify that CSN (Change Sequence Number) and operational attributes
//! are automatically generated and updated for all write operations (add, modify, delete, rename).

use opendr::backend::{
    DirectoryBackend, DirectoryEntry, MockBackend, Modification, ModifyOperation,
};
use opendr::backend_lmdb::LmdbBackend;
use std::collections::HashMap;
use tempfile::TempDir;

#[tokio::test]
async fn test_add_entry_generates_csn_mock() {
    let backend = MockBackend::with_replica_id(1);

    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["John Doe".to_string()]);
    attributes.insert("objectclass".to_string(), vec!["person".to_string()]);

    let entry = DirectoryEntry::new("cn=jdoe,dc=example,dc=org", attributes);

    backend
        .add_entry(entry, b"password".to_vec())
        .await
        .unwrap();

    // Verify entry has entryCSN
    let stored = backend
        .get_entry("cn=jdoe,dc=example,dc=org")
        .await
        .unwrap()
        .unwrap();
    assert!(
        stored.operational_attributes.entry_csn.is_some(),
        "entryCSN should be set"
    );
    assert!(
        stored.operational_attributes.create_timestamp.is_some(),
        "createTimestamp should be set"
    );
    assert!(
        stored.operational_attributes.modify_timestamp.is_some(),
        "modifyTimestamp should be set"
    );

    // Verify contextCSN was updated
    let context_csn = backend.get_context_csn().await.unwrap();
    assert!(context_csn.is_some(), "contextCSN should be set after add");
}

#[tokio::test]
async fn test_add_entry_generates_csn_lmdb() {
    let dir = TempDir::new().unwrap();
    let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["John Doe".to_string()]);
    attributes.insert("objectclass".to_string(), vec!["person".to_string()]);

    let entry = DirectoryEntry::new("cn=jdoe,dc=example,dc=org", attributes);

    backend
        .add_entry(entry, b"password".to_vec())
        .await
        .unwrap();

    // Verify entry has entryCSN
    let stored = backend
        .get_entry("cn=jdoe,dc=example,dc=org")
        .await
        .unwrap()
        .unwrap();
    assert!(
        stored.operational_attributes.entry_csn.is_some(),
        "entryCSN should be set"
    );
    assert!(
        stored.operational_attributes.create_timestamp.is_some(),
        "createTimestamp should be set"
    );
    assert!(
        stored.operational_attributes.modify_timestamp.is_some(),
        "modifyTimestamp should be set"
    );

    // Verify contextCSN was updated
    let context_csn = backend.get_context_csn().await.unwrap();
    assert!(context_csn.is_some(), "contextCSN should be set after add");
}

#[tokio::test]
async fn test_modify_entry_updates_csn_mock() {
    let backend = MockBackend::with_replica_id(1);

    // Add initial entry
    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["John Doe".to_string()]);
    attributes.insert("mail".to_string(), vec!["john@example.org".to_string()]);

    let entry = DirectoryEntry::new("cn=jdoe,dc=example,dc=org", attributes);
    backend
        .add_entry(entry, b"password".to_vec())
        .await
        .unwrap();

    let original_entry = backend
        .get_entry("cn=jdoe,dc=example,dc=org")
        .await
        .unwrap()
        .unwrap();
    let original_csn = original_entry.operational_attributes.entry_csn.clone();
    let original_modify_time = original_entry
        .operational_attributes
        .modify_timestamp
        .clone();

    // Wait a bit to ensure timestamp changes (timestamps have 1-second granularity)
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // Modify entry
    let modifications = vec![Modification {
        operation: ModifyOperation::Replace,
        attribute: "mail".to_string(),
        values: vec!["newemail@example.org".to_string()],
    }];

    backend
        .modify_entry("cn=jdoe,dc=example,dc=org", modifications)
        .await
        .unwrap();

    // Verify entryCSN was updated
    let modified_entry = backend
        .get_entry("cn=jdoe,dc=example,dc=org")
        .await
        .unwrap()
        .unwrap();
    let modified_csn = modified_entry.operational_attributes.entry_csn.clone();
    let modified_modify_time = modified_entry
        .operational_attributes
        .modify_timestamp
        .clone();

    assert!(modified_csn.is_some(), "entryCSN should still be set");
    assert_ne!(original_csn, modified_csn, "entryCSN should have changed");
    assert_ne!(
        original_modify_time, modified_modify_time,
        "modifyTimestamp should have changed"
    );

    // Verify contextCSN was updated
    let context_csn = backend.get_context_csn().await.unwrap();
    assert!(
        context_csn.is_some(),
        "contextCSN should be updated after modify"
    );
}

#[tokio::test]
async fn test_delete_entry_updates_context_csn_mock() {
    let backend = MockBackend::with_replica_id(1);

    // Add entry
    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["John Doe".to_string()]);

    let entry = DirectoryEntry::new("cn=jdoe,dc=example,dc=org", attributes);
    backend
        .add_entry(entry, b"password".to_vec())
        .await
        .unwrap();

    let context_csn_before = backend.get_context_csn().await.unwrap();

    // Wait a bit to ensure CSN changes
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    // Delete entry
    backend
        .delete_entry("cn=jdoe,dc=example,dc=org")
        .await
        .unwrap();

    // Verify contextCSN was updated
    let context_csn_after = backend.get_context_csn().await.unwrap();
    assert!(
        context_csn_after.is_some(),
        "contextCSN should be set after delete"
    );
    assert_ne!(
        context_csn_before, context_csn_after,
        "contextCSN should have changed after delete"
    );
}

#[tokio::test]
async fn test_rename_entry_updates_csn_mock() {
    let backend = MockBackend::with_replica_id(1);

    // Add entry
    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["John Doe".to_string()]);

    let entry = DirectoryEntry::new("cn=jdoe,dc=example,dc=org", attributes);
    backend
        .add_entry(entry, b"password".to_vec())
        .await
        .unwrap();

    let original_entry = backend
        .get_entry("cn=jdoe,dc=example,dc=org")
        .await
        .unwrap()
        .unwrap();
    let original_csn = original_entry.operational_attributes.entry_csn.clone();

    // Wait a bit to ensure CSN changes
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    // Rename entry
    backend
        .rename_entry("cn=jdoe,dc=example,dc=org", "cn=johndoe", false, None)
        .await
        .unwrap();

    // Verify entryCSN was updated
    let renamed_entry = backend
        .get_entry("cn=johndoe,dc=example,dc=org")
        .await
        .unwrap()
        .unwrap();
    let renamed_csn = renamed_entry.operational_attributes.entry_csn.clone();

    assert!(
        renamed_csn.is_some(),
        "entryCSN should still be set after rename"
    );
    assert_ne!(
        original_csn, renamed_csn,
        "entryCSN should have changed after rename"
    );

    // Verify contextCSN was updated
    let context_csn = backend.get_context_csn().await.unwrap();
    assert!(
        context_csn.is_some(),
        "contextCSN should be updated after rename"
    );
}

#[tokio::test]
async fn test_csn_ordering() {
    let backend = MockBackend::with_replica_id(1);

    // Add multiple entries with small delays
    for i in 0..5 {
        let mut attributes = HashMap::new();
        attributes.insert("cn".to_string(), vec![format!("User{}", i)]);

        let entry = DirectoryEntry::new(format!("cn=user{},dc=example,dc=org", i), attributes);
        backend
            .add_entry(entry, b"password".to_vec())
            .await
            .unwrap();

        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
    }

    // Verify CSNs are in order
    let mut prev_csn = None;
    for i in 0..5 {
        let entry = backend
            .get_entry(&format!("cn=user{},dc=example,dc=org", i))
            .await
            .unwrap()
            .unwrap();
        let csn = entry.operational_attributes.entry_csn.unwrap();

        if let Some(prev) = prev_csn {
            assert!(csn > prev, "CSNs should be in ascending order");
        }
        prev_csn = Some(csn);
    }
}

#[tokio::test]
async fn test_context_csn_reflects_latest_change() {
    let backend = MockBackend::with_replica_id(1);

    // Add entry
    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["User1".to_string()]);
    let entry = DirectoryEntry::new("cn=user1,dc=example,dc=org", attributes);
    backend.add_entry(entry, Vec::new()).await.unwrap();

    let csn1 = backend.get_context_csn().await.unwrap().unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    // Add another entry
    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["User2".to_string()]);
    let entry = DirectoryEntry::new("cn=user2,dc=example,dc=org", attributes);
    backend.add_entry(entry, Vec::new()).await.unwrap();

    let csn2 = backend.get_context_csn().await.unwrap().unwrap();

    // contextCSN should reflect the latest change
    assert!(
        csn2 > csn1,
        "contextCSN should increase with each write operation"
    );
}

//! End-to-End Integration Tests - Phase 6.5
//!
//! Comprehensive E2E tests validating the entire OpenDR LDAP server with full operation cycles.

use ldap_parser::ldap::SearchScope;
use opendr::backend::{
    DirectoryBackend, DirectoryEntry, MockBackend, Modification, ModifyOperation,
};
use opendr::backend_lmdb::LmdbBackend;
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::TempDir;

/// Test 1: Full CRUD cycle with MockBackend
#[tokio::test]
async fn test_mock_backend_full_crud_cycle() {
    let backend = Arc::new(MockBackend::default());

    // Create
    let mut attrs = HashMap::new();
    attrs.insert("objectClass".to_string(), vec!["person".to_string()]);
    attrs.insert("cn".to_string(), vec!["Test User".to_string()]);
    let entry = DirectoryEntry::new("cn=Test User,dc=example,dc=com", attrs);
    backend
        .add_entry(entry, vec![])
        .await
        .expect("Failed to add");

    // Read
    let retrieved = backend
        .get_entry("cn=Test User,dc=example,dc=com")
        .await
        .unwrap();
    assert!(retrieved.is_some());

    // Update
    let modifications = vec![Modification {
        operation: ModifyOperation::Add,
        attribute: "description".to_string(),
        values: vec!["Test description".to_string()],
    }];
    backend
        .modify_entry("cn=Test User,dc=example,dc=com", modifications)
        .await
        .expect("Failed to modify");

    // Delete
    backend
        .delete_entry("cn=Test User,dc=example,dc=com")
        .await
        .expect("Failed to delete");
    let after_delete = backend
        .get_entry("cn=Test User,dc=example,dc=com")
        .await
        .unwrap();
    assert!(after_delete.is_none());
}

/// Test 2: Full CRUD cycle with LmdbBackend
#[tokio::test]
async fn test_lmdb_backend_full_crud_cycle() {
    let temp_dir = TempDir::new().unwrap();
    let backend = Arc::new(LmdbBackend::new(temp_dir.path(), 10, 1).unwrap());

    // Create
    let mut attrs = HashMap::new();
    attrs.insert("objectClass".to_string(), vec!["person".to_string()]);
    attrs.insert("cn".to_string(), vec!["LMDB User".to_string()]);
    let entry = DirectoryEntry::new("cn=LMDB User,dc=test,dc=com", attrs);
    backend
        .add_entry(entry, vec![])
        .await
        .expect("Failed to add");

    // Read
    let retrieved = backend
        .get_entry("cn=LMDB User,dc=test,dc=com")
        .await
        .unwrap();
    assert!(retrieved.is_some());

    // Update
    let modifications = vec![Modification {
        operation: ModifyOperation::Replace,
        attribute: "cn".to_string(),
        values: vec!["Modified User".to_string()],
    }];
    backend
        .modify_entry("cn=LMDB User,dc=test,dc=com", modifications)
        .await
        .expect("Failed to modify");

    // Delete
    backend
        .delete_entry("cn=LMDB User,dc=test,dc=com")
        .await
        .expect("Failed to delete");
    let after_delete = backend
        .get_entry("cn=LMDB User,dc=test,dc=com")
        .await
        .unwrap();
    assert!(after_delete.is_none());
}

/// Test 3: Concurrent add operations
#[tokio::test]
async fn test_concurrent_operations() {
    let backend = Arc::new(MockBackend::default());

    // Spawn 20 concurrent add operations
    let mut handles = vec![];
    for i in 0..20 {
        let backend_clone = backend.clone();
        let handle = tokio::spawn(async move {
            let dn = format!("cn=User{},dc=example,dc=com", i);
            let mut attrs = HashMap::new();
            attrs.insert("objectClass".to_string(), vec!["person".to_string()]);
            attrs.insert("cn".to_string(), vec![format!("User{}", i)]);
            let entry = DirectoryEntry::new(dn, attrs);
            backend_clone.add_entry(entry, vec![]).await
        });
        handles.push(handle);
    }

    // Wait for all
    for handle in handles {
        assert!(handle.await.is_ok());
    }

    // Verify all entries were added
    let results = backend
        .search_entries("dc=example,dc=com", SearchScope::WholeSubtree)
        .await;
    assert_eq!(results.unwrap().len(), 20);
}

/// Test 4: Concurrent search operations
#[tokio::test]
async fn test_concurrent_searches() {
    let backend = Arc::new(MockBackend::default());

    // Add 50 entries
    for i in 0..50 {
        let dn = format!("cn=SearchUser{},dc=example,dc=com", i);
        let mut attrs = HashMap::new();
        attrs.insert("objectClass".to_string(), vec!["person".to_string()]);
        let entry = DirectoryEntry::new(dn, attrs);
        backend.add_entry(entry, vec![]).await.ok();
    }

    // Perform 30 concurrent searches
    let mut handles = vec![];
    for _ in 0..30 {
        let backend_clone = backend.clone();
        let handle = tokio::spawn(async move {
            backend_clone
                .search_entries("dc=example,dc=com", SearchScope::WholeSubtree)
                .await
        });
        handles.push(handle);
    }

    // Verify all searches succeed
    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 50);
    }
}

/// Test 5: Error - duplicate entry
#[tokio::test]
async fn test_error_duplicate_entry() {
    let backend = Arc::new(MockBackend::default());

    let mut attrs = HashMap::new();
    attrs.insert("objectClass".to_string(), vec!["person".to_string()]);
    let entry = DirectoryEntry::new("cn=Duplicate,dc=example,dc=com", attrs.clone());
    backend
        .add_entry(entry, vec![])
        .await
        .expect("First add should succeed");

    // Try adding again
    let entry2 = DirectoryEntry::new("cn=Duplicate,dc=example,dc=com", attrs);
    let result = backend.add_entry(entry2, vec![]).await;
    assert!(result.is_err());
}

/// Test 6: Error - nonexistent entry
#[tokio::test]
async fn test_error_nonexistent_entry() {
    let backend = Arc::new(MockBackend::default());

    // Try to modify
    let modifications = vec![Modification {
        operation: ModifyOperation::Replace,
        attribute: "mail".to_string(),
        values: vec!["test@example.com".to_string()],
    }];
    let result = backend
        .modify_entry("cn=NonExistent,dc=example,dc=com", modifications)
        .await;
    assert!(result.is_err());

    // Try to delete
    let result = backend
        .delete_entry("cn=NonExistent,dc=example,dc=com")
        .await;
    assert!(result.is_err());
}

/// Test 7: Large result sets
#[tokio::test]
async fn test_large_result_sets() {
    let backend = Arc::new(MockBackend::default());

    // Add 500 entries
    for i in 0..500 {
        let dn = format!("cn=LargeUser{},dc=example,dc=com", i);
        let mut attrs = HashMap::new();
        attrs.insert("objectClass".to_string(), vec!["person".to_string()]);
        let entry = DirectoryEntry::new(dn, attrs);
        backend.add_entry(entry, vec![]).await.ok();
    }

    // Search and verify count
    let results = backend
        .search_entries("dc=example,dc=com", SearchScope::WholeSubtree)
        .await;
    assert_eq!(results.unwrap().len(), 500);
}

/// Test 8: Multiple modifications
#[tokio::test]
async fn test_multiple_modifications() {
    let backend = Arc::new(MockBackend::default());

    // Create entry
    let mut attrs = HashMap::new();
    attrs.insert("objectClass".to_string(), vec!["person".to_string()]);
    attrs.insert("cn".to_string(), vec!["Modify Test".to_string()]);
    attrs.insert("mail".to_string(), vec!["old@example.com".to_string()]);
    let entry = DirectoryEntry::new("cn=Modify Test,dc=example,dc=com", attrs);
    backend
        .add_entry(entry, vec![])
        .await
        .expect("Failed to add");

    // Apply multiple modifications
    let modifications = vec![
        Modification {
            operation: ModifyOperation::Replace,
            attribute: "mail".to_string(),
            values: vec!["new@example.com".to_string()],
        },
        Modification {
            operation: ModifyOperation::Add,
            attribute: "description".to_string(),
            values: vec!["Modified entry".to_string()],
        },
    ];
    backend
        .modify_entry("cn=Modify Test,dc=example,dc=com", modifications)
        .await
        .expect("Failed to modify");

    // Verify
    let entry = backend
        .get_entry("cn=Modify Test,dc=example,dc=com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(entry.attributes.get("mail").unwrap()[0], "new@example.com");
    assert_eq!(
        entry.attributes.get("description").unwrap()[0],
        "Modified entry"
    );
}

/// Test 9: Rename operations
#[tokio::test]
async fn test_rename_entry() {
    let backend = Arc::new(MockBackend::default());

    // Create entry
    let mut attrs = HashMap::new();
    attrs.insert("objectClass".to_string(), vec!["person".to_string()]);
    attrs.insert("cn".to_string(), vec!["OldName".to_string()]);
    let entry = DirectoryEntry::new("cn=OldName,dc=example,dc=com", attrs);
    backend
        .add_entry(entry, vec![])
        .await
        .expect("Failed to add");

    // Rename
    backend
        .rename_entry("cn=OldName,dc=example,dc=com", "cn=NewName", true, None)
        .await
        .expect("Failed to rename");

    // Verify old DN doesn't exist
    assert!(
        backend
            .get_entry("cn=OldName,dc=example,dc=com")
            .await
            .unwrap()
            .is_none()
    );

    // Verify new DN exists
    assert!(
        backend
            .get_entry("cn=NewName,dc=example,dc=com")
            .await
            .unwrap()
            .is_some()
    );
}

/// Test 10: Compare operations
#[tokio::test]
async fn test_compare_operations() {
    let backend = Arc::new(MockBackend::default());

    // Create entry
    let mut attrs = HashMap::new();
    attrs.insert("objectClass".to_string(), vec!["person".to_string()]);
    attrs.insert("cn".to_string(), vec!["Compare Test".to_string()]);
    attrs.insert("sn".to_string(), vec!["TestSurname".to_string()]);
    let entry = DirectoryEntry::new("cn=Compare Test,dc=example,dc=com", attrs);
    backend
        .add_entry(entry, vec![])
        .await
        .expect("Failed to add");

    // Compare with correct value
    let result = backend
        .compare_attribute("cn=Compare Test,dc=example,dc=com", "sn", "TestSurname")
        .await;
    assert!(result.is_ok());
    assert!(result.unwrap());

    // Compare with incorrect value
    let result = backend
        .compare_attribute("cn=Compare Test,dc=example,dc=com", "sn", "WrongValue")
        .await;
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

//! Comprehensive integration tests for LMDB backend
//!
//! This test suite verifies the LMDB backend implementation with focus on:
//! - Read performance and optimization
//! - ACID transaction properties
//! - Concurrent access patterns
//! - Index utilization
//! - Data persistence

use base64::Engine;
use ldap_parser::ldap::SearchScope;
use opendr::backend::{DirectoryBackend, DirectoryEntry, Modification, ModifyOperation};
use opendr::backend_lmdb::{IndexConfig, LmdbBackend};
use sha2::{Digest, Sha512};
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::tempdir;

fn ssha512_hash(password: &str) -> String {
    let salt = [0x5Au8; 16];
    let mut hasher = Sha512::new();
    hasher.update(password.as_bytes());
    hasher.update(salt);
    let hash = hasher.finalize();

    let mut combined = Vec::with_capacity(64 + salt.len());
    combined.extend_from_slice(&hash);
    combined.extend_from_slice(&salt);

    format!(
        "{{SSHA512}}{}",
        base64::engine::general_purpose::STANDARD.encode(combined)
    )
}

#[tokio::test]
async fn test_lmdb_basic_crud() {
    let dir = tempdir().unwrap();
    let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

    // Create
    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["John Doe".to_string()]);
    attributes.insert("mail".to_string(), vec!["john@example.org".to_string()]);
    attributes.insert("objectclass".to_string(), vec!["person".to_string()]);

    let entry = DirectoryEntry::new(
        "cn=John Doe,ou=people,dc=example,dc=org",
        attributes.clone(),
    );
    backend.add_entry(entry, b"secret".to_vec()).await.unwrap();

    // Read
    let retrieved = backend
        .get_entry("cn=John Doe,ou=people,dc=example,dc=org")
        .await
        .unwrap();
    assert!(retrieved.is_some());
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.dn, "cn=John Doe,ou=people,dc=example,dc=org");
    assert_eq!(
        retrieved.attributes.get("cn").unwrap(),
        &vec!["John Doe".to_string()]
    );

    // Update
    let modifications = vec![Modification {
        operation: ModifyOperation::Add,
        attribute: "telephoneNumber".to_string(),
        values: vec!["+1-555-1234".to_string()],
    }];
    backend
        .modify_entry("cn=John Doe,ou=people,dc=example,dc=org", modifications)
        .await
        .unwrap();

    let updated = backend
        .get_entry("cn=John Doe,ou=people,dc=example,dc=org")
        .await
        .unwrap()
        .unwrap();
    assert!(updated.attributes.contains_key("telephonenumber")); // normalized

    // Delete
    backend
        .delete_entry("cn=John Doe,ou=people,dc=example,dc=org")
        .await
        .unwrap();
    let deleted = backend
        .get_entry("cn=John Doe,ou=people,dc=example,dc=org")
        .await
        .unwrap();
    assert!(deleted.is_none());
}

#[tokio::test]
async fn test_lmdb_case_insensitive_operations() {
    let dir = tempdir().unwrap();
    let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["Test User".to_string()]);

    let entry = DirectoryEntry::new("cn=Test User,dc=example,dc=org", attributes);
    backend
        .add_entry(entry, b"password".to_vec())
        .await
        .unwrap();

    // Test various case variations
    let variations = vec![
        "cn=Test User,dc=example,dc=org",
        "CN=Test User,DC=EXAMPLE,DC=ORG",
        "cn=test user,dc=example,dc=org",
        "Cn=Test User,Dc=Example,Dc=Org",
    ];

    for dn in variations {
        let result = backend.get_entry(dn).await.unwrap();
        assert!(result.is_some(), "Failed to find entry with DN: {}", dn);

        let auth = backend.authenticate(dn, b"password").await.unwrap();
        assert!(auth, "Failed to authenticate with DN: {}", dn);
    }
}

#[tokio::test]
async fn test_lmdb_persistence() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().to_path_buf();

    // Create backend and add entry
    {
        let backend = LmdbBackend::new(&db_path, 100, 1).unwrap();

        let mut attributes = HashMap::new();
        attributes.insert("cn".to_string(), vec!["persistent".to_string()]);

        let entry = DirectoryEntry::new("cn=persistent,dc=example,dc=org", attributes);
        backend
            .add_entry(entry, b"password".to_vec())
            .await
            .unwrap();
    }

    // Reopen backend and verify data persists
    {
        let backend = LmdbBackend::new(&db_path, 100, 1).unwrap();

        let retrieved = backend
            .get_entry("cn=persistent,dc=example,dc=org")
            .await
            .unwrap();
        assert!(
            retrieved.is_some(),
            "Data should persist after backend restart"
        );

        let auth = backend
            .authenticate("cn=persistent,dc=example,dc=org", b"password")
            .await
            .unwrap();
        assert!(auth, "Authentication should work after backend restart");
    }
}

#[tokio::test]
async fn test_lmdb_concurrent_reads() {
    let dir = tempdir().unwrap();
    let backend = Arc::new(LmdbBackend::new(dir.path(), 100, 1).unwrap());

    // Add test entries
    for i in 0..100 {
        let mut attributes = HashMap::new();
        attributes.insert("cn".to_string(), vec![format!("user{}", i)]);

        let entry = DirectoryEntry::new(format!("cn=user{},dc=example,dc=org", i), attributes);
        backend
            .add_entry(entry, format!("pass{}", i).as_bytes().to_vec())
            .await
            .unwrap();
    }

    // Spawn concurrent read tasks
    let mut handles = vec![];
    for i in 0..50 {
        let backend_clone = backend.clone();
        let handle = tokio::spawn(async move {
            let dn = format!("cn=user{},dc=example,dc=org", i % 100);
            let entry = backend_clone.get_entry(&dn).await.unwrap();
            assert!(entry.is_some());
        });
        handles.push(handle);
    }

    // Wait for all tasks
    for handle in handles {
        handle.await.unwrap();
    }
}

#[tokio::test]
async fn test_lmdb_entry_cache_hits_and_invalidation() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().to_path_buf();

    {
        let backend = LmdbBackend::new(&db_path, 100, 1).unwrap();
        let mut attributes = HashMap::new();
        attributes.insert("cn".to_string(), vec!["Cache User".to_string()]);
        attributes.insert("mail".to_string(), vec!["cache@example.org".to_string()]);
        let entry = DirectoryEntry::new("uid=cache,dc=example,dc=org", attributes);
        backend
            .add_entry(entry, b"password".to_vec())
            .await
            .unwrap();
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

    assert_eq!(backend.configured_entry_cache_capacity(), 2);
    assert_eq!(backend.entry_cache_stats().len, 0);

    backend
        .get_entry("uid=cache,dc=example,dc=org")
        .await
        .unwrap()
        .unwrap();
    let after_first_read = backend.entry_cache_stats();
    assert_eq!(after_first_read.hits, 0);
    assert_eq!(after_first_read.misses, 1);
    assert_eq!(after_first_read.len, 1);

    backend
        .compare_attribute("uid=cache,dc=example,dc=org", "mail", "cache@example.org")
        .await
        .unwrap();
    let after_compare = backend.entry_cache_stats();
    assert_eq!(after_compare.hits, 1);
    assert_eq!(after_compare.misses, 1);

    backend
        .modify_entry(
            "uid=cache,dc=example,dc=org",
            vec![Modification {
                operation: ModifyOperation::Replace,
                attribute: "mail".to_string(),
                values: vec!["updated@example.org".to_string()],
            }],
        )
        .await
        .unwrap();

    let updated = backend
        .get_entry("uid=cache,dc=example,dc=org")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        updated.attributes.get("mail").unwrap(),
        &vec!["updated@example.org".to_string()]
    );

    backend
        .delete_entry("uid=cache,dc=example,dc=org")
        .await
        .unwrap();
    let deleted = backend
        .get_entry("uid=cache,dc=example,dc=org")
        .await
        .unwrap();
    assert!(deleted.is_none());

    let final_stats = backend.entry_cache_stats();
    assert_eq!(final_stats.hits, 2);
    assert_eq!(final_stats.misses, 3);
    assert_eq!(final_stats.len, 0);
}

#[tokio::test]
async fn test_lmdb_search_operations() {
    let dir = tempdir().unwrap();
    let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

    // Add hierarchical entries
    for i in 0..10 {
        let mut attributes = HashMap::new();
        attributes.insert("cn".to_string(), vec![format!("person{}", i)]);

        let entry = DirectoryEntry::new(
            format!("cn=person{},ou=people,dc=example,dc=org", i),
            attributes,
        );
        backend
            .add_entry(entry, b"password".to_vec())
            .await
            .unwrap();
    }

    // Test subtree scope - this should work
    let subtree_results = backend
        .search_entries("dc=example,dc=org", SearchScope(2))
        .await
        .unwrap();
    assert_eq!(
        subtree_results.len(),
        10,
        "Subtree should find exactly 10 entries"
    );

    // Test with more specific base
    let subtree_results2 = backend
        .search_entries("ou=people,dc=example,dc=org", SearchScope(2))
        .await
        .unwrap();
    assert_eq!(
        subtree_results2.len(),
        10,
        "Subtree under ou=people should find 10 entries"
    );
}

#[tokio::test]
async fn test_lmdb_modify_operations() {
    let dir = tempdir().unwrap();
    let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["Test".to_string()]);
    attributes.insert("mail".to_string(), vec!["old@example.org".to_string()]);

    let entry = DirectoryEntry::new("cn=Test,dc=example,dc=org", attributes);
    backend
        .add_entry(entry, b"password".to_vec())
        .await
        .unwrap();

    // Test Add operation
    backend
        .modify_entry(
            "cn=Test,dc=example,dc=org",
            vec![Modification {
                operation: ModifyOperation::Add,
                attribute: "mail".to_string(),
                values: vec!["new@example.org".to_string()],
            }],
        )
        .await
        .unwrap();

    let result = backend
        .get_entry("cn=Test,dc=example,dc=org")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result.attributes.get("mail").unwrap().len(), 2);

    // Test Replace operation
    backend
        .modify_entry(
            "cn=Test,dc=example,dc=org",
            vec![Modification {
                operation: ModifyOperation::Replace,
                attribute: "mail".to_string(),
                values: vec!["replaced@example.org".to_string()],
            }],
        )
        .await
        .unwrap();

    let result = backend
        .get_entry("cn=Test,dc=example,dc=org")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        result.attributes.get("mail").unwrap(),
        &vec!["replaced@example.org".to_string()]
    );

    // Test Delete operation
    backend
        .modify_entry(
            "cn=Test,dc=example,dc=org",
            vec![Modification {
                operation: ModifyOperation::Delete,
                attribute: "mail".to_string(),
                values: vec![],
            }],
        )
        .await
        .unwrap();

    let result = backend
        .get_entry("cn=Test,dc=example,dc=org")
        .await
        .unwrap()
        .unwrap();
    assert!(!result.attributes.contains_key("mail"));
}

#[tokio::test]
async fn test_lmdb_rename_operations() {
    let dir = tempdir().unwrap();
    let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["oldname".to_string()]);
    attributes.insert("sn".to_string(), vec!["Doe".to_string()]);

    let entry = DirectoryEntry::new("cn=oldname,dc=example,dc=org", attributes);
    backend
        .add_entry(entry, b"password".to_vec())
        .await
        .unwrap();

    // Rename entry
    backend
        .rename_entry("cn=oldname,dc=example,dc=org", "cn=newname", true, None)
        .await
        .unwrap();

    // Verify old entry doesn't exist
    let old_entry = backend
        .get_entry("cn=oldname,dc=example,dc=org")
        .await
        .unwrap();
    assert!(old_entry.is_none());

    // Verify new entry exists
    let new_entry = backend
        .get_entry("cn=newname,dc=example,dc=org")
        .await
        .unwrap();
    assert!(new_entry.is_some());

    // Verify authentication works with new DN
    let auth = backend
        .authenticate("cn=newname,dc=example,dc=org", b"password")
        .await
        .unwrap();
    assert!(auth);
}

#[tokio::test]
async fn test_lmdb_modify_userpassword_updates_authentication() {
    let dir = tempdir().unwrap();
    let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["password-user".to_string()]);
    attributes.insert("sn".to_string(), vec!["User".to_string()]);
    attributes.insert(
        "userPassword".to_string(),
        vec!["initial-secret".to_string()],
    );

    let entry = DirectoryEntry::new("cn=password-user,dc=example,dc=org", attributes);
    backend
        .add_entry(entry, b"initial-secret".to_vec())
        .await
        .unwrap();

    backend
        .modify_entry(
            "cn=password-user,dc=example,dc=org",
            vec![Modification {
                operation: ModifyOperation::Replace,
                attribute: "userPassword".to_string(),
                values: vec!["rotated-secret".to_string()],
            }],
        )
        .await
        .unwrap();

    assert!(!backend
        .authenticate("cn=password-user,dc=example,dc=org", b"initial-secret")
        .await
        .unwrap());
    assert!(backend
        .authenticate("cn=password-user,dc=example,dc=org", b"rotated-secret")
        .await
        .unwrap());
}

#[tokio::test]
async fn test_lmdb_add_entry_preserves_prehashed_userpassword() {
    let dir = tempdir().unwrap();
    let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();
    let hashed_password = ssha512_hash("prehashed-secret");

    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["hash-user".to_string()]);
    attributes.insert("sn".to_string(), vec!["User".to_string()]);
    attributes.insert("userPassword".to_string(), vec![hashed_password.clone()]);

    let entry = DirectoryEntry::new("cn=hash-user,dc=example,dc=org", attributes);
    backend
        .add_entry(entry, hashed_password.as_bytes().to_vec())
        .await
        .unwrap();

    assert!(backend
        .authenticate("cn=hash-user,dc=example,dc=org", b"prehashed-secret")
        .await
        .unwrap());
}

#[tokio::test]
async fn test_lmdb_compare_operations() {
    let dir = tempdir().unwrap();
    let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["Test".to_string()]);
    attributes.insert("mail".to_string(), vec!["test@example.org".to_string()]);

    let entry = DirectoryEntry::new("cn=Test,dc=example,dc=org", attributes);
    backend
        .add_entry(entry, b"password".to_vec())
        .await
        .unwrap();

    // Test compare matches
    let result = backend
        .compare_attribute("cn=Test,dc=example,dc=org", "mail", "test@example.org")
        .await
        .unwrap();
    assert!(result, "Compare should match existing value");

    // Test compare doesn't match
    let result = backend
        .compare_attribute("cn=Test,dc=example,dc=org", "mail", "wrong@example.org")
        .await
        .unwrap();
    assert!(!result, "Compare should not match wrong value");

    // Test compare non-existent attribute
    let result = backend
        .compare_attribute("cn=Test,dc=example,dc=org", "telephonenumber", "123")
        .await
        .unwrap();
    assert!(
        !result,
        "Compare should return false for non-existent attribute"
    );
}

#[tokio::test]
async fn test_lmdb_duplicate_prevention() {
    let dir = tempdir().unwrap();
    let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["duplicate".to_string()]);

    let entry1 = DirectoryEntry::new("cn=duplicate,dc=example,dc=org", attributes.clone());
    backend
        .add_entry(entry1, b"password".to_vec())
        .await
        .unwrap();

    // Try to add duplicate
    let entry2 = DirectoryEntry::new("cn=duplicate,dc=example,dc=org", attributes);
    let result = backend.add_entry(entry2, b"password".to_vec()).await;

    assert!(result.is_err(), "Should not allow duplicate entries");
}

#[tokio::test]
async fn test_lmdb_error_handling() {
    let dir = tempdir().unwrap();
    let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

    // Test delete non-existent entry
    let result = backend
        .delete_entry("cn=nonexistent,dc=example,dc=org")
        .await;
    assert!(
        result.is_err(),
        "Should error on deleting non-existent entry"
    );

    // Test modify non-existent entry
    let result = backend
        .modify_entry("cn=nonexistent,dc=example,dc=org", vec![])
        .await;
    assert!(
        result.is_err(),
        "Should error on modifying non-existent entry"
    );

    // Test compare on non-existent entry
    let result = backend
        .compare_attribute("cn=nonexistent,dc=example,dc=org", "cn", "test")
        .await;
    assert!(
        result.is_err(),
        "Should error on comparing non-existent entry"
    );
}

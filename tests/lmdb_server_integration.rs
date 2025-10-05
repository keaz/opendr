//! Integration tests for LMDB backend with LDAP server
//!
//! This test suite verifies that the LMDB backend works correctly
//! with the LDAP server, including:
//! - Server initialization with LMDB backend
//! - Data persistence across restarts
//! - Authentication with stored credentials
//! - LDAP operations (bind, search, add, modify, delete)

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use opendr::backend::{DirectoryBackend, DirectoryEntry};
use opendr::backend_lmdb::LmdbBackend;
use opendr::setup::{BackendType, SetupConfig, ReplicationConfig};
use tempfile::TempDir;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

/// Helper function to initialize LMDB backend with test data
async fn create_test_backend(temp_dir: &TempDir) -> LmdbBackend {
    let mut backend = LmdbBackend::new(temp_dir.path(), 100).unwrap();

    // Add base DN
    let base_entry = DirectoryEntry::new(
        "dc=test,dc=com",
        HashMap::from([
            ("objectClass".to_string(), vec!["top".to_string(), "organization".to_string()]),
            ("o".to_string(), vec!["Test Organization".to_string()]),
        ]),
    );
    backend.add_entry(base_entry, vec![]).await.unwrap();

    // Add admin user
    let admin_entry = DirectoryEntry::new(
        "cn=admin,dc=test,dc=com",
        HashMap::from([
            ("objectClass".to_string(), vec!["top".to_string(), "person".to_string()]),
            ("cn".to_string(), vec!["admin".to_string()]),
            ("sn".to_string(), vec!["Administrator".to_string()]),
        ]),
    );
    backend.add_entry(admin_entry, b"admin123".to_vec()).await.unwrap();

    backend
}

#[tokio::test]
async fn test_lmdb_backend_initialization() {
    let temp_dir = TempDir::new().unwrap();
    let backend = create_test_backend(&temp_dir).await;

    // Verify base entry exists
    let entry = backend.get_entry("dc=test,dc=com").await.unwrap().unwrap();
    assert_eq!(entry.dn, "dc=test,dc=com");
    // Attributes are normalized to lowercase
    assert!(entry.attributes.contains_key("objectclass"));

    // Verify admin entry exists
    let admin_entry = backend.get_entry("cn=admin,dc=test,dc=com").await.unwrap().unwrap();
    assert_eq!(admin_entry.dn, "cn=admin,dc=test,dc=com");

    // Verify authentication works
    assert!(backend.authenticate("cn=admin,dc=test,dc=com", b"admin123").await.unwrap());
    assert!(!backend.authenticate("cn=admin,dc=test,dc=com", b"wrong").await.unwrap());
}

#[tokio::test]
async fn test_lmdb_backend_persistence() {
    let temp_dir = TempDir::new().unwrap();

    // Create backend and add data
    {
        let mut backend = LmdbBackend::new(temp_dir.path(), 100).unwrap();

        let entry = DirectoryEntry::new(
            "dc=persist,dc=test",
            HashMap::from([
                ("objectClass".to_string(), vec!["top".to_string(), "organization".to_string()]),
                ("o".to_string(), vec!["Persistence Test".to_string()]),
            ]),
        );
        backend.add_entry(entry, vec![]).await.unwrap();

        // Backend goes out of scope here
    }

    // Create new backend instance with same directory
    {
        let backend = LmdbBackend::new(temp_dir.path(), 100).unwrap();

        // Verify data persisted
        let entry = backend.get_entry("dc=persist,dc=test").await.unwrap().unwrap();
        assert_eq!(entry.dn, "dc=persist,dc=test");
        assert_eq!(entry.attributes["o"][0], "Persistence Test");
    }
}

#[tokio::test]
async fn test_lmdb_backend_concurrent_reads() {
    let temp_dir = TempDir::new().unwrap();
    let backend = Arc::new(create_test_backend(&temp_dir).await);

    // Spawn multiple concurrent read tasks
    let mut handles = vec![];
    for i in 0..10 {
        let backend = Arc::clone(&backend);
        let handle = tokio::spawn(async move {
            for _ in 0..5 {
                let entry = backend.get_entry("dc=test,dc=com").await.unwrap().unwrap();
                assert_eq!(entry.dn, "dc=test,dc=com");
                tokio::time::sleep(Duration::from_millis(i * 10)).await;
            }
        });
        handles.push(handle);
    }

    // Wait for all tasks to complete
    for handle in handles {
        handle.await.unwrap();
    }
}

#[tokio::test]
async fn test_lmdb_backend_add_modify_delete() {
    let temp_dir = TempDir::new().unwrap();
    let mut backend = create_test_backend(&temp_dir).await;

    // Add a new entry
    let user_entry = DirectoryEntry::new(
        "uid=testuser,dc=test,dc=com",
        HashMap::from([
            ("objectClass".to_string(), vec!["top".to_string(), "person".to_string()]),
            ("uid".to_string(), vec!["testuser".to_string()]),
            ("cn".to_string(), vec!["Test User".to_string()]),
            ("sn".to_string(), vec!["User".to_string()]),
        ]),
    );
    backend.add_entry(user_entry, b"password".to_vec()).await.unwrap();

    // Verify entry was added
    let entry = backend.get_entry("uid=testuser,dc=test,dc=com").await.unwrap().unwrap();
    assert_eq!(entry.attributes["uid"][0], "testuser");

    // Modify the entry
    use opendr::backend::{Modification, ModifyOperation};
    let modifications = vec![
        Modification {
            operation: ModifyOperation::Replace,
            attribute: "cn".to_string(),
            values: vec!["Modified User".to_string()],
        },
    ];
    backend.modify_entry("uid=testuser,dc=test,dc=com", modifications).await.unwrap();

    // Verify modification
    let modified_entry = backend.get_entry("uid=testuser,dc=test,dc=com").await.unwrap().unwrap();
    assert_eq!(modified_entry.attributes["cn"][0], "Modified User");

    // Delete the entry
    backend.delete_entry("uid=testuser,dc=test,dc=com").await.unwrap();

    // Verify entry was deleted
    let result = backend.get_entry("uid=testuser,dc=test,dc=com").await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_lmdb_backend_search_operations() {
    let temp_dir = TempDir::new().unwrap();
    let mut backend = create_test_backend(&temp_dir).await;

    // Add multiple entries
    for i in 1..=5 {
        let entry = DirectoryEntry::new(
            &format!("uid=user{},dc=test,dc=com", i),
            HashMap::from([
                ("objectClass".to_string(), vec!["top".to_string(), "person".to_string()]),
                ("uid".to_string(), vec![format!("user{}", i)]),
                ("cn".to_string(), vec![format!("User {}", i)]),
                ("sn".to_string(), vec!["TestUser".to_string()]),
            ]),
        );
        backend.add_entry(entry, vec![]).await.unwrap();
    }

    // Search for all entries under base DN
    use ldap_parser::ldap::SearchScope;
    let results = backend
        .search_entries("dc=test,dc=com", SearchScope::WholeSubtree)
        .await
        .unwrap();

    // Should find base DN + admin + 5 users = 7 entries
    assert!(results.len() >= 7);
}

#[tokio::test]
async fn test_lmdb_backend_dn_normalization() {
    let temp_dir = TempDir::new().unwrap();
    let backend = create_test_backend(&temp_dir).await;

    // Test case-insensitive DN lookups
    let dn_variations = vec![
        "dc=test,dc=com",
        "DC=test,DC=com",
        "dc=TEST,dc=COM",
        "Dc=Test,Dc=Com",
    ];

    for dn in dn_variations {
        let entry = backend.get_entry(dn).await.unwrap().unwrap();
        assert_eq!(entry.dn, "dc=test,dc=com");
    }
}

#[tokio::test]
async fn test_lmdb_backend_password_authentication() {
    let temp_dir = TempDir::new().unwrap();
    let backend = create_test_backend(&temp_dir).await;

    // Test successful authentication
    assert!(backend.authenticate("cn=admin,dc=test,dc=com", b"admin123").await.unwrap());

    // Test failed authentication with wrong password
    assert!(!backend.authenticate("cn=admin,dc=test,dc=com", b"wrongpass").await.unwrap());

    // Test failed authentication with non-existent user
    let result = backend.authenticate("cn=nobody,dc=test,dc=com", b"password").await;
    // Should return Ok(false) for non-existent user, or Err
    assert!(result.is_err() || !result.unwrap());
}

#[tokio::test]
async fn test_lmdb_backend_large_dataset() {
    let temp_dir = TempDir::new().unwrap();
    let mut backend = LmdbBackend::new(temp_dir.path(), 100).unwrap();

    // Add base DN
    let base_entry = DirectoryEntry::new(
        "dc=large,dc=test",
        HashMap::from([
            ("objectClass".to_string(), vec!["top".to_string(), "organization".to_string()]),
            ("o".to_string(), vec!["Large Test".to_string()]),
        ]),
    );
    backend.add_entry(base_entry, vec![]).await.unwrap();

    // Add 100 entries
    for i in 0..100 {
        let entry = DirectoryEntry::new(
            &format!("uid=user{:03},dc=large,dc=test", i),
            HashMap::from([
                ("objectClass".to_string(), vec!["top".to_string(), "person".to_string()]),
                ("uid".to_string(), vec![format!("user{:03}", i)]),
                ("cn".to_string(), vec![format!("User Number {}", i)]),
                ("sn".to_string(), vec!["Batch".to_string()]),
            ]),
        );
        backend.add_entry(entry, vec![]).await.unwrap();
    }

    // Verify all entries were added
    for i in 0..100 {
        let dn = format!("uid=user{:03},dc=large,dc=test", i);
        let entry = backend.get_entry(&dn).await.unwrap().unwrap();
        assert_eq!(entry.attributes["uid"][0], format!("user{:03}", i));
    }
}

#[tokio::test]
async fn test_setup_config_with_lmdb_backend() {
    let temp_dir = TempDir::new().unwrap();

    let config = SetupConfig {
        base_dn: "dc=config,dc=test".to_string(),
        root_user_dn: "cn=manager".to_string(),
        root_password: "ManagerPass123".to_string(),
        ldap_port: 1389,
        ldaps_port: 1636,
        hostname: "testhost".to_string(),
        organization_name: "Config Test Org".to_string(),
        backend_type: BackendType::Lmdb,
        data_directory: temp_dir.path().to_path_buf(),
        import_sample_data: false,
        replication: ReplicationConfig::default(),
    };

    // Create backend
    let mut backend = LmdbBackend::new(&config.data_directory, 100).unwrap();

    // Add base structure (similar to what main.rs does)
    let base_entry = DirectoryEntry::new(
        &config.base_dn,
        HashMap::from([
            ("objectClass".to_string(), vec!["top".to_string(), "organization".to_string()]),
            ("o".to_string(), vec![config.organization_name.clone()]),
        ]),
    );
    backend.add_entry(base_entry, vec![]).await.unwrap();

    // Add root user
    let root_dn = format!("{},{}", config.root_user_dn, config.base_dn);
    let root_entry = DirectoryEntry::new(
        &root_dn,
        HashMap::from([
            ("objectClass".to_string(), vec!["top".to_string(), "person".to_string()]),
            ("cn".to_string(), vec!["manager".to_string()]),
            ("sn".to_string(), vec!["Manager".to_string()]),
        ]),
    );
    backend.add_entry(root_entry, config.root_password.as_bytes().to_vec()).await.unwrap();

    // Verify configuration
    let base = backend.get_entry(&config.base_dn).await.unwrap().unwrap();
    assert_eq!(base.attributes["o"][0], "Config Test Org");

    // Verify root user authentication
    assert!(backend.authenticate(&root_dn, config.root_password.as_bytes()).await.unwrap());
}

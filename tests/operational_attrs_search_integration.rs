//! Integration tests for operational attributes in search operations
//!
//! These tests verify that operational attributes (entryCSN, createTimestamp, etc.)
//! are correctly returned in search results when requested via "+" or by name.

use std::collections::HashMap;
use std::sync::Arc;
use opendr::backend::{DirectoryBackend, DirectoryEntry, BackendError, MockBackend, OperationalAttributes};
use opendr::backend_lmdb::LmdbBackend;
use opendr::backend_adapters::SearchBackendAdapter;
use opendr::search_fsm::SearchBackend;
use opendr::csn::Csn;

/// Helper to create a test entry with operational attributes
fn create_test_entry_with_op_attrs(dn: &str, cn: &str, mail: &str, replica_id: u16) -> DirectoryEntry {
    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec![cn.to_string()]);
    attributes.insert("mail".to_string(), vec![mail.to_string()]);
    attributes.insert("objectclass".to_string(), vec!["person".to_string(), "inetOrgPerson".to_string()]);

    let csn = Csn::new(replica_id);
    let op_attrs = OperationalAttributes::for_new_entry(csn, Some("cn=admin,dc=example,dc=com".to_string()));

    DirectoryEntry::with_operational_attrs(dn, attributes, op_attrs)
}

#[tokio::test]
async fn test_search_without_operational_attrs_mockbackend() {
    let backend = Arc::new(MockBackend::new());
    let entry = create_test_entry_with_op_attrs(
        "cn=john,ou=users,dc=example,dc=com",
        "John Doe",
        "john@example.com",
        1,
    );
    backend.add_entry(entry, Vec::new()).await.unwrap();

    let adapter = SearchBackendAdapter::new(backend);

    // Search without requesting operational attributes
    let requested_attrs = vec!["cn".to_string(), "mail".to_string()];
    let result = adapter.get_entry("cn=john,ou=users,dc=example,dc=com", &requested_attrs)
        .await
        .unwrap()
        .expect("Entry should exist");

    // Should only have user attributes
    assert_eq!(result.attributes.get("cn").unwrap()[0], "John Doe");
    assert_eq!(result.attributes.get("mail").unwrap()[0], "john@example.com");
    
    // Should NOT have operational attributes
    assert!(!result.attributes.contains_key("entrycsn"), "Should not contain entrycsn");
    assert!(!result.attributes.contains_key("createtimestamp"), "Should not contain createtimestamp");
    assert!(!result.attributes.contains_key("modifytimestamp"), "Should not contain modifytimestamp");
}

#[tokio::test]
async fn test_search_with_plus_all_operational_attrs_mockbackend() {
    let backend = Arc::new(MockBackend::new());
    let entry = create_test_entry_with_op_attrs(
        "cn=jane,ou=users,dc=example,dc=com",
        "Jane Smith",
        "jane@example.com",
        1,
    );
    backend.add_entry(entry, Vec::new()).await.unwrap();

    let adapter = SearchBackendAdapter::new(backend);

    // Search with "+" to request all operational attributes
    let requested_attrs = vec!["+".to_string()];
    let result = adapter.get_entry("cn=jane,ou=users,dc=example,dc=com", &requested_attrs)
        .await
        .unwrap()
        .expect("Entry should exist");

    // Should NOT have user attributes (only "+" was requested)
    assert!(!result.attributes.contains_key("cn"), "Should not contain cn when only '+' requested");
    assert!(!result.attributes.contains_key("mail"), "Should not contain mail when only '+' requested");
    
    // Should have operational attributes
    assert!(result.attributes.contains_key("entrycsn"), "Should contain entrycsn");
    assert!(result.attributes.contains_key("createtimestamp"), "Should contain createtimestamp");
    assert!(result.attributes.contains_key("modifytimestamp"), "Should contain modifytimestamp");
    // Note: creatorsname/modifiersname might not be present if backend doesn't set them
}

#[tokio::test]
async fn test_search_with_star_and_plus_mockbackend() {
    let backend = Arc::new(MockBackend::new());
    let entry = create_test_entry_with_op_attrs(
        "cn=bob,ou=users,dc=example,dc=com",
        "Bob Johnson",
        "bob@example.com",
        1,
    );
    backend.add_entry(entry, Vec::new()).await.unwrap();

    let adapter = SearchBackendAdapter::new(backend);

    // Search with "*" and "+" to request all user and operational attributes
    let requested_attrs = vec!["*".to_string(), "+".to_string()];
    let result = adapter.get_entry("cn=bob,ou=users,dc=example,dc=com", &requested_attrs)
        .await
        .unwrap()
        .expect("Entry should exist");

    // Should have user attributes
    assert_eq!(result.attributes.get("cn").unwrap()[0], "Bob Johnson");
    assert_eq!(result.attributes.get("mail").unwrap()[0], "bob@example.com");
    
    // Should have operational attributes
    assert!(result.attributes.contains_key("entrycsn"), "Should contain entrycsn");
    assert!(result.attributes.contains_key("createtimestamp"), "Should contain createtimestamp");
    assert!(result.attributes.contains_key("modifytimestamp"), "Should contain modifytimestamp");
}

#[tokio::test]
async fn test_search_specific_operational_attr_mockbackend() {
    let backend = Arc::new(MockBackend::new());
    let entry = create_test_entry_with_op_attrs(
        "cn=alice,ou=users,dc=example,dc=com",
        "Alice Brown",
        "alice@example.com",
        1,
    );
    backend.add_entry(entry, Vec::new()).await.unwrap();

    let adapter = SearchBackendAdapter::new(backend);

    // Request specific operational attribute
    let requested_attrs = vec!["entrycsn".to_string()];
    let result = adapter.get_entry("cn=alice,ou=users,dc=example,dc=com", &requested_attrs)
        .await
        .unwrap()
        .expect("Entry should exist");

    // Should NOT have user attributes
    assert!(!result.attributes.contains_key("cn"), "Should not contain cn");
    assert!(!result.attributes.contains_key("mail"), "Should not contain mail");
    
    // Should have only requested operational attribute
    assert!(result.attributes.contains_key("entrycsn"), "Should contain entrycsn");
    assert!(!result.attributes.contains_key("createtimestamp"), "Should not contain non-requested createtimestamp");
}

#[tokio::test]
async fn test_search_mixed_user_and_operational_attrs_mockbackend() {
    let backend = Arc::new(MockBackend::new());
    let entry = create_test_entry_with_op_attrs(
        "cn=charlie,ou=users,dc=example,dc=com",
        "Charlie Davis",
        "charlie@example.com",
        1,
    );
    backend.add_entry(entry, Vec::new()).await.unwrap();

    let adapter = SearchBackendAdapter::new(backend);

    // Request mix of user and operational attributes
    let requested_attrs = vec![
        "cn".to_string(),
        "entrycsn".to_string(),
        "modifytimestamp".to_string(),
    ];
    let result = adapter.get_entry("cn=charlie,ou=users,dc=example,dc=com", &requested_attrs)
        .await
        .unwrap()
        .expect("Entry should exist");

    // Should have requested user attribute
    assert_eq!(result.attributes.get("cn").unwrap()[0], "Charlie Davis");
    assert!(!result.attributes.contains_key("mail"), "Should not contain non-requested mail");
    
    // Should have requested operational attributes
    assert!(result.attributes.contains_key("entrycsn"), "Should contain entrycsn");
    assert!(result.attributes.contains_key("modifytimestamp"), "Should contain modifytimestamp");
    assert!(!result.attributes.contains_key("createtimestamp"), "Should not contain non-requested createtimestamp");
}

#[tokio::test]
async fn test_search_without_operational_attrs_lmdb() {
    let temp_dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(LmdbBackend::new(temp_dir.path().to_str().unwrap(), 100, 1).unwrap());
    
    let entry = create_test_entry_with_op_attrs(
        "cn=david,ou=users,dc=example,dc=com",
        "David Wilson",
        "david@example.com",
        1,
    );
    backend.add_entry(entry, Vec::new()).await.unwrap();

    let adapter = SearchBackendAdapter::new(backend);

    // Search without requesting operational attributes
    let requested_attrs = vec!["cn".to_string(), "mail".to_string()];
    let result = adapter.get_entry("cn=david,ou=users,dc=example,dc=com", &requested_attrs)
        .await
        .unwrap()
        .expect("Entry should exist");

    // Should only have user attributes
    assert_eq!(result.attributes.get("cn").unwrap()[0], "David Wilson");
    assert_eq!(result.attributes.get("mail").unwrap()[0], "david@example.com");
    
    // Should NOT have operational attributes
    assert!(!result.attributes.contains_key("entrycsn"), "Should not contain entrycsn");
}

#[tokio::test]
async fn test_search_with_plus_all_operational_attrs_lmdb() {
    let temp_dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(LmdbBackend::new(temp_dir.path().to_str().unwrap(), 100, 1).unwrap());
    
    let entry = create_test_entry_with_op_attrs(
        "cn=emma,ou=users,dc=example,dc=com",
        "Emma Martinez",
        "emma@example.com",
        1,
    );
    backend.add_entry(entry, Vec::new()).await.unwrap();

    let adapter = SearchBackendAdapter::new(backend);

    // Search with "+" to request all operational attributes
    let requested_attrs = vec!["+".to_string()];
    let result = adapter.get_entry("cn=emma,ou=users,dc=example,dc=com", &requested_attrs)
        .await
        .unwrap()
        .expect("Entry should exist");

    // Should have operational attributes
    assert!(result.attributes.contains_key("entrycsn"), "Should contain entrycsn");
    assert!(result.attributes.contains_key("createtimestamp"), "Should contain createtimestamp");
    
    // Verify entryCSN format
    let entry_csn = result.attributes.get("entrycsn").unwrap()[0].clone();
    assert!(entry_csn.contains('#'), "entryCSN should contain '#' separators");
}

#[tokio::test]
async fn test_search_with_star_and_plus_lmdb() {
    let temp_dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(LmdbBackend::new(temp_dir.path().to_str().unwrap(), 100, 1).unwrap());
    
    let entry = create_test_entry_with_op_attrs(
        "cn=frank,ou=users,dc=example,dc=com",
        "Frank Thompson",
        "frank@example.com",
        1,
    );
    backend.add_entry(entry, Vec::new()).await.unwrap();

    let adapter = SearchBackendAdapter::new(backend);

    // Search with "*" and "+" to request all user and operational attributes
    let requested_attrs = vec!["*".to_string(), "+".to_string()];
    let result = adapter.get_entry("cn=frank,ou=users,dc=example,dc=com", &requested_attrs)
        .await
        .unwrap()
        .expect("Entry should exist");

    // Should have both user and operational attributes
    assert_eq!(result.attributes.get("cn").unwrap()[0], "Frank Thompson");
    assert!(result.attributes.contains_key("entrycsn"), "Should contain entrycsn");
}

#[tokio::test]
async fn test_search_specific_operational_attr_lmdb() {
    let temp_dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(LmdbBackend::new(temp_dir.path().to_str().unwrap(), 100, 1).unwrap());
    
    let entry = create_test_entry_with_op_attrs(
        "cn=grace,ou=users,dc=example,dc=com",
        "Grace Lee",
        "grace@example.com",
        1,
    );
    backend.add_entry(entry, Vec::new()).await.unwrap();

    let adapter = SearchBackendAdapter::new(backend);

    // Request specific operational attributes
    let requested_attrs = vec!["entrycsn".to_string(), "createtimestamp".to_string()];
    let result = adapter.get_entry("cn=grace,ou=users,dc=example,dc=com", &requested_attrs)
        .await
        .unwrap()
        .expect("Entry should exist");

    // Should have only requested operational attributes
    assert!(result.attributes.contains_key("entrycsn"), "Should contain entrycsn");
    assert!(result.attributes.contains_key("createtimestamp"), "Should contain createtimestamp");
    assert!(!result.attributes.contains_key("modifytimestamp"), "Should not contain non-requested modifytimestamp");
}

#[tokio::test]
async fn test_search_case_insensitive_operational_attrs() {
    let backend = Arc::new(MockBackend::new());
    let entry = create_test_entry_with_op_attrs(
        "cn=henry,ou=users,dc=example,dc=com",
        "Henry Clark",
        "henry@example.com",
        1,
    );
    backend.add_entry(entry, Vec::new()).await.unwrap();

    let adapter = SearchBackendAdapter::new(backend);

    // Request operational attributes with different case
    let requested_attrs = vec![
        "ENTRYCSN".to_string(),
        "CreateTimestamp".to_string(),
    ];
    let result = adapter.get_entry("cn=henry,ou=users,dc=example,dc=com", &requested_attrs)
        .await
        .unwrap()
        .expect("Entry should exist");

    // Should recognize case-insensitive operational attribute names
    assert!(result.attributes.contains_key("entrycsn"), "Should contain entrycsn (case-insensitive)");
    assert!(result.attributes.contains_key("createtimestamp"), "Should contain createtimestamp (case-insensitive)");
}

#[tokio::test]
async fn test_search_empty_attrs_defaults_to_user_only() {
    let backend = Arc::new(MockBackend::new());
    let entry = create_test_entry_with_op_attrs(
        "cn=iris,ou=users,dc=example,dc=com",
        "Iris Taylor",
        "iris@example.com",
        1,
    );
    backend.add_entry(entry, Vec::new()).await.unwrap();

    let adapter = SearchBackendAdapter::new(backend);

    // Search with empty attributes list (default behavior)
    let requested_attrs: Vec<String> = vec![];
    let result = adapter.get_entry("cn=iris,ou=users,dc=example,dc=com", &requested_attrs)
        .await
        .unwrap()
        .expect("Entry should exist");

    // Should have user attributes
    assert!(result.attributes.contains_key("cn"), "Should contain user attributes by default");
    assert!(result.attributes.contains_key("mail"), "Should contain user attributes by default");
    
    // Should NOT have operational attributes
    assert!(!result.attributes.contains_key("entrycsn"), "Should not contain operational attrs by default");
}

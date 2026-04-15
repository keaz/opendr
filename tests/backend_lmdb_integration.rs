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
use opendr::backend::{
    DirectoryBackend, DirectoryEntry, Modification, ModifyOperation, SearchCandidateHint,
    SearchSubstringPart,
};
use opendr::backend_lmdb::{AttributeIndexConfig, IndexConfig, IndexType, LmdbBackend};
use opendr::schema::LdapSchema;
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
async fn test_lmdb_modify_increment_is_atomic() {
    let dir = tempdir().unwrap();
    let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

    backend
        .add_entry(
            DirectoryEntry::new(
                "cn=Counter,dc=example,dc=org",
                HashMap::from([
                    ("cn".to_string(), vec!["Counter".to_string()]),
                    (
                        "objectclass".to_string(),
                        vec!["extensibleObject".to_string()],
                    ),
                    ("examplecounter".to_string(), vec!["10".to_string()]),
                ]),
            ),
            Vec::new(),
        )
        .await
        .unwrap();

    backend
        .modify_entry(
            "cn=Counter,dc=example,dc=org",
            vec![Modification {
                operation: ModifyOperation::Increment,
                attribute: "exampleCounter".to_string(),
                values: vec!["5".to_string()],
            }],
        )
        .await
        .unwrap();

    let updated = backend
        .get_entry("cn=Counter,dc=example,dc=org")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        updated.attributes.get("examplecounter").unwrap(),
        &vec!["15".to_string()]
    );

    let malformed = backend
        .modify_entry(
            "cn=Counter,dc=example,dc=org",
            vec![Modification {
                operation: ModifyOperation::Increment,
                attribute: "exampleCounter".to_string(),
                values: vec!["1".to_string(), "2".to_string()],
            }],
        )
        .await;
    assert!(malformed.is_err());

    let unchanged = backend
        .get_entry("cn=Counter,dc=example,dc=org")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        unchanged.attributes.get("examplecounter").unwrap(),
        &vec!["15".to_string()]
    );
}

#[tokio::test]
async fn test_lmdb_indexes_use_schema_matching_rule_normalization() {
    let dir = tempdir().unwrap();
    let schema = LdapSchema::default();
    let backend = LmdbBackend::new_with_schema_config(
        dir.path(),
        100,
        1,
        IndexConfig {
            indexed_attributes: Vec::new(),
            attribute_indexes: vec![AttributeIndexConfig {
                attribute: "telephoneNumber".to_string(),
                index_types: vec![IndexType::Equality, IndexType::Substring],
            }],
        },
        &schema,
    )
    .unwrap();

    for (cn, telephone) in [("Alice", "+1 555-0100"), ("Bob", "+1 555-0111")] {
        let mut attributes = HashMap::new();
        attributes.insert(
            "objectClass".to_string(),
            vec!["top".to_string(), "person".to_string()],
        );
        attributes.insert("cn".to_string(), vec![cn.to_string()]);
        attributes.insert("sn".to_string(), vec![cn.to_string()]);
        attributes.insert("telephoneNumber".to_string(), vec![telephone.to_string()]);
        backend
            .add_entry(
                DirectoryEntry::new(format!("cn={cn},dc=example,dc=org"), attributes),
                vec![],
            )
            .await
            .unwrap();
    }

    let exact = backend
        .search_entries_with_hint(
            "dc=example,dc=org",
            SearchScope(2),
            Some(SearchCandidateHint::Equality {
                attribute: "telephoneNumber".to_string(),
                value: "+15550100".to_string(),
            }),
        )
        .await
        .unwrap();
    assert_eq!(exact.len(), 1);
    assert_eq!(exact[0].dn, "cn=Alice,dc=example,dc=org");

    let substring = backend
        .search_entries_with_hint(
            "dc=example,dc=org",
            SearchScope(2),
            Some(SearchCandidateHint::Substring {
                attribute: "telephoneNumber".to_string(),
                parts: vec![SearchSubstringPart::Any("5550100".to_string())],
            }),
        )
        .await
        .unwrap();
    assert_eq!(substring.len(), 1);
    assert_eq!(substring[0].dn, "cn=Alice,dc=example,dc=org");
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
    assert_eq!(final_stats.hits, 1);
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
async fn test_lmdb_rfc4514_dn_canonicalization_for_crud_search_and_compare() {
    let dir = tempdir().unwrap();
    let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

    let mut base_attrs = HashMap::new();
    base_attrs.insert("objectclass".to_string(), vec!["domain".to_string()]);
    base_attrs.insert("dc".to_string(), vec!["org".to_string()]);
    backend
        .add_entry(
            DirectoryEntry::new("dc=example,dc=org", base_attrs),
            Vec::new(),
        )
        .await
        .unwrap();

    let mut ou_attrs = HashMap::new();
    ou_attrs.insert(
        "objectclass".to_string(),
        vec!["organizationalUnit".to_string()],
    );
    ou_attrs.insert("ou".to_string(), vec!["People".to_string()]);
    backend
        .add_entry(
            DirectoryEntry::new("ou=People,dc=example,dc=org", ou_attrs),
            Vec::new(),
        )
        .await
        .unwrap();

    let mut attributes = HashMap::new();
    attributes.insert("objectclass".to_string(), vec!["person".to_string()]);
    attributes.insert("cn".to_string(), vec!["Doe, John".to_string()]);
    attributes.insert("uid".to_string(), vec!["user+1".to_string()]);
    attributes.insert("sn".to_string(), vec!["Doe".to_string()]);

    backend
        .add_entry(
            DirectoryEntry::new(
                r"cn=Doe\, John+uid=user\+1,ou=People,dc=example,dc=org",
                attributes,
            ),
            b"secret".to_vec(),
        )
        .await
        .unwrap();

    assert!(
        backend
            .add_entry(
                DirectoryEntry::new(
                    r"UID=user\2B1+CN=doe\2C john,OU=people,DC=example,DC=org",
                    HashMap::new(),
                ),
                b"duplicate".to_vec(),
            )
            .await
            .is_err(),
        "equivalent multi-valued DNs must collide"
    );

    let retrieved = backend
        .get_entry(r"UID=user\2B1+CN=doe\2C john,OU=people,DC=example,DC=org")
        .await
        .unwrap()
        .expect("canonical DN lookup should find entry");
    assert_eq!(
        retrieved.dn,
        r"cn=Doe\, John+uid=user\+1,ou=People,dc=example,dc=org"
    );

    assert!(
        backend
            .compare_attribute(
                r"cn=doe\2C john+uid=user\2B1,ou=people,dc=example,dc=org",
                "cn",
                "Doe, John"
            )
            .await
            .unwrap()
    );

    let one_level = backend
        .search_entries("ou=people,dc=example,dc=org", SearchScope(1))
        .await
        .unwrap();
    assert_eq!(one_level.len(), 1);
    assert_eq!(
        one_level[0].dn,
        r"cn=Doe\, John+uid=user\+1,ou=People,dc=example,dc=org"
    );

    let subtree = backend
        .search_entries("dc=example,dc=org", SearchScope(2))
        .await
        .unwrap();
    assert_eq!(subtree.len(), 3);

    backend
        .rename_entry(
            r"cn=doe\2C john+uid=user\2B1,ou=people,dc=example,dc=org",
            r"cn=Jane\+Doe",
            true,
            None,
        )
        .await
        .unwrap();

    assert!(
        backend
            .get_entry(r"uid=user\2B1+cn=doe\2C john,ou=people,dc=example,dc=org")
            .await
            .unwrap()
            .is_none()
    );

    let renamed = backend
        .get_entry(r"cn=jane\2Bdoe,ou=people,dc=example,dc=org")
        .await
        .unwrap()
        .expect("renamed entry should be found by canonical DN");
    assert_eq!(renamed.dn, r"cn=jane\+doe,ou=people,dc=example,dc=org");
    assert_eq!(
        renamed.attributes.get("cn").unwrap(),
        &vec!["Jane+Doe".to_string()]
    );

    backend
        .delete_entry(r"CN=JANE\2BDOE,OU=PEOPLE,DC=EXAMPLE,DC=ORG")
        .await
        .unwrap();
    assert!(
        backend
            .get_entry(r"cn=jane\+doe,ou=people,dc=example,dc=org")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn test_lmdb_modifydn_preserves_child_hierarchy_with_escaped_parent_dn() {
    let dir = tempdir().unwrap();
    let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

    let mut parent_attrs = HashMap::new();
    parent_attrs.insert("objectclass".to_string(), vec!["person".to_string()]);
    parent_attrs.insert("cn".to_string(), vec!["Parent, One".to_string()]);
    parent_attrs.insert("sn".to_string(), vec!["One".to_string()]);
    backend
        .add_entry(
            DirectoryEntry::new(r"cn=Parent\, One,dc=example,dc=org", parent_attrs),
            b"parent".to_vec(),
        )
        .await
        .unwrap();

    let mut child_attrs = HashMap::new();
    child_attrs.insert("objectclass".to_string(), vec!["person".to_string()]);
    child_attrs.insert("cn".to_string(), vec!["Child".to_string()]);
    child_attrs.insert("sn".to_string(), vec!["Child".to_string()]);
    backend
        .add_entry(
            DirectoryEntry::new(r"cn=Child,cn=Parent\, One,dc=example,dc=org", child_attrs),
            b"child".to_vec(),
        )
        .await
        .unwrap();

    backend
        .rename_entry(
            r"cn=parent\2C one,dc=example,dc=org",
            r"cn=Parent\+Two",
            true,
            None,
        )
        .await
        .unwrap();

    assert!(
        backend
            .get_entry(r"cn=child,cn=parent\2C one,dc=example,dc=org")
            .await
            .unwrap()
            .is_none()
    );

    assert!(
        backend
            .get_entry(r"cn=child,cn=parent\2Btwo,dc=example,dc=org")
            .await
            .unwrap()
            .is_some(),
        "child DN should move with renamed parent"
    );
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

    assert!(
        !backend
            .authenticate("cn=password-user,dc=example,dc=org", b"initial-secret")
            .await
            .unwrap()
    );
    assert!(
        backend
            .authenticate("cn=password-user,dc=example,dc=org", b"rotated-secret")
            .await
            .unwrap()
    );
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

    assert!(
        backend
            .authenticate("cn=hash-user,dc=example,dc=org", b"prehashed-secret")
            .await
            .unwrap()
    );
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

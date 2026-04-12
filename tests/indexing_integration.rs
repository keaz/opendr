//! Integration tests for attribute indexing in LMDB backend
//!
//! This test suite verifies that attribute indexing works correctly:
//! - Index creation and configuration
//! - Index updates on add/modify/delete operations
//! - Indexed searches with performance benefits
//! - Case-insensitive indexing
//! - Multi-value attribute indexing

use std::collections::HashMap;
use std::time::Instant;

use ldap_parser::ldap::SearchScope;
use opendr::backend::{
    DirectoryBackend, DirectoryEntry, Modification, ModifyOperation, SearchCandidateHint,
    SearchSubstringPart,
};
use opendr::backend_lmdb::{AttributeIndexConfig, IndexConfig, IndexType, LmdbBackend};
use tempfile::TempDir;

/// Helper to create a test backend with default configuration
fn create_test_backend(temp_dir: &TempDir) -> LmdbBackend {
    LmdbBackend::new(temp_dir.path(), 100, 1).unwrap()
}

/// Helper to create a test backend with custom index configuration
fn create_custom_backend(temp_dir: &TempDir, indexed_attrs: Vec<String>) -> LmdbBackend {
    let config = IndexConfig {
        indexed_attributes: indexed_attrs,
        attribute_indexes: Vec::new(),
    };
    LmdbBackend::new_with_config(temp_dir.path(), 100, 1, config).unwrap()
}

fn create_typed_backend(
    temp_dir: &TempDir,
    attribute_indexes: Vec<AttributeIndexConfig>,
) -> LmdbBackend {
    LmdbBackend::new_with_config(
        temp_dir.path(),
        100,
        1,
        IndexConfig {
            indexed_attributes: Vec::new(),
            attribute_indexes,
        },
    )
    .unwrap()
}

#[tokio::test]
async fn test_default_indexed_attributes() {
    let temp_dir = TempDir::new().unwrap();
    let backend = create_test_backend(&temp_dir);

    // Verify default indexed attributes
    assert!(backend.is_indexed("cn"));
    assert!(backend.is_indexed("uid"));
    assert!(backend.is_indexed("mail"));
    assert!(backend.is_indexed("objectclass"));
    assert!(backend.is_indexed("ou"));

    // Non-indexed by default
    assert!(!backend.is_indexed("description"));
    assert!(!backend.is_indexed("telephoneNumber"));
}

#[tokio::test]
async fn test_indexed_search_single_entry() {
    let temp_dir = TempDir::new().unwrap();
    let backend = create_test_backend(&temp_dir);

    // Add entry with indexed attributes
    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["Alice Smith".to_string()]);
    attributes.insert("uid".to_string(), vec!["asmith".to_string()]);
    attributes.insert("mail".to_string(), vec!["alice@example.com".to_string()]);

    let entry = DirectoryEntry::new("uid=asmith,ou=People,dc=example,dc=org", attributes);
    backend.add_entry(entry, vec![]).await.unwrap();

    // Search by cn
    let results = backend.search_by_index("cn", "Alice Smith").unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0], "uid=asmith,ou=People,dc=example,dc=org");

    // Search by uid
    let results = backend.search_by_index("uid", "asmith").unwrap();
    assert_eq!(results.len(), 1);

    // Search by mail
    let results = backend
        .search_by_index("mail", "alice@example.com")
        .unwrap();
    assert_eq!(results.len(), 1);
}

#[tokio::test]
async fn test_indexed_search_multiple_entries() {
    let temp_dir = TempDir::new().unwrap();
    let backend = create_test_backend(&temp_dir);

    // Add multiple users in Engineering department
    for i in 1..=10 {
        let mut attributes = HashMap::new();
        attributes.insert("cn".to_string(), vec![format!("Engineer {}", i)]);
        attributes.insert("uid".to_string(), vec![format!("eng{}", i)]);
        attributes.insert("ou".to_string(), vec!["Engineering".to_string()]);

        let entry = DirectoryEntry::new(
            format!("uid=eng{},ou=People,dc=example,dc=org", i),
            attributes,
        );
        backend.add_entry(entry, vec![]).await.unwrap();
    }

    // Search by department should return all 10 engineers
    let results = backend.search_by_index("ou", "Engineering").unwrap();
    assert_eq!(results.len(), 10);

    // Verify all expected DNs are in results
    for i in 1..=10 {
        let expected_dn = format!("uid=eng{},ou=People,dc=example,dc=org", i);
        assert!(results.contains(&expected_dn));
    }
}

#[tokio::test]
async fn test_indexed_search_case_insensitive() {
    let temp_dir = TempDir::new().unwrap();
    let backend = create_test_backend(&temp_dir);

    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["John Doe".to_string()]);
    let entry = DirectoryEntry::new("uid=jdoe,dc=example,dc=org", attributes);
    backend.add_entry(entry, vec![]).await.unwrap();

    // All case variations should find the entry
    let test_cases = vec!["john doe", "JOHN DOE", "John Doe", "jOhN dOe"];

    for test_case in test_cases {
        let results = backend.search_by_index("cn", test_case).unwrap();
        assert_eq!(results.len(), 1, "Failed for case: {}", test_case);
        assert_eq!(results[0], "uid=jdoe,dc=example,dc=org");
    }
}

#[tokio::test]
async fn test_indexed_search_multivalued_attribute() {
    let temp_dir = TempDir::new().unwrap();
    let backend = create_test_backend(&temp_dir);

    // Entry with multiple cn values
    let mut attributes = HashMap::new();
    attributes.insert(
        "cn".to_string(),
        vec![
            "Robert Smith".to_string(),
            "Bob Smith".to_string(),
            "R. Smith".to_string(),
        ],
    );
    attributes.insert("uid".to_string(), vec!["rsmith".to_string()]);

    let entry = DirectoryEntry::new("uid=rsmith,dc=example,dc=org", attributes);
    backend.add_entry(entry, vec![]).await.unwrap();

    // All cn values should be indexed
    let results = backend.search_by_index("cn", "Robert Smith").unwrap();
    assert_eq!(results.len(), 1);

    let results = backend.search_by_index("cn", "Bob Smith").unwrap();
    assert_eq!(results.len(), 1);

    let results = backend.search_by_index("cn", "R. Smith").unwrap();
    assert_eq!(results.len(), 1);
}

#[tokio::test]
async fn test_index_maintenance_on_modify() {
    let temp_dir = TempDir::new().unwrap();
    let backend = create_test_backend(&temp_dir);

    // Add entry
    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["Original Name".to_string()]);
    attributes.insert("mail".to_string(), vec!["original@example.com".to_string()]);
    let entry = DirectoryEntry::new("uid=test,dc=example,dc=org", attributes);
    backend.add_entry(entry, vec![]).await.unwrap();

    // Replace cn
    let modifications = vec![Modification {
        operation: ModifyOperation::Replace,
        attribute: "cn".to_string(),
        values: vec!["Updated Name".to_string()],
    }];
    backend
        .modify_entry("uid=test,dc=example,dc=org", modifications)
        .await
        .unwrap();

    // Old value should not be findable
    let results = backend.search_by_index("cn", "Original Name").unwrap();
    assert_eq!(results.len(), 0);

    // New value should be findable
    let results = backend.search_by_index("cn", "Updated Name").unwrap();
    assert_eq!(results.len(), 1);

    // mail should still be indexed (unchanged)
    let results = backend
        .search_by_index("mail", "original@example.com")
        .unwrap();
    assert_eq!(results.len(), 1);
}

#[tokio::test]
async fn test_index_maintenance_on_delete() {
    let temp_dir = TempDir::new().unwrap();
    let backend = create_test_backend(&temp_dir);

    // Add multiple entries
    for i in 1..=3 {
        let mut attributes = HashMap::new();
        attributes.insert("cn".to_string(), vec![format!("User {}", i)]);
        attributes.insert("ou".to_string(), vec!["Sales".to_string()]);
        let entry = DirectoryEntry::new(format!("uid=user{},dc=example,dc=org", i), attributes);
        backend.add_entry(entry, vec![]).await.unwrap();
    }

    // Verify all indexed
    let results = backend.search_by_index("ou", "Sales").unwrap();
    assert_eq!(results.len(), 3);

    // Delete one entry
    backend
        .delete_entry("uid=user2,dc=example,dc=org")
        .await
        .unwrap();

    // Should now find only 2
    let results = backend.search_by_index("ou", "Sales").unwrap();
    assert_eq!(results.len(), 2);
    assert!(!results.contains(&"uid=user2,dc=example,dc=org".to_string()));

    // cn for deleted entry should not be findable
    let results = backend.search_by_index("cn", "User 2").unwrap();
    assert_eq!(results.len(), 0);
}

#[tokio::test]
async fn test_index_with_add_operation() {
    let temp_dir = TempDir::new().unwrap();
    let backend = create_test_backend(&temp_dir);

    // Add entry with one mail
    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["Test User".to_string()]);
    attributes.insert("mail".to_string(), vec!["test@example.com".to_string()]);
    let entry = DirectoryEntry::new("uid=test,dc=example,dc=org", attributes);
    backend.add_entry(entry, vec![]).await.unwrap();

    // Add another mail value
    let modifications = vec![Modification {
        operation: ModifyOperation::Add,
        attribute: "mail".to_string(),
        values: vec!["test2@example.com".to_string()],
    }];
    backend
        .modify_entry("uid=test,dc=example,dc=org", modifications)
        .await
        .unwrap();

    // Both mail values should be indexed
    let results = backend.search_by_index("mail", "test@example.com").unwrap();
    assert_eq!(results.len(), 1);

    let results = backend
        .search_by_index("mail", "test2@example.com")
        .unwrap();
    assert_eq!(results.len(), 1);
}

#[tokio::test]
async fn test_index_with_delete_operation() {
    let temp_dir = TempDir::new().unwrap();
    let backend = create_test_backend(&temp_dir);

    // Add entry with multiple mail values
    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["Test User".to_string()]);
    attributes.insert(
        "mail".to_string(),
        vec![
            "test1@example.com".to_string(),
            "test2@example.com".to_string(),
        ],
    );
    let entry = DirectoryEntry::new("uid=test,dc=example,dc=org", attributes);
    backend.add_entry(entry, vec![]).await.unwrap();

    // Delete one mail value
    let modifications = vec![Modification {
        operation: ModifyOperation::Delete,
        attribute: "mail".to_string(),
        values: vec!["test1@example.com".to_string()],
    }];
    backend
        .modify_entry("uid=test,dc=example,dc=org", modifications)
        .await
        .unwrap();

    // Deleted value should not be indexed
    let results = backend
        .search_by_index("mail", "test1@example.com")
        .unwrap();
    assert_eq!(results.len(), 0);

    // Remaining value should still be indexed
    let results = backend
        .search_by_index("mail", "test2@example.com")
        .unwrap();
    assert_eq!(results.len(), 1);
}

#[tokio::test]
async fn test_custom_index_configuration() {
    let temp_dir = TempDir::new().unwrap();

    // Create backend with custom indexed attributes
    let backend = create_custom_backend(
        &temp_dir,
        vec![
            "employeeNumber".to_string(),
            "department".to_string(),
            "title".to_string(),
        ],
    );

    // Verify custom attributes are indexed
    assert!(backend.is_indexed("employeeNumber"));
    assert!(backend.is_indexed("department"));
    assert!(backend.is_indexed("title"));

    // Default attributes should NOT be indexed
    assert!(!backend.is_indexed("cn"));
    assert!(!backend.is_indexed("uid"));

    // Add entry with custom indexed attributes
    let mut attributes = HashMap::new();
    attributes.insert("employeeNumber".to_string(), vec!["12345".to_string()]);
    attributes.insert("department".to_string(), vec!["Engineering".to_string()]);
    attributes.insert("title".to_string(), vec!["Senior Engineer".to_string()]);

    let entry = DirectoryEntry::new("uid=emp12345,dc=example,dc=org", attributes);
    backend.add_entry(entry, vec![]).await.unwrap();

    // Search by custom indexed attributes
    let results = backend.search_by_index("employeeNumber", "12345").unwrap();
    assert_eq!(results.len(), 1);

    let results = backend
        .search_by_index("department", "Engineering")
        .unwrap();
    assert_eq!(results.len(), 1);

    let results = backend.search_by_index("title", "Senior Engineer").unwrap();
    assert_eq!(results.len(), 1);
}

#[tokio::test]
async fn test_typed_substring_index_configuration_and_candidates() {
    let temp_dir = TempDir::new().unwrap();
    let backend = create_typed_backend(
        &temp_dir,
        vec![AttributeIndexConfig {
            attribute: "description".to_string(),
            index_types: vec![IndexType::Substring],
        }],
    );

    assert!(backend.is_indexed("description"));
    assert!(backend.has_attribute_index("description", IndexType::Substring));
    assert!(!backend.has_attribute_index("description", IndexType::Equality));
    assert!(!backend.has_attribute_index("description", IndexType::Presence));
    assert!(!backend.has_attribute_index("description", IndexType::Ordering));

    let mut alice_attributes = HashMap::new();
    alice_attributes.insert("description".to_string(), vec!["alpha marker".to_string()]);
    let alice = DirectoryEntry::new("uid=alice,ou=people,dc=example,dc=org", alice_attributes);
    backend.add_entry(alice, vec![]).await.unwrap();

    let mut bob_attributes = HashMap::new();
    bob_attributes.insert("description".to_string(), vec!["omega marker".to_string()]);
    let bob = DirectoryEntry::new("uid=bob,ou=people,dc=example,dc=org", bob_attributes);
    backend.add_entry(bob, vec![]).await.unwrap();

    assert!(backend
        .search_by_index("description", "alpha marker")
        .unwrap()
        .is_empty());

    let results = backend
        .search_entries_with_hint(
            "ou=people,dc=example,dc=org",
            SearchScope(2),
            Some(SearchCandidateHint::Substring {
                attribute: "description".to_string(),
                parts: vec![SearchSubstringPart::Any("pha".to_string())],
            }),
        )
        .await
        .unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].dn, "uid=alice,ou=people,dc=example,dc=org");
}

#[tokio::test]
async fn test_typed_ordering_index_configuration_and_candidates() {
    let temp_dir = TempDir::new().unwrap();
    let backend = create_typed_backend(
        &temp_dir,
        vec![AttributeIndexConfig {
            attribute: "serialNumber".to_string(),
            index_types: vec![IndexType::Ordering],
        }],
    );

    assert!(backend.is_indexed("serialNumber"));
    assert!(backend.has_attribute_index("serialNumber", IndexType::Ordering));
    assert!(!backend.has_attribute_index("serialNumber", IndexType::Equality));
    assert!(!backend.has_attribute_index("serialNumber", IndexType::Presence));
    assert!(!backend.has_attribute_index("serialNumber", IndexType::Substring));

    for (uid, serial) in [("low", "010"), ("mid", "020"), ("high", "030")] {
        let mut attributes = HashMap::new();
        attributes.insert("serialNumber".to_string(), vec![serial.to_string()]);
        backend
            .add_entry(
                DirectoryEntry::new(format!("uid={uid},ou=people,dc=example,dc=org"), attributes),
                vec![],
            )
            .await
            .unwrap();
    }

    assert!(backend
        .search_by_index("serialNumber", "020")
        .unwrap()
        .is_empty());

    let greater_or_equal = backend
        .search_entries_with_hint(
            "ou=people,dc=example,dc=org",
            SearchScope(2),
            Some(SearchCandidateHint::GreaterOrEqual {
                attribute: "serialNumber".to_string(),
                value: "020".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_iter()
        .map(|entry| entry.dn)
        .collect::<Vec<_>>();

    assert_eq!(
        greater_or_equal,
        vec![
            "uid=mid,ou=people,dc=example,dc=org".to_string(),
            "uid=high,ou=people,dc=example,dc=org".to_string(),
        ]
    );
}

#[tokio::test]
async fn test_typed_indexes_are_backfilled_for_existing_data() {
    let temp_dir = TempDir::new().unwrap();

    {
        let backend = create_typed_backend(&temp_dir, Vec::new());

        for (uid, description, serial) in [
            ("alice", "alpha marker", "010"),
            ("bob", "omega marker", "020"),
            ("carol", "gamma marker", "030"),
        ] {
            let mut attributes = HashMap::new();
            attributes.insert("description".to_string(), vec![description.to_string()]);
            attributes.insert("serialNumber".to_string(), vec![serial.to_string()]);
            backend
                .add_entry(
                    DirectoryEntry::new(
                        format!("uid={uid},ou=people,dc=example,dc=org"),
                        attributes,
                    ),
                    vec![],
                )
                .await
                .unwrap();
        }
    }

    let backend = create_typed_backend(
        &temp_dir,
        vec![
            AttributeIndexConfig {
                attribute: "description".to_string(),
                index_types: vec![IndexType::Substring],
            },
            AttributeIndexConfig {
                attribute: "serialNumber".to_string(),
                index_types: vec![IndexType::Ordering],
            },
        ],
    );

    assert!(backend.has_attribute_index("description", IndexType::Substring));
    assert!(backend.has_attribute_index("serialNumber", IndexType::Ordering));

    let substring_results = backend
        .search_entries_with_hint(
            "ou=people,dc=example,dc=org",
            SearchScope(2),
            Some(SearchCandidateHint::Substring {
                attribute: "description".to_string(),
                parts: vec![SearchSubstringPart::Any("pha".to_string())],
            }),
        )
        .await
        .unwrap();

    assert_eq!(substring_results.len(), 1);
    assert_eq!(
        substring_results[0].dn,
        "uid=alice,ou=people,dc=example,dc=org"
    );

    let ordering_results = backend
        .search_entries_with_hint(
            "ou=people,dc=example,dc=org",
            SearchScope(2),
            Some(SearchCandidateHint::LessOrEqual {
                attribute: "serialNumber".to_string(),
                value: "020".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_iter()
        .map(|entry| entry.dn)
        .collect::<Vec<_>>();

    assert_eq!(
        ordering_results,
        vec![
            "uid=alice,ou=people,dc=example,dc=org".to_string(),
            "uid=bob,ou=people,dc=example,dc=org".to_string(),
        ]
    );
}

#[tokio::test]
async fn test_indexed_search_performance() {
    let temp_dir = TempDir::new().unwrap();
    let backend = create_test_backend(&temp_dir);

    // Add 1000 entries
    for i in 0..1000 {
        let mut attributes = HashMap::new();
        attributes.insert("cn".to_string(), vec![format!("User {}", i)]);
        attributes.insert("uid".to_string(), vec![format!("user{}", i)]);
        attributes.insert(
            "ou".to_string(),
            vec![format!("Department{}", i % 10)], // 10 different departments
        );

        let entry = DirectoryEntry::new(format!("uid=user{},dc=example,dc=org", i), attributes);
        backend.add_entry(entry, vec![]).await.unwrap();
    }

    // Time indexed search
    let start = Instant::now();
    let results = backend.search_by_index("ou", "Department5").unwrap();
    let indexed_duration = start.elapsed();

    // Should find approximately 100 entries (1000 / 10)
    assert_eq!(results.len(), 100);

    // Indexed search should be very fast (< 10ms even for 1000 entries)
    assert!(
        indexed_duration.as_millis() < 10,
        "Indexed search took {}ms, expected < 10ms",
        indexed_duration.as_millis()
    );
}

#[tokio::test]
async fn test_indexed_search_no_results() {
    let temp_dir = TempDir::new().unwrap();
    let backend = create_test_backend(&temp_dir);

    // Add some entries
    for i in 1..=5 {
        let mut attributes = HashMap::new();
        attributes.insert("cn".to_string(), vec![format!("User {}", i)]);
        let entry = DirectoryEntry::new(format!("uid=user{},dc=example,dc=org", i), attributes);
        backend.add_entry(entry, vec![]).await.unwrap();
    }

    // Search for non-existent value
    let results = backend.search_by_index("cn", "Non Existent User").unwrap();
    assert_eq!(results.len(), 0);
}

#[tokio::test]
async fn test_objectclass_indexing() {
    let temp_dir = TempDir::new().unwrap();
    let backend = create_test_backend(&temp_dir);

    // Add entries with different objectClass values
    let classes = [
        vec!["person".to_string(), "inetOrgPerson".to_string()],
        vec!["organizationalUnit".to_string()],
        vec!["person".to_string()],
    ];

    for (i, obj_class) in classes.iter().enumerate() {
        let mut attributes = HashMap::new();
        attributes.insert("objectclass".to_string(), obj_class.clone());
        attributes.insert("cn".to_string(), vec![format!("Entry {}", i)]);

        let entry = DirectoryEntry::new(format!("cn=entry{},dc=example,dc=org", i), attributes);
        backend.add_entry(entry, vec![]).await.unwrap();
    }

    // Search by objectClass
    let results = backend.search_by_index("objectclass", "person").unwrap();
    assert_eq!(results.len(), 2); // Entry 0 and Entry 2

    let results = backend
        .search_by_index("objectclass", "inetOrgPerson")
        .unwrap();
    assert_eq!(results.len(), 1); // Only Entry 0

    let results = backend
        .search_by_index("objectclass", "organizationalUnit")
        .unwrap();
    assert_eq!(results.len(), 1); // Only Entry 1
}

#[tokio::test]
async fn test_objectclass_hint_search_handles_large_result_sets() {
    let temp_dir = TempDir::new().unwrap();
    let backend = create_test_backend(&temp_dir);

    let users_ou = "ou=users,dc=example,dc=org";
    let mut ou_attributes = HashMap::new();
    ou_attributes.insert(
        "objectclass".to_string(),
        vec!["top".to_string(), "organizationalUnit".to_string()],
    );
    ou_attributes.insert("ou".to_string(), vec!["users".to_string()]);
    backend
        .add_entry(
            DirectoryEntry::new(users_ou.to_string(), ou_attributes),
            vec![],
        )
        .await
        .unwrap();

    for i in 0..1000 {
        let uid = format!("user{i:04}");
        let dn = format!("uid={uid},{users_ou}");
        let mut attributes = HashMap::new();
        attributes.insert(
            "objectclass".to_string(),
            vec![
                "top".to_string(),
                "person".to_string(),
                "organizationalPerson".to_string(),
                "inetOrgPerson".to_string(),
            ],
        );
        attributes.insert("uid".to_string(), vec![uid.clone()]);
        attributes.insert("cn".to_string(), vec![format!("User {i}")]);
        attributes.insert("sn".to_string(), vec![format!("User{i}")]);
        attributes.insert("mail".to_string(), vec![format!("{uid}@example.com")]);
        backend
            .add_entry(DirectoryEntry::new(dn, attributes), vec![])
            .await
            .unwrap();
    }

    let started = Instant::now();
    let results = backend
        .search_entries_with_hint(
            users_ou,
            SearchScope(2),
            Some(SearchCandidateHint::Equality {
                attribute: "objectclass".to_string(),
                value: "inetOrgPerson".to_string(),
            }),
        )
        .await
        .unwrap();

    assert_eq!(results.len(), 1000);
    assert!(
        started.elapsed().as_secs() < 5,
        "large objectClass hint search took too long: {:?}",
        started.elapsed()
    );
}

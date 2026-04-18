//! Main server integration tests for operational attributes
//!
//! These tests verify that operational attributes work correctly
//! in a full server context, from backend through adapters to search results.

use opendr::backend::{DirectoryBackend, DirectoryEntry, MockBackend};
use opendr::backend_adapters::SearchBackendAdapter;
use opendr::backend_lmdb::LmdbBackend;
use opendr::search_fsm::SearchBackend;
use std::collections::HashMap;
use std::sync::Arc;

/// Test end-to-end flow: Add entry → Search with operational attrs
#[tokio::test]
async fn test_e2e_add_and_search_with_operational_attrs() {
    let backend = Arc::new(MockBackend::new());

    // Add an entry
    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["Test User".to_string()]);
    attributes.insert("mail".to_string(), vec!["test@example.com".to_string()]);
    attributes.insert("objectclass".to_string(), vec!["person".to_string()]);

    let entry = DirectoryEntry::new("cn=Test User,ou=users,dc=example,dc=com", attributes);
    backend
        .add_entry(entry, b"password".to_vec())
        .await
        .unwrap();

    // Search with "+" to get operational attributes
    let adapter = SearchBackendAdapter::new(backend.clone());
    let requested_attrs = vec!["+".to_string()];
    let result = adapter
        .get_entry("cn=Test User,ou=users,dc=example,dc=com", &requested_attrs)
        .await
        .unwrap()
        .expect("Entry should exist");

    // Verify operational attributes are present
    assert!(
        result.attributes.contains_key("entrycsn"),
        "Should have entryCSN"
    );
    assert_eq!(
        result.attributes.get("entryDN"),
        Some(&vec!["cn=Test User,ou=users,dc=example,dc=com".to_string()])
    );
    assert!(
        result.attributes.contains_key("createtimestamp"),
        "Should have createTimestamp"
    );
    assert!(
        result.attributes.contains_key("modifytimestamp"),
        "Should have modifyTimestamp"
    );

    // Verify user attributes are NOT present when only "+" is requested
    assert!(
        !result.attributes.contains_key("cn"),
        "Should not have user attrs with only '+'"
    );
    assert!(
        !result.attributes.contains_key("mail"),
        "Should not have user attrs with only '+'"
    );
}

#[tokio::test]
async fn test_specific_entry_dn_operational_attribute_is_searchable() {
    let backend = Arc::new(MockBackend::new());
    let dn = "uid=auth-user,ou=users,dc=example,dc=com";

    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["Auth User".to_string()]);
    attributes.insert("uid".to_string(), vec!["auth-user".to_string()]);
    attributes.insert("objectclass".to_string(), vec!["person".to_string()]);
    backend
        .add_entry(DirectoryEntry::new(dn, attributes), b"password".to_vec())
        .await
        .unwrap();

    let adapter = SearchBackendAdapter::new(backend);
    let requested_attrs = vec!["entryDN".to_string()];
    let result = adapter
        .get_entry(dn, &requested_attrs)
        .await
        .unwrap()
        .expect("Entry should exist");

    assert_eq!(
        result.attributes.get("entryDN"),
        Some(&vec![dn.to_string()])
    );
    assert!(
        !result.attributes.contains_key("cn"),
        "Specific entryDN request should not include user attributes"
    );
}

#[tokio::test]
async fn test_account_authentication_metadata_tracks_failures_and_success() {
    let backend = Arc::new(MockBackend::new());

    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["Login User".to_string()]);
    attributes.insert("objectclass".to_string(), vec!["person".to_string()]);

    let dn = "cn=Login User,ou=users,dc=example,dc=com";
    let entry = DirectoryEntry::new(dn, attributes);
    backend
        .add_entry(entry, b"password".to_vec())
        .await
        .unwrap();

    assert!(backend.record_authentication_failure(dn).await.unwrap());
    assert!(backend.record_authentication_failure(dn).await.unwrap());

    let after_failures = backend.get_entry(dn).await.unwrap().unwrap();
    assert!(
        after_failures
            .operational_attributes
            .last_failed_login
            .is_some()
    );
    assert_eq!(
        after_failures.operational_attributes.failed_login_count,
        Some(2)
    );
    assert!(
        after_failures
            .operational_attributes
            .last_successful_login
            .is_none()
    );

    assert!(backend.record_authentication_success(dn).await.unwrap());

    let after_success = backend.get_entry(dn).await.unwrap().unwrap();
    assert!(
        after_success
            .operational_attributes
            .last_successful_login
            .is_some()
    );
    assert_eq!(
        after_success.operational_attributes.failed_login_count,
        Some(0)
    );
    assert_eq!(
        after_success.operational_attributes.last_failed_login,
        after_failures.operational_attributes.last_failed_login
    );
}

#[tokio::test]
async fn test_authentication_metadata_is_searchable_as_operational_attributes() {
    let backend = Arc::new(MockBackend::new());

    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["Search Login".to_string()]);
    attributes.insert("objectclass".to_string(), vec!["person".to_string()]);

    let dn = "cn=Search Login,ou=users,dc=example,dc=com";
    let entry = DirectoryEntry::new(dn, attributes);
    backend
        .add_entry(entry, b"password".to_vec())
        .await
        .unwrap();
    backend.record_authentication_failure(dn).await.unwrap();
    backend.record_authentication_success(dn).await.unwrap();

    let adapter = SearchBackendAdapter::new(backend);
    let requested_attrs = vec![
        "lastSuccessfulLogin".to_string(),
        "failedLoginCount".to_string(),
    ];
    let result = adapter
        .get_entry(dn, &requested_attrs)
        .await
        .unwrap()
        .expect("Entry should exist");

    assert!(result.attributes.contains_key("lastsuccessfullogin"));
    assert_eq!(
        result.attributes.get("failedlogincount"),
        Some(&vec!["0".to_string()])
    );
    assert!(!result.attributes.contains_key("lastfailedlogin"));
    assert!(!result.attributes.contains_key("cn"));
}

/// Test end-to-end flow: Add entry → Modify entry → Search shows updated timestamps
#[tokio::test]
async fn test_e2e_modify_updates_operational_attrs() {
    let backend = Arc::new(MockBackend::new());

    // Add an entry
    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["Original Name".to_string()]);
    attributes.insert("mail".to_string(), vec!["original@example.com".to_string()]);
    attributes.insert("objectclass".to_string(), vec!["person".to_string()]);

    let entry = DirectoryEntry::new("cn=Test Modify,ou=users,dc=example,dc=com", attributes);
    backend
        .add_entry(entry, b"password".to_vec())
        .await
        .unwrap();

    // Get initial operational attributes
    let adapter = SearchBackendAdapter::new(backend.clone());
    let requested_attrs = vec!["*".to_string(), "+".to_string()];
    let initial_result = adapter
        .get_entry(
            "cn=Test Modify,ou=users,dc=example,dc=com",
            &requested_attrs,
        )
        .await
        .unwrap()
        .expect("Entry should exist");

    let initial_modify_time = initial_result
        .attributes
        .get("modifytimestamp")
        .expect("Should have modifyTimestamp")
        .first()
        .expect("Should have value")
        .clone();

    // Wait a moment to ensure timestamp changes (GeneralizedTime is second-precision)
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Modify the entry
    use opendr::backend::{Modification, ModifyOperation};
    let modifications = vec![Modification {
        operation: ModifyOperation::Replace,
        attribute: "cn".to_string(),
        values: vec!["Modified Name".to_string()],
    }];
    backend
        .modify_entry("cn=Test Modify,ou=users,dc=example,dc=com", modifications)
        .await
        .unwrap();

    // Search again and verify modifyTimestamp changed
    let updated_result = adapter
        .get_entry(
            "cn=Test Modify,ou=users,dc=example,dc=com",
            &requested_attrs,
        )
        .await
        .unwrap()
        .expect("Entry should exist");

    let updated_modify_time = updated_result
        .attributes
        .get("modifytimestamp")
        .expect("Should have modifyTimestamp")
        .first()
        .expect("Should have value")
        .clone();

    // Verify the timestamp changed
    assert_ne!(
        initial_modify_time, updated_modify_time,
        "modifyTimestamp should be updated"
    );

    // Verify user attribute was updated
    assert_eq!(
        updated_result.attributes.get("cn").unwrap()[0],
        "Modified Name"
    );
}

/// Test end-to-end with LMDB backend
#[tokio::test]
async fn test_e2e_lmdb_operational_attrs() {
    let temp_dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(LmdbBackend::new(temp_dir.path(), 100, 1).unwrap());

    // Add multiple entries
    for i in 1..=5 {
        let mut attributes = HashMap::new();
        attributes.insert("cn".to_string(), vec![format!("User {}", i)]);
        attributes.insert("uid".to_string(), vec![format!("user{}", i)]);
        attributes.insert("mail".to_string(), vec![format!("user{}@example.com", i)]);
        attributes.insert("objectclass".to_string(), vec!["person".to_string()]);

        let dn = format!("uid=user{},ou=users,dc=example,dc=com", i);
        let entry = DirectoryEntry::new(dn, attributes);
        backend
            .add_entry(entry, b"password".to_vec())
            .await
            .unwrap();
    }

    // Search for all entries with operational attributes
    let adapter = SearchBackendAdapter::new(backend.clone());
    let requested_attrs = vec!["uid".to_string(), "entrycsn".to_string()];

    // Verify each entry has the requested attributes
    for i in 1..=5 {
        let dn = format!("uid=user{},ou=users,dc=example,dc=com", i);
        let result = adapter
            .get_entry(&dn, &requested_attrs)
            .await
            .unwrap()
            .expect("Entry should exist");

        // Should have requested user attribute
        assert_eq!(
            result.attributes.get("uid").unwrap()[0],
            format!("user{}", i)
        );

        // Should have requested operational attribute
        assert!(
            result.attributes.contains_key("entrycsn"),
            "Should have entryCSN"
        );

        // Should NOT have non-requested attributes
        assert!(
            !result.attributes.contains_key("cn"),
            "Should not have non-requested cn"
        );
        assert!(
            !result.attributes.contains_key("mail"),
            "Should not have non-requested mail"
        );
        assert!(
            !result.attributes.contains_key("createtimestamp"),
            "Should not have non-requested createTimestamp"
        );
    }
}

#[tokio::test]
async fn test_e2e_lmdb_authentication_metadata_persists_and_resets() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().to_path_buf();
    let dn = "cn=Persistent Login,dc=example,dc=com";

    {
        let backend = LmdbBackend::new(&db_path, 100, 1).unwrap();
        let mut attributes = HashMap::new();
        attributes.insert("cn".to_string(), vec!["Persistent Login".to_string()]);
        attributes.insert("objectclass".to_string(), vec!["person".to_string()]);

        let entry = DirectoryEntry::new(dn, attributes);
        backend
            .add_entry(entry, b"password".to_vec())
            .await
            .unwrap();
        backend.record_authentication_failure(dn).await.unwrap();
    }

    {
        let backend = LmdbBackend::new(&db_path, 100, 1).unwrap();
        let restored = backend.get_entry(dn).await.unwrap().unwrap();
        assert!(restored.operational_attributes.last_failed_login.is_some());
        assert_eq!(restored.operational_attributes.failed_login_count, Some(1));

        backend.record_authentication_success(dn).await.unwrap();
        let after_success = backend.get_entry(dn).await.unwrap().unwrap();
        assert!(
            after_success
                .operational_attributes
                .last_successful_login
                .is_some()
        );
        assert_eq!(
            after_success.operational_attributes.failed_login_count,
            Some(0)
        );
    }
}

/// Test contextCSN is available via operational attributes
#[tokio::test]
async fn test_e2e_context_csn_queryable() {
    let backend = Arc::new(MockBackend::new());

    // Add an entry
    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["Test".to_string()]);
    attributes.insert("objectclass".to_string(), vec!["person".to_string()]);

    let entry = DirectoryEntry::new("cn=Test,dc=example,dc=com", attributes);
    backend
        .add_entry(entry, b"password".to_vec())
        .await
        .unwrap();

    // Get contextCSN from backend
    let context_csn = backend.get_context_csn().await.unwrap();
    assert!(
        context_csn.is_some(),
        "contextCSN should be set after adding entry"
    );

    // In a real LDAP server, contextCSN would be queryable on the root DSE
    // For now, we just verify it's tracked correctly
    let csn_value = context_csn.unwrap();
    assert!(
        csn_value.to_ldap_string().contains('#'),
        "CSN should be in LDAP format"
    );
}

/// Test that search with "*" alone does not return operational attributes
#[tokio::test]
async fn test_e2e_star_excludes_operational_attrs() {
    let backend = Arc::new(MockBackend::new());

    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["Test".to_string()]);
    attributes.insert("mail".to_string(), vec!["test@example.com".to_string()]);
    attributes.insert("objectclass".to_string(), vec!["person".to_string()]);

    let entry = DirectoryEntry::new("cn=Test,dc=example,dc=com", attributes);
    backend
        .add_entry(entry, b"password".to_vec())
        .await
        .unwrap();

    let adapter = SearchBackendAdapter::new(backend);

    // Search with "*" (all user attributes)
    let requested_attrs = vec!["*".to_string()];
    let result = adapter
        .get_entry("cn=Test,dc=example,dc=com", &requested_attrs)
        .await
        .unwrap()
        .expect("Entry should exist");

    // Should have user attributes
    assert!(result.attributes.contains_key("cn"));
    assert!(result.attributes.contains_key("mail"));

    // Should NOT have operational attributes
    assert!(!result.attributes.contains_key("entrycsn"));
    assert!(!result.attributes.contains_key("createtimestamp"));
    assert!(!result.attributes.contains_key("modifytimestamp"));
}

/// Test concurrent searches with different operational attribute requests
#[tokio::test]
async fn test_e2e_concurrent_operational_attr_searches() {
    let backend = Arc::new(MockBackend::new());

    // Add test entries
    for i in 1..=10 {
        let mut attributes = HashMap::new();
        attributes.insert("cn".to_string(), vec![format!("User {}", i)]);
        attributes.insert("objectclass".to_string(), vec!["person".to_string()]);

        let entry = DirectoryEntry::new(format!("cn=User {},dc=example,dc=com", i), attributes);
        backend
            .add_entry(entry, b"password".to_vec())
            .await
            .unwrap();
    }

    let adapter = Arc::new(SearchBackendAdapter::new(backend));

    // Spawn concurrent searches with different attribute requests
    let mut handles = vec![];

    for i in 1..=10 {
        let adapter_clone = adapter.clone();
        let handle = tokio::spawn(async move {
            let dn = format!("cn=User {},dc=example,dc=com", i);

            // Alternate between different search types
            let requested_attrs = if i % 3 == 0 {
                vec!["+".to_string()] // All operational
            } else if i % 3 == 1 {
                vec!["*".to_string(), "+".to_string()] // All user and operational
            } else {
                vec!["cn".to_string(), "entrycsn".to_string()] // Specific mix
            };

            adapter_clone.get_entry(&dn, &requested_attrs).await
        });
        handles.push(handle);
    }

    // Wait for all searches to complete
    for handle in handles {
        let result = handle.await.unwrap().unwrap();
        assert!(result.is_some(), "All entries should be found");
    }
}

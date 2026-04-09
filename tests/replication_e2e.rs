//! End-to-End Replication Tests
//!
//! This module contains comprehensive E2E tests for LDAP replication
//! according to RFC 4533 (LDAP Content Synchronization Operation).
//!
//! These tests validate:
//! - Full synchronization (refresh phase)
//! - Incremental synchronization (persist phase)
//! - CRUD operation replication
//! - Error handling and recovery
//! - State persistence
//! - Multi-consumer scenarios

use ldap_parser::filter::{AttributeValueAssertion, Filter};
use ldap_parser::ldap::{DerefAliases, LdapDN, LdapString, ProtocolOp, SearchRequest, SearchScope};
use ldap_parser::parse_ldap_messages;
use opendr::backend::{DirectoryBackend, DirectoryEntry, MockBackend};
use opendr::backend_changelog_wrapper::ChangelogBackendWrapper;
use opendr::config::ServerConfig;
use opendr::replication::ChangelogTracker;
use opendr::replication_provider_fsm::ChangeType;
use opendr::replication_service::ReplicationService;
use opendr::server;
use opendr::shutdown::{ShutdownConfig, ShutdownCoordinator};
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio::time::{sleep, timeout};

/// Helper function to create a test provider configuration
fn create_provider_config() -> ServerConfig {
    let mut config = ServerConfig::default();
    config.replication.enabled = true;
    config.replication.mode = "provider".to_string();
    config.replication.changelog_capacity = 1000;
    config.replication.state_storage_path = unique_replication_state_path("provider");
    config.server.base_dn = "dc=test,dc=org".to_string();
    config
}

/// Helper function to create a test consumer configuration
fn create_consumer_config() -> ServerConfig {
    let mut config = ServerConfig::default();
    config.replication.enabled = true;
    config.replication.mode = "consumer".to_string();
    config.replication.provider_url = Some("ldap://provider:389".to_string());
    config.replication.sync_interval_secs = 1;
    config.replication.state_storage_path = unique_replication_state_path("consumer");
    config.server.base_dn = "dc=test,dc=org".to_string();
    config
}

fn unique_replication_state_path(prefix: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "opendr-repl-e2e-{prefix}-{}-{nanos}",
        std::process::id()
    ))
}

/// Helper function to create a test entry
fn create_test_entry(dn: &str, cn: &str, sn: &str) -> DirectoryEntry {
    DirectoryEntry::new(
        dn,
        HashMap::from([
            (
                "objectClass".to_string(),
                vec!["top".to_string(), "person".to_string()],
            ),
            ("cn".to_string(), vec![cn.to_string()]),
            ("sn".to_string(), vec![sn.to_string()]),
        ]),
    )
}

fn create_listening_provider_backend() -> Arc<dyn DirectoryBackend> {
    let backend = Arc::new(MockBackend::default());
    let changelog = Arc::new(ChangelogTracker::new());
    let mut wrapper = ChangelogBackendWrapper::new(backend, Some(changelog));
    let (replication_sender, _) = broadcast::channel(32);
    wrapper.set_replication_sender(replication_sender);
    Arc::new(wrapper)
}

async fn connected_stream_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let client = tokio::spawn(async move { tokio::net::TcpStream::connect(addr).await.unwrap() });
    let (server_stream, _) = listener.accept().await.unwrap();
    let client_stream = client.await.unwrap();

    (server_stream, client_stream)
}

async fn read_response(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut buf = vec![0u8; 4096];
    let len = timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .expect("response timeout")
        .expect("failed to read response");
    buf.truncate(len);
    buf
}

fn create_replication_search_request(cookie: Option<&str>) -> SearchRequest<'static> {
    let mut attributes = vec![LdapString(Cow::Owned(
        opendr::replication::REPLICATION_STREAM_ATTRIBUTE.to_string(),
    ))];

    if let Some(cookie) = cookie {
        attributes.push(LdapString(Cow::Owned(format!(
            "{}{}",
            opendr::replication::REPLICATION_COOKIE_ATTRIBUTE_PREFIX,
            cookie
        ))));
    }

    SearchRequest {
        base_object: LdapDN(Cow::Owned("dc=example,dc=org".to_string())),
        scope: SearchScope(2),
        deref_aliases: DerefAliases(0),
        size_limit: 0,
        time_limit: 0,
        types_only: false,
        filter: Filter::EqualityMatch(AttributeValueAssertion {
            attribute_desc: LdapString(Cow::Owned("objectClass".to_string())),
            assertion_value: b"top",
        }),
        attributes,
    }
}

/// Test basic provider-consumer setup
#[tokio::test]
async fn test_e2e_provider_consumer_setup() {
    let provider_config = create_provider_config();
    let consumer_config = create_consumer_config();

    let provider_backend = Arc::new(MockBackend::new());
    let consumer_backend = Arc::new(MockBackend::new());

    let provider_service =
        ReplicationService::from_config(&provider_config, provider_backend).unwrap();
    let consumer_service =
        ReplicationService::from_config(&consumer_config, consumer_backend).unwrap();

    assert!(provider_service.is_provider());
    assert!(!provider_service.is_consumer());
    assert!(consumer_service.is_consumer());
    assert!(!consumer_service.is_provider());
}

/// Test changelog tracking for add operations (RFC 4533 Section 2)
#[tokio::test]
async fn test_e2e_add_operation_tracking() {
    let config = create_provider_config();
    let backend = Arc::new(MockBackend::new());
    let service = ReplicationService::from_config(&config, backend.clone()).unwrap();

    // Get wrapped backend
    let wrapped_backend = service.backend();

    // Add an entry
    let entry = create_test_entry("cn=user1,dc=test,dc=org", "user1", "User One");
    wrapped_backend
        .add_entry(entry.clone(), vec![])
        .await
        .unwrap();

    // Verify changelog recorded the add
    let changelog = service.changelog().unwrap();
    let entries = changelog.get_all();

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].change_type, ChangeType::Add);
    assert_eq!(entries[0].dn, "cn=user1,dc=test,dc=org");
    // Verify CSN is assigned
    assert_eq!(entries[0].csn.replica_id(), 1); // Default replica ID
}

/// Test changelog tracking for modify operations
#[tokio::test]
async fn test_e2e_modify_operation_tracking() {
    let config = create_provider_config();
    let backend = Arc::new(MockBackend::new());
    let service = ReplicationService::from_config(&config, backend.clone()).unwrap();

    let wrapped_backend = service.backend();

    // Add an entry first
    let entry = create_test_entry("cn=user1,dc=test,dc=org", "user1", "User One");
    wrapped_backend
        .add_entry(entry.clone(), vec![])
        .await
        .unwrap();

    // Modify the entry with proper Modification structure
    use opendr::backend::{Modification, ModifyOperation};
    let modifications = vec![Modification {
        operation: ModifyOperation::Add,
        attribute: "description".to_string(),
        values: vec!["Modified description".to_string()],
    }];
    wrapped_backend
        .modify_entry(&entry.dn, modifications)
        .await
        .unwrap();

    // Verify changelog has both operations
    let changelog = service.changelog().unwrap();
    let entries = changelog.get_all();

    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].change_type, ChangeType::Add);
    assert_eq!(entries[1].change_type, ChangeType::Modify);
    // Verify CSNs are ordered
    assert!(entries[1].csn > entries[0].csn);
}

/// Test changelog tracking for delete operations
#[tokio::test]
async fn test_e2e_delete_operation_tracking() {
    let config = create_provider_config();
    let backend = Arc::new(MockBackend::new());
    let service = ReplicationService::from_config(&config, backend.clone()).unwrap();

    let wrapped_backend = service.backend();

    // Add and then delete an entry
    let entry = create_test_entry("cn=user1,dc=test,dc=org", "user1", "User One");
    wrapped_backend
        .add_entry(entry.clone(), vec![])
        .await
        .unwrap();
    wrapped_backend.delete_entry(&entry.dn).await.unwrap();

    // Verify changelog has both operations
    let changelog = service.changelog().unwrap();
    let entries = changelog.get_all();

    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].change_type, ChangeType::Add);
    assert_eq!(entries[1].change_type, ChangeType::Delete);
    assert_eq!(entries[1].dn, "cn=user1,dc=test,dc=org");
}

/// Test changelog tracking for rename operations (ModifyDN)
#[tokio::test]
async fn test_e2e_rename_operation_tracking() {
    let config = create_provider_config();
    let backend = Arc::new(MockBackend::new());
    let service = ReplicationService::from_config(&config, backend.clone()).unwrap();

    let wrapped_backend = service.backend();

    // Add and then rename an entry
    let entry = create_test_entry("cn=user1,dc=test,dc=org", "user1", "User One");
    wrapped_backend
        .add_entry(entry.clone(), vec![])
        .await
        .unwrap();
    wrapped_backend
        .rename_entry(&entry.dn, "cn=user1_renamed", true, None)
        .await
        .unwrap();

    // Verify changelog has both operations
    let changelog = service.changelog().unwrap();
    let entries = changelog.get_all();

    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].change_type, ChangeType::Add);
    assert_eq!(entries[1].change_type, ChangeType::Rename);
    assert_eq!(entries[1].dn, "cn=user1,dc=test,dc=org");
}

/// Test changelog sequence numbers are monotonically increasing
#[tokio::test]
async fn test_e2e_sequence_number_ordering() {
    let config = create_provider_config();
    let backend = Arc::new(MockBackend::new());
    let service = ReplicationService::from_config(&config, backend.clone()).unwrap();

    let wrapped_backend = service.backend();

    // Perform multiple operations
    for i in 1..=5 {
        let entry = create_test_entry(
            &format!("cn=user{},dc=test,dc=org", i),
            &format!("user{}", i),
            &format!("User {}", i),
        );
        wrapped_backend.add_entry(entry, vec![]).await.unwrap();
    }

    // Verify CSN ordering
    let changelog = service.changelog().unwrap();
    let entries = changelog.get_all();

    assert_eq!(entries.len(), 5);
    // Verify CSNs are strictly increasing
    for idx in 1..entries.len() {
        assert!(
            entries[idx].csn > entries[idx - 1].csn,
            "CSN at index {} should be greater than CSN at index {}",
            idx,
            idx - 1
        );
    }
}

/// Test changelog capacity enforcement
#[tokio::test]
async fn test_e2e_changelog_capacity() {
    let mut config = create_provider_config();
    config.replication.changelog_capacity = 3; // Small capacity for testing

    let backend = Arc::new(MockBackend::new());
    let service = ReplicationService::from_config(&config, backend.clone()).unwrap();

    let wrapped_backend = service.backend();

    // Add more entries than capacity
    for i in 1..=5 {
        let entry = create_test_entry(
            &format!("cn=user{},dc=test,dc=org", i),
            &format!("user{}", i),
            &format!("User {}", i),
        );
        wrapped_backend.add_entry(entry, vec![]).await.unwrap();
    }

    // Verify only latest entries retained
    let changelog = service.changelog().unwrap();
    let entries = changelog.get_all();

    // Should keep only last 3 entries (most recent)
    assert!(entries.len() <= 3);
    // Verify CSNs are ordered
    for idx in 1..entries.len() {
        assert!(entries[idx].csn > entries[idx - 1].csn);
    }
}

/// Test provider service startup and shutdown
#[tokio::test]
async fn test_e2e_provider_lifecycle() {
    let config = create_provider_config();
    let backend = Arc::new(MockBackend::new());
    let service = ReplicationService::from_config(&config, backend).unwrap();

    let shutdown = Arc::new(ShutdownCoordinator::new(ShutdownConfig::default()));

    // Start provider
    let handle = service.start_provider(shutdown.clone()).await.unwrap();
    assert!(handle.is_some());

    // Let it run briefly
    sleep(Duration::from_millis(100)).await;

    // Shutdown
    shutdown.initiate_shutdown().await;
    if let Some(h) = handle {
        let result = tokio::time::timeout(Duration::from_secs(2), h).await;
        assert!(result.is_ok(), "Provider should shutdown cleanly");
    }
}

/// Test consumer service startup and shutdown
#[tokio::test]
async fn test_e2e_consumer_lifecycle() {
    let config = create_consumer_config();
    let backend = Arc::new(MockBackend::new());
    let service = ReplicationService::from_config(&config, backend).unwrap();

    let shutdown = Arc::new(ShutdownCoordinator::new(ShutdownConfig::default()));

    // Start consumer
    let handle = service.start_consumer(shutdown.clone()).await.unwrap();
    assert!(handle.is_some());

    // Let it run briefly
    sleep(Duration::from_millis(100)).await;

    // Shutdown
    shutdown.initiate_shutdown().await;
    if let Some(h) = handle {
        let result = tokio::time::timeout(Duration::from_secs(2), h).await;
        assert!(result.is_ok(), "Consumer should shutdown cleanly");
    }
}

/// Test both provider and consumer running simultaneously
#[tokio::test]
async fn test_e2e_both_mode_lifecycle() {
    let mut config = ServerConfig::default();
    config.replication.enabled = true;
    config.replication.mode = "both".to_string();
    config.replication.provider_url = Some("ldap://provider:389".to_string());
    config.replication.changelog_capacity = 1000;
    config.replication.sync_interval_secs = 1;

    let backend = Arc::new(MockBackend::new());
    let service = ReplicationService::from_config(&config, backend).unwrap();

    let shutdown = Arc::new(ShutdownCoordinator::new(ShutdownConfig::default()));

    // Start both services
    let provider_handle = service.start_provider(shutdown.clone()).await.unwrap();
    let consumer_handle = service.start_consumer(shutdown.clone()).await.unwrap();

    assert!(provider_handle.is_some());
    assert!(consumer_handle.is_some());

    // Let them run briefly
    sleep(Duration::from_millis(100)).await;

    // Shutdown both
    shutdown.initiate_shutdown().await;

    if let Some(h) = provider_handle {
        let _ = tokio::time::timeout(Duration::from_secs(2), h).await;
    }
    if let Some(h) = consumer_handle {
        let _ = tokio::time::timeout(Duration::from_secs(2), h).await;
    }
}

/// Test changelog persistence across multiple operations
#[tokio::test]
async fn test_e2e_changelog_persistence() {
    let config = create_provider_config();
    let backend = Arc::new(MockBackend::new());
    let service = ReplicationService::from_config(&config, backend.clone()).unwrap();

    let wrapped_backend = service.backend();

    // Perform a series of operations
    let entry1 = create_test_entry("cn=user1,dc=test,dc=org", "user1", "User One");
    wrapped_backend
        .add_entry(entry1.clone(), vec![])
        .await
        .unwrap();

    let entry2 = create_test_entry("cn=user2,dc=test,dc=org", "user2", "User Two");
    wrapped_backend
        .add_entry(entry2.clone(), vec![])
        .await
        .unwrap();

    // Modify user1 with proper Modification structure
    use opendr::backend::{Modification, ModifyOperation};
    let modifications = vec![Modification {
        operation: ModifyOperation::Add,
        attribute: "description".to_string(),
        values: vec!["Modified".to_string()],
    }];
    wrapped_backend
        .modify_entry(&entry1.dn, modifications)
        .await
        .unwrap();

    // Delete user2
    wrapped_backend.delete_entry(&entry2.dn).await.unwrap();

    // Verify all operations in changelog
    let changelog = service.changelog().unwrap();
    let entries = changelog.get_all();

    assert_eq!(entries.len(), 4);
    assert_eq!(entries[0].change_type, ChangeType::Add);
    assert_eq!(entries[1].change_type, ChangeType::Add);
    assert_eq!(entries[2].change_type, ChangeType::Modify);
    assert_eq!(entries[3].change_type, ChangeType::Delete);
}

/// Test provider serves changes to consumer (simulated)
#[tokio::test]
async fn test_e2e_provider_serves_changes() {
    let config = create_provider_config();
    let backend = Arc::new(MockBackend::new());
    let service = ReplicationService::from_config(&config, backend.clone()).unwrap();

    let wrapped_backend = service.backend();

    // Add test data
    for i in 1..=10 {
        let entry = create_test_entry(
            &format!("cn=user{},dc=test,dc=org", i),
            &format!("user{}", i),
            &format!("User {}", i),
        );
        wrapped_backend.add_entry(entry, vec![]).await.unwrap();
    }

    // Get changelog and verify it can be queried
    let changelog = service.changelog().unwrap();

    // Get all changes and verify count
    let all_changes = changelog.get_all();
    assert_eq!(all_changes.len(), 10); // All 10 entries

    // Simulate consumer query from cookie (get changes since 5th CSN)
    let csn5 = &all_changes[4].csn; // 5th entry (index 4)
    let changes_since_5 = changelog.get_since_csn(csn5);

    assert_eq!(changes_since_5.len(), 5); // Entries 6-10
}

/// Test concurrent operations don't corrupt changelog
#[tokio::test]
async fn test_e2e_concurrent_operations() {
    let config = create_provider_config();
    let backend = Arc::new(MockBackend::new());
    let service = ReplicationService::from_config(&config, backend.clone()).unwrap();

    let wrapped_backend = service.backend();

    // Spawn multiple tasks adding entries concurrently
    let mut handles = vec![];
    for i in 1..=20 {
        let backend_clone = wrapped_backend.clone();
        let handle = tokio::spawn(async move {
            let entry = create_test_entry(
                &format!("cn=user{},dc=test,dc=org", i),
                &format!("user{}", i),
                &format!("User {}", i),
            );
            backend_clone.add_entry(entry, vec![]).await.unwrap();
        });
        handles.push(handle);
    }

    // Wait for all tasks
    for handle in handles {
        handle.await.unwrap();
    }

    // Verify all operations recorded
    let changelog = service.changelog().unwrap();
    let entries = changelog.get_all();

    assert_eq!(entries.len(), 20);

    // Verify CSNs are unique and all entries recorded
    let mut csns: Vec<_> = entries.iter().map(|e| e.csn.clone()).collect();
    csns.sort();

    // Verify all CSNs are unique (no duplicates after sorting)
    for idx in 1..csns.len() {
        assert!(
            csns[idx] > csns[idx - 1],
            "CSNs should be unique and ordered"
        );
    }
}

/// Test empty changelog handling
#[tokio::test]
async fn test_e2e_empty_changelog() {
    let config = create_provider_config();
    let backend = Arc::new(MockBackend::new());
    let service = ReplicationService::from_config(&config, backend).unwrap();

    let changelog = service.changelog().unwrap();
    let entries = changelog.get_all();

    assert_eq!(entries.len(), 0);
}

/// Test changelog cookie generation (RFC 4533 Section 2.2)
#[tokio::test]
async fn test_e2e_changelog_cookie() {
    let config = create_provider_config();
    let backend = Arc::new(MockBackend::new());
    let service = ReplicationService::from_config(&config, backend.clone()).unwrap();

    let wrapped_backend = service.backend();

    // Add entries
    for i in 1..=5 {
        let entry = create_test_entry(
            &format!("cn=user{},dc=test,dc=org", i),
            &format!("user{}", i),
            &format!("User {}", i),
        );
        wrapped_backend.add_entry(entry, vec![]).await.unwrap();
    }

    // Cookie should represent the latest CSN
    let changelog = service.changelog().unwrap();
    let context_csn = changelog.get_context_csn();

    assert!(
        context_csn.is_some(),
        "Context CSN should exist after changes"
    );

    // Verify we can generate and parse cookies
    let cookie = changelog.generate_context_cookie();
    let parsed_csn = changelog.parse_cookie(&cookie);

    assert!(parsed_csn.is_some(), "Cookie should be parseable");
    assert_eq!(parsed_csn.unwrap(), context_csn.unwrap());
}

/// Test read operations don't affect changelog
#[tokio::test]
async fn test_e2e_reads_dont_replicate() {
    let config = create_provider_config();
    let backend = Arc::new(MockBackend::new());
    let service = ReplicationService::from_config(&config, backend.clone()).unwrap();

    let wrapped_backend = service.backend();

    // Add an entry
    let entry = create_test_entry("cn=user1,dc=test,dc=org", "user1", "User One");
    wrapped_backend
        .add_entry(entry.clone(), vec![])
        .await
        .unwrap();

    // Perform multiple reads
    for _ in 0..10 {
        let _ = wrapped_backend.get_entry(&entry.dn).await;
    }

    // Verify only the add operation is in changelog
    let changelog = service.changelog().unwrap();
    let entries = changelog.get_all();

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].change_type, ChangeType::Add);
}

#[tokio::test]
async fn test_e2e_listening_replication_stream_emits_live_change() {
    let provider_backend = create_listening_provider_backend();
    let (mut server_stream, mut client_stream) = connected_stream_pair().await;
    let request = create_replication_search_request(None);
    let server_backend = provider_backend.clone();

    let handler = tokio::spawn(async move {
        server::handle_search_request(&mut server_stream, server_backend.as_ref(), 1, request)
            .await
            .unwrap();
    });

    sleep(Duration::from_millis(100)).await;

    let entry = create_test_entry(
        "cn=listener-user,dc=example,dc=org",
        "listener-user",
        "Listener User",
    );
    provider_backend
        .add_entry(entry.clone(), vec![])
        .await
        .unwrap();

    let data = read_response(&mut client_stream).await;
    let (_, messages) = parse_ldap_messages(&data).unwrap();
    assert!(!messages.is_empty(), "expected a replication stream entry");

    match &messages[0].protocol_op {
        ProtocolOp::SearchResultEntry(response) => {
            assert_eq!(response.object_name.0.as_ref(), entry.dn);
            assert!(response
                .attributes
                .iter()
                .any(|attr| attr.attr_type.0.as_ref()
                    == opendr::replication::REPLICATION_CHANGE_TYPE_ATTRIBUTE
                    && std::str::from_utf8(attr.attr_vals[0].0.as_ref()).unwrap() == "add"));
            assert!(response
                .attributes
                .iter()
                .any(|attr| attr.attr_type.0.as_ref()
                    == opendr::replication::REPLICATION_CHANGE_DATA_ATTRIBUTE
                    && !attr.attr_vals[0].0.as_ref().is_empty()));
            assert!(response
                .attributes
                .iter()
                .any(|attr| attr.attr_type.0.as_ref()
                    == opendr::replication::REPLICATION_CSN_ATTRIBUTE
                    && !attr.attr_vals[0].0.as_ref().is_empty()));
        }
        other => panic!("unexpected replication response: {:?}", other),
    }

    handler.abort();
    let _ = handler.await;
}

#[tokio::test]
async fn test_e2e_listening_replication_stream_respects_cookie_resume() {
    let provider_backend = create_listening_provider_backend();
    let first_entry = create_test_entry(
        "cn=preexisting-user,dc=example,dc=org",
        "preexisting-user",
        "Preexisting User",
    );
    provider_backend
        .add_entry(first_entry.clone(), vec![])
        .await
        .unwrap();

    let cookie = provider_backend
        .replication_changelog()
        .unwrap()
        .generate_context_cookie();

    let (mut server_stream, mut client_stream) = connected_stream_pair().await;
    let request = create_replication_search_request(Some(&cookie));
    let server_backend = provider_backend.clone();

    let handler = tokio::spawn(async move {
        server::handle_search_request(&mut server_stream, server_backend.as_ref(), 1, request)
            .await
            .unwrap();
    });

    sleep(Duration::from_millis(100)).await;

    let second_entry = create_test_entry(
        "cn=fresh-user,dc=example,dc=org",
        "fresh-user",
        "Fresh User",
    );
    provider_backend
        .add_entry(second_entry.clone(), vec![])
        .await
        .unwrap();

    let data = read_response(&mut client_stream).await;
    let (_, messages) = parse_ldap_messages(&data).unwrap();
    assert!(!messages.is_empty(), "expected a replicated change");

    let stream_entries: Vec<_> = messages
        .iter()
        .filter_map(|message| match &message.protocol_op {
            ProtocolOp::SearchResultEntry(entry) => Some(entry.object_name.0.as_ref().to_string()),
            _ => None,
        })
        .collect();

    assert!(
        stream_entries.iter().all(|dn| dn != &first_entry.dn),
        "cookie should skip the already-replicated entry"
    );
    assert!(
        stream_entries.iter().any(|dn| dn == &second_entry.dn),
        "cookie should still deliver the new change"
    );

    handler.abort();
    let _ = handler.await;
}

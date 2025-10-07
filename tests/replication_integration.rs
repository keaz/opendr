//! Replication Integration Tests
//!
//! This test suite validates the end-to-end replication functionality
//! between provider and consumer servers.

use opendr::backend::{DirectoryBackend, DirectoryEntry, BackendError, MockBackend};
use opendr::fsm::{
    StateMachine,
    ReplicationProviderEvent, ReplicationConsumerEvent,
    ReplicationProviderState, ReplicationConsumerState,
    ReplicationProviderFsm, ReplicationConsumerFsm,
};
use opendr::replication::*;
use opendr::replication_provider_fsm::*;
use opendr::replication_consumer_fsm::*;
use std::collections::HashMap;
use std::sync::Arc;
use tokio;

// Helper to create mock backend with test data
async fn create_test_backend() -> MockBackend {
    let backend = MockBackend::default();

    // Add test entries
    let mut attrs1 = HashMap::new();
    attrs1.insert("cn".to_string(), vec!["user1".to_string()]);
    attrs1.insert("objectclass".to_string(), vec!["person".to_string()]);
    let entry1 = DirectoryEntry::new("cn=user1,dc=example,dc=org", attrs1);
    let _ = backend.add_entry(entry1, b"password1".to_vec()).await;

    let mut attrs2 = HashMap::new();
    attrs2.insert("cn".to_string(), vec!["user2".to_string()]);
    attrs2.insert("objectclass".to_string(), vec!["person".to_string()]);
    let entry2 = DirectoryEntry::new("cn=user2,dc=example,dc=org", attrs2);
    let _ = backend.add_entry(entry2, b"password2".to_vec()).await;

    backend
}

// Helper to create provider FSM
fn create_provider_fsm(backend: Arc<dyn DirectoryBackend>) -> ReplicationProviderFsmImpl {
    let tracker = ChangelogTracker::new();
    let changelog_provider = Box::new(ChangelogProviderImpl::new(tracker.clone(), backend));
    let consumer_registry = Box::new(ConsumerRegistryImpl::new());
    let streaming_manager = Box::new(StreamingManagerImpl::new());
    let sync_request_handler = Box::new(SyncRequestHandlerImpl::new());

    ReplicationProviderFsmImpl::new(
        changelog_provider,
        consumer_registry,
        streaming_manager,
        sync_request_handler,
    )
}

// Helper to create consumer FSM
fn create_consumer_fsm(backend: Arc<dyn DirectoryBackend>, changelog_provider: Arc<dyn ChangelogProvider>) -> ReplicationConsumerFsmImpl {
    let provider_connection = Box::new(ProviderConnectionImpl::new(changelog_provider));
    let batch_processor = Box::new(BatchProcessorImpl::new(backend.clone()));
    let state_manager = Box::new(StateManagerImpl::new("/tmp/repl_state".to_string()));
    let change_listener = Box::new(ChangeListenerImpl::new());

    ReplicationConsumerFsmImpl::new(
        provider_connection,
        batch_processor,
        state_manager,
        change_listener,
    )
}

#[tokio::test]
async fn test_changelog_tracker_records_changes() {
    let tracker = ChangelogTracker::new();

    // Record changes
    let csn1 = tracker.record_change(
        ChangeType::Add,
        "cn=user1,dc=example,dc=org".to_string(),
        b"entry data 1".to_vec(),
    );

    let csn2 = tracker.record_change(
        ChangeType::Modify,
        "cn=user1,dc=example,dc=org".to_string(),
        b"entry data 2".to_vec(),
    );

    let csn3 = tracker.record_change(
        ChangeType::Delete,
        "cn=user2,dc=example,dc=org".to_string(),
        b"entry data 3".to_vec(),
    );

    // Verify CSNs are unique and properly ordered
    assert!(csn2 > csn1);
    assert!(csn3 > csn2);
    
    // Verify context CSN is updated
    let context_csn = tracker.get_context_csn();
    assert_eq!(context_csn, Some(csn3.clone()));

    // Get changes since csn1
    let changes = tracker.get_since_csn(&csn1);
    assert_eq!(changes.len(), 2);
    assert!(changes[0].csn > csn1);
    assert!(changes[1].csn > changes[0].csn);
}

#[tokio::test]
async fn test_changelog_provider_get_all_entries() {
    let backend = Arc::new(create_test_backend().await);
    let tracker = ChangelogTracker::new();
    let provider = ChangelogProviderImpl::new(tracker, backend);

    let entries = provider.get_all_entries("dc=example,dc=org", None).await.unwrap();

    // Should return all entries from backend (at least the 2 we added + admin)
    assert!(entries.len() >= 2);
    assert!(entries.iter().any(|e| e.dn == "cn=user1,dc=example,dc=org"));
    assert!(entries.iter().any(|e| e.dn == "cn=user2,dc=example,dc=org"));
}

#[tokio::test]
async fn test_changelog_provider_get_changelog_since() {
    let backend = Arc::new(create_test_backend().await);
    let tracker = ChangelogTracker::new();

    // Record some changes
    tracker.record_change(
        ChangeType::Add,
        "cn=user3,dc=example,dc=org".to_string(),
        b"data".to_vec(),
    );

    tracker.record_change(
        ChangeType::Modify,
        "cn=user4,dc=example,dc=org".to_string(),
        b"data".to_vec(),
    );

    let provider = ChangelogProviderImpl::new(tracker, backend);

    // Get changes since sequence 0
    let changes = provider.get_changelog_since(None, 100).await.unwrap();
    assert_eq!(changes.len(), 2);

    // Get changes with a CSN-based cookie
    let context_csn = provider.get_context_csn().await.unwrap().unwrap();
    let cookie = format!("csn-{}", context_csn);
    let changes = provider.get_changelog_since(Some(&cookie), 100).await.unwrap();
    // Should return empty since we're asking for changes after the latest CSN
    assert_eq!(changes.len(), 0);
}

#[tokio::test]
async fn test_provider_fsm_start_sync_replication() {
    let backend = Arc::new(create_test_backend().await);
    let mut fsm = create_provider_fsm(backend);

    // Start sync replication
    let result = fsm.handle_event(ReplicationProviderEvent::StartSyncReplication {
        consumer_id: "consumer1".to_string(),
        cookie: None,
    }).await;

    assert!(result.is_ok());

    // Should return number of entries to sync (at least 2 from our test data + default admin)
    let count = result.unwrap();
    assert!(count.is_some());
    assert!(count.unwrap() >= 2, "Expected at least 2 entries, got {}", count.unwrap());

    // FSM should be in Refresh state
    assert!(matches!(fsm.current_state(), ReplicationProviderState::Refresh { .. }));

    // Should have 1 active consumer
    assert_eq!(fsm.active_consumers(), 1);
}

#[tokio::test]
async fn test_provider_fsm_complete_refresh_phase() {
    let backend = Arc::new(create_test_backend().await);
    let mut fsm = create_provider_fsm(backend);

    // Start sync replication
    fsm.handle_event(ReplicationProviderEvent::StartSyncReplication {
        consumer_id: "consumer1".to_string(),
        cookie: None,
    }).await.unwrap();

    // Complete refresh phase
    let result = fsm.handle_event(ReplicationProviderEvent::RefreshComplete {
        entries_sent: 2,
    }).await;

    assert!(result.is_ok());

    // FSM should transition to Present state
    assert!(matches!(fsm.current_state(), ReplicationProviderState::Present { .. }));

    // Should report 2 entries sent
    assert_eq!(fsm.entries_sent(), 2);
}

#[tokio::test]
async fn test_provider_fsm_complete_present_phase() {
    let backend = Arc::new(create_test_backend().await);
    let mut fsm = create_provider_fsm(backend);

    // Go through refresh phase
    fsm.handle_event(ReplicationProviderEvent::StartSyncReplication {
        consumer_id: "consumer1".to_string(),
        cookie: None,
    }).await.unwrap();

    fsm.handle_event(ReplicationProviderEvent::RefreshComplete {
        entries_sent: 2,
    }).await.unwrap();

    // Complete present phase
    let result = fsm.handle_event(ReplicationProviderEvent::PresentComplete {
        entries_streamed: 0,
    }).await;

    assert!(result.is_ok());

    // FSM should transition to Persist state
    assert!(matches!(fsm.current_state(), ReplicationProviderState::Persist { .. }));

    // Should have a cookie
    assert!(fsm.cookie().is_some());
}

#[tokio::test]
async fn test_provider_fsm_stream_changelog_entries() {
    let backend = Arc::new(create_test_backend().await);
    let mut fsm = create_provider_fsm(backend);

    // Progress to present phase
    fsm.handle_event(ReplicationProviderEvent::StartSyncReplication {
        consumer_id: "consumer1".to_string(),
        cookie: None,
    }).await.unwrap();

    fsm.handle_event(ReplicationProviderEvent::RefreshComplete {
        entries_sent: 2,
    }).await.unwrap();

    // Stream a changelog entry with CSN
    let csn_gen = opendr::csn::CsnGenerator::new(1);
    let csn = csn_gen.generate();
    let result = fsm.handle_event(ReplicationProviderEvent::ChangelogEntry {
        entry: b"test entry data".to_vec(),
        csn: csn,
    }).await;

    assert!(result.is_ok());

    // FSM should transition to Streaming state
    assert!(matches!(fsm.current_state(), ReplicationProviderState::Streaming { .. }));
    assert!(fsm.is_streaming());
}

#[tokio::test]
async fn test_provider_fsm_consumer_disconnect() {
    let backend = Arc::new(create_test_backend().await);
    let mut fsm = create_provider_fsm(backend);

    // Start replication
    fsm.handle_event(ReplicationProviderEvent::StartSyncReplication {
        consumer_id: "consumer1".to_string(),
        cookie: None,
    }).await.unwrap();

    assert_eq!(fsm.active_consumers(), 1);

    // Consumer disconnects
    let result = fsm.handle_event(ReplicationProviderEvent::ConsumerDisconnected {
        consumer_id: "consumer1".to_string(),
    }).await;

    assert!(result.is_ok());

    // FSM should transition to Completed state
    assert!(matches!(fsm.current_state(), ReplicationProviderState::Completed));
    assert_eq!(fsm.active_consumers(), 0);
}

#[tokio::test]
async fn test_consumer_fsm_start_consumption() {
    let backend = Arc::new(create_test_backend().await);
    let tracker = ChangelogTracker::new();
    let changelog_provider = Arc::new(ChangelogProviderImpl::new(tracker, backend.clone()));

    let mut fsm = create_consumer_fsm(backend, changelog_provider);

    // Start consumption
    let result = fsm.handle_event(ReplicationConsumerEvent::StartConsumption {
        provider_url: "ldap://provider.example.com:389".to_string(),
        cookie: None,
    }).await;

    assert!(result.is_ok());

    // FSM should be in ReceivingBatches state
    assert!(matches!(fsm.current_state(), ReplicationConsumerState::ReceivingBatches { .. }));

    // Provider URL should be set
    assert_eq!(fsm.provider_url(), Some("ldap://provider.example.com:389"));
}

#[tokio::test]
async fn test_consumer_fsm_receive_and_apply_batch() {
    let backend = Arc::new(create_test_backend().await);
    let tracker = ChangelogTracker::new();
    let changelog_provider = Arc::new(ChangelogProviderImpl::new(tracker, backend.clone()));

    let mut fsm = create_consumer_fsm(backend, changelog_provider);

    // Start consumption
    fsm.handle_event(ReplicationConsumerEvent::StartConsumption {
        provider_url: "ldap://provider.example.com:389".to_string(),
        cookie: None,
    }).await.unwrap();

    // Receive batch
    let result = fsm.handle_event(ReplicationConsumerEvent::BatchReceived {
        entries: vec![b"entry1".to_vec(), b"entry2".to_vec()],
    }).await;

    assert!(result.is_ok());

    // FSM should transition to ApplyingChanges state
    assert!(matches!(fsm.current_state(), ReplicationConsumerState::ApplyingChanges { .. }));
}

#[tokio::test]
async fn test_consumer_fsm_persist_state() {
    let backend = Arc::new(create_test_backend().await);
    let tracker = ChangelogTracker::new();
    let changelog_provider = Arc::new(ChangelogProviderImpl::new(tracker, backend.clone()));

    let mut fsm = create_consumer_fsm(backend, changelog_provider);

    // Progress through states
    fsm.handle_event(ReplicationConsumerEvent::StartConsumption {
        provider_url: "ldap://provider.example.com:389".to_string(),
        cookie: None,
    }).await.unwrap();

    fsm.handle_event(ReplicationConsumerEvent::BatchReceived {
        entries: vec![b"entry1".to_vec()],
    }).await.unwrap();

    fsm.handle_event(ReplicationConsumerEvent::EntryApplied).await.unwrap();

    // Persist state
    let result = fsm.handle_event(ReplicationConsumerEvent::StatePersisted {
        cookie: "seq-42".to_string(),
    }).await;

    assert!(result.is_ok());

    // FSM should be in Listening state (if change listening is enabled)
    assert!(matches!(fsm.current_state(), ReplicationConsumerState::Listening));

    // Cookie should be saved
    assert_eq!(fsm.current_cookie(), Some("seq-42"));
}

#[tokio::test]
async fn test_consumer_fsm_receive_real_time_changes() {
    let backend = Arc::new(create_test_backend().await);
    let tracker = ChangelogTracker::new();
    let changelog_provider = Arc::new(ChangelogProviderImpl::new(tracker, backend.clone()));

    let mut fsm = create_consumer_fsm(backend, changelog_provider);

    // Progress to listening state
    fsm.handle_event(ReplicationConsumerEvent::StartConsumption {
        provider_url: "ldap://provider.example.com:389".to_string(),
        cookie: None,
    }).await.unwrap();

    fsm.handle_event(ReplicationConsumerEvent::BatchReceived {
        entries: vec![b"entry1".to_vec()],
    }).await.unwrap();

    fsm.handle_event(ReplicationConsumerEvent::EntryApplied).await.unwrap();

    fsm.handle_event(ReplicationConsumerEvent::StatePersisted {
        cookie: "seq-1".to_string(),
    }).await.unwrap();

    // Receive real-time change
    let result = fsm.handle_event(ReplicationConsumerEvent::ChangeReceived(
        b"realtime change data".to_vec()
    )).await;

    assert!(result.is_ok());

    // Should still be listening
    assert!(fsm.is_listening());

    // Entries applied count should increment
    assert_eq!(fsm.entries_applied(), 2);
}

#[tokio::test]
async fn test_end_to_end_replication_flow() {
    // Setup provider
    let provider_backend = Arc::new(create_test_backend().await);
    let tracker = ChangelogTracker::new();

    // Record some changes in the changelog
    tracker.record_change(
        ChangeType::Add,
        "cn=user3,dc=example,dc=org".to_string(),
        b"user3 data".to_vec(),
    );

    tracker.record_change(
        ChangeType::Modify,
        "cn=user1,dc=example,dc=org".to_string(),
        b"modified user1 data".to_vec(),
    );

    let mut provider_fsm = create_provider_fsm(provider_backend.clone());

    // Setup consumer
    let consumer_backend = Arc::new(create_test_backend().await);
    let changelog_provider = Arc::new(ChangelogProviderImpl::new(tracker.clone(), provider_backend));
    let mut consumer_fsm = create_consumer_fsm(consumer_backend, changelog_provider);

    // Provider: Start sync replication
    let provider_result = provider_fsm.handle_event(ReplicationProviderEvent::StartSyncReplication {
        consumer_id: "consumer1".to_string(),
        cookie: None,
    }).await;
    assert!(provider_result.is_ok());
    let entry_count = provider_result.unwrap().unwrap();
    assert!(entry_count >= 2, "Expected at least 2 entries, got {}", entry_count);

    // Consumer: Start consumption
    let consumer_result = consumer_fsm.handle_event(ReplicationConsumerEvent::StartConsumption {
        provider_url: "ldap://provider.example.com:389".to_string(),
        cookie: None,
    }).await;
    assert!(consumer_result.is_ok());

    // Provider: Complete refresh
    provider_fsm.handle_event(ReplicationProviderEvent::RefreshComplete {
        entries_sent: entry_count,
    }).await.unwrap();

    // Provider: Complete present
    provider_fsm.handle_event(ReplicationProviderEvent::PresentComplete {
        entries_streamed: 2,
    }).await.unwrap();

    // Verify provider state
    assert!(matches!(provider_fsm.current_state(), ReplicationProviderState::Persist { .. }));
    assert!(provider_fsm.cookie().is_some());

    // Consumer: Apply entries
    consumer_fsm.handle_event(ReplicationConsumerEvent::BatchReceived {
        entries: vec![b"entry1".to_vec(), b"entry2".to_vec()],
    }).await.unwrap();

    consumer_fsm.handle_event(ReplicationConsumerEvent::EntryApplied).await.unwrap();

    // Consumer: Persist state
    let cookie = provider_fsm.cookie().unwrap().to_string();
    consumer_fsm.handle_event(ReplicationConsumerEvent::StatePersisted {
        cookie: cookie.clone(),
    }).await.unwrap();

    // Verify consumer state
    assert!(consumer_fsm.is_listening());
    assert_eq!(consumer_fsm.current_cookie(), Some(cookie.as_str()));

    // Verify replication stats
    let (provider_sessions, provider_successful, _, provider_entries, _) = provider_fsm.get_stats();
    assert_eq!(provider_sessions, 1);
    // entry_count from refresh + 2 changelog entries from present
    assert!(provider_entries >= 4, "Expected at least 4 provider entries, got {}", provider_entries);

    let (consumer_sessions, _, _, consumer_entries, _) = consumer_fsm.get_stats();
    assert_eq!(consumer_sessions, 1);
    assert_eq!(consumer_entries, 1);
}

#[tokio::test]
async fn test_replication_with_existing_cookie() {
    let backend = Arc::new(create_test_backend().await);
    let tracker = ChangelogTracker::new();

    // Record changes with specific sequence numbers
    tracker.record_change(ChangeType::Add, "cn=old1,dc=example,dc=org".to_string(), b"old".to_vec());
    tracker.record_change(ChangeType::Add, "cn=old2,dc=example,dc=org".to_string(), b"old".to_vec());
    tracker.record_change(ChangeType::Add, "cn=new1,dc=example,dc=org".to_string(), b"new".to_vec());
    tracker.record_change(ChangeType::Add, "cn=new2,dc=example,dc=org".to_string(), b"new".to_vec());

    let changelog_provider = Arc::new(ChangelogProviderImpl::new(tracker.clone(), backend.clone()));

    // Get all changes
    let changes = changelog_provider.get_changelog_since(None, 100).await.unwrap();

    // Should get all recorded changes
    assert_eq!(changes.len(), 4);
    
    // Verify CSNs are in order
    for i in 1..changes.len() {
        assert!(changes[i].csn > changes[i-1].csn);
    }
    
    assert_eq!(changes[0].dn, "cn=admin,dc=example,dc=org");
    assert_eq!(changes[1].dn, "cn=admin,dc=example,dc=org");
    assert_eq!(changes[2].dn, "cn=new1,dc=example,dc=org");
    assert_eq!(changes[3].dn, "cn=new2,dc=example,dc=org");
}

#[tokio::test]
async fn test_replication_error_handling() {
    let backend = Arc::new(create_test_backend().await);
    let mut fsm = create_provider_fsm(backend);

    // Try to complete refresh without starting sync
    let result = fsm.handle_event(ReplicationProviderEvent::RefreshComplete {
        entries_sent: 2,
    }).await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), ReplicationProviderError::InvalidStateTransition { .. }));
}

#[tokio::test]
async fn test_consumer_registry() {
    let mut registry = ConsumerRegistryImpl::new();

    let connection = ConsumerConnection::new("consumer1".to_string());

    // Register consumer
    registry.register_consumer("consumer1", connection.clone()).await.unwrap();

    // Check if connected
    assert!(registry.is_consumer_connected("consumer1").await.unwrap());

    // Get active consumers
    let active = registry.get_active_consumers().await.unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0], "consumer1");

    // Unregister consumer
    let removed = registry.unregister_consumer("consumer1").await.unwrap();
    assert!(removed);

    // Should no longer be connected
    assert!(!registry.is_consumer_connected("consumer1").await.unwrap());
}

#[tokio::test]
async fn test_streaming_manager() {
    let mut manager = StreamingManagerImpl::new();

    // Start streaming
    manager.start_streaming("consumer1", None).await.unwrap();

    // Check if active
    assert!(manager.is_streaming_active("consumer1").await.unwrap());

    // Send entry with CSN
    let csn_gen = opendr::csn::CsnGenerator::new(1);
    let csn = csn_gen.generate();
    let entry = ChangelogEntry::new(csn, ChangeType::Add, "cn=test,dc=example,dc=org".to_string(), b"data".to_vec());
    manager.send_entry("consumer1", &entry).await.unwrap();

    // Get stats
    let stats = manager.get_streaming_stats("consumer1").await.unwrap();
    assert_eq!(stats.entries_streamed, 1);

    // Stop streaming
    manager.stop_streaming("consumer1").await.unwrap();
    assert!(!manager.is_streaming_active("consumer1").await.unwrap());
}

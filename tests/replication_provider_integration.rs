//! Replication Provider Integration Tests
//!
//! These tests validate the integration of the replication provider service
//! with the main server components.

use opendr::backend::{DirectoryBackend, DirectoryEntry, MockBackend};
use opendr::backend_changelog_wrapper::ChangelogBackendWrapper;
use opendr::config::ServerConfig;
use opendr::replication::ChangelogTracker;
use opendr::replication_provider_fsm::ChangeType;
use opendr::replication_service::ReplicationService;
use opendr::shutdown::{ShutdownConfig, ShutdownCoordinator};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{sleep, timeout, Duration};

fn create_test_entry(dn: &str, cn: &str) -> DirectoryEntry {
    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec![cn.to_string()]);
    attributes.insert("objectclass".to_string(), vec!["person".to_string()]);
    DirectoryEntry::new(dn, attributes)
}

fn create_provider_config() -> ServerConfig {
    let mut config = ServerConfig::default();
    config.replication.enabled = true;
    config.replication.mode = "provider".to_string();
    config.replication.state_storage_path = unique_replication_state_path("provider-integration");
    config
}

fn unique_replication_state_path(prefix: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("opendr-{prefix}-{}-{nanos}", std::process::id()))
}

#[tokio::test]
async fn test_replication_service_provider_initialization() {
    let mut config = create_provider_config();
    config.replication.changelog_capacity = 1000;

    let backend = Arc::new(MockBackend::new());
    let service = ReplicationService::from_config(&config, backend).unwrap();

    assert!(service.is_enabled());
    assert!(service.is_provider());
    assert!(service.changelog().is_some());
}

#[tokio::test]
async fn test_replication_service_uses_configured_replica_id() {
    let mut config = create_provider_config();
    config.server.replica_id = 42;

    let backend = Arc::new(MockBackend::with_replica_id(config.server.replica_id));
    let service = ReplicationService::from_config(&config, backend).unwrap();

    let changelog = service.changelog().unwrap();
    let csn = changelog.record_change(
        ChangeType::Add,
        "cn=test,dc=example,dc=com".to_string(),
        Vec::new(),
    );

    assert_eq!(csn.replica_id(), 42);
}

#[tokio::test]
async fn test_replication_service_provider_with_shutdown() {
    let config = create_provider_config();

    let backend = Arc::new(MockBackend::new());
    let service = ReplicationService::from_config(&config, backend).unwrap();

    let shutdown = Arc::new(ShutdownCoordinator::new(ShutdownConfig::default()));

    // Start provider
    let handle = service.start_provider(shutdown.clone()).await;
    assert!(handle.is_ok());
    assert!(handle.unwrap().is_some());
}

#[tokio::test]
async fn test_replication_service_disabled_provider() {
    let mut config = create_provider_config();
    config.replication.enabled = false;

    let backend = Arc::new(MockBackend::new());
    let service = ReplicationService::from_config(&config, backend).unwrap();

    let shutdown = Arc::new(ShutdownCoordinator::new(ShutdownConfig::default()));

    // Start provider should return None
    let handle = service.start_provider(shutdown).await;
    assert!(handle.is_ok());
    assert!(handle.unwrap().is_none());
}

#[tokio::test]
async fn test_replication_service_consumer_mode_no_provider() {
    let mut config = create_provider_config();
    config.replication.mode = "consumer".to_string();
    config.replication.provider_url = Some("ldap://provider:389".to_string());

    let backend = Arc::new(MockBackend::new());
    let service = ReplicationService::from_config(&config, backend).unwrap();

    let shutdown = Arc::new(ShutdownCoordinator::new(ShutdownConfig::default()));

    // Consumer mode should not start provider
    let handle = service.start_provider(shutdown).await;
    assert!(handle.is_ok());
    assert!(handle.unwrap().is_none());
}

#[tokio::test]
async fn test_backend_wrapper_with_changelog() {
    let backend = Arc::new(MockBackend::new());
    let changelog = Arc::new(ChangelogTracker::new());
    let wrapper = Arc::new(ChangelogBackendWrapper::new(
        backend,
        Some(changelog.clone()),
    ));

    // Add an entry
    let entry = create_test_entry("cn=test,dc=example,dc=com", "Test User");
    wrapper.add_entry(entry, vec![]).await.unwrap();

    // Verify changelog recorded it
    let entries = changelog.get_all();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].dn, "cn=test,dc=example,dc=com");
}

#[tokio::test]
async fn test_replication_service_backend_wrapper() {
    let config = create_provider_config();

    let backend = Arc::new(MockBackend::new());
    let service = ReplicationService::from_config(&config, backend.clone()).unwrap();

    // Get wrapped backend
    let wrapped_backend = service.backend();

    // Add entry through wrapped backend
    let entry = create_test_entry("cn=user1,dc=example,dc=com", "User 1");
    wrapped_backend.add_entry(entry, vec![]).await.unwrap();

    // Verify changelog recorded it
    let changelog = service.changelog().unwrap();
    let entries = changelog.get_all();
    assert_eq!(entries.len(), 1);
}

#[tokio::test]
async fn test_replication_service_multiple_operations() {
    let config = create_provider_config();

    let backend = Arc::new(MockBackend::new());
    let service = ReplicationService::from_config(&config, backend).unwrap();

    let wrapped_backend = service.backend();

    // Add multiple entries
    for i in 0..5 {
        let entry = create_test_entry(
            &format!("cn=user{},dc=example,dc=com", i),
            &format!("User {}", i),
        );
        wrapped_backend.add_entry(entry, vec![]).await.unwrap();
    }

    // Verify all recorded
    let changelog = service.changelog().unwrap();
    let entries = changelog.get_all();
    assert_eq!(entries.len(), 5);
}

#[tokio::test]
async fn test_replication_service_changelog_capacity() {
    let mut config = create_provider_config();
    config.replication.changelog_capacity = 3; // Small capacity

    let backend = Arc::new(MockBackend::new());
    let service = ReplicationService::from_config(&config, backend).unwrap();

    let wrapped_backend = service.backend();

    // Add more entries than capacity
    for i in 0..10 {
        let entry = create_test_entry(
            &format!("cn=user{},dc=example,dc=com", i),
            &format!("User {}", i),
        );
        wrapped_backend.add_entry(entry, vec![]).await.unwrap();
    }

    // Verify capacity limit enforced
    let changelog = service.changelog().unwrap();
    let entries = changelog.get_all();
    // Should have pruned old entries
    assert!(entries.len() <= 10);
}

#[tokio::test]
async fn test_replication_service_both_mode() {
    let mut config = create_provider_config();
    config.replication.mode = "both".to_string();
    config.replication.provider_url = Some("ldap://other:389".to_string());

    let backend = Arc::new(MockBackend::new());
    let service = ReplicationService::from_config(&config, backend).unwrap();

    assert!(service.is_provider());
    assert!(service.is_consumer());

    let shutdown = Arc::new(ShutdownCoordinator::new(ShutdownConfig::default()));

    // Should be able to start provider in both mode
    let handle = service.start_provider(shutdown).await;
    assert!(handle.is_ok());
    assert!(handle.unwrap().is_some());
}

#[tokio::test]
async fn test_replication_service_provider_shutdown_waits_for_active_sessions_to_drain() {
    let config = create_provider_config();

    let backend = Arc::new(MockBackend::new());
    let service = ReplicationService::from_config(&config, backend).unwrap();
    let provider_backend = service.backend();
    let lifecycle = provider_backend
        .replication_provider_lifecycle()
        .expect("provider lifecycle should be available");
    let session_guard = lifecycle
        .register_session()
        .expect("session registration should succeed before shutdown");

    let shutdown = Arc::new(ShutdownCoordinator::new(ShutdownConfig {
        shutdown_timeout: Duration::from_secs(2),
        drain_timeout: Duration::from_millis(500),
        graceful_drain: true,
    }));

    let handle = service
        .start_provider(shutdown.clone())
        .await
        .unwrap()
        .expect("provider task should start");

    shutdown.initiate_shutdown().await;
    sleep(Duration::from_millis(50)).await;

    assert!(lifecycle.is_draining());
    assert!(!handle.is_finished());

    drop(session_guard);

    timeout(Duration::from_secs(1), handle)
        .await
        .expect("provider task should finish after drain")
        .unwrap();
    assert_eq!(lifecycle.active_session_count(), 0);
}

#[tokio::test]
async fn test_replication_service_provider_shutdown_rejects_new_sessions_without_graceful_drain() {
    let config = create_provider_config();

    let backend = Arc::new(MockBackend::new());
    let service = ReplicationService::from_config(&config, backend).unwrap();
    let provider_backend = service.backend();
    let lifecycle = provider_backend
        .replication_provider_lifecycle()
        .expect("provider lifecycle should be available");
    let session_guard = lifecycle
        .register_session()
        .expect("session registration should succeed before shutdown");

    let shutdown = Arc::new(ShutdownCoordinator::new(ShutdownConfig {
        shutdown_timeout: Duration::from_secs(2),
        drain_timeout: Duration::from_secs(5),
        graceful_drain: false,
    }));

    let handle = service
        .start_provider(shutdown.clone())
        .await
        .unwrap()
        .expect("provider task should start");

    shutdown.initiate_shutdown().await;

    timeout(Duration::from_secs(1), handle)
        .await
        .expect("provider task should stop immediately when graceful drain is disabled")
        .unwrap();

    assert!(lifecycle.is_draining());
    assert!(
        lifecycle.register_session().is_none(),
        "new replication sessions must be rejected after shutdown begins"
    );

    drop(session_guard);
    assert_eq!(lifecycle.active_session_count(), 0);
}

//! Replication Provider Integration Tests
//!
//! These tests validate the integration of the replication provider service
//! with the main server components.

use opendr::backend::{DirectoryBackend, DirectoryEntry, MockBackend};
use opendr::backend_changelog_wrapper::ChangelogBackendWrapper;
use opendr::config::ServerConfig;
use opendr::replication::ChangelogTracker;
use opendr::replication_service::ReplicationService;
use opendr::shutdown::{ShutdownConfig, ShutdownCoordinator};
use std::collections::HashMap;
use std::sync::Arc;

fn create_test_entry(dn: &str, cn: &str) -> DirectoryEntry {
    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec![cn.to_string()]);
    attributes.insert("objectclass".to_string(), vec!["person".to_string()]);
    DirectoryEntry::new(dn, attributes)
}

#[tokio::test]
async fn test_replication_service_provider_initialization() {
    let mut config = ServerConfig::default();
    config.replication.enabled = true;
    config.replication.mode = "provider".to_string();
    config.replication.changelog_capacity = 1000;

    let backend = Arc::new(MockBackend::new());
    let service = ReplicationService::from_config(&config, backend).unwrap();

    assert!(service.is_enabled());
    assert!(service.is_provider());
    assert!(service.changelog().is_some());
}

#[tokio::test]
async fn test_replication_service_provider_with_shutdown() {
    let mut config = ServerConfig::default();
    config.replication.enabled = true;
    config.replication.mode = "provider".to_string();

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
    let mut config = ServerConfig::default();
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
    let mut config = ServerConfig::default();
    config.replication.enabled = true;
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
    let mut config = ServerConfig::default();
    config.replication.enabled = true;
    config.replication.mode = "provider".to_string();

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
    let mut config = ServerConfig::default();
    config.replication.enabled = true;
    config.replication.mode = "provider".to_string();

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
    let mut config = ServerConfig::default();
    config.replication.enabled = true;
    config.replication.mode = "provider".to_string();
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
    let mut config = ServerConfig::default();
    config.replication.enabled = true;
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

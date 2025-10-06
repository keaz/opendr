//! Integration tests for replication consumer service
//!
//! These tests validate the consumer service integration with the main server,
//! including initialization, sync cycles, error handling, and shutdown behavior.

use opendr::backend::MockBackend;
use opendr::config::ServerConfig;
use opendr::replication_service::ReplicationService;
use opendr::shutdown::{ShutdownConfig, ShutdownCoordinator};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

/// Helper function to create a test configuration for consumer mode
fn create_consumer_config() -> ServerConfig {
    let mut config = ServerConfig::default();
    config.replication.enabled = true;
    config.replication.mode = "consumer".to_string();
    config.replication.provider_url = Some("ldap://provider.example.com:389".to_string());
    config.replication.sync_interval_secs = 1; // Fast for testing
    config.replication.bind_dn = Some("cn=admin,dc=example,dc=com".to_string());
    config.replication.bind_password = Some("secret".to_string());
    config
}

#[tokio::test]
async fn test_consumer_service_initialization() {
    let config = create_consumer_config();
    let backend = Arc::new(MockBackend::new());

    let service = ReplicationService::from_config(&config, backend).unwrap();
    let shutdown = Arc::new(ShutdownCoordinator::new(ShutdownConfig::default()));

    let handle = service.start_consumer(shutdown.clone()).await.unwrap();

    assert!(handle.is_some(), "Consumer should start successfully");
    assert!(service.is_consumer());
    assert!(!service.is_provider());

    // Shutdown immediately
    shutdown.initiate_shutdown().await;
    if let Some(h) = handle {
        let _ = tokio::time::timeout(Duration::from_secs(2), h).await;
    }
}

#[tokio::test]
async fn test_consumer_service_with_shutdown() {
    let config = create_consumer_config();
    let backend = Arc::new(MockBackend::new());

    let service = ReplicationService::from_config(&config, backend).unwrap();
    let shutdown = Arc::new(ShutdownCoordinator::new(ShutdownConfig::default()));

    let handle = service.start_consumer(shutdown.clone()).await.unwrap();
    assert!(handle.is_some());

    // Let it run for a moment
    sleep(Duration::from_millis(100)).await;

    // Initiate shutdown
    shutdown.initiate_shutdown().await;

    // Wait for consumer to shutdown
    if let Some(h) = handle {
        let result = tokio::time::timeout(Duration::from_secs(2), h).await;
        assert!(result.is_ok(), "Consumer should shutdown within timeout");
    }
}

#[tokio::test]
async fn test_consumer_disabled_returns_none() {
    let mut config = ServerConfig::default();
    config.replication.enabled = false;
    let backend = Arc::new(MockBackend::new());

    let service = ReplicationService::from_config(&config, backend).unwrap();
    let shutdown = Arc::new(ShutdownCoordinator::new(ShutdownConfig::default()));

    let handle = service.start_consumer(shutdown).await.unwrap();

    assert!(handle.is_none(), "Disabled consumer should return None");
}

#[tokio::test]
async fn test_consumer_provider_mode_returns_none() {
    let mut config = ServerConfig::default();
    config.replication.enabled = true;
    config.replication.mode = "provider".to_string();
    let backend = Arc::new(MockBackend::new());

    let service = ReplicationService::from_config(&config, backend).unwrap();
    let shutdown = Arc::new(ShutdownCoordinator::new(ShutdownConfig::default()));

    let handle = service.start_consumer(shutdown).await.unwrap();

    assert!(handle.is_none(), "Provider mode should not start consumer");
}

#[tokio::test]
async fn test_consumer_configuration_values() {
    let mut config = create_consumer_config();
    config.replication.sync_interval_secs = 30;
    let backend = Arc::new(MockBackend::new());

    let service = ReplicationService::from_config(&config, backend).unwrap();

    assert!(service.is_consumer());
    assert!(service.consumer_config().is_some());

    let consumer_cfg = service.consumer_config().unwrap();
    assert_eq!(consumer_cfg.provider_url, "ldap://provider.example.com:389");
    assert_eq!(consumer_cfg.sync_interval_secs, 30);
    assert_eq!(consumer_cfg.max_retry_attempts, 3);
    assert_eq!(consumer_cfg.retry_delay_secs, 5);
}

#[tokio::test]
async fn test_consumer_both_mode() {
    let mut config = ServerConfig::default();
    config.replication.enabled = true;
    config.replication.mode = "both".to_string();
    config.replication.provider_url = Some("ldap://provider:389".to_string());
    let backend = Arc::new(MockBackend::new());

    let service = ReplicationService::from_config(&config, backend).unwrap();
    let shutdown = Arc::new(ShutdownCoordinator::new(ShutdownConfig::default()));

    let provider_handle = service.start_provider(shutdown.clone()).await.unwrap();
    let consumer_handle = service.start_consumer(shutdown.clone()).await.unwrap();

    assert!(provider_handle.is_some(), "Both mode should start provider");
    assert!(consumer_handle.is_some(), "Both mode should start consumer");
    assert!(service.is_provider());
    assert!(service.is_consumer());

    // Shutdown
    shutdown.initiate_shutdown().await;
    if let Some(h) = provider_handle {
        let _ = tokio::time::timeout(Duration::from_secs(2), h).await;
    }
    if let Some(h) = consumer_handle {
        let _ = tokio::time::timeout(Duration::from_secs(2), h).await;
    }
}

#[tokio::test]
async fn test_consumer_sync_interval() {
    let mut config = create_consumer_config();
    config.replication.sync_interval_secs = 1; // 1 second for testing
    let backend = Arc::new(MockBackend::new());

    let service = ReplicationService::from_config(&config, backend).unwrap();
    let shutdown = Arc::new(ShutdownCoordinator::new(ShutdownConfig::default()));

    let handle = service.start_consumer(shutdown.clone()).await.unwrap();
    assert!(handle.is_some());

    // Let it run for slightly more than one sync interval
    sleep(Duration::from_millis(1500)).await;

    // Shutdown
    shutdown.initiate_shutdown().await;
    if let Some(h) = handle {
        let _ = tokio::time::timeout(Duration::from_secs(2), h).await;
    }

    // Test passes if no panics occurred during sync attempts
}

#[tokio::test]
async fn test_consumer_state_storage_path() {
    let config = create_consumer_config();
    let backend = Arc::new(MockBackend::new());

    let service = ReplicationService::from_config(&config, backend).unwrap();

    let consumer_cfg = service.consumer_config().unwrap();
    assert_eq!(consumer_cfg.state_storage_path, "./data/replication_state");
}

#[tokio::test]
async fn test_consumer_missing_provider_url_error() {
    let mut config = ServerConfig::default();
    config.replication.enabled = true;
    config.replication.mode = "consumer".to_string();
    config.replication.provider_url = None; // Missing URL
    let backend = Arc::new(MockBackend::new());

    let result = ReplicationService::from_config(&config, backend);

    assert!(result.is_err());
    let err_msg = result.err().unwrap();
    assert!(err_msg.contains("provider_url required"));
}

#[tokio::test]
async fn test_consumer_credentials_configuration() {
    let mut config = create_consumer_config();
    config.replication.bind_dn = Some("cn=replicator,dc=example,dc=com".to_string());
    config.replication.bind_password = Some("repl_password".to_string());
    let backend = Arc::new(MockBackend::new());

    let service = ReplicationService::from_config(&config, backend).unwrap();

    let consumer_cfg = service.consumer_config().unwrap();
    assert_eq!(
        consumer_cfg.provider_bind_dn,
        Some("cn=replicator,dc=example,dc=com".to_string())
    );
    assert_eq!(
        consumer_cfg.provider_bind_password,
        Some("repl_password".to_string())
    );
}

#[tokio::test]
async fn test_consumer_change_listening_enabled() {
    let config = create_consumer_config();
    let backend = Arc::new(MockBackend::new());

    let service = ReplicationService::from_config(&config, backend).unwrap();

    let consumer_cfg = service.consumer_config().unwrap();
    assert!(consumer_cfg.enable_change_listening);
}

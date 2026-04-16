//! Integration tests for replication consumer service
//!
//! These tests validate the consumer service integration with the main server,
//! including initialization, sync cycles, error handling, and shutdown behavior.

use opendr::backend::{DirectoryBackend, DirectoryEntry, MockBackend};
use opendr::config::ServerConfig;
use opendr::replication_service::ReplicationService;
use opendr::server;
use opendr::shutdown::{ShutdownConfig, ShutdownCoordinator};
use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;
use tempfile::{NamedTempFile, TempDir};
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep, timeout};

/// Helper function to create a test configuration for consumer mode
fn create_consumer_config() -> ServerConfig {
    let mut config = ServerConfig::default();
    config.server.base_dn = "dc=example,dc=org".to_string();
    config.replication.enabled = true;
    config.replication.mode = "consumer".to_string();
    config.replication.provider_url = Some("ldap://provider.example.com:389".to_string());
    config.replication.allow_insecure_provider_bind = true;
    config.replication.sync_interval_secs = 1; // Fast for testing
    config.replication.bind_dn = Some("cn=admin,dc=example,dc=com".to_string());
    config.replication.bind_password = Some("secret".to_string());
    config
}

fn create_provider_config() -> ServerConfig {
    let mut config = ServerConfig::default();
    config.server.base_dn = "dc=example,dc=org".to_string();
    config.replication.enabled = true;
    config.replication.mode = "provider".to_string();
    config.replication.sync_interval_secs = 1;
    config
}

fn create_test_entry(dn: &str, cn: &str) -> DirectoryEntry {
    DirectoryEntry::new(
        dn,
        HashMap::from([
            (
                "objectclass".to_string(),
                vec!["top".to_string(), "person".to_string()],
            ),
            ("cn".to_string(), vec![cn.to_string()]),
            ("sn".to_string(), vec!["Replication".to_string()]),
        ]),
    )
}

fn allocate_listen_addr() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    format!("127.0.0.1:{}", addr.port())
}

async fn wait_for_port(addr: &str) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if TcpStream::connect(addr).await.is_ok() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for LDAP server on {addr}"
        );
        sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_for_entry(backend: &MockBackend, dn: &str) -> DirectoryEntry {
    timeout(Duration::from_secs(10), async {
        loop {
            if let Some(entry) = backend
                .get_entry(dn)
                .await
                .expect("backend lookup should succeed")
            {
                return entry;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("timed out waiting for replicated entry")
}

async fn assert_entry_absent_for(backend: &MockBackend, dn: &str, duration: Duration) {
    let deadline = Instant::now() + duration;
    loop {
        assert!(
            backend
                .get_entry(dn)
                .await
                .expect("backend lookup should succeed")
                .is_none(),
            "entry {dn} should stay absent during the observation window"
        );

        if Instant::now() >= deadline {
            return;
        }

        sleep(Duration::from_millis(25)).await;
    }
}

async fn shutdown_consumer(
    shutdown: Arc<ShutdownCoordinator>,
    handle: JoinHandle<()>,
    context: &str,
) {
    shutdown.initiate_shutdown().await;
    timeout(Duration::from_secs(5), handle)
        .await
        .unwrap_or_else(|_| panic!("{context} did not shut down within timeout"))
        .expect("consumer task should exit cleanly");
}

async fn shutdown_provider(shutdown_tx: &broadcast::Sender<()>, handle: JoinHandle<()>) {
    let _ = shutdown_tx.send(());
    timeout(Duration::from_secs(5), handle)
        .await
        .expect("provider server did not shut down within timeout")
        .expect("provider server task should exit cleanly");
}

async fn start_provider_server() -> (
    Arc<dyn DirectoryBackend>,
    broadcast::Sender<()>,
    JoinHandle<()>,
    String,
) {
    let config = create_provider_config();
    let backend = Arc::new(MockBackend::new());
    let service = ReplicationService::from_config(&config, backend).unwrap();
    let provider_backend = service.backend();

    let addr = allocate_listen_addr();
    let ldap_url = format!("ldap://{addr}");
    let (shutdown_tx, shutdown_rx) = broadcast::channel(4);
    let server_backend = provider_backend.clone();
    let server_addr = addr.clone();

    let task = tokio::spawn(async move {
        server::run(&server_addr, server_backend, shutdown_rx)
            .await
            .expect("provider LDAP server should run");
    });

    wait_for_port(&addr).await;

    (provider_backend, shutdown_tx, task, ldap_url)
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
    assert_eq!(consumer_cfg.heartbeat_interval_secs, 30);
    assert_eq!(consumer_cfg.state_storage_path, "./data/replication_state");
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
async fn test_consumer_credentials_configuration_from_secret_file() {
    let mut secret_file = NamedTempFile::new().unwrap();
    writeln!(secret_file, "file-backed-repl-password").unwrap();

    let mut config = create_consumer_config();
    config.replication.bind_password = None;
    config.replication.bind_password_file = Some(secret_file.path().to_path_buf());
    let backend = Arc::new(MockBackend::new());

    let service = ReplicationService::from_config(&config, backend).unwrap();

    let consumer_cfg = service.consumer_config().unwrap();
    assert_eq!(
        consumer_cfg.provider_bind_password,
        Some("file-backed-repl-password".to_string())
    );

    let debug_output = format!("{consumer_cfg:?}");
    assert!(!debug_output.contains("file-backed-repl-password"));
    assert!(debug_output.contains("<redacted>"));
}

#[tokio::test]
async fn test_consumer_change_listening_enabled() {
    let config = create_consumer_config();
    let backend = Arc::new(MockBackend::new());

    let service = ReplicationService::from_config(&config, backend).unwrap();

    let consumer_cfg = service.consumer_config().unwrap();
    assert!(consumer_cfg.enable_change_listening);
}

#[tokio::test]
async fn test_consumer_custom_listening_config_propagates() {
    let mut config = create_consumer_config();
    config.replication.sync_interval_secs = 20;
    config.replication.max_retry_attempts = 7;
    config.replication.retry_delay_secs = 13;
    config.replication.heartbeat_interval_secs = 47;
    config.replication.state_storage_path = std::path::PathBuf::from("/tmp/opendr/repl_state");

    let backend = Arc::new(MockBackend::new());
    let service = ReplicationService::from_config(&config, backend).unwrap();

    let consumer_cfg = service.consumer_config().unwrap();
    assert_eq!(consumer_cfg.sync_interval_secs, 20);
    assert_eq!(consumer_cfg.max_retry_attempts, 7);
    assert_eq!(consumer_cfg.retry_delay_secs, 13);
    assert!(consumer_cfg.enable_change_listening);
    assert_eq!(consumer_cfg.heartbeat_interval_secs, 47);
    assert_eq!(consumer_cfg.state_storage_path, "/tmp/opendr/repl_state");
}

#[tokio::test]
async fn test_consumer_service_listening_mode_applies_initial_refresh_and_live_update_in_one_session()
 {
    let (provider_backend, provider_shutdown, provider_task, provider_url) =
        start_provider_server().await;
    let state_dir = TempDir::new().unwrap();
    let consumer_backend = Arc::new(MockBackend::new());

    let initial_entry = create_test_entry("cn=initial,dc=example,dc=org", "initial");
    provider_backend
        .add_entry(initial_entry.clone(), Vec::new())
        .await
        .unwrap();

    let mut config = create_consumer_config();
    config.replication.provider_url = Some(provider_url);
    config.replication.bind_dn = None;
    config.replication.bind_password = None;
    config.replication.sync_interval_secs = 5;
    config.replication.enable_change_listening = true;
    config.replication.state_storage_path = state_dir.path().to_path_buf();

    let service = ReplicationService::from_config(&config, consumer_backend.clone()).unwrap();
    let shutdown = Arc::new(ShutdownCoordinator::new(ShutdownConfig::default()));
    let handle = service
        .start_consumer(shutdown.clone())
        .await
        .unwrap()
        .expect("consumer handle should be present");

    wait_for_entry(consumer_backend.as_ref(), &initial_entry.dn).await;

    let live_entry = create_test_entry("cn=live,dc=example,dc=org", "live");
    provider_backend
        .add_entry(live_entry.clone(), Vec::new())
        .await
        .unwrap();

    wait_for_entry(consumer_backend.as_ref(), &live_entry.dn).await;
    assert!(
        state_dir.path().join("replication_cookie.txt").exists(),
        "initial refresh should persist a replication cookie"
    );

    shutdown_consumer(shutdown, handle, "listening consumer").await;
    shutdown_provider(&provider_shutdown, provider_task).await;
}

#[tokio::test]
async fn test_consumer_service_reconnects_and_resumes_from_persisted_cookie() {
    let (provider_backend, provider_shutdown, provider_task, provider_url) =
        start_provider_server().await;
    let state_dir = TempDir::new().unwrap();
    let consumer_backend = Arc::new(MockBackend::new());

    let initial_entry = create_test_entry("cn=resume-initial,dc=example,dc=org", "resume-initial");
    provider_backend
        .add_entry(initial_entry.clone(), Vec::new())
        .await
        .unwrap();

    let mut config = create_consumer_config();
    config.replication.provider_url = Some(provider_url.clone());
    config.replication.bind_dn = None;
    config.replication.bind_password = None;
    config.replication.sync_interval_secs = 5;
    config.replication.enable_change_listening = true;
    config.replication.state_storage_path = state_dir.path().to_path_buf();

    let first_service = ReplicationService::from_config(&config, consumer_backend.clone()).unwrap();
    let first_shutdown = Arc::new(ShutdownCoordinator::new(ShutdownConfig::default()));
    let first_handle = first_service
        .start_consumer(first_shutdown.clone())
        .await
        .unwrap()
        .expect("first consumer handle should be present");

    wait_for_entry(consumer_backend.as_ref(), &initial_entry.dn).await;
    shutdown_consumer(first_shutdown, first_handle, "first listening consumer").await;

    consumer_backend
        .delete_entry(&initial_entry.dn)
        .await
        .unwrap();

    let offline_entry = create_test_entry("cn=resume-offline,dc=example,dc=org", "resume-offline");
    provider_backend
        .add_entry(offline_entry.clone(), Vec::new())
        .await
        .unwrap();

    let restarted_service =
        ReplicationService::from_config(&config, consumer_backend.clone()).unwrap();
    let restarted_shutdown = Arc::new(ShutdownCoordinator::new(ShutdownConfig::default()));
    let restarted_handle = restarted_service
        .start_consumer(restarted_shutdown.clone())
        .await
        .unwrap()
        .expect("restarted consumer handle should be present");

    wait_for_entry(consumer_backend.as_ref(), &offline_entry.dn).await;
    assert_entry_absent_for(
        consumer_backend.as_ref(),
        &initial_entry.dn,
        Duration::from_millis(300),
    )
    .await;

    shutdown_consumer(
        restarted_shutdown,
        restarted_handle,
        "restarted listening consumer",
    )
    .await;
    shutdown_provider(&provider_shutdown, provider_task).await;
}

#[tokio::test]
async fn test_consumer_service_rejects_poll_based_replication() {
    let (_provider_backend, provider_shutdown, provider_task, provider_url) =
        start_provider_server().await;
    let state_dir = TempDir::new().unwrap();
    let consumer_backend = Arc::new(MockBackend::new());

    let mut config = create_consumer_config();
    config.replication.provider_url = Some(provider_url);
    config.replication.bind_dn = None;
    config.replication.bind_password = None;
    config.replication.enable_change_listening = false;
    config.replication.state_storage_path = state_dir.path().to_path_buf();

    let err = match ReplicationService::from_config(&config, consumer_backend) {
        Ok(_) => panic!("disabled listener config should be rejected"),
        Err(err) => err,
    };
    assert!(err.contains("poll-based replication has been removed"));

    shutdown_provider(&provider_shutdown, provider_task).await;
}

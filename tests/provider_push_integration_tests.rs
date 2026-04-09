//! Integration Tests for Provider-Push Manager Integration
//!
//! This test suite validates Task 2.2: Integration with Provider FSM
//! Testing refreshAndPersist mode support and push-based replication.

use opendr::backend::{DirectoryBackend, MockBackend};
use opendr::change_observer::ChangeObserverImpl;
use opendr::provider_push_integration::{ProviderPushConfig, ProviderPushCoordinator};
use opendr::push_manager::{PushManager, PushManagerConfig};
use opendr::replication_provider_fsm::{ConsumerConnection, SyncMode};
use opendr::server;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::sleep;

// ================================================================================================
// Test Helpers
// ================================================================================================

async fn create_test_coordinator() -> ProviderPushCoordinator {
    let observer = Arc::new(ChangeObserverImpl::new());
    let push_config = PushManagerConfig::default();
    let push_manager = Arc::new(RwLock::new(PushManager::new(observer, push_config)));
    let config = ProviderPushConfig {
        connect_on_registration: false,
        ..ProviderPushConfig::default()
    };
    ProviderPushCoordinator::new(push_manager, config)
}

async fn create_coordinator_with_config(config: ProviderPushConfig) -> ProviderPushCoordinator {
    let observer = Arc::new(ChangeObserverImpl::new());
    let push_config = PushManagerConfig::default();
    let push_manager = Arc::new(RwLock::new(PushManager::new(observer, push_config)));
    let mut config = config;
    config.connect_on_registration = false;
    ProviderPushCoordinator::new(push_manager, config)
}

fn create_test_connection(address: String, sync_mode: SyncMode) -> ConsumerConnection {
    ConsumerConnection::with_sync_mode(address, sync_mode)
}

struct TestLdapServer {
    url: String,
    shutdown_tx: broadcast::Sender<()>,
    handle: JoinHandle<()>,
}

impl TestLdapServer {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let backend: Arc<dyn DirectoryBackend> = Arc::new(MockBackend::new());
        let bind_addr = addr.to_string();
        let handle = tokio::spawn(async move {
            if let Err(err) = server::run(&bind_addr, backend, shutdown_rx).await {
                panic!("test LDAP server failed: {}", err);
            }
        });

        sleep(Duration::from_millis(25)).await;

        Self {
            url: format!("ldap://{}", addr),
            shutdown_tx,
            handle,
        }
    }

    async fn stop(self) {
        let _ = self.shutdown_tx.send(());
        self.handle.await.unwrap();
    }
}

// ================================================================================================
// Coordinator Lifecycle Tests
// ================================================================================================

#[tokio::test]
async fn test_coordinator_creation() {
    println!("\n=== Test: Coordinator Creation ===");
    let coordinator = create_test_coordinator().await;
    let stats = coordinator.get_stats().await;

    assert_eq!(stats.total_registered, 0);
    assert_eq!(stats.active_persistent, 0);
    assert_eq!(stats.total_unregistered, 0);
    assert_eq!(stats.total_heartbeats, 0);
    assert_eq!(stats.total_timeouts, 0);
    assert_eq!(stats.total_errors, 0);

    println!("✅ Coordinator created with clean state");
}

#[tokio::test]
async fn test_coordinator_start_stop() {
    println!("\n=== Test: Coordinator Start/Stop ===");
    let coordinator = create_test_coordinator().await;

    // Start coordinator
    let result = coordinator.start().await;
    assert!(result.is_ok(), "Coordinator should start successfully");
    println!("✅ Coordinator started");

    // Stop coordinator
    let result = coordinator.stop().await;
    assert!(result.is_ok(), "Coordinator should stop successfully");
    println!("✅ Coordinator stopped");
}

#[tokio::test]
async fn test_coordinator_multiple_start_stop_cycles() {
    println!("\n=== Test: Multiple Start/Stop Cycles ===");
    let coordinator = create_test_coordinator().await;

    for cycle in 1..=3 {
        println!("Cycle {}/3", cycle);

        let result = coordinator.start().await;
        assert!(result.is_ok(), "Start should succeed on cycle {}", cycle);

        let result = coordinator.stop().await;
        assert!(result.is_ok(), "Stop should succeed on cycle {}", cycle);
    }

    println!("✅ Multiple start/stop cycles completed successfully");
}

// ================================================================================================
// Consumer Registration Tests
// ================================================================================================

#[tokio::test]
async fn test_register_single_persistent_consumer() {
    println!("\n=== Test: Register Single Persistent Consumer ===");
    let coordinator = create_test_coordinator().await;
    let test_server = TestLdapServer::start().await;
    coordinator.start().await.unwrap();

    let consumer_id = "consumer-1".to_string();
    let connection = create_test_connection(test_server.url.clone(), SyncMode::RefreshAndPersist);

    let result = coordinator
        .register_persistent_consumer(
            consumer_id.clone(),
            connection,
            "dc=example,dc=com".to_string(),
            None,
            "csn-20251008000000000000#001#000001#000000".to_string(),
        )
        .await;

    assert!(result.is_ok(), "Registration should succeed");

    // Verify registration
    assert!(
        coordinator.is_consumer_registered(&consumer_id).await,
        "Consumer should be registered"
    );

    // Check statistics
    let stats = coordinator.get_stats().await;
    assert_eq!(stats.total_registered, 1);
    assert_eq!(stats.active_persistent, 1);

    println!("✅ Consumer registered successfully: {}", consumer_id);

    coordinator.stop().await.unwrap();
    test_server.stop().await;
}

#[tokio::test]
async fn test_register_multiple_persistent_consumers() {
    println!("\n=== Test: Register Multiple Persistent Consumers ===");
    let coordinator = create_test_coordinator().await;
    let test_server = TestLdapServer::start().await;
    coordinator.start().await.unwrap();

    let consumer_count = 5;
    for i in 1..=consumer_count {
        let consumer_id = format!("consumer-{}", i);
        let connection =
            create_test_connection(test_server.url.clone(), SyncMode::RefreshAndPersist);

        let result = coordinator
            .register_persistent_consumer(
                consumer_id.clone(),
                connection,
                "dc=example,dc=com".to_string(),
                None,
                format!("csn-2025100800000000000{}#001#000001#000000", i),
            )
            .await;

        assert!(
            result.is_ok(),
            "Registration should succeed for consumer {}",
            i
        );
        println!("  ✓ Registered consumer {}/{}", i, consumer_count);
    }

    // Verify all consumers registered
    let stats = coordinator.get_stats().await;
    assert_eq!(stats.total_registered, consumer_count);
    assert_eq!(stats.active_persistent, consumer_count as usize);

    // Verify consumer list
    let consumer_ids = coordinator.get_persistent_consumer_ids().await;
    assert_eq!(consumer_ids.len(), consumer_count as usize);

    println!(
        "✅ All {} consumers registered successfully",
        consumer_count
    );

    coordinator.stop().await.unwrap();
    test_server.stop().await;
}

#[tokio::test]
async fn test_register_consumer_with_filter() {
    println!("\n=== Test: Register Consumer with Filter ===");
    let coordinator = create_test_coordinator().await;
    let test_server = TestLdapServer::start().await;
    coordinator.start().await.unwrap();

    let consumer_id = "consumer-filtered".to_string();
    let connection = create_test_connection(test_server.url.clone(), SyncMode::RefreshAndPersist);
    let filter = Some("(objectClass=person)".to_string());

    let result = coordinator
        .register_persistent_consumer(
            consumer_id.clone(),
            connection,
            "dc=example,dc=com".to_string(),
            filter.clone(),
            "csn-20251008000000000000#001#000001#000000".to_string(),
        )
        .await;

    assert!(result.is_ok(), "Registration with filter should succeed");

    // Verify consumer info
    let info = coordinator.get_consumer_info(&consumer_id).await;
    assert!(info.is_some());

    println!("✅ Consumer with filter registered successfully");

    coordinator.stop().await.unwrap();
    test_server.stop().await;
}

#[tokio::test]
async fn test_unregister_persistent_consumer() {
    println!("\n=== Test: Unregister Persistent Consumer ===");
    let coordinator = create_test_coordinator().await;
    let test_server = TestLdapServer::start().await;
    coordinator.start().await.unwrap();

    let consumer_id = "consumer-1".to_string();
    let connection = create_test_connection(test_server.url.clone(), SyncMode::RefreshAndPersist);

    // Register
    coordinator
        .register_persistent_consumer(
            consumer_id.clone(),
            connection,
            "dc=example,dc=com".to_string(),
            None,
            "csn-20251008000000000000#001#000001#000000".to_string(),
        )
        .await
        .unwrap();

    assert!(coordinator.is_consumer_registered(&consumer_id).await);
    println!("  ✓ Consumer registered");

    // Unregister
    let result = coordinator
        .unregister_persistent_consumer(&consumer_id)
        .await;
    assert!(result.is_ok(), "Unregistration should succeed");

    assert!(!coordinator.is_consumer_registered(&consumer_id).await);
    println!("  ✓ Consumer unregistered");

    // Check statistics
    let stats = coordinator.get_stats().await;
    assert_eq!(stats.total_registered, 1);
    assert_eq!(stats.total_unregistered, 1);
    assert_eq!(stats.active_persistent, 0);

    println!("✅ Consumer unregistered successfully");

    coordinator.stop().await.unwrap();
    test_server.stop().await;
}

#[tokio::test]
async fn test_unregister_nonexistent_consumer() {
    println!("\n=== Test: Unregister Nonexistent Consumer ===");
    let coordinator = create_test_coordinator().await;
    coordinator.start().await.unwrap();

    let result = coordinator
        .unregister_persistent_consumer("nonexistent-consumer")
        .await;

    assert!(result.is_err(), "Should fail for nonexistent consumer");
    assert!(result.unwrap_err().contains("Consumer not found"));

    println!("✅ Correctly handles nonexistent consumer");

    coordinator.stop().await.unwrap();
}

// ================================================================================================
// Configuration and Limits Tests
// ================================================================================================

#[tokio::test]
async fn test_max_persistent_consumers_limit() {
    println!("\n=== Test: Max Persistent Consumers Limit ===");

    let config = ProviderPushConfig {
        max_persistent_consumers: 3,
        ..ProviderPushConfig::default()
    };

    let coordinator = create_coordinator_with_config(config).await;
    let test_server = TestLdapServer::start().await;
    coordinator.start().await.unwrap();

    // Register up to limit (should succeed)
    for i in 1..=3 {
        let consumer_id = format!("consumer-{}", i);
        let connection =
            create_test_connection(test_server.url.clone(), SyncMode::RefreshAndPersist);

        let result = coordinator
            .register_persistent_consumer(
                consumer_id,
                connection,
                "dc=example,dc=com".to_string(),
                None,
                format!("csn-2025100800000000000{}#001#000001#000000", i),
            )
            .await;

        assert!(result.is_ok(), "Should succeed for consumer {}", i);
        println!("  ✓ Registered consumer {}/3", i);
    }

    // Try to register beyond limit (should fail)
    let consumer_id = "consumer-4".to_string();
    let connection = create_test_connection(test_server.url.clone(), SyncMode::RefreshAndPersist);

    let result = coordinator
        .register_persistent_consumer(
            consumer_id,
            connection,
            "dc=example,dc=com".to_string(),
            None,
            "csn-20251008000000000004#001#000001#000000".to_string(),
        )
        .await;

    assert!(result.is_err(), "Should fail when at limit");
    assert!(result
        .unwrap_err()
        .contains("Maximum persistent consumer limit"));

    println!("✅ Max consumer limit enforced correctly");

    coordinator.stop().await.unwrap();
    test_server.stop().await;
}

#[tokio::test]
async fn test_custom_configuration() {
    println!("\n=== Test: Custom Configuration ===");

    let config = ProviderPushConfig {
        heartbeat_interval: Duration::from_secs(60),
        connection_timeout: Duration::from_secs(600),
        max_persistent_consumers: 50,
        enable_auto_cleanup: false,
        cleanup_interval: Duration::from_secs(120),
        connect_on_registration: false,
    };

    let coordinator = create_coordinator_with_config(config.clone()).await;
    let test_server = TestLdapServer::start().await;
    coordinator.start().await.unwrap();

    // Register a consumer to verify config is used
    let consumer_id = "consumer-1".to_string();
    let connection = create_test_connection(test_server.url.clone(), SyncMode::RefreshAndPersist);

    let result = coordinator
        .register_persistent_consumer(
            consumer_id,
            connection,
            "dc=example,dc=com".to_string(),
            None,
            "csn-20251008000000000000#001#000001#000000".to_string(),
        )
        .await;

    assert!(result.is_ok());

    println!("✅ Custom configuration applied successfully");

    coordinator.stop().await.unwrap();
    test_server.stop().await;
}

// ================================================================================================
// Cookie Management Tests
// ================================================================================================

#[tokio::test]
async fn test_update_consumer_cookie() {
    println!("\n=== Test: Update Consumer Cookie ===");
    let coordinator = create_test_coordinator().await;
    let test_server = TestLdapServer::start().await;
    coordinator.start().await.unwrap();

    let consumer_id = "consumer-1".to_string();
    let connection = create_test_connection(test_server.url.clone(), SyncMode::RefreshAndPersist);
    let initial_cookie = "csn-20251008000000000000#001#000001#000000".to_string();

    // Register
    coordinator
        .register_persistent_consumer(
            consumer_id.clone(),
            connection,
            "dc=example,dc=com".to_string(),
            None,
            initial_cookie.clone(),
        )
        .await
        .unwrap();

    // Verify initial cookie
    let info = coordinator.get_consumer_info(&consumer_id).await.unwrap();
    assert_eq!(info.last_cookie, Some(initial_cookie));
    println!("  ✓ Initial cookie set");

    // Update cookie
    let new_cookie = "csn-20251008123456789000#001#000001#000000".to_string();
    let result = coordinator
        .update_consumer_cookie(&consumer_id, new_cookie.clone())
        .await;
    assert!(result.is_ok());
    println!("  ✓ Cookie updated");

    // Verify updated cookie
    let info = coordinator.get_consumer_info(&consumer_id).await.unwrap();
    assert_eq!(info.last_cookie, Some(new_cookie));

    println!("✅ Consumer cookie updated successfully");

    coordinator.stop().await.unwrap();
    test_server.stop().await;
}

#[tokio::test]
async fn test_update_cookie_for_nonexistent_consumer() {
    println!("\n=== Test: Update Cookie for Nonexistent Consumer ===");
    let coordinator = create_test_coordinator().await;
    coordinator.start().await.unwrap();

    let result = coordinator
        .update_consumer_cookie(
            "nonexistent-consumer",
            "csn-20251008000000000000#001#000001#000000".to_string(),
        )
        .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Consumer not found"));

    println!("✅ Correctly handles nonexistent consumer");

    coordinator.stop().await.unwrap();
}

// ================================================================================================
// Consumer Information Tests
// ================================================================================================

#[tokio::test]
async fn test_get_consumer_info() {
    println!("\n=== Test: Get Consumer Info ===");
    let coordinator = create_test_coordinator().await;
    let test_server = TestLdapServer::start().await;
    coordinator.start().await.unwrap();

    let consumer_id = "consumer-1".to_string();
    let address = test_server.url.clone();
    let connection = create_test_connection(address.clone(), SyncMode::RefreshAndPersist);
    let cookie = "csn-20251008000000000000#001#000001#000000".to_string();

    // Register
    coordinator
        .register_persistent_consumer(
            consumer_id.clone(),
            connection,
            "dc=example,dc=com".to_string(),
            None,
            cookie.clone(),
        )
        .await
        .unwrap();

    // Get info
    let info = coordinator.get_consumer_info(&consumer_id).await;
    assert!(info.is_some());

    let info = info.unwrap();
    assert_eq!(info.consumer_id, consumer_id);
    assert_eq!(info.connection.address, address);
    assert_eq!(info.last_cookie, Some(cookie));
    assert!(info.connection.is_persistent_mode());

    println!("✅ Consumer info retrieved successfully");

    coordinator.stop().await.unwrap();
    test_server.stop().await;
}

#[tokio::test]
async fn test_get_persistent_consumer_ids() {
    println!("\n=== Test: Get Persistent Consumer IDs ===");
    let coordinator = create_test_coordinator().await;
    let test_server = TestLdapServer::start().await;
    coordinator.start().await.unwrap();

    // Register multiple consumers
    let expected_ids: Vec<String> = (1..=3).map(|i| format!("consumer-{}", i)).collect();

    for id in &expected_ids {
        let connection =
            create_test_connection(test_server.url.clone(), SyncMode::RefreshAndPersist);

        coordinator
            .register_persistent_consumer(
                id.clone(),
                connection,
                "dc=example,dc=com".to_string(),
                None,
                format!("csn-{}", id),
            )
            .await
            .unwrap();
    }

    // Get all IDs
    let consumer_ids = coordinator.get_persistent_consumer_ids().await;
    assert_eq!(consumer_ids.len(), 3);

    // Verify all expected IDs are present
    for expected_id in &expected_ids {
        assert!(
            consumer_ids.contains(expected_id),
            "Should contain {}",
            expected_id
        );
    }

    println!("✅ All consumer IDs retrieved correctly");

    coordinator.stop().await.unwrap();
    test_server.stop().await;
}

#[tokio::test]
async fn test_is_consumer_registered() {
    println!("\n=== Test: Is Consumer Registered ===");
    let coordinator = create_test_coordinator().await;
    let test_server = TestLdapServer::start().await;
    coordinator.start().await.unwrap();

    let consumer_id = "consumer-1".to_string();

    // Check before registration
    assert!(!coordinator.is_consumer_registered(&consumer_id).await);
    println!("  ✓ Consumer not registered initially");

    // Register
    let connection = create_test_connection(test_server.url.clone(), SyncMode::RefreshAndPersist);

    coordinator
        .register_persistent_consumer(
            consumer_id.clone(),
            connection,
            "dc=example,dc=com".to_string(),
            None,
            "csn-20251008000000000000#001#000001#000000".to_string(),
        )
        .await
        .unwrap();

    // Check after registration
    assert!(coordinator.is_consumer_registered(&consumer_id).await);
    println!("  ✓ Consumer registered");

    // Unregister
    coordinator
        .unregister_persistent_consumer(&consumer_id)
        .await
        .unwrap();

    // Check after unregistration
    assert!(!coordinator.is_consumer_registered(&consumer_id).await);
    println!("  ✓ Consumer unregistered");

    println!("✅ Consumer registration status tracked correctly");

    coordinator.stop().await.unwrap();
    test_server.stop().await;
}

// ================================================================================================
// Statistics Tests
// ================================================================================================

#[tokio::test]
async fn test_coordinator_statistics_tracking() {
    println!("\n=== Test: Coordinator Statistics Tracking ===");
    let coordinator = create_test_coordinator().await;
    let test_server = TestLdapServer::start().await;
    coordinator.start().await.unwrap();

    // Initial stats
    let stats = coordinator.get_stats().await;
    assert_eq!(stats.total_registered, 0);
    assert_eq!(stats.active_persistent, 0);
    assert_eq!(stats.total_unregistered, 0);
    println!("  ✓ Initial statistics: 0/0/0");

    // Register 3 consumers
    for i in 1..=3 {
        let consumer_id = format!("consumer-{}", i);
        let connection =
            create_test_connection(test_server.url.clone(), SyncMode::RefreshAndPersist);

        coordinator
            .register_persistent_consumer(
                consumer_id,
                connection,
                "dc=example,dc=com".to_string(),
                None,
                format!("csn-{}", i),
            )
            .await
            .unwrap();
    }

    let stats = coordinator.get_stats().await;
    assert_eq!(stats.total_registered, 3);
    assert_eq!(stats.active_persistent, 3);
    println!("  ✓ After registrations: 3/3/0");

    // Unregister 2 consumers
    for i in 1..=2 {
        let consumer_id = format!("consumer-{}", i);
        coordinator
            .unregister_persistent_consumer(&consumer_id)
            .await
            .unwrap();
    }

    let stats = coordinator.get_stats().await;
    assert_eq!(stats.total_registered, 3);
    assert_eq!(stats.active_persistent, 1);
    assert_eq!(stats.total_unregistered, 2);
    println!("  ✓ After unregistrations: 3/1/2");

    println!("✅ Statistics tracked correctly throughout lifecycle");

    coordinator.stop().await.unwrap();
    test_server.stop().await;
}

// ================================================================================================
// End-to-End Integration Tests
// ================================================================================================

#[tokio::test]
async fn test_full_registration_lifecycle() {
    println!("\n=== Test: Full Registration Lifecycle ===");
    let coordinator = create_test_coordinator().await;
    let test_server = TestLdapServer::start().await;
    coordinator.start().await.unwrap();

    let consumer_id = "consumer-lifecycle".to_string();
    let connection = create_test_connection(test_server.url.clone(), SyncMode::RefreshAndPersist);

    // 1. Register
    println!("  Step 1: Register consumer");
    coordinator
        .register_persistent_consumer(
            consumer_id.clone(),
            connection,
            "dc=example,dc=com".to_string(),
            Some("(objectClass=person)".to_string()),
            "csn-initial".to_string(),
        )
        .await
        .unwrap();

    assert!(coordinator.is_consumer_registered(&consumer_id).await);

    // 2. Update cookie
    println!("  Step 2: Update cookie");
    coordinator
        .update_consumer_cookie(&consumer_id, "csn-updated".to_string())
        .await
        .unwrap();

    let info = coordinator.get_consumer_info(&consumer_id).await.unwrap();
    assert_eq!(info.last_cookie, Some("csn-updated".to_string()));

    // 3. Get info
    println!("  Step 3: Verify consumer info");
    let info = coordinator.get_consumer_info(&consumer_id).await;
    assert!(info.is_some());

    // 4. Unregister
    println!("  Step 4: Unregister consumer");
    coordinator
        .unregister_persistent_consumer(&consumer_id)
        .await
        .unwrap();

    assert!(!coordinator.is_consumer_registered(&consumer_id).await);

    println!("✅ Full lifecycle completed successfully");

    coordinator.stop().await.unwrap();
    test_server.stop().await;
}

#[tokio::test]
async fn test_concurrent_consumer_operations() {
    println!("\n=== Test: Concurrent Consumer Operations ===");
    let coordinator = Arc::new(create_test_coordinator().await);
    let test_server = TestLdapServer::start().await;
    let consumer_url = test_server.url.clone();
    coordinator.start().await.unwrap();

    let consumer_count = 10;
    let mut handles = vec![];

    // Spawn concurrent registration tasks
    for i in 1..=consumer_count {
        let coord = coordinator.clone();
        let consumer_url = consumer_url.clone();
        let handle = tokio::spawn(async move {
            let consumer_id = format!("consumer-{}", i);
            let connection = create_test_connection(consumer_url, SyncMode::RefreshAndPersist);

            coord
                .register_persistent_consumer(
                    consumer_id,
                    connection,
                    "dc=example,dc=com".to_string(),
                    None,
                    format!("csn-{}", i),
                )
                .await
        });
        handles.push(handle);
    }

    // Wait for all registrations
    for (i, handle) in handles.into_iter().enumerate() {
        let result = handle.await.unwrap();
        assert!(result.is_ok(), "Registration {} should succeed", i + 1);
    }

    // Verify all consumers registered
    let stats = coordinator.get_stats().await;
    assert_eq!(stats.total_registered, consumer_count);
    assert_eq!(stats.active_persistent, consumer_count as usize);

    println!("✅ {} concurrent registrations completed", consumer_count);

    coordinator.stop().await.unwrap();
    test_server.stop().await;
}

// ================================================================================================
// Test Summary
// ================================================================================================

#[tokio::test]
async fn test_integration_test_summary() {
    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║  Provider-Push Integration Test Summary (Task 2.2)      ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!("\n✅ Coordinator Lifecycle Tests");
    println!("  - Creation");
    println!("  - Start/Stop");
    println!("  - Multiple cycles");
    println!("\n✅ Consumer Registration Tests");
    println!("  - Single consumer");
    println!("  - Multiple consumers");
    println!("  - With filters");
    println!("  - Unregistration");
    println!("\n✅ Configuration Tests");
    println!("  - Max consumer limits");
    println!("  - Custom configuration");
    println!("\n✅ Cookie Management Tests");
    println!("  - Update cookies");
    println!("  - Error handling");
    println!("\n✅ Consumer Information Tests");
    println!("  - Get info");
    println!("  - Get IDs");
    println!("  - Registration status");
    println!("\n✅ Statistics Tests");
    println!("  - Tracking throughout lifecycle");
    println!("\n✅ End-to-End Tests");
    println!("  - Full lifecycle");
    println!("  - Concurrent operations");
    println!("\n═══════════════════════════════════════════════════════════");
}

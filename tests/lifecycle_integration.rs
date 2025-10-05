//! Integration tests for lifecycle management and graceful shutdown
//!
//! These tests verify that the shutdown coordinator and graceful shutdown
//! work correctly in realistic scenarios.

use opendr::backend::MockBackend;
use opendr::fsm_server::{FsmServerConfig, run_with_shutdown};
use opendr::shutdown::{ShutdownCoordinator, ShutdownConfig, ShutdownState};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::test]
async fn test_shutdown_coordinator_basic() {
    let config = ShutdownConfig::default();
    let coordinator = ShutdownCoordinator::new(config);

    assert_eq!(coordinator.get_state().await, ShutdownState::Running);
    assert!(!coordinator.is_shutting_down().await);
}

#[tokio::test]
async fn test_shutdown_initiation() {
    let config = ShutdownConfig::default();
    let coordinator = ShutdownCoordinator::new(config);

    coordinator.initiate_shutdown().await;

    assert_eq!(coordinator.get_state().await, ShutdownState::ShuttingDown);
    assert!(coordinator.is_shutting_down().await);
}

#[tokio::test]
async fn test_connection_registration_and_tracking() {
    let config = ShutdownConfig::default();
    let coordinator = ShutdownCoordinator::new(config);

    // Register connections
    assert!(coordinator.register_connection().await.is_some());
    assert!(coordinator.register_connection().await.is_some());
    assert_eq!(coordinator.active_connection_count().await, 2);

    // Unregister one
    coordinator.unregister_connection().await;
    assert_eq!(coordinator.active_connection_count().await, 1);
}

#[tokio::test]
async fn test_shutdown_rejects_new_connections() {
    let config = ShutdownConfig::default();
    let coordinator = ShutdownCoordinator::new(config);

    // Register a connection before shutdown
    assert!(coordinator.register_connection().await.is_some());

    // Initiate shutdown
    coordinator.initiate_shutdown().await;

    // Try to register new connection - should fail
    assert!(coordinator.register_connection().await.is_none());
}

#[tokio::test]
async fn test_operation_tracking() {
    let config = ShutdownConfig::default();
    let coordinator = ShutdownCoordinator::new(config);

    // Register operations
    assert!(coordinator.register_operation().await.is_some());
    assert!(coordinator.register_operation().await.is_some());
    assert!(coordinator.register_operation().await.is_some());
    assert_eq!(coordinator.in_flight_operation_count().await, 3);

    // Unregister
    coordinator.unregister_operation().await;
    assert_eq!(coordinator.in_flight_operation_count().await, 2);
}

#[tokio::test]
async fn test_drain_rejects_new_operations() {
    let config = ShutdownConfig::default();
    let coordinator = ShutdownCoordinator::new(config);

    // Register operation before shutdown
    assert!(coordinator.register_operation().await.is_some());

    // Initiate shutdown
    coordinator.initiate_shutdown().await;

    // Start drain
    let coord_arc = Arc::new(coordinator);
    let coord_clone = coord_arc.clone();

    tokio::spawn(async move {
        coord_clone.drain().await;
    });

    // Wait for drain to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Try to register operation during drain - should fail
    assert!(coord_arc.register_operation().await.is_none());
}

#[tokio::test]
async fn test_graceful_drain_waits_for_completion() {
    let config = ShutdownConfig {
        graceful_drain: true,
        drain_timeout: Duration::from_secs(5),
        ..Default::default()
    };
    let coordinator = Arc::new(ShutdownCoordinator::new(config));

    // Register connections and operations
    coordinator.register_connection().await;
    coordinator.register_operation().await;
    coordinator.register_operation().await;

    // Initiate shutdown
    coordinator.initiate_shutdown().await;

    // Start drain in background
    let coord_clone = coordinator.clone();
    let drain_task = tokio::spawn(async move {
        coord_clone.drain().await;
    });

    // Wait a bit
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Should still be draining
    assert_eq!(coordinator.get_state().await, ShutdownState::Draining);

    // Complete operations and connection
    coordinator.unregister_operation().await;
    coordinator.unregister_operation().await;
    coordinator.unregister_connection().await;

    // Wait for drain to complete
    drain_task.await.unwrap();
}

#[tokio::test]
async fn test_drain_timeout_enforcement() {
    let config = ShutdownConfig {
        graceful_drain: true,
        drain_timeout: Duration::from_millis(200),
        ..Default::default()
    };
    let coordinator = ShutdownCoordinator::new(config);

    // Register operations that won't complete
    coordinator.register_operation().await;
    coordinator.register_operation().await;

    // Initiate and drain
    coordinator.initiate_shutdown().await;

    let start = std::time::Instant::now();
    coordinator.drain().await;
    let elapsed = start.elapsed();

    // Should have timed out around 200ms
    assert!(elapsed >= Duration::from_millis(200));
    assert!(elapsed < Duration::from_millis(500));

    // Operations should still exist
    assert_eq!(coordinator.in_flight_operation_count().await, 2);
}

#[tokio::test]
async fn test_force_drain() {
    let config = ShutdownConfig {
        graceful_drain: false,
        ..Default::default()
    };
    let coordinator = ShutdownCoordinator::new(config);

    // Register operations
    coordinator.register_operation().await;
    coordinator.register_operation().await;

    // Initiate shutdown
    coordinator.initiate_shutdown().await;

    // Force drain should complete immediately
    let start = std::time::Instant::now();
    coordinator.drain().await;
    let elapsed = start.elapsed();

    // Should complete very quickly (< 100ms)
    assert!(elapsed < Duration::from_millis(100));
}

#[tokio::test]
async fn test_complete_shutdown_sequence() {
    let config = ShutdownConfig::default();
    let coordinator = ShutdownCoordinator::new(config);

    // Register some activity
    coordinator.register_connection().await;
    coordinator.register_operation().await;

    // Execute full shutdown sequence
    coordinator.shutdown().await;

    assert_eq!(coordinator.get_state().await, ShutdownState::Terminated);
}

#[tokio::test]
async fn test_shutdown_broadcast_notification() {
    let config = ShutdownConfig::default();
    let coordinator = ShutdownCoordinator::new(config);

    // Subscribe to shutdown notifications
    let mut rx1 = coordinator.subscribe();
    let mut rx2 = coordinator.subscribe();

    // Initiate shutdown
    coordinator.initiate_shutdown().await;

    // Both subscribers should receive notification
    assert!(rx1.try_recv().is_ok());
    assert!(rx2.try_recv().is_ok());
}

#[tokio::test]
async fn test_server_with_shutdown() {
    let backend = Arc::new(MockBackend::default());
    let config = FsmServerConfig::default();
    let shutdown_config = ShutdownConfig {
        shutdown_timeout: Duration::from_secs(5),
        drain_timeout: Duration::from_secs(2),
        graceful_drain: true,
    };
    let shutdown = Arc::new(ShutdownCoordinator::new(shutdown_config));

    // Start server
    let server_shutdown = shutdown.clone();
    let server_task = tokio::spawn(async move {
        run_with_shutdown("127.0.0.1:0", backend, config, Some(server_shutdown)).await
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Initiate shutdown
    shutdown.initiate_shutdown().await;

    // Wait for server to stop
    tokio::time::timeout(Duration::from_secs(2), server_task)
        .await
        .expect("Server should stop within timeout")
        .expect("Server task should complete successfully")
        .expect("Server should shutdown cleanly");
}

#[tokio::test]
async fn test_shutdown_with_active_connections() {
    let backend = Arc::new(MockBackend::default());
    let mut config = FsmServerConfig::default();
    config.cleanup_interval = Duration::from_secs(60); // Don't interfere with test

    let shutdown_config = ShutdownConfig {
        shutdown_timeout: Duration::from_secs(5),
        drain_timeout: Duration::from_secs(2),
        graceful_drain: true,
    };
    let shutdown = Arc::new(ShutdownCoordinator::new(shutdown_config));

    // Start server on a random port
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_shutdown = shutdown.clone();
    let server_task = tokio::spawn(async move {
        drop(listener); // Close listener, we'll use our own accept loop
        run_with_shutdown(&addr.to_string(), backend, config, Some(server_shutdown)).await
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect a client (but don't close it)
    let _client = TcpStream::connect(addr).await.ok();

    // Wait a bit
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Initiate shutdown
    shutdown.initiate_shutdown().await;

    // Server should drain and complete within timeout
    tokio::time::timeout(Duration::from_secs(3), server_task)
        .await
        .expect("Server should stop within timeout")
        .expect("Server task should complete")
        .ok(); // Server may return error due to listener being closed
}

#[tokio::test]
async fn test_shutdown_state_transitions() {
    let config = ShutdownConfig::default();
    let coordinator = ShutdownCoordinator::new(config);

    // Initial state
    assert_eq!(coordinator.get_state().await, ShutdownState::Running);

    // Initiate shutdown
    coordinator.initiate_shutdown().await;
    assert_eq!(coordinator.get_state().await, ShutdownState::ShuttingDown);

    // Start drain (manually set state for test)
    coordinator.drain().await;
    assert_eq!(coordinator.get_state().await, ShutdownState::Draining);

    // Complete shutdown
    coordinator.complete_shutdown().await;
    assert_eq!(coordinator.get_state().await, ShutdownState::Terminated);
}

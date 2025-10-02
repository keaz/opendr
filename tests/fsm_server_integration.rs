//! Integration tests for the FSM-based LDAP server
//!
//! These tests verify that the FSM server infrastructure works correctly.
//! Full end-to-end LDAP operation testing is done in server_handlers.rs.

use std::sync::Arc;
use std::time::Duration;

use opendr::backend::MockBackend;
use opendr::fsm_server::FsmServerConfig;
use opendr::fsm_runtime::ConnectionFsmSet;
use tokio::net::TcpStream;

#[tokio::test]
async fn test_fsm_server_config_default() {
    // Test default configuration
    let config = FsmServerConfig::default();
    assert_eq!(config.operation_timeout, Duration::from_secs(300));
    assert_eq!(config.cleanup_interval, Duration::from_secs(60));
    assert_eq!(config.read_buffer_size, 4096);
    assert_eq!(config.max_concurrent_operations, 100);
}

#[tokio::test]
async fn test_fsm_server_config_custom() {
    // Test custom configuration
    let custom_config = FsmServerConfig {
        operation_timeout: Duration::from_secs(60),
        cleanup_interval: Duration::from_secs(30),
        read_buffer_size: 8192,
        max_concurrent_operations: 50,
    };

    assert_eq!(custom_config.operation_timeout, Duration::from_secs(60));
    assert_eq!(custom_config.cleanup_interval, Duration::from_secs(30));
    assert_eq!(custom_config.read_buffer_size, 8192);
    assert_eq!(custom_config.max_concurrent_operations, 50);
}

#[tokio::test]
async fn test_connection_fsm_set_with_real_socket() {
    // Test that ConnectionFsmSet can be created with a real socket
    let backend = Arc::new(MockBackend::default());

    // Create a listener and connect to it
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Spawn task to accept connection
    let accept_task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let fsm_set = ConnectionFsmSet::new(socket, backend, None);

        // Verify FSM set is initialized
        assert_eq!(fsm_set.active_operation_count(), 0);
        assert!(!fsm_set.is_authenticated());
        assert!(!fsm_set.is_terminal());
    });

    // Connect to the listener
    let _client = TcpStream::connect(addr).await.unwrap();

    // Wait for acceptance and verification
    accept_task.await.unwrap();
}

#[tokio::test]
async fn test_connection_fsm_set_timeout_operations() {
    // Test timeout management with ConnectionFsmSet
    let backend = Arc::new(MockBackend::default());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let accept_task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut fsm_set = ConnectionFsmSet::new(socket, backend, None);

        // Initially no operations
        assert_eq!(fsm_set.active_operation_count(), 0);

        // Test timeout cleanup with very short timeout
        let timeout = Duration::from_millis(10);

        // Wait for timeout period
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Cleanup timed out operations
        let cleaned = fsm_set.cleanup_timed_out_operations(timeout);
        assert_eq!(cleaned, 0); // No operations to clean

        // Cleanup terminal operations
        let cleaned = fsm_set.cleanup_terminal_operations();
        assert_eq!(cleaned, 0); // No operations to clean
    });

    let _client = TcpStream::connect(addr).await.unwrap();
    accept_task.await.unwrap();
}

#[tokio::test]
async fn test_fsm_server_multiple_connections() {
    // Test that multiple connections can be handled
    let backend = Arc::new(MockBackend::default());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Spawn task to accept multiple connections
    let server_task = tokio::spawn(async move {
        for _ in 0..3 {
            let (socket, _) = listener.accept().await.unwrap();
            let backend = backend.clone();

            tokio::spawn(async move {
                let _fsm_set = ConnectionFsmSet::new(socket, backend, None);
                // Let it live briefly
                tokio::time::sleep(Duration::from_millis(50)).await;
            });
        }
    });

    // Connect 3 times
    for _ in 0..3 {
        let _client = TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Wait for server to handle all connections
    tokio::time::timeout(Duration::from_secs(2), server_task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn test_fsm_server_connection_cleanup() {
    // Test that connections clean up properly
    let backend = Arc::new(MockBackend::default());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let accept_task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let fsm_set = ConnectionFsmSet::new(socket, backend, None);

        // FSM set should be created successfully
        assert!(!fsm_set.is_terminal());

        // When we drop it, resources should be cleaned up
        drop(fsm_set);
    });

    let client = TcpStream::connect(addr).await.unwrap();
    accept_task.await.unwrap();

    // Client should be able to close normally
    drop(client);
}

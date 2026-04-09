//! Integration tests for resource management and connection pooling
//!
//! These tests verify that the connection pool and resource limits work correctly
//! in a realistic server scenario.

use opendr::connection_pool::{ConnectionPool, ResourceLimits};
use opendr::fsm_server::FsmServerConfig;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

/// Helper to create a test address
fn test_addr(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
}

#[tokio::test]
async fn test_connection_pool_basic_flow() {
    let pool = ConnectionPool::new(ResourceLimits::default());

    // Acquire connection
    let conn_id = pool.acquire_connection(test_addr(1234)).await;
    assert!(conn_id.is_some());

    let conn_id = conn_id.unwrap();

    // Verify statistics
    let stats = pool.get_statistics().await;
    assert_eq!(stats.active_connections, 1);
    assert_eq!(stats.total_connections, 1);

    // Release connection
    pool.release_connection(conn_id).await;

    // Verify cleanup
    let stats = pool.get_statistics().await;
    assert_eq!(stats.active_connections, 0);
}

#[tokio::test]
async fn test_max_connections_enforcement() {
    let limits = ResourceLimits {
        max_connections: 3,
        ..Default::default()
    };
    let pool = ConnectionPool::new(limits);

    // Acquire 3 connections
    let conn1 = pool.acquire_connection(test_addr(1234)).await.unwrap();
    let _conn2 = pool.acquire_connection(test_addr(1235)).await.unwrap();
    let _conn3 = pool.acquire_connection(test_addr(1236)).await.unwrap();

    // Fourth should be rejected
    let conn4 = pool.acquire_connection(test_addr(1237)).await;
    assert!(conn4.is_none());

    // Verify rejection count
    let stats = pool.get_statistics().await;
    assert_eq!(stats.active_connections, 3);
    assert_eq!(stats.rejected_connections, 1);

    // Release one connection
    pool.release_connection(conn1).await;

    // Now we should be able to acquire again
    let conn5 = pool.acquire_connection(test_addr(1238)).await;
    assert!(conn5.is_some());
}

#[tokio::test]
async fn test_per_ip_connection_limits() {
    let limits = ResourceLimits {
        max_connections_per_ip: 2,
        max_connections: 100,
        ..Default::default()
    };
    let pool = ConnectionPool::new(limits);

    let ip1_addr = test_addr(0);
    let ip2_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 1234);

    // Acquire 2 connections from IP1
    let _conn1 = pool.acquire_connection(ip1_addr).await.unwrap();
    let _conn2 = pool.acquire_connection(ip1_addr).await.unwrap();

    // Third from same IP should be rejected
    let conn3 = pool.acquire_connection(ip1_addr).await;
    assert!(conn3.is_none());

    // But different IP should work
    let conn4 = pool.acquire_connection(ip2_addr).await;
    assert!(conn4.is_some());

    // Verify IP tracking
    assert_eq!(pool.get_ip_connection_count(ip1_addr).await, 2);
    assert_eq!(pool.get_ip_connection_count(ip2_addr).await, 1);
}

#[tokio::test]
async fn test_operation_limits() {
    let limits = ResourceLimits {
        max_operations_per_connection: 5,
        ..Default::default()
    };
    let pool = ConnectionPool::new(limits);

    let conn_id = pool.acquire_connection(test_addr(1234)).await.unwrap();

    // Start 5 operations
    for _ in 0..5 {
        assert!(pool.start_operation(conn_id).await);
    }

    // Sixth should be rejected
    assert!(!pool.start_operation(conn_id).await);

    // Verify statistics
    let stats = pool.get_statistics().await;
    assert_eq!(stats.total_operations, 5);
    assert_eq!(stats.rejected_operations, 1);

    // End one operation
    pool.end_operation(conn_id).await;

    // Now we should be able to start another
    assert!(pool.start_operation(conn_id).await);
}

#[tokio::test]
async fn test_memory_tracking_per_connection() {
    let limits = ResourceLimits {
        max_memory_per_connection: 1000,
        max_total_memory: 10000,
        ..Default::default()
    };
    let pool = ConnectionPool::new(limits);

    let conn_id = pool.acquire_connection(test_addr(1234)).await.unwrap();

    // Allocate memory within limit
    assert!(pool.update_memory_usage(conn_id, 500).await);
    assert!(pool.update_memory_usage(conn_id, 400).await);

    // Should be at 900 bytes
    let stats = pool.get_statistics().await;
    assert_eq!(stats.total_memory_usage, 900);

    // Try to allocate more (would exceed 1000)
    assert!(!pool.update_memory_usage(conn_id, 200).await);

    // Release memory
    assert!(pool.update_memory_usage(conn_id, -500).await);

    // Now should work
    assert!(pool.update_memory_usage(conn_id, 200).await);
}

#[tokio::test]
async fn test_memory_tracking_total_limit() {
    let limits = ResourceLimits {
        max_memory_per_connection: 1000,
        max_total_memory: 1500,
        ..Default::default()
    };
    let pool = ConnectionPool::new(limits);

    let conn1 = pool.acquire_connection(test_addr(1234)).await.unwrap();
    let conn2 = pool.acquire_connection(test_addr(1235)).await.unwrap();

    // Allocate from both connections
    assert!(pool.update_memory_usage(conn1, 800).await);
    assert!(pool.update_memory_usage(conn2, 600).await);

    // Should be at 1400 total
    let stats = pool.get_statistics().await;
    assert_eq!(stats.total_memory_usage, 1400);

    // Try to allocate more (would exceed total limit of 1500)
    assert!(!pool.update_memory_usage(conn2, 200).await);

    // Release from conn1
    assert!(pool.update_memory_usage(conn1, -300).await);

    // Now conn2 can allocate
    assert!(pool.update_memory_usage(conn2, 200).await);
}

#[tokio::test]
async fn test_idle_connection_cleanup() {
    let limits = ResourceLimits {
        connection_idle_timeout: Duration::from_millis(100),
        ..Default::default()
    };
    let pool = ConnectionPool::new(limits);

    let conn1 = pool.acquire_connection(test_addr(1234)).await.unwrap();
    let conn2 = pool.acquire_connection(test_addr(1235)).await.unwrap();

    // Wait for timeout
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Both should be idle
    let idle = pool.get_idle_connections().await;
    assert_eq!(idle.len(), 2);

    // Clean up
    let cleaned = pool.cleanup_idle_connections().await;
    assert_eq!(cleaned, 2);

    // Connections should be gone
    assert!(!pool.has_connection(conn1).await);
    assert!(!pool.has_connection(conn2).await);

    let stats = pool.get_statistics().await;
    assert_eq!(stats.active_connections, 0);
}

#[tokio::test]
async fn test_activity_prevents_idle_cleanup() {
    let limits = ResourceLimits {
        connection_idle_timeout: Duration::from_millis(100),
        ..Default::default()
    };
    let pool = ConnectionPool::new(limits);

    let conn_id = pool.acquire_connection(test_addr(1234)).await.unwrap();

    // Wait a bit
    tokio::time::sleep(Duration::from_millis(60)).await;

    // Update activity
    pool.update_activity(conn_id).await;

    // Wait for what would be timeout
    tokio::time::sleep(Duration::from_millis(60)).await;

    // Should not be idle
    let idle = pool.get_idle_connections().await;
    assert_eq!(idle.len(), 0);

    // Connection should still exist
    assert!(pool.has_connection(conn_id).await);
}

#[tokio::test]
async fn test_fsm_server_config_includes_resource_limits() {
    let config = FsmServerConfig::default();

    // Verify default resource limits are set
    assert_eq!(config.resource_limits.max_connections, 1000);
    assert_eq!(config.resource_limits.max_connections_per_ip, 10);
    assert_eq!(config.resource_limits.max_operations_per_connection, 100);
}

#[tokio::test]
async fn test_concurrent_connection_management() {
    let limits = ResourceLimits {
        max_connections: 100,
        max_connections_per_ip: 50,
        ..Default::default()
    };
    let pool = Arc::new(ConnectionPool::new(limits));

    // Spawn multiple tasks to acquire/release connections
    let mut handles = vec![];

    for i in 0..20 {
        let pool_clone = pool.clone();
        let handle = tokio::spawn(async move {
            let addr = test_addr(5000 + i);
            if let Some(conn_id) = pool_clone.acquire_connection(addr).await {
                // Do some work
                pool_clone.start_operation(conn_id).await;
                tokio::time::sleep(Duration::from_millis(10)).await;
                pool_clone.end_operation(conn_id).await;

                // Release
                pool_clone.release_connection(conn_id).await;
            }
        });
        handles.push(handle);
    }

    // Wait for all tasks
    for handle in handles {
        handle.await.unwrap();
    }

    // All connections should be released
    let stats = pool.get_statistics().await;
    assert_eq!(stats.active_connections, 0);
    assert_eq!(stats.total_operations, 0);
}

#[tokio::test]
async fn test_statistics_accuracy() {
    let pool = ConnectionPool::new(ResourceLimits::default());

    // Create multiple connections
    let conn1 = pool.acquire_connection(test_addr(1234)).await.unwrap();
    let conn2 = pool.acquire_connection(test_addr(1235)).await.unwrap();

    // Start operations
    pool.start_operation(conn1).await;
    pool.start_operation(conn1).await;
    pool.start_operation(conn2).await;

    // Allocate memory
    pool.update_memory_usage(conn1, 500).await;
    pool.update_memory_usage(conn2, 300).await;

    // Check statistics
    let stats = pool.get_statistics().await;
    assert_eq!(stats.active_connections, 2);
    assert_eq!(stats.total_connections, 2);
    assert_eq!(stats.total_operations, 3);
    assert_eq!(stats.total_memory_usage, 800);

    // Verify IP tracking (both connections from same IP)
    assert_eq!(stats.connections_by_ip.len(), 1);
    assert_eq!(*stats.connections_by_ip.get("127.0.0.1").unwrap(), 2);
}

#[tokio::test]
async fn test_connection_release_cleanup() {
    let pool = ConnectionPool::new(ResourceLimits::default());

    let conn_id = pool.acquire_connection(test_addr(1234)).await.unwrap();

    // Allocate resources
    pool.start_operation(conn_id).await;
    pool.start_operation(conn_id).await;
    pool.update_memory_usage(conn_id, 1000).await;

    let stats = pool.get_statistics().await;
    assert_eq!(stats.total_operations, 2);
    assert_eq!(stats.total_memory_usage, 1000);

    // Release connection
    pool.release_connection(conn_id).await;

    // All resources should be cleaned up
    let stats = pool.get_statistics().await;
    assert_eq!(stats.active_connections, 0);
    assert_eq!(stats.total_operations, 0);
    assert_eq!(stats.total_memory_usage, 0);
}

//! Unit tests for Enhanced Consumer Registry (Task 1.2)
//!
//! Tests the new features added to ConsumerConnection and ConsumerRegistry:
//! - Sync mode tracking (RefreshOnly vs RefreshAndPersist)
//! - Persistent connection tracking
//! - Cookie management per consumer
//! - Querying consumers by sync mode

use opendr::replication::ConsumerRegistryImpl;
use opendr::replication_provider_fsm::{ConsumerConnection, ConsumerRegistry, SyncMode};
use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
async fn test_consumer_connection_defaults() {
    let conn = ConsumerConnection::new("consumer1".to_string());

    assert_eq!(conn.address, "consumer1");
    assert_eq!(conn.sync_mode, SyncMode::RefreshOnly);
    assert!(!conn.is_persistent);
    assert_eq!(conn.last_cookie, None);
    assert!(!conn.consumer_id.is_empty());
}

#[tokio::test]
async fn test_consumer_connection_with_sync_mode_refresh_only() {
    let conn = ConsumerConnection::with_sync_mode("consumer1".to_string(), SyncMode::RefreshOnly);

    assert_eq!(conn.sync_mode, SyncMode::RefreshOnly);
    assert!(!conn.is_persistent);
    assert!(!conn.is_persistent_mode());
}

#[tokio::test]
async fn test_consumer_connection_with_sync_mode_refresh_and_persist() {
    let conn =
        ConsumerConnection::with_sync_mode("consumer1".to_string(), SyncMode::RefreshAndPersist);

    assert_eq!(conn.sync_mode, SyncMode::RefreshAndPersist);
    assert!(conn.is_persistent);
    assert!(conn.is_persistent_mode());
}

#[tokio::test]
async fn test_consumer_connection_set_sync_mode() {
    let mut conn = ConsumerConnection::new("consumer1".to_string());
    assert_eq!(conn.sync_mode, SyncMode::RefreshOnly);
    assert!(!conn.is_persistent);

    // Change to persistent
    conn.set_sync_mode(SyncMode::RefreshAndPersist);
    assert_eq!(conn.sync_mode, SyncMode::RefreshAndPersist);
    assert!(conn.is_persistent);
    assert!(conn.is_persistent_mode());

    // Change back to refresh only
    conn.set_sync_mode(SyncMode::RefreshOnly);
    assert_eq!(conn.sync_mode, SyncMode::RefreshOnly);
    assert!(!conn.is_persistent);
    assert!(!conn.is_persistent_mode());
}

#[tokio::test]
async fn test_consumer_connection_update_cookie() {
    let mut conn = ConsumerConnection::new("consumer1".to_string());
    assert_eq!(conn.last_cookie, None);

    let initial_activity = conn.last_activity;

    // Wait a bit to ensure timestamp changes
    sleep(Duration::from_millis(10)).await;

    conn.update_cookie("seq-12345".to_string());

    assert_eq!(conn.last_cookie, Some("seq-12345".to_string()));
    assert_eq!(conn.get_last_cookie(), Some(&"seq-12345".to_string()));
    assert!(conn.last_activity > initial_activity);
}

#[tokio::test]
async fn test_consumer_connection_get_last_cookie() {
    let mut conn = ConsumerConnection::new("consumer1".to_string());
    assert_eq!(conn.get_last_cookie(), None);

    conn.update_cookie("cookie1".to_string());
    assert_eq!(conn.get_last_cookie(), Some(&"cookie1".to_string()));

    conn.update_cookie("cookie2".to_string());
    assert_eq!(conn.get_last_cookie(), Some(&"cookie2".to_string()));
}

#[tokio::test]
async fn test_registry_get_persistent_consumers_empty() {
    let registry = ConsumerRegistryImpl::new();

    let persistent = registry.get_persistent_consumers().await.unwrap();
    assert_eq!(persistent.len(), 0);
}

#[tokio::test]
async fn test_registry_get_persistent_consumers_with_mixed_consumers() {
    let mut registry = ConsumerRegistryImpl::new();

    // Add refresh-only consumer
    let conn1 = ConsumerConnection::with_sync_mode("consumer1".to_string(), SyncMode::RefreshOnly);
    registry
        .register_consumer("consumer1", conn1)
        .await
        .unwrap();

    // Add persistent consumer
    let conn2 =
        ConsumerConnection::with_sync_mode("consumer2".to_string(), SyncMode::RefreshAndPersist);
    registry
        .register_consumer("consumer2", conn2)
        .await
        .unwrap();

    // Add another persistent consumer
    let conn3 =
        ConsumerConnection::with_sync_mode("consumer3".to_string(), SyncMode::RefreshAndPersist);
    registry
        .register_consumer("consumer3", conn3)
        .await
        .unwrap();

    // Get all active consumers
    let active = registry.get_active_consumers().await.unwrap();
    assert_eq!(active.len(), 3);

    // Get only persistent consumers
    let persistent = registry.get_persistent_consumers().await.unwrap();
    assert_eq!(persistent.len(), 2);
    assert!(persistent.contains(&"consumer2".to_string()));
    assert!(persistent.contains(&"consumer3".to_string()));
    assert!(!persistent.contains(&"consumer1".to_string()));
}

#[tokio::test]
async fn test_registry_get_consumer_not_found() {
    let registry = ConsumerRegistryImpl::new();

    let result = registry.get_consumer("nonexistent").await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_registry_get_consumer_found() {
    let mut registry = ConsumerRegistryImpl::new();

    let conn = ConsumerConnection::with_sync_mode(
        "test-consumer".to_string(),
        SyncMode::RefreshAndPersist,
    );
    registry
        .register_consumer("consumer1", conn.clone())
        .await
        .unwrap();

    let result = registry.get_consumer("consumer1").await.unwrap();
    assert!(result.is_some());

    let retrieved = result.unwrap();
    assert_eq!(retrieved.address, "test-consumer");
    assert_eq!(retrieved.sync_mode, SyncMode::RefreshAndPersist);
    assert!(retrieved.is_persistent);
}

#[tokio::test]
async fn test_registry_update_consumer_cookie() {
    let mut registry = ConsumerRegistryImpl::new();

    let conn = ConsumerConnection::new("consumer1".to_string());
    registry.register_consumer("consumer1", conn).await.unwrap();

    // Update cookie
    registry
        .update_consumer_cookie("consumer1", "seq-100".to_string())
        .await
        .unwrap();

    // Verify cookie was updated
    let retrieved = registry.get_consumer("consumer1").await.unwrap().unwrap();
    assert_eq!(retrieved.last_cookie, Some("seq-100".to_string()));

    // Update again
    registry
        .update_consumer_cookie("consumer1", "seq-200".to_string())
        .await
        .unwrap();

    let retrieved = registry.get_consumer("consumer1").await.unwrap().unwrap();
    assert_eq!(retrieved.last_cookie, Some("seq-200".to_string()));
}

#[tokio::test]
async fn test_registry_update_cookie_for_nonexistent_consumer() {
    let mut registry = ConsumerRegistryImpl::new();

    // Should not error, just silently do nothing
    let result = registry
        .update_consumer_cookie("nonexistent", "cookie".to_string())
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_consumer_lifecycle_with_persistent_mode() {
    let mut registry = ConsumerRegistryImpl::new();

    // Register persistent consumer
    let conn = ConsumerConnection::with_sync_mode(
        "persistent-consumer".to_string(),
        SyncMode::RefreshAndPersist,
    );
    registry.register_consumer("consumer1", conn).await.unwrap();

    // Verify registered
    assert!(registry.is_consumer_connected("consumer1").await.unwrap());

    // Verify in persistent list
    let persistent = registry.get_persistent_consumers().await.unwrap();
    assert_eq!(persistent.len(), 1);
    assert!(persistent.contains(&"consumer1".to_string()));

    // Update cookie
    registry
        .update_consumer_cookie("consumer1", "seq-50".to_string())
        .await
        .unwrap();

    // Verify cookie stored
    let retrieved = registry.get_consumer("consumer1").await.unwrap().unwrap();
    assert_eq!(retrieved.last_cookie, Some("seq-50".to_string()));

    // Unregister
    let removed = registry.unregister_consumer("consumer1").await.unwrap();
    assert!(removed);

    // Verify no longer persistent
    let persistent = registry.get_persistent_consumers().await.unwrap();
    assert_eq!(persistent.len(), 0);
}

#[tokio::test]
async fn test_multiple_persistent_consumers_with_different_cookies() {
    let mut registry = ConsumerRegistryImpl::new();

    // Register 3 persistent consumers
    for i in 1..=3 {
        let conn = ConsumerConnection::with_sync_mode(
            format!("consumer{}", i),
            SyncMode::RefreshAndPersist,
        );
        registry
            .register_consumer(&format!("consumer{}", i), conn)
            .await
            .unwrap();
    }

    // Verify all persistent
    let persistent = registry.get_persistent_consumers().await.unwrap();
    assert_eq!(persistent.len(), 3);

    // Update different cookies for each
    for i in 1..=3 {
        registry
            .update_consumer_cookie(&format!("consumer{}", i), format!("seq-{}", i * 100))
            .await
            .unwrap();
    }

    // Verify each has correct cookie
    for i in 1..=3 {
        let conn = registry
            .get_consumer(&format!("consumer{}", i))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(conn.last_cookie, Some(format!("seq-{}", i * 100)));
    }
}

#[tokio::test]
async fn test_consumer_id_uniqueness() {
    let conn1 = ConsumerConnection::new("address1".to_string());
    let conn2 = ConsumerConnection::new("address1".to_string());

    // Same address but different consumer IDs
    assert_ne!(conn1.consumer_id, conn2.consumer_id);
}

#[tokio::test]
async fn test_persistent_mode_change_lifecycle() {
    let mut registry = ConsumerRegistryImpl::new();

    // Start with refresh-only
    let mut conn =
        ConsumerConnection::with_sync_mode("consumer1".to_string(), SyncMode::RefreshOnly);
    registry
        .register_consumer("consumer1", conn.clone())
        .await
        .unwrap();

    // Verify not in persistent list
    let persistent = registry.get_persistent_consumers().await.unwrap();
    assert_eq!(persistent.len(), 0);

    // Change to persistent mode
    conn.set_sync_mode(SyncMode::RefreshAndPersist);
    registry.register_consumer("consumer1", conn).await.unwrap();

    // Verify now in persistent list
    let persistent = registry.get_persistent_consumers().await.unwrap();
    assert_eq!(persistent.len(), 1);
    assert!(persistent.contains(&"consumer1".to_string()));
}

#[tokio::test]
async fn test_registry_thread_safety() {
    use std::sync::Arc;
    use tokio::sync::RwLock;

    let registry = Arc::new(RwLock::new(ConsumerRegistryImpl::new()));

    // Spawn multiple tasks to register consumers concurrently
    let mut handles = vec![];
    for i in 0..10 {
        let registry = registry.clone();
        let handle = tokio::spawn(async move {
            let mut reg = registry.write().await;
            let conn = ConsumerConnection::with_sync_mode(
                format!("consumer{}", i),
                if i % 2 == 0 {
                    SyncMode::RefreshAndPersist
                } else {
                    SyncMode::RefreshOnly
                },
            );
            reg.register_consumer(&format!("consumer{}", i), conn)
                .await
                .unwrap();
        });
        handles.push(handle);
    }

    // Wait for all registrations
    for handle in handles {
        handle.await.unwrap();
    }

    // Verify all registered
    let reg = registry.read().await;
    let active = reg.get_active_consumers().await.unwrap();
    assert_eq!(active.len(), 10);

    // Verify 5 are persistent (even numbers)
    let persistent = reg.get_persistent_consumers().await.unwrap();
    assert_eq!(persistent.len(), 5);
}

#[tokio::test]
async fn test_connection_duration_tracking() {
    let conn = ConsumerConnection::new("consumer1".to_string());

    sleep(Duration::from_millis(100)).await;

    let duration = conn.connection_duration();
    assert!(duration.as_millis() >= 100);
}

#[tokio::test]
async fn test_consumer_capabilities_preserved() {
    let mut conn =
        ConsumerConnection::with_sync_mode("consumer1".to_string(), SyncMode::RefreshAndPersist);

    conn.add_capability("ldap_v3".to_string());
    conn.add_capability("tls".to_string());

    assert_eq!(conn.capabilities.len(), 2);
    assert!(conn.capabilities.contains("ldap_v3"));
    assert!(conn.capabilities.contains("tls"));
}

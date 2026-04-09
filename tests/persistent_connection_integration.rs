//! Integration tests for the Persistent Connection Handler
//!
//! These tests verify the functionality of the persistent connection management
//! system for push-based replication. They cover:
//! - Connection lifecycle (create, use, close)
//! - Entry sending with different sync states
//! - Sync info message delivery
//! - Heartbeat mechanism
//! - Connection health monitoring
//! - Error handling and reconnection
//! - Thread safety
//!
//! Note: Some tests use mock connections since we don't have a real LDAP consumer
//! in the test environment. In production, these would connect to actual LDAP servers.

use opendr::persistent_connection::{
    ConnectionStats, DirectoryEntry, PersistentConsumer, SyncInfo, SyncState,
};
use std::sync::Arc;
use std::time::Duration;

/// Test: Create a basic persistent consumer
#[tokio::test]
async fn test_create_persistent_consumer() {
    // Note: This will fail to connect since there's no server, but tests construction
    let result = PersistentConsumer::new(
        "test-consumer-1".to_string(),
        "ldap://localhost:12389".to_string(),
        "dc=example,dc=com".to_string(),
        Duration::from_secs(30),
    )
    .await;

    // We expect this to fail with connection error (no server running)
    assert!(result.is_err(), "Should fail when no server is available");
    if let Err(e) = result {
        assert!(
            e.contains("Failed to connect"),
            "Error should mention connection failure: {}",
            e
        );
    }
}

/// Test: Create consumer with custom filter and attributes
#[tokio::test]
async fn test_create_consumer_with_filter() {
    let result = PersistentConsumer::with_filter(
        "test-consumer-2".to_string(),
        "ldap://localhost:12390".to_string(),
        "dc=example,dc=com".to_string(),
        "(objectClass=person)".to_string(),
        vec!["cn".to_string(), "sn".to_string(), "mail".to_string()],
        Duration::from_secs(20),
    )
    .await;

    // Should fail to connect, but that's expected
    assert!(result.is_err(), "Should fail when no server is available");
}

/// Test: Directory entry creation and properties
#[test]
fn test_directory_entry() {
    let entry = DirectoryEntry::new(
        "cn=John Doe,ou=people,dc=example,dc=com".to_string(),
        "550e8400-e29b-41d4-a716-446655440000".to_string(),
        vec![
            ("cn".to_string(), vec!["John Doe".to_string()]),
            ("sn".to_string(), vec!["Doe".to_string()]),
            ("mail".to_string(), vec!["john@example.com".to_string()]),
            (
                "objectClass".to_string(),
                vec![
                    "top".to_string(),
                    "person".to_string(),
                    "inetOrgPerson".to_string(),
                ],
            ),
        ],
    );

    assert_eq!(entry.dn, "cn=John Doe,ou=people,dc=example,dc=com");
    assert_eq!(entry.uuid, "550e8400-e29b-41d4-a716-446655440000");
    assert_eq!(entry.attributes.len(), 4);

    // Verify specific attributes
    let cn = entry
        .attributes
        .iter()
        .find(|(k, _)| k == "cn")
        .map(|(_, v)| v);
    assert_eq!(cn, Some(&vec!["John Doe".to_string()]));
}

/// Test: SyncState control value encoding
#[test]
fn test_sync_state_encoding() {
    assert_eq!(SyncState::Present.to_control_value(), 0);
    assert_eq!(SyncState::Add.to_control_value(), 1);
    assert_eq!(SyncState::Modify.to_control_value(), 2);
    assert_eq!(SyncState::Delete.to_control_value(), 3);
}

/// Test: SyncState clone and equality
#[test]
fn test_sync_state_clone_equality() {
    let state1 = SyncState::Add;
    let state2 = state1.clone();
    assert_eq!(state1, state2);

    let state3 = SyncState::Modify;
    assert_ne!(state1, state3);
}

/// Test: SyncInfo variants
#[test]
fn test_sync_info_variants() {
    // New Cookie
    let info1 =
        SyncInfo::NewCookie("rid=001,csn=20240101000000.000000Z#000000#001#000000".to_string());
    match info1 {
        SyncInfo::NewCookie(cookie) => {
            assert!(cookie.contains("rid=001"));
        }
        _ => panic!("Wrong variant"),
    }

    // Refresh Delete
    let info2 = SyncInfo::RefreshDelete {
        cookie: Some("cookie123".to_string()),
        refresh_done: true,
    };
    match info2 {
        SyncInfo::RefreshDelete {
            cookie,
            refresh_done,
        } => {
            assert_eq!(cookie, Some("cookie123".to_string()));
            assert!(refresh_done);
        }
        _ => panic!("Wrong variant"),
    }

    // Refresh Present
    let info3 = SyncInfo::RefreshPresent {
        cookie: None,
        refresh_done: false,
    };
    match info3 {
        SyncInfo::RefreshPresent {
            cookie,
            refresh_done,
        } => {
            assert!(cookie.is_none());
            assert!(!refresh_done);
        }
        _ => panic!("Wrong variant"),
    }

    // Sync ID Set
    let info4 = SyncInfo::SyncIdSet {
        cookie: Some("cookie456".to_string()),
        refresh_deletes: true,
        uuids: vec![
            "uuid1".to_string(),
            "uuid2".to_string(),
            "uuid3".to_string(),
        ],
    };
    match info4 {
        SyncInfo::SyncIdSet {
            cookie,
            refresh_deletes,
            uuids,
        } => {
            assert_eq!(cookie, Some("cookie456".to_string()));
            assert!(refresh_deletes);
            assert_eq!(uuids.len(), 3);
        }
        _ => panic!("Wrong variant"),
    }
}

/// Test: Connection statistics initialization
#[test]
fn test_connection_stats() {
    let stats = ConnectionStats::default();
    assert_eq!(stats.entries_sent, 0);
    assert_eq!(stats.sync_info_sent, 0);
    assert_eq!(stats.heartbeats_sent, 0);
    assert_eq!(stats.errors, 0);
    assert!(stats.last_error.is_none());

    // Test clone
    let stats2 = stats.clone();
    assert_eq!(stats2.entries_sent, 0);
}

/// Mock consumer for testing without actual LDAP connection
mod mock_consumer {
    use super::*;
    use std::sync::Mutex as StdMutex;

    pub struct MockConsumer {
        #[allow(dead_code)]
        pub id: String,
        pub entries_sent: Arc<StdMutex<Vec<(String, SyncState)>>>,
        pub sync_info_sent: Arc<StdMutex<Vec<SyncInfo>>>,
        pub heartbeats: Arc<StdMutex<u32>>,
        pub is_alive: Arc<StdMutex<bool>>,
    }

    impl MockConsumer {
        pub fn new(id: String) -> Self {
            Self {
                id,
                entries_sent: Arc::new(StdMutex::new(Vec::new())),
                sync_info_sent: Arc::new(StdMutex::new(Vec::new())),
                heartbeats: Arc::new(StdMutex::new(0)),
                is_alive: Arc::new(StdMutex::new(true)),
            }
        }

        pub async fn send_entry(&self, dn: String, state: SyncState) -> Result<(), String> {
            let mut entries = self.entries_sent.lock().unwrap();
            entries.push((dn, state));
            Ok(())
        }

        pub async fn send_sync_info(&self, info: SyncInfo) -> Result<(), String> {
            let mut sync_info = self.sync_info_sent.lock().unwrap();
            sync_info.push(info);
            Ok(())
        }

        pub async fn send_heartbeat(&self) -> Result<(), String> {
            let mut heartbeats = self.heartbeats.lock().unwrap();
            *heartbeats += 1;
            Ok(())
        }

        pub async fn is_alive(&self) -> bool {
            *self.is_alive.lock().unwrap()
        }

        pub fn get_entries_count(&self) -> usize {
            self.entries_sent.lock().unwrap().len()
        }

        pub fn get_sync_info_count(&self) -> usize {
            self.sync_info_sent.lock().unwrap().len()
        }

        pub fn get_heartbeat_count(&self) -> u32 {
            *self.heartbeats.lock().unwrap()
        }
    }
}

/// Test: Mock consumer entry sending
#[tokio::test]
async fn test_mock_consumer_send_entry() {
    let consumer = mock_consumer::MockConsumer::new("mock-1".to_string());

    // Send several entries
    consumer
        .send_entry("cn=user1,dc=example,dc=com".to_string(), SyncState::Add)
        .await
        .unwrap();
    consumer
        .send_entry("cn=user2,dc=example,dc=com".to_string(), SyncState::Modify)
        .await
        .unwrap();
    consumer
        .send_entry("cn=user3,dc=example,dc=com".to_string(), SyncState::Delete)
        .await
        .unwrap();

    assert_eq!(consumer.get_entries_count(), 3);

    let entries = consumer.entries_sent.lock().unwrap();
    assert_eq!(entries[0].0, "cn=user1,dc=example,dc=com");
    assert_eq!(entries[0].1, SyncState::Add);
    assert_eq!(entries[1].1, SyncState::Modify);
    assert_eq!(entries[2].1, SyncState::Delete);
}

/// Test: Mock consumer sync info sending
#[tokio::test]
async fn test_mock_consumer_send_sync_info() {
    let consumer = mock_consumer::MockConsumer::new("mock-2".to_string());

    consumer
        .send_sync_info(SyncInfo::NewCookie("cookie1".to_string()))
        .await
        .unwrap();
    consumer
        .send_sync_info(SyncInfo::RefreshPresent {
            cookie: Some("cookie2".to_string()),
            refresh_done: true,
        })
        .await
        .unwrap();

    assert_eq!(consumer.get_sync_info_count(), 2);
}

/// Test: Mock consumer heartbeat
#[tokio::test]
async fn test_mock_consumer_heartbeat() {
    let consumer = mock_consumer::MockConsumer::new("mock-3".to_string());

    assert_eq!(consumer.get_heartbeat_count(), 0);

    consumer.send_heartbeat().await.unwrap();
    consumer.send_heartbeat().await.unwrap();
    consumer.send_heartbeat().await.unwrap();

    assert_eq!(consumer.get_heartbeat_count(), 3);
}

/// Test: Mock consumer health check
#[tokio::test]
async fn test_mock_consumer_health() {
    let consumer = mock_consumer::MockConsumer::new("mock-4".to_string());

    assert!(consumer.is_alive().await);

    // Mark as dead
    {
        let mut alive = consumer.is_alive.lock().unwrap();
        *alive = false;
    }

    assert!(!consumer.is_alive().await);
}

/// Test: Concurrent operations on mock consumer (thread safety)
#[tokio::test]
async fn test_mock_consumer_concurrent() {
    let consumer = Arc::new(mock_consumer::MockConsumer::new("mock-5".to_string()));

    // Spawn 10 tasks each sending 10 entries
    let mut handles = vec![];
    for i in 0..10 {
        let consumer_clone = consumer.clone();
        let handle = tokio::spawn(async move {
            for j in 0..10 {
                let dn = format!("cn=user{}-{},dc=example,dc=com", i, j);
                consumer_clone.send_entry(dn, SyncState::Add).await.unwrap();
            }
        });
        handles.push(handle);
    }

    // Wait for all tasks
    for handle in handles {
        handle.await.unwrap();
    }

    // Should have 100 entries
    assert_eq!(consumer.get_entries_count(), 100);
}

/// Test: Multiple consumers operating independently
#[tokio::test]
async fn test_multiple_consumers() {
    let consumer1 = mock_consumer::MockConsumer::new("mock-6a".to_string());
    let consumer2 = mock_consumer::MockConsumer::new("mock-6b".to_string());

    consumer1
        .send_entry("cn=user1,dc=example,dc=com".to_string(), SyncState::Add)
        .await
        .unwrap();
    consumer2
        .send_entry("cn=user2,dc=example,dc=com".to_string(), SyncState::Add)
        .await
        .unwrap();
    consumer2
        .send_entry("cn=user3,dc=example,dc=com".to_string(), SyncState::Modify)
        .await
        .unwrap();

    assert_eq!(consumer1.get_entries_count(), 1);
    assert_eq!(consumer2.get_entries_count(), 2);
}

/// Test: Error handling in mock consumer
#[tokio::test]
async fn test_mock_consumer_error_isolation() {
    let consumer = mock_consumer::MockConsumer::new("mock-7".to_string());

    // Even if we mark as dead, operations should still succeed
    // (in mock, they don't actually fail - this tests error isolation pattern)
    {
        let mut alive = consumer.is_alive.lock().unwrap();
        *alive = false;
    }

    // Should still work (in production, would trigger reconnection)
    let result = consumer
        .send_entry("cn=user1,dc=example,dc=com".to_string(), SyncState::Add)
        .await;
    assert!(result.is_ok());
}

/// Test: Large batch of entries
#[tokio::test]
async fn test_large_batch() {
    let consumer = mock_consumer::MockConsumer::new("mock-8".to_string());

    // Send 1000 entries
    for i in 0..1000 {
        let dn = format!("cn=user{},ou=people,dc=example,dc=com", i);
        consumer.send_entry(dn, SyncState::Add).await.unwrap();
    }

    assert_eq!(consumer.get_entries_count(), 1000);
}

/// Test: Concurrent reconnect attempts fail cleanly without deadlocking
#[tokio::test]
async fn test_persistent_consumer_concurrent_reconnect_attempts_are_bounded() {
    let consumer = Arc::new(PersistentConsumer::new_lazy(
        "test-consumer-reconnect".to_string(),
        "not-a-url".to_string(),
        "dc=example,dc=com".to_string(),
        Duration::from_secs(30),
    ));
    let entry = DirectoryEntry::new(
        "cn=Reconnect Test,dc=example,dc=com".to_string(),
        "550e8400-e29b-41d4-a716-446655440001".to_string(),
        vec![("cn".to_string(), vec!["Reconnect Test".to_string()])],
    );

    let mut tasks = Vec::new();
    for _ in 0..4 {
        let consumer = consumer.clone();
        let entry = entry.clone();
        tasks.push(tokio::spawn(async move {
            consumer
                .send_entry(&entry, SyncState::Add, Some("cookie-1".to_string()))
                .await
        }));
    }

    let joined = tokio::time::timeout(Duration::from_secs(2), async move {
        let mut results = Vec::new();
        for task in tasks {
            results.push(task.await.unwrap());
        }
        results
    })
    .await
    .expect("concurrent reconnect attempts should finish promptly");

    assert!(joined.iter().all(|result| result.is_err()));

    let stats = consumer.get_stats().await;
    assert!(stats.errors >= 1);
    assert!(stats.last_error.is_some());
}

/// Test: Entry with complex attributes
#[test]
fn test_complex_directory_entry() {
    let entry = DirectoryEntry::new(
        "cn=Jane Smith,ou=staff,ou=people,dc=example,dc=com".to_string(),
        "c1f0a7e8-3d4b-4c9e-8f1a-2b3c4d5e6f7a".to_string(),
        vec![
            ("cn".to_string(), vec!["Jane Smith".to_string()]),
            ("sn".to_string(), vec!["Smith".to_string()]),
            ("givenName".to_string(), vec!["Jane".to_string()]),
            (
                "mail".to_string(),
                vec![
                    "jane.smith@example.com".to_string(),
                    "jsmith@example.com".to_string(),
                ],
            ),
            (
                "telephoneNumber".to_string(),
                vec![
                    "+1-555-1234".to_string(),
                    "+1-555-5678".to_string(),
                    "+1-555-9012".to_string(),
                ],
            ),
            (
                "objectClass".to_string(),
                vec![
                    "top".to_string(),
                    "person".to_string(),
                    "organizationalPerson".to_string(),
                    "inetOrgPerson".to_string(),
                ],
            ),
        ],
    );

    assert_eq!(entry.attributes.len(), 6);

    // Verify multi-valued attributes
    let mail = entry
        .attributes
        .iter()
        .find(|(k, _)| k == "mail")
        .map(|(_, v)| v);
    assert_eq!(mail.as_ref().unwrap().len(), 2);

    let phone = entry
        .attributes
        .iter()
        .find(|(k, _)| k == "telephoneNumber")
        .map(|(_, v)| v);
    assert_eq!(phone.as_ref().unwrap().len(), 3);
}

/// Test: Cookie management in sync info
#[test]
fn test_sync_info_cookie_extraction() {
    let info1 = SyncInfo::NewCookie("cookie123".to_string());
    let info2 = SyncInfo::RefreshDelete {
        cookie: Some("cookie456".to_string()),
        refresh_done: true,
    };
    let info3 = SyncInfo::RefreshPresent {
        cookie: None,
        refresh_done: false,
    };

    // Helper to extract cookie
    let extract_cookie = |info: &SyncInfo| -> Option<String> {
        match info {
            SyncInfo::NewCookie(cookie) => Some(cookie.clone()),
            SyncInfo::RefreshDelete { cookie, .. }
            | SyncInfo::RefreshPresent { cookie, .. }
            | SyncInfo::SyncIdSet { cookie, .. } => cookie.clone(),
        }
    };

    assert_eq!(extract_cookie(&info1), Some("cookie123".to_string()));
    assert_eq!(extract_cookie(&info2), Some("cookie456".to_string()));
    assert_eq!(extract_cookie(&info3), None);
}

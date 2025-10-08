//! Integration Tests for Real-Time Change Propagation
//!
//! These tests verify end-to-end change propagation from backend operations
//! through the change observer, filtering, and push manager to consumers.

use opendr::backend::DirectoryEntry;
use opendr::change_observer::{ChangeCallback, ChangeObserver, ChangeObserverImpl};
use opendr::push_manager::{PushManager, PushManagerConfig};
use opendr::real_time_propagation::{is_dn_in_scope, PropagationConfig, RealTimePropagationEngine};
use opendr::replication_provider_fsm::{ChangeType, ChangelogEntry};

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};

/// Test callback that records changes
struct RecordingCallback {
    changes: Arc<Mutex<Vec<ChangelogEntry>>>,
}

impl RecordingCallback {
    fn new() -> (Self, Arc<Mutex<Vec<ChangelogEntry>>>) {
        let changes = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                changes: changes.clone(),
            },
            changes,
        )
    }
}

#[async_trait]
impl ChangeCallback for RecordingCallback {
    async fn on_change(&self, change: &ChangelogEntry) -> Result<(), String> {
        self.changes.lock().await.push(change.clone());
        Ok(())
    }
}

/// Test callback that counts changes
struct CountingCallback {
    count: Arc<AtomicUsize>,
}

impl CountingCallback {
    fn new() -> (Self, Arc<AtomicUsize>) {
        let count = Arc::new(AtomicUsize::new(0));
        (
            Self {
                count: count.clone(),
            },
            count,
        )
    }
}

#[async_trait]
impl ChangeCallback for CountingCallback {
    async fn on_change(&self, _change: &ChangelogEntry) -> Result<(), String> {
        self.count.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[allow(dead_code)]
fn create_test_entry(dn: &str, cn: &str) -> DirectoryEntry {
    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec![cn.to_string()]);
    attributes.insert(
        "objectclass".to_string(),
        vec!["person".to_string(), "inetOrgPerson".to_string()],
    );
    DirectoryEntry::new(dn, attributes)
}

#[tokio::test]
async fn test_propagation_engine_lifecycle() {
    let observer = Arc::new(ChangeObserverImpl::new());
    let push_config = PushManagerConfig::default();
    let push_manager = Arc::new(RwLock::new(PushManager::new(observer.clone(), push_config)));
    let config = PropagationConfig::default();

    let engine = RealTimePropagationEngine::new(observer.clone(), push_manager, config);

    // Engine should not be running initially
    assert!(!engine.is_running().await);

    // Start engine
    engine.start().await.unwrap();
    assert!(engine.is_running().await);

    // Verify observer has callback registered
    assert_eq!(observer.callback_count(), 2); // PushManager + PropagationEngine

    // Stop engine
    let mut engine = engine;
    engine.stop().await.unwrap();
    assert!(!engine.is_running().await);
}

#[tokio::test]
async fn test_propagation_with_dn_scope_filtering() {
    let observer = Arc::new(ChangeObserverImpl::new());
    let push_config = PushManagerConfig::default();
    let push_manager = Arc::new(RwLock::new(PushManager::new(observer.clone(), push_config)));

    let mut config = PropagationConfig::default();
    config.enable_filtering = true;

    let engine = RealTimePropagationEngine::new(observer.clone(), push_manager, config);
    engine.start().await.unwrap();

    // Register consumer filter for dc=example,dc=com
    engine
        .register_consumer_filter(
            "consumer-1".to_string(),
            "dc=example,dc=com".to_string(),
            None,
        )
        .await
        .unwrap();

    // Add a recording callback to track changes
    let (callback, changes) = RecordingCallback::new();
    observer.register_callback(Arc::new(callback));

    // Simulate changes
    let change1 = ChangelogEntry::new(
        opendr::csn::Csn::new(1),
        ChangeType::Add,
        "cn=user1,dc=example,dc=com".to_string(),
        vec![],
    );
    observer.notify_change(&change1).await.unwrap();

    // Give time for async processing
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify change was recorded
    let recorded = changes.lock().await;
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].dn, "cn=user1,dc=example,dc=com");

    // Check filter stats
    let filter = engine.get_consumer_filter("consumer-1").await.unwrap();
    assert_eq!(filter.stats.total_evaluated, 1);
    assert_eq!(filter.stats.matches, 1);
}

#[tokio::test]
async fn test_propagation_filters_out_of_scope() {
    let observer = Arc::new(ChangeObserverImpl::new());
    let push_config = PushManagerConfig::default();
    let push_manager = Arc::new(RwLock::new(PushManager::new(observer.clone(), push_config)));

    let mut config = PropagationConfig::default();
    config.enable_filtering = true;

    let engine = RealTimePropagationEngine::new(observer.clone(), push_manager, config);
    engine.start().await.unwrap();

    // Register consumer filter for dc=example,dc=com
    engine
        .register_consumer_filter(
            "consumer-1".to_string(),
            "dc=example,dc=com".to_string(),
            None,
        )
        .await
        .unwrap();

    // Simulate change outside scope
    let change_outside = ChangelogEntry::new(
        opendr::csn::Csn::new(1),
        ChangeType::Add,
        "cn=user1,dc=other,dc=com".to_string(), // Different base DN
        vec![],
    );
    observer.notify_change(&change_outside).await.unwrap();

    // Give time for async processing
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Check filter stats - should be filtered out
    let filter = engine.get_consumer_filter("consumer-1").await.unwrap();
    assert_eq!(filter.stats.total_evaluated, 1);
    assert_eq!(filter.stats.misses, 1);
    assert_eq!(filter.stats.matches, 0);
}

#[tokio::test]
async fn test_propagation_multiple_consumers() {
    let observer = Arc::new(ChangeObserverImpl::new());
    let push_config = PushManagerConfig::default();
    let push_manager = Arc::new(RwLock::new(PushManager::new(observer.clone(), push_config)));

    let mut config = PropagationConfig::default();
    config.enable_filtering = true;

    let engine = RealTimePropagationEngine::new(observer.clone(), push_manager, config);
    engine.start().await.unwrap();

    // Register three consumer filters with different scopes
    engine
        .register_consumer_filter(
            "consumer-1".to_string(),
            "dc=example,dc=com".to_string(),
            None,
        )
        .await
        .unwrap();

    engine
        .register_consumer_filter(
            "consumer-2".to_string(),
            "ou=people,dc=example,dc=com".to_string(),
            None,
        )
        .await
        .unwrap();

    engine
        .register_consumer_filter(
            "consumer-3".to_string(),
            "dc=other,dc=com".to_string(),
            None,
        )
        .await
        .unwrap();

    // Simulate changes
    let change1 = ChangelogEntry::new(
        opendr::csn::Csn::new(1),
        ChangeType::Add,
        "cn=user1,dc=example,dc=com".to_string(),
        vec![],
    );
    observer.notify_change(&change1).await.unwrap();

    let change2 = ChangelogEntry::new(
        opendr::csn::Csn::new(2),
        ChangeType::Add,
        "cn=user2,ou=people,dc=example,dc=com".to_string(),
        vec![],
    );
    observer.notify_change(&change2).await.unwrap();

    // Give time for async processing
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Check filter stats
    let filter1 = engine.get_consumer_filter("consumer-1").await.unwrap();
    let filter2 = engine.get_consumer_filter("consumer-2").await.unwrap();
    let filter3 = engine.get_consumer_filter("consumer-3").await.unwrap();

    // Consumer 1: should match both changes (broader scope)
    assert_eq!(filter1.stats.total_evaluated, 2);
    assert_eq!(filter1.stats.matches, 2);

    // Consumer 2: should match only change2 (narrower scope)
    assert_eq!(filter2.stats.total_evaluated, 2);
    assert_eq!(filter2.stats.matches, 1); // Only the ou=people entry

    // Consumer 3: should match neither (different tree)
    assert_eq!(filter3.stats.total_evaluated, 2);
    assert_eq!(filter3.stats.matches, 0);
}

#[tokio::test]
async fn test_propagation_without_filtering() {
    let observer = Arc::new(ChangeObserverImpl::new());
    let push_config = PushManagerConfig::default();
    let push_manager = Arc::new(RwLock::new(PushManager::new(observer.clone(), push_config)));

    let mut config = PropagationConfig::default();
    config.enable_filtering = false; // Disable filtering

    let engine = RealTimePropagationEngine::new(observer.clone(), push_manager, config);
    engine.start().await.unwrap();

    // Register consumer filter (but filtering is disabled)
    engine
        .register_consumer_filter(
            "consumer-1".to_string(),
            "dc=example,dc=com".to_string(),
            None,
        )
        .await
        .unwrap();

    // Add counting callback
    let (callback, count) = CountingCallback::new();
    observer.register_callback(Arc::new(callback));

    // Simulate change
    let change = ChangelogEntry::new(
        opendr::csn::Csn::new(1),
        ChangeType::Add,
        "cn=user1,dc=example,dc=com".to_string(),
        vec![],
    );
    observer.notify_change(&change).await.unwrap();

    // Give time for async processing
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Callback should still be invoked (filtering disabled)
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_propagation_statistics() {
    let observer = Arc::new(ChangeObserverImpl::new());
    let push_config = PushManagerConfig::default();
    let push_manager = Arc::new(RwLock::new(PushManager::new(observer.clone(), push_config)));

    let mut config = PropagationConfig::default();
    config.enable_filtering = true;

    let engine = RealTimePropagationEngine::new(observer.clone(), push_manager, config);
    engine.start().await.unwrap();

    // Register consumer filter
    engine
        .register_consumer_filter(
            "consumer-1".to_string(),
            "dc=example,dc=com".to_string(),
            None,
        )
        .await
        .unwrap();

    // Simulate multiple changes
    for i in 1..=5 {
        let change = ChangelogEntry::new(
            opendr::csn::Csn::new(i),
            ChangeType::Add,
            format!("cn=user{},dc=example,dc=com", i),
            vec![],
        );
        observer.notify_change(&change).await.unwrap();
    }

    // Give time for async processing
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Check engine statistics
    let stats = engine.get_stats().await;
    assert_eq!(stats.total_changes, 5);
    assert_eq!(stats.changes_propagated, 5);
    assert_eq!(stats.changes_filtered, 0);
    assert!(stats.avg_latency_ms >= 0.0);
}

#[tokio::test]
async fn test_unregister_consumer_filter() {
    let observer = Arc::new(ChangeObserverImpl::new());
    let push_config = PushManagerConfig::default();
    let push_manager = Arc::new(RwLock::new(PushManager::new(observer.clone(), push_config)));
    let config = PropagationConfig::default();

    let engine = RealTimePropagationEngine::new(observer.clone(), push_manager, config);
    engine.start().await.unwrap();

    // Register filter
    engine
        .register_consumer_filter(
            "consumer-1".to_string(),
            "dc=example,dc=com".to_string(),
            None,
        )
        .await
        .unwrap();

    // Verify registered
    assert!(engine.get_consumer_filter("consumer-1").await.is_some());

    // Unregister
    let removed = engine
        .unregister_consumer_filter("consumer-1")
        .await
        .unwrap();
    assert!(removed);

    // Verify removed
    assert!(engine.get_consumer_filter("consumer-1").await.is_none());
}

#[tokio::test]
async fn test_get_all_filter_stats() {
    let observer = Arc::new(ChangeObserverImpl::new());
    let push_config = PushManagerConfig::default();
    let push_manager = Arc::new(RwLock::new(PushManager::new(observer.clone(), push_config)));
    let config = PropagationConfig::default();

    let engine = RealTimePropagationEngine::new(observer.clone(), push_manager, config);
    engine.start().await.unwrap();

    // Register multiple filters
    for i in 1..=3 {
        engine
            .register_consumer_filter(
                format!("consumer-{}", i),
                "dc=example,dc=com".to_string(),
                None,
            )
            .await
            .unwrap();
    }

    // Get all stats
    let all_stats = engine.get_all_filter_stats().await;
    assert_eq!(all_stats.len(), 3);

    for i in 1..=3 {
        let consumer_id = format!("consumer-{}", i);
        assert!(all_stats.contains_key(&consumer_id));
    }
}

#[tokio::test]
async fn test_dn_scope_matching_edge_cases() {
    // Exact match
    assert!(is_dn_in_scope("dc=example,dc=com", "dc=example,dc=com"));

    // Child entry
    assert!(is_dn_in_scope(
        "cn=user,dc=example,dc=com",
        "dc=example,dc=com"
    ));

    // Grandchild entry
    assert!(is_dn_in_scope(
        "cn=user,ou=people,dc=example,dc=com",
        "dc=example,dc=com"
    ));

    // Not in scope (different tree)
    assert!(!is_dn_in_scope(
        "cn=user,dc=other,dc=com",
        "dc=example,dc=com"
    ));

    // Not in scope (parent)
    assert!(!is_dn_in_scope(
        "dc=example,dc=com",
        "cn=user,dc=example,dc=com"
    ));

    // Case insensitive
    assert!(is_dn_in_scope(
        "CN=User,DC=EXAMPLE,DC=COM",
        "dc=example,dc=com"
    ));

    // Partial component match should fail
    assert!(!is_dn_in_scope(
        "cn=userdc=example,dc=com",
        "dc=example,dc=com"
    ));
}

#[tokio::test]
async fn test_concurrent_filter_operations() {
    let observer = Arc::new(ChangeObserverImpl::new());
    let push_config = PushManagerConfig::default();
    let push_manager = Arc::new(RwLock::new(PushManager::new(observer.clone(), push_config)));
    let config = PropagationConfig::default();

    let engine = Arc::new(RealTimePropagationEngine::new(
        observer.clone(),
        push_manager,
        config,
    ));
    engine.start().await.unwrap();

    // Spawn multiple tasks to register filters concurrently
    let mut handles = vec![];
    for i in 0..10 {
        let engine = engine.clone();
        let handle = tokio::spawn(async move {
            engine
                .register_consumer_filter(
                    format!("consumer-{}", i),
                    "dc=example,dc=com".to_string(),
                    None,
                )
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
    let all_stats = engine.get_all_filter_stats().await;
    assert_eq!(all_stats.len(), 10);
}

#[tokio::test]
async fn test_filter_with_ldap_filter_string() {
    let observer = Arc::new(ChangeObserverImpl::new());
    let push_config = PushManagerConfig::default();
    let push_manager = Arc::new(RwLock::new(PushManager::new(observer.clone(), push_config)));
    let config = PropagationConfig::default();

    let engine = RealTimePropagationEngine::new(observer.clone(), push_manager, config);
    engine.start().await.unwrap();

    // Register filter with LDAP filter string
    engine
        .register_consumer_filter(
            "consumer-1".to_string(),
            "dc=example,dc=com".to_string(),
            Some("(objectClass=person)".to_string()),
        )
        .await
        .unwrap();

    // Verify filter registered with LDAP filter
    let filter = engine.get_consumer_filter("consumer-1").await.unwrap();
    assert_eq!(filter.filter, Some("(objectClass=person)".to_string()));
}

#[tokio::test]
async fn test_propagation_latency_tracking() {
    let observer = Arc::new(ChangeObserverImpl::new());
    let push_config = PushManagerConfig::default();
    let push_manager = Arc::new(RwLock::new(PushManager::new(observer.clone(), push_config)));

    let mut config = PropagationConfig::default();
    config.target_latency = Duration::from_secs(1);

    let engine = RealTimePropagationEngine::new(observer.clone(), push_manager, config);
    engine.start().await.unwrap();

    // Register consumer filter
    engine
        .register_consumer_filter(
            "consumer-1".to_string(),
            "dc=example,dc=com".to_string(),
            None,
        )
        .await
        .unwrap();

    // Simulate change
    let change = ChangelogEntry::new(
        opendr::csn::Csn::new(1),
        ChangeType::Add,
        "cn=user1,dc=example,dc=com".to_string(),
        vec![],
    );
    observer.notify_change(&change).await.unwrap();

    // Give time for async processing
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Check that latency was tracked
    let stats = engine.get_stats().await;
    assert!(stats.avg_latency_ms >= 0.0);
    assert!(stats.started_at.is_some());
}

#[tokio::test]
async fn test_filter_match_rate_calculation() {
    let observer = Arc::new(ChangeObserverImpl::new());
    let push_config = PushManagerConfig::default();
    let push_manager = Arc::new(RwLock::new(PushManager::new(observer.clone(), push_config)));

    let mut config = PropagationConfig::default();
    config.enable_filtering = true;

    let engine = RealTimePropagationEngine::new(observer.clone(), push_manager, config);
    engine.start().await.unwrap();

    // Register consumer filter
    engine
        .register_consumer_filter(
            "consumer-1".to_string(),
            "dc=example,dc=com".to_string(),
            None,
        )
        .await
        .unwrap();

    // Simulate 3 in-scope changes and 2 out-of-scope changes
    for i in 1..=3 {
        let change = ChangelogEntry::new(
            opendr::csn::Csn::new(i),
            ChangeType::Add,
            format!("cn=user{},dc=example,dc=com", i),
            vec![],
        );
        observer.notify_change(&change).await.unwrap();
    }

    for i in 4..=5 {
        let change = ChangelogEntry::new(
            opendr::csn::Csn::new(i),
            ChangeType::Add,
            format!("cn=user{},dc=other,dc=com", i),
            vec![],
        );
        observer.notify_change(&change).await.unwrap();
    }

    // Give time for async processing
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Check filter stats
    let filter = engine.get_consumer_filter("consumer-1").await.unwrap();
    assert_eq!(filter.stats.total_evaluated, 5);
    assert_eq!(filter.stats.matches, 3);
    assert_eq!(filter.stats.misses, 2);
    assert_eq!(filter.stats.match_rate(), 0.6); // 3/5 = 60%
}

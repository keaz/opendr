//! Integration test for Change Observer with Backend Changelog Wrapper
//!
//! This test demonstrates Phase 1, Task 1.1 implementation:
//! - Change Observer notifies callbacks when directory changes occur
//! - Backend Changelog Wrapper integrates with observer
//! - Notifications happen asynchronously without blocking operations

use async_trait::async_trait;
use opendr::backend::{
    DirectoryBackend, DirectoryEntry, MockBackend, Modification, ModifyOperation,
};
use opendr::backend_changelog_wrapper::ChangelogBackendWrapper;
use opendr::change_observer::{ChangeCallback, ChangeObserver, ChangeObserverImpl};
use opendr::replication::ChangelogTracker;
use opendr::replication_provider_fsm::{ChangeType, ChangelogEntry};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Mutex;

/// Test callback that counts notifications and records change details
struct TestNotificationCallback {
    add_count: Arc<AtomicUsize>,
    modify_count: Arc<AtomicUsize>,
    delete_count: Arc<AtomicUsize>,
    rename_count: Arc<AtomicUsize>,
    changes: Arc<Mutex<Vec<String>>>,
}

impl TestNotificationCallback {
    fn new() -> Self {
        Self {
            add_count: Arc::new(AtomicUsize::new(0)),
            modify_count: Arc::new(AtomicUsize::new(0)),
            delete_count: Arc::new(AtomicUsize::new(0)),
            rename_count: Arc::new(AtomicUsize::new(0)),
            changes: Arc::new(Mutex::new(Vec::new())),
        }
    }

    async fn get_add_count(&self) -> usize {
        self.add_count.load(Ordering::SeqCst)
    }

    async fn get_modify_count(&self) -> usize {
        self.modify_count.load(Ordering::SeqCst)
    }

    async fn get_delete_count(&self) -> usize {
        self.delete_count.load(Ordering::SeqCst)
    }

    async fn get_rename_count(&self) -> usize {
        self.rename_count.load(Ordering::SeqCst)
    }

    async fn get_changes(&self) -> Vec<String> {
        self.changes.lock().await.clone()
    }
}

#[async_trait]
impl ChangeCallback for TestNotificationCallback {
    async fn on_change(&self, change: &ChangelogEntry) -> Result<(), String> {
        // Record change details
        let mut changes = self.changes.lock().await;
        changes.push(format!("{:?}: {}", change.change_type, change.dn));

        // Increment appropriate counter
        match change.change_type {
            ChangeType::Add => {
                self.add_count.fetch_add(1, Ordering::SeqCst);
            }
            ChangeType::Modify => {
                self.modify_count.fetch_add(1, Ordering::SeqCst);
            }
            ChangeType::Delete => {
                self.delete_count.fetch_add(1, Ordering::SeqCst);
            }
            ChangeType::Rename => {
                self.rename_count.fetch_add(1, Ordering::SeqCst);
            }
        }

        Ok(())
    }
}

fn create_test_entry(dn: &str, cn: &str) -> DirectoryEntry {
    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec![cn.to_string()]);
    attributes.insert("objectclass".to_string(), vec!["person".to_string()]);
    DirectoryEntry::new(dn, attributes)
}

#[tokio::test]
async fn test_observer_notified_on_add() {
    // Setup backend with changelog and observer
    let backend = Arc::new(MockBackend::new());
    let changelog = Arc::new(ChangelogTracker::new());
    let observer = Arc::new(ChangeObserverImpl::new());
    let callback = Arc::new(TestNotificationCallback::new());

    observer.register_callback(callback.clone());

    let mut wrapper = ChangelogBackendWrapper::new(backend, Some(changelog));
    wrapper.set_observer(observer);

    // Perform add operation
    let entry = create_test_entry("cn=user1,dc=test,dc=org", "user1");
    wrapper.add_entry(entry, vec![]).await.unwrap();

    // Give async notification time to complete
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Verify observer was notified
    assert_eq!(callback.get_add_count().await, 1);
    assert_eq!(callback.get_modify_count().await, 0);
    assert_eq!(callback.get_delete_count().await, 0);

    let changes = callback.get_changes().await;
    assert_eq!(changes.len(), 1);
    assert!(changes[0].contains("Add"));
    assert!(changes[0].contains("cn=user1,dc=test,dc=org"));
}

#[tokio::test]
async fn test_observer_notified_on_modify() {
    // Setup
    let backend = MockBackend::new();
    let entry = create_test_entry("cn=user1,dc=test,dc=org", "user1");
    backend.add_entry(entry, vec![]).await.unwrap();

    let backend = Arc::new(backend);
    let changelog = Arc::new(ChangelogTracker::new());
    let observer = Arc::new(ChangeObserverImpl::new());
    let callback = Arc::new(TestNotificationCallback::new());

    observer.register_callback(callback.clone());

    let mut wrapper = ChangelogBackendWrapper::new(backend, Some(changelog));
    wrapper.set_observer(observer);

    // Perform modify operation
    let modifications = vec![Modification {
        operation: ModifyOperation::Replace,
        attribute: "cn".to_string(),
        values: vec!["Modified User".to_string()],
    }];
    wrapper
        .modify_entry("cn=user1,dc=test,dc=org", modifications)
        .await
        .unwrap();

    // Give async notification time to complete
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Verify observer was notified
    assert_eq!(callback.get_add_count().await, 0);
    assert_eq!(callback.get_modify_count().await, 1);
    assert_eq!(callback.get_delete_count().await, 0);
}

#[tokio::test]
async fn test_observer_notified_on_delete() {
    // Setup
    let backend = MockBackend::new();
    let entry = create_test_entry("cn=user1,dc=test,dc=org", "user1");
    backend.add_entry(entry, vec![]).await.unwrap();

    let backend = Arc::new(backend);
    let changelog = Arc::new(ChangelogTracker::new());
    let observer = Arc::new(ChangeObserverImpl::new());
    let callback = Arc::new(TestNotificationCallback::new());

    observer.register_callback(callback.clone());

    let mut wrapper = ChangelogBackendWrapper::new(backend, Some(changelog));
    wrapper.set_observer(observer);

    // Perform delete operation
    wrapper
        .delete_entry("cn=user1,dc=test,dc=org")
        .await
        .unwrap();

    // Give async notification time to complete
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Verify observer was notified
    assert_eq!(callback.get_add_count().await, 0);
    assert_eq!(callback.get_modify_count().await, 0);
    assert_eq!(callback.get_delete_count().await, 1);
}

#[tokio::test]
async fn test_observer_notified_on_rename() {
    // Setup
    let backend = MockBackend::new();
    let entry = create_test_entry("cn=user1,dc=test,dc=org", "user1");
    backend.add_entry(entry, vec![]).await.unwrap();

    let backend = Arc::new(backend);
    let changelog = Arc::new(ChangelogTracker::new());
    let observer = Arc::new(ChangeObserverImpl::new());
    let callback = Arc::new(TestNotificationCallback::new());

    observer.register_callback(callback.clone());

    let mut wrapper = ChangelogBackendWrapper::new(backend, Some(changelog));
    wrapper.set_observer(observer);

    // Perform rename operation
    wrapper
        .rename_entry("cn=user1,dc=test,dc=org", "cn=renameduser", true, None)
        .await
        .unwrap();

    // Give async notification time to complete
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Verify observer was notified
    assert_eq!(callback.get_add_count().await, 0);
    assert_eq!(callback.get_modify_count().await, 0);
    assert_eq!(callback.get_delete_count().await, 0);
    assert_eq!(callback.get_rename_count().await, 1);
}

#[tokio::test]
async fn test_multiple_callbacks_all_notified() {
    // Setup with multiple callbacks
    let backend = Arc::new(MockBackend::new());
    let changelog = Arc::new(ChangelogTracker::new());
    let observer = Arc::new(ChangeObserverImpl::new());

    let callback1 = Arc::new(TestNotificationCallback::new());
    let callback2 = Arc::new(TestNotificationCallback::new());
    let callback3 = Arc::new(TestNotificationCallback::new());

    observer.register_callback(callback1.clone());
    observer.register_callback(callback2.clone());
    observer.register_callback(callback3.clone());

    let mut wrapper = ChangelogBackendWrapper::new(backend, Some(changelog));
    wrapper.set_observer(observer);

    // Perform add operation
    let entry = create_test_entry("cn=user1,dc=test,dc=org", "user1");
    wrapper.add_entry(entry, vec![]).await.unwrap();

    // Give async notification time to complete
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Verify all callbacks were notified
    assert_eq!(callback1.get_add_count().await, 1);
    assert_eq!(callback2.get_add_count().await, 1);
    assert_eq!(callback3.get_add_count().await, 1);
}

#[tokio::test]
async fn test_observer_handles_rapid_changes() {
    // Setup
    let backend = Arc::new(MockBackend::new());
    let changelog = Arc::new(ChangelogTracker::new());
    let observer = Arc::new(ChangeObserverImpl::new());
    let callback = Arc::new(TestNotificationCallback::new());

    observer.register_callback(callback.clone());

    let mut wrapper = ChangelogBackendWrapper::new(backend, Some(changelog));
    wrapper.set_observer(observer);
    let wrapper = Arc::new(wrapper);

    // Perform multiple rapid operations
    let mut handles = vec![];
    for i in 0..10 {
        let wrapper = wrapper.clone();
        let handle = tokio::spawn(async move {
            let entry = create_test_entry(
                &format!("cn=user{},dc=test,dc=org", i),
                &format!("user{}", i),
            );
            wrapper.add_entry(entry, vec![]).await.unwrap();
        });
        handles.push(handle);
    }

    // Wait for all operations to complete
    for handle in handles {
        handle.await.unwrap();
    }

    // Give async notifications time to complete
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    // Verify all changes were notified
    assert_eq!(callback.get_add_count().await, 10);

    let changes = callback.get_changes().await;
    assert_eq!(changes.len(), 10);
}

#[tokio::test]
async fn test_backend_without_observer_still_works() {
    // Setup backend without observer (should work fine)
    let backend = Arc::new(MockBackend::new());
    let changelog = Arc::new(ChangelogTracker::new());
    let wrapper = ChangelogBackendWrapper::new(backend, Some(changelog.clone()));

    // Perform operations without observer
    let entry = create_test_entry("cn=user1,dc=test,dc=org", "user1");
    wrapper.add_entry(entry, vec![]).await.unwrap();

    // Verify changelog still works
    let entries = changelog.get_all();
    assert_eq!(entries.len(), 1);
}

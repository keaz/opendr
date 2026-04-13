//! Change Observer Implementation
//!
//! This module provides the observer pattern for monitoring directory changes
//! and notifying registered callbacks. This is a core component for push-based
//! replication where the provider needs to be immediately notified of changes.
//!
//! ## Architecture
//!
//! ```text
//! Backend Change → ChangeObserver → Callbacks → PushManager
//! ```
//!
//! ## Usage
//!
//! ```rust,no_run
//! use async_trait::async_trait;
//! use opendr::change_observer::{ChangeCallback, ChangeObserver, ChangeObserverImpl};
//! use opendr::replication_provider_fsm::ChangelogEntry;
//! use std::sync::Arc;
//!
//! // Create observer
//! let observer = ChangeObserverImpl::new();
//!
//! // Register callback
//! struct MyCallback;
//! #[async_trait]
//! impl ChangeCallback for MyCallback {
//!     async fn on_change(&self, change: &ChangelogEntry) -> Result<(), String> {
//!         println!("Change detected: {}", change.dn);
//!         Ok(())
//!     }
//! }
//!
//! observer.register_callback(Arc::new(MyCallback));
//!
//! // Notify on changes
//! // observer.notify_change(entry).await;
//! ```

use async_trait::async_trait;
use log::{debug, error, info, warn};
use std::sync::{Arc, RwLock};

use crate::replication_provider_fsm::ChangelogEntry;

/// Trait for receiving change notifications
///
/// Implement this trait to receive notifications when directory entries change.
/// Callbacks are invoked asynchronously and should complete quickly to avoid
/// blocking other callbacks.
#[async_trait]
pub trait ChangeCallback: Send + Sync {
    /// Called when a directory change occurs
    ///
    /// # Arguments
    /// * `change` - The changelog entry describing the change
    ///
    /// # Returns
    /// * `Ok(())` if the callback processed successfully
    /// * `Err(msg)` if the callback encountered an error (logged but doesn't block others)
    async fn on_change(&self, change: &ChangelogEntry) -> Result<(), String>;
}

/// Trait for observing directory changes
///
/// This trait defines the interface for change observation. Implementations
/// should ensure thread-safety and minimal performance impact.
#[async_trait]
pub trait ChangeObserver: Send + Sync {
    /// Register a callback to be notified of changes
    ///
    /// # Arguments
    /// * `callback` - The callback to register
    ///
    /// Callbacks are invoked in the order they were registered.
    fn register_callback(&self, callback: Arc<dyn ChangeCallback>);

    /// Unregister all callbacks
    ///
    /// Useful for cleanup or testing purposes.
    fn clear_callbacks(&self);

    /// Get the number of registered callbacks
    fn callback_count(&self) -> usize;

    /// Notify all registered callbacks of a change
    ///
    /// # Arguments
    /// * `change` - The changelog entry to notify about
    ///
    /// # Returns
    /// * `Ok(())` if all callbacks were notified (even if some failed)
    /// * Individual callback errors are logged but don't prevent other callbacks
    ///
    /// # Performance
    /// This method should complete quickly (< 1ms overhead). Long-running
    /// operations should be spawned as separate tasks.
    async fn notify_change(&self, change: &ChangelogEntry) -> Result<(), String>;
}

/// Default implementation of ChangeObserver
///
/// This implementation stores callbacks in a thread-safe vector and notifies
/// them sequentially when changes occur. All callbacks are invoked even if
/// some fail.
///
/// # Thread Safety
/// This implementation is fully thread-safe and can be shared across threads.
///
/// # Performance
/// - `register_callback`: O(1) with write lock
/// - `notify_change`: O(n) where n is number of callbacks
/// - Minimal memory overhead (< 100 bytes per callback)
pub struct ChangeObserverImpl {
    /// Registered callbacks (protected by RwLock for thread safety)
    callbacks: Arc<RwLock<Vec<Arc<dyn ChangeCallback>>>>,
}

impl ChangeObserverImpl {
    /// Create a new change observer
    ///
    /// # Example
    /// ```
    /// use opendr::change_observer::{ChangeObserver, ChangeObserverImpl};
    ///
    /// let observer = ChangeObserverImpl::new();
    /// assert_eq!(observer.callback_count(), 0);
    /// ```
    pub fn new() -> Self {
        Self {
            callbacks: Arc::new(RwLock::new(Vec::new())),
        }
    }
}

impl Default for ChangeObserverImpl {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ChangeObserver for ChangeObserverImpl {
    fn register_callback(&self, callback: Arc<dyn ChangeCallback>) {
        let mut callbacks = self.callbacks.write().unwrap();
        callbacks.push(callback);
        info!("Registered change callback (total: {})", callbacks.len());
    }

    fn clear_callbacks(&self) {
        let mut callbacks = self.callbacks.write().unwrap();
        let count = callbacks.len();
        callbacks.clear();
        info!("Cleared {} change callbacks", count);
    }

    fn callback_count(&self) -> usize {
        self.callbacks.read().unwrap().len()
    }

    async fn notify_change(&self, change: &ChangelogEntry) -> Result<(), String> {
        let callbacks = {
            // Clone the Arc references while holding the read lock
            // This allows callbacks to be invoked without holding the lock
            let guard = self.callbacks.read().unwrap();
            guard.clone()
        };

        let callback_count = callbacks.len();
        if callback_count == 0 {
            debug!(
                "No callbacks registered for change notification: {}",
                change.dn
            );
            return Ok(());
        }

        debug!(
            "Notifying {} callbacks of change: {} (type: {:?}, CSN: {})",
            callback_count, change.dn, change.change_type, change.csn
        );

        let mut success_count = 0;
        let mut error_count = 0;

        // Invoke all callbacks
        for (index, callback) in callbacks.iter().enumerate() {
            match callback.on_change(change).await {
                Ok(()) => {
                    success_count += 1;
                    debug!("Callback {} completed successfully", index);
                }
                Err(e) => {
                    error_count += 1;
                    error!("Callback {} failed: {}", index, e);
                    // Continue with other callbacks even if one fails
                }
            }
        }

        if error_count > 0 {
            warn!(
                "Change notification completed with errors: {}/{} callbacks succeeded",
                success_count, callback_count
            );
        } else {
            debug!(
                "Change notification completed: all {} callbacks succeeded",
                callback_count
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csn::Csn;
    use crate::replication_provider_fsm::ChangeType;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Test callback that counts invocations
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

    /// Test callback that fails
    struct FailingCallback;

    #[async_trait]
    impl ChangeCallback for FailingCallback {
        async fn on_change(&self, _change: &ChangelogEntry) -> Result<(), String> {
            Err("Intentional failure".to_string())
        }
    }

    /// Test callback that records the DN
    struct RecordingCallback {
        dns: Arc<Mutex<Vec<String>>>,
    }

    impl RecordingCallback {
        fn new() -> (Self, Arc<Mutex<Vec<String>>>) {
            let dns = Arc::new(Mutex::new(Vec::new()));
            (Self { dns: dns.clone() }, dns)
        }
    }

    #[async_trait]
    impl ChangeCallback for RecordingCallback {
        async fn on_change(&self, change: &ChangelogEntry) -> Result<(), String> {
            self.dns.lock().unwrap().push(change.dn.clone());
            Ok(())
        }
    }

    fn create_test_entry(dn: &str, change_type: ChangeType) -> ChangelogEntry {
        ChangelogEntry::new(Csn::new(1), change_type, dn.to_string(), vec![])
    }

    #[tokio::test]
    async fn test_new_observer_has_no_callbacks() {
        let observer = ChangeObserverImpl::new();
        assert_eq!(observer.callback_count(), 0);
    }

    #[tokio::test]
    async fn test_register_callback() {
        let observer = ChangeObserverImpl::new();
        let (callback, _) = CountingCallback::new();

        observer.register_callback(Arc::new(callback));
        assert_eq!(observer.callback_count(), 1);
    }

    #[tokio::test]
    async fn test_register_multiple_callbacks() {
        let observer = ChangeObserverImpl::new();
        let (callback1, _) = CountingCallback::new();
        let (callback2, _) = CountingCallback::new();
        let (callback3, _) = CountingCallback::new();

        observer.register_callback(Arc::new(callback1));
        observer.register_callback(Arc::new(callback2));
        observer.register_callback(Arc::new(callback3));

        assert_eq!(observer.callback_count(), 3);
    }

    #[tokio::test]
    async fn test_clear_callbacks() {
        let observer = ChangeObserverImpl::new();
        let (callback1, _) = CountingCallback::new();
        let (callback2, _) = CountingCallback::new();

        observer.register_callback(Arc::new(callback1));
        observer.register_callback(Arc::new(callback2));
        assert_eq!(observer.callback_count(), 2);

        observer.clear_callbacks();
        assert_eq!(observer.callback_count(), 0);
    }

    #[tokio::test]
    async fn test_notify_change_with_no_callbacks() {
        let observer = ChangeObserverImpl::new();
        let entry = create_test_entry("cn=test,dc=example,dc=com", ChangeType::Add);

        let result = observer.notify_change(&entry).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_notify_change_invokes_callback() {
        let observer = ChangeObserverImpl::new();
        let (callback, counter) = CountingCallback::new();
        observer.register_callback(Arc::new(callback));

        let entry = create_test_entry("cn=test,dc=example,dc=com", ChangeType::Add);
        observer.notify_change(&entry).await.unwrap();

        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_notify_change_invokes_all_callbacks() {
        let observer = ChangeObserverImpl::new();
        let (callback1, counter1) = CountingCallback::new();
        let (callback2, counter2) = CountingCallback::new();
        let (callback3, counter3) = CountingCallback::new();

        observer.register_callback(Arc::new(callback1));
        observer.register_callback(Arc::new(callback2));
        observer.register_callback(Arc::new(callback3));

        let entry = create_test_entry("cn=test,dc=example,dc=com", ChangeType::Add);
        observer.notify_change(&entry).await.unwrap();

        assert_eq!(counter1.load(Ordering::SeqCst), 1);
        assert_eq!(counter2.load(Ordering::SeqCst), 1);
        assert_eq!(counter3.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_notify_multiple_changes() {
        let observer = ChangeObserverImpl::new();
        let (callback, counter) = CountingCallback::new();
        observer.register_callback(Arc::new(callback));

        let entry1 = create_test_entry("cn=test1,dc=example,dc=com", ChangeType::Add);
        let entry2 = create_test_entry("cn=test2,dc=example,dc=com", ChangeType::Modify);
        let entry3 = create_test_entry("cn=test3,dc=example,dc=com", ChangeType::Delete);

        observer.notify_change(&entry1).await.unwrap();
        observer.notify_change(&entry2).await.unwrap();
        observer.notify_change(&entry3).await.unwrap();

        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_callback_receives_correct_entry() {
        let observer = ChangeObserverImpl::new();
        let (callback, dns) = RecordingCallback::new();
        observer.register_callback(Arc::new(callback));

        let entry = create_test_entry("cn=test,dc=example,dc=com", ChangeType::Add);
        observer.notify_change(&entry).await.unwrap();

        let recorded_dns = dns.lock().unwrap();
        assert_eq!(recorded_dns.len(), 1);
        assert_eq!(recorded_dns[0], "cn=test,dc=example,dc=com");
    }

    #[tokio::test]
    async fn test_failing_callback_doesnt_block_others() {
        let observer = ChangeObserverImpl::new();
        let (callback1, counter1) = CountingCallback::new();
        let (callback3, counter3) = CountingCallback::new();

        observer.register_callback(Arc::new(callback1));
        observer.register_callback(Arc::new(FailingCallback));
        observer.register_callback(Arc::new(callback3));

        let entry = create_test_entry("cn=test,dc=example,dc=com", ChangeType::Add);
        let result = observer.notify_change(&entry).await;

        // Should succeed even though one callback failed
        assert!(result.is_ok());

        // Other callbacks should still have been invoked
        assert_eq!(counter1.load(Ordering::SeqCst), 1);
        assert_eq!(counter3.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_thread_safety() {
        use tokio::task;

        let observer = Arc::new(ChangeObserverImpl::new());
        let (callback, counter) = CountingCallback::new();
        observer.register_callback(Arc::new(callback));

        // Spawn multiple tasks that notify changes concurrently
        let mut handles = vec![];
        for i in 0..10 {
            let observer_clone = observer.clone();
            let handle = task::spawn(async move {
                let entry =
                    create_test_entry(&format!("cn=test{},dc=example,dc=com", i), ChangeType::Add);
                observer_clone.notify_change(&entry).await
            });
            handles.push(handle);
        }

        // Wait for all tasks to complete
        for handle in handles {
            handle.await.unwrap().unwrap();
        }

        // All notifications should have been received
        assert_eq!(counter.load(Ordering::SeqCst), 10);
    }

    #[tokio::test]
    async fn test_default_implementation() {
        let observer = ChangeObserverImpl::default();
        assert_eq!(observer.callback_count(), 0);
    }

    #[test]
    fn test_observer_is_send_and_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<ChangeObserverImpl>();
        assert_sync::<ChangeObserverImpl>();
    }
}

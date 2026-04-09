//! Push Manager for Real-Time Replication
//!
//! This module implements the Push Manager, which coordinates real-time change
//! propagation to persistent consumers in refreshAndPersist mode (RFC 4533).
//!
//! The active runtime path for replication streaming is the provider-owned LDAP
//! search session handled in [`crate::server::handle_search_request`]. This
//! module remains available for compatibility and test harnesses that model
//! push delivery outside the shipped server runtime.
//!
//! # Architecture
//!
//! ```text
//! ChangeObserver → PushManager → PersistentConsumer → LDAP Consumer
//!      ↓               ↓              ↓                     ↓
//!   Detect         Route to       Send via           Apply
//!   Changes        Consumers      Connection         Changes
//! ```
//!
//! # Key Responsibilities
//!
//! - Register/unregister persistent consumers
//! - Route changes to appropriate consumers based on filter
//! - Handle consumer disconnections and reconnections
//! - Implement retry logic for failed deliveries
//! - Track delivery statistics and health
//!
//! # Example Usage
//!
//! ```no_run
//! use opendr::push_manager::{PushManager, PushManagerConfig};
//! use opendr::change_observer::ChangeObserverImpl;
//! use std::sync::Arc;
//! use std::time::Duration;
//!
//! # async fn example() -> Result<(), String> {
//! let observer = Arc::new(ChangeObserverImpl::new());
//! let config = PushManagerConfig::default();
//! let mut manager = PushManager::new(observer, config);
//!
//! // Start listening for changes
//! manager.start().await?;
//!
//! // Register a persistent consumer
//! // let consumer = PersistentConsumer::new(...).await?;
//! // manager.register_consumer("consumer-1", consumer).await?;
//!
//! // Changes will be automatically pushed to registered consumers
//! # Ok(())
//! # }
//! ```

use async_trait::async_trait;
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::sleep;

use crate::change_observer::{ChangeCallback, ChangeObserver};
use crate::ldap_filter_eval::{compile_filter, prepare_change, CompiledLdapFilter, PreparedChange};
use crate::persistent_connection::{DirectoryEntry, PersistentConsumer, SyncState};
use crate::replication_provider_fsm::{ChangeType, ChangelogEntry};

/// Configuration for the Push Manager
#[derive(Debug, Clone)]
pub struct PushManagerConfig {
    /// Maximum number of retry attempts for failed deliveries
    pub max_retries: u32,

    /// Delay between retry attempts
    pub retry_delay: Duration,

    /// Timeout for push operations
    pub push_timeout: Duration,

    /// Enable change batching (future optimization)
    pub enable_batching: bool,

    /// Batch size for change delivery (if batching enabled)
    pub batch_size: usize,

    /// Batch timeout (send batch even if not full)
    pub batch_timeout: Duration,
}

impl Default for PushManagerConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            retry_delay: Duration::from_secs(5),
            push_timeout: Duration::from_secs(30),
            enable_batching: false,
            batch_size: 10,
            batch_timeout: Duration::from_millis(500),
        }
    }
}

/// Statistics for a consumer's push operations
#[derive(Debug, Clone)]
pub struct ConsumerPushStats {
    pub consumer_id: String,
    pub changes_pushed: u64,
    pub changes_failed: u64,
    pub changes_filtered: u64,
    pub filter_errors: u64,
    pub retries: u64,
    pub last_push: Option<Instant>,
    pub last_error: Option<String>,
    pub registered_at: Instant,
}

impl ConsumerPushStats {
    fn new(consumer_id: String) -> Self {
        Self {
            consumer_id,
            changes_pushed: 0,
            changes_failed: 0,
            changes_filtered: 0,
            filter_errors: 0,
            retries: 0,
            last_push: None,
            last_error: None,
            registered_at: Instant::now(),
        }
    }
}

/// Overall Push Manager statistics
#[derive(Debug, Clone, Default)]
pub struct PushManagerStats {
    pub total_changes_pushed: u64,
    pub total_changes_failed: u64,
    pub total_changes_filtered: u64,
    pub total_filter_errors: u64,
    pub total_retries: u64,
    pub active_consumers: usize,
    pub started_at: Option<Instant>,
}

/// Manages persistent consumers and pushes changes to them
///
/// The PushManager is the central coordinator for push-based replication.
/// It maintains a registry of persistent consumers, receives change notifications,
/// and routes them to the appropriate consumers.
pub struct PushManager {
    /// Registered persistent consumers (consumer_id -> PersistentConsumer)
    consumers: Arc<RwLock<HashMap<String, Arc<PersistentConsumer>>>>,

    /// Routing metadata compiled from DN scopes and LDAP filters.
    consumer_routes: Arc<RwLock<HashMap<String, ConsumerRouting>>>,

    /// Per-consumer statistics
    consumer_stats: Arc<RwLock<HashMap<String, ConsumerPushStats>>>,

    /// Overall statistics
    stats: Arc<RwLock<PushManagerStats>>,

    /// Configuration
    config: PushManagerConfig,

    /// Change observer for receiving notifications
    observer: Arc<dyn ChangeObserver>,

    /// Flag indicating if manager is running
    running: Arc<RwLock<bool>>,
}

impl PushManager {
    /// Create a new Push Manager
    ///
    /// # Arguments
    ///
    /// * `observer` - Change observer to receive notifications from
    /// * `config` - Configuration for push behavior
    ///
    /// # Returns
    ///
    /// A new PushManager instance
    pub fn new(observer: Arc<dyn ChangeObserver>, config: PushManagerConfig) -> Self {
        info!("Creating Push Manager with config: {:?}", config);

        Self {
            consumers: Arc::new(RwLock::new(HashMap::new())),
            consumer_routes: Arc::new(RwLock::new(HashMap::new())),
            consumer_stats: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(PushManagerStats::default())),
            config,
            observer,
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Start the Push Manager
    ///
    /// This registers the manager as a callback with the change observer
    /// and begins listening for directory changes.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if started successfully
    /// * `Err(msg)` if already running or registration fails
    pub async fn start(&mut self) -> Result<(), String> {
        let mut running = self.running.write().await;
        if *running {
            return Err("Push Manager already running".to_string());
        }

        info!("Starting Push Manager");

        // Register self as change callback
        let callback: Arc<dyn ChangeCallback> = Arc::new(PushManagerCallback {
            push_manager: Arc::new(RwLock::new(PushManagerState {
                consumers: self.consumers.clone(),
                consumer_routes: self.consumer_routes.clone(),
                consumer_stats: self.consumer_stats.clone(),
                stats: self.stats.clone(),
                config: self.config.clone(),
            })),
        });

        self.observer.register_callback(callback);

        // Update stats
        let mut stats = self.stats.write().await;
        stats.started_at = Some(Instant::now());
        drop(stats);

        *running = true;
        info!("Push Manager started successfully");

        Ok(())
    }

    /// Stop the Push Manager
    ///
    /// This will stop processing new changes but will not close
    /// existing consumer connections.
    pub async fn stop(&mut self) -> Result<(), String> {
        let mut running = self.running.write().await;
        if !*running {
            return Err("Push Manager not running".to_string());
        }

        info!("Stopping Push Manager");
        *running = false;

        Ok(())
    }

    /// Register a persistent consumer
    ///
    /// # Arguments
    ///
    /// * `consumer_id` - Unique identifier for the consumer
    /// * `consumer` - PersistentConsumer instance
    ///
    /// # Returns
    ///
    /// * `Ok(())` if registered successfully
    /// * `Err(msg)` if consumer_id already exists
    pub async fn register_consumer(
        &mut self,
        consumer_id: String,
        consumer: PersistentConsumer,
    ) -> Result<(), String> {
        info!("Registering persistent consumer: {}", consumer_id);

        let route = ConsumerRouting {
            base_dn: consumer.base_dn().to_string(),
            compiled_filter: match consumer.filter.as_deref() {
                Some(filter) => Some(compile_filter(filter)?),
                None => None,
            },
        };

        let mut consumers = self.consumers.write().await;
        if consumers.contains_key(&consumer_id) {
            return Err(format!("Consumer {} already registered", consumer_id));
        }

        consumers.insert(consumer_id.clone(), Arc::new(consumer));
        drop(consumers);

        let mut consumer_routes = self.consumer_routes.write().await;
        consumer_routes.insert(consumer_id.clone(), route);
        drop(consumer_routes);

        // Initialize stats
        let mut consumer_stats = self.consumer_stats.write().await;
        consumer_stats.insert(
            consumer_id.clone(),
            ConsumerPushStats::new(consumer_id.clone()),
        );
        drop(consumer_stats);

        // Update overall stats
        let mut stats = self.stats.write().await;
        stats.active_consumers += 1;
        drop(stats);

        info!("Consumer {} registered successfully", consumer_id);
        Ok(())
    }

    /// Unregister a persistent consumer
    ///
    /// # Arguments
    ///
    /// * `consumer_id` - Unique identifier of the consumer to remove
    ///
    /// # Returns
    ///
    /// * `Ok(true)` if consumer was removed
    /// * `Ok(false)` if consumer was not found
    pub async fn unregister_consumer(&mut self, consumer_id: &str) -> Result<bool, String> {
        info!("Unregistering persistent consumer: {}", consumer_id);

        let mut consumers = self.consumers.write().await;
        let removed = consumers.remove(consumer_id).is_some();
        drop(consumers);

        if removed {
            let mut consumer_routes = self.consumer_routes.write().await;
            consumer_routes.remove(consumer_id);
            drop(consumer_routes);

            // Update overall stats
            let mut stats = self.stats.write().await;
            stats.active_consumers = stats.active_consumers.saturating_sub(1);
            drop(stats);

            info!("Consumer {} unregistered successfully", consumer_id);
            Ok(true)
        } else {
            warn!("Consumer {} not found for unregistration", consumer_id);
            Ok(false)
        }
    }

    /// Get list of registered consumer IDs
    pub async fn get_registered_consumers(&self) -> Vec<String> {
        self.consumers.read().await.keys().cloned().collect()
    }

    /// Get statistics for a specific consumer
    pub async fn get_consumer_stats(&self, consumer_id: &str) -> Option<ConsumerPushStats> {
        self.consumer_stats.read().await.get(consumer_id).cloned()
    }

    /// Get overall Push Manager statistics
    pub async fn get_stats(&self) -> PushManagerStats {
        let mut stats = self.stats.read().await.clone();
        stats.active_consumers = self.consumers.read().await.len();
        stats
    }

    /// Check if manager is running
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    /// Get number of registered consumers
    pub async fn consumer_count(&self) -> usize {
        self.consumers.read().await.len()
    }
}

/// Internal state for the PushManager callback
struct PushManagerState {
    consumers: Arc<RwLock<HashMap<String, Arc<PersistentConsumer>>>>,
    consumer_routes: Arc<RwLock<HashMap<String, ConsumerRouting>>>,
    consumer_stats: Arc<RwLock<HashMap<String, ConsumerPushStats>>>,
    stats: Arc<RwLock<PushManagerStats>>,
    config: PushManagerConfig,
}

#[derive(Debug, Clone)]
struct ConsumerRouting {
    base_dn: String,
    compiled_filter: Option<CompiledLdapFilter>,
}

/// Callback implementation for receiving change notifications
struct PushManagerCallback {
    push_manager: Arc<RwLock<PushManagerState>>,
}

#[async_trait]
impl ChangeCallback for PushManagerCallback {
    async fn on_change(&self, change: &ChangelogEntry) -> Result<(), String> {
        debug!(
            "PushManager received change notification: {} (type: {:?})",
            change.dn, change.change_type
        );

        let state = self.push_manager.read().await;
        let consumers = state.consumers.read().await.clone();
        let routes = state.consumer_routes.read().await.clone();
        let config = state.config.clone();
        drop(state);

        if consumers.is_empty() {
            debug!("No consumers registered, skipping push");
            return Ok(());
        }

        info!(
            "Evaluating change {} for {} consumers",
            change.dn,
            consumers.len()
        );

        let requires_entry_snapshot = routes.values().any(|route| route.compiled_filter.is_some());
        let scope_prepared = prepare_change(change, false);
        let attribute_prepared = if requires_entry_snapshot {
            Some(prepare_change(change, true))
        } else {
            None
        };

        // Push to all consumers in parallel
        let mut tasks = vec![];
        let mut filtered_count = 0;
        let mut filter_error_count = 0;
        for (consumer_id, consumer) in consumers.iter() {
            let Some(route) = routes.get(consumer_id).cloned() else {
                let error = format!("missing routing metadata for consumer {}", consumer_id);
                record_filter_error(&self.push_manager, consumer_id, &error).await;
                filter_error_count += 1;
                continue;
            };

            let prepared_change = if route.compiled_filter.is_some() {
                attribute_prepared
                    .as_ref()
                    .expect("attribute-prepared change must exist when filters require snapshots")
            } else {
                &scope_prepared
            };

            match should_route_change(prepared_change, &route) {
                Ok(true) => {}
                Ok(false) => {
                    record_filtered_change(&self.push_manager, consumer_id).await;
                    filtered_count += 1;
                    continue;
                }
                Err(error_message) => {
                    record_filter_error(&self.push_manager, consumer_id, &error_message).await;
                    filter_error_count += 1;
                    continue;
                }
            }

            let consumer_id = consumer_id.clone();
            let consumer = consumer.clone();
            let change = change.clone();
            let push_manager = self.push_manager.clone();
            let config = config.clone();

            // Use spawn instead of spawn_blocking since we'll manage the locks properly
            let task = tokio::spawn(async move {
                let result = push_change_to_consumer_wrapper(
                    &consumer_id,
                    &consumer,
                    &change,
                    push_manager,
                    &config,
                )
                .await;
                result
            });

            tasks.push(task);
        }

        // Wait for all pushes to complete
        let mut success_count = 0;
        let mut push_error_count = 0;

        for task in tasks {
            match task.await {
                Ok(Ok(())) => success_count += 1,
                Ok(Err(e)) => {
                    push_error_count += 1;
                    error!("Push task failed: {}", e);
                }
                Err(e) => {
                    push_error_count += 1;
                    error!("Push task panicked: {}", e);
                }
            }
        }

        if push_error_count > 0 || filter_error_count > 0 {
            warn!(
                "Push completed with issues: {}/{} succeeded, {} filtered, {} filter errors",
                success_count,
                success_count + push_error_count,
                filtered_count,
                filter_error_count
            );
        } else {
            debug!(
                "Push completed successfully: {} delivered, {} filtered",
                success_count, filtered_count
            );
        }

        Ok(())
    }
}

/// Wrapper to push changes that's Send-safe
async fn push_change_to_consumer_wrapper(
    consumer_id: &str,
    consumer: &PersistentConsumer,
    change: &ChangelogEntry,
    push_manager: Arc<RwLock<PushManagerState>>,
    config: &PushManagerConfig,
) -> Result<(), String> {
    push_change_to_consumer(consumer_id, consumer, change, &push_manager, config).await
}

fn should_route_change(
    prepared_change: &Result<PreparedChange, String>,
    route: &ConsumerRouting,
) -> Result<bool, String> {
    let prepared_change = prepared_change.as_ref().map_err(Clone::clone)?;
    prepared_change.matches(&route.base_dn, route.compiled_filter.as_ref())
}

async fn record_filtered_change(push_manager: &Arc<RwLock<PushManagerState>>, consumer_id: &str) {
    let state = push_manager.read().await;
    if let Some(stats) = state.consumer_stats.write().await.get_mut(consumer_id) {
        stats.changes_filtered += 1;
    }
    state.stats.write().await.total_changes_filtered += 1;
}

async fn record_filter_error(
    push_manager: &Arc<RwLock<PushManagerState>>,
    consumer_id: &str,
    error_message: &str,
) {
    let state = push_manager.read().await;
    if let Some(stats) = state.consumer_stats.write().await.get_mut(consumer_id) {
        stats.filter_errors += 1;
        stats.last_error = Some(error_message.to_string());
    }
    state.stats.write().await.total_filter_errors += 1;
    warn!(
        "Skipping change delivery for consumer {} because filter evaluation failed: {}",
        consumer_id, error_message
    );
}

/// Push a change to a specific consumer with retry logic
async fn push_change_to_consumer(
    consumer_id: &str,
    consumer: &PersistentConsumer,
    change: &ChangelogEntry,
    push_manager: &Arc<RwLock<PushManagerState>>,
    config: &PushManagerConfig,
) -> Result<(), String> {
    let mut attempts = 0;
    let mut last_error = None;

    while attempts <= config.max_retries {
        if attempts > 0 {
            debug!(
                "Retry attempt {} for consumer {} (after {} seconds)",
                attempts,
                consumer_id,
                config.retry_delay.as_secs()
            );
            sleep(config.retry_delay).await;

            // Update retry stats
            let state = push_manager.read().await;
            if let Some(stats) = state.consumer_stats.write().await.get_mut(consumer_id) {
                stats.retries += 1;
            }
            state.stats.write().await.total_retries += 1;
        }

        // Convert ChangelogEntry to DirectoryEntry and SyncState
        let (entry, sync_state) = convert_changelog_to_entry(change);

        // Generate cookie from CSN
        let cookie = Some(change.csn.to_string());

        // Attempt to send entry
        match consumer.send_entry(&entry, sync_state, cookie).await {
            Ok(()) => {
                debug!("Successfully pushed change to consumer {}", consumer_id);

                // Update success stats
                let state = push_manager.read().await;
                if let Some(stats) = state.consumer_stats.write().await.get_mut(consumer_id) {
                    stats.changes_pushed += 1;
                    stats.last_push = Some(Instant::now());
                    stats.last_error = None;
                }
                state.stats.write().await.total_changes_pushed += 1;

                return Ok(());
            }
            Err(e) => {
                error!(
                    "Failed to push change to consumer {} (attempt {}): {}",
                    consumer_id,
                    attempts + 1,
                    e
                );
                last_error = Some(e);
                attempts += 1;
            }
        }
    }

    // All retries exhausted
    let error_msg = format!(
        "Failed to push change to consumer {} after {} attempts: {}",
        consumer_id,
        config.max_retries + 1,
        last_error.unwrap_or_else(|| "Unknown error".to_string())
    );

    error!("{}", error_msg);

    // Update failure stats
    let state = push_manager.read().await;
    if let Some(stats) = state.consumer_stats.write().await.get_mut(consumer_id) {
        stats.changes_failed += 1;
        stats.last_error = Some(error_msg.clone());
    }
    state.stats.write().await.total_changes_failed += 1;

    Err(error_msg)
}

/// Convert a ChangelogEntry to a DirectoryEntry and SyncState
fn convert_changelog_to_entry(change: &ChangelogEntry) -> (DirectoryEntry, SyncState) {
    let sync_state = match change.change_type {
        ChangeType::Add => SyncState::Add,
        ChangeType::Modify => SyncState::Modify,
        ChangeType::Delete => SyncState::Delete,
        ChangeType::Rename => SyncState::Modify, // Treat rename as modify
    };

    // Parse change_data to extract attributes (simplified version)
    // In production, would properly decode the change_data Vec<u8>
    let attributes: Vec<(String, Vec<String>)> = if !change.change_data.is_empty() {
        // For now, create minimal attributes from the change
        vec![(
            "changetype".to_string(),
            vec![format!("{:?}", change.change_type)],
        )]
    } else {
        vec![]
    };

    // Use CSN as UUID (in production, would extract actual UUID)
    let uuid = change.csn.to_string();

    let entry = DirectoryEntry::new(change.dn.clone(), uuid, attributes);

    (entry, sync_state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::change_observer::ChangeObserverImpl;
    use crate::csn::Csn;

    fn create_test_change(dn: &str, change_type: ChangeType) -> ChangelogEntry {
        ChangelogEntry::new(
            Csn::new(1),
            change_type,
            dn.to_string(),
            vec![], /* change_data */
        )
    }

    #[tokio::test]
    async fn test_push_manager_creation() {
        let observer = Arc::new(ChangeObserverImpl::new());
        let config = PushManagerConfig::default();
        let manager = PushManager::new(observer, config);

        assert_eq!(manager.consumer_count().await, 0);
        assert!(!manager.is_running().await);
    }

    #[tokio::test]
    async fn test_push_manager_start() {
        let observer = Arc::new(ChangeObserverImpl::new());
        let config = PushManagerConfig::default();
        let mut manager = PushManager::new(observer.clone(), config);

        let result = manager.start().await;
        assert!(result.is_ok());
        assert!(manager.is_running().await);

        // Observer should have the callback registered
        assert_eq!(observer.callback_count(), 1);
    }

    #[tokio::test]
    async fn test_push_manager_start_twice_fails() {
        let observer = Arc::new(ChangeObserverImpl::new());
        let config = PushManagerConfig::default();
        let mut manager = PushManager::new(observer, config);

        manager.start().await.unwrap();
        let result = manager.start().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already running"));
    }

    #[tokio::test]
    async fn test_push_manager_stop() {
        let observer = Arc::new(ChangeObserverImpl::new());
        let config = PushManagerConfig::default();
        let mut manager = PushManager::new(observer, config);

        manager.start().await.unwrap();
        assert!(manager.is_running().await);

        let result = manager.stop().await;
        assert!(result.is_ok());
        assert!(!manager.is_running().await);
    }

    #[tokio::test]
    async fn test_stop_without_start_fails() {
        let observer = Arc::new(ChangeObserverImpl::new());
        let config = PushManagerConfig::default();
        let mut manager = PushManager::new(observer, config);

        let result = manager.stop().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_register_consumer() {
        let observer = Arc::new(ChangeObserverImpl::new());
        let config = PushManagerConfig::default();
        let mut manager = PushManager::new(observer, config);

        let consumer = PersistentConsumer::new(
            "consumer-1".to_string(),
            "ldap://localhost:389".to_string(),
            "dc=example,dc=com".to_string(),
            Duration::from_secs(30),
        )
        .await;

        // Consumer creation will fail without real LDAP server, but we can test the logic
        if let Ok(consumer) = consumer {
            let result = manager
                .register_consumer("consumer-1".to_string(), consumer)
                .await;
            assert!(result.is_ok());
            assert_eq!(manager.consumer_count().await, 1);
        }
    }

    #[tokio::test]
    async fn test_get_registered_consumers_empty() {
        let observer = Arc::new(ChangeObserverImpl::new());
        let config = PushManagerConfig::default();
        let manager = PushManager::new(observer, config);

        let consumers = manager.get_registered_consumers().await;
        assert_eq!(consumers.len(), 0);
    }

    #[tokio::test]
    async fn test_get_stats() {
        let observer = Arc::new(ChangeObserverImpl::new());
        let config = PushManagerConfig::default();
        let manager = PushManager::new(observer, config);

        let stats = manager.get_stats().await;
        assert_eq!(stats.total_changes_pushed, 0);
        assert_eq!(stats.total_changes_failed, 0);
        assert_eq!(stats.total_changes_filtered, 0);
        assert_eq!(stats.total_filter_errors, 0);
        assert_eq!(stats.active_consumers, 0);
        assert!(stats.started_at.is_none());
    }

    #[tokio::test]
    async fn test_get_consumer_stats_not_found() {
        let observer = Arc::new(ChangeObserverImpl::new());
        let config = PushManagerConfig::default();
        let manager = PushManager::new(observer, config);

        let stats = manager.get_consumer_stats("nonexistent").await;
        assert!(stats.is_none());
    }

    #[tokio::test]
    async fn test_config_default_values() {
        let config = PushManagerConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.retry_delay, Duration::from_secs(5));
        assert_eq!(config.push_timeout, Duration::from_secs(30));
        assert!(!config.enable_batching);
        assert_eq!(config.batch_size, 10);
    }

    #[test]
    fn test_convert_changelog_to_entry_add() {
        let change = create_test_change("cn=test,dc=example,dc=com", ChangeType::Add);
        let (entry, state) = convert_changelog_to_entry(&change);

        assert_eq!(entry.dn, "cn=test,dc=example,dc=com");
        assert_eq!(state, SyncState::Add);
    }

    #[test]
    fn test_convert_changelog_to_entry_modify() {
        let change = create_test_change("cn=test,dc=example,dc=com", ChangeType::Modify);
        let (_entry, state) = convert_changelog_to_entry(&change);

        assert_eq!(state, SyncState::Modify);
    }

    #[test]
    fn test_convert_changelog_to_entry_delete() {
        let change = create_test_change("cn=test,dc=example,dc=com", ChangeType::Delete);
        let (_entry, state) = convert_changelog_to_entry(&change);

        assert_eq!(state, SyncState::Delete);
    }

    #[test]
    fn test_consumer_push_stats_creation() {
        let stats = ConsumerPushStats::new("consumer-1".to_string());
        assert_eq!(stats.consumer_id, "consumer-1");
        assert_eq!(stats.changes_pushed, 0);
        assert_eq!(stats.changes_failed, 0);
        assert_eq!(stats.changes_filtered, 0);
        assert_eq!(stats.filter_errors, 0);
        assert!(stats.last_error.is_none());
    }

    #[tokio::test]
    async fn test_register_consumer_rejects_invalid_filter() {
        let observer = Arc::new(ChangeObserverImpl::new());
        let config = PushManagerConfig::default();
        let mut manager = PushManager::new(observer, config);

        let consumer = PersistentConsumer::with_filter_lazy(
            "consumer-1".to_string(),
            "ldap://127.0.0.1:389".to_string(),
            "dc=example,dc=com".to_string(),
            "(objectClass=person".to_string(),
            vec!["*".to_string()],
            Duration::from_secs(30),
        );

        let result = manager
            .register_consumer("consumer-1".to_string(), consumer)
            .await;
        assert!(result.is_err());
        assert_eq!(manager.consumer_count().await, 0);
    }

    #[tokio::test]
    async fn test_push_manager_filters_non_matching_changes() {
        let observer = Arc::new(ChangeObserverImpl::new());
        let config = PushManagerConfig::default();
        let mut manager = PushManager::new(observer.clone(), config);
        manager.start().await.unwrap();

        let consumer = PersistentConsumer::with_filter_lazy(
            "consumer-1".to_string(),
            "ldap://127.0.0.1:389".to_string(),
            "dc=example,dc=com".to_string(),
            "(objectClass=person)".to_string(),
            vec!["*".to_string()],
            Duration::from_secs(30),
        );

        manager
            .register_consumer("consumer-1".to_string(), consumer)
            .await
            .unwrap();

        let mut attributes = std::collections::HashMap::new();
        attributes.insert("objectclass".to_string(), vec!["group".to_string()]);
        attributes.insert("cn".to_string(), vec!["admins".to_string()]);
        let entry = crate::backend::DirectoryEntry::new("cn=admins,dc=example,dc=com", attributes);
        let change = ChangelogEntry::new(
            Csn::new(1),
            ChangeType::Add,
            entry.dn.clone(),
            serde_json::to_vec(&entry).unwrap(),
        );

        observer.notify_change(&change).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let stats = manager.get_consumer_stats("consumer-1").await.unwrap();
        assert_eq!(stats.changes_pushed, 0);
        assert_eq!(stats.changes_failed, 0);
        assert_eq!(stats.changes_filtered, 1);

        let manager_stats = manager.get_stats().await;
        assert_eq!(manager_stats.total_changes_filtered, 1);
        assert_eq!(manager_stats.total_filter_errors, 0);
    }
}

//! Provider FSM and Push Manager Integration
//!
//! This module integrates the Replication Provider FSM with the Push Manager
//! to enable refreshAndPersist mode support for push-based replication.
//!
//! # Architecture
//!
//! ```text
//! Consumer Request (refreshAndPersist)
//!         ↓
//! Provider FSM (Refresh Phase) → Send all entries
//!         ↓
//! Provider FSM (Present Phase) → Send changelog entries
//!         ↓
//! Provider FSM (Persist Phase) → Register with Push Manager
//!         ↓
//! Push Manager → Continuously push new changes
//! ```
//!
//! # Key Components
//!
//! - `ProviderPushCoordinator`: Bridges Provider FSM and Push Manager
//! - Lifecycle management for persistent consumers
//! - Connection keep-alive handling
//! - Automatic registration/unregistration

use async_trait::async_trait;
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::fsm::ReplicationProviderFsm;
use crate::persistent_connection::PersistentConsumer;
use crate::push_manager::PushManager;
use crate::replication_provider_fsm::{ConsumerConnection, SyncMode};

/// Configuration for Provider-Push integration
#[derive(Debug, Clone)]
pub struct ProviderPushConfig {
    /// Heartbeat interval for persistent connections
    pub heartbeat_interval: Duration,

    /// Connection timeout before considering consumer dead
    pub connection_timeout: Duration,

    /// Maximum number of persistent consumers
    pub max_persistent_consumers: u32,

    /// Enable automatic cleanup of dead connections
    pub enable_auto_cleanup: bool,

    /// Cleanup check interval
    pub cleanup_interval: Duration,
}

impl Default for ProviderPushConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval: Duration::from_secs(30),
            connection_timeout: Duration::from_secs(300), // 5 minutes
            max_persistent_consumers: 100,
            enable_auto_cleanup: true,
            cleanup_interval: Duration::from_secs(60),
        }
    }
}

/// Coordinates between Provider FSM and Push Manager for refreshAndPersist mode
pub struct ProviderPushCoordinator {
    /// Push Manager instance
    push_manager: Arc<RwLock<PushManager>>,

    /// Persistent consumers registered
    persistent_consumers: Arc<RwLock<HashMap<String, PersistentConsumerInfo>>>,

    /// Configuration
    config: ProviderPushConfig,

    /// Statistics
    stats: Arc<RwLock<CoordinatorStats>>,
}

/// Information about a persistent consumer
#[derive(Debug, Clone)]
pub struct PersistentConsumerInfo {
    /// Consumer identifier
    pub consumer_id: String,

    /// Consumer connection details
    pub connection: ConsumerConnection,

    /// Registration timestamp
    pub registered_at: Instant,

    /// Last heartbeat sent
    pub last_heartbeat: Instant,

    /// Last activity timestamp
    pub last_activity: Instant,

    /// Last cookie sent
    pub last_cookie: Option<String>,
}

/// Coordinator statistics
#[derive(Debug, Clone)]
pub struct CoordinatorStats {
    /// Total persistent consumers registered
    pub total_registered: u64,

    /// Currently active persistent consumers
    pub active_persistent: usize,

    /// Total consumers unregistered
    pub total_unregistered: u64,

    /// Total heartbeats sent
    pub total_heartbeats: u64,

    /// Total connection timeouts
    pub total_timeouts: u64,

    /// Total errors encountered
    pub total_errors: u64,

    /// Statistics collection start time
    pub started_at: Instant,
}

impl CoordinatorStats {
    pub fn new() -> Self {
        Self {
            total_registered: 0,
            active_persistent: 0,
            total_unregistered: 0,
            total_heartbeats: 0,
            total_timeouts: 0,
            total_errors: 0,
            started_at: Instant::now(),
        }
    }
}

impl ProviderPushCoordinator {
    /// Create a new Provider-Push Coordinator
    ///
    /// # Arguments
    /// * `push_manager` - Push Manager instance
    /// * `config` - Configuration for the coordinator
    ///
    /// # Returns
    /// * New ProviderPushCoordinator instance
    pub fn new(push_manager: Arc<RwLock<PushManager>>, config: ProviderPushConfig) -> Self {
        Self {
            push_manager,
            persistent_consumers: Arc::new(RwLock::new(HashMap::new())),
            config,
            stats: Arc::new(RwLock::new(CoordinatorStats::new())),
        }
    }

    /// Start the coordinator (starts push manager and cleanup tasks)
    ///
    /// # Returns
    /// * Result indicating success or error
    pub async fn start(&self) -> Result<(), String> {
        info!("Starting Provider-Push Coordinator");

        // Start the push manager
        let mut push_manager = self.push_manager.write().await;
        push_manager.start().await?;
        drop(push_manager);

        // Start cleanup task if enabled
        if self.config.enable_auto_cleanup {
            self.start_cleanup_task().await;
        }

        info!("Provider-Push Coordinator started successfully");
        Ok(())
    }

    /// Stop the coordinator
    ///
    /// # Returns
    /// * Result indicating success or error
    pub async fn stop(&self) -> Result<(), String> {
        info!("Stopping Provider-Push Coordinator");

        // Unregister all persistent consumers
        let consumer_ids: Vec<String> = {
            let consumers = self.persistent_consumers.read().await;
            consumers.keys().cloned().collect()
        };

        for consumer_id in consumer_ids {
            let _ = self.unregister_persistent_consumer(&consumer_id).await;
        }

        // Stop the push manager
        let mut push_manager = self.push_manager.write().await;
        push_manager.stop().await?;

        info!("Provider-Push Coordinator stopped successfully");
        Ok(())
    }

    /// Register a consumer for persistent mode (refreshAndPersist)
    ///
    /// This is called when the Provider FSM completes the present phase
    /// and transitions to persist phase for a consumer in refreshAndPersist mode.
    ///
    /// # Arguments
    /// * `consumer_id` - Consumer identifier
    /// * `connection` - Consumer connection details
    /// * `base_dn` - Base DN for replication
    /// * `filter` - Optional search filter
    /// * `cookie` - Current replication cookie
    ///
    /// # Returns
    /// * Result indicating success or error
    pub async fn register_persistent_consumer(
        &self,
        consumer_id: String,
        connection: ConsumerConnection,
        base_dn: String,
        filter: Option<String>,
        cookie: String,
    ) -> Result<(), String> {
        info!("Registering persistent consumer: {}", consumer_id);

        // Check if we're at the limit
        let current_count = {
            let consumers = self.persistent_consumers.read().await;
            consumers.len()
        };

        if current_count >= self.config.max_persistent_consumers as usize {
            let msg = format!(
                "Maximum persistent consumer limit ({}) reached",
                self.config.max_persistent_consumers
            );
            error!("{}", msg);
            return Err(msg);
        }

        // Create persistent consumer connection
        let persistent_consumer = PersistentConsumer::new(
            consumer_id.clone(),
            connection.address.clone(),
            base_dn,
            self.config.heartbeat_interval,
        )
        .await?;

        // Register with push manager first (push_manager takes ownership)
        let mut push_manager = self.push_manager.write().await;
        push_manager
            .register_consumer(consumer_id.clone(), persistent_consumer)
            .await?;
        drop(push_manager);

        // Store consumer info (without persistent_consumer since push_manager owns it)
        let now = Instant::now();
        let consumer_info = PersistentConsumerInfo {
            consumer_id: consumer_id.clone(),
            connection: connection.clone(),
            registered_at: now,
            last_heartbeat: now,
            last_activity: now,
            last_cookie: Some(cookie.clone()),
        };

        {
            let mut consumers = self.persistent_consumers.write().await;
            consumers.insert(consumer_id.clone(), consumer_info);
        }

        // Update statistics
        let mut stats = self.stats.write().await;
        stats.total_registered += 1;
        stats.active_persistent = {
            let consumers = self.persistent_consumers.read().await;
            consumers.len()
        };
        drop(stats);

        info!(
            "Persistent consumer registered successfully: {}",
            consumer_id
        );
        Ok(())
    }

    /// Unregister a persistent consumer
    ///
    /// # Arguments
    /// * `consumer_id` - Consumer identifier to unregister
    ///
    /// # Returns
    /// * Result indicating success or error
    pub async fn unregister_persistent_consumer(&self, consumer_id: &str) -> Result<(), String> {
        info!("Unregistering persistent consumer: {}", consumer_id);

        // Remove from tracking
        let consumer_info = {
            let mut consumers = self.persistent_consumers.write().await;
            consumers.remove(consumer_id)
        };

        if consumer_info.is_some() {
            // Unregister from push manager (this will close the connection)
            let mut push_manager = self.push_manager.write().await;
            push_manager.unregister_consumer(consumer_id).await?;
            drop(push_manager);

            // Update statistics
            let mut stats = self.stats.write().await;
            stats.total_unregistered += 1;
            stats.active_persistent = {
                let consumers = self.persistent_consumers.read().await;
                consumers.len()
            };
            drop(stats);

            info!(
                "Persistent consumer unregistered successfully: {}",
                consumer_id
            );
            Ok(())
        } else {
            warn!("Consumer not found: {}", consumer_id);
            Err(format!("Consumer not found: {}", consumer_id))
        }
    }

    /// Send heartbeat to a persistent consumer
    ///
    /// # Arguments
    /// * `consumer_id` - Consumer identifier
    ///
    /// # Returns
    /// * Result indicating success or error
    pub async fn send_heartbeat(&self, consumer_id: &str) -> Result<(), String> {
        debug!("Sending heartbeat to consumer: {}", consumer_id);

        let consumer_exists = {
            let consumers = self.persistent_consumers.read().await;
            consumers.contains_key(consumer_id)
        };

        if consumer_exists {
            // NOTE: Actual heartbeat is handled by PersistentConsumer inside PushManager
            // Here we just track the heartbeat time and update activity

            // Update last heartbeat timestamp
            {
                let mut consumers = self.persistent_consumers.write().await;
                if let Some(consumer) = consumers.get_mut(consumer_id) {
                    consumer.last_heartbeat = Instant::now();
                    consumer.last_activity = Instant::now();
                }
            }

            // Update statistics
            let mut stats = self.stats.write().await;
            stats.total_heartbeats += 1;

            debug!("Heartbeat tracked for: {}", consumer_id);
            Ok(())
        } else {
            Err(format!("Consumer not found: {}", consumer_id))
        }
    }

    /// Send heartbeat to all persistent consumers
    ///
    /// # Returns
    /// * (successful, failed) counts
    pub async fn send_heartbeat_to_all(&self) -> (usize, usize) {
        let consumer_ids: Vec<String> = {
            let consumers = self.persistent_consumers.read().await;
            consumers.keys().cloned().collect()
        };

        let mut successful = 0;
        let mut failed = 0;

        for consumer_id in consumer_ids {
            match self.send_heartbeat(&consumer_id).await {
                Ok(_) => successful += 1,
                Err(e) => {
                    warn!("Failed to send heartbeat to {}: {}", consumer_id, e);
                    failed += 1;

                    // Update error stats
                    let mut stats = self.stats.write().await;
                    stats.total_errors += 1;
                }
            }
        }

        (successful, failed)
    }

    /// Update consumer's last cookie
    ///
    /// # Arguments
    /// * `consumer_id` - Consumer identifier
    /// * `cookie` - New cookie value
    ///
    /// # Returns
    /// * Result indicating success or error
    pub async fn update_consumer_cookie(
        &self,
        consumer_id: &str,
        cookie: String,
    ) -> Result<(), String> {
        let mut consumers = self.persistent_consumers.write().await;
        if let Some(consumer) = consumers.get_mut(consumer_id) {
            consumer.last_cookie = Some(cookie);
            consumer.last_activity = Instant::now();
            Ok(())
        } else {
            Err(format!("Consumer not found: {}", consumer_id))
        }
    }

    /// Check for timed out connections and remove them
    ///
    /// # Returns
    /// * Number of consumers removed
    pub async fn cleanup_timed_out_consumers(&self) -> usize {
        let timeout = self.config.connection_timeout;
        let now = Instant::now();

        let timed_out: Vec<String> = {
            let consumers = self.persistent_consumers.read().await;
            consumers
                .iter()
                .filter(|(_, info)| now.duration_since(info.last_activity) > timeout)
                .map(|(id, _)| id.clone())
                .collect()
        };

        let mut removed = 0;
        for consumer_id in timed_out {
            warn!("Consumer timed out: {}", consumer_id);
            if self
                .unregister_persistent_consumer(&consumer_id)
                .await
                .is_ok()
            {
                removed += 1;

                // Update timeout statistics
                let mut stats = self.stats.write().await;
                stats.total_timeouts += 1;
            }
        }

        if removed > 0 {
            info!("Cleaned up {} timed out consumers", removed);
        }

        removed
    }

    /// Start background cleanup task
    async fn start_cleanup_task(&self) {
        let coordinator = self.clone();
        let interval = self.config.cleanup_interval;

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                coordinator.cleanup_timed_out_consumers().await;
            }
        });

        debug!("Cleanup task started with interval: {:?}", interval);
    }

    /// Get coordinator statistics
    ///
    /// # Returns
    /// * Current coordinator statistics
    pub async fn get_stats(&self) -> CoordinatorStats {
        let stats = self.stats.read().await;
        stats.clone()
    }

    /// Get list of persistent consumer IDs
    ///
    /// # Returns
    /// * Vector of consumer IDs
    pub async fn get_persistent_consumer_ids(&self) -> Vec<String> {
        let consumers = self.persistent_consumers.read().await;
        consumers.keys().cloned().collect()
    }

    /// Check if a consumer is registered
    ///
    /// # Arguments
    /// * `consumer_id` - Consumer identifier to check
    ///
    /// # Returns
    /// * True if consumer is registered
    pub async fn is_consumer_registered(&self, consumer_id: &str) -> bool {
        let consumers = self.persistent_consumers.read().await;
        consumers.contains_key(consumer_id)
    }

    /// Get consumer information
    ///
    /// # Arguments
    /// * `consumer_id` - Consumer identifier
    ///
    /// # Returns
    /// * Consumer information if found
    pub async fn get_consumer_info(&self, consumer_id: &str) -> Option<PersistentConsumerInfo> {
        let consumers = self.persistent_consumers.read().await;
        consumers.get(consumer_id).cloned()
    }
}

// Implement Clone manually for ProviderPushCoordinator
impl Clone for ProviderPushCoordinator {
    fn clone(&self) -> Self {
        Self {
            push_manager: self.push_manager.clone(),
            persistent_consumers: self.persistent_consumers.clone(),
            config: self.config.clone(),
            stats: self.stats.clone(),
        }
    }
}

/// Extension trait for ReplicationProviderFsm to add refreshAndPersist support
#[async_trait]
pub trait ProviderFsmPushExtension: ReplicationProviderFsm {
    /// Handle transition to persist phase for refreshAndPersist mode
    ///
    /// This method should be called when the provider FSM transitions to
    /// the Persist state after completing refresh and present phases.
    ///
    /// # Arguments
    /// * `coordinator` - Provider-Push coordinator
    /// * `consumer_id` - Consumer identifier
    /// * `connection` - Consumer connection details
    /// * `base_dn` - Base DN for replication
    /// * `filter` - Optional search filter
    /// * `cookie` - Current replication cookie
    ///
    /// # Returns
    /// * Result indicating success or error
    async fn handle_persist_phase_entry(
        &self,
        coordinator: &ProviderPushCoordinator,
        consumer_id: String,
        connection: ConsumerConnection,
        base_dn: String,
        filter: Option<String>,
        cookie: String,
    ) -> Result<(), String> {
        // Check if consumer is in refreshAndPersist mode
        if connection.sync_mode != SyncMode::RefreshAndPersist {
            return Ok(()); // Not persistent mode, nothing to do
        }

        // Register with coordinator
        coordinator
            .register_persistent_consumer(consumer_id, connection, base_dn, filter, cookie)
            .await
    }

    /// Handle consumer disconnection for persistent consumers
    ///
    /// # Arguments
    /// * `coordinator` - Provider-Push coordinator
    /// * `consumer_id` - Disconnected consumer identifier
    ///
    /// # Returns
    /// * Result indicating success or error
    async fn handle_consumer_disconnect(
        &self,
        coordinator: &ProviderPushCoordinator,
        consumer_id: &str,
    ) -> Result<(), String> {
        // Unregister from coordinator
        coordinator
            .unregister_persistent_consumer(consumer_id)
            .await
    }
}

// Implement the extension trait for any ReplicationProviderFsm
impl<T: ReplicationProviderFsm> ProviderFsmPushExtension for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::change_observer::ChangeObserverImpl;
    use crate::push_manager::PushManagerConfig;

    async fn create_test_coordinator() -> ProviderPushCoordinator {
        let observer = Arc::new(ChangeObserverImpl::new());
        let push_config = PushManagerConfig::default();
        let push_manager = Arc::new(RwLock::new(PushManager::new(observer, push_config)));
        let config = ProviderPushConfig::default();
        ProviderPushCoordinator::new(push_manager, config)
    }

    fn create_test_connection(address: String, sync_mode: SyncMode) -> ConsumerConnection {
        ConsumerConnection::with_sync_mode(address, sync_mode)
    }

    #[tokio::test]
    async fn test_coordinator_creation() {
        let coordinator = create_test_coordinator().await;
        let stats = coordinator.get_stats().await;

        assert_eq!(stats.total_registered, 0);
        assert_eq!(stats.active_persistent, 0);
        assert_eq!(stats.total_unregistered, 0);
    }

    #[tokio::test]
    async fn test_coordinator_start_stop() {
        let coordinator = create_test_coordinator().await;

        // Start coordinator
        let result = coordinator.start().await;
        assert!(result.is_ok());

        // Stop coordinator
        let result = coordinator.stop().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_register_persistent_consumer() {
        let coordinator = create_test_coordinator().await;
        coordinator.start().await.unwrap();

        let consumer_id = "test-consumer-1".to_string();
        let connection = create_test_connection(
            "ldap://consumer:389".to_string(),
            SyncMode::RefreshAndPersist,
        );

        let result = coordinator
            .register_persistent_consumer(
                consumer_id.clone(),
                connection,
                "dc=example,dc=com".to_string(),
                None,
                "cookie-123".to_string(),
            )
            .await;

        assert!(result.is_ok());

        // Check statistics
        let stats = coordinator.get_stats().await;
        assert_eq!(stats.total_registered, 1);
        assert_eq!(stats.active_persistent, 1);

        // Check consumer is registered
        assert!(coordinator.is_consumer_registered(&consumer_id).await);

        coordinator.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_unregister_persistent_consumer() {
        let coordinator = create_test_coordinator().await;
        coordinator.start().await.unwrap();

        let consumer_id = "test-consumer-1".to_string();
        let connection = create_test_connection(
            "ldap://consumer:389".to_string(),
            SyncMode::RefreshAndPersist,
        );

        // Register
        coordinator
            .register_persistent_consumer(
                consumer_id.clone(),
                connection,
                "dc=example,dc=com".to_string(),
                None,
                "cookie-123".to_string(),
            )
            .await
            .unwrap();

        // Unregister
        let result = coordinator
            .unregister_persistent_consumer(&consumer_id)
            .await;
        assert!(result.is_ok());

        // Check statistics
        let stats = coordinator.get_stats().await;
        assert_eq!(stats.total_registered, 1);
        assert_eq!(stats.total_unregistered, 1);
        assert_eq!(stats.active_persistent, 0);

        // Check consumer is not registered
        assert!(!coordinator.is_consumer_registered(&consumer_id).await);

        coordinator.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_register_multiple_consumers() {
        let coordinator = create_test_coordinator().await;
        coordinator.start().await.unwrap();

        for i in 1..=3 {
            let consumer_id = format!("test-consumer-{}", i);
            let connection = create_test_connection(
                format!("ldap://consumer{}:389", i),
                SyncMode::RefreshAndPersist,
            );

            coordinator
                .register_persistent_consumer(
                    consumer_id,
                    connection,
                    "dc=example,dc=com".to_string(),
                    None,
                    format!("cookie-{}", i),
                )
                .await
                .unwrap();
        }

        // Check statistics
        let stats = coordinator.get_stats().await;
        assert_eq!(stats.total_registered, 3);
        assert_eq!(stats.active_persistent, 3);

        // Check all consumers are registered
        let consumer_ids = coordinator.get_persistent_consumer_ids().await;
        assert_eq!(consumer_ids.len(), 3);

        coordinator.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_update_consumer_cookie() {
        let coordinator = create_test_coordinator().await;
        coordinator.start().await.unwrap();

        let consumer_id = "test-consumer-1".to_string();
        let connection = create_test_connection(
            "ldap://consumer:389".to_string(),
            SyncMode::RefreshAndPersist,
        );

        // Register
        coordinator
            .register_persistent_consumer(
                consumer_id.clone(),
                connection,
                "dc=example,dc=com".to_string(),
                None,
                "cookie-123".to_string(),
            )
            .await
            .unwrap();

        // Update cookie
        let result = coordinator
            .update_consumer_cookie(&consumer_id, "cookie-456".to_string())
            .await;
        assert!(result.is_ok());

        // Verify cookie was updated
        let info = coordinator.get_consumer_info(&consumer_id).await;
        assert!(info.is_some());
        assert_eq!(info.unwrap().last_cookie, Some("cookie-456".to_string()));

        coordinator.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_get_consumer_info() {
        let coordinator = create_test_coordinator().await;
        coordinator.start().await.unwrap();

        let consumer_id = "test-consumer-1".to_string();
        let connection = create_test_connection(
            "ldap://consumer:389".to_string(),
            SyncMode::RefreshAndPersist,
        );

        // Register
        coordinator
            .register_persistent_consumer(
                consumer_id.clone(),
                connection,
                "dc=example,dc=com".to_string(),
                Some("(objectClass=person)".to_string()),
                "cookie-123".to_string(),
            )
            .await
            .unwrap();

        // Get info
        let info = coordinator.get_consumer_info(&consumer_id).await;
        assert!(info.is_some());

        let info = info.unwrap();
        assert_eq!(info.consumer_id, consumer_id);
        assert_eq!(info.last_cookie, Some("cookie-123".to_string()));

        coordinator.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_max_persistent_consumers_limit() {
        let observer = Arc::new(ChangeObserverImpl::new());
        let push_config = PushManagerConfig::default();
        let push_manager = Arc::new(RwLock::new(PushManager::new(observer, push_config)));
        let mut config = ProviderPushConfig::default();
        config.max_persistent_consumers = 2; // Set limit to 2

        let coordinator = ProviderPushCoordinator::new(push_manager, config);
        coordinator.start().await.unwrap();

        // Register 2 consumers (should succeed)
        for i in 1..=2 {
            let consumer_id = format!("test-consumer-{}", i);
            let connection = create_test_connection(
                format!("ldap://consumer{}:389", i),
                SyncMode::RefreshAndPersist,
            );

            let result = coordinator
                .register_persistent_consumer(
                    consumer_id,
                    connection,
                    "dc=example,dc=com".to_string(),
                    None,
                    format!("cookie-{}", i),
                )
                .await;
            assert!(result.is_ok());
        }

        // Try to register 3rd consumer (should fail)
        let consumer_id = "test-consumer-3".to_string();
        let connection = create_test_connection(
            "ldap://consumer3:389".to_string(),
            SyncMode::RefreshAndPersist,
        );

        let result = coordinator
            .register_persistent_consumer(
                consumer_id,
                connection,
                "dc=example,dc=com".to_string(),
                None,
                "cookie-3".to_string(),
            )
            .await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Maximum persistent consumer limit"));

        coordinator.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_coordinator_statistics() {
        let coordinator = create_test_coordinator().await;
        coordinator.start().await.unwrap();

        let consumer_id = "test-consumer-1".to_string();
        let connection = create_test_connection(
            "ldap://consumer:389".to_string(),
            SyncMode::RefreshAndPersist,
        );

        // Register
        coordinator
            .register_persistent_consumer(
                consumer_id.clone(),
                connection,
                "dc=example,dc=com".to_string(),
                None,
                "cookie-123".to_string(),
            )
            .await
            .unwrap();

        // Unregister
        coordinator
            .unregister_persistent_consumer(&consumer_id)
            .await
            .unwrap();

        // Check final statistics
        let stats = coordinator.get_stats().await;
        assert_eq!(stats.total_registered, 1);
        assert_eq!(stats.total_unregistered, 1);
        assert_eq!(stats.active_persistent, 0);

        coordinator.stop().await.unwrap();
    }
}

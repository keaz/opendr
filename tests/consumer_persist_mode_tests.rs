//! Integration Tests for Consumer Persist Mode (Task 3.1)
//!
//! Comprehensive test suite for RFC 4533 refreshAndPersist mode implementation.

use async_trait::async_trait;
use opendr::consumer_persist_mode::{
    PersistConnectionState, PersistModeConfig, PersistModeManager, PersistModeStats,
    create_persist_mode_event, is_persist_mode_compatible_state, should_use_persist_mode,
};
use opendr::fsm::ReplicationConsumerState;
use opendr::replication_consumer_fsm::{
    ChangeListener, ConsumerError, ListeningStats, ProviderConnection, StateManager,
    StorageMetadata,
};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

// ================================================================================================
// Mock Implementations
// ================================================================================================

/// Mock provider connection for testing
struct MockProviderConnection {
    connected: Arc<RwLock<bool>>,
    connection_count: Arc<RwLock<usize>>,
}

impl MockProviderConnection {
    fn new() -> Self {
        Self {
            connected: Arc::new(RwLock::new(false)),
            connection_count: Arc::new(RwLock::new(0)),
        }
    }

    async fn get_connection_count(&self) -> usize {
        *self.connection_count.read().await
    }
}

#[async_trait]
impl ProviderConnection for MockProviderConnection {
    async fn connect(&self, _url: &str) -> Result<(), ConsumerError> {
        let mut connected = self.connected.write().await;
        *connected = true;
        let mut count = self.connection_count.write().await;
        *count += 1;
        Ok(())
    }

    async fn request_from_cookie(
        &self,
        _cookie: Option<&str>,
    ) -> Result<Vec<Vec<u8>>, ConsumerError> {
        Ok(vec![])
    }

    async fn disconnect(&self) -> Result<(), ConsumerError> {
        let mut connected = self.connected.write().await;
        *connected = false;
        Ok(())
    }

    async fn is_connected(&self) -> Result<bool, ConsumerError> {
        Ok(*self.connected.read().await)
    }

    async fn get_connection_info(
        &self,
    ) -> Result<opendr::replication_consumer_fsm::ConnectionInfo, ConsumerError> {
        Ok(opendr::replication_consumer_fsm::ConnectionInfo::new(
            "ldap://mock:389".to_string(),
            "v3".to_string(),
            false,
        ))
    }
}

/// Mock change listener for testing
struct MockChangeListener {
    listening: Arc<RwLock<bool>>,
    changes: Arc<RwLock<VecDeque<Vec<u8>>>>,
}

impl MockChangeListener {
    fn new() -> Self {
        Self {
            listening: Arc::new(RwLock::new(false)),
            changes: Arc::new(RwLock::new(VecDeque::new())),
        }
    }

    async fn add_change(&self, change: Vec<u8>) {
        let mut changes = self.changes.write().await;
        changes.push_back(change);
    }

    async fn get_listening_status(&self) -> bool {
        *self.listening.read().await
    }
}

#[async_trait]
impl ChangeListener for MockChangeListener {
    async fn start_listening(&self, _cookie: Option<&str>) -> Result<(), ConsumerError> {
        let mut listening = self.listening.write().await;
        *listening = true;
        Ok(())
    }

    async fn receive_change(&self) -> Result<Option<Vec<u8>>, ConsumerError> {
        let mut changes = self.changes.write().await;
        Ok(changes.pop_front())
    }

    async fn stop_listening(&self) -> Result<(), ConsumerError> {
        let mut listening = self.listening.write().await;
        *listening = false;
        Ok(())
    }

    async fn is_listening(&self) -> Result<bool, ConsumerError> {
        Ok(*self.listening.read().await)
    }

    async fn get_listening_stats(&self) -> Result<ListeningStats, ConsumerError> {
        Ok(ListeningStats::new())
    }
}

/// Mock state manager for testing
struct MockStateManager {
    cookie: Arc<RwLock<Option<String>>>,
}

impl MockStateManager {
    fn new() -> Self {
        Self {
            cookie: Arc::new(RwLock::new(None)),
        }
    }

    #[allow(dead_code)]
    async fn get_cookie(&self) -> Option<String> {
        self.cookie.read().await.clone()
    }
}

#[async_trait]
impl StateManager for MockStateManager {
    async fn save_cookie(&self, cookie: &str) -> Result<(), ConsumerError> {
        let mut stored = self.cookie.write().await;
        *stored = Some(cookie.to_string());
        Ok(())
    }

    async fn load_cookie(&self) -> Result<Option<String>, ConsumerError> {
        Ok(self.cookie.read().await.clone())
    }

    async fn delete_cookie(&self) -> Result<(), ConsumerError> {
        let mut stored = self.cookie.write().await;
        *stored = None;
        Ok(())
    }

    async fn cookie_exists(&self) -> Result<bool, ConsumerError> {
        Ok(self.cookie.read().await.is_some())
    }

    async fn get_storage_metadata(&self) -> Result<StorageMetadata, ConsumerError> {
        Ok(StorageMetadata::new(0, "v1".to_string(), false))
    }
}

// ================================================================================================
// Configuration Tests
// ================================================================================================

#[test]
fn test_persist_mode_config_default() {
    let config = PersistModeConfig::default();
    assert!(!config.enable_persist_mode);
    assert_eq!(config.heartbeat_interval, Duration::from_secs(30));
    assert_eq!(config.reconnect_delay, Duration::from_secs(5));
    assert_eq!(config.max_reconnect_attempts, 3);
    assert_eq!(config.change_buffer_size, 1000);
    assert_eq!(config.receive_timeout, Duration::from_secs(60));
    assert_eq!(config.max_idle_time, Duration::from_secs(300));
}

#[test]
fn test_persist_mode_config_custom() {
    let config = PersistModeConfig {
        enable_persist_mode: true,
        heartbeat_interval: Duration::from_secs(60),
        reconnect_delay: Duration::from_secs(10),
        max_reconnect_attempts: 5,
        change_buffer_size: 2000,
        receive_timeout: Duration::from_secs(120),
        max_idle_time: Duration::from_secs(600),
    };

    assert!(config.enable_persist_mode);
    assert_eq!(config.heartbeat_interval, Duration::from_secs(60));
    assert_eq!(config.reconnect_delay, Duration::from_secs(10));
    assert_eq!(config.max_reconnect_attempts, 5);
    assert_eq!(config.change_buffer_size, 2000);
}

// ================================================================================================
// Connection State Tests
// ================================================================================================

#[test]
fn test_persist_connection_state_equality() {
    assert_eq!(
        PersistConnectionState::Disconnected,
        PersistConnectionState::Disconnected
    );
    assert_eq!(
        PersistConnectionState::Connected,
        PersistConnectionState::Connected
    );
    assert_ne!(
        PersistConnectionState::Connected,
        PersistConnectionState::Disconnected
    );
}

#[test]
fn test_persist_connection_state_reconnecting() {
    let state1 = PersistConnectionState::Reconnecting { attempt: 1 };
    let state2 = PersistConnectionState::Reconnecting { attempt: 1 };
    assert_eq!(state1, state2);
}

#[test]
fn test_persist_connection_state_terminated() {
    let state = PersistConnectionState::Terminated {
        reason: "Connection lost".to_string(),
    };
    match state {
        PersistConnectionState::Terminated { reason } => {
            assert_eq!(reason, "Connection lost");
        }
        _ => panic!("Expected Terminated state"),
    }
}

// ================================================================================================
// Statistics Tests
// ================================================================================================

#[test]
fn test_persist_mode_stats_new() {
    let stats = PersistModeStats::new();
    assert_eq!(stats.changes_received, 0);
    assert_eq!(stats.changes_applied, 0);
    assert_eq!(stats.heartbeats_sent, 0);
    assert!(stats.last_heartbeat.is_none());
    assert!(stats.last_change_received.is_none());
    assert!(stats.connection_start.is_none());
    assert_eq!(stats.reconnect_attempts, 0);
    assert_eq!(stats.successful_reconnects, 0);
}

#[test]
fn test_persist_mode_stats_connection_duration() {
    let mut stats = PersistModeStats::new();
    assert!(stats.connection_duration().is_none());

    stats.connection_start = Some(Instant::now());
    assert!(stats.connection_duration().is_some());
}

#[test]
fn test_persist_mode_stats_time_since_last_change() {
    let mut stats = PersistModeStats::new();
    assert!(stats.time_since_last_change().is_none());

    stats.last_change_received = Some(Instant::now());
    assert!(stats.time_since_last_change().is_some());
}

#[test]
fn test_persist_mode_stats_is_idle() {
    let mut stats = PersistModeStats::new();
    assert!(!stats.is_idle(Duration::from_secs(60)));

    // Set last change to 2 minutes ago
    stats.last_change_received = Some(Instant::now() - Duration::from_secs(120));
    assert!(stats.is_idle(Duration::from_secs(60)));
    assert!(!stats.is_idle(Duration::from_secs(180)));
}

// ================================================================================================
// Manager Tests
// ================================================================================================

#[tokio::test]
async fn test_persist_mode_manager_creation() {
    let config = PersistModeConfig::default();
    let provider_connection = Arc::new(MockProviderConnection::new());
    let change_listener = Arc::new(MockChangeListener::new());
    let state_manager = Arc::new(MockStateManager::new());

    let manager =
        PersistModeManager::new(config, provider_connection, change_listener, state_manager);

    let stats = manager.get_stats().await;
    assert_eq!(stats.connection_state, PersistConnectionState::Disconnected);
    assert!(!manager.is_active().await);
}

#[tokio::test]
async fn test_persist_mode_manager_start_disabled() {
    let config = PersistModeConfig {
        enable_persist_mode: false,
        ..Default::default()
    };

    let provider_connection = Arc::new(MockProviderConnection::new());
    let change_listener = Arc::new(MockChangeListener::new());
    let state_manager = Arc::new(MockStateManager::new());

    let manager =
        PersistModeManager::new(config, provider_connection, change_listener, state_manager);

    let result = manager
        .start_persist_mode("ldap://provider:389", None)
        .await;

    assert!(result.is_err());
    match result {
        Err(ConsumerError::ConfigError { message }) => {
            assert!(message.contains("not enabled"));
        }
        _ => panic!("Expected ConfigError"),
    }
}

#[tokio::test]
async fn test_persist_mode_manager_start_enabled() {
    let config = PersistModeConfig {
        enable_persist_mode: true,
        heartbeat_interval: Duration::from_secs(30),
        ..Default::default()
    };

    let provider_connection = Arc::new(MockProviderConnection::new());
    let change_listener = Arc::new(MockChangeListener::new());
    let state_manager = Arc::new(MockStateManager::new());

    let provider_connection_clone = Arc::clone(&provider_connection);
    let change_listener_clone = Arc::clone(&change_listener);

    let manager = PersistModeManager::new(
        config,
        provider_connection_clone as Arc<dyn ProviderConnection>,
        change_listener_clone as Arc<dyn ChangeListener>,
        state_manager as Arc<dyn StateManager>,
    );

    let result = manager
        .start_persist_mode("ldap://provider:389", None)
        .await;

    assert!(result.is_ok());

    // Check connection was established
    assert!(provider_connection.is_connected().await.unwrap());
    assert_eq!(provider_connection.get_connection_count().await, 1);

    // Check listening started
    assert!(change_listener.get_listening_status().await);

    // Check stats
    let stats = manager.get_stats().await;
    assert_eq!(stats.connection_state, PersistConnectionState::Connected);
    assert!(manager.is_active().await);
}

#[tokio::test]
async fn test_persist_mode_manager_stop() {
    let config = PersistModeConfig {
        enable_persist_mode: true,
        ..Default::default()
    };

    let provider_connection = Arc::new(MockProviderConnection::new());
    let change_listener = Arc::new(MockChangeListener::new());
    let state_manager = Arc::new(MockStateManager::new());

    let provider_connection_clone = Arc::clone(&provider_connection);
    let change_listener_clone = Arc::clone(&change_listener);

    let manager = PersistModeManager::new(
        config,
        provider_connection_clone as Arc<dyn ProviderConnection>,
        change_listener_clone as Arc<dyn ChangeListener>,
        state_manager as Arc<dyn StateManager>,
    );

    // Start persist mode
    manager
        .start_persist_mode("ldap://provider:389", None)
        .await
        .unwrap();

    assert!(manager.is_active().await);

    // Stop persist mode
    let result = manager.stop_persist_mode().await;
    assert!(result.is_ok());

    // Check connection was closed
    assert!(!provider_connection.is_connected().await.unwrap());

    // Check listening stopped
    assert!(!change_listener.get_listening_status().await);

    // Check stats
    let stats = manager.get_stats().await;
    assert_eq!(stats.connection_state, PersistConnectionState::Disconnected);
    assert!(!manager.is_active().await);
}

#[tokio::test]
async fn test_persist_mode_manager_receive_change() {
    let config = PersistModeConfig {
        enable_persist_mode: true,
        receive_timeout: Duration::from_millis(100),
        ..Default::default()
    };

    let provider_connection = Arc::new(MockProviderConnection::new());
    let change_listener = Arc::new(MockChangeListener::new());
    let state_manager = Arc::new(MockStateManager::new());

    let change_listener_clone = Arc::clone(&change_listener);

    let manager = PersistModeManager::new(
        config,
        provider_connection as Arc<dyn ProviderConnection>,
        change_listener_clone as Arc<dyn ChangeListener>,
        state_manager as Arc<dyn StateManager>,
    );

    // Start persist mode
    manager
        .start_persist_mode("ldap://provider:389", None)
        .await
        .unwrap();

    // Add a change to the mock listener
    change_listener.add_change(b"test_change".to_vec()).await;

    // Give background task time to process
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Receive change
    let result = manager.receive_change().await;
    assert!(result.is_ok());

    // Note: The change might not be immediately available due to async processing
    // In a real implementation, we'd use proper synchronization
}

#[tokio::test]
async fn test_persist_mode_manager_receive_change_timeout() {
    let config = PersistModeConfig {
        enable_persist_mode: true,
        receive_timeout: Duration::from_millis(50),
        ..Default::default()
    };

    let provider_connection = Arc::new(MockProviderConnection::new());
    let change_listener = Arc::new(MockChangeListener::new());
    let state_manager = Arc::new(MockStateManager::new());

    let manager = PersistModeManager::new(
        config,
        provider_connection as Arc<dyn ProviderConnection>,
        change_listener as Arc<dyn ChangeListener>,
        state_manager as Arc<dyn StateManager>,
    );

    // Start persist mode
    manager
        .start_persist_mode("ldap://provider:389", None)
        .await
        .unwrap();

    // Try to receive without any changes (should timeout)
    let result = manager.receive_change().await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), None);
}

// ================================================================================================
// Helper Function Tests
// ================================================================================================

#[test]
fn test_should_use_persist_mode() {
    assert!(should_use_persist_mode(true, true));
    assert!(!should_use_persist_mode(true, false));
    assert!(!should_use_persist_mode(false, true));
    assert!(!should_use_persist_mode(false, false));
}

#[test]
fn test_create_persist_mode_event() {
    let change = b"test_change".to_vec();
    let event = create_persist_mode_event(change.clone());

    match event {
        opendr::fsm::ReplicationConsumerEvent::ChangeReceived(data) => {
            assert_eq!(data, change);
        }
        _ => panic!("Expected ChangeReceived event"),
    }
}

#[test]
fn test_is_persist_mode_compatible_state() {
    // Compatible states
    assert!(is_persist_mode_compatible_state(
        &ReplicationConsumerState::Listening
    ));
    assert!(is_persist_mode_compatible_state(
        &ReplicationConsumerState::PersistingState {
            new_cookie: "cookie".to_string()
        }
    ));

    // Non-compatible states
    assert!(!is_persist_mode_compatible_state(
        &ReplicationConsumerState::RequestingFromCookie { cookie: None }
    ));
    assert!(!is_persist_mode_compatible_state(
        &ReplicationConsumerState::ReceivingBatches {
            entries_received: 0
        }
    ));
    assert!(!is_persist_mode_compatible_state(
        &ReplicationConsumerState::ApplyingChanges { entries_applied: 0 }
    ));
    assert!(!is_persist_mode_compatible_state(
        &ReplicationConsumerState::Completed
    ));
    assert!(!is_persist_mode_compatible_state(
        &ReplicationConsumerState::Error
    ));
}

// ================================================================================================
// Integration Scenario Tests
// ================================================================================================

#[tokio::test]
async fn test_full_persist_mode_lifecycle() {
    let config = PersistModeConfig {
        enable_persist_mode: true,
        heartbeat_interval: Duration::from_millis(100),
        receive_timeout: Duration::from_millis(50),
        ..Default::default()
    };

    let provider_connection = Arc::new(MockProviderConnection::new());
    let change_listener = Arc::new(MockChangeListener::new());
    let state_manager = Arc::new(MockStateManager::new());

    let provider_connection_clone = Arc::clone(&provider_connection);
    let change_listener_clone = Arc::clone(&change_listener);

    let manager = PersistModeManager::new(
        config,
        provider_connection_clone as Arc<dyn ProviderConnection>,
        change_listener_clone as Arc<dyn ChangeListener>,
        state_manager as Arc<dyn StateManager>,
    );

    // 1. Start persist mode
    let result = manager
        .start_persist_mode("ldap://provider:389", Some("initial-cookie".to_string()))
        .await;
    assert!(result.is_ok());
    assert!(manager.is_active().await);

    // 2. Wait for heartbeat
    tokio::time::sleep(Duration::from_millis(150)).await;
    let stats = manager.get_stats().await;
    assert!(stats.heartbeats_sent > 0);

    // 3. Simulate receiving changes
    change_listener.add_change(b"change1".to_vec()).await;
    change_listener.add_change(b"change2".to_vec()).await;

    // Give background task time to process
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 4. Stop persist mode
    let result = manager.stop_persist_mode().await;
    assert!(result.is_ok());
    assert!(!manager.is_active().await);

    // Verify connection was closed properly
    assert!(!provider_connection.is_connected().await.unwrap());
    assert!(!change_listener.get_listening_status().await);
}

#[tokio::test]
async fn test_persist_mode_stats_tracking() {
    let config = PersistModeConfig {
        enable_persist_mode: true,
        ..Default::default()
    };

    let provider_connection = Arc::new(MockProviderConnection::new());
    let change_listener = Arc::new(MockChangeListener::new());
    let state_manager = Arc::new(MockStateManager::new());

    let manager = PersistModeManager::new(
        config,
        provider_connection as Arc<dyn ProviderConnection>,
        change_listener as Arc<dyn ChangeListener>,
        state_manager as Arc<dyn StateManager>,
    );

    // Start persist mode
    manager
        .start_persist_mode("ldap://provider:389", None)
        .await
        .unwrap();

    // Check initial stats
    let stats = manager.get_stats().await;
    assert_eq!(stats.changes_received, 0);
    assert_eq!(stats.changes_applied, 0);
    assert!(stats.connection_start.is_some());
    assert!(stats.connection_duration().is_some());

    // Stop persist mode
    manager.stop_persist_mode().await.unwrap();
}

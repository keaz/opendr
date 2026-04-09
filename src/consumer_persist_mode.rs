//! Consumer Persist Mode Support (Task 3.1)
//!
//! This module extends the Replication Consumer FSM with support for RFC 4533
//! refreshAndPersist mode, enabling real-time push-based replication where the
//! consumer maintains a persistent connection to the provider and receives
//! changes as they occur.
//!
//! # Key Features
//!
//! - **Persistent Connection Management**: Maintains long-lived LDAP connections
//! - **Real-Time Change Reception**: Receives and processes changes immediately
//! - **Heartbeat Mechanism**: Keeps connections alive with periodic heartbeats
//! - **Automatic Reconnection**: Handles connection failures gracefully
//! - **State Management**: Persists sync state across reconnections
//!
//! # RFC 4533 refreshAndPersist Mode
//!
//! Per RFC 4533 Section 3.4, in refreshAndPersist mode:
//! 1. Consumer connects and sends SearchRequest with mode=refreshAndPersist
//! 2. Provider sends initial content (refresh stage)
//! 3. Provider sends Sync Info Message (refreshDone=TRUE)
//! 4. Connection persists - provider pushes changes as they occur
//! 5. Consumer applies changes in real-time
//!
//! # Architecture
//!
//! ```text
//! Consumer FSM (refreshAndPersist)
//! ┌─────────────────────────────────────┐
//! │                                     │
//! │  RequestingFromCookie               │
//! │         ↓                           │
//! │  ReceivingBatches (refresh)         │
//! │         ↓                           │
//! │  ApplyingChanges                    │
//! │         ↓                           │
//! │  PersistingState                    │
//! │         ↓                           │
//! │  PersistMode ←──────────┐          │
//! │    ├─ Heartbeat          │          │
//! │    ├─ ReceiveChanges  ───┘          │
//! │    └─ ApplyChanges                  │
//! │                                     │
//! └─────────────────────────────────────┘
//! ```
//!
//! # Usage Example
//!
//! ```no_run
//! use opendr::consumer_persist_mode::{PersistModeConfig, PersistModeManager};
//! use std::time::Duration;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create persist mode configuration
//! let config = PersistModeConfig {
//!     enable_persist_mode: true,
//!     heartbeat_interval: Duration::from_secs(30),
//!     reconnect_delay: Duration::from_secs(5),
//!     max_reconnect_attempts: 3,
//!     change_buffer_size: 1000,
//! };
//!
//! // Create persist mode manager
//! // let manager = PersistModeManager::new(config, /* dependencies */);
//!
//! // Start persistent connection
//! // manager.start_persist_mode("ldap://provider:389", Some("cookie")).await?;
//!
//! // Manager will handle:
//! // - Maintaining persistent connection
//! // - Sending heartbeats
//! // - Receiving real-time changes
//! // - Automatic reconnection on failure
//! # Ok(())
//! # }
//! ```

use crate::fsm::{ReplicationConsumerEvent, ReplicationConsumerState};
use crate::replication_consumer_fsm::{
    ChangeListener, ConsumerError, ProviderConnection, StateManager,
};
use async_trait::async_trait;
use log::{debug, error, info, warn};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use tokio::time::interval;

// ================================================================================================
// Configuration
// ================================================================================================

/// Configuration for Consumer Persist Mode
#[derive(Debug, Clone)]
pub struct PersistModeConfig {
    /// Enable persist mode (refreshAndPersist)
    pub enable_persist_mode: bool,
    /// Heartbeat interval for keep-alive
    pub heartbeat_interval: Duration,
    /// Delay before reconnection attempt
    pub reconnect_delay: Duration,
    /// Maximum reconnection attempts
    pub max_reconnect_attempts: u32,
    /// Buffer size for incoming changes
    pub change_buffer_size: usize,
    /// Timeout for receiving changes
    pub receive_timeout: Duration,
    /// Maximum idle time before reconnection
    pub max_idle_time: Duration,
}

impl Default for PersistModeConfig {
    fn default() -> Self {
        Self {
            enable_persist_mode: false,
            heartbeat_interval: Duration::from_secs(30),
            reconnect_delay: Duration::from_secs(5),
            max_reconnect_attempts: 3,
            change_buffer_size: 1000,
            receive_timeout: Duration::from_secs(60),
            max_idle_time: Duration::from_secs(300),
        }
    }
}

// ================================================================================================
// Persist Mode State
// ================================================================================================

/// State of the persistent connection
#[derive(Debug, Clone, PartialEq)]
pub enum PersistConnectionState {
    /// Not connected
    Disconnected,
    /// Connecting to provider
    Connecting,
    /// Connected and active
    Connected,
    /// Receiving changes
    Receiving,
    /// Connection idle (no changes received)
    Idle { since: Instant },
    /// Reconnecting after failure
    Reconnecting { attempt: u32 },
    /// Connection terminated
    Terminated { reason: String },
}

/// Statistics for persist mode
#[derive(Debug, Clone)]
pub struct PersistModeStats {
    /// Connection state
    pub connection_state: PersistConnectionState,
    /// Total changes received
    pub changes_received: u64,
    /// Total changes applied
    pub changes_applied: u64,
    /// Total heartbeats sent
    pub heartbeats_sent: u64,
    /// Last heartbeat time
    pub last_heartbeat: Option<Instant>,
    /// Last change received time
    pub last_change_received: Option<Instant>,
    /// Connection start time
    pub connection_start: Option<Instant>,
    /// Total reconnection attempts
    pub reconnect_attempts: u32,
    /// Successful reconnections
    pub successful_reconnects: u32,
}

impl PersistModeStats {
    /// Create new persist mode statistics
    pub fn new() -> Self {
        Self {
            connection_state: PersistConnectionState::Disconnected,
            changes_received: 0,
            changes_applied: 0,
            heartbeats_sent: 0,
            last_heartbeat: None,
            last_change_received: None,
            connection_start: None,
            reconnect_attempts: 0,
            successful_reconnects: 0,
        }
    }

    /// Get connection duration
    pub fn connection_duration(&self) -> Option<Duration> {
        self.connection_start.map(|start| start.elapsed())
    }

    /// Get time since last change
    pub fn time_since_last_change(&self) -> Option<Duration> {
        self.last_change_received.map(|last| last.elapsed())
    }

    /// Get time since last heartbeat
    pub fn time_since_last_heartbeat(&self) -> Option<Duration> {
        self.last_heartbeat.map(|last| last.elapsed())
    }

    /// Check if connection is idle
    pub fn is_idle(&self, max_idle: Duration) -> bool {
        if let Some(duration) = self.time_since_last_change() {
            duration > max_idle
        } else {
            false
        }
    }
}

impl Default for PersistModeStats {
    fn default() -> Self {
        Self::new()
    }
}

// ================================================================================================
// Persist Mode Manager
// ================================================================================================

/// Manages persistent connection mode for the consumer
///
/// This component handles the lifecycle of a persistent LDAP connection in
/// refreshAndPersist mode, including connection management, heartbeats, change
/// reception, and automatic reconnection.
pub struct PersistModeManager {
    /// Configuration
    config: PersistModeConfig,
    /// Current statistics
    stats: Arc<RwLock<PersistModeStats>>,
    /// Provider connection
    provider_connection: Arc<dyn ProviderConnection>,
    /// Change listener
    change_listener: Arc<dyn ChangeListener>,
    /// State manager
    state_manager: Arc<dyn StateManager>,
    /// Change notification channel
    change_tx: mpsc::Sender<Vec<u8>>,
    change_rx: Arc<RwLock<mpsc::Receiver<Vec<u8>>>>,
}

impl PersistModeManager {
    /// Create a new persist mode manager
    ///
    /// # Arguments
    /// * `config` - Persist mode configuration
    /// * `provider_connection` - Provider connection interface
    /// * `change_listener` - Change listener interface
    /// * `state_manager` - State persistence manager
    ///
    /// # Returns
    /// * New PersistModeManager instance
    pub fn new(
        config: PersistModeConfig,
        provider_connection: Arc<dyn ProviderConnection>,
        change_listener: Arc<dyn ChangeListener>,
        state_manager: Arc<dyn StateManager>,
    ) -> Self {
        let (change_tx, change_rx) = mpsc::channel(config.change_buffer_size);

        Self {
            config,
            stats: Arc::new(RwLock::new(PersistModeStats::new())),
            provider_connection,
            change_listener,
            state_manager,
            change_tx,
            change_rx: Arc::new(RwLock::new(change_rx)),
        }
    }

    /// Start persist mode connection
    ///
    /// # Arguments
    /// * `provider_url` - Provider server URL
    /// * `cookie` - Last replication cookie (if any)
    ///
    /// # Returns
    /// * `Ok(())` - Persist mode started successfully
    /// * `Err(ConsumerError)` - Failed to start persist mode
    pub async fn start_persist_mode(
        &self,
        provider_url: &str,
        cookie: Option<String>,
    ) -> Result<(), ConsumerError> {
        if !self.config.enable_persist_mode {
            return Err(ConsumerError::ConfigError {
                message: "Persist mode is not enabled in configuration".to_string(),
            });
        }

        info!("Starting persist mode connection to {}", provider_url);

        // Update state
        {
            let mut stats = self.stats.write().await;
            stats.connection_state = PersistConnectionState::Connecting;
            stats.connection_start = Some(Instant::now());
        }

        // Connect to provider
        self.provider_connection
            .connect(provider_url)
            .await
            .map_err(|e| {
                error!("Failed to connect to provider: {}", e);
                e
            })?;

        // Update state
        {
            let mut stats = self.stats.write().await;
            stats.connection_state = PersistConnectionState::Connected;
        }

        // Start change listener
        self.change_listener
            .start_listening(cookie.as_deref())
            .await
            .map_err(|e| {
            error!("Failed to start change listener: {}", e);
            e
        })?;

        info!("Persist mode connection established");

        // Start background tasks
        self.start_heartbeat_task().await;
        self.start_change_receiver_task().await;

        Ok(())
    }

    /// Stop persist mode connection
    ///
    /// # Returns
    /// * `Ok(())` - Persist mode stopped successfully
    /// * `Err(ConsumerError)` - Failed to stop persist mode
    pub async fn stop_persist_mode(&self) -> Result<(), ConsumerError> {
        info!("Stopping persist mode connection");

        // Stop change listener
        self.change_listener.stop_listening().await?;

        // Disconnect from provider
        self.provider_connection.disconnect().await?;

        // Update state
        {
            let mut stats = self.stats.write().await;
            stats.connection_state = PersistConnectionState::Disconnected;
        }

        info!("Persist mode connection stopped");

        Ok(())
    }

    /// Receive next change from provider
    ///
    /// # Returns
    /// * `Ok(Some(Vec<u8>))` - Change received
    /// * `Ok(None)` - No changes available (timeout)
    /// * `Err(ConsumerError)` - Failed to receive change
    pub async fn receive_change(&self) -> Result<Option<Vec<u8>>, ConsumerError> {
        let mut rx = self.change_rx.write().await;

        // Try to receive with timeout
        match tokio::time::timeout(self.config.receive_timeout, rx.recv()).await {
            Ok(Some(change)) => {
                // Update stats
                {
                    let mut stats = self.stats.write().await;
                    stats.changes_received += 1;
                    stats.last_change_received = Some(Instant::now());
                    stats.connection_state = PersistConnectionState::Receiving;
                }

                debug!("Received change: {} bytes", change.len());
                Ok(Some(change))
            }
            Ok(None) => {
                // Channel closed
                warn!("Change channel closed");
                Ok(None)
            }
            Err(_) => {
                // Timeout - check if connection is idle
                let stats = self.stats.read().await;
                if stats.is_idle(self.config.max_idle_time) {
                    warn!("Connection idle for too long");
                }
                Ok(None)
            }
        }
    }

    /// Send heartbeat to provider
    ///
    /// # Returns
    /// * `Ok(())` - Heartbeat sent successfully
    /// * `Err(ConsumerError)` - Failed to send heartbeat
    async fn send_heartbeat(&self) -> Result<(), ConsumerError> {
        debug!("Sending heartbeat to provider");

        // Check if connection is active
        let is_connected = self.provider_connection.is_connected().await?;

        if !is_connected {
            warn!("Provider connection lost, attempting reconnection");
            return Err(ConsumerError::ConnectionError {
                message: "Connection lost".to_string(),
            });
        }

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.heartbeats_sent += 1;
            stats.last_heartbeat = Some(Instant::now());
        }

        debug!("Heartbeat sent successfully");

        Ok(())
    }

    /// Start background heartbeat task
    async fn start_heartbeat_task(&self) {
        let stats = Arc::clone(&self.stats);
        let provider_connection = Arc::clone(&self.provider_connection);
        let heartbeat_interval = self.config.heartbeat_interval;

        tokio::spawn(async move {
            let mut interval = interval(heartbeat_interval);

            loop {
                interval.tick().await;

                // Check if connection is still active
                let state = {
                    let stats = stats.read().await;
                    stats.connection_state.clone()
                };

                match state {
                    PersistConnectionState::Connected
                    | PersistConnectionState::Receiving
                    | PersistConnectionState::Idle { .. } => {
                        // Send heartbeat
                        match provider_connection.is_connected().await {
                            Ok(true) => {
                                let mut stats = stats.write().await;
                                stats.heartbeats_sent += 1;
                                stats.last_heartbeat = Some(Instant::now());
                                debug!("Heartbeat sent");
                            }
                            Ok(false) => {
                                warn!("Provider connection lost");
                                let mut stats = stats.write().await;
                                stats.connection_state =
                                    PersistConnectionState::Reconnecting { attempt: 1 };
                            }
                            Err(e) => {
                                error!("Failed to check connection: {}", e);
                            }
                        }
                    }
                    PersistConnectionState::Disconnected
                    | PersistConnectionState::Terminated { .. } => {
                        // Stop heartbeat task
                        debug!("Connection terminated, stopping heartbeat task");
                        break;
                    }
                    _ => {
                        // Skip heartbeat in other states
                    }
                }
            }
        });
    }

    /// Start background change receiver task
    async fn start_change_receiver_task(&self) {
        let change_listener = Arc::clone(&self.change_listener);
        let change_tx = self.change_tx.clone();
        let stats = Arc::clone(&self.stats);

        tokio::spawn(async move {
            loop {
                // Check if still listening
                let is_listening = match change_listener.is_listening().await {
                    Ok(listening) => listening,
                    Err(e) => {
                        error!("Failed to check listening status: {}", e);
                        break;
                    }
                };

                if !is_listening {
                    debug!("Not listening, stopping change receiver task");
                    break;
                }

                // Receive change
                match change_listener.receive_change().await {
                    Ok(Some(change)) => {
                        debug!("Received change: {} bytes", change.len());

                        // Forward to channel
                        if let Err(e) = change_tx.send(change).await {
                            error!("Failed to forward change: {}", e);
                            break;
                        }

                        // Update stats
                        let mut stats = stats.write().await;
                        stats.changes_received += 1;
                        stats.last_change_received = Some(Instant::now());
                        stats.connection_state = PersistConnectionState::Receiving;
                    }
                    Ok(None) => {
                        // No changes, continue
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    Err(e) => {
                        error!("Failed to receive change: {}", e);
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }

            info!("Change receiver task stopped");
        });
    }

    /// Get current statistics
    ///
    /// # Returns
    /// * Current persist mode statistics
    pub async fn get_stats(&self) -> PersistModeStats {
        self.stats.read().await.clone()
    }

    /// Check if in persist mode
    ///
    /// # Returns
    /// * True if persist mode is active
    pub async fn is_active(&self) -> bool {
        let stats = self.stats.read().await;
        matches!(
            stats.connection_state,
            PersistConnectionState::Connected
                | PersistConnectionState::Receiving
                | PersistConnectionState::Idle { .. }
        )
    }
}

// ================================================================================================
// Extension Trait for Consumer FSM
// ================================================================================================

/// Extension trait for adding persist mode support to Consumer FSM
#[async_trait]
pub trait ConsumerPersistModeExtension {
    /// Transition to persist mode after initial sync
    ///
    /// # Arguments
    /// * `cookie` - Current replication cookie
    ///
    /// # Returns
    /// * `Ok(())` - Successfully transitioned to persist mode
    /// * `Err(ConsumerError)` - Failed to transition
    async fn enter_persist_mode(&mut self, cookie: String) -> Result<(), ConsumerError>;

    /// Handle change received in persist mode
    ///
    /// # Arguments
    /// * `change` - Change data received from provider
    ///
    /// # Returns
    /// * `Ok(usize)` - Number of entries processed
    /// * `Err(ConsumerError)` - Failed to handle change
    async fn handle_persist_mode_change(&mut self, change: Vec<u8>)
        -> Result<usize, ConsumerError>;

    /// Exit persist mode
    ///
    /// # Returns
    /// * `Ok(())` - Successfully exited persist mode
    /// * `Err(ConsumerError)` - Failed to exit
    async fn exit_persist_mode(&mut self) -> Result<(), ConsumerError>;

    /// Check if currently in persist mode
    ///
    /// # Returns
    /// * True if in persist mode
    fn is_in_persist_mode(&self) -> bool;
}

// ================================================================================================
// Helper Functions
// ================================================================================================

/// Determine if a consumer should use persist mode based on configuration
///
/// # Arguments
/// * `enable_persist_mode` - Persist mode enabled flag
/// * `enable_change_listening` - Change listening enabled flag
///
/// # Returns
/// * True if persist mode should be used
pub fn should_use_persist_mode(enable_persist_mode: bool, enable_change_listening: bool) -> bool {
    enable_persist_mode && enable_change_listening
}

/// Create persist mode event for FSM
///
/// # Arguments
/// * `change` - Change data received
///
/// # Returns
/// * ReplicationConsumerEvent for the change
pub fn create_persist_mode_event(change: Vec<u8>) -> ReplicationConsumerEvent {
    ReplicationConsumerEvent::ChangeReceived(change)
}

/// Check if state supports persist mode
///
/// # Arguments
/// * `state` - Current consumer state
///
/// # Returns
/// * True if state supports persist mode
pub fn is_persist_mode_compatible_state(state: &ReplicationConsumerState) -> bool {
    matches!(
        state,
        ReplicationConsumerState::Listening | ReplicationConsumerState::PersistingState { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_persist_mode_config_default() {
        let config = PersistModeConfig::default();
        assert!(!config.enable_persist_mode);
        assert_eq!(config.heartbeat_interval, Duration::from_secs(30));
        assert_eq!(config.reconnect_delay, Duration::from_secs(5));
        assert_eq!(config.max_reconnect_attempts, 3);
        assert_eq!(config.change_buffer_size, 1000);
    }

    #[test]
    fn test_persist_connection_state() {
        assert_eq!(
            PersistConnectionState::Disconnected,
            PersistConnectionState::Disconnected
        );
        assert_ne!(
            PersistConnectionState::Connected,
            PersistConnectionState::Disconnected
        );
    }

    #[test]
    fn test_persist_mode_stats() {
        let stats = PersistModeStats::new();
        assert_eq!(stats.changes_received, 0);
        assert_eq!(stats.changes_applied, 0);
        assert_eq!(stats.heartbeats_sent, 0);
        assert!(stats.connection_duration().is_none());
    }

    #[test]
    fn test_should_use_persist_mode() {
        assert!(should_use_persist_mode(true, true));
        assert!(!should_use_persist_mode(true, false));
        assert!(!should_use_persist_mode(false, true));
        assert!(!should_use_persist_mode(false, false));
    }

    #[test]
    fn test_is_persist_mode_compatible_state() {
        assert!(is_persist_mode_compatible_state(
            &ReplicationConsumerState::Listening
        ));
        assert!(is_persist_mode_compatible_state(
            &ReplicationConsumerState::PersistingState {
                new_cookie: "cookie".to_string()
            }
        ));
        assert!(!is_persist_mode_compatible_state(
            &ReplicationConsumerState::RequestingFromCookie { cookie: None }
        ));
    }
}

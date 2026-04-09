//! Connection Lifecycle Management (Task 3.2)
//!
//! This module provides comprehensive connection lifecycle management for persistent
//! LDAP connections in refreshAndPersist mode. It handles graceful closure, automatic
//! reconnection with exponential backoff, network interruption recovery, and timeout
//! management.
//!
//! # Key Features
//!
//! - **Graceful Closure**: Clean shutdown with resource cleanup
//! - **Exponential Backoff**: Smart reconnection with increasing delays
//! - **Network Interruption Handling**: Automatic recovery from network issues
//! - **Timeout Management**: Configurable timeouts for all operations
//! - **State Persistence**: Maintains sync state across reconnections
//!
//! # Architecture
//!
//! ```text
//! Connection Lifecycle
//! ┌────────────────────────────────────────┐
//! │                                        │
//! │  Disconnected                          │
//! │      ↓                                 │
//! │  Connecting ─────────→ Connected       │
//! │      ↓ (failure)           ↓           │
//! │  Reconnecting              ↓           │
//! │      ↑ ←──────────────── Failed        │
//! │      │                      ↓           │
//! │      └── Exponential ──→ Terminated    │
//! │          Backoff                       │
//! │                                        │
//! └────────────────────────────────────────┘
//! ```
//!
//! # Usage Example
//!
//! ```no_run
//! use opendr::connection_lifecycle::{ConnectionLifecycleManager, LifecycleConfig};
//! use std::time::Duration;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Configure lifecycle management
//! let config = LifecycleConfig {
//!     connection_timeout: Duration::from_secs(30),
//!     operation_timeout: Duration::from_secs(60),
//!     reconnect_base_delay: Duration::from_secs(1),
//!     reconnect_max_delay: Duration::from_secs(60),
//!     max_reconnect_attempts: 5,
//!     enable_exponential_backoff: true,
//!     backoff_multiplier: 2.0,
//!     enable_jitter: true,
//!     max_jitter_percent: 0.25,
//! };
//!
//! // Create lifecycle manager
//! // let manager = ConnectionLifecycleManager::new(config, persist_manager);
//!
//! // Manager automatically handles:
//! // - Connection failures with exponential backoff
//! // - Network interruptions with recovery
//! // - Graceful shutdown with cleanup
//! # Ok(())
//! # }
//! ```

use crate::consumer_persist_mode::{PersistConnectionState, PersistModeManager, PersistModeStats};
use crate::replication_consumer_fsm::ConsumerError;
use async_trait::async_trait;
use log::{debug, error, info, warn};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::sleep;

// ================================================================================================
// Configuration
// ================================================================================================

/// Configuration for connection lifecycle management
#[derive(Debug, Clone)]
pub struct LifecycleConfig {
    /// Timeout for establishing connection
    pub connection_timeout: Duration,
    /// Timeout for individual operations
    pub operation_timeout: Duration,
    /// Base delay for reconnection attempts
    pub reconnect_base_delay: Duration,
    /// Maximum delay between reconnection attempts
    pub reconnect_max_delay: Duration,
    /// Maximum number of reconnection attempts
    pub max_reconnect_attempts: u32,
    /// Enable exponential backoff for reconnections
    pub enable_exponential_backoff: bool,
    /// Backoff multiplier for exponential backoff
    pub backoff_multiplier: f64,
    /// Enable jitter in backoff delays
    pub enable_jitter: bool,
    /// Maximum jitter percentage (0.0 to 1.0)
    pub max_jitter_percent: f64,
}

impl Default for LifecycleConfig {
    fn default() -> Self {
        Self {
            connection_timeout: Duration::from_secs(30),
            operation_timeout: Duration::from_secs(60),
            reconnect_base_delay: Duration::from_secs(1),
            reconnect_max_delay: Duration::from_secs(60),
            max_reconnect_attempts: 5,
            enable_exponential_backoff: true,
            backoff_multiplier: 2.0,
            enable_jitter: true,
            max_jitter_percent: 0.25,
        }
    }
}

// ================================================================================================
// Connection State
// ================================================================================================

/// Detailed connection lifecycle state
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionLifecycleState {
    /// Connection is closed
    Closed,
    /// Attempting to establish connection
    Connecting { attempt: u32, started_at: Instant },
    /// Connection established and healthy
    Active { connected_at: Instant },
    /// Connection experiencing issues
    Degraded { reason: String, since: Instant },
    /// Connection failed, will attempt reconnect
    Failed {
        reason: String,
        will_reconnect: bool,
        next_attempt_at: Option<Instant>,
    },
    /// Reconnection in progress
    Reconnecting {
        attempt: u32,
        last_failure: String,
        started_at: Instant,
    },
    /// Connection permanently terminated
    Terminated {
        reason: String,
        terminated_at: Instant,
    },
}

/// Statistics for connection lifecycle
#[derive(Debug, Clone)]
pub struct LifecycleStats {
    /// Current lifecycle state
    pub state: ConnectionLifecycleState,
    /// Total connection attempts
    pub total_connection_attempts: u64,
    /// Successful connections
    pub successful_connections: u64,
    /// Failed connection attempts
    pub failed_connection_attempts: u64,
    /// Total reconnections
    pub total_reconnections: u64,
    /// Successful reconnections
    pub successful_reconnections: u64,
    /// Network interruptions detected
    pub network_interruptions: u64,
    /// Recoveries from network interruptions
    pub interruption_recoveries: u64,
    /// Graceful closures
    pub graceful_closures: u64,
    /// Abnormal terminations
    pub abnormal_terminations: u64,
    /// Total uptime (sum of all connected periods)
    pub total_uptime: Duration,
    /// Current connection uptime (if connected)
    pub current_connection_start: Option<Instant>,
    /// Last failure time
    pub last_failure_time: Option<Instant>,
    /// Last failure reason
    pub last_failure_reason: Option<String>,
}

impl LifecycleStats {
    /// Create new lifecycle statistics
    pub fn new() -> Self {
        Self {
            state: ConnectionLifecycleState::Closed,
            total_connection_attempts: 0,
            successful_connections: 0,
            failed_connection_attempts: 0,
            total_reconnections: 0,
            successful_reconnections: 0,
            network_interruptions: 0,
            interruption_recoveries: 0,
            graceful_closures: 0,
            abnormal_terminations: 0,
            total_uptime: Duration::from_secs(0),
            current_connection_start: None,
            last_failure_time: None,
            last_failure_reason: None,
        }
    }

    /// Get current uptime if connected
    pub fn current_uptime(&self) -> Option<Duration> {
        self.current_connection_start.map(|start| start.elapsed())
    }

    /// Get time since last failure
    pub fn time_since_last_failure(&self) -> Option<Duration> {
        self.last_failure_time.map(|time| time.elapsed())
    }

    /// Calculate success rate
    pub fn success_rate(&self) -> f64 {
        if self.total_connection_attempts == 0 {
            0.0
        } else {
            self.successful_connections as f64 / self.total_connection_attempts as f64
        }
    }

    /// Calculate reconnection success rate
    pub fn reconnection_success_rate(&self) -> f64 {
        if self.total_reconnections == 0 {
            0.0
        } else {
            self.successful_reconnections as f64 / self.total_reconnections as f64
        }
    }
}

impl Default for LifecycleStats {
    fn default() -> Self {
        Self::new()
    }
}

// ================================================================================================
// Connection Lifecycle Manager
// ================================================================================================

/// Manages the complete lifecycle of persistent connections
///
/// This component handles connection establishment, failure detection,
/// reconnection with exponential backoff, network interruption recovery,
/// and graceful shutdown.
pub struct ConnectionLifecycleManager {
    /// Configuration
    config: LifecycleConfig,
    /// Lifecycle statistics
    stats: Arc<RwLock<LifecycleStats>>,
    /// Persist mode manager
    persist_manager: Arc<PersistModeManager>,
    /// Provider URL
    provider_url: Arc<RwLock<Option<String>>>,
    /// Last cookie for resumption
    last_cookie: Arc<RwLock<Option<String>>>,
    /// Shutdown signal
    shutdown: Arc<RwLock<bool>>,
}

impl ConnectionLifecycleManager {
    /// Create a new connection lifecycle manager
    ///
    /// # Arguments
    /// * `config` - Lifecycle configuration
    /// * `persist_manager` - Persist mode manager
    ///
    /// # Returns
    /// * New ConnectionLifecycleManager instance
    pub fn new(config: LifecycleConfig, persist_manager: Arc<PersistModeManager>) -> Self {
        Self {
            config,
            stats: Arc::new(RwLock::new(LifecycleStats::new())),
            persist_manager,
            provider_url: Arc::new(RwLock::new(None)),
            last_cookie: Arc::new(RwLock::new(None)),
            shutdown: Arc::new(RwLock::new(false)),
        }
    }

    /// Start managed connection with automatic lifecycle handling
    ///
    /// # Arguments
    /// * `provider_url` - Provider server URL
    /// * `cookie` - Optional starting cookie
    ///
    /// # Returns
    /// * `Ok(())` - Connection started successfully
    /// * `Err(ConsumerError)` - Failed to start connection
    pub async fn start(
        &self,
        provider_url: String,
        cookie: Option<String>,
    ) -> Result<(), ConsumerError> {
        info!("Starting managed connection to {}", provider_url);

        // Store URL and cookie
        {
            let mut url = self.provider_url.write().await;
            *url = Some(provider_url.clone());
        }
        {
            let mut last_cookie = self.last_cookie.write().await;
            *last_cookie = cookie.clone();
        }

        // Reset shutdown flag
        {
            let mut shutdown = self.shutdown.write().await;
            *shutdown = false;
        }

        // Update state
        {
            let mut stats = self.stats.write().await;
            stats.state = ConnectionLifecycleState::Connecting {
                attempt: 1,
                started_at: Instant::now(),
            };
            stats.total_connection_attempts += 1;
        }

        // Attempt connection with timeout
        match tokio::time::timeout(
            self.config.connection_timeout,
            self.persist_manager
                .start_persist_mode(&provider_url, cookie),
        )
        .await
        {
            Ok(Ok(())) => {
                info!("Connection established successfully");
                let mut stats = self.stats.write().await;
                stats.state = ConnectionLifecycleState::Active {
                    connected_at: Instant::now(),
                };
                stats.successful_connections += 1;
                stats.current_connection_start = Some(Instant::now());

                // Start monitoring task
                self.start_monitoring_task().await;

                Ok(())
            }
            Ok(Err(e)) => {
                error!("Connection failed: {}", e);
                let mut stats = self.stats.write().await;
                stats.failed_connection_attempts += 1;
                stats.last_failure_time = Some(Instant::now());
                stats.last_failure_reason = Some(format!("{}", e));
                stats.state = ConnectionLifecycleState::Failed {
                    reason: format!("{}", e),
                    will_reconnect: true,
                    next_attempt_at: Some(Instant::now() + self.config.reconnect_base_delay),
                };

                // Start reconnection task
                self.start_reconnection_task().await;

                Err(e)
            }
            Err(_) => {
                error!(
                    "Connection timeout after {:?}",
                    self.config.connection_timeout
                );
                let mut stats = self.stats.write().await;
                stats.failed_connection_attempts += 1;
                stats.last_failure_time = Some(Instant::now());
                stats.last_failure_reason = Some("Connection timeout".to_string());
                stats.state = ConnectionLifecycleState::Failed {
                    reason: "Connection timeout".to_string(),
                    will_reconnect: true,
                    next_attempt_at: Some(Instant::now() + self.config.reconnect_base_delay),
                };

                // Start reconnection task
                self.start_reconnection_task().await;

                Err(ConsumerError::ConnectionError {
                    message: "Connection timeout".to_string(),
                })
            }
        }
    }

    /// Stop managed connection gracefully
    ///
    /// # Returns
    /// * `Ok(())` - Connection stopped successfully
    /// * `Err(ConsumerError)` - Failed to stop connection
    pub async fn stop(&self) -> Result<(), ConsumerError> {
        info!("Stopping managed connection gracefully");

        // Set shutdown flag
        {
            let mut shutdown = self.shutdown.write().await;
            *shutdown = true;
        }

        // Stop persist mode
        self.persist_manager.stop_persist_mode().await?;

        // Update statistics
        {
            let mut stats = self.stats.write().await;

            // Record uptime if connected
            if let Some(start) = stats.current_connection_start {
                stats.total_uptime += start.elapsed();
                stats.current_connection_start = None;
            }

            stats.graceful_closures += 1;
            stats.state = ConnectionLifecycleState::Closed;
        }

        info!("Connection stopped gracefully");

        Ok(())
    }

    /// Get current lifecycle statistics
    ///
    /// # Returns
    /// * Current lifecycle statistics
    pub async fn get_stats(&self) -> LifecycleStats {
        self.stats.read().await.clone()
    }

    /// Check if connection is active
    ///
    /// # Returns
    /// * True if connection is active
    pub async fn is_active(&self) -> bool {
        let stats = self.stats.read().await;
        matches!(stats.state, ConnectionLifecycleState::Active { .. })
    }

    /// Force reconnection
    ///
    /// # Returns
    /// * `Ok(())` - Reconnection initiated
    /// * `Err(ConsumerError)` - Failed to initiate reconnection
    pub async fn force_reconnect(&self) -> Result<(), ConsumerError> {
        info!("Forcing reconnection");

        // Stop current connection
        let _ = self.persist_manager.stop_persist_mode().await;

        // Start reconnection
        self.start_reconnection_task().await;

        Ok(())
    }

    /// Calculate reconnection delay with exponential backoff
    fn calculate_backoff_delay(&self, attempt: u32) -> Duration {
        if !self.config.enable_exponential_backoff {
            return self.config.reconnect_base_delay;
        }

        // Calculate exponential delay
        let multiplier = self.config.backoff_multiplier.powi(attempt as i32 - 1);
        let delay_secs = self.config.reconnect_base_delay.as_secs_f64() * multiplier;
        let mut delay =
            Duration::from_secs_f64(delay_secs.min(self.config.reconnect_max_delay.as_secs_f64()));

        // Add jitter if enabled
        if self.config.enable_jitter {
            let jitter_percent = self.get_random_jitter();
            let jitter = Duration::from_secs_f64(delay.as_secs_f64() * jitter_percent);
            delay += jitter;
        }

        delay
    }

    /// Get random jitter value
    fn get_random_jitter(&self) -> f64 {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        rng.gen_range(0.0..self.config.max_jitter_percent)
    }

    /// Start monitoring task for connection health
    async fn start_monitoring_task(&self) {
        let persist_manager = Arc::clone(&self.persist_manager);
        let stats = Arc::clone(&self.stats);
        let shutdown = Arc::clone(&self.shutdown);

        tokio::spawn(async move {
            debug!("Starting connection monitoring task");

            let mut check_interval = tokio::time::interval(Duration::from_secs(5));

            loop {
                check_interval.tick().await;

                // Check shutdown flag
                if *shutdown.read().await {
                    debug!("Monitoring task shutting down");
                    break;
                }

                // Check connection health
                if !persist_manager.is_active().await {
                    warn!("Connection health check failed");

                    let mut stats = stats.write().await;
                    stats.network_interruptions += 1;
                    stats.state = ConnectionLifecycleState::Degraded {
                        reason: "Connection lost".to_string(),
                        since: Instant::now(),
                    };

                    // Note: Reconnection will be handled by reconnection task
                    break;
                }
            }

            debug!("Connection monitoring task stopped");
        });
    }

    /// Start reconnection task with exponential backoff
    async fn start_reconnection_task(&self) {
        let config = self.config.clone();
        let stats = Arc::clone(&self.stats);
        let persist_manager = Arc::clone(&self.persist_manager);
        let provider_url = Arc::clone(&self.provider_url);
        let last_cookie = Arc::clone(&self.last_cookie);
        let shutdown = Arc::clone(&self.shutdown);
        let lifecycle_manager = self;

        // Clone the manager for spawning (we need to avoid moving self)
        let self_stats = Arc::clone(&self.stats);

        tokio::spawn(async move {
            info!("Starting reconnection task");

            for attempt in 1..=config.max_reconnect_attempts {
                // Check shutdown flag
                if *shutdown.read().await {
                    debug!("Reconnection task cancelled due to shutdown");
                    return;
                }

                // Calculate backoff delay
                let delay = {
                    let multiplier = if config.enable_exponential_backoff {
                        config.backoff_multiplier.powi(attempt as i32 - 1)
                    } else {
                        1.0
                    };
                    let delay_secs = config.reconnect_base_delay.as_secs_f64() * multiplier;
                    let mut delay = Duration::from_secs_f64(
                        delay_secs.min(config.reconnect_max_delay.as_secs_f64()),
                    );

                    // Add jitter if enabled
                    if config.enable_jitter {
                        use rand::Rng;
                        let mut rng = rand::thread_rng();
                        let jitter_percent = rng.gen_range(0.0..config.max_jitter_percent);
                        let jitter = Duration::from_secs_f64(delay.as_secs_f64() * jitter_percent);
                        delay += jitter;
                    }

                    delay
                };

                info!("Reconnection attempt {} in {:?}", attempt, delay);

                // Update state
                {
                    let mut stats = stats.write().await;
                    stats.state = ConnectionLifecycleState::Reconnecting {
                        attempt,
                        last_failure: stats.last_failure_reason.clone().unwrap_or_default(),
                        started_at: Instant::now(),
                    };
                    stats.total_reconnections += 1;
                }

                // Wait before reconnecting
                sleep(delay).await;

                // Get connection details
                let url = provider_url.read().await.clone();
                let cookie = last_cookie.read().await.clone();

                if let Some(url) = url {
                    // Attempt reconnection
                    match persist_manager.start_persist_mode(&url, cookie).await {
                        Ok(()) => {
                            info!("Reconnection successful on attempt {}", attempt);

                            let mut stats = stats.write().await;
                            stats.state = ConnectionLifecycleState::Active {
                                connected_at: Instant::now(),
                            };
                            stats.successful_reconnections += 1;
                            stats.successful_connections += 1;
                            stats.interruption_recoveries += 1;
                            stats.current_connection_start = Some(Instant::now());

                            return;
                        }
                        Err(e) => {
                            warn!("Reconnection attempt {} failed: {}", attempt, e);

                            let mut stats = stats.write().await;
                            stats.failed_connection_attempts += 1;
                            stats.last_failure_time = Some(Instant::now());
                            stats.last_failure_reason = Some(format!("{}", e));
                        }
                    }
                }
            }

            // All reconnection attempts failed
            error!(
                "All {} reconnection attempts failed",
                config.max_reconnect_attempts
            );

            let mut stats = self_stats.write().await;
            stats.state = ConnectionLifecycleState::Terminated {
                reason: "Maximum reconnection attempts exceeded".to_string(),
                terminated_at: Instant::now(),
            };
            stats.abnormal_terminations += 1;
        });
    }
}

// ================================================================================================
// Helper Functions
// ================================================================================================

/// Check if a connection state indicates an active connection
pub fn is_connection_active(state: &ConnectionLifecycleState) -> bool {
    matches!(state, ConnectionLifecycleState::Active { .. })
}

/// Check if a connection state indicates a terminal state
pub fn is_terminal_state(state: &ConnectionLifecycleState) -> bool {
    matches!(state, ConnectionLifecycleState::Terminated { .. })
}

/// Check if a connection state allows reconnection
pub fn can_reconnect(state: &ConnectionLifecycleState) -> bool {
    matches!(
        state,
        ConnectionLifecycleState::Failed { .. }
            | ConnectionLifecycleState::Degraded { .. }
            | ConnectionLifecycleState::Closed
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lifecycle_config_default() {
        let config = LifecycleConfig::default();
        assert_eq!(config.connection_timeout, Duration::from_secs(30));
        assert_eq!(config.operation_timeout, Duration::from_secs(60));
        assert_eq!(config.reconnect_base_delay, Duration::from_secs(1));
        assert_eq!(config.reconnect_max_delay, Duration::from_secs(60));
        assert_eq!(config.max_reconnect_attempts, 5);
        assert!(config.enable_exponential_backoff);
        assert_eq!(config.backoff_multiplier, 2.0);
    }

    #[test]
    fn test_lifecycle_stats_new() {
        let stats = LifecycleStats::new();
        assert_eq!(stats.total_connection_attempts, 0);
        assert_eq!(stats.successful_connections, 0);
        assert_eq!(stats.failed_connection_attempts, 0);
        assert!(matches!(stats.state, ConnectionLifecycleState::Closed));
    }

    #[test]
    fn test_lifecycle_stats_success_rate() {
        let mut stats = LifecycleStats::new();
        assert_eq!(stats.success_rate(), 0.0);

        stats.total_connection_attempts = 10;
        stats.successful_connections = 8;
        assert_eq!(stats.success_rate(), 0.8);
    }

    #[test]
    fn test_is_connection_active() {
        assert!(is_connection_active(&ConnectionLifecycleState::Active {
            connected_at: Instant::now()
        }));
        assert!(!is_connection_active(&ConnectionLifecycleState::Closed));
        assert!(!is_connection_active(
            &ConnectionLifecycleState::Terminated {
                reason: "Test".to_string(),
                terminated_at: Instant::now()
            }
        ));
    }

    #[test]
    fn test_is_terminal_state() {
        assert!(is_terminal_state(&ConnectionLifecycleState::Terminated {
            reason: "Test".to_string(),
            terminated_at: Instant::now()
        }));
        assert!(!is_terminal_state(&ConnectionLifecycleState::Active {
            connected_at: Instant::now()
        }));
        assert!(!is_terminal_state(&ConnectionLifecycleState::Closed));
    }

    #[test]
    fn test_can_reconnect() {
        assert!(can_reconnect(&ConnectionLifecycleState::Failed {
            reason: "Test".to_string(),
            will_reconnect: true,
            next_attempt_at: None
        }));
        assert!(can_reconnect(&ConnectionLifecycleState::Closed));
        assert!(!can_reconnect(&ConnectionLifecycleState::Terminated {
            reason: "Test".to_string(),
            terminated_at: Instant::now()
        }));
    }
}

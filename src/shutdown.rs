//! Graceful Shutdown and Lifecycle Management
//!
//! This module provides graceful shutdown capabilities for the LDAP server,
//! including signal handling, connection draining, and clean termination.
//!
//! ## Features
//!
//! - **Signal Handling**: Respond to SIGTERM/SIGINT for graceful shutdown
//! - **Connection Draining**: Allow in-flight operations to complete
//! - **Shutdown Coordination**: Coordinate shutdown across multiple components
//! - **Timeout Management**: Enforce maximum shutdown time
//!
//! ## Usage
//!
//! ```rust,ignore
//! use opendr::shutdown::{ShutdownCoordinator, ShutdownConfig};
//!
//! let config = ShutdownConfig::default();
//! let coordinator = ShutdownCoordinator::new(config);
//!
//! // Install signal handlers
//! let shutdown_signal = coordinator.install_signal_handlers();
//!
//! // Wait for shutdown signal
//! shutdown_signal.await;
//!
//! // Begin graceful shutdown
//! coordinator.shutdown().await;
//! ```

use log::{info, warn};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, Notify, RwLock};
use tokio::time::timeout;

/// Shutdown configuration
#[derive(Debug, Clone)]
pub struct ShutdownConfig {
    /// Maximum time to wait for graceful shutdown before forcing termination
    pub shutdown_timeout: Duration,

    /// Maximum time to wait for in-flight operations to complete
    pub drain_timeout: Duration,

    /// Whether to wait for all operations to complete (true) or force close (false)
    pub graceful_drain: bool,
}

impl Default for ShutdownConfig {
    fn default() -> Self {
        Self {
            shutdown_timeout: Duration::from_secs(30),
            drain_timeout: Duration::from_secs(10),
            graceful_drain: true,
        }
    }
}

/// Shutdown state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownState {
    /// Server is running normally
    Running,
    /// Shutdown signal received, beginning graceful shutdown
    ShuttingDown,
    /// Draining connections, waiting for operations to complete
    Draining,
    /// Shutdown complete
    Terminated,
}

/// Shutdown coordinator manages graceful shutdown process
pub struct ShutdownCoordinator {
    /// Configuration
    config: ShutdownConfig,

    /// Current shutdown state
    state: Arc<RwLock<ShutdownState>>,

    /// Shutdown signal broadcaster
    shutdown_tx: broadcast::Sender<()>,

    /// Number of active connections
    active_connections: Arc<RwLock<u64>>,

    /// Number of in-flight operations
    in_flight_operations: Arc<RwLock<u64>>,

    /// Notify when all operations complete
    operations_complete: Arc<Notify>,
}

impl ShutdownCoordinator {
    /// Create a new shutdown coordinator
    pub fn new(config: ShutdownConfig) -> Self {
        let (shutdown_tx, _) = broadcast::channel(16);

        Self {
            config,
            state: Arc::new(RwLock::new(ShutdownState::Running)),
            shutdown_tx,
            active_connections: Arc::new(RwLock::new(0)),
            in_flight_operations: Arc::new(RwLock::new(0)),
            operations_complete: Arc::new(Notify::new()),
        }
    }

    /// Install signal handlers for SIGTERM and SIGINT
    ///
    /// Returns a future that completes when a shutdown signal is received
    pub fn install_signal_handlers(&self) -> ShutdownSignal {
        let state = self.state.clone();
        let shutdown_tx = self.shutdown_tx.clone();

        ShutdownSignal { state, shutdown_tx }
    }

    /// Subscribe to shutdown notifications
    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    /// Check if shutdown has been initiated
    pub async fn is_shutting_down(&self) -> bool {
        let state = self.state.read().await;
        *state != ShutdownState::Running
    }

    /// Get the configured drain timeout.
    pub fn drain_timeout(&self) -> Duration {
        self.config.drain_timeout
    }

    /// Return whether graceful draining is enabled.
    pub fn graceful_drain_enabled(&self) -> bool {
        self.config.graceful_drain
    }

    /// Get current shutdown state
    pub async fn get_state(&self) -> ShutdownState {
        *self.state.read().await
    }

    /// Initiate graceful shutdown
    pub async fn initiate_shutdown(&self) {
        let mut state = self.state.write().await;
        if *state == ShutdownState::Running {
            info!("Initiating graceful shutdown");
            *state = ShutdownState::ShuttingDown;

            // Broadcast shutdown signal
            let _ = self.shutdown_tx.send(());
        }
    }

    /// Register a new connection
    pub async fn register_connection(&self) -> Option<()> {
        let state = self.state.read().await;
        if *state != ShutdownState::Running {
            // Reject new connections during shutdown
            return None;
        }

        let mut count = self.active_connections.write().await;
        *count += 1;
        info!("Connection registered, active: {}", *count);
        Some(())
    }

    /// Unregister a connection
    pub async fn unregister_connection(&self) {
        let mut count = self.active_connections.write().await;
        *count = count.saturating_sub(1);
        info!("Connection unregistered, active: {}", *count);

        // Notify if all connections are closed
        if *count == 0 {
            self.operations_complete.notify_waiters();
        }
    }

    /// Register a new operation
    pub async fn register_operation(&self) -> Option<()> {
        let state = self.state.read().await;
        if *state == ShutdownState::Draining || *state == ShutdownState::Terminated {
            // Reject new operations during drain
            return None;
        }

        let mut count = self.in_flight_operations.write().await;
        *count += 1;
        Some(())
    }

    /// Unregister an operation
    pub async fn unregister_operation(&self) {
        let mut count = self.in_flight_operations.write().await;
        *count = count.saturating_sub(1);

        // Notify if all operations are complete
        if *count == 0 {
            self.operations_complete.notify_waiters();
        }
    }

    /// Get number of active connections
    pub async fn active_connection_count(&self) -> u64 {
        *self.active_connections.read().await
    }

    /// Get number of in-flight operations
    pub async fn in_flight_operation_count(&self) -> u64 {
        *self.in_flight_operations.read().await
    }

    /// Drain connections and wait for operations to complete
    pub async fn drain(&self) {
        let mut state = self.state.write().await;
        if *state != ShutdownState::ShuttingDown {
            warn!("Drain called but not in ShuttingDown state");
            return;
        }

        info!("Beginning connection drain");
        *state = ShutdownState::Draining;
        drop(state); // Release lock

        if self.config.graceful_drain {
            // Wait for all operations to complete with timeout
            let drain_future = async {
                loop {
                    let ops = self.in_flight_operation_count().await;
                    let conns = self.active_connection_count().await;

                    if ops == 0 && conns == 0 {
                        info!("All operations and connections completed");
                        break;
                    }

                    info!(
                        "Waiting for {} operations and {} connections to complete",
                        ops, conns
                    );

                    // Wait for notification or check periodically
                    tokio::select! {
                        _ = self.operations_complete.notified() => {
                            // Check again
                            continue;
                        }
                        _ = tokio::time::sleep(Duration::from_secs(1)) => {
                            // Periodic check
                            continue;
                        }
                    }
                }
            };

            match timeout(self.config.drain_timeout, drain_future).await {
                Ok(_) => {
                    info!("Graceful drain completed successfully");
                }
                Err(_) => {
                    let ops = self.in_flight_operation_count().await;
                    let conns = self.active_connection_count().await;
                    warn!(
                        "Drain timeout exceeded, forcing shutdown with {} operations and {} connections remaining",
                        ops, conns
                    );
                }
            }
        } else {
            info!("Force drain enabled, closing immediately");
        }
    }

    /// Complete shutdown process
    pub async fn complete_shutdown(&self) {
        let mut state = self.state.write().await;
        info!("Shutdown complete");
        *state = ShutdownState::Terminated;
    }

    /// Execute complete shutdown sequence
    pub async fn shutdown(&self) {
        info!("Starting shutdown sequence");

        // Initiate shutdown
        self.initiate_shutdown().await;

        // Drain connections
        self.drain().await;

        // Mark as terminated
        self.complete_shutdown().await;

        info!("Shutdown sequence finished");
    }
}

/// Signal handler for graceful shutdown
pub struct ShutdownSignal {
    state: Arc<RwLock<ShutdownState>>,
    shutdown_tx: broadcast::Sender<()>,
}

impl ShutdownSignal {
    /// Wait for shutdown signal (SIGTERM or SIGINT)
    pub async fn wait(self) {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};

            let mut sigterm =
                signal(SignalKind::terminate()).expect("Failed to install SIGTERM handler");
            let mut sigint =
                signal(SignalKind::interrupt()).expect("Failed to install SIGINT handler");

            tokio::select! {
                _ = sigterm.recv() => {
                    info!("Received SIGTERM signal");
                }
                _ = sigint.recv() => {
                    info!("Received SIGINT signal");
                }
            }
        }

        #[cfg(not(unix))]
        {
            use tokio::signal;

            signal::ctrl_c()
                .await
                .expect("Failed to install Ctrl+C handler");
            info!("Received Ctrl+C signal");
        }

        // Update state
        let mut state = self.state.write().await;
        *state = ShutdownState::ShuttingDown;

        // Broadcast shutdown
        let _ = self.shutdown_tx.send(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_shutdown_coordinator_creation() {
        let config = ShutdownConfig::default();
        let coordinator = ShutdownCoordinator::new(config);

        assert_eq!(coordinator.get_state().await, ShutdownState::Running);
        assert_eq!(coordinator.active_connection_count().await, 0);
        assert_eq!(coordinator.in_flight_operation_count().await, 0);
    }

    #[tokio::test]
    async fn test_connection_registration() {
        let coordinator = ShutdownCoordinator::new(ShutdownConfig::default());

        // Register connections
        assert!(coordinator.register_connection().await.is_some());
        assert!(coordinator.register_connection().await.is_some());
        assert_eq!(coordinator.active_connection_count().await, 2);

        // Unregister connection
        coordinator.unregister_connection().await;
        assert_eq!(coordinator.active_connection_count().await, 1);
    }

    #[tokio::test]
    async fn test_operation_registration() {
        let coordinator = ShutdownCoordinator::new(ShutdownConfig::default());

        // Register operations
        assert!(coordinator.register_operation().await.is_some());
        assert!(coordinator.register_operation().await.is_some());
        assert!(coordinator.register_operation().await.is_some());
        assert_eq!(coordinator.in_flight_operation_count().await, 3);

        // Unregister operation
        coordinator.unregister_operation().await;
        assert_eq!(coordinator.in_flight_operation_count().await, 2);
    }

    #[tokio::test]
    async fn test_shutdown_rejects_new_connections() {
        let coordinator = ShutdownCoordinator::new(ShutdownConfig::default());

        // Register a connection
        assert!(coordinator.register_connection().await.is_some());

        // Initiate shutdown
        coordinator.initiate_shutdown().await;
        assert_eq!(coordinator.get_state().await, ShutdownState::ShuttingDown);

        // Try to register new connection (should fail)
        assert!(coordinator.register_connection().await.is_none());
    }

    #[tokio::test]
    async fn test_drain_rejects_new_operations() {
        let coordinator = ShutdownCoordinator::new(ShutdownConfig::default());

        // Register an operation
        assert!(coordinator.register_operation().await.is_some());

        // Initiate shutdown and drain
        coordinator.initiate_shutdown().await;

        let mut state = coordinator.state.write().await;
        *state = ShutdownState::Draining;
        drop(state);

        // Try to register new operation (should fail)
        assert!(coordinator.register_operation().await.is_none());
    }

    #[tokio::test]
    async fn test_graceful_drain_waits_for_operations() {
        let config = ShutdownConfig {
            graceful_drain: true,
            drain_timeout: Duration::from_secs(5),
            ..Default::default()
        };
        let coordinator = ShutdownCoordinator::new(config);

        // Register operations
        coordinator.register_operation().await;
        coordinator.register_operation().await;

        // Initiate shutdown
        coordinator.initiate_shutdown().await;

        // Spawn drain task
        let coord_clone = Arc::new(coordinator);
        let drain_coord = coord_clone.clone();
        let drain_task = tokio::spawn(async move {
            drain_coord.drain().await;
        });

        // Wait a bit
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Should still be draining
        assert_eq!(coord_clone.get_state().await, ShutdownState::Draining);

        // Complete operations
        coord_clone.unregister_operation().await;
        coord_clone.unregister_operation().await;

        // Wait for drain to complete
        drain_task.await.unwrap();

        assert_eq!(coord_clone.get_state().await, ShutdownState::Draining);
    }

    #[tokio::test]
    async fn test_drain_timeout() {
        let config = ShutdownConfig {
            graceful_drain: true,
            drain_timeout: Duration::from_millis(100),
            ..Default::default()
        };
        let coordinator = ShutdownCoordinator::new(config);

        // Register operations that won't complete
        coordinator.register_operation().await;
        coordinator.register_operation().await;

        // Initiate shutdown
        coordinator.initiate_shutdown().await;

        // Drain should timeout
        coordinator.drain().await;

        // Should still have operations (they didn't complete)
        assert_eq!(coordinator.in_flight_operation_count().await, 2);
    }

    #[tokio::test]
    async fn test_force_drain() {
        let config = ShutdownConfig {
            graceful_drain: false,
            ..Default::default()
        };
        let coordinator = ShutdownCoordinator::new(config);

        // Register operations
        coordinator.register_operation().await;
        coordinator.register_operation().await;

        // Initiate shutdown
        coordinator.initiate_shutdown().await;

        // Force drain should complete immediately
        coordinator.drain().await;

        // Operations still exist but drain completed
        assert_eq!(coordinator.get_state().await, ShutdownState::Draining);
    }

    #[tokio::test]
    async fn test_shutdown_sequence() {
        let coordinator = ShutdownCoordinator::new(ShutdownConfig::default());

        // Register some activity
        coordinator.register_connection().await;
        coordinator.register_operation().await;

        // Complete shutdown sequence
        coordinator.shutdown().await;

        assert_eq!(coordinator.get_state().await, ShutdownState::Terminated);
    }

    #[tokio::test]
    async fn test_shutdown_broadcast() {
        let coordinator = ShutdownCoordinator::new(ShutdownConfig::default());

        // Subscribe to shutdown notifications
        let mut rx1 = coordinator.subscribe();
        let mut rx2 = coordinator.subscribe();

        // Initiate shutdown
        coordinator.initiate_shutdown().await;

        // Both subscribers should receive notification
        assert!(rx1.try_recv().is_ok());
        assert!(rx2.try_recv().is_ok());
    }
}

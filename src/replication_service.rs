//! Replication Service Module
//!
//! This module provides high-level services for managing LDAP replication,
//! including provider and consumer initialization, lifecycle management,
//! and monitoring integration.
//!
//! ## Overview
//!
//! The replication service acts as the integration layer between the main
//! server and the replication FSMs, handling:
//!
//! - Provider service initialization and management
//! - Consumer service initialization and management
//! - Changelog tracking and distribution
//! - Metrics and monitoring integration
//! - Graceful shutdown coordination
//!
//! ## Usage
//!
//! ```rust,ignore
//! use opendr::replication_service::ReplicationService;
//! use opendr::config::ServerConfig;
//!
//! // Initialize replication service from configuration
//! let service = ReplicationService::from_config(&config, backend.clone())?;
//!
//! // Start provider if enabled
//! if let Some(provider_handle) = service.start_provider(shutdown.clone()).await? {
//!     // Provider running in background
//! }
//!
//! // Start consumer if enabled
//! if let Some(consumer_handle) = service.start_consumer(shutdown.clone()).await? {
//!     // Consumer running in background
//! }
//! ```

use log::{error, info};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

use crate::backend::DirectoryBackend;
use crate::backend_changelog_wrapper::ChangelogBackendWrapper;
use crate::config::ServerConfig;
use crate::replication::{
    ChangeListenerImpl, ChangelogProviderImpl, ChangelogTracker, ConsumerRegistryImpl,
    LdapChangeListener, ProviderConnectionImpl, StreamingManagerImpl, SyncRequestHandlerImpl,
};
use crate::replication_provider_fsm::{ReplicationProviderConfig, ReplicationProviderFsmImpl};
use crate::shutdown::ShutdownCoordinator;

/// Replication service for managing provider and consumer
pub struct ReplicationService {
    /// Changelog tracker (shared between provider and backend wrapper)
    changelog: Option<Arc<ChangelogTracker>>,

    /// Backend wrapped with changelog tracking
    backend: Arc<dyn DirectoryBackend>,

    /// Original backend (without changelog wrapper)
    original_backend: Arc<dyn DirectoryBackend>,

    /// Replication configuration
    config: ReplicationConfig,
}

/// Replication configuration extracted from ServerConfig
#[derive(Debug, Clone)]
pub struct ReplicationConfig {
    pub enabled: bool,
    pub mode: ReplicationMode,
    pub provider_config: Option<ProviderServiceConfig>,
    pub consumer_config: Option<ConsumerServiceConfig>,
}

/// Replication mode
#[derive(Debug, Clone, PartialEq)]
pub enum ReplicationMode {
    Provider,
    Consumer,
    Both,
}

/// Provider service configuration
#[derive(Debug, Clone)]
pub struct ProviderServiceConfig {
    pub changelog_capacity: usize,
    pub changelog_enabled: bool,
    pub max_batch_size: usize,
    pub enable_streaming: bool,
    pub heartbeat_interval_secs: u64,
    pub max_concurrent_consumers: usize,
    pub consumer_timeout_secs: u64,
    pub max_retry_attempts: u32,
}

/// Consumer service configuration
#[derive(Clone)]
pub struct ConsumerServiceConfig {
    pub provider_url: String,
    pub base_dn: String,
    pub provider_bind_dn: Option<String>,
    pub provider_bind_password: Option<String>,
    pub max_batch_size: usize,
    pub sync_interval_secs: u64,
    pub max_retry_attempts: u32,
    pub retry_delay_secs: u64,
    pub enable_change_listening: bool,
    pub heartbeat_interval_secs: u64,
    pub provider_timeout_secs: u64,
    pub state_persistence_timeout_secs: u64,
    pub change_buffer_size: usize,
    pub state_storage_path: String,
}

impl fmt::Debug for ConsumerServiceConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConsumerServiceConfig")
            .field("provider_url", &self.provider_url)
            .field("base_dn", &self.base_dn)
            .field("provider_bind_dn", &self.provider_bind_dn)
            .field(
                "provider_bind_password",
                &self
                    .provider_bind_password
                    .as_ref()
                    .map(|_| "<redacted>")
                    .unwrap_or("<unset>"),
            )
            .field("max_batch_size", &self.max_batch_size)
            .field("sync_interval_secs", &self.sync_interval_secs)
            .field("max_retry_attempts", &self.max_retry_attempts)
            .field("retry_delay_secs", &self.retry_delay_secs)
            .field("enable_change_listening", &self.enable_change_listening)
            .field("heartbeat_interval_secs", &self.heartbeat_interval_secs)
            .field("provider_timeout_secs", &self.provider_timeout_secs)
            .field(
                "state_persistence_timeout_secs",
                &self.state_persistence_timeout_secs,
            )
            .field("change_buffer_size", &self.change_buffer_size)
            .field("state_storage_path", &self.state_storage_path)
            .finish()
    }
}

impl ReplicationService {
    fn uses_local_provider_runtime(provider_url: &str) -> bool {
        provider_url.starts_with("local://") || provider_url.starts_with("in-memory://")
    }

    /// Create a new replication service from configuration
    ///
    /// # Arguments
    /// * `config` - Server configuration
    /// * `backend` - Directory backend
    ///
    /// # Returns
    /// * `Result<Self, String>` - New replication service or error
    pub fn from_config(
        config: &ServerConfig,
        backend: Arc<dyn DirectoryBackend>,
    ) -> Result<Self, String> {
        let repl_config = Self::parse_replication_config(config)?;
        let should_track_changelog = repl_config
            .provider_config
            .as_ref()
            .map(|provider| provider.changelog_enabled)
            .unwrap_or(false);

        // Create changelog if replication enabled
        let changelog = if should_track_changelog {
            let capacity = repl_config
                .provider_config
                .as_ref()
                .map(|c| c.changelog_capacity)
                .unwrap_or(10000);
            Some(Arc::new(
                ChangelogTracker::with_capacity_replica_and_storage(
                    capacity,
                    config.server.replica_id,
                    config.replication.state_storage_path.clone(),
                ),
            ))
        } else {
            None
        };

        // Wrap backend with changelog tracking if provider mode
        let wrapped_backend = if should_track_changelog {
            let mut wrapper = ChangelogBackendWrapper::new(backend.clone(), changelog.clone());
            let (replication_sender, _) = broadcast::channel(1024);
            wrapper.set_replication_sender(replication_sender);
            Arc::new(wrapper) as Arc<dyn DirectoryBackend>
        } else {
            backend.clone()
        };

        Ok(Self {
            changelog,
            backend: wrapped_backend,
            original_backend: backend,
            config: repl_config,
        })
    }

    /// Parse replication configuration from server config
    fn parse_replication_config(config: &ServerConfig) -> Result<ReplicationConfig, String> {
        if !config.replication.enabled {
            return Ok(ReplicationConfig {
                enabled: false,
                mode: ReplicationMode::Provider,
                provider_config: None,
                consumer_config: None,
            });
        }

        let mode = match config.replication.mode.to_lowercase().as_str() {
            "provider" => ReplicationMode::Provider,
            "consumer" => ReplicationMode::Consumer,
            "both" => ReplicationMode::Both,
            _ => {
                return Err(format!(
                    "Invalid replication mode: {}",
                    config.replication.mode
                ))
            }
        };

        let provider_config = if mode == ReplicationMode::Provider || mode == ReplicationMode::Both
        {
            Some(ProviderServiceConfig {
                changelog_capacity: config.replication.changelog_capacity,
                changelog_enabled: config.replication.changelog_enabled,
                max_batch_size: config.replication.max_batch_size,
                enable_streaming: config.replication.enable_streaming,
                heartbeat_interval_secs: config.replication.heartbeat_interval_secs,
                max_concurrent_consumers: config.replication.max_concurrent_consumers,
                consumer_timeout_secs: config.replication.consumer_timeout_secs,
                max_retry_attempts: config.replication.max_retry_attempts,
            })
        } else {
            None
        };

        let consumer_config = if mode == ReplicationMode::Consumer || mode == ReplicationMode::Both
        {
            let provider_url = config
                .replication
                .provider_url
                .as_ref()
                .ok_or_else(|| "provider_url required for consumer mode".to_string())?;
            let provider_bind_password = config
                .resolved_replication_bind_password()
                .map_err(|err| err.to_string())?;

            Some(ConsumerServiceConfig {
                provider_url: provider_url.clone(),
                base_dn: config.server.base_dn.clone(),
                provider_bind_dn: config.replication.bind_dn.clone(),
                provider_bind_password,
                max_batch_size: config.replication.max_batch_size,
                sync_interval_secs: config.replication.sync_interval_secs,
                max_retry_attempts: config.replication.max_retry_attempts,
                retry_delay_secs: config.replication.retry_delay_secs,
                enable_change_listening: config.replication.enable_change_listening,
                heartbeat_interval_secs: config.replication.heartbeat_interval_secs,
                provider_timeout_secs: config.replication.provider_timeout_secs,
                state_persistence_timeout_secs: config.replication.state_persistence_timeout_secs,
                change_buffer_size: config.replication.change_buffer_size,
                state_storage_path: config.replication.state_storage_path.display().to_string(),
            })
        } else {
            None
        };

        Ok(ReplicationConfig {
            enabled: true,
            mode,
            provider_config,
            consumer_config,
        })
    }

    /// Get the backend (with changelog wrapper if provider mode)
    pub fn backend(&self) -> Arc<dyn DirectoryBackend> {
        self.backend.clone()
    }

    /// Get the changelog tracker
    pub fn changelog(&self) -> Option<Arc<ChangelogTracker>> {
        self.changelog.clone()
    }

    /// Start the replication provider service
    ///
    /// # Arguments
    /// * `shutdown` - Shutdown coordinator
    ///
    /// # Returns
    /// * `Result<Option<JoinHandle<()>>, String>` - Provider task handle or None if not enabled
    pub async fn start_provider(
        &self,
        shutdown: Arc<ShutdownCoordinator>,
    ) -> Result<Option<JoinHandle<()>>, String> {
        if !self.config.enabled {
            return Ok(None);
        }

        if self.config.mode != ReplicationMode::Provider
            && self.config.mode != ReplicationMode::Both
        {
            return Ok(None);
        }

        let provider_config = self
            .config
            .provider_config
            .as_ref()
            .ok_or_else(|| "Provider config not available".to_string())?;

        let changelog = self
            .changelog
            .as_ref()
            .ok_or_else(|| "Changelog not initialized".to_string())?;

        info!("Starting replication provider service");

        // Create provider dependencies
        let changelog_provider = Box::new(ChangelogProviderImpl::new(
            changelog.as_ref().clone(),
            self.original_backend.clone(),
        ));

        let consumer_registry = Box::new(ConsumerRegistryImpl::new());
        let streaming_manager = Box::new(StreamingManagerImpl::new());
        let sync_handler = Box::new(SyncRequestHandlerImpl::new());

        // Create provider FSM configuration
        let fsm_config = ReplicationProviderConfig {
            refresh_batch_size: provider_config.max_batch_size,
            changelog_batch_size: provider_config.max_batch_size / 2,
            consumer_timeout: Duration::from_secs(provider_config.consumer_timeout_secs),
            max_concurrent_consumers: provider_config.max_concurrent_consumers as u32,
            enable_compression: true,
            heartbeat_interval: Duration::from_secs(provider_config.heartbeat_interval_secs),
            cookie_expiry: Duration::from_secs(3600),
            max_retry_attempts: provider_config.max_retry_attempts,
        };

        // Create provider FSM
        let _provider_fsm = ReplicationProviderFsmImpl::with_config(
            changelog_provider,
            consumer_registry,
            streaming_manager,
            sync_handler,
            fsm_config,
        );

        // Get shutdown receiver
        let mut shutdown_rx = shutdown.subscribe();

        // Spawn provider service task
        let handle = tokio::spawn(async move {
            info!("Replication provider service started");

            // Wait for shutdown signal
            let _ = shutdown_rx.recv().await;

            info!("Replication provider service shutting down");

            // TODO: Add graceful provider shutdown
            // - Stop accepting new consumers
            // - Complete active sync operations
            // - Cleanup resources
        });

        Ok(Some(handle))
    }

    /// Start the replication consumer service
    ///
    /// # Arguments
    /// * `shutdown` - Shutdown coordinator
    ///
    /// # Returns
    /// * `Result<Option<JoinHandle<()>>, String>` - Consumer task handle or None if not enabled
    pub async fn start_consumer(
        &self,
        shutdown: Arc<ShutdownCoordinator>,
    ) -> Result<Option<JoinHandle<()>>, String> {
        if !self.config.enabled {
            return Ok(None);
        }

        if self.config.mode != ReplicationMode::Consumer
            && self.config.mode != ReplicationMode::Both
        {
            return Ok(None);
        }

        let consumer_config = self
            .config
            .consumer_config
            .as_ref()
            .ok_or_else(|| "Consumer config not available".to_string())?;

        if consumer_config.enable_change_listening
            && Self::uses_local_provider_runtime(&consumer_config.provider_url)
        {
            return Err(
                "listening mode requires ldap:// or ldaps:// provider_url; local:// and in-memory:// remain polling-only compatibility URLs".to_string()
            );
        }

        info!("Starting replication consumer service");

        // Create consumer dependencies
        use crate::replication::{BatchProcessorImpl, StateManagerImpl};
        use crate::replication_consumer_fsm::{ConsumerConfig, ReplicationConsumerFsmImpl};

        let changelog_provider = if let Some(ref changelog) = self.changelog {
            Arc::new(ChangelogProviderImpl::new(
                changelog.as_ref().clone(),
                self.original_backend.clone(),
            ))
        } else {
            Arc::new(ChangelogProviderImpl::new(
                ChangelogTracker::new(),
                self.original_backend.clone(),
            ))
        };

        let provider_connection = Box::new(ProviderConnectionImpl::with_credentials_and_base(
            changelog_provider,
            consumer_config.provider_bind_dn.clone(),
            consumer_config.provider_bind_password.clone(),
            consumer_config.base_dn.clone(),
        ));

        let batch_processor = Box::new(BatchProcessorImpl::new(self.original_backend.clone()));

        let state_manager = Box::new(StateManagerImpl::new(
            consumer_config.state_storage_path.clone(),
        ));

        let change_listener: Box<dyn crate::replication_consumer_fsm::ChangeListener> =
            if consumer_config.enable_change_listening {
                Box::new(LdapChangeListener::new(
                    consumer_config.provider_url.clone(),
                    consumer_config.base_dn.clone(),
                    consumer_config.provider_bind_dn.clone(),
                    consumer_config.provider_bind_password.clone(),
                    consumer_config.change_buffer_size,
                ))
            } else {
                Box::new(ChangeListenerImpl::new())
            };

        // Create consumer FSM configuration
        let fsm_config = ConsumerConfig {
            max_batch_size: consumer_config.max_batch_size,
            provider_timeout: Duration::from_secs(consumer_config.provider_timeout_secs),
            max_retry_attempts: consumer_config.max_retry_attempts,
            retry_delay: Duration::from_secs(consumer_config.retry_delay_secs),
            enable_change_listening: consumer_config.enable_change_listening,
            heartbeat_interval: Duration::from_secs(consumer_config.heartbeat_interval_secs),
            change_buffer_size: consumer_config.change_buffer_size,
            state_persistence_timeout: Duration::from_secs(
                consumer_config.state_persistence_timeout_secs,
            ),
        };

        // Create consumer FSM
        let mut consumer_fsm = ReplicationConsumerFsmImpl::with_config(
            provider_connection,
            batch_processor,
            state_manager,
            change_listener,
            fsm_config,
        );

        // Get shutdown receiver
        let mut shutdown_rx = shutdown.subscribe();
        let sync_interval = Duration::from_secs(consumer_config.sync_interval_secs);
        let retry_delay = Duration::from_secs(consumer_config.retry_delay_secs);
        let enable_change_listening = consumer_config.enable_change_listening;

        let provider_url = consumer_config.provider_url.clone();

        // Spawn consumer service task
        let handle = tokio::spawn(async move {
            info!("Replication consumer service started");

            use crate::fsm::{ReplicationConsumerEvent, StateMachine};
            use tokio::time::interval;

            if enable_change_listening {
                loop {
                    if let Err(e) = consumer_fsm.reset().await {
                        error!("Failed to reset consumer FSM: {:?}", e);
                        tokio::select! {
                            _ = tokio::time::sleep(retry_delay) => {}
                            _ = shutdown_rx.recv() => {
                                info!("Replication consumer service shutting down");
                                let _ = consumer_fsm.stop_live_listening().await;
                                info!("Replication consumer service stopped");
                                return;
                            }
                        }
                        continue;
                    }

                    let event = ReplicationConsumerEvent::StartConsumption {
                        provider_url: provider_url.clone(),
                        cookie: None,
                    };

                    match consumer_fsm.handle_event(event).await {
                        Ok(_) if consumer_fsm.is_listening_state() => {
                            info!("Replication consumer entered listening mode");
                        }
                        Ok(_) => {
                            info!("Replication consumer completed without entering listening mode");
                            tokio::select! {
                                _ = tokio::time::sleep(retry_delay) => {}
                                _ = shutdown_rx.recv() => {
                                    info!("Replication consumer service shutting down");
                                    let _ = consumer_fsm.stop_live_listening().await;
                                    info!("Replication consumer service stopped");
                                    return;
                                }
                            }
                            continue;
                        }
                        Err(e) => {
                            error!("Initial listening sync failed: {:?}", e);
                            tokio::select! {
                                _ = tokio::time::sleep(retry_delay) => {}
                                _ = shutdown_rx.recv() => {
                                    info!("Replication consumer service shutting down");
                                    let _ = consumer_fsm.stop_live_listening().await;
                                    info!("Replication consumer service stopped");
                                    return;
                                }
                            }
                            continue;
                        }
                    }

                    loop {
                        tokio::select! {
                            _ = shutdown_rx.recv() => {
                                info!("Replication consumer service shutting down");
                                let _ = consumer_fsm.stop_live_listening().await;
                                info!("Replication consumer service stopped");
                                return;
                            }
                            change = consumer_fsm.next_live_change() => {
                                match change {
                                    Ok(Some(change)) => {
                                        if let Err(e) = consumer_fsm.handle_event(ReplicationConsumerEvent::ChangeReceived(change)).await {
                                            error!("Failed to process live replication change: {:?}", e);
                                            let _ = consumer_fsm.stop_live_listening().await;
                                            break;
                                        }
                                    }
                                    Ok(None) => {
                                        tokio::time::sleep(Duration::from_millis(100)).await;
                                    }
                                    Err(e) => {
                                        error!("Listening channel failed: {:?}", e);
                                        let _ = consumer_fsm.stop_live_listening().await;
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    tokio::select! {
                        _ = tokio::time::sleep(retry_delay) => {}
                        _ = shutdown_rx.recv() => {
                            info!("Replication consumer service shutting down");
                            let _ = consumer_fsm.stop_live_listening().await;
                            info!("Replication consumer service stopped");
                            return;
                        }
                    }
                }
            } else {
                let mut sync_timer = interval(sync_interval);

                loop {
                    tokio::select! {
                        _ = sync_timer.tick() => {
                            info!("Starting replication sync cycle");

                            if let Err(e) = consumer_fsm.reset().await {
                                error!("Failed to reset consumer FSM: {:?}", e);
                                continue;
                            }

                            let event = ReplicationConsumerEvent::StartConsumption {
                                provider_url: provider_url.clone(),
                                cookie: None,
                            };

                            match consumer_fsm.handle_event(event).await {
                                Ok(_) => info!("Replication sync cycle completed successfully"),
                                Err(e) => error!("Replication sync cycle failed: {:?}", e),
                            }
                        }
                        _ = shutdown_rx.recv() => {
                            info!("Replication consumer service shutting down");
                            break;
                        }
                    }
                }

                info!("Replication consumer service stopped");
            }
        });

        Ok(Some(handle))
    }

    /// Check if replication is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Check if provider mode is enabled
    pub fn is_provider(&self) -> bool {
        self.config.enabled
            && (self.config.mode == ReplicationMode::Provider
                || self.config.mode == ReplicationMode::Both)
    }

    /// Check if consumer mode is enabled
    pub fn is_consumer(&self) -> bool {
        self.config.enabled
            && (self.config.mode == ReplicationMode::Consumer
                || self.config.mode == ReplicationMode::Both)
    }

    /// Get consumer configuration
    pub fn consumer_config(&self) -> Option<&ConsumerServiceConfig> {
        self.config.consumer_config.as_ref()
    }

    /// Get provider configuration
    pub fn provider_config(&self) -> Option<&ProviderServiceConfig> {
        self.config.provider_config.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MockBackend;
    use crate::replication_provider_fsm::ChangeType;
    use std::io::Write;
    use tempfile::{tempdir, NamedTempFile};

    fn create_test_config() -> ServerConfig {
        let mut config = ServerConfig::default();
        config.replication.enabled = true;
        config.replication.mode = "provider".to_string();
        config.replication.changelog_capacity = 5000;
        config
    }

    #[test]
    fn test_replication_service_creation() {
        let config = create_test_config();
        let backend = Arc::new(MockBackend::new());

        let service = ReplicationService::from_config(&config, backend).unwrap();

        assert!(service.is_enabled());
        assert!(service.is_provider());
        assert!(!service.is_consumer());
        assert!(service.changelog().is_some());
    }

    #[test]
    fn test_replication_service_disabled() {
        let mut config = ServerConfig::default();
        config.replication.enabled = false;
        let backend = Arc::new(MockBackend::new());

        let service = ReplicationService::from_config(&config, backend).unwrap();

        assert!(!service.is_enabled());
        assert!(!service.is_provider());
        assert!(!service.is_consumer());
        assert!(service.changelog().is_none());
    }

    #[test]
    fn test_replication_service_provider_mode() {
        let mut config = create_test_config();
        config.replication.mode = "provider".to_string();
        let backend = Arc::new(MockBackend::new());

        let service = ReplicationService::from_config(&config, backend).unwrap();

        assert!(service.is_provider());
        assert!(!service.is_consumer());
    }

    #[test]
    fn test_replication_service_consumer_mode() {
        let mut config = create_test_config();
        config.replication.mode = "consumer".to_string();
        config.replication.provider_url = Some("ldap://provider:389".to_string());
        let backend = Arc::new(MockBackend::new());

        let service = ReplicationService::from_config(&config, backend).unwrap();

        assert!(!service.is_provider());
        assert!(service.is_consumer());
        assert!(service.changelog().is_none());
    }

    #[test]
    fn test_replication_service_both_mode() {
        let mut config = create_test_config();
        config.replication.mode = "both".to_string();
        config.replication.provider_url = Some("ldap://provider:389".to_string());
        let backend = Arc::new(MockBackend::new());

        let service = ReplicationService::from_config(&config, backend).unwrap();

        assert!(service.is_provider());
        assert!(service.is_consumer());
    }

    #[test]
    fn test_replication_service_consumer_requires_provider_url() {
        let mut config = create_test_config();
        config.replication.mode = "consumer".to_string();
        config.replication.provider_url = None;
        let backend = Arc::new(MockBackend::new());

        let result = ReplicationService::from_config(&config, backend);

        assert!(result.is_err());
        let err_msg = result.err().unwrap();
        assert!(err_msg.contains("provider_url required"));
    }

    #[test]
    fn test_replication_service_invalid_mode() {
        let mut config = create_test_config();
        config.replication.mode = "invalid".to_string();
        let backend = Arc::new(MockBackend::new());

        let result = ReplicationService::from_config(&config, backend);

        assert!(result.is_err());
        let err_msg = result.err().unwrap();
        assert!(err_msg.contains("Invalid replication mode"));
    }

    #[test]
    fn test_replication_service_changelog_capacity() {
        let mut config = create_test_config();
        config.replication.changelog_capacity = 15000;
        let backend = Arc::new(MockBackend::new());

        let service = ReplicationService::from_config(&config, backend).unwrap();

        assert!(service.changelog().is_some());
        // Changelog created with specified capacity
    }

    #[test]
    fn test_replication_service_reloads_persisted_changelog_from_state_path() {
        let state_dir = tempdir().unwrap();
        let backend = Arc::new(MockBackend::new());
        let mut config = create_test_config();
        config.replication.state_storage_path = state_dir.path().to_path_buf();

        let service = ReplicationService::from_config(&config, backend.clone()).unwrap();
        let changelog = service.changelog().unwrap();
        let first_csn = changelog.record_change(
            ChangeType::Add,
            "cn=first,dc=example,dc=org".to_string(),
            b"first".to_vec(),
        );
        let second_csn = changelog.record_change(
            ChangeType::Modify,
            "cn=second,dc=example,dc=org".to_string(),
            b"second".to_vec(),
        );

        let restarted = ReplicationService::from_config(&config, backend).unwrap();
        let restarted_changelog = restarted.changelog().unwrap();
        let changes = restarted_changelog.get_all();

        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].csn, first_csn);
        assert_eq!(changes[1].csn, second_csn);
        assert_eq!(restarted_changelog.get_context_csn(), Some(second_csn));
    }

    #[tokio::test]
    async fn test_consumer_service_initialization() {
        use crate::shutdown::{ShutdownConfig, ShutdownCoordinator};

        let mut config = create_test_config();
        config.replication.mode = "consumer".to_string();
        config.replication.provider_url = Some("ldap://provider:389".to_string());
        config.replication.sync_interval_secs = 30;
        let backend = Arc::new(MockBackend::new());

        let service = ReplicationService::from_config(&config, backend).unwrap();
        let shutdown = Arc::new(ShutdownCoordinator::new(ShutdownConfig::default()));

        let handle = service.start_consumer(shutdown.clone()).await.unwrap();

        assert!(handle.is_some());

        // Shutdown
        shutdown.initiate_shutdown().await;
        if let Some(h) = handle {
            let _ = h.await;
        }
    }

    #[tokio::test]
    async fn test_consumer_service_disabled() {
        use crate::shutdown::{ShutdownConfig, ShutdownCoordinator};

        let mut config = create_test_config();
        config.replication.enabled = false;
        let backend = Arc::new(MockBackend::new());

        let service = ReplicationService::from_config(&config, backend).unwrap();
        let shutdown = Arc::new(ShutdownCoordinator::new(ShutdownConfig::default()));

        let handle = service.start_consumer(shutdown).await.unwrap();

        assert!(handle.is_none());
    }

    #[tokio::test]
    async fn test_consumer_service_provider_mode_no_consumer() {
        use crate::shutdown::{ShutdownConfig, ShutdownCoordinator};

        let mut config = create_test_config();
        config.replication.mode = "provider".to_string();
        let backend = Arc::new(MockBackend::new());

        let service = ReplicationService::from_config(&config, backend).unwrap();
        let shutdown = Arc::new(ShutdownCoordinator::new(ShutdownConfig::default()));

        let handle = service.start_consumer(shutdown).await.unwrap();

        assert!(handle.is_none());
    }

    #[tokio::test]
    async fn test_both_mode_starts_both_services() {
        use crate::shutdown::{ShutdownConfig, ShutdownCoordinator};

        let mut config = create_test_config();
        config.replication.mode = "both".to_string();
        config.replication.provider_url = Some("ldap://provider:389".to_string());
        let backend = Arc::new(MockBackend::new());

        let service = ReplicationService::from_config(&config, backend).unwrap();
        let shutdown = Arc::new(ShutdownCoordinator::new(ShutdownConfig::default()));

        let provider_handle = service.start_provider(shutdown.clone()).await.unwrap();
        let consumer_handle = service.start_consumer(shutdown.clone()).await.unwrap();

        assert!(provider_handle.is_some());
        assert!(consumer_handle.is_some());

        // Shutdown
        shutdown.initiate_shutdown().await;
        if let Some(h) = provider_handle {
            let _ = h.await;
        }
        if let Some(h) = consumer_handle {
            let _ = h.await;
        }
    }

    #[tokio::test]
    async fn test_consumer_service_rejects_local_provider_url_when_listening_enabled() {
        use crate::shutdown::{ShutdownConfig, ShutdownCoordinator};

        let mut config = create_test_config();
        config.replication.mode = "consumer".to_string();
        config.replication.provider_url = Some("local://provider".to_string());
        config.replication.enable_change_listening = true;
        let backend = Arc::new(MockBackend::new());

        let service = ReplicationService::from_config(&config, backend).unwrap();
        let shutdown = Arc::new(ShutdownCoordinator::new(ShutdownConfig::default()));

        let err = service.start_consumer(shutdown).await.unwrap_err();

        assert!(err.contains("listening mode requires ldap:// or ldaps:// provider_url"));
    }

    #[tokio::test]
    async fn test_consumer_service_allows_local_provider_url_when_listening_disabled() {
        use crate::shutdown::{ShutdownConfig, ShutdownCoordinator};

        let mut config = create_test_config();
        config.replication.mode = "consumer".to_string();
        config.replication.provider_url = Some("in-memory://provider".to_string());
        config.replication.enable_change_listening = false;
        config.replication.sync_interval_secs = 30;
        let backend = Arc::new(MockBackend::new());

        let service = ReplicationService::from_config(&config, backend).unwrap();
        let shutdown = Arc::new(ShutdownCoordinator::new(ShutdownConfig::default()));

        let handle = service.start_consumer(shutdown.clone()).await.unwrap();

        assert!(handle.is_some());

        shutdown.initiate_shutdown().await;
        if let Some(h) = handle {
            let _ = h.await;
        }
    }

    #[test]
    fn test_consumer_config_parsing() {
        let mut config = create_test_config();
        config.replication.mode = "consumer".to_string();
        config.replication.provider_url = Some("ldap://provider:389".to_string());
        config.replication.max_batch_size = 150;
        config.replication.sync_interval_secs = 60;
        config.replication.bind_dn = Some("cn=admin,dc=example,dc=com".to_string());
        config.replication.bind_password = Some("secret".to_string());
        let backend = Arc::new(MockBackend::new());

        let service = ReplicationService::from_config(&config, backend).unwrap();

        assert!(service.is_consumer());
        assert!(!service.is_provider());
        assert!(service.config.consumer_config.is_some());

        let consumer_cfg = service.config.consumer_config.as_ref().unwrap();
        assert_eq!(consumer_cfg.provider_url, "ldap://provider:389");
        assert_eq!(consumer_cfg.max_batch_size, 150);
        assert_eq!(consumer_cfg.sync_interval_secs, 60);
        assert_eq!(
            consumer_cfg.provider_bind_dn,
            Some("cn=admin,dc=example,dc=com".to_string())
        );
    }

    #[test]
    fn test_consumer_config_resolves_bind_password_from_file() {
        let mut secret_file = NamedTempFile::new().unwrap();
        writeln!(secret_file, "file-backed-bind-password").unwrap();

        let mut config = create_test_config();
        config.replication.mode = "consumer".to_string();
        config.replication.provider_url = Some("ldap://provider:389".to_string());
        config.replication.bind_password_file = Some(secret_file.path().to_path_buf());
        let backend = Arc::new(MockBackend::new());

        let service = ReplicationService::from_config(&config, backend).unwrap();
        let consumer_cfg = service.consumer_config().unwrap();

        assert_eq!(
            consumer_cfg.provider_bind_password,
            Some("file-backed-bind-password".to_string())
        );

        let debug_output = format!("{consumer_cfg:?}");
        assert!(!debug_output.contains("file-backed-bind-password"));
        assert!(debug_output.contains("<redacted>"));
    }

    #[test]
    fn test_consumer_config_parses_listening_settings() {
        let mut config = create_test_config();
        config.server.base_dn = "dc=test,dc=org".to_string();
        config.replication.mode = "consumer".to_string();
        config.replication.provider_url = Some("ldap://provider:389".to_string());
        config.replication.max_batch_size = 250;
        config.replication.max_retry_attempts = 7;
        config.replication.retry_delay_secs = 11;
        config.replication.enable_change_listening = false;
        config.replication.heartbeat_interval_secs = 45;
        config.replication.provider_timeout_secs = 90;
        config.replication.state_persistence_timeout_secs = 18;
        config.replication.change_buffer_size = 4096;
        config.replication.state_storage_path =
            std::path::PathBuf::from("/tmp/opendr-replication-state");
        let backend = Arc::new(MockBackend::new());

        let service = ReplicationService::from_config(&config, backend).unwrap();
        let consumer_cfg = service.consumer_config().unwrap();

        assert_eq!(consumer_cfg.base_dn, "dc=test,dc=org");
        assert_eq!(consumer_cfg.max_batch_size, 250);
        assert_eq!(consumer_cfg.max_retry_attempts, 7);
        assert_eq!(consumer_cfg.retry_delay_secs, 11);
        assert!(!consumer_cfg.enable_change_listening);
        assert_eq!(consumer_cfg.heartbeat_interval_secs, 45);
        assert_eq!(consumer_cfg.provider_timeout_secs, 90);
        assert_eq!(consumer_cfg.state_persistence_timeout_secs, 18);
        assert_eq!(consumer_cfg.change_buffer_size, 4096);
        assert_eq!(
            consumer_cfg.state_storage_path,
            "/tmp/opendr-replication-state"
        );
    }

    #[test]
    fn test_provider_config_parses_runtime_settings() {
        let mut config = create_test_config();
        config.replication.max_batch_size = 220;
        config.replication.enable_streaming = false;
        config.replication.heartbeat_interval_secs = 75;
        config.replication.max_concurrent_consumers = 17;
        config.replication.consumer_timeout_secs = 600;
        config.replication.max_retry_attempts = 8;
        let backend = Arc::new(MockBackend::new());

        let service = ReplicationService::from_config(&config, backend).unwrap();
        let provider_cfg = service.provider_config().unwrap();

        assert!(provider_cfg.changelog_enabled);
        assert_eq!(provider_cfg.max_batch_size, 220);
        assert!(!provider_cfg.enable_streaming);
        assert_eq!(provider_cfg.heartbeat_interval_secs, 75);
        assert_eq!(provider_cfg.max_concurrent_consumers, 17);
        assert_eq!(provider_cfg.consumer_timeout_secs, 600);
        assert_eq!(provider_cfg.max_retry_attempts, 8);
    }
}

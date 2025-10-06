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

use async_trait::async_trait;
use log::{error, info};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;

use crate::backend::DirectoryBackend;
use crate::backend_changelog_wrapper::ChangelogBackendWrapper;
use crate::config::ServerConfig;
use crate::replication::{
    ChangelogProviderImpl, ChangelogTracker, ConsumerRegistryImpl, StreamingManagerImpl,
    SyncRequestHandlerImpl,
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
}

/// Consumer service configuration
#[derive(Debug, Clone)]
pub struct ConsumerServiceConfig {
    pub provider_url: String,
    pub provider_bind_dn: Option<String>,
    pub provider_bind_password: Option<String>,
    pub sync_interval_secs: u64,
    pub max_retry_attempts: u32,
    pub retry_delay_secs: u64,
    pub enable_change_listening: bool,
    pub state_storage_path: String,
}

impl ReplicationService {
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

        // Create changelog if replication enabled
        let changelog = if repl_config.enabled {
            let capacity = repl_config
                .provider_config
                .as_ref()
                .map(|c| c.changelog_capacity)
                .unwrap_or(10000);
            Some(Arc::new(ChangelogTracker::with_capacity(capacity)))
        } else {
            None
        };

        // Wrap backend with changelog tracking if provider mode
        let wrapped_backend = if repl_config.enabled
            && (repl_config.mode == ReplicationMode::Provider
                || repl_config.mode == ReplicationMode::Both)
        {
            Arc::new(ChangelogBackendWrapper::new(
                backend.clone(),
                changelog.clone(),
            )) as Arc<dyn DirectoryBackend>
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
                changelog_enabled: true,
                max_batch_size: 100,
                enable_streaming: true,
                heartbeat_interval_secs: 60,
                max_concurrent_consumers: 10,
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

            Some(ConsumerServiceConfig {
                provider_url: provider_url.clone(),
                provider_bind_dn: config.replication.bind_dn.clone(),
                provider_bind_password: config.replication.bind_password.clone(),
                sync_interval_secs: config.replication.sync_interval_secs,
                max_retry_attempts: 3,
                retry_delay_secs: 5,
                enable_change_listening: true,
                state_storage_path: "./data/replication_state".to_string(),
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
            consumer_timeout: Duration::from_secs(300),
            max_concurrent_consumers: provider_config.max_concurrent_consumers as u32,
            enable_compression: true,
            heartbeat_interval: Duration::from_secs(provider_config.heartbeat_interval_secs),
            cookie_expiry: Duration::from_secs(3600),
            max_retry_attempts: 3,
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

        info!("Starting replication consumer service");

        // Create consumer dependencies
        use crate::replication::{
            BatchProcessorImpl, ChangeListenerImpl, ChangelogProviderImpl, ProviderConnectionImpl,
            StateManagerImpl,
        };
        use crate::replication_consumer_fsm::{ConsumerConfig, ReplicationConsumerFsmImpl};

        // Create a changelog provider for the consumer to query the remote provider
        // In a real implementation, this would be a remote connection
        // For now, we use a local one that can be replaced with network implementation
        let remote_changelog_provider = Arc::new(ChangelogProviderImpl::new(
            ChangelogTracker::new(),
            self.original_backend.clone(),
        ));

        let provider_connection = Box::new(ProviderConnectionImpl::new(remote_changelog_provider));

        let batch_processor = Box::new(BatchProcessorImpl::new(self.original_backend.clone()));

        let state_manager = Box::new(StateManagerImpl::new(
            consumer_config.state_storage_path.clone(),
        ));

        let change_listener = Box::new(ChangeListenerImpl::new());

        // Create consumer FSM configuration
        let fsm_config = ConsumerConfig {
            max_batch_size: 100,
            provider_timeout: Duration::from_secs(30),
            max_retry_attempts: consumer_config.max_retry_attempts,
            retry_delay: Duration::from_secs(consumer_config.retry_delay_secs),
            enable_change_listening: consumer_config.enable_change_listening,
            heartbeat_interval: Duration::from_secs(60),
            change_buffer_size: 1000,
            state_persistence_timeout: Duration::from_secs(10),
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

        let provider_url = consumer_config.provider_url.clone();

        // Spawn consumer service task
        let handle = tokio::spawn(async move {
            info!("Replication consumer service started");

            use crate::fsm::{ReplicationConsumerEvent, StateMachine};
            use tokio::time::interval;

            let mut sync_timer = interval(sync_interval);

            loop {
                tokio::select! {
                    _ = sync_timer.tick() => {
                        info!("Starting replication sync cycle");

                        // Start sync by sending StartConsumption event
                        let event = ReplicationConsumerEvent::StartConsumption {
                            provider_url: provider_url.clone(),
                            cookie: None, // Will be loaded from state by FSM
                        };

                        match consumer_fsm.handle_event(event).await {
                            Ok(_) => {
                                info!("Replication sync cycle completed successfully");
                            }
                            Err(e) => {
                                error!("Replication sync cycle failed: {:?}", e);
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!("Replication consumer service shutting down");
                        break;
                    }
                }
            }

            // Cleanup
            info!("Replication consumer service stopped");
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

    #[test]
    fn test_consumer_config_parsing() {
        let mut config = create_test_config();
        config.replication.mode = "consumer".to_string();
        config.replication.provider_url = Some("ldap://provider:389".to_string());
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
        assert_eq!(consumer_cfg.sync_interval_secs, 60);
        assert_eq!(
            consumer_cfg.provider_bind_dn,
            Some("cn=admin,dc=example,dc=com".to_string())
        );
    }
}

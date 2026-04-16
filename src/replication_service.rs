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
//! use opendr::config::ServerConfig;
//! use opendr::replication_service::ReplicationService;
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

use log::{error, info, warn};
use serde::Serialize;
use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Notify;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::backend::DirectoryBackend;
use crate::backend_changelog_wrapper::ChangelogBackendWrapper;
use crate::config::ServerConfig;
use crate::replication::{
    ChangelogProviderImpl, ChangelogTracker, LdapChangeListener, ProviderConnectionImpl,
};
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

    /// Provider lifecycle state shared with inbound replication stream handlers.
    provider_lifecycle: Option<Arc<ReplicationProviderLifecycle>>,

    /// Runtime status shared with the management console.
    status: Arc<ReplicationStatusRegistry>,
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

impl ReplicationMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Provider => "provider",
            Self::Consumer => "consumer",
            Self::Both => "both",
        }
    }
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

#[derive(Debug, Clone, Serialize)]
pub struct ReplicationStatusSnapshot {
    pub enabled: bool,
    pub mode: String,
    pub provider: ProviderReplicationStatus,
    pub consumer: ConsumerReplicationStatus,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProviderReplicationStatus {
    pub enabled: bool,
    pub running: bool,
    pub draining: bool,
    pub active_sessions: usize,
    pub changelog_capacity: Option<usize>,
    pub changelog_enabled: bool,
    pub max_batch_size: Option<usize>,
    pub enable_streaming: Option<bool>,
    pub heartbeat_interval_secs: Option<u64>,
    pub max_concurrent_consumers: Option<usize>,
    pub consumer_timeout_secs: Option<u64>,
    pub retained_changelog_entries: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oldest_retained_csn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_context_csn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConsumerReplicationStatus {
    pub enabled: bool,
    pub running: bool,
    pub listening: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_url: Option<String>,
    pub max_batch_size: Option<usize>,
    pub max_retry_attempts: Option<u32>,
    pub retry_delay_secs: Option<u64>,
    pub heartbeat_interval_secs: Option<u64>,
    pub change_buffer_size: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persisted_cookie: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_applied_cookie: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_applied_csn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_successful_sync_unix_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seconds_since_last_successful_sync: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_sync_entries: Option<usize>,
    pub failed_sessions: u64,
    pub full_refreshes: u64,
    pub full_refresh_required: u64,
    pub replay_gap_errors: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

pub struct ReplicationStatusRegistry {
    snapshot: StdRwLock<ReplicationStatusSnapshot>,
    provider_lifecycle: StdRwLock<Option<Arc<ReplicationProviderLifecycle>>>,
    provider_changelog: StdRwLock<Option<Arc<ChangelogTracker>>>,
    consumer_cookie_path: StdRwLock<Option<PathBuf>>,
}

impl ReplicationStatusRegistry {
    fn new(config: &ReplicationConfig) -> Arc<Self> {
        let provider = config.provider_config.as_ref();
        let consumer = config.consumer_config.as_ref();
        Arc::new(Self {
            snapshot: StdRwLock::new(ReplicationStatusSnapshot {
                enabled: config.enabled,
                mode: if config.enabled {
                    config.mode.as_str().to_string()
                } else {
                    "disabled".to_string()
                },
                provider: ProviderReplicationStatus {
                    enabled: provider.is_some(),
                    running: false,
                    draining: false,
                    active_sessions: 0,
                    changelog_capacity: provider.map(|settings| settings.changelog_capacity),
                    changelog_enabled: provider
                        .map(|settings| settings.changelog_enabled)
                        .unwrap_or(false),
                    max_batch_size: provider.map(|settings| settings.max_batch_size),
                    enable_streaming: provider.map(|settings| settings.enable_streaming),
                    heartbeat_interval_secs: provider
                        .map(|settings| settings.heartbeat_interval_secs),
                    max_concurrent_consumers: provider
                        .map(|settings| settings.max_concurrent_consumers),
                    consumer_timeout_secs: provider.map(|settings| settings.consumer_timeout_secs),
                    retained_changelog_entries: provider.map(|_| 0),
                    oldest_retained_csn: None,
                    latest_context_csn: None,
                    last_error: None,
                },
                consumer: ConsumerReplicationStatus {
                    enabled: consumer.is_some(),
                    running: false,
                    listening: false,
                    provider_url: consumer.map(|settings| settings.provider_url.clone()),
                    max_batch_size: consumer.map(|settings| settings.max_batch_size),
                    max_retry_attempts: consumer.map(|settings| settings.max_retry_attempts),
                    retry_delay_secs: consumer.map(|settings| settings.retry_delay_secs),
                    heartbeat_interval_secs: consumer
                        .map(|settings| settings.heartbeat_interval_secs),
                    change_buffer_size: consumer.map(|settings| settings.change_buffer_size),
                    persisted_cookie: consumer.map(|_| false),
                    last_applied_cookie: None,
                    last_applied_csn: None,
                    last_successful_sync_unix_secs: None,
                    seconds_since_last_successful_sync: None,
                    last_sync_entries: None,
                    failed_sessions: 0,
                    full_refreshes: 0,
                    full_refresh_required: 0,
                    replay_gap_errors: 0,
                    last_error: None,
                },
            }),
            provider_lifecycle: StdRwLock::new(None),
            provider_changelog: StdRwLock::new(None),
            consumer_cookie_path: StdRwLock::new(consumer.map(|settings| {
                PathBuf::from(&settings.state_storage_path).join("replication_cookie.txt")
            })),
        })
    }

    fn update(&self, update: impl FnOnce(&mut ReplicationStatusSnapshot)) {
        let mut snapshot = self
            .snapshot
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        update(&mut snapshot);
    }

    fn set_provider_lifecycle(&self, lifecycle: Option<Arc<ReplicationProviderLifecycle>>) {
        let mut provider_lifecycle = self
            .provider_lifecycle
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *provider_lifecycle = lifecycle;
    }

    fn set_provider_changelog(&self, changelog: Option<Arc<ChangelogTracker>>) {
        let mut provider_changelog = self
            .provider_changelog
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *provider_changelog = changelog;
    }

    fn set_provider_running(&self, running: bool) {
        self.update(|snapshot| {
            snapshot.provider.running = running;
            if running {
                snapshot.provider.last_error = None;
            }
        });
    }

    fn set_provider_draining(&self, draining: bool) {
        self.update(|snapshot| {
            snapshot.provider.draining = draining;
        });
    }

    fn set_provider_error(&self, error: impl Into<String>) {
        self.update(|snapshot| {
            snapshot.provider.running = false;
            snapshot.provider.last_error = Some(error.into());
        });
    }

    fn set_consumer_running(&self, running: bool) {
        self.update(|snapshot| {
            snapshot.consumer.running = running;
            if !running {
                snapshot.consumer.listening = false;
            }
            if running {
                snapshot.consumer.last_error = None;
            }
        });
    }

    fn set_consumer_error(&self, error: impl Into<String>) {
        let error = error.into();
        self.update(|snapshot| {
            snapshot.consumer.listening = false;
            snapshot.consumer.failed_sessions += 1;
            if Self::requires_full_refresh(&error) {
                snapshot.consumer.full_refresh_required += 1;
                snapshot.consumer.replay_gap_errors += 1;
            }
            snapshot.consumer.last_error = Some(error);
        });
    }

    fn record_consumer_success(
        &self,
        cookie: Option<&str>,
        entries_processed: usize,
        full_refresh: bool,
    ) {
        let now = current_unix_secs();
        self.update(|snapshot| {
            snapshot.consumer.running = true;
            snapshot.consumer.listening = true;
            snapshot.consumer.last_successful_sync_unix_secs = Some(now);
            snapshot.consumer.seconds_since_last_successful_sync = Some(0);
            snapshot.consumer.last_sync_entries = Some(entries_processed);
            snapshot.consumer.last_applied_cookie = cookie.map(str::to_string);
            snapshot.consumer.last_applied_csn = cookie.and_then(cookie_to_csn);
            snapshot.consumer.last_error = None;
            if full_refresh {
                snapshot.consumer.full_refreshes += 1;
            }
        });
    }

    fn requires_full_refresh(error: &str) -> bool {
        error.contains("FullRefreshRequired")
            || error.contains("Stale replication cookie")
            || error.contains("requires a full refresh")
            || error.contains("full refresh required")
    }

    pub fn snapshot(&self) -> ReplicationStatusSnapshot {
        let mut snapshot = self
            .snapshot
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();

        if let Some(lifecycle) = self
            .provider_lifecycle
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
        {
            snapshot.provider.active_sessions = lifecycle.active_session_count();
            snapshot.provider.draining = lifecycle.is_draining();
        }

        if let Some(changelog) = self
            .provider_changelog
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
        {
            snapshot.provider.retained_changelog_entries = Some(changelog.count_all());
            snapshot.provider.oldest_retained_csn =
                changelog.get_oldest_csn().map(|csn| csn.to_string());
            snapshot.provider.latest_context_csn =
                changelog.get_context_csn().map(|csn| csn.to_string());
        }

        if let Some(cookie_path) = self
            .consumer_cookie_path
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
        {
            snapshot.consumer.persisted_cookie = Some(cookie_path.exists());
        }

        if let Some(last_sync) = snapshot.consumer.last_successful_sync_unix_secs {
            snapshot.consumer.seconds_since_last_successful_sync =
                Some(current_unix_secs().saturating_sub(last_sync));
        }

        snapshot
    }
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn cookie_to_csn(cookie: &str) -> Option<String> {
    cookie
        .strip_prefix("csn-")
        .filter(|csn| !csn.is_empty() && *csn != "empty")
        .map(str::to_string)
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
        let provider_lifecycle = if should_track_changelog {
            Some(Arc::new(ReplicationProviderLifecycle::new()))
        } else {
            None
        };
        let status = ReplicationStatusRegistry::new(&repl_config);
        status.set_provider_lifecycle(provider_lifecycle.clone());

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
        status.set_provider_changelog(changelog.clone());

        // Wrap backend with changelog tracking if provider mode
        let wrapped_backend = if should_track_changelog {
            let mut wrapper = ChangelogBackendWrapper::new(backend.clone(), changelog.clone());
            let (replication_sender, _) = broadcast::channel(1024);
            wrapper.set_replication_sender(replication_sender);
            wrapper.set_provider_lifecycle(provider_lifecycle.clone());
            Arc::new(wrapper) as Arc<dyn DirectoryBackend>
        } else {
            backend.clone()
        };

        Ok(Self {
            changelog,
            backend: wrapped_backend,
            original_backend: backend,
            config: repl_config,
            provider_lifecycle,
            status,
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
                ));
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
            if !config.replication.enable_change_listening {
                return Err(
                    "poll-based replication has been removed; enable_change_listening must be true"
                        .to_string(),
                );
            }

            let provider_url = config
                .replication
                .provider_url
                .as_ref()
                .ok_or_else(|| "provider_url required for consumer mode".to_string())?;
            let provider_bind_password = config
                .resolved_replication_bind_password()
                .map_err(|err| err.to_string())?;
            config
                .validate_replication_provider_transport()
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

    /// Get the runtime replication status registry.
    pub fn status(&self) -> Arc<ReplicationStatusRegistry> {
        self.status.clone()
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
        let provider_lifecycle = self.provider_lifecycle.clone().ok_or_else(|| {
            self.status
                .set_provider_error("Provider lifecycle not initialized");
            "Provider lifecycle not initialized".to_string()
        })?;

        self.changelog.as_ref().ok_or_else(|| {
            self.status.set_provider_error("Changelog not initialized");
            "Changelog not initialized".to_string()
        })?;

        info!(
            "Starting replication provider service with inbound stream sessions (streaming={}, heartbeat={}s)",
            provider_config.enable_streaming, provider_config.heartbeat_interval_secs
        );

        // Get shutdown receiver
        let mut shutdown_rx = shutdown.subscribe();
        let graceful_drain = shutdown.graceful_drain_enabled();
        let drain_timeout = shutdown.drain_timeout();
        let status = self.status.clone();
        status.set_provider_running(true);

        // Spawn provider service task
        let handle = tokio::spawn(async move {
            info!(
                "Replication provider service started; live changes are served through inbound replication search sessions"
            );

            // Wait for shutdown signal
            let _ = shutdown_rx.recv().await;

            info!("Replication provider service shutting down");
            provider_lifecycle.begin_shutdown();
            status.set_provider_draining(true);

            if !graceful_drain {
                info!("Replication provider service shutdown will not wait for session drain");
                status.set_provider_running(false);
                return;
            }

            match timeout(
                drain_timeout,
                provider_lifecycle.wait_for_sessions_to_drain(),
            )
            .await
            {
                Ok(()) => {
                    info!("Replication provider sessions drained cleanly");
                }
                Err(_) => {
                    warn!(
                        "Replication provider drain timeout exceeded with {} active session(s) remaining",
                        provider_lifecycle.active_session_count()
                    );
                }
            }
            status.set_provider_running(false);
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

        if Self::uses_local_provider_runtime(&consumer_config.provider_url) {
            let message = "listener-based replication requires ldap:// or ldaps:// provider_url; local:// and in-memory:// are not supported";
            self.status.set_consumer_error(message);
            return Err(message.to_string());
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
            Box::new(LdapChangeListener::new(
                consumer_config.provider_url.clone(),
                consumer_config.base_dn.clone(),
                consumer_config.provider_bind_dn.clone(),
                consumer_config.provider_bind_password.clone(),
                consumer_config.change_buffer_size,
            ));

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
        let retry_delay = Duration::from_secs(consumer_config.retry_delay_secs);

        let provider_url = consumer_config.provider_url.clone();
        let status = self.status.clone();
        status.set_consumer_running(true);

        // Spawn consumer service task
        let handle = tokio::spawn(async move {
            info!("Replication consumer service started");

            use crate::fsm::{ReplicationConsumerEvent, ReplicationConsumerFsm, StateMachine};

            loop {
                if let Err(e) = consumer_fsm.reset().await {
                    error!("Failed to reset consumer FSM: {:?}", e);
                    status.set_consumer_error(format!("consumer FSM reset failed: {e:?}"));
                    tokio::select! {
                        _ = tokio::time::sleep(retry_delay) => {}
                        _ = shutdown_rx.recv() => {
                            info!("Replication consumer service shutting down");
                            let _ = consumer_fsm.stop_live_listening().await;
                            status.set_consumer_running(false);
                            info!("Replication consumer service stopped");
                            return;
                        }
                    }
                    continue;
                }

                let started_without_cookie =
                    !status.snapshot().consumer.persisted_cookie.unwrap_or(false);
                let event = ReplicationConsumerEvent::StartConsumption {
                    provider_url: provider_url.clone(),
                    cookie: None,
                };

                match consumer_fsm.handle_event(event).await {
                    Ok(entries_processed) if consumer_fsm.is_listening_state() => {
                        info!("Replication consumer entered listening mode");
                        status.record_consumer_success(
                            consumer_fsm.current_cookie(),
                            entries_processed.unwrap_or(0),
                            started_without_cookie,
                        );
                    }
                    Ok(_) => {
                        error!("Replication consumer completed without entering listening mode");
                        status.set_consumer_error(
                            "consumer completed without entering listening mode",
                        );
                        tokio::select! {
                            _ = tokio::time::sleep(retry_delay) => {}
                            _ = shutdown_rx.recv() => {
                                info!("Replication consumer service shutting down");
                                let _ = consumer_fsm.stop_live_listening().await;
                                status.set_consumer_running(false);
                                info!("Replication consumer service stopped");
                                return;
                            }
                        }
                        continue;
                    }
                    Err(e) => {
                        error!("Initial listening sync failed: {:?}", e);
                        status.set_consumer_error(format!("initial listening sync failed: {e:?}"));
                        tokio::select! {
                            _ = tokio::time::sleep(retry_delay) => {}
                            _ = shutdown_rx.recv() => {
                                info!("Replication consumer service shutting down");
                                let _ = consumer_fsm.stop_live_listening().await;
                                status.set_consumer_running(false);
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
                            status.set_consumer_running(false);
                            info!("Replication consumer service stopped");
                            return;
                        }
                        change = consumer_fsm.next_live_change() => {
                            match change {
                                Ok(Some(change)) => {
                                    match consumer_fsm.handle_event(ReplicationConsumerEvent::ChangeReceived(change)).await {
                                        Ok(entries_processed) => {
                                            status.record_consumer_success(
                                                consumer_fsm.current_cookie(),
                                                entries_processed.unwrap_or(0),
                                                false,
                                            );
                                        }
                                        Err(e) => {
                                            error!("Failed to process live replication change: {:?}", e);
                                            status.set_consumer_error(format!("live replication change failed: {e:?}"));
                                            let _ = consumer_fsm.stop_live_listening().await;
                                            break;
                                        }
                                    }
                                }
                                Ok(None) => {
                                    tokio::time::sleep(Duration::from_millis(100)).await;
                                }
                                Err(e) => {
                                    error!("Listening channel failed: {:?}", e);
                                    status.set_consumer_error(format!("listening channel failed: {e:?}"));
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
                        status.set_consumer_running(false);
                        info!("Replication consumer service stopped");
                        return;
                    }
                }
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

/// Shared provider lifecycle used to reject new sessions and drain active ones.
pub struct ReplicationProviderLifecycle {
    draining: AtomicBool,
    active_sessions: AtomicUsize,
    shutdown_notifier: Notify,
    drained_notifier: Notify,
}

impl ReplicationProviderLifecycle {
    pub fn new() -> Self {
        Self {
            draining: AtomicBool::new(false),
            active_sessions: AtomicUsize::new(0),
            shutdown_notifier: Notify::new(),
            drained_notifier: Notify::new(),
        }
    }
}

impl Default for ReplicationProviderLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplicationProviderLifecycle {
    pub fn begin_shutdown(&self) {
        if !self.draining.swap(true, Ordering::SeqCst) {
            self.shutdown_notifier.notify_waiters();
            if self.active_sessions.load(Ordering::SeqCst) == 0 {
                self.drained_notifier.notify_waiters();
            }
        }
    }

    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::SeqCst)
    }

    pub fn active_session_count(&self) -> usize {
        self.active_sessions.load(Ordering::SeqCst)
    }

    pub fn register_session(self: &Arc<Self>) -> Option<ReplicationProviderSessionGuard> {
        if self.is_draining() {
            return None;
        }

        self.active_sessions.fetch_add(1, Ordering::SeqCst);

        if self.is_draining() {
            if self.active_sessions.fetch_sub(1, Ordering::SeqCst) == 1 {
                self.drained_notifier.notify_waiters();
            }
            return None;
        }

        Some(ReplicationProviderSessionGuard {
            lifecycle: self.clone(),
        })
    }

    pub async fn wait_for_shutdown(&self) {
        loop {
            if self.is_draining() {
                return;
            }

            let notified = self.shutdown_notifier.notified();
            if self.is_draining() {
                return;
            }

            notified.await;
        }
    }

    pub async fn wait_for_sessions_to_drain(&self) {
        loop {
            if self.active_session_count() == 0 {
                return;
            }

            let notified = self.drained_notifier.notified();
            if self.active_session_count() == 0 {
                return;
            }

            notified.await;
        }
    }
}

pub struct ReplicationProviderSessionGuard {
    lifecycle: Arc<ReplicationProviderLifecycle>,
}

impl Drop for ReplicationProviderSessionGuard {
    fn drop(&mut self) {
        if self
            .lifecycle
            .active_sessions
            .fetch_sub(1, Ordering::SeqCst)
            == 1
        {
            self.lifecycle.drained_notifier.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MockBackend;
    use crate::replication_provider_fsm::ChangeType;
    use std::io::Write;
    use tempfile::{NamedTempFile, tempdir};

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
    fn test_replication_status_snapshot_tracks_provider_sessions() {
        let config = create_test_config();
        let backend = Arc::new(MockBackend::new());

        let service = ReplicationService::from_config(&config, backend).unwrap();
        let lifecycle = service.provider_lifecycle.as_ref().unwrap();
        let guard = lifecycle.register_session().unwrap();

        let snapshot = service.status().snapshot();
        assert!(snapshot.enabled);
        assert_eq!(snapshot.mode, "provider");
        assert!(snapshot.provider.enabled);
        assert_eq!(snapshot.provider.active_sessions, 1);
        assert!(!snapshot.consumer.enabled);

        drop(guard);
        assert_eq!(service.status().snapshot().provider.active_sessions, 0);
    }

    #[test]
    fn test_replication_status_snapshot_tracks_consumer_health() {
        let state_dir = tempdir().unwrap();
        let mut config = ServerConfig::default();
        config.replication.enabled = true;
        config.replication.mode = "consumer".to_string();
        config.replication.provider_url = Some("ldap://provider.example.org:1389".to_string());
        config.replication.state_storage_path = state_dir.path().to_path_buf();
        let backend = Arc::new(MockBackend::new());

        let service = ReplicationService::from_config(&config, backend).unwrap();
        service.status().record_consumer_success(
            Some("csn-20251007123456789012#001#000001#000000"),
            3,
            true,
        );

        let snapshot = service.status().snapshot();
        assert!(snapshot.consumer.enabled);
        assert!(snapshot.consumer.running);
        assert!(snapshot.consumer.listening);
        assert_eq!(
            snapshot.consumer.last_applied_csn.as_deref(),
            Some("20251007123456789012#001#000001#000000")
        );
        assert_eq!(snapshot.consumer.last_sync_entries, Some(3));
        assert_eq!(snapshot.consumer.full_refreshes, 1);
        assert_eq!(snapshot.consumer.failed_sessions, 0);
        assert!(
            snapshot
                .consumer
                .seconds_since_last_successful_sync
                .unwrap()
                <= 1
        );

        service
            .status()
            .set_consumer_error("Stale replication cookie: csn-old");
        let snapshot = service.status().snapshot();
        assert!(!snapshot.consumer.listening);
        assert_eq!(snapshot.consumer.failed_sessions, 1);
        assert_eq!(snapshot.consumer.full_refresh_required, 1);
        assert_eq!(snapshot.consumer.replay_gap_errors, 1);
        assert!(
            snapshot
                .consumer
                .last_error
                .as_deref()
                .unwrap()
                .contains("Stale replication cookie")
        );
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

        assert!(
            err.contains("listener-based replication requires ldap:// or ldaps:// provider_url")
        );
    }

    #[test]
    fn test_consumer_service_rejects_disabled_listening() {
        let mut config = create_test_config();
        config.replication.mode = "consumer".to_string();
        config.replication.provider_url = Some("ldap://provider:389".to_string());
        config.replication.enable_change_listening = false;
        let backend = Arc::new(MockBackend::new());

        let err = match ReplicationService::from_config(&config, backend) {
            Ok(_) => panic!("disabled listener config should be rejected"),
            Err(err) => err,
        };
        assert!(err.contains("poll-based replication has been removed"));
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
        config.replication.allow_insecure_provider_bind = true;
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
        config.replication.allow_insecure_provider_bind = true;
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
    fn test_consumer_config_rejects_credentialed_cleartext_provider_url() {
        let mut config = create_test_config();
        config.replication.mode = "consumer".to_string();
        config.replication.provider_url = Some("ldap://provider:389".to_string());
        config.replication.bind_password = Some("secret".to_string());
        let backend = Arc::new(MockBackend::new());

        let error = match ReplicationService::from_config(&config, backend) {
            Ok(_) => panic!("credentialed cleartext replication should be rejected"),
            Err(error) => error,
        };

        assert!(error.contains("replication.provider_url uses ldap://"));
        assert!(error.contains("ldaps://"));
    }

    #[test]
    fn test_consumer_config_accepts_ldaps_provider_url_with_credentials() {
        let mut config = create_test_config();
        config.replication.mode = "consumer".to_string();
        config.replication.provider_url = Some("ldaps://provider:636".to_string());
        config.replication.bind_password = Some("secret".to_string());
        let backend = Arc::new(MockBackend::new());

        let service = ReplicationService::from_config(&config, backend).unwrap();
        let consumer_cfg = service.consumer_config().unwrap();

        assert_eq!(consumer_cfg.provider_url, "ldaps://provider:636");
        assert_eq!(
            consumer_cfg.provider_bind_password,
            Some("secret".to_string())
        );
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
        assert!(consumer_cfg.enable_change_listening);
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

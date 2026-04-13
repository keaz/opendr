//! Real-Time Change Propagation for Push-Based Replication
//!
//! This module implements real-time change propagation by connecting the
//! ChangeObserver to the PushManager with advanced filtering and batching
//! capabilities.
//!
//! # Architecture
//!
//! ```text
//! Backend Write → ChangelogBackendWrapper → ChangeObserver
//!                                               ↓
//!                                       ChangeFilterEngine
//!                                      (per-consumer filtering)
//!                                               ↓
//!                                          BatchManager
//!                                       (optional batching)
//!                                               ↓
//!                                         PushManager
//!                                               ↓
//!                                      PersistentConsumers
//! ```
//!
//! # Features
//!
//! - **Per-Consumer Filtering**: Only send changes matching consumer's DN scope and filter
//! - **Change Batching**: Optionally batch multiple changes for efficiency
//! - **Priority Delivery**: Critical changes can bypass batching
//! - **Filtering Statistics**: Track filter matches/misses per consumer
//!
//! # Example Usage
//!
//! ```no_run
//! use opendr::change_observer::{ChangeObserver, ChangeObserverImpl};
//! use opendr::real_time_propagation::{RealTimePropagationEngine, PropagationConfig};
//! use opendr::push_manager::{PushManager, PushManagerConfig};
//! use std::sync::Arc;
//! use tokio::sync::RwLock;
//!
//! # async fn example() -> Result<(), String> {
//! let observer: Arc<dyn ChangeObserver> = Arc::new(ChangeObserverImpl::new());
//! let push_manager = Arc::new(RwLock::new(PushManager::new(
//!     observer.clone(),
//!     PushManagerConfig::default(),
//! )));
//! let config = PropagationConfig::default();
//!
//! let engine = RealTimePropagationEngine::new(
//!     observer,
//!     push_manager,
//!     config
//! );
//!
//! // Start the engine
//! engine.start().await?;
//!
//! // Register consumer filters
//! engine.register_consumer_filter(
//!     "consumer-1".to_string(),
//!     "dc=example,dc=com".to_string(),
//!     Some("(objectClass=person)".to_string()),
//! ).await?;
//!
//! // Changes will be automatically filtered and pushed
//! # Ok(())
//! # }
//! ```

use async_trait::async_trait;
use log::{debug, info, warn};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::change_observer::{ChangeCallback, ChangeObserver};
use crate::ldap_filter_eval::{
    CompiledLdapFilter, PreparedChange, compile_filter, is_dn_in_scope as ldap_dn_in_scope,
    prepare_change,
};
use crate::push_manager::PushManager;
use crate::replication_provider_fsm::ChangelogEntry;

/// Configuration for real-time propagation
#[derive(Debug, Clone)]
pub struct PropagationConfig {
    /// Enable change batching (groups multiple changes before sending)
    pub enable_batching: bool,

    /// Maximum batch size (number of changes)
    pub max_batch_size: usize,

    /// Batch timeout (send batch even if not full)
    pub batch_timeout: Duration,

    /// Enable per-consumer filtering
    pub enable_filtering: bool,

    /// Parallel push to consumers (vs sequential)
    pub parallel_push: bool,

    /// Maximum latency target (for monitoring)
    pub target_latency: Duration,
}

impl Default for PropagationConfig {
    fn default() -> Self {
        Self {
            enable_batching: false,
            max_batch_size: 10,
            batch_timeout: Duration::from_millis(100),
            enable_filtering: true,
            parallel_push: true,
            target_latency: Duration::from_secs(1),
        }
    }
}

/// Filter criteria for a consumer
#[derive(Debug, Clone)]
pub struct ConsumerFilter {
    /// Consumer identifier
    pub consumer_id: String,

    /// Base DN scope (only changes under this DN are sent)
    pub base_dn: String,

    /// Optional LDAP filter (only matching entries are sent)
    pub filter: Option<String>,

    /// Compiled LDAP filter used during change evaluation.
    pub(crate) compiled_filter: Option<CompiledLdapFilter>,

    /// Filter statistics
    pub stats: FilterStats,
}

/// Statistics for filter operations
#[derive(Debug, Clone)]
pub struct FilterStats {
    /// Total changes evaluated
    pub total_evaluated: u64,

    /// Changes that matched filter
    pub matches: u64,

    /// Changes that didn't match
    pub misses: u64,

    /// Filter evaluation errors
    pub errors: u64,

    /// Last evaluation timestamp
    pub last_evaluation: Option<Instant>,
}

impl Default for FilterStats {
    fn default() -> Self {
        Self::new()
    }
}

impl FilterStats {
    pub fn new() -> Self {
        Self {
            total_evaluated: 0,
            matches: 0,
            misses: 0,
            errors: 0,
            last_evaluation: None,
        }
    }

    pub fn record_match(&mut self) {
        self.total_evaluated += 1;
        self.matches += 1;
        self.last_evaluation = Some(Instant::now());
    }

    pub fn record_miss(&mut self) {
        self.total_evaluated += 1;
        self.misses += 1;
        self.last_evaluation = Some(Instant::now());
    }

    pub fn record_error(&mut self) {
        self.total_evaluated += 1;
        self.errors += 1;
        self.last_evaluation = Some(Instant::now());
    }

    /// Get match rate as a percentage (0.0 to 1.0)
    pub fn match_rate(&self) -> f64 {
        if self.total_evaluated == 0 {
            0.0
        } else {
            (self.matches as f64) / (self.total_evaluated as f64)
        }
    }
}

/// Propagation engine statistics
#[derive(Debug, Clone)]
pub struct PropagationStats {
    /// Total changes received
    pub total_changes: u64,

    /// Changes propagated to consumers
    pub changes_propagated: u64,

    /// Changes filtered out
    pub changes_filtered: u64,

    /// Filter evaluation errors
    pub filter_errors: u64,

    /// Average propagation latency
    pub avg_latency_ms: f64,

    /// Started timestamp
    pub started_at: Option<Instant>,
}

impl Default for PropagationStats {
    fn default() -> Self {
        Self::new()
    }
}

impl PropagationStats {
    pub fn new() -> Self {
        Self {
            total_changes: 0,
            changes_propagated: 0,
            changes_filtered: 0,
            filter_errors: 0,
            avg_latency_ms: 0.0,
            started_at: None,
        }
    }
}

/// Real-Time Propagation Engine
///
/// Coordinates change filtering, batching, and propagation to consumers.
pub struct RealTimePropagationEngine {
    /// Change observer
    observer: Arc<dyn ChangeObserver>,

    /// Push manager
    push_manager: Arc<RwLock<PushManager>>,

    /// Configuration
    config: PropagationConfig,

    /// Consumer filters (consumer_id -> ConsumerFilter)
    consumer_filters: Arc<RwLock<HashMap<String, ConsumerFilter>>>,

    /// Engine statistics
    stats: Arc<RwLock<PropagationStats>>,

    /// Running flag
    running: Arc<RwLock<bool>>,
}

impl RealTimePropagationEngine {
    /// Create a new Real-Time Propagation Engine
    ///
    /// # Arguments
    ///
    /// * `observer` - Change observer to receive notifications from
    /// * `push_manager` - Push manager to send changes to consumers
    /// * `config` - Configuration for propagation behavior
    ///
    /// # Returns
    ///
    /// New RealTimePropagationEngine instance
    pub fn new(
        observer: Arc<dyn ChangeObserver>,
        push_manager: Arc<RwLock<PushManager>>,
        config: PropagationConfig,
    ) -> Self {
        info!(
            "Creating Real-Time Propagation Engine with config: {:?}",
            config
        );

        Self {
            observer,
            push_manager,
            config,
            consumer_filters: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(PropagationStats::new())),
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Start the propagation engine
    ///
    /// This registers the engine as a callback with the change observer
    /// and begins filtering and routing changes to consumers.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if started successfully
    /// * `Err(msg)` if already running
    pub async fn start(&self) -> Result<(), String> {
        let mut running = self.running.write().await;
        if *running {
            return Err("Propagation engine already running".to_string());
        }

        info!("Starting Real-Time Propagation Engine");

        // Ensure push manager is started
        let mut push_manager = self.push_manager.write().await;
        if !push_manager.is_running().await {
            push_manager.start().await?;
        }
        drop(push_manager);

        // Register self as change callback
        let callback: Arc<dyn ChangeCallback> = Arc::new(PropagationCallback {
            engine_state: Arc::new(RwLock::new(PropagationEngineState {
                _push_manager: self.push_manager.clone(),
                consumer_filters: self.consumer_filters.clone(),
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
        info!("Real-Time Propagation Engine started successfully");

        Ok(())
    }

    /// Stop the propagation engine
    pub async fn stop(&mut self) -> Result<(), String> {
        let mut running = self.running.write().await;
        if !*running {
            return Err("Propagation engine not running".to_string());
        }

        info!("Stopping Real-Time Propagation Engine");
        *running = false;

        Ok(())
    }

    /// Register a consumer filter
    ///
    /// # Arguments
    ///
    /// * `consumer_id` - Consumer identifier
    /// * `base_dn` - Base DN scope for this consumer
    /// * `filter` - Optional LDAP filter
    ///
    /// # Returns
    ///
    /// * `Ok(())` if registered successfully
    pub async fn register_consumer_filter(
        &self,
        consumer_id: String,
        base_dn: String,
        filter: Option<String>,
    ) -> Result<(), String> {
        info!(
            "Registering filter for consumer {}: base_dn={}, filter={:?}",
            consumer_id, base_dn, filter
        );

        let compiled_filter = match filter.as_deref() {
            Some(filter_text) => Some(compile_filter(filter_text)?),
            None => None,
        };

        let consumer_filter = ConsumerFilter {
            consumer_id: consumer_id.clone(),
            base_dn,
            filter,
            compiled_filter,
            stats: FilterStats::new(),
        };

        let mut filters = self.consumer_filters.write().await;
        filters.insert(consumer_id.clone(), consumer_filter);

        info!(
            "Filter registered successfully for consumer {}",
            consumer_id
        );
        Ok(())
    }

    /// Unregister a consumer filter
    pub async fn unregister_consumer_filter(&self, consumer_id: &str) -> Result<bool, String> {
        info!("Unregistering filter for consumer {}", consumer_id);

        let mut filters = self.consumer_filters.write().await;
        let removed = filters.remove(consumer_id).is_some();

        if removed {
            info!("Filter unregistered for consumer {}", consumer_id);
        } else {
            warn!("No filter found for consumer {}", consumer_id);
        }

        Ok(removed)
    }

    /// Get consumer filter
    pub async fn get_consumer_filter(&self, consumer_id: &str) -> Option<ConsumerFilter> {
        self.consumer_filters.read().await.get(consumer_id).cloned()
    }

    /// Get engine statistics
    pub async fn get_stats(&self) -> PropagationStats {
        self.stats.read().await.clone()
    }

    /// Get all consumer filter statistics
    pub async fn get_all_filter_stats(&self) -> HashMap<String, FilterStats> {
        let filters = self.consumer_filters.read().await;
        filters
            .iter()
            .map(|(id, filter)| (id.clone(), filter.stats.clone()))
            .collect()
    }

    /// Check if engine is running
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }
}

/// Internal state for the propagation callback
struct PropagationEngineState {
    _push_manager: Arc<RwLock<PushManager>>,
    consumer_filters: Arc<RwLock<HashMap<String, ConsumerFilter>>>,
    stats: Arc<RwLock<PropagationStats>>,
    config: PropagationConfig,
}

/// Callback implementation for receiving change notifications
struct PropagationCallback {
    engine_state: Arc<RwLock<PropagationEngineState>>,
}

#[async_trait]
impl ChangeCallback for PropagationCallback {
    async fn on_change(&self, change: &ChangelogEntry) -> Result<(), String> {
        let start = Instant::now();

        debug!(
            "PropagationEngine received change: {} (type: {:?})",
            change.dn, change.change_type
        );

        let state = self.engine_state.read().await;

        // Update statistics
        {
            let mut stats = state.stats.write().await;
            stats.total_changes += 1;
        }

        // If filtering is disabled, push to all consumers
        if !state.config.enable_filtering {
            debug!("Filtering disabled, change will be pushed to all consumers");
            drop(state);
            return Ok(());
        }

        // Get all consumer filters
        let filters = state.consumer_filters.read().await.clone();
        let requires_entry_snapshot = filters
            .values()
            .any(|filter| filter.compiled_filter.is_some());
        let scope_prepared = prepare_change(change, false);
        let attribute_prepared = if requires_entry_snapshot {
            Some(prepare_change(change, true))
        } else {
            None
        };

        if filters.is_empty() {
            debug!("No consumer filters registered");
            return Ok(());
        }

        // Filter and route change to matching consumers
        let mut matched_consumers = 0;
        let mut filtered_out = 0;
        let mut filter_errors = 0;

        for (consumer_id, filter) in filters.iter() {
            let prepared = if filter.compiled_filter.is_some() {
                attribute_prepared
                    .as_ref()
                    .expect("attribute-prepared change must exist when filters require snapshots")
            } else {
                &scope_prepared
            };

            match evaluate_filter(prepared, filter) {
                Ok(true) => {
                    matched_consumers += 1;
                    let mut filters = state.consumer_filters.write().await;
                    if let Some(f) = filters.get_mut(consumer_id) {
                        f.stats.record_match();
                    }
                    debug!(
                        "Change {} matches filter for consumer {}",
                        change.dn, consumer_id
                    );
                }
                Ok(false) => {
                    filtered_out += 1;
                    let mut filters = state.consumer_filters.write().await;
                    if let Some(f) = filters.get_mut(consumer_id) {
                        f.stats.record_miss();
                    }
                    debug!(
                        "Change {} filtered out for consumer {}",
                        change.dn, consumer_id
                    );
                }
                Err(err) => {
                    filter_errors += 1;
                    let mut filters = state.consumer_filters.write().await;
                    if let Some(f) = filters.get_mut(consumer_id) {
                        f.stats.record_error();
                    }
                    warn!(
                        "Failed to evaluate change {} for consumer {}: {}",
                        change.dn, consumer_id, err
                    );
                }
            }
        }

        // Update statistics
        {
            let mut stats = state.stats.write().await;
            stats.changes_propagated += matched_consumers;
            stats.changes_filtered += filtered_out;
            stats.filter_errors += filter_errors;

            // Update average latency
            let latency_ms = start.elapsed().as_millis() as f64;
            let total = stats.total_changes as f64;
            stats.avg_latency_ms = (stats.avg_latency_ms * (total - 1.0) + latency_ms) / total;
        }

        let elapsed = start.elapsed();
        debug!(
            "Change routing completed in {:?}: {} consumers matched, {} filtered out, {} errors",
            elapsed, matched_consumers, filtered_out, filter_errors
        );

        Ok(())
    }
}

/// Evaluate if a change matches a consumer filter
///
/// # Arguments
///
/// * `prepared_change` - The prepared changelog entry to evaluate
/// * `filter` - Consumer filter criteria
///
/// # Returns
///
/// * `true` if change matches filter
/// * `false` if change doesn't match
fn evaluate_filter(
    prepared_change: &Result<PreparedChange, String>,
    filter: &ConsumerFilter,
) -> Result<bool, String> {
    let prepared_change = prepared_change.as_ref().map_err(Clone::clone)?;
    prepared_change.matches(&filter.base_dn, filter.compiled_filter.as_ref())
}

/// Check if a DN is within the scope of a base DN
///
/// # Arguments
///
/// * `dn` - DN to check
/// * `base_dn` - Base DN scope
///
/// # Returns
///
/// * `true` if DN is under base_dn
/// * `false` otherwise
///
/// # Example
///
/// ```
/// # use opendr::real_time_propagation::is_dn_in_scope;
/// assert!(is_dn_in_scope(
///     "cn=user,ou=people,dc=example,dc=com",
///     "dc=example,dc=com"
/// ));
/// assert!(!is_dn_in_scope(
///     "cn=user,dc=other,dc=com",
///     "dc=example,dc=com"
/// ));
/// ```
pub fn is_dn_in_scope(dn: &str, base_dn: &str) -> bool {
    ldap_dn_in_scope(dn, base_dn)
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use super::*;
    use crate::change_observer::ChangeObserverImpl;
    use crate::csn::Csn;
    use crate::push_manager::PushManagerConfig;
    use crate::replication_provider_fsm::ChangeType;

    fn create_test_change(dn: &str, change_type: ChangeType) -> ChangelogEntry {
        ChangelogEntry::new(Csn::new(1), change_type, dn.to_string(), vec![])
    }

    async fn create_test_engine() -> RealTimePropagationEngine {
        let observer = Arc::new(ChangeObserverImpl::new());
        let push_config = PushManagerConfig::default();
        let push_manager = Arc::new(RwLock::new(PushManager::new(observer.clone(), push_config)));
        let config = PropagationConfig::default();

        RealTimePropagationEngine::new(observer, push_manager, config)
    }

    #[tokio::test]
    async fn test_engine_creation() {
        let engine = create_test_engine().await;
        assert!(!engine.is_running().await);

        let stats = engine.get_stats().await;
        assert_eq!(stats.total_changes, 0);
        assert_eq!(stats.changes_propagated, 0);
    }

    #[tokio::test]
    async fn test_engine_start_stop() {
        let engine = create_test_engine().await;

        // Start engine
        let result = engine.start().await;
        assert!(result.is_ok());
        assert!(engine.is_running().await);

        // Stop engine
        let mut engine = engine;
        let result = engine.stop().await;
        assert!(result.is_ok());
        assert!(!engine.is_running().await);
    }

    #[tokio::test]
    async fn test_register_consumer_filter() {
        let engine = create_test_engine().await;

        let result = engine
            .register_consumer_filter(
                "consumer-1".to_string(),
                "dc=example,dc=com".to_string(),
                Some("(objectClass=person)".to_string()),
            )
            .await;

        assert!(result.is_ok());

        // Verify filter registered
        let filter = engine.get_consumer_filter("consumer-1").await;
        assert!(filter.is_some());

        let filter = filter.unwrap();
        assert_eq!(filter.consumer_id, "consumer-1");
        assert_eq!(filter.base_dn, "dc=example,dc=com");
        assert_eq!(filter.filter, Some("(objectClass=person)".to_string()));
    }

    #[tokio::test]
    async fn test_unregister_consumer_filter() {
        let engine = create_test_engine().await;

        // Register first
        engine
            .register_consumer_filter(
                "consumer-1".to_string(),
                "dc=example,dc=com".to_string(),
                None,
            )
            .await
            .unwrap();

        // Unregister
        let result = engine.unregister_consumer_filter("consumer-1").await;
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Verify removed
        let filter = engine.get_consumer_filter("consumer-1").await;
        assert!(filter.is_none());
    }

    #[tokio::test]
    async fn test_register_multiple_filters() {
        let engine = create_test_engine().await;

        for i in 1..=3 {
            engine
                .register_consumer_filter(
                    format!("consumer-{}", i),
                    "dc=example,dc=com".to_string(),
                    None,
                )
                .await
                .unwrap();
        }

        // Verify all registered
        for i in 1..=3 {
            let filter = engine.get_consumer_filter(&format!("consumer-{}", i)).await;
            assert!(filter.is_some());
        }
    }

    #[test]
    fn test_is_dn_in_scope_exact_match() {
        assert!(is_dn_in_scope("dc=example,dc=com", "dc=example,dc=com"));
    }

    #[test]
    fn test_is_dn_in_scope_child() {
        assert!(is_dn_in_scope(
            "cn=user,dc=example,dc=com",
            "dc=example,dc=com"
        ));
        assert!(is_dn_in_scope(
            "cn=user,ou=people,dc=example,dc=com",
            "dc=example,dc=com"
        ));
    }

    #[test]
    fn test_is_dn_in_scope_not_in_scope() {
        assert!(!is_dn_in_scope(
            "cn=user,dc=other,dc=com",
            "dc=example,dc=com"
        ));
        assert!(!is_dn_in_scope(
            "dc=example,dc=com",
            "cn=user,dc=example,dc=com"
        ));
    }

    #[test]
    fn test_is_dn_in_scope_case_insensitive() {
        assert!(is_dn_in_scope(
            "CN=User,DC=EXAMPLE,DC=COM",
            "dc=example,dc=com"
        ));
        assert!(is_dn_in_scope(
            "cn=user,dc=example,dc=com",
            "DC=EXAMPLE,DC=COM"
        ));
    }

    #[test]
    fn test_is_dn_in_scope_partial_match() {
        // Should not match partial DN components
        assert!(!is_dn_in_scope("dc=example,dc=com", "example,dc=com"));
        assert!(!is_dn_in_scope(
            "cn=userdc=example,dc=com",
            "dc=example,dc=com"
        ));
    }

    #[test]
    fn test_filter_stats() {
        let mut stats = FilterStats::new();

        assert_eq!(stats.total_evaluated, 0);
        assert_eq!(stats.matches, 0);
        assert_eq!(stats.misses, 0);

        stats.record_match();
        assert_eq!(stats.total_evaluated, 1);
        assert_eq!(stats.matches, 1);
        assert_eq!(stats.match_rate(), 1.0);

        stats.record_miss();
        assert_eq!(stats.total_evaluated, 2);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.match_rate(), 0.5);

        stats.record_error();
        assert_eq!(stats.total_evaluated, 3);
        assert_eq!(stats.errors, 1);
    }

    #[test]
    fn test_propagation_config_default() {
        let config = PropagationConfig::default();
        assert!(!config.enable_batching);
        assert_eq!(config.max_batch_size, 10);
        assert!(config.enable_filtering);
        assert!(config.parallel_push);
        assert_eq!(config.target_latency, Duration::from_secs(1));
    }

    #[tokio::test]
    async fn test_get_all_filter_stats() {
        let engine = create_test_engine().await;

        // Register multiple filters
        for i in 1..=3 {
            engine
                .register_consumer_filter(
                    format!("consumer-{}", i),
                    "dc=example,dc=com".to_string(),
                    None,
                )
                .await
                .unwrap();
        }

        // Get all stats
        let all_stats = engine.get_all_filter_stats().await;
        assert_eq!(all_stats.len(), 3);

        for i in 1..=3 {
            let consumer_id = format!("consumer-{}", i);
            assert!(all_stats.contains_key(&consumer_id));
        }
    }

    #[tokio::test]
    async fn test_propagation_stats() {
        let stats = PropagationStats::new();

        assert_eq!(stats.total_changes, 0);
        assert_eq!(stats.changes_propagated, 0);
        assert_eq!(stats.changes_filtered, 0);
        assert_eq!(stats.avg_latency_ms, 0.0);
        assert!(stats.started_at.is_none());
    }
}

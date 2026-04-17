//! Metrics Collection and Monitoring for OpenDR LDAP Server
//!
//! This module provides comprehensive operational visibility and performance tracking
//! for the LDAP server, including Prometheus-compatible metrics export, operation
//! counters, latency histograms, FSM state distribution monitoring, and health checks.
//!
//! ## Features
//!
//! - **Prometheus Metrics Export**: Standard Prometheus text format for easy integration
//! - **Operation Metrics**: Track counts, latencies, and success/failure rates for all LDAP operations
//! - **FSM State Monitoring**: Monitor state distribution across all finite state machines
//! - **Connection Metrics**: Track active connections, connection rates, and lifecycle
//! - **Backend Metrics**: Monitor backend operations, cache hits/misses, and performance
//! - **Health Checks**: Comprehensive health status with dependency checking
//! - **Custom Metrics**: Extensible framework for application-specific metrics
//!
//! ## Usage Example
//!
//! ```rust,no_run
//! use opendr::metrics::{MetricsCollector, OperationType};
//! use std::time::Duration;
//!
//! # async fn example() {
//! let metrics = MetricsCollector::new();
//!
//! // Record operation
//! metrics.record_operation_start(OperationType::Bind, "127.0.0.1:1234");
//! // ... perform operation ...
//! metrics.record_operation_complete(OperationType::Bind, Duration::from_millis(10), true);
//!
//! // Export Prometheus metrics
//! let prometheus_output = metrics.export_prometheus();
//! println!("{}", prometheus_output);
//!
//! // Check health
//! let health = metrics.health_check().await;
//! assert!(health.is_healthy());
//! # }
//! ```

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// LDAP operation types for metrics tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperationType {
    Bind,
    Unbind,
    Search,
    Modify,
    Add,
    Delete,
    ModifyDN,
    Compare,
    Extended,
    Abandon,
}

impl OperationType {
    /// Get the operation name as a string
    pub fn as_str(&self) -> &'static str {
        match self {
            OperationType::Bind => "bind",
            OperationType::Unbind => "unbind",
            OperationType::Search => "search",
            OperationType::Modify => "modify",
            OperationType::Add => "add",
            OperationType::Delete => "delete",
            OperationType::ModifyDN => "modifydn",
            OperationType::Compare => "compare",
            OperationType::Extended => "extended",
            OperationType::Abandon => "abandon",
        }
    }

    /// Get all operation types
    pub fn all() -> Vec<OperationType> {
        vec![
            OperationType::Bind,
            OperationType::Unbind,
            OperationType::Search,
            OperationType::Modify,
            OperationType::Add,
            OperationType::Delete,
            OperationType::ModifyDN,
            OperationType::Compare,
            OperationType::Extended,
            OperationType::Abandon,
        ]
    }
}

/// FSM state types for monitoring
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FsmType {
    Connection,
    BerDecoder,
    Auth,
    Sasl,
    Search,
    Write,
    Compare,
    ExtendedOp,
    Referral,
    ReplicationProvider,
    ReplicationConsumer,
    BackendTxn,
}

/// Resource events that should be surfaced to observability and future FSM hooks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceEventType {
    ConnectionRejected,
    OperationRejected,
    MemoryRejected,
    RateLimitBlocked,
    RateLimitAllowed,
    IdleConnectionEvicted,
}

impl FsmType {
    /// Get the FSM type name as a string
    pub fn as_str(&self) -> &str {
        match self {
            FsmType::Connection => "connection",
            FsmType::BerDecoder => "ber_decoder",
            FsmType::Auth => "auth",
            FsmType::Sasl => "sasl",
            FsmType::Search => "search",
            FsmType::Write => "write",
            FsmType::Compare => "compare",
            FsmType::ExtendedOp => "extended_op",
            FsmType::Referral => "referral",
            FsmType::ReplicationProvider => "replication_provider",
            FsmType::ReplicationConsumer => "replication_consumer",
            FsmType::BackendTxn => "backend_txn",
        }
    }
}

/// Operation metrics for a specific operation type
#[derive(Debug, Default)]
struct OperationMetrics {
    /// Total number of operations started
    count: AtomicU64,
    /// Number of successful operations
    success: AtomicU64,
    /// Number of failed operations
    failures: AtomicU64,
    /// Total latency in nanoseconds
    total_latency_ns: AtomicU64,
    /// Minimum latency in nanoseconds
    min_latency_ns: AtomicU64,
    /// Maximum latency in nanoseconds
    max_latency_ns: AtomicU64,
    /// Active operations currently in progress
    active: AtomicUsize,
}

impl OperationMetrics {
    fn new() -> Self {
        Self {
            count: AtomicU64::new(0),
            success: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            total_latency_ns: AtomicU64::new(0),
            min_latency_ns: AtomicU64::new(u64::MAX),
            max_latency_ns: AtomicU64::new(0),
            active: AtomicUsize::new(0),
        }
    }

    fn start_operation(&self) {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.active.fetch_add(1, Ordering::Relaxed);
    }

    fn complete_operation(&self, duration: Duration, success: bool) {
        self.active.fetch_sub(1, Ordering::Relaxed);

        if success {
            self.success.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failures.fetch_add(1, Ordering::Relaxed);
        }

        let latency_ns = duration.as_nanos() as u64;
        self.total_latency_ns
            .fetch_add(latency_ns, Ordering::Relaxed);

        // Update min latency
        let mut current_min = self.min_latency_ns.load(Ordering::Relaxed);
        while latency_ns < current_min {
            match self.min_latency_ns.compare_exchange(
                current_min,
                latency_ns,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(new_min) => current_min = new_min,
            }
        }

        // Update max latency
        let mut current_max = self.max_latency_ns.load(Ordering::Relaxed);
        while latency_ns > current_max {
            match self.max_latency_ns.compare_exchange(
                current_max,
                latency_ns,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(new_max) => current_max = new_max,
            }
        }
    }

    fn get_stats(&self) -> OperationStats {
        let count = self.count.load(Ordering::Relaxed);
        let success = self.success.load(Ordering::Relaxed);
        let failures = self.failures.load(Ordering::Relaxed);
        let total_latency_ns = self.total_latency_ns.load(Ordering::Relaxed);
        let min_latency_ns = self.min_latency_ns.load(Ordering::Relaxed);
        let max_latency_ns = self.max_latency_ns.load(Ordering::Relaxed);
        let active = self.active.load(Ordering::Relaxed);

        let avg_latency_ns = total_latency_ns.checked_div(count).unwrap_or(0);

        OperationStats {
            count,
            success,
            failures,
            active,
            avg_latency_ns,
            min_latency_ns: if min_latency_ns == u64::MAX {
                0
            } else {
                min_latency_ns
            },
            max_latency_ns,
        }
    }
}

/// Statistics for a specific operation type
#[derive(Debug, Clone)]
pub struct OperationStats {
    pub count: u64,
    pub success: u64,
    pub failures: u64,
    pub active: usize,
    pub avg_latency_ns: u64,
    pub min_latency_ns: u64,
    pub max_latency_ns: u64,
}

/// Connection metrics
#[derive(Debug, Default)]
struct ConnectionMetrics {
    /// Total connections accepted
    total_connections: AtomicU64,
    /// Currently active connections
    active_connections: AtomicUsize,
    /// Total connections closed
    closed_connections: AtomicU64,
    /// Failed connection attempts
    failed_connections: AtomicU64,
}

/// Resource event metrics used to bridge connection/resource/rate-limit state into monitoring.
#[derive(Debug, Default)]
struct ResourceMetrics {
    connection_rejections: AtomicU64,
    operation_rejections: AtomicU64,
    memory_rejections: AtomicU64,
    rate_limit_blocks: AtomicU64,
    rate_limit_allows: AtomicU64,
    idle_connection_evictions: AtomicU64,
}

#[derive(Debug, Default)]
struct AuthCacheMetrics {
    capacity: AtomicU64,
    entries: AtomicU64,
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
}

impl AuthCacheMetrics {
    fn new() -> Self {
        Self::default()
    }

    fn record_snapshot(&self, capacity: u64, entries: u64, hits: u64, misses: u64, evictions: u64) {
        self.capacity.store(capacity, Ordering::Relaxed);
        self.entries.store(entries, Ordering::Relaxed);
        self.hits.store(hits, Ordering::Relaxed);
        self.misses.store(misses, Ordering::Relaxed);
        self.evictions.store(evictions, Ordering::Relaxed);
    }

    fn get_stats(&self) -> AuthCacheStats {
        AuthCacheStats {
            capacity: self.capacity.load(Ordering::Relaxed),
            entries: self.entries.load(Ordering::Relaxed),
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
        }
    }
}

impl ResourceMetrics {
    fn new() -> Self {
        Self::default()
    }

    fn record_event(&self, event: ResourceEventType) {
        match event {
            ResourceEventType::ConnectionRejected => {
                self.connection_rejections.fetch_add(1, Ordering::Relaxed);
            }
            ResourceEventType::OperationRejected => {
                self.operation_rejections.fetch_add(1, Ordering::Relaxed);
            }
            ResourceEventType::MemoryRejected => {
                self.memory_rejections.fetch_add(1, Ordering::Relaxed);
            }
            ResourceEventType::RateLimitBlocked => {
                self.rate_limit_blocks.fetch_add(1, Ordering::Relaxed);
            }
            ResourceEventType::RateLimitAllowed => {
                self.rate_limit_allows.fetch_add(1, Ordering::Relaxed);
            }
            ResourceEventType::IdleConnectionEvicted => {
                self.idle_connection_evictions
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn get_stats(&self) -> ResourceStats {
        ResourceStats {
            connection_rejections: self.connection_rejections.load(Ordering::Relaxed),
            operation_rejections: self.operation_rejections.load(Ordering::Relaxed),
            memory_rejections: self.memory_rejections.load(Ordering::Relaxed),
            rate_limit_blocks: self.rate_limit_blocks.load(Ordering::Relaxed),
            rate_limit_allows: self.rate_limit_allows.load(Ordering::Relaxed),
            idle_connection_evictions: self.idle_connection_evictions.load(Ordering::Relaxed),
        }
    }
}

/// Resource event statistics for observability scaffolding.
#[derive(Debug, Clone, Default)]
pub struct ResourceStats {
    pub connection_rejections: u64,
    pub operation_rejections: u64,
    pub memory_rejections: u64,
    pub rate_limit_blocks: u64,
    pub rate_limit_allows: u64,
    pub idle_connection_evictions: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AuthCacheStats {
    pub capacity: u64,
    pub entries: u64,
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
}

impl ConnectionMetrics {
    fn new() -> Self {
        Self::default()
    }

    fn connection_accepted(&self) {
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    fn connection_closed(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
        self.closed_connections.fetch_add(1, Ordering::Relaxed);
    }

    fn connection_failed(&self) {
        self.failed_connections.fetch_add(1, Ordering::Relaxed);
    }

    fn get_stats(&self) -> ConnectionStats {
        ConnectionStats {
            total: self.total_connections.load(Ordering::Relaxed),
            active: self.active_connections.load(Ordering::Relaxed),
            closed: self.closed_connections.load(Ordering::Relaxed),
            failed: self.failed_connections.load(Ordering::Relaxed),
        }
    }
}

/// Connection statistics
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub total: u64,
    pub active: usize,
    pub closed: u64,
    pub failed: u64,
}

/// FSM state distribution tracker
#[derive(Debug)]
struct FsmStateTracker {
    states: RwLock<HashMap<String, AtomicUsize>>,
}

impl FsmStateTracker {
    fn new() -> Self {
        Self {
            states: RwLock::new(HashMap::new()),
        }
    }

    fn record_state(&self, fsm_type: &FsmType, state: &str) {
        let key = format!("{}:{}", fsm_type.as_str(), state);
        let states = self.states.read().unwrap();

        if let Some(counter) = states.get(&key) {
            counter.fetch_add(1, Ordering::Relaxed);
        } else {
            drop(states);
            let mut states = self.states.write().unwrap();
            states
                .entry(key)
                .or_insert_with(|| AtomicUsize::new(0))
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    fn get_distribution(&self) -> HashMap<String, usize> {
        let states = self.states.read().unwrap();
        states
            .iter()
            .map(|(k, v)| (k.clone(), v.load(Ordering::Relaxed)))
            .collect()
    }
}

/// Health status for a component
#[derive(Debug, Clone, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

impl HealthStatus {
    pub fn is_healthy(&self) -> bool {
        matches!(self, HealthStatus::Healthy)
    }

    pub fn as_str(&self) -> &str {
        match self {
            HealthStatus::Healthy => "healthy",
            HealthStatus::Degraded => "degraded",
            HealthStatus::Unhealthy => "unhealthy",
        }
    }
}

/// Overall health check result
#[derive(Debug, Clone)]
pub struct HealthCheck {
    pub status: HealthStatus,
    pub timestamp: SystemTime,
    pub uptime_seconds: u64,
    pub components: HashMap<String, HealthStatus>,
    pub details: Vec<String>,
}

impl HealthCheck {
    pub fn is_healthy(&self) -> bool {
        self.status.is_healthy()
    }
}

/// Main metrics collector
pub struct MetricsCollector {
    /// Server start time
    start_time: Instant,
    /// Operation metrics by type
    operations: HashMap<OperationType, OperationMetrics>,
    /// Connection metrics
    connections: ConnectionMetrics,
    /// Resource metrics
    resources: ResourceMetrics,
    /// Authentication credential cache metrics
    auth_cache: AuthCacheMetrics,
    /// FSM state distribution
    fsm_states: FsmStateTracker,
    /// Custom counters
    custom_counters: RwLock<HashMap<String, AtomicU64>>,
    /// Custom gauges
    custom_gauges: RwLock<HashMap<String, AtomicU64>>,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new() -> Arc<Self> {
        let mut operations = HashMap::new();
        for op_type in OperationType::all() {
            operations.insert(op_type, OperationMetrics::new());
        }

        Arc::new(Self {
            start_time: Instant::now(),
            operations,
            connections: ConnectionMetrics::new(),
            resources: ResourceMetrics::new(),
            auth_cache: AuthCacheMetrics::new(),
            fsm_states: FsmStateTracker::new(),
            custom_counters: RwLock::new(HashMap::new()),
            custom_gauges: RwLock::new(HashMap::new()),
        })
    }

    /// Get uptime in seconds
    pub fn uptime_seconds(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Record operation start
    pub fn record_operation_start(&self, op_type: OperationType, _client: &str) {
        if let Some(metrics) = self.operations.get(&op_type) {
            metrics.start_operation();
        }
    }

    /// Record operation completion
    pub fn record_operation_complete(
        &self,
        op_type: OperationType,
        duration: Duration,
        success: bool,
    ) {
        if let Some(metrics) = self.operations.get(&op_type) {
            metrics.complete_operation(duration, success);
        }
    }

    /// Get operation statistics
    pub fn get_operation_stats(&self, op_type: OperationType) -> Option<OperationStats> {
        self.operations.get(&op_type).map(|m| m.get_stats())
    }

    /// Get all operation statistics
    pub fn get_all_operation_stats(&self) -> HashMap<OperationType, OperationStats> {
        self.operations
            .iter()
            .map(|(op, metrics)| (*op, metrics.get_stats()))
            .collect()
    }

    /// Record connection accepted
    pub fn record_connection_accepted(&self) {
        self.connections.connection_accepted();
    }

    /// Record connection closed
    pub fn record_connection_closed(&self) {
        self.connections.connection_closed();
    }

    /// Record connection failed
    pub fn record_connection_failed(&self) {
        self.connections.connection_failed();
    }

    /// Record a resource-related event for future FSM and monitoring hooks.
    pub fn record_resource_event(&self, event: ResourceEventType) {
        self.resources.record_event(event);
    }

    /// Get connection statistics
    pub fn get_connection_stats(&self) -> ConnectionStats {
        self.connections.get_stats()
    }

    /// Get resource event statistics.
    pub fn get_resource_stats(&self) -> ResourceStats {
        self.resources.get_stats()
    }

    pub fn record_auth_cache_stats(
        &self,
        capacity: u64,
        entries: u64,
        hits: u64,
        misses: u64,
        evictions: u64,
    ) {
        self.auth_cache
            .record_snapshot(capacity, entries, hits, misses, evictions);
    }

    pub fn get_auth_cache_stats(&self) -> AuthCacheStats {
        self.auth_cache.get_stats()
    }

    /// Record FSM state
    pub fn record_fsm_state(&self, fsm_type: FsmType, state: &str) {
        self.fsm_states.record_state(&fsm_type, state);
    }

    /// Get FSM state distribution
    pub fn get_fsm_state_distribution(&self) -> HashMap<String, usize> {
        self.fsm_states.get_distribution()
    }

    /// Increment a custom counter
    pub fn increment_counter(&self, name: &str, value: u64) {
        let counters = self.custom_counters.read().unwrap();
        if let Some(counter) = counters.get(name) {
            counter.fetch_add(value, Ordering::Relaxed);
        } else {
            drop(counters);
            let mut counters = self.custom_counters.write().unwrap();
            counters
                .entry(name.to_string())
                .or_insert_with(|| AtomicU64::new(0))
                .fetch_add(value, Ordering::Relaxed);
        }
    }

    /// Set a custom gauge value
    pub fn set_gauge(&self, name: &str, value: u64) {
        let gauges = self.custom_gauges.read().unwrap();
        if let Some(gauge) = gauges.get(name) {
            gauge.store(value, Ordering::Relaxed);
        } else {
            drop(gauges);
            let mut gauges = self.custom_gauges.write().unwrap();
            gauges
                .entry(name.to_string())
                .or_insert_with(|| AtomicU64::new(0))
                .store(value, Ordering::Relaxed);
        }
    }

    /// Get custom counter value
    pub fn get_counter(&self, name: &str) -> Option<u64> {
        let counters = self.custom_counters.read().unwrap();
        counters.get(name).map(|c| c.load(Ordering::Relaxed))
    }

    /// Get custom gauge value
    pub fn get_gauge(&self, name: &str) -> Option<u64> {
        let gauges = self.custom_gauges.read().unwrap();
        gauges.get(name).map(|g| g.load(Ordering::Relaxed))
    }

    /// Export metrics in Prometheus text format
    pub fn export_prometheus(&self) -> String {
        let mut output = String::new();

        // Server uptime
        output.push_str("# HELP ldap_server_uptime_seconds Server uptime in seconds\n");
        output.push_str("# TYPE ldap_server_uptime_seconds gauge\n");
        output.push_str(&format!(
            "ldap_server_uptime_seconds {}\n",
            self.uptime_seconds()
        ));
        output.push('\n');

        // Connection metrics
        let conn_stats = self.get_connection_stats();
        output.push_str("# HELP ldap_connections_total Total number of connections\n");
        output.push_str("# TYPE ldap_connections_total counter\n");
        output.push_str(&format!("ldap_connections_total {}\n", conn_stats.total));
        output.push('\n');

        output.push_str("# HELP ldap_connections_active Currently active connections\n");
        output.push_str("# TYPE ldap_connections_active gauge\n");
        output.push_str(&format!("ldap_connections_active {}\n", conn_stats.active));
        output.push('\n');

        output.push_str("# HELP ldap_connections_closed Total closed connections\n");
        output.push_str("# TYPE ldap_connections_closed counter\n");
        output.push_str(&format!("ldap_connections_closed {}\n", conn_stats.closed));
        output.push('\n');

        output.push_str("# HELP ldap_connections_failed Total failed connection attempts\n");
        output.push_str("# TYPE ldap_connections_failed counter\n");
        output.push_str(&format!("ldap_connections_failed {}\n", conn_stats.failed));
        output.push('\n');

        // Resource event metrics
        let resource_stats = self.get_resource_stats();
        output.push_str("# HELP ldap_resource_connection_rejections_total Connection rejections due to resource limits\n");
        output.push_str("# TYPE ldap_resource_connection_rejections_total counter\n");
        output.push_str(&format!(
            "ldap_resource_connection_rejections_total {}\n",
            resource_stats.connection_rejections
        ));
        output.push('\n');

        output.push_str("# HELP ldap_resource_operation_rejections_total Operation rejections due to resource limits\n");
        output.push_str("# TYPE ldap_resource_operation_rejections_total counter\n");
        output.push_str(&format!(
            "ldap_resource_operation_rejections_total {}\n",
            resource_stats.operation_rejections
        ));
        output.push('\n');

        output.push_str("# HELP ldap_resource_memory_rejections_total Memory rejections due to resource limits\n");
        output.push_str("# TYPE ldap_resource_memory_rejections_total counter\n");
        output.push_str(&format!(
            "ldap_resource_memory_rejections_total {}\n",
            resource_stats.memory_rejections
        ));
        output.push('\n');

        output.push_str(
            "# HELP ldap_resource_rate_limit_blocks_total Requests blocked by rate limiting\n",
        );
        output.push_str("# TYPE ldap_resource_rate_limit_blocks_total counter\n");
        output.push_str(&format!(
            "ldap_resource_rate_limit_blocks_total {}\n",
            resource_stats.rate_limit_blocks
        ));
        output.push('\n');

        output.push_str(
            "# HELP ldap_resource_rate_limit_allows_total Requests allowed by rate limiting\n",
        );
        output.push_str("# TYPE ldap_resource_rate_limit_allows_total counter\n");
        output.push_str(&format!(
            "ldap_resource_rate_limit_allows_total {}\n",
            resource_stats.rate_limit_allows
        ));
        output.push('\n');

        output.push_str("# HELP ldap_resource_idle_connection_evictions_total Idle connections evicted by cleanup\n");
        output.push_str("# TYPE ldap_resource_idle_connection_evictions_total counter\n");
        output.push_str(&format!(
            "ldap_resource_idle_connection_evictions_total {}\n",
            resource_stats.idle_connection_evictions
        ));
        output.push('\n');

        // Authentication credential cache metrics
        let auth_cache_stats = self.get_auth_cache_stats();
        output.push_str(
            "# HELP ldap_auth_cache_capacity Configured authentication credential cache capacity\n",
        );
        output.push_str("# TYPE ldap_auth_cache_capacity gauge\n");
        output.push_str(&format!(
            "ldap_auth_cache_capacity {}\n",
            auth_cache_stats.capacity
        ));
        output.push('\n');

        output.push_str(
            "# HELP ldap_auth_cache_entries Current authentication credential cache entries\n",
        );
        output.push_str("# TYPE ldap_auth_cache_entries gauge\n");
        output.push_str(&format!(
            "ldap_auth_cache_entries {}\n",
            auth_cache_stats.entries
        ));
        output.push('\n');

        output.push_str("# HELP ldap_auth_cache_hits_total Authentication credential cache hits\n");
        output.push_str("# TYPE ldap_auth_cache_hits_total counter\n");
        output.push_str(&format!(
            "ldap_auth_cache_hits_total {}\n",
            auth_cache_stats.hits
        ));
        output.push('\n');

        output.push_str(
            "# HELP ldap_auth_cache_misses_total Authentication credential cache misses\n",
        );
        output.push_str("# TYPE ldap_auth_cache_misses_total counter\n");
        output.push_str(&format!(
            "ldap_auth_cache_misses_total {}\n",
            auth_cache_stats.misses
        ));
        output.push('\n');

        output.push_str(
            "# HELP ldap_auth_cache_evictions_total Authentication credential cache evictions\n",
        );
        output.push_str("# TYPE ldap_auth_cache_evictions_total counter\n");
        output.push_str(&format!(
            "ldap_auth_cache_evictions_total {}\n",
            auth_cache_stats.evictions
        ));
        output.push('\n');

        // Operation metrics
        for (op_type, stats) in self.get_all_operation_stats() {
            let op_name = op_type.as_str();

            output.push_str(&format!(
                "# HELP ldap_operations_total{{operation=\"{}\"}} Total operations\n",
                op_name
            ));
            output.push_str(&format!(
                "# TYPE ldap_operations_total{{operation=\"{}\"}} counter\n",
                op_name
            ));
            output.push_str(&format!(
                "ldap_operations_total{{operation=\"{}\"}} {}\n",
                op_name, stats.count
            ));
            output.push('\n');

            output.push_str(&format!(
                "ldap_operations_success{{operation=\"{}\"}} {}\n",
                op_name, stats.success
            ));
            output.push_str(&format!(
                "ldap_operations_failures{{operation=\"{}\"}} {}\n",
                op_name, stats.failures
            ));
            output.push_str(&format!(
                "ldap_operations_active{{operation=\"{}\"}} {}\n",
                op_name, stats.active
            ));

            if stats.count > 0 {
                output.push_str(&format!(
                    "ldap_operations_latency_avg_ns{{operation=\"{}\"}} {}\n",
                    op_name, stats.avg_latency_ns
                ));
                output.push_str(&format!(
                    "ldap_operations_latency_min_ns{{operation=\"{}\"}} {}\n",
                    op_name, stats.min_latency_ns
                ));
                output.push_str(&format!(
                    "ldap_operations_latency_max_ns{{operation=\"{}\"}} {}\n",
                    op_name, stats.max_latency_ns
                ));
            }
            output.push('\n');
        }

        // FSM state distribution
        output.push_str("# HELP ldap_fsm_states FSM state distribution\n");
        output.push_str("# TYPE ldap_fsm_states gauge\n");
        for (state_key, count) in self.get_fsm_state_distribution() {
            let parts: Vec<&str> = state_key.split(':').collect();
            if parts.len() == 2 {
                output.push_str(&format!(
                    "ldap_fsm_states{{fsm=\"{}\",state=\"{}\"}} {}\n",
                    parts[0], parts[1], count
                ));
            }
        }
        output.push('\n');

        // Custom counters
        let counters = self.custom_counters.read().unwrap();
        for (name, counter) in counters.iter() {
            output.push_str(&format!(
                "ldap_custom_counter{{name=\"{}\"}} {}\n",
                name,
                counter.load(Ordering::Relaxed)
            ));
        }
        if !counters.is_empty() {
            output.push('\n');
        }
        drop(counters);

        // Custom gauges
        let gauges = self.custom_gauges.read().unwrap();
        for (name, gauge) in gauges.iter() {
            output.push_str(&format!(
                "ldap_custom_gauge{{name=\"{}\"}} {}\n",
                name,
                gauge.load(Ordering::Relaxed)
            ));
        }

        output
    }

    /// Perform health check
    pub async fn health_check(&self) -> HealthCheck {
        let mut components = HashMap::new();
        let mut details = Vec::new();

        // Check connection health
        let conn_stats = self.get_connection_stats();
        let conn_health = if conn_stats.active > 0 || conn_stats.total > 0 {
            HealthStatus::Healthy
        } else {
            HealthStatus::Degraded
        };
        components.insert("connections".to_string(), conn_health.clone());

        if conn_stats.failed > 0 {
            details.push(format!("Failed connections: {}", conn_stats.failed));
        }

        let resource_stats = self.get_resource_stats();
        if resource_stats.connection_rejections > 0
            || resource_stats.operation_rejections > 0
            || resource_stats.memory_rejections > 0
            || resource_stats.rate_limit_blocks > 0
            || resource_stats.idle_connection_evictions > 0
        {
            details.push(format!(
                "Resource events: connection_rejections={}, operation_rejections={}, memory_rejections={}, rate_limit_blocks={}, rate_limit_allows={}, idle_connection_evictions={}",
                resource_stats.connection_rejections,
                resource_stats.operation_rejections,
                resource_stats.memory_rejections,
                resource_stats.rate_limit_blocks,
                resource_stats.rate_limit_allows,
                resource_stats.idle_connection_evictions
            ));
        }

        // Check operation health
        let mut has_failed_ops = false;
        for (op_type, stats) in self.get_all_operation_stats() {
            if stats.failures > 0 {
                has_failed_ops = true;
                details.push(format!(
                    "{} operation failures: {}",
                    op_type.as_str(),
                    stats.failures
                ));
            }
        }

        let ops_health = if has_failed_ops {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };
        components.insert("operations".to_string(), ops_health.clone());

        // Overall status
        let overall_status = if components
            .values()
            .any(|s| matches!(s, HealthStatus::Unhealthy))
        {
            HealthStatus::Unhealthy
        } else if components
            .values()
            .any(|s| matches!(s, HealthStatus::Degraded))
        {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };

        HealthCheck {
            status: overall_status,
            timestamp: SystemTime::now(),
            uptime_seconds: self.uptime_seconds(),
            components,
            details,
        }
    }

    /// Get health check as JSON string
    pub async fn health_check_json(&self) -> String {
        let health = self.health_check().await;
        let timestamp = health
            .timestamp
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut components_json = String::new();
        for (i, (name, status)) in health.components.iter().enumerate() {
            if i > 0 {
                components_json.push(',');
            }
            components_json.push_str(&format!("\"{}\":\"{}\"", name, status.as_str()));
        }

        let mut details_json = String::new();
        for (i, detail) in health.details.iter().enumerate() {
            if i > 0 {
                details_json.push(',');
            }
            details_json.push_str(&format!("\"{}\"", detail.replace('"', "\\\"")));
        }

        format!(
            "{{\"status\":\"{}\",\"timestamp\":{},\"uptime_seconds\":{},\"components\":{{{}}},\"details\":[{}]}}",
            health.status.as_str(),
            timestamp,
            health.uptime_seconds,
            components_json,
            details_json
        )
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        let mut operations = HashMap::new();
        for op_type in OperationType::all() {
            operations.insert(op_type, OperationMetrics::new());
        }

        Self {
            start_time: Instant::now(),
            operations,
            connections: ConnectionMetrics::new(),
            resources: ResourceMetrics::new(),
            auth_cache: AuthCacheMetrics::new(),
            fsm_states: FsmStateTracker::new(),
            custom_counters: RwLock::new(HashMap::new()),
            custom_gauges: RwLock::new(HashMap::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_metrics_collector_new() {
        let metrics = MetricsCollector::new();
        assert!(metrics.uptime_seconds() < 1);

        // All operations should start with zero counts
        for op_type in OperationType::all() {
            let stats = metrics.get_operation_stats(op_type).unwrap();
            assert_eq!(stats.count, 0);
            assert_eq!(stats.success, 0);
            assert_eq!(stats.failures, 0);
            assert_eq!(stats.active, 0);
        }

        // Connections should start at zero
        let conn_stats = metrics.get_connection_stats();
        assert_eq!(conn_stats.total, 0);
        assert_eq!(conn_stats.active, 0);
        assert_eq!(conn_stats.closed, 0);
        assert_eq!(conn_stats.failed, 0);

        let resource_stats = metrics.get_resource_stats();
        assert_eq!(resource_stats.connection_rejections, 0);
        assert_eq!(resource_stats.operation_rejections, 0);
        assert_eq!(resource_stats.memory_rejections, 0);
        assert_eq!(resource_stats.rate_limit_blocks, 0);
        assert_eq!(resource_stats.rate_limit_allows, 0);
        assert_eq!(resource_stats.idle_connection_evictions, 0);
    }

    #[test]
    fn test_operation_metrics_basic() {
        let metrics = MetricsCollector::new();

        // Start an operation
        metrics.record_operation_start(OperationType::Bind, "127.0.0.1:1234");

        let stats = metrics.get_operation_stats(OperationType::Bind).unwrap();
        assert_eq!(stats.count, 1);
        assert_eq!(stats.active, 1);

        // Complete the operation
        metrics.record_operation_complete(OperationType::Bind, Duration::from_millis(10), true);

        let stats = metrics.get_operation_stats(OperationType::Bind).unwrap();
        assert_eq!(stats.count, 1);
        assert_eq!(stats.success, 1);
        assert_eq!(stats.failures, 0);
        assert_eq!(stats.active, 0);
        assert!(stats.avg_latency_ns > 0);
    }

    #[test]
    fn test_operation_metrics_failure() {
        let metrics = MetricsCollector::new();

        metrics.record_operation_start(OperationType::Search, "127.0.0.1:1234");
        metrics.record_operation_complete(OperationType::Search, Duration::from_millis(5), false);

        let stats = metrics.get_operation_stats(OperationType::Search).unwrap();
        assert_eq!(stats.count, 1);
        assert_eq!(stats.success, 0);
        assert_eq!(stats.failures, 1);
        assert_eq!(stats.active, 0);
    }

    #[test]
    fn test_operation_metrics_latency() {
        let metrics = MetricsCollector::new();

        // Record multiple operations with different latencies
        let latencies = vec![
            Duration::from_millis(5),
            Duration::from_millis(10),
            Duration::from_millis(15),
        ];

        for latency in &latencies {
            metrics.record_operation_start(OperationType::Add, "127.0.0.1:1234");
            metrics.record_operation_complete(OperationType::Add, *latency, true);
        }

        let stats = metrics.get_operation_stats(OperationType::Add).unwrap();
        assert_eq!(stats.count, 3);
        assert_eq!(stats.success, 3);

        // Check min/max latencies
        assert_eq!(
            stats.min_latency_ns,
            Duration::from_millis(5).as_nanos() as u64
        );
        assert_eq!(
            stats.max_latency_ns,
            Duration::from_millis(15).as_nanos() as u64
        );

        // Check average
        let expected_avg = Duration::from_millis(10).as_nanos() as u64;
        assert_eq!(stats.avg_latency_ns, expected_avg);
    }

    #[test]
    fn test_connection_metrics() {
        let metrics = MetricsCollector::new();

        // Accept connections
        metrics.record_connection_accepted();
        metrics.record_connection_accepted();

        let stats = metrics.get_connection_stats();
        assert_eq!(stats.total, 2);
        assert_eq!(stats.active, 2);

        // Close one connection
        metrics.record_connection_closed();

        let stats = metrics.get_connection_stats();
        assert_eq!(stats.active, 1);
        assert_eq!(stats.closed, 1);

        // Record failed connection
        metrics.record_connection_failed();

        let stats = metrics.get_connection_stats();
        assert_eq!(stats.failed, 1);
    }

    #[test]
    fn test_resource_metrics_and_export() {
        let metrics = MetricsCollector::new();

        metrics.record_resource_event(ResourceEventType::ConnectionRejected);
        metrics.record_resource_event(ResourceEventType::OperationRejected);
        metrics.record_resource_event(ResourceEventType::MemoryRejected);
        metrics.record_resource_event(ResourceEventType::RateLimitBlocked);
        metrics.record_resource_event(ResourceEventType::RateLimitAllowed);
        metrics.record_resource_event(ResourceEventType::IdleConnectionEvicted);

        let stats = metrics.get_resource_stats();
        assert_eq!(stats.connection_rejections, 1);
        assert_eq!(stats.operation_rejections, 1);
        assert_eq!(stats.memory_rejections, 1);
        assert_eq!(stats.rate_limit_blocks, 1);
        assert_eq!(stats.rate_limit_allows, 1);
        assert_eq!(stats.idle_connection_evictions, 1);

        let output = metrics.export_prometheus();
        assert!(output.contains("ldap_resource_connection_rejections_total 1"));
        assert!(output.contains("ldap_resource_operation_rejections_total 1"));
        assert!(output.contains("ldap_resource_memory_rejections_total 1"));
        assert!(output.contains("ldap_resource_rate_limit_blocks_total 1"));
        assert!(output.contains("ldap_resource_rate_limit_allows_total 1"));
        assert!(output.contains("ldap_resource_idle_connection_evictions_total 1"));
    }

    #[test]
    fn test_auth_cache_metrics_and_export() {
        let metrics = MetricsCollector::new();

        metrics.record_auth_cache_stats(1000, 42, 7, 3, 2);

        let stats = metrics.get_auth_cache_stats();
        assert_eq!(
            stats,
            AuthCacheStats {
                capacity: 1000,
                entries: 42,
                hits: 7,
                misses: 3,
                evictions: 2,
            }
        );

        let output = metrics.export_prometheus();
        assert!(output.contains("ldap_auth_cache_capacity 1000"));
        assert!(output.contains("ldap_auth_cache_entries 42"));
        assert!(output.contains("ldap_auth_cache_hits_total 7"));
        assert!(output.contains("ldap_auth_cache_misses_total 3"));
        assert!(output.contains("ldap_auth_cache_evictions_total 2"));
    }

    #[test]
    fn test_fsm_state_tracking() {
        let metrics = MetricsCollector::new();

        metrics.record_fsm_state(FsmType::Connection, "connected");
        metrics.record_fsm_state(FsmType::Connection, "connected");
        metrics.record_fsm_state(FsmType::Connection, "disconnected");
        metrics.record_fsm_state(FsmType::Auth, "authenticating");

        let distribution = metrics.get_fsm_state_distribution();

        assert_eq!(distribution.get("connection:connected"), Some(&2));
        assert_eq!(distribution.get("connection:disconnected"), Some(&1));
        assert_eq!(distribution.get("auth:authenticating"), Some(&1));
    }

    #[test]
    fn test_custom_counters() {
        let metrics = MetricsCollector::new();

        metrics.increment_counter("test_counter", 5);
        assert_eq!(metrics.get_counter("test_counter"), Some(5));

        metrics.increment_counter("test_counter", 3);
        assert_eq!(metrics.get_counter("test_counter"), Some(8));

        assert_eq!(metrics.get_counter("nonexistent"), None);
    }

    #[test]
    fn test_custom_gauges() {
        let metrics = MetricsCollector::new();

        metrics.set_gauge("test_gauge", 100);
        assert_eq!(metrics.get_gauge("test_gauge"), Some(100));

        metrics.set_gauge("test_gauge", 200);
        assert_eq!(metrics.get_gauge("test_gauge"), Some(200));

        assert_eq!(metrics.get_gauge("nonexistent"), None);
    }

    #[test]
    fn test_prometheus_export() {
        let metrics = MetricsCollector::new();

        // Record some metrics
        metrics.record_connection_accepted();
        metrics.record_operation_start(OperationType::Bind, "127.0.0.1:1234");
        metrics.record_operation_complete(OperationType::Bind, Duration::from_millis(10), true);
        metrics.record_fsm_state(FsmType::Auth, "authenticated");

        let output = metrics.export_prometheus();

        // Verify output contains expected metrics
        assert!(output.contains("ldap_server_uptime_seconds"));
        assert!(output.contains("ldap_connections_total 1"));
        assert!(output.contains("ldap_connections_active 1"));
        assert!(output.contains("ldap_operations_total{operation=\"bind\"} 1"));
        assert!(output.contains("ldap_operations_success{operation=\"bind\"} 1"));
        assert!(output.contains("ldap_fsm_states{fsm=\"auth\",state=\"authenticated\"} 1"));
    }

    #[test]
    fn test_uptime() {
        let metrics = MetricsCollector::new();

        let uptime1 = metrics.uptime_seconds();
        thread::sleep(Duration::from_millis(100));
        let uptime2 = metrics.uptime_seconds();

        assert!(uptime2 >= uptime1);
    }

    #[tokio::test]
    async fn test_health_check_healthy() {
        let metrics = MetricsCollector::new();

        metrics.record_connection_accepted();
        metrics.record_operation_start(OperationType::Bind, "127.0.0.1:1234");
        metrics.record_operation_complete(OperationType::Bind, Duration::from_millis(10), true);

        let health = metrics.health_check().await;
        assert!(health.is_healthy());
        assert!(health.uptime_seconds < 10);
    }

    #[tokio::test]
    async fn test_health_check_degraded() {
        let metrics = MetricsCollector::new();

        metrics.record_connection_accepted();
        metrics.record_operation_start(OperationType::Search, "127.0.0.1:1234");
        metrics.record_operation_complete(OperationType::Search, Duration::from_millis(10), false);

        let health = metrics.health_check().await;
        assert_eq!(health.status, HealthStatus::Degraded);
        assert!(!health.details.is_empty());
    }

    #[tokio::test]
    async fn test_health_check_json() {
        let metrics = MetricsCollector::new();

        metrics.record_connection_accepted();

        let json = metrics.health_check_json().await;
        assert!(json.contains("\"status\":"));
        assert!(json.contains("\"timestamp\":"));
        assert!(json.contains("\"uptime_seconds\":"));
        assert!(json.contains("\"components\":"));
    }

    #[test]
    fn test_operation_type_as_str() {
        assert_eq!(OperationType::Bind.as_str(), "bind");
        assert_eq!(OperationType::Search.as_str(), "search");
        assert_eq!(OperationType::Modify.as_str(), "modify");
    }

    #[test]
    fn test_operation_type_all() {
        let all = OperationType::all();
        assert_eq!(all.len(), 10);
        assert!(all.contains(&OperationType::Bind));
        assert!(all.contains(&OperationType::Search));
    }

    #[test]
    fn test_fsm_type_as_str() {
        assert_eq!(FsmType::Connection.as_str(), "connection");
        assert_eq!(FsmType::Auth.as_str(), "auth");
        assert_eq!(FsmType::Search.as_str(), "search");
    }

    #[test]
    fn test_health_status() {
        assert!(HealthStatus::Healthy.is_healthy());
        assert!(!HealthStatus::Degraded.is_healthy());
        assert!(!HealthStatus::Unhealthy.is_healthy());

        assert_eq!(HealthStatus::Healthy.as_str(), "healthy");
        assert_eq!(HealthStatus::Degraded.as_str(), "degraded");
        assert_eq!(HealthStatus::Unhealthy.as_str(), "unhealthy");
    }
}

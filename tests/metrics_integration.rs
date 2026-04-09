//! Integration tests for metrics collection and monitoring
//!
//! These tests verify the complete metrics workflow including:
//! - Operation metrics collection and aggregation
//! - Connection lifecycle tracking
//! - FSM state distribution monitoring
//! - Prometheus metrics export
//! - Health check functionality
//! - Custom counters and gauges

use opendr::metrics::{FsmType, HealthStatus, MetricsCollector, OperationType};
use std::thread;
use std::time::Duration;

// ================================================================================================
// Test: Basic Metrics Collection
// ================================================================================================

#[test]
fn test_metrics_collector_creation() {
    let metrics = MetricsCollector::new();

    assert!(metrics.uptime_seconds() < 1);

    // Verify all operation types start at zero
    for op_type in OperationType::all() {
        let stats = metrics.get_operation_stats(op_type).unwrap();
        assert_eq!(stats.count, 0);
        assert_eq!(stats.success, 0);
        assert_eq!(stats.failures, 0);
        assert_eq!(stats.active, 0);
    }

    // Verify connection stats start at zero
    let conn_stats = metrics.get_connection_stats();
    assert_eq!(conn_stats.total, 0);
    assert_eq!(conn_stats.active, 0);
}

#[test]
fn test_uptime_tracking() {
    let metrics = MetricsCollector::new();

    let uptime1 = metrics.uptime_seconds();
    thread::sleep(Duration::from_millis(200));
    let uptime2 = metrics.uptime_seconds();

    assert!(uptime2 >= uptime1);
    assert!(uptime2 <= uptime1 + 1);
}

// ================================================================================================
// Test: Operation Metrics
// ================================================================================================

#[test]
fn test_single_operation_success() {
    let metrics = MetricsCollector::new();

    metrics.record_operation_start(OperationType::Bind, "127.0.0.1:1234");

    let stats = metrics.get_operation_stats(OperationType::Bind).unwrap();
    assert_eq!(stats.count, 1);
    assert_eq!(stats.active, 1);

    metrics.record_operation_complete(OperationType::Bind, Duration::from_millis(10), true);

    let stats = metrics.get_operation_stats(OperationType::Bind).unwrap();
    assert_eq!(stats.count, 1);
    assert_eq!(stats.success, 1);
    assert_eq!(stats.failures, 0);
    assert_eq!(stats.active, 0);
    assert!(stats.avg_latency_ns > 0);
}

#[test]
fn test_single_operation_failure() {
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
fn test_multiple_operations_same_type() {
    let metrics = MetricsCollector::new();

    // Perform 10 bind operations
    for i in 0..10 {
        metrics.record_operation_start(OperationType::Bind, "127.0.0.1:1234");
        metrics.record_operation_complete(
            OperationType::Bind,
            Duration::from_millis(5 + i),
            i % 2 == 0, // Alternate success/failure
        );
    }

    let stats = metrics.get_operation_stats(OperationType::Bind).unwrap();
    assert_eq!(stats.count, 10);
    assert_eq!(stats.success, 5);
    assert_eq!(stats.failures, 5);
    assert_eq!(stats.active, 0);
}

#[test]
fn test_multiple_operations_different_types() {
    let metrics = MetricsCollector::new();

    // Bind operations
    metrics.record_operation_start(OperationType::Bind, "127.0.0.1:1234");
    metrics.record_operation_complete(OperationType::Bind, Duration::from_millis(10), true);

    // Search operations
    metrics.record_operation_start(OperationType::Search, "127.0.0.1:1234");
    metrics.record_operation_complete(OperationType::Search, Duration::from_millis(20), true);

    // Modify operations
    metrics.record_operation_start(OperationType::Modify, "127.0.0.1:1234");
    metrics.record_operation_complete(OperationType::Modify, Duration::from_millis(15), false);

    let bind_stats = metrics.get_operation_stats(OperationType::Bind).unwrap();
    assert_eq!(bind_stats.count, 1);
    assert_eq!(bind_stats.success, 1);

    let search_stats = metrics.get_operation_stats(OperationType::Search).unwrap();
    assert_eq!(search_stats.count, 1);
    assert_eq!(search_stats.success, 1);

    let modify_stats = metrics.get_operation_stats(OperationType::Modify).unwrap();
    assert_eq!(modify_stats.count, 1);
    assert_eq!(modify_stats.failures, 1);
}

#[test]
fn test_concurrent_operations() {
    let metrics = MetricsCollector::new();

    // Start multiple operations without completing them
    metrics.record_operation_start(OperationType::Search, "127.0.0.1:1234");
    metrics.record_operation_start(OperationType::Search, "127.0.0.1:1235");
    metrics.record_operation_start(OperationType::Search, "127.0.0.1:1236");

    let stats = metrics.get_operation_stats(OperationType::Search).unwrap();
    assert_eq!(stats.count, 3);
    assert_eq!(stats.active, 3);

    // Complete one operation
    metrics.record_operation_complete(OperationType::Search, Duration::from_millis(10), true);

    let stats = metrics.get_operation_stats(OperationType::Search).unwrap();
    assert_eq!(stats.active, 2);
    assert_eq!(stats.success, 1);
}

// ================================================================================================
// Test: Latency Tracking
// ================================================================================================

#[test]
fn test_latency_min_max_avg() {
    let metrics = MetricsCollector::new();

    let latencies = vec![
        Duration::from_millis(5),
        Duration::from_millis(10),
        Duration::from_millis(15),
        Duration::from_millis(20),
    ];

    for latency in &latencies {
        metrics.record_operation_start(OperationType::Add, "127.0.0.1:1234");
        metrics.record_operation_complete(OperationType::Add, *latency, true);
    }

    let stats = metrics.get_operation_stats(OperationType::Add).unwrap();
    assert_eq!(stats.count, 4);
    assert_eq!(
        stats.min_latency_ns,
        Duration::from_millis(5).as_nanos() as u64
    );
    assert_eq!(
        stats.max_latency_ns,
        Duration::from_millis(20).as_nanos() as u64
    );

    // Average should be (5+10+15+20)/4 = 12.5ms
    let expected_avg = ((5 + 10 + 15 + 20) * 1_000_000) / 4;
    assert_eq!(stats.avg_latency_ns, expected_avg);
}

#[test]
fn test_latency_single_operation() {
    let metrics = MetricsCollector::new();

    metrics.record_operation_start(OperationType::Delete, "127.0.0.1:1234");
    metrics.record_operation_complete(OperationType::Delete, Duration::from_millis(100), true);

    let stats = metrics.get_operation_stats(OperationType::Delete).unwrap();
    assert_eq!(
        stats.min_latency_ns,
        Duration::from_millis(100).as_nanos() as u64
    );
    assert_eq!(
        stats.max_latency_ns,
        Duration::from_millis(100).as_nanos() as u64
    );
    assert_eq!(
        stats.avg_latency_ns,
        Duration::from_millis(100).as_nanos() as u64
    );
}

// ================================================================================================
// Test: Connection Metrics
// ================================================================================================

#[test]
fn test_connection_lifecycle() {
    let metrics = MetricsCollector::new();

    // Accept connections
    metrics.record_connection_accepted();
    metrics.record_connection_accepted();
    metrics.record_connection_accepted();

    let stats = metrics.get_connection_stats();
    assert_eq!(stats.total, 3);
    assert_eq!(stats.active, 3);
    assert_eq!(stats.closed, 0);

    // Close connections
    metrics.record_connection_closed();
    metrics.record_connection_closed();

    let stats = metrics.get_connection_stats();
    assert_eq!(stats.active, 1);
    assert_eq!(stats.closed, 2);

    // Close remaining connection
    metrics.record_connection_closed();

    let stats = metrics.get_connection_stats();
    assert_eq!(stats.active, 0);
    assert_eq!(stats.closed, 3);
}

#[test]
fn test_connection_failures() {
    let metrics = MetricsCollector::new();

    metrics.record_connection_accepted();
    metrics.record_connection_failed();
    metrics.record_connection_failed();

    let stats = metrics.get_connection_stats();
    assert_eq!(stats.total, 1);
    assert_eq!(stats.failed, 2);
}

#[test]
fn test_connection_mixed_scenarios() {
    let metrics = MetricsCollector::new();

    // Mix of successful and failed connections
    metrics.record_connection_accepted();
    metrics.record_connection_accepted();
    metrics.record_connection_failed();
    metrics.record_connection_closed();
    metrics.record_connection_accepted();

    let stats = metrics.get_connection_stats();
    assert_eq!(stats.total, 3);
    assert_eq!(stats.active, 2);
    assert_eq!(stats.closed, 1);
    assert_eq!(stats.failed, 1);
}

// ================================================================================================
// Test: FSM State Tracking
// ================================================================================================

#[test]
fn test_fsm_state_distribution_single_fsm() {
    let metrics = MetricsCollector::new();

    metrics.record_fsm_state(FsmType::Connection, "connected");
    metrics.record_fsm_state(FsmType::Connection, "connected");
    metrics.record_fsm_state(FsmType::Connection, "disconnected");

    let distribution = metrics.get_fsm_state_distribution();

    assert_eq!(distribution.get("connection:connected"), Some(&2));
    assert_eq!(distribution.get("connection:disconnected"), Some(&1));
}

#[test]
fn test_fsm_state_distribution_multiple_fsms() {
    let metrics = MetricsCollector::new();

    metrics.record_fsm_state(FsmType::Connection, "connected");
    metrics.record_fsm_state(FsmType::Auth, "authenticating");
    metrics.record_fsm_state(FsmType::Auth, "authenticated");
    metrics.record_fsm_state(FsmType::Search, "searching");

    let distribution = metrics.get_fsm_state_distribution();

    assert_eq!(distribution.get("connection:connected"), Some(&1));
    assert_eq!(distribution.get("auth:authenticating"), Some(&1));
    assert_eq!(distribution.get("auth:authenticated"), Some(&1));
    assert_eq!(distribution.get("search:searching"), Some(&1));
}

#[test]
fn test_fsm_state_accumulation() {
    let metrics = MetricsCollector::new();

    // Record same state multiple times
    for _ in 0..10 {
        metrics.record_fsm_state(FsmType::Write, "writing");
    }

    let distribution = metrics.get_fsm_state_distribution();
    assert_eq!(distribution.get("write:writing"), Some(&10));
}

// ================================================================================================
// Test: Custom Metrics
// ================================================================================================

#[test]
fn test_custom_counter_basic() {
    let metrics = MetricsCollector::new();

    metrics.increment_counter("requests_processed", 1);
    assert_eq!(metrics.get_counter("requests_processed"), Some(1));

    metrics.increment_counter("requests_processed", 5);
    assert_eq!(metrics.get_counter("requests_processed"), Some(6));
}

#[test]
fn test_custom_counter_multiple() {
    let metrics = MetricsCollector::new();

    metrics.increment_counter("cache_hits", 10);
    metrics.increment_counter("cache_misses", 3);

    assert_eq!(metrics.get_counter("cache_hits"), Some(10));
    assert_eq!(metrics.get_counter("cache_misses"), Some(3));
}

#[test]
fn test_custom_counter_nonexistent() {
    let metrics = MetricsCollector::new();

    assert_eq!(metrics.get_counter("nonexistent"), None);
}

#[test]
fn test_custom_gauge_basic() {
    let metrics = MetricsCollector::new();

    metrics.set_gauge("memory_usage", 1024);
    assert_eq!(metrics.get_gauge("memory_usage"), Some(1024));

    metrics.set_gauge("memory_usage", 2048);
    assert_eq!(metrics.get_gauge("memory_usage"), Some(2048));
}

#[test]
fn test_custom_gauge_multiple() {
    let metrics = MetricsCollector::new();

    metrics.set_gauge("queue_depth", 100);
    metrics.set_gauge("active_workers", 5);

    assert_eq!(metrics.get_gauge("queue_depth"), Some(100));
    assert_eq!(metrics.get_gauge("active_workers"), Some(5));
}

#[test]
fn test_custom_gauge_nonexistent() {
    let metrics = MetricsCollector::new();

    assert_eq!(metrics.get_gauge("nonexistent"), None);
}

// ================================================================================================
// Test: Prometheus Export
// ================================================================================================

#[test]
fn test_prometheus_export_basic() {
    let metrics = MetricsCollector::new();

    let output = metrics.export_prometheus();

    // Should contain uptime
    assert!(output.contains("ldap_server_uptime_seconds"));

    // Should contain connection metrics
    assert!(output.contains("ldap_connections_total"));
    assert!(output.contains("ldap_connections_active"));
    assert!(output.contains("ldap_connections_closed"));
    assert!(output.contains("ldap_connections_failed"));
}

#[test]
fn test_prometheus_export_with_operations() {
    let metrics = MetricsCollector::new();

    metrics.record_operation_start(OperationType::Bind, "127.0.0.1:1234");
    metrics.record_operation_complete(OperationType::Bind, Duration::from_millis(10), true);

    metrics.record_operation_start(OperationType::Search, "127.0.0.1:1234");
    metrics.record_operation_complete(OperationType::Search, Duration::from_millis(20), false);

    let output = metrics.export_prometheus();

    // Should contain bind metrics
    assert!(output.contains("ldap_operations_total{operation=\"bind\"} 1"));
    assert!(output.contains("ldap_operations_success{operation=\"bind\"} 1"));

    // Should contain search metrics
    assert!(output.contains("ldap_operations_total{operation=\"search\"} 1"));
    assert!(output.contains("ldap_operations_failures{operation=\"search\"} 1"));

    // Should contain latency metrics
    assert!(output.contains("ldap_operations_latency_avg_ns{operation=\"bind\"}"));
    assert!(output.contains("ldap_operations_latency_min_ns{operation=\"bind\"}"));
    assert!(output.contains("ldap_operations_latency_max_ns{operation=\"bind\"}"));
}

#[test]
fn test_prometheus_export_with_fsm_states() {
    let metrics = MetricsCollector::new();

    metrics.record_fsm_state(FsmType::Auth, "authenticated");
    metrics.record_fsm_state(FsmType::Connection, "connected");

    let output = metrics.export_prometheus();

    assert!(output.contains("ldap_fsm_states"));
    assert!(output.contains("ldap_fsm_states{fsm=\"auth\",state=\"authenticated\"} 1"));
    assert!(output.contains("ldap_fsm_states{fsm=\"connection\",state=\"connected\"} 1"));
}

#[test]
fn test_prometheus_export_with_custom_metrics() {
    let metrics = MetricsCollector::new();

    metrics.increment_counter("custom_requests", 42);
    metrics.set_gauge("custom_memory", 1024);

    let output = metrics.export_prometheus();

    assert!(output.contains("ldap_custom_counter{name=\"custom_requests\"} 42"));
    assert!(output.contains("ldap_custom_gauge{name=\"custom_memory\"} 1024"));
}

#[test]
fn test_prometheus_export_format() {
    let metrics = MetricsCollector::new();

    metrics.record_connection_accepted();

    let output = metrics.export_prometheus();

    // Should have HELP and TYPE comments
    assert!(output.contains("# HELP"));
    assert!(output.contains("# TYPE"));

    // Should have proper line endings
    let lines: Vec<&str> = output.lines().collect();
    assert!(lines.len() > 10);
}

// ================================================================================================
// Test: Health Checks
// ================================================================================================

#[tokio::test]
async fn test_health_check_healthy() {
    let metrics = MetricsCollector::new();

    metrics.record_connection_accepted();
    metrics.record_operation_start(OperationType::Bind, "127.0.0.1:1234");
    metrics.record_operation_complete(OperationType::Bind, Duration::from_millis(10), true);

    let health = metrics.health_check().await;

    assert_eq!(health.status, HealthStatus::Healthy);
    assert!(health.is_healthy());
    assert!(health.uptime_seconds < 10);
    assert!(health.components.contains_key("connections"));
    assert!(health.components.contains_key("operations"));
}

#[tokio::test]
async fn test_health_check_degraded() {
    let metrics = MetricsCollector::new();

    metrics.record_connection_accepted();
    metrics.record_operation_start(OperationType::Search, "127.0.0.1:1234");
    metrics.record_operation_complete(OperationType::Search, Duration::from_millis(10), false);

    let health = metrics.health_check().await;

    assert_eq!(health.status, HealthStatus::Degraded);
    assert!(!health.is_healthy());
    assert!(!health.details.is_empty());
}

#[tokio::test]
async fn test_health_check_multiple_failures() {
    let metrics = MetricsCollector::new();

    // Multiple failed operations
    for _ in 0..5 {
        metrics.record_operation_start(OperationType::Bind, "127.0.0.1:1234");
        metrics.record_operation_complete(OperationType::Bind, Duration::from_millis(10), false);
    }

    // Failed connections
    metrics.record_connection_failed();
    metrics.record_connection_failed();

    let health = metrics.health_check().await;

    assert_eq!(health.status, HealthStatus::Degraded);
    assert!(health.details.len() >= 2); // Should have details about failures
}

#[tokio::test]
async fn test_health_check_json() {
    let metrics = MetricsCollector::new();

    metrics.record_connection_accepted();

    let json = metrics.health_check_json().await;

    // Should be valid JSON structure
    assert!(json.starts_with('{'));
    assert!(json.ends_with('}'));

    // Should contain required fields
    assert!(json.contains("\"status\":"));
    assert!(json.contains("\"timestamp\":"));
    assert!(json.contains("\"uptime_seconds\":"));
    assert!(json.contains("\"components\":"));
    assert!(json.contains("\"details\":"));
}

#[tokio::test]
async fn test_health_check_json_with_failures() {
    let metrics = MetricsCollector::new();

    metrics.record_operation_start(OperationType::Bind, "127.0.0.1:1234");
    metrics.record_operation_complete(OperationType::Bind, Duration::from_millis(10), false);

    let json = metrics.health_check_json().await;

    assert!(json.contains("\"status\":\"degraded\""));
    assert!(json.contains("\"details\":["));
}

// ================================================================================================
// Test: Get All Operation Stats
// ================================================================================================

#[test]
fn test_get_all_operation_stats() {
    let metrics = MetricsCollector::new();

    // Record operations for different types
    metrics.record_operation_start(OperationType::Bind, "127.0.0.1:1234");
    metrics.record_operation_complete(OperationType::Bind, Duration::from_millis(10), true);

    metrics.record_operation_start(OperationType::Search, "127.0.0.1:1234");
    metrics.record_operation_complete(OperationType::Search, Duration::from_millis(20), true);

    let all_stats = metrics.get_all_operation_stats();

    // Should have stats for all operation types
    assert_eq!(all_stats.len(), OperationType::all().len());

    // Bind should have 1 successful operation
    let bind_stats = all_stats.get(&OperationType::Bind).unwrap();
    assert_eq!(bind_stats.success, 1);

    // Search should have 1 successful operation
    let search_stats = all_stats.get(&OperationType::Search).unwrap();
    assert_eq!(search_stats.success, 1);

    // Other operations should have zero counts
    let modify_stats = all_stats.get(&OperationType::Modify).unwrap();
    assert_eq!(modify_stats.count, 0);
}

// ================================================================================================
// Test: Complete Workflow
// ================================================================================================

#[test]
fn test_complete_metrics_workflow() {
    let metrics = MetricsCollector::new();

    // Simulate server activity
    // 1. Accept connections
    metrics.record_connection_accepted();
    metrics.record_connection_accepted();

    // 2. Bind operations
    for i in 0..3 {
        metrics.record_operation_start(OperationType::Bind, &format!("127.0.0.1:{}", 1234 + i));
        thread::sleep(Duration::from_millis(1));
        metrics.record_operation_complete(OperationType::Bind, Duration::from_millis(5), true);
    }

    // 3. Search operations
    for i in 0..5 {
        metrics.record_operation_start(OperationType::Search, &format!("127.0.0.1:{}", 1234 + i));
        thread::sleep(Duration::from_millis(1));
        metrics.record_operation_complete(
            OperationType::Search,
            Duration::from_millis(10),
            i % 2 == 0,
        );
    }

    // 4. FSM state tracking
    metrics.record_fsm_state(FsmType::Auth, "authenticated");
    metrics.record_fsm_state(FsmType::Search, "searching");

    // 5. Custom metrics
    metrics.increment_counter("total_requests", 8);
    metrics.set_gauge("active_sessions", 2);

    // Verify all metrics
    let conn_stats = metrics.get_connection_stats();
    assert_eq!(conn_stats.total, 2);
    assert_eq!(conn_stats.active, 2);

    let bind_stats = metrics.get_operation_stats(OperationType::Bind).unwrap();
    assert_eq!(bind_stats.count, 3);
    assert_eq!(bind_stats.success, 3);

    let search_stats = metrics.get_operation_stats(OperationType::Search).unwrap();
    assert_eq!(search_stats.count, 5);
    assert_eq!(search_stats.success, 3);
    assert_eq!(search_stats.failures, 2);

    let fsm_dist = metrics.get_fsm_state_distribution();
    assert_eq!(fsm_dist.get("auth:authenticated"), Some(&1));

    assert_eq!(metrics.get_counter("total_requests"), Some(8));
    assert_eq!(metrics.get_gauge("active_sessions"), Some(2));

    // Export should contain all metrics
    let prometheus = metrics.export_prometheus();
    assert!(prometheus.contains("ldap_connections_total 2"));
    assert!(prometheus.contains("ldap_operations_total{operation=\"bind\"} 3"));
    assert!(prometheus.contains("ldap_operations_total{operation=\"search\"} 5"));
}

# OpenDR LDAP Server Monitoring Guide

This guide explains the monitoring and metrics capabilities of the OpenDR LDAP server, including how to collect metrics, export them to Prometheus, and set up health checks.

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Metrics Collection](#metrics-collection)
- [Prometheus Integration](#prometheus-integration)
- [Health Checks](#health-checks)
- [Custom Metrics](#custom-metrics)
- [Monitoring Best Practices](#monitoring-best-practices)
- [Troubleshooting](#troubleshooting)

## Overview

OpenDR provides comprehensive monitoring capabilities built on a high-performance, lock-free metrics collection system. The monitoring system tracks:

- **Operation Metrics**: All LDAP operations with counts, success rates, and latency statistics
- **Connection Metrics**: Connection lifecycle, active connections, and failure tracking
- **FSM State Distribution**: State distribution across all finite state machines
- **Health Status**: Component-level health checks with degradation detection
- **Custom Metrics**: Extensible counters and gauges for application-specific metrics

### Architecture

The monitoring system is designed for:
- **Zero-Copy Performance**: Atomic operations minimize overhead
- **Thread Safety**: Safe concurrent access from multiple threads
- **Lock-Free Operations**: No mutex contention on hot paths
- **Prometheus Compatible**: Standard text format export
- **Production Ready**: Battle-tested with comprehensive test coverage

## Quick Start

> **🚀 Live Demo Available!**
>
> Run the comprehensive monitoring demo to see all features in action:
> ```bash
> cargo run --example monitoring_demo
> ```
> See [MONITORING_DEMO_RESULTS.md](../examples/MONITORING_DEMO_RESULTS.md) for detailed verification results.

### Basic Usage

```rust
use opendr::metrics::{MetricsCollector, OperationType};
use std::time::Duration;

// Create metrics collector (typically done once at server startup)
let metrics = MetricsCollector::new();

// Record an operation
metrics.record_operation_start(OperationType::Bind, "127.0.0.1:1234");

// ... perform the operation ...

metrics.record_operation_complete(
    OperationType::Bind,
    Duration::from_millis(10),
    true, // success
);

// Export metrics in Prometheus format
let prometheus_output = metrics.export_prometheus();
println!("{}", prometheus_output);
```

### Integration with Server

```rust
use opendr::metrics::MetricsCollector;
use std::sync::Arc;

// Create shared metrics collector
let metrics = MetricsCollector::new();

// Share with server components
let server_metrics = Arc::clone(&metrics);
let handler_metrics = Arc::clone(&metrics);

// Use in request handlers
async fn handle_bind_request(metrics: Arc<MetricsCollector>) {
    metrics.record_operation_start(OperationType::Bind, "client_addr");

    // ... handle request ...

    metrics.record_operation_complete(
        OperationType::Bind,
        duration,
        success
    );
}
```

## Metrics Collection

### Operation Metrics

The server tracks all LDAP operation types:

| Operation | Description |
|-----------|-------------|
| `Bind` | Authentication operations |
| `Unbind` | Connection termination |
| `Search` | Directory search operations |
| `Modify` | Entry modification operations |
| `Add` | Entry creation operations |
| `Delete` | Entry deletion operations |
| `ModifyDN` | Entry rename/move operations |
| `Compare` | Attribute comparison operations |
| `Extended` | Extended operations |
| `Abandon` | Abandoned operations |

#### Operation Statistics

For each operation type, the following metrics are tracked:

```rust
pub struct OperationStats {
    pub count: u64,              // Total operations
    pub success: u64,            // Successful operations
    pub failures: u64,           // Failed operations
    pub active: usize,           // Currently active operations
    pub avg_latency_ns: u64,     // Average latency in nanoseconds
    pub min_latency_ns: u64,     // Minimum latency
    pub max_latency_ns: u64,     // Maximum latency
}
```

#### Recording Operations

```rust
// Start an operation
metrics.record_operation_start(OperationType::Search, "127.0.0.1:1234");

// Complete with timing
let start = Instant::now();
// ... perform operation ...
let duration = start.elapsed();

metrics.record_operation_complete(
    OperationType::Search,
    duration,
    true  // or false for failure
);

// Get statistics
let stats = metrics.get_operation_stats(OperationType::Search).unwrap();
println!("Search operations: {} total, {} successful, avg latency: {}ns",
         stats.count, stats.success, stats.avg_latency_ns);
```

### Connection Metrics

Track connection lifecycle events:

```rust
// Connection accepted
metrics.record_connection_accepted();

// Connection closed
metrics.record_connection_closed();

// Connection failed
metrics.record_connection_failed();

// Get statistics
let conn_stats = metrics.get_connection_stats();
println!("Connections: {} total, {} active, {} closed, {} failed",
         conn_stats.total,
         conn_stats.active,
         conn_stats.closed,
         conn_stats.failed);
```

### FSM State Monitoring

Track state distribution across all finite state machines:

```rust
use opendr::metrics::FsmType;

// Record FSM state transitions
metrics.record_fsm_state(FsmType::Connection, "connected");
metrics.record_fsm_state(FsmType::Auth, "authenticating");
metrics.record_fsm_state(FsmType::Auth, "authenticated");

// Get state distribution
let distribution = metrics.get_fsm_state_distribution();

for (state_key, count) in distribution {
    println!("{}: {}", state_key, count);
}
// Output:
// connection:connected: 1
// auth:authenticating: 1
// auth:authenticated: 1
```

Available FSM types:
- `Connection`, `BerDecoder`, `Auth`, `Sasl`
- `Search`, `Write`, `Compare`, `ExtendedOp`
- `Referral`, `ReplicationProvider`, `ReplicationConsumer`, `BackendTxn`

## Prometheus Integration

### Metrics Export

Export all metrics in Prometheus text format:

```rust
let prometheus_output = metrics.export_prometheus();

// Write to file
std::fs::write("/var/lib/opendr/metrics", prometheus_output)?;

// Or serve via HTTP endpoint
async fn metrics_handler(
    metrics: Arc<MetricsCollector>
) -> impl warp::Reply {
    warp::reply::with_header(
        metrics.export_prometheus(),
        "Content-Type",
        "text/plain; version=0.0.4"
    )
}
```

### Sample Prometheus Output

```prometheus
# HELP ldap_server_uptime_seconds Server uptime in seconds
# TYPE ldap_server_uptime_seconds gauge
ldap_server_uptime_seconds 3600

# HELP ldap_connections_total Total number of connections
# TYPE ldap_connections_total counter
ldap_connections_total 1523

# HELP ldap_connections_active Currently active connections
# TYPE ldap_connections_active gauge
ldap_connections_active 42

# HELP ldap_connections_closed Total closed connections
# TYPE ldap_connections_closed counter
ldap_connections_closed 1481

# HELP ldap_connections_failed Total failed connection attempts
# TYPE ldap_connections_failed counter
ldap_connections_failed 5

# HELP ldap_operations_total{operation="bind"} Total operations
# TYPE ldap_operations_total{operation="bind"} counter
ldap_operations_total{operation="bind"} 1523
ldap_operations_success{operation="bind"} 1520
ldap_operations_failures{operation="bind"} 3
ldap_operations_active{operation="bind"} 2
ldap_operations_latency_avg_ns{operation="bind"} 5234567
ldap_operations_latency_min_ns{operation="bind"} 1234567
ldap_operations_latency_max_ns{operation="bind"} 25678901

# HELP ldap_operations_total{operation="search"} Total operations
# TYPE ldap_operations_total{operation="search"} counter
ldap_operations_total{operation="search"} 8945
ldap_operations_success{operation="search"} 8940
ldap_operations_failures{operation="search"} 5
ldap_operations_active{operation="search"} 15
ldap_operations_latency_avg_ns{operation="search"} 12456789
ldap_operations_latency_min_ns{operation="search"} 2345678
ldap_operations_latency_max_ns{operation="search"} 89012345

# HELP ldap_fsm_states FSM state distribution
# TYPE ldap_fsm_states gauge
ldap_fsm_states{fsm="connection",state="connected"} 42
ldap_fsm_states{fsm="auth",state="authenticated"} 40
ldap_fsm_states{fsm="search",state="searching"} 15
```

### Prometheus Configuration

Add to your `prometheus.yml`:

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'opendr-ldap'
    static_configs:
      - targets: ['localhost:9090']
    metrics_path: '/metrics'
    scrape_interval: 10s
```

### Setting Up HTTP Metrics Endpoint

Example using `warp`:

```rust
use warp::Filter;
use std::sync::Arc;

async fn run_metrics_server(metrics: Arc<MetricsCollector>) {
    // Metrics endpoint
    let metrics_route = warp::path("metrics")
        .and(warp::get())
        .map(move || {
            warp::reply::with_header(
                metrics.export_prometheus(),
                "Content-Type",
                "text/plain; version=0.0.4; charset=utf-8"
            )
        });

    warp::serve(metrics_route)
        .run(([0, 0, 0, 0], 9090))
        .await;
}
```

Example using `axum`:

```rust
use axum::{routing::get, Router, Extension};
use std::sync::Arc;

async fn metrics_handler(
    Extension(metrics): Extension<Arc<MetricsCollector>>
) -> ([(String, String); 1], String) {
    (
        [("content-type".to_string(), "text/plain; version=0.0.4".to_string())],
        metrics.export_prometheus()
    )
}

#[tokio::main]
async fn main() {
    let metrics = MetricsCollector::new();

    let app = Router::new()
        .route("/metrics", get(metrics_handler))
        .layer(Extension(metrics));

    axum::Server::bind(&"0.0.0.0:9090".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
```

## Health Checks

### Basic Health Check

```rust
// Perform health check
let health = metrics.health_check().await;

println!("Status: {:?}", health.status);
println!("Uptime: {} seconds", health.uptime_seconds);

for (component, status) in &health.components {
    println!("  {}: {:?}", component, status);
}

for detail in &health.details {
    println!("  - {}", detail);
}

// Check if healthy
if health.is_healthy() {
    println!("Server is healthy!");
} else {
    println!("Server has issues!");
}
```

### Health Status Levels

```rust
pub enum HealthStatus {
    Healthy,    // All components operating normally
    Degraded,   // Some components have issues but server is operational
    Unhealthy,  // Critical issues, server may not be functional
}
```

### Health Check JSON Export

For API integration:

```rust
let health_json = metrics.health_check_json().await;
println!("{}", health_json);

// Output:
// {
//   "status": "healthy",
//   "timestamp": 1696512345,
//   "uptime_seconds": 3600,
//   "components": {
//     "connections": "healthy",
//     "operations": "healthy"
//   },
//   "details": []
// }
```

### HTTP Health Endpoint

```rust
async fn health_handler(
    Extension(metrics): Extension<Arc<MetricsCollector>>
) -> (StatusCode, String) {
    let health = metrics.health_check().await;

    let status_code = match health.status {
        HealthStatus::Healthy => StatusCode::OK,
        HealthStatus::Degraded => StatusCode::OK,
        HealthStatus::Unhealthy => StatusCode::SERVICE_UNAVAILABLE,
    };

    (status_code, metrics.health_check_json().await)
}

// Add to router
let app = Router::new()
    .route("/health", get(health_handler))
    .layer(Extension(metrics));
```

### Kubernetes Liveness/Readiness Probes

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: opendr-ldap
spec:
  containers:
  - name: opendr
    image: opendr:latest
    ports:
    - containerPort: 389
      name: ldap
    - containerPort: 9090
      name: metrics
    livenessProbe:
      httpGet:
        path: /health
        port: 9090
      initialDelaySeconds: 30
      periodSeconds: 10
      timeoutSeconds: 5
      failureThreshold: 3
    readinessProbe:
      httpGet:
        path: /health
        port: 9090
      initialDelaySeconds: 5
      periodSeconds: 5
      timeoutSeconds: 3
      failureThreshold: 2
```

## Custom Metrics

### Custom Counters

Use counters for monotonically increasing values:

```rust
// Increment counter
metrics.increment_counter("cache_hits", 1);
metrics.increment_counter("schema_validations", 1);
metrics.increment_counter("acl_checks", 1);

// Increment by specific value
metrics.increment_counter("bytes_sent", 1024);

// Get counter value
if let Some(value) = metrics.get_counter("cache_hits") {
    println!("Cache hits: {}", value);
}
```

### Custom Gauges

Use gauges for values that can increase or decrease:

```rust
// Set gauge value
metrics.set_gauge("queue_depth", 42);
metrics.set_gauge("memory_usage_mb", 512);
metrics.set_gauge("active_sessions", 15);

// Update based on calculation
let active_count = calculate_active_count();
metrics.set_gauge("active_workers", active_count as u64);

// Get gauge value
if let Some(value) = metrics.get_gauge("queue_depth") {
    println!("Current queue depth: {}", value);
}
```

### Custom Metrics in Prometheus

Custom metrics are automatically exported:

```prometheus
ldap_custom_counter{name="cache_hits"} 12345
ldap_custom_counter{name="schema_validations"} 8901
ldap_custom_gauge{name="queue_depth"} 42
ldap_custom_gauge{name="memory_usage_mb"} 512
```

## Monitoring Best Practices

### 1. Metric Naming Conventions

Follow Prometheus naming conventions:

```rust
// Good: Descriptive, uses underscores
metrics.increment_counter("ldap_bind_attempts_total", 1);
metrics.set_gauge("ldap_active_connections", count as u64);

// Avoid: Too generic, unclear units
metrics.increment_counter("requests", 1);
metrics.set_gauge("memory", bytes as u64);
```

### 2. Latency Tracking

Always track operation latency:

```rust
use std::time::Instant;

let start = Instant::now();
metrics.record_operation_start(OperationType::Search, client_addr);

// Perform operation
let result = perform_search().await;

// Record completion with timing
metrics.record_operation_complete(
    OperationType::Search,
    start.elapsed(),
    result.is_ok()
);
```

### 3. Error Tracking

Record both successes and failures:

```rust
match perform_operation().await {
    Ok(_) => {
        metrics.record_operation_complete(op_type, duration, true);
        metrics.increment_counter("operation_success_total", 1);
    }
    Err(e) => {
        metrics.record_operation_complete(op_type, duration, false);
        metrics.increment_counter("operation_errors_total", 1);

        // Track specific error types
        let error_type = classify_error(&e);
        metrics.increment_counter(
            &format!("operation_error_{}", error_type),
            1
        );
    }
}
```

### 4. Resource Monitoring

Track resource usage:

```rust
use sysinfo::{System, SystemExt};

fn update_system_metrics(metrics: &MetricsCollector) {
    let mut sys = System::new_all();
    sys.refresh_all();

    // Memory usage
    metrics.set_gauge(
        "process_memory_bytes",
        sys.process(sysinfo::get_current_pid().unwrap())
            .unwrap()
            .memory() * 1024
    );

    // CPU usage
    metrics.set_gauge(
        "process_cpu_percent",
        (sys.process(sysinfo::get_current_pid().unwrap())
            .unwrap()
            .cpu_usage() * 100.0) as u64
    );
}
```

### 5. Alert Thresholds

Define and monitor key thresholds:

```rust
async fn check_alerts(metrics: &MetricsCollector) {
    let conn_stats = metrics.get_connection_stats();

    // Alert on high connection failures
    if conn_stats.failed > 100 {
        log::warn!("High connection failure rate: {}", conn_stats.failed);
    }

    // Alert on operation latency
    if let Some(stats) = metrics.get_operation_stats(OperationType::Search) {
        let avg_latency_ms = stats.avg_latency_ns / 1_000_000;
        if avg_latency_ms > 100 {
            log::warn!("High search latency: {}ms", avg_latency_ms);
        }
    }

    // Alert on health degradation
    let health = metrics.health_check().await;
    if health.status != HealthStatus::Healthy {
        log::error!("Server health degraded: {:?}", health.details);
    }
}
```

## Alerting Rules

### Prometheus Alert Rules

Example `alerts.yml`:

```yaml
groups:
  - name: opendr_ldap_alerts
    interval: 30s
    rules:
      # High error rate
      - alert: HighLdapErrorRate
        expr: |
          (
            sum(rate(ldap_operations_failures[5m]))
            /
            sum(rate(ldap_operations_total[5m]))
          ) > 0.05
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High LDAP error rate"
          description: "LDAP error rate is {{ $value | humanizePercentage }} (over 5%)"

      # High latency
      - alert: HighLdapLatency
        expr: ldap_operations_latency_avg_ns > 100000000
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High LDAP operation latency"
          description: "Average latency is {{ $value | humanizeDuration }} (over 100ms)"

      # Connection failures
      - alert: HighConnectionFailures
        expr: rate(ldap_connections_failed[5m]) > 1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High connection failure rate"
          description: "Connection failures: {{ $value }} per second"

      # No active connections
      - alert: NoActiveConnections
        expr: ldap_connections_active == 0
        for: 10m
        labels:
          severity: critical
        annotations:
          summary: "No active LDAP connections"
          description: "Server has no active connections for 10 minutes"

      # Server down
      - alert: LdapServerDown
        expr: up{job="opendr-ldap"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "LDAP server is down"
          description: "LDAP server has been down for 1 minute"
```

## Grafana Dashboards

### Sample Dashboard JSON

Create visualizations for key metrics:

```json
{
  "dashboard": {
    "title": "OpenDR LDAP Server",
    "panels": [
      {
        "title": "Operations per Second",
        "targets": [
          {
            "expr": "rate(ldap_operations_total[5m])"
          }
        ],
        "type": "graph"
      },
      {
        "title": "Error Rate",
        "targets": [
          {
            "expr": "rate(ldap_operations_failures[5m])"
          }
        ],
        "type": "graph"
      },
      {
        "title": "Active Connections",
        "targets": [
          {
            "expr": "ldap_connections_active"
          }
        ],
        "type": "stat"
      },
      {
        "title": "Average Latency by Operation",
        "targets": [
          {
            "expr": "ldap_operations_latency_avg_ns / 1000000"
          }
        ],
        "type": "graph"
      }
    ]
  }
}
```

### Key Metrics to Visualize

1. **Operations Dashboard**
   - Operations per second (by type)
   - Success/failure rates
   - Average latency trends
   - P95/P99 latency (calculate from min/max)

2. **Connections Dashboard**
   - Active connections
   - Connection rate (accepts/sec)
   - Connection failures
   - Connection duration

3. **Performance Dashboard**
   - CPU usage
   - Memory usage
   - FSM state distribution
   - Queue depths

4. **Health Dashboard**
   - Health status over time
   - Component status breakdown
   - Uptime
   - Alert history

## Troubleshooting

### High Latency

```rust
// Check per-operation latency
for op_type in OperationType::all() {
    if let Some(stats) = metrics.get_operation_stats(op_type) {
        let avg_ms = stats.avg_latency_ns / 1_000_000;
        if avg_ms > 100 {
            println!("High latency for {:?}: {}ms (min: {}ms, max: {}ms)",
                     op_type,
                     avg_ms,
                     stats.min_latency_ns / 1_000_000,
                     stats.max_latency_ns / 1_000_000);
        }
    }
}
```

### Connection Issues

```rust
let conn_stats = metrics.get_connection_stats();

if conn_stats.failed > conn_stats.total / 10 {
    println!("High connection failure rate: {}/{} ({}%)",
             conn_stats.failed,
             conn_stats.total,
             (conn_stats.failed * 100) / conn_stats.total);
}

if conn_stats.active == 0 && conn_stats.total > 0 {
    println!("Warning: No active connections but {} total connections seen",
             conn_stats.total);
}
```

### FSM State Analysis

```rust
let distribution = metrics.get_fsm_state_distribution();

// Find stuck FSMs
for (state_key, count) in distribution {
    // Parse "fsm:state" format
    let parts: Vec<&str> = state_key.split(':').collect();
    if parts.len() == 2 {
        let (fsm, state) = (parts[0], parts[1]);

        // Check for potentially stuck states
        if state.contains("error") || state.contains("timeout") {
            println!("Potential issue: {} FSM in {} state (count: {})",
                     fsm, state, count);
        }
    }
}
```

### Memory Leaks

```rust
// Monitor operation counts for leaks
let all_stats = metrics.get_all_operation_stats();
let total_active: usize = all_stats.values()
    .map(|s| s.active)
    .sum();

if total_active > 1000 {
    println!("Warning: {} active operations may indicate a leak", total_active);

    for (op_type, stats) in all_stats {
        if stats.active > 100 {
            println!("  {:?}: {} active operations", op_type, stats.active);
        }
    }
}
```

## Performance Considerations

### Metrics Collection Overhead

The metrics system is designed for minimal overhead:

- **Atomic Operations**: Lock-free counters using `AtomicU64` and `AtomicUsize`
- **No Allocations**: Pre-allocated data structures on hot paths
- **Batching**: Consider batching metric updates in high-throughput scenarios

```rust
// Efficient: Single atomic operation
metrics.record_operation_complete(op_type, duration, success);

// Less efficient: Multiple separate updates
metrics.increment_counter("op_count", 1);
metrics.increment_counter("op_latency", duration.as_nanos() as u64);
metrics.increment_counter(if success { "success" } else { "failure" }, 1);
```

### Export Frequency

Balance between freshness and overhead:

```rust
// Good: Export every 10-15 seconds
tokio::spawn(async move {
    let mut interval = tokio::time::interval(Duration::from_secs(10));
    loop {
        interval.tick().await;
        let metrics_text = metrics.export_prometheus();
        // Write to file or serve via HTTP
    }
});

// Avoid: Exporting on every request (high overhead)
```

## Summary

OpenDR's monitoring system provides:

- ✅ **Comprehensive Metrics**: All LDAP operations, connections, and FSM states
- ✅ **Prometheus Compatible**: Standard export format
- ✅ **Health Checks**: Component-level status monitoring
- ✅ **Custom Metrics**: Extensible counters and gauges
- ✅ **High Performance**: Lock-free atomic operations
- ✅ **Production Ready**: Battle-tested with 61 tests

For more information, see:
- [Source Code](../src/metrics.rs)
- [Integration Tests](../tests/metrics_integration.rs)
- [TASK.md - Phase 5.3](../TASK.md#53-monitoring)

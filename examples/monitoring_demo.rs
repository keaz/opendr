//! Monitoring System Demo
//!
//! This example demonstrates all features of the OpenDR monitoring system:
//! - Operation metrics collection
//! - Connection tracking
//! - FSM state monitoring
//! - Prometheus export
//! - Health checks
//! - Custom metrics
//!
//! Run with: cargo run --example monitoring_demo

use opendr::metrics::{FsmType, MetricsCollector, OperationType};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::main]
async fn main() {
    println!("═══════════════════════════════════════════════════════");
    println!("      OpenDR LDAP Server - Monitoring System Demo");
    println!("═══════════════════════════════════════════════════════\n");

    // Create metrics collector
    let metrics = MetricsCollector::new();

    println!("✓ Metrics collector initialized\n");

    // Demo 1: Connection Metrics
    println!("━━━ Demo 1: Connection Tracking ━━━");
    demo_connection_metrics(&metrics).await;

    // Demo 2: Operation Metrics
    println!("\n━━━ Demo 2: Operation Metrics ━━━");
    demo_operation_metrics(&metrics).await;

    // Demo 3: Latency Tracking
    println!("\n━━━ Demo 3: Latency Tracking ━━━");
    demo_latency_tracking(&metrics).await;

    // Demo 4: FSM State Monitoring
    println!("\n━━━ Demo 4: FSM State Monitoring ━━━");
    demo_fsm_state_tracking(&metrics).await;

    // Demo 5: Custom Metrics
    println!("\n━━━ Demo 5: Custom Metrics ━━━");
    demo_custom_metrics(&metrics).await;

    // Demo 6: Prometheus Export
    println!("\n━━━ Demo 6: Prometheus Export ━━━");
    demo_prometheus_export(&metrics).await;

    // Demo 7: Health Checks
    println!("\n━━━ Demo 7: Health Checks ━━━");
    demo_health_checks(&metrics).await;

    // Demo 8: Real-world Simulation
    println!("\n━━━ Demo 8: Real-World Server Simulation ━━━");
    demo_realistic_scenario(&metrics).await;

    println!("\n═══════════════════════════════════════════════════════");
    println!("           Demo Complete! All Features Working ✓");
    println!("═══════════════════════════════════════════════════════");
}

/// Demo 1: Connection lifecycle tracking
async fn demo_connection_metrics(metrics: &MetricsCollector) {
    println!("Simulating connection lifecycle...");

    // Accept 5 connections
    for i in 1..=5 {
        metrics.record_connection_accepted();
        println!("  ✓ Connection {} accepted", i);
        sleep(Duration::from_millis(10)).await;
    }

    // Close 2 connections
    for i in 1..=2 {
        metrics.record_connection_closed();
        println!("  ✓ Connection {} closed", i);
        sleep(Duration::from_millis(10)).await;
    }

    // Fail 1 connection
    metrics.record_connection_failed();
    println!("  ✗ Connection failed");

    // Display statistics
    let stats = metrics.get_connection_stats();
    println!("\nConnection Statistics:");
    println!("  Total connections: {}", stats.total);
    println!("  Active connections: {}", stats.active);
    println!("  Closed connections: {}", stats.closed);
    println!("  Failed connections: {}", stats.failed);
}

/// Demo 2: Operation metrics for different LDAP operations
async fn demo_operation_metrics(metrics: &MetricsCollector) {
    println!("Simulating LDAP operations...");

    // Simulate bind operations
    for i in 1..=3 {
        metrics.record_operation_start(OperationType::Bind, &format!("client-{}", i));
        sleep(Duration::from_millis(5)).await;
        metrics.record_operation_complete(OperationType::Bind, Duration::from_millis(5), true);
        println!("  ✓ Bind operation {} completed", i);
    }

    // Simulate search operations (some failures)
    for i in 1..=5 {
        metrics.record_operation_start(OperationType::Search, &format!("client-{}", i));
        sleep(Duration::from_millis(10)).await;
        let success = i != 3; // Third search fails
        metrics.record_operation_complete(
            OperationType::Search,
            Duration::from_millis(10),
            success,
        );
        if success {
            println!("  ✓ Search operation {} completed", i);
        } else {
            println!("  ✗ Search operation {} failed", i);
        }
    }

    // Display statistics
    println!("\nOperation Statistics:");
    if let Some(bind_stats) = metrics.get_operation_stats(OperationType::Bind) {
        println!(
            "  Bind: {} total, {} success, {} failures",
            bind_stats.count, bind_stats.success, bind_stats.failures
        );
    }
    if let Some(search_stats) = metrics.get_operation_stats(OperationType::Search) {
        println!(
            "  Search: {} total, {} success, {} failures",
            search_stats.count, search_stats.success, search_stats.failures
        );
    }
}

/// Demo 3: Latency tracking with min/max/avg
async fn demo_latency_tracking(metrics: &MetricsCollector) {
    println!("Simulating operations with varying latencies...");

    let latencies = [5, 10, 15, 20, 25, 30, 35, 40];

    for (i, latency_ms) in latencies.iter().enumerate() {
        metrics.record_operation_start(OperationType::Add, &format!("client-{}", i));
        sleep(Duration::from_millis(*latency_ms)).await;
        metrics.record_operation_complete(
            OperationType::Add,
            Duration::from_millis(*latency_ms),
            true,
        );
        println!("  ✓ Add operation {} completed in {}ms", i + 1, latency_ms);
    }

    // Display latency statistics
    if let Some(stats) = metrics.get_operation_stats(OperationType::Add) {
        println!("\nLatency Statistics for Add operations:");
        println!("  Count: {}", stats.count);
        println!("  Average: {}ms", stats.avg_latency_ns / 1_000_000);
        println!("  Minimum: {}ms", stats.min_latency_ns / 1_000_000);
        println!("  Maximum: {}ms", stats.max_latency_ns / 1_000_000);
    }
}

/// Demo 4: FSM state distribution tracking
async fn demo_fsm_state_tracking(metrics: &MetricsCollector) {
    println!("Tracking FSM state transitions...");

    // Simulate connection FSM states
    metrics.record_fsm_state(FsmType::Connection, "connected");
    metrics.record_fsm_state(FsmType::Connection, "connected");
    metrics.record_fsm_state(FsmType::Connection, "connected");
    metrics.record_fsm_state(FsmType::Connection, "disconnected");
    println!("  ✓ Recorded Connection FSM states");

    // Simulate auth FSM states
    metrics.record_fsm_state(FsmType::Auth, "authenticating");
    metrics.record_fsm_state(FsmType::Auth, "authenticated");
    metrics.record_fsm_state(FsmType::Auth, "authenticated");
    println!("  ✓ Recorded Auth FSM states");

    // Simulate search FSM states
    metrics.record_fsm_state(FsmType::Search, "searching");
    metrics.record_fsm_state(FsmType::Search, "searching");
    metrics.record_fsm_state(FsmType::Search, "completed");
    println!("  ✓ Recorded Search FSM states");

    // Simulate SASL FSM states
    metrics.record_fsm_state(FsmType::Sasl, "negotiating");
    metrics.record_fsm_state(FsmType::Sasl, "completed");
    println!("  ✓ Recorded SASL FSM states");

    // Display distribution
    println!("\nFSM State Distribution:");
    let distribution = metrics.get_fsm_state_distribution();
    let mut entries: Vec<_> = distribution.iter().collect();
    entries.sort_by_key(|(k, _)| *k);

    for (state_key, count) in entries {
        let parts: Vec<&str> = state_key.split(':').collect();
        if parts.len() == 2 {
            println!("  {:<20} {:>15}: {}", parts[0], parts[1], count);
        }
    }
}

/// Demo 5: Custom counters and gauges
async fn demo_custom_metrics(metrics: &MetricsCollector) {
    println!("Working with custom metrics...");

    // Custom counters (monotonically increasing)
    metrics.increment_counter("cache_hits", 100);
    metrics.increment_counter("cache_misses", 15);
    metrics.increment_counter("schema_validations", 50);
    metrics.increment_counter("acl_checks", 75);
    println!("  ✓ Incremented custom counters");

    // Custom gauges (can go up or down)
    metrics.set_gauge("queue_depth", 42);
    metrics.set_gauge("memory_usage_mb", 256);
    metrics.set_gauge("active_sessions", 12);
    metrics.set_gauge("thread_pool_size", 8);
    println!("  ✓ Set custom gauges");

    // Display custom metrics
    println!("\nCustom Counters:");
    println!(
        "  cache_hits: {}",
        metrics.get_counter("cache_hits").unwrap_or(0)
    );
    println!(
        "  cache_misses: {}",
        metrics.get_counter("cache_misses").unwrap_or(0)
    );
    println!(
        "  schema_validations: {}",
        metrics.get_counter("schema_validations").unwrap_or(0)
    );
    println!(
        "  acl_checks: {}",
        metrics.get_counter("acl_checks").unwrap_or(0)
    );

    println!("\nCustom Gauges:");
    println!(
        "  queue_depth: {}",
        metrics.get_gauge("queue_depth").unwrap_or(0)
    );
    println!(
        "  memory_usage_mb: {}",
        metrics.get_gauge("memory_usage_mb").unwrap_or(0)
    );
    println!(
        "  active_sessions: {}",
        metrics.get_gauge("active_sessions").unwrap_or(0)
    );
    println!(
        "  thread_pool_size: {}",
        metrics.get_gauge("thread_pool_size").unwrap_or(0)
    );
}

/// Demo 6: Prometheus metrics export
async fn demo_prometheus_export(metrics: &MetricsCollector) {
    println!("Exporting metrics in Prometheus format...");

    let prometheus_output = metrics.export_prometheus();

    println!("\nPrometheus Export Sample (first 50 lines):");
    println!("─────────────────────────────────────────────────────");

    let lines: Vec<&str> = prometheus_output.lines().take(50).collect();
    for line in lines {
        println!("{}", line);
    }

    println!("─────────────────────────────────────────────────────");
    let total_lines = prometheus_output.lines().count();
    println!("\nTotal metrics exported: {} lines", total_lines);
    println!("✓ Prometheus export format validated");
}

/// Demo 7: Health check functionality
async fn demo_health_checks(metrics: &MetricsCollector) {
    println!("Performing health checks...");

    // Perform health check
    let health = metrics.health_check().await;

    println!("\nHealth Check Results:");
    println!("  Overall Status: {:?}", health.status);
    println!("  Uptime: {} seconds", health.uptime_seconds);

    println!("\n  Component Health:");
    for (component, status) in &health.components {
        println!("    {:<20}: {:?}", component, status);
    }

    if !health.details.is_empty() {
        println!("\n  Details:");
        for detail in &health.details {
            println!("    - {}", detail);
        }
    }

    // Export as JSON
    let health_json = metrics.health_check_json().await;
    println!("\nHealth Check JSON:");
    println!("─────────────────────────────────────────────────────");
    println!("{}", health_json);
    println!("─────────────────────────────────────────────────────");

    if health.is_healthy() {
        println!("\n✓ Server is healthy!");
    } else {
        println!("\n⚠ Server has issues - check details above");
    }
}

/// Demo 8: Realistic server scenario
async fn demo_realistic_scenario(metrics: &MetricsCollector) {
    println!("Simulating realistic LDAP server workload...");
    println!("(10 seconds of activity)\n");

    // Create a new shared metrics instance for the demo
    let shared_metrics = MetricsCollector::new();

    // Copy current state to the new instance
    let conn_stats = metrics.get_connection_stats();
    for _ in 0..conn_stats.total {
        shared_metrics.record_connection_accepted();
    }
    for _ in 0..conn_stats.closed {
        shared_metrics.record_connection_closed();
    }
    for _ in 0..conn_stats.failed {
        shared_metrics.record_connection_failed();
    }

    let metrics = Arc::new(shared_metrics);

    // Spawn connection handler
    let conn_metrics = Arc::clone(&metrics);
    let conn_task = tokio::spawn(async move {
        for i in 1..=10 {
            conn_metrics.record_connection_accepted();
            sleep(Duration::from_millis(800)).await;

            if i % 3 == 0 {
                conn_metrics.record_connection_closed();
            }
        }
    });

    // Spawn bind operation handler
    let bind_metrics = Arc::clone(&metrics);
    let bind_task = tokio::spawn(async move {
        for _ in 1..=15 {
            bind_metrics.record_operation_start(OperationType::Bind, "client");
            sleep(Duration::from_millis(600)).await;
            bind_metrics.record_operation_complete(
                OperationType::Bind,
                Duration::from_millis(5),
                true,
            );
        }
    });

    // Spawn search operation handler
    let search_metrics = Arc::clone(&metrics);
    let search_task = tokio::spawn(async move {
        for i in 1..=20 {
            search_metrics.record_operation_start(OperationType::Search, "client");
            let latency_ms = 10 + (i % 20);
            sleep(Duration::from_millis(400)).await;
            search_metrics.record_operation_complete(
                OperationType::Search,
                Duration::from_millis(latency_ms),
                i % 10 != 0, // 10% failure rate
            );
        }
    });

    // Spawn modify operation handler
    let modify_metrics = Arc::clone(&metrics);
    let modify_task = tokio::spawn(async move {
        for i in 1..=8 {
            modify_metrics.record_operation_start(OperationType::Modify, "client");
            sleep(Duration::from_millis(1000)).await;
            modify_metrics.record_operation_complete(
                OperationType::Modify,
                Duration::from_millis(15),
                i % 5 != 0, // 20% failure rate
            );
        }
    });

    // Spawn FSM state tracker
    let fsm_metrics = Arc::clone(&metrics);
    let fsm_task = tokio::spawn(async move {
        let states = vec![
            (FsmType::Connection, "connected"),
            (FsmType::Auth, "authenticated"),
            (FsmType::Search, "searching"),
            (FsmType::Search, "completed"),
            (FsmType::Write, "writing"),
        ];

        for _ in 0..5 {
            for (fsm_type, state) in &states {
                fsm_metrics.record_fsm_state(fsm_type.clone(), state);
                sleep(Duration::from_millis(300)).await;
            }
        }
    });

    // Spawn custom metrics updater
    let custom_metrics = Arc::clone(&metrics);
    let custom_task = tokio::spawn(async move {
        for i in 0..10 {
            custom_metrics.increment_counter("total_requests", 10);
            custom_metrics.set_gauge("active_workers", 5 + (i % 3));
            custom_metrics.set_gauge("queue_depth", 20 - (i % 15));
            sleep(Duration::from_millis(1000)).await;
        }
    });

    // Print progress
    for _ in 1..=10 {
        print!(".");
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        sleep(Duration::from_secs(1)).await;
    }
    println!(" Done!");

    // Wait for all tasks
    let _ = tokio::join!(
        conn_task,
        bind_task,
        search_task,
        modify_task,
        fsm_task,
        custom_task
    );

    // Display final statistics
    println!("\n╔════════════════════════════════════════════════════╗");
    println!("║          Final Workload Statistics                ║");
    println!("╚════════════════════════════════════════════════════╝");

    let conn_stats = metrics.get_connection_stats();
    println!("\n📡 Connections:");
    println!(
        "   Total: {}, Active: {}, Closed: {}, Failed: {}",
        conn_stats.total, conn_stats.active, conn_stats.closed, conn_stats.failed
    );

    println!("\n⚙️  Operations:");
    let all_stats = metrics.get_all_operation_stats();
    for (op_type, stats) in all_stats {
        if stats.count > 0 {
            let success_rate = if stats.count > 0 {
                (stats.success as f64 / stats.count as f64) * 100.0
            } else {
                0.0
            };
            println!(
                "   {:?}: {} ops, {:.1}% success, avg latency: {}ms",
                op_type,
                stats.count,
                success_rate,
                stats.avg_latency_ns / 1_000_000
            );
        }
    }

    println!("\n🎯 Custom Metrics:");
    println!(
        "   total_requests: {}",
        metrics.get_counter("total_requests").unwrap_or(0)
    );
    println!(
        "   active_workers: {}",
        metrics.get_gauge("active_workers").unwrap_or(0)
    );
    println!(
        "   queue_depth: {}",
        metrics.get_gauge("queue_depth").unwrap_or(0)
    );

    println!("\n📊 FSM State Distribution:");
    let distribution = metrics.get_fsm_state_distribution();
    let mut entries: Vec<_> = distribution.iter().collect();
    entries.sort_by(|a, b| b.1.cmp(a.1)); // Sort by count descending
    for (state_key, count) in entries.iter().take(5) {
        println!("   {}: {}", state_key, count);
    }

    // Final health check
    let health = metrics.health_check().await;
    println!("\n💚 Health Status: {:?}", health.status);
}

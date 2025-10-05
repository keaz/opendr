//! Rate Limiting Demo
//!
//! This example demonstrates the rate limiting and DoS protection features
//! of the OpenDR LDAP server.
//!
//! It shows:
//! - Basic rate limiting per client
//! - Operation-specific rate limits
//! - Global rate limiting
//! - Blacklist/whitelist management
//! - Auto-ban functionality
//! - Adaptive rate limiting under load
//! - Statistics tracking
//!
//! Run with:
//! ```bash
//! cargo run --example rate_limit_demo
//! ```

use opendr::rate_limit::{RateLimiter, RateLimitConfig, OperationType};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::main]
async fn main() {
    println!("=== OpenDR Rate Limiting Demo ===\n");

    // Demo 1: Basic per-client rate limiting
    demo_basic_rate_limiting().await;

    // Demo 2: Operation-specific limits
    demo_operation_limits().await;

    // Demo 3: Global rate limiting
    demo_global_limiting().await;

    // Demo 4: Whitelist and blacklist
    demo_whitelist_blacklist().await;

    // Demo 5: Auto-ban on violations
    demo_auto_ban().await;

    // Demo 6: Adaptive rate limiting
    demo_adaptive_limiting().await;

    // Demo 7: Statistics and monitoring
    demo_statistics().await;

    println!("\n=== Demo Complete ===");
}

async fn demo_basic_rate_limiting() {
    println!("--- Demo 1: Basic Per-Client Rate Limiting ---");

    let config = RateLimitConfig {
        per_client_requests_per_second: 5,
        ..Default::default()
    };
    let limiter = RateLimiter::new(config);

    let client_ip: IpAddr = "192.168.1.100".parse().unwrap();

    println!("Client: {}", client_ip);
    println!("Limit: 5 requests per second\n");

    let mut allowed = 0;
    let mut blocked = 0;

    // Try to make 10 requests
    for i in 1..=10 {
        if limiter.check_rate_limit(client_ip, "search").await {
            println!("Request {}: ✓ Allowed", i);
            allowed += 1;
        } else {
            println!("Request {}: ✗ Blocked (rate limit exceeded)", i);
            blocked += 1;
        }
    }

    println!("\nResult: {} allowed, {} blocked", allowed, blocked);
    println!("---------------------------------------\n");

    // Wait for window to reset
    sleep(Duration::from_millis(1100)).await;
}

async fn demo_operation_limits() {
    println!("--- Demo 2: Operation-Specific Limits ---");

    let mut operation_limits = HashMap::new();
    operation_limits.insert(OperationType::Bind, 3);
    operation_limits.insert(OperationType::Search, 10);
    operation_limits.insert(OperationType::Modify, 5);

    let config = RateLimitConfig {
        per_client_requests_per_second: 100,
        operation_limits,
        ..Default::default()
    };
    let limiter = RateLimiter::new(config);

    let client_ip: IpAddr = "192.168.1.100".parse().unwrap();

    println!("Client: {}", client_ip);
    println!("Operation Limits:");
    println!("  - Bind: 3/sec");
    println!("  - Search: 10/sec");
    println!("  - Modify: 5/sec\n");

    // Test bind operations
    println!("Testing Bind operations:");
    let mut bind_allowed = 0;
    for i in 1..=5 {
        if limiter.check_rate_limit(client_ip, "bind").await {
            println!("  Bind {}: ✓ Allowed", i);
            bind_allowed += 1;
        } else {
            println!("  Bind {}: ✗ Blocked", i);
        }
    }
    println!("Bind: {} allowed / 5 attempted", bind_allowed);

    // Test search operations
    println!("\nTesting Search operations:");
    let mut search_allowed = 0;
    for i in 1..=12 {
        if limiter.check_rate_limit(client_ip, "search").await {
            println!("  Search {}: ✓ Allowed", i);
            search_allowed += 1;
        } else {
            println!("  Search {}: ✗ Blocked", i);
        }
    }
    println!("Search: {} allowed / 12 attempted", search_allowed);

    println!("---------------------------------------\n");

    // Wait for window to reset
    sleep(Duration::from_millis(1100)).await;
}

async fn demo_global_limiting() {
    println!("--- Demo 3: Global Rate Limiting ---");

    let config = RateLimitConfig {
        global_requests_per_second: 20,
        per_client_requests_per_second: 100,
        ..Default::default()
    };
    let limiter = RateLimiter::new(config);

    println!("Global Limit: 20 requests/sec across all clients\n");

    let mut total_allowed = 0;
    let mut total_blocked = 0;

    // Simulate 5 clients making requests
    for client_num in 1..=5 {
        let client_ip: IpAddr = format!("192.168.1.{}", 100 + client_num)
            .parse()
            .unwrap();

        let mut client_allowed = 0;
        for _ in 0..8 {
            if limiter.check_rate_limit(client_ip, "search").await {
                client_allowed += 1;
                total_allowed += 1;
            } else {
                total_blocked += 1;
            }
        }

        println!(
            "Client {} ({}): {} requests allowed",
            client_num, client_ip, client_allowed
        );
    }

    println!("\nTotal: {} allowed, {} blocked", total_allowed, total_blocked);
    println!("Note: Global limit prevents excessive total load");
    println!("---------------------------------------\n");

    // Wait for window to reset
    sleep(Duration::from_millis(1100)).await;
}

async fn demo_whitelist_blacklist() {
    println!("--- Demo 4: Whitelist and Blacklist ---");

    let config = RateLimitConfig {
        per_client_requests_per_second: 3,
        whitelist: vec!["192.168.1.200".parse().unwrap()],
        blacklist: vec!["192.168.1.250".parse().unwrap()],
        ..Default::default()
    };
    let limiter = RateLimiter::new(config);

    let normal_ip: IpAddr = "192.168.1.100".parse().unwrap();
    let whitelisted_ip: IpAddr = "192.168.1.200".parse().unwrap();
    let blacklisted_ip: IpAddr = "192.168.1.250".parse().unwrap();

    println!("Normal client ({}): limited to 3 req/sec", normal_ip);
    println!("Whitelisted client ({}): unlimited", whitelisted_ip);
    println!("Blacklisted client ({}): always blocked\n", blacklisted_ip);

    // Test normal client
    print!("Normal client: ");
    let mut normal_allowed = 0;
    for _ in 0..5 {
        if limiter.check_rate_limit(normal_ip, "search").await {
            normal_allowed += 1;
        }
    }
    println!("{}/5 requests allowed", normal_allowed);

    // Test whitelisted client
    print!("Whitelisted client: ");
    let mut white_allowed = 0;
    for _ in 0..10 {
        if limiter.check_rate_limit(whitelisted_ip, "search").await {
            white_allowed += 1;
        }
    }
    println!("{}/10 requests allowed (bypasses limits)", white_allowed);

    // Test blacklisted client
    print!("Blacklisted client: ");
    let mut black_allowed = 0;
    for _ in 0..5 {
        if limiter.check_rate_limit(blacklisted_ip, "search").await {
            black_allowed += 1;
        }
    }
    println!("{}/5 requests allowed (always blocked)", black_allowed);

    println!("---------------------------------------\n");

    // Wait for window to reset
    sleep(Duration::from_millis(1100)).await;
}

async fn demo_auto_ban() {
    println!("--- Demo 5: Auto-Ban on Violations ---");

    let config = RateLimitConfig {
        per_client_requests_per_second: 5,
        auto_ban_threshold: 10,
        auto_ban_duration: Duration::from_secs(2),
        ..Default::default()
    };
    let limiter = RateLimiter::new(config);

    let client_ip: IpAddr = "192.168.1.100".parse().unwrap();

    println!("Client: {}", client_ip);
    println!("Limit: 5 requests/sec");
    println!("Auto-ban: 10 violations → 2 second ban\n");

    // Generate violations
    println!("Sending burst of 20 requests...");
    for _ in 0..20 {
        limiter.check_rate_limit(client_ip, "search").await;
    }

    let violations = limiter.get_client_violations(client_ip).await;
    println!("Violations accumulated: {}", violations);

    let stats = limiter.get_stats().await;
    println!("Banned clients: {}", stats.banned_clients);

    // Try to make requests while banned
    println!("\nTrying to make requests while banned...");
    let mut allowed_while_banned = 0;
    for _ in 0..3 {
        if limiter.check_rate_limit(client_ip, "search").await {
            allowed_while_banned += 1;
        }
    }
    println!("Requests allowed while banned: {} (should be 0)", allowed_while_banned);

    // Wait for ban to expire
    println!("\nWaiting for ban to expire (2 seconds)...");
    sleep(Duration::from_secs(3)).await;

    // Cleanup expired bans
    limiter.cleanup_expired_bans().await;

    let stats = limiter.get_stats().await;
    println!("Banned clients after cleanup: {}", stats.banned_clients);

    // Try requests after unban
    println!("\nTrying requests after unban...");
    if limiter.check_rate_limit(client_ip, "search").await {
        println!("✓ Request allowed - client unbanned successfully");
    }

    println!("---------------------------------------\n");

    // Wait for window to reset
    sleep(Duration::from_millis(1100)).await;
}

async fn demo_adaptive_limiting() {
    println!("--- Demo 6: Adaptive Rate Limiting ---");

    let config = RateLimitConfig {
        global_requests_per_second: 50,
        per_client_requests_per_second: 20,
        adaptive_enabled: true,
        adaptive_threshold: 0.6, // 60% of global limit
        adaptive_multiplier: 0.5, // Reduce to 50%
        ..Default::default()
    };
    let limiter = RateLimiter::new(config);

    println!("Global limit: 50 req/sec");
    println!("Per-client limit: 20 req/sec");
    println!("Adaptive threshold: 60% (30 req/sec)");
    println!("Adaptive multiplier: 0.5 (reduces limits to 50%)\n");

    // Generate high load
    println!("Generating high load from multiple clients...");
    for i in 0..5 {
        let client_ip: IpAddr = format!("192.168.1.{}", 100 + i)
            .parse()
            .unwrap();

        for _ in 0..10 {
            limiter.check_rate_limit(client_ip, "search").await;
        }
    }

    let stats = limiter.get_stats().await;
    println!("Total requests: {}", stats.total_requests);
    println!("Adaptive limiting active: {}", stats.adaptive_active);
    println!("Current multiplier: {}", stats.current_multiplier);

    if stats.adaptive_active {
        println!("\n✓ Adaptive limiting activated under high load");
        println!("  Limits reduced to protect server resources");
    } else {
        println!("\n• Load within threshold - normal limits apply");
    }

    println!("---------------------------------------\n");

    // Wait for window to reset
    sleep(Duration::from_millis(1100)).await;
}

async fn demo_statistics() {
    println!("--- Demo 7: Statistics and Monitoring ---");

    let limiter = RateLimiter::new(RateLimitConfig::default());

    let client1: IpAddr = "192.168.1.100".parse().unwrap();
    let client2: IpAddr = "192.168.1.101".parse().unwrap();

    println!("Making various requests from multiple clients...\n");

    // Make various requests
    limiter.check_rate_limit(client1, "bind").await;
    limiter.check_rate_limit(client1, "search").await;
    limiter.check_rate_limit(client1, "search").await;
    limiter.check_rate_limit(client2, "modify").await;
    limiter.check_rate_limit(client2, "add").await;

    let stats = limiter.get_stats().await;

    println!("=== Rate Limiting Statistics ===");
    println!("Total requests:     {}", stats.total_requests);
    println!("Requests allowed:   {}", stats.requests_allowed);
    println!("Requests blocked:   {}", stats.requests_blocked);
    println!("Banned clients:     {}", stats.banned_clients);
    println!("Adaptive active:    {}", stats.adaptive_active);
    println!("Current multiplier: {:.2}", stats.current_multiplier);

    let config = limiter.get_config().await;
    println!("\n=== Configuration ===");
    println!("Global limit:       {} req/sec", config.global_requests_per_second);
    println!("Per-client limit:   {} req/sec", config.per_client_requests_per_second);
    println!("Burst size:         {}", config.burst_size);
    println!("Adaptive enabled:   {}", config.adaptive_enabled);
    println!("Auto-ban threshold: {} violations", config.auto_ban_threshold);
    println!("Auto-ban duration:  {:?}", config.auto_ban_duration);

    println!("\n=== Operation Limits ===");
    for (op, limit) in config.operation_limits.iter() {
        println!("{:12} {} req/sec", format!("{}:", op.as_str()), limit);
    }

    println!("---------------------------------------\n");
}

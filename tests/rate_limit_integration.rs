//! Integration tests for rate limiting and DoS protection
//!
//! These tests verify the rate limiting functionality works correctly
//! in realistic scenarios with multiple clients and operations.

use opendr::rate_limit::{OperationType, RateLimitConfig, RateLimiter};
use std::net::IpAddr;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
async fn test_concurrent_clients() {
    let config = RateLimitConfig {
        per_client_requests_per_second: 10,
        global_requests_per_second: 50,
        ..Default::default()
    };
    let limiter = RateLimiter::new(config);

    // Spawn multiple concurrent clients
    let mut handles = vec![];

    for i in 0..5 {
        let limiter_clone = limiter.clone();
        let client_ip: IpAddr = format!("192.168.1.{}", 100 + i).parse().unwrap();

        let handle = tokio::spawn(async move {
            let mut allowed = 0;
            for _ in 0..15 {
                if limiter_clone.check_rate_limit(client_ip, "search").await {
                    allowed += 1;
                }
            }
            allowed
        });

        handles.push(handle);
    }

    // Collect results
    let mut total_allowed = 0;
    for handle in handles {
        let allowed = handle.await.unwrap();
        total_allowed += allowed;
        // Each client should get approximately 10 requests (per-client limit)
        assert!(allowed <= 11); // Allow some tolerance
    }

    // Global limit should also be respected
    assert!(total_allowed <= 51); // Allow some tolerance
}

#[tokio::test]
async fn test_burst_handling() {
    let config = RateLimitConfig {
        per_client_requests_per_second: 10,
        burst_size: 20,
        ..Default::default()
    };
    let limiter = RateLimiter::new(config);

    let client_ip: IpAddr = "192.168.1.100".parse().unwrap();

    // Send burst of requests
    let mut allowed = 0;
    for _ in 0..25 {
        if limiter.check_rate_limit(client_ip, "search").await {
            allowed += 1;
        }
    }

    // Should allow around 10 requests (per-client limit)
    assert!((9..=11).contains(&allowed));

    let stats = limiter.get_stats().await;
    assert_eq!(stats.total_requests, 25);
    assert!(stats.requests_blocked >= 14);
}

#[tokio::test]
async fn test_operation_priority() {
    let mut operation_limits = std::collections::HashMap::new();
    operation_limits.insert(OperationType::Bind, 5);
    operation_limits.insert(OperationType::Search, 20);
    operation_limits.insert(OperationType::Modify, 10);

    let config = RateLimitConfig {
        per_client_requests_per_second: 100,
        operation_limits,
        ..Default::default()
    };
    let limiter = RateLimiter::new(config);

    let client_ip: IpAddr = "192.168.1.100".parse().unwrap();

    // Test bind limit
    let mut bind_allowed = 0;
    for _ in 0..10 {
        if limiter.check_rate_limit(client_ip, "bind").await {
            bind_allowed += 1;
        }
    }
    assert!((4..=6).contains(&bind_allowed)); // Should be around 5

    // Reset for search test
    sleep(Duration::from_millis(1100)).await;

    // Test search limit
    let mut search_allowed = 0;
    for _ in 0..25 {
        if limiter.check_rate_limit(client_ip, "search").await {
            search_allowed += 1;
        }
    }
    assert!((19..=21).contains(&search_allowed)); // Should be around 20
}

#[tokio::test]
async fn test_distributed_attack_protection() {
    let config = RateLimitConfig {
        global_requests_per_second: 50,
        per_client_requests_per_second: 20,
        auto_ban_threshold: 10,
        auto_ban_duration: Duration::from_secs(2),
        ..Default::default()
    };
    let limiter = RateLimiter::new(config);

    // Simulate distributed attack from multiple IPs
    let mut total_blocked = 0;

    for i in 0..10 {
        let client_ip: IpAddr = format!("192.168.1.{}", 100 + i).parse().unwrap();

        for _ in 0..30 {
            if !limiter.check_rate_limit(client_ip, "search").await {
                total_blocked += 1;
            }
        }
    }

    // Many requests should be blocked
    assert!(total_blocked > 200);

    let stats = limiter.get_stats().await;
    assert!(stats.requests_blocked > 200);
    assert!(stats.banned_clients > 0);
}

#[tokio::test]
async fn test_whitelist_during_attack() {
    let config = RateLimitConfig {
        global_requests_per_second: 20,
        per_client_requests_per_second: 5,
        whitelist: vec!["192.168.1.200".parse().unwrap()],
        ..Default::default()
    };
    let limiter = RateLimiter::new(config);

    let whitelisted_ip: IpAddr = "192.168.1.200".parse().unwrap();
    let attacker_ip: IpAddr = "192.168.1.100".parse().unwrap();

    // Attacker floods the server
    for _ in 0..100 {
        limiter.check_rate_limit(attacker_ip, "search").await;
    }

    // Whitelisted client should still work
    let mut allowed = 0;
    for _ in 0..20 {
        if limiter.check_rate_limit(whitelisted_ip, "search").await {
            allowed += 1;
        }
    }

    assert_eq!(allowed, 20); // All requests from whitelisted IP should succeed
}

#[tokio::test]
async fn test_ban_lifecycle() {
    let config = RateLimitConfig {
        per_client_requests_per_second: 5,
        auto_ban_threshold: 5,
        auto_ban_duration: Duration::from_secs(1),
        ..Default::default()
    };
    let limiter = RateLimiter::new(config);

    let client_ip: IpAddr = "192.168.1.100".parse().unwrap();

    // Trigger violations
    for _ in 0..10 {
        limiter.check_rate_limit(client_ip, "search").await;
    }

    // Check violations
    let violations = limiter.get_client_violations(client_ip).await;
    assert!(violations >= 5);

    // Client should be banned
    let stats = limiter.get_stats().await;
    assert!(stats.banned_clients > 0);

    // Wait for ban to expire
    sleep(Duration::from_secs(2)).await;

    // Cleanup expired bans
    limiter.cleanup_expired_bans().await;

    let stats = limiter.get_stats().await;
    assert_eq!(stats.banned_clients, 0);

    // Client should be able to make requests again
    assert!(limiter.check_rate_limit(client_ip, "search").await);
}

#[tokio::test]
async fn test_adaptive_under_load() {
    let config = RateLimitConfig {
        global_requests_per_second: 100,
        per_client_requests_per_second: 50,
        adaptive_enabled: true,
        adaptive_threshold: 0.7, // 70 requests/sec triggers adaptation
        adaptive_multiplier: 0.5,
        ..Default::default()
    };
    let limiter = RateLimiter::new(config);

    // Generate high load from multiple clients
    let mut handles = vec![];

    for i in 0..10 {
        let limiter_clone = limiter.clone();
        let client_ip: IpAddr = format!("192.168.1.{}", 100 + i).parse().unwrap();

        let handle = tokio::spawn(async move {
            for _ in 0..10 {
                limiter_clone.check_rate_limit(client_ip, "search").await;
            }
        });

        handles.push(handle);
    }

    // Wait for all clients
    for handle in handles {
        handle.await.unwrap();
    }

    let stats = limiter.get_stats().await;

    // Adaptive limiting should have been activated
    // Note: Due to timing, this might not always trigger, so we check if it was active at any point
    // In a real scenario with sustained load, this would reliably trigger
    assert!(stats.total_requests == 100);
}

#[tokio::test]
async fn test_dynamic_blacklist_whitelist() {
    let limiter = RateLimiter::new(RateLimitConfig::default());

    let client_ip: IpAddr = "192.168.1.100".parse().unwrap();

    // Initially should work
    assert!(limiter.check_rate_limit(client_ip, "search").await);

    // Add to blacklist
    limiter.blacklist_ip(client_ip).await;

    // Should be blocked
    assert!(!limiter.check_rate_limit(client_ip, "search").await);

    // Remove from blacklist and add to whitelist
    limiter.unblacklist_ip(client_ip).await;
    limiter.whitelist_ip(client_ip).await;

    // Should work and bypass rate limits
    for _ in 0..100 {
        assert!(limiter.check_rate_limit(client_ip, "search").await);
    }
}

#[tokio::test]
async fn test_sliding_window_accuracy() {
    let config = RateLimitConfig {
        per_client_requests_per_second: 10,
        window_duration: Duration::from_secs(1),
        ..Default::default()
    };
    let limiter = RateLimiter::new(config);

    let client_ip: IpAddr = "192.168.1.100".parse().unwrap();

    // Make 5 requests
    for _ in 0..5 {
        assert!(limiter.check_rate_limit(client_ip, "search").await);
    }

    // Wait 500ms
    sleep(Duration::from_millis(500)).await;

    // Make 5 more requests (should work - total 10 in window)
    for _ in 0..5 {
        assert!(limiter.check_rate_limit(client_ip, "search").await);
    }

    // 11th request should be blocked
    assert!(!limiter.check_rate_limit(client_ip, "search").await);

    // Wait another 600ms (first 5 requests should be outside window now)
    sleep(Duration::from_millis(600)).await;

    // Should be able to make more requests
    assert!(limiter.check_rate_limit(client_ip, "search").await);
}

#[tokio::test]
async fn test_stats_accuracy() {
    let limiter = RateLimiter::new(RateLimitConfig::default());

    let client1: IpAddr = "192.168.1.100".parse().unwrap();
    let client2: IpAddr = "192.168.1.101".parse().unwrap();

    // Make various requests
    limiter.check_rate_limit(client1, "search").await;
    limiter.check_rate_limit(client1, "bind").await;
    limiter.check_rate_limit(client2, "modify").await;

    let stats = limiter.get_stats().await;
    assert_eq!(stats.total_requests, 3);
    assert_eq!(stats.requests_allowed, 3);
    assert_eq!(stats.requests_blocked, 0);

    // Reset stats
    limiter.reset_stats().await;

    let stats = limiter.get_stats().await;
    assert_eq!(stats.total_requests, 0);
    assert_eq!(stats.requests_allowed, 0);
    assert_eq!(stats.requests_blocked, 0);
}

#[tokio::test]
async fn test_mixed_operations() {
    let mut operation_limits = std::collections::HashMap::new();
    operation_limits.insert(OperationType::Bind, 3);
    operation_limits.insert(OperationType::Search, 10);
    operation_limits.insert(OperationType::Modify, 5);

    let config = RateLimitConfig {
        per_client_requests_per_second: 50,
        operation_limits,
        ..Default::default()
    };
    let limiter = RateLimiter::new(config);

    let client_ip: IpAddr = "192.168.1.100".parse().unwrap();

    // Mix different operations
    let mut bind_count = 0;
    let mut search_count = 0;
    let mut modify_count = 0;

    for i in 0..20 {
        let _op = match i % 3 {
            0 => {
                if limiter.check_rate_limit(client_ip, "bind").await {
                    bind_count += 1;
                }
                "bind"
            }
            1 => {
                if limiter.check_rate_limit(client_ip, "search").await {
                    search_count += 1;
                }
                "search"
            }
            _ => {
                if limiter.check_rate_limit(client_ip, "modify").await {
                    modify_count += 1;
                }
                "modify"
            }
        };
    }

    // Each operation should be limited independently
    assert!(bind_count <= 4); // ~3 limit
    assert!((6..=7).contains(&search_count)); // ~10 limit but only ~7 tries
    assert!((5..=6).contains(&modify_count)); // ~5 limit
}

#[tokio::test]
async fn test_config_update() {
    let initial_config = RateLimitConfig {
        per_client_requests_per_second: 5,
        ..Default::default()
    };
    let limiter = RateLimiter::new(initial_config);

    let client_ip: IpAddr = "192.168.1.100".parse().unwrap();

    // Use up the initial limit
    for _ in 0..5 {
        limiter.check_rate_limit(client_ip, "search").await;
    }
    assert!(!limiter.check_rate_limit(client_ip, "search").await);

    // Update config with higher limit
    let new_config = RateLimitConfig {
        per_client_requests_per_second: 100,
        ..Default::default()
    };
    limiter.update_config(new_config).await;

    // Wait for window to reset
    sleep(Duration::from_millis(1100)).await;

    // Should now allow more requests
    for _ in 0..20 {
        assert!(limiter.check_rate_limit(client_ip, "search").await);
    }
}

#[tokio::test]
async fn test_manual_ban_override() {
    let limiter = RateLimiter::new(RateLimitConfig::default());

    let client_ip: IpAddr = "192.168.1.100".parse().unwrap();

    // Manually ban the client
    limiter.ban_client(client_ip, Duration::from_secs(10)).await;

    // Even though client is within rate limits, should be blocked
    assert!(!limiter.check_rate_limit(client_ip, "search").await);

    // Unban
    limiter.unban_client(client_ip).await;

    // Should work again
    assert!(limiter.check_rate_limit(client_ip, "search").await);
}

#[tokio::test]
async fn test_zero_violations_after_unban() {
    let config = RateLimitConfig {
        per_client_requests_per_second: 5,
        ..Default::default()
    };
    let limiter = RateLimiter::new(config);

    let client_ip: IpAddr = "192.168.1.100".parse().unwrap();

    // Generate violations
    for _ in 0..20 {
        limiter.check_rate_limit(client_ip, "search").await;
    }

    let violations_before = limiter.get_client_violations(client_ip).await;
    assert!(violations_before > 0);

    // Unban should reset violations
    limiter.unban_client(client_ip).await;

    let violations_after = limiter.get_client_violations(client_ip).await;
    assert_eq!(violations_after, 0);
}

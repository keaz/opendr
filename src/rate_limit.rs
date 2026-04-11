//! Rate Limiting and DoS Protection
//!
//! This module provides rate limiting and denial-of-service (DoS) protection
//! capabilities to protect the LDAP server from abusive clients.
//!
//! ## Features
//!
//! - **Per-Client Rate Limiting**: Limit requests per IP address
//! - **Operation-Specific Limits**: Different limits for different operations
//! - **Adaptive Rate Limiting**: Adjust limits based on server load
//! - **Blacklist/Whitelist Support**: Block or allow specific IP addresses
//! - **Sliding Window**: Accurate rate tracking using sliding window algorithm
//!
//! ## Usage
//!
//! ```rust
//! use opendr::rate_limit::{RateLimiter, RateLimitConfig};
//! use std::net::IpAddr;
//!
//! # tokio::runtime::Runtime::new().unwrap().block_on(async {
//! let config = RateLimitConfig::default();
//! let limiter = RateLimiter::new(config);
//!
//! // Check if client is allowed to perform operation
//! let client_ip: IpAddr = "192.168.1.100".parse().unwrap();
//! if limiter.check_rate_limit(client_ip, "bind").await {
//!     // Process request
//! } else {
//!     // Reject request - rate limit exceeded
//! }
//! # });
//! ```

use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// LDAP operation types for rate limiting
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperationType {
    /// Bind operation (authentication)
    Bind,
    /// Search operation
    Search,
    /// Modify operation
    Modify,
    /// Add operation
    Add,
    /// Delete operation
    Delete,
    /// ModifyDN operation
    ModifyDN,
    /// Compare operation
    Compare,
    /// Extended operation
    Extended,
    /// Unbind operation
    Unbind,
    /// Abandon operation
    Abandon,
}

impl OperationType {
    /// Convert from string representation
    pub fn parse_name(s: &str) -> Option<Self> {
        s.parse().ok()
    }

    /// Get string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Bind => "bind",
            Self::Search => "search",
            Self::Modify => "modify",
            Self::Add => "add",
            Self::Delete => "delete",
            Self::ModifyDN => "modifydn",
            Self::Compare => "compare",
            Self::Extended => "extended",
            Self::Unbind => "unbind",
            Self::Abandon => "abandon",
        }
    }
}

impl FromStr for OperationType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "bind" => Ok(Self::Bind),
            "search" => Ok(Self::Search),
            "modify" => Ok(Self::Modify),
            "add" => Ok(Self::Add),
            "delete" => Ok(Self::Delete),
            "modifydn" => Ok(Self::ModifyDN),
            "compare" => Ok(Self::Compare),
            "extended" => Ok(Self::Extended),
            "unbind" => Ok(Self::Unbind),
            "abandon" => Ok(Self::Abandon),
            _ => Err(()),
        }
    }
}

/// Rate limit configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Global rate limit (requests per second)
    pub global_requests_per_second: u32,

    /// Per-client rate limit (requests per second)
    pub per_client_requests_per_second: u32,

    /// Operation-specific rate limits (requests per second)
    pub operation_limits: HashMap<OperationType, u32>,

    /// Burst size (number of requests allowed in burst)
    pub burst_size: u32,

    /// Window duration for sliding window algorithm
    pub window_duration: Duration,

    /// Enable adaptive rate limiting
    pub adaptive_enabled: bool,

    /// Adaptive threshold (% of global limit)
    pub adaptive_threshold: f64,

    /// Adaptive multiplier when threshold exceeded
    pub adaptive_multiplier: f64,

    /// Blacklisted IP addresses
    pub blacklist: Vec<IpAddr>,

    /// Whitelisted IP addresses (bypass rate limits)
    pub whitelist: Vec<IpAddr>,

    /// Auto-ban threshold (violations before ban)
    pub auto_ban_threshold: u32,

    /// Auto-ban duration
    pub auto_ban_duration: Duration,
}

/// Detailed reason for a rate-limit decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitDecisionReason {
    Allowed,
    UnknownOperation,
    Whitelisted,
    Blacklisted,
    ClientBanned,
    GlobalLimitExceeded,
    ClientLimitExceeded,
    OperationLimitExceeded,
}

/// Structured rate-limit decision used by future runtime hooks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitDecision {
    pub allowed: bool,
    pub reason: RateLimitDecisionReason,
}

impl RateLimitDecision {
    fn allowed(reason: RateLimitDecisionReason) -> Self {
        Self {
            allowed: true,
            reason,
        }
    }

    fn blocked(reason: RateLimitDecisionReason) -> Self {
        Self {
            allowed: false,
            reason,
        }
    }
}

/// Point-in-time rate-limit snapshot for observability.
#[derive(Debug, Clone)]
pub struct RateLimitSnapshot {
    pub config: RateLimitConfig,
    pub stats: RateLimitStats,
    pub current_multiplier: f64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        let mut operation_limits = HashMap::new();

        // Conservative defaults for security-sensitive operations
        operation_limits.insert(OperationType::Bind, 10); // 10 auth attempts per second
        operation_limits.insert(OperationType::Search, 50); // 50 searches per second
        operation_limits.insert(OperationType::Modify, 20); // 20 modifications per second
        operation_limits.insert(OperationType::Add, 20); // 20 adds per second
        operation_limits.insert(OperationType::Delete, 10); // 10 deletes per second
        operation_limits.insert(OperationType::ModifyDN, 10); // 10 renames per second
        operation_limits.insert(OperationType::Compare, 30); // 30 compares per second
        operation_limits.insert(OperationType::Extended, 20); // 20 extended ops per second
        operation_limits.insert(OperationType::Unbind, 100); // 100 unbinds per second
        operation_limits.insert(OperationType::Abandon, 100); // 100 abandons per second

        Self {
            global_requests_per_second: 1000,
            per_client_requests_per_second: 100,
            operation_limits,
            burst_size: 50,
            window_duration: Duration::from_secs(1),
            adaptive_enabled: true,
            adaptive_threshold: 0.8,  // 80% of global limit
            adaptive_multiplier: 0.5, // Reduce limits to 50%
            blacklist: Vec::new(),
            whitelist: Vec::new(),
            auto_ban_threshold: 100,                     // 100 violations
            auto_ban_duration: Duration::from_secs(300), // 5 minutes
        }
    }
}

/// Request timestamp in sliding window
#[derive(Debug, Clone)]
struct RequestTimestamp {
    timestamp: Instant,
    operation: OperationType,
}

/// Client rate limit state
#[derive(Debug)]
struct ClientState {
    /// IP address
    _ip: IpAddr,

    /// Recent requests (sliding window)
    requests: Vec<RequestTimestamp>,

    /// Number of rate limit violations
    violations: u32,

    /// Last violation time
    last_violation: Option<Instant>,

    /// Ban expiry time (if banned)
    ban_expiry: Option<Instant>,
}

impl ClientState {
    fn new(ip: IpAddr) -> Self {
        Self {
            _ip: ip,
            requests: Vec::new(),
            violations: 0,
            last_violation: None,
            ban_expiry: None,
        }
    }

    /// Check if client is currently banned
    fn is_banned(&self) -> bool {
        if let Some(expiry) = self.ban_expiry {
            Instant::now() < expiry
        } else {
            false
        }
    }

    /// Ban the client
    fn ban(&mut self, duration: Duration) {
        self.ban_expiry = Some(Instant::now() + duration);
    }

    /// Unban the client
    fn unban(&mut self) {
        self.ban_expiry = None;
        self.violations = 0;
    }

    /// Record a violation
    fn record_violation(&mut self) {
        self.violations += 1;
        self.last_violation = Some(Instant::now());
    }

    /// Clean old requests outside the window
    fn clean_old_requests(&mut self, window: Duration) {
        let now = Instant::now();
        self.requests
            .retain(|req| now.duration_since(req.timestamp) < window);
    }

    /// Add a request
    fn add_request(&mut self, operation: OperationType) {
        self.requests.push(RequestTimestamp {
            timestamp: Instant::now(),
            operation,
        });
    }

    /// Count requests in window
    fn count_requests(&self, window: Duration) -> usize {
        let now = Instant::now();
        self.requests
            .iter()
            .filter(|req| now.duration_since(req.timestamp) < window)
            .count()
    }

    /// Count operation-specific requests in window
    fn count_operation_requests(&self, operation: OperationType, window: Duration) -> usize {
        let now = Instant::now();
        self.requests
            .iter()
            .filter(|req| req.operation == operation && now.duration_since(req.timestamp) < window)
            .count()
    }
}

/// Rate limiter statistics
#[derive(Debug, Clone)]
pub struct RateLimitStats {
    /// Total requests processed
    pub total_requests: u64,

    /// Total requests allowed
    pub requests_allowed: u64,

    /// Total requests blocked
    pub requests_blocked: u64,

    /// Currently banned clients
    pub banned_clients: usize,

    /// Active adaptive limiting
    pub adaptive_active: bool,

    /// Current adaptive multiplier
    pub current_multiplier: f64,
}

/// Rate limiter
#[derive(Clone)]
pub struct RateLimiter {
    /// Configuration
    config: Arc<RwLock<RateLimitConfig>>,

    /// Client states
    clients: Arc<RwLock<HashMap<IpAddr, ClientState>>>,

    /// Global request count
    global_requests: Arc<RwLock<Vec<Instant>>>,

    /// Statistics
    stats: Arc<RwLock<RateLimitStats>>,

    /// Current adaptive multiplier
    adaptive_multiplier: Arc<RwLock<f64>>,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            clients: Arc::new(RwLock::new(HashMap::new())),
            global_requests: Arc::new(RwLock::new(Vec::new())),
            stats: Arc::new(RwLock::new(RateLimitStats {
                total_requests: 0,
                requests_allowed: 0,
                requests_blocked: 0,
                banned_clients: 0,
                adaptive_active: false,
                current_multiplier: 1.0,
            })),
            adaptive_multiplier: Arc::new(RwLock::new(1.0)),
        }
    }

    /// Check if a request should be allowed
    pub async fn check_rate_limit(&self, client_ip: IpAddr, operation: &str) -> bool {
        self.check_rate_limit_detailed(client_ip, operation)
            .await
            .allowed
    }

    /// Check if a request should be allowed and return the reason.
    pub async fn check_rate_limit_detailed(
        &self,
        client_ip: IpAddr,
        operation: &str,
    ) -> RateLimitDecision {
        let op = match OperationType::parse_name(operation) {
            Some(o) => o,
            None => return RateLimitDecision::allowed(RateLimitDecisionReason::UnknownOperation),
        };

        self.record_total_request().await;

        // Check whitelist
        let config = self.config.read().await;
        if config.whitelist.contains(&client_ip) {
            self.record_allowed().await;
            return RateLimitDecision::allowed(RateLimitDecisionReason::Whitelisted);
        }

        // Check blacklist
        if config.blacklist.contains(&client_ip) {
            self.record_blocked().await;
            return RateLimitDecision::blocked(RateLimitDecisionReason::Blacklisted);
        }
        drop(config);

        // Get or create client state
        let mut clients = self.clients.write().await;
        let client = clients
            .entry(client_ip)
            .or_insert_with(|| ClientState::new(client_ip));

        // Check if client is banned
        if client.is_banned() {
            self.record_blocked().await;
            return RateLimitDecision::blocked(RateLimitDecisionReason::ClientBanned);
        }

        // Clean old requests
        let config = self.config.read().await;
        client.clean_old_requests(config.window_duration);

        // Check global rate limit
        if !self.check_global_limit(&config).await {
            client.record_violation();
            self.check_auto_ban(client, &config).await;
            self.record_blocked().await;
            return RateLimitDecision::blocked(RateLimitDecisionReason::GlobalLimitExceeded);
        }

        // Check per-client rate limit
        let current_multiplier = *self.adaptive_multiplier.read().await;
        let adjusted_limit =
            (config.per_client_requests_per_second as f64 * current_multiplier) as u32;

        if client.count_requests(config.window_duration) >= adjusted_limit as usize {
            client.record_violation();
            self.check_auto_ban(client, &config).await;
            self.record_blocked().await;
            return RateLimitDecision::blocked(RateLimitDecisionReason::ClientLimitExceeded);
        }

        // Check operation-specific limit
        if let Some(&op_limit) = config.operation_limits.get(&op) {
            let adjusted_op_limit = (op_limit as f64 * current_multiplier) as u32;
            if client.count_operation_requests(op, config.window_duration)
                >= adjusted_op_limit as usize
            {
                client.record_violation();
                self.check_auto_ban(client, &config).await;
                self.record_blocked().await;
                return RateLimitDecision::blocked(RateLimitDecisionReason::OperationLimitExceeded);
            }
        }

        // Record the request
        client.add_request(op);

        // Record the accepted request before recomputing adaptive limits.
        {
            let mut global = self.global_requests.write().await;
            global.push(Instant::now());
        }

        // Update adaptive limiting
        if config.adaptive_enabled {
            self.update_adaptive_limiting(&config).await;
        }

        self.record_allowed().await;
        RateLimitDecision::allowed(RateLimitDecisionReason::Allowed)
    }

    /// Check global rate limit
    async fn check_global_limit(&self, config: &RateLimitConfig) -> bool {
        let mut global = self.global_requests.write().await;

        // Clean old requests
        let now = Instant::now();
        global.retain(|&ts| now.duration_since(ts) < config.window_duration);

        global.len() < config.global_requests_per_second as usize
    }

    /// Update adaptive limiting based on server load
    async fn update_adaptive_limiting(&self, config: &RateLimitConfig) {
        let global = self.global_requests.read().await;
        let now = Instant::now();

        // Count requests in current window
        let current_load = global
            .iter()
            .filter(|&&ts| now.duration_since(ts) < config.window_duration)
            .count();

        let threshold =
            (config.global_requests_per_second as f64 * config.adaptive_threshold) as usize;

        let mut multiplier = self.adaptive_multiplier.write().await;
        let mut stats = self.stats.write().await;

        if current_load > threshold {
            // High load - reduce limits
            *multiplier = config.adaptive_multiplier;
            stats.adaptive_active = true;
        } else {
            // Normal load - restore limits
            *multiplier = 1.0;
            stats.adaptive_active = false;
        }

        stats.current_multiplier = *multiplier;
    }

    /// Check if client should be auto-banned
    async fn check_auto_ban(&self, client: &mut ClientState, config: &RateLimitConfig) {
        if client.violations >= config.auto_ban_threshold && !client.is_banned() {
            client.ban(config.auto_ban_duration);

            let mut stats = self.stats.write().await;
            stats.banned_clients += 1;
        }
    }

    /// Record a seen request before classification.
    async fn record_total_request(&self) {
        let mut stats = self.stats.write().await;
        stats.total_requests += 1;
    }

    /// Record an allowed request
    async fn record_allowed(&self) {
        let mut stats = self.stats.write().await;
        stats.requests_allowed += 1;
    }

    /// Record a blocked request
    async fn record_blocked(&self) {
        let mut stats = self.stats.write().await;
        stats.requests_blocked += 1;
    }

    /// Add an IP to the blacklist
    pub async fn blacklist_ip(&self, ip: IpAddr) {
        let mut config = self.config.write().await;
        if !config.blacklist.contains(&ip) {
            config.blacklist.push(ip);
        }
    }

    /// Remove an IP from the blacklist
    pub async fn unblacklist_ip(&self, ip: IpAddr) {
        let mut config = self.config.write().await;
        config.blacklist.retain(|&x| x != ip);
    }

    /// Add an IP to the whitelist
    pub async fn whitelist_ip(&self, ip: IpAddr) {
        let mut config = self.config.write().await;
        if !config.whitelist.contains(&ip) {
            config.whitelist.push(ip);
        }
    }

    /// Remove an IP from the whitelist
    pub async fn unwhitelist_ip(&self, ip: IpAddr) {
        let mut config = self.config.write().await;
        config.whitelist.retain(|&x| x != ip);
    }

    /// Manually ban a client
    pub async fn ban_client(&self, ip: IpAddr, duration: Duration) {
        let mut clients = self.clients.write().await;
        let client = clients.entry(ip).or_insert_with(|| ClientState::new(ip));
        let was_banned = client.is_banned();
        client.ban(duration);

        if !was_banned {
            let mut stats = self.stats.write().await;
            stats.banned_clients += 1;
        }
    }

    /// Manually unban a client
    pub async fn unban_client(&self, ip: IpAddr) {
        let mut clients = self.clients.write().await;
        if let Some(client) = clients.get_mut(&ip) {
            let was_banned = client.is_banned();
            client.unban();

            if was_banned {
                let mut stats = self.stats.write().await;
                stats.banned_clients = stats.banned_clients.saturating_sub(1);
            }
        }
    }

    /// Get statistics
    pub async fn get_stats(&self) -> RateLimitStats {
        self.stats.read().await.clone()
    }

    /// Get a point-in-time rate-limit snapshot for observability.
    pub async fn snapshot(&self) -> RateLimitSnapshot {
        RateLimitSnapshot {
            config: self.get_config().await,
            stats: self.get_stats().await,
            current_multiplier: *self.adaptive_multiplier.read().await,
        }
    }

    /// Reset statistics
    pub async fn reset_stats(&self) {
        let mut stats = self.stats.write().await;
        stats.total_requests = 0;
        stats.requests_allowed = 0;
        stats.requests_blocked = 0;
    }

    /// Get client violations count
    pub async fn get_client_violations(&self, ip: IpAddr) -> u32 {
        let clients = self.clients.read().await;
        clients.get(&ip).map(|c| c.violations).unwrap_or(0)
    }

    /// Clean up expired bans
    pub async fn cleanup_expired_bans(&self) {
        let mut clients = self.clients.write().await;
        let mut unbanned_count = 0;

        for client in clients.values_mut() {
            if let Some(expiry) = client.ban_expiry {
                if Instant::now() >= expiry {
                    client.unban();
                    unbanned_count += 1;
                }
            }
        }

        if unbanned_count > 0 {
            let mut stats = self.stats.write().await;
            stats.banned_clients = stats.banned_clients.saturating_sub(unbanned_count);
        }
    }

    /// Get current configuration
    pub async fn get_config(&self) -> RateLimitConfig {
        self.config.read().await.clone()
    }

    /// Update configuration
    pub async fn update_config(&self, config: RateLimitConfig) {
        let mut cfg = self.config.write().await;
        *cfg = config;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_basic_rate_limit() {
        let config = RateLimitConfig {
            per_client_requests_per_second: 5,
            window_duration: Duration::from_millis(50),
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        let client_ip: IpAddr = "192.168.1.100".parse().unwrap();

        // First 5 requests should be allowed
        for _ in 0..5 {
            assert!(limiter.check_rate_limit(client_ip, "search").await);
        }

        // 6th request should be blocked
        assert!(!limiter.check_rate_limit(client_ip, "search").await);

        // Wait for window to pass
        sleep(Duration::from_millis(60)).await;

        // Should be allowed again
        assert!(limiter.check_rate_limit(client_ip, "search").await);
    }

    #[tokio::test]
    async fn test_operation_specific_limit() {
        let mut operation_limits = HashMap::new();
        operation_limits.insert(OperationType::Bind, 2);
        operation_limits.insert(OperationType::Search, 10);

        let config = RateLimitConfig {
            per_client_requests_per_second: 100,
            operation_limits,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        let client_ip: IpAddr = "192.168.1.100".parse().unwrap();

        // First 2 bind requests should be allowed
        assert!(limiter.check_rate_limit(client_ip, "bind").await);
        assert!(limiter.check_rate_limit(client_ip, "bind").await);

        // 3rd bind request should be blocked
        assert!(!limiter.check_rate_limit(client_ip, "bind").await);

        // But search should still work (different limit)
        assert!(limiter.check_rate_limit(client_ip, "search").await);
    }

    #[tokio::test]
    async fn test_whitelist() {
        let config = RateLimitConfig {
            per_client_requests_per_second: 1,
            whitelist: vec!["192.168.1.200".parse().unwrap()],
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        let whitelisted_ip: IpAddr = "192.168.1.200".parse().unwrap();
        let normal_ip: IpAddr = "192.168.1.100".parse().unwrap();

        // Whitelisted IP should bypass rate limits
        for _ in 0..10 {
            assert!(limiter.check_rate_limit(whitelisted_ip, "search").await);
        }

        // Normal IP should be rate limited
        assert!(limiter.check_rate_limit(normal_ip, "search").await);
        assert!(!limiter.check_rate_limit(normal_ip, "search").await);
    }

    #[tokio::test]
    async fn test_blacklist() {
        let config = RateLimitConfig {
            blacklist: vec!["192.168.1.100".parse().unwrap()],
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        let blacklisted_ip: IpAddr = "192.168.1.100".parse().unwrap();

        // Blacklisted IP should always be blocked
        assert!(!limiter.check_rate_limit(blacklisted_ip, "search").await);
    }

    #[tokio::test]
    async fn test_auto_ban() {
        let config = RateLimitConfig {
            per_client_requests_per_second: 1,
            window_duration: Duration::from_millis(50),
            auto_ban_threshold: 3,
            auto_ban_duration: Duration::from_millis(100),
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        let client_ip: IpAddr = "192.168.1.100".parse().unwrap();

        // First request allowed
        assert!(limiter.check_rate_limit(client_ip, "search").await);

        // Next 3 requests blocked (violations)
        assert!(!limiter.check_rate_limit(client_ip, "search").await);
        assert!(!limiter.check_rate_limit(client_ip, "search").await);
        assert!(!limiter.check_rate_limit(client_ip, "search").await);

        // Wait for window to pass
        sleep(Duration::from_millis(60)).await;

        // Should still be banned even after window
        assert!(!limiter.check_rate_limit(client_ip, "search").await);

        // Wait for ban to expire
        sleep(Duration::from_millis(110)).await;

        // Cleanup expired bans
        limiter.cleanup_expired_bans().await;

        // Should be allowed again
        assert!(limiter.check_rate_limit(client_ip, "search").await);
    }

    #[tokio::test]
    async fn test_manual_ban_unban() {
        let limiter = RateLimiter::new(RateLimitConfig::default());
        let client_ip: IpAddr = "192.168.1.100".parse().unwrap();

        // Ban the client
        limiter.ban_client(client_ip, Duration::from_secs(10)).await;

        // Should be blocked
        assert!(!limiter.check_rate_limit(client_ip, "search").await);

        // Unban the client
        limiter.unban_client(client_ip).await;

        // Should be allowed again
        assert!(limiter.check_rate_limit(client_ip, "search").await);
    }

    #[tokio::test]
    async fn test_statistics() {
        let limiter = RateLimiter::new(RateLimitConfig::default());
        let client_ip: IpAddr = "192.168.1.100".parse().unwrap();

        // Make some requests
        limiter.check_rate_limit(client_ip, "search").await;
        limiter.check_rate_limit(client_ip, "bind").await;

        let stats = limiter.get_stats().await;
        assert_eq!(stats.total_requests, 2);
        assert_eq!(stats.requests_allowed, 2);
        assert_eq!(stats.requests_blocked, 0);
    }

    #[tokio::test]
    async fn test_global_rate_limit() {
        let config = RateLimitConfig {
            global_requests_per_second: 10,
            per_client_requests_per_second: 100,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        // Make requests from multiple clients
        let client1: IpAddr = "192.168.1.100".parse().unwrap();
        let client2: IpAddr = "192.168.1.101".parse().unwrap();

        let mut allowed = 0;
        for i in 0..15 {
            let ip = if i % 2 == 0 { client1 } else { client2 };
            if limiter.check_rate_limit(ip, "search").await {
                allowed += 1;
            }
        }

        // Should allow approximately 10 requests (global limit)
        assert!(allowed <= 11); // Allow some tolerance
    }

    #[tokio::test]
    async fn test_adaptive_rate_limiting() {
        let config = RateLimitConfig {
            global_requests_per_second: 10,
            per_client_requests_per_second: 10,
            adaptive_enabled: true,
            adaptive_threshold: 0.5,  // 50%
            adaptive_multiplier: 0.5, // Reduce to 50%
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        let client_ip: IpAddr = "192.168.1.100".parse().unwrap();

        // Make enough requests to trigger adaptive limiting
        for _ in 0..6 {
            limiter.check_rate_limit(client_ip, "search").await;
        }

        let stats = limiter.get_stats().await;
        // Adaptive limiting should be active
        assert_eq!(stats.current_multiplier, 0.5);
    }

    #[tokio::test]
    async fn test_operation_type_conversion() {
        assert_eq!(OperationType::parse_name("bind"), Some(OperationType::Bind));
        assert_eq!(
            OperationType::parse_name("SEARCH"),
            Some(OperationType::Search)
        );
        assert_eq!(
            OperationType::parse_name("ModifyDN"),
            Some(OperationType::ModifyDN)
        );
        assert_eq!(OperationType::parse_name("invalid"), None);

        assert_eq!(OperationType::Bind.as_str(), "bind");
        assert_eq!(OperationType::Search.as_str(), "search");
    }

    #[tokio::test]
    async fn test_adaptive_enabled_request_path_does_not_deadlock() {
        let limiter = RateLimiter::new(RateLimitConfig {
            adaptive_enabled: true,
            ..Default::default()
        });
        let client_ip: IpAddr = "192.168.1.100".parse().unwrap();

        let result = tokio::time::timeout(
            Duration::from_secs(1),
            limiter.check_rate_limit(client_ip, "search"),
        )
        .await;

        assert_eq!(result, Ok(true));
    }

    #[tokio::test]
    async fn test_manual_ban_is_idempotent_for_banned_stats() {
        let limiter = RateLimiter::new(RateLimitConfig::default());
        let client_ip: IpAddr = "192.168.1.100".parse().unwrap();

        limiter.ban_client(client_ip, Duration::from_secs(10)).await;
        limiter.ban_client(client_ip, Duration::from_secs(10)).await;

        let stats = limiter.get_stats().await;
        assert_eq!(stats.banned_clients, 1);

        limiter.unban_client(client_ip).await;
        limiter.unban_client(client_ip).await;

        let stats = limiter.get_stats().await;
        assert_eq!(stats.banned_clients, 0);
    }

    #[tokio::test]
    async fn test_detailed_rate_limit_decisions_and_snapshot() {
        let limiter = RateLimiter::new(RateLimitConfig {
            per_client_requests_per_second: 1,
            window_duration: Duration::from_millis(100),
            adaptive_enabled: false,
            ..Default::default()
        });
        let client_ip: IpAddr = "192.168.1.100".parse().unwrap();

        let decision = limiter.check_rate_limit_detailed(client_ip, "search").await;
        assert!(decision.allowed);
        assert_eq!(decision.reason, RateLimitDecisionReason::Allowed);

        let decision = limiter.check_rate_limit_detailed(client_ip, "search").await;
        assert!(!decision.allowed);
        assert_eq!(
            decision.reason,
            RateLimitDecisionReason::ClientLimitExceeded
        );

        let decision = limiter
            .check_rate_limit_detailed(client_ip, "unknown-op")
            .await;
        assert!(decision.allowed);
        assert_eq!(decision.reason, RateLimitDecisionReason::UnknownOperation);

        let snapshot = limiter.snapshot().await;
        assert_eq!(snapshot.stats.total_requests, 2);
        assert_eq!(snapshot.stats.requests_allowed, 1);
        assert_eq!(snapshot.stats.requests_blocked, 1);
        assert_eq!(snapshot.current_multiplier, 1.0);
    }
}

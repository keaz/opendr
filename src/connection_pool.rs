//! Connection Pool and Resource Management
//!
//! This module provides connection pooling and resource management capabilities
//! to prevent resource exhaustion and ensure efficient server operation.
//!
//! ## Features
//!
//! - **Connection Limits**: Maximum total connections and per-IP limits
//! - **Operation Limits**: Per-client operation limits to prevent resource hogging
//! - **Memory Tracking**: Monitor and limit memory usage per connection
//! - **Statistics**: Track connection and resource metrics
//!
//! ## Usage
//!
//! ```rust
//! use opendr::connection_pool::{ConnectionPool, ResourceLimits};
//! use std::net::SocketAddr;
//!
//! # tokio::runtime::Runtime::new().unwrap().block_on(async {
//! let limits = ResourceLimits::default();
//! let pool = ConnectionPool::new(limits);
//! let client_addr: SocketAddr = "127.0.0.1:1389".parse().unwrap();
//!
//! // Try to acquire a connection slot
//! if let Some(conn_id) = pool.acquire_connection(client_addr).await {
//!     // Connection accepted
//!     // ... handle connection ...
//!     pool.release_connection(conn_id).await;
//! } else {
//!     // Connection rejected due to limits
//! }
//! # });
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Unique identifier for a connection
pub type ConnectionId = u64;

/// Resource limits configuration
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// Maximum total concurrent connections
    pub max_connections: usize,

    /// Maximum connections per IP address
    pub max_connections_per_ip: usize,

    /// Maximum concurrent operations per connection
    pub max_operations_per_connection: usize,

    /// Maximum memory usage per connection (in bytes)
    pub max_memory_per_connection: usize,

    /// Maximum total server memory usage (in bytes)
    pub max_total_memory: usize,

    /// Connection idle timeout
    pub connection_idle_timeout: Duration,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_connections: 1000,
            max_connections_per_ip: 10,
            max_operations_per_connection: 100,
            max_memory_per_connection: 10 * 1024 * 1024, // 10 MB
            max_total_memory: 1024 * 1024 * 1024,        // 1 GB
            connection_idle_timeout: Duration::from_secs(600), // 10 minutes
        }
    }
}

/// Connection metadata
#[derive(Debug)]
struct ConnectionInfo {
    /// Unique connection ID
    id: ConnectionId,

    /// Client socket address
    addr: SocketAddr,

    /// Last activity time
    last_activity: Mutex<Instant>,

    /// Current number of operations
    operation_count: AtomicUsize,

    /// Estimated memory usage (in bytes)
    memory_usage: Mutex<usize>,
}

#[derive(Debug)]
struct PoolCounters {
    total_connections: AtomicU64,
    active_connections: AtomicUsize,
    total_operations: AtomicUsize,
    total_memory_usage: AtomicUsize,
    rejected_connections: AtomicU64,
    rejected_operations: AtomicU64,
    rejected_memory_updates: AtomicU64,
}

impl PoolCounters {
    fn new() -> Self {
        Self {
            total_connections: AtomicU64::new(0),
            active_connections: AtomicUsize::new(0),
            total_operations: AtomicUsize::new(0),
            total_memory_usage: AtomicUsize::new(0),
            rejected_connections: AtomicU64::new(0),
            rejected_operations: AtomicU64::new(0),
            rejected_memory_updates: AtomicU64::new(0),
        }
    }
}

/// Connection pool statistics
#[derive(Debug, Clone)]
pub struct PoolStatistics {
    /// Total connections ever created
    pub total_connections: u64,

    /// Current active connections
    pub active_connections: usize,

    /// Current total operations
    pub total_operations: usize,

    /// Current total memory usage
    pub total_memory_usage: usize,

    /// Connections rejected due to limits
    pub rejected_connections: u64,

    /// Operations rejected due to limits
    pub rejected_operations: u64,

    /// Memory updates rejected due to limits
    pub rejected_memory_updates: u64,

    /// Connections by IP address
    pub connections_by_ip: HashMap<String, usize>,
}

/// Point-in-time resource snapshot for observability and future FSM hooks.
#[derive(Debug, Clone)]
pub struct ResourceSnapshot {
    pub limits: ResourceLimits,
    pub active_connections: usize,
    pub total_operations: usize,
    pub total_memory_usage: usize,
    pub rejected_connections: u64,
    pub rejected_operations: u64,
    pub rejected_memory_updates: u64,
}

/// Connection pool manager
pub struct ConnectionPool {
    /// Resource limits
    limits: ResourceLimits,

    /// Active connections
    connections: Arc<RwLock<HashMap<ConnectionId, Arc<ConnectionInfo>>>>,

    /// Connections grouped by IP address
    connections_by_ip: Arc<RwLock<HashMap<String, Vec<ConnectionId>>>>,

    /// Next connection ID
    next_id: AtomicU64,

    /// Statistics
    counters: PoolCounters,
}

impl ConnectionPool {
    /// Create a new connection pool with specified limits
    pub fn new(limits: ResourceLimits) -> Self {
        Self {
            limits,
            connections: Arc::new(RwLock::new(HashMap::new())),
            connections_by_ip: Arc::new(RwLock::new(HashMap::new())),
            next_id: AtomicU64::new(0),
            counters: PoolCounters::new(),
        }
    }

    async fn connection_info(&self, conn_id: ConnectionId) -> Option<Arc<ConnectionInfo>> {
        self.connections.read().await.get(&conn_id).cloned()
    }

    fn atomic_saturating_sub(counter: &AtomicUsize, value: usize) {
        if value == 0 {
            return;
        }
        counter
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                Some(current.saturating_sub(value))
            })
            .ok();
    }

    fn try_reserve_total_memory(&self, delta: usize) -> bool {
        if delta == 0 {
            return true;
        }

        let mut current = self.counters.total_memory_usage.load(Ordering::Acquire);
        loop {
            let Some(next) = current.checked_add(delta) else {
                return false;
            };
            if next > self.limits.max_total_memory {
                return false;
            }

            match self.counters.total_memory_usage.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    /// Attempt to acquire a connection slot
    ///
    /// Returns `Some(ConnectionId)` if the connection is allowed,
    /// or `None` if limits are exceeded.
    pub async fn acquire_connection(&self, addr: SocketAddr) -> Option<ConnectionId> {
        let mut connections = self.connections.write().await;
        let mut connections_by_ip = self.connections_by_ip.write().await;

        // Check total connection limit
        if connections.len() >= self.limits.max_connections {
            self.counters
                .rejected_connections
                .fetch_add(1, Ordering::Relaxed);
            return None;
        }

        // Check per-IP connection limit
        let ip_str = addr.ip().to_string();
        let ip_count = connections_by_ip.get(&ip_str).map(|v| v.len()).unwrap_or(0);
        if ip_count >= self.limits.max_connections_per_ip {
            self.counters
                .rejected_connections
                .fetch_add(1, Ordering::Relaxed);
            return None;
        }

        // Allocate connection ID
        let conn_id = self.next_id.fetch_add(1, Ordering::Relaxed);

        // Create connection info
        let conn_info = Arc::new(ConnectionInfo {
            id: conn_id,
            addr,
            last_activity: Mutex::new(Instant::now()),
            operation_count: AtomicUsize::new(0),
            memory_usage: Mutex::new(0),
        });

        // Register connection
        connections.insert(conn_id, conn_info);
        connections_by_ip
            .entry(ip_str.clone())
            .or_insert_with(Vec::new)
            .push(conn_id);

        // Update statistics
        self.counters
            .total_connections
            .fetch_add(1, Ordering::Relaxed);
        self.counters
            .active_connections
            .store(connections.len(), Ordering::Release);

        Some(conn_id)
    }

    /// Release a connection slot
    pub async fn release_connection(&self, conn_id: ConnectionId) {
        let mut connections = self.connections.write().await;
        let mut connections_by_ip = self.connections_by_ip.write().await;

        if let Some(conn_info) = connections.remove(&conn_id) {
            let ip_str = conn_info.addr.ip().to_string();

            // Remove from IP tracking
            if let Some(ip_conns) = connections_by_ip.get_mut(&ip_str) {
                ip_conns.retain(|&id| id != conn_id);
                if ip_conns.is_empty() {
                    connections_by_ip.remove(&ip_str);
                }
            }

            // Update statistics
            self.counters
                .active_connections
                .store(connections.len(), Ordering::Release);
            Self::atomic_saturating_sub(
                &self.counters.total_operations,
                conn_info.operation_count.load(Ordering::Acquire),
            );
            Self::atomic_saturating_sub(
                &self.counters.total_memory_usage,
                *conn_info
                    .memory_usage
                    .lock()
                    .expect("connection memory lock poisoned"),
            );
        }
    }

    /// Attempt to start an operation on a connection
    ///
    /// Returns `true` if the operation is allowed, `false` if limits are exceeded.
    pub async fn start_operation(&self, conn_id: ConnectionId) -> bool {
        let Some(conn_info) = self.connection_info(conn_id).await else {
            return false;
        };

        let limit = self.limits.max_operations_per_connection;
        let mut current = conn_info.operation_count.load(Ordering::Acquire);
        loop {
            if current >= limit {
                self.counters
                    .rejected_operations
                    .fetch_add(1, Ordering::Relaxed);
                return false;
            }

            match conn_info.operation_count.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    *conn_info
                        .last_activity
                        .lock()
                        .expect("connection activity lock poisoned") = Instant::now();
                    self.counters
                        .total_operations
                        .fetch_add(1, Ordering::AcqRel);
                    return true;
                }
                Err(actual) => current = actual,
            }
        }
    }

    /// Complete an operation on a connection
    pub async fn end_operation(&self, conn_id: ConnectionId) {
        let Some(conn_info) = self.connection_info(conn_id).await else {
            return;
        };

        let previous = conn_info
            .operation_count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count > 0).then_some(count - 1)
            })
            .unwrap_or(0);

        if previous > 0 {
            *conn_info
                .last_activity
                .lock()
                .expect("connection activity lock poisoned") = Instant::now();
            self.counters
                .total_operations
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                    (count > 0).then_some(count - 1)
                })
                .ok();
        }
    }

    /// Update memory usage for a connection
    pub async fn update_memory_usage(&self, conn_id: ConnectionId, memory_delta: isize) -> bool {
        let Some(conn_info) = self.connection_info(conn_id).await else {
            return false;
        };

        let mut memory_usage = conn_info
            .memory_usage
            .lock()
            .expect("connection memory lock poisoned");

        let current_usage = *memory_usage;
        let new_usage = if memory_delta >= 0 {
            current_usage.saturating_add(memory_delta as usize)
        } else {
            current_usage.saturating_sub((-memory_delta) as usize)
        };

        if memory_delta >= 0 {
            // Check per-connection limit
            if new_usage > self.limits.max_memory_per_connection {
                self.counters
                    .rejected_memory_updates
                    .fetch_add(1, Ordering::Relaxed);
                return false;
            }

            // Check total memory limit
            let delta = memory_delta as usize;
            if !self.try_reserve_total_memory(delta) {
                self.counters
                    .rejected_memory_updates
                    .fetch_add(1, Ordering::Relaxed);
                return false;
            }
            *memory_usage = new_usage;
        } else {
            let released = current_usage.saturating_sub(new_usage);
            *memory_usage = new_usage;
            Self::atomic_saturating_sub(&self.counters.total_memory_usage, released);
        }

        true
    }

    /// Update last activity time for a connection
    pub async fn update_activity(&self, conn_id: ConnectionId) {
        if let Some(conn_info) = self.connection_info(conn_id).await {
            *conn_info
                .last_activity
                .lock()
                .expect("connection activity lock poisoned") = Instant::now();
        }
    }

    /// Get idle connections that exceed the timeout
    pub async fn get_idle_connections(&self) -> Vec<ConnectionId> {
        let connections = self.connections.read().await;
        let now = Instant::now();
        let timeout = self.limits.connection_idle_timeout;

        connections
            .values()
            .filter(|conn| {
                let last_activity = *conn
                    .last_activity
                    .lock()
                    .expect("connection activity lock poisoned");
                now.duration_since(last_activity) > timeout
            })
            .map(|conn| conn.id)
            .collect()
    }

    /// Clean up idle connections
    pub async fn cleanup_idle_connections(&self) -> usize {
        let idle_conns = self.get_idle_connections().await;
        let count = idle_conns.len();

        for conn_id in idle_conns {
            self.release_connection(conn_id).await;
        }

        count
    }

    /// Get current pool statistics
    pub async fn get_statistics(&self) -> PoolStatistics {
        let connections_by_ip = self
            .connections_by_ip
            .read()
            .await
            .iter()
            .map(|(ip, connections)| (ip.clone(), connections.len()))
            .collect();

        PoolStatistics {
            total_connections: self.counters.total_connections.load(Ordering::Acquire),
            active_connections: self.counters.active_connections.load(Ordering::Acquire),
            total_operations: self.counters.total_operations.load(Ordering::Acquire),
            total_memory_usage: self.counters.total_memory_usage.load(Ordering::Acquire),
            rejected_connections: self.counters.rejected_connections.load(Ordering::Acquire),
            rejected_operations: self.counters.rejected_operations.load(Ordering::Acquire),
            rejected_memory_updates: self
                .counters
                .rejected_memory_updates
                .load(Ordering::Acquire),
            connections_by_ip,
        }
    }

    /// Get a point-in-time resource snapshot including current limits and utilization.
    pub async fn snapshot(&self) -> ResourceSnapshot {
        let stats = self.get_statistics().await;
        ResourceSnapshot {
            limits: self.limits.clone(),
            active_connections: stats.active_connections,
            total_operations: stats.total_operations,
            total_memory_usage: stats.total_memory_usage,
            rejected_connections: stats.rejected_connections,
            rejected_operations: stats.rejected_operations,
            rejected_memory_updates: stats.rejected_memory_updates,
        }
    }

    /// Get connection count for an IP address
    pub async fn get_ip_connection_count(&self, addr: SocketAddr) -> usize {
        let connections_by_ip = self.connections_by_ip.read().await;
        let ip_str = addr.ip().to_string();
        connections_by_ip.get(&ip_str).map(|v| v.len()).unwrap_or(0)
    }

    /// Check if a connection exists
    pub async fn has_connection(&self, conn_id: ConnectionId) -> bool {
        let connections = self.connections.read().await;
        connections.contains_key(&conn_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    #[tokio::test]
    async fn test_connection_pool_basic() {
        let pool = ConnectionPool::new(ResourceLimits::default());

        // Acquire a connection
        let conn_id = pool.acquire_connection(test_addr(1234)).await;
        assert!(conn_id.is_some());

        let conn_id = conn_id.unwrap();

        // Check statistics
        let stats = pool.get_statistics().await;
        assert_eq!(stats.active_connections, 1);
        assert_eq!(stats.total_connections, 1);
        assert_eq!(stats.rejected_memory_updates, 0);

        // Release connection
        pool.release_connection(conn_id).await;

        let stats = pool.get_statistics().await;
        assert_eq!(stats.active_connections, 0);
    }

    #[tokio::test]
    async fn test_resource_snapshot_tracks_limits_and_usage() {
        let limits = ResourceLimits {
            max_connections: 2,
            max_connections_per_ip: 1,
            max_operations_per_connection: 2,
            max_memory_per_connection: 1000,
            max_total_memory: 1500,
            connection_idle_timeout: Duration::from_secs(10),
        };
        let pool = ConnectionPool::new(limits.clone());

        let conn_id = pool.acquire_connection(test_addr(1234)).await.unwrap();
        assert!(pool.start_operation(conn_id).await);
        assert!(pool.update_memory_usage(conn_id, 500).await);

        let snapshot = pool.snapshot().await;
        assert_eq!(snapshot.limits.max_connections, limits.max_connections);
        assert_eq!(snapshot.active_connections, 1);
        assert_eq!(snapshot.total_operations, 1);
        assert_eq!(snapshot.total_memory_usage, 500);
        assert_eq!(snapshot.rejected_connections, 0);
        assert_eq!(snapshot.rejected_operations, 0);
        assert_eq!(snapshot.rejected_memory_updates, 0);
    }

    #[tokio::test]
    async fn test_max_connections_limit() {
        let limits = ResourceLimits {
            max_connections: 2,
            ..Default::default()
        };
        let pool = ConnectionPool::new(limits);

        // Acquire two connections
        let conn1 = pool.acquire_connection(test_addr(1234)).await;
        let conn2 = pool.acquire_connection(test_addr(1235)).await;
        assert!(conn1.is_some());
        assert!(conn2.is_some());

        // Third connection should be rejected
        let conn3 = pool.acquire_connection(test_addr(1236)).await;
        assert!(conn3.is_none());

        // Check rejection count
        let stats = pool.get_statistics().await;
        assert_eq!(stats.rejected_connections, 1);
    }

    #[tokio::test]
    async fn test_per_ip_limit() {
        let limits = ResourceLimits {
            max_connections_per_ip: 2,
            ..Default::default()
        };
        let pool = ConnectionPool::new(limits);

        let addr = test_addr(0);

        // Acquire two connections from same IP
        let conn1 = pool.acquire_connection(addr).await;
        let conn2 = pool.acquire_connection(addr).await;
        assert!(conn1.is_some());
        assert!(conn2.is_some());

        // Third connection from same IP should be rejected
        let conn3 = pool.acquire_connection(addr).await;
        assert!(conn3.is_none());

        // Different IP should work
        let other_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 1234);
        let conn4 = pool.acquire_connection(other_addr).await;
        assert!(conn4.is_some());
    }

    #[tokio::test]
    async fn test_operation_limits() {
        let limits = ResourceLimits {
            max_operations_per_connection: 2,
            ..Default::default()
        };
        let pool = ConnectionPool::new(limits);

        let conn_id = pool.acquire_connection(test_addr(1234)).await.unwrap();

        // Start two operations
        assert!(pool.start_operation(conn_id).await);
        assert!(pool.start_operation(conn_id).await);

        // Third operation should be rejected
        assert!(!pool.start_operation(conn_id).await);

        // End one operation
        pool.end_operation(conn_id).await;

        // Now we should be able to start another
        assert!(pool.start_operation(conn_id).await);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_operation_limit_remains_enforced() {
        let limits = ResourceLimits {
            max_operations_per_connection: 64,
            ..Default::default()
        };
        let pool = Arc::new(ConnectionPool::new(limits));
        let conn_id = pool.acquire_connection(test_addr(1234)).await.unwrap();

        let mut handles = Vec::new();
        for _ in 0..256 {
            let pool = Arc::clone(&pool);
            handles.push(tokio::spawn(
                async move { pool.start_operation(conn_id).await },
            ));
        }

        let mut started = 0;
        for handle in handles {
            if handle.await.unwrap() {
                started += 1;
            }
        }

        assert_eq!(started, 64);
        let stats = pool.get_statistics().await;
        assert_eq!(stats.total_operations, 64);
        assert_eq!(stats.rejected_operations, 192);

        let mut handles = Vec::new();
        for _ in 0..started {
            let pool = Arc::clone(&pool);
            handles.push(tokio::spawn(async move {
                pool.end_operation(conn_id).await;
            }));
        }
        for handle in handles {
            handle.await.unwrap();
        }

        let stats = pool.get_statistics().await;
        assert_eq!(stats.total_operations, 0);
    }

    #[tokio::test]
    async fn test_memory_tracking() {
        let limits = ResourceLimits {
            max_memory_per_connection: 1000,
            max_total_memory: 2000,
            ..Default::default()
        };
        let pool = ConnectionPool::new(limits);

        let conn_id = pool.acquire_connection(test_addr(1234)).await.unwrap();

        // Allocate memory
        assert!(pool.update_memory_usage(conn_id, 500).await);
        assert!(pool.update_memory_usage(conn_id, 400).await);

        // Should be at 900 bytes, under limit
        let stats = pool.get_statistics().await;
        assert_eq!(stats.total_memory_usage, 900);

        // Try to allocate 200 more (would exceed per-connection limit of 1000)
        assert!(!pool.update_memory_usage(conn_id, 200).await);

        // Release some memory
        assert!(pool.update_memory_usage(conn_id, -500).await);

        // Now we should be able to allocate again
        assert!(pool.update_memory_usage(conn_id, 200).await);
    }

    #[tokio::test]
    async fn test_idle_connection_cleanup() {
        let limits = ResourceLimits {
            connection_idle_timeout: Duration::from_millis(100),
            ..Default::default()
        };
        let pool = ConnectionPool::new(limits);

        let conn_id = pool.acquire_connection(test_addr(1234)).await.unwrap();

        // Wait for timeout
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Connection should be idle
        let idle = pool.get_idle_connections().await;
        assert_eq!(idle.len(), 1);
        assert_eq!(idle[0], conn_id);

        // Clean up idle connections
        let cleaned = pool.cleanup_idle_connections().await;
        assert_eq!(cleaned, 1);

        // Connection should be gone
        assert!(!pool.has_connection(conn_id).await);
    }

    #[tokio::test]
    async fn test_activity_update() {
        let limits = ResourceLimits {
            connection_idle_timeout: Duration::from_millis(100),
            ..Default::default()
        };
        let pool = ConnectionPool::new(limits);

        let conn_id = pool.acquire_connection(test_addr(1234)).await.unwrap();

        // Wait a bit
        tokio::time::sleep(Duration::from_millis(60)).await;

        // Update activity
        pool.update_activity(conn_id).await;

        // Wait for what would be timeout
        tokio::time::sleep(Duration::from_millis(60)).await;

        // Should not be idle because we updated activity
        let idle = pool.get_idle_connections().await;
        assert_eq!(idle.len(), 0);
    }

    #[tokio::test]
    async fn test_statistics() {
        let pool = ConnectionPool::new(ResourceLimits::default());

        let conn1 = pool.acquire_connection(test_addr(1234)).await.unwrap();
        let conn2 = pool.acquire_connection(test_addr(1235)).await.unwrap();

        pool.start_operation(conn1).await;
        pool.start_operation(conn1).await;
        pool.start_operation(conn2).await;

        pool.update_memory_usage(conn1, 100).await;
        pool.update_memory_usage(conn2, 200).await;

        let stats = pool.get_statistics().await;
        assert_eq!(stats.active_connections, 2);
        assert_eq!(stats.total_operations, 3);
        assert_eq!(stats.total_memory_usage, 300);
    }
}

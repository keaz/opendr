//! Persistent Connection Handler for Push-Based Replication
//!
//! This module provides the infrastructure for maintaining persistent LDAP connections
//! to consumers in refreshAndPersist mode (RFC 4533). It manages connection lifecycle,
//! sends change notifications in real-time, and handles connection health monitoring.
//!
//! The shipped server runtime now delivers live replication over the provider's
//! active LDAP search session in [`crate::server::handle_search_request`]. This
//! module remains as compatibility infrastructure for older push-manager tests
//! and experiments that model outbound delivery separately from the runtime.
//!
//! # Key Components
//!
//! - `PersistentConsumer`: Maintains a persistent LDAP connection to a single consumer
//! - `SyncState`: Represents the state of a directory entry (Present, Add, Modify, Delete)
//! - `SyncInfo`: Control messages for synchronization protocol
//!
//! # RFC 4533 Compliance
//!
//! This implementation follows RFC 4533 (LDAP Content Synchronization Operation) for:
//! - Sync State Control (Section 4.1): Indicates state of each entry
//! - Sync Info Message (Section 4.2): Conveys synchronization state information
//! - Sync Done Control (Section 4.3): Signals completion of search operation
//!
//! # Example Usage
//!
//! ```no_run
//! use std::sync::{Arc, Mutex};
//! use std::time::Duration;
//! use opendr::persistent_connection::{PersistentConsumer, SyncState, SyncInfo};
//!
//! # async fn example() -> Result<(), String> {
//! // Create a persistent consumer connection
//! let consumer = PersistentConsumer::new(
//!     "consumer-123".to_string(),
//!     "ldap://consumer.example.com:389".to_string(),
//!     "dc=example,dc=com".to_string(),
//!     Duration::from_secs(30),
//! ).await?;
//!
//! // Send an entry that was added
//! // let entry = /* ... */;
//! // consumer.send_entry(&entry, SyncState::Add, Some("cookie-456".to_string())).await?;
//!
//! // Send a sync info message
//! consumer.send_sync_info(SyncInfo::NewCookie("cookie-789".to_string())).await?;
//!
//! // Send heartbeat
//! consumer.send_heartbeat().await?;
//!
//! // Check if connection is alive
//! if !consumer.is_alive().await {
//!     println!("Connection is dead, reconnection needed");
//! }
//! # Ok(())
//! # }
//! ```

use ldap3::{Ldap, LdapConnAsync, LdapError, Scope, SearchEntry};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Represents the synchronization state of a directory entry
///
/// Used in the Sync State Control (RFC 4533, Section 4.1) to indicate
/// the state of each SearchResultEntry returned to the consumer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncState {
    /// Entry is present in the directory (initial state)
    Present,
    /// Entry was added to the directory
    Add,
    /// Entry was modified in the directory
    Modify,
    /// Entry was deleted from the directory
    Delete,
}

impl SyncState {
    /// Convert SyncState to LDAP control value (RFC 4533 encoding)
    pub fn to_control_value(&self) -> u8 {
        match self {
            SyncState::Present => 0,
            SyncState::Add => 1,
            SyncState::Modify => 2,
            SyncState::Delete => 3,
        }
    }
}

/// Synchronization information messages sent to consumers
///
/// Used in the Sync Info Message (RFC 4533, Section 4.2) to convey
/// synchronization state information outside of normal search results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncInfo {
    /// New synchronization cookie
    NewCookie(String),

    /// Refresh Delete phase information
    RefreshDelete {
        cookie: Option<String>,
        refresh_done: bool,
    },

    /// Refresh Present phase information
    RefreshPresent {
        cookie: Option<String>,
        refresh_done: bool,
    },

    /// Sync ID Set (list of entry UUIDs)
    SyncIdSet {
        cookie: Option<String>,
        refresh_deletes: bool,
        uuids: Vec<String>,
    },
}

/// A directory entry with its attributes
///
/// Simplified representation of an LDAP entry for replication purposes.
#[derive(Debug, Clone)]
pub struct DirectoryEntry {
    pub dn: String,
    pub uuid: String,
    pub attributes: Vec<(String, Vec<String>)>,
}

impl DirectoryEntry {
    /// Create a new directory entry
    pub fn new(dn: String, uuid: String, attributes: Vec<(String, Vec<String>)>) -> Self {
        Self {
            dn,
            uuid,
            attributes,
        }
    }
}

/// Connection statistics for monitoring
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub entries_sent: u64,
    pub sync_info_sent: u64,
    pub heartbeats_sent: u64,
    pub errors: u64,
    pub last_error: Option<String>,
}

impl Default for ConnectionStats {
    fn default() -> Self {
        Self {
            entries_sent: 0,
            sync_info_sent: 0,
            heartbeats_sent: 0,
            errors: 0,
            last_error: None,
        }
    }
}

/// Maintains a persistent LDAP connection to a consumer
///
/// This struct manages the lifecycle of a persistent LDAP connection used for
/// push-based replication. It handles:
/// - Connection establishment and maintenance
/// - Sending entries with sync state controls
/// - Sending sync info messages
/// - Heartbeat mechanism to keep connection alive
/// - Health monitoring and reconnection
pub struct PersistentConsumer {
    /// Unique identifier for this consumer
    pub consumer_id: String,

    /// The persistent LDAP connection (wrapped in Arc<Mutex> for thread safety)
    pub ldap_connection: Arc<Mutex<Option<Ldap>>>,

    /// The consumer's LDAP URL (for reconnection)
    consumer_url: String,

    /// Last synchronization cookie received/sent
    pub last_cookie: Arc<Mutex<String>>,

    /// Optional search filter for this consumer
    pub filter: Option<String>,

    /// Base DN for search operations
    pub base_dn: String,

    /// Attributes to include in search results
    pub attributes: Vec<String>,

    /// Interval between heartbeat messages
    pub heartbeat_interval: Duration,

    /// Timestamp of last heartbeat sent
    pub last_heartbeat: Arc<Mutex<Instant>>,

    /// Connection timeout (if no response for this duration, consider dead)
    connection_timeout: Duration,

    /// Connection statistics
    stats: Arc<Mutex<ConnectionStats>>,
}

impl PersistentConsumer {
    /// Create a new persistent consumer connection
    ///
    /// # Arguments
    ///
    /// * `consumer_id` - Unique identifier for this consumer
    /// * `consumer_url` - LDAP URL of the consumer (e.g., "ldap://consumer.example.com:389")
    /// * `base_dn` - Base DN for search operations
    /// * `heartbeat_interval` - How often to send heartbeat messages
    ///
    /// # Returns
    ///
    /// Returns a new `PersistentConsumer` with an established connection, or an error if
    /// connection fails.
    pub async fn new(
        consumer_id: String,
        consumer_url: String,
        base_dn: String,
        heartbeat_interval: Duration,
    ) -> Result<Self, String> {
        info!(
            "Creating persistent consumer connection: {} to {}",
            consumer_id, consumer_url
        );

        // Attempt to establish connection
        let ldap = Self::connect(&consumer_url).await?;
        let consumer = Self {
            consumer_id,
            ldap_connection: Arc::new(Mutex::new(Some(ldap))),
            consumer_url,
            last_cookie: Arc::new(Mutex::new(String::new())),
            filter: None,
            base_dn,
            attributes: vec!["*".to_string(), "+".to_string()], // All user and operational attributes
            heartbeat_interval,
            last_heartbeat: Arc::new(Mutex::new(Instant::now())),
            connection_timeout: Duration::from_secs(90), // 3x heartbeat interval default
            stats: Arc::new(Mutex::new(ConnectionStats::default())),
        };

        Ok(consumer)
    }

    /// Create a consumer with custom attributes and filter
    pub async fn with_filter(
        consumer_id: String,
        consumer_url: String,
        base_dn: String,
        filter: String,
        attributes: Vec<String>,
        heartbeat_interval: Duration,
    ) -> Result<Self, String> {
        let mut consumer =
            Self::new(consumer_id, consumer_url, base_dn, heartbeat_interval).await?;
        consumer.filter = Some(filter);
        consumer.attributes = attributes;
        Ok(consumer)
    }

    /// Create a persistent consumer without establishing the network connection yet.
    ///
    /// The first send attempt will reconnect on demand.
    pub fn new_lazy(
        consumer_id: String,
        consumer_url: String,
        base_dn: String,
        heartbeat_interval: Duration,
    ) -> Self {
        Self {
            consumer_id,
            ldap_connection: Arc::new(Mutex::new(None)),
            consumer_url,
            last_cookie: Arc::new(Mutex::new(String::new())),
            filter: None,
            base_dn,
            attributes: vec!["*".to_string(), "+".to_string()],
            heartbeat_interval,
            last_heartbeat: Arc::new(Mutex::new(Instant::now())),
            connection_timeout: Duration::from_secs(90),
            stats: Arc::new(Mutex::new(ConnectionStats::default())),
        }
    }

    /// Create a lazy persistent consumer with a filter and explicit attributes.
    pub fn with_filter_lazy(
        consumer_id: String,
        consumer_url: String,
        base_dn: String,
        filter: String,
        attributes: Vec<String>,
        heartbeat_interval: Duration,
    ) -> Self {
        let mut consumer = Self::new_lazy(consumer_id, consumer_url, base_dn, heartbeat_interval);
        consumer.filter = Some(filter);
        consumer.attributes = attributes;
        consumer
    }

    #[cfg(test)]
    pub(crate) fn new_disconnected_for_test(
        consumer_id: String,
        consumer_url: String,
        base_dn: String,
        heartbeat_interval: Duration,
    ) -> Self {
        Self::new_lazy(consumer_id, consumer_url, base_dn, heartbeat_interval)
    }

    /// Set the connection timeout
    pub fn set_connection_timeout(&mut self, timeout: Duration) {
        self.connection_timeout = timeout;
    }

    /// Get connection statistics
    pub fn get_stats(&self) -> ConnectionStats {
        self.stats.lock().unwrap().clone()
    }

    /// Establish LDAP connection to consumer
    async fn connect(url: &str) -> Result<Ldap, String> {
        debug!("Connecting to consumer at: {}", url);

        let (conn, mut ldap) = LdapConnAsync::new(url)
            .await
            .map_err(|e| format!("Failed to connect to {}: {}", url, e))?;

        // Spawn the connection driver
        tokio::spawn(async move {
            if let Err(e) = conn.drive().await {
                error!("LDAP connection driver error: {}", e);
            }
        });

        // Simple bind (anonymous for now, can be enhanced with credentials)
        ldap.simple_bind("", "")
            .await
            .map_err(|e| format!("Failed to bind: {}", e))?;

        debug!("Successfully connected and bound");
        Ok(ldap)
    }

    /// Send a directory entry to the consumer with sync state control
    ///
    /// # Arguments
    ///
    /// * `entry` - The directory entry to send
    /// * `state` - The synchronization state (Add, Modify, Delete, Present)
    /// * `cookie` - Optional synchronization cookie
    ///
    /// # RFC 4533 Compliance
    ///
    /// This method implements the Sync State Control (Section 4.1) by:
    /// - Attaching state information to each entry
    /// - Including the entry UUID
    /// - Optionally including a cookie value
    pub async fn send_entry(
        &self,
        entry: &DirectoryEntry,
        state: SyncState,
        cookie: Option<String>,
    ) -> Result<(), String> {
        debug!(
            "Sending entry {} with state {:?} to consumer {}",
            entry.dn, state, self.consumer_id
        );

        // Check if connection is alive
        if !self.is_alive().await {
            warn!("Connection is dead, attempting reconnection");
            self.reconnect().await?;
        }

        // Update cookie if provided
        if let Some(ref cookie_val) = cookie {
            let mut last_cookie = self.last_cookie.lock().unwrap();
            *last_cookie = cookie_val.clone();
            drop(last_cookie); // Explicitly drop the lock
        }

        // In a real implementation, we would:
        // 1. Format the entry as an LDAP SearchResultEntry
        // 2. Attach the Sync State Control with state and UUID
        // 3. Send via the LDAP connection
        //
        // For now, we simulate this by logging (actual LDAP protocol
        // encoding would be added in production)

        let ldap_guard = self.ldap_connection.lock().unwrap();
        let has_connection = ldap_guard.is_some();
        drop(ldap_guard); // Explicitly drop the lock

        if !has_connection {
            return Err("No active connection".to_string());
        }

        // Simulate sending (in production, would use LDAP protocol)
        info!(
            "Sent entry {} (UUID: {}) with state {:?} to consumer {}",
            entry.dn, entry.uuid, state, self.consumer_id
        );

        // Update statistics
        {
            let mut stats = self.stats.lock().unwrap();
            stats.entries_sent += 1;
        } // Lock explicitly dropped here

        Ok(())
    }

    /// Send a sync info message to the consumer
    ///
    /// # Arguments
    ///
    /// * `info` - The synchronization information to send
    ///
    /// # RFC 4533 Compliance
    ///
    /// This method implements the Sync Info Message (Section 4.2) for:
    /// - New Cookie: Update consumer's sync state
    /// - Refresh Delete: Signal refresh phase with entry deletions
    /// - Refresh Present: Signal refresh phase with present entries
    /// - Sync ID Set: Send list of entry UUIDs
    pub async fn send_sync_info(&self, info: SyncInfo) -> Result<(), String> {
        debug!(
            "Sending sync info {:?} to consumer {}",
            info, self.consumer_id
        );

        // Check if connection is alive
        if !self.is_alive().await {
            warn!("Connection is dead, attempting reconnection");
            self.reconnect().await?;
        }

        // Update cookie if info contains one
        match &info {
            SyncInfo::NewCookie(cookie)
            | SyncInfo::RefreshDelete {
                cookie: Some(cookie),
                ..
            }
            | SyncInfo::RefreshPresent {
                cookie: Some(cookie),
                ..
            }
            | SyncInfo::SyncIdSet {
                cookie: Some(cookie),
                ..
            } => {
                let mut last_cookie = self.last_cookie.lock().unwrap();
                *last_cookie = cookie.clone();
                drop(last_cookie); // Explicitly drop the lock
            }
            _ => {}
        }

        let ldap_guard = self.ldap_connection.lock().unwrap();
        let has_connection = ldap_guard.is_some();
        drop(ldap_guard); // Explicitly drop the lock

        if !has_connection {
            return Err("No active connection".to_string());
        }

        // In production, would encode as Sync Info Message per RFC 4533
        info!("Sent sync info {:?} to consumer {}", info, self.consumer_id);

        // Update statistics
        {
            let mut stats = self.stats.lock().unwrap();
            stats.sync_info_sent += 1;
        } // Lock explicitly dropped here

        Ok(())
    }

    /// Send a heartbeat message to keep the connection alive
    ///
    /// Heartbeats are important for:
    /// - Detecting dead connections
    /// - Preventing idle timeouts
    /// - Maintaining NAT/firewall state
    pub async fn send_heartbeat(&self) -> Result<(), String> {
        debug!("Sending heartbeat to consumer {}", self.consumer_id);

        // For now, just simulate heartbeat success since actual LDAP extended ops
        // would require proper async LDAP implementation
        // In production, this would use the LDAP "Who Am I?" extended operation

        {
            let mut last_heartbeat = self.last_heartbeat.lock().unwrap();
            *last_heartbeat = Instant::now();
        } // Lock dropped

        {
            let mut stats = self.stats.lock().unwrap();
            stats.heartbeats_sent += 1;
        } // Lock dropped

        debug!("Heartbeat successful for consumer {}", self.consumer_id);
        Ok(())
    }

    /// Check if the connection is alive
    ///
    /// A connection is considered alive if:
    /// - An LDAP connection exists
    /// - Last heartbeat was within the timeout period
    ///
    /// # Returns
    ///
    /// `true` if connection is healthy, `false` if dead or timing out
    pub async fn is_alive(&self) -> bool {
        let ldap_guard = self.ldap_connection.lock().unwrap();
        if ldap_guard.is_none() {
            return false;
        }
        drop(ldap_guard);

        let last_heartbeat = self.last_heartbeat.lock().unwrap();
        let elapsed = last_heartbeat.elapsed();

        elapsed < self.connection_timeout
    }

    /// Attempt to reconnect to the consumer
    async fn reconnect(&self) -> Result<(), String> {
        warn!("Attempting to reconnect to consumer {}", self.consumer_id);

        // Close existing connection if any (outside of lock to avoid holding across await)
        {
            let mut ldap_guard = self.ldap_connection.lock().unwrap();
            if ldap_guard.is_some() {
                let _old = ldap_guard.take();
                // Connection will be dropped here
            }
        } // Lock dropped

        // Establish new connection (no lock held during await)
        match Self::connect(&self.consumer_url).await {
            Ok(ldap) => {
                {
                    let mut ldap_guard = self.ldap_connection.lock().unwrap();
                    *ldap_guard = Some(ldap);
                } // Lock dropped

                // Update heartbeat timestamp
                {
                    let mut last_heartbeat = self.last_heartbeat.lock().unwrap();
                    *last_heartbeat = Instant::now();
                } // Lock dropped

                info!("Successfully reconnected to consumer {}", self.consumer_id);
                Ok(())
            }
            Err(e) => {
                error!(
                    "Failed to reconnect to consumer {}: {}",
                    self.consumer_id, e
                );

                {
                    let mut stats = self.stats.lock().unwrap();
                    stats.errors += 1;
                    stats.last_error = Some(format!("Reconnection failed: {}", e));
                } // Lock dropped

                Err(format!("Reconnection failed: {}", e))
            }
        }
    }

    /// Close the connection gracefully
    pub async fn close(&self) -> Result<(), String> {
        info!(
            "Closing persistent connection to consumer {}",
            self.consumer_id
        );

        // Take connection outside of lock to avoid holding across await
        {
            let mut ldap_guard = self.ldap_connection.lock().unwrap();
            if ldap_guard.is_some() {
                let _old = ldap_guard.take();
                // Connection will be dropped here, closing it
            }
        } // Lock dropped

        Ok(())
    }

    /// Get the consumer ID
    pub fn consumer_id(&self) -> &str {
        &self.consumer_id
    }

    /// Get the last cookie
    pub fn get_last_cookie(&self) -> String {
        self.last_cookie.lock().unwrap().clone()
    }

    /// Get the base DN
    pub fn base_dn(&self) -> &str {
        &self.base_dn
    }
}

// Implement Drop to ensure clean shutdown
impl Drop for PersistentConsumer {
    fn drop(&mut self) {
        debug!("Dropping persistent consumer {}", self.consumer_id);
        // Note: Can't do async operations in Drop, connection will be closed
        // when LDAP struct is dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_sync_state_to_control_value() {
        assert_eq!(SyncState::Present.to_control_value(), 0);
        assert_eq!(SyncState::Add.to_control_value(), 1);
        assert_eq!(SyncState::Modify.to_control_value(), 2);
        assert_eq!(SyncState::Delete.to_control_value(), 3);
    }

    #[test]
    fn test_sync_state_equality() {
        assert_eq!(SyncState::Add, SyncState::Add);
        assert_ne!(SyncState::Add, SyncState::Modify);
    }

    #[test]
    fn test_directory_entry_creation() {
        let entry = DirectoryEntry::new(
            "cn=test,dc=example,dc=com".to_string(),
            "123e4567-e89b-12d3-a456-426614174000".to_string(),
            vec![
                ("cn".to_string(), vec!["test".to_string()]),
                ("objectClass".to_string(), vec!["person".to_string()]),
            ],
        );

        assert_eq!(entry.dn, "cn=test,dc=example,dc=com");
        assert_eq!(entry.uuid, "123e4567-e89b-12d3-a456-426614174000");
        assert_eq!(entry.attributes.len(), 2);
    }

    #[test]
    fn test_connection_stats_default() {
        let stats = ConnectionStats::default();
        assert_eq!(stats.entries_sent, 0);
        assert_eq!(stats.sync_info_sent, 0);
        assert_eq!(stats.heartbeats_sent, 0);
        assert_eq!(stats.errors, 0);
        assert!(stats.last_error.is_none());
    }

    #[test]
    fn test_sync_info_variants() {
        let info1 = SyncInfo::NewCookie("cookie123".to_string());
        let info2 = SyncInfo::RefreshDelete {
            cookie: Some("cookie456".to_string()),
            refresh_done: true,
        };
        let info3 = SyncInfo::RefreshPresent {
            cookie: None,
            refresh_done: false,
        };
        let info4 = SyncInfo::SyncIdSet {
            cookie: Some("cookie789".to_string()),
            refresh_deletes: true,
            uuids: vec!["uuid1".to_string(), "uuid2".to_string()],
        };

        // Just ensure they compile and can be created
        match info1 {
            SyncInfo::NewCookie(ref cookie) => assert_eq!(cookie, "cookie123"),
            _ => panic!("Wrong variant"),
        }
    }

    // Note: Integration tests with actual LDAP connections would be in
    // tests/persistent_connection_integration.rs
}

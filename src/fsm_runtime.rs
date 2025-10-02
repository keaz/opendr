//! FSM Runtime Management
//!
//! This module provides the runtime infrastructure for managing FSM instances
//! in the LDAP server. It handles the lifecycle of all FSMs associated with
//! a single client connection and provides message routing to appropriate FSMs.
//!
//! ## Architecture
//!
//! Each client connection has a `ConnectionFsmSet` that contains:
//! - 1 ConnectionFsm: TCP/TLS connection management
//! - 1 BerDecoderFsm: LDAP message decoding
//! - 1 Authentication FSM: Simple or SASL authentication
//! - N Operation FSMs: One per concurrent LDAP operation (search, modify, etc.)
//! - Optional Replication FSMs: For replication sessions
//!
//! ## Message Routing
//!
//! The runtime maintains a mapping of LDAP message IDs to operation FSM instances,
//! allowing concurrent operations to be processed independently.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpStream;

use crate::backend::DirectoryBackend;
use crate::auth_fsm::AuthFsmImpl;
use crate::ber_decoder_fsm::BerDecoderFsmImpl;
use crate::connection_fsm::{ConnectionFsmImpl, TlsHandler};
use crate::sasl_fsm::SaslFsmImpl;
use crate::search_fsm::SearchFsmImpl;
use crate::write_fsm::WriteFsmImpl;
use crate::compare_fsm::CompareFsmImpl;
use crate::extended_op_fsm::ExtendedOpFsmImpl;
use crate::fsm::{StateMachine, AuthState, SaslFsm, TimeoutFsm};

/// Represents the authentication FSM, which can be either Simple or SASL
pub enum AuthenticationFsm {
    /// Simple bind authentication
    Simple(AuthFsmImpl),
    /// SASL authentication with various mechanisms
    Sasl(SaslFsmImpl),
}

impl AuthenticationFsm {
    /// Get the authenticated DN if the user is authenticated
    pub fn authenticated_dn(&self) -> Option<&str> {
        match self {
            AuthenticationFsm::Simple(auth) => {
                match auth.current_state() {
                    AuthState::SimpleBound { dn } => Some(dn.as_str()),
                    _ => None,
                }
            }
            AuthenticationFsm::Sasl(sasl) => sasl.authenticated_identity(),
        }
    }

    /// Check if the user is authenticated
    pub fn is_authenticated(&self) -> bool {
        self.authenticated_dn().is_some()
    }
}

/// Represents a single LDAP operation FSM
pub enum OperationFsm {
    /// Search operation
    Search(SearchFsmImpl),
    /// Write operation (Add, Modify, ModifyDN, Delete)
    Write(WriteFsmImpl),
    /// Compare operation
    Compare(CompareFsmImpl),
    /// Extended operation
    Extended(ExtendedOpFsmImpl),
}

impl OperationFsm {
    /// Check if this operation FSM is in a terminal state
    pub fn is_terminal(&self) -> bool {
        match self {
            OperationFsm::Search(fsm) => fsm.is_terminal(),
            OperationFsm::Write(fsm) => fsm.is_terminal(),
            OperationFsm::Compare(fsm) => fsm.is_terminal(),
            OperationFsm::Extended(fsm) => fsm.is_terminal(),
        }
    }

    /// Check if this operation supports timeouts
    pub fn has_timeout(&self) -> bool {
        matches!(self, OperationFsm::Search(_))
    }
}

/// Information about an operation tracked by the runtime
#[derive(Debug, Clone)]
pub struct OperationInfo {
    /// LDAP message ID for this operation
    pub message_id: i32,
    /// When this operation was created
    pub created_at: Instant,
    /// Type of operation
    pub operation_type: OperationType,
}

/// Types of LDAP operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationType {
    Search,
    Add,
    Modify,
    ModifyDN,
    Delete,
    Compare,
    Extended,
}

/// Complete set of FSMs for a single LDAP connection
///
/// This structure manages all FSM instances associated with one client connection.
/// It handles message routing, FSM lifecycle, and cleanup of completed operations.
pub struct ConnectionFsmSet {
    /// Connection/transport FSM
    connection: ConnectionFsmImpl,

    /// BER message decoder FSM
    decoder: BerDecoderFsmImpl,

    /// Authentication FSM (Simple or SASL)
    auth: AuthenticationFsm,

    /// Active operation FSMs, keyed by LDAP message ID
    operations: HashMap<i32, OperationFsm>,

    /// Backend for directory operations
    backend: Arc<dyn DirectoryBackend>,

    /// Metadata about operations
    operation_info: HashMap<i32, OperationInfo>,
}

impl ConnectionFsmSet {
    /// Create a new ConnectionFsmSet for an accepted connection
    ///
    /// # Arguments
    /// * `stream` - The TCP stream for this connection
    /// * `backend` - The directory backend to use for operations
    /// * `tls_handler` - Handler for TLS operations (if TLS is supported)
    ///
    /// # Returns
    /// A new ConnectionFsmSet ready to handle LDAP operations
    pub fn new(
        stream: TcpStream,
        backend: Arc<dyn DirectoryBackend>,
        tls_handler: Option<Box<dyn TlsHandler>>,
    ) -> Self {
        // Get address info before moving stream
        let remote_addr = stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        // Create connection FSM with the stream
        let connection = if let Some(tls) = tls_handler {
            ConnectionFsmImpl::new_with_stream(stream, remote_addr.clone(), Some(tls))
        } else {
            ConnectionFsmImpl::new_with_stream(stream, remote_addr, None)
        };

        // Create BER decoder FSM
        let decoder = BerDecoderFsmImpl::new();

        // Start with simple authentication (anonymous)
        let auth = AuthenticationFsm::Simple(AuthFsmImpl::new());

        Self {
            connection,
            decoder,
            auth,
            operations: HashMap::new(),
            backend,
            operation_info: HashMap::new(),
        }
    }

    /// Get a reference to the connection FSM
    pub fn connection(&self) -> &ConnectionFsmImpl {
        &self.connection
    }

    /// Get a mutable reference to the connection FSM
    pub fn connection_mut(&mut self) -> &mut ConnectionFsmImpl {
        &mut self.connection
    }

    /// Get a reference to the decoder FSM
    pub fn decoder(&self) -> &BerDecoderFsmImpl {
        &self.decoder
    }

    /// Get a mutable reference to the decoder FSM
    pub fn decoder_mut(&mut self) -> &mut BerDecoderFsmImpl {
        &mut self.decoder
    }

    /// Get a reference to the authentication FSM
    pub fn auth(&self) -> &AuthenticationFsm {
        &self.auth
    }

    /// Get a mutable reference to the authentication FSM
    pub fn auth_mut(&mut self) -> &mut AuthenticationFsm {
        &mut self.auth
    }

    /// Get the authenticated DN, if any
    pub fn authenticated_dn(&self) -> Option<&str> {
        self.auth.authenticated_dn()
    }

    /// Check if the connection is authenticated
    pub fn is_authenticated(&self) -> bool {
        self.auth.is_authenticated()
    }

    /// Create a new operation FSM for the given message ID
    ///
    /// # Arguments
    /// * `message_id` - LDAP message ID for this operation
    /// * `operation` - The operation FSM to track
    /// * `operation_type` - Type of operation being created
    ///
    /// # Returns
    /// * `Ok(())` if the operation was registered
    /// * `Err(String)` if the message ID is already in use
    pub fn add_operation(
        &mut self,
        message_id: i32,
        operation: OperationFsm,
        operation_type: OperationType,
    ) -> Result<(), String> {
        if self.operations.contains_key(&message_id) {
            return Err(format!("Message ID {} already in use", message_id));
        }

        let info = OperationInfo {
            message_id,
            created_at: Instant::now(),
            operation_type,
        };

        self.operations.insert(message_id, operation);
        self.operation_info.insert(message_id, info);
        Ok(())
    }

    /// Get a mutable reference to an operation FSM by message ID
    ///
    /// # Arguments
    /// * `message_id` - LDAP message ID to look up
    ///
    /// # Returns
    /// * `Some(&mut OperationFsm)` if found
    /// * `None` if not found
    pub fn get_operation_mut(&mut self, message_id: i32) -> Option<&mut OperationFsm> {
        self.operations.get_mut(&message_id)
    }

    /// Get a reference to an operation FSM by message ID
    pub fn get_operation(&self, message_id: i32) -> Option<&OperationFsm> {
        self.operations.get(&message_id)
    }

    /// Remove and return a completed operation FSM
    ///
    /// # Arguments
    /// * `message_id` - LDAP message ID to remove
    ///
    /// # Returns
    /// * `Some(OperationFsm)` if found and removed
    /// * `None` if not found
    pub fn remove_operation(&mut self, message_id: i32) -> Option<OperationFsm> {
        self.operation_info.remove(&message_id);
        self.operations.remove(&message_id)
    }

    /// Clean up all terminal (completed) operations
    ///
    /// This should be called periodically to free resources from completed operations.
    ///
    /// # Returns
    /// The number of operations cleaned up
    pub fn cleanup_terminal_operations(&mut self) -> usize {
        let terminal_ids: Vec<i32> = self
            .operations
            .iter()
            .filter(|(_, op)| op.is_terminal())
            .map(|(id, _)| *id)
            .collect();

        let count = terminal_ids.len();
        for id in terminal_ids {
            self.remove_operation(id);
        }
        count
    }

    /// Get the number of active operations
    pub fn active_operation_count(&self) -> usize {
        self.operations.len()
    }

    /// Get information about all active operations
    pub fn active_operations(&self) -> Vec<OperationInfo> {
        self.operation_info.values().cloned().collect()
    }

    /// Get a reference to the backend
    pub fn backend(&self) -> &Arc<dyn DirectoryBackend> {
        &self.backend
    }

    /// Check if the connection is in a terminal state
    pub fn is_terminal(&self) -> bool {
        self.connection.is_terminal()
    }

    /// Check for and clean up timed-out operations
    ///
    /// This should be called periodically to detect operations that have exceeded
    /// their timeout and remove them.
    ///
    /// # Arguments
    /// * `max_operation_age` - Maximum age for operations before they're considered stale
    ///
    /// # Returns
    /// Number of operations that were removed due to timeout
    pub fn cleanup_timed_out_operations(&mut self, max_operation_age: std::time::Duration) -> usize {
        let now = Instant::now();
        let timed_out_ids: Vec<i32> = self
            .operation_info
            .iter()
            .filter(|(_, info)| now.duration_since(info.created_at) > max_operation_age)
            .map(|(id, _)| *id)
            .collect();

        let count = timed_out_ids.len();
        for id in timed_out_ids {
            self.remove_operation(id);
        }
        count
    }

    /// Get all operations that are approaching timeout
    ///
    /// # Arguments
    /// * `warning_threshold` - Duration before timeout to start warning
    /// * `max_operation_age` - Maximum age for operations
    ///
    /// # Returns
    /// List of message IDs for operations approaching timeout
    pub fn get_operations_approaching_timeout(
        &self,
        warning_threshold: std::time::Duration,
        max_operation_age: std::time::Duration,
    ) -> Vec<i32> {
        let now = Instant::now();
        let warning_age = max_operation_age.saturating_sub(warning_threshold);

        self.operation_info
            .iter()
            .filter(|(_, info)| {
                let age = now.duration_since(info.created_at);
                age > warning_age && age < max_operation_age
            })
            .map(|(id, _)| *id)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MockBackend;

    #[test]
    fn test_authentication_fsm_anonymous() {
        let auth = AuthenticationFsm::Simple(AuthFsmImpl::new());

        assert!(!auth.is_authenticated());
        assert_eq!(auth.authenticated_dn(), None);
    }

    #[test]
    fn test_operation_info() {
        let info = OperationInfo {
            message_id: 1,
            created_at: Instant::now(),
            operation_type: OperationType::Search,
        };

        assert_eq!(info.message_id, 1);
        assert_eq!(info.operation_type, OperationType::Search);
    }

    #[tokio::test]
    async fn test_connection_fsm_set_creation() {
        use tokio::net::TcpListener;

        // Create a test server
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn a task to accept the connection
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        // Connect to the test server
        let stream = TcpStream::connect(addr).await.unwrap();
        let backend = Arc::new(MockBackend::default());

        let fsm_set = ConnectionFsmSet::new(stream, backend, None);

        // Initially no operations
        assert_eq!(fsm_set.active_operation_count(), 0);
        assert!(!fsm_set.is_authenticated());
        assert_eq!(fsm_set.authenticated_dn(), None);
    }

    #[tokio::test]
    async fn test_connection_fsm_set_backend_access() {
        use tokio::net::TcpListener;

        // Create a test server
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn a task to accept the connection
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        // Connect to the test server
        let stream = TcpStream::connect(addr).await.unwrap();
        let backend = Arc::new(MockBackend::default());

        let fsm_set = ConnectionFsmSet::new(stream, backend, None);

        // Verify backend access
        assert!(fsm_set.backend().authenticate("cn=admin,dc=example,dc=org", b"secret").await.unwrap());

        // Verify connection and decoder FSMs are accessible
        assert!(!fsm_set.connection().is_terminal());
        assert!(!fsm_set.decoder().is_terminal());
    }

    #[test]
    fn test_timeout_management() {
        use std::time::Duration;

        let mut info_map = HashMap::new();

        // Create some test operation info with different ages
        let now = Instant::now();
        let old_time = now - Duration::from_secs(120); // 2 minutes ago
        let recent_time = now - Duration::from_secs(30); // 30 seconds ago

        info_map.insert(1, OperationInfo {
            message_id: 1,
            created_at: old_time,
            operation_type: OperationType::Search,
        });

        info_map.insert(2, OperationInfo {
            message_id: 2,
            created_at: recent_time,
            operation_type: OperationType::Search,
        });

        // Test that old operations are identified for cleanup
        let max_age = Duration::from_secs(60);
        let old_ops: Vec<i32> = info_map
            .iter()
            .filter(|(_, info)| now.duration_since(info.created_at) > max_age)
            .map(|(id, _)| *id)
            .collect();

        assert_eq!(old_ops.len(), 1);
        assert_eq!(old_ops[0], 1);
    }
}

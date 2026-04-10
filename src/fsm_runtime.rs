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
//!
//! Replication provider/consumer FSMs are exposed as standalone modules and are
//! not embedded in the connection-scoped runtime. Backend transaction FSMs are
//! internal storage/runtime plumbing rather than part of `ConnectionFsmSet`.
//!
//! ## Message Routing
//!
//! The runtime maintains a mapping of LDAP message IDs to operation FSM instances,
//! allowing concurrent operations to be processed independently.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use ldap_parser::ldap::LdapMessage;
use tokio::net::TcpStream;

use crate::auth_fsm::{AuthFsmImpl, AuthUserInfo, AuthenticationBackend};
use crate::backend::{DirectoryBackend, DirectoryEntry};
use crate::ber_decoder_fsm::BerDecoderFsmImpl;
use crate::compare_fsm::CompareFsmImpl;
use crate::connection_fsm::{ConnectionFsmImpl, ConnectionTransport, TlsHandler};
use crate::extended_op_fsm::ExtendedOpFsmImpl;
use crate::fsm::{AuthState, ConnectionFsm, SaslFsm, StateMachine};
use crate::fsm_operation_registry::{FsmOperationRegistry, OperationInfo};
use crate::fsm_request::{build_request_context, FsmRequestContext, FsmRequestRejection};
use crate::sasl_fsm::SaslFsmImpl;
use crate::search_fsm::SearchFsmImpl;
use crate::write_fsm::{SchemaValidator, WriteFsmImpl};

pub use crate::fsm_operation_registry::OperationType;

struct DirectoryAuthenticationBackend {
    backend: Arc<dyn DirectoryBackend>,
}

impl DirectoryAuthenticationBackend {
    fn new(backend: Arc<dyn DirectoryBackend>) -> Self {
        Self { backend }
    }
}

fn first_attribute_value(entry: &DirectoryEntry, attribute: &str) -> Option<String> {
    entry
        .attributes
        .get(attribute)
        .and_then(|values| values.first())
        .cloned()
}

#[async_trait]
impl AuthenticationBackend for DirectoryAuthenticationBackend {
    async fn authenticate(&self, dn: &str, password: &[u8]) -> Result<bool, String> {
        self.backend
            .authenticate(dn, password)
            .await
            .map_err(|e| e.to_string())
    }

    async fn dn_exists(&self, dn: &str) -> Result<bool, String> {
        self.backend
            .get_entry(dn)
            .await
            .map(|entry| entry.is_some())
            .map_err(|e| e.to_string())
    }

    fn validate_dn(&self, dn: &str) -> Result<(), String> {
        let normalized = dn.trim();
        if normalized.is_empty() {
            return Err("DN must not be empty".to_string());
        }
        if !normalized.contains('=') {
            return Err(format!("Invalid DN format: {normalized}"));
        }
        Ok(())
    }

    async fn get_user_info(&self, dn: &str) -> Result<AuthUserInfo, String> {
        let entry = self
            .backend
            .get_entry(dn)
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("DN not found: {dn}"))?;

        Ok(AuthUserInfo {
            dn: entry.dn.clone(),
            display_name: first_attribute_value(&entry, "displayname")
                .or_else(|| first_attribute_value(&entry, "cn")),
            email: first_attribute_value(&entry, "mail"),
            groups: entry
                .attributes
                .get("memberof")
                .cloned()
                .unwrap_or_default(),
            last_login: Some(Instant::now()),
        })
    }
}

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
            AuthenticationFsm::Simple(auth) => match auth.current_state() {
                AuthState::SimpleBound { dn } => Some(dn.as_str()),
                _ => None,
            },
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

/// Complete set of FSMs for a single LDAP connection
///
/// This structure manages all FSM instances associated with one client connection.
/// It handles message routing, FSM lifecycle, and cleanup of completed operations.
/// The runtime surface is intentionally limited to transport, decoding,
/// authentication, and request/response LDAP operations for one connection.
pub struct ConnectionFsmSet {
    /// Connection/transport FSM
    connection: ConnectionFsmImpl,

    /// BER message decoder FSM
    decoder: BerDecoderFsmImpl,

    /// Authentication FSM (Simple or SASL)
    auth: AuthenticationFsm,

    /// Active operation FSMs and metadata, keyed by LDAP message ID.
    operations: FsmOperationRegistry<OperationFsm>,

    /// Backend for directory operations
    backend: Arc<dyn DirectoryBackend>,

    /// Schema validator for write operations
    schema_validator: Arc<dyn SchemaValidator>,
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
        Self::new_with_schema_validator(stream, backend, tls_handler, None)
    }

    /// Create a new ConnectionFsmSet with a custom schema validator
    ///
    /// # Arguments
    /// * `stream` - The TCP stream for this connection
    /// * `backend` - The directory backend to use for operations
    /// * `tls_handler` - Handler for TLS operations (if TLS is supported)
    /// * `schema_validator` - Custom schema validator (uses default if None)
    ///
    /// # Returns
    /// A new ConnectionFsmSet ready to handle LDAP operations
    pub fn new_with_schema_validator(
        stream: TcpStream,
        backend: Arc<dyn DirectoryBackend>,
        tls_handler: Option<Box<dyn TlsHandler>>,
        schema_validator: Option<Arc<dyn SchemaValidator>>,
    ) -> Self {
        Self::new_with_transport_and_schema_validator(
            ConnectionTransport::plain(stream),
            backend,
            tls_handler,
            schema_validator,
        )
    }

    /// Create a new ConnectionFsmSet with an already established transport.
    pub fn new_with_transport(
        transport: ConnectionTransport,
        backend: Arc<dyn DirectoryBackend>,
        tls_handler: Option<Box<dyn TlsHandler>>,
    ) -> Self {
        Self::new_with_transport_and_schema_validator(transport, backend, tls_handler, None)
    }

    /// Create a new ConnectionFsmSet with an already established transport and schema validator.
    pub fn new_with_transport_and_schema_validator(
        transport: ConnectionTransport,
        backend: Arc<dyn DirectoryBackend>,
        tls_handler: Option<Box<dyn TlsHandler>>,
        schema_validator: Option<Arc<dyn SchemaValidator>>,
    ) -> Self {
        // Get address info before moving stream
        let remote_addr = transport
            .tcp_ref()
            .and_then(|stream| stream.peer_addr().ok())
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let connection = ConnectionFsmImpl::new_with_transport(transport, remote_addr, tls_handler);

        // Create BER decoder FSM
        let decoder = BerDecoderFsmImpl::new();

        // Start with simple authentication (anonymous)
        let auth = AuthenticationFsm::Simple(AuthFsmImpl::new().with_backend(Box::new(
            DirectoryAuthenticationBackend::new(backend.clone()),
        )));

        // Use provided schema validator or create default one
        let schema_validator = schema_validator.unwrap_or_else(|| {
            use crate::schema_adapter::LdapSchemaValidator;
            Arc::new(LdapSchemaValidator::new())
        });

        Self {
            connection,
            decoder,
            auth,
            operations: FsmOperationRegistry::default(),
            backend,
            schema_validator,
        }
    }

    /// Get a reference to the schema validator
    pub fn schema_validator(&self) -> &Arc<dyn SchemaValidator> {
        &self.schema_validator
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

    /// Build the shared request context used by the FSM dispatcher.
    pub fn build_request_context(
        &self,
        connection_id: u64,
        client_ip: Option<IpAddr>,
        message: &LdapMessage<'_>,
    ) -> Result<FsmRequestContext, FsmRequestRejection> {
        build_request_context(
            message,
            connection_id,
            client_ip,
            self.authenticated_dn(),
            self.connection.is_secure(),
        )
    }

    /// Get a reference to the operation registry.
    pub fn operation_registry(&self) -> &FsmOperationRegistry<OperationFsm> {
        &self.operations
    }

    /// Get a mutable reference to the operation registry.
    pub fn operation_registry_mut(&mut self) -> &mut FsmOperationRegistry<OperationFsm> {
        &mut self.operations
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
        self.operations
            .add_operation(message_id, operation, operation_type)
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
        self.operations.get_mut(message_id)
    }

    /// Get a reference to an operation FSM by message ID
    pub fn get_operation(&self, message_id: i32) -> Option<&OperationFsm> {
        self.operations.get(message_id)
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
        self.operations.remove(message_id)
    }

    /// Clean up all terminal (completed) operations
    ///
    /// This should be called periodically to free resources from completed operations.
    ///
    /// # Returns
    /// The number of operations cleaned up
    pub fn cleanup_terminal_operations(&mut self) -> usize {
        self.operations.cleanup_where(OperationFsm::is_terminal)
    }

    /// Get the number of active operations
    pub fn active_operation_count(&self) -> usize {
        self.operations.len()
    }

    /// Get information about all active operations
    pub fn active_operations(&self) -> Vec<OperationInfo> {
        self.operations.active_operations()
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
    pub fn cleanup_timed_out_operations(
        &mut self,
        max_operation_age: std::time::Duration,
    ) -> usize {
        self.operations
            .cleanup_timed_out_operations(max_operation_age)
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
        self.operations
            .get_operations_approaching_timeout(warning_threshold, max_operation_age)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MockBackend;
    use crate::fsm::AuthEvent;
    use crate::fsm::StateMachine;
    use std::collections::HashMap;

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
        assert!(fsm_set
            .backend()
            .authenticate("cn=admin,dc=example,dc=org", b"secret")
            .await
            .unwrap());

        // Verify connection and decoder FSMs are accessible
        assert!(!fsm_set.connection().is_terminal());
        assert!(!fsm_set.decoder().is_terminal());
    }

    #[tokio::test]
    async fn test_connection_fsm_set_simple_bind_uses_directory_backend() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let backend = Arc::new(MockBackend::default());
        let mut fsm_set = ConnectionFsmSet::new(stream, backend, None);

        match fsm_set.auth_mut() {
            AuthenticationFsm::Simple(auth) => {
                let result = auth
                    .handle_event(AuthEvent::BindRequest {
                        dn: "cn=admin,dc=example,dc=org".to_string(),
                        password: b"secret".to_vec(),
                    })
                    .await
                    .unwrap();

                assert!(result.is_some());
            }
            AuthenticationFsm::Sasl(_) => panic!("expected simple auth FSM"),
        }

        assert!(fsm_set.is_authenticated());
        assert_eq!(
            fsm_set.authenticated_dn(),
            Some("cn=admin,dc=example,dc=org")
        );
    }

    #[test]
    fn test_timeout_management() {
        use std::time::Duration;

        let mut info_map = HashMap::new();

        // Create some test operation info with different ages
        let now = Instant::now();
        let old_time = now - Duration::from_secs(120); // 2 minutes ago
        let recent_time = now - Duration::from_secs(30); // 30 seconds ago

        info_map.insert(
            1,
            OperationInfo {
                message_id: 1,
                created_at: old_time,
                operation_type: OperationType::Search,
            },
        );

        info_map.insert(
            2,
            OperationInfo {
                message_id: 2,
                created_at: recent_time,
                operation_type: OperationType::Search,
            },
        );

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

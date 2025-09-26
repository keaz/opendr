//! FSM implementation modules
//!
//! This module contains concrete implementations of all the FSM traits
//! defined in the core FSM module.

use std::sync::Arc;
use std::time::{Duration, Instant};
use log::{debug, error, info, warn};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use crate::auth_fsm::{AuthFsmImpl, AuthenticationBackend, AuthUserInfo};
use crate::backend::DirectoryBackend;
use crate::fsm::{AuthFsm, AuthLevel, BerDecoderEvent, BerDecoderFsm, ConnectionEvent, SaslFsm, StateMachine};
use crate::sasl_fsm::SaslFsmImpl;
use crate::server::{process_message, send_bind_response};
use std::collections::HashMap;

pub mod ber_decoder;
pub mod connection;
pub mod operation_fsms;
pub mod fsm_handlers;

// Re-export key types for convenience
pub use ber_decoder::{BerDecoderFsmImpl, BerDecoderError};
pub use connection::{ConnectionFsmImpl, ConnectionFsmError};
pub use operation_fsms::{
    FsmFactory, FsmRoutingConfig, OperationFsmConfig, OperationFsmInstance,
    SearchBackendAdapter, WriteBackendAdapter, CompareBackendAdapter, ExtendedOpBackendAdapter,
};
pub use fsm_handlers::{
    FsmOperationHandler, FsmHandlerFactory, FsmHandlerResult,
    SearchFsmHandler, WriteFsmHandler, CompareFsmHandler, ExtendedOpFsmHandler,
};

/// Represents the FSMs managing a single LDAP connection
pub struct ConnectionFsmSet {
    connection: ConnectionFsmImpl,
    decoder: BerDecoderFsmImpl,
    auth: AuthFsmImpl,
    sasl: Option<SaslFsmImpl>,
    // Session timeout tracking
    last_activity: Instant,
    session_timeout: Duration,
    // Operation FSM management
    operation_fsms: HashMap<u32, OperationFsmInstance>, // Message ID -> FSM
    fsm_factory: Option<FsmFactory>,
    routing_config: FsmRoutingConfig,
    fsm_config: OperationFsmConfig,
    // Track FSM start times for timeout management
    fsm_start_times: HashMap<u32, Instant>,
}

impl ConnectionFsmSet {
    pub fn new(stream: TcpStream) -> std::io::Result<Self> {
        let remote_addr = stream.peer_addr()?;
        let local_addr = stream.local_addr()?;
        
        Ok(Self {
            connection: ConnectionFsmImpl::new(stream, remote_addr, local_addr),
            decoder: BerDecoderFsmImpl::new(),
            auth: AuthFsmImpl::new(),
            sasl: None, // Created on-demand for SASL binds
            last_activity: Instant::now(),
            session_timeout: Duration::from_secs(3600), // Default 1 hour timeout
            operation_fsms: HashMap::new(),
            fsm_factory: None, // Set later when backend is configured
            routing_config: FsmRoutingConfig::default(),
            fsm_config: OperationFsmConfig::default(),
            fsm_start_times: HashMap::new(),
        })
    }
    
    /// Create a new ConnectionFsmSet with custom timeout
    pub fn new_with_timeout(stream: TcpStream, timeout: Duration) -> std::io::Result<Self> {
        let mut fsm_set = Self::new(stream)?;
        fsm_set.session_timeout = timeout;
        Ok(fsm_set)
    }
    
    /// Create a new ConnectionFsmSet with FSM routing enabled
    pub fn new_with_fsm_routing(
        stream: TcpStream, 
        backend: Arc<dyn DirectoryBackend>,
        routing_config: FsmRoutingConfig,
        fsm_config: OperationFsmConfig
    ) -> std::io::Result<Self> {
        let mut fsm_set = Self::new(stream)?;
        fsm_set.configure_operation_fsms(backend, routing_config, fsm_config);
        Ok(fsm_set)
    }
    
    /// Get mutable reference to auth FSM
    pub fn auth_fsm_mut(&mut self) -> &mut AuthFsmImpl {
        &mut self.auth
    }
    
    /// Get reference to auth FSM
    pub fn auth_fsm(&self) -> &AuthFsmImpl {
        &self.auth
    }
    
    /// Get or create SASL FSM
    pub fn sasl_fsm_mut(&mut self) -> &mut SaslFsmImpl {
        if self.sasl.is_none() {
            // For now, create a basic SASL FSM without handlers
            // In a real implementation, you'd inject the mechanism handlers
            self.sasl = Some(SaslFsmImpl::new(
                Box::new(MockSaslMechanismHandler::new()),
                Box::new(MockCredentialVerifier::new()),
            ));
        }
        self.sasl.as_mut().unwrap()
    }
    
    /// Get reference to SASL FSM if it exists
    pub fn sasl_fsm(&self) -> Option<&SaslFsmImpl> {
        self.sasl.as_ref()
    }
    
    /// Get authenticated DN from current authentication state
    pub fn authenticated_dn(&self) -> Option<&str> {
        self.auth.authenticated_dn()
    }
    
    /// Check if connection is authenticated
    pub fn is_authenticated(&self) -> bool {
        self.auth.is_authenticated() || 
        self.sasl.as_ref().map(|s| s.authenticated_identity().is_some()).unwrap_or(false)
    }
    
    /// Get current authentication level
    pub fn auth_level(&self) -> AuthLevel {
        if let Some(sasl) = &self.sasl {
            if let Some(mechanism) = sasl.mechanism() {
                return AuthLevel::Sasl(mechanism.to_string());
            }
        }
        self.auth.auth_level()
    }
    
    /// Configure authentication backend for this connection
    pub fn configure_auth_backend(&mut self, backend: Arc<dyn DirectoryBackend>) {
        let auth_backend = DirectoryAuthBackend::new(backend);
        self.auth = AuthFsmImpl::new().with_backend(Box::new(auth_backend));
    }
    
    /// Update last activity timestamp
    pub fn update_activity(&mut self) {
        self.last_activity = Instant::now();
    }
    
    /// Check if the session has timed out
    pub fn is_session_timed_out(&self) -> bool {
        // Only enforce timeout if authenticated
        if self.is_authenticated() {
            self.last_activity.elapsed() > self.session_timeout
        } else {
            false
        }
    }
    
    /// Get time remaining until session timeout
    pub fn time_until_timeout(&self) -> Option<Duration> {
        if self.is_authenticated() {
            let elapsed = self.last_activity.elapsed();
            if elapsed < self.session_timeout {
                Some(self.session_timeout - elapsed)
            } else {
                Some(Duration::ZERO)
            }
        } else {
            None
        }
    }
    
    /// Set session timeout duration
    pub fn set_session_timeout(&mut self, timeout: Duration) {
        self.session_timeout = timeout;
    }
    
    /// Get current session timeout duration
    pub fn session_timeout(&self) -> Duration {
        self.session_timeout
    }
    
    /// Reset session timeout (extends the session)
    pub fn reset_session_timeout(&mut self) {
        self.update_activity();
    }
    
    //=== Operation FSM Management ===
    
    /// Configure operation FSMs with backend and configurations
    pub fn configure_operation_fsms(
        &mut self, 
        backend: Arc<dyn DirectoryBackend>,
        routing_config: FsmRoutingConfig,
        fsm_config: OperationFsmConfig
    ) {
        self.fsm_factory = Some(operation_fsms::FsmFactory::with_config(backend.clone(), fsm_config.clone()));
        self.routing_config = routing_config;
        self.fsm_config = fsm_config;
        
        // Also configure auth backend for consistency
        self.configure_auth_backend(backend);
    }
    
    /// Check if operation FSMs are enabled for a specific operation type
    pub fn is_fsm_enabled(&self, operation: &str) -> bool {
        match operation {
            "search" => self.routing_config.enable_search_fsm,
            "add" | "modify" | "modifyDn" | "delete" => self.routing_config.enable_write_fsm,
            "compare" => self.routing_config.enable_compare_fsm,
            "extended" => self.routing_config.enable_extended_op_fsm,
            _ => false,
        }
    }
    
    /// Create and store a search FSM instance for the given message ID
    pub fn create_search_fsm(&mut self, message_id: u32) -> Result<(), String> {
        if let Some(factory) = &self.fsm_factory {
            if self.operation_fsms.len() >= self.fsm_config.max_concurrent_operations {
                return Err("Maximum concurrent operations exceeded".to_string());
            }
            
            let fsm = factory.create_search_fsm();
            self.operation_fsms.insert(message_id, OperationFsmInstance::Search(fsm));
            self.fsm_start_times.insert(message_id, Instant::now());
            Ok(())
        } else {
            Err("FSM factory not configured".to_string())
        }
    }
    
    /// Create and store a write FSM instance for the given message ID
    pub fn create_write_fsm(&mut self, message_id: u32) -> Result<(), String> {
        if let Some(factory) = &self.fsm_factory {
            if self.operation_fsms.len() >= self.fsm_config.max_concurrent_operations {
                return Err("Maximum concurrent operations exceeded".to_string());
            }
            
            let fsm = factory.create_write_fsm();
            self.operation_fsms.insert(message_id, OperationFsmInstance::Write(fsm));
            self.fsm_start_times.insert(message_id, Instant::now());
            Ok(())
        } else {
            Err("FSM factory not configured".to_string())
        }
    }
    
    /// Create and store a compare FSM instance for the given message ID
    pub fn create_compare_fsm(&mut self, message_id: u32) -> Result<(), String> {
        if let Some(factory) = &self.fsm_factory {
            if self.operation_fsms.len() >= self.fsm_config.max_concurrent_operations {
                return Err("Maximum concurrent operations exceeded".to_string());
            }
            
            let fsm = factory.create_compare_fsm();
            self.operation_fsms.insert(message_id, OperationFsmInstance::Compare(fsm));
            self.fsm_start_times.insert(message_id, Instant::now());
            Ok(())
        } else {
            Err("FSM factory not configured".to_string())
        }
    }
    
    /// Create and store an extended operation FSM instance for the given message ID
    pub fn create_extended_op_fsm(&mut self, message_id: u32) -> Result<(), String> {
        if let Some(factory) = &self.fsm_factory {
            if self.operation_fsms.len() >= self.fsm_config.max_concurrent_operations {
                return Err("Maximum concurrent operations exceeded".to_string());
            }
            
            let fsm = factory.create_extended_op_fsm();
            self.operation_fsms.insert(message_id, OperationFsmInstance::ExtendedOp(fsm));
            self.fsm_start_times.insert(message_id, Instant::now());
            Ok(())
        } else {
            Err("FSM factory not configured".to_string())
        }
    }
    
    /// Get a reference to an operation FSM by message ID
    pub fn get_operation_fsm(&self, message_id: u32) -> Option<&OperationFsmInstance> {
        self.operation_fsms.get(&message_id)
    }
    
    /// Get a mutable reference to an operation FSM by message ID
    pub fn get_operation_fsm_mut(&mut self, message_id: u32) -> Option<&mut OperationFsmInstance> {
        self.operation_fsms.get_mut(&message_id)
    }
    
    /// Remove and return an operation FSM by message ID
    pub fn remove_operation_fsm(&mut self, message_id: u32) -> Option<OperationFsmInstance> {
        self.fsm_start_times.remove(&message_id);
        self.operation_fsms.remove(&message_id)
    }
    
    /// Clean up timed-out operation FSMs
    pub fn cleanup_timed_out_fsms(&mut self) -> Vec<u32> {
        let now = Instant::now();
        let timeout = self.fsm_config.operation_timeout;
        let mut timed_out = Vec::new();
        
        // Find timed-out FSMs
        let message_ids: Vec<u32> = self.fsm_start_times.iter()
            .filter_map(|(msg_id, start_time)| {
                if now.duration_since(*start_time) > timeout {
                    Some(*msg_id)
                } else {
                    None
                }
            })
            .collect();
            
        // Remove them
        for message_id in message_ids {
            self.remove_operation_fsm(message_id);
            timed_out.push(message_id);
        }
        
        timed_out
    }
    
    /// Get count of active operation FSMs
    pub fn active_operation_count(&self) -> usize {
        self.operation_fsms.len()
    }
    
    /// Check if fallback to direct handlers is enabled
    pub fn should_fallback_to_direct(&self) -> bool {
        self.routing_config.fallback_to_direct
    }
    
    /// Get the FSM routing configuration
    pub fn routing_config(&self) -> &FsmRoutingConfig {
        &self.routing_config
    }
    
    /// Update FSM routing configuration
    pub fn update_routing_config(&mut self, config: FsmRoutingConfig) {
        self.routing_config = config;
    }
    
    /// Get the operation FSM configuration
    pub fn operation_fsm_config(&self) -> &OperationFsmConfig {
        &self.fsm_config
    }
    
    /// Update operation FSM configuration
    pub fn update_operation_fsm_config(&mut self, config: OperationFsmConfig) {
        self.fsm_config = config;
        // For now, we'll just update the config and let new FSMs use it
        // A more sophisticated approach would recreate the factory and update existing FSMs
        // TODO: Consider recreating the factory with the new config
    }
}

/// Handle bind request through authentication FSMs
pub async fn handle_bind_request_fsm(
    fsm_set: &mut ConnectionFsmSet,
    socket: &mut TcpStream,
    message_id: u32,
    request: ldap_parser::ldap::BindRequest<'_>,
) -> Result<(), crate::server::ServerError> {
    use crate::fsm::{AuthEvent, SaslEvent, StateMachine};
    use ldap_parser::ldap::AuthenticationChoice;
    use crate::server::send_bind_response;
    use rasn_ldap::ResultCode;
    
    if request.version != 3 {
        send_bind_response(
            socket,
            message_id,
            ResultCode::ProtocolError,
            "unsupported LDAP version",
        )
        .await?;
        return Ok(());
    }

    match request.authentication {
        AuthenticationChoice::Simple(password) => {
            let dn = request.name.0.as_ref().trim().to_owned();
            
            // Route through AuthFsm
            let auth_event = AuthEvent::BindRequest {
                dn: dn.clone(),
                password: password.as_ref().to_vec(),
            };
            
            match fsm_set.auth_fsm_mut().handle_event(auth_event).await {
                Ok(_) => {
                    // Check if we need to trigger actual authentication
                    if let crate::fsm::AuthState::Authenticating { dn: _auth_dn } = fsm_set.auth_fsm().current_state() {
                        // Perform actual authentication (this would normally be done by the FSM with a backend)
                        // For now, we'll simulate success
                        if let Err(e) = fsm_set.auth_fsm_mut().handle_event(AuthEvent::AuthenticationSuccess).await {
                            error!("Authentication success event failed: {:?}", e);
                            send_bind_response(
                                socket,
                                message_id,
                                ResultCode::Unavailable,
                                "internal error",
                            ).await?;
                            return Ok(());
                        }
                    }
                    
                    // Send success response
                    send_bind_response(socket, message_id, ResultCode::Success, "").await?
                }
                Err(e) => {
                    error!("Auth FSM error for {}: {:?}", dn, e);
                    let result_code = match e {
                        crate::auth_fsm::AuthError::InvalidCredentials => ResultCode::InvalidCredentials,
                        crate::auth_fsm::AuthError::AuthenticationFailed { .. } => ResultCode::InvalidCredentials,
                        _ => ResultCode::Unavailable,
                    };
                    
                    let message = match &e {
                        crate::auth_fsm::AuthError::InvalidCredentials => "invalid credentials",
                        crate::auth_fsm::AuthError::AuthenticationFailed { reason } => reason.as_str(),
                        _ => "authentication failed",
                    };
                    
                    send_bind_response(socket, message_id, result_code, message).await?
                }
            }
        }
        AuthenticationChoice::Sasl(sasl_creds) => {
            let mechanism = sasl_creds.mechanism.0.as_ref().to_owned();
            let initial_data = sasl_creds.credentials.map(|c| c.as_ref().to_vec());
            
            // Route through SaslFsm
            let sasl_event = SaslEvent::InitiateBind {
                mechanism: mechanism.clone(),
                initial_data,
            };
            
            match fsm_set.sasl_fsm_mut().handle_event(sasl_event).await {
                Ok(_) => {
                    // For now, simulate that SASL is not fully implemented
                    send_bind_response(
                        socket,
                        message_id,
                        ResultCode::AuthMethodNotSupported,
                        "SASL authentication not fully implemented",
                    ).await?
                }
                Err(e) => {
                    error!("SASL FSM error for mechanism {}: {:?}", mechanism, e);
                    send_bind_response(
                        socket,
                        message_id,
                        ResultCode::AuthMethodNotSupported,
                        "SASL authentication failed",
                    ).await?
                }
            }
        }
    }

    Ok(())
}

/// FSM-based client handler - simplified version for testing
/// This demonstrates FSM integration without complex borrowing issues
pub async fn handle_client_fsm_simple(mut socket: TcpStream, backend: Arc<dyn DirectoryBackend>) {
    // For now, create FSM for tracking state, but don't store the socket in it
    let remote_addr = socket.peer_addr().unwrap();
    let local_addr = socket.local_addr().unwrap();
    let mut connection_fsm = ConnectionFsmImpl::new_outbound();
    // Manually set addresses for info
    let connection_info = crate::fsm::ConnectionInfo {
        remote_addr: remote_addr.to_string(),
        local_addr: local_addr.to_string(),
        is_secure: false,
        protocol_version: "3".to_string(),
    };
    
    let mut decoder_fsm = BerDecoderFsmImpl::new();
    let mut buffer = vec![0; 4096];
    
    info!("FSM-based connection established: {:?}", connection_info);
    
    // Simulate the FSM integration without borrowing conflicts
    loop {
        match socket.read(&mut buffer).await {
            Ok(0) => {
                debug!("Connection closed by client");
                if let Err(e) = connection_fsm.handle_event(ConnectionEvent::Close).await {
                    warn!("Failed to handle connection close: {:?}", e);
                }
                break;
            }
            Ok(n) => {
                let chunk = buffer[..n].to_vec();
                debug!("Read {} bytes from connection", n);
                
                // Process chunk through BER decoder FSM
                if let Err(e) = decoder_fsm
                    .handle_event(BerDecoderEvent::DataReceived(chunk))
                    .await 
                {
                    error!("BER decoder FSM error: {:?}", e);
                    break;
                }
                
                // Extract complete message if available
                if let Some(message_data) = decoder_fsm.extract_message() {
                    debug!("Extracted {} byte message from decoder", message_data.len());
                    
                    // Parse and process LDAP messages (reusing existing logic)
                    match ldap_parser::parse_ldap_messages(&message_data) {
                        Ok((_, messages)) => {
                            for message in messages {
                                if let Err(err) = process_message(
                                    &mut socket, 
                                    backend.as_ref(), 
                                    message
                                ).await {
                                    error!("Failed to process message: {}", err);
                                    if let Err(conn_err) = connection_fsm
                                        .handle_event(ConnectionEvent::Error(err.to_string()))
                                        .await 
                                    {
                                        error!("Failed to handle connection error: {:?}", conn_err);
                                    }
                                    return;
                                }
                            }
                        }
                        Err(err) => {
                            error!("Failed to parse LDAP message: {:?}", err);
                            if let Err(conn_err) = connection_fsm
                                .handle_event(ConnectionEvent::Error("parse error".to_string()))
                                .await 
                            {
                                error!("Failed to handle connection error: {:?}", conn_err);
                            }
                            // Send protocol error response
                            if let Err(write_err) = send_bind_response(
                                &mut socket,
                                0,
                                rasn_ldap::ResultCode::ProtocolError,
                                "invalid message",
                            ).await {
                                error!("Failed to write error response: {}", write_err);
                            }
                            return;
                        }
                    }
                }
            }
            Err(err) => {
                error!("Failed to read from socket: {}", err);
                if let Err(conn_err) = connection_fsm
                    .handle_event(ConnectionEvent::ConnectionLost)
                    .await 
                {
                    error!("Failed to handle connection lost: {:?}", conn_err);
                }
                break;
            }
        }
    }
    
    debug!("Connection FSM final state: {:?}", connection_fsm.current_state());
}

// Mock implementations for testing - in production these would be injected
use crate::sasl_fsm::{SaslMechanismHandler, SaslChallengeResult, CredentialVerifier};
use async_trait::async_trait;

/// Mock SASL mechanism handler for testing
struct MockSaslMechanismHandler;

impl MockSaslMechanismHandler {
    fn new() -> Self {
        Self
    }
}

#[async_trait]
impl SaslMechanismHandler for MockSaslMechanismHandler {
    async fn supports_mechanism(&self, mechanism: &str) -> bool {
        matches!(mechanism, "PLAIN" | "DIGEST-MD5")
    }
    
    async fn start_authentication(
        &self, 
        mechanism: &str, 
        initial_data: Option<&[u8]>
    ) -> Result<SaslChallengeResult, String> {
        match mechanism {
            "PLAIN" => {
                if let Some(data) = initial_data {
                    // Parse PLAIN mechanism: \0username\0password
                    let parts: Vec<&[u8]> = data.split(|&b| b == 0).collect();
                    if parts.len() >= 3 {
                        let username = String::from_utf8_lossy(parts[1]);
                        // Simulate successful authentication
                        return Ok(SaslChallengeResult::Success { 
                            dn: format!("cn={},dc=example,dc=org", username) 
                        });
                    }
                }
                Ok(SaslChallengeResult::Failure("Invalid PLAIN data".to_string()))
            }
            _ => Ok(SaslChallengeResult::Failure("Mechanism not implemented".to_string()))
        }
    }
    
    async fn process_response(
        &self, 
        _mechanism: &str, 
        _step: u32, 
        _response: &[u8]
    ) -> Result<SaslChallengeResult, String> {
        Ok(SaslChallengeResult::Failure("Not implemented".to_string()))
    }
}

/// Mock credential verifier for testing
struct MockCredentialVerifier;

impl MockCredentialVerifier {
    fn new() -> Self {
        Self
    }
}

#[async_trait]
impl CredentialVerifier for MockCredentialVerifier {
    async fn verify_credentials(&self, _mechanism: &str, _identity: &str) -> Result<bool, String> {
        Ok(true) // Always succeed for testing
    }
    
    async fn get_user_dn(&self, identity: &str) -> Result<Option<String>, String> {
        Ok(Some(format!("cn={},dc=example,dc=org", identity)))
    }
}

/// Mock authentication backend adapter
struct DirectoryAuthBackend {
    backend: Arc<dyn DirectoryBackend>,
}

impl DirectoryAuthBackend {
    pub fn new(backend: Arc<dyn DirectoryBackend>) -> Self {
        Self { backend }
    }
}

#[async_trait]
impl AuthenticationBackend for DirectoryAuthBackend {
    async fn authenticate(&self, dn: &str, password: &[u8]) -> Result<bool, String> {
        self.backend.authenticate(dn, password).await
            .map_err(|e| e.to_string())
    }
    
    async fn dn_exists(&self, dn: &str) -> Result<bool, String> {
        // Simple implementation - check if we can get the entry
        match self.backend.get_entry(dn).await {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(e) => Err(e.to_string()),
        }
    }
    
    fn validate_dn(&self, dn: &str) -> Result<(), String> {
        if dn.is_empty() {
            return Ok(()); // Anonymous bind
        }
        // Basic DN validation - check for basic structure
        if !dn.contains('=') {
            return Err("Invalid DN format".to_string());
        }
        Ok(())
    }
    
    async fn get_user_info(&self, dn: &str) -> Result<AuthUserInfo, String> {
        Ok(AuthUserInfo {
            dn: dn.to_string(),
            display_name: None,
            email: None,
            groups: Vec::new(),
            last_login: Some(std::time::Instant::now()),
        })
    }
}

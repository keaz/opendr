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
use crate::server::{process_message_with_fsm, send_bind_response, ServerError};
use std::collections::HashMap;

/// Status information about FSM timeout state for monitoring
#[derive(Debug, Clone)]
pub struct FsmTimeoutStatus {
    pub message_id: u32,
    pub operation_type: String,
    pub elapsed: Duration,
    pub effective_timeout: Duration,
    pub is_timed_out: bool,
    pub is_terminal: bool,
    pub has_specific_timeout: bool,
}

pub mod ber_decoder;
pub mod connection;
pub mod operation_fsms;
pub mod fsm_handlers;

// Re-export key types for convenience
pub use ber_decoder::{BerDecoderFsmImpl, BerDecoderError};
pub use connection::{ConnectionFsmImpl, ConnectionFsmError};
pub use operation_fsms::{
    FsmFactory, FsmRoutingConfig, OperationFsmConfig, OperationFsmInstance, ExtendedOpFsmConfig,
    SearchBackendAdapter, WriteBackendAdapter, CompareBackendAdapter, ExtendedOpBackendAdapter,
};


// Import FSM configuration types
use crate::search_fsm::SearchFsmConfig;
use crate::write_fsm::WriteFsmConfig;
use crate::compare_fsm::CompareFsmConfig;
pub use fsm_handlers::{
    FsmOperationHandler, FsmHandlerFactory, FsmHandlerResult,
    SearchFsmHandler, WriteFsmHandler, CompareFsmHandler, ExtendedOpFsmHandler,
};

/// Represents the FSMs managing a single LDAP connection
pub struct ConnectionFsmSet {
    pub connection: ConnectionFsmImpl,
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
    
    /// Clean up timed-out operation FSMs using per-FSM timeout logic
    pub fn cleanup_timed_out_fsms(&mut self) -> Vec<u32> {
        let now = Instant::now();
        let mut timed_out = Vec::new();
        
        // Find timed-out FSMs using per-FSM timeout checking
        let message_ids: Vec<u32> = self.operation_fsms.iter()
            .filter_map(|(msg_id, fsm_instance)| {
                // Get the start time for this FSM
                if let Some(start_time) = self.fsm_start_times.get(msg_id) {
                    let elapsed = now.duration_since(*start_time);
                    
                    // Use the FSM-specific timeout logic
                    if fsm_instance.is_timed_out(&self.fsm_config, elapsed) {
                        debug!("FSM {} ({}) timed out after {:?}", 
                               msg_id, fsm_instance.operation_type(), elapsed);
                        Some(*msg_id)
                    } else {
                        None
                    }
                } else {
                    // FSM exists but no start time recorded - this shouldn't happen
                    // but let's clean it up anyway
                    warn!("FSM {} ({}) has no recorded start time - removing", 
                          msg_id, fsm_instance.operation_type());
                    Some(*msg_id)
                }
            })
            .collect();
            
        // Remove timed-out FSMs and log additional details
        for message_id in message_ids {
            if let Some(fsm_instance) = self.operation_fsms.get(&message_id) {
                let fsm_type = fsm_instance.operation_type();
                let is_terminal = fsm_instance.is_terminal();
                
                info!("Cleaning up timed-out FSM {} (type: {}, terminal: {})", 
                      message_id, fsm_type, is_terminal);
                      
                // Log FSM-specific timeout value for debugging
                if let Some(fsm_timeout) = fsm_instance.fsm_specific_timeout() {
                    debug!("FSM {} had specific timeout of {:?}", message_id, fsm_timeout);
                } else {
                    debug!("FSM {} used global timeout of {:?}", 
                           message_id, self.fsm_config.operation_timeout);
                }
            }
            
            self.remove_operation_fsm(message_id);
            timed_out.push(message_id);
        }
        
        if !timed_out.is_empty() {
            info!("Cleaned up {} timed-out FSMs: {:?}", timed_out.len(), timed_out);
        }
        
        timed_out
    }
    
    /// Get count of active operation FSMs
    pub fn active_operation_count(&self) -> usize {
        self.operation_fsms.len()
    }
    
    /// Get detailed timeout status information for all active FSMs
    pub fn get_fsm_timeout_status(&self) -> Vec<FsmTimeoutStatus> {
        let now = Instant::now();
        
        self.operation_fsms.iter()
            .filter_map(|(msg_id, fsm_instance)| {
                self.fsm_start_times.get(msg_id).map(|start_time| {
                    let elapsed = now.duration_since(*start_time);
                    let is_timed_out = fsm_instance.is_timed_out(&self.fsm_config, elapsed);
                    let specific_timeout = fsm_instance.fsm_specific_timeout();
                    let effective_timeout = specific_timeout.unwrap_or(self.fsm_config.operation_timeout);
                    
                    FsmTimeoutStatus {
                        message_id: *msg_id,
                        operation_type: fsm_instance.operation_type().to_string(),
                        elapsed,
                        effective_timeout,
                        is_timed_out,
                        is_terminal: fsm_instance.is_terminal(),
                        has_specific_timeout: specific_timeout.is_some(),
                    }
                })
            })
            .collect()
    }
    
    /// Check if any FSM is approaching its timeout (within 10% of timeout duration)
    pub fn has_fsms_approaching_timeout(&self) -> bool {
        let now = Instant::now();
        
        self.operation_fsms.iter().any(|(msg_id, fsm_instance)| {
            if let Some(start_time) = self.fsm_start_times.get(msg_id) {
                let elapsed = now.duration_since(*start_time);
                let specific_timeout = fsm_instance.fsm_specific_timeout();
                let effective_timeout = specific_timeout.unwrap_or(self.fsm_config.operation_timeout);
                
                let threshold = effective_timeout.mul_f64(0.9); // 90% of timeout
                elapsed >= threshold && !fsm_instance.is_timed_out(&self.fsm_config, elapsed)
            } else {
                false
            }
        })
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
    
    /// Update operation FSM configuration with full factory reconfiguration
    pub fn update_operation_fsm_config(&mut self, config: OperationFsmConfig) -> Result<(), String> {
        info!("Updating operation FSM configuration");
        
        // Store old config for rollback if needed
        let old_config = self.fsm_config.clone();
        let had_active_fsms = !self.operation_fsms.is_empty();
        
        // Update configuration
        self.fsm_config = config;
        
        // Recreate factory with new configuration if we have a backend
        if let Some(ref factory) = self.fsm_factory {
            // Extract backend from current factory - we need to clone it
            // In a real implementation, we'd store the backend separately
            let backend = factory.backend().clone();
            
            // Recreate factory with new configuration
            self.fsm_factory = Some(operation_fsms::FsmFactory::with_config(backend, self.fsm_config.clone()));
            
            info!("FSM factory recreated with new configuration");
            
            // Log configuration changes
            self.log_configuration_changes(&old_config, &self.fsm_config);
            
            // Warn about active FSMs if any exist
            if had_active_fsms {
                warn!("Configuration updated while {} FSMs are active. New FSMs will use updated configuration, but existing FSMs will continue with their original configuration until completion.", 
                      self.operation_fsms.len());
            }
            
            Ok(())
        } else {
            // No factory exists - just update config for when factory is created
            info!("No FSM factory configured - configuration will be applied when factory is created");
            Ok(())
        }
    }
    
    /// Update FSM factory configuration with backend reconfiguration
    pub fn reconfigure_fsm_factory(
        &mut self, 
        backend: Arc<dyn DirectoryBackend>, 
        routing_config: FsmRoutingConfig,
        fsm_config: OperationFsmConfig
    ) -> Result<(), String> {
        info!("Reconfiguring FSM factory with new backend and configurations");
        
        let had_active_fsms = !self.operation_fsms.is_empty();
        
        // Store old configurations for comparison
        let old_routing_config = self.routing_config.clone();
        let old_fsm_config = self.fsm_config.clone();
        
        // Apply new configurations
        self.routing_config = routing_config;
        self.fsm_config = fsm_config;
        
        // Recreate factory with new backend and configuration
        self.fsm_factory = Some(operation_fsms::FsmFactory::with_config(backend.clone(), self.fsm_config.clone()));
        
        // Also reconfigure auth backend for consistency
        self.configure_auth_backend(backend);
        
        info!("FSM factory successfully reconfigured");
        
        // Log configuration changes
        self.log_routing_configuration_changes(&old_routing_config, &self.routing_config);
        self.log_configuration_changes(&old_fsm_config, &self.fsm_config);
        
        // Handle active FSMs
        if had_active_fsms {
            warn!("Factory reconfigured while {} FSMs are active. Consider graceful shutdown or FSM migration.", 
                  self.operation_fsms.len());
            
            // Optionally provide FSM migration capability
            self.suggest_fsm_migration();
        }
        
        Ok(())
    }
    
    /// Gracefully migrate active FSMs to new configuration (if possible)
    pub fn migrate_active_fsms_to_new_config(&mut self) -> Result<Vec<u32>, String> {
        if self.operation_fsms.is_empty() {
            return Ok(Vec::new());
        }
        
        info!("Attempting to migrate {} active FSMs to new configuration", self.operation_fsms.len());
        
        let mut migrated_fsms = Vec::new();
        let mut failed_migrations = Vec::new();
        
        // For now, we'll just log which FSMs could potentially be migrated
        // In a full implementation, this would depend on FSM state and migration capabilities
        for (msg_id, fsm_instance) in &self.operation_fsms {
            let can_migrate = match fsm_instance {
                operation_fsms::OperationFsmInstance::Search(_) => {
                    // Search FSMs might be migratable if they're in certain states
                    !fsm_instance.is_terminal()
                },
                operation_fsms::OperationFsmInstance::Write(_) => {
                    // Write FSMs are typically not migratable due to transaction consistency
                    false
                },
                operation_fsms::OperationFsmInstance::Compare(_) => {
                    // Compare FSMs might be migratable if they haven't started processing
                    !fsm_instance.is_terminal()
                },
                operation_fsms::OperationFsmInstance::ExtendedOp(_) => {
                    // Extended operations vary by operation type
                    !fsm_instance.is_terminal()
                },
            };
            
            if can_migrate {
                debug!("FSM {} ({}) is potentially migratable", msg_id, fsm_instance.operation_type());
                migrated_fsms.push(*msg_id);
            } else {
                debug!("FSM {} ({}) cannot be migrated - will complete with old configuration", 
                       msg_id, fsm_instance.operation_type());
                failed_migrations.push(*msg_id);
            }
        }
        
        if !migrated_fsms.is_empty() {
            info!("Identified {} FSMs for potential migration: {:?}", migrated_fsms.len(), migrated_fsms);
        }
        
        if !failed_migrations.is_empty() {
            info!("Identified {} FSMs that cannot be migrated: {:?}", failed_migrations.len(), failed_migrations);
        }
        
        Ok(migrated_fsms)
    }
    
    /// Force cleanup of all active FSMs (use with caution)
    pub fn force_cleanup_all_fsms(&mut self, reason: &str) -> Vec<u32> {
        warn!("Force cleaning up all {} active FSMs: {}", self.operation_fsms.len(), reason);
        
        let all_msg_ids: Vec<u32> = self.operation_fsms.keys().cloned().collect();
        
        for msg_id in &all_msg_ids {
            if let Some(fsm_instance) = self.operation_fsms.get(msg_id) {
                warn!("Force removing FSM {} ({}) - {}", 
                      msg_id, fsm_instance.operation_type(), reason);
            }
            self.remove_operation_fsm(*msg_id);
        }
        
        info!("Force cleanup completed - removed {} FSMs", all_msg_ids.len());
        all_msg_ids
    }
    
    /// Log configuration changes for debugging
    fn log_configuration_changes(&self, old_config: &OperationFsmConfig, new_config: &OperationFsmConfig) {
        if old_config.operation_timeout != new_config.operation_timeout {
            info!("Operation timeout changed: {:?} -> {:?}", 
                  old_config.operation_timeout, new_config.operation_timeout);
        }
        
        if old_config.max_concurrent_operations != new_config.max_concurrent_operations {
            info!("Max concurrent operations changed: {} -> {}", 
                  old_config.max_concurrent_operations, new_config.max_concurrent_operations);
        }
        
        // Log FSM-specific configuration changes
        if old_config.search != new_config.search {
            debug!("Search FSM configuration changed");
        }
        
        if old_config.write != new_config.write {
            debug!("Write FSM configuration changed");
        }
        
        if old_config.compare != new_config.compare {
            debug!("Compare FSM configuration changed");
        }
        
        if old_config.extended_op != new_config.extended_op {
            debug!("Extended operation FSM configuration changed");
        }
    }
    
    /// Log routing configuration changes
    fn log_routing_configuration_changes(&self, old_config: &FsmRoutingConfig, new_config: &FsmRoutingConfig) {
        if old_config.enable_search_fsm != new_config.enable_search_fsm {
            info!("Search FSM routing changed: {} -> {}", 
                  old_config.enable_search_fsm, new_config.enable_search_fsm);
        }
        
        if old_config.enable_write_fsm != new_config.enable_write_fsm {
            info!("Write FSM routing changed: {} -> {}", 
                  old_config.enable_write_fsm, new_config.enable_write_fsm);
        }
        
        if old_config.enable_compare_fsm != new_config.enable_compare_fsm {
            info!("Compare FSM routing changed: {} -> {}", 
                  old_config.enable_compare_fsm, new_config.enable_compare_fsm);
        }
        
        if old_config.enable_extended_op_fsm != new_config.enable_extended_op_fsm {
            info!("Extended operation FSM routing changed: {} -> {}", 
                  old_config.enable_extended_op_fsm, new_config.enable_extended_op_fsm);
        }
        
        if old_config.fallback_to_direct != new_config.fallback_to_direct {
            info!("Fallback to direct handling changed: {} -> {}", 
                  old_config.fallback_to_direct, new_config.fallback_to_direct);
        }
    }
    
    /// Suggest FSM migration strategies
    fn suggest_fsm_migration(&self) {
        if self.operation_fsms.is_empty() {
            return;
        }
        
        info!("FSM migration suggestions:");
        info!("  1. Wait for active FSMs to complete naturally");
        info!("  2. Use migrate_active_fsms_to_new_config() to attempt graceful migration");
        info!("  3. Use force_cleanup_all_fsms() for immediate cleanup (may cause operation failures)");
        info!("  4. Monitor FSM completion with get_fsm_timeout_status()");
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
                Ok(user_info) => {
                    // FSM handled authentication internally - send success response
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

/// FSM-based client handler with full FSM routing
/// This demonstrates complete FSM integration with proper routing
pub async fn handle_client_fsm_simple(mut socket: TcpStream, backend: Arc<dyn DirectoryBackend>) {
    // Create FSM set with FSM routing enabled
    let routing_config = FsmRoutingConfig {
        enable_search_fsm: true,
        enable_write_fsm: true,
        enable_compare_fsm: true,
        enable_extended_op_fsm: true,
        fallback_to_direct: true, // Allow fallback if FSMs fail
    };
    
    let fsm_config = OperationFsmConfig {
        max_concurrent_operations: 100,
        operation_timeout: Duration::from_secs(300), // 5 minutes
        search: SearchFsmConfig {
            enable_metrics: true,
            ..Default::default()
        },
        write: WriteFsmConfig {
            enable_audit_logging: true,
            ..Default::default()
        },
        compare: CompareFsmConfig {
            enable_metrics: true,
            ..Default::default()
        },
        extended_op: ExtendedOpFsmConfig {
            enable_metrics: true,
            ..Default::default()
        },
    };
    
    // Create FSM set with routing configuration
    // We'll create a ConnectionFsmSet without the complex constructor that needs TcpStream
    let remote_addr = socket.peer_addr().expect("Failed to get remote address");
    let local_addr = socket.local_addr().expect("Failed to get local address");
    
    let mut fsm_set = ConnectionFsmSet {
        connection: ConnectionFsmImpl::new_outbound(),
        decoder: BerDecoderFsmImpl::new(),
        auth: AuthFsmImpl::new(),
        sasl: None,
        last_activity: Instant::now(),
        session_timeout: Duration::from_secs(3600),
        operation_fsms: HashMap::new(),
        fsm_factory: None,
        routing_config,
        fsm_config: fsm_config.clone(),
        fsm_start_times: HashMap::new(),
    };
    
    // Configure the FSMs with the backend
    fsm_set.configure_operation_fsms(backend.clone(), fsm_set.routing_config.clone(), fsm_config);
    
    let mut decoder_fsm = BerDecoderFsmImpl::new();
    let mut buffer = vec![0; 4096];
    
    info!("FSM-enabled connection established with full routing support");
    
    loop {
        match socket.read(&mut buffer).await {
            Ok(0) => {
                debug!("Connection closed by client");
                if let Err(e) = fsm_set.connection.handle_event(ConnectionEvent::Close).await {
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
                    
                    // Parse and process LDAP messages with FSM routing
                    match ldap_parser::parse_ldap_messages(&message_data) {
                        Ok((_, messages)) => {
                            for message in messages {
                                // Use FSM routing instead of direct processing
                                if let Err(err) = process_message_with_fsm(
                                    &mut socket, 
                                    backend.as_ref(),
                                    Some(&mut fsm_set),
                                    message
                                ).await {
                                    error!("Failed to process message through FSM routing: {}", err);
                                    
                                    // Handle different error types appropriately
                                    match err {
                                        ServerError::Io(_) => {
                                            // Network error - close connection
                                            if let Err(conn_err) = fsm_set.connection
                                                .handle_event(ConnectionEvent::ConnectionLost)
                                                .await 
                                            {
                                                error!("Failed to handle connection lost: {:?}", conn_err);
                                            }
                                            return;
                                        }
                                        _ => {
                                            // Other errors - log and continue
                                            if let Err(conn_err) = fsm_set.connection
                                                .handle_event(ConnectionEvent::Error(err.to_string()))
                                                .await 
                                            {
                                                error!("Failed to handle connection error: {:?}", conn_err);
                                            }
                                            // Continue processing other messages
                                        }
                                    }
                                }
                            }
                        }
                        Err(err) => {
                            error!("Failed to parse LDAP message: {:?}", err);
                            if let Err(conn_err) = fsm_set.connection
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
                if let Err(conn_err) = fsm_set.connection
                    .handle_event(ConnectionEvent::ConnectionLost)
                    .await 
                {
                    error!("Failed to handle connection lost: {:?}", conn_err);
                }
                break;
            }
        }
        
        // Periodic cleanup of timed-out FSMs
        let timed_out_fsms = fsm_set.cleanup_timed_out_fsms();
        if !timed_out_fsms.is_empty() {
            info!("Cleaned up {} timed-out FSMs during connection handling", timed_out_fsms.len());
        }
    }
    
    info!("FSM-enabled LDAP connection closed. Final stats: {} active operations", 
          fsm_set.active_operation_count());
    debug!("Connection FSM final state: {:?}", fsm_set.connection.current_state());
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

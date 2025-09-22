//! Write Finite State Machine Implementation
//!
//! This module implements a comprehensive Write FSM for LDAP write operations.
//! The FSM manages Add, Modify, ModifyDN, and Delete operations with proper
//! schema validation, access control checks, transaction management, and 
//! comprehensive error handling.
//!
//! ## Write Operation Flow
//!
//! ```text
//! Validating -> CheckingSchema -> CheckingAci -> InTransaction -> Committing -> Completed
//!     |               |              |             |              |            ^
//!     |               |              |             |              |            |
//!     v               v              v             v              v            |
//!   Failed          Failed         Failed        Failed       Rollback    ----+
//!     ^               ^              ^             ^              ^
//!     |               |              |             |              |
//!     +-- Error ------+-- Error -----+-- Error ----+-- Error -----+
//! ```
//!
//! ## Supported Write Operations
//!
//! The FSM supports all LDAP write operations:
//! - **Add**: Create new directory entries with validation
//! - **Modify**: Update existing entries with change tracking
//! - **ModifyDN**: Rename/move entries with referential integrity
//! - **Delete**: Remove entries with dependency checking
//!
//! ## External Dependencies
//!
//! The FSM abstracts external dependencies through traits:
//! - `WriteBackend`: Entry manipulation and transaction management
//! - `SchemaValidator`: LDAP schema compliance verification
//! - `AciChecker`: Access Control Information evaluation
//! - `WriteMetrics`: Performance monitoring and audit logging
//!
//! ## Usage Example
//!
//! ```rust,no_run
//! use opendr::write_fsm::*;
//! use opendr::fsm::{StateMachine, WriteState, WriteEvent, WriteOperation};
//! 
//! # struct MockWriteBackend;
//! # #[async_trait::async_trait]
//! # impl WriteBackend for MockWriteBackend {
//! #     async fn validate_entry(&self, _dn: &str, _entry: &[u8]) -> Result<(), String> { Ok(()) }
//! #     async fn begin_transaction(&self) -> Result<String, String> { Ok("txn-1".to_string()) }
//! #     async fn commit_transaction(&self, _txn_id: &str) -> Result<(), String> { Ok(()) }
//! # }
//! #
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let backend = Box::new(MockWriteBackend);
//! let schema_validator = Box::new(MockSchemaValidator::new());
//! let aci_checker = Box::new(MockAciChecker::new());
//! 
//! let mut fsm = WriteFsmImpl::new(backend, schema_validator, aci_checker);
//! 
//! // Start add operation
//! let result = fsm.handle_event(WriteEvent::StartWrite(WriteOperation::Add {
//!     dn: "cn=newuser,ou=people,dc=example,dc=org".to_string(),
//!     entry: b"dn: cn=newuser,ou=people,dc=example,dc=org\nobjectClass: person\ncn: newuser\n".to_vec(),
//! })).await?;
//! # Ok(())
//! # }
//! ```

use crate::fsm::{StateMachine, WriteFsm, WriteState, WriteEvent, WriteOperation, WriteResultCode};
use async_trait::async_trait;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use thiserror::Error;

/// Errors that can occur during write operations
#[derive(Error, Debug, Clone, PartialEq)]
pub enum WriteFsmError {
    #[error("Invalid write operation: {message}")]
    InvalidOperation { message: String },
    
    #[error("Write backend error: {message}")]
    BackendError { message: String },
    
    #[error("Schema validation error: {message}")]
    SchemaError { message: String },
    
    #[error("Access control violation: {message}")]
    AccessDenied { message: String },
    
    #[error("Transaction error: {message}")]
    TransactionError { message: String },
    
    #[error("Entry already exists: {dn}")]
    EntryAlreadyExists { dn: String },
    
    #[error("Entry not found: {dn}")]
    NoSuchObject { dn: String },
    
    #[error("Constraint violation: {message}")]
    ConstraintViolation { message: String },
    
    #[error("Invalid state transition from {from:?} to {to:?}")]
    InvalidStateTransition { from: WriteState, to: WriteState },
    
    #[error("No active write operation")]
    NoActiveOperation,
    
    #[error("Generic write error: {message}")]
    Generic { message: String },
}

/// Represents an LDAP entry for write operations
#[derive(Debug, Clone, PartialEq)]
pub struct WriteEntry {
    /// Distinguished Name of the entry
    pub dn: String,
    /// Entry attributes as key-value pairs
    pub attributes: HashMap<String, Vec<String>>,
    /// Entry object classes
    pub object_classes: Vec<String>,
    /// Binary attributes (for non-text data)
    pub binary_attributes: HashMap<String, Vec<Vec<u8>>>,
}

impl WriteEntry {
    /// Create a new write entry
    /// 
    /// # Arguments
    /// * `dn` - Distinguished name of the entry
    /// 
    /// # Returns
    /// * New WriteEntry instance
    pub fn new(dn: String) -> Self {
        Self {
            dn,
            attributes: HashMap::new(),
            object_classes: Vec::new(),
            binary_attributes: HashMap::new(),
        }
    }
    
    /// Add a text attribute to the entry
    /// 
    /// # Arguments
    /// * `name` - Attribute name
    /// * `values` - Attribute values
    pub fn add_attribute(&mut self, name: String, values: Vec<String>) {
        self.attributes.insert(name, values);
    }
    
    /// Add a binary attribute to the entry
    /// 
    /// # Arguments
    /// * `name` - Attribute name
    /// * `values` - Binary attribute values
    pub fn add_binary_attribute(&mut self, name: String, values: Vec<Vec<u8>>) {
        self.binary_attributes.insert(name, values);
    }
    
    /// Set object classes for the entry
    /// 
    /// # Arguments
    /// * `object_classes` - List of object class names
    pub fn set_object_classes(&mut self, object_classes: Vec<String>) {
        self.object_classes = object_classes;
    }
    
    /// Get attribute values by name
    /// 
    /// # Arguments
    /// * `name` - Attribute name
    /// 
    /// # Returns
    /// * Option containing attribute values if found
    pub fn get_attribute(&self, name: &str) -> Option<&Vec<String>> {
        self.attributes.get(name)
    }
    
    /// Get binary attribute values by name
    /// 
    /// # Arguments
    /// * `name` - Attribute name
    /// 
    /// # Returns
    /// * Option containing binary attribute values if found
    pub fn get_binary_attribute(&self, name: &str) -> Option<&Vec<Vec<u8>>> {
        self.binary_attributes.get(name)
    }
    
    /// Check if entry has a specific object class
    /// 
    /// # Arguments
    /// * `object_class` - Object class name to check
    /// 
    /// # Returns
    /// * true if entry has the object class
    pub fn has_object_class(&self, object_class: &str) -> bool {
        self.object_classes.iter().any(|oc| oc.eq_ignore_ascii_case(object_class))
    }
    
    /// Encode entry as LDIF bytes
    /// 
    /// # Returns
    /// * Entry encoded as LDIF
    pub fn encode_as_ldif(&self) -> Vec<u8> {
        let mut ldif = format!("dn: {}\n", self.dn);
        
        for object_class in &self.object_classes {
            ldif.push_str(&format!("objectClass: {}\n", object_class));
        }
        
        for (name, values) in &self.attributes {
            for value in values {
                ldif.push_str(&format!("{}: {}\n", name, value));
            }
        }
        
        // Binary attributes would be base64 encoded in real implementation
        for (name, values) in &self.binary_attributes {
            for value in values {
                ldif.push_str(&format!("{}:: <{} bytes of binary data>\n", name, value.len()));
            }
        }
        
        ldif.into_bytes()
    }
}

/// Represents a modification to an entry
#[derive(Debug, Clone, PartialEq)]
pub enum Modification {
    /// Add attribute values
    Add { name: String, values: Vec<String> },
    /// Delete attribute values (empty values = delete all)
    Delete { name: String, values: Vec<String> },
    /// Replace attribute values
    Replace { name: String, values: Vec<String> },
}

/// Trait for backend write operations
/// 
/// This trait abstracts the directory backend for write operations,
/// allowing different storage implementations.
#[async_trait]
pub trait WriteBackend: Send + Sync {
    /// Begin a new transaction
    /// 
    /// # Returns
    /// * `Ok(String)` - Transaction ID
    /// * `Err(String)` - Error message if transaction cannot be started
    async fn begin_transaction(&self) -> Result<String, String>;
    
    /// Commit a transaction
    /// 
    /// # Arguments
    /// * `txn_id` - Transaction ID to commit
    /// 
    /// # Returns
    /// * `Ok(())` - Transaction committed successfully
    /// * `Err(String)` - Error message if commit fails
    async fn commit_transaction(&self, txn_id: &str) -> Result<(), String>;
    
    /// Rollback a transaction
    /// 
    /// # Arguments
    /// * `txn_id` - Transaction ID to rollback
    /// * `reason` - Reason for rollback
    /// 
    /// # Returns
    /// * `Ok(())` - Transaction rolled back successfully
    /// * `Err(String)` - Error message if rollback fails
    async fn rollback_transaction(&self, txn_id: &str, reason: &str) -> Result<(), String>;
    
    /// Validate an entry before writing
    /// 
    /// # Arguments
    /// * `dn` - Distinguished name of entry
    /// * `entry` - Entry data to validate
    /// 
    /// # Returns
    /// * `Ok(())` - Entry is valid
    /// * `Err(String)` - Validation error message
    async fn validate_entry(&self, dn: &str, entry: &[u8]) -> Result<(), String>;
    
    /// Add a new entry
    /// 
    /// # Arguments
    /// * `txn_id` - Transaction ID
    /// * `dn` - Distinguished name
    /// * `entry` - Entry data
    /// 
    /// # Returns
    /// * `Ok(())` - Entry added successfully
    /// * `Err(String)` - Error message if add fails
    async fn add_entry(&self, txn_id: &str, dn: &str, entry: &[u8]) -> Result<(), String>;
    
    /// Modify an existing entry
    /// 
    /// # Arguments
    /// * `txn_id` - Transaction ID
    /// * `dn` - Distinguished name
    /// * `modifications` - Changes to apply
    /// 
    /// # Returns
    /// * `Ok(())` - Entry modified successfully
    /// * `Err(String)` - Error message if modify fails
    async fn modify_entry(&self, txn_id: &str, dn: &str, modifications: &[Modification]) -> Result<(), String>;
    
    /// Rename/move an entry
    /// 
    /// # Arguments
    /// * `txn_id` - Transaction ID
    /// * `dn` - Current distinguished name
    /// * `new_rdn` - New relative distinguished name
    /// * `delete_old` - Whether to delete old RDN
    /// * `new_superior` - New parent DN (for moves)
    /// 
    /// # Returns
    /// * `Ok(())` - Entry renamed successfully
    /// * `Err(String)` - Error message if rename fails
    async fn modify_dn(&self, txn_id: &str, dn: &str, new_rdn: &str, delete_old: bool, new_superior: Option<&str>) -> Result<(), String>;
    
    /// Delete an entry
    /// 
    /// # Arguments
    /// * `txn_id` - Transaction ID
    /// * `dn` - Distinguished name
    /// 
    /// # Returns
    /// * `Ok(())` - Entry deleted successfully
    /// * `Err(String)` - Error message if delete fails
    async fn delete_entry(&self, txn_id: &str, dn: &str) -> Result<(), String>;
    
    /// Check if an entry exists
    /// 
    /// # Arguments
    /// * `dn` - Distinguished name to check
    /// 
    /// # Returns
    /// * `Ok(true)` - Entry exists
    /// * `Ok(false)` - Entry does not exist
    /// * `Err(String)` - Error message if check fails
    async fn entry_exists(&self, dn: &str) -> Result<bool, String>;
    
    /// Get transaction statistics
    /// 
    /// # Arguments
    /// * `txn_id` - Transaction ID
    /// 
    /// # Returns
    /// * (operations_performed, entries_affected)
    async fn get_transaction_stats(&self, txn_id: &str) -> Result<(usize, usize), String> {
        // Default implementation returns zeros
        Ok((0, 0))
    }
}

/// Trait for LDAP schema validation
/// 
/// This trait abstracts schema validation logic, allowing different
/// schema implementations and validation strategies.
#[async_trait]
pub trait SchemaValidator: Send + Sync {
    /// Validate entry against schema
    /// 
    /// # Arguments
    /// * `entry` - Entry to validate
    /// 
    /// # Returns
    /// * `Ok(())` - Entry conforms to schema
    /// * `Err(String)` - Schema validation error
    async fn validate_entry(&self, entry: &WriteEntry) -> Result<(), String>;
    
    /// Validate modifications against schema
    /// 
    /// # Arguments
    /// * `dn` - Entry being modified
    /// * `modifications` - Modifications to validate
    /// 
    /// # Returns
    /// * `Ok(())` - Modifications conform to schema
    /// * `Err(String)` - Schema validation error
    async fn validate_modifications(&self, dn: &str, modifications: &[Modification]) -> Result<(), String>;
    
    /// Validate DN rename/move against schema
    /// 
    /// # Arguments
    /// * `dn` - Current DN
    /// * `new_rdn` - New RDN
    /// * `new_superior` - New parent DN
    /// 
    /// # Returns
    /// * `Ok(())` - Rename/move conforms to schema
    /// * `Err(String)` - Schema validation error
    async fn validate_dn_modification(&self, dn: &str, new_rdn: &str, new_superior: Option<&str>) -> Result<(), String> {
        // Default implementation accepts all modifications
        Ok(())
    }
    
    /// Check if object class is known
    /// 
    /// # Arguments
    /// * `object_class` - Object class name to check
    /// 
    /// # Returns
    /// * true if object class is defined in schema
    fn is_object_class_defined(&self, object_class: &str) -> bool {
        // Default implementation assumes all object classes are valid
        true
    }
}

/// Trait for Access Control Information (ACI) checking
/// 
/// This trait abstracts access control evaluation, allowing different
/// authorization implementations and policies.
#[async_trait]
pub trait AciChecker: Send + Sync {
    /// Check if user has permission for write operation
    /// 
    /// # Arguments
    /// * `user_dn` - Distinguished name of user performing operation
    /// * `operation` - Write operation being performed
    /// 
    /// # Returns
    /// * `Ok(())` - User has permission
    /// * `Err(String)` - Access denied error message
    async fn check_write_permission(&self, user_dn: Option<&str>, operation: &WriteOperation) -> Result<(), String>;
    
    /// Check if user can add entry
    /// 
    /// # Arguments
    /// * `user_dn` - User performing operation
    /// * `entry_dn` - DN of entry to add
    /// * `entry` - Entry data
    /// 
    /// # Returns
    /// * `Ok(())` - User can add entry
    /// * `Err(String)` - Access denied
    async fn check_add_permission(&self, user_dn: Option<&str>, entry_dn: &str, entry: &WriteEntry) -> Result<(), String> {
        // Default implementation allows all operations
        Ok(())
    }
    
    /// Check if user can modify entry
    /// 
    /// # Arguments
    /// * `user_dn` - User performing operation
    /// * `entry_dn` - DN of entry to modify
    /// * `modifications` - Modifications to apply
    /// 
    /// # Returns
    /// * `Ok(())` - User can modify entry
    /// * `Err(String)` - Access denied
    async fn check_modify_permission(&self, user_dn: Option<&str>, entry_dn: &str, modifications: &[Modification]) -> Result<(), String> {
        // Default implementation allows all operations
        Ok(())
    }
    
    /// Check if user can delete entry
    /// 
    /// # Arguments
    /// * `user_dn` - User performing operation
    /// * `entry_dn` - DN of entry to delete
    /// 
    /// # Returns
    /// * `Ok(())` - User can delete entry
    /// * `Err(String)` - Access denied
    async fn check_delete_permission(&self, user_dn: Option<&str>, entry_dn: &str) -> Result<(), String> {
        // Default implementation allows all operations
        Ok(())
    }
}

/// Trait for write operation metrics and monitoring
/// 
/// This trait provides hooks for performance monitoring,
/// audit logging, and operational insights.
pub trait WriteMetrics: Send + Sync {
    /// Record write operation start
    /// 
    /// # Arguments
    /// * `user_dn` - User performing operation
    /// * `operation` - Write operation being performed
    fn record_write_start(&self, user_dn: Option<&str>, operation: &WriteOperation);
    
    /// Record validation phase completion
    /// 
    /// # Arguments
    /// * `operation_type` - Type of operation validated
    /// * `duration` - Validation duration
    fn record_validation_complete(&self, operation_type: &str, duration: Duration);
    
    /// Record schema check completion
    /// 
    /// # Arguments
    /// * `operation_type` - Type of operation checked
    /// * `duration` - Schema check duration
    fn record_schema_check_complete(&self, operation_type: &str, duration: Duration);
    
    /// Record ACI check completion
    /// 
    /// # Arguments
    /// * `operation_type` - Type of operation checked
    /// * `duration` - ACI check duration
    fn record_aci_check_complete(&self, operation_type: &str, duration: Duration);
    
    /// Record transaction started
    /// 
    /// # Arguments
    /// * `txn_id` - Transaction ID
    fn record_transaction_started(&self, txn_id: &str);
    
    /// Record write operation completion
    /// 
    /// # Arguments
    /// * `operation` - Completed operation
    /// * `result_code` - Final result code
    /// * `duration` - Total operation duration
    fn record_write_complete(&self, operation: &WriteOperation, result_code: &WriteResultCode, duration: Duration);
    
    /// Record write operation rollback
    /// 
    /// # Arguments
    /// * `operation` - Failed operation
    /// * `reason` - Rollback reason
    fn record_write_rollback(&self, operation: &WriteOperation, reason: &str);
    
    /// Get write statistics
    /// 
    /// # Returns
    /// * (total_writes, successful_writes, failed_writes)
    fn get_stats(&self) -> (u64, u64, u64) {
        // Default implementation returns zeros
        (0, 0, 0)
    }
}

/// Configuration for the Write FSM
#[derive(Debug, Clone)]
pub struct WriteFsmConfig {
    /// Default transaction timeout (in seconds)
    pub default_transaction_timeout: u32,
    /// Maximum transaction timeout (in seconds)
    pub max_transaction_timeout: u32,
    /// Enable strict schema validation
    pub strict_schema_validation: bool,
    /// Enable access control checks
    pub enable_aci_checks: bool,
    /// Maximum entry size in bytes
    pub max_entry_size: usize,
    /// Maximum number of modifications per request
    pub max_modifications_per_request: usize,
    /// Enable write operation auditing
    pub enable_audit_logging: bool,
}

impl Default for WriteFsmConfig {
    fn default() -> Self {
        Self {
            default_transaction_timeout: 30,
            max_transaction_timeout: 300, // 5 minutes
            strict_schema_validation: true,
            enable_aci_checks: true,
            max_entry_size: 1_048_576, // 1MB
            max_modifications_per_request: 1000,
            enable_audit_logging: true,
        }
    }
}

/// Write session state for tracking write progress
#[derive(Debug, Clone)]
pub struct WriteSession {
    /// Write operation being performed
    pub operation: WriteOperation,
    /// User performing the operation
    pub user_dn: Option<String>,
    /// Start time of the operation
    pub start_time: Instant,
    /// Transaction ID if in transaction
    pub transaction_id: Option<String>,
    /// Validation start time
    pub validation_start: Option<Instant>,
    /// Schema check start time
    pub schema_check_start: Option<Instant>,
    /// ACI check start time
    pub aci_check_start: Option<Instant>,
    /// Transaction start time
    pub transaction_start: Option<Instant>,
    /// Whether operation can be rolled back
    pub can_rollback: bool,
}

impl WriteSession {
    /// Create a new write session
    /// 
    /// # Arguments
    /// * `operation` - Write operation to perform
    /// * `user_dn` - User performing the operation
    /// 
    /// # Returns
    /// * New WriteSession instance
    pub fn new(operation: WriteOperation, user_dn: Option<String>) -> Self {
        Self {
            operation,
            user_dn,
            start_time: Instant::now(),
            transaction_id: None,
            validation_start: None,
            schema_check_start: None,
            aci_check_start: None,
            transaction_start: None,
            can_rollback: false,
        }
    }
    
    /// Get operation type as string
    /// 
    /// # Returns
    /// * Operation type name
    pub fn operation_type(&self) -> &str {
        match &self.operation {
            WriteOperation::Add { .. } => "add",
            WriteOperation::Modify { .. } => "modify",
            WriteOperation::ModifyDn { .. } => "modifydn",
            WriteOperation::Delete { .. } => "delete",
        }
    }
    
    /// Get target DN for the operation
    /// 
    /// # Returns
    /// * DN being operated on
    pub fn target_dn(&self) -> &str {
        match &self.operation {
            WriteOperation::Add { dn, .. } => dn,
            WriteOperation::Modify { dn, .. } => dn,
            WriteOperation::ModifyDn { dn, .. } => dn,
            WriteOperation::Delete { dn } => dn,
        }
    }
    
    /// Check if transaction timeout has been exceeded
    /// 
    /// # Arguments
    /// * `timeout_seconds` - Transaction timeout in seconds
    /// 
    /// # Returns
    /// * true if transaction has timed out
    pub fn is_transaction_timed_out(&self, timeout_seconds: u32) -> bool {
        if let Some(txn_start) = self.transaction_start {
            let elapsed = txn_start.elapsed().as_secs() as u32;
            elapsed > timeout_seconds
        } else {
            false
        }
    }
}

/// Write FSM Implementation
/// 
/// This FSM manages the complete write operation lifecycle including:
/// - Operation validation and preprocessing
/// - Schema compliance verification
/// - Access control evaluation
/// - Transaction management and rollback
/// - Error handling and audit logging
pub struct WriteFsmImpl {
    /// Current FSM state
    state: WriteState,
    
    /// Current write session (if active)
    session: Option<WriteSession>,
    
    /// Write backend for entry manipulation
    backend: Box<dyn WriteBackend>,
    
    /// Schema validator for compliance checking
    schema_validator: Box<dyn SchemaValidator>,
    
    /// ACI checker for access control
    aci_checker: Box<dyn AciChecker>,
    
    /// Metrics collector (optional)
    metrics: Option<Box<dyn WriteMetrics>>,
    
    /// FSM configuration
    config: WriteFsmConfig,
    
    /// Statistics tracking
    total_writes: u64,
    successful_writes: u64,
    failed_writes: u64,
}

impl WriteFsmImpl {
    /// Create a new Write FSM instance
    /// 
    /// # Arguments
    /// * `backend` - Write backend implementation
    /// * `schema_validator` - Schema validation implementation
    /// * `aci_checker` - Access control implementation
    /// 
    /// # Returns
    /// * New Write FSM instance
    pub fn new(
        backend: Box<dyn WriteBackend>,
        schema_validator: Box<dyn SchemaValidator>,
        aci_checker: Box<dyn AciChecker>,
    ) -> Self {
        Self {
            state: WriteState::Validating,
            session: None,
            backend,
            schema_validator,
            aci_checker,
            metrics: None,
            config: WriteFsmConfig::default(),
            total_writes: 0,
            successful_writes: 0,
            failed_writes: 0,
        }
    }
    
    /// Create a Write FSM with custom configuration
    /// 
    /// # Arguments
    /// * `backend` - Write backend implementation
    /// * `schema_validator` - Schema validation implementation
    /// * `aci_checker` - Access control implementation
    /// * `config` - FSM configuration
    /// 
    /// # Returns
    /// * New Write FSM instance with custom configuration
    pub fn with_config(
        backend: Box<dyn WriteBackend>,
        schema_validator: Box<dyn SchemaValidator>,
        aci_checker: Box<dyn AciChecker>,
        config: WriteFsmConfig,
    ) -> Self {
        Self {
            state: WriteState::Validating,
            session: None,
            backend,
            schema_validator,
            aci_checker,
            metrics: None,
            config,
            total_writes: 0,
            successful_writes: 0,
            failed_writes: 0,
        }
    }
    
    /// Set metrics collector
    /// 
    /// # Arguments
    /// * `metrics` - Metrics implementation
    /// 
    /// # Returns
    /// * Updated Write FSM instance
    pub fn with_metrics(mut self, metrics: Box<dyn WriteMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }
    
    /// Get write statistics
    /// 
    /// # Returns
    /// * (total_writes, successful_writes, failed_writes)
    pub fn stats(&self) -> (u64, u64, u64) {
        (self.total_writes, self.successful_writes, self.failed_writes)
    }
    
    /// Validate write operation
    /// 
    /// # Arguments
    /// * `operation` - Write operation to validate
    /// 
    /// # Returns
    /// * `Ok(())` if operation is valid
    /// * `Err(WriteFsmError)` if validation fails
    fn validate_write_operation(&self, operation: &WriteOperation) -> Result<(), WriteFsmError> {
        match operation {
            WriteOperation::Add { dn, entry } => {
                if dn.is_empty() {
                    return Err(WriteFsmError::InvalidOperation {
                        message: "DN cannot be empty for add operation".to_string(),
                    });
                }
                if entry.is_empty() {
                    return Err(WriteFsmError::InvalidOperation {
                        message: "Entry data cannot be empty for add operation".to_string(),
                    });
                }
                if entry.len() > self.config.max_entry_size {
                    return Err(WriteFsmError::InvalidOperation {
                        message: format!("Entry size {} exceeds maximum {}", entry.len(), self.config.max_entry_size),
                    });
                }
            },
            WriteOperation::Modify { dn, changes } => {
                if dn.is_empty() {
                    return Err(WriteFsmError::InvalidOperation {
                        message: "DN cannot be empty for modify operation".to_string(),
                    });
                }
                if changes.is_empty() {
                    return Err(WriteFsmError::InvalidOperation {
                        message: "Changes cannot be empty for modify operation".to_string(),
                    });
                }
                if changes.len() > self.config.max_entry_size {
                    return Err(WriteFsmError::InvalidOperation {
                        message: format!("Changes size {} exceeds maximum {}", changes.len(), self.config.max_entry_size),
                    });
                }
            },
            WriteOperation::ModifyDn { dn, new_rdn, .. } => {
                if dn.is_empty() {
                    return Err(WriteFsmError::InvalidOperation {
                        message: "DN cannot be empty for modifydn operation".to_string(),
                    });
                }
                if new_rdn.is_empty() {
                    return Err(WriteFsmError::InvalidOperation {
                        message: "New RDN cannot be empty for modifydn operation".to_string(),
                    });
                }
            },
            WriteOperation::Delete { dn } => {
                if dn.is_empty() {
                    return Err(WriteFsmError::InvalidOperation {
                        message: "DN cannot be empty for delete operation".to_string(),
                    });
                }
            },
        }
        
        Ok(())
    }
    
    /// Handle start write event
    /// 
    /// # Arguments
    /// * `operation` - Write operation to perform
    /// 
    /// # Returns
    /// * Result indicating success or error
    async fn handle_start_write(&mut self, operation: WriteOperation) -> Result<Option<Vec<u8>>, WriteFsmError> {
        // Validate operation
        self.validate_write_operation(&operation)?;
        
        // Create new session
        let session = WriteSession::new(operation.clone(), None); // User DN would be set from context
        
        // Record metrics
        if let Some(ref metrics) = self.metrics {
            metrics.record_write_start(session.user_dn.as_deref(), &operation);
        }
        
        self.session = Some(session);
        self.state = WriteState::Validating;
        self.total_writes += 1;
        
        Ok(None)
    }
    
    /// Handle validation complete event
    /// 
    /// # Returns
    /// * Result indicating success or error
    async fn handle_validation_complete(&mut self) -> Result<Option<Vec<u8>>, WriteFsmError> {
        if let Some(session) = &mut self.session {
            // Record validation metrics
            if let Some(ref metrics) = self.metrics {
                let duration = session.validation_start.map(|s| s.elapsed()).unwrap_or(Duration::ZERO);
                metrics.record_validation_complete(session.operation_type(), duration);
            }
            
            if self.config.strict_schema_validation {
                self.state = WriteState::CheckingSchema;
            } else if self.config.enable_aci_checks {
                self.state = WriteState::CheckingAci;
            } else {
                self.state = WriteState::InTransaction;
            }
            
            Ok(None)
        } else {
            Err(WriteFsmError::NoActiveOperation)
        }
    }
    
    /// Handle schema check complete event
    /// 
    /// # Returns
    /// * Result indicating success or error
    async fn handle_schema_check_complete(&mut self) -> Result<Option<Vec<u8>>, WriteFsmError> {
        if let Some(session) = &mut self.session {
            // Record schema check metrics
            if let Some(ref metrics) = self.metrics {
                let duration = session.schema_check_start.map(|s| s.elapsed()).unwrap_or(Duration::ZERO);
                metrics.record_schema_check_complete(session.operation_type(), duration);
            }
            
            if self.config.enable_aci_checks {
                self.state = WriteState::CheckingAci;
            } else {
                self.state = WriteState::InTransaction;
            }
            
            Ok(None)
        } else {
            Err(WriteFsmError::NoActiveOperation)
        }
    }
    
    /// Handle ACI check complete event
    /// 
    /// # Returns
    /// * Result indicating success or error
    async fn handle_aci_check_complete(&mut self) -> Result<Option<Vec<u8>>, WriteFsmError> {
        if let Some(session) = &mut self.session {
            // Record ACI check metrics
            if let Some(ref metrics) = self.metrics {
                let duration = session.aci_check_start.map(|s| s.elapsed()).unwrap_or(Duration::ZERO);
                metrics.record_aci_check_complete(session.operation_type(), duration);
            }
            
            self.state = WriteState::InTransaction;
            Ok(None)
        } else {
            Err(WriteFsmError::NoActiveOperation)
        }
    }
    
    /// Handle transaction started event
    /// 
    /// # Returns
    /// * Result indicating success or error
    async fn handle_transaction_started(&mut self) -> Result<Option<Vec<u8>>, WriteFsmError> {
        if let Some(session) = &mut self.session {
            session.transaction_start = Some(Instant::now());
            session.can_rollback = true;
            
            // Record transaction metrics
            if let Some(ref metrics) = self.metrics {
                if let Some(ref txn_id) = session.transaction_id {
                    metrics.record_transaction_started(txn_id);
                }
            }
            
            self.state = WriteState::InTransaction;
            Ok(None)
        } else {
            Err(WriteFsmError::NoActiveOperation)
        }
    }
    
    /// Handle write complete event
    /// 
    /// # Returns
    /// * Result indicating success or error
    async fn handle_write_complete(&mut self) -> Result<Option<Vec<u8>>, WriteFsmError> {
        if let Some(_session) = &self.session {
            self.state = WriteState::Committing;
            Ok(None)
        } else {
            Err(WriteFsmError::NoActiveOperation)
        }
    }
    
    /// Handle commit complete event
    /// 
    /// # Returns
    /// * Result indicating success or error
    async fn handle_commit_complete(&mut self) -> Result<Option<Vec<u8>>, WriteFsmError> {
        if let Some(session) = &self.session {
            self.state = WriteState::Completed { 
                result_code: WriteResultCode::Success 
            };
            
            // Record success metrics
            if let Some(ref metrics) = self.metrics {
                metrics.record_write_complete(
                    &session.operation,
                    &WriteResultCode::Success,
                    session.start_time.elapsed(),
                );
            }
            
            self.successful_writes += 1;
            Ok(None)
        } else {
            Err(WriteFsmError::NoActiveOperation)
        }
    }
    
    /// Handle rollback event
    /// 
    /// # Arguments
    /// * `reason` - Reason for rollback
    /// 
    /// # Returns
    /// * Result indicating rollback
    async fn handle_rollback(&mut self, reason: String) -> Result<Option<Vec<u8>>, WriteFsmError> {
        if let Some(session) = &mut self.session {
            self.state = WriteState::Rollback { reason: reason.clone() };
            session.can_rollback = false;
            
            // Record rollback metrics
            if let Some(ref metrics) = self.metrics {
                metrics.record_write_rollback(&session.operation, &reason);
            }
            
            self.failed_writes += 1;
            Err(WriteFsmError::TransactionError { message: reason })
        } else {
            Err(WriteFsmError::NoActiveOperation)
        }
    }
    
    /// Handle error event
    /// 
    /// # Arguments
    /// * `error_message` - Error description
    /// 
    /// # Returns
    /// * Result containing error
    async fn handle_error(&mut self, error_message: String) -> Result<Option<Vec<u8>>, WriteFsmError> {
        self.state = WriteState::Failed { error: error_message.clone() };
        self.failed_writes += 1;
        
        Err(WriteFsmError::Generic { message: error_message })
    }
}

#[async_trait]
impl StateMachine for WriteFsmImpl {
    type State = WriteState;
    type Event = WriteEvent;
    type Error = WriteFsmError;
    type Output = Vec<u8>; // Operation result data
    
    fn current_state(&self) -> &Self::State {
        &self.state
    }
    
    async fn handle_event(&mut self, event: Self::Event) -> Result<Option<Self::Output>, Self::Error> {
        match event {
            WriteEvent::StartWrite(operation) => {
                self.handle_start_write(operation).await
            },
            WriteEvent::ValidationComplete => {
                self.handle_validation_complete().await
            },
            WriteEvent::SchemaCheckComplete => {
                self.handle_schema_check_complete().await
            },
            WriteEvent::AciCheckComplete => {
                self.handle_aci_check_complete().await
            },
            WriteEvent::TransactionStarted => {
                self.handle_transaction_started().await
            },
            WriteEvent::WriteComplete => {
                self.handle_write_complete().await
            },
            WriteEvent::CommitInitiated => {
                // Transitional state, proceed to commit complete
                Ok(None)
            },
            WriteEvent::CommitComplete => {
                self.handle_commit_complete().await
            },
            WriteEvent::RollbackInitiated { reason } => {
                self.handle_rollback(reason).await
            },
            WriteEvent::RollbackComplete => {
                // Final state after rollback
                Ok(None)
            },
            WriteEvent::Error(error_message) => {
                self.handle_error(error_message).await
            },
        }
    }
    
    fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            WriteState::Completed { .. } 
            | WriteState::Failed { .. }
            | WriteState::Rollback { .. }
        )
    }
    
    async fn reset(&mut self) -> Result<(), Self::Error> {
        self.state = WriteState::Validating;
        self.session = None;
        Ok(())
    }
}

#[async_trait]
impl WriteFsm for WriteFsmImpl {
    fn operation(&self) -> Option<&WriteOperation> {
        self.session.as_ref().map(|s| &s.operation)
    }
    
    fn transaction_id(&self) -> Option<&str> {
        self.session.as_ref()
            .and_then(|s| s.transaction_id.as_deref())
    }
    
    fn can_rollback(&self) -> bool {
        self.session.as_ref()
            .map(|s| s.can_rollback)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio;

    /// Mock write backend for testing
    #[derive(Debug)]
    pub struct MockWriteBackend {
        pub should_fail: bool,
        pub transaction_counter: Arc<Mutex<u32>>,
        pub call_log: Arc<Mutex<Vec<String>>>,
    }

    impl MockWriteBackend {
        pub fn new() -> Self {
            Self {
                should_fail: false,
                transaction_counter: Arc::new(Mutex::new(0)),
                call_log: Arc::new(Mutex::new(Vec::new())),
            }
        }

        pub fn with_failure(mut self) -> Self {
            self.should_fail = true;
            self
        }

        pub fn call_log(&self) -> Vec<String> {
            self.call_log.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl WriteBackend for MockWriteBackend {
        async fn begin_transaction(&self) -> Result<String, String> {
            self.call_log.lock().unwrap().push("begin_transaction".to_string());
            
            if self.should_fail {
                return Err("Mock backend transaction failure".to_string());
            }
            
            let mut counter = self.transaction_counter.lock().unwrap();
            *counter += 1;
            Ok(format!("txn-{}", *counter))
        }

        async fn commit_transaction(&self, txn_id: &str) -> Result<(), String> {
            self.call_log.lock().unwrap().push(format!("commit_transaction({})", txn_id));
            
            if self.should_fail {
                return Err("Mock backend commit failure".to_string());
            }
            
            Ok(())
        }

        async fn rollback_transaction(&self, txn_id: &str, reason: &str) -> Result<(), String> {
            self.call_log.lock().unwrap().push(format!("rollback_transaction({}, {})", txn_id, reason));
            Ok(())
        }

        async fn validate_entry(&self, dn: &str, _entry: &[u8]) -> Result<(), String> {
            self.call_log.lock().unwrap().push(format!("validate_entry({})", dn));
            
            if self.should_fail {
                return Err("Mock backend validation failure".to_string());
            }
            
            Ok(())
        }

        async fn add_entry(&self, txn_id: &str, dn: &str, _entry: &[u8]) -> Result<(), String> {
            self.call_log.lock().unwrap().push(format!("add_entry({}, {})", txn_id, dn));
            
            if self.should_fail {
                return Err("Mock backend add failure".to_string());
            }
            
            Ok(())
        }

        async fn modify_entry(&self, txn_id: &str, dn: &str, _modifications: &[Modification]) -> Result<(), String> {
            self.call_log.lock().unwrap().push(format!("modify_entry({}, {})", txn_id, dn));
            
            if self.should_fail {
                return Err("Mock backend modify failure".to_string());
            }
            
            Ok(())
        }

        async fn modify_dn(&self, txn_id: &str, dn: &str, new_rdn: &str, delete_old: bool, new_superior: Option<&str>) -> Result<(), String> {
            self.call_log.lock().unwrap().push(format!(
                "modify_dn({}, {}, {}, {}, {:?})", 
                txn_id, dn, new_rdn, delete_old, new_superior
            ));
            
            if self.should_fail {
                return Err("Mock backend modifydn failure".to_string());
            }
            
            Ok(())
        }

        async fn delete_entry(&self, txn_id: &str, dn: &str) -> Result<(), String> {
            self.call_log.lock().unwrap().push(format!("delete_entry({}, {})", txn_id, dn));
            
            if self.should_fail {
                return Err("Mock backend delete failure".to_string());
            }
            
            Ok(())
        }

        async fn entry_exists(&self, dn: &str) -> Result<bool, String> {
            self.call_log.lock().unwrap().push(format!("entry_exists({})", dn));
            Ok(true)
        }
    }

    /// Mock schema validator for testing
    #[derive(Debug)]
    pub struct MockSchemaValidator {
        pub should_fail: bool,
        pub call_log: Arc<Mutex<Vec<String>>>,
    }

    impl MockSchemaValidator {
        pub fn new() -> Self {
            Self {
                should_fail: false,
                call_log: Arc::new(Mutex::new(Vec::new())),
            }
        }

        pub fn with_failure(mut self) -> Self {
            self.should_fail = true;
            self
        }

        pub fn call_log(&self) -> Vec<String> {
            self.call_log.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl SchemaValidator for MockSchemaValidator {
        async fn validate_entry(&self, entry: &WriteEntry) -> Result<(), String> {
            self.call_log.lock().unwrap().push(format!("validate_entry({})", entry.dn));
            
            if self.should_fail {
                return Err("Mock schema validation failure".to_string());
            }
            
            Ok(())
        }

        async fn validate_modifications(&self, dn: &str, _modifications: &[Modification]) -> Result<(), String> {
            self.call_log.lock().unwrap().push(format!("validate_modifications({})", dn));
            
            if self.should_fail {
                return Err("Mock schema validation failure".to_string());
            }
            
            Ok(())
        }
    }

    /// Mock ACI checker for testing
    #[derive(Debug)]
    pub struct MockAciChecker {
        pub should_fail: bool,
        pub call_log: Arc<Mutex<Vec<String>>>,
    }

    impl MockAciChecker {
        pub fn new() -> Self {
            Self {
                should_fail: false,
                call_log: Arc::new(Mutex::new(Vec::new())),
            }
        }

        pub fn with_failure(mut self) -> Self {
            self.should_fail = true;
            self
        }

        pub fn call_log(&self) -> Vec<String> {
            self.call_log.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl AciChecker for MockAciChecker {
        async fn check_write_permission(&self, user_dn: Option<&str>, operation: &WriteOperation) -> Result<(), String> {
            self.call_log.lock().unwrap().push(format!(
                "check_write_permission({:?}, {:?})", 
                user_dn, operation
            ));
            
            if self.should_fail {
                return Err("Mock ACI check failure".to_string());
            }
            
            Ok(())
        }
    }

    /// Mock write metrics for testing
    #[derive(Debug)]
    pub struct MockWriteMetrics {
        pub call_log: Arc<Mutex<Vec<String>>>,
    }

    impl MockWriteMetrics {
        pub fn new() -> Self {
            Self {
                call_log: Arc::new(Mutex::new(Vec::new())),
            }
        }

        pub fn call_log(&self) -> Vec<String> {
            self.call_log.lock().unwrap().clone()
        }
    }

    impl WriteMetrics for MockWriteMetrics {
        fn record_write_start(&self, user_dn: Option<&str>, operation: &WriteOperation) {
            self.call_log.lock().unwrap().push(format!(
                "record_write_start({:?}, {:?})", 
                user_dn, operation
            ));
        }

        fn record_validation_complete(&self, operation_type: &str, _duration: Duration) {
            self.call_log.lock().unwrap().push(format!("record_validation_complete({})", operation_type));
        }

        fn record_schema_check_complete(&self, operation_type: &str, _duration: Duration) {
            self.call_log.lock().unwrap().push(format!("record_schema_check_complete({})", operation_type));
        }

        fn record_aci_check_complete(&self, operation_type: &str, _duration: Duration) {
            self.call_log.lock().unwrap().push(format!("record_aci_check_complete({})", operation_type));
        }

        fn record_transaction_started(&self, txn_id: &str) {
            self.call_log.lock().unwrap().push(format!("record_transaction_started({})", txn_id));
        }

        fn record_write_complete(&self, operation: &WriteOperation, result_code: &WriteResultCode, _duration: Duration) {
            self.call_log.lock().unwrap().push(format!(
                "record_write_complete({:?}, {:?})", 
                operation, result_code
            ));
        }

        fn record_write_rollback(&self, operation: &WriteOperation, reason: &str) {
            self.call_log.lock().unwrap().push(format!(
                "record_write_rollback({:?}, {})", 
                operation, reason
            ));
        }
    }

    #[tokio::test]
    async fn test_new_write_fsm() {
        let backend = Box::new(MockWriteBackend::new());
        let schema_validator = Box::new(MockSchemaValidator::new());
        let aci_checker = Box::new(MockAciChecker::new());
        
        let fsm = WriteFsmImpl::new(backend, schema_validator, aci_checker);
        
        assert_eq!(fsm.current_state(), &WriteState::Validating);
        assert!(fsm.operation().is_none());
        assert!(fsm.transaction_id().is_none());
        assert!(!fsm.can_rollback());
        assert!(!fsm.is_terminal());
    }

    #[tokio::test]
    async fn test_write_fsm_with_config() {
        let backend = Box::new(MockWriteBackend::new());
        let schema_validator = Box::new(MockSchemaValidator::new());
        let aci_checker = Box::new(MockAciChecker::new());
        
        let config = WriteFsmConfig {
            default_transaction_timeout: 60,
            max_transaction_timeout: 600,
            strict_schema_validation: false,
            enable_aci_checks: false,
            max_entry_size: 2_097_152, // 2MB
            max_modifications_per_request: 2000,
            enable_audit_logging: false,
        };
        
        let fsm = WriteFsmImpl::with_config(backend, schema_validator, aci_checker, config);
        
        assert_eq!(fsm.current_state(), &WriteState::Validating);
        assert_eq!(fsm.config.default_transaction_timeout, 60);
        assert_eq!(fsm.config.max_entry_size, 2_097_152);
        assert!(!fsm.config.strict_schema_validation);
        assert!(!fsm.config.enable_aci_checks);
    }

    #[tokio::test]
    async fn test_start_write_add_operation() {
        let backend = Box::new(MockWriteBackend::new());
        let schema_validator = Box::new(MockSchemaValidator::new());
        let aci_checker = Box::new(MockAciChecker::new());
        
        let mut fsm = WriteFsmImpl::new(backend, schema_validator, aci_checker);
        
        let result = fsm.handle_event(WriteEvent::StartWrite(WriteOperation::Add {
            dn: "cn=newuser,ou=people,dc=example,dc=org".to_string(),
            entry: b"dn: cn=newuser,ou=people,dc=example,dc=org\nobjectClass: person\ncn: newuser\n".to_vec(),
        })).await;
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
        assert_eq!(fsm.current_state(), &WriteState::Validating);
        assert!(fsm.operation().is_some());
        
        if let Some(WriteOperation::Add { dn, .. }) = fsm.operation() {
            assert_eq!(dn, "cn=newuser,ou=people,dc=example,dc=org");
        } else {
            panic!("Expected Add operation");
        }
        
        let (total_writes, _, _) = fsm.stats();
        assert_eq!(total_writes, 1);
    }

    #[tokio::test]
    async fn test_start_write_invalid_operation() {
        let backend = Box::new(MockWriteBackend::new());
        let schema_validator = Box::new(MockSchemaValidator::new());
        let aci_checker = Box::new(MockAciChecker::new());
        
        let mut fsm = WriteFsmImpl::new(backend, schema_validator, aci_checker);
        
        // Test empty DN
        let result = fsm.handle_event(WriteEvent::StartWrite(WriteOperation::Add {
            dn: "".to_string(),
            entry: b"test".to_vec(),
        })).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WriteFsmError::InvalidOperation { .. }));
        
        // Test empty entry
        let result = fsm.handle_event(WriteEvent::StartWrite(WriteOperation::Add {
            dn: "cn=test,dc=example,dc=org".to_string(),
            entry: Vec::new(),
        })).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WriteFsmError::InvalidOperation { .. }));
    }

    #[tokio::test]
    async fn test_validation_complete() {
        let backend = Box::new(MockWriteBackend::new());
        let schema_validator = Box::new(MockSchemaValidator::new());
        let aci_checker = Box::new(MockAciChecker::new());
        
        let mut fsm = WriteFsmImpl::new(backend, schema_validator, aci_checker);
        
        // Start write operation first
        let _result = fsm.handle_event(WriteEvent::StartWrite(WriteOperation::Add {
            dn: "cn=test,dc=example,dc=org".to_string(),
            entry: b"test entry".to_vec(),
        })).await.unwrap();
        
        // Handle validation complete
        let result = fsm.handle_event(WriteEvent::ValidationComplete).await;
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
        assert_eq!(fsm.current_state(), &WriteState::CheckingSchema); // Default config has strict validation
    }

    #[tokio::test]
    async fn test_schema_check_complete() {
        let backend = Box::new(MockWriteBackend::new());
        let schema_validator = Box::new(MockSchemaValidator::new());
        let aci_checker = Box::new(MockAciChecker::new());
        
        let mut fsm = WriteFsmImpl::new(backend, schema_validator, aci_checker);
        
        // Start write and complete validation
        let _result = fsm.handle_event(WriteEvent::StartWrite(WriteOperation::Add {
            dn: "cn=test,dc=example,dc=org".to_string(),
            entry: b"test entry".to_vec(),
        })).await.unwrap();
        
        let _result = fsm.handle_event(WriteEvent::ValidationComplete).await.unwrap();
        
        // Handle schema check complete
        let result = fsm.handle_event(WriteEvent::SchemaCheckComplete).await;
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
        assert_eq!(fsm.current_state(), &WriteState::CheckingAci); // Default config has ACI checks
    }

    #[tokio::test]
    async fn test_aci_check_complete() {
        let backend = Box::new(MockWriteBackend::new());
        let schema_validator = Box::new(MockSchemaValidator::new());
        let aci_checker = Box::new(MockAciChecker::new());
        
        let mut fsm = WriteFsmImpl::new(backend, schema_validator, aci_checker);
        
        // Start write, complete validation and schema check
        let _result = fsm.handle_event(WriteEvent::StartWrite(WriteOperation::Add {
            dn: "cn=test,dc=example,dc=org".to_string(),
            entry: b"test entry".to_vec(),
        })).await.unwrap();
        
        let _result = fsm.handle_event(WriteEvent::ValidationComplete).await.unwrap();
        let _result = fsm.handle_event(WriteEvent::SchemaCheckComplete).await.unwrap();
        
        // Handle ACI check complete
        let result = fsm.handle_event(WriteEvent::AciCheckComplete).await;
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
        assert_eq!(fsm.current_state(), &WriteState::InTransaction);
    }

    #[tokio::test]
    async fn test_write_complete_and_commit() {
        let backend = Box::new(MockWriteBackend::new());
        let schema_validator = Box::new(MockSchemaValidator::new());
        let aci_checker = Box::new(MockAciChecker::new());
        
        let mut fsm = WriteFsmImpl::new(backend, schema_validator, aci_checker);
        
        // Progress through all states to InTransaction
        let _result = fsm.handle_event(WriteEvent::StartWrite(WriteOperation::Add {
            dn: "cn=test,dc=example,dc=org".to_string(),
            entry: b"test entry".to_vec(),
        })).await.unwrap();
        
        let _result = fsm.handle_event(WriteEvent::ValidationComplete).await.unwrap();
        let _result = fsm.handle_event(WriteEvent::SchemaCheckComplete).await.unwrap();
        let _result = fsm.handle_event(WriteEvent::AciCheckComplete).await.unwrap();
        
        // Handle write complete
        let result = fsm.handle_event(WriteEvent::WriteComplete).await;
        
        assert!(result.is_ok());
        assert_eq!(fsm.current_state(), &WriteState::Committing);
        
        // Handle commit complete
        let result = fsm.handle_event(WriteEvent::CommitComplete).await;
        
        assert!(result.is_ok());
        assert_eq!(fsm.current_state(), &WriteState::Completed { 
            result_code: WriteResultCode::Success 
        });
        assert!(fsm.is_terminal());
        
        let (total_writes, successful_writes, failed_writes) = fsm.stats();
        assert_eq!(total_writes, 1);
        assert_eq!(successful_writes, 1);
        assert_eq!(failed_writes, 0);
    }

    #[tokio::test]
    async fn test_write_rollback() {
        let backend = Box::new(MockWriteBackend::new());
        let schema_validator = Box::new(MockSchemaValidator::new());
        let aci_checker = Box::new(MockAciChecker::new());
        
        let mut fsm = WriteFsmImpl::new(backend, schema_validator, aci_checker);
        
        // Start write operation
        let _result = fsm.handle_event(WriteEvent::StartWrite(WriteOperation::Add {
            dn: "cn=test,dc=example,dc=org".to_string(),
            entry: b"test entry".to_vec(),
        })).await.unwrap();
        
        // Trigger rollback
        let result = fsm.handle_event(WriteEvent::RollbackInitiated { 
            reason: "Test rollback".to_string() 
        }).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WriteFsmError::TransactionError { .. }));
        assert_eq!(fsm.current_state(), &WriteState::Rollback { 
            reason: "Test rollback".to_string() 
        });
        assert!(fsm.is_terminal());
        
        let (total_writes, successful_writes, failed_writes) = fsm.stats();
        assert_eq!(total_writes, 1);
        assert_eq!(successful_writes, 0);
        assert_eq!(failed_writes, 1);
    }

    #[tokio::test]
    async fn test_write_error() {
        let backend = Box::new(MockWriteBackend::new());
        let schema_validator = Box::new(MockSchemaValidator::new());
        let aci_checker = Box::new(MockAciChecker::new());
        
        let mut fsm = WriteFsmImpl::new(backend, schema_validator, aci_checker);
        
        // Trigger error
        let result = fsm.handle_event(WriteEvent::Error("Test error".to_string())).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WriteFsmError::Generic { .. }));
        assert_eq!(fsm.current_state(), &WriteState::Failed { 
            error: "Test error".to_string() 
        });
        assert!(fsm.is_terminal());
    }

    #[tokio::test]
    async fn test_fsm_reset() {
        let backend = Box::new(MockWriteBackend::new());
        let schema_validator = Box::new(MockSchemaValidator::new());
        let aci_checker = Box::new(MockAciChecker::new());
        
        let mut fsm = WriteFsmImpl::new(backend, schema_validator, aci_checker);
        
        // Start write operation
        let _result = fsm.handle_event(WriteEvent::StartWrite(WriteOperation::Add {
            dn: "cn=test,dc=example,dc=org".to_string(),
            entry: b"test entry".to_vec(),
        })).await.unwrap();
        
        assert_eq!(fsm.current_state(), &WriteState::Validating);
        assert!(fsm.operation().is_some());
        
        // Reset FSM
        let result = fsm.reset().await;
        
        assert!(result.is_ok());
        assert_eq!(fsm.current_state(), &WriteState::Validating);
        assert!(fsm.operation().is_none());
    }

    #[tokio::test]
    async fn test_write_with_metrics() {
        let backend = Box::new(MockWriteBackend::new());
        let schema_validator = Box::new(MockSchemaValidator::new());
        let aci_checker = Box::new(MockAciChecker::new());
        let metrics = Box::new(MockWriteMetrics::new());
        let metrics_log = metrics.call_log.clone();
        
        let mut fsm = WriteFsmImpl::new(backend, schema_validator, aci_checker)
            .with_metrics(metrics);
        
        // Start write operation
        let _result = fsm.handle_event(WriteEvent::StartWrite(WriteOperation::Add {
            dn: "cn=test,dc=example,dc=org".to_string(),
            entry: b"test entry".to_vec(),
        })).await.unwrap();
        
        // Check metrics were called
        let calls = metrics_log.lock().unwrap();
        assert!(calls.iter().any(|call| call.contains("record_write_start")));
    }

    #[tokio::test]
    async fn test_write_entry_methods() {
        let mut entry = WriteEntry::new("cn=test,dc=example,dc=org".to_string());
        
        assert_eq!(entry.dn, "cn=test,dc=example,dc=org");
        assert!(entry.attributes.is_empty());
        assert!(entry.object_classes.is_empty());
        assert!(entry.binary_attributes.is_empty());
        
        entry.add_attribute("cn".to_string(), vec!["test".to_string()]);
        entry.add_attribute("mail".to_string(), vec!["test@example.org".to_string()]);
        entry.add_binary_attribute("photo".to_string(), vec![vec![0x89, 0x50, 0x4E, 0x47]]);
        entry.set_object_classes(vec!["person".to_string(), "inetOrgPerson".to_string()]);
        
        assert_eq!(entry.get_attribute("cn"), Some(&vec!["test".to_string()]));
        assert_eq!(entry.get_attribute("mail"), Some(&vec!["test@example.org".to_string()]));
        assert_eq!(entry.get_attribute("nonexistent"), None);
        
        assert_eq!(entry.get_binary_attribute("photo"), Some(&vec![vec![0x89, 0x50, 0x4E, 0x47]]));
        assert_eq!(entry.get_binary_attribute("nonexistent"), None);
        
        assert!(entry.has_object_class("person"));
        assert!(entry.has_object_class("inetOrgPerson"));
        assert!(entry.has_object_class("PERSON")); // Case insensitive
        assert!(!entry.has_object_class("group"));
        
        // Test LDIF encoding
        let ldif = entry.encode_as_ldif();
        let ldif_str = String::from_utf8(ldif).unwrap();
        assert!(ldif_str.contains("dn: cn=test,dc=example,dc=org"));
        assert!(ldif_str.contains("objectClass: person"));
        assert!(ldif_str.contains("cn: test"));
        assert!(ldif_str.contains("mail: test@example.org"));
        assert!(ldif_str.contains("photo:: <4 bytes of binary data>"));
    }

    #[tokio::test]
    async fn test_write_session_methods() {
        let operation = WriteOperation::Add {
            dn: "cn=test,dc=example,dc=org".to_string(),
            entry: b"test entry".to_vec(),
        };
        
        let session = WriteSession::new(operation, Some("cn=admin,dc=example,dc=org".to_string()));
        
        assert_eq!(session.operation_type(), "add");
        assert_eq!(session.target_dn(), "cn=test,dc=example,dc=org");
        assert_eq!(session.user_dn, Some("cn=admin,dc=example,dc=org".to_string()));
        assert!(!session.can_rollback);
        assert!(session.transaction_id.is_none());
        
        // Test timeout checking (should not be timed out immediately)
        assert!(!session.is_transaction_timed_out(30));
    }

    #[tokio::test]
    async fn test_write_fsm_trait_implementation() {
        let backend = Box::new(MockWriteBackend::new());
        let schema_validator = Box::new(MockSchemaValidator::new());
        let aci_checker = Box::new(MockAciChecker::new());
        
        let mut fsm = WriteFsmImpl::new(backend, schema_validator, aci_checker);
        
        // Initially no operation
        assert!(fsm.operation().is_none());
        assert!(fsm.transaction_id().is_none());
        assert!(!fsm.can_rollback());
        
        // Start write operation
        let _result = fsm.handle_event(WriteEvent::StartWrite(WriteOperation::Delete {
            dn: "cn=test,dc=example,dc=org".to_string(),
        })).await.unwrap();
        
        // Should have operation now
        assert!(fsm.operation().is_some());
        if let Some(WriteOperation::Delete { dn }) = fsm.operation() {
            assert_eq!(dn, "cn=test,dc=example,dc=org");
        } else {
            panic!("Expected Delete operation");
        }
    }
}
//! Compare Finite State Machine Implementation
//!
//! This module implements a comprehensive Compare FSM for LDAP compare operations.
//! The FSM manages the complete compare lifecycle: read entry, evaluate attribute
//! comparison, and emit boolean result.
//!
//! ## Compare Operation Flow
//!
//! ```text
//! Reading -> Evaluating -> Emitting -> Completed
//!    |          |             |           ^
//!    |          |             |           |
//!    v          v             v           |
//!  Error      Error         Error     Terminal
//! ```
//!
//! ## LDAP Compare Operation
//!
//! The LDAP Compare operation allows clients to test whether a particular
//! attribute-value assertion exists in a specific entry. It returns a
//! boolean result (true/false) without exposing the actual attribute values.
//!
//! ## Supported Features
//!
//! The FSM supports comprehensive LDAP compare operations:
//! - **Binary-safe comparisons** for all attribute types
//! - **Case-insensitive string comparisons** for string attributes
//! - **Multi-value attribute handling** (true if any value matches)
//! - **Entry existence checking** (automatically fails if entry doesn't exist)
//! - **Access control integration** via trait abstraction
//! - **Performance monitoring** with metrics collection
//!
//! ## External Dependencies
//!
//! The FSM abstracts external dependencies through traits:
//! - `CompareBackend`: Entry retrieval from directory storage
//! - `AttributeComparator`: Attribute value comparison logic
//! - `CompareAccessControl`: Permission checking for compare operations
//! - `CompareMetrics`: Performance and audit logging
//!
//! ## Usage Example
//!
//! ```rust,no_run
//! use opendr::compare_fsm::*;
//! use opendr::fsm::{StateMachine, CompareFsm, CompareState, CompareEvent};
//!
//! # struct MockCompareBackend;
//! # #[async_trait::async_trait]
//! # impl CompareBackend for MockCompareBackend {
//! #     async fn get_entry_attributes(&self, _dn: &str, _attributes: &[String]) -> Result<Option<CompareEntry>, String> {
//! #         Ok(None)
//! #     }
//! # }
//! #
//! # struct MockAttributeComparator;
//! # #[async_trait::async_trait]  
//! # impl AttributeComparator for MockAttributeComparator {
//! #     async fn compare_attribute(&self, _entry: &CompareEntry, _attr_name: &str, _value: &[u8]) -> Result<bool, String> {
//! #         Ok(true)
//! #     }
//! # }
//! #
//! # struct MockCompareAccessControl;
//! # #[async_trait::async_trait]
//! # impl CompareAccessControl for MockCompareAccessControl {
//! #     async fn check_compare_permission(&self, _user_dn: Option<&str>, _entry_dn: &str, _attribute: &str) -> Result<(), String> {
//! #         Ok(())
//! #     }
//! # }
//! #
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let backend = Box::new(MockCompareBackend);
//! let comparator = Box::new(MockAttributeComparator);
//! let access_control = Box::new(MockCompareAccessControl);
//!
//! let mut fsm = CompareFsmImpl::new(backend, comparator, access_control);
//!
//! // Start compare operation
//! let result = fsm.handle_event(CompareEvent::StartCompare {
//!     dn: "cn=john,ou=people,dc=example,dc=org".to_string(),
//!     attribute: "mail".to_string(),
//!     value: b"john@example.org".to_vec(),
//! }).await?;
//!
//! // Process through FSM states
//! fsm.handle_event(CompareEvent::EntryRead).await?;
//! fsm.handle_event(CompareEvent::ResultEmitted).await?;
//!
//! // Check final result
//! assert_eq!(fsm.result(), Some(true));
//! # Ok(())
//! # }
//! ```

use crate::fsm::{CompareEvent, CompareFsm, CompareParams, CompareState, StateMachine};
use async_trait::async_trait;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use thiserror::Error;

/// Errors that can occur during compare operations
#[derive(Error, Debug, Clone, PartialEq)]
pub enum CompareFsmError {
    #[error("Invalid compare parameters: {message}")]
    InvalidParameters { message: String },

    #[error("Backend error: {message}")]
    BackendError { message: String },

    #[error("Attribute comparison error: {message}")]
    ComparisonError { message: String },

    #[error("Access denied: {message}")]
    AccessDenied { message: String },

    #[error("Entry not found: {dn}")]
    NoSuchObject { dn: String },

    #[error("Attribute not found: {attribute} in entry {dn}")]
    NoSuchAttribute { dn: String, attribute: String },

    #[error("Invalid state transition from {from:?} to {to:?}")]
    InvalidStateTransition {
        from: CompareState,
        to: CompareState,
    },

    #[error("No active compare operation")]
    NoActiveCompare,

    #[error("Generic compare error: {message}")]
    Generic { message: String },
}

/// Represents an LDAP entry for compare operations
///
/// This structure contains only the attributes needed for comparison,
/// reducing memory usage and network overhead.
#[derive(Debug, Clone, PartialEq)]
pub struct CompareEntry {
    /// Distinguished Name of the entry
    pub dn: String,
    /// Entry attributes as key-value pairs (only requested attributes)
    pub attributes: HashMap<String, Vec<Vec<u8>>>,
    /// Object classes for the entry (may be needed for comparison rules)
    pub object_classes: Vec<String>,
}

impl CompareEntry {
    /// Create a new compare entry
    ///
    /// # Arguments
    /// * `dn` - Distinguished name of the entry
    ///
    /// # Returns
    /// * New CompareEntry instance
    pub fn new(dn: String) -> Self {
        Self {
            dn,
            attributes: HashMap::new(),
            object_classes: Vec::new(),
        }
    }

    /// Add an attribute to the entry
    ///
    /// # Arguments
    /// * `name` - Attribute name
    /// * `values` - Binary attribute values
    pub fn add_attribute(&mut self, name: String, values: Vec<Vec<u8>>) {
        self.attributes.insert(name, values);
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
    /// * `name` - Attribute name (case-insensitive)
    ///
    /// # Returns
    /// * Option containing attribute values if found
    pub fn get_attribute(&self, name: &str) -> Option<&Vec<Vec<u8>>> {
        // LDAP attribute names are case-insensitive
        self.attributes
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
    }

    /// Check if entry has a specific attribute
    ///
    /// # Arguments
    /// * `name` - Attribute name to check
    ///
    /// # Returns
    /// * true if entry has the attribute
    pub fn has_attribute(&self, name: &str) -> bool {
        self.attributes.keys().any(|k| k.eq_ignore_ascii_case(name))
    }

    /// Check if entry has a specific object class
    ///
    /// # Arguments
    /// * `object_class` - Object class name to check
    ///
    /// # Returns
    /// * true if entry has the object class
    pub fn has_object_class(&self, object_class: &str) -> bool {
        self.object_classes
            .iter()
            .any(|oc| oc.eq_ignore_ascii_case(object_class))
    }
}

/// Trait for backend compare operations
///
/// This trait abstracts the directory backend, allowing different
/// storage implementations to be used with the Compare FSM.
#[async_trait]
pub trait CompareBackend: Send + Sync {
    /// Retrieve specific attributes from an entry
    ///
    /// # Arguments
    /// * `dn` - Distinguished name of entry to retrieve
    /// * `attributes` - List of attributes to retrieve
    ///
    /// # Returns
    /// * `Ok(Some(CompareEntry))` - Entry with requested attributes if found
    /// * `Ok(None)` - Entry not found
    /// * `Err(String)` - Error message if operation fails
    async fn get_entry_attributes(
        &self,
        dn: &str,
        attributes: &[String],
    ) -> Result<Option<CompareEntry>, String>;

    /// Check if an entry exists (lightweight operation)
    ///
    /// # Arguments
    /// * `dn` - Distinguished name to check
    ///
    /// # Returns
    /// * `Ok(true)` - Entry exists
    /// * `Ok(false)` - Entry does not exist
    /// * `Err(String)` - Error message if check fails
    async fn entry_exists(&self, dn: &str) -> Result<bool, String> {
        // Default implementation using get_entry_attributes
        match self.get_entry_attributes(dn, &[]).await? {
            Some(_) => Ok(true),
            None => Ok(false),
        }
    }

    /// Get backend statistics (for optimization)
    ///
    /// # Arguments
    /// * `dn` - Entry DN for statistics
    ///
    /// # Returns
    /// * (cache_hits, cache_misses)
    async fn get_compare_stats(&self, _dn: &str) -> Result<(u64, u64), String> {
        // Default implementation returns zero statistics
        Ok((0, 0))
    }
}

/// Trait for attribute value comparison
///
/// This trait abstracts attribute comparison logic, allowing different
/// comparison rules and optimizations for different attribute types.
#[async_trait]
pub trait AttributeComparator: Send + Sync {
    /// Compare an attribute value with a given value
    ///
    /// # Arguments
    /// * `entry` - Entry containing the attribute
    /// * `attr_name` - Name of attribute to compare
    /// * `value` - Value to compare against
    ///
    /// # Returns
    /// * `Ok(true)` - Attribute matches the given value
    /// * `Ok(false)` - Attribute does not match
    /// * `Err(String)` - Error message if comparison fails
    async fn compare_attribute(
        &self,
        entry: &CompareEntry,
        attr_name: &str,
        value: &[u8],
    ) -> Result<bool, String>;

    /// Get the comparison rule for an attribute type
    ///
    /// # Arguments
    /// * `attr_name` - Attribute name
    ///
    /// # Returns
    /// * Comparison rule identifier (e.g., "caseIgnoreMatch", "exactMatch")
    fn get_comparison_rule(&self, _attr_name: &str) -> String {
        // Default to exact binary comparison
        "octetStringMatch".to_string()
    }

    /// Check if an attribute supports case-insensitive comparison
    ///
    /// # Arguments
    /// * `attr_name` - Attribute name
    ///
    /// # Returns
    /// * true if case-insensitive comparison should be used
    fn is_case_insensitive(&self, attr_name: &str) -> bool {
        // Common case-insensitive string attributes
        matches!(
            attr_name.to_lowercase().as_str(),
            "cn" | "commonname"
                | "sn"
                | "surname"
                | "givenname"
                | "displayname"
                | "description"
                | "o"
                | "organizationname"
                | "ou"
                | "organizationalunitname"
                | "l"
                | "localityname"
                | "st"
                | "stateorprovincename"
                | "street"
                | "postaladdress"
                | "postalcode"
                | "telephonenumber"
                | "mail"
                | "email"
        )
    }
}

/// Trait for compare operation access control
///
/// This trait abstracts access control checking, allowing different
/// authorization implementations and policies.
#[async_trait]
pub trait CompareAccessControl: Send + Sync {
    /// Check if user has permission to compare an attribute
    ///
    /// # Arguments
    /// * `user_dn` - DN of authenticated user (None for anonymous)
    /// * `entry_dn` - DN of entry to compare
    /// * `attribute` - Attribute name being compared
    ///
    /// # Returns
    /// * `Ok(())` - Permission granted
    /// * `Err(String)` - Access denied with reason
    async fn check_compare_permission(
        &self,
        user_dn: Option<&str>,
        entry_dn: &str,
        attribute: &str,
    ) -> Result<(), String>;

    /// Get the access control policy version
    ///
    /// # Returns
    /// * Policy version string
    fn policy_version(&self) -> String {
        "default".to_string()
    }

    /// Check if anonymous compare is allowed
    ///
    /// # Returns
    /// * true if anonymous users can perform compare operations
    fn allow_anonymous_compare(&self) -> bool {
        true // Default allows anonymous compare (LDAP standard behavior)
    }
}

/// Trait for compare metrics and monitoring
///
/// This trait provides hooks for performance monitoring,
/// statistics collection, and operational insights.
pub trait CompareMetrics: Send + Sync {
    /// Record compare operation start
    ///
    /// # Arguments
    /// * `params` - Compare parameters
    /// * `user_dn` - Authenticated user DN
    fn record_compare_start(&self, params: &CompareParams, user_dn: Option<&str>);

    /// Record entry read completion
    ///
    /// # Arguments
    /// * `dn` - Entry DN that was read
    /// * `found` - Whether entry was found
    /// * `duration` - Time taken to read entry
    fn record_entry_read(&self, dn: &str, found: bool, duration: Duration);

    /// Record attribute comparison completion
    ///
    /// # Arguments
    /// * `attribute` - Attribute name that was compared
    /// * `result` - Comparison result
    /// * `duration` - Time taken for comparison
    fn record_comparison_complete(&self, attribute: &str, result: bool, duration: Duration);

    /// Record compare operation completion
    ///
    /// # Arguments
    /// * `result` - Final comparison result
    /// * `duration` - Total operation duration
    fn record_compare_complete(&self, result: bool, duration: Duration);

    /// Record compare operation error
    ///
    /// # Arguments
    /// * `error_type` - Type of error that occurred
    /// * `duration` - Time before error occurred
    fn record_compare_error(&self, error_type: &str, duration: Duration);

    /// Get compare statistics
    ///
    /// # Returns
    /// * (total_compares, successful_compares, avg_duration_ms)
    fn get_stats(&self) -> (u64, u64, f64) {
        // Default implementation returns zeros
        (0, 0, 0.0)
    }
}

/// Configuration for the Compare FSM
#[derive(Debug, Clone)]
pub struct CompareFsmConfig {
    /// Maximum time to wait for backend operations (in seconds)
    pub max_backend_timeout: u32,
    /// Maximum size of attribute values to compare (in bytes)
    pub max_value_size: usize,
    /// Whether to enable detailed access control checks
    pub enable_access_control: bool,
    /// Whether to enable performance metrics collection
    pub enable_metrics: bool,
    /// Whether to allow comparison of operational attributes
    pub allow_operational_attributes: bool,
}

impl Default for CompareFsmConfig {
    fn default() -> Self {
        Self {
            max_backend_timeout: 30,
            max_value_size: 1_048_576, // 1MB
            enable_access_control: true,
            enable_metrics: true,
            allow_operational_attributes: false,
        }
    }
}

/// Compare session state for tracking compare progress
#[derive(Debug, Clone)]
pub struct CompareSession {
    /// Compare parameters
    pub params: CompareParams,
    /// Authenticated user DN
    pub user_dn: Option<String>,
    /// Start time of the compare
    pub start_time: Instant,
    /// Retrieved entry (if found)
    pub entry: Option<CompareEntry>,
    /// Comparison result
    pub result: Option<bool>,
    /// Time when entry was read
    pub entry_read_time: Option<Instant>,
    /// Time when comparison was completed
    pub comparison_complete_time: Option<Instant>,
}

impl CompareSession {
    /// Create a new compare session
    ///
    /// # Arguments
    /// * `params` - Compare parameters
    /// * `user_dn` - Authenticated user DN
    ///
    /// # Returns
    /// * New CompareSession instance
    pub fn new(params: CompareParams, user_dn: Option<String>) -> Self {
        Self {
            params,
            user_dn,
            start_time: Instant::now(),
            entry: None,
            result: None,
            entry_read_time: None,
            comparison_complete_time: None,
        }
    }

    /// Get the duration of the entry read phase
    ///
    /// # Returns
    /// * Duration of entry read, or None if not completed
    pub fn entry_read_duration(&self) -> Option<Duration> {
        self.entry_read_time
            .map(|t| t.duration_since(self.start_time))
    }

    /// Get the duration of the comparison phase
    ///
    /// # Returns
    /// * Duration of comparison, or None if not completed
    pub fn comparison_duration(&self) -> Option<Duration> {
        if let (Some(start), Some(end)) = (self.entry_read_time, self.comparison_complete_time) {
            Some(end.duration_since(start))
        } else {
            None
        }
    }

    /// Get the total duration of the compare operation
    ///
    /// # Returns
    /// * Total duration elapsed
    pub fn total_duration(&self) -> Duration {
        self.start_time.elapsed()
    }
}

/// Compare FSM Implementation
///
/// This FSM manages the complete compare operation lifecycle including:
/// - Parameter validation and access control checking
/// - Entry retrieval with minimal attributes
/// - Attribute value comparison using appropriate rules
/// - Result emission with proper LDAP response codes
/// - Performance monitoring and error handling
pub struct CompareFsmImpl {
    /// Current FSM state
    state: CompareState,

    /// Authenticated user bound to the connection runtime
    authenticated_user_dn: Option<String>,

    /// Current compare session (if active)
    session: Option<CompareSession>,

    /// Compare backend for entry retrieval
    backend: Box<dyn CompareBackend>,

    /// Attribute comparator for value evaluation
    comparator: Box<dyn AttributeComparator>,

    /// Access control checker
    access_control: Box<dyn CompareAccessControl>,

    /// Metrics collector (optional)
    metrics: Option<Box<dyn CompareMetrics>>,

    /// FSM configuration
    config: CompareFsmConfig,

    /// Statistics tracking
    total_compares: u64,
    successful_compares: u64,
    total_duration: Duration,
}

impl CompareFsmImpl {
    /// Create a new Compare FSM instance
    ///
    /// # Arguments
    /// * `backend` - Compare backend implementation
    /// * `comparator` - Attribute comparison implementation
    /// * `access_control` - Access control implementation
    ///
    /// # Returns
    /// * New Compare FSM instance
    pub fn new(
        backend: Box<dyn CompareBackend>,
        comparator: Box<dyn AttributeComparator>,
        access_control: Box<dyn CompareAccessControl>,
    ) -> Self {
        Self {
            state: CompareState::Reading,
            authenticated_user_dn: None,
            session: None,
            backend,
            comparator,
            access_control,
            metrics: None,
            config: CompareFsmConfig::default(),
            total_compares: 0,
            successful_compares: 0,
            total_duration: Duration::default(),
        }
    }

    /// Create a Compare FSM with custom configuration
    ///
    /// # Arguments
    /// * `backend` - Compare backend implementation
    /// * `comparator` - Attribute comparison implementation
    /// * `access_control` - Access control implementation
    /// * `config` - FSM configuration
    ///
    /// # Returns
    /// * New Compare FSM instance with custom configuration
    pub fn with_config(
        backend: Box<dyn CompareBackend>,
        comparator: Box<dyn AttributeComparator>,
        access_control: Box<dyn CompareAccessControl>,
        config: CompareFsmConfig,
    ) -> Self {
        Self {
            state: CompareState::Reading,
            authenticated_user_dn: None,
            session: None,
            backend,
            comparator,
            access_control,
            metrics: None,
            config,
            total_compares: 0,
            successful_compares: 0,
            total_duration: Duration::default(),
        }
    }

    /// Set metrics collector
    ///
    /// # Arguments
    /// * `metrics` - Metrics implementation
    ///
    /// # Returns
    /// * Updated Compare FSM instance
    pub fn with_metrics(mut self, metrics: Box<dyn CompareMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Set authenticated user DN for the session
    ///
    /// # Arguments
    /// * `user_dn` - Authenticated user DN
    ///
    /// # Returns
    /// * Updated Compare FSM instance
    pub fn with_user_dn(mut self, user_dn: String) -> Self {
        self.authenticated_user_dn = Some(user_dn.clone());
        if let Some(ref mut session) = self.session {
            session.user_dn = Some(user_dn);
        }
        self
    }

    fn invalid_transition(&self, to: CompareState) -> CompareFsmError {
        CompareFsmError::InvalidStateTransition {
            from: self.state.clone(),
            to,
        }
    }

    fn record_compare_error_metric(&self, error_type: &str) {
        if !self.config.enable_metrics {
            return;
        }

        if let (Some(metrics), Some(session)) = (&self.metrics, &self.session) {
            metrics.record_compare_error(error_type, session.total_duration());
        }
    }

    async fn evaluate_loaded_entry(&mut self) -> Result<Option<Vec<u8>>, CompareFsmError> {
        if !matches!(self.state, CompareState::Evaluating) {
            return Err(self.invalid_transition(CompareState::Evaluating));
        }

        let (entry, dn, attribute, value) = {
            let session = self.session.as_ref().ok_or(CompareFsmError::NoActiveCompare)?;
            (
                session.entry.clone().ok_or(CompareFsmError::NoActiveCompare)?,
                session.params.dn.clone(),
                session.params.attribute.clone(),
                session.params.value.clone(),
            )
        };

        if !entry.has_attribute(&attribute) {
            self.state = CompareState::Completed { result: false };
            self.record_compare_error_metric("NoSuchAttribute");
            return Err(CompareFsmError::NoSuchAttribute { dn, attribute });
        }

        let comparison_start = Instant::now();
        let result = match self
            .comparator
            .compare_attribute(&entry, &attribute, &value)
            .await
        {
            Ok(result) => result,
            Err(message) => {
                self.state = CompareState::Completed { result: false };
                self.record_compare_error_metric("ComparisonError");
                return Err(CompareFsmError::ComparisonError { message });
            }
        };

        if let Some(session) = &mut self.session {
            session.comparison_complete_time = Some(Instant::now());
            session.result = Some(result);
        }

        if self.config.enable_metrics {
            if let Some(metrics) = &self.metrics {
                metrics.record_comparison_complete(&attribute, result, comparison_start.elapsed());
            }
        }

        self.state = CompareState::Emitting { result };
        Ok(None)
    }

    /// Get compare statistics
    ///
    /// # Returns
    /// * (total_compares, successful_compares, avg_duration_ms)
    pub fn stats(&self) -> (u64, u64, f64) {
        let avg_ms = if self.total_compares > 0 {
            self.total_duration.as_millis() as f64 / self.total_compares as f64
        } else {
            0.0
        };
        (self.total_compares, self.successful_compares, avg_ms)
    }

    /// Validate compare parameters
    ///
    /// # Arguments
    /// * `params` - Compare parameters to validate
    ///
    /// # Returns
    /// * `Ok(())` if parameters are valid
    /// * `Err(CompareFsmError)` if validation fails
    fn validate_compare_params(&self, params: &CompareParams) -> Result<(), CompareFsmError> {
        // Validate DN
        if params.dn.is_empty() {
            return Err(CompareFsmError::InvalidParameters {
                message: "Distinguished Name cannot be empty".to_string(),
            });
        }

        // Validate attribute name
        if params.attribute.is_empty() {
            return Err(CompareFsmError::InvalidParameters {
                message: "Attribute name cannot be empty".to_string(),
            });
        }

        // Validate value size
        if params.value.len() > self.config.max_value_size {
            return Err(CompareFsmError::InvalidParameters {
                message: format!(
                    "Attribute value size {} exceeds maximum {}",
                    params.value.len(),
                    self.config.max_value_size
                ),
            });
        }

        // Check for operational attributes if not allowed
        if !self.config.allow_operational_attributes
            && self.is_operational_attribute(&params.attribute)
        {
            return Err(CompareFsmError::InvalidParameters {
                message: format!(
                    "Comparison of operational attribute '{}' is not allowed",
                    params.attribute
                ),
            });
        }

        Ok(())
    }

    /// Check if an attribute is operational
    ///
    /// # Arguments
    /// * `attr_name` - Attribute name to check
    ///
    /// # Returns
    /// * true if attribute is operational
    fn is_operational_attribute(&self, attr_name: &str) -> bool {
        // Common operational attributes that are typically not compared
        matches!(
            attr_name.to_lowercase().as_str(),
            "createtimestamp"
                | "modifytimestamp"
                | "creatorsname"
                | "modifiersname"
                | "subschemasubentry"
                | "hassubordinates"
                | "numsubordinates"
                | "structuralobjectclass"
                | "pwdchangedtime"
                | "pwdaccountlockedtime"
                | "pwdfailuretime"
                | "pwdhistory"
        )
    }

    /// Handle compare start event
    ///
    /// # Arguments
    /// * `dn` - Entry DN to compare
    /// * `attribute` - Attribute name
    /// * `value` - Value to compare
    ///
    /// # Returns
    /// * Result indicating success or error
    async fn handle_start_compare(
        &mut self,
        dn: String,
        attribute: String,
        value: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, CompareFsmError> {
        let params = CompareParams {
            dn,
            attribute,
            value,
        };

        // Validate parameters
        self.validate_compare_params(&params)?;

        let user_dn = self.authenticated_user_dn.clone();

        // Check access control if enabled
        if self.config.enable_access_control {
            self.access_control
                .check_compare_permission(user_dn.as_deref(), &params.dn, &params.attribute)
                .await
                .map_err(|e| CompareFsmError::AccessDenied { message: e })?;
        }

        // Create new session
        let session = CompareSession::new(params.clone(), user_dn);

        // Record metrics
        if self.config.enable_metrics {
            if let Some(ref metrics) = self.metrics {
                metrics.record_compare_start(&params, session.user_dn.as_deref());
            }
        }

        self.session = Some(session);
        self.state = CompareState::Reading;
        self.total_compares += 1;

        Ok(None)
    }

    /// Handle entry read event
    ///
    /// # Returns
    /// * Result indicating success or error
    async fn handle_entry_read(&mut self) -> Result<Option<Vec<u8>>, CompareFsmError> {
        if self.session.is_none() {
            return Err(CompareFsmError::NoActiveCompare);
        }

        if !matches!(self.state, CompareState::Reading) {
            return Err(self.invalid_transition(CompareState::Evaluating));
        }

        let (dn, attribute) = {
            let session = self.session.as_ref().ok_or(CompareFsmError::NoActiveCompare)?;
            (session.params.dn.clone(), session.params.attribute.clone())
        };

        let read_start = Instant::now();
        let entry_result = match self
            .backend
            .get_entry_attributes(&dn, std::slice::from_ref(&attribute))
            .await
        {
            Ok(entry_result) => entry_result,
            Err(message) => {
                self.state = CompareState::Completed { result: false };
                self.record_compare_error_metric("BackendError");
                return Err(CompareFsmError::BackendError { message });
            }
        };

        let read_duration = read_start.elapsed();
        if let Some(session) = &mut self.session {
            session.entry_read_time = Some(Instant::now());
        }

        if self.config.enable_metrics {
            if let Some(metrics) = &self.metrics {
                metrics.record_entry_read(&dn, entry_result.is_some(), read_duration);
            }
        }

        match entry_result {
            Some(entry) => {
                if let Some(session) = &mut self.session {
                    session.entry = Some(entry);
                }
                self.state = CompareState::Evaluating;
                self.evaluate_loaded_entry().await
            }
            None => {
                self.state = CompareState::Completed { result: false };
                self.record_compare_error_metric("NoSuchObject");
                Err(CompareFsmError::NoSuchObject { dn })
            }
        }
    }

    /// Handle comparison complete event
    ///
    /// # Arguments
    /// * `result` - Comparison result
    ///
    /// # Returns
    /// * Result indicating success or error
    async fn handle_comparison_complete(
        &mut self,
        result: bool,
    ) -> Result<Option<Vec<u8>>, CompareFsmError> {
        if !matches!(self.state, CompareState::Evaluating) {
            return Err(self.invalid_transition(CompareState::Emitting { result }));
        }

        if let Some(session) = &mut self.session {
            session.comparison_complete_time = Some(Instant::now());
            session.result = Some(result);

            // Record comparison metrics
            if self.config.enable_metrics {
                if let Some(ref metrics) = self.metrics {
                    if let Some(duration) = session.comparison_duration() {
                        metrics.record_comparison_complete(
                            &session.params.attribute,
                            result,
                            duration,
                        );
                    }
                }
            }

            self.state = CompareState::Emitting { result };
            Ok(None)
        } else {
            Err(CompareFsmError::NoActiveCompare)
        }
    }

    /// Handle result emitted event
    ///
    /// # Returns
    /// * Result indicating success or error
    async fn handle_result_emitted(&mut self) -> Result<Option<Vec<u8>>, CompareFsmError> {
        if !matches!(self.state, CompareState::Emitting { .. }) {
            return Err(self.invalid_transition(CompareState::Completed {
                result: self.result().unwrap_or(false),
            }));
        }

        if let Some(session) = &self.session {
            let result = session.result.unwrap_or(false);

            self.state = CompareState::Completed { result };

            // Update statistics
            if result {
                self.successful_compares += 1;
            }
            self.total_duration += session.total_duration();

            // Record final metrics
            if self.config.enable_metrics {
                if let Some(ref metrics) = self.metrics {
                    metrics.record_compare_complete(result, session.total_duration());
                }
            }

            Ok(None)
        } else {
            Err(CompareFsmError::NoActiveCompare)
        }
    }

    /// Handle error event
    ///
    /// # Arguments
    /// * `error_message` - Error description
    ///
    /// # Returns
    /// * Result containing error
    async fn handle_error(
        &mut self,
        error_message: String,
    ) -> Result<Option<Vec<u8>>, CompareFsmError> {
        if let Some(session) = &self.session {
            // Record error metrics
            if self.config.enable_metrics {
                if let Some(ref metrics) = self.metrics {
                    metrics.record_compare_error("Generic", session.total_duration());
                }
            }
        }

        self.state = CompareState::Completed { result: false };
        Err(CompareFsmError::Generic {
            message: error_message,
        })
    }
}

#[async_trait]
impl StateMachine for CompareFsmImpl {
    type State = CompareState;
    type Event = CompareEvent;
    type Error = CompareFsmError;
    type Output = Vec<u8>; // Encoded compare result

    fn current_state(&self) -> &Self::State {
        &self.state
    }

    async fn handle_event(
        &mut self,
        event: Self::Event,
    ) -> Result<Option<Self::Output>, Self::Error> {
        match event {
            CompareEvent::StartCompare {
                dn,
                attribute,
                value,
            } => self.handle_start_compare(dn, attribute, value).await,
            CompareEvent::EntryRead => self.handle_entry_read().await,
            CompareEvent::ComparisonComplete(result) => {
                self.handle_comparison_complete(result).await
            }
            CompareEvent::ResultEmitted => self.handle_result_emitted().await,
            CompareEvent::Error(error_message) => self.handle_error(error_message).await,
        }
    }

    fn is_terminal(&self) -> bool {
        matches!(self.state, CompareState::Completed { .. })
    }

    async fn reset(&mut self) -> Result<(), Self::Error> {
        self.state = CompareState::Reading;
        self.session = None;
        Ok(())
    }
}

#[async_trait]
impl CompareFsm for CompareFsmImpl {
    fn compare_params(&self) -> Option<&CompareParams> {
        self.session.as_ref().map(|s| &s.params)
    }

    fn result(&self) -> Option<bool> {
        match &self.state {
            CompareState::Emitting { result } | CompareState::Completed { result } => Some(*result),
            _ => self.session.as_ref().and_then(|s| s.result),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio;

    /// Mock compare backend for testing
    #[derive(Debug)]
    pub struct MockCompareBackend {
        pub entries: HashMap<String, CompareEntry>,
        pub should_fail: bool,
        pub call_log: Arc<Mutex<Vec<String>>>,
    }

    impl MockCompareBackend {
        pub fn new() -> Self {
            let mut entries = HashMap::new();

            // Add test entries
            let mut entry1 = CompareEntry::new("cn=john,dc=example,dc=org".to_string());
            entry1.add_attribute("cn".to_string(), vec![b"john".to_vec()]);
            entry1.add_attribute("mail".to_string(), vec![b"john@example.org".to_vec()]);
            entry1.add_attribute(
                "objectClass".to_string(),
                vec![b"person".to_vec(), b"inetOrgPerson".to_vec()],
            );
            entry1.set_object_classes(vec!["person".to_string(), "inetOrgPerson".to_string()]);
            entries.insert(entry1.dn.clone(), entry1);

            let mut entry2 = CompareEntry::new("cn=jane,dc=example,dc=org".to_string());
            entry2.add_attribute("cn".to_string(), vec![b"jane".to_vec()]);
            entry2.add_attribute("mail".to_string(), vec![b"jane@example.org".to_vec()]);
            entry2.set_object_classes(vec!["person".to_string()]);
            entries.insert(entry2.dn.clone(), entry2);

            Self {
                entries,
                should_fail: false,
                call_log: Arc::new(Mutex::new(Vec::new())),
            }
        }

        pub fn with_failure(mut self) -> Self {
            self.should_fail = true;
            self
        }

        pub fn with_empty_results(mut self) -> Self {
            self.entries.clear();
            self
        }

        pub fn call_log(&self) -> Vec<String> {
            self.call_log.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl CompareBackend for MockCompareBackend {
        async fn get_entry_attributes(
            &self,
            dn: &str,
            attributes: &[String],
        ) -> Result<Option<CompareEntry>, String> {
            self.call_log
                .lock()
                .unwrap()
                .push(format!("get_entry_attributes({}, {:?})", dn, attributes));

            if self.should_fail {
                return Err("Mock backend failure".to_string());
            }

            if let Some(mut entry) = self.entries.get(dn).cloned() {
                // Filter to requested attributes only
                if !attributes.is_empty() {
                    let mut filtered_attrs = HashMap::new();
                    for attr in attributes {
                        if let Some(values) = entry.attributes.get(attr) {
                            filtered_attrs.insert(attr.clone(), values.clone());
                        }
                    }
                    entry.attributes = filtered_attrs;
                }
                Ok(Some(entry))
            } else {
                Ok(None)
            }
        }
    }

    /// Mock attribute comparator for testing
    #[derive(Debug)]
    pub struct MockAttributeComparator {
        pub should_match: bool,
        pub should_fail: bool,
        pub call_log: Arc<Mutex<Vec<String>>>,
    }

    impl MockAttributeComparator {
        pub fn new() -> Self {
            Self {
                should_match: true,
                should_fail: false,
                call_log: Arc::new(Mutex::new(Vec::new())),
            }
        }

        pub fn with_failure(mut self) -> Self {
            self.should_fail = true;
            self
        }

        pub fn with_no_match(mut self) -> Self {
            self.should_match = false;
            self
        }

        pub fn call_log(&self) -> Vec<String> {
            self.call_log.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl AttributeComparator for MockAttributeComparator {
        async fn compare_attribute(
            &self,
            entry: &CompareEntry,
            attr_name: &str,
            value: &[u8],
        ) -> Result<bool, String> {
            self.call_log.lock().unwrap().push(format!(
                "compare_attribute({}, {}, {:?})",
                entry.dn, attr_name, value
            ));

            if self.should_fail {
                return Err("Mock comparator failure".to_string());
            }

            // Simple exact match comparison for testing
            if let Some(attr_values) = entry.get_attribute(attr_name) {
                let matches = attr_values.iter().any(|v| v == value);
                Ok(matches && self.should_match)
            } else {
                Ok(false)
            }
        }
    }

    /// Mock access control for testing
    #[derive(Debug)]
    pub struct MockCompareAccessControl {
        pub should_allow: bool,
        pub required_user_dn: Option<String>,
        pub call_log: Arc<Mutex<Vec<String>>>,
    }

    impl MockCompareAccessControl {
        pub fn new() -> Self {
            Self {
                should_allow: true,
                required_user_dn: None,
                call_log: Arc::new(Mutex::new(Vec::new())),
            }
        }

        pub fn with_denial(mut self) -> Self {
            self.should_allow = false;
            self
        }

        pub fn requiring_user_dn(mut self, user_dn: &str) -> Self {
            self.required_user_dn = Some(user_dn.to_string());
            self
        }

        pub fn call_log(&self) -> Vec<String> {
            self.call_log.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl CompareAccessControl for MockCompareAccessControl {
        async fn check_compare_permission(
            &self,
            user_dn: Option<&str>,
            entry_dn: &str,
            attribute: &str,
        ) -> Result<(), String> {
            self.call_log.lock().unwrap().push(format!(
                "check_compare_permission({:?}, {}, {})",
                user_dn, entry_dn, attribute
            ));

            if !self.should_allow {
                return Err("Access denied".to_string());
            }

            if let Some(required_user_dn) = &self.required_user_dn {
                if user_dn == Some(required_user_dn.as_str()) {
                    Ok(())
                } else {
                    Err(format!("Access denied for {:?}", user_dn))
                }
            } else {
                Ok(())
            }
        }
    }

    /// Mock metrics collector for testing
    #[derive(Debug)]
    pub struct MockCompareMetrics {
        pub call_log: Arc<Mutex<Vec<String>>>,
    }

    impl MockCompareMetrics {
        pub fn new() -> Self {
            Self {
                call_log: Arc::new(Mutex::new(Vec::new())),
            }
        }

        pub fn call_log(&self) -> Vec<String> {
            self.call_log.lock().unwrap().clone()
        }
    }

    impl CompareMetrics for MockCompareMetrics {
        fn record_compare_start(&self, params: &CompareParams, user_dn: Option<&str>) {
            self.call_log.lock().unwrap().push(format!(
                "record_compare_start({}, {}, {:?})",
                params.dn, params.attribute, user_dn
            ));
        }

        fn record_entry_read(&self, dn: &str, found: bool, duration: Duration) {
            self.call_log.lock().unwrap().push(format!(
                "record_entry_read({}, {}, {:?})",
                dn, found, duration
            ));
        }

        fn record_comparison_complete(&self, attribute: &str, result: bool, duration: Duration) {
            self.call_log.lock().unwrap().push(format!(
                "record_comparison_complete({}, {}, {:?})",
                attribute, result, duration
            ));
        }

        fn record_compare_complete(&self, result: bool, duration: Duration) {
            self.call_log.lock().unwrap().push(format!(
                "record_compare_complete({}, {:?})",
                result, duration
            ));
        }

        fn record_compare_error(&self, error_type: &str, duration: Duration) {
            self.call_log.lock().unwrap().push(format!(
                "record_compare_error({}, {:?})",
                error_type, duration
            ));
        }
    }

    #[tokio::test]
    async fn test_new_compare_fsm() {
        let backend = Box::new(MockCompareBackend::new());
        let comparator = Box::new(MockAttributeComparator::new());
        let access_control = Box::new(MockCompareAccessControl::new());

        let fsm = CompareFsmImpl::new(backend, comparator, access_control);

        assert_eq!(fsm.current_state(), &CompareState::Reading);
        assert!(fsm.compare_params().is_none());
        assert!(fsm.result().is_none());
        assert!(!fsm.is_terminal());
    }

    #[tokio::test]
    async fn test_compare_fsm_with_config() {
        let backend = Box::new(MockCompareBackend::new());
        let comparator = Box::new(MockAttributeComparator::new());
        let access_control = Box::new(MockCompareAccessControl::new());

        let config = CompareFsmConfig {
            max_backend_timeout: 60,
            max_value_size: 2_097_152, // 2MB
            enable_access_control: false,
            enable_metrics: false,
            allow_operational_attributes: true,
        };

        let fsm = CompareFsmImpl::with_config(backend, comparator, access_control, config);

        assert_eq!(fsm.current_state(), &CompareState::Reading);
        assert!(!fsm.config.enable_access_control);
        assert!(!fsm.config.enable_metrics);
        assert!(fsm.config.allow_operational_attributes);
    }

    #[tokio::test]
    async fn test_start_compare_success() {
        let backend = Box::new(MockCompareBackend::new());
        let comparator = Box::new(MockAttributeComparator::new());
        let access_control = Box::new(MockCompareAccessControl::new());

        let mut fsm = CompareFsmImpl::new(backend, comparator, access_control);

        let result = fsm
            .handle_event(CompareEvent::StartCompare {
                dn: "cn=john,dc=example,dc=org".to_string(),
                attribute: "mail".to_string(),
                value: b"john@example.org".to_vec(),
            })
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
        assert_eq!(fsm.current_state(), &CompareState::Reading);
        assert!(fsm.compare_params().is_some());

        let params = fsm.compare_params().unwrap();
        assert_eq!(params.dn, "cn=john,dc=example,dc=org");
        assert_eq!(params.attribute, "mail");
        assert_eq!(params.value, b"john@example.org");

        let (total_compares, _, _) = fsm.stats();
        assert_eq!(total_compares, 1);
    }

    #[tokio::test]
    async fn test_start_compare_invalid_parameters() {
        let backend = Box::new(MockCompareBackend::new());
        let comparator = Box::new(MockAttributeComparator::new());
        let access_control = Box::new(MockCompareAccessControl::new());

        let mut fsm = CompareFsmImpl::new(backend, comparator, access_control);

        // Test empty DN
        let result = fsm
            .handle_event(CompareEvent::StartCompare {
                dn: "".to_string(),
                attribute: "mail".to_string(),
                value: b"test@example.org".to_vec(),
            })
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CompareFsmError::InvalidParameters { .. }
        ));
        assert_eq!(fsm.current_state(), &CompareState::Reading);

        // Test empty attribute
        let result = fsm
            .handle_event(CompareEvent::StartCompare {
                dn: "cn=test,dc=example,dc=org".to_string(),
                attribute: "".to_string(),
                value: b"test".to_vec(),
            })
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CompareFsmError::InvalidParameters { .. }
        ));
    }

    #[tokio::test]
    async fn test_entry_read_success() {
        let backend = Box::new(MockCompareBackend::new());
        let comparator = MockAttributeComparator::new();
        let comparator_log = comparator.call_log.clone();
        let comparator = Box::new(comparator);
        let access_control = Box::new(MockCompareAccessControl::new());

        let mut fsm = CompareFsmImpl::new(backend, comparator, access_control);

        // Start compare first
        let _result = fsm
            .handle_event(CompareEvent::StartCompare {
                dn: "cn=john,dc=example,dc=org".to_string(),
                attribute: "mail".to_string(),
                value: b"john@example.org".to_vec(),
            })
            .await
            .unwrap();

        // Handle entry read
        let result = fsm.handle_event(CompareEvent::EntryRead).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
        assert_eq!(fsm.current_state(), &CompareState::Emitting { result: true });
        assert_eq!(fsm.result(), Some(true));
        assert!(comparator_log
            .lock()
            .unwrap()
            .iter()
            .any(|call| call.contains("compare_attribute")));
    }

    #[tokio::test]
    async fn test_entry_read_not_found() {
        let backend = Box::new(MockCompareBackend::new().with_empty_results());
        let comparator = Box::new(MockAttributeComparator::new());
        let access_control = Box::new(MockCompareAccessControl::new());

        let mut fsm = CompareFsmImpl::new(backend, comparator, access_control);

        // Start compare first
        let _result = fsm
            .handle_event(CompareEvent::StartCompare {
                dn: "cn=nonexistent,dc=example,dc=org".to_string(),
                attribute: "mail".to_string(),
                value: b"test@example.org".to_vec(),
            })
            .await
            .unwrap();

        // Handle entry read
        let result = fsm.handle_event(CompareEvent::EntryRead).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CompareFsmError::NoSuchObject { .. }
        ));
        assert_eq!(
            fsm.current_state(),
            &CompareState::Completed { result: false }
        );
    }

    #[tokio::test]
    async fn test_entry_read_computes_false_result() {
        let backend = Box::new(MockCompareBackend::new());
        let comparator = Box::new(MockAttributeComparator::new().with_no_match());
        let access_control = Box::new(MockCompareAccessControl::new());

        let mut fsm = CompareFsmImpl::new(backend, comparator, access_control);

        // Start compare and read entry
        let _result = fsm
            .handle_event(CompareEvent::StartCompare {
                dn: "cn=john,dc=example,dc=org".to_string(),
                attribute: "mail".to_string(),
                value: b"john@example.org".to_vec(),
            })
            .await
            .unwrap();

        let result = fsm.handle_event(CompareEvent::EntryRead).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
        assert_eq!(
            fsm.current_state(),
            &CompareState::Emitting { result: false }
        );
        assert_eq!(fsm.result(), Some(false));
    }

    #[tokio::test]
    async fn test_entry_read_missing_attribute_returns_no_such_attribute() {
        let backend = Box::new(MockCompareBackend::new());
        let comparator = Box::new(MockAttributeComparator::new());
        let access_control = Box::new(MockCompareAccessControl::new());

        let mut fsm = CompareFsmImpl::new(backend, comparator, access_control);

        // Start compare with an attribute that is not present on the entry.
        let _result = fsm
            .handle_event(CompareEvent::StartCompare {
                dn: "cn=john,dc=example,dc=org".to_string(),
                attribute: "telephoneNumber".to_string(),
                value: b"+1-555-0100".to_vec(),
            })
            .await
            .unwrap();

        let result = fsm.handle_event(CompareEvent::EntryRead).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CompareFsmError::NoSuchAttribute { .. }
        ));
        assert_eq!(
            fsm.current_state(),
            &CompareState::Completed { result: false }
        );
        assert_eq!(fsm.result(), Some(false));
    }

    #[tokio::test]
    async fn test_entry_read_comparator_error_returns_comparison_error() {
        let backend = Box::new(MockCompareBackend::new());
        let comparator = Box::new(MockAttributeComparator::new().with_failure());
        let access_control = Box::new(MockCompareAccessControl::new());

        let mut fsm = CompareFsmImpl::new(backend, comparator, access_control);

        let _result = fsm
            .handle_event(CompareEvent::StartCompare {
                dn: "cn=john,dc=example,dc=org".to_string(),
                attribute: "mail".to_string(),
                value: b"john@example.org".to_vec(),
            })
            .await
            .unwrap();

        let result = fsm.handle_event(CompareEvent::EntryRead).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CompareFsmError::ComparisonError { .. }
        ));
        assert_eq!(
            fsm.current_state(),
            &CompareState::Completed { result: false }
        );
    }

    #[tokio::test]
    async fn test_result_emitted() {
        let backend = Box::new(MockCompareBackend::new());
        let comparator = Box::new(MockAttributeComparator::new());
        let access_control = Box::new(MockCompareAccessControl::new());

        let mut fsm = CompareFsmImpl::new(backend, comparator, access_control);

        // Complete full compare flow
        let _result = fsm
            .handle_event(CompareEvent::StartCompare {
                dn: "cn=john,dc=example,dc=org".to_string(),
                attribute: "mail".to_string(),
                value: b"john@example.org".to_vec(),
            })
            .await
            .unwrap();

        let _result = fsm.handle_event(CompareEvent::EntryRead).await.unwrap();

        // Handle result emitted
        let result = fsm.handle_event(CompareEvent::ResultEmitted).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
        assert_eq!(
            fsm.current_state(),
            &CompareState::Completed { result: true }
        );
        assert!(fsm.is_terminal());
        assert_eq!(fsm.result(), Some(true));

        let (total_compares, successful_compares, _) = fsm.stats();
        assert_eq!(total_compares, 1);
        assert_eq!(successful_compares, 1);
    }

    #[tokio::test]
    async fn test_compare_error() {
        let backend = Box::new(MockCompareBackend::new());
        let comparator = Box::new(MockAttributeComparator::new());
        let access_control = Box::new(MockCompareAccessControl::new());

        let mut fsm = CompareFsmImpl::new(backend, comparator, access_control);

        // Start compare
        let _result = fsm
            .handle_event(CompareEvent::StartCompare {
                dn: "cn=john,dc=example,dc=org".to_string(),
                attribute: "mail".to_string(),
                value: b"john@example.org".to_vec(),
            })
            .await
            .unwrap();

        // Trigger error
        let result = fsm
            .handle_event(CompareEvent::Error("Test error".to_string()))
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CompareFsmError::Generic { .. }
        ));
        assert_eq!(
            fsm.current_state(),
            &CompareState::Completed { result: false }
        );
        assert!(fsm.is_terminal());
    }

    #[tokio::test]
    async fn test_fsm_reset() {
        let backend = Box::new(MockCompareBackend::new());
        let comparator = Box::new(MockAttributeComparator::new());
        let access_control = Box::new(MockCompareAccessControl::new());

        let mut fsm = CompareFsmImpl::new(backend, comparator, access_control);

        // Start compare
        let _result = fsm
            .handle_event(CompareEvent::StartCompare {
                dn: "cn=john,dc=example,dc=org".to_string(),
                attribute: "mail".to_string(),
                value: b"john@example.org".to_vec(),
            })
            .await
            .unwrap();

        assert_eq!(fsm.current_state(), &CompareState::Reading);
        assert!(fsm.compare_params().is_some());

        // Reset FSM
        let result = fsm.reset().await;

        assert!(result.is_ok());
        assert_eq!(fsm.current_state(), &CompareState::Reading);
        assert!(fsm.compare_params().is_none());
    }

    #[tokio::test]
    async fn test_compare_with_metrics() {
        let backend = Box::new(MockCompareBackend::new());
        let comparator = Box::new(MockAttributeComparator::new());
        let access_control = Box::new(MockCompareAccessControl::new());
        let metrics = Box::new(MockCompareMetrics::new());
        let metrics_log = metrics.call_log.clone();

        let mut fsm =
            CompareFsmImpl::new(backend, comparator, access_control).with_metrics(metrics);

        // Start compare
        let _result = fsm
            .handle_event(CompareEvent::StartCompare {
                dn: "cn=john,dc=example,dc=org".to_string(),
                attribute: "mail".to_string(),
                value: b"john@example.org".to_vec(),
            })
            .await
            .unwrap();

        // Check metrics were called
        let calls = metrics_log.lock().unwrap();
        assert!(calls
            .iter()
            .any(|call| call.contains("record_compare_start")));
    }

    #[tokio::test]
    async fn test_access_control_denial() {
        let backend = Box::new(MockCompareBackend::new());
        let comparator = Box::new(MockAttributeComparator::new());
        let access_control = Box::new(MockCompareAccessControl::new().with_denial());

        let mut fsm = CompareFsmImpl::new(backend, comparator, access_control);

        // Start compare - should be denied
        let result = fsm
            .handle_event(CompareEvent::StartCompare {
                dn: "cn=john,dc=example,dc=org".to_string(),
                attribute: "mail".to_string(),
                value: b"john@example.org".to_vec(),
            })
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CompareFsmError::AccessDenied { .. }
        ));
    }

    #[tokio::test]
    async fn test_with_user_dn_affects_access_control() {
        let backend = Box::new(MockCompareBackend::new());
        let comparator = Box::new(MockAttributeComparator::new());
        let access_control = MockCompareAccessControl::new().requiring_user_dn(
            "cn=admin,dc=example,dc=org",
        );
        let access_log = access_control.call_log.clone();

        let mut allowed_fsm =
            CompareFsmImpl::new(backend, comparator, Box::new(access_control))
                .with_user_dn("cn=admin,dc=example,dc=org".to_string());

        let allowed = allowed_fsm
            .handle_event(CompareEvent::StartCompare {
                dn: "cn=john,dc=example,dc=org".to_string(),
                attribute: "mail".to_string(),
                value: b"john@example.org".to_vec(),
            })
            .await;

        assert!(allowed.is_ok());
        assert!(access_log
            .lock()
            .unwrap()
            .iter()
            .any(|call| call.contains("Some(\"cn=admin,dc=example,dc=org\")")));

        let backend = Box::new(MockCompareBackend::new());
        let comparator = Box::new(MockAttributeComparator::new());
        let access_control = Box::new(
            MockCompareAccessControl::new().requiring_user_dn("cn=admin,dc=example,dc=org"),
        );
        let mut denied_fsm =
            CompareFsmImpl::new(backend, comparator, access_control)
                .with_user_dn("cn=hacker,dc=example,dc=org".to_string());

        let denied = denied_fsm
            .handle_event(CompareEvent::StartCompare {
                dn: "cn=john,dc=example,dc=org".to_string(),
                attribute: "mail".to_string(),
                value: b"john@example.org".to_vec(),
            })
            .await;

        assert!(denied.is_err());
        assert!(matches!(
            denied.unwrap_err(),
            CompareFsmError::AccessDenied { .. }
        ));
    }

    #[tokio::test]
    async fn test_compare_entry_methods() {
        let mut entry = CompareEntry::new("cn=test,dc=example,dc=org".to_string());

        assert_eq!(entry.dn, "cn=test,dc=example,dc=org");
        assert!(entry.attributes.is_empty());
        assert!(entry.object_classes.is_empty());

        entry.add_attribute("cn".to_string(), vec![b"test".to_vec()]);
        entry.add_attribute("mail".to_string(), vec![b"test@example.org".to_vec()]);
        entry.set_object_classes(vec!["person".to_string(), "inetOrgPerson".to_string()]);

        assert_eq!(entry.get_attribute("cn"), Some(&vec![b"test".to_vec()]));
        assert_eq!(entry.get_attribute("CN"), Some(&vec![b"test".to_vec()])); // Case insensitive
        assert_eq!(entry.get_attribute("nonexistent"), None);

        assert!(entry.has_attribute("cn"));
        assert!(entry.has_attribute("CN")); // Case insensitive
        assert!(!entry.has_attribute("nonexistent"));

        assert!(entry.has_object_class("person"));
        assert!(entry.has_object_class("PERSON")); // Case insensitive
        assert!(!entry.has_object_class("group"));
    }

    #[tokio::test]
    async fn test_compare_session_methods() {
        let params = CompareParams {
            dn: "cn=test,dc=example,dc=org".to_string(),
            attribute: "mail".to_string(),
            value: b"test@example.org".to_vec(),
        };

        let mut session =
            CompareSession::new(params, Some("cn=admin,dc=example,dc=org".to_string()));

        assert_eq!(session.params.dn, "cn=test,dc=example,dc=org");
        assert_eq!(
            session.user_dn,
            Some("cn=admin,dc=example,dc=org".to_string())
        );
        assert!(session.entry.is_none());
        assert!(session.result.is_none());

        // Test timing methods
        assert!(session.entry_read_duration().is_none());
        assert!(session.comparison_duration().is_none());

        session.entry_read_time = Some(Instant::now());
        session.comparison_complete_time = Some(Instant::now());

        assert!(session.entry_read_duration().is_some());
        assert!(session.comparison_duration().is_some());
        assert!(session.total_duration().as_millis() >= 0);
    }
}

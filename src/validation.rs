//! LDAP Message Validation Module
//!
//! This module provides comprehensive validation of LDAP messages and protocol constraints
//! to ensure compliance with RFC 4511 and related specifications. It extends the basic
//! parsing provided by ldap-parser with additional semantic validation.

use std::collections::HashMap;
use std::fmt;

use ldap_parser::filter::{Filter, Substring, SubstringFilter, AttributeValueAssertion};
use ldap_parser::ldap::{
    LdapMessage, ProtocolOp, BindRequest, SearchRequest, AddRequest, ModifyRequest, 
    ModDnRequest, CompareRequest, ExtendedRequest, LdapDN, LdapString, SearchScope,
    DerefAliases, Operation, Change,
};
use log::{debug, warn, error};

/// Validation errors that can occur during LDAP message processing
#[derive(Debug, Clone)]
pub enum ValidationError {
    /// Protocol version mismatch or unsupported
    InvalidProtocolVersion { version: i32, supported: Vec<i32> },
    /// Message ID constraints violated
    InvalidMessageId { id: u32, reason: String },
    /// DN format validation failed
    InvalidDn { dn: String, reason: String },
    /// Attribute name constraints violated
    InvalidAttributeName { name: String, reason: String },
    /// Attribute value constraints violated
    InvalidAttributeValue { name: String, value: String, reason: String },
    /// Search filter validation failed
    InvalidSearchFilter { reason: String },
    /// Search scope constraints violated
    InvalidSearchScope { scope: i32, reason: String },
    /// Size or time limit constraints violated
    InvalidLimits { size_limit: i32, time_limit: i32, reason: String },
    /// Operation-specific constraint violation
    OperationConstraintViolation { operation: String, reason: String },
    /// Extended operation validation failed
    InvalidExtendedOperation { oid: String, reason: String },
    /// Schema constraint violation (future extension)
    SchemaViolation { object_class: Option<String>, reason: String },
    /// Security constraint violation
    SecurityConstraintViolation { reason: String },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::InvalidProtocolVersion { version, supported } => {
                write!(f, "Invalid LDAP protocol version {}, supported versions: {:?}", version, supported)
            }
            ValidationError::InvalidMessageId { id, reason } => {
                write!(f, "Invalid message ID {}: {}", id, reason)
            }
            ValidationError::InvalidDn { dn, reason } => {
                write!(f, "Invalid DN '{}': {}", dn, reason)
            }
            ValidationError::InvalidAttributeName { name, reason } => {
                write!(f, "Invalid attribute name '{}': {}", name, reason)
            }
            ValidationError::InvalidAttributeValue { name, value, reason } => {
                write!(f, "Invalid value '{}' for attribute '{}': {}", value, name, reason)
            }
            ValidationError::InvalidSearchFilter { reason } => {
                write!(f, "Invalid search filter: {}", reason)
            }
            ValidationError::InvalidSearchScope { scope, reason } => {
                write!(f, "Invalid search scope {}: {}", scope, reason)
            }
            ValidationError::InvalidLimits { size_limit, time_limit, reason } => {
                write!(f, "Invalid limits (size: {}, time: {}): {}", size_limit, time_limit, reason)
            }
            ValidationError::OperationConstraintViolation { operation, reason } => {
                write!(f, "Constraint violation in {} operation: {}", operation, reason)
            }
            ValidationError::InvalidExtendedOperation { oid, reason } => {
                write!(f, "Invalid extended operation {}: {}", oid, reason)
            }
            ValidationError::SchemaViolation { object_class, reason } => {
                match object_class {
                    Some(oc) => write!(f, "Schema violation for object class '{}': {}", oc, reason),
                    None => write!(f, "Schema violation: {}", reason),
                }
            }
            ValidationError::SecurityConstraintViolation { reason } => {
                write!(f, "Security constraint violation: {}", reason)
            }
        }
    }
}

impl std::error::Error for ValidationError {}

/// Configuration for LDAP message validation
#[derive(Debug, Clone)]
pub struct ValidationConfig {
    /// Supported LDAP protocol versions (typically [3])
    pub supported_versions: Vec<i32>,
    /// Maximum allowed size limit in search operations (0 = no limit)
    pub max_size_limit: i32,
    /// Maximum allowed time limit in search operations (0 = no limit)
    pub max_time_limit: i32,
    /// Maximum DN length to prevent DoS attacks
    pub max_dn_length: usize,
    /// Maximum attribute value length
    pub max_attribute_value_length: usize,
    /// Maximum number of attributes per entry
    pub max_attributes_per_entry: usize,
    /// Enable strict DN validation (RFC 4514)
    pub strict_dn_validation: bool,
    /// Enable strict attribute name validation
    pub strict_attribute_validation: bool,
    /// Enable filter complexity validation
    pub validate_filter_complexity: bool,
    /// Maximum filter nesting depth
    pub max_filter_depth: usize,
    /// Known extended operation OIDs
    pub supported_extended_operations: HashMap<String, String>,
    /// Enable security constraint checking
    pub enable_security_checks: bool,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        let mut supported_extended_ops = HashMap::new();
        supported_extended_ops.insert("1.3.6.1.4.1.1466.20037".to_string(), "StartTLS".to_string());
        supported_extended_ops.insert("1.3.6.1.4.1.4203.1.11.1".to_string(), "Password Modify".to_string());
        supported_extended_ops.insert("1.3.6.1.4.1.4203.1.11.3".to_string(), "Who Am I".to_string());
        supported_extended_ops.insert("1.3.6.1.1.8".to_string(), "Cancel".to_string());
        
        Self {
            supported_versions: vec![3],
            max_size_limit: 1000,
            max_time_limit: 300, // 5 minutes
            max_dn_length: 8192,
            max_attribute_value_length: 1_048_576, // 1MB
            max_attributes_per_entry: 1000,
            strict_dn_validation: true,
            strict_attribute_validation: true,
            validate_filter_complexity: true,
            max_filter_depth: 20,
            supported_extended_operations: supported_extended_ops,
            enable_security_checks: true,
        }
    }
}

/// Comprehensive LDAP message validator
pub struct LdapMessageValidator {
    config: ValidationConfig,
    /// Statistics for monitoring validation performance
    validation_stats: ValidationStats,
}

/// Validation statistics for monitoring
#[derive(Debug, Default, Clone)]
pub struct ValidationStats {
    pub messages_validated: u64,
    pub validation_errors: u64,
    pub bind_validations: u64,
    pub search_validations: u64,
    pub modify_validations: u64,
    pub add_validations: u64,
    pub delete_validations: u64,
    pub moddn_validations: u64,
    pub compare_validations: u64,
    pub extended_validations: u64,
    pub filter_validations: u64,
    pub dn_validations: u64,
}

impl LdapMessageValidator {
    /// Create a new validator with default configuration
    pub fn new() -> Self {
        Self::with_config(ValidationConfig::default())
    }
    
    /// Create a new validator with custom configuration
    pub fn with_config(config: ValidationConfig) -> Self {
        Self {
            config,
            validation_stats: ValidationStats::default(),
        }
    }
    
    /// Get current validation statistics
    pub fn stats(&self) -> &ValidationStats {
        &self.validation_stats
    }
    
    /// Reset validation statistics
    pub fn reset_stats(&mut self) {
        self.validation_stats = ValidationStats::default();
    }
    
    /// Validate a complete LDAP message
    pub fn validate_message(&mut self, message: &LdapMessage<'_>) -> Result<(), ValidationError> {
        self.validation_stats.messages_validated += 1;
        
        debug!("Validating LDAP message ID {}", message.message_id.0);
        
        // Validate message ID constraints
        self.validate_message_id(message.message_id.0)?;
        
        // Validate specific protocol operation
        match &message.protocol_op {
            ProtocolOp::BindRequest(req) => {
                self.validation_stats.bind_validations += 1;
                self.validate_bind_request(req)?;
            }
            ProtocolOp::SearchRequest(req) => {
                self.validation_stats.search_validations += 1;
                self.validate_search_request(req)?;
            }
            ProtocolOp::AddRequest(req) => {
                self.validation_stats.add_validations += 1;
                self.validate_add_request(req)?;
            }
            ProtocolOp::ModifyRequest(req) => {
                self.validation_stats.modify_validations += 1;
                self.validate_modify_request(req)?;
            }
            ProtocolOp::DelRequest(dn) => {
                self.validation_stats.delete_validations += 1;
                self.validate_delete_request(dn)?;
            }
            ProtocolOp::ModDnRequest(req) => {
                self.validation_stats.moddn_validations += 1;
                self.validate_moddn_request(req)?;
            }
            ProtocolOp::CompareRequest(req) => {
                self.validation_stats.compare_validations += 1;
                self.validate_compare_request(req)?;
            }
            ProtocolOp::ExtendedRequest(req) => {
                self.validation_stats.extended_validations += 1;
                self.validate_extended_request(req)?;
            }
            ProtocolOp::UnbindRequest => {
                // Unbind requests have no validation requirements
                debug!("Unbind request - no validation needed");
            }
            ProtocolOp::AbandonRequest(msg_id) => {
                // Validate the target message ID
                self.validate_message_id(msg_id.0)?;
                debug!("Abandon request for message ID {} - validated", msg_id.0);
            }
            _ => {
                // Response operations shouldn't be validated as incoming requests
                warn!("Received unexpected protocol operation type in request validation");
            }
        }
        
        debug!("Successfully validated LDAP message ID {}", message.message_id.0);
        Ok(())
    }
    
    /// Validate message ID constraints
    fn validate_message_id(&self, message_id: u32) -> Result<(), ValidationError> {
        // Message ID 0 is reserved for unsolicited notifications
        if message_id == 0 {
            return Err(ValidationError::InvalidMessageId {
                id: message_id,
                reason: "Message ID 0 is reserved for unsolicited notifications".to_string(),
            });
        }
        
        // RFC 4511 specifies message IDs should be positive integers
        // We use u32, so this is automatically satisfied, but we can add additional constraints
        const MAX_MESSAGE_ID: u32 = 2_147_483_647; // 2^31 - 1
        if message_id > MAX_MESSAGE_ID {
            return Err(ValidationError::InvalidMessageId {
                id: message_id,
                reason: format!("Message ID {} exceeds maximum allowed value {}", message_id, MAX_MESSAGE_ID),
            });
        }
        
        Ok(())
    }
    
    /// Validate bind request
    fn validate_bind_request(&mut self, request: &BindRequest<'_>) -> Result<(), ValidationError> {
        // Validate protocol version
        let version_i32 = request.version as i32;
        if !self.config.supported_versions.contains(&version_i32) {
            return Err(ValidationError::InvalidProtocolVersion {
                version: version_i32,
                supported: self.config.supported_versions.clone(),
            });
        }
        
        // Validate DN
        self.validate_dn(&request.name.0)?;
        
        // Additional bind-specific validations could be added here
        // (e.g., SASL mechanism validation, credential format checking)
        
        Ok(())
    }
    
    /// Validate search request
    fn validate_search_request(&mut self, request: &SearchRequest<'_>) -> Result<(), ValidationError> {
        // Validate base DN
        self.validate_dn(&request.base_object.0)?;
        
        // Validate search scope
        self.validate_search_scope(request.scope.0 as i32)?;
        
        // Validate deref aliases value
        self.validate_deref_aliases(request.deref_aliases.0 as i32)?;
        
        // Validate size and time limits
        self.validate_search_limits(request.size_limit as i32, request.time_limit as i32)?;
        
        // Validate search filter
        self.validate_search_filter(&request.filter, 0)?;
        
        // Validate requested attributes
        for attr in &request.attributes {
            self.validate_attribute_name(&attr.0)?;
        }
        
        Ok(())
    }
    
    /// Validate add request
    fn validate_add_request(&mut self, request: &AddRequest<'_>) -> Result<(), ValidationError> {
        // Validate entry DN
        self.validate_dn(&request.entry.0)?;
        
        // Validate attribute count
        if request.attributes.len() > self.config.max_attributes_per_entry {
            return Err(ValidationError::OperationConstraintViolation {
                operation: "Add".to_string(),
                reason: format!("Too many attributes: {} > {}", 
                               request.attributes.len(), 
                               self.config.max_attributes_per_entry),
            });
        }
        
        // Validate each attribute
        for attr in &request.attributes {
            self.validate_attribute_name(&attr.attr_type.0)?;
            
            for value in &attr.attr_vals {
                self.validate_attribute_value(&attr.attr_type.0, value.0.as_ref())?;
            }
            
            // Check for duplicate values (LDAP doesn't allow duplicates)
            let mut seen_values = std::collections::HashSet::new();
            for value in &attr.attr_vals {
                if !seen_values.insert(value.0.as_ref()) {
                    return Err(ValidationError::OperationConstraintViolation {
                        operation: "Add".to_string(),
                        reason: format!("Duplicate attribute value in attribute '{}'", attr.attr_type.0),
                    });
                }
            }
        }
        
        Ok(())
    }
    
    /// Validate modify request
    fn validate_modify_request(&mut self, request: &ModifyRequest<'_>) -> Result<(), ValidationError> {
        // Validate object DN
        self.validate_dn(&request.object.0)?;
        
        // Validate modifications
        for change in &request.changes {
            self.validate_modify_operation(change)?;
        }
        
        Ok(())
    }
    
    /// Validate delete request
    fn validate_delete_request(&mut self, dn: &LdapDN<'_>) -> Result<(), ValidationError> {
        self.validate_dn(&dn.0)
    }
    
    /// Validate moddn (rename) request
    fn validate_moddn_request(&mut self, request: &ModDnRequest<'_>) -> Result<(), ValidationError> {
        // Validate source DN
        self.validate_dn(&request.entry.0)?;
        
        // Validate new RDN
        self.validate_rdn(&request.newrdn.0)?;
        
        // Validate new superior if present
        if let Some(ref superior) = request.newsuperior {
            self.validate_dn(&superior.0)?;
        }
        
        Ok(())
    }
    
    /// Validate compare request
    fn validate_compare_request(&mut self, request: &CompareRequest<'_>) -> Result<(), ValidationError> {
        // Validate entry DN
        self.validate_dn(&request.entry.0)?;
        
        // Validate attribute name
        self.validate_attribute_name(&request.ava.attribute_desc.0)?;
        
        // Validate attribute value
        self.validate_attribute_value(&request.ava.attribute_desc.0, &request.ava.assertion_value)?;
        
        Ok(())
    }
    
    /// Validate extended request
    fn validate_extended_request(&mut self, request: &ExtendedRequest<'_>) -> Result<(), ValidationError> {
        let oid = request.request_name.0.as_ref();
        
        // Check if the extended operation is known/supported
        if !self.config.supported_extended_operations.contains_key(oid) {
            warn!("Unknown extended operation OID: {}", oid);
        }
        
        // Validate OID format (basic check)
        if !self.validate_oid_format(oid) {
            return Err(ValidationError::InvalidExtendedOperation {
                oid: oid.to_string(),
                reason: "Invalid OID format".to_string(),
            });
        }
        
        // Extended operation-specific validation could be added here
        // based on the specific OID
        
        Ok(())
    }
    
    /// Validate DN format and constraints
    fn validate_dn(&mut self, dn: &str) -> Result<(), ValidationError> {
        self.validation_stats.dn_validations += 1;
        
        // Check length constraints
        if dn.len() > self.config.max_dn_length {
            return Err(ValidationError::InvalidDn {
                dn: dn.to_string(),
                reason: format!("DN length {} exceeds maximum {}", dn.len(), self.config.max_dn_length),
            });
        }
        
        // Empty DN (root DSE) is valid
        if dn.trim().is_empty() {
            return Ok(());
        }
        
        if self.config.strict_dn_validation {
            // Basic DN format validation (RFC 4514)
            // This is a simplified check - a full implementation would parse the DN completely
            if !dn.contains('=') {
                return Err(ValidationError::InvalidDn {
                    dn: dn.to_string(),
                    reason: "DN must contain at least one '=' for attribute=value pairs".to_string(),
                });
            }
            
            // Check for balanced quotes and proper escaping
            if self.has_unescaped_special_chars(dn) {
                return Err(ValidationError::InvalidDn {
                    dn: dn.to_string(),
                    reason: "DN contains unescaped special characters".to_string(),
                });
            }
        }
        
        Ok(())
    }
    
    /// Validate RDN (Relative Distinguished Name)
    fn validate_rdn(&self, rdn: &str) -> Result<(), ValidationError> {
        if rdn.trim().is_empty() {
            return Err(ValidationError::InvalidDn {
                dn: rdn.to_string(),
                reason: "RDN cannot be empty".to_string(),
            });
        }
        
        // Basic RDN format check
        if !rdn.contains('=') {
            return Err(ValidationError::InvalidDn {
                dn: rdn.to_string(),
                reason: "RDN must contain '=' for attribute=value".to_string(),
            });
        }
        
        Ok(())
    }
    
    /// Validate attribute name
    fn validate_attribute_name(&self, name: &str) -> Result<(), ValidationError> {
        if name.is_empty() {
            return Err(ValidationError::InvalidAttributeName {
                name: name.to_string(),
                reason: "Attribute name cannot be empty".to_string(),
            });
        }
        
        if self.config.strict_attribute_validation {
            // RFC 4512 attribute name validation
            if !name.chars().next().unwrap().is_ascii_alphabetic() {
                return Err(ValidationError::InvalidAttributeName {
                    name: name.to_string(),
                    reason: "Attribute name must start with a letter".to_string(),
                });
            }
            
            if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return Err(ValidationError::InvalidAttributeName {
                    name: name.to_string(),
                    reason: "Attribute name can only contain letters, numbers, and hyphens".to_string(),
                });
            }
        }
        
        Ok(())
    }
    
    /// Validate attribute value
    fn validate_attribute_value(&self, attr_name: &str, value: &[u8]) -> Result<(), ValidationError> {
        // Check value length
        if value.len() > self.config.max_attribute_value_length {
            return Err(ValidationError::InvalidAttributeValue {
                name: attr_name.to_string(),
                value: format!("<{} bytes>", value.len()),
                reason: format!("Value length {} exceeds maximum {}", 
                               value.len(), 
                               self.config.max_attribute_value_length),
            });
        }
        
        // Additional attribute-specific validation could be added here
        // (e.g., email format for mail attributes, DN format for member attributes)
        
        Ok(())
    }
    
    /// Validate search filter
    fn validate_search_filter(&mut self, filter: &Filter<'_>, depth: usize) -> Result<(), ValidationError> {
        self.validation_stats.filter_validations += 1;
        
        if self.config.validate_filter_complexity {
            if depth > self.config.max_filter_depth {
                return Err(ValidationError::InvalidSearchFilter {
                    reason: format!("Filter nesting depth {} exceeds maximum {}", 
                                   depth, self.config.max_filter_depth),
                });
            }
        }
        
        match filter {
            Filter::And(filters) | Filter::Or(filters) => {
                if filters.is_empty() {
                    return Err(ValidationError::InvalidSearchFilter {
                        reason: "Boolean filter (AND/OR) cannot be empty".to_string(),
                    });
                }
                
                for sub_filter in filters {
                    self.validate_search_filter(sub_filter, depth + 1)?;
                }
            }
            Filter::Not(sub_filter) => {
                self.validate_search_filter(sub_filter, depth + 1)?;
            }
            Filter::EqualityMatch(ava) | Filter::GreaterOrEqual(ava) | Filter::LessOrEqual(ava) => {
                self.validate_attribute_name(&ava.attribute_desc.0)?;
                self.validate_attribute_value(&ava.attribute_desc.0, &ava.assertion_value)?;
            }
            Filter::Present(attr) => {
                self.validate_attribute_name(&attr.0)?;
            }
            Filter::ApproxMatch(ava) => {
                self.validate_attribute_name(&ava.attribute_desc.0)?;
                self.validate_attribute_value(&ava.attribute_desc.0, &ava.assertion_value)?;
            }
            Filter::Substrings(substring_filter) => {
                self.validate_attribute_name(&substring_filter.filter_type.0)?;
                for substring in &substring_filter.substrings {
                    match substring {
                        Substring::Initial(val) | Substring::Any(val) | Substring::Final(val) => {
                            self.validate_attribute_value(&substring_filter.filter_type.0, val.0.as_ref())?;
                        }
                    }
                }
            }
            Filter::ExtensibleMatch(_) => {
                // Extensible match filters require more complex validation
                // This is a placeholder for future implementation
                debug!("Extensible match filter validation not fully implemented");
            }
        }
        
        Ok(())
    }
    
    /// Validate modify operation
    fn validate_modify_operation(&self, change: &Change<'_>) -> Result<(), ValidationError> {
        // Validate operation type
        match change.operation.0 {
            0 => { /* Add */ }
            1 => { /* Delete */ }
            2 => { /* Replace */ }
            _ => {
                return Err(ValidationError::OperationConstraintViolation {
                    operation: "Modify".to_string(),
                    reason: format!("Invalid modify operation type: {}", change.operation.0),
                });
            }
        }
        
        // Validate attribute name
        self.validate_attribute_name(&change.modification.attr_type.0)?;
        
        // Validate attribute values
        for value in &change.modification.attr_vals {
            self.validate_attribute_value(&change.modification.attr_type.0, value.0.as_ref())?;
        }
        
        Ok(())
    }
    
    /// Validate search scope
    fn validate_search_scope(&self, scope: i32) -> Result<(), ValidationError> {
        match scope {
            0 => Ok(()), // baseObject
            1 => Ok(()), // singleLevel  
            2 => Ok(()), // wholeSubtree
            _ => Err(ValidationError::InvalidSearchScope {
                scope,
                reason: "Search scope must be 0 (base), 1 (one level), or 2 (subtree)".to_string(),
            }),
        }
    }
    
    /// Validate deref aliases parameter
    fn validate_deref_aliases(&self, deref: i32) -> Result<(), ValidationError> {
        match deref {
            0 => Ok(()), // neverDerefAliases
            1 => Ok(()), // derefInSearching
            2 => Ok(()), // derefFindingBaseObj
            3 => Ok(()), // derefAlways
            _ => Err(ValidationError::OperationConstraintViolation {
                operation: "Search".to_string(),
                reason: format!("Invalid deref aliases value: {}", deref),
            }),
        }
    }
    
    /// Validate search size and time limits
    fn validate_search_limits(&self, size_limit: i32, time_limit: i32) -> Result<(), ValidationError> {
        if self.config.max_size_limit > 0 && size_limit > self.config.max_size_limit {
            return Err(ValidationError::InvalidLimits {
                size_limit,
                time_limit,
                reason: format!("Size limit {} exceeds maximum {}", size_limit, self.config.max_size_limit),
            });
        }
        
        if self.config.max_time_limit > 0 && time_limit > self.config.max_time_limit {
            return Err(ValidationError::InvalidLimits {
                size_limit,
                time_limit,
                reason: format!("Time limit {} exceeds maximum {}", time_limit, self.config.max_time_limit),
            });
        }
        
        if size_limit < 0 || time_limit < 0 {
            return Err(ValidationError::InvalidLimits {
                size_limit,
                time_limit,
                reason: "Limits cannot be negative".to_string(),
            });
        }
        
        Ok(())
    }
    
    /// Validate OID format (basic check)
    fn validate_oid_format(&self, oid: &str) -> bool {
        // Basic OID format: series of numbers separated by dots
        // Must start and end with a number, no consecutive dots
        if oid.is_empty() || oid.starts_with('.') || oid.ends_with('.') || oid.contains("..") {
            return false;
        }
        
        oid.split('.').all(|component| {
            !component.is_empty() && component.chars().all(|c| c.is_ascii_digit())
        })
    }
    
    /// Check for unescaped special characters in DN
    fn has_unescaped_special_chars(&self, dn: &str) -> bool {
        // Simplified validation - in a real implementation we'd parse the DN properly
        // For now, we'll only flag truly problematic characters, not separators
        let problematic_chars = ['<', '>', '\0'];
        
        for ch in dn.chars() {
            if problematic_chars.contains(&ch) {
                return true;
            }
        }
        
        // Check for unbalanced quotes (simplified check)
        let quote_count = dn.chars().filter(|&c| c == '"').count();
        if quote_count % 2 != 0 {
            return true; // Unbalanced quotes
        }
        
        false
    }
}

impl Default for LdapMessageValidator {
    fn default() -> Self {
        Self::new()
    }
}

// Public convenience methods for testing and validation
impl LdapMessageValidator {
    /// Public method to validate a DN
    pub fn validate_dn_public(&mut self, dn: &str) -> Result<(), ValidationError> {
        self.validate_dn(dn)
    }
    
    /// Public method to validate an attribute name
    pub fn validate_attribute_name_public(&self, name: &str) -> Result<(), ValidationError> {
        self.validate_attribute_name(name)
    }
    
    /// Public method to validate a message ID
    pub fn validate_message_id_public(&self, message_id: u32) -> Result<(), ValidationError> {
        self.validate_message_id(message_id)
    }
    
    /// Public method to validate a search scope
    pub fn validate_search_scope_public(&self, scope: i32) -> Result<(), ValidationError> {
        self.validate_search_scope(scope)
    }
    
    /// Public method to validate OID format
    pub fn validate_oid_format_public(&self, oid: &str) -> bool {
        self.validate_oid_format(oid)
    }
}

/// Convenience function to validate a parsed LDAP message with default configuration
pub fn validate_ldap_message(message: &LdapMessage<'_>) -> Result<(), ValidationError> {
    let mut validator = LdapMessageValidator::new();
    validator.validate_message(message)
}

/// Enhanced LDAP message parsing with validation
pub fn parse_and_validate_ldap_messages<'a>(
    data: &'a [u8],
    validator: &mut LdapMessageValidator,
) -> Result<(Vec<LdapMessage<'a>>, Vec<ValidationError>), String> {
    // First parse the raw messages
    match ldap_parser::parse_ldap_messages(data) {
        Ok((remaining, messages)) => {
            // Then validate each message
            let mut validation_errors = Vec::new();
            for message in &messages {
                if let Err(validation_error) = validator.validate_message(message) {
                    validation_errors.push(validation_error);
                }
            }
            
            if !remaining.is_empty() {
                debug!("Remaining unparsed data: {} bytes", remaining.len());
            }
            
            Ok((messages, validation_errors))
        }
        Err(err) => {
            Err(format!("LDAP message parsing failed: {:?}", err))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ldap_parser::ldap::*;
    use std::borrow::Cow;

    #[test]
    fn test_message_id_validation() {
        let validator = LdapMessageValidator::new();
        
        // Valid message IDs
        assert!(validator.validate_message_id(1).is_ok());
        assert!(validator.validate_message_id(12345).is_ok());
        
        // Invalid message ID (reserved)
        assert!(validator.validate_message_id(0).is_err());
        
        // Invalid message ID (too large)
        assert!(validator.validate_message_id(u32::MAX).is_err());
    }
    
    #[test]
    fn test_dn_validation() {
        let mut validator = LdapMessageValidator::new();
        
        // Valid DNs
        assert!(validator.validate_dn("").is_ok()); // Root DSE
        assert!(validator.validate_dn("cn=test,dc=example,dc=org").is_ok());
        assert!(validator.validate_dn("uid=user,ou=people,dc=example,dc=org").is_ok());
        
        // Invalid DNs
        assert!(validator.validate_dn("invalid_dn").is_err()); // No equals sign
        let long_dn = "cn=".to_string() + &"x".repeat(10000);
        assert!(validator.validate_dn(&long_dn).is_err()); // Too long
    }
    
    #[test]
    fn test_attribute_name_validation() {
        let validator = LdapMessageValidator::new();
        
        // Valid attribute names
        assert!(validator.validate_attribute_name("cn").is_ok());
        assert!(validator.validate_attribute_name("sn").is_ok());
        assert!(validator.validate_attribute_name("mail").is_ok());
        assert!(validator.validate_attribute_name("object-class").is_ok()); // With hyphen
        
        // Invalid attribute names
        assert!(validator.validate_attribute_name("").is_err()); // Empty
        assert!(validator.validate_attribute_name("1invalid").is_err()); // Starts with number
        assert!(validator.validate_attribute_name("invalid.name").is_err()); // Contains dot
    }
    
    #[test]
    fn test_search_scope_validation() {
        let validator = LdapMessageValidator::new();
        
        // Valid scopes
        assert!(validator.validate_search_scope(0).is_ok()); // Base
        assert!(validator.validate_search_scope(1).is_ok()); // One level
        assert!(validator.validate_search_scope(2).is_ok()); // Subtree
        
        // Invalid scope
        assert!(validator.validate_search_scope(3).is_err());
        assert!(validator.validate_search_scope(-1).is_err());
    }
    
    #[test]
    fn test_oid_format_validation() {
        let validator = LdapMessageValidator::new();
        
        // Valid OIDs
        assert!(validator.validate_oid_format("1.2.3.4"));
        assert!(validator.validate_oid_format("1.3.6.1.4.1.1466.20037"));
        
        // Invalid OIDs
        assert!(!validator.validate_oid_format(""));
        assert!(!validator.validate_oid_format(".1.2.3"));
        assert!(!validator.validate_oid_format("1.2.3."));
        assert!(!validator.validate_oid_format("1..2.3"));
        assert!(!validator.validate_oid_format("1.a.3"));
    }
    
    #[test]
    fn test_validation_stats() {
        let mut validator = LdapMessageValidator::new();
        
        // Simulate some validations
        validator.validate_message_id(123).unwrap();
        validator.validate_dn("cn=test,dc=example,dc=org").unwrap();
        
        let stats = validator.stats();
        assert!(stats.dn_validations > 0);
        
        validator.reset_stats();
        let reset_stats = validator.stats();
        assert_eq!(reset_stats.dn_validations, 0);
    }
}
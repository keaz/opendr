//! Operation FSM configurations and factory for integration with LDAP operations
//!
//! This module provides configuration structures, factory methods, and backend
//! adapters for integrating operation FSMs (Search, Write, Compare, ExtendedOp)
//! with the LDAP server message processing.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use async_trait::async_trait;

use crate::backend::{DirectoryBackend, DirectoryEntry};
use crate::fsm::{
    WriteResultCode, WriteOperation,
    CompareParams, SearchParams, SearchResultCode,
};

// Import the actual SearchFsm implementation and related types
use crate::search_fsm::{
    SearchFsmImpl, SearchBackend, SearchEntry, FilterMatcher, EntryFormatter,
    SearchFsmConfig, SearchMetrics
};


use crate::write_fsm::{
    WriteFsmImpl, WriteBackend, WriteEntry, SchemaValidator,
    AciChecker, WriteMetrics, WriteFsmConfig,
};
use crate::compare_fsm::{
    CompareFsmImpl, CompareBackend, CompareEntry, AttributeComparator,
    CompareAccessControl, CompareMetrics, CompareFsmConfig,
};
use crate::extended_op_fsm::{
    ExtendedOpFsmImpl, ExtendedOpBackend, ExtendedOpParser, ExtendedOpDelegator,
    ExtendedOpAccessControl, ExtendedOpMetrics,
    ParsedOperation, ExtendedOperationType,
};

/// Configuration for operation FSM routing
#[derive(Debug, Clone)]
pub struct FsmRoutingConfig {
    /// Enable SearchFsm for search operations
    pub enable_search_fsm: bool,
    /// Enable WriteFsm for write operations (add, modify, modifyDn, delete)
    pub enable_write_fsm: bool, 
    /// Enable CompareFsm for compare operations
    pub enable_compare_fsm: bool,
    /// Enable ExtendedOpFsm for extended operations
    pub enable_extended_op_fsm: bool,
    /// Use direct handlers as fallback if FSM processing fails
    pub fallback_to_direct: bool,
}

impl Default for FsmRoutingConfig {
    fn default() -> Self {
        Self {
            enable_search_fsm: false, // Default to existing direct handlers
            enable_write_fsm: false,
            enable_compare_fsm: false,
            enable_extended_op_fsm: false,
            fallback_to_direct: true, // Allow fallback by default
        }
    }
}

/// Configuration for Extended Operation FSM
#[derive(Debug, Clone, PartialEq)]
pub struct ExtendedOpFsmConfig {
    /// Enable access control checking
    pub enable_access_control: bool,
    /// Enable metrics collection
    pub enable_metrics: bool,
    /// Maximum operation timeout
    pub operation_timeout: Duration,
    /// List of supported operation OIDs
    pub supported_operations: Vec<String>,
}

impl Default for ExtendedOpFsmConfig {
    fn default() -> Self {
        Self {
            enable_access_control: true,
            enable_metrics: false,
            operation_timeout: Duration::from_secs(30),
            supported_operations: vec![
                "1.3.6.1.4.1.4203.1.11.3".to_string(), // WhoAmI
            ],
        }
    }
}

/// Combined configuration for all operation FSMs
#[derive(Debug, Clone)]
pub struct OperationFsmConfig {
    /// Search FSM configuration
    pub search: SearchFsmConfig,
    /// Write FSM configuration
    pub write: WriteFsmConfig,
    /// Compare FSM configuration
    pub compare: CompareFsmConfig,
    /// Extended operation FSM configuration
    pub extended_op: ExtendedOpFsmConfig,
    
    /// Maximum number of concurrent operations per connection
    pub max_concurrent_operations: usize,
    /// Global timeout for operations
    pub operation_timeout: Duration,
}

impl Default for OperationFsmConfig {
    fn default() -> Self {
        Self {
            search: SearchFsmConfig::default(),
            write: WriteFsmConfig::default(),
            compare: CompareFsmConfig::default(),
            extended_op: ExtendedOpFsmConfig::default(),
            max_concurrent_operations: 10,
            operation_timeout: Duration::from_secs(60), // 1 minute default
        }
    }
}

/// Enum for storing different operation FSM instances
pub enum OperationFsmInstance {
    Search(Box<SearchFsmImpl>),
    Write(Box<WriteFsmImpl>),
    Compare(Box<CompareFsmImpl>),
    ExtendedOp(Box<ExtendedOpFsmImpl>),
}

impl OperationFsmInstance {
    /// Check if the FSM operation has timed out given elapsed time
    pub fn is_timed_out(&self, config: &OperationFsmConfig, elapsed: Duration) -> bool {
        match self {
            OperationFsmInstance::Search(fsm) => {
                // SearchFsm implements TimeoutFsm trait
                use crate::fsm::TimeoutFsm;
                if let Some(fsm_timeout) = fsm.timeout() {
                    // Use the FSM's specific timeout if it's shorter than the global timeout
                    let effective_timeout = std::cmp::min(config.operation_timeout, fsm_timeout);
                    elapsed > effective_timeout
                } else {
                    // Fall back to global timeout
                    elapsed > config.operation_timeout
                }
            },
            OperationFsmInstance::Write(_fsm) => {
                // WriteFsm timeout checking - use simple elapsed time approach
                // In a real implementation, this would check session transaction timeout
                let write_timeout = Duration::from_secs(30); // Default write timeout
                elapsed > write_timeout
            },
            OperationFsmInstance::Compare(_fsm) => {
                // CompareFsm timeout checking - use simple elapsed time
                let compare_timeout = Duration::from_secs(30); // Default compare timeout
                elapsed > compare_timeout
            },
            OperationFsmInstance::ExtendedOp(_fsm) => {
                // ExtendedOpFsm timeout checking
                // For now, we'll use the global timeout mechanism
                elapsed > config.operation_timeout
            },
        }
    }
    
    /// Get the operation type name for logging and debugging
    pub fn operation_type(&self) -> &'static str {
        match self {
            OperationFsmInstance::Search(_) => "search",
            OperationFsmInstance::Write(_) => "write",
            OperationFsmInstance::Compare(_) => "compare",
            OperationFsmInstance::ExtendedOp(_) => "extended",
        }
    }
    
    /// Check if the FSM is in a terminal state (completed, failed, etc.)
    pub fn is_terminal(&self) -> bool {
        use crate::fsm::StateMachine;
        match self {
            OperationFsmInstance::Search(fsm) => fsm.is_terminal(),
            OperationFsmInstance::Write(fsm) => fsm.is_terminal(),
            OperationFsmInstance::Compare(fsm) => fsm.is_terminal(),
            OperationFsmInstance::ExtendedOp(fsm) => fsm.is_terminal(),
        }
    }
    
    /// Get timeout duration specific to this FSM type, if any
    pub fn fsm_specific_timeout(&self) -> Option<Duration> {
        match self {
            OperationFsmInstance::Search(fsm) => {
                use crate::fsm::TimeoutFsm;
                fsm.timeout()
            },
            OperationFsmInstance::Write(fsm) => {
                // WriteFsm uses transaction timeout - use a reasonable default
                // In a real implementation, this would be configurable
                Some(Duration::from_secs(30)) // Default 30 seconds for write operations
            },
            OperationFsmInstance::Compare(fsm) => {
                // CompareFsm could have its own timeout from config
                Some(Duration::from_secs(30)) // Default 30 seconds for compare operations
            },
            OperationFsmInstance::ExtendedOp(fsm) => {
                // ExtendedOpFsm timeout from parsed operation or config
                if let Some(parsed_op) = fsm.parsed_operation() {
                    // Some extended operations might have specific timeouts
                    match parsed_op.operation_type {
                        crate::extended_op_fsm::ExtendedOperationType::WhoAmI => Some(Duration::from_secs(10)),
                        crate::extended_op_fsm::ExtendedOperationType::PasswordModify => Some(Duration::from_secs(60)),
                        crate::extended_op_fsm::ExtendedOperationType::StartTLS => Some(Duration::from_secs(30)),
                        _ => Some(Duration::from_secs(30)), // Default for custom/other operations
                    }
                } else {
                    None
                }
            },
        }
    }
}

/// Factory for creating operation FSMs with appropriate backends
pub struct FsmFactory {
    /// Directory backend for all operations
    backend: Arc<dyn DirectoryBackend>,
    /// Configuration for all FSMs
    config: OperationFsmConfig,
}

impl FsmFactory {
    /// Create a new FSM factory with the given backend and default configuration
    pub fn new(backend: Arc<dyn DirectoryBackend>) -> Self {
        Self {
            backend,
            config: OperationFsmConfig::default(),
        }
    }
    
    /// Create a new FSM factory with custom configuration
    pub fn with_config(backend: Arc<dyn DirectoryBackend>, config: OperationFsmConfig) -> Self {
        Self {
            backend,
            config,
        }
    }
    
    /// Get reference to the backend
    pub fn backend(&self) -> &Arc<dyn DirectoryBackend> {
        &self.backend
    }
    
    /// Get reference to the configuration
    pub fn config(&self) -> &OperationFsmConfig {
        &self.config
    }
    
    /// Create a new SearchFsm instance
    pub fn create_search_fsm(&self) -> Box<SearchFsmImpl> {
        let backend = Box::new(SearchBackendAdapter::new(self.backend.clone()));
        let filter_matcher = Box::new(DefaultFilterMatcher::new());
        let entry_formatter = Box::new(DefaultEntryFormatter::new());
        
        let fsm = SearchFsmImpl::with_config(
            backend,
            filter_matcher,
            entry_formatter,
            self.config.search.clone(),
        );
        
        // Optional metrics
        if self.config.search.enable_metrics {
            let metrics = Box::new(DefaultSearchMetrics::new());
            Box::new(fsm.with_metrics(metrics))
        } else {
            Box::new(fsm)
        }
    }
    
    /// Create a new WriteFsm instance
    pub fn create_write_fsm(&self) -> Box<WriteFsmImpl> {
        let backend = Box::new(WriteBackendAdapter::new(self.backend.clone()));
        let schema_validator = Box::new(DefaultSchemaValidator::new());
        let aci_checker = Box::new(DefaultAciChecker::new());
        
        let fsm = WriteFsmImpl::with_config(
            backend,
            schema_validator,
            aci_checker,
            self.config.write.clone(),
        );
        
        // Optional metrics
        if self.config.write.enable_audit_logging {
            let metrics = Box::new(DefaultWriteMetrics::new());
            Box::new(fsm.with_metrics(metrics))
        } else {
            Box::new(fsm)
        }
    }
    
    /// Create a new CompareFsm instance
    pub fn create_compare_fsm(&self) -> Box<CompareFsmImpl> {
        let backend = Box::new(CompareBackendAdapter::new(self.backend.clone()));
        let comparator = Box::new(DefaultAttributeComparator::new());
        let access_control = Box::new(DefaultCompareAccessControl::new());
        
        let fsm = CompareFsmImpl::with_config(
            backend,
            comparator,
            access_control,
            self.config.compare.clone(),
        );
        
        // Optional metrics
        if self.config.compare.enable_metrics {
            let metrics = Box::new(DefaultCompareMetrics::new());
            Box::new(fsm.with_metrics(metrics))
        } else {
            Box::new(fsm)
        }
    }
    
    /// Create a new ExtendedOpFsm instance
    pub fn create_extended_op_fsm(&self) -> Box<ExtendedOpFsmImpl> {
        let backend = Box::new(ExtendedOpBackendAdapter::new(self.backend.clone()));
        let parser = Box::new(DefaultExtendedOpParser::new());
        let delegator = Box::new(DefaultExtendedOpDelegator::new());
        let access_control = Box::new(DefaultExtendedOpAccessControl::new());
        let metrics = Box::new(DefaultExtendedOpMetrics::new());
        
        Box::new(ExtendedOpFsmImpl::new(
            backend,
            parser,
            delegator,
            access_control,
            metrics,
        ))
    }
}

//=============================================================================
// Backend Adapters
//=============================================================================

/// Search backend adapter that bridges DirectoryBackend to SearchBackend
pub struct SearchBackendAdapter {
    backend: Arc<dyn DirectoryBackend>,
}

impl SearchBackendAdapter {
    /// Create a new search backend adapter
    pub fn new(backend: Arc<dyn DirectoryBackend>) -> Self {
        Self { backend }
    }
    
    /// Convert DirectoryEntry to SearchEntry
    fn convert_to_search_entry(&self, entry: DirectoryEntry, attributes: &[String]) -> SearchEntry {
        let mut search_entry = SearchEntry::new(entry.dn.clone());
        
        // Copy object classes from attributes (case insensitive)
        let object_classes = entry.attributes.get("objectClass")
            .or_else(|| entry.attributes.get("objectclass"))
            .or_else(|| entry.attributes.get("OBJECTCLASS"));
            
        if let Some(object_classes) = object_classes {
            search_entry.set_object_classes(object_classes.clone());
        }
        
        // Copy attributes (only requested ones if specified)
        let include_all = attributes.is_empty();
        
        for (name, values) in &entry.attributes {
            if include_all || attributes.iter().any(|a| a.eq_ignore_ascii_case(name)) {
                // SearchEntry expects Vec<String> for attributes
                search_entry.add_attribute(name.clone(), values.clone());
            }
        }
        
        search_entry
    }
    
    /// Check if entry matches LDAP filter
    fn entry_matches_filter(&self, entry: &DirectoryEntry, filter: &str) -> bool {
        // Basic filter matching logic
        // In a real implementation, this would parse and evaluate the filter expression
        
        // For now, handle some basic cases
        if filter == "(objectClass=*)" || filter == "*" {
            return true;
        }
        
        // Simple equality match: (attr=value)
        if filter.starts_with('(') && filter.ends_with(')') {
            let inner = &filter[1..filter.len() - 1];
            if let Some(equals_pos) = inner.find('=') {
                let attr = &inner[0..equals_pos];
                let value = &inner[equals_pos + 1..];
                
                if let Some(attr_values) = entry.attributes.get(attr) {
                    return attr_values.iter().any(|v| v == value);
                }
            }
        }
        
        // Default to true for testing
        // In production, add proper filter parsing and evaluation
        true
    }
}

#[async_trait]
impl SearchBackend for SearchBackendAdapter {
    async fn find_candidates(&self, base_dn: &str, scope: i32, filter: &str) -> Result<Vec<String>, String> {
        // Convert scope to LDAP SearchScope
        let ldap_scope = match scope {
            0 => ldap_parser::ldap::SearchScope(0), // Base
            1 => ldap_parser::ldap::SearchScope(1), // OneLevel
            2 => ldap_parser::ldap::SearchScope(2), // Subtree
            _ => return Err(format!("Invalid search scope: {}", scope)),
        };
        
        // Perform search using DirectoryBackend
        match self.backend.search_entries(base_dn, ldap_scope).await {
            Ok(entries) => {
                // Filter entries and extract DNs
                let candidates: Vec<String> = entries.iter()
                    .filter(|entry| self.entry_matches_filter(entry, filter))
                    .map(|entry| entry.dn.clone())
                    .collect();
                
                Ok(candidates)
            },
            Err(e) => Err(e.to_string()),
        }
    }
    
    async fn get_entry(&self, dn: &str, attributes: &[String]) -> Result<Option<SearchEntry>, String> {
        match self.backend.get_entry(dn).await {
            Ok(Some(entry)) => {
                let search_entry = self.convert_to_search_entry(entry, attributes);
                Ok(Some(search_entry))
            },
            Ok(None) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }
}

/// Write backend adapter that bridges DirectoryBackend to WriteBackend
pub struct WriteBackendAdapter {
    backend: Arc<dyn DirectoryBackend>,
}

impl WriteBackendAdapter {
    /// Create a new write backend adapter
    pub fn new(backend: Arc<dyn DirectoryBackend>) -> Self {
        Self { backend }
    }
    
    /// Convert WriteEntry to DirectoryEntry
    fn convert_to_directory_entry(&self, write_entry: &WriteEntry) -> (DirectoryEntry, Vec<u8>) {
        let mut attributes = HashMap::new();
        let mut password = Vec::new();
        
        // Copy text attributes
        for (name, values) in &write_entry.attributes {
            attributes.insert(name.clone(), values.clone());
        }
        
        // Handle binary attributes (special case for userPassword)
        for (name, values) in &write_entry.binary_attributes {
            if name.eq_ignore_ascii_case("userPassword") && !values.is_empty() {
                password = values[0].clone();
            }
        }
        
        (DirectoryEntry::new(&write_entry.dn, attributes), password)
    }
    
    /// Parse LDIF data into WriteEntry
    fn parse_ldif(&self, dn: &str, ldif: &[u8]) -> Result<WriteEntry, String> {
        // Basic LDIF parsing - in production, use a proper LDIF parser
        let ldif_str = String::from_utf8_lossy(ldif);
        let mut entry = WriteEntry::new(dn.to_string());
        
        for line in ldif_str.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            
            if let Some(pos) = line.find(':') {
                let attr = line[0..pos].trim();
                let value = line[pos+1..].trim();
                
                if attr.eq_ignore_ascii_case("objectClass") {
                    entry.object_classes.push(value.to_string());
                } else if attr.eq_ignore_ascii_case("userPassword") {
                    // Handle password specially
                    let password_bytes = value.as_bytes().to_vec();
                    entry.add_binary_attribute(attr.to_string(), vec![password_bytes]);
                } else {
                    // Regular attribute
                    if let Some(values) = entry.attributes.get_mut(attr) {
                        values.push(value.to_string());
                    } else {
                        entry.add_attribute(attr.to_string(), vec![value.to_string()]);
                    }
                }
            }
        }
        
        Ok(entry)
    }
}

#[async_trait]
impl WriteBackend for WriteBackendAdapter {
    async fn begin_transaction(&self) -> Result<String, String> {
        // Most simple backends don't have transactions, so generate a fake ID
        Ok(format!("tx-{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()))
    }
    
    async fn commit_transaction(&self, _txn_id: &str) -> Result<(), String> {
        // Simple implementation - real backends would commit here
        Ok(())
    }
    
    async fn rollback_transaction(&self, _txn_id: &str, _reason: &str) -> Result<(), String> {
        // Simple implementation - real backends would rollback here
        Ok(())
    }
    
    async fn validate_entry(&self, dn: &str, entry: &[u8]) -> Result<(), String> {
        // Basic validation
        if dn.is_empty() {
            return Err("Empty DN is not allowed".to_string());
        }
        
        if !dn.contains('=') {
            return Err("Invalid DN format".to_string());
        }
        
        Ok(())
    }
    
    async fn add_entry(&self, _txn_id: &str, dn: &str, entry: &[u8]) -> Result<(), String> {
        // Parse the entry
        let write_entry = self.parse_ldif(dn, entry)?;
        let (directory_entry, password) = self.convert_to_directory_entry(&write_entry);
        
        // Use backend to add entry
        match self.backend.add_entry(directory_entry, password).await {
            Ok(()) => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }
    
    async fn modify_entry(&self, _txn_id: &str, dn: &str, modifications: &[crate::write_fsm::Modification]) -> Result<(), String> {
        // Convert to backend Modification type
        let backend_mods: Vec<crate::backend::Modification> = modifications.iter().map(|m| {
            let operation = match m {
                crate::write_fsm::Modification::Add { .. } => crate::backend::ModifyOperation::Add,
                crate::write_fsm::Modification::Delete { .. } => crate::backend::ModifyOperation::Delete,
                crate::write_fsm::Modification::Replace { .. } => crate::backend::ModifyOperation::Replace,
            };
            
            let (name, values) = match m {
                crate::write_fsm::Modification::Add { name, values } => (name, values),
                crate::write_fsm::Modification::Delete { name, values } => (name, values),
                crate::write_fsm::Modification::Replace { name, values } => (name, values),
            };
            
            crate::backend::Modification {
                operation,
                attribute: name.clone(),
                values: values.clone(),
            }
        }).collect();
        
        // Use backend to modify entry
        match self.backend.modify_entry(dn, backend_mods).await {
            Ok(()) => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }
    
    async fn modify_dn(&self, _txn_id: &str, dn: &str, new_rdn: &str, delete_old: bool, new_superior: Option<&str>) -> Result<(), String> {
        let superior = new_superior.map(|s| s.to_string());
        
        // Use backend to rename entry
        match self.backend.rename_entry(dn, new_rdn, delete_old, superior).await {
            Ok(()) => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }
    
    async fn delete_entry(&self, _txn_id: &str, dn: &str) -> Result<(), String> {
        // Use backend to delete entry
        match self.backend.delete_entry(dn).await {
            Ok(()) => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }
    
    async fn entry_exists(&self, dn: &str) -> Result<bool, String> {
        // Check if entry exists
        match self.backend.get_entry(dn).await {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(e) => Err(e.to_string()),
        }
    }
}

/// Compare backend adapter that bridges DirectoryBackend to CompareBackend
pub struct CompareBackendAdapter {
    backend: Arc<dyn DirectoryBackend>,
}

impl CompareBackendAdapter {
    /// Create a new compare backend adapter
    pub fn new(backend: Arc<dyn DirectoryBackend>) -> Self {
        Self { backend }
    }
    
    /// Convert DirectoryEntry to CompareEntry
    fn convert_to_compare_entry(&self, entry: DirectoryEntry, attributes: &[String]) -> CompareEntry {
        let mut compare_entry = CompareEntry::new(entry.dn);
        
        // Set object classes
        if let Some(object_classes) = entry.attributes.get("objectClass") {
            compare_entry.set_object_classes(object_classes.clone());
        }
        
        // Add requested attributes or all if empty
        let include_all = attributes.is_empty();
        
        for (name, values) in entry.attributes {
            if include_all || attributes.iter().any(|a| a.eq_ignore_ascii_case(&name)) {
                // Convert string values to bytes
                let binary_values: Vec<Vec<u8>> = values.iter()
                    .map(|v| v.as_bytes().to_vec())
                    .collect();
                
                compare_entry.add_attribute(name, binary_values);
            }
        }
        
        compare_entry
    }
}

#[async_trait]
impl CompareBackend for CompareBackendAdapter {
    async fn get_entry_attributes(&self, dn: &str, attributes: &[String]) -> Result<Option<CompareEntry>, String> {
        match self.backend.get_entry(dn).await {
            Ok(Some(entry)) => {
                let compare_entry = self.convert_to_compare_entry(entry, attributes);
                Ok(Some(compare_entry))
            },
            Ok(None) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }
}

/// Extended operation backend adapter that bridges DirectoryBackend to ExtendedOpBackend
pub struct ExtendedOpBackendAdapter {
    backend: Arc<dyn DirectoryBackend>,
}

impl ExtendedOpBackendAdapter {
    /// Create a new extended op backend adapter
    pub fn new(backend: Arc<dyn DirectoryBackend>) -> Self {
        Self { backend }
    }
}

#[async_trait]
impl ExtendedOpBackend for ExtendedOpBackendAdapter {
    async fn execute_operation(&self, oid: &str, value: Option<&[u8]>) -> Result<Vec<u8>, String> {
        // Handle supported operations
        match oid {
            "1.3.6.1.4.1.4203.1.11.3" => {
                // WhoAmI extended operation (RFC 4532)
                // Returns the authenticated DN
                
                // Get user info if needed for advanced operations
                // For now, just return a basic response
                Ok(b"dn:".to_vec())
            },
            _ => Err(format!("Unsupported extended operation: {}", oid)),
        }
    }
    
    fn is_operation_supported(&self, oid: &str) -> bool {
        matches!(oid, 
            // List of supported operations
            "1.3.6.1.4.1.4203.1.11.3" // WhoAmI
        )
    }
    
    fn requires_delegation(&self, oid: &str) -> bool {
        matches!(oid,
            // Operations requiring delegation
            "1.3.6.1.1.7.1" | // StartTLS
            "1.3.6.1.4.1.1466.20037" // StartTLS (old)
        )
    }
}

//=============================================================================
// Default implementations for FSM-specific traits
//=============================================================================

/// Default filter matcher for search operations
pub struct DefaultFilterMatcher;

impl DefaultFilterMatcher {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl FilterMatcher for DefaultFilterMatcher {
    async fn matches_filter(&self, entry: &SearchEntry, filter: &str) -> Result<bool, String> {
        // Basic filter matching implementation
        // In production, this would be a full LDAP filter parser and evaluator
        
        if filter == "(objectClass=*)" || filter == "*" {
            return Ok(true);
        }
        
        // Simple equality match: (attr=value)
        if filter.starts_with('(') && filter.ends_with(')') {
            let inner = &filter[1..filter.len() - 1];
            if let Some(equals_pos) = inner.find('=') {
                let attr = &inner[0..equals_pos];
                let value = &inner[equals_pos + 1..];
                
                // SearchEntry from search_fsm has attributes as HashMap<String, Vec<String>>
                if let Some(attr_values) = entry.get_attribute(attr) {
                    return Ok(attr_values.iter().any(|v| v == value));
                }
            }
        }
        
        // Default to false for non-matching filters
        Ok(false)
    }
    
    async fn validate_filter(&self, filter: &str) -> Result<(), String> {
        if filter.is_empty() {
            return Err("Filter cannot be empty".to_string());
        }
        Ok(())
    }
}

/// Default entry formatter for search results
pub struct DefaultEntryFormatter;

impl DefaultEntryFormatter {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl EntryFormatter for DefaultEntryFormatter {
    async fn format_entry(&self, entry: &SearchEntry, requested_attributes: &[String]) -> Result<Vec<u8>, String> {
        // Simple LDIF formatting
        let mut result = format!("dn: {}\n", entry.dn);
        
        // Include object classes
        for oc in &entry.object_classes {
            result.push_str(&format!("objectClass: {}\n", oc));
        }
        
        // Handle attribute selection - SearchEntry from search_fsm has Vec<String> values
        let include_all = requested_attributes.is_empty();
        
        for (name, values) in &entry.attributes {
            if include_all || requested_attributes.iter().any(|a| a.eq_ignore_ascii_case(name)) {
                for value in values {
                    result.push_str(&format!("{}: {}\n", name, value));
                }
            }
        }
        
        result.push('\n'); // Empty line to separate entries
        Ok(result.into_bytes())
    }
    
    async fn calculate_entry_size(&self, entry: &SearchEntry, requested_attributes: &[String]) -> Result<usize, String> {
        let formatted = self.format_entry(entry, requested_attributes).await?;
        Ok(formatted.len())
    }
}

/// Default schema validator (minimal implementation)
pub struct DefaultSchemaValidator;

impl DefaultSchemaValidator {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl SchemaValidator for DefaultSchemaValidator {
    async fn validate_entry(&self, entry: &WriteEntry) -> Result<(), String> {
        // Basic validation - check required attributes
        if entry.object_classes.is_empty() {
            return Err("Entry must have at least one objectClass".to_string());
        }
        
        Ok(())
    }
    
    async fn validate_modifications(&self, _dn: &str, modifications: &[crate::write_fsm::Modification]) -> Result<(), String> {
        // Basic validation - check for empty modifications
        if modifications.is_empty() {
            return Err("No modifications specified".to_string());
        }
        
        Ok(())
    }
}

/// Default ACI checker (allows all operations)
pub struct DefaultAciChecker;

impl DefaultAciChecker {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl AciChecker for DefaultAciChecker {
    async fn check_write_permission(&self, _user_dn: Option<&str>, _operation: &WriteOperation) -> Result<(), String> {
        // Allow all operations in this basic implementation
        Ok(())
    }
}

/// Default write metrics implementation
pub struct DefaultWriteMetrics;

impl DefaultWriteMetrics {
    pub fn new() -> Self {
        Self
    }
}

impl WriteMetrics for DefaultWriteMetrics {
    fn record_write_start(&self, user_dn: Option<&str>, operation: &WriteOperation) {
        // Log the operation start
        log::debug!("Write operation started by {:?}: {:?}", user_dn, operation);
    }
    
    fn record_validation_complete(&self, operation_type: &str, duration: Duration) {
        log::debug!("Validation complete for {}: {:?}", operation_type, duration);
    }
    
    fn record_schema_check_complete(&self, operation_type: &str, duration: Duration) {
        log::debug!("Schema check complete for {}: {:?}", operation_type, duration);
    }
    
    fn record_aci_check_complete(&self, operation_type: &str, duration: Duration) {
        log::debug!("ACI check complete for {}: {:?}", operation_type, duration);
    }
    
    fn record_transaction_started(&self, txn_id: &str) {
        log::debug!("Transaction started: {}", txn_id);
    }
    
    fn record_write_complete(&self, operation: &WriteOperation, result_code: &WriteResultCode, duration: Duration) {
        log::debug!("Write operation complete: {:?}, result: {:?}, duration: {:?}", operation, result_code, duration);
    }
    
    fn record_write_rollback(&self, operation: &WriteOperation, reason: &str) {
        log::warn!("Write operation rolled back: {:?}, reason: {}", operation, reason);
    }
}

/// Default attribute comparator
pub struct DefaultAttributeComparator;

impl DefaultAttributeComparator {
    pub fn new() -> Self {
        Self
    }
    
    /// Determine if an attribute should be compared case-insensitively
    fn is_case_insensitive(&self, attr_name: &str) -> bool {
        // Most directory attributes are case-insensitive
        // Binary attributes like userPassword should be case-sensitive
        match attr_name.to_lowercase().as_str() {
            "userpassword" | "userCertificate" | "jpegPhoto" => false,
            _ => true,
        }
    }
}

#[async_trait]
impl AttributeComparator for DefaultAttributeComparator {
    async fn compare_attribute(&self, entry: &CompareEntry, attr_name: &str, value: &[u8]) -> Result<bool, String> {
        if let Some(attr_values) = entry.get_attribute(attr_name) {
            // Check case sensitivity based on attribute type
            let is_case_insensitive = self.is_case_insensitive(attr_name);
            
            for attr_value in attr_values {
                if is_case_insensitive {
                    // Case-insensitive string comparison
                    if let (Ok(str1), Ok(str2)) = (std::str::from_utf8(attr_value), std::str::from_utf8(value)) {
                        if str1.eq_ignore_ascii_case(str2) {
                            return Ok(true);
                        }
                    }
                } else {
                    // Exact binary comparison
                    if attr_value == value {
                        return Ok(true);
                    }
                }
            }
            
            // No match found
            Ok(false)
        } else {
            // Attribute not present
            Ok(false)
        }
    }
}

/// Default compare access control
pub struct DefaultCompareAccessControl;

impl DefaultCompareAccessControl {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl CompareAccessControl for DefaultCompareAccessControl {
    async fn check_compare_permission(&self, _user_dn: Option<&str>, _entry_dn: &str, _attribute: &str) -> Result<(), String> {
        // Allow all operations in this basic implementation
        Ok(())
    }
}

/// Default compare metrics
pub struct DefaultCompareMetrics;

impl DefaultCompareMetrics {
    pub fn new() -> Self {
        Self
    }
}

impl CompareMetrics for DefaultCompareMetrics {
    fn record_compare_start(&self, params: &CompareParams, user_dn: Option<&str>) {
        log::debug!("Compare operation started by {:?}: {:?}", user_dn, params);
    }
    
    fn record_entry_read(&self, dn: &str, found: bool, duration: Duration) {
        log::debug!("Entry read for compare: {}, found: {}, duration: {:?}", dn, found, duration);
    }
    
    fn record_comparison_complete(&self, attribute: &str, result: bool, duration: Duration) {
        log::debug!("Comparison complete for {}: {}, duration: {:?}", attribute, result, duration);
    }
    
    fn record_compare_complete(&self, result: bool, duration: Duration) {
        log::debug!("Compare operation complete: {}, duration: {:?}", result, duration);
    }
    
    fn record_compare_error(&self, error_type: &str, duration: Duration) {
        log::warn!("Compare operation error: {}, duration: {:?}", error_type, duration);
    }
}

/// Default extended operation parser
pub struct DefaultExtendedOpParser;

impl DefaultExtendedOpParser {
    pub fn new() -> Self {
        Self
    }
}

impl ExtendedOpParser for DefaultExtendedOpParser {
    fn parse_request(&self, oid: &str, _value: Option<&[u8]>) -> Result<ParsedOperation, String> {
        // Basic parsing based on OID
        let operation_type = match oid {
            "1.3.6.1.4.1.4203.1.11.3" => ExtendedOperationType::WhoAmI,
            _ => ExtendedOperationType::Custom(oid.to_string()),
        };
        
        let mut parameters = HashMap::new();
        
        // For custom operations, you could parse the value based on operation type
        
        Ok(ParsedOperation {
            oid: oid.to_string(),
            operation_type,
            parameters,
            requires_delegation: false,
        })
    }
    
    fn validate_operation(&self, operation: &ParsedOperation) -> Result<(), String> {
        // Basic validation
        match operation.operation_type {
            ExtendedOperationType::StartTLS => {
                // TLS would need delegation to TLS handler
                Ok(())
            },
            ExtendedOperationType::WhoAmI => {
                // No special validation needed
                Ok(())
            },
            ExtendedOperationType::Custom(ref oid) => {
                // Unknown operation
                Err(format!("Unsupported extended operation: {}", oid))
            },
            _ => Ok(()),
        }
    }
}

/// Default extended operation delegator
pub struct DefaultExtendedOpDelegator;

impl DefaultExtendedOpDelegator {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ExtendedOpDelegator for DefaultExtendedOpDelegator {
    async fn delegate_operation(&self, operation: &ParsedOperation) -> Result<Vec<u8>, String> {
        // In a real implementation, this would delegate to external handlers
        match operation.operation_type {
            ExtendedOperationType::StartTLS => {
                Err("StartTLS delegation not implemented".to_string())
            },
            _ => Err(format!("No delegate available for operation: {}", operation.oid)),
        }
    }
    
    fn get_delegates(&self, oid: &str) -> Vec<String> {
        // Return available delegates for operation
        match oid {
            "1.3.6.1.1.7.1" => vec!["tls_handler".to_string()],
            _ => Vec::new(),
        }
    }
}

/// Default extended operation access control
pub struct DefaultExtendedOpAccessControl;

impl DefaultExtendedOpAccessControl {
    pub fn new() -> Self {
        Self
    }
}

impl ExtendedOpAccessControl for DefaultExtendedOpAccessControl {
    fn check_permission(&self, _oid: &str, _user_dn: Option<&str>) -> Result<(), String> {
        // Allow all operations in this basic implementation
        Ok(())
    }
}

/// Default extended operation metrics
pub struct DefaultExtendedOpMetrics;

impl DefaultExtendedOpMetrics {
    pub fn new() -> Self {
        Self
    }
}

impl ExtendedOpMetrics for DefaultExtendedOpMetrics {
    fn record_operation_start(&self, oid: &str) {
        log::debug!("Extended operation started: {}", oid);
    }
    
    fn record_operation_complete(&self, oid: &str, success: bool, duration_ms: u64) {
        log::debug!("Extended operation complete: {}, success: {}, duration: {}ms", oid, success, duration_ms);
    }
    
    fn record_delegation(&self, oid: &str, delegate: &str) {
        log::debug!("Extended operation delegated: {} to {}", oid, delegate);
    }
}

/// Helper function to format a filter for logging
pub fn format_filter(filter: &ldap_parser::filter::Filter) -> String {
    // Simple filter formatting
    match filter {
        ldap_parser::filter::Filter::And(filters) => {
            let inner: Vec<String> = filters.iter().map(format_filter).collect();
            format!("(&{})", inner.join(""))
        },
        ldap_parser::filter::Filter::Or(filters) => {
            let inner: Vec<String> = filters.iter().map(format_filter).collect();
            format!("(|{})", inner.join(""))
        },
        ldap_parser::filter::Filter::Not(filter) => {
            format!("(!{})", format_filter(filter))
        },
        ldap_parser::filter::Filter::EqualityMatch(ava) => {
            let value = String::from_utf8_lossy(ava.assertion_value);
            format!("({}={})", ava.attribute_desc.0, value)
        },
        ldap_parser::filter::Filter::Present(attr) => {
            format!("({}=*)", attr.0)
        },
        _ => "(unimplemented-filter)".to_string(),
    }
}

/// Helper function to convert LDAP message filter to string
pub fn ldap_filter_to_string(filter: &ldap_parser::filter::Filter) -> String {
    format_filter(filter)
}

/// Default search metrics for search operations
pub struct DefaultSearchMetrics;

impl DefaultSearchMetrics {
    pub fn new() -> Self {
        Self
    }
}

impl SearchMetrics for DefaultSearchMetrics {
    fn record_search_start(&self, params: &SearchParams) {
        log::debug!("Search operation started: base_dn={}, scope={}, filter={}", 
                   params.base_dn, params.scope, params.filter);
    }
    
    fn record_candidates_found(&self, count: usize) {
        log::debug!("Search candidates found: {}", count);
    }
    
    fn record_entry_processed(&self, dn: &str, matched: bool) {
        log::debug!("Search entry processed: {}, matched: {}", dn, matched);
    }
    
    fn record_search_complete(&self, result_code: &SearchResultCode, entries_sent: usize, duration: Duration) {
        log::debug!("Search operation complete: result={:?}, entries_sent={}, duration={:?}", 
                   result_code, entries_sent, duration);
    }
    
    fn record_search_abandoned(&self) {
        log::debug!("Search operation abandoned");
    }
}


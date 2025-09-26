//! Search Finite State Machine Implementation
//!
//! This module implements a comprehensive Search FSM for LDAP search operations.
//! The FSM manages the complete search lifecycle including candidate finding,
//! entry iteration, result emission, and proper handling of abandon, timeout,
//! and size limit constraints.
//!
//! ## Search Operation Flow
//!
//! ```text
//! Initializing -> FindingCandidates -> Iterating -> EmittingEntries -> Completed
//!      |               |                  |  ^           |              ^
//!      |               |                  |  |           |              |
//!      v               v                  v  |           v              |
//!  Abandoned     TimeLimitExceeded   SizeLimitExceeded   |              |
//!      ^               ^                  ^              |              |
//!      |               |                  |              |              |
//!      +---------------+------------------+--------------+--------------+
//!                      |                                 |
//!                      +-- Abandon Event ----------------+
//! ```
//!
//! ## Supported Search Features
//!
//! The FSM supports comprehensive LDAP search operations:
//! - **Base, OneLevel, Subtree scope** search operations
//! - **Complex filter evaluation** with attribute matching
//! - **Attribute selection** and result projection
//! - **Size and time limits** with proper constraint handling
//! - **Search abandonment** with clean resource cleanup
//! - **Pagination support** for large result sets
//!
//! ## External Dependencies
//!
//! The FSM abstracts external dependencies through traits:
//! - `SearchBackend`: Entry retrieval and candidate finding
//! - `FilterMatcher`: LDAP filter evaluation
//! - `EntryFormatter`: Result encoding and attribute projection
//! - `SearchMetrics`: Statistics and performance tracking
//!
//! ## Usage Example
//!
//! ```rust,no_run
//! use opendr::search_fsm::*;
//! use opendr::fsm::{StateMachine, SearchState, SearchEvent};
//! 
//! # struct MockSearchBackend;
//! # #[async_trait::async_trait]
//! # impl SearchBackend for MockSearchBackend {
//! #     async fn find_candidates(&self, _base_dn: &str, _scope: i32, _filter: &str) -> Result<Vec<String>, String> {
//! #         Ok(vec!["cn=user1,dc=example,dc=org".to_string()])
//! #     }
//! #     async fn get_entry(&self, _dn: &str, _attributes: &[String]) -> Result<Option<SearchEntry>, String> {
//! #         Ok(None)
//! #     }
//! # }
//! #
//! # struct MockFilterMatcher;
//! # #[async_trait::async_trait]
//! # impl FilterMatcher for MockFilterMatcher {
//! #     async fn matches_filter(&self, _entry: &SearchEntry, _filter: &str) -> Result<bool, String> {
//! #         Ok(true)
//! #     }
//! # }
//! #
//! # struct MockEntryFormatter;
//! # #[async_trait::async_trait]
//! # impl EntryFormatter for MockEntryFormatter {
//! #     async fn format_entry(&self, _entry: &SearchEntry, _attributes: &[String]) -> Result<Vec<u8>, String> {
//! #         Ok(vec![])
//! #     }
//! # }
//! #
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let backend = Box::new(MockSearchBackend);
//! let filter_matcher = Box::new(MockFilterMatcher);
//! let entry_formatter = Box::new(MockEntryFormatter);
//! 
//! let mut fsm = SearchFsmImpl::new(backend, filter_matcher, entry_formatter);
//! 
//! // Start search operation
//! let result = fsm.handle_event(SearchEvent::StartSearch {
//!     base_dn: "dc=example,dc=org".to_string(),
//!     scope: 2, // Subtree search
//!     filter: "(objectClass=person)".to_string(),
//!     attributes: vec!["cn".to_string(), "mail".to_string()],
//!     size_limit: 100,
//!     time_limit: 30,
//! }).await?;
//! # Ok(())
//! # }
//! ```

use crate::fsm::{StateMachine, SearchFsm, SearchState, SearchEvent, SearchResultCode, SearchParams, AbandonableFsm, TimeoutFsm};
use async_trait::async_trait;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use thiserror::Error;

/// Errors that can occur during search operations
#[derive(Error, Debug, Clone, PartialEq)]
pub enum SearchFsmError {
    #[error("Invalid search parameters: {message}")]
    InvalidParameters { message: String },
    
    #[error("Search backend error: {message}")]
    BackendError { message: String },
    
    #[error("Filter evaluation error: {message}")]
    FilterError { message: String },
    
    #[error("Entry formatting error: {message}")]
    FormattingError { message: String },
    
    #[error("Search operation abandoned")]
    Abandoned,
    
    #[error("Search time limit exceeded")]
    TimeLimitExceeded,
    
    #[error("Search size limit exceeded")]
    SizeLimitExceeded,
    
    #[error("Invalid state transition from {from:?} to {to:?}")]
    InvalidStateTransition { from: SearchState, to: SearchState },
    
    #[error("No active search session")]
    NoActiveSearch,
    
    #[error("Generic search error: {message}")]
    Generic { message: String },
}

/// Represents an LDAP entry for search operations
#[derive(Debug, Clone, PartialEq)]
pub struct SearchEntry {
    /// Distinguished Name of the entry
    pub dn: String,
    /// Entry attributes as key-value pairs
    pub attributes: HashMap<String, Vec<String>>,
    /// Entry object classes
    pub object_classes: Vec<String>,
}

impl SearchEntry {
    /// Create a new search entry
    /// 
    /// # Arguments
    /// * `dn` - Distinguished name of the entry
    /// 
    /// # Returns
    /// * New SearchEntry instance
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
    /// * `values` - Attribute values
    pub fn add_attribute(&mut self, name: String, values: Vec<String>) {
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
    /// * `name` - Attribute name
    /// 
    /// # Returns
    /// * Option containing attribute values if found
    pub fn get_attribute(&self, name: &str) -> Option<&Vec<String>> {
        self.attributes.get(name)
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
}

/// Trait for backend search operations
/// 
/// This trait abstracts the directory backend, allowing different
/// storage implementations to be used with the Search FSM.
#[async_trait]
pub trait SearchBackend: Send + Sync {
    /// Find candidate entries for a search operation
    /// 
    /// # Arguments
    /// * `base_dn` - Base DN for search
    /// * `scope` - Search scope (0=base, 1=onelevel, 2=subtree)
    /// * `filter` - LDAP filter string
    /// 
    /// # Returns
    /// * `Ok(Vec<String>)` - List of candidate entry DNs
    /// * `Err(String)` - Error message if operation fails
    async fn find_candidates(&self, base_dn: &str, scope: i32, filter: &str) -> Result<Vec<String>, String>;
    
    /// Retrieve a specific entry with requested attributes
    /// 
    /// # Arguments
    /// * `dn` - Distinguished name of entry to retrieve
    /// * `attributes` - List of attributes to include (empty = all attributes)
    /// 
    /// # Returns
    /// * `Ok(Some(SearchEntry))` - Entry if found
    /// * `Ok(None)` - Entry not found
    /// * `Err(String)` - Error message if operation fails
    async fn get_entry(&self, dn: &str, attributes: &[String]) -> Result<Option<SearchEntry>, String>;
    
    /// Check if an entry exists
    /// 
    /// # Arguments
    /// * `dn` - Distinguished name to check
    /// 
    /// # Returns
    /// * `Ok(true)` - Entry exists
    /// * `Ok(false)` - Entry does not exist
    /// * `Err(String)` - Error message if check fails
    async fn entry_exists(&self, dn: &str) -> Result<bool, String> {
        match self.get_entry(dn, &[]).await? {
            Some(_) => Ok(true),
            None => Ok(false),
        }
    }
    
    /// Get search statistics (for optimization)
    /// 
    /// # Arguments
    /// * `base_dn` - Base DN for statistics
    /// 
    /// # Returns
    /// * (estimated_entries, estimated_depth)
    async fn get_search_stats(&self, base_dn: &str) -> Result<(usize, usize), String> {
        // Default implementation returns conservative estimates
        Ok((1000, 10))
    }
}

/// Trait for LDAP filter evaluation
/// 
/// This trait abstracts filter matching logic, allowing different
/// filter implementations and optimizations.
#[async_trait]
pub trait FilterMatcher: Send + Sync {
    /// Evaluate if an entry matches an LDAP filter
    /// 
    /// # Arguments
    /// * `entry` - Entry to evaluate
    /// * `filter` - LDAP filter string
    /// 
    /// # Returns
    /// * `Ok(true)` - Entry matches filter
    /// * `Ok(false)` - Entry does not match filter
    /// * `Err(String)` - Error message if evaluation fails
    async fn matches_filter(&self, entry: &SearchEntry, filter: &str) -> Result<bool, String>;
    
    /// Validate filter syntax
    /// 
    /// # Arguments
    /// * `filter` - LDAP filter string to validate
    /// 
    /// # Returns
    /// * `Ok(())` - Filter is valid
    /// * `Err(String)` - Error message if filter is invalid
    async fn validate_filter(&self, filter: &str) -> Result<(), String> {
        // Default implementation accepts all filters
        Ok(())
    }
    
    /// Extract indexed attributes from filter (for optimization)
    /// 
    /// # Arguments
    /// * `filter` - LDAP filter string
    /// 
    /// # Returns
    /// * List of attribute names that could benefit from indexing
    fn extract_indexed_attributes(&self, _filter: &str) -> Vec<String> {
        // Default implementation returns empty list
        Vec::new()
    }
}

/// Trait for formatting search result entries
/// 
/// This trait abstracts entry encoding and attribute projection,
/// allowing different output formats and attribute handling.
#[async_trait]
pub trait EntryFormatter: Send + Sync {
    /// Format an entry for transmission to client
    /// 
    /// # Arguments
    /// * `entry` - Entry to format
    /// * `requested_attributes` - Attributes requested by client
    /// 
    /// # Returns
    /// * `Ok(Vec<u8>)` - Encoded entry data
    /// * `Err(String)` - Error message if formatting fails
    async fn format_entry(&self, entry: &SearchEntry, requested_attributes: &[String]) -> Result<Vec<u8>, String>;
    
    /// Calculate formatted entry size (for size limit checks)
    /// 
    /// # Arguments
    /// * `entry` - Entry to measure
    /// * `requested_attributes` - Attributes that would be included
    /// 
    /// # Returns
    /// * Estimated size in bytes
    async fn calculate_entry_size(&self, entry: &SearchEntry, requested_attributes: &[String]) -> Result<usize, String> {
        // Default implementation estimates based on attribute count and values
        let mut size = entry.dn.len() + 50; // DN + overhead
        
        for (name, values) in &entry.attributes {
            if requested_attributes.is_empty() || requested_attributes.contains(name) {
                size += name.len() + 10; // Attribute name + overhead
                for value in values {
                    size += value.len() + 5; // Value + overhead
                }
            }
        }
        
        Ok(size)
    }
}

/// Trait for search metrics and monitoring
/// 
/// This trait provides hooks for performance monitoring,
/// statistics collection, and operational insights.
pub trait SearchMetrics: Send + Sync {
    /// Record search operation start
    /// 
    /// # Arguments
    /// * `params` - Search parameters
    fn record_search_start(&self, params: &SearchParams);
    
    /// Record candidates found
    /// 
    /// # Arguments
    /// * `count` - Number of candidates found
    fn record_candidates_found(&self, count: usize);
    
    /// Record entry processed
    /// 
    /// # Arguments
    /// * `dn` - Entry DN that was processed
    /// * `matched` - Whether entry matched filter
    fn record_entry_processed(&self, dn: &str, matched: bool);
    
    /// Record search completion
    /// 
    /// # Arguments
    /// * `result_code` - Final result code
    /// * `entries_sent` - Number of entries sent to client
    /// * `duration` - Total search duration
    fn record_search_complete(&self, result_code: &SearchResultCode, entries_sent: usize, duration: Duration);
    
    /// Record search abandonment
    fn record_search_abandoned(&self);
    
    /// Get search statistics
    /// 
    /// # Returns
    /// * (total_searches, avg_duration_ms, avg_entries_per_search)
    fn get_stats(&self) -> (u64, u64, f64) {
        // Default implementation returns zeros
        (0, 0, 0.0)
    }
}

/// Configuration for the Search FSM
#[derive(Debug, Clone, PartialEq)]
pub struct SearchFsmConfig {
    /// Default size limit for searches
    pub default_size_limit: u32,
    /// Default time limit for searches (in seconds)
    pub default_time_limit: u32,
    /// Maximum size limit allowed
    pub max_size_limit: u32,
    /// Maximum time limit allowed (in seconds)
    pub max_time_limit: u32,
    /// Maximum number of candidates to process
    pub max_candidates: usize,
    /// Batch size for candidate processing
    pub candidate_batch_size: usize,
    /// Enable search result caching
    pub enable_caching: bool,
    /// Enable metrics collection
    pub enable_metrics: bool,
}

impl Default for SearchFsmConfig {
    fn default() -> Self {
        Self {
            default_size_limit: 1000,
            default_time_limit: 30,
            max_size_limit: 10000,
            max_time_limit: 300, // 5 minutes
            max_candidates: 50000,
            candidate_batch_size: 100,
            enable_caching: false,
            enable_metrics: false,
        }
    }
}

/// Search session state for tracking search progress
#[derive(Debug, Clone)]
pub struct SearchSession {
    /// Search parameters
    pub params: SearchParams,
    /// Start time of the search
    pub start_time: Instant,
    /// Candidate entry DNs to process
    pub candidates: Vec<String>,
    /// Current position in candidate list
    pub candidate_index: usize,
    /// Number of entries sent to client
    pub entries_sent: usize,
    /// Number of candidates found
    pub candidates_found: usize,
    /// Number of entries processed
    pub entries_processed: usize,
    /// Current batch of entries being processed
    pub current_batch: Vec<SearchEntry>,
    /// Whether search has been abandoned
    pub is_abandoned: bool,
}

impl SearchSession {
    /// Create a new search session
    /// 
    /// # Arguments
    /// * `params` - Search parameters
    /// 
    /// # Returns
    /// * New SearchSession instance
    pub fn new(params: SearchParams) -> Self {
        Self {
            params,
            start_time: Instant::now(),
            candidates: Vec::new(),
            candidate_index: 0,
            entries_sent: 0,
            candidates_found: 0,
            entries_processed: 0,
            current_batch: Vec::new(),
            is_abandoned: false,
        }
    }
    
    /// Check if all candidates have been processed
    /// 
    /// # Returns
    /// * true if all candidates processed
    pub fn has_more_candidates(&self) -> bool {
        self.candidate_index < self.candidates.len()
    }
    
    /// Get next batch of candidates to process
    /// 
    /// # Arguments
    /// * `batch_size` - Maximum batch size
    /// 
    /// # Returns
    /// * Vector of candidate DNs
    pub fn get_next_candidate_batch(&mut self, batch_size: usize) -> Vec<String> {
        let start = self.candidate_index;
        let end = std::cmp::min(start + batch_size, self.candidates.len());
        
        if start >= end {
            return Vec::new();
        }
        
        let batch = self.candidates[start..end].to_vec();
        self.candidate_index = end;
        batch
    }
    
    /// Check if size limit would be exceeded
    /// 
    /// # Arguments
    /// * `additional_entries` - Number of additional entries to consider
    /// 
    /// # Returns
    /// * true if size limit would be exceeded
    pub fn would_exceed_size_limit(&self, additional_entries: usize) -> bool {
        (self.entries_sent + additional_entries) as u32 > self.params.size_limit
    }
    
    /// Check if time limit has been exceeded
    /// 
    /// # Returns
    /// * true if time limit exceeded
    pub fn is_time_limit_exceeded(&self) -> bool {
        if self.params.time_limit == 0 {
            return false; // No time limit
        }
        
        let elapsed = self.start_time.elapsed().as_secs() as u32;
        elapsed > self.params.time_limit
    }
}

/// Search FSM Implementation
/// 
/// This FSM manages the complete search operation lifecycle including:
/// - Parameter validation and initialization
/// - Candidate finding and iteration
/// - Filter evaluation and entry emission  
/// - Size/time limit enforcement
/// - Search abandonment handling
/// - Performance monitoring and statistics
pub struct SearchFsmImpl {
    /// Current FSM state
    state: SearchState,
    
    /// Current search session (if active)
    session: Option<SearchSession>,
    
    /// Search backend for entry retrieval
    backend: Box<dyn SearchBackend>,
    
    /// Filter matcher for entry evaluation
    filter_matcher: Box<dyn FilterMatcher>,
    
    /// Entry formatter for result encoding
    entry_formatter: Box<dyn EntryFormatter>,
    
    /// Metrics collector (optional)
    metrics: Option<Box<dyn SearchMetrics>>,
    
    /// FSM configuration
    config: SearchFsmConfig,
    
    /// Statistics tracking
    total_searches: u64,
    total_entries_sent: u64,
    total_candidates_processed: u64,
}

impl SearchFsmImpl {
    /// Create a new Search FSM instance
    /// 
    /// # Arguments
    /// * `backend` - Search backend implementation
    /// * `filter_matcher` - Filter evaluation implementation
    /// * `entry_formatter` - Entry formatting implementation
    /// 
    /// # Returns
    /// * New Search FSM instance
    pub fn new(
        backend: Box<dyn SearchBackend>,
        filter_matcher: Box<dyn FilterMatcher>,
        entry_formatter: Box<dyn EntryFormatter>,
    ) -> Self {
        Self {
            state: SearchState::Initializing,
            session: None,
            backend,
            filter_matcher,
            entry_formatter,
            metrics: None,
            config: SearchFsmConfig::default(),
            total_searches: 0,
            total_entries_sent: 0,
            total_candidates_processed: 0,
        }
    }
    
    /// Create a Search FSM with custom configuration
    /// 
    /// # Arguments
    /// * `backend` - Search backend implementation
    /// * `filter_matcher` - Filter evaluation implementation  
    /// * `entry_formatter` - Entry formatting implementation
    /// * `config` - FSM configuration
    /// 
    /// # Returns
    /// * New Search FSM instance with custom configuration
    pub fn with_config(
        backend: Box<dyn SearchBackend>,
        filter_matcher: Box<dyn FilterMatcher>,
        entry_formatter: Box<dyn EntryFormatter>,
        config: SearchFsmConfig,
    ) -> Self {
        Self {
            state: SearchState::Initializing,
            session: None,
            backend,
            filter_matcher,
            entry_formatter,
            metrics: None,
            config,
            total_searches: 0,
            total_entries_sent: 0,
            total_candidates_processed: 0,
        }
    }
    
    /// Set metrics collector
    /// 
    /// # Arguments
    /// * `metrics` - Metrics implementation
    /// 
    /// # Returns
    /// * Self for method chaining
    pub fn with_metrics(mut self, metrics: Box<dyn SearchMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }
    
    /// Get the current FSM configuration
    /// 
    /// # Returns
    /// * Reference to the FSM configuration
    pub fn config(&self) -> &SearchFsmConfig {
        &self.config
    }
    
    /// Get the current FSM configuration mutably
    /// 
    /// # Returns
    /// * Mutable reference to the FSM configuration
    pub fn config_mut(&mut self) -> &mut SearchFsmConfig {
        &mut self.config
    }
    
    /// Set the FSM configuration
    /// 
    /// # Arguments
    /// * `config` - New configuration
    pub fn set_config(&mut self, config: SearchFsmConfig) {
        self.config = config;
    }
    
    /// Get search statistics
    /// 
    /// # Returns
    /// * (total_searches, total_entries_sent, total_candidates_processed)
    pub fn stats(&self) -> (u64, u64, u64) {
        (self.total_searches, self.total_entries_sent, self.total_candidates_processed)
    }
    
    /// Validate search parameters
    /// 
    /// # Arguments
    /// * `params` - Search parameters to validate
    /// 
    /// # Returns
    /// * `Ok(())` if parameters are valid
    /// * `Err(SearchFsmError)` if validation fails
    fn validate_search_params(&self, params: &SearchParams) -> Result<(), SearchFsmError> {
        // Validate base DN
        if params.base_dn.is_empty() {
            return Err(SearchFsmError::InvalidParameters {
                message: "Base DN cannot be empty".to_string(),
            });
        }
        
        // Validate scope
        if params.scope < 0 || params.scope > 2 {
            return Err(SearchFsmError::InvalidParameters {
                message: format!("Invalid search scope: {}", params.scope),
            });
        }
        
        // Validate filter
        if params.filter.is_empty() {
            return Err(SearchFsmError::InvalidParameters {
                message: "Search filter cannot be empty".to_string(),
            });
        }
        
        // Validate limits
        if params.size_limit > self.config.max_size_limit {
            return Err(SearchFsmError::InvalidParameters {
                message: format!("Size limit {} exceeds maximum {}", params.size_limit, self.config.max_size_limit),
            });
        }
        
        if params.time_limit > self.config.max_time_limit {
            return Err(SearchFsmError::InvalidParameters {
                message: format!("Time limit {} exceeds maximum {}", params.time_limit, self.config.max_time_limit),
            });
        }
        
        Ok(())
    }
    
    /// Apply default limits to search parameters
    /// 
    /// # Arguments
    /// * `params` - Search parameters to update
    /// 
    /// # Returns
    /// * Updated search parameters
    fn apply_default_limits(&self, mut params: SearchParams) -> SearchParams {
        // Note: 0 means no limit specified, use defaults
        // If user explicitly wants zero entries, they should use a very small positive number
        if params.size_limit == 0 {
            params.size_limit = self.config.default_size_limit;
        }
        
        if params.time_limit == 0 {
            params.time_limit = self.config.default_time_limit;
        }
        
        params
    }
    
    /// Handle search start event
    /// 
    /// # Arguments
    /// * `base_dn` - Base DN for search
    /// * `scope` - Search scope
    /// * `filter` - LDAP filter
    /// * `attributes` - Requested attributes
    /// * `size_limit` - Size limit
    /// * `time_limit` - Time limit
    /// 
    /// # Returns
    /// * Result indicating success or error
    async fn handle_start_search(
        &mut self,
        base_dn: String,
        scope: i32,
        filter: String,
        attributes: Vec<String>,
        size_limit: u32,
        time_limit: u32,
    ) -> Result<Option<Vec<u8>>, SearchFsmError> {
        let mut params = SearchParams {
            base_dn,
            scope,
            filter,
            attributes,
            size_limit,
            time_limit,
        };
        
        // Apply default limits
        params = self.apply_default_limits(params);
        
        // Validate parameters
        self.validate_search_params(&params)?;
        
        // Validate filter syntax
        self.filter_matcher.validate_filter(&params.filter).await
            .map_err(|e| SearchFsmError::FilterError { message: e })?;
        
        // Create new session
        let session = SearchSession::new(params.clone());
        
        // Record metrics
        if let Some(ref metrics) = self.metrics {
            metrics.record_search_start(&params);
        }
        
        self.session = Some(session);
        self.state = SearchState::FindingCandidates;
        self.total_searches += 1;
        
        Ok(None)
    }
    
    /// Handle candidates found event
    /// 
    /// # Arguments
    /// * `candidate_count` - Number of candidates found
    /// 
    /// # Returns
    /// * Result indicating success or error
    async fn handle_candidates_found(
        &mut self,
        candidate_count: usize,
    ) -> Result<Option<Vec<u8>>, SearchFsmError> {
        if let Some(session) = &mut self.session {
            session.candidates_found = candidate_count;
            
            // Record metrics
            if let Some(ref metrics) = self.metrics {
                metrics.record_candidates_found(candidate_count);
            }
            
            // Check if we have candidates to process
            if candidate_count > 0 {
                self.state = SearchState::Iterating {
                    candidates_found: candidate_count,
                    entries_sent: 0,
                };
            } else {
                // No candidates found - complete search
                self.state = SearchState::Completed {
                    entries_sent: 0,
                    result_code: SearchResultCode::Success,
                };
                
                if let Some(ref metrics) = self.metrics {
                    metrics.record_search_complete(
                        &SearchResultCode::Success,
                        0,
                        session.start_time.elapsed(),
                    );
                }
            }
            
            Ok(None)
        } else {
            Err(SearchFsmError::NoActiveSearch)
        }
    }
    
    /// Handle entry found event
    /// 
    /// # Arguments
    /// * `entry_data` - Encoded entry data
    /// 
    /// # Returns
    /// * Result containing formatted entry for emission
    async fn handle_entry_found(
        &mut self,
        entry_data: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, SearchFsmError> {
        if let Some(session) = &mut self.session {
            // Check time limit
            if session.is_time_limit_exceeded() {
                self.state = SearchState::TimeLimitExceeded;
                
                if let Some(ref metrics) = self.metrics {
                    metrics.record_search_complete(
                        &SearchResultCode::TimeLimitExceeded,
                        session.entries_sent,
                        session.start_time.elapsed(),
                    );
                }
                
                return Err(SearchFsmError::TimeLimitExceeded);
            }
            
            // Check size limit
            if session.would_exceed_size_limit(1) {
                self.state = SearchState::SizeLimitExceeded;
                
                if let Some(ref metrics) = self.metrics {
                    metrics.record_search_complete(
                        &SearchResultCode::SizeLimitExceeded,
                        session.entries_sent,
                        session.start_time.elapsed(),
                    );
                }
                
                return Err(SearchFsmError::SizeLimitExceeded);
            }
            
            self.state = SearchState::EmittingEntries;
            Ok(Some(entry_data))
        } else {
            Err(SearchFsmError::NoActiveSearch)
        }
    }
    
    /// Handle entry emitted event
    /// 
    /// # Returns
    /// * Result indicating success or error
    async fn handle_entry_emitted(&mut self) -> Result<Option<Vec<u8>>, SearchFsmError> {
        if let Some(session) = &mut self.session {
            session.entries_sent += 1;
            self.total_entries_sent += 1;
            
            // Check if we have more candidates to process
            if session.has_more_candidates() {
                self.state = SearchState::Iterating {
                    candidates_found: session.candidates_found,
                    entries_sent: session.entries_sent,
                };
            } else {
                // All candidates processed - complete search
                self.state = SearchState::Completed {
                    entries_sent: session.entries_sent,
                    result_code: SearchResultCode::Success,
                };
                
                if let Some(ref metrics) = self.metrics {
                    metrics.record_search_complete(
                        &SearchResultCode::Success,
                        session.entries_sent,
                        session.start_time.elapsed(),
                    );
                }
            }
            
            Ok(None)
        } else {
            Err(SearchFsmError::NoActiveSearch)
        }
    }
    
    /// Handle search complete event
    /// 
    /// # Returns
    /// * Result indicating success
    async fn handle_search_complete(&mut self) -> Result<Option<Vec<u8>>, SearchFsmError> {
        if let Some(session) = &self.session {
            self.state = SearchState::Completed {
                entries_sent: session.entries_sent,
                result_code: SearchResultCode::Success,
            };
            
            if let Some(ref metrics) = self.metrics {
                metrics.record_search_complete(
                    &SearchResultCode::Success,
                    session.entries_sent,
                    session.start_time.elapsed(),
                );
            }
            
            Ok(None)
        } else {
            Err(SearchFsmError::NoActiveSearch)
        }
    }
    
    /// Handle search abandon event
    /// 
    /// # Returns
    /// * Result indicating abandonment
    async fn handle_abandon(&mut self) -> Result<Option<Vec<u8>>, SearchFsmError> {
        if let Some(session) = &mut self.session {
            session.is_abandoned = true;
            self.state = SearchState::Abandoned;
            
            if let Some(ref metrics) = self.metrics {
                metrics.record_search_abandoned();
            }
            
            Err(SearchFsmError::Abandoned)
        } else {
            Err(SearchFsmError::NoActiveSearch)
        }
    }
    
    /// Handle time limit exceeded
    /// 
    /// # Returns
    /// * Result indicating time limit exceeded
    async fn handle_time_limit(&mut self) -> Result<Option<Vec<u8>>, SearchFsmError> {
        if let Some(session) = &self.session {
            self.state = SearchState::TimeLimitExceeded;
            
            if let Some(ref metrics) = self.metrics {
                metrics.record_search_complete(
                    &SearchResultCode::TimeLimitExceeded,
                    session.entries_sent,
                    session.start_time.elapsed(),
                );
            }
            
            Err(SearchFsmError::TimeLimitExceeded)
        } else {
            Err(SearchFsmError::NoActiveSearch)
        }
    }
    
    /// Handle size limit exceeded
    /// 
    /// # Returns
    /// * Result indicating size limit exceeded
    async fn handle_size_limit(&mut self) -> Result<Option<Vec<u8>>, SearchFsmError> {
        if let Some(session) = &self.session {
            self.state = SearchState::SizeLimitExceeded;
            
            if let Some(ref metrics) = self.metrics {
                metrics.record_search_complete(
                    &SearchResultCode::SizeLimitExceeded,
                    session.entries_sent,
                    session.start_time.elapsed(),
                );
            }
            
            Err(SearchFsmError::SizeLimitExceeded)
        } else {
            Err(SearchFsmError::NoActiveSearch)
        }
    }
    
    /// Handle error event
    /// 
    /// # Arguments
    /// * `error_message` - Error description
    /// 
    /// # Returns
    /// * Result containing error
    async fn handle_error(&mut self, error_message: String) -> Result<Option<Vec<u8>>, SearchFsmError> {
        self.state = SearchState::Completed {
            entries_sent: self.session.as_ref().map(|s| s.entries_sent).unwrap_or(0),
            result_code: SearchResultCode::Other(1), // Generic error
        };
        
        Err(SearchFsmError::Generic { message: error_message })
    }
}

#[async_trait]
impl StateMachine for SearchFsmImpl {
    type State = SearchState;
    type Event = SearchEvent;
    type Error = SearchFsmError;
    type Output = Vec<u8>; // Encoded entry data
    
    fn current_state(&self) -> &Self::State {
        &self.state
    }
    
    async fn handle_event(&mut self, event: Self::Event) -> Result<Option<Self::Output>, Self::Error> {
        match event {
            SearchEvent::StartSearch { base_dn, scope, filter, attributes, size_limit, time_limit } => {
                self.handle_start_search(base_dn, scope, filter, attributes, size_limit, time_limit).await
            },
            SearchEvent::CandidatesFound(count) => {
                self.handle_candidates_found(count).await
            },
            SearchEvent::EntryFound(entry_data) => {
                self.handle_entry_found(entry_data).await
            },
            SearchEvent::EntryEmitted => {
                self.handle_entry_emitted().await
            },
            SearchEvent::SearchComplete => {
                self.handle_search_complete().await
            },
            SearchEvent::Abandon => {
                self.handle_abandon().await
            },
            SearchEvent::TimeLimit => {
                self.handle_time_limit().await
            },
            SearchEvent::SizeLimit => {
                self.handle_size_limit().await
            },
            SearchEvent::Error(error_message) => {
                self.handle_error(error_message).await
            },
        }
    }
    
    fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            SearchState::Completed { .. } 
            | SearchState::Abandoned 
            | SearchState::TimeLimitExceeded 
            | SearchState::SizeLimitExceeded
        )
    }
    
    async fn reset(&mut self) -> Result<(), Self::Error> {
        self.state = SearchState::Initializing;
        self.session = None;
        Ok(())
    }
}

#[async_trait]
impl AbandonableFsm for SearchFsmImpl {
    async fn abandon(&mut self) -> Result<(), Self::Error> {
        if let Some(session) = &mut self.session {
            session.is_abandoned = true;
            self.state = SearchState::Abandoned;
            
            if let Some(ref metrics) = self.metrics {
                metrics.record_search_abandoned();
            }
            
            Ok(())
        } else {
            Err(SearchFsmError::NoActiveSearch)
        }
    }
    
    fn is_abandoned(&self) -> bool {
        self.session.as_ref().map(|s| s.is_abandoned).unwrap_or(false) 
            || matches!(self.state, SearchState::Abandoned)
    }
}

impl TimeoutFsm for SearchFsmImpl {
    fn timeout(&self) -> Option<Duration> {
        self.session.as_ref().map(|s| Duration::from_secs(s.params.time_limit as u64))
    }
    
    fn start_time(&self) -> Instant {
        self.session.as_ref().map(|s| s.start_time).unwrap_or_else(Instant::now)
    }
}

#[async_trait]
impl SearchFsm for SearchFsmImpl {
    fn search_params(&self) -> Option<&SearchParams> {
        self.session.as_ref().map(|s| &s.params)
    }
    
    fn entries_sent(&self) -> usize {
        self.session.as_ref().map(|s| s.entries_sent).unwrap_or(0)
    }
    
    fn size_limit(&self) -> u32 {
        self.session.as_ref().map(|s| s.params.size_limit).unwrap_or(self.config.default_size_limit)
    }
    
    fn would_exceed_size_limit(&self) -> bool {
        if let Some(session) = &self.session {
            session.would_exceed_size_limit(1)
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio;

    /// Mock search backend for testing
    #[derive(Debug)]
    pub struct MockSearchBackend {
        pub candidates: Vec<String>,
        pub entries: HashMap<String, SearchEntry>,
        pub should_fail: bool,
        pub call_log: Arc<Mutex<Vec<String>>>,
    }

    impl MockSearchBackend {
        pub fn new() -> Self {
            let mut entries = HashMap::new();
            
            // Add test entries
            let mut entry1 = SearchEntry::new("cn=john,dc=example,dc=org".to_string());
            entry1.add_attribute("cn".to_string(), vec!["john".to_string()]);
            entry1.add_attribute("mail".to_string(), vec!["john@example.org".to_string()]);
            entry1.set_object_classes(vec!["person".to_string(), "inetOrgPerson".to_string()]);
            entries.insert(entry1.dn.clone(), entry1);
            
            let mut entry2 = SearchEntry::new("cn=jane,dc=example,dc=org".to_string());
            entry2.add_attribute("cn".to_string(), vec!["jane".to_string()]);
            entry2.add_attribute("mail".to_string(), vec!["jane@example.org".to_string()]);
            entry2.set_object_classes(vec!["person".to_string(), "inetOrgPerson".to_string()]);
            entries.insert(entry2.dn.clone(), entry2);
            
            Self {
                candidates: vec![
                    "cn=john,dc=example,dc=org".to_string(),
                    "cn=jane,dc=example,dc=org".to_string(),
                ],
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
            self.candidates.clear();
            self.entries.clear();
            self
        }

        pub fn call_log(&self) -> Vec<String> {
            self.call_log.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl SearchBackend for MockSearchBackend {
        async fn find_candidates(&self, base_dn: &str, scope: i32, filter: &str) -> Result<Vec<String>, String> {
            self.call_log.lock().unwrap().push(format!(
                "find_candidates({}, {}, {})", 
                base_dn, scope, filter
            ));
            
            if self.should_fail {
                return Err("Mock backend failure".to_string());
            }
            
            Ok(self.candidates.clone())
        }

        async fn get_entry(&self, dn: &str, _attributes: &[String]) -> Result<Option<SearchEntry>, String> {
            self.call_log.lock().unwrap().push(format!("get_entry({})", dn));
            
            if self.should_fail {
                return Err("Mock backend failure".to_string());
            }
            
            Ok(self.entries.get(dn).cloned())
        }
    }

    /// Mock filter matcher for testing
    #[derive(Debug)]
    pub struct MockFilterMatcher {
        pub should_match: bool,
        pub should_fail: bool,
        pub call_log: Arc<Mutex<Vec<String>>>,
    }

    impl MockFilterMatcher {
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

        pub fn with_no_matches(mut self) -> Self {
            self.should_match = false;
            self
        }

        pub fn call_log(&self) -> Vec<String> {
            self.call_log.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl FilterMatcher for MockFilterMatcher {
        async fn matches_filter(&self, entry: &SearchEntry, filter: &str) -> Result<bool, String> {
            self.call_log.lock().unwrap().push(format!(
                "matches_filter({}, {})", 
                entry.dn, filter
            ));
            
            if self.should_fail {
                return Err("Mock filter matcher failure".to_string());
            }
            
            Ok(self.should_match)
        }
    }

    /// Mock entry formatter for testing
    #[derive(Debug)]
    pub struct MockEntryFormatter {
        pub should_fail: bool,
        pub call_log: Arc<Mutex<Vec<String>>>,
    }

    impl MockEntryFormatter {
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
    impl EntryFormatter for MockEntryFormatter {
        async fn format_entry(&self, entry: &SearchEntry, attributes: &[String]) -> Result<Vec<u8>, String> {
            self.call_log.lock().unwrap().push(format!(
                "format_entry({}, {:?})", 
                entry.dn, attributes
            ));
            
            if self.should_fail {
                return Err("Mock entry formatter failure".to_string());
            }
            
            // Return a simple encoded representation
            let encoded = format!("dn: {}\n", entry.dn);
            Ok(encoded.into_bytes())
        }
    }

    /// Mock metrics collector for testing
    #[derive(Debug)]
    pub struct MockSearchMetrics {
        pub call_log: Arc<Mutex<Vec<String>>>,
    }

    impl MockSearchMetrics {
        pub fn new() -> Self {
            Self {
                call_log: Arc::new(Mutex::new(Vec::new())),
            }
        }

        pub fn call_log(&self) -> Vec<String> {
            self.call_log.lock().unwrap().clone()
        }
    }

    impl SearchMetrics for MockSearchMetrics {
        fn record_search_start(&self, params: &SearchParams) {
            self.call_log.lock().unwrap().push(format!(
                "record_search_start(base_dn: {})", 
                params.base_dn
            ));
        }

        fn record_candidates_found(&self, count: usize) {
            self.call_log.lock().unwrap().push(format!("record_candidates_found({})", count));
        }

        fn record_entry_processed(&self, dn: &str, matched: bool) {
            self.call_log.lock().unwrap().push(format!(
                "record_entry_processed({}, {})", 
                dn, matched
            ));
        }

        fn record_search_complete(&self, result_code: &SearchResultCode, entries_sent: usize, duration: Duration) {
            self.call_log.lock().unwrap().push(format!(
                "record_search_complete({:?}, {}, {:?})", 
                result_code, entries_sent, duration
            ));
        }

        fn record_search_abandoned(&self) {
            self.call_log.lock().unwrap().push("record_search_abandoned".to_string());
        }
    }

    #[tokio::test]
    async fn test_new_search_fsm() {
        let backend = Box::new(MockSearchBackend::new());
        let filter_matcher = Box::new(MockFilterMatcher::new());
        let entry_formatter = Box::new(MockEntryFormatter::new());
        
        let fsm = SearchFsmImpl::new(backend, filter_matcher, entry_formatter);
        
        assert_eq!(fsm.current_state(), &SearchState::Initializing);
        assert_eq!(fsm.entries_sent(), 0);
        assert!(!fsm.is_abandoned());
        assert!(!fsm.is_terminal());
        assert!(fsm.search_params().is_none());
    }

    #[tokio::test]
    async fn test_search_fsm_with_config() {
        let backend = Box::new(MockSearchBackend::new());
        let filter_matcher = Box::new(MockFilterMatcher::new());
        let entry_formatter = Box::new(MockEntryFormatter::new());
        
        let config = SearchFsmConfig {
            default_size_limit: 50,
            default_time_limit: 60,
            max_size_limit: 5000,
            max_time_limit: 600,
            max_candidates: 10000,
            candidate_batch_size: 50,
            enable_caching: true,
            enable_metrics: false,
        };
        
        let fsm = SearchFsmImpl::with_config(backend, filter_matcher, entry_formatter, config);
        
        assert_eq!(fsm.current_state(), &SearchState::Initializing);
        assert_eq!(fsm.config.default_size_limit, 50);
        assert_eq!(fsm.config.default_time_limit, 60);
        assert_eq!(fsm.config.max_size_limit, 5000);
        assert!(fsm.config.enable_caching);
    }

    #[tokio::test]
    async fn test_start_search_success() {
        let backend = Box::new(MockSearchBackend::new());
        let filter_matcher = Box::new(MockFilterMatcher::new());
        let entry_formatter = Box::new(MockEntryFormatter::new());
        
        let mut fsm = SearchFsmImpl::new(backend, filter_matcher, entry_formatter);
        
        let result = fsm.handle_event(SearchEvent::StartSearch {
            base_dn: "dc=example,dc=org".to_string(),
            scope: 2,
            filter: "(objectClass=person)".to_string(),
            attributes: vec!["cn".to_string(), "mail".to_string()],
            size_limit: 100,
            time_limit: 30,
        }).await;
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
        assert_eq!(fsm.current_state(), &SearchState::FindingCandidates);
        assert!(fsm.search_params().is_some());
        
        let params = fsm.search_params().unwrap();
        assert_eq!(params.base_dn, "dc=example,dc=org");
        assert_eq!(params.scope, 2);
        assert_eq!(params.filter, "(objectClass=person)");
        assert_eq!(params.size_limit, 100);
        assert_eq!(params.time_limit, 30);
        
        let (total_searches, _, _) = fsm.stats();
        assert_eq!(total_searches, 1);
    }

    #[tokio::test]
    async fn test_start_search_invalid_parameters() {
        let backend = Box::new(MockSearchBackend::new());
        let filter_matcher = Box::new(MockFilterMatcher::new());
        let entry_formatter = Box::new(MockEntryFormatter::new());
        
        let mut fsm = SearchFsmImpl::new(backend, filter_matcher, entry_formatter);
        
        // Test empty base DN
        let result = fsm.handle_event(SearchEvent::StartSearch {
            base_dn: "".to_string(),
            scope: 2,
            filter: "(objectClass=person)".to_string(),
            attributes: vec![],
            size_limit: 100,
            time_limit: 30,
        }).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SearchFsmError::InvalidParameters { .. }));
        assert_eq!(fsm.current_state(), &SearchState::Initializing);
        
        // Test invalid scope
        let result = fsm.handle_event(SearchEvent::StartSearch {
            base_dn: "dc=example,dc=org".to_string(),
            scope: 5, // Invalid scope
            filter: "(objectClass=person)".to_string(),
            attributes: vec![],
            size_limit: 100,
            time_limit: 30,
        }).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SearchFsmError::InvalidParameters { .. }));
        
        // Test empty filter
        let result = fsm.handle_event(SearchEvent::StartSearch {
            base_dn: "dc=example,dc=org".to_string(),
            scope: 2,
            filter: "".to_string(),
            attributes: vec![],
            size_limit: 100,
            time_limit: 30,
        }).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SearchFsmError::InvalidParameters { .. }));
    }

    #[tokio::test]
    async fn test_candidates_found_success() {
        let backend = Box::new(MockSearchBackend::new());
        let filter_matcher = Box::new(MockFilterMatcher::new());
        let entry_formatter = Box::new(MockEntryFormatter::new());
        
        let mut fsm = SearchFsmImpl::new(backend, filter_matcher, entry_formatter);
        
        // Start search first
        let _result = fsm.handle_event(SearchEvent::StartSearch {
            base_dn: "dc=example,dc=org".to_string(),
            scope: 2,
            filter: "(objectClass=person)".to_string(),
            attributes: vec!["cn".to_string()],
            size_limit: 100,
            time_limit: 30,
        }).await.unwrap();
        
        // Handle candidates found
        let result = fsm.handle_event(SearchEvent::CandidatesFound(2)).await;
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
        assert_eq!(fsm.current_state(), &SearchState::Iterating {
            candidates_found: 2,
            entries_sent: 0,
        });
    }

    #[tokio::test]
    async fn test_candidates_found_no_candidates() {
        let backend = Box::new(MockSearchBackend::new());
        let filter_matcher = Box::new(MockFilterMatcher::new());
        let entry_formatter = Box::new(MockEntryFormatter::new());
        
        let mut fsm = SearchFsmImpl::new(backend, filter_matcher, entry_formatter);
        
        // Start search first
        let _result = fsm.handle_event(SearchEvent::StartSearch {
            base_dn: "dc=example,dc=org".to_string(),
            scope: 2,
            filter: "(objectClass=person)".to_string(),
            attributes: vec!["cn".to_string()],
            size_limit: 100,
            time_limit: 30,
        }).await.unwrap();
        
        // Handle no candidates found
        let result = fsm.handle_event(SearchEvent::CandidatesFound(0)).await;
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
        assert_eq!(fsm.current_state(), &SearchState::Completed {
            entries_sent: 0,
            result_code: SearchResultCode::Success,
        });
        assert!(fsm.is_terminal());
    }

    #[tokio::test]
    async fn test_entry_found_and_emitted() {
        let backend = Box::new(MockSearchBackend::new());
        let filter_matcher = Box::new(MockFilterMatcher::new());
        let entry_formatter = Box::new(MockEntryFormatter::new());
        
        let mut fsm = SearchFsmImpl::new(backend, filter_matcher, entry_formatter);
        
        // Start search and find candidates
        let _result = fsm.handle_event(SearchEvent::StartSearch {
            base_dn: "dc=example,dc=org".to_string(),
            scope: 2,
            filter: "(objectClass=person)".to_string(),
            attributes: vec!["cn".to_string()],
            size_limit: 100,
            time_limit: 30,
        }).await.unwrap();
        
        let _result = fsm.handle_event(SearchEvent::CandidatesFound(1)).await.unwrap();
        
        // Handle entry found
        let entry_data = b"dn: cn=test,dc=example,dc=org\ncn: test\n".to_vec();
        let result = fsm.handle_event(SearchEvent::EntryFound(entry_data.clone())).await;
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some(entry_data));
        assert_eq!(fsm.current_state(), &SearchState::EmittingEntries);
        
        // Handle entry emitted
        let result = fsm.handle_event(SearchEvent::EntryEmitted).await;
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
        assert_eq!(fsm.entries_sent(), 1);
        
        let (_, total_entries_sent, _) = fsm.stats();
        assert_eq!(total_entries_sent, 1);
    }

    #[tokio::test]
    async fn test_search_abandon() {
        let backend = Box::new(MockSearchBackend::new());
        let filter_matcher = Box::new(MockFilterMatcher::new());
        let entry_formatter = Box::new(MockEntryFormatter::new());
        
        let mut fsm = SearchFsmImpl::new(backend, filter_matcher, entry_formatter);
        
        // Start search
        let _result = fsm.handle_event(SearchEvent::StartSearch {
            base_dn: "dc=example,dc=org".to_string(),
            scope: 2,
            filter: "(objectClass=person)".to_string(),
            attributes: vec!["cn".to_string()],
            size_limit: 100,
            time_limit: 30,
        }).await.unwrap();
        
        // Abandon search
        let result = fsm.handle_event(SearchEvent::Abandon).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SearchFsmError::Abandoned));
        assert_eq!(fsm.current_state(), &SearchState::Abandoned);
        assert!(fsm.is_abandoned());
        assert!(fsm.is_terminal());
    }

    #[tokio::test]
    async fn test_size_limit_exceeded() {
        let backend = Box::new(MockSearchBackend::new());
        let filter_matcher = Box::new(MockFilterMatcher::new());
        let entry_formatter = Box::new(MockEntryFormatter::new());
        
        let mut fsm = SearchFsmImpl::new(backend, filter_matcher, entry_formatter);
        
        // Start search with very low size limit
        let _result = fsm.handle_event(SearchEvent::StartSearch {
            base_dn: "dc=example,dc=org".to_string(),
            scope: 2,
            filter: "(objectClass=person)".to_string(),
            attributes: vec!["cn".to_string()],
            size_limit: 1, // Allow only 1 entry
            time_limit: 30,
        }).await.unwrap();
        
        let _result = fsm.handle_event(SearchEvent::CandidatesFound(2)).await.unwrap();
        
        // Emit first entry - should succeed
        let entry_data1 = b"dn: cn=test1,dc=example,dc=org\n".to_vec();
        let result = fsm.handle_event(SearchEvent::EntryFound(entry_data1.clone())).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some(entry_data1));
        
        let _result = fsm.handle_event(SearchEvent::EntryEmitted).await.unwrap();
        assert_eq!(fsm.entries_sent(), 1);
        
        // Try to find second entry - should trigger size limit
        let entry_data2 = b"dn: cn=test2,dc=example,dc=org\n".to_vec();
        let result = fsm.handle_event(SearchEvent::EntryFound(entry_data2)).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SearchFsmError::SizeLimitExceeded));
        assert_eq!(fsm.current_state(), &SearchState::SizeLimitExceeded);
        assert!(fsm.is_terminal());
    }

    #[tokio::test]
    async fn test_time_limit_exceeded() {
        let backend = Box::new(MockSearchBackend::new());
        let filter_matcher = Box::new(MockFilterMatcher::new());
        let entry_formatter = Box::new(MockEntryFormatter::new());
        
        let mut fsm = SearchFsmImpl::new(backend, filter_matcher, entry_formatter);
        
        let result = fsm.handle_event(SearchEvent::TimeLimit).await;
        
        // Should fail without active search
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SearchFsmError::NoActiveSearch));
        
        // Start search first
        let _result = fsm.handle_event(SearchEvent::StartSearch {
            base_dn: "dc=example,dc=org".to_string(),
            scope: 2,
            filter: "(objectClass=person)".to_string(),
            attributes: vec!["cn".to_string()],
            size_limit: 100,
            time_limit: 1, // 1 second
        }).await.unwrap();
        
        // Trigger time limit
        let result = fsm.handle_event(SearchEvent::TimeLimit).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SearchFsmError::TimeLimitExceeded));
        assert_eq!(fsm.current_state(), &SearchState::TimeLimitExceeded);
        assert!(fsm.is_terminal());
    }

    #[tokio::test]
    async fn test_search_complete() {
        let backend = Box::new(MockSearchBackend::new());
        let filter_matcher = Box::new(MockFilterMatcher::new());
        let entry_formatter = Box::new(MockEntryFormatter::new());
        
        let mut fsm = SearchFsmImpl::new(backend, filter_matcher, entry_formatter);
        
        // Start search
        let _result = fsm.handle_event(SearchEvent::StartSearch {
            base_dn: "dc=example,dc=org".to_string(),
            scope: 2,
            filter: "(objectClass=person)".to_string(),
            attributes: vec!["cn".to_string()],
            size_limit: 100,
            time_limit: 30,
        }).await.unwrap();
        
        // Complete search
        let result = fsm.handle_event(SearchEvent::SearchComplete).await;
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
        assert_eq!(fsm.current_state(), &SearchState::Completed {
            entries_sent: 0,
            result_code: SearchResultCode::Success,
        });
        assert!(fsm.is_terminal());
    }

    #[tokio::test]
    async fn test_fsm_reset() {
        let backend = Box::new(MockSearchBackend::new());
        let filter_matcher = Box::new(MockFilterMatcher::new());
        let entry_formatter = Box::new(MockEntryFormatter::new());
        
        let mut fsm = SearchFsmImpl::new(backend, filter_matcher, entry_formatter);
        
        // Start search
        let _result = fsm.handle_event(SearchEvent::StartSearch {
            base_dn: "dc=example,dc=org".to_string(),
            scope: 2,
            filter: "(objectClass=person)".to_string(),
            attributes: vec!["cn".to_string()],
            size_limit: 100,
            time_limit: 30,
        }).await.unwrap();
        
        assert_eq!(fsm.current_state(), &SearchState::FindingCandidates);
        assert!(fsm.search_params().is_some());
        
        // Reset FSM
        let result = fsm.reset().await;
        
        assert!(result.is_ok());
        assert_eq!(fsm.current_state(), &SearchState::Initializing);
        assert!(fsm.search_params().is_none());
        assert_eq!(fsm.entries_sent(), 0);
    }

    #[tokio::test]
    async fn test_search_with_metrics() {
        let backend = Box::new(MockSearchBackend::new());
        let filter_matcher = Box::new(MockFilterMatcher::new());
        let entry_formatter = Box::new(MockEntryFormatter::new());
        let metrics = Box::new(MockSearchMetrics::new());
        let metrics_log = metrics.call_log.clone();
        
        let mut fsm = SearchFsmImpl::new(backend, filter_matcher, entry_formatter)
            .with_metrics(metrics);
        
        // Start search
        let _result = fsm.handle_event(SearchEvent::StartSearch {
            base_dn: "dc=example,dc=org".to_string(),
            scope: 2,
            filter: "(objectClass=person)".to_string(),
            attributes: vec!["cn".to_string()],
            size_limit: 100,
            time_limit: 30,
        }).await.unwrap();
        
        // Check metrics were called
        let calls = metrics_log.lock().unwrap();
        assert!(calls.iter().any(|call| call.contains("record_search_start")));
    }

    #[tokio::test]
    async fn test_abandonable_fsm_trait() {
        let backend = Box::new(MockSearchBackend::new());
        let filter_matcher = Box::new(MockFilterMatcher::new());
        let entry_formatter = Box::new(MockEntryFormatter::new());
        
        let mut fsm = SearchFsmImpl::new(backend, filter_matcher, entry_formatter);
        
        // Start search
        let _result = fsm.handle_event(SearchEvent::StartSearch {
            base_dn: "dc=example,dc=org".to_string(),
            scope: 2,
            filter: "(objectClass=person)".to_string(),
            attributes: vec!["cn".to_string()],
            size_limit: 100,
            time_limit: 30,
        }).await.unwrap();
        
        assert!(!fsm.is_abandoned());
        
        // Abandon via trait method
        let result = fsm.abandon().await;
        
        assert!(result.is_ok());
        assert!(fsm.is_abandoned());
        assert_eq!(fsm.current_state(), &SearchState::Abandoned);
    }

    #[tokio::test]
    async fn test_timeout_fsm_trait() {
        let backend = Box::new(MockSearchBackend::new());
        let filter_matcher = Box::new(MockFilterMatcher::new());
        let entry_formatter = Box::new(MockEntryFormatter::new());
        
        let mut fsm = SearchFsmImpl::new(backend, filter_matcher, entry_formatter);
        
        // No timeout without active search
        assert!(fsm.timeout().is_none());
        
        // Start search
        let _result = fsm.handle_event(SearchEvent::StartSearch {
            base_dn: "dc=example,dc=org".to_string(),
            scope: 2,
            filter: "(objectClass=person)".to_string(),
            attributes: vec!["cn".to_string()],
            size_limit: 100,
            time_limit: 30,
        }).await.unwrap();
        
        // Should have timeout now
        assert_eq!(fsm.timeout(), Some(Duration::from_secs(30)));
        assert!(!fsm.is_timed_out()); // Should not be timed out immediately
    }

    #[tokio::test]
    async fn test_search_entry_methods() {
        let mut entry = SearchEntry::new("cn=test,dc=example,dc=org".to_string());
        
        assert_eq!(entry.dn, "cn=test,dc=example,dc=org");
        assert!(entry.attributes.is_empty());
        assert!(entry.object_classes.is_empty());
        
        entry.add_attribute("cn".to_string(), vec!["test".to_string()]);
        entry.add_attribute("mail".to_string(), vec!["test@example.org".to_string()]);
        entry.set_object_classes(vec!["person".to_string(), "inetOrgPerson".to_string()]);
        
        assert_eq!(entry.get_attribute("cn"), Some(&vec!["test".to_string()]));
        assert_eq!(entry.get_attribute("mail"), Some(&vec!["test@example.org".to_string()]));
        assert_eq!(entry.get_attribute("nonexistent"), None);
        
        assert!(entry.has_object_class("person"));
        assert!(entry.has_object_class("inetOrgPerson"));
        assert!(entry.has_object_class("PERSON")); // Case insensitive
        assert!(!entry.has_object_class("group"));
    }

    #[tokio::test]
    async fn test_search_session_methods() {
        let params = SearchParams {
            base_dn: "dc=example,dc=org".to_string(),
            scope: 2,
            filter: "(objectClass=person)".to_string(),
            attributes: vec!["cn".to_string()],
            size_limit: 10,
            time_limit: 30,
        };
        
        let mut session = SearchSession::new(params);
        
        assert_eq!(session.entries_sent, 0);
        assert_eq!(session.candidates_found, 0);
        assert!(!session.is_abandoned);
        
        session.candidates = vec![
            "cn=user1,dc=example,dc=org".to_string(),
            "cn=user2,dc=example,dc=org".to_string(),
            "cn=user3,dc=example,dc=org".to_string(),
        ];
        
        assert!(session.has_more_candidates());
        
        let batch = session.get_next_candidate_batch(2);
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0], "cn=user1,dc=example,dc=org");
        assert_eq!(batch[1], "cn=user2,dc=example,dc=org");
        
        let batch = session.get_next_candidate_batch(2);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0], "cn=user3,dc=example,dc=org");
        
        assert!(!session.has_more_candidates());
        
        let batch = session.get_next_candidate_batch(2);
        assert!(batch.is_empty());
        
        // Test size limit checking
        session.entries_sent = 8;
        assert!(!session.would_exceed_size_limit(1));
        assert!(!session.would_exceed_size_limit(2));
        assert!(session.would_exceed_size_limit(3));
        
        // Test time limit (should not be exceeded immediately)
        assert!(!session.is_time_limit_exceeded());
    }
}
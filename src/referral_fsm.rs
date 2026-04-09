//! Referral/Chaining Finite State Machine Implementation
//!
//! This module implements a comprehensive Referral/Chaining FSM for LDAP referral operations.
//! The FSM manages the complete referral lifecycle: referral evaluation, hop count management,
//! request chaining/proxying to other Directory System Agents (DSAs), and response processing.
//!
//! ## Referral Operation Flow
//!
//! ```text
//! EvaluatingReferral -> ChainRequest/ProxyRequest -> AwaitingResponse -> ProcessingResponse -> Completed
//!         |                     |                           |                    |             ^
//!         |                     |                           |                    |             |
//!         v                     v                           v                    v             |
//!       Failed                Failed                      Failed               Failed        ---+
//!         ^                     ^                           ^                    ^
//!         |                     |                           |                    |
//!         +-- HopLimitExceeded -+-- NetworkError -----------+-- ProcessingError-+
//! ```
//!
//! ## LDAP Referral Operations
//!
//! The LDAP Referral mechanism allows servers to redirect client requests to other DSAs
//! when the requested information is not available locally. This FSM handles:
//! - **Referral URL parsing and validation**
//! - **Hop count tracking** to prevent infinite loops
//! - **Request chaining** (server-to-server forwarding)
//! - **Request proxying** (transparent client redirection)
//! - **Response aggregation** from multiple DSAs
//!
//! ## Supported Features
//!
//! The FSM supports comprehensive LDAP referral operations:
//! - **Multiple referral URL handling** with fallback support
//! - **Hop limit enforcement** to prevent referral loops
//! - **Smart routing decisions** between chaining and proxying
//! - **Network timeout management** for remote DSA connections
//! - **Response aggregation** from multiple referral sources
//! - **Error recovery** with automatic failover to alternative URLs
//! - **Performance monitoring** with detailed metrics collection
//!
//! ## External Dependencies
//!
//! The FSM abstracts external dependencies through traits:
//! - `ReferralResolver`: URL parsing and DSA endpoint resolution
//! - `ChainHandler`: Server-to-server request forwarding
//! - `ProxyHandler`: Transparent client request proxying
//! - `NetworkClient`: Low-level network communication with DSAs
//! - `ReferralMetrics`: Performance monitoring and audit logging
//!
//! ## Usage Example
//!
//! ```rust,no_run
//! use opendr::referral_fsm::*;
//! use opendr::fsm::{StateMachine, ReferralFsm, ReferralState, ReferralEvent};
//!
//! # struct MockReferralResolver;
//! # #[async_trait::async_trait]
//! # impl ReferralResolver for MockReferralResolver {
//! #     async fn resolve_referral_urls(&self, _urls: &[String]) -> Result<Vec<ResolvedEndpoint>, String> {
//! #         Ok(vec![])
//! #     }
//! #     fn validate_referral_url(&self, _url: &str) -> Result<(), String> {
//! #         Ok(())
//! #     }
//! # }
//! #
//! # struct MockChainHandler;
//! # #[async_trait::async_trait]
//! # impl ChainHandler for MockChainHandler {
//! #     async fn chain_request(&self, _target: &str, _request: &[u8], _hop_count: u32) -> Result<Vec<u8>, String> {
//! #         Ok(vec![])
//! #     }
//! # }
//! #
//! # struct MockProxyHandler;
//! # #[async_trait::async_trait]
//! # impl ProxyHandler for MockProxyHandler {
//! #     async fn proxy_request(&self, _target: &str, _request: &[u8]) -> Result<Vec<u8>, String> {
//! #         Ok(vec![])
//! #     }
//! # }
//! #
//! # struct MockNetworkClient;
//! # #[async_trait::async_trait]
//! # impl NetworkClient for MockNetworkClient {
//! #     async fn send_request(&self, _endpoint: &ResolvedEndpoint, _request: &[u8], _timeout_ms: u64) -> Result<Vec<u8>, String> {
//! #         Ok(vec![])
//! #     }
//! # }
//! #
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let resolver = Box::new(MockReferralResolver);
//! let chain_handler = Box::new(MockChainHandler);
//! let proxy_handler = Box::new(MockProxyHandler);
//! let network_client = Box::new(MockNetworkClient);
//!
//! let mut fsm = ReferralFsmImpl::new(resolver, chain_handler, proxy_handler, network_client);
//!
//! // Start referral evaluation
//! let result = fsm.handle_event(ReferralEvent::ReferralReceived {
//!     urls: vec!["ldap://other-server.example.com/dc=remote,dc=org".to_string()],
//! }).await?;
//!
//! // Choose to chain the request
//! fsm.handle_event(ReferralEvent::ChainDecision {
//!     target: "other-server.example.com".to_string(),
//! }).await?;
//!
//! // Process through remaining FSM states
//! fsm.handle_event(ReferralEvent::RequestSent).await?;
//! fsm.handle_event(ReferralEvent::ResponseReceived(b"response_data".to_vec())).await?;
//! fsm.handle_event(ReferralEvent::ProcessingComplete).await?;
//!
//! // Check final result
//! assert_eq!(fsm.hop_count(), 1);
//! # Ok(())
//! # }
//! ```

use crate::fsm::{ReferralEvent, ReferralFsm, ReferralResultCode, ReferralState, StateMachine};
use async_trait::async_trait;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::time::timeout;

/// Errors that can occur during referral operations
#[derive(Error, Debug, Clone, PartialEq)]
pub enum ReferralFsmError {
    #[error("Invalid referral URLs: {message}")]
    InvalidReferralUrls { message: String },

    #[error("Referral resolver error: {message}")]
    ResolverError { message: String },

    #[error("Chain handler error: {message}")]
    ChainError { message: String },

    #[error("Proxy handler error: {message}")]
    ProxyError { message: String },

    #[error("Network communication error: {message}")]
    NetworkError { message: String },

    #[error("Hop limit exceeded: current={current}, max={max}")]
    HopLimitExceeded { current: u32, max: u32 },

    #[error("Request timeout: {duration_ms}ms")]
    RequestTimeout { duration_ms: u64 },

    #[error("No available DSA endpoints: tried {attempted} URLs")]
    NoAvailableEndpoints { attempted: usize },

    #[error("Response processing error: {message}")]
    ResponseProcessingError { message: String },

    #[error("Invalid state transition from {from:?} to {to:?}")]
    InvalidStateTransition {
        from: ReferralState,
        to: ReferralState,
    },

    #[error("No active referral operation")]
    NoActiveReferral,

    #[error("Generic referral error: {message}")]
    Generic { message: String },
}

/// Represents a resolved DSA endpoint for referral operations
///
/// This structure contains the parsed and validated endpoint information
/// needed to establish connections with remote DSAs.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedEndpoint {
    /// Target hostname or IP address
    pub host: String,
    /// Port number for connection
    pub port: u16,
    /// Base DN for this endpoint
    pub base_dn: String,
    /// Whether to use TLS/SSL
    pub use_tls: bool,
    /// Connection priority (lower values = higher priority)
    pub priority: u8,
    /// Connection weight for load balancing
    pub weight: u8,
}

impl ResolvedEndpoint {
    /// Create a new resolved endpoint
    ///
    /// # Arguments
    /// * `host` - Target hostname or IP
    /// * `port` - Connection port
    /// * `base_dn` - Base distinguished name
    ///
    /// # Returns
    /// * New ResolvedEndpoint instance
    pub fn new(host: String, port: u16, base_dn: String) -> Self {
        Self {
            host,
            port,
            base_dn,
            use_tls: false,
            priority: 0,
            weight: 1,
        }
    }

    /// Set TLS usage for this endpoint
    ///
    /// # Arguments
    /// * `use_tls` - Whether to use TLS encryption
    ///
    /// # Returns
    /// * Self for method chaining
    pub fn with_tls(mut self, use_tls: bool) -> Self {
        self.use_tls = use_tls;
        self
    }

    /// Set priority for this endpoint
    ///
    /// # Arguments
    /// * `priority` - Connection priority (0 = highest)
    ///
    /// # Returns
    /// * Self for method chaining
    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    /// Set weight for load balancing
    ///
    /// # Arguments
    /// * `weight` - Load balancing weight
    ///
    /// # Returns
    /// * Self for method chaining
    pub fn with_weight(mut self, weight: u8) -> Self {
        self.weight = weight;
        self
    }

    /// Get connection string for this endpoint
    ///
    /// # Returns
    /// * LDAP URL string for connection
    pub fn connection_string(&self) -> String {
        let scheme = if self.use_tls { "ldaps" } else { "ldap" };
        format!("{}://{}:{}/{}", scheme, self.host, self.port, self.base_dn)
    }
}

/// Represents referral request context
///
/// This structure contains the original request data and metadata
/// needed for referral processing.
#[derive(Debug, Clone)]
pub struct ReferralRequest {
    /// Original LDAP request data
    pub request_data: Vec<u8>,
    /// Client connection identifier
    pub client_id: String,
    /// Original base DN requested
    pub base_dn: String,
    /// Request type (search, modify, etc.)
    pub operation_type: String,
    /// Request timestamp
    pub timestamp: Instant,
}

impl ReferralRequest {
    /// Create a new referral request
    ///
    /// # Arguments
    /// * `request_data` - Raw LDAP request data
    /// * `client_id` - Client connection identifier
    /// * `base_dn` - Requested base DN
    /// * `operation_type` - LDAP operation type
    ///
    /// # Returns
    /// * New ReferralRequest instance
    pub fn new(
        request_data: Vec<u8>,
        client_id: String,
        base_dn: String,
        operation_type: String,
    ) -> Self {
        Self {
            request_data,
            client_id,
            base_dn,
            operation_type,
            timestamp: Instant::now(),
        }
    }

    /// Get request age in milliseconds
    ///
    /// # Returns
    /// * Age of request in milliseconds
    pub fn age_ms(&self) -> u64 {
        self.timestamp.elapsed().as_millis() as u64
    }
}

/// Trait for resolving referral URLs to DSA endpoints
///
/// This trait abstracts referral URL parsing and DSA endpoint resolution,
/// allowing different URL formats and resolution strategies.
#[async_trait]
pub trait ReferralResolver: Send + Sync {
    /// Parse and resolve referral URLs to DSA endpoints
    ///
    /// # Arguments
    /// * `urls` - List of referral URLs to resolve
    ///
    /// # Returns
    /// * `Ok(Vec<ResolvedEndpoint>)` - List of resolved DSA endpoints
    /// * `Err(String)` - Resolution error message
    async fn resolve_referral_urls(&self, urls: &[String])
        -> Result<Vec<ResolvedEndpoint>, String>;

    /// Validate a single referral URL format
    ///
    /// # Arguments
    /// * `url` - Referral URL to validate
    ///
    /// # Returns
    /// * `Ok(())` - URL is valid
    /// * `Err(String)` - Validation error message
    fn validate_referral_url(&self, url: &str) -> Result<(), String>;

    /// Get preferred endpoint from multiple options
    ///
    /// # Arguments
    /// * `endpoints` - Available endpoints to choose from
    ///
    /// # Returns
    /// * Option containing preferred endpoint
    fn select_preferred_endpoint<'a>(
        &self,
        endpoints: &'a [ResolvedEndpoint],
    ) -> Option<&'a ResolvedEndpoint> {
        // Default implementation selects by priority then weight
        endpoints.iter().min_by_key(|e| (e.priority, e.weight))
    }
}

/// Trait for handling chained requests to other DSAs
///
/// This trait abstracts server-to-server request forwarding,
/// allowing different chaining strategies and protocols.
#[async_trait]
pub trait ChainHandler: Send + Sync {
    /// Chain a request to another DSA server
    ///
    /// # Arguments
    /// * `target` - Target DSA endpoint
    /// * `request` - Request data to forward
    /// * `hop_count` - Current hop count
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Response data from target DSA
    /// * `Err(String)` - Chain error message
    async fn chain_request(
        &self,
        target: &str,
        request: &[u8],
        hop_count: u32,
    ) -> Result<Vec<u8>, String>;

    /// Check if chaining is supported for endpoint
    ///
    /// # Arguments
    /// * `endpoint` - Target endpoint to check
    ///
    /// # Returns
    /// * true if chaining is supported
    fn supports_chaining(&self, _endpoint: &ResolvedEndpoint) -> bool {
        // Default implementation supports all endpoints
        true
    }

    /// Get maximum chain depth allowed
    ///
    /// # Returns
    /// * Maximum number of hops for chaining
    fn max_chain_depth(&self) -> u32 {
        // Default maximum chain depth
        10
    }
}

/// Trait for handling proxied requests to other DSAs
///
/// This trait abstracts transparent client request proxying,
/// allowing different proxy strategies and connection pooling.
#[async_trait]
pub trait ProxyHandler: Send + Sync {
    /// Proxy a request to another DSA transparently
    ///
    /// # Arguments
    /// * `target` - Target DSA endpoint
    /// * `request` - Request data to proxy
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Response data from target DSA
    /// * `Err(String)` - Proxy error message
    async fn proxy_request(&self, target: &str, request: &[u8]) -> Result<Vec<u8>, String>;

    /// Check if proxying is supported for endpoint
    ///
    /// # Arguments
    /// * `endpoint` - Target endpoint to check
    ///
    /// # Returns
    /// * true if proxying is supported
    fn supports_proxying(&self, _endpoint: &ResolvedEndpoint) -> bool {
        // Default implementation supports all endpoints
        true
    }

    /// Get connection timeout for proxying
    ///
    /// # Returns
    /// * Timeout in milliseconds
    fn proxy_timeout_ms(&self) -> u64 {
        // Default proxy timeout
        30000
    }
}

/// Trait for low-level network communication with DSAs
///
/// This trait abstracts network-level communication,
/// allowing different transport protocols and connection management.
#[async_trait]
pub trait NetworkClient: Send + Sync {
    /// Send request to DSA endpoint with timeout
    ///
    /// # Arguments
    /// * `endpoint` - Target DSA endpoint
    /// * `request` - Request data to send
    /// * `timeout_ms` - Request timeout in milliseconds
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Response data from DSA
    /// * `Err(String)` - Network error message
    async fn send_request(
        &self,
        endpoint: &ResolvedEndpoint,
        request: &[u8],
        timeout_ms: u64,
    ) -> Result<Vec<u8>, String>;

    /// Check network connectivity to endpoint
    ///
    /// # Arguments
    /// * `endpoint` - Endpoint to check
    ///
    /// # Returns
    /// * `Ok(())` - Endpoint is reachable
    /// * `Err(String)` - Connectivity error
    async fn check_connectivity(&self, endpoint: &ResolvedEndpoint) -> Result<(), String> {
        // Default implementation attempts a minimal request
        let ping_request = vec![
            0x30, 0x0C, 0x02, 0x01, 0x01, 0x42, 0x07, 0x0A, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00,
        ];
        self.send_request(endpoint, &ping_request, 5000)
            .await
            .map(|_| ())
    }
}

/// Trait for referral operation metrics and monitoring
///
/// This trait provides hooks for performance monitoring,
/// audit logging, and operational insights for referral operations.
pub trait ReferralMetrics: Send + Sync {
    /// Record referral operation start
    ///
    /// # Arguments
    /// * `urls` - Referral URLs being processed
    /// * `hop_count` - Current hop count
    fn record_referral_start(&self, urls: &[String], hop_count: u32);

    /// Record referral resolution completion
    ///
    /// # Arguments
    /// * `urls` - Original referral URLs
    /// * `resolved_count` - Number of successfully resolved endpoints
    /// * `duration` - Resolution duration
    fn record_resolution_complete(
        &self,
        urls: &[String],
        resolved_count: usize,
        duration: Duration,
    );

    /// Record chain request sent
    ///
    /// # Arguments
    /// * `target` - Target DSA endpoint
    /// * `hop_count` - Hop count for request
    fn record_chain_request(&self, target: &str, hop_count: u32);

    /// Record proxy request sent
    ///
    /// # Arguments
    /// * `target` - Target DSA endpoint
    fn record_proxy_request(&self, target: &str);

    /// Record referral response received
    ///
    /// # Arguments
    /// * `target` - Source DSA endpoint
    /// * `response_size` - Size of response data
    /// * `duration` - Request duration
    fn record_response_received(&self, target: &str, response_size: usize, duration: Duration);

    /// Record referral operation completion
    ///
    /// # Arguments
    /// * `result_code` - Final result code
    /// * `total_duration` - Total operation duration
    fn record_referral_complete(&self, result_code: &ReferralResultCode, total_duration: Duration);

    /// Record referral error
    ///
    /// # Arguments
    /// * `error` - Error that occurred
    /// * `context` - Additional error context
    fn record_referral_error(&self, error: &ReferralFsmError, context: &str);

    /// Get referral statistics
    ///
    /// # Returns
    /// * (total_referrals, successful_referrals, failed_referrals, avg_hops)
    fn get_referral_stats(&self) -> (u64, u64, u64, f64) {
        // Default implementation returns zeros
        (0, 0, 0, 0.0)
    }
}

/// Configuration for referral FSM behavior
#[derive(Debug, Clone)]
pub struct ReferralConfig {
    /// Maximum number of hops allowed
    pub max_hop_limit: u32,
    /// Default request timeout in milliseconds
    pub default_timeout_ms: u64,
    /// Maximum number of concurrent referrals
    pub max_concurrent_referrals: usize,
    /// Enable automatic failover to backup URLs
    pub enable_failover: bool,
    /// Enable response caching
    pub enable_response_caching: bool,
    /// Cache TTL in seconds
    pub cache_ttl_seconds: u64,
}

impl Default for ReferralConfig {
    fn default() -> Self {
        Self {
            max_hop_limit: 10,
            default_timeout_ms: 30000,
            max_concurrent_referrals: 5,
            enable_failover: true,
            enable_response_caching: false,
            cache_ttl_seconds: 300,
        }
    }
}

/// Internal session data for active referral operations
#[derive(Debug)]
struct ReferralSession {
    /// Original referral URLs
    referral_urls: Vec<String>,
    /// Resolved DSA endpoints
    resolved_endpoints: Vec<ResolvedEndpoint>,
    /// Current target endpoint
    current_target: Option<String>,
    /// Current hop count
    hop_count: u32,
    /// Original client request
    request: Option<ReferralRequest>,
    /// Response data received
    response_data: Option<Vec<u8>>,
    /// Session start time
    start_time: Instant,
    /// Request sent time
    request_sent_time: Option<Instant>,
    /// Response received time
    response_received_time: Option<Instant>,
    /// Number of retry attempts
    retry_count: u32,
}

impl ReferralSession {
    /// Create a new referral session
    fn new(urls: Vec<String>, hop_count: u32) -> Self {
        Self {
            referral_urls: urls,
            resolved_endpoints: Vec::new(),
            current_target: None,
            hop_count,
            request: None,
            response_data: None,
            start_time: Instant::now(),
            request_sent_time: None,
            response_received_time: None,
            retry_count: 0,
        }
    }

    /// Get total session duration
    fn total_duration(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Get request duration if available
    fn request_duration(&self) -> Option<Duration> {
        if let (Some(sent), Some(received)) =
            (&self.request_sent_time, &self.response_received_time)
        {
            Some(received.duration_since(*sent))
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReferralExecutionMode {
    Chain,
    Proxy,
}

/// Main implementation of the Referral/Chaining FSM
pub struct ReferralFsmImpl {
    /// Current FSM state
    state: ReferralState,
    /// FSM configuration
    config: ReferralConfig,
    /// Active referral session
    session: Option<ReferralSession>,
    /// Request context waiting for the next referral session
    pending_request: Option<ReferralRequest>,
    /// Statistics counters
    total_referrals: u64,
    successful_referrals: u64,
    failed_referrals: u64,
    total_hops: u64,

    /// External dependency: Referral URL resolver
    resolver: Box<dyn ReferralResolver>,
    /// External dependency: Chain request handler
    chain_handler: Box<dyn ChainHandler>,
    /// External dependency: Proxy request handler  
    proxy_handler: Box<dyn ProxyHandler>,
    /// External dependency: Network client
    network_client: Box<dyn NetworkClient>,
    /// External dependency: Metrics collector (optional)
    metrics: Option<Box<dyn ReferralMetrics>>,
}

impl ReferralFsmImpl {
    /// Create a new Referral FSM instance
    ///
    /// # Arguments
    /// * `resolver` - Referral URL resolver
    /// * `chain_handler` - Chain request handler
    /// * `proxy_handler` - Proxy request handler
    /// * `network_client` - Network client
    ///
    /// # Returns
    /// * New ReferralFsmImpl instance
    pub fn new(
        resolver: Box<dyn ReferralResolver>,
        chain_handler: Box<dyn ChainHandler>,
        proxy_handler: Box<dyn ProxyHandler>,
        network_client: Box<dyn NetworkClient>,
    ) -> Self {
        Self {
            state: ReferralState::EvaluatingReferral,
            config: ReferralConfig::default(),
            session: None,
            pending_request: None,
            total_referrals: 0,
            successful_referrals: 0,
            failed_referrals: 0,
            total_hops: 0,
            resolver,
            chain_handler,
            proxy_handler,
            network_client,
            metrics: None,
        }
    }

    /// Create FSM with custom configuration
    ///
    /// # Arguments
    /// * `resolver` - Referral URL resolver
    /// * `chain_handler` - Chain request handler
    /// * `proxy_handler` - Proxy request handler
    /// * `network_client` - Network client
    /// * `config` - FSM configuration
    ///
    /// # Returns
    /// * New ReferralFsmImpl instance with custom config
    pub fn with_config(
        resolver: Box<dyn ReferralResolver>,
        chain_handler: Box<dyn ChainHandler>,
        proxy_handler: Box<dyn ProxyHandler>,
        network_client: Box<dyn NetworkClient>,
        config: ReferralConfig,
    ) -> Self {
        Self {
            state: ReferralState::EvaluatingReferral,
            config,
            session: None,
            pending_request: None,
            total_referrals: 0,
            successful_referrals: 0,
            failed_referrals: 0,
            total_hops: 0,
            resolver,
            chain_handler,
            proxy_handler,
            network_client,
            metrics: None,
        }
    }

    /// Set metrics collector
    ///
    /// # Arguments
    /// * `metrics` - Metrics collector instance
    ///
    /// # Returns
    /// * Self for method chaining
    pub fn with_metrics(mut self, metrics: Box<dyn ReferralMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Attach request context for the next or current referral execution.
    pub fn set_request_context(&mut self, request: ReferralRequest) {
        if let Some(session) = self.session.as_mut() {
            session.request = Some(request);
        } else {
            self.pending_request = Some(request);
        }
    }

    /// Get current configuration
    ///
    /// # Returns
    /// * Reference to current configuration
    pub fn config(&self) -> &ReferralConfig {
        &self.config
    }

    /// Get referral statistics
    ///
    /// # Returns
    /// * (total, successful, failed, avg_hops)
    pub fn get_stats(&self) -> (u64, u64, u64, f64) {
        let avg_hops = if self.total_referrals > 0 {
            self.total_hops as f64 / self.total_referrals as f64
        } else {
            0.0
        };
        (
            self.total_referrals,
            self.successful_referrals,
            self.failed_referrals,
            avg_hops,
        )
    }

    fn request_payload(session: &ReferralSession) -> Vec<u8> {
        session
            .request
            .as_ref()
            .map(|request| request.request_data.clone())
            .unwrap_or_default()
    }

    fn find_endpoint(
        endpoints: &[ResolvedEndpoint],
        target: &str,
    ) -> Result<usize, ReferralFsmError> {
        endpoints
            .iter()
            .position(|endpoint| {
                endpoint.host == target || endpoint.connection_string().contains(target)
            })
            .ok_or_else(|| ReferralFsmError::Generic {
                message: format!("Target '{}' not found in resolved endpoints", target),
            })
    }

    fn build_attempt_plan(
        &self,
        endpoints: &[ResolvedEndpoint],
        target: &str,
    ) -> Result<Vec<ResolvedEndpoint>, ReferralFsmError> {
        let selected_index = Self::find_endpoint(endpoints, target)?;
        let mut attempts = vec![endpoints[selected_index].clone()];

        if self.config.enable_failover {
            attempts.extend(
                endpoints
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| *index != selected_index)
                    .map(|(_, endpoint)| endpoint.clone()),
            );
        }

        Ok(attempts)
    }

    fn request_timeout_ms(&self, mode: ReferralExecutionMode) -> u64 {
        match mode {
            ReferralExecutionMode::Chain => self.config.default_timeout_ms,
            ReferralExecutionMode::Proxy => self.proxy_handler.proxy_timeout_ms(),
        }
    }

    fn record_request_metric(&self, mode: ReferralExecutionMode, target: &str, hop_count: u32) {
        if let Some(metrics) = &self.metrics {
            match mode {
                ReferralExecutionMode::Chain => metrics.record_chain_request(target, hop_count),
                ReferralExecutionMode::Proxy => metrics.record_proxy_request(target),
            }
        }
    }

    fn mark_attempt_started(
        &mut self,
        mode: ReferralExecutionMode,
        target: &str,
        hop_count: u32,
        retry_count: u32,
    ) -> Result<(), ReferralFsmError> {
        let session = self
            .session
            .as_mut()
            .ok_or(ReferralFsmError::NoActiveReferral)?;

        session.current_target = Some(target.to_string());
        session.retry_count = retry_count;
        session.request_sent_time = Some(Instant::now());
        session.response_received_time = None;
        session.response_data = None;

        self.state = match mode {
            ReferralExecutionMode::Chain => ReferralState::ChainRequest {
                target: target.to_string(),
                hop_count,
            },
            ReferralExecutionMode::Proxy => ReferralState::ProxyRequest {
                target: target.to_string(),
            },
        };

        self.record_request_metric(mode, target, hop_count);
        Ok(())
    }

    fn mark_execution_success(
        &mut self,
        mode: ReferralExecutionMode,
        target: &str,
        response: Vec<u8>,
        chain_hop_count: u32,
    ) -> Result<Option<Vec<u8>>, ReferralFsmError> {
        let session = self
            .session
            .as_mut()
            .ok_or(ReferralFsmError::NoActiveReferral)?;

        session.response_received_time = Some(Instant::now());
        if mode == ReferralExecutionMode::Chain {
            session.hop_count = chain_hop_count;
        }
        session.response_data = Some(response.clone());
        self.state = ReferralState::ProcessingResponse;

        if let Some(metrics) = &self.metrics {
            if let Some(duration) = session.request_duration() {
                metrics.record_response_received(target, response.len(), duration);
            }
        }

        Ok(None)
    }

    fn finalize_execution_error(
        &mut self,
        error: ReferralFsmError,
        context: &str,
    ) -> ReferralFsmError {
        self.state = ReferralState::Completed {
            result_code: ReferralResultCode::Unavailable,
        };
        self.failed_referrals += 1;

        if let Some(metrics) = &self.metrics {
            metrics.record_referral_error(&error, context);
            if let Some(session) = &self.session {
                metrics.record_referral_complete(
                    &ReferralResultCode::Unavailable,
                    session.total_duration(),
                );
            }
        }

        error
    }

    async fn execute_attempt(
        &self,
        mode: ReferralExecutionMode,
        endpoint: &ResolvedEndpoint,
        request_data: &[u8],
        hop_count: u32,
    ) -> Result<Vec<u8>, ReferralFsmError> {
        let timeout_ms = self.request_timeout_ms(mode);
        let operation = async {
            match mode {
                ReferralExecutionMode::Chain => self
                    .chain_handler
                    .chain_request(&endpoint.host, request_data, hop_count)
                    .await
                    .map_err(|message| ReferralFsmError::ChainError { message }),
                ReferralExecutionMode::Proxy => self
                    .proxy_handler
                    .proxy_request(&endpoint.host, request_data)
                    .await
                    .map_err(|message| ReferralFsmError::ProxyError { message }),
            }
        };

        match timeout(Duration::from_millis(timeout_ms), operation).await {
            Ok(result) => result,
            Err(_) => Err(ReferralFsmError::RequestTimeout {
                duration_ms: timeout_ms,
            }),
        }
    }

    async fn execute_referral_path(
        &mut self,
        mode: ReferralExecutionMode,
        target: String,
    ) -> Result<Option<Vec<u8>>, ReferralFsmError> {
        let (resolved_endpoints, request_data, current_hop_count) = {
            let session = self
                .session
                .as_ref()
                .ok_or(ReferralFsmError::NoActiveReferral)?;
            (
                session.resolved_endpoints.clone(),
                Self::request_payload(session),
                session.hop_count,
            )
        };

        if mode == ReferralExecutionMode::Chain && current_hop_count >= self.config.max_hop_limit {
            self.state = ReferralState::HopLimitExceeded;
            return Err(ReferralFsmError::HopLimitExceeded {
                current: current_hop_count,
                max: self.config.max_hop_limit,
            });
        }

        let attempt_plan = self.build_attempt_plan(&resolved_endpoints, &target)?;
        let chain_hop_count = current_hop_count + u32::from(mode == ReferralExecutionMode::Chain);
        let attempt_total = attempt_plan.len();
        let mut last_error: Option<ReferralFsmError> = None;

        for (attempt_index, endpoint) in attempt_plan.iter().enumerate() {
            let supported = match mode {
                ReferralExecutionMode::Chain => self.chain_handler.supports_chaining(endpoint),
                ReferralExecutionMode::Proxy => self.proxy_handler.supports_proxying(endpoint),
            };

            if !supported {
                last_error = Some(match mode {
                    ReferralExecutionMode::Chain => ReferralFsmError::ChainError {
                        message: format!(
                            "Chaining not supported for endpoint: {}",
                            endpoint.connection_string()
                        ),
                    },
                    ReferralExecutionMode::Proxy => ReferralFsmError::ProxyError {
                        message: format!(
                            "Proxying not supported for endpoint: {}",
                            endpoint.connection_string()
                        ),
                    },
                });

                if attempt_index + 1 == attempt_total {
                    let error = last_error.take().unwrap_or(ReferralFsmError::Generic {
                        message: "No supported referral endpoint".to_string(),
                    });
                    return Err(
                        self.finalize_execution_error(error, "All referral endpoints rejected")
                    );
                }

                continue;
            }

            self.mark_attempt_started(mode, &endpoint.host, chain_hop_count, attempt_index as u32)?;

            match self
                .execute_attempt(mode, endpoint, &request_data, chain_hop_count)
                .await
            {
                Ok(response) => {
                    return self.mark_execution_success(
                        mode,
                        &endpoint.host,
                        response,
                        chain_hop_count,
                    );
                }
                Err(error) => {
                    last_error = Some(error);
                    if attempt_index + 1 < attempt_total && self.config.enable_failover {
                        continue;
                    }
                }
            }
        }

        let context = match mode {
            ReferralExecutionMode::Chain => "Chain execution failed",
            ReferralExecutionMode::Proxy => "Proxy execution failed",
        };

        Err(self.finalize_execution_error(
            last_error.unwrap_or(ReferralFsmError::Generic {
                message: "Referral execution failed without an error".to_string(),
            }),
            context,
        ))
    }

    /// Handle referral received event
    ///
    /// # Arguments
    /// * `urls` - List of referral URLs
    ///
    /// # Returns
    /// * Result indicating success or error
    async fn handle_referral_received(
        &mut self,
        urls: Vec<String>,
    ) -> Result<Option<Vec<u8>>, ReferralFsmError> {
        // Validate current state
        if !matches!(self.state, ReferralState::EvaluatingReferral) {
            return Err(ReferralFsmError::InvalidStateTransition {
                from: self.state.clone(),
                to: ReferralState::EvaluatingReferral,
            });
        }

        // Validate referral URLs
        if urls.is_empty() {
            return Err(ReferralFsmError::InvalidReferralUrls {
                message: "No referral URLs provided".to_string(),
            });
        }

        // Validate each URL format
        for url in &urls {
            if let Err(e) = self.resolver.validate_referral_url(url) {
                return Err(ReferralFsmError::InvalidReferralUrls {
                    message: format!("Invalid URL '{}': {}", url, e),
                });
            }
        }

        // Create new session
        let mut session = ReferralSession::new(urls.clone(), 0);
        session.request = self.pending_request.take();
        self.session = Some(session);
        self.total_referrals += 1;

        // Record metrics
        if let Some(ref metrics) = self.metrics {
            metrics.record_referral_start(&urls, 0);
        }

        // Resolve referral URLs
        let start_time = Instant::now();
        let resolved_endpoints = self
            .resolver
            .resolve_referral_urls(&urls)
            .await
            .map_err(|e| ReferralFsmError::ResolverError { message: e })?;

        if resolved_endpoints.is_empty() {
            return Err(ReferralFsmError::NoAvailableEndpoints {
                attempted: urls.len(),
            });
        }

        // Update session with resolved endpoints
        let resolved_count = resolved_endpoints.len();
        if let Some(ref mut session) = self.session {
            session.resolved_endpoints = resolved_endpoints;
        }

        // Record resolution metrics
        if let Some(ref metrics) = self.metrics {
            metrics.record_resolution_complete(&urls, resolved_count, start_time.elapsed());
        }

        Ok(None)
    }

    /// Handle chain decision event
    ///
    /// # Arguments
    /// * `target` - Target DSA for chaining
    ///
    /// # Returns
    /// * Result indicating success or error
    async fn handle_chain_decision(
        &mut self,
        target: String,
    ) -> Result<Option<Vec<u8>>, ReferralFsmError> {
        self.execute_referral_path(ReferralExecutionMode::Chain, target)
            .await
    }

    /// Handle proxy decision event
    ///
    /// # Arguments
    /// * `target` - Target DSA for proxying
    ///
    /// # Returns
    /// * Result indicating success or error
    async fn handle_proxy_decision(
        &mut self,
        target: String,
    ) -> Result<Option<Vec<u8>>, ReferralFsmError> {
        self.execute_referral_path(ReferralExecutionMode::Proxy, target)
            .await
    }

    /// Handle request sent event
    ///
    /// # Returns
    /// * Result indicating success or error
    async fn handle_request_sent(&mut self) -> Result<Option<Vec<u8>>, ReferralFsmError> {
        if self.session.is_none() {
            return Err(ReferralFsmError::NoActiveReferral);
        }

        let previous_state = self.state.clone();
        if !matches!(
            previous_state,
            ReferralState::ChainRequest { .. } | ReferralState::ProxyRequest { .. }
        ) {
            return Err(ReferralFsmError::InvalidStateTransition {
                from: previous_state,
                to: ReferralState::AwaitingResponse,
            });
        }

        let session = self
            .session
            .as_mut()
            .ok_or(ReferralFsmError::NoActiveReferral)?;

        // Record request sent time
        session.request_sent_time = Some(Instant::now());

        if let Some(ref metrics) = self.metrics {
            if let Some(target) = &session.current_target {
                match previous_state {
                    ReferralState::ChainRequest { hop_count, .. } => {
                        metrics.record_chain_request(target, hop_count);
                    }
                    ReferralState::ProxyRequest { .. } => {
                        metrics.record_proxy_request(target);
                    }
                    _ => {}
                }
            }
        }

        // Update state to awaiting response
        self.state = ReferralState::AwaitingResponse;

        Ok(None)
    }

    /// Handle response received event
    ///
    /// # Arguments
    /// * `response` - Response data from DSA
    ///
    /// # Returns
    /// * Result indicating success or error
    async fn handle_response_received(
        &mut self,
        response: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, ReferralFsmError> {
        let session = self
            .session
            .as_mut()
            .ok_or(ReferralFsmError::NoActiveReferral)?;

        // Validate state
        if !matches!(self.state, ReferralState::AwaitingResponse) {
            return Err(ReferralFsmError::InvalidStateTransition {
                from: self.state.clone(),
                to: ReferralState::ProcessingResponse,
            });
        }

        // Record response received time
        session.response_received_time = Some(Instant::now());
        session.response_data = Some(response.clone());

        // Update state to processing response
        self.state = ReferralState::ProcessingResponse;

        // Record metrics
        if let Some(ref metrics) = self.metrics {
            if let (Some(target), Some(duration)) =
                (&session.current_target, session.request_duration())
            {
                metrics.record_response_received(target, response.len(), duration);
            }
        }

        Ok(None)
    }

    /// Handle processing complete event
    ///
    /// # Returns
    /// * Result indicating success or error
    async fn handle_processing_complete(&mut self) -> Result<Option<Vec<u8>>, ReferralFsmError> {
        let session = self
            .session
            .as_mut()
            .ok_or(ReferralFsmError::NoActiveReferral)?;

        // Validate state
        if !matches!(self.state, ReferralState::ProcessingResponse) {
            return Err(ReferralFsmError::InvalidStateTransition {
                from: self.state.clone(),
                to: ReferralState::Completed {
                    result_code: ReferralResultCode::Success,
                },
            });
        }

        // Update state to completed
        self.state = ReferralState::Completed {
            result_code: ReferralResultCode::Success,
        };

        // Update statistics
        self.successful_referrals += 1;
        self.total_hops += session.hop_count as u64;

        // Record completion metrics
        if let Some(ref metrics) = self.metrics {
            metrics
                .record_referral_complete(&ReferralResultCode::Success, session.total_duration());
        }

        // Return response data if available
        Ok(session.response_data.clone())
    }

    /// Handle hop limit reached event
    ///
    /// # Returns
    /// * Result containing error
    async fn handle_hop_limit_reached(&mut self) -> Result<Option<Vec<u8>>, ReferralFsmError> {
        let session = self
            .session
            .as_ref()
            .ok_or(ReferralFsmError::NoActiveReferral)?;

        // Update state
        self.state = ReferralState::HopLimitExceeded;
        self.failed_referrals += 1;

        // Record error metrics
        if let Some(ref metrics) = self.metrics {
            let error = ReferralFsmError::HopLimitExceeded {
                current: session.hop_count,
                max: self.config.max_hop_limit,
            };
            metrics.record_referral_error(&error, "Hop limit exceeded");
            metrics.record_referral_complete(
                &ReferralResultCode::HopLimitExceeded,
                session.total_duration(),
            );
        }

        Err(ReferralFsmError::HopLimitExceeded {
            current: session.hop_count,
            max: self.config.max_hop_limit,
        })
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
    ) -> Result<Option<Vec<u8>>, ReferralFsmError> {
        // Update state to completed with error
        self.state = ReferralState::Completed {
            result_code: ReferralResultCode::Unavailable,
        };
        self.failed_referrals += 1;

        let error = ReferralFsmError::Generic {
            message: error_message.clone(),
        };

        // Record error metrics
        if let Some(ref metrics) = self.metrics {
            metrics.record_referral_error(&error, "Generic error occurred");
            if let Some(ref session) = self.session {
                metrics.record_referral_complete(
                    &ReferralResultCode::Unavailable,
                    session.total_duration(),
                );
            }
        }

        Err(error)
    }
}

#[async_trait]
impl StateMachine for ReferralFsmImpl {
    type State = ReferralState;
    type Event = ReferralEvent;
    type Error = ReferralFsmError;
    type Output = Vec<u8>;

    fn current_state(&self) -> &Self::State {
        &self.state
    }

    fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            ReferralState::Completed { .. } | ReferralState::HopLimitExceeded
        )
    }

    async fn handle_event(
        &mut self,
        event: Self::Event,
    ) -> Result<Option<Self::Output>, Self::Error> {
        match event {
            ReferralEvent::ReferralReceived { urls } => self.handle_referral_received(urls).await,
            ReferralEvent::ChainDecision { target } => self.handle_chain_decision(target).await,
            ReferralEvent::ProxyDecision { target } => self.handle_proxy_decision(target).await,
            ReferralEvent::RequestSent => self.handle_request_sent().await,
            ReferralEvent::ResponseReceived(response) => {
                self.handle_response_received(response).await
            }
            ReferralEvent::ProcessingComplete => self.handle_processing_complete().await,
            ReferralEvent::HopLimitReached => self.handle_hop_limit_reached().await,
            ReferralEvent::Error(message) => self.handle_error(message).await,
        }
    }

    async fn reset(&mut self) -> Result<(), Self::Error> {
        self.state = ReferralState::EvaluatingReferral;
        self.session = None;
        self.pending_request = None;
        Ok(())
    }
}

#[async_trait]
impl ReferralFsm for ReferralFsmImpl {
    fn hop_count(&self) -> u32 {
        self.session.as_ref().map(|s| s.hop_count).unwrap_or(0)
    }

    fn hop_limit(&self) -> u32 {
        self.config.max_hop_limit
    }

    fn current_target(&self) -> Option<&str> {
        self.session
            .as_ref()
            .and_then(|s| s.current_target.as_deref())
    }

    fn referral_urls(&self) -> Option<&[String]> {
        self.session.as_ref().map(|s| s.referral_urls.as_slice())
    }
}

// ================================================================================================
// Mock Implementations for Testing
// ================================================================================================

#[cfg(test)]
pub mod mocks {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::sync::Mutex;

    /// Mock referral resolver for testing
    pub struct MockReferralResolver {
        should_fail_validate: bool,
        should_fail_resolve: bool,
        resolved_endpoints: Vec<ResolvedEndpoint>,
        call_log: Arc<Mutex<Vec<String>>>,
    }

    impl MockReferralResolver {
        pub fn new() -> Self {
            Self {
                should_fail_validate: false,
                should_fail_resolve: false,
                resolved_endpoints: vec![ResolvedEndpoint::new(
                    "test-server.example.com".to_string(),
                    389,
                    "dc=example,dc=org".to_string(),
                )],
                call_log: Arc::new(Mutex::new(Vec::new())),
            }
        }

        pub fn with_failure(mut self) -> Self {
            self.should_fail_validate = true;
            self.should_fail_resolve = true;
            self
        }

        pub fn with_resolve_failure(mut self) -> Self {
            self.should_fail_resolve = true;
            self
        }

        pub fn with_endpoints(mut self, endpoints: Vec<ResolvedEndpoint>) -> Self {
            self.resolved_endpoints = endpoints;
            self
        }

        pub fn call_log(&self) -> Vec<String> {
            self.call_log.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl ReferralResolver for MockReferralResolver {
        async fn resolve_referral_urls(
            &self,
            urls: &[String],
        ) -> Result<Vec<ResolvedEndpoint>, String> {
            self.call_log
                .lock()
                .unwrap()
                .push(format!("resolve_referral_urls: {:?}", urls));

            if self.should_fail_resolve {
                Err("Mock resolver failure".to_string())
            } else {
                Ok(self.resolved_endpoints.clone())
            }
        }

        fn validate_referral_url(&self, url: &str) -> Result<(), String> {
            self.call_log
                .lock()
                .unwrap()
                .push(format!("validate_referral_url: {}", url));

            if self.should_fail_validate {
                Err("Invalid URL format".to_string())
            } else if url.starts_with("ldap://") || url.starts_with("ldaps://") {
                Ok(())
            } else {
                Err("URL must start with ldap:// or ldaps://".to_string())
            }
        }
    }

    /// Mock chain handler for testing
    pub struct MockChainHandler {
        should_fail: bool,
        fail_targets: HashSet<String>,
        response_data: Vec<u8>,
        call_log: Arc<Mutex<Vec<String>>>,
    }

    impl MockChainHandler {
        pub fn new() -> Self {
            Self {
                should_fail: false,
                fail_targets: HashSet::new(),
                response_data: b"mock chain response".to_vec(),
                call_log: Arc::new(Mutex::new(Vec::new())),
            }
        }

        pub fn with_failure(mut self) -> Self {
            self.should_fail = true;
            self
        }

        pub fn with_response(mut self, response: Vec<u8>) -> Self {
            self.response_data = response;
            self
        }

        pub fn with_failed_target(mut self, target: &str) -> Self {
            self.fail_targets.insert(target.to_string());
            self
        }

        pub fn call_log(&self) -> Vec<String> {
            self.call_log.lock().unwrap().clone()
        }

        pub fn call_log_handle(&self) -> Arc<Mutex<Vec<String>>> {
            Arc::clone(&self.call_log)
        }
    }

    #[async_trait]
    impl ChainHandler for MockChainHandler {
        async fn chain_request(
            &self,
            target: &str,
            request: &[u8],
            hop_count: u32,
        ) -> Result<Vec<u8>, String> {
            self.call_log.lock().unwrap().push(format!(
                "chain_request: target={}, request_len={}, hop_count={}",
                target,
                request.len(),
                hop_count
            ));

            if self.should_fail || self.fail_targets.contains(target) {
                Err("Mock chain handler failure".to_string())
            } else {
                Ok(self.response_data.clone())
            }
        }
    }

    /// Mock proxy handler for testing
    pub struct MockProxyHandler {
        should_fail: bool,
        fail_targets: HashSet<String>,
        response_data: Vec<u8>,
        call_log: Arc<Mutex<Vec<String>>>,
    }

    impl MockProxyHandler {
        pub fn new() -> Self {
            Self {
                should_fail: false,
                fail_targets: HashSet::new(),
                response_data: b"mock proxy response".to_vec(),
                call_log: Arc::new(Mutex::new(Vec::new())),
            }
        }

        pub fn with_failure(mut self) -> Self {
            self.should_fail = true;
            self
        }

        pub fn with_response(mut self, response: Vec<u8>) -> Self {
            self.response_data = response;
            self
        }

        pub fn with_failed_target(mut self, target: &str) -> Self {
            self.fail_targets.insert(target.to_string());
            self
        }

        pub fn call_log(&self) -> Vec<String> {
            self.call_log.lock().unwrap().clone()
        }

        pub fn call_log_handle(&self) -> Arc<Mutex<Vec<String>>> {
            Arc::clone(&self.call_log)
        }
    }

    #[async_trait]
    impl ProxyHandler for MockProxyHandler {
        async fn proxy_request(&self, target: &str, request: &[u8]) -> Result<Vec<u8>, String> {
            self.call_log.lock().unwrap().push(format!(
                "proxy_request: target={}, request_len={}",
                target,
                request.len()
            ));

            if self.should_fail || self.fail_targets.contains(target) {
                Err("Mock proxy handler failure".to_string())
            } else {
                Ok(self.response_data.clone())
            }
        }
    }

    /// Mock network client for testing
    pub struct MockNetworkClient {
        should_fail: bool,
        response_data: Vec<u8>,
        call_log: Arc<Mutex<Vec<String>>>,
    }

    impl MockNetworkClient {
        pub fn new() -> Self {
            Self {
                should_fail: false,
                response_data: b"mock network response".to_vec(),
                call_log: Arc::new(Mutex::new(Vec::new())),
            }
        }

        pub fn with_failure(mut self) -> Self {
            self.should_fail = true;
            self
        }

        pub fn with_response(mut self, response: Vec<u8>) -> Self {
            self.response_data = response;
            self
        }

        pub fn call_log(&self) -> Vec<String> {
            self.call_log.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl NetworkClient for MockNetworkClient {
        async fn send_request(
            &self,
            endpoint: &ResolvedEndpoint,
            request: &[u8],
            timeout_ms: u64,
        ) -> Result<Vec<u8>, String> {
            self.call_log.lock().unwrap().push(format!(
                "send_request: endpoint={}, request_len={}, timeout={}ms",
                endpoint.connection_string(),
                request.len(),
                timeout_ms
            ));

            if self.should_fail {
                Err("Mock network client failure".to_string())
            } else {
                Ok(self.response_data.clone())
            }
        }
    }

    /// Mock metrics collector for testing
    pub struct MockReferralMetrics {
        call_log: Arc<Mutex<Vec<String>>>,
        stats: Arc<Mutex<(u64, u64, u64, f64)>>,
    }

    impl MockReferralMetrics {
        pub fn new() -> Self {
            Self {
                call_log: Arc::new(Mutex::new(Vec::new())),
                stats: Arc::new(Mutex::new((0, 0, 0, 0.0))),
            }
        }

        pub fn call_log(&self) -> Vec<String> {
            self.call_log.lock().unwrap().clone()
        }

        pub fn call_log_handle(&self) -> Arc<Mutex<Vec<String>>> {
            Arc::clone(&self.call_log)
        }

        pub fn with_stats(self, total: u64, successful: u64, failed: u64, avg_hops: f64) -> Self {
            *self.stats.lock().unwrap() = (total, successful, failed, avg_hops);
            self
        }
    }

    impl ReferralMetrics for MockReferralMetrics {
        fn record_referral_start(&self, urls: &[String], hop_count: u32) {
            self.call_log.lock().unwrap().push(format!(
                "record_referral_start: urls={:?}, hop_count={}",
                urls, hop_count
            ));
        }

        fn record_resolution_complete(
            &self,
            urls: &[String],
            resolved_count: usize,
            duration: Duration,
        ) {
            self.call_log.lock().unwrap().push(format!(
                "record_resolution_complete: urls={:?}, resolved_count={}, duration={:?}",
                urls, resolved_count, duration
            ));
        }

        fn record_chain_request(&self, target: &str, hop_count: u32) {
            self.call_log.lock().unwrap().push(format!(
                "record_chain_request: target={}, hop_count={}",
                target, hop_count
            ));
        }

        fn record_proxy_request(&self, target: &str) {
            self.call_log
                .lock()
                .unwrap()
                .push(format!("record_proxy_request: target={}", target));
        }

        fn record_response_received(&self, target: &str, response_size: usize, duration: Duration) {
            self.call_log.lock().unwrap().push(format!(
                "record_response_received: target={}, response_size={}, duration={:?}",
                target, response_size, duration
            ));
        }

        fn record_referral_complete(
            &self,
            result_code: &ReferralResultCode,
            total_duration: Duration,
        ) {
            self.call_log.lock().unwrap().push(format!(
                "record_referral_complete: result_code={:?}, total_duration={:?}",
                result_code, total_duration
            ));
        }

        fn record_referral_error(&self, error: &ReferralFsmError, context: &str) {
            self.call_log.lock().unwrap().push(format!(
                "record_referral_error: error={:?}, context={}",
                error, context
            ));
        }

        fn get_referral_stats(&self) -> (u64, u64, u64, f64) {
            *self.stats.lock().unwrap()
        }
    }
}

// ================================================================================================
// Unit Tests
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::mocks::*;
    use super::*;

    /// Helper function to create a basic FSM for testing
    fn create_test_fsm() -> ReferralFsmImpl {
        let resolver = Box::new(MockReferralResolver::new());
        let chain_handler = Box::new(MockChainHandler::new());
        let proxy_handler = Box::new(MockProxyHandler::new());
        let network_client = Box::new(MockNetworkClient::new());

        ReferralFsmImpl::new(resolver, chain_handler, proxy_handler, network_client)
    }

    /// Helper function to create FSM with metrics
    fn create_test_fsm_with_metrics() -> ReferralFsmImpl {
        let resolver = Box::new(MockReferralResolver::new());
        let chain_handler = Box::new(MockChainHandler::new());
        let proxy_handler = Box::new(MockProxyHandler::new());
        let network_client = Box::new(MockNetworkClient::new());
        let metrics = Box::new(MockReferralMetrics::new());

        ReferralFsmImpl::new(resolver, chain_handler, proxy_handler, network_client)
            .with_metrics(metrics)
    }

    #[tokio::test]
    async fn test_new_referral_fsm() {
        let fsm = create_test_fsm();

        // Verify initial state
        assert!(matches!(
            fsm.current_state(),
            ReferralState::EvaluatingReferral
        ));
        assert_eq!(fsm.hop_count(), 0);
        assert_eq!(fsm.hop_limit(), 10); // Default config
        assert!(fsm.current_target().is_none());
        assert!(fsm.referral_urls().is_none());

        // Verify initial statistics
        let (total, successful, failed, avg_hops) = fsm.get_stats();
        assert_eq!(total, 0);
        assert_eq!(successful, 0);
        assert_eq!(failed, 0);
        assert_eq!(avg_hops, 0.0);
    }

    #[tokio::test]
    async fn test_referral_fsm_with_config() {
        let config = ReferralConfig {
            max_hop_limit: 5,
            default_timeout_ms: 15000,
            max_concurrent_referrals: 3,
            enable_failover: false,
            enable_response_caching: true,
            cache_ttl_seconds: 600,
        };

        let resolver = Box::new(MockReferralResolver::new());
        let chain_handler = Box::new(MockChainHandler::new());
        let proxy_handler = Box::new(MockProxyHandler::new());
        let network_client = Box::new(MockNetworkClient::new());

        let fsm = ReferralFsmImpl::with_config(
            resolver,
            chain_handler,
            proxy_handler,
            network_client,
            config,
        );

        assert_eq!(fsm.hop_limit(), 5);
        assert_eq!(fsm.config().default_timeout_ms, 15000);
        assert_eq!(fsm.config().max_concurrent_referrals, 3);
        assert!(!fsm.config().enable_failover);
        assert!(fsm.config().enable_response_caching);
        assert_eq!(fsm.config().cache_ttl_seconds, 600);
    }

    #[tokio::test]
    async fn test_referral_received_success() {
        let mut fsm = create_test_fsm();
        let urls = vec![
            "ldap://server1.example.com/dc=example,dc=org".to_string(),
            "ldap://server2.example.com/dc=example,dc=org".to_string(),
        ];

        let result = fsm
            .handle_event(ReferralEvent::ReferralReceived { urls: urls.clone() })
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
        assert!(matches!(
            fsm.current_state(),
            ReferralState::EvaluatingReferral
        ));
        assert_eq!(fsm.referral_urls(), Some(urls.as_slice()));

        let (total, _, _, _) = fsm.get_stats();
        assert_eq!(total, 1);
    }

    #[tokio::test]
    async fn test_referral_received_empty_urls() {
        let mut fsm = create_test_fsm();

        let result = fsm
            .handle_event(ReferralEvent::ReferralReceived { urls: vec![] })
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ReferralFsmError::InvalidReferralUrls { .. }
        ));
    }

    #[tokio::test]
    async fn test_referral_received_invalid_url() {
        let resolver = Box::new(MockReferralResolver::new().with_failure());
        let chain_handler = Box::new(MockChainHandler::new());
        let proxy_handler = Box::new(MockProxyHandler::new());
        let network_client = Box::new(MockNetworkClient::new());

        let mut fsm = ReferralFsmImpl::new(resolver, chain_handler, proxy_handler, network_client);

        let result = fsm
            .handle_event(ReferralEvent::ReferralReceived {
                urls: vec!["invalid-url".to_string()],
            })
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ReferralFsmError::InvalidReferralUrls { .. }
        ));
    }

    #[tokio::test]
    async fn test_referral_received_resolver_error() {
        let resolver = Box::new(MockReferralResolver::new().with_resolve_failure());
        let chain_handler = Box::new(MockChainHandler::new());
        let proxy_handler = Box::new(MockProxyHandler::new());
        let network_client = Box::new(MockNetworkClient::new());

        let mut fsm = ReferralFsmImpl::new(resolver, chain_handler, proxy_handler, network_client);

        // Receive referral - should pass URL validation but fail on resolution
        let result = fsm
            .handle_event(ReferralEvent::ReferralReceived {
                urls: vec!["ldap://test.example.com/dc=test,dc=org".to_string()],
            })
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ReferralFsmError::ResolverError { .. }
        ));
    }

    #[tokio::test]
    async fn test_chain_decision_success() {
        let mut fsm = create_test_fsm();
        let request = ReferralRequest::new(
            b"test request".to_vec(),
            "client-1".to_string(),
            "dc=example,dc=org".to_string(),
            "search".to_string(),
        );
        fsm.set_request_context(request);

        // First receive referral
        fsm.handle_event(ReferralEvent::ReferralReceived {
            urls: vec!["ldap://test-server.example.com/dc=example,dc=org".to_string()],
        })
        .await
        .unwrap();

        // Then make chain decision
        let result = fsm
            .handle_event(ReferralEvent::ChainDecision {
                target: "test-server.example.com".to_string(),
            })
            .await;

        assert!(result.is_ok());
        assert!(matches!(
            fsm.current_state(),
            ReferralState::ProcessingResponse
        ));
        assert_eq!(fsm.hop_count(), 1);
        assert_eq!(fsm.current_target(), Some("test-server.example.com"));
        assert_eq!(
            fsm.handle_event(ReferralEvent::ProcessingComplete)
                .await
                .unwrap(),
            Some(b"mock chain response".to_vec())
        );
    }

    #[tokio::test]
    async fn test_chain_decision_no_active_referral() {
        let mut fsm = create_test_fsm();

        let result = fsm
            .handle_event(ReferralEvent::ChainDecision {
                target: "test-server.example.com".to_string(),
            })
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ReferralFsmError::NoActiveReferral
        ));
    }

    #[tokio::test]
    async fn test_chain_decision_hop_limit_exceeded() {
        let config = ReferralConfig {
            max_hop_limit: 1,
            ..Default::default()
        };

        let resolver = Box::new(MockReferralResolver::new());
        let chain_handler = Box::new(MockChainHandler::new());
        let proxy_handler = Box::new(MockProxyHandler::new());
        let network_client = Box::new(MockNetworkClient::new());

        let mut fsm = ReferralFsmImpl::with_config(
            resolver,
            chain_handler,
            proxy_handler,
            network_client,
            config,
        );

        // Receive referral and make first chain decision
        fsm.handle_event(ReferralEvent::ReferralReceived {
            urls: vec!["ldap://test-server.example.com/dc=example,dc=org".to_string()],
        })
        .await
        .unwrap();

        fsm.handle_event(ReferralEvent::ChainDecision {
            target: "test-server.example.com".to_string(),
        })
        .await
        .unwrap();

        // Try to chain again - should hit hop limit
        let result = fsm
            .handle_event(ReferralEvent::ChainDecision {
                target: "test-server.example.com".to_string(),
            })
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ReferralFsmError::HopLimitExceeded { .. }
        ));
        assert!(matches!(
            fsm.current_state(),
            ReferralState::HopLimitExceeded
        ));
    }

    #[tokio::test]
    async fn test_proxy_decision_success() {
        let mut fsm = create_test_fsm();
        let request = ReferralRequest::new(
            b"proxy request".to_vec(),
            "client-1".to_string(),
            "dc=example,dc=org".to_string(),
            "search".to_string(),
        );
        fsm.set_request_context(request);

        // First receive referral
        fsm.handle_event(ReferralEvent::ReferralReceived {
            urls: vec!["ldap://test-server.example.com/dc=example,dc=org".to_string()],
        })
        .await
        .unwrap();

        // Then make proxy decision
        let result = fsm
            .handle_event(ReferralEvent::ProxyDecision {
                target: "test-server.example.com".to_string(),
            })
            .await;

        assert!(result.is_ok());
        assert!(matches!(
            fsm.current_state(),
            ReferralState::ProcessingResponse
        ));
        assert_eq!(fsm.current_target(), Some("test-server.example.com"));
        assert_eq!(
            fsm.handle_event(ReferralEvent::ProcessingComplete)
                .await
                .unwrap(),
            Some(b"mock proxy response".to_vec())
        );
    }

    #[tokio::test]
    async fn test_proxy_decision_no_active_referral() {
        let mut fsm = create_test_fsm();

        let result = fsm
            .handle_event(ReferralEvent::ProxyDecision {
                target: "test-server.example.com".to_string(),
            })
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ReferralFsmError::NoActiveReferral
        ));
    }

    #[tokio::test]
    async fn test_request_sent_success() {
        let mut fsm = create_test_fsm();

        // Setup: receive referral and place the FSM in the pre-send chain state.
        fsm.handle_event(ReferralEvent::ReferralReceived {
            urls: vec!["ldap://test-server.example.com/dc=example,dc=org".to_string()],
        })
        .await
        .unwrap();

        if let Some(session) = fsm.session.as_mut() {
            session.current_target = Some("test-server.example.com".to_string());
            session.hop_count = 1;
        }
        fsm.state = ReferralState::ChainRequest {
            target: "test-server.example.com".to_string(),
            hop_count: 1,
        };

        // Send request
        let result = fsm.handle_event(ReferralEvent::RequestSent).await;

        assert!(result.is_ok());
        assert!(matches!(
            fsm.current_state(),
            ReferralState::AwaitingResponse
        ));
    }

    #[tokio::test]
    async fn test_request_sent_before_routing_decision_is_rejected_without_mutation() {
        let mut fsm = create_test_fsm();
        fsm.handle_event(ReferralEvent::ReferralReceived {
            urls: vec!["ldap://test-server.example.com/dc=example,dc=org".to_string()],
        })
        .await
        .unwrap();

        let stats_before = fsm.get_stats();
        let result = fsm.handle_event(ReferralEvent::RequestSent).await;

        assert!(matches!(
            result.unwrap_err(),
            ReferralFsmError::InvalidStateTransition {
                from: ReferralState::EvaluatingReferral,
                to: ReferralState::AwaitingResponse,
            }
        ));
        assert_eq!(fsm.current_state(), &ReferralState::EvaluatingReferral);
        assert_eq!(fsm.get_stats(), stats_before);
        assert!(fsm.current_target().is_none());
    }

    #[tokio::test]
    async fn test_request_sent_no_active_referral() {
        let mut fsm = create_test_fsm();

        let result = fsm.handle_event(ReferralEvent::RequestSent).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ReferralFsmError::NoActiveReferral
        ));
    }

    #[tokio::test]
    async fn test_response_received_success() {
        let mut fsm = create_test_fsm();
        let response_data = b"test response".to_vec();

        // Setup: full flow to awaiting response using the legacy low-level events.
        fsm.handle_event(ReferralEvent::ReferralReceived {
            urls: vec!["ldap://test-server.example.com/dc=example,dc=org".to_string()],
        })
        .await
        .unwrap();

        if let Some(session) = fsm.session.as_mut() {
            session.current_target = Some("test-server.example.com".to_string());
            session.hop_count = 1;
        }
        fsm.state = ReferralState::ChainRequest {
            target: "test-server.example.com".to_string(),
            hop_count: 1,
        };

        fsm.handle_event(ReferralEvent::RequestSent).await.unwrap();

        // Receive response
        let result = fsm
            .handle_event(ReferralEvent::ResponseReceived(response_data.clone()))
            .await;

        assert!(result.is_ok());
        assert!(matches!(
            fsm.current_state(),
            ReferralState::ProcessingResponse
        ));
    }

    #[tokio::test]
    async fn test_response_received_invalid_state() {
        let mut fsm = create_test_fsm();

        let result = fsm
            .handle_event(ReferralEvent::ResponseReceived(vec![]))
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ReferralFsmError::NoActiveReferral
        ));
    }

    #[tokio::test]
    async fn test_processing_complete_success() {
        let mut fsm = create_test_fsm();
        let request = ReferralRequest::new(
            b"test request".to_vec(),
            "client-1".to_string(),
            "dc=example,dc=org".to_string(),
            "search".to_string(),
        );
        fsm.set_request_context(request);

        // Setup: direct execution path to processing response
        fsm.handle_event(ReferralEvent::ReferralReceived {
            urls: vec!["ldap://test-server.example.com/dc=example,dc=org".to_string()],
        })
        .await
        .unwrap();

        fsm.handle_event(ReferralEvent::ChainDecision {
            target: "test-server.example.com".to_string(),
        })
        .await
        .unwrap();

        // Complete processing
        let result = fsm.handle_event(ReferralEvent::ProcessingComplete).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some(b"mock chain response".to_vec()));
        assert!(matches!(
            fsm.current_state(),
            ReferralState::Completed {
                result_code: ReferralResultCode::Success
            }
        ));

        let (total, successful, failed, _) = fsm.get_stats();
        assert_eq!(total, 1);
        assert_eq!(successful, 1);
        assert_eq!(failed, 0);
    }

    #[tokio::test]
    async fn test_processing_complete_invalid_state() {
        let mut fsm = create_test_fsm();

        let result = fsm.handle_event(ReferralEvent::ProcessingComplete).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ReferralFsmError::NoActiveReferral
        ));
    }

    #[tokio::test]
    async fn test_hop_limit_reached() {
        let mut fsm = create_test_fsm();

        // Setup: receive referral first
        fsm.handle_event(ReferralEvent::ReferralReceived {
            urls: vec!["ldap://test-server.example.com/dc=example,dc=org".to_string()],
        })
        .await
        .unwrap();

        let result = fsm.handle_event(ReferralEvent::HopLimitReached).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ReferralFsmError::HopLimitExceeded { .. }
        ));
        assert!(matches!(
            fsm.current_state(),
            ReferralState::HopLimitExceeded
        ));

        let (total, successful, failed, _) = fsm.get_stats();
        assert_eq!(total, 1);
        assert_eq!(successful, 0);
        assert_eq!(failed, 1);
    }

    #[tokio::test]
    async fn test_error_event() {
        let mut fsm = create_test_fsm();
        let error_message = "Test error message";

        let result = fsm
            .handle_event(ReferralEvent::Error(error_message.to_string()))
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ReferralFsmError::Generic { .. }
        ));
        assert!(matches!(
            fsm.current_state(),
            ReferralState::Completed {
                result_code: ReferralResultCode::Unavailable
            }
        ));

        let (total, successful, failed, _) = fsm.get_stats();
        assert_eq!(total, 0); // No referral was started
        assert_eq!(successful, 0);
        assert_eq!(failed, 1);
    }

    #[tokio::test]
    async fn test_fsm_reset() {
        let mut fsm = create_test_fsm();

        // Setup: progress through some states
        fsm.handle_event(ReferralEvent::ReferralReceived {
            urls: vec!["ldap://test-server.example.com/dc=example,dc=org".to_string()],
        })
        .await
        .unwrap();

        fsm.handle_event(ReferralEvent::ChainDecision {
            target: "test-server.example.com".to_string(),
        })
        .await
        .unwrap();

        // Reset FSM
        let result = fsm.reset().await;

        assert!(result.is_ok());
        assert!(matches!(
            fsm.current_state(),
            ReferralState::EvaluatingReferral
        ));
        assert_eq!(fsm.hop_count(), 0);
        assert!(fsm.current_target().is_none());
        assert!(fsm.referral_urls().is_none());
    }

    #[tokio::test]
    async fn test_is_terminal_states() {
        let mut fsm = create_test_fsm();

        // Initial state should not be terminal
        assert!(!fsm.is_terminal());

        // Set to completed state
        fsm.handle_event(ReferralEvent::Error("test".to_string()))
            .await
            .unwrap_err();
        assert!(fsm.is_terminal());

        // Reset and test hop limit exceeded
        fsm.reset().await.unwrap();
        assert!(!fsm.is_terminal());

        fsm.handle_event(ReferralEvent::ReferralReceived {
            urls: vec!["ldap://test-server.example.com/dc=example,dc=org".to_string()],
        })
        .await
        .unwrap();

        fsm.handle_event(ReferralEvent::HopLimitReached)
            .await
            .unwrap_err();
        assert!(fsm.is_terminal());
    }

    #[tokio::test]
    async fn test_referral_fsm_with_metrics() {
        let resolver = Box::new(MockReferralResolver::new());
        let chain_handler = Box::new(MockChainHandler::new());
        let proxy_handler = Box::new(MockProxyHandler::new());
        let network_client = Box::new(MockNetworkClient::new());
        let metrics = MockReferralMetrics::new();
        let metric_log = metrics.call_log_handle();

        let mut fsm = ReferralFsmImpl::new(resolver, chain_handler, proxy_handler, network_client)
            .with_metrics(Box::new(metrics));
        fsm.set_request_context(ReferralRequest::new(
            b"request".to_vec(),
            "client-1".to_string(),
            "dc=example,dc=org".to_string(),
            "search".to_string(),
        ));

        // Perform full successful referral flow
        fsm.handle_event(ReferralEvent::ReferralReceived {
            urls: vec!["ldap://test-server.example.com/dc=example,dc=org".to_string()],
        })
        .await
        .unwrap();

        fsm.handle_event(ReferralEvent::ChainDecision {
            target: "test-server.example.com".to_string(),
        })
        .await
        .unwrap();

        fsm.handle_event(ReferralEvent::ProcessingComplete)
            .await
            .unwrap();

        let log = metric_log.lock().unwrap().clone();
        assert!(log
            .iter()
            .any(|entry| entry.contains("record_chain_request: target=test-server.example.com")));
        assert!(!log
            .iter()
            .any(|entry| entry.contains("record_proxy_request")));
        assert!(log
            .iter()
            .any(|entry| entry.contains("record_response_received")));

        let (total, successful, failed, avg_hops) = fsm.get_stats();
        assert_eq!(total, 1);
        assert_eq!(successful, 1);
        assert_eq!(failed, 0);
        assert_eq!(avg_hops, 1.0);
    }

    #[tokio::test]
    async fn test_chain_decision_failover_uses_second_endpoint() {
        let resolver = Box::new(MockReferralResolver::new().with_endpoints(vec![
            ResolvedEndpoint::new(
                "primary.example.com".to_string(),
                389,
                "dc=example,dc=org".to_string(),
            ),
            ResolvedEndpoint::new(
                "secondary.example.com".to_string(),
                389,
                "dc=example,dc=org".to_string(),
            ),
        ]));
        let chain_handler = MockChainHandler::new().with_failed_target("primary.example.com");
        let chain_log = chain_handler.call_log_handle();
        let proxy_handler = Box::new(MockProxyHandler::new());
        let network_client = Box::new(MockNetworkClient::new());

        let mut fsm = ReferralFsmImpl::new(
            resolver,
            Box::new(chain_handler),
            proxy_handler,
            network_client,
        );
        fsm.set_request_context(ReferralRequest::new(
            b"request".to_vec(),
            "client-1".to_string(),
            "dc=example,dc=org".to_string(),
            "search".to_string(),
        ));

        fsm.handle_event(ReferralEvent::ReferralReceived {
            urls: vec![
                "ldap://primary.example.com/dc=example,dc=org".to_string(),
                "ldap://secondary.example.com/dc=example,dc=org".to_string(),
            ],
        })
        .await
        .unwrap();

        fsm.handle_event(ReferralEvent::ChainDecision {
            target: "primary.example.com".to_string(),
        })
        .await
        .unwrap();

        let log = chain_log.lock().unwrap().clone();
        assert_eq!(log.len(), 2);
        assert!(log[0].contains("target=primary.example.com"));
        assert!(log[0].contains("request_len=7"));
        assert!(log[1].contains("target=secondary.example.com"));
        assert_eq!(fsm.current_target(), Some("secondary.example.com"));
        assert!(matches!(
            fsm.current_state(),
            ReferralState::ProcessingResponse
        ));
    }

    // ================================================================================================
    // Test helper structures
    // ================================================================================================

    #[tokio::test]
    async fn test_resolved_endpoint_methods() {
        let mut endpoint = ResolvedEndpoint::new(
            "test.example.com".to_string(),
            389,
            "dc=test,dc=org".to_string(),
        );

        assert_eq!(endpoint.host, "test.example.com");
        assert_eq!(endpoint.port, 389);
        assert_eq!(endpoint.base_dn, "dc=test,dc=org");
        assert!(!endpoint.use_tls);
        assert_eq!(endpoint.priority, 0);
        assert_eq!(endpoint.weight, 1);

        // Test method chaining
        endpoint = endpoint.with_tls(true).with_priority(5).with_weight(10);

        assert!(endpoint.use_tls);
        assert_eq!(endpoint.priority, 5);
        assert_eq!(endpoint.weight, 10);

        // Test connection string
        let conn_str = endpoint.connection_string();
        assert!(conn_str.starts_with("ldaps://"));
        assert!(conn_str.contains("test.example.com"));
        assert!(conn_str.contains("389"));
        assert!(conn_str.contains("dc=test,dc=org"));
    }

    #[tokio::test]
    async fn test_referral_request_methods() {
        let request = ReferralRequest::new(
            b"test request".to_vec(),
            "client-123".to_string(),
            "dc=test,dc=org".to_string(),
            "search".to_string(),
        );

        assert_eq!(request.request_data, b"test request");
        assert_eq!(request.client_id, "client-123");
        assert_eq!(request.base_dn, "dc=test,dc=org");
        assert_eq!(request.operation_type, "search");

        // Age should be very small (just created)
        assert!(request.age_ms() < 100);
    }

    #[tokio::test]
    async fn test_default_config() {
        let config = ReferralConfig::default();

        assert_eq!(config.max_hop_limit, 10);
        assert_eq!(config.default_timeout_ms, 30000);
        assert_eq!(config.max_concurrent_referrals, 5);
        assert!(config.enable_failover);
        assert!(!config.enable_response_caching);
        assert_eq!(config.cache_ttl_seconds, 300);
    }

    #[tokio::test]
    async fn test_mock_resolver_methods() {
        let resolver = MockReferralResolver::new();

        // Test URL validation
        assert!(resolver
            .validate_referral_url("ldap://test.com/dc=test,dc=org")
            .is_ok());
        assert!(resolver
            .validate_referral_url("ldaps://test.com/dc=test,dc=org")
            .is_ok());
        assert!(resolver.validate_referral_url("invalid-url").is_err());

        // Test resolution
        let urls = vec!["ldap://test.com/dc=test,dc=org".to_string()];
        let result = resolver.resolve_referral_urls(&urls).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);

        // Test call log
        let log = resolver.call_log();
        assert!(!log.is_empty());
        assert!(log
            .iter()
            .any(|entry| entry.contains("validate_referral_url")));
        assert!(log
            .iter()
            .any(|entry| entry.contains("resolve_referral_urls")));
    }

    #[tokio::test]
    async fn test_mock_chain_handler_methods() {
        let handler = MockChainHandler::new();

        let result = handler.chain_request("test.com", b"request", 1).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"mock chain response");

        let log = handler.call_log();
        assert_eq!(log.len(), 1);
        assert!(log[0].contains("chain_request"));
    }

    #[tokio::test]
    async fn test_mock_proxy_handler_methods() {
        let handler = MockProxyHandler::new();

        let result = handler.proxy_request("test.com", b"request").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"mock proxy response");

        let log = handler.call_log();
        assert_eq!(log.len(), 1);
        assert!(log[0].contains("proxy_request"));
    }

    #[tokio::test]
    async fn test_mock_network_client_methods() {
        let client = MockNetworkClient::new();
        let endpoint =
            ResolvedEndpoint::new("test.com".to_string(), 389, "dc=test,dc=org".to_string());

        let result = client.send_request(&endpoint, b"request", 5000).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"mock network response");

        // Test connectivity check
        let result = client.check_connectivity(&endpoint).await;
        assert!(result.is_ok());

        let log = client.call_log();
        assert_eq!(log.len(), 2); // send_request called twice (once direct, once via connectivity check)
    }

    #[tokio::test]
    async fn test_mock_metrics_methods() {
        let metrics = MockReferralMetrics::new().with_stats(10, 8, 2, 2.5);

        let urls = vec!["ldap://test.com".to_string()];
        metrics.record_referral_start(&urls, 0);
        metrics.record_resolution_complete(&urls, 1, Duration::from_millis(100));
        metrics.record_chain_request("test.com", 1);
        metrics.record_proxy_request("test.com");
        metrics.record_response_received("test.com", 1024, Duration::from_millis(500));
        metrics.record_referral_complete(&ReferralResultCode::Success, Duration::from_secs(1));
        metrics.record_referral_error(
            &ReferralFsmError::Generic {
                message: "test".to_string(),
            },
            "test context",
        );

        let log = metrics.call_log();
        assert_eq!(log.len(), 7);

        let stats = metrics.get_referral_stats();
        assert_eq!(stats, (10, 8, 2, 2.5));
    }
}

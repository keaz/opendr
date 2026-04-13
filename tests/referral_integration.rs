//! Integration tests for LDAP referral and chaining functionality
//!
//! These tests verify the complete referral workflow including:
//! - Referral URL parsing and validation
//! - Endpoint resolution
//! - Hop limit enforcement
//! - Chain request handling
//! - Proxy request handling
//! - Error handling and recovery

use async_trait::async_trait;
use opendr::fsm::{ReferralEvent, ReferralFsm, ReferralResultCode, ReferralState, StateMachine};
use opendr::referral::LdapReferralResolver;
use opendr::referral_fsm::{
    ChainHandler, NetworkClient, ProxyHandler, ReferralConfig, ReferralFsmError, ReferralFsmImpl,
    ReferralMetrics, ReferralRequest, ReferralResolver, ResolvedEndpoint,
};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

struct RecordingChainHandler {
    failed_targets: HashSet<String>,
    response: Vec<u8>,
    log: Arc<Mutex<Vec<String>>>,
}

impl RecordingChainHandler {
    fn new() -> Self {
        Self {
            failed_targets: HashSet::new(),
            response: b"mock chained response".to_vec(),
            log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn with_failed_target(mut self, target: &str) -> Self {
        self.failed_targets.insert(target.to_string());
        self
    }

    fn log_handle(&self) -> Arc<Mutex<Vec<String>>> {
        Arc::clone(&self.log)
    }
}

#[async_trait]
impl ChainHandler for RecordingChainHandler {
    async fn chain_request(
        &self,
        target: &str,
        request: &[u8],
        hop_count: u32,
    ) -> Result<Vec<u8>, String> {
        self.log.lock().unwrap().push(format!(
            "chain_request: target={}, request_len={}, hop_count={}",
            target,
            request.len(),
            hop_count
        ));

        if self.failed_targets.contains(target) {
            Err(format!("chain failure for {}", target))
        } else {
            Ok(self.response.clone())
        }
    }
}

struct RecordingProxyHandler {
    failed_targets: HashSet<String>,
    response: Vec<u8>,
    log: Arc<Mutex<Vec<String>>>,
}

impl RecordingProxyHandler {
    fn new() -> Self {
        Self {
            failed_targets: HashSet::new(),
            response: b"mock proxied response".to_vec(),
            log: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[async_trait]
impl ProxyHandler for RecordingProxyHandler {
    async fn proxy_request(&self, target: &str, request: &[u8]) -> Result<Vec<u8>, String> {
        self.log.lock().unwrap().push(format!(
            "proxy_request: target={}, request_len={}",
            target,
            request.len()
        ));

        if self.failed_targets.contains(target) {
            Err(format!("proxy failure for {}", target))
        } else {
            Ok(self.response.clone())
        }
    }
}

struct RecordingNetworkClient;

#[async_trait]
impl NetworkClient for RecordingNetworkClient {
    async fn send_request(
        &self,
        _endpoint: &ResolvedEndpoint,
        _request: &[u8],
        _timeout_ms: u64,
    ) -> Result<Vec<u8>, String> {
        Ok(b"network response".to_vec())
    }
}

struct RecordingMetrics {
    log: Arc<Mutex<Vec<String>>>,
}

impl RecordingMetrics {
    fn new() -> Self {
        Self {
            log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn log_handle(&self) -> Arc<Mutex<Vec<String>>> {
        Arc::clone(&self.log)
    }
}

impl ReferralMetrics for RecordingMetrics {
    fn record_referral_start(&self, urls: &[String], hop_count: u32) {
        self.log.lock().unwrap().push(format!(
            "record_referral_start: urls={:?}, hop_count={}",
            urls, hop_count
        ));
    }

    fn record_resolution_complete(
        &self,
        urls: &[String],
        resolved_count: usize,
        _duration: Duration,
    ) {
        self.log.lock().unwrap().push(format!(
            "record_resolution_complete: urls={:?}, resolved_count={}",
            urls, resolved_count
        ));
    }

    fn record_chain_request(&self, target: &str, hop_count: u32) {
        self.log.lock().unwrap().push(format!(
            "record_chain_request: target={}, hop_count={}",
            target, hop_count
        ));
    }

    fn record_proxy_request(&self, target: &str) {
        self.log
            .lock()
            .unwrap()
            .push(format!("record_proxy_request: target={}", target));
    }

    fn record_response_received(&self, target: &str, response_size: usize, _duration: Duration) {
        self.log.lock().unwrap().push(format!(
            "record_response_received: target={}, response_size={}",
            target, response_size
        ));
    }

    fn record_referral_complete(
        &self,
        result_code: &ReferralResultCode,
        _total_duration: Duration,
    ) {
        self.log.lock().unwrap().push(format!(
            "record_referral_complete: result_code={:?}",
            result_code
        ));
    }

    fn record_referral_error(&self, error: &ReferralFsmError, context: &str) {
        self.log.lock().unwrap().push(format!(
            "record_referral_error: error={:?}, context={}",
            error, context
        ));
    }
}

fn create_flow_fsm(
    config: Option<ReferralConfig>,
    chain_handler: Box<dyn ChainHandler>,
    proxy_handler: Box<dyn ProxyHandler>,
) -> ReferralFsmImpl {
    let resolver = Box::new(LdapReferralResolver::new());
    let network_client = Box::new(RecordingNetworkClient);

    match config {
        Some(config) => ReferralFsmImpl::with_config(
            resolver,
            chain_handler,
            proxy_handler,
            network_client,
            config,
        ),
        None => ReferralFsmImpl::new(resolver, chain_handler, proxy_handler, network_client),
    }
}

fn attach_request_context(fsm: &mut ReferralFsmImpl) {
    fsm.set_request_context(ReferralRequest::new(
        b"integration request".to_vec(),
        "client-1".to_string(),
        "dc=example,dc=org".to_string(),
        "search".to_string(),
    ));
}

// ================================================================================================
// Test: Referral URL Parsing and Resolution
// ================================================================================================

#[tokio::test]
async fn test_referral_url_parsing_ldap() {
    let resolver = LdapReferralResolver::new();

    let urls = vec!["ldap://server1.example.com/dc=example,dc=org".to_string()];

    let result = resolver.resolve_referral_urls(&urls).await;
    assert!(
        result.is_ok(),
        "Failed to resolve LDAP URLs: {:?}",
        result.err()
    );

    let endpoints = result.unwrap();
    assert_eq!(endpoints.len(), 1);
    assert_eq!(endpoints[0].host, "server1.example.com");
    assert_eq!(endpoints[0].port, 389);
    assert_eq!(endpoints[0].base_dn, "dc=example,dc=org");
    assert!(!endpoints[0].use_tls);
}

#[tokio::test]
async fn test_referral_url_parsing_ldaps() {
    let resolver = LdapReferralResolver::new();

    let urls = vec!["ldaps://secure.example.com:636/dc=secure,dc=org".to_string()];

    let result = resolver.resolve_referral_urls(&urls).await;
    assert!(result.is_ok());

    let endpoints = result.unwrap();
    assert_eq!(endpoints.len(), 1);
    assert_eq!(endpoints[0].host, "secure.example.com");
    assert_eq!(endpoints[0].port, 636);
    assert_eq!(endpoints[0].base_dn, "dc=secure,dc=org");
    assert!(endpoints[0].use_tls);
}

#[tokio::test]
async fn test_referral_url_parsing_custom_port() {
    let resolver = LdapReferralResolver::new();

    let urls = vec!["ldap://server.example.com:1389/dc=test,dc=org".to_string()];

    let result = resolver.resolve_referral_urls(&urls).await;
    assert!(result.is_ok());

    let endpoints = result.unwrap();
    assert_eq!(endpoints[0].port, 1389);
}

#[tokio::test]
async fn test_referral_url_parsing_multiple_urls() {
    let resolver = LdapReferralResolver::new();

    let urls = vec![
        "ldap://server1.example.com/dc=example,dc=org".to_string(),
        "ldaps://server2.example.com/dc=backup,dc=org".to_string(),
        "ldap://server3.example.com:1389/dc=tertiary,dc=org".to_string(),
    ];

    let result = resolver.resolve_referral_urls(&urls).await;
    assert!(result.is_ok());

    let endpoints = result.unwrap();
    assert_eq!(endpoints.len(), 3);
}

#[tokio::test]
async fn test_referral_url_validation_invalid_scheme() {
    let resolver = LdapReferralResolver::new();

    let result = resolver.validate_referral_url("http://server.example.com/dc=test,dc=org");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("scheme"));
}

#[tokio::test]
async fn test_referral_url_validation_malformed() {
    let resolver = LdapReferralResolver::new();

    let result = resolver.validate_referral_url("not-a-valid-url");
    assert!(result.is_err());
}

#[tokio::test]
async fn test_referral_url_resolution_mixed_valid_invalid() {
    let resolver = LdapReferralResolver::new();

    let urls = vec![
        "ldap://valid1.example.com/dc=example,dc=org".to_string(),
        "invalid-url".to_string(),
        "ldap://valid2.example.com/dc=test,dc=org".to_string(),
    ];

    let result = resolver.resolve_referral_urls(&urls).await;
    // Should succeed with only valid URLs
    assert!(result.is_ok());

    let endpoints = result.unwrap();
    assert_eq!(endpoints.len(), 2); // Only 2 valid URLs
}

#[tokio::test]
async fn test_referral_url_resolution_all_invalid() {
    let resolver = LdapReferralResolver::new();

    let urls = vec!["invalid1".to_string(), "invalid2".to_string()];

    let result = resolver.resolve_referral_urls(&urls).await;
    assert!(result.is_err());
}

// ================================================================================================
// Test: FSM Integration with Real Resolver
// ================================================================================================

#[tokio::test]
async fn test_fsm_with_real_resolver_success() {
    let resolver = Box::new(LdapReferralResolver::new());
    let chain_handler = Box::new(RecordingChainHandler::new());
    let proxy_handler = Box::new(RecordingProxyHandler::new());
    let network_client = Box::new(RecordingNetworkClient);

    let mut fsm = ReferralFsmImpl::new(resolver, chain_handler, proxy_handler, network_client);

    let urls = vec!["ldap://server.example.com/dc=example,dc=org".to_string()];

    let result = fsm
        .handle_event(ReferralEvent::ReferralReceived { urls: urls.clone() })
        .await;

    assert!(result.is_ok());
    assert_eq!(fsm.current_state(), &ReferralState::EvaluatingReferral);
    assert_eq!(fsm.referral_urls(), Some(urls.as_slice()));
}

#[tokio::test]
async fn test_fsm_with_real_resolver_invalid_urls() {
    let resolver = Box::new(LdapReferralResolver::new());
    let chain_handler = Box::new(RecordingChainHandler::new());
    let proxy_handler = Box::new(RecordingProxyHandler::new());
    let network_client = Box::new(RecordingNetworkClient);

    let mut fsm = ReferralFsmImpl::new(resolver, chain_handler, proxy_handler, network_client);

    let urls = vec!["invalid-url".to_string()];

    let result = fsm
        .handle_event(ReferralEvent::ReferralReceived { urls })
        .await;

    assert!(result.is_err());
}

// ================================================================================================
// Test: Hop Limit Enforcement
// ================================================================================================

#[tokio::test]
async fn test_hop_limit_enforcement_chain_handler() {
    struct LimitedChainHandler {
        max_depth: u32,
    }

    #[async_trait]
    impl ChainHandler for LimitedChainHandler {
        async fn chain_request(
            &self,
            _target: &str,
            _request: &[u8],
            hop_count: u32,
        ) -> Result<Vec<u8>, String> {
            if hop_count >= self.max_depth {
                Err(format!(
                    "Hop limit exceeded: {} >= {}",
                    hop_count, self.max_depth
                ))
            } else {
                Ok(b"ok".to_vec())
            }
        }

        fn max_chain_depth(&self) -> u32 {
            self.max_depth
        }
    }

    let handler = LimitedChainHandler { max_depth: 2 };

    let request = b"test request";

    // Hop count 0 - should be allowed
    let result = handler
        .chain_request("server.example.com", request, 0)
        .await;
    assert!(result.is_ok());

    // Hop count 1 - should be allowed
    let result = handler
        .chain_request("server.example.com", request, 1)
        .await;
    assert!(result.is_ok());

    // Hop count 2 (at limit) - should be rejected
    let result = handler
        .chain_request("server.example.com", request, 2)
        .await;
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Hop limit exceeded"));

    // Hop count 3 (exceeds limit) - should be rejected
    let result = handler
        .chain_request("server.example.com", request, 3)
        .await;
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Hop limit exceeded"));
}

#[tokio::test]
async fn test_hop_limit_enforcement_in_fsm() {
    let config = ReferralConfig {
        max_hop_limit: 1,
        default_timeout_ms: 30000,
        max_concurrent_referrals: 5,
        enable_failover: true,
        enable_response_caching: false,
        cache_ttl_seconds: 300,
    };

    let mut fsm = create_flow_fsm(
        Some(config),
        Box::new(RecordingChainHandler::new()),
        Box::new(RecordingProxyHandler::new()),
    );
    attach_request_context(&mut fsm);

    // Start referral
    fsm.handle_event(ReferralEvent::ReferralReceived {
        urls: vec!["ldap://server.example.com/dc=example,dc=org".to_string()],
    })
    .await
    .unwrap();

    // First chain decision - should succeed
    fsm.handle_event(ReferralEvent::ChainDecision {
        target: "server.example.com".to_string(),
    })
    .await
    .unwrap();

    assert_eq!(fsm.hop_count(), 1);

    // Try to chain again - should fail due to hop limit
    let result = fsm
        .handle_event(ReferralEvent::ChainDecision {
            target: "server.example.com".to_string(),
        })
        .await;

    assert!(result.is_err());
    assert_eq!(fsm.current_state(), &ReferralState::HopLimitExceeded);
}

// ================================================================================================
// Test: Chain Request Functionality
// ================================================================================================

#[tokio::test]
async fn test_chain_request_flow() {
    let mut fsm = create_flow_fsm(
        None,
        Box::new(RecordingChainHandler::new()),
        Box::new(RecordingProxyHandler::new()),
    );
    attach_request_context(&mut fsm);

    // Receive referral
    fsm.handle_event(ReferralEvent::ReferralReceived {
        urls: vec!["ldap://server.example.com/dc=example,dc=org".to_string()],
    })
    .await
    .unwrap();

    // Make chain decision
    let result = fsm
        .handle_event(ReferralEvent::ChainDecision {
            target: "server.example.com".to_string(),
        })
        .await;

    assert!(result.is_ok());
    assert!(matches!(
        fsm.current_state(),
        ReferralState::ProcessingResponse
    ));
    assert_eq!(fsm.hop_count(), 1);
    assert_eq!(fsm.current_target(), Some("server.example.com"));
    assert_eq!(
        fsm.handle_event(ReferralEvent::ProcessingComplete)
            .await
            .unwrap(),
        Some(b"mock chained response".to_vec())
    );
}

#[tokio::test]
async fn test_chain_request_target_not_found() {
    let mut fsm = create_flow_fsm(
        None,
        Box::new(RecordingChainHandler::new()),
        Box::new(RecordingProxyHandler::new()),
    );

    // Receive referral
    fsm.handle_event(ReferralEvent::ReferralReceived {
        urls: vec!["ldap://server1.example.com/dc=example,dc=org".to_string()],
    })
    .await
    .unwrap();

    // Try to chain to a different server not in resolved endpoints
    let result = fsm
        .handle_event(ReferralEvent::ChainDecision {
            target: "server2.example.com".to_string(),
        })
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_chain_request_no_active_referral() {
    let mut fsm = create_flow_fsm(
        None,
        Box::new(RecordingChainHandler::new()),
        Box::new(RecordingProxyHandler::new()),
    );

    // Try to make chain decision without receiving referral first
    let result = fsm
        .handle_event(ReferralEvent::ChainDecision {
            target: "server.example.com".to_string(),
        })
        .await;

    assert!(result.is_err());
}

// ================================================================================================
// Test: Proxy Request Functionality
// ================================================================================================

#[tokio::test]
async fn test_proxy_request_flow() {
    let mut fsm = create_flow_fsm(
        None,
        Box::new(RecordingChainHandler::new()),
        Box::new(RecordingProxyHandler::new()),
    );
    attach_request_context(&mut fsm);

    // Receive referral
    fsm.handle_event(ReferralEvent::ReferralReceived {
        urls: vec!["ldap://server.example.com/dc=example,dc=org".to_string()],
    })
    .await
    .unwrap();

    // Make proxy decision
    let result = fsm
        .handle_event(ReferralEvent::ProxyDecision {
            target: "server.example.com".to_string(),
        })
        .await;

    assert!(result.is_ok());
    assert!(matches!(
        fsm.current_state(),
        ReferralState::ProcessingResponse
    ));
    assert_eq!(fsm.current_target(), Some("server.example.com"));
    assert_eq!(
        fsm.handle_event(ReferralEvent::ProcessingComplete)
            .await
            .unwrap(),
        Some(b"mock proxied response".to_vec())
    );
}

#[tokio::test]
async fn test_proxy_request_target_not_found() {
    let mut fsm = create_flow_fsm(
        None,
        Box::new(RecordingChainHandler::new()),
        Box::new(RecordingProxyHandler::new()),
    );

    // Receive referral
    fsm.handle_event(ReferralEvent::ReferralReceived {
        urls: vec!["ldap://server1.example.com/dc=example,dc=org".to_string()],
    })
    .await
    .unwrap();

    // Try to proxy to a different server not in resolved endpoints
    let result = fsm
        .handle_event(ReferralEvent::ProxyDecision {
            target: "server2.example.com".to_string(),
        })
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_proxy_request_no_active_referral() {
    let mut fsm = create_flow_fsm(
        None,
        Box::new(RecordingChainHandler::new()),
        Box::new(RecordingProxyHandler::new()),
    );

    // Try to make proxy decision without receiving referral first
    let result = fsm
        .handle_event(ReferralEvent::ProxyDecision {
            target: "server.example.com".to_string(),
        })
        .await;

    assert!(result.is_err());
}

// ================================================================================================
// Test: Complete Referral Workflow
// ================================================================================================

#[tokio::test]
async fn test_complete_chain_workflow() {
    let mut fsm = create_flow_fsm(
        None,
        Box::new(RecordingChainHandler::new()),
        Box::new(RecordingProxyHandler::new()),
    );
    attach_request_context(&mut fsm);

    // Step 1: Receive referral
    let result = fsm
        .handle_event(ReferralEvent::ReferralReceived {
            urls: vec!["ldap://server.example.com/dc=example,dc=org".to_string()],
        })
        .await;
    assert!(result.is_ok());

    // Step 2: Make chain decision
    let result = fsm
        .handle_event(ReferralEvent::ChainDecision {
            target: "server.example.com".to_string(),
        })
        .await;
    assert!(result.is_ok());

    assert_eq!(fsm.current_state(), &ReferralState::ProcessingResponse);

    // Step 3: Processing complete
    let result = fsm.handle_event(ReferralEvent::ProcessingComplete).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Some(b"mock chained response".to_vec()));
    assert!(matches!(
        fsm.current_state(),
        ReferralState::Completed {
            result_code: ReferralResultCode::Success
        }
    ));
}

#[tokio::test]
async fn test_complete_proxy_workflow() {
    let mut fsm = create_flow_fsm(
        None,
        Box::new(RecordingChainHandler::new()),
        Box::new(RecordingProxyHandler::new()),
    );
    attach_request_context(&mut fsm);

    // Step 1: Receive referral
    fsm.handle_event(ReferralEvent::ReferralReceived {
        urls: vec!["ldap://server.example.com/dc=example,dc=org".to_string()],
    })
    .await
    .unwrap();

    // Step 2: Make proxy decision
    fsm.handle_event(ReferralEvent::ProxyDecision {
        target: "server.example.com".to_string(),
    })
    .await
    .unwrap();

    assert_eq!(fsm.current_state(), &ReferralState::ProcessingResponse);

    // Step 3: Processing complete
    let result = fsm.handle_event(ReferralEvent::ProcessingComplete).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Some(b"mock proxied response".to_vec()));
}

// ================================================================================================
// Test: Error Handling
// ================================================================================================

#[tokio::test]
async fn test_error_handling_empty_urls() {
    let mut fsm = create_flow_fsm(
        None,
        Box::new(RecordingChainHandler::new()),
        Box::new(RecordingProxyHandler::new()),
    );

    let result = fsm
        .handle_event(ReferralEvent::ReferralReceived { urls: vec![] })
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_error_handling_generic_error() {
    let mut fsm = create_flow_fsm(
        None,
        Box::new(RecordingChainHandler::new()),
        Box::new(RecordingProxyHandler::new()),
    );

    let result = fsm
        .handle_event(ReferralEvent::Error("Test error".to_string()))
        .await;

    assert!(result.is_err());
    assert!(matches!(
        fsm.current_state(),
        ReferralState::Completed {
            result_code: ReferralResultCode::Unavailable
        }
    ));
}

#[tokio::test]
async fn test_error_handling_hop_limit_reached() {
    let mut fsm = create_flow_fsm(
        None,
        Box::new(RecordingChainHandler::new()),
        Box::new(RecordingProxyHandler::new()),
    );

    // Start referral first
    fsm.handle_event(ReferralEvent::ReferralReceived {
        urls: vec!["ldap://server.example.com/dc=example,dc=org".to_string()],
    })
    .await
    .unwrap();

    let result = fsm.handle_event(ReferralEvent::HopLimitReached).await;

    assert!(result.is_err());
    assert_eq!(fsm.current_state(), &ReferralState::HopLimitExceeded);
}

// ================================================================================================
// Test: FSM State Management
// ================================================================================================

#[tokio::test]
async fn test_fsm_reset() {
    let mut fsm = create_flow_fsm(
        None,
        Box::new(RecordingChainHandler::new()),
        Box::new(RecordingProxyHandler::new()),
    );
    attach_request_context(&mut fsm);

    // Progress through some states
    fsm.handle_event(ReferralEvent::ReferralReceived {
        urls: vec!["ldap://server.example.com/dc=example,dc=org".to_string()],
    })
    .await
    .unwrap();

    fsm.handle_event(ReferralEvent::ChainDecision {
        target: "server.example.com".to_string(),
    })
    .await
    .unwrap();

    // Reset FSM
    let result = fsm.reset().await;
    assert!(result.is_ok());

    // Verify state is reset
    assert_eq!(fsm.current_state(), &ReferralState::EvaluatingReferral);
    assert_eq!(fsm.hop_count(), 0);
    assert!(fsm.current_target().is_none());
    assert!(fsm.referral_urls().is_none());
}

#[tokio::test]
async fn test_fsm_is_terminal() {
    let mut fsm = create_flow_fsm(
        None,
        Box::new(RecordingChainHandler::new()),
        Box::new(RecordingProxyHandler::new()),
    );

    // Initial state is not terminal
    assert!(!fsm.is_terminal());

    // Error state is terminal
    fsm.handle_event(ReferralEvent::Error("test".to_string()))
        .await
        .unwrap_err();
    assert!(fsm.is_terminal());

    // Reset and test HopLimitExceeded
    fsm.reset().await.unwrap();
    assert!(!fsm.is_terminal());

    fsm.handle_event(ReferralEvent::ReferralReceived {
        urls: vec!["ldap://server.example.com/dc=example,dc=org".to_string()],
    })
    .await
    .unwrap();

    fsm.handle_event(ReferralEvent::HopLimitReached)
        .await
        .unwrap_err();
    assert!(fsm.is_terminal());
}

// ================================================================================================
// Test: Statistics and Metrics
// ================================================================================================

#[tokio::test]
async fn test_fsm_statistics_tracking() {
    let mut fsm = create_flow_fsm(
        None,
        Box::new(RecordingChainHandler::new()),
        Box::new(RecordingProxyHandler::new()),
    );
    attach_request_context(&mut fsm);

    // Initial stats
    let (total, successful, failed, avg_hops) = fsm.get_stats();
    assert_eq!(total, 0);
    assert_eq!(successful, 0);
    assert_eq!(failed, 0);
    assert_eq!(avg_hops, 0.0);

    // Complete successful referral
    fsm.handle_event(ReferralEvent::ReferralReceived {
        urls: vec!["ldap://server.example.com/dc=example,dc=org".to_string()],
    })
    .await
    .unwrap();

    fsm.handle_event(ReferralEvent::ChainDecision {
        target: "server.example.com".to_string(),
    })
    .await
    .unwrap();

    fsm.handle_event(ReferralEvent::ProcessingComplete)
        .await
        .unwrap();

    // Check stats after successful referral
    let (total, successful, failed, avg_hops) = fsm.get_stats();
    assert_eq!(total, 1);
    assert_eq!(successful, 1);
    assert_eq!(failed, 0);
    assert_eq!(avg_hops, 1.0);
}

#[tokio::test]
async fn test_fsm_statistics_failed_referral() {
    let mut fsm = create_flow_fsm(
        None,
        Box::new(RecordingChainHandler::new()),
        Box::new(RecordingProxyHandler::new()),
    );

    // Start and fail a referral
    fsm.handle_event(ReferralEvent::ReferralReceived {
        urls: vec!["ldap://server.example.com/dc=example,dc=org".to_string()],
    })
    .await
    .unwrap();

    fsm.handle_event(ReferralEvent::HopLimitReached)
        .await
        .unwrap_err();

    // Check stats
    let (total, successful, failed, _) = fsm.get_stats();
    assert_eq!(total, 1);
    assert_eq!(successful, 0);
    assert_eq!(failed, 1);
}

#[tokio::test]
async fn test_chain_failover_tries_second_endpoint() {
    let chain_handler = RecordingChainHandler::new().with_failed_target("server1.example.com");
    let chain_log = chain_handler.log_handle();
    let mut fsm = create_flow_fsm(
        None,
        Box::new(chain_handler),
        Box::new(RecordingProxyHandler::new()),
    );
    attach_request_context(&mut fsm);

    fsm.handle_event(ReferralEvent::ReferralReceived {
        urls: vec![
            "ldap://server1.example.com/dc=example,dc=org".to_string(),
            "ldap://server2.example.com/dc=example,dc=org".to_string(),
        ],
    })
    .await
    .unwrap();

    fsm.handle_event(ReferralEvent::ChainDecision {
        target: "server1.example.com".to_string(),
    })
    .await
    .unwrap();

    let log = chain_log.lock().unwrap().clone();
    assert_eq!(log.len(), 2);
    assert!(log[0].contains("target=server1.example.com"));
    assert!(log[0].contains("request_len=19"));
    assert!(log[1].contains("target=server2.example.com"));
    assert_eq!(fsm.current_target(), Some("server2.example.com"));
}

#[tokio::test]
async fn test_metrics_distinguish_chain_and_proxy_execution() {
    let resolver = Box::new(LdapReferralResolver::new());
    let chain_handler = Box::new(RecordingChainHandler::new());
    let proxy_handler = Box::new(RecordingProxyHandler::new());
    let network_client = Box::new(RecordingNetworkClient);
    let metrics = RecordingMetrics::new();
    let metric_log = metrics.log_handle();

    let mut fsm = ReferralFsmImpl::new(resolver, chain_handler, proxy_handler, network_client)
        .with_metrics(Box::new(metrics));
    attach_request_context(&mut fsm);

    fsm.handle_event(ReferralEvent::ReferralReceived {
        urls: vec!["ldap://server.example.com/dc=example,dc=org".to_string()],
    })
    .await
    .unwrap();

    fsm.handle_event(ReferralEvent::ProxyDecision {
        target: "server.example.com".to_string(),
    })
    .await
    .unwrap();
    fsm.handle_event(ReferralEvent::ProcessingComplete)
        .await
        .unwrap();

    let log = metric_log.lock().unwrap().clone();
    assert!(
        log.iter()
            .any(|entry| entry.contains("record_proxy_request: target=server.example.com"))
    );
    assert!(
        !log.iter()
            .any(|entry| entry.contains("record_chain_request: target=server.example.com"))
    );
    assert!(
        log.iter()
            .any(|entry| entry.contains("record_response_received: target=server.example.com"))
    );
}

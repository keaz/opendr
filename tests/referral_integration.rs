//! Integration tests for LDAP referral and chaining functionality
//!
//! These tests verify the complete referral workflow including:
//! - Referral URL parsing and validation
//! - Endpoint resolution
//! - Hop limit enforcement
//! - Chain request handling
//! - Proxy request handling
//! - Error handling and recovery

use opendr::fsm::{ReferralEvent, ReferralFsm, ReferralResultCode, ReferralState, StateMachine};
use opendr::referral::{
    LdapChainHandler, LdapNetworkClient, LdapProxyHandler, LdapReferralResolver,
};
use opendr::referral_fsm::{
    ChainHandler, NetworkClient, ProxyHandler, ReferralConfig, ReferralFsmImpl,
    ReferralResolver, ResolvedEndpoint,
};

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
    let chain_handler = Box::new(LdapChainHandler::new());
    let proxy_handler = Box::new(LdapProxyHandler::new());
    let network_client = Box::new(LdapNetworkClient::new());

    let mut fsm = ReferralFsmImpl::new(resolver, chain_handler, proxy_handler, network_client);

    let urls = vec!["ldap://server.example.com/dc=example,dc=org".to_string()];

    let result = fsm
        .handle_event(ReferralEvent::ReferralReceived { urls: urls.clone() })
        .await;

    assert!(result.is_ok());
    assert_eq!(
        fsm.current_state(),
        &ReferralState::EvaluatingReferral
    );
    assert_eq!(fsm.referral_urls(), Some(urls.as_slice()));
}

#[tokio::test]
async fn test_fsm_with_real_resolver_invalid_urls() {
    let resolver = Box::new(LdapReferralResolver::new());
    let chain_handler = Box::new(LdapChainHandler::new());
    let proxy_handler = Box::new(LdapProxyHandler::new());
    let network_client = Box::new(LdapNetworkClient::new());

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
    let handler = LdapChainHandler::with_config(2, 30000);

    let request = b"test request";

    // Hop count 0 - should be allowed (but fail due to network layer)
    let result = handler
        .chain_request("server.example.com", request, 0)
        .await;
    assert!(result.is_err());
    assert!(!result.unwrap_err().contains("Hop limit"));

    // Hop count 1 - should be allowed
    let result = handler
        .chain_request("server.example.com", request, 1)
        .await;
    assert!(result.is_err());
    assert!(!result.unwrap_err().contains("Hop limit"));

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

    let resolver = Box::new(LdapReferralResolver::new());
    let chain_handler = Box::new(LdapChainHandler::new());
    let proxy_handler = Box::new(LdapProxyHandler::new());
    let network_client = Box::new(LdapNetworkClient::new());

    let mut fsm =
        ReferralFsmImpl::with_config(resolver, chain_handler, proxy_handler, network_client, config);

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
    assert_eq!(
        fsm.current_state(),
        &ReferralState::HopLimitExceeded
    );
}

// ================================================================================================
// Test: Chain Request Functionality
// ================================================================================================

#[tokio::test]
async fn test_chain_request_flow() {
    let resolver = Box::new(LdapReferralResolver::new());
    let chain_handler = Box::new(LdapChainHandler::new());
    let proxy_handler = Box::new(LdapProxyHandler::new());
    let network_client = Box::new(LdapNetworkClient::new());

    let mut fsm = ReferralFsmImpl::new(resolver, chain_handler, proxy_handler, network_client);

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
        ReferralState::ChainRequest { .. }
    ));
    assert_eq!(fsm.hop_count(), 1);
    assert_eq!(fsm.current_target(), Some("server.example.com"));
}

#[tokio::test]
async fn test_chain_request_target_not_found() {
    let resolver = Box::new(LdapReferralResolver::new());
    let chain_handler = Box::new(LdapChainHandler::new());
    let proxy_handler = Box::new(LdapProxyHandler::new());
    let network_client = Box::new(LdapNetworkClient::new());

    let mut fsm = ReferralFsmImpl::new(resolver, chain_handler, proxy_handler, network_client);

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
    let resolver = Box::new(LdapReferralResolver::new());
    let chain_handler = Box::new(LdapChainHandler::new());
    let proxy_handler = Box::new(LdapProxyHandler::new());
    let network_client = Box::new(LdapNetworkClient::new());

    let mut fsm = ReferralFsmImpl::new(resolver, chain_handler, proxy_handler, network_client);

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
    let resolver = Box::new(LdapReferralResolver::new());
    let chain_handler = Box::new(LdapChainHandler::new());
    let proxy_handler = Box::new(LdapProxyHandler::new());
    let network_client = Box::new(LdapNetworkClient::new());

    let mut fsm = ReferralFsmImpl::new(resolver, chain_handler, proxy_handler, network_client);

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
        ReferralState::ProxyRequest { .. }
    ));
    assert_eq!(fsm.current_target(), Some("server.example.com"));
}

#[tokio::test]
async fn test_proxy_request_target_not_found() {
    let resolver = Box::new(LdapReferralResolver::new());
    let chain_handler = Box::new(LdapChainHandler::new());
    let proxy_handler = Box::new(LdapProxyHandler::new());
    let network_client = Box::new(LdapNetworkClient::new());

    let mut fsm = ReferralFsmImpl::new(resolver, chain_handler, proxy_handler, network_client);

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
    let resolver = Box::new(LdapReferralResolver::new());
    let chain_handler = Box::new(LdapChainHandler::new());
    let proxy_handler = Box::new(LdapProxyHandler::new());
    let network_client = Box::new(LdapNetworkClient::new());

    let mut fsm = ReferralFsmImpl::new(resolver, chain_handler, proxy_handler, network_client);

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
    let resolver = Box::new(LdapReferralResolver::new());
    let chain_handler = Box::new(LdapChainHandler::new());
    let proxy_handler = Box::new(LdapProxyHandler::new());
    let network_client = Box::new(LdapNetworkClient::new());

    let mut fsm = ReferralFsmImpl::new(resolver, chain_handler, proxy_handler, network_client);

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

    // Step 3: Request sent
    let result = fsm.handle_event(ReferralEvent::RequestSent).await;
    assert!(result.is_ok());
    assert_eq!(
        fsm.current_state(),
        &ReferralState::AwaitingResponse
    );

    // Step 4: Response received
    let response_data = b"test response data".to_vec();
    let result = fsm
        .handle_event(ReferralEvent::ResponseReceived(response_data.clone()))
        .await;
    assert!(result.is_ok());
    assert_eq!(
        fsm.current_state(),
        &ReferralState::ProcessingResponse
    );

    // Step 5: Processing complete
    let result = fsm
        .handle_event(ReferralEvent::ProcessingComplete)
        .await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Some(response_data));
    assert!(matches!(
        fsm.current_state(),
        ReferralState::Completed {
            result_code: ReferralResultCode::Success
        }
    ));
}

#[tokio::test]
async fn test_complete_proxy_workflow() {
    let resolver = Box::new(LdapReferralResolver::new());
    let chain_handler = Box::new(LdapChainHandler::new());
    let proxy_handler = Box::new(LdapProxyHandler::new());
    let network_client = Box::new(LdapNetworkClient::new());

    let mut fsm = ReferralFsmImpl::new(resolver, chain_handler, proxy_handler, network_client);

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

    // Step 3: Request sent
    fsm.handle_event(ReferralEvent::RequestSent)
        .await
        .unwrap();

    // Step 4: Response received
    let response_data = b"proxy response".to_vec();
    fsm.handle_event(ReferralEvent::ResponseReceived(response_data.clone()))
        .await
        .unwrap();

    // Step 5: Processing complete
    let result = fsm
        .handle_event(ReferralEvent::ProcessingComplete)
        .await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Some(response_data));
}

// ================================================================================================
// Test: Error Handling
// ================================================================================================

#[tokio::test]
async fn test_error_handling_empty_urls() {
    let resolver = Box::new(LdapReferralResolver::new());
    let chain_handler = Box::new(LdapChainHandler::new());
    let proxy_handler = Box::new(LdapProxyHandler::new());
    let network_client = Box::new(LdapNetworkClient::new());

    let mut fsm = ReferralFsmImpl::new(resolver, chain_handler, proxy_handler, network_client);

    let result = fsm
        .handle_event(ReferralEvent::ReferralReceived { urls: vec![] })
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_error_handling_generic_error() {
    let resolver = Box::new(LdapReferralResolver::new());
    let chain_handler = Box::new(LdapChainHandler::new());
    let proxy_handler = Box::new(LdapProxyHandler::new());
    let network_client = Box::new(LdapNetworkClient::new());

    let mut fsm = ReferralFsmImpl::new(resolver, chain_handler, proxy_handler, network_client);

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
    let resolver = Box::new(LdapReferralResolver::new());
    let chain_handler = Box::new(LdapChainHandler::new());
    let proxy_handler = Box::new(LdapProxyHandler::new());
    let network_client = Box::new(LdapNetworkClient::new());

    let mut fsm = ReferralFsmImpl::new(resolver, chain_handler, proxy_handler, network_client);

    // Start referral first
    fsm.handle_event(ReferralEvent::ReferralReceived {
        urls: vec!["ldap://server.example.com/dc=example,dc=org".to_string()],
    })
    .await
    .unwrap();

    let result = fsm
        .handle_event(ReferralEvent::HopLimitReached)
        .await;

    assert!(result.is_err());
    assert_eq!(
        fsm.current_state(),
        &ReferralState::HopLimitExceeded
    );
}

// ================================================================================================
// Test: FSM State Management
// ================================================================================================

#[tokio::test]
async fn test_fsm_reset() {
    let resolver = Box::new(LdapReferralResolver::new());
    let chain_handler = Box::new(LdapChainHandler::new());
    let proxy_handler = Box::new(LdapProxyHandler::new());
    let network_client = Box::new(LdapNetworkClient::new());

    let mut fsm = ReferralFsmImpl::new(resolver, chain_handler, proxy_handler, network_client);

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
    assert_eq!(
        fsm.current_state(),
        &ReferralState::EvaluatingReferral
    );
    assert_eq!(fsm.hop_count(), 0);
    assert!(fsm.current_target().is_none());
    assert!(fsm.referral_urls().is_none());
}

#[tokio::test]
async fn test_fsm_is_terminal() {
    let resolver = Box::new(LdapReferralResolver::new());
    let chain_handler = Box::new(LdapChainHandler::new());
    let proxy_handler = Box::new(LdapProxyHandler::new());
    let network_client = Box::new(LdapNetworkClient::new());

    let mut fsm = ReferralFsmImpl::new(resolver, chain_handler, proxy_handler, network_client);

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
    let resolver = Box::new(LdapReferralResolver::new());
    let chain_handler = Box::new(LdapChainHandler::new());
    let proxy_handler = Box::new(LdapProxyHandler::new());
    let network_client = Box::new(LdapNetworkClient::new());

    let mut fsm = ReferralFsmImpl::new(resolver, chain_handler, proxy_handler, network_client);

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

    fsm.handle_event(ReferralEvent::RequestSent)
        .await
        .unwrap();
    fsm.handle_event(ReferralEvent::ResponseReceived(b"response".to_vec()))
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
    let resolver = Box::new(LdapReferralResolver::new());
    let chain_handler = Box::new(LdapChainHandler::new());
    let proxy_handler = Box::new(LdapProxyHandler::new());
    let network_client = Box::new(LdapNetworkClient::new());

    let mut fsm = ReferralFsmImpl::new(resolver, chain_handler, proxy_handler, network_client);

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

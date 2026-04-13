//! Concrete helpers for LDAP referral and chaining functionality.
//!
//! The shipped runtime uses this module today for RFC 4516 referral URL parsing
//! and validation. Server-side chaining and proxying remain helper-level building
//! blocks and are not yet enabled in the active network runtime.

use crate::referral_fsm::{
    ChainHandler, NetworkClient, ProxyHandler, ReferralResolver, ResolvedEndpoint,
};
use async_trait::async_trait;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use url::Url;

/// Referral URL parser and resolver used by the active runtime.
pub struct LdapReferralResolver {
    /// Default port for non-TLS connections
    default_port: u16,
    /// Default port for TLS connections
    default_tls_port: u16,
}

impl LdapReferralResolver {
    /// Create a new LDAP referral resolver
    pub fn new() -> Self {
        Self {
            default_port: 389,
            default_tls_port: 636,
        }
    }

    /// Create resolver with custom default ports
    pub fn with_ports(default_port: u16, default_tls_port: u16) -> Self {
        Self {
            default_port,
            default_tls_port,
        }
    }

    /// Parse an LDAP URL into its components
    ///
    /// Supports ldap:// and ldaps:// schemes
    fn parse_ldap_url(&self, url_str: &str) -> Result<ResolvedEndpoint, String> {
        let url = Url::parse(url_str).map_err(|e| format!("Invalid URL: {}", e))?;

        let scheme = url.scheme();
        if scheme != "ldap" && scheme != "ldaps" {
            return Err(format!(
                "Invalid scheme '{}', expected 'ldap' or 'ldaps'",
                scheme
            ));
        }

        let use_tls = scheme == "ldaps";
        let host = url.host_str().ok_or("Missing host in URL")?.to_string();

        let port = url.port().unwrap_or(if use_tls {
            self.default_tls_port
        } else {
            self.default_port
        });

        // Extract base DN from path (remove leading slash)
        let base_dn = url.path().trim_start_matches('/').to_string();

        Ok(ResolvedEndpoint::new(host, port, base_dn).with_tls(use_tls))
    }
}

impl Default for LdapReferralResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ReferralResolver for LdapReferralResolver {
    async fn resolve_referral_urls(
        &self,
        urls: &[String],
    ) -> Result<Vec<ResolvedEndpoint>, String> {
        let mut endpoints = Vec::new();

        for url in urls {
            match self.parse_ldap_url(url) {
                Ok(endpoint) => endpoints.push(endpoint),
                Err(e) => {
                    // Log error but continue with other URLs
                    eprintln!("Failed to parse referral URL '{}': {}", url, e);
                }
            }
        }

        if endpoints.is_empty() {
            return Err("No valid endpoints could be resolved".to_string());
        }

        Ok(endpoints)
    }

    fn validate_referral_url(&self, url: &str) -> Result<(), String> {
        self.parse_ldap_url(url).map(|_| ())
    }
}

/// Helper implementation of ChainHandler.
///
/// Hop-count enforcement is implemented here, but actual network-layer chaining
/// is still not wired into the active runtime.
pub struct LdapChainHandler {
    /// Maximum hop depth allowed
    max_depth: u32,
    /// Connection timeout in milliseconds
    _timeout_ms: u64,
}

impl LdapChainHandler {
    /// Create a new chain handler
    pub fn new() -> Self {
        Self {
            max_depth: 10,
            _timeout_ms: 30000,
        }
    }

    /// Create chain handler with custom configuration
    pub fn with_config(max_depth: u32, timeout_ms: u64) -> Self {
        Self {
            max_depth,
            _timeout_ms: timeout_ms,
        }
    }

    /// Add hop count header to LDAP request
    ///
    /// This modifies the request to include hop count information
    /// to prevent infinite referral loops
    fn add_hop_count_to_request(&self, request: &[u8], _hop_count: u32) -> Vec<u8> {
        // In a real implementation, this would modify the LDAP message
        // to include a control indicating the hop count.
        // For now, we just pass through the request as-is.
        //
        // To properly implement this, we would:
        // 1. Parse the LDAP message
        // 2. Add a ManageDsaIT control or similar
        // 3. Re-encode the message
        request.to_vec()
    }
}

impl Default for LdapChainHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ChainHandler for LdapChainHandler {
    async fn chain_request(
        &self,
        target: &str,
        request: &[u8],
        hop_count: u32,
    ) -> Result<Vec<u8>, String> {
        if hop_count >= self.max_depth {
            return Err(format!(
                "Hop limit exceeded: {} >= {}",
                hop_count, self.max_depth
            ));
        }

        // Add hop count to request
        let _modified_request = self.add_hop_count_to_request(request, hop_count);

        // Forward request to target DSA once chaining is enabled in the runtime.
        Err(format!(
            "Chaining to '{}' with hop count {} is not enabled in the active runtime",
            target, hop_count
        ))
    }

    fn max_chain_depth(&self) -> u32 {
        self.max_depth
    }
}

/// Helper implementation of ProxyHandler.
///
/// Transparent request proxying is not yet enabled in the active runtime.
pub struct LdapProxyHandler {
    /// Connection timeout in milliseconds
    timeout_ms: u64,
    /// Enable connection pooling
    enable_pooling: bool,
}

impl LdapProxyHandler {
    /// Create a new proxy handler
    pub fn new() -> Self {
        Self {
            timeout_ms: 30000,
            enable_pooling: false,
        }
    }

    /// Create proxy handler with custom timeout
    pub fn with_timeout(timeout_ms: u64) -> Self {
        Self {
            timeout_ms,
            enable_pooling: false,
        }
    }

    /// Create proxy handler with connection pooling enabled
    pub fn with_pooling(mut self) -> Self {
        self.enable_pooling = true;
        self
    }
}

impl Default for LdapProxyHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProxyHandler for LdapProxyHandler {
    async fn proxy_request(&self, target: &str, _request: &[u8]) -> Result<Vec<u8>, String> {
        Err(format!(
            "Proxying to '{}' is not enabled in the active runtime",
            target
        ))
    }

    fn proxy_timeout_ms(&self) -> u64 {
        self.timeout_ms
    }
}

/// Production implementation of NetworkClient
///
/// Handles low-level LDAP network communication
pub struct LdapNetworkClient {
    /// Default connection timeout
    timeout_ms: u64,
    /// Enable TCP keepalive
    enable_keepalive: bool,
}

impl LdapNetworkClient {
    /// Create a new network client
    pub fn new() -> Self {
        Self {
            timeout_ms: 30000,
            enable_keepalive: true,
        }
    }

    /// Create client with custom timeout
    pub fn with_timeout(timeout_ms: u64) -> Self {
        Self {
            timeout_ms,
            enable_keepalive: true,
        }
    }

    /// Create client without TCP keepalive
    pub fn without_keepalive(mut self) -> Self {
        self.enable_keepalive = false;
        self
    }

    /// Establish TCP connection to endpoint
    async fn connect(&self, endpoint: &ResolvedEndpoint) -> Result<TcpStream, String> {
        let addr = format!("{}:{}", endpoint.host, endpoint.port);
        let duration = Duration::from_millis(self.timeout_ms);

        let stream = timeout(duration, TcpStream::connect(&addr))
            .await
            .map_err(|_| format!("Connection timeout to {}", addr))?
            .map_err(|e| format!("Connection failed to {}: {}", addr, e))?;

        if self.enable_keepalive {
            let socket = socket2::Socket::from(stream.into_std().map_err(|e| e.to_string())?);
            socket
                .set_keepalive(true)
                .map_err(|e| format!("Failed to set keepalive: {}", e))?;
            let stream = TcpStream::from_std(socket.into())
                .map_err(|e| format!("Failed to convert socket: {}", e))?;
            Ok(stream)
        } else {
            Ok(stream)
        }
    }
}

impl Default for LdapNetworkClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NetworkClient for LdapNetworkClient {
    async fn send_request(
        &self,
        endpoint: &ResolvedEndpoint,
        request: &[u8],
        timeout_ms: u64,
    ) -> Result<Vec<u8>, String> {
        // Connect to endpoint
        let mut stream = self.connect(endpoint).await?;

        let duration = Duration::from_millis(timeout_ms);

        // Send request with timeout
        timeout(duration, stream.write_all(request))
            .await
            .map_err(|_| "Write timeout".to_string())?
            .map_err(|e| format!("Write failed: {}", e))?;

        // Flush to ensure data is sent
        timeout(duration, stream.flush())
            .await
            .map_err(|_| "Flush timeout".to_string())?
            .map_err(|e| format!("Flush failed: {}", e))?;

        // Read response with timeout
        let mut response = Vec::new();
        timeout(duration, stream.read_to_end(&mut response))
            .await
            .map_err(|_| "Read timeout".to_string())?
            .map_err(|e| format!("Read failed: {}", e))?;

        Ok(response)
    }

    async fn check_connectivity(&self, endpoint: &ResolvedEndpoint) -> Result<(), String> {
        // Try to establish connection
        let _stream = self.connect(endpoint).await?;
        Ok(())
    }
}

/// Configuration for referral behavior
#[derive(Debug, Clone)]
pub struct ReferralConfig {
    /// Enable referral following
    pub enable_referrals: bool,
    /// Enable server-side chaining
    pub enable_chaining: bool,
    /// Maximum hop count
    pub max_hops: u32,
    /// Connection timeout in milliseconds
    pub timeout_ms: u64,
}

impl Default for ReferralConfig {
    fn default() -> Self {
        Self {
            enable_referrals: true,
            enable_chaining: false,
            max_hops: 10,
            timeout_ms: 30000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ldap_referral_resolver_parse_ldap_url() {
        let resolver = LdapReferralResolver::new();

        // Test standard ldap:// URL
        let result = resolver.parse_ldap_url("ldap://server.example.com:389/dc=example,dc=org");
        assert!(result.is_ok());
        let endpoint = result.unwrap();
        assert_eq!(endpoint.host, "server.example.com");
        assert_eq!(endpoint.port, 389);
        assert_eq!(endpoint.base_dn, "dc=example,dc=org");
        assert!(!endpoint.use_tls);

        // Test ldaps:// URL
        let result = resolver.parse_ldap_url("ldaps://server.example.com/dc=example,dc=org");
        assert!(result.is_ok());
        let endpoint = result.unwrap();
        assert_eq!(endpoint.host, "server.example.com");
        assert_eq!(endpoint.port, 636); // Default LDAPS port
        assert!(endpoint.use_tls);

        // Test URL with custom port
        let result = resolver.parse_ldap_url("ldap://server.example.com:1389/dc=test,dc=org");
        assert!(result.is_ok());
        let endpoint = result.unwrap();
        assert_eq!(endpoint.port, 1389);

        // Test invalid scheme
        let result = resolver.parse_ldap_url("http://server.example.com/dc=test,dc=org");
        assert!(result.is_err());

        // Test invalid URL
        let result = resolver.parse_ldap_url("not-a-url");
        assert!(result.is_err());
    }

    #[test]
    fn test_ldap_referral_resolver_validate() {
        let resolver = LdapReferralResolver::new();

        assert!(
            resolver
                .validate_referral_url("ldap://server.example.com/dc=example,dc=org")
                .is_ok()
        );
        assert!(
            resolver
                .validate_referral_url("ldaps://server.example.com/dc=example,dc=org")
                .is_ok()
        );
        assert!(resolver.validate_referral_url("invalid-url").is_err());
    }

    #[tokio::test]
    async fn test_ldap_referral_resolver_resolve_urls() {
        let resolver = LdapReferralResolver::new();

        let urls = vec![
            "ldap://server1.example.com/dc=example,dc=org".to_string(),
            "ldaps://server2.example.com:1636/dc=test,dc=org".to_string(),
        ];

        let result = resolver.resolve_referral_urls(&urls).await;
        assert!(result.is_ok());
        let endpoints = result.unwrap();
        assert_eq!(endpoints.len(), 2);

        assert_eq!(endpoints[0].host, "server1.example.com");
        assert_eq!(endpoints[0].port, 389);
        assert!(!endpoints[0].use_tls);

        assert_eq!(endpoints[1].host, "server2.example.com");
        assert_eq!(endpoints[1].port, 1636);
        assert!(endpoints[1].use_tls);
    }

    #[tokio::test]
    async fn test_ldap_referral_resolver_resolve_mixed_urls() {
        let resolver = LdapReferralResolver::new();

        // Mix of valid and invalid URLs
        let urls = vec![
            "ldap://server1.example.com/dc=example,dc=org".to_string(),
            "invalid-url".to_string(),
            "ldaps://server2.example.com/dc=test,dc=org".to_string(),
        ];

        let result = resolver.resolve_referral_urls(&urls).await;
        // Should succeed with valid URLs only
        assert!(result.is_ok());
        let endpoints = result.unwrap();
        assert_eq!(endpoints.len(), 2); // Only 2 valid URLs
    }

    #[tokio::test]
    async fn test_ldap_referral_resolver_all_invalid() {
        let resolver = LdapReferralResolver::new();

        let urls = vec!["invalid-url-1".to_string(), "invalid-url-2".to_string()];

        let result = resolver.resolve_referral_urls(&urls).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_ldap_chain_handler_new() {
        let handler = LdapChainHandler::new();
        assert_eq!(handler.max_chain_depth(), 10);
        assert_eq!(handler._timeout_ms, 30000);
    }

    #[test]
    fn test_ldap_chain_handler_custom_config() {
        let handler = LdapChainHandler::with_config(5, 15000);
        assert_eq!(handler.max_chain_depth(), 5);
        assert_eq!(handler._timeout_ms, 15000);
    }

    #[tokio::test]
    async fn test_ldap_chain_handler_hop_limit() {
        let handler = LdapChainHandler::with_config(2, 30000);

        let request = b"test request";

        // First hop should be allowed
        let result = handler
            .chain_request("server1.example.com", request, 0)
            .await;
        assert!(result.is_err()); // Will fail due to network layer not implemented, but not due to hop limit

        let result = handler
            .chain_request("server1.example.com", request, 1)
            .await;
        assert!(result.is_err());

        // Hop at limit should fail
        let result = handler
            .chain_request("server1.example.com", request, 2)
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Hop limit exceeded"));
    }

    #[test]
    fn test_ldap_proxy_handler_new() {
        let handler = LdapProxyHandler::new();
        assert_eq!(handler.proxy_timeout_ms(), 30000);
        assert!(!handler.enable_pooling);
    }

    #[test]
    fn test_ldap_proxy_handler_with_timeout() {
        let handler = LdapProxyHandler::with_timeout(15000);
        assert_eq!(handler.proxy_timeout_ms(), 15000);
    }

    #[test]
    fn test_ldap_proxy_handler_with_pooling() {
        let handler = LdapProxyHandler::new().with_pooling();
        assert!(handler.enable_pooling);
    }

    #[test]
    fn test_ldap_network_client_new() {
        let client = LdapNetworkClient::new();
        assert_eq!(client.timeout_ms, 30000);
        assert!(client.enable_keepalive);
    }

    #[test]
    fn test_ldap_network_client_with_timeout() {
        let client = LdapNetworkClient::with_timeout(15000);
        assert_eq!(client.timeout_ms, 15000);
    }

    #[test]
    fn test_ldap_network_client_without_keepalive() {
        let client = LdapNetworkClient::new().without_keepalive();
        assert!(!client.enable_keepalive);
    }

    #[test]
    fn test_referral_config_default() {
        let config = ReferralConfig::default();
        assert!(config.enable_referrals);
        assert!(!config.enable_chaining);
        assert_eq!(config.max_hops, 10);
        assert_eq!(config.timeout_ms, 30000);
    }
}

//! TLS/StartTLS Implementation for LDAP
//!
//! This module provides TLS support for LDAP connections using rustls,
//! implementing the TlsHandler trait defined in connection_fsm.

use crate::connection_fsm::{ConnectionTransport, TlsHandler};
use async_trait::async_trait;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, SupportedProtocolVersion, version};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, server::TlsStream};

/// TLS configuration for LDAP server
#[derive(Clone)]
pub struct TlsConfig {
    /// Path to server certificate file (PEM format)
    pub cert_path: String,
    /// Path to server private key file (PKCS8 PEM format)
    pub key_path: String,
    /// Path to CA bundle for client certificate verification
    pub ca_file: Option<String>,
    /// Minimum TLS version (defaults to TLS 1.2)
    pub min_tls_version: TlsVersion,
    /// Maximum TLS version (defaults to TLS 1.3)
    pub max_tls_version: TlsVersion,
    /// Whether to require client certificates
    pub require_client_cert: bool,
}

/// TLS protocol versions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    Tls12,
    Tls13,
}

impl TlsVersion {
    pub fn as_str(&self) -> &'static str {
        match self {
            TlsVersion::Tls12 => "TLSv1.2",
            TlsVersion::Tls13 => "TLSv1.3",
        }
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            cert_path: "server.crt".to_string(),
            key_path: "server.key".to_string(),
            ca_file: None,
            min_tls_version: TlsVersion::Tls12,
            max_tls_version: TlsVersion::Tls13,
            require_client_cert: false,
        }
    }
}

/// Rustls-based TLS handler implementation
pub struct RustlsTlsHandler {
    /// Server configuration
    server_config: Arc<ServerConfig>,
    /// Highest configured protocol version
    protocol_version: String,
}

impl RustlsTlsHandler {
    /// Create a new TLS handler with the given configuration
    ///
    /// # Arguments
    /// * `tls_config` - TLS configuration
    ///
    /// # Returns
    /// * `Ok(RustlsTlsHandler)` if configuration is valid
    /// * `Err(String)` if configuration fails
    pub fn new(tls_config: &TlsConfig) -> Result<Self, String> {
        let server_config = Self::build_server_config(tls_config)?;
        let protocol_version = tls_config.min_tls_version.as_str().to_string();

        Ok(Self {
            server_config: Arc::new(server_config),
            protocol_version,
        })
    }

    /// Build rustls ServerConfig from TlsConfig
    fn build_server_config(tls_config: &TlsConfig) -> Result<ServerConfig, String> {
        let versions = Self::protocol_versions(tls_config)?;

        // Load certificates
        let cert_file = File::open(&tls_config.cert_path).map_err(|e| {
            format!(
                "Failed to open certificate file {}: {}",
                tls_config.cert_path, e
            )
        })?;
        let mut cert_reader = BufReader::new(cert_file);
        let certs = certs(&mut cert_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Failed to parse certificates: {}", e))?;

        if certs.is_empty() {
            return Err("No certificates found in certificate file".to_string());
        }

        // Load private key
        let key_file = File::open(&tls_config.key_path).map_err(|e| {
            format!(
                "Failed to open private key file {}: {}",
                tls_config.key_path, e
            )
        })?;
        let mut key_reader = BufReader::new(key_file);
        let mut keys = pkcs8_private_keys(&mut key_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Failed to parse private key: {}", e))?;

        if keys.is_empty() {
            return Err("No private keys found in key file".to_string());
        }

        let key = keys.remove(0);

        let builder = ServerConfig::builder_with_protocol_versions(&versions)
            .with_client_cert_verifier(Self::client_cert_verifier(tls_config)?);

        let config = builder
            .with_single_cert(certs, key.into())
            .map_err(|e| format!("Failed to build TLS config: {}", e))?;

        Ok(config)
    }

    fn protocol_versions(
        tls_config: &TlsConfig,
    ) -> Result<Vec<&'static SupportedProtocolVersion>, String> {
        match (tls_config.min_tls_version, tls_config.max_tls_version) {
            (TlsVersion::Tls12, TlsVersion::Tls12) => Ok(vec![&version::TLS12]),
            (TlsVersion::Tls12, TlsVersion::Tls13) => Ok(vec![&version::TLS13, &version::TLS12]),
            (TlsVersion::Tls13, TlsVersion::Tls13) => Ok(vec![&version::TLS13]),
            (TlsVersion::Tls13, TlsVersion::Tls12) => {
                Err("max_tls_version cannot be lower than min_tls_version".to_string())
            }
        }
    }

    fn client_cert_verifier(
        tls_config: &TlsConfig,
    ) -> Result<Arc<dyn rustls::server::danger::ClientCertVerifier>, String> {
        if !tls_config.require_client_cert {
            return Ok(WebPkiClientVerifier::no_client_auth());
        }

        let ca_file = tls_config
            .ca_file
            .as_deref()
            .ok_or("Client certificate verification requires a CA file")?;

        let file = File::open(ca_file)
            .map_err(|e| format!("Failed to open CA file {}: {}", ca_file, e))?;
        let mut reader = BufReader::new(file);
        let parsed = certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Failed to parse CA certificates: {}", e))?;

        if parsed.is_empty() {
            return Err("No CA certificates found in CA file".to_string());
        }

        let mut roots = RootCertStore::empty();
        for cert in parsed {
            roots
                .add(cert)
                .map_err(|e| format!("Failed to add CA certificate: {}", e))?;
        }

        WebPkiClientVerifier::builder(roots.into())
            .build()
            .map_err(|e| format!("Failed to build client certificate verifier: {}", e))
    }

    pub async fn accept(&self, stream: TcpStream) -> Result<TlsStream<TcpStream>, String> {
        TlsAcceptor::from(self.server_config.clone())
            .accept(stream)
            .await
            .map_err(|e| format!("TLS handshake failed: {}", e))
    }

    pub async fn accept_transport(&self, stream: TcpStream) -> Result<ConnectionTransport, String> {
        self.accept(stream).await.map(ConnectionTransport::tls)
    }

    /// Create a test TLS handler for testing
    ///
    /// Note: This creates a minimal handler for testing the interface.
    /// Real TLS operations require valid certificates.
    pub fn new_test() -> Result<Self, String> {
        // For testing, we create a handler that reports TLS support
        // but doesn't require actual certificates
        Ok(Self {
            server_config: Arc::new(
                ServerConfig::builder()
                    .with_no_client_auth()
                    .with_cert_resolver(Arc::new(TestCertResolver)),
            ),
            protocol_version: "TLSv1.3".to_string(),
        })
    }
}

#[derive(Debug)]
pub struct TestCertResolver;

impl rustls::server::ResolvesServerCert for TestCertResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        None // Test resolver that doesn't provide certificates
    }
}

#[async_trait]
impl TlsHandler for RustlsTlsHandler {
    async fn perform_handshake(&self, _stream: &mut TcpStream) -> Result<(), String> {
        Err(
            "RustlsTlsHandler::perform_handshake cannot perform a real TLS upgrade without consuming the stream; use RustlsTlsHandler::accept in the runtime path"
                .to_string(),
        )
    }

    async fn upgrade_transport(&self, stream: TcpStream) -> Result<ConnectionTransport, String> {
        self.accept_transport(stream).await
    }

    fn supports_tls(&self) -> bool {
        true
    }

    fn protocol_version(&self) -> String {
        self.protocol_version.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_config_default() {
        let config = TlsConfig::default();
        assert_eq!(config.cert_path, "server.crt");
        assert_eq!(config.key_path, "server.key");
        assert_eq!(config.ca_file, None);
        assert_eq!(config.min_tls_version, TlsVersion::Tls12);
        assert_eq!(config.max_tls_version, TlsVersion::Tls13);
        assert!(!config.require_client_cert);
    }

    #[test]
    fn test_tls_version_as_str() {
        assert_eq!(TlsVersion::Tls12.as_str(), "TLSv1.2");
        assert_eq!(TlsVersion::Tls13.as_str(), "TLSv1.3");
    }

    #[test]
    fn test_rustls_tls_handler_supports_tls() {
        let handler = RustlsTlsHandler::new_test().unwrap();
        assert!(handler.supports_tls());
        assert_eq!(handler.protocol_version(), "TLSv1.3");
    }

    #[test]
    fn tls_protocol_versions_respect_min_and_max() {
        let config = TlsConfig {
            min_tls_version: TlsVersion::Tls12,
            max_tls_version: TlsVersion::Tls12,
            ..TlsConfig::default()
        };
        let versions = RustlsTlsHandler::protocol_versions(&config).unwrap();
        assert_eq!(versions, vec![&version::TLS12]);

        let invalid = TlsConfig {
            min_tls_version: TlsVersion::Tls13,
            max_tls_version: TlsVersion::Tls12,
            ..TlsConfig::default()
        };
        assert!(RustlsTlsHandler::protocol_versions(&invalid).is_err());
    }
}

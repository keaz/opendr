//! SASL Mechanism Implementations
//!
//! This module provides concrete implementations of various SASL mechanisms
//! for LDAP authentication. The built-in production handler currently enables
//! SASL PLAIN plus SASL EXTERNAL authzid parsing for the server bind paths;
//! challenge-response mechanisms should be added only once their client proofs
//! are verified against credential material.

use crate::sasl_fsm::{CredentialVerifier, SaslChallengeResult, SaslMechanismHandler};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;

/// Built-in SASL mechanism handler for production-supported mechanisms.
pub struct MultiMechanismHandler {
    /// Credential verifier for authentication
    credential_verifier: Arc<dyn CredentialVerifier>,
    /// Supported mechanisms
    supported_mechanisms: Vec<String>,
}

pub(crate) struct PlainCredentialsRef<'a> {
    pub(crate) authzid: &'a str,
    pub(crate) authcid: &'a str,
    pub(crate) password: &'a [u8],
}

pub(crate) fn plain_authzid_matches_authenticated_identity(
    authzid: &str,
    authcid: &str,
    authenticated_dn: &str,
) -> bool {
    if authzid.is_empty() {
        return true;
    }

    if let Some(dn) = strip_authzid_prefix(authzid, "dn:") {
        return crate::dn::dn_eq(dn, authenticated_dn);
    }

    if let Some(username) = strip_authzid_prefix(authzid, "u:") {
        return username == authcid;
    }

    crate::dn::dn_eq(authzid, authenticated_dn) || authzid.eq_ignore_ascii_case(authenticated_dn)
}

pub(crate) fn parse_sasl_external_authzid(credentials: Option<&[u8]>) -> Result<&str, String> {
    match credentials {
        Some(bytes) => std::str::from_utf8(bytes)
            .map_err(|_| "invalid SASL EXTERNAL authzid encoding".to_string()),
        None => Ok(""),
    }
}

fn strip_authzid_prefix<'a>(authzid: &'a str, prefix: &str) -> Option<&'a str> {
    if authzid.len() < prefix.len() {
        return None;
    }
    let (candidate, value) = authzid.split_at(prefix.len());
    candidate.eq_ignore_ascii_case(prefix).then_some(value)
}

impl MultiMechanismHandler {
    /// Create a new multi-mechanism handler
    ///
    /// # Arguments
    /// * `credential_verifier` - Verifier for user credentials
    ///
    /// # Returns
    /// * New multi-mechanism handler instance
    pub fn new(credential_verifier: Arc<dyn CredentialVerifier>) -> Self {
        Self {
            credential_verifier,
            supported_mechanisms: vec!["PLAIN".to_string()],
        }
    }

    /// Add a supported mechanism implemented by this handler.
    pub fn add_mechanism(&mut self, mechanism: String) -> Result<(), String> {
        let mechanism = mechanism.trim().to_ascii_uppercase();
        if mechanism != "PLAIN" {
            return Err(format!(
                "SASL mechanism {mechanism} is not production-supported by MultiMechanismHandler"
            ));
        }
        if !self.supported_mechanisms.contains(&mechanism) {
            self.supported_mechanisms.push(mechanism);
        }
        Ok(())
    }

    /// Parse PLAIN mechanism credentials
    ///
    /// Format: [authzid]\0authcid\0passwd
    #[cfg(test)]
    pub(crate) fn parse_plain_credentials(
        data: &[u8],
    ) -> Result<(String, String, Vec<u8>), String> {
        let credentials = Self::parse_plain_credentials_ref(data)?;
        Ok((
            credentials.authzid.to_string(),
            credentials.authcid.to_string(),
            credentials.password.to_vec(),
        ))
    }

    /// Parse PLAIN mechanism credentials as borrowed values.
    ///
    /// Format: [authzid]\0authcid\0passwd
    pub(crate) fn parse_plain_credentials_ref(
        data: &[u8],
    ) -> Result<PlainCredentialsRef<'_>, String> {
        let mut parts = data.split(|&b| b == 0);
        let authzid_bytes = parts
            .next()
            .ok_or_else(|| "Invalid PLAIN credentials format".to_string())?;
        let authcid_bytes = parts
            .next()
            .ok_or_else(|| "Invalid PLAIN credentials format".to_string())?;
        let password = parts
            .next()
            .ok_or_else(|| "Invalid PLAIN credentials format".to_string())?;
        if parts.next().is_some() {
            return Err("Invalid PLAIN credentials format".to_string());
        }

        let authzid = std::str::from_utf8(authzid_bytes)
            .map_err(|e| format!("Invalid authzid encoding: {}", e))?;
        let authcid = std::str::from_utf8(authcid_bytes)
            .map_err(|e| format!("Invalid authcid encoding: {}", e))?;

        Ok(PlainCredentialsRef {
            authzid,
            authcid,
            password,
        })
    }

    /// Handle PLAIN mechanism authentication
    async fn handle_plain(
        &self,
        initial_data: Option<&[u8]>,
    ) -> Result<SaslChallengeResult, String> {
        let data = initial_data.ok_or("PLAIN requires initial data")?;

        let credentials = Self::parse_plain_credentials_ref(data)?;
        if credentials.authcid.is_empty() {
            return Ok(SaslChallengeResult::Failure(
                "Empty SASL identity".to_string(),
            ));
        }

        if !self
            .credential_verifier
            .is_mechanism_allowed(credentials.authcid, "PLAIN")
            .await?
        {
            return Ok(SaslChallengeResult::Failure(
                "SASL mechanism is not allowed for identity".to_string(),
            ));
        }

        // Verify credentials through the credential verifier
        let is_valid = self
            .credential_verifier
            .verify_credentials("PLAIN", credentials.authcid, credentials.password)
            .await?;

        if !is_valid {
            return Ok(SaslChallengeResult::Failure(
                "Invalid credentials".to_string(),
            ));
        }

        // Get user DN
        let dn = self
            .credential_verifier
            .get_user_dn(credentials.authcid)
            .await?
            .ok_or_else(|| "User not found".to_string())?;

        if !plain_authzid_matches_authenticated_identity(
            credentials.authzid,
            credentials.authcid,
            &dn,
        ) {
            return Ok(SaslChallengeResult::Failure(
                "proxy authorization is not supported".to_string(),
            ));
        }

        Ok(SaslChallengeResult::Success { dn })
    }
}

#[async_trait]
impl SaslMechanismHandler for MultiMechanismHandler {
    async fn supports_mechanism(&self, mechanism: &str) -> bool {
        self.supported_mechanisms
            .iter()
            .any(|supported| supported.eq_ignore_ascii_case(mechanism.trim()))
    }

    async fn start_authentication(
        &self,
        mechanism: &str,
        initial_data: Option<&[u8]>,
    ) -> Result<SaslChallengeResult, String> {
        match mechanism.trim().to_ascii_uppercase().as_str() {
            "PLAIN" => self.handle_plain(initial_data).await,
            "DIGEST-MD5" | "CRAM-MD5" => Err(format!("{mechanism} is not production-supported")),
            _ => Err(format!("Unsupported mechanism: {}", mechanism)),
        }
    }

    async fn process_response(
        &self,
        mechanism: &str,
        _step: u32,
        _response: &[u8],
    ) -> Result<SaslChallengeResult, String> {
        match mechanism {
            "DIGEST-MD5" | "CRAM-MD5" => Err(format!("{mechanism} is not production-supported")),
            _ => Err(format!(
                "Mechanism {} does not support multi-step",
                mechanism
            )),
        }
    }

    fn get_mechanism_properties(&self, mechanism: &str) -> HashMap<String, String> {
        let mut props = HashMap::new();
        if mechanism.trim().eq_ignore_ascii_case("PLAIN") {
            props.insert("steps".to_string(), "1".to_string());
            props.insert("security".to_string(), "requires-tls".to_string());
        }
        props
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sasl_fsm::CredentialVerifier;
    use async_trait::async_trait;

    struct MockCredentialVerifier;

    #[async_trait]
    impl CredentialVerifier for MockCredentialVerifier {
        async fn verify_credentials(
            &self,
            _mechanism: &str,
            identity: &str,
            credential: &[u8],
        ) -> Result<bool, String> {
            Ok(identity == "testuser" && credential == b"password")
        }

        async fn get_user_dn(&self, identity: &str) -> Result<Option<String>, String> {
            if identity == "testuser" {
                Ok(Some("cn=testuser,dc=example,dc=org".to_string()))
            } else {
                Ok(None)
            }
        }
    }

    #[tokio::test]
    async fn test_multi_mechanism_handler_supports_mechanisms() {
        let verifier = Arc::new(MockCredentialVerifier);
        let handler = MultiMechanismHandler::new(verifier);

        assert!(handler.supports_mechanism("PLAIN").await);
        assert!(handler.supports_mechanism("plain").await);
        assert!(!handler.supports_mechanism("DIGEST-MD5").await);
        assert!(!handler.supports_mechanism("CRAM-MD5").await);
        assert!(!handler.supports_mechanism("GSSAPI").await);
    }

    #[test]
    fn test_plain_authzid_matches_authenticated_identity() {
        let dn = "cn=testuser,dc=example,dc=org";

        assert!(plain_authzid_matches_authenticated_identity(
            "", "testuser", dn
        ));
        assert!(plain_authzid_matches_authenticated_identity(
            "dn:CN=testuser,DC=example,DC=org",
            "testuser",
            dn
        ));
        assert!(plain_authzid_matches_authenticated_identity(
            "DN:CN=testuser,DC=example,DC=org",
            "testuser",
            dn
        ));
        assert!(plain_authzid_matches_authenticated_identity(
            "u:testuser",
            "testuser",
            dn
        ));
        assert!(plain_authzid_matches_authenticated_identity(
            "cn=testuser,dc=example,dc=org",
            "testuser",
            dn
        ));

        assert!(!plain_authzid_matches_authenticated_identity(
            "dn:cn=other,dc=example,dc=org",
            "testuser",
            dn
        ));
        assert!(!plain_authzid_matches_authenticated_identity(
            "u:other", "testuser", dn
        ));
    }

    #[test]
    fn test_parse_sasl_external_authzid() {
        assert_eq!(parse_sasl_external_authzid(None).unwrap(), "");
        assert_eq!(
            parse_sasl_external_authzid(Some(b"dn:cn=testuser,dc=example,dc=org")).unwrap(),
            "dn:cn=testuser,dc=example,dc=org"
        );
        assert!(parse_sasl_external_authzid(Some(&[0xff])).is_err());
    }

    #[tokio::test]
    async fn test_plain_mechanism_success() {
        let verifier = Arc::new(MockCredentialVerifier);
        let handler = MultiMechanismHandler::new(verifier);

        let credentials = b"\0testuser\0password";
        let result = handler.handle_plain(Some(credentials)).await;

        assert!(result.is_ok());
        match result.unwrap() {
            SaslChallengeResult::Success { dn } => {
                assert_eq!(dn, "cn=testuser,dc=example,dc=org");
            }
            _ => panic!("Expected success"),
        }
    }

    #[tokio::test]
    async fn test_plain_mechanism_accepts_self_authorization_identity_forms() {
        let verifier = Arc::new(MockCredentialVerifier);
        let handler = MultiMechanismHandler::new(verifier);

        let result = handler
            .handle_plain(Some(
                b"dn:CN=testuser,DC=example,DC=org\0testuser\0password",
            ))
            .await
            .unwrap();
        assert_eq!(
            result,
            SaslChallengeResult::Success {
                dn: "cn=testuser,dc=example,dc=org".to_string()
            }
        );

        let result = handler
            .handle_plain(Some(b"u:testuser\0testuser\0password"))
            .await
            .unwrap();
        assert_eq!(
            result,
            SaslChallengeResult::Success {
                dn: "cn=testuser,dc=example,dc=org".to_string()
            }
        );
    }

    #[tokio::test]
    async fn test_plain_mechanism_rejects_proxy_authorization_identity() {
        let verifier = Arc::new(MockCredentialVerifier);
        let handler = MultiMechanismHandler::new(verifier);

        let result = handler
            .handle_plain(Some(b"dn:cn=other,dc=example,dc=org\0testuser\0password"))
            .await
            .unwrap();

        assert!(matches!(
            result,
            SaslChallengeResult::Failure(reason)
                if reason == "proxy authorization is not supported"
        ));
    }

    #[tokio::test]
    async fn test_plain_mechanism_failure() {
        let verifier = Arc::new(MockCredentialVerifier);
        let handler = MultiMechanismHandler::new(verifier);

        let credentials = b"\0baduser\0password";
        let result = handler.handle_plain(Some(credentials)).await;

        assert!(result.is_ok());
        match result.unwrap() {
            SaslChallengeResult::Failure(_) => {}
            _ => panic!("Expected failure"),
        }
    }

    #[tokio::test]
    async fn test_plain_mechanism_wrong_password_fails() {
        let verifier = Arc::new(MockCredentialVerifier);
        let handler = MultiMechanismHandler::new(verifier);

        let credentials = b"\0testuser\0wrong";
        let result = handler.handle_plain(Some(credentials)).await;

        assert!(result.is_ok());
        match result.unwrap() {
            SaslChallengeResult::Failure(_) => {}
            _ => panic!("Expected failure"),
        }
    }

    #[tokio::test]
    async fn test_parse_plain_credentials() {
        let credentials = b"\0testuser\0password";
        let result = MultiMechanismHandler::parse_plain_credentials(credentials);

        assert!(result.is_ok());
        let (authzid, authcid, passwd) = result.unwrap();
        assert_eq!(authzid, "");
        assert_eq!(authcid, "testuser");
        assert_eq!(passwd, b"password");
    }

    #[tokio::test]
    async fn test_mechanism_properties() {
        let verifier = Arc::new(MockCredentialVerifier);
        let handler = MultiMechanismHandler::new(verifier);

        let props = handler.get_mechanism_properties("PLAIN");
        assert_eq!(props.get("steps"), Some(&"1".to_string()));
        assert_eq!(props.get("security"), Some(&"requires-tls".to_string()));

        let props = handler.get_mechanism_properties("plain");
        assert_eq!(props.get("steps"), Some(&"1".to_string()));
        assert_eq!(props.get("security"), Some(&"requires-tls".to_string()));

        let props = handler.get_mechanism_properties("DIGEST-MD5");
        assert!(props.is_empty());
    }
}

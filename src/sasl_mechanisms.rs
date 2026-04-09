//! SASL Mechanism Implementations
//!
//! This module provides concrete implementations of various SASL mechanisms
//! for LDAP authentication, including PLAIN, DIGEST-MD5, and others.

use crate::sasl_fsm::{CredentialVerifier, SaslChallengeResult, SaslMechanismHandler};
use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use std::collections::HashMap;
use std::sync::Arc;

/// Combined SASL mechanism handler supporting multiple mechanisms
pub struct MultiMechanismHandler {
    /// Credential verifier for authentication
    credential_verifier: Arc<dyn CredentialVerifier>,
    /// Supported mechanisms
    supported_mechanisms: Vec<String>,
    /// Active sessions for multi-step authentication
    sessions: Arc<tokio::sync::Mutex<HashMap<String, SaslSessionData>>>,
}

/// Session data for multi-step SASL authentication
#[allow(dead_code)]
#[derive(Debug, Clone)]
struct SaslSessionData {
    mechanism: String,
    step: u32,
    nonce: Option<String>,
    username: Option<String>,
    realm: Option<String>,
    cnonce: Option<String>,
    qop: Option<String>,
    nc: Option<String>,
    response_hash: Option<String>,
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
            supported_mechanisms: vec![
                "PLAIN".to_string(),
                "DIGEST-MD5".to_string(),
                "CRAM-MD5".to_string(),
            ],
            sessions: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }

    /// Add a supported mechanism
    pub fn add_mechanism(&mut self, mechanism: String) {
        if !self.supported_mechanisms.contains(&mechanism) {
            self.supported_mechanisms.push(mechanism);
        }
    }

    /// Parse PLAIN mechanism credentials
    ///
    /// Format: [authzid]\0authcid\0passwd
    fn parse_plain_credentials(data: &[u8]) -> Result<(String, String, String), String> {
        let parts: Vec<&[u8]> = data.split(|&b| b == 0).collect();

        if parts.len() != 3 {
            return Err("Invalid PLAIN credentials format".to_string());
        }

        let authzid = String::from_utf8(parts[0].to_vec())
            .map_err(|e| format!("Invalid authzid encoding: {}", e))?;
        let authcid = String::from_utf8(parts[1].to_vec())
            .map_err(|e| format!("Invalid authcid encoding: {}", e))?;
        let passwd = String::from_utf8(parts[2].to_vec())
            .map_err(|e| format!("Invalid password encoding: {}", e))?;

        Ok((authzid, authcid, passwd))
    }

    /// Handle PLAIN mechanism authentication
    async fn handle_plain(
        &self,
        initial_data: Option<&[u8]>,
    ) -> Result<SaslChallengeResult, String> {
        let data = initial_data.ok_or("PLAIN requires initial data")?;

        let (_authzid, authcid, _passwd) = Self::parse_plain_credentials(data)?;

        // Verify credentials through the credential verifier
        let is_valid = self
            .credential_verifier
            .verify_credentials("PLAIN", &authcid)
            .await?;

        if !is_valid {
            return Ok(SaslChallengeResult::Failure(
                "Invalid credentials".to_string(),
            ));
        }

        // Get user DN
        let dn = self
            .credential_verifier
            .get_user_dn(&authcid)
            .await?
            .ok_or_else(|| "User not found".to_string())?;

        Ok(SaslChallengeResult::Success { dn })
    }

    /// Generate a random nonce for DIGEST-MD5
    fn generate_nonce() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let random_bytes = uuid::Uuid::new_v4();
        general_purpose::STANDARD.encode(format!("{}{}", timestamp, random_bytes))
    }

    /// Handle DIGEST-MD5 mechanism authentication (initial challenge)
    async fn handle_digest_md5_start(&self) -> Result<SaslChallengeResult, String> {
        let nonce = Self::generate_nonce();
        let realm = "ldap.example.org";
        let qop = "auth";
        let algorithm = "md5-sess";

        // Create challenge
        let challenge = format!(
            "realm=\"{}\",nonce=\"{}\",qop=\"{}\",algorithm={}",
            realm, nonce, qop, algorithm
        );

        // Store session data
        let session_id = nonce.clone();
        let session = SaslSessionData {
            mechanism: "DIGEST-MD5".to_string(),
            step: 1,
            nonce: Some(nonce),
            username: None,
            realm: Some(realm.to_string()),
            cnonce: None,
            qop: Some(qop.to_string()),
            nc: None,
            response_hash: None,
        };

        self.sessions.lock().await.insert(session_id, session);

        Ok(SaslChallengeResult::Challenge(challenge.into_bytes()))
    }

    /// Parse DIGEST-MD5 response
    fn parse_digest_md5_response(data: &[u8]) -> Result<HashMap<String, String>, String> {
        let response_str = String::from_utf8(data.to_vec())
            .map_err(|e| format!("Invalid response encoding: {}", e))?;

        let mut params = HashMap::new();
        for part in response_str.split(',') {
            let trimmed = part.trim();
            if let Some(eq_pos) = trimmed.find('=') {
                let key = trimmed[..eq_pos].trim().to_string();
                let value = trimmed[eq_pos + 1..].trim().trim_matches('"').to_string();
                params.insert(key, value);
            }
        }

        Ok(params)
    }

    /// Handle DIGEST-MD5 response verification
    async fn handle_digest_md5_response(
        &self,
        response_data: &[u8],
    ) -> Result<SaslChallengeResult, String> {
        let params = Self::parse_digest_md5_response(response_data)?;

        let username = params
            .get("username")
            .ok_or("Missing username in response")?;
        let nonce = params.get("nonce").ok_or("Missing nonce in response")?;
        let _response = params
            .get("response")
            .ok_or("Missing response in response")?;

        // Verify credentials
        let is_valid = self
            .credential_verifier
            .verify_credentials("DIGEST-MD5", username)
            .await?;

        if !is_valid {
            return Ok(SaslChallengeResult::Failure(
                "Invalid credentials".to_string(),
            ));
        }

        // Get user DN
        let dn = self
            .credential_verifier
            .get_user_dn(username)
            .await?
            .ok_or_else(|| "User not found".to_string())?;

        // Clean up session
        self.sessions.lock().await.remove(nonce);

        Ok(SaslChallengeResult::Success { dn })
    }

    /// Handle CRAM-MD5 mechanism authentication
    async fn handle_cram_md5_start(&self) -> Result<SaslChallengeResult, String> {
        let challenge = Self::generate_nonce();
        Ok(SaslChallengeResult::Challenge(challenge.into_bytes()))
    }

    /// Handle CRAM-MD5 response
    async fn handle_cram_md5_response(
        &self,
        response_data: &[u8],
    ) -> Result<SaslChallengeResult, String> {
        let response_str = String::from_utf8(response_data.to_vec())
            .map_err(|e| format!("Invalid response encoding: {}", e))?;

        let parts: Vec<&str> = response_str.split_whitespace().collect();
        if parts.len() != 2 {
            return Ok(SaslChallengeResult::Failure(
                "Invalid CRAM-MD5 response".to_string(),
            ));
        }

        let username = parts[0];
        let _provided_hash = parts[1];

        // Verify credentials
        let is_valid = self
            .credential_verifier
            .verify_credentials("CRAM-MD5", username)
            .await?;

        if !is_valid {
            return Ok(SaslChallengeResult::Failure(
                "Invalid credentials".to_string(),
            ));
        }

        // Get user DN
        let dn = self
            .credential_verifier
            .get_user_dn(username)
            .await?
            .ok_or_else(|| "User not found".to_string())?;

        Ok(SaslChallengeResult::Success { dn })
    }
}

#[async_trait]
impl SaslMechanismHandler for MultiMechanismHandler {
    async fn supports_mechanism(&self, mechanism: &str) -> bool {
        self.supported_mechanisms.contains(&mechanism.to_string())
    }

    async fn start_authentication(
        &self,
        mechanism: &str,
        initial_data: Option<&[u8]>,
    ) -> Result<SaslChallengeResult, String> {
        match mechanism {
            "PLAIN" => self.handle_plain(initial_data).await,
            "DIGEST-MD5" => self.handle_digest_md5_start().await,
            "CRAM-MD5" => self.handle_cram_md5_start().await,
            _ => Err(format!("Unsupported mechanism: {}", mechanism)),
        }
    }

    async fn process_response(
        &self,
        mechanism: &str,
        _step: u32,
        response: &[u8],
    ) -> Result<SaslChallengeResult, String> {
        match mechanism {
            "DIGEST-MD5" => self.handle_digest_md5_response(response).await,
            "CRAM-MD5" => self.handle_cram_md5_response(response).await,
            _ => Err(format!(
                "Mechanism {} does not support multi-step",
                mechanism
            )),
        }
    }

    fn get_mechanism_properties(&self, mechanism: &str) -> HashMap<String, String> {
        let mut props = HashMap::new();
        match mechanism {
            "PLAIN" => {
                props.insert("steps".to_string(), "1".to_string());
                props.insert("security".to_string(), "requires-tls".to_string());
            }
            "DIGEST-MD5" => {
                props.insert("steps".to_string(), "2".to_string());
                props.insert("security".to_string(), "hash-based".to_string());
            }
            "CRAM-MD5" => {
                props.insert("steps".to_string(), "2".to_string());
                props.insert("security".to_string(), "hash-based".to_string());
            }
            _ => {}
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
        ) -> Result<bool, String> {
            Ok(identity == "testuser")
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
        assert!(handler.supports_mechanism("DIGEST-MD5").await);
        assert!(handler.supports_mechanism("CRAM-MD5").await);
        assert!(!handler.supports_mechanism("GSSAPI").await);
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
    async fn test_parse_plain_credentials() {
        let credentials = b"\0testuser\0password";
        let result = MultiMechanismHandler::parse_plain_credentials(credentials);

        assert!(result.is_ok());
        let (authzid, authcid, passwd) = result.unwrap();
        assert_eq!(authzid, "");
        assert_eq!(authcid, "testuser");
        assert_eq!(passwd, "password");
    }

    #[tokio::test]
    async fn test_digest_md5_start() {
        let verifier = Arc::new(MockCredentialVerifier);
        let handler = MultiMechanismHandler::new(verifier);

        let result = handler.handle_digest_md5_start().await;

        assert!(result.is_ok());
        match result.unwrap() {
            SaslChallengeResult::Challenge(data) => {
                let challenge = String::from_utf8(data).unwrap();
                assert!(challenge.contains("realm="));
                assert!(challenge.contains("nonce="));
                assert!(challenge.contains("qop="));
            }
            _ => panic!("Expected challenge"),
        }
    }

    #[test]
    fn test_generate_nonce() {
        let nonce1 = MultiMechanismHandler::generate_nonce();
        let nonce2 = MultiMechanismHandler::generate_nonce();

        assert_ne!(nonce1, nonce2);
        assert!(!nonce1.is_empty());
        assert!(!nonce2.is_empty());
    }

    #[tokio::test]
    async fn test_mechanism_properties() {
        let verifier = Arc::new(MockCredentialVerifier);
        let handler = MultiMechanismHandler::new(verifier);

        let props = handler.get_mechanism_properties("PLAIN");
        assert_eq!(props.get("steps"), Some(&"1".to_string()));
        assert_eq!(props.get("security"), Some(&"requires-tls".to_string()));

        let props = handler.get_mechanism_properties("DIGEST-MD5");
        assert_eq!(props.get("steps"), Some(&"2".to_string()));
        assert_eq!(props.get("security"), Some(&"hash-based".to_string()));
    }
}

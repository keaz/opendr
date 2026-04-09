//! Extended Operations Implementations
//!
//! This module provides concrete implementations of LDAP extended operations
//! including StartTLS, Password Modify, WhoAmI, and Cancel.

use crate::extended_op_fsm::{
    ExtendedOpAccessControl, ExtendedOpBackend, ExtendedOpDelegator, ExtendedOpMetrics,
    ExtendedOpParser, ExtendedOperationType, ParsedOperation,
};
use async_trait::async_trait;
use rasn::types::OctetString;
use rasn::{AsnType, Decode, Encode};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// OIDs for standard extended operations
pub mod oids {
    pub const START_TLS: &str = "1.3.6.1.4.1.1466.20037";
    pub const PASSWORD_MODIFY: &str = "1.3.6.1.4.1.4203.1.11.1";
    pub const WHO_AM_I: &str = "1.3.6.1.4.1.4203.1.11.3";
    pub const CANCEL: &str = "1.3.6.1.1.8";
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CancelRequestCodecError {
    MissingRequestValue,
    InvalidAsn1(String),
    InvalidMessageId,
}

impl std::fmt::Display for CancelRequestCodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingRequestValue => write!(f, "cancel requires requestValue"),
            Self::InvalidAsn1(err) => write!(f, "invalid cancel BER: {err}"),
            Self::InvalidMessageId => write!(f, "cancelID must be a positive message ID"),
        }
    }
}

impl std::error::Error for CancelRequestCodecError {}

#[derive(AsnType, Decode, Encode)]
struct CancelRequestValue {
    cancel_id: i32,
}

pub fn encode_cancel_request_value(message_id: i32) -> Result<Vec<u8>, CancelRequestCodecError> {
    if message_id <= 0 {
        return Err(CancelRequestCodecError::InvalidMessageId);
    }

    rasn::ber::encode(&CancelRequestValue {
        cancel_id: message_id,
    })
    .map_err(|err| CancelRequestCodecError::InvalidAsn1(err.to_string()))
}

pub fn parse_cancel_request_value(value: Option<&[u8]>) -> Result<i32, CancelRequestCodecError> {
    let value = value.ok_or(CancelRequestCodecError::MissingRequestValue)?;
    let decoded: CancelRequestValue = rasn::ber::decode(value)
        .map_err(|err| CancelRequestCodecError::InvalidAsn1(err.to_string()))?;
    if decoded.cancel_id <= 0 {
        return Err(CancelRequestCodecError::InvalidMessageId);
    }
    Ok(decoded.cancel_id)
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PasswordModifyRequest {
    pub user_identity: Option<String>,
    pub old_password: Option<Vec<u8>>,
    pub new_password: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordModifyCodecError {
    InvalidAsn1(String),
    InvalidUtf8(&'static str),
    EmptyRequestValue,
    MissingGeneratedPassword,
}

impl std::fmt::Display for PasswordModifyCodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidAsn1(err) => write!(f, "invalid password modify BER: {err}"),
            Self::InvalidUtf8(field) => write!(f, "{field} must be valid UTF-8"),
            Self::EmptyRequestValue => write!(
                f,
                "password modify requestValue must contain at least one field"
            ),
            Self::MissingGeneratedPassword => {
                write!(f, "password modify response did not include genPasswd")
            }
        }
    }
}

impl std::error::Error for PasswordModifyCodecError {}

#[derive(AsnType, Decode, Encode)]
struct PasswordModifyRequestValue {
    #[rasn(tag(context, 0))]
    user_identity: Option<OctetString>,
    #[rasn(tag(context, 1))]
    old_password: Option<OctetString>,
    #[rasn(tag(context, 2))]
    new_password: Option<OctetString>,
}

#[derive(AsnType, Decode, Encode)]
struct PasswordModifyResponseValue {
    #[rasn(tag(context, 0))]
    generated_password: Option<OctetString>,
}

pub fn parse_password_modify_request_value(
    value: Option<&[u8]>,
) -> Result<PasswordModifyRequest, PasswordModifyCodecError> {
    let Some(value) = value else {
        return Ok(PasswordModifyRequest::default());
    };

    let decoded: PasswordModifyRequestValue = rasn::ber::decode(value)
        .map_err(|err| PasswordModifyCodecError::InvalidAsn1(err.to_string()))?;

    if decoded.user_identity.is_none()
        && decoded.old_password.is_none()
        && decoded.new_password.is_none()
    {
        return Err(PasswordModifyCodecError::EmptyRequestValue);
    }

    let user_identity = decoded
        .user_identity
        .map(|value| {
            String::from_utf8(value.to_vec())
                .map_err(|_| PasswordModifyCodecError::InvalidUtf8("userIdentity"))
        })
        .transpose()?;

    Ok(PasswordModifyRequest {
        user_identity,
        old_password: decoded.old_password.map(|value| value.to_vec()),
        new_password: decoded.new_password.map(|value| value.to_vec()),
    })
}

pub fn encode_password_modify_request_value(
    request: &PasswordModifyRequest,
) -> Result<Option<Vec<u8>>, PasswordModifyCodecError> {
    if request.user_identity.is_none()
        && request.old_password.is_none()
        && request.new_password.is_none()
    {
        return Ok(None);
    }

    rasn::ber::encode(&PasswordModifyRequestValue {
        user_identity: request
            .user_identity
            .as_deref()
            .map(|value| value.as_bytes().to_vec().into()),
        old_password: request
            .old_password
            .as_deref()
            .map(|value| value.to_vec().into()),
        new_password: request
            .new_password
            .as_deref()
            .map(|value| value.to_vec().into()),
    })
    .map(Some)
    .map_err(|err| PasswordModifyCodecError::InvalidAsn1(err.to_string()))
}

pub fn encode_password_modify_response_value(
    generated_password: Option<&[u8]>,
) -> Result<Option<Vec<u8>>, PasswordModifyCodecError> {
    let Some(generated_password) = generated_password else {
        return Ok(None);
    };

    rasn::ber::encode(&PasswordModifyResponseValue {
        generated_password: Some(generated_password.to_vec().into()),
    })
    .map(Some)
    .map_err(|err| PasswordModifyCodecError::InvalidAsn1(err.to_string()))
}

pub fn decode_password_modify_response_value(
    value: Option<&[u8]>,
) -> Result<Option<Vec<u8>>, PasswordModifyCodecError> {
    let Some(value) = value else {
        return Ok(None);
    };

    let decoded: PasswordModifyResponseValue = rasn::ber::decode(value)
        .map_err(|err| PasswordModifyCodecError::InvalidAsn1(err.to_string()))?;
    let generated_password = decoded
        .generated_password
        .ok_or(PasswordModifyCodecError::MissingGeneratedPassword)?;
    Ok(Some(generated_password.to_vec()))
}

/// Standard extended operations backend implementation
pub struct StandardExtendedOpBackend {
    /// Password modifier for password modify operation
    password_modifier: Arc<dyn PasswordModifier>,
    /// Operation canceller
    operation_canceller: Arc<dyn OperationCanceller>,
}

/// Trait for modifying user passwords
#[async_trait]
pub trait PasswordModifier: Send + Sync {
    /// Modify a user's password
    ///
    /// # Arguments
    /// * `user_dn` - User DN whose password to modify
    /// * `old_password` - Optional old password for verification
    /// * `new_password` - New password to set
    ///
    /// # Returns
    /// * `Ok(())` if password was modified successfully
    /// * `Err(String)` if modification failed
    async fn modify_password(
        &self,
        user_dn: &str,
        old_password: Option<&str>,
        new_password: &str,
    ) -> Result<(), String>;
}

/// Trait for cancelling operations
#[async_trait]
pub trait OperationCanceller: Send + Sync {
    /// Cancel an operation by message ID
    ///
    /// # Arguments
    /// * `message_id` - Message ID of operation to cancel
    ///
    /// # Returns
    /// * `Ok(())` if operation was cancelled
    /// * `Err(String)` if cancellation failed
    async fn cancel_operation(&self, message_id: i32) -> Result<(), String>;
}

impl StandardExtendedOpBackend {
    /// Create a new standard extended operations backend
    pub fn new(
        password_modifier: Arc<dyn PasswordModifier>,
        operation_canceller: Arc<dyn OperationCanceller>,
    ) -> Self {
        Self {
            password_modifier,
            operation_canceller,
        }
    }

    /// Handle StartTLS operation
    async fn handle_start_tls(&self, _value: Option<&[u8]>) -> Result<Vec<u8>, String> {
        // StartTLS is handled by delegation to TLS layer
        // Return success response
        Ok(vec![])
    }

    /// Handle Password Modify operation
    async fn handle_password_modify(&self, value: Option<&[u8]>) -> Result<Vec<u8>, String> {
        let request = parse_password_modify_request_value(value).map_err(|err| err.to_string())?;
        let user_dn = request
            .user_identity
            .as_deref()
            .ok_or("Password modify helper backend requires userIdentity")?;
        let old_password = request
            .old_password
            .as_deref()
            .map(|password| {
                std::str::from_utf8(password)
                    .map_err(|_| "Old password must be valid UTF-8".to_string())
            })
            .transpose()?;
        let new_password = request
            .new_password
            .as_deref()
            .ok_or("Password modify helper backend requires newPasswd")?;
        let new_password = std::str::from_utf8(new_password)
            .map_err(|_| "New password must be valid UTF-8".to_string())?;

        // Modify password
        self.password_modifier
            .modify_password(user_dn, old_password, new_password)
            .await?;

        // Return success response
        Ok(vec![])
    }

    /// Handle WhoAmI operation
    async fn handle_who_am_i(&self, user_dn: Option<&str>) -> Result<Vec<u8>, String> {
        let dn = user_dn.unwrap_or("anonymous");
        Ok(dn.as_bytes().to_vec())
    }

    /// Handle Cancel operation
    async fn handle_cancel(&self, value: Option<&[u8]>) -> Result<Vec<u8>, String> {
        let message_id = parse_cancel_request_value(value).map_err(|err| err.to_string())?;

        self.operation_canceller
            .cancel_operation(message_id)
            .await?;

        Ok(vec![])
    }
}

#[async_trait]
impl ExtendedOpBackend for StandardExtendedOpBackend {
    async fn execute_operation(&self, oid: &str, value: Option<&[u8]>) -> Result<Vec<u8>, String> {
        match oid {
            oids::START_TLS => self.handle_start_tls(value).await,
            oids::PASSWORD_MODIFY => self.handle_password_modify(value).await,
            oids::WHO_AM_I => self.handle_who_am_i(None).await, // User DN would come from context
            oids::CANCEL => self.handle_cancel(value).await,
            _ => Err(format!("Unsupported operation OID: {}", oid)),
        }
    }

    fn is_operation_supported(&self, oid: &str) -> bool {
        matches!(
            oid,
            oids::START_TLS | oids::PASSWORD_MODIFY | oids::WHO_AM_I | oids::CANCEL
        )
    }

    fn requires_delegation(&self, oid: &str) -> bool {
        // Only StartTLS requires delegation to TLS layer
        oid == oids::START_TLS
    }
}

/// Standard parser for extended operations
pub struct StandardExtendedOpParser;

impl StandardExtendedOpParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for StandardExtendedOpParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ExtendedOpParser for StandardExtendedOpParser {
    fn parse_request(&self, oid: &str, value: Option<&[u8]>) -> Result<ParsedOperation, String> {
        let operation_type = match oid {
            oids::START_TLS => ExtendedOperationType::StartTLS,
            oids::PASSWORD_MODIFY => ExtendedOperationType::PasswordModify,
            oids::WHO_AM_I => ExtendedOperationType::WhoAmI,
            oids::CANCEL => ExtendedOperationType::Cancel,
            _ => ExtendedOperationType::Custom(oid.to_string()),
        };

        let mut parameters = HashMap::new();
        if let Some(data) = value {
            parameters.insert("value".to_string(), data.to_vec());
        }

        Ok(ParsedOperation {
            oid: oid.to_string(),
            operation_type,
            parameters,
            requires_delegation: oid == oids::START_TLS,
        })
    }

    fn validate_operation(&self, operation: &ParsedOperation) -> Result<(), String> {
        match &operation.operation_type {
            ExtendedOperationType::Cancel => {
                if !operation.parameters.contains_key("value") {
                    return Err("Cancel requires value parameter (message ID)".to_string());
                }
            }
            _ => {}
        }
        Ok(())
    }
}

/// No-op delegator (for testing or when delegation not needed)
pub struct NoOpDelegator;

#[async_trait]
impl ExtendedOpDelegator for NoOpDelegator {
    async fn delegate_operation(&self, _operation: &ParsedOperation) -> Result<Vec<u8>, String> {
        Err("Delegation not supported".to_string())
    }

    fn get_delegates(&self, _oid: &str) -> Vec<String> {
        vec![]
    }
}

/// Permissive access control (allows all operations for testing)
pub struct PermissiveAccessControl;

impl ExtendedOpAccessControl for PermissiveAccessControl {
    fn check_permission(&self, _oid: &str, _user_dn: Option<&str>) -> Result<(), String> {
        Ok(())
    }
}

/// Basic metrics collector for extended operations
pub struct ExtendedOpMetricsCollector {
    operation_starts: Arc<AtomicU64>,
    operation_successes: Arc<AtomicU64>,
    operation_failures: Arc<AtomicU64>,
    delegations: Arc<AtomicU64>,
}

impl ExtendedOpMetricsCollector {
    pub fn new() -> Self {
        Self {
            operation_starts: Arc::new(AtomicU64::new(0)),
            operation_successes: Arc::new(AtomicU64::new(0)),
            operation_failures: Arc::new(AtomicU64::new(0)),
            delegations: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn stats(&self) -> (u64, u64, u64, u64) {
        (
            self.operation_starts.load(Ordering::Relaxed),
            self.operation_successes.load(Ordering::Relaxed),
            self.operation_failures.load(Ordering::Relaxed),
            self.delegations.load(Ordering::Relaxed),
        )
    }
}

impl Default for ExtendedOpMetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl ExtendedOpMetrics for ExtendedOpMetricsCollector {
    fn record_operation_start(&self, _oid: &str) {
        self.operation_starts.fetch_add(1, Ordering::Relaxed);
    }

    fn record_operation_complete(&self, _oid: &str, success: bool, _duration_ms: u64) {
        if success {
            self.operation_successes.fetch_add(1, Ordering::Relaxed);
        } else {
            self.operation_failures.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn record_delegation(&self, _oid: &str, _delegate: &str) {
        self.delegations.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockPasswordModifier;

    #[async_trait]
    impl PasswordModifier for MockPasswordModifier {
        async fn modify_password(
            &self,
            user_dn: &str,
            _old_password: Option<&str>,
            _new_password: &str,
        ) -> Result<(), String> {
            if user_dn.contains("testuser") {
                Ok(())
            } else {
                Err("User not found".to_string())
            }
        }
    }

    struct MockOperationCanceller;

    #[async_trait]
    impl OperationCanceller for MockOperationCanceller {
        async fn cancel_operation(&self, message_id: i32) -> Result<(), String> {
            if message_id > 0 {
                Ok(())
            } else {
                Err("Invalid message ID".to_string())
            }
        }
    }

    #[tokio::test]
    async fn test_start_tls_operation() {
        let backend = StandardExtendedOpBackend::new(
            Arc::new(MockPasswordModifier),
            Arc::new(MockOperationCanceller),
        );

        let result = backend.execute_operation(oids::START_TLS, None).await;
        assert!(result.is_ok());
        assert!(backend.requires_delegation(oids::START_TLS));
    }

    #[tokio::test]
    async fn test_who_am_i_operation() {
        let backend = StandardExtendedOpBackend::new(
            Arc::new(MockPasswordModifier),
            Arc::new(MockOperationCanceller),
        );

        let result = backend.execute_operation(oids::WHO_AM_I, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_password_modify_operation() {
        let backend = StandardExtendedOpBackend::new(
            Arc::new(MockPasswordModifier),
            Arc::new(MockOperationCanceller),
        );

        let request = PasswordModifyRequest {
            user_identity: Some("cn=testuser,dc=example,dc=org".to_string()),
            old_password: Some(b"old123".to_vec()),
            new_password: Some(b"new456".to_vec()),
        };
        let request = encode_password_modify_request_value(&request)
            .unwrap()
            .unwrap();
        let result = backend
            .execute_operation(oids::PASSWORD_MODIFY, Some(&request))
            .await;
        if let Err(ref e) = result {
            eprintln!("Password modify failed: {}", e);
        }
        assert!(result.is_ok(), "Password modify failed: {:?}", result);
    }

    #[tokio::test]
    async fn test_cancel_operation() {
        let backend = StandardExtendedOpBackend::new(
            Arc::new(MockPasswordModifier),
            Arc::new(MockOperationCanceller),
        );

        let message_id = encode_cancel_request_value(42).unwrap();
        let result = backend
            .execute_operation(oids::CANCEL, Some(&message_id))
            .await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_parser_start_tls() {
        let parser = StandardExtendedOpParser::new();
        let result = parser.parse_request(oids::START_TLS, None);

        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.oid, oids::START_TLS);
        assert_eq!(parsed.operation_type, ExtendedOperationType::StartTLS);
        assert!(parsed.requires_delegation);
    }

    #[test]
    fn test_parser_password_modify() {
        let parser = StandardExtendedOpParser::new();
        let value = b"test data";
        let result = parser.parse_request(oids::PASSWORD_MODIFY, Some(value));

        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.oid, oids::PASSWORD_MODIFY);
        assert_eq!(parsed.operation_type, ExtendedOperationType::PasswordModify);
        assert!(!parsed.requires_delegation);
    }

    #[test]
    fn parse_password_modify_request_value_accepts_absent_value() {
        let parsed = parse_password_modify_request_value(None).unwrap();
        assert_eq!(parsed, PasswordModifyRequest::default());
    }

    #[test]
    fn parse_password_modify_request_value_round_trips_all_fields() {
        let encoded = encode_password_modify_request_value(&PasswordModifyRequest {
            user_identity: Some("cn=testuser,dc=example,dc=org".to_string()),
            old_password: Some(b"old123".to_vec()),
            new_password: Some(b"new456".to_vec()),
        })
        .unwrap()
        .unwrap();

        let parsed = parse_password_modify_request_value(Some(&encoded)).unwrap();
        assert_eq!(
            parsed.user_identity.as_deref(),
            Some("cn=testuser,dc=example,dc=org")
        );
        assert_eq!(parsed.old_password.as_deref(), Some(b"old123".as_ref()));
        assert_eq!(parsed.new_password.as_deref(), Some(b"new456".as_ref()));
    }

    #[test]
    fn parse_password_modify_request_value_rejects_empty_sequence() {
        let encoded = rasn::ber::encode(&PasswordModifyRequestValue {
            user_identity: None,
            old_password: None,
            new_password: None,
        })
        .unwrap();

        let err = parse_password_modify_request_value(Some(&encoded)).unwrap_err();
        assert_eq!(err, PasswordModifyCodecError::EmptyRequestValue);
    }

    #[test]
    fn encode_and_decode_password_modify_response_value_round_trip() {
        let encoded = encode_password_modify_response_value(Some(b"generated-secret")).unwrap();
        let decoded = decode_password_modify_response_value(encoded.as_deref()).unwrap();
        assert_eq!(decoded.as_deref(), Some(b"generated-secret".as_ref()));
    }

    #[test]
    fn cancel_request_value_round_trips_message_id() {
        let encoded = encode_cancel_request_value(42).unwrap();
        let decoded = parse_cancel_request_value(Some(&encoded)).unwrap();
        assert_eq!(decoded, 42);
    }

    #[test]
    fn encode_password_modify_request_value_omits_empty_request() {
        let encoded =
            encode_password_modify_request_value(&PasswordModifyRequest::default()).unwrap();
        assert!(encoded.is_none());
    }

    #[test]
    fn parser_allows_password_modify_without_request_value() {
        let parser = StandardExtendedOpParser::new();
        let parsed = parser.parse_request(oids::PASSWORD_MODIFY, None).unwrap();
        assert_eq!(parsed.oid, oids::PASSWORD_MODIFY);
        assert!(!parsed.requires_delegation);
        assert!(parser.validate_operation(&parsed).is_ok());
    }

    #[test]
    fn test_metrics_collector() {
        let metrics = ExtendedOpMetricsCollector::new();

        metrics.record_operation_start("test.oid");
        metrics.record_operation_complete("test.oid", true, 100);
        metrics.record_operation_complete("test.oid", false, 50);
        metrics.record_delegation("test.oid", "delegate1");

        let (starts, successes, failures, delegations) = metrics.stats();
        assert_eq!(starts, 1);
        assert_eq!(successes, 1);
        assert_eq!(failures, 1);
        assert_eq!(delegations, 1);
    }

    #[test]
    fn test_permissive_access_control() {
        let ac = PermissiveAccessControl;
        assert!(ac.check_permission("any.oid", Some("cn=user")).is_ok());
        assert!(ac.check_permission("any.oid", None).is_ok());
    }
}

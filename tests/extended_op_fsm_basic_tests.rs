use opendr::extended_op_fsm::{
    ExtendedOpFsmImpl, ParsedOperation, ExtendedOperationType, ExtendedOpError,
    ExtendedOpBackend, ExtendedOpParser, ExtendedOpDelegator, 
    ExtendedOpAccessControl, ExtendedOpMetrics,
};
use opendr::fsm::{ExtendedOpState, ExtendedOpEvent, ExtendedOpResultCode, StateMachine, ExtendedOpFsm};
use std::collections::HashMap;
use async_trait::async_trait;
use tokio;

/// Mock backend for testing
pub struct MockBackend;

#[async_trait]
impl ExtendedOpBackend for MockBackend {
    async fn execute_operation(&self, _oid: &str, _value: Option<&[u8]>) -> Result<Vec<u8>, String> {
        Ok(b"test_response".to_vec())
    }
    
    fn is_operation_supported(&self, _oid: &str) -> bool {
        true
    }
    
    fn requires_delegation(&self, _oid: &str) -> bool {
        false
    }
}

/// Mock parser for testing
pub struct MockParser;

impl ExtendedOpParser for MockParser {
    fn parse_request(&self, oid: &str, _value: Option<&[u8]>) -> Result<ParsedOperation, String> {
        Ok(ParsedOperation {
            oid: oid.to_string(),
            operation_type: ExtendedOperationType::WhoAmI,
            parameters: HashMap::new(),
            requires_delegation: false,
        })
    }
    
    fn validate_operation(&self, _operation: &ParsedOperation) -> Result<(), String> {
        Ok(())
    }
}

/// Mock delegator for testing
pub struct MockDelegator;

#[async_trait]
impl ExtendedOpDelegator for MockDelegator {
    async fn delegate_operation(&self, _operation: &ParsedOperation) -> Result<Vec<u8>, String> {
        Ok(b"delegated_response".to_vec())
    }
    
    fn get_delegates(&self, _oid: &str) -> Vec<String> {
        vec![]
    }
}

/// Mock access control for testing
pub struct MockAccessControl {
    pub allow_access: bool,
}

impl ExtendedOpAccessControl for MockAccessControl {
    fn check_permission(&self, _oid: &str, _user_dn: Option<&str>) -> Result<(), String> {
        if self.allow_access {
            Ok(())
        } else {
            Err("Access denied".to_string())
        }
    }
}

/// Mock metrics for testing
pub struct MockMetrics;

impl ExtendedOpMetrics for MockMetrics {
    fn record_operation_start(&self, _oid: &str) {}
    fn record_operation_complete(&self, _oid: &str, _success: bool, _duration_ms: u64) {}
    fn record_delegation(&self, _oid: &str, _delegate: &str) {}
}

/// Create a test FSM with mock dependencies
fn create_test_fsm() -> ExtendedOpFsmImpl {
    let backend = Box::new(MockBackend);
    let parser = Box::new(MockParser);
    let delegator = Box::new(MockDelegator);
    let access_control = Box::new(MockAccessControl { allow_access: true });
    let metrics = Box::new(MockMetrics);
    
    ExtendedOpFsmImpl::new(backend, parser, delegator, access_control, metrics)
}

#[test]
fn test_extended_op_fsm_creation() {
    let fsm = create_test_fsm();
    assert_eq!(*fsm.current_state(), ExtendedOpState::Parsing);
    assert!(fsm.operation_oid().is_none());
    assert!(fsm.operation_value().is_none());
    assert!(fsm.response_value().is_none());
    assert!(!fsm.requires_delegation());
}

#[test]
fn test_extended_op_fsm_basic_methods() {
    let mut fsm = create_test_fsm();
    
    // Test set_user_dn
    let user_dn = "cn=testuser,dc=example,dc=org".to_string();
    fsm.set_user_dn(user_dn.clone());
    
    // Test current_state
    assert_eq!(*fsm.current_state(), ExtendedOpState::Parsing);
    
    // Test completion status
    assert!(!fsm.is_completed());
    assert!(!fsm.has_error());
    
    // Test parsed_operation
    assert!(fsm.parsed_operation().is_none());
    
    // Test current_delegate
    assert!(fsm.current_delegate().is_none());
}

#[tokio::test]
async fn test_extended_op_fsm_reset() {
    let mut fsm = create_test_fsm();
    
    // Reset should work without error
    let result = fsm.reset().await;
    assert!(result.is_ok());
    
    // Should be back to initial state
    assert_eq!(*fsm.current_state(), ExtendedOpState::Parsing);
    assert!(fsm.operation_oid().is_none());
    assert!(fsm.operation_value().is_none());
    assert!(fsm.response_value().is_none());
}

#[tokio::test]
async fn test_extended_op_fsm_start_operation() {
    let mut fsm = create_test_fsm();
    
    let event = ExtendedOpEvent::StartExtendedOp {
        oid: "1.3.6.1.4.1.4203.1.11.3".to_string(), // WhoAmI OID
        value: None,
    };
    
    let result = fsm.handle_event(event).await;
    assert!(result.is_ok());
    
    // Should transition to Processing state (since no delegation required)
    match fsm.current_state() {
        ExtendedOpState::Processing { operation } => {
            assert_eq!(operation, "1.3.6.1.4.1.4203.1.11.3");
        },
        _ => panic!("Expected Processing state, got {:?}", fsm.current_state()),
    }
    
    assert_eq!(fsm.operation_oid(), Some("1.3.6.1.4.1.4203.1.11.3"));
    assert!(fsm.parsed_operation().is_some());
}

#[tokio::test]
async fn test_extended_op_fsm_access_denied() {
    let backend = Box::new(MockBackend);
    let parser = Box::new(MockParser);
    let delegator = Box::new(MockDelegator);
    let access_control = Box::new(MockAccessControl { allow_access: false });
    let metrics = Box::new(MockMetrics);
    
    let mut fsm = ExtendedOpFsmImpl::new(backend, parser, delegator, access_control, metrics);
    
    let event = ExtendedOpEvent::StartExtendedOp {
        oid: "1.3.6.1.4.1.4203.1.11.3".to_string(),
        value: None,
    };
    
    let result = fsm.handle_event(event).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Access denied"));
}

#[tokio::test]
async fn test_extended_op_fsm_error_handling() {
    let mut fsm = create_test_fsm();
    
    let error_event = ExtendedOpEvent::Error("Test error message".to_string());
    let result = fsm.handle_event(error_event).await;
    
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Test error message"));
    
    // Should transition to Completed state with error
    match fsm.current_state() {
        ExtendedOpState::Completed { result_code } => {
            assert_eq!(*result_code, ExtendedOpResultCode::ProtocolError);
        },
        _ => panic!("Expected Completed state with error"),
    }
    
    assert!(!fsm.is_completed());
    assert!(fsm.has_error());
}

#[test]
fn test_extended_operation_types() {
    let start_tls = ExtendedOperationType::StartTLS;
    let password_modify = ExtendedOperationType::PasswordModify;
    let who_am_i = ExtendedOperationType::WhoAmI;
    let cancel = ExtendedOperationType::Cancel;
    let modify_password = ExtendedOperationType::ModifyPassword;
    let custom = ExtendedOperationType::Custom("test_op".to_string());
    
    // Test equality
    assert_eq!(start_tls, ExtendedOperationType::StartTLS);
    assert_eq!(password_modify, ExtendedOperationType::PasswordModify);
    assert_eq!(who_am_i, ExtendedOperationType::WhoAmI);
    assert_eq!(cancel, ExtendedOperationType::Cancel);
    assert_eq!(modify_password, ExtendedOperationType::ModifyPassword);
    assert_eq!(custom, ExtendedOperationType::Custom("test_op".to_string()));
    
    // Test inequality
    assert_ne!(start_tls, password_modify);
    assert_ne!(who_am_i, cancel);
}

#[test]
fn test_parsed_operation_creation() {
    let mut parameters = HashMap::new();
    parameters.insert("test_param".to_string(), b"test_value".to_vec());
    
    let parsed_op = ParsedOperation {
        oid: "1.2.3.4.5.6".to_string(),
        operation_type: ExtendedOperationType::Custom("test_operation".to_string()),
        parameters: parameters.clone(),
        requires_delegation: true,
    };
    
    assert_eq!(parsed_op.oid, "1.2.3.4.5.6");
    assert_eq!(parsed_op.operation_type, ExtendedOperationType::Custom("test_operation".to_string()));
    assert_eq!(parsed_op.parameters, parameters);
    assert!(parsed_op.requires_delegation);
}

#[test]
fn test_extended_op_error() {
    let error = ExtendedOpError::from("Test error message");
    
    // Test Display implementation
    assert_eq!(format!("{}", error), "Extended operation error: Test error message");
    
    // Test contains method
    assert!(error.contains("Test error"));
    assert!(error.contains("message"));
    assert!(!error.contains("different"));
    
    // Test PartialEq implementation
    assert_eq!(error, "Test error message");
    assert_ne!(error, "Different message");
}
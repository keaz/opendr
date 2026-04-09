//! Integration tests for Write FSM schema validation
//!
//! Tests that schema validation is actually called during write operations

use async_trait::async_trait;
use opendr::fsm::{StateMachine, WriteEvent, WriteOperation, WriteResultCode, WriteState};
use opendr::write_fsm::{
    AciChecker, Modification, SchemaValidator, WriteBackend, WriteEntry, WriteFsmConfig,
    WriteFsmImpl,
};
use std::sync::{Arc, Mutex};

/// Mock write backend for testing
#[derive(Debug)]
pub struct MockWriteBackend;

#[async_trait]
impl WriteBackend for MockWriteBackend {
    async fn begin_transaction(&self) -> Result<String, String> {
        Ok("txn-1".to_string())
    }

    async fn commit_transaction(&self, _txn_id: &str) -> Result<(), String> {
        Ok(())
    }

    async fn rollback_transaction(&self, _txn_id: &str, _reason: &str) -> Result<(), String> {
        Ok(())
    }

    async fn validate_entry(&self, _dn: &str, _entry: &[u8]) -> Result<(), String> {
        Ok(())
    }

    async fn add_entry(&self, _txn_id: &str, _dn: &str, _entry: &[u8]) -> Result<(), String> {
        Ok(())
    }

    async fn modify_entry(
        &self,
        _txn_id: &str,
        _dn: &str,
        _modifications: &[Modification],
    ) -> Result<(), String> {
        Ok(())
    }

    async fn modify_dn(
        &self,
        _txn_id: &str,
        _dn: &str,
        _new_rdn: &str,
        _delete_old: bool,
        _new_superior: Option<&str>,
    ) -> Result<(), String> {
        Ok(())
    }

    async fn delete_entry(&self, _txn_id: &str, _dn: &str) -> Result<(), String> {
        Ok(())
    }

    async fn entry_exists(&self, _dn: &str) -> Result<bool, String> {
        Ok(false)
    }
}

/// Mock schema validator that tracks calls
#[derive(Debug)]
pub struct TrackingSchemaValidator {
    pub validate_entry_calls: Arc<Mutex<Vec<String>>>,
    pub validate_modifications_calls: Arc<Mutex<Vec<String>>>,
    pub validate_dn_modification_calls: Arc<Mutex<Vec<String>>>,
    pub should_fail: bool,
}

impl TrackingSchemaValidator {
    pub fn new() -> Self {
        Self {
            validate_entry_calls: Arc::new(Mutex::new(Vec::new())),
            validate_modifications_calls: Arc::new(Mutex::new(Vec::new())),
            validate_dn_modification_calls: Arc::new(Mutex::new(Vec::new())),
            should_fail: false,
        }
    }

    pub fn with_failure() -> Self {
        Self {
            validate_entry_calls: Arc::new(Mutex::new(Vec::new())),
            validate_modifications_calls: Arc::new(Mutex::new(Vec::new())),
            validate_dn_modification_calls: Arc::new(Mutex::new(Vec::new())),
            should_fail: true,
        }
    }

    pub fn entry_calls(&self) -> Vec<String> {
        self.validate_entry_calls.lock().unwrap().clone()
    }

    pub fn modification_calls(&self) -> Vec<String> {
        self.validate_modifications_calls.lock().unwrap().clone()
    }

    pub fn dn_modification_calls(&self) -> Vec<String> {
        self.validate_dn_modification_calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl SchemaValidator for TrackingSchemaValidator {
    async fn validate_entry(&self, entry: &WriteEntry) -> Result<(), String> {
        self.validate_entry_calls
            .lock()
            .unwrap()
            .push(entry.dn.clone());

        if self.should_fail {
            return Err(format!("Schema validation failed for: {}", entry.dn));
        }

        Ok(())
    }

    async fn validate_modifications(
        &self,
        dn: &str,
        _modifications: &[Modification],
    ) -> Result<(), String> {
        self.validate_modifications_calls
            .lock()
            .unwrap()
            .push(dn.to_string());

        if self.should_fail {
            return Err(format!("Modification validation failed for: {}", dn));
        }

        Ok(())
    }

    async fn validate_dn_modification(
        &self,
        dn: &str,
        _new_rdn: &str,
        _new_superior: Option<&str>,
    ) -> Result<(), String> {
        self.validate_dn_modification_calls
            .lock()
            .unwrap()
            .push(dn.to_string());

        if self.should_fail {
            return Err(format!("DN modification validation failed for: {}", dn));
        }

        Ok(())
    }

    fn is_object_class_defined(&self, _object_class: &str) -> bool {
        true
    }
}

/// Mock ACI checker for testing
#[derive(Debug)]
pub struct MockAciChecker;

#[async_trait]
impl AciChecker for MockAciChecker {
    async fn check_write_permission(
        &self,
        _user_dn: Option<&str>,
        _operation: &WriteOperation,
    ) -> Result<(), String> {
        Ok(())
    }
}

#[tokio::test]
async fn test_schema_validation_is_called_for_add() {
    let backend = Box::new(MockWriteBackend);
    let schema_validator = Box::new(TrackingSchemaValidator::new());
    let validator_clone = schema_validator.validate_entry_calls.clone();
    let aci_checker = Box::new(MockAciChecker);

    let mut fsm = WriteFsmImpl::new(backend, schema_validator, aci_checker);

    let entry = b"dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\nsn: user\n";

    // Start write operation
    let _result = fsm
        .handle_event(WriteEvent::StartWrite(WriteOperation::Add {
            dn: "cn=test,dc=example,dc=com".to_string(),
            entry: entry.to_vec(),
        }))
        .await
        .unwrap();

    // Handle validation complete - this should trigger schema validation
    let result = fsm.handle_event(WriteEvent::ValidationComplete).await;

    // Verify schema validation was called
    let calls = validator_clone.lock().unwrap();
    assert!(result.is_ok(), "Validation should succeed");
    assert_eq!(calls.len(), 1, "Schema validator should be called once");
    assert_eq!(calls[0], "cn=test,dc=example,dc=com");
}

#[tokio::test]
async fn test_schema_validation_failure_for_add() {
    let backend = Box::new(MockWriteBackend);
    let schema_validator = Box::new(TrackingSchemaValidator::with_failure());
    let validator_clone = schema_validator.validate_entry_calls.clone();
    let aci_checker = Box::new(MockAciChecker);

    let mut fsm = WriteFsmImpl::new(backend, schema_validator, aci_checker);

    let entry = b"dn: cn=test,dc=example,dc=com\nobjectClass: invalidClass\n";

    // Start write operation
    let _result = fsm
        .handle_event(WriteEvent::StartWrite(WriteOperation::Add {
            dn: "cn=test,dc=example,dc=com".to_string(),
            entry: entry.to_vec(),
        }))
        .await
        .unwrap();

    // Handle validation complete - this should trigger schema validation and fail
    let result = fsm.handle_event(WriteEvent::ValidationComplete).await;

    // Verify schema validation was called and failed
    let calls = validator_clone.lock().unwrap();
    assert!(result.is_err(), "Validation should fail");
    assert_eq!(calls.len(), 1, "Schema validator should be called once");
    assert!(matches!(fsm.current_state(), WriteState::Failed { .. }));
}

#[tokio::test]
async fn test_schema_validation_is_called_for_modify() {
    let backend = Box::new(MockWriteBackend);
    let schema_validator = Box::new(TrackingSchemaValidator::new());
    let validator_clone = schema_validator.validate_modifications_calls.clone();
    let aci_checker = Box::new(MockAciChecker);

    let mut fsm = WriteFsmImpl::new(backend, schema_validator, aci_checker);

    let modifications = b"add: mail\nmail: test@example.com\n";

    // Start modify operation
    let _result = fsm
        .handle_event(WriteEvent::StartWrite(WriteOperation::Modify {
            dn: "cn=test,dc=example,dc=com".to_string(),
            changes: modifications.to_vec(),
        }))
        .await
        .unwrap();

    // Handle validation complete - this should trigger schema validation
    let result = fsm.handle_event(WriteEvent::ValidationComplete).await;

    // Verify schema validation was called
    let calls = validator_clone.lock().unwrap();
    assert!(result.is_ok(), "Validation should succeed");
    assert_eq!(calls.len(), 1, "Schema validator should be called once");
    assert_eq!(calls[0], "cn=test,dc=example,dc=com");
}

#[tokio::test]
async fn test_schema_validation_is_called_for_modifydn() {
    let backend = Box::new(MockWriteBackend);
    let schema_validator = Box::new(TrackingSchemaValidator::new());
    let validator_clone = schema_validator.validate_dn_modification_calls.clone();
    let aci_checker = Box::new(MockAciChecker);

    let mut fsm = WriteFsmImpl::new(backend, schema_validator, aci_checker);

    // Start modifydn operation
    let _result = fsm
        .handle_event(WriteEvent::StartWrite(WriteOperation::ModifyDn {
            dn: "cn=test,dc=example,dc=com".to_string(),
            new_rdn: "cn=newtest".to_string(),
            delete_old: true,
            new_superior: None,
        }))
        .await
        .unwrap();

    // Handle validation complete - this should trigger schema validation
    let result = fsm.handle_event(WriteEvent::ValidationComplete).await;

    // Verify schema validation was called
    let calls = validator_clone.lock().unwrap();
    assert!(result.is_ok(), "Validation should succeed");
    assert_eq!(calls.len(), 1, "Schema validator should be called once");
    assert_eq!(calls[0], "cn=test,dc=example,dc=com");
}

#[tokio::test]
async fn test_schema_validation_skipped_when_disabled() {
    let backend = Box::new(MockWriteBackend);
    let schema_validator = Box::new(TrackingSchemaValidator::new());
    let validator_clone = schema_validator.validate_entry_calls.clone();
    let aci_checker = Box::new(MockAciChecker);

    let config = WriteFsmConfig {
        strict_schema_validation: false, // Disable schema validation
        enable_aci_checks: false,
        ..Default::default()
    };

    let mut fsm = WriteFsmImpl::with_config(backend, schema_validator, aci_checker, config);

    let entry = b"dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\nsn: user\n";

    // Start write operation
    let _result = fsm
        .handle_event(WriteEvent::StartWrite(WriteOperation::Add {
            dn: "cn=test,dc=example,dc=com".to_string(),
            entry: entry.to_vec(),
        }))
        .await
        .unwrap();

    // Handle validation complete - schema validation should be skipped
    let _result = fsm.handle_event(WriteEvent::ValidationComplete).await;

    // Verify schema validation was NOT called
    let calls = validator_clone.lock().unwrap();
    assert_eq!(
        calls.len(),
        0,
        "Schema validator should NOT be called when disabled"
    );
    assert_eq!(
        fsm.current_state(),
        &WriteState::Completed {
            result_code: WriteResultCode::Success,
        }
    );
}

#[tokio::test]
async fn test_schema_validation_with_real_ldap_schema_validator() {
    use opendr::schema_adapter::LdapSchemaValidator;

    let backend = Box::new(MockWriteBackend);
    let schema_validator: Box<dyn SchemaValidator> = Box::new(LdapSchemaValidator::new());
    let aci_checker = Box::new(MockAciChecker);

    let mut fsm = WriteFsmImpl::new(backend, schema_validator, aci_checker);

    // Valid person entry
    let entry = b"dn: cn=John Doe,dc=example,dc=com\nobjectClass: top\nobjectClass: person\ncn: John Doe\nsn: Doe\n";

    // Start write operation
    let _result = fsm
        .handle_event(WriteEvent::StartWrite(WriteOperation::Add {
            dn: "cn=John Doe,dc=example,dc=com".to_string(),
            entry: entry.to_vec(),
        }))
        .await
        .unwrap();

    // Handle validation complete - should pass with real schema
    let result = fsm.handle_event(WriteEvent::ValidationComplete).await;

    assert!(result.is_ok(), "Valid person entry should pass validation");
}

#[tokio::test]
async fn test_schema_validation_with_real_ldap_schema_validator_failure() {
    use opendr::schema_adapter::LdapSchemaValidator;

    let backend = Box::new(MockWriteBackend);
    let schema_validator: Box<dyn SchemaValidator> = Box::new(LdapSchemaValidator::new());
    let aci_checker = Box::new(MockAciChecker);

    let mut fsm = WriteFsmImpl::new(backend, schema_validator, aci_checker);

    // Invalid entry - missing required attribute 'sn'
    let entry =
        b"dn: cn=John Doe,dc=example,dc=com\nobjectClass: top\nobjectClass: person\ncn: John Doe\n";

    // Start write operation
    let _result = fsm
        .handle_event(WriteEvent::StartWrite(WriteOperation::Add {
            dn: "cn=John Doe,dc=example,dc=com".to_string(),
            entry: entry.to_vec(),
        }))
        .await
        .unwrap();

    // Handle validation complete - should fail due to missing 'sn'
    let result = fsm.handle_event(WriteEvent::ValidationComplete).await;

    assert!(
        result.is_err(),
        "Entry missing required 'sn' should fail validation"
    );
    assert!(matches!(fsm.current_state(), WriteState::Failed { .. }));
}

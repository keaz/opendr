//! Integration Tests for Security Features
//!
//! This module contains comprehensive integration tests for:
//! - TLS/StartTLS support
//! - SASL authentication mechanisms
//! - Extended operations
//! - Access Control Information (ACI) system

use async_trait::async_trait;
use opendr::aci::{AciEngine, AciRuleBuilder, Permission};
use opendr::backend::{DirectoryBackend, DirectoryEntry, MockBackend};
use opendr::connection_fsm::{ConnectionFsmImpl, TlsHandler};
use opendr::extended_op_fsm::{ExtendedOpBackend, ExtendedOpMetrics, ExtendedOpParser};
use opendr::extended_ops::{
    encode_password_modify_request_value, oids, ExtendedOpMetricsCollector, OperationCanceller,
    PasswordModifier, PasswordModifyRequest, StandardExtendedOpBackend, StandardExtendedOpParser,
};
use opendr::fsm::{ConnectionEvent, ConnectionState, SaslEvent, SaslFsm, StateMachine};
use opendr::sasl_fsm::{CredentialVerifier, SaslFsmImpl, SaslMechanismHandler};
use opendr::sasl_mechanisms::MultiMechanismHandler;
use opendr::tls::{RustlsTlsHandler, TlsConfig, TlsVersion};
use std::collections::HashMap;
use std::sync::Arc;

// ========================================================================
// TLS Integration Tests
// ========================================================================

#[tokio::test]
async fn test_tls_handler_creation() {
    // Test TLS handler creation for testing
    let result = RustlsTlsHandler::new_test();
    assert!(result.is_ok());

    let handler = result.unwrap();
    assert!(handler.supports_tls());
    assert_eq!(handler.protocol_version(), "TLSv1.3");
}

#[tokio::test]
async fn test_connection_fsm_with_tls() {
    let tls_handler = Box::new(RustlsTlsHandler::new_test().unwrap());
    let mut fsm = ConnectionFsmImpl::new("127.0.0.1:1389", tls_handler);

    // Establish connection
    let result = fsm
        .handle_event(ConnectionEvent::ConnectionEstablished)
        .await;
    assert!(result.is_ok());
    assert_eq!(fsm.current_state(), &ConnectionState::Connected);

    // Note: StartTLS would require a real TcpStream
    // This demonstrates the FSM structure is correct
}

#[tokio::test]
async fn test_tls_config_defaults() {
    let config = TlsConfig::default();
    assert_eq!(config.min_tls_version, TlsVersion::Tls12);
    assert_eq!(config.max_tls_version, TlsVersion::Tls13);
    assert!(!config.require_client_cert);
}

// ========================================================================
// SASL Mechanism Integration Tests
// ========================================================================

struct TestCredentialVerifier {
    valid_users: Vec<(String, String)>, // (username, dn)
}

impl TestCredentialVerifier {
    fn new() -> Self {
        Self {
            valid_users: vec![
                (
                    "alice".to_string(),
                    "cn=alice,dc=example,dc=org".to_string(),
                ),
                ("bob".to_string(), "cn=bob,dc=example,dc=org".to_string()),
                (
                    "admin".to_string(),
                    "cn=admin,dc=example,dc=org".to_string(),
                ),
            ],
        }
    }
}

#[async_trait]
impl CredentialVerifier for TestCredentialVerifier {
    async fn verify_credentials(&self, _mechanism: &str, identity: &str) -> Result<bool, String> {
        Ok(self.valid_users.iter().any(|(user, _)| user == identity))
    }

    async fn get_user_dn(&self, identity: &str) -> Result<Option<String>, String> {
        Ok(self
            .valid_users
            .iter()
            .find(|(user, _)| user == identity)
            .map(|(_, dn)| dn.clone()))
    }
}

#[tokio::test]
async fn test_sasl_plain_authentication_success() {
    let verifier_arc = Arc::new(TestCredentialVerifier::new());
    let mechanism_handler = Box::new(MultiMechanismHandler::new(verifier_arc.clone()));
    let verifier_box: Box<dyn CredentialVerifier> = Box::new(TestCredentialVerifier::new());
    let mut fsm = SaslFsmImpl::new(mechanism_handler, verifier_box);

    // Authenticate with PLAIN mechanism
    let credentials = b"\0alice\0password";
    let result = fsm
        .handle_event(SaslEvent::InitiateBind {
            mechanism: "PLAIN".to_string(),
            initial_data: Some(credentials.to_vec()),
        })
        .await;

    assert!(result.is_ok());
    assert!(fsm.is_terminal());
    assert_eq!(
        fsm.authenticated_identity(),
        Some("cn=alice,dc=example,dc=org")
    );
}

#[tokio::test]
async fn test_sasl_plain_authentication_failure() {
    let verifier_arc = Arc::new(TestCredentialVerifier::new());
    let mechanism_handler = Box::new(MultiMechanismHandler::new(verifier_arc.clone()));
    let verifier_box: Box<dyn CredentialVerifier> = Box::new(TestCredentialVerifier::new());
    let mut fsm = SaslFsmImpl::new(mechanism_handler, verifier_box);

    // Authenticate with invalid user
    let credentials = b"\0invalid\0password";
    let result = fsm
        .handle_event(SaslEvent::InitiateBind {
            mechanism: "PLAIN".to_string(),
            initial_data: Some(credentials.to_vec()),
        })
        .await;

    assert!(result.is_err());
    assert!(fsm.is_terminal());
    assert_eq!(fsm.authenticated_identity(), None);
}

#[tokio::test]
async fn test_sasl_digest_md5_authentication() {
    let verifier_arc = Arc::new(TestCredentialVerifier::new());
    let mechanism_handler = Box::new(MultiMechanismHandler::new(verifier_arc.clone()));
    let verifier_box: Box<dyn CredentialVerifier> = Box::new(TestCredentialVerifier::new());
    let mut fsm = SaslFsmImpl::new(mechanism_handler, verifier_box);

    // Initiate DIGEST-MD5 authentication
    let result = fsm
        .handle_event(SaslEvent::InitiateBind {
            mechanism: "DIGEST-MD5".to_string(),
            initial_data: None,
        })
        .await;

    assert!(result.is_ok());
    assert!(fsm.needs_more_steps());

    // Verify challenge was generated
    let challenge_data = result.unwrap();
    assert!(challenge_data.is_some());

    let challenge = String::from_utf8(challenge_data.unwrap()).unwrap();
    assert!(challenge.contains("realm="));
    assert!(challenge.contains("nonce="));
    assert!(challenge.contains("qop="));
}

#[tokio::test]
async fn test_sasl_multiple_mechanisms() {
    let verifier = Arc::new(TestCredentialVerifier::new());
    let mechanism_handler = Box::new(MultiMechanismHandler::new(verifier.clone()));

    // Test supported mechanisms
    assert!(mechanism_handler.supports_mechanism("PLAIN").await);
    assert!(mechanism_handler.supports_mechanism("DIGEST-MD5").await);
    assert!(mechanism_handler.supports_mechanism("CRAM-MD5").await);
    assert!(!mechanism_handler.supports_mechanism("GSSAPI").await);
}

#[tokio::test]
async fn test_sasl_mechanism_properties() {
    let verifier = Arc::new(TestCredentialVerifier::new());
    let mechanism_handler = MultiMechanismHandler::new(verifier);

    let plain_props = mechanism_handler.get_mechanism_properties("PLAIN");
    assert_eq!(plain_props.get("steps"), Some(&"1".to_string()));
    assert_eq!(
        plain_props.get("security"),
        Some(&"requires-tls".to_string())
    );

    let digest_props = mechanism_handler.get_mechanism_properties("DIGEST-MD5");
    assert_eq!(digest_props.get("steps"), Some(&"2".to_string()));
    assert_eq!(
        digest_props.get("security"),
        Some(&"hash-based".to_string())
    );
}

// ========================================================================
// Extended Operations Integration Tests
// ========================================================================

struct TestPasswordModifier;

#[async_trait]
impl PasswordModifier for TestPasswordModifier {
    async fn modify_password(
        &self,
        user_dn: &str,
        _old_password: Option<&str>,
        _new_password: &str,
    ) -> Result<(), String> {
        if user_dn.contains("alice") || user_dn.contains("bob") {
            Ok(())
        } else {
            Err("User not found".to_string())
        }
    }
}

struct TestOperationCanceller;

#[async_trait]
impl OperationCanceller for TestOperationCanceller {
    async fn cancel_operation(&self, message_id: i32) -> Result<(), String> {
        if message_id > 0 && message_id < 1000 {
            Ok(())
        } else {
            Err("Invalid message ID".to_string())
        }
    }
}

#[tokio::test]
async fn test_extended_op_start_tls() {
    let backend = StandardExtendedOpBackend::new(
        Arc::new(TestPasswordModifier),
        Arc::new(TestOperationCanceller),
    );

    assert!(backend.is_operation_supported(oids::START_TLS));
    assert!(backend.requires_delegation(oids::START_TLS));

    let result = backend.execute_operation(oids::START_TLS, None).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_extended_op_password_modify() {
    let backend = StandardExtendedOpBackend::new(
        Arc::new(TestPasswordModifier),
        Arc::new(TestOperationCanceller),
    );

    let request = encode_password_modify_request_value(&PasswordModifyRequest {
        user_identity: Some("cn=alice,dc=example,dc=org".to_string()),
        old_password: Some(b"old123".to_vec()),
        new_password: Some(b"new456".to_vec()),
    })
    .unwrap()
    .unwrap();
    let result = backend
        .execute_operation(oids::PASSWORD_MODIFY, Some(&request))
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_extended_op_who_am_i() {
    let backend = StandardExtendedOpBackend::new(
        Arc::new(TestPasswordModifier),
        Arc::new(TestOperationCanceller),
    );

    let result = backend.execute_operation(oids::WHO_AM_I, None).await;
    assert!(result.is_ok());

    let response = String::from_utf8(result.unwrap()).unwrap();
    assert_eq!(response, "anonymous");
}

#[tokio::test]
async fn test_extended_op_cancel() {
    let backend = StandardExtendedOpBackend::new(
        Arc::new(TestPasswordModifier),
        Arc::new(TestOperationCanceller),
    );

    let message_id = b"42";
    let result = backend
        .execute_operation(oids::CANCEL, Some(message_id))
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_extended_op_parser() {
    let parser = StandardExtendedOpParser::new();

    // Test StartTLS parsing
    let result = parser.parse_request(oids::START_TLS, None);
    assert!(result.is_ok());
    let parsed = result.unwrap();
    assert!(parsed.requires_delegation);

    // Test Password Modify parsing
    let value = b"test data";
    let result = parser.parse_request(oids::PASSWORD_MODIFY, Some(value));
    assert!(result.is_ok());
    let parsed = result.unwrap();
    assert!(!parsed.requires_delegation);

    // Validate operation
    assert!(parser.validate_operation(&parsed).is_ok());
}

#[tokio::test]
async fn test_extended_op_metrics() {
    let metrics = ExtendedOpMetricsCollector::new();

    metrics.record_operation_start(oids::PASSWORD_MODIFY);
    metrics.record_operation_complete(oids::PASSWORD_MODIFY, true, 100);
    metrics.record_operation_complete(oids::WHO_AM_I, false, 50);
    metrics.record_delegation(oids::START_TLS, "tls-handler");

    let (starts, successes, failures, delegations) = metrics.stats();
    assert_eq!(starts, 1);
    assert_eq!(successes, 1);
    assert_eq!(failures, 1);
    assert_eq!(delegations, 1);
}

// ========================================================================
// ACI System Integration Tests
// ========================================================================

#[tokio::test]
async fn test_aci_basic_access_control() {
    let engine = AciEngine::restrictive();

    // Add rule: Allow alice to read entries under dc=example,dc=org
    let rule = AciRuleBuilder::grant("alice-read")
        .target_subtree("dc=example,dc=org")
        .permissions(vec![Permission::Read, Permission::Search])
        .subject_user("cn=alice,dc=example,dc=org")
        .build()
        .unwrap();

    engine.add_rule(rule).await;

    // Alice should be allowed to read
    let result = engine
        .check_permission(
            Some("cn=alice,dc=example,dc=org"),
            "cn=bob,dc=example,dc=org",
            None,
            Permission::Read,
        )
        .await;
    assert!(result.is_ok());

    // Bob should be denied
    let result = engine
        .check_permission(
            Some("cn=bob,dc=example,dc=org"),
            "cn=alice,dc=example,dc=org",
            None,
            Permission::Read,
        )
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_aci_group_grant_with_backend_lookup() {
    let engine = AciEngine::restrictive();
    let backend = MockBackend::new();
    backend
        .add_entry(
            DirectoryEntry::new(
                "cn=admins,dc=example,dc=org",
                HashMap::from([
                    (
                        "member".to_string(),
                        vec!["cn=alice,dc=example,dc=org".to_string()],
                    ),
                    ("objectclass".to_string(), vec!["groupOfNames".to_string()]),
                ]),
            ),
            Vec::new(),
        )
        .await
        .unwrap();

    let rule = AciRuleBuilder::grant("admins-read")
        .target_subtree("dc=example,dc=org")
        .permission(Permission::Read)
        .subject_group("cn=admins,dc=example,dc=org")
        .build()
        .unwrap();
    engine.add_rule(rule).await;

    let allowed = engine
        .check_permission_with_backend(
            Some("cn=alice,dc=example,dc=org"),
            "cn=bob,dc=example,dc=org",
            None,
            Permission::Read,
            &backend,
        )
        .await;
    assert!(allowed.is_ok());

    let denied = engine
        .check_permission_with_backend(
            Some("cn=bob,dc=example,dc=org"),
            "cn=alice,dc=example,dc=org",
            None,
            Permission::Read,
            &backend,
        )
        .await;
    assert!(denied.is_err());
}

#[tokio::test]
async fn test_aci_group_deny_with_backend_lookup() {
    let engine = AciEngine::permissive();
    let backend = MockBackend::new();
    backend
        .add_entry(
            DirectoryEntry::new(
                "cn=blocked,dc=example,dc=org",
                HashMap::from([
                    (
                        "uniquemember".to_string(),
                        vec!["cn=alice,dc=example,dc=org".to_string()],
                    ),
                    ("objectclass".to_string(), vec!["groupOfNames".to_string()]),
                ]),
            ),
            Vec::new(),
        )
        .await
        .unwrap();

    let rule = AciRuleBuilder::deny("blocked-delete")
        .target_subtree("dc=example,dc=org")
        .permission(Permission::Delete)
        .subject_group("cn=blocked,dc=example,dc=org")
        .build()
        .unwrap();
    engine.add_rule(rule).await;

    let denied = engine
        .check_permission_with_backend(
            Some("cn=alice,dc=example,dc=org"),
            "cn=bob,dc=example,dc=org",
            None,
            Permission::Delete,
            &backend,
        )
        .await;
    assert!(denied.is_err());

    let allowed = engine
        .check_permission_with_backend(
            Some("cn=bob,dc=example,dc=org"),
            "cn=alice,dc=example,dc=org",
            None,
            Permission::Delete,
            &backend,
        )
        .await;
    assert!(allowed.is_ok());
}

#[tokio::test]
async fn test_aci_self_entry_access() {
    let engine = AciEngine::restrictive();

    // Add rule: Users can modify their own entry
    let rule = AciRuleBuilder::grant("self-modify")
        .target_subtree("dc=example,dc=org")
        .permissions(vec![Permission::Modify, Permission::Read])
        .subject_self()
        .build()
        .unwrap();

    engine.add_rule(rule).await;

    // Alice can modify her own entry
    let result = engine
        .check_permission(
            Some("cn=alice,dc=example,dc=org"),
            "cn=alice,dc=example,dc=org",
            None,
            Permission::Modify,
        )
        .await;
    assert!(result.is_ok());

    // Alice cannot modify Bob's entry
    let result = engine
        .check_permission(
            Some("cn=alice,dc=example,dc=org"),
            "cn=bob,dc=example,dc=org",
            None,
            Permission::Modify,
        )
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_aci_all_authenticated_access() {
    let engine = AciEngine::restrictive();

    // Add rule: All authenticated users can search
    let rule = AciRuleBuilder::grant("all-auth-search")
        .target_subtree("dc=example,dc=org")
        .permission(Permission::Search)
        .subject_all_authenticated()
        .build()
        .unwrap();

    engine.add_rule(rule).await;

    // Any authenticated user can search
    let result = engine
        .check_permission(
            Some("cn=alice,dc=example,dc=org"),
            "cn=bob,dc=example,dc=org",
            None,
            Permission::Search,
        )
        .await;
    assert!(result.is_ok());

    // Anonymous cannot search
    let result = engine
        .check_permission(None, "cn=bob,dc=example,dc=org", None, Permission::Search)
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_aci_attribute_level_access() {
    let engine = AciEngine::restrictive();

    // Add rule: Users can read cn and sn attributes only
    let rule = AciRuleBuilder::grant("read-public-attrs")
        .target_attributes(vec!["cn".to_string(), "sn".to_string()])
        .permission(Permission::Read)
        .subject_all_authenticated()
        .build()
        .unwrap();

    engine.add_rule(rule).await;

    // Can read cn attribute
    let result = engine
        .check_permission(
            Some("cn=alice,dc=example,dc=org"),
            "cn=bob,dc=example,dc=org",
            Some("cn"),
            Permission::Read,
        )
        .await;
    assert!(result.is_ok());

    // Cannot read mail attribute (not in allowed list)
    let result = engine
        .check_permission(
            Some("cn=alice,dc=example,dc=org"),
            "cn=bob,dc=example,dc=org",
            Some("mail"),
            Permission::Read,
        )
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_aci_deny_rules() {
    let engine = AciEngine::permissive();

    // Add rule: Deny alice from deleting entries
    let rule = AciRuleBuilder::deny("alice-no-delete")
        .target_subtree("dc=example,dc=org")
        .permission(Permission::Delete)
        .subject_user("cn=alice,dc=example,dc=org")
        .build()
        .unwrap();

    engine.add_rule(rule).await;

    // Alice cannot delete
    let result = engine
        .check_permission(
            Some("cn=alice,dc=example,dc=org"),
            "cn=bob,dc=example,dc=org",
            None,
            Permission::Delete,
        )
        .await;
    assert!(result.is_err());

    // Alice can still read (permissive default)
    let result = engine
        .check_permission(
            Some("cn=alice,dc=example,dc=org"),
            "cn=bob,dc=example,dc=org",
            None,
            Permission::Read,
        )
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_aci_priority_resolution() {
    let engine = AciEngine::restrictive();

    // High priority: Deny alice write
    let deny_rule = AciRuleBuilder::deny("deny-alice-write")
        .target_subtree("dc=example,dc=org")
        .permission(Permission::Write)
        .subject_user("cn=alice,dc=example,dc=org")
        .priority(100)
        .build()
        .unwrap();

    // Low priority: Grant alice write
    let grant_rule = AciRuleBuilder::grant("grant-alice-write")
        .target_subtree("dc=example,dc=org")
        .permission(Permission::Write)
        .subject_user("cn=alice,dc=example,dc=org")
        .priority(10)
        .build()
        .unwrap();

    engine.add_rule(grant_rule).await;
    engine.add_rule(deny_rule).await;

    // Deny should win due to higher priority
    let result = engine
        .check_permission(
            Some("cn=alice,dc=example,dc=org"),
            "cn=bob,dc=example,dc=org",
            None,
            Permission::Write,
        )
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_aci_rule_management() {
    let engine = AciEngine::restrictive();

    // Add multiple rules
    let rule1 = AciRuleBuilder::grant("rule1")
        .target_subtree("dc=example,dc=org")
        .permission(Permission::Read)
        .subject_all_authenticated()
        .build()
        .unwrap();

    let rule2 = AciRuleBuilder::grant("rule2")
        .target_subtree("dc=example,dc=org")
        .permission(Permission::Search)
        .subject_all_authenticated()
        .build()
        .unwrap();

    engine.add_rule(rule1).await;
    engine.add_rule(rule2).await;

    assert_eq!(engine.get_rules().await.len(), 2);

    // Remove one rule
    let removed = engine.remove_rule("rule1").await;
    assert!(removed);
    assert_eq!(engine.get_rules().await.len(), 1);

    // Clear all rules
    engine.clear_rules().await;
    assert_eq!(engine.get_rules().await.len(), 0);
}

#[tokio::test]
async fn test_aci_multiple_permissions_check() {
    let engine = AciEngine::restrictive();

    let rule = AciRuleBuilder::grant("multi-perm")
        .target_subtree("dc=example,dc=org")
        .permissions(vec![
            Permission::Read,
            Permission::Search,
            Permission::Compare,
        ])
        .subject_all_authenticated()
        .build()
        .unwrap();

    engine.add_rule(rule).await;

    // Check multiple allowed permissions
    let result = engine
        .check_permissions(
            Some("cn=alice,dc=example,dc=org"),
            "cn=bob,dc=example,dc=org",
            None,
            &[Permission::Read, Permission::Search],
        )
        .await;
    assert!(result.is_ok());

    // Check with one disallowed permission
    let result = engine
        .check_permissions(
            Some("cn=alice,dc=example,dc=org"),
            "cn=bob,dc=example,dc=org",
            None,
            &[Permission::Read, Permission::Write],
        )
        .await;
    assert!(result.is_err());
}

// ========================================================================
// Integration Tests: Combined Security Features
// ========================================================================

#[tokio::test]
async fn test_authentication_and_authorization_flow() {
    // Step 1: Authenticate user with SASL
    let verifier_arc = Arc::new(TestCredentialVerifier::new());
    let mechanism_handler = Box::new(MultiMechanismHandler::new(verifier_arc.clone()));
    let verifier_box: Box<dyn CredentialVerifier> = Box::new(TestCredentialVerifier::new());
    let mut sasl_fsm = SaslFsmImpl::new(mechanism_handler, verifier_box);

    let credentials = b"\0alice\0password";
    let result = sasl_fsm
        .handle_event(SaslEvent::InitiateBind {
            mechanism: "PLAIN".to_string(),
            initial_data: Some(credentials.to_vec()),
        })
        .await;

    assert!(result.is_ok());
    let user_dn = sasl_fsm.authenticated_identity();
    assert_eq!(user_dn, Some("cn=alice,dc=example,dc=org"));

    // Step 2: Check authorization with ACI
    let aci_engine = AciEngine::restrictive();

    let rule = AciRuleBuilder::grant("alice-read")
        .target_subtree("dc=example,dc=org")
        .permission(Permission::Read)
        .subject_user("cn=alice,dc=example,dc=org")
        .build()
        .unwrap();

    aci_engine.add_rule(rule).await;

    // Alice can read entries
    let result = aci_engine
        .check_permission(user_dn, "cn=bob,dc=example,dc=org", None, Permission::Read)
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_extended_op_with_access_control() {
    // Create ACI engine with rules
    let aci_engine = AciEngine::restrictive();

    let rule = AciRuleBuilder::grant("alice-modify-password")
        .target_subtree("dc=example,dc=org")
        .permission(Permission::Modify)
        .subject_user("cn=alice,dc=example,dc=org")
        .build()
        .unwrap();

    aci_engine.add_rule(rule).await;

    // Check if alice can modify password
    let result = aci_engine
        .check_permission(
            Some("cn=alice,dc=example,dc=org"),
            "cn=alice,dc=example,dc=org",
            None,
            Permission::Modify,
        )
        .await;
    assert!(result.is_ok());

    // Execute password modify operation
    let backend = StandardExtendedOpBackend::new(
        Arc::new(TestPasswordModifier),
        Arc::new(TestOperationCanceller),
    );

    let request = encode_password_modify_request_value(&PasswordModifyRequest {
        user_identity: Some("cn=alice,dc=example,dc=org".to_string()),
        old_password: Some(b"old123".to_vec()),
        new_password: Some(b"new456".to_vec()),
    })
    .unwrap()
    .unwrap();
    let result = backend
        .execute_operation(oids::PASSWORD_MODIFY, Some(&request))
        .await;
    assert!(result.is_ok());
}

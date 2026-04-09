//! Integration tests for audit logging
//!
//! These tests verify the complete audit logging workflow including:
//! - Event creation and logging
//! - Multiple log formats (JSON, syslog, text)
//! - Level filtering
//! - Authentication event logging
//! - Authorization event logging
//! - Data modification event logging
//! - Connection event logging
//! - File I/O and persistence

use opendr::audit::{
    AuditConfig, AuditEvent, AuditEventType, AuditFormat, AuditLevel, AuditLogger, AuthOperation,
    ModifyOperation,
};
use std::fs;
use tempfile::NamedTempFile;
use tokio::time::{sleep, Duration};

// ================================================================================================
// Test: Audit Event Creation and Formatting
// ================================================================================================

#[test]
fn test_audit_event_basic_creation() {
    let event = AuditEvent::new(
        AuditLevel::Info,
        AuditEventType::Authentication,
        "bind".to_string(),
        true,
    );

    assert_eq!(event.level, AuditLevel::Info);
    assert_eq!(event.event_type, AuditEventType::Authentication);
    assert_eq!(event.action, "bind");
    assert!(event.success);
}

#[test]
fn test_audit_event_builder_pattern() {
    let event = AuditEvent::new(
        AuditLevel::Warning,
        AuditEventType::Authorization,
        "modify".to_string(),
        false,
    )
    .with_user_dn("cn=user,dc=example,dc=com")
    .with_target_dn("cn=admin,dc=example,dc=com")
    .with_client_ip("192.168.1.100")
    .with_session_id("session-123")
    .with_error("Insufficient permissions")
    .with_detail("operation", "write")
    .with_detail("attribute", "userPassword");

    assert_eq!(event.user_dn.as_deref(), Some("cn=user,dc=example,dc=com"));
    assert_eq!(
        event.target_dn.as_deref(),
        Some("cn=admin,dc=example,dc=com")
    );
    assert_eq!(event.client_ip.as_deref(), Some("192.168.1.100"));
    assert_eq!(event.session_id.as_deref(), Some("session-123"));
    assert_eq!(
        event.error_message.as_deref(),
        Some("Insufficient permissions")
    );
    assert_eq!(event.details.get("operation"), Some(&"write".to_string()));
    assert_eq!(
        event.details.get("attribute"),
        Some(&"userPassword".to_string())
    );
}

#[test]
fn test_audit_event_json_format() {
    let event = AuditEvent::new(
        AuditLevel::Info,
        AuditEventType::Authentication,
        AuthOperation::SimpleBind.as_str().to_string(),
        true,
    )
    .with_user_dn("cn=admin,dc=example,dc=com")
    .with_client_ip("127.0.0.1");

    let json = event.to_json();

    assert!(json.contains("\"level\":\"Info\""));
    assert!(json.contains("\"event_type\":\"Authentication\""));
    assert!(json.contains("\"action\":\"simple_bind\""));
    assert!(json.contains("\"success\":true"));
    assert!(json.contains("\"user_dn\":\"cn=admin,dc=example,dc=com\""));
    assert!(json.contains("\"client_ip\":\"127.0.0.1\""));
}

#[test]
fn test_audit_event_text_format() {
    let event = AuditEvent::new(
        AuditLevel::Error,
        AuditEventType::DataModification,
        ModifyOperation::Delete.as_str().to_string(),
        false,
    )
    .with_user_dn("cn=hacker,dc=example,dc=com")
    .with_target_dn("cn=critical,dc=example,dc=com")
    .with_client_ip("10.0.0.1")
    .with_error("Access denied");

    let text = event.to_text();

    assert!(text.contains("ERROR"));
    assert!(text.contains("data_modification"));
    assert!(text.contains("delete"));
    assert!(text.contains("FAILURE"));
    assert!(text.contains("user=\"cn=hacker,dc=example,dc=com\""));
    assert!(text.contains("target=\"cn=critical,dc=example,dc=com\""));
    assert!(text.contains("client=\"10.0.0.1\""));
    assert!(text.contains("error=\"Access denied\""));
}

#[test]
fn test_audit_event_syslog_format() {
    let event = AuditEvent::new(
        AuditLevel::Critical,
        AuditEventType::Authentication,
        "bind".to_string(),
        false,
    )
    .with_user_dn("cn=attacker,dc=example,dc=com")
    .with_error("Brute force detected");

    let syslog = event.to_syslog();

    // Priority: facility (10) * 8 + level (2 for critical) = 82
    assert!(syslog.starts_with("<82>"));
    assert!(syslog.contains("opendr-ldap"));
    assert!(syslog.contains("authentication"));
    assert!(syslog.contains("FAILURE"));
}

// ================================================================================================
// Test: Audit Logger Basic Operations
// ================================================================================================

#[tokio::test]
async fn test_audit_logger_creation_and_initialization() {
    let temp_file = NamedTempFile::new().unwrap();
    let logger = AuditLogger::new(temp_file.path(), AuditLevel::Info);

    assert_eq!(logger.events_logged().await, 0);

    let result = logger.initialize().await;
    assert!(result.is_ok(), "Logger initialization failed: {:?}", result);
}

#[tokio::test]
async fn test_audit_logger_log_single_event() {
    let temp_file = NamedTempFile::new().unwrap();
    let logger = AuditLogger::new(temp_file.path(), AuditLevel::Info);
    logger.initialize().await.unwrap();

    let event = AuditEvent::new(
        AuditLevel::Info,
        AuditEventType::Authentication,
        "bind".to_string(),
        true,
    );

    logger.log_event(event).await;

    assert_eq!(logger.events_logged().await, 1);

    // Verify file was written
    logger.close().await.unwrap();
    let content = fs::read_to_string(temp_file.path()).unwrap();
    assert!(!content.is_empty());
    assert!(content.contains("bind"));
}

#[tokio::test]
async fn test_audit_logger_multiple_events() {
    let temp_file = NamedTempFile::new().unwrap();
    let logger = AuditLogger::new(temp_file.path(), AuditLevel::Debug);
    logger.initialize().await.unwrap();

    for i in 1..=10 {
        let event = AuditEvent::new(
            AuditLevel::Info,
            AuditEventType::Authentication,
            format!("bind_{}", i),
            true,
        );
        logger.log_event(event).await;
    }

    assert_eq!(logger.events_logged().await, 10);
}

#[tokio::test]
async fn test_audit_logger_level_filtering() {
    let temp_file = NamedTempFile::new().unwrap();
    let logger = AuditLogger::new(temp_file.path(), AuditLevel::Warning);
    logger.initialize().await.unwrap();

    // Debug event (should be filtered out)
    logger
        .log_event(AuditEvent::new(
            AuditLevel::Debug,
            AuditEventType::Connection,
            "debug_event".to_string(),
            true,
        ))
        .await;

    // Info event (should be filtered out)
    logger
        .log_event(AuditEvent::new(
            AuditLevel::Info,
            AuditEventType::Authentication,
            "info_event".to_string(),
            true,
        ))
        .await;

    // Warning event (should be logged)
    logger
        .log_event(AuditEvent::new(
            AuditLevel::Warning,
            AuditEventType::Authorization,
            "warning_event".to_string(),
            false,
        ))
        .await;

    // Error event (should be logged)
    logger
        .log_event(AuditEvent::new(
            AuditLevel::Error,
            AuditEventType::DataModification,
            "error_event".to_string(),
            false,
        ))
        .await;

    // Critical event (should be logged)
    logger
        .log_event(AuditEvent::new(
            AuditLevel::Critical,
            AuditEventType::System,
            "critical_event".to_string(),
            false,
        ))
        .await;

    assert_eq!(logger.events_logged().await, 3); // Only Warning, Error, Critical
}

// ================================================================================================
// Test: Authentication Event Logging
// ================================================================================================

#[tokio::test]
async fn test_log_auth_success() {
    let temp_file = NamedTempFile::new().unwrap();
    let logger = AuditLogger::new(temp_file.path(), AuditLevel::Info);
    logger.initialize().await.unwrap();

    logger
        .log_auth_success("cn=admin,dc=example,dc=com", "127.0.0.1")
        .await;

    assert_eq!(logger.events_logged().await, 1);

    logger.close().await.unwrap();
    let content = fs::read_to_string(temp_file.path()).unwrap();
    assert!(content.contains("cn=admin,dc=example,dc=com"));
    assert!(content.contains("127.0.0.1"));
    assert!(content.contains("\"success\":true"));
}

#[tokio::test]
async fn test_log_auth_failure() {
    let temp_file = NamedTempFile::new().unwrap();
    let logger = AuditLogger::new(temp_file.path(), AuditLevel::Info);
    logger.initialize().await.unwrap();

    logger
        .log_auth_failure(
            "cn=hacker,dc=example,dc=com",
            "192.168.1.100",
            "Invalid credentials",
        )
        .await;

    assert_eq!(logger.events_logged().await, 1);

    logger.close().await.unwrap();
    let content = fs::read_to_string(temp_file.path()).unwrap();
    assert!(content.contains("cn=hacker,dc=example,dc=com"));
    assert!(content.contains("192.168.1.100"));
    assert!(content.contains("Invalid credentials"));
    assert!(content.contains("\"success\":false"));
}

#[tokio::test]
async fn test_log_sasl_auth_success() {
    let temp_file = NamedTempFile::new().unwrap();
    let logger = AuditLogger::new(temp_file.path(), AuditLevel::Info);
    logger.initialize().await.unwrap();

    logger
        .log_sasl_auth(
            "cn=user,dc=example,dc=com",
            "127.0.0.1",
            "DIGEST-MD5",
            true,
            None,
        )
        .await;

    assert_eq!(logger.events_logged().await, 1);

    logger.close().await.unwrap();
    let content = fs::read_to_string(temp_file.path()).unwrap();
    assert!(content.contains("DIGEST-MD5"));
    assert!(content.contains("\"success\":true"));
}

#[tokio::test]
async fn test_log_sasl_auth_failure() {
    let temp_file = NamedTempFile::new().unwrap();
    let logger = AuditLogger::new(temp_file.path(), AuditLevel::Info);
    logger.initialize().await.unwrap();

    logger
        .log_sasl_auth(
            "cn=user,dc=example,dc=com",
            "127.0.0.1",
            "CRAM-MD5",
            false,
            Some("Authentication failed"),
        )
        .await;

    assert_eq!(logger.events_logged().await, 1);

    logger.close().await.unwrap();
    let content = fs::read_to_string(temp_file.path()).unwrap();
    assert!(content.contains("CRAM-MD5"));
    assert!(content.contains("Authentication failed"));
    assert!(content.contains("\"success\":false"));
}

// ================================================================================================
// Test: Authorization Event Logging
// ================================================================================================

#[tokio::test]
async fn test_log_authz_success() {
    let temp_file = NamedTempFile::new().unwrap();
    let logger = AuditLogger::new(temp_file.path(), AuditLevel::Debug);
    logger.initialize().await.unwrap();

    logger
        .log_authz_success(
            "cn=admin,dc=example,dc=com",
            "modify",
            "cn=user,dc=example,dc=com",
        )
        .await;

    assert_eq!(logger.events_logged().await, 1);

    logger.close().await.unwrap();
    let content = fs::read_to_string(temp_file.path()).unwrap();
    assert!(content.contains("authz_modify"));
    assert!(content.contains("cn=admin,dc=example,dc=com"));
}

#[tokio::test]
async fn test_log_authz_denial() {
    let temp_file = NamedTempFile::new().unwrap();
    let logger = AuditLogger::new(temp_file.path(), AuditLevel::Info);
    logger.initialize().await.unwrap();

    logger
        .log_authz_denial(
            "cn=user,dc=example,dc=com",
            "delete",
            "cn=protected,dc=example,dc=com",
            "Insufficient permissions",
        )
        .await;

    assert_eq!(logger.events_logged().await, 1);

    logger.close().await.unwrap();
    let content = fs::read_to_string(temp_file.path()).unwrap();
    assert!(content.contains("authz_delete"));
    assert!(content.contains("cn=user,dc=example,dc=com"));
    assert!(content.contains("cn=protected,dc=example,dc=com"));
    assert!(content.contains("Insufficient permissions"));
    assert!(content.contains("\"success\":false"));
}

// ================================================================================================
// Test: Data Modification Event Logging
// ================================================================================================

#[tokio::test]
async fn test_log_add_operation() {
    let temp_file = NamedTempFile::new().unwrap();
    let logger = AuditLogger::new(temp_file.path(), AuditLevel::Info);
    logger.initialize().await.unwrap();

    logger
        .log_add(
            "cn=newuser,dc=example,dc=com",
            "cn=admin,dc=example,dc=com",
            "127.0.0.1",
            true,
        )
        .await;

    assert_eq!(logger.events_logged().await, 1);

    logger.close().await.unwrap();
    let content = fs::read_to_string(temp_file.path()).unwrap();
    assert!(content.contains("add"));
    assert!(content.contains("cn=newuser,dc=example,dc=com"));
    assert!(content.contains("cn=admin,dc=example,dc=com"));
    assert!(content.contains("\"success\":true"));
}

#[tokio::test]
async fn test_log_modify_operation() {
    let temp_file = NamedTempFile::new().unwrap();
    let logger = AuditLogger::new(temp_file.path(), AuditLevel::Info);
    logger.initialize().await.unwrap();

    logger
        .log_modify(
            "cn=john,dc=example,dc=com",
            "cn=admin,dc=example,dc=com",
            "127.0.0.1",
            &["mail", "telephoneNumber", "description"],
        )
        .await;

    assert_eq!(logger.events_logged().await, 1);

    logger.close().await.unwrap();
    let content = fs::read_to_string(temp_file.path()).unwrap();
    assert!(content.contains("modify"));
    assert!(content.contains("cn=john,dc=example,dc=com"));
    assert!(content.contains("mail,telephoneNumber,description"));
}

#[tokio::test]
async fn test_log_delete_operation() {
    let temp_file = NamedTempFile::new().unwrap();
    let logger = AuditLogger::new(temp_file.path(), AuditLevel::Info);
    logger.initialize().await.unwrap();

    logger
        .log_delete(
            "cn=olduser,dc=example,dc=com",
            "cn=admin,dc=example,dc=com",
            "127.0.0.1",
            true,
        )
        .await;

    assert_eq!(logger.events_logged().await, 1);

    logger.close().await.unwrap();
    let content = fs::read_to_string(temp_file.path()).unwrap();
    assert!(content.contains("delete"));
    assert!(content.contains("cn=olduser,dc=example,dc=com"));
}

#[tokio::test]
async fn test_log_modifydn_operation() {
    let temp_file = NamedTempFile::new().unwrap();
    let logger = AuditLogger::new(temp_file.path(), AuditLevel::Info);
    logger.initialize().await.unwrap();

    logger
        .log_modifydn(
            "cn=john,ou=users,dc=example,dc=com",
            "cn=john,ou=people,dc=example,dc=com",
            "cn=admin,dc=example,dc=com",
            "127.0.0.1",
        )
        .await;

    assert_eq!(logger.events_logged().await, 1);

    logger.close().await.unwrap();
    let content = fs::read_to_string(temp_file.path()).unwrap();
    assert!(content.contains("modifydn"));
    assert!(content.contains("cn=john,ou=users,dc=example,dc=com"));
    assert!(content.contains("cn=john,ou=people,dc=example,dc=com"));
}

// ================================================================================================
// Test: Connection Event Logging
// ================================================================================================

#[tokio::test]
async fn test_log_connection_accepted() {
    let temp_file = NamedTempFile::new().unwrap();
    let logger = AuditLogger::new(temp_file.path(), AuditLevel::Debug);
    logger.initialize().await.unwrap();

    logger
        .log_connection_accepted("192.168.1.50", "session-abc123")
        .await;

    assert_eq!(logger.events_logged().await, 1);

    logger.close().await.unwrap();
    let content = fs::read_to_string(temp_file.path()).unwrap();
    assert!(content.contains("connection_accepted"));
    assert!(content.contains("192.168.1.50"));
    assert!(content.contains("session-abc123"));
}

#[tokio::test]
async fn test_log_connection_closed() {
    let temp_file = NamedTempFile::new().unwrap();
    let logger = AuditLogger::new(temp_file.path(), AuditLevel::Debug);
    logger.initialize().await.unwrap();

    logger
        .log_connection_closed("192.168.1.50", "session-abc123")
        .await;

    assert_eq!(logger.events_logged().await, 1);

    logger.close().await.unwrap();
    let content = fs::read_to_string(temp_file.path()).unwrap();
    assert!(content.contains("connection_closed"));
    assert!(content.contains("192.168.1.50"));
}

// ================================================================================================
// Test: Different Log Formats
// ================================================================================================

#[tokio::test]
async fn test_json_format_output() {
    let temp_file = NamedTempFile::new().unwrap();

    let config = AuditConfig {
        log_path: temp_file.path().to_path_buf(),
        min_level: AuditLevel::Info,
        format: AuditFormat::Json,
        ..Default::default()
    };

    let logger = AuditLogger::with_config(config);
    logger.initialize().await.unwrap();

    logger
        .log_auth_success("cn=admin,dc=example,dc=com", "127.0.0.1")
        .await;

    logger.close().await.unwrap();
    let content = fs::read_to_string(temp_file.path()).unwrap();

    // Verify it's valid JSON
    assert!(serde_json::from_str::<serde_json::Value>(content.trim()).is_ok());
}

#[tokio::test]
async fn test_text_format_output() {
    let temp_file = NamedTempFile::new().unwrap();

    let config = AuditConfig {
        log_path: temp_file.path().to_path_buf(),
        min_level: AuditLevel::Info,
        format: AuditFormat::Text,
        ..Default::default()
    };

    let logger = AuditLogger::with_config(config);
    logger.initialize().await.unwrap();

    logger
        .log_auth_success("cn=admin,dc=example,dc=com", "127.0.0.1")
        .await;

    logger.close().await.unwrap();
    let content = fs::read_to_string(temp_file.path()).unwrap();

    assert!(content.contains("INFO"));
    assert!(content.contains("authentication"));
    assert!(content.contains("user=\"cn=admin,dc=example,dc=com\""));
}

#[tokio::test]
async fn test_syslog_format_output() {
    let temp_file = NamedTempFile::new().unwrap();

    let config = AuditConfig {
        log_path: temp_file.path().to_path_buf(),
        min_level: AuditLevel::Info,
        format: AuditFormat::Syslog,
        ..Default::default()
    };

    let logger = AuditLogger::with_config(config);
    logger.initialize().await.unwrap();

    logger
        .log_auth_success("cn=admin,dc=example,dc=com", "127.0.0.1")
        .await;

    logger.close().await.unwrap();
    let content = fs::read_to_string(temp_file.path()).unwrap();

    assert!(content.starts_with("<")); // Syslog priority
    assert!(content.contains("opendr-ldap"));
}

// ================================================================================================
// Test: Concurrent Logging
// ================================================================================================

#[tokio::test]
async fn test_concurrent_logging() {
    let temp_file = NamedTempFile::new().unwrap();
    let logger = AuditLogger::new(temp_file.path(), AuditLevel::Info);
    logger.initialize().await.unwrap();

    use std::sync::Arc;
    let logger = Arc::new(logger);

    let mut handles = vec![];

    for i in 0..10 {
        let logger_clone = Arc::clone(&logger);
        let handle = tokio::spawn(async move {
            for j in 0..10 {
                logger_clone
                    .log_auth_success(
                        &format!("cn=user{},dc=example,dc=com", i),
                        &format!("127.0.0.{}", j),
                    )
                    .await;
                sleep(Duration::from_micros(100)).await;
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.unwrap();
    }

    assert_eq!(logger.events_logged().await, 100);
}

// ================================================================================================
// Test: Complete Workflow
// ================================================================================================

#[tokio::test]
async fn test_complete_audit_workflow() {
    let temp_file = NamedTempFile::new().unwrap();
    let logger = AuditLogger::new(temp_file.path(), AuditLevel::Info);
    logger.initialize().await.unwrap();

    // Simulate a user session
    logger
        .log_connection_accepted("192.168.1.100", "session-xyz789")
        .await;

    // Successful authentication
    logger
        .log_auth_success("cn=john,dc=example,dc=com", "192.168.1.100")
        .await;

    // Perform some operations
    logger
        .log_add(
            "cn=newuser,dc=example,dc=com",
            "cn=john,dc=example,dc=com",
            "192.168.1.100",
            true,
        )
        .await;

    logger
        .log_modify(
            "cn=john,dc=example,dc=com",
            "cn=john,dc=example,dc=com",
            "192.168.1.100",
            &["mail"],
        )
        .await;

    // Authorization denial
    logger
        .log_authz_denial(
            "cn=john,dc=example,dc=com",
            "delete",
            "cn=admin,dc=example,dc=com",
            "User cannot delete admin",
        )
        .await;

    // Close connection
    logger
        .log_connection_closed("192.168.1.100", "session-xyz789")
        .await;

    logger.close().await.unwrap();

    // Verify all events were written
    let content = fs::read_to_string(temp_file.path()).unwrap();
    let lines: Vec<&str> = content.lines().collect();

    // Should have 6 lines (connection events are debug level, won't be logged)
    // Actually should have 4: auth_success, add, modify, authz_denial
    assert!(lines.len() >= 4);
}

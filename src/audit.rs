//! Audit Logging for OpenDR LDAP Server
//!
//! This module provides comprehensive security audit trail capabilities for the LDAP server.
//! It tracks authentication attempts, authorization decisions, data modifications, and other
//! security-relevant events.
//!
//! ## Features
//!
//! - **Authentication Auditing**: Track all authentication attempts (success/failure)
//! - **Authorization Auditing**: Log access control decisions and permission denials
//! - **Data Modification Auditing**: Track all write operations (add, modify, delete)
//! - **Connection Auditing**: Track connection lifecycle events
//! - **Configurable Levels**: Filter events by severity level
//! - **Multiple Formats**: JSON, syslog, and custom formats
//! - **Async Logging**: Non-blocking audit event recording
//! - **Structured Data**: Rich context for each event
//!
//! ## Usage Example
//!
//! ```rust
//! use opendr::audit::{AuditLogger, AuditEvent, AuditLevel};
//!
//! # async fn example() {
//! let logger = AuditLogger::new("/var/log/opendr/audit.log", AuditLevel::Info);
//!
//! // Log authentication attempt
//! logger.log_auth_success("cn=admin,dc=example,dc=com", "127.0.0.1").await;
//!
//! // Log failed authentication
//! logger.log_auth_failure("cn=hacker,dc=example,dc=com", "192.168.1.100", "Invalid credentials").await;
//!
//! // Log authorization denial
//! logger.log_authz_denial(
//!     "cn=user,dc=example,dc=com",
//!     "modify",
//!     "cn=admin,dc=example,dc=com",
//!     "Insufficient permissions"
//! ).await;
//!
//! // Log data modification
//! logger.log_modify(
//!     "cn=john,ou=users,dc=example,dc=com",
//!     "cn=admin,dc=example,dc=com",
//!     "127.0.0.1",
//!     &["mail", "telephoneNumber"]
//! ).await;
//! # }
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;

/// Audit event severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AuditLevel {
    /// Debug-level events (very verbose)
    Debug,
    /// Informational events
    Info,
    /// Warning events (potential issues)
    Warning,
    /// Error events (actual problems)
    Error,
    /// Critical security events
    Critical,
}

impl AuditLevel {
    /// Get the level as a string
    pub fn as_str(&self) -> &str {
        match self {
            AuditLevel::Debug => "DEBUG",
            AuditLevel::Info => "INFO",
            AuditLevel::Warning => "WARNING",
            AuditLevel::Error => "ERROR",
            AuditLevel::Critical => "CRITICAL",
        }
    }

    /// Get numeric priority (for syslog)
    pub fn to_priority(&self) -> u8 {
        match self {
            AuditLevel::Debug => 7,    // Debug
            AuditLevel::Info => 6,     // Informational
            AuditLevel::Warning => 4,  // Warning
            AuditLevel::Error => 3,    // Error
            AuditLevel::Critical => 2, // Critical
        }
    }
}

/// Type of audit event
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditEventType {
    /// Authentication event
    Authentication,
    /// Authorization event
    Authorization,
    /// Data modification event
    DataModification,
    /// Connection event
    Connection,
    /// Configuration change
    Configuration,
    /// Schema modification
    Schema,
    /// Replication event
    Replication,
    /// System event
    System,
}

impl AuditEventType {
    /// Get the event type as a string
    pub fn as_str(&self) -> &str {
        match self {
            AuditEventType::Authentication => "authentication",
            AuditEventType::Authorization => "authorization",
            AuditEventType::DataModification => "data_modification",
            AuditEventType::Connection => "connection",
            AuditEventType::Configuration => "configuration",
            AuditEventType::Schema => "schema",
            AuditEventType::Replication => "replication",
            AuditEventType::System => "system",
        }
    }
}

/// Authentication operation result
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthOperation {
    /// Simple bind
    SimpleBind,
    /// SASL bind
    SaslBind,
    /// Anonymous bind
    AnonymousBind,
    /// Unbind
    Unbind,
}

impl AuthOperation {
    pub fn as_str(&self) -> &str {
        match self {
            AuthOperation::SimpleBind => "simple_bind",
            AuthOperation::SaslBind => "sasl_bind",
            AuthOperation::AnonymousBind => "anonymous_bind",
            AuthOperation::Unbind => "unbind",
        }
    }
}

/// Data modification operation type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModifyOperation {
    /// Add new entry
    Add,
    /// Modify existing entry
    Modify,
    /// Delete entry
    Delete,
    /// Modify DN (rename/move)
    ModifyDN,
}

impl ModifyOperation {
    pub fn as_str(&self) -> &str {
        match self {
            ModifyOperation::Add => "add",
            ModifyOperation::Modify => "modify",
            ModifyOperation::Delete => "delete",
            ModifyOperation::ModifyDN => "modifydn",
        }
    }
}

/// Audit event structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Event timestamp (UTC)
    pub timestamp: DateTime<Utc>,
    /// Event level
    pub level: AuditLevel,
    /// Event type
    pub event_type: AuditEventType,
    /// Event action/operation
    pub action: String,
    /// Result (success/failure)
    pub success: bool,
    /// User DN (who performed the action)
    pub user_dn: Option<String>,
    /// Target DN (what was acted upon)
    pub target_dn: Option<String>,
    /// Client IP address
    pub client_ip: Option<String>,
    /// Session ID
    pub session_id: Option<String>,
    /// Error message (if failed)
    pub error_message: Option<String>,
    /// Additional context
    pub details: HashMap<String, String>,
}

impl AuditEvent {
    /// Create a new audit event
    pub fn new(
        level: AuditLevel,
        event_type: AuditEventType,
        action: String,
        success: bool,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            level,
            event_type,
            action,
            success,
            user_dn: None,
            target_dn: None,
            client_ip: None,
            session_id: None,
            error_message: None,
            details: HashMap::new(),
        }
    }

    /// Set user DN
    pub fn with_user_dn(mut self, user_dn: impl Into<String>) -> Self {
        self.user_dn = Some(user_dn.into());
        self
    }

    /// Set target DN
    pub fn with_target_dn(mut self, target_dn: impl Into<String>) -> Self {
        self.target_dn = Some(target_dn.into());
        self
    }

    /// Set client IP
    pub fn with_client_ip(mut self, client_ip: impl Into<String>) -> Self {
        self.client_ip = Some(client_ip.into());
        self
    }

    /// Set session ID
    pub fn with_session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Set error message
    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.error_message = Some(error.into());
        self
    }

    /// Add detail field
    pub fn with_detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }

    /// Format as JSON
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// Format as syslog message (RFC 5424)
    pub fn to_syslog(&self) -> String {
        let priority = self.level.to_priority();
        let facility = 10; // Security/authorization messages
        let pri = facility * 8 + priority;

        let timestamp = self.timestamp.to_rfc3339();
        let hostname = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "unknown".to_string());

        let app_name = "opendr-ldap";
        let msg_id = self.event_type.as_str();

        let mut msg = format!(
            "{} {} {} {}",
            self.action,
            if self.success { "SUCCESS" } else { "FAILURE" },
            self.user_dn.as_deref().unwrap_or("-"),
            self.target_dn.as_deref().unwrap_or("-")
        );

        if let Some(ref error) = self.error_message {
            msg.push_str(&format!(" error=\"{}\"", error));
        }

        format!(
            "<{}> {} {} {} - {} {}",
            pri, timestamp, hostname, app_name, msg_id, msg
        )
    }

    /// Format as plain text
    pub fn to_text(&self) -> String {
        let mut parts = vec![
            self.timestamp.to_rfc3339(),
            self.level.as_str().to_string(),
            self.event_type.as_str().to_string(),
            self.action.clone(),
            if self.success {
                "SUCCESS".to_string()
            } else {
                "FAILURE".to_string()
            },
        ];

        if let Some(ref user_dn) = self.user_dn {
            parts.push(format!("user=\"{}\"", user_dn));
        }

        if let Some(ref target_dn) = self.target_dn {
            parts.push(format!("target=\"{}\"", target_dn));
        }

        if let Some(ref client_ip) = self.client_ip {
            parts.push(format!("client=\"{}\"", client_ip));
        }

        if let Some(ref error) = self.error_message {
            parts.push(format!("error=\"{}\"", error));
        }

        for (key, value) in &self.details {
            parts.push(format!("{}=\"{}\"", key, value));
        }

        parts.join(" ")
    }
}

/// Audit log format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditFormat {
    /// JSON format (one event per line)
    Json,
    /// Syslog format (RFC 5424)
    Syslog,
    /// Plain text format
    Text,
}

/// Audit logger configuration
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Log file path
    pub log_path: PathBuf,
    /// Minimum audit level
    pub min_level: AuditLevel,
    /// Log format
    pub format: AuditFormat,
    /// Enable async logging
    pub async_logging: bool,
    /// Buffer size for async logging
    pub buffer_size: usize,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            log_path: PathBuf::from("/var/log/opendr/audit.log"),
            min_level: AuditLevel::Info,
            format: AuditFormat::Json,
            async_logging: true,
            buffer_size: 1000,
        }
    }
}

/// Main audit logger
pub struct AuditLogger {
    config: AuditConfig,
    file: Arc<RwLock<Option<File>>>,
    events_logged: Arc<RwLock<u64>>,
}

impl AuditLogger {
    /// Create a new audit logger
    pub fn new(log_path: impl Into<PathBuf>, min_level: AuditLevel) -> Arc<Self> {
        let config = AuditConfig {
            log_path: log_path.into(),
            min_level,
            ..Default::default()
        };

        Arc::new(Self {
            config,
            file: Arc::new(RwLock::new(None)),
            events_logged: Arc::new(RwLock::new(0)),
        })
    }

    /// Create audit logger with custom configuration
    pub fn with_config(config: AuditConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            file: Arc::new(RwLock::new(None)),
            events_logged: Arc::new(RwLock::new(0)),
        })
    }

    /// Initialize the audit logger (open log file)
    pub async fn initialize(&self) -> Result<(), String> {
        // Create parent directory if it doesn't exist
        if let Some(parent) = self.config.log_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| format!("Failed to create log directory: {}", e))?;
        }

        // Open log file for appending
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.config.log_path)
            .await
            .map_err(|e| format!("Failed to open audit log file: {}", e))?;

        *self.file.write().await = Some(file);

        Ok(())
    }

    /// Log an audit event
    pub async fn log_event(&self, event: AuditEvent) {
        // Filter by level
        if event.level < self.config.min_level {
            return;
        }

        // Format event
        let line = match self.config.format {
            AuditFormat::Json => event.to_json(),
            AuditFormat::Syslog => event.to_syslog(),
            AuditFormat::Text => event.to_text(),
        };

        // Write to file
        if let Err(e) = self.write_log(&format!("{}\n", line)).await {
            eprintln!("Failed to write audit log: {}", e);
        }

        // Increment counter
        let mut count = self.events_logged.write().await;
        *count += 1;
    }

    /// Write to log file
    async fn write_log(&self, line: &str) -> Result<(), String> {
        let mut file_guard = self.file.write().await;

        if let Some(ref mut file) = *file_guard {
            file.write_all(line.as_bytes())
                .await
                .map_err(|e| format!("Failed to write to audit log: {}", e))?;
            file.flush()
                .await
                .map_err(|e| format!("Failed to flush audit log: {}", e))?;
        } else {
            return Err("Audit log not initialized".to_string());
        }

        Ok(())
    }

    /// Get number of events logged
    pub async fn events_logged(&self) -> u64 {
        *self.events_logged.read().await
    }

    // ========================================================================
    // Authentication Events
    // ========================================================================

    /// Log successful authentication
    pub async fn log_auth_success(&self, user_dn: &str, client_ip: &str) {
        let event = AuditEvent::new(
            AuditLevel::Info,
            AuditEventType::Authentication,
            AuthOperation::SimpleBind.as_str().to_string(),
            true,
        )
        .with_user_dn(user_dn)
        .with_client_ip(client_ip);

        self.log_event(event).await;
    }

    /// Log failed authentication
    pub async fn log_auth_failure(&self, user_dn: &str, client_ip: &str, reason: &str) {
        let event = AuditEvent::new(
            AuditLevel::Warning,
            AuditEventType::Authentication,
            AuthOperation::SimpleBind.as_str().to_string(),
            false,
        )
        .with_user_dn(user_dn)
        .with_client_ip(client_ip)
        .with_error(reason);

        self.log_event(event).await;
    }

    /// Log SASL authentication
    pub async fn log_sasl_auth(
        &self,
        user_dn: &str,
        client_ip: &str,
        mechanism: &str,
        success: bool,
        error: Option<&str>,
    ) {
        let level = if success {
            AuditLevel::Info
        } else {
            AuditLevel::Warning
        };

        let mut event = AuditEvent::new(
            level,
            AuditEventType::Authentication,
            AuthOperation::SaslBind.as_str().to_string(),
            success,
        )
        .with_user_dn(user_dn)
        .with_client_ip(client_ip)
        .with_detail("mechanism", mechanism);

        if let Some(err) = error {
            event = event.with_error(err);
        }

        self.log_event(event).await;
    }

    // ========================================================================
    // Authorization Events
    // ========================================================================

    /// Log authorization success
    pub async fn log_authz_success(&self, user_dn: &str, operation: &str, target_dn: &str) {
        let event = AuditEvent::new(
            AuditLevel::Debug,
            AuditEventType::Authorization,
            format!("authz_{}", operation),
            true,
        )
        .with_user_dn(user_dn)
        .with_target_dn(target_dn);

        self.log_event(event).await;
    }

    /// Log authorization denial
    pub async fn log_authz_denial(
        &self,
        user_dn: &str,
        operation: &str,
        target_dn: &str,
        reason: &str,
    ) {
        let event = AuditEvent::new(
            AuditLevel::Warning,
            AuditEventType::Authorization,
            format!("authz_{}", operation),
            false,
        )
        .with_user_dn(user_dn)
        .with_target_dn(target_dn)
        .with_error(reason);

        self.log_event(event).await;
    }

    // ========================================================================
    // Data Modification Events
    // ========================================================================

    /// Log add operation
    pub async fn log_add(&self, dn: &str, user_dn: &str, client_ip: &str, success: bool) {
        let level = if success {
            AuditLevel::Info
        } else {
            AuditLevel::Error
        };

        let event = AuditEvent::new(
            level,
            AuditEventType::DataModification,
            ModifyOperation::Add.as_str().to_string(),
            success,
        )
        .with_target_dn(dn)
        .with_user_dn(user_dn)
        .with_client_ip(client_ip);

        self.log_event(event).await;
    }

    /// Log modify operation
    pub async fn log_modify(&self, dn: &str, user_dn: &str, client_ip: &str, attributes: &[&str]) {
        let event = AuditEvent::new(
            AuditLevel::Info,
            AuditEventType::DataModification,
            ModifyOperation::Modify.as_str().to_string(),
            true,
        )
        .with_target_dn(dn)
        .with_user_dn(user_dn)
        .with_client_ip(client_ip)
        .with_detail("attributes", attributes.join(","));

        self.log_event(event).await;
    }

    /// Log delete operation
    pub async fn log_delete(&self, dn: &str, user_dn: &str, client_ip: &str, success: bool) {
        let level = if success {
            AuditLevel::Info
        } else {
            AuditLevel::Error
        };

        let event = AuditEvent::new(
            level,
            AuditEventType::DataModification,
            ModifyOperation::Delete.as_str().to_string(),
            success,
        )
        .with_target_dn(dn)
        .with_user_dn(user_dn)
        .with_client_ip(client_ip);

        self.log_event(event).await;
    }

    /// Log modifydn operation
    pub async fn log_modifydn(&self, old_dn: &str, new_dn: &str, user_dn: &str, client_ip: &str) {
        let event = AuditEvent::new(
            AuditLevel::Info,
            AuditEventType::DataModification,
            ModifyOperation::ModifyDN.as_str().to_string(),
            true,
        )
        .with_target_dn(old_dn)
        .with_user_dn(user_dn)
        .with_client_ip(client_ip)
        .with_detail("new_dn", new_dn);

        self.log_event(event).await;
    }

    // ========================================================================
    // Connection Events
    // ========================================================================

    /// Log connection established
    pub async fn log_connection_accepted(&self, client_ip: &str, session_id: &str) {
        let event = AuditEvent::new(
            AuditLevel::Debug,
            AuditEventType::Connection,
            "connection_accepted".to_string(),
            true,
        )
        .with_client_ip(client_ip)
        .with_session_id(session_id);

        self.log_event(event).await;
    }

    /// Log connection closed
    pub async fn log_connection_closed(&self, client_ip: &str, session_id: &str) {
        let event = AuditEvent::new(
            AuditLevel::Debug,
            AuditEventType::Connection,
            "connection_closed".to_string(),
            true,
        )
        .with_client_ip(client_ip)
        .with_session_id(session_id);

        self.log_event(event).await;
    }

    /// Flush and close the audit log
    pub async fn close(&self) -> Result<(), String> {
        let mut file_guard = self.file.write().await;
        if let Some(ref mut file) = *file_guard {
            file.flush()
                .await
                .map_err(|e| format!("Failed to flush audit log: {}", e))?;
        }
        *file_guard = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_audit_level_ordering() {
        assert!(AuditLevel::Debug < AuditLevel::Info);
        assert!(AuditLevel::Info < AuditLevel::Warning);
        assert!(AuditLevel::Warning < AuditLevel::Error);
        assert!(AuditLevel::Error < AuditLevel::Critical);
    }

    #[test]
    fn test_audit_level_to_priority() {
        assert_eq!(AuditLevel::Debug.to_priority(), 7);
        assert_eq!(AuditLevel::Info.to_priority(), 6);
        assert_eq!(AuditLevel::Warning.to_priority(), 4);
        assert_eq!(AuditLevel::Error.to_priority(), 3);
        assert_eq!(AuditLevel::Critical.to_priority(), 2);
    }

    #[test]
    fn test_audit_event_creation() {
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
        assert!(event.user_dn.is_none());
    }

    #[test]
    fn test_audit_event_builder() {
        let event = AuditEvent::new(
            AuditLevel::Info,
            AuditEventType::Authentication,
            "bind".to_string(),
            true,
        )
        .with_user_dn("cn=admin,dc=example,dc=com")
        .with_client_ip("127.0.0.1")
        .with_detail("method", "simple");

        assert_eq!(
            event.user_dn,
            Some("cn=admin,dc=example,dc=com".to_string())
        );
        assert_eq!(event.client_ip, Some("127.0.0.1".to_string()));
        assert_eq!(event.details.get("method"), Some(&"simple".to_string()));
    }

    #[test]
    fn test_audit_event_json_format() {
        let event = AuditEvent::new(
            AuditLevel::Info,
            AuditEventType::Authentication,
            "bind".to_string(),
            true,
        )
        .with_user_dn("cn=admin,dc=example,dc=com");

        let json = event.to_json();
        assert!(json.contains("\"level\":\"Info\""));
        assert!(json.contains("\"action\":\"bind\""));
        assert!(json.contains("\"success\":true"));
    }

    #[test]
    fn test_audit_event_text_format() {
        let event = AuditEvent::new(
            AuditLevel::Warning,
            AuditEventType::Authentication,
            "bind".to_string(),
            false,
        )
        .with_user_dn("cn=hacker,dc=example,dc=com")
        .with_client_ip("192.168.1.100")
        .with_error("Invalid credentials");

        let text = event.to_text();
        assert!(text.contains("WARNING"));
        assert!(text.contains("authentication"));
        assert!(text.contains("bind"));
        assert!(text.contains("FAILURE"));
        assert!(text.contains("user=\"cn=hacker,dc=example,dc=com\""));
        assert!(text.contains("client=\"192.168.1.100\""));
        assert!(text.contains("error=\"Invalid credentials\""));
    }

    #[test]
    fn test_audit_event_syslog_format() {
        let event = AuditEvent::new(
            AuditLevel::Info,
            AuditEventType::Authentication,
            "bind".to_string(),
            true,
        )
        .with_user_dn("cn=admin,dc=example,dc=com");

        let syslog = event.to_syslog();
        // Priority: facility (10) * 8 + level (6) = 86
        assert!(syslog.starts_with("<86>"));
        assert!(syslog.contains("opendr-ldap"));
        assert!(syslog.contains("authentication"));
        assert!(syslog.contains("SUCCESS"));
    }

    #[tokio::test]
    async fn test_audit_logger_creation() {
        let temp_file = NamedTempFile::new().unwrap();
        let logger = AuditLogger::new(temp_file.path(), AuditLevel::Info);

        assert_eq!(logger.config.min_level, AuditLevel::Info);
        assert_eq!(logger.events_logged().await, 0);
    }

    #[tokio::test]
    async fn test_audit_logger_initialization() {
        let temp_file = NamedTempFile::new().unwrap();
        let logger = AuditLogger::new(temp_file.path(), AuditLevel::Info);

        let result = logger.initialize().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_audit_logger_log_event() {
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
    }

    #[tokio::test]
    async fn test_audit_logger_level_filtering() {
        let temp_file = NamedTempFile::new().unwrap();
        let logger = AuditLogger::new(temp_file.path(), AuditLevel::Warning);
        logger.initialize().await.unwrap();

        // Debug event should be filtered out
        let debug_event = AuditEvent::new(
            AuditLevel::Debug,
            AuditEventType::Connection,
            "debug".to_string(),
            true,
        );
        logger.log_event(debug_event).await;

        // Warning event should be logged
        let warning_event = AuditEvent::new(
            AuditLevel::Warning,
            AuditEventType::Authentication,
            "warning".to_string(),
            false,
        );
        logger.log_event(warning_event).await;

        assert_eq!(logger.events_logged().await, 1);
    }

    #[tokio::test]
    async fn test_audit_logger_auth_success() {
        let temp_file = NamedTempFile::new().unwrap();
        let logger = AuditLogger::new(temp_file.path(), AuditLevel::Info);
        logger.initialize().await.unwrap();

        logger
            .log_auth_success("cn=admin,dc=example,dc=com", "127.0.0.1")
            .await;

        assert_eq!(logger.events_logged().await, 1);
    }

    #[tokio::test]
    async fn test_audit_logger_auth_failure() {
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
    }

    #[tokio::test]
    async fn test_audit_logger_authz_denial() {
        let temp_file = NamedTempFile::new().unwrap();
        let logger = AuditLogger::new(temp_file.path(), AuditLevel::Info);
        logger.initialize().await.unwrap();

        logger
            .log_authz_denial(
                "cn=user,dc=example,dc=com",
                "modify",
                "cn=admin,dc=example,dc=com",
                "Insufficient permissions",
            )
            .await;

        assert_eq!(logger.events_logged().await, 1);
    }

    #[tokio::test]
    async fn test_audit_logger_data_modifications() {
        let temp_file = NamedTempFile::new().unwrap();
        let logger = AuditLogger::new(temp_file.path(), AuditLevel::Info);
        logger.initialize().await.unwrap();

        // Add
        logger
            .log_add(
                "cn=new,dc=example,dc=com",
                "cn=admin,dc=example,dc=com",
                "127.0.0.1",
                true,
            )
            .await;

        // Modify
        logger
            .log_modify(
                "cn=john,dc=example,dc=com",
                "cn=admin,dc=example,dc=com",
                "127.0.0.1",
                &["mail", "phone"],
            )
            .await;

        // Delete
        logger
            .log_delete(
                "cn=old,dc=example,dc=com",
                "cn=admin,dc=example,dc=com",
                "127.0.0.1",
                true,
            )
            .await;

        assert_eq!(logger.events_logged().await, 3);
    }

    #[tokio::test]
    async fn test_event_type_as_str() {
        assert_eq!(AuditEventType::Authentication.as_str(), "authentication");
        assert_eq!(AuditEventType::Authorization.as_str(), "authorization");
        assert_eq!(
            AuditEventType::DataModification.as_str(),
            "data_modification"
        );
    }

    #[tokio::test]
    async fn test_auth_operation_as_str() {
        assert_eq!(AuthOperation::SimpleBind.as_str(), "simple_bind");
        assert_eq!(AuthOperation::SaslBind.as_str(), "sasl_bind");
        assert_eq!(AuthOperation::AnonymousBind.as_str(), "anonymous_bind");
    }

    #[tokio::test]
    async fn test_modify_operation_as_str() {
        assert_eq!(ModifyOperation::Add.as_str(), "add");
        assert_eq!(ModifyOperation::Modify.as_str(), "modify");
        assert_eq!(ModifyOperation::Delete.as_str(), "delete");
        assert_eq!(ModifyOperation::ModifyDN.as_str(), "modifydn");
    }
}

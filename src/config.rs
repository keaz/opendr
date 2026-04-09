//! Configuration Management System
//!
//! This module provides a comprehensive configuration system for the OpenDR LDAP server.
//! It supports loading configuration from TOML files with environment variable overrides
//! and provides validation to ensure configuration integrity.
//!
//! ## Features
//!
//! - **TOML Configuration Files**: Human-readable configuration format
//! - **Environment Variable Overrides**: Override any config value via environment variables
//! - **Configuration Validation**: Ensure all values are valid before starting server
//! - **Hot Reload Support**: Configuration can be reloaded without server restart
//! - **Sensible Defaults**: Works out-of-the-box with minimal configuration
//!
//! ## Usage
//!
//! ```rust,no_run
//! use opendr::config::ServerConfig;
//!
//! # fn main() -> Result<(), opendr::config::ConfigError> {
//! // Load from file with environment overrides
//! let file_config = ServerConfig::from_file("config/server.toml")?;
//!
//! // Or use defaults
//! let default_config = ServerConfig::default();
//!
//! // Validate configuration
//! file_config.validate()?;
//! default_config.validate()?;
//! # Ok(())
//! # }
//! ```

use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;
use thiserror::Error;

/// Configuration errors
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Failed to load configuration: {0}")]
    LoadError(String),

    #[error("Invalid configuration: {0}")]
    ValidationError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    ParseError(String),
}

/// Complete server configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServerConfig {
    /// Server settings
    #[serde(default)]
    pub server: ServerSettings,

    /// Directory backend settings
    #[serde(default)]
    pub backend: BackendSettings,

    /// TLS/SSL settings
    #[serde(default)]
    pub tls: TlsSettings,

    /// Resource management settings
    #[serde(default)]
    pub resources: ResourceSettings,

    /// Rate limiting settings
    #[serde(default)]
    pub rate_limit: RateLimitSettings,

    /// Replication settings
    #[serde(default)]
    pub replication: ReplicationSettings,

    /// Monitoring and metrics settings
    #[serde(default)]
    pub monitoring: MonitoringSettings,

    /// Audit logging settings
    #[serde(default)]
    pub audit: AuditSettings,

    /// Access control settings
    #[serde(default)]
    pub access_control: AccessControlSettings,

    /// Performance tuning settings
    #[serde(default)]
    pub performance: PerformanceSettings,
}

/// Server settings
#[derive(Clone, Serialize, Deserialize)]
pub struct ServerSettings {
    /// LDAP bind address
    #[serde(default = "default_bind_address")]
    pub bind_address: String,

    /// LDAP port
    #[serde(default = "default_ldap_port")]
    pub ldap_port: u16,

    /// LDAPS port (TLS)
    #[serde(default = "default_ldaps_port")]
    pub ldaps_port: u16,

    /// Server hostname
    #[serde(default = "default_hostname")]
    pub hostname: String,

    /// Runtime used by the shipped executable
    #[serde(default = "default_server_runtime")]
    pub runtime: String,

    /// Replica ID used in generated CSNs
    #[serde(default = "default_replica_id")]
    pub replica_id: u16,

    /// Base DN
    #[serde(default = "default_base_dn")]
    pub base_dn: String,

    /// Root user DN
    #[serde(default = "default_root_user_dn")]
    pub root_user_dn: String,

    /// Root password (hashed)
    #[serde(
        default = "default_root_password",
        skip_serializing_if = "String::is_empty"
    )]
    pub root_password: String,

    /// Environment variable containing the root password
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_password_env: Option<String>,

    /// File containing the root password
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_password_file: Option<PathBuf>,

    /// Organization name
    #[serde(default = "default_organization_name")]
    pub organization_name: String,

    /// Read buffer size (bytes)
    #[serde(default = "default_read_buffer_size")]
    pub read_buffer_size: usize,

    /// Operation timeout (seconds)
    #[serde(default = "default_operation_timeout_secs")]
    pub operation_timeout_secs: u64,

    /// Cleanup interval (seconds)
    #[serde(default = "default_cleanup_interval_secs")]
    pub cleanup_interval_secs: u64,

    /// Maximum concurrent operations per connection
    #[serde(default = "default_max_concurrent_operations")]
    pub max_concurrent_operations: usize,
}

/// Backend settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendSettings {
    /// Backend type: "memory", "lmdb"
    #[serde(default = "default_backend_type")]
    pub backend_type: String,

    /// Data directory for persistent backends
    #[serde(default = "default_data_directory")]
    pub data_directory: PathBuf,

    /// LMDB maximum database size (bytes)
    #[serde(default = "default_lmdb_max_size")]
    pub lmdb_max_size: usize,

    /// LMDB maximum readers
    #[serde(default = "default_lmdb_max_readers")]
    pub lmdb_max_readers: u32,

    /// Import sample data on startup
    #[serde(default)]
    pub import_sample_data: bool,

    /// Indexed attributes
    #[serde(default = "default_indexed_attributes")]
    pub indexed_attributes: Vec<String>,
}

/// TLS settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsSettings {
    /// Enable TLS/SSL
    #[serde(default)]
    pub enabled: bool,

    /// Certificate file path
    #[serde(default = "default_cert_file")]
    pub cert_file: PathBuf,

    /// Private key file path
    #[serde(default = "default_key_file")]
    pub key_file: PathBuf,

    /// CA certificate file path (for client cert verification)
    #[serde(default)]
    pub ca_file: Option<PathBuf>,

    /// Require client certificates
    #[serde(default)]
    pub require_client_cert: bool,

    /// Minimum TLS version: "1.2" or "1.3"
    #[serde(default = "default_min_tls_version")]
    pub min_tls_version: String,
}

/// Resource management settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceSettings {
    /// Maximum total connections
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    /// Maximum connections per IP
    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: usize,

    /// Maximum operations per connection
    #[serde(default = "default_max_operations_per_connection")]
    pub max_operations_per_connection: usize,

    /// Maximum memory per connection (bytes)
    #[serde(default = "default_max_memory_per_connection")]
    pub max_memory_per_connection: usize,

    /// Maximum total memory (bytes)
    #[serde(default = "default_max_total_memory")]
    pub max_total_memory: usize,

    /// Connection idle timeout (seconds)
    #[serde(default = "default_connection_idle_timeout_secs")]
    pub connection_idle_timeout_secs: u64,
}

/// Rate limiting settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitSettings {
    /// Enable rate limiting
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Global requests per second
    #[serde(default = "default_global_requests_per_second")]
    pub global_requests_per_second: u32,

    /// Per-client requests per second
    #[serde(default = "default_per_client_requests_per_second")]
    pub per_client_requests_per_second: u32,

    /// Burst size
    #[serde(default = "default_burst_size")]
    pub burst_size: u32,

    /// Window duration (seconds)
    #[serde(default = "default_window_duration_secs")]
    pub window_duration_secs: u64,

    /// Enable adaptive rate limiting
    #[serde(default = "default_true")]
    pub adaptive_enabled: bool,

    /// Adaptive threshold (0.0-1.0)
    #[serde(default = "default_adaptive_threshold")]
    pub adaptive_threshold: f64,

    /// Adaptive multiplier (0.0-1.0)
    #[serde(default = "default_adaptive_multiplier")]
    pub adaptive_multiplier: f64,

    /// Auto-ban threshold (violations)
    #[serde(default = "default_auto_ban_threshold")]
    pub auto_ban_threshold: u32,

    /// Auto-ban duration (seconds)
    #[serde(default = "default_auto_ban_duration_secs")]
    pub auto_ban_duration_secs: u64,

    /// Blacklisted IPs
    #[serde(default)]
    pub blacklist: Vec<String>,

    /// Whitelisted IPs
    #[serde(default)]
    pub whitelist: Vec<String>,

    /// Operation-specific limits
    #[serde(default = "default_operation_limits")]
    pub operation_limits: OperationLimits,
}

/// Operation-specific rate limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationLimits {
    #[serde(default = "default_bind_limit")]
    pub bind: u32,
    #[serde(default = "default_search_limit")]
    pub search: u32,
    #[serde(default = "default_modify_limit")]
    pub modify: u32,
    #[serde(default = "default_add_limit")]
    pub add: u32,
    #[serde(default = "default_delete_limit")]
    pub delete: u32,
    #[serde(default = "default_modifydn_limit")]
    pub modifydn: u32,
    #[serde(default = "default_compare_limit")]
    pub compare: u32,
    #[serde(default = "default_extended_limit")]
    pub extended: u32,
}

/// Replication settings
#[derive(Clone, Serialize, Deserialize)]
pub struct ReplicationSettings {
    /// Enable replication
    #[serde(default)]
    pub enabled: bool,

    /// Replication mode: "provider", "consumer", "both"
    #[serde(default = "default_replication_mode", alias = "role")]
    pub mode: String,

    /// Provider URL (for consumer mode)
    #[serde(default)]
    pub provider_url: Option<String>,

    /// Replication bind DN
    #[serde(default, alias = "provider_bind_dn", alias = "replication_bind_dn")]
    pub bind_dn: Option<String>,

    /// Replication bind password
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "provider_bind_password",
        alias = "replication_bind_password"
    )]
    pub bind_password: Option<String>,

    /// Environment variable containing the replication bind password
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "provider_bind_password_env",
        alias = "replication_bind_password_env"
    )]
    pub bind_password_env: Option<String>,

    /// File containing the replication bind password
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "provider_bind_password_file",
        alias = "replication_bind_password_file"
    )]
    pub bind_password_file: Option<PathBuf>,

    /// Changelog capacity
    #[serde(
        default = "default_changelog_capacity",
        alias = "changelog_max_entries"
    )]
    pub changelog_capacity: usize,

    /// Keep the provider changelog enabled when running in provider/both mode.
    #[serde(default = "default_true")]
    pub changelog_enabled: bool,

    /// Maximum entries per replication batch.
    #[serde(default = "default_replication_max_batch_size")]
    pub max_batch_size: usize,

    /// Sync interval (seconds)
    #[serde(default = "default_sync_interval_secs")]
    pub sync_interval_secs: u64,

    /// Maximum retry attempts for listening/polling reconnects
    #[serde(default = "default_max_retry_attempts")]
    pub max_retry_attempts: u32,

    /// Delay between retry attempts (seconds)
    #[serde(default = "default_retry_delay_secs")]
    pub retry_delay_secs: u64,

    /// Keep a long-lived listener open for post-refresh changes
    #[serde(default = "default_true", alias = "listen_for_changes")]
    pub enable_change_listening: bool,

    /// Enable provider-side live streaming support.
    #[serde(default = "default_true")]
    pub enable_streaming: bool,

    /// Heartbeat interval for listening-based replication (seconds)
    #[serde(default = "default_heartbeat_interval_secs")]
    pub heartbeat_interval_secs: u64,

    /// Maximum concurrent provider-side consumers.
    #[serde(default = "default_max_concurrent_consumers")]
    pub max_concurrent_consumers: usize,

    /// Provider-side consumer session timeout in seconds.
    #[serde(default = "default_consumer_timeout_secs")]
    pub consumer_timeout_secs: u64,

    /// Consumer-side provider request timeout in seconds.
    #[serde(default = "default_provider_timeout_secs")]
    pub provider_timeout_secs: u64,

    /// Consumer-side state persistence timeout in seconds.
    #[serde(default = "default_state_persistence_timeout_secs")]
    pub state_persistence_timeout_secs: u64,

    /// Consumer-side live change buffer size.
    #[serde(default = "default_change_buffer_size")]
    pub change_buffer_size: usize,

    /// Path for persisted replication state
    #[serde(default = "default_replication_state_storage_path")]
    pub state_storage_path: PathBuf,

    /// TCP port used for the live replication stream (0 = derive from LDAP port)
    #[serde(
        default,
        alias = "replication_stream_port",
        alias = "change_listener_port"
    )]
    pub stream_port: u16,
}

/// Monitoring settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringSettings {
    /// Enable metrics collection
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Metrics export address
    #[serde(default = "default_metrics_address")]
    pub metrics_address: String,

    /// Metrics export port
    #[serde(default = "default_metrics_port")]
    pub metrics_port: u16,

    /// Prometheus export path
    #[serde(default = "default_metrics_path")]
    pub metrics_path: String,

    /// Health check path
    #[serde(default = "default_health_path")]
    pub health_path: String,
}

/// Audit logging settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSettings {
    /// Enable audit logging
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Audit log file path
    #[serde(default = "default_audit_log_file")]
    pub log_file: PathBuf,

    /// Audit log format: "json", "syslog", "text"
    #[serde(default = "default_audit_format")]
    pub format: String,

    /// Minimum audit level: "debug", "info", "warning", "error", "critical"
    #[serde(default = "default_audit_level")]
    pub level: String,

    /// Log authentication events
    #[serde(default = "default_true")]
    pub log_authentication: bool,

    /// Log authorization events
    #[serde(default = "default_true")]
    pub log_authorization: bool,

    /// Log data modifications
    #[serde(default = "default_true")]
    pub log_modifications: bool,

    /// Log connection events
    #[serde(default = "default_true")]
    pub log_connections: bool,
}

/// Access control settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlSettings {
    /// Enable access control
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Default access policy: "allow" or "deny"
    #[serde(default = "default_access_policy")]
    pub default_policy: String,

    /// ACI rules file path
    #[serde(default)]
    pub rules_file: Option<PathBuf>,
}

/// Performance tuning settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSettings {
    /// Worker threads (0 = auto)
    #[serde(default)]
    pub worker_threads: usize,

    /// Enable schema validation
    #[serde(default = "default_true")]
    pub schema_validation: bool,

    /// Enable indexing
    #[serde(default = "default_true")]
    pub indexing_enabled: bool,

    /// Cache size (entries)
    #[serde(default = "default_cache_size")]
    pub cache_size: usize,

    /// Enable query optimization
    #[serde(default = "default_true")]
    pub query_optimization: bool,
}

// Default value functions
fn default_bind_address() -> String {
    "127.0.0.1".to_string()
}
fn default_ldap_port() -> u16 {
    1389
}
fn default_ldaps_port() -> u16 {
    1636
}
fn default_hostname() -> String {
    "localhost".to_string()
}
fn default_server_runtime() -> String {
    "legacy".to_string()
}
fn default_replica_id() -> u16 {
    1
}
fn default_base_dn() -> String {
    "dc=example,dc=com".to_string()
}
fn default_root_user_dn() -> String {
    "cn=admin".to_string()
}
fn default_root_password() -> String {
    "secret".to_string()
}
fn default_organization_name() -> String {
    "Example Organization".to_string()
}
fn default_read_buffer_size() -> usize {
    4096
}
fn default_operation_timeout_secs() -> u64 {
    300
}
fn default_cleanup_interval_secs() -> u64 {
    60
}
fn default_max_concurrent_operations() -> usize {
    100
}

fn default_backend_type() -> String {
    "lmdb".to_string()
}
fn default_data_directory() -> PathBuf {
    PathBuf::from("./data")
}
fn default_lmdb_max_size() -> usize {
    10 * 1024 * 1024 * 1024
} // 10 GB
fn default_lmdb_max_readers() -> u32 {
    126
}
fn default_indexed_attributes() -> Vec<String> {
    vec![
        "cn".to_string(),
        "uid".to_string(),
        "mail".to_string(),
        "objectClass".to_string(),
    ]
}

fn default_cert_file() -> PathBuf {
    PathBuf::from("certs/server.crt")
}
fn default_key_file() -> PathBuf {
    PathBuf::from("certs/server.key")
}
fn default_min_tls_version() -> String {
    "1.2".to_string()
}

fn default_max_connections() -> usize {
    1000
}
fn default_max_connections_per_ip() -> usize {
    10
}
fn default_max_operations_per_connection() -> usize {
    100
}
fn default_max_memory_per_connection() -> usize {
    10 * 1024 * 1024
} // 10 MB
fn default_max_total_memory() -> usize {
    1024 * 1024 * 1024
} // 1 GB
fn default_connection_idle_timeout_secs() -> u64 {
    600
}

fn default_true() -> bool {
    true
}
fn default_global_requests_per_second() -> u32 {
    1000
}
fn default_per_client_requests_per_second() -> u32 {
    100
}
fn default_burst_size() -> u32 {
    50
}
fn default_window_duration_secs() -> u64 {
    1
}
fn default_adaptive_threshold() -> f64 {
    0.8
}
fn default_adaptive_multiplier() -> f64 {
    0.5
}
fn default_auto_ban_threshold() -> u32 {
    100
}
fn default_auto_ban_duration_secs() -> u64 {
    300
}

fn default_bind_limit() -> u32 {
    10
}
fn default_search_limit() -> u32 {
    50
}
fn default_modify_limit() -> u32 {
    20
}
fn default_add_limit() -> u32 {
    20
}
fn default_delete_limit() -> u32 {
    10
}
fn default_modifydn_limit() -> u32 {
    10
}
fn default_compare_limit() -> u32 {
    30
}
fn default_extended_limit() -> u32 {
    20
}

fn default_operation_limits() -> OperationLimits {
    OperationLimits {
        bind: 10,
        search: 50,
        modify: 20,
        add: 20,
        delete: 10,
        modifydn: 10,
        compare: 30,
        extended: 20,
    }
}

fn default_replication_mode() -> String {
    "provider".to_string()
}
fn default_changelog_capacity() -> usize {
    10000
}
fn default_replication_max_batch_size() -> usize {
    100
}
fn default_sync_interval_secs() -> u64 {
    60
}
fn default_max_retry_attempts() -> u32 {
    3
}
fn default_retry_delay_secs() -> u64 {
    5
}
fn default_heartbeat_interval_secs() -> u64 {
    30
}
fn default_max_concurrent_consumers() -> usize {
    10
}
fn default_consumer_timeout_secs() -> u64 {
    300
}
fn default_provider_timeout_secs() -> u64 {
    30
}
fn default_state_persistence_timeout_secs() -> u64 {
    10
}
fn default_change_buffer_size() -> usize {
    1000
}
fn default_replication_state_storage_path() -> PathBuf {
    PathBuf::from("./data/replication_state")
}

fn default_metrics_address() -> String {
    "127.0.0.1".to_string()
}
fn default_metrics_port() -> u16 {
    9090
}
fn default_metrics_path() -> String {
    "/metrics".to_string()
}
fn default_health_path() -> String {
    "/health".to_string()
}

fn default_audit_log_file() -> PathBuf {
    PathBuf::from("./logs/audit.log")
}
fn default_audit_format() -> String {
    "json".to_string()
}
fn default_audit_level() -> String {
    "info".to_string()
}

fn default_access_policy() -> String {
    "deny".to_string()
}

fn default_cache_size() -> usize {
    1000
}

// Default implementations
impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            bind_address: default_bind_address(),
            ldap_port: default_ldap_port(),
            ldaps_port: default_ldaps_port(),
            hostname: default_hostname(),
            runtime: default_server_runtime(),
            replica_id: default_replica_id(),
            base_dn: default_base_dn(),
            root_user_dn: default_root_user_dn(),
            root_password: default_root_password(),
            root_password_env: None,
            root_password_file: None,
            organization_name: default_organization_name(),
            read_buffer_size: default_read_buffer_size(),
            operation_timeout_secs: default_operation_timeout_secs(),
            cleanup_interval_secs: default_cleanup_interval_secs(),
            max_concurrent_operations: default_max_concurrent_operations(),
        }
    }
}

impl Default for BackendSettings {
    fn default() -> Self {
        Self {
            backend_type: default_backend_type(),
            data_directory: default_data_directory(),
            lmdb_max_size: default_lmdb_max_size(),
            lmdb_max_readers: default_lmdb_max_readers(),
            import_sample_data: false,
            indexed_attributes: default_indexed_attributes(),
        }
    }
}

impl Default for TlsSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            cert_file: default_cert_file(),
            key_file: default_key_file(),
            ca_file: None,
            require_client_cert: false,
            min_tls_version: default_min_tls_version(),
        }
    }
}

impl Default for ResourceSettings {
    fn default() -> Self {
        Self {
            max_connections: default_max_connections(),
            max_connections_per_ip: default_max_connections_per_ip(),
            max_operations_per_connection: default_max_operations_per_connection(),
            max_memory_per_connection: default_max_memory_per_connection(),
            max_total_memory: default_max_total_memory(),
            connection_idle_timeout_secs: default_connection_idle_timeout_secs(),
        }
    }
}

impl Default for RateLimitSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            global_requests_per_second: default_global_requests_per_second(),
            per_client_requests_per_second: default_per_client_requests_per_second(),
            burst_size: default_burst_size(),
            window_duration_secs: default_window_duration_secs(),
            adaptive_enabled: true,
            adaptive_threshold: default_adaptive_threshold(),
            adaptive_multiplier: default_adaptive_multiplier(),
            auto_ban_threshold: default_auto_ban_threshold(),
            auto_ban_duration_secs: default_auto_ban_duration_secs(),
            blacklist: Vec::new(),
            whitelist: Vec::new(),
            operation_limits: default_operation_limits(),
        }
    }
}

impl Default for ReplicationSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: default_replication_mode(),
            provider_url: None,
            bind_dn: None,
            bind_password: None,
            bind_password_env: None,
            bind_password_file: None,
            changelog_capacity: default_changelog_capacity(),
            changelog_enabled: true,
            max_batch_size: default_replication_max_batch_size(),
            sync_interval_secs: default_sync_interval_secs(),
            max_retry_attempts: default_max_retry_attempts(),
            retry_delay_secs: default_retry_delay_secs(),
            enable_change_listening: true,
            enable_streaming: true,
            heartbeat_interval_secs: default_heartbeat_interval_secs(),
            max_concurrent_consumers: default_max_concurrent_consumers(),
            consumer_timeout_secs: default_consumer_timeout_secs(),
            provider_timeout_secs: default_provider_timeout_secs(),
            state_persistence_timeout_secs: default_state_persistence_timeout_secs(),
            change_buffer_size: default_change_buffer_size(),
            state_storage_path: default_replication_state_storage_path(),
            stream_port: 0,
        }
    }
}

impl Default for MonitoringSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            metrics_address: default_metrics_address(),
            metrics_port: default_metrics_port(),
            metrics_path: default_metrics_path(),
            health_path: default_health_path(),
        }
    }
}

impl Default for AuditSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            log_file: default_audit_log_file(),
            format: default_audit_format(),
            level: default_audit_level(),
            log_authentication: true,
            log_authorization: true,
            log_modifications: true,
            log_connections: true,
        }
    }
}

impl Default for AccessControlSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            default_policy: default_access_policy(),
            rules_file: None,
        }
    }
}

impl Default for PerformanceSettings {
    fn default() -> Self {
        Self {
            worker_threads: 0,
            schema_validation: true,
            indexing_enabled: true,
            cache_size: default_cache_size(),
            query_optimization: true,
        }
    }
}

fn trim_secret_value(secret: String) -> String {
    secret.trim_end_matches(['\n', '\r']).to_string()
}

fn resolve_secret_source(
    field_name: &str,
    inline_secret: Option<&str>,
    env_var: Option<&str>,
    file_path: Option<&std::path::Path>,
) -> Result<Option<String>, ConfigError> {
    let inline_secret = inline_secret.filter(|secret| !secret.is_empty());
    let configured_sources = usize::from(inline_secret.is_some())
        + usize::from(env_var.is_some())
        + usize::from(file_path.is_some());

    if configured_sources > 1 {
        return Err(ConfigError::ValidationError(format!(
            "{field_name} may only be configured with one of the inline value, *_env, or *_file options"
        )));
    }

    if let Some(secret) = inline_secret {
        return Ok(Some(secret.to_string()));
    }

    if let Some(env_var) = env_var {
        let secret = std::env::var(env_var).map_err(|_| {
            ConfigError::ValidationError(format!(
                "{field_name}_env references missing environment variable {env_var}"
            ))
        })?;
        let secret = trim_secret_value(secret);
        if secret.is_empty() {
            return Err(ConfigError::ValidationError(format!(
                "{field_name}_env resolved to an empty value"
            )));
        }
        return Ok(Some(secret));
    }

    if let Some(file_path) = file_path {
        let secret = std::fs::read_to_string(file_path).map_err(|err| {
            ConfigError::ValidationError(format!(
                "{field_name}_file could not be read from {}: {err}",
                file_path.display()
            ))
        })?;
        let secret = trim_secret_value(secret);
        if secret.is_empty() {
            return Err(ConfigError::ValidationError(format!(
                "{field_name}_file resolved to an empty value"
            )));
        }
        return Ok(Some(secret));
    }

    Ok(None)
}

fn redacted_secret_display(
    inline_secret: Option<&str>,
    env_var: Option<&str>,
    file_path: Option<&std::path::Path>,
) -> String {
    if inline_secret.is_some_and(|secret| !secret.is_empty()) {
        "<redacted>".to_string()
    } else if let Some(env_var) = env_var {
        format!("<redacted via env:{env_var}>")
    } else if let Some(file_path) = file_path {
        format!("<redacted via file:{}>", file_path.display())
    } else {
        "<unset>".to_string()
    }
}

impl fmt::Debug for ServerSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerSettings")
            .field("bind_address", &self.bind_address)
            .field("ldap_port", &self.ldap_port)
            .field("ldaps_port", &self.ldaps_port)
            .field("hostname", &self.hostname)
            .field("runtime", &self.runtime)
            .field("replica_id", &self.replica_id)
            .field("base_dn", &self.base_dn)
            .field("root_user_dn", &self.root_user_dn)
            .field(
                "root_password",
                &redacted_secret_display(
                    Some(&self.root_password),
                    self.root_password_env.as_deref(),
                    self.root_password_file.as_deref(),
                ),
            )
            .field("root_password_env", &self.root_password_env)
            .field("root_password_file", &self.root_password_file)
            .field("organization_name", &self.organization_name)
            .field("read_buffer_size", &self.read_buffer_size)
            .field("operation_timeout_secs", &self.operation_timeout_secs)
            .field("cleanup_interval_secs", &self.cleanup_interval_secs)
            .field("max_concurrent_operations", &self.max_concurrent_operations)
            .finish()
    }
}

impl fmt::Debug for ReplicationSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReplicationSettings")
            .field("enabled", &self.enabled)
            .field("mode", &self.mode)
            .field("provider_url", &self.provider_url)
            .field("bind_dn", &self.bind_dn)
            .field(
                "bind_password",
                &redacted_secret_display(
                    self.bind_password.as_deref(),
                    self.bind_password_env.as_deref(),
                    self.bind_password_file.as_deref(),
                ),
            )
            .field("bind_password_env", &self.bind_password_env)
            .field("bind_password_file", &self.bind_password_file)
            .field("changelog_capacity", &self.changelog_capacity)
            .field("changelog_enabled", &self.changelog_enabled)
            .field("max_batch_size", &self.max_batch_size)
            .field("sync_interval_secs", &self.sync_interval_secs)
            .field("max_retry_attempts", &self.max_retry_attempts)
            .field("retry_delay_secs", &self.retry_delay_secs)
            .field("enable_change_listening", &self.enable_change_listening)
            .field("enable_streaming", &self.enable_streaming)
            .field("heartbeat_interval_secs", &self.heartbeat_interval_secs)
            .field("max_concurrent_consumers", &self.max_concurrent_consumers)
            .field("consumer_timeout_secs", &self.consumer_timeout_secs)
            .field("provider_timeout_secs", &self.provider_timeout_secs)
            .field(
                "state_persistence_timeout_secs",
                &self.state_persistence_timeout_secs,
            )
            .field("change_buffer_size", &self.change_buffer_size)
            .field("state_storage_path", &self.state_storage_path)
            .field("stream_port", &self.stream_port)
            .finish()
    }
}

impl ServerConfig {
    fn normalize_compatibility_fields(&mut self) {
        self.replication.mode = self.replication.mode.to_lowercase();
    }

    fn normalize_secret_placeholders(&mut self) {
        let uses_external_root_secret =
            self.server.root_password_env.is_some() || self.server.root_password_file.is_some();
        if uses_external_root_secret && self.server.root_password == default_root_password() {
            self.server.root_password.clear();
        }
    }

    /// Resolve the configured root password without serializing it back into config files.
    pub fn resolved_root_password(&self) -> Result<String, ConfigError> {
        resolve_secret_source(
            "server.root_password",
            Some(&self.server.root_password),
            self.server.root_password_env.as_deref(),
            self.server.root_password_file.as_deref(),
        )?
        .ok_or_else(|| {
            ConfigError::ValidationError(
                "server.root_password requires an inline value, *_env, or *_file source"
                    .to_string(),
            )
        })
    }

    /// Resolve the configured replication bind password if one is configured.
    pub fn resolved_replication_bind_password(&self) -> Result<Option<String>, ConfigError> {
        resolve_secret_source(
            "replication.bind_password",
            self.replication.bind_password.as_deref(),
            self.replication.bind_password_env.as_deref(),
            self.replication.bind_password_file.as_deref(),
        )
    }

    /// Convert ServerConfig to FsmServerConfig for FSM server usage
    pub fn to_fsm_server_config(&self) -> crate::fsm_server::FsmServerConfig {
        use crate::connection_pool::ResourceLimits;

        crate::fsm_server::FsmServerConfig {
            operation_timeout: self.operation_timeout(),
            cleanup_interval: self.cleanup_interval(),
            read_buffer_size: self.server.read_buffer_size,
            max_concurrent_operations: self.server.max_concurrent_operations,
            resource_limits: ResourceLimits {
                max_connections: self.resources.max_connections,
                max_connections_per_ip: self.resources.max_connections_per_ip,
                max_operations_per_connection: self.resources.max_operations_per_connection,
                max_memory_per_connection: self.resources.max_memory_per_connection,
                max_total_memory: self.resources.max_total_memory,
                connection_idle_timeout: self.connection_idle_timeout(),
            },
            rate_limit_config: self.to_rate_limit_config(),
            rate_limiting_enabled: self.rate_limit.enabled,
        }
    }

    /// Convert to RateLimitConfig
    pub fn to_rate_limit_config(&self) -> crate::rate_limit::RateLimitConfig {
        use crate::rate_limit::{OperationType, RateLimitConfig as RlConfig};
        use std::collections::HashMap;

        let mut operation_limits = HashMap::new();
        operation_limits.insert(OperationType::Bind, self.rate_limit.operation_limits.bind);
        operation_limits.insert(
            OperationType::Search,
            self.rate_limit.operation_limits.search,
        );
        operation_limits.insert(
            OperationType::Modify,
            self.rate_limit.operation_limits.modify,
        );
        operation_limits.insert(OperationType::Add, self.rate_limit.operation_limits.add);
        operation_limits.insert(
            OperationType::Delete,
            self.rate_limit.operation_limits.delete,
        );
        operation_limits.insert(
            OperationType::ModifyDN,
            self.rate_limit.operation_limits.modifydn,
        );
        operation_limits.insert(
            OperationType::Compare,
            self.rate_limit.operation_limits.compare,
        );
        operation_limits.insert(
            OperationType::Extended,
            self.rate_limit.operation_limits.extended,
        );

        let blacklist: Vec<std::net::IpAddr> = self
            .rate_limit
            .blacklist
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();

        let whitelist: Vec<std::net::IpAddr> = self
            .rate_limit
            .whitelist
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();

        RlConfig {
            global_requests_per_second: self.rate_limit.global_requests_per_second,
            per_client_requests_per_second: self.rate_limit.per_client_requests_per_second,
            operation_limits,
            burst_size: self.rate_limit.burst_size,
            window_duration: self.rate_limit_window_duration(),
            adaptive_enabled: self.rate_limit.adaptive_enabled,
            adaptive_threshold: self.rate_limit.adaptive_threshold,
            adaptive_multiplier: self.rate_limit.adaptive_multiplier,
            blacklist,
            whitelist,
            auto_ban_threshold: self.rate_limit.auto_ban_threshold,
            auto_ban_duration: self.auto_ban_duration(),
        }
    }

    /// Get LDAP bind address
    pub fn ldap_bind_address(&self) -> String {
        format!("{}:{}", self.server.bind_address, self.server.ldap_port)
    }

    /// Get LDAPS bind address
    pub fn ldaps_bind_address(&self) -> String {
        format!("{}:{}", self.server.bind_address, self.server.ldaps_port)
    }

    /// Load configuration from a TOML file with environment variable overrides
    pub fn from_file(path: &str) -> Result<Self, ConfigError> {
        use config::{Config, Environment, File};

        let config = Config::builder()
            // Load from file
            .add_source(File::with_name(path).required(true))
            // Override with environment variables (OPENDR_SERVER__LDAP_PORT=1389)
            .add_source(Environment::with_prefix("OPENDR").separator("__"))
            .build()
            .map_err(|e| ConfigError::LoadError(e.to_string()))?;

        let mut config: Self = config
            .try_deserialize()
            .map_err(|e| ConfigError::ParseError(e.to_string()))?;
        config.normalize_compatibility_fields();
        config.normalize_secret_placeholders();
        Ok(config)
    }

    /// Load configuration from TOML string
    pub fn from_toml_str(toml: &str) -> Result<Self, ConfigError> {
        let mut config: Self =
            toml::from_str(toml).map_err(|e| ConfigError::ParseError(e.to_string()))?;
        config.normalize_compatibility_fields();
        config.normalize_secret_placeholders();
        Ok(config)
    }

    /// Validate configuration values
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate ports
        if self.server.ldap_port == 0 {
            return Err(ConfigError::ValidationError(
                "LDAP port cannot be 0".to_string(),
            ));
        }
        if self.server.ldaps_port == 0 && self.tls.enabled {
            return Err(ConfigError::ValidationError(
                "LDAPS port cannot be 0 when TLS is enabled".to_string(),
            ));
        }
        if self.server.ldap_port == self.server.ldaps_port {
            return Err(ConfigError::ValidationError(
                "LDAP and LDAPS ports must be different".to_string(),
            ));
        }

        // Validate base DN
        if self.server.base_dn.is_empty() {
            return Err(ConfigError::ValidationError(
                "Base DN cannot be empty".to_string(),
            ));
        }
        if !["legacy", "fsm"].contains(&self.server.runtime.as_str()) {
            return Err(ConfigError::ValidationError(format!(
                "server.runtime must be one of: legacy, fsm (got {})",
                self.server.runtime
            )));
        }
        let _ = self.resolved_root_password()?;
        if self.server.replica_id == 0 {
            return Err(ConfigError::ValidationError(
                "replica_id must be between 1 and 65535".to_string(),
            ));
        }

        // Validate backend type
        if !["memory", "lmdb"].contains(&self.backend.backend_type.to_lowercase().as_str()) {
            return Err(ConfigError::ValidationError(format!(
                "Invalid backend type: {}",
                self.backend.backend_type
            )));
        }

        // Validate TLS settings
        if self.tls.enabled {
            if !self.tls.cert_file.exists() {
                return Err(ConfigError::ValidationError(format!(
                    "TLS certificate file not found: {:?}",
                    self.tls.cert_file
                )));
            }
            if !self.tls.key_file.exists() {
                return Err(ConfigError::ValidationError(format!(
                    "TLS key file not found: {:?}",
                    self.tls.key_file
                )));
            }
            if !["1.2", "1.3"].contains(&self.tls.min_tls_version.as_str()) {
                return Err(ConfigError::ValidationError(format!(
                    "Invalid TLS version: {}",
                    self.tls.min_tls_version
                )));
            }
        }

        // Validate resource limits
        if self.resources.max_connections == 0 {
            return Err(ConfigError::ValidationError(
                "max_connections must be > 0".to_string(),
            ));
        }
        if self.resources.max_connections_per_ip > self.resources.max_connections {
            return Err(ConfigError::ValidationError(
                "max_connections_per_ip cannot exceed max_connections".to_string(),
            ));
        }

        // Validate rate limit settings
        if self.rate_limit.enabled {
            if self.rate_limit.adaptive_threshold < 0.0 || self.rate_limit.adaptive_threshold > 1.0
            {
                return Err(ConfigError::ValidationError(
                    "adaptive_threshold must be between 0.0 and 1.0".to_string(),
                ));
            }
            if self.rate_limit.adaptive_multiplier < 0.0
                || self.rate_limit.adaptive_multiplier > 1.0
            {
                return Err(ConfigError::ValidationError(
                    "adaptive_multiplier must be between 0.0 and 1.0".to_string(),
                ));
            }

            // Validate blacklist/whitelist IPs
            for ip in &self.rate_limit.blacklist {
                ip.parse::<IpAddr>().map_err(|_| {
                    ConfigError::ValidationError(format!("Invalid blacklist IP: {}", ip))
                })?;
            }
            for ip in &self.rate_limit.whitelist {
                ip.parse::<IpAddr>().map_err(|_| {
                    ConfigError::ValidationError(format!("Invalid whitelist IP: {}", ip))
                })?;
            }
        }

        // Validate replication settings
        if self.replication.enabled {
            if !["provider", "consumer", "both"].contains(&self.replication.mode.as_str()) {
                return Err(ConfigError::ValidationError(format!(
                    "Invalid replication mode: {}",
                    self.replication.mode
                )));
            }
            if self.replication.mode == "consumer" || self.replication.mode == "both" {
                if self.replication.provider_url.is_none() {
                    return Err(ConfigError::ValidationError(
                        "provider_url required for consumer mode".to_string(),
                    ));
                }
                let _ = self.resolved_replication_bind_password()?;
            }
            if self.replication.sync_interval_secs == 0 {
                return Err(ConfigError::ValidationError(
                    "sync_interval_secs must be > 0".to_string(),
                ));
            }
            if self.replication.max_retry_attempts == 0 {
                return Err(ConfigError::ValidationError(
                    "max_retry_attempts must be > 0".to_string(),
                ));
            }
            if self.replication.max_batch_size == 0 {
                return Err(ConfigError::ValidationError(
                    "max_batch_size must be > 0".to_string(),
                ));
            }
            if self.replication.retry_delay_secs == 0 {
                return Err(ConfigError::ValidationError(
                    "retry_delay_secs must be > 0".to_string(),
                ));
            }
            if self.replication.heartbeat_interval_secs == 0 {
                return Err(ConfigError::ValidationError(
                    "heartbeat_interval_secs must be > 0".to_string(),
                ));
            }
            if self.replication.max_concurrent_consumers == 0 {
                return Err(ConfigError::ValidationError(
                    "max_concurrent_consumers must be > 0".to_string(),
                ));
            }
            if self.replication.consumer_timeout_secs == 0 {
                return Err(ConfigError::ValidationError(
                    "consumer_timeout_secs must be > 0".to_string(),
                ));
            }
            if self.replication.provider_timeout_secs == 0 {
                return Err(ConfigError::ValidationError(
                    "provider_timeout_secs must be > 0".to_string(),
                ));
            }
            if self.replication.state_persistence_timeout_secs == 0 {
                return Err(ConfigError::ValidationError(
                    "state_persistence_timeout_secs must be > 0".to_string(),
                ));
            }
            if self.replication.change_buffer_size == 0 {
                return Err(ConfigError::ValidationError(
                    "change_buffer_size must be > 0".to_string(),
                ));
            }
            if self.replication.stream_port != 0
                && (self.replication.stream_port == self.server.ldap_port
                    || self.replication.stream_port == self.server.ldaps_port)
            {
                return Err(ConfigError::ValidationError(
                    "replication stream_port must differ from LDAP and LDAPS ports".to_string(),
                ));
            }
        }

        // Validate audit settings
        if self.audit.enabled {
            if !["json", "syslog", "text"].contains(&self.audit.format.as_str()) {
                return Err(ConfigError::ValidationError(format!(
                    "Invalid audit format: {}",
                    self.audit.format
                )));
            }
            if !["debug", "info", "warning", "error", "critical"]
                .contains(&self.audit.level.as_str())
            {
                return Err(ConfigError::ValidationError(format!(
                    "Invalid audit level: {}",
                    self.audit.level
                )));
            }
        }

        // Validate access control settings
        if !["allow", "deny"].contains(&self.access_control.default_policy.as_str()) {
            return Err(ConfigError::ValidationError(format!(
                "Invalid access policy: {}",
                self.access_control.default_policy
            )));
        }

        Ok(())
    }

    /// Validate that the selected runtime is supported by the shipped `opendr` binary.
    pub fn validate_for_shipped_binary(&self) -> Result<(), ConfigError> {
        match self.server.runtime.as_str() {
            "legacy" => {
                if self.rate_limit.burst_size != default_burst_size() {
                    return Err(ConfigError::ValidationError(
                        "rate_limit.burst_size is not supported by the shipped legacy runtime yet; use the default value"
                            .to_string(),
                    ));
                }
                Ok(())
            }
            "fsm" => Err(ConfigError::ValidationError(
                "server.runtime = \"fsm\" is not supported by the shipped opendr binary yet; use \"legacy\""
                    .to_string(),
            )),
            other => Err(ConfigError::ValidationError(format!(
                "server.runtime must be one of: legacy, fsm (got {})",
                other
            ))),
        }
    }

    /// Get operation timeout as Duration
    pub fn operation_timeout(&self) -> Duration {
        Duration::from_secs(self.server.operation_timeout_secs)
    }

    /// Get cleanup interval as Duration
    pub fn cleanup_interval(&self) -> Duration {
        Duration::from_secs(self.server.cleanup_interval_secs)
    }

    /// Get connection idle timeout as Duration
    pub fn connection_idle_timeout(&self) -> Duration {
        Duration::from_secs(self.resources.connection_idle_timeout_secs)
    }

    /// Get rate limit window duration as Duration
    pub fn rate_limit_window_duration(&self) -> Duration {
        Duration::from_secs(self.rate_limit.window_duration_secs)
    }

    /// Get auto-ban duration as Duration
    pub fn auto_ban_duration(&self) -> Duration {
        Duration::from_secs(self.rate_limit.auto_ban_duration_secs)
    }

    /// Get sync interval as Duration
    pub fn sync_interval(&self) -> Duration {
        Duration::from_secs(self.replication.sync_interval_secs)
    }

    /// Export configuration to TOML string
    pub fn to_toml_string(&self) -> Result<String, ConfigError> {
        toml::to_string_pretty(self).map_err(|e| ConfigError::ParseError(e.to_string()))
    }

    /// Save configuration to file
    pub fn save_to_file(&self, path: &str) -> Result<(), ConfigError> {
        let toml = self.to_toml_string()?;
        std::fs::write(path, toml)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::{Mutex, OnceLock};
    use tempfile::NamedTempFile;

    fn env_lock() -> &'static Mutex<()> {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        ENV_LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn test_default_config() {
        let config = ServerConfig::default();
        assert_eq!(config.server.ldap_port, 1389);
        assert_eq!(config.server.ldaps_port, 1636);
        assert_eq!(config.server.bind_address, "127.0.0.1");
        assert_eq!(config.server.runtime, "legacy");
        assert_eq!(config.server.replica_id, 1);
        assert!(config.rate_limit.enabled);
        assert!(config.monitoring.enabled);
    }

    #[test]
    fn test_config_validation_success() {
        let config = ServerConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validation_invalid_port() {
        let mut config = ServerConfig::default();
        config.server.ldap_port = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_same_ports() {
        let mut config = ServerConfig::default();
        config.server.ldap_port = 1389;
        config.server.ldaps_port = 1389;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_empty_base_dn() {
        let mut config = ServerConfig::default();
        config.server.base_dn = String::new();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_invalid_replica_id() {
        let mut config = ServerConfig::default();
        config.server.replica_id = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_invalid_backend() {
        let mut config = ServerConfig::default();
        config.backend.backend_type = "invalid".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_invalid_adaptive_threshold() {
        let mut config = ServerConfig::default();
        config.rate_limit.adaptive_threshold = 1.5;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_invalid_ip() {
        let mut config = ServerConfig::default();
        config.rate_limit.blacklist = vec!["not-an-ip".to_string()];
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_to_toml() {
        let config = ServerConfig::default();
        let toml = config.to_toml_string();
        assert!(toml.is_ok());
        let toml_str = toml.unwrap();
        assert!(toml_str.contains("[server]"));
        assert!(toml_str.contains("[backend]"));
        assert!(toml_str.contains("[rate_limit]"));
    }

    #[test]
    fn test_config_from_toml() {
        let toml = r#"
[server]
bind_address = "0.0.0.0"
ldap_port = 389
runtime = "fsm"
replica_id = 7
base_dn = "dc=test,dc=org"

[backend]
backend_type = "memory"
        "#;

        let config = ServerConfig::from_toml_str(toml).unwrap();
        assert_eq!(config.server.bind_address, "0.0.0.0");
        assert_eq!(config.server.ldap_port, 389);
        assert_eq!(config.server.runtime, "fsm");
        assert_eq!(config.server.replica_id, 7);
        assert_eq!(config.server.base_dn, "dc=test,dc=org");
        assert_eq!(config.backend.backend_type, "memory");
    }

    #[test]
    fn test_root_password_file_resolution_and_serialization() {
        let mut secret_file = NamedTempFile::new().unwrap();
        writeln!(secret_file, "{{SSHA512}}file-backed-secret").unwrap();

        let toml = format!(
            r#"
[server]
root_password_file = "{}"
"#,
            secret_file.path().display()
        );

        let config = ServerConfig::from_toml_str(&toml).unwrap();
        assert_eq!(config.server.root_password, "");
        assert_eq!(
            config.resolved_root_password().unwrap(),
            "{SSHA512}file-backed-secret"
        );
        assert!(config.validate().is_ok());

        let serialized = config.to_toml_string().unwrap();
        assert!(serialized.contains("root_password_file"));
        assert!(!serialized.contains("file-backed-secret"));

        let debug_output = format!("{config:?}");
        assert!(!debug_output.contains("file-backed-secret"));
        assert!(debug_output.contains("<redacted via file:"));
    }

    #[test]
    fn test_replication_bind_password_env_resolution_and_debug_redaction() {
        let _guard = env_lock().lock().unwrap();
        let env_name = format!("OPENDR_TEST_BIND_PASSWORD_{}", std::process::id());
        unsafe {
            std::env::set_var(&env_name, "env-backed-secret");
        }

        let toml = format!(
            r#"
[replication]
enabled = true
mode = "consumer"
provider_url = "ldap://provider.example.com:389"
bind_password_env = "{env_name}"
"#
        );

        let config = ServerConfig::from_toml_str(&toml).unwrap();
        assert_eq!(
            config.resolved_replication_bind_password().unwrap(),
            Some("env-backed-secret".to_string())
        );
        assert!(config.validate().is_ok());

        let debug_output = format!("{config:?}");
        assert!(!debug_output.contains("env-backed-secret"));
        assert!(debug_output.contains(&format!("<redacted via env:{env_name}>")));

        unsafe {
            std::env::remove_var(&env_name);
        }
    }

    #[test]
    fn test_validation_rejects_multiple_root_password_sources() {
        let toml = r#"
[server]
root_password = "inline-secret"
root_password_env = "OPENDR_TEST_ROOT_PASSWORD"
"#;

        let config = ServerConfig::from_toml_str(toml).unwrap();
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("server.root_password may only be configured"));
    }

    #[test]
    fn test_duration_helpers() {
        let config = ServerConfig::default();
        assert_eq!(config.operation_timeout(), Duration::from_secs(300));
        assert_eq!(config.cleanup_interval(), Duration::from_secs(60));
        assert_eq!(config.connection_idle_timeout(), Duration::from_secs(600));
    }

    #[test]
    fn test_operation_limits_default() {
        let limits = default_operation_limits();
        assert_eq!(limits.bind, 10);
        assert_eq!(limits.search, 50);
        assert_eq!(limits.modify, 20);
    }

    #[test]
    fn test_invalid_replication_mode() {
        let mut config = ServerConfig::default();
        config.replication.enabled = true;
        config.replication.mode = "invalid".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_invalid_server_runtime() {
        let mut config = ServerConfig::default();
        config.server.runtime = "unsupported".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_shipped_binary_rejects_fsm_runtime() {
        let mut config = ServerConfig::default();
        config.server.runtime = "fsm".to_string();
        let error = config
            .validate_for_shipped_binary()
            .unwrap_err()
            .to_string();
        assert!(error.contains("not supported by the shipped opendr binary"));
    }

    #[test]
    fn test_consumer_requires_provider_url() {
        let mut config = ServerConfig::default();
        config.replication.enabled = true;
        config.replication.mode = "consumer".to_string();
        config.replication.provider_url = None;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_invalid_audit_format() {
        let mut config = ServerConfig::default();
        config.audit.format = "invalid".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_invalid_access_policy() {
        let mut config = ServerConfig::default();
        config.access_control.default_policy = "invalid".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_to_fsm_server_config() {
        let config = ServerConfig::default();
        let fsm_config = config.to_fsm_server_config();

        assert_eq!(fsm_config.operation_timeout, config.operation_timeout());
        assert_eq!(fsm_config.cleanup_interval, config.cleanup_interval());
        assert_eq!(fsm_config.read_buffer_size, config.server.read_buffer_size);
        assert_eq!(
            fsm_config.max_concurrent_operations,
            config.server.max_concurrent_operations
        );
        assert_eq!(fsm_config.rate_limiting_enabled, config.rate_limit.enabled);
        assert_eq!(
            fsm_config.resource_limits.max_connections,
            config.resources.max_connections
        );
    }

    #[test]
    fn test_to_rate_limit_config() {
        let config = ServerConfig::default();
        let rate_config = config.to_rate_limit_config();

        assert_eq!(
            rate_config.global_requests_per_second,
            config.rate_limit.global_requests_per_second
        );
        assert_eq!(
            rate_config.per_client_requests_per_second,
            config.rate_limit.per_client_requests_per_second
        );
        assert_eq!(rate_config.burst_size, config.rate_limit.burst_size);
        assert_eq!(
            rate_config.adaptive_enabled,
            config.rate_limit.adaptive_enabled
        );
        assert_eq!(
            rate_config.adaptive_threshold,
            config.rate_limit.adaptive_threshold
        );
    }

    #[test]
    fn test_bind_addresses() {
        let mut config = ServerConfig::default();
        config.server.bind_address = "0.0.0.0".to_string();
        config.server.ldap_port = 389;
        config.server.ldaps_port = 636;

        assert_eq!(config.ldap_bind_address(), "0.0.0.0:389");
        assert_eq!(config.ldaps_bind_address(), "0.0.0.0:636");
    }
}

//! Integration tests for configuration system
//!
//! These tests verify that the configuration system works correctly
//! with file loading, environment variables, and validation.

use opendr::config::ServerConfig;
use std::env;
use std::fs;
use std::path::PathBuf;

#[test]
fn test_load_default_config() {
    let config = ServerConfig::default();
    assert!(config.validate().is_ok());
    assert_eq!(config.server.ldap_port, 1389);
    assert_eq!(config.server.base_dn, "dc=example,dc=com");
    assert!(config.rate_limit.enabled);
    assert!(config.replication.enable_change_listening);
    assert!(config.replication.changelog_enabled);
    assert_eq!(config.replication.max_batch_size, 100);
    assert_eq!(config.replication.max_retry_attempts, 3);
    assert_eq!(config.replication.retry_delay_secs, 5);
    assert!(config.replication.enable_streaming);
    assert_eq!(config.replication.heartbeat_interval_secs, 30);
    assert_eq!(config.replication.max_concurrent_consumers, 10);
    assert_eq!(config.replication.consumer_timeout_secs, 300);
    assert_eq!(config.replication.provider_timeout_secs, 30);
    assert_eq!(config.replication.state_persistence_timeout_secs, 10);
    assert_eq!(config.replication.change_buffer_size, 1000);
    assert_eq!(
        config.replication.state_storage_path,
        PathBuf::from("./data/replication_state")
    );
}

#[test]
fn test_load_from_toml_string() {
    let toml = r#"
[server]
bind_address = "0.0.0.0"
ldap_port = 389
ldaps_port = 636
base_dn = "dc=test,dc=local"
hostname = "ldap.test.local"

[backend]
backend_type = "memory"
data_directory = "/var/lib/opendr"

[rate_limit]
enabled = false
global_requests_per_second = 500

[monitoring]
enabled = true
metrics_port = 8080
    "#;

    let config = ServerConfig::from_toml_str(toml).unwrap();

    assert_eq!(config.server.bind_address, "0.0.0.0");
    assert_eq!(config.server.ldap_port, 389);
    assert_eq!(config.server.ldaps_port, 636);
    assert_eq!(config.server.base_dn, "dc=test,dc=local");
    assert_eq!(config.server.hostname, "ldap.test.local");
    assert_eq!(config.backend.backend_type, "memory");
    assert_eq!(
        config.backend.data_directory,
        PathBuf::from("/var/lib/opendr")
    );
    assert!(!config.rate_limit.enabled);
    assert_eq!(config.rate_limit.global_requests_per_second, 500);
    assert!(config.monitoring.enabled);
    assert_eq!(config.monitoring.metrics_port, 8080);
}

#[test]
fn test_config_to_toml_and_back() {
    let original = ServerConfig::default();

    // Convert to TOML
    let toml_str = original.to_toml_string().unwrap();
    assert!(toml_str.contains("[server]"));
    assert!(toml_str.contains("[backend]"));
    assert!(toml_str.contains("[rate_limit]"));

    // Parse back
    let parsed = ServerConfig::from_toml_str(&toml_str).unwrap();

    assert_eq!(original.server.ldap_port, parsed.server.ldap_port);
    assert_eq!(original.server.base_dn, parsed.server.base_dn);
    assert_eq!(original.backend.backend_type, parsed.backend.backend_type);
}

#[test]
fn test_partial_config() {
    // Only specify some values, rest should use defaults
    let toml = r#"
[server]
ldap_port = 3389
base_dn = "dc=myorg,dc=com"
    "#;

    let config = ServerConfig::from_toml_str(toml).unwrap();

    assert_eq!(config.server.ldap_port, 3389);
    assert_eq!(config.server.base_dn, "dc=myorg,dc=com");
    // These should still be defaults
    assert_eq!(config.server.ldaps_port, 1636);
    assert_eq!(config.backend.backend_type, "lmdb");
    assert!(config.rate_limit.enabled);
}

#[test]
fn test_validation_invalid_ports() {
    let toml = r#"
[server]
ldap_port = 1389
ldaps_port = 1389
    "#;

    let config = ServerConfig::from_toml_str(toml).unwrap();
    let result = config.validate();

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("ports must be different"));
}

#[test]
fn test_validation_zero_port() {
    let toml = r#"
[server]
ldap_port = 0
    "#;

    let config = ServerConfig::from_toml_str(toml).unwrap();
    let result = config.validate();

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("port cannot be 0"));
}

#[test]
fn test_validation_empty_base_dn() {
    let toml = r#"
[server]
base_dn = ""
    "#;

    let config = ServerConfig::from_toml_str(toml).unwrap();
    let result = config.validate();

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Base DN cannot be empty"));
}

#[test]
fn test_validation_invalid_backend_type() {
    let toml = r#"
[backend]
backend_type = "postgresql"
    "#;

    let config = ServerConfig::from_toml_str(toml).unwrap();
    let result = config.validate();

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Invalid backend type"));
}

#[test]
fn test_validation_invalid_adaptive_threshold() {
    let toml = r#"
[rate_limit]
adaptive_threshold = 1.5
    "#;

    let config = ServerConfig::from_toml_str(toml).unwrap();
    let result = config.validate();

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("adaptive_threshold"));
}

#[test]
fn test_validation_invalid_ip_blacklist() {
    let toml = r#"
[rate_limit]
blacklist = ["not-an-ip-address", "192.168.1.1"]
    "#;

    let config = ServerConfig::from_toml_str(toml).unwrap();
    let result = config.validate();

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Invalid blacklist IP"));
}

#[test]
fn test_validation_valid_ip_lists() {
    let toml = r#"
[rate_limit]
blacklist = ["192.168.1.100", "10.0.0.5"]
whitelist = ["127.0.0.1", "::1"]
    "#;

    let config = ServerConfig::from_toml_str(toml).unwrap();
    assert!(config.validate().is_ok());
    assert_eq!(config.rate_limit.blacklist.len(), 2);
    assert_eq!(config.rate_limit.whitelist.len(), 2);
}

#[test]
fn test_validation_invalid_replication_mode() {
    let toml = r#"
[replication]
enabled = true
mode = "invalid"
    "#;

    let config = ServerConfig::from_toml_str(toml).unwrap();
    let result = config.validate();

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Invalid replication mode"));
}

#[test]
fn test_validation_consumer_needs_provider_url() {
    let toml = r#"
[replication]
enabled = true
mode = "consumer"
    "#;

    let config = ServerConfig::from_toml_str(toml).unwrap();
    let result = config.validate();

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("provider_url"));
}

#[test]
fn test_validation_valid_replication_consumer() {
    let toml = r#"
[replication]
enabled = true
mode = "consumer"
provider_url = "ldap://provider.example.com:389"
bind_dn = "cn=replicator,dc=example,dc=com"
bind_password = "secret"
max_batch_size = 128
max_retry_attempts = 9
retry_delay_secs = 12
enable_change_listening = true
enable_streaming = true
heartbeat_interval_secs = 45
max_concurrent_consumers = 20
consumer_timeout_secs = 600
provider_timeout_secs = 55
state_persistence_timeout_secs = 22
change_buffer_size = 2048
state_storage_path = "/var/lib/opendr/repl_state"
    "#;

    let config = ServerConfig::from_toml_str(toml).unwrap();
    assert!(config.validate().is_ok());
    assert_eq!(config.replication.mode, "consumer");
    assert_eq!(
        config.replication.provider_url.unwrap(),
        "ldap://provider.example.com:389"
    );
    assert_eq!(config.replication.max_batch_size, 128);
    assert_eq!(config.replication.max_retry_attempts, 9);
    assert_eq!(config.replication.retry_delay_secs, 12);
    assert!(config.replication.enable_change_listening);
    assert!(config.replication.enable_streaming);
    assert_eq!(config.replication.heartbeat_interval_secs, 45);
    assert_eq!(config.replication.max_concurrent_consumers, 20);
    assert_eq!(config.replication.consumer_timeout_secs, 600);
    assert_eq!(config.replication.provider_timeout_secs, 55);
    assert_eq!(config.replication.state_persistence_timeout_secs, 22);
    assert_eq!(config.replication.change_buffer_size, 2048);
    assert_eq!(
        config.replication.state_storage_path,
        PathBuf::from("/var/lib/opendr/repl_state")
    );
}

#[test]
fn test_validation_invalid_replication_listening_settings() {
    let toml = r#"
[replication]
enabled = true
mode = "consumer"
provider_url = "ldap://provider.example.com:389"
max_batch_size = 0
max_retry_attempts = 0
retry_delay_secs = 0
heartbeat_interval_secs = 0
max_concurrent_consumers = 0
consumer_timeout_secs = 0
provider_timeout_secs = 0
state_persistence_timeout_secs = 0
change_buffer_size = 0
    "#;

    let config = ServerConfig::from_toml_str(toml).unwrap();
    let result = config.validate();

    assert!(result.is_err());
    let message = result.unwrap_err().to_string();
    assert!(
        message.contains("max_retry_attempts")
            || message.contains("max_batch_size")
            || message.contains("retry_delay_secs")
            || message.contains("heartbeat_interval_secs")
            || message.contains("max_concurrent_consumers")
            || message.contains("consumer_timeout_secs")
            || message.contains("provider_timeout_secs")
            || message.contains("state_persistence_timeout_secs")
            || message.contains("change_buffer_size")
    );
}

#[test]
fn test_validation_custom_replication_listening_config() {
    let toml = r#"
[replication]
enabled = true
mode = "consumer"
provider_url = "ldap://provider.example.com:389"
bind_dn = "cn=replicator,dc=example,dc=com"
bind_password = "secret"
sync_interval_secs = 15
max_batch_size = 250
max_retry_attempts = 9
retry_delay_secs = 11
enable_change_listening = true
enable_streaming = false
heartbeat_interval_secs = 45
max_concurrent_consumers = 14
consumer_timeout_secs = 480
provider_timeout_secs = 90
state_persistence_timeout_secs = 18
change_buffer_size = 4096
state_storage_path = "/var/lib/opendr/replication_state"
    "#;

    let config = ServerConfig::from_toml_str(toml).unwrap();
    assert!(config.validate().is_ok());
    assert_eq!(config.replication.sync_interval_secs, 15);
    assert_eq!(config.replication.max_batch_size, 250);
    assert_eq!(config.replication.max_retry_attempts, 9);
    assert_eq!(config.replication.retry_delay_secs, 11);
    assert!(config.replication.enable_change_listening);
    assert!(!config.replication.enable_streaming);
    assert_eq!(config.replication.heartbeat_interval_secs, 45);
    assert_eq!(config.replication.max_concurrent_consumers, 14);
    assert_eq!(config.replication.consumer_timeout_secs, 480);
    assert_eq!(config.replication.provider_timeout_secs, 90);
    assert_eq!(config.replication.state_persistence_timeout_secs, 18);
    assert_eq!(config.replication.change_buffer_size, 4096);
    assert_eq!(
        config.replication.state_storage_path,
        PathBuf::from("/var/lib/opendr/replication_state")
    );
}

#[test]
fn test_validation_rejects_poll_based_replication() {
    let toml = r#"
[replication]
enabled = true
mode = "consumer"
provider_url = "ldap://provider.example.com:389"
enable_change_listening = false
    "#;

    let config = ServerConfig::from_toml_str(toml).unwrap();
    let result = config.validate();

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("poll-based replication has been removed"));
}

#[test]
fn test_validation_legacy_setup_role_alias_is_normalized() {
    let toml = r#"
[replication]
enabled = true
role = "Consumer"
provider_url = "ldap://provider.example.com:389"
bind_dn = "cn=replicator,dc=example,dc=com"
bind_password = "secret"
    "#;

    let config = ServerConfig::from_toml_str(toml).unwrap();
    assert_eq!(config.replication.mode, "consumer");
    assert!(config.validate().is_ok());
}

#[test]
fn test_validation_replication_zero_retry_attempts() {
    let toml = r#"
[replication]
enabled = true
mode = "consumer"
provider_url = "ldap://provider.example.com:389"
max_retry_attempts = 0
    "#;

    let config = ServerConfig::from_toml_str(toml).unwrap();
    let result = config.validate();

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("max_retry_attempts must be > 0"));
}

#[test]
fn test_validation_invalid_audit_format() {
    let toml = r#"
[audit]
format = "xml"
    "#;

    let config = ServerConfig::from_toml_str(toml).unwrap();
    let result = config.validate();

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Invalid audit format"));
}

#[test]
fn test_validation_invalid_audit_level() {
    let toml = r#"
[audit]
level = "verbose"
    "#;

    let config = ServerConfig::from_toml_str(toml).unwrap();
    let result = config.validate();

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Invalid audit level"));
}

#[test]
fn test_validation_invalid_access_policy() {
    let toml = r#"
[access_control]
default_policy = "maybe"
    "#;

    let config = ServerConfig::from_toml_str(toml).unwrap();
    let result = config.validate();

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Invalid access policy"));
}

#[test]
fn test_duration_helpers() {
    let config = ServerConfig::default();

    use std::time::Duration;

    assert_eq!(config.operation_timeout(), Duration::from_secs(300));
    assert_eq!(config.cleanup_interval(), Duration::from_secs(60));
    assert_eq!(config.connection_idle_timeout(), Duration::from_secs(600));
    assert_eq!(config.rate_limit_window_duration(), Duration::from_secs(1));
    assert_eq!(config.auto_ban_duration(), Duration::from_secs(300));
    assert_eq!(config.sync_interval(), Duration::from_secs(60));
}

#[test]
fn test_operation_limits_config() {
    let toml = r#"
[rate_limit.operation_limits]
bind = 5
search = 100
modify = 30
add = 25
delete = 15
    "#;

    let config = ServerConfig::from_toml_str(toml).unwrap();

    assert_eq!(config.rate_limit.operation_limits.bind, 5);
    assert_eq!(config.rate_limit.operation_limits.search, 100);
    assert_eq!(config.rate_limit.operation_limits.modify, 30);
    assert_eq!(config.rate_limit.operation_limits.add, 25);
    assert_eq!(config.rate_limit.operation_limits.delete, 15);
}

#[test]
fn test_comprehensive_config() {
    let toml = r#"
[server]
bind_address = "0.0.0.0"
ldap_port = 389
ldaps_port = 636
hostname = "ldap.example.com"
base_dn = "dc=example,dc=com"
root_user_dn = "cn=admin,dc=example,dc=com"
root_password = "SuperSecret123!"
organization_name = "Example Corp"
read_buffer_size = 8192
operation_timeout_secs = 600
cleanup_interval_secs = 120
max_concurrent_operations = 200

[backend]
backend_type = "lmdb"
data_directory = "/var/lib/opendr/data"
lmdb_max_size = 21474836480
lmdb_max_readers = 200
import_sample_data = true
indexed_attributes = ["cn", "uid", "mail", "sn", "givenName"]

[tls]
enabled = false

[resources]
max_connections = 2000
max_connections_per_ip = 50
max_operations_per_connection = 200
max_memory_per_connection = 20971520
max_total_memory = 2147483648
connection_idle_timeout_secs = 1200

[rate_limit]
enabled = true
global_requests_per_second = 2000
per_client_requests_per_second = 200
burst_size = 100
window_duration_secs = 1
adaptive_enabled = true
adaptive_threshold = 0.75
adaptive_multiplier = 0.6
auto_ban_threshold = 200
auto_ban_duration_secs = 600

[rate_limit.operation_limits]
bind = 20
search = 100
modify = 40
add = 40
delete = 20
modifydn = 20
compare = 60
extended = 40

[replication]
enabled = false

[monitoring]
enabled = true
metrics_address = "0.0.0.0"
metrics_port = 9090
metrics_path = "/metrics"
health_path = "/health"

[audit]
enabled = true
log_file = "/var/log/opendr/audit.log"
format = "json"
level = "info"
log_authentication = true
log_authorization = true
log_modifications = true
log_connections = true

[access_control]
enabled = true
default_policy = "deny"

[performance]
worker_threads = 8
schema_validation = true
indexing_enabled = true
cache_size = 5000
query_optimization = true
    "#;

    let config = ServerConfig::from_toml_str(toml).unwrap();
    assert!(config.validate().is_ok());

    // Verify all sections loaded correctly
    assert_eq!(config.server.bind_address, "0.0.0.0");
    assert_eq!(config.server.ldap_port, 389);
    assert_eq!(config.backend.backend_type, "lmdb");
    assert_eq!(config.backend.lmdb_max_size, 21474836480);
    assert_eq!(config.resources.max_connections, 2000);
    assert_eq!(config.rate_limit.global_requests_per_second, 2000);
    assert_eq!(config.monitoring.metrics_port, 9090);
    assert_eq!(config.audit.format, "json");
    assert_eq!(config.access_control.default_policy, "deny");
    assert_eq!(config.performance.worker_threads, 8);
}

#[test]
fn test_save_and_load_config() {
    let temp_dir = env::temp_dir();
    let config_path = temp_dir.join("test_config.toml");

    // Create a config
    let mut config = ServerConfig::default();
    config.server.ldap_port = 3389;
    config.server.base_dn = "dc=test,dc=local".to_string();

    // Save it
    config.save_to_file(config_path.to_str().unwrap()).unwrap();

    // Load it back
    let loaded_toml = fs::read_to_string(&config_path).unwrap();
    let loaded_config = ServerConfig::from_toml_str(&loaded_toml).unwrap();

    assert_eq!(loaded_config.server.ldap_port, 3389);
    assert_eq!(loaded_config.server.base_dn, "dc=test,dc=local");

    // Cleanup
    fs::remove_file(config_path).ok();
}

#[test]
fn test_indexed_attributes_config() {
    let toml = r#"
[backend]
indexed_attributes = ["cn", "uid", "mail", "sn", "givenName", "objectClass", "ou"]
    "#;

    let config = ServerConfig::from_toml_str(toml).unwrap();
    assert_eq!(config.backend.indexed_attributes.len(), 7);
    assert!(config
        .backend
        .indexed_attributes
        .contains(&"sn".to_string()));
    assert!(config
        .backend
        .indexed_attributes
        .contains(&"givenName".to_string()));
}

#[test]
fn test_typed_backend_indexes_config() {
    let toml = r#"
[backend]
indexed_attributes = []

[[backend.indexes]]
attribute = "cn"
types = ["equality", "presence", "substring"]

[[backend.indexes]]
attribute = "entryCSN"
types = ["ordering"]
    "#;

    let config = ServerConfig::from_toml_str(toml).unwrap();
    config.validate().unwrap();

    assert_eq!(config.backend.indexes.len(), 2);
    assert_eq!(config.backend.indexes[0].attribute, "cn");
    assert_eq!(
        config.backend.indexes[0].types,
        vec![
            "equality".to_string(),
            "presence".to_string(),
            "substring".to_string()
        ]
    );
    assert_eq!(config.backend.indexes[1].attribute, "entryCSN");
    assert_eq!(
        config.backend.indexes[1].types,
        vec!["ordering".to_string()]
    );
}

#[test]
fn test_invalid_backend_index_type_validation() {
    let toml = r#"
[backend]
indexed_attributes = []

[[backend.indexes]]
attribute = "cn"
types = ["bogus"]
    "#;

    let config = ServerConfig::from_toml_str(toml).unwrap();
    let result = config.validate();

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("unsupported backend index type for cn: bogus"));
}

#[test]
fn test_max_connections_validation() {
    let toml = r#"
[resources]
max_connections = 100
max_connections_per_ip = 200
    "#;

    let config = ServerConfig::from_toml_str(toml).unwrap();
    let result = config.validate();

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("max_connections_per_ip cannot exceed max_connections"));
}

#[test]
fn test_zero_max_connections() {
    let toml = r#"
[resources]
max_connections = 0
    "#;

    let config = ServerConfig::from_toml_str(toml).unwrap();
    let result = config.validate();

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("max_connections must be > 0"));
}

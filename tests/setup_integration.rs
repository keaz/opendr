// Integration tests for server setup functionality

use opendr::config::ServerConfig;
use opendr::setup::{
    BackendType, ConsumerConfig, ProviderConfig, ReplicationConfig, ReplicationRole, SetupConfig,
    SetupHandler,
};
use std::path::PathBuf;
use tempfile::TempDir;

#[tokio::test]
async fn test_setup_handler_creation() {
    let temp_dir = TempDir::new().unwrap();
    let handler = SetupHandler::new(temp_dir.path());

    // Should not be configured initially
    assert!(!handler.is_configured().await.unwrap());
}

#[tokio::test]
async fn test_non_interactive_setup() {
    let temp_dir = TempDir::new().unwrap();
    let handler = SetupHandler::new(temp_dir.path());

    let config = SetupConfig {
        base_dn: "dc=test,dc=org".to_string(),
        root_user_dn: "cn=admin".to_string(),
        root_password: "TestPass123".to_string(),
        ldap_port: 1389,
        ldaps_port: 1636,
        hostname: "localhost".to_string(),
        organization_name: "Test Org".to_string(),
        backend_type: BackendType::InMemory,
        data_directory: temp_dir.path().join("data"),
        import_sample_data: false,
        replication: ReplicationConfig::default(),
    };

    // Perform setup
    handler.run_non_interactive_setup(config).await.unwrap();

    // Should be configured now
    assert!(handler.is_configured().await.unwrap());
}

#[tokio::test]
async fn test_setup_with_sample_data() {
    let temp_dir = TempDir::new().unwrap();
    let handler = SetupHandler::new(temp_dir.path());

    let config = SetupConfig {
        base_dn: "dc=example,dc=com".to_string(),
        root_user_dn: "cn=Directory Manager".to_string(),
        root_password: "AdminPass123".to_string(),
        ldap_port: 1389,
        ldaps_port: 1636,
        hostname: "localhost".to_string(),
        organization_name: "Example Organization".to_string(),
        backend_type: BackendType::InMemory,
        data_directory: temp_dir.path().join("data"),
        import_sample_data: true,
        replication: ReplicationConfig::default(),
    };

    handler.run_non_interactive_setup(config).await.unwrap();

    // Verify sample data file was created
    let sample_file = temp_dir.path().join("sample.ldif");
    assert!(sample_file.exists());

    let content = tokio::fs::read_to_string(&sample_file).await.unwrap();
    assert!(content.contains("uid=john.doe"));
    assert!(content.contains("uid=jane.smith"));
    assert!(content.contains("cn=users"));
}

#[tokio::test]
async fn test_setup_creates_admin_account() {
    let temp_dir = TempDir::new().unwrap();
    let handler = SetupHandler::new(temp_dir.path());

    let config = SetupConfig {
        base_dn: "dc=test,dc=org".to_string(),
        root_user_dn: "cn=admin,dc=test,dc=org".to_string(),
        root_password: "SecurePass123".to_string(),
        ldap_port: 1389,
        ldaps_port: 1636,
        hostname: "localhost".to_string(),
        organization_name: "Test Org".to_string(),
        backend_type: BackendType::InMemory,
        data_directory: temp_dir.path().join("data"),
        import_sample_data: false,
        replication: ReplicationConfig::default(),
    };

    handler.run_non_interactive_setup(config).await.unwrap();

    // Verify admin LDIF file was created
    let admin_file = temp_dir.path().join("admin.ldif");
    assert!(admin_file.exists());

    let content = tokio::fs::read_to_string(&admin_file).await.unwrap();
    assert!(content.contains("dn: cn=admin,dc=test,dc=org"));
    assert!(content.contains("objectClass: inetOrgPerson"));
    assert!(content.contains("userPassword: {SSHA512}"));
}

#[tokio::test]
async fn test_setup_creates_base_structure() {
    let temp_dir = TempDir::new().unwrap();
    let handler = SetupHandler::new(temp_dir.path());

    let config = SetupConfig {
        base_dn: "dc=example,dc=com".to_string(),
        root_user_dn: "cn=admin".to_string(),
        root_password: "TestPass123".to_string(),
        ldap_port: 1389,
        ldaps_port: 1636,
        hostname: "localhost".to_string(),
        organization_name: "Example Org".to_string(),
        backend_type: BackendType::InMemory,
        data_directory: temp_dir.path().join("data"),
        import_sample_data: false,
        replication: ReplicationConfig::default(),
    };

    handler.run_non_interactive_setup(config).await.unwrap();

    // Verify base structure file was created
    let base_file = temp_dir.path().join("base.ldif");
    assert!(base_file.exists());

    let content = tokio::fs::read_to_string(&base_file).await.unwrap();
    assert!(content.contains("ou=People"));
    assert!(content.contains("ou=Groups"));
    assert!(content.contains("ou=Applications"));
}

#[tokio::test]
async fn test_setup_with_lmdb_backend() {
    let temp_dir = TempDir::new().unwrap();
    let handler = SetupHandler::new(temp_dir.path());

    let data_dir = temp_dir.path().join("data");

    let config = SetupConfig {
        base_dn: "dc=lmdb,dc=test".to_string(),
        root_user_dn: "cn=admin".to_string(),
        root_password: "LmdbPass123".to_string(),
        ldap_port: 1389,
        ldaps_port: 1636,
        hostname: "localhost".to_string(),
        organization_name: "LMDB Test".to_string(),
        backend_type: BackendType::Lmdb,
        data_directory: data_dir.clone(),
        import_sample_data: false,
        replication: ReplicationConfig::default(),
    };

    handler.run_non_interactive_setup(config).await.unwrap();

    // Verify data directory was created
    assert!(data_dir.exists());
}

#[tokio::test]
async fn test_password_validation() {
    let temp_dir = TempDir::new().unwrap();
    let handler = SetupHandler::new(temp_dir.path());

    // Test weak passwords
    let weak_configs = vec![
        ("short", "Short1"), // Too short
        ("no uppercase", "nouppercase1"),
        ("no lowercase", "NOLOWERCASE1"),
        ("no digits", "NoDigits"),
    ];

    for (name, password) in weak_configs {
        let config = SetupConfig {
            base_dn: "dc=test,dc=org".to_string(),
            root_user_dn: "cn=admin".to_string(),
            root_password: password.to_string(),
            ldap_port: 1389,
            ldaps_port: 1636,
            hostname: "localhost".to_string(),
            organization_name: "Test".to_string(),
            backend_type: BackendType::InMemory,
            data_directory: temp_dir.path().join("data"),
            import_sample_data: false,
            replication: ReplicationConfig::default(),
        };

        let result = handler.run_non_interactive_setup(config).await;
        assert!(result.is_err(), "Expected failure for {}", name);
    }

    // Test strong password
    let strong_config = SetupConfig {
        base_dn: "dc=test,dc=org".to_string(),
        root_user_dn: "cn=admin".to_string(),
        root_password: "StrongPass123".to_string(),
        ldap_port: 1389,
        ldaps_port: 1636,
        hostname: "localhost".to_string(),
        organization_name: "Test".to_string(),
        backend_type: BackendType::InMemory,
        data_directory: temp_dir.path().join("data"),
        import_sample_data: false,
        replication: ReplicationConfig::default(),
    };

    handler
        .run_non_interactive_setup(strong_config)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_setup_state_persistence() {
    let temp_dir = TempDir::new().unwrap();
    let handler = SetupHandler::new(temp_dir.path());

    let config = SetupConfig {
        base_dn: "dc=state,dc=test".to_string(),
        root_user_dn: "cn=admin".to_string(),
        root_password: "StatePass123".to_string(),
        ldap_port: 1389,
        ldaps_port: 1636,
        hostname: "localhost".to_string(),
        organization_name: "State Test".to_string(),
        backend_type: BackendType::InMemory,
        data_directory: temp_dir.path().join("data"),
        import_sample_data: false,
        replication: ReplicationConfig::default(),
    };

    handler.run_non_interactive_setup(config).await.unwrap();

    // Create a new handler with the same config directory
    let handler2 = SetupHandler::new(temp_dir.path());
    assert!(handler2.is_configured().await.unwrap());
}

#[tokio::test]
async fn test_complex_dn_parsing() {
    let temp_dir = TempDir::new().unwrap();
    let handler = SetupHandler::new(temp_dir.path());

    let config = SetupConfig {
        base_dn: "ou=Users,dc=example,dc=com".to_string(),
        root_user_dn: "cn=admin,ou=Administrators,dc=example,dc=com".to_string(),
        root_password: "ComplexPass123".to_string(),
        ldap_port: 1389,
        ldaps_port: 1636,
        hostname: "localhost".to_string(),
        organization_name: "Complex DN Test".to_string(),
        backend_type: BackendType::InMemory,
        data_directory: temp_dir.path().join("data"),
        import_sample_data: false,
        replication: ReplicationConfig::default(),
    };

    handler.run_non_interactive_setup(config).await.unwrap();

    let base_file = temp_dir.path().join("base.ldif");
    let content = tokio::fs::read_to_string(&base_file).await.unwrap();
    assert!(content.contains("dc=example"));
    assert!(content.contains("dc=com"));
}

#[tokio::test]
async fn test_setup_config_serialization() {
    let config = SetupConfig {
        base_dn: "dc=test,dc=org".to_string(),
        root_user_dn: "cn=admin".to_string(),
        root_password: "SerialPass123".to_string(),
        ldap_port: 1389,
        ldaps_port: 1636,
        hostname: "localhost".to_string(),
        organization_name: "Serial Test".to_string(),
        backend_type: BackendType::Lmdb,
        data_directory: PathBuf::from("/tmp/data"),
        import_sample_data: true,
        replication: ReplicationConfig::default(),
    };

    // Serialize to TOML
    let serialized = toml::to_string(&config).unwrap();

    // Deserialize back
    let deserialized: SetupConfig = toml::from_str(&serialized).unwrap();

    assert_eq!(config.base_dn, deserialized.base_dn);
    assert_eq!(config.root_user_dn, deserialized.root_user_dn);
    assert_eq!(config.ldap_port, deserialized.ldap_port);
    assert_eq!(config.backend_type, deserialized.backend_type);
}

#[tokio::test]
async fn test_password_hashing_uniqueness() {
    let temp_dir = TempDir::new().unwrap();
    let handler = SetupHandler::new(temp_dir.path());

    let config = SetupConfig {
        base_dn: "dc=hash,dc=test".to_string(),
        root_user_dn: "cn=admin".to_string(),
        root_password: "HashPass123".to_string(),
        ldap_port: 1389,
        ldaps_port: 1636,
        hostname: "localhost".to_string(),
        organization_name: "Hash Test".to_string(),
        backend_type: BackendType::InMemory,
        data_directory: temp_dir.path().join("data"),
        import_sample_data: false,
        replication: ReplicationConfig::default(),
    };

    handler
        .run_non_interactive_setup(config.clone())
        .await
        .unwrap();

    let admin_file1 = temp_dir.path().join("admin.ldif");
    let content1 = tokio::fs::read_to_string(&admin_file1).await.unwrap();

    // Setup again in a different directory with same password
    let temp_dir2 = TempDir::new().unwrap();
    let handler2 = SetupHandler::new(temp_dir2.path());
    handler2.run_non_interactive_setup(config).await.unwrap();

    let admin_file2 = temp_dir2.path().join("admin.ldif");
    let content2 = tokio::fs::read_to_string(&admin_file2).await.unwrap();

    // Extract password hashes
    let hash1 = extract_password_hash(&content1);
    let hash2 = extract_password_hash(&content2);

    // Hashes should be different due to random salt
    assert_ne!(hash1, hash2);
}

#[tokio::test]
async fn test_multiple_organizational_units() {
    let temp_dir = TempDir::new().unwrap();
    let handler = SetupHandler::new(temp_dir.path());

    let config = SetupConfig {
        base_dn: "dc=example,dc=com".to_string(),
        root_user_dn: "cn=admin".to_string(),
        root_password: "OuPass123".to_string(),
        ldap_port: 1389,
        ldaps_port: 1636,
        hostname: "localhost".to_string(),
        organization_name: "OU Test".to_string(),
        backend_type: BackendType::InMemory,
        data_directory: temp_dir.path().join("data"),
        import_sample_data: false,
        replication: ReplicationConfig::default(),
    };

    handler.run_non_interactive_setup(config).await.unwrap();

    let base_file = temp_dir.path().join("base.ldif");
    let content = tokio::fs::read_to_string(&base_file).await.unwrap();

    // Should have all standard OUs
    assert!(content.contains("ou=People"));
    assert!(content.contains("ou=Groups"));
    assert!(content.contains("ou=Applications"));
}

// Helper function to extract password hash from LDIF content
fn extract_password_hash(ldif: &str) -> String {
    for line in ldif.lines() {
        if line.starts_with("userPassword: {SSHA512}") {
            return line
                .replace("userPassword: {SSHA512}", "")
                .trim()
                .to_string();
        }
    }
    String::new()
}

#[tokio::test]
async fn test_replication_config_provider_serialization() {
    // Test that Provider replication config serializes/deserializes correctly
    let config = SetupConfig {
        base_dn: "dc=test,dc=org".to_string(),
        root_user_dn: "cn=admin".to_string(),
        root_password: "ReplPass123".to_string(),
        ldap_port: 1389,
        ldaps_port: 1636,
        hostname: "localhost".to_string(),
        organization_name: "Replication Test".to_string(),
        backend_type: BackendType::Lmdb,
        data_directory: PathBuf::from("/tmp/data"),
        import_sample_data: false,
        replication: ReplicationConfig {
            enabled: true,
            role: ReplicationRole::Provider,
            provider: Some(ProviderConfig {
                changelog_enabled: true,
                changelog_max_entries: 100000,
                max_batch_size: 100,
                enable_streaming: true,
                heartbeat_interval_secs: 60,
                max_concurrent_consumers: 10,
                consumer_timeout_secs: 300,
            }),
            consumer: None,
        },
    };

    // Serialize to TOML
    let serialized = toml::to_string(&config).unwrap();

    // Verify it contains the correct case-sensitive role
    assert!(
        serialized.contains("role = \"Provider\""),
        "Serialized config should contain 'role = \"Provider\"', got:\n{}",
        serialized
    );

    // Deserialize back
    let deserialized: SetupConfig = toml::from_str(&serialized).unwrap();

    assert_eq!(config.replication.enabled, deserialized.replication.enabled);
    assert_eq!(config.replication.role, deserialized.replication.role);
    assert!(deserialized.replication.provider.is_some());
    assert!(deserialized.replication.consumer.is_none());
}

#[tokio::test]
async fn test_replication_config_consumer_serialization() {
    // Test that Consumer replication config serializes/deserializes correctly
    let config = SetupConfig {
        base_dn: "dc=test,dc=org".to_string(),
        root_user_dn: "cn=admin".to_string(),
        root_password: "ReplPass123".to_string(),
        ldap_port: 1389,
        ldaps_port: 1636,
        hostname: "localhost".to_string(),
        organization_name: "Replication Test".to_string(),
        backend_type: BackendType::Lmdb,
        data_directory: PathBuf::from("/tmp/data"),
        import_sample_data: false,
        replication: ReplicationConfig {
            enabled: true,
            role: ReplicationRole::Consumer,
            provider: None,
            consumer: Some(ConsumerConfig {
                provider_url: "ldap://provider.example.com:1389".to_string(),
                provider_bind_dn: Some("cn=replication".to_string()),
                provider_bind_password: Some("secret".to_string()),
                max_batch_size: 100,
                sync_interval_secs: 60,
                max_retry_attempts: 3,
                retry_delay_secs: 10,
                enable_change_listening: true,
                heartbeat_interval_secs: 30,
                provider_timeout_secs: 30,
                state_persistence_timeout_secs: 10,
                change_buffer_size: 1000,
                state_storage_path: PathBuf::from("/tmp/repl_state"),
            }),
        },
    };

    // Serialize to TOML
    let serialized = toml::to_string(&config).unwrap();

    // Verify it contains the correct case-sensitive role
    assert!(
        serialized.contains("role = \"Consumer\""),
        "Serialized config should contain 'role = \"Consumer\"', got:\n{}",
        serialized
    );

    // Deserialize back
    let deserialized: SetupConfig = toml::from_str(&serialized).unwrap();

    assert_eq!(config.replication.enabled, deserialized.replication.enabled);
    assert_eq!(config.replication.role, deserialized.replication.role);
    assert!(deserialized.replication.consumer.is_some());
    assert!(deserialized.replication.provider.is_none());
}

#[tokio::test]
async fn test_replication_config_lowercase_compatibility() {
    // Test that lowercase "provider" and "consumer" are properly deserialized
    // This ensures backward compatibility with configs generated by the setup wizard

    let toml_provider = r#"
base_dn = "dc=test,dc=org"
root_user_dn = "cn=admin"
root_password = "TestPass123"
ldap_port = 1389
ldaps_port = 1636
hostname = "localhost"
organization_name = "Test"
backend_type = "Lmdb"
data_directory = "/tmp/data"
import_sample_data = false

[replication]
enabled = true
role = "Provider"

[replication.provider]
changelog_enabled = true
changelog_max_entries = 100000
max_batch_size = 100
enable_streaming = true
heartbeat_interval_secs = 60
"#;

    let config: SetupConfig = toml::from_str(toml_provider).unwrap();
    assert_eq!(config.replication.role, ReplicationRole::Provider);
    assert!(config.replication.enabled);

    let toml_consumer = r#"
base_dn = "dc=test,dc=org"
root_user_dn = "cn=admin"
root_password = "TestPass123"
ldap_port = 1389
ldaps_port = 1636
hostname = "localhost"
organization_name = "Test"
backend_type = "Lmdb"
data_directory = "/tmp/data"
import_sample_data = false

[replication]
enabled = true
role = "Consumer"

[replication.consumer]
provider_url = "ldap://provider:1389"
sync_interval_secs = 60
max_retry_attempts = 3
retry_delay_secs = 10
enable_change_listening = true
state_storage_path = "/tmp/state"
"#;

    let config: SetupConfig = toml::from_str(toml_consumer).unwrap();
    assert_eq!(config.replication.role, ReplicationRole::Consumer);
    assert!(config.replication.enabled);
}

#[tokio::test]
async fn test_setup_handler_generates_loadable_config() {
    // Test the complete flow: SetupHandler generates config -> save to file -> load from file
    let temp_dir = TempDir::new().unwrap();
    let config_dir = temp_dir.path().to_path_buf();
    let handler = SetupHandler::new(&config_dir);

    let config = SetupConfig {
        base_dn: "dc=example,dc=com".to_string(),
        root_user_dn: "cn=manager".to_string(),
        root_password: "SecurePass123".to_string(),
        ldap_port: 1389,
        ldaps_port: 1636,
        hostname: "localhost".to_string(),
        organization_name: "Example Org".to_string(),
        backend_type: BackendType::InMemory,
        data_directory: temp_dir.path().join("data"),
        import_sample_data: false,
        replication: ReplicationConfig {
            enabled: true,
            role: ReplicationRole::Provider,
            provider: Some(ProviderConfig {
                changelog_enabled: true,
                changelog_max_entries: 100000,
                max_batch_size: 100,
                enable_streaming: true,
                heartbeat_interval_secs: 60,
                max_concurrent_consumers: 10,
                consumer_timeout_secs: 300,
            }),
            consumer: None,
        },
    };

    // Run setup which generates the config file
    handler
        .run_non_interactive_setup(config.clone())
        .await
        .unwrap();

    // Verify config file exists
    let config_path = config_dir.join("server.toml");
    assert!(
        config_path.exists(),
        "Config file should be created at {:?}",
        config_path
    );

    // Load the generated config file
    let config_content = tokio::fs::read_to_string(&config_path).await.unwrap();

    // Verify the content uses canonical server config replication keys
    assert!(
        config_content.contains("mode = \"provider\""),
        "Config should contain mode = \"provider\", got:\n{}",
        config_content
    );
    assert!(config_content.contains("changelog_capacity = 100000"));

    // Deserialize the generated server config through the canonical runtime config type.
    let loaded_config = ServerConfig::from_toml_str(&config_content)
        .map_err(|e| {
            format!(
                "Failed to deserialize server config: {}\nConfig content:\n{}",
                e, config_content
            )
        })
        .unwrap();

    assert_eq!(loaded_config.server.base_dn, config.base_dn);
    assert!(loaded_config.replication.enabled);
    assert_eq!(loaded_config.replication.mode, "provider");
    assert_eq!(loaded_config.replication.changelog_capacity, 100000);
}

#[tokio::test]
async fn test_setup_handler_generates_canonical_consumer_replication_config() {
    let temp_dir = TempDir::new().unwrap();
    let config_dir = temp_dir.path().to_path_buf();
    let handler = SetupHandler::new(&config_dir);

    let config = SetupConfig {
        base_dn: "dc=example,dc=com".to_string(),
        root_user_dn: "cn=manager".to_string(),
        root_password: "SecurePass123".to_string(),
        ldap_port: 1389,
        ldaps_port: 1636,
        hostname: "localhost".to_string(),
        organization_name: "Example Org".to_string(),
        backend_type: BackendType::InMemory,
        data_directory: temp_dir.path().join("data"),
        import_sample_data: false,
        replication: ReplicationConfig {
            enabled: true,
            role: ReplicationRole::Consumer,
            provider: None,
            consumer: Some(ConsumerConfig {
                provider_url: "ldap://provider.example.com:1389".to_string(),
                provider_bind_dn: Some("cn=replication,dc=example,dc=com".to_string()),
                provider_bind_password: Some("replica-secret".to_string()),
                sync_interval_secs: 45,
                max_retry_attempts: 8,
                retry_delay_secs: 12,
                enable_change_listening: false,
                heartbeat_interval_secs: 50,
                max_batch_size: 250,
                provider_timeout_secs: 80,
                state_persistence_timeout_secs: 20,
                change_buffer_size: 4096,
                state_storage_path: PathBuf::from("/tmp/opendr-repl-state"),
            }),
        },
    };

    handler
        .run_non_interactive_setup(config.clone())
        .await
        .unwrap();

    let config_path = config_dir.join("server.toml");
    let config_content = tokio::fs::read_to_string(&config_path).await.unwrap();

    assert!(config_content.contains("mode = \"consumer\""));
    assert!(config_content.contains("bind_dn = \"cn=replication,dc=example,dc=com\""));
    assert!(config_content.contains("retry_delay_secs = 12"));
    assert!(config_content.contains("state_storage_path = \"/tmp/opendr-repl-state\""));

    let loaded_config = ServerConfig::from_toml_str(&config_content)
        .map_err(|e| {
            format!(
                "Failed to deserialize server config: {}\nConfig content:\n{}",
                e, config_content
            )
        })
        .unwrap();

    assert!(loaded_config.replication.enabled);
    assert_eq!(loaded_config.replication.mode, "consumer");
    assert_eq!(
        loaded_config.replication.provider_url.as_deref(),
        Some("ldap://provider.example.com:1389")
    );
    assert_eq!(
        loaded_config.replication.bind_dn.as_deref(),
        Some("cn=replication,dc=example,dc=com")
    );
    assert_eq!(loaded_config.replication.max_retry_attempts, 8);
    assert_eq!(loaded_config.replication.retry_delay_secs, 12);
    assert!(!loaded_config.replication.enable_change_listening);
    assert_eq!(loaded_config.replication.heartbeat_interval_secs, 50);
    assert_eq!(loaded_config.replication.max_batch_size, 250);
    assert_eq!(loaded_config.replication.provider_timeout_secs, 80);
    assert_eq!(loaded_config.replication.state_persistence_timeout_secs, 20);
    assert_eq!(loaded_config.replication.change_buffer_size, 4096);
    assert_eq!(
        loaded_config.replication.state_storage_path,
        PathBuf::from("/tmp/opendr-repl-state")
    );
}

// Integration tests for server setup functionality

use opendr::config::ServerConfig;
use opendr::schema::LdapSchema;
use opendr::setup::{
    BackendType, ConsumerConfig, ProviderConfig, ReplicationConfig, ReplicationRole, SetupConfig,
    SetupHandler, TlsConfig,
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
        tls: TlsConfig::default(),
        hostname: "localhost".to_string(),
        organization_name: "Test Org".to_string(),
        replica_id: 1,
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
async fn test_setup_creates_missing_config_directory() {
    let temp_dir = TempDir::new().unwrap();
    let config_dir = temp_dir.path().join("nested").join("config");
    let handler = SetupHandler::new(&config_dir);

    let config = SetupConfig {
        base_dn: "dc=test,dc=org".to_string(),
        root_user_dn: "cn=admin".to_string(),
        root_password: "TestPass123".to_string(),
        ldap_port: 1389,
        ldaps_port: 1636,
        tls: TlsConfig::default(),
        hostname: "localhost".to_string(),
        organization_name: "Test Org".to_string(),
        replica_id: 1,
        backend_type: BackendType::InMemory,
        data_directory: temp_dir.path().join("data"),
        import_sample_data: false,
        replication: ReplicationConfig::default(),
    };

    handler.run_non_interactive_setup(config).await.unwrap();

    assert!(config_dir.is_dir());
    assert!(config_dir.join("server.toml").is_file());
    assert!(config_dir.join("log4rs.yml").is_file());
    assert!(config_dir.join("admin.ldif").is_file());
    assert!(config_dir.join("base.ldif").is_file());
}

#[tokio::test]
async fn test_setup_generates_bundled_schema_files() {
    let temp_dir = TempDir::new().unwrap();
    let config_dir = temp_dir.path().join("config");
    let schema_dir = config_dir.join("schema");
    let handler = SetupHandler::new(&config_dir);

    let written = handler
        .generate_builtin_schema_files(&schema_dir, &["all".to_string()], false)
        .await
        .unwrap();

    let core_schema = schema_dir.join("core").join("rfc3672.ldif");
    let posix_schema = schema_dir.join("posix").join("rfc2307.ldif");
    let cosine_schema = schema_dir.join("cosine").join("rfc4524.ldif");
    let x509_schema = schema_dir.join("x509").join("rfc4523.ldif");
    assert_eq!(
        written,
        vec![
            core_schema.clone(),
            posix_schema.clone(),
            cosine_schema.clone(),
            x509_schema.clone()
        ]
    );
    assert!(core_schema.is_file());
    assert!(posix_schema.is_file());
    assert!(cosine_schema.is_file());
    assert!(x509_schema.is_file());

    let mut schema = LdapSchema::with_core_schema();
    schema.load_schema_dir(&schema_dir).unwrap();
    assert!(schema.get_object_class("subentry").is_some());
    assert!(schema.get_object_class("posixAccount").is_some());
    assert!(schema.get_object_class("nisNetgroup").is_some());
    assert!(schema.get_object_class("document").is_some());
    assert!(schema.get_object_class("simpleSecurityObject").is_some());
    assert!(schema.get_object_class("pkiUser").is_some());
    assert!(schema.get_object_class("cRLDistributionPoint").is_some());
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
        tls: TlsConfig::default(),
        hostname: "localhost".to_string(),
        organization_name: "Example Organization".to_string(),
        replica_id: 1,
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
        tls: TlsConfig::default(),
        hostname: "localhost".to_string(),
        organization_name: "Test Org".to_string(),
        replica_id: 1,
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
        tls: TlsConfig::default(),
        hostname: "localhost".to_string(),
        organization_name: "Example Org".to_string(),
        replica_id: 1,
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
        tls: TlsConfig::default(),
        hostname: "localhost".to_string(),
        organization_name: "LMDB Test".to_string(),
        replica_id: 1,
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
            tls: TlsConfig::default(),
            hostname: "localhost".to_string(),
            organization_name: "Test".to_string(),
            replica_id: 1,
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
        tls: TlsConfig::default(),
        hostname: "localhost".to_string(),
        organization_name: "Test".to_string(),
        replica_id: 1,
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
        tls: TlsConfig::default(),
        hostname: "localhost".to_string(),
        organization_name: "State Test".to_string(),
        replica_id: 1,
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
        tls: TlsConfig::default(),
        hostname: "localhost".to_string(),
        organization_name: "Complex DN Test".to_string(),
        replica_id: 1,
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
        tls: TlsConfig::default(),
        hostname: "localhost".to_string(),
        organization_name: "Serial Test".to_string(),
        replica_id: 1,
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
        tls: TlsConfig::default(),
        hostname: "localhost".to_string(),
        organization_name: "Hash Test".to_string(),
        replica_id: 1,
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
        tls: TlsConfig::default(),
        hostname: "localhost".to_string(),
        organization_name: "OU Test".to_string(),
        replica_id: 1,
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
        tls: TlsConfig::default(),
        hostname: "localhost".to_string(),
        organization_name: "Replication Test".to_string(),
        replica_id: 1,
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
        tls: TlsConfig::default(),
        hostname: "localhost".to_string(),
        organization_name: "Replication Test".to_string(),
        replica_id: 1,
        backend_type: BackendType::Lmdb,
        data_directory: PathBuf::from("/tmp/data"),
        import_sample_data: false,
        replication: ReplicationConfig {
            enabled: true,
            role: ReplicationRole::Consumer,
            provider: None,
            consumer: Some(ConsumerConfig {
                provider_url: "ldaps://provider.example.com:1636".to_string(),
                provider_bind_dn: Some("cn=replication".to_string()),
                provider_bind_password: Some("secret".to_string()),
                provider_bind_password_env: None,
                provider_bind_password_file: None,
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
provider_url = "ldaps://provider:1636"
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
        tls: TlsConfig::default(),
        hostname: "localhost".to_string(),
        organization_name: "Example Org".to_string(),
        replica_id: 1,
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
    let log_config_path = config_dir.join("log4rs.yml");
    assert!(
        log_config_path.exists(),
        "Log config file should be created at {:?}",
        log_config_path
    );
    let log_config_content = tokio::fs::read_to_string(&log_config_path).await.unwrap();
    assert!(log_config_content.contains("kind: console"));
    assert!(log_config_content.contains("root:"));

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
        tls: TlsConfig::default(),
        hostname: "localhost".to_string(),
        organization_name: "Example Org".to_string(),
        replica_id: 1,
        backend_type: BackendType::InMemory,
        data_directory: temp_dir.path().join("data"),
        import_sample_data: false,
        replication: ReplicationConfig {
            enabled: true,
            role: ReplicationRole::Consumer,
            provider: None,
            consumer: Some(ConsumerConfig {
                provider_url: "ldaps://provider.example.com:1636".to_string(),
                provider_bind_dn: Some("cn=replication,dc=example,dc=com".to_string()),
                provider_bind_password: Some("replica-secret".to_string()),
                provider_bind_password_env: None,
                provider_bind_password_file: None,
                sync_interval_secs: 45,
                max_retry_attempts: 8,
                retry_delay_secs: 12,
                enable_change_listening: true,
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
        Some("ldaps://provider.example.com:1636")
    );
    assert_eq!(
        loaded_config.replication.bind_dn.as_deref(),
        Some("cn=replication,dc=example,dc=com")
    );
    assert_eq!(loaded_config.replication.max_retry_attempts, 8);
    assert_eq!(loaded_config.replication.retry_delay_secs, 12);
    assert!(loaded_config.replication.enable_change_listening);
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

#[tokio::test]
async fn test_setup_handler_generates_canonical_both_replication_config() {
    let temp_dir = TempDir::new().unwrap();
    let config_dir = temp_dir.path().to_path_buf();
    let handler = SetupHandler::new(&config_dir);

    let config = SetupConfig {
        base_dn: "dc=example,dc=com".to_string(),
        root_user_dn: "cn=manager".to_string(),
        root_password: "SecurePass123".to_string(),
        ldap_port: 1389,
        ldaps_port: 1636,
        tls: TlsConfig::default(),
        hostname: "localhost".to_string(),
        organization_name: "Example Org".to_string(),
        replica_id: 3,
        backend_type: BackendType::Lmdb,
        data_directory: temp_dir.path().join("data"),
        import_sample_data: false,
        replication: ReplicationConfig {
            enabled: true,
            role: ReplicationRole::Both,
            provider: Some(ProviderConfig {
                changelog_enabled: true,
                changelog_max_entries: 200000,
                max_batch_size: 200,
                enable_streaming: true,
                heartbeat_interval_secs: 60,
                max_concurrent_consumers: 12,
                consumer_timeout_secs: 360,
            }),
            consumer: Some(ConsumerConfig {
                provider_url: "ldaps://peer.example.com:1636".to_string(),
                provider_bind_dn: Some("cn=replication,dc=example,dc=com".to_string()),
                provider_bind_password: None,
                provider_bind_password_env: Some("OPENDR_REPLICATION_BIND_PASSWORD".to_string()),
                provider_bind_password_file: None,
                sync_interval_secs: 15,
                max_retry_attempts: 5,
                retry_delay_secs: 7,
                enable_change_listening: true,
                heartbeat_interval_secs: 60,
                max_batch_size: 200,
                provider_timeout_secs: 45,
                state_persistence_timeout_secs: 20,
                change_buffer_size: 2048,
                state_storage_path: temp_dir.path().join("replication_state"),
            }),
        },
    };

    handler
        .run_non_interactive_setup(config.clone())
        .await
        .unwrap();

    let config_path = config_dir.join("server.toml");
    let config_content = tokio::fs::read_to_string(&config_path).await.unwrap();

    assert!(config_content.contains("runtime = \"fsm\""));
    assert!(config_content.contains("replica_id = 3"));
    assert!(config_content.contains("mode = \"both\""));
    assert!(config_content.contains("bind_dn = \"cn=replication,dc=example,dc=com\""));
    assert!(config_content.contains("bind_password_env = \"OPENDR_REPLICATION_BIND_PASSWORD\""));
    assert!(config_content.contains("changelog_capacity = 200000"));
    assert!(!config_content.contains("role = "));
    assert!(!config_content.contains("provider_bind_dn"));
    assert!(!config_content.contains("changelog_max_entries"));

    let loaded_config = ServerConfig::from_toml_str(&config_content)
        .map_err(|e| {
            format!(
                "Failed to deserialize server config: {}\nConfig content:\n{}",
                e, config_content
            )
        })
        .unwrap();

    assert!(loaded_config.replication.enabled);
    assert_eq!(loaded_config.server.replica_id, 3);
    assert_eq!(loaded_config.replication.mode, "both");
    assert_eq!(loaded_config.replication.changelog_capacity, 200000);
    assert_eq!(
        loaded_config.replication.provider_url.as_deref(),
        Some("ldaps://peer.example.com:1636")
    );
    assert_eq!(
        loaded_config.replication.bind_password_env.as_deref(),
        Some("OPENDR_REPLICATION_BIND_PASSWORD")
    );
    assert_eq!(
        loaded_config.replication.state_storage_path,
        temp_dir.path().join("replication_state")
    );
}

#[tokio::test]
async fn test_setup_handler_generates_loadable_tls_config() {
    let temp_dir = TempDir::new().unwrap();
    let config_dir = temp_dir.path().to_path_buf();
    let handler = SetupHandler::new(&config_dir);
    let cert_dir = temp_dir.path().join("certs");
    tokio::fs::create_dir_all(&cert_dir).await.unwrap();
    let cert_file = cert_dir.join("server.crt");
    let key_file = cert_dir.join("server.key");
    let ca_file = cert_dir.join("ca.crt");
    tokio::fs::write(&cert_file, "test certificate")
        .await
        .unwrap();
    tokio::fs::write(&key_file, "test private key")
        .await
        .unwrap();
    tokio::fs::write(&ca_file, "test ca").await.unwrap();

    let config = SetupConfig {
        base_dn: "dc=example,dc=com".to_string(),
        root_user_dn: "cn=manager".to_string(),
        root_password: "SecurePass123".to_string(),
        ldap_port: 1389,
        ldaps_port: 1636,
        tls: TlsConfig {
            enabled: true,
            cert_file: cert_file.clone(),
            key_file: key_file.clone(),
            ca_file: Some(ca_file.clone()),
            require_client_cert: true,
            min_tls_version: "1.3".to_string(),
        },
        hostname: "localhost".to_string(),
        organization_name: "Example Org".to_string(),
        replica_id: 4,
        backend_type: BackendType::InMemory,
        data_directory: temp_dir.path().join("data"),
        import_sample_data: false,
        replication: ReplicationConfig::default(),
    };

    handler
        .run_non_interactive_setup(config.clone())
        .await
        .unwrap();

    let config_content = tokio::fs::read_to_string(config_dir.join("server.toml"))
        .await
        .unwrap();

    assert!(config_content.contains("[tls]"));
    assert!(config_content.contains("enabled = true"));
    assert!(config_content.contains("require_client_cert = true"));
    assert!(config_content.contains("min_tls_version = \"1.3\""));
    assert!(config_content.contains(&cert_file.display().to_string()));
    assert!(config_content.contains(&key_file.display().to_string()));
    assert!(config_content.contains(&ca_file.display().to_string()));

    let loaded_config = ServerConfig::from_toml_str(&config_content).unwrap();

    assert!(loaded_config.tls.enabled);
    assert_eq!(loaded_config.tls.cert_file, cert_file);
    assert_eq!(loaded_config.tls.key_file, key_file);
    assert_eq!(loaded_config.tls.ca_file, Some(ca_file));
    assert!(loaded_config.tls.require_client_cert);
    assert_eq!(loaded_config.tls.min_tls_version, "1.3");
    assert!(loaded_config.validate().is_ok());
}

#[tokio::test]
async fn test_setup_provider_creates_replication_state_directory() {
    let temp_dir = TempDir::new().unwrap();
    let config_dir = temp_dir.path().to_path_buf();
    let handler = SetupHandler::new(&config_dir);
    let data_directory = temp_dir.path().join("provider_data");
    let state_directory = data_directory.join("replication_state");

    let config = SetupConfig {
        base_dn: "dc=example,dc=com".to_string(),
        root_user_dn: "cn=manager".to_string(),
        root_password: "SecurePass123".to_string(),
        ldap_port: 1389,
        ldaps_port: 1636,
        tls: TlsConfig::default(),
        hostname: "localhost".to_string(),
        organization_name: "Example Org".to_string(),
        replica_id: 11,
        backend_type: BackendType::InMemory,
        data_directory,
        import_sample_data: false,
        replication: ReplicationConfig {
            enabled: true,
            role: ReplicationRole::Provider,
            provider: Some(ProviderConfig {
                changelog_enabled: true,
                changelog_max_entries: 10_000,
                max_batch_size: 100,
                enable_streaming: true,
                heartbeat_interval_secs: 30,
                max_concurrent_consumers: 10,
                consumer_timeout_secs: 300,
            }),
            consumer: None,
        },
    };

    handler.run_non_interactive_setup(config).await.unwrap();

    assert!(
        state_directory.exists(),
        "provider replication state directory should be created at {:?}",
        state_directory
    );

    let generated_config = tokio::fs::read_to_string(config_dir.join("server.toml"))
        .await
        .unwrap();
    let loaded_config = ServerConfig::from_toml_str(&generated_config).unwrap();

    assert_eq!(loaded_config.replication.mode, "provider");
    assert_eq!(
        loaded_config.replication.state_storage_path,
        state_directory
    );
}

#[tokio::test]
async fn test_setup_consumer_file_secret_source_does_not_inline_secret() {
    let temp_dir = TempDir::new().unwrap();
    let config_dir = temp_dir.path().to_path_buf();
    let handler = SetupHandler::new(&config_dir);
    let secret_file = temp_dir.path().join("replication-password.txt");
    tokio::fs::write(&secret_file, "file-backed-replication-secret\n")
        .await
        .unwrap();

    let config = SetupConfig {
        base_dn: "dc=example,dc=com".to_string(),
        root_user_dn: "cn=manager".to_string(),
        root_password: "SecurePass123".to_string(),
        ldap_port: 1389,
        ldaps_port: 1636,
        tls: TlsConfig::default(),
        hostname: "localhost".to_string(),
        organization_name: "Example Org".to_string(),
        replica_id: 12,
        backend_type: BackendType::InMemory,
        data_directory: temp_dir.path().join("consumer_data"),
        import_sample_data: false,
        replication: ReplicationConfig {
            enabled: true,
            role: ReplicationRole::Consumer,
            provider: None,
            consumer: Some(ConsumerConfig {
                provider_url: "ldaps://provider.example.com:1636".to_string(),
                provider_bind_dn: Some("cn=replication,dc=example,dc=com".to_string()),
                provider_bind_password: None,
                provider_bind_password_env: None,
                provider_bind_password_file: Some(secret_file.clone()),
                sync_interval_secs: 60,
                max_retry_attempts: 5,
                retry_delay_secs: 10,
                enable_change_listening: true,
                heartbeat_interval_secs: 30,
                max_batch_size: 100,
                provider_timeout_secs: 45,
                state_persistence_timeout_secs: 15,
                change_buffer_size: 1024,
                state_storage_path: temp_dir.path().join("consumer_replication_state"),
            }),
        },
    };

    handler.run_non_interactive_setup(config).await.unwrap();

    let generated_config = tokio::fs::read_to_string(config_dir.join("server.toml"))
        .await
        .unwrap();

    assert!(generated_config.contains("bind_password_file = "));
    assert!(generated_config.contains(&secret_file.display().to_string()));
    assert!(!generated_config.contains("bind_password = "));
    assert!(!generated_config.contains("file-backed-replication-secret"));

    let loaded_config = ServerConfig::from_toml_str(&generated_config).unwrap();

    assert_eq!(
        loaded_config.replication.bind_password_file,
        Some(secret_file)
    );
    assert_eq!(
        loaded_config.resolved_replication_bind_password().unwrap(),
        Some("file-backed-replication-secret".to_string())
    );
}

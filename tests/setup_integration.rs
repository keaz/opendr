// Integration tests for server setup functionality

use opendr::setup::{BackendType, SetupConfig, SetupHandler};
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
    };

    handler.run_non_interactive_setup(strong_config).await.unwrap();
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
    };

    handler.run_non_interactive_setup(config.clone()).await.unwrap();

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
            return line.replace("userPassword: {SSHA512}", "").trim().to_string();
        }
    }
    String::new()
}

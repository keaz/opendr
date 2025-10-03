use std::error::Error;
use std::sync::Arc;
use std::collections::HashMap;
use std::path::Path;

use opendr::backend::{DirectoryBackend, DirectoryEntry, MockBackend};
use opendr::backend_lmdb::LmdbBackend;
use opendr::setup::{SetupConfig, BackendType};
use opendr::server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    log4rs::init_file("config/log4rs.yml", Default::default()).unwrap();

    // Load configuration from server.toml
    let config = load_config("config/server.toml").await?;

    // Create backend based on configuration
    let backend: Arc<dyn DirectoryBackend> = match config.backend_type {
        BackendType::Lmdb => {
            println!("Initializing LMDB backend at {:?}", config.data_directory);

            // Create LMDB backend with 1GB max size
            let mut backend = LmdbBackend::new(&config.data_directory, 1024)?;

            // Initialize with base structure if needed
            match backend.get_entry(&config.base_dn).await {
                Ok(Some(_)) => {
                    println!("Base DN exists, skipping initialization");
                },
                Ok(None) | Err(_) => {
                    println!("Initializing base directory structure...");
                    initialize_base_structure(&mut backend, &config).await?;
                }
            }

            Arc::new(backend)
        }
        BackendType::InMemory => {
            println!("Initializing in-memory backend (MockBackend)");

            // Create mock backend with credentials from config
            let mut backend = MockBackend::from_credentials([(
                &format!("{},{}", config.root_user_dn, config.base_dn),
                config.root_password.as_bytes().to_vec(),
            )]);

            // Add base structure entries
            initialize_base_structure(&mut backend, &config).await?;

            Arc::new(backend)
        }
        BackendType::Custom(ref name) => {
            return Err(format!("Unsupported backend type: {}", name).into());
        }
    };

    let bind_addr = format!("127.0.0.1:{}", config.ldap_port);
    println!("Starting LDAP server on {}", bind_addr);

    server::run(&bind_addr, backend)
        .await
        .map_err(|err| Box::new(err) as Box<dyn Error>)
}

/// Load configuration from TOML file
async fn load_config(path: impl AsRef<Path>) -> Result<SetupConfig, Box<dyn Error>> {
    let content = tokio::fs::read_to_string(path).await?;
    let config: SetupConfig = toml::from_str(&content)?;
    Ok(config)
}

/// Initialize base directory structure
async fn initialize_base_structure(
    backend: &mut dyn DirectoryBackend,
    config: &SetupConfig,
) -> Result<(), Box<dyn Error>> {
    // Add root DN entry
    let base_dn_entry = DirectoryEntry::new(
        &config.base_dn,
        HashMap::from([
            ("objectClass".to_string(), vec!["top".to_string(), "organization".to_string()]),
            ("o".to_string(), vec![config.organization_name.clone()]),
            ("description".to_string(), vec![config.organization_name.clone()]),
        ])
    );
    backend.add_entry(base_dn_entry, vec![]).await?;

    // Add root user entry with password
    let root_user_entry = DirectoryEntry::new(
        &format!("{},{}", config.root_user_dn, config.base_dn),
        HashMap::from([
            ("objectClass".to_string(), vec!["top".to_string(), "person".to_string()]),
            ("cn".to_string(), vec![config.root_user_dn.split('=').nth(1).unwrap_or("manager").to_string()]),
            ("sn".to_string(), vec!["Manager".to_string()]),
        ])
    );
    backend.add_entry(root_user_entry, config.root_password.as_bytes().to_vec()).await?;

    // Add organizational units
    let people_ou_entry = DirectoryEntry::new(
        &format!("ou=People,{}", config.base_dn),
        HashMap::from([
            ("objectClass".to_string(), vec!["top".to_string(), "organizationalUnit".to_string()]),
            ("ou".to_string(), vec!["People".to_string()]),
            ("description".to_string(), vec!["People container".to_string()]),
        ])
    );
    backend.add_entry(people_ou_entry, vec![]).await?;

    let groups_ou_entry = DirectoryEntry::new(
        &format!("ou=Groups,{}", config.base_dn),
        HashMap::from([
            ("objectClass".to_string(), vec!["top".to_string(), "organizationalUnit".to_string()]),
            ("ou".to_string(), vec!["Groups".to_string()]),
            ("description".to_string(), vec!["Groups container".to_string()]),
        ])
    );
    backend.add_entry(groups_ou_entry, vec![]).await?;

    let apps_ou_entry = DirectoryEntry::new(
        &format!("ou=Applications,{}", config.base_dn),
        HashMap::from([
            ("objectClass".to_string(), vec!["top".to_string(), "organizationalUnit".to_string()]),
            ("ou".to_string(), vec!["Applications".to_string()]),
            ("description".to_string(), vec!["Applications container".to_string()]),
        ])
    );
    backend.add_entry(apps_ou_entry, vec![]).await?;

    println!("Base directory structure initialized");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_load_config_from_file() {
        // Create a temporary config file
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("test_server.toml");

        let config_content = r#"
            base_dn = "dc=test,dc=com"
            root_user_dn = "cn=admin"
            root_password = "TestPassword123"
            ldap_port = 3389
            ldaps_port = 3636
            hostname = "testhost"
            organization_name = "Test Org"
            backend_type = "Lmdb"
            data_directory = "./test_data"
            import_sample_data = true
        "#;

        tokio::fs::write(&config_path, config_content).await.unwrap();

        // Load the configuration
        let config = load_config(&config_path).await.unwrap();

        // Verify configuration values
        assert_eq!(config.base_dn, "dc=test,dc=com");
        assert_eq!(config.root_user_dn, "cn=admin");
        assert_eq!(config.root_password, "TestPassword123");
        assert_eq!(config.ldap_port, 3389);
        assert_eq!(config.ldaps_port, 3636);
        assert_eq!(config.hostname, "testhost");
        assert_eq!(config.organization_name, "Test Org");
        assert_eq!(config.backend_type, BackendType::Lmdb);
        assert_eq!(config.import_sample_data, true);
    }

    #[tokio::test]
    async fn test_initialize_base_structure_inmemory() {
        let config = SetupConfig {
            base_dn: "dc=example,dc=org".to_string(),
            root_user_dn: "cn=manager".to_string(),
            root_password: "secret".to_string(),
            ldap_port: 1389,
            ldaps_port: 1636,
            hostname: "localhost".to_string(),
            organization_name: "Example Org".to_string(),
            backend_type: BackendType::InMemory,
            data_directory: "./data".into(),
            import_sample_data: false,
        };

        let mut backend = MockBackend::new();
        initialize_base_structure(&mut backend, &config).await.unwrap();

        // Verify base DN entry was created
        let base_entry = backend.get_entry("dc=example,dc=org").await.unwrap().unwrap();
        // Attributes are normalized to lowercase
        assert!(base_entry.attributes.contains_key("objectclass"));
        assert_eq!(base_entry.attributes["o"][0], "Example Org");

        // Verify root user entry was created
        let root_entry = backend.get_entry("cn=manager,dc=example,dc=org").await.unwrap().unwrap();
        assert!(root_entry.attributes.contains_key("cn"));

        // Verify organizational units were created
        assert!(backend.get_entry("ou=People,dc=example,dc=org").await.is_ok());
        assert!(backend.get_entry("ou=Groups,dc=example,dc=org").await.is_ok());
        assert!(backend.get_entry("ou=Applications,dc=example,dc=org").await.is_ok());

        // Verify authentication works with root user
        assert!(backend.authenticate("cn=manager,dc=example,dc=org", b"secret").await.unwrap());
        assert!(!backend.authenticate("cn=manager,dc=example,dc=org", b"wrong").await.unwrap());
    }

    #[tokio::test]
    async fn test_initialize_base_structure_lmdb() {
        let temp_dir = TempDir::new().unwrap();
        let config = SetupConfig {
            base_dn: "dc=test,dc=local".to_string(),
            root_user_dn: "cn=admin".to_string(),
            root_password: "AdminPass123".to_string(),
            ldap_port: 1389,
            ldaps_port: 1636,
            hostname: "localhost".to_string(),
            organization_name: "Test Org".to_string(),
            backend_type: BackendType::Lmdb,
            data_directory: temp_dir.path().to_path_buf(),
            import_sample_data: false,
        };

        let mut backend = LmdbBackend::new(temp_dir.path(), 100).unwrap();
        initialize_base_structure(&mut backend, &config).await.unwrap();

        // Verify base DN entry was created
        let base_entry = backend.get_entry("dc=test,dc=local").await.unwrap().unwrap();
        // Attributes are normalized to lowercase
        assert!(base_entry.attributes.contains_key("objectclass"));
        assert_eq!(base_entry.attributes["o"][0], "Test Org");

        // Verify root user entry was created
        let root_entry = backend.get_entry("cn=admin,dc=test,dc=local").await.unwrap().unwrap();
        assert!(root_entry.attributes.contains_key("cn"));

        // Verify organizational units were created
        assert!(backend.get_entry("ou=People,dc=test,dc=local").await.is_ok());
        assert!(backend.get_entry("ou=Groups,dc=test,dc=local").await.is_ok());
        assert!(backend.get_entry("ou=Applications,dc=test,dc=local").await.is_ok());

        // Verify authentication works with root user
        assert!(backend.authenticate("cn=admin,dc=test,dc=local", b"AdminPass123").await.unwrap());
        assert!(!backend.authenticate("cn=admin,dc=test,dc=local", b"wrong").await.unwrap());
    }
}

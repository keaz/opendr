use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;

use opendr::backend::{DirectoryBackend, DirectoryEntry, MockBackend};
use opendr::backend_lmdb::LmdbBackend;
use opendr::config::ServerConfig;
use opendr::replication_service::ReplicationService;
use opendr::server;
use opendr::shutdown::{ShutdownConfig, ShutdownCoordinator};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    log4rs::init_file("config/log4rs.yml", Default::default()).unwrap();

    // Load configuration from server.toml
    let config = ServerConfig::from_file("config/server.toml")?;

    // Validate configuration
    config.validate()?;
    config.validate_for_shipped_binary()?;
    let root_password = config.resolved_root_password()?;

    // Create shutdown coordinator
    let shutdown_config = ShutdownConfig::default();
    let shutdown = Arc::new(ShutdownCoordinator::new(shutdown_config));

    // Install signal handlers
    let shutdown_signal = shutdown.install_signal_handlers();
    let shutdown_clone = shutdown.clone();

    // Spawn signal handler task
    tokio::spawn(async move {
        shutdown_signal.wait().await;
        println!("\nShutdown signal received, initiating graceful shutdown...");
    });

    // Create backend based on configuration
    let raw_backend: Arc<dyn DirectoryBackend> =
        match config.backend.backend_type.to_lowercase().as_str() {
            "lmdb" => {
                println!(
                    "Initializing LMDB backend at {:?}",
                    config.backend.data_directory
                );

                // Create LMDB backend with configured max size (convert to MB)
                let max_size_mb = (config.backend.lmdb_max_size / (1024 * 1024)) as usize;
                let replica_id = config.server.replica_id;
                let mut backend =
                    LmdbBackend::new(&config.backend.data_directory, max_size_mb, replica_id)?;

                // Initialize with base structure if needed
                match backend.get_entry(&config.server.base_dn).await {
                    Ok(Some(_)) => {
                        println!("Base DN exists, skipping initialization");
                    }
                    Ok(None) | Err(_) => {
                        println!("Initializing base directory structure...");
                        initialize_lmdb_base_structure(&mut backend, &config, &root_password)
                            .await?;
                    }
                }

                Arc::new(backend)
            }
            "memory" => {
                println!("Initializing in-memory backend (MockBackend)");

                // Create mock backend with credentials from config
                let mut backend = MockBackend::from_credentials_with_replica_id(
                    [(
                        &format!("{},{}", config.server.root_user_dn, config.server.base_dn),
                        root_password.as_bytes().to_vec(),
                    )],
                    config.server.replica_id,
                );

                // Add base structure entries
                initialize_base_structure(&mut backend, &config, &root_password).await?;

                Arc::new(backend)
            }
            backend_type => {
                return Err(format!("Unsupported backend type: {}", backend_type).into());
            }
        };

    // Wrap backend with replication service if configured
    let replication_service = ReplicationService::from_config(&config, raw_backend)?;

    // Get the backend to use (wrapped with changelog if provider enabled)
    let backend = replication_service.backend();

    // Start replication provider if enabled
    let provider_handle = match replication_service.start_provider(shutdown.clone()).await {
        Ok(Some(handle)) => {
            println!("Replication provider started");
            Some(handle)
        }
        Ok(None) => None,
        Err(e) => {
            eprintln!("Failed to start replication provider: {}", e);
            None
        }
    };

    // Start replication consumer if enabled
    let consumer_handle = match replication_service.start_consumer(shutdown.clone()).await {
        Ok(Some(handle)) => {
            println!("Replication consumer started");
            Some(handle)
        }
        Ok(None) => None,
        Err(e) => {
            eprintln!("Failed to start replication consumer: {}", e);
            None
        }
    };

    let bind_addr = config.ldap_bind_address();
    println!("Starting LDAP server on {}", bind_addr);

    // Create a channel for server shutdown
    let shutdown_rx = shutdown_clone.subscribe();

    // Run server with shutdown support
    let selected_runtime = config.server.runtime.clone();
    let server_task = tokio::spawn(async move {
        let result = match selected_runtime.as_str() {
            "legacy" => server::run(&bind_addr, backend, shutdown_rx).await,
            unsupported => Err(std::io::Error::other(format!(
                "server.runtime = {:?} is not supported by the shipped opendr binary",
                unsupported
            ))
            .into()),
        };

        if let Err(e) = result {
            eprintln!("Server error: {}", e);
        }
    });

    // Wait for shutdown signal
    let mut shutdown_signal_rx = shutdown_clone.subscribe();
    let _ = shutdown_signal_rx.recv().await;

    println!("Shutting down server...");

    // Execute shutdown sequence
    shutdown_clone.drain().await;
    shutdown_clone.complete_shutdown().await;

    // Wait for server task to finish
    match server_task.await {
        Ok(()) => println!("Server shutdown complete"),
        Err(e) => eprintln!("Server task error: {}", e),
    }

    // Wait for replication provider to finish if it was started
    if let Some(handle) = provider_handle {
        match handle.await {
            Ok(()) => println!("Replication provider shutdown complete"),
            Err(e) => eprintln!("Replication provider task error: {}", e),
        }
    }

    // Wait for replication consumer to finish if it was started
    if let Some(handle) = consumer_handle {
        match handle.await {
            Ok(()) => println!("Replication consumer shutdown complete"),
            Err(e) => eprintln!("Replication consumer task error: {}", e),
        }
    }

    Ok(())
}

/// Initialize base directory structure
async fn initialize_base_structure(
    backend: &mut dyn DirectoryBackend,
    config: &ServerConfig,
    root_password: &str,
) -> Result<(), Box<dyn Error>> {
    // Add root DN entry
    let base_dn_entry = DirectoryEntry::new(
        &config.server.base_dn,
        HashMap::from([
            (
                "objectClass".to_string(),
                vec!["top".to_string(), "organization".to_string()],
            ),
            (
                "o".to_string(),
                vec![config.server.organization_name.clone()],
            ),
            (
                "description".to_string(),
                vec![config.server.organization_name.clone()],
            ),
        ]),
    );
    backend.add_entry(base_dn_entry, vec![]).await?;

    // Add root user entry with password
    let root_user_entry = DirectoryEntry::new(
        &format!("{},{}", config.server.root_user_dn, config.server.base_dn),
        HashMap::from([
            (
                "objectClass".to_string(),
                vec!["top".to_string(), "person".to_string()],
            ),
            (
                "cn".to_string(),
                vec![config
                    .server
                    .root_user_dn
                    .split('=')
                    .nth(1)
                    .unwrap_or("manager")
                    .to_string()],
            ),
            ("sn".to_string(), vec!["Manager".to_string()]),
        ]),
    );
    backend
        .add_entry(root_user_entry, root_password.as_bytes().to_vec())
        .await?;

    // Add organizational units
    let people_ou_entry = DirectoryEntry::new(
        &format!("ou=People,{}", config.server.base_dn),
        HashMap::from([
            (
                "objectClass".to_string(),
                vec!["top".to_string(), "organizationalUnit".to_string()],
            ),
            ("ou".to_string(), vec!["People".to_string()]),
            (
                "description".to_string(),
                vec!["People container".to_string()],
            ),
        ]),
    );
    backend.add_entry(people_ou_entry, vec![]).await?;

    let groups_ou_entry = DirectoryEntry::new(
        &format!("ou=Groups,{}", config.server.base_dn),
        HashMap::from([
            (
                "objectClass".to_string(),
                vec!["top".to_string(), "organizationalUnit".to_string()],
            ),
            ("ou".to_string(), vec!["Groups".to_string()]),
            (
                "description".to_string(),
                vec!["Groups container".to_string()],
            ),
        ]),
    );
    backend.add_entry(groups_ou_entry, vec![]).await?;

    let apps_ou_entry = DirectoryEntry::new(
        &format!("ou=Applications,{}", config.server.base_dn),
        HashMap::from([
            (
                "objectClass".to_string(),
                vec!["top".to_string(), "organizationalUnit".to_string()],
            ),
            ("ou".to_string(), vec!["Applications".to_string()]),
            (
                "description".to_string(),
                vec!["Applications container".to_string()],
            ),
        ]),
    );
    backend.add_entry(apps_ou_entry, vec![]).await?;

    println!("Base directory structure initialized");
    Ok(())
}

/// Initialize base directory structure for LMDB backend
async fn initialize_lmdb_base_structure(
    backend: &mut LmdbBackend,
    config: &ServerConfig,
    root_password: &str,
) -> Result<(), Box<dyn Error>> {
    // Add root DN entry
    let base_dn_entry = DirectoryEntry::new(
        &config.server.base_dn,
        HashMap::from([
            (
                "objectClass".to_string(),
                vec!["top".to_string(), "organization".to_string()],
            ),
            (
                "o".to_string(),
                vec![config.server.organization_name.clone()],
            ),
            (
                "description".to_string(),
                vec![config.server.organization_name.clone()],
            ),
        ]),
    );
    backend.add_entry(base_dn_entry, vec![]).await?;

    // Add root user entry (without password initially)
    let root_dn = format!("{},{}", config.server.root_user_dn, config.server.base_dn);
    let root_user_entry = DirectoryEntry::new(
        &root_dn,
        HashMap::from([
            (
                "objectClass".to_string(),
                vec!["top".to_string(), "person".to_string()],
            ),
            (
                "cn".to_string(),
                vec![config
                    .server
                    .root_user_dn
                    .split('=')
                    .nth(1)
                    .unwrap_or("manager")
                    .to_string()],
            ),
            ("sn".to_string(), vec!["Manager".to_string()]),
        ]),
    );
    backend.add_entry(root_user_entry, vec![]).await?;

    // Set the pre-hashed password from config
    backend
        .set_prehashed_password(&root_dn, root_password)
        .await?;

    // Add organizational units
    let people_ou_entry = DirectoryEntry::new(
        &format!("ou=People,{}", config.server.base_dn),
        HashMap::from([
            (
                "objectClass".to_string(),
                vec!["top".to_string(), "organizationalUnit".to_string()],
            ),
            ("ou".to_string(), vec!["People".to_string()]),
            (
                "description".to_string(),
                vec!["People container".to_string()],
            ),
        ]),
    );
    backend.add_entry(people_ou_entry, vec![]).await?;

    let groups_ou_entry = DirectoryEntry::new(
        &format!("ou=Groups,{}", config.server.base_dn),
        HashMap::from([
            (
                "objectClass".to_string(),
                vec!["top".to_string(), "organizationalUnit".to_string()],
            ),
            ("ou".to_string(), vec!["Groups".to_string()]),
            (
                "description".to_string(),
                vec!["Groups container".to_string()],
            ),
        ]),
    );
    backend.add_entry(groups_ou_entry, vec![]).await?;

    let apps_ou_entry = DirectoryEntry::new(
        &format!("ou=Applications,{}", config.server.base_dn),
        HashMap::from([
            (
                "objectClass".to_string(),
                vec!["top".to_string(), "organizationalUnit".to_string()],
            ),
            ("ou".to_string(), vec!["Applications".to_string()]),
            (
                "description".to_string(),
                vec!["Applications container".to_string()],
            ),
        ]),
    );
    backend.add_entry(apps_ou_entry, vec![]).await?;

    println!("Base directory structure initialized");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_initialize_base_structure_inmemory() {
        let mut config = ServerConfig::default();
        config.server.base_dn = "dc=example,dc=org".to_string();
        config.server.root_user_dn = "cn=manager".to_string();
        config.server.root_password = "secret".to_string();
        config.server.organization_name = "Example Org".to_string();
        config.backend.backend_type = "memory".to_string();

        let mut backend = MockBackend::new();
        initialize_base_structure(&mut backend, &config, "secret")
            .await
            .unwrap();

        // Verify base DN entry was created
        let base_entry = backend
            .get_entry("dc=example,dc=org")
            .await
            .unwrap()
            .unwrap();
        // Attributes are normalized to lowercase
        assert!(base_entry.attributes.contains_key("objectclass"));
        assert_eq!(base_entry.attributes["o"][0], "Example Org");

        // Verify root user entry was created
        let root_entry = backend
            .get_entry("cn=manager,dc=example,dc=org")
            .await
            .unwrap()
            .unwrap();
        assert!(root_entry.attributes.contains_key("cn"));

        // Verify organizational units were created
        assert!(backend
            .get_entry("ou=People,dc=example,dc=org")
            .await
            .is_ok());
        assert!(backend
            .get_entry("ou=Groups,dc=example,dc=org")
            .await
            .is_ok());
        assert!(backend
            .get_entry("ou=Applications,dc=example,dc=org")
            .await
            .is_ok());

        // Verify authentication works with root user
        assert!(backend
            .authenticate("cn=manager,dc=example,dc=org", b"secret")
            .await
            .unwrap());
        assert!(!backend
            .authenticate("cn=manager,dc=example,dc=org", b"wrong")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_initialize_base_structure_lmdb() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = ServerConfig::default();
        config.server.base_dn = "dc=test,dc=local".to_string();
        config.server.root_user_dn = "cn=admin".to_string();
        config.server.root_password = "AdminPass123".to_string();
        config.server.organization_name = "Test Org".to_string();
        config.backend.backend_type = "lmdb".to_string();
        config.backend.data_directory = temp_dir.path().to_path_buf();

        let mut backend = LmdbBackend::new(temp_dir.path(), 100, 1).unwrap();
        initialize_base_structure(&mut backend, &config, "AdminPass123")
            .await
            .unwrap();

        // Verify base DN entry was created
        let base_entry = backend
            .get_entry("dc=test,dc=local")
            .await
            .unwrap()
            .unwrap();
        // Attributes are normalized to lowercase
        assert!(base_entry.attributes.contains_key("objectclass"));
        assert_eq!(base_entry.attributes["o"][0], "Test Org");

        // Verify root user entry was created
        let root_entry = backend
            .get_entry("cn=admin,dc=test,dc=local")
            .await
            .unwrap()
            .unwrap();
        assert!(root_entry.attributes.contains_key("cn"));

        // Verify organizational units were created
        assert!(backend
            .get_entry("ou=People,dc=test,dc=local")
            .await
            .is_ok());
        assert!(backend
            .get_entry("ou=Groups,dc=test,dc=local")
            .await
            .is_ok());
        assert!(backend
            .get_entry("ou=Applications,dc=test,dc=local")
            .await
            .is_ok());

        // Verify authentication works with root user
        assert!(backend
            .authenticate("cn=admin,dc=test,dc=local", b"AdminPass123")
            .await
            .unwrap());
        assert!(!backend
            .authenticate("cn=admin,dc=test,dc=local", b"wrong")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_initialize_base_structure_inmemory_with_root_password_file() {
        let mut secret_file = NamedTempFile::new().unwrap();
        writeln!(secret_file, "file-backed-secret").unwrap();

        let mut config = ServerConfig::default();
        config.server.base_dn = "dc=example,dc=org".to_string();
        config.server.root_user_dn = "cn=manager".to_string();
        config.server.root_password.clear();
        config.server.root_password_file = Some(secret_file.path().to_path_buf());
        config.server.organization_name = "Example Org".to_string();
        config.backend.backend_type = "memory".to_string();

        let mut backend = MockBackend::new();
        let root_password = config.resolved_root_password().unwrap();
        initialize_base_structure(&mut backend, &config, &root_password)
            .await
            .unwrap();

        assert!(backend
            .authenticate("cn=manager,dc=example,dc=org", b"file-backed-secret")
            .await
            .unwrap());
        assert!(!backend
            .authenticate("cn=manager,dc=example,dc=org", b"wrong")
            .await
            .unwrap());
    }
}

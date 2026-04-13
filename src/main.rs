use std::collections::HashMap;
use std::error::Error;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use opendr::aci::AciEngine;
use opendr::audit::{AuditConfig, AuditFormat, AuditLevel, AuditLogger};
use opendr::backend::{DirectoryBackend, DirectoryEntry, MockBackend};
use opendr::backend_lmdb::{AttributeIndexConfig, IndexConfig, IndexType, LmdbBackend};
use opendr::config::ServerConfig;
use opendr::fsm_server;
use opendr::metrics::MetricsCollector;
use opendr::monitoring_runtime::{
    ComponentStatus, MonitoringRuntimeContext, RuntimeHealthRegistry, console_admin_dn,
    spawn_monitoring_server_with_context,
};
use opendr::replication_service::ReplicationService;
use opendr::server;
use opendr::shutdown::{ShutdownConfig, ShutdownCoordinator};
use opendr::tls::{RustlsTlsHandler, TlsConfig as RuntimeTlsConfig, TlsVersion};

#[derive(Debug, Parser)]
#[command(name = "opendr")]
#[command(about = "OpenDR LDAP server")]
struct Args {
    #[arg(long, default_value = "config/server.toml")]
    config: PathBuf,

    #[arg(long, default_value = "config/log4rs.yml")]
    log_config: PathBuf,
}

fn parse_audit_level(level: &str) -> Result<AuditLevel, Box<dyn Error>> {
    match level {
        "debug" => Ok(AuditLevel::Debug),
        "info" => Ok(AuditLevel::Info),
        "warning" => Ok(AuditLevel::Warning),
        "error" => Ok(AuditLevel::Error),
        "critical" => Ok(AuditLevel::Critical),
        other => Err(format!("unsupported audit level: {}", other).into()),
    }
}

fn parse_audit_format(format: &str) -> Result<AuditFormat, Box<dyn Error>> {
    match format {
        "json" => Ok(AuditFormat::Json),
        "syslog" => Ok(AuditFormat::Syslog),
        "text" => Ok(AuditFormat::Text),
        other => Err(format!("unsupported audit format: {}", other).into()),
    }
}

async fn build_legacy_security_config(
    config: &ServerConfig,
) -> Result<Option<Arc<server::LegacySecurityConfig>>, Box<dyn Error>> {
    let audit_logger = if config.audit.enabled {
        let audit_logger = AuditLogger::with_config(AuditConfig {
            log_path: PathBuf::from(&config.audit.log_file),
            min_level: parse_audit_level(&config.audit.level)?,
            format: parse_audit_format(&config.audit.format)?,
            ..Default::default()
        });
        audit_logger.initialize().await?;
        Some(audit_logger)
    } else {
        None
    };

    let access_control = if config.access_control.enabled {
        let engine = match config.access_control.default_policy.as_str() {
            "allow" => AciEngine::permissive(),
            "deny" => AciEngine::restrictive(),
            other => return Err(format!("unsupported access control policy: {}", other).into()),
        };

        if let Some(rules_file) = config.access_control.rules_file.as_ref() {
            let loaded_rules = engine.load_rules_from_file(rules_file).await?;
            log::info!(
                "Loaded {} ACI rule(s) from {}",
                loaded_rules,
                rules_file.display()
            );
        }

        Some(Arc::new(engine))
    } else {
        None
    };

    if audit_logger.is_none() && access_control.is_none() {
        return Ok(None);
    }

    Ok(Some(Arc::new(server::LegacySecurityConfig {
        audit_logger,
        audit_config: server::LegacyAuditConfig {
            log_authentication: config.audit.log_authentication,
            log_authorization: config.audit.log_authorization,
            log_modifications: config.audit.log_modifications,
            log_connections: config.audit.log_connections,
        },
        access_control,
        root_dn: Some(config.server.root_user_dn.clone()),
    })))
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    tokio::runtime::Runtime::new()?.block_on(run(args))
}

async fn run(args: Args) -> Result<(), Box<dyn Error>> {
    log4rs::init_file(&args.log_config, Default::default()).unwrap();

    // Load configuration from server.toml
    let config_path = args.config.to_string_lossy();
    let config = ServerConfig::from_file(&config_path)?;

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

    let monitoring_metrics = if config.monitoring.enabled {
        Some(MetricsCollector::new())
    } else {
        None
    };
    let monitoring_health = if config.monitoring.enabled {
        Some(RuntimeHealthRegistry::new())
    } else {
        None
    };

    // Create backend based on configuration
    let raw_backend: Arc<dyn DirectoryBackend> =
        match config.backend.backend_type.to_lowercase().as_str() {
            "lmdb" => {
                println!(
                    "Initializing LMDB backend at {:?}",
                    config.backend.data_directory
                );

                // Create LMDB backend with configured max size (convert to MB)
                let max_size_mb = config.backend.lmdb_max_size / (1024 * 1024);
                let replica_id = config.server.replica_id;
                let mut attribute_indexes = Vec::new();
                if config.performance.indexing_enabled {
                    for index in &config.backend.indexes {
                        let mut index_types = Vec::new();
                        for index_type in &index.types {
                            let Some(index_type) = IndexType::from_name(index_type) else {
                                return Err(format!(
                                    "unsupported index type for {}: {}",
                                    index.attribute, index_type
                                )
                                .into());
                            };
                            index_types.push(index_type);
                        }
                        attribute_indexes.push(AttributeIndexConfig {
                            attribute: index.attribute.clone(),
                            index_types,
                        });
                    }
                }
                let index_config = IndexConfig {
                    indexed_attributes: if config.performance.indexing_enabled {
                        config.backend.indexed_attributes.clone()
                    } else {
                        Vec::new()
                    },
                    attribute_indexes,
                };
                println!(
                    "LMDB entry cache capacity: {}",
                    config.performance.cache_size
                );
                let mut backend = LmdbBackend::new_with_runtime_and_cache_config(
                    &config.backend.data_directory,
                    max_size_mb,
                    replica_id,
                    index_config,
                    config.backend.lmdb_max_readers,
                    config.performance.cache_size,
                )?;
                backend.set_metrics(monitoring_metrics.clone());

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

                // Start with an empty in-memory backend; initialize_base_structure
                // installs the base entry and root user with the configured password.
                let mut backend = MockBackend::with_replica_id(config.server.replica_id);

                // Add base structure entries
                initialize_base_structure(&mut backend, &config, &root_password).await?;

                Arc::new(backend)
            }
            backend_type => {
                return Err(format!("Unsupported backend type: {}", backend_type).into());
            }
        };

    if let Some(health) = monitoring_health.as_ref() {
        health
            .set_component(
                "backend",
                ComponentStatus::Healthy,
                Some(format!(
                    "{} backend initialized",
                    config.backend.backend_type.to_lowercase()
                )),
            )
            .await;
    }

    // Wrap backend with replication service if configured
    let replication_service = ReplicationService::from_config(&config, raw_backend)?;

    if let Some(health) = monitoring_health.as_ref() {
        let provider_status = if replication_service.is_provider() {
            (
                ComponentStatus::Degraded,
                Some("replication provider is configured but not started yet".to_string()),
            )
        } else {
            (
                ComponentStatus::Disabled,
                Some("replication provider not enabled".to_string()),
            )
        };
        health
            .set_component("replication_provider", provider_status.0, provider_status.1)
            .await;

        let consumer_status = if replication_service.is_consumer() {
            (
                ComponentStatus::Degraded,
                Some("replication consumer is configured but not started yet".to_string()),
            )
        } else {
            (
                ComponentStatus::Disabled,
                Some("replication consumer not enabled".to_string()),
            )
        };
        health
            .set_component("replication_consumer", consumer_status.0, consumer_status.1)
            .await;
    }

    // Get the backend to use (wrapped with changelog if provider enabled)
    let backend = replication_service.backend();

    // Start replication provider if enabled
    let provider_handle = match replication_service.start_provider(shutdown.clone()).await {
        Ok(Some(handle)) => {
            println!("Replication provider started");
            if let Some(health) = monitoring_health.as_ref() {
                health
                    .set_component(
                        "replication_provider",
                        ComponentStatus::Healthy,
                        Some("replication provider running".to_string()),
                    )
                    .await;
            }
            Some(handle)
        }
        Ok(None) => {
            if let Some(health) = monitoring_health.as_ref() {
                health
                    .set_component(
                        "replication_provider",
                        ComponentStatus::Disabled,
                        Some("replication provider not enabled".to_string()),
                    )
                    .await;
            }
            None
        }
        Err(e) => {
            if let Some(health) = monitoring_health.as_ref() {
                health
                    .set_component(
                        "replication_provider",
                        ComponentStatus::Degraded,
                        Some(format!("replication provider failed to start: {e}")),
                    )
                    .await;
            }
            eprintln!("Failed to start replication provider: {}", e);
            None
        }
    };

    // Start replication consumer if enabled
    let consumer_handle = match replication_service.start_consumer(shutdown.clone()).await {
        Ok(Some(handle)) => {
            println!("Replication consumer started");
            if let Some(health) = monitoring_health.as_ref() {
                health
                    .set_component(
                        "replication_consumer",
                        ComponentStatus::Healthy,
                        Some("replication consumer running".to_string()),
                    )
                    .await;
            }
            Some(handle)
        }
        Ok(None) => {
            if let Some(health) = monitoring_health.as_ref() {
                health
                    .set_component(
                        "replication_consumer",
                        ComponentStatus::Disabled,
                        Some("replication consumer not enabled".to_string()),
                    )
                    .await;
            }
            None
        }
        Err(e) => {
            if let Some(health) = monitoring_health.as_ref() {
                health
                    .set_component(
                        "replication_consumer",
                        ComponentStatus::Degraded,
                        Some(format!("replication consumer failed to start: {e}")),
                    )
                    .await;
            }
            eprintln!("Failed to start replication consumer: {}", e);
            None
        }
    };

    let monitoring_handle = if let (Some(metrics), Some(health)) =
        (monitoring_metrics.clone(), monitoring_health.clone())
    {
        Some(spawn_monitoring_server_with_context(
            config.monitoring.clone(),
            metrics,
            health,
            MonitoringRuntimeContext {
                console_backend: Some(backend.clone()),
                console_admin_dn: Some(console_admin_dn(
                    &config.server.root_user_dn,
                    &config.server.base_dn,
                )),
                replication_status: Some(replication_service.status()),
            },
            shutdown_clone.subscribe(),
        )?)
    } else {
        None
    };

    let bind_addr = config.ldap_bind_address();
    let ldaps_bind_addr = config.ldaps_bind_address();
    println!("Starting LDAP server on {}", bind_addr);
    let fsm_server_config = config.to_fsm_server_config();
    let legacy_server_config = server::LegacyServerConfig::from_server_config(&config);
    let legacy_security_config = build_legacy_security_config(&config).await?;
    let tls_handler = if config.tls.enabled {
        let min_tls_version = match config.tls.min_tls_version.as_str() {
            "1.2" => TlsVersion::Tls12,
            "1.3" => TlsVersion::Tls13,
            other => {
                return Err(format!("unsupported TLS version configured: {}", other).into());
            }
        };

        let runtime_tls_config = RuntimeTlsConfig {
            cert_path: config.tls.cert_file.display().to_string(),
            key_path: config.tls.key_file.display().to_string(),
            ca_file: config
                .tls
                .ca_file
                .as_ref()
                .map(|path| path.display().to_string()),
            min_tls_version,
            max_tls_version: TlsVersion::Tls13,
            require_client_cert: config.tls.require_client_cert,
        };

        Some(Arc::new(RustlsTlsHandler::new(&runtime_tls_config)?))
    } else {
        None
    };

    // Create a channel for server shutdown
    let ldap_shutdown_rx = shutdown_clone.subscribe();
    let ldaps_shutdown_rx = shutdown_clone.subscribe();

    // Run server with shutdown support
    let selected_runtime = config.server.runtime.clone();
    let ldap_backend = backend.clone();
    let ldap_metrics = monitoring_metrics.clone();
    let ldap_runtime_config = legacy_server_config.clone();
    let ldap_fsm_runtime_config = fsm_server_config.clone();
    let ldap_fsm_runtime_context = fsm_server::FsmServerRuntimeContext {
        legacy_runtime_config: legacy_server_config.clone(),
        metrics: monitoring_metrics.clone(),
        security: legacy_security_config.clone(),
        tls_handler: tls_handler.clone(),
    };
    let ldap_tls_handler = tls_handler.clone();
    let ldap_security = legacy_security_config.clone();
    let ldap_shutdown = shutdown.clone();
    let ldap_server_task = tokio::spawn(async move {
        let result = match selected_runtime.as_str() {
            "legacy" => {
                server::run_with_metrics_and_config_with_tls_and_security(
                    &bind_addr,
                    ldap_backend,
                    ldap_shutdown_rx,
                    ldap_metrics,
                    ldap_runtime_config,
                    ldap_tls_handler,
                    ldap_security,
                )
                .await
            }
            "fsm" => {
                fsm_server::run_with_shutdown_and_context(
                    &bind_addr,
                    ldap_backend,
                    ldap_fsm_runtime_config,
                    ldap_fsm_runtime_context,
                    Some(ldap_shutdown),
                )
                .await
            }
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

    let ldaps_server_task = match tls_handler.clone() {
        Some(tls_handler) => {
            let ldaps_backend = backend.clone();
            let ldaps_metrics = monitoring_metrics.clone();
            let ldaps_runtime_config = legacy_server_config.clone();
            let ldaps_fsm_runtime_config = fsm_server_config.clone();
            let ldaps_fsm_runtime_context = fsm_server::FsmServerRuntimeContext {
                legacy_runtime_config: legacy_server_config.clone(),
                metrics: monitoring_metrics.clone(),
                security: legacy_security_config.clone(),
                tls_handler: Some(tls_handler.clone()),
            };
            let ldaps_security = legacy_security_config.clone();
            let ldaps_runtime = config.server.runtime.clone();
            let ldaps_shutdown = shutdown.clone();
            println!("Starting LDAPS server on {}", ldaps_bind_addr);
            Some(tokio::spawn(async move {
                let result = match ldaps_runtime.as_str() {
                    "legacy" => {
                        server::run_tls_with_metrics_and_config_and_security(
                            &ldaps_bind_addr,
                            ldaps_backend,
                            ldaps_shutdown_rx,
                            ldaps_metrics,
                            ldaps_runtime_config,
                            tls_handler,
                            ldaps_security,
                        )
                        .await
                    }
                    "fsm" => {
                        fsm_server::run_tls_with_shutdown_and_context(
                            &ldaps_bind_addr,
                            ldaps_backend,
                            ldaps_fsm_runtime_config,
                            ldaps_fsm_runtime_context,
                            Some(ldaps_shutdown),
                        )
                        .await
                    }
                    unsupported => Err(std::io::Error::other(format!(
                        "server.runtime = {:?} is not supported by the shipped opendr binary",
                        unsupported
                    ))
                    .into()),
                };

                if let Err(e) = result {
                    eprintln!("LDAPS server error: {}", e);
                }
            }))
        }
        _ => None,
    };

    // Wait for shutdown signal
    let mut shutdown_signal_rx = shutdown_clone.subscribe();
    let _ = shutdown_signal_rx.recv().await;

    println!("Shutting down server...");

    // Execute shutdown sequence
    shutdown_clone.drain().await;
    shutdown_clone.complete_shutdown().await;

    // Wait for server task to finish
    match ldap_server_task.await {
        Ok(()) => println!("LDAP server shutdown complete"),
        Err(e) => eprintln!("LDAP server task error: {}", e),
    }

    if let Some(handle) = ldaps_server_task {
        match handle.await {
            Ok(()) => println!("LDAPS server shutdown complete"),
            Err(e) => eprintln!("LDAPS server task error: {}", e),
        }
    }

    if let Some(handle) = monitoring_handle {
        match handle.await {
            Ok(()) => println!("Monitoring server shutdown complete"),
            Err(e) => eprintln!("Monitoring task error: {}", e),
        }
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
        format!("{},{}", config.server.root_user_dn, config.server.base_dn),
        HashMap::from([
            (
                "objectClass".to_string(),
                vec!["top".to_string(), "person".to_string()],
            ),
            (
                "cn".to_string(),
                vec![
                    config
                        .server
                        .root_user_dn
                        .split('=')
                        .nth(1)
                        .unwrap_or("manager")
                        .to_string(),
                ],
            ),
            ("sn".to_string(), vec!["Manager".to_string()]),
        ]),
    );
    backend
        .add_entry(root_user_entry, root_password.as_bytes().to_vec())
        .await?;

    // Add organizational units
    let people_ou_entry = DirectoryEntry::new(
        format!("ou=People,{}", config.server.base_dn),
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
        format!("ou=Groups,{}", config.server.base_dn),
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
        format!("ou=Applications,{}", config.server.base_dn),
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
                vec![
                    config
                        .server
                        .root_user_dn
                        .split('=')
                        .nth(1)
                        .unwrap_or("manager")
                        .to_string(),
                ],
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
        format!("ou=People,{}", config.server.base_dn),
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
        format!("ou=Groups,{}", config.server.base_dn),
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
        format!("ou=Applications,{}", config.server.base_dn),
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
        assert!(
            backend
                .get_entry("ou=People,dc=example,dc=org")
                .await
                .is_ok()
        );
        assert!(
            backend
                .get_entry("ou=Groups,dc=example,dc=org")
                .await
                .is_ok()
        );
        assert!(
            backend
                .get_entry("ou=Applications,dc=example,dc=org")
                .await
                .is_ok()
        );

        // Verify authentication works with root user
        assert!(
            backend
                .authenticate("cn=manager,dc=example,dc=org", b"secret")
                .await
                .unwrap()
        );
        assert!(
            !backend
                .authenticate("cn=manager,dc=example,dc=org", b"wrong")
                .await
                .unwrap()
        );
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
        assert!(
            backend
                .get_entry("ou=People,dc=test,dc=local")
                .await
                .is_ok()
        );
        assert!(
            backend
                .get_entry("ou=Groups,dc=test,dc=local")
                .await
                .is_ok()
        );
        assert!(
            backend
                .get_entry("ou=Applications,dc=test,dc=local")
                .await
                .is_ok()
        );

        // Verify authentication works with root user
        assert!(
            backend
                .authenticate("cn=admin,dc=test,dc=local", b"AdminPass123")
                .await
                .unwrap()
        );
        assert!(
            !backend
                .authenticate("cn=admin,dc=test,dc=local", b"wrong")
                .await
                .unwrap()
        );
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

        assert!(
            backend
                .authenticate("cn=manager,dc=example,dc=org", b"file-backed-secret")
                .await
                .unwrap()
        );
        assert!(
            !backend
                .authenticate("cn=manager,dc=example,dc=org", b"wrong")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn build_legacy_security_config_loads_aci_rules_file() {
        let mut rules_file = NamedTempFile::new().unwrap();
        write!(
            rules_file,
            r#"
[[rules]]
name = "reader-cn"
effect = "grant"
priority = 10
permissions = ["read"]
target = {{ subtree = "dc=example,dc=com", attributes = ["cn"] }}
subject = {{ user = "cn=reader,dc=example,dc=com" }}
"#
        )
        .unwrap();

        let mut config = ServerConfig::default();
        config.audit.enabled = false;
        config.access_control.enabled = true;
        config.access_control.default_policy = "deny".to_string();
        config.access_control.rules_file = Some(rules_file.path().to_path_buf());

        let security = build_legacy_security_config(&config)
            .await
            .unwrap()
            .unwrap();
        let aci_engine = security.access_control.as_ref().unwrap();

        assert!(
            aci_engine
                .check_permission(
                    Some("cn=reader,dc=example,dc=com"),
                    "uid=target,dc=example,dc=com",
                    Some("cn"),
                    opendr::aci::Permission::Read,
                )
                .await
                .is_ok()
        );
        assert!(
            aci_engine
                .check_permission(
                    Some("cn=reader,dc=example,dc=com"),
                    "uid=target,dc=example,dc=com",
                    Some("mail"),
                    opendr::aci::Permission::Read,
                )
                .await
                .is_err()
        );
    }
}

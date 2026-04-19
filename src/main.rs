use std::collections::HashMap;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine;
use clap::{Parser, Subcommand};
use opendr::aci::AciEngine;
use opendr::audit::{AuditConfig, AuditFormat, AuditLevel, AuditLogger};
use opendr::auth_metadata::AuthMetadataRecorder;
use opendr::backend::{DirectoryBackend, DirectoryEntry, MockBackend};
use opendr::backend_lmdb::{AttributeIndexConfig, IndexConfig, IndexType, LmdbBackend};
use opendr::config::ServerConfig;
use opendr::fsm_server;
use opendr::metrics::MetricsCollector;
use opendr::monitoring_runtime::{
    ComponentStatus, MonitoringRuntimeContext, RuntimeHealthRegistry,
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

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Manage LDAP schema files and registry output.
    Schema {
        #[command(subcommand)]
        command: SchemaCommand,
    },
}

#[derive(Debug, Subcommand)]
enum SchemaCommand {
    /// Validate configured or supplied schema files.
    Validate {
        #[arg(long)]
        schema_dir: Option<PathBuf>,
    },
    /// Print the effective schema in RFC subschema attribute format.
    Dump {
        #[arg(long)]
        schema_dir: Option<PathBuf>,
    },
    /// Show one schema element by descriptor or OID.
    Explain {
        name_or_oid: String,
        #[arg(long)]
        schema_dir: Option<PathBuf>,
    },
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

    let security_policy = config.security.effective_policy();
    Ok(Some(Arc::new(server::LegacySecurityConfig {
        audit_logger,
        audit_config: server::LegacyAuditConfig {
            log_authentication: config.audit.log_authentication,
            log_authorization: config.audit.log_authorization,
            log_modifications: config.audit.log_modifications,
            log_connections: config.audit.log_connections,
            log_replication: config.audit.log_replication,
        },
        access_control,
        root_dn: Some(config.canonical_root_dn()?),
        security_policy,
    })))
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let config_path = args.config.to_string_lossy();
    let config = ServerConfig::from_file(&config_path)?;
    let runtime = if config.performance.worker_threads > 0 {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(config.performance.worker_threads)
            .build()?
    } else {
        tokio::runtime::Runtime::new()?
    };
    runtime.block_on(run(args, config))
}

fn init_logging(log_config: &Path) -> Result<(), Box<dyn Error>> {
    if !log_config.is_file() {
        return Err(format!(
            "log config file not found at {}. Pass --log-config with a readable log4rs YAML file, or run opendr-setup to generate one.",
            log_config.display()
        )
        .into());
    }

    log4rs::init_file(log_config, Default::default())
        .map(|_| ())
        .map_err(|err| {
            format!(
                "failed to initialize logging from {}: {}",
                log_config.display(),
                err
            )
            .into()
        })
}

fn run_cli_command(mut config: ServerConfig, command: Command) -> Result<(), Box<dyn Error>> {
    match command {
        Command::Schema { command } => {
            let schema_dir = match &command {
                SchemaCommand::Validate { schema_dir }
                | SchemaCommand::Dump { schema_dir }
                | SchemaCommand::Explain { schema_dir, .. } => schema_dir.clone(),
            };
            if let Some(schema_dir) = schema_dir {
                config.schema.schema_dir = schema_dir;
            }
            config.validate()?;
            let schema = config.load_schema()?;
            config.validate_indexes_against_schema(&schema)?;

            match command {
                SchemaCommand::Validate { .. } => {
                    println!("Schema is valid");
                }
                SchemaCommand::Dump { .. } => {
                    for value in schema.attribute_type_descriptions_unique_sorted() {
                        println!("attributeTypes: {}", value);
                    }
                    for value in schema.object_class_descriptions_unique_sorted() {
                        println!("objectClasses: {}", value);
                    }
                    for value in schema.ldap_syntax_descriptions_unique_sorted() {
                        println!("ldapSyntaxes: {}", value);
                    }
                    for value in schema.matching_rule_descriptions_unique_sorted() {
                        println!("matchingRules: {}", value);
                    }
                    for value in schema.matching_rule_use_descriptions_unique_sorted() {
                        println!("matchingRuleUse: {}", value);
                    }
                    for value in schema.dit_content_rule_descriptions_unique_sorted() {
                        println!("dITContentRules: {}", value);
                    }
                    for value in schema.name_form_descriptions_unique_sorted() {
                        println!("nameForms: {}", value);
                    }
                    for value in schema.dit_structure_rule_descriptions_unique_sorted() {
                        println!("dITStructureRules: {}", value);
                    }
                }
                SchemaCommand::Explain { name_or_oid, .. } => {
                    let Some(description) = schema.explain(&name_or_oid) else {
                        return Err(format!("schema element not found: {}", name_or_oid).into());
                    };
                    println!("{}", description);
                }
            }
        }
    }
    Ok(())
}

async fn run(args: Args, config: ServerConfig) -> Result<(), Box<dyn Error>> {
    init_logging(&args.log_config)?;

    if let Some(command) = args.command {
        return run_cli_command(config, command);
    }

    // Validate configuration
    config.validate()?;
    config.validate_for_shipped_binary()?;
    let root_password = config.resolved_root_password()?;
    let schema = config.load_schema()?;
    config.validate_indexes_against_schema(&schema)?;
    let schema_for_indexes = schema.clone();
    let schema = server::shared_schema(schema);

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
                let mut backend = LmdbBackend::new_with_runtime_and_cache_config_with_schema(
                    &config.backend.data_directory,
                    max_size_mb,
                    replica_id,
                    index_config,
                    config.backend.lmdb_max_readers,
                    config.performance.cache_size,
                    &schema_for_indexes,
                )?;
                backend.set_metrics(monitoring_metrics.clone());

                // Initialize with base structure if needed
                match backend.get_entry(&config.server.base_dn).await {
                    Ok(Some(_)) => {
                        println!("Base DN exists, skipping initialization");
                    }
                    Ok(None) | Err(_) => {
                        println!("Initializing base directory structure...");
                        initialize_lmdb_base_structure(
                            &mut backend,
                            &config,
                            &root_password,
                            &args.config,
                            &schema_for_indexes,
                        )
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
                if !initialize_base_structure_from_config_ldif(
                    &mut backend,
                    &config,
                    &root_password,
                    &args.config,
                    &schema_for_indexes,
                )
                .await?
                {
                    initialize_base_structure(&mut backend, &config, &root_password).await?;
                }

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

    let legacy_security_config = build_legacy_security_config(&config).await?;
    let replication_audit_logger = legacy_security_config
        .as_ref()
        .and_then(|security| security.audit_logger.clone());

    // Wrap backend with replication service if configured
    let replication_service =
        ReplicationService::from_config_with_audit(&config, raw_backend, replication_audit_logger)?;

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
    let auth_metadata_recorder =
        AuthMetadataRecorder::new(backend.clone(), config.to_auth_metadata_config());

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
                console_admin_dn: Some(config.canonical_root_dn()?),
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
    let mut legacy_server_config = server::LegacyServerConfig::from_server_config(&config);
    legacy_server_config.auth_metadata = Some(auth_metadata_recorder.clone());
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
        auth_metadata: Some(auth_metadata_recorder.clone()),
    };
    let ldap_tls_handler = tls_handler.clone();
    let ldap_security = legacy_security_config.clone();
    let ldap_shutdown = shutdown.clone();
    let ldap_schema = schema.clone();
    let ldap_server_task = tokio::spawn(async move {
        let result = match selected_runtime.as_str() {
            "legacy" => {
                server::run_with_metrics_and_config_with_tls_and_security_and_shared_schema(
                    &bind_addr,
                    ldap_backend,
                    ldap_shutdown_rx,
                    ldap_metrics,
                    ldap_runtime_config,
                    ldap_tls_handler,
                    ldap_security,
                    ldap_schema.clone(),
                )
                .await
            }
            "fsm" => {
                fsm_server::run_with_shutdown_and_context(
                    &bind_addr,
                    ldap_backend,
                    ldap_fsm_runtime_config,
                    ldap_fsm_runtime_context,
                    ldap_schema.clone(),
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
                auth_metadata: Some(auth_metadata_recorder.clone()),
            };
            let ldaps_security = legacy_security_config.clone();
            let ldaps_runtime = config.server.runtime.clone();
            let ldaps_shutdown = shutdown.clone();
            let ldaps_schema = schema.clone();
            println!("Starting LDAPS server on {}", ldaps_bind_addr);
            Some(tokio::spawn(async move {
                let result = match ldaps_runtime.as_str() {
                    "legacy" => {
                        server::run_tls_with_metrics_and_config_and_security_and_shared_schema(
                            &ldaps_bind_addr,
                            ldaps_backend,
                            ldaps_shutdown_rx,
                            ldaps_metrics,
                            ldaps_runtime_config,
                            tls_handler,
                            ldaps_security,
                            ldaps_schema.clone(),
                        )
                        .await
                    }
                    "fsm" => {
                        fsm_server::run_tls_with_shutdown_and_context(
                            &ldaps_bind_addr,
                            ldaps_backend,
                            ldaps_fsm_runtime_config,
                            ldaps_fsm_runtime_context,
                            ldaps_schema.clone(),
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

    auth_metadata_recorder.shutdown().await;

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

fn root_common_name(root_dn: &str) -> String {
    opendr::dn::dn_attribute_values(root_dn, Some("cn"))
        .ok()
        .and_then(|values| values.into_iter().next())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "manager".to_string())
}

#[derive(Debug)]
struct InitialLdifEntry {
    dn: String,
    attributes: HashMap<String, Vec<String>>,
    password: Vec<u8>,
}

fn config_directory(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

async fn initialize_base_structure_from_config_ldif(
    backend: &mut dyn DirectoryBackend,
    config: &ServerConfig,
    root_password: &str,
    config_path: &Path,
    schema: &opendr::schema::LdapSchema,
) -> Result<bool, Box<dyn Error>> {
    let config_dir = config_directory(config_path);
    let base_path = config_dir.join("base.ldif");
    let admin_path = config_dir.join("admin.ldif");

    let mut entries = Vec::new();
    if base_path.is_file() {
        entries.extend(read_initial_ldif_entries(
            &base_path,
            config,
            root_password,
            schema,
        )?);
    }
    if admin_path.is_file() {
        entries.extend(read_initial_ldif_entries(
            &admin_path,
            config,
            root_password,
            schema,
        )?);
    }

    if entries.is_empty() {
        return Ok(false);
    }

    for entry in entries {
        backend
            .add_entry(
                DirectoryEntry::new(entry.dn, entry.attributes),
                entry.password,
            )
            .await?;
    }

    ensure_initialized_entry_exists(backend, &config.server.base_dn, "base DN").await?;
    ensure_initialized_entry_exists(backend, &config.canonical_root_dn()?, "root user").await?;
    println!(
        "Base directory structure initialized from {}",
        config_dir.display()
    );
    Ok(true)
}

async fn ensure_initialized_entry_exists(
    backend: &dyn DirectoryBackend,
    dn: &str,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    if backend.get_entry(dn).await?.is_some() {
        return Ok(());
    }

    Err(format!(
        "{} entry {} was not created by initial LDIF import",
        label, dn
    )
    .into())
}

fn read_initial_ldif_entries(
    path: &Path,
    config: &ServerConfig,
    root_password: &str,
    schema: &opendr::schema::LdapSchema,
) -> Result<Vec<InitialLdifEntry>, Box<dyn Error>> {
    let contents = std::fs::read_to_string(path)?;
    parse_initial_ldif_entries(&contents, path, config, root_password, schema)
}

fn parse_initial_ldif_entries(
    contents: &str,
    source: &Path,
    config: &ServerConfig,
    root_password: &str,
    schema: &opendr::schema::LdapSchema,
) -> Result<Vec<InitialLdifEntry>, Box<dyn Error>> {
    let root_dn = config.canonical_root_dn()?;
    let lines = unfold_initial_ldif_lines(contents, source)?;
    let mut entries = Vec::new();
    let mut current = Vec::new();

    for (line_no, line) in lines {
        if line.trim().is_empty() {
            if !current.is_empty() {
                entries.push(parse_initial_ldif_entry(
                    &current,
                    source,
                    config,
                    &root_dn,
                    root_password,
                    schema,
                )?);
                current.clear();
            }
            continue;
        }
        current.push((line_no, line));
    }

    if !current.is_empty() {
        entries.push(parse_initial_ldif_entry(
            &current,
            source,
            config,
            &root_dn,
            root_password,
            schema,
        )?);
    }

    Ok(entries)
}

fn unfold_initial_ldif_lines(
    contents: &str,
    source: &Path,
) -> Result<Vec<(usize, String)>, Box<dyn Error>> {
    let mut lines: Vec<(usize, String)> = Vec::new();
    for (index, raw_line) in contents.lines().enumerate() {
        let line_no = index + 1;
        if let Some(continuation) = raw_line.strip_prefix(' ') {
            let Some((_, previous)) = lines.last_mut() else {
                return Err(format!(
                    "{}:{}: LDIF continuation line has no preceding line",
                    source.display(),
                    line_no
                )
                .into());
            };
            previous.push_str(continuation);
        } else {
            lines.push((line_no, raw_line.to_string()));
        }
    }
    Ok(lines)
}

fn parse_initial_ldif_entry(
    lines: &[(usize, String)],
    source: &Path,
    config: &ServerConfig,
    root_dn: &str,
    root_password: &str,
    schema: &opendr::schema::LdapSchema,
) -> Result<InitialLdifEntry, Box<dyn Error>> {
    let mut dn = None;
    let mut attributes: HashMap<String, Vec<String>> = HashMap::new();

    for (line_no, line) in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let (name, value) = parse_initial_ldif_attr_value(line, source, *line_no)?;
        if name.eq_ignore_ascii_case("dn") {
            dn = Some(value);
            continue;
        }

        let key = name.to_ascii_lowercase();
        if opendr::backend::OperationalAttributes::is_operational(&key) {
            return Err(format!(
                "{}:{}: operational attribute {} is server-managed",
                source.display(),
                line_no,
                name
            )
            .into());
        }
        attributes.entry(key).or_default().push(value);
    }

    let raw_dn = dn.ok_or_else(|| format!("{}: LDIF entry is missing dn", source.display()))?;
    let canonical_root = config.canonical_root_dn()?;
    let dn = if raw_dn.eq_ignore_ascii_case(&config.server.root_user_dn)
        || raw_dn.eq_ignore_ascii_case(root_dn)
    {
        canonical_root
    } else {
        raw_dn
    };

    let is_root_entry = dn.eq_ignore_ascii_case(root_dn);
    if is_root_entry && !root_password.is_empty() {
        attributes.insert("userpassword".to_string(), vec![root_password.to_string()]);
    }

    schema.validate_entry(&attributes).map_err(|err| {
        format!(
            "{}: schema validation failed for initial entry {}: {}",
            source.display(),
            dn,
            err
        )
    })?;

    let password = attributes
        .get("userpassword")
        .and_then(|values| values.first())
        .map(|value| value.as_bytes().to_vec())
        .unwrap_or_default();

    Ok(InitialLdifEntry {
        dn,
        attributes,
        password,
    })
}

fn parse_initial_ldif_attr_value(
    line: &str,
    source: &Path,
    line_no: usize,
) -> Result<(String, String), Box<dyn Error>> {
    let Some((name, rest)) = line.split_once(':') else {
        return Err(format!(
            "{}:{}: invalid LDIF attribute line: {}",
            source.display(),
            line_no,
            line
        )
        .into());
    };

    let name = name.trim();
    if name.is_empty() {
        return Err(format!(
            "{}:{}: empty LDIF attribute name",
            source.display(),
            line_no
        )
        .into());
    }

    if let Some(encoded) = rest.strip_prefix(':') {
        let decoded = base64::engine::general_purpose::STANDARD.decode(encoded.trim_start())?;
        let value = String::from_utf8(decoded).map_err(|err| {
            format!(
                "{}:{}: base64 LDIF value for {} is not valid UTF-8: {}",
                source.display(),
                line_no,
                name,
                err
            )
        })?;
        return Ok((name.to_string(), value));
    }

    if rest.trim_start().starts_with('<') {
        return Err(format!(
            "{}:{}: LDIF URL values are not supported during startup import",
            source.display(),
            line_no
        )
        .into());
    }

    Ok((name.to_string(), rest.trim_start().to_string()))
}

/// Initialize base directory structure
async fn initialize_base_structure(
    backend: &mut dyn DirectoryBackend,
    config: &ServerConfig,
    root_password: &str,
) -> Result<(), Box<dyn Error>> {
    let root_dn = config.canonical_root_dn()?;
    let root_cn = root_common_name(&root_dn);

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
        root_dn,
        HashMap::from([
            (
                "objectClass".to_string(),
                vec!["top".to_string(), "person".to_string()],
            ),
            ("cn".to_string(), vec![root_cn]),
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
    config_path: &Path,
    schema: &opendr::schema::LdapSchema,
) -> Result<(), Box<dyn Error>> {
    if initialize_base_structure_from_config_ldif(
        backend,
        config,
        root_password,
        config_path,
        schema,
    )
    .await?
    {
        return Ok(());
    }

    let root_dn = config.canonical_root_dn()?;
    let root_cn = root_common_name(&root_dn);

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
    let root_user_entry = DirectoryEntry::new(
        &root_dn,
        HashMap::from([
            (
                "objectClass".to_string(),
                vec!["top".to_string(), "person".to_string()],
            ),
            ("cn".to_string(), vec![root_cn]),
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

    #[test]
    fn test_init_logging_reports_missing_config() {
        let temp_dir = TempDir::new().unwrap();
        let missing_config = temp_dir.path().join("missing-log4rs.yml");

        let err = init_logging(&missing_config).unwrap_err().to_string();

        assert!(err.contains("log config file not found"));
        assert!(err.contains("missing-log4rs.yml"));
    }

    #[tokio::test]
    async fn test_initialize_base_structure_imports_config_ldif_files() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("server.toml");
        std::fs::write(&config_path, "").unwrap();
        std::fs::write(
            temp_dir.path().join("base.ldif"),
            r#"dn: dc=example,dc=org
objectClass: top
objectClass: organization
o: Example Org
description: Example Org

dn: ou=People,dc=example,dc=org
objectClass: top
objectClass: organizationalUnit
objectClass: opendrPeopleProfile
ou: People
description: People container
department: People
employeeType: DirectoryContainer
mobile: +94 77 123 4567
age: 1
"#,
        )
        .unwrap();
        std::fs::write(
            temp_dir.path().join("admin.ldif"),
            r#"dn: cn=manager
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: manager
sn: Administrator
userPassword: stale
description: Root Administrator Account
"#,
        )
        .unwrap();

        let mut config = ServerConfig::default();
        config.server.base_dn = "dc=example,dc=org".to_string();
        config.server.root_user_dn = "cn=manager".to_string();
        config.server.organization_name = "Example Org".to_string();

        let mut schema = opendr::schema::LdapSchema::with_core_schema();
        schema
            .load_ldif_str(
                r#"dn: cn=schema
attributeTypes: ( 1.3.6.1.4.1.55555.40.1 NAME 'department' DESC 'Department name for people entries' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.55555.40.2 NAME 'age' DESC 'Age for people entries' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
objectClasses: ( 1.3.6.1.4.1.55555.40.100 NAME 'opendrPeopleProfile' DESC 'Custom profile attributes for entries under ou=People' SUP top AUXILIARY MAY ( department $ employeeType $ mobile $ age ) )
"#,
            )
            .unwrap();

        let mut backend = MockBackend::new();
        let imported = initialize_base_structure_from_config_ldif(
            &mut backend,
            &config,
            "secret",
            &config_path,
            &schema,
        )
        .await
        .unwrap();

        assert!(imported);
        let people = backend
            .get_entry("ou=People,dc=example,dc=org")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            people.attributes["objectclass"],
            vec![
                "top".to_string(),
                "organizationalUnit".to_string(),
                "opendrPeopleProfile".to_string()
            ]
        );
        assert_eq!(people.attributes["department"], vec!["People".to_string()]);
        assert_eq!(
            people.attributes["employeetype"],
            vec!["DirectoryContainer".to_string()]
        );
        assert_eq!(
            people.attributes["mobile"],
            vec!["+94 77 123 4567".to_string()]
        );
        assert_eq!(people.attributes["age"], vec!["1".to_string()]);

        assert!(
            backend
                .get_entry("cn=manager,dc=example,dc=org")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            backend
                .authenticate("cn=manager,dc=example,dc=org", b"secret")
                .await
                .unwrap()
        );
        assert!(
            !backend
                .authenticate("cn=manager,dc=example,dc=org", b"stale")
                .await
                .unwrap()
        );
    }

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
    async fn test_initialize_base_structure_inmemory_full_root_dn() {
        let mut config = ServerConfig::default();
        config.server.base_dn = "dc=example,dc=org".to_string();
        config.server.root_user_dn = "cn=manager,dc=example,dc=org".to_string();
        config.server.root_password = "secret".to_string();
        config.server.organization_name = "Example Org".to_string();
        config.backend.backend_type = "memory".to_string();

        let mut backend = MockBackend::new();
        initialize_base_structure(&mut backend, &config, "secret")
            .await
            .unwrap();

        assert!(
            backend
                .get_entry("cn=manager,dc=example,dc=org")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            backend
                .get_entry("cn=manager,dc=example,dc=org,dc=example,dc=org")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            backend
                .authenticate("cn=manager,dc=example,dc=org", b"secret")
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
    async fn test_initialize_base_structure_lmdb_full_root_dn() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = ServerConfig::default();
        config.server.base_dn = "dc=test,dc=local".to_string();
        config.server.root_user_dn = "cn=admin,dc=test,dc=local".to_string();
        config.server.root_password = "AdminPass123".to_string();
        config.server.organization_name = "Test Org".to_string();
        config.backend.backend_type = "lmdb".to_string();
        config.backend.data_directory = temp_dir.path().to_path_buf();

        let mut backend = LmdbBackend::new(temp_dir.path(), 100, 1).unwrap();
        initialize_base_structure(&mut backend, &config, "AdminPass123")
            .await
            .unwrap();

        assert!(
            backend
                .get_entry("cn=admin,dc=test,dc=local")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            backend
                .get_entry("cn=admin,dc=test,dc=local,dc=test,dc=local")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            backend
                .authenticate("cn=admin,dc=test,dc=local", b"AdminPass123")
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

    #[tokio::test]
    async fn build_legacy_security_config_uses_canonical_root_dn() {
        let mut config = ServerConfig::default();
        config.server.base_dn = "dc=example,dc=com".to_string();
        config.server.root_user_dn = "cn=admin".to_string();

        let security = build_legacy_security_config(&config)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            security.root_dn.as_deref(),
            Some("cn=admin,dc=example,dc=com")
        );

        config.server.root_user_dn = "CN=Admin,DC=Example,DC=COM".to_string();
        let security = build_legacy_security_config(&config)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            security.root_dn.as_deref(),
            Some("cn=admin,dc=example,dc=com")
        );
    }
}

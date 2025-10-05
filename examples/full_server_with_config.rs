//! Complete Server Example with ServerConfig Integration
//!
//! This example shows the complete flow of using ServerConfig to configure
//! and run a production-ready OpenDR LDAP server.
//!
//! Flow:
//! 1. Load ServerConfig from TOML file
//! 2. Validate configuration
//! 3. Convert to FsmServerConfig using to_fsm_server_config()
//! 4. Create backend based on config
//! 5. Run server with all features enabled
//!
//! Run with:
//! ```bash
//! cargo run --example full_server_with_config
//! ```

use opendr::config::ServerConfig;
use opendr::backend::{DirectoryBackend, DirectoryEntry, MockBackend};
use opendr::backend_lmdb::LmdbBackend;
use opendr::fsm_server;
use opendr::shutdown::{ShutdownCoordinator, ShutdownConfig};
use std::sync::Arc;
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== OpenDR LDAP Server with ServerConfig ===\n");

    // Step 1: Load Configuration
    println!("Step 1: Loading configuration...");
    let config = load_configuration()?;
    println!("✓ Configuration loaded from TOML\n");

    // Step 2: Validate Configuration
    println!("Step 2: Validating configuration...");
    config.validate()?;
    println!("✓ Configuration validated successfully\n");

    // Step 3: Display Configuration Summary
    display_config_summary(&config);

    // Step 4: Convert to FSM Server Config
    println!("\nStep 4: Converting to FSM server configuration...");
    let fsm_config = config.to_fsm_server_config();
    println!("✓ Converted ServerConfig → FsmServerConfig");
    display_fsm_config(&fsm_config);

    // Step 5: Create Backend
    println!("\nStep 5: Creating backend...");
    let backend = create_backend(&config).await?;
    println!("✓ Backend created: {}\n", config.backend.backend_type);

    // Step 6: Setup Shutdown Handling
    println!("Step 6: Setting up graceful shutdown...");
    let shutdown = setup_shutdown_handling();
    println!("✓ Shutdown coordinator ready\n");

    // Step 7: Run Server
    println!("Step 7: Starting LDAP server...");
    let bind_address = config.ldap_bind_address();
    println!("Server listening on: {}", bind_address);
    println!("Press Ctrl+C to stop\n");
    println!("----------------------------------------");

    // This would run the actual server - commented out for demo
    // fsm_server::run_with_shutdown(&bind_address, backend, fsm_config, Some(shutdown)).await?;

    println!("\nServer would be running here...");
    println!("(Actual server startup commented out for demo)");
    println!("\n=== Demo Complete ===");

    Ok(())
}

/// Load configuration with fallback logic
fn load_configuration() -> Result<ServerConfig, Box<dyn std::error::Error>> {
    // Try to load from file, fall back to defaults
    let config_path = "config/server.development.toml";

    let config = if std::path::Path::new(config_path).exists() {
        println!("  Loading from: {}", config_path);
        ServerConfig::from_file(config_path)?
    } else {
        println!("  Config file not found, using defaults");
        ServerConfig::default()
    };

    Ok(config)
}

/// Display configuration summary
fn display_config_summary(config: &ServerConfig) {
    println!("\nStep 3: Configuration Summary");
    println!("========================================");

    println!("\n[Server Settings]");
    println!("  Bind Address:    {}", config.ldap_bind_address());
    println!("  LDAPS Address:   {}", config.ldaps_bind_address());
    println!("  Base DN:         {}", config.server.base_dn);
    println!("  Root User:       {}", config.server.root_user_dn);
    println!("  Organization:    {}", config.server.organization_name);
    println!("  Buffer Size:     {} bytes", config.server.read_buffer_size);
    println!("  Op Timeout:      {:?}", config.operation_timeout());
    println!("  Cleanup:         {:?}", config.cleanup_interval());

    println!("\n[Backend Settings]");
    println!("  Type:            {}", config.backend.backend_type);
    println!("  Data Directory:  {:?}", config.backend.data_directory);
    if config.backend.backend_type == "lmdb" {
        println!("  Max Size:        {} MB", config.backend.lmdb_max_size / (1024 * 1024));
        println!("  Max Readers:     {}", config.backend.lmdb_max_readers);
    }
    println!("  Indexed Attrs:   {:?}", config.backend.indexed_attributes);

    println!("\n[Resource Management]");
    println!("  Max Connections:     {}", config.resources.max_connections);
    println!("  Per-IP Limit:        {}", config.resources.max_connections_per_ip);
    println!("  Ops/Connection:      {}", config.resources.max_operations_per_connection);
    println!("  Memory/Connection:   {} MB", config.resources.max_memory_per_connection / (1024 * 1024));
    println!("  Total Memory:        {} MB", config.resources.max_total_memory / (1024 * 1024));
    println!("  Idle Timeout:        {:?}", config.connection_idle_timeout());

    println!("\n[Rate Limiting]");
    println!("  Enabled:         {}", config.rate_limit.enabled);
    if config.rate_limit.enabled {
        println!("  Global Limit:    {} req/sec", config.rate_limit.global_requests_per_second);
        println!("  Per-Client:      {} req/sec", config.rate_limit.per_client_requests_per_second);
        println!("  Burst Size:      {}", config.rate_limit.burst_size);
        println!("  Adaptive:        {}", config.rate_limit.adaptive_enabled);
        println!("  Auto-Ban:        {} violations → {:?}",
                 config.rate_limit.auto_ban_threshold,
                 config.auto_ban_duration());
    }

    println!("\n[Monitoring]");
    println!("  Enabled:         {}", config.monitoring.enabled);
    if config.monitoring.enabled {
        println!("  Metrics:         {}:{}{}",
                 config.monitoring.metrics_address,
                 config.monitoring.metrics_port,
                 config.monitoring.metrics_path);
        println!("  Health Check:    {}:{}{}",
                 config.monitoring.metrics_address,
                 config.monitoring.metrics_port,
                 config.monitoring.health_path);
    }

    println!("\n[Audit Logging]");
    println!("  Enabled:         {}", config.audit.enabled);
    if config.audit.enabled {
        println!("  Log File:        {:?}", config.audit.log_file);
        println!("  Format:          {}", config.audit.format);
        println!("  Level:           {}", config.audit.level);
    }

    println!("========================================");
}

/// Display FSM configuration details
fn display_fsm_config(fsm_config: &opendr::fsm_server::FsmServerConfig) {
    println!("\n[FSM Server Configuration]");
    println!("  Operation Timeout:    {:?}", fsm_config.operation_timeout);
    println!("  Cleanup Interval:     {:?}", fsm_config.cleanup_interval);
    println!("  Read Buffer Size:     {} bytes", fsm_config.read_buffer_size);
    println!("  Max Concurrent Ops:   {}", fsm_config.max_concurrent_operations);
    println!("  Rate Limiting:        {}", fsm_config.rate_limiting_enabled);

    println!("\n  Resource Limits:");
    println!("    Max Connections:        {}", fsm_config.resource_limits.max_connections);
    println!("    Max Per-IP:             {}", fsm_config.resource_limits.max_connections_per_ip);
    println!("    Max Ops/Connection:     {}", fsm_config.resource_limits.max_operations_per_connection);
    println!("    Max Memory/Connection:  {} MB",
             fsm_config.resource_limits.max_memory_per_connection / (1024 * 1024));
    println!("    Max Total Memory:       {} MB",
             fsm_config.resource_limits.max_total_memory / (1024 * 1024));
    println!("    Idle Timeout:           {:?}", fsm_config.resource_limits.connection_idle_timeout);

    if fsm_config.rate_limiting_enabled {
        println!("\n  Rate Limit Config:");
        println!("    Global Limit:           {} req/sec", fsm_config.rate_limit_config.global_requests_per_second);
        println!("    Per-Client Limit:       {} req/sec", fsm_config.rate_limit_config.per_client_requests_per_second);
        println!("    Adaptive Enabled:       {}", fsm_config.rate_limit_config.adaptive_enabled);
        println!("    Window Duration:        {:?}", fsm_config.rate_limit_config.window_duration);
    }
}

/// Create backend based on configuration
async fn create_backend(config: &ServerConfig) -> Result<Arc<dyn DirectoryBackend>, Box<dyn std::error::Error>> {
    match config.backend.backend_type.as_str() {
        "lmdb" => {
            println!("  Initializing LMDB backend...");
            let max_size_mb = (config.backend.lmdb_max_size / (1024 * 1024)) as usize;

            let mut backend = LmdbBackend::new(
                &config.backend.data_directory,
                max_size_mb
            )?;

            // Initialize directory structure if needed
            if backend.get_entry(&config.server.base_dn).await?.is_none() {
                println!("  Creating base directory structure...");
                initialize_directory(&mut backend, config).await?;
            } else {
                println!("  Base directory already exists");
            }

            Ok(Arc::new(backend))
        }
        "memory" | _ => {
            println!("  Initializing in-memory backend...");
            let mut backend = MockBackend::default();
            initialize_directory(&mut backend, config).await?;
            Ok(Arc::new(backend))
        }
    }
}

/// Initialize base directory structure
async fn initialize_directory(
    backend: &mut dyn DirectoryBackend,
    config: &ServerConfig
) -> Result<(), Box<dyn std::error::Error>> {
    // Create base DN entry
    let base_entry = DirectoryEntry::new(
        &config.server.base_dn,
        HashMap::from([
            ("objectClass".to_string(), vec!["top".to_string(), "organization".to_string()]),
            ("o".to_string(), vec![config.server.organization_name.clone()]),
            ("description".to_string(), vec![format!("{} LDAP Directory", config.server.organization_name)]),
        ])
    );
    backend.add_entry(base_entry, vec![]).await?;

    // Create admin user
    let admin_dn = format!("{},{}", config.server.root_user_dn, config.server.base_dn);
    let admin_cn = config.server.root_user_dn
        .split('=')
        .nth(1)
        .unwrap_or("admin")
        .to_string();

    let admin_entry = DirectoryEntry::new(
        &admin_dn,
        HashMap::from([
            ("objectClass".to_string(), vec!["top".to_string(), "person".to_string()]),
            ("cn".to_string(), vec![admin_cn]),
            ("sn".to_string(), vec!["Administrator".to_string()]),
            ("description".to_string(), vec!["Directory Administrator".to_string()]),
        ])
    );
    backend.add_entry(admin_entry, config.server.root_password.as_bytes().to_vec()).await?;

    // Create organizational units
    let people_ou = DirectoryEntry::new(
        &format!("ou=People,{}", config.server.base_dn),
        HashMap::from([
            ("objectClass".to_string(), vec!["top".to_string(), "organizationalUnit".to_string()]),
            ("ou".to_string(), vec!["People".to_string()]),
            ("description".to_string(), vec!["User Accounts".to_string()]),
        ])
    );
    backend.add_entry(people_ou, vec![]).await?;

    let groups_ou = DirectoryEntry::new(
        &format!("ou=Groups,{}", config.server.base_dn),
        HashMap::from([
            ("objectClass".to_string(), vec!["top".to_string(), "organizationalUnit".to_string()]),
            ("ou".to_string(), vec!["Groups".to_string()]),
            ("description".to_string(), vec!["Group Definitions".to_string()]),
        ])
    );
    backend.add_entry(groups_ou, vec![]).await?;

    println!("    ✓ Base DN created");
    println!("    ✓ Admin user created");
    println!("    ✓ Organizational units created");

    Ok(())
}

/// Setup shutdown handling
fn setup_shutdown_handling() -> Arc<ShutdownCoordinator> {
    let shutdown_config = ShutdownConfig::default();
    let shutdown = Arc::new(ShutdownCoordinator::new(shutdown_config));

    // Install signal handlers
    let shutdown_signal = shutdown.install_signal_handlers();
    let shutdown_clone = shutdown.clone();

    tokio::spawn(async move {
        shutdown_signal.wait().await;
        println!("\n🛑 Shutdown signal received!");
        println!("Initiating graceful shutdown...");
    });

    shutdown
}

/// Example: How the conversion works internally
#[allow(dead_code)]
fn demonstrate_conversion_internals() {
    println!("\n=== Understanding to_fsm_server_config() ===\n");

    let server_config = ServerConfig::default();

    println!("BEFORE CONVERSION (ServerConfig):");
    println!("  server.operation_timeout_secs = {}", server_config.server.operation_timeout_secs);
    println!("  server.cleanup_interval_secs = {}", server_config.server.cleanup_interval_secs);
    println!("  server.read_buffer_size = {}", server_config.server.read_buffer_size);
    println!("  resources.max_connections = {}", server_config.resources.max_connections);
    println!("  rate_limit.enabled = {}", server_config.rate_limit.enabled);

    // This is what happens inside to_fsm_server_config():
    let fsm_config = server_config.to_fsm_server_config();

    println!("\nAFTER CONVERSION (FsmServerConfig):");
    println!("  operation_timeout = {:?}", fsm_config.operation_timeout);
    println!("  cleanup_interval = {:?}", fsm_config.cleanup_interval);
    println!("  read_buffer_size = {}", fsm_config.read_buffer_size);
    println!("  resource_limits.max_connections = {}", fsm_config.resource_limits.max_connections);
    println!("  rate_limiting_enabled = {}", fsm_config.rate_limiting_enabled);

    println!("\nCONVERSIONS PERFORMED:");
    println!("  ✓ u64 seconds → Duration (operation_timeout, cleanup_interval)");
    println!("  ✓ ServerConfig.server → FsmServerConfig fields");
    println!("  ✓ ServerConfig.resources → ResourceLimits");
    println!("  ✓ ServerConfig.rate_limit → RateLimitConfig (via to_rate_limit_config())");
    println!("  ✓ IP strings → IpAddr (for blacklist/whitelist)");
    println!("  ✓ Operation limit map → HashMap<OperationType, u32>");
}

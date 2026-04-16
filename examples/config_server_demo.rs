//! Configuration Integration Demo
//!
//! This example demonstrates how to use the ServerConfig to configure
//! and run an OpenDR LDAP server with all features.
//!
//! Run with:
//! ```bash
//! cargo run --example config_server_demo
//! ```

use opendr::backend::{DirectoryBackend, DirectoryEntry, MockBackend};
use opendr::config::ServerConfig;
use opendr::fsm_server;
use std::collections::HashMap;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== OpenDR Configuration Integration Demo ===\n");

    // Demo 1: Load configuration from TOML string
    demo_load_from_toml().await?;

    // Demo 2: Use default configuration
    demo_default_config().await?;

    // Demo 3: Configuration conversion
    demo_config_conversion().await?;

    // Demo 4: Configuration validation
    demo_config_validation().await?;

    println!("\n=== Demo Complete ===");
    Ok(())
}

async fn demo_load_from_toml() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- Demo 1: Load Configuration from TOML ---");

    let toml = r#"
[server]
bind_address = "127.0.0.1"
ldap_port = 1389
base_dn = "dc=example,dc=com"
root_user_dn = "cn=admin"
# Demo-only inline credential; production profile rejects inline root_password.
root_password = "secret"

[backend]
backend_type = "memory"

[rate_limit]
enabled = true
global_requests_per_second = 500
    "#;

    let config = ServerConfig::from_toml_str(toml)?;

    println!("Configuration loaded successfully:");
    println!("  LDAP Address: {}", config.ldap_bind_address());
    println!("  Base DN: {}", config.server.base_dn);
    println!("  Backend: {}", config.backend.backend_type);
    println!("  Rate Limiting: {}", config.rate_limit.enabled);
    println!(
        "  Global Rate Limit: {} req/sec",
        config.rate_limit.global_requests_per_second
    );

    // Validate configuration
    config.validate()?;
    println!("  ✓ Configuration validated successfully");

    println!("---------------------------------------\n");
    Ok(())
}

async fn demo_default_config() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- Demo 2: Use Default Configuration ---");

    let config = ServerConfig::default();

    println!("Default configuration:");
    println!("  LDAP Address: {}", config.ldap_bind_address());
    println!("  LDAPS Address: {}", config.ldaps_bind_address());
    println!("  Base DN: {}", config.server.base_dn);
    println!("  Max Connections: {}", config.resources.max_connections);
    println!(
        "  Per-IP Limit: {}",
        config.resources.max_connections_per_ip
    );
    println!("  Operation Timeout: {:?}", config.operation_timeout());
    println!("  Cleanup Interval: {:?}", config.cleanup_interval());

    println!("\nRate Limiting:");
    println!("  Enabled: {}", config.rate_limit.enabled);
    println!(
        "  Global Limit: {} req/sec",
        config.rate_limit.global_requests_per_second
    );
    println!(
        "  Per-Client: {} req/sec",
        config.rate_limit.per_client_requests_per_second
    );
    println!("  Adaptive: {}", config.rate_limit.adaptive_enabled);

    println!("\nMonitoring:");
    println!("  Enabled: {}", config.monitoring.enabled);
    println!("  Metrics Port: {}", config.monitoring.metrics_port);
    println!("  Metrics Path: {}", config.monitoring.metrics_path);

    println!("---------------------------------------\n");
    Ok(())
}

async fn demo_config_conversion() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- Demo 3: Configuration Conversion ---");

    let server_config = ServerConfig::default();

    // Convert to FSM server config
    let fsm_config = server_config.to_fsm_server_config();

    println!("Converted to FsmServerConfig:");
    println!("  Operation Timeout: {:?}", fsm_config.operation_timeout);
    println!("  Cleanup Interval: {:?}", fsm_config.cleanup_interval);
    println!("  Read Buffer: {} bytes", fsm_config.read_buffer_size);
    println!("  Max Operations: {}", fsm_config.max_concurrent_operations);
    println!("  Rate Limiting: {}", fsm_config.rate_limiting_enabled);

    println!("\nResource Limits:");
    println!(
        "  Max Connections: {}",
        fsm_config.resource_limits.max_connections
    );
    println!(
        "  Per-IP Limit: {}",
        fsm_config.resource_limits.max_connections_per_ip
    );
    println!(
        "  Memory Per Connection: {} bytes",
        fsm_config.resource_limits.max_memory_per_connection
    );

    // Convert to rate limit config
    let rate_config = server_config.to_rate_limit_config();

    println!("\nRate Limit Config:");
    println!(
        "  Global: {} req/sec",
        rate_config.global_requests_per_second
    );
    println!(
        "  Per-Client: {} req/sec",
        rate_config.per_client_requests_per_second
    );
    println!("  Window: {:?}", rate_config.window_duration);
    println!("  Adaptive: {}", rate_config.adaptive_enabled);

    println!("---------------------------------------\n");
    Ok(())
}

async fn demo_config_validation() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- Demo 4: Configuration Validation ---");

    // Valid configuration
    let valid_config = ServerConfig::default();
    match valid_config.validate() {
        Ok(()) => println!("✓ Default configuration is valid"),
        Err(e) => println!("✗ Validation error: {}", e),
    }

    // Invalid configuration - same ports
    let invalid_toml = r#"
[server]
ldap_port = 1389
ldaps_port = 1389
    "#;

    let invalid_config = ServerConfig::from_toml_str(invalid_toml)?;
    match invalid_config.validate() {
        Ok(()) => println!("✗ Should have failed validation"),
        Err(e) => println!("✓ Caught validation error: {}", e),
    }

    // Invalid configuration - empty base DN
    let invalid_toml2 = r#"
[server]
base_dn = ""
    "#;

    let invalid_config2 = ServerConfig::from_toml_str(invalid_toml2)?;
    match invalid_config2.validate() {
        Ok(()) => println!("✗ Should have failed validation"),
        Err(e) => println!("✓ Caught validation error: {}", e),
    }

    // Invalid configuration - bad IP
    let invalid_toml3 = r#"
[rate_limit]
blacklist = ["not-an-ip"]
    "#;

    let invalid_config3 = ServerConfig::from_toml_str(invalid_toml3)?;
    match invalid_config3.validate() {
        Ok(()) => println!("✗ Should have failed validation"),
        Err(e) => println!("✓ Caught validation error: {}", e),
    }

    println!("---------------------------------------\n");
    Ok(())
}

// Example of how to use ServerConfig with FSM server
#[allow(dead_code)]
async fn example_run_server_with_config() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration
    let config = ServerConfig::from_file("config/server.toml")?;

    // Validate
    config.validate()?;

    // Create backend (simplified example)
    let backend: Arc<dyn DirectoryBackend> = {
        let mock = MockBackend::default();

        // Initialize base structure
        let base_entry = DirectoryEntry::new(
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
            ]),
        );
        mock.add_entry(base_entry, vec![]).await?;

        Arc::new(mock)
    };

    // Convert to FSM server config
    let fsm_config = config.to_fsm_server_config();

    // Run server
    let bind_address = config.ldap_bind_address();
    println!("Starting LDAP server on {}", bind_address);

    fsm_server::run(&bind_address, backend, fsm_config).await?;

    Ok(())
}

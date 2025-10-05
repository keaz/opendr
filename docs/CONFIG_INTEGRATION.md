# ServerConfig Integration Guide

This guide shows how to integrate the `ServerConfig` into your OpenDR LDAP server application.

## Quick Start

### 1. Basic Usage

```rust
use opendr::config::ServerConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration from file
    let config = ServerConfig::from_file("config/server.toml")?;

    // Validate configuration
    config.validate()?;

    // Use configuration values
    println!("Server will bind to: {}", config.ldap_bind_address());

    Ok(())
}
```

### 2. Using with FSM Server

```rust
use opendr::config::ServerConfig;
use opendr::fsm_server;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load and validate configuration
    let config = ServerConfig::from_file("config/server.toml")?;
    config.validate()?;

    // Create backend (example with mock backend)
    let backend = Arc::new(create_backend(&config).await?);

    // Convert to FSM server configuration
    let fsm_config = config.to_fsm_server_config();

    // Run server
    let bind_address = config.ldap_bind_address();
    fsm_server::run(&bind_address, backend, fsm_config).await?;

    Ok(())
}
```

### 3. Environment Variable Overrides

```bash
# Override server settings
export OPENDR_SERVER__LDAP_PORT=389
export OPENDR_SERVER__BASE_DN="dc=myorg,dc=com"

# Override backend settings
export OPENDR_BACKEND__DATA_DIRECTORY="/var/lib/opendr"

# Override rate limits
export OPENDR_RATE_LIMIT__GLOBAL_REQUESTS_PER_SECOND=5000

# Run server (environment variables take precedence)
cargo run
```

## Integration with Main Server

Here's a complete example of integrating ServerConfig with the main server:

```rust
use opendr::config::ServerConfig;
use opendr::backend::{DirectoryBackend, DirectoryEntry};
use opendr::backend_lmdb::LmdbBackend;
use opendr::fsm_server;
use opendr::shutdown::{ShutdownCoordinator, ShutdownConfig};
use std::sync::Arc;
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    log4rs::init_file("config/log4rs.yml", Default::default())?;

    // Load configuration
    let config = ServerConfig::from_file("config/server.toml")?;

    // Validate configuration
    config.validate()?;

    // Create shutdown coordinator
    let shutdown_config = ShutdownConfig::default();
    let shutdown = Arc::new(ShutdownCoordinator::new(shutdown_config));

    // Install signal handlers
    let shutdown_signal = shutdown.install_signal_handlers();
    let shutdown_clone = shutdown.clone();

    tokio::spawn(async move {
        shutdown_signal.wait().await;
        println!("\nShutdown signal received");
    });

    // Create backend based on configuration
    let backend = create_backend_from_config(&config).await?;

    // Convert to FSM server config
    let fsm_config = config.to_fsm_server_config();

    // Run server with shutdown support
    let bind_address = config.ldap_bind_address();
    println!("Starting LDAP server on {}", bind_address);

    fsm_server::run_with_shutdown(
        &bind_address,
        backend,
        fsm_config,
        Some(shutdown_clone.clone())
    ).await?;

    Ok(())
}

async fn create_backend_from_config(
    config: &ServerConfig
) -> Result<Arc<dyn DirectoryBackend>, Box<dyn std::error::Error>> {
    match config.backend.backend_type.as_str() {
        "lmdb" => {
            // Create LMDB backend
            let max_size_mb = config.backend.lmdb_max_size / (1024 * 1024);
            let mut backend = LmdbBackend::new(
                &config.backend.data_directory,
                max_size_mb as usize
            )?;

            // Initialize base structure if needed
            if backend.get_entry(&config.server.base_dn).await?.is_none() {
                initialize_directory(&mut backend, config).await?;
            }

            Ok(Arc::new(backend))
        }
        "memory" => {
            // Create in-memory backend
            use opendr::backend::MockBackend;

            let mut backend = MockBackend::default();
            initialize_directory(&mut backend, config).await?;

            Ok(Arc::new(backend))
        }
        _ => Err(format!("Unsupported backend: {}", config.backend.backend_type).into())
    }
}

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
        ])
    );
    backend.add_entry(base_entry, vec![]).await?;

    // Create admin user
    let admin_dn = format!("{},{}", config.server.root_user_dn, config.server.base_dn);
    let admin_entry = DirectoryEntry::new(
        &admin_dn,
        HashMap::from([
            ("objectClass".to_string(), vec!["top".to_string(), "person".to_string()]),
            ("cn".to_string(), vec!["admin".to_string()]),
            ("sn".to_string(), vec!["Administrator".to_string()]),
        ])
    );
    backend.add_entry(admin_entry, config.server.root_password.as_bytes().to_vec()).await?;

    Ok(())
}
```

## Configuration Helpers

### Duration Conversions

```rust
let config = ServerConfig::default();

// Get durations directly
let op_timeout = config.operation_timeout();           // Duration
let cleanup = config.cleanup_interval();               // Duration
let idle_timeout = config.connection_idle_timeout();   // Duration
let rate_window = config.rate_limit_window_duration(); // Duration
let ban_duration = config.auto_ban_duration();         // Duration

// Use in server configuration
fsm_config.operation_timeout = op_timeout;
fsm_config.cleanup_interval = cleanup;
```

### Bind Addresses

```rust
let config = ServerConfig::default();

// Get formatted bind addresses
let ldap_addr = config.ldap_bind_address();   // "127.0.0.1:1389"
let ldaps_addr = config.ldaps_bind_address(); // "127.0.0.1:1636"

// Use for server binding
let listener = TcpListener::bind(&ldap_addr).await?;
```

### Configuration Conversion

```rust
let config = ServerConfig::from_file("config/server.toml")?;

// Convert to FSM server configuration
let fsm_config = config.to_fsm_server_config();

// Convert to rate limit configuration
let rate_config = config.to_rate_limit_config();

// Use in respective modules
let limiter = RateLimiter::new(rate_config);
```

## Validation

Always validate configuration before using it:

```rust
let config = ServerConfig::from_file("config/server.toml")?;

// Validate all settings
match config.validate() {
    Ok(()) => println!("Configuration is valid"),
    Err(e) => {
        eprintln!("Configuration error: {}", e);
        return Err(e.into());
    }
}
```

Common validation checks:
- Port numbers are non-zero and unique
- Base DN is not empty
- Backend type is valid
- TLS files exist (when TLS is enabled)
- IP addresses are valid
- Value ranges are correct
- Required fields are set for enabled features

## Testing Configuration

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_config() {
        let config = ServerConfig::from_file("config/server.toml").unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_conversion() {
        let config = ServerConfig::default();
        let fsm_config = config.to_fsm_server_config();

        assert_eq!(fsm_config.operation_timeout, config.operation_timeout());
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_server_with_config() {
    let config = ServerConfig::default();
    config.validate().unwrap();

    let backend = create_test_backend(&config).await.unwrap();
    let fsm_config = config.to_fsm_server_config();

    // Test server startup
    // ...
}
```

## Best Practices

1. **Always Validate**: Call `validate()` after loading configuration
2. **Use Environment Variables**: For environment-specific settings and secrets
3. **Provide Defaults**: Use `ServerConfig::default()` as a baseline
4. **Document Customizations**: Comment why settings differ from defaults
5. **Test Configuration**: Validate in CI/CD pipeline
6. **Secure Secrets**: Don't commit passwords in configuration files
7. **Version Control**: Track configuration changes
8. **Use Type Safety**: Leverage Rust's type system for compile-time checks

## Troubleshooting

### Configuration Not Loaded

```rust
// Check file exists
if !std::path::Path::new("config/server.toml").exists() {
    eprintln!("Configuration file not found");
    // Use defaults or exit
}

// Check file permissions
let config = match ServerConfig::from_file("config/server.toml") {
    Ok(c) => c,
    Err(e) => {
        eprintln!("Failed to load configuration: {}", e);
        return Err(e.into());
    }
};
```

### Environment Variables Not Working

```bash
# Ensure correct prefix and separator
export OPENDR_SERVER__LDAP_PORT=389  # Correct
export SERVER_LDAP_PORT=389          # Wrong - missing OPENDR prefix
export OPENDR_SERVER_LDAP_PORT=389   # Wrong - single underscore
```

### Validation Fails

```rust
let config = ServerConfig::from_file("config/server.toml")?;

match config.validate() {
    Ok(()) => {
        // Continue with valid configuration
    }
    Err(e) => {
        // Log specific error
        eprintln!("Configuration validation failed: {}", e);
        eprintln!("Please check your configuration file");
        return Err(e.into());
    }
}
```

## Examples

See the following examples for complete integration:

- `examples/config_server_demo.rs` - Configuration loading and conversion
- `config/server.example.toml` - Fully annotated example
- `config/server.development.toml` - Development settings
- `config/server.production.toml` - Production settings

## API Reference

### ServerConfig Methods

- `from_file(path)` - Load from TOML file with environment overrides
- `from_toml_str(toml)` - Load from TOML string
- `validate()` - Validate all configuration values
- `to_fsm_server_config()` - Convert to FSM server configuration
- `to_rate_limit_config()` - Convert to rate limiter configuration
- `ldap_bind_address()` - Get LDAP bind address string
- `ldaps_bind_address()` - Get LDAPS bind address string
- `operation_timeout()` - Get operation timeout as Duration
- `cleanup_interval()` - Get cleanup interval as Duration
- `connection_idle_timeout()` - Get idle timeout as Duration
- `rate_limit_window_duration()` - Get rate limit window as Duration
- `auto_ban_duration()` - Get auto-ban duration as Duration
- `to_toml_string()` - Export configuration to TOML string
- `save_to_file(path)` - Save configuration to file

## Migration Guide

If you're migrating from the old `SetupConfig`:

```rust
// Old way
let config: SetupConfig = toml::from_str(&content)?;

// New way
let config = ServerConfig::from_file("config/server.toml")?;
config.validate()?;

// Access settings (same field names in server section)
let base_dn = config.server.base_dn;
let ldap_port = config.server.ldap_port;
```

The new `ServerConfig` provides:
- More comprehensive settings (10 sections vs 1)
- Built-in validation
- Environment variable support
- Conversion helpers
- Better type safety

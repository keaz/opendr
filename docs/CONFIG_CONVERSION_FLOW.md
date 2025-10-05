# ServerConfig to FsmServerConfig Conversion Flow

This document explains how `ServerConfig.to_fsm_server_config()` works and how configuration flows through the system.

## Overview

The `to_fsm_server_config()` method converts the comprehensive `ServerConfig` into the FSM-specific `FsmServerConfig` that the server uses at runtime.

## Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                      Configuration Sources                   │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  1. TOML File                2. Environment Variables        │
│     config/server.toml          OPENDR_SERVER__LDAP_PORT     │
│                                 OPENDR_RATE_LIMIT__ENABLED   │
│                                                               │
└───────────────────┬─────────────────────────────────────────┘
                    │
                    │ ServerConfig::from_file()
                    ▼
┌─────────────────────────────────────────────────────────────┐
│                       ServerConfig                           │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   server    │  │   backend   │  │     tls     │         │
│  ├─────────────┤  ├─────────────┤  ├─────────────┤         │
│  │ ldap_port   │  │ type        │  │ enabled     │         │
│  │ base_dn     │  │ data_dir    │  │ cert_file   │         │
│  │ timeout_sec │  │ lmdb_size   │  │ key_file    │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
│                                                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │  resources  │  │ rate_limit  │  │ monitoring  │         │
│  ├─────────────┤  ├─────────────┤  ├─────────────┤         │
│  │ max_conns   │  │ enabled     │  │ enabled     │         │
│  │ max_per_ip  │  │ global_rps  │  │ port        │         │
│  │ timeout_sec │  │ per_cli_rps │  │ path        │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
│                                                               │
│  + audit, replication, access_control, performance           │
└───────────────────┬─────────────────────────────────────────┘
                    │
                    │ .validate()
                    ▼
             ┌──────────────┐
             │  Validation  │
             │  - Ports     │
             │  - IPs       │
             │  - Files     │
             │  - Ranges    │
             └──────┬───────┘
                    │
                    │ .to_fsm_server_config()
                    ▼
┌─────────────────────────────────────────────────────────────┐
│                     FsmServerConfig                          │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  operation_timeout: Duration        ← server.timeout_secs    │
│  cleanup_interval: Duration         ← server.cleanup_secs    │
│  read_buffer_size: usize           ← server.buffer_size     │
│  max_concurrent_operations: usize  ← server.max_ops         │
│  rate_limiting_enabled: bool       ← rate_limit.enabled     │
│                                                               │
│  resource_limits: ResourceLimits {                           │
│    max_connections                 ← resources.max_conns     │
│    max_connections_per_ip          ← resources.max_per_ip    │
│    max_operations_per_connection   ← resources.max_ops       │
│    max_memory_per_connection       ← resources.max_mem       │
│    max_total_memory                ← resources.total_mem     │
│    connection_idle_timeout         ← resources.timeout_secs  │
│  }                                                            │
│                                                               │
│  rate_limit_config: RateLimitConfig {                        │
│    ← via .to_rate_limit_config()                            │
│  }                                                            │
│                                                               │
└───────────────────┬─────────────────────────────────────────┘
                    │
                    │ Used by FSM Server
                    ▼
┌─────────────────────────────────────────────────────────────┐
│                    FSM Server Runtime                        │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────────────────────────────────────────┐       │
│  │  Connection Pool                                  │       │
│  │  - Uses resource_limits.max_connections          │       │
│  │  - Uses resource_limits.max_connections_per_ip   │       │
│  └──────────────────────────────────────────────────┘       │
│                                                               │
│  ┌──────────────────────────────────────────────────┐       │
│  │  Rate Limiter                                     │       │
│  │  - Uses rate_limit_config                        │       │
│  │  - Checks rate_limiting_enabled                  │       │
│  └──────────────────────────────────────────────────┘       │
│                                                               │
│  ┌──────────────────────────────────────────────────┐       │
│  │  Operation Handler                                │       │
│  │  - Uses operation_timeout for timeouts           │       │
│  │  - Uses cleanup_interval for cleanup tasks       │       │
│  └──────────────────────────────────────────────────┘       │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

## Conversion Details

### 1. Duration Conversions

```rust
// ServerConfig (u64 seconds) → FsmServerConfig (Duration)
operation_timeout: Duration::from_secs(config.server.operation_timeout_secs)
cleanup_interval: Duration::from_secs(config.server.cleanup_interval_secs)
```

### 2. Resource Limits Mapping

```rust
resource_limits: ResourceLimits {
    max_connections:                 config.resources.max_connections,
    max_connections_per_ip:          config.resources.max_connections_per_ip,
    max_operations_per_connection:   config.resources.max_operations_per_connection,
    max_memory_per_connection:       config.resources.max_memory_per_connection,
    max_total_memory:                config.resources.max_total_memory,
    connection_idle_timeout:         Duration::from_secs(config.resources.connection_idle_timeout_secs),
}
```

### 3. Rate Limit Config Conversion

```rust
// Delegates to to_rate_limit_config()
rate_limit_config: config.to_rate_limit_config()

// Which converts:
- global_requests_per_second    → u32
- per_client_requests_per_second → u32
- operation_limits               → HashMap<OperationType, u32>
- blacklist strings              → Vec<IpAddr> (parsed)
- whitelist strings              → Vec<IpAddr> (parsed)
- window_duration_secs           → Duration
- auto_ban_duration_secs         → Duration
```

## Usage Example

### Complete Flow

```rust
use opendr::config::ServerConfig;
use opendr::fsm_server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Load configuration
    let config = ServerConfig::from_file("config/server.toml")?;
    //    ↓ Reads TOML file
    //    ↓ Applies environment variable overrides
    //    ↓ Returns ServerConfig instance

    // 2. Validate
    config.validate()?;
    //    ↓ Checks all constraints
    //    ↓ Returns Ok(()) or ConfigError

    // 3. Convert to FSM config
    let fsm_config = config.to_fsm_server_config();
    //    ↓ Maps fields from ServerConfig
    //    ↓ Converts u64 → Duration
    //    ↓ Creates ResourceLimits
    //    ↓ Creates RateLimitConfig
    //    ↓ Returns FsmServerConfig

    // 4. Create backend
    let backend = create_backend(&config).await?;

    // 5. Run server
    fsm_server::run(
        &config.ldap_bind_address(),  // Uses ServerConfig helper
        backend,
        fsm_config,                    // Uses converted config
    ).await?;

    Ok(())
}
```

## Configuration Fields Used

### From ServerConfig.server

| Field | Type | Used For | Converted To |
|-------|------|----------|--------------|
| `operation_timeout_secs` | `u64` | Operation timeouts | `Duration` |
| `cleanup_interval_secs` | `u64` | Cleanup task interval | `Duration` |
| `read_buffer_size` | `usize` | Socket read buffer | `usize` |
| `max_concurrent_operations` | `usize` | Max ops per connection | `usize` |

### From ServerConfig.resources

| Field | Type | Used For | Converted To |
|-------|------|----------|--------------|
| `max_connections` | `usize` | Total connection limit | `usize` |
| `max_connections_per_ip` | `usize` | Per-IP limit | `usize` |
| `max_operations_per_connection` | `usize` | Operation limit | `usize` |
| `max_memory_per_connection` | `usize` | Memory limit | `usize` |
| `max_total_memory` | `usize` | Total memory limit | `usize` |
| `connection_idle_timeout_secs` | `u64` | Idle timeout | `Duration` |

### From ServerConfig.rate_limit

| Field | Type | Used For | Converted To |
|-------|------|----------|--------------|
| `enabled` | `bool` | Enable/disable rate limiting | `bool` |
| `global_requests_per_second` | `u32` | Global rate limit | `u32` |
| `per_client_requests_per_second` | `u32` | Per-client limit | `u32` |
| `operation_limits` | `OperationLimits` | Per-operation limits | `HashMap<OperationType, u32>` |
| `window_duration_secs` | `u64` | Rate limit window | `Duration` |
| `adaptive_*` | various | Adaptive limiting | various |
| `blacklist` | `Vec<String>` | Blocked IPs | `Vec<IpAddr>` |
| `whitelist` | `Vec<String>` | Allowed IPs | `Vec<IpAddr>` |
| `auto_ban_*` | various | Auto-ban settings | various |

## Helper Methods

### Bind Address Helpers

```rust
let config = ServerConfig::default();

// Get formatted addresses
config.ldap_bind_address()   // "127.0.0.1:1389"
config.ldaps_bind_address()  // "127.0.0.1:1636"

// Used for:
let listener = TcpListener::bind(&config.ldap_bind_address()).await?;
```

### Duration Helpers

```rust
let config = ServerConfig::default();

// Get as Duration directly
config.operation_timeout()            // Duration::from_secs(300)
config.cleanup_interval()             // Duration::from_secs(60)
config.connection_idle_timeout()      // Duration::from_secs(600)
config.rate_limit_window_duration()  // Duration::from_secs(1)
config.auto_ban_duration()            // Duration::from_secs(300)

// Used for:
tokio::time::timeout(config.operation_timeout(), operation).await?;
```

## Type Conversions

### String → IpAddr

```rust
// In ServerConfig
blacklist: Vec<String>  = ["192.168.1.100", "10.0.0.5"]

// In RateLimitConfig (after conversion)
blacklist: Vec<IpAddr>  = [192.168.1.100, 10.0.0.5]

// Conversion code:
config.rate_limit.blacklist
    .iter()
    .filter_map(|s| s.parse().ok())
    .collect()
```

### OperationLimits → HashMap

```rust
// In ServerConfig
operation_limits: OperationLimits {
    bind: 10,
    search: 50,
    modify: 20,
    // ...
}

// In RateLimitConfig (after conversion)
operation_limits: HashMap<OperationType, u32> {
    OperationType::Bind => 10,
    OperationType::Search => 50,
    OperationType::Modify => 20,
    // ...
}
```

### u64 Seconds → Duration

```rust
// In ServerConfig
operation_timeout_secs: u64 = 300

// In FsmServerConfig (after conversion)
operation_timeout: Duration = Duration::from_secs(300)
```

## Integration Points

### 1. FSM Server Startup

```rust
// fsm_server::run() receives FsmServerConfig
pub async fn run(
    addr: &str,
    backend: Arc<dyn DirectoryBackend>,
    config: FsmServerConfig,  // ← Converted from ServerConfig
) -> Result<(), ServerError>
```

### 2. Connection Pool

```rust
// Uses resource_limits from FsmServerConfig
let pool = ConnectionPool::new(config.resource_limits.clone());
```

### 3. Rate Limiter

```rust
// Uses rate_limit_config from FsmServerConfig
let rate_limiter = if config.rate_limiting_enabled {
    Some(RateLimiter::new(config.rate_limit_config.clone()))
} else {
    None
};
```

### 4. Operation Handling

```rust
// Uses timeouts and buffer sizes
let read_buffer = vec![0u8; config.read_buffer_size];
tokio::time::timeout(config.operation_timeout, operation).await?;
```

## Benefits of This Design

1. **Separation of Concerns**
   - `ServerConfig`: User-facing, TOML-friendly, comprehensive
   - `FsmServerConfig`: Runtime-optimized, FSM-specific

2. **Type Safety**
   - Compile-time guarantees for conversions
   - Duration instead of raw seconds
   - IpAddr instead of strings

3. **Validation**
   - Configuration validated before conversion
   - Invalid configs caught early
   - Type conversions can't fail

4. **Flexibility**
   - Easy to add new config options
   - Backward compatible
   - Environment variable overrides

5. **Maintainability**
   - Single source of truth (ServerConfig)
   - Clear conversion logic
   - Well-documented flow

## Testing

The conversion is tested at multiple levels:

```rust
// Unit test
#[test]
fn test_to_fsm_server_config() {
    let config = ServerConfig::default();
    let fsm_config = config.to_fsm_server_config();

    assert_eq!(fsm_config.operation_timeout, config.operation_timeout());
    assert_eq!(fsm_config.resource_limits.max_connections, config.resources.max_connections);
}

// Integration test
#[tokio::test]
async fn test_server_with_converted_config() {
    let config = ServerConfig::from_toml_str(TOML).unwrap();
    let fsm_config = config.to_fsm_server_config();

    // Verify server starts with converted config
    // ...
}
```

## Summary

The `to_fsm_server_config()` method provides a clean, type-safe bridge between the user-friendly `ServerConfig` and the runtime-optimized `FsmServerConfig`. It handles all necessary type conversions, delegates to specialized converters, and ensures the FSM server receives properly formatted configuration data.

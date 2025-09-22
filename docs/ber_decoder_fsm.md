# BER Decoder FSM Implementation

## Overview

The `BerDecoderFsmImpl` is a comprehensive implementation of the `BerDecoderFsm` trait that provides streaming BER (Basic Encoding Rules) decoding for LDAP messages. It handles incremental data processing, maintains state across partial message reception, and provides extensive validation and callback mechanisms.

## Architecture

```
┌─────────────┐  DataReceived   ┌──────────────┐  Length Parsed   ┌─────────────────┐
│ WaitingTag  ├────────────────►│ WaitingLength├─────────────────►│  WaitingValue   │
└─────────────┘                 └──────────────┘                   └─────────────────┘
       ▲                                                                      │ Message Complete
       │                                                                      ▼
       │                        ┌──────────────────┐                ┌─────────────────┐
       └────── Reset/Next ──────│ MessageComplete  │◄───────────────│ Value Complete  │
                                └──────────────────┘                └─────────────────┘
                                         │
                                    Extract Message
                                         │
                                         ▼
                                 ┌─────────────┐
                                 │ WaitingTag  │ (Next Message)
                                 └─────────────┘
```

## BER Encoding Format

BER follows the Tag-Length-Value (TLV) structure:

### Tag (1+ bytes)
- **Universal Tags**: 0x01-0x1F (BOOLEAN, INTEGER, OCTET STRING, etc.)
- **Context-Specific**: 0x80-0xBF (Application-specific meanings)
- **Constructed Flag**: Bit 5 (0x20) indicates compound structures

### Length (1+ bytes)
- **Short Form**: 0x00-0x7F (lengths 0-127)
- **Long Form**: 0x80-0xFF followed by 1-4 length bytes
- **Indefinite**: 0x80 (not supported in this implementation)

### Value (0+ bytes)
- Actual data content as specified by the length field

## Key Features

### ✅ **Streaming Processing**
- Handles partial messages across multiple data receptions
- Maintains internal buffer for incomplete data
- Processes messages incrementally without blocking

### ✅ **Complete BER Support**
- Short length encoding (0-127 bytes)
- Long length encoding (128+ bytes, up to 4 length bytes)
- Zero-length messages (NULL, empty OCTET STRINGs)
- All standard BER tag types

### ✅ **Validation & Security**
- Configurable message size limits
- Buffer overflow protection
- Custom tag validation via `BerValidator` trait
- Length validation and sanity checking

### ✅ **Callback System**
- `BerMessageHandler` for processing complete messages
- Progress tracking with `BerDecodingProgress`
- Error notification and recovery

### ✅ **Performance & Statistics**
- Message and byte counters
- Processing statistics and uptime tracking
- Minimal memory allocation and zero-copy where possible

## Core Types

### BerDecoderFsmImpl
The main FSM implementation with configurable behavior:

```rust
pub struct BerDecoderFsmImpl {
    // FSM state and buffer management
    state: BerDecoderState,
    buffer: Vec<u8>,
    current_message: Option<BerMessage>,
    
    // Configuration and handlers
    config: BerDecoderConfig,
    validator: Option<Box<dyn BerValidator>>,
    message_handler: Option<Box<dyn BerMessageHandler>>,
    
    // Statistics and timing
    messages_processed: u64,
    bytes_processed: u64,
    start_time: Instant,
}
```

### BerDecoderConfig
Comprehensive configuration options:

```rust
pub struct BerDecoderConfig {
    pub max_message_size: usize,    // Maximum single message size
    pub max_buffer_size: usize,     // Maximum internal buffer size
    pub message_timeout: Option<Duration>, // Timeout for message completion
    pub strict_validation: bool,    // Enable strict BER validation
}
```

### BerValidator Trait
Custom validation interface:

```rust
#[async_trait]
pub trait BerValidator: Send + Sync {
    async fn validate_tag(&self, tag: u8) -> Result<(), String>;
    async fn validate_length(&self, length: usize) -> Result<(), String>;
    fn max_message_size(&self) -> usize;
    fn is_constructed(&self, tag: u8) -> bool;
}
```

### BerMessageHandler Trait
Callback interface for message processing:

```rust
#[async_trait]
pub trait BerMessageHandler: Send + Sync {
    async fn on_message_complete(&mut self, message: &[u8]) -> Result<(), String>;
    async fn on_progress_update(&mut self, progress: &BerDecodingProgress) -> Result<(), String>;
    async fn on_error(&mut self, error: &str) -> Result<(), String>;
}
```

## Usage Examples

### Basic Usage

```rust
use opendr::ber_decoder_fsm::BerDecoderFsmImpl;
use opendr::fsm::{StateMachine, BerDecoderEvent};

// Create decoder with default settings
let mut decoder = BerDecoderFsmImpl::new();

// Process BER-encoded LDAP message
let ber_message = vec![0x04, 0x05, b'H', b'e', b'l', b'l', b'o']; // OCTET STRING "Hello"
match decoder.handle_event(BerDecoderEvent::DataReceived(ber_message)).await {
    Ok(Some(decoded)) => {
        println!("Decoded message: {} bytes", decoded.len());
        // Process the complete BER message
    }
    Ok(None) => println!("Incomplete message, need more data"),
    Err(e) => println!("Decoding error: {}", e),
}
```

### Advanced Configuration

```rust
use opendr::ber_decoder_fsm::{BerDecoderFsmImpl, BerDecoderConfig};
use std::time::Duration;

// Custom configuration for LDAP server
let config = BerDecoderConfig {
    max_message_size: 64 * 1024,    // 64KB LDAP message limit
    max_buffer_size: 128 * 1024,    // 128KB buffer limit
    message_timeout: Some(Duration::from_secs(30)),
    strict_validation: true,
};

let mut decoder = BerDecoderFsmImpl::with_config(config);
```

### With Validation

```rust
struct LdapBerValidator;

#[async_trait]
impl BerValidator for LdapBerValidator {
    async fn validate_tag(&self, tag: u8) -> Result<(), String> {
        match tag {
            // Allow common LDAP BER tags
            0x01 | 0x02 | 0x04 | 0x05 | 0x0A | 0x30 | 0x31 => Ok(()),
            0x80..=0x8F => Ok(()), // Context-specific tags
            _ => Err(format!("Invalid LDAP tag: 0x{:02X}", tag)),
        }
    }
    
    async fn validate_length(&self, length: usize) -> Result<(), String> {
        if length > 64 * 1024 {
            Err("LDAP message too large".to_string())
        } else {
            Ok(())
        }
    }
    
    fn max_message_size(&self) -> usize { 64 * 1024 }
    fn is_constructed(&self, tag: u8) -> bool { tag & 0x20 != 0 }
}

let validator = Box::new(LdapBerValidator);
let mut decoder = BerDecoderFsmImpl::new().with_validator(validator);
```

### With Message Handler

```rust
struct MessageProcessor {
    messages: Vec<Vec<u8>>,
}

#[async_trait]
impl BerMessageHandler for MessageProcessor {
    async fn on_message_complete(&mut self, message: &[u8]) -> Result<(), String> {
        println!("Received LDAP message: {} bytes", message.len());
        self.messages.push(message.to_vec());
        
        // Process LDAP message content
        if message.len() >= 2 && message[0] == 0x30 {
            println!("LDAP SEQUENCE detected");
        }
        
        Ok(())
    }
    
    async fn on_progress_update(&mut self, progress: &BerDecodingProgress) -> Result<(), String> {
        if let Some(length) = progress.length {
            let pct = (progress.bytes_received as f32 / length as f32) * 100.0;
            println!("Progress: {:.1}%", pct);
        }
        Ok(())
    }
    
    async fn on_error(&mut self, error: &str) -> Result<(), String> {
        eprintln!("BER decoder error: {}", error);
        Ok(())
    }
}

let handler = Box::new(MessageProcessor { messages: Vec::new() });
let mut decoder = BerDecoderFsmImpl::new().with_message_handler(handler);
```

### Incremental Processing

```rust
let mut decoder = BerDecoderFsmImpl::new();

// Receive data incrementally (e.g., from TCP stream)
let tag_data = vec![0x04]; // OCTET STRING tag
let result1 = decoder.handle_event(BerDecoderEvent::DataReceived(tag_data)).await?;
assert!(result1.is_none()); // Not complete yet

let length_data = vec![0x0A]; // Length 10
let result2 = decoder.handle_event(BerDecoderEvent::DataReceived(length_data)).await?;
assert!(result2.is_none()); // Still not complete

let partial_value = vec![b'H', b'e', b'l', b'l', b'o'];
let result3 = decoder.handle_event(BerDecoderEvent::DataReceived(partial_value)).await?;
assert!(result3.is_none()); // Still need 5 more bytes

let remaining_value = vec![b' ', b'W', b'o', b'r', b'l', b'd'];
let result4 = decoder.handle_event(BerDecoderEvent::DataReceived(remaining_value)).await?;
if let Some(complete_message) = result4 {
    println!("Complete message: {} bytes", complete_message.len());
}
```

## Implementation Details

### State Management
The FSM enforces valid state transitions:
- `WaitingTag` → `WaitingLength` (when tag received)
- `WaitingLength` → `WaitingValue` (when length parsed)
- `WaitingValue` → `MessageComplete` (when value complete)
- `MessageComplete` → `WaitingTag` (after message extraction)

### Memory Management
- **Buffer Management**: Automatically grows/shrinks based on message size
- **Zero-Copy**: Messages are extracted without additional copying where possible
- **Bounded Growth**: Configurable limits prevent unbounded memory usage

### Error Handling
- **Validation Errors**: Invalid tags/lengths trigger immediate error state
- **Size Limits**: Messages exceeding limits are rejected
- **Recovery**: FSM can be reset after errors for continued operation

### Thread Safety
- FSM itself is not `Send + Sync` due to internal state
- Each connection should have its own FSM instance
- Handlers are required to be `Send + Sync` for async compatibility

## Performance Characteristics

- **State Transitions**: O(1) time complexity
- **Memory Usage**: ~500 bytes base + buffer size + message size
- **Processing Overhead**: Minimal - primarily memory copies and state checks
- **Async Overhead**: Zero-cost abstractions with tokio compatibility

## Testing

The implementation includes 22 comprehensive unit tests covering:

### Core Functionality
- Message decoding (short/long length, zero-length)
- Incremental data processing
- State transitions and validation
- Buffer management and limits

### Error Conditions
- Invalid tags and lengths
- Buffer overflow protection
- Message size limits
- Validation failures

### Advanced Features
- Custom validators and message handlers
- Statistics and progress tracking
- FSM reset and recovery
- Configuration validation

### Running Tests

```bash
# Run all BER decoder tests
cargo test ber_decoder_fsm

# Run with output for debugging
cargo test ber_decoder_fsm -- --nocapture

# Run specific test
cargo test ber_decoder_fsm::tests::test_simple_ber_message_short_length
```

## Examples

Two demonstration programs showcase the decoder:

```bash
# Simple usage demonstration
cargo run --example ber_decoder_fsm_simple

# Advanced features with custom handlers
cargo run --example ber_decoder_fsm_demo
```

## Integration with LDAP Server

The BerDecoderFsm integrates seamlessly with other FSMs:

```rust
struct LdapConnection {
    connection_fsm: ConnectionFsmImpl,
    ber_decoder_fsm: BerDecoderFsmImpl,
    auth_fsm: AuthFsmImpl,
}

impl LdapConnection {
    async fn handle_tcp_data(&mut self, data: Vec<u8>) -> Result<(), LdapError> {
        // First decode BER messages from TCP stream
        match self.ber_decoder_fsm.handle_event(BerDecoderEvent::DataReceived(data)).await? {
            Some(ber_message) => {
                // Parse LDAP message from BER encoding
                let ldap_message = parse_ldap_message(&ber_message)?;
                
                // Route to appropriate operation FSM
                match ldap_message.operation {
                    LdapOperation::Bind => self.auth_fsm.handle_bind(ldap_message).await?,
                    LdapOperation::Search => self.search_fsm.handle_search(ldap_message).await?,
                    // ... other operations
                }
            }
            None => {
                // Incomplete BER message, wait for more data
            }
        }
        Ok(())
    }
}
```

## Common BER Tags in LDAP

| Tag | Type | Description | Usage in LDAP |
|-----|------|-------------|---------------|
| 0x01 | BOOLEAN | Boolean value | Simple authentication |
| 0x02 | INTEGER | Signed integer | Message ID, result codes |
| 0x04 | OCTET STRING | Byte sequence | DNs, attribute values |
| 0x05 | NULL | Empty value | No value present |
| 0x0A | ENUMERATED | Enumerated value | Search scope, operation type |
| 0x30 | SEQUENCE | Ordered collection | LDAP messages, search results |
| 0x31 | SET | Unordered collection | Attribute sets |
| 0x80-0x8F | Context[0-15] | Context-specific | LDAP operation parameters |

## Future Enhancements

- [ ] Support for indefinite length encoding (0x80)
- [ ] Multi-byte tag support for extended BER
- [ ] Compression integration for large messages
- [ ] Metrics collection and OpenTelemetry integration
- [ ] Performance optimizations for high-throughput scenarios
- [ ] Schema-aware validation for specific LDAP message types

## Error Reference

### BerDecoderError Types

- **InvalidTag**: Unrecognized or invalid BER tag
- **InvalidLength**: Malformed length encoding
- **BufferOverflow**: Input exceeds buffer capacity
- **MessageTooLarge**: Message exceeds size limits
- **IncompleteMessage**: More data needed to complete message
- **Generic**: Catch-all for other error conditions

All errors include detailed messages for debugging and provide context about the specific failure condition.
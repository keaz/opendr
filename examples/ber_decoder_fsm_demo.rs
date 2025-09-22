//! BER Decoder FSM Demo
//!
//! This example demonstrates how to use the BerDecoderFsm implementation
//! for streaming BER message decoding with validation and callbacks.

use opendr::ber_decoder_fsm::{
    BerDecoderFsmImpl, BerValidator, BerMessageHandler, BerDecoderConfig
};
use opendr::fsm::{StateMachine, BerDecoderEvent, BerDecoderFsm, BerDecodingProgress};
use async_trait::async_trait;
use std::time::Duration;

/// Example BER validator that implements LDAP-specific validation rules
struct LdapBerValidator {
    max_message_size: usize,
}

impl LdapBerValidator {
    fn new() -> Self {
        Self {
            max_message_size: 64 * 1024, // 64KB for LDAP messages
        }
    }
}

#[async_trait]
impl BerValidator for LdapBerValidator {
    async fn validate_tag(&self, tag: u8) -> Result<(), String> {
        // LDAP commonly uses these BER tags
        match tag {
            // SEQUENCE (0x30), SET (0x31), OCTET STRING (0x04), INTEGER (0x02)
            // BOOLEAN (0x01), ENUMERATED (0x0A), etc.
            0x01 | 0x02 | 0x04 | 0x05 | 0x0A | 0x30 | 0x31 => {
                println!("🟢 Validated BER tag: 0x{:02X}", tag);
                Ok(())
            }
            // Context-specific tags (0x80-0x8F) common in LDAP
            0x80..=0x8F => {
                println!("🔵 Context-specific tag: 0x{:02X}", tag);
                Ok(())
            }
            _ => {
                println!("🔴 Unknown BER tag: 0x{:02X}", tag);
                Err(format!("Unsupported BER tag: 0x{:02X}", tag))
            }
        }
    }
    
    async fn validate_length(&self, length: usize) -> Result<(), String> {
        if length > self.max_message_size {
            Err(format!("Length {} exceeds maximum {}", length, self.max_message_size))
        } else {
            println!("✅ Validated length: {} bytes", length);
            Ok(())
        }
    }
    
    fn max_message_size(&self) -> usize {
        self.max_message_size
    }
    
    fn is_constructed(&self, tag: u8) -> bool {
        // In BER, bit 5 (0x20) indicates constructed encoding
        tag & 0x20 != 0
    }
}

/// Example message handler that processes complete BER messages
struct LdapMessageHandler {
    messages_received: usize,
    total_bytes: usize,
}

impl LdapMessageHandler {
    fn new() -> Self {
        Self {
            messages_received: 0,
            total_bytes: 0,
        }
    }
}

#[async_trait]
impl BerMessageHandler for LdapMessageHandler {
    async fn on_message_complete(&mut self, message: &[u8]) -> Result<(), String> {
        self.messages_received += 1;
        self.total_bytes += message.len();
        
        println!("🎉 Message #{} completed! ({} bytes)", 
                 self.messages_received, message.len());
        
        // Pretty print first few bytes
        let preview = if message.len() > 10 {
            format!("{:02X?}...", &message[..10])
        } else {
            format!("{:02X?}", message)
        };
        println!("   Content preview: {}", preview);
        
        // Analyze message structure
        if message.len() >= 2 {
            let tag = message[0];
            let length = message[1];
            println!("   Tag: 0x{:02X}, Length: {}", tag, length);
            
            if tag == 0x30 {
                println!("   📦 SEQUENCE structure detected");
            } else if tag == 0x04 {
                println!("   📄 OCTET STRING detected");
                if message.len() > 2 {
                    let value = &message[2..];
                    if let Ok(s) = std::str::from_utf8(value) {
                        println!("   📝 String content: \"{}\"", s);
                    }
                }
            }
        }
        
        Ok(())
    }
    
    async fn on_progress_update(&mut self, progress: &BerDecodingProgress) -> Result<(), String> {
        if let (Some(tag), Some(length)) = (progress.tag, progress.length) {
            let percentage = if length > 0 {
                (progress.bytes_received as f32 / length as f32) * 100.0
            } else {
                100.0
            };
            
            println!("📊 Progress: {:.1}% ({}/{} bytes) for tag 0x{:02X}", 
                     percentage, progress.bytes_received, length, tag);
        }
        Ok(())
    }
    
    async fn on_error(&mut self, error: &str) -> Result<(), String> {
        println!("❌ BER decoder error: {}", error);
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 BER Decoder FSM Demo");
    println!("======================");
    
    // Create custom configuration
    let config = BerDecoderConfig {
        max_message_size: 1024,
        max_buffer_size: 2048,
        message_timeout: Some(Duration::from_secs(10)),
        strict_validation: true,
    };
    
    // Create validator and message handler
    let validator = Box::new(LdapBerValidator::new());
    let message_handler = Box::new(LdapMessageHandler::new());
    
    // Create BER decoder FSM
    let mut fsm = BerDecoderFsmImpl::with_config(config)
        .with_validator(validator)
        .with_message_handler(message_handler);
    
    println!("📊 Initial state: {:?}", fsm.current_state());
    println!("🏁 Terminal: {}", fsm.is_terminal());
    
    // Demonstrate BER message decoding
    println!("\n🧪 Testing BER Message Decoding:");
    
    // Test 1: Simple OCTET STRING
    println!("\n📝 Test 1: OCTET STRING \"Hello\"");
    let octet_string = vec![0x04, 0x05, b'H', b'e', b'l', b'l', b'o'];
    
    match fsm.handle_event(BerDecoderEvent::DataReceived(octet_string)).await {
        Ok(Some(message)) => {
            println!("✅ Successfully decoded message: {} bytes", message.len());
        }
        Ok(None) => println!("⏳ Message incomplete, need more data"),
        Err(e) => println!("❌ Error: {}", e),
    }
    
    // Test 2: SEQUENCE with multiple elements (simulated LDAP structure)
    println!("\n📦 Test 2: SEQUENCE structure");
    let sequence = vec![
        0x30, 0x0A,           // SEQUENCE, length 10
        0x02, 0x01, 0x01,     // INTEGER 1 (version)
        0x04, 0x05, b'a', b'd', b'm', b'i', b'n' // OCTET STRING "admin"
    ];
    
    match fsm.handle_event(BerDecoderEvent::DataReceived(sequence)).await {
        Ok(Some(message)) => {
            println!("✅ Successfully decoded SEQUENCE: {} bytes", message.len());
        }
        Ok(None) => println!("⏳ SEQUENCE incomplete, need more data"),
        Err(e) => println!("❌ Error: {}", e),
    }
    
    // Test 3: Incremental message processing
    println!("\n🔄 Test 3: Incremental message processing");
    
    // Send message in parts
    println!("   Sending tag...");
    let result1 = fsm.handle_event(BerDecoderEvent::DataReceived(vec![0x04])).await;
    println!("   Result: {:?}", result1.is_ok());
    
    println!("   Sending length...");
    let result2 = fsm.handle_event(BerDecoderEvent::DataReceived(vec![0x06])).await;
    println!("   Result: {:?}", result2.is_ok());
    
    println!("   Sending partial value...");
    let result3 = fsm.handle_event(BerDecoderEvent::DataReceived(vec![b'W', b'o', b'r'])).await;
    println!("   Result: {:?}", result3.is_ok());
    
    println!("   Sending remaining value...");
    let result4 = fsm.handle_event(BerDecoderEvent::DataReceived(vec![b'l', b'd', b'!'])).await;
    match result4 {
        Ok(Some(message)) => {
            println!("   ✅ Complete message received: {} bytes", message.len());
        }
        Ok(None) => println!("   ⏳ Still incomplete"),
        Err(e) => println!("   ❌ Error: {}", e),
    }
    
    // Test 4: Long length encoding
    println!("\n🔢 Test 4: Long length encoding");
    let mut long_message = vec![0x04, 0x82, 0x00, 0x80]; // OCTET STRING, length 128 (long form)
    long_message.extend(vec![b'X'; 128]);
    
    match fsm.handle_event(BerDecoderEvent::DataReceived(long_message)).await {
        Ok(Some(message)) => {
            println!("✅ Long message decoded: {} bytes", message.len());
        }
        Ok(None) => println!("⏳ Long message incomplete"),
        Err(e) => println!("❌ Error: {}", e),
    }
    
    // Test 5: Context-specific tag
    println!("\n🏷️  Test 5: Context-specific tag");
    let context_tag = vec![0x80, 0x04, b't', b'e', b's', b't']; // Context tag [0], length 4
    
    match fsm.handle_event(BerDecoderEvent::DataReceived(context_tag)).await {
        Ok(Some(message)) => {
            println!("✅ Context-specific tag decoded: {} bytes", message.len());
        }
        Ok(None) => println!("⏳ Context tag incomplete"),
        Err(e) => println!("❌ Error: {}", e),
    }
    
    // Test 6: Zero-length message
    println!("\n🕳️  Test 6: Zero-length message");
    let empty_message = vec![0x05, 0x00]; // NULL, length 0
    
    match fsm.handle_event(BerDecoderEvent::DataReceived(empty_message)).await {
        Ok(Some(message)) => {
            println!("✅ Zero-length message decoded: {} bytes", message.len());
        }
        Ok(None) => println!("⏳ Zero-length incomplete"),
        Err(e) => println!("❌ Error: {}", e),
    }
    
    // Show FSM statistics
    let stats = fsm.stats();
    println!("\n📈 Final Statistics:");
    println!("   Messages processed: {}", stats.messages_processed);
    println!("   Bytes processed: {}", stats.bytes_processed);
    println!("   Current buffer size: {}", stats.current_buffer_size);
    println!("   Uptime: {:?}", stats.uptime);
    
    // Test decoder capabilities
    println!("\n🔍 Decoder Capabilities:");
    println!("   Current state: {:?}", fsm.current_state());
    println!("   Buffer contents: {} bytes", fsm.buffer().len());
    
    if let Some(needed) = fsm.bytes_needed() {
        println!("   Bytes needed: {}", needed);
    } else {
        println!("   Bytes needed: N/A");
    }
    
    let progress = fsm.progress();
    println!("   Progress: tag={:?}, length={:?}, received={}, needed={:?}", 
             progress.tag, progress.length, progress.bytes_received, progress.bytes_needed);
    
    // Test error handling
    println!("\n💥 Test 7: Error handling");
    println!("   Sending invalid tag...");
    let invalid_data = vec![0xFF, 0x01, 0x00]; // Invalid tag
    
    match fsm.handle_event(BerDecoderEvent::DataReceived(invalid_data)).await {
        Ok(Some(_)) => println!("   🤔 Unexpectedly succeeded"),
        Ok(None) => println!("   ⏳ Incomplete (unexpected)"),
        Err(e) => println!("   ✅ Expected error: {}", e),
    }
    
    // Reset FSM after error
    println!("   Resetting FSM...");
    fsm.reset().await?;
    println!("   ✅ FSM reset, state: {:?}", fsm.current_state());
    
    println!("\n🎯 Demo Summary:");
    println!("   - BER decoding works incrementally");
    println!("   - Supports both short and long length encoding");
    println!("   - Validates tags and lengths via custom handlers");
    println!("   - Provides progress tracking and statistics");
    println!("   - Handles errors gracefully with reset capability");
    println!("   - Supports context-specific tags and zero-length messages");
    
    println!("\n🎉 Demo completed successfully!");
    Ok(())
}
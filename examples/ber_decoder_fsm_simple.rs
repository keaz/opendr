//! Simple BER Decoder FSM Demo
//!
//! This example shows basic usage of the BerDecoderFsm for processing
//! BER-encoded messages commonly found in LDAP protocols.

use opendr::ber_decoder_fsm::{BerDecoderConfig, BerDecoderFsmImpl};
use opendr::fsm::{BerDecoderEvent, BerDecoderFsm, StateMachine};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Simple BER Decoder FSM Demo");
    println!("=============================");

    // Create a basic BER decoder with default configuration
    let mut fsm = BerDecoderFsmImpl::new();

    println!("📊 Initial state: {:?}", fsm.current_state());
    println!("🏁 Terminal: {}", fsm.is_terminal());
    println!("📦 Buffer size: {} bytes", fsm.buffer().len());

    // Example 1: Simple OCTET STRING
    println!("\n📝 Example 1: Decoding OCTET STRING");
    let message1 = vec![
        0x04, 0x0C, b'H', b'e', b'l', b'l', b'o', b' ', b'W', b'o', b'r', b'l', b'd', b'!',
    ]; // "Hello World!"

    match fsm
        .handle_event(BerDecoderEvent::DataReceived(message1))
        .await
    {
        Ok(Some(decoded)) => {
            println!("✅ Decoded message: {} bytes", decoded.len());
            println!("   Tag: 0x{:02X}", decoded[0]);
            println!("   Length: {}", decoded[1]);
            if let Ok(content) = std::str::from_utf8(&decoded[2..]) {
                println!("   Content: \"{}\"", content);
            }
        }
        Ok(None) => println!("⏳ Need more data"),
        Err(e) => println!("❌ Error: {}", e),
    }

    // Example 2: INTEGER
    println!("\n🔢 Example 2: Decoding INTEGER");
    let message2 = vec![0x02, 0x02, 0x01, 0xFF]; // INTEGER 511

    match fsm
        .handle_event(BerDecoderEvent::DataReceived(message2))
        .await
    {
        Ok(Some(decoded)) => {
            println!("✅ Decoded INTEGER: {} bytes", decoded.len());
            let value = (decoded[2] as u16) << 8 | decoded[3] as u16;
            println!("   Value: {}", value);
        }
        Ok(None) => println!("⏳ Need more data"),
        Err(e) => println!("❌ Error: {}", e),
    }

    // Example 3: Zero-length message
    println!("\n🕳️  Example 3: Zero-length NULL");
    let message3 = vec![0x05, 0x00]; // NULL

    match fsm
        .handle_event(BerDecoderEvent::DataReceived(message3))
        .await
    {
        Ok(Some(decoded)) => {
            println!("✅ Decoded NULL: {} bytes", decoded.len());
            println!("   Tag: 0x{:02X} (NULL)", decoded[0]);
            println!("   Length: {}", decoded[1]);
        }
        Ok(None) => println!("⏳ Need more data"),
        Err(e) => println!("❌ Error: {}", e),
    }

    // Example 4: Incremental processing
    println!("\n🔄 Example 4: Incremental message processing");

    println!("   Step 1: Sending tag (0x04)...");
    let _result1 = fsm
        .handle_event(BerDecoderEvent::DataReceived(vec![0x04]))
        .await;
    println!(
        "   State: {:?}, Bytes needed: {:?}",
        fsm.current_state(),
        fsm.bytes_needed()
    );

    println!("   Step 2: Sending length (0x08)...");
    let _result2 = fsm
        .handle_event(BerDecoderEvent::DataReceived(vec![0x08]))
        .await;
    println!(
        "   State: {:?}, Bytes needed: {:?}",
        fsm.current_state(),
        fsm.bytes_needed()
    );

    println!("   Step 3: Sending partial value...");
    let _result3 = fsm
        .handle_event(BerDecoderEvent::DataReceived(vec![b'P', b'a', b'r', b't']))
        .await;
    println!(
        "   State: {:?}, Bytes needed: {:?}",
        fsm.current_state(),
        fsm.bytes_needed()
    );

    println!("   Step 4: Sending remaining value...");
    let result4 = fsm
        .handle_event(BerDecoderEvent::DataReceived(vec![b'i', b'a', b'l', b'!']))
        .await;

    match result4 {
        Ok(Some(decoded)) => {
            println!("   ✅ Complete message assembled: {} bytes", decoded.len());
            if let Ok(content) = std::str::from_utf8(&decoded[2..]) {
                println!("   Content: \"{}\"", content);
            }
        }
        Ok(None) => println!("   ⏳ Still need more data"),
        Err(e) => println!("   ❌ Error: {}", e),
    }

    // Example 5: Long length encoding
    println!("\n📏 Example 5: Long length encoding (256+ bytes)");
    let mut long_message = vec![0x04, 0x82, 0x01, 0x00]; // OCTET STRING, length 256 (long form)
    long_message.extend(vec![b'A'; 256]); // 256 'A' characters

    match fsm
        .handle_event(BerDecoderEvent::DataReceived(long_message))
        .await
    {
        Ok(Some(decoded)) => {
            println!("✅ Long message decoded: {} bytes", decoded.len());
            println!("   Tag: 0x{:02X}", decoded[0]);
            println!(
                "   Length encoding: [0x{:02X}, 0x{:02X}, 0x{:02X}]",
                decoded[1], decoded[2], decoded[3]
            );
            println!("   Content length: {} bytes", decoded.len() - 4);
        }
        Ok(None) => println!("⏳ Long message incomplete"),
        Err(e) => println!("❌ Error: {}", e),
    }

    // Show FSM progress and statistics
    let progress = fsm.progress();
    let stats = fsm.stats();

    println!("\n📊 FSM Status:");
    println!("   Current state: {:?}", fsm.current_state());
    println!("   Buffer: {} bytes", fsm.buffer().len());
    println!(
        "   Progress: tag={:?}, length={:?}",
        progress.tag, progress.length
    );
    println!("   Messages processed: {}", stats.messages_processed);
    println!("   Total bytes processed: {}", stats.bytes_processed);

    // Example 6: Reset functionality
    println!("\n🔄 Example 6: FSM Reset");
    println!("   Before reset - State: {:?}", fsm.current_state());

    fsm.reset().await?;

    println!("   After reset - State: {:?}", fsm.current_state());
    println!("   Buffer cleared: {} bytes", fsm.buffer().len());

    // Example 7: Custom configuration
    println!("\n⚙️  Example 7: Custom configuration");
    let config = BerDecoderConfig {
        max_message_size: 512,                         // Limit messages to 512 bytes
        max_buffer_size: 1024,                         // Limit buffer to 1KB
        message_timeout: Some(Duration::from_secs(5)), // 5 second timeout
        strict_validation: true,                       // Enable strict validation
    };

    let mut custom_fsm = BerDecoderFsmImpl::with_config(config);
    println!("   Custom FSM created with 512 byte message limit");

    // Try to decode a message that exceeds the limit
    let oversized = vec![0x04, 0x82, 0x02, 0x01]; // OCTET STRING, length 513 (exceeds limit)
    match custom_fsm
        .handle_event(BerDecoderEvent::DataReceived(oversized))
        .await
    {
        Ok(Some(_)) => println!("   🤔 Unexpectedly succeeded"),
        Ok(None) => println!("   ⏳ Incomplete (normal)"),
        Err(e) => println!("   ✅ Expected size limit error: {}", e),
    }

    println!("\n🎯 Demo Summary:");
    println!("   ✅ Successfully decoded various BER message types");
    println!("   ✅ Demonstrated incremental processing capability");
    println!("   ✅ Showed long length encoding support");
    println!("   ✅ Verified FSM reset functionality");
    println!("   ✅ Tested custom configuration limits");

    println!("\n🔧 Key Features:");
    println!("   • Streaming BER decoding");
    println!("   • Support for both short and long length encoding");
    println!("   • Progress tracking and statistics");
    println!("   • Configurable size limits and validation");
    println!("   • Clean error handling and recovery");

    println!("\n🎉 Simple demo completed!");
    Ok(())
}

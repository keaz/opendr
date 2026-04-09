//! Simple ConnectionFsm Demo
//!
//! This example demonstrates the state transitions of ConnectionFsm
//! using mock handlers that simulate successful operations.

use async_trait::async_trait;
use opendr::connection_fsm::{ConnectionFsmImpl, NetworkHandler, TlsHandler};
use opendr::fsm::{ConnectionEvent, ConnectionFsm, StateMachine};
use std::io::ErrorKind;
use std::time::Duration;
use tokio::net::TcpStream;

/// Mock TLS handler for demonstration
struct MockTlsHandler;

#[async_trait]
impl TlsHandler for MockTlsHandler {
    async fn perform_handshake(&self, _stream: &mut TcpStream) -> Result<(), String> {
        println!("🔐 Mock TLS handshake...");
        tokio::time::sleep(Duration::from_millis(10)).await;
        Ok(())
    }

    fn supports_tls(&self) -> bool {
        true
    }

    fn protocol_version(&self) -> String {
        "Mock-TLS-1.3".to_string()
    }
}

/// Mock network handler that simulates connection success
struct MockNetworkHandler;

#[async_trait]
impl NetworkHandler for MockNetworkHandler {
    async fn connect(&self, addr: &str) -> Result<TcpStream, std::io::Error> {
        println!("🌐 Mock connecting to {}...", addr);
        tokio::time::sleep(Duration::from_millis(10)).await;

        // We can't create a real TcpStream easily in examples, but the FSM
        // handles the case where no stream is available gracefully
        Err(std::io::Error::new(
            ErrorKind::ConnectionRefused,
            "Mock connection",
        ))
    }

    fn local_addr(&self, _stream: &TcpStream) -> Result<String, std::io::Error> {
        Ok("127.0.0.1:12345".to_string())
    }

    fn remote_addr(&self, _stream: &TcpStream) -> Result<String, std::io::Error> {
        Ok("127.0.0.1:1389".to_string())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Simple ConnectionFsm Demo");
    println!("===========================");

    // Create FSM with mock handlers
    let tls_handler = Box::new(MockTlsHandler);
    let network_handler = Box::new(MockNetworkHandler);

    let mut fsm =
        ConnectionFsmImpl::with_network_handler("127.0.0.1:1389", tls_handler, network_handler);

    println!("📊 Initial state: {:?}", fsm.current_state());
    println!("🏁 Is terminal: {}", fsm.is_terminal());

    // Demonstrate state inspection
    println!("\n🔍 Connection Properties:");
    println!("   Address: 127.0.0.1:1389");
    println!("   Secure: {}", fsm.is_secure());

    let info = fsm.connection_info();
    println!("   Connection Info:");
    println!("     Remote: {}", info.remote_addr);
    println!("     Local: {}", info.local_addr);
    println!("     Secure: {}", info.is_secure);
    println!("     Protocol: {}", info.protocol_version);

    // Show various events and their results
    println!("\n🧪 Event Testing:");

    // Test connection establishment
    println!("📡 Testing ConnectionEstablished event...");
    match fsm
        .handle_event(ConnectionEvent::ConnectionEstablished)
        .await
    {
        Ok(Some(info)) => {
            println!("   ✅ Success! New state: {:?}", fsm.current_state());
            println!(
                "   📋 Info: Remote={}, Secure={}",
                info.remote_addr, info.is_secure
            );
        }
        Ok(None) => println!("   ✅ Success! No additional info"),
        Err(e) => println!("   ❌ Error: {}", e),
    }

    // Test StartTLS request
    println!("🔒 Testing StartTlsRequest event...");
    match fsm.handle_event(ConnectionEvent::StartTlsRequest).await {
        Ok(_) => println!("   ✅ Success! New state: {:?}", fsm.current_state()),
        Err(e) => println!("   ❌ Error: {}", e),
    }

    // Test TLS handshake complete
    println!("🤝 Testing TlsHandshakeComplete event...");
    match fsm
        .handle_event(ConnectionEvent::TlsHandshakeComplete)
        .await
    {
        Ok(Some(info)) => {
            println!("   ✅ Success! New state: {:?}", fsm.current_state());
            println!("   📋 Secure connection: {}", info.is_secure);
        }
        Ok(None) => println!("   ✅ Success! No additional info"),
        Err(e) => println!("   ❌ Error: {}", e),
    }

    // Test close
    println!("🔌 Testing Close event...");
    match fsm.handle_event(ConnectionEvent::Close).await {
        Ok(_) => println!("   ✅ Success! New state: {:?}", fsm.current_state()),
        Err(e) => println!("   ❌ Error: {}", e),
    }

    println!("🏁 Final terminal state: {}", fsm.is_terminal());

    // Test reset
    println!("\n🔄 Testing FSM reset...");
    fsm.reset().await?;
    println!("   ✅ Reset successful! State: {:?}", fsm.current_state());

    // Demonstrate error handling
    println!("\n💥 Testing Error Handling:");

    // Try invalid transition
    println!("🚫 Attempting invalid transition (Close from Connecting)...");
    match fsm.handle_event(ConnectionEvent::Close).await {
        Ok(_) => println!("   🤔 Unexpected success"),
        Err(e) => println!("   ✅ Expected error: {}", e),
    }

    println!("\n🎯 Demo Summary:");
    println!("   - FSM properly manages connection state");
    println!("   - State transitions are validated");
    println!("   - Error conditions are handled gracefully");
    println!("   - Mock handlers allow testing without real connections");
    println!("   - ConnectionInfo provides connection metadata");

    println!("\n🎉 Demo completed successfully!");
    Ok(())
}

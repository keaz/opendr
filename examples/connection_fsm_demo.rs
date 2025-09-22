//! ConnectionFsm Demo
//! 
//! This example demonstrates how to use the ConnectionFsm implementation
//! for managing LDAP connection lifecycle with optional TLS upgrade.

use opendr::connection_fsm::{ConnectionFsmImpl, TlsHandler, NetworkHandler};
use opendr::fsm::{StateMachine, ConnectionEvent};
use async_trait::async_trait;
use tokio::net::TcpStream;
use std::time::Duration;

/// Example TLS handler that simulates real TLS operations
struct ExampleTlsHandler {
    supports_tls: bool,
}

impl ExampleTlsHandler {
    fn new(supports_tls: bool) -> Self {
        Self { supports_tls }
    }
}

#[async_trait]
impl TlsHandler for ExampleTlsHandler {
    async fn perform_handshake(&self, _stream: &mut TcpStream) -> Result<(), String> {
        println!("🔐 Performing TLS handshake...");
        
        // Simulate TLS handshake delay
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        if self.supports_tls {
            println!("✅ TLS handshake successful!");
            Ok(())
        } else {
            Err("TLS not supported by server".to_string())
        }
    }
    
    fn supports_tls(&self) -> bool {
        self.supports_tls
    }
    
    fn protocol_version(&self) -> String {
        "TLSv1.3".to_string()
    }
}

/// Example network handler for demonstration
struct ExampleNetworkHandler;

#[async_trait]
impl NetworkHandler for ExampleNetworkHandler {
    async fn connect(&self, addr: &str) -> Result<TcpStream, std::io::Error> {
        println!("🌐 Connecting to {}...", addr);
        
        // For demo purposes, we'll simulate a connection
        // In real usage, this would be: TcpStream::connect(addr).await
        tokio::time::sleep(Duration::from_millis(50)).await;
        
        // Since we can't easily create a real TcpStream in examples,
        // we'll simulate with an error that indicates success
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "DEMO_SUCCESS"
        ))
    }
    
    fn local_addr(&self, _stream: &TcpStream) -> Result<String, std::io::Error> {
        Ok("127.0.0.1:55432".to_string())
    }
    
    fn remote_addr(&self, _stream: &TcpStream) -> Result<String, std::io::Error> {
        Ok("127.0.0.1:1389".to_string())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 ConnectionFsm Demo Starting");
    println!("================================");
    
    // Create TLS handler
    let tls_handler = Box::new(ExampleTlsHandler::new(true));
    let network_handler = Box::new(ExampleNetworkHandler);
    
    // Create ConnectionFsm
    let mut fsm = ConnectionFsmImpl::with_network_handler(
        "127.0.0.1:1389",
        tls_handler,
        network_handler,
    );
    
    println!("📊 Initial State: {:?}", fsm.current_state());
    
    // Demonstrate connection establishment
    println!("\n🔄 Step 1: Establishing connection...");
    match fsm.handle_event(ConnectionEvent::ConnectionEstablished).await {
        Ok(Some(info)) => {
            println!("✅ Connection established!");
            println!("   Remote: {}", info.remote_addr);
            println!("   Local: {}", info.local_addr);
            println!("   Secure: {}", info.is_secure);
            println!("   Protocol: {}", info.protocol_version);
        }
        Ok(None) => println!("📝 Connection established (no info)"),
        Err(e) => println!("❌ Connection failed: {}", e),
    }
    
    println!("📊 Current State: {:?}", fsm.current_state());
    
    // Demonstrate StartTLS upgrade (proper sequence)
    println!("\n🔄 Step 2: Starting TLS upgrade...");
    
    // First, initiate StartTLS negotiation
    println!("🔒 Initiating StartTLS negotiation...");
    match fsm.handle_event(ConnectionEvent::StartTlsRequest).await {
        Ok(_) => println!("✅ StartTLS negotiation initiated"),
        Err(e) => println!("❌ StartTLS negotiation failed: {}", e),
    }
    
    println!("📊 Current State: {:?}", fsm.current_state());
    
    // Then, complete the TLS handshake
    println!("🔒 Completing TLS handshake...");
    match fsm.handle_event(ConnectionEvent::TlsHandshakeComplete).await {
        Ok(Some(info)) => {
            println!("✅ TLS upgrade successful!");
            println!("   Secure: {}", info.is_secure);
            println!("   Protocol: {}", info.protocol_version);
        }
        Ok(None) => println!("📝 TLS upgrade completed"),
        Err(e) => println!("❌ TLS upgrade failed: {}", e),
    }
    
    println!("📊 Current State: {:?}", fsm.current_state());
    
    // Demonstrate connection closure
    println!("\n🔄 Step 3: Closing connection...");
    match fsm.handle_event(ConnectionEvent::Close).await {
        Ok(_) => println!("✅ Connection closed successfully"),
        Err(e) => println!("❌ Connection close failed: {}", e),
    }
    
    println!("📊 Final State: {:?}", fsm.current_state());
    println!("🏁 Terminal State: {}", fsm.is_terminal());
    
    // Demonstrate FSM reset
    println!("\n🔄 Step 4: Resetting FSM...");
    fsm.reset().await?;
    println!("✅ FSM reset to initial state");
    println!("📊 Reset State: {:?}", fsm.current_state());
    
    println!("\n🎉 Demo completed successfully!");
    Ok(())
}
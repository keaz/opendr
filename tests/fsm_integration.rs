//! Integration tests for FSM-based server functionality
//!
//! This test suite verifies that the FSM integration maintains compatibility
//! with existing LDAP operations while adding the FSM layer for state management.

use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use opendr::backend::MockBackend;
use opendr::server_fsm::handle_client_fsm_simple;

#[tokio::test]
async fn test_fsm_server_basic_connection() {
    // Create a test server using FSM infrastructure
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    let backend = Arc::new(MockBackend::default());

    // Spawn FSM-based server task
    let server_handle = tokio::spawn({
        let backend = backend.clone();
        async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_client_fsm_simple(stream, backend).await;
        }
    });

    // Create a client connection
    let mut client = TcpStream::connect(local_addr).await.unwrap();
    
    // Send a simple LDAP bind request (raw bytes)
    // This is a minimal bind request: message ID 1, version 3, empty DN, simple auth with empty password
    let bind_request = vec![
        0x30, 0x0e, // SEQUENCE, length 14
        0x02, 0x01, 0x01, // messageID: 1
        0x60, 0x09, // BindRequest, length 9
        0x02, 0x01, 0x03, // version: 3
        0x04, 0x00, // name: empty string
        0x80, 0x00, // simple authentication: empty password
    ];
    
    client.write_all(&bind_request).await.unwrap();
    
    // Read the response
    let mut buffer = vec![0; 1024];
    let n = client.read(&mut buffer).await.unwrap();
    
    // We should get some response (the exact format depends on the backend)
    assert!(n > 0, "Should receive a response from the FSM server");
    
    // Close the connection gracefully
    drop(client);
    
    // Wait for the server to finish processing
    let _ = tokio::time::timeout(std::time::Duration::from_millis(100), server_handle).await;
}

#[tokio::test]  
async fn test_fsm_ber_decoder_functionality() {
    use opendr::server_fsm::{BerDecoderFsmImpl};
    use opendr::fsm::{BerDecoderEvent, BerDecoderFsm, BerDecoderState, StateMachine};

    let mut decoder = BerDecoderFsmImpl::new();
    
    // Test the BER decoder FSM with sample LDAP message data
    let sample_data = vec![
        0x30, 0x0e, // SEQUENCE, length 14
        0x02, 0x01, 0x01, // messageID: 1  
        0x60, 0x09, // BindRequest, length 9
        0x02, 0x01, 0x03, // version: 3
        0x04, 0x00, // name: empty string
        0x80, 0x00, // simple authentication: empty password
    ];
    
    // Send data to decoder
    decoder.handle_event(BerDecoderEvent::DataReceived(sample_data.clone()))
        .await
        .unwrap();
    
    // Should be in MessageComplete state
    assert_eq!(decoder.current_state(), &BerDecoderState::MessageComplete);
    
    // Should be able to extract the complete message
    let extracted = decoder.extract_message().unwrap();
    assert_eq!(extracted, sample_data);
    
    // After extraction, should return to WaitingTag state
    assert_eq!(decoder.current_state(), &BerDecoderState::WaitingTag);
}
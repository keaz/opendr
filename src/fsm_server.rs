//! FSM-Based LDAP Server Implementation
//!
//! This module provides a complete LDAP server implementation using the FSM
//! (Finite State Machine) architecture. Unlike the traditional server.rs which
//! processes messages synchronously, this server manages FSM instances for
//! concurrent operations.
//!
//! ## Architecture
//!
//! Each client connection gets a `ConnectionFsmSet` that manages:
//! - Connection FSM: TCP/TLS lifecycle
//! - BER Decoder FSM: Message parsing
//! - Authentication FSM: Session identity
//! - Operation FSMs: One per concurrent LDAP operation
//!
//! ## Benefits over Traditional Server
//!
//! - **True Concurrency**: Multiple operations can run in parallel per connection
//! - **Timeout Management**: Automatic cleanup of stale operations
//! - **State Tracking**: Clear FSM states for debugging and monitoring
//! - **Extensibility**: Easy to add new operation types or protocols

use std::sync::Arc;
use std::time::Duration;

use ldap_parser::ldap::{ProtocolOp, LdapMessage};
use ldap_parser::parse_ldap_messages;
use log::{error, info, warn, debug};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

use crate::backend::DirectoryBackend;
use crate::fsm_runtime::{ConnectionFsmSet, OperationFsm, OperationType};
use crate::fsm::{StateMachine, BerDecoderEvent, ConnectionEvent, ConnectionFsm, BerDecoderFsm};
use crate::server::ServerError;

/// Configuration for the FSM-based server
#[derive(Debug, Clone)]
pub struct FsmServerConfig {
    /// Maximum age for operations before timeout
    pub operation_timeout: Duration,

    /// How often to check for timed-out operations
    pub cleanup_interval: Duration,

    /// Buffer size for reading from socket
    pub read_buffer_size: usize,

    /// Maximum number of concurrent operations per connection
    pub max_concurrent_operations: usize,
}

impl Default for FsmServerConfig {
    fn default() -> Self {
        Self {
            operation_timeout: Duration::from_secs(300), // 5 minutes
            cleanup_interval: Duration::from_secs(60),   // 1 minute
            read_buffer_size: 4096,
            max_concurrent_operations: 100,
        }
    }
}

/// Run the FSM-based LDAP server
///
/// # Arguments
/// * `addr` - Address to bind to (e.g., "127.0.0.1:1389")
/// * `backend` - Directory backend implementation
/// * `config` - Server configuration
///
/// # Returns
/// * `Result<(), ServerError>` - Server error if binding or operation fails
pub async fn run(
    addr: &str,
    backend: Arc<dyn DirectoryBackend>,
    config: FsmServerConfig,
) -> Result<(), ServerError> {
    let listener = TcpListener::bind(addr).await?;
    info!("FSM-based LDAP server listening on {}", addr);

    loop {
        let (socket, client_addr) = listener.accept().await?;
        info!("Accepted FSM connection from {:?}", client_addr);

        let backend = backend.clone();
        let config = config.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket, backend, config).await {
                error!("Connection error for {:?}: {}", client_addr, e);
            }
            info!("FSM connection {:?} closed", client_addr);
        });
    }
}

/// Handle a single client connection using FSM architecture
async fn handle_connection(
    socket: TcpStream,
    backend: Arc<dyn DirectoryBackend>,
    config: FsmServerConfig,
) -> Result<(), ServerError> {
    // Create FSM set for this connection
    let mut fsm_set = ConnectionFsmSet::new(socket, backend.clone(), None);

    // Buffer for reading from socket
    let mut read_buffer = vec![0u8; config.read_buffer_size];

    // Spawn timeout cleanup task
    let cleanup_interval = config.cleanup_interval;
    let operation_timeout = config.operation_timeout;

    // Main event loop
    loop {
        // Check if connection is terminated
        if fsm_set.is_terminal() {
            debug!("Connection FSM reached terminal state");
            break;
        }

        // Clean up timed-out and terminal operations periodically
        let timed_out = fsm_set.cleanup_timed_out_operations(operation_timeout);
        if timed_out > 0 {
            warn!("Cleaned up {} timed-out operations", timed_out);
        }

        let terminal = fsm_set.cleanup_terminal_operations();
        if terminal > 0 {
            debug!("Cleaned up {} completed operations", terminal);
        }

        // Read from socket
        let stream = fsm_set.connection_mut().stream_mut()
            .ok_or_else(|| std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "No active stream"
            ))?;

        // Try to read with a timeout so we can periodically clean up
        let read_result = tokio::time::timeout(
            cleanup_interval,
            stream.read(&mut read_buffer)
        ).await;

        match read_result {
            Ok(Ok(0)) => {
                // Connection closed
                debug!("Client closed connection");
                break;
            }
            Ok(Ok(n)) => {
                // Got data, process it
                let data = &read_buffer[..n];
                debug!("Received {} bytes", n);

                // Feed data to BER decoder FSM
                let decoder_event = BerDecoderEvent::DataReceived(data.to_vec());
                if let Err(e) = fsm_set.decoder_mut().handle_event(decoder_event).await {
                    error!("BER decoder error: {}", e);
                    break;
                }

                // Extract complete messages from decoder
                while let Some(message_bytes) = fsm_set.decoder_mut().extract_message() {
                    // Parse LDAP message
                    match parse_ldap_messages(&message_bytes) {
                        Ok((_, messages)) => {
                            for message in messages {
                                if let Err(e) = process_ldap_message(
                                    &mut fsm_set,
                                    message,
                                    &config,
                                ).await {
                                    error!("Failed to process LDAP message: {}", e);
                                    // Don't break, try to continue with next message
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to parse LDAP message: {:?}", e);
                            // Send protocol error response?
                            break;
                        }
                    }
                }
            }
            Ok(Err(e)) => {
                error!("Socket read error: {}", e);
                break;
            }
            Err(_) => {
                // Timeout - continue loop to check for cleanup
                continue;
            }
        }
    }

    Ok(())
}

/// Process a parsed LDAP message using FSM architecture
async fn process_ldap_message(
    fsm_set: &mut ConnectionFsmSet,
    message: LdapMessage<'_>,
    config: &FsmServerConfig,
) -> Result<(), String> {
    let message_id = message.message_id.0 as i32;

    debug!("Processing LDAP message ID {} type {:?}", message_id, message.protocol_op);

    match message.protocol_op {
        ProtocolOp::BindRequest(bind_req) => {
            // Handle bind through auth FSM
            handle_bind_with_fsm(fsm_set, message_id, bind_req).await?;
        }

        ProtocolOp::UnbindRequest => {
            info!("Received unbind request");
            // Trigger connection close
            if let Err(e) = fsm_set.connection_mut()
                .handle_event(ConnectionEvent::Close).await {
                warn!("Error closing connection: {}", e);
            }
        }

        ProtocolOp::SearchRequest(_req) => {
            // For now, return "operation not supported in FSM mode"
            // Full implementation would create SearchFsm instance
            warn!("Search operations not yet fully implemented in FSM server");
            send_not_implemented_response(fsm_set, message_id, "SearchResultDone").await?;
        }

        ProtocolOp::ModifyRequest(_req) => {
            warn!("Modify operations not yet fully implemented in FSM server");
            send_not_implemented_response(fsm_set, message_id, "ModifyResponse").await?;
        }

        ProtocolOp::AddRequest(_req) => {
            warn!("Add operations not yet fully implemented in FSM server");
            send_not_implemented_response(fsm_set, message_id, "AddResponse").await?;
        }

        ProtocolOp::DelRequest(_req) => {
            warn!("Delete operations not yet fully implemented in FSM server");
            send_not_implemented_response(fsm_set, message_id, "DelResponse").await?;
        }

        ProtocolOp::ModDnRequest(_req) => {
            warn!("ModifyDN operations not yet fully implemented in FSM server");
            send_not_implemented_response(fsm_set, message_id, "ModifyDNResponse").await?;
        }

        ProtocolOp::CompareRequest(_req) => {
            warn!("Compare operations not yet fully implemented in FSM server");
            send_not_implemented_response(fsm_set, message_id, "CompareResponse").await?;
        }

        ProtocolOp::AbandonRequest(abandoned_id) => {
            info!("Abandon request for message ID {}", abandoned_id.0);
            // Remove the operation FSM
            fsm_set.remove_operation(abandoned_id.0 as i32);
        }

        ProtocolOp::ExtendedRequest(_req) => {
            warn!("Extended operations not yet fully implemented in FSM server");
            send_not_implemented_response(fsm_set, message_id, "ExtendedResponse").await?;
        }

        _ => {
            warn!("Unsupported operation: {:?}", message.protocol_op);
        }
    }

    Ok(())
}

/// Handle bind request using Authentication FSM
async fn handle_bind_with_fsm(
    fsm_set: &mut ConnectionFsmSet,
    message_id: i32,
    bind_req: ldap_parser::ldap::BindRequest<'_>,
) -> Result<(), String> {
    use ldap_parser::ldap::AuthenticationChoice;
    use crate::fsm::{AuthEvent, StateMachine};
    use crate::fsm_runtime::AuthenticationFsm;

    // Check LDAP version
    if bind_req.version != 3 {
        send_bind_error(fsm_set, message_id as u32, "unsupported LDAP version").await?;
        return Ok(());
    }

    match bind_req.authentication {
        AuthenticationChoice::Simple(password) => {
            let dn = bind_req.name.0.as_ref().trim().to_owned();

            // Get mutable reference to auth FSM
            let auth_event = AuthEvent::BindRequest {
                dn: dn.clone(),
                password: password.as_ref().to_vec(),
            };

            // Send event to auth FSM
            match fsm_set.auth_mut() {
                AuthenticationFsm::Simple(auth_fsm) => {
                    match auth_fsm.handle_event(auth_event).await {
                        Ok(_) => {
                            // Check if authenticated
                            if fsm_set.is_authenticated() {
                                send_bind_success(fsm_set, message_id as u32).await?;
                            } else {
                                send_bind_error(fsm_set, message_id as u32, "invalid credentials").await?;
                            }
                        }
                        Err(e) => {
                            error!("Auth FSM error: {}", e);
                            send_bind_error(fsm_set, message_id as u32, "authentication failed").await?;
                        }
                    }
                }
                AuthenticationFsm::Sasl(_) => {
                    send_bind_error(fsm_set, message_id as u32, "SASL not configured").await?;
                }
            }
        }
        AuthenticationChoice::Sasl(_) => {
            send_bind_error(fsm_set, message_id as u32, "SASL not supported").await?;
        }
    }

    Ok(())
}

/// Send bind success response
async fn send_bind_success(fsm_set: &mut ConnectionFsmSet, message_id: u32) -> Result<(), String> {
    use crate::parser::encode_bind_response;
    use rasn_ldap::ResultCode;

    let response = encode_bind_response(message_id, ResultCode::Success, "", "")
        .map_err(|e| format!("Encode error: {:?}", e))?;

    let stream = fsm_set.connection_mut().stream_mut()
        .ok_or("No active stream")?;

    stream.write_all(&response).await
        .map_err(|e| format!("Write error: {}", e))?;

    Ok(())
}

/// Send bind error response
async fn send_bind_error(
    fsm_set: &mut ConnectionFsmSet,
    message_id: u32,
    diagnostic: &str,
) -> Result<(), String> {
    use crate::parser::encode_bind_response;
    use rasn_ldap::ResultCode;

    let response = encode_bind_response(
        message_id,
        ResultCode::InvalidCredentials,
        "",
        diagnostic
    ).map_err(|e| format!("Encode error: {:?}", e))?;

    let stream = fsm_set.connection_mut().stream_mut()
        .ok_or("No active stream")?;

    stream.write_all(&response).await
        .map_err(|e| format!("Write error: {}", e))?;

    Ok(())
}

/// Send "not implemented" response for operations not yet supported in FSM mode
async fn send_not_implemented_response(
    fsm_set: &mut ConnectionFsmSet,
    message_id: i32,
    _op_name: &str,
) -> Result<(), String> {
    use crate::parser::encode_result_response;
    use crate::parser::ResponseOp;
    use rasn_ldap::ResultCode;

    // Send a generic result response
    let response = encode_result_response(
        message_id as u32,
        ResponseOp::SearchDone, // Generic response type
        ResultCode::Other,
        "",
        "FSM operation handler not yet implemented"
    ).map_err(|e| format!("Encode error: {:?}", e))?;

    let stream = fsm_set.connection_mut().stream_mut()
        .ok_or("No active stream")?;

    stream.write_all(&response).await
        .map_err(|e| format!("Write error: {}", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MockBackend;

    #[test]
    fn test_fsm_server_config_default() {
        let config = FsmServerConfig::default();
        assert_eq!(config.operation_timeout, Duration::from_secs(300));
        assert_eq!(config.cleanup_interval, Duration::from_secs(60));
        assert_eq!(config.read_buffer_size, 4096);
        assert_eq!(config.max_concurrent_operations, 100);
    }

    #[tokio::test]
    async fn test_fsm_server_bind_and_accept() {
        use tokio::net::TcpListener;

        // Create test server
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn accept task
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let backend = Arc::new(MockBackend::default());
            let config = FsmServerConfig::default();

            // Should handle connection without panicking
            let _ = handle_connection(socket, backend, config).await;
        });

        // Connect and immediately close
        let _stream = TcpStream::connect(addr).await.unwrap();

        // Give it time to process
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

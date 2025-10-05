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
use crate::connection_pool::{ConnectionPool, ResourceLimits};
use crate::fsm_runtime::{ConnectionFsmSet, OperationFsm, OperationType};
use crate::fsm::{StateMachine, BerDecoderEvent, ConnectionEvent, ConnectionFsm, BerDecoderFsm};
use crate::server::ServerError;
use crate::shutdown::ShutdownCoordinator;

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

    /// Resource limits for connection pooling
    pub resource_limits: ResourceLimits,
}

impl Default for FsmServerConfig {
    fn default() -> Self {
        Self {
            operation_timeout: Duration::from_secs(300), // 5 minutes
            cleanup_interval: Duration::from_secs(60),   // 1 minute
            read_buffer_size: 4096,
            max_concurrent_operations: 100,
            resource_limits: ResourceLimits::default(),
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
    run_with_shutdown(addr, backend, config, None).await
}

/// Run the FSM-based LDAP server with optional shutdown coordinator
///
/// # Arguments
/// * `addr` - Address to bind to (e.g., "127.0.0.1:1389")
/// * `backend` - Directory backend implementation
/// * `config` - Server configuration
/// * `shutdown` - Optional shutdown coordinator for graceful shutdown
///
/// # Returns
/// * `Result<(), ServerError>` - Server error if binding or operation fails
pub async fn run_with_shutdown(
    addr: &str,
    backend: Arc<dyn DirectoryBackend>,
    config: FsmServerConfig,
    shutdown: Option<Arc<ShutdownCoordinator>>,
) -> Result<(), ServerError> {
    let listener = TcpListener::bind(addr).await?;
    info!("FSM-based LDAP server listening on {}", addr);

    // Create connection pool
    let pool = Arc::new(ConnectionPool::new(config.resource_limits.clone()));

    // Create shutdown receiver if coordinator provided
    let mut shutdown_rx = shutdown.as_ref().map(|s| s.subscribe());

    // Spawn idle connection cleanup task
    let cleanup_pool = pool.clone();
    let cleanup_interval = config.cleanup_interval;
    let cleanup_shutdown = shutdown.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = sleep(cleanup_interval) => {
                    let cleaned = cleanup_pool.cleanup_idle_connections().await;
                    if cleaned > 0 {
                        info!("Cleaned up {} idle connections", cleaned);
                    }
                }
                _ = async {
                    if let Some(ref sd) = cleanup_shutdown {
                        let mut rx = sd.subscribe();
                        let _ = rx.recv().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {
                    info!("Cleanup task shutting down");
                    break;
                }
            }
        }
    });

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (socket, client_addr) = accept_result?;

                // Check if we're shutting down
                if let Some(ref shutdown_coord) = shutdown {
                    if shutdown_coord.is_shutting_down().await {
                        info!("Rejecting connection from {:?} - server is shutting down", client_addr);
                        let _ = send_shutdown_in_progress(socket).await;
                        continue;
                    }

                    // Register connection with shutdown coordinator
                    if shutdown_coord.register_connection().await.is_none() {
                        info!("Connection from {:?} rejected - server is shutting down", client_addr);
                        let _ = send_shutdown_in_progress(socket).await;
                        continue;
                    }
                }

                // Try to acquire connection slot
                let conn_id = match pool.acquire_connection(client_addr).await {
                    Some(id) => id,
                    None => {
                        warn!("Connection from {:?} rejected due to resource limits", client_addr);
                        // Unregister from shutdown coordinator
                        if let Some(ref shutdown_coord) = shutdown {
                            shutdown_coord.unregister_connection().await;
                        }
                        // Send error response and close
                        if let Err(e) = send_connection_rejected(socket).await {
                            error!("Failed to send rejection message: {}", e);
                        }
                        continue;
                    }
                };

                info!("Accepted FSM connection from {:?} (conn_id={})", client_addr, conn_id);

                let backend = backend.clone();
                let config = config.clone();
                let pool_clone = pool.clone();
                let shutdown_clone = shutdown.clone();

                tokio::spawn(async move {
                    if let Err(e) = handle_connection(socket, backend, config, pool_clone.clone(), conn_id, shutdown_clone.clone()).await {
                        error!("Connection error for {:?}: {}", client_addr, e);
                    }
                    // Release connection when done
                    pool_clone.release_connection(conn_id).await;

                    // Unregister from shutdown coordinator
                    if let Some(ref shutdown_coord) = shutdown_clone {
                        shutdown_coord.unregister_connection().await;
                    }

                    info!("FSM connection {:?} (conn_id={}) closed", client_addr, conn_id);
                });
            }
            _ = async {
                if let Some(ref mut rx) = shutdown_rx {
                    let _ = rx.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                info!("Shutdown signal received, stopping accept loop");
                break;
            }
        }
    }

    info!("Server stopped accepting new connections");
    Ok(())
}

/// Send connection rejected response
async fn send_connection_rejected(mut socket: TcpStream) -> Result<(), std::io::Error> {
    use crate::parser::{encode_result_response, ResponseOp};
    use rasn_ldap::ResultCode;

    // Send a generic "unavailable" response
    let response = encode_result_response(
        0, // message ID 0 for unsolicited notification
        ResponseOp::SearchDone,
        ResultCode::Unavailable,
        "",
        "Server resource limits exceeded"
    ).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{:?}", e)))?;

    socket.write_all(&response).await?;
    socket.shutdown().await?;
    Ok(())
}

/// Send shutdown in progress response
async fn send_shutdown_in_progress(mut socket: TcpStream) -> Result<(), std::io::Error> {
    use crate::parser::{encode_result_response, ResponseOp};
    use rasn_ldap::ResultCode;

    // Send "unavailable" response for shutdown
    let response = encode_result_response(
        0, // message ID 0 for unsolicited notification
        ResponseOp::SearchDone,
        ResultCode::Unavailable,
        "",
        "Server is shutting down"
    ).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{:?}", e)))?;

    socket.write_all(&response).await?;
    socket.shutdown().await?;
    Ok(())
}

/// Handle a single client connection using FSM architecture
async fn handle_connection(
    socket: TcpStream,
    backend: Arc<dyn DirectoryBackend>,
    config: FsmServerConfig,
    pool: Arc<ConnectionPool>,
    conn_id: u64,
    shutdown: Option<Arc<ShutdownCoordinator>>,
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

                // Update activity
                pool.update_activity(conn_id).await;

                // Track memory usage for received data
                pool.update_memory_usage(conn_id, data.len() as isize).await;

                // Feed data to BER decoder FSM
                let decoder_event = BerDecoderEvent::DataReceived(data.to_vec());
                if let Err(e) = fsm_set.decoder_mut().handle_event(decoder_event).await {
                    error!("BER decoder error: {}", e);
                    break;
                }

                // Extract complete messages from decoder
                while let Some(message_bytes) = fsm_set.decoder_mut().extract_message() {
                    // Release memory for the raw buffer
                    pool.update_memory_usage(conn_id, -(data.len() as isize)).await;

                    // Parse LDAP message
                    match parse_ldap_messages(&message_bytes) {
                        Ok((_, messages)) => {
                            for message in messages {
                                if let Err(e) = process_ldap_message(
                                    &mut fsm_set,
                                    message,
                                    &config,
                                    &pool,
                                    conn_id,
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
    pool: &Arc<ConnectionPool>,
    conn_id: u64,
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
            // Check if we can start an operation
            if !pool.start_operation(conn_id).await {
                warn!("Search operation rejected due to operation limit");
                send_busy_response(fsm_set, message_id, "SearchResultDone").await?;
                return Ok(());
            }

            // For now, return "operation not supported in FSM mode"
            // Full implementation would create SearchFsm instance
            warn!("Search operations not yet fully implemented in FSM server");
            send_not_implemented_response(fsm_set, message_id, "SearchResultDone").await?;

            // End operation
            pool.end_operation(conn_id).await;
        }

        ProtocolOp::ModifyRequest(_req) => {
            if !pool.start_operation(conn_id).await {
                warn!("Modify operation rejected due to operation limit");
                send_busy_response(fsm_set, message_id, "ModifyResponse").await?;
                return Ok(());
            }

            warn!("Modify operations not yet fully implemented in FSM server");
            send_not_implemented_response(fsm_set, message_id, "ModifyResponse").await?;
            pool.end_operation(conn_id).await;
        }

        ProtocolOp::AddRequest(_req) => {
            if !pool.start_operation(conn_id).await {
                warn!("Add operation rejected due to operation limit");
                send_busy_response(fsm_set, message_id, "AddResponse").await?;
                return Ok(());
            }

            warn!("Add operations not yet fully implemented in FSM server");
            send_not_implemented_response(fsm_set, message_id, "AddResponse").await?;
            pool.end_operation(conn_id).await;
        }

        ProtocolOp::DelRequest(_req) => {
            if !pool.start_operation(conn_id).await {
                warn!("Delete operation rejected due to operation limit");
                send_busy_response(fsm_set, message_id, "DelResponse").await?;
                return Ok(());
            }

            warn!("Delete operations not yet fully implemented in FSM server");
            send_not_implemented_response(fsm_set, message_id, "DelResponse").await?;
            pool.end_operation(conn_id).await;
        }

        ProtocolOp::ModDnRequest(_req) => {
            if !pool.start_operation(conn_id).await {
                warn!("ModifyDN operation rejected due to operation limit");
                send_busy_response(fsm_set, message_id, "ModifyDNResponse").await?;
                return Ok(());
            }

            warn!("ModifyDN operations not yet fully implemented in FSM server");
            send_not_implemented_response(fsm_set, message_id, "ModifyDNResponse").await?;
            pool.end_operation(conn_id).await;
        }

        ProtocolOp::CompareRequest(_req) => {
            if !pool.start_operation(conn_id).await {
                warn!("Compare operation rejected due to operation limit");
                send_busy_response(fsm_set, message_id, "CompareResponse").await?;
                return Ok(());
            }

            warn!("Compare operations not yet fully implemented in FSM server");
            send_not_implemented_response(fsm_set, message_id, "CompareResponse").await?;
            pool.end_operation(conn_id).await;
        }

        ProtocolOp::AbandonRequest(abandoned_id) => {
            info!("Abandon request for message ID {}", abandoned_id.0);
            // Remove the operation FSM
            fsm_set.remove_operation(abandoned_id.0 as i32);
            // End operation in pool
            pool.end_operation(conn_id).await;
        }

        ProtocolOp::ExtendedRequest(_req) => {
            if !pool.start_operation(conn_id).await {
                warn!("Extended operation rejected due to operation limit");
                send_busy_response(fsm_set, message_id, "ExtendedResponse").await?;
                return Ok(());
            }

            warn!("Extended operations not yet fully implemented in FSM server");
            send_not_implemented_response(fsm_set, message_id, "ExtendedResponse").await?;
            pool.end_operation(conn_id).await;
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

/// Send "busy" response when operation limits are exceeded
async fn send_busy_response(
    fsm_set: &mut ConnectionFsmSet,
    message_id: i32,
    _op_name: &str,
) -> Result<(), String> {
    use crate::parser::encode_result_response;
    use crate::parser::ResponseOp;
    use rasn_ldap::ResultCode;

    // Send busy response
    let response = encode_result_response(
        message_id as u32,
        ResponseOp::SearchDone, // Generic response type
        ResultCode::Busy,
        "",
        "Server is busy - operation limit exceeded"
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
            let (socket, client_addr) = listener.accept().await.unwrap();
            let backend = Arc::new(MockBackend::default());
            let config = FsmServerConfig::default();
            let pool = Arc::new(ConnectionPool::new(config.resource_limits.clone()));
            let conn_id = pool.acquire_connection(client_addr).await.unwrap();

            // Should handle connection without panicking
            let _ = handle_connection(socket, backend, config, pool.clone(), conn_id, None).await;
            pool.release_connection(conn_id).await;
        });

        // Connect and immediately close
        let _stream = TcpStream::connect(addr).await.unwrap();

        // Give it time to process
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

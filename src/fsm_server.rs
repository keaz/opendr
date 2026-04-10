//! FSM-Based LDAP Server Implementation
//!
//! This module provides an LDAP server implementation using the FSM
//! (Finite State Machine) architecture. Unlike the traditional `server.rs`
//! listener, this module manages FSM instances for connection lifecycle,
//! BER decoding, authentication state, and operation dispatch while reusing
//! the proven legacy handlers for protocol-heavy LDAP operations.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ldap_parser::ldap::{LdapMessage, ProtocolOp};
use ldap_parser::parse_ldap_messages;
use log::{debug, error, info, warn};
use rand::distributions::{Alphanumeric, DistString};
use rasn_ldap::ResultCode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

use crate::audit::{AuditEventType, AuditLevel};
use crate::backend::DirectoryBackend;
use crate::connection_fsm::{ConnectionTransport, TlsHandler};
use crate::connection_pool::{ConnectionPool, ResourceLimits};
use crate::extended_ops::{
    encode_password_modify_response_value, oids, parse_cancel_request_value,
    parse_password_modify_request_value,
};
use crate::fsm::{BerDecoderEvent, ConnectionEvent, ConnectionFsm, StateMachine};
use crate::fsm_request::{
    active_fsm_control_registry, FsmRequestContext, FsmRequestRejection, FsmResponseKind,
};
use crate::fsm_runtime::{AuthenticationFsm, ConnectionFsmSet};
use crate::ldap_controls::RequestControls;
use crate::metrics::{
    FsmType, MetricsCollector, OperationType as MetricsOperationType, ResourceEventType,
};
use crate::parser::{encode_custom_extended_response, encode_extended_response, ResponseOp};
use crate::rate_limit::{RateLimitConfig, RateLimiter};
use crate::schema::LdapSchema;
use crate::server::{
    handle_add_request_with_context, handle_compare_request_with_context,
    handle_delete_request_with_context, handle_moddn_request_with_context,
    handle_modify_request_with_context, handle_search_request_with_context_and_registry,
    log_anonymous_bind, log_generic_audit_event, log_password_modify_audit_event,
    log_simple_bind_failure, log_simple_bind_success, CancelRequestOutcome,
    ConnectionOperationRegistry, ConnectionSession, LegacySecurityConfig, LegacyServerConfig,
    RequestContext, ServerError,
};
use crate::shutdown::ShutdownCoordinator;
use crate::tls::RustlsTlsHandler;

/// Configuration for the FSM-based server.
#[derive(Debug, Clone)]
pub struct FsmServerConfig {
    /// Maximum age for operations before timeout.
    pub operation_timeout: Duration,
    /// How often to check for timed-out operations.
    pub cleanup_interval: Duration,
    /// Buffer size for reading from socket.
    pub read_buffer_size: usize,
    /// Maximum number of concurrent operations per connection.
    pub max_concurrent_operations: usize,
    /// Resource limits for connection pooling.
    pub resource_limits: ResourceLimits,
    /// Rate limiting configuration.
    pub rate_limit_config: RateLimitConfig,
    /// Enable rate limiting.
    pub rate_limiting_enabled: bool,
}

impl Default for FsmServerConfig {
    fn default() -> Self {
        Self {
            operation_timeout: Duration::from_secs(300),
            cleanup_interval: Duration::from_secs(60),
            read_buffer_size: 4096,
            max_concurrent_operations: 100,
            resource_limits: ResourceLimits::default(),
            rate_limit_config: RateLimitConfig::default(),
            rate_limiting_enabled: true,
        }
    }
}

/// Runtime dependencies shared with the production listener path.
#[derive(Clone, Default)]
pub struct FsmServerRuntimeContext {
    pub legacy_runtime_config: LegacyServerConfig,
    pub metrics: Option<Arc<MetricsCollector>>,
    pub security: Option<Arc<LegacySecurityConfig>>,
    pub tls_handler: Option<Arc<RustlsTlsHandler>>,
}

impl FsmServerRuntimeContext {
    fn request_context(&self, client_ip: Option<IpAddr>, conn_id: u64) -> RequestContext {
        RequestContext::new(
            client_ip,
            Some(conn_id),
            self.security.clone(),
            self.metrics.clone(),
        )
    }

    fn boxed_tls_handler(&self) -> Option<Box<dyn TlsHandler>> {
        self.tls_handler
            .clone()
            .map(|handler| Box::new(handler) as Box<dyn TlsHandler>)
    }
}

/// Run the FSM-based LDAP server with default runtime context.
pub async fn run(
    addr: &str,
    backend: Arc<dyn DirectoryBackend>,
    config: FsmServerConfig,
) -> Result<(), ServerError> {
    run_with_shutdown_and_context(
        addr,
        backend,
        config,
        FsmServerRuntimeContext::default(),
        None,
    )
    .await
}

/// Run the FSM-based LDAP server with optional shutdown and default runtime context.
pub async fn run_with_shutdown(
    addr: &str,
    backend: Arc<dyn DirectoryBackend>,
    config: FsmServerConfig,
    shutdown: Option<Arc<ShutdownCoordinator>>,
) -> Result<(), ServerError> {
    run_with_shutdown_and_context(
        addr,
        backend,
        config,
        FsmServerRuntimeContext::default(),
        shutdown,
    )
    .await
}

/// Run the FSM-based plain LDAP listener with production runtime context.
pub async fn run_with_shutdown_and_context(
    addr: &str,
    backend: Arc<dyn DirectoryBackend>,
    config: FsmServerConfig,
    runtime_context: FsmServerRuntimeContext,
    shutdown: Option<Arc<ShutdownCoordinator>>,
) -> Result<(), ServerError> {
    let listener = TcpListener::bind(addr).await?;
    info!("FSM-based LDAP server listening on {}", addr);

    let pool = Arc::new(ConnectionPool::new(config.resource_limits.clone()));
    let rate_limiter = if config.rate_limiting_enabled {
        Some(Arc::new(RateLimiter::new(config.rate_limit_config.clone())))
    } else {
        None
    };
    let mut shutdown_rx = shutdown.as_ref().map(|coord| coord.subscribe());

    spawn_runtime_tasks(
        &config,
        pool.clone(),
        rate_limiter.clone(),
        &runtime_context,
        shutdown.clone(),
    );

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (socket, client_addr) = accept_result?;
                if let Err(err) = socket.set_nodelay(true) {
                    warn!("Failed to enable TCP_NODELAY for {:?}: {}", client_addr, err);
                }

                if let Some(ref shutdown_coord) = shutdown {
                    if shutdown_coord.is_shutting_down().await {
                        info!("Rejecting connection from {:?} - server is shutting down", client_addr);
                        let _ = send_shutdown_in_progress(socket).await;
                        continue;
                    }

                    if shutdown_coord.register_connection().await.is_none() {
                        info!("Connection from {:?} rejected - server is shutting down", client_addr);
                        let _ = send_shutdown_in_progress(socket).await;
                        continue;
                    }
                }

                let conn_id = match pool.acquire_connection(client_addr).await {
                    Some(id) => id,
                    None => {
                        warn!("Connection from {:?} rejected due to resource limits", client_addr);
                        record_connection_failed(&runtime_context);
                        record_resource_event(&runtime_context, ResourceEventType::ConnectionRejected);
                        if let Some(ref shutdown_coord) = shutdown {
                            shutdown_coord.unregister_connection().await;
                        }
                        if let Err(err) = send_connection_rejected(socket).await {
                            error!("Failed to send rejection message: {}", err);
                        }
                        continue;
                    }
                };

                info!("Accepted FSM connection from {:?} (conn_id={})", client_addr, conn_id);
                record_connection_accepted(&runtime_context, false);
                audit_connection_accepted(&runtime_context, client_addr.ip(), conn_id).await;

                let backend = backend.clone();
                let config = config.clone();
                let runtime_context = runtime_context.clone();
                let pool_clone = pool.clone();
                let shutdown_clone = shutdown.clone();
                let rate_limiter_clone = rate_limiter.clone();

                tokio::spawn(async move {
                    if let Err(err) = handle_connection_with_transport(
                        ConnectionTransport::plain(socket),
                        backend,
                        config,
                        runtime_context.clone(),
                        pool_clone.clone(),
                        conn_id,
                        Some(client_addr.ip()),
                        rate_limiter_clone,
                    )
                    .await
                    {
                        error!("Connection error for {:?}: {}", client_addr, err);
                        record_connection_failed(&runtime_context);
                    }

                    pool_clone.release_connection(conn_id).await;
                    if let Some(ref shutdown_coord) = shutdown_clone {
                        shutdown_coord.unregister_connection().await;
                    }
                    record_connection_closed(&runtime_context);
                    audit_connection_closed(&runtime_context, client_addr.ip(), conn_id).await;
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
                info!("Shutdown signal received, stopping FSM LDAP accept loop");
                break;
            }
        }
    }

    info!("FSM LDAP server stopped accepting new connections");
    Ok(())
}

/// Run the FSM-based LDAPS listener with production runtime context.
pub async fn run_tls_with_shutdown_and_context(
    addr: &str,
    backend: Arc<dyn DirectoryBackend>,
    config: FsmServerConfig,
    runtime_context: FsmServerRuntimeContext,
    shutdown: Option<Arc<ShutdownCoordinator>>,
) -> Result<(), ServerError> {
    let listener = TcpListener::bind(addr).await?;
    info!("FSM-based LDAPS server listening on {}", addr);

    let pool = Arc::new(ConnectionPool::new(config.resource_limits.clone()));
    let rate_limiter = if config.rate_limiting_enabled {
        Some(Arc::new(RateLimiter::new(config.rate_limit_config.clone())))
    } else {
        None
    };
    let mut shutdown_rx = shutdown.as_ref().map(|coord| coord.subscribe());

    spawn_runtime_tasks(
        &config,
        pool.clone(),
        rate_limiter.clone(),
        &runtime_context,
        shutdown.clone(),
    );

    let tls_handler = runtime_context
        .tls_handler
        .clone()
        .ok_or_else(|| std::io::Error::other("LDAPS requires a configured TLS handler"))?;

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (socket, client_addr) = accept_result?;
                if let Err(err) = socket.set_nodelay(true) {
                    warn!("Failed to enable TCP_NODELAY for {:?}: {}", client_addr, err);
                }

                if let Some(ref shutdown_coord) = shutdown {
                    if shutdown_coord.is_shutting_down().await {
                        info!("Rejecting LDAPS connection from {:?} - server is shutting down", client_addr);
                        continue;
                    }

                    if shutdown_coord.register_connection().await.is_none() {
                        info!("LDAPS connection from {:?} rejected - server is shutting down", client_addr);
                        continue;
                    }
                }

                let conn_id = match pool.acquire_connection(client_addr).await {
                    Some(id) => id,
                    None => {
                        warn!("LDAPS connection from {:?} rejected due to resource limits", client_addr);
                        record_connection_failed(&runtime_context);
                        record_resource_event(&runtime_context, ResourceEventType::ConnectionRejected);
                        if let Some(ref shutdown_coord) = shutdown {
                            shutdown_coord.unregister_connection().await;
                        }
                        continue;
                    }
                };

                let transport = match tls_handler.accept_transport(socket).await {
                    Ok(transport) => transport,
                    Err(err) => {
                        warn!("LDAPS handshake failed for {:?}: {}", client_addr, err);
                        record_connection_failed(&runtime_context);
                        pool.release_connection(conn_id).await;
                        if let Some(ref shutdown_coord) = shutdown {
                            shutdown_coord.unregister_connection().await;
                        }
                        continue;
                    }
                };

                info!("Accepted FSM LDAPS connection from {:?} (conn_id={})", client_addr, conn_id);
                record_connection_accepted(&runtime_context, true);
                audit_connection_accepted(&runtime_context, client_addr.ip(), conn_id).await;

                let backend = backend.clone();
                let config = config.clone();
                let runtime_context = runtime_context.clone();
                let pool_clone = pool.clone();
                let shutdown_clone = shutdown.clone();
                let rate_limiter_clone = rate_limiter.clone();

                tokio::spawn(async move {
                    if let Err(err) = handle_connection_with_transport(
                        transport,
                        backend,
                        config,
                        runtime_context.clone(),
                        pool_clone.clone(),
                        conn_id,
                        Some(client_addr.ip()),
                        rate_limiter_clone,
                    )
                    .await
                    {
                        error!("LDAPS connection error for {:?}: {}", client_addr, err);
                        record_connection_failed(&runtime_context);
                    }

                    pool_clone.release_connection(conn_id).await;
                    if let Some(ref shutdown_coord) = shutdown_clone {
                        shutdown_coord.unregister_connection().await;
                    }
                    record_connection_closed(&runtime_context);
                    audit_connection_closed(&runtime_context, client_addr.ip(), conn_id).await;
                    info!("FSM LDAPS connection {:?} (conn_id={}) closed", client_addr, conn_id);
                });
            }
            _ = async {
                if let Some(ref mut rx) = shutdown_rx {
                    let _ = rx.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                info!("Shutdown signal received, stopping FSM LDAPS accept loop");
                break;
            }
        }
    }

    info!("FSM LDAPS server stopped accepting new connections");
    Ok(())
}

fn spawn_runtime_tasks(
    config: &FsmServerConfig,
    pool: Arc<ConnectionPool>,
    rate_limiter: Option<Arc<RateLimiter>>,
    runtime_context: &FsmServerRuntimeContext,
    shutdown: Option<Arc<ShutdownCoordinator>>,
) {
    let cleanup_pool = pool;
    let cleanup_interval = config.cleanup_interval;
    let cleanup_shutdown = shutdown.clone();
    let cleanup_metrics = runtime_context.metrics.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = sleep(cleanup_interval) => {
                    let cleaned = cleanup_pool.cleanup_idle_connections().await;
                    if cleaned > 0 {
                        info!("Cleaned up {} idle FSM connections", cleaned);
                        if let Some(metrics) = cleanup_metrics.as_ref() {
                            for _ in 0..cleaned {
                                metrics.record_resource_event(ResourceEventType::IdleConnectionEvicted);
                            }
                        }
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
                    info!("FSM cleanup task shutting down");
                    break;
                }
            }
        }
    });

    if let Some(limiter) = rate_limiter {
        let cleanup_shutdown = shutdown;
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = sleep(Duration::from_secs(60)) => {
                        limiter.cleanup_expired_bans().await;
                    }
                    _ = async {
                        if let Some(ref sd) = cleanup_shutdown {
                            let mut rx = sd.subscribe();
                            let _ = rx.recv().await;
                        } else {
                            std::future::pending::<()>().await;
                        }
                    } => {
                        info!("FSM rate limiter cleanup task shutting down");
                        break;
                    }
                }
            }
        });
    }
}

/// Send connection rejected response.
async fn send_connection_rejected(mut socket: TcpStream) -> Result<(), std::io::Error> {
    use crate::parser::encode_result_response;

    let response = encode_result_response(
        0,
        ResponseOp::SearchDone,
        ResultCode::Unavailable,
        "",
        "Server resource limits exceeded",
    )
    .map_err(|e| std::io::Error::other(format!("{:?}", e)))?;

    socket.write_all(&response).await?;
    socket.shutdown().await?;
    Ok(())
}

/// Send shutdown in progress response.
async fn send_shutdown_in_progress(mut socket: TcpStream) -> Result<(), std::io::Error> {
    use crate::parser::encode_result_response;

    let response = encode_result_response(
        0,
        ResponseOp::SearchDone,
        ResultCode::Unavailable,
        "",
        "Server is shutting down",
    )
    .map_err(|e| std::io::Error::other(format!("{:?}", e)))?;

    socket.write_all(&response).await?;
    socket.shutdown().await?;
    Ok(())
}

/// Compatibility wrapper used by the unit tests.
#[cfg_attr(not(test), allow(dead_code))]
async fn handle_connection(
    socket: TcpStream,
    backend: Arc<dyn DirectoryBackend>,
    config: FsmServerConfig,
    pool: Arc<ConnectionPool>,
    conn_id: u64,
    _shutdown: Option<Arc<ShutdownCoordinator>>,
    rate_limiter: Option<Arc<RateLimiter>>,
) -> Result<(), ServerError> {
    let client_ip = socket.peer_addr().ok().map(|addr| addr.ip());
    handle_connection_with_transport(
        ConnectionTransport::plain(socket),
        backend,
        config,
        FsmServerRuntimeContext::default(),
        pool,
        conn_id,
        client_ip,
        rate_limiter,
    )
    .await
}

async fn handle_connection_with_transport(
    transport: ConnectionTransport,
    backend: Arc<dyn DirectoryBackend>,
    config: FsmServerConfig,
    runtime_context: FsmServerRuntimeContext,
    pool: Arc<ConnectionPool>,
    conn_id: u64,
    client_ip: Option<IpAddr>,
    rate_limiter: Option<Arc<RateLimiter>>,
) -> Result<(), ServerError> {
    let mut fsm_set = ConnectionFsmSet::new_with_transport(
        transport,
        backend.clone(),
        runtime_context.boxed_tls_handler(),
    );
    let schema = LdapSchema::with_core_schema();
    let request_context = runtime_context.request_context(client_ip, conn_id);
    let mut legacy_operation_registry = ConnectionOperationRegistry::default();
    let mut read_buffer = vec![0u8; config.read_buffer_size];
    let cleanup_interval = config.cleanup_interval;
    let operation_timeout = config.operation_timeout;

    loop {
        if fsm_set.is_terminal() {
            debug!("Connection FSM reached terminal state");
            break;
        }

        let timed_out = fsm_set.cleanup_timed_out_operations(operation_timeout);
        if timed_out > 0 {
            warn!("Cleaned up {} timed-out operations", timed_out);
        }

        let terminal = fsm_set.cleanup_terminal_operations();
        if terminal > 0 {
            debug!("Cleaned up {} completed operations", terminal);
        }

        let stream = fsm_set.connection_mut().stream_mut().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotConnected, "No active stream")
        })?;
        let read_result =
            tokio::time::timeout(cleanup_interval, stream.read(&mut read_buffer)).await;

        match read_result {
            Ok(Ok(0)) => {
                debug!("Client closed connection");
                break;
            }
            Ok(Ok(n)) => {
                let data = &read_buffer[..n];
                debug!("Received {} bytes", n);

                pool.update_activity(conn_id).await;
                if !pool.update_memory_usage(conn_id, data.len() as isize).await {
                    record_resource_event(&runtime_context, ResourceEventType::MemoryRejected);
                    send_transport_unavailable(&mut fsm_set, "Server resource limits exceeded")
                        .await
                        .map_err(std::io::Error::other)?;
                    return Err(
                        std::io::Error::other("FSM connection exceeded memory limits").into(),
                    );
                }

                let decoded_messages =
                    match decode_ready_messages(&mut fsm_set, data.to_vec()).await {
                        Ok(messages) => messages,
                        Err(err) => {
                            pool.update_memory_usage(conn_id, -(data.len() as isize))
                                .await;
                            return Err(std::io::Error::other(err).into());
                        }
                    };

                pool.update_memory_usage(conn_id, -(data.len() as isize))
                    .await;

                for message_bytes in decoded_messages {
                    let parsed_messages = parse_ldap_messages(&message_bytes)
                        .map(|(_, messages)| messages)
                        .map_err(|err| std::io::Error::other(format!("{:?}", err)))?;

                    for message in parsed_messages {
                        let operation_type = metrics_operation_for_protocol(&message.protocol_op);
                        let started_at = Instant::now();
                        if let Some(metrics) = runtime_context.metrics.as_ref() {
                            if let Some(operation_type) = operation_type {
                                metrics.record_operation_start(operation_type, "");
                            }
                        }

                        let result = process_ldap_message(
                            &mut fsm_set,
                            message,
                            &runtime_context,
                            &pool,
                            &schema,
                            &request_context,
                            &mut legacy_operation_registry,
                            conn_id,
                            &rate_limiter,
                            client_ip,
                        )
                        .await;

                        if let Some(metrics) = runtime_context.metrics.as_ref() {
                            if let Some(operation_type) = operation_type {
                                metrics.record_operation_complete(
                                    operation_type,
                                    started_at.elapsed(),
                                    result.is_ok(),
                                );
                            }
                        }

                        if let Err(err) = result {
                            return Err(std::io::Error::other(err).into());
                        }
                    }
                }
            }
            Ok(Err(err)) => return Err(err.into()),
            Err(_) => continue,
        }
    }

    Ok(())
}

async fn decode_ready_messages(
    fsm_set: &mut ConnectionFsmSet,
    initial_data: Vec<u8>,
) -> Result<Vec<Vec<u8>>, String> {
    let mut messages = Vec::new();
    let mut next_chunk = Some(initial_data);

    loop {
        let decoder_event = BerDecoderEvent::DataReceived(next_chunk.take().unwrap_or_default());
        match fsm_set.decoder_mut().handle_event(decoder_event).await {
            Ok(Some(message)) => messages.push(message),
            Ok(None) => return Ok(messages),
            Err(err) => return Err(err.to_string()),
        }
    }
}

async fn process_ldap_message(
    fsm_set: &mut ConnectionFsmSet,
    message: LdapMessage<'_>,
    runtime_context: &FsmServerRuntimeContext,
    pool: &Arc<ConnectionPool>,
    schema: &LdapSchema,
    request_context: &RequestContext,
    legacy_operation_registry: &mut ConnectionOperationRegistry,
    conn_id: u64,
    rate_limiter: &Option<Arc<RateLimiter>>,
    client_ip: Option<IpAddr>,
) -> Result<(), String> {
    let request = match fsm_set.build_request_context(conn_id, client_ip, &message) {
        Ok(request) => request,
        Err(rejection) => {
            send_request_rejection_response(fsm_set, message.message_id.0, &rejection).await?;
            return Ok(());
        }
    };
    let request_controls = extract_request_controls(&message)?;

    debug!(
        "Processing LDAP message ID {} type {:?}",
        request.message_id, message.protocol_op
    );

    if let (Some(limiter), Some(ip)) = (rate_limiter, client_ip) {
        if !limiter.check_rate_limit(ip, request.operation_name()).await {
            warn!(
                "Rate limit exceeded for {} from {}",
                request.operation_name(),
                ip
            );
            record_resource_event(runtime_context, ResourceEventType::RateLimitBlocked);
            return send_rate_limit_exceeded(fsm_set, &request).await;
        }
        record_resource_event(runtime_context, ResourceEventType::RateLimitAllowed);
    }

    match message.protocol_op {
        ProtocolOp::BindRequest(bind_req) => {
            handle_bind_with_fsm(
                fsm_set,
                request.message_id,
                bind_req,
                request_context,
                runtime_context.metrics.as_deref(),
            )
            .await?;
        }
        ProtocolOp::UnbindRequest => {
            info!("Received unbind request");
            legacy_operation_registry.clear_paged_searches();
            if let Err(err) = fsm_set
                .connection_mut()
                .handle_event(ConnectionEvent::Close)
                .await
            {
                warn!("Error closing connection: {}", err);
            }
        }
        ProtocolOp::SearchRequest(search_req) => {
            if !pool.start_operation(conn_id).await {
                warn!("Search operation rejected due to operation limit");
                record_resource_event(runtime_context, ResourceEventType::OperationRejected);
                send_busy_response(fsm_set, &request).await?;
                return Ok(());
            }

            let session = legacy_session_from_fsm(fsm_set);
            let connection_is_secure = fsm_set.connection().is_secure();
            let backend = fsm_set.backend().clone();
            let result = {
                let stream = fsm_set
                    .connection_mut()
                    .stream_mut()
                    .ok_or("No active stream")?;
                handle_search_request_with_context_and_registry(
                    stream,
                    backend.as_ref(),
                    schema,
                    &runtime_context.legacy_runtime_config,
                    request.message_id as u32,
                    search_req,
                    &session,
                    legacy_operation_registry,
                    request_context,
                    &request_controls,
                    connection_is_secure,
                    runtime_context.tls_handler.is_some(),
                )
                .await
                .map_err(|err| err.to_string())
            };
            pool.end_operation(conn_id).await;
            result?;
        }
        ProtocolOp::ModifyRequest(modify_req) => {
            if !pool.start_operation(conn_id).await {
                warn!("Modify operation rejected due to operation limit");
                record_resource_event(runtime_context, ResourceEventType::OperationRejected);
                send_busy_response(fsm_set, &request).await?;
                return Ok(());
            }

            if !fsm_set.is_authenticated() {
                pool.end_operation(conn_id).await;
                send_request_result_response(
                    fsm_set,
                    request.message_id as u32,
                    request.response_kind,
                    ResultCode::InsufficientAccessRights,
                    "authentication required for modify operations",
                )
                .await?;
                return Ok(());
            }

            let session = legacy_session_from_fsm(fsm_set);
            let backend = fsm_set.backend().clone();
            let result = {
                let stream = fsm_set
                    .connection_mut()
                    .stream_mut()
                    .ok_or("No active stream")?;
                handle_modify_request_with_context(
                    stream,
                    backend.as_ref(),
                    request.message_id as u32,
                    modify_req,
                    &session,
                    request_context,
                    &request_controls,
                )
                .await
                .map_err(|err| err.to_string())
            };
            pool.end_operation(conn_id).await;
            result?;
        }
        ProtocolOp::AddRequest(add_req) => {
            if !pool.start_operation(conn_id).await {
                warn!("Add operation rejected due to operation limit");
                record_resource_event(runtime_context, ResourceEventType::OperationRejected);
                send_busy_response(fsm_set, &request).await?;
                return Ok(());
            }

            if !fsm_set.is_authenticated() {
                pool.end_operation(conn_id).await;
                send_request_result_response(
                    fsm_set,
                    request.message_id as u32,
                    request.response_kind,
                    ResultCode::InsufficientAccessRights,
                    "authentication required for add operations",
                )
                .await?;
                return Ok(());
            }

            let session = legacy_session_from_fsm(fsm_set);
            let backend = fsm_set.backend().clone();
            let result = {
                let stream = fsm_set
                    .connection_mut()
                    .stream_mut()
                    .ok_or("No active stream")?;
                handle_add_request_with_context(
                    stream,
                    backend.as_ref(),
                    schema,
                    request.message_id as u32,
                    add_req,
                    &session,
                    request_context,
                    &request_controls,
                )
                .await
                .map_err(|err| err.to_string())
            };
            pool.end_operation(conn_id).await;
            result?;
        }
        ProtocolOp::DelRequest(delete_req) => {
            if !pool.start_operation(conn_id).await {
                warn!("Delete operation rejected due to operation limit");
                record_resource_event(runtime_context, ResourceEventType::OperationRejected);
                send_busy_response(fsm_set, &request).await?;
                return Ok(());
            }

            if !fsm_set.is_authenticated() {
                pool.end_operation(conn_id).await;
                send_request_result_response(
                    fsm_set,
                    request.message_id as u32,
                    request.response_kind,
                    ResultCode::InsufficientAccessRights,
                    "authentication required for delete operations",
                )
                .await?;
                return Ok(());
            }

            let session = legacy_session_from_fsm(fsm_set);
            let backend = fsm_set.backend().clone();
            let result = {
                let stream = fsm_set
                    .connection_mut()
                    .stream_mut()
                    .ok_or("No active stream")?;
                handle_delete_request_with_context(
                    stream,
                    backend.as_ref(),
                    request.message_id as u32,
                    delete_req,
                    &session,
                    request_context,
                    &request_controls,
                )
                .await
                .map_err(|err| err.to_string())
            };
            pool.end_operation(conn_id).await;
            result?;
        }
        ProtocolOp::ModDnRequest(rename_req) => {
            if !pool.start_operation(conn_id).await {
                warn!("ModifyDN operation rejected due to operation limit");
                record_resource_event(runtime_context, ResourceEventType::OperationRejected);
                send_busy_response(fsm_set, &request).await?;
                return Ok(());
            }

            if !fsm_set.is_authenticated() {
                pool.end_operation(conn_id).await;
                send_request_result_response(
                    fsm_set,
                    request.message_id as u32,
                    request.response_kind,
                    ResultCode::InsufficientAccessRights,
                    "authentication required for modifydn operations",
                )
                .await?;
                return Ok(());
            }

            let session = legacy_session_from_fsm(fsm_set);
            let backend = fsm_set.backend().clone();
            let result = {
                let stream = fsm_set
                    .connection_mut()
                    .stream_mut()
                    .ok_or("No active stream")?;
                handle_moddn_request_with_context(
                    stream,
                    backend.as_ref(),
                    request.message_id as u32,
                    rename_req,
                    &session,
                    request_context,
                    &request_controls,
                )
                .await
                .map_err(|err| err.to_string())
            };
            pool.end_operation(conn_id).await;
            result?;
        }
        ProtocolOp::CompareRequest(compare_req) => {
            if !pool.start_operation(conn_id).await {
                warn!("Compare operation rejected due to operation limit");
                record_resource_event(runtime_context, ResourceEventType::OperationRejected);
                send_busy_response(fsm_set, &request).await?;
                return Ok(());
            }

            let session = legacy_session_from_fsm(fsm_set);
            let backend = fsm_set.backend().clone();
            let result = {
                let stream = fsm_set
                    .connection_mut()
                    .stream_mut()
                    .ok_or("No active stream")?;
                handle_compare_request_with_context(
                    stream,
                    backend.as_ref(),
                    request.message_id as u32,
                    compare_req,
                    &session,
                    request_context,
                    &request_controls,
                )
                .await
                .map_err(|err| err.to_string())
            };
            pool.end_operation(conn_id).await;
            result?;
        }
        ProtocolOp::AbandonRequest(abandoned_id) => {
            info!("Abandon request for message ID {}", abandoned_id.0);
            let _ = legacy_operation_registry.request_abandon(abandoned_id.0 as u32);
        }
        ProtocolOp::ExtendedRequest(extended_req) => {
            if !pool.start_operation(conn_id).await {
                warn!("Extended operation rejected due to operation limit");
                record_resource_event(runtime_context, ResourceEventType::OperationRejected);
                send_busy_response(fsm_set, &request).await?;
                return Ok(());
            }

            let backend = fsm_set.backend().clone();
            let result = handle_extended_request_with_fsm_runtime(
                fsm_set,
                request.message_id as u32,
                &extended_req,
                backend.as_ref(),
                legacy_operation_registry,
                runtime_context.tls_handler.as_deref(),
                request_context,
                runtime_context.metrics.as_deref(),
            )
            .await;
            pool.end_operation(conn_id).await;
            result?;
        }
        _ => {
            warn!("Unsupported operation: {:?}", message.protocol_op);
        }
    }

    Ok(())
}

fn legacy_session_from_fsm(fsm_set: &ConnectionFsmSet) -> ConnectionSession {
    let mut session = ConnectionSession::default();
    if let Some(bound_dn) = fsm_set.authenticated_dn() {
        session.bind(bound_dn.to_string());
    }
    session
}

fn extract_request_controls(message: &LdapMessage<'_>) -> Result<RequestControls, String> {
    active_fsm_control_registry()
        .validate_request_controls(message.controls.as_deref())
        .map(|validated| validated.into_accepted())
        .map_err(|err| err.to_string())
}

fn map_backend_error_code(err: &crate::backend::BackendError) -> ResultCode {
    match err {
        crate::backend::BackendError::AlreadyExists => ResultCode::EntryAlreadyExists,
        crate::backend::BackendError::NotFound => ResultCode::NoSuchObject,
        crate::backend::BackendError::Storage(_) => ResultCode::Unavailable,
    }
}

fn backend_diagnostic(err: &crate::backend::BackendError) -> &'static str {
    match err {
        crate::backend::BackendError::AlreadyExists => "entry already exists",
        crate::backend::BackendError::NotFound => "no such object",
        crate::backend::BackendError::Storage(_) => "backend failure",
    }
}

async fn send_extended_response_value(
    fsm_set: &mut ConnectionFsmSet,
    message_id: u32,
    result_code: ResultCode,
    response_name: Option<String>,
    response_value: Option<Vec<u8>>,
    diagnostic: &str,
) -> Result<(), String> {
    let encoded = encode_extended_response(
        message_id,
        result_code,
        "",
        diagnostic,
        response_name,
        response_value,
    )
    .map_err(|e| format!("Encode error: {:?}", e))?;

    let stream = fsm_set
        .connection_mut()
        .stream_mut()
        .ok_or("No active stream")?;
    stream
        .write_all(&encoded)
        .await
        .map_err(|e| format!("Write error: {}", e))?;
    Ok(())
}

async fn send_custom_extended_response_value(
    fsm_set: &mut ConnectionFsmSet,
    message_id: u32,
    result_code: crate::parser::CustomResultCode,
    diagnostic: &str,
) -> Result<(), String> {
    let encoded = encode_custom_extended_response(message_id, result_code, "", diagnostic)
        .map_err(|e| format!("Encode error: {:?}", e))?;

    let stream = fsm_set
        .connection_mut()
        .stream_mut()
        .ok_or("No active stream")?;
    stream
        .write_all(&encoded)
        .await
        .map_err(|e| format!("Write error: {}", e))?;
    Ok(())
}

async fn handle_extended_request_with_fsm_runtime(
    fsm_set: &mut ConnectionFsmSet,
    message_id: u32,
    request: &ldap_parser::ldap::ExtendedRequest<'_>,
    backend: &dyn DirectoryBackend,
    legacy_operation_registry: &mut ConnectionOperationRegistry,
    tls_handler: Option<&RustlsTlsHandler>,
    request_context: &RequestContext,
    metrics: Option<&MetricsCollector>,
) -> Result<(), String> {
    let oid = request.request_name.0.as_ref();
    let mut session = legacy_session_from_fsm(fsm_set);

    if oid == oids::WHO_AM_I {
        let authz_id = fsm_set
            .authenticated_dn()
            .map(|dn| format!("dn:{dn}"))
            .unwrap_or_default();
        return send_extended_response_value(
            fsm_set,
            message_id,
            ResultCode::Success,
            Some(oids::WHO_AM_I.to_string()),
            Some(authz_id.into_bytes()),
            "",
        )
        .await;
    }

    if oid == oids::START_TLS {
        if fsm_set.connection().is_secure() {
            log_generic_audit_event(
                request_context,
                &session,
                AuditLevel::Warning,
                AuditEventType::System,
                "starttls",
                false,
                None,
                Some("connection already uses TLS"),
                Vec::new(),
            )
            .await;
            return send_request_result_response(
                fsm_set,
                message_id,
                FsmResponseKind::Result(ResponseOp::Extended),
                ResultCode::OperationsError,
                "connection already uses TLS",
            )
            .await;
        }

        if tls_handler.is_none() {
            log_generic_audit_event(
                request_context,
                &session,
                AuditLevel::Warning,
                AuditEventType::System,
                "starttls",
                false,
                None,
                Some("StartTLS is not available"),
                Vec::new(),
            )
            .await;
            return send_request_result_response(
                fsm_set,
                message_id,
                FsmResponseKind::Result(ResponseOp::Extended),
                ResultCode::Unavailable,
                "StartTLS is not available",
            )
            .await;
        }

        send_request_result_response(
            fsm_set,
            message_id,
            FsmResponseKind::Result(ResponseOp::Extended),
            ResultCode::Success,
            "",
        )
        .await?;

        fsm_set
            .connection_mut()
            .handle_event(ConnectionEvent::StartTlsRequest)
            .await
            .map_err(|err| err.to_string())?;
        reset_auth_state(fsm_set).await?;
        legacy_operation_registry.clear_paged_searches();
        session.clear();
        if let Some(metrics) = metrics {
            metrics.record_fsm_state(FsmType::Connection, "secure");
            metrics.record_fsm_state(FsmType::Auth, "anonymous");
        }
        log_generic_audit_event(
            request_context,
            &session,
            AuditLevel::Info,
            AuditEventType::System,
            "starttls",
            true,
            None,
            None,
            Vec::new(),
        )
        .await;
        return Ok(());
    }

    if oid == oids::CANCEL {
        let cancel_id = match parse_cancel_request_value(request.request_value.as_deref()) {
            Ok(cancel_id) => cancel_id as u32,
            Err(err) => {
                return send_custom_extended_response_value(
                    fsm_set,
                    message_id,
                    crate::parser::CustomResultCode::ProtocolError,
                    &err.to_string(),
                )
                .await;
            }
        };

        let (result_code, diagnostic) = match legacy_operation_registry.request_cancel(cancel_id) {
            CancelRequestOutcome::Accepted => {
                (crate::parser::CustomResultCode::Success, String::new())
            }
            CancelRequestOutcome::NoSuchOperation => (
                crate::parser::CustomResultCode::NoSuchOperation,
                "no such operation".to_string(),
            ),
            CancelRequestOutcome::TooLate => (
                crate::parser::CustomResultCode::TooLate,
                "too late to cancel operation".to_string(),
            ),
            CancelRequestOutcome::CannotCancel => (
                crate::parser::CustomResultCode::CannotCancel,
                "operation cannot be canceled".to_string(),
            ),
        };

        return send_custom_extended_response_value(fsm_set, message_id, result_code, &diagnostic)
            .await;
    }

    if oid == oids::PASSWORD_MODIFY {
        if !fsm_set.connection().is_secure() {
            audit_password_modify_failure(
                request_context,
                &session,
                "Password Modify requires confidentiality protection",
                None,
                "self-service",
                false,
            )
            .await;
            return send_request_result_response(
                fsm_set,
                message_id,
                FsmResponseKind::Result(ResponseOp::Extended),
                ResultCode::ConfidentialityRequired,
                "Password Modify requires confidentiality protection",
            )
            .await;
        }

        let Some(bound_dn) = fsm_set.authenticated_dn().map(str::to_string) else {
            audit_password_modify_failure(
                request_context,
                &session,
                "Password Modify requires an authenticated session",
                None,
                "self-service",
                false,
            )
            .await;
            return send_request_result_response(
                fsm_set,
                message_id,
                FsmResponseKind::Result(ResponseOp::Extended),
                ResultCode::UnwillingToPerform,
                "Password Modify requires an authenticated session",
            )
            .await;
        };

        let request_value =
            match parse_password_modify_request_value(request.request_value.as_deref()) {
                Ok(request_value) => request_value,
                Err(err) => {
                    let err_string = err.to_string();
                    log_password_modify_audit_event(
                        request_context,
                        &session,
                        None,
                        "self-service",
                        false,
                        false,
                        Some(&err_string),
                    )
                    .await;
                    return send_request_result_response(
                        fsm_set,
                        message_id,
                        FsmResponseKind::Result(ResponseOp::Extended),
                        ResultCode::ProtocolError,
                        &err_string,
                    )
                    .await;
                }
            };

        let target_dn = request_value
            .user_identity
            .clone()
            .unwrap_or_else(|| bound_dn.clone());
        let mode = if request_value.user_identity.is_some() {
            "password-reset"
        } else {
            "self-service"
        };

        if !target_dn.eq_ignore_ascii_case(&bound_dn) {
            audit_password_modify_failure(
                request_context,
                &session,
                "password resets require explicit authorization",
                Some(&target_dn),
                mode,
                false,
            )
            .await;
            return send_request_result_response(
                fsm_set,
                message_id,
                FsmResponseKind::Result(ResponseOp::Extended),
                ResultCode::InsufficientAccessRights,
                "password resets require explicit authorization",
            )
            .await;
        }

        let Some(old_password) = request_value.old_password.as_deref() else {
            audit_password_modify_failure(
                request_context,
                &session,
                "Self-service password changes require oldPasswd",
                Some(&target_dn),
                mode,
                false,
            )
            .await;
            return send_request_result_response(
                fsm_set,
                message_id,
                FsmResponseKind::Result(ResponseOp::Extended),
                ResultCode::UnwillingToPerform,
                "Self-service password changes require oldPasswd",
            )
            .await;
        };

        match backend.authenticate(&target_dn, old_password).await {
            Ok(true) => {}
            Ok(false) => {
                audit_password_modify_failure(
                    request_context,
                    &session,
                    "invalid credentials",
                    Some(&target_dn),
                    mode,
                    false,
                )
                .await;
                return send_request_result_response(
                    fsm_set,
                    message_id,
                    FsmResponseKind::Result(ResponseOp::Extended),
                    ResultCode::InvalidCredentials,
                    "invalid credentials",
                )
                .await;
            }
            Err(err) => {
                let diagnostic = backend_diagnostic(&err);
                audit_password_modify_failure(
                    request_context,
                    &session,
                    diagnostic,
                    Some(&target_dn),
                    mode,
                    false,
                )
                .await;
                return send_request_result_response(
                    fsm_set,
                    message_id,
                    FsmResponseKind::Result(ResponseOp::Extended),
                    map_backend_error_code(&err),
                    diagnostic,
                )
                .await;
            }
        }

        let (new_password, generated_password) = match request_value.new_password {
            Some(new_password) => (new_password, false),
            None => (
                Alphanumeric
                    .sample_string(&mut rand::thread_rng(), 24)
                    .into_bytes(),
                true,
            ),
        };
        let new_password_string = match String::from_utf8(new_password.clone()) {
            Ok(password) => password,
            Err(_) => {
                audit_password_modify_failure(
                    request_context,
                    &session,
                    "newPasswd must be valid UTF-8",
                    Some(&target_dn),
                    mode,
                    generated_password,
                )
                .await;
                return send_request_result_response(
                    fsm_set,
                    message_id,
                    FsmResponseKind::Result(ResponseOp::Extended),
                    ResultCode::ProtocolError,
                    "newPasswd must be valid UTF-8",
                )
                .await;
            }
        };

        match backend
            .modify_entry_with_actor(
                &target_dn,
                vec![crate::backend::Modification {
                    operation: crate::backend::ModifyOperation::Replace,
                    attribute: "userPassword".to_string(),
                    values: vec![new_password_string],
                }],
                Some(bound_dn),
            )
            .await
        {
            Ok(()) => {}
            Err(err) => {
                let diagnostic = backend_diagnostic(&err);
                audit_password_modify_failure(
                    request_context,
                    &session,
                    diagnostic,
                    Some(&target_dn),
                    mode,
                    generated_password,
                )
                .await;
                return send_request_result_response(
                    fsm_set,
                    message_id,
                    FsmResponseKind::Result(ResponseOp::Extended),
                    map_backend_error_code(&err),
                    diagnostic,
                )
                .await;
            }
        }

        let response_value = encode_password_modify_response_value(
            generated_password.then_some(new_password.as_slice()),
        )
        .map_err(|err| err.to_string())?;

        log_password_modify_audit_event(
            request_context,
            &session,
            Some(&target_dn),
            mode,
            generated_password,
            true,
            None,
        )
        .await;

        return send_extended_response_value(
            fsm_set,
            message_id,
            ResultCode::Success,
            None,
            response_value,
            "",
        )
        .await;
    }

    send_request_result_response(
        fsm_set,
        message_id,
        FsmResponseKind::Result(ResponseOp::Extended),
        ResultCode::ProtocolError,
        "extended operations are not supported",
    )
    .await
}

async fn audit_password_modify_failure(
    request_context: &RequestContext,
    session: &ConnectionSession,
    message: &str,
    target_dn: Option<&str>,
    mode: &str,
    generated_password: bool,
) {
    log_password_modify_audit_event(
        request_context,
        session,
        target_dn,
        mode,
        generated_password,
        false,
        Some(message),
    )
    .await;
}

async fn handle_bind_with_fsm(
    fsm_set: &mut ConnectionFsmSet,
    message_id: i32,
    bind_req: ldap_parser::ldap::BindRequest<'_>,
    request_context: &RequestContext,
    metrics: Option<&MetricsCollector>,
) -> Result<(), String> {
    use crate::fsm::{AuthEvent, StateMachine};
    use ldap_parser::ldap::AuthenticationChoice;

    if bind_req.version != 3 {
        send_bind_error(fsm_set, message_id as u32, "unsupported LDAP version").await?;
        return Ok(());
    }

    match bind_req.authentication {
        AuthenticationChoice::Simple(password) => {
            let dn = bind_req.name.0.as_ref().trim().to_owned();
            let is_anonymous_bind = dn.is_empty() && password.as_ref().is_empty();
            let auth_event = AuthEvent::BindRequest {
                dn: dn.clone(),
                password: password.as_ref().to_vec(),
            };

            match fsm_set.auth_mut() {
                AuthenticationFsm::Simple(auth_fsm) => {
                    match auth_fsm.handle_event(auth_event).await {
                        Ok(_) => {
                            if is_anonymous_bind {
                                if let Some(metrics) = metrics {
                                    metrics.record_fsm_state(FsmType::Auth, "anonymous");
                                }
                                log_anonymous_bind(request_context).await;
                                send_bind_success(fsm_set, message_id as u32).await?;
                            } else if fsm_set.is_authenticated() {
                                if let Some(metrics) = metrics {
                                    metrics.record_fsm_state(FsmType::Auth, "simple_bound");
                                }
                                if let Some(bound_dn) = fsm_set.authenticated_dn() {
                                    log_simple_bind_success(request_context, bound_dn).await;
                                }
                                send_bind_success(fsm_set, message_id as u32).await?;
                            } else {
                                if let Some(metrics) = metrics {
                                    metrics.record_fsm_state(FsmType::Auth, "anonymous");
                                }
                                log_simple_bind_failure(
                                    request_context,
                                    &dn,
                                    "invalid credentials",
                                )
                                .await;
                                send_bind_error(fsm_set, message_id as u32, "invalid credentials")
                                    .await?;
                            }
                        }
                        Err(err) => {
                            error!("Auth FSM error: {}", err);
                            if let Some(metrics) = metrics {
                                metrics.record_fsm_state(FsmType::Auth, "authentication_failed");
                            }
                            log_simple_bind_failure(request_context, &dn, &err.to_string()).await;
                            send_bind_error(fsm_set, message_id as u32, "authentication failed")
                                .await?;
                        }
                    }
                }
                AuthenticationFsm::Sasl(_) => {
                    if let Some(metrics) = metrics {
                        metrics.record_fsm_state(FsmType::Auth, "sasl_not_configured");
                    }
                    send_bind_error(fsm_set, message_id as u32, "SASL not configured").await?;
                }
            }
        }
        AuthenticationChoice::Sasl(_) => {
            if let Some(metrics) = metrics {
                metrics.record_fsm_state(FsmType::Auth, "sasl_not_supported");
            }
            send_bind_error(fsm_set, message_id as u32, "SASL not supported").await?;
        }
    }

    Ok(())
}

async fn reset_auth_state(fsm_set: &mut ConnectionFsmSet) -> Result<(), String> {
    match fsm_set.auth_mut() {
        AuthenticationFsm::Simple(auth_fsm) => {
            auth_fsm.reset().await.map_err(|err| err.to_string())
        }
        AuthenticationFsm::Sasl(sasl_fsm) => sasl_fsm.reset().await.map_err(|err| err.to_string()),
    }
}

async fn send_bind_success(fsm_set: &mut ConnectionFsmSet, message_id: u32) -> Result<(), String> {
    use crate::parser::encode_bind_response;

    let response = encode_bind_response(message_id, ResultCode::Success, "", "")
        .map_err(|e| format!("Encode error: {:?}", e))?;

    let stream = fsm_set
        .connection_mut()
        .stream_mut()
        .ok_or("No active stream")?;
    stream
        .write_all(&response)
        .await
        .map_err(|e| format!("Write error: {}", e))?;
    Ok(())
}

async fn send_bind_error(
    fsm_set: &mut ConnectionFsmSet,
    message_id: u32,
    diagnostic: &str,
) -> Result<(), String> {
    use crate::parser::encode_bind_response;

    let response = encode_bind_response(message_id, ResultCode::InvalidCredentials, "", diagnostic)
        .map_err(|e| format!("Encode error: {:?}", e))?;

    let stream = fsm_set
        .connection_mut()
        .stream_mut()
        .ok_or("No active stream")?;
    stream
        .write_all(&response)
        .await
        .map_err(|e| format!("Write error: {}", e))?;
    Ok(())
}

async fn send_busy_response(
    fsm_set: &mut ConnectionFsmSet,
    request: &FsmRequestContext,
) -> Result<(), String> {
    send_request_result_response(
        fsm_set,
        request.message_id as u32,
        request.response_kind,
        ResultCode::Busy,
        "Server is busy - operation limit exceeded",
    )
    .await
}

async fn send_rate_limit_exceeded(
    fsm_set: &mut ConnectionFsmSet,
    request: &FsmRequestContext,
) -> Result<(), String> {
    send_request_result_response(
        fsm_set,
        request.message_id as u32,
        request.response_kind,
        ResultCode::Busy,
        "Rate limit exceeded - please slow down",
    )
    .await
}

async fn send_request_rejection_response(
    fsm_set: &mut ConnectionFsmSet,
    message_id: u32,
    rejection: &FsmRequestRejection,
) -> Result<(), String> {
    send_request_result_response(
        fsm_set,
        message_id,
        rejection.response_kind,
        rejection.result_code,
        &rejection.diagnostic_message,
    )
    .await
}

async fn send_request_result_response(
    fsm_set: &mut ConnectionFsmSet,
    message_id: u32,
    response_kind: FsmResponseKind,
    result_code: ResultCode,
    diagnostic: &str,
) -> Result<(), String> {
    use crate::parser::{encode_bind_response, encode_result_response};

    let response = match response_kind {
        FsmResponseKind::Bind => encode_bind_response(message_id, result_code, "", diagnostic)
            .map_err(|e| format!("Encode error: {:?}", e))?,
        FsmResponseKind::Result(op) => {
            encode_result_response(message_id, op, result_code, "", diagnostic)
                .map_err(|e| format!("Encode error: {:?}", e))?
        }
        FsmResponseKind::None => return Ok(()),
    };

    let stream = fsm_set
        .connection_mut()
        .stream_mut()
        .ok_or("No active stream")?;
    stream
        .write_all(&response)
        .await
        .map_err(|e| format!("Write error: {}", e))?;
    Ok(())
}

async fn send_transport_unavailable(
    fsm_set: &mut ConnectionFsmSet,
    diagnostic: &str,
) -> Result<(), String> {
    send_request_result_response(
        fsm_set,
        0,
        FsmResponseKind::Result(ResponseOp::SearchDone),
        ResultCode::Unavailable,
        diagnostic,
    )
    .await?;
    let _ = fsm_set
        .connection_mut()
        .handle_event(ConnectionEvent::Close)
        .await;
    Ok(())
}

fn metrics_operation_for_protocol(protocol_op: &ProtocolOp<'_>) -> Option<MetricsOperationType> {
    match protocol_op {
        ProtocolOp::BindRequest(_) => Some(MetricsOperationType::Bind),
        ProtocolOp::UnbindRequest => Some(MetricsOperationType::Unbind),
        ProtocolOp::SearchRequest(_) => Some(MetricsOperationType::Search),
        ProtocolOp::ModifyRequest(_) => Some(MetricsOperationType::Modify),
        ProtocolOp::AddRequest(_) => Some(MetricsOperationType::Add),
        ProtocolOp::DelRequest(_) => Some(MetricsOperationType::Delete),
        ProtocolOp::ModDnRequest(_) => Some(MetricsOperationType::ModifyDN),
        ProtocolOp::CompareRequest(_) => Some(MetricsOperationType::Compare),
        ProtocolOp::ExtendedRequest(_) => Some(MetricsOperationType::Extended),
        ProtocolOp::AbandonRequest(_) => Some(MetricsOperationType::Abandon),
        _ => None,
    }
}

fn record_connection_accepted(runtime_context: &FsmServerRuntimeContext, secure: bool) {
    if let Some(metrics) = runtime_context.metrics.as_ref() {
        metrics.record_connection_accepted();
        metrics.record_fsm_state(
            FsmType::Connection,
            if secure { "secure" } else { "connected" },
        );
    }
}

fn record_connection_closed(runtime_context: &FsmServerRuntimeContext) {
    if let Some(metrics) = runtime_context.metrics.as_ref() {
        metrics.record_connection_closed();
        metrics.record_fsm_state(FsmType::Connection, "closed");
    }
}

fn record_connection_failed(runtime_context: &FsmServerRuntimeContext) {
    if let Some(metrics) = runtime_context.metrics.as_ref() {
        metrics.record_connection_failed();
        metrics.record_fsm_state(FsmType::Connection, "error");
    }
}

fn record_resource_event(runtime_context: &FsmServerRuntimeContext, event: ResourceEventType) {
    if let Some(metrics) = runtime_context.metrics.as_ref() {
        metrics.record_resource_event(event);
    }
}

async fn audit_connection_accepted(
    runtime_context: &FsmServerRuntimeContext,
    client_ip: IpAddr,
    conn_id: u64,
) {
    let Some(security) = runtime_context.security.as_ref() else {
        return;
    };
    if !security.audit_config.log_connections {
        return;
    }
    let Some(audit) = security.audit_logger.as_ref() else {
        return;
    };
    audit
        .log_connection_accepted(&client_ip.to_string(), &conn_id.to_string())
        .await;
}

async fn audit_connection_closed(
    runtime_context: &FsmServerRuntimeContext,
    client_ip: IpAddr,
    conn_id: u64,
) {
    let Some(security) = runtime_context.security.as_ref() else {
        return;
    };
    if !security.audit_config.log_connections {
        return;
    }
    let Some(audit) = security.audit_logger.as_ref() else {
        return;
    };
    audit
        .log_connection_closed(&client_ip.to_string(), &conn_id.to_string())
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MockBackend;
    use crate::extended_ops::oids;
    use ldap_parser::ldap::{ProtocolOp, ResultCode as ParserResultCode};
    use ldap_parser::parse_ldap_messages;
    use rasn::der;
    use rasn_ldap::{
        Attribute, AuthenticationChoice as RasnAuthChoice, BindRequest as RasnBindRequest,
        Filter as RasnFilter, LdapMessage as RasnLdapMessage, ProtocolOp as RasnProtocolOp,
        SearchRequest as RasnSearchRequest, SearchRequestDerefAliases, SearchRequestScope,
    };
    use tokio::time::timeout;

    async fn connected_stream_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (server_stream, _) = listener.accept().await.unwrap();
        let client_stream = client.await.unwrap();

        (server_stream, client_stream)
    }

    fn encode_bind_request(message_id: u32) -> Vec<u8> {
        let bind_request = RasnBindRequest::new(
            3,
            b"cn=admin,dc=example,dc=org".to_vec().into(),
            RasnAuthChoice::Simple(b"secret".to_vec().into()),
        );
        let message = rasn_ldap::LdapMessage::new(
            message_id,
            rasn_ldap::ProtocolOp::BindRequest(bind_request),
        );
        der::encode(&message).unwrap()
    }

    fn encode_root_dse_search_request(message_id: u32) -> Vec<u8> {
        let search_request = RasnSearchRequest::new(
            b"".to_vec().into(),
            SearchRequestScope::BaseObject,
            SearchRequestDerefAliases::NeverDerefAliases,
            0,
            0,
            false,
            RasnFilter::Present(b"objectClass".to_vec().into()),
            vec![b"supportedLDAPVersion".to_vec().into()],
        );
        let message =
            RasnLdapMessage::new(message_id, RasnProtocolOp::SearchRequest(search_request));
        der::encode(&message).unwrap()
    }

    fn encode_add_request(message_id: u32) -> Vec<u8> {
        let attributes = vec![
            Attribute::new(
                b"objectClass".to_vec().into(),
                vec![b"person".to_vec().into()].into_iter().collect(),
            ),
            Attribute::new(
                b"cn".to_vec().into(),
                vec![b"alice".to_vec().into()].into_iter().collect(),
            ),
            Attribute::new(
                b"sn".to_vec().into(),
                vec![b"User".to_vec().into()].into_iter().collect(),
            ),
        ]
        .into_iter()
        .collect();
        let request = rasn_ldap::AddRequest {
            entry: b"cn=alice,dc=example,dc=org".to_vec().into(),
            attributes,
        };
        let message = RasnLdapMessage::new(message_id, RasnProtocolOp::AddRequest(request));
        der::encode(&message).unwrap()
    }

    fn encode_whoami_request(message_id: u32) -> Vec<u8> {
        let request = rasn_ldap::ExtendedRequest {
            request_name: oids::WHO_AM_I.as_bytes().to_vec().into(),
            request_value: None,
        };
        let message = RasnLdapMessage::new(message_id, RasnProtocolOp::ExtendedReq(request));
        der::encode(&message).unwrap()
    }

    async fn read_ldap_payload(stream: &mut TcpStream, expected_messages: usize) -> Vec<u8> {
        let mut buf = Vec::new();

        loop {
            let mut chunk = vec![0u8; 4096];
            let len = timeout(Duration::from_millis(200), stream.read(&mut chunk))
                .await
                .expect("response timeout")
                .expect("failed to read response");
            assert!(len > 0, "connection closed before receiving response");
            buf.extend_from_slice(&chunk[..len]);

            if let Ok((remaining, messages)) = parse_ldap_messages(&buf) {
                if remaining.is_empty() && messages.len() >= expected_messages {
                    return buf;
                }
            }
        }
    }

    async fn spawn_test_connection(
        backend: Arc<MockBackend>,
    ) -> (tokio::task::JoinHandle<()>, TcpStream) {
        let config = FsmServerConfig {
            cleanup_interval: Duration::from_millis(50),
            ..FsmServerConfig::default()
        };
        let pool = Arc::new(ConnectionPool::new(config.resource_limits.clone()));
        let (server_stream, client_stream) = connected_stream_pair().await;
        let conn_id = pool
            .acquire_connection(server_stream.peer_addr().unwrap())
            .await
            .unwrap();

        let server_task = tokio::spawn(async move {
            let _ = handle_connection(
                server_stream,
                backend,
                config,
                pool.clone(),
                conn_id,
                None,
                None,
            )
            .await;
            pool.release_connection(conn_id).await;
        });

        (server_task, client_stream)
    }

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

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (socket, client_addr) = listener.accept().await.unwrap();
            let backend = Arc::new(MockBackend::default());
            let config = FsmServerConfig::default();
            let pool = Arc::new(ConnectionPool::new(config.resource_limits.clone()));
            let conn_id = pool.acquire_connection(client_addr).await.unwrap();

            let _ =
                handle_connection(socket, backend, config, pool.clone(), conn_id, None, None).await;
            pool.release_connection(conn_id).await;
        });

        let _stream = TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn handle_connection_processes_single_ber_frame_from_single_read() {
        let backend = Arc::new(MockBackend::default());
        let (server_task, mut client_stream) = spawn_test_connection(backend).await;

        let encoded = encode_bind_request(1);
        client_stream.write_all(&encoded).await.unwrap();

        let response = read_ldap_payload(&mut client_stream, 1).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message_id.0, 1);
        match &messages[0].protocol_op {
            ProtocolOp::BindResponse(bind_response) => {
                assert_eq!(bind_response.result.result_code, ParserResultCode::Success);
            }
            other => panic!("unexpected response: {:?}", other),
        }

        client_stream.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handle_connection_processes_fragmented_ber_frame_once() {
        let backend = Arc::new(MockBackend::default());
        let (server_task, mut client_stream) = spawn_test_connection(backend).await;

        let encoded = encode_bind_request(7);
        let split_at = encoded.len() / 2;

        client_stream.write_all(&encoded[..split_at]).await.unwrap();
        client_stream.write_all(&encoded[split_at..]).await.unwrap();

        let response = read_ldap_payload(&mut client_stream, 1).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message_id.0, 7);
        match &messages[0].protocol_op {
            ProtocolOp::BindResponse(bind_response) => {
                assert_eq!(bind_response.result.result_code, ParserResultCode::Success);
            }
            other => panic!("unexpected response: {:?}", other),
        }

        client_stream.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handle_connection_processes_multiple_ber_frames_from_one_read() {
        let backend = Arc::new(MockBackend::default());
        let (server_task, mut client_stream) = spawn_test_connection(backend).await;

        let mut encoded = encode_bind_request(3);
        encoded.extend_from_slice(&encode_bind_request(4));
        client_stream.write_all(&encoded).await.unwrap();

        let response = read_ldap_payload(&mut client_stream, 2).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].message_id.0, 3);
        assert_eq!(messages[1].message_id.0, 4);

        for message in &messages {
            match &message.protocol_op {
                ProtocolOp::BindResponse(bind_response) => {
                    assert_eq!(bind_response.result.result_code, ParserResultCode::Success);
                }
                other => panic!("unexpected response: {:?}", other),
            }
        }

        client_stream.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handle_connection_processes_root_dse_search_request() {
        let backend = Arc::new(MockBackend::default());
        let (server_task, mut client_stream) = spawn_test_connection(backend).await;

        client_stream
            .write_all(&encode_root_dse_search_request(11))
            .await
            .unwrap();

        let response = read_ldap_payload(&mut client_stream, 2).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].message_id.0, 11);
        assert_eq!(messages[1].message_id.0, 11);
        assert!(matches!(
            messages[0].protocol_op,
            ProtocolOp::SearchResultEntry(_)
        ));
        match &messages[1].protocol_op {
            ProtocolOp::SearchResultDone(done) => {
                assert_eq!(done.result_code, ParserResultCode::Success);
            }
            other => panic!("unexpected response: {:?}", other),
        }

        client_stream.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handle_connection_rejects_unauthenticated_add_request() {
        let backend = Arc::new(MockBackend::default());
        let (server_task, mut client_stream) = spawn_test_connection(backend).await;

        client_stream
            .write_all(&encode_add_request(12))
            .await
            .unwrap();

        let response = read_ldap_payload(&mut client_stream, 1).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message_id.0, 12);
        match &messages[0].protocol_op {
            ProtocolOp::AddResponse(result) => {
                assert_eq!(
                    result.result_code,
                    ParserResultCode::InsufficientAccessRights
                );
            }
            other => panic!("unexpected response: {:?}", other),
        }

        client_stream.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handle_connection_whoami_returns_bound_dn() {
        let backend = Arc::new(MockBackend::default());
        let (server_task, mut client_stream) = spawn_test_connection(backend).await;

        client_stream
            .write_all(&encode_bind_request(21))
            .await
            .unwrap();
        let bind_response = read_ldap_payload(&mut client_stream, 1).await;
        let (_, bind_messages) = parse_ldap_messages(&bind_response).unwrap();
        assert_eq!(bind_messages.len(), 1);

        client_stream
            .write_all(&encode_whoami_request(22))
            .await
            .unwrap();
        let response = read_ldap_payload(&mut client_stream, 1).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message_id.0, 22);
        match &messages[0].protocol_op {
            ProtocolOp::ExtendedResponse(response) => {
                assert_eq!(response.result.result_code, ParserResultCode::Success);
                assert_eq!(
                    response.response_value.as_ref().unwrap().as_ref(),
                    b"dn:cn=admin,dc=example,dc=org"
                );
            }
            other => panic!("unexpected response: {:?}", other),
        }

        client_stream.shutdown().await.unwrap();
        server_task.await.unwrap();
    }
}

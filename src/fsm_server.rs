//! FSM-Based LDAP Server Implementation
//!
//! This module provides an LDAP server implementation using the FSM
//! (Finite State Machine) architecture. Unlike the traditional `server.rs`
//! listener, this module manages FSM instances for connection lifecycle,
//! BER decoding, authentication state, operation dispatch, LDAP controls,
//! and operation execution.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ldap_parser::filter::{Filter, Substring};
use ldap_parser::ldap::{LdapMessage, ProtocolOp};
use ldap_parser::parse_ldap_messages;
use log::{debug, error, info, warn};
use rand::distr::{Alphanumeric, SampleString};
use rasn_ldap::ResultCode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

use crate::aci::Permission;
use crate::audit::{AuditEventType, AuditLevel};
use crate::auth_metadata::AuthMetadataRecorder;
use crate::backend::{
    DirectoryAttributeProjection, DirectoryBackend, DirectoryEntry, NativeModifyError,
    ProjectedDirectoryEntry, ProjectedSearchEntryStreamReceiver, SearchCandidateHint,
    SearchEntryStreamReceiver,
};
use crate::backend_adapters::{
    AllowAllCompareAccessControl, AllowAllWriteAciChecker, CompareBackendAdapter,
    PassthroughSchemaValidator, ProductionAttributeComparator, ProductionCompareMetrics,
    ProductionWriteMetrics, WriteBackendAdapter,
};
use crate::compare_fsm::{CompareFsmConfig, CompareFsmError, CompareFsmImpl};
use crate::connection_fsm::{ConnectionTransport, TlsHandler};
use crate::connection_pool::{ConnectionPool, ResourceLimits};
use crate::extended_ops::{
    encode_password_modify_response_value, oids, parse_cancel_request_value,
    parse_password_modify_request_value,
};
use crate::fsm::{
    CompareEvent, CompareFsm, ConnectionEvent, ConnectionFsm, SearchEvent, StateMachine,
    WriteEvent, WriteOperation,
};
use crate::fsm_request::{FsmRequestContext, FsmRequestRejection, FsmResponseKind};
use crate::fsm_runtime::{AuthenticationFsm, ConnectionFsmSet};
use crate::ldap_controls::LdapControl;
use crate::ldap_filter_eval::{
    FilterSchemaError, PreparedLdapFilter, prepare_search_filter_with_schema,
};
use crate::metrics::{
    FsmType, MetricsCollector, OperationType as MetricsOperationType, ResourceEventType,
};
use crate::parser::{
    ResponseOp, encode_custom_extended_response, encode_extended_response,
    encode_result_response_with_referrals, encode_search_entry_parts_with_controls,
    encode_search_reference_with_controls,
};
use crate::perf_profile::PerfPhase;
use crate::rate_limit::{RateLimitConfig, RateLimiter};
use crate::referral::LdapReferralResolver;
use crate::referral_fsm::ReferralResolver;
use crate::schema::LdapSchema;
use crate::schema_adapter::LdapSchemaValidator;
use crate::search_adapters::{
    ProductionEntryFormatter, ProductionFilterMatcher, ProductionSearchMetrics,
};
use crate::search_controls::{
    PAGED_RESULTS_OID, PagedResultsControl, SERVER_SIDE_SORT_REQUEST_OID,
    SERVER_SIDE_SORT_RESPONSE_OID, ServerSideSortResultCode, SortKey, decode_paged_results_control,
    decode_server_side_sort_request_control, encode_paged_results_control,
    encode_server_side_sort_response_control,
};
use crate::search_fsm::{
    EntryFormatter, SearchBackend, SearchEntry, SearchFsmConfig, SearchFsmError, SearchFsmImpl,
};
use crate::server::{
    CancelRequestOutcome, ConnectionOperationRegistry, ConnectionSession, LegacySecurityConfig,
    LegacyServerConfig, PagedSearchCursor, RequestContext, SearchRequestSignature, ServerError,
    SharedLdapSchema, SyncRequestError, apply_online_schema_modify,
    authorize_attribute_permissions, authorize_operation, build_entry_from_add_request,
    can_skip_search_post_filter, compute_new_dn, convert_ldap_changes_to_modifications,
    entry_is_referral as directory_entry_is_referral, filter_search_entries_for_read_access,
    first_server_managed_operational_attribute, handle_sync_search_request,
    increment_control_counter, log_add_audit_event, log_anonymous_bind, log_compare_audit,
    log_delete_audit_event, log_generic_audit_event, log_moddn_audit_event, log_modify_audit_event,
    log_password_modify_audit_event, log_sasl_bind, log_simple_bind_failure,
    log_simple_bind_success, online_schema_update_result, parse_sync_request_control,
    record_authentication_failure_metadata_with_context,
    record_authentication_success_metadata_with_context, referral_urls_for_entry,
    reject_sync_request, resolve_search_base_dn, resolve_search_candidate_entry, schema_snapshot,
    server_managed_operational_attribute_diagnostic, shared_schema,
};
use crate::shutdown::ShutdownCoordinator;
use crate::sync_controls::SYNC_REQUEST_OID;
use crate::tls::RustlsTlsHandler;
use crate::write_fsm::{WriteFsmConfig, WriteFsmError, WriteFsmImpl};

const MANAGE_DSA_IT_OID: &str = "2.16.840.1.113730.3.4.2";
const FSM_SEARCH_ENTRY_WRITE_BATCH_BYTES: usize = 64 * 1024;

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
    pub auth_metadata: Option<AuthMetadataRecorder>,
}

impl FsmServerRuntimeContext {
    fn request_context(&self, client_ip: Option<IpAddr>, conn_id: u64) -> RequestContext {
        RequestContext::new(
            client_ip,
            Some(conn_id),
            self.security.clone(),
            self.metrics.clone(),
        )
        .with_auth_metadata(self.auth_metadata.clone())
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
        shared_schema(LdapSchema::with_core_schema()),
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
        shared_schema(LdapSchema::with_core_schema()),
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
    schema: SharedLdapSchema,
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
                let schema = schema.clone();
                let pool_clone = pool.clone();
                let shutdown_clone = shutdown.clone();
                let rate_limiter_clone = rate_limiter.clone();

                tokio::spawn(async move {
                    if let Err(err) = handle_connection_with_transport(
                        ConnectionTransport::plain(socket),
                        backend,
                        config,
                        runtime_context.clone(),
                        schema,
                        pool_clone.clone(),
                        conn_id,
                        Some(client_addr.ip()),
                        rate_limiter_clone,
                    )
                    .await
                    {
                        log_connection_failure(
                            "Connection error",
                            client_addr,
                            &err.to_string(),
                        );
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
    schema: SharedLdapSchema,
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

                let backend = backend.clone();
                let config = config.clone();
                let runtime_context = runtime_context.clone();
                let schema = schema.clone();
                let pool_clone = pool.clone();
                let shutdown_clone = shutdown.clone();
                let rate_limiter_clone = rate_limiter.clone();
                let tls_handler = tls_handler.clone();

                tokio::spawn(async move {
                    let transport = match tls_handler.accept_transport(socket).await {
                        Ok(transport) => transport,
                        Err(err) => {
                            log_connection_failure(
                                "LDAPS handshake failed",
                                client_addr,
                                &err,
                            );
                            record_connection_failed(&runtime_context);
                            pool_clone.release_connection(conn_id).await;
                            if let Some(ref shutdown_coord) = shutdown_clone {
                                shutdown_coord.unregister_connection().await;
                            }
                            return;
                        }
                    };

                    info!(
                        "Accepted FSM LDAPS connection from {:?} (conn_id={})",
                        client_addr, conn_id
                    );
                    record_connection_accepted(&runtime_context, true);
                    audit_connection_accepted(&runtime_context, client_addr.ip(), conn_id).await;

                    if let Err(err) = handle_connection_with_transport(
                        transport,
                        backend,
                        config,
                        runtime_context.clone(),
                        schema,
                        pool_clone.clone(),
                        conn_id,
                        Some(client_addr.ip()),
                        rate_limiter_clone,
                    )
                    .await
                    {
                        log_connection_failure(
                            "LDAPS connection error",
                            client_addr,
                            &err.to_string(),
                        );
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

fn trace_fsm_search(message: std::fmt::Arguments<'_>) {
    if std::env::var_os("OPENDR_TRACE_SEARCH").is_some() {
        eprintln!("trace_fsm_search: {message}");
    }
}

#[allow(clippy::manual_is_multiple_of)]
fn fsm_search_progress_checkpoint(emitted: usize) -> bool {
    emitted % 100 == 0
}

async fn flush_fsm_search_entry_batch(
    fsm_set: &mut ConnectionFsmSet,
    pending_bytes: &mut Vec<u8>,
) -> Result<usize, String> {
    if pending_bytes.is_empty() {
        return Ok(0);
    }

    let flushed_bytes = pending_bytes.len();
    let stream = fsm_set
        .connection_mut()
        .stream_mut()
        .ok_or("No active stream")?;
    stream
        .write_all(pending_bytes.as_slice())
        .await
        .map_err(|err| format!("Write error: {err}"))?;
    pending_bytes.clear();

    Ok(flushed_bytes)
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
        shared_schema(LdapSchema::with_core_schema()),
        pool,
        conn_id,
        client_ip,
        rate_limiter,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection_with_transport(
    transport: ConnectionTransport,
    backend: Arc<dyn DirectoryBackend>,
    config: FsmServerConfig,
    runtime_context: FsmServerRuntimeContext,
    schema: SharedLdapSchema,
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

                let decoded_messages = match decode_ready_messages(&mut fsm_set, data).await {
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
                        if let Some(metrics) = runtime_context.metrics.as_ref()
                            && let Some(operation_type) = operation_type
                        {
                            metrics.record_operation_start(operation_type, "");
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

                        if let Some(metrics) = runtime_context.metrics.as_ref()
                            && let Some(operation_type) = operation_type
                        {
                            metrics.record_operation_complete(
                                operation_type,
                                started_at.elapsed(),
                                result.is_ok(),
                            );
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
    initial_data: &[u8],
) -> Result<Vec<Vec<u8>>, String> {
    fsm_set
        .decoder_mut()
        .decode_available_messages(initial_data)
        .await
        .map_err(|err| err.to_string())
}

#[allow(clippy::too_many_arguments)]
async fn process_ldap_message(
    fsm_set: &mut ConnectionFsmSet,
    message: LdapMessage<'_>,
    runtime_context: &FsmServerRuntimeContext,
    pool: &Arc<ConnectionPool>,
    schema: &SharedLdapSchema,
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
                request.is_secure,
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

            let schema_snapshot = connection_schema_snapshot(fsm_set, schema, runtime_context);
            let result = handle_search_request_with_fsm_runtime(
                fsm_set,
                &request,
                search_req,
                schema_snapshot.as_ref(),
                request_context,
                runtime_context,
                legacy_operation_registry,
            )
            .await;
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

            let dn = modify_req.object.0.as_ref().trim().to_owned();
            let result = if dn
                .eq_ignore_ascii_case(&runtime_context.legacy_runtime_config.subschema_dn)
            {
                handle_online_schema_modify_with_fsm_runtime(
                    fsm_set,
                    &request,
                    modify_req,
                    schema,
                    request_context,
                    runtime_context,
                )
                .await
            } else {
                let schema_snapshot = connection_schema_snapshot(fsm_set, schema, runtime_context);
                handle_modify_request_with_fsm_runtime(
                    fsm_set,
                    &request,
                    modify_req,
                    schema_snapshot.as_ref(),
                    request_context,
                    runtime_context,
                )
                .await
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

            let schema_snapshot = connection_schema_snapshot(fsm_set, schema, runtime_context);
            let result = handle_add_request_with_fsm_runtime(
                fsm_set,
                &request,
                add_req,
                schema_snapshot.as_ref(),
                request_context,
                runtime_context,
            )
            .await;
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

            let result = handle_delete_request_with_fsm_runtime(
                fsm_set,
                &request,
                delete_req,
                request_context,
                runtime_context,
            )
            .await;
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

            let schema_snapshot = connection_schema_snapshot(fsm_set, schema, runtime_context);
            let result = handle_moddn_request_with_fsm_runtime(
                fsm_set,
                &request,
                rename_req,
                schema_snapshot.as_ref(),
                request_context,
                runtime_context,
            )
            .await;
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

            let schema_snapshot = connection_schema_snapshot(fsm_set, schema, runtime_context);
            let result = handle_compare_request_with_fsm_runtime(
                fsm_set,
                &request,
                compare_req,
                schema_snapshot.as_ref(),
                request_context,
                runtime_context,
            )
            .await;
            pool.end_operation(conn_id).await;
            result?;
        }
        ProtocolOp::AbandonRequest(abandoned_id) => {
            info!("Abandon request for message ID {}", abandoned_id.0);
            let _ = legacy_operation_registry.request_abandon(abandoned_id.0);
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

fn connection_schema_snapshot(
    fsm_set: &mut ConnectionFsmSet,
    schema: &SharedLdapSchema,
    runtime_context: &FsmServerRuntimeContext,
) -> Arc<LdapSchema> {
    if runtime_context
        .legacy_runtime_config
        .allow_online_schema_updates
    {
        return Arc::new(schema_snapshot(schema));
    }

    if let Some(snapshot) = fsm_set.immutable_schema_snapshot() {
        return snapshot;
    }

    let snapshot = Arc::new(schema_snapshot(schema));
    fsm_set.remember_immutable_schema_snapshot(snapshot.clone());
    snapshot
}

fn prepare_or_cache_search_filter(
    fsm_set: &mut ConnectionFsmSet,
    schema: &LdapSchema,
    rendered_filter: &str,
    filter: &Filter<'_>,
    allow_online_schema_updates: bool,
) -> Result<PreparedLdapFilter, FilterSchemaError> {
    if !allow_online_schema_updates
        && let Some(prepared_filter) = fsm_set.prepared_search_filter(rendered_filter)
    {
        return Ok(prepared_filter);
    }

    let prepared_filter = prepare_search_filter_with_schema(schema, filter)?;
    if !allow_online_schema_updates {
        fsm_set
            .remember_prepared_search_filter(rendered_filter.to_string(), prepared_filter.clone());
    }
    Ok(prepared_filter)
}

struct PreloadedSearchBackend {
    candidates: Mutex<Option<Vec<String>>>,
    entries: HashMap<String, Arc<SearchEntry>>,
}

impl PreloadedSearchBackend {
    fn new(entries: Vec<crate::backend::DirectoryEntry>) -> Self {
        let mut candidates = Vec::with_capacity(entries.len());
        let mut indexed_entries = HashMap::with_capacity(entries.len());

        for entry in entries {
            let normalized_dn = normalize_search_dn(&entry.dn);
            if indexed_entries.contains_key(&normalized_dn) {
                continue;
            }

            candidates.push(entry.dn.clone());
            indexed_entries.insert(
                normalized_dn,
                Arc::new(directory_entry_to_search_entry(&entry)),
            );
        }

        Self {
            candidates: Mutex::new(Some(candidates)),
            entries: indexed_entries,
        }
    }
}

#[async_trait::async_trait]
impl SearchBackend for PreloadedSearchBackend {
    async fn find_candidates(
        &self,
        _base_dn: &str,
        _scope: i32,
        _filter: &str,
    ) -> Result<Vec<String>, String> {
        Ok(self
            .candidates
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .take()
            .unwrap_or_default())
    }

    async fn get_entry(
        &self,
        dn: &str,
        _requested_attributes: &[String],
    ) -> Result<Option<Arc<SearchEntry>>, String> {
        Ok(self.entries.get(&normalize_search_dn(dn)).cloned())
    }

    async fn entry_exists(&self, dn: &str) -> Result<bool, String> {
        Ok(self.entries.contains_key(&normalize_search_dn(dn)))
    }

    async fn get_search_stats(&self, _base_dn: &str) -> Result<(usize, usize), String> {
        Ok((self.entries.len(), 1))
    }
}

async fn handle_search_request_with_fsm_runtime(
    fsm_set: &mut ConnectionFsmSet,
    request: &FsmRequestContext,
    search_req: ldap_parser::ldap::SearchRequest<'_>,
    schema: &LdapSchema,
    request_context: &RequestContext,
    runtime_context: &FsmServerRuntimeContext,
    legacy_operation_registry: &mut ConnectionOperationRegistry,
) -> Result<(), String> {
    let _profile_total = PerfPhase::start("search", "total", Some(request.message_id as u32));
    if try_handle_virtual_search_request_with_fsm_runtime(
        fsm_set,
        request,
        &search_req,
        schema,
        request_context,
        runtime_context,
    )
    .await?
    {
        return Ok(());
    }

    let manage_dsa_it = match parse_native_manage_dsa_it_request(&request.request_controls) {
        Ok(manage_dsa_it) => manage_dsa_it,
        Err(diagnostic) => {
            send_request_result_response_with_referrals(
                fsm_set,
                request.message_id as u32,
                request.response_kind,
                ResultCode::ProtocolError,
                search_req.base_object.0.as_ref().trim(),
                &diagnostic,
                &[],
            )
            .await?;
            return Ok(());
        }
    };
    let requested_sort = match parse_native_server_side_sort_request(&request.request_controls) {
        Ok(requested_sort) => requested_sort,
        Err(error) => {
            let base_dn = search_req.base_object.0.as_ref().trim().to_owned();
            let session = legacy_session_from_fsm(fsm_set);
            reject_native_server_side_sort_request(
                fsm_set,
                request,
                request_context,
                &session,
                &base_dn,
                error,
            )
            .await?;
            return Ok(());
        }
    };
    if requested_sort.is_some() {
        increment_control_counter(request_context, "ldap_sort_requests_total", 1);
    }
    let paged_results = match parse_native_paged_results_request(&request.request_controls) {
        Ok(paged_results) => paged_results,
        Err(error) => {
            let base_dn = search_req.base_object.0.as_ref().trim().to_owned();
            let session = legacy_session_from_fsm(fsm_set);
            reject_native_paged_search_request(
                fsm_set,
                request,
                request_context,
                &session,
                &base_dn,
                error,
            )
            .await?;
            return Ok(());
        }
    };
    if paged_results.is_some() {
        increment_control_counter(request_context, "ldap_paged_search_requests_total", 1);
    }
    let requested_sync = match parse_sync_request_control(&request.request_controls) {
        Ok(sync) => sync,
        Err(error) => {
            let base_dn = search_req.base_object.0.as_ref().trim().to_owned();
            let stream = fsm_set
                .connection_mut()
                .stream_mut()
                .ok_or("No active stream")?;
            reject_sync_request(stream, request.message_id as u32, &base_dn, &error)
                .await
                .map_err(|err| err.to_string())?;
            return Ok(());
        }
    };
    if requested_sync.is_some() {
        increment_control_counter(request_context, "ldap_sync_requests_total", 1);
    }
    if requested_sync.is_some() && paged_results.is_some() {
        let base_dn = search_req.base_object.0.as_ref().trim().to_owned();
        let err = SyncRequestError::Unsupported(
            "sync request control cannot be combined with paged results".to_string(),
        );
        let stream = fsm_set
            .connection_mut()
            .stream_mut()
            .ok_or("No active stream")?;
        reject_sync_request(stream, request.message_id as u32, &base_dn, &err)
            .await
            .map_err(|err| err.to_string())?;
        return Ok(());
    }
    if requested_sync.is_some() && requested_sort.is_some() {
        let base_dn = search_req.base_object.0.as_ref().trim().to_owned();
        let err = SyncRequestError::Unsupported(
            "sync request control cannot be combined with server-side sort".to_string(),
        );
        let stream = fsm_set
            .connection_mut()
            .stream_mut()
            .ok_or("No active stream")?;
        reject_sync_request(stream, request.message_id as u32, &base_dn, &err)
            .await
            .map_err(|err| err.to_string())?;
        return Ok(());
    }
    if let Some(control) = paged_results.as_ref()
        && control.size == 0
        && control.cookie.is_empty()
    {
        let base_dn = search_req.base_object.0.as_ref().trim().to_owned();
        let session = legacy_session_from_fsm(fsm_set);
        reject_native_paged_search_request(
            fsm_set,
            request,
            request_context,
            &session,
            &base_dn,
            NativePagedSearchError::ProtocolError(
                "paged results page size must be greater than zero on the initial request"
                    .to_string(),
            ),
        )
        .await?;
        return Ok(());
    }

    let session = legacy_session_from_fsm(fsm_set);
    let backend = fsm_set.backend().clone();
    let base_dn = search_req.base_object.0.as_ref().trim().to_owned();
    let attribute_selection: Vec<String> = search_req
        .attributes
        .iter()
        .map(|attribute| attribute.0.as_ref().trim().to_owned())
        .collect();

    let filter = render_search_filter_string(&search_req.filter);
    let prepared_filter = match prepare_or_cache_search_filter(
        fsm_set,
        schema,
        &filter,
        &search_req.filter,
        runtime_context
            .legacy_runtime_config
            .allow_online_schema_updates,
    ) {
        Ok(prepared_filter) => prepared_filter,
        Err(err) => {
            let diagnostic = err.to_string();
            send_request_result_response(
                fsm_set,
                request.message_id as u32,
                request.response_kind,
                map_filter_schema_error_code(&err),
                &diagnostic,
            )
            .await?;
            return Ok(());
        }
    };

    let authorized = {
        let stream = fsm_set
            .connection_mut()
            .stream_mut()
            .ok_or("No active stream")?;
        authorize_operation(
            stream,
            Some(backend.as_ref()),
            request.message_id as u32,
            ResponseOp::SearchDone,
            &session,
            request_context,
            Permission::Search,
            "search",
            &base_dn,
            None,
        )
        .await
        .map_err(|err| err.to_string())?
    };
    if !authorized {
        return Ok(());
    }

    let effective_base_dn =
        match resolve_search_base_dn(backend.as_ref(), &base_dn, search_req.deref_aliases).await {
            Ok(dn) => dn,
            Err((result_code, diagnostic)) => {
                increment_control_counter(
                    request_context,
                    "ldap_search_alias_dereference_failures_total",
                    1,
                );
                log_generic_audit_event(
                    request_context,
                    &session,
                    AuditLevel::Warning,
                    AuditEventType::Authorization,
                    "search_alias_deref",
                    false,
                    Some(base_dn.as_str()),
                    Some(diagnostic.as_str()),
                    Vec::new(),
                )
                .await;
                send_request_result_response_with_referrals(
                    fsm_set,
                    request.message_id as u32,
                    request.response_kind,
                    result_code,
                    &base_dn,
                    &diagnostic,
                    &[],
                )
                .await?;
                return Ok(());
            }
        };

    if let Some(sync_request) = requested_sync.as_ref() {
        if !manage_dsa_it && search_req.scope == ldap_parser::ldap::SearchScope::BaseObject {
            match backend.get_entry(&effective_base_dn).await {
                Ok(Some(base_entry)) if directory_entry_is_referral(&base_entry) => {
                    match referral_urls_for_entry(&base_entry) {
                        Ok(referrals) => {
                            increment_control_counter(
                                request_context,
                                "ldap_referral_results_total",
                                1,
                            );
                            log_generic_audit_event(
                                request_context,
                                &session,
                                AuditLevel::Info,
                                AuditEventType::Authorization,
                                "search_referral",
                                true,
                                Some(effective_base_dn.as_str()),
                                Some("base search resolved to referral"),
                                vec![("referral_count".to_string(), referrals.len().to_string())],
                            )
                            .await;
                            send_request_result_response_with_referrals(
                                fsm_set,
                                request.message_id as u32,
                                request.response_kind,
                                ResultCode::Referral,
                                &effective_base_dn,
                                "search base is a referral",
                                &referrals,
                            )
                            .await?;
                            return Ok(());
                        }
                        Err(diagnostic) => {
                            increment_control_counter(
                                request_context,
                                "ldap_referral_processing_failures_total",
                                1,
                            );
                            send_request_result_response(
                                fsm_set,
                                request.message_id as u32,
                                request.response_kind,
                                ResultCode::OperationsError,
                                &diagnostic,
                            )
                            .await?;
                            return Ok(());
                        }
                    }
                }
                Ok(_) => {}
                Err(err) => {
                    send_request_result_response(
                        fsm_set,
                        request.message_id as u32,
                        request.response_kind,
                        map_backend_error_code(&err),
                        backend_diagnostic(&err),
                    )
                    .await?;
                    return Ok(());
                }
            }
        }

        let search_deadline = if search_req.time_limit == 0 {
            None
        } else {
            Some(Instant::now() + Duration::from_secs(search_req.time_limit as u64))
        };
        let stream = fsm_set
            .connection_mut()
            .stream_mut()
            .ok_or("No active stream")?;
        handle_sync_search_request(
            stream,
            backend.as_ref(),
            schema,
            request.message_id as u32,
            &search_req,
            &effective_base_dn,
            &attribute_selection,
            sync_request,
            manage_dsa_it,
            &session,
            legacy_operation_registry,
            request_context,
            search_deadline,
        )
        .await
        .map_err(|err| err.to_string())?;
        return Ok(());
    }

    let search_signature = paged_results.as_ref().map(|_| {
        SearchRequestSignature::from_request(
            &base_dn,
            &search_req,
            &attribute_selection,
            requested_sort.as_ref().map(|sort| sort.keys.as_slice()),
        )
    });
    if let Some(control) = paged_results
        .as_ref()
        .filter(|control| !control.cookie.is_empty())
    {
        handle_native_paged_search_continuation(
            fsm_set,
            request,
            request_context,
            legacy_operation_registry,
            control,
            search_signature.as_ref().expect("paged search signature"),
            &base_dn,
            &attribute_selection,
            search_req.types_only,
            search_req.time_limit,
            requested_sort.as_ref(),
        )
        .await?;
        return Ok(());
    }

    let search_started_at = Instant::now();
    let search_hint = prepared_filter.search_candidate_hint();
    let exact_index_hint = prepared_filter.exact_index_coverage_hint();
    trace_fsm_search(format_args!(
        "plain_search load candidates base={effective_base_dn} scope={} hint={search_hint:?}",
        search_req.scope.0
    ));
    let can_stream_plain_search = paged_results.is_none()
        && backend.supports_search_entry_streaming()
        && requested_sort.is_none()
        && !matches!(search_req.deref_aliases.0, 1 | 3)
        && can_skip_search_post_filter(&session, request_context);
    let can_stream_index_covered_plain_search = can_stream_plain_search
        && exact_index_hint.as_ref() == search_hint.as_ref()
        && search_hint.is_some();
    if can_stream_index_covered_plain_search
        && matches!(search_hint, Some(SearchCandidateHint::Equality { .. }))
    {
        let stream_report = match backend
            .stream_projected_search_entries_with_hint_report(
                &effective_base_dn,
                search_req.scope,
                search_hint.clone(),
                attribute_selection.clone(),
            )
            .await
        {
            Ok(stream_report) => stream_report,
            Err(err) => {
                send_request_result_response(
                    fsm_set,
                    request.message_id as u32,
                    request.response_kind,
                    map_backend_error_code(&err),
                    backend_diagnostic(&err),
                )
                .await?;
                return Ok(());
            }
        };

        let index_covers_filter = stream_report.hint_covers_filter
            && !matches!(search_req.deref_aliases.0, 1 | 3)
            && can_skip_search_post_filter(&session, request_context);
        if index_covers_filter {
            emit_projected_index_covered_plain_search_stream(
                fsm_set,
                request,
                request_context,
                runtime_context.metrics.as_deref(),
                stream_report.entries,
                manage_dsa_it,
                search_req.scope,
                search_req.types_only,
                search_started_at,
                search_req.time_limit,
                search_req.size_limit,
            )
            .await?;
            return Ok(());
        }
    }

    if can_stream_plain_search {
        let stream_report = match backend
            .stream_search_entries_with_hint_report(
                &effective_base_dn,
                search_req.scope,
                search_hint.clone(),
            )
            .await
        {
            Ok(stream_report) => stream_report,
            Err(err) => {
                send_request_result_response(
                    fsm_set,
                    request.message_id as u32,
                    request.response_kind,
                    map_backend_error_code(&err),
                    backend_diagnostic(&err),
                )
                .await?;
                return Ok(());
            }
        };

        let index_covers_filter = stream_report.hint_covers_filter
            && !matches!(search_req.deref_aliases.0, 1 | 3)
            && exact_index_hint.as_ref() == search_hint.as_ref()
            && can_skip_search_post_filter(&session, request_context);
        if index_covers_filter {
            emit_index_covered_plain_search_stream(
                fsm_set,
                request,
                request_context,
                runtime_context.metrics.as_deref(),
                stream_report.entries,
                manage_dsa_it,
                search_req.scope,
                &attribute_selection,
                search_req.types_only,
                search_started_at,
                search_req.time_limit,
                search_req.size_limit,
            )
            .await?;
            return Ok(());
        }

        emit_filtering_plain_search_stream(
            fsm_set,
            request,
            request_context,
            runtime_context.metrics.as_deref(),
            stream_report.entries,
            manage_dsa_it,
            search_req.scope,
            &attribute_selection,
            search_req.types_only,
            search_started_at,
            search_req.time_limit,
            search_req.size_limit,
            &prepared_filter,
        )
        .await?;
        return Ok(());
    }

    let search_report = match backend
        .search_entries_with_hint_report(&effective_base_dn, search_req.scope, search_hint.clone())
        .await
    {
        Ok(search_report) => search_report,
        Err(err) => {
            send_request_result_response(
                fsm_set,
                request.message_id as u32,
                request.response_kind,
                map_backend_error_code(&err),
                backend_diagnostic(&err),
            )
            .await?;
            return Ok(());
        }
    };
    let mut index_covers_filter = search_report.hint_covers_filter
        && exact_index_hint.as_ref() == search_hint.as_ref()
        && !matches!(search_req.deref_aliases.0, 1 | 3)
        && can_skip_search_post_filter(&session, request_context);
    let mut preloaded_entries = search_report.entries;

    match resolve_plain_search_alias_candidates(
        backend.as_ref(),
        preloaded_entries,
        search_req.deref_aliases,
    )
    .await
    {
        Ok(entries) => preloaded_entries = entries,
        Err(error) => {
            increment_control_counter(
                request_context,
                "ldap_search_alias_dereference_failures_total",
                1,
            );
            log_generic_audit_event(
                request_context,
                &session,
                AuditLevel::Warning,
                AuditEventType::Authorization,
                "search_alias_deref",
                false,
                Some(error.target_dn.as_str()),
                Some(error.diagnostic.as_str()),
                Vec::new(),
            )
            .await;
            send_request_result_response_with_referrals(
                fsm_set,
                request.message_id as u32,
                request.response_kind,
                error.result_code,
                &base_dn,
                &error.diagnostic,
                &[],
            )
            .await?;
            return Ok(());
        }
    }
    if matches!(search_req.deref_aliases.0, 1 | 3) {
        index_covers_filter = false;
    }

    let mut search_references = Vec::new();
    if !manage_dsa_it {
        match prepare_plain_search_referrals(preloaded_entries, search_req.scope) {
            Ok(PlainSearchReferralDisposition::BaseReferral { dn, referrals }) => {
                increment_control_counter(request_context, "ldap_referral_results_total", 1);
                log_generic_audit_event(
                    request_context,
                    &session,
                    AuditLevel::Info,
                    AuditEventType::Authorization,
                    "search_referral",
                    true,
                    Some(dn.as_str()),
                    Some("base search resolved to referral"),
                    vec![("referral_count".to_string(), referrals.len().to_string())],
                )
                .await;
                send_request_result_response_with_referrals(
                    fsm_set,
                    request.message_id as u32,
                    request.response_kind,
                    ResultCode::Referral,
                    &dn,
                    "search base is a referral",
                    &referrals,
                )
                .await?;
                return Ok(());
            }
            Ok(PlainSearchReferralDisposition::SearchEntries {
                entries,
                references,
            }) => {
                preloaded_entries = entries;
                search_references = references;
            }
            Err(error) => {
                increment_control_counter(
                    request_context,
                    "ldap_referral_processing_failures_total",
                    1,
                );
                log_generic_audit_event(
                    request_context,
                    &session,
                    AuditLevel::Warning,
                    AuditEventType::Authorization,
                    "search_referral",
                    false,
                    Some(error.target_dn.as_str()),
                    Some(error.diagnostic.as_str()),
                    Vec::new(),
                )
                .await;
                send_request_result_response(
                    fsm_set,
                    request.message_id as u32,
                    request.response_kind,
                    ResultCode::OperationsError,
                    &error.diagnostic,
                )
                .await?;
                return Ok(());
            }
        }
    }

    if !can_skip_search_post_filter(&session, request_context) {
        preloaded_entries = filter_search_entries_for_read_access(
            backend.as_ref(),
            &session,
            request_context,
            preloaded_entries,
        )
        .await;
    }
    if let Some(requested_sort) = requested_sort.as_ref() {
        sort_native_search_entries(&mut preloaded_entries, requested_sort);
    }

    let effective_time_limit = match remaining_time_limit(search_started_at, search_req.time_limit)
    {
        Some(time_limit) => time_limit,
        None => {
            send_request_result_response(
                fsm_set,
                request.message_id as u32,
                request.response_kind,
                ResultCode::TimeLimitExceeded,
                "time limit exceeded",
            )
            .await?;
            return Ok(());
        }
    };

    if let Some(control) = paged_results.as_ref() {
        handle_native_paged_search_initial(
            fsm_set,
            request,
            request_context,
            legacy_operation_registry,
            control,
            search_signature.expect("paged search signature"),
            &base_dn,
            &attribute_selection,
            search_req.types_only,
            requested_sort.as_ref(),
            preloaded_entries,
            search_references,
            &prepared_filter,
            index_covers_filter,
            effective_time_limit,
            search_req.size_limit,
        )
        .await?;
        return Ok(());
    }

    if index_covers_filter && requested_sort.is_none() {
        emit_index_covered_plain_search(
            fsm_set,
            request,
            request_context,
            runtime_context.metrics.as_deref(),
            preloaded_entries,
            &search_references,
            &attribute_selection,
            search_req.types_only,
            search_started_at,
            search_req.time_limit,
            search_req.size_limit,
        )
        .await?;
        return Ok(());
    }

    let mut search_fsm = build_preloaded_search_fsm(
        preloaded_entries,
        schema,
        Some((filter.clone(), prepared_filter, index_covers_filter)),
        runtime_context.metrics.clone(),
        request.message_id as u32,
        search_req.types_only,
    );

    let mut next_entry = match search_fsm
        .handle_event(SearchEvent::StartSearch {
            base_dn: effective_base_dn,
            scope: search_req.scope.0 as i32,
            filter,
            attributes: attribute_selection,
            size_limit: search_req.size_limit,
            time_limit: effective_time_limit,
        })
        .await
    {
        Ok(next_entry) => next_entry,
        Err(error) => {
            let (result_code, diagnostic) = search_fsm_error_response(&error);
            send_request_result_response(
                fsm_set,
                request.message_id as u32,
                request.response_kind,
                result_code,
                &diagnostic,
            )
            .await?;
            return Ok(());
        }
    };

    let mut pending_entry_bytes = Vec::with_capacity(FSM_SEARCH_ENTRY_WRITE_BATCH_BYTES);
    let mut emitted_entries = 0usize;
    let mut flushed_batches = 0usize;
    let mut flushed_bytes = 0usize;

    loop {
        let Some(encoded_entry) = next_entry else {
            let bytes = flush_fsm_search_entry_batch(fsm_set, &mut pending_entry_bytes).await?;
            if bytes > 0 {
                flushed_batches += 1;
                flushed_bytes += bytes;
            }
            trace_fsm_search(format_args!(
                "plain_search complete emitted={emitted_entries} flushed_batches={flushed_batches} flushed_bytes={flushed_bytes}"
            ));
            emit_plain_search_references(fsm_set, request, request_context, &search_references)
                .await?;
            let response_controls =
                native_search_done_controls(requested_sort.as_ref(), ResultCode::Success)?;
            send_request_result_response_with_controls(
                fsm_set,
                request.message_id as u32,
                request.response_kind,
                ResultCode::Success,
                "",
                "",
                &response_controls,
            )
            .await?;
            return Ok(());
        };

        pending_entry_bytes.extend(encoded_entry);
        if pending_entry_bytes.len() >= FSM_SEARCH_ENTRY_WRITE_BATCH_BYTES {
            let bytes = flush_fsm_search_entry_batch(fsm_set, &mut pending_entry_bytes).await?;
            flushed_batches += 1;
            flushed_bytes += bytes;
            trace_fsm_search(format_args!(
                "plain_search flushed batch={flushed_batches} bytes={bytes} total_bytes={flushed_bytes}"
            ));
        }

        next_entry = match search_fsm.handle_event(SearchEvent::EntryEmitted).await {
            Ok(next_entry) => {
                emitted_entries += 1;
                if fsm_search_progress_checkpoint(emitted_entries) {
                    trace_fsm_search(format_args!(
                        "plain_search progress emitted={emitted_entries} buffered_bytes={}",
                        pending_entry_bytes.len()
                    ));
                }
                next_entry
            }
            Err(error) => {
                emitted_entries += 1;
                let bytes = flush_fsm_search_entry_batch(fsm_set, &mut pending_entry_bytes).await?;
                if bytes > 0 {
                    flushed_batches += 1;
                    flushed_bytes += bytes;
                }
                trace_fsm_search(format_args!(
                    "plain_search error={error:?} emitted={emitted_entries} flushed_batches={flushed_batches} flushed_bytes={flushed_bytes}"
                ));
                if matches!(
                    error,
                    SearchFsmError::SizeLimitExceeded | SearchFsmError::TimeLimitExceeded
                ) {
                    emit_plain_search_references(
                        fsm_set,
                        request,
                        request_context,
                        &search_references,
                    )
                    .await?;
                }
                let (result_code, diagnostic) = search_fsm_error_response(&error);
                let response_controls =
                    native_search_error_controls(requested_sort.as_ref(), &error)?;
                send_request_result_response_with_controls(
                    fsm_set,
                    request.message_id as u32,
                    request.response_kind,
                    result_code,
                    "",
                    &diagnostic,
                    &response_controls,
                )
                .await?;
                return Ok(());
            }
        };
    }
}

enum PlainSearchReferralDisposition {
    SearchEntries {
        entries: Vec<crate::backend::DirectoryEntry>,
        references: Vec<Vec<String>>,
    },
    BaseReferral {
        dn: String,
        referrals: Vec<String>,
    },
}

struct PlainSearchReferralError {
    target_dn: String,
    diagnostic: String,
}

struct PlainSearchAliasError {
    target_dn: String,
    result_code: ResultCode,
    diagnostic: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NativeServerSideSort {
    keys: Vec<SortKey>,
    critical: bool,
}

#[derive(Debug)]
enum NativeServerSideSortError {
    ProtocolError(String),
    Unsupported {
        result: ServerSideSortResultCode,
        attribute_type: Option<String>,
        diagnostic: String,
        critical: bool,
    },
}

#[derive(Debug)]
enum NativePagedSearchError {
    ProtocolError(String),
    InvalidCookie(String),
}

impl NativePagedSearchError {
    fn result_code(&self) -> ResultCode {
        match self {
            Self::ProtocolError(_) => ResultCode::ProtocolError,
            Self::InvalidCookie(_) => ResultCode::UnwillingToPerform,
        }
    }

    fn diagnostic(&self) -> &str {
        match self {
            Self::ProtocolError(message) | Self::InvalidCookie(message) => message.as_str(),
        }
    }
}

fn parse_native_paged_results_request(
    request_controls: &crate::ldap_controls::RequestControls,
) -> Result<Option<PagedResultsControl>, NativePagedSearchError> {
    let control = request_controls
        .singleton(PAGED_RESULTS_OID)
        .map_err(|err| NativePagedSearchError::ProtocolError(err.to_string()))?;
    let Some(control) = control else {
        return Ok(None);
    };

    decode_paged_results_control(control.value())
        .map(Some)
        .map_err(|err| {
            NativePagedSearchError::ProtocolError(format!("malformed paged results control: {err}"))
        })
}

fn native_paged_results_response_control(
    total_size: usize,
    cookie: &[u8],
) -> Result<LdapControl, String> {
    let value = encode_paged_results_control(u32::try_from(total_size).unwrap_or(u32::MAX), cookie)
        .map_err(|err| err.to_string())?;
    Ok(LdapControl::new(PAGED_RESULTS_OID, false, Some(value)))
}

async fn reject_native_paged_search_request(
    fsm_set: &mut ConnectionFsmSet,
    request: &FsmRequestContext,
    request_context: &RequestContext,
    session: &ConnectionSession,
    base_dn: &str,
    error: NativePagedSearchError,
) -> Result<(), String> {
    if matches!(error, NativePagedSearchError::InvalidCookie(_)) {
        increment_control_counter(request_context, "ldap_paged_search_invalid_cookie_total", 1);
    }

    let error_kind = match &error {
        NativePagedSearchError::ProtocolError(_) => "protocol_error",
        NativePagedSearchError::InvalidCookie(_) => "invalid_cookie",
    };
    log_generic_audit_event(
        request_context,
        session,
        AuditLevel::Warning,
        AuditEventType::Authorization,
        "paged_search",
        false,
        Some(base_dn),
        Some(error.diagnostic()),
        vec![("error_kind".to_string(), error_kind.to_string())],
    )
    .await;

    send_request_result_response_with_controls(
        fsm_set,
        request.message_id as u32,
        request.response_kind,
        error.result_code(),
        base_dn,
        error.diagnostic(),
        &[],
    )
    .await
}

fn parse_native_manage_dsa_it_request(
    request_controls: &crate::ldap_controls::RequestControls,
) -> Result<bool, String> {
    let control = request_controls
        .singleton(MANAGE_DSA_IT_OID)
        .map_err(|err| err.to_string())?;
    let Some(control) = control else {
        return Ok(false);
    };

    if control.value().is_some() {
        return Err("ManageDsaIT control must not include a controlValue".to_string());
    }

    Ok(true)
}

fn parse_native_server_side_sort_request(
    request_controls: &crate::ldap_controls::RequestControls,
) -> Result<Option<NativeServerSideSort>, NativeServerSideSortError> {
    let control = request_controls
        .singleton(SERVER_SIDE_SORT_REQUEST_OID)
        .map_err(|err| NativeServerSideSortError::ProtocolError(err.to_string()))?;
    let Some(control) = control else {
        return Ok(None);
    };

    let decoded = decode_server_side_sort_request_control(control.value()).map_err(|err| {
        NativeServerSideSortError::ProtocolError(format!(
            "malformed server-side sort control: {err}"
        ))
    })?;
    let requested_sort = NativeServerSideSort {
        keys: decoded.keys,
        critical: control.criticality(),
    };
    validate_native_server_side_sort_request(&requested_sort)?;

    Ok(Some(requested_sort))
}

fn validate_native_server_side_sort_request(
    requested_sort: &NativeServerSideSort,
) -> Result<(), NativeServerSideSortError> {
    let mut seen_attributes = std::collections::HashSet::new();
    for key in &requested_sort.keys {
        let normalized_attribute = key.attribute_type.to_ascii_lowercase();
        if !seen_attributes.insert(normalized_attribute) {
            return Err(NativeServerSideSortError::Unsupported {
                result: ServerSideSortResultCode::UnwillingToPerform,
                attribute_type: Some(key.attribute_type.clone()),
                diagnostic: format!(
                    "server-side sort attribute {} appears more than once",
                    key.attribute_type
                ),
                critical: requested_sort.critical,
            });
        }

        if key.ordering_rule.is_some() {
            return Err(NativeServerSideSortError::Unsupported {
                result: ServerSideSortResultCode::InappropriateMatching,
                attribute_type: Some(key.attribute_type.clone()),
                diagnostic: format!(
                    "explicit ordering rule is not supported for {}",
                    key.attribute_type
                ),
                critical: requested_sort.critical,
            });
        }
    }

    Ok(())
}

async fn reject_native_server_side_sort_request(
    fsm_set: &mut ConnectionFsmSet,
    request: &FsmRequestContext,
    request_context: &RequestContext,
    session: &ConnectionSession,
    base_dn: &str,
    error: NativeServerSideSortError,
) -> Result<(), String> {
    match error {
        NativeServerSideSortError::ProtocolError(diagnostic) => {
            log_generic_audit_event(
                request_context,
                session,
                AuditLevel::Warning,
                AuditEventType::Authorization,
                "server_side_sort",
                false,
                Some(base_dn),
                Some(diagnostic.as_str()),
                vec![("error_kind".to_string(), "protocol_error".to_string())],
            )
            .await;
            send_request_result_response_with_referrals(
                fsm_set,
                request.message_id as u32,
                request.response_kind,
                ResultCode::ProtocolError,
                base_dn,
                &diagnostic,
                &[],
            )
            .await
        }
        NativeServerSideSortError::Unsupported {
            result,
            attribute_type,
            diagnostic,
            critical,
        } => {
            increment_control_counter(request_context, "ldap_sort_failures_total", 1);
            if result == ServerSideSortResultCode::InappropriateMatching {
                increment_control_counter(
                    request_context,
                    "ldap_sort_unsupported_ordering_rule_total",
                    1,
                );
            }
            log_generic_audit_event(
                request_context,
                session,
                AuditLevel::Warning,
                AuditEventType::Authorization,
                "server_side_sort",
                false,
                Some(base_dn),
                Some(diagnostic.as_str()),
                vec![("error_kind".to_string(), "sort_failure".to_string())],
            )
            .await;

            let sort_response =
                native_server_side_sort_response_control(result, attribute_type.as_deref())?;
            let result_code = if critical {
                ResultCode::UnavailableCriticalExtension
            } else {
                ResultCode::Success
            };
            send_request_result_response_with_controls(
                fsm_set,
                request.message_id as u32,
                request.response_kind,
                result_code,
                base_dn,
                &diagnostic,
                &[sort_response],
            )
            .await
        }
    }
}

fn native_server_side_sort_response_control(
    result: ServerSideSortResultCode,
    attribute_type: Option<&str>,
) -> Result<LdapControl, String> {
    let value = encode_server_side_sort_response_control(result, attribute_type)
        .map_err(|err| err.to_string())?;
    Ok(LdapControl::new(
        SERVER_SIDE_SORT_RESPONSE_OID,
        false,
        Some(value),
    ))
}

fn sort_native_search_entries(
    entries: &mut [crate::backend::DirectoryEntry],
    requested_sort: &NativeServerSideSort,
) {
    entries.sort_by(|left, right| {
        for key in &requested_sort.keys {
            let left_value = native_sort_value_for_key(left, key);
            let right_value = native_sort_value_for_key(right, key);
            let ordering = match (&left_value, &right_value) {
                (Some(left_value), Some(right_value)) => left_value.cmp(right_value),
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, None) => std::cmp::Ordering::Equal,
            };

            let ordering = if key.reverse_order {
                ordering.reverse()
            } else {
                ordering
            };

            if ordering != std::cmp::Ordering::Equal {
                return ordering;
            }
        }

        normalize_search_dn(&left.dn).cmp(&normalize_search_dn(&right.dn))
    });
}

fn native_sort_value_for_key(
    entry: &crate::backend::DirectoryEntry,
    key: &SortKey,
) -> Option<String> {
    let attribute_name = key.attribute_type.to_ascii_lowercase();
    entry
        .attributes
        .get(&attribute_name)
        .and_then(|values| values.iter().map(|value| value.to_ascii_lowercase()).min())
}

fn native_search_done_controls(
    requested_sort: Option<&NativeServerSideSort>,
    result_code: ResultCode,
) -> Result<Vec<LdapControl>, String> {
    let Some(_requested_sort) = requested_sort else {
        return Ok(Vec::new());
    };

    let sort_result = if result_code == ResultCode::TimeLimitExceeded {
        ServerSideSortResultCode::TimeLimitExceeded
    } else {
        ServerSideSortResultCode::Success
    };
    Ok(vec![native_server_side_sort_response_control(
        sort_result,
        None,
    )?])
}

fn native_search_error_controls(
    requested_sort: Option<&NativeServerSideSort>,
    error: &SearchFsmError,
) -> Result<Vec<LdapControl>, String> {
    match error {
        SearchFsmError::SizeLimitExceeded => {
            native_search_done_controls(requested_sort, ResultCode::SizeLimitExceeded)
        }
        SearchFsmError::TimeLimitExceeded => {
            native_search_done_controls(requested_sort, ResultCode::TimeLimitExceeded)
        }
        _ => Ok(Vec::new()),
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_native_paged_search_continuation(
    fsm_set: &mut ConnectionFsmSet,
    request: &FsmRequestContext,
    request_context: &RequestContext,
    operation_registry: &mut ConnectionOperationRegistry,
    control: &PagedResultsControl,
    search_signature: &SearchRequestSignature,
    base_dn: &str,
    attribute_selection: &[String],
    types_only: bool,
    requested_time_limit: u32,
    requested_sort: Option<&NativeServerSideSort>,
) -> Result<(), String> {
    let Some(cursor) = operation_registry.paged_search(control.cookie.as_slice()) else {
        let session = legacy_session_from_fsm(fsm_set);
        reject_native_paged_search_request(
            fsm_set,
            request,
            request_context,
            &session,
            base_dn,
            NativePagedSearchError::InvalidCookie(
                "paged results cookie is not valid for this search sequence".to_string(),
            ),
        )
        .await?;
        return Ok(());
    };

    if &cursor.signature != search_signature {
        let session = legacy_session_from_fsm(fsm_set);
        reject_native_paged_search_request(
            fsm_set,
            request,
            request_context,
            &session,
            base_dn,
            NativePagedSearchError::InvalidCookie(
                "paged results cookie does not match the active search sequence".to_string(),
            ),
        )
        .await?;
        return Ok(());
    }

    if control.size == 0 {
        operation_registry.remove_paged_search(control.cookie.as_slice());
        increment_control_counter(request_context, "ldap_paged_search_abandoned_total", 1);
        let response_control = native_paged_results_response_control(0, &[])?;
        send_request_result_response_with_controls(
            fsm_set,
            request.message_id as u32,
            request.response_kind,
            ResultCode::Success,
            base_dn,
            "",
            &[response_control],
        )
        .await?;
        return Ok(());
    }

    let total_size = operation_registry
        .paged_search(control.cookie.as_slice())
        .map(|cursor| cursor.total_size() as usize)
        .unwrap_or_default();
    let (page_entries, result_code, diagnostic, complete) = operation_registry
        .paged_search_mut(control.cookie.as_slice())
        .expect("paged search cursor must exist after validation")
        .next_page(control.size as usize);
    if complete {
        operation_registry.remove_paged_search(control.cookie.as_slice());
    }

    let search_deadline = search_deadline_from_limit(requested_time_limit);
    let (returned, time_limit_hit) = emit_native_search_entries(
        fsm_set,
        request.message_id as u32,
        &page_entries,
        attribute_selection,
        types_only,
        search_deadline,
    )
    .await?;
    let _ = returned;
    increment_control_counter(request_context, "ldap_paged_search_pages_total", 1);

    let response_cookie = if complete || time_limit_hit {
        if time_limit_hit {
            operation_registry.remove_paged_search(control.cookie.as_slice());
        }
        Vec::new()
    } else {
        control.cookie.clone()
    };
    let response_control = native_paged_results_response_control(total_size, &response_cookie)?;
    let (result_code, diagnostic) = if time_limit_hit {
        (ResultCode::TimeLimitExceeded, "time limit exceeded")
    } else {
        (result_code, diagnostic)
    };
    let mut response_controls = vec![response_control];
    response_controls.extend(native_search_done_controls(requested_sort, result_code)?);
    send_request_result_response_with_controls(
        fsm_set,
        request.message_id as u32,
        request.response_kind,
        result_code,
        base_dn,
        diagnostic,
        &response_controls,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn handle_native_paged_search_initial(
    fsm_set: &mut ConnectionFsmSet,
    request: &FsmRequestContext,
    request_context: &RequestContext,
    operation_registry: &mut ConnectionOperationRegistry,
    control: &PagedResultsControl,
    search_signature: SearchRequestSignature,
    base_dn: &str,
    attribute_selection: &[String],
    types_only: bool,
    requested_sort: Option<&NativeServerSideSort>,
    entries: Vec<crate::backend::DirectoryEntry>,
    references: Vec<Vec<String>>,
    prepared_filter: &PreparedLdapFilter,
    index_covers_filter: bool,
    effective_time_limit: u32,
    size_limit: u32,
) -> Result<(), String> {
    let search_deadline = search_deadline_from_limit(effective_time_limit);
    let NativePagedSearchCollection {
        mut entries,
        size_limit_hit,
        time_limit_hit,
    } = match collect_native_paged_search_entries(
        entries,
        prepared_filter,
        index_covers_filter,
        size_limit,
        search_deadline,
    ) {
        Ok(collection) => collection,
        Err(diagnostic) => {
            send_request_result_response_with_controls(
                fsm_set,
                request.message_id as u32,
                request.response_kind,
                ResultCode::Unavailable,
                base_dn,
                &diagnostic,
                &[],
            )
            .await?;
            return Ok(());
        }
    };

    let page_size = control.size as usize;
    let total_size = entries.len();
    let (page_entries, response_cookie, result_code, diagnostic) = if time_limit_hit {
        (
            entries.into_iter().take(page_size).collect::<Vec<_>>(),
            Vec::new(),
            ResultCode::TimeLimitExceeded,
            "time limit exceeded",
        )
    } else if entries.len() > page_size {
        let remaining_entries = entries.split_off(page_size);
        let cursor = PagedSearchCursor::new(
            search_signature,
            total_size,
            remaining_entries,
            if size_limit_hit {
                ResultCode::SizeLimitExceeded
            } else {
                ResultCode::Success
            },
            if size_limit_hit {
                "size limit exceeded"
            } else {
                ""
            },
        );
        let cookie = operation_registry.remember_paged_search(cursor);
        increment_control_counter(request_context, "ldap_paged_search_sequences_total", 1);
        (entries, cookie, ResultCode::Success, "")
    } else if size_limit_hit {
        (
            entries,
            Vec::new(),
            ResultCode::SizeLimitExceeded,
            "size limit exceeded",
        )
    } else {
        (entries, Vec::new(), ResultCode::Success, "")
    };

    let (returned, emit_time_limit_hit) = emit_native_search_entries(
        fsm_set,
        request.message_id as u32,
        &page_entries,
        attribute_selection,
        types_only,
        search_deadline,
    )
    .await?;
    let _ = returned;
    emit_plain_search_references(fsm_set, request, request_context, &references).await?;
    increment_control_counter(request_context, "ldap_paged_search_pages_total", 1);

    let final_cookie = if emit_time_limit_hit {
        if !response_cookie.is_empty() {
            operation_registry.remove_paged_search(response_cookie.as_slice());
        }
        Vec::new()
    } else {
        response_cookie
    };
    let response_control = native_paged_results_response_control(total_size, &final_cookie)?;
    let (result_code, diagnostic) = if emit_time_limit_hit {
        (ResultCode::TimeLimitExceeded, "time limit exceeded")
    } else {
        (result_code, diagnostic)
    };
    let mut response_controls = vec![response_control];
    response_controls.extend(native_search_done_controls(requested_sort, result_code)?);
    send_request_result_response_with_controls(
        fsm_set,
        request.message_id as u32,
        request.response_kind,
        result_code,
        base_dn,
        diagnostic,
        &response_controls,
    )
    .await
}

struct NativePagedSearchCollection {
    entries: Vec<crate::backend::DirectoryEntry>,
    size_limit_hit: bool,
    time_limit_hit: bool,
}

fn collect_native_paged_search_entries(
    entries: Vec<crate::backend::DirectoryEntry>,
    prepared_filter: &PreparedLdapFilter,
    index_covers_filter: bool,
    size_limit: u32,
    search_deadline: Option<Instant>,
) -> Result<NativePagedSearchCollection, String> {
    let mut collected = Vec::new();
    let mut returned_dns = HashSet::new();
    let mut size_limit_hit = false;
    let mut time_limit_hit = false;

    for entry in entries {
        if search_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            time_limit_hit = true;
            break;
        }

        let search_entry = directory_entry_to_search_entry(&entry);
        if !index_covers_filter
            && !prepared_filter
                .matches_search_entry(&search_entry)
                .map_err(|err| err.to_string())?
        {
            continue;
        }

        if !returned_dns.insert(normalize_search_dn(&entry.dn)) {
            continue;
        }

        if size_limit != 0 && collected.len() >= size_limit as usize {
            size_limit_hit = true;
            break;
        }

        collected.push(entry);
    }

    if !time_limit_hit && search_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        time_limit_hit = true;
    }

    Ok(NativePagedSearchCollection {
        entries: collected,
        size_limit_hit,
        time_limit_hit,
    })
}

fn search_deadline_from_limit(time_limit: u32) -> Option<Instant> {
    (time_limit != 0).then(|| Instant::now() + Duration::from_secs(time_limit as u64))
}

async fn emit_native_search_entries(
    fsm_set: &mut ConnectionFsmSet,
    message_id: u32,
    entries: &[crate::backend::DirectoryEntry],
    attribute_selection: &[String],
    types_only: bool,
    search_deadline: Option<Instant>,
) -> Result<(usize, bool), String> {
    let mut formatter = ProductionEntryFormatter::with_request(message_id, types_only);
    let mut pending_bytes = Vec::new();
    let mut returned = 0usize;

    for entry in entries {
        if search_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            break;
        }

        let search_entry = directory_entry_to_search_entry(entry);
        let encoded = formatter
            .format_entry(&search_entry, attribute_selection)
            .await?;
        pending_bytes.extend_from_slice(&encoded);
        returned += 1;

        if search_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            let stream = fsm_set
                .connection_mut()
                .stream_mut()
                .ok_or("No active stream")?;
            if !pending_bytes.is_empty() {
                stream
                    .write_all(&pending_bytes)
                    .await
                    .map_err(|err| format!("Write error: {err}"))?;
            }
            return Ok((returned, true));
        }
    }

    if !pending_bytes.is_empty() {
        let stream = fsm_set
            .connection_mut()
            .stream_mut()
            .ok_or("No active stream")?;
        stream
            .write_all(&pending_bytes)
            .await
            .map_err(|err| format!("Write error: {err}"))?;
    }

    Ok((
        returned,
        search_deadline.is_some_and(|deadline| Instant::now() >= deadline),
    ))
}

async fn resolve_plain_search_alias_candidates(
    backend: &dyn DirectoryBackend,
    entries: Vec<crate::backend::DirectoryEntry>,
    deref_aliases: ldap_parser::ldap::DerefAliases,
) -> Result<Vec<crate::backend::DirectoryEntry>, PlainSearchAliasError> {
    if !matches!(deref_aliases.0, 1 | 3) {
        return Ok(entries);
    }

    let mut resolved_entries = Vec::with_capacity(entries.len());
    for entry in entries {
        let target_dn = entry.dn.clone();
        let resolved = resolve_search_candidate_entry(backend, &entry, deref_aliases)
            .await
            .map_err(|(result_code, diagnostic)| PlainSearchAliasError {
                target_dn,
                result_code,
                diagnostic,
            })?;
        resolved_entries.push(resolved);
    }

    Ok(resolved_entries)
}

fn prepare_plain_search_referrals(
    entries: Vec<crate::backend::DirectoryEntry>,
    scope: ldap_parser::ldap::SearchScope,
) -> Result<PlainSearchReferralDisposition, PlainSearchReferralError> {
    if scope == ldap_parser::ldap::SearchScope::BaseObject {
        if let Some(entry) = entries
            .first()
            .filter(|entry| directory_entry_is_referral(entry))
        {
            let referrals =
                referral_urls_for_entry(entry).map_err(|diagnostic| PlainSearchReferralError {
                    target_dn: entry.dn.clone(),
                    diagnostic,
                })?;
            return Ok(PlainSearchReferralDisposition::BaseReferral {
                dn: entry.dn.clone(),
                referrals,
            });
        }

        return Ok(PlainSearchReferralDisposition::SearchEntries {
            entries,
            references: Vec::new(),
        });
    }

    let mut searchable_entries = Vec::with_capacity(entries.len());
    let mut references = Vec::new();
    for entry in entries {
        if directory_entry_is_referral(&entry) {
            let referrals =
                referral_urls_for_entry(&entry).map_err(|diagnostic| PlainSearchReferralError {
                    target_dn: entry.dn.clone(),
                    diagnostic,
                })?;
            references.push(referrals);
        } else {
            searchable_entries.push(entry);
        }
    }

    Ok(PlainSearchReferralDisposition::SearchEntries {
        entries: searchable_entries,
        references,
    })
}

async fn emit_plain_search_references(
    fsm_set: &mut ConnectionFsmSet,
    request: &FsmRequestContext,
    request_context: &RequestContext,
    references: &[Vec<String>],
) -> Result<(), String> {
    if references.is_empty() {
        return Ok(());
    }

    let stream = fsm_set
        .connection_mut()
        .stream_mut()
        .ok_or("No active stream")?;
    for referrals in references {
        let encoded =
            encode_search_reference_with_controls(request.message_id as u32, referrals, &[])
                .map_err(|err| format!("Encode error: {err:?}"))?;
        stream
            .write_all(&encoded)
            .await
            .map_err(|err| format!("Write error: {err}"))?;
    }
    increment_control_counter(
        request_context,
        "ldap_search_references_total",
        references.len() as u64,
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn emit_projected_index_covered_plain_search_stream(
    fsm_set: &mut ConnectionFsmSet,
    request: &FsmRequestContext,
    request_context: &RequestContext,
    metrics: Option<&MetricsCollector>,
    mut entries: ProjectedSearchEntryStreamReceiver,
    manage_dsa_it: bool,
    scope: ldap_parser::ldap::SearchScope,
    types_only: bool,
    started_at: Instant,
    time_limit: u32,
    size_limit: u32,
) -> Result<(), String> {
    let effective_size_limit = (size_limit != 0).then_some(size_limit as usize);
    let mut pending_entry_bytes = Vec::with_capacity(FSM_SEARCH_ENTRY_WRITE_BATCH_BYTES);
    let mut emitted_entries = 0usize;
    let mut search_references = Vec::new();

    record_streaming_direct_search_start(metrics);

    while let Some(entry_result) = entries.recv().await {
        if search_time_limit_exceeded(started_at, time_limit) {
            flush_fsm_search_entry_batch(fsm_set, &mut pending_entry_bytes).await?;
            record_direct_search_complete(metrics, emitted_entries, started_at, false);
            send_request_result_response(
                fsm_set,
                request.message_id as u32,
                request.response_kind,
                ResultCode::TimeLimitExceeded,
                "time limit exceeded",
            )
            .await?;
            return Ok(());
        }

        let entry = match entry_result {
            Ok(entry) => entry,
            Err(err) => {
                flush_fsm_search_entry_batch(fsm_set, &mut pending_entry_bytes).await?;
                record_direct_search_complete(metrics, emitted_entries, started_at, false);
                send_request_result_response(
                    fsm_set,
                    request.message_id as u32,
                    request.response_kind,
                    map_backend_error_code(&err),
                    backend_diagnostic(&err),
                )
                .await?;
                return Ok(());
            }
        };

        if !manage_dsa_it && entry.is_referral() {
            let referrals = match referral_urls_for_projected_entry(&entry) {
                Ok(referrals) => referrals,
                Err(diagnostic) => {
                    flush_fsm_search_entry_batch(fsm_set, &mut pending_entry_bytes).await?;
                    record_direct_search_complete(metrics, emitted_entries, started_at, false);
                    send_request_result_response(
                        fsm_set,
                        request.message_id as u32,
                        request.response_kind,
                        ResultCode::OperationsError,
                        &diagnostic,
                    )
                    .await?;
                    return Ok(());
                }
            };

            if scope == ldap_parser::ldap::SearchScope::BaseObject {
                flush_fsm_search_entry_batch(fsm_set, &mut pending_entry_bytes).await?;
                increment_control_counter(request_context, "ldap_referral_results_total", 1);
                record_direct_search_complete(metrics, emitted_entries, started_at, true);
                send_request_result_response_with_referrals(
                    fsm_set,
                    request.message_id as u32,
                    request.response_kind,
                    ResultCode::Referral,
                    &entry.dn,
                    "search base is a referral",
                    &referrals,
                )
                .await?;
                return Ok(());
            }

            search_references.push(referrals);
            continue;
        }

        if effective_size_limit.is_some_and(|limit| emitted_entries >= limit) {
            flush_fsm_search_entry_batch(fsm_set, &mut pending_entry_bytes).await?;
            record_direct_search_complete(metrics, emitted_entries, started_at, false);
            send_request_result_response(
                fsm_set,
                request.message_id as u32,
                request.response_kind,
                ResultCode::SizeLimitExceeded,
                "size limit exceeded",
            )
            .await?;
            return Ok(());
        }

        let encoded_entry = encode_search_entry_parts_with_controls(
            request.message_id as u32,
            &entry.dn,
            &entry.attributes,
            types_only,
            &[],
        )
        .map_err(|err| format!("failed to encode search entry: {err:?}"))?;
        pending_entry_bytes.extend(encoded_entry);
        emitted_entries += 1;

        if pending_entry_bytes.len() >= FSM_SEARCH_ENTRY_WRITE_BATCH_BYTES {
            flush_fsm_search_entry_batch(fsm_set, &mut pending_entry_bytes).await?;
        }
    }

    flush_fsm_search_entry_batch(fsm_set, &mut pending_entry_bytes).await?;
    emit_plain_search_references(fsm_set, request, request_context, &search_references).await?;
    let response_controls = native_search_done_controls(None, ResultCode::Success)?;
    record_direct_search_complete(metrics, emitted_entries, started_at, true);
    send_request_result_response_with_controls(
        fsm_set,
        request.message_id as u32,
        request.response_kind,
        ResultCode::Success,
        "",
        "",
        &response_controls,
    )
    .await
}

fn referral_urls_for_projected_entry(
    entry: &ProjectedDirectoryEntry,
) -> Result<Vec<String>, String> {
    let urls = entry
        .referral_urls
        .clone()
        .ok_or_else(|| format!("referral entry {} is missing ref URLs", entry.dn))?;
    if urls.is_empty() {
        return Err(format!(
            "referral entry {} does not contain any ref URLs",
            entry.dn
        ));
    }

    let resolver = LdapReferralResolver::default();
    for url in &urls {
        resolver.validate_referral_url(url).map_err(|err| {
            format!(
                "referral entry {} contains invalid LDAP URL {}: {}",
                entry.dn, url, err
            )
        })?;
    }

    Ok(urls)
}

#[allow(clippy::too_many_arguments)]
async fn emit_index_covered_plain_search_stream(
    fsm_set: &mut ConnectionFsmSet,
    request: &FsmRequestContext,
    request_context: &RequestContext,
    metrics: Option<&MetricsCollector>,
    mut entries: SearchEntryStreamReceiver,
    manage_dsa_it: bool,
    scope: ldap_parser::ldap::SearchScope,
    requested_attributes: &[String],
    types_only: bool,
    started_at: Instant,
    time_limit: u32,
    size_limit: u32,
) -> Result<(), String> {
    let projection = DirectoryAttributeProjection::new(requested_attributes);
    let effective_size_limit = (size_limit != 0).then_some(size_limit as usize);
    let mut pending_entry_bytes = Vec::with_capacity(FSM_SEARCH_ENTRY_WRITE_BATCH_BYTES);
    let mut emitted_entries = 0usize;
    let mut search_references = Vec::new();

    record_streaming_direct_search_start(metrics);

    while let Some(entry_result) = entries.recv().await {
        if search_time_limit_exceeded(started_at, time_limit) {
            flush_fsm_search_entry_batch(fsm_set, &mut pending_entry_bytes).await?;
            record_direct_search_complete(metrics, emitted_entries, started_at, false);
            send_request_result_response(
                fsm_set,
                request.message_id as u32,
                request.response_kind,
                ResultCode::TimeLimitExceeded,
                "time limit exceeded",
            )
            .await?;
            return Ok(());
        }

        let entry = match entry_result {
            Ok(entry) => entry,
            Err(err) => {
                flush_fsm_search_entry_batch(fsm_set, &mut pending_entry_bytes).await?;
                record_direct_search_complete(metrics, emitted_entries, started_at, false);
                send_request_result_response(
                    fsm_set,
                    request.message_id as u32,
                    request.response_kind,
                    map_backend_error_code(&err),
                    backend_diagnostic(&err),
                )
                .await?;
                return Ok(());
            }
        };

        if !manage_dsa_it && directory_entry_is_referral(&entry) {
            let referrals = match referral_urls_for_entry(&entry) {
                Ok(referrals) => referrals,
                Err(diagnostic) => {
                    flush_fsm_search_entry_batch(fsm_set, &mut pending_entry_bytes).await?;
                    record_direct_search_complete(metrics, emitted_entries, started_at, false);
                    send_request_result_response(
                        fsm_set,
                        request.message_id as u32,
                        request.response_kind,
                        ResultCode::OperationsError,
                        &diagnostic,
                    )
                    .await?;
                    return Ok(());
                }
            };

            if scope == ldap_parser::ldap::SearchScope::BaseObject {
                flush_fsm_search_entry_batch(fsm_set, &mut pending_entry_bytes).await?;
                increment_control_counter(request_context, "ldap_referral_results_total", 1);
                record_direct_search_complete(metrics, emitted_entries, started_at, true);
                send_request_result_response_with_referrals(
                    fsm_set,
                    request.message_id as u32,
                    request.response_kind,
                    ResultCode::Referral,
                    &entry.dn,
                    "search base is a referral",
                    &referrals,
                )
                .await?;
                return Ok(());
            }

            search_references.push(referrals);
            continue;
        }

        if effective_size_limit.is_some_and(|limit| emitted_entries >= limit) {
            flush_fsm_search_entry_batch(fsm_set, &mut pending_entry_bytes).await?;
            record_direct_search_complete(metrics, emitted_entries, started_at, false);
            send_request_result_response(
                fsm_set,
                request.message_id as u32,
                request.response_kind,
                ResultCode::SizeLimitExceeded,
                "size limit exceeded",
            )
            .await?;
            return Ok(());
        }

        let selected_attributes = projection.project_entry(&entry);
        let encoded_entry = encode_search_entry_parts_with_controls(
            request.message_id as u32,
            &entry.dn,
            &selected_attributes,
            types_only,
            &[],
        )
        .map_err(|err| format!("failed to encode search entry: {err:?}"))?;
        pending_entry_bytes.extend(encoded_entry);
        emitted_entries += 1;

        if pending_entry_bytes.len() >= FSM_SEARCH_ENTRY_WRITE_BATCH_BYTES {
            flush_fsm_search_entry_batch(fsm_set, &mut pending_entry_bytes).await?;
        }
    }

    flush_fsm_search_entry_batch(fsm_set, &mut pending_entry_bytes).await?;
    emit_plain_search_references(fsm_set, request, request_context, &search_references).await?;
    let response_controls = native_search_done_controls(None, ResultCode::Success)?;
    record_direct_search_complete(metrics, emitted_entries, started_at, true);
    send_request_result_response_with_controls(
        fsm_set,
        request.message_id as u32,
        request.response_kind,
        ResultCode::Success,
        "",
        "",
        &response_controls,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn emit_filtering_plain_search_stream(
    fsm_set: &mut ConnectionFsmSet,
    request: &FsmRequestContext,
    request_context: &RequestContext,
    metrics: Option<&MetricsCollector>,
    mut entries: SearchEntryStreamReceiver,
    manage_dsa_it: bool,
    scope: ldap_parser::ldap::SearchScope,
    requested_attributes: &[String],
    types_only: bool,
    started_at: Instant,
    time_limit: u32,
    size_limit: u32,
    prepared_filter: &PreparedLdapFilter,
) -> Result<(), String> {
    let projection = DirectoryAttributeProjection::new(requested_attributes);
    let effective_size_limit = (size_limit != 0).then_some(size_limit as usize);
    let mut pending_entry_bytes = Vec::with_capacity(FSM_SEARCH_ENTRY_WRITE_BATCH_BYTES);
    let mut emitted_entries = 0usize;
    let mut returned_dns = HashSet::new();
    let mut search_references = Vec::new();

    record_streaming_direct_search_start(metrics);

    while let Some(entry_result) = entries.recv().await {
        if search_time_limit_exceeded(started_at, time_limit) {
            flush_fsm_search_entry_batch(fsm_set, &mut pending_entry_bytes).await?;
            record_direct_search_complete(metrics, emitted_entries, started_at, false);
            send_request_result_response(
                fsm_set,
                request.message_id as u32,
                request.response_kind,
                ResultCode::TimeLimitExceeded,
                "time limit exceeded",
            )
            .await?;
            return Ok(());
        }

        let entry = match entry_result {
            Ok(entry) => entry,
            Err(err) => {
                flush_fsm_search_entry_batch(fsm_set, &mut pending_entry_bytes).await?;
                record_direct_search_complete(metrics, emitted_entries, started_at, false);
                send_request_result_response(
                    fsm_set,
                    request.message_id as u32,
                    request.response_kind,
                    map_backend_error_code(&err),
                    backend_diagnostic(&err),
                )
                .await?;
                return Ok(());
            }
        };

        if !manage_dsa_it && directory_entry_is_referral(&entry) {
            let referrals = match referral_urls_for_entry(&entry) {
                Ok(referrals) => referrals,
                Err(diagnostic) => {
                    flush_fsm_search_entry_batch(fsm_set, &mut pending_entry_bytes).await?;
                    record_direct_search_complete(metrics, emitted_entries, started_at, false);
                    send_request_result_response(
                        fsm_set,
                        request.message_id as u32,
                        request.response_kind,
                        ResultCode::OperationsError,
                        &diagnostic,
                    )
                    .await?;
                    return Ok(());
                }
            };

            if scope == ldap_parser::ldap::SearchScope::BaseObject {
                flush_fsm_search_entry_batch(fsm_set, &mut pending_entry_bytes).await?;
                increment_control_counter(request_context, "ldap_referral_results_total", 1);
                record_direct_search_complete(metrics, emitted_entries, started_at, true);
                send_request_result_response_with_referrals(
                    fsm_set,
                    request.message_id as u32,
                    request.response_kind,
                    ResultCode::Referral,
                    &entry.dn,
                    "search base is a referral",
                    &referrals,
                )
                .await?;
                return Ok(());
            }

            search_references.push(referrals);
            continue;
        }

        let search_entry = directory_entry_to_search_entry(&entry);
        if !prepared_filter
            .matches_search_entry(&search_entry)
            .map_err(|err| err.to_string())?
        {
            continue;
        }

        if !returned_dns.insert(normalize_search_dn(&entry.dn)) {
            continue;
        }

        if effective_size_limit.is_some_and(|limit| emitted_entries >= limit) {
            flush_fsm_search_entry_batch(fsm_set, &mut pending_entry_bytes).await?;
            record_direct_search_complete(metrics, emitted_entries, started_at, false);
            send_request_result_response(
                fsm_set,
                request.message_id as u32,
                request.response_kind,
                ResultCode::SizeLimitExceeded,
                "size limit exceeded",
            )
            .await?;
            return Ok(());
        }

        let selected_attributes = projection.project_entry(&entry);
        let encoded_entry = encode_search_entry_parts_with_controls(
            request.message_id as u32,
            &entry.dn,
            &selected_attributes,
            types_only,
            &[],
        )
        .map_err(|err| format!("failed to encode search entry: {err:?}"))?;
        pending_entry_bytes.extend(encoded_entry);
        emitted_entries += 1;

        if pending_entry_bytes.len() >= FSM_SEARCH_ENTRY_WRITE_BATCH_BYTES {
            flush_fsm_search_entry_batch(fsm_set, &mut pending_entry_bytes).await?;
        }
    }

    flush_fsm_search_entry_batch(fsm_set, &mut pending_entry_bytes).await?;
    emit_plain_search_references(fsm_set, request, request_context, &search_references).await?;
    let response_controls = native_search_done_controls(None, ResultCode::Success)?;
    record_direct_search_complete(metrics, emitted_entries, started_at, true);
    send_request_result_response_with_controls(
        fsm_set,
        request.message_id as u32,
        request.response_kind,
        ResultCode::Success,
        "",
        "",
        &response_controls,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn emit_index_covered_plain_search(
    fsm_set: &mut ConnectionFsmSet,
    request: &FsmRequestContext,
    request_context: &RequestContext,
    metrics: Option<&MetricsCollector>,
    entries: Vec<DirectoryEntry>,
    references: &[Vec<String>],
    requested_attributes: &[String],
    types_only: bool,
    started_at: Instant,
    time_limit: u32,
    size_limit: u32,
) -> Result<(), String> {
    let projection = DirectoryAttributeProjection::new(requested_attributes);
    let effective_size_limit = (size_limit != 0).then_some(size_limit as usize);
    let mut pending_entry_bytes = Vec::with_capacity(FSM_SEARCH_ENTRY_WRITE_BATCH_BYTES);
    let mut emitted_entries = 0usize;

    record_direct_search_start(metrics, entries.len());

    for entry in entries {
        if search_time_limit_exceeded(started_at, time_limit) {
            flush_fsm_search_entry_batch(fsm_set, &mut pending_entry_bytes).await?;
            record_direct_search_complete(metrics, emitted_entries, started_at, false);
            send_request_result_response(
                fsm_set,
                request.message_id as u32,
                request.response_kind,
                ResultCode::TimeLimitExceeded,
                "time limit exceeded",
            )
            .await?;
            return Ok(());
        }

        if effective_size_limit.is_some_and(|limit| emitted_entries >= limit) {
            flush_fsm_search_entry_batch(fsm_set, &mut pending_entry_bytes).await?;
            record_direct_search_complete(metrics, emitted_entries, started_at, false);
            send_request_result_response(
                fsm_set,
                request.message_id as u32,
                request.response_kind,
                ResultCode::SizeLimitExceeded,
                "size limit exceeded",
            )
            .await?;
            return Ok(());
        }

        let selected_attributes = projection.project_entry(&entry);
        let encoded_entry = encode_search_entry_parts_with_controls(
            request.message_id as u32,
            &entry.dn,
            &selected_attributes,
            types_only,
            &[],
        )
        .map_err(|err| format!("failed to encode search entry: {err:?}"))?;
        pending_entry_bytes.extend(encoded_entry);
        emitted_entries += 1;

        if pending_entry_bytes.len() >= FSM_SEARCH_ENTRY_WRITE_BATCH_BYTES {
            flush_fsm_search_entry_batch(fsm_set, &mut pending_entry_bytes).await?;
        }
    }

    flush_fsm_search_entry_batch(fsm_set, &mut pending_entry_bytes).await?;
    emit_plain_search_references(fsm_set, request, request_context, references).await?;
    let response_controls = native_search_done_controls(None, ResultCode::Success)?;
    record_direct_search_complete(metrics, emitted_entries, started_at, true);
    send_request_result_response_with_controls(
        fsm_set,
        request.message_id as u32,
        request.response_kind,
        ResultCode::Success,
        "",
        "",
        &response_controls,
    )
    .await
}

fn search_time_limit_exceeded(started_at: Instant, time_limit: u32) -> bool {
    time_limit != 0 && started_at.elapsed() > Duration::from_secs(time_limit as u64)
}

fn record_direct_search_start(metrics: Option<&MetricsCollector>, candidates: usize) {
    let Some(metrics) = metrics else {
        return;
    };
    metrics.record_operation_start(MetricsOperationType::Search, "");
    metrics.record_fsm_state(FsmType::Search, "searching");
    metrics.increment_counter("ldap_search_candidates_found", candidates as u64);
    metrics.increment_counter("ldap_search_entries_seen", candidates as u64);
    metrics.increment_counter("ldap_search_entries_matched", candidates as u64);
}

fn record_streaming_direct_search_start(metrics: Option<&MetricsCollector>) {
    let Some(metrics) = metrics else {
        return;
    };
    metrics.record_operation_start(MetricsOperationType::Search, "");
    metrics.record_fsm_state(FsmType::Search, "searching");
}

fn record_direct_search_complete(
    metrics: Option<&MetricsCollector>,
    entries_sent: usize,
    started_at: Instant,
    success: bool,
) {
    let Some(metrics) = metrics else {
        return;
    };
    metrics.record_operation_complete(MetricsOperationType::Search, started_at.elapsed(), success);
    metrics.set_gauge("ldap_search_entries_sent", entries_sent as u64);
    metrics.record_fsm_state(
        FsmType::Search,
        if success {
            "completed"
        } else {
            "completed_with_error"
        },
    );
}

async fn try_handle_virtual_search_request_with_fsm_runtime(
    fsm_set: &mut ConnectionFsmSet,
    request: &FsmRequestContext,
    search_req: &ldap_parser::ldap::SearchRequest<'_>,
    schema: &LdapSchema,
    request_context: &RequestContext,
    runtime_context: &FsmServerRuntimeContext,
) -> Result<bool, String> {
    if search_req.scope != ldap_parser::ldap::SearchScope::BaseObject {
        return Ok(false);
    }

    let base_dn = search_req.base_object.0.as_ref().trim();
    if !base_dn.is_empty()
        && !base_dn.eq_ignore_ascii_case(&runtime_context.legacy_runtime_config.subschema_dn)
    {
        return Ok(false);
    }

    if !native_search_control_oids_supported(&request.request_controls) {
        return Ok(false);
    }

    let session = legacy_session_from_fsm(fsm_set);
    let manage_dsa_it = match parse_native_manage_dsa_it_request(&request.request_controls) {
        Ok(manage_dsa_it) => manage_dsa_it,
        Err(diagnostic) => {
            send_request_result_response_with_referrals(
                fsm_set,
                request.message_id as u32,
                request.response_kind,
                ResultCode::ProtocolError,
                base_dn,
                &diagnostic,
                &[],
            )
            .await?;
            return Ok(true);
        }
    };
    if manage_dsa_it {
        increment_control_counter(request_context, "ldap_manage_dsa_it_requests_total", 1);
    }

    let requested_sort = match parse_native_server_side_sort_request(&request.request_controls) {
        Ok(requested_sort) => requested_sort,
        Err(error) => {
            reject_native_server_side_sort_request(
                fsm_set,
                request,
                request_context,
                &session,
                base_dn,
                error,
            )
            .await?;
            return Ok(true);
        }
    };
    if requested_sort.is_some() {
        increment_control_counter(request_context, "ldap_sort_requests_total", 1);
    }

    let paged_results = match parse_native_paged_results_request(&request.request_controls) {
        Ok(paged_results) => paged_results,
        Err(error) => {
            reject_native_paged_search_request(
                fsm_set,
                request,
                request_context,
                &session,
                base_dn,
                error,
            )
            .await?;
            return Ok(true);
        }
    };
    if paged_results.is_some() {
        increment_control_counter(request_context, "ldap_paged_search_requests_total", 1);
    }

    let requested_sync = match parse_sync_request_control(&request.request_controls) {
        Ok(requested_sync) => requested_sync,
        Err(error) => {
            let stream = fsm_set
                .connection_mut()
                .stream_mut()
                .ok_or("No active stream")?;
            reject_sync_request(stream, request.message_id as u32, base_dn, &error)
                .await
                .map_err(|err| err.to_string())?;
            return Ok(true);
        }
    };
    if requested_sync.is_some() {
        increment_control_counter(request_context, "ldap_sync_requests_total", 1);
        let error = SyncRequestError::Unsupported(
            "sync request control is not supported for virtual search bases".to_string(),
        );
        let stream = fsm_set
            .connection_mut()
            .stream_mut()
            .ok_or("No active stream")?;
        reject_sync_request(stream, request.message_id as u32, base_dn, &error)
            .await
            .map_err(|err| err.to_string())?;
        return Ok(true);
    }

    if let Some(control) = paged_results.as_ref() {
        if control.size == 0 && control.cookie.is_empty() {
            reject_native_paged_search_request(
                fsm_set,
                request,
                request_context,
                &session,
                base_dn,
                NativePagedSearchError::ProtocolError(
                    "paged results page size must be greater than zero on the initial request"
                        .to_string(),
                ),
            )
            .await?;
            return Ok(true);
        }

        if !control.cookie.is_empty() {
            reject_native_paged_search_request(
                fsm_set,
                request,
                request_context,
                &session,
                base_dn,
                NativePagedSearchError::InvalidCookie(
                    "paged results cookie is not valid for this search sequence".to_string(),
                ),
            )
            .await?;
            return Ok(true);
        }
    }

    let requested_attributes: Vec<String> = search_req
        .attributes
        .iter()
        .map(|attribute| attribute.0.as_ref().trim().to_owned())
        .collect();

    let available_attributes = if base_dn.is_empty() {
        let supported_control_oids =
            crate::fsm_request::active_fsm_control_registry().supported_control_oids();
        match crate::search_protocol::build_root_dse_attributes(
            fsm_set.backend().as_ref(),
            &runtime_context.legacy_runtime_config.naming_contexts,
            &runtime_context.legacy_runtime_config.subschema_dn,
            request.is_secure,
            runtime_context.tls_handler.is_some(),
            &supported_control_oids,
            &crate::search_protocol::supported_fsm_sasl_mechanisms(),
        )
        .await
        {
            Ok(attributes) => attributes,
            Err(err) => {
                send_request_result_response(
                    fsm_set,
                    request.message_id as u32,
                    request.response_kind,
                    map_backend_error_code(&err),
                    backend_diagnostic(&err),
                )
                .await?;
                return Ok(true);
            }
        }
    } else if base_dn.eq_ignore_ascii_case(&runtime_context.legacy_runtime_config.subschema_dn) {
        crate::search_protocol::build_subschema_attributes(schema)
    } else {
        return Ok(false);
    };

    let selected_attributes = crate::search_protocol::select_virtual_attributes(
        &available_attributes,
        &requested_attributes,
    );
    let synthetic_entry = crate::backend::DirectoryEntry::new(base_dn, HashMap::new());
    let encoded = crate::parser::encode_search_entry(
        request.message_id as u32,
        &synthetic_entry,
        &selected_attributes,
        search_req.types_only,
    )
    .map_err(|err| format!("failed to encode virtual search entry: {err:?}"))?;

    let stream = fsm_set
        .connection_mut()
        .stream_mut()
        .ok_or("No active stream")?;
    stream
        .write_all(&encoded)
        .await
        .map_err(|err| format!("Write error: {err}"))?;
    let mut response_controls =
        native_search_done_controls(requested_sort.as_ref(), ResultCode::Success)?;
    if paged_results.is_some() {
        response_controls.push(native_paged_results_response_control(1, &[])?);
        increment_control_counter(request_context, "ldap_paged_search_pages_total", 1);
    }
    send_request_result_response_with_controls(
        fsm_set,
        request.message_id as u32,
        request.response_kind,
        ResultCode::Success,
        "",
        "",
        &response_controls,
    )
    .await?;
    Ok(true)
}

fn native_search_control_oids_supported(
    request_controls: &crate::ldap_controls::RequestControls,
) -> bool {
    request_controls.iter().all(|control| {
        control.oid().eq_ignore_ascii_case(MANAGE_DSA_IT_OID)
            || control.oid().eq_ignore_ascii_case(PAGED_RESULTS_OID)
            || control
                .oid()
                .eq_ignore_ascii_case(SERVER_SIDE_SORT_REQUEST_OID)
            || control.oid().eq_ignore_ascii_case(SYNC_REQUEST_OID)
    })
}

fn build_preloaded_search_fsm(
    entries: Vec<crate::backend::DirectoryEntry>,
    schema: &LdapSchema,
    prepared_filter: Option<(String, PreparedLdapFilter, bool)>,
    metrics: Option<Arc<MetricsCollector>>,
    message_id: u32,
    types_only: bool,
) -> SearchFsmImpl {
    let candidate_count = entries.len().max(1);
    let config = SearchFsmConfig {
        default_size_limit: u32::MAX,
        default_time_limit: 0,
        max_size_limit: u32::MAX,
        max_time_limit: u32::MAX,
        max_candidates: candidate_count,
        candidate_batch_size: 100,
    };

    let backend = Box::new(PreloadedSearchBackend::new(entries));
    let filter_matcher = Box::new(match prepared_filter {
        Some((filter, prepared_filter, true)) => {
            ProductionFilterMatcher::with_index_covered_prepared_filter(
                schema.clone(),
                filter,
                prepared_filter,
            )
        }
        Some((filter, prepared_filter, false)) => {
            ProductionFilterMatcher::with_schema_and_prepared_filter(
                schema.clone(),
                filter,
                prepared_filter,
            )
        }
        None => ProductionFilterMatcher::with_schema(schema.clone()),
    });
    let entry_formatter = Box::new(ProductionEntryFormatter::with_request(
        message_id, types_only,
    ));
    let mut fsm = SearchFsmImpl::with_config(backend, filter_matcher, entry_formatter, config);

    if let Some(metrics) = metrics {
        fsm = fsm.with_metrics(Box::new(ProductionSearchMetrics::new(metrics)));
    }

    fsm
}

fn search_fsm_error_response(error: &SearchFsmError) -> (ResultCode, String) {
    match error {
        SearchFsmError::InvalidParameters { message } => {
            (ResultCode::ProtocolError, message.clone())
        }
        SearchFsmError::TimeLimitExceeded => (
            ResultCode::TimeLimitExceeded,
            "time limit exceeded".to_string(),
        ),
        SearchFsmError::SizeLimitExceeded => (
            ResultCode::SizeLimitExceeded,
            "size limit exceeded".to_string(),
        ),
        SearchFsmError::BackendError { message }
        | SearchFsmError::FilterError { message }
        | SearchFsmError::FormattingError { message }
        | SearchFsmError::Generic { message } => (ResultCode::Unavailable, message.clone()),
        SearchFsmError::Abandoned
        | SearchFsmError::InvalidStateTransition { .. }
        | SearchFsmError::NoActiveSearch => (ResultCode::OperationsError, error.to_string()),
    }
}

fn directory_entry_to_search_entry(entry: &crate::backend::DirectoryEntry) -> SearchEntry {
    let mut combined_attrs = entry.attributes.clone();
    combined_attrs.extend(entry.operational_attributes.to_attributes());

    SearchEntry {
        dn: entry.dn.clone(),
        attributes: combined_attrs,
        object_classes: entry
            .attributes
            .get("objectclass")
            .cloned()
            .unwrap_or_default(),
    }
}

fn normalize_search_dn(dn: &str) -> String {
    dn.trim().to_ascii_lowercase()
}

fn remaining_time_limit(started_at: Instant, requested_time_limit: u32) -> Option<u32> {
    if requested_time_limit == 0 {
        return Some(0);
    }

    let elapsed = started_at.elapsed().as_secs();
    if elapsed >= requested_time_limit as u64 {
        None
    } else {
        Some(requested_time_limit - elapsed as u32)
    }
}

fn render_search_filter_string(filter: &Filter<'_>) -> String {
    match filter {
        Filter::And(filters) => format!(
            "(&{})",
            filters
                .iter()
                .map(render_search_filter_string)
                .collect::<String>()
        ),
        Filter::Or(filters) => format!(
            "(|{})",
            filters
                .iter()
                .map(render_search_filter_string)
                .collect::<String>()
        ),
        Filter::Not(filter) => format!("(!{})", render_search_filter_string(filter)),
        Filter::EqualityMatch(ava) => format!(
            "({}={})",
            ava.attribute_desc.0.as_ref(),
            escape_filter_value(&ava.assertion_value)
        ),
        Filter::Substrings(substring) => format!(
            "({}={})",
            substring.filter_type.0.as_ref(),
            render_substring_filter(&substring.substrings)
        ),
        Filter::GreaterOrEqual(ava) => format!(
            "({}>={})",
            ava.attribute_desc.0.as_ref(),
            escape_filter_value(&ava.assertion_value)
        ),
        Filter::LessOrEqual(ava) => format!(
            "({}<={})",
            ava.attribute_desc.0.as_ref(),
            escape_filter_value(&ava.assertion_value)
        ),
        Filter::Present(attribute) => format!("({}=*)", attribute.0.as_ref()),
        Filter::ApproxMatch(ava) => format!(
            "({}~={})",
            ava.attribute_desc.0.as_ref(),
            escape_filter_value(&ava.assertion_value)
        ),
        Filter::ExtensibleMatch(assertion) => {
            let mut head = String::new();
            if let Some(rule_type) = assertion.rule_type.as_ref() {
                head.push_str(rule_type.0.as_ref());
            }
            if assertion.dn_attributes.unwrap_or(false) {
                head.push_str(":dn");
            }
            if let Some(matching_rule) = assertion.matching_rule.as_ref() {
                head.push(':');
                head.push_str(matching_rule.0.as_ref());
            }
            format!(
                "({}:={})",
                head,
                escape_filter_value(assertion.assertion_value.0.as_ref())
            )
        }
    }
}

fn render_substring_filter(substrings: &[Substring<'_>]) -> String {
    if substrings.is_empty() {
        return "*".to_string();
    }

    let mut rendered = String::new();
    if !matches!(substrings.first(), Some(Substring::Initial(_))) {
        rendered.push('*');
    }

    for substring in substrings {
        match substring {
            Substring::Initial(value) => {
                rendered.push_str(&escape_filter_value(value.0.as_ref()));
            }
            Substring::Any(value) => {
                if !rendered.ends_with('*') {
                    rendered.push('*');
                }
                rendered.push_str(&escape_filter_value(value.0.as_ref()));
                rendered.push('*');
            }
            Substring::Final(value) => {
                if !rendered.ends_with('*') {
                    rendered.push('*');
                }
                rendered.push_str(&escape_filter_value(value.0.as_ref()));
            }
        }
    }

    rendered
}

fn escape_filter_value(value: &[u8]) -> String {
    let mut escaped = String::with_capacity(value.len());
    for byte in value {
        match byte {
            b'*' | b'(' | b')' | b'\\' | 0 => {
                escaped.push_str(&format!("\\{:02x}", byte));
            }
            0x20..=0x7e => escaped.push(*byte as char),
            _ => escaped.push_str(&format!("\\{:02x}", byte)),
        }
    }
    escaped
}

async fn handle_delete_request_with_fsm_runtime(
    fsm_set: &mut ConnectionFsmSet,
    request: &FsmRequestContext,
    delete_req: ldap_parser::ldap::LdapDN<'_>,
    request_context: &RequestContext,
    runtime_context: &FsmServerRuntimeContext,
) -> Result<(), String> {
    let session = legacy_session_from_fsm(fsm_set);
    let backend = fsm_set.backend().clone();
    let dn = delete_req.0.as_ref().trim().to_owned();

    let authorized = {
        let stream = fsm_set
            .connection_mut()
            .stream_mut()
            .ok_or("No active stream")?;
        authorize_operation(
            stream,
            Some(backend.as_ref()),
            request.message_id as u32,
            ResponseOp::Delete,
            &session,
            request_context,
            Permission::Delete,
            "delete",
            &dn,
            None,
        )
        .await
        .map_err(|err| err.to_string())?
    };
    if !authorized {
        return Ok(());
    }

    let write_config = WriteFsmConfig {
        strict_schema_validation: false,
        enable_aci_checks: false,
        enable_audit_logging: false,
        ..WriteFsmConfig::default()
    };

    let mut write_fsm = WriteFsmImpl::with_config(
        Box::new(
            WriteBackendAdapter::new(backend).with_actor(session.bound_dn().map(str::to_string)),
        ),
        Box::new(PassthroughSchemaValidator),
        Box::new(AllowAllWriteAciChecker),
        write_config,
    );

    if let Some(bound_dn) = fsm_set.authenticated_dn() {
        write_fsm = write_fsm.with_user_dn(bound_dn.to_string());
    }
    if let Some(metrics) = runtime_context.metrics.as_ref() {
        write_fsm = write_fsm.with_metrics(Box::new(ProductionWriteMetrics::new(metrics.clone())));
    }

    if let Err(err) = write_fsm
        .handle_event(WriteEvent::StartWrite(WriteOperation::Delete {
            dn: dn.clone(),
        }))
        .await
    {
        return send_delete_write_fsm_error(fsm_set, request, request_context, &session, &dn, err)
            .await;
    }

    if let Err(err) = write_fsm.handle_event(WriteEvent::ValidationComplete).await {
        return send_delete_write_fsm_error(fsm_set, request, request_context, &session, &dn, err)
            .await;
    }

    log_delete_audit_event(request_context, &session, &dn, true).await;
    send_request_result_response(
        fsm_set,
        request.message_id as u32,
        request.response_kind,
        ResultCode::Success,
        "",
    )
    .await
}

async fn handle_online_schema_modify_with_fsm_runtime(
    fsm_set: &mut ConnectionFsmSet,
    request: &FsmRequestContext,
    modify_req: ldap_parser::ldap::ModifyRequest<'_>,
    schema: &SharedLdapSchema,
    request_context: &RequestContext,
    runtime_context: &FsmServerRuntimeContext,
) -> Result<(), String> {
    let session = legacy_session_from_fsm(fsm_set);
    let backend = fsm_set.backend().clone();
    let dn = modify_req.object.0.as_ref().trim().to_owned();
    let modifications = convert_ldap_changes_to_modifications(&modify_req.changes);
    let modified_attributes = modifications
        .iter()
        .map(|modification| modification.attribute.clone())
        .collect::<Vec<_>>();

    let authorized = {
        let stream = fsm_set
            .connection_mut()
            .stream_mut()
            .ok_or("No active stream")?;
        authorize_operation(
            stream,
            Some(backend.as_ref()),
            request.message_id as u32,
            ResponseOp::Modify,
            &session,
            request_context,
            Permission::Modify,
            "modify",
            &dn,
            None,
        )
        .await
        .map_err(|err| err.to_string())?
    };
    if !authorized {
        return Ok(());
    }

    let authorized = {
        let stream = fsm_set
            .connection_mut()
            .stream_mut()
            .ok_or("No active stream")?;
        authorize_attribute_permissions(
            stream,
            backend.as_ref(),
            request.message_id as u32,
            ResponseOp::Modify,
            &session,
            request_context,
            Permission::Modify,
            "modify",
            &dn,
            &modified_attributes,
        )
        .await
        .map_err(|err| err.to_string())?
    };
    if !authorized {
        return Ok(());
    }

    match apply_online_schema_modify(
        backend.as_ref(),
        schema,
        &runtime_context.legacy_runtime_config,
        &session,
        modifications,
    )
    .await
    {
        Ok(()) => {
            log_modify_audit_event(
                request_context,
                &session,
                &dn,
                true,
                &modified_attributes,
                None,
            )
            .await;
            send_request_result_response(
                fsm_set,
                request.message_id as u32,
                request.response_kind,
                ResultCode::Success,
                "",
            )
            .await
        }
        Err(err) => {
            let (result_code, diagnostic) = online_schema_update_result(&err);
            error!("Online schema update failed for {}: {}", dn, diagnostic);
            log_modify_audit_event(
                request_context,
                &session,
                &dn,
                false,
                &modified_attributes,
                Some(&diagnostic),
            )
            .await;
            send_request_result_response(
                fsm_set,
                request.message_id as u32,
                request.response_kind,
                result_code,
                &diagnostic,
            )
            .await
        }
    }
}

async fn handle_modify_request_with_fsm_runtime(
    fsm_set: &mut ConnectionFsmSet,
    request: &FsmRequestContext,
    modify_req: ldap_parser::ldap::ModifyRequest<'_>,
    schema: &LdapSchema,
    request_context: &RequestContext,
    _runtime_context: &FsmServerRuntimeContext,
) -> Result<(), String> {
    let _profile_total = PerfPhase::start("modify", "total", Some(request.message_id as u32));
    let session = legacy_session_from_fsm(fsm_set);
    let backend = fsm_set.backend().clone();
    let dn = modify_req.object.0.as_ref().trim().to_owned();
    let modifications = convert_ldap_changes_to_modifications(&modify_req.changes);
    let modified_attributes: Vec<String> = modifications
        .iter()
        .map(|modification| modification.attribute.clone())
        .collect();
    if let Some(attribute) = first_server_managed_operational_attribute(&modified_attributes) {
        let diagnostic = server_managed_operational_attribute_diagnostic(&attribute);
        log_modify_audit_event(
            request_context,
            &session,
            &dn,
            false,
            &modified_attributes,
            Some(&diagnostic),
        )
        .await;
        send_request_result_response(
            fsm_set,
            request.message_id as u32,
            request.response_kind,
            ResultCode::UnwillingToPerform,
            &diagnostic,
        )
        .await?;
        return Ok(());
    }

    let authorized = {
        let stream = fsm_set
            .connection_mut()
            .stream_mut()
            .ok_or("No active stream")?;
        authorize_operation(
            stream,
            Some(backend.as_ref()),
            request.message_id as u32,
            ResponseOp::Modify,
            &session,
            request_context,
            Permission::Modify,
            "modify",
            &dn,
            None,
        )
        .await
        .map_err(|err| err.to_string())?
    };
    if !authorized {
        return Ok(());
    }

    let authorized = {
        let stream = fsm_set
            .connection_mut()
            .stream_mut()
            .ok_or("No active stream")?;
        authorize_attribute_permissions(
            stream,
            backend.as_ref(),
            request.message_id as u32,
            ResponseOp::Modify,
            &session,
            request_context,
            Permission::Modify,
            "modify",
            &dn,
            &modified_attributes,
        )
        .await
        .map_err(|err| err.to_string())?
    };
    if !authorized {
        return Ok(());
    }

    for attribute in &modified_attributes {
        if schema.get_attribute_type(attribute).is_none() {
            let diagnostic =
                format!("Schema validation failed: Attribute type not found: {attribute}");
            error!("Schema validation failed for modify {}: {}", dn, diagnostic);
            log_modify_audit_event(
                request_context,
                &session,
                &dn,
                false,
                &modified_attributes,
                Some(&diagnostic),
            )
            .await;
            send_request_result_response(
                fsm_set,
                request.message_id as u32,
                request.response_kind,
                ResultCode::ObjectClassViolation,
                &diagnostic,
            )
            .await?;
            return Ok(());
        }
    }

    let modify_result = {
        let _profile_phase =
            PerfPhase::start("modify", "backend_write", Some(request.message_id as u32));
        backend
            .modify_entry_validated_with_actor(
                &dn,
                modifications,
                session.bound_dn().map(str::to_string),
                schema,
            )
            .await
    };
    if let Err(err) = modify_result {
        match err {
            NativeModifyError::Schema(diagnostic) => {
                error!("Schema validation failed for modify {}: {}", dn, diagnostic);
                log_modify_audit_event(
                    request_context,
                    &session,
                    &dn,
                    false,
                    &modified_attributes,
                    Some(&diagnostic),
                )
                .await;
                send_request_result_response(
                    fsm_set,
                    request.message_id as u32,
                    request.response_kind,
                    ResultCode::ObjectClassViolation,
                    &diagnostic,
                )
                .await?;
                return Ok(());
            }
            NativeModifyError::Backend(err) => {
                error!("Modify operation failed for {}: {}", dn, err);
                log_modify_audit_event(
                    request_context,
                    &session,
                    &dn,
                    false,
                    &modified_attributes,
                    Some(backend_diagnostic(&err)),
                )
                .await;
                send_request_result_response(
                    fsm_set,
                    request.message_id as u32,
                    request.response_kind,
                    map_backend_error_code(&err),
                    backend_diagnostic(&err),
                )
                .await?;
                return Ok(());
            }
        }
    }

    log_modify_audit_event(
        request_context,
        &session,
        &dn,
        true,
        &modified_attributes,
        None,
    )
    .await;
    send_request_result_response(
        fsm_set,
        request.message_id as u32,
        request.response_kind,
        ResultCode::Success,
        "",
    )
    .await
}

async fn handle_add_request_with_fsm_runtime(
    fsm_set: &mut ConnectionFsmSet,
    request: &FsmRequestContext,
    add_req: ldap_parser::ldap::AddRequest<'_>,
    schema: &LdapSchema,
    request_context: &RequestContext,
    runtime_context: &FsmServerRuntimeContext,
) -> Result<(), String> {
    let session = legacy_session_from_fsm(fsm_set);
    let backend = fsm_set.backend().clone();
    let dn = add_req.entry.0.as_ref().trim().to_owned();
    let (entry, _) = build_entry_from_add_request(&dn, add_req.attributes);
    let encoded_entry = encode_add_entry_for_write_fsm(&entry);

    let authorized = {
        let stream = fsm_set
            .connection_mut()
            .stream_mut()
            .ok_or("No active stream")?;
        authorize_operation(
            stream,
            Some(backend.as_ref()),
            request.message_id as u32,
            ResponseOp::Add,
            &session,
            request_context,
            Permission::Add,
            "add",
            &dn,
            None,
        )
        .await
        .map_err(|err| err.to_string())?
    };
    if !authorized {
        return Ok(());
    }

    let added_attributes = entry.attributes.keys().cloned().collect::<Vec<_>>();
    if let Some(attribute) = first_server_managed_operational_attribute(&added_attributes) {
        let diagnostic = server_managed_operational_attribute_diagnostic(&attribute);
        log_add_audit_event(request_context, &session, &dn, false).await;
        send_request_result_response(
            fsm_set,
            request.message_id as u32,
            request.response_kind,
            ResultCode::UnwillingToPerform,
            &diagnostic,
        )
        .await?;
        return Ok(());
    }
    let authorized = {
        let stream = fsm_set
            .connection_mut()
            .stream_mut()
            .ok_or("No active stream")?;
        authorize_attribute_permissions(
            stream,
            backend.as_ref(),
            request.message_id as u32,
            ResponseOp::Add,
            &session,
            request_context,
            Permission::Add,
            "add",
            &dn,
            &added_attributes,
        )
        .await
        .map_err(|err| err.to_string())?
    };
    if !authorized {
        return Ok(());
    }

    let write_config = WriteFsmConfig {
        enable_aci_checks: false,
        enable_audit_logging: false,
        ..WriteFsmConfig::default()
    };

    let mut write_fsm = WriteFsmImpl::with_config(
        Box::new(
            WriteBackendAdapter::new(backend).with_actor(session.bound_dn().map(str::to_string)),
        ),
        Box::new(LdapSchemaValidator::with_schema(schema.clone())),
        Box::new(AllowAllWriteAciChecker),
        write_config,
    );

    if let Some(bound_dn) = fsm_set.authenticated_dn() {
        write_fsm = write_fsm.with_user_dn(bound_dn.to_string());
    }
    if let Some(metrics) = runtime_context.metrics.as_ref() {
        write_fsm = write_fsm.with_metrics(Box::new(ProductionWriteMetrics::new(metrics.clone())));
    }

    if let Err(err) = write_fsm
        .handle_event(WriteEvent::StartWrite(WriteOperation::Add {
            dn: dn.clone(),
            entry: encoded_entry,
        }))
        .await
    {
        return send_add_write_fsm_error(fsm_set, request, request_context, &session, &dn, err)
            .await;
    }

    if let Err(err) = write_fsm.handle_event(WriteEvent::ValidationComplete).await {
        return send_add_write_fsm_error(fsm_set, request, request_context, &session, &dn, err)
            .await;
    }

    log_add_audit_event(request_context, &session, &dn, true).await;
    send_request_result_response(
        fsm_set,
        request.message_id as u32,
        request.response_kind,
        ResultCode::Success,
        "",
    )
    .await
}

async fn handle_moddn_request_with_fsm_runtime(
    fsm_set: &mut ConnectionFsmSet,
    request: &FsmRequestContext,
    rename_req: ldap_parser::ldap::ModDnRequest<'_>,
    schema: &LdapSchema,
    request_context: &RequestContext,
    runtime_context: &FsmServerRuntimeContext,
) -> Result<(), String> {
    let session = legacy_session_from_fsm(fsm_set);
    let backend = fsm_set.backend().clone();
    let dn = rename_req.entry.0.as_ref().trim().to_owned();
    let new_rdn = rename_req.newrdn.0.as_ref().trim().to_owned();
    let delete_old = rename_req.deleteoldrdn;
    let new_superior = rename_req
        .newsuperior
        .map(|sup| sup.0.into_owned())
        .filter(|sup| !sup.is_empty());
    let new_dn = compute_new_dn(&dn, &new_rdn, new_superior.as_deref());

    let authorized = {
        let stream = fsm_set
            .connection_mut()
            .stream_mut()
            .ok_or("No active stream")?;
        authorize_operation(
            stream,
            Some(backend.as_ref()),
            request.message_id as u32,
            ResponseOp::ModifyDn,
            &session,
            request_context,
            Permission::Modify,
            "modifydn",
            &dn,
            None,
        )
        .await
        .map_err(|err| err.to_string())?
    };
    if !authorized {
        return Ok(());
    }

    let existing_entry = match backend.get_entry(&dn).await {
        Ok(Some(existing_entry)) => existing_entry,
        Ok(None) => {
            send_request_result_response(
                fsm_set,
                request.message_id as u32,
                request.response_kind,
                ResultCode::NoSuchObject,
                "no such object",
            )
            .await?;
            return Ok(());
        }
        Err(err) => {
            error!("ModifyDN lookup failed for {}: {}", dn, err);
            log_moddn_audit_event(
                request_context,
                &session,
                &dn,
                &new_dn,
                false,
                Some(backend_diagnostic(&err)),
            )
            .await;
            send_request_result_response(
                fsm_set,
                request.message_id as u32,
                request.response_kind,
                map_backend_error_code(&err),
                backend_diagnostic(&err),
            )
            .await?;
            return Ok(());
        }
    };
    if let Err(schema_error) = schema.validate_rdn_for_entry(&existing_entry.attributes, &new_rdn) {
        let diagnostic = format!("Schema validation failed: {}", schema_error);
        error!(
            "Schema validation failed for modifydn {}: {}",
            dn, schema_error
        );
        log_moddn_audit_event(
            request_context,
            &session,
            &dn,
            &new_dn,
            false,
            Some(&diagnostic),
        )
        .await;
        send_request_result_response(
            fsm_set,
            request.message_id as u32,
            request.response_kind,
            ResultCode::ObjectClassViolation,
            &diagnostic,
        )
        .await?;
        return Ok(());
    }

    let write_config = WriteFsmConfig {
        strict_schema_validation: true,
        enable_aci_checks: false,
        enable_audit_logging: false,
        ..WriteFsmConfig::default()
    };

    let mut write_fsm = WriteFsmImpl::with_config(
        Box::new(
            WriteBackendAdapter::new(backend).with_actor(session.bound_dn().map(str::to_string)),
        ),
        Box::new(LdapSchemaValidator::with_schema(schema.clone())),
        Box::new(AllowAllWriteAciChecker),
        write_config,
    );

    if let Some(bound_dn) = fsm_set.authenticated_dn() {
        write_fsm = write_fsm.with_user_dn(bound_dn.to_string());
    }
    if let Some(metrics) = runtime_context.metrics.as_ref() {
        write_fsm = write_fsm.with_metrics(Box::new(ProductionWriteMetrics::new(metrics.clone())));
    }

    if let Err(err) = write_fsm
        .handle_event(WriteEvent::StartWrite(WriteOperation::ModifyDn {
            dn: dn.clone(),
            new_rdn: new_rdn.clone(),
            delete_old,
            new_superior: new_superior.clone(),
        }))
        .await
    {
        return send_moddn_write_fsm_error(
            fsm_set,
            request,
            request_context,
            &session,
            &dn,
            &new_dn,
            err,
        )
        .await;
    }

    if let Err(err) = write_fsm.handle_event(WriteEvent::ValidationComplete).await {
        return send_moddn_write_fsm_error(
            fsm_set,
            request,
            request_context,
            &session,
            &dn,
            &new_dn,
            err,
        )
        .await;
    }

    log_moddn_audit_event(request_context, &session, &dn, &new_dn, true, None).await;
    send_request_result_response(
        fsm_set,
        request.message_id as u32,
        request.response_kind,
        ResultCode::Success,
        "",
    )
    .await
}

async fn handle_compare_request_with_fsm_runtime(
    fsm_set: &mut ConnectionFsmSet,
    request: &FsmRequestContext,
    compare_req: ldap_parser::ldap::CompareRequest<'_>,
    schema: &LdapSchema,
    request_context: &RequestContext,
    runtime_context: &FsmServerRuntimeContext,
) -> Result<(), String> {
    let session = legacy_session_from_fsm(fsm_set);
    let backend = fsm_set.backend().clone();
    let dn = compare_req.entry.0.as_ref().trim().to_owned();
    let attribute = compare_req.ava.attribute_desc.0.as_ref().trim().to_owned();
    let assertion = compare_req.ava.assertion_value.to_vec();

    let authorized = {
        let stream = fsm_set
            .connection_mut()
            .stream_mut()
            .ok_or("No active stream")?;
        authorize_operation(
            stream,
            Some(backend.as_ref()),
            request.message_id as u32,
            ResponseOp::Compare,
            &session,
            request_context,
            Permission::Compare,
            "compare",
            &dn,
            Some(&attribute),
        )
        .await
        .map_err(|err| err.to_string())?
    };
    if !authorized {
        return Ok(());
    }

    let compare_config = CompareFsmConfig {
        enable_access_control: false,
        enable_metrics: runtime_context.metrics.is_some(),
        ..CompareFsmConfig::default()
    };

    let mut compare_fsm = CompareFsmImpl::with_config(
        Box::new(CompareBackendAdapter::new(backend)),
        Box::new(ProductionAttributeComparator::with_schema(schema.clone())),
        Box::new(AllowAllCompareAccessControl),
        compare_config,
    );

    if let Some(bound_dn) = fsm_set.authenticated_dn() {
        compare_fsm = compare_fsm.with_user_dn(bound_dn.to_string());
    }
    if let Some(metrics) = runtime_context.metrics.as_ref() {
        compare_fsm =
            compare_fsm.with_metrics(Box::new(ProductionCompareMetrics::new(metrics.clone())));
    }

    if let Err(err) = compare_fsm
        .handle_event(CompareEvent::StartCompare {
            dn: dn.clone(),
            attribute: attribute.clone(),
            value: assertion,
        })
        .await
    {
        return send_compare_fsm_error(
            fsm_set,
            request,
            request_context,
            &session,
            &dn,
            &attribute,
            err,
        )
        .await;
    }

    if let Err(err) = compare_fsm.handle_event(CompareEvent::EntryRead).await {
        return send_compare_fsm_error(
            fsm_set,
            request,
            request_context,
            &session,
            &dn,
            &attribute,
            err,
        )
        .await;
    }

    let result = compare_fsm
        .result()
        .ok_or_else(|| "compare FSM did not produce a result".to_string())?;

    if let Err(err) = compare_fsm.handle_event(CompareEvent::ResultEmitted).await {
        return send_compare_fsm_error(
            fsm_set,
            request,
            request_context,
            &session,
            &dn,
            &attribute,
            err,
        )
        .await;
    }

    log_compare_audit(
        request_context,
        &session,
        &dn,
        &attribute,
        true,
        if result { "true" } else { "false" },
        None,
    )
    .await;

    send_request_result_response(
        fsm_set,
        request.message_id as u32,
        request.response_kind,
        if result {
            ResultCode::CompareTrue
        } else {
            ResultCode::CompareFalse
        },
        "",
    )
    .await
}

fn compare_fsm_error_response(error: &CompareFsmError) -> (ResultCode, String) {
    match error {
        CompareFsmError::InvalidParameters { message } => {
            (ResultCode::ProtocolError, message.clone())
        }
        CompareFsmError::NoSuchObject { .. } => {
            (ResultCode::NoSuchObject, "no such object".to_string())
        }
        CompareFsmError::AccessDenied { message } => {
            (ResultCode::InsufficientAccessRights, message.clone())
        }
        CompareFsmError::ComparisonError { message } => compare_schema_error_response(message)
            .unwrap_or_else(|| (ResultCode::Unavailable, message.clone())),
        CompareFsmError::BackendError { message } | CompareFsmError::Generic { message } => {
            (ResultCode::Unavailable, message.clone())
        }
        CompareFsmError::InvalidStateTransition { .. } | CompareFsmError::NoActiveCompare => {
            (ResultCode::OperationsError, error.to_string())
        }
        CompareFsmError::NoSuchAttribute { .. } => (ResultCode::CompareFalse, String::new()),
    }
}

fn compare_schema_error_response(message: &str) -> Option<(ResultCode, String)> {
    if message.starts_with("undefined attribute type:") {
        return Some((ResultCode::UndefinedAttributeType, message.to_string()));
    }
    if message.starts_with("inappropriate matching:") {
        return Some((ResultCode::InappropriateMatching, message.to_string()));
    }
    if message.starts_with("invalid attribute syntax:") {
        return Some((ResultCode::InvalidAttributeSyntax, message.to_string()));
    }
    if message.starts_with("invalid filter:") {
        return Some((ResultCode::ProtocolError, message.to_string()));
    }
    None
}

fn write_fsm_error_response(error: &WriteFsmError) -> (ResultCode, String) {
    match error {
        WriteFsmError::InvalidOperation { message } => (ResultCode::ProtocolError, message.clone()),
        WriteFsmError::AccessDenied { message } => {
            (ResultCode::InsufficientAccessRights, message.clone())
        }
        WriteFsmError::EntryAlreadyExists { .. } => (
            ResultCode::EntryAlreadyExists,
            "entry already exists".to_string(),
        ),
        WriteFsmError::NoSuchObject { .. } => {
            (ResultCode::NoSuchObject, "no such object".to_string())
        }
        WriteFsmError::ConstraintViolation { message } => {
            (ResultCode::ConstraintViolation, message.clone())
        }
        WriteFsmError::SchemaError { message } => {
            (ResultCode::ObjectClassViolation, message.clone())
        }
        WriteFsmError::BackendError { message }
        | WriteFsmError::TransactionError { message }
        | WriteFsmError::Generic { message } => backend_write_fsm_error_response(message)
            .unwrap_or_else(|| (ResultCode::Unavailable, message.clone())),
        WriteFsmError::InvalidStateTransition { .. } | WriteFsmError::NoActiveOperation => {
            (ResultCode::OperationsError, error.to_string())
        }
    }
}

fn backend_write_fsm_error_response(message: &str) -> Option<(ResultCode, String)> {
    let normalized = message.to_ascii_lowercase();
    if normalized.contains("entry already exists") {
        return Some((
            ResultCode::EntryAlreadyExists,
            "entry already exists".to_string(),
        ));
    }
    if normalized.contains("entry not found") || normalized.contains("no such object") {
        return Some((ResultCode::NoSuchObject, "no such object".to_string()));
    }
    None
}

async fn send_compare_fsm_error(
    fsm_set: &mut ConnectionFsmSet,
    request: &FsmRequestContext,
    request_context: &RequestContext,
    session: &ConnectionSession,
    dn: &str,
    attribute: &str,
    error: CompareFsmError,
) -> Result<(), String> {
    let (result_code, diagnostic) = compare_fsm_error_response(&error);

    log_compare_audit(
        request_context,
        session,
        dn,
        attribute,
        false,
        "error",
        if diagnostic.is_empty() {
            None
        } else {
            Some(diagnostic.as_str())
        },
    )
    .await;

    send_request_result_response(
        fsm_set,
        request.message_id as u32,
        request.response_kind,
        result_code,
        &diagnostic,
    )
    .await
}

async fn send_delete_write_fsm_error(
    fsm_set: &mut ConnectionFsmSet,
    request: &FsmRequestContext,
    request_context: &RequestContext,
    session: &ConnectionSession,
    dn: &str,
    error: WriteFsmError,
) -> Result<(), String> {
    let (result_code, diagnostic) = write_fsm_error_response(&error);

    log_delete_audit_event(request_context, session, dn, false).await;

    send_request_result_response(
        fsm_set,
        request.message_id as u32,
        request.response_kind,
        result_code,
        &diagnostic,
    )
    .await
}

async fn send_add_write_fsm_error(
    fsm_set: &mut ConnectionFsmSet,
    request: &FsmRequestContext,
    request_context: &RequestContext,
    session: &ConnectionSession,
    dn: &str,
    error: WriteFsmError,
) -> Result<(), String> {
    let (result_code, diagnostic) = write_fsm_error_response(&error);

    log_add_audit_event(request_context, session, dn, false).await;

    send_request_result_response(
        fsm_set,
        request.message_id as u32,
        request.response_kind,
        result_code,
        &diagnostic,
    )
    .await
}

async fn send_moddn_write_fsm_error(
    fsm_set: &mut ConnectionFsmSet,
    request: &FsmRequestContext,
    request_context: &RequestContext,
    session: &ConnectionSession,
    dn: &str,
    new_dn: &str,
    error: WriteFsmError,
) -> Result<(), String> {
    let (result_code, diagnostic) = write_fsm_error_response(&error);

    log_moddn_audit_event(
        request_context,
        session,
        dn,
        new_dn,
        false,
        if diagnostic.is_empty() {
            None
        } else {
            Some(diagnostic.as_str())
        },
    )
    .await;

    send_request_result_response(
        fsm_set,
        request.message_id as u32,
        request.response_kind,
        result_code,
        &diagnostic,
    )
    .await
}

fn map_backend_error_code(err: &crate::backend::BackendError) -> ResultCode {
    match err {
        crate::backend::BackendError::AlreadyExists => ResultCode::EntryAlreadyExists,
        crate::backend::BackendError::NotFound => ResultCode::NoSuchObject,
        crate::backend::BackendError::Storage(_) => ResultCode::Unavailable,
    }
}

fn map_filter_schema_error_code(err: &FilterSchemaError) -> ResultCode {
    match err {
        FilterSchemaError::UndefinedAttribute(_) => ResultCode::UndefinedAttributeType,
        FilterSchemaError::InappropriateMatching(_) => ResultCode::InappropriateMatching,
        FilterSchemaError::InvalidAttributeSyntax(_) => ResultCode::InvalidAttributeSyntax,
        FilterSchemaError::InvalidFilter(_) => ResultCode::ProtocolError,
    }
}

fn backend_diagnostic(err: &crate::backend::BackendError) -> &'static str {
    match err {
        crate::backend::BackendError::AlreadyExists => "entry already exists",
        crate::backend::BackendError::NotFound => "no such object",
        crate::backend::BackendError::Storage(_) => "backend failure",
    }
}

fn encode_add_entry_for_write_fsm(entry: &crate::backend::DirectoryEntry) -> Vec<u8> {
    let mut encoded = format!("dn: {}\n", entry.dn);
    let mut attribute_names: Vec<_> = entry.attributes.keys().cloned().collect();
    attribute_names.sort();

    for attribute in attribute_names {
        if let Some(values) = entry.attributes.get(&attribute) {
            for value in values {
                encoded.push_str(&format!("{}: {}\n", attribute, value));
            }
        }
    }

    encoded.into_bytes()
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

#[allow(clippy::too_many_arguments)]
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
                    .sample_string(&mut rand::rng(), 24)
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
    connection_is_secure: bool,
    request_context: &RequestContext,
    metrics: Option<&MetricsCollector>,
) -> Result<(), String> {
    use crate::fsm::{AuthEvent, StateMachine};
    use ldap_parser::ldap::AuthenticationChoice;

    let _profile_total = PerfPhase::start("bind", "total", Some(message_id as u32));
    if bind_req.version != 3 {
        send_bind_result(
            fsm_set,
            message_id as u32,
            ResultCode::ProtocolError,
            "unsupported LDAP version",
        )
        .await?;
        return Ok(());
    }

    let bind_name = bind_req.name.0.as_ref().trim().to_owned();
    match bind_req.authentication {
        AuthenticationChoice::Simple(password) => {
            let dn = bind_name;
            let is_anonymous_bind = dn.is_empty() && password.as_ref().is_empty();
            let backend = fsm_set.backend().clone();
            let auth_event = AuthEvent::BindRequest {
                dn: dn.clone(),
                password: password.as_ref().to_vec(),
            };

            match fsm_set.auth_mut() {
                AuthenticationFsm::Simple(auth_fsm) => {
                    let auth_result = {
                        let _profile_phase =
                            PerfPhase::start("bind", "auth", Some(message_id as u32));
                        auth_fsm.handle_event(auth_event).await
                    };
                    match auth_result {
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
                                if let Some(bound_dn) =
                                    fsm_set.authenticated_dn().map(str::to_string)
                                {
                                    record_authentication_success_metadata_with_context(
                                        request_context,
                                        backend.as_ref(),
                                        &bound_dn,
                                    )
                                    .await;
                                    log_simple_bind_success(request_context, &bound_dn).await;
                                }
                                send_bind_success(fsm_set, message_id as u32).await?;
                            } else {
                                if let Some(metrics) = metrics {
                                    metrics.record_fsm_state(FsmType::Auth, "anonymous");
                                }
                                record_authentication_failure_metadata_with_context(
                                    request_context,
                                    backend.as_ref(),
                                    &dn,
                                )
                                .await;
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
        AuthenticationChoice::Sasl(credentials) => {
            handle_sasl_bind_with_fsm(
                fsm_set,
                message_id as u32,
                bind_name,
                credentials,
                connection_is_secure,
                request_context,
                metrics,
            )
            .await?;
        }
    }

    Ok(())
}

async fn handle_sasl_bind_with_fsm(
    fsm_set: &mut ConnectionFsmSet,
    message_id: u32,
    request_name: String,
    credentials: ldap_parser::ldap::SaslCredentials<'_>,
    connection_is_secure: bool,
    request_context: &RequestContext,
    metrics: Option<&MetricsCollector>,
) -> Result<(), String> {
    use crate::fsm::{AuthEvent, StateMachine};

    let mechanism = credentials.mechanism.0.as_ref().trim().to_owned();
    reset_auth_state(fsm_set).await?;

    if !mechanism.eq_ignore_ascii_case("PLAIN") {
        if let Some(metrics) = metrics {
            metrics.record_fsm_state(FsmType::Auth, "sasl_unsupported_mechanism");
        }
        log_sasl_bind(
            request_context,
            request_name.as_str(),
            mechanism.as_str(),
            false,
            Some("unsupported SASL mechanism"),
        )
        .await;
        send_bind_result(
            fsm_set,
            message_id,
            ResultCode::AuthMethodNotSupported,
            "only SASL PLAIN is supported",
        )
        .await?;
        return Ok(());
    }

    if !connection_is_secure {
        if let Some(metrics) = metrics {
            metrics.record_fsm_state(FsmType::Auth, "sasl_confidentiality_required");
        }
        log_sasl_bind(
            request_context,
            request_name.as_str(),
            "PLAIN",
            false,
            Some("SASL PLAIN requires TLS"),
        )
        .await;
        send_bind_result(
            fsm_set,
            message_id,
            ResultCode::ConfidentialityRequired,
            "SASL PLAIN requires TLS",
        )
        .await?;
        return Ok(());
    }

    let parsed = match credentials
        .credentials
        .as_deref()
        .ok_or_else(|| "SASL PLAIN requires credentials".to_string())
        .and_then(crate::sasl_mechanisms::MultiMechanismHandler::parse_plain_credentials_ref)
    {
        Ok(parsed) => parsed,
        Err(err) => {
            if let Some(metrics) = metrics {
                metrics.record_fsm_state(FsmType::Auth, "sasl_malformed_credentials");
            }
            log_sasl_bind(
                request_context,
                request_name.as_str(),
                "PLAIN",
                false,
                Some(&err),
            )
            .await;
            send_bind_result(fsm_set, message_id, ResultCode::InvalidCredentials, &err).await?;
            return Ok(());
        }
    };

    let bind_dn = if request_name.is_empty() {
        parsed.authcid.to_owned()
    } else {
        request_name
    };

    if bind_dn.is_empty() {
        if let Some(metrics) = metrics {
            metrics.record_fsm_state(FsmType::Auth, "sasl_failed");
        }
        log_sasl_bind(
            request_context,
            "anonymous",
            "PLAIN",
            false,
            Some("empty SASL identity"),
        )
        .await;
        send_bind_result(
            fsm_set,
            message_id,
            ResultCode::InvalidCredentials,
            "empty SASL identity",
        )
        .await?;
        return Ok(());
    }

    if !parsed.authzid.is_empty() && !parsed.authzid.eq_ignore_ascii_case(&bind_dn) {
        if let Some(metrics) = metrics {
            metrics.record_fsm_state(FsmType::Auth, "sasl_failed");
        }
        log_sasl_bind(
            request_context,
            bind_dn.as_str(),
            "PLAIN",
            false,
            Some("proxy authorization is not supported"),
        )
        .await;
        send_bind_result(
            fsm_set,
            message_id,
            ResultCode::InappropriateAuthentication,
            "proxy authorization is not supported",
        )
        .await?;
        return Ok(());
    }

    let auth_event = AuthEvent::BindRequest {
        dn: bind_dn.clone(),
        password: parsed.password.to_vec(),
    };
    let backend = fsm_set.backend().clone();

    match fsm_set.auth_mut() {
        AuthenticationFsm::Simple(auth_fsm) => match auth_fsm.handle_event(auth_event).await {
            Ok(_) if fsm_set.is_authenticated() => {
                if let Some(metrics) = metrics {
                    metrics.record_fsm_state(FsmType::Auth, "sasl_bound");
                }
                record_authentication_success_metadata_with_context(
                    request_context,
                    backend.as_ref(),
                    &bind_dn,
                )
                .await;
                log_sasl_bind(request_context, bind_dn.as_str(), "PLAIN", true, None).await;
                send_bind_success(fsm_set, message_id).await?;
            }
            Ok(_) => {
                if let Some(metrics) = metrics {
                    metrics.record_fsm_state(FsmType::Auth, "sasl_failed");
                }
                record_authentication_failure_metadata_with_context(
                    request_context,
                    backend.as_ref(),
                    &bind_dn,
                )
                .await;
                log_sasl_bind(
                    request_context,
                    bind_dn.as_str(),
                    "PLAIN",
                    false,
                    Some("invalid credentials"),
                )
                .await;
                send_bind_error(fsm_set, message_id, "invalid credentials").await?;
            }
            Err(err) => {
                error!("SASL PLAIN auth FSM error for {}: {}", bind_dn, err);
                let backend_error =
                    matches!(err, crate::auth_fsm::AuthError::DirectoryError { .. });
                if let Some(metrics) = metrics {
                    metrics.record_fsm_state(FsmType::Auth, "sasl_failed");
                }
                let (result_code, diagnostic) = if backend_error {
                    (ResultCode::Unavailable, "backend failure")
                } else {
                    (ResultCode::InvalidCredentials, "authentication failed")
                };
                log_sasl_bind(
                    request_context,
                    bind_dn.as_str(),
                    "PLAIN",
                    false,
                    Some(diagnostic),
                )
                .await;
                send_bind_result(fsm_set, message_id, result_code, diagnostic).await?;
            }
        },
        AuthenticationFsm::Sasl(_) => {
            if let Some(metrics) = metrics {
                metrics.record_fsm_state(FsmType::Auth, "sasl_not_configured");
            }
            log_sasl_bind(
                request_context,
                bind_dn.as_str(),
                "PLAIN",
                false,
                Some("SASL not configured"),
            )
            .await;
            send_bind_result(
                fsm_set,
                message_id,
                ResultCode::Unavailable,
                "SASL not configured",
            )
            .await?;
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
    send_bind_result(fsm_set, message_id, ResultCode::Success, "").await
}

async fn send_bind_error(
    fsm_set: &mut ConnectionFsmSet,
    message_id: u32,
    diagnostic: &str,
) -> Result<(), String> {
    send_bind_result(
        fsm_set,
        message_id,
        ResultCode::InvalidCredentials,
        diagnostic,
    )
    .await
}

async fn send_bind_result(
    fsm_set: &mut ConnectionFsmSet,
    message_id: u32,
    result_code: ResultCode,
    diagnostic: &str,
) -> Result<(), String> {
    use crate::parser::encode_bind_response;

    let response = encode_bind_response(message_id, result_code, "", diagnostic)
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

async fn send_request_result_response_with_controls(
    fsm_set: &mut ConnectionFsmSet,
    message_id: u32,
    response_kind: FsmResponseKind,
    result_code: ResultCode,
    matched_dn: &str,
    diagnostic: &str,
    controls: &[LdapControl],
) -> Result<(), String> {
    use crate::parser::{encode_bind_response, encode_result_response_with_controls};

    let response = match response_kind {
        FsmResponseKind::Bind => {
            encode_bind_response(message_id, result_code, matched_dn, diagnostic)
                .map_err(|err| format!("Encode error: {err:?}"))?
        }
        FsmResponseKind::Result(op) => encode_result_response_with_controls(
            message_id,
            op,
            result_code,
            matched_dn,
            diagnostic,
            controls,
        )
        .map_err(|err| format!("Encode error: {err:?}"))?,
        FsmResponseKind::None => return Ok(()),
    };

    let stream = fsm_set
        .connection_mut()
        .stream_mut()
        .ok_or("No active stream")?;
    stream
        .write_all(&response)
        .await
        .map_err(|err| format!("Write error: {err}"))?;
    Ok(())
}

async fn send_request_result_response_with_referrals(
    fsm_set: &mut ConnectionFsmSet,
    message_id: u32,
    response_kind: FsmResponseKind,
    result_code: ResultCode,
    matched_dn: &str,
    diagnostic: &str,
    referrals: &[String],
) -> Result<(), String> {
    use crate::parser::encode_bind_response;

    let response = match response_kind {
        FsmResponseKind::Bind => {
            encode_bind_response(message_id, result_code, matched_dn, diagnostic)
                .map_err(|err| format!("Encode error: {err:?}"))?
        }
        FsmResponseKind::Result(op) => encode_result_response_with_referrals(
            message_id,
            op,
            result_code,
            matched_dn,
            diagnostic,
            referrals,
            &[],
        )
        .map_err(|err| format!("Encode error: {err:?}"))?,
        FsmResponseKind::None => return Ok(()),
    };

    let stream = fsm_set
        .connection_mut()
        .stream_mut()
        .ok_or("No active stream")?;
    stream
        .write_all(&response)
        .await
        .map_err(|err| format!("Write error: {err}"))?;
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

fn log_connection_failure(context: &str, client_addr: SocketAddr, error: &str) {
    if expected_peer_disconnect_error(error) {
        debug!("{context} for {client_addr:?}: {error}");
    } else {
        error!("{context} for {client_addr:?}: {error}");
    }
}

fn expected_peer_disconnect_error(error: &str) -> bool {
    error.contains("Connection reset by peer")
        || error.contains("tls handshake eof")
        || error.contains("Broken pipe")
        || error.contains("connection closed")
        || error.contains("unexpected eof")
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
    use crate::backend::{
        BackendError, DirectoryBackend, DirectoryEntry, MockBackend, Modification,
        SearchCandidateHint,
    };
    use crate::config::ServerConfig;
    use crate::extended_ops::oids;
    use crate::replication_service::ReplicationService;
    use crate::sync_controls::{
        SYNC_DONE_OID, SYNC_STATE_OID, SyncRefreshMode, SyncRequestControl, SyncStateControl,
        SyncStateType, decode_sync_done_control, decode_sync_state_control,
        encode_sync_request_control,
    };
    use ldap_parser::ldap::{
        AuthenticationChoice, BindRequest, LdapDN, LdapString, ProtocolOp,
        ResultCode as ParserResultCode, SaslCredentials,
    };
    use ldap_parser::parse_ldap_messages;
    use rasn::der;
    use rasn_ldap::{
        Attribute, AttributeDescription as RasnAttributeDescription,
        AttributeValue as RasnAttributeValue,
        AttributeValueAssertion as RasnAttributeValueAssertion,
        AuthenticationChoice as RasnAuthChoice, BindRequest as RasnBindRequest,
        ChangeOperation as RasnChangeOperation, CompareRequest as RasnCompareRequest,
        Control as RasnControl, Filter as RasnFilter, LdapMessage as RasnLdapMessage,
        ModifyDnRequest as RasnModifyDnRequest, ModifyRequest as RasnModifyRequest,
        ModifyRequestChanges as RasnModifyRequestChanges, PartialAttribute as RasnPartialAttribute,
        ProtocolOp as RasnProtocolOp, SaslCredentials as RasnSaslCredentials,
        SearchRequest as RasnSearchRequest, SearchRequestDerefAliases, SearchRequestScope,
    };
    use std::borrow::Cow;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::time::timeout;

    async fn connected_stream_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (server_stream, _) = listener.accept().await.unwrap();
        let client_stream = client.await.unwrap();

        (server_stream, client_stream)
    }

    struct HintTrackingBackend {
        inner: MockBackend,
        direct_search_calls: AtomicUsize,
        hinted_search_calls: AtomicUsize,
        stream_search_calls: AtomicUsize,
        projected_stream_search_calls: AtomicUsize,
        hints: Mutex<Vec<Option<SearchCandidateHint>>>,
        streaming_supported: bool,
    }

    impl HintTrackingBackend {
        fn new() -> Self {
            Self {
                inner: MockBackend::default(),
                direct_search_calls: AtomicUsize::new(0),
                hinted_search_calls: AtomicUsize::new(0),
                stream_search_calls: AtomicUsize::new(0),
                projected_stream_search_calls: AtomicUsize::new(0),
                hints: Mutex::new(Vec::new()),
                streaming_supported: false,
            }
        }

        fn new_streaming() -> Self {
            Self {
                streaming_supported: true,
                ..Self::new()
            }
        }

        async fn insert_entry(&self, entry: DirectoryEntry) {
            self.inner.add_entry(entry, Vec::new()).await.unwrap();
        }

        fn direct_search_calls(&self) -> usize {
            self.direct_search_calls.load(Ordering::SeqCst)
        }

        fn hinted_search_calls(&self) -> usize {
            self.hinted_search_calls.load(Ordering::SeqCst)
        }

        fn stream_search_calls(&self) -> usize {
            self.stream_search_calls.load(Ordering::SeqCst)
        }

        fn projected_stream_search_calls(&self) -> usize {
            self.projected_stream_search_calls.load(Ordering::SeqCst)
        }

        fn recorded_hints(&self) -> Vec<Option<SearchCandidateHint>> {
            self.hints.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl DirectoryBackend for HintTrackingBackend {
        async fn authenticate(&self, dn: &str, password: &[u8]) -> Result<bool, BackendError> {
            self.inner.authenticate(dn, password).await
        }

        async fn get_entry(&self, dn: &str) -> Result<Option<DirectoryEntry>, BackendError> {
            self.inner.get_entry(dn).await
        }

        async fn add_entry(
            &self,
            entry: DirectoryEntry,
            password: Vec<u8>,
        ) -> Result<(), BackendError> {
            self.inner.add_entry(entry, password).await
        }

        async fn delete_entry(&self, dn: &str) -> Result<(), BackendError> {
            self.inner.delete_entry(dn).await
        }

        async fn modify_entry(
            &self,
            dn: &str,
            modifications: Vec<Modification>,
        ) -> Result<(), BackendError> {
            self.inner.modify_entry(dn, modifications).await
        }

        async fn compare_attribute(
            &self,
            dn: &str,
            attribute: &str,
            value: &str,
        ) -> Result<bool, BackendError> {
            self.inner.compare_attribute(dn, attribute, value).await
        }

        async fn rename_entry(
            &self,
            dn: &str,
            new_rdn: &str,
            delete_old: bool,
            new_superior: Option<String>,
        ) -> Result<(), BackendError> {
            self.inner
                .rename_entry(dn, new_rdn, delete_old, new_superior)
                .await
        }

        async fn search_entries(
            &self,
            base_dn: &str,
            scope: ldap_parser::ldap::SearchScope,
        ) -> Result<Vec<DirectoryEntry>, BackendError> {
            self.direct_search_calls.fetch_add(1, Ordering::SeqCst);
            self.inner.search_entries(base_dn, scope).await
        }

        async fn search_entries_with_hint(
            &self,
            base_dn: &str,
            scope: ldap_parser::ldap::SearchScope,
            hint: Option<SearchCandidateHint>,
        ) -> Result<Vec<DirectoryEntry>, BackendError> {
            self.hinted_search_calls.fetch_add(1, Ordering::SeqCst);
            self.hints.lock().unwrap().push(hint);
            self.inner.search_entries(base_dn, scope).await
        }

        fn supports_search_entry_streaming(&self) -> bool {
            self.streaming_supported
        }

        async fn stream_search_entries_with_hint_report(
            &self,
            base_dn: &str,
            scope: ldap_parser::ldap::SearchScope,
            hint: Option<SearchCandidateHint>,
        ) -> Result<crate::backend::SearchEntriesStreamReport, BackendError> {
            self.stream_search_calls.fetch_add(1, Ordering::SeqCst);
            self.hints.lock().unwrap().push(hint.clone());
            let mut entries = self.inner.search_entries(base_dn, scope).await?;
            let hint_covers_filter = matches!(
                hint,
                Some(SearchCandidateHint::Equality { .. })
                    | Some(SearchCandidateHint::Present { .. })
            );
            if hint_covers_filter {
                entries.retain(|entry| match hint.as_ref() {
                    Some(SearchCandidateHint::Equality { attribute, value }) => entry
                        .attributes
                        .get(&attribute.to_ascii_lowercase())
                        .map(|values| values.iter().any(|candidate| candidate == value))
                        .unwrap_or(false),
                    Some(SearchCandidateHint::Present { attribute }) => entry
                        .attributes
                        .contains_key(&attribute.to_ascii_lowercase()),
                    _ => true,
                });
            }

            let (sender, receiver) = tokio::sync::mpsc::channel(8);
            tokio::spawn(async move {
                for entry in entries {
                    if sender.send(Ok(entry)).await.is_err() {
                        break;
                    }
                }
            });

            Ok(crate::backend::SearchEntriesStreamReport {
                entries: receiver,
                hint_covers_filter,
                plan_type: match hint.as_ref() {
                    Some(SearchCandidateHint::Equality { .. }) => {
                        crate::backend::SearchPlanType::EqualityIndex
                    }
                    Some(SearchCandidateHint::Present { .. }) => {
                        crate::backend::SearchPlanType::PresenceIndex
                    }
                    _ => crate::backend::SearchPlanType::FullScan,
                },
                fallback_reason: (!hint_covers_filter).then_some(if hint.is_some() {
                    crate::backend::SearchPlanFallbackReason::IndexUnavailable
                } else {
                    crate::backend::SearchPlanFallbackReason::MissingHint
                }),
            })
        }

        async fn stream_projected_search_entries_with_hint_report(
            &self,
            base_dn: &str,
            scope: ldap_parser::ldap::SearchScope,
            hint: Option<SearchCandidateHint>,
            requested_attributes: Vec<String>,
        ) -> Result<crate::backend::ProjectedSearchEntriesStreamReport, BackendError> {
            self.projected_stream_search_calls
                .fetch_add(1, Ordering::SeqCst);
            self.hints.lock().unwrap().push(hint.clone());
            let mut entries = self.inner.search_entries(base_dn, scope).await?;
            let hint_covers_filter = matches!(hint, Some(SearchCandidateHint::Equality { .. }));
            if hint_covers_filter {
                entries.retain(|entry| match hint.as_ref() {
                    Some(SearchCandidateHint::Equality { attribute, value }) => entry
                        .attributes
                        .get(&attribute.to_ascii_lowercase())
                        .map(|values| values.iter().any(|candidate| candidate == value))
                        .unwrap_or(false),
                    _ => true,
                });
            }
            let projection = DirectoryAttributeProjection::new(&requested_attributes);
            let (sender, receiver) = tokio::sync::mpsc::channel(8);
            tokio::spawn(async move {
                for entry in entries {
                    let projected = ProjectedDirectoryEntry::from_entry(&entry, &projection);
                    if sender.send(Ok(projected)).await.is_err() {
                        break;
                    }
                }
            });

            Ok(crate::backend::ProjectedSearchEntriesStreamReport {
                entries: receiver,
                hint_covers_filter,
                plan_type: if hint_covers_filter {
                    crate::backend::SearchPlanType::EqualityIndex
                } else {
                    crate::backend::SearchPlanType::FullScan
                },
                fallback_reason: (!hint_covers_filter).then_some(if hint.is_some() {
                    crate::backend::SearchPlanFallbackReason::IndexUnavailable
                } else {
                    crate::backend::SearchPlanFallbackReason::MissingHint
                }),
            })
        }

        async fn get_context_csn(&self) -> Result<Option<crate::csn::Csn>, BackendError> {
            self.inner.get_context_csn().await
        }

        async fn set_context_csn(&self, csn: crate::csn::Csn) -> Result<(), BackendError> {
            self.inner.set_context_csn(csn).await
        }
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

    fn encode_sasl_plain_bind_request(message_id: u32, bind_dn: &str, password: &str) -> Vec<u8> {
        let credentials = format!("\0{bind_dn}\0{password}").into_bytes();
        let bind_request = RasnBindRequest::new(
            3,
            bind_dn.as_bytes().to_vec().into(),
            RasnAuthChoice::Sasl(RasnSaslCredentials::new(
                b"PLAIN".to_vec().into(),
                Some(credentials.into()),
            )),
        );
        let message = RasnLdapMessage::new(message_id, RasnProtocolOp::BindRequest(bind_request));
        der::encode(&message).unwrap()
    }

    fn sasl_plain_bind_request(bind_dn: &str, password: &[u8]) -> BindRequest<'static> {
        sasl_plain_bind_request_with_authzid(bind_dn, "", bind_dn, password)
    }

    fn sasl_plain_bind_request_with_authzid(
        request_dn: &str,
        authzid: &str,
        authcid: &str,
        password: &[u8],
    ) -> BindRequest<'static> {
        let mut credentials = Vec::new();
        credentials.extend_from_slice(authzid.as_bytes());
        credentials.push(0);
        credentials.extend_from_slice(authcid.as_bytes());
        credentials.push(0);
        credentials.extend_from_slice(password);

        BindRequest {
            version: 3,
            name: LdapDN(Cow::Owned(request_dn.to_string())),
            authentication: AuthenticationChoice::Sasl(SaslCredentials {
                mechanism: LdapString(Cow::Owned("PLAIN".to_string())),
                credentials: Some(Cow::Owned(credentials)),
            }),
        }
    }

    fn malformed_sasl_plain_bind_request(bind_dn: &str) -> BindRequest<'static> {
        BindRequest {
            version: 3,
            name: LdapDN(Cow::Owned(bind_dn.to_string())),
            authentication: AuthenticationChoice::Sasl(SaslCredentials {
                mechanism: LdapString(Cow::Owned("PLAIN".to_string())),
                credentials: Some(Cow::Owned(b"\0missing-password-delimiter".to_vec())),
            }),
        }
    }

    fn simple_bind_request(bind_dn: &str, password: &[u8]) -> BindRequest<'static> {
        BindRequest {
            version: 3,
            name: LdapDN(Cow::Owned(bind_dn.to_string())),
            authentication: AuthenticationChoice::Simple(Cow::Owned(password.to_vec())),
        }
    }

    fn sasl_bind_request_with_mechanism(mechanism: &str) -> BindRequest<'static> {
        BindRequest {
            version: 3,
            name: LdapDN(Cow::Owned("cn=admin,dc=example,dc=org".to_string())),
            authentication: AuthenticationChoice::Sasl(SaslCredentials {
                mechanism: LdapString(Cow::Owned(mechanism.to_string())),
                credentials: None,
            }),
        }
    }

    fn encode_root_dse_search_request(message_id: u32) -> Vec<u8> {
        encode_search_request(
            message_id,
            "",
            SearchRequestScope::BaseObject,
            RasnFilter::Present(b"objectClass".to_vec().into()),
            &["supportedLDAPVersion"],
            false,
        )
    }

    fn encode_search_request(
        message_id: u32,
        base_dn: &str,
        scope: SearchRequestScope,
        filter: RasnFilter,
        attributes: &[&str],
        types_only: bool,
    ) -> Vec<u8> {
        let search_request = RasnSearchRequest::new(
            base_dn.as_bytes().to_vec().into(),
            scope,
            SearchRequestDerefAliases::NeverDerefAliases,
            0,
            0,
            types_only,
            filter,
            attributes
                .iter()
                .map(|attribute| attribute.as_bytes().to_vec().into())
                .collect(),
        );
        let message =
            RasnLdapMessage::new(message_id, RasnProtocolOp::SearchRequest(search_request));
        der::encode(&message).unwrap()
    }

    fn encode_search_request_with_deref_aliases(
        message_id: u32,
        base_dn: &str,
        scope: SearchRequestScope,
        deref_aliases: SearchRequestDerefAliases,
        filter: RasnFilter,
        attributes: &[&str],
    ) -> Vec<u8> {
        let search_request = RasnSearchRequest::new(
            base_dn.as_bytes().to_vec().into(),
            scope,
            deref_aliases,
            0,
            0,
            false,
            filter,
            attributes
                .iter()
                .map(|attribute| attribute.as_bytes().to_vec().into())
                .collect(),
        );
        let message =
            RasnLdapMessage::new(message_id, RasnProtocolOp::SearchRequest(search_request));
        der::encode(&message).unwrap()
    }

    fn encode_search_request_with_controls(
        message_id: u32,
        base_dn: &str,
        scope: SearchRequestScope,
        filter: RasnFilter,
        attributes: &[&str],
        types_only: bool,
        controls: Vec<RasnControl>,
    ) -> Vec<u8> {
        let search_request = RasnSearchRequest::new(
            base_dn.as_bytes().to_vec().into(),
            scope,
            SearchRequestDerefAliases::NeverDerefAliases,
            0,
            0,
            types_only,
            filter,
            attributes
                .iter()
                .map(|attribute| attribute.as_bytes().to_vec().into())
                .collect(),
        );
        let mut message =
            RasnLdapMessage::new(message_id, RasnProtocolOp::SearchRequest(search_request));
        message.controls = Some(controls.into_iter().collect());
        der::encode(&message).unwrap()
    }

    fn manage_dsa_it_control() -> RasnControl {
        RasnControl::new(MANAGE_DSA_IT_OID.as_bytes().to_vec().into(), true, None)
    }

    fn server_side_sort_control(attribute: &str, reverse_order: bool) -> RasnControl {
        let value = crate::search_controls::encode_server_side_sort_request_control(&[SortKey {
            attribute_type: attribute.to_string(),
            ordering_rule: None,
            reverse_order,
        }])
        .unwrap();
        RasnControl::new(
            SERVER_SIDE_SORT_REQUEST_OID.as_bytes().to_vec().into(),
            true,
            Some(value.into()),
        )
    }

    fn paged_results_control(size: u32, cookie: &[u8]) -> RasnControl {
        let value = crate::search_controls::encode_paged_results_control(size, cookie).unwrap();
        RasnControl::new(
            PAGED_RESULTS_OID.as_bytes().to_vec().into(),
            false,
            Some(value.into()),
        )
    }

    fn sync_request_control(mode: SyncRefreshMode, cookie: Option<&[u8]>) -> RasnControl {
        let value = encode_sync_request_control(&SyncRequestControl {
            mode,
            cookie: cookie.map(|cookie| cookie.to_vec()),
            reload_hint: false,
        })
        .unwrap();
        RasnControl::new(
            SYNC_REQUEST_OID.as_bytes().to_vec().into(),
            true,
            Some(value.into()),
        )
    }

    fn search_result_dns(messages: &[ldap_parser::ldap::LdapMessage<'_>]) -> Vec<String> {
        messages
            .iter()
            .filter_map(|message| match &message.protocol_op {
                ProtocolOp::SearchResultEntry(entry) => {
                    Some(entry.object_name.0.as_ref().to_string())
                }
                _ => None,
            })
            .collect()
    }

    fn response_sort_result(
        messages: &[ldap_parser::ldap::LdapMessage<'_>],
    ) -> crate::search_controls::ServerSideSortResponseControl {
        let done = messages.last().expect("search done message");
        let controls = done.controls.as_ref().expect("response controls");
        let control = controls
            .iter()
            .find(|control| control.control_type.0.as_ref() == SERVER_SIDE_SORT_RESPONSE_OID)
            .expect("sort response control");
        crate::search_controls::decode_server_side_sort_response_control(
            control.control_value.as_deref(),
        )
        .unwrap()
    }

    fn response_paged_results(
        messages: &[ldap_parser::ldap::LdapMessage<'_>],
    ) -> crate::search_controls::PagedResultsControl {
        let done = messages.last().expect("search done message");
        let controls = done.controls.as_ref().expect("response controls");
        let control = controls
            .iter()
            .find(|control| control.control_type.0.as_ref() == PAGED_RESULTS_OID)
            .expect("paged results response control");
        crate::search_controls::decode_paged_results_control(control.control_value.as_deref())
            .unwrap()
    }

    fn response_sync_state(message: &ldap_parser::ldap::LdapMessage<'_>) -> SyncStateControl {
        let controls = message.controls.as_ref().expect("response controls");
        let control = controls
            .iter()
            .find(|control| control.control_type.0.as_ref() == SYNC_STATE_OID)
            .expect("sync state response control");
        decode_sync_state_control(control.control_value.as_deref()).unwrap()
    }

    fn response_sync_done(message: &ldap_parser::ldap::LdapMessage<'_>) {
        let controls = message.controls.as_ref().expect("response controls");
        let control = controls
            .iter()
            .find(|control| control.control_type.0.as_ref() == SYNC_DONE_OID)
            .expect("sync done response control");
        decode_sync_done_control(control.control_value.as_deref()).unwrap();
    }

    fn encode_add_request_with_attributes(
        message_id: u32,
        dn: &str,
        attributes: &[(&str, &[&str])],
    ) -> Vec<u8> {
        let attributes = attributes
            .iter()
            .map(|(name, values)| {
                Attribute::new(
                    name.as_bytes().to_vec().into(),
                    values
                        .iter()
                        .map(|value| value.as_bytes().to_vec().into())
                        .collect(),
                )
            })
            .collect();
        let request = rasn_ldap::AddRequest {
            entry: dn.as_bytes().to_vec().into(),
            attributes,
        };
        let message = RasnLdapMessage::new(message_id, RasnProtocolOp::AddRequest(request));
        der::encode(&message).unwrap()
    }

    fn encode_add_request(message_id: u32) -> Vec<u8> {
        encode_add_request_with_attributes(
            message_id,
            "cn=alice,dc=example,dc=org",
            &[
                ("objectClass", &["person"]),
                ("cn", &["alice"]),
                ("sn", &["User"]),
            ],
        )
    }

    fn encode_delete_request(message_id: u32, dn: &str) -> Vec<u8> {
        let message = RasnLdapMessage::new(
            message_id,
            RasnProtocolOp::DelRequest(rasn_ldap::DelRequest(dn.as_bytes().to_vec().into())),
        );
        der::encode(&message).unwrap()
    }

    fn encode_modify_request(
        message_id: u32,
        dn: &str,
        operation: RasnChangeOperation,
        attribute: &str,
        values: &[&str],
    ) -> Vec<u8> {
        let change = RasnModifyRequestChanges {
            operation,
            modification: RasnPartialAttribute::new(
                RasnAttributeDescription::from(attribute.as_bytes().to_vec()),
                values
                    .iter()
                    .map(|value| RasnAttributeValue::from(value.as_bytes().to_vec()))
                    .collect(),
            ),
        };
        let request = RasnModifyRequest {
            object: dn.as_bytes().to_vec().into(),
            changes: vec![change],
        };
        let message = RasnLdapMessage::new(message_id, RasnProtocolOp::ModifyRequest(request));
        der::encode(&message).unwrap()
    }

    fn encode_modifydn_request(
        message_id: u32,
        dn: &str,
        new_rdn: &str,
        delete_old_rdn: bool,
        new_superior: Option<&str>,
    ) -> Vec<u8> {
        let request = RasnModifyDnRequest {
            entry: dn.as_bytes().to_vec().into(),
            new_rdn: new_rdn.as_bytes().to_vec().into(),
            delete_old_rdn,
            new_superior: new_superior.map(|dn| dn.as_bytes().to_vec().into()),
        };
        let message = RasnLdapMessage::new(message_id, RasnProtocolOp::ModDnRequest(request));
        der::encode(&message).unwrap()
    }

    fn encode_compare_request(message_id: u32, dn: &str, attribute: &str, value: &str) -> Vec<u8> {
        let request = RasnCompareRequest {
            entry: dn.as_bytes().to_vec().into(),
            ava: RasnAttributeValueAssertion::new(
                attribute.as_bytes().to_vec().into(),
                value.as_bytes().to_vec().into(),
            ),
        };
        let message = RasnLdapMessage::new(message_id, RasnProtocolOp::CompareRequest(request));
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
        read_ldap_payload_with_timeout(stream, expected_messages, Duration::from_millis(200)).await
    }

    async fn read_ldap_payload_with_timeout(
        stream: &mut TcpStream,
        expected_messages: usize,
        response_timeout: Duration,
    ) -> Vec<u8> {
        let mut buf = Vec::new();

        loop {
            let mut chunk = vec![0u8; 4096];
            let len = timeout(response_timeout, stream.read(&mut chunk))
                .await
                .expect("response timeout")
                .expect("failed to read response");
            assert!(len > 0, "connection closed before receiving response");
            buf.extend_from_slice(&chunk[..len]);

            if let Ok((remaining, messages)) = parse_ldap_messages(&buf)
                && remaining.is_empty()
                && messages.len() >= expected_messages
            {
                return buf;
            }
        }
    }

    async fn spawn_test_connection(
        backend: Arc<dyn DirectoryBackend>,
    ) -> (tokio::task::JoinHandle<()>, TcpStream) {
        spawn_test_connection_with_runtime_context(backend, FsmServerRuntimeContext::default())
            .await
    }

    async fn spawn_test_connection_with_runtime_context(
        backend: Arc<dyn DirectoryBackend>,
        runtime_context: FsmServerRuntimeContext,
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
        let client_ip = server_stream.peer_addr().ok().map(|addr| addr.ip());

        let server_task = tokio::spawn(async move {
            let _ = handle_connection_with_transport(
                ConnectionTransport::plain(server_stream),
                backend,
                config,
                runtime_context,
                shared_schema(LdapSchema::with_core_schema()),
                pool.clone(),
                conn_id,
                client_ip,
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
    async fn handle_connection_processes_root_dse_sort_control_natively() {
        let backend = Arc::new(MockBackend::default());
        let (server_task, mut client_stream) = spawn_test_connection(backend).await;

        client_stream
            .write_all(&encode_search_request_with_controls(
                111,
                "",
                SearchRequestScope::BaseObject,
                RasnFilter::Present(b"objectClass".to_vec().into()),
                &["supportedLDAPVersion"],
                false,
                vec![server_side_sort_control("supportedLDAPVersion", false)],
            ))
            .await
            .unwrap();

        let response = read_ldap_payload(&mut client_stream, 2).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 2);
        assert!(matches!(
            messages[0].protocol_op,
            ProtocolOp::SearchResultEntry(_)
        ));
        let sort_result = response_sort_result(&messages);
        assert_eq!(sort_result.result, ServerSideSortResultCode::Success);
        assert!(matches!(
            messages.last().map(|message| &message.protocol_op),
            Some(ProtocolOp::SearchResultDone(done)) if done.result_code == ParserResultCode::Success
        ));

        client_stream.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handle_connection_processes_root_dse_paged_search_natively() {
        let backend = Arc::new(MockBackend::default());
        let (server_task, mut client_stream) = spawn_test_connection(backend).await;

        client_stream
            .write_all(&encode_search_request_with_controls(
                112,
                "",
                SearchRequestScope::BaseObject,
                RasnFilter::Present(b"objectClass".to_vec().into()),
                &["supportedLDAPVersion"],
                false,
                vec![paged_results_control(1, &[])],
            ))
            .await
            .unwrap();

        let response = read_ldap_payload(&mut client_stream, 2).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 2);
        assert!(matches!(
            messages[0].protocol_op,
            ProtocolOp::SearchResultEntry(_)
        ));
        let paged_result = response_paged_results(&messages);
        assert_eq!(paged_result.size, 1);
        assert!(paged_result.cookie.is_empty());
        assert!(matches!(
            messages.last().map(|message| &message.protocol_op),
            Some(ProtocolOp::SearchResultDone(done)) if done.result_code == ParserResultCode::Success
        ));

        client_stream.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handle_connection_processes_subschema_search_request() {
        let backend = Arc::new(MockBackend::default());
        let (server_task, mut client_stream) = spawn_test_connection(backend).await;

        client_stream
            .write_all(&encode_search_request(
                12,
                "cn=Subschema",
                SearchRequestScope::BaseObject,
                RasnFilter::Present(b"objectClass".to_vec().into()),
                &["cn", "objectClass"],
                false,
            ))
            .await
            .unwrap();

        let response = read_ldap_payload(&mut client_stream, 2).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 2);
        match &messages[0].protocol_op {
            ProtocolOp::SearchResultEntry(entry) => {
                assert_eq!(entry.object_name.0.as_ref(), "cn=Subschema");
                assert!(
                    entry
                        .attributes
                        .iter()
                        .any(|attribute| attribute.attr_type.0.as_ref() == "cn")
                );
                assert!(
                    entry
                        .attributes
                        .iter()
                        .any(|attribute| attribute.attr_type.0.as_ref() == "objectClass")
                );
            }
            other => panic!("unexpected response: {:?}", other),
        }
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
    async fn handle_connection_processes_plain_search_request() {
        let backend = Arc::new(MockBackend::default());
        backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=alice,dc=example,dc=org",
                    HashMap::from([
                        ("objectClass".to_string(), vec!["person".to_string()]),
                        ("cn".to_string(), vec!["alice".to_string()]),
                        ("mail".to_string(), vec!["alice@example.org".to_string()]),
                    ]),
                ),
                Vec::new(),
            )
            .await
            .unwrap();
        backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=bob,dc=example,dc=org",
                    HashMap::from([
                        ("objectClass".to_string(), vec!["person".to_string()]),
                        ("cn".to_string(), vec!["bob".to_string()]),
                    ]),
                ),
                Vec::new(),
            )
            .await
            .unwrap();

        let (server_task, mut client_stream) = spawn_test_connection(backend).await;

        client_stream
            .write_all(&encode_search_request(
                12,
                "dc=example,dc=org",
                SearchRequestScope::WholeSubtree,
                RasnFilter::EqualityMatch(RasnAttributeValueAssertion::new(
                    b"cn".to_vec().into(),
                    b"alice".to_vec().into(),
                )),
                &["cn"],
                false,
            ))
            .await
            .unwrap();

        let response = read_ldap_payload(&mut client_stream, 2).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 2);
        match &messages[0].protocol_op {
            ProtocolOp::SearchResultEntry(entry) => {
                assert_eq!(entry.object_name.0.as_ref(), "cn=alice,dc=example,dc=org");
                assert_eq!(entry.attributes.len(), 1);
                assert_eq!(entry.attributes[0].attr_type.0.as_ref(), "cn");
                assert_eq!(entry.attributes[0].attr_vals.len(), 1);
                assert_eq!(entry.attributes[0].attr_vals[0].0.as_ref(), b"alice");
            }
            other => panic!("unexpected response: {:?}", other),
        }
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
    async fn handle_connection_filters_search_attributes_with_aci() {
        let backend = Arc::new(MockBackend::from_credentials([(
            "cn=admin,dc=example,dc=org",
            b"secret".to_vec(),
        )]));
        backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=target,dc=example,dc=org",
                    HashMap::from([
                        ("objectClass".to_string(), vec!["person".to_string()]),
                        ("cn".to_string(), vec!["target".to_string()]),
                        ("sn".to_string(), vec!["Target".to_string()]),
                        ("userPassword".to_string(), vec!["secret".to_string()]),
                    ]),
                ),
                Vec::new(),
            )
            .await
            .unwrap();

        let aci_engine = Arc::new(crate::aci::AciEngine::restrictive());
        aci_engine
            .add_rule(
                crate::aci::AciRuleBuilder::grant("admin-search")
                    .target_subtree("dc=example,dc=org")
                    .permission(crate::aci::Permission::Search)
                    .subject_user("cn=admin,dc=example,dc=org")
                    .build()
                    .unwrap(),
            )
            .await;
        aci_engine
            .add_rule(
                crate::aci::AciRuleBuilder::grant("admin-visible-attrs")
                    .target_subtree("dc=example,dc=org")
                    .target_attributes(vec!["cn".to_string(), "objectClass".to_string()])
                    .permission(crate::aci::Permission::Read)
                    .subject_user("cn=admin,dc=example,dc=org")
                    .build()
                    .unwrap(),
            )
            .await;

        let runtime_context = FsmServerRuntimeContext {
            security: Some(Arc::new(LegacySecurityConfig {
                audit_logger: None,
                audit_config: crate::server::LegacyAuditConfig::default(),
                access_control: Some(aci_engine),
                root_dn: Some("cn=directory manager,dc=example,dc=org".to_string()),
            })),
            ..FsmServerRuntimeContext::default()
        };
        let backend_for_server: Arc<dyn DirectoryBackend> = backend;
        let (server_task, mut client_stream) =
            spawn_test_connection_with_runtime_context(backend_for_server, runtime_context).await;

        client_stream
            .write_all(&encode_bind_request(1))
            .await
            .unwrap();
        let bind_response = read_ldap_payload(&mut client_stream, 1).await;
        let (_, bind_messages) = parse_ldap_messages(&bind_response).unwrap();
        assert!(matches!(
            bind_messages.first().map(|message| &message.protocol_op),
            Some(ProtocolOp::BindResponse(response))
                if response.result.result_code == ParserResultCode::Success
        ));

        client_stream
            .write_all(&encode_search_request(
                12,
                "dc=example,dc=org",
                SearchRequestScope::WholeSubtree,
                RasnFilter::Present(b"objectClass".to_vec().into()),
                &["cn", "sn", "userPassword", "objectClass"],
                false,
            ))
            .await
            .unwrap();

        let response = read_ldap_payload(&mut client_stream, 2).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 2);
        match &messages[0].protocol_op {
            ProtocolOp::SearchResultEntry(entry) => {
                assert_eq!(entry.object_name.0.as_ref(), "cn=target,dc=example,dc=org");
                let attribute_names: Vec<&str> = entry
                    .attributes
                    .iter()
                    .map(|attribute| attribute.attr_type.0.as_ref())
                    .collect();
                assert!(attribute_names.contains(&"cn"));
                assert!(
                    attribute_names
                        .iter()
                        .any(|name| name.eq_ignore_ascii_case("objectClass"))
                );
                assert!(!attribute_names.contains(&"sn"));
                assert!(
                    !attribute_names
                        .iter()
                        .any(|name| name.eq_ignore_ascii_case("userPassword"))
                );
            }
            other => panic!("unexpected response: {:?}", other),
        }
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
    async fn handle_connection_uses_equality_search_hint_for_plain_search() {
        let backend = Arc::new(HintTrackingBackend::new());
        backend
            .insert_entry(DirectoryEntry::new(
                "cn=alice,dc=example,dc=org",
                HashMap::from([
                    ("objectClass".to_string(), vec!["person".to_string()]),
                    ("cn".to_string(), vec!["alice".to_string()]),
                ]),
            ))
            .await;
        backend
            .insert_entry(DirectoryEntry::new(
                "cn=bob,dc=example,dc=org",
                HashMap::from([
                    ("objectClass".to_string(), vec!["person".to_string()]),
                    ("cn".to_string(), vec!["bob".to_string()]),
                ]),
            ))
            .await;

        let backend_for_server: Arc<dyn DirectoryBackend> = backend.clone();
        let (server_task, mut client_stream) = spawn_test_connection(backend_for_server).await;

        client_stream
            .write_all(&encode_search_request(
                122,
                "dc=example,dc=org",
                SearchRequestScope::WholeSubtree,
                RasnFilter::EqualityMatch(RasnAttributeValueAssertion::new(
                    b"cn".to_vec().into(),
                    b"alice".to_vec().into(),
                )),
                &["cn"],
                false,
            ))
            .await
            .unwrap();

        let response = read_ldap_payload(&mut client_stream, 2).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(
            search_result_dns(&messages),
            vec!["cn=alice,dc=example,dc=org".to_string()]
        );
        assert!(matches!(
            messages.last().map(|message| &message.protocol_op),
            Some(ProtocolOp::SearchResultDone(done)) if done.result_code == ParserResultCode::Success
        ));
        assert_eq!(backend.direct_search_calls(), 0);
        assert_eq!(backend.hinted_search_calls(), 1);
        assert_eq!(
            backend.recorded_hints(),
            vec![Some(SearchCandidateHint::Equality {
                attribute: "cn".to_string(),
                value: "alice".to_string(),
            })]
        );

        client_stream.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handle_connection_streams_index_covered_plain_search_when_supported() {
        let backend = Arc::new(HintTrackingBackend::new_streaming());
        backend
            .insert_entry(DirectoryEntry::new(
                "cn=alice,dc=example,dc=org",
                HashMap::from([
                    ("objectClass".to_string(), vec!["person".to_string()]),
                    ("cn".to_string(), vec!["alice".to_string()]),
                ]),
            ))
            .await;
        backend
            .insert_entry(DirectoryEntry::new(
                "cn=bob,dc=example,dc=org",
                HashMap::from([
                    ("objectClass".to_string(), vec!["person".to_string()]),
                    ("cn".to_string(), vec!["bob".to_string()]),
                ]),
            ))
            .await;

        let backend_for_server: Arc<dyn DirectoryBackend> = backend.clone();
        let (server_task, mut client_stream) = spawn_test_connection(backend_for_server).await;

        client_stream
            .write_all(&encode_search_request(
                124,
                "dc=example,dc=org",
                SearchRequestScope::WholeSubtree,
                RasnFilter::EqualityMatch(RasnAttributeValueAssertion::new(
                    b"cn".to_vec().into(),
                    b"alice".to_vec().into(),
                )),
                &["cn"],
                false,
            ))
            .await
            .unwrap();

        let response = read_ldap_payload(&mut client_stream, 2).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(
            search_result_dns(&messages),
            vec!["cn=alice,dc=example,dc=org".to_string()]
        );
        assert!(matches!(
            messages.last().map(|message| &message.protocol_op),
            Some(ProtocolOp::SearchResultDone(done)) if done.result_code == ParserResultCode::Success
        ));
        assert_eq!(backend.direct_search_calls(), 0);
        assert_eq!(backend.hinted_search_calls(), 0);
        assert_eq!(backend.stream_search_calls(), 0);
        assert_eq!(backend.projected_stream_search_calls(), 1);
        assert_eq!(
            backend.recorded_hints(),
            vec![Some(SearchCandidateHint::Equality {
                attribute: "cn".to_string(),
                value: "alice".to_string(),
            })]
        );

        client_stream.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handle_connection_streams_and_filters_uncovered_plain_search_when_supported() {
        let backend = Arc::new(HintTrackingBackend::new_streaming());
        backend
            .insert_entry(DirectoryEntry::new(
                "cn=alice,dc=example,dc=org",
                HashMap::from([
                    ("objectClass".to_string(), vec!["person".to_string()]),
                    ("cn".to_string(), vec!["Alice".to_string()]),
                ]),
            ))
            .await;
        backend
            .insert_entry(DirectoryEntry::new(
                "cn=bob,dc=example,dc=org",
                HashMap::from([
                    ("objectClass".to_string(), vec!["person".to_string()]),
                    ("cn".to_string(), vec!["Bob".to_string()]),
                ]),
            ))
            .await;

        let backend_for_server: Arc<dyn DirectoryBackend> = backend.clone();
        let (server_task, mut client_stream) = spawn_test_connection(backend_for_server).await;

        client_stream
            .write_all(&encode_search_request(
                125,
                "dc=example,dc=org",
                SearchRequestScope::WholeSubtree,
                RasnFilter::ExtensibleMatch(rasn_ldap::MatchingRuleAssertion::new(
                    Some(b"caseIgnoreMatch".to_vec().into()),
                    Some(b"cn".to_vec().into()),
                    b"alice".to_vec().into(),
                    false,
                )),
                &["cn"],
                false,
            ))
            .await
            .unwrap();

        let response = read_ldap_payload(&mut client_stream, 2).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(
            search_result_dns(&messages),
            vec!["cn=alice,dc=example,dc=org".to_string()]
        );
        assert!(matches!(
            messages.last().map(|message| &message.protocol_op),
            Some(ProtocolOp::SearchResultDone(done)) if done.result_code == ParserResultCode::Success
        ));
        assert_eq!(backend.direct_search_calls(), 0);
        assert_eq!(backend.hinted_search_calls(), 0);
        assert_eq!(backend.stream_search_calls(), 1);
        assert_eq!(backend.projected_stream_search_calls(), 0);

        client_stream.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handle_connection_uses_present_search_hint_for_plain_search() {
        let backend = Arc::new(HintTrackingBackend::new());
        backend
            .insert_entry(DirectoryEntry::new(
                "cn=alice,dc=example,dc=org",
                HashMap::from([
                    ("objectClass".to_string(), vec!["person".to_string()]),
                    ("cn".to_string(), vec!["alice".to_string()]),
                    ("mail".to_string(), vec!["alice@example.org".to_string()]),
                ]),
            ))
            .await;
        backend
            .insert_entry(DirectoryEntry::new(
                "cn=bob,dc=example,dc=org",
                HashMap::from([
                    ("objectClass".to_string(), vec!["person".to_string()]),
                    ("cn".to_string(), vec!["bob".to_string()]),
                ]),
            ))
            .await;

        let backend_for_server: Arc<dyn DirectoryBackend> = backend.clone();
        let (server_task, mut client_stream) = spawn_test_connection(backend_for_server).await;

        client_stream
            .write_all(&encode_search_request(
                123,
                "dc=example,dc=org",
                SearchRequestScope::WholeSubtree,
                RasnFilter::Present(b"mail".to_vec().into()),
                &["cn", "mail"],
                false,
            ))
            .await
            .unwrap();

        let response = read_ldap_payload(&mut client_stream, 2).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(
            search_result_dns(&messages),
            vec!["cn=alice,dc=example,dc=org".to_string()]
        );
        assert!(matches!(
            messages.last().map(|message| &message.protocol_op),
            Some(ProtocolOp::SearchResultDone(done)) if done.result_code == ParserResultCode::Success
        ));
        assert_eq!(backend.direct_search_calls(), 0);
        assert_eq!(backend.hinted_search_calls(), 1);
        assert_eq!(
            backend.recorded_hints(),
            vec![Some(SearchCandidateHint::Present {
                attribute: "mail".to_string(),
            })]
        );

        client_stream.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handle_connection_batches_large_plain_search_result_set() {
        let backend = Arc::new(MockBackend::default());
        let entry_count = 1_100usize;

        for index in 0..entry_count {
            let uid = format!("user{index:04}");
            backend
                .add_entry(
                    DirectoryEntry::new(
                        format!("uid={uid},ou=people,dc=example,dc=org"),
                        HashMap::from([
                            ("objectClass".to_string(), vec!["inetOrgPerson".to_string()]),
                            ("uid".to_string(), vec![uid.clone()]),
                            ("cn".to_string(), vec![format!("User {index:04}")]),
                            ("sn".to_string(), vec![format!("Surname {index:04}")]),
                            ("mail".to_string(), vec![format!("{uid}@example.org")]),
                            ("description".to_string(), vec!["x".repeat(128)]),
                        ]),
                    ),
                    Vec::new(),
                )
                .await
                .unwrap();
        }

        let (server_task, mut client_stream) = spawn_test_connection(backend).await;

        client_stream
            .write_all(&encode_search_request(
                121,
                "dc=example,dc=org",
                SearchRequestScope::WholeSubtree,
                RasnFilter::Present(b"objectClass".to_vec().into()),
                &["uid", "cn", "sn", "mail", "description"],
                false,
            ))
            .await
            .unwrap();

        let response = read_ldap_payload_with_timeout(
            &mut client_stream,
            entry_count + 1,
            Duration::from_secs(5),
        )
        .await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), entry_count + 1);
        let dns = search_result_dns(&messages);
        assert_eq!(dns.len(), entry_count);
        assert!(dns.contains(&"uid=user0000,ou=people,dc=example,dc=org".to_string()));
        assert!(dns.contains(&"uid=user1099,ou=people,dc=example,dc=org".to_string()));
        assert!(matches!(
            messages.last().map(|message| &message.protocol_op),
            Some(ProtocolOp::SearchResultDone(done)) if done.result_code == ParserResultCode::Success
        ));

        client_stream.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handle_connection_processes_extensible_match_search_natively() {
        let backend = Arc::new(MockBackend::default());
        backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=alice,dc=example,dc=org",
                    HashMap::from([
                        ("objectClass".to_string(), vec!["person".to_string()]),
                        ("cn".to_string(), vec!["Alice".to_string()]),
                    ]),
                ),
                Vec::new(),
            )
            .await
            .unwrap();

        let (server_task, mut client_stream) = spawn_test_connection(backend).await;

        client_stream
            .write_all(&encode_search_request(
                13,
                "dc=example,dc=org",
                SearchRequestScope::WholeSubtree,
                RasnFilter::ExtensibleMatch(rasn_ldap::MatchingRuleAssertion::new(
                    Some(b"caseIgnoreMatch".to_vec().into()),
                    Some(b"cn".to_vec().into()),
                    b"alice".to_vec().into(),
                    false,
                )),
                &["cn"],
                false,
            ))
            .await
            .unwrap();

        let response = read_ldap_payload(&mut client_stream, 2).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(
            search_result_dns(&messages),
            vec!["cn=alice,dc=example,dc=org".to_string()]
        );
        assert!(matches!(
            messages.last().map(|message| &message.protocol_op),
            Some(ProtocolOp::SearchResultDone(done)) if done.result_code == ParserResultCode::Success
        ));

        client_stream.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handle_connection_processes_types_only_search_request() {
        let backend = Arc::new(MockBackend::default());
        backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=alice,dc=example,dc=org",
                    HashMap::from([
                        ("objectClass".to_string(), vec!["person".to_string()]),
                        ("cn".to_string(), vec!["alice".to_string()]),
                        ("mail".to_string(), vec!["alice@example.org".to_string()]),
                    ]),
                ),
                Vec::new(),
            )
            .await
            .unwrap();

        let (server_task, mut client_stream) = spawn_test_connection(backend).await;

        client_stream
            .write_all(&encode_search_request(
                13,
                "dc=example,dc=org",
                SearchRequestScope::WholeSubtree,
                RasnFilter::EqualityMatch(RasnAttributeValueAssertion::new(
                    b"cn".to_vec().into(),
                    b"alice".to_vec().into(),
                )),
                &["cn", "mail"],
                true,
            ))
            .await
            .unwrap();

        let response = read_ldap_payload(&mut client_stream, 2).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 2);
        match &messages[0].protocol_op {
            ProtocolOp::SearchResultEntry(entry) => {
                assert_eq!(entry.object_name.0.as_ref(), "cn=alice,dc=example,dc=org");
                assert_eq!(entry.attributes.len(), 2);
                assert!(
                    entry
                        .attributes
                        .iter()
                        .all(|attr| attr.attr_vals.is_empty())
                );
            }
            other => panic!("unexpected response: {:?}", other),
        }
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
    async fn handle_connection_processes_server_side_sort_search_natively() {
        let backend = Arc::new(MockBackend::default());
        for (dn, cn) in [
            ("cn=bob,dc=example,dc=org", "bob"),
            ("cn=alice,dc=example,dc=org", "alice"),
            ("cn=charlie,dc=example,dc=org", "charlie"),
        ] {
            backend
                .add_entry(
                    DirectoryEntry::new(
                        dn,
                        HashMap::from([
                            ("objectClass".to_string(), vec!["person".to_string()]),
                            ("cn".to_string(), vec![cn.to_string()]),
                        ]),
                    ),
                    Vec::new(),
                )
                .await
                .unwrap();
        }

        let (server_task, mut client_stream) = spawn_test_connection(backend).await;

        client_stream
            .write_all(&encode_search_request_with_controls(
                14,
                "dc=example,dc=org",
                SearchRequestScope::WholeSubtree,
                RasnFilter::Present(b"objectClass".to_vec().into()),
                &["cn"],
                false,
                vec![server_side_sort_control("cn", false)],
            ))
            .await
            .unwrap();

        let response = read_ldap_payload(&mut client_stream, 4).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(
            search_result_dns(&messages),
            vec![
                "cn=alice,dc=example,dc=org".to_string(),
                "cn=bob,dc=example,dc=org".to_string(),
                "cn=charlie,dc=example,dc=org".to_string(),
            ]
        );
        let sort_result = response_sort_result(&messages);
        assert_eq!(sort_result.result, ServerSideSortResultCode::Success);
        assert!(matches!(
            messages.last().map(|message| &message.protocol_op),
            Some(ProtocolOp::SearchResultDone(done)) if done.result_code == ParserResultCode::Success
        ));

        client_stream.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handle_connection_processes_paged_search_natively() {
        let backend = Arc::new(MockBackend::default());
        for cn in ["alice", "bob", "charlie"] {
            backend
                .add_entry(
                    DirectoryEntry::new(
                        format!("cn={cn},dc=example,dc=org"),
                        HashMap::from([
                            ("objectClass".to_string(), vec!["person".to_string()]),
                            ("cn".to_string(), vec![cn.to_string()]),
                        ]),
                    ),
                    Vec::new(),
                )
                .await
                .unwrap();
        }

        let (server_task, mut client_stream) = spawn_test_connection(backend).await;

        client_stream
            .write_all(&encode_search_request_with_controls(
                20,
                "dc=example,dc=org",
                SearchRequestScope::WholeSubtree,
                RasnFilter::Present(b"objectClass".to_vec().into()),
                &["cn"],
                false,
                vec![paged_results_control(2, &[])],
            ))
            .await
            .unwrap();

        let response = read_ldap_payload(&mut client_stream, 3).await;
        let (_, first_page) = parse_ldap_messages(&response).unwrap();
        assert_eq!(search_result_dns(&first_page).len(), 2);
        let first_page_control = response_paged_results(&first_page);
        assert_eq!(first_page_control.size, 3);
        assert!(!first_page_control.cookie.is_empty());

        client_stream
            .write_all(&encode_search_request_with_controls(
                21,
                "dc=example,dc=org",
                SearchRequestScope::WholeSubtree,
                RasnFilter::Present(b"objectClass".to_vec().into()),
                &["cn"],
                false,
                vec![paged_results_control(2, &first_page_control.cookie)],
            ))
            .await
            .unwrap();

        let response = read_ldap_payload(&mut client_stream, 2).await;
        let (_, second_page) = parse_ldap_messages(&response).unwrap();
        assert_eq!(search_result_dns(&second_page).len(), 1);
        let second_page_control = response_paged_results(&second_page);
        assert_eq!(second_page_control.size, 3);
        assert!(second_page_control.cookie.is_empty());
        assert!(matches!(
            second_page.last().map(|message| &message.protocol_op),
            Some(ProtocolOp::SearchResultDone(done)) if done.result_code == ParserResultCode::Success
        ));

        client_stream.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handle_connection_processes_sorted_paged_search_natively() {
        let backend = Arc::new(MockBackend::default());
        for cn in ["charlie", "alice", "bob"] {
            backend
                .add_entry(
                    DirectoryEntry::new(
                        format!("cn={cn},dc=example,dc=org"),
                        HashMap::from([
                            ("objectClass".to_string(), vec!["person".to_string()]),
                            ("cn".to_string(), vec![cn.to_string()]),
                        ]),
                    ),
                    Vec::new(),
                )
                .await
                .unwrap();
        }

        let (server_task, mut client_stream) = spawn_test_connection(backend).await;

        client_stream
            .write_all(&encode_search_request_with_controls(
                22,
                "dc=example,dc=org",
                SearchRequestScope::WholeSubtree,
                RasnFilter::Present(b"objectClass".to_vec().into()),
                &["cn"],
                false,
                vec![
                    paged_results_control(2, &[]),
                    server_side_sort_control("cn", false),
                ],
            ))
            .await
            .unwrap();

        let response = read_ldap_payload(&mut client_stream, 3).await;
        let (_, first_page) = parse_ldap_messages(&response).unwrap();
        assert_eq!(
            search_result_dns(&first_page),
            vec![
                "cn=alice,dc=example,dc=org".to_string(),
                "cn=bob,dc=example,dc=org".to_string(),
            ]
        );
        assert_eq!(
            response_sort_result(&first_page).result,
            ServerSideSortResultCode::Success
        );
        let first_page_control = response_paged_results(&first_page);
        assert!(!first_page_control.cookie.is_empty());

        client_stream
            .write_all(&encode_search_request_with_controls(
                23,
                "dc=example,dc=org",
                SearchRequestScope::WholeSubtree,
                RasnFilter::Present(b"objectClass".to_vec().into()),
                &["cn"],
                false,
                vec![
                    paged_results_control(2, &first_page_control.cookie),
                    server_side_sort_control("cn", false),
                ],
            ))
            .await
            .unwrap();

        let response = read_ldap_payload(&mut client_stream, 2).await;
        let (_, second_page) = parse_ldap_messages(&response).unwrap();
        assert_eq!(
            search_result_dns(&second_page),
            vec!["cn=charlie,dc=example,dc=org".to_string()]
        );
        assert!(response_paged_results(&second_page).cookie.is_empty());
        assert_eq!(
            response_sort_result(&second_page).result,
            ServerSideSortResultCode::Success
        );

        client_stream.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handle_connection_processes_sync_refresh_only_search_natively() {
        let mut config = ServerConfig::default();
        config.server.base_dn = "dc=example,dc=org".to_string();
        config.replication.enabled = true;
        config.replication.mode = "provider".to_string();

        let backend = Arc::new(MockBackend::new());
        let service = ReplicationService::from_config(&config, backend).unwrap();
        let provider_backend = service.backend();
        provider_backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=sync-user,dc=example,dc=org",
                    HashMap::from([
                        ("objectClass".to_string(), vec!["person".to_string()]),
                        ("cn".to_string(), vec!["sync-user".to_string()]),
                    ]),
                ),
                Vec::new(),
            )
            .await
            .unwrap();

        let (server_task, mut client_stream) = spawn_test_connection(provider_backend).await;

        client_stream
            .write_all(&encode_search_request_with_controls(
                24,
                "dc=example,dc=org",
                SearchRequestScope::WholeSubtree,
                RasnFilter::Present(b"objectClass".to_vec().into()),
                &["cn"],
                false,
                vec![sync_request_control(SyncRefreshMode::RefreshOnly, None)],
            ))
            .await
            .unwrap();

        let response = read_ldap_payload(&mut client_stream, 2).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(
            search_result_dns(&messages),
            vec!["cn=sync-user,dc=example,dc=org".to_string()]
        );
        assert_eq!(
            response_sync_state(&messages[0]).state,
            SyncStateType::Present
        );
        assert!(matches!(
            messages.last().map(|message| &message.protocol_op),
            Some(ProtocolOp::SearchResultDone(done)) if done.result_code == ParserResultCode::Success
        ));
        response_sync_done(messages.last().expect("sync done message"));

        client_stream.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handle_connection_processes_manage_dsa_it_search_as_entry() {
        let backend = Arc::new(MockBackend::default());
        backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=referral,dc=example,dc=org",
                    HashMap::from([
                        ("objectClass".to_string(), vec!["referral".to_string()]),
                        (
                            "ref".to_string(),
                            vec!["ldap://remote.example.org/dc=example,dc=org".to_string()],
                        ),
                    ]),
                ),
                Vec::new(),
            )
            .await
            .unwrap();

        let (server_task, mut client_stream) = spawn_test_connection(backend).await;

        client_stream
            .write_all(&encode_search_request_with_controls(
                14,
                "cn=referral,dc=example,dc=org",
                SearchRequestScope::BaseObject,
                RasnFilter::Present(b"objectClass".to_vec().into()),
                &["objectClass", "ref"],
                false,
                vec![manage_dsa_it_control()],
            ))
            .await
            .unwrap();

        let response = read_ldap_payload(&mut client_stream, 2).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 2);
        match &messages[0].protocol_op {
            ProtocolOp::SearchResultEntry(entry) => {
                assert_eq!(
                    entry.object_name.0.as_ref(),
                    "cn=referral,dc=example,dc=org"
                );
                assert!(
                    entry
                        .attributes
                        .iter()
                        .any(|attribute| attribute.attr_type.0.as_ref() == "ref")
                );
            }
            other => panic!("unexpected response: {:?}", other),
        }
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
    async fn handle_connection_processes_base_search_referral_natively() {
        let backend = Arc::new(MockBackend::default());
        backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=referral,dc=example,dc=org",
                    HashMap::from([
                        ("objectClass".to_string(), vec!["referral".to_string()]),
                        (
                            "ref".to_string(),
                            vec!["ldap://remote.example.org/dc=example,dc=org".to_string()],
                        ),
                    ]),
                ),
                Vec::new(),
            )
            .await
            .unwrap();

        let (server_task, mut client_stream) = spawn_test_connection(backend).await;

        client_stream
            .write_all(&encode_search_request(
                15,
                "cn=referral,dc=example,dc=org",
                SearchRequestScope::BaseObject,
                RasnFilter::Present(b"objectClass".to_vec().into()),
                &["objectClass"],
                false,
            ))
            .await
            .unwrap();

        let response = read_ldap_payload(&mut client_stream, 1).await;
        let decoded: RasnLdapMessage = der::decode(&response).unwrap();
        match decoded.protocol_op {
            RasnProtocolOp::SearchResDone(done) => {
                assert_eq!(done.0.result_code, ResultCode::Referral);
                let referrals = done.0.referral.expect("referral URLs");
                let urls: Vec<String> = referrals
                    .iter()
                    .map(|value| String::from_utf8(value.to_vec()).expect("valid UTF-8 URL"))
                    .collect();
                assert_eq!(
                    urls,
                    vec!["ldap://remote.example.org/dc=example,dc=org".to_string()]
                );
            }
            other => panic!("unexpected response: {:?}", other),
        }

        client_stream.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handle_connection_processes_subtree_search_referral_reference_natively() {
        let backend = Arc::new(MockBackend::default());
        backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=alice,dc=example,dc=org",
                    HashMap::from([
                        ("objectClass".to_string(), vec!["person".to_string()]),
                        ("cn".to_string(), vec!["alice".to_string()]),
                    ]),
                ),
                Vec::new(),
            )
            .await
            .unwrap();
        backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=referral,dc=example,dc=org",
                    HashMap::from([
                        ("objectClass".to_string(), vec!["referral".to_string()]),
                        (
                            "ref".to_string(),
                            vec!["ldap://remote.example.org/dc=example,dc=org??sub".to_string()],
                        ),
                    ]),
                ),
                Vec::new(),
            )
            .await
            .unwrap();

        let (server_task, mut client_stream) = spawn_test_connection(backend).await;

        client_stream
            .write_all(&encode_search_request(
                16,
                "dc=example,dc=org",
                SearchRequestScope::WholeSubtree,
                RasnFilter::Present(b"objectClass".to_vec().into()),
                &["cn"],
                false,
            ))
            .await
            .unwrap();

        let response = read_ldap_payload(&mut client_stream, 3).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 3);
        assert!(
            messages
                .iter()
                .any(|message| matches!(message.protocol_op, ProtocolOp::SearchResultEntry(_)))
        );
        let reference = messages
            .iter()
            .find_map(|message| match &message.protocol_op {
                ProtocolOp::SearchResultReference(refs) => Some(
                    refs.iter()
                        .map(|url| url.0.as_ref().to_string())
                        .collect::<Vec<_>>(),
                ),
                _ => None,
            })
            .expect("search result reference");
        assert_eq!(
            reference,
            vec!["ldap://remote.example.org/dc=example,dc=org??sub".to_string()]
        );
        assert!(matches!(
            messages.last().map(|message| &message.protocol_op),
            Some(ProtocolOp::SearchResultDone(done)) if done.result_code == ParserResultCode::Success
        ));

        client_stream.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handle_connection_search_dereferences_alias_base_natively() {
        let backend = Arc::new(MockBackend::default());
        backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=target,dc=example,dc=org",
                    HashMap::from([
                        ("objectclass".to_string(), vec!["person".to_string()]),
                        ("cn".to_string(), vec!["Target User".to_string()]),
                        ("sn".to_string(), vec!["Target".to_string()]),
                    ]),
                ),
                Vec::new(),
            )
            .await
            .unwrap();
        backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=alias,dc=example,dc=org",
                    HashMap::from([
                        ("objectclass".to_string(), vec!["alias".to_string()]),
                        ("cn".to_string(), vec!["Alias Entry".to_string()]),
                        (
                            "aliasedobjectname".to_string(),
                            vec!["cn=target,dc=example,dc=org".to_string()],
                        ),
                    ]),
                ),
                Vec::new(),
            )
            .await
            .unwrap();

        let (server_task, mut client_stream) = spawn_test_connection(backend).await;

        client_stream
            .write_all(&encode_search_request_with_deref_aliases(
                17,
                "cn=alias,dc=example,dc=org",
                SearchRequestScope::BaseObject,
                SearchRequestDerefAliases::DerefFindingBaseObj,
                RasnFilter::Present(b"objectClass".to_vec().into()),
                &["cn"],
            ))
            .await
            .unwrap();

        let response = read_ldap_payload(&mut client_stream, 2).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 2);
        match &messages[0].protocol_op {
            ProtocolOp::SearchResultEntry(entry) => {
                assert_eq!(entry.object_name.0.as_ref(), "cn=target,dc=example,dc=org");
            }
            other => panic!("unexpected response: {:?}", other),
        }
        assert!(matches!(
            messages.last().map(|message| &message.protocol_op),
            Some(ProtocolOp::SearchResultDone(done)) if done.result_code == ParserResultCode::Success
        ));

        client_stream.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handle_connection_search_dereferences_alias_candidates_natively() {
        let backend = Arc::new(MockBackend::default());
        backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=target,ou=people,dc=example,dc=org",
                    HashMap::from([
                        ("objectclass".to_string(), vec!["person".to_string()]),
                        ("cn".to_string(), vec!["Target User".to_string()]),
                        ("sn".to_string(), vec!["Target".to_string()]),
                    ]),
                ),
                Vec::new(),
            )
            .await
            .unwrap();
        backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=external,ou=aliases,dc=example,dc=org",
                    HashMap::from([
                        ("objectclass".to_string(), vec!["alias".to_string()]),
                        ("cn".to_string(), vec!["External Alias".to_string()]),
                        (
                            "aliasedobjectname".to_string(),
                            vec!["cn=target,ou=people,dc=example,dc=org".to_string()],
                        ),
                    ]),
                ),
                Vec::new(),
            )
            .await
            .unwrap();

        let (server_task, mut client_stream) = spawn_test_connection(backend).await;

        client_stream
            .write_all(&encode_search_request_with_deref_aliases(
                18,
                "ou=aliases,dc=example,dc=org",
                SearchRequestScope::WholeSubtree,
                SearchRequestDerefAliases::DerefAlways,
                RasnFilter::EqualityMatch(RasnAttributeValueAssertion::new(
                    b"sn".to_vec().into(),
                    b"Target".to_vec().into(),
                )),
                &["cn"],
            ))
            .await
            .unwrap();

        let response = read_ldap_payload(&mut client_stream, 2).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 2);
        match &messages[0].protocol_op {
            ProtocolOp::SearchResultEntry(entry) => {
                assert_eq!(
                    entry.object_name.0.as_ref(),
                    "cn=target,ou=people,dc=example,dc=org"
                );
            }
            other => panic!("unexpected response: {:?}", other),
        }
        assert!(matches!(
            messages.last().map(|message| &message.protocol_op),
            Some(ProtocolOp::SearchResultDone(done)) if done.result_code == ParserResultCode::Success
        ));

        client_stream.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handle_connection_search_deref_alias_loop_returns_loop_detect() {
        let backend = Arc::new(MockBackend::default());
        backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=loop-a,dc=example,dc=org",
                    HashMap::from([
                        ("objectclass".to_string(), vec!["alias".to_string()]),
                        ("cn".to_string(), vec!["Loop A".to_string()]),
                        (
                            "aliasedobjectname".to_string(),
                            vec!["cn=loop-b,dc=example,dc=org".to_string()],
                        ),
                    ]),
                ),
                Vec::new(),
            )
            .await
            .unwrap();
        backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=loop-b,dc=example,dc=org",
                    HashMap::from([
                        ("objectclass".to_string(), vec!["alias".to_string()]),
                        ("cn".to_string(), vec!["Loop B".to_string()]),
                        (
                            "aliasedobjectname".to_string(),
                            vec!["cn=loop-a,dc=example,dc=org".to_string()],
                        ),
                    ]),
                ),
                Vec::new(),
            )
            .await
            .unwrap();

        let (server_task, mut client_stream) = spawn_test_connection(backend).await;

        client_stream
            .write_all(&encode_search_request_with_deref_aliases(
                19,
                "cn=loop-a,dc=example,dc=org",
                SearchRequestScope::BaseObject,
                SearchRequestDerefAliases::DerefAlways,
                RasnFilter::Present(b"objectClass".to_vec().into()),
                &["cn"],
            ))
            .await
            .unwrap();

        let response = read_ldap_payload(&mut client_stream, 1).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 1);
        match &messages[0].protocol_op {
            ProtocolOp::SearchResultDone(done) => {
                assert_eq!(done.result_code, ParserResultCode::LoopDetect);
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
    async fn handle_connection_processes_add_request_and_preserves_password() {
        let backend = Arc::new(MockBackend::default());
        let (server_task, mut client_stream) = spawn_test_connection(backend.clone()).await;

        client_stream
            .write_all(&encode_bind_request(13))
            .await
            .unwrap();
        let bind_response = read_ldap_payload(&mut client_stream, 1).await;
        let (_, bind_messages) = parse_ldap_messages(&bind_response).unwrap();
        assert_eq!(bind_messages.len(), 1);

        client_stream
            .write_all(&encode_add_request_with_attributes(
                14,
                "cn=add-me,dc=example,dc=org",
                &[
                    ("objectClass", &["person"]),
                    ("cn", &["add-me"]),
                    ("sn", &["User"]),
                    ("userPassword", &["new-secret"]),
                ],
            ))
            .await
            .unwrap();

        let response = read_ldap_payload(&mut client_stream, 1).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message_id.0, 14);
        match &messages[0].protocol_op {
            ProtocolOp::AddResponse(result) => {
                assert_eq!(result.result_code, ParserResultCode::Success);
            }
            other => panic!("unexpected response: {:?}", other),
        }

        assert!(
            backend
                .get_entry("cn=add-me,dc=example,dc=org")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            backend
                .authenticate("cn=add-me,dc=example,dc=org", b"new-secret")
                .await
                .unwrap()
        );

        client_stream.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handle_connection_add_duplicate_returns_entry_already_exists() {
        let backend = Arc::new(MockBackend::default());
        backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=duplicate,dc=example,dc=org",
                    HashMap::from([
                        ("objectClass".to_string(), vec!["person".to_string()]),
                        ("cn".to_string(), vec!["duplicate".to_string()]),
                        ("sn".to_string(), vec!["User".to_string()]),
                    ]),
                ),
                Vec::new(),
            )
            .await
            .unwrap();

        let (server_task, mut client_stream) = spawn_test_connection(backend).await;

        client_stream
            .write_all(&encode_bind_request(15))
            .await
            .unwrap();
        let bind_response = read_ldap_payload(&mut client_stream, 1).await;
        let (_, bind_messages) = parse_ldap_messages(&bind_response).unwrap();
        assert_eq!(bind_messages.len(), 1);

        client_stream
            .write_all(&encode_add_request_with_attributes(
                16,
                "cn=duplicate,dc=example,dc=org",
                &[
                    ("objectClass", &["person"]),
                    ("cn", &["duplicate"]),
                    ("sn", &["User"]),
                ],
            ))
            .await
            .unwrap();

        let response = read_ldap_payload(&mut client_stream, 1).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message_id.0, 16);
        match &messages[0].protocol_op {
            ProtocolOp::AddResponse(result) => {
                assert_eq!(result.result_code, ParserResultCode::EntryAlreadyExists);
            }
            other => panic!("unexpected response: {:?}", other),
        }

        client_stream.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handle_connection_add_invalid_entry_returns_object_class_violation() {
        let backend = Arc::new(MockBackend::default());
        let (server_task, mut client_stream) = spawn_test_connection(backend).await;

        client_stream
            .write_all(&encode_bind_request(17))
            .await
            .unwrap();
        let bind_response = read_ldap_payload(&mut client_stream, 1).await;
        let (_, bind_messages) = parse_ldap_messages(&bind_response).unwrap();
        assert_eq!(bind_messages.len(), 1);

        client_stream
            .write_all(&encode_add_request_with_attributes(
                18,
                "cn=invalid,dc=example,dc=org",
                &[("objectClass", &["person"]), ("cn", &["invalid"])],
            ))
            .await
            .unwrap();

        let response = read_ldap_payload(&mut client_stream, 1).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message_id.0, 18);
        match &messages[0].protocol_op {
            ProtocolOp::AddResponse(result) => {
                assert_eq!(result.result_code, ParserResultCode::ObjectClassViolation);
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

    #[tokio::test]
    async fn handle_bind_with_fsm_accepts_secure_sasl_plain() {
        let backend = Arc::new(MockBackend::default());
        let (server_stream, mut client_stream) = connected_stream_pair().await;
        let mut fsm_set = ConnectionFsmSet::new(server_stream, backend, None);

        handle_bind_with_fsm(
            &mut fsm_set,
            31,
            sasl_plain_bind_request("cn=admin,dc=example,dc=org", b"secret"),
            true,
            &RequestContext::default(),
            None,
        )
        .await
        .unwrap();

        let response = read_ldap_payload(&mut client_stream, 1).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(
            fsm_set.authenticated_dn(),
            Some("cn=admin,dc=example,dc=org")
        );
        match &messages[0].protocol_op {
            ProtocolOp::BindResponse(bind_response) => {
                assert_eq!(bind_response.result.result_code, ParserResultCode::Success);
            }
            other => panic!("unexpected response: {:?}", other),
        }
    }

    #[tokio::test]
    async fn handle_bind_with_fsm_rejects_secure_sasl_plain_wrong_password() {
        let backend = Arc::new(MockBackend::default());
        let (server_stream, mut client_stream) = connected_stream_pair().await;
        let mut fsm_set = ConnectionFsmSet::new(server_stream, backend, None);

        handle_bind_with_fsm(
            &mut fsm_set,
            32,
            sasl_plain_bind_request("cn=admin,dc=example,dc=org", b"wrong"),
            true,
            &RequestContext::default(),
            None,
        )
        .await
        .unwrap();

        let response = read_ldap_payload(&mut client_stream, 1).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(fsm_set.authenticated_dn(), None);
        match &messages[0].protocol_op {
            ProtocolOp::BindResponse(bind_response) => {
                assert_eq!(
                    bind_response.result.result_code,
                    ParserResultCode::InvalidCredentials
                );
            }
            other => panic!("unexpected response: {:?}", other),
        }
    }

    #[tokio::test]
    async fn handle_bind_with_fsm_rejects_malformed_sasl_plain_credentials() {
        let backend = Arc::new(MockBackend::default());
        let (server_stream, mut client_stream) = connected_stream_pair().await;
        let mut fsm_set = ConnectionFsmSet::new(server_stream, backend, None);

        handle_bind_with_fsm(
            &mut fsm_set,
            37,
            malformed_sasl_plain_bind_request("cn=admin,dc=example,dc=org"),
            true,
            &RequestContext::default(),
            None,
        )
        .await
        .unwrap();

        let response = read_ldap_payload(&mut client_stream, 1).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(fsm_set.authenticated_dn(), None);
        match &messages[0].protocol_op {
            ProtocolOp::BindResponse(bind_response) => {
                assert_eq!(
                    bind_response.result.result_code,
                    ParserResultCode::InvalidCredentials
                );
            }
            other => panic!("unexpected response: {:?}", other),
        }
    }

    #[tokio::test]
    async fn handle_bind_with_fsm_rejects_sasl_plain_proxy_authorization() {
        let backend = Arc::new(MockBackend::default());
        let (server_stream, mut client_stream) = connected_stream_pair().await;
        let mut fsm_set = ConnectionFsmSet::new(server_stream, backend, None);

        handle_bind_with_fsm(
            &mut fsm_set,
            38,
            sasl_plain_bind_request_with_authzid(
                "cn=admin,dc=example,dc=org",
                "cn=other,dc=example,dc=org",
                "cn=admin,dc=example,dc=org",
                b"secret",
            ),
            true,
            &RequestContext::default(),
            None,
        )
        .await
        .unwrap();

        let response = read_ldap_payload(&mut client_stream, 1).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(fsm_set.authenticated_dn(), None);
        match &messages[0].protocol_op {
            ProtocolOp::BindResponse(bind_response) => {
                assert_eq!(
                    bind_response.result.result_code,
                    ParserResultCode::InappropriateAuthentication
                );
            }
            other => panic!("unexpected response: {:?}", other),
        }
    }

    #[tokio::test]
    async fn handle_bind_with_fsm_rejects_unsupported_sasl_mechanism() {
        let backend = Arc::new(MockBackend::default());
        let (server_stream, mut client_stream) = connected_stream_pair().await;
        let mut fsm_set = ConnectionFsmSet::new(server_stream, backend, None);

        handle_bind_with_fsm(
            &mut fsm_set,
            33,
            sasl_bind_request_with_mechanism("GSSAPI"),
            true,
            &RequestContext::default(),
            None,
        )
        .await
        .unwrap();

        let response = read_ldap_payload(&mut client_stream, 1).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(fsm_set.authenticated_dn(), None);
        match &messages[0].protocol_op {
            ProtocolOp::BindResponse(bind_response) => {
                assert_eq!(
                    bind_response.result.result_code,
                    ParserResultCode::AuthMethodNotSupported
                );
            }
            other => panic!("unexpected response: {:?}", other),
        }
    }

    #[tokio::test]
    async fn handle_bind_with_fsm_failed_sasl_bind_clears_previous_authentication() {
        let backend = Arc::new(MockBackend::default());
        let (server_stream, mut client_stream) = connected_stream_pair().await;
        let mut fsm_set = ConnectionFsmSet::new(server_stream, backend, None);

        handle_bind_with_fsm(
            &mut fsm_set,
            34,
            simple_bind_request("cn=admin,dc=example,dc=org", b"secret"),
            true,
            &RequestContext::default(),
            None,
        )
        .await
        .unwrap();

        let response = read_ldap_payload(&mut client_stream, 1).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();
        match &messages[0].protocol_op {
            ProtocolOp::BindResponse(bind_response) => {
                assert_eq!(bind_response.result.result_code, ParserResultCode::Success);
            }
            other => panic!("unexpected response: {:?}", other),
        }
        assert_eq!(
            fsm_set.authenticated_dn(),
            Some("cn=admin,dc=example,dc=org")
        );

        handle_bind_with_fsm(
            &mut fsm_set,
            35,
            sasl_bind_request_with_mechanism("GSSAPI"),
            true,
            &RequestContext::default(),
            None,
        )
        .await
        .unwrap();

        let response = read_ldap_payload(&mut client_stream, 1).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();
        match &messages[0].protocol_op {
            ProtocolOp::BindResponse(bind_response) => {
                assert_eq!(
                    bind_response.result.result_code,
                    ParserResultCode::AuthMethodNotSupported
                );
            }
            other => panic!("unexpected response: {:?}", other),
        }
        assert_eq!(fsm_set.authenticated_dn(), None);
    }

    #[tokio::test]
    async fn handle_connection_rejects_sasl_plain_without_confidentiality() {
        let backend = Arc::new(MockBackend::default());
        let (server_task, mut client_stream) = spawn_test_connection(backend).await;

        client_stream
            .write_all(&encode_sasl_plain_bind_request(
                36,
                "cn=admin,dc=example,dc=org",
                "secret",
            ))
            .await
            .unwrap();

        let response = read_ldap_payload(&mut client_stream, 1).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        match &messages[0].protocol_op {
            ProtocolOp::BindResponse(bind_response) => {
                assert_eq!(
                    bind_response.result.result_code,
                    ParserResultCode::ConfidentialityRequired
                );
            }
            other => panic!("unexpected response: {:?}", other),
        }

        client_stream.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handle_connection_processes_compare_request() {
        let backend = Arc::new(MockBackend::default());
        backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=target,dc=example,dc=org",
                    HashMap::from([
                        ("objectClass".to_string(), vec!["person".to_string()]),
                        ("cn".to_string(), vec!["target".to_string()]),
                    ]),
                ),
                Vec::new(),
            )
            .await
            .unwrap();
        let (server_task, mut client_stream) = spawn_test_connection(backend).await;

        client_stream
            .write_all(&encode_compare_request(
                31,
                "cn=target,dc=example,dc=org",
                "cn",
                "target",
            ))
            .await
            .unwrap();

        let response = read_ldap_payload(&mut client_stream, 1).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message_id.0, 31);
        match &messages[0].protocol_op {
            ProtocolOp::CompareResponse(result) => {
                assert_eq!(result.result_code, ParserResultCode::CompareTrue);
            }
            other => panic!("unexpected response: {:?}", other),
        }

        client_stream.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handle_connection_compare_missing_attribute_returns_false() {
        let backend = Arc::new(MockBackend::default());
        backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=target,dc=example,dc=org",
                    HashMap::from([
                        ("objectClass".to_string(), vec!["person".to_string()]),
                        ("cn".to_string(), vec!["target".to_string()]),
                    ]),
                ),
                Vec::new(),
            )
            .await
            .unwrap();
        let (server_task, mut client_stream) = spawn_test_connection(backend).await;

        client_stream
            .write_all(&encode_compare_request(
                32,
                "cn=target,dc=example,dc=org",
                "telephoneNumber",
                "+1-555-0100",
            ))
            .await
            .unwrap();

        let response = read_ldap_payload(&mut client_stream, 1).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message_id.0, 32);
        match &messages[0].protocol_op {
            ProtocolOp::CompareResponse(result) => {
                assert_eq!(result.result_code, ParserResultCode::CompareFalse);
            }
            other => panic!("unexpected response: {:?}", other),
        }

        client_stream.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handle_connection_processes_delete_request() {
        let backend = Arc::new(MockBackend::default());
        backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=delete-me,dc=example,dc=org",
                    HashMap::from([
                        ("objectClass".to_string(), vec!["person".to_string()]),
                        ("cn".to_string(), vec!["delete-me".to_string()]),
                    ]),
                ),
                Vec::new(),
            )
            .await
            .unwrap();

        let (server_task, mut client_stream) = spawn_test_connection(backend.clone()).await;

        client_stream
            .write_all(&encode_bind_request(41))
            .await
            .unwrap();
        let bind_response = read_ldap_payload(&mut client_stream, 1).await;
        let (_, bind_messages) = parse_ldap_messages(&bind_response).unwrap();
        assert_eq!(bind_messages.len(), 1);

        client_stream
            .write_all(&encode_delete_request(42, "cn=delete-me,dc=example,dc=org"))
            .await
            .unwrap();

        let response = read_ldap_payload(&mut client_stream, 1).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message_id.0, 42);
        match &messages[0].protocol_op {
            ProtocolOp::DelResponse(result) => {
                assert_eq!(result.result_code, ParserResultCode::Success);
            }
            other => panic!("unexpected response: {:?}", other),
        }

        assert!(
            backend
                .get_entry("cn=delete-me,dc=example,dc=org")
                .await
                .unwrap()
                .is_none()
        );

        client_stream.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handle_connection_delete_missing_entry_returns_no_such_object() {
        let backend = Arc::new(MockBackend::default());
        let (server_task, mut client_stream) = spawn_test_connection(backend).await;

        client_stream
            .write_all(&encode_bind_request(51))
            .await
            .unwrap();
        let bind_response = read_ldap_payload(&mut client_stream, 1).await;
        let (_, bind_messages) = parse_ldap_messages(&bind_response).unwrap();
        assert_eq!(bind_messages.len(), 1);

        client_stream
            .write_all(&encode_delete_request(52, "cn=missing,dc=example,dc=org"))
            .await
            .unwrap();

        let response = read_ldap_payload(&mut client_stream, 1).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message_id.0, 52);
        match &messages[0].protocol_op {
            ProtocolOp::DelResponse(result) => {
                assert_eq!(result.result_code, ParserResultCode::NoSuchObject);
            }
            other => panic!("unexpected response: {:?}", other),
        }

        client_stream.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handle_connection_processes_modify_request() {
        let backend = Arc::new(MockBackend::default());
        backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=modify-me,dc=example,dc=org",
                    HashMap::from([
                        ("objectClass".to_string(), vec!["person".to_string()]),
                        ("cn".to_string(), vec!["modify-me".to_string()]),
                        ("sn".to_string(), vec!["User".to_string()]),
                        (
                            "telephoneNumber".to_string(),
                            vec!["+1-555-0100".to_string()],
                        ),
                    ]),
                ),
                Vec::new(),
            )
            .await
            .unwrap();

        let (server_task, mut client_stream) = spawn_test_connection(backend.clone()).await;

        client_stream
            .write_all(&encode_bind_request(43))
            .await
            .unwrap();
        let bind_response = read_ldap_payload(&mut client_stream, 1).await;
        let (_, bind_messages) = parse_ldap_messages(&bind_response).unwrap();
        assert_eq!(bind_messages.len(), 1);

        client_stream
            .write_all(&encode_modify_request(
                44,
                "cn=modify-me,dc=example,dc=org",
                RasnChangeOperation::Replace,
                "telephoneNumber",
                &["+1-555-0199"],
            ))
            .await
            .unwrap();

        let response = read_ldap_payload(&mut client_stream, 1).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message_id.0, 44);
        match &messages[0].protocol_op {
            ProtocolOp::ModifyResponse(result) => {
                assert_eq!(result.result.result_code, ParserResultCode::Success);
            }
            other => panic!("unexpected response: {:?}", other),
        }

        let stored = backend
            .get_entry("cn=modify-me,dc=example,dc=org")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.attributes.get("telephonenumber"),
            Some(&vec!["+1-555-0199".to_string()])
        );

        client_stream.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handle_connection_modify_missing_entry_returns_no_such_object() {
        let backend = Arc::new(MockBackend::default());
        let (server_task, mut client_stream) = spawn_test_connection(backend).await;

        client_stream
            .write_all(&encode_bind_request(53))
            .await
            .unwrap();
        let bind_response = read_ldap_payload(&mut client_stream, 1).await;
        let (_, bind_messages) = parse_ldap_messages(&bind_response).unwrap();
        assert_eq!(bind_messages.len(), 1);

        client_stream
            .write_all(&encode_modify_request(
                54,
                "cn=missing,dc=example,dc=org",
                RasnChangeOperation::Replace,
                "telephoneNumber",
                &["+1-555-0199"],
            ))
            .await
            .unwrap();

        let response = read_ldap_payload(&mut client_stream, 1).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message_id.0, 54);
        match &messages[0].protocol_op {
            ProtocolOp::ModifyResponse(result) => {
                assert_eq!(result.result.result_code, ParserResultCode::NoSuchObject);
            }
            other => panic!("unexpected response: {:?}", other),
        }

        client_stream.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handle_connection_processes_modifydn_request() {
        let backend = Arc::new(MockBackend::default());
        backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=rename-me,dc=example,dc=org",
                    HashMap::from([
                        ("objectClass".to_string(), vec!["person".to_string()]),
                        ("cn".to_string(), vec!["rename-me".to_string()]),
                        ("sn".to_string(), vec!["User".to_string()]),
                    ]),
                ),
                Vec::new(),
            )
            .await
            .unwrap();

        let (server_task, mut client_stream) = spawn_test_connection(backend.clone()).await;

        client_stream
            .write_all(&encode_bind_request(61))
            .await
            .unwrap();
        let bind_response = read_ldap_payload(&mut client_stream, 1).await;
        let (_, bind_messages) = parse_ldap_messages(&bind_response).unwrap();
        assert_eq!(bind_messages.len(), 1);

        client_stream
            .write_all(&encode_modifydn_request(
                62,
                "cn=rename-me,dc=example,dc=org",
                "cn=renamed-user",
                true,
                None,
            ))
            .await
            .unwrap();

        let response = read_ldap_payload(&mut client_stream, 1).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message_id.0, 62);
        match &messages[0].protocol_op {
            ProtocolOp::ModDnResponse(result) => {
                assert_eq!(result.result_code, ParserResultCode::Success);
            }
            other => panic!("unexpected response: {:?}", other),
        }

        assert!(
            backend
                .get_entry("cn=rename-me,dc=example,dc=org")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            backend
                .get_entry("cn=renamed-user,dc=example,dc=org")
                .await
                .unwrap()
                .is_some()
        );

        client_stream.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handle_connection_modifydn_missing_entry_returns_no_such_object() {
        let backend = Arc::new(MockBackend::default());
        let (server_task, mut client_stream) = spawn_test_connection(backend).await;

        client_stream
            .write_all(&encode_bind_request(71))
            .await
            .unwrap();
        let bind_response = read_ldap_payload(&mut client_stream, 1).await;
        let (_, bind_messages) = parse_ldap_messages(&bind_response).unwrap();
        assert_eq!(bind_messages.len(), 1);

        client_stream
            .write_all(&encode_modifydn_request(
                72,
                "cn=missing,dc=example,dc=org",
                "cn=renamed-missing",
                true,
                None,
            ))
            .await
            .unwrap();

        let response = read_ldap_payload(&mut client_stream, 1).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message_id.0, 72);
        match &messages[0].protocol_op {
            ProtocolOp::ModDnResponse(result) => {
                assert_eq!(result.result_code, ParserResultCode::NoSuchObject);
            }
            other => panic!("unexpected response: {:?}", other),
        }

        client_stream.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handle_connection_modifydn_conflict_returns_entry_already_exists() {
        let backend = Arc::new(MockBackend::default());
        backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=rename-source,dc=example,dc=org",
                    HashMap::from([
                        ("objectClass".to_string(), vec!["person".to_string()]),
                        ("cn".to_string(), vec!["rename-source".to_string()]),
                        ("sn".to_string(), vec!["Source".to_string()]),
                    ]),
                ),
                Vec::new(),
            )
            .await
            .unwrap();
        backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=rename-target,dc=example,dc=org",
                    HashMap::from([
                        ("objectClass".to_string(), vec!["person".to_string()]),
                        ("cn".to_string(), vec!["rename-target".to_string()]),
                        ("sn".to_string(), vec!["Target".to_string()]),
                    ]),
                ),
                Vec::new(),
            )
            .await
            .unwrap();

        let (server_task, mut client_stream) = spawn_test_connection(backend.clone()).await;

        client_stream
            .write_all(&encode_bind_request(81))
            .await
            .unwrap();
        let bind_response = read_ldap_payload(&mut client_stream, 1).await;
        let (_, bind_messages) = parse_ldap_messages(&bind_response).unwrap();
        assert_eq!(bind_messages.len(), 1);

        client_stream
            .write_all(&encode_modifydn_request(
                82,
                "cn=rename-source,dc=example,dc=org",
                "cn=rename-target",
                true,
                None,
            ))
            .await
            .unwrap();

        let response = read_ldap_payload(&mut client_stream, 1).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message_id.0, 82);
        match &messages[0].protocol_op {
            ProtocolOp::ModDnResponse(result) => {
                assert_eq!(result.result_code, ParserResultCode::EntryAlreadyExists);
            }
            other => panic!("unexpected response: {:?}", other),
        }

        assert!(
            backend
                .get_entry("cn=rename-source,dc=example,dc=org")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            backend
                .get_entry("cn=rename-target,dc=example,dc=org")
                .await
                .unwrap()
                .is_some()
        );

        client_stream.shutdown().await.unwrap();
        server_task.await.unwrap();
    }
}

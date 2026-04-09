use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use ldap_parser::filter::Filter;
use ldap_parser::ldap::{
    AddRequest, AuthenticationChoice, BindRequest, Change, CompareRequest, ExtendedRequest,
    MessageID, ModDnRequest, ModifyRequest, ProtocolOp, SearchRequest,
};
use ldap_parser::parse_ldap_messages;
use log::{error, info, warn};
use rand::distributions::{Alphanumeric, DistString};
use rasn::error::EncodeError;
use rasn_ldap::{LdapMessage as RasnLdapMessage, ProtocolOp as RasnProtocolOp, ResultCode};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;

use crate::aci::{AciEngine, Permission};
use crate::audit::{AuditEvent, AuditEventType, AuditLevel, AuditLogger};
use crate::backend::{
    BackendError, DirectoryBackend, DirectoryEntry, Modification, ModifyOperation,
    SearchCandidateHint,
};
use crate::ber_decoder_fsm::BerDecoderFsmImpl;
use crate::connection_pool::{ConnectionId, ConnectionPool, ResourceLimits};
use crate::extended_ops::{
    encode_password_modify_response_value, oids, parse_cancel_request_value,
    parse_password_modify_request_value,
};
use crate::fsm::{BerDecoderEvent, BerDecoderFsm, StateMachine};
use crate::ldap_controls::{ControlRegistry, ControlValidationError, LdapControl, RequestControls};
use crate::metrics::{MetricsCollector, OperationType};
use crate::parser::{
    encode_bind_response, encode_custom_extended_response, encode_custom_search_result_done,
    encode_extended_response_with_controls, encode_result_response_with_controls,
    encode_search_entry_with_controls, CustomResultCode, ResponseOp,
};
use crate::rate_limit::{RateLimitConfig, RateLimiter};
use crate::real_time_propagation::is_dn_in_scope;
use crate::replication::{
    changelog_entry_to_replication_attrs, REPLICATION_COOKIE_ATTRIBUTE_PREFIX,
    REPLICATION_STREAM_ATTRIBUTE,
};
use crate::schema::LdapSchema;
use crate::tls::RustlsTlsHandler;

#[derive(Debug)]
pub enum ServerError {
    Io(std::io::Error),
    Encode(EncodeError),
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServerError::Io(err) => write!(f, "I/O error: {}", err),
            ServerError::Encode(err) => write!(f, "encoding error: {:?}", err),
        }
    }
}

impl std::error::Error for ServerError {}

impl From<std::io::Error> for ServerError {
    fn from(err: std::io::Error) -> Self {
        ServerError::Io(err)
    }
}

impl From<EncodeError> for ServerError {
    fn from(err: EncodeError) -> Self {
        ServerError::Encode(err)
    }
}

#[derive(Debug, Clone, Default)]
struct ConnectionSession {
    bound_dn: Option<String>,
}

impl ConnectionSession {
    fn bind(&mut self, dn: String) {
        self.bound_dn = Some(dn);
    }

    fn clear(&mut self) {
        self.bound_dn = None;
    }

    fn is_authenticated(&self) -> bool {
        self.bound_dn.is_some()
    }

    fn bound_dn(&self) -> Option<&str> {
        self.bound_dn.as_deref()
    }
}

const START_TLS_OID: &str = "1.3.6.1.4.1.1466.20037";
const CANCEL_OID: &str = oids::CANCEL;
const PASSWORD_MODIFY_OID: &str = oids::PASSWORD_MODIFY;
const WHO_AM_I_OID: &str = "1.3.6.1.4.1.4203.1.11.3";
const SUBSCHEMA_DN: &str = "cn=Subschema";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionOperationKind {
    Search,
    ReplicationStream,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveOperationState {
    Running,
    CancelRequested,
    AbandonRequested,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FinishedOperationState {
    Completed,
    Canceled,
    Abandoned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CancelRequestOutcome {
    Accepted,
    NoSuchOperation,
    TooLate,
    CannotCancel,
}

#[derive(Debug, Clone, Copy)]
struct RegisteredOperation {
    kind: ConnectionOperationKind,
    cancellable: bool,
    state: ActiveOperationState,
}

#[derive(Debug, Default)]
struct ConnectionOperationRegistry {
    active: HashMap<u32, RegisteredOperation>,
    finished: HashMap<u32, FinishedOperationState>,
}

impl ConnectionOperationRegistry {
    fn register(&mut self, message_id: u32, kind: ConnectionOperationKind, cancellable: bool) {
        self.finished.remove(&message_id);
        self.active.insert(
            message_id,
            RegisteredOperation {
                kind,
                cancellable,
                state: ActiveOperationState::Running,
            },
        );
    }

    fn request_cancel(&mut self, message_id: u32) -> CancelRequestOutcome {
        if let Some(operation) = self.active.get_mut(&message_id) {
            if !operation.cancellable {
                return CancelRequestOutcome::CannotCancel;
            }
            if operation.kind != ConnectionOperationKind::Search
                && operation.kind != ConnectionOperationKind::ReplicationStream
            {
                return CancelRequestOutcome::CannotCancel;
            }
            if operation.state != ActiveOperationState::Running {
                return CancelRequestOutcome::CannotCancel;
            }
            operation.state = ActiveOperationState::CancelRequested;
            return CancelRequestOutcome::Accepted;
        }

        if self.finished.contains_key(&message_id) {
            return CancelRequestOutcome::TooLate;
        }

        CancelRequestOutcome::NoSuchOperation
    }

    fn request_abandon(&mut self, message_id: u32) -> bool {
        let Some(operation) = self.active.get_mut(&message_id) else {
            return false;
        };
        if !operation.cancellable || operation.state != ActiveOperationState::Running {
            return false;
        }
        operation.state = ActiveOperationState::AbandonRequested;
        true
    }

    fn finish(&mut self, message_id: u32, outcome: FinishedOperationState) {
        self.active.remove(&message_id);
        self.finished.insert(message_id, outcome);
    }
}

#[derive(Debug, Clone)]
pub struct LegacyServerConfig {
    pub resource_limits: ResourceLimits,
    pub rate_limit_config: RateLimitConfig,
    pub rate_limiting_enabled: bool,
    pub naming_contexts: Vec<String>,
    pub subschema_dn: String,
}

impl Default for LegacyServerConfig {
    fn default() -> Self {
        Self {
            resource_limits: ResourceLimits::default(),
            rate_limit_config: RateLimitConfig::default(),
            rate_limiting_enabled: true,
            naming_contexts: Vec::new(),
            subschema_dn: SUBSCHEMA_DN.to_string(),
        }
    }
}

impl LegacyServerConfig {
    pub fn from_server_config(config: &crate::config::ServerConfig) -> Self {
        Self {
            resource_limits: ResourceLimits {
                max_connections: config.resources.max_connections,
                max_connections_per_ip: config.resources.max_connections_per_ip,
                max_operations_per_connection: config.resources.max_operations_per_connection,
                max_memory_per_connection: config.resources.max_memory_per_connection,
                max_total_memory: config.resources.max_total_memory,
                connection_idle_timeout: config.connection_idle_timeout(),
            },
            rate_limit_config: config.to_rate_limit_config(),
            rate_limiting_enabled: config.rate_limit.enabled,
            naming_contexts: vec![config.server.base_dn.clone()],
            subschema_dn: SUBSCHEMA_DN.to_string(),
        }
    }
}

#[derive(Clone)]
struct ConnectionControls {
    conn_id: ConnectionId,
    client_ip: IpAddr,
    idle_timeout: Duration,
    pool: Arc<ConnectionPool>,
    rate_limiter: Option<Arc<RateLimiter>>,
}

#[derive(Debug, Clone)]
pub struct LegacyAuditConfig {
    pub log_authentication: bool,
    pub log_authorization: bool,
    pub log_modifications: bool,
    pub log_connections: bool,
}

impl Default for LegacyAuditConfig {
    fn default() -> Self {
        Self {
            log_authentication: true,
            log_authorization: true,
            log_modifications: true,
            log_connections: true,
        }
    }
}

#[derive(Clone, Default)]
pub struct LegacySecurityConfig {
    pub audit_logger: Option<Arc<AuditLogger>>,
    pub audit_config: LegacyAuditConfig,
    pub access_control: Option<Arc<AciEngine>>,
    pub root_dn: Option<String>,
}

#[derive(Clone, Default)]
struct RequestContext {
    client_ip: Option<IpAddr>,
    session_id: Option<ConnectionId>,
    security: Option<Arc<LegacySecurityConfig>>,
    metrics: Option<Arc<MetricsCollector>>,
}

#[derive(Clone, Copy)]
enum RejectionResponse {
    Bind,
    SearchDone,
    Modify,
    Add,
    Delete,
    ModifyDn,
    Compare,
    Extended,
}

pub enum ConnectionStream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
    Closed,
}

impl ConnectionStream {
    fn plain(stream: TcpStream) -> Self {
        Self::Plain(stream)
    }

    fn tls(stream: TlsStream<TcpStream>) -> Self {
        Self::Tls(Box::new(stream))
    }

    fn is_secure(&self) -> bool {
        matches!(self, Self::Tls(_))
    }

    async fn upgrade_in_place(
        &mut self,
        tls_handler: &RustlsTlsHandler,
    ) -> Result<(), ServerError> {
        if self.is_secure() {
            return Err(ServerError::Io(std::io::Error::other(
                "connection already uses TLS",
            )));
        }

        let plain_stream = match std::mem::replace(self, Self::Closed) {
            Self::Plain(stream) => stream,
            Self::Tls(stream) => {
                *self = Self::Tls(stream);
                return Err(ServerError::Io(std::io::Error::other(
                    "connection already uses TLS",
                )));
            }
            Self::Closed => {
                return Err(ServerError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "connection is closed",
                )));
            }
        };

        match tls_handler.accept(plain_stream).await {
            Ok(stream) => {
                *self = Self::Tls(Box::new(stream));
                Ok(())
            }
            Err(err) => {
                *self = Self::Closed;
                Err(ServerError::Io(std::io::Error::other(err)))
            }
        }
    }
}

impl AsyncRead for ConnectionStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Closed => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "connection is closed",
            ))),
        }
    }
}

impl AsyncWrite for ConnectionStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Closed => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "connection is closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream).poll_flush(cx),
            Self::Closed => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "connection is closed",
            ))),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Closed => Poll::Ready(Ok(())),
        }
    }
}

pub async fn run(
    addr: &str,
    backend: Arc<dyn DirectoryBackend>,
    shutdown_rx: tokio::sync::broadcast::Receiver<()>,
) -> Result<(), ServerError> {
    run_with_metrics_and_config(
        addr,
        backend,
        shutdown_rx,
        None,
        LegacyServerConfig::default(),
    )
    .await
}

pub async fn run_with_metrics(
    addr: &str,
    backend: Arc<dyn DirectoryBackend>,
    shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    metrics: Option<Arc<MetricsCollector>>,
) -> Result<(), ServerError> {
    run_with_metrics_and_config_with_tls_and_security(
        addr,
        backend,
        shutdown_rx,
        metrics,
        LegacyServerConfig::default(),
        None,
        None,
    )
    .await
}

pub async fn run_with_metrics_and_config(
    addr: &str,
    backend: Arc<dyn DirectoryBackend>,
    shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    metrics: Option<Arc<MetricsCollector>>,
    runtime_config: LegacyServerConfig,
) -> Result<(), ServerError> {
    run_with_metrics_and_config_with_tls_and_security(
        addr,
        backend,
        shutdown_rx,
        metrics,
        runtime_config,
        None,
        None,
    )
    .await
}

pub async fn run_with_metrics_and_config_with_tls(
    addr: &str,
    backend: Arc<dyn DirectoryBackend>,
    shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    metrics: Option<Arc<MetricsCollector>>,
    runtime_config: LegacyServerConfig,
    tls_handler: Option<Arc<RustlsTlsHandler>>,
) -> Result<(), ServerError> {
    run_with_metrics_and_config_with_tls_and_security(
        addr,
        backend,
        shutdown_rx,
        metrics,
        runtime_config,
        tls_handler,
        None,
    )
    .await
}

pub async fn run_with_metrics_and_config_with_tls_and_security(
    addr: &str,
    backend: Arc<dyn DirectoryBackend>,
    shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    metrics: Option<Arc<MetricsCollector>>,
    runtime_config: LegacyServerConfig,
    tls_handler: Option<Arc<RustlsTlsHandler>>,
    security: Option<Arc<LegacySecurityConfig>>,
) -> Result<(), ServerError> {
    run_plain_listener(
        addr,
        backend,
        shutdown_rx,
        metrics,
        runtime_config,
        tls_handler,
        security,
    )
    .await
}

async fn run_plain_listener(
    addr: &str,
    backend: Arc<dyn DirectoryBackend>,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    metrics: Option<Arc<MetricsCollector>>,
    runtime_config: LegacyServerConfig,
    tls_handler: Option<Arc<RustlsTlsHandler>>,
    security: Option<Arc<LegacySecurityConfig>>,
) -> Result<(), ServerError> {
    let listener = TcpListener::bind(addr).await?;
    info!("LDAP server listening on {}", addr);

    // Create schema validator with core schema
    let schema = Arc::new(LdapSchema::with_core_schema());
    let pool = Arc::new(ConnectionPool::new(runtime_config.resource_limits.clone()));
    let rate_limiter = if runtime_config.rate_limiting_enabled {
        Some(Arc::new(RateLimiter::new(
            runtime_config.rate_limit_config.clone(),
        )))
    } else {
        None
    };

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (mut socket, addr) = match result {
                    Ok(accepted) => accepted,
                    Err(err) => {
                        if let Some(metrics) = metrics.as_ref() {
                            metrics.record_connection_failed();
                        }
                        return Err(err.into());
                    }
                };

                let conn_id = match pool.acquire_connection(addr).await {
                    Some(conn_id) => conn_id,
                    None => {
                        if let Some(metrics) = metrics.as_ref() {
                            metrics.record_connection_failed();
                        }
                        warn!("Connection from {:?} rejected due to resource limits", addr);
                        if let Err(err) = send_connection_rejected(&mut socket).await {
                            error!("Failed to send connection rejection to {:?}: {}", addr, err);
                        }
                        continue;
                    }
                };

                info!("Accepted connection from {:?} (conn_id={})", addr, conn_id);

                let backend = backend.clone();
                let schema = schema.clone();
                let metrics = metrics.clone();
                let pool = pool.clone();
                let connection_runtime_config = runtime_config.clone();
                let tls_handler = tls_handler.clone();
                let security = security.clone();
                let controls = ConnectionControls {
                    conn_id,
                    client_ip: addr.ip(),
                    idle_timeout: runtime_config.resource_limits.connection_idle_timeout,
                    pool: pool.clone(),
                    rate_limiter: rate_limiter.clone(),
                };

                if let Some(metrics) = metrics.as_ref() {
                    metrics.record_connection_accepted();
                }

                if let Some(security) = security.as_ref() {
                    if let Some(audit) = security.audit_logger.as_ref() {
                        if security.audit_config.log_connections {
                            audit
                                .log_connection_accepted(
                                    &addr.ip().to_string(),
                                    &conn_id.to_string(),
                                )
                                .await;
                        }
                    }
                }

                tokio::spawn(async move {
                    let request_context = RequestContext {
                        client_ip: Some(addr.ip()),
                        session_id: Some(conn_id),
                        security: security.clone(),
                        metrics: metrics.clone(),
                    };
                    handle_client_with_metrics_and_tls(
                        ConnectionStream::plain(socket),
                        backend,
                        schema,
                        connection_runtime_config,
                        tls_handler,
                        metrics.clone(),
                        Some(controls),
                        request_context.clone(),
                    )
                    .await;
                    pool.release_connection(conn_id).await;
                    if let Some(metrics) = metrics.as_ref() {
                        metrics.record_connection_closed();
                    }
                    if let Some(security) = request_context.security.as_ref() {
                        if let Some(audit) = security.audit_logger.as_ref() {
                            if security.audit_config.log_connections {
                                audit
                                    .log_connection_closed(
                                        &addr.ip().to_string(),
                                        &conn_id.to_string(),
                                    )
                                    .await;
                            }
                        }
                    }
                    info!("Connection {:?} (conn_id={}) closed", addr, conn_id);
                });
            }
            _ = shutdown_rx.recv() => {
                info!("Server received shutdown signal, stopping accept loop");
                break;
            }
        }
    }

    info!("Server stopped accepting new connections");
    Ok(())
}

pub async fn run_tls_with_metrics_and_config(
    addr: &str,
    backend: Arc<dyn DirectoryBackend>,
    shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    metrics: Option<Arc<MetricsCollector>>,
    runtime_config: LegacyServerConfig,
    tls_handler: Arc<RustlsTlsHandler>,
) -> Result<(), ServerError> {
    run_tls_with_metrics_and_config_and_security(
        addr,
        backend,
        shutdown_rx,
        metrics,
        runtime_config,
        tls_handler,
        None,
    )
    .await
}

pub async fn run_tls_with_metrics_and_config_and_security(
    addr: &str,
    backend: Arc<dyn DirectoryBackend>,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    metrics: Option<Arc<MetricsCollector>>,
    runtime_config: LegacyServerConfig,
    tls_handler: Arc<RustlsTlsHandler>,
    security: Option<Arc<LegacySecurityConfig>>,
) -> Result<(), ServerError> {
    let listener = TcpListener::bind(addr).await?;
    info!("LDAPS server listening on {}", addr);

    let schema = Arc::new(LdapSchema::with_core_schema());
    let pool = Arc::new(ConnectionPool::new(runtime_config.resource_limits.clone()));
    let rate_limiter = if runtime_config.rate_limiting_enabled {
        Some(Arc::new(RateLimiter::new(
            runtime_config.rate_limit_config.clone(),
        )))
    } else {
        None
    };

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (socket, addr) = match result {
                    Ok(accepted) => accepted,
                    Err(err) => {
                        if let Some(metrics) = metrics.as_ref() {
                            metrics.record_connection_failed();
                        }
                        return Err(err.into());
                    }
                };

                let conn_id = match pool.acquire_connection(addr).await {
                    Some(conn_id) => conn_id,
                    None => {
                        if let Some(metrics) = metrics.as_ref() {
                            metrics.record_connection_failed();
                        }
                        warn!("LDAPS connection from {:?} rejected due to resource limits", addr);
                        continue;
                    }
                };

                let tls_stream = match tls_handler.accept(socket).await {
                    Ok(stream) => stream,
                    Err(err) => {
                        if let Some(metrics) = metrics.as_ref() {
                            metrics.record_connection_failed();
                        }
                        pool.release_connection(conn_id).await;
                        warn!("LDAPS handshake failed for {:?}: {}", addr, err);
                        continue;
                    }
                };

                info!("Accepted LDAPS connection from {:?} (conn_id={})", addr, conn_id);

                let backend = backend.clone();
                let schema = schema.clone();
                let metrics = metrics.clone();
                let pool = pool.clone();
                let connection_runtime_config = runtime_config.clone();
                let tls_handler = tls_handler.clone();
                let security = security.clone();
                let controls = ConnectionControls {
                    conn_id,
                    client_ip: addr.ip(),
                    idle_timeout: runtime_config.resource_limits.connection_idle_timeout,
                    pool: pool.clone(),
                    rate_limiter: rate_limiter.clone(),
                };

                if let Some(metrics) = metrics.as_ref() {
                    metrics.record_connection_accepted();
                }

                if let Some(security) = security.as_ref() {
                    if let Some(audit) = security.audit_logger.as_ref() {
                        if security.audit_config.log_connections {
                            audit
                                .log_connection_accepted(
                                    &addr.ip().to_string(),
                                    &conn_id.to_string(),
                                )
                                .await;
                        }
                    }
                }

                tokio::spawn(async move {
                    let request_context = RequestContext {
                        client_ip: Some(addr.ip()),
                        session_id: Some(conn_id),
                        security: security.clone(),
                        metrics: metrics.clone(),
                    };
                    handle_client_with_metrics_and_tls(
                        ConnectionStream::tls(tls_stream),
                        backend,
                        schema,
                        connection_runtime_config,
                        Some(tls_handler),
                        metrics.clone(),
                        Some(controls),
                        request_context.clone(),
                    )
                    .await;
                    pool.release_connection(conn_id).await;
                    if let Some(metrics) = metrics.as_ref() {
                        metrics.record_connection_closed();
                    }
                    if let Some(security) = request_context.security.as_ref() {
                        if let Some(audit) = security.audit_logger.as_ref() {
                            if security.audit_config.log_connections {
                                audit
                                    .log_connection_closed(
                                        &addr.ip().to_string(),
                                        &conn_id.to_string(),
                                    )
                                    .await;
                            }
                        }
                    }
                    info!("LDAPS connection {:?} (conn_id={}) closed", addr, conn_id);
                });
            }
            _ = shutdown_rx.recv() => {
                info!("LDAPS server received shutdown signal, stopping accept loop");
                break;
            }
        }
    }

    info!("LDAPS server stopped accepting new connections");
    Ok(())
}

pub async fn handle_client(
    socket: TcpStream,
    backend: Arc<dyn DirectoryBackend>,
    schema: Arc<LdapSchema>,
) {
    handle_client_with_metrics_and_tls(
        ConnectionStream::plain(socket),
        backend,
        schema,
        LegacyServerConfig::default(),
        None,
        None,
        None,
        RequestContext::default(),
    )
    .await;
}

async fn handle_client_with_metrics_and_tls(
    mut socket: ConnectionStream,
    backend: Arc<dyn DirectoryBackend>,
    schema: Arc<LdapSchema>,
    runtime_config: LegacyServerConfig,
    tls_handler: Option<Arc<RustlsTlsHandler>>,
    metrics: Option<Arc<MetricsCollector>>,
    controls: Option<ConnectionControls>,
    request_context: RequestContext,
) {
    let mut read_buffer = vec![0; 8192];
    let mut decoder = BerDecoderFsmImpl::new();
    let mut session = ConnectionSession::default();
    let mut operation_registry = ConnectionOperationRegistry::default();

    loop {
        let read_result = match controls.as_ref() {
            Some(controls) => {
                match tokio::time::timeout(controls.idle_timeout, socket.read(&mut read_buffer))
                    .await
                {
                    Ok(result) => result.map(Some),
                    Err(_) => Ok(None),
                }
            }
            None => socket.read(&mut read_buffer).await.map(Some),
        };

        match read_result {
            Ok(None) => {
                info!("Closing idle connection after timeout");
                break;
            }
            Ok(Some(0)) => break,
            Ok(Some(n)) => {
                let mut accounted_read_bytes = false;
                if let Some(controls) = controls.as_ref() {
                    controls.pool.update_activity(controls.conn_id).await;
                    if !controls
                        .pool
                        .update_memory_usage(controls.conn_id, n as isize)
                        .await
                    {
                        warn!(
                            "Connection {} exceeded memory/resource limits while reading",
                            controls.conn_id
                        );
                        if let Some(metrics) = metrics.as_ref() {
                            metrics.record_connection_failed();
                        }
                        if let Err(err) = send_connection_rejected(&mut socket).await {
                            error!("Failed to send resource rejection: {}", err);
                        }
                        return;
                    }
                    accounted_read_bytes = true;
                }

                let decoded_messages =
                    match decode_messages(&mut decoder, read_buffer[..n].to_vec()).await {
                        Ok(messages) => messages,
                        Err(err) => {
                            if let Some(controls) = controls.as_ref() {
                                if accounted_read_bytes {
                                    controls
                                        .pool
                                        .update_memory_usage(controls.conn_id, -(n as isize))
                                        .await;
                                }
                            }
                            error!("Failed to decode BER message: {}", err);
                            if let Err(write_err) = send_bind_response(
                                &mut socket,
                                0,
                                ResultCode::ProtocolError,
                                "invalid message",
                            )
                            .await
                            {
                                error!("Failed to write error response: {}", write_err);
                            }
                            return;
                        }
                    };

                if let Some(controls) = controls.as_ref() {
                    if accounted_read_bytes {
                        controls
                            .pool
                            .update_memory_usage(controls.conn_id, -(n as isize))
                            .await;
                    }
                }

                for message_bytes in decoded_messages {
                    let parsed_messages = match parse_ldap_messages(&message_bytes) {
                        Ok((_, messages)) => messages,
                        Err(err) => {
                            if let Some(message) = parse_abandon_message_fallback(&message_bytes) {
                                vec![message]
                            } else {
                                error!("Failed to parse LDAP message: {:?}", err);
                                if let Err(write_err) = send_bind_response(
                                    &mut socket,
                                    0,
                                    ResultCode::ProtocolError,
                                    "invalid message",
                                )
                                .await
                                {
                                    error!("Failed to write error response: {}", write_err);
                                }
                                return;
                            }
                        }
                    };

                    for message in parsed_messages {
                        let operation_type = operation_type_for_protocol(&message.protocol_op);
                        let response_kind = rejection_response_for_protocol(&message.protocol_op);
                        let started_at = Instant::now();
                        if let Some(metrics) = metrics.as_ref() {
                            if let Some(operation_type) = operation_type {
                                metrics.record_operation_start(operation_type, "");
                            }
                        }

                        if let Some(controls) = controls.as_ref() {
                            if let Some(operation_name) =
                                rate_limited_operation_name_for_protocol(&message.protocol_op)
                            {
                                if let Some(rate_limiter) = controls.rate_limiter.as_ref() {
                                    if !rate_limiter
                                        .check_rate_limit(controls.client_ip, operation_name)
                                        .await
                                    {
                                        let result = send_rejection_response(
                                            &mut socket,
                                            message.message_id.0,
                                            response_kind,
                                            ResultCode::Busy,
                                            "Rate limit exceeded - please slow down",
                                        )
                                        .await;
                                        if let Some(metrics) = metrics.as_ref() {
                                            if let Some(operation_type) = operation_type {
                                                metrics.record_operation_complete(
                                                    operation_type,
                                                    started_at.elapsed(),
                                                    false,
                                                );
                                            }
                                        }
                                        if let Err(err) = result {
                                            error!("Failed to send rate-limit response: {}", err);
                                            return;
                                        }
                                        continue;
                                    }
                                }
                            }

                            if !controls.pool.start_operation(controls.conn_id).await {
                                let result = send_rejection_response(
                                    &mut socket,
                                    message.message_id.0,
                                    response_kind,
                                    ResultCode::Busy,
                                    "Server is busy - operation limit exceeded",
                                )
                                .await;
                                if let Some(metrics) = metrics.as_ref() {
                                    if let Some(operation_type) = operation_type {
                                        metrics.record_operation_complete(
                                            operation_type,
                                            started_at.elapsed(),
                                            false,
                                        );
                                    }
                                }
                                if let Err(err) = result {
                                    error!("Failed to send busy response: {}", err);
                                    return;
                                }
                                continue;
                            }
                        }

                        let result = process_message_with_session(
                            &mut socket,
                            backend.as_ref(),
                            schema.as_ref(),
                            &runtime_config,
                            &mut session,
                            &mut operation_registry,
                            message,
                            tls_handler.as_deref(),
                            &request_context,
                        )
                        .await;

                        if let Some(controls) = controls.as_ref() {
                            controls.pool.end_operation(controls.conn_id).await;
                        }

                        if let Some(metrics) = metrics.as_ref() {
                            if let Some(operation_type) = operation_type {
                                metrics.record_operation_complete(
                                    operation_type,
                                    started_at.elapsed(),
                                    result.is_ok(),
                                );
                            }
                        }

                        if let Err(err) = result {
                            error!("Failed to process message: {}", err);
                            return;
                        }
                    }
                }
            }
            Err(err) => {
                if let Some(metrics) = metrics.as_ref() {
                    metrics.record_connection_failed();
                }
                error!("Failed to read from socket: {}", err);
                return;
            }
        }
    }
}

fn operation_type_for_protocol(protocol_op: &ProtocolOp<'_>) -> Option<OperationType> {
    match protocol_op {
        ProtocolOp::BindRequest(_) => Some(OperationType::Bind),
        ProtocolOp::SearchRequest(_) => Some(OperationType::Search),
        ProtocolOp::ModifyRequest(_) => Some(OperationType::Modify),
        ProtocolOp::AddRequest(_) => Some(OperationType::Add),
        ProtocolOp::DelRequest(_) => Some(OperationType::Delete),
        ProtocolOp::ModDnRequest(_) => Some(OperationType::ModifyDN),
        ProtocolOp::CompareRequest(_) => Some(OperationType::Compare),
        ProtocolOp::UnbindRequest => Some(OperationType::Unbind),
        ProtocolOp::AbandonRequest(_) => Some(OperationType::Abandon),
        ProtocolOp::ExtendedRequest(_) => Some(OperationType::Extended),
        _ => None,
    }
}

fn rate_limited_operation_name_for_protocol(protocol_op: &ProtocolOp<'_>) -> Option<&'static str> {
    match protocol_op {
        ProtocolOp::BindRequest(_) => Some("bind"),
        ProtocolOp::SearchRequest(_) => Some("search"),
        ProtocolOp::ModifyRequest(_) => Some("modify"),
        ProtocolOp::AddRequest(_) => Some("add"),
        ProtocolOp::DelRequest(_) => Some("delete"),
        ProtocolOp::ModDnRequest(_) => Some("modifydn"),
        ProtocolOp::CompareRequest(_) => Some("compare"),
        ProtocolOp::ExtendedRequest(_) => Some("extended"),
        _ => None,
    }
}

fn rejection_response_for_protocol(protocol_op: &ProtocolOp<'_>) -> Option<RejectionResponse> {
    match protocol_op {
        ProtocolOp::BindRequest(_) => Some(RejectionResponse::Bind),
        ProtocolOp::SearchRequest(_) => Some(RejectionResponse::SearchDone),
        ProtocolOp::ModifyRequest(_) => Some(RejectionResponse::Modify),
        ProtocolOp::AddRequest(_) => Some(RejectionResponse::Add),
        ProtocolOp::DelRequest(_) => Some(RejectionResponse::Delete),
        ProtocolOp::ModDnRequest(_) => Some(RejectionResponse::ModifyDn),
        ProtocolOp::CompareRequest(_) => Some(RejectionResponse::Compare),
        ProtocolOp::ExtendedRequest(_) => Some(RejectionResponse::Extended),
        _ => None,
    }
}

async fn send_connection_rejected(
    socket: &mut (impl AsyncWrite + Unpin),
) -> Result<(), ServerError> {
    send_result(
        socket,
        0,
        ResponseOp::SearchDone,
        ResultCode::Unavailable,
        "",
        "Server resource limits exceeded",
    )
    .await?;
    socket.shutdown().await?;
    Ok(())
}

async fn send_rejection_response(
    socket: &mut (impl AsyncWrite + Unpin),
    message_id: u32,
    response_kind: Option<RejectionResponse>,
    result_code: ResultCode,
    diagnostic_message: &str,
) -> Result<(), ServerError> {
    match response_kind {
        Some(RejectionResponse::Bind) => {
            send_bind_response(socket, message_id, result_code, diagnostic_message).await
        }
        Some(RejectionResponse::SearchDone) => {
            send_result(
                socket,
                message_id,
                ResponseOp::SearchDone,
                result_code,
                "",
                diagnostic_message,
            )
            .await
        }
        Some(RejectionResponse::Modify) => {
            send_result(
                socket,
                message_id,
                ResponseOp::Modify,
                result_code,
                "",
                diagnostic_message,
            )
            .await
        }
        Some(RejectionResponse::Add) => {
            send_result(
                socket,
                message_id,
                ResponseOp::Add,
                result_code,
                "",
                diagnostic_message,
            )
            .await
        }
        Some(RejectionResponse::Delete) => {
            send_result(
                socket,
                message_id,
                ResponseOp::Delete,
                result_code,
                "",
                diagnostic_message,
            )
            .await
        }
        Some(RejectionResponse::ModifyDn) => {
            send_result(
                socket,
                message_id,
                ResponseOp::ModifyDn,
                result_code,
                "",
                diagnostic_message,
            )
            .await
        }
        Some(RejectionResponse::Compare) => {
            send_result(
                socket,
                message_id,
                ResponseOp::Compare,
                result_code,
                "",
                diagnostic_message,
            )
            .await
        }
        Some(RejectionResponse::Extended) => {
            send_result(
                socket,
                message_id,
                ResponseOp::Extended,
                result_code,
                "",
                diagnostic_message,
            )
            .await
        }
        None => {
            send_result(
                socket,
                message_id,
                ResponseOp::SearchDone,
                result_code,
                "",
                diagnostic_message,
            )
            .await
        }
    }
}

async fn decode_messages(
    decoder: &mut BerDecoderFsmImpl,
    input: Vec<u8>,
) -> Result<Vec<Vec<u8>>, crate::ber_decoder_fsm::BerDecoderError> {
    let mut messages = Vec::new();
    let mut pending_input = Some(input);

    loop {
        let mut made_progress = false;
        let next_input = pending_input.take().unwrap_or_default();

        if let Some(message) = decoder
            .handle_event(BerDecoderEvent::DataReceived(next_input))
            .await?
        {
            messages.push(message);
            made_progress = true;
        }

        while let Some(message) = decoder.extract_message() {
            messages.push(message);
            made_progress = true;
        }

        if !made_progress {
            break;
        }
    }

    Ok(messages)
}

fn parse_abandon_message_fallback(
    message_bytes: &[u8],
) -> Option<ldap_parser::ldap::LdapMessage<'static>> {
    let message: RasnLdapMessage = rasn::ber::decode(message_bytes).ok()?;
    let RasnProtocolOp::AbandonRequest(request_id) = message.protocol_op else {
        return None;
    };

    Some(ldap_parser::ldap::LdapMessage {
        message_id: MessageID(message.message_id),
        protocol_op: ProtocolOp::AbandonRequest(MessageID(request_id.0)),
        controls: None,
    })
}

pub async fn process_message(
    socket: &mut ConnectionStream,
    backend: &dyn DirectoryBackend,
    schema: &LdapSchema,
    message: ldap_parser::ldap::LdapMessage<'_>,
) -> Result<(), ServerError> {
    let mut session = ConnectionSession::default();
    let mut operation_registry = ConnectionOperationRegistry::default();
    let runtime_config = LegacyServerConfig::default();
    process_message_with_session(
        socket,
        backend,
        schema,
        &runtime_config,
        &mut session,
        &mut operation_registry,
        message,
        None,
        &RequestContext::default(),
    )
    .await
}

async fn process_message_with_session(
    socket: &mut ConnectionStream,
    backend: &dyn DirectoryBackend,
    schema: &LdapSchema,
    runtime_config: &LegacyServerConfig,
    session: &mut ConnectionSession,
    operation_registry: &mut ConnectionOperationRegistry,
    message: ldap_parser::ldap::LdapMessage<'_>,
    tls_handler: Option<&RustlsTlsHandler>,
    request_context: &RequestContext,
) -> Result<(), ServerError> {
    let message_id = message.message_id.0;
    let response_kind = rejection_response_for_protocol(&message.protocol_op);
    let request_controls = match validate_message_controls(
        socket,
        message_id,
        response_kind,
        &message,
        session,
        request_context,
    )
    .await?
    {
        Some(controls) => controls,
        None => return Ok(()),
    };

    match message.protocol_op {
        ProtocolOp::BindRequest(bind_request) => {
            handle_bind_request_with_session_and_context(
                socket,
                backend,
                message_id,
                bind_request,
                session,
                request_context,
                socket.is_secure(),
                &request_controls,
            )
            .await?;
        }
        ProtocolOp::SearchRequest(search_request) => {
            handle_search_request_with_context_and_registry(
                socket,
                backend,
                schema,
                runtime_config,
                message_id,
                search_request,
                session,
                operation_registry,
                request_context,
                &request_controls,
                socket.is_secure(),
                tls_handler.is_some(),
            )
            .await?;
        }
        ProtocolOp::ModifyRequest(modify_request) => {
            let dn = modify_request.object.0.as_ref().trim().to_owned();
            if !ensure_authenticated_for_mutation(
                socket,
                message_id,
                session,
                ResponseOp::Modify,
                &dn,
            )
            .await?
            {
                return Ok(());
            }
            handle_modify_request_with_context(
                socket,
                backend,
                message_id,
                modify_request,
                session,
                request_context,
                &request_controls,
            )
            .await?;
        }
        ProtocolOp::AddRequest(add_request) => {
            let dn = add_request.entry.0.as_ref().trim().to_owned();
            if !ensure_authenticated_for_mutation(socket, message_id, session, ResponseOp::Add, &dn)
                .await?
            {
                return Ok(());
            }
            handle_add_request_with_context(
                socket,
                backend,
                schema,
                message_id,
                add_request,
                session,
                request_context,
                &request_controls,
            )
            .await?;
        }
        ProtocolOp::DelRequest(delete_request) => {
            let dn = delete_request.0.as_ref().trim().to_owned();
            if !ensure_authenticated_for_mutation(
                socket,
                message_id,
                session,
                ResponseOp::Delete,
                &dn,
            )
            .await?
            {
                return Ok(());
            }
            handle_delete_request_with_context(
                socket,
                backend,
                message_id,
                delete_request,
                session,
                request_context,
                &request_controls,
            )
            .await?;
        }
        ProtocolOp::ModDnRequest(rename_request) => {
            let dn = rename_request.entry.0.as_ref().trim().to_owned();
            if !ensure_authenticated_for_mutation(
                socket,
                message_id,
                session,
                ResponseOp::ModifyDn,
                &dn,
            )
            .await?
            {
                return Ok(());
            }
            handle_moddn_request_with_context(
                socket,
                backend,
                message_id,
                rename_request,
                session,
                request_context,
                &request_controls,
            )
            .await?;
        }
        ProtocolOp::CompareRequest(compare_request) => {
            handle_compare_request_with_context(
                socket,
                backend,
                message_id,
                compare_request,
                session,
                request_context,
                &request_controls,
            )
            .await?;
        }
        ProtocolOp::UnbindRequest => {
            info!("Received unbind request");
            session.clear();
            return Ok(());
        }
        ProtocolOp::AbandonRequest(request_id) => {
            handle_abandon_request(request_id, operation_registry, session, request_context).await;
        }
        ProtocolOp::ExtendedRequest(request) => {
            handle_extended_request_with_session_and_registry(
                socket,
                backend,
                message_id,
                request,
                session,
                operation_registry,
                tls_handler,
                request_context,
                &request_controls,
            )
            .await?;
        }
        op => {
            warn!("Unsupported operation received: {:?}", op);
        }
    }

    Ok(())
}

fn active_runtime_control_registry() -> ControlRegistry {
    ControlRegistry::default()
}

fn control_metric_fragment(oid: &str) -> String {
    oid.chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect()
}

fn increment_control_counter(request_context: &RequestContext, counter: &str, value: u64) {
    if let Some(metrics) = request_context.metrics.as_ref() {
        metrics.increment_counter(counter, value);
    }
}

fn record_control_metrics(
    request_context: &RequestContext,
    controls: &[LdapControl],
    ignored_controls: &[LdapControl],
) {
    for control in controls {
        increment_control_counter(request_context, "ldap_controls_seen_total", 1);
        increment_control_counter(
            request_context,
            &format!(
                "ldap_controls_seen_{}",
                control_metric_fragment(control.oid())
            ),
            1,
        );
    }

    for control in ignored_controls {
        increment_control_counter(request_context, "ldap_controls_ignored_total", 1);
        increment_control_counter(
            request_context,
            &format!(
                "ldap_controls_ignored_{}",
                control_metric_fragment(control.oid())
            ),
            1,
        );
    }
}

fn record_rejected_control_metric(request_context: &RequestContext, oid: &str) {
    increment_control_counter(request_context, "ldap_controls_rejected_total", 1);
    increment_control_counter(
        request_context,
        &format!("ldap_controls_rejected_{}", control_metric_fragment(oid)),
        1,
    );
}

fn describe_controls(controls: &[LdapControl]) -> String {
    controls
        .iter()
        .map(|control| {
            let value_len = control.value().map(|value| value.len()).unwrap_or_default();
            format!(
                "{}(critical={},value_len={})",
                control.oid(),
                control.criticality(),
                value_len
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

async fn log_control_processing(
    request_context: &RequestContext,
    session: &ConnectionSession,
    accepted_controls: &[LdapControl],
    ignored_controls: &[LdapControl],
    rejected_control_oid: Option<&str>,
) {
    if accepted_controls.is_empty() && ignored_controls.is_empty() && rejected_control_oid.is_none()
    {
        return;
    }

    let mut details = Vec::new();
    if !accepted_controls.is_empty() {
        details.push((
            "accepted_controls".to_string(),
            describe_controls(accepted_controls),
        ));
    }
    if !ignored_controls.is_empty() {
        details.push((
            "ignored_controls".to_string(),
            describe_controls(ignored_controls),
        ));
    }
    if let Some(rejected_control_oid) = rejected_control_oid {
        details.push((
            "rejected_control".to_string(),
            rejected_control_oid.to_string(),
        ));
    }

    let (level, success, error_message) = if let Some(rejected_control_oid) = rejected_control_oid {
        (
            AuditLevel::Warning,
            false,
            Some(format!(
                "unsupported critical control {}",
                rejected_control_oid
            )),
        )
    } else {
        (AuditLevel::Info, true, None)
    };

    log_generic_audit_event(
        request_context,
        session,
        level,
        AuditEventType::System,
        "ldap_controls",
        success,
        session.bound_dn(),
        error_message.as_deref(),
        details,
    )
    .await;
}

async fn validate_message_controls(
    socket: &mut ConnectionStream,
    message_id: u32,
    response_kind: Option<RejectionResponse>,
    message: &ldap_parser::ldap::LdapMessage<'_>,
    session: &ConnectionSession,
    request_context: &RequestContext,
) -> Result<Option<RequestControls>, ServerError> {
    let registry = active_runtime_control_registry();
    match registry.validate_request_controls(message.controls.as_deref()) {
        Ok(validated_controls) => {
            record_control_metrics(
                request_context,
                validated_controls.accepted().as_slice(),
                validated_controls.ignored(),
            );
            log_control_processing(
                request_context,
                session,
                validated_controls.accepted().as_slice(),
                validated_controls.ignored(),
                None,
            )
            .await;
            Ok(Some(validated_controls.into_accepted()))
        }
        Err(ControlValidationError::UnknownCritical { oid }) => {
            record_rejected_control_metric(request_context, &oid);
            log_control_processing(request_context, session, &[], &[], Some(&oid)).await;
            send_rejection_response(
                socket,
                message_id,
                response_kind,
                ResultCode::UnavailableCriticalExtension,
                &format!("unsupported critical control {}", oid),
            )
            .await?;
            Ok(None)
        }
    }
}

pub async fn handle_bind_request(
    socket: &mut (impl AsyncWrite + Unpin),
    backend: &dyn DirectoryBackend,
    message_id: u32,
    request: BindRequest<'_>,
) -> Result<(), ServerError> {
    let mut session = ConnectionSession::default();
    let request_controls = RequestControls::default();
    handle_bind_request_with_session_and_context(
        socket,
        backend,
        message_id,
        request,
        &mut session,
        &RequestContext::default(),
        false,
        &request_controls,
    )
    .await
}

fn client_ip_for_audit(request_context: &RequestContext) -> String {
    request_context
        .client_ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn session_id_for_audit(request_context: &RequestContext) -> Option<String> {
    request_context
        .session_id
        .map(|session_id| session_id.to_string())
}

fn audit_user_dn(session: &ConnectionSession) -> Option<String> {
    session.bound_dn().map(|dn| dn.to_string())
}

fn audit_actor(session: &ConnectionSession) -> String {
    session
        .bound_dn()
        .map(|dn| dn.to_string())
        .unwrap_or_else(|| "anonymous".to_string())
}

fn is_root_dn(session: &ConnectionSession, request_context: &RequestContext) -> bool {
    let Some(bound_dn) = session.bound_dn() else {
        return false;
    };

    request_context
        .security
        .as_ref()
        .and_then(|security| security.root_dn.as_deref())
        .map(|root_dn| bound_dn.eq_ignore_ascii_case(root_dn))
        .unwrap_or(false)
}

#[allow(clippy::too_many_arguments)]
async fn log_generic_audit_event(
    request_context: &RequestContext,
    session: &ConnectionSession,
    level: AuditLevel,
    event_type: AuditEventType,
    action: impl Into<String>,
    success: bool,
    target_dn: Option<&str>,
    error_message: Option<&str>,
    details: Vec<(String, String)>,
) {
    let Some(security) = request_context.security.as_ref() else {
        return;
    };
    let Some(logger) = security.audit_logger.as_ref() else {
        return;
    };

    let mut event = AuditEvent::new(level, event_type, action.into(), success)
        .with_client_ip(client_ip_for_audit(request_context));

    if let Some(user_dn) = audit_user_dn(session) {
        event = event.with_user_dn(user_dn);
    }
    if let Some(target_dn) = target_dn {
        event = event.with_target_dn(target_dn);
    }
    if let Some(session_id) = session_id_for_audit(request_context) {
        event = event.with_session_id(session_id);
    }
    if let Some(error_message) = error_message {
        event = event.with_error(error_message);
    }
    for (key, value) in details {
        event = event.with_detail(key, value);
    }

    logger.log_event(event).await;
}

async fn log_simple_bind_success(request_context: &RequestContext, user_dn: &str) {
    let Some(security) = request_context.security.as_ref() else {
        return;
    };
    if !security.audit_config.log_authentication {
        return;
    }
    let Some(logger) = security.audit_logger.as_ref() else {
        return;
    };
    logger
        .log_auth_success(user_dn, &client_ip_for_audit(request_context))
        .await;
}

async fn log_simple_bind_failure(request_context: &RequestContext, user_dn: &str, reason: &str) {
    let Some(security) = request_context.security.as_ref() else {
        return;
    };
    if !security.audit_config.log_authentication {
        return;
    }
    let Some(logger) = security.audit_logger.as_ref() else {
        return;
    };
    logger
        .log_auth_failure(user_dn, &client_ip_for_audit(request_context), reason)
        .await;
}

async fn log_sasl_bind(
    request_context: &RequestContext,
    user_dn: &str,
    mechanism: &str,
    success: bool,
    error_message: Option<&str>,
) {
    let Some(security) = request_context.security.as_ref() else {
        return;
    };
    if !security.audit_config.log_authentication {
        return;
    }
    let Some(logger) = security.audit_logger.as_ref() else {
        return;
    };
    logger
        .log_sasl_auth(
            user_dn,
            &client_ip_for_audit(request_context),
            mechanism,
            success,
            error_message,
        )
        .await;
}

async fn log_anonymous_bind(request_context: &RequestContext) {
    let session = ConnectionSession::default();
    if let Some(security) = request_context.security.as_ref() {
        if security.audit_config.log_authentication {
            log_generic_audit_event(
                request_context,
                &session,
                AuditLevel::Info,
                AuditEventType::Authentication,
                "anonymous_bind",
                true,
                None,
                None,
                Vec::new(),
            )
            .await;
        }
    }
}

async fn log_authz_success(
    request_context: &RequestContext,
    session: &ConnectionSession,
    operation: &str,
    target_dn: &str,
) {
    let Some(security) = request_context.security.as_ref() else {
        return;
    };
    if !security.audit_config.log_authorization {
        return;
    }
    let Some(logger) = security.audit_logger.as_ref() else {
        return;
    };
    logger
        .log_authz_success(&audit_actor(session), operation, target_dn)
        .await;
}

async fn log_authz_denial(
    request_context: &RequestContext,
    session: &ConnectionSession,
    operation: &str,
    target_dn: &str,
    reason: &str,
) {
    let Some(security) = request_context.security.as_ref() else {
        return;
    };
    if !security.audit_config.log_authorization {
        return;
    }
    let Some(logger) = security.audit_logger.as_ref() else {
        return;
    };
    logger
        .log_authz_denial(&audit_actor(session), operation, target_dn, reason)
        .await;
}

#[allow(clippy::too_many_arguments)]
async fn authorize_operation(
    socket: &mut (impl AsyncWrite + Unpin),
    backend: Option<&dyn DirectoryBackend>,
    message_id: u32,
    response_op: ResponseOp,
    session: &ConnectionSession,
    request_context: &RequestContext,
    permission: Permission,
    operation: &str,
    target_dn: &str,
    attribute: Option<&str>,
) -> Result<bool, ServerError> {
    let Some(security) = request_context.security.as_ref() else {
        return Ok(true);
    };
    let Some(aci_engine) = security.access_control.as_ref() else {
        return Ok(true);
    };

    if is_root_dn(session, request_context) {
        log_authz_success(request_context, session, operation, target_dn).await;
        return Ok(true);
    }

    let authz_result = if let Some(backend) = backend {
        aci_engine
            .check_permission_with_backend(
                session.bound_dn(),
                target_dn,
                attribute,
                permission,
                backend,
            )
            .await
    } else {
        aci_engine
            .check_permission(session.bound_dn(), target_dn, attribute, permission)
            .await
    };

    match authz_result {
        Ok(()) => {
            log_authz_success(request_context, session, operation, target_dn).await;
            Ok(true)
        }
        Err(err) => {
            log_authz_denial(request_context, session, operation, target_dn, &err).await;
            send_result(
                socket,
                message_id,
                response_op,
                ResultCode::InsufficientAccessRights,
                target_dn,
                &err,
            )
            .await?;
            Ok(false)
        }
    }
}

fn parse_sasl_plain_credentials(
    credentials: Option<&[u8]>,
) -> Result<(String, String, Vec<u8>), &'static str> {
    let Some(credentials) = credentials else {
        return Err("SASL PLAIN requires credentials");
    };

    let parts: Vec<&[u8]> = credentials.split(|&byte| byte == 0).collect();
    if parts.len() != 3 {
        return Err("invalid SASL PLAIN credential format");
    }

    let authzid =
        String::from_utf8(parts[0].to_vec()).map_err(|_| "invalid SASL authzid encoding")?;
    let authcid =
        String::from_utf8(parts[1].to_vec()).map_err(|_| "invalid SASL authcid encoding")?;

    Ok((authzid, authcid, parts[2].to_vec()))
}

async fn handle_bind_request_with_session_and_context(
    socket: &mut (impl AsyncWrite + Unpin),
    backend: &dyn DirectoryBackend,
    message_id: u32,
    request: BindRequest<'_>,
    session: &mut ConnectionSession,
    request_context: &RequestContext,
    connection_is_secure: bool,
    _request_controls: &RequestControls,
) -> Result<(), ServerError> {
    if request.version != 3 {
        session.clear();
        log_simple_bind_failure(request_context, "unknown", "unsupported LDAP version").await;
        send_bind_response(
            socket,
            message_id,
            ResultCode::ProtocolError,
            "unsupported LDAP version",
        )
        .await?;
        return Ok(());
    }

    match request.authentication {
        AuthenticationChoice::Simple(password) => {
            let dn = request.name.0.as_ref().trim().to_owned();
            if dn.is_empty() && password.as_ref().is_empty() {
                session.clear();
                log_anonymous_bind(request_context).await;
                send_bind_success(socket, message_id).await?;
                return Ok(());
            }

            match backend.authenticate(&dn, password.as_ref()).await {
                Ok(true) => {
                    session.bind(dn);
                    log_simple_bind_success(
                        request_context,
                        session.bound_dn().unwrap_or("anonymous"),
                    )
                    .await;
                    send_bind_success(socket, message_id).await?;
                }
                Ok(false) => {
                    session.clear();
                    log_simple_bind_failure(request_context, &dn, "invalid credentials").await;
                    send_bind_response(
                        socket,
                        message_id,
                        ResultCode::InvalidCredentials,
                        "invalid credentials",
                    )
                    .await?;
                }
                Err(err) => {
                    session.clear();
                    error!("Backend authentication error for {}: {}", dn, err);
                    log_simple_bind_failure(request_context, &dn, "backend failure").await;
                    send_bind_response(
                        socket,
                        message_id,
                        ResultCode::Unavailable,
                        "backend failure",
                    )
                    .await?;
                }
            }
        }
        AuthenticationChoice::Sasl(credentials) => {
            let mechanism = credentials.mechanism.0.as_ref().trim().to_owned();
            if !mechanism.eq_ignore_ascii_case("PLAIN") {
                session.clear();
                log_sasl_bind(
                    request_context,
                    request.name.0.as_ref().trim(),
                    &mechanism,
                    false,
                    Some("unsupported SASL mechanism"),
                )
                .await;
                send_bind_response(
                    socket,
                    message_id,
                    ResultCode::AuthMethodNotSupported,
                    "only SASL PLAIN is supported",
                )
                .await?;
                return Ok(());
            }

            if !connection_is_secure {
                session.clear();
                log_sasl_bind(
                    request_context,
                    request.name.0.as_ref().trim(),
                    "PLAIN",
                    false,
                    Some("SASL PLAIN requires TLS"),
                )
                .await;
                send_bind_response(
                    socket,
                    message_id,
                    ResultCode::ConfidentialityRequired,
                    "SASL PLAIN requires TLS",
                )
                .await?;
                return Ok(());
            }

            let (authzid, authcid, password) =
                match parse_sasl_plain_credentials(credentials.credentials.as_deref()) {
                    Ok(parsed) => parsed,
                    Err(err) => {
                        session.clear();
                        log_sasl_bind(
                            request_context,
                            request.name.0.as_ref().trim(),
                            "PLAIN",
                            false,
                            Some(err),
                        )
                        .await;
                        send_bind_response(socket, message_id, ResultCode::InvalidCredentials, err)
                            .await?;
                        return Ok(());
                    }
                };

            let bind_dn = if request.name.0.as_ref().trim().is_empty() {
                authcid.clone()
            } else {
                request.name.0.as_ref().trim().to_owned()
            };

            if bind_dn.is_empty() {
                session.clear();
                log_sasl_bind(
                    request_context,
                    "anonymous",
                    "PLAIN",
                    false,
                    Some("empty SASL identity"),
                )
                .await;
                send_bind_response(
                    socket,
                    message_id,
                    ResultCode::InvalidCredentials,
                    "empty SASL identity",
                )
                .await?;
                return Ok(());
            }

            if !authzid.is_empty() && !authzid.eq_ignore_ascii_case(&bind_dn) {
                session.clear();
                log_sasl_bind(
                    request_context,
                    &bind_dn,
                    "PLAIN",
                    false,
                    Some("proxy authorization is not supported"),
                )
                .await;
                send_bind_response(
                    socket,
                    message_id,
                    ResultCode::InappropriateAuthentication,
                    "proxy authorization is not supported",
                )
                .await?;
                return Ok(());
            }

            match backend.authenticate(&bind_dn, &password).await {
                Ok(true) => {
                    session.bind(bind_dn.clone());
                    log_sasl_bind(request_context, &bind_dn, "PLAIN", true, None).await;
                    send_bind_success(socket, message_id).await?;
                }
                Ok(false) => {
                    session.clear();
                    log_sasl_bind(
                        request_context,
                        &bind_dn,
                        "PLAIN",
                        false,
                        Some("invalid credentials"),
                    )
                    .await;
                    send_bind_response(
                        socket,
                        message_id,
                        ResultCode::InvalidCredentials,
                        "invalid credentials",
                    )
                    .await?;
                }
                Err(err) => {
                    session.clear();
                    error!("Backend SASL authentication error for {}: {}", bind_dn, err);
                    log_sasl_bind(
                        request_context,
                        &bind_dn,
                        "PLAIN",
                        false,
                        Some("backend failure"),
                    )
                    .await;
                    send_bind_response(
                        socket,
                        message_id,
                        ResultCode::Unavailable,
                        "backend failure",
                    )
                    .await?;
                }
            }
        }
    }

    Ok(())
}

async fn ensure_authenticated_for_mutation(
    socket: &mut (impl AsyncWrite + Unpin),
    message_id: u32,
    session: &ConnectionSession,
    op: ResponseOp,
    target_dn: &str,
) -> Result<bool, ServerError> {
    if session.is_authenticated() {
        return Ok(true);
    }

    send_result(
        socket,
        message_id,
        op,
        ResultCode::InsufficientAccessRights,
        target_dn,
        "bind required before mutating directory data",
    )
    .await?;

    Ok(false)
}

async fn send_bind_success(
    socket: &mut (impl AsyncWrite + Unpin),
    message_id: u32,
) -> Result<(), ServerError> {
    send_bind_response(socket, message_id, ResultCode::Success, "").await
}

async fn send_bind_response(
    socket: &mut (impl AsyncWrite + Unpin),
    message_id: u32,
    result_code: ResultCode,
    diagnostic_message: impl Into<String>,
) -> Result<(), ServerError> {
    let encoded = encode_bind_response(message_id, result_code, "", diagnostic_message)?;
    socket.write_all(&encoded).await?;
    Ok(())
}

async fn send_result(
    socket: &mut (impl AsyncWrite + Unpin),
    message_id: u32,
    op: ResponseOp,
    result_code: ResultCode,
    matched_dn: impl Into<String>,
    diagnostic_message: impl Into<String>,
) -> Result<(), ServerError> {
    send_result_with_controls(
        socket,
        message_id,
        op,
        result_code,
        matched_dn,
        diagnostic_message,
        &[],
    )
    .await
}

async fn send_result_with_controls(
    socket: &mut (impl AsyncWrite + Unpin),
    message_id: u32,
    op: ResponseOp,
    result_code: ResultCode,
    matched_dn: impl Into<String>,
    diagnostic_message: impl Into<String>,
    controls: &[LdapControl],
) -> Result<(), ServerError> {
    let encoded = encode_result_response_with_controls(
        message_id,
        op,
        result_code,
        matched_dn,
        diagnostic_message,
        controls,
    )?;
    socket.write_all(&encoded).await?;
    Ok(())
}

async fn send_extended_response(
    socket: &mut (impl AsyncWrite + Unpin),
    message_id: u32,
    result_code: ResultCode,
    matched_dn: impl Into<String>,
    diagnostic_message: impl Into<String>,
    response_name: Option<String>,
    response_value: Option<Vec<u8>>,
) -> Result<(), ServerError> {
    send_extended_response_with_controls(
        socket,
        message_id,
        result_code,
        matched_dn,
        diagnostic_message,
        response_name,
        response_value,
        &[],
    )
    .await
}

async fn send_extended_response_with_controls(
    socket: &mut (impl AsyncWrite + Unpin),
    message_id: u32,
    result_code: ResultCode,
    matched_dn: impl Into<String>,
    diagnostic_message: impl Into<String>,
    response_name: Option<String>,
    response_value: Option<Vec<u8>>,
    controls: &[LdapControl],
) -> Result<(), ServerError> {
    let encoded = encode_extended_response_with_controls(
        message_id,
        result_code,
        matched_dn,
        diagnostic_message,
        response_name,
        response_value,
        controls,
    )?;
    socket.write_all(&encoded).await?;
    Ok(())
}

async fn send_custom_extended_response(
    socket: &mut (impl AsyncWrite + Unpin),
    message_id: u32,
    result_code: CustomResultCode,
    diagnostic_message: impl Into<String>,
) -> Result<(), ServerError> {
    let encoded = encode_custom_extended_response(message_id, result_code, "", diagnostic_message)?;
    socket.write_all(&encoded).await?;
    Ok(())
}

async fn send_custom_search_done(
    socket: &mut (impl AsyncWrite + Unpin),
    message_id: u32,
    result_code: CustomResultCode,
    diagnostic_message: impl Into<String>,
) -> Result<(), ServerError> {
    let encoded =
        encode_custom_search_result_done(message_id, result_code, "", diagnostic_message)?;
    socket.write_all(&encoded).await?;
    Ok(())
}

async fn send_search_entry_with_controls(
    socket: &mut (impl AsyncWrite + Unpin),
    message_id: u32,
    entry: &DirectoryEntry,
    attributes: &[(String, Vec<String>)],
    types_only: bool,
    controls: &[LdapControl],
) -> Result<(), ServerError> {
    let encoded =
        encode_search_entry_with_controls(message_id, entry, attributes, types_only, controls)?;
    socket.write_all(&encoded).await?;
    Ok(())
}

async fn try_handle_virtual_search_request(
    socket: &mut (impl AsyncWrite + Unpin),
    backend: &dyn DirectoryBackend,
    schema: &LdapSchema,
    runtime_config: &LegacyServerConfig,
    message_id: u32,
    base_dn: &str,
    scope: ldap_parser::ldap::SearchScope,
    requested_attributes: &[String],
    types_only: bool,
    connection_is_secure: bool,
    starttls_available: bool,
) -> Result<bool, ServerError> {
    if scope != ldap_parser::ldap::SearchScope::BaseObject {
        return Ok(false);
    }

    if base_dn.is_empty() {
        let attributes = match build_root_dse_attributes(
            backend,
            runtime_config,
            connection_is_secure,
            starttls_available,
        )
        .await
        {
            Ok(attributes) => attributes,
            Err(err) => {
                send_result(
                    socket,
                    message_id,
                    ResponseOp::SearchDone,
                    map_backend_error(&err),
                    base_dn,
                    diagnostic_for_error(&err),
                )
                .await?;
                return Ok(true);
            }
        };
        send_virtual_search_entry(
            socket,
            message_id,
            "",
            &attributes,
            requested_attributes,
            types_only,
        )
        .await?;
        send_result(
            socket,
            message_id,
            ResponseOp::SearchDone,
            ResultCode::Success,
            "",
            "",
        )
        .await?;
        return Ok(true);
    }

    if base_dn.eq_ignore_ascii_case(&runtime_config.subschema_dn) {
        let attributes = build_subschema_attributes(schema);
        send_virtual_search_entry(
            socket,
            message_id,
            &runtime_config.subschema_dn,
            &attributes,
            requested_attributes,
            types_only,
        )
        .await?;
        send_result(
            socket,
            message_id,
            ResponseOp::SearchDone,
            ResultCode::Success,
            &runtime_config.subschema_dn,
            "",
        )
        .await?;
        return Ok(true);
    }

    Ok(false)
}

async fn build_root_dse_attributes(
    backend: &dyn DirectoryBackend,
    runtime_config: &LegacyServerConfig,
    connection_is_secure: bool,
    starttls_available: bool,
) -> Result<Vec<(String, Vec<String>)>, BackendError> {
    let mut attributes = vec![("supportedLDAPVersion".to_string(), vec!["3".to_string()])];

    if !runtime_config.naming_contexts.is_empty() {
        attributes.push((
            "namingContexts".to_string(),
            runtime_config.naming_contexts.clone(),
        ));
    }

    attributes.push((
        "subschemaSubentry".to_string(),
        vec![runtime_config.subschema_dn.clone()],
    ));

    let supported_extensions =
        active_runtime_supported_extensions(connection_is_secure, starttls_available);
    if !supported_extensions.is_empty() {
        attributes.push(("supportedExtension".to_string(), supported_extensions));
    }

    let supported_controls = active_runtime_control_registry().supported_control_oids();
    if !supported_controls.is_empty() {
        attributes.push(("supportedControl".to_string(), supported_controls));
    }

    let supported_sasl = active_runtime_supported_sasl_mechanisms();
    if !supported_sasl.is_empty() {
        attributes.push(("supportedSASLMechanisms".to_string(), supported_sasl));
    }

    if let Some(context_csn) = backend.get_context_csn().await? {
        attributes.push(("contextCSN".to_string(), vec![context_csn.to_ldap_string()]));
    }

    Ok(attributes)
}

fn build_subschema_attributes(schema: &LdapSchema) -> Vec<(String, Vec<String>)> {
    let mut attributes = vec![
        (
            "objectClass".to_string(),
            vec![
                "top".to_string(),
                "subentry".to_string(),
                "subschema".to_string(),
            ],
        ),
        ("cn".to_string(), vec!["Subschema".to_string()]),
    ];

    let attribute_types = schema
        .attribute_types_unique_sorted()
        .into_iter()
        .map(|attribute| attribute.to_schema_description())
        .collect::<Vec<_>>();
    if !attribute_types.is_empty() {
        attributes.push(("attributeTypes".to_string(), attribute_types));
    }

    let object_classes = schema
        .object_classes_unique_sorted()
        .into_iter()
        .map(|object_class| object_class.to_schema_description())
        .collect::<Vec<_>>();
    if !object_classes.is_empty() {
        attributes.push(("objectClasses".to_string(), object_classes));
    }

    attributes
}

fn active_runtime_supported_extensions(
    connection_is_secure: bool,
    starttls_available: bool,
) -> Vec<String> {
    let mut supported = Vec::new();
    if starttls_available && !connection_is_secure {
        supported.push(START_TLS_OID.to_string());
    }
    supported.push(CANCEL_OID.to_string());
    supported.push(PASSWORD_MODIFY_OID.to_string());
    supported.push(WHO_AM_I_OID.to_string());
    supported
}

fn active_runtime_supported_sasl_mechanisms() -> Vec<String> {
    vec!["PLAIN".to_string()]
}

async fn send_virtual_search_entry(
    socket: &mut (impl AsyncWrite + Unpin),
    message_id: u32,
    dn: &str,
    available_attributes: &[(String, Vec<String>)],
    requested_attributes: &[String],
    types_only: bool,
) -> Result<(), ServerError> {
    let synthetic_entry = DirectoryEntry::new(dn, HashMap::new());
    let selected_attributes = select_virtual_attributes(available_attributes, requested_attributes);
    send_search_entry_with_controls(
        socket,
        message_id,
        &synthetic_entry,
        &selected_attributes,
        types_only,
        &[],
    )
    .await
}

fn select_virtual_attributes(
    available_attributes: &[(String, Vec<String>)],
    requested_attributes: &[String],
) -> Vec<(String, Vec<String>)> {
    if requested_attributes
        .iter()
        .any(|attribute| attribute.eq_ignore_ascii_case("1.1"))
    {
        return Vec::new();
    }

    let include_all = requested_attributes.is_empty()
        || requested_attributes
            .iter()
            .any(|attribute| attribute == "*" || attribute == "+");

    available_attributes
        .iter()
        .filter(|(name, _)| {
            include_all
                || requested_attributes
                    .iter()
                    .any(|attribute| attribute.eq_ignore_ascii_case(name))
        })
        .cloned()
        .collect()
}

fn map_backend_error(err: &BackendError) -> ResultCode {
    match err {
        BackendError::AlreadyExists => ResultCode::EntryAlreadyExists,
        BackendError::NotFound => ResultCode::NoSuchObject,
        BackendError::Storage(_) => ResultCode::Unavailable,
    }
}

fn diagnostic_for_error(err: &BackendError) -> &'static str {
    match err {
        BackendError::AlreadyExists => "entry already exists",
        BackendError::NotFound => "no such object",
        BackendError::Storage(_) => "backend failure",
    }
}

fn compute_new_dn(dn: &str, new_rdn: &str, new_superior: Option<&str>) -> String {
    if let Some(superior) = new_superior {
        format!("{},{}", new_rdn, superior)
    } else if let Some((_, rest)) = dn.split_once(',') {
        if rest.is_empty() {
            new_rdn.to_string()
        } else {
            format!("{},{}", new_rdn, rest)
        }
    } else {
        new_rdn.to_string()
    }
}

pub async fn handle_search_request(
    socket: &mut (impl AsyncRead + AsyncWrite + Unpin),
    backend: &dyn DirectoryBackend,
    message_id: u32,
    request: SearchRequest<'_>,
) -> Result<(), ServerError> {
    let session = ConnectionSession::default();
    let schema = LdapSchema::default();
    let runtime_config = LegacyServerConfig::default();
    let request_controls = RequestControls::default();
    let mut operation_registry = ConnectionOperationRegistry::default();
    handle_search_request_with_context_and_registry(
        socket,
        backend,
        &schema,
        &runtime_config,
        message_id,
        request,
        &session,
        &mut operation_registry,
        &RequestContext::default(),
        &request_controls,
        false,
        false,
    )
    .await
}

#[cfg_attr(not(test), allow(dead_code))]
async fn handle_search_request_with_context(
    socket: &mut (impl AsyncRead + AsyncWrite + Unpin),
    backend: &dyn DirectoryBackend,
    schema: &LdapSchema,
    runtime_config: &LegacyServerConfig,
    message_id: u32,
    request: SearchRequest<'_>,
    session: &ConnectionSession,
    request_context: &RequestContext,
    _request_controls: &RequestControls,
    connection_is_secure: bool,
    starttls_available: bool,
) -> Result<(), ServerError> {
    let mut operation_registry = ConnectionOperationRegistry::default();
    handle_search_request_with_context_and_registry(
        socket,
        backend,
        schema,
        runtime_config,
        message_id,
        request,
        session,
        &mut operation_registry,
        request_context,
        _request_controls,
        connection_is_secure,
        starttls_available,
    )
    .await
}

async fn handle_search_request_with_context_and_registry(
    socket: &mut (impl AsyncRead + AsyncWrite + Unpin),
    backend: &dyn DirectoryBackend,
    schema: &LdapSchema,
    runtime_config: &LegacyServerConfig,
    message_id: u32,
    request: SearchRequest<'_>,
    session: &ConnectionSession,
    operation_registry: &mut ConnectionOperationRegistry,
    request_context: &RequestContext,
    _request_controls: &RequestControls,
    connection_is_secure: bool,
    starttls_available: bool,
) -> Result<(), ServerError> {
    let base_dn = request.base_object.0.as_ref().trim().to_owned();
    let attribute_selection: Vec<String> = request
        .attributes
        .iter()
        .map(|attribute| attribute.0.as_ref().trim().to_owned())
        .collect();

    if try_handle_virtual_search_request(
        socket,
        backend,
        schema,
        runtime_config,
        message_id,
        &base_dn,
        request.scope,
        &attribute_selection,
        request.types_only,
        connection_is_secure,
        starttls_available,
    )
    .await?
    {
        return Ok(());
    }

    if !authorize_operation(
        socket,
        Some(backend),
        message_id,
        ResponseOp::SearchDone,
        session,
        request_context,
        Permission::Search,
        "search",
        &base_dn,
        None,
    )
    .await?
    {
        return Ok(());
    }

    if attribute_selection
        .iter()
        .any(|attribute| attribute.eq_ignore_ascii_case(REPLICATION_STREAM_ATTRIBUTE))
    {
        return handle_replication_stream_request(
            socket,
            backend,
            message_id,
            &base_dn,
            &attribute_selection,
            session,
            operation_registry,
            request_context,
        )
        .await;
    }

    operation_registry.register(message_id, ConnectionOperationKind::Search, true);

    let search_hint = extract_search_hint(&request.filter);
    let entries = match backend
        .search_entries_with_hint(&base_dn, request.scope, search_hint)
        .await
    {
        Ok(entries) => entries,
        Err(err) => {
            error!("Search backend failure for {}: {}", base_dn, err);
            send_result(
                socket,
                message_id,
                ResponseOp::SearchDone,
                map_backend_error(&err),
                &base_dn,
                diagnostic_for_error(&err),
            )
            .await?;
            operation_registry.finish(message_id, FinishedOperationState::Completed);
            return Ok(());
        }
    };

    let mut returned = 0usize;
    let mut size_limit_hit = false;

    for entry in entries {
        if !entry_matches_filter(&entry, &request.filter) {
            continue;
        }

        if request.size_limit != 0 && returned >= request.size_limit as usize {
            size_limit_hit = true;
            break;
        }

        let attributes = select_attributes(&entry, &attribute_selection);
        send_search_entry_with_controls(
            socket,
            message_id,
            &entry,
            &attributes,
            request.types_only,
            &[],
        )
        .await?;
        returned += 1;
    }

    let (result_code, diagnostic) = if size_limit_hit {
        (ResultCode::SizeLimitExceeded, "size limit exceeded")
    } else {
        (ResultCode::Success, "")
    };

    send_result(
        socket,
        message_id,
        ResponseOp::SearchDone,
        result_code,
        &base_dn,
        diagnostic,
    )
    .await?;
    operation_registry.finish(message_id, FinishedOperationState::Completed);

    Ok(())
}

fn extract_search_hint(filter: &Filter<'_>) -> Option<SearchCandidateHint> {
    match filter {
        Filter::And(filters) => filters.iter().find_map(extract_search_hint),
        Filter::EqualityMatch(ava) => Some(SearchCandidateHint::Equality {
            attribute: ava.attribute_desc.0.as_ref().to_string(),
            value: bytes_to_string(ava.assertion_value),
        }),
        Filter::Present(attribute) => Some(SearchCandidateHint::Present {
            attribute: attribute.0.as_ref().to_string(),
        }),
        _ => None,
    }
}

async fn handle_replication_stream_request(
    socket: &mut (impl AsyncRead + AsyncWrite + Unpin),
    backend: &dyn DirectoryBackend,
    message_id: u32,
    base_dn: &str,
    attribute_selection: &[String],
    connection_session: &ConnectionSession,
    operation_registry: &mut ConnectionOperationRegistry,
    request_context: &RequestContext,
) -> Result<(), ServerError> {
    operation_registry.register(message_id, ConnectionOperationKind::ReplicationStream, true);
    let mut session = ProviderOwnedReplicationSession::new(socket, message_id, base_dn);
    let provider_lifecycle = backend.replication_provider_lifecycle();
    let _session_guard = if let Some(lifecycle) = provider_lifecycle.as_ref() {
        match lifecycle.register_session() {
            Some(guard) => Some(guard),
            None => {
                operation_registry.finish(message_id, FinishedOperationState::Completed);
                return finish_replication_stream_unavailable(
                    &mut session,
                    "replication provider shutting down",
                )
                .await;
            }
        }
    } else {
        None
    };

    let mut receiver = if let Some(receiver) = backend.subscribe_to_replication_changes() {
        receiver
    } else {
        session
            .send_unavailable("replication stream not available")
            .await?;
        operation_registry.finish(message_id, FinishedOperationState::Completed);
        return Ok(());
    };
    let mut control_decoder = BerDecoderFsmImpl::new();
    let mut control_buffer = vec![0_u8; 4096];

    let start_cookie = attribute_selection.iter().find_map(|attribute| {
        attribute
            .strip_prefix(REPLICATION_COOKIE_ATTRIBUTE_PREFIX)
            .map(|cookie| cookie.to_string())
    });

    if let Some(changelog) = backend.replication_changelog() {
        let replay_entries = match start_cookie.as_deref() {
            Some("csn-empty") | None => Vec::new(),
            Some(cookie) => changelog
                .parse_cookie(cookie)
                .map(|csn| changelog.get_since_csn(&csn))
                .unwrap_or_default(),
        };

        for entry in replay_entries {
            if provider_lifecycle
                .as_ref()
                .is_some_and(|lifecycle| lifecycle.is_draining())
            {
                operation_registry.finish(message_id, FinishedOperationState::Completed);
                return finish_replication_stream_unavailable(
                    &mut session,
                    "replication provider shutting down",
                )
                .await;
            }
            if !is_dn_in_scope(&entry.dn, base_dn) {
                continue;
            }
            session.send_change(&entry).await?;
        }
    }

    loop {
        let recv_result = if let Some(lifecycle) = provider_lifecycle.as_ref() {
            tokio::select! {
                _ = lifecycle.wait_for_shutdown() => {
                    operation_registry.finish(message_id, FinishedOperationState::Completed);
                    return finish_replication_stream_unavailable(
                        &mut session,
                        "replication provider shutting down",
                    ).await;
                }
                control_result = receive_stream_control_event(
                    session.socket,
                    &mut control_decoder,
                    &mut control_buffer,
                    message_id,
                    operation_registry,
                    connection_session,
                    request_context,
                ) => {
                    match control_result? {
                        StreamControlEvent::Continue => continue,
                        StreamControlEvent::Cancel => {
                            operation_registry.finish(message_id, FinishedOperationState::Canceled);
                            let _ = send_custom_search_done(
                                session.socket,
                                message_id,
                                CustomResultCode::Canceled,
                                "operation canceled",
                            )
                            .await;
                            return Ok(());
                        }
                        StreamControlEvent::Abandon => {
                            operation_registry.finish(message_id, FinishedOperationState::Abandoned);
                            return Ok(());
                        }
                        StreamControlEvent::ClientClosed => {
                            operation_registry.finish(message_id, FinishedOperationState::Completed);
                            return Ok(());
                        }
                    }
                }
                recv_result = receiver.recv() => recv_result,
            }
        } else {
            tokio::select! {
                control_result = receive_stream_control_event(
                    session.socket,
                    &mut control_decoder,
                    &mut control_buffer,
                    message_id,
                    operation_registry,
                    connection_session,
                    request_context,
                ) => {
                    match control_result? {
                        StreamControlEvent::Continue => continue,
                        StreamControlEvent::Cancel => {
                            operation_registry.finish(message_id, FinishedOperationState::Canceled);
                            let _ = send_custom_search_done(
                                session.socket,
                                message_id,
                                CustomResultCode::Canceled,
                                "operation canceled",
                            )
                            .await;
                            return Ok(());
                        }
                        StreamControlEvent::Abandon => {
                            operation_registry.finish(message_id, FinishedOperationState::Abandoned);
                            return Ok(());
                        }
                        StreamControlEvent::ClientClosed => {
                            operation_registry.finish(message_id, FinishedOperationState::Completed);
                            return Ok(());
                        }
                    }
                }
                recv_result = receiver.recv() => recv_result,
            }
        };

        match recv_result {
            Ok(entry) => {
                if provider_lifecycle
                    .as_ref()
                    .is_some_and(|lifecycle| lifecycle.is_draining())
                {
                    operation_registry.finish(message_id, FinishedOperationState::Completed);
                    return finish_replication_stream_unavailable(
                        &mut session,
                        "replication provider shutting down",
                    )
                    .await;
                }
                if !is_dn_in_scope(&entry.dn, base_dn) {
                    continue;
                }
                if let Err(err) = session.send_change(&entry).await {
                    warn!("Replication stream send failed: {}", err);
                    operation_registry.finish(message_id, FinishedOperationState::Completed);
                    break;
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                warn!("Replication stream lagged by {} messages", skipped);
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }

    operation_registry.finish(message_id, FinishedOperationState::Completed);
    let _ = session.finish().await;

    Ok(())
}

enum StreamControlEvent {
    Continue,
    Cancel,
    Abandon,
    ClientClosed,
}

async fn receive_stream_control_event(
    socket: &mut (impl AsyncRead + AsyncWrite + Unpin),
    decoder: &mut BerDecoderFsmImpl,
    read_buffer: &mut [u8],
    active_message_id: u32,
    operation_registry: &mut ConnectionOperationRegistry,
    session: &ConnectionSession,
    request_context: &RequestContext,
) -> Result<StreamControlEvent, ServerError> {
    let bytes_read = socket.read(read_buffer).await?;
    if bytes_read == 0 {
        return Ok(StreamControlEvent::ClientClosed);
    }

    let decoded_messages = match decode_messages(decoder, read_buffer[..bytes_read].to_vec()).await
    {
        Ok(messages) => messages,
        Err(err) => {
            error!("Failed to decode stream control message: {}", err);
            send_bind_response(socket, 0, ResultCode::ProtocolError, "invalid message").await?;
            return Ok(StreamControlEvent::Continue);
        }
    };

    for message_bytes in decoded_messages {
        let parsed_messages = match parse_ldap_messages(&message_bytes) {
            Ok((_, messages)) => messages,
            Err(_) => {
                if let Some(message) = parse_abandon_message_fallback(&message_bytes) {
                    vec![message]
                } else {
                    send_bind_response(socket, 0, ResultCode::ProtocolError, "invalid message")
                        .await?;
                    continue;
                }
            }
        };

        for message in parsed_messages {
            match message.protocol_op {
                ProtocolOp::AbandonRequest(request_id) => {
                    let abandoned = operation_registry.request_abandon(request_id.0);
                    if let Some(metrics) = request_context.metrics.as_ref() {
                        metrics.increment_counter("ldap_abandon_requests_total", 1);
                        if abandoned {
                            metrics.increment_counter("ldap_abandon_accepted_total", 1);
                        }
                    }
                    log_generic_audit_event(
                        request_context,
                        session,
                        AuditLevel::Info,
                        AuditEventType::System,
                        "abandon",
                        abandoned,
                        None,
                        if abandoned {
                            None
                        } else {
                            Some("target operation was not active or not cancellable")
                        },
                        vec![("target_message_id".to_string(), request_id.0.to_string())],
                    )
                    .await;
                    if abandoned && request_id.0 == active_message_id {
                        return Ok(StreamControlEvent::Abandon);
                    }
                }
                ProtocolOp::ExtendedRequest(request)
                    if request.request_name.0.as_ref() == CANCEL_OID =>
                {
                    increment_control_counter(request_context, "ldap_cancel_requests_total", 1);
                    let cancel_id =
                        match parse_cancel_request_value(request.request_value.as_deref()) {
                            Ok(cancel_id) => cancel_id as u32,
                            Err(err) => {
                                send_custom_extended_response(
                                    socket,
                                    message.message_id.0,
                                    CustomResultCode::ProtocolError,
                                    err.to_string(),
                                )
                                .await?;
                                log_generic_audit_event(
                                    request_context,
                                    session,
                                    AuditLevel::Warning,
                                    AuditEventType::System,
                                    "cancel",
                                    false,
                                    None,
                                    Some("Malformed Cancel request"),
                                    vec![("result".to_string(), "protocol_error".to_string())],
                                )
                                .await;
                                continue;
                            }
                        };

                    let outcome = operation_registry.request_cancel(cancel_id);
                    let (result_code, diagnostic, success, result_name) = match outcome {
                        CancelRequestOutcome::Accepted => {
                            (CustomResultCode::Success, String::new(), true, "success")
                        }
                        CancelRequestOutcome::NoSuchOperation => (
                            CustomResultCode::NoSuchOperation,
                            "no such operation".to_string(),
                            false,
                            "no_such_operation",
                        ),
                        CancelRequestOutcome::TooLate => (
                            CustomResultCode::TooLate,
                            "too late to cancel operation".to_string(),
                            false,
                            "too_late",
                        ),
                        CancelRequestOutcome::CannotCancel => (
                            CustomResultCode::CannotCancel,
                            "operation cannot be canceled".to_string(),
                            false,
                            "cannot_cancel",
                        ),
                    };
                    if success {
                        increment_control_counter(request_context, "ldap_cancel_accepted_total", 1);
                    }
                    send_custom_extended_response(
                        socket,
                        message.message_id.0,
                        result_code,
                        &diagnostic,
                    )
                    .await?;
                    log_generic_audit_event(
                        request_context,
                        session,
                        if success {
                            AuditLevel::Info
                        } else {
                            AuditLevel::Warning
                        },
                        AuditEventType::System,
                        "cancel",
                        success,
                        None,
                        if diagnostic.is_empty() {
                            None
                        } else {
                            Some(diagnostic.as_str())
                        },
                        vec![
                            ("target_message_id".to_string(), cancel_id.to_string()),
                            ("result".to_string(), result_name.to_string()),
                        ],
                    )
                    .await;
                    if success && cancel_id == active_message_id {
                        return Ok(StreamControlEvent::Cancel);
                    }
                }
                other => {
                    let response_kind = rejection_response_for_protocol(&other);
                    send_rejection_response(
                        socket,
                        message.message_id.0,
                        response_kind,
                        ResultCode::Busy,
                        "another operation is already in progress",
                    )
                    .await?;
                }
            }
        }
    }

    Ok(StreamControlEvent::Continue)
}

async fn finish_replication_stream_unavailable<S: AsyncWrite + Unpin>(
    session: &mut ProviderOwnedReplicationSession<'_, S>,
    message: &str,
) -> Result<(), ServerError> {
    if let Err(err) = session.send_unavailable(message).await {
        warn!("Replication stream shutdown response failed: {}", err);
    }
    Ok(())
}

struct ProviderOwnedReplicationSession<'a, S> {
    socket: &'a mut S,
    message_id: u32,
    base_dn: &'a str,
}

impl<'a, S: AsyncWrite + Unpin> ProviderOwnedReplicationSession<'a, S> {
    fn new(socket: &'a mut S, message_id: u32, base_dn: &'a str) -> Self {
        Self {
            socket,
            message_id,
            base_dn,
        }
    }

    async fn send_change(
        &mut self,
        entry: &crate::replication_provider_fsm::ChangelogEntry,
    ) -> Result<(), ServerError> {
        let synthetic_entry = DirectoryEntry::new(entry.dn.clone(), HashMap::new());
        let attributes = changelog_entry_to_replication_attrs(entry);
        send_search_entry_with_controls(
            self.socket,
            self.message_id,
            &synthetic_entry,
            &attributes,
            false,
            &[],
        )
        .await?;
        Ok(())
    }

    async fn send_unavailable(&mut self, message: &str) -> Result<(), ServerError> {
        send_result(
            self.socket,
            self.message_id,
            ResponseOp::SearchDone,
            ResultCode::Unavailable,
            self.base_dn,
            message,
        )
        .await
    }

    async fn finish(&mut self) -> Result<(), ServerError> {
        send_result(
            self.socket,
            self.message_id,
            ResponseOp::SearchDone,
            ResultCode::Success,
            self.base_dn,
            "",
        )
        .await
    }
}

async fn log_compare_audit(
    request_context: &RequestContext,
    session: &ConnectionSession,
    dn: &str,
    attribute: &str,
    success: bool,
    result: &str,
    error_message: Option<&str>,
) {
    let Some(security) = request_context.security.as_ref() else {
        return;
    };
    if !security.audit_config.log_authorization {
        return;
    }
    log_generic_audit_event(
        request_context,
        session,
        if success {
            AuditLevel::Info
        } else {
            AuditLevel::Warning
        },
        AuditEventType::Authorization,
        "compare",
        success,
        Some(dn),
        error_message,
        vec![
            ("attribute".to_string(), attribute.to_string()),
            ("result".to_string(), result.to_string()),
        ],
    )
    .await;
}

async fn log_modify_audit_event(
    request_context: &RequestContext,
    session: &ConnectionSession,
    dn: &str,
    success: bool,
    attribute_names: &[String],
    error_message: Option<&str>,
) {
    let Some(security) = request_context.security.as_ref() else {
        return;
    };
    if !security.audit_config.log_modifications {
        return;
    }
    if success {
        if let Some(logger) = security.audit_logger.as_ref() {
            let attribute_refs: Vec<&str> = attribute_names.iter().map(String::as_str).collect();
            logger
                .log_modify(
                    dn,
                    &audit_actor(session),
                    &client_ip_for_audit(request_context),
                    &attribute_refs,
                )
                .await;
        }
        return;
    }

    log_generic_audit_event(
        request_context,
        session,
        AuditLevel::Error,
        AuditEventType::DataModification,
        "modify",
        false,
        Some(dn),
        error_message,
        vec![("attributes".to_string(), attribute_names.join(","))],
    )
    .await;
}

async fn log_password_modify_audit_event(
    request_context: &RequestContext,
    session: &ConnectionSession,
    target_dn: Option<&str>,
    mode: &str,
    generated_password: bool,
    success: bool,
    error_message: Option<&str>,
) {
    let Some(security) = request_context.security.as_ref() else {
        return;
    };
    if !security.audit_config.log_modifications {
        return;
    }

    log_generic_audit_event(
        request_context,
        session,
        if success {
            AuditLevel::Info
        } else {
            AuditLevel::Warning
        },
        AuditEventType::DataModification,
        "password_modify",
        success,
        target_dn,
        error_message,
        vec![
            ("attribute".to_string(), "userPassword".to_string()),
            ("mode".to_string(), mode.to_string()),
            (
                "generated_password".to_string(),
                generated_password.to_string(),
            ),
        ],
    )
    .await;
}

pub async fn handle_modify_request(
    socket: &mut (impl AsyncWrite + Unpin),
    backend: &dyn DirectoryBackend,
    message_id: u32,
    request: ModifyRequest<'_>,
) -> Result<(), ServerError> {
    let session = ConnectionSession::default();
    let request_controls = RequestControls::default();
    handle_modify_request_with_context(
        socket,
        backend,
        message_id,
        request,
        &session,
        &RequestContext::default(),
        &request_controls,
    )
    .await
}

async fn handle_modify_request_with_context(
    socket: &mut (impl AsyncWrite + Unpin),
    backend: &dyn DirectoryBackend,
    message_id: u32,
    request: ModifyRequest<'_>,
    session: &ConnectionSession,
    request_context: &RequestContext,
    _request_controls: &RequestControls,
) -> Result<(), ServerError> {
    let dn = request.object.0.as_ref().trim().to_owned();
    let modifications = convert_modifications(request.changes);
    let modified_attributes: Vec<String> = modifications
        .iter()
        .map(|modification| modification.attribute.clone())
        .collect();

    if !authorize_operation(
        socket,
        Some(backend),
        message_id,
        ResponseOp::Modify,
        session,
        request_context,
        Permission::Modify,
        "modify",
        &dn,
        None,
    )
    .await?
    {
        return Ok(());
    }

    match backend
        .modify_entry_with_actor(&dn, modifications, session.bound_dn().map(str::to_string))
        .await
    {
        Ok(()) => {
            log_modify_audit_event(
                request_context,
                session,
                &dn,
                true,
                &modified_attributes,
                None,
            )
            .await;
            send_result(
                socket,
                message_id,
                ResponseOp::Modify,
                ResultCode::Success,
                &dn,
                "",
            )
            .await?;
        }
        Err(err) => {
            error!("Modify operation failed for {}: {}", dn, err);
            log_modify_audit_event(
                request_context,
                session,
                &dn,
                false,
                &modified_attributes,
                Some(diagnostic_for_error(&err)),
            )
            .await;
            send_result(
                socket,
                message_id,
                ResponseOp::Modify,
                map_backend_error(&err),
                &dn,
                diagnostic_for_error(&err),
            )
            .await?;
        }
    }

    Ok(())
}

pub async fn handle_add_request(
    socket: &mut (impl AsyncWrite + Unpin),
    backend: &dyn DirectoryBackend,
    schema: &LdapSchema,
    message_id: u32,
    request: AddRequest<'_>,
) -> Result<(), ServerError> {
    let session = ConnectionSession::default();
    let request_controls = RequestControls::default();
    handle_add_request_with_context(
        socket,
        backend,
        schema,
        message_id,
        request,
        &session,
        &RequestContext::default(),
        &request_controls,
    )
    .await
}

async fn handle_add_request_with_context(
    socket: &mut (impl AsyncWrite + Unpin),
    backend: &dyn DirectoryBackend,
    schema: &LdapSchema,
    message_id: u32,
    request: AddRequest<'_>,
    session: &ConnectionSession,
    request_context: &RequestContext,
    _request_controls: &RequestControls,
) -> Result<(), ServerError> {
    let dn = request.entry.0.as_ref().trim().to_owned();
    let (entry, password) = build_entry_from_add_request(&dn, request.attributes);

    if !authorize_operation(
        socket,
        Some(backend),
        message_id,
        ResponseOp::Add,
        session,
        request_context,
        Permission::Add,
        "add",
        &dn,
        None,
    )
    .await?
    {
        return Ok(());
    }

    // Perform schema validation before adding
    if let Err(schema_error) = schema.validate_entry(&entry.attributes) {
        error!("Schema validation failed for {}: {}", dn, schema_error);
        log_generic_audit_event(
            request_context,
            session,
            AuditLevel::Error,
            AuditEventType::DataModification,
            "add",
            false,
            Some(&dn),
            Some(&format!("Schema validation failed: {}", schema_error)),
            Vec::new(),
        )
        .await;
        send_result(
            socket,
            message_id,
            ResponseOp::Add,
            ResultCode::ObjectClassViolation,
            &dn,
            &format!("Schema validation failed: {}", schema_error),
        )
        .await?;
        return Ok(());
    }

    match backend
        .add_entry_with_actor(entry, password, session.bound_dn().map(str::to_string))
        .await
    {
        Ok(()) => {
            if let Some(security) = request_context.security.as_ref() {
                if security.audit_config.log_modifications {
                    if let Some(logger) = security.audit_logger.as_ref() {
                        logger
                            .log_add(
                                &dn,
                                &audit_actor(session),
                                &client_ip_for_audit(request_context),
                                true,
                            )
                            .await;
                    }
                }
            }
            send_result(
                socket,
                message_id,
                ResponseOp::Add,
                ResultCode::Success,
                &dn,
                "",
            )
            .await?;
        }
        Err(err) => {
            error!("Add operation failed for {}: {}", dn, err);
            if let Some(security) = request_context.security.as_ref() {
                if security.audit_config.log_modifications {
                    if let Some(logger) = security.audit_logger.as_ref() {
                        logger
                            .log_add(
                                &dn,
                                &audit_actor(session),
                                &client_ip_for_audit(request_context),
                                false,
                            )
                            .await;
                    }
                }
            }
            send_result(
                socket,
                message_id,
                ResponseOp::Add,
                map_backend_error(&err),
                &dn,
                diagnostic_for_error(&err),
            )
            .await?;
        }
    }

    Ok(())
}

pub async fn handle_delete_request(
    socket: &mut (impl AsyncWrite + Unpin),
    backend: &dyn DirectoryBackend,
    message_id: u32,
    dn: ldap_parser::ldap::LdapDN<'_>,
) -> Result<(), ServerError> {
    let session = ConnectionSession::default();
    let request_controls = RequestControls::default();
    handle_delete_request_with_context(
        socket,
        backend,
        message_id,
        dn,
        &session,
        &RequestContext::default(),
        &request_controls,
    )
    .await
}

async fn handle_delete_request_with_context(
    socket: &mut (impl AsyncWrite + Unpin),
    backend: &dyn DirectoryBackend,
    message_id: u32,
    dn: ldap_parser::ldap::LdapDN<'_>,
    session: &ConnectionSession,
    request_context: &RequestContext,
    _request_controls: &RequestControls,
) -> Result<(), ServerError> {
    let dn = dn.0.as_ref().trim().to_owned();

    if !authorize_operation(
        socket,
        Some(backend),
        message_id,
        ResponseOp::Delete,
        session,
        request_context,
        Permission::Delete,
        "delete",
        &dn,
        None,
    )
    .await?
    {
        return Ok(());
    }

    match backend.delete_entry(&dn).await {
        Ok(()) => {
            if let Some(security) = request_context.security.as_ref() {
                if security.audit_config.log_modifications {
                    if let Some(logger) = security.audit_logger.as_ref() {
                        logger
                            .log_delete(
                                &dn,
                                &audit_actor(session),
                                &client_ip_for_audit(request_context),
                                true,
                            )
                            .await;
                    }
                }
            }
            send_result(
                socket,
                message_id,
                ResponseOp::Delete,
                ResultCode::Success,
                &dn,
                "",
            )
            .await?;
        }
        Err(err) => {
            error!("Delete operation failed for {}: {}", dn, err);
            if let Some(security) = request_context.security.as_ref() {
                if security.audit_config.log_modifications {
                    if let Some(logger) = security.audit_logger.as_ref() {
                        logger
                            .log_delete(
                                &dn,
                                &audit_actor(session),
                                &client_ip_for_audit(request_context),
                                false,
                            )
                            .await;
                    }
                }
            }
            send_result(
                socket,
                message_id,
                ResponseOp::Delete,
                map_backend_error(&err),
                &dn,
                diagnostic_for_error(&err),
            )
            .await?;
        }
    }

    Ok(())
}

pub async fn handle_moddn_request(
    socket: &mut (impl AsyncWrite + Unpin),
    backend: &dyn DirectoryBackend,
    message_id: u32,
    request: ModDnRequest<'_>,
) -> Result<(), ServerError> {
    let session = ConnectionSession::default();
    let request_controls = RequestControls::default();
    handle_moddn_request_with_context(
        socket,
        backend,
        message_id,
        request,
        &session,
        &RequestContext::default(),
        &request_controls,
    )
    .await
}

async fn handle_moddn_request_with_context(
    socket: &mut (impl AsyncWrite + Unpin),
    backend: &dyn DirectoryBackend,
    message_id: u32,
    request: ModDnRequest<'_>,
    session: &ConnectionSession,
    request_context: &RequestContext,
    _request_controls: &RequestControls,
) -> Result<(), ServerError> {
    let dn = request.entry.0.as_ref().trim().to_owned();
    let new_rdn = request.newrdn.0.as_ref().trim().to_owned();
    let delete_old = request.deleteoldrdn;
    let new_superior = request
        .newsuperior
        .map(|sup| sup.0.into_owned())
        .filter(|sup| !sup.is_empty());

    if !authorize_operation(
        socket,
        Some(backend),
        message_id,
        ResponseOp::ModifyDn,
        session,
        request_context,
        Permission::Modify,
        "modifydn",
        &dn,
        None,
    )
    .await?
    {
        return Ok(());
    }

    let new_dn = compute_new_dn(&dn, &new_rdn, new_superior.as_deref());

    match backend
        .rename_entry_with_actor(
            &dn,
            &new_rdn,
            delete_old,
            new_superior,
            session.bound_dn().map(str::to_string),
        )
        .await
    {
        Ok(()) => {
            if let Some(security) = request_context.security.as_ref() {
                if security.audit_config.log_modifications {
                    if let Some(logger) = security.audit_logger.as_ref() {
                        logger
                            .log_modifydn(
                                &dn,
                                &new_dn,
                                &audit_actor(session),
                                &client_ip_for_audit(request_context),
                            )
                            .await;
                    }
                }
            }
            send_result(
                socket,
                message_id,
                ResponseOp::ModifyDn,
                ResultCode::Success,
                &dn,
                "",
            )
            .await?;
        }
        Err(err) => {
            error!("ModifyDN operation failed for {}: {}", dn, err);
            log_generic_audit_event(
                request_context,
                session,
                AuditLevel::Error,
                AuditEventType::DataModification,
                "modifydn",
                false,
                Some(&dn),
                Some(diagnostic_for_error(&err)),
                vec![("new_dn".to_string(), new_dn)],
            )
            .await;
            send_result(
                socket,
                message_id,
                ResponseOp::ModifyDn,
                map_backend_error(&err),
                &dn,
                diagnostic_for_error(&err),
            )
            .await?;
        }
    }

    Ok(())
}

pub async fn handle_compare_request(
    socket: &mut (impl AsyncWrite + Unpin),
    backend: &dyn DirectoryBackend,
    message_id: u32,
    request: CompareRequest<'_>,
) -> Result<(), ServerError> {
    let session = ConnectionSession::default();
    let request_controls = RequestControls::default();
    handle_compare_request_with_context(
        socket,
        backend,
        message_id,
        request,
        &session,
        &RequestContext::default(),
        &request_controls,
    )
    .await
}

async fn handle_compare_request_with_context(
    socket: &mut (impl AsyncWrite + Unpin),
    backend: &dyn DirectoryBackend,
    message_id: u32,
    request: CompareRequest<'_>,
    session: &ConnectionSession,
    request_context: &RequestContext,
    _request_controls: &RequestControls,
) -> Result<(), ServerError> {
    let dn = request.entry.0.as_ref().trim().to_owned();
    let attribute = request.ava.attribute_desc.0.as_ref().trim().to_owned();
    let assertion = bytes_to_string(request.ava.assertion_value);

    if !authorize_operation(
        socket,
        Some(backend),
        message_id,
        ResponseOp::Compare,
        session,
        request_context,
        Permission::Compare,
        "compare",
        &dn,
        Some(&attribute),
    )
    .await?
    {
        return Ok(());
    }

    match backend.compare_attribute(&dn, &attribute, &assertion).await {
        Ok(true) => {
            log_compare_audit(
                request_context,
                session,
                &dn,
                &attribute,
                true,
                "true",
                None,
            )
            .await;
            send_result(
                socket,
                message_id,
                ResponseOp::Compare,
                ResultCode::CompareTrue,
                &dn,
                "",
            )
            .await?;
        }
        Ok(false) => {
            log_compare_audit(
                request_context,
                session,
                &dn,
                &attribute,
                true,
                "false",
                None,
            )
            .await;
            send_result(
                socket,
                message_id,
                ResponseOp::Compare,
                ResultCode::CompareFalse,
                &dn,
                "",
            )
            .await?;
        }
        Err(err) => {
            error!("Compare operation failed for {}: {}", dn, err);
            log_compare_audit(
                request_context,
                session,
                &dn,
                &attribute,
                false,
                "error",
                Some(diagnostic_for_error(&err)),
            )
            .await;
            send_result(
                socket,
                message_id,
                ResponseOp::Compare,
                map_backend_error(&err),
                &dn,
                diagnostic_for_error(&err),
            )
            .await?;
        }
    }

    Ok(())
}

async fn handle_abandon_request(
    request_id: ldap_parser::ldap::MessageID,
    operation_registry: &mut ConnectionOperationRegistry,
    session: &ConnectionSession,
    request_context: &RequestContext,
) {
    info!("Received abandon request for message {}", request_id.0);
    let abandoned = operation_registry.request_abandon(request_id.0);
    if let Some(metrics) = request_context.metrics.as_ref() {
        metrics.increment_counter("ldap_abandon_requests_total", 1);
        if abandoned {
            metrics.increment_counter("ldap_abandon_accepted_total", 1);
        }
    }
    log_generic_audit_event(
        request_context,
        session,
        AuditLevel::Info,
        AuditEventType::System,
        "abandon",
        abandoned,
        None,
        if abandoned {
            None
        } else {
            Some("target operation was not active or not cancellable")
        },
        vec![("target_message_id".to_string(), request_id.0.to_string())],
    )
    .await;
}

pub async fn handle_extended_request(
    socket: &mut ConnectionStream,
    message_id: u32,
    request: ExtendedRequest<'_>,
) -> Result<(), ServerError> {
    let backend = crate::backend::MockBackend::default();
    let mut session = ConnectionSession::default();
    let request_controls = RequestControls::default();
    let mut operation_registry = ConnectionOperationRegistry::default();
    handle_extended_request_with_session_and_registry(
        socket,
        &backend,
        message_id,
        request,
        &mut session,
        &mut operation_registry,
        None,
        &RequestContext::default(),
        &request_controls,
    )
    .await
}

#[cfg_attr(not(test), allow(dead_code))]
async fn handle_extended_request_with_session(
    socket: &mut ConnectionStream,
    backend: &dyn DirectoryBackend,
    message_id: u32,
    request: ExtendedRequest<'_>,
    session: &mut ConnectionSession,
    tls_handler: Option<&RustlsTlsHandler>,
    request_context: &RequestContext,
    request_controls: &RequestControls,
) -> Result<(), ServerError> {
    let mut operation_registry = ConnectionOperationRegistry::default();
    handle_extended_request_with_session_and_registry(
        socket,
        backend,
        message_id,
        request,
        session,
        &mut operation_registry,
        tls_handler,
        request_context,
        request_controls,
    )
    .await
}

async fn handle_extended_request_with_session_and_registry(
    socket: &mut ConnectionStream,
    backend: &dyn DirectoryBackend,
    message_id: u32,
    request: ExtendedRequest<'_>,
    session: &mut ConnectionSession,
    operation_registry: &mut ConnectionOperationRegistry,
    tls_handler: Option<&RustlsTlsHandler>,
    request_context: &RequestContext,
    _request_controls: &RequestControls,
) -> Result<(), ServerError> {
    let oid = request.request_name.0.as_ref();

    if oid == START_TLS_OID {
        if socket.is_secure() {
            log_generic_audit_event(
                request_context,
                session,
                AuditLevel::Warning,
                AuditEventType::System,
                "starttls",
                false,
                None,
                Some("connection already uses TLS"),
                Vec::new(),
            )
            .await;
            return send_result(
                socket,
                message_id,
                ResponseOp::Extended,
                ResultCode::OperationsError,
                "",
                "connection already uses TLS",
            )
            .await;
        }

        let Some(tls_handler) = tls_handler else {
            log_generic_audit_event(
                request_context,
                session,
                AuditLevel::Warning,
                AuditEventType::System,
                "starttls",
                false,
                None,
                Some("StartTLS is not available"),
                Vec::new(),
            )
            .await;
            return send_result(
                socket,
                message_id,
                ResponseOp::Extended,
                ResultCode::Unavailable,
                "",
                "StartTLS is not available",
            )
            .await;
        };

        send_result(
            socket,
            message_id,
            ResponseOp::Extended,
            ResultCode::Success,
            "",
            "",
        )
        .await?;
        socket.upgrade_in_place(tls_handler).await?;
        session.clear();
        log_generic_audit_event(
            request_context,
            session,
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

    if oid == WHO_AM_I_OID {
        let target_dn = session.bound_dn().unwrap_or("");
        if !authorize_operation(
            socket,
            None,
            message_id,
            ResponseOp::Extended,
            session,
            request_context,
            Permission::Read,
            "whoami",
            target_dn,
            None,
        )
        .await?
        {
            return Ok(());
        }

        let authz_id = session
            .bound_dn()
            .map(|dn| format!("dn:{}", dn))
            .unwrap_or_default();
        send_extended_response(
            socket,
            message_id,
            ResultCode::Success,
            "",
            "",
            Some(WHO_AM_I_OID.to_string()),
            Some(authz_id.into_bytes()),
        )
        .await?;
        log_generic_audit_event(
            request_context,
            session,
            AuditLevel::Info,
            AuditEventType::System,
            "whoami",
            true,
            if target_dn.is_empty() {
                None
            } else {
                Some(target_dn)
            },
            None,
            Vec::new(),
        )
        .await;
        return Ok(());
    }

    if oid == CANCEL_OID {
        let cancel_id = match parse_cancel_request_value(request.request_value.as_deref()) {
            Ok(cancel_id) => cancel_id as u32,
            Err(err) => {
                increment_control_counter(request_context, "ldap_cancel_requests_total", 1);
                log_generic_audit_event(
                    request_context,
                    session,
                    AuditLevel::Warning,
                    AuditEventType::System,
                    "cancel",
                    false,
                    None,
                    Some("Malformed Cancel request"),
                    vec![("result".to_string(), "protocol_error".to_string())],
                )
                .await;
                return send_custom_extended_response(
                    socket,
                    message_id,
                    CustomResultCode::ProtocolError,
                    err.to_string(),
                )
                .await;
            }
        };

        increment_control_counter(request_context, "ldap_cancel_requests_total", 1);
        let (result_code, diagnostic, success, result_name) =
            match operation_registry.request_cancel(cancel_id) {
                CancelRequestOutcome::Accepted => {
                    (CustomResultCode::Success, String::new(), true, "success")
                }
                CancelRequestOutcome::NoSuchOperation => (
                    CustomResultCode::NoSuchOperation,
                    "no such operation".to_string(),
                    false,
                    "no_such_operation",
                ),
                CancelRequestOutcome::TooLate => (
                    CustomResultCode::TooLate,
                    "too late to cancel operation".to_string(),
                    false,
                    "too_late",
                ),
                CancelRequestOutcome::CannotCancel => (
                    CustomResultCode::CannotCancel,
                    "operation cannot be canceled".to_string(),
                    false,
                    "cannot_cancel",
                ),
            };
        if success {
            increment_control_counter(request_context, "ldap_cancel_accepted_total", 1);
        }
        log_generic_audit_event(
            request_context,
            session,
            if success {
                AuditLevel::Info
            } else {
                AuditLevel::Warning
            },
            AuditEventType::System,
            "cancel",
            success,
            None,
            if diagnostic.is_empty() {
                None
            } else {
                Some(diagnostic.as_str())
            },
            vec![
                ("target_message_id".to_string(), cancel_id.to_string()),
                ("result".to_string(), result_name.to_string()),
            ],
        )
        .await;
        return send_custom_extended_response(socket, message_id, result_code, diagnostic).await;
    }

    if oid == PASSWORD_MODIFY_OID {
        if !socket.is_secure() {
            log_password_modify_audit_event(
                request_context,
                session,
                session.bound_dn(),
                "unknown",
                false,
                false,
                Some("Password Modify requires confidentiality protection"),
            )
            .await;
            return send_result(
                socket,
                message_id,
                ResponseOp::Extended,
                ResultCode::ConfidentialityRequired,
                "",
                "Password Modify requires confidentiality protection",
            )
            .await;
        }

        let Some(bound_dn) = session.bound_dn() else {
            log_password_modify_audit_event(
                request_context,
                session,
                None,
                "unknown",
                false,
                false,
                Some("Password Modify requires an authenticated session"),
            )
            .await;
            return send_result(
                socket,
                message_id,
                ResponseOp::Extended,
                ResultCode::UnwillingToPerform,
                "",
                "Password Modify requires an authenticated session",
            )
            .await;
        };

        let request_value =
            match parse_password_modify_request_value(request.request_value.as_deref()) {
                Ok(request_value) => request_value,
                Err(err) => {
                    log_password_modify_audit_event(
                        request_context,
                        session,
                        session.bound_dn(),
                        "unknown",
                        false,
                        false,
                        Some("Malformed Password Modify request"),
                    )
                    .await;
                    return send_result(
                        socket,
                        message_id,
                        ResponseOp::Extended,
                        ResultCode::ProtocolError,
                        "",
                        &err.to_string(),
                    )
                    .await;
                }
            };

        let target_dn = request_value
            .user_identity
            .clone()
            .unwrap_or_else(|| bound_dn.to_string());
        let is_self_service = bound_dn.eq_ignore_ascii_case(&target_dn);
        let mode = if is_self_service {
            "self_service"
        } else {
            "admin_reset"
        };

        if is_self_service {
            if !is_root_dn(session, request_context) {
                let Some(old_password) = request_value.old_password.as_deref() else {
                    log_password_modify_audit_event(
                        request_context,
                        session,
                        Some(&target_dn),
                        mode,
                        false,
                        false,
                        Some("Self-service password changes require oldPasswd"),
                    )
                    .await;
                    return send_result(
                        socket,
                        message_id,
                        ResponseOp::Extended,
                        ResultCode::UnwillingToPerform,
                        "",
                        "Self-service password changes require oldPasswd",
                    )
                    .await;
                };

                match backend.authenticate(&target_dn, old_password).await {
                    Ok(true) => {}
                    Ok(false) => {
                        log_password_modify_audit_event(
                            request_context,
                            session,
                            Some(&target_dn),
                            mode,
                            false,
                            false,
                            Some("invalid credentials"),
                        )
                        .await;
                        return send_result(
                            socket,
                            message_id,
                            ResponseOp::Extended,
                            ResultCode::InvalidCredentials,
                            "",
                            "invalid credentials",
                        )
                        .await;
                    }
                    Err(err) => {
                        log_password_modify_audit_event(
                            request_context,
                            session,
                            Some(&target_dn),
                            mode,
                            false,
                            false,
                            Some(diagnostic_for_error(&err)),
                        )
                        .await;
                        return send_result(
                            socket,
                            message_id,
                            ResponseOp::Extended,
                            map_backend_error(&err),
                            "",
                            diagnostic_for_error(&err),
                        )
                        .await;
                    }
                }
            }
        } else if !is_root_dn(session, request_context) {
            let has_access_control = request_context
                .security
                .as_ref()
                .and_then(|security| security.access_control.as_ref())
                .is_some();
            if !has_access_control {
                log_password_modify_audit_event(
                    request_context,
                    session,
                    Some(&target_dn),
                    mode,
                    false,
                    false,
                    Some("Password resets require root or explicit write authorization"),
                )
                .await;
                return send_result(
                    socket,
                    message_id,
                    ResponseOp::Extended,
                    ResultCode::InsufficientAccessRights,
                    "",
                    "Password resets require root or explicit write authorization",
                )
                .await;
            }

            if !authorize_operation(
                socket,
                Some(backend),
                message_id,
                ResponseOp::Extended,
                session,
                request_context,
                Permission::Modify,
                "password_modify",
                &target_dn,
                Some("userPassword"),
            )
            .await?
            {
                return Ok(());
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
                log_password_modify_audit_event(
                    request_context,
                    session,
                    Some(&target_dn),
                    mode,
                    generated_password,
                    false,
                    Some("newPasswd must be valid UTF-8"),
                )
                .await;
                return send_result(
                    socket,
                    message_id,
                    ResponseOp::Extended,
                    ResultCode::ProtocolError,
                    "",
                    "newPasswd must be valid UTF-8",
                )
                .await;
            }
        };

        match backend
            .modify_entry_with_actor(
                &target_dn,
                vec![Modification {
                    operation: ModifyOperation::Replace,
                    attribute: "userPassword".to_string(),
                    values: vec![new_password_string],
                }],
                session.bound_dn().map(str::to_string),
            )
            .await
        {
            Ok(()) => {}
            Err(err) => {
                log_password_modify_audit_event(
                    request_context,
                    session,
                    Some(&target_dn),
                    mode,
                    generated_password,
                    false,
                    Some(diagnostic_for_error(&err)),
                )
                .await;
                return send_result(
                    socket,
                    message_id,
                    ResponseOp::Extended,
                    map_backend_error(&err),
                    "",
                    diagnostic_for_error(&err),
                )
                .await;
            }
        }

        let response_value = match encode_password_modify_response_value(
            generated_password.then_some(new_password.as_slice()),
        ) {
            Ok(response_value) => response_value,
            Err(err) => {
                error!("failed to encode password modify response: {err}");
                log_password_modify_audit_event(
                    request_context,
                    session,
                    Some(&target_dn),
                    mode,
                    generated_password,
                    false,
                    Some("Failed to encode Password Modify response"),
                )
                .await;
                return send_result(
                    socket,
                    message_id,
                    ResponseOp::Extended,
                    ResultCode::OperationsError,
                    "",
                    "Failed to encode Password Modify response",
                )
                .await;
            }
        };

        send_extended_response(
            socket,
            message_id,
            ResultCode::Success,
            "",
            "",
            None,
            response_value,
        )
        .await?;
        log_password_modify_audit_event(
            request_context,
            session,
            Some(&target_dn),
            mode,
            generated_password,
            true,
            None,
        )
        .await;
        return Ok(());
    }

    warn!("Unsupported extended operation requested: {}", oid);
    log_generic_audit_event(
        request_context,
        session,
        AuditLevel::Warning,
        AuditEventType::System,
        format!("extended:{}", oid),
        false,
        session.bound_dn(),
        Some("extended operations are not supported"),
        Vec::new(),
    )
    .await;

    send_result(
        socket,
        message_id,
        ResponseOp::Extended,
        ResultCode::ProtocolError,
        "",
        "extended operations are not supported",
    )
    .await
}

fn select_attributes(entry: &DirectoryEntry, requested: &[String]) -> Vec<(String, Vec<String>)> {
    if requested
        .iter()
        .any(|attribute| attribute.eq_ignore_ascii_case("1.1"))
    {
        return Vec::new();
    }

    let include_all = requested.is_empty() || requested.iter().any(|attr| attr == "*");
    let include_all_operational = requested.iter().any(|attr| attr == "+");

    let mut selected = Vec::new();

    // Add regular attributes
    for (name, values) in &entry.attributes {
        if include_all
            || requested
                .iter()
                .any(|attribute| attribute.eq_ignore_ascii_case(name))
        {
            selected.push((name.clone(), values.clone()));
        }
    }

    // Add operational attributes if requested
    // Check for "+" (all operational) or specific operational attribute names
    if include_all_operational
        || requested.iter().any(|attr| {
            attr.eq_ignore_ascii_case("entrycsn")
                || attr.eq_ignore_ascii_case("createtimestamp")
                || attr.eq_ignore_ascii_case("modifytimestamp")
                || attr.eq_ignore_ascii_case("creatorsname")
                || attr.eq_ignore_ascii_case("modifiersname")
        })
    {
        let op_attrs = &entry.operational_attributes;

        // entryCSN
        if include_all_operational || requested.iter().any(|a| a.eq_ignore_ascii_case("entrycsn")) {
            if let Some(entry_csn) = op_attrs.entry_csn.as_ref() {
                selected.push(("entryCSN".to_string(), vec![entry_csn.to_ldap_string()]));
            }
        }

        // createTimestamp
        if (include_all_operational
            || requested
                .iter()
                .any(|a| a.eq_ignore_ascii_case("createtimestamp")))
            && op_attrs.create_timestamp.is_some()
        {
            selected.push((
                "createTimestamp".to_string(),
                vec![op_attrs.create_timestamp.clone().unwrap()],
            ));
        }

        // modifyTimestamp
        if (include_all_operational
            || requested
                .iter()
                .any(|a| a.eq_ignore_ascii_case("modifytimestamp")))
            && op_attrs.modify_timestamp.is_some()
        {
            selected.push((
                "modifyTimestamp".to_string(),
                vec![op_attrs.modify_timestamp.clone().unwrap()],
            ));
        }

        // creatorsName
        if (include_all_operational
            || requested
                .iter()
                .any(|a| a.eq_ignore_ascii_case("creatorsname")))
            && op_attrs.creators_name.is_some()
        {
            selected.push((
                "creatorsName".to_string(),
                vec![op_attrs.creators_name.clone().unwrap()],
            ));
        }

        // modifiersName
        if (include_all_operational
            || requested
                .iter()
                .any(|a| a.eq_ignore_ascii_case("modifiersname")))
            && op_attrs.modifiers_name.is_some()
        {
            selected.push((
                "modifiersName".to_string(),
                vec![op_attrs.modifiers_name.clone().unwrap()],
            ));
        }
    }

    selected
}

fn entry_matches_filter(entry: &DirectoryEntry, filter: &Filter<'_>) -> bool {
    crate::ldap_filter_eval::matches_search_filter(entry, filter)
}

fn convert_modifications(changes: Vec<Change<'_>>) -> Vec<Modification> {
    changes
        .into_iter()
        .map(|change| {
            let operation = match change.operation.0 {
                0 => ModifyOperation::Add,
                1 => ModifyOperation::Delete,
                2 => ModifyOperation::Replace,
                _ => ModifyOperation::Replace,
            };

            let attribute = change.modification.attr_type.0.to_lowercase();

            let values = change
                .modification
                .attr_vals
                .iter()
                .map(|value| bytes_to_string(value.0.as_ref()))
                .collect();

            Modification {
                operation,
                attribute,
                values,
            }
        })
        .collect()
}

fn build_entry_from_add_request(
    dn: &str,
    attributes: Vec<ldap_parser::filter::Attribute<'_>>,
) -> (DirectoryEntry, Vec<u8>) {
    let mut attribute_map: HashMap<String, Vec<String>> = HashMap::new();
    let mut password = Vec::new();

    for attribute in attributes {
        let name = attribute.attr_type.0.to_ascii_lowercase();
        let values: Vec<String> = attribute
            .attr_vals
            .iter()
            .map(|value| bytes_to_string(value.0.as_ref()))
            .collect();

        if name == "userpassword" {
            if let Some(first) = values.first() {
                password = first.as_bytes().to_vec();
            }
        }

        let entry_values = attribute_map.entry(name).or_default();
        for value in values {
            if !entry_values.contains(&value) {
                entry_values.push(value);
            }
        }
    }

    (DirectoryEntry::new(dn.to_owned(), attribute_map), password)
}

fn bytes_to_string(value: &[u8]) -> String {
    String::from_utf8_lossy(value).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aci::AciEngine;
    use crate::backend::MockBackend;
    use crate::config::ServerConfig;
    use crate::extended_ops::encode_cancel_request_value;
    use crate::ldap_controls::LdapControl;
    use crate::replication::REPLICATION_STREAM_ATTRIBUTE;
    use crate::replication_service::ReplicationService;
    use crate::schema::LdapSchema;
    use ldap_parser::filter::{
        Attribute as FilterAttribute, AttributeValue, AttributeValueAssertion, Filter,
        PartialAttribute, SubstringFilter,
    };
    use ldap_parser::ldap::LdapString;
    use ldap_parser::ldap::{
        AddRequest, AuthenticationChoice, BindRequest, CompareRequest, DerefAliases,
        ExtendedRequest, LdapDN, LdapOID, ModDnRequest, ModifyRequest, RelativeLdapDN,
        ResultCode as ParserResultCode, SaslCredentials, SearchRequest, SearchScope,
    };
    use ldap_parser::ldap::{Change, Operation};
    use rasn::der;
    use rasn_ldap::{
        AuthenticationChoice as RasnAuthChoice, BindRequest as RasnBindRequest,
        Control as RasnControl, ExtendedRequest as RasnExtendedRequest,
        LdapMessage as RasnLdapMessage, ProtocolOp as RasnProtocolOp,
    };
    use std::borrow::Cow;
    use std::sync::Arc;
    use tempfile::NamedTempFile;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::{timeout, Duration};

    async fn connected_stream_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (server_stream, _) = listener.accept().await.unwrap();
        let client_stream = client.await.unwrap();

        (server_stream, client_stream)
    }

    async fn read_response(stream: &mut TcpStream) -> Vec<u8> {
        let mut buf = vec![0u8; 4096];
        let len = timeout(Duration::from_millis(200), stream.read(&mut buf))
            .await
            .expect("response timeout")
            .expect("failed to read response");
        buf.truncate(len);

        loop {
            let mut chunk = vec![0u8; 4096];
            match timeout(Duration::from_millis(20), stream.read(&mut chunk)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(len)) => buf.extend_from_slice(&chunk[..len]),
                Ok(Err(err)) => panic!("failed to read response: {err}"),
                Err(_) => break,
            }
        }

        buf
    }

    fn rasn_control(oid: &str, criticality: bool, value: Option<&[u8]>) -> RasnControl {
        RasnControl::new(
            oid.as_bytes().to_vec().into(),
            criticality,
            value.map(|value| value.to_vec().into()),
        )
    }

    fn bind_request_with_controls(message_id: u32, controls: Vec<RasnControl>) -> Vec<u8> {
        let bind_request = RasnBindRequest::new(
            3,
            b"cn=admin,dc=example,dc=org".to_vec().into(),
            RasnAuthChoice::Simple(b"secret".to_vec().into()),
        );
        let mut message =
            RasnLdapMessage::new(message_id, RasnProtocolOp::BindRequest(bind_request));
        if !controls.is_empty() {
            message.controls = Some(controls.into_iter().collect());
        }
        der::encode(&message).unwrap()
    }

    fn cancel_extended_request(target_message_id: i32) -> ExtendedRequest<'static> {
        ExtendedRequest {
            request_name: LdapOID(Cow::Owned(CANCEL_OID.to_string())),
            request_value: Some(Cow::Owned(
                encode_cancel_request_value(target_message_id).unwrap(),
            )),
        }
    }

    fn cancel_request_message(message_id: u32, target_message_id: i32) -> Vec<u8> {
        let request = RasnExtendedRequest {
            request_name: CANCEL_OID.as_bytes().to_vec().into(),
            request_value: Some(
                encode_cancel_request_value(target_message_id)
                    .unwrap()
                    .into(),
            ),
        };
        let message = RasnLdapMessage::new(message_id, RasnProtocolOp::ExtendedReq(request));
        der::encode(&message).unwrap()
    }

    fn encode_ber_integer(value: u32) -> Vec<u8> {
        let mut bytes = value.to_be_bytes().to_vec();
        while bytes.len() > 1 && bytes[0] == 0 {
            bytes.remove(0);
        }
        if bytes[0] & 0x80 != 0 {
            bytes.insert(0, 0);
        }
        bytes
    }

    fn encode_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        assert!(
            value.len() < 128,
            "test helper only supports short-form BER lengths"
        );
        let mut encoded = Vec::with_capacity(value.len() + 2);
        encoded.push(tag);
        encoded.push(value.len() as u8);
        encoded.extend_from_slice(value);
        encoded
    }

    fn abandon_request_message(message_id: u32, target_message_id: u32) -> Vec<u8> {
        let message_id_tlv = encode_tlv(0x02, &encode_ber_integer(message_id));
        let abandon_tlv = encode_tlv(0x50, &encode_ber_integer(target_message_id));

        let mut payload = Vec::with_capacity(message_id_tlv.len() + abandon_tlv.len());
        payload.extend_from_slice(&message_id_tlv);
        payload.extend_from_slice(&abandon_tlv);
        encode_tlv(0x30, &payload)
    }

    #[test]
    fn parse_abandon_message_fallback_decodes_abandon_request() {
        let message = parse_abandon_message_fallback(&abandon_request_message(42, 41)).unwrap();
        assert_eq!(message.message_id.0, 42);
        match message.protocol_op {
            ProtocolOp::AbandonRequest(request_id) => assert_eq!(request_id.0, 41),
            other => panic!("unexpected fallback protocol op: {:?}", other),
        }
    }

    fn search_request_for_base(base_dn: &str, attributes: &[&str]) -> SearchRequest<'static> {
        SearchRequest {
            base_object: LdapDN(Cow::Owned(base_dn.to_string())),
            scope: SearchScope::BaseObject,
            deref_aliases: DerefAliases(0),
            size_limit: 0,
            time_limit: 0,
            types_only: false,
            filter: Filter::Present(LdapString(Cow::Owned("objectClass".to_string()))),
            attributes: attributes
                .iter()
                .map(|attribute| LdapString(Cow::Owned((*attribute).to_string())))
                .collect(),
        }
    }

    fn search_entry_attribute_map(
        entry: &ldap_parser::ldap::SearchResultEntry<'_>,
    ) -> HashMap<String, Vec<String>> {
        entry
            .attributes
            .iter()
            .map(|attribute| {
                (
                    attribute.attr_type.0.as_ref().to_string(),
                    attribute
                        .attr_vals
                        .iter()
                        .map(|value| bytes_to_string(value.0.as_ref()))
                        .collect::<Vec<_>>(),
                )
            })
            .collect()
    }

    fn replication_stream_request() -> SearchRequest<'static> {
        SearchRequest {
            base_object: LdapDN(Cow::Owned("dc=example,dc=org".to_string())),
            scope: SearchScope::BaseObject,
            deref_aliases: DerefAliases(0),
            size_limit: 0,
            time_limit: 0,
            types_only: false,
            filter: Filter::Present(LdapString(Cow::Owned("objectClass".to_string()))),
            attributes: vec![LdapString(Cow::Owned(
                REPLICATION_STREAM_ATTRIBUTE.to_string(),
            ))],
        }
    }

    #[test]
    fn convert_modifications_translates_operations_and_values() {
        let changes = vec![
            Change {
                operation: Operation(0),
                modification: PartialAttribute {
                    attr_type: LdapString(Cow::Owned("cn".to_string())),
                    attr_vals: vec![AttributeValue(Cow::Owned(b"Alice".to_vec()))],
                },
            },
            Change {
                operation: Operation(1),
                modification: PartialAttribute {
                    attr_type: LdapString(Cow::Owned("sn".to_string())),
                    attr_vals: vec![AttributeValue(Cow::Owned(b"Smith".to_vec()))],
                },
            },
            Change {
                operation: Operation(2),
                modification: PartialAttribute {
                    attr_type: LdapString(Cow::Owned("mail".to_string())),
                    attr_vals: vec![AttributeValue(Cow::Owned(b"alice@example.org".to_vec()))],
                },
            },
        ];

        let modifications = convert_modifications(changes);
        assert_eq!(modifications.len(), 3);
        assert_eq!(modifications[0].operation, ModifyOperation::Add);
        assert_eq!(modifications[0].attribute, "cn");
        assert_eq!(modifications[0].values, vec!["Alice".to_string()]);
        assert_eq!(modifications[1].operation, ModifyOperation::Delete);
        assert_eq!(modifications[1].attribute, "sn");
        assert_eq!(modifications[1].values, vec!["Smith".to_string()]);
        assert_eq!(modifications[2].operation, ModifyOperation::Replace);
        assert_eq!(modifications[2].attribute, "mail");
        assert_eq!(
            modifications[2].values,
            vec!["alice@example.org".to_string()]
        );
    }

    #[test]
    fn build_entry_from_add_request_collects_attributes_and_password() {
        let attributes = vec![
            FilterAttribute {
                attr_type: LdapString(Cow::Owned("cn".to_string())),
                attr_vals: vec![AttributeValue(Cow::Owned(b"Alice".to_vec()))],
            },
            FilterAttribute {
                attr_type: LdapString(Cow::Owned("userPassword".to_string())),
                attr_vals: vec![AttributeValue(Cow::Owned(b"secret".to_vec()))],
            },
        ];

        let (entry, password) =
            build_entry_from_add_request("cn=Alice,dc=example,dc=org", attributes);

        assert_eq!(entry.dn, "cn=Alice,dc=example,dc=org");
        assert_eq!(
            entry.attributes.get("cn").unwrap(),
            &vec!["Alice".to_string()]
        );
        assert_eq!(
            entry.attributes.get("userpassword").unwrap(),
            &vec!["secret".to_string()]
        );
        assert_eq!(password, b"secret".to_vec());
    }

    #[test]
    fn entry_matches_filter_handles_basic_conditions() {
        let mut attributes = HashMap::new();
        attributes.insert("cn".to_string(), vec!["Alice".to_string()]);
        attributes.insert("sn".to_string(), vec!["Smith".to_string()]);
        let entry = DirectoryEntry::new("cn=Alice,dc=example,dc=org", attributes);

        let equality_filter = Filter::EqualityMatch(AttributeValueAssertion {
            attribute_desc: LdapString(Cow::Owned("cn".to_string())),
            assertion_value: b"Alice",
        });
        assert!(entry_matches_filter(&entry, &equality_filter));

        let present_filter = Filter::Present(LdapString(Cow::Owned("sn".to_string())));
        assert!(entry_matches_filter(&entry, &present_filter));

        let missing_filter = Filter::Present(LdapString(Cow::Owned("mail".to_string())));
        assert!(!entry_matches_filter(&entry, &missing_filter));
    }

    #[test]
    fn extract_search_hint_prefers_indexable_terms() {
        let equality_filter = Filter::EqualityMatch(AttributeValueAssertion {
            attribute_desc: LdapString(Cow::Owned("uid".to_string())),
            assertion_value: b"alice",
        });
        assert_eq!(
            extract_search_hint(&equality_filter),
            Some(SearchCandidateHint::Equality {
                attribute: "uid".to_string(),
                value: "alice".to_string(),
            })
        );

        let and_filter = Filter::And(vec![
            Filter::Substrings(SubstringFilter {
                filter_type: LdapString(Cow::Owned("cn".to_string())),
                substrings: vec![],
            }),
            Filter::Present(LdapString(Cow::Owned("mail".to_string()))),
        ]);
        assert_eq!(
            extract_search_hint(&and_filter),
            Some(SearchCandidateHint::Present {
                attribute: "mail".to_string(),
            })
        );

        let unsupported = Filter::Or(vec![Filter::Not(Box::new(Filter::Present(LdapString(
            Cow::Owned("cn".to_string()),
        ))))]);
        assert_eq!(extract_search_hint(&unsupported), None);
    }

    #[tokio::test]
    async fn successful_bind_updates_connection_session() {
        let backend = MockBackend::from_credentials([(
            String::from("cn=admin,dc=example,dc=org"),
            b"secret".to_vec(),
        )]);
        let mut session = ConnectionSession::default();
        let request = BindRequest {
            version: 3,
            name: LdapDN(Cow::Owned("cn=admin,dc=example,dc=org".to_string())),
            authentication: AuthenticationChoice::Simple(Cow::Owned(b"secret".to_vec())),
        };

        let (mut server_stream, mut client_stream) = connected_stream_pair().await;
        let request_controls = RequestControls::default();

        handle_bind_request_with_session_and_context(
            &mut server_stream,
            &backend,
            1,
            request,
            &mut session,
            &RequestContext::default(),
            false,
            &request_controls,
        )
        .await
        .unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(session.bound_dn(), Some("cn=admin,dc=example,dc=org"));
        match &messages[0].protocol_op {
            ProtocolOp::BindResponse(bind_response) => {
                assert_eq!(bind_response.result.result_code, ParserResultCode::Success);
            }
            other => panic!("unexpected response: {:?}", other),
        }
    }

    #[tokio::test]
    async fn sasl_plain_bind_requires_secure_transport() {
        let backend = MockBackend::from_credentials([(
            String::from("cn=admin,dc=example,dc=org"),
            b"secret".to_vec(),
        )]);
        let mut session = ConnectionSession::default();
        let request = BindRequest {
            version: 3,
            name: LdapDN(Cow::Owned("cn=admin,dc=example,dc=org".to_string())),
            authentication: AuthenticationChoice::Sasl(SaslCredentials {
                mechanism: LdapString(Cow::Owned("PLAIN".to_string())),
                credentials: Some(Cow::Owned(b"\0cn=admin,dc=example,dc=org\0secret".to_vec())),
            }),
        };

        let (mut server_stream, mut client_stream) = connected_stream_pair().await;
        let request_controls = RequestControls::default();

        handle_bind_request_with_session_and_context(
            &mut server_stream,
            &backend,
            2,
            request,
            &mut session,
            &RequestContext::default(),
            false,
            &request_controls,
        )
        .await
        .unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(session.bound_dn(), None);
        match &messages[0].protocol_op {
            ProtocolOp::BindResponse(bind_response) => {
                assert_eq!(
                    bind_response.result.result_code,
                    ParserResultCode::ConfidentialityRequired
                );
            }
            other => panic!("unexpected response: {:?}", other),
        }
    }

    #[tokio::test]
    async fn sasl_plain_bind_success_logs_audit_event() {
        let backend = MockBackend::from_credentials([(
            String::from("cn=admin,dc=example,dc=org"),
            b"secret".to_vec(),
        )]);
        let temp_file = NamedTempFile::new().unwrap();
        let audit_logger = AuditLogger::new(temp_file.path(), AuditLevel::Debug);
        audit_logger.initialize().await.unwrap();
        let request_context = RequestContext {
            client_ip: Some("127.0.0.1".parse().unwrap()),
            session_id: Some(55),
            security: Some(Arc::new(LegacySecurityConfig {
                audit_logger: Some(audit_logger.clone()),
                audit_config: LegacyAuditConfig::default(),
                access_control: None,
                root_dn: Some("cn=admin,dc=example,dc=org".to_string()),
            })),
            metrics: None,
        };

        let mut session = ConnectionSession::default();
        let request = BindRequest {
            version: 3,
            name: LdapDN(Cow::Owned("cn=admin,dc=example,dc=org".to_string())),
            authentication: AuthenticationChoice::Sasl(SaslCredentials {
                mechanism: LdapString(Cow::Owned("PLAIN".to_string())),
                credentials: Some(Cow::Owned(b"\0cn=admin,dc=example,dc=org\0secret".to_vec())),
            }),
        };

        let (mut server_stream, mut client_stream) = connected_stream_pair().await;
        let request_controls = RequestControls::default();
        handle_bind_request_with_session_and_context(
            &mut server_stream,
            &backend,
            3,
            request,
            &mut session,
            &request_context,
            true,
            &request_controls,
        )
        .await
        .unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();
        let log_content = tokio::fs::read_to_string(temp_file.path()).await.unwrap();

        assert_eq!(session.bound_dn(), Some("cn=admin,dc=example,dc=org"));
        assert!(log_content.contains("sasl_bind"));
        assert!(log_content.contains("PLAIN"));
        match &messages[0].protocol_op {
            ProtocolOp::BindResponse(bind_response) => {
                assert_eq!(bind_response.result.result_code, ParserResultCode::Success);
            }
            other => panic!("unexpected response: {:?}", other),
        }
    }

    #[tokio::test]
    async fn compare_denial_returns_insufficient_access_and_audits_denial() {
        let backend = MockBackend::new();
        let temp_file = NamedTempFile::new().unwrap();
        let audit_logger = AuditLogger::new(temp_file.path(), AuditLevel::Debug);
        audit_logger.initialize().await.unwrap();
        let request_context = RequestContext {
            client_ip: Some("127.0.0.1".parse().unwrap()),
            session_id: Some(77),
            security: Some(Arc::new(LegacySecurityConfig {
                audit_logger: Some(audit_logger.clone()),
                audit_config: LegacyAuditConfig::default(),
                access_control: Some(Arc::new(AciEngine::restrictive())),
                root_dn: Some("cn=admin,dc=example,dc=org".to_string()),
            })),
            metrics: None,
        };
        let mut session = ConnectionSession::default();
        session.bind("cn=user,dc=example,dc=org".to_string());
        let request_controls = RequestControls::default();

        let request = CompareRequest {
            entry: LdapDN(Cow::Owned("cn=target,dc=example,dc=org".to_string())),
            ava: AttributeValueAssertion {
                attribute_desc: LdapString(Cow::Owned("cn".to_string())),
                assertion_value: b"target",
            },
        };

        let (mut server_stream, mut client_stream) = connected_stream_pair().await;
        handle_compare_request_with_context(
            &mut server_stream,
            &backend,
            4,
            request,
            &session,
            &request_context,
            &request_controls,
        )
        .await
        .unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();
        let log_content = tokio::fs::read_to_string(temp_file.path()).await.unwrap();

        assert!(log_content.contains("authz_compare"));
        assert!(log_content.contains("Access denied"));
        match &messages[0].protocol_op {
            ProtocolOp::CompareResponse(compare_response) => {
                assert_eq!(
                    compare_response.result_code,
                    ParserResultCode::InsufficientAccessRights
                );
            }
            other => panic!("unexpected response: {:?}", other),
        }
    }

    #[tokio::test]
    async fn whoami_extended_request_returns_bound_dn() {
        let request = ExtendedRequest {
            request_name: LdapOID(Cow::Owned("1.3.6.1.4.1.4203.1.11.3".to_string())),
            request_value: None,
        };
        let (server_stream, mut client_stream) = connected_stream_pair().await;
        let mut server_stream = ConnectionStream::Plain(server_stream);
        let backend = MockBackend::default();
        let mut session = ConnectionSession::default();
        session.bind("cn=admin,dc=example,dc=org".to_string());
        let request_controls = RequestControls::default();

        handle_extended_request_with_session(
            &mut server_stream,
            &backend,
            5,
            request,
            &mut session,
            None,
            &RequestContext::default(),
            &request_controls,
        )
        .await
        .unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        match &messages[0].protocol_op {
            ProtocolOp::ExtendedResponse(extended_response) => {
                assert_eq!(
                    extended_response.result.result_code,
                    ParserResultCode::Success
                );
                assert_eq!(
                    extended_response
                        .response_name
                        .as_ref()
                        .map(|oid| oid.0.as_ref()),
                    Some("1.3.6.1.4.1.4203.1.11.3")
                );
                assert_eq!(
                    extended_response
                        .response_value
                        .as_ref()
                        .map(|value| value.as_ref()),
                    Some(b"dn:cn=admin,dc=example,dc=org".as_ref())
                );
            }
            other => panic!("unexpected response: {:?}", other),
        }
    }

    #[test]
    fn connection_operation_registry_reports_cancel_lifecycle() {
        let mut registry = ConnectionOperationRegistry::default();

        assert_eq!(
            registry.request_cancel(7),
            CancelRequestOutcome::NoSuchOperation
        );

        registry.register(7, ConnectionOperationKind::Search, true);
        assert_eq!(registry.request_cancel(7), CancelRequestOutcome::Accepted);
        assert_eq!(
            registry.request_cancel(7),
            CancelRequestOutcome::CannotCancel
        );

        registry.finish(7, FinishedOperationState::Completed);
        assert_eq!(registry.request_cancel(7), CancelRequestOutcome::TooLate);

        registry.register(8, ConnectionOperationKind::Search, false);
        assert_eq!(
            registry.request_cancel(8),
            CancelRequestOutcome::CannotCancel
        );

        registry.register(9, ConnectionOperationKind::ReplicationStream, true);
        assert!(registry.request_abandon(9));
        assert!(!registry.request_abandon(9));
    }

    #[tokio::test]
    async fn cancel_extended_request_reports_no_such_operation() {
        let (server_stream, mut client_stream) = connected_stream_pair().await;
        let mut server_stream = ConnectionStream::Plain(server_stream);
        let backend = MockBackend::default();
        let mut session = ConnectionSession::default();
        let request_controls = RequestControls::default();
        let mut operation_registry = ConnectionOperationRegistry::default();

        handle_extended_request_with_session_and_registry(
            &mut server_stream,
            &backend,
            21,
            cancel_extended_request(404),
            &mut session,
            &mut operation_registry,
            None,
            &RequestContext::default(),
            &request_controls,
        )
        .await
        .unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 1);
        match &messages[0].protocol_op {
            ProtocolOp::ExtendedResponse(extended_response) => {
                assert_eq!(messages[0].message_id.0, 21);
                assert_eq!(extended_response.result.result_code.0, 119);
                assert_eq!(
                    extended_response.result.diagnostic_message.0.as_ref(),
                    "no such operation"
                );
            }
            other => panic!("unexpected response: {:?}", other),
        }
    }

    #[tokio::test]
    async fn cancel_extended_request_reports_too_late_for_completed_operation() {
        let (server_stream, mut client_stream) = connected_stream_pair().await;
        let mut server_stream = ConnectionStream::Plain(server_stream);
        let backend = MockBackend::default();
        let mut session = ConnectionSession::default();
        let request_controls = RequestControls::default();
        let mut operation_registry = ConnectionOperationRegistry::default();
        operation_registry.finish(15, FinishedOperationState::Completed);

        handle_extended_request_with_session_and_registry(
            &mut server_stream,
            &backend,
            22,
            cancel_extended_request(15),
            &mut session,
            &mut operation_registry,
            None,
            &RequestContext::default(),
            &request_controls,
        )
        .await
        .unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 1);
        match &messages[0].protocol_op {
            ProtocolOp::ExtendedResponse(extended_response) => {
                assert_eq!(messages[0].message_id.0, 22);
                assert_eq!(extended_response.result.result_code.0, 120);
                assert_eq!(
                    extended_response.result.diagnostic_message.0.as_ref(),
                    "too late to cancel operation"
                );
            }
            other => panic!("unexpected response: {:?}", other),
        }
    }

    #[tokio::test]
    async fn unauthenticated_mutation_is_rejected() {
        let session = ConnectionSession::default();
        let (mut server_stream, mut client_stream) = connected_stream_pair().await;

        let allowed = ensure_authenticated_for_mutation(
            &mut server_stream,
            7,
            &session,
            ResponseOp::Add,
            "cn=Alice,dc=example,dc=org",
        )
        .await
        .unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert!(!allowed);
        assert_eq!(messages.len(), 1);
        match &messages[0].protocol_op {
            ProtocolOp::AddResponse(add_response) => {
                assert_eq!(
                    add_response.result_code,
                    ParserResultCode::InsufficientAccessRights
                );
            }
            other => panic!("unexpected response: {:?}", other),
        }
    }

    #[tokio::test]
    async fn authenticated_add_uses_bound_dn_for_operational_attrs() {
        let backend = MockBackend::new();
        let mut session = ConnectionSession::default();
        session.bind("cn=admin,dc=example,dc=org".to_string());
        let schema = LdapSchema::default();
        let request = AddRequest {
            entry: LdapDN(Cow::Owned("cn=Alice,dc=example,dc=org".to_string())),
            attributes: vec![
                FilterAttribute {
                    attr_type: LdapString(Cow::Owned("objectClass".to_string())),
                    attr_vals: vec![AttributeValue(Cow::Owned(b"person".to_vec()))],
                },
                FilterAttribute {
                    attr_type: LdapString(Cow::Owned("cn".to_string())),
                    attr_vals: vec![AttributeValue(Cow::Owned(b"Alice".to_vec()))],
                },
                FilterAttribute {
                    attr_type: LdapString(Cow::Owned("sn".to_string())),
                    attr_vals: vec![AttributeValue(Cow::Owned(b"User".to_vec()))],
                },
            ],
        };

        let (mut server_stream, mut client_stream) = connected_stream_pair().await;
        let request_controls = RequestControls::default();
        handle_add_request_with_context(
            &mut server_stream,
            &backend,
            &schema,
            8,
            request,
            &session,
            &RequestContext::default(),
            &request_controls,
        )
        .await
        .unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();
        match &messages[0].protocol_op {
            ProtocolOp::AddResponse(add_response) => {
                assert_eq!(add_response.result_code, ParserResultCode::Success);
            }
            other => panic!("unexpected response: {:?}", other),
        }

        let stored = backend
            .get_entry("cn=Alice,dc=example,dc=org")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.operational_attributes.creators_name.as_deref(),
            Some("cn=admin,dc=example,dc=org")
        );
        assert_eq!(
            stored.operational_attributes.modifiers_name.as_deref(),
            Some("cn=admin,dc=example,dc=org")
        );
    }

    #[tokio::test]
    async fn authenticated_modify_uses_bound_dn_for_operational_attrs() {
        let backend = MockBackend::new();
        backend
            .add_entry_with_actor(
                DirectoryEntry::new(
                    "cn=Alice,dc=example,dc=org",
                    HashMap::from([
                        ("cn".to_string(), vec!["Alice".to_string()]),
                        ("sn".to_string(), vec!["User".to_string()]),
                        ("objectclass".to_string(), vec!["person".to_string()]),
                    ]),
                ),
                Vec::new(),
                Some("cn=creator,dc=example,dc=org".to_string()),
            )
            .await
            .unwrap();

        let mut session = ConnectionSession::default();
        session.bind("cn=modifier,dc=example,dc=org".to_string());
        let request = ModifyRequest {
            object: LdapDN(Cow::Owned("cn=Alice,dc=example,dc=org".to_string())),
            changes: vec![Change {
                operation: Operation(2),
                modification: PartialAttribute {
                    attr_type: LdapString(Cow::Owned("cn".to_string())),
                    attr_vals: vec![AttributeValue(Cow::Owned(b"Alice Updated".to_vec()))],
                },
            }],
        };

        let (mut server_stream, mut client_stream) = connected_stream_pair().await;
        let request_controls = RequestControls::default();
        handle_modify_request_with_context(
            &mut server_stream,
            &backend,
            9,
            request,
            &session,
            &RequestContext::default(),
            &request_controls,
        )
        .await
        .unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();
        match &messages[0].protocol_op {
            ProtocolOp::ModifyResponse(modify_response) => {
                assert_eq!(
                    modify_response.result.result_code,
                    ParserResultCode::Success
                );
            }
            other => panic!("unexpected response: {:?}", other),
        }

        let stored = backend
            .get_entry("cn=Alice,dc=example,dc=org")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.operational_attributes.creators_name.as_deref(),
            Some("cn=creator,dc=example,dc=org")
        );
        assert_eq!(
            stored.operational_attributes.modifiers_name.as_deref(),
            Some("cn=modifier,dc=example,dc=org")
        );
    }

    #[tokio::test]
    async fn authenticated_moddn_uses_bound_dn_for_operational_attrs() {
        let backend = MockBackend::new();
        backend
            .add_entry_with_actor(
                DirectoryEntry::new(
                    "cn=Alice,dc=example,dc=org",
                    HashMap::from([
                        ("cn".to_string(), vec!["Alice".to_string()]),
                        ("sn".to_string(), vec!["User".to_string()]),
                        ("objectclass".to_string(), vec!["person".to_string()]),
                    ]),
                ),
                Vec::new(),
                Some("cn=creator,dc=example,dc=org".to_string()),
            )
            .await
            .unwrap();

        let mut session = ConnectionSession::default();
        session.bind("cn=renamer,dc=example,dc=org".to_string());
        let request = ModDnRequest {
            entry: LdapDN(Cow::Owned("cn=Alice,dc=example,dc=org".to_string())),
            newrdn: RelativeLdapDN(Cow::Owned("cn=Alice Renamed".to_string())),
            deleteoldrdn: true,
            newsuperior: None,
        };

        let (mut server_stream, mut client_stream) = connected_stream_pair().await;
        let request_controls = RequestControls::default();
        handle_moddn_request_with_context(
            &mut server_stream,
            &backend,
            10,
            request,
            &session,
            &RequestContext::default(),
            &request_controls,
        )
        .await
        .unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();
        match &messages[0].protocol_op {
            ProtocolOp::ModDnResponse(moddn_response) => {
                assert_eq!(moddn_response.result_code, ParserResultCode::Success);
            }
            other => panic!("unexpected response: {:?}", other),
        }

        let stored = backend
            .get_entry("cn=Alice Renamed,dc=example,dc=org")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.operational_attributes.creators_name.as_deref(),
            Some("cn=creator,dc=example,dc=org")
        );
        assert_eq!(
            stored.operational_attributes.modifiers_name.as_deref(),
            Some("cn=renamer,dc=example,dc=org")
        );
    }

    #[tokio::test]
    async fn handle_client_accepts_fragmented_bind_request() {
        let backend = Arc::new(MockBackend::from_credentials([(
            String::from("cn=admin,dc=example,dc=org"),
            b"secret".to_vec(),
        )]));
        let schema = Arc::new(LdapSchema::with_core_schema());
        let (server_stream, mut client_stream) = connected_stream_pair().await;

        let server_task = tokio::spawn(async move {
            handle_client(server_stream, backend, schema).await;
        });

        let bind_request = RasnBindRequest::new(
            3,
            b"cn=admin,dc=example,dc=org".to_vec().into(),
            RasnAuthChoice::Simple(b"secret".to_vec().into()),
        );
        let message =
            rasn_ldap::LdapMessage::new(1, rasn_ldap::ProtocolOp::BindRequest(bind_request));
        let encoded = der::encode(&message).unwrap();
        let split_at = encoded.len() / 2;

        client_stream.write_all(&encoded[..split_at]).await.unwrap();
        client_stream.write_all(&encoded[split_at..]).await.unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 1);
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
    async fn handle_client_rejects_unknown_critical_control() {
        let backend = Arc::new(MockBackend::from_credentials([(
            String::from("cn=admin,dc=example,dc=org"),
            b"secret".to_vec(),
        )]));
        let schema = Arc::new(LdapSchema::with_core_schema());
        let (server_stream, mut client_stream) = connected_stream_pair().await;

        let server_task = tokio::spawn(async move {
            handle_client(server_stream, backend, schema).await;
        });

        let encoded = bind_request_with_controls(11, vec![rasn_control("1.2.3.4", true, None)]);
        client_stream.write_all(&encoded).await.unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 1);
        match &messages[0].protocol_op {
            ProtocolOp::BindResponse(bind_response) => {
                assert_eq!(
                    bind_response.result.result_code,
                    ParserResultCode::UnavailableCriticalExtension
                );
            }
            other => panic!("unexpected response: {:?}", other),
        }

        client_stream.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handle_client_ignores_unknown_non_critical_control() {
        let backend = Arc::new(MockBackend::from_credentials([(
            String::from("cn=admin,dc=example,dc=org"),
            b"secret".to_vec(),
        )]));
        let schema = Arc::new(LdapSchema::with_core_schema());
        let (server_stream, mut client_stream) = connected_stream_pair().await;

        let server_task = tokio::spawn(async move {
            handle_client(server_stream, backend, schema).await;
        });

        let encoded =
            bind_request_with_controls(12, vec![rasn_control("1.2.3.4", false, Some(b"ignored"))]);
        client_stream.write_all(&encoded).await.unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 1);
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
    async fn send_result_with_controls_emits_response_controls() {
        let (mut server_stream, mut client_stream) = connected_stream_pair().await;

        send_result_with_controls(
            &mut server_stream,
            13,
            ResponseOp::SearchDone,
            ResultCode::Success,
            "",
            "",
            &[LdapControl::new(
                "1.2.840.113556.1.4.319",
                false,
                Some(vec![1, 2, 3]),
            )],
        )
        .await
        .unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].controls.as_ref().unwrap().len(), 1);
        assert_eq!(
            messages[0].controls.as_ref().unwrap()[0]
                .control_type
                .0
                .as_ref(),
            "1.2.840.113556.1.4.319"
        );
    }

    #[tokio::test]
    async fn root_dse_search_returns_truthful_capabilities_and_context_csn() {
        let backend = MockBackend::new();
        backend
            .set_context_csn(crate::csn::Csn::with_values(1696680896789012, 1, 1, 0))
            .await
            .unwrap();
        let schema = LdapSchema::with_core_schema();
        let runtime_config = LegacyServerConfig {
            naming_contexts: vec!["dc=example,dc=org".to_string()],
            ..LegacyServerConfig::default()
        };
        let request_controls = RequestControls::default();
        let request = search_request_for_base("", &[]);
        let (mut server_stream, mut client_stream) = connected_stream_pair().await;

        handle_search_request_with_context(
            &mut server_stream,
            &backend,
            &schema,
            &runtime_config,
            14,
            request,
            &ConnectionSession::default(),
            &RequestContext::default(),
            &request_controls,
            false,
            true,
        )
        .await
        .unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 2);
        let attributes = match &messages[0].protocol_op {
            ProtocolOp::SearchResultEntry(entry) => {
                assert_eq!(entry.object_name.0.as_ref(), "");
                search_entry_attribute_map(entry)
            }
            other => panic!("unexpected response: {:?}", other),
        };

        assert_eq!(
            attributes.get("supportedLDAPVersion").unwrap(),
            &vec!["3".to_string()]
        );
        assert_eq!(
            attributes.get("namingContexts").unwrap(),
            &vec!["dc=example,dc=org".to_string()]
        );
        assert_eq!(
            attributes.get("subschemaSubentry").unwrap(),
            &vec!["cn=Subschema".to_string()]
        );
        assert_eq!(
            attributes.get("supportedSASLMechanisms").unwrap(),
            &vec!["PLAIN".to_string()]
        );
        assert_eq!(
            attributes.get("contextCSN").unwrap(),
            &vec!["1696680896789012#001#000001#000000".to_string()]
        );
        let mut supported_extensions = attributes.get("supportedExtension").unwrap().clone();
        supported_extensions.sort();
        let mut expected_extensions = vec![
            START_TLS_OID.to_string(),
            CANCEL_OID.to_string(),
            PASSWORD_MODIFY_OID.to_string(),
            WHO_AM_I_OID.to_string(),
        ];
        expected_extensions.sort();
        assert_eq!(supported_extensions, expected_extensions);
        assert!(!attributes.contains_key("supportedControl"));

        match &messages[1].protocol_op {
            ProtocolOp::SearchResultDone(done) => {
                assert_eq!(done.result_code, ParserResultCode::Success);
            }
            other => panic!("unexpected completion: {:?}", other),
        }
    }

    #[tokio::test]
    async fn secure_root_dse_search_omits_starttls_extension() {
        let backend = MockBackend::new();
        let schema = LdapSchema::with_core_schema();
        let runtime_config = LegacyServerConfig {
            naming_contexts: vec!["dc=example,dc=org".to_string()],
            ..LegacyServerConfig::default()
        };
        let request_controls = RequestControls::default();
        let request = search_request_for_base("", &["supportedExtension"]);
        let (mut server_stream, mut client_stream) = connected_stream_pair().await;

        handle_search_request_with_context(
            &mut server_stream,
            &backend,
            &schema,
            &runtime_config,
            15,
            request,
            &ConnectionSession::default(),
            &RequestContext::default(),
            &request_controls,
            true,
            true,
        )
        .await
        .unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();
        let attributes = match &messages[0].protocol_op {
            ProtocolOp::SearchResultEntry(entry) => search_entry_attribute_map(entry),
            other => panic!("unexpected response: {:?}", other),
        };

        let mut supported_extensions = attributes.get("supportedExtension").unwrap().clone();
        supported_extensions.sort();
        let mut expected_extensions = vec![
            CANCEL_OID.to_string(),
            PASSWORD_MODIFY_OID.to_string(),
            WHO_AM_I_OID.to_string(),
        ];
        expected_extensions.sort();
        assert_eq!(supported_extensions, expected_extensions);
    }

    #[tokio::test]
    async fn subschema_search_returns_attribute_types_and_object_classes() {
        let backend = MockBackend::new();
        let schema = LdapSchema::with_core_schema();
        let runtime_config = LegacyServerConfig {
            naming_contexts: vec!["dc=example,dc=org".to_string()],
            ..LegacyServerConfig::default()
        };
        let request_controls = RequestControls::default();
        let request = search_request_for_base("cn=Subschema", &[]);
        let (mut server_stream, mut client_stream) = connected_stream_pair().await;

        handle_search_request_with_context(
            &mut server_stream,
            &backend,
            &schema,
            &runtime_config,
            16,
            request,
            &ConnectionSession::default(),
            &RequestContext::default(),
            &request_controls,
            false,
            true,
        )
        .await
        .unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();
        let attributes = match &messages[0].protocol_op {
            ProtocolOp::SearchResultEntry(entry) => {
                assert_eq!(entry.object_name.0.as_ref(), "cn=Subschema");
                search_entry_attribute_map(entry)
            }
            other => panic!("unexpected response: {:?}", other),
        };

        assert_eq!(
            attributes.get("cn").unwrap(),
            &vec!["Subschema".to_string()]
        );
        assert!(attributes
            .get("attributeTypes")
            .unwrap()
            .iter()
            .any(|value| value.contains("2.5.4.3") && value.contains("commonName")));
        assert!(attributes
            .get("objectClasses")
            .unwrap()
            .iter()
            .any(|value| value.contains("2.16.840.1.113730.3.2.2")
                && value.contains("inetOrgPerson")));
    }

    #[tokio::test]
    async fn replication_stream_request_without_provider_runtime_returns_unavailable() {
        let backend = MockBackend::new();
        let (mut server_stream, mut client_stream) = connected_stream_pair().await;

        handle_search_request(
            &mut server_stream,
            &backend,
            9,
            replication_stream_request(),
        )
        .await
        .unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 1);
        match &messages[0].protocol_op {
            ProtocolOp::SearchResultDone(done) => {
                assert_eq!(done.result_code, ParserResultCode::Unavailable);
            }
            other => panic!("unexpected response: {:?}", other),
        }
    }

    #[tokio::test]
    async fn replication_stream_request_emits_live_change_through_provider_owned_session() {
        let mut config = ServerConfig::default();
        config.server.base_dn = "dc=example,dc=org".to_string();
        config.replication.enabled = true;
        config.replication.mode = "provider".to_string();

        let backend = Arc::new(MockBackend::new());
        let service = ReplicationService::from_config(&config, backend).unwrap();
        let provider_backend = service.backend();

        let (mut server_stream, mut client_stream) = connected_stream_pair().await;
        let request = replication_stream_request();
        let stream_backend = provider_backend.clone();

        let handler = tokio::spawn(async move {
            handle_search_request(&mut server_stream, stream_backend.as_ref(), 11, request)
                .await
                .unwrap();
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        provider_backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=stream-user,dc=example,dc=org",
                    HashMap::from([
                        ("cn".to_string(), vec!["stream-user".to_string()]),
                        ("objectclass".to_string(), vec!["person".to_string()]),
                    ]),
                ),
                vec![],
            )
            .await
            .unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert!(messages
            .iter()
            .any(|message| matches!(message.protocol_op, ProtocolOp::SearchResultEntry(_))));

        handler.abort();
        let _ = handler.await;
    }

    #[tokio::test]
    async fn replication_stream_request_rejects_new_consumer_while_provider_is_draining() {
        let mut config = ServerConfig::default();
        config.server.base_dn = "dc=example,dc=org".to_string();
        config.replication.enabled = true;
        config.replication.mode = "provider".to_string();

        let backend = Arc::new(MockBackend::new());
        let service = ReplicationService::from_config(&config, backend).unwrap();
        let provider_backend = service.backend();
        let lifecycle = provider_backend
            .replication_provider_lifecycle()
            .expect("provider lifecycle should be available");
        lifecycle.begin_shutdown();

        let (mut server_stream, mut client_stream) = connected_stream_pair().await;

        handle_search_request(
            &mut server_stream,
            provider_backend.as_ref(),
            12,
            replication_stream_request(),
        )
        .await
        .unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 1);
        match &messages[0].protocol_op {
            ProtocolOp::SearchResultDone(done) => {
                assert_eq!(done.result_code, ParserResultCode::Unavailable);
            }
            other => panic!("unexpected response: {:?}", other),
        }
    }

    #[tokio::test]
    async fn replication_stream_request_drains_active_session_on_provider_shutdown() {
        let mut config = ServerConfig::default();
        config.server.base_dn = "dc=example,dc=org".to_string();
        config.replication.enabled = true;
        config.replication.mode = "provider".to_string();

        let backend = Arc::new(MockBackend::new());
        let service = ReplicationService::from_config(&config, backend).unwrap();
        let provider_backend = service.backend();
        let lifecycle = provider_backend
            .replication_provider_lifecycle()
            .expect("provider lifecycle should be available");

        let (mut server_stream, mut client_stream) = connected_stream_pair().await;
        let request = replication_stream_request();
        let stream_backend = provider_backend.clone();

        let handler = tokio::spawn(async move {
            handle_search_request(&mut server_stream, stream_backend.as_ref(), 13, request)
                .await
                .unwrap();
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        lifecycle.begin_shutdown();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 1);
        match &messages[0].protocol_op {
            ProtocolOp::SearchResultDone(done) => {
                assert_eq!(done.result_code, ParserResultCode::Unavailable);
            }
            other => panic!("unexpected response: {:?}", other),
        }

        timeout(Duration::from_secs(1), handler)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(lifecycle.active_session_count(), 0);
    }

    #[tokio::test]
    async fn replication_stream_cancel_returns_cancel_response_and_canceled_search_done() {
        let mut config = ServerConfig::default();
        config.server.base_dn = "dc=example,dc=org".to_string();
        config.replication.enabled = true;
        config.replication.mode = "provider".to_string();

        let backend = Arc::new(MockBackend::new());
        let service = ReplicationService::from_config(&config, backend).unwrap();
        let provider_backend = service.backend();

        let (mut server_stream, mut client_stream) = connected_stream_pair().await;
        let request = replication_stream_request();
        let stream_backend = provider_backend.clone();

        let handler = tokio::spawn(async move {
            handle_search_request(&mut server_stream, stream_backend.as_ref(), 31, request)
                .await
                .unwrap();
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        client_stream
            .write_all(&cancel_request_message(32, 31))
            .await
            .unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 2);
        assert!(messages.iter().any(|message| {
            matches!(
                &message.protocol_op,
                ProtocolOp::ExtendedResponse(extended_response)
                    if message.message_id.0 == 32
                        && extended_response.result.result_code == ParserResultCode::Success
            )
        }));
        assert!(messages.iter().any(|message| {
            matches!(
                &message.protocol_op,
                ProtocolOp::SearchResultDone(done)
                    if message.message_id.0 == 31 && done.result_code.0 == 118
            )
        }));

        timeout(Duration::from_secs(1), handler)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn replication_stream_abandon_stops_search_without_sending_response() {
        let mut config = ServerConfig::default();
        config.server.base_dn = "dc=example,dc=org".to_string();
        config.replication.enabled = true;
        config.replication.mode = "provider".to_string();

        let backend = Arc::new(MockBackend::new());
        let service = ReplicationService::from_config(&config, backend).unwrap();
        let provider_backend = service.backend();

        let (mut server_stream, mut client_stream) = connected_stream_pair().await;
        let request = replication_stream_request();
        let stream_backend = provider_backend.clone();

        let handler = tokio::spawn(async move {
            handle_search_request(&mut server_stream, stream_backend.as_ref(), 41, request)
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(250)).await;
            let _ = server_stream.peer_addr();
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        client_stream
            .write_all(&abandon_request_message(42, 41))
            .await
            .unwrap();

        let mut buf = [0_u8; 64];
        match timeout(Duration::from_millis(150), client_stream.read(&mut buf)).await {
            Err(_) => {}
            Ok(Ok(0)) => {}
            Ok(Ok(len)) => panic!("unexpected abandon response bytes: {:?}", &buf[..len]),
            Ok(Err(err)) => panic!("failed to read abandon response state: {err}"),
        }

        timeout(Duration::from_secs(1), handler)
            .await
            .unwrap()
            .unwrap();
    }
}

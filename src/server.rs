use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ldap_parser::filter::{Filter, Substring, SubstringFilter};
use ldap_parser::ldap::{
    AddRequest, AuthenticationChoice, BindRequest, Change, CompareRequest, ExtendedRequest,
    ModDnRequest, ModifyRequest, ProtocolOp, SearchRequest,
};
use ldap_parser::parse_ldap_messages;
use log::{error, info, warn};
use rasn::error::EncodeError;
use rasn_ldap::ResultCode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::backend::{
    BackendError, DirectoryBackend, DirectoryEntry, Modification, ModifyOperation,
    SearchCandidateHint,
};
use crate::ber_decoder_fsm::BerDecoderFsmImpl;
use crate::connection_pool::{ConnectionId, ConnectionPool, ResourceLimits};
use crate::fsm::{BerDecoderEvent, BerDecoderFsm, StateMachine};
use crate::metrics::{MetricsCollector, OperationType};
use crate::parser::{
    encode_bind_response, encode_result_response, encode_search_entry, ResponseOp,
};
use crate::rate_limit::{RateLimitConfig, RateLimiter};
use crate::real_time_propagation::is_dn_in_scope;
use crate::replication::{
    changelog_entry_to_replication_attrs, REPLICATION_COOKIE_ATTRIBUTE_PREFIX,
    REPLICATION_STREAM_ATTRIBUTE,
};
use crate::schema::LdapSchema;

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

    #[cfg(test)]
    fn bound_dn(&self) -> Option<&str> {
        self.bound_dn.as_deref()
    }
}

#[derive(Debug, Clone)]
pub struct LegacyServerConfig {
    pub resource_limits: ResourceLimits,
    pub rate_limit_config: RateLimitConfig,
    pub rate_limiting_enabled: bool,
}

impl Default for LegacyServerConfig {
    fn default() -> Self {
        Self {
            resource_limits: ResourceLimits::default(),
            rate_limit_config: RateLimitConfig::default(),
            rate_limiting_enabled: true,
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
    run_with_metrics_and_config(
        addr,
        backend,
        shutdown_rx,
        metrics,
        LegacyServerConfig::default(),
    )
    .await
}

pub async fn run_with_metrics_and_config(
    addr: &str,
    backend: Arc<dyn DirectoryBackend>,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    metrics: Option<Arc<MetricsCollector>>,
    runtime_config: LegacyServerConfig,
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

                tokio::spawn(async move {
                    handle_client_with_metrics(
                        socket,
                        backend,
                        schema,
                        metrics.clone(),
                        Some(controls),
                    )
                    .await;
                    pool.release_connection(conn_id).await;
                    if let Some(metrics) = metrics.as_ref() {
                        metrics.record_connection_closed();
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

pub async fn handle_client(
    socket: TcpStream,
    backend: Arc<dyn DirectoryBackend>,
    schema: Arc<LdapSchema>,
) {
    handle_client_with_metrics(socket, backend, schema, None, None).await;
}

async fn handle_client_with_metrics(
    mut socket: TcpStream,
    backend: Arc<dyn DirectoryBackend>,
    schema: Arc<LdapSchema>,
    metrics: Option<Arc<MetricsCollector>>,
    controls: Option<ConnectionControls>,
) {
    let mut read_buffer = vec![0; 8192];
    let mut decoder = BerDecoderFsmImpl::new();
    let mut session = ConnectionSession::default();

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
                    match parse_ldap_messages(&message_bytes) {
                        Ok((_, messages)) => {
                            for message in messages {
                                let operation_type =
                                    operation_type_for_protocol(&message.protocol_op);
                                let response_kind =
                                    rejection_response_for_protocol(&message.protocol_op);
                                let started_at = Instant::now();
                                if let Some(metrics) = metrics.as_ref() {
                                    if let Some(operation_type) = operation_type {
                                        metrics.record_operation_start(operation_type, "");
                                    }
                                }

                                if let Some(controls) = controls.as_ref() {
                                    if let Some(operation_name) =
                                        rate_limited_operation_name_for_protocol(
                                            &message.protocol_op,
                                        )
                                    {
                                        if let Some(rate_limiter) = controls.rate_limiter.as_ref() {
                                            if !rate_limiter
                                                .check_rate_limit(
                                                    controls.client_ip,
                                                    operation_name,
                                                )
                                                .await
                                            {
                                                let result = send_rejection_response(
                                                    &mut socket,
                                                    message.message_id.0,
                                                    response_kind.clone(),
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
                                                    error!(
                                                        "Failed to send rate-limit response: {}",
                                                        err
                                                    );
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
                                            response_kind.clone(),
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
                                    &mut session,
                                    message,
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
                        Err(err) => {
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

async fn send_connection_rejected(socket: &mut TcpStream) -> Result<(), ServerError> {
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
    socket: &mut TcpStream,
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

pub async fn process_message(
    socket: &mut TcpStream,
    backend: &dyn DirectoryBackend,
    schema: &LdapSchema,
    message: ldap_parser::ldap::LdapMessage<'_>,
) -> Result<(), ServerError> {
    let mut session = ConnectionSession::default();
    process_message_with_session(socket, backend, schema, &mut session, message).await
}

async fn process_message_with_session(
    socket: &mut TcpStream,
    backend: &dyn DirectoryBackend,
    schema: &LdapSchema,
    session: &mut ConnectionSession,
    message: ldap_parser::ldap::LdapMessage<'_>,
) -> Result<(), ServerError> {
    let message_id = message.message_id.0;

    match message.protocol_op {
        ProtocolOp::BindRequest(bind_request) => {
            handle_bind_request_with_session(socket, backend, message_id, bind_request, session)
                .await?;
        }
        ProtocolOp::SearchRequest(search_request) => {
            handle_search_request(socket, backend, message_id, search_request).await?;
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
            handle_modify_request(socket, backend, message_id, modify_request).await?;
        }
        ProtocolOp::AddRequest(add_request) => {
            let dn = add_request.entry.0.as_ref().trim().to_owned();
            if !ensure_authenticated_for_mutation(socket, message_id, session, ResponseOp::Add, &dn)
                .await?
            {
                return Ok(());
            }
            handle_add_request(socket, backend, schema, message_id, add_request).await?;
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
            handle_delete_request(socket, backend, message_id, delete_request).await?;
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
            handle_moddn_request(socket, backend, message_id, rename_request).await?;
        }
        ProtocolOp::CompareRequest(compare_request) => {
            handle_compare_request(socket, backend, message_id, compare_request).await?;
        }
        ProtocolOp::UnbindRequest => {
            info!("Received unbind request");
            session.clear();
            return Ok(());
        }
        ProtocolOp::AbandonRequest(request_id) => {
            handle_abandon_request(request_id);
        }
        ProtocolOp::ExtendedRequest(request) => {
            handle_extended_request(socket, message_id, request).await?;
        }
        op => {
            warn!("Unsupported operation received: {:?}", op);
        }
    }

    Ok(())
}

pub async fn handle_bind_request(
    socket: &mut TcpStream,
    backend: &dyn DirectoryBackend,
    message_id: u32,
    request: BindRequest<'_>,
) -> Result<(), ServerError> {
    let mut session = ConnectionSession::default();
    handle_bind_request_with_session(socket, backend, message_id, request, &mut session).await
}

async fn handle_bind_request_with_session(
    socket: &mut TcpStream,
    backend: &dyn DirectoryBackend,
    message_id: u32,
    request: BindRequest<'_>,
    session: &mut ConnectionSession,
) -> Result<(), ServerError> {
    if request.version != 3 {
        session.clear();
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
                send_bind_success(socket, message_id).await?;
                return Ok(());
            }

            match backend.authenticate(&dn, password.as_ref()).await {
                Ok(true) => {
                    session.bind(dn);
                    send_bind_success(socket, message_id).await?;
                }
                Ok(false) => {
                    session.clear();
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
        AuthenticationChoice::Sasl(_) => {
            session.clear();
            send_bind_response(
                socket,
                message_id,
                ResultCode::AuthMethodNotSupported,
                "SASL authentication is not supported",
            )
            .await?;
        }
    }

    Ok(())
}

async fn ensure_authenticated_for_mutation(
    socket: &mut TcpStream,
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

async fn send_bind_success(socket: &mut TcpStream, message_id: u32) -> Result<(), ServerError> {
    send_bind_response(socket, message_id, ResultCode::Success, "").await
}

async fn send_bind_response(
    socket: &mut TcpStream,
    message_id: u32,
    result_code: ResultCode,
    diagnostic_message: impl Into<String>,
) -> Result<(), ServerError> {
    let encoded = encode_bind_response(message_id, result_code, "", diagnostic_message)?;
    socket.write_all(&encoded).await?;
    Ok(())
}

async fn send_result(
    socket: &mut TcpStream,
    message_id: u32,
    op: ResponseOp,
    result_code: ResultCode,
    matched_dn: impl Into<String>,
    diagnostic_message: impl Into<String>,
) -> Result<(), ServerError> {
    let encoded =
        encode_result_response(message_id, op, result_code, matched_dn, diagnostic_message)?;
    socket.write_all(&encoded).await?;
    Ok(())
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

pub async fn handle_search_request(
    socket: &mut TcpStream,
    backend: &dyn DirectoryBackend,
    message_id: u32,
    request: SearchRequest<'_>,
) -> Result<(), ServerError> {
    let base_dn = request.base_object.0.as_ref().trim().to_owned();
    let attribute_selection: Vec<String> = request
        .attributes
        .iter()
        .map(|attribute| attribute.0.as_ref().trim().to_owned())
        .collect();

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
        )
        .await;
    }

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
        let encoded = encode_search_entry(message_id, &entry, &attributes, request.types_only)?;
        socket.write_all(&encoded).await?;
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
    socket: &mut TcpStream,
    backend: &dyn DirectoryBackend,
    message_id: u32,
    base_dn: &str,
    attribute_selection: &[String],
) -> Result<(), ServerError> {
    let mut session = ProviderOwnedReplicationSession::new(socket, message_id, base_dn);

    let mut receiver = if let Some(receiver) = backend.subscribe_to_replication_changes() {
        receiver
    } else {
        session
            .send_unavailable("replication stream not available")
            .await?;
        return Ok(());
    };

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
            if !is_dn_in_scope(&entry.dn, base_dn) {
                continue;
            }
            session.send_change(&entry).await?;
        }
    }

    loop {
        match receiver.recv().await {
            Ok(entry) => {
                if !is_dn_in_scope(&entry.dn, base_dn) {
                    continue;
                }
                if let Err(err) = session.send_change(&entry).await {
                    warn!("Replication stream send failed: {}", err);
                    break;
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                warn!("Replication stream lagged by {} messages", skipped);
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }

    let _ = session.finish().await;

    Ok(())
}

struct ProviderOwnedReplicationSession<'a> {
    socket: &'a mut TcpStream,
    message_id: u32,
    base_dn: &'a str,
}

impl<'a> ProviderOwnedReplicationSession<'a> {
    fn new(socket: &'a mut TcpStream, message_id: u32, base_dn: &'a str) -> Self {
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
        let encoded = encode_search_entry(self.message_id, &synthetic_entry, &attributes, false)?;
        self.socket.write_all(&encoded).await?;
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

pub async fn handle_modify_request(
    socket: &mut TcpStream,
    backend: &dyn DirectoryBackend,
    message_id: u32,
    request: ModifyRequest<'_>,
) -> Result<(), ServerError> {
    let dn = request.object.0.as_ref().trim().to_owned();
    let modifications = convert_modifications(request.changes);

    match backend.modify_entry(&dn, modifications).await {
        Ok(()) => {
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
    socket: &mut TcpStream,
    backend: &dyn DirectoryBackend,
    schema: &LdapSchema,
    message_id: u32,
    request: AddRequest<'_>,
) -> Result<(), ServerError> {
    let dn = request.entry.0.as_ref().trim().to_owned();
    let (entry, password) = build_entry_from_add_request(&dn, request.attributes);

    // Perform schema validation before adding
    if let Err(schema_error) = schema.validate_entry(&entry.attributes) {
        error!("Schema validation failed for {}: {}", dn, schema_error);
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

    match backend.add_entry(entry, password).await {
        Ok(()) => {
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
    socket: &mut TcpStream,
    backend: &dyn DirectoryBackend,
    message_id: u32,
    dn: ldap_parser::ldap::LdapDN<'_>,
) -> Result<(), ServerError> {
    let dn = dn.0.as_ref().trim().to_owned();

    match backend.delete_entry(&dn).await {
        Ok(()) => {
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
    socket: &mut TcpStream,
    backend: &dyn DirectoryBackend,
    message_id: u32,
    request: ModDnRequest<'_>,
) -> Result<(), ServerError> {
    let dn = request.entry.0.as_ref().trim().to_owned();
    let new_rdn = request.newrdn.0.as_ref().trim().to_owned();
    let delete_old = request.deleteoldrdn;
    let new_superior = request
        .newsuperior
        .map(|sup| sup.0.into_owned())
        .filter(|sup| !sup.is_empty());

    match backend
        .rename_entry(&dn, &new_rdn, delete_old, new_superior)
        .await
    {
        Ok(()) => {
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
    socket: &mut TcpStream,
    backend: &dyn DirectoryBackend,
    message_id: u32,
    request: CompareRequest<'_>,
) -> Result<(), ServerError> {
    let dn = request.entry.0.as_ref().trim().to_owned();
    let attribute = request.ava.attribute_desc.0.as_ref().trim().to_owned();
    let assertion = bytes_to_string(request.ava.assertion_value);

    match backend.compare_attribute(&dn, &attribute, &assertion).await {
        Ok(true) => {
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

fn handle_abandon_request(request_id: ldap_parser::ldap::MessageID) {
    info!("Received abandon request for message {}", request_id.0);
}

pub async fn handle_extended_request(
    socket: &mut TcpStream,
    message_id: u32,
    request: ExtendedRequest<'_>,
) -> Result<(), ServerError> {
    warn!(
        "Unsupported extended operation requested: {}",
        request.request_name.0.as_ref()
    );

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
        if (include_all_operational || requested.iter().any(|a| a.eq_ignore_ascii_case("entrycsn")))
            && op_attrs.entry_csn.is_some()
        {
            selected.push((
                "entryCSN".to_string(),
                vec![op_attrs.entry_csn.as_ref().unwrap().to_ldap_string()],
            ));
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
    match filter {
        Filter::And(filters) => filters.iter().all(|f| entry_matches_filter(entry, f)),
        Filter::Or(filters) => filters.iter().any(|f| entry_matches_filter(entry, f)),
        Filter::Not(filter) => !entry_matches_filter(entry, filter),
        Filter::EqualityMatch(ava) => attribute_values(entry, ava.attribute_desc.0.as_ref())
            .map(|values| {
                let assertion = bytes_to_string(ava.assertion_value);
                values.iter().any(|candidate| candidate == &assertion)
            })
            .unwrap_or(false),
        Filter::Substrings(substring) => attribute_values(entry, substring.filter_type.0.as_ref())
            .map(|values| matches_substrings(values, substring))
            .unwrap_or(false),
        Filter::GreaterOrEqual(ava) => attribute_values(entry, ava.attribute_desc.0.as_ref())
            .map(|values| {
                let assertion = bytes_to_string(ava.assertion_value);
                values.iter().any(|candidate| candidate >= &assertion)
            })
            .unwrap_or(false),
        Filter::LessOrEqual(ava) => attribute_values(entry, ava.attribute_desc.0.as_ref())
            .map(|values| {
                let assertion = bytes_to_string(ava.assertion_value);
                values.iter().any(|candidate| candidate <= &assertion)
            })
            .unwrap_or(false),
        Filter::Present(attribute) => attribute_values(entry, attribute.0.as_ref()).is_some(),
        Filter::ApproxMatch(ava) => attribute_values(entry, ava.attribute_desc.0.as_ref())
            .map(|values| {
                let assertion = bytes_to_string(ava.assertion_value);
                values
                    .iter()
                    .any(|candidate| candidate.eq_ignore_ascii_case(&assertion))
            })
            .unwrap_or(false),
        Filter::ExtensibleMatch(_) => false,
    }
}

fn matches_substrings(values: &[String], filter: &SubstringFilter<'_>) -> bool {
    if filter.substrings.is_empty() {
        return values.iter().any(|value| value.is_empty());
    }

    values
        .iter()
        .any(|value| substring_matches(value, &filter.substrings))
}

fn substring_matches(value: &str, substrings: &[Substring<'_>]) -> bool {
    let mut remainder = value;

    for substring in substrings {
        match substring {
            Substring::Initial(segment) => {
                let segment = bytes_to_string(segment.0.as_ref());
                if !remainder.starts_with(&segment) {
                    return false;
                }
                remainder = &remainder[segment.len()..];
            }
            Substring::Any(segment) => {
                let segment = bytes_to_string(segment.0.as_ref());
                if segment.is_empty() {
                    continue;
                }
                if let Some(index) = remainder.find(&segment) {
                    remainder = &remainder[index + segment.len()..];
                } else {
                    return false;
                }
            }
            Substring::Final(segment) => {
                let segment = bytes_to_string(segment.0.as_ref());
                return remainder.ends_with(&segment);
            }
        }
    }

    true
}

fn attribute_values<'a>(entry: &'a DirectoryEntry, attribute: &str) -> Option<&'a Vec<String>> {
    entry.attributes.get(&attribute.to_lowercase())
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
    use crate::backend::MockBackend;
    use crate::config::ServerConfig;
    use crate::replication::REPLICATION_STREAM_ATTRIBUTE;
    use crate::replication_service::ReplicationService;
    use ldap_parser::filter::{
        Attribute as FilterAttribute, AttributeValue, AttributeValueAssertion, Filter,
        PartialAttribute,
    };
    use ldap_parser::ldap::LdapString;
    use ldap_parser::ldap::{
        AuthenticationChoice, BindRequest, DerefAliases, LdapDN, ResultCode as ParserResultCode,
        SearchRequest, SearchScope,
    };
    use ldap_parser::ldap::{Change, Operation};
    use rasn::der;
    use rasn_ldap::{AuthenticationChoice as RasnAuthChoice, BindRequest as RasnBindRequest};
    use std::borrow::Cow;
    use std::sync::Arc;
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
        buf
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

        handle_bind_request_with_session(&mut server_stream, &backend, 1, request, &mut session)
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
}

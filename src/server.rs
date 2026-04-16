use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use ldap_parser::filter::Filter;
use ldap_parser::ldap::{
    AddRequest, AuthenticationChoice, BindRequest, Change, CompareRequest, ExtendedRequest,
    MessageID, ModDnRequest, ModifyRequest, ProtocolOp, SearchRequest,
};
use ldap_parser::parse_ldap_messages;
use log::{error, info, warn};
use rand::distr::{Alphanumeric, SampleString};
use rasn::error::EncodeError;
use rasn_ldap::{LdapMessage as RasnLdapMessage, ProtocolOp as RasnProtocolOp, ResultCode};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;

use crate::aci::{AciEngine, Permission};
use crate::audit::{AuditEvent, AuditEventType, AuditLevel, AuditLogger};
use crate::auth_metadata::AuthMetadataRecorder;
#[cfg(test)]
use crate::backend::SearchCandidateHint;
use crate::backend::{
    BackendError, DirectoryBackend, DirectoryEntry, Modification, ModifyOperation,
    NativeModifyError, OperationalAttributes,
};
use crate::ber_decoder_fsm::BerDecoderFsmImpl;
use crate::connection_pool::{ConnectionId, ConnectionPool, ResourceLimits};
use crate::dn::dn_eq;
use crate::extended_ops::{
    encode_password_modify_response_value, oids, parse_cancel_request_value,
    parse_password_modify_request_value,
};
use crate::ldap_controls::{ControlRegistry, ControlValidationError, LdapControl, RequestControls};
use crate::ldap_filter_eval::{
    FilterSchemaError, PreparedLdapFilter, compare_attribute_with_schema,
    matches_search_filter_with_schema, prepare_search_filter_with_schema, validate_search_filter,
};
use crate::metrics::{MetricsCollector, OperationType};
use crate::parser::{
    CustomResultCode, ResponseOp, encode_bind_response, encode_custom_extended_response,
    encode_custom_search_result_done, encode_extended_response_with_controls,
    encode_intermediate_response, encode_result_response_with_controls,
    encode_result_response_with_referrals, encode_search_entry_with_controls,
    encode_search_reference_with_controls,
};
use crate::rate_limit::{RateLimitConfig, RateLimiter};
use crate::real_time_propagation::is_dn_in_scope;
use crate::referral::LdapReferralResolver;
use crate::referral_fsm::ReferralResolver;
use crate::replication::RenameChange;
use crate::schema::{LdapSchema, SchemaError, canonical_schema_attr_name, schema_definition_key};
use crate::search_controls::{
    PAGED_RESULTS_OID, PagedResultsControl, SERVER_SIDE_SORT_REQUEST_OID,
    SERVER_SIDE_SORT_RESPONSE_OID, ServerSideSortResultCode, SortKey, decode_paged_results_control,
    decode_server_side_sort_request_control, encode_paged_results_control,
    encode_server_side_sort_response_control,
};
use crate::sync_controls::{
    SYNC_DONE_OID, SYNC_INFO_OID, SYNC_REQUEST_OID, SYNC_STATE_OID, SyncDoneControl, SyncInfoValue,
    SyncRefreshMode, SyncRequestControl, SyncStateControl, SyncStateType,
    decode_sync_request_control, encode_sync_done_control, encode_sync_info_value,
    encode_sync_state_control,
};
use crate::tls::RustlsTlsHandler;
use uuid::Uuid;

const MANAGE_DSA_IT_OID: &str = "2.16.840.1.113730.3.4.2";

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
pub(crate) struct ConnectionSession {
    bound_dn: Option<String>,
}

impl ConnectionSession {
    pub(crate) fn bind(&mut self, dn: String) {
        self.bound_dn = Some(dn);
    }

    pub(crate) fn clear(&mut self) {
        self.bound_dn = None;
    }

    pub(crate) fn is_authenticated(&self) -> bool {
        self.bound_dn.is_some()
    }

    pub(crate) fn bound_dn(&self) -> Option<&str> {
        self.bound_dn.as_deref()
    }
}

const START_TLS_OID: &str = "1.3.6.1.4.1.1466.20037";
const CANCEL_OID: &str = oids::CANCEL;
const PASSWORD_MODIFY_OID: &str = oids::PASSWORD_MODIFY;
const WHO_AM_I_OID: &str = "1.3.6.1.4.1.4203.1.11.3";
const SUBSCHEMA_DN: &str = "cn=Subschema";
const ONLINE_SCHEMA_FILE: &str = "99-online.ldif";

pub type SharedLdapSchema = Arc<RwLock<LdapSchema>>;

pub fn shared_schema(schema: LdapSchema) -> SharedLdapSchema {
    Arc::new(RwLock::new(schema))
}

pub(crate) fn schema_snapshot(schema: &SharedLdapSchema) -> LdapSchema {
    schema.read().expect("LDAP schema lock poisoned").clone()
}

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
pub(crate) enum CancelRequestOutcome {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SearchRequestSignature {
    base_dn: String,
    scope: u32,
    deref_aliases: u32,
    size_limit: u32,
    time_limit: u32,
    types_only: bool,
    filter_repr: String,
    attributes: Vec<String>,
    sort_keys: Option<Vec<SortKey>>,
}

impl SearchRequestSignature {
    pub(crate) fn from_request(
        base_dn: &str,
        request: &SearchRequest<'_>,
        attribute_selection: &[String],
        sort_keys: Option<&[SortKey]>,
    ) -> Self {
        let mut attributes = attribute_selection
            .iter()
            .map(|attribute| attribute.to_ascii_lowercase())
            .collect::<Vec<_>>();
        attributes.sort();
        attributes.dedup();

        Self {
            base_dn: normalize_search_dn(base_dn),
            scope: request.scope.0,
            deref_aliases: request.deref_aliases.0,
            size_limit: request.size_limit,
            time_limit: request.time_limit,
            types_only: request.types_only,
            filter_repr: format!("{:?}", request.filter),
            attributes,
            sort_keys: sort_keys.map(|keys| keys.to_vec()),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PagedSearchCursor {
    pub(crate) signature: SearchRequestSignature,
    total_size: usize,
    remaining_entries: Vec<DirectoryEntry>,
    completion_code: ResultCode,
    completion_diagnostic: &'static str,
}

impl PagedSearchCursor {
    pub(crate) fn new(
        signature: SearchRequestSignature,
        total_size: usize,
        remaining_entries: Vec<DirectoryEntry>,
        completion_code: ResultCode,
        completion_diagnostic: &'static str,
    ) -> Self {
        Self {
            signature,
            total_size,
            remaining_entries,
            completion_code,
            completion_diagnostic,
        }
    }

    pub(crate) fn total_size(&self) -> u32 {
        u32::try_from(self.total_size).unwrap_or(u32::MAX)
    }

    pub(crate) fn next_page(
        &mut self,
        page_size: usize,
    ) -> (Vec<DirectoryEntry>, ResultCode, &'static str, bool) {
        let rest = if self.remaining_entries.len() > page_size {
            self.remaining_entries.split_off(page_size)
        } else {
            Vec::new()
        };
        let page = std::mem::replace(&mut self.remaining_entries, rest);
        let complete = self.remaining_entries.is_empty();

        if complete {
            (page, self.completion_code, self.completion_diagnostic, true)
        } else {
            (page, ResultCode::Success, "", false)
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct ConnectionOperationRegistry {
    active: HashMap<u32, RegisteredOperation>,
    finished: HashMap<u32, FinishedOperationState>,
    paged_searches: HashMap<Vec<u8>, PagedSearchCursor>,
    active_paged_searches: HashMap<u32, Vec<u8>>,
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

    pub(crate) fn request_cancel(&mut self, message_id: u32) -> CancelRequestOutcome {
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

    pub(crate) fn request_abandon(&mut self, message_id: u32) -> bool {
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
        if let Some(cookie) = self.active_paged_searches.remove(&message_id)
            && matches!(
                outcome,
                FinishedOperationState::Canceled | FinishedOperationState::Abandoned
            )
        {
            self.paged_searches.remove(&cookie);
        }
        self.finished.insert(message_id, outcome);
    }

    pub(crate) fn clear_paged_searches(&mut self) {
        self.paged_searches.clear();
        self.active_paged_searches.clear();
    }

    pub(crate) fn remember_paged_search(&mut self, cursor: PagedSearchCursor) -> Vec<u8> {
        loop {
            let cookie = Alphanumeric
                .sample_string(&mut rand::rng(), 24)
                .into_bytes();
            if self.paged_searches.contains_key(&cookie) {
                continue;
            }
            self.paged_searches.insert(cookie.clone(), cursor);
            return cookie;
        }
    }

    pub(crate) fn paged_search(&self, cookie: &[u8]) -> Option<&PagedSearchCursor> {
        self.paged_searches.get(cookie)
    }

    pub(crate) fn paged_search_mut(&mut self, cookie: &[u8]) -> Option<&mut PagedSearchCursor> {
        self.paged_searches.get_mut(cookie)
    }

    pub(crate) fn remove_paged_search(&mut self, cookie: &[u8]) -> Option<PagedSearchCursor> {
        self.paged_searches.remove(cookie)
    }

    pub(crate) fn attach_paged_search_to_operation(&mut self, message_id: u32, cookie: Vec<u8>) {
        self.active_paged_searches.insert(message_id, cookie);
    }
}

#[derive(Debug, Clone)]
pub struct LegacyServerConfig {
    pub resource_limits: ResourceLimits,
    pub rate_limit_config: RateLimitConfig,
    pub rate_limiting_enabled: bool,
    pub auth_metadata: Option<AuthMetadataRecorder>,
    pub naming_contexts: Vec<String>,
    pub subschema_dn: String,
    pub schema_dir: PathBuf,
    pub allow_online_schema_updates: bool,
}

impl Default for LegacyServerConfig {
    fn default() -> Self {
        Self {
            resource_limits: ResourceLimits::default(),
            rate_limit_config: RateLimitConfig::default(),
            rate_limiting_enabled: true,
            auth_metadata: None,
            naming_contexts: Vec::new(),
            subschema_dn: SUBSCHEMA_DN.to_string(),
            schema_dir: PathBuf::from("config/schema"),
            allow_online_schema_updates: false,
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
            auth_metadata: None,
            naming_contexts: vec![config.server.base_dn.clone()],
            subschema_dn: SUBSCHEMA_DN.to_string(),
            schema_dir: config.schema.schema_dir.clone(),
            allow_online_schema_updates: config.schema.allow_online_updates,
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
    pub log_replication: bool,
}

impl Default for LegacyAuditConfig {
    fn default() -> Self {
        Self {
            log_authentication: true,
            log_authorization: true,
            log_modifications: true,
            log_connections: true,
            log_replication: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegacySecurityPolicy {
    pub allow_anonymous_bind: bool,
    pub allow_cleartext_simple_bind: bool,
    pub allow_sasl_plain: bool,
    pub allow_password_modify: bool,
    pub root_dse_requires_authentication: bool,
}

impl LegacySecurityPolicy {
    pub const fn development() -> Self {
        Self {
            allow_anonymous_bind: true,
            allow_cleartext_simple_bind: true,
            allow_sasl_plain: true,
            allow_password_modify: true,
            root_dse_requires_authentication: false,
        }
    }

    pub const fn production() -> Self {
        Self {
            allow_anonymous_bind: false,
            allow_cleartext_simple_bind: false,
            allow_sasl_plain: true,
            allow_password_modify: true,
            root_dse_requires_authentication: false,
        }
    }
}

impl Default for LegacySecurityPolicy {
    fn default() -> Self {
        Self::development()
    }
}

#[derive(Clone, Default)]
pub struct LegacySecurityConfig {
    pub audit_logger: Option<Arc<AuditLogger>>,
    pub audit_config: LegacyAuditConfig,
    pub access_control: Option<Arc<AciEngine>>,
    pub root_dn: Option<String>,
    pub security_policy: LegacySecurityPolicy,
}

#[derive(Clone, Default)]
pub(crate) struct RequestContext {
    client_ip: Option<IpAddr>,
    session_id: Option<ConnectionId>,
    security: Option<Arc<LegacySecurityConfig>>,
    metrics: Option<Arc<MetricsCollector>>,
    auth_metadata: Option<AuthMetadataRecorder>,
}

impl RequestContext {
    pub(crate) fn new(
        client_ip: Option<IpAddr>,
        session_id: Option<ConnectionId>,
        security: Option<Arc<LegacySecurityConfig>>,
        metrics: Option<Arc<MetricsCollector>>,
    ) -> Self {
        Self {
            client_ip,
            session_id,
            security,
            metrics,
            auth_metadata: None,
        }
    }

    pub(crate) fn with_auth_metadata(
        mut self,
        auth_metadata: Option<AuthMetadataRecorder>,
    ) -> Self {
        self.auth_metadata = auth_metadata;
        self
    }
}

pub(crate) fn security_policy(request_context: &RequestContext) -> LegacySecurityPolicy {
    request_context
        .security
        .as_ref()
        .map(|security| security.security_policy)
        .unwrap_or_default()
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
    run_with_metrics_and_config_with_tls_and_security_and_shared_schema(
        addr,
        backend,
        shutdown_rx,
        metrics,
        runtime_config,
        tls_handler,
        security,
        shared_schema(LdapSchema::with_core_schema()),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn run_with_metrics_and_config_with_tls_and_security_and_schema(
    addr: &str,
    backend: Arc<dyn DirectoryBackend>,
    shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    metrics: Option<Arc<MetricsCollector>>,
    runtime_config: LegacyServerConfig,
    tls_handler: Option<Arc<RustlsTlsHandler>>,
    security: Option<Arc<LegacySecurityConfig>>,
    schema: Arc<LdapSchema>,
) -> Result<(), ServerError> {
    run_with_metrics_and_config_with_tls_and_security_and_shared_schema(
        addr,
        backend,
        shutdown_rx,
        metrics,
        runtime_config,
        tls_handler,
        security,
        shared_schema((*schema).clone()),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn run_with_metrics_and_config_with_tls_and_security_and_shared_schema(
    addr: &str,
    backend: Arc<dyn DirectoryBackend>,
    shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    metrics: Option<Arc<MetricsCollector>>,
    runtime_config: LegacyServerConfig,
    tls_handler: Option<Arc<RustlsTlsHandler>>,
    security: Option<Arc<LegacySecurityConfig>>,
    schema: SharedLdapSchema,
) -> Result<(), ServerError> {
    run_plain_listener(
        addr,
        backend,
        shutdown_rx,
        metrics,
        runtime_config,
        tls_handler,
        security,
        schema,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_plain_listener(
    addr: &str,
    backend: Arc<dyn DirectoryBackend>,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    metrics: Option<Arc<MetricsCollector>>,
    runtime_config: LegacyServerConfig,
    tls_handler: Option<Arc<RustlsTlsHandler>>,
    security: Option<Arc<LegacySecurityConfig>>,
    schema: SharedLdapSchema,
) -> Result<(), ServerError> {
    let listener = TcpListener::bind(addr).await?;
    info!("LDAP server listening on {}", addr);

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
                if let Err(err) = socket.set_nodelay(true) {
                    warn!("Failed to enable TCP_NODELAY for {:?}: {}", addr, err);
                }

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

                if let Some(security) = security.as_ref()
                    && let Some(audit) = security.audit_logger.as_ref()
                        && security.audit_config.log_connections {
                            audit
                                .log_connection_accepted(
                                    &addr.ip().to_string(),
                                    &conn_id.to_string(),
                                )
                                .await;
                        }

                tokio::spawn(async move {
                    let request_context = RequestContext {
                        client_ip: Some(addr.ip()),
                        session_id: Some(conn_id),
                        security: security.clone(),
                        metrics: metrics.clone(),
                        auth_metadata: connection_runtime_config.auth_metadata.clone(),
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
                    if let Some(security) = request_context.security.as_ref()
                        && let Some(audit) = security.audit_logger.as_ref()
                            && security.audit_config.log_connections {
                                audit
                                    .log_connection_closed(
                                        &addr.ip().to_string(),
                                        &conn_id.to_string(),
                                    )
                                    .await;
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
    shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    metrics: Option<Arc<MetricsCollector>>,
    runtime_config: LegacyServerConfig,
    tls_handler: Arc<RustlsTlsHandler>,
    security: Option<Arc<LegacySecurityConfig>>,
) -> Result<(), ServerError> {
    run_tls_with_metrics_and_config_and_security_and_shared_schema(
        addr,
        backend,
        shutdown_rx,
        metrics,
        runtime_config,
        tls_handler,
        security,
        shared_schema(LdapSchema::with_core_schema()),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn run_tls_with_metrics_and_config_and_security_and_schema(
    addr: &str,
    backend: Arc<dyn DirectoryBackend>,
    shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    metrics: Option<Arc<MetricsCollector>>,
    runtime_config: LegacyServerConfig,
    tls_handler: Arc<RustlsTlsHandler>,
    security: Option<Arc<LegacySecurityConfig>>,
    schema: Arc<LdapSchema>,
) -> Result<(), ServerError> {
    run_tls_with_metrics_and_config_and_security_and_shared_schema(
        addr,
        backend,
        shutdown_rx,
        metrics,
        runtime_config,
        tls_handler,
        security,
        shared_schema((*schema).clone()),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn run_tls_with_metrics_and_config_and_security_and_shared_schema(
    addr: &str,
    backend: Arc<dyn DirectoryBackend>,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    metrics: Option<Arc<MetricsCollector>>,
    runtime_config: LegacyServerConfig,
    tls_handler: Arc<RustlsTlsHandler>,
    security: Option<Arc<LegacySecurityConfig>>,
    schema: SharedLdapSchema,
) -> Result<(), ServerError> {
    let listener = TcpListener::bind(addr).await?;
    info!("LDAPS server listening on {}", addr);

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
                if let Err(err) = socket.set_nodelay(true) {
                    warn!("Failed to enable TCP_NODELAY for LDAPS {:?}: {}", addr, err);
                }

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

                if let Some(security) = security.as_ref()
                    && let Some(audit) = security.audit_logger.as_ref()
                        && security.audit_config.log_connections {
                            audit
                                .log_connection_accepted(
                                    &addr.ip().to_string(),
                                    &conn_id.to_string(),
                                )
                                .await;
                        }

                tokio::spawn(async move {
                    let request_context = RequestContext {
                        client_ip: Some(addr.ip()),
                        session_id: Some(conn_id),
                        security: security.clone(),
                        metrics: metrics.clone(),
                        auth_metadata: connection_runtime_config.auth_metadata.clone(),
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
                    if let Some(security) = request_context.security.as_ref()
                        && let Some(audit) = security.audit_logger.as_ref()
                            && security.audit_config.log_connections {
                                audit
                                    .log_connection_closed(
                                        &addr.ip().to_string(),
                                        &conn_id.to_string(),
                                    )
                                    .await;
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
        shared_schema((*schema).clone()),
        LegacyServerConfig::default(),
        None,
        None,
        None,
        RequestContext::default(),
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn handle_client_with_metrics_and_tls(
    mut socket: ConnectionStream,
    backend: Arc<dyn DirectoryBackend>,
    schema: SharedLdapSchema,
    runtime_config: LegacyServerConfig,
    tls_handler: Option<Arc<RustlsTlsHandler>>,
    metrics: Option<Arc<MetricsCollector>>,
    controls: Option<ConnectionControls>,
    request_context: RequestContext,
) {
    let mut read_buffer = vec![0; 8192];
    let mut decoder = BerDecoderFsmImpl::new();
    let mut decoded_messages = Vec::new();
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

                decoded_messages.clear();
                if let Err(err) =
                    decode_messages_into(&mut decoder, &read_buffer[..n], &mut decoded_messages)
                        .await
                {
                    if let Some(controls) = controls.as_ref()
                        && accounted_read_bytes
                    {
                        controls
                            .pool
                            .update_memory_usage(controls.conn_id, -(n as isize))
                            .await;
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

                if let Some(controls) = controls.as_ref()
                    && accounted_read_bytes
                {
                    controls
                        .pool
                        .update_memory_usage(controls.conn_id, -(n as isize))
                        .await;
                }

                for message_bytes in decoded_messages.drain(..) {
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
                        if let Some(metrics) = metrics.as_ref()
                            && let Some(operation_type) = operation_type
                        {
                            metrics.record_operation_start(operation_type, "");
                        }

                        if let Some(controls) = controls.as_ref() {
                            if let Some(operation_name) =
                                rate_limited_operation_name_for_protocol(&message.protocol_op)
                                && let Some(rate_limiter) = controls.rate_limiter.as_ref()
                                && !rate_limiter
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
                                if let Some(metrics) = metrics.as_ref()
                                    && let Some(operation_type) = operation_type
                                {
                                    metrics.record_operation_complete(
                                        operation_type,
                                        started_at.elapsed(),
                                        false,
                                    );
                                }
                                if let Err(err) = result {
                                    error!("Failed to send rate-limit response: {}", err);
                                    return;
                                }
                                continue;
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
                                if let Some(metrics) = metrics.as_ref()
                                    && let Some(operation_type) = operation_type
                                {
                                    metrics.record_operation_complete(
                                        operation_type,
                                        started_at.elapsed(),
                                        false,
                                    );
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
                            &schema,
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

                        if let Some(metrics) = metrics.as_ref()
                            && let Some(operation_type) = operation_type
                        {
                            metrics.record_operation_complete(
                                operation_type,
                                started_at.elapsed(),
                                result.is_ok(),
                            );
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
    input: &[u8],
) -> Result<Vec<Vec<u8>>, crate::ber_decoder_fsm::BerDecoderError> {
    decoder.decode_available_messages(input).await
}

async fn decode_messages_into(
    decoder: &mut BerDecoderFsmImpl,
    input: &[u8],
    messages: &mut Vec<Vec<u8>>,
) -> Result<(), crate::ber_decoder_fsm::BerDecoderError> {
    decoder
        .decode_available_messages_into(input, messages)
        .await
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
    let shared_schema = shared_schema(schema.clone());
    process_message_with_session(
        socket,
        backend,
        &shared_schema,
        &runtime_config,
        &mut session,
        &mut operation_registry,
        message,
        None,
        &RequestContext::default(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn process_message_with_session(
    socket: &mut ConnectionStream,
    backend: &dyn DirectoryBackend,
    schema: &SharedLdapSchema,
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
            operation_registry.clear_paged_searches();
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
            let schema_snapshot = schema_snapshot(schema);
            handle_search_request_with_context_and_registry(
                socket,
                backend,
                &schema_snapshot,
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
            if dn.eq_ignore_ascii_case(&runtime_config.subschema_dn) {
                handle_online_schema_modify_request_with_context(
                    socket,
                    backend,
                    schema,
                    runtime_config,
                    message_id,
                    modify_request,
                    session,
                    request_context,
                )
                .await?;
            } else {
                let schema_snapshot = schema_snapshot(schema);
                handle_modify_request_with_context(
                    socket,
                    backend,
                    &schema_snapshot,
                    message_id,
                    modify_request,
                    session,
                    request_context,
                    &request_controls,
                )
                .await?;
            }
        }
        ProtocolOp::AddRequest(add_request) => {
            let dn = add_request.entry.0.as_ref().trim().to_owned();
            if !ensure_authenticated_for_mutation(socket, message_id, session, ResponseOp::Add, &dn)
                .await?
            {
                return Ok(());
            }
            let schema_snapshot = schema_snapshot(schema);
            handle_add_request_with_context(
                socket,
                backend,
                &schema_snapshot,
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
            let schema_snapshot = schema_snapshot(schema);
            handle_moddn_request_with_context(
                socket,
                backend,
                &schema_snapshot,
                message_id,
                rename_request,
                session,
                request_context,
                &request_controls,
            )
            .await?;
        }
        ProtocolOp::CompareRequest(compare_request) => {
            let schema_snapshot = schema_snapshot(schema);
            handle_compare_request_with_context(
                socket,
                backend,
                &schema_snapshot,
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
            operation_registry.clear_paged_searches();
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
    let mut registry = ControlRegistry::default();
    registry
        .register_request_control(PAGED_RESULTS_OID)
        .register_response_control(PAGED_RESULTS_OID)
        .register_request_control(SERVER_SIDE_SORT_REQUEST_OID)
        .register_response_control(SERVER_SIDE_SORT_RESPONSE_OID)
        .register_request_control(MANAGE_DSA_IT_OID)
        .register_request_control(SYNC_REQUEST_OID)
        .register_response_control(SYNC_STATE_OID)
        .register_response_control(SYNC_DONE_OID);
    registry
}

fn control_metric_fragment(oid: &str) -> String {
    oid.chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect()
}

pub(crate) fn increment_control_counter(
    request_context: &RequestContext,
    counter: &str,
    value: u64,
) {
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

#[derive(Debug)]
struct SearchResultSet {
    entries: Vec<DirectoryEntry>,
    references: Vec<Vec<String>>,
    size_limit_hit: bool,
    time_limit_hit: bool,
}

#[derive(Debug)]
struct SearchExecutionError {
    result_code: ResultCode,
    diagnostic: String,
    target_dn: String,
    alias_dereference_failure: bool,
    referral_processing_failure: bool,
}

fn search_filter_execution_error(err: FilterSchemaError, target_dn: &str) -> SearchExecutionError {
    SearchExecutionError {
        result_code: map_filter_schema_error(&err),
        diagnostic: err.to_string(),
        target_dn: target_dn.to_string(),
        alias_dereference_failure: false,
        referral_processing_failure: false,
    }
}

#[derive(Debug)]
enum PagedSearchRequestError {
    ProtocolError(String),
    InvalidCookie(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RequestedServerSideSort {
    keys: Vec<SortKey>,
    critical: bool,
}

#[derive(Debug)]
enum ServerSideSortRequestError {
    ProtocolError(String),
    Unsupported {
        result: ServerSideSortResultCode,
        attribute_type: Option<String>,
        diagnostic: String,
        critical: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RequestedSyncControl {
    pub(crate) request: SyncRequestControl,
    pub(crate) critical: bool,
}

#[derive(Debug)]
pub(crate) enum SyncRequestError {
    ProtocolError(String),
    InvalidCookie(String),
    Unsupported(String),
}

#[derive(Debug)]
enum ManageDsaItRequestError {
    ProtocolError(String),
}

impl PagedSearchRequestError {
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

fn paged_results_response_control(
    total_size: usize,
    cookie: &[u8],
) -> Result<LdapControl, ServerError> {
    let value = encode_paged_results_control(u32::try_from(total_size).unwrap_or(u32::MAX), cookie)
        .map_err(|err| ServerError::Io(std::io::Error::other(err.to_string())))?;
    Ok(LdapControl::new(PAGED_RESULTS_OID, false, Some(value)))
}

fn server_side_sort_response_control(
    result: ServerSideSortResultCode,
    attribute_type: Option<&str>,
) -> Result<LdapControl, ServerError> {
    let value = encode_server_side_sort_response_control(result, attribute_type)
        .map_err(|err| ServerError::Io(std::io::Error::other(err.to_string())))?;
    Ok(LdapControl::new(
        SERVER_SIDE_SORT_RESPONSE_OID,
        false,
        Some(value),
    ))
}

fn sync_state_response_control(
    state: SyncStateType,
    entry_uuid: Uuid,
    cookie: Option<Vec<u8>>,
) -> Result<LdapControl, ServerError> {
    let value = encode_sync_state_control(&SyncStateControl {
        state,
        entry_uuid,
        cookie,
    })
    .map_err(|err| ServerError::Io(std::io::Error::other(err.to_string())))?;
    Ok(LdapControl::new(SYNC_STATE_OID, false, Some(value)))
}

fn sync_done_response_control(
    cookie: Option<Vec<u8>>,
    refresh_deletes: bool,
) -> Result<LdapControl, ServerError> {
    let value = encode_sync_done_control(&SyncDoneControl {
        cookie,
        refresh_deletes,
    })
    .map_err(|err| ServerError::Io(std::io::Error::other(err.to_string())))?;
    Ok(LdapControl::new(SYNC_DONE_OID, false, Some(value)))
}

pub(crate) fn parse_sync_request_control(
    request_controls: &RequestControls,
) -> Result<Option<RequestedSyncControl>, SyncRequestError> {
    let control = request_controls
        .singleton(SYNC_REQUEST_OID)
        .map_err(|err| SyncRequestError::ProtocolError(err.to_string()))?;
    let Some(control) = control else {
        return Ok(None);
    };

    let request = decode_sync_request_control(control.value()).map_err(|err| {
        SyncRequestError::ProtocolError(format!("malformed sync request control: {err}"))
    })?;

    Ok(Some(RequestedSyncControl {
        request,
        critical: control.criticality(),
    }))
}

fn parse_manage_dsa_it_request(
    request_controls: &RequestControls,
) -> Result<bool, ManageDsaItRequestError> {
    let control = request_controls
        .singleton(MANAGE_DSA_IT_OID)
        .map_err(|err| ManageDsaItRequestError::ProtocolError(err.to_string()))?;
    let Some(control) = control else {
        return Ok(false);
    };

    if control.value().is_some() {
        return Err(ManageDsaItRequestError::ProtocolError(
            "ManageDsaIT control must not include a controlValue".to_string(),
        ));
    }

    Ok(true)
}

fn parse_paged_results_request(
    request_controls: &RequestControls,
) -> Result<Option<PagedResultsControl>, PagedSearchRequestError> {
    let control = request_controls
        .singleton(PAGED_RESULTS_OID)
        .map_err(|err| PagedSearchRequestError::ProtocolError(err.to_string()))?;
    let Some(control) = control else {
        return Ok(None);
    };

    decode_paged_results_control(control.value())
        .map(Some)
        .map_err(|err| {
            PagedSearchRequestError::ProtocolError(format!(
                "malformed paged results control: {err}"
            ))
        })
}

fn record_paged_search_invalid_cookie(request_context: &RequestContext) {
    increment_control_counter(request_context, "ldap_paged_search_invalid_cookie_total", 1);
}

fn parse_server_side_sort_request(
    request_controls: &RequestControls,
) -> Result<Option<RequestedServerSideSort>, ServerSideSortRequestError> {
    let control = request_controls
        .singleton(SERVER_SIDE_SORT_REQUEST_OID)
        .map_err(|err| ServerSideSortRequestError::ProtocolError(err.to_string()))?;
    let Some(control) = control else {
        return Ok(None);
    };

    let decoded = decode_server_side_sort_request_control(control.value()).map_err(|err| {
        ServerSideSortRequestError::ProtocolError(format!(
            "malformed server-side sort control: {err}"
        ))
    })?;

    Ok(Some(RequestedServerSideSort {
        keys: decoded.keys,
        critical: control.criticality(),
    }))
}

fn validate_server_side_sort_request(
    requested_sort: &RequestedServerSideSort,
) -> Result<(), ServerSideSortRequestError> {
    let mut seen_attributes = HashSet::new();
    for key in &requested_sort.keys {
        let normalized_attribute = key.attribute_type.to_ascii_lowercase();
        if !seen_attributes.insert(normalized_attribute) {
            return Err(ServerSideSortRequestError::Unsupported {
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
            return Err(ServerSideSortRequestError::Unsupported {
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

fn sort_value_for_key(entry: &DirectoryEntry, key: &SortKey) -> Option<String> {
    let attribute_name = key.attribute_type.to_ascii_lowercase();
    entry
        .attributes
        .get(&attribute_name)
        .and_then(|values| values.iter().map(|value| value.to_ascii_lowercase()).min())
}

fn sort_search_entries(entries: &mut [DirectoryEntry], requested_sort: &RequestedServerSideSort) {
    entries.sort_by(|left, right| {
        for key in &requested_sort.keys {
            let left_value = sort_value_for_key(left, key);
            let right_value = sort_value_for_key(right, key);
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

async fn reject_paged_search_request(
    socket: &mut (impl AsyncWrite + Unpin),
    message_id: u32,
    base_dn: &str,
    session: &ConnectionSession,
    request_context: &RequestContext,
    error: &PagedSearchRequestError,
) -> Result<(), ServerError> {
    if matches!(error, PagedSearchRequestError::InvalidCookie(_)) {
        record_paged_search_invalid_cookie(request_context);
    }

    let error_kind = match error {
        PagedSearchRequestError::ProtocolError(_) => "protocol_error",
        PagedSearchRequestError::InvalidCookie(_) => "invalid_cookie",
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

    send_result(
        socket,
        message_id,
        ResponseOp::SearchDone,
        error.result_code(),
        base_dn,
        error.diagnostic(),
    )
    .await
}

async fn reject_server_side_sort_request(
    socket: &mut (impl AsyncWrite + Unpin),
    message_id: u32,
    base_dn: &str,
    session: &ConnectionSession,
    request_context: &RequestContext,
    error: &ServerSideSortRequestError,
) -> Result<(), ServerError> {
    match error {
        ServerSideSortRequestError::ProtocolError(diagnostic) => {
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

            send_result(
                socket,
                message_id,
                ResponseOp::SearchDone,
                ResultCode::ProtocolError,
                base_dn,
                diagnostic.as_str(),
            )
            .await
        }
        ServerSideSortRequestError::Unsupported {
            result,
            attribute_type,
            diagnostic,
            critical,
        } => {
            increment_control_counter(request_context, "ldap_sort_failures_total", 1);
            if *result == ServerSideSortResultCode::InappropriateMatching {
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
                server_side_sort_response_control(*result, attribute_type.as_deref())?;
            let result_code = if *critical {
                ResultCode::UnavailableCriticalExtension
            } else {
                ResultCode::Success
            };
            send_result_with_controls(
                socket,
                message_id,
                ResponseOp::SearchDone,
                result_code,
                base_dn,
                diagnostic.as_str(),
                &[sort_response],
            )
            .await
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
        .map(|root_dn| dn_eq(bound_dn, root_dn))
        .unwrap_or(false)
}

pub(crate) fn can_skip_search_post_filter(
    session: &ConnectionSession,
    request_context: &RequestContext,
) -> bool {
    request_context
        .security
        .as_ref()
        .and_then(|security| security.access_control.as_ref())
        .is_none()
        || is_root_dn(session, request_context)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn log_generic_audit_event(
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

pub(crate) async fn log_simple_bind_success(request_context: &RequestContext, user_dn: &str) {
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

pub(crate) async fn log_simple_bind_failure(
    request_context: &RequestContext,
    user_dn: &str,
    reason: &str,
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
        .log_auth_failure(user_dn, &client_ip_for_audit(request_context), reason)
        .await;
}

pub(crate) async fn record_authentication_success_metadata(
    backend: &dyn DirectoryBackend,
    user_dn: &str,
) {
    if let Err(err) = backend.record_authentication_success(user_dn).await {
        error!(
            "Failed to update account authentication success metadata for {}: {}",
            user_dn, err
        );
    }
}

pub(crate) async fn record_authentication_success_metadata_with_context(
    request_context: &RequestContext,
    backend: &dyn DirectoryBackend,
    user_dn: &str,
) {
    if let Some(recorder) = request_context.auth_metadata.as_ref() {
        recorder.record_success(user_dn).await;
    } else {
        record_authentication_success_metadata(backend, user_dn).await;
    }
}

pub(crate) async fn record_authentication_failure_metadata(
    backend: &dyn DirectoryBackend,
    user_dn: &str,
) {
    if let Err(err) = backend.record_authentication_failure(user_dn).await {
        error!(
            "Failed to update account authentication failure metadata for {}: {}",
            user_dn, err
        );
    }
}

pub(crate) async fn record_authentication_failure_metadata_with_context(
    request_context: &RequestContext,
    backend: &dyn DirectoryBackend,
    user_dn: &str,
) {
    if let Some(recorder) = request_context.auth_metadata.as_ref() {
        recorder.record_failure(user_dn).await;
    } else {
        record_authentication_failure_metadata(backend, user_dn).await;
    }
}

pub(crate) fn first_server_managed_operational_attribute<I, S>(attributes: I) -> Option<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    attributes.into_iter().find_map(|attribute| {
        let attribute = attribute.as_ref();
        OperationalAttributes::is_operational(attribute).then(|| attribute.to_string())
    })
}

pub(crate) fn server_managed_operational_attribute_diagnostic(attribute: &str) -> String {
    format!("operational attribute {attribute} is server-managed")
}

pub(crate) async fn log_sasl_bind(
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

pub(crate) async fn log_anonymous_bind(request_context: &RequestContext) {
    let session = ConnectionSession::default();
    if let Some(security) = request_context.security.as_ref()
        && security.audit_config.log_authentication
    {
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
pub(crate) async fn authorize_operation(
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

#[allow(clippy::too_many_arguments)]
pub(crate) async fn authorize_attribute_permissions(
    socket: &mut (impl AsyncWrite + Unpin),
    backend: &dyn DirectoryBackend,
    message_id: u32,
    response_op: ResponseOp,
    session: &ConnectionSession,
    request_context: &RequestContext,
    attribute_permission: Permission,
    operation: &str,
    target_dn: &str,
    attributes: &[String],
) -> Result<bool, ServerError> {
    for attribute in attributes {
        if !authorize_operation(
            socket,
            Some(backend),
            message_id,
            response_op,
            session,
            request_context,
            attribute_permission,
            operation,
            target_dn,
            Some(attribute),
        )
        .await?
        {
            return Ok(false);
        }
    }

    Ok(true)
}

pub(crate) async fn filter_search_entry_for_read_access(
    backend: &dyn DirectoryBackend,
    session: &ConnectionSession,
    request_context: &RequestContext,
    entry: DirectoryEntry,
) -> Option<DirectoryEntry> {
    let Some(security) = request_context.security.as_ref() else {
        return Some(entry);
    };
    let Some(aci_engine) = security.access_control.as_ref() else {
        return Some(entry);
    };

    if is_root_dn(session, request_context) {
        return Some(entry);
    }

    match aci_engine
        .filter_readable_entry_with_backend(session.bound_dn(), &entry, backend)
        .await
    {
        Ok(filtered_entry) => filtered_entry,
        Err(err) => {
            warn!("Failed to apply search read ACI for {}: {}", entry.dn, err);
            None
        }
    }
}

pub(crate) async fn filter_search_entries_for_read_access(
    backend: &dyn DirectoryBackend,
    session: &ConnectionSession,
    request_context: &RequestContext,
    entries: Vec<DirectoryEntry>,
) -> Vec<DirectoryEntry> {
    let mut readable_entries = Vec::with_capacity(entries.len());
    for entry in entries {
        if let Some(entry) =
            filter_search_entry_for_read_access(backend, session, request_context, entry).await
        {
            readable_entries.push(entry);
        }
    }
    readable_entries
}

struct SaslPlainCredentialsRef<'a> {
    authzid: &'a str,
    authcid: &'a str,
    password: &'a [u8],
}

fn parse_sasl_plain_credentials(
    credentials: Option<&[u8]>,
) -> Result<SaslPlainCredentialsRef<'_>, &'static str> {
    let Some(credentials) = credentials else {
        return Err("SASL PLAIN requires credentials");
    };

    let mut parts = credentials.split(|&byte| byte == 0);
    let Some(authzid_bytes) = parts.next() else {
        return Err("invalid SASL PLAIN credential format");
    };
    let Some(authcid_bytes) = parts.next() else {
        return Err("invalid SASL PLAIN credential format");
    };
    let Some(password) = parts.next() else {
        return Err("invalid SASL PLAIN credential format");
    };
    if parts.next().is_some() {
        return Err("invalid SASL PLAIN credential format");
    }

    let authzid =
        std::str::from_utf8(authzid_bytes).map_err(|_| "invalid SASL authzid encoding")?;
    let authcid =
        std::str::from_utf8(authcid_bytes).map_err(|_| "invalid SASL authcid encoding")?;

    Ok(SaslPlainCredentialsRef {
        authzid,
        authcid,
        password,
    })
}

#[allow(clippy::too_many_arguments)]
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
                if !security_policy(request_context).allow_anonymous_bind {
                    session.clear();
                    log_simple_bind_failure(
                        request_context,
                        "anonymous",
                        "anonymous bind is disabled by security policy",
                    )
                    .await;
                    send_bind_response(
                        socket,
                        message_id,
                        ResultCode::InappropriateAuthentication,
                        "anonymous bind is disabled by security policy",
                    )
                    .await?;
                    return Ok(());
                }
                session.clear();
                log_anonymous_bind(request_context).await;
                send_bind_success(socket, message_id).await?;
                return Ok(());
            }

            if !connection_is_secure
                && !security_policy(request_context).allow_cleartext_simple_bind
            {
                session.clear();
                log_simple_bind_failure(
                    request_context,
                    &dn,
                    "simple bind requires TLS by security policy",
                )
                .await;
                send_bind_response(
                    socket,
                    message_id,
                    ResultCode::ConfidentialityRequired,
                    "simple bind requires TLS",
                )
                .await?;
                return Ok(());
            }

            match backend.authenticate(&dn, password.as_ref()).await {
                Ok(true) => {
                    session.bind(dn);
                    record_authentication_success_metadata_with_context(
                        request_context,
                        backend,
                        session.bound_dn().unwrap_or(""),
                    )
                    .await;
                    log_simple_bind_success(
                        request_context,
                        session.bound_dn().unwrap_or("anonymous"),
                    )
                    .await;
                    send_bind_success(socket, message_id).await?;
                }
                Ok(false) => {
                    session.clear();
                    record_authentication_failure_metadata_with_context(
                        request_context,
                        backend,
                        &dn,
                    )
                    .await;
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

            if !security_policy(request_context).allow_sasl_plain {
                session.clear();
                log_sasl_bind(
                    request_context,
                    request.name.0.as_ref().trim(),
                    "PLAIN",
                    false,
                    Some("SASL PLAIN is disabled by security policy"),
                )
                .await;
                send_bind_response(
                    socket,
                    message_id,
                    ResultCode::AuthMethodNotSupported,
                    "SASL PLAIN is disabled by security policy",
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

            let parsed = match parse_sasl_plain_credentials(credentials.credentials.as_deref()) {
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
                parsed.authcid.to_owned()
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

            if !parsed.authzid.is_empty() && !parsed.authzid.eq_ignore_ascii_case(&bind_dn) {
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

            match backend.authenticate(&bind_dn, parsed.password).await {
                Ok(true) => {
                    session.bind(bind_dn.clone());
                    record_authentication_success_metadata_with_context(
                        request_context,
                        backend,
                        &bind_dn,
                    )
                    .await;
                    log_sasl_bind(request_context, &bind_dn, "PLAIN", true, None).await;
                    send_bind_success(socket, message_id).await?;
                }
                Ok(false) => {
                    session.clear();
                    record_authentication_failure_metadata_with_context(
                        request_context,
                        backend,
                        &bind_dn,
                    )
                    .await;
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
    let op_name = response_op_name(op);
    trace_search(format_args!(
        "send_result_with_controls start op={op_name} message_id={message_id} bytes={}",
        encoded.len()
    ));
    socket.write_all(&encoded).await?;
    trace_search(format_args!(
        "send_result_with_controls complete op={op_name} message_id={message_id}"
    ));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn send_result_with_referrals(
    socket: &mut (impl AsyncWrite + Unpin),
    message_id: u32,
    op: ResponseOp,
    result_code: ResultCode,
    matched_dn: impl Into<String>,
    diagnostic_message: impl Into<String>,
    referrals: &[String],
    controls: &[LdapControl],
) -> Result<(), ServerError> {
    let encoded = encode_result_response_with_referrals(
        message_id,
        op,
        result_code,
        matched_dn,
        diagnostic_message,
        referrals,
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

#[allow(clippy::too_many_arguments)]
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

async fn send_search_reference_with_controls(
    socket: &mut (impl AsyncWrite + Unpin),
    message_id: u32,
    referrals: &[String],
    controls: &[LdapControl],
) -> Result<(), ServerError> {
    let encoded = encode_search_reference_with_controls(message_id, referrals, controls)?;
    socket.write_all(&encoded).await?;
    Ok(())
}

async fn send_intermediate_response(
    socket: &mut (impl AsyncWrite + Unpin),
    message_id: u32,
    response_name: Option<String>,
    response_value: Option<Vec<u8>>,
    controls: &[LdapControl],
) -> Result<(), ServerError> {
    let encoded =
        encode_intermediate_response(message_id, response_name, response_value, controls)?;
    socket.write_all(&encoded).await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn try_handle_virtual_search_request(
    socket: &mut (impl AsyncWrite + Unpin),
    backend: &dyn DirectoryBackend,
    schema: &LdapSchema,
    runtime_config: &LegacyServerConfig,
    message_id: u32,
    base_dn: &str,
    scope: ldap_parser::ldap::SearchScope,
    session: &ConnectionSession,
    request_context: &RequestContext,
    requested_attributes: &[String],
    types_only: bool,
    result_controls: &[LdapControl],
    connection_is_secure: bool,
    starttls_available: bool,
) -> Result<bool, ServerError> {
    if scope != ldap_parser::ldap::SearchScope::BaseObject {
        return Ok(false);
    }

    if base_dn.is_empty() {
        if security_policy(request_context).root_dse_requires_authentication
            && !session.is_authenticated()
        {
            send_result(
                socket,
                message_id,
                ResponseOp::SearchDone,
                ResultCode::InsufficientAccessRights,
                "",
                "Root DSE requires authentication",
            )
            .await?;
            return Ok(true);
        }

        let supported_control_oids =
            active_runtime_control_registry().root_dse_supported_control_oids();
        let supported_sasl_mechanisms =
            crate::search_protocol::supported_legacy_sasl_mechanisms_for_context(
                connection_is_secure,
            );
        let attributes = match crate::search_protocol::build_root_dse_attributes(
            backend,
            &runtime_config.naming_contexts,
            &runtime_config.subschema_dn,
            connection_is_secure,
            starttls_available,
            &supported_control_oids,
            &supported_sasl_mechanisms,
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
        send_result_with_controls(
            socket,
            message_id,
            ResponseOp::SearchDone,
            ResultCode::Success,
            "",
            "",
            result_controls,
        )
        .await?;
        return Ok(true);
    }

    if base_dn.eq_ignore_ascii_case(&runtime_config.subschema_dn) {
        let attributes = crate::search_protocol::build_subschema_attributes(schema);
        send_virtual_search_entry(
            socket,
            message_id,
            &runtime_config.subschema_dn,
            &attributes,
            requested_attributes,
            types_only,
        )
        .await?;
        send_result_with_controls(
            socket,
            message_id,
            ResponseOp::SearchDone,
            ResultCode::Success,
            &runtime_config.subschema_dn,
            "",
            result_controls,
        )
        .await?;
        return Ok(true);
    }

    Ok(false)
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
    let selected_attributes = crate::search_protocol::select_virtual_attributes(
        available_attributes,
        requested_attributes,
    );
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

fn map_backend_error(err: &BackendError) -> ResultCode {
    match err {
        BackendError::AlreadyExists => ResultCode::EntryAlreadyExists,
        BackendError::NotFound => ResultCode::NoSuchObject,
        BackendError::InvalidDn(_) => ResultCode::InvalidDnSyntax,
        BackendError::Storage(_) => ResultCode::Unavailable,
    }
}

fn map_filter_schema_error(err: &FilterSchemaError) -> ResultCode {
    match err {
        FilterSchemaError::UndefinedAttribute(_) => ResultCode::UndefinedAttributeType,
        FilterSchemaError::InappropriateMatching(_) => ResultCode::InappropriateMatching,
        FilterSchemaError::InvalidAttributeSyntax(_) => ResultCode::InvalidAttributeSyntax,
        FilterSchemaError::InvalidFilter(_) => ResultCode::ProtocolError,
    }
}

fn diagnostic_for_error(err: &BackendError) -> &'static str {
    match err {
        BackendError::AlreadyExists => "entry already exists",
        BackendError::NotFound => "no such object",
        BackendError::InvalidDn(_) => "invalid DN syntax",
        BackendError::Storage(_) => "backend failure",
    }
}

pub async fn handle_search_request(
    socket: &mut (impl AsyncRead + AsyncWrite + Unpin),
    backend: &dyn DirectoryBackend,
    message_id: u32,
    request: SearchRequest<'_>,
) -> Result<(), ServerError> {
    handle_search_request_with_controls(
        socket,
        backend,
        message_id,
        request,
        &RequestControls::default(),
    )
    .await
}

pub async fn handle_search_request_with_controls(
    socket: &mut (impl AsyncRead + AsyncWrite + Unpin),
    backend: &dyn DirectoryBackend,
    message_id: u32,
    request: SearchRequest<'_>,
    request_controls: &RequestControls,
) -> Result<(), ServerError> {
    let session = ConnectionSession::default();
    let schema = LdapSchema::default();
    let runtime_config = LegacyServerConfig::default();
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
        request_controls,
        false,
        false,
    )
    .await
}

#[cfg_attr(not(test), allow(dead_code))]
#[allow(clippy::too_many_arguments)]
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

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_search_request_with_context_and_registry(
    socket: &mut (impl AsyncRead + AsyncWrite + Unpin),
    backend: &dyn DirectoryBackend,
    schema: &LdapSchema,
    runtime_config: &LegacyServerConfig,
    message_id: u32,
    request: SearchRequest<'_>,
    session: &ConnectionSession,
    operation_registry: &mut ConnectionOperationRegistry,
    request_context: &RequestContext,
    request_controls: &RequestControls,
    connection_is_secure: bool,
    starttls_available: bool,
) -> Result<(), ServerError> {
    let base_dn = request.base_object.0.as_ref().trim().to_owned();
    let attribute_selection: Vec<String> = request
        .attributes
        .iter()
        .map(|attribute| attribute.0.as_ref().trim().to_owned())
        .collect();
    let deref_aliases = request.deref_aliases;
    if let Err(diagnostic) = validate_search_deref_aliases(deref_aliases) {
        send_result(
            socket,
            message_id,
            ResponseOp::SearchDone,
            ResultCode::ProtocolError,
            &base_dn,
            diagnostic,
        )
        .await?;
        return Ok(());
    }

    let search_deadline = if request.time_limit == 0 {
        None
    } else {
        Some(Instant::now() + Duration::from_secs(request.time_limit as u64))
    };
    let paged_results = match parse_paged_results_request(request_controls) {
        Ok(controls) => controls,
        Err(err) => {
            reject_paged_search_request(
                socket,
                message_id,
                &base_dn,
                session,
                request_context,
                &err,
            )
            .await?;
            return Ok(());
        }
    };

    if paged_results.is_some() {
        increment_control_counter(request_context, "ldap_paged_search_requests_total", 1);
    }

    let requested_sort = match parse_server_side_sort_request(request_controls) {
        Ok(sort) => sort,
        Err(err) => {
            reject_server_side_sort_request(
                socket,
                message_id,
                &base_dn,
                session,
                request_context,
                &err,
            )
            .await?;
            return Ok(());
        }
    };

    if requested_sort.is_some() {
        increment_control_counter(request_context, "ldap_sort_requests_total", 1);
    }

    if let Some(requested_sort) = requested_sort.as_ref()
        && let Err(err) = validate_server_side_sort_request(requested_sort)
    {
        reject_server_side_sort_request(
            socket,
            message_id,
            &base_dn,
            session,
            request_context,
            &err,
        )
        .await?;
        return Ok(());
    }

    let requested_sync = match parse_sync_request_control(request_controls) {
        Ok(sync) => sync,
        Err(err) => {
            reject_sync_request(socket, message_id, &base_dn, &err).await?;
            return Ok(());
        }
    };

    if requested_sync.is_some() {
        increment_control_counter(request_context, "ldap_sync_requests_total", 1);
    }

    if requested_sync.is_some() && paged_results.is_some() {
        let err = SyncRequestError::Unsupported(
            "sync request control cannot be combined with paged results".to_string(),
        );
        reject_sync_request(socket, message_id, &base_dn, &err).await?;
        return Ok(());
    }

    if requested_sync.is_some() && requested_sort.is_some() {
        let err = SyncRequestError::Unsupported(
            "sync request control cannot be combined with server-side sort".to_string(),
        );
        reject_sync_request(socket, message_id, &base_dn, &err).await?;
        return Ok(());
    }

    let manage_dsa_it = match parse_manage_dsa_it_request(request_controls) {
        Ok(manage_dsa_it) => manage_dsa_it,
        Err(ManageDsaItRequestError::ProtocolError(diagnostic)) => {
            send_result(
                socket,
                message_id,
                ResponseOp::SearchDone,
                ResultCode::ProtocolError,
                &base_dn,
                diagnostic,
            )
            .await?;
            return Ok(());
        }
    };

    if manage_dsa_it {
        increment_control_counter(request_context, "ldap_manage_dsa_it_requests_total", 1);
    }

    if let Some(control) = paged_results.as_ref()
        && control.size == 0
        && control.cookie.is_empty()
    {
        let err = PagedSearchRequestError::ProtocolError(
            "paged results page size must be greater than zero on the initial request".to_string(),
        );
        reject_paged_search_request(socket, message_id, &base_dn, session, request_context, &err)
            .await?;
        return Ok(());
    }

    let is_virtual_base =
        base_dn.is_empty() || base_dn.eq_ignore_ascii_case(&runtime_config.subschema_dn);
    let mut virtual_result_controls = Vec::new();
    if requested_sort.is_some() && is_virtual_base {
        virtual_result_controls.push(server_side_sort_response_control(
            ServerSideSortResultCode::Success,
            None,
        )?);
    }
    if let Some(control) = paged_results.as_ref() {
        if !control.cookie.is_empty() && is_virtual_base {
            let err = PagedSearchRequestError::InvalidCookie(
                "paged results cookie is not valid for this search sequence".to_string(),
            );
            reject_paged_search_request(
                socket,
                message_id,
                &base_dn,
                session,
                request_context,
                &err,
            )
            .await?;
            return Ok(());
        }

        if is_virtual_base {
            virtual_result_controls.push(paged_results_response_control(1, &[])?);
        }
    }

    if try_handle_virtual_search_request(
        socket,
        backend,
        schema,
        runtime_config,
        message_id,
        &base_dn,
        request.scope,
        session,
        request_context,
        &attribute_selection,
        request.types_only,
        &virtual_result_controls,
        connection_is_secure,
        starttls_available,
    )
    .await?
    {
        return Ok(());
    }

    if let Err(err) = validate_search_filter(schema, &request.filter) {
        let diagnostic = err.to_string();
        send_result(
            socket,
            message_id,
            ResponseOp::SearchDone,
            map_filter_schema_error(&err),
            &base_dn,
            &diagnostic,
        )
        .await?;
        operation_registry.finish(message_id, FinishedOperationState::Completed);
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

    let effective_base_dn = match resolve_search_base_dn(backend, &base_dn, deref_aliases).await {
        Ok(dn) => dn,
        Err((result_code, diagnostic)) => {
            increment_control_counter(
                request_context,
                "ldap_search_alias_dereference_failures_total",
                1,
            );
            log_generic_audit_event(
                request_context,
                session,
                AuditLevel::Warning,
                AuditEventType::Authorization,
                "search_alias_deref",
                false,
                Some(base_dn.as_str()),
                Some(diagnostic.as_str()),
                Vec::new(),
            )
            .await;
            send_result(
                socket,
                message_id,
                ResponseOp::SearchDone,
                result_code,
                &base_dn,
                diagnostic.as_str(),
            )
            .await?;
            operation_registry.finish(message_id, FinishedOperationState::Completed);
            return Ok(());
        }
    };

    let base_object_entry = if request.scope == ldap_parser::ldap::SearchScope::BaseObject {
        backend.get_entry(&effective_base_dn).await.map_err(|err| {
            ServerError::Io(std::io::Error::other(format!(
                "failed to load search base {}: {}",
                effective_base_dn, err
            )))
        })?
    } else {
        None
    };

    if !manage_dsa_it
        && request.scope == ldap_parser::ldap::SearchScope::BaseObject
        && let Some(base_entry) = base_object_entry.as_ref()
        && entry_is_referral(base_entry)
    {
        match referral_urls_for_entry(base_entry) {
            Ok(referrals) => {
                increment_control_counter(request_context, "ldap_referral_results_total", 1);
                log_generic_audit_event(
                    request_context,
                    session,
                    AuditLevel::Info,
                    AuditEventType::Authorization,
                    "search_referral",
                    true,
                    Some(effective_base_dn.as_str()),
                    Some("base search resolved to referral"),
                    vec![("referral_count".to_string(), referrals.len().to_string())],
                )
                .await;
                send_result_with_referrals(
                    socket,
                    message_id,
                    ResponseOp::SearchDone,
                    ResultCode::Referral,
                    &effective_base_dn,
                    "search base is a referral",
                    &referrals,
                    &[],
                )
                .await?;
                operation_registry.finish(message_id, FinishedOperationState::Completed);
                return Ok(());
            }
            Err(diagnostic) => {
                increment_control_counter(
                    request_context,
                    "ldap_referral_processing_failures_total",
                    1,
                );
                send_result(
                    socket,
                    message_id,
                    ResponseOp::SearchDone,
                    ResultCode::OperationsError,
                    &effective_base_dn,
                    diagnostic,
                )
                .await?;
                operation_registry.finish(message_id, FinishedOperationState::Completed);
                return Ok(());
            }
        }
    }

    if let Some(sync_request) = requested_sync.as_ref() {
        return handle_sync_search_request(
            socket,
            backend,
            schema,
            message_id,
            &request,
            &effective_base_dn,
            &attribute_selection,
            sync_request,
            manage_dsa_it,
            session,
            operation_registry,
            request_context,
            search_deadline,
        )
        .await;
    }

    operation_registry.register(message_id, ConnectionOperationKind::Search, true);

    let search_signature = paged_results.as_ref().map(|_| {
        SearchRequestSignature::from_request(
            &base_dn,
            &request,
            &attribute_selection,
            requested_sort.as_ref().map(|sort| sort.keys.as_slice()),
        )
    });

    if let Some(control) = paged_results
        .as_ref()
        .filter(|control| !control.cookie.is_empty())
    {
        let Some(cursor) = operation_registry.paged_search(control.cookie.as_slice()) else {
            let err = PagedSearchRequestError::InvalidCookie(
                "paged results cookie is not valid for this search sequence".to_string(),
            );
            reject_paged_search_request(
                socket,
                message_id,
                &base_dn,
                session,
                request_context,
                &err,
            )
            .await?;
            operation_registry.finish(message_id, FinishedOperationState::Completed);
            return Ok(());
        };

        if Some(&cursor.signature) != search_signature.as_ref() {
            let err = PagedSearchRequestError::InvalidCookie(
                "paged results cookie does not match the active search sequence".to_string(),
            );
            reject_paged_search_request(
                socket,
                message_id,
                &base_dn,
                session,
                request_context,
                &err,
            )
            .await?;
            operation_registry.finish(message_id, FinishedOperationState::Completed);
            return Ok(());
        }

        if control.size == 0 {
            operation_registry.remove_paged_search(control.cookie.as_slice());
            increment_control_counter(request_context, "ldap_paged_search_abandoned_total", 1);
            let response_control = paged_results_response_control(0, &[])?;
            send_result_with_controls(
                socket,
                message_id,
                ResponseOp::SearchDone,
                ResultCode::Success,
                &base_dn,
                "",
                &[response_control],
            )
            .await?;
            operation_registry.finish(message_id, FinishedOperationState::Completed);
            return Ok(());
        }

        let total_size = operation_registry
            .paged_search(control.cookie.as_slice())
            .map(|cursor| cursor.total_size() as usize)
            .unwrap_or_default();
        operation_registry.attach_paged_search_to_operation(message_id, control.cookie.clone());
        let (page_entries, result_code, diagnostic, complete) = operation_registry
            .paged_search_mut(control.cookie.as_slice())
            .expect("paged search cursor must exist after validation")
            .next_page(control.size as usize);
        if complete {
            operation_registry.remove_paged_search(control.cookie.as_slice());
        }

        let (returned, time_limit_hit) = emit_search_entries(
            socket,
            message_id,
            &page_entries,
            &attribute_selection,
            request.types_only,
            search_deadline,
        )
        .await?;
        increment_control_counter(request_context, "ldap_paged_search_pages_total", 1);

        let response_cookie = if complete || time_limit_hit {
            if time_limit_hit {
                operation_registry.remove_paged_search(control.cookie.as_slice());
            }
            Vec::new()
        } else {
            control.cookie.clone()
        };
        let response_control = paged_results_response_control(total_size, &response_cookie)?;
        let (result_code, diagnostic) = if time_limit_hit {
            (ResultCode::TimeLimitExceeded, "time limit exceeded")
        } else {
            (result_code, diagnostic)
        };
        let mut response_controls = vec![response_control];
        if requested_sort.is_some() {
            response_controls.push(server_side_sort_response_control(
                if time_limit_hit {
                    ServerSideSortResultCode::TimeLimitExceeded
                } else {
                    ServerSideSortResultCode::Success
                },
                None,
            )?);
        }
        send_result_with_controls(
            socket,
            message_id,
            ResponseOp::SearchDone,
            result_code,
            &base_dn,
            diagnostic,
            &response_controls,
        )
        .await?;
        if result_code == ResultCode::TimeLimitExceeded {
            increment_control_counter(request_context, "ldap_search_time_limit_exceeded_total", 1);
            log_generic_audit_event(
                request_context,
                session,
                AuditLevel::Warning,
                AuditEventType::Authorization,
                "search_time_limit",
                false,
                Some(base_dn.as_str()),
                Some("search time limit exceeded"),
                vec![("entries_returned".to_string(), returned.to_string())],
            )
            .await;
        }
        operation_registry.finish(message_id, FinishedOperationState::Completed);
        return Ok(());
    }

    let mut search_result_set = match collect_search_result_set(
        backend,
        schema,
        &effective_base_dn,
        base_object_entry,
        &request,
        deref_aliases,
        manage_dsa_it,
        session,
        request_context,
        search_deadline,
    )
    .await
    {
        Ok(result_set) => result_set,
        Err(err) => {
            if err.alias_dereference_failure {
                increment_control_counter(
                    request_context,
                    "ldap_search_alias_dereference_failures_total",
                    1,
                );
                log_generic_audit_event(
                    request_context,
                    session,
                    AuditLevel::Warning,
                    AuditEventType::Authorization,
                    "search_alias_deref",
                    false,
                    Some(err.target_dn.as_str()),
                    Some(err.diagnostic.as_str()),
                    Vec::new(),
                )
                .await;
            } else if err.referral_processing_failure {
                increment_control_counter(
                    request_context,
                    "ldap_referral_processing_failures_total",
                    1,
                );
                log_generic_audit_event(
                    request_context,
                    session,
                    AuditLevel::Warning,
                    AuditEventType::Authorization,
                    "search_referral",
                    false,
                    Some(err.target_dn.as_str()),
                    Some(err.diagnostic.as_str()),
                    Vec::new(),
                )
                .await;
            } else {
                error!(
                    "Search backend failure for {}: {}",
                    effective_base_dn, err.diagnostic
                );
            }

            send_result(
                socket,
                message_id,
                ResponseOp::SearchDone,
                err.result_code,
                &base_dn,
                err.diagnostic.as_str(),
            )
            .await?;
            operation_registry.finish(message_id, FinishedOperationState::Completed);
            return Ok(());
        }
    };

    if let Some(requested_sort) = requested_sort.as_ref() {
        sort_search_entries(&mut search_result_set.entries, requested_sort);
    }

    if let Some(control) = paged_results.as_ref() {
        let page_size = control.size as usize;
        let SearchResultSet {
            mut entries,
            references,
            size_limit_hit,
            time_limit_hit,
        } = search_result_set;
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
            let cursor = PagedSearchCursor {
                signature: search_signature
                    .clone()
                    .expect("paged search signature must exist"),
                total_size,
                remaining_entries,
                completion_code: if size_limit_hit {
                    ResultCode::SizeLimitExceeded
                } else {
                    ResultCode::Success
                },
                completion_diagnostic: if size_limit_hit {
                    "size limit exceeded"
                } else {
                    ""
                },
            };
            let cookie = operation_registry.remember_paged_search(cursor);
            operation_registry.attach_paged_search_to_operation(message_id, cookie.clone());
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

        let (returned, time_limit_hit) = emit_search_entries(
            socket,
            message_id,
            &page_entries,
            &attribute_selection,
            request.types_only,
            search_deadline,
        )
        .await?;
        emit_search_references(socket, message_id, &references, request_context).await?;
        increment_control_counter(request_context, "ldap_paged_search_pages_total", 1);
        if time_limit_hit && !response_cookie.is_empty() {
            operation_registry.remove_paged_search(response_cookie.as_slice());
        }
        let final_cookie = if time_limit_hit {
            Vec::new()
        } else {
            response_cookie
        };
        let response_control = paged_results_response_control(total_size, &final_cookie)?;
        let (result_code, diagnostic) = if time_limit_hit {
            (ResultCode::TimeLimitExceeded, "time limit exceeded")
        } else {
            (result_code, diagnostic)
        };
        let mut response_controls = vec![response_control];
        if requested_sort.is_some() {
            response_controls.push(server_side_sort_response_control(
                if time_limit_hit {
                    ServerSideSortResultCode::TimeLimitExceeded
                } else {
                    ServerSideSortResultCode::Success
                },
                None,
            )?);
        }
        send_result_with_controls(
            socket,
            message_id,
            ResponseOp::SearchDone,
            result_code,
            &base_dn,
            diagnostic,
            &response_controls,
        )
        .await?;
        if result_code == ResultCode::TimeLimitExceeded {
            increment_control_counter(request_context, "ldap_search_time_limit_exceeded_total", 1);
            log_generic_audit_event(
                request_context,
                session,
                AuditLevel::Warning,
                AuditEventType::Authorization,
                "search_time_limit",
                false,
                Some(base_dn.as_str()),
                Some("search time limit exceeded"),
                vec![("entries_returned".to_string(), returned.to_string())],
            )
            .await;
        }
    } else {
        let (returned, emit_time_limit_hit) = emit_search_entries(
            socket,
            message_id,
            &search_result_set.entries,
            &attribute_selection,
            request.types_only,
            search_deadline,
        )
        .await?;
        emit_search_references(
            socket,
            message_id,
            &search_result_set.references,
            request_context,
        )
        .await?;
        let (result_code, diagnostic) = if search_result_set.time_limit_hit || emit_time_limit_hit {
            increment_control_counter(request_context, "ldap_search_time_limit_exceeded_total", 1);
            log_generic_audit_event(
                request_context,
                session,
                AuditLevel::Warning,
                AuditEventType::Authorization,
                "search_time_limit",
                false,
                Some(base_dn.as_str()),
                Some("search time limit exceeded"),
                vec![("entries_returned".to_string(), returned.to_string())],
            )
            .await;
            (ResultCode::TimeLimitExceeded, "time limit exceeded")
        } else if search_result_set.size_limit_hit {
            (ResultCode::SizeLimitExceeded, "size limit exceeded")
        } else {
            (ResultCode::Success, "")
        };

        if requested_sort.is_some() {
            let sort_response = server_side_sort_response_control(
                if search_result_set.time_limit_hit || emit_time_limit_hit {
                    ServerSideSortResultCode::TimeLimitExceeded
                } else {
                    ServerSideSortResultCode::Success
                },
                None,
            )?;
            send_result_with_controls(
                socket,
                message_id,
                ResponseOp::SearchDone,
                result_code,
                &base_dn,
                diagnostic,
                &[sort_response],
            )
            .await?;
        } else {
            send_result(
                socket,
                message_id,
                ResponseOp::SearchDone,
                result_code,
                &base_dn,
                diagnostic,
            )
            .await?;
        }
    }

    operation_registry.finish(message_id, FinishedOperationState::Completed);

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn collect_search_result_set(
    backend: &dyn DirectoryBackend,
    schema: &LdapSchema,
    effective_base_dn: &str,
    base_object_entry: Option<DirectoryEntry>,
    request: &SearchRequest<'_>,
    deref_aliases: ldap_parser::ldap::DerefAliases,
    manage_dsa_it: bool,
    session: &ConnectionSession,
    request_context: &RequestContext,
    search_deadline: Option<Instant>,
) -> Result<SearchResultSet, SearchExecutionError> {
    let prepared_filter =
        prepare_search_filter_with_schema(schema, &request.filter).map_err(|err| {
            SearchExecutionError {
                result_code: map_filter_schema_error(&err),
                diagnostic: err.to_string(),
                target_dn: effective_base_dn.to_string(),
                alias_dereference_failure: false,
                referral_processing_failure: false,
            }
        })?;

    if request.scope == ldap_parser::ldap::SearchScope::BaseObject {
        return collect_base_object_search_result_set(
            backend,
            &prepared_filter,
            effective_base_dn,
            base_object_entry,
            request,
            deref_aliases,
            manage_dsa_it,
            session,
            request_context,
            search_deadline,
        )
        .await;
    }

    let search_hint = prepared_filter.search_candidate_hint();
    let exact_index_hint = prepared_filter.exact_index_coverage_hint();
    trace_search(format_args!(
        "collect_search_result_set start base={effective_base_dn} scope={} hint={:?}",
        request.scope.0, search_hint
    ));
    let search_report = backend
        .search_entries_with_hint_report(effective_base_dn, request.scope, search_hint.clone())
        .await
        .map_err(|err| SearchExecutionError {
            result_code: map_backend_error(&err),
            diagnostic: diagnostic_for_error(&err).to_string(),
            target_dn: effective_base_dn.to_string(),
            alias_dereference_failure: false,
            referral_processing_failure: false,
        })?;
    let index_covers_filter = search_report.hint_covers_filter
        && exact_index_hint.as_ref() == search_hint.as_ref()
        && !should_deref_search_candidates(deref_aliases)
        && can_skip_search_post_filter(session, request_context);
    let entries = search_report.entries;
    trace_search(format_args!(
        "collect_search_result_set loaded {} candidate entries for base={effective_base_dn}",
        entries.len()
    ));

    let mut collected = Vec::new();
    let mut references = Vec::new();
    let mut size_limit_hit = false;
    let mut time_limit_hit = false;
    let mut returned_dns = HashSet::new();

    for entry in entries {
        if let Some(deadline) = search_deadline
            && Instant::now() >= deadline
        {
            time_limit_hit = true;
            break;
        }

        let entry = resolve_search_candidate_entry(backend, &entry, deref_aliases)
            .await
            .map_err(|(result_code, diagnostic)| SearchExecutionError {
                result_code,
                diagnostic,
                target_dn: entry.dn.clone(),
                alias_dereference_failure: true,
                referral_processing_failure: false,
            })?;

        if entry_is_referral(&entry) && !manage_dsa_it {
            let referral_urls =
                referral_urls_for_entry(&entry).map_err(|diagnostic| SearchExecutionError {
                    result_code: ResultCode::OperationsError,
                    diagnostic,
                    target_dn: entry.dn.clone(),
                    alias_dereference_failure: false,
                    referral_processing_failure: true,
                })?;
            references.push(referral_urls);
            continue;
        }

        let Some(entry) =
            filter_search_entry_for_read_access(backend, session, request_context, entry).await
        else {
            continue;
        };

        if !index_covers_filter
            && !prepared_filter
                .matches_entry(&entry)
                .map_err(|err| search_filter_execution_error(err, &entry.dn))?
        {
            continue;
        }

        if !returned_dns.insert(normalize_search_dn(&entry.dn)) {
            continue;
        }

        if request.size_limit != 0 && collected.len() >= request.size_limit as usize {
            size_limit_hit = true;
            break;
        }

        collected.push(entry);
    }

    if !time_limit_hit
        && let Some(deadline) = search_deadline
        && Instant::now() >= deadline
    {
        time_limit_hit = true;
    }

    Ok(SearchResultSet {
        entries: collected,
        references,
        size_limit_hit,
        time_limit_hit,
    })
}

#[allow(clippy::too_many_arguments)]
async fn collect_base_object_search_result_set(
    backend: &dyn DirectoryBackend,
    prepared_filter: &PreparedLdapFilter,
    effective_base_dn: &str,
    base_object_entry: Option<DirectoryEntry>,
    _request: &SearchRequest<'_>,
    deref_aliases: ldap_parser::ldap::DerefAliases,
    manage_dsa_it: bool,
    session: &ConnectionSession,
    request_context: &RequestContext,
    search_deadline: Option<Instant>,
) -> Result<SearchResultSet, SearchExecutionError> {
    trace_search(format_args!(
        "collect_search_result_set base-object fast path base={effective_base_dn}"
    ));

    if let Some(deadline) = search_deadline
        && Instant::now() >= deadline
    {
        return Ok(SearchResultSet {
            entries: Vec::new(),
            references: Vec::new(),
            size_limit_hit: false,
            time_limit_hit: true,
        });
    }

    let entry = match base_object_entry {
        Some(entry) => Some(entry),
        None => backend
            .get_entry(effective_base_dn)
            .await
            .map_err(|err| SearchExecutionError {
                result_code: map_backend_error(&err),
                diagnostic: diagnostic_for_error(&err).to_string(),
                target_dn: effective_base_dn.to_string(),
                alias_dereference_failure: false,
                referral_processing_failure: false,
            })?,
    };
    let Some(entry) = entry else {
        return Ok(SearchResultSet {
            entries: Vec::new(),
            references: Vec::new(),
            size_limit_hit: false,
            time_limit_hit: false,
        });
    };

    if let Some(deadline) = search_deadline
        && Instant::now() >= deadline
    {
        return Ok(SearchResultSet {
            entries: Vec::new(),
            references: Vec::new(),
            size_limit_hit: false,
            time_limit_hit: true,
        });
    }

    let entry = resolve_search_candidate_entry(backend, &entry, deref_aliases)
        .await
        .map_err(|(result_code, diagnostic)| SearchExecutionError {
            result_code,
            diagnostic,
            target_dn: entry.dn.clone(),
            alias_dereference_failure: true,
            referral_processing_failure: false,
        })?;

    if entry_is_referral(&entry) && !manage_dsa_it {
        let referral_urls =
            referral_urls_for_entry(&entry).map_err(|diagnostic| SearchExecutionError {
                result_code: ResultCode::OperationsError,
                diagnostic,
                target_dn: entry.dn.clone(),
                alias_dereference_failure: false,
                referral_processing_failure: true,
            })?;
        return Ok(SearchResultSet {
            entries: Vec::new(),
            references: vec![referral_urls],
            size_limit_hit: false,
            time_limit_hit: false,
        });
    }

    let Some(entry) =
        filter_search_entry_for_read_access(backend, session, request_context, entry).await
    else {
        return Ok(SearchResultSet {
            entries: Vec::new(),
            references: Vec::new(),
            size_limit_hit: false,
            time_limit_hit: false,
        });
    };

    if !prepared_filter
        .matches_entry(&entry)
        .map_err(|err| search_filter_execution_error(err, &entry.dn))?
    {
        return Ok(SearchResultSet {
            entries: Vec::new(),
            references: Vec::new(),
            size_limit_hit: false,
            time_limit_hit: false,
        });
    }

    Ok(SearchResultSet {
        entries: vec![entry],
        references: Vec::new(),
        size_limit_hit: false,
        time_limit_hit: false,
    })
}

#[allow(clippy::manual_is_multiple_of)]
fn search_progress_checkpoint(returned: usize) -> bool {
    returned % 100 == 0
}

async fn emit_search_entries(
    socket: &mut (impl AsyncWrite + Unpin),
    message_id: u32,
    entries: &[DirectoryEntry],
    attribute_selection: &[String],
    types_only: bool,
    search_deadline: Option<Instant>,
) -> Result<(usize, bool), ServerError> {
    const SEARCH_ENTRY_WRITE_BATCH_BYTES: usize = 64 * 1024;

    trace_search(format_args!(
        "emit_search_entries start count={}",
        entries.len()
    ));

    // Preserve partial-result time limit behavior by checking the deadline around
    // each individual write when the client requested a time-limited search.
    if search_deadline.is_some() {
        let mut returned = 0usize;
        for entry in entries {
            if let Some(deadline) = search_deadline
                && Instant::now() >= deadline
            {
                trace_search(format_args!(
                    "emit_search_entries deadline hit after {} entries",
                    returned
                ));
                return Ok((returned, true));
            }

            let attributes = select_attributes(entry, attribute_selection);
            send_search_entry_with_controls(
                socket,
                message_id,
                entry,
                &attributes,
                types_only,
                &[],
            )
            .await?;
            returned += 1;

            if search_progress_checkpoint(returned) || returned == entries.len() {
                trace_search(format_args!(
                    "emit_search_entries progress returned={returned}/{}",
                    entries.len()
                ));
            }

            if let Some(deadline) = search_deadline
                && Instant::now() >= deadline
            {
                trace_search(format_args!(
                    "emit_search_entries deadline hit after send {} entries",
                    returned
                ));
                return Ok((returned, true));
            }
        }

        trace_search(format_args!(
            "emit_search_entries complete returned={returned}"
        ));
        return Ok((returned, false));
    }

    let mut returned = 0usize;
    let mut pending_bytes = Vec::with_capacity(SEARCH_ENTRY_WRITE_BATCH_BYTES);
    let mut pending_entries = 0usize;
    for entry in entries {
        let attributes = select_attributes(entry, attribute_selection);
        let encoded =
            encode_search_entry_with_controls(message_id, entry, &attributes, types_only, &[])?;
        pending_bytes.extend_from_slice(&encoded);
        pending_entries += 1;

        if pending_bytes.len() >= SEARCH_ENTRY_WRITE_BATCH_BYTES {
            socket.write_all(&pending_bytes).await?;
            returned += pending_entries;
            pending_bytes.clear();
            pending_entries = 0;
        }

        let progress_returned = returned + pending_entries;
        if search_progress_checkpoint(progress_returned) || progress_returned == entries.len() {
            trace_search(format_args!(
                "emit_search_entries progress returned={progress_returned}/{}",
                entries.len()
            ));
        }
    }

    if !pending_bytes.is_empty() {
        socket.write_all(&pending_bytes).await?;
        returned += pending_entries;
    }

    trace_search(format_args!(
        "emit_search_entries complete returned={returned}"
    ));
    Ok((returned, false))
}

async fn emit_search_references(
    socket: &mut (impl AsyncWrite + Unpin),
    message_id: u32,
    references: &[Vec<String>],
    request_context: &RequestContext,
) -> Result<(), ServerError> {
    for referrals in references {
        send_search_reference_with_controls(socket, message_id, referrals, &[]).await?;
    }
    if !references.is_empty() {
        increment_control_counter(
            request_context,
            "ldap_search_references_total",
            references.len() as u64,
        );
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn extract_search_hint(filter: &Filter<'_>) -> Option<SearchCandidateHint> {
    crate::ldap_filter_eval::extract_search_candidate_hint(filter)
}

fn trace_search(message: std::fmt::Arguments<'_>) {
    if std::env::var_os("OPENDR_TRACE_SEARCH").is_some() {
        eprintln!("trace_search: {message}");
    }
}

fn response_op_name(op: ResponseOp) -> &'static str {
    match op {
        ResponseOp::SearchDone => "SearchDone",
        ResponseOp::Modify => "Modify",
        ResponseOp::Add => "Add",
        ResponseOp::Delete => "Delete",
        ResponseOp::ModifyDn => "ModifyDn",
        ResponseOp::Compare => "Compare",
        ResponseOp::Extended => "Extended",
    }
}

fn should_deref_search_base(deref_aliases: ldap_parser::ldap::DerefAliases) -> bool {
    matches!(deref_aliases.0, 2 | 3)
}

fn should_deref_search_candidates(deref_aliases: ldap_parser::ldap::DerefAliases) -> bool {
    matches!(deref_aliases.0, 1 | 3)
}

fn validate_search_deref_aliases(
    deref_aliases: ldap_parser::ldap::DerefAliases,
) -> Result<(), &'static str> {
    match deref_aliases.0 {
        0..=3 => Ok(()),
        _ => Err(
            "derefAliases must be one of neverDerefAliases(0), derefInSearching(1), derefFindingBaseObj(2), or derefAlways(3)",
        ),
    }
}

fn entry_is_alias(entry: &DirectoryEntry) -> bool {
    entry
        .attributes
        .get("objectclass")
        .map(|values| {
            values
                .iter()
                .any(|value| value.eq_ignore_ascii_case("alias"))
        })
        .unwrap_or(false)
        && entry.attributes.contains_key("aliasedobjectname")
}

fn alias_target_dn(entry: &DirectoryEntry) -> Option<&str> {
    entry
        .attributes
        .get("aliasedobjectname")
        .and_then(|values| values.first())
        .map(String::as_str)
}

pub(crate) fn entry_is_referral(entry: &DirectoryEntry) -> bool {
    entry
        .attributes
        .get("objectclass")
        .map(|values| {
            values
                .iter()
                .any(|value| value.eq_ignore_ascii_case("referral"))
        })
        .unwrap_or(false)
        && entry
            .attributes
            .get("ref")
            .is_some_and(|values| !values.is_empty())
}

pub(crate) fn referral_urls_for_entry(entry: &DirectoryEntry) -> Result<Vec<String>, String> {
    let urls = entry
        .attributes
        .get("ref")
        .cloned()
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

fn normalize_search_dn(dn: &str) -> String {
    dn.trim().to_ascii_lowercase()
}

async fn resolve_alias_chain(
    backend: &dyn DirectoryBackend,
    entry: &DirectoryEntry,
    visited_dns: &mut HashSet<String>,
) -> Result<DirectoryEntry, (ResultCode, String)> {
    let current_dn = normalize_search_dn(&entry.dn);
    if !visited_dns.insert(current_dn) {
        return Err((
            ResultCode::LoopDetect,
            format!("alias loop detected for {}", entry.dn),
        ));
    }

    let Some(target_dn) = alias_target_dn(entry) else {
        return Err((
            ResultCode::AliasProblem,
            format!("alias {} is missing aliasedObjectName", entry.dn),
        ));
    };

    let Some(target_entry) = backend.get_entry(target_dn).await.map_err(|err| {
        (
            map_backend_error(&err),
            diagnostic_for_error(&err).to_string(),
        )
    })?
    else {
        return Err((
            ResultCode::AliasDereferencingProblem,
            format!("alias target {} not found", target_dn),
        ));
    };

    if entry_is_alias(&target_entry) {
        return Box::pin(resolve_alias_chain(backend, &target_entry, visited_dns)).await;
    }

    Ok(target_entry)
}

pub(crate) async fn resolve_search_base_dn(
    backend: &dyn DirectoryBackend,
    base_dn: &str,
    deref_aliases: ldap_parser::ldap::DerefAliases,
) -> Result<String, (ResultCode, String)> {
    if !should_deref_search_base(deref_aliases) {
        return Ok(base_dn.to_string());
    }

    let Some(entry) = backend.get_entry(base_dn).await.map_err(|err| {
        (
            map_backend_error(&err),
            diagnostic_for_error(&err).to_string(),
        )
    })?
    else {
        return Ok(base_dn.to_string());
    };

    if !entry_is_alias(&entry) {
        return Ok(base_dn.to_string());
    }

    let mut visited_dns = HashSet::new();
    resolve_alias_chain(backend, &entry, &mut visited_dns)
        .await
        .map(|resolved| resolved.dn)
}

pub(crate) async fn resolve_search_candidate_entry(
    backend: &dyn DirectoryBackend,
    entry: &DirectoryEntry,
    deref_aliases: ldap_parser::ldap::DerefAliases,
) -> Result<DirectoryEntry, (ResultCode, String)> {
    if !should_deref_search_candidates(deref_aliases) || !entry_is_alias(entry) {
        return Ok(entry.clone());
    }

    let mut visited_dns = HashSet::new();
    resolve_alias_chain(backend, entry, &mut visited_dns).await
}

struct SyncSearchEntry {
    entry: DirectoryEntry,
    attributes: Vec<(String, Vec<String>)>,
    state: SyncStateType,
    cookie: Option<Vec<u8>>,
}

fn sync_scope_matches(dn: &str, base_dn: &str, scope: ldap_parser::ldap::SearchScope) -> bool {
    match scope.0 {
        0 => dn.eq_ignore_ascii_case(base_dn),
        1 => {
            let Some((_, parent)) = dn.split_once(',') else {
                return false;
            };
            parent.eq_ignore_ascii_case(base_dn)
        }
        _ => is_dn_in_scope(dn, base_dn),
    }
}

fn sync_cookie_string(cookie: Option<&[u8]>) -> Result<Option<String>, SyncRequestError> {
    cookie
        .map(|cookie| {
            std::str::from_utf8(cookie)
                .map(|cookie| cookie.to_string())
                .map_err(|_| {
                    SyncRequestError::ProtocolError("sync cookie must be valid UTF-8".to_string())
                })
        })
        .transpose()
}

fn sync_cookie_from_csn(csn: &crate::csn::Csn) -> Vec<u8> {
    format!("csn-{csn}").into_bytes()
}

fn current_sync_cookie(changelog: &crate::replication::ChangelogTracker) -> Vec<u8> {
    changelog.generate_context_cookie().into_bytes()
}

async fn validate_sync_cookie(
    backend: &dyn DirectoryBackend,
    changelog: &crate::replication::ChangelogTracker,
    cookie: Option<&str>,
) -> Result<Option<crate::csn::Csn>, SyncRequestError> {
    let Some(cookie) = cookie else {
        return Ok(None);
    };
    if cookie == "csn-empty" {
        return Ok(None);
    }

    let Some(csn) = changelog.parse_cookie(cookie) else {
        return Err(SyncRequestError::InvalidCookie(format!(
            "invalid sync cookie {cookie}"
        )));
    };

    if let Some(oldest) = changelog.get_oldest_csn()
        && csn < oldest
    {
        return Err(SyncRequestError::InvalidCookie(format!(
            "stale sync cookie {cookie} requires a full refresh"
        )));
    }

    let backend_context = backend.get_context_csn().await.map_err(|err| {
        SyncRequestError::InvalidCookie(format!("sync cookie validation failed: {err}"))
    })?;

    if let Some(backend_context) = backend_context {
        let changelog_context = changelog.get_context_csn();
        if csn > backend_context
            && changelog_context
                .as_ref()
                .is_none_or(|latest| &csn > latest)
        {
            return Err(SyncRequestError::InvalidCookie(format!(
                "invalid sync cookie {cookie}"
            )));
        }

        if csn < backend_context
            && changelog_context
                .as_ref()
                .is_none_or(|latest| latest < &backend_context)
        {
            return Err(SyncRequestError::InvalidCookie(format!(
                "stale sync cookie {cookie} requires a full refresh"
            )));
        }
    }

    if let Some(latest) = changelog.get_context_csn()
        && csn > latest
    {
        return Err(SyncRequestError::InvalidCookie(format!(
            "invalid sync cookie {cookie}"
        )));
    }

    Ok(Some(csn))
}

fn sync_entry_uuid(entry: &DirectoryEntry) -> Uuid {
    entry
        .operational_attributes
        .entry_uuid
        .as_deref()
        .and_then(|uuid| Uuid::parse_str(uuid).ok())
        .unwrap_or_else(|| {
            Uuid::new_v5(
                &Uuid::NAMESPACE_X500,
                normalize_search_dn(&entry.dn).as_bytes(),
            )
        })
}

fn serialized_entry_from_change(
    change: &crate::replication_provider_fsm::ChangelogEntry,
) -> Option<DirectoryEntry> {
    serde_json::from_slice::<DirectoryEntry>(&change.change_data).ok()
}

#[allow(clippy::too_many_arguments)]
async fn build_sync_search_entry_from_change(
    backend: &dyn DirectoryBackend,
    schema: &LdapSchema,
    change: &crate::replication_provider_fsm::ChangelogEntry,
    base_dn: &str,
    request: &SearchRequest<'_>,
    attribute_selection: &[String],
    session: &ConnectionSession,
    request_context: &RequestContext,
) -> Result<Option<SyncSearchEntry>, ServerError> {
    let cookie = Some(sync_cookie_from_csn(&change.csn));
    match change.change_type {
        crate::replication_provider_fsm::ChangeType::Add
        | crate::replication_provider_fsm::ChangeType::Modify => {
            let Some(entry) = serialized_entry_from_change(change) else {
                return Ok(None);
            };
            if !sync_scope_matches(&entry.dn, base_dn, request.scope) {
                return Ok(None);
            }
            let Some(entry) =
                filter_search_entry_for_read_access(backend, session, request_context, entry).await
            else {
                return Ok(None);
            };
            if !entry_matches_filter_with_schema(&entry, &request.filter, schema)
                .map_err(|err| ServerError::Io(std::io::Error::other(err.to_string())))?
            {
                return Ok(None);
            }
            let state = if matches!(
                change.change_type,
                crate::replication_provider_fsm::ChangeType::Add
            ) {
                SyncStateType::Add
            } else {
                SyncStateType::Modify
            };
            Ok(Some(SyncSearchEntry {
                attributes: select_attributes(&entry, attribute_selection),
                entry,
                state,
                cookie,
            }))
        }
        crate::replication_provider_fsm::ChangeType::Delete => {
            let entry = serialized_entry_from_change(change)
                .unwrap_or_else(|| DirectoryEntry::new(change.dn.clone(), HashMap::new()));
            if !sync_scope_matches(&entry.dn, base_dn, request.scope) {
                return Ok(None);
            }
            let Some(entry) =
                filter_search_entry_for_read_access(backend, session, request_context, entry).await
            else {
                return Ok(None);
            };
            if !entry.attributes.is_empty()
                && !entry_matches_filter_with_schema(&entry, &request.filter, schema)
                    .map_err(|err| ServerError::Io(std::io::Error::other(err.to_string())))?
            {
                return Ok(None);
            }
            Ok(Some(SyncSearchEntry {
                entry,
                attributes: Vec::new(),
                state: SyncStateType::Delete,
                cookie,
            }))
        }
        crate::replication_provider_fsm::ChangeType::Rename => {
            let rename: RenameChange = match serde_json::from_slice(&change.change_data) {
                Ok(rename) => rename,
                Err(_) => return Ok(None),
            };
            let target_dn = if let Some(new_superior) = rename.new_superior.as_deref() {
                format!("{},{}", rename.new_rdn, new_superior)
            } else if let Some((_, parent)) = change.dn.split_once(',') {
                format!("{},{}", rename.new_rdn, parent)
            } else {
                rename.new_rdn.clone()
            };

            let entry = backend
                .get_entry(&target_dn)
                .await
                .map_err(|err| {
                    ServerError::Io(std::io::Error::other(format!(
                        "failed to resolve renamed entry {target_dn}: {err}"
                    )))
                })?
                .ok_or_else(|| {
                    ServerError::Io(std::io::Error::other(format!(
                        "renamed entry {target_dn} missing during sync replay"
                    )))
                })?;
            if !sync_scope_matches(&entry.dn, base_dn, request.scope) {
                return Ok(None);
            }
            let Some(entry) =
                filter_search_entry_for_read_access(backend, session, request_context, entry).await
            else {
                return Ok(None);
            };
            if !entry_matches_filter_with_schema(&entry, &request.filter, schema)
                .map_err(|err| ServerError::Io(std::io::Error::other(err.to_string())))?
            {
                return Ok(None);
            }
            Ok(Some(SyncSearchEntry {
                attributes: select_attributes(&entry, attribute_selection),
                entry,
                state: SyncStateType::Modify,
                cookie,
            }))
        }
    }
}

async fn emit_sync_entry(
    socket: &mut (impl AsyncWrite + Unpin),
    message_id: u32,
    sync_entry: &SyncSearchEntry,
    types_only: bool,
) -> Result<(), ServerError> {
    let control = sync_state_response_control(
        sync_entry.state,
        sync_entry_uuid(&sync_entry.entry),
        sync_entry.cookie.clone(),
    )?;
    send_search_entry_with_controls(
        socket,
        message_id,
        &sync_entry.entry,
        &sync_entry.attributes,
        types_only,
        &[control],
    )
    .await
}

async fn emit_sync_refresh_entries(
    socket: &mut (impl AsyncWrite + Unpin),
    message_id: u32,
    entries: &[DirectoryEntry],
    attribute_selection: &[String],
    types_only: bool,
    search_deadline: Option<Instant>,
) -> Result<(usize, bool), ServerError> {
    let mut returned = 0usize;
    for entry in entries {
        if search_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Ok((returned, true));
        }

        let sync_entry = SyncSearchEntry {
            attributes: select_attributes(entry, attribute_selection),
            entry: entry.clone(),
            state: SyncStateType::Present,
            cookie: entry
                .operational_attributes
                .entry_csn
                .as_ref()
                .map(sync_cookie_from_csn),
        };
        emit_sync_entry(socket, message_id, &sync_entry, types_only).await?;
        returned += 1;
    }

    Ok((returned, false))
}

fn sync_mode_name(mode: SyncRefreshMode) -> &'static str {
    match mode {
        SyncRefreshMode::RefreshOnly => "refresh_only",
        SyncRefreshMode::RefreshAndPersist => "refresh_and_persist",
    }
}

fn summarize_audit_value(value: Option<&str>) -> String {
    const MAX_INLINE_LEN: usize = 48;
    match value {
        Some(value) if value.chars().count() > MAX_INLINE_LEN => {
            let prefix = value.chars().take(24).collect::<String>();
            let suffix = value
                .chars()
                .rev()
                .take(12)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<String>();
            format!("{prefix}...{suffix} (len={})", value.chars().count())
        }
        Some(value) => value.to_string(),
        None => "none".to_string(),
    }
}

fn sync_request_error_message(error: &SyncRequestError) -> &str {
    match error {
        SyncRequestError::ProtocolError(message)
        | SyncRequestError::InvalidCookie(message)
        | SyncRequestError::Unsupported(message) => message.as_str(),
    }
}

fn provider_replica_id(changelog: &crate::replication::ChangelogTracker) -> String {
    changelog
        .get_context_csn()
        .map(|csn| csn.replica_id().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn provider_context_csn(changelog: &crate::replication::ChangelogTracker) -> String {
    changelog
        .get_context_csn()
        .map(|csn| csn.to_string())
        .unwrap_or_else(|| "none".to_string())
}

async fn log_replication_audit_event(
    request_context: &RequestContext,
    session: &ConnectionSession,
    level: AuditLevel,
    action: &str,
    success: bool,
    error_message: Option<&str>,
    details: Vec<(String, String)>,
) {
    let Some(security) = request_context.security.as_ref() else {
        return;
    };
    if !security.audit_config.log_replication {
        return;
    }

    log_generic_audit_event(
        request_context,
        session,
        level,
        AuditEventType::Replication,
        action,
        success,
        None,
        error_message,
        details,
    )
    .await;
}

fn provider_sync_audit_details(
    changelog: &crate::replication::ChangelogTracker,
    base_dn: &str,
    mode: SyncRefreshMode,
    cookie: Option<&str>,
) -> Vec<(String, String)> {
    vec![
        ("role".to_string(), "provider".to_string()),
        ("base_dn".to_string(), base_dn.to_string()),
        ("sync_mode".to_string(), sync_mode_name(mode).to_string()),
        ("cookie".to_string(), summarize_audit_value(cookie)),
        ("replica_id".to_string(), provider_replica_id(changelog)),
        (
            "latest_context_csn".to_string(),
            provider_context_csn(changelog),
        ),
    ]
}

pub(crate) async fn reject_sync_request(
    socket: &mut (impl AsyncWrite + Unpin),
    message_id: u32,
    base_dn: &str,
    error: &SyncRequestError,
) -> Result<(), ServerError> {
    match error {
        SyncRequestError::ProtocolError(diagnostic) => {
            send_result(
                socket,
                message_id,
                ResponseOp::SearchDone,
                ResultCode::ProtocolError,
                base_dn,
                diagnostic,
            )
            .await
        }
        SyncRequestError::InvalidCookie(diagnostic) | SyncRequestError::Unsupported(diagnostic) => {
            send_result(
                socket,
                message_id,
                ResponseOp::SearchDone,
                ResultCode::UnwillingToPerform,
                base_dn,
                diagnostic,
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_sync_search_request(
    socket: &mut (impl AsyncRead + AsyncWrite + Unpin),
    backend: &dyn DirectoryBackend,
    schema: &LdapSchema,
    message_id: u32,
    request: &SearchRequest<'_>,
    base_dn: &str,
    attribute_selection: &[String],
    sync_request: &RequestedSyncControl,
    manage_dsa_it: bool,
    connection_session: &ConnectionSession,
    operation_registry: &mut ConnectionOperationRegistry,
    request_context: &RequestContext,
    search_deadline: Option<Instant>,
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

    let Some(changelog) = backend.replication_changelog() else {
        log_replication_audit_event(
            request_context,
            connection_session,
            AuditLevel::Warning,
            "provider_session_failure",
            false,
            Some("replication sync not available"),
            vec![
                ("role".to_string(), "provider".to_string()),
                ("base_dn".to_string(), base_dn.to_string()),
                (
                    "sync_mode".to_string(),
                    sync_mode_name(sync_request.request.mode).to_string(),
                ),
                (
                    "cookie".to_string(),
                    summarize_audit_value(
                        sync_request
                            .request
                            .cookie
                            .as_deref()
                            .and_then(|cookie| std::str::from_utf8(cookie).ok()),
                    ),
                ),
                ("result".to_string(), "unavailable".to_string()),
            ],
        )
        .await;
        session
            .send_unavailable("replication sync not available")
            .await?;
        operation_registry.finish(message_id, FinishedOperationState::Completed);
        return Ok(());
    };

    let cookie_text = match sync_cookie_string(sync_request.request.cookie.as_deref()) {
        Ok(cookie_text) => cookie_text,
        Err(error) => {
            let diagnostic = sync_request_error_message(&error).to_string();
            let mut details =
                provider_sync_audit_details(&changelog, base_dn, sync_request.request.mode, None);
            details.push(("result".to_string(), "cookie_rejected".to_string()));
            log_replication_audit_event(
                request_context,
                connection_session,
                AuditLevel::Warning,
                "provider_cookie_rejected",
                false,
                Some(&diagnostic),
                details,
            )
            .await;
            reject_sync_request(session.socket, message_id, base_dn, &error).await?;
            operation_registry.finish(message_id, FinishedOperationState::Completed);
            return Ok(());
        }
    };
    let cookie_csn = match validate_sync_cookie(backend, &changelog, cookie_text.as_deref()).await {
        Ok(cookie_csn) => cookie_csn,
        Err(error) => {
            let diagnostic = sync_request_error_message(&error).to_string();
            let mut details = provider_sync_audit_details(
                &changelog,
                base_dn,
                sync_request.request.mode,
                cookie_text.as_deref(),
            );
            details.push(("result".to_string(), "cookie_rejected".to_string()));
            log_replication_audit_event(
                request_context,
                connection_session,
                AuditLevel::Warning,
                "provider_cookie_rejected",
                false,
                Some(&diagnostic),
                details,
            )
            .await;
            reject_sync_request(session.socket, message_id, base_dn, &error).await?;
            operation_registry.finish(message_id, FinishedOperationState::Completed);
            return Ok(());
        }
    };
    let mut control_decoder = BerDecoderFsmImpl::new();
    let mut control_buffer = vec![0_u8; 4096];

    let mut receiver = if sync_request.request.mode == SyncRefreshMode::RefreshAndPersist {
        match backend.subscribe_to_replication_changes() {
            Some(receiver) => Some(receiver),
            _ => {
                let mut details = provider_sync_audit_details(
                    &changelog,
                    base_dn,
                    sync_request.request.mode,
                    cookie_text.as_deref(),
                );
                details.push(("result".to_string(), "stream_unavailable".to_string()));
                log_replication_audit_event(
                    request_context,
                    connection_session,
                    AuditLevel::Warning,
                    "provider_session_failure",
                    false,
                    Some("replication stream not available"),
                    details,
                )
                .await;
                session
                    .send_unavailable("replication stream not available")
                    .await?;
                operation_registry.finish(message_id, FinishedOperationState::Completed);
                return Ok(());
            }
        }
    } else {
        None
    };

    let mut start_details = provider_sync_audit_details(
        &changelog,
        base_dn,
        sync_request.request.mode,
        cookie_text.as_deref(),
    );
    start_details.push((
        "sync_kind".to_string(),
        if cookie_csn.is_some() {
            "incremental_replay".to_string()
        } else {
            "full_refresh".to_string()
        },
    ));
    start_details.push(("result".to_string(), "started".to_string()));
    log_replication_audit_event(
        request_context,
        connection_session,
        AuditLevel::Info,
        "provider_session_start",
        true,
        None,
        start_details,
    )
    .await;

    if cookie_csn.is_none() {
        let result_set = collect_search_result_set(
            backend,
            schema,
            base_dn,
            None,
            request,
            request.deref_aliases,
            manage_dsa_it,
            connection_session,
            request_context,
            search_deadline,
        )
        .await
        .map_err(|err| ServerError::Io(std::io::Error::other(err.diagnostic)))?;
        let (returned, time_limit_hit) = emit_sync_refresh_entries(
            session.socket,
            message_id,
            &result_set.entries,
            attribute_selection,
            request.types_only,
            search_deadline,
        )
        .await?;
        if sync_request.request.mode == SyncRefreshMode::RefreshOnly {
            let sync_done =
                sync_done_response_control(Some(current_sync_cookie(&changelog)), false)?;
            send_result_with_controls(
                session.socket,
                message_id,
                ResponseOp::SearchDone,
                if time_limit_hit {
                    ResultCode::TimeLimitExceeded
                } else {
                    ResultCode::Success
                },
                base_dn,
                if time_limit_hit {
                    "time limit exceeded"
                } else {
                    ""
                },
                &[sync_done],
            )
            .await?;
            let mut details = provider_sync_audit_details(
                &changelog,
                base_dn,
                sync_request.request.mode,
                cookie_text.as_deref(),
            );
            details.push(("sync_kind".to_string(), "full_refresh".to_string()));
            details.push(("entries_sent".to_string(), returned.to_string()));
            details.push((
                "result".to_string(),
                if time_limit_hit {
                    "time_limit_exceeded"
                } else {
                    "success"
                }
                .to_string(),
            ));
            log_replication_audit_event(
                request_context,
                connection_session,
                if time_limit_hit {
                    AuditLevel::Warning
                } else {
                    AuditLevel::Info
                },
                "provider_session_complete",
                !time_limit_hit,
                time_limit_hit.then_some("time limit exceeded"),
                details,
            )
            .await;
            operation_registry.finish(message_id, FinishedOperationState::Completed);
            return Ok(());
        }
    } else if let Some(cookie_csn) = cookie_csn.as_ref() {
        let mut entries_sent = 0usize;
        for change in changelog.get_since_csn(cookie_csn) {
            if provider_lifecycle
                .as_ref()
                .is_some_and(|lifecycle| lifecycle.is_draining())
            {
                let mut details = provider_sync_audit_details(
                    &changelog,
                    base_dn,
                    sync_request.request.mode,
                    cookie_text.as_deref(),
                );
                details.push(("sync_kind".to_string(), "incremental_replay".to_string()));
                details.push(("entries_sent".to_string(), entries_sent.to_string()));
                details.push(("result".to_string(), "provider_shutdown".to_string()));
                log_replication_audit_event(
                    request_context,
                    connection_session,
                    AuditLevel::Warning,
                    "provider_session_failure",
                    false,
                    Some("replication provider shutting down"),
                    details,
                )
                .await;
                operation_registry.finish(message_id, FinishedOperationState::Completed);
                return finish_replication_stream_unavailable(
                    &mut session,
                    "replication provider shutting down",
                )
                .await;
            }
            if let Some(sync_entry) = build_sync_search_entry_from_change(
                backend,
                schema,
                &change,
                base_dn,
                request,
                attribute_selection,
                connection_session,
                request_context,
            )
            .await?
            {
                emit_sync_entry(session.socket, message_id, &sync_entry, request.types_only)
                    .await?;
                entries_sent += 1;
            }
        }

        if sync_request.request.mode == SyncRefreshMode::RefreshOnly {
            let sync_done =
                sync_done_response_control(Some(current_sync_cookie(&changelog)), false)?;
            send_result_with_controls(
                session.socket,
                message_id,
                ResponseOp::SearchDone,
                ResultCode::Success,
                base_dn,
                "",
                &[sync_done],
            )
            .await?;
            let mut details = provider_sync_audit_details(
                &changelog,
                base_dn,
                sync_request.request.mode,
                cookie_text.as_deref(),
            );
            details.push(("sync_kind".to_string(), "incremental_replay".to_string()));
            details.push(("entries_sent".to_string(), entries_sent.to_string()));
            details.push(("result".to_string(), "success".to_string()));
            log_replication_audit_event(
                request_context,
                connection_session,
                AuditLevel::Info,
                "provider_session_complete",
                true,
                None,
                details,
            )
            .await;
            operation_registry.finish(message_id, FinishedOperationState::Completed);
            return Ok(());
        }
    }

    let mut receiver = receiver
        .take()
        .expect("refreshAndPersist requests create a replication receiver before refresh");

    send_intermediate_response(
        session.socket,
        message_id,
        Some(SYNC_INFO_OID.to_string()),
        Some(
            encode_sync_info_value(&SyncInfoValue::RefreshPresent {
                cookie: Some(current_sync_cookie(&changelog)),
                refresh_done: true,
            })
            .map_err(|err| ServerError::Io(std::io::Error::other(err.to_string())))?,
        ),
        &[],
    )
    .await?;

    loop {
        let recv_result = if let Some(lifecycle) = provider_lifecycle.as_ref() {
            tokio::select! {
                _ = lifecycle.wait_for_shutdown() => {
                    let mut details = provider_sync_audit_details(
                        &changelog,
                        base_dn,
                        sync_request.request.mode,
                        cookie_text.as_deref(),
                    );
                    details.push(("sync_kind".to_string(), "refresh_and_persist".to_string()));
                    details.push(("result".to_string(), "provider_shutdown".to_string()));
                    log_replication_audit_event(
                        request_context,
                        connection_session,
                        AuditLevel::Warning,
                        "provider_session_failure",
                        false,
                        Some("replication provider shutting down"),
                        details,
                    ).await;
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
                            let mut details = provider_sync_audit_details(
                                &changelog,
                                base_dn,
                                sync_request.request.mode,
                                cookie_text.as_deref(),
                            );
                            details.push(("sync_kind".to_string(), "refresh_and_persist".to_string()));
                            details.push(("result".to_string(), "canceled".to_string()));
                            log_replication_audit_event(
                                request_context,
                                connection_session,
                                AuditLevel::Info,
                                "provider_session_complete",
                                true,
                                None,
                                details,
                            ).await;
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
                            let mut details = provider_sync_audit_details(
                                &changelog,
                                base_dn,
                                sync_request.request.mode,
                                cookie_text.as_deref(),
                            );
                            details.push(("sync_kind".to_string(), "refresh_and_persist".to_string()));
                            details.push(("result".to_string(), "abandoned".to_string()));
                            log_replication_audit_event(
                                request_context,
                                connection_session,
                                AuditLevel::Info,
                                "provider_session_complete",
                                true,
                                None,
                                details,
                            ).await;
                            operation_registry.finish(message_id, FinishedOperationState::Abandoned);
                            return Ok(());
                        }
                        StreamControlEvent::ClientClosed => {
                            let mut details = provider_sync_audit_details(
                                &changelog,
                                base_dn,
                                sync_request.request.mode,
                                cookie_text.as_deref(),
                            );
                            details.push(("sync_kind".to_string(), "refresh_and_persist".to_string()));
                            details.push(("result".to_string(), "client_closed".to_string()));
                            log_replication_audit_event(
                                request_context,
                                connection_session,
                                AuditLevel::Info,
                                "provider_session_complete",
                                true,
                                None,
                                details,
                            ).await;
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
                            let mut details = provider_sync_audit_details(
                                &changelog,
                                base_dn,
                                sync_request.request.mode,
                                cookie_text.as_deref(),
                            );
                            details.push(("sync_kind".to_string(), "refresh_and_persist".to_string()));
                            details.push(("result".to_string(), "canceled".to_string()));
                            log_replication_audit_event(
                                request_context,
                                connection_session,
                                AuditLevel::Info,
                                "provider_session_complete",
                                true,
                                None,
                                details,
                            ).await;
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
                            let mut details = provider_sync_audit_details(
                                &changelog,
                                base_dn,
                                sync_request.request.mode,
                                cookie_text.as_deref(),
                            );
                            details.push(("sync_kind".to_string(), "refresh_and_persist".to_string()));
                            details.push(("result".to_string(), "abandoned".to_string()));
                            log_replication_audit_event(
                                request_context,
                                connection_session,
                                AuditLevel::Info,
                                "provider_session_complete",
                                true,
                                None,
                                details,
                            ).await;
                            operation_registry.finish(message_id, FinishedOperationState::Abandoned);
                            return Ok(());
                        }
                        StreamControlEvent::ClientClosed => {
                            let mut details = provider_sync_audit_details(
                                &changelog,
                                base_dn,
                                sync_request.request.mode,
                                cookie_text.as_deref(),
                            );
                            details.push(("sync_kind".to_string(), "refresh_and_persist".to_string()));
                            details.push(("result".to_string(), "client_closed".to_string()));
                            log_replication_audit_event(
                                request_context,
                                connection_session,
                                AuditLevel::Info,
                                "provider_session_complete",
                                true,
                                None,
                                details,
                            ).await;
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
                    let mut details = provider_sync_audit_details(
                        &changelog,
                        base_dn,
                        sync_request.request.mode,
                        cookie_text.as_deref(),
                    );
                    details.push(("sync_kind".to_string(), "refresh_and_persist".to_string()));
                    details.push(("result".to_string(), "provider_shutdown".to_string()));
                    log_replication_audit_event(
                        request_context,
                        connection_session,
                        AuditLevel::Warning,
                        "provider_session_failure",
                        false,
                        Some("replication provider shutting down"),
                        details,
                    )
                    .await;
                    operation_registry.finish(message_id, FinishedOperationState::Completed);
                    return finish_replication_stream_unavailable(
                        &mut session,
                        "replication provider shutting down",
                    )
                    .await;
                }
                let sync_entry = match build_sync_search_entry_from_change(
                    backend,
                    schema,
                    &entry,
                    base_dn,
                    request,
                    attribute_selection,
                    connection_session,
                    request_context,
                )
                .await?
                {
                    Some(sync_entry) => sync_entry,
                    None => continue,
                };
                if let Err(err) =
                    emit_sync_entry(session.socket, message_id, &sync_entry, request.types_only)
                        .await
                {
                    warn!("Replication stream send failed: {}", err);
                    let mut details = provider_sync_audit_details(
                        &changelog,
                        base_dn,
                        sync_request.request.mode,
                        cookie_text.as_deref(),
                    );
                    details.push(("sync_kind".to_string(), "refresh_and_persist".to_string()));
                    details.push(("result".to_string(), "send_failed".to_string()));
                    log_replication_audit_event(
                        request_context,
                        connection_session,
                        AuditLevel::Warning,
                        "provider_session_failure",
                        false,
                        Some(&err.to_string()),
                        details,
                    )
                    .await;
                    operation_registry.finish(message_id, FinishedOperationState::Completed);
                    break;
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                warn!("Replication stream lagged by {} messages", skipped);
                let mut details = provider_sync_audit_details(
                    &changelog,
                    base_dn,
                    sync_request.request.mode,
                    cookie_text.as_deref(),
                );
                details.push(("sync_kind".to_string(), "refresh_and_persist".to_string()));
                details.push(("skipped_messages".to_string(), skipped.to_string()));
                details.push(("result".to_string(), "stream_lagged".to_string()));
                log_replication_audit_event(
                    request_context,
                    connection_session,
                    AuditLevel::Warning,
                    "provider_stream_lagged",
                    false,
                    Some("replication stream lagged"),
                    details,
                )
                .await;
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }

    let mut details = provider_sync_audit_details(
        &changelog,
        base_dn,
        sync_request.request.mode,
        cookie_text.as_deref(),
    );
    details.push(("sync_kind".to_string(), "refresh_and_persist".to_string()));
    details.push(("result".to_string(), "stream_closed".to_string()));
    log_replication_audit_event(
        request_context,
        connection_session,
        AuditLevel::Info,
        "provider_session_complete",
        true,
        None,
        details,
    )
    .await;
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

    let decoded_messages = match decode_messages(decoder, &read_buffer[..bytes_read]).await {
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

pub(crate) async fn log_compare_audit(
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

pub(crate) async fn log_modify_audit_event(
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

pub(crate) async fn log_add_audit_event(
    request_context: &RequestContext,
    session: &ConnectionSession,
    dn: &str,
    success: bool,
) {
    let Some(security) = request_context.security.as_ref() else {
        return;
    };
    if !security.audit_config.log_modifications {
        return;
    }
    let Some(logger) = security.audit_logger.as_ref() else {
        return;
    };

    logger
        .log_add(
            dn,
            &audit_actor(session),
            &client_ip_for_audit(request_context),
            success,
        )
        .await;
}

pub(crate) async fn log_delete_audit_event(
    request_context: &RequestContext,
    session: &ConnectionSession,
    dn: &str,
    success: bool,
) {
    let Some(security) = request_context.security.as_ref() else {
        return;
    };
    if !security.audit_config.log_modifications {
        return;
    }
    let Some(logger) = security.audit_logger.as_ref() else {
        return;
    };

    logger
        .log_delete(
            dn,
            &audit_actor(session),
            &client_ip_for_audit(request_context),
            success,
        )
        .await;
}

pub(crate) async fn log_moddn_audit_event(
    request_context: &RequestContext,
    session: &ConnectionSession,
    dn: &str,
    new_dn: &str,
    success: bool,
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
            logger
                .log_modifydn(
                    dn,
                    new_dn,
                    &audit_actor(session),
                    &client_ip_for_audit(request_context),
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
        "modifydn",
        false,
        Some(dn),
        error_message,
        vec![("new_dn".to_string(), new_dn.to_string())],
    )
    .await;
}

pub(crate) async fn log_password_modify_audit_event(
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
    let schema = LdapSchema::default();
    handle_modify_request_with_context(
        socket,
        backend,
        &schema,
        message_id,
        request,
        &session,
        &RequestContext::default(),
        &request_controls,
    )
    .await
}

#[derive(Debug)]
pub(crate) enum OnlineSchemaUpdateError {
    Disabled,
    Unauthorized,
    UnsupportedAttribute(String),
    Schema(SchemaError),
    Unsafe(String),
    Backend(String),
    Io(String),
}

impl fmt::Display for OnlineSchemaUpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OnlineSchemaUpdateError::Disabled => write!(f, "online schema updates are disabled"),
            OnlineSchemaUpdateError::Unauthorized => {
                write!(f, "authentication required for online schema updates")
            }
            OnlineSchemaUpdateError::UnsupportedAttribute(attribute) => {
                write!(
                    f,
                    "unsupported schema attribute for online update: {}",
                    attribute
                )
            }
            OnlineSchemaUpdateError::Schema(err) => write!(f, "{}", err),
            OnlineSchemaUpdateError::Unsafe(message) => write!(f, "{}", message),
            OnlineSchemaUpdateError::Backend(message) => write!(f, "{}", message),
            OnlineSchemaUpdateError::Io(message) => write!(f, "{}", message),
        }
    }
}

impl From<SchemaError> for OnlineSchemaUpdateError {
    fn from(err: SchemaError) -> Self {
        OnlineSchemaUpdateError::Schema(err)
    }
}

pub(crate) fn online_schema_update_result(err: &OnlineSchemaUpdateError) -> (ResultCode, String) {
    match err {
        OnlineSchemaUpdateError::Disabled => (ResultCode::UnwillingToPerform, err.to_string()),
        OnlineSchemaUpdateError::Unauthorized => {
            (ResultCode::InsufficientAccessRights, err.to_string())
        }
        OnlineSchemaUpdateError::UnsupportedAttribute(_) => {
            (ResultCode::ObjectClassViolation, err.to_string())
        }
        OnlineSchemaUpdateError::Schema(_) | OnlineSchemaUpdateError::Unsafe(_) => {
            (ResultCode::ObjectClassViolation, err.to_string())
        }
        OnlineSchemaUpdateError::Backend(_) | OnlineSchemaUpdateError::Io(_) => {
            (ResultCode::Unavailable, err.to_string())
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_online_schema_modify_request_with_context(
    socket: &mut (impl AsyncWrite + Unpin),
    backend: &dyn DirectoryBackend,
    schema: &SharedLdapSchema,
    runtime_config: &LegacyServerConfig,
    message_id: u32,
    request: ModifyRequest<'_>,
    session: &ConnectionSession,
    request_context: &RequestContext,
) -> Result<(), ServerError> {
    let dn = request.object.0.as_ref().trim().to_owned();
    let modifications = match convert_ldap_changes_to_modifications(&request.changes) {
        Ok(modifications) => modifications,
        Err(err) => {
            send_result(
                socket,
                message_id,
                ResponseOp::Modify,
                ResultCode::ProtocolError,
                &dn,
                err.to_string(),
            )
            .await?;
            return Ok(());
        }
    };
    let modified_attributes = modifications
        .iter()
        .map(|modification| modification.attribute.clone())
        .collect::<Vec<_>>();

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

    if !authorize_attribute_permissions(
        socket,
        backend,
        message_id,
        ResponseOp::Modify,
        session,
        request_context,
        Permission::Modify,
        "modify",
        &dn,
        &modified_attributes,
    )
    .await?
    {
        return Ok(());
    }

    match apply_online_schema_modify(backend, schema, runtime_config, session, modifications).await
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
            let (result_code, diagnostic) = online_schema_update_result(&err);
            error!("Online schema update failed for {}: {}", dn, diagnostic);
            log_modify_audit_event(
                request_context,
                session,
                &dn,
                false,
                &modified_attributes,
                Some(&diagnostic),
            )
            .await;
            send_result(
                socket,
                message_id,
                ResponseOp::Modify,
                result_code,
                &dn,
                &diagnostic,
            )
            .await?;
        }
    }

    Ok(())
}

pub(crate) async fn apply_online_schema_modify(
    backend: &dyn DirectoryBackend,
    schema: &SharedLdapSchema,
    runtime_config: &LegacyServerConfig,
    session: &ConnectionSession,
    modifications: Vec<Modification>,
) -> Result<(), OnlineSchemaUpdateError> {
    if !runtime_config.allow_online_schema_updates {
        return Err(OnlineSchemaUpdateError::Disabled);
    }
    if !session.is_authenticated() {
        return Err(OnlineSchemaUpdateError::Unauthorized);
    }

    let schema_file = online_schema_file_path(runtime_config);
    let online_store = read_online_schema_store(&schema_file)?;
    let mut proposed_store = online_store.clone();
    let mut proposed_schema = schema_snapshot(schema);

    for modification in &modifications {
        let Some(canonical_name) = canonical_schema_attr_name(&modification.attribute) else {
            return Err(OnlineSchemaUpdateError::UnsupportedAttribute(
                modification.attribute.clone(),
            ));
        };
        match modification.operation {
            ModifyOperation::Add => {
                for value in &modification.values {
                    proposed_schema.apply_schema_attr_value(canonical_name, value)?;
                    proposed_store
                        .entry(canonical_name.to_string())
                        .or_default()
                        .push(value.clone());
                }
            }
            ModifyOperation::Delete => {
                if modification.values.is_empty() {
                    let removed_values =
                        proposed_store.remove(canonical_name).ok_or_else(|| {
                            OnlineSchemaUpdateError::Unsafe(format!(
                                "{} has no online-managed schema definitions to delete",
                                canonical_name
                            ))
                        })?;
                    for removed_value in removed_values {
                        proposed_schema.remove_schema_attr_value(canonical_name, &removed_value)?;
                    }
                } else {
                    for value in &modification.values {
                        let removed_value =
                            remove_online_store_value(&mut proposed_store, canonical_name, value)?;
                        proposed_schema.remove_schema_attr_value(canonical_name, &removed_value)?;
                    }
                }
            }
            ModifyOperation::Replace => {
                if let Some(removed_values) = proposed_store.remove(canonical_name) {
                    for removed_value in removed_values {
                        proposed_schema.remove_schema_attr_value(canonical_name, &removed_value)?;
                    }
                }
                if !modification.values.is_empty() {
                    for value in &modification.values {
                        proposed_schema.apply_schema_attr_value(canonical_name, value)?;
                    }
                    proposed_store.insert(canonical_name.to_string(), modification.values.clone());
                }
            }
            ModifyOperation::Increment => {
                return Err(OnlineSchemaUpdateError::Unsafe(format!(
                    "Modify-Increment is not supported for online schema attribute {}",
                    canonical_name
                )));
            }
        }
    }

    proposed_schema.validate_schema_dependencies()?;
    validate_existing_entries_against_schema(backend, runtime_config, &proposed_schema).await?;
    write_online_schema_store(&schema_file, &proposed_store)?;

    *schema.write().expect("LDAP schema lock poisoned") = proposed_schema;
    Ok(())
}

fn online_schema_file_path(runtime_config: &LegacyServerConfig) -> PathBuf {
    runtime_config.schema_dir.join(ONLINE_SCHEMA_FILE)
}

fn read_online_schema_store(
    path: &PathBuf,
) -> Result<std::collections::BTreeMap<String, Vec<String>>, OnlineSchemaUpdateError> {
    if !path.exists() {
        return Ok(Default::default());
    }
    let contents = fs::read_to_string(path)
        .map_err(|err| OnlineSchemaUpdateError::Io(format!("{}: {}", path.display(), err)))?;
    LdapSchema::parse_schema_ldif_values(&contents).map_err(OnlineSchemaUpdateError::Schema)
}

fn remove_online_store_value(
    store: &mut std::collections::BTreeMap<String, Vec<String>>,
    canonical_name: &str,
    value: &str,
) -> Result<String, OnlineSchemaUpdateError> {
    let target_key = schema_definition_key(canonical_name, value)?;
    let values = store.get_mut(canonical_name).ok_or_else(|| {
        OnlineSchemaUpdateError::Unsafe(format!(
            "{} definition is not managed by the online schema store",
            target_key
        ))
    })?;
    let Some(position) = values.iter().position(|candidate| {
        schema_definition_key(canonical_name, candidate).is_ok_and(|key| key == target_key)
    }) else {
        return Err(OnlineSchemaUpdateError::Unsafe(format!(
            "{} definition is not managed by the online schema store",
            target_key
        )));
    };
    let removed = values.remove(position);
    if values.is_empty() {
        store.remove(canonical_name);
    }
    Ok(removed)
}

fn write_online_schema_store(
    path: &PathBuf,
    store: &std::collections::BTreeMap<String, Vec<String>>,
) -> Result<(), OnlineSchemaUpdateError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| OnlineSchemaUpdateError::Io(format!("{}: {}", parent.display(), err)))?;
    }
    let temp_path = path.with_extension("ldif.tmp");
    let mut file = fs::File::create(&temp_path)
        .map_err(|err| OnlineSchemaUpdateError::Io(format!("{}: {}", temp_path.display(), err)))?;
    file.write_all(render_online_schema_store(store).as_bytes())
        .map_err(|err| OnlineSchemaUpdateError::Io(format!("{}: {}", temp_path.display(), err)))?;
    file.sync_all()
        .map_err(|err| OnlineSchemaUpdateError::Io(format!("{}: {}", temp_path.display(), err)))?;
    drop(file);
    fs::rename(&temp_path, path).map_err(|err| {
        OnlineSchemaUpdateError::Io(format!(
            "rename {} to {}: {}",
            temp_path.display(),
            path.display(),
            err
        ))
    })
}

fn render_online_schema_store(store: &std::collections::BTreeMap<String, Vec<String>>) -> String {
    let mut output = String::from(
        "dn: cn=Subschema\nobjectClass: top\nobjectClass: subentry\nobjectClass: subschema\ncn: Subschema\n",
    );
    for (name, values) in store {
        for value in values {
            output.push_str(name);
            output.push_str(": ");
            output.push_str(value);
            output.push('\n');
        }
    }
    output
}

async fn validate_existing_entries_against_schema(
    backend: &dyn DirectoryBackend,
    runtime_config: &LegacyServerConfig,
    schema: &LdapSchema,
) -> Result<(), OnlineSchemaUpdateError> {
    let naming_contexts = if runtime_config.naming_contexts.is_empty() {
        vec![String::new()]
    } else {
        runtime_config.naming_contexts.clone()
    };
    for naming_context in naming_contexts {
        let entries = backend
            .search_entries(
                &naming_context,
                ldap_parser::ldap::SearchScope::WholeSubtree,
            )
            .await
            .map_err(|err| OnlineSchemaUpdateError::Backend(err.to_string()))?;
        for entry in entries {
            schema.validate_entry(&entry.attributes).map_err(|err| {
                OnlineSchemaUpdateError::Unsafe(format!(
                    "schema update would invalidate existing entry {}: {}",
                    entry.dn, err
                ))
            })?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_modify_request_with_context(
    socket: &mut (impl AsyncWrite + Unpin),
    backend: &dyn DirectoryBackend,
    schema: &LdapSchema,
    message_id: u32,
    request: ModifyRequest<'_>,
    session: &ConnectionSession,
    request_context: &RequestContext,
    _request_controls: &RequestControls,
) -> Result<(), ServerError> {
    let dn = request.object.0.as_ref().trim().to_owned();
    let modifications = match convert_modifications(request.changes) {
        Ok(modifications) => modifications,
        Err(err) => {
            send_result(
                socket,
                message_id,
                ResponseOp::Modify,
                ResultCode::ProtocolError,
                &dn,
                err.to_string(),
            )
            .await?;
            return Ok(());
        }
    };
    let modified_attributes: Vec<String> = modifications
        .iter()
        .map(|modification| modification.attribute.clone())
        .collect();
    if let Some(attribute) = first_server_managed_operational_attribute(&modified_attributes) {
        let diagnostic = server_managed_operational_attribute_diagnostic(&attribute);
        log_modify_audit_event(
            request_context,
            session,
            &dn,
            false,
            &modified_attributes,
            Some(&diagnostic),
        )
        .await;
        send_result(
            socket,
            message_id,
            ResponseOp::Modify,
            ResultCode::UnwillingToPerform,
            &dn,
            &diagnostic,
        )
        .await?;
        return Ok(());
    }

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

    if !authorize_attribute_permissions(
        socket,
        backend,
        message_id,
        ResponseOp::Modify,
        session,
        request_context,
        Permission::Modify,
        "modify",
        &dn,
        &modified_attributes,
    )
    .await?
    {
        return Ok(());
    }

    match backend
        .modify_entry_validated_with_actor(
            &dn,
            modifications,
            session.bound_dn().map(str::to_string),
            schema,
        )
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
        Err(NativeModifyError::Protocol(diagnostic)) => {
            error!("Malformed modify request for {}: {}", dn, diagnostic);
            log_modify_audit_event(
                request_context,
                session,
                &dn,
                false,
                &modified_attributes,
                Some(&diagnostic),
            )
            .await;
            send_result(
                socket,
                message_id,
                ResponseOp::Modify,
                ResultCode::ProtocolError,
                &dn,
                &diagnostic,
            )
            .await?;
        }
        Err(NativeModifyError::Constraint(diagnostic)) => {
            error!("Modify constraint violation for {}: {}", dn, diagnostic);
            log_modify_audit_event(
                request_context,
                session,
                &dn,
                false,
                &modified_attributes,
                Some(&diagnostic),
            )
            .await;
            send_result(
                socket,
                message_id,
                ResponseOp::Modify,
                ResultCode::ConstraintViolation,
                &dn,
                &diagnostic,
            )
            .await?;
        }
        Err(NativeModifyError::Schema(diagnostic)) => {
            error!("Schema validation failed for modify {}: {}", dn, diagnostic);
            log_modify_audit_event(
                request_context,
                session,
                &dn,
                false,
                &modified_attributes,
                Some(&diagnostic),
            )
            .await;
            send_result(
                socket,
                message_id,
                ResponseOp::Modify,
                ResultCode::ObjectClassViolation,
                &dn,
                &diagnostic,
            )
            .await?;
        }
        Err(NativeModifyError::Backend(err)) => {
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

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_add_request_with_context(
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

    let added_attributes = entry.attributes.keys().cloned().collect::<Vec<_>>();
    if let Some(attribute) = first_server_managed_operational_attribute(&added_attributes) {
        let diagnostic = server_managed_operational_attribute_diagnostic(&attribute);
        log_generic_audit_event(
            request_context,
            session,
            AuditLevel::Error,
            AuditEventType::DataModification,
            "add",
            false,
            Some(&dn),
            Some(&diagnostic),
            Vec::new(),
        )
        .await;
        send_result(
            socket,
            message_id,
            ResponseOp::Add,
            ResultCode::UnwillingToPerform,
            &dn,
            &diagnostic,
        )
        .await?;
        return Ok(());
    }
    if !authorize_attribute_permissions(
        socket,
        backend,
        message_id,
        ResponseOp::Add,
        session,
        request_context,
        Permission::Add,
        "add",
        &dn,
        &added_attributes,
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
            log_add_audit_event(request_context, session, &dn, true).await;
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
            log_add_audit_event(request_context, session, &dn, false).await;
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

pub(crate) async fn handle_delete_request_with_context(
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
            log_delete_audit_event(request_context, session, &dn, true).await;
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
            log_delete_audit_event(request_context, session, &dn, false).await;
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
    let schema = LdapSchema::default();
    handle_moddn_request_with_context(
        socket,
        backend,
        &schema,
        message_id,
        request,
        &session,
        &RequestContext::default(),
        &request_controls,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_moddn_request_with_context(
    socket: &mut (impl AsyncWrite + Unpin),
    backend: &dyn DirectoryBackend,
    schema: &LdapSchema,
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

    let new_dn = match crate::dn::replace_dn_rdn(&dn, &new_rdn, new_superior.as_deref()) {
        Ok(new_dn) => new_dn,
        Err(err) => {
            send_result(
                socket,
                message_id,
                ResponseOp::ModifyDn,
                ResultCode::InvalidDnSyntax,
                &dn,
                &format!("invalid DN syntax: {}", err),
            )
            .await?;
            return Ok(());
        }
    };

    let existing_entry = match backend.get_entry(&dn).await {
        Ok(Some(existing_entry)) => existing_entry,
        Ok(None) => {
            send_result(
                socket,
                message_id,
                ResponseOp::ModifyDn,
                ResultCode::NoSuchObject,
                &dn,
                "no such object",
            )
            .await?;
            return Ok(());
        }
        Err(err) => {
            error!("ModifyDN lookup failed for {}: {}", dn, err);
            log_moddn_audit_event(
                request_context,
                session,
                &dn,
                &new_dn,
                false,
                Some(diagnostic_for_error(&err)),
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
            return Ok(());
        }
    };

    if let Err(schema_error) = schema.validate_rdn_for_entry(&existing_entry.attributes, &new_rdn) {
        error!(
            "Schema validation failed for modifydn {}: {}",
            dn, schema_error
        );
        log_moddn_audit_event(
            request_context,
            session,
            &dn,
            &new_dn,
            false,
            Some(&format!("Schema validation failed: {}", schema_error)),
        )
        .await;
        send_result(
            socket,
            message_id,
            ResponseOp::ModifyDn,
            ResultCode::ObjectClassViolation,
            &dn,
            &format!("Schema validation failed: {}", schema_error),
        )
        .await?;
        return Ok(());
    }

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
            log_moddn_audit_event(request_context, session, &dn, &new_dn, true, None).await;
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
            log_moddn_audit_event(
                request_context,
                session,
                &dn,
                &new_dn,
                false,
                Some(diagnostic_for_error(&err)),
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
    let schema = LdapSchema::default();
    handle_compare_request_with_context(
        socket,
        backend,
        &schema,
        message_id,
        request,
        &session,
        &RequestContext::default(),
        &request_controls,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_compare_request_with_context(
    socket: &mut (impl AsyncWrite + Unpin),
    backend: &dyn DirectoryBackend,
    schema: &LdapSchema,
    message_id: u32,
    request: CompareRequest<'_>,
    session: &ConnectionSession,
    request_context: &RequestContext,
    _request_controls: &RequestControls,
) -> Result<(), ServerError> {
    let dn = request.entry.0.as_ref().trim().to_owned();
    let attribute = request.ava.attribute_desc.0.as_ref().trim().to_owned();
    let assertion = bytes_to_string(&request.ava.assertion_value);

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

    let compare_result = match backend.get_entry(&dn).await {
        Ok(Some(entry)) => {
            compare_attribute_with_schema(schema, &dn, &entry.attributes, &attribute, &assertion)
                .map_err(CompareRequestError::Filter)
        }
        Ok(None) => Err(CompareRequestError::Backend(BackendError::NotFound)),
        Err(err) => Err(CompareRequestError::Backend(err)),
    };

    match compare_result {
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
        Err(CompareRequestError::Backend(err)) => {
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
        Err(CompareRequestError::Filter(err)) => {
            let diagnostic = err.to_string();
            error!(
                "Compare schema validation failed for {}: {}",
                dn, diagnostic
            );
            log_compare_audit(
                request_context,
                session,
                &dn,
                &attribute,
                false,
                "error",
                Some(&diagnostic),
            )
            .await;
            send_result(
                socket,
                message_id,
                ResponseOp::Compare,
                map_filter_schema_error(&err),
                &dn,
                &diagnostic,
            )
            .await?;
        }
    }

    Ok(())
}

enum CompareRequestError {
    Backend(BackendError),
    Filter(FilterSchemaError),
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
#[allow(clippy::too_many_arguments)]
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

#[allow(clippy::too_many_arguments)]
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
        if !security_policy(request_context).allow_password_modify {
            log_password_modify_audit_event(
                request_context,
                session,
                session.bound_dn(),
                "unknown",
                false,
                false,
                Some("Password Modify is disabled by security policy"),
            )
            .await;
            return send_result(
                socket,
                message_id,
                ResponseOp::Extended,
                ResultCode::UnwillingToPerform,
                "",
                "Password Modify is disabled by security policy",
            )
            .await;
        }

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
        let is_self_service = dn_eq(bound_dn, &target_dn);
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
                    .sample_string(&mut rand::rng(), 24)
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

    if include_all_operational
        || requested
            .iter()
            .any(|attr| OperationalAttributes::is_operational(attr))
    {
        for (name, values) in entry.operational_attributes.to_attributes() {
            if include_all_operational
                || requested
                    .iter()
                    .any(|attribute| attribute.eq_ignore_ascii_case(&name))
            {
                selected.push((name, values));
            }
        }
    }

    selected
}

#[cfg(test)]
fn entry_matches_filter(entry: &DirectoryEntry, filter: &Filter<'_>) -> bool {
    crate::ldap_filter_eval::matches_search_filter(entry, filter)
}

fn entry_matches_filter_with_schema(
    entry: &DirectoryEntry,
    filter: &Filter<'_>,
    schema: &LdapSchema,
) -> Result<bool, FilterSchemaError> {
    matches_search_filter_with_schema(entry, filter, schema)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ModifyRequestDecodeError {
    message: String,
}

impl ModifyRequestDecodeError {
    fn unsupported_operation(operation: u32) -> Self {
        Self {
            message: format!(
                "unsupported modify operation {operation}; expected add(0), delete(1), replace(2), or increment(3)"
            ),
        }
    }
}

impl std::fmt::Display for ModifyRequestDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ModifyRequestDecodeError {}

pub(crate) fn convert_ldap_changes_to_modifications(
    changes: &[Change<'_>],
) -> Result<Vec<Modification>, ModifyRequestDecodeError> {
    changes
        .iter()
        .map(|change| {
            let operation = match change.operation.0 {
                0 => ModifyOperation::Add,
                1 => ModifyOperation::Delete,
                2 => ModifyOperation::Replace,
                3 => ModifyOperation::Increment,
                operation => {
                    return Err(ModifyRequestDecodeError::unsupported_operation(operation));
                }
            };

            let attribute = change.modification.attr_type.0.to_lowercase();

            let values = change
                .modification
                .attr_vals
                .iter()
                .map(|value| bytes_to_string(value.0.as_ref()))
                .collect();

            Ok(Modification {
                operation,
                attribute,
                values,
            })
        })
        .collect()
}

fn convert_modifications(
    changes: Vec<Change<'_>>,
) -> Result<Vec<Modification>, ModifyRequestDecodeError> {
    convert_ldap_changes_to_modifications(&changes)
}

pub(crate) fn build_entry_from_add_request(
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

        if name == "userpassword"
            && let Some(first) = values.first()
        {
            password = first.as_bytes().to_vec();
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
    use crate::replication_service::ReplicationService;
    use crate::schema::LdapSchema;
    use crate::search_controls::{
        PAGED_RESULTS_OID, PagedResultsControl, SERVER_SIDE_SORT_REQUEST_OID,
        SERVER_SIDE_SORT_RESPONSE_OID, ServerSideSortResponseControl, ServerSideSortResultCode,
        SortKey, decode_paged_results_control, decode_server_side_sort_response_control,
        encode_paged_results_control, encode_server_side_sort_request_control,
    };
    use crate::sync_controls::{
        SYNC_DONE_OID, SYNC_INFO_OID, SYNC_REQUEST_OID, SYNC_STATE_OID, SyncDoneControl,
        SyncInfoValue, SyncRefreshMode, SyncRequestControl, SyncStateControl, SyncStateType,
        decode_sync_done_control, decode_sync_info_value, decode_sync_state_control,
        encode_sync_request_control,
    };
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
    use rasn::{ber, der};
    use rasn_ldap::{
        AuthenticationChoice as RasnAuthChoice, BindRequest as RasnBindRequest,
        Control as RasnControl, ExtendedRequest as RasnExtendedRequest,
        LdapMessage as RasnLdapMessage, ProtocolOp as RasnProtocolOp,
    };
    use std::borrow::Cow;
    use std::future::Future;
    use std::io;
    use std::sync::Arc;
    use tempfile::NamedTempFile;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::{Duration, Sleep, timeout};

    async fn connected_stream_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (server_stream, _) = listener.accept().await.unwrap();
        let client_stream = client.await.unwrap();

        (server_stream, client_stream)
    }

    async fn replication_audit_request_context(temp_file: &NamedTempFile) -> RequestContext {
        let audit_logger = AuditLogger::new(temp_file.path(), AuditLevel::Debug);
        audit_logger.initialize().await.unwrap();
        RequestContext {
            client_ip: Some("127.0.0.1".parse().unwrap()),
            session_id: Some(2026),
            security: Some(Arc::new(LegacySecurityConfig {
                audit_logger: Some(audit_logger),
                audit_config: LegacyAuditConfig::default(),
                access_control: None,
                root_dn: Some("cn=admin,dc=example,dc=org".to_string()),
                security_policy: LegacySecurityPolicy::default(),
            })),
            metrics: None,
            auth_metadata: None,
        }
    }

    #[derive(Default)]
    struct DelayedCaptureStream {
        write_delay: Duration,
        pending_write: Option<Pin<Box<Sleep>>>,
        written: Vec<u8>,
    }

    impl DelayedCaptureStream {
        fn new(write_delay: Duration) -> Self {
            Self {
                write_delay,
                pending_write: None,
                written: Vec::new(),
            }
        }

        fn written_bytes(&self) -> &[u8] {
            &self.written
        }
    }

    impl tokio::io::AsyncRead for DelayedCaptureStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<Result<(), io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    impl tokio::io::AsyncWrite for DelayedCaptureStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            if self.write_delay.is_zero() {
                self.written.extend_from_slice(buf);
                return Poll::Ready(Ok(buf.len()));
            }

            if self.pending_write.is_none() {
                self.pending_write = Some(Box::pin(tokio::time::sleep(self.write_delay)));
            }

            let Some(delay) = self.pending_write.as_mut() else {
                return Poll::Pending;
            };

            if delay.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }

            self.pending_write = None;
            self.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            Poll::Ready(Ok(()))
        }
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

    async fn bind_result_code_for_control(
        oid: &str,
        criticality: bool,
        value: Option<&[u8]>,
    ) -> ParserResultCode {
        let backend = Arc::new(MockBackend::from_credentials([(
            String::from("cn=admin,dc=example,dc=org"),
            b"secret".to_vec(),
        )]));
        let schema = Arc::new(LdapSchema::with_core_schema());
        let (server_stream, mut client_stream) = connected_stream_pair().await;

        let server_task = tokio::spawn(async move {
            handle_client(server_stream, backend, schema).await;
        });

        let encoded = bind_request_with_controls(11, vec![rasn_control(oid, criticality, value)]);
        client_stream.write_all(&encoded).await.unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();
        let result_code = match &messages[0].protocol_op {
            ProtocolOp::BindResponse(bind_response) => bind_response.result.result_code,
            other => panic!("unexpected response: {:?}", other),
        };

        client_stream.shutdown().await.unwrap();
        server_task.await.unwrap();
        result_code
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

    fn referral_entry(dn: &str, urls: &[&str]) -> DirectoryEntry {
        DirectoryEntry::new(
            dn,
            HashMap::from([
                (
                    "objectclass".to_string(),
                    vec![
                        "top".to_string(),
                        "extensibleObject".to_string(),
                        "referral".to_string(),
                    ],
                ),
                (
                    "ref".to_string(),
                    urls.iter().map(|url| (*url).to_string()).collect(),
                ),
                ("cn".to_string(), vec!["referral".to_string()]),
            ]),
        )
    }

    fn sync_search_request() -> SearchRequest<'static> {
        SearchRequest {
            base_object: LdapDN(Cow::Owned("dc=example,dc=org".to_string())),
            scope: SearchScope::WholeSubtree,
            deref_aliases: DerefAliases(0),
            size_limit: 0,
            time_limit: 0,
            types_only: false,
            filter: Filter::Present(LdapString(Cow::Owned("objectClass".to_string()))),
            attributes: Vec::new(),
        }
    }

    fn sync_request_controls(mode: SyncRefreshMode, cookie: Option<&[u8]>) -> RequestControls {
        RequestControls::new(vec![LdapControl::new(
            SYNC_REQUEST_OID,
            true,
            Some(
                encode_sync_request_control(&SyncRequestControl {
                    mode,
                    cookie: cookie.map(|cookie| cookie.to_vec()),
                    reload_hint: false,
                })
                .unwrap(),
            ),
        )])
    }

    fn manage_dsa_it_request_controls() -> RequestControls {
        RequestControls::new(vec![LdapControl::new(MANAGE_DSA_IT_OID, true, None)])
    }

    fn sync_state_response(message: &ldap_parser::ldap::LdapMessage<'_>) -> SyncStateControl {
        let controls = message.controls.as_ref().expect("response controls");
        let control = controls
            .iter()
            .find(|control| control.control_type.0.as_ref() == SYNC_STATE_OID)
            .expect("sync state response control");
        decode_sync_state_control(control.control_value.as_deref()).unwrap()
    }

    fn sync_done_response(message: &ldap_parser::ldap::LdapMessage<'_>) -> SyncDoneControl {
        let controls = message.controls.as_ref().expect("response controls");
        let control = controls
            .iter()
            .find(|control| control.control_type.0.as_ref() == SYNC_DONE_OID)
            .expect("sync done response control");
        decode_sync_done_control(control.control_value.as_deref()).unwrap()
    }

    fn sync_info_response(message: &ldap_parser::ldap::LdapMessage<'_>) -> SyncInfoValue {
        match &message.protocol_op {
            ProtocolOp::IntermediateResponse(response) => {
                assert_eq!(
                    response
                        .response_name
                        .as_ref()
                        .expect("sync info response name")
                        .0
                        .as_ref(),
                    SYNC_INFO_OID
                );
                decode_sync_info_value(
                    response
                        .response_value
                        .as_deref()
                        .expect("sync info response value"),
                )
                .unwrap()
            }
            other => panic!("unexpected protocol op: {:?}", other),
        }
    }

    fn subtree_search_request(base_dn: &str, attributes: &[&str]) -> SearchRequest<'static> {
        SearchRequest {
            base_object: LdapDN(Cow::Owned(base_dn.to_string())),
            scope: SearchScope::WholeSubtree,
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

    fn paged_results_request_controls(size: u32, cookie: &[u8]) -> RequestControls {
        RequestControls::new(vec![LdapControl::new(
            PAGED_RESULTS_OID,
            false,
            Some(encode_paged_results_control(size, cookie).unwrap()),
        )])
    }

    fn paged_results_response(message: &ldap_parser::ldap::LdapMessage<'_>) -> PagedResultsControl {
        let controls = message.controls.as_ref().expect("response controls");
        let control = controls
            .iter()
            .find(|control| control.control_type.0.as_ref() == PAGED_RESULTS_OID)
            .expect("paged results response control");
        decode_paged_results_control(control.control_value.as_deref()).unwrap()
    }

    fn server_side_sort_request_controls(keys: &[SortKey], critical: bool) -> RequestControls {
        RequestControls::new(vec![LdapControl::new(
            SERVER_SIDE_SORT_REQUEST_OID,
            critical,
            Some(encode_server_side_sort_request_control(keys).unwrap()),
        )])
    }

    fn paged_and_sort_request_controls(
        size: u32,
        cookie: &[u8],
        keys: &[SortKey],
        critical: bool,
    ) -> RequestControls {
        RequestControls::new(vec![
            LdapControl::new(
                PAGED_RESULTS_OID,
                false,
                Some(encode_paged_results_control(size, cookie).unwrap()),
            ),
            LdapControl::new(
                SERVER_SIDE_SORT_REQUEST_OID,
                critical,
                Some(encode_server_side_sort_request_control(keys).unwrap()),
            ),
        ])
    }

    fn server_side_sort_response(
        message: &ldap_parser::ldap::LdapMessage<'_>,
    ) -> ServerSideSortResponseControl {
        let controls = message.controls.as_ref().expect("response controls");
        let control = controls
            .iter()
            .find(|control| control.control_type.0.as_ref() == SERVER_SIDE_SORT_RESPONSE_OID)
            .expect("server-side sort response control");
        decode_server_side_sort_response_control(control.control_value.as_deref()).unwrap()
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
            Change {
                operation: Operation(3),
                modification: PartialAttribute {
                    attr_type: LdapString(Cow::Owned("exampleCounter".to_string())),
                    attr_vals: vec![AttributeValue(Cow::Owned(b"5".to_vec()))],
                },
            },
        ];

        let modifications = convert_modifications(changes).unwrap();
        assert_eq!(modifications.len(), 4);
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
        assert_eq!(modifications[3].operation, ModifyOperation::Increment);
        assert_eq!(modifications[3].attribute, "examplecounter");
        assert_eq!(modifications[3].values, vec!["5".to_string()]);
    }

    #[test]
    fn convert_modifications_rejects_unknown_operation() {
        let changes = vec![Change {
            operation: Operation(4),
            modification: PartialAttribute {
                attr_type: LdapString(Cow::Owned("cn".to_string())),
                attr_vals: vec![AttributeValue(Cow::Owned(b"Alice".to_vec()))],
            },
        }];

        let err = convert_modifications(changes).unwrap_err();
        assert!(err.to_string().contains("unsupported modify operation 4"));
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
            assertion_value: Cow::Borrowed(b"Alice"),
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
            assertion_value: Cow::Borrowed(b"alice"),
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
                security_policy: LegacySecurityPolicy::default(),
            })),
            metrics: None,
            auth_metadata: None,
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
                security_policy: LegacySecurityPolicy::default(),
            })),
            metrics: None,
            auth_metadata: None,
        };
        let mut session = ConnectionSession::default();
        session.bind("cn=user,dc=example,dc=org".to_string());
        let request_controls = RequestControls::default();

        let request = CompareRequest {
            entry: LdapDN(Cow::Owned("cn=target,dc=example,dc=org".to_string())),
            ava: AttributeValueAssertion {
                attribute_desc: LdapString(Cow::Owned("cn".to_string())),
                assertion_value: Cow::Borrowed(b"target"),
            },
        };

        let (mut server_stream, mut client_stream) = connected_stream_pair().await;
        let schema = LdapSchema::default();
        handle_compare_request_with_context(
            &mut server_stream,
            &backend,
            &schema,
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

    #[test]
    fn connection_operation_registry_cleans_up_paged_searches_on_cancel_and_abandon() {
        let mut registry = ConnectionOperationRegistry::default();
        let signature = SearchRequestSignature {
            base_dn: "dc=example,dc=org".to_string(),
            scope: 2,
            deref_aliases: 0,
            size_limit: 0,
            time_limit: 0,
            types_only: false,
            filter_repr: "present".to_string(),
            attributes: vec!["cn".to_string()],
            sort_keys: None,
        };

        let cancel_cookie = registry.remember_paged_search(PagedSearchCursor {
            signature: signature.clone(),
            total_size: 3,
            remaining_entries: vec![DirectoryEntry::new(
                "cn=a,dc=example,dc=org",
                HashMap::from([("cn".to_string(), vec!["a".to_string()])]),
            )],
            completion_code: ResultCode::Success,
            completion_diagnostic: "",
        });
        registry.register(41, ConnectionOperationKind::Search, true);
        registry.attach_paged_search_to_operation(41, cancel_cookie.clone());
        assert_eq!(registry.request_cancel(41), CancelRequestOutcome::Accepted);
        registry.finish(41, FinishedOperationState::Canceled);
        assert!(registry.paged_search(cancel_cookie.as_slice()).is_none());

        let abandon_cookie = registry.remember_paged_search(PagedSearchCursor {
            signature,
            total_size: 2,
            remaining_entries: vec![DirectoryEntry::new(
                "cn=b,dc=example,dc=org",
                HashMap::from([("cn".to_string(), vec!["b".to_string()])]),
            )],
            completion_code: ResultCode::Success,
            completion_diagnostic: "",
        });
        registry.register(42, ConnectionOperationKind::Search, true);
        registry.attach_paged_search_to_operation(42, abandon_cookie.clone());
        assert!(registry.request_abandon(42));
        registry.finish(42, FinishedOperationState::Abandoned);
        assert!(registry.paged_search(abandon_cookie.as_slice()).is_none());
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
        let schema = LdapSchema::default();
        handle_modify_request_with_context(
            &mut server_stream,
            &backend,
            &schema,
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

    fn modify_increment_test_schema() -> LdapSchema {
        let mut schema = LdapSchema::with_core_schema();
        schema
            .load_ldif_str(
                "
dn: cn=schema
attributeTypes: ( 1.3.6.1.4.1.55555.152.1 NAME 'exampleCounter' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
objectClasses: ( 1.3.6.1.4.1.55555.152.2 NAME 'exampleCounterObject' SUP top AUXILIARY MAY exampleCounter )
",
            )
            .unwrap();
        schema
    }

    fn modify_increment_request(increment_values: Vec<&[u8]>) -> ModifyRequest<'static> {
        ModifyRequest {
            object: LdapDN(Cow::Owned("cn=Alice,dc=example,dc=org".to_string())),
            changes: vec![Change {
                operation: Operation(3),
                modification: PartialAttribute {
                    attr_type: LdapString(Cow::Owned("exampleCounter".to_string())),
                    attr_vals: increment_values
                        .into_iter()
                        .map(|value| AttributeValue(Cow::Owned(value.to_vec())))
                        .collect(),
                },
            }],
        }
    }

    async fn add_counter_entry(backend: &MockBackend, counter: &str) {
        backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=Alice,dc=example,dc=org",
                    HashMap::from([
                        ("cn".to_string(), vec!["Alice".to_string()]),
                        ("sn".to_string(), vec!["User".to_string()]),
                        (
                            "objectclass".to_string(),
                            vec!["person".to_string(), "exampleCounterObject".to_string()],
                        ),
                        ("examplecounter".to_string(), vec![counter.to_string()]),
                    ]),
                ),
                Vec::new(),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn modify_increment_updates_integer_attribute_atomically() {
        let backend = MockBackend::new();
        add_counter_entry(&backend, "41").await;
        let schema = modify_increment_test_schema();
        let session = bound_schema_session();
        let request_controls = RequestControls::default();
        let (mut server_stream, mut client_stream) = connected_stream_pair().await;

        handle_modify_request_with_context(
            &mut server_stream,
            &backend,
            &schema,
            10,
            modify_increment_request(vec![b"1"]),
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
            stored.attributes.get("examplecounter").unwrap(),
            &vec!["42".to_string()]
        );
    }

    #[tokio::test]
    async fn modify_increment_rejects_malformed_increment_without_mutating_entry() {
        let backend = MockBackend::new();
        add_counter_entry(&backend, "41").await;
        let schema = modify_increment_test_schema();
        let session = bound_schema_session();
        let request_controls = RequestControls::default();
        let (mut server_stream, mut client_stream) = connected_stream_pair().await;

        handle_modify_request_with_context(
            &mut server_stream,
            &backend,
            &schema,
            11,
            modify_increment_request(vec![b"1", b"2"]),
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
                    ParserResultCode::ProtocolError
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
            stored.attributes.get("examplecounter").unwrap(),
            &vec!["41".to_string()]
        );
    }

    const ONLINE_TEST_ATTRIBUTE: &str = "( 1.3.6.1.4.1.55555.1.1 NAME 'openDRTestCode' DESC 'OpenDR online schema test attribute' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )";
    const ONLINE_TEST_OBJECT_CLASS: &str = "( 1.3.6.1.4.1.55555.2.1 NAME 'openDRTestObject' DESC 'OpenDR online schema test object class' SUP top STRUCTURAL MUST cn MAY openDRTestCode )";

    fn bound_schema_session() -> ConnectionSession {
        let mut session = ConnectionSession::default();
        session.bind("cn=admin,dc=example,dc=org".to_string());
        session
    }

    fn online_schema_runtime_config(schema_dir: &std::path::Path) -> LegacyServerConfig {
        LegacyServerConfig {
            naming_contexts: vec!["dc=example,dc=org".to_string()],
            schema_dir: schema_dir.to_path_buf(),
            allow_online_schema_updates: true,
            ..LegacyServerConfig::default()
        }
    }

    fn online_schema_add_modifications() -> Vec<Modification> {
        vec![
            Modification {
                operation: ModifyOperation::Add,
                attribute: "attributeTypes".to_string(),
                values: vec![ONLINE_TEST_ATTRIBUTE.to_string()],
            },
            Modification {
                operation: ModifyOperation::Add,
                attribute: "objectClasses".to_string(),
                values: vec![ONLINE_TEST_OBJECT_CLASS.to_string()],
            },
        ]
    }

    #[tokio::test]
    async fn online_schema_modify_adds_definition_and_persists() {
        let temp_dir = tempfile::tempdir().unwrap();
        let runtime_config = online_schema_runtime_config(temp_dir.path());
        let backend = MockBackend::new();
        let schema = shared_schema(LdapSchema::with_core_schema());
        let session = bound_schema_session();

        apply_online_schema_modify(
            &backend,
            &schema,
            &runtime_config,
            &session,
            online_schema_add_modifications(),
        )
        .await
        .unwrap();

        let schema_snapshot = schema_snapshot(&schema);
        assert!(
            schema_snapshot
                .get_attribute_type("openDRTestCode")
                .is_some()
        );
        assert!(
            schema_snapshot
                .get_object_class("openDRTestObject")
                .is_some()
        );
        schema_snapshot
            .validate_entry(&HashMap::from([
                (
                    "objectclass".to_string(),
                    vec!["top".to_string(), "openDRTestObject".to_string()],
                ),
                ("cn".to_string(), vec!["custom entry".to_string()]),
                ("openDRTestCode".to_string(), vec!["alpha".to_string()]),
            ]))
            .unwrap();

        let online_schema_path = temp_dir.path().join(ONLINE_SCHEMA_FILE);
        let persisted = std::fs::read_to_string(&online_schema_path).unwrap();
        assert!(persisted.contains("attributeTypes:"));
        assert!(persisted.contains("openDRTestObject"));

        let mut reloaded_schema = LdapSchema::with_core_schema();
        reloaded_schema.load_schema_dir(temp_dir.path()).unwrap();
        assert!(
            reloaded_schema
                .get_attribute_type("openDRTestCode")
                .is_some()
        );
        assert!(
            reloaded_schema
                .get_object_class("openDRTestObject")
                .is_some()
        );
    }

    #[tokio::test]
    async fn online_schema_modify_rejects_disabled_updates() {
        let temp_dir = tempfile::tempdir().unwrap();
        let runtime_config = LegacyServerConfig {
            schema_dir: temp_dir.path().to_path_buf(),
            allow_online_schema_updates: false,
            ..LegacyServerConfig::default()
        };
        let backend = MockBackend::new();
        let schema = shared_schema(LdapSchema::with_core_schema());
        let session = bound_schema_session();

        let error = apply_online_schema_modify(
            &backend,
            &schema,
            &runtime_config,
            &session,
            online_schema_add_modifications(),
        )
        .await
        .unwrap_err();

        assert!(matches!(error, OnlineSchemaUpdateError::Disabled));
        assert!(!temp_dir.path().join(ONLINE_SCHEMA_FILE).exists());
    }

    #[tokio::test]
    async fn online_schema_modify_rejects_deleting_object_class_used_by_existing_entry() {
        let temp_dir = tempfile::tempdir().unwrap();
        let runtime_config = online_schema_runtime_config(temp_dir.path());
        let backend = MockBackend::new();
        let schema = shared_schema(LdapSchema::with_core_schema());
        let session = bound_schema_session();

        apply_online_schema_modify(
            &backend,
            &schema,
            &runtime_config,
            &session,
            online_schema_add_modifications(),
        )
        .await
        .unwrap();

        backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=custom entry,dc=example,dc=org",
                    HashMap::from([
                        (
                            "objectclass".to_string(),
                            vec!["top".to_string(), "openDRTestObject".to_string()],
                        ),
                        ("cn".to_string(), vec!["custom entry".to_string()]),
                        ("opendrtestcode".to_string(), vec!["alpha".to_string()]),
                    ]),
                ),
                Vec::new(),
            )
            .await
            .unwrap();

        let error = apply_online_schema_modify(
            &backend,
            &schema,
            &runtime_config,
            &session,
            vec![Modification {
                operation: ModifyOperation::Delete,
                attribute: "objectClasses".to_string(),
                values: vec![ONLINE_TEST_OBJECT_CLASS.to_string()],
            }],
        )
        .await
        .unwrap_err();

        assert!(matches!(error, OnlineSchemaUpdateError::Unsafe(_)));
        assert!(
            schema_snapshot(&schema)
                .get_object_class("openDRTestObject")
                .is_some()
        );
        let persisted = std::fs::read_to_string(temp_dir.path().join(ONLINE_SCHEMA_FILE)).unwrap();
        assert!(persisted.contains("openDRTestObject"));
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
        let schema = LdapSchema::default();
        handle_moddn_request_with_context(
            &mut server_stream,
            &backend,
            &schema,
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
    async fn unsupported_expected_controls_follow_generic_criticality_semantics() {
        const ASSERTION_CONTROL_OID: &str = "1.3.6.1.1.12";
        const PRE_READ_CONTROL_OID: &str = "1.3.6.1.1.13.1";
        const POST_READ_CONTROL_OID: &str = "1.3.6.1.1.13.2";

        for oid in [
            ASSERTION_CONTROL_OID,
            PRE_READ_CONTROL_OID,
            POST_READ_CONTROL_OID,
        ] {
            assert_eq!(
                bind_result_code_for_control(oid, true, None).await,
                ParserResultCode::UnavailableCriticalExtension
            );
            assert_eq!(
                bind_result_code_for_control(oid, false, Some(b"ignored")).await,
                ParserResultCode::Success
            );
        }
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
        assert!(!attributes.contains_key("supportedSASLMechanisms"));
        assert_eq!(
            attributes.get("contextCSN").unwrap(),
            &vec!["1696680896789012#001#000001#000000".to_string()]
        );
        assert_eq!(
            attributes.get("supportedFeatures").unwrap(),
            &vec![crate::search_protocol::MODIFY_INCREMENT_FEATURE_OID.to_string()]
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
        let mut supported_controls = attributes.get("supportedControl").unwrap().clone();
        supported_controls.sort();
        let mut expected_controls = vec![
            MANAGE_DSA_IT_OID.to_string(),
            PAGED_RESULTS_OID.to_string(),
            SERVER_SIDE_SORT_REQUEST_OID.to_string(),
            SYNC_REQUEST_OID.to_string(),
        ];
        expected_controls.sort();
        assert_eq!(supported_controls, expected_controls);

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
        let request =
            search_request_for_base("", &["supportedExtension", "supportedSASLMechanisms"]);
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
        assert_eq!(
            attributes.get("supportedSASLMechanisms").unwrap(),
            &vec!["PLAIN".to_string()]
        );
    }

    #[tokio::test]
    async fn paged_search_returns_multi_page_results_and_final_empty_cookie() {
        let backend = MockBackend::new();
        for user in ["one", "two", "three", "four", "five"] {
            backend
                .add_entry(
                    DirectoryEntry::new(
                        format!("cn={},dc=example,dc=org", user),
                        HashMap::from([
                            ("cn".to_string(), vec![user.to_string()]),
                            ("sn".to_string(), vec!["User".to_string()]),
                            ("objectclass".to_string(), vec!["person".to_string()]),
                        ]),
                    ),
                    Vec::new(),
                )
                .await
                .unwrap();
        }

        let schema = LdapSchema::with_core_schema();
        let runtime_config = LegacyServerConfig::default();
        let request_context = RequestContext::default();
        let session = ConnectionSession::default();
        let mut operation_registry = ConnectionOperationRegistry::default();
        let (mut server_stream, mut client_stream) = connected_stream_pair().await;

        let request_controls = paged_results_request_controls(2, &[]);
        handle_search_request_with_context_and_registry(
            &mut server_stream,
            &backend,
            &schema,
            &runtime_config,
            31,
            subtree_search_request("dc=example,dc=org", &["cn"]),
            &session,
            &mut operation_registry,
            &request_context,
            &request_controls,
            false,
            false,
        )
        .await
        .unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();
        assert_eq!(messages.len(), 3);
        let first_cookie = paged_results_response(messages.last().unwrap());
        assert_eq!(first_cookie.size, 5);
        assert!(!first_cookie.cookie.is_empty());

        let request_controls = paged_results_request_controls(2, &first_cookie.cookie);
        handle_search_request_with_context_and_registry(
            &mut server_stream,
            &backend,
            &schema,
            &runtime_config,
            32,
            subtree_search_request("dc=example,dc=org", &["cn"]),
            &session,
            &mut operation_registry,
            &request_context,
            &request_controls,
            false,
            false,
        )
        .await
        .unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();
        assert_eq!(messages.len(), 3);
        let second_cookie = paged_results_response(messages.last().unwrap());
        assert_eq!(second_cookie.size, 5);
        assert_eq!(second_cookie.cookie, first_cookie.cookie);

        let request_controls = paged_results_request_controls(2, &second_cookie.cookie);
        handle_search_request_with_context_and_registry(
            &mut server_stream,
            &backend,
            &schema,
            &runtime_config,
            33,
            subtree_search_request("dc=example,dc=org", &["cn"]),
            &session,
            &mut operation_registry,
            &request_context,
            &request_controls,
            false,
            false,
        )
        .await
        .unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();
        assert_eq!(messages.len(), 2);
        let final_cookie = paged_results_response(messages.last().unwrap());
        assert_eq!(final_cookie.size, 5);
        assert!(final_cookie.cookie.is_empty());

        let mut seen_dns = Vec::new();
        for message in messages {
            if let ProtocolOp::SearchResultEntry(entry) = &message.protocol_op {
                seen_dns.push(entry.object_name.0.as_ref().to_string());
            }
        }
        assert_eq!(seen_dns.len(), 1);
        assert!(
            operation_registry
                .paged_search(first_cookie.cookie.as_slice())
                .is_none()
        );
    }

    #[tokio::test]
    async fn paged_search_rejects_replayed_cookie_after_completion() {
        let backend = MockBackend::new();
        for user in ["one", "two", "three"] {
            backend
                .add_entry(
                    DirectoryEntry::new(
                        format!("cn={},dc=example,dc=org", user),
                        HashMap::from([
                            ("cn".to_string(), vec![user.to_string()]),
                            ("sn".to_string(), vec!["User".to_string()]),
                            ("objectclass".to_string(), vec!["person".to_string()]),
                        ]),
                    ),
                    Vec::new(),
                )
                .await
                .unwrap();
        }

        let schema = LdapSchema::with_core_schema();
        let runtime_config = LegacyServerConfig::default();
        let request_context = RequestContext::default();
        let session = ConnectionSession::default();
        let mut operation_registry = ConnectionOperationRegistry::default();
        let (mut server_stream, mut client_stream) = connected_stream_pair().await;

        let request_controls = paged_results_request_controls(2, &[]);
        handle_search_request_with_context_and_registry(
            &mut server_stream,
            &backend,
            &schema,
            &runtime_config,
            34,
            subtree_search_request("dc=example,dc=org", &["cn"]),
            &session,
            &mut operation_registry,
            &request_context,
            &request_controls,
            false,
            false,
        )
        .await
        .unwrap();
        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();
        let first_cookie = paged_results_response(messages.last().unwrap());

        let request_controls = paged_results_request_controls(2, &first_cookie.cookie);
        handle_search_request_with_context_and_registry(
            &mut server_stream,
            &backend,
            &schema,
            &runtime_config,
            35,
            subtree_search_request("dc=example,dc=org", &["cn"]),
            &session,
            &mut operation_registry,
            &request_context,
            &request_controls,
            false,
            false,
        )
        .await
        .unwrap();
        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();
        assert!(
            paged_results_response(messages.last().unwrap())
                .cookie
                .is_empty()
        );

        let request_controls = paged_results_request_controls(2, &first_cookie.cookie);
        handle_search_request_with_context_and_registry(
            &mut server_stream,
            &backend,
            &schema,
            &runtime_config,
            36,
            subtree_search_request("dc=example,dc=org", &["cn"]),
            &session,
            &mut operation_registry,
            &request_context,
            &request_controls,
            false,
            false,
        )
        .await
        .unwrap();
        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 1);
        match &messages[0].protocol_op {
            ProtocolOp::SearchResultDone(done) => {
                assert_eq!(done.result_code, ParserResultCode::UnwillingToPerform);
                assert_eq!(
                    done.diagnostic_message.0.as_ref(),
                    "paged results cookie is not valid for this search sequence"
                );
            }
            other => panic!("unexpected response: {:?}", other),
        }
    }

    #[tokio::test]
    async fn server_side_sort_orders_results_by_requested_attribute() {
        let backend = MockBackend::new();
        for (dn, cn) in [
            ("cn=zeta,dc=example,dc=org", "Zulu"),
            ("cn=alpha,dc=example,dc=org", "alpha"),
            ("cn=beta,dc=example,dc=org", "Beta"),
        ] {
            backend
                .add_entry(
                    DirectoryEntry::new(
                        dn,
                        HashMap::from([
                            ("cn".to_string(), vec![cn.to_string()]),
                            ("objectclass".to_string(), vec!["person".to_string()]),
                        ]),
                    ),
                    Vec::new(),
                )
                .await
                .unwrap();
        }

        let schema = LdapSchema::with_core_schema();
        let runtime_config = LegacyServerConfig::default();
        let request_context = RequestContext::default();
        let session = ConnectionSession::default();
        let mut operation_registry = ConnectionOperationRegistry::default();
        let (mut server_stream, mut client_stream) = connected_stream_pair().await;

        let request_controls = server_side_sort_request_controls(
            &[SortKey {
                attribute_type: "cn".to_string(),
                ordering_rule: None,
                reverse_order: false,
            }],
            false,
        );
        handle_search_request_with_context_and_registry(
            &mut server_stream,
            &backend,
            &schema,
            &runtime_config,
            37,
            subtree_search_request("dc=example,dc=org", &["cn"]),
            &session,
            &mut operation_registry,
            &request_context,
            &request_controls,
            false,
            false,
        )
        .await
        .unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(
            search_result_dns(&messages),
            vec![
                "cn=alpha,dc=example,dc=org".to_string(),
                "cn=beta,dc=example,dc=org".to_string(),
                "cn=zeta,dc=example,dc=org".to_string(),
            ]
        );
        let sort_response = server_side_sort_response(messages.last().unwrap());
        assert_eq!(sort_response.result, ServerSideSortResultCode::Success);
        assert_eq!(sort_response.attribute_type, None);
    }

    #[tokio::test]
    async fn server_side_sort_supports_multi_key_ordering_and_missing_values() {
        let backend = MockBackend::new();
        for (dn, attrs) in [
            (
                "cn=one,dc=example,dc=org",
                HashMap::from([
                    ("sn".to_string(), vec!["Jones".to_string()]),
                    ("givenname".to_string(), vec!["Zara".to_string()]),
                    ("objectclass".to_string(), vec!["person".to_string()]),
                ]),
            ),
            (
                "cn=two,dc=example,dc=org",
                HashMap::from([
                    ("sn".to_string(), vec!["Jones".to_string()]),
                    ("givenname".to_string(), vec!["Adam".to_string()]),
                    ("objectclass".to_string(), vec!["person".to_string()]),
                ]),
            ),
            (
                "cn=three,dc=example,dc=org",
                HashMap::from([
                    ("sn".to_string(), vec!["Jones".to_string()]),
                    ("objectclass".to_string(), vec!["person".to_string()]),
                ]),
            ),
            (
                "cn=four,dc=example,dc=org",
                HashMap::from([
                    ("sn".to_string(), vec!["Smith".to_string()]),
                    ("givenname".to_string(), vec!["Ava".to_string()]),
                    ("objectclass".to_string(), vec!["person".to_string()]),
                ]),
            ),
        ] {
            backend
                .add_entry(DirectoryEntry::new(dn, attrs), Vec::new())
                .await
                .unwrap();
        }

        let schema = LdapSchema::with_core_schema();
        let runtime_config = LegacyServerConfig::default();
        let request_context = RequestContext::default();
        let session = ConnectionSession::default();
        let mut operation_registry = ConnectionOperationRegistry::default();
        let (mut server_stream, mut client_stream) = connected_stream_pair().await;

        let request_controls = server_side_sort_request_controls(
            &[
                SortKey {
                    attribute_type: "sn".to_string(),
                    ordering_rule: None,
                    reverse_order: false,
                },
                SortKey {
                    attribute_type: "givenName".to_string(),
                    ordering_rule: None,
                    reverse_order: false,
                },
            ],
            false,
        );
        handle_search_request_with_context_and_registry(
            &mut server_stream,
            &backend,
            &schema,
            &runtime_config,
            38,
            subtree_search_request("dc=example,dc=org", &["sn", "givenName"]),
            &session,
            &mut operation_registry,
            &request_context,
            &request_controls,
            false,
            false,
        )
        .await
        .unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(
            search_result_dns(&messages),
            vec![
                "cn=two,dc=example,dc=org".to_string(),
                "cn=one,dc=example,dc=org".to_string(),
                "cn=three,dc=example,dc=org".to_string(),
                "cn=four,dc=example,dc=org".to_string(),
            ]
        );
        let sort_response = server_side_sort_response(messages.last().unwrap());
        assert_eq!(sort_response.result, ServerSideSortResultCode::Success);
    }

    #[tokio::test]
    async fn server_side_sort_rejects_unsupported_ordering_rule_with_control() {
        let backend = MockBackend::new();
        backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=user,dc=example,dc=org",
                    HashMap::from([
                        ("cn".to_string(), vec!["User".to_string()]),
                        ("objectclass".to_string(), vec!["person".to_string()]),
                    ]),
                ),
                Vec::new(),
            )
            .await
            .unwrap();

        let schema = LdapSchema::with_core_schema();
        let runtime_config = LegacyServerConfig::default();
        let request_context = RequestContext::default();
        let session = ConnectionSession::default();
        let mut operation_registry = ConnectionOperationRegistry::default();
        let (mut server_stream, mut client_stream) = connected_stream_pair().await;

        let request_controls = server_side_sort_request_controls(
            &[SortKey {
                attribute_type: "cn".to_string(),
                ordering_rule: Some("caseIgnoreOrderingMatch".to_string()),
                reverse_order: false,
            }],
            false,
        );
        handle_search_request_with_context_and_registry(
            &mut server_stream,
            &backend,
            &schema,
            &runtime_config,
            39,
            subtree_search_request("dc=example,dc=org", &["cn"]),
            &session,
            &mut operation_registry,
            &request_context,
            &request_controls,
            false,
            false,
        )
        .await
        .unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 1);
        match &messages[0].protocol_op {
            ProtocolOp::SearchResultDone(done) => {
                assert_eq!(done.result_code, ParserResultCode::Success);
            }
            other => panic!("unexpected response: {:?}", other),
        }
        let sort_response = server_side_sort_response(&messages[0]);
        assert_eq!(
            sort_response.result,
            ServerSideSortResultCode::InappropriateMatching
        );
        assert_eq!(sort_response.attribute_type.as_deref(), Some("cn"));
    }

    #[tokio::test]
    async fn paged_server_side_sort_preserves_sorted_sequence_across_pages() {
        let backend = MockBackend::new();
        for (dn, cn) in [
            ("cn=zeta,dc=example,dc=org", "Zulu"),
            ("cn=alpha,dc=example,dc=org", "alpha"),
            ("cn=gamma,dc=example,dc=org", "Gamma"),
            ("cn=beta,dc=example,dc=org", "Beta"),
            ("cn=delta,dc=example,dc=org", "delta"),
        ] {
            backend
                .add_entry(
                    DirectoryEntry::new(
                        dn,
                        HashMap::from([
                            ("cn".to_string(), vec![cn.to_string()]),
                            ("objectclass".to_string(), vec!["person".to_string()]),
                        ]),
                    ),
                    Vec::new(),
                )
                .await
                .unwrap();
        }

        let schema = LdapSchema::with_core_schema();
        let runtime_config = LegacyServerConfig::default();
        let request_context = RequestContext::default();
        let session = ConnectionSession::default();
        let mut operation_registry = ConnectionOperationRegistry::default();
        let (mut server_stream, mut client_stream) = connected_stream_pair().await;
        let sort_keys = [SortKey {
            attribute_type: "cn".to_string(),
            ordering_rule: None,
            reverse_order: false,
        }];

        let request_controls = paged_and_sort_request_controls(2, &[], &sort_keys, false);
        handle_search_request_with_context_and_registry(
            &mut server_stream,
            &backend,
            &schema,
            &runtime_config,
            40,
            subtree_search_request("dc=example,dc=org", &["cn"]),
            &session,
            &mut operation_registry,
            &request_context,
            &request_controls,
            false,
            false,
        )
        .await
        .unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, first_page) = parse_ldap_messages(&response).unwrap();
        assert_eq!(
            search_result_dns(&first_page),
            vec![
                "cn=alpha,dc=example,dc=org".to_string(),
                "cn=beta,dc=example,dc=org".to_string(),
            ]
        );
        assert_eq!(
            server_side_sort_response(first_page.last().unwrap()).result,
            ServerSideSortResultCode::Success
        );
        let first_cookie = paged_results_response(first_page.last().unwrap());
        assert!(!first_cookie.cookie.is_empty());

        let request_controls =
            paged_and_sort_request_controls(2, &first_cookie.cookie, &sort_keys, false);
        handle_search_request_with_context_and_registry(
            &mut server_stream,
            &backend,
            &schema,
            &runtime_config,
            41,
            subtree_search_request("dc=example,dc=org", &["cn"]),
            &session,
            &mut operation_registry,
            &request_context,
            &request_controls,
            false,
            false,
        )
        .await
        .unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, second_page) = parse_ldap_messages(&response).unwrap();
        assert_eq!(
            search_result_dns(&second_page),
            vec![
                "cn=delta,dc=example,dc=org".to_string(),
                "cn=gamma,dc=example,dc=org".to_string(),
            ]
        );
        assert_eq!(
            server_side_sort_response(second_page.last().unwrap()).result,
            ServerSideSortResultCode::Success
        );
        let second_cookie = paged_results_response(second_page.last().unwrap());
        assert_eq!(second_cookie.cookie, first_cookie.cookie);

        let request_controls =
            paged_and_sort_request_controls(2, &second_cookie.cookie, &sort_keys, false);
        handle_search_request_with_context_and_registry(
            &mut server_stream,
            &backend,
            &schema,
            &runtime_config,
            42,
            subtree_search_request("dc=example,dc=org", &["cn"]),
            &session,
            &mut operation_registry,
            &request_context,
            &request_controls,
            false,
            false,
        )
        .await
        .unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, third_page) = parse_ldap_messages(&response).unwrap();
        assert_eq!(
            search_result_dns(&third_page),
            vec!["cn=zeta,dc=example,dc=org".to_string()]
        );
        let final_cookie = paged_results_response(third_page.last().unwrap());
        assert!(final_cookie.cookie.is_empty());
        assert_eq!(
            server_side_sort_response(third_page.last().unwrap()).result,
            ServerSideSortResultCode::Success
        );
    }

    #[tokio::test]
    async fn search_honors_time_limit_and_returns_partial_results() {
        let backend = MockBackend::new();
        for user in ["one", "two", "three"] {
            backend
                .add_entry(
                    DirectoryEntry::new(
                        format!("cn={},dc=example,dc=org", user),
                        HashMap::from([
                            ("cn".to_string(), vec![user.to_string()]),
                            ("sn".to_string(), vec!["User".to_string()]),
                            ("objectclass".to_string(), vec!["person".to_string()]),
                        ]),
                    ),
                    Vec::new(),
                )
                .await
                .unwrap();
        }

        let schema = LdapSchema::with_core_schema();
        let runtime_config = LegacyServerConfig {
            naming_contexts: vec!["dc=example,dc=org".to_string()],
            ..LegacyServerConfig::default()
        };
        let request_controls = RequestControls::default();
        let request = SearchRequest {
            base_object: LdapDN(Cow::Owned("dc=example,dc=org".to_string())),
            scope: SearchScope::WholeSubtree,
            deref_aliases: DerefAliases(0),
            size_limit: 0,
            time_limit: 1,
            types_only: false,
            filter: Filter::Present(LdapString(Cow::Owned("cn".to_string()))),
            attributes: vec![LdapString(Cow::Owned("cn".to_string()))],
        };
        let mut stream = DelayedCaptureStream::new(Duration::from_millis(450));

        handle_search_request_with_context(
            &mut stream,
            &backend,
            &schema,
            &runtime_config,
            60,
            request,
            &ConnectionSession::default(),
            &RequestContext::default(),
            &request_controls,
            false,
            true,
        )
        .await
        .unwrap();

        let (_, messages) = parse_ldap_messages(stream.written_bytes()).unwrap();
        let entry_count = messages
            .iter()
            .filter(|message| matches!(message.protocol_op, ProtocolOp::SearchResultEntry(_)))
            .count();
        assert!(entry_count >= 1);
        match &messages.last().unwrap().protocol_op {
            ProtocolOp::SearchResultDone(done) => {
                assert_eq!(done.result_code, ParserResultCode::TimeLimitExceeded);
            }
            other => panic!("unexpected completion: {:?}", other),
        }
    }

    #[tokio::test]
    async fn search_deref_finding_base_object_resolves_alias_base() {
        let backend = MockBackend::new();
        backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=target,dc=example,dc=org",
                    HashMap::from([
                        ("cn".to_string(), vec!["Target User".to_string()]),
                        ("sn".to_string(), vec!["User".to_string()]),
                        ("objectclass".to_string(), vec!["person".to_string()]),
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
                        ("cn".to_string(), vec!["Alias Entry".to_string()]),
                        ("objectclass".to_string(), vec!["alias".to_string()]),
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

        let schema = LdapSchema::with_core_schema();
        let runtime_config = LegacyServerConfig {
            naming_contexts: vec!["dc=example,dc=org".to_string()],
            ..LegacyServerConfig::default()
        };
        let request_controls = RequestControls::default();
        let request = SearchRequest {
            base_object: LdapDN(Cow::Owned("cn=alias,dc=example,dc=org".to_string())),
            scope: SearchScope::BaseObject,
            deref_aliases: DerefAliases(2),
            size_limit: 0,
            time_limit: 0,
            types_only: false,
            filter: Filter::Present(LdapString(Cow::Owned("objectClass".to_string()))),
            attributes: vec![LdapString(Cow::Owned("cn".to_string()))],
        };
        let (mut server_stream, mut client_stream) = connected_stream_pair().await;

        handle_search_request_with_context(
            &mut server_stream,
            &backend,
            &schema,
            &runtime_config,
            61,
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
        match &messages[0].protocol_op {
            ProtocolOp::SearchResultEntry(entry) => {
                assert_eq!(entry.object_name.0.as_ref(), "cn=target,dc=example,dc=org");
                assert_eq!(
                    search_entry_attribute_map(entry).get("cn").unwrap(),
                    &vec!["Target User".to_string()]
                );
            }
            other => panic!("unexpected response: {:?}", other),
        }
    }

    #[tokio::test]
    async fn search_deref_always_differs_from_never_and_detects_alias_cycles() {
        let backend = MockBackend::new();
        backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=target,ou=people,dc=example,dc=org",
                    HashMap::from([
                        ("cn".to_string(), vec!["Target User".to_string()]),
                        ("sn".to_string(), vec!["Target".to_string()]),
                        ("objectclass".to_string(), vec!["person".to_string()]),
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
                        ("cn".to_string(), vec!["External Alias".to_string()]),
                        ("objectclass".to_string(), vec!["alias".to_string()]),
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
        backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=loop-a,dc=example,dc=org",
                    HashMap::from([
                        ("cn".to_string(), vec!["Loop A".to_string()]),
                        ("objectclass".to_string(), vec!["alias".to_string()]),
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
                        ("cn".to_string(), vec!["Loop B".to_string()]),
                        ("objectclass".to_string(), vec!["alias".to_string()]),
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

        let schema = LdapSchema::with_core_schema();
        let runtime_config = LegacyServerConfig {
            naming_contexts: vec!["dc=example,dc=org".to_string()],
            ..LegacyServerConfig::default()
        };
        let request_controls = RequestControls::default();
        let subtree_request = |deref_aliases| SearchRequest {
            base_object: LdapDN(Cow::Owned("ou=aliases,dc=example,dc=org".to_string())),
            scope: SearchScope::WholeSubtree,
            deref_aliases: DerefAliases(deref_aliases),
            size_limit: 0,
            time_limit: 0,
            types_only: false,
            filter: Filter::EqualityMatch(AttributeValueAssertion {
                attribute_desc: LdapString(Cow::Owned("sn".to_string())),
                assertion_value: Cow::Borrowed(b"Target".as_ref()),
            }),
            attributes: vec![LdapString(Cow::Owned("cn".to_string()))],
        };

        let (mut never_server, mut never_client) = connected_stream_pair().await;
        handle_search_request_with_context(
            &mut never_server,
            &backend,
            &schema,
            &runtime_config,
            62,
            subtree_request(0),
            &ConnectionSession::default(),
            &RequestContext::default(),
            &request_controls,
            false,
            true,
        )
        .await
        .unwrap();
        let never_response = read_response(&mut never_client).await;
        let (_, never_messages) = parse_ldap_messages(&never_response).unwrap();
        assert_eq!(
            never_messages
                .iter()
                .filter(|message| matches!(message.protocol_op, ProtocolOp::SearchResultEntry(_)))
                .count(),
            0
        );

        let (mut searching_server, mut searching_client) = connected_stream_pair().await;
        handle_search_request_with_context(
            &mut searching_server,
            &backend,
            &schema,
            &runtime_config,
            63,
            subtree_request(1),
            &ConnectionSession::default(),
            &RequestContext::default(),
            &request_controls,
            false,
            true,
        )
        .await
        .unwrap();
        let searching_response = read_response(&mut searching_client).await;
        let (_, searching_messages) = parse_ldap_messages(&searching_response).unwrap();
        match &searching_messages[0].protocol_op {
            ProtocolOp::SearchResultEntry(entry) => {
                assert_eq!(
                    entry.object_name.0.as_ref(),
                    "cn=target,ou=people,dc=example,dc=org"
                );
            }
            other => panic!("unexpected response: {:?}", other),
        }

        let (mut always_server, mut always_client) = connected_stream_pair().await;
        handle_search_request_with_context(
            &mut always_server,
            &backend,
            &schema,
            &runtime_config,
            64,
            subtree_request(3),
            &ConnectionSession::default(),
            &RequestContext::default(),
            &request_controls,
            false,
            true,
        )
        .await
        .unwrap();
        let always_response = read_response(&mut always_client).await;
        let (_, always_messages) = parse_ldap_messages(&always_response).unwrap();
        match &always_messages[0].protocol_op {
            ProtocolOp::SearchResultEntry(entry) => {
                assert_eq!(
                    entry.object_name.0.as_ref(),
                    "cn=target,ou=people,dc=example,dc=org"
                );
            }
            other => panic!("unexpected response: {:?}", other),
        }

        let cycle_request = SearchRequest {
            base_object: LdapDN(Cow::Owned("cn=loop-a,dc=example,dc=org".to_string())),
            scope: SearchScope::BaseObject,
            deref_aliases: DerefAliases(3),
            size_limit: 0,
            time_limit: 0,
            types_only: false,
            filter: Filter::Present(LdapString(Cow::Owned("objectClass".to_string()))),
            attributes: vec![LdapString(Cow::Owned("cn".to_string()))],
        };
        let (mut cycle_server, mut cycle_client) = connected_stream_pair().await;
        handle_search_request_with_context(
            &mut cycle_server,
            &backend,
            &schema,
            &runtime_config,
            65,
            cycle_request,
            &ConnectionSession::default(),
            &RequestContext::default(),
            &request_controls,
            false,
            true,
        )
        .await
        .unwrap();
        let cycle_response = read_response(&mut cycle_client).await;
        let (_, cycle_messages) = parse_ldap_messages(&cycle_response).unwrap();
        match &cycle_messages[0].protocol_op {
            ProtocolOp::SearchResultDone(done) => {
                assert_eq!(done.result_code, ParserResultCode::LoopDetect);
            }
            other => panic!("unexpected response: {:?}", other),
        }
    }

    #[tokio::test]
    async fn search_rejects_unknown_deref_aliases_mode() {
        let backend = MockBackend::new();
        let schema = LdapSchema::with_core_schema();
        let runtime_config = LegacyServerConfig {
            naming_contexts: vec!["dc=example,dc=org".to_string()],
            ..LegacyServerConfig::default()
        };
        let request_controls = RequestControls::default();
        let request = SearchRequest {
            base_object: LdapDN(Cow::Owned("dc=example,dc=org".to_string())),
            scope: SearchScope::BaseObject,
            deref_aliases: DerefAliases(4),
            size_limit: 0,
            time_limit: 0,
            types_only: false,
            filter: Filter::Present(LdapString(Cow::Owned("objectClass".to_string()))),
            attributes: vec![LdapString(Cow::Owned("cn".to_string()))],
        };
        let (mut server_stream, mut client_stream) = connected_stream_pair().await;

        handle_search_request_with_context(
            &mut server_stream,
            &backend,
            &schema,
            &runtime_config,
            66,
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
        match &messages[0].protocol_op {
            ProtocolOp::SearchResultDone(done) => {
                assert_eq!(done.result_code, ParserResultCode::ProtocolError);
                assert!(
                    done.diagnostic_message
                        .0
                        .as_ref()
                        .contains("derefAliases must be one of")
                );
            }
            other => panic!("unexpected response: {:?}", other),
        }
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
        assert!(
            attributes
                .get("attributeTypes")
                .unwrap()
                .iter()
                .any(|value| value.contains("2.5.4.3") && value.contains("commonName"))
        );
        assert!(
            attributes
                .get("objectClasses")
                .unwrap()
                .iter()
                .any(|value| value.contains("2.16.840.1.113730.3.2.2")
                    && value.contains("inetOrgPerson"))
        );
    }

    #[tokio::test]
    async fn replication_stream_request_without_provider_runtime_returns_unavailable() {
        let backend = MockBackend::new();
        let (mut server_stream, mut client_stream) = connected_stream_pair().await;

        handle_search_request_with_controls(
            &mut server_stream,
            &backend,
            9,
            sync_search_request(),
            &sync_request_controls(SyncRefreshMode::RefreshAndPersist, None),
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
        let request = sync_search_request();
        let request_controls = sync_request_controls(SyncRefreshMode::RefreshAndPersist, None);
        let stream_backend = provider_backend.clone();

        let handler = tokio::spawn(async move {
            handle_search_request_with_controls(
                &mut server_stream,
                stream_backend.as_ref(),
                11,
                request,
                &request_controls,
            )
            .await
            .unwrap();
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        let initial = read_response(&mut client_stream).await;
        let (_, initial_messages) = parse_ldap_messages(&initial).unwrap();
        assert_eq!(initial_messages.len(), 1);
        match sync_info_response(&initial_messages[0]) {
            SyncInfoValue::RefreshPresent {
                cookie,
                refresh_done,
            } => {
                assert!(refresh_done);
                assert!(cookie.is_some());
            }
            other => panic!("unexpected sync info response: {:?}", other),
        }

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
        let entry = messages
            .iter()
            .find(|message| matches!(message.protocol_op, ProtocolOp::SearchResultEntry(_)))
            .expect("search result entry");
        match &entry.protocol_op {
            ProtocolOp::SearchResultEntry(result_entry) => {
                assert_eq!(
                    result_entry.object_name.0.as_ref(),
                    "cn=stream-user,dc=example,dc=org"
                );
            }
            other => panic!("unexpected response: {:?}", other),
        }
        assert_eq!(sync_state_response(entry).state, SyncStateType::Add);

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

        handle_search_request_with_controls(
            &mut server_stream,
            provider_backend.as_ref(),
            12,
            sync_search_request(),
            &sync_request_controls(SyncRefreshMode::RefreshAndPersist, None),
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
        let request = sync_search_request();
        let request_controls = sync_request_controls(SyncRefreshMode::RefreshAndPersist, None);
        let stream_backend = provider_backend.clone();

        let handler = tokio::spawn(async move {
            handle_search_request_with_controls(
                &mut server_stream,
                stream_backend.as_ref(),
                13,
                request,
                &request_controls,
            )
            .await
            .unwrap();
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        let initial = read_response(&mut client_stream).await;
        let (_, initial_messages) = parse_ldap_messages(&initial).unwrap();
        assert_eq!(initial_messages.len(), 1);
        assert!(matches!(
            sync_info_response(&initial_messages[0]),
            SyncInfoValue::RefreshPresent { .. }
        ));
        lifecycle.begin_shutdown();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        let done = messages
            .iter()
            .find(|message| matches!(message.protocol_op, ProtocolOp::SearchResultDone(_)))
            .expect("search result done");
        match &done.protocol_op {
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
        let request = sync_search_request();
        let request_controls = sync_request_controls(SyncRefreshMode::RefreshAndPersist, None);
        let stream_backend = provider_backend.clone();

        let handler = tokio::spawn(async move {
            handle_search_request_with_controls(
                &mut server_stream,
                stream_backend.as_ref(),
                31,
                request,
                &request_controls,
            )
            .await
            .unwrap();
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        let initial = read_response(&mut client_stream).await;
        let (_, initial_messages) = parse_ldap_messages(&initial).unwrap();
        assert_eq!(initial_messages.len(), 1);
        assert!(matches!(
            sync_info_response(&initial_messages[0]),
            SyncInfoValue::RefreshPresent { .. }
        ));
        client_stream
            .write_all(&cancel_request_message(32, 31))
            .await
            .unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

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
        let request = sync_search_request();
        let request_controls = sync_request_controls(SyncRefreshMode::RefreshAndPersist, None);
        let stream_backend = provider_backend.clone();

        let handler = tokio::spawn(async move {
            handle_search_request_with_controls(
                &mut server_stream,
                stream_backend.as_ref(),
                41,
                request,
                &request_controls,
            )
            .await
            .unwrap();
            tokio::time::sleep(Duration::from_millis(250)).await;
            let _ = server_stream.peer_addr();
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        let initial = read_response(&mut client_stream).await;
        let (_, initial_messages) = parse_ldap_messages(&initial).unwrap();
        assert_eq!(initial_messages.len(), 1);
        assert!(matches!(
            sync_info_response(&initial_messages[0]),
            SyncInfoValue::RefreshPresent { .. }
        ));
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

    #[tokio::test]
    async fn sync_refresh_only_request_returns_present_entries_and_sync_done_cookie() {
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
                        ("cn".to_string(), vec!["sync-user".to_string()]),
                        ("sn".to_string(), vec!["User".to_string()]),
                        ("objectclass".to_string(), vec!["person".to_string()]),
                    ]),
                ),
                vec![],
            )
            .await
            .unwrap();

        let (mut server_stream, mut client_stream) = connected_stream_pair().await;
        handle_search_request_with_controls(
            &mut server_stream,
            provider_backend.as_ref(),
            51,
            sync_search_request(),
            &sync_request_controls(SyncRefreshMode::RefreshOnly, None),
        )
        .await
        .unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 2);
        match &messages[0].protocol_op {
            ProtocolOp::SearchResultEntry(entry) => {
                assert_eq!(
                    entry.object_name.0.as_ref(),
                    "cn=sync-user,dc=example,dc=org"
                );
            }
            other => panic!("unexpected response: {:?}", other),
        }
        assert_eq!(
            sync_state_response(&messages[0]).state,
            SyncStateType::Present
        );
        match &messages[1].protocol_op {
            ProtocolOp::SearchResultDone(done) => {
                assert_eq!(done.result_code, ParserResultCode::Success);
            }
            other => panic!("unexpected completion: {:?}", other),
        }
        let sync_done = sync_done_response(&messages[1]);
        assert!(!sync_done.refresh_deletes);
        assert_eq!(
            String::from_utf8(sync_done.cookie.expect("sync done cookie")).unwrap(),
            format!(
                "csn-{}",
                provider_backend
                    .replication_changelog()
                    .unwrap()
                    .get_context_csn()
                    .unwrap()
            )
        );
    }

    #[tokio::test]
    async fn sync_refresh_only_request_emits_replication_audit_events() {
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
                        ("cn".to_string(), vec!["sync-user".to_string()]),
                        ("sn".to_string(), vec!["User".to_string()]),
                        ("objectclass".to_string(), vec!["person".to_string()]),
                    ]),
                ),
                vec![],
            )
            .await
            .unwrap();

        let temp_file = NamedTempFile::new().unwrap();
        let request_context = replication_audit_request_context(&temp_file).await;
        let schema = LdapSchema::default();
        let runtime_config = LegacyServerConfig::default();
        let mut operation_registry = ConnectionOperationRegistry::default();
        let mut session = ConnectionSession::default();
        session.bind("cn=replicator,dc=example,dc=org".to_string());

        let (mut server_stream, mut client_stream) = connected_stream_pair().await;
        handle_search_request_with_context_and_registry(
            &mut server_stream,
            provider_backend.as_ref(),
            &schema,
            &runtime_config,
            151,
            sync_search_request(),
            &session,
            &mut operation_registry,
            &request_context,
            &sync_request_controls(SyncRefreshMode::RefreshOnly, None),
            false,
            false,
        )
        .await
        .unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();
        assert_eq!(messages.len(), 2);

        let log_content = tokio::fs::read_to_string(temp_file.path()).await.unwrap();
        assert!(log_content.contains("\"event_type\":\"Replication\""));
        assert!(log_content.contains("\"action\":\"provider_session_start\""));
        assert!(log_content.contains("\"action\":\"provider_session_complete\""));
        assert!(log_content.contains("\"role\":\"provider\""));
        assert!(log_content.contains("\"sync_kind\":\"full_refresh\""));
        assert!(log_content.contains("\"entries_sent\":\"1\""));
        assert!(log_content.contains("\"replica_id\":\"1\""));
        assert!(!log_content.contains("bind-password"));
        assert!(!log_content.contains("secret"));
    }

    #[tokio::test]
    async fn sync_refresh_only_request_resumes_from_cookie() {
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
                    "cn=existing,dc=example,dc=org",
                    HashMap::from([
                        ("cn".to_string(), vec!["existing".to_string()]),
                        ("sn".to_string(), vec!["Existing".to_string()]),
                        ("objectclass".to_string(), vec!["person".to_string()]),
                    ]),
                ),
                vec![],
            )
            .await
            .unwrap();
        let resume_cookie = format!(
            "csn-{}",
            provider_backend
                .replication_changelog()
                .unwrap()
                .get_context_csn()
                .unwrap()
        );
        provider_backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=new,dc=example,dc=org",
                    HashMap::from([
                        ("cn".to_string(), vec!["new".to_string()]),
                        ("sn".to_string(), vec!["New".to_string()]),
                        ("objectclass".to_string(), vec!["person".to_string()]),
                    ]),
                ),
                vec![],
            )
            .await
            .unwrap();

        let (mut server_stream, mut client_stream) = connected_stream_pair().await;
        handle_search_request_with_controls(
            &mut server_stream,
            provider_backend.as_ref(),
            52,
            sync_search_request(),
            &sync_request_controls(SyncRefreshMode::RefreshOnly, Some(resume_cookie.as_bytes())),
        )
        .await
        .unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();

        assert_eq!(messages.len(), 2);
        match &messages[0].protocol_op {
            ProtocolOp::SearchResultEntry(entry) => {
                assert_eq!(entry.object_name.0.as_ref(), "cn=new,dc=example,dc=org");
            }
            other => panic!("unexpected response: {:?}", other),
        }
        assert_eq!(sync_state_response(&messages[0]).state, SyncStateType::Add);
        assert!(matches!(
            &messages[1].protocol_op,
            ProtocolOp::SearchResultDone(done) if done.result_code == ParserResultCode::Success
        ));
    }

    #[tokio::test]
    async fn sync_refresh_only_request_rejects_malformed_cookie() {
        let mut config = ServerConfig::default();
        config.server.base_dn = "dc=example,dc=org".to_string();
        config.replication.enabled = true;
        config.replication.mode = "provider".to_string();

        let backend = Arc::new(MockBackend::new());
        let service = ReplicationService::from_config(&config, backend).unwrap();
        let provider_backend = service.backend();

        let (mut server_stream, mut client_stream) = connected_stream_pair().await;
        handle_search_request_with_controls(
            &mut server_stream,
            provider_backend.as_ref(),
            53,
            sync_search_request(),
            &sync_request_controls(SyncRefreshMode::RefreshOnly, Some(&[0xff, 0xfe])),
        )
        .await
        .unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();
        assert_eq!(messages.len(), 1);
        match &messages[0].protocol_op {
            ProtocolOp::SearchResultDone(done) => {
                assert_eq!(done.result_code, ParserResultCode::ProtocolError);
            }
            other => panic!("unexpected response: {:?}", other),
        }
    }

    #[tokio::test]
    async fn sync_refresh_only_request_rejects_stale_cookie() {
        let mut config = ServerConfig::default();
        config.server.base_dn = "dc=example,dc=org".to_string();
        config.replication.enabled = true;
        config.replication.mode = "provider".to_string();
        config.replication.changelog_capacity = 1;

        let backend = Arc::new(MockBackend::new());
        let service = ReplicationService::from_config(&config, backend).unwrap();
        let provider_backend = service.backend();
        provider_backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=old,dc=example,dc=org",
                    HashMap::from([
                        ("cn".to_string(), vec!["old".to_string()]),
                        ("sn".to_string(), vec!["Old".to_string()]),
                        ("objectclass".to_string(), vec!["person".to_string()]),
                    ]),
                ),
                vec![],
            )
            .await
            .unwrap();
        let stale_cookie = format!(
            "csn-{}",
            provider_backend
                .replication_changelog()
                .unwrap()
                .get_context_csn()
                .unwrap()
        );
        provider_backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=newer,dc=example,dc=org",
                    HashMap::from([
                        ("cn".to_string(), vec!["newer".to_string()]),
                        ("sn".to_string(), vec!["Newer".to_string()]),
                        ("objectclass".to_string(), vec!["person".to_string()]),
                    ]),
                ),
                vec![],
            )
            .await
            .unwrap();

        let (mut server_stream, mut client_stream) = connected_stream_pair().await;
        handle_search_request_with_controls(
            &mut server_stream,
            provider_backend.as_ref(),
            54,
            sync_search_request(),
            &sync_request_controls(SyncRefreshMode::RefreshOnly, Some(stale_cookie.as_bytes())),
        )
        .await
        .unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();
        assert_eq!(messages.len(), 1);
        match &messages[0].protocol_op {
            ProtocolOp::SearchResultDone(done) => {
                assert_eq!(done.result_code, ParserResultCode::UnwillingToPerform);
            }
            other => panic!("unexpected response: {:?}", other),
        }
    }

    #[tokio::test]
    async fn sync_refresh_only_stale_cookie_emits_replication_audit_failure() {
        let mut config = ServerConfig::default();
        config.server.base_dn = "dc=example,dc=org".to_string();
        config.replication.enabled = true;
        config.replication.mode = "provider".to_string();
        config.replication.changelog_capacity = 1;

        let backend = Arc::new(MockBackend::new());
        let service = ReplicationService::from_config(&config, backend).unwrap();
        let provider_backend = service.backend();
        provider_backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=old,dc=example,dc=org",
                    HashMap::from([
                        ("cn".to_string(), vec!["old".to_string()]),
                        ("sn".to_string(), vec!["Old".to_string()]),
                        ("objectclass".to_string(), vec!["person".to_string()]),
                    ]),
                ),
                vec![],
            )
            .await
            .unwrap();
        let stale_cookie = format!(
            "csn-{}",
            provider_backend
                .replication_changelog()
                .unwrap()
                .get_context_csn()
                .unwrap()
        );
        provider_backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=newer,dc=example,dc=org",
                    HashMap::from([
                        ("cn".to_string(), vec!["newer".to_string()]),
                        ("sn".to_string(), vec!["Newer".to_string()]),
                        ("objectclass".to_string(), vec!["person".to_string()]),
                    ]),
                ),
                vec![],
            )
            .await
            .unwrap();

        let temp_file = NamedTempFile::new().unwrap();
        let request_context = replication_audit_request_context(&temp_file).await;
        let schema = LdapSchema::default();
        let runtime_config = LegacyServerConfig::default();
        let mut operation_registry = ConnectionOperationRegistry::default();
        let mut session = ConnectionSession::default();
        session.bind("cn=replicator,dc=example,dc=org".to_string());

        let (mut server_stream, mut client_stream) = connected_stream_pair().await;
        handle_search_request_with_context_and_registry(
            &mut server_stream,
            provider_backend.as_ref(),
            &schema,
            &runtime_config,
            154,
            sync_search_request(),
            &session,
            &mut operation_registry,
            &request_context,
            &sync_request_controls(SyncRefreshMode::RefreshOnly, Some(stale_cookie.as_bytes())),
            false,
            false,
        )
        .await
        .unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();
        assert_eq!(messages.len(), 1);
        assert!(matches!(
            &messages[0].protocol_op,
            ProtocolOp::SearchResultDone(done)
                if done.result_code == ParserResultCode::UnwillingToPerform
        ));

        let log_content = tokio::fs::read_to_string(temp_file.path()).await.unwrap();
        assert!(log_content.contains("\"event_type\":\"Replication\""));
        assert!(log_content.contains("\"action\":\"provider_cookie_rejected\""));
        assert!(log_content.contains("\"success\":false"));
        assert!(log_content.contains("\"result\":\"cookie_rejected\""));
        assert!(log_content.contains("full refresh"));
        assert!(log_content.contains("\"replica_id\":\"1\""));
        assert!(!log_content.contains("bind-password"));
        assert!(!log_content.contains("secret"));
    }

    #[tokio::test]
    async fn sync_cookie_validation_rejects_backend_context_without_changelog_window() {
        let backend = MockBackend::new();
        backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=before-truncation,dc=example,dc=org",
                    HashMap::from([
                        ("cn".to_string(), vec!["before-truncation".to_string()]),
                        ("sn".to_string(), vec!["Before".to_string()]),
                        ("objectclass".to_string(), vec!["person".to_string()]),
                    ]),
                ),
                vec![],
            )
            .await
            .unwrap();
        let stale_cookie = format!("csn-{}", backend.get_context_csn().await.unwrap().unwrap());
        backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=after-truncation,dc=example,dc=org",
                    HashMap::from([
                        ("cn".to_string(), vec!["after-truncation".to_string()]),
                        ("sn".to_string(), vec!["After".to_string()]),
                        ("objectclass".to_string(), vec!["person".to_string()]),
                    ]),
                ),
                vec![],
            )
            .await
            .unwrap();

        let empty_changelog = crate::replication::ChangelogTracker::with_capacity(25);
        let result = validate_sync_cookie(&backend, &empty_changelog, Some(&stale_cookie)).await;

        assert!(matches!(
            result,
            Err(SyncRequestError::InvalidCookie(message))
                if message.contains("stale sync cookie")
                    && message.contains("requires a full refresh")
        ));
    }

    #[tokio::test]
    async fn base_search_referral_returns_referral_result_urls() {
        let backend = MockBackend::new();
        let entry = referral_entry(
            "ou=remote,dc=example,dc=org",
            &[
                "ldap://remote.example.org/dc=remote,dc=org",
                "ldaps://backup.example.org/ou=people,dc=remote,dc=org?cn,sn?sub?(objectClass=person)?!bindname=cn%3Dproxy%2Cdc%3Dremote%2Cdc%3Dorg",
            ],
        );
        backend.add_entry(entry, Vec::new()).await.unwrap();

        let (mut server_stream, mut client_stream) = connected_stream_pair().await;
        handle_search_request_with_controls(
            &mut server_stream,
            &backend,
            61,
            search_request_for_base("ou=remote,dc=example,dc=org", &[]),
            &RequestControls::default(),
        )
        .await
        .unwrap();

        let response = read_response(&mut client_stream).await;
        let decoded: RasnLdapMessage = ber::decode(&response).unwrap();
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
                    vec![
                        "ldap://remote.example.org/dc=remote,dc=org".to_string(),
                        "ldaps://backup.example.org/ou=people,dc=remote,dc=org?cn,sn?sub?(objectClass=person)?!bindname=cn%3Dproxy%2Cdc%3Dremote%2Cdc%3Dorg".to_string(),
                    ]
                );
            }
            other => panic!("unexpected response: {:?}", other),
        }
    }

    #[tokio::test]
    async fn subtree_search_emits_search_result_reference_for_referral_entry() {
        let backend = MockBackend::new();
        backend
            .add_entry(
                referral_entry(
                    "ou=remote,dc=example,dc=org",
                    &["ldap://remote.example.org/dc=remote,dc=org??sub"],
                ),
                Vec::new(),
            )
            .await
            .unwrap();

        let (mut server_stream, mut client_stream) = connected_stream_pair().await;
        handle_search_request_with_controls(
            &mut server_stream,
            &backend,
            62,
            subtree_search_request("dc=example,dc=org", &[]),
            &RequestControls::default(),
        )
        .await
        .unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();
        assert!(
            messages
                .iter()
                .any(|message| matches!(message.protocol_op, ProtocolOp::SearchResultReference(_)))
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
            vec!["ldap://remote.example.org/dc=remote,dc=org??sub".to_string()]
        );
        assert!(matches!(
            messages.last().map(|message| &message.protocol_op),
            Some(ProtocolOp::SearchResultDone(done)) if done.result_code == ParserResultCode::Success
        ));
    }

    #[tokio::test]
    async fn manage_dsa_it_base_search_returns_referral_object_as_entry() {
        let backend = MockBackend::new();
        backend
            .add_entry(
                referral_entry(
                    "ou=remote,dc=example,dc=org",
                    &["ldap://remote.example.org/dc=remote,dc=org"],
                ),
                Vec::new(),
            )
            .await
            .unwrap();

        let (mut server_stream, mut client_stream) = connected_stream_pair().await;
        handle_search_request_with_controls(
            &mut server_stream,
            &backend,
            63,
            search_request_for_base("ou=remote,dc=example,dc=org", &["ref", "objectClass"]),
            &manage_dsa_it_request_controls(),
        )
        .await
        .unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();
        assert_eq!(messages.len(), 2);
        match &messages[0].protocol_op {
            ProtocolOp::SearchResultEntry(entry) => {
                let attributes = search_entry_attribute_map(entry);
                assert_eq!(
                    attributes.get("ref").unwrap(),
                    &vec!["ldap://remote.example.org/dc=remote,dc=org".to_string()]
                );
                assert!(
                    attributes
                        .get("objectclass")
                        .unwrap()
                        .iter()
                        .any(|value| value.eq_ignore_ascii_case("referral"))
                );
            }
            other => panic!("unexpected response: {:?}", other),
        }
        assert!(
            !messages
                .iter()
                .any(|message| matches!(message.protocol_op, ProtocolOp::SearchResultReference(_)))
        );
        assert!(matches!(
            &messages[1].protocol_op,
            ProtocolOp::SearchResultDone(done) if done.result_code == ParserResultCode::Success
        ));
    }

    #[tokio::test]
    async fn manage_dsa_it_control_rejects_control_value() {
        let backend = MockBackend::new();
        let (mut server_stream, mut client_stream) = connected_stream_pair().await;
        let request_controls = RequestControls::new(vec![LdapControl::new(
            MANAGE_DSA_IT_OID,
            true,
            Some(vec![0x04, 0x00]),
        )]);

        handle_search_request_with_controls(
            &mut server_stream,
            &backend,
            64,
            search_request_for_base("dc=example,dc=org", &[]),
            &request_controls,
        )
        .await
        .unwrap();

        let response = read_response(&mut client_stream).await;
        let (_, messages) = parse_ldap_messages(&response).unwrap();
        assert_eq!(messages.len(), 1);
        assert!(matches!(
            &messages[0].protocol_op,
            ProtocolOp::SearchResultDone(done) if done.result_code == ParserResultCode::ProtocolError
        ));
    }
}

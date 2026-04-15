use std::collections::HashMap;
use std::io;
use std::net::TcpListener as StdTcpListener;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use log::warn;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{RwLock, broadcast};
use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::backend::DirectoryBackend;
use crate::config::MonitoringSettings;
use crate::metrics::{HealthStatus, MetricsCollector, OperationType};
use crate::replication_service::{ReplicationStatusRegistry, ReplicationStatusSnapshot};

const MAX_HTTP_REQUEST_BYTES: usize = 64 * 1024;
const SESSION_COOKIE_NAME: &str = "opendr_console_session";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Disabled,
}

impl ComponentStatus {
    fn from_metrics(status: &HealthStatus) -> Self {
        match status {
            HealthStatus::Healthy => Self::Healthy,
            HealthStatus::Degraded => Self::Degraded,
            HealthStatus::Unhealthy => Self::Unhealthy,
        }
    }

    fn severity(&self) -> u8 {
        match self {
            Self::Disabled => 0,
            Self::Healthy => 1,
            Self::Degraded => 2,
            Self::Unhealthy => 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ComponentReport {
    pub status: ComponentStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Default)]
pub struct RuntimeHealthRegistry {
    components: RwLock<HashMap<String, ComponentReport>>,
}

impl RuntimeHealthRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub async fn set_component(
        &self,
        name: impl Into<String>,
        status: ComponentStatus,
        detail: Option<String>,
    ) {
        self.components
            .write()
            .await
            .insert(name.into(), ComponentReport { status, detail });
    }

    /// Remove a component from the runtime health registry.
    pub async fn remove_component(&self, name: &str) -> Option<ComponentReport> {
        self.components.write().await.remove(name)
    }

    /// Get a component report, if one exists.
    pub async fn get_component(&self, name: &str) -> Option<ComponentReport> {
        self.components.read().await.get(name).cloned()
    }

    /// Snapshot all registered components.
    pub async fn snapshot(&self) -> HashMap<String, ComponentReport> {
        self.components.read().await.clone()
    }

    /// Return the current component names in the registry.
    pub async fn component_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.components.read().await.keys().cloned().collect();
        names.sort();
        names
    }
}

#[derive(Clone, Default)]
pub struct MonitoringRuntimeContext {
    pub console_backend: Option<Arc<dyn DirectoryBackend>>,
    pub console_admin_dn: Option<String>,
    pub replication_status: Option<Arc<ReplicationStatusRegistry>>,
}

#[derive(Debug, Clone, Serialize)]
struct HealthResponse {
    status: ComponentStatus,
    timestamp: u64,
    uptime_seconds: u64,
    components: HashMap<String, ComponentReport>,
    details: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ConsoleOverviewResponse {
    timestamp: u64,
    uptime_seconds: u64,
    health: HealthResponse,
    connections: ConnectionOverview,
    operations: Vec<OperationOverview>,
    resources: ResourceOverview,
    auth_cache: AuthCacheOverview,
    fsm_states: HashMap<String, usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    replication: Option<ReplicationStatusSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
struct ConnectionOverview {
    total: u64,
    active: usize,
    closed: u64,
    failed: u64,
}

#[derive(Debug, Clone, Serialize)]
struct OperationOverview {
    operation: &'static str,
    count: u64,
    success: u64,
    failures: u64,
    active: usize,
    avg_latency_ns: u64,
    min_latency_ns: u64,
    max_latency_ns: u64,
}

#[derive(Debug, Clone, Serialize)]
struct ResourceOverview {
    connection_rejections: u64,
    operation_rejections: u64,
    memory_rejections: u64,
    rate_limit_blocks: u64,
    rate_limit_allows: u64,
    idle_connection_evictions: u64,
}

#[derive(Debug, Clone, Serialize)]
struct AuthCacheOverview {
    capacity: u64,
    entries: u64,
    hits: u64,
    misses: u64,
    evictions: u64,
}

#[derive(Debug, Clone, Serialize)]
struct ErrorResponse {
    error: &'static str,
}

#[derive(Debug, Clone, Deserialize)]
struct ConsoleLoginRequest {
    dn: String,
    password: String,
}

#[derive(Debug, Clone, Serialize)]
struct ConsoleLoginResponse {
    authenticated: bool,
}

#[derive(Debug, Clone)]
struct ConsoleSession {
    expires_at: Instant,
}

#[derive(Clone)]
struct ManagementConsole {
    backend: Option<Arc<dyn DirectoryBackend>>,
    admin_dn: Option<String>,
    sessions: Arc<RwLock<HashMap<String, ConsoleSession>>>,
    session_ttl: Duration,
    replication_status: Option<Arc<ReplicationStatusRegistry>>,
}

impl ManagementConsole {
    fn new(settings: &MonitoringSettings, context: MonitoringRuntimeContext) -> Self {
        Self {
            backend: context.console_backend,
            admin_dn: context.console_admin_dn,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            session_ttl: Duration::from_secs(settings.console_session_ttl_secs.max(1)),
            replication_status: context.replication_status,
        }
    }

    fn enabled(&self) -> bool {
        self.backend.is_some() && self.admin_dn.is_some()
    }

    async fn login(
        &self,
        settings: &MonitoringSettings,
        request: &HttpRequest,
    ) -> io::Result<String> {
        let Some(backend) = self.backend.as_ref() else {
            return Ok(not_found_response());
        };
        let Some(admin_dn) = self.admin_dn.as_deref() else {
            return Ok(not_found_response());
        };

        let credentials: ConsoleLoginRequest =
            serde_json::from_slice(&request.body).map_err(invalid_http_request)?;
        let dn = credentials.dn.trim();
        if !dn.eq_ignore_ascii_case(admin_dn) {
            return json_response(
                "401 Unauthorized",
                &ErrorResponse {
                    error: "unauthorized",
                },
                &[],
            );
        }

        match backend
            .authenticate(dn, credentials.password.as_bytes())
            .await
        {
            Ok(true) => {
                let session_id = Uuid::new_v4().to_string();
                let expires_at = Instant::now() + self.session_ttl;
                self.sessions
                    .write()
                    .await
                    .insert(session_id.clone(), ConsoleSession { expires_at });
                let cookie = set_session_cookie(settings, &session_id, self.session_ttl.as_secs());
                json_response(
                    "200 OK",
                    &ConsoleLoginResponse {
                        authenticated: true,
                    },
                    &[("set-cookie", cookie)],
                )
            }
            Ok(false) => json_response(
                "401 Unauthorized",
                &ErrorResponse {
                    error: "unauthorized",
                },
                &[],
            ),
            Err(_) => json_response(
                "503 Service Unavailable",
                &ErrorResponse {
                    error: "authentication_unavailable",
                },
                &[],
            ),
        }
    }

    async fn logout(
        &self,
        settings: &MonitoringSettings,
        request: &HttpRequest,
    ) -> io::Result<String> {
        if let Some(session_id) = session_cookie(request) {
            self.sessions.write().await.remove(&session_id);
        }
        json_response(
            "200 OK",
            &ConsoleLoginResponse {
                authenticated: false,
            },
            &[("set-cookie", expire_session_cookie(settings))],
        )
    }

    async fn is_authenticated(&self, request: &HttpRequest) -> bool {
        let Some(session_id) = session_cookie(request) else {
            return false;
        };
        let now = Instant::now();
        let mut sessions = self.sessions.write().await;
        sessions.retain(|_, session| session.expires_at > now);
        let Some(session) = sessions.get_mut(&session_id) else {
            return false;
        };
        session.expires_at = now + self.session_ttl;
        true
    }

    async fn overview(
        &self,
        metrics: &MetricsCollector,
        health: &RuntimeHealthRegistry,
    ) -> io::Result<String> {
        let health = build_health_response(metrics, health).await;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let connections = metrics.get_connection_stats();
        let resources = metrics.get_resource_stats();
        let auth_cache = metrics.get_auth_cache_stats();
        let operations = OperationType::all()
            .into_iter()
            .filter_map(|operation| {
                metrics
                    .get_operation_stats(operation)
                    .map(|stats| OperationOverview {
                        operation: operation.as_str(),
                        count: stats.count,
                        success: stats.success,
                        failures: stats.failures,
                        active: stats.active,
                        avg_latency_ns: stats.avg_latency_ns,
                        min_latency_ns: stats.min_latency_ns,
                        max_latency_ns: stats.max_latency_ns,
                    })
            })
            .collect();

        let overview = ConsoleOverviewResponse {
            timestamp,
            uptime_seconds: metrics.uptime_seconds(),
            health,
            connections: ConnectionOverview {
                total: connections.total,
                active: connections.active,
                closed: connections.closed,
                failed: connections.failed,
            },
            operations,
            resources: ResourceOverview {
                connection_rejections: resources.connection_rejections,
                operation_rejections: resources.operation_rejections,
                memory_rejections: resources.memory_rejections,
                rate_limit_blocks: resources.rate_limit_blocks,
                rate_limit_allows: resources.rate_limit_allows,
                idle_connection_evictions: resources.idle_connection_evictions,
            },
            auth_cache: AuthCacheOverview {
                capacity: auth_cache.capacity,
                entries: auth_cache.entries,
                hits: auth_cache.hits,
                misses: auth_cache.misses,
                evictions: auth_cache.evictions,
            },
            fsm_states: metrics.get_fsm_state_distribution(),
            replication: self
                .replication_status
                .as_ref()
                .map(|status| status.snapshot()),
        };
        json_response("200 OK", &overview, &[])
    }
}

#[derive(Debug, Clone)]
struct HttpRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    Metrics,
    Health,
    Console,
    ConsoleLogin,
    ConsoleLogout,
    ConsoleOverview,
    NotFound,
    MethodNotAllowed,
    #[cfg(test)]
    BadRequest,
}

pub fn console_admin_dn(root_user_dn: &str, base_dn: &str) -> String {
    let root_user_dn = root_user_dn.trim();
    if root_user_dn.contains(',') || base_dn.trim().is_empty() {
        root_user_dn.to_string()
    } else {
        format!("{root_user_dn},{}", base_dn.trim())
    }
}

pub fn spawn_monitoring_server(
    settings: MonitoringSettings,
    metrics: Arc<MetricsCollector>,
    health: Arc<RuntimeHealthRegistry>,
    shutdown_rx: broadcast::Receiver<()>,
) -> io::Result<JoinHandle<()>> {
    spawn_monitoring_server_with_context(
        settings,
        metrics,
        health,
        MonitoringRuntimeContext::default(),
        shutdown_rx,
    )
}

pub fn spawn_monitoring_server_with_context(
    settings: MonitoringSettings,
    metrics: Arc<MetricsCollector>,
    health: Arc<RuntimeHealthRegistry>,
    context: MonitoringRuntimeContext,
    shutdown_rx: broadcast::Receiver<()>,
) -> io::Result<JoinHandle<()>> {
    let bind_addr = format!("{}:{}", settings.metrics_address, settings.metrics_port);
    let std_listener = StdTcpListener::bind(&bind_addr)?;
    std_listener.set_nonblocking(true)?;
    let listener = TcpListener::from_std(std_listener)?;
    let console = Arc::new(ManagementConsole::new(&settings, context));

    Ok(tokio::spawn(async move {
        if let Err(err) =
            run_monitoring_server(listener, settings, metrics, health, console, shutdown_rx).await
        {
            warn!("monitoring server error: {}", err);
        }
    }))
}

async fn run_monitoring_server(
    listener: TcpListener,
    settings: MonitoringSettings,
    metrics: Arc<MetricsCollector>,
    health: Arc<RuntimeHealthRegistry>,
    console: Arc<ManagementConsole>,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> io::Result<()> {
    loop {
        tokio::select! {
            result = listener.accept() => {
                let (socket, _) = result?;
                let settings = settings.clone();
                let metrics = metrics.clone();
                let health = health.clone();
                let console = console.clone();

                tokio::spawn(async move {
                    if let Err(err) = handle_connection(socket, &settings, metrics, health, console).await {
                        warn!("failed to serve monitoring request: {}", err);
                    }
                });
            }
            _ = shutdown_rx.recv() => break,
        }
    }

    Ok(())
}

async fn handle_connection(
    mut socket: TcpStream,
    settings: &MonitoringSettings,
    metrics: Arc<MetricsCollector>,
    health: Arc<RuntimeHealthRegistry>,
    console: Arc<ManagementConsole>,
) -> io::Result<()> {
    let request = match read_http_request(&mut socket).await {
        Ok(request) => request,
        Err(err) if err.kind() == io::ErrorKind::InvalidData => {
            let response = bad_request_response();
            socket.write_all(response.as_bytes()).await?;
            return socket.shutdown().await;
        }
        Err(err) => return Err(err),
    };
    let route = resolve_request_route(&request, settings);

    let response = match route {
        Route::Metrics => http_response(
            "200 OK",
            "text/plain; version=0.0.4",
            metrics.export_prometheus(),
        ),
        Route::Health => {
            let health = build_health_response(metrics.as_ref(), health.as_ref()).await;
            let status = match health.status {
                ComponentStatus::Unhealthy => "503 Service Unavailable",
                _ => "200 OK",
            };
            json_response(status, &health, &[])?
        }
        Route::Console => {
            if console.enabled() {
                http_response(
                    "200 OK",
                    "text/html; charset=utf-8",
                    MANAGEMENT_CONSOLE_HTML.to_string(),
                )
            } else {
                not_found_response()
            }
        }
        Route::ConsoleLogin => console.login(settings, &request).await?,
        Route::ConsoleLogout => console.logout(settings, &request).await?,
        Route::ConsoleOverview => {
            if !console.enabled() {
                not_found_response()
            } else if console.is_authenticated(&request).await {
                console.overview(metrics.as_ref(), health.as_ref()).await?
            } else {
                json_response(
                    "401 Unauthorized",
                    &ErrorResponse {
                        error: "unauthorized",
                    },
                    &[],
                )?
            }
        }
        Route::MethodNotAllowed => http_response(
            "405 Method Not Allowed",
            "text/plain; charset=utf-8",
            "method not allowed".to_string(),
        ),
        #[cfg(test)]
        Route::BadRequest => bad_request_response(),
        Route::NotFound => not_found_response(),
    };

    socket.write_all(response.as_bytes()).await?;
    socket.shutdown().await
}

async fn read_http_request(socket: &mut TcpStream) -> io::Result<HttpRequest> {
    let mut buffer = Vec::with_capacity(4096);

    loop {
        let mut chunk = [0_u8; 4096];
        let bytes_read = socket.read(&mut chunk).await?;
        if bytes_read == 0 {
            if buffer.is_empty() {
                return Err(invalid_http_request("empty request"));
            }
            break;
        }
        buffer.extend_from_slice(&chunk[..bytes_read]);
        if buffer.len() > MAX_HTTP_REQUEST_BYTES {
            return Err(invalid_http_request("request too large"));
        }

        if let Some(header_end) = find_header_end(&buffer) {
            let content_length = parse_content_length(&buffer[..header_end])?;
            let body_len = buffer.len().saturating_sub(header_end + 4);
            if body_len >= content_length {
                break;
            }
        }
    }

    parse_http_request_bytes(&buffer)
}

fn parse_content_length(headers: &[u8]) -> io::Result<usize> {
    let headers = std::str::from_utf8(headers).map_err(invalid_http_request)?;
    for line in headers.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("content-length") {
            return value.trim().parse::<usize>().map_err(invalid_http_request);
        }
    }
    Ok(0)
}

fn parse_http_request_bytes(bytes: &[u8]) -> io::Result<HttpRequest> {
    let header_end =
        find_header_end(bytes).ok_or_else(|| invalid_http_request("missing header"))?;
    let headers = std::str::from_utf8(&bytes[..header_end]).map_err(invalid_http_request)?;
    let mut lines = headers.lines();
    let line = lines
        .next()
        .ok_or_else(|| invalid_http_request("missing request line"))?;

    let mut parts = line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| invalid_http_request("missing method"))?;
    let path = parts
        .next()
        .ok_or_else(|| invalid_http_request("missing path"))?;

    let mut headers = HashMap::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
    }

    Ok(HttpRequest {
        method: method.to_string(),
        path: path.split('?').next().unwrap_or(path).to_string(),
        headers,
        body: bytes[header_end + 4..].to_vec(),
    })
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

#[cfg(test)]
fn resolve_route(request: &str, settings: &MonitoringSettings) -> Route {
    parse_http_request_bytes(request.as_bytes())
        .map(|request| resolve_request_route(&request, settings))
        .unwrap_or(Route::BadRequest)
}

fn resolve_request_route(request: &HttpRequest, settings: &MonitoringSettings) -> Route {
    if request.path == settings.metrics_path {
        return get_only(&request.method, Route::Metrics);
    }
    if request.path == settings.health_path {
        return get_only(&request.method, Route::Health);
    }

    if !settings.console_enabled {
        return Route::NotFound;
    }

    let console_path = normalized_console_path(&settings.console_path);
    if request.path == console_path || request.path == format!("{console_path}/") {
        return get_only(&request.method, Route::Console);
    }
    if request.path == format!("{console_path}/login") {
        return post_only(&request.method, Route::ConsoleLogin);
    }
    if request.path == format!("{console_path}/logout") {
        return post_only(&request.method, Route::ConsoleLogout);
    }
    if request.path == format!("{console_path}/api/overview") {
        return get_only(&request.method, Route::ConsoleOverview);
    }

    Route::NotFound
}

fn get_only(method: &str, route: Route) -> Route {
    if method == "GET" {
        route
    } else {
        Route::MethodNotAllowed
    }
}

fn post_only(method: &str, route: Route) -> Route {
    if method == "POST" {
        route
    } else {
        Route::MethodNotAllowed
    }
}

fn normalized_console_path(path: &str) -> String {
    let path = path.trim();
    let path = if path.is_empty() { "/console" } else { path };
    let path = path.trim_end_matches('/');
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

fn session_cookie(request: &HttpRequest) -> Option<String> {
    let cookie_header = request.headers.get("cookie")?;
    cookie_header.split(';').find_map(|cookie| {
        let (name, value) = cookie.trim().split_once('=')?;
        if name == SESSION_COOKIE_NAME && !value.is_empty() {
            Some(value.to_string())
        } else {
            None
        }
    })
}

fn set_session_cookie(
    settings: &MonitoringSettings,
    session_id: &str,
    max_age_secs: u64,
) -> String {
    format!(
        "{SESSION_COOKIE_NAME}={session_id}; HttpOnly; SameSite=Strict; Path={}; Max-Age={max_age_secs}",
        normalized_console_path(&settings.console_path)
    )
}

fn expire_session_cookie(settings: &MonitoringSettings) -> String {
    format!(
        "{SESSION_COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path={}; Max-Age=0",
        normalized_console_path(&settings.console_path)
    )
}

fn json_response<T: Serialize>(
    status: &str,
    body: &T,
    extra_headers: &[(&str, String)],
) -> io::Result<String> {
    let body = serde_json::to_string(body)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    Ok(http_response_with_headers(
        status,
        "application/json",
        body,
        extra_headers,
    ))
}

fn bad_request_response() -> String {
    http_response(
        "400 Bad Request",
        "text/plain; charset=utf-8",
        "bad request".to_string(),
    )
}

fn not_found_response() -> String {
    http_response(
        "404 Not Found",
        "text/plain; charset=utf-8",
        "not found".to_string(),
    )
}

fn http_response(status: &str, content_type: &str, body: String) -> String {
    http_response_with_headers(status, content_type, body, &[])
}

fn http_response_with_headers(
    status: &str,
    content_type: &str,
    body: String,
    extra_headers: &[(&str, String)],
) -> String {
    let mut response = format!(
        "HTTP/1.1 {status}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n",
        body.len()
    );
    for (name, value) in extra_headers {
        response.push_str(name);
        response.push_str(": ");
        response.push_str(value);
        response.push_str("\r\n");
    }
    response.push_str("\r\n");
    response.push_str(&body);
    response
}

fn invalid_http_request(error: impl ToString) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

async fn build_health_response(
    metrics: &MetricsCollector,
    registry: &RuntimeHealthRegistry,
) -> HealthResponse {
    let base = metrics.health_check().await;
    let mut components = HashMap::new();
    let mut details = base.details;

    for (name, status) in base.components {
        components.insert(
            name,
            ComponentReport {
                status: ComponentStatus::from_metrics(&status),
                detail: None,
            },
        );
    }

    for (name, report) in registry.snapshot().await {
        if let Some(detail) = report.detail.as_ref() {
            details.push(format!("{name}: {detail}"));
        }
        components.insert(name, report);
    }

    let overall_status = components
        .values()
        .map(|report| report.status.clone())
        .max_by_key(|status| status.severity())
        .unwrap_or(ComponentStatus::Healthy);
    let timestamp = base
        .timestamp
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    HealthResponse {
        status: overall_status,
        timestamp,
        uptime_seconds: base.uptime_seconds,
        components,
        details,
    }
}

const MANAGEMENT_CONSOLE_HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>OpenDR Management Console</title>
  <style>
    :root { color-scheme: light; --ink: #1b1f24; --muted: #5b6573; --line: #d8dee8; --bg: #f7f9fc; --panel: #ffffff; --accent: #0a7f6c; --warn: #9a3412; --bad: #b42318; }
    * { box-sizing: border-box; }
    body { margin: 0; font: 15px/1.45 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: var(--ink); background: var(--bg); letter-spacing: 0; }
    main { width: min(1120px, calc(100% - 32px)); margin: 0 auto; padding: 32px 0; }
    header { display: flex; justify-content: space-between; gap: 16px; align-items: center; margin-bottom: 24px; }
    h1 { margin: 0; font-size: 28px; }
    h2 { margin: 0 0 12px; font-size: 18px; }
    button, input { font: inherit; border-radius: 6px; }
    button { border: 0; background: var(--accent); color: white; padding: 10px 14px; cursor: pointer; }
    button.secondary { background: #2f3a45; }
    input { width: 100%; border: 1px solid var(--line); padding: 10px 12px; }
    label { display: grid; gap: 6px; color: var(--muted); }
    form { display: grid; gap: 14px; max-width: 520px; }
    .panel { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 18px; }
    .grid { display: grid; gap: 16px; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); }
    .metric { display: grid; gap: 4px; }
    .value { font-size: 26px; font-weight: 700; }
    .muted { color: var(--muted); }
    .hidden { display: none; }
    .status-healthy { color: var(--accent); }
    .status-degraded { color: var(--warn); }
    .status-unhealthy { color: var(--bad); }
    table { width: 100%; border-collapse: collapse; }
    th, td { text-align: left; border-bottom: 1px solid var(--line); padding: 8px 6px; vertical-align: top; }
    code { overflow-wrap: anywhere; }
    #message { min-height: 22px; color: var(--bad); }
  </style>
</head>
<body>
  <main>
    <header>
      <div>
        <h1>OpenDR Management Console</h1>
        <div id="last-refresh" class="muted">Not signed in</div>
      </div>
      <button id="logout" class="secondary hidden" type="button">Sign out</button>
    </header>

    <section id="login-panel" class="panel">
      <h2>Sign in</h2>
      <form id="login-form">
        <label>Admin DN <input id="dn" name="dn" autocomplete="username" required></label>
        <label>Password <input id="password" name="password" type="password" autocomplete="current-password" required></label>
        <button type="submit">Sign in</button>
        <div id="message"></div>
      </form>
    </section>

    <section id="dashboard" class="hidden">
      <div class="grid">
        <div class="panel metric"><span class="muted">Health</span><span id="health" class="value">unknown</span></div>
        <div class="panel metric"><span class="muted">Active connections</span><span id="active-connections" class="value">0</span></div>
        <div class="panel metric"><span class="muted">Failed connections</span><span id="failed-connections" class="value">0</span></div>
        <div class="panel metric"><span class="muted">Uptime</span><span id="uptime" class="value">0s</span></div>
      </div>

      <div class="grid" style="margin-top:16px">
        <section class="panel">
          <h2>Replication</h2>
          <div id="replication" class="muted">No status</div>
        </section>
        <section class="panel">
          <h2>Operations</h2>
          <table><thead><tr><th>Operation</th><th>Total</th><th>Active</th><th>Failed</th></tr></thead><tbody id="operations"></tbody></table>
        </section>
      </div>
    </section>
  </main>
  <script>
    const base = window.location.pathname.replace(/\/$/, "");
    const loginPanel = document.querySelector("#login-panel");
    const dashboard = document.querySelector("#dashboard");
    const message = document.querySelector("#message");
    const logout = document.querySelector("#logout");

    function signedOut(text) {
      dashboard.classList.add("hidden");
      logout.classList.add("hidden");
      loginPanel.classList.remove("hidden");
      document.querySelector("#last-refresh").textContent = "Not signed in";
      message.textContent = text || "";
    }

    function signedIn() {
      loginPanel.classList.add("hidden");
      dashboard.classList.remove("hidden");
      logout.classList.remove("hidden");
      message.textContent = "";
    }

    function seconds(value) {
      if (value < 60) return `${value}s`;
      const minutes = Math.floor(value / 60);
      if (minutes < 60) return `${minutes}m`;
      return `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
    }

    function render(data) {
      signedIn();
      const health = document.querySelector("#health");
      health.textContent = data.health.status;
      health.className = `value status-${data.health.status}`;
      document.querySelector("#active-connections").textContent = data.connections.active;
      document.querySelector("#failed-connections").textContent = data.connections.failed;
      document.querySelector("#uptime").textContent = seconds(data.uptime_seconds);
      document.querySelector("#last-refresh").textContent = `Last refresh ${new Date(data.timestamp * 1000).toLocaleTimeString()}`;

      const operations = document.querySelector("#operations");
      operations.innerHTML = data.operations.map((operation) => `
        <tr><td>${operation.operation}</td><td>${operation.count}</td><td>${operation.active}</td><td>${operation.failures}</td></tr>
      `).join("");

      const replication = data.replication;
      document.querySelector("#replication").innerHTML = replication ? `
        <div>Mode: <strong>${replication.mode}</strong></div>
        <div>Provider: ${replication.provider.enabled ? (replication.provider.running ? "running" : "stopped") : "disabled"}</div>
        <div>Provider sessions: ${replication.provider.active_sessions}</div>
        <div>Consumer: ${replication.consumer.enabled ? (replication.consumer.listening ? "listening" : (replication.consumer.running ? "running" : "stopped")) : "disabled"}</div>
        <div>Provider URL: <code>${replication.consumer.provider_url || "none"}</code></div>
        <div>Cookie persisted: ${replication.consumer.persisted_cookie === undefined ? "n/a" : replication.consumer.persisted_cookie}</div>
        <div>Last applied CSN: <code>${replication.consumer.last_applied_csn || "none"}</code></div>
        <div>Sync lag: ${replication.consumer.seconds_since_last_successful_sync === undefined ? "n/a" : seconds(replication.consumer.seconds_since_last_successful_sync)}</div>
        <div>Failed sessions: ${replication.consumer.failed_sessions}</div>
        <div>Replay gaps: ${replication.consumer.replay_gap_errors}</div>
        <div>Full refresh required: ${replication.consumer.full_refresh_required}</div>
        <div>Latest provider CSN: <code>${replication.provider.latest_context_csn || "none"}</code></div>
        <div>Provider changelog entries: ${replication.provider.retained_changelog_entries === undefined ? "n/a" : replication.provider.retained_changelog_entries}</div>
        <div>Last replication error: ${replication.consumer.last_error || replication.provider.last_error || "none"}</div>
      ` : "No status";
    }

    async function refresh() {
      const response = await fetch(`${base}/api/overview`);
      if (response.status === 401 || response.status === 404) {
        signedOut("");
        return;
      }
      if (!response.ok) {
        signedOut("Status unavailable");
        return;
      }
      render(await response.json());
    }

    document.querySelector("#login-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const response = await fetch(`${base}/login`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          dn: document.querySelector("#dn").value,
          password: document.querySelector("#password").value
        })
      });
      if (!response.ok) {
        signedOut("Invalid credentials");
        return;
      }
      document.querySelector("#password").value = "";
      await refresh();
    });

    logout.addEventListener("click", async () => {
      await fetch(`${base}/logout`, { method: "POST" });
      signedOut("");
    });

    refresh();
    setInterval(refresh, 5000);
  </script>
</body>
</html>
"##;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MonitoringSettings;

    #[tokio::test]
    async fn build_health_response_merges_runtime_components() {
        let metrics = MetricsCollector::new();
        metrics.record_connection_accepted();
        let registry = RuntimeHealthRegistry::new();
        registry
            .set_component(
                "backend",
                ComponentStatus::Healthy,
                Some("memory backend initialized".to_string()),
            )
            .await;
        registry
            .set_component(
                "replication_provider",
                ComponentStatus::Disabled,
                Some("replication provider not enabled".to_string()),
            )
            .await;

        let response = build_health_response(metrics.as_ref(), registry.as_ref()).await;

        assert_eq!(response.status, ComponentStatus::Healthy);
        assert_eq!(
            response.components["backend"].status,
            ComponentStatus::Healthy
        );
        assert_eq!(
            response.components["replication_provider"].status,
            ComponentStatus::Disabled
        );
        assert!(
            response
                .details
                .iter()
                .any(|detail| detail.contains("memory backend initialized"))
        );
    }

    #[tokio::test]
    async fn runtime_health_registry_supports_component_lifecycle() {
        let registry = RuntimeHealthRegistry::new();

        registry
            .set_component("backend", ComponentStatus::Healthy, None)
            .await;
        registry
            .set_component(
                "rate_limiter",
                ComponentStatus::Degraded,
                Some("too many requests".to_string()),
            )
            .await;

        assert_eq!(
            registry.component_names().await,
            vec!["backend".to_string(), "rate_limiter".to_string()]
        );

        let component = registry.get_component("rate_limiter").await.unwrap();
        assert_eq!(component.status, ComponentStatus::Degraded);
        assert_eq!(component.detail.as_deref(), Some("too many requests"));

        let removed = registry.remove_component("backend").await;
        assert!(removed.is_some());
        assert!(registry.get_component("backend").await.is_none());
    }

    #[test]
    fn resolve_route_matches_configured_paths() {
        let settings = MonitoringSettings {
            enabled: true,
            metrics_address: "127.0.0.1".to_string(),
            metrics_port: 9090,
            metrics_path: "/metricsz".to_string(),
            health_path: "/healthz".to_string(),
            console_path: "/admin".to_string(),
            ..MonitoringSettings::default()
        };

        assert_eq!(
            resolve_route(
                "GET /metricsz HTTP/1.1\r\nHost: localhost\r\n\r\n",
                &settings
            ),
            Route::Metrics
        );
        assert_eq!(
            resolve_route(
                "GET /healthz?verbose=1 HTTP/1.1\r\nHost: localhost\r\n\r\n",
                &settings
            ),
            Route::Health
        );
        assert_eq!(
            resolve_route(
                "POST /metricsz HTTP/1.1\r\nHost: localhost\r\n\r\n",
                &settings
            ),
            Route::MethodNotAllowed
        );
        assert_eq!(
            resolve_route(
                "GET /admin/api/overview HTTP/1.1\r\nHost: localhost\r\n\r\n",
                &settings
            ),
            Route::ConsoleOverview
        );
        assert_eq!(
            resolve_route(
                "POST /admin/login HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}",
                &settings
            ),
            Route::ConsoleLogin
        );
        assert_eq!(
            resolve_route(
                "GET /missing HTTP/1.1\r\nHost: localhost\r\n\r\n",
                &settings
            ),
            Route::NotFound
        );
    }

    #[test]
    fn console_admin_dn_expands_rdn() {
        assert_eq!(
            console_admin_dn("cn=admin", "dc=example,dc=org"),
            "cn=admin,dc=example,dc=org"
        );
        assert_eq!(
            console_admin_dn("cn=admin,dc=example,dc=org", "dc=ignored"),
            "cn=admin,dc=example,dc=org"
        );
    }
}

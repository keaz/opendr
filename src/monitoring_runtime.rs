use std::collections::HashMap;
use std::io;
use std::net::TcpListener as StdTcpListener;
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use log::warn;
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, RwLock};
use tokio::task::JoinHandle;

use crate::config::MonitoringSettings;
use crate::metrics::{HealthStatus, MetricsCollector};

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

    async fn snapshot(&self) -> HashMap<String, ComponentReport> {
        self.components.read().await.clone()
    }
}

#[derive(Debug, Clone, Serialize)]
struct HealthResponse {
    status: ComponentStatus,
    timestamp: u64,
    uptime_seconds: u64,
    components: HashMap<String, ComponentReport>,
    details: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    Metrics,
    Health,
    NotFound,
    MethodNotAllowed,
    BadRequest,
}

pub fn spawn_monitoring_server(
    settings: MonitoringSettings,
    metrics: Arc<MetricsCollector>,
    health: Arc<RuntimeHealthRegistry>,
    shutdown_rx: broadcast::Receiver<()>,
) -> io::Result<JoinHandle<()>> {
    let bind_addr = format!("{}:{}", settings.metrics_address, settings.metrics_port);
    let std_listener = StdTcpListener::bind(&bind_addr)?;
    std_listener.set_nonblocking(true)?;
    let listener = TcpListener::from_std(std_listener)?;

    Ok(tokio::spawn(async move {
        if let Err(err) =
            run_monitoring_server(listener, settings, metrics, health, shutdown_rx).await
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
    mut shutdown_rx: broadcast::Receiver<()>,
) -> io::Result<()> {
    loop {
        tokio::select! {
            result = listener.accept() => {
                let (socket, _) = result?;
                let settings = settings.clone();
                let metrics = metrics.clone();
                let health = health.clone();

                tokio::spawn(async move {
                    if let Err(err) = handle_connection(socket, &settings, metrics, health).await {
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
) -> io::Result<()> {
    let route = read_route(&mut socket, settings).await?;

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
            let body = serde_json::to_string(&health)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            http_response(status, "application/json", body)
        }
        Route::MethodNotAllowed => http_response(
            "405 Method Not Allowed",
            "text/plain; charset=utf-8",
            "method not allowed".to_string(),
        ),
        Route::BadRequest => http_response(
            "400 Bad Request",
            "text/plain; charset=utf-8",
            "bad request".to_string(),
        ),
        Route::NotFound => http_response(
            "404 Not Found",
            "text/plain; charset=utf-8",
            "not found".to_string(),
        ),
    };

    socket.write_all(response.as_bytes()).await?;
    socket.shutdown().await
}

async fn read_route(socket: &mut TcpStream, settings: &MonitoringSettings) -> io::Result<Route> {
    let mut buffer = vec![0_u8; 4096];
    let bytes_read = socket.read(&mut buffer).await?;
    if bytes_read == 0 {
        return Ok(Route::BadRequest);
    }

    let request = String::from_utf8_lossy(&buffer[..bytes_read]);
    Ok(resolve_route(&request, settings))
}

fn resolve_route(request: &str, settings: &MonitoringSettings) -> Route {
    let Some(line) = request.lines().next() else {
        return Route::BadRequest;
    };

    let mut parts = line.split_whitespace();
    let Some(method) = parts.next() else {
        return Route::BadRequest;
    };
    let Some(path) = parts.next() else {
        return Route::BadRequest;
    };

    if method != "GET" {
        return Route::MethodNotAllowed;
    }

    let path = path.split('?').next().unwrap_or(path);
    if path == settings.metrics_path {
        Route::Metrics
    } else if path == settings.health_path {
        Route::Health
    } else {
        Route::NotFound
    }
}

fn http_response(status: &str, content_type: &str, body: String) -> String {
    format!(
        "HTTP/1.1 {status}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body
    )
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
        assert!(response
            .details
            .iter()
            .any(|detail| detail.contains("memory backend initialized")));
    }

    #[test]
    fn resolve_route_matches_configured_paths() {
        let settings = MonitoringSettings {
            enabled: true,
            metrics_address: "127.0.0.1".to_string(),
            metrics_port: 9090,
            metrics_path: "/metricsz".to_string(),
            health_path: "/healthz".to_string(),
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
                "GET /missing HTTP/1.1\r\nHost: localhost\r\n\r\n",
                &settings
            ),
            Route::NotFound
        );
    }
}

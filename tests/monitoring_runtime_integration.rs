use std::sync::Arc;
use std::time::Duration;

use ldap_parser::ldap::ProtocolOp;
use ldap_parser::parse_ldap_messages;
use opendr::backend::MockBackend;
use opendr::config::MonitoringSettings;
use opendr::metrics::MetricsCollector;
use opendr::monitoring_runtime::{
    ComponentStatus, MonitoringRuntimeContext, RuntimeHealthRegistry, spawn_monitoring_server,
    spawn_monitoring_server_with_context,
};
use opendr::server;
use rasn::der;
use rasn_ldap::{AuthenticationChoice as RasnAuthChoice, BindRequest as RasnBindRequest};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::broadcast;
use tokio::time::{sleep, timeout};

async fn reserve_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

async fn wait_for_port(port: u16) {
    let addr = format!("127.0.0.1:{port}");
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(&addr).await.is_ok() {
            return;
        }
        sleep(Duration::from_millis(20)).await;
    }

    panic!("port {port} did not open in time");
}

async fn connect_with_retry(port: u16) -> tokio::net::TcpStream {
    let addr = format!("127.0.0.1:{port}");
    for _ in 0..50 {
        match tokio::net::TcpStream::connect(&addr).await {
            Ok(stream) => return stream,
            Err(_) => sleep(Duration::from_millis(20)).await,
        }
    }

    panic!("port {port} did not accept connections in time");
}

async fn http_get(port: u16, path: &str) -> (String, String) {
    http_request(port, "GET", path, &[], "").await
}

async fn http_post(
    port: u16,
    path: &str,
    body: &str,
    headers: &[(&str, &str)],
) -> (String, String) {
    http_request(port, "POST", path, headers, body).await
}

async fn http_request(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (String, String) {
    let addr = format!("127.0.0.1:{port}");
    let mut stream = tokio::net::TcpStream::connect(&addr).await.unwrap();
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    if !body.is_empty() {
        request.push_str("Content-Type: application/json\r\n");
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");
    request.push_str(body);
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();

    let response = String::from_utf8(response).unwrap();
    let (headers, body) = response.split_once("\r\n\r\n").unwrap();
    (headers.to_string(), body.to_string())
}

fn response_cookie(headers: &str) -> String {
    headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("set-cookie") {
                Some(value.trim().to_string())
            } else {
                None
            }
        })
        .expect("response did not include set-cookie")
}

async fn wait_for_metrics(port: u16, expected: &str) -> String {
    for _ in 0..50 {
        let (_, body) = http_get(port, "/metrics").await;
        if body.contains(expected) {
            return body;
        }
        sleep(Duration::from_millis(20)).await;
    }

    panic!("metrics never contained {expected:?}");
}

#[tokio::test]
async fn monitoring_server_exports_live_metrics_and_health() {
    let ldap_port = reserve_port().await;
    let monitoring_port = reserve_port().await;
    let ldap_addr = format!("127.0.0.1:{ldap_port}");

    let backend = Arc::new(MockBackend::default());
    let metrics = MetricsCollector::new();
    let health = RuntimeHealthRegistry::new();
    health
        .set_component(
            "backend",
            ComponentStatus::Healthy,
            Some("memory backend initialized".to_string()),
        )
        .await;
    health
        .set_component(
            "replication_provider",
            ComponentStatus::Disabled,
            Some("replication provider not enabled".to_string()),
        )
        .await;
    health
        .set_component(
            "replication_consumer",
            ComponentStatus::Disabled,
            Some("replication consumer not enabled".to_string()),
        )
        .await;

    let settings = MonitoringSettings {
        enabled: true,
        metrics_address: "127.0.0.1".to_string(),
        metrics_port: monitoring_port,
        metrics_path: "/metrics".to_string(),
        health_path: "/health".to_string(),
        ..MonitoringSettings::default()
    };

    let (shutdown_tx, _) = broadcast::channel(8);

    let monitoring_task = spawn_monitoring_server(
        settings,
        metrics.clone(),
        health.clone(),
        shutdown_tx.subscribe(),
    )
    .unwrap();

    let server_metrics = metrics.clone();
    let ldap_shutdown = shutdown_tx.clone();
    let ldap_task = tokio::spawn(async move {
        server::run_with_metrics(
            &ldap_addr,
            backend,
            ldap_shutdown.subscribe(),
            Some(server_metrics),
        )
        .await
        .unwrap();
    });

    wait_for_port(monitoring_port).await;

    let mut ldap_stream = connect_with_retry(ldap_port).await;
    let bind_request = RasnBindRequest::new(
        3,
        b"cn=admin,dc=example,dc=org".to_vec().into(),
        RasnAuthChoice::Simple(b"secret".to_vec().into()),
    );
    let bind_message =
        rasn_ldap::LdapMessage::new(1, rasn_ldap::ProtocolOp::BindRequest(bind_request));
    let bind_message = der::encode(&bind_message).unwrap();
    ldap_stream.write_all(&bind_message).await.unwrap();

    let mut bind_response = vec![0_u8; 4096];
    let bytes = timeout(Duration::from_secs(1), ldap_stream.read(&mut bind_response))
        .await
        .unwrap()
        .unwrap();
    assert!(bytes > 0);

    let (_, messages) = parse_ldap_messages(&bind_response[..bytes]).unwrap();
    match &messages[0].protocol_op {
        ProtocolOp::BindResponse(response) => {
            assert_eq!(
                response.result.result_code,
                ldap_parser::ldap::ResultCode::Success
            );
        }
        other => panic!("unexpected response: {:?}", other),
    }
    ldap_stream.shutdown().await.unwrap();

    let metrics_body = wait_for_metrics(
        monitoring_port,
        "ldap_operations_total{operation=\"bind\"} 1",
    )
    .await;
    assert!(metrics_body.contains("ldap_connections_total 1"));

    let (health_headers, health_body) = http_get(monitoring_port, "/health").await;
    assert!(health_headers.contains("200 OK"));

    let health_json: serde_json::Value = serde_json::from_str(&health_body).unwrap();
    assert_eq!(health_json["status"], "healthy");
    assert_eq!(health_json["components"]["backend"]["status"], "healthy");
    assert_eq!(
        health_json["components"]["replication_provider"]["status"],
        "disabled"
    );
    assert_eq!(
        health_json["components"]["replication_consumer"]["status"],
        "disabled"
    );

    let _ = shutdown_tx.send(());
    timeout(Duration::from_secs(2), ldap_task)
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(2), monitoring_task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn management_console_requires_root_session() {
    let monitoring_port = reserve_port().await;
    let backend = Arc::new(MockBackend::default());
    let metrics = MetricsCollector::new();
    metrics.record_connection_accepted();
    let health = RuntimeHealthRegistry::new();
    health
        .set_component(
            "backend",
            ComponentStatus::Healthy,
            Some("memory backend initialized".to_string()),
        )
        .await;

    let settings = MonitoringSettings {
        enabled: true,
        metrics_address: "127.0.0.1".to_string(),
        metrics_port: monitoring_port,
        metrics_path: "/metrics".to_string(),
        health_path: "/health".to_string(),
        console_path: "/console".to_string(),
        console_session_ttl_secs: 60,
        ..MonitoringSettings::default()
    };
    let (shutdown_tx, _) = broadcast::channel(8);
    let monitoring_task = spawn_monitoring_server_with_context(
        settings,
        metrics.clone(),
        health.clone(),
        MonitoringRuntimeContext {
            console_backend: Some(backend),
            console_admin_dn: Some("cn=admin,dc=example,dc=org".to_string()),
            replication_status: None,
        },
        shutdown_tx.subscribe(),
    )
    .unwrap();

    wait_for_port(monitoring_port).await;

    let (headers, body) = http_get(monitoring_port, "/console/api/overview").await;
    assert!(headers.contains("401 Unauthorized"));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["error"],
        "unauthorized"
    );

    let (headers, _) = http_post(
        monitoring_port,
        "/console/login",
        r#"{"dn":"uid=user,dc=example,dc=org","password":"secret"}"#,
        &[],
    )
    .await;
    assert!(headers.contains("401 Unauthorized"));

    let (headers, body) = http_post(
        monitoring_port,
        "/console/login",
        r#"{"dn":"CN = Admin , DC = Example , DC = ORG","password":"secret"}"#,
        &[],
    )
    .await;
    assert!(headers.contains("200 OK"));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["authenticated"],
        true
    );
    let cookie = response_cookie(&headers);

    let (headers, body) = http_request(
        monitoring_port,
        "GET",
        "/console/api/overview",
        &[("Cookie", &cookie)],
        "",
    )
    .await;
    assert!(headers.contains("200 OK"));
    let overview: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(overview["health"]["status"], "healthy");
    assert_eq!(overview["connections"]["active"], 1);
    assert!(overview["operations"].as_array().unwrap().len() >= 10);

    let (headers, body) = http_post(
        monitoring_port,
        "/console/logout",
        "",
        &[("Cookie", &cookie)],
    )
    .await;
    assert!(headers.contains("200 OK"));
    assert!(response_cookie(&headers).contains("Max-Age=0"));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["authenticated"],
        false
    );

    let (headers, _) = http_request(
        monitoring_port,
        "GET",
        "/console/api/overview",
        &[("Cookie", &cookie)],
        "",
    )
    .await;
    assert!(headers.contains("401 Unauthorized"));

    let _ = shutdown_tx.send(());
    timeout(Duration::from_secs(2), monitoring_task)
        .await
        .unwrap()
        .unwrap();
}

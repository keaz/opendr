use std::fs;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use ldap_parser::ldap::ProtocolOp;
use ldap_parser::parse_ldap_messages;
use rasn::der;
use rasn_ldap::{AuthenticationChoice as RasnAuthChoice, BindRequest as RasnBindRequest};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};

struct TestBinaryServer {
    _tempdir: TempDir,
    child: Child,
    port: u16,
}

impl Drop for TestBinaryServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn opendr_binary() -> PathBuf {
    let cargo_binary = PathBuf::from(env!("CARGO_BIN_EXE_opendr"));
    let stable_binary = cargo_binary
        .parent()
        .and_then(|parent| parent.parent())
        .map(|parent| parent.join("opendr"));

    match stable_binary {
        Some(path) if path.exists() => path,
        _ => cargo_binary,
    }
}

fn reserve_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn write_runtime_fixture(
    tempdir: &TempDir,
    ldap_port: u16,
    resource_overrides: &str,
    rate_limit_overrides: &str,
    operation_limit_overrides: &str,
) {
    fn merge_section(default_lines: &[&str], override_lines: &str) -> String {
        let override_lines: Vec<&str> = override_lines
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect();
        let override_keys: Vec<&str> = override_lines
            .iter()
            .filter_map(|line| line.split('=').next())
            .map(str::trim)
            .collect();

        let mut merged = Vec::new();
        for line in default_lines {
            let key = line
                .split('=')
                .next()
                .expect("default fixture line must contain '='")
                .trim();
            if !override_keys.contains(&key) {
                merged.push((*line).to_string());
            }
        }
        merged.extend(override_lines.into_iter().map(str::to_string));
        merged.join("\n")
    }

    let config_dir = tempdir.path().join("config");
    fs::create_dir_all(&config_dir).unwrap();
    fs::create_dir_all(tempdir.path().join("data")).unwrap();

    let resource_section = merge_section(
        &[
            "max_connections = 100",
            "max_connections_per_ip = 10",
            "max_operations_per_connection = 100",
            "max_memory_per_connection = 10485760",
            "max_total_memory = 1073741824",
            "connection_idle_timeout_secs = 600",
        ],
        resource_overrides,
    );
    let rate_limit_section = merge_section(
        &[
            "enabled = false",
            "global_requests_per_second = 1000",
            "per_client_requests_per_second = 100",
            "burst_size = 50",
            "window_duration_secs = 1",
            "adaptive_enabled = false",
            "adaptive_threshold = 0.8",
            "adaptive_multiplier = 0.5",
            "blacklist = []",
            "whitelist = []",
            "auto_ban_threshold = 100",
            "auto_ban_duration_secs = 300",
        ],
        rate_limit_overrides,
    );
    let operation_limit_section = merge_section(
        &[
            "bind = 10",
            "search = 50",
            "modify = 20",
            "add = 20",
            "delete = 10",
            "modifydn = 10",
            "compare = 30",
            "extended = 20",
        ],
        operation_limit_overrides,
    );

    let server_toml = format!(
        r#"
[server]
runtime = "legacy"
bind_address = "127.0.0.1"
ldap_port = {ldap_port}
base_dn = "dc=example,dc=org"
root_user_dn = "cn=admin"
root_password = "secret"

[backend]
backend_type = "memory"

[monitoring]
enabled = false

[replication]
enabled = false

[resources]
{resource_section}

[rate_limit]
{rate_limit_section}

[rate_limit.operation_limits]
{operation_limit_section}
"#
    );
    fs::write(config_dir.join("server.toml"), server_toml).unwrap();

    let log4rs = r#"
appenders:
  stdout:
    kind: console
root:
  level: error
  appenders:
    - stdout
"#;
    fs::write(config_dir.join("log4rs.yml"), log4rs).unwrap();
}

fn spawn_opendr(tempdir: TempDir, port: u16) -> TestBinaryServer {
    let child = Command::new(opendr_binary())
        .current_dir(tempdir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    TestBinaryServer {
        _tempdir: tempdir,
        child,
        port,
    }
}

async fn connect_with_retry(port: u16) -> TcpStream {
    let addr = format!("127.0.0.1:{port}");
    for _ in 0..50 {
        match TcpStream::connect(&addr).await {
            Ok(stream) => return stream,
            Err(_) => sleep(Duration::from_millis(20)).await,
        }
    }

    panic!("failed to connect to LDAP server on port {port}");
}

async fn read_response_bytes(stream: &mut TcpStream) -> Vec<u8> {
    let mut response = Vec::new();
    let mut buf = vec![0_u8; 4096];

    loop {
        match timeout(Duration::from_millis(500), stream.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(bytes_read)) => {
                response.extend_from_slice(&buf[..bytes_read]);
                if !response.is_empty() && parse_ldap_messages(&response).is_ok() {
                    break;
                }
            }
            Ok(Err(err)) => panic!("failed to read LDAP response: {err}"),
            Err(_) if !response.is_empty() => break,
            Err(_) => panic!("timed out waiting for LDAP response"),
        }
    }

    response
}

async fn send_bind_request(stream: &mut TcpStream, message_id: u32) -> Vec<u8> {
    let bind_request = RasnBindRequest::new(
        3,
        b"cn=admin,dc=example,dc=org".to_vec().into(),
        RasnAuthChoice::Simple(b"secret".to_vec().into()),
    );
    let bind_message =
        rasn_ldap::LdapMessage::new(message_id, rasn_ldap::ProtocolOp::BindRequest(bind_request));
    let bind_message = der::encode(&bind_message).unwrap();

    stream.write_all(&bind_message).await.unwrap();
    read_response_bytes(stream).await
}

fn assert_unavailable_rejection(response: &[u8]) {
    let (_, messages) = parse_ldap_messages(response).unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].message_id.0, 0);
    match &messages[0].protocol_op {
        ProtocolOp::SearchResultDone(result) => {
            assert_eq!(
                result.result_code,
                ldap_parser::ldap::ResultCode::Unavailable
            );
            assert_eq!(
                result.diagnostic_message.0.as_ref(),
                "Server resource limits exceeded"
            );
        }
        other => panic!("unexpected rejection response: {:?}", other),
    }
}

fn assert_bind_result_code(response: &[u8], expected: ldap_parser::ldap::ResultCode) {
    let (_, messages) = parse_ldap_messages(response).unwrap();
    assert_eq!(messages.len(), 1);
    match &messages[0].protocol_op {
        ProtocolOp::BindResponse(bind_response) => {
            assert_eq!(bind_response.result.result_code, expected);
        }
        other => panic!("unexpected bind response: {:?}", other),
    }
}

fn runtime_fixture(
    resource_overrides: &str,
    rate_limit_overrides: &str,
    operation_limit_overrides: &str,
) -> TestBinaryServer {
    let tempdir = tempfile::tempdir().unwrap();
    let port = reserve_port();
    write_runtime_fixture(
        &tempdir,
        port,
        resource_overrides,
        rate_limit_overrides,
        operation_limit_overrides,
    );
    spawn_opendr(tempdir, port)
}

#[tokio::test]
async fn legacy_runtime_enforces_connection_and_rate_limits() {
    {
        let server = runtime_fixture("max_connections = 1\nmax_connections_per_ip = 1", "", "");

        let mut first_client = connect_with_retry(server.port).await;
        sleep(Duration::from_millis(100)).await;

        let mut second_client = connect_with_retry(server.port).await;
        let rejection = read_response_bytes(&mut second_client).await;
        assert_unavailable_rejection(&rejection);

        let bind_response = send_bind_request(&mut first_client, 1).await;
        assert_bind_result_code(&bind_response, ldap_parser::ldap::ResultCode::Success);
    }

    {
        let server = runtime_fixture("max_connections = 8\nmax_connections_per_ip = 1", "", "");

        let mut first_client = connect_with_retry(server.port).await;
        sleep(Duration::from_millis(100)).await;

        let mut second_client = connect_with_retry(server.port).await;
        let rejection = read_response_bytes(&mut second_client).await;
        assert_unavailable_rejection(&rejection);

        let bind_response = send_bind_request(&mut first_client, 1).await;
        assert_bind_result_code(&bind_response, ldap_parser::ldap::ResultCode::Success);
    }

    {
        let server = runtime_fixture(
            "",
            "enabled = true\nglobal_requests_per_second = 100\nper_client_requests_per_second = 1\nwindow_duration_secs = 1\nadaptive_enabled = false\nauto_ban_threshold = 100",
            "bind = 1",
        );

        let mut client = connect_with_retry(server.port).await;

        let first_response = send_bind_request(&mut client, 1).await;
        assert_bind_result_code(&first_response, ldap_parser::ldap::ResultCode::Success);

        let second_response = send_bind_request(&mut client, 2).await;
        assert_bind_result_code(&second_response, ldap_parser::ldap::ResultCode::Busy);

        sleep(Duration::from_millis(1100)).await;
        let third_response = send_bind_request(&mut client, 3).await;
        assert_bind_result_code(&third_response, ldap_parser::ldap::ResultCode::Success);
    }
}

#[test]
fn legacy_runtime_rejects_unsupported_burst_size() {
    let tempdir = tempfile::tempdir().unwrap();
    let port = reserve_port();
    write_runtime_fixture(&tempdir, port, "", "burst_size = 5", "");

    let output = Command::new(opendr_binary())
        .current_dir(tempdir.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    assert!(!output.status.success());
    let combined_output = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined_output.contains("burst_size"),
        "expected startup failure to mention burst_size, got: {combined_output}"
    );
    assert!(
        combined_output.contains("legacy runtime"),
        "expected startup failure to mention legacy runtime, got: {combined_output}"
    );
}

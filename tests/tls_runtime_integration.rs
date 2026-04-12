use std::fs;
use std::io::Cursor;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use ldap_parser::ldap::ProtocolOp;
use ldap_parser::parse_ldap_messages;
use opendr::extended_ops::oids;
use rasn::der;
use rasn_ldap::{
    AuthenticationChoice as RasnAuthChoice, BindRequest as RasnBindRequest,
    ExtendedRequest as RasnExtendedRequest, SaslCredentials as RasnSaslCredentials,
};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tempfile::TempDir;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsConnector;

struct TestBinaryServer {
    _tempdir: TempDir,
    child: Child,
    ldap_port: u16,
    ldaps_port: u16,
    cert_pem: String,
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

fn generate_test_certificate() -> (String, String) {
    let certified = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_pem = certified.cert.pem();
    let key_pem = certified.key_pair.serialize_pem();
    (cert_pem, key_pem)
}

fn write_tls_fixture(
    tempdir: &TempDir,
    runtime: &str,
    ldap_port: u16,
    ldaps_port: u16,
    tls_enabled: bool,
    cert_pem: &str,
    key_pem: &str,
) {
    let config_dir = tempdir.path().join("config");
    let cert_dir = tempdir.path().join("certs");
    let data_dir = tempdir.path().join("data");

    fs::create_dir_all(&config_dir).unwrap();
    fs::create_dir_all(&cert_dir).unwrap();
    fs::create_dir_all(&data_dir).unwrap();

    fs::write(cert_dir.join("server.crt"), cert_pem).unwrap();
    fs::write(cert_dir.join("server.key"), key_pem).unwrap();

    let server_toml = format!(
        r#"
[server]
runtime = "{runtime}"
bind_address = "127.0.0.1"
ldap_port = {ldap_port}
ldaps_port = {ldaps_port}
base_dn = "dc=example,dc=org"
root_user_dn = "cn=admin"
root_password = "secret"

[backend]
backend_type = "memory"
data_directory = "./data"

[tls]
enabled = {tls_enabled}
cert_file = "certs/server.crt"
key_file = "certs/server.key"
require_client_cert = false
min_tls_version = "1.2"

[monitoring]
enabled = false

[replication]
enabled = false

[rate_limit]
enabled = false
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

fn spawn_opendr(
    tempdir: TempDir,
    ldap_port: u16,
    ldaps_port: u16,
    cert_pem: String,
) -> TestBinaryServer {
    let child = Command::new(opendr_binary())
        .current_dir(tempdir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    TestBinaryServer {
        _tempdir: tempdir,
        child,
        ldap_port,
        ldaps_port,
        cert_pem,
    }
}

fn tls_runtime_fixture(runtime: &str, tls_enabled: bool) -> TestBinaryServer {
    let tempdir = tempfile::tempdir().unwrap();
    let ldap_port = reserve_port();
    let ldaps_port = reserve_port();
    let (cert_pem, key_pem) = generate_test_certificate();
    write_tls_fixture(
        &tempdir,
        runtime,
        ldap_port,
        ldaps_port,
        tls_enabled,
        &cert_pem,
        &key_pem,
    );
    spawn_opendr(tempdir, ldap_port, ldaps_port, cert_pem)
}

async fn connect_with_retry(port: u16) -> TcpStream {
    let addr = format!("127.0.0.1:{port}");
    for _ in 0..80 {
        match TcpStream::connect(&addr).await {
            Ok(stream) => return stream,
            Err(_) => sleep(Duration::from_millis(50)).await,
        }
    }

    panic!("failed to connect to LDAP server on port {port}");
}

async fn read_response_bytes<S>(stream: &mut S) -> Vec<u8>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut response = Vec::new();
    let mut buf = vec![0_u8; 4096];

    loop {
        match timeout(Duration::from_millis(750), stream.read(&mut buf)).await {
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

async fn send_bind_request<S>(stream: &mut S, message_id: u32) -> Vec<u8>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
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

async fn send_sasl_plain_bind_request<S>(stream: &mut S, message_id: u32) -> Vec<u8>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let bind_dn = "cn=admin,dc=example,dc=org";
    let credentials = format!("\0{bind_dn}\0secret").into_bytes();
    let bind_request = RasnBindRequest::new(
        3,
        bind_dn.as_bytes().to_vec().into(),
        RasnAuthChoice::Sasl(RasnSaslCredentials::new(
            b"PLAIN".to_vec().into(),
            Some(credentials.into()),
        )),
    );
    let bind_message =
        rasn_ldap::LdapMessage::new(message_id, rasn_ldap::ProtocolOp::BindRequest(bind_request));
    let bind_message = der::encode(&bind_message).unwrap();

    stream.write_all(&bind_message).await.unwrap();
    read_response_bytes(stream).await
}

async fn send_starttls_request(stream: &mut TcpStream, message_id: u32) -> Vec<u8> {
    let request = RasnExtendedRequest {
        request_name: oids::START_TLS.as_bytes().to_vec().into(),
        request_value: None,
    };
    let message =
        rasn_ldap::LdapMessage::new(message_id, rasn_ldap::ProtocolOp::ExtendedReq(request));
    let message = der::encode(&message).unwrap();

    stream.write_all(&message).await.unwrap();
    read_response_bytes(stream).await
}

async fn send_whoami_request<S>(stream: &mut S, message_id: u32) -> Vec<u8>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = RasnExtendedRequest {
        request_name: oids::WHO_AM_I.as_bytes().to_vec().into(),
        request_value: None,
    };
    let message =
        rasn_ldap::LdapMessage::new(message_id, rasn_ldap::ProtocolOp::ExtendedReq(request));
    let message = der::encode(&message).unwrap();

    stream.write_all(&message).await.unwrap();
    read_response_bytes(stream).await
}

fn trusted_tls_connector(cert_pem: &str) -> TlsConnector {
    let mut roots = RootCertStore::empty();
    let mut reader = Cursor::new(cert_pem.as_bytes());
    for cert in rustls_pemfile::certs(&mut reader) {
        roots.add(cert.unwrap()).unwrap();
    }

    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

fn untrusted_tls_connector() -> TlsConnector {
    let config = ClientConfig::builder()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

fn localhost_server_name() -> ServerName<'static> {
    ServerName::try_from("localhost").unwrap().to_owned()
}

fn assert_bind_success(response: &[u8]) {
    let (_, messages) = parse_ldap_messages(response).unwrap();
    assert_eq!(messages.len(), 1);
    match &messages[0].protocol_op {
        ProtocolOp::BindResponse(bind_response) => {
            assert_eq!(
                bind_response.result.result_code,
                ldap_parser::ldap::ResultCode::Success
            );
        }
        other => panic!("unexpected bind response: {:?}", other),
    }
}

fn assert_starttls_success(response: &[u8]) {
    let (_, messages) = parse_ldap_messages(response).unwrap();
    assert_eq!(messages.len(), 1);
    match &messages[0].protocol_op {
        ProtocolOp::ExtendedResponse(response) => {
            assert_eq!(
                response.result.result_code,
                ldap_parser::ldap::ResultCode::Success
            );
        }
        other => panic!("unexpected StartTLS response: {:?}", other),
    }
}

fn assert_whoami_bound_admin(response: &[u8]) {
    let (_, messages) = parse_ldap_messages(response).unwrap();
    assert_eq!(messages.len(), 1);
    match &messages[0].protocol_op {
        ProtocolOp::ExtendedResponse(response) => {
            assert_eq!(
                response.result.result_code,
                ldap_parser::ldap::ResultCode::Success
            );
            assert_eq!(
                response.response_name.as_ref().map(|oid| oid.0.as_ref()),
                Some(oids::WHO_AM_I)
            );
            assert_eq!(
                response
                    .response_value
                    .as_ref()
                    .map(|value| std::str::from_utf8(value.as_ref()).unwrap()),
                Some("dn:cn=admin,dc=example,dc=org")
            );
        }
        other => panic!("unexpected WhoAmI response: {:?}", other),
    }
}

#[tokio::test]
async fn ldaps_accepts_tls_and_allows_bind() {
    let server = tls_runtime_fixture("legacy", true);

    let stream = connect_with_retry(server.ldaps_port).await;
    let connector = trusted_tls_connector(&server.cert_pem);
    let mut tls_stream = connector
        .connect(localhost_server_name(), stream)
        .await
        .expect("LDAPS handshake should succeed with trusted server certificate");

    let bind_response = send_bind_request(&mut tls_stream, 1).await;
    assert_bind_success(&bind_response);
}

#[tokio::test]
async fn ldaps_rejects_untrusted_client_handshake() {
    let server = tls_runtime_fixture("legacy", true);

    let stream = connect_with_retry(server.ldaps_port).await;
    let connector = untrusted_tls_connector();
    let handshake = connector.connect(localhost_server_name(), stream).await;

    assert!(
        handshake.is_err(),
        "LDAPS handshake should fail when the client does not trust the server certificate"
    );
}

#[tokio::test]
async fn starttls_upgrades_connection_and_allows_bind() {
    let server = tls_runtime_fixture("legacy", true);

    let mut stream = connect_with_retry(server.ldap_port).await;
    let starttls_response = send_starttls_request(&mut stream, 1).await;
    assert_starttls_success(&starttls_response);

    let connector = trusted_tls_connector(&server.cert_pem);
    let mut tls_stream = connector
        .connect(localhost_server_name(), stream)
        .await
        .expect("StartTLS upgrade should complete with trusted server certificate");

    let bind_response = send_bind_request(&mut tls_stream, 2).await;
    assert_bind_success(&bind_response);
}

#[tokio::test]
async fn starttls_upgrade_fails_for_untrusted_server_certificate() {
    let server = tls_runtime_fixture("legacy", true);

    let mut stream = connect_with_retry(server.ldap_port).await;
    let starttls_response = send_starttls_request(&mut stream, 1).await;
    assert_starttls_success(&starttls_response);

    let connector = untrusted_tls_connector();
    let handshake = connector.connect(localhost_server_name(), stream).await;

    assert!(
        handshake.is_err(),
        "StartTLS handshake should fail when the client does not trust the server certificate"
    );
}

#[tokio::test]
async fn fsm_ldaps_accepts_tls_and_allows_bind() {
    let server = tls_runtime_fixture("fsm", true);

    let stream = connect_with_retry(server.ldaps_port).await;
    let connector = trusted_tls_connector(&server.cert_pem);
    let mut tls_stream = connector
        .connect(localhost_server_name(), stream)
        .await
        .expect("FSM LDAPS handshake should succeed with trusted server certificate");

    let bind_response = send_bind_request(&mut tls_stream, 1).await;
    assert_bind_success(&bind_response);
}

#[tokio::test]
async fn fsm_ldaps_accepts_sasl_plain_and_whoami_returns_bound_dn() {
    let server = tls_runtime_fixture("fsm", true);

    let stream = connect_with_retry(server.ldaps_port).await;
    let connector = trusted_tls_connector(&server.cert_pem);
    let mut tls_stream = connector
        .connect(localhost_server_name(), stream)
        .await
        .expect("FSM LDAPS handshake should succeed with trusted server certificate");

    let bind_response = send_sasl_plain_bind_request(&mut tls_stream, 1).await;
    assert_bind_success(&bind_response);

    let whoami_response = send_whoami_request(&mut tls_stream, 2).await;
    assert_whoami_bound_admin(&whoami_response);
}

#[tokio::test]
async fn fsm_starttls_upgrades_connection_and_allows_bind() {
    let server = tls_runtime_fixture("fsm", true);

    let mut stream = connect_with_retry(server.ldap_port).await;
    let starttls_response = send_starttls_request(&mut stream, 1).await;
    assert_starttls_success(&starttls_response);

    let connector = trusted_tls_connector(&server.cert_pem);
    let mut tls_stream = connector
        .connect(localhost_server_name(), stream)
        .await
        .expect("FSM StartTLS upgrade should complete with trusted server certificate");

    let bind_response = send_bind_request(&mut tls_stream, 2).await;
    assert_bind_success(&bind_response);
}

#[tokio::test]
async fn fsm_starttls_accepts_sasl_plain_and_whoami_returns_bound_dn() {
    let server = tls_runtime_fixture("fsm", true);

    let mut stream = connect_with_retry(server.ldap_port).await;
    let starttls_response = send_starttls_request(&mut stream, 1).await;
    assert_starttls_success(&starttls_response);

    let connector = trusted_tls_connector(&server.cert_pem);
    let mut tls_stream = connector
        .connect(localhost_server_name(), stream)
        .await
        .expect("FSM StartTLS upgrade should complete with trusted server certificate");

    let bind_response = send_sasl_plain_bind_request(&mut tls_stream, 2).await;
    assert_bind_success(&bind_response);

    let whoami_response = send_whoami_request(&mut tls_stream, 3).await;
    assert_whoami_bound_admin(&whoami_response);
}

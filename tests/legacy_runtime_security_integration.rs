use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ldap_parser::ldap::{ProtocolOp, ResultCode as ParserResultCode};
use ldap_parser::parse_ldap_messages;
use opendr::aci::AciEngine;
use opendr::audit::{AuditLevel, AuditLogger};
use opendr::backend::{DirectoryBackend, MockBackend};
use opendr::extended_ops::{
    PasswordModifyRequest, decode_password_modify_response_value,
    encode_password_modify_request_value, oids,
};
use opendr::server::{
    self, LegacyAuditConfig, LegacySecurityConfig, LegacyServerConfig, ServerError,
};
use opendr::tls::{RustlsTlsHandler, TlsConfig, TlsVersion};
use rasn::der;
use rasn::types::SetOf;
use rasn_ldap::{
    AddRequest as RasnAddRequest, Attribute as RasnAttribute,
    AttributeValueAssertion as RasnAttributeValueAssertion, AuthenticationChoice as RasnAuthChoice,
    BindRequest as RasnBindRequest, CompareRequest as RasnCompareRequest,
    ExtendedRequest as RasnExtendedRequest, LdapMessage as RasnLdapMessage,
    ProtocolOp as RasnProtocolOp, SaslCredentials as RasnSaslCredentials,
};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tempfile::TempDir;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsConnector;

const ADMIN_DN: &str = "cn=admin,dc=example,dc=org";
const ADMIN_PASSWORD: &str = "secret";
const USER_DN: &str = "cn=user,dc=example,dc=org";
const USER_PASSWORD: &str = "user-secret";
const OTHER_DN: &str = "cn=other,dc=example,dc=org";
const OTHER_PASSWORD: &str = "other-secret";
const NEW_ENTRY_DN: &str = "cn=alice,dc=example,dc=org";
const COMPARE_TARGET_DN: &str = "cn=target,dc=example,dc=org";

struct RuntimeServer {
    _tempdir: TempDir,
    audit_log_path: PathBuf,
    shutdown_tx: broadcast::Sender<()>,
    join_handle: JoinHandle<Result<(), ServerError>>,
    port: u16,
    cert_pem: Option<String>,
}

impl RuntimeServer {
    async fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
        match timeout(Duration::from_secs(5), self.join_handle).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(err))) => panic!("server returned runtime error: {err}"),
            Ok(Err(err)) => panic!("server task failed: {err}"),
            Err(_) => panic!("timed out waiting for server shutdown"),
        }
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
    let key_pem = certified.signing_key.serialize_pem();
    (cert_pem, key_pem)
}

fn build_tls_handler(cert_path: &Path, key_path: &Path) -> Arc<RustlsTlsHandler> {
    let config = TlsConfig {
        cert_path: cert_path.to_string_lossy().into_owned(),
        key_path: key_path.to_string_lossy().into_owned(),
        ca_file: None,
        min_tls_version: TlsVersion::Tls12,
        max_tls_version: TlsVersion::Tls13,
        require_client_cert: false,
    };

    Arc::new(RustlsTlsHandler::new(&config).unwrap())
}

async fn build_security_config(
    audit_log_path: &Path,
    access_control: Option<Arc<AciEngine>>,
    root_dn: Option<String>,
) -> Arc<LegacySecurityConfig> {
    let audit_logger = AuditLogger::new(audit_log_path, AuditLevel::Debug);
    audit_logger.initialize().await.unwrap();
    Arc::new(LegacySecurityConfig {
        audit_logger: Some(audit_logger),
        audit_config: LegacyAuditConfig::default(),
        access_control,
        root_dn,
    })
}

async fn spawn_plain_runtime_server_with(
    credentials: Vec<(String, Vec<u8>)>,
    access_control: Option<Arc<AciEngine>>,
    root_dn: Option<String>,
) -> RuntimeServer {
    let backend: Arc<dyn DirectoryBackend> = Arc::new(MockBackend::from_credentials(credentials));
    spawn_plain_runtime_server_with_backend(backend, access_control, root_dn).await
}

async fn spawn_plain_runtime_server_with_backend(
    backend: Arc<dyn DirectoryBackend>,
    access_control: Option<Arc<AciEngine>>,
    root_dn: Option<String>,
) -> RuntimeServer {
    let tempdir = tempfile::tempdir().unwrap();
    let audit_log_path = tempdir.path().join("audit.log");
    let security = build_security_config(&audit_log_path, access_control, root_dn).await;
    let port = reserve_port();
    let addr = format!("127.0.0.1:{port}");
    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let runtime_config = LegacyServerConfig {
        rate_limiting_enabled: false,
        ..LegacyServerConfig::default()
    };

    let join_handle = tokio::spawn(async move {
        server::run_with_metrics_and_config_with_tls_and_security(
            &addr,
            backend,
            shutdown_rx,
            None,
            runtime_config,
            None,
            Some(security),
        )
        .await
    });

    RuntimeServer {
        _tempdir: tempdir,
        audit_log_path,
        shutdown_tx,
        join_handle,
        port,
        cert_pem: None,
    }
}

async fn spawn_plain_runtime_server() -> RuntimeServer {
    spawn_plain_runtime_server_with(
        vec![(ADMIN_DN.to_string(), ADMIN_PASSWORD.as_bytes().to_vec())],
        None,
        Some(ADMIN_DN.to_string()),
    )
    .await
}

async fn spawn_ldaps_runtime_server() -> RuntimeServer {
    spawn_ldaps_runtime_server_with(
        vec![(ADMIN_DN.to_string(), ADMIN_PASSWORD.as_bytes().to_vec())],
        None,
        Some(ADMIN_DN.to_string()),
    )
    .await
}

async fn spawn_ldaps_runtime_server_with(
    credentials: Vec<(String, Vec<u8>)>,
    access_control: Option<Arc<AciEngine>>,
    root_dn: Option<String>,
) -> RuntimeServer {
    let tempdir = tempfile::tempdir().unwrap();
    let audit_log_path = tempdir.path().join("audit.log");
    let cert_path = tempdir.path().join("server.crt");
    let key_path = tempdir.path().join("server.key");
    let (cert_pem, key_pem) = generate_test_certificate();
    std::fs::write(&cert_path, &cert_pem).unwrap();
    std::fs::write(&key_path, &key_pem).unwrap();

    let backend: Arc<dyn DirectoryBackend> = Arc::new(MockBackend::from_credentials(credentials));
    let security = build_security_config(&audit_log_path, access_control, root_dn).await;
    let tls_handler = build_tls_handler(&cert_path, &key_path);
    let port = reserve_port();
    let addr = format!("127.0.0.1:{port}");
    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let runtime_config = LegacyServerConfig {
        rate_limiting_enabled: false,
        ..LegacyServerConfig::default()
    };

    let join_handle = tokio::spawn(async move {
        server::run_tls_with_metrics_and_config_and_security(
            &addr,
            backend,
            shutdown_rx,
            None,
            runtime_config,
            tls_handler,
            Some(security),
        )
        .await
    });

    RuntimeServer {
        _tempdir: tempdir,
        audit_log_path,
        shutdown_tx,
        join_handle,
        port,
        cert_pem: Some(cert_pem),
    }
}

async fn connect_with_retry(port: u16) -> TcpStream {
    let addr = format!("127.0.0.1:{port}");
    for _ in 0..80 {
        match TcpStream::connect(&addr).await {
            Ok(stream) => return stream,
            Err(_) => sleep(Duration::from_millis(50)).await,
        }
    }

    panic!("failed to connect to runtime on port {port}");
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

fn encode_sasl_plain_bind_request(message_id: u32, bind_dn: &str) -> Vec<u8> {
    let credentials = format!("\0{bind_dn}\0{ADMIN_PASSWORD}").into_bytes();
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

fn encode_simple_bind_request(message_id: u32, bind_dn: &str, password: &str) -> Vec<u8> {
    let bind_request = RasnBindRequest::new(
        3,
        bind_dn.as_bytes().to_vec().into(),
        RasnAuthChoice::Simple(password.as_bytes().to_vec().into()),
    );
    let message = RasnLdapMessage::new(message_id, RasnProtocolOp::BindRequest(bind_request));
    der::encode(&message).unwrap()
}

fn rasn_attribute(name: &str, values: &[&str]) -> RasnAttribute {
    RasnAttribute::new(
        name.as_bytes().to_vec().into(),
        values
            .iter()
            .map(|value| value.as_bytes().to_vec().into())
            .collect::<SetOf<_>>(),
    )
}

fn encode_add_request(message_id: u32, dn: &str) -> Vec<u8> {
    let request = RasnAddRequest {
        entry: dn.as_bytes().to_vec().into(),
        attributes: vec![
            rasn_attribute("objectClass", &["person"]),
            rasn_attribute("cn", &["Alice"]),
            rasn_attribute("sn", &["Smith"]),
            rasn_attribute("userPassword", &["secret"]),
        ],
    };
    let message = RasnLdapMessage::new(message_id, RasnProtocolOp::AddRequest(request));
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
    let request = RasnExtendedRequest {
        request_name: oids::WHO_AM_I.as_bytes().to_vec().into(),
        request_value: None,
    };
    let message = RasnLdapMessage::new(message_id, RasnProtocolOp::ExtendedReq(request));
    der::encode(&message).unwrap()
}

fn encode_password_modify_request(
    message_id: u32,
    user_identity: Option<&str>,
    old_password: Option<&str>,
    new_password: Option<&str>,
) -> Vec<u8> {
    let request_value = encode_password_modify_request_value(&PasswordModifyRequest {
        user_identity: user_identity.map(str::to_string),
        old_password: old_password.map(|value| value.as_bytes().to_vec()),
        new_password: new_password.map(|value| value.as_bytes().to_vec()),
    })
    .unwrap()
    .map(Into::into);
    let request = RasnExtendedRequest {
        request_name: oids::PASSWORD_MODIFY.as_bytes().to_vec().into(),
        request_value,
    };
    let message = RasnLdapMessage::new(message_id, RasnProtocolOp::ExtendedReq(request));
    der::encode(&message).unwrap()
}

async fn send_message<S>(stream: &mut S, message: &[u8]) -> Vec<u8>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(message).await.unwrap();
    stream.flush().await.unwrap();
    read_response_bytes(stream).await
}

fn assert_bind_success(response: &[u8]) {
    let (_, messages) = parse_ldap_messages(response).unwrap();
    match &messages[0].protocol_op {
        ProtocolOp::BindResponse(bind_result) => {
            assert_eq!(bind_result.result.result_code, ParserResultCode::Success);
        }
        other => panic!("unexpected bind response: {:?}", other),
    }
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

fn localhost_server_name() -> ServerName<'static> {
    ServerName::try_from("localhost").unwrap().to_owned()
}

async fn wait_for_audit_content(path: &Path, needles: &[&str]) -> String {
    for _ in 0..80 {
        let content = tokio::fs::read_to_string(path).await.unwrap_or_default();
        if needles.iter().all(|needle| content.contains(needle)) {
            return content;
        }
        sleep(Duration::from_millis(50)).await;
    }

    let content = tokio::fs::read_to_string(path).await.unwrap_or_default();
    panic!(
        "audit log did not contain all expected markers {:?}. current content: {}",
        needles, content
    );
}

#[tokio::test]
async fn plaintext_runtime_rejects_sasl_plain_with_confidentiality_required() {
    let server = spawn_plain_runtime_server().await;
    let mut stream = connect_with_retry(server.port).await;

    let response = send_message(&mut stream, &encode_sasl_plain_bind_request(1, ADMIN_DN)).await;
    let (_, messages) = parse_ldap_messages(&response).unwrap();

    assert_eq!(messages.len(), 1);
    match &messages[0].protocol_op {
        ProtocolOp::BindResponse(bind_response) => {
            assert_eq!(
                bind_response.result.result_code,
                ParserResultCode::ConfidentialityRequired
            );
            assert_eq!(
                bind_response.result.diagnostic_message.0.as_ref(),
                "SASL PLAIN requires TLS"
            );
        }
        other => panic!("unexpected LDAP response: {:?}", other),
    }

    drop(stream);
    let audit = wait_for_audit_content(
        &server.audit_log_path,
        &[
            "\"action\":\"sasl_bind\"",
            "\"success\":false",
            "SASL PLAIN requires TLS",
            "PLAIN",
        ],
    )
    .await;
    assert!(audit.contains(ADMIN_DN));

    server.shutdown().await;
}

#[tokio::test]
async fn ldaps_runtime_accepts_sasl_plain_and_whoami_returns_bound_dn_with_audit() {
    let server = spawn_ldaps_runtime_server().await;
    let cert_pem = server.cert_pem.clone().unwrap();

    let tcp_stream = connect_with_retry(server.port).await;
    let connector = trusted_tls_connector(&cert_pem);
    let mut stream = connector
        .connect(localhost_server_name(), tcp_stream)
        .await
        .unwrap();

    let bind_response =
        send_message(&mut stream, &encode_sasl_plain_bind_request(1, ADMIN_DN)).await;
    let (_, bind_messages) = parse_ldap_messages(&bind_response).unwrap();

    assert_eq!(bind_messages.len(), 1);
    match &bind_messages[0].protocol_op {
        ProtocolOp::BindResponse(bind_result) => {
            assert_eq!(bind_result.result.result_code, ParserResultCode::Success);
        }
        other => panic!("unexpected bind response: {:?}", other),
    }

    let whoami_response = send_message(&mut stream, &encode_whoami_request(2)).await;
    let (_, whoami_messages) = parse_ldap_messages(&whoami_response).unwrap();

    assert_eq!(whoami_messages.len(), 1);
    match &whoami_messages[0].protocol_op {
        ProtocolOp::ExtendedResponse(response) => {
            assert_eq!(response.result.result_code, ParserResultCode::Success);
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
        other => panic!("unexpected extended response: {:?}", other),
    }

    drop(stream);
    let audit = wait_for_audit_content(
        &server.audit_log_path,
        &[
            "\"action\":\"sasl_bind\"",
            "\"action\":\"whoami\"",
            "\"success\":true",
            ADMIN_DN,
        ],
    )
    .await;
    assert!(audit.contains("PLAIN"));

    server.shutdown().await;
}

#[tokio::test]
async fn plaintext_runtime_rejects_password_modify_without_confidentiality() {
    let server = spawn_plain_runtime_server_with(
        vec![(USER_DN.to_string(), USER_PASSWORD.as_bytes().to_vec())],
        None,
        Some(USER_DN.to_string()),
    )
    .await;
    let mut stream = connect_with_retry(server.port).await;

    let bind_response = send_message(
        &mut stream,
        &encode_simple_bind_request(1, USER_DN, USER_PASSWORD),
    )
    .await;
    assert_bind_success(&bind_response);

    let response = send_message(
        &mut stream,
        &encode_password_modify_request(2, None, Some(USER_PASSWORD), Some("updated-secret")),
    )
    .await;
    let (_, messages) = parse_ldap_messages(&response).unwrap();

    assert_eq!(messages.len(), 1);
    match &messages[0].protocol_op {
        ProtocolOp::ExtendedResponse(result) => {
            assert_eq!(
                result.result.result_code,
                ParserResultCode::ConfidentialityRequired
            );
            assert_eq!(result.response_name, None);
            assert_eq!(result.response_value, None);
        }
        other => panic!("unexpected password modify response: {:?}", other),
    }

    drop(stream);
    let audit = wait_for_audit_content(
        &server.audit_log_path,
        &[
            "\"action\":\"password_modify\"",
            "\"success\":false",
            "Password Modify requires confidentiality protection",
        ],
    )
    .await;
    assert!(!audit.contains(USER_PASSWORD));
    assert!(!audit.contains("updated-secret"));

    server.shutdown().await;
}

#[tokio::test]
async fn ldaps_runtime_password_modify_self_service_updates_credentials_and_redacts_audit() {
    let server = spawn_ldaps_runtime_server_with(
        vec![(USER_DN.to_string(), USER_PASSWORD.as_bytes().to_vec())],
        None,
        Some(ADMIN_DN.to_string()),
    )
    .await;
    let cert_pem = server.cert_pem.clone().unwrap();

    let tcp_stream = connect_with_retry(server.port).await;
    let connector = trusted_tls_connector(&cert_pem);
    let mut stream = connector
        .connect(localhost_server_name(), tcp_stream)
        .await
        .unwrap();

    let bind_response = send_message(
        &mut stream,
        &encode_simple_bind_request(1, USER_DN, USER_PASSWORD),
    )
    .await;
    assert_bind_success(&bind_response);

    let new_password = "UpdatedUserSecret123!";
    let response = send_message(
        &mut stream,
        &encode_password_modify_request(2, None, Some(USER_PASSWORD), Some(new_password)),
    )
    .await;
    let (_, messages) = parse_ldap_messages(&response).unwrap();

    assert_eq!(messages.len(), 1);
    match &messages[0].protocol_op {
        ProtocolOp::ExtendedResponse(result) => {
            assert_eq!(result.result.result_code, ParserResultCode::Success);
            assert_eq!(result.response_name, None);
            assert_eq!(result.response_value, None);
        }
        other => panic!("unexpected password modify response: {:?}", other),
    }

    drop(stream);
    let audit = wait_for_audit_content(
        &server.audit_log_path,
        &[
            "\"action\":\"password_modify\"",
            "\"success\":true",
            "\"mode\":\"self_service\"",
            USER_DN,
        ],
    )
    .await;
    assert!(!audit.contains(USER_PASSWORD));
    assert!(!audit.contains(new_password));

    let tcp_stream = connect_with_retry(server.port).await;
    let connector = trusted_tls_connector(&cert_pem);
    let mut stream = connector
        .connect(localhost_server_name(), tcp_stream)
        .await
        .unwrap();

    let old_bind_response = send_message(
        &mut stream,
        &encode_simple_bind_request(3, USER_DN, USER_PASSWORD),
    )
    .await;
    let (_, old_bind_messages) = parse_ldap_messages(&old_bind_response).unwrap();
    match &old_bind_messages[0].protocol_op {
        ProtocolOp::BindResponse(bind_result) => {
            assert_eq!(
                bind_result.result.result_code,
                ParserResultCode::InvalidCredentials
            );
        }
        other => panic!("unexpected bind response: {:?}", other),
    }

    let new_bind_response = send_message(
        &mut stream,
        &encode_simple_bind_request(4, USER_DN, new_password),
    )
    .await;
    assert_bind_success(&new_bind_response);

    server.shutdown().await;
}

#[tokio::test]
async fn ldaps_runtime_password_modify_rejects_wrong_old_password() {
    let server = spawn_ldaps_runtime_server_with(
        vec![(USER_DN.to_string(), USER_PASSWORD.as_bytes().to_vec())],
        None,
        Some(ADMIN_DN.to_string()),
    )
    .await;
    let cert_pem = server.cert_pem.clone().unwrap();

    let tcp_stream = connect_with_retry(server.port).await;
    let connector = trusted_tls_connector(&cert_pem);
    let mut stream = connector
        .connect(localhost_server_name(), tcp_stream)
        .await
        .unwrap();

    let bind_response = send_message(
        &mut stream,
        &encode_simple_bind_request(1, USER_DN, USER_PASSWORD),
    )
    .await;
    assert_bind_success(&bind_response);

    let attempted_password = "CandidateSecret789!";
    let response = send_message(
        &mut stream,
        &encode_password_modify_request(
            2,
            None,
            Some("wrong-old-secret"),
            Some(attempted_password),
        ),
    )
    .await;
    let (_, messages) = parse_ldap_messages(&response).unwrap();

    assert_eq!(messages.len(), 1);
    match &messages[0].protocol_op {
        ProtocolOp::ExtendedResponse(result) => {
            assert_eq!(
                result.result.result_code,
                ParserResultCode::InvalidCredentials
            );
            assert_eq!(result.response_name, None);
            assert_eq!(result.response_value, None);
        }
        other => panic!("unexpected password modify response: {:?}", other),
    }

    drop(stream);
    let audit = wait_for_audit_content(
        &server.audit_log_path,
        &[
            "\"action\":\"password_modify\"",
            "\"success\":false",
            "\"mode\":\"self_service\"",
            "invalid credentials",
        ],
    )
    .await;
    assert!(!audit.contains("wrong-old-secret"));
    assert!(!audit.contains(attempted_password));

    let tcp_stream = connect_with_retry(server.port).await;
    let connector = trusted_tls_connector(&cert_pem);
    let mut stream = connector
        .connect(localhost_server_name(), tcp_stream)
        .await
        .unwrap();

    let bind_response = send_message(
        &mut stream,
        &encode_simple_bind_request(3, USER_DN, USER_PASSWORD),
    )
    .await;
    assert_bind_success(&bind_response);

    server.shutdown().await;
}

#[tokio::test]
async fn ldaps_runtime_password_modify_admin_reset_returns_generated_password() {
    let server = spawn_ldaps_runtime_server_with(
        vec![
            (ADMIN_DN.to_string(), ADMIN_PASSWORD.as_bytes().to_vec()),
            (OTHER_DN.to_string(), OTHER_PASSWORD.as_bytes().to_vec()),
        ],
        None,
        Some(ADMIN_DN.to_string()),
    )
    .await;
    let cert_pem = server.cert_pem.clone().unwrap();

    let tcp_stream = connect_with_retry(server.port).await;
    let connector = trusted_tls_connector(&cert_pem);
    let mut stream = connector
        .connect(localhost_server_name(), tcp_stream)
        .await
        .unwrap();

    let bind_response = send_message(
        &mut stream,
        &encode_simple_bind_request(1, ADMIN_DN, ADMIN_PASSWORD),
    )
    .await;
    assert_bind_success(&bind_response);

    let response = send_message(
        &mut stream,
        &encode_password_modify_request(2, Some(OTHER_DN), None, None),
    )
    .await;
    let (_, messages) = parse_ldap_messages(&response).unwrap();

    assert_eq!(messages.len(), 1);
    let generated_password = match &messages[0].protocol_op {
        ProtocolOp::ExtendedResponse(result) => {
            assert_eq!(result.result.result_code, ParserResultCode::Success);
            assert_eq!(result.response_name, None);
            let response_value = decode_password_modify_response_value(
                result.response_value.as_ref().map(|value| value.as_ref()),
            )
            .unwrap()
            .expect("generated password response value");
            String::from_utf8(response_value).unwrap()
        }
        other => panic!("unexpected password modify response: {:?}", other),
    };

    drop(stream);
    let audit = wait_for_audit_content(
        &server.audit_log_path,
        &[
            "\"action\":\"password_modify\"",
            "\"success\":true",
            "\"mode\":\"admin_reset\"",
            OTHER_DN,
        ],
    )
    .await;
    assert!(!audit.contains(&generated_password));

    let tcp_stream = connect_with_retry(server.port).await;
    let connector = trusted_tls_connector(&cert_pem);
    let mut stream = connector
        .connect(localhost_server_name(), tcp_stream)
        .await
        .unwrap();

    let bind_response = send_message(
        &mut stream,
        &encode_simple_bind_request(3, OTHER_DN, &generated_password),
    )
    .await;
    assert_bind_success(&bind_response);

    server.shutdown().await;
}

#[tokio::test]
async fn ldaps_runtime_password_modify_rejects_malformed_request_value() {
    let server = spawn_ldaps_runtime_server_with(
        vec![(USER_DN.to_string(), USER_PASSWORD.as_bytes().to_vec())],
        None,
        Some(ADMIN_DN.to_string()),
    )
    .await;
    let cert_pem = server.cert_pem.clone().unwrap();

    let tcp_stream = connect_with_retry(server.port).await;
    let connector = trusted_tls_connector(&cert_pem);
    let mut stream = connector
        .connect(localhost_server_name(), tcp_stream)
        .await
        .unwrap();

    let bind_response = send_message(
        &mut stream,
        &encode_simple_bind_request(1, USER_DN, USER_PASSWORD),
    )
    .await;
    assert_bind_success(&bind_response);

    let request = RasnExtendedRequest {
        request_name: oids::PASSWORD_MODIFY.as_bytes().to_vec().into(),
        request_value: Some(vec![0x01, 0x01, 0x00].into()),
    };
    let message = RasnLdapMessage::new(2, RasnProtocolOp::ExtendedReq(request));
    let response = send_message(&mut stream, &der::encode(&message).unwrap()).await;
    let (_, messages) = parse_ldap_messages(&response).unwrap();

    assert_eq!(messages.len(), 1);
    match &messages[0].protocol_op {
        ProtocolOp::ExtendedResponse(result) => {
            assert_eq!(result.result.result_code, ParserResultCode::ProtocolError);
            assert_eq!(result.response_name, None);
            assert_eq!(result.response_value, None);
        }
        other => panic!("unexpected password modify response: {:?}", other),
    }

    server.shutdown().await;
}

#[tokio::test]
async fn plaintext_runtime_emits_bind_and_add_audit_events() {
    let server = spawn_plain_runtime_server().await;
    let mut stream = connect_with_retry(server.port).await;

    let bind_response = send_message(
        &mut stream,
        &encode_simple_bind_request(1, ADMIN_DN, ADMIN_PASSWORD),
    )
    .await;
    let (_, bind_messages) = parse_ldap_messages(&bind_response).unwrap();
    match &bind_messages[0].protocol_op {
        ProtocolOp::BindResponse(bind_result) => {
            assert_eq!(bind_result.result.result_code, ParserResultCode::Success);
        }
        other => panic!("unexpected bind response: {:?}", other),
    }

    let add_response = send_message(&mut stream, &encode_add_request(2, NEW_ENTRY_DN)).await;
    let (_, add_messages) = parse_ldap_messages(&add_response).unwrap();
    match &add_messages[0].protocol_op {
        ProtocolOp::AddResponse(add_result) => {
            assert_eq!(add_result.result_code, ParserResultCode::Success);
        }
        other => panic!("unexpected add response: {:?}", other),
    }

    drop(stream);
    let _audit = wait_for_audit_content(
        &server.audit_log_path,
        &[
            "\"action\":\"simple_bind\"",
            "\"action\":\"add\"",
            "\"success\":true",
            ADMIN_DN,
            NEW_ENTRY_DN,
        ],
    )
    .await;

    server.shutdown().await;
}

#[tokio::test]
async fn restrictive_aci_denies_compare_in_live_runtime_and_audits_denial() {
    let server = spawn_plain_runtime_server_with(
        vec![
            (ADMIN_DN.to_string(), ADMIN_PASSWORD.as_bytes().to_vec()),
            (USER_DN.to_string(), USER_PASSWORD.as_bytes().to_vec()),
        ],
        Some(Arc::new(AciEngine::restrictive())),
        Some(ADMIN_DN.to_string()),
    )
    .await;
    let mut stream = connect_with_retry(server.port).await;

    let bind_response = send_message(
        &mut stream,
        &encode_simple_bind_request(1, USER_DN, USER_PASSWORD),
    )
    .await;
    let (_, bind_messages) = parse_ldap_messages(&bind_response).unwrap();
    match &bind_messages[0].protocol_op {
        ProtocolOp::BindResponse(bind_result) => {
            assert_eq!(bind_result.result.result_code, ParserResultCode::Success);
        }
        other => panic!("unexpected bind response: {:?}", other),
    }

    let compare_response = send_message(
        &mut stream,
        &encode_compare_request(2, COMPARE_TARGET_DN, "cn", "target"),
    )
    .await;
    let (_, compare_messages) = parse_ldap_messages(&compare_response).unwrap();
    match &compare_messages[0].protocol_op {
        ProtocolOp::CompareResponse(compare_result) => {
            assert_eq!(
                compare_result.result_code,
                ParserResultCode::InsufficientAccessRights
            );
            assert!(
                compare_result
                    .diagnostic_message
                    .0
                    .as_ref()
                    .contains("Access denied")
            );
        }
        other => panic!("unexpected compare response: {:?}", other),
    }

    drop(stream);
    let _audit = wait_for_audit_content(
        &server.audit_log_path,
        &[
            "\"action\":\"authz_compare\"",
            "\"success\":false",
            USER_DN,
            COMPARE_TARGET_DN,
            "Access denied",
        ],
    )
    .await;

    server.shutdown().await;
}

#[tokio::test]
async fn group_aci_grants_compare_and_add_for_member_in_live_runtime() {
    let backend = MockBackend::from_credentials([
        (ADMIN_DN.to_string(), ADMIN_PASSWORD.as_bytes().to_vec()),
        (USER_DN.to_string(), USER_PASSWORD.as_bytes().to_vec()),
    ]);
    backend
        .add_entry(
            opendr::backend::DirectoryEntry::new(
                COMPARE_TARGET_DN,
                std::collections::HashMap::from([
                    ("cn".to_string(), vec!["target".to_string()]),
                    ("objectclass".to_string(), vec!["person".to_string()]),
                ]),
            ),
            Vec::new(),
        )
        .await
        .unwrap();
    backend
        .add_entry(
            opendr::backend::DirectoryEntry::new(
                "cn=operators,dc=example,dc=org",
                std::collections::HashMap::from([
                    ("member".to_string(), vec![USER_DN.to_string()]),
                    ("objectclass".to_string(), vec!["groupOfNames".to_string()]),
                ]),
            ),
            Vec::new(),
        )
        .await
        .unwrap();

    let engine = Arc::new(AciEngine::restrictive());
    engine
        .add_rule(
            opendr::aci::AciRuleBuilder::grant("group-compare")
                .target_subtree("dc=example,dc=org")
                .permission(opendr::aci::Permission::Compare)
                .subject_group("cn=operators,dc=example,dc=org")
                .build()
                .unwrap(),
        )
        .await;
    engine
        .add_rule(
            opendr::aci::AciRuleBuilder::grant("group-add")
                .target_subtree("dc=example,dc=org")
                .permission(opendr::aci::Permission::Add)
                .subject_group("cn=operators,dc=example,dc=org")
                .build()
                .unwrap(),
        )
        .await;

    let server = spawn_plain_runtime_server_with_backend(
        Arc::new(backend),
        Some(engine),
        Some(ADMIN_DN.to_string()),
    )
    .await;
    let mut stream = connect_with_retry(server.port).await;

    let bind_response = send_message(
        &mut stream,
        &encode_simple_bind_request(1, USER_DN, USER_PASSWORD),
    )
    .await;
    assert_bind_success(&bind_response);

    let compare_response = send_message(
        &mut stream,
        &encode_compare_request(2, COMPARE_TARGET_DN, "cn", "target"),
    )
    .await;
    let (_, compare_messages) = parse_ldap_messages(&compare_response).unwrap();
    match &compare_messages[0].protocol_op {
        ProtocolOp::CompareResponse(compare_result) => {
            assert_eq!(compare_result.result_code, ParserResultCode::CompareTrue);
        }
        other => panic!("unexpected compare response: {:?}", other),
    }

    let add_response = send_message(&mut stream, &encode_add_request(3, NEW_ENTRY_DN)).await;
    let (_, add_messages) = parse_ldap_messages(&add_response).unwrap();
    match &add_messages[0].protocol_op {
        ProtocolOp::AddResponse(add_result) => {
            assert_eq!(add_result.result_code, ParserResultCode::Success);
        }
        other => panic!("unexpected add response: {:?}", other),
    }

    server.shutdown().await;
}

#[tokio::test]
async fn group_aci_denies_non_member_in_live_runtime() {
    let backend = MockBackend::from_credentials([
        (ADMIN_DN.to_string(), ADMIN_PASSWORD.as_bytes().to_vec()),
        (USER_DN.to_string(), USER_PASSWORD.as_bytes().to_vec()),
        (OTHER_DN.to_string(), OTHER_PASSWORD.as_bytes().to_vec()),
    ]);
    backend
        .add_entry(
            opendr::backend::DirectoryEntry::new(
                COMPARE_TARGET_DN,
                std::collections::HashMap::from([
                    ("cn".to_string(), vec!["target".to_string()]),
                    ("objectclass".to_string(), vec!["person".to_string()]),
                ]),
            ),
            Vec::new(),
        )
        .await
        .unwrap();
    backend
        .add_entry(
            opendr::backend::DirectoryEntry::new(
                "cn=operators,dc=example,dc=org",
                std::collections::HashMap::from([
                    ("member".to_string(), vec![USER_DN.to_string()]),
                    ("objectclass".to_string(), vec!["groupOfNames".to_string()]),
                ]),
            ),
            Vec::new(),
        )
        .await
        .unwrap();

    let engine = Arc::new(AciEngine::restrictive());
    engine
        .add_rule(
            opendr::aci::AciRuleBuilder::grant("group-compare")
                .target_subtree("dc=example,dc=org")
                .permission(opendr::aci::Permission::Compare)
                .subject_group("cn=operators,dc=example,dc=org")
                .build()
                .unwrap(),
        )
        .await;

    let server = spawn_plain_runtime_server_with_backend(
        Arc::new(backend),
        Some(engine),
        Some(ADMIN_DN.to_string()),
    )
    .await;
    let mut stream = connect_with_retry(server.port).await;

    let bind_response = send_message(
        &mut stream,
        &encode_simple_bind_request(1, OTHER_DN, OTHER_PASSWORD),
    )
    .await;
    assert_bind_success(&bind_response);

    let compare_response = send_message(
        &mut stream,
        &encode_compare_request(2, COMPARE_TARGET_DN, "cn", "target"),
    )
    .await;
    let (_, compare_messages) = parse_ldap_messages(&compare_response).unwrap();
    match &compare_messages[0].protocol_op {
        ProtocolOp::CompareResponse(compare_result) => {
            assert_eq!(
                compare_result.result_code,
                ParserResultCode::InsufficientAccessRights
            );
        }
        other => panic!("unexpected compare response: {:?}", other),
    }

    server.shutdown().await;
}

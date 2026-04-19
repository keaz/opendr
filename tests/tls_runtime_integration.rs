use std::collections::HashMap;
use std::fs;
use std::io::Cursor;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use ldap_parser::ldap::{ProtocolOp, ResultCode as ParserResultCode};
use ldap_parser::parse_ldap_messages;
use opendr::extended_ops::oids;
use opendr::read_entry_controls::{POST_READ_CONTROL_OID, PRE_READ_CONTROL_OID};
use opendr::search_controls::{
    PAGED_RESULTS_OID, SERVER_SIDE_SORT_REQUEST_OID, SERVER_SIDE_SORT_RESPONSE_OID,
    SUBENTRIES_CONTROL_OID,
};
use opendr::sync_controls::{SYNC_DONE_OID, SYNC_REQUEST_OID, SYNC_STATE_OID};
use rasn::der;
use rasn_ldap::{
    AuthenticationChoice as RasnAuthChoice, BindRequest as RasnBindRequest,
    ExtendedRequest as RasnExtendedRequest, Filter as RasnFilter, LdapMessage as RasnLdapMessage,
    ProtocolOp as RasnProtocolOp, SaslCredentials as RasnSaslCredentials,
    SearchRequest as RasnSearchRequest, SearchRequestDerefAliases, SearchRequestScope,
};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, generate_simple_self_signed,
};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tempfile::TempDir;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsConnector;

const MANAGE_DSA_IT_OID: &str = "2.16.840.1.113730.3.4.2";
const DEFAULT_TEST_ROOT_PASSWORD: &str = "secret";
const PRODUCTION_TEST_ROOT_PASSWORD: &str = "TlsRuntimeProductionRootSecret123!";

struct TestBinaryServer {
    _tempdir: TempDir,
    child: Child,
    ldap_port: u16,
    ldaps_port: u16,
    cert_pem: String,
    client_cert_pem: Option<String>,
    client_key_pem: Option<String>,
}

struct TlsFixtureConfig<'a> {
    runtime: &'a str,
    ldap_port: u16,
    ldaps_port: u16,
    tls_enabled: bool,
    cert_pem: &'a str,
    key_pem: &'a str,
    ca_pem: Option<&'a str>,
    require_client_cert: bool,
    sasl_external_identity_map: Option<(&'a str, &'a str)>,
    security_profile: Option<&'a str>,
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
    let key_pem = certified.signing_key.serialize_pem();
    (cert_pem, key_pem)
}

fn certificate_params_with_cn(common_name: &str) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params
}

fn generate_mtls_certificates() -> (String, String, String, String, String) {
    let mut ca_params = certificate_params_with_cn("OpenDR Test CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::from_params(&ca_params, &ca_key);

    let server_key = KeyPair::generate().unwrap();
    let server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let server_cert = server_params.signed_by(&server_key, &issuer).unwrap();

    let client_key = KeyPair::generate().unwrap();
    let mut client_params = certificate_params_with_cn("opendr-client");
    client_params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);
    let client_cert = client_params.signed_by(&client_key, &issuer).unwrap();

    (
        ca_cert.pem(),
        server_cert.pem(),
        server_key.serialize_pem(),
        client_cert.pem(),
        client_key.serialize_pem(),
    )
}

fn write_tls_fixture(tempdir: &TempDir, fixture: &TlsFixtureConfig<'_>) {
    let config_dir = tempdir.path().join("config");
    let cert_dir = tempdir.path().join("certs");
    let data_dir = tempdir.path().join("data");

    fs::create_dir_all(&config_dir).unwrap();
    fs::create_dir_all(&cert_dir).unwrap();
    fs::create_dir_all(&data_dir).unwrap();

    fs::write(cert_dir.join("server.crt"), fixture.cert_pem).unwrap();
    fs::write(cert_dir.join("server.key"), fixture.key_pem).unwrap();
    if let Some(ca_pem) = fixture.ca_pem {
        fs::write(cert_dir.join("ca.crt"), ca_pem).unwrap();
    }

    let production_profile = fixture
        .security_profile
        .is_some_and(|profile| profile.eq_ignore_ascii_case("production"));
    let root_password_toml = if production_profile {
        let root_password_file = config_dir.join("root-password.txt");
        fs::write(&root_password_file, PRODUCTION_TEST_ROOT_PASSWORD).unwrap();
        r#"root_password_file = "config/root-password.txt""#.to_string()
    } else {
        format!(r#"root_password = "{DEFAULT_TEST_ROOT_PASSWORD}""#)
    };

    let mut security_toml = fixture
        .security_profile
        .map(|profile| {
            format!(
                r#"
[security]
profile = "{profile}"
"#
            )
        })
        .unwrap_or_default();
    if let Some((certificate_cn, mapped_dn)) = fixture.sasl_external_identity_map {
        if security_toml.is_empty() {
            security_toml.push_str("\n[security]\n");
        }
        security_toml.push_str("allow_sasl_external = true\n");
        security_toml.push_str(&format!(
            "sasl_external_identity_map = {{ \"{certificate_cn}\" = \"{mapped_dn}\" }}\n"
        ));
    }

    let server_toml = format!(
        r#"
[server]
runtime = "{runtime}"
bind_address = "127.0.0.1"
ldap_port = {ldap_port}
ldaps_port = {ldaps_port}
base_dn = "dc=example,dc=org"
root_user_dn = "cn=admin"
{root_password_toml}

[backend]
backend_type = "memory"
data_directory = "./data"

[tls]
enabled = {tls_enabled}
cert_file = "certs/server.crt"
key_file = "certs/server.key"
{ca_file}
require_client_cert = {require_client_cert}
min_tls_version = "1.2"
{security_toml}

[monitoring]
enabled = false

[replication]
enabled = false

[rate_limit]
enabled = false
"#,
        runtime = fixture.runtime,
        ldap_port = fixture.ldap_port,
        ldaps_port = fixture.ldaps_port,
        tls_enabled = fixture.tls_enabled,
        ca_file = fixture
            .ca_pem
            .map(|_| r#"ca_file = "certs/ca.crt""#)
            .unwrap_or(""),
        require_client_cert = fixture.require_client_cert,
        root_password_toml = root_password_toml,
        security_toml = security_toml,
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
    client_cert_pem: Option<String>,
    client_key_pem: Option<String>,
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
        client_cert_pem,
        client_key_pem,
    }
}

fn tls_runtime_fixture(runtime: &str, tls_enabled: bool) -> TestBinaryServer {
    let tempdir = tempfile::tempdir().unwrap();
    let ldap_port = reserve_port();
    let ldaps_port = reserve_port();
    let (cert_pem, key_pem) = generate_test_certificate();
    write_tls_fixture(
        &tempdir,
        &TlsFixtureConfig {
            runtime,
            ldap_port,
            ldaps_port,
            tls_enabled,
            cert_pem: &cert_pem,
            key_pem: &key_pem,
            ca_pem: None,
            require_client_cert: false,
            sasl_external_identity_map: None,
            security_profile: None,
        },
    );
    spawn_opendr(tempdir, ldap_port, ldaps_port, cert_pem, None, None)
}

fn tls_runtime_fixture_with_security_profile(runtime: &str, profile: &str) -> TestBinaryServer {
    let tempdir = tempfile::tempdir().unwrap();
    let ldap_port = reserve_port();
    let ldaps_port = reserve_port();
    let (cert_pem, key_pem) = generate_test_certificate();
    write_tls_fixture(
        &tempdir,
        &TlsFixtureConfig {
            runtime,
            ldap_port,
            ldaps_port,
            tls_enabled: true,
            cert_pem: &cert_pem,
            key_pem: &key_pem,
            ca_pem: None,
            require_client_cert: false,
            sasl_external_identity_map: None,
            security_profile: Some(profile),
        },
    );
    spawn_opendr(tempdir, ldap_port, ldaps_port, cert_pem, None, None)
}

fn mtls_runtime_fixture(runtime: &str) -> TestBinaryServer {
    let tempdir = tempfile::tempdir().unwrap();
    let ldap_port = reserve_port();
    let ldaps_port = reserve_port();
    let (ca_pem, server_cert_pem, server_key_pem, client_cert_pem, client_key_pem) =
        generate_mtls_certificates();
    write_tls_fixture(
        &tempdir,
        &TlsFixtureConfig {
            runtime,
            ldap_port,
            ldaps_port,
            tls_enabled: true,
            cert_pem: &server_cert_pem,
            key_pem: &server_key_pem,
            ca_pem: Some(&ca_pem),
            require_client_cert: true,
            sasl_external_identity_map: Some(("opendr-client", "cn=admin,dc=example,dc=org")),
            security_profile: None,
        },
    );
    spawn_opendr(
        tempdir,
        ldap_port,
        ldaps_port,
        ca_pem,
        Some(client_cert_pem),
        Some(client_key_pem),
    )
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
    send_bind_request_with_password(stream, message_id, DEFAULT_TEST_ROOT_PASSWORD).await
}

async fn send_bind_request_with_password<S>(
    stream: &mut S,
    message_id: u32,
    password: &str,
) -> Vec<u8>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let bind_request = RasnBindRequest::new(
        3,
        b"cn=admin,dc=example,dc=org".to_vec().into(),
        RasnAuthChoice::Simple(password.as_bytes().to_vec().into()),
    );
    let bind_message =
        rasn_ldap::LdapMessage::new(message_id, rasn_ldap::ProtocolOp::BindRequest(bind_request));
    let bind_message = der::encode(&bind_message).unwrap();

    stream.write_all(&bind_message).await.unwrap();
    read_response_bytes(stream).await
}

async fn send_anonymous_bind_request<S>(stream: &mut S, message_id: u32) -> Vec<u8>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let bind_request = RasnBindRequest::new(
        3,
        Vec::<u8>::new().into(),
        RasnAuthChoice::Simple(Vec::<u8>::new().into()),
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

async fn send_sasl_external_bind_request<S>(
    stream: &mut S,
    message_id: u32,
    authzid: Option<&str>,
) -> Vec<u8>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let bind_request = RasnBindRequest::new(
        3,
        Vec::<u8>::new().into(),
        RasnAuthChoice::Sasl(RasnSaslCredentials::new(
            b"EXTERNAL".to_vec().into(),
            authzid.map(|authzid| authzid.as_bytes().to_vec().into()),
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

fn root_dse_search_message(message_id: u32) -> Vec<u8> {
    let search_request = RasnSearchRequest::new(
        b"".to_vec().into(),
        SearchRequestScope::BaseObject,
        SearchRequestDerefAliases::NeverDerefAliases,
        0,
        0,
        false,
        RasnFilter::Present(b"objectClass".to_vec().into()),
        [
            "supportedLDAPVersion",
            "namingContexts",
            "supportedExtension",
            "supportedControl",
            "supportedSASLMechanisms",
        ]
        .into_iter()
        .map(|attribute| attribute.as_bytes().to_vec().into())
        .collect(),
    );
    let message = RasnLdapMessage::new(message_id, RasnProtocolOp::SearchRequest(search_request));
    der::encode(&message).unwrap()
}

async fn read_search_response_bytes<S>(stream: &mut S) -> Vec<u8>
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
                match parse_ldap_messages(&response) {
                    Ok((_, messages))
                        if messages.iter().any(|message| {
                            matches!(message.protocol_op, ProtocolOp::SearchResultDone(_))
                        }) =>
                    {
                        break;
                    }
                    _ => {}
                }
            }
            Ok(Err(err)) => panic!("failed to read LDAP search response: {err}"),
            Err(_) if !response.is_empty() => break,
            Err(_) => panic!("timed out waiting for LDAP search response"),
        }
    }

    response
}

async fn send_root_dse_search_request<S>(stream: &mut S, message_id: u32) -> Vec<u8>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream
        .write_all(&root_dse_search_message(message_id))
        .await
        .unwrap();
    read_search_response_bytes(stream).await
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
                    .map(|value| String::from_utf8(value.0.as_ref().to_vec()).unwrap())
                    .collect::<Vec<_>>(),
            )
        })
        .collect()
}

fn assert_root_dse_capabilities(response: &[u8], secure_connection: bool, expect_starttls: bool) {
    let (_, messages) = parse_ldap_messages(response).unwrap();
    let attributes = messages
        .iter()
        .find_map(|message| match &message.protocol_op {
            ProtocolOp::SearchResultEntry(entry) => Some(search_entry_attribute_map(entry)),
            _ => None,
        })
        .expect("Root DSE search entry");

    let done = messages
        .iter()
        .find_map(|message| match &message.protocol_op {
            ProtocolOp::SearchResultDone(done) => Some(done),
            _ => None,
        })
        .expect("Root DSE search done");
    assert_eq!(done.result_code, ParserResultCode::Success);

    assert_eq!(
        attributes.get("supportedLDAPVersion").unwrap(),
        &vec!["3".to_string()]
    );
    assert_eq!(
        attributes.get("namingContexts").unwrap(),
        &vec!["dc=example,dc=org".to_string()]
    );

    let mut supported_controls = attributes.get("supportedControl").unwrap().clone();
    supported_controls.sort();
    let mut expected_controls = vec![
        MANAGE_DSA_IT_OID.to_string(),
        PAGED_RESULTS_OID.to_string(),
        POST_READ_CONTROL_OID.to_string(),
        PRE_READ_CONTROL_OID.to_string(),
        SERVER_SIDE_SORT_REQUEST_OID.to_string(),
        SUBENTRIES_CONTROL_OID.to_string(),
        SYNC_REQUEST_OID.to_string(),
    ];
    expected_controls.sort();
    assert_eq!(supported_controls, expected_controls);
    assert!(!supported_controls.contains(&SERVER_SIDE_SORT_RESPONSE_OID.to_string()));
    assert!(!supported_controls.contains(&SYNC_STATE_OID.to_string()));
    assert!(!supported_controls.contains(&SYNC_DONE_OID.to_string()));

    let supported_extensions = attributes.get("supportedExtension").unwrap();
    assert!(supported_extensions.contains(&oids::CANCEL.to_string()));
    assert!(supported_extensions.contains(&oids::PASSWORD_MODIFY.to_string()));
    assert!(supported_extensions.contains(&oids::WHO_AM_I.to_string()));
    assert_eq!(
        supported_extensions.contains(&oids::START_TLS.to_string()),
        expect_starttls
    );

    if secure_connection {
        assert_eq!(
            attributes.get("supportedSASLMechanisms").unwrap(),
            &vec!["PLAIN".to_string()]
        );
    } else {
        assert!(
            !attributes.contains_key("supportedSASLMechanisms"),
            "SASL PLAIN must not be advertised before transport confidentiality is established"
        );
    }
}

fn assert_root_dse_sasl_mechanisms(response: &[u8], expected: &[&str]) {
    let (_, messages) = parse_ldap_messages(response).unwrap();
    let attributes = messages
        .iter()
        .find_map(|message| match &message.protocol_op {
            ProtocolOp::SearchResultEntry(entry) => Some(search_entry_attribute_map(entry)),
            _ => None,
        })
        .expect("Root DSE search entry");
    let mut actual = attributes
        .get("supportedSASLMechanisms")
        .cloned()
        .unwrap_or_default();
    actual.sort();
    let mut expected = expected
        .iter()
        .map(|mechanism| mechanism.to_string())
        .collect::<Vec<_>>();
    expected.sort();
    assert_eq!(actual, expected);
}

async fn assert_root_dse_transport_capabilities(runtime: &str) {
    let server = tls_runtime_fixture(runtime, true);

    let mut stream = connect_with_retry(server.ldap_port).await;
    let response = send_root_dse_search_request(&mut stream, 1).await;
    assert_root_dse_capabilities(&response, false, true);

    let mut stream = connect_with_retry(server.ldap_port).await;
    let starttls_response = send_starttls_request(&mut stream, 2).await;
    assert_starttls_success(&starttls_response);
    let connector = trusted_tls_connector(&server.cert_pem);
    let mut tls_stream = connector
        .connect(localhost_server_name(), stream)
        .await
        .expect("StartTLS upgrade should complete with trusted server certificate");
    let response = send_root_dse_search_request(&mut tls_stream, 3).await;
    assert_root_dse_capabilities(&response, true, false);

    let stream = connect_with_retry(server.ldaps_port).await;
    let connector = trusted_tls_connector(&server.cert_pem);
    let mut tls_stream = connector
        .connect(localhost_server_name(), stream)
        .await
        .expect("LDAPS handshake should succeed with trusted server certificate");
    let response = send_root_dse_search_request(&mut tls_stream, 4).await;
    assert_root_dse_capabilities(&response, true, false);
}

async fn assert_production_security_profile(runtime: &str) {
    let server = tls_runtime_fixture_with_security_profile(runtime, "production");

    let mut stream = connect_with_retry(server.ldap_port).await;
    let response = send_anonymous_bind_request(&mut stream, 1).await;
    assert_bind_result(&response, ParserResultCode::InappropriateAuthentication);

    let mut stream = connect_with_retry(server.ldap_port).await;
    let response = send_bind_request(&mut stream, 2).await;
    assert_bind_result(&response, ParserResultCode::ConfidentialityRequired);

    let mut stream = connect_with_retry(server.ldap_port).await;
    let starttls_response = send_starttls_request(&mut stream, 3).await;
    assert_starttls_success(&starttls_response);
    let connector = trusted_tls_connector(&server.cert_pem);
    let mut tls_stream = connector
        .connect(localhost_server_name(), stream)
        .await
        .expect("StartTLS upgrade should complete with trusted server certificate");
    let response =
        send_bind_request_with_password(&mut tls_stream, 4, PRODUCTION_TEST_ROOT_PASSWORD).await;
    assert_bind_success(&response);
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

fn trusted_tls_connector_with_client_cert(
    ca_pem: &str,
    client_cert_pem: &str,
    client_key_pem: &str,
) -> TlsConnector {
    let mut roots = RootCertStore::empty();
    let mut ca_reader = Cursor::new(ca_pem.as_bytes());
    for cert in rustls_pemfile::certs(&mut ca_reader) {
        roots.add(cert.unwrap()).unwrap();
    }

    let mut cert_reader = Cursor::new(client_cert_pem.as_bytes());
    let client_certs = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut key_reader = Cursor::new(client_key_pem.as_bytes());
    let client_key = rustls_pemfile::pkcs8_private_keys(&mut key_reader)
        .next()
        .unwrap()
        .unwrap()
        .into();

    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(client_certs, client_key)
        .unwrap();
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
    assert_bind_result(response, ldap_parser::ldap::ResultCode::Success);
}

fn assert_bind_result(response: &[u8], expected: ldap_parser::ldap::ResultCode) {
    let (_, messages) = parse_ldap_messages(response).unwrap();
    assert_eq!(messages.len(), 1);
    match &messages[0].protocol_op {
        ProtocolOp::BindResponse(bind_response) => {
            assert_eq!(bind_response.result.result_code, expected);
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
async fn legacy_root_dse_advertises_capabilities_by_transport_state() {
    assert_root_dse_transport_capabilities("legacy").await;
}

#[tokio::test]
async fn fsm_root_dse_advertises_capabilities_by_transport_state() {
    assert_root_dse_transport_capabilities("fsm").await;
}

#[tokio::test]
async fn legacy_production_profile_denies_unsafe_binds_until_starttls() {
    assert_production_security_profile("legacy").await;
}

#[tokio::test]
async fn fsm_production_profile_denies_unsafe_binds_until_starttls() {
    assert_production_security_profile("fsm").await;
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

async fn assert_ldaps_sasl_external_with_client_certificate(runtime: &str) {
    let server = mtls_runtime_fixture(runtime);
    let stream = connect_with_retry(server.ldaps_port).await;
    let connector = trusted_tls_connector_with_client_cert(
        &server.cert_pem,
        server.client_cert_pem.as_ref().unwrap(),
        server.client_key_pem.as_ref().unwrap(),
    );
    let mut tls_stream = connector
        .connect(localhost_server_name(), stream)
        .await
        .expect("LDAPS mTLS handshake should succeed");

    let root_dse_response = send_root_dse_search_request(&mut tls_stream, 1).await;
    assert_root_dse_sasl_mechanisms(&root_dse_response, &["PLAIN", "EXTERNAL"]);

    let bind_response = send_sasl_external_bind_request(&mut tls_stream, 2, None).await;
    assert_bind_success(&bind_response);

    let whoami_response = send_whoami_request(&mut tls_stream, 3).await;
    assert_whoami_bound_admin(&whoami_response);
}

#[tokio::test]
async fn legacy_ldaps_accepts_sasl_external_with_client_certificate() {
    assert_ldaps_sasl_external_with_client_certificate("legacy").await;
}

#[tokio::test]
async fn fsm_ldaps_accepts_sasl_external_with_client_certificate() {
    assert_ldaps_sasl_external_with_client_certificate("fsm").await;
}

#[tokio::test]
async fn fsm_starttls_accepts_sasl_external_with_client_certificate_authzid() {
    let server = mtls_runtime_fixture("fsm");

    let mut stream = connect_with_retry(server.ldap_port).await;
    let starttls_response = send_starttls_request(&mut stream, 1).await;
    assert_starttls_success(&starttls_response);

    let connector = trusted_tls_connector_with_client_cert(
        &server.cert_pem,
        server.client_cert_pem.as_ref().unwrap(),
        server.client_key_pem.as_ref().unwrap(),
    );
    let mut tls_stream = connector
        .connect(localhost_server_name(), stream)
        .await
        .expect("StartTLS mTLS upgrade should complete with client certificate");

    let root_dse_response = send_root_dse_search_request(&mut tls_stream, 2).await;
    assert_root_dse_sasl_mechanisms(&root_dse_response, &["PLAIN", "EXTERNAL"]);

    let bind_response =
        send_sasl_external_bind_request(&mut tls_stream, 3, Some("dn:CN=admin,DC=example,DC=org"))
            .await;
    assert_bind_success(&bind_response);

    let whoami_response = send_whoami_request(&mut tls_stream, 4).await;
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

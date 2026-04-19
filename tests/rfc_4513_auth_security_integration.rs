use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ldap_parser::asn1_rs::ToStatic;
use ldap_parser::ldap::{
    AuthenticationChoice, BindRequest, LdapDN, LdapMessage, LdapString, ProtocolOp,
    ResultCode as ParserResultCode, SaslCredentials,
};
use ldap_parser::parse_ldap_messages;
use opendr::backend::MockBackend;
use opendr::extended_ops::oids;
use opendr::fsm_request::active_fsm_control_registry;
use opendr::sasl_fsm::{CredentialVerifier, SaslChallengeResult, SaslMechanismHandler};
use opendr::sasl_mechanisms::MultiMechanismHandler;
use opendr::search_protocol::{
    build_root_dse_attributes, supported_legacy_sasl_mechanisms_for_context,
    supported_legacy_sasl_mechanisms_for_effective_security,
};
use opendr::security_layer::{EffectiveSecurityContext, SaslMechanismPolicy};
use opendr::server;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const RESPONSE_TIMEOUT: Duration = Duration::from_millis(200);
const ADMIN_DN: &str = "cn=admin,dc=example,dc=org";
const ADMIN_PASSWORD: &str = "Admin123!";
const WRONG_PASSWORD: &str = "WrongSecret!";
const SASL_SECRET: &str = "SaslSecret123!";

#[tokio::test]
async fn simple_bind_success_failure_and_anonymous_bind_return_rfc_4513_codes() {
    let backend = MockBackend::from_credentials(vec![(
        ADMIN_DN.to_string(),
        ADMIN_PASSWORD.as_bytes().to_vec(),
    )]);

    let success = bind_response(
        &backend,
        11,
        bind_request(
            ADMIN_DN,
            AuthenticationChoice::Simple(Cow::Borrowed(ADMIN_PASSWORD.as_bytes())),
        ),
    )
    .await;
    assert_eq!(success.result.result_code, ParserResultCode::Success);

    let invalid = bind_response(
        &backend,
        12,
        bind_request(
            ADMIN_DN,
            AuthenticationChoice::Simple(Cow::Borrowed(WRONG_PASSWORD.as_bytes())),
        ),
    )
    .await;
    assert_eq!(
        invalid.result.result_code,
        ParserResultCode::InvalidCredentials
    );
    assert_eq!(
        invalid.result.diagnostic_message.0.as_ref(),
        "invalid credentials"
    );
    assert!(
        !invalid.result.diagnostic_message.0.contains(WRONG_PASSWORD),
        "Bind diagnostics must not echo client credentials"
    );

    let anonymous = bind_response(
        &backend,
        13,
        bind_request("", AuthenticationChoice::Simple(Cow::Borrowed(b""))),
    )
    .await;
    assert_eq!(anonymous.result.result_code, ParserResultCode::Success);
}

#[tokio::test]
async fn sasl_plain_over_insecure_transport_is_rejected_before_credentials_are_used() {
    let backend = MockBackend::from_credentials(vec![(
        ADMIN_DN.to_string(),
        SASL_SECRET.as_bytes().to_vec(),
    )]);

    let response =
        bind_response(&backend, 21, sasl_plain_bind_request(ADMIN_DN, SASL_SECRET)).await;

    assert_eq!(
        response.result.result_code,
        ParserResultCode::ConfidentialityRequired
    );
    assert_eq!(
        response.result.diagnostic_message.0.as_ref(),
        "SASL PLAIN requires TLS"
    );
    assert!(
        !response.result.diagnostic_message.0.contains(SASL_SECRET),
        "SASL diagnostics must not echo client credentials"
    );
}

#[tokio::test]
async fn sasl_plain_handler_supports_only_the_documented_confidentiality_bound_mechanism() {
    let handler = MultiMechanismHandler::new(Arc::new(StaticCredentialVerifier));

    assert!(handler.supports_mechanism("PLAIN").await);
    assert!(handler.supports_mechanism("plain").await);
    assert!(!handler.supports_mechanism("DIGEST-MD5").await);
    assert!(!handler.supports_mechanism("CRAM-MD5").await);
    assert!(!handler.supports_mechanism("GSSAPI").await);

    let properties = handler.get_mechanism_properties("PLAIN");
    assert_eq!(properties.get("steps").map(String::as_str), Some("1"));
    assert_eq!(
        properties.get("security").map(String::as_str),
        Some("requires-tls")
    );

    let result = handler
        .start_authentication("PLAIN", Some(format!("\0admin\0{SASL_SECRET}").as_bytes()))
        .await
        .unwrap();
    assert_eq!(
        result,
        SaslChallengeResult::Success {
            dn: ADMIN_DN.to_string()
        }
    );

    let result = handler
        .start_authentication(
            "plain",
            Some(format!("dn:{ADMIN_DN}\0admin\0{SASL_SECRET}").as_bytes()),
        )
        .await
        .unwrap();
    assert_eq!(
        result,
        SaslChallengeResult::Success {
            dn: ADMIN_DN.to_string()
        }
    );

    let result = handler
        .start_authentication(
            "PLAIN",
            Some(format!("u:admin\0admin\0{SASL_SECRET}").as_bytes()),
        )
        .await
        .unwrap();
    assert_eq!(
        result,
        SaslChallengeResult::Success {
            dn: ADMIN_DN.to_string()
        }
    );

    let result = handler
        .start_authentication(
            "PLAIN",
            Some(format!("dn:cn=other,dc=example,dc=org\0admin\0{SASL_SECRET}").as_bytes()),
        )
        .await
        .unwrap();
    assert!(
        matches!(result, SaslChallengeResult::Failure(reason) if reason == "proxy authorization is not supported")
    );

    let result = handler
        .start_authentication("PLAIN", Some(b"\0admin\0wrong"))
        .await
        .unwrap();
    assert!(
        matches!(result, SaslChallengeResult::Failure(reason) if reason == "Invalid credentials")
    );

    assert!(
        handler
            .start_authentication("DIGEST-MD5", Some(b"proof"))
            .await
            .unwrap_err()
            .contains("not production-supported")
    );
}

#[tokio::test]
async fn root_dse_advertises_starttls_and_sasl_plain_only_for_appropriate_security_contexts() {
    let backend = MockBackend::new();
    let registry = active_fsm_control_registry();

    let insecure_attributes = build_root_dse_attributes(
        &backend,
        &["dc=example,dc=org".to_string()],
        "cn=Subschema",
        false,
        true,
        &registry.root_dse_supported_control_oids(),
        &supported_legacy_sasl_mechanisms_for_context(false),
    )
    .await
    .unwrap();
    let insecure_attributes = attrs_to_map(insecure_attributes);
    assert!(
        insecure_attributes
            .get("supportedExtension")
            .unwrap()
            .contains(&oids::START_TLS.to_string())
    );
    assert!(
        !insecure_attributes.contains_key("supportedSASLMechanisms"),
        "SASL PLAIN must not be advertised before transport confidentiality is active"
    );

    let secure_attributes = build_root_dse_attributes(
        &backend,
        &["dc=example,dc=org".to_string()],
        "cn=Subschema",
        true,
        true,
        &registry.root_dse_supported_control_oids(),
        &supported_legacy_sasl_mechanisms_for_context(true),
    )
    .await
    .unwrap();
    let secure_attributes = attrs_to_map(secure_attributes);
    assert!(
        !secure_attributes
            .get("supportedExtension")
            .unwrap()
            .contains(&oids::START_TLS.to_string()),
        "StartTLS must not be advertised once the connection is already secure"
    );
    assert_eq!(
        secure_attributes.get("supportedSASLMechanisms").unwrap(),
        &vec!["PLAIN".to_string()]
    );

    assert_eq!(
        supported_legacy_sasl_mechanisms_for_effective_security(
            &EffectiveSecurityContext::new(true, Some("cn=admin,dc=example,dc=org".to_string())),
            SaslMechanismPolicy::default(),
        ),
        vec!["PLAIN".to_string(), "EXTERNAL".to_string()]
    );
}

struct StaticCredentialVerifier;

#[async_trait]
impl CredentialVerifier for StaticCredentialVerifier {
    async fn verify_credentials(
        &self,
        mechanism: &str,
        identity: &str,
        credential: &[u8],
    ) -> Result<bool, String> {
        Ok(mechanism == "PLAIN" && identity == "admin" && credential == SASL_SECRET.as_bytes())
    }

    async fn get_user_dn(&self, identity: &str) -> Result<Option<String>, String> {
        Ok((identity == "admin").then(|| ADMIN_DN.to_string()))
    }
}

async fn bind_response(
    backend: &MockBackend,
    message_id: u32,
    request: BindRequest<'static>,
) -> ldap_parser::ldap::BindResponse<'static> {
    let (mut server_stream, mut client_stream) = connected_stream_pair().await;
    server::handle_bind_request(&mut server_stream, backend, message_id, request)
        .await
        .unwrap();

    let messages = read_ldap_response(&mut client_stream).await;
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].message_id.0, message_id);
    match &messages[0].protocol_op {
        ProtocolOp::BindResponse(response) => response.to_static(),
        other => panic!("unexpected bind response: {other:?}"),
    }
}

async fn connected_stream_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
    let (server_stream, _) = listener.accept().await.unwrap();
    let client_stream = client.await.unwrap();
    (server_stream, client_stream)
}

async fn read_ldap_response(stream: &mut TcpStream) -> Vec<LdapMessage<'static>> {
    let mut response = Vec::new();
    let mut buf = vec![0u8; 4096];

    loop {
        match timeout(RESPONSE_TIMEOUT, stream.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(len)) => response.extend_from_slice(&buf[..len]),
            Ok(Err(err)) => panic!("failed to read response: {err}"),
            Err(_) if !response.is_empty() => break,
            Err(_) => panic!("response timeout"),
        }
    }

    let (_, messages) = parse_ldap_messages(&response).unwrap();
    messages
        .into_iter()
        .map(|message| message.to_static())
        .collect()
}

fn bind_request(
    dn: &'static str,
    authentication: AuthenticationChoice<'static>,
) -> BindRequest<'static> {
    BindRequest {
        version: 3,
        name: LdapDN(Cow::Borrowed(dn)),
        authentication,
    }
}

fn sasl_plain_bind_request(dn: &'static str, password: &'static str) -> BindRequest<'static> {
    bind_request(
        dn,
        AuthenticationChoice::Sasl(SaslCredentials {
            mechanism: LdapString(Cow::Borrowed("PLAIN")),
            credentials: Some(Cow::Owned(format!("\0{dn}\0{password}").into_bytes())),
        }),
    )
}

fn attrs_to_map(attributes: Vec<(String, Vec<String>)>) -> HashMap<String, Vec<String>> {
    attributes.into_iter().collect()
}

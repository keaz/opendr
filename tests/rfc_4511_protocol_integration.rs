use std::borrow::Cow;
use std::collections::HashMap;
use std::time::Duration;

use ldap_parser::asn1_rs::ToStatic;
use ldap_parser::filter::{
    Attribute as FilterAttribute, AttributeValue, AttributeValueAssertion, Filter, PartialAttribute,
};
use ldap_parser::ldap::{
    AddRequest, AuthenticationChoice, BindRequest, Change, CompareRequest, Control, DerefAliases,
    ExtendedRequest, LdapDN, LdapMessage, LdapOID, LdapString, MessageID, ModDnRequest,
    ModifyRequest, Operation, ProtocolOp, RelativeLdapDN, ResultCode as ParserResultCode,
    SearchRequest, SearchScope,
};
use ldap_parser::parse_ldap_messages;
use opendr::backend::{DirectoryBackend, DirectoryEntry, MockBackend};
use opendr::fsm_request::{FsmRequestKind, FsmResponseKind, build_request_context};
use opendr::parser::ResponseOp;
use opendr::schema::LdapSchema;
use opendr::search_controls::{
    PAGED_RESULTS_OID, SERVER_SIDE_SORT_REQUEST_OID, SUBENTRIES_CONTROL_OID,
};
use opendr::server;
use opendr::sync_controls::SYNC_REQUEST_OID;
use rasn_ldap::ResultCode as RasnResultCode;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const RESPONSE_TIMEOUT: Duration = Duration::from_millis(200);
const MANAGE_DSA_IT_OID: &str = "2.16.840.1.113730.3.4.2";
const ASSERTION_CONTROL_OID: &str = "1.3.6.1.1.12";
const SERVER_SIDE_SORT_RESPONSE_OID: &str = "1.2.840.113556.1.4.474";

#[test]
fn request_context_maps_rfc_4511_operations_to_response_kinds() {
    let cases = [
        (
            ldap_message(ProtocolOp::BindRequest(bind_request("cn=admin", b"secret"))),
            FsmRequestKind::Bind,
            FsmResponseKind::Bind,
            false,
        ),
        (
            ldap_message(ProtocolOp::SearchRequest(search_request())),
            FsmRequestKind::Search,
            FsmResponseKind::Result(ResponseOp::SearchDone),
            true,
        ),
        (
            ldap_message(ProtocolOp::ModifyRequest(modify_request())),
            FsmRequestKind::Modify,
            FsmResponseKind::Result(ResponseOp::Modify),
            true,
        ),
        (
            ldap_message(ProtocolOp::AddRequest(add_request(
                "cn=Alice,dc=example,dc=org",
            ))),
            FsmRequestKind::Add,
            FsmResponseKind::Result(ResponseOp::Add),
            true,
        ),
        (
            ldap_message(ProtocolOp::DelRequest(LdapDN(Cow::Borrowed(
                "cn=Alice,dc=example,dc=org",
            )))),
            FsmRequestKind::Delete,
            FsmResponseKind::Result(ResponseOp::Delete),
            true,
        ),
        (
            ldap_message(ProtocolOp::ModDnRequest(moddn_request())),
            FsmRequestKind::ModifyDn,
            FsmResponseKind::Result(ResponseOp::ModifyDn),
            true,
        ),
        (
            ldap_message(ProtocolOp::CompareRequest(compare_request(
                "cn=Alice,dc=example,dc=org",
                "Alice",
            ))),
            FsmRequestKind::Compare,
            FsmResponseKind::Result(ResponseOp::Compare),
            true,
        ),
        (
            ldap_message(ProtocolOp::ExtendedRequest(ExtendedRequest {
                request_name: LdapOID(Cow::Borrowed("1.2.3.4")),
                request_value: None,
            })),
            FsmRequestKind::Extended,
            FsmResponseKind::Result(ResponseOp::Extended),
            true,
        ),
        (
            ldap_message(ProtocolOp::AbandonRequest(MessageID(44))),
            FsmRequestKind::Abandon,
            FsmResponseKind::None,
            false,
        ),
        (
            ldap_message(ProtocolOp::UnbindRequest),
            FsmRequestKind::Unbind,
            FsmResponseKind::None,
            false,
        ),
    ];

    for (message, expected_kind, expected_response, expected_slot) in cases {
        let context = build_request_context(&message, 77, None, Some("cn=admin"), true).unwrap();

        assert_eq!(context.message_id, 10);
        assert_eq!(context.request_kind, expected_kind);
        assert_eq!(context.response_kind, expected_response);
        assert_eq!(context.requires_operation_slot(), expected_slot);
    }
}

#[test]
fn request_context_applies_rfc_4511_control_criticality_semantics() {
    let accepted = ldap_message_with_controls(
        ProtocolOp::SearchRequest(search_request()),
        vec![
            control(PAGED_RESULTS_OID, false),
            control(SERVER_SIDE_SORT_REQUEST_OID, false),
            control(SUBENTRIES_CONTROL_OID, false),
            control(MANAGE_DSA_IT_OID, false),
            control(SYNC_REQUEST_OID, false),
        ],
    );
    let context = build_request_context(&accepted, 1, None, None, false).unwrap();
    assert_eq!(context.request_controls.len(), 5);

    for unsupported_oid in [ASSERTION_CONTROL_OID, SERVER_SIDE_SORT_RESPONSE_OID] {
        let critical = ldap_message_with_controls(
            ProtocolOp::SearchRequest(search_request()),
            vec![control(unsupported_oid, true)],
        );
        let rejection = build_request_context(&critical, 1, None, None, false).unwrap_err();
        assert_eq!(
            rejection.result_code,
            RasnResultCode::UnavailableCriticalExtension
        );
        assert!(
            rejection.diagnostic_message.contains(unsupported_oid),
            "diagnostic should identify rejected control OID"
        );

        let non_critical = ldap_message_with_controls(
            ProtocolOp::SearchRequest(search_request()),
            vec![control(unsupported_oid, false)],
        );
        let context = build_request_context(&non_critical, 1, None, None, false).unwrap();
        assert!(
            context.request_controls.is_empty(),
            "unsupported non-critical controls are ignored"
        );
    }
}

#[test]
fn malformed_ber_messages_return_parse_errors_without_panicking() {
    let malformed_messages = [
        &[0xff][..],
        &[0x30, 0x03, 0x02][..],
        &[0x30, 0x05, 0x02, 0x01, 0x01, 0x7f, 0x00][..],
    ];

    for malformed in malformed_messages {
        assert!(
            std::panic::catch_unwind(
                || parse_ldap_messages(malformed).map(|(_, messages)| messages)
            )
            .unwrap()
            .is_err(),
            "malformed BER should return a parser error"
        );
    }
}

#[tokio::test]
async fn simple_bind_invalid_credentials_returns_invalid_credentials() {
    let backend = MockBackend::new();
    let (mut server_stream, mut client_stream) = connected_stream_pair().await;

    server::handle_bind_request(
        &mut server_stream,
        &backend,
        41,
        bind_request("cn=missing,dc=example,dc=org", b"wrong"),
    )
    .await
    .unwrap();

    let messages = read_ldap_response(&mut client_stream).await;
    assert_eq!(messages[0].message_id.0, 41);
    match &messages[0].protocol_op {
        ProtocolOp::BindResponse(response) => {
            assert_eq!(
                response.result.result_code,
                ParserResultCode::InvalidCredentials
            );
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn write_handlers_return_representative_rfc_4511_result_codes() {
    let backend = MockBackend::new();
    let schema = LdapSchema::with_core_schema();
    backend
        .add_entry(person_entry("cn=Alice,dc=example,dc=org"), Vec::new())
        .await
        .unwrap();

    let (mut server_stream, mut client_stream) = connected_stream_pair().await;
    server::handle_add_request(
        &mut server_stream,
        &backend,
        &schema,
        51,
        add_request("cn=Alice,dc=example,dc=org"),
    )
    .await
    .unwrap();
    assert_single_result_code(&mut client_stream, 51, |op| match op {
        ProtocolOp::AddResponse(result) => result.result_code,
        other => panic!("unexpected add response: {other:?}"),
    })
    .await
    .assert_code(ParserResultCode::EntryAlreadyExists);

    let (mut server_stream, mut client_stream) = connected_stream_pair().await;
    server::handle_modify_request(&mut server_stream, &backend, 52, modify_request())
        .await
        .unwrap();
    assert_single_result_code(&mut client_stream, 52, |op| match op {
        ProtocolOp::ModifyResponse(response) => response.result.result_code,
        other => panic!("unexpected modify response: {other:?}"),
    })
    .await
    .assert_code(ParserResultCode::NoSuchObject);

    let (mut server_stream, mut client_stream) = connected_stream_pair().await;
    server::handle_delete_request(
        &mut server_stream,
        &backend,
        53,
        LdapDN(Cow::Borrowed("cn=Missing,dc=example,dc=org")),
    )
    .await
    .unwrap();
    assert_single_result_code(&mut client_stream, 53, |op| match op {
        ProtocolOp::DelResponse(result) => result.result_code,
        other => panic!("unexpected delete response: {other:?}"),
    })
    .await
    .assert_code(ParserResultCode::NoSuchObject);
}

#[tokio::test]
async fn compare_and_extended_handlers_return_rfc_4511_result_codes() {
    let backend = MockBackend::new();
    backend
        .add_entry(person_entry("cn=Alice,dc=example,dc=org"), Vec::new())
        .await
        .unwrap();

    let (mut server_stream, mut client_stream) = connected_stream_pair().await;
    server::handle_compare_request(
        &mut server_stream,
        &backend,
        61,
        compare_request("cn=Alice,dc=example,dc=org", "Alice"),
    )
    .await
    .unwrap();
    assert_single_result_code(&mut client_stream, 61, |op| match op {
        ProtocolOp::CompareResponse(result) => result.result_code,
        other => panic!("unexpected compare response: {other:?}"),
    })
    .await
    .assert_code(ParserResultCode::CompareTrue);

    let (mut server_stream, mut client_stream) = connected_stream_pair().await;
    server::handle_compare_request(
        &mut server_stream,
        &backend,
        62,
        compare_request("cn=Alice,dc=example,dc=org", "Bob"),
    )
    .await
    .unwrap();
    assert_single_result_code(&mut client_stream, 62, |op| match op {
        ProtocolOp::CompareResponse(result) => result.result_code,
        other => panic!("unexpected compare response: {other:?}"),
    })
    .await
    .assert_code(ParserResultCode::CompareFalse);

    let (server_stream, mut client_stream) = connected_stream_pair().await;
    let mut server_stream = server::ConnectionStream::Plain(server_stream);
    server::handle_extended_request(
        &mut server_stream,
        63,
        ExtendedRequest {
            request_name: LdapOID(Cow::Borrowed("1.2.3.4")),
            request_value: None,
        },
    )
    .await
    .unwrap();
    assert_single_result_code(&mut client_stream, 63, |op| match op {
        ProtocolOp::ExtendedResponse(response) => response.result.result_code,
        other => panic!("unexpected extended response: {other:?}"),
    })
    .await
    .assert_code(ParserResultCode::ProtocolError);
}

struct ResultCodeAssertion {
    actual: ParserResultCode,
}

impl ResultCodeAssertion {
    fn assert_code(self, expected: ParserResultCode) {
        assert_eq!(self.actual, expected);
    }
}

async fn assert_single_result_code(
    stream: &mut TcpStream,
    expected_message_id: u32,
    extractor: impl FnOnce(&ProtocolOp<'_>) -> ParserResultCode,
) -> ResultCodeAssertion {
    let messages = read_ldap_response(stream).await;
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].message_id.0, expected_message_id);
    ResultCodeAssertion {
        actual: extractor(&messages[0].protocol_op),
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

fn ldap_message(protocol_op: ProtocolOp<'static>) -> LdapMessage<'static> {
    LdapMessage {
        message_id: MessageID(10),
        protocol_op,
        controls: None,
    }
}

fn ldap_message_with_controls(
    protocol_op: ProtocolOp<'static>,
    controls: Vec<Control<'static>>,
) -> LdapMessage<'static> {
    LdapMessage {
        message_id: MessageID(10),
        protocol_op,
        controls: Some(controls.into_iter().collect()),
    }
}

fn control(oid: &'static str, criticality: bool) -> Control<'static> {
    Control {
        control_type: LdapOID(Cow::Borrowed(oid)),
        criticality,
        control_value: None,
    }
}

fn bind_request(dn: &'static str, password: &'static [u8]) -> BindRequest<'static> {
    BindRequest {
        version: 3,
        name: LdapDN(Cow::Borrowed(dn)),
        authentication: AuthenticationChoice::Simple(Cow::Borrowed(password)),
    }
}

fn search_request() -> SearchRequest<'static> {
    SearchRequest {
        base_object: LdapDN(Cow::Borrowed("dc=example,dc=org")),
        scope: SearchScope(2),
        deref_aliases: DerefAliases(0),
        size_limit: 0,
        time_limit: 0,
        types_only: false,
        filter: Filter::Present(LdapString(Cow::Borrowed("objectClass"))),
        attributes: vec![LdapString(Cow::Borrowed("cn"))],
    }
}

fn modify_request() -> ModifyRequest<'static> {
    ModifyRequest {
        object: LdapDN(Cow::Borrowed("cn=Missing,dc=example,dc=org")),
        changes: vec![Change {
            operation: Operation(2),
            modification: PartialAttribute {
                attr_type: LdapString(Cow::Borrowed("cn")),
                attr_vals: vec![AttributeValue(Cow::Borrowed(b"Updated"))],
            },
        }],
    }
}

fn add_request(dn: &'static str) -> AddRequest<'static> {
    AddRequest {
        entry: LdapDN(Cow::Borrowed(dn)),
        attributes: person_add_attributes(),
    }
}

fn moddn_request() -> ModDnRequest<'static> {
    ModDnRequest {
        entry: LdapDN(Cow::Borrowed("cn=Alice,dc=example,dc=org")),
        newrdn: RelativeLdapDN(Cow::Borrowed("cn=Bob")),
        deleteoldrdn: true,
        newsuperior: None,
    }
}

fn compare_request(dn: &'static str, assertion: &'static str) -> CompareRequest<'static> {
    CompareRequest {
        entry: LdapDN(Cow::Borrowed(dn)),
        ava: AttributeValueAssertion {
            attribute_desc: LdapString(Cow::Borrowed("cn")),
            assertion_value: Cow::Borrowed(assertion.as_bytes()),
        },
    }
}

fn person_entry(dn: &str) -> DirectoryEntry {
    DirectoryEntry::new(
        dn,
        HashMap::from([
            (
                "objectClass".to_string(),
                vec!["top".to_string(), "person".to_string()],
            ),
            ("cn".to_string(), vec!["Alice".to_string()]),
            ("sn".to_string(), vec!["Example".to_string()]),
        ]),
    )
}

fn person_add_attributes() -> Vec<FilterAttribute<'static>> {
    vec![
        FilterAttribute {
            attr_type: LdapString(Cow::Borrowed("objectClass")),
            attr_vals: vec![
                AttributeValue(Cow::Borrowed(b"top")),
                AttributeValue(Cow::Borrowed(b"person")),
            ],
        },
        FilterAttribute {
            attr_type: LdapString(Cow::Borrowed("cn")),
            attr_vals: vec![AttributeValue(Cow::Borrowed(b"Alice"))],
        },
        FilterAttribute {
            attr_type: LdapString(Cow::Borrowed("sn")),
            attr_vals: vec![AttributeValue(Cow::Borrowed(b"Example"))],
        },
    ]
}

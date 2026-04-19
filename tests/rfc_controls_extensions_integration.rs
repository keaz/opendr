use std::borrow::Cow;
use std::collections::HashMap;
use std::time::Duration;

use ldap_parser::asn1_rs::ToStatic;
use ldap_parser::filter::Filter;
use ldap_parser::ldap::{
    Control, DerefAliases, ExtendedRequest, ExtendedResponse, LdapDN, LdapMessage, LdapOID,
    LdapString, MessageID, ProtocolOp, ResultCode as ParserResultCode, SearchRequest, SearchScope,
};
use ldap_parser::parse_ldap_messages;
use opendr::backend::MockBackend;
use opendr::extended_ops::encode_cancel_request_value;
use opendr::fsm_request::active_fsm_control_registry;
use opendr::fsm_request::build_request_context;
use opendr::search_controls::{
    PAGED_RESULTS_OID, PagedResultsControl, SERVER_SIDE_SORT_REQUEST_OID,
    SERVER_SIDE_SORT_RESPONSE_OID, SUBENTRIES_CONTROL_OID, ServerSideSortRequestControl, SortKey,
    decode_paged_results_control, decode_server_side_sort_request_control,
    encode_paged_results_control, encode_server_side_sort_request_control,
    encode_subentries_control,
};
use opendr::search_protocol::{
    MODIFY_INCREMENT_FEATURE_OID, REQUEST_ATTRIBUTES_BY_OBJECT_CLASS_FEATURE_OID,
    build_root_dse_attributes,
};
use opendr::server;
use opendr::sync_controls::{
    SYNC_DONE_OID, SYNC_REQUEST_OID, SYNC_STATE_OID, SyncRefreshMode, SyncRequestControl,
    decode_sync_request_control, encode_sync_request_control,
};
use rasn_ldap::ResultCode as RasnResultCode;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const RESPONSE_TIMEOUT: Duration = Duration::from_millis(200);
const MANAGE_DSA_IT_OID: &str = "2.16.840.1.113730.3.4.2";
const START_TLS_OID: &str = "1.3.6.1.4.1.1466.20037";
const CANCEL_OID: &str = "1.3.6.1.1.8";
const PASSWORD_MODIFY_OID: &str = "1.3.6.1.4.1.4203.1.11.1";
const WHO_AM_I_OID: &str = "1.3.6.1.4.1.4203.1.11.3";
const ASSERTION_CONTROL_OID: &str = "1.3.6.1.1.12";
const PRE_READ_CONTROL_OID: &str = "1.3.6.1.1.13.1";
const POST_READ_CONTROL_OID: &str = "1.3.6.1.1.13.2";

#[tokio::test]
async fn root_dse_advertises_only_request_usable_controls_extensions_and_features() {
    let backend = MockBackend::new();
    let registry = active_fsm_control_registry();

    let attributes = build_root_dse_attributes(
        &backend,
        &["dc=example,dc=org".to_string()],
        "cn=Subschema",
        false,
        true,
        &registry.root_dse_supported_control_oids(),
        &[],
    )
    .await
    .unwrap();
    let attributes = attrs_to_map(attributes);

    assert_eq!(
        sorted(attributes.get("supportedControl").unwrap()),
        sorted(&[
            MANAGE_DSA_IT_OID.to_string(),
            PAGED_RESULTS_OID.to_string(),
            SERVER_SIDE_SORT_REQUEST_OID.to_string(),
            SUBENTRIES_CONTROL_OID.to_string(),
            SYNC_REQUEST_OID.to_string(),
        ])
    );
    for unadvertised_control in [
        SERVER_SIDE_SORT_RESPONSE_OID,
        SYNC_STATE_OID,
        SYNC_DONE_OID,
        ASSERTION_CONTROL_OID,
        PRE_READ_CONTROL_OID,
        POST_READ_CONTROL_OID,
    ] {
        assert!(
            !attributes
                .get("supportedControl")
                .unwrap()
                .contains(&unadvertised_control.to_string()),
            "Root DSE must not advertise unsupported or response-only control {unadvertised_control}"
        );
    }

    assert_eq!(
        sorted(attributes.get("supportedExtension").unwrap()),
        sorted(&[
            START_TLS_OID.to_string(),
            CANCEL_OID.to_string(),
            PASSWORD_MODIFY_OID.to_string(),
            WHO_AM_I_OID.to_string(),
        ])
    );
    assert_eq!(
        sorted(attributes.get("supportedFeatures").unwrap()),
        sorted(&[
            MODIFY_INCREMENT_FEATURE_OID.to_string(),
            REQUEST_ATTRIBUTES_BY_OBJECT_CLASS_FEATURE_OID.to_string(),
        ])
    );

    let secure_attributes = build_root_dse_attributes(
        &backend,
        &["dc=example,dc=org".to_string()],
        "cn=Subschema",
        true,
        true,
        &registry.root_dse_supported_control_oids(),
        &[],
    )
    .await
    .unwrap();
    let secure_attributes = attrs_to_map(secure_attributes);
    assert!(
        !secure_attributes
            .get("supportedExtension")
            .unwrap()
            .contains(&START_TLS_OID.to_string()),
        "StartTLS is only advertised before confidentiality is already active"
    );
}

#[test]
fn control_registry_separates_request_response_and_root_dse_oids() {
    let registry = active_fsm_control_registry();

    let request_oids = registry.supported_request_control_oids();
    assert_eq!(
        request_oids,
        sorted(&[
            MANAGE_DSA_IT_OID.to_string(),
            PAGED_RESULTS_OID.to_string(),
            SERVER_SIDE_SORT_REQUEST_OID.to_string(),
            SUBENTRIES_CONTROL_OID.to_string(),
            SYNC_REQUEST_OID.to_string(),
        ])
    );

    let response_oids = registry.supported_response_control_oids();
    assert_eq!(
        response_oids,
        sorted(&[
            PAGED_RESULTS_OID.to_string(),
            SERVER_SIDE_SORT_RESPONSE_OID.to_string(),
            SYNC_STATE_OID.to_string(),
            SYNC_DONE_OID.to_string(),
        ])
    );

    assert_eq!(registry.root_dse_supported_control_oids(), request_oids);
    assert!(!registry.supports_request_control(SERVER_SIDE_SORT_RESPONSE_OID));
    assert!(!registry.supports_request_control(SYNC_STATE_OID));
    assert!(!registry.supports_request_control(SYNC_DONE_OID));
}

#[test]
fn advertised_request_control_codecs_round_trip_positive_values() {
    let paged_value = encode_paged_results_control(250, b"opaque-cookie").unwrap();
    assert_eq!(
        decode_paged_results_control(Some(&paged_value)).unwrap(),
        PagedResultsControl {
            size: 250,
            cookie: b"opaque-cookie".to_vec(),
        }
    );

    let sort_value = encode_server_side_sort_request_control(&[
        SortKey {
            attribute_type: "sn".to_string(),
            ordering_rule: None,
            reverse_order: false,
        },
        SortKey {
            attribute_type: "givenName".to_string(),
            ordering_rule: Some("caseIgnoreOrderingMatch".to_string()),
            reverse_order: true,
        },
    ])
    .unwrap();
    assert_eq!(
        decode_server_side_sort_request_control(Some(&sort_value)).unwrap(),
        ServerSideSortRequestControl {
            keys: vec![
                SortKey {
                    attribute_type: "sn".to_string(),
                    ordering_rule: None,
                    reverse_order: false,
                },
                SortKey {
                    attribute_type: "givenName".to_string(),
                    ordering_rule: Some("caseIgnoreOrderingMatch".to_string()),
                    reverse_order: true,
                },
            ],
        }
    );

    let sync_value = encode_sync_request_control(&SyncRequestControl {
        mode: SyncRefreshMode::RefreshOnly,
        cookie: Some(b"csn-cookie".to_vec()),
        reload_hint: true,
    })
    .unwrap();
    assert_eq!(
        decode_sync_request_control(Some(&sync_value)).unwrap(),
        SyncRequestControl {
            mode: SyncRefreshMode::RefreshOnly,
            cookie: Some(b"csn-cookie".to_vec()),
            reload_hint: true,
        }
    );
}

#[test]
fn supported_request_controls_are_accepted_by_shared_request_pipeline() {
    let paged_value = encode_paged_results_control(100, b"").unwrap();
    let sort_value = encode_server_side_sort_request_control(&[SortKey {
        attribute_type: "cn".to_string(),
        ordering_rule: None,
        reverse_order: false,
    }])
    .unwrap();
    let sync_value = encode_sync_request_control(&SyncRequestControl {
        mode: SyncRefreshMode::RefreshOnly,
        cookie: None,
        reload_hint: false,
    })
    .unwrap();
    let subentries_value = encode_subentries_control(true).unwrap();

    let message = ldap_message_with_controls(vec![
        control_with_value(PAGED_RESULTS_OID, false, Some(paged_value)),
        control_with_value(SERVER_SIDE_SORT_REQUEST_OID, false, Some(sort_value)),
        control_with_value(SUBENTRIES_CONTROL_OID, false, Some(subentries_value)),
        control_with_value(MANAGE_DSA_IT_OID, false, None),
        control_with_value(SYNC_REQUEST_OID, false, Some(sync_value)),
    ]);

    let context = build_request_context(&message, 77, None, Some("cn=admin"), true).unwrap();
    assert_eq!(context.request_controls.len(), 5);
    assert_eq!(
        context
            .request_controls
            .iter()
            .map(|control| control.oid().to_string())
            .collect::<Vec<_>>(),
        vec![
            PAGED_RESULTS_OID.to_string(),
            SERVER_SIDE_SORT_REQUEST_OID.to_string(),
            SUBENTRIES_CONTROL_OID.to_string(),
            MANAGE_DSA_IT_OID.to_string(),
            SYNC_REQUEST_OID.to_string(),
        ]
    );
}

#[test]
fn unsupported_or_response_only_controls_follow_rfc_4511_criticality_semantics() {
    for oid in [
        SERVER_SIDE_SORT_RESPONSE_OID,
        SYNC_STATE_OID,
        SYNC_DONE_OID,
        ASSERTION_CONTROL_OID,
        PRE_READ_CONTROL_OID,
        POST_READ_CONTROL_OID,
        REQUEST_ATTRIBUTES_BY_OBJECT_CLASS_FEATURE_OID,
    ] {
        let critical = ldap_message_with_controls(vec![control_with_value(oid, true, None)]);
        let rejection = build_request_context(&critical, 1, None, None, false).unwrap_err();
        assert_eq!(
            rejection.result_code,
            RasnResultCode::UnavailableCriticalExtension
        );
        assert!(rejection.diagnostic_message.contains(oid));

        let non_critical = ldap_message_with_controls(vec![control_with_value(oid, false, None)]);
        let context = build_request_context(&non_critical, 1, None, None, false).unwrap();
        assert!(
            context.request_controls.is_empty(),
            "unsupported non-critical control {oid} should be ignored"
        );
    }
}

#[tokio::test]
async fn advertised_extended_operations_return_rfc_result_codes() {
    let whoami = send_extended_request(21, WHO_AM_I_OID, None).await;
    assert_eq!(whoami.result.result_code, ParserResultCode::Success);
    assert_eq!(
        whoami.response_name.as_ref().map(|oid| oid.0.as_ref()),
        Some(WHO_AM_I_OID)
    );
    assert_eq!(whoami.response_value.as_deref(), Some(&[][..]));

    let starttls = send_extended_request(22, START_TLS_OID, None).await;
    assert_eq!(starttls.result.result_code, ParserResultCode::Unavailable);
    assert!(
        starttls
            .result
            .diagnostic_message
            .0
            .contains("StartTLS is not available")
    );

    let password_modify = send_extended_request(23, PASSWORD_MODIFY_OID, None).await;
    assert_eq!(
        password_modify.result.result_code,
        ParserResultCode::ConfidentialityRequired
    );

    let cancel_value = encode_cancel_request_value(777).unwrap();
    let cancel = send_extended_request(24, CANCEL_OID, Some(cancel_value)).await;
    assert_eq!(cancel.result.result_code, ParserResultCode(119));
    assert!(
        cancel
            .result
            .diagnostic_message
            .0
            .contains("no such operation")
    );

    let malformed_cancel = send_extended_request(25, CANCEL_OID, Some(b"bad".to_vec())).await;
    assert_eq!(
        malformed_cancel.result.result_code,
        ParserResultCode::ProtocolError
    );
}

async fn send_extended_request(
    message_id: u32,
    oid: &'static str,
    value: Option<Vec<u8>>,
) -> ExtendedResponse<'static> {
    let (server_stream, mut client_stream) = connected_stream_pair().await;
    let mut server_stream = server::ConnectionStream::Plain(server_stream);
    server::handle_extended_request(
        &mut server_stream,
        message_id,
        ExtendedRequest {
            request_name: LdapOID(Cow::Borrowed(oid)),
            request_value: value.map(Cow::Owned),
        },
    )
    .await
    .unwrap();

    let messages = read_ldap_response(&mut client_stream).await;
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].message_id.0, message_id);
    match &messages[0].protocol_op {
        ProtocolOp::ExtendedResponse(response) => response.to_static(),
        other => panic!("unexpected extended response: {other:?}"),
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

fn ldap_message_with_controls(controls: Vec<Control<'static>>) -> LdapMessage<'static> {
    LdapMessage {
        message_id: MessageID(10),
        protocol_op: ProtocolOp::SearchRequest(search_request()),
        controls: Some(controls.into_iter().collect()),
    }
}

fn control_with_value(
    oid: &'static str,
    criticality: bool,
    value: Option<Vec<u8>>,
) -> Control<'static> {
    Control {
        control_type: LdapOID(Cow::Borrowed(oid)),
        criticality,
        control_value: value.map(Cow::Owned),
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

fn attrs_to_map(attributes: Vec<(String, Vec<String>)>) -> HashMap<String, Vec<String>> {
    attributes.into_iter().collect()
}

fn sorted(values: &[String]) -> Vec<String> {
    let mut values = values.to_vec();
    values.sort();
    values
}

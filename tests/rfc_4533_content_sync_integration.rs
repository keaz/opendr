use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use ldap_parser::asn1_rs::ToStatic;
use ldap_parser::filter::Filter;
use ldap_parser::ldap::{
    DerefAliases, LdapDN, LdapMessage, LdapString, ProtocolOp, ResultCode as ParserResultCode,
    SearchRequest, SearchScope,
};
use ldap_parser::parse_ldap_messages;
use opendr::backend::{DirectoryBackend, DirectoryEntry, MockBackend};
use opendr::config::ServerConfig;
use opendr::ldap_controls::{LdapControl, RequestControls};
use opendr::replication_service::ReplicationService;
use opendr::server;
use opendr::sync_controls::{
    SYNC_DONE_OID, SYNC_INFO_OID, SYNC_REQUEST_OID, SYNC_STATE_OID, SyncDoneControl, SyncInfoValue,
    SyncRefreshMode, SyncRequestControl, SyncStateControl, SyncStateType, decode_sync_done_control,
    decode_sync_info_value, decode_sync_request_control, decode_sync_state_control,
    encode_sync_done_control, encode_sync_info_value, encode_sync_request_control,
    encode_sync_state_control,
};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use uuid::Uuid;

const RESPONSE_TIMEOUT: Duration = Duration::from_secs(2);

#[test]
fn content_sync_oids_match_rfc_4533_assignments() {
    assert_eq!(SYNC_REQUEST_OID, "1.3.6.1.4.1.4203.1.9.1.1");
    assert_eq!(SYNC_STATE_OID, "1.3.6.1.4.1.4203.1.9.1.2");
    assert_eq!(SYNC_DONE_OID, "1.3.6.1.4.1.4203.1.9.1.3");
    assert_eq!(SYNC_INFO_OID, "1.3.6.1.4.1.4203.1.9.1.4");
}

#[test]
fn content_sync_controls_round_trip_supported_payloads() {
    for mode in [
        SyncRefreshMode::RefreshOnly,
        SyncRefreshMode::RefreshAndPersist,
    ] {
        let request = SyncRequestControl {
            mode,
            cookie: Some(b"csn-cookie".to_vec()),
            reload_hint: true,
        };
        let encoded = encode_sync_request_control(&request).unwrap();
        assert_eq!(
            decode_sync_request_control(Some(&encoded)).unwrap(),
            request
        );
    }

    let entry_uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
    for state in [
        SyncStateType::Present,
        SyncStateType::Add,
        SyncStateType::Modify,
        SyncStateType::Delete,
    ] {
        let control = SyncStateControl {
            state,
            entry_uuid,
            cookie: Some(b"state-cookie".to_vec()),
        };
        let encoded = encode_sync_state_control(&control).unwrap();
        assert_eq!(decode_sync_state_control(Some(&encoded)).unwrap(), control);
    }

    let done = SyncDoneControl {
        cookie: Some(b"done-cookie".to_vec()),
        refresh_deletes: true,
    };
    let encoded = encode_sync_done_control(&done).unwrap();
    assert_eq!(decode_sync_done_control(Some(&encoded)).unwrap(), done);
}

#[test]
fn sync_info_intermediate_values_round_trip_supported_refresh_phases() {
    let uuid_one = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
    let uuid_two = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440001").unwrap();
    let values = vec![
        SyncInfoValue::NewCookie(b"new-cookie".to_vec()),
        SyncInfoValue::RefreshDelete {
            cookie: Some(b"delete-cookie".to_vec()),
            refresh_done: false,
        },
        SyncInfoValue::RefreshPresent {
            cookie: Some(b"present-cookie".to_vec()),
            refresh_done: true,
        },
        SyncInfoValue::SyncIdSet {
            cookie: Some(b"idset-cookie".to_vec()),
            refresh_deletes: true,
            sync_uuids: vec![uuid_one, uuid_two],
        },
    ];

    for value in values {
        let encoded = encode_sync_info_value(&value).unwrap();
        assert_eq!(decode_sync_info_value(&encoded).unwrap(), value);
    }
}

#[test]
fn malformed_or_missing_sync_controls_are_rejected_by_codecs() {
    assert!(decode_sync_request_control(None).is_err());
    assert!(decode_sync_request_control(Some(b"not-ber")).is_err());
    assert!(decode_sync_state_control(None).is_err());
    assert!(decode_sync_done_control(Some(b"not-ber")).is_err());
    assert!(decode_sync_info_value(b"not-ber").is_err());
}

#[tokio::test]
async fn refresh_only_request_returns_present_entries_and_sync_done_cookie() {
    let provider_backend = provider_backend();
    provider_backend
        .add_entry(
            person_entry("cn=sync-user,dc=example,dc=org", "sync-user"),
            vec![],
        )
        .await
        .unwrap();

    let messages = run_sync_refresh_only_search(provider_backend.as_ref(), None).await;

    assert_eq!(messages.len(), 2);
    match &messages[0].protocol_op {
        ProtocolOp::SearchResultEntry(entry) => {
            assert_eq!(
                entry.object_name.0.as_ref(),
                "cn=sync-user,dc=example,dc=org"
            );
        }
        other => panic!("unexpected refresh entry response: {other:?}"),
    }
    assert_eq!(
        sync_state_response(&messages[0]).state,
        SyncStateType::Present
    );
    assert!(matches!(
        &messages[1].protocol_op,
        ProtocolOp::SearchResultDone(done) if done.result_code == ParserResultCode::Success
    ));

    let sync_done = sync_done_response(&messages[1]);
    assert!(!sync_done.refresh_deletes);
    assert!(
        String::from_utf8(sync_done.cookie.expect("sync done cookie"))
            .unwrap()
            .starts_with("csn-")
    );
}

#[tokio::test]
async fn refresh_only_cookie_replays_only_changes_after_the_cookie() {
    let provider_backend = provider_backend();
    provider_backend
        .add_entry(person_entry("cn=old,dc=example,dc=org", "old"), vec![])
        .await
        .unwrap();
    let resume_cookie = provider_backend
        .replication_changelog()
        .unwrap()
        .generate_context_cookie();
    provider_backend
        .add_entry(person_entry("cn=new,dc=example,dc=org", "new"), vec![])
        .await
        .unwrap();

    let messages =
        run_sync_refresh_only_search(provider_backend.as_ref(), Some(resume_cookie.as_bytes()))
            .await;

    assert_eq!(messages.len(), 2);
    match &messages[0].protocol_op {
        ProtocolOp::SearchResultEntry(entry) => {
            assert_eq!(entry.object_name.0.as_ref(), "cn=new,dc=example,dc=org");
        }
        other => panic!("unexpected incremental entry response: {other:?}"),
    }
    assert_eq!(sync_state_response(&messages[0]).state, SyncStateType::Add);
    assert!(matches!(
        &messages[1].protocol_op,
        ProtocolOp::SearchResultDone(done) if done.result_code == ParserResultCode::Success
    ));
}

#[tokio::test]
async fn refresh_only_request_rejects_malformed_cookie_without_implying_full_rfc_support() {
    let provider_backend = provider_backend();

    let messages =
        run_sync_refresh_only_search(provider_backend.as_ref(), Some(&[0xff, 0xfe])).await;

    assert_eq!(messages.len(), 1);
    match &messages[0].protocol_op {
        ProtocolOp::SearchResultDone(done) => {
            assert_eq!(done.result_code, ParserResultCode::ProtocolError);
            assert!(
                done.diagnostic_message
                    .0
                    .contains("sync cookie must be valid UTF-8")
            );
        }
        other => panic!("unexpected malformed-cookie response: {other:?}"),
    }
}

fn provider_backend() -> Arc<dyn DirectoryBackend> {
    let mut config = ServerConfig::default();
    config.server.base_dn = "dc=example,dc=org".to_string();
    config.replication.enabled = true;
    config.replication.mode = "provider".to_string();

    let service = ReplicationService::from_config(&config, Arc::new(MockBackend::new())).unwrap();
    service.backend()
}

async fn run_sync_refresh_only_search(
    backend: &dyn DirectoryBackend,
    cookie: Option<&[u8]>,
) -> Vec<LdapMessage<'static>> {
    let (mut server_stream, mut client_stream) = connected_stream_pair().await;
    server::handle_search_request_with_controls(
        &mut server_stream,
        backend,
        51,
        sync_search_request(),
        &sync_request_controls(SyncRefreshMode::RefreshOnly, cookie),
    )
    .await
    .unwrap();
    read_ldap_messages_until_search_done(&mut client_stream).await
}

async fn connected_stream_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
    let (server_stream, _) = listener.accept().await.unwrap();
    let client_stream = client.await.unwrap();
    (server_stream, client_stream)
}

async fn read_ldap_messages_until_search_done(stream: &mut TcpStream) -> Vec<LdapMessage<'static>> {
    let mut response = Vec::new();
    let mut buf = vec![0u8; 4096];

    loop {
        match timeout(RESPONSE_TIMEOUT, stream.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(len)) => {
                response.extend_from_slice(&buf[..len]);
                if parse_ldap_messages(&response).is_ok_and(|(_, messages)| {
                    messages.iter().any(|message| {
                        matches!(message.protocol_op, ProtocolOp::SearchResultDone(_))
                    })
                }) {
                    break;
                }
            }
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

fn sync_search_request() -> SearchRequest<'static> {
    SearchRequest {
        base_object: LdapDN(Cow::Borrowed("dc=example,dc=org")),
        scope: SearchScope(2),
        deref_aliases: DerefAliases(0),
        size_limit: 0,
        time_limit: 0,
        types_only: false,
        filter: Filter::Present(LdapString(Cow::Borrowed("objectClass"))),
        attributes: Vec::new(),
    }
}

fn sync_request_controls(mode: SyncRefreshMode, cookie: Option<&[u8]>) -> RequestControls {
    RequestControls::new(vec![LdapControl::new(
        SYNC_REQUEST_OID,
        true,
        Some(
            encode_sync_request_control(&SyncRequestControl {
                mode,
                cookie: cookie.map(|cookie| cookie.to_vec()),
                reload_hint: false,
            })
            .unwrap(),
        ),
    )])
}

fn sync_state_response(message: &LdapMessage<'_>) -> SyncStateControl {
    let controls = message.controls.as_ref().expect("response controls");
    let control = controls
        .iter()
        .find(|control| control.control_type.0.as_ref() == SYNC_STATE_OID)
        .expect("sync state response control");
    decode_sync_state_control(control.control_value.as_deref()).unwrap()
}

fn sync_done_response(message: &LdapMessage<'_>) -> SyncDoneControl {
    let controls = message.controls.as_ref().expect("response controls");
    let control = controls
        .iter()
        .find(|control| control.control_type.0.as_ref() == SYNC_DONE_OID)
        .expect("sync done response control");
    decode_sync_done_control(control.control_value.as_deref()).unwrap()
}

fn person_entry(dn: &str, cn: &str) -> DirectoryEntry {
    DirectoryEntry::new(
        dn,
        HashMap::from([
            (
                "objectClass".to_string(),
                vec!["top".to_string(), "person".to_string()],
            ),
            ("cn".to_string(), vec![cn.to_string()]),
            ("sn".to_string(), vec!["Sync".to_string()]),
        ]),
    )
}

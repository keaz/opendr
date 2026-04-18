use std::borrow::Cow;
use std::collections::HashMap;
use std::time::Duration;

use ldap_parser::asn1_rs::ToStatic;
use ldap_parser::filter::Filter;
use ldap_parser::ldap::{
    DerefAliases, LdapDN, LdapString, ProtocolOp, ResultCode as ParserResultCode, SearchRequest,
    SearchScope,
};
use ldap_parser::parse_ldap_messages;
use opendr::backend::{DirectoryBackend, DirectoryEntry, MockBackend};
use opendr::ldap_controls::{LdapControl, RequestControls};
use opendr::ldap_url::{LdapUrl, LdapUrlError, LdapUrlExtension, LdapUrlScheme, LdapUrlScope};
use opendr::server;
use rasn::{ber, types::OctetString};
use rasn_ldap::{LdapMessage as RasnLdapMessage, ProtocolOp as RasnProtocolOp, ResultCode};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const RESPONSE_TIMEOUT: Duration = Duration::from_millis(200);
const MANAGE_DSA_IT_OID: &str = "2.16.840.1.113730.3.4.2";

#[test]
fn parses_and_renders_full_rfc_4516_ldap_urls() {
    let url = LdapUrl::parse(
        "ldap://directory.example.com:1389/ou=People,dc=example,dc=org?cn,sn,mail?sub?(objectClass=person)?!bindname=cn%3Dproxy%2Cdc%3Dexample%2Cdc%3Dorg,x-chain",
    )
    .unwrap();

    assert_eq!(url.scheme, LdapUrlScheme::Ldap);
    assert_eq!(url.host.as_deref(), Some("directory.example.com"));
    assert_eq!(url.port, Some(1389));
    assert_eq!(url.dn, "ou=People,dc=example,dc=org");
    assert_eq!(url.attributes, vec!["cn", "sn", "mail"]);
    assert_eq!(url.scope, Some(LdapUrlScope::Sub));
    assert_eq!(url.filter.as_deref(), Some("(objectClass=person)"));
    assert_eq!(
        url.extensions,
        vec![
            LdapUrlExtension {
                critical: true,
                name: "bindname".to_string(),
                value: Some("cn=proxy,dc=example,dc=org".to_string()),
            },
            LdapUrlExtension {
                critical: false,
                name: "x-chain".to_string(),
                value: None,
            },
        ]
    );

    let rendered = url.to_url_string();
    assert_eq!(
        rendered,
        "ldap://directory.example.com:1389/ou=People,dc=example,dc=org?cn,sn,mail?sub?%28objectClass%3Dperson%29?!bindname=cn%3Dproxy%2Cdc%3Dexample%2Cdc%3Dorg,x-chain"
    );
    assert_eq!(LdapUrl::parse(&rendered).unwrap(), url);
}

#[test]
fn rejects_invalid_rfc_4516_urls_predictably() {
    assert!(matches!(
        LdapUrl::parse("http://directory.example.com/dc=example,dc=org"),
        Err(LdapUrlError::UnsupportedScheme { .. })
    ));
    assert!(matches!(
        LdapUrl::parse("ldap://user@directory.example.com/dc=example,dc=org"),
        Err(LdapUrlError::UnsupportedUserInfo)
    ));
    assert!(matches!(
        LdapUrl::parse("ldap://directory.example.com/dc=example%ZZ,dc=org"),
        Err(LdapUrlError::InvalidPercentEncoding { .. })
    ));
    assert!(matches!(
        LdapUrl::parse("ldap://directory.example.com/dc=example,dc=org??children"),
        Err(LdapUrlError::InvalidScope { .. })
    ));
    assert!(matches!(
        LdapUrl::parse("ldap://directory.example.com/dc=example,dc=org???objectClass=*"),
        Err(LdapUrlError::InvalidFilter { .. })
    ));
}

#[tokio::test]
async fn base_search_referral_returns_referral_result_without_rewriting_urls() {
    let backend = MockBackend::new();
    let referral_urls = vec![
        "ldap://remote.example.org/dc=remote,dc=org".to_string(),
        "ldaps://backup.example.org/ou=people,dc=remote,dc=org?cn,sn?sub?(objectClass=person)?!bindname=cn%3Dproxy%2Cdc%3Dremote%2Cdc%3Dorg".to_string(),
    ];
    backend
        .add_entry(
            referral_entry("ou=remote,dc=example,dc=org", referral_urls.clone()),
            Vec::new(),
        )
        .await
        .unwrap();

    let (mut server_stream, mut client_stream) = connected_stream_pair().await;
    server::handle_search_request_with_controls(
        &mut server_stream,
        &backend,
        71,
        search_request("ou=remote,dc=example,dc=org", SearchScope::BaseObject, 0),
        &RequestControls::default(),
    )
    .await
    .unwrap();

    let response = read_response_bytes(&mut client_stream).await;
    let decoded: RasnLdapMessage = ber::decode(&response).unwrap();
    match decoded.protocol_op {
        RasnProtocolOp::SearchResDone(done) => {
            assert_eq!(done.0.result_code, ResultCode::Referral);
            assert_eq!(
                octet_strings_to_strings(done.0.referral.unwrap()),
                referral_urls
            );
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn subtree_search_emits_search_result_reference_for_referral_entries() {
    let backend = MockBackend::new();
    backend
        .add_entry(
            referral_entry(
                "ou=remote,dc=example,dc=org",
                vec!["ldap://remote.example.org/dc=remote,dc=org??sub".to_string()],
            ),
            Vec::new(),
        )
        .await
        .unwrap();

    let (mut server_stream, mut client_stream) = connected_stream_pair().await;
    server::handle_search_request_with_controls(
        &mut server_stream,
        &backend,
        72,
        search_request("dc=example,dc=org", SearchScope(2), 0),
        &RequestControls::default(),
    )
    .await
    .unwrap();

    let messages = read_ldap_messages(&mut client_stream).await;
    let references = messages
        .iter()
        .find_map(|message| match &message.protocol_op {
            ProtocolOp::SearchResultReference(refs) => Some(
                refs.iter()
                    .map(|url| url.0.as_ref().to_string())
                    .collect::<Vec<_>>(),
            ),
            _ => None,
        })
        .expect("search result reference");

    assert_eq!(
        references,
        vec!["ldap://remote.example.org/dc=remote,dc=org??sub".to_string()]
    );
    assert!(matches!(
        messages.last().map(|message| &message.protocol_op),
        Some(ProtocolOp::SearchResultDone(done)) if done.result_code == ParserResultCode::Success
    ));
}

#[tokio::test]
async fn invalid_referral_urls_return_operations_error() {
    let backend = MockBackend::new();
    backend
        .add_entry(
            referral_entry(
                "ou=remote,dc=example,dc=org",
                vec!["http://remote.example.org/dc=remote,dc=org".to_string()],
            ),
            Vec::new(),
        )
        .await
        .unwrap();

    let (mut server_stream, mut client_stream) = connected_stream_pair().await;
    server::handle_search_request_with_controls(
        &mut server_stream,
        &backend,
        73,
        search_request("ou=remote,dc=example,dc=org", SearchScope::BaseObject, 0),
        &RequestControls::default(),
    )
    .await
    .unwrap();

    let messages = read_ldap_messages(&mut client_stream).await;
    assert!(matches!(
        &messages[0].protocol_op,
        ProtocolOp::SearchResultDone(done)
            if done.result_code == ParserResultCode::OperationsError
                && done.diagnostic_message.0.contains("invalid LDAP URL")
    ));
}

#[tokio::test]
async fn alias_dereference_loop_returns_loop_detect() {
    let backend = MockBackend::new();
    backend
        .add_entry(
            alias_entry(
                "cn=alias-one,dc=example,dc=org",
                "cn=alias-two,dc=example,dc=org",
            ),
            Vec::new(),
        )
        .await
        .unwrap();
    backend
        .add_entry(
            alias_entry(
                "cn=alias-two,dc=example,dc=org",
                "cn=alias-one,dc=example,dc=org",
            ),
            Vec::new(),
        )
        .await
        .unwrap();

    let (mut server_stream, mut client_stream) = connected_stream_pair().await;
    server::handle_search_request_with_controls(
        &mut server_stream,
        &backend,
        74,
        search_request("cn=alias-one,dc=example,dc=org", SearchScope::BaseObject, 2),
        &RequestControls::default(),
    )
    .await
    .unwrap();

    let messages = read_ldap_messages(&mut client_stream).await;
    assert!(matches!(
        &messages[0].protocol_op,
        ProtocolOp::SearchResultDone(done)
            if done.result_code == ParserResultCode::LoopDetect
                && done.diagnostic_message.0.contains("alias loop detected")
    ));
}

#[tokio::test]
async fn manage_dsa_it_returns_referral_object_instead_of_reference() {
    let backend = MockBackend::new();
    backend
        .add_entry(
            referral_entry(
                "ou=remote,dc=example,dc=org",
                vec!["ldap://remote.example.org/dc=remote,dc=org".to_string()],
            ),
            Vec::new(),
        )
        .await
        .unwrap();

    let (mut server_stream, mut client_stream) = connected_stream_pair().await;
    server::handle_search_request_with_controls(
        &mut server_stream,
        &backend,
        75,
        search_request("ou=remote,dc=example,dc=org", SearchScope::BaseObject, 0),
        &RequestControls::new(vec![LdapControl::new(MANAGE_DSA_IT_OID, true, None)]),
    )
    .await
    .unwrap();

    let messages = read_ldap_messages(&mut client_stream).await;
    assert!(matches!(
        &messages[0].protocol_op,
        ProtocolOp::SearchResultEntry(entry)
            if entry.object_name.0.as_ref() == "ou=remote,dc=example,dc=org"
    ));
    assert!(
        !messages
            .iter()
            .any(|message| matches!(message.protocol_op, ProtocolOp::SearchResultReference(_))),
        "ManageDsaIT search must not emit a reference for the referral object"
    );
}

fn referral_entry(dn: &str, urls: Vec<String>) -> DirectoryEntry {
    DirectoryEntry::new(
        dn,
        HashMap::from([
            (
                "objectClass".to_string(),
                vec!["top".to_string(), "referral".to_string()],
            ),
            ("ref".to_string(), urls),
        ]),
    )
}

fn alias_entry(dn: &str, target_dn: &str) -> DirectoryEntry {
    DirectoryEntry::new(
        dn,
        HashMap::from([
            (
                "objectClass".to_string(),
                vec!["top".to_string(), "alias".to_string()],
            ),
            ("aliasedObjectName".to_string(), vec![target_dn.to_string()]),
        ]),
    )
}

fn search_request(
    base_dn: &'static str,
    scope: SearchScope,
    deref_aliases: u32,
) -> SearchRequest<'static> {
    SearchRequest {
        base_object: LdapDN(Cow::Borrowed(base_dn)),
        scope,
        deref_aliases: DerefAliases(deref_aliases),
        size_limit: 0,
        time_limit: 0,
        types_only: false,
        filter: Filter::Present(LdapString(Cow::Borrowed("objectClass"))),
        attributes: vec![
            LdapString(Cow::Borrowed("objectClass")),
            LdapString(Cow::Borrowed("ref")),
        ],
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

async fn read_response_bytes(stream: &mut TcpStream) -> Vec<u8> {
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

    response
}

async fn read_ldap_messages(
    stream: &mut TcpStream,
) -> Vec<ldap_parser::ldap::LdapMessage<'static>> {
    let response = read_response_bytes(stream).await;
    let (_, messages) = parse_ldap_messages(&response).unwrap();
    messages
        .into_iter()
        .map(|message| message.to_static())
        .collect()
}

fn octet_strings_to_strings(values: Vec<OctetString>) -> Vec<String> {
    values
        .iter()
        .map(|value| String::from_utf8(value.to_vec()).expect("valid UTF-8 URL"))
        .collect()
}

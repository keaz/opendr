use std::sync::Arc;
use std::time::Duration;

use ldap_parser::ldap::{ProtocolOp, ResultCode as ParserResultCode};
use ldap_parser::parse_ldap_messages;
use opendr::backend::{DirectoryBackend, DirectoryEntry, MockBackend};
use opendr::search_controls::{
    PAGED_RESULTS_OID, SERVER_SIDE_SORT_REQUEST_OID, SERVER_SIDE_SORT_RESPONSE_OID,
    ServerSideSortResponseControl, ServerSideSortResultCode, SortKey, decode_paged_results_control,
    decode_server_side_sort_response_control, encode_paged_results_control,
    encode_server_side_sort_request_control,
};
use opendr::server::{self, LegacyServerConfig, ServerError};
use rasn::der;
use rasn_ldap::{
    Control as RasnControl, Filter as RasnFilter, LdapMessage as RasnLdapMessage,
    ProtocolOp as RasnProtocolOp, SearchRequest as RasnSearchRequest, SearchRequestDerefAliases,
    SearchRequestScope,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

struct RuntimeServer {
    shutdown_tx: broadcast::Sender<()>,
    join_handle: JoinHandle<Result<(), ServerError>>,
    port: u16,
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

async fn spawn_runtime_server(backend: Arc<dyn DirectoryBackend>) -> RuntimeServer {
    let port = reserve_port();
    let addr = format!("127.0.0.1:{port}");
    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let runtime_config = LegacyServerConfig {
        rate_limiting_enabled: false,
        ..LegacyServerConfig::default()
    };

    let join_handle = tokio::spawn(async move {
        server::run_with_metrics_and_config(&addr, backend, shutdown_rx, None, runtime_config).await
    });

    RuntimeServer {
        shutdown_tx,
        join_handle,
        port,
    }
}

async fn read_response(stream: &mut TcpStream) -> Vec<u8> {
    let mut buf = vec![0u8; 4096];
    let len = timeout(Duration::from_secs(1), stream.read(&mut buf))
        .await
        .expect("response timeout")
        .expect("failed to read response");
    buf.truncate(len);

    loop {
        let mut chunk = vec![0u8; 4096];
        match timeout(Duration::from_millis(25), stream.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(len)) => buf.extend_from_slice(&chunk[..len]),
            Ok(Err(err)) => panic!("failed to read response: {err}"),
            Err(_) => break,
        }
    }

    buf
}

async fn connect_client(port: u16) -> TcpStream {
    for _ in 0..40 {
        match TcpStream::connect(("127.0.0.1", port)).await {
            Ok(stream) => return stream,
            Err(_) => sleep(Duration::from_millis(25)).await,
        }
    }

    panic!("failed to connect to runtime server on port {port}");
}

fn search_message(
    message_id: u32,
    sort_keys: &[SortKey],
    sort_critical: bool,
    paged: Option<(u32, &[u8])>,
) -> Vec<u8> {
    let search_request = RasnSearchRequest::new(
        b"dc=example,dc=org".to_vec().into(),
        SearchRequestScope::WholeSubtree,
        SearchRequestDerefAliases::NeverDerefAliases,
        0,
        0,
        false,
        RasnFilter::Present(b"objectClass".to_vec().into()),
        vec![b"cn".to_vec().into()],
    );

    let mut controls = vec![RasnControl::new(
        SERVER_SIDE_SORT_REQUEST_OID.as_bytes().to_vec().into(),
        sort_critical,
        Some(
            encode_server_side_sort_request_control(sort_keys)
                .unwrap()
                .into(),
        ),
    )];
    if let Some((size, cookie)) = paged {
        controls.push(RasnControl::new(
            PAGED_RESULTS_OID.as_bytes().to_vec().into(),
            false,
            Some(encode_paged_results_control(size, cookie).unwrap().into()),
        ));
    }

    let mut message =
        RasnLdapMessage::new(message_id, RasnProtocolOp::SearchRequest(search_request));
    message.controls = Some(controls.into_iter().collect());
    der::encode(&message).unwrap()
}

fn response_paged_results(
    messages: &[ldap_parser::ldap::LdapMessage<'_>],
) -> opendr::search_controls::PagedResultsControl {
    let done = messages.last().expect("search done message");
    let controls = done.controls.as_ref().expect("response controls");
    let control = controls
        .iter()
        .find(|control| control.control_type.0.as_ref() == PAGED_RESULTS_OID)
        .expect("paged results control");
    decode_paged_results_control(control.control_value.as_deref()).unwrap()
}

fn response_sort_result(
    messages: &[ldap_parser::ldap::LdapMessage<'_>],
) -> ServerSideSortResponseControl {
    let done = messages.last().expect("search done message");
    let controls = done.controls.as_ref().expect("response controls");
    let control = controls
        .iter()
        .find(|control| control.control_type.0.as_ref() == SERVER_SIDE_SORT_RESPONSE_OID)
        .expect("sort response control");
    decode_server_side_sort_response_control(control.control_value.as_deref()).unwrap()
}

fn search_result_dns(messages: &[ldap_parser::ldap::LdapMessage<'_>]) -> Vec<String> {
    messages
        .iter()
        .filter_map(|message| match &message.protocol_op {
            ProtocolOp::SearchResultEntry(entry) => Some(entry.object_name.0.as_ref().to_string()),
            _ => None,
        })
        .collect()
}

fn test_entry(dn: &str, cn: &str) -> DirectoryEntry {
    DirectoryEntry::new(
        dn,
        [
            ("cn".to_string(), vec![cn.to_string()]),
            ("objectclass".to_string(), vec!["person".to_string()]),
        ]
        .into_iter()
        .collect(),
    )
}

#[tokio::test]
async fn live_runtime_supports_rfc2891_server_side_sort() {
    let backend = Arc::new(MockBackend::new());
    for (dn, cn) in [
        ("cn=zeta,dc=example,dc=org", "Zulu"),
        ("cn=alpha,dc=example,dc=org", "alpha"),
        ("cn=beta,dc=example,dc=org", "Beta"),
    ] {
        backend
            .add_entry(test_entry(dn, cn), Vec::new())
            .await
            .unwrap();
    }

    let server = spawn_runtime_server(backend).await;
    let mut stream = connect_client(server.port).await;
    let sort_keys = [SortKey {
        attribute_type: "cn".to_string(),
        ordering_rule: None,
        reverse_order: false,
    }];

    stream
        .write_all(&search_message(1, &sort_keys, false, None))
        .await
        .unwrap();
    let response = read_response(&mut stream).await;
    let (_, messages) = parse_ldap_messages(&response).unwrap();

    assert_eq!(
        search_result_dns(&messages),
        vec![
            "cn=alpha,dc=example,dc=org".to_string(),
            "cn=beta,dc=example,dc=org".to_string(),
            "cn=zeta,dc=example,dc=org".to_string(),
        ]
    );
    match &messages.last().unwrap().protocol_op {
        ProtocolOp::SearchResultDone(done) => {
            assert_eq!(done.result_code, ParserResultCode::Success);
        }
        other => panic!("unexpected response: {:?}", other),
    }
    assert_eq!(
        response_sort_result(&messages).result,
        ServerSideSortResultCode::Success
    );

    server.shutdown().await;
}

#[tokio::test]
async fn live_runtime_reports_unsupported_ordering_rule_in_sort_response() {
    let backend = Arc::new(MockBackend::new());
    backend
        .add_entry(test_entry("cn=user,dc=example,dc=org", "User"), Vec::new())
        .await
        .unwrap();

    let server = spawn_runtime_server(backend).await;
    let mut stream = connect_client(server.port).await;
    let sort_keys = [SortKey {
        attribute_type: "cn".to_string(),
        ordering_rule: Some("caseIgnoreOrderingMatch".to_string()),
        reverse_order: false,
    }];

    stream
        .write_all(&search_message(1, &sort_keys, false, None))
        .await
        .unwrap();
    let response = read_response(&mut stream).await;
    let (_, messages) = parse_ldap_messages(&response).unwrap();

    assert_eq!(messages.len(), 1);
    match &messages[0].protocol_op {
        ProtocolOp::SearchResultDone(done) => {
            assert_eq!(done.result_code, ParserResultCode::Success);
        }
        other => panic!("unexpected response: {:?}", other),
    }
    let sort_response = response_sort_result(&messages);
    assert_eq!(
        sort_response.result,
        ServerSideSortResultCode::InappropriateMatching
    );
    assert_eq!(sort_response.attribute_type.as_deref(), Some("cn"));

    server.shutdown().await;
}

#[tokio::test]
async fn live_runtime_supports_sorted_paged_results() {
    let backend = Arc::new(MockBackend::new());
    for (dn, cn) in [
        ("cn=zeta,dc=example,dc=org", "Zulu"),
        ("cn=alpha,dc=example,dc=org", "alpha"),
        ("cn=gamma,dc=example,dc=org", "Gamma"),
        ("cn=beta,dc=example,dc=org", "Beta"),
        ("cn=delta,dc=example,dc=org", "delta"),
    ] {
        backend
            .add_entry(test_entry(dn, cn), Vec::new())
            .await
            .unwrap();
    }

    let server = spawn_runtime_server(backend).await;
    let mut stream = connect_client(server.port).await;
    let sort_keys = [SortKey {
        attribute_type: "cn".to_string(),
        ordering_rule: None,
        reverse_order: false,
    }];

    stream
        .write_all(&search_message(1, &sort_keys, false, Some((2, &[]))))
        .await
        .unwrap();
    let response = read_response(&mut stream).await;
    let (_, first_page) = parse_ldap_messages(&response).unwrap();
    assert_eq!(
        search_result_dns(&first_page),
        vec![
            "cn=alpha,dc=example,dc=org".to_string(),
            "cn=beta,dc=example,dc=org".to_string(),
        ]
    );
    assert_eq!(
        response_sort_result(&first_page).result,
        ServerSideSortResultCode::Success
    );
    let first_cookie = response_paged_results(&first_page);
    assert_eq!(first_cookie.size, 5);
    assert!(!first_cookie.cookie.is_empty());

    stream
        .write_all(&search_message(
            2,
            &sort_keys,
            false,
            Some((2, &first_cookie.cookie)),
        ))
        .await
        .unwrap();
    let response = read_response(&mut stream).await;
    let (_, second_page) = parse_ldap_messages(&response).unwrap();
    assert_eq!(
        search_result_dns(&second_page),
        vec![
            "cn=delta,dc=example,dc=org".to_string(),
            "cn=gamma,dc=example,dc=org".to_string(),
        ]
    );
    assert_eq!(
        response_sort_result(&second_page).result,
        ServerSideSortResultCode::Success
    );
    let second_cookie = response_paged_results(&second_page);
    assert_eq!(second_cookie.size, 5);
    assert_eq!(second_cookie.cookie, first_cookie.cookie);

    stream
        .write_all(&search_message(
            3,
            &sort_keys,
            false,
            Some((2, &second_cookie.cookie)),
        ))
        .await
        .unwrap();
    let response = read_response(&mut stream).await;
    let (_, third_page) = parse_ldap_messages(&response).unwrap();
    assert_eq!(
        search_result_dns(&third_page),
        vec!["cn=zeta,dc=example,dc=org".to_string()]
    );
    assert_eq!(
        response_sort_result(&third_page).result,
        ServerSideSortResultCode::Success
    );
    let third_cookie = response_paged_results(&third_page);
    assert_eq!(third_cookie.size, 5);
    assert!(third_cookie.cookie.is_empty());

    server.shutdown().await;
}

use std::sync::Arc;
use std::time::Duration;

use ldap_parser::ldap::{ProtocolOp, ResultCode as ParserResultCode};
use ldap_parser::parse_ldap_messages;
use opendr::backend::{DirectoryBackend, DirectoryEntry, MockBackend};
use opendr::search_controls::{
    decode_paged_results_control, encode_paged_results_control, PAGED_RESULTS_OID,
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

fn paged_search_message(message_id: u32, page_size: u32, cookie: &[u8]) -> Vec<u8> {
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
    let control_value = encode_paged_results_control(page_size, cookie).unwrap();
    let control = RasnControl::new(
        PAGED_RESULTS_OID.as_bytes().to_vec().into(),
        false,
        Some(control_value.into()),
    );

    let mut message =
        RasnLdapMessage::new(message_id, RasnProtocolOp::SearchRequest(search_request));
    message.controls = Some(vec![control].into_iter().collect());
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
async fn live_runtime_supports_rfc2696_paged_results() {
    let backend = Arc::new(MockBackend::new());
    for (dn, cn) in [
        ("cn=one,dc=example,dc=org", "one"),
        ("cn=two,dc=example,dc=org", "two"),
        ("cn=three,dc=example,dc=org", "three"),
        ("cn=four,dc=example,dc=org", "four"),
        ("cn=five,dc=example,dc=org", "five"),
    ] {
        backend
            .add_entry(test_entry(dn, cn), Vec::new())
            .await
            .unwrap();
    }

    let server = spawn_runtime_server(backend).await;
    let mut stream = connect_client(server.port).await;

    stream
        .write_all(&paged_search_message(1, 3, &[]))
        .await
        .unwrap();
    let response = read_response(&mut stream).await;
    let (_, first_page) = parse_ldap_messages(&response).unwrap();
    assert_eq!(first_page.len(), 4);
    let first_cookie = response_paged_results(&first_page);
    assert_eq!(first_cookie.size, 5);
    assert!(!first_cookie.cookie.is_empty());

    stream
        .write_all(&paged_search_message(2, 3, &first_cookie.cookie))
        .await
        .unwrap();
    let response = read_response(&mut stream).await;
    let (_, second_page) = parse_ldap_messages(&response).unwrap();
    assert_eq!(second_page.len(), 3);
    let second_cookie = response_paged_results(&second_page);
    assert_eq!(second_cookie.size, 5);
    assert!(second_cookie.cookie.is_empty());

    match &second_page.last().unwrap().protocol_op {
        ProtocolOp::SearchResultDone(done) => {
            assert_eq!(done.result_code, ParserResultCode::Success);
        }
        other => panic!("unexpected response: {:?}", other),
    }

    server.shutdown().await;
}

#[tokio::test]
async fn live_runtime_rejects_replayed_paged_results_cookie() {
    let backend = Arc::new(MockBackend::new());
    for (dn, cn) in [
        ("cn=one,dc=example,dc=org", "one"),
        ("cn=two,dc=example,dc=org", "two"),
        ("cn=three,dc=example,dc=org", "three"),
    ] {
        backend
            .add_entry(test_entry(dn, cn), Vec::new())
            .await
            .unwrap();
    }

    let server = spawn_runtime_server(backend).await;
    let mut stream = connect_client(server.port).await;

    stream
        .write_all(&paged_search_message(1, 2, &[]))
        .await
        .unwrap();
    let response = read_response(&mut stream).await;
    let (_, first_page) = parse_ldap_messages(&response).unwrap();
    let first_cookie = response_paged_results(&first_page);

    stream
        .write_all(&paged_search_message(2, 2, &first_cookie.cookie))
        .await
        .unwrap();
    let response = read_response(&mut stream).await;
    let (_, second_page) = parse_ldap_messages(&response).unwrap();
    assert!(response_paged_results(&second_page).cookie.is_empty());

    stream
        .write_all(&paged_search_message(3, 2, &first_cookie.cookie))
        .await
        .unwrap();
    let response = read_response(&mut stream).await;
    let (_, replay) = parse_ldap_messages(&response).unwrap();
    assert_eq!(replay.len(), 1);
    match &replay[0].protocol_op {
        ProtocolOp::SearchResultDone(done) => {
            assert_eq!(done.result_code, ParserResultCode::UnwillingToPerform);
            assert_eq!(
                done.diagnostic_message.0.as_ref(),
                "paged results cookie is not valid for this search sequence"
            );
        }
        other => panic!("unexpected response: {:?}", other),
    }

    server.shutdown().await;
}

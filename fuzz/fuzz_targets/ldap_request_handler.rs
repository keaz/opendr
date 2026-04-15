#![no_main]

use ldap_parser::parse_ldap_messages;
use libfuzzer_sys::fuzz_target;
use opendr::backend::MockBackend;
use opendr::schema::LdapSchema;
use opendr::server::handle_client;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncWriteExt, Interest};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

fuzz_target!(|data: &[u8]| {
    if data.len() > 4096 {
        return;
    }

    let _ = parse_ldap_messages(data);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("tokio runtime");

    runtime.block_on(async {
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(_) => return,
        };
        let addr = match listener.local_addr() {
            Ok(addr) => addr,
            Err(_) => return,
        };

        let backend = Arc::new(MockBackend::new());
        let schema = Arc::new(LdapSchema::with_core_schema());
        let server = tokio::spawn(async move {
            if let Ok((socket, _)) = listener.accept().await {
                let _ = timeout(
                    Duration::from_millis(100),
                    handle_client(socket, backend, schema),
                )
                .await;
            }
        });

        let mut client = match TcpStream::connect(addr).await {
            Ok(client) => client,
            Err(_) => return,
        };
        let _ = timeout(Duration::from_millis(100), client.ready(Interest::WRITABLE)).await;
        let _ = client.write_all(data).await;
        let _ = client.shutdown().await;
        let _ = timeout(Duration::from_millis(200), server).await;
    });
});

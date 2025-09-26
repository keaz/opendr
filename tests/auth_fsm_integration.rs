//! Authentication FSM Integration Tests
//!
//! Comprehensive tests for authentication finite state machine integration
//! covering simple bind, SASL bind, session management, and timeout handling.

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ldap_parser::ldap::{AuthenticationChoice, BindRequest, LdapDN, ProtocolOp, SaslCredentials, LdapString};
use ldap_parser::parse_ldap_messages;
use mockall::mock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use opendr::backend::{BackendError, DirectoryBackend, DirectoryEntry};
use opendr::server_fsm::{ConnectionFsmSet, handle_bind_request_fsm};
use opendr::server::{process_message_with_fsm, send_bind_response};
use opendr::fsm::{AuthState, AuthLevel};

mock! {
    pub AuthTestDirectory {}

    #[async_trait]
    impl DirectoryBackend for AuthTestDirectory {
        async fn authenticate(&self, dn: &str, password: &[u8]) -> Result<bool, BackendError>;
        async fn get_entry(&self, dn: &str) -> Result<Option<DirectoryEntry>, BackendError>;
        async fn add_entry(&self, entry: DirectoryEntry, password: Vec<u8>) -> Result<(), BackendError>;
        async fn delete_entry(&self, dn: &str) -> Result<(), BackendError>;
        async fn modify_entry(&self, dn: &str, modifications: Vec<opendr::backend::Modification>) -> Result<(), BackendError>;
        async fn compare_attribute(&self, dn: &str, attribute: &str, value: &str) -> Result<bool, BackendError>;
        async fn rename_entry(&self, dn: &str, new_rdn: &str, delete_old: bool, new_superior: Option<String>) -> Result<(), BackendError>;
        async fn search_entries(&self, base_dn: &str, scope: ldap_parser::ldap::SearchScope) -> Result<Vec<DirectoryEntry>, BackendError>;
    }
}

const RESPONSE_TIMEOUT: Duration = Duration::from_millis(200);

async fn connected_stream_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let client = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
    let (server_stream, _) = listener.accept().await.unwrap();
    let client_stream = client.await.unwrap();

    (server_stream, client_stream)
}

async fn read_response(stream: &mut TcpStream) -> Vec<u8> {
    let mut buf = vec![0u8; 4096];
    let len = timeout(RESPONSE_TIMEOUT, stream.read(&mut buf))
        .await
        .expect("response timeout")
        .expect("failed to read response");
    
    buf.truncate(len);
    buf
}

#[tokio::test]
async fn test_fsm_simple_bind_success() {
    let mut backend = MockAuthTestDirectory::new();
    backend
        .expect_authenticate()
        .withf(|dn, password| dn == "cn=admin,dc=example,dc=org" && password == b"secret")
        .returning(|_, _| Ok(true));

    let request = BindRequest {
        version: 3,
        name: LdapDN(Cow::Owned("cn=admin,dc=example,dc=org".to_string())),
        authentication: AuthenticationChoice::Simple(Cow::Owned(b"secret".to_vec())),
    };

    let (server_stream, mut client_stream) = connected_stream_pair().await;
    
    // Create FSM set with server stream
    let mut fsm_set = ConnectionFsmSet::new(server_stream).expect("Failed to create FSM set");
    fsm_set.configure_auth_backend(Arc::new(backend));
    
    // Use a new client stream for communication
    let (mut server_stream2, mut client_stream2) = connected_stream_pair().await;

    // Handle bind request through FSM
    handle_bind_request_fsm(&mut fsm_set, &mut server_stream2, 42, request)
        .await
        .unwrap();

    let data = read_response(&mut client_stream2).await;
    let (_, messages) = parse_ldap_messages(&data).unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].message_id.0, 42);

    match &messages[0].protocol_op {
        ProtocolOp::BindResponse(response) => {
            assert_eq!(
                response.result.result_code,
                ldap_parser::ldap::ResultCode::Success
            );
            assert!(response.result.diagnostic_message.0.is_empty());
        }
        other => panic!("unexpected response: {:?}", other),
    }

    // Verify FSM state
    assert!(fsm_set.is_authenticated());
    assert_eq!(fsm_set.authenticated_dn(), Some("cn=admin,dc=example,dc=org"));
    assert_eq!(fsm_set.auth_level(), AuthLevel::Simple);
}

#[tokio::test]
async fn test_fsm_simple_bind_invalid_credentials() {
    let mut backend = MockAuthTestDirectory::new();
    backend
        .expect_authenticate()
        .returning(|_, _| Ok(false));

    let request = BindRequest {
        version: 3,
        name: LdapDN(Cow::Owned("cn=user,dc=example,dc=org".to_string())),
        authentication: AuthenticationChoice::Simple(Cow::Owned(b"wrong".to_vec())),
    };

    let (server_stream, _) = connected_stream_pair().await;
    let mut fsm_set = ConnectionFsmSet::new(server_stream).expect("Failed to create FSM set");
    fsm_set.configure_auth_backend(Arc::new(backend));

    let (mut server_stream2, mut client_stream2) = connected_stream_pair().await;

    handle_bind_request_fsm(&mut fsm_set, &mut server_stream2, 7, request)
        .await
        .unwrap();

    let data = read_response(&mut client_stream2).await;
    let (_, messages) = parse_ldap_messages(&data).unwrap();

    match &messages[0].protocol_op {
        ProtocolOp::BindResponse(response) => {
            assert_eq!(
                response.result.result_code,
                ldap_parser::ldap::ResultCode::InvalidCredentials
            );
            assert_eq!(
                response.result.diagnostic_message.0.as_ref(),
                "invalid credentials"
            );
        }
        other => panic!("unexpected response: {:?}", other),
    }

    // Verify FSM remains unauthenticated
    assert!(!fsm_set.is_authenticated());
    assert_eq!(fsm_set.authenticated_dn(), None);
    assert_eq!(fsm_set.auth_level(), AuthLevel::Anonymous);
}

#[tokio::test]
async fn test_fsm_simple_bind_backend_error() {
    let mut backend = MockAuthTestDirectory::new();
    backend
        .expect_authenticate()
        .returning(|_, _| Err(BackendError::Storage("database failure".into())));

    let request = BindRequest {
        version: 3,
        name: LdapDN(Cow::Owned("cn=user,dc=example,dc=org".to_string())),
        authentication: AuthenticationChoice::Simple(Cow::Owned(b"secret".to_vec())),
    };

    let (server_stream, _) = connected_stream_pair().await;
    let mut fsm_set = ConnectionFsmSet::new(server_stream).expect("Failed to create FSM set");
    fsm_set.configure_auth_backend(Arc::new(backend));

    let (mut server_stream2, mut client_stream2) = connected_stream_pair().await;

    handle_bind_request_fsm(&mut fsm_set, &mut server_stream2, 9, request)
        .await
        .unwrap();

    let data = read_response(&mut client_stream2).await;
    let (_, messages) = parse_ldap_messages(&data).unwrap();

    match &messages[0].protocol_op {
        ProtocolOp::BindResponse(response) => {
            assert_eq!(
                response.result.result_code,
                ldap_parser::ldap::ResultCode::Unavailable
            );
            assert_eq!(
                response.result.diagnostic_message.0.as_ref(),
                "authentication failed"
            );
        }
        other => panic!("unexpected response: {:?}", other),
    }

    // Verify FSM remains unauthenticated
    assert!(!fsm_set.is_authenticated());
    assert_eq!(fsm_set.authenticated_dn(), None);
}

#[tokio::test]
async fn test_fsm_sasl_bind_not_implemented() {
    let backend = MockAuthTestDirectory::new();

    let request = BindRequest {
        version: 3,
        name: LdapDN(Cow::Owned("cn=user,dc=example,dc=org".to_string())),
        authentication: AuthenticationChoice::Sasl(SaslCredentials {
            mechanism: LdapString(Cow::Owned("PLAIN".to_string())),
            credentials: Some(Cow::Owned(b"\x00username\x00password".to_vec())),
        }),
    };

    let (server_stream, _) = connected_stream_pair().await;
    let mut fsm_set = ConnectionFsmSet::new(server_stream).expect("Failed to create FSM set");
    fsm_set.configure_auth_backend(Arc::new(backend));

    let (mut server_stream2, mut client_stream2) = connected_stream_pair().await;

    handle_bind_request_fsm(&mut fsm_set, &mut server_stream2, 10, request)
        .await
        .unwrap();

    let data = read_response(&mut client_stream2).await;
    let (_, messages) = parse_ldap_messages(&data).unwrap();

    match &messages[0].protocol_op {
        ProtocolOp::BindResponse(response) => {
            assert_eq!(
                response.result.result_code,
                ldap_parser::ldap::ResultCode::AuthMethodNotSupported
            );
            assert!(response.result.diagnostic_message.0.contains("SASL authentication"));
        }
        other => panic!("unexpected response: {:?}", other),
    }
}

#[tokio::test]
async fn test_fsm_bind_unsupported_ldap_version() {
    let backend = MockAuthTestDirectory::new();

    let request = BindRequest {
        version: 2, // Unsupported version
        name: LdapDN(Cow::Owned("cn=user,dc=example,dc=org".to_string())),
        authentication: AuthenticationChoice::Simple(Cow::Owned(b"secret".to_vec())),
    };

    let (server_stream, _) = connected_stream_pair().await;
    let mut fsm_set = ConnectionFsmSet::new(server_stream).expect("Failed to create FSM set");
    fsm_set.configure_auth_backend(Arc::new(backend));

    let (mut server_stream2, mut client_stream2) = connected_stream_pair().await;

    handle_bind_request_fsm(&mut fsm_set, &mut server_stream2, 11, request)
        .await
        .unwrap();

    let data = read_response(&mut client_stream2).await;
    let (_, messages) = parse_ldap_messages(&data).unwrap();

    match &messages[0].protocol_op {
        ProtocolOp::BindResponse(response) => {
            assert_eq!(
                response.result.result_code,
                ldap_parser::ldap::ResultCode::ProtocolError
            );
            assert_eq!(
                response.result.diagnostic_message.0.as_ref(),
                "unsupported LDAP version"
            );
        }
        other => panic!("unexpected response: {:?}", other),
    }
}

#[tokio::test]
async fn test_fsm_session_timeout_functionality() {
    let mut backend = MockAuthTestDirectory::new();
    backend
        .expect_authenticate()
        .returning(|_, _| Ok(true));

    // Create FSM set with very short timeout (100ms)
    let (server_stream, _) = connected_stream_pair().await;
    let mut fsm_set = ConnectionFsmSet::new_with_timeout(server_stream, Duration::from_millis(100))
        .expect("Failed to create FSM set");
    fsm_set.configure_auth_backend(Arc::new(backend));

    // First bind to authenticate
    let request = BindRequest {
        version: 3,
        name: LdapDN(Cow::Owned("cn=admin,dc=example,dc=org".to_string())),
        authentication: AuthenticationChoice::Simple(Cow::Owned(b"secret".to_vec())),
    };

    let (mut server_stream2, mut client_stream2) = connected_stream_pair().await;
    handle_bind_request_fsm(&mut fsm_set, &mut server_stream2, 12, request)
        .await
        .unwrap();

    // Verify authentication succeeded
    assert!(fsm_set.is_authenticated());
    assert!(!fsm_set.is_session_timed_out());
    assert!(fsm_set.time_until_timeout().is_some());

    // Wait for timeout
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Should be timed out now
    assert!(fsm_set.is_session_timed_out());
    assert_eq!(fsm_set.time_until_timeout(), Some(Duration::ZERO));

    // Reset timeout should extend session
    fsm_set.reset_session_timeout();
    assert!(!fsm_set.is_session_timed_out());
    assert!(fsm_set.time_until_timeout().unwrap() > Duration::from_millis(50));
}

#[tokio::test]
async fn test_fsm_session_timeout_only_applies_when_authenticated() {
    let backend = MockAuthTestDirectory::new();
    
    let (server_stream, _) = connected_stream_pair().await;
    let fsm_set = ConnectionFsmSet::new_with_timeout(server_stream, Duration::from_millis(100))
        .expect("Failed to create FSM set");

    // Should not timeout when not authenticated
    assert!(!fsm_set.is_authenticated());
    assert!(!fsm_set.is_session_timed_out());
    assert_eq!(fsm_set.time_until_timeout(), None);

    // Even after timeout period
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(!fsm_set.is_session_timed_out());
}

#[tokio::test]
async fn test_fsm_timeout_handling_in_message_processing() {
    let mut backend = MockAuthTestDirectory::new();
    backend
        .expect_authenticate()
        .returning(|_, _| Ok(true));

    // Create FSM with short timeout
    let (server_stream, _) = connected_stream_pair().await;
    let mut fsm_set = ConnectionFsmSet::new_with_timeout(server_stream, Duration::from_millis(50))
        .expect("Failed to create FSM set");
    fsm_set.configure_auth_backend(Arc::new(backend));

    // Authenticate first
    let request = BindRequest {
        version: 3,
        name: LdapDN(Cow::Owned("cn=admin,dc=example,dc=org".to_string())),
        authentication: AuthenticationChoice::Simple(Cow::Owned(b"secret".to_vec())),
    };

    let (mut temp_stream, _) = connected_stream_pair().await;
    handle_bind_request_fsm(&mut fsm_set, &mut temp_stream, 1, request)
        .await
        .unwrap();

    assert!(fsm_set.is_authenticated());

    // Wait for timeout
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Try to process another message - should fail due to timeout
    let another_request = BindRequest {
        version: 3,
        name: LdapDN(Cow::Owned("cn=user,dc=example,dc=org".to_string())),
        authentication: AuthenticationChoice::Simple(Cow::Owned(b"test".to_vec())),
    };

    let message = ldap_parser::ldap::LdapMessage {
        message_id: ldap_parser::ldap::MessageID(2),
        protocol_op: ldap_parser::ldap::ProtocolOp::BindRequest(another_request),
        controls: None,
    };

    let (mut stream_for_processing, _) = connected_stream_pair().await;
    
    // Create another mock backend for the timeout test
    let backend2 = MockAuthTestDirectory::new();
    
    // This should return an error due to session timeout
    let result = process_message_with_fsm(&mut stream_for_processing, &backend2, Some(&mut fsm_set), message).await;
    
    // Should get a timeout error
    assert!(result.is_err());
    if let Err(opendr::server::ServerError::Io(io_err)) = result {
        assert_eq!(io_err.kind(), std::io::ErrorKind::TimedOut);
    } else {
        panic!("Expected timeout error, got: {:?}", result);
    }
}

#[tokio::test]
async fn test_fsm_activity_updates_prevent_timeout() {
    let mut backend = MockAuthTestDirectory::new();
    backend
        .expect_authenticate()
        .returning(|_, _| Ok(true));

    let (server_stream, _) = connected_stream_pair().await;
    let mut fsm_set = ConnectionFsmSet::new_with_timeout(server_stream, Duration::from_millis(200))
        .expect("Failed to create FSM set");
    fsm_set.configure_auth_backend(Arc::new(backend));

    // Authenticate
    let request = BindRequest {
        version: 3,
        name: LdapDN(Cow::Owned("cn=admin,dc=example,dc=org".to_string())),
        authentication: AuthenticationChoice::Simple(Cow::Owned(b"secret".to_vec())),
    };

    let (mut temp_stream, _) = connected_stream_pair().await;
    handle_bind_request_fsm(&mut fsm_set, &mut temp_stream, 1, request)
        .await
        .unwrap();

    assert!(fsm_set.is_authenticated());

    // Keep updating activity before timeout
    for _ in 0..5 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        fsm_set.update_activity(); // This should prevent timeout
        assert!(!fsm_set.is_session_timed_out());
    }
}

#[tokio::test]
async fn test_fsm_anonymous_bind() {
    let backend = MockAuthTestDirectory::new();

    let request = BindRequest {
        version: 3,
        name: LdapDN(Cow::Owned("".to_string())), // Empty DN for anonymous
        authentication: AuthenticationChoice::Simple(Cow::Owned(b"".to_vec())), // Empty password
    };

    let (server_stream, _) = connected_stream_pair().await;
    let mut fsm_set = ConnectionFsmSet::new(server_stream).expect("Failed to create FSM set");
    fsm_set.configure_auth_backend(Arc::new(backend));

    let (mut server_stream2, mut client_stream2) = connected_stream_pair().await;

    handle_bind_request_fsm(&mut fsm_set, &mut server_stream2, 13, request)
        .await
        .unwrap();

    let data = read_response(&mut client_stream2).await;
    let (_, messages) = parse_ldap_messages(&data).unwrap();

    match &messages[0].protocol_op {
        ProtocolOp::BindResponse(response) => {
            assert_eq!(
                response.result.result_code,
                ldap_parser::ldap::ResultCode::Success
            );
        }
        other => panic!("unexpected response: {:?}", other),
    }

    // For anonymous bind, FSM might still be considered "authenticated" but with anonymous level
    assert_eq!(fsm_set.auth_level(), AuthLevel::Anonymous);
    assert_eq!(fsm_set.authenticated_dn(), None);
}

#[tokio::test]
async fn test_fsm_backward_compatibility() {
    // Test that FSM authentication produces the same results as direct authentication
    let mut fsm_backend = MockAuthTestDirectory::new();
    let mut direct_backend = MockAuthTestDirectory::new();
    
    // Both should behave identically
    fsm_backend
        .expect_authenticate()
        .withf(|dn, password| dn == "cn=test,dc=example,dc=org" && password == b"password")
        .returning(|_, _| Ok(true));
        
    direct_backend
        .expect_authenticate()
        .withf(|dn, password| dn == "cn=test,dc=example,dc=org" && password == b"password")
        .returning(|_, _| Ok(true));

    let request = BindRequest {
        version: 3,
        name: LdapDN(Cow::Owned("cn=test,dc=example,dc=org".to_string())),
        authentication: AuthenticationChoice::Simple(Cow::Owned(b"password".to_vec())),
    };

    // Test FSM version
    let (server_stream, _) = connected_stream_pair().await;
    let mut fsm_set = ConnectionFsmSet::new(server_stream).expect("Failed to create FSM set");
    fsm_set.configure_auth_backend(Arc::new(fsm_backend));

    let (mut fsm_stream, mut fsm_client) = connected_stream_pair().await;
    handle_bind_request_fsm(&mut fsm_set, &mut fsm_stream, 14, request.clone())
        .await
        .unwrap();

    let fsm_response = read_response(&mut fsm_client).await;
    let (_, fsm_messages) = parse_ldap_messages(&fsm_response).unwrap();

    // Test direct version
    let (mut direct_stream, mut direct_client) = connected_stream_pair().await;
    opendr::server::handle_bind_request(&mut direct_stream, &direct_backend, 14, request)
        .await
        .unwrap();

    let direct_response = read_response(&mut direct_client).await;
    let (_, direct_messages) = parse_ldap_messages(&direct_response).unwrap();

    // Responses should be identical (modulo any FSM-specific behavior)
    assert_eq!(fsm_messages.len(), direct_messages.len());
    if let (ProtocolOp::BindResponse(fsm_resp), ProtocolOp::BindResponse(direct_resp)) = 
        (&fsm_messages[0].protocol_op, &direct_messages[0].protocol_op) {
        assert_eq!(fsm_resp.result.result_code, direct_resp.result.result_code);
        // Note: diagnostic messages might differ slightly due to FSM processing
    }
}
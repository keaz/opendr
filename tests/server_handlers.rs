use std::borrow::Cow;
use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use ldap_parser::filter::{
    Attribute as FilterAttribute, AttributeValue, AttributeValueAssertion, Filter, PartialAttribute,
};
use ldap_parser::ldap::{
    AddRequest, AuthenticationChoice, BindRequest, Change, CompareRequest, DerefAliases,
    ExtendedRequest, LdapDN, LdapOID, LdapString, ModDnRequest, ModifyRequest, Operation,
    ProtocolOp, RelativeLdapDN, SearchRequest, SearchScope,
};
use ldap_parser::parse_ldap_messages;
use mockall::mock;
use opendr::backend::{
    BackendError, DirectoryBackend, DirectoryEntry, Modification, ModifyOperation,
    NativeModifyError, SearchCandidateHint,
};
use opendr::schema::LdapSchema;
use opendr::server;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

mock! {
    pub Directory {}

    #[async_trait]
    impl DirectoryBackend for Directory {
        async fn authenticate(&self, dn: &str, password: &[u8]) -> Result<bool, BackendError>;
        async fn get_entry(&self, dn: &str) -> Result<Option<DirectoryEntry>, BackendError>;
        async fn add_entry(&self, entry: DirectoryEntry, password: Vec<u8>)
            -> Result<(), BackendError>;
        async fn add_entry_with_actor(
            &self,
            entry: DirectoryEntry,
            password: Vec<u8>,
            actor_dn: Option<String>,
        ) -> Result<(), BackendError>;
        async fn delete_entry(&self, dn: &str) -> Result<(), BackendError>;
        async fn modify_entry(
            &self,
            dn: &str,
            modifications: Vec<Modification>,
        ) -> Result<(), BackendError>;
        async fn modify_entry_with_actor(
            &self,
            dn: &str,
            modifications: Vec<Modification>,
            actor_dn: Option<String>,
        ) -> Result<(), BackendError>;
        async fn modify_entry_validated_with_actor(
            &self,
            dn: &str,
            modifications: Vec<Modification>,
            actor_dn: Option<String>,
            schema: &LdapSchema,
        ) -> Result<(), NativeModifyError>;
        async fn compare_attribute(
            &self,
            dn: &str,
            attribute: &str,
            value: &str,
        ) -> Result<bool, BackendError>;
        async fn rename_entry(
            &self,
            dn: &str,
            new_rdn: &str,
            delete_old: bool,
            new_superior: Option<String>,
        ) -> Result<(), BackendError>;
        async fn rename_entry_with_actor(
            &self,
            dn: &str,
            new_rdn: &str,
            delete_old: bool,
            new_superior: Option<String>,
            actor_dn: Option<String>,
        ) -> Result<(), BackendError>;
        async fn search_entries(
            &self,
            base_dn: &str,
            scope: SearchScope,
        ) -> Result<Vec<DirectoryEntry>, BackendError>;
        async fn search_entries_with_hint(
            &self,
            base_dn: &str,
            scope: SearchScope,
            hint: Option<SearchCandidateHint>,
        ) -> Result<Vec<DirectoryEntry>, BackendError>;
        async fn get_context_csn(&self) -> Result<Option<opendr::csn::Csn>, BackendError>;
        async fn set_context_csn(&self, csn: opendr::csn::Csn) -> Result<(), BackendError>;
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

fn person_entry(dn: &str) -> DirectoryEntry {
    DirectoryEntry::new(
        dn,
        HashMap::from([
            (
                "objectClass".to_string(),
                vec!["top".to_string(), "person".to_string()],
            ),
            ("cn".to_string(), vec!["Alice".to_string()]),
            ("sn".to_string(), vec!["Smith".to_string()]),
        ]),
    )
}

fn person_add_attributes(include_password: bool) -> Vec<FilterAttribute<'static>> {
    let mut attributes = vec![
        FilterAttribute {
            attr_type: LdapString(Cow::Owned("objectClass".to_string())),
            attr_vals: vec![AttributeValue(Cow::Owned(b"person".to_vec()))],
        },
        FilterAttribute {
            attr_type: LdapString(Cow::Owned("cn".to_string())),
            attr_vals: vec![AttributeValue(Cow::Owned(b"Alice".to_vec()))],
        },
        FilterAttribute {
            attr_type: LdapString(Cow::Owned("sn".to_string())),
            attr_vals: vec![AttributeValue(Cow::Owned(b"Smith".to_vec()))],
        },
    ];

    if include_password {
        attributes.push(FilterAttribute {
            attr_type: LdapString(Cow::Owned("userPassword".to_string())),
            attr_vals: vec![AttributeValue(Cow::Owned(b"secret".to_vec()))],
        });
    }

    attributes
}

#[tokio::test]
async fn simple_bind_success_returns_success_code() {
    let mut backend = MockDirectory::new();
    backend
        .expect_authenticate()
        .withf(|dn, password| dn == "cn=admin,dc=example,dc=org" && password == b"secret")
        .returning(|_, _| Ok(true));

    let request = BindRequest {
        version: 3,
        name: LdapDN(Cow::Owned("cn=admin,dc=example,dc=org".to_string())),
        authentication: AuthenticationChoice::Simple(Cow::Owned(b"secret".to_vec())),
    };

    let (mut server_stream, mut client_stream) = connected_stream_pair().await;

    server::handle_bind_request(&mut server_stream, &backend, 42, request)
        .await
        .unwrap();

    let data = read_response(&mut client_stream).await;
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
}

#[tokio::test]
async fn simple_bind_invalid_credentials_returns_failure() {
    let mut backend = MockDirectory::new();
    backend.expect_authenticate().returning(|_, _| Ok(false));

    let request = BindRequest {
        version: 3,
        name: LdapDN(Cow::Owned("cn=user,dc=example,dc=org".to_string())),
        authentication: AuthenticationChoice::Simple(Cow::Owned(b"wrong".to_vec())),
    };

    let (mut server_stream, mut client_stream) = connected_stream_pair().await;

    server::handle_bind_request(&mut server_stream, &backend, 7, request)
        .await
        .unwrap();

    let data = read_response(&mut client_stream).await;
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
}

#[tokio::test]
async fn simple_bind_backend_error_returns_unavailable() {
    let mut backend = MockDirectory::new();
    backend
        .expect_authenticate()
        .returning(|_, _| Err(BackendError::Storage("boom".into())));

    let request = BindRequest {
        version: 3,
        name: LdapDN(Cow::Owned("cn=user,dc=example,dc=org".to_string())),
        authentication: AuthenticationChoice::Simple(Cow::Owned(b"secret".to_vec())),
    };

    let (mut server_stream, mut client_stream) = connected_stream_pair().await;

    server::handle_bind_request(&mut server_stream, &backend, 9, request)
        .await
        .unwrap();

    let data = read_response(&mut client_stream).await;
    let (_, messages) = parse_ldap_messages(&data).unwrap();
    match &messages[0].protocol_op {
        ProtocolOp::BindResponse(response) => {
            assert_eq!(
                response.result.result_code,
                ldap_parser::ldap::ResultCode::Unavailable
            );
            assert_eq!(
                response.result.diagnostic_message.0.as_ref(),
                "backend failure"
            );
        }
        other => panic!("unexpected response: {:?}", other),
    }
}

#[tokio::test]
async fn search_returns_entries_and_success() {
    let mut backend = MockDirectory::new();
    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["Alice".to_string()]);
    let entry = DirectoryEntry::new("cn=Alice,dc=example,dc=org", attributes);
    let entry_clone = entry.clone();

    backend
        .expect_search_entries_with_hint()
        .withf(|base_dn, scope, hint| {
            base_dn == "dc=example,dc=org"
                && *scope == SearchScope(2)
                && *hint
                    == Some(SearchCandidateHint::Equality {
                        attribute: "cn".to_string(),
                        value: "alice".to_string(),
                    })
        })
        .return_once(move |_, _, _| Ok(vec![entry_clone.clone()]));

    let request = SearchRequest {
        base_object: LdapDN(Cow::Owned("dc=example,dc=org".to_string())),
        scope: SearchScope(2),
        deref_aliases: DerefAliases(0),
        size_limit: 0,
        time_limit: 0,
        types_only: false,
        filter: Filter::EqualityMatch(AttributeValueAssertion {
            attribute_desc: LdapString(Cow::Owned("cn".to_string())),
            assertion_value: Cow::Borrowed(b"Alice"),
        }),
        attributes: vec![LdapString(Cow::Owned("cn".to_string()))],
    };

    let (mut server_stream, mut client_stream) = connected_stream_pair().await;

    server::handle_search_request(&mut server_stream, &backend, 3, request)
        .await
        .unwrap();

    let data = read_response(&mut client_stream).await;
    let (_, messages) = parse_ldap_messages(&data).unwrap();
    assert_eq!(messages.len(), 2);

    match &messages[0].protocol_op {
        ProtocolOp::SearchResultEntry(entry_response) => {
            assert_eq!(
                entry_response.object_name.0.as_ref(),
                "cn=Alice,dc=example,dc=org"
            );
            assert_eq!(entry_response.attributes.len(), 1);
            let attr = &entry_response.attributes[0];
            assert_eq!(attr.attr_type.0.as_ref(), "cn");
            assert_eq!(attr.attr_vals[0].0.as_ref(), b"Alice");
        }
        other => panic!("unexpected response: {:?}", other),
    }

    match &messages[1].protocol_op {
        ProtocolOp::SearchResultDone(result) => {
            assert_eq!(result.result_code, ldap_parser::ldap::ResultCode::Success);
        }
        other => panic!("unexpected completion: {:?}", other),
    }
}

#[tokio::test]
async fn search_backend_error_returns_result_code() {
    let mut backend = MockDirectory::new();
    backend
        .expect_search_entries_with_hint()
        .withf(|base_dn, scope, hint| {
            base_dn == "dc=example,dc=org"
                && *scope == SearchScope(1)
                && *hint
                    == Some(SearchCandidateHint::Present {
                        attribute: "cn".to_string(),
                    })
        })
        .returning(|_, _, _| Err(BackendError::NotFound));

    let request = SearchRequest {
        base_object: LdapDN(Cow::Owned("dc=example,dc=org".to_string())),
        scope: SearchScope(1),
        deref_aliases: DerefAliases(0),
        size_limit: 0,
        time_limit: 0,
        types_only: false,
        filter: Filter::Present(LdapString(Cow::Owned("cn".to_string()))),
        attributes: vec![LdapString(Cow::Owned("cn".to_string()))],
    };

    let (mut server_stream, mut client_stream) = connected_stream_pair().await;

    server::handle_search_request(&mut server_stream, &backend, 11, request)
        .await
        .unwrap();

    let data = read_response(&mut client_stream).await;
    let (_, messages) = parse_ldap_messages(&data).unwrap();
    assert_eq!(messages.len(), 1);

    match &messages[0].protocol_op {
        ProtocolOp::SearchResultDone(result) => {
            assert_eq!(
                result.result_code,
                ldap_parser::ldap::ResultCode::NoSuchObject
            );
            assert_eq!(result.diagnostic_message.0.as_ref(), "no such object");
        }
        other => panic!("unexpected response: {:?}", other),
    }
}

#[tokio::test]
async fn base_object_search_uses_get_entry_fast_path() {
    let mut backend = MockDirectory::new();
    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["Alice".to_string()]);
    attributes.insert("objectclass".to_string(), vec!["person".to_string()]);
    let entry = DirectoryEntry::new("cn=Alice,dc=example,dc=org", attributes);

    backend
        .expect_get_entry()
        .withf(|dn| dn == "cn=Alice,dc=example,dc=org")
        .times(1)
        .return_once(|_| Ok(Some(entry)));
    backend.expect_search_entries_with_hint().times(0);

    let request = SearchRequest {
        base_object: LdapDN(Cow::Owned("cn=Alice,dc=example,dc=org".to_string())),
        scope: SearchScope::BaseObject,
        deref_aliases: DerefAliases(0),
        size_limit: 0,
        time_limit: 0,
        types_only: false,
        filter: Filter::EqualityMatch(AttributeValueAssertion {
            attribute_desc: LdapString(Cow::Owned("cn".to_string())),
            assertion_value: Cow::Borrowed(b"Alice"),
        }),
        attributes: vec![LdapString(Cow::Owned("cn".to_string()))],
    };

    let (mut server_stream, mut client_stream) = connected_stream_pair().await;

    server::handle_search_request(&mut server_stream, &backend, 12, request)
        .await
        .unwrap();

    let data = read_response(&mut client_stream).await;
    let (_, messages) = parse_ldap_messages(&data).unwrap();
    assert_eq!(messages.len(), 2);

    match &messages[0].protocol_op {
        ProtocolOp::SearchResultEntry(entry_response) => {
            assert_eq!(
                entry_response.object_name.0.as_ref(),
                "cn=Alice,dc=example,dc=org"
            );
        }
        other => panic!("unexpected response: {:?}", other),
    }

    match &messages[1].protocol_op {
        ProtocolOp::SearchResultDone(result) => {
            assert_eq!(result.result_code, ldap_parser::ldap::ResultCode::Success);
        }
        other => panic!("unexpected completion: {:?}", other),
    }
}

#[tokio::test]
async fn modify_success_returns_success_response() {
    let mut backend = MockDirectory::new();
    backend
        .expect_modify_entry_validated_with_actor()
        .withf(|dn, modifications, actor_dn, _schema| {
            dn == "cn=Alice,dc=example,dc=org"
                && modifications.len() == 1
                && modifications[0].operation == ModifyOperation::Replace
                && modifications[0].attribute == "cn"
                && modifications[0].values == ["Alice Updated"]
                && actor_dn.is_none()
        })
        .return_once(|_, _, _, _| Ok(()));

    let request = ModifyRequest {
        object: LdapDN(Cow::Owned("cn=Alice,dc=example,dc=org".to_string())),
        changes: vec![Change {
            operation: Operation(2),
            modification: PartialAttribute {
                attr_type: LdapString(Cow::Owned("cn".to_string())),
                attr_vals: vec![AttributeValue(Cow::Owned(b"Alice Updated".to_vec()))],
            },
        }],
    };

    let (mut server_stream, mut client_stream) = connected_stream_pair().await;

    server::handle_modify_request(&mut server_stream, &backend, 13, request)
        .await
        .unwrap();

    let data = read_response(&mut client_stream).await;
    let (_, messages) = parse_ldap_messages(&data).unwrap();
    assert_eq!(messages.len(), 1);

    match &messages[0].protocol_op {
        ProtocolOp::ModifyResponse(response) => {
            assert_eq!(
                response.result.result_code,
                ldap_parser::ldap::ResultCode::Success
            );
        }
        other => panic!("unexpected response: {:?}", other),
    }
}

#[tokio::test]
async fn modify_backend_error_returns_mapping() {
    let mut backend = MockDirectory::new();
    backend
        .expect_modify_entry_validated_with_actor()
        .returning(|_, _, _, _| Err(NativeModifyError::Backend(BackendError::NotFound)));

    let request = ModifyRequest {
        object: LdapDN(Cow::Owned("cn=Missing,dc=example,dc=org".to_string())),
        changes: vec![],
    };

    let (mut server_stream, mut client_stream) = connected_stream_pair().await;

    server::handle_modify_request(&mut server_stream, &backend, 21, request)
        .await
        .unwrap();

    let data = read_response(&mut client_stream).await;
    let (_, messages) = parse_ldap_messages(&data).unwrap();

    match &messages[0].protocol_op {
        ProtocolOp::ModifyResponse(response) => {
            assert_eq!(
                response.result.result_code,
                ldap_parser::ldap::ResultCode::NoSuchObject
            );
            assert_eq!(
                response.result.diagnostic_message.0.as_ref(),
                "no such object"
            );
        }
        other => panic!("unexpected response: {:?}", other),
    }
}

#[tokio::test]
async fn add_success_persists_entry() {
    let mut backend = MockDirectory::new();
    backend
        .expect_add_entry_with_actor()
        .withf(|entry, password, actor_dn| {
            entry.dn == "cn=Alice,dc=example,dc=org"
                && entry
                    .attributes
                    .get("cn")
                    .map(|values| values == &["Alice".to_string()])
                    .unwrap_or(false)
                && password == b"secret"
                && actor_dn.is_none()
        })
        .return_once(|_, _, _| Ok(()));

    let request = AddRequest {
        entry: LdapDN(Cow::Owned("cn=Alice,dc=example,dc=org".to_string())),
        attributes: person_add_attributes(true),
    };

    let (mut server_stream, mut client_stream) = connected_stream_pair().await;
    let schema = LdapSchema::default();

    server::handle_add_request(&mut server_stream, &backend, &schema, 15, request)
        .await
        .unwrap();

    let data = read_response(&mut client_stream).await;
    let (_, messages) = parse_ldap_messages(&data).unwrap();

    match &messages[0].protocol_op {
        ProtocolOp::AddResponse(response) => {
            assert_eq!(response.result_code, ldap_parser::ldap::ResultCode::Success);
        }
        other => panic!("unexpected response: {:?}", other),
    }
}

#[tokio::test]
async fn add_existing_entry_returns_error() {
    let mut backend = MockDirectory::new();
    backend
        .expect_add_entry_with_actor()
        .returning(|_, _, _| Err(BackendError::AlreadyExists));

    let request = AddRequest {
        entry: LdapDN(Cow::Owned("cn=Alice,dc=example,dc=org".to_string())),
        attributes: person_add_attributes(false),
    };

    let (mut server_stream, mut client_stream) = connected_stream_pair().await;
    let schema = LdapSchema::default();

    server::handle_add_request(&mut server_stream, &backend, &schema, 16, request)
        .await
        .unwrap();

    let data = read_response(&mut client_stream).await;
    let (_, messages) = parse_ldap_messages(&data).unwrap();

    match &messages[0].protocol_op {
        ProtocolOp::AddResponse(response) => {
            assert_eq!(
                response.result_code,
                ldap_parser::ldap::ResultCode::EntryAlreadyExists
            );
            assert_eq!(
                response.diagnostic_message.0.as_ref(),
                "entry already exists"
            );
        }
        other => panic!("unexpected response: {:?}", other),
    }
}

#[tokio::test]
async fn delete_success_returns_success_result() {
    let mut backend = MockDirectory::new();
    backend
        .expect_delete_entry()
        .withf(|dn| dn == "cn=Alice,dc=example,dc=org")
        .return_once(|_| Ok(()));

    let request_dn = LdapDN(Cow::Owned("cn=Alice,dc=example,dc=org".to_string()));

    let (mut server_stream, mut client_stream) = connected_stream_pair().await;

    server::handle_delete_request(&mut server_stream, &backend, 17, request_dn)
        .await
        .unwrap();

    let data = read_response(&mut client_stream).await;
    let (_, messages) = parse_ldap_messages(&data).unwrap();

    match &messages[0].protocol_op {
        ProtocolOp::DelResponse(response) => {
            assert_eq!(response.result_code, ldap_parser::ldap::ResultCode::Success);
        }
        other => panic!("unexpected response: {:?}", other),
    }
}

#[tokio::test]
async fn delete_missing_entry_returns_error() {
    let mut backend = MockDirectory::new();
    backend
        .expect_delete_entry()
        .returning(|_| Err(BackendError::NotFound));

    let request_dn = LdapDN(Cow::Owned("cn=Missing,dc=example,dc=org".to_string()));

    let (mut server_stream, mut client_stream) = connected_stream_pair().await;

    server::handle_delete_request(&mut server_stream, &backend, 18, request_dn)
        .await
        .unwrap();

    let data = read_response(&mut client_stream).await;
    let (_, messages) = parse_ldap_messages(&data).unwrap();

    match &messages[0].protocol_op {
        ProtocolOp::DelResponse(response) => {
            assert_eq!(
                response.result_code,
                ldap_parser::ldap::ResultCode::NoSuchObject
            );
        }
        other => panic!("unexpected response: {:?}", other),
    }
}

#[tokio::test]
async fn moddn_successful_rename_returns_success() {
    let mut backend = MockDirectory::new();
    backend
        .expect_get_entry()
        .withf(|dn| dn == "cn=Alice,dc=example,dc=org")
        .return_once(|_| Ok(Some(person_entry("cn=Alice,dc=example,dc=org"))));
    backend
        .expect_rename_entry_with_actor()
        .withf(|dn, new_rdn, delete_old, superior, actor_dn| {
            dn == "cn=Alice,dc=example,dc=org"
                && new_rdn == "cn=Bob"
                && *delete_old
                && superior.is_none()
                && actor_dn.is_none()
        })
        .return_once(|_, _, _, _, _| Ok(()));

    let request = ModDnRequest {
        entry: LdapDN(Cow::Owned("cn=Alice,dc=example,dc=org".to_string())),
        newrdn: RelativeLdapDN(Cow::Owned("cn=Bob".to_string())),
        deleteoldrdn: true,
        newsuperior: None,
    };

    let (mut server_stream, mut client_stream) = connected_stream_pair().await;

    server::handle_moddn_request(&mut server_stream, &backend, 19, request)
        .await
        .unwrap();

    let data = read_response(&mut client_stream).await;
    let (_, messages) = parse_ldap_messages(&data).unwrap();

    match &messages[0].protocol_op {
        ProtocolOp::ModDnResponse(result) => {
            assert_eq!(result.result_code, ldap_parser::ldap::ResultCode::Success);
        }
        other => panic!("unexpected response: {:?}", other),
    }
}

#[tokio::test]
async fn moddn_conflict_returns_error() {
    let mut backend = MockDirectory::new();
    backend
        .expect_get_entry()
        .withf(|dn| dn == "cn=Alice,dc=example,dc=org")
        .return_once(|_| Ok(Some(person_entry("cn=Alice,dc=example,dc=org"))));
    backend
        .expect_rename_entry_with_actor()
        .returning(|_, _, _, _, _| Err(BackendError::AlreadyExists));

    let request = ModDnRequest {
        entry: LdapDN(Cow::Owned("cn=Alice,dc=example,dc=org".to_string())),
        newrdn: RelativeLdapDN(Cow::Owned("cn=Bob".to_string())),
        deleteoldrdn: false,
        newsuperior: None,
    };

    let (mut server_stream, mut client_stream) = connected_stream_pair().await;

    server::handle_moddn_request(&mut server_stream, &backend, 20, request)
        .await
        .unwrap();

    let data = read_response(&mut client_stream).await;
    let (_, messages) = parse_ldap_messages(&data).unwrap();

    match &messages[0].protocol_op {
        ProtocolOp::ModDnResponse(result) => {
            assert_eq!(
                result.result_code,
                ldap_parser::ldap::ResultCode::EntryAlreadyExists
            );
            assert_eq!(result.diagnostic_message.0.as_ref(), "entry already exists");
        }
        other => panic!("unexpected response: {:?}", other),
    }
}

#[tokio::test]
async fn compare_matching_attribute_returns_true() {
    let mut backend = MockDirectory::new();
    let entry = person_entry("cn=Alice,dc=example,dc=org");
    backend
        .expect_get_entry()
        .withf(|dn| dn == "cn=Alice,dc=example,dc=org")
        .return_once(move |_| Ok(Some(entry)));

    let request = CompareRequest {
        entry: LdapDN(Cow::Owned("cn=Alice,dc=example,dc=org".to_string())),
        ava: AttributeValueAssertion {
            attribute_desc: LdapString(Cow::Owned("cn".to_string())),
            assertion_value: Cow::Borrowed(b"Alice"),
        },
    };

    let (mut server_stream, mut client_stream) = connected_stream_pair().await;

    server::handle_compare_request(&mut server_stream, &backend, 22, request)
        .await
        .unwrap();

    let data = read_response(&mut client_stream).await;
    let (_, messages) = parse_ldap_messages(&data).unwrap();

    match &messages[0].protocol_op {
        ProtocolOp::CompareResponse(result) => {
            assert_eq!(
                result.result_code,
                ldap_parser::ldap::ResultCode::CompareTrue
            );
        }
        other => panic!("unexpected response: {:?}", other),
    }
}

#[tokio::test]
async fn compare_non_matching_attribute_returns_false() {
    let mut backend = MockDirectory::new();
    let entry = person_entry("cn=Alice,dc=example,dc=org");
    backend
        .expect_get_entry()
        .withf(|dn| dn == "cn=Alice,dc=example,dc=org")
        .return_once(move |_| Ok(Some(entry)));

    let request = CompareRequest {
        entry: LdapDN(Cow::Owned("cn=Alice,dc=example,dc=org".to_string())),
        ava: AttributeValueAssertion {
            attribute_desc: LdapString(Cow::Owned("cn".to_string())),
            assertion_value: Cow::Borrowed(b"Bob"),
        },
    };

    let (mut server_stream, mut client_stream) = connected_stream_pair().await;

    server::handle_compare_request(&mut server_stream, &backend, 23, request)
        .await
        .unwrap();

    let data = read_response(&mut client_stream).await;
    let (_, messages) = parse_ldap_messages(&data).unwrap();

    match &messages[0].protocol_op {
        ProtocolOp::CompareResponse(result) => {
            assert_eq!(
                result.result_code,
                ldap_parser::ldap::ResultCode::CompareFalse
            );
        }
        other => panic!("unexpected response: {:?}", other),
    }
}

#[tokio::test]
async fn compare_backend_error_maps_to_no_such_object() {
    let mut backend = MockDirectory::new();
    backend
        .expect_get_entry()
        .withf(|dn| dn == "cn=Missing,dc=example,dc=org")
        .returning(|_| Err(BackendError::NotFound));

    let request = CompareRequest {
        entry: LdapDN(Cow::Owned("cn=Missing,dc=example,dc=org".to_string())),
        ava: AttributeValueAssertion {
            attribute_desc: LdapString(Cow::Owned("cn".to_string())),
            assertion_value: Cow::Borrowed(b"Alice"),
        },
    };

    let (mut server_stream, mut client_stream) = connected_stream_pair().await;

    server::handle_compare_request(&mut server_stream, &backend, 24, request)
        .await
        .unwrap();

    let data = read_response(&mut client_stream).await;
    let (_, messages) = parse_ldap_messages(&data).unwrap();

    match &messages[0].protocol_op {
        ProtocolOp::CompareResponse(result) => {
            assert_eq!(
                result.result_code,
                ldap_parser::ldap::ResultCode::NoSuchObject
            );
        }
        other => panic!("unexpected response: {:?}", other),
    }
}

#[tokio::test]
async fn extended_request_returns_protocol_error() {
    let request = ExtendedRequest {
        request_name: LdapOID(Cow::Owned("1.2.3.4".to_string())),
        request_value: None,
    };

    let (server_stream, mut client_stream) = connected_stream_pair().await;
    let mut server_stream = server::ConnectionStream::Plain(server_stream);

    server::handle_extended_request(&mut server_stream, 25, request)
        .await
        .unwrap();

    let data = read_response(&mut client_stream).await;
    let (_, messages) = parse_ldap_messages(&data).unwrap();

    match &messages[0].protocol_op {
        ProtocolOp::ExtendedResponse(response) => {
            assert_eq!(
                response.result.result_code,
                ldap_parser::ldap::ResultCode::ProtocolError
            );
            assert_eq!(
                response.result.diagnostic_message.0.as_ref(),
                "extended operations are not supported"
            );
        }
        other => panic!("unexpected response: {:?}", other),
    }
}

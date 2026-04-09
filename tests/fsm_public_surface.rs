use opendr::fsm_runtime::OperationType;
use opendr::replication_consumer_fsm::ConnectionInfo;
use opendr::replication_provider_fsm::{ConsumerConnection, SyncMode, SyncRequest, SyncResponse};

#[test]
fn replication_modules_are_public_standalone_surfaces() {
    let consumer_connection = ConsumerConnection::with_sync_mode(
        "127.0.0.1:1389".to_string(),
        SyncMode::RefreshAndPersist,
    );
    assert!(consumer_connection.is_persistent_mode());

    let request = SyncRequest::new(
        consumer_connection.consumer_id.clone(),
        "dc=example,dc=org".to_string(),
    )
    .with_cookie("cookie-1".to_string())
    .with_filter("(objectClass=*)".to_string())
    .with_sync_mode(SyncMode::RefreshOnly);
    assert_eq!(request.cookie.as_deref(), Some("cookie-1"));
    assert_eq!(request.filter.as_deref(), Some("(objectClass=*)"));
    assert_eq!(request.sync_mode, SyncMode::RefreshOnly);

    let response = SyncResponse::new(0)
        .with_cookie("cookie-2".to_string())
        .with_entry_count(3);
    assert_eq!(response.result_code, 0);
    assert_eq!(response.cookie.as_deref(), Some("cookie-2"));
    assert_eq!(response.entry_count, 3);

    let connection_info = ConnectionInfo::new(
        "ldap://provider.example.org:389".to_string(),
        "LDAPv3".to_string(),
        true,
    );
    assert_eq!(
        connection_info.provider_url,
        "ldap://provider.example.org:389"
    );
    assert_eq!(connection_info.protocol_version, "LDAPv3");
    assert!(connection_info.is_secure);

    assert_eq!(OperationType::Extended, OperationType::Extended);
}

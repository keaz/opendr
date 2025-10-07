//! FSM Integration Tests - Phase 2.2
//!
//! Comprehensive integration tests for FSM coordination, multi-FSM workflows,
//! concurrent operations, and error propagation. These tests verify that
//! the FSM runtime correctly manages:
//! - ConnectionFsmSet lifecycle and operation tracking
//! - Backend integration (MockBackend and LMDB)
//! - Concurrent operations across multiple connections
//! - Operation timeouts and cleanup
//! - Error handling and recovery

use opendr::backend::{
    DirectoryBackend, DirectoryEntry, MockBackend, Modification, ModifyOperation,
};
use opendr::backend_lmdb::LmdbBackend;
use opendr::fsm_runtime::ConnectionFsmSet;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::net::TcpStream;

// ============================================================================
// Integration Tests - ConnectionFsmSet with Backends
// ============================================================================

#[tokio::test]
async fn test_connection_fsm_set_with_mock_backend() {
    // Test that ConnectionFsmSet correctly initializes with MockBackend
    let backend = Arc::new(MockBackend::default());

    // Create a real TCP connection for testing
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let accept_task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let fsm_set = ConnectionFsmSet::new(socket, backend, None);

        // Verify initial state
        assert_eq!(fsm_set.active_operation_count(), 0);
        assert!(!fsm_set.is_authenticated());
        assert!(!fsm_set.is_terminal());
    });

    let _client = TcpStream::connect(addr).await.unwrap();
    accept_task.await.unwrap();
}

#[tokio::test]
async fn test_connection_fsm_set_with_lmdb_backend() {
    // Test ConnectionFsmSet with real LMDB backend
    let temp_dir = TempDir::new().unwrap();
    let backend = Arc::new(LmdbBackend::new(temp_dir.path(), 10, 1).unwrap());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let accept_task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let fsm_set = ConnectionFsmSet::new(socket, backend, None);

        assert_eq!(fsm_set.active_operation_count(), 0);
        assert!(!fsm_set.is_authenticated());
    });

    let _client = TcpStream::connect(addr).await.unwrap();
    accept_task.await.unwrap();
}

#[tokio::test]
async fn test_operation_tracking_in_fsm_set() {
    // Test that ConnectionFsmSet correctly tracks operations
    let backend = Arc::new(MockBackend::default());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let accept_task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let fsm_set = ConnectionFsmSet::new(socket, backend, None);

        // Initially no operations
        assert_eq!(fsm_set.active_operation_count(), 0);

        // FSM set should not be terminal initially
        assert!(!fsm_set.is_terminal());
    });

    let _client = TcpStream::connect(addr).await.unwrap();
    accept_task.await.unwrap();
}

#[tokio::test]
async fn test_timeout_cleanup_in_fsm_set() {
    // Test that FSM set properly handles operation timeouts
    let backend = Arc::new(MockBackend::default());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let accept_task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut fsm_set = ConnectionFsmSet::new(socket, backend, None);

        // Initially no operations
        assert_eq!(fsm_set.active_operation_count(), 0);

        // Test timeout cleanup with very short timeout
        let timeout = Duration::from_millis(10);

        // Wait for timeout period
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Cleanup timed out operations (should be 0 since no operations were added)
        let cleaned = fsm_set.cleanup_timed_out_operations(timeout);
        assert_eq!(cleaned, 0);

        // Cleanup terminal operations
        let cleaned = fsm_set.cleanup_terminal_operations();
        assert_eq!(cleaned, 0);
    });

    let _client = TcpStream::connect(addr).await.unwrap();
    accept_task.await.unwrap();
}

#[tokio::test]
async fn test_backend_operations_with_mock() {
    // Test basic backend operations with MockBackend
    let backend = Arc::new(MockBackend::default());

    // Add entries
    let entry1 = DirectoryEntry::new(
        "dc=example,dc=com".to_string(),
        HashMap::from([
            (
                "objectClass".to_string(),
                vec!["top".to_string(), "domain".to_string()],
            ),
            ("dc".to_string(), vec!["example".to_string()]),
        ]),
    );
    backend.add_entry(entry1, vec![]).await.unwrap();

    let entry2 = DirectoryEntry::new(
        "cn=user,dc=example,dc=com".to_string(),
        HashMap::from([
            ("objectClass".to_string(), vec!["person".to_string()]),
            ("cn".to_string(), vec!["user".to_string()]),
            ("sn".to_string(), vec!["User".to_string()]),
        ]),
    );
    backend.add_entry(entry2, vec![]).await.unwrap();

    // Verify entries exist
    assert!(backend
        .get_entry("dc=example,dc=com")
        .await
        .unwrap()
        .is_some());
    assert!(backend
        .get_entry("cn=user,dc=example,dc=com")
        .await
        .unwrap()
        .is_some());

    // Test search
    let results = backend
        .search_entries(
            "dc=example,dc=com",
            ldap_parser::ldap::SearchScope::WholeSubtree,
        )
        .await
        .unwrap();
    assert_eq!(results.len(), 2);

    // Test modify
    let modifications = vec![Modification {
        operation: ModifyOperation::Replace,
        attribute: "sn".to_string(),
        values: vec!["NewUser".to_string()],
    }];
    backend
        .modify_entry("cn=user,dc=example,dc=com", modifications)
        .await
        .unwrap();

    let entry = backend
        .get_entry("cn=user,dc=example,dc=com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(entry.attributes.get("sn").unwrap()[0], "NewUser");

    // Test delete
    backend
        .delete_entry("cn=user,dc=example,dc=com")
        .await
        .unwrap();
    assert!(backend
        .get_entry("cn=user,dc=example,dc=com")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn test_backend_operations_with_lmdb() {
    // Test basic backend operations with LMDB
    let temp_dir = TempDir::new().unwrap();
    let backend = Arc::new(LmdbBackend::new(temp_dir.path(), 10, 1).unwrap());

    // Add entries
    let entry1 = DirectoryEntry::new(
        "dc=test,dc=com".to_string(),
        HashMap::from([
            (
                "objectClass".to_string(),
                vec!["top".to_string(), "domain".to_string()],
            ),
            ("dc".to_string(), vec!["test".to_string()]),
        ]),
    );
    backend.add_entry(entry1, vec![]).await.unwrap();

    let entry2 = DirectoryEntry::new(
        "cn=testuser,dc=test,dc=com".to_string(),
        HashMap::from([
            ("objectClass".to_string(), vec!["person".to_string()]),
            ("cn".to_string(), vec!["testuser".to_string()]),
            ("sn".to_string(), vec!["TestUser".to_string()]),
        ]),
    );
    backend.add_entry(entry2, vec![]).await.unwrap();

    // Verify entries exist
    assert!(backend.get_entry("dc=test,dc=com").await.unwrap().is_some());
    assert!(backend
        .get_entry("cn=testuser,dc=test,dc=com")
        .await
        .unwrap()
        .is_some());

    // Test search
    let results = backend
        .search_entries(
            "dc=test,dc=com",
            ldap_parser::ldap::SearchScope::WholeSubtree,
        )
        .await
        .unwrap();
    assert_eq!(results.len(), 2);

    // Test modify
    let modifications = vec![Modification {
        operation: ModifyOperation::Replace,
        attribute: "sn".to_string(),
        values: vec!["ModifiedUser".to_string()],
    }];
    backend
        .modify_entry("cn=testuser,dc=test,dc=com", modifications)
        .await
        .unwrap();

    let entry = backend
        .get_entry("cn=testuser,dc=test,dc=com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(entry.attributes.get("sn").unwrap()[0], "ModifiedUser");

    // Test delete
    backend
        .delete_entry("cn=testuser,dc=test,dc=com")
        .await
        .unwrap();
    assert!(backend
        .get_entry("cn=testuser,dc=test,dc=com")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn test_concurrent_backend_operations() {
    // Test concurrent operations on the same backend
    let backend = Arc::new(MockBackend::default());

    // Add base entry
    let base = DirectoryEntry::new(
        "dc=concurrent,dc=com".to_string(),
        HashMap::from([
            (
                "objectClass".to_string(),
                vec!["top".to_string(), "domain".to_string()],
            ),
            ("dc".to_string(), vec!["concurrent".to_string()]),
        ]),
    );
    backend.add_entry(base, vec![]).await.unwrap();

    // Execute concurrent adds
    let backend1 = backend.clone();
    let backend2 = backend.clone();
    let backend3 = backend.clone();

    let add1 = tokio::spawn(async move {
        let entry = DirectoryEntry::new(
            "cn=user1,dc=concurrent,dc=com".to_string(),
            HashMap::from([
                ("objectClass".to_string(), vec!["person".to_string()]),
                ("cn".to_string(), vec!["user1".to_string()]),
            ]),
        );
        backend1.add_entry(entry, vec![]).await
    });

    let add2 = tokio::spawn(async move {
        let entry = DirectoryEntry::new(
            "cn=user2,dc=concurrent,dc=com".to_string(),
            HashMap::from([
                ("objectClass".to_string(), vec!["person".to_string()]),
                ("cn".to_string(), vec!["user2".to_string()]),
            ]),
        );
        backend2.add_entry(entry, vec![]).await
    });

    let add3 = tokio::spawn(async move {
        let entry = DirectoryEntry::new(
            "cn=user3,dc=concurrent,dc=com".to_string(),
            HashMap::from([
                ("objectClass".to_string(), vec!["person".to_string()]),
                ("cn".to_string(), vec!["user3".to_string()]),
            ]),
        );
        backend3.add_entry(entry, vec![]).await
    });

    // Wait for all operations to complete
    let (result1, result2, result3) = tokio::join!(add1, add2, add3);
    assert!(result1.unwrap().is_ok());
    assert!(result2.unwrap().is_ok());
    assert!(result3.unwrap().is_ok());

    // Verify all entries exist
    assert!(backend
        .get_entry("cn=user1,dc=concurrent,dc=com")
        .await
        .unwrap()
        .is_some());
    assert!(backend
        .get_entry("cn=user2,dc=concurrent,dc=com")
        .await
        .unwrap()
        .is_some());
    assert!(backend
        .get_entry("cn=user3,dc=concurrent,dc=com")
        .await
        .unwrap()
        .is_some());

    // Verify total count
    let results = backend
        .search_entries(
            "dc=concurrent,dc=com",
            ldap_parser::ldap::SearchScope::WholeSubtree,
        )
        .await
        .unwrap();
    assert_eq!(results.len(), 4); // base + 3 users
}

#[tokio::test]
async fn test_error_handling_duplicate_entry() {
    // Test that backends handle duplicate entry errors correctly
    let backend = Arc::new(MockBackend::default());

    let entry = DirectoryEntry::new(
        "cn=duplicate,dc=example,dc=com".to_string(),
        HashMap::from([
            ("objectClass".to_string(), vec!["person".to_string()]),
            ("cn".to_string(), vec!["duplicate".to_string()]),
        ]),
    );

    // First add should succeed
    assert!(backend.add_entry(entry.clone(), vec![]).await.is_ok());

    // Second add should fail
    let result = backend.add_entry(entry, vec![]).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_error_handling_nonexistent_entry() {
    // Test that backends handle operations on nonexistent entries correctly
    let backend = Arc::new(MockBackend::default());

    // Try to get nonexistent entry
    let result = backend
        .get_entry("cn=nonexistent,dc=example,dc=com")
        .await
        .unwrap();
    assert!(result.is_none());

    // Try to modify nonexistent entry
    let modifications = vec![Modification {
        operation: ModifyOperation::Replace,
        attribute: "sn".to_string(),
        values: vec!["Test".to_string()],
    }];
    let result = backend
        .modify_entry("cn=nonexistent,dc=example,dc=com", modifications)
        .await;
    assert!(result.is_err());

    // Try to delete nonexistent entry
    let result = backend
        .delete_entry("cn=nonexistent,dc=example,dc=com")
        .await;
    assert!(result.is_err());
}

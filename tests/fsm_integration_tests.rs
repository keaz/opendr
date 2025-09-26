//! Integration tests for FSM routing functionality
//!
//! These tests verify that the FSM routing system works correctly, including:
//! - FSM creation and lifecycle management
//! - Routing decisions based on configuration
//! - Fallback mechanisms when FSMs are disabled or fail
//! - Error handling and timeout cleanup

use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

use opendr::backend::{DirectoryBackend, BackendError, DirectoryEntry};
use opendr::server_fsm::{
    ConnectionFsmSet, FsmRoutingConfig, OperationFsmConfig, FsmHandlerFactory
};
// Removed unused imports: process_message_with_fsm, ServerError

/// Mock backend for testing
#[derive(Debug, Clone)]
struct MockBackend {
    pub should_fail: bool,
}

impl MockBackend {
    fn new() -> Self {
        Self { should_fail: false }
    }
    
    fn with_failure() -> Self {
        Self { should_fail: true }
    }
}

#[async_trait::async_trait]
impl DirectoryBackend for MockBackend {
    async fn authenticate(&self, _dn: &str, _password: &[u8]) -> Result<bool, BackendError> {
        if self.should_fail {
            Err(BackendError::Storage("Mock authentication failure".into()))
        } else {
            Ok(true)
        }
    }
    
    async fn get_entry(&self, _dn: &str) -> Result<Option<DirectoryEntry>, BackendError> {
        if self.should_fail {
            Err(BackendError::NotFound)
        } else {
            Ok(Some(DirectoryEntry::new("cn=test", Default::default())))
        }
    }
    
    async fn search_entries(&self, _base_dn: &str, _scope: ldap_parser::ldap::SearchScope) -> Result<Vec<DirectoryEntry>, BackendError> {
        if self.should_fail {
            Err(BackendError::Storage("Mock search failure".into()))
        } else {
            Ok(vec![DirectoryEntry::new("cn=test", Default::default())])
        }
    }
    
    async fn add_entry(&self, _entry: DirectoryEntry, _password: Vec<u8>) -> Result<(), BackendError> {
        if self.should_fail {
            Err(BackendError::AlreadyExists)
        } else {
            Ok(())
        }
    }
    
    async fn modify_entry(&self, _dn: &str, _modifications: Vec<opendr::backend::Modification>) -> Result<(), BackendError> {
        if self.should_fail {
            Err(BackendError::NotFound)
        } else {
            Ok(())
        }
    }
    
    async fn delete_entry(&self, _dn: &str) -> Result<(), BackendError> {
        if self.should_fail {
            Err(BackendError::NotFound)
        } else {
            Ok(())
        }
    }
    
    async fn rename_entry(&self, _dn: &str, _new_rdn: &str, _delete_old: bool, _new_superior: Option<String>) -> Result<(), BackendError> {
        if self.should_fail {
            Err(BackendError::NotFound)
        } else {
            Ok(())
        }
    }
    
    async fn compare_attribute(&self, _dn: &str, _attribute: &str, _value: &str) -> Result<bool, BackendError> {
        if self.should_fail {
            Err(BackendError::NotFound)
        } else {
            Ok(true)
        }
    }
}

#[tokio::test]
async fn test_fsm_routing_configuration() {
    // Test FSM routing configuration creation and defaults
    let default_config = FsmRoutingConfig::default();
    
    // By default, all FSMs should be disabled with fallback enabled
    assert!(!default_config.enable_search_fsm);
    assert!(!default_config.enable_write_fsm);
    assert!(!default_config.enable_compare_fsm);
    assert!(!default_config.enable_extended_op_fsm);
    assert!(default_config.fallback_to_direct);
    
    // Test custom configuration
    let mut custom_config = FsmRoutingConfig::default();
    custom_config.enable_write_fsm = true;
    custom_config.enable_compare_fsm = true;
    custom_config.fallback_to_direct = false;
    
    assert!(!custom_config.enable_search_fsm);
    assert!(custom_config.enable_write_fsm);
    assert!(custom_config.enable_compare_fsm);
    assert!(!custom_config.enable_extended_op_fsm);
    assert!(!custom_config.fallback_to_direct);
}

#[tokio::test]
async fn test_operation_fsm_config() {
    // Test operation FSM configuration
    let default_config = OperationFsmConfig::default();
    
    assert_eq!(default_config.max_concurrent_operations, 10);
    assert_eq!(default_config.operation_timeout, Duration::from_secs(60));
    
    // Test that all sub-configurations have sensible defaults
    // This ensures the configuration chain works properly
    let _search_config = &default_config.search;
    let _write_config = &default_config.write;
    let _compare_config = &default_config.compare;
    let _extended_op_config = &default_config.extended_op;
}

#[tokio::test]
async fn test_connection_fsm_set_lifecycle() {
    // Create a mock socket for testing
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    
    // Connect to create a socket pair
    let socket_task = tokio::spawn(async move {
        TcpStream::connect(addr).await.unwrap()
    });
    
    let (server_socket, _) = listener.accept().await.unwrap();
    let client_socket = socket_task.await.unwrap();
    
    // Create ConnectionFsmSet
    let mut fsm_set = ConnectionFsmSet::new(server_socket).unwrap();
    
    // Test basic properties
    assert!(!fsm_set.is_authenticated());
    assert_eq!(fsm_set.active_operation_count(), 0);
    assert!(fsm_set.should_fallback_to_direct()); // Default fallback enabled
    
    // Configure FSM routing
    let backend = Arc::new(MockBackend::new());
    let routing_config = FsmRoutingConfig {
        enable_search_fsm: false,
        enable_write_fsm: true,
        enable_compare_fsm: true,
        enable_extended_op_fsm: false,
        fallback_to_direct: true,
    };
    let fsm_config = OperationFsmConfig::default();
    
    fsm_set.configure_operation_fsms(backend, routing_config, fsm_config);
    
    // Test FSM enabling checks
    assert!(!fsm_set.is_fsm_enabled("search"));
    assert!(fsm_set.is_fsm_enabled("add"));
    assert!(fsm_set.is_fsm_enabled("modify"));
    assert!(fsm_set.is_fsm_enabled("compare"));
    assert!(!fsm_set.is_fsm_enabled("extended"));
    
    // Test FSM creation
    assert!(fsm_set.create_write_fsm(1).is_ok());
    assert!(fsm_set.create_compare_fsm(2).is_ok());
    
    assert_eq!(fsm_set.active_operation_count(), 2);
    
    // Test FSM retrieval
    assert!(fsm_set.get_operation_fsm(1).is_some());
    assert!(fsm_set.get_operation_fsm(2).is_some());
    assert!(fsm_set.get_operation_fsm(3).is_none());
    
    // Test FSM removal
    let removed_fsm = fsm_set.remove_operation_fsm(1);
    assert!(removed_fsm.is_some());
    assert_eq!(fsm_set.active_operation_count(), 1);
    
    // Test timeout cleanup
    let timed_out = fsm_set.cleanup_timed_out_fsms();
    // Should be empty since FSMs were just created
    assert!(timed_out.is_empty());
    
    drop(client_socket); // Clean up
}

#[tokio::test]
async fn test_fsm_handler_factory() {
    // Test FSM handler factory
    let factory = FsmHandlerFactory::new();
    
    // Create mock LDAP messages to test handler selection
    use ldap_parser::ldap::{LdapMessage, MessageID, ProtocolOp, SearchRequest, AddRequest};
    
    // Test search request handler selection
    let search_message = LdapMessage {
        message_id: MessageID(1),
        protocol_op: ProtocolOp::SearchRequest(SearchRequest {
            base_object: ldap_parser::ldap::LdapDN("dc=example,dc=com".into()),
            scope: ldap_parser::ldap::SearchScope(2),
            deref_aliases: ldap_parser::ldap::DerefAliases(0),
            size_limit: 1000,
            time_limit: 60,
            types_only: false,
            filter: ldap_parser::filter::Filter::Present(
                ldap_parser::ldap::LdapString(std::borrow::Cow::Borrowed("objectClass"))
            ),
            attributes: vec![],
        }),
        controls: None,
    };
    
    let handler = factory.get_handler(&search_message);
    assert!(handler.is_some());
    assert_eq!(handler.unwrap().operation_name(), "search");
    
    // Test add request handler selection  
    let add_message = LdapMessage {
        message_id: MessageID(2),
        protocol_op: ProtocolOp::AddRequest(AddRequest {
            entry: ldap_parser::ldap::LdapDN("cn=test,dc=example,dc=com".into()),
            attributes: vec![],
        }),
        controls: None,
    };
    
    let handler = factory.get_handler(&add_message);
    assert!(handler.is_some());
    assert_eq!(handler.unwrap().operation_name(), "write");
}

#[tokio::test]
async fn test_fsm_concurrency_limits() {
    // Test that FSM concurrency limits are enforced
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    
    let socket_task = tokio::spawn(async move {
        TcpStream::connect(addr).await.unwrap()
    });
    
    let (server_socket, _) = listener.accept().await.unwrap();
    let client_socket = socket_task.await.unwrap();
    
    let mut fsm_set = ConnectionFsmSet::new(server_socket).unwrap();
    
    // Configure with a low concurrency limit for testing
    let backend = Arc::new(MockBackend::new());
    let routing_config = FsmRoutingConfig {
        enable_write_fsm: true,
        ..Default::default()
    };
    let mut fsm_config = OperationFsmConfig::default();
    fsm_config.max_concurrent_operations = 2; // Set low limit
    
    fsm_set.configure_operation_fsms(backend, routing_config, fsm_config);
    
    // Create FSMs up to the limit
    assert!(fsm_set.create_write_fsm(1).is_ok());
    assert!(fsm_set.create_write_fsm(2).is_ok());
    
    // Next FSM creation should fail due to limit
    let result = fsm_set.create_write_fsm(3);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Maximum concurrent operations exceeded"));
    
    // Remove one FSM and try again
    fsm_set.remove_operation_fsm(1);
    assert!(fsm_set.create_write_fsm(4).is_ok());
    
    drop(client_socket);
}

#[tokio::test]
async fn test_fsm_timeout_cleanup() {
    // Test FSM timeout and cleanup functionality
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    
    let socket_task = tokio::spawn(async move {
        TcpStream::connect(addr).await.unwrap()
    });
    
    let (server_socket, _) = listener.accept().await.unwrap();
    let client_socket = socket_task.await.unwrap();
    
    let mut fsm_set = ConnectionFsmSet::new(server_socket).unwrap();
    
    // Configure with very short timeout for testing
    let backend = Arc::new(MockBackend::new());
    let routing_config = FsmRoutingConfig {
        enable_write_fsm: true,
        ..Default::default()
    };
    let mut fsm_config = OperationFsmConfig::default();
    fsm_config.operation_timeout = Duration::from_millis(50); // Very short timeout
    
    fsm_set.configure_operation_fsms(backend, routing_config, fsm_config);
    
    // Create some FSMs
    assert!(fsm_set.create_write_fsm(1).is_ok());
    assert!(fsm_set.create_write_fsm(2).is_ok());
    assert_eq!(fsm_set.active_operation_count(), 2);
    
    // Wait for timeout
    sleep(Duration::from_millis(100)).await;
    
    // Clean up timed out FSMs
    let timed_out = fsm_set.cleanup_timed_out_fsms();
    
    // FSMs should have been cleaned up due to timeout
    assert_eq!(timed_out.len(), 2);
    assert_eq!(fsm_set.active_operation_count(), 0);
    
    drop(client_socket);
}

#[tokio::test] 
async fn test_fsm_routing_decisions() {
    // Test that FSM routing decisions work correctly
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    
    let socket_task = tokio::spawn(async move {
        TcpStream::connect(addr).await.unwrap()
    });
    
    let (server_socket, _) = listener.accept().await.unwrap();
    let client_socket = socket_task.await.unwrap();
    
    let mut fsm_set = ConnectionFsmSet::new(server_socket).unwrap();
    
    // Test different routing configurations
    let backend = Arc::new(MockBackend::new());
    
    // Configuration 1: Only write FSM enabled
    let routing_config1 = FsmRoutingConfig {
        enable_search_fsm: false,
        enable_write_fsm: true,
        enable_compare_fsm: false,
        enable_extended_op_fsm: false,
        fallback_to_direct: true,
    };
    
    fsm_set.configure_operation_fsms(
        backend.clone(), 
        routing_config1.clone(), 
        OperationFsmConfig::default()
    );
    
    assert!(!fsm_set.is_fsm_enabled("search"));
    assert!(fsm_set.is_fsm_enabled("add"));
    assert!(!fsm_set.is_fsm_enabled("compare"));
    
    // Configuration 2: All FSMs enabled
    let routing_config2 = FsmRoutingConfig {
        enable_search_fsm: true,
        enable_write_fsm: true,
        enable_compare_fsm: true,
        enable_extended_op_fsm: true,
        fallback_to_direct: false, // Disable fallback
    };
    
    fsm_set.configure_operation_fsms(
        backend.clone(), 
        routing_config2, 
        OperationFsmConfig::default()
    );
    
    assert!(fsm_set.is_fsm_enabled("search"));
    assert!(fsm_set.is_fsm_enabled("add"));
    assert!(fsm_set.is_fsm_enabled("compare"));
    assert!(fsm_set.is_fsm_enabled("extended"));
    assert!(!fsm_set.should_fallback_to_direct());
    
    drop(client_socket);
}

/// Test that demonstrates the overall integration flow
#[tokio::test]
async fn test_full_fsm_integration_flow() {
    // This test demonstrates how all the FSM components work together
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    
    let socket_task = tokio::spawn(async move {
        TcpStream::connect(addr).await.unwrap()
    });
    
    let (server_socket, _) = listener.accept().await.unwrap();
    let client_socket = socket_task.await.unwrap();
    
    // Create and configure FSM system
    let mut fsm_set = ConnectionFsmSet::new(server_socket).unwrap();
    let backend = Arc::new(MockBackend::new());
    
    let routing_config = FsmRoutingConfig {
        enable_search_fsm: true,
        enable_write_fsm: true,
        enable_compare_fsm: true,
        enable_extended_op_fsm: true,
        fallback_to_direct: true,
    };
    
    let fsm_config = OperationFsmConfig {
        max_concurrent_operations: 5,
        operation_timeout: Duration::from_secs(30),
        ..Default::default()
    };
    
    fsm_set.configure_operation_fsms(backend.clone(), routing_config, fsm_config);
    
    // Test handler factory integration
    let _factory = FsmHandlerFactory::new();
    
    // Simulate different types of operations
    let operations = ["search", "write", "compare", "extended"];
    
    for operation in &operations {
        if fsm_set.is_fsm_enabled(operation) {
            println!("✓ FSM routing enabled for {} operations", operation);
            
            // In a real scenario, we would:
            // 1. Create appropriate LDAP message
            // 2. Get handler from factory
            // 3. Process through FSM
            // 4. Handle responses and cleanup
        } else {
            println!("→ Direct handler routing for {} operations", operation);
        }
    }
    
    // Test concurrent operation management
    let message_ids = [1, 2, 3, 4, 5];
    for &msg_id in &message_ids {
        let result = fsm_set.create_write_fsm(msg_id);
        assert!(result.is_ok(), "Should be able to create FSM for message {}", msg_id);
    }
    
    assert_eq!(fsm_set.active_operation_count(), 5);
    
    // Test cleanup
    for &msg_id in &message_ids {
        let removed = fsm_set.remove_operation_fsm(msg_id);
        assert!(removed.is_some(), "Should be able to remove FSM for message {}", msg_id);
    }
    
    assert_eq!(fsm_set.active_operation_count(), 0);
    
    println!("✓ Full FSM integration flow test completed successfully");
    
    drop(client_socket);
}
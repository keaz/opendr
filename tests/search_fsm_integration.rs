//! Integration tests for Search FSM factory integration
//!
//! This test suite verifies that the Search FSM can be correctly created and integrated
//! with the operation FSM factory system.

use std::sync::Arc;
use opendr::backend::MockBackend;
use opendr::server_fsm::operation_fsms::{FsmFactory, OperationFsmConfig, OperationFsmInstance};
use opendr::search_fsm::{SearchBackend, FilterMatcher, EntryFormatter};
use opendr::fsm::{StateMachine, AbandonableFsm, SearchFsm};

#[tokio::test]
async fn test_search_fsm_factory_creation() {
    // Create backend and factory
    let backend = Arc::new(MockBackend::default());
    let factory = FsmFactory::new(backend);
    
    // Create search FSM
    let search_fsm = factory.create_search_fsm();
    
    // Verify it's actually a SearchFsmImpl
    assert_eq!(format!("{:?}", search_fsm.current_state()), "Initializing");
    assert_eq!(search_fsm.entries_sent(), 0);
    assert!(!search_fsm.is_abandoned());
    assert!(!search_fsm.is_terminal());
    assert!(search_fsm.search_params().is_none());
}

#[tokio::test]
async fn test_search_fsm_with_custom_config() {
    // Create backend with custom configuration
    let backend = Arc::new(MockBackend::default());
    
    let mut fsm_config = OperationFsmConfig::default();
    fsm_config.search.default_size_limit = 100;
    fsm_config.search.default_time_limit = 60;
    fsm_config.search.enable_metrics = true;
    
    let factory = FsmFactory::with_config(backend, fsm_config);
    
    // Create search FSM with custom config
    let search_fsm = factory.create_search_fsm();
    
    // Verify configuration was applied
    assert_eq!(search_fsm.config().default_size_limit, 100);
    assert_eq!(search_fsm.config().default_time_limit, 60);
    assert!(search_fsm.config().enable_metrics);
}

#[tokio::test]
async fn test_operation_fsm_instance_enum() {
    // Create backend and factory
    let backend = Arc::new(MockBackend::default());
    let factory = FsmFactory::new(backend);
    
    // Create search FSM and wrap in enum
    let search_fsm = factory.create_search_fsm();
    let fsm_instance = OperationFsmInstance::Search(search_fsm);
    
    // Verify we can match on the enum variant
    match fsm_instance {
        OperationFsmInstance::Search(fsm) => {
            assert_eq!(format!("{:?}", fsm.current_state()), "Initializing");
        },
        _ => panic!("Expected Search FSM instance"),
    }
}

#[tokio::test]
async fn test_search_backend_adapter_basic_functionality() {
    use opendr::server_fsm::operation_fsms::SearchBackendAdapter;
    use opendr::backend::{DirectoryBackend, DirectoryEntry};
    use std::collections::HashMap;
    
    // Create a mock backend with test data
    let mut backend = MockBackend::default();
    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["test user".to_string()]);
    attributes.insert("mail".to_string(), vec!["test@example.com".to_string()]);
    attributes.insert("objectClass".to_string(), vec!["person".to_string(), "inetOrgPerson".to_string()]);
    
    let test_entry = DirectoryEntry::new("cn=test,dc=example,dc=com", attributes);
    backend.add_entry(test_entry.clone(), vec![]).await.unwrap();
    
    let backend_arc = Arc::new(backend);
    let adapter = SearchBackendAdapter::new(backend_arc);
    
    // Test find_candidates
    let candidates = adapter.find_candidates("dc=example,dc=com", 2, "(objectClass=*)").await.unwrap();
    assert!(!candidates.is_empty(), "Should find at least one candidate");
    
    // Test get_entry
    let search_entry = adapter.get_entry("cn=test,dc=example,dc=com", &[]).await.unwrap();
    assert!(search_entry.is_some(), "Should find the test entry");
    
    let entry = search_entry.unwrap();
    assert_eq!(entry.dn, "cn=test,dc=example,dc=com");
    assert_eq!(entry.object_classes, vec!["person", "inetOrgPerson"]);
    assert!(entry.get_attribute("cn").is_some());
    assert!(entry.get_attribute("mail").is_some());
    assert!(entry.get_attribute("objectclass").is_some());
}

#[tokio::test]
async fn test_search_fsm_start_search_operation() {
    use opendr::fsm::{StateMachine, SearchEvent, SearchState};
    
    // Create backend and factory
    let backend = Arc::new(MockBackend::default());
    let factory = FsmFactory::new(backend);
    
    // Create search FSM
    let mut search_fsm = factory.create_search_fsm();
    
    // Start a search operation
    let result = search_fsm.handle_event(SearchEvent::StartSearch {
        base_dn: "dc=example,dc=com".to_string(),
        scope: 2, // Subtree search
        filter: "(objectClass=person)".to_string(),
        attributes: vec!["cn".to_string(), "mail".to_string()],
        size_limit: 100,
        time_limit: 30,
    }).await;
    
    assert!(result.is_ok(), "Search start should succeed");
    assert_eq!(search_fsm.current_state(), &SearchState::FindingCandidates);
    assert!(search_fsm.search_params().is_some(), "Search parameters should be set");
    
    let params = search_fsm.search_params().unwrap();
    assert_eq!(params.base_dn, "dc=example,dc=com");
    assert_eq!(params.scope, 2);
    assert_eq!(params.filter, "(objectClass=person)");
    assert_eq!(params.size_limit, 100);
    assert_eq!(params.time_limit, 30);
}

#[tokio::test]
async fn test_search_fsm_parameter_validation() {
    use opendr::fsm::{StateMachine, SearchEvent};
    use opendr::search_fsm::SearchFsmError;
    
    // Create backend and factory
    let backend = Arc::new(MockBackend::default());
    let factory = FsmFactory::new(backend);
    
    // Create search FSM
    let mut search_fsm = factory.create_search_fsm();
    
    // Test empty base DN validation
    let result = search_fsm.handle_event(SearchEvent::StartSearch {
        base_dn: "".to_string(), // Empty DN should fail
        scope: 2,
        filter: "(objectClass=person)".to_string(),
        attributes: vec![],
        size_limit: 100,
        time_limit: 30,
    }).await;
    
    assert!(result.is_err(), "Empty base DN should fail validation");
    assert!(matches!(result.unwrap_err(), SearchFsmError::InvalidParameters { .. }));
    
    // Test invalid scope validation
    let result = search_fsm.handle_event(SearchEvent::StartSearch {
        base_dn: "dc=example,dc=com".to_string(),
        scope: 5, // Invalid scope should fail
        filter: "(objectClass=person)".to_string(),
        attributes: vec![],
        size_limit: 100,
        time_limit: 30,
    }).await;
    
    assert!(result.is_err(), "Invalid scope should fail validation");
    assert!(matches!(result.unwrap_err(), SearchFsmError::InvalidParameters { .. }));
    
    // Test empty filter validation
    let result = search_fsm.handle_event(SearchEvent::StartSearch {
        base_dn: "dc=example,dc=com".to_string(),
        scope: 2,
        filter: "".to_string(), // Empty filter should fail
        attributes: vec![],
        size_limit: 100,
        time_limit: 30,
    }).await;
    
    assert!(result.is_err(), "Empty filter should fail validation");
    assert!(matches!(result.unwrap_err(), SearchFsmError::InvalidParameters { .. }));
}

#[tokio::test] 
async fn test_default_filter_matcher() {
    use opendr::server_fsm::operation_fsms::DefaultFilterMatcher;
    use opendr::search_fsm::{SearchEntry, FilterMatcher};
    use std::collections::HashMap;
    
    let filter_matcher = DefaultFilterMatcher::new();
    
    // Create test search entry
    let mut entry = SearchEntry::new("cn=test,dc=example,dc=com".to_string());
    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["test user".to_string()]);
    attributes.insert("mail".to_string(), vec!["test@example.com".to_string()]);
    entry.attributes = attributes;
    
    // Test wildcard filter
    let result = filter_matcher.matches_filter(&entry, "(objectClass=*)").await.unwrap();
    assert!(result, "Wildcard filter should match");
    
    // Test simple equality filter
    let result = filter_matcher.matches_filter(&entry, "(cn=test user)").await.unwrap();
    assert!(result, "Equality filter should match");
    
    // Test non-matching filter
    let result = filter_matcher.matches_filter(&entry, "(cn=other user)").await.unwrap();
    assert!(!result, "Non-matching filter should return false");
    
    // Test filter validation
    let result = filter_matcher.validate_filter("(cn=test)").await;
    assert!(result.is_ok(), "Valid filter should pass validation");
    
    let result = filter_matcher.validate_filter("").await;
    assert!(result.is_err(), "Empty filter should fail validation");
}

#[tokio::test]
async fn test_default_entry_formatter() {
    use opendr::server_fsm::operation_fsms::DefaultEntryFormatter;
    use opendr::search_fsm::{SearchEntry, EntryFormatter};
    use std::collections::HashMap;
    
    let formatter = DefaultEntryFormatter::new();
    
    // Create test search entry
    let mut entry = SearchEntry::new("cn=test,dc=example,dc=com".to_string());
    entry.object_classes = vec!["person".to_string(), "inetOrgPerson".to_string()];
    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["test user".to_string()]);
    attributes.insert("mail".to_string(), vec!["test@example.com".to_string()]);
    entry.attributes = attributes;
    
    // Test formatting with all attributes
    let result = formatter.format_entry(&entry, &[]).await.unwrap();
    let formatted = String::from_utf8(result).unwrap();
    
    assert!(formatted.contains("dn: cn=test,dc=example,dc=com"));
    assert!(formatted.contains("objectClass: person"));
    assert!(formatted.contains("objectClass: inetOrgPerson"));
    assert!(formatted.contains("cn: test user"));
    assert!(formatted.contains("mail: test@example.com"));
    
    // Test formatting with specific attributes
    let result = formatter.format_entry(&entry, &["cn".to_string()]).await.unwrap();
    let formatted = String::from_utf8(result).unwrap();
    
    assert!(formatted.contains("cn: test user"));
    assert!(!formatted.contains("mail: test@example.com")); // Should not include mail
    
    // Test entry size calculation
    let size = formatter.calculate_entry_size(&entry, &[]).await.unwrap();
    assert!(size > 0, "Entry size should be greater than 0");
}
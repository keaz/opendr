//! CSN-Based Replication Integration Tests
//!
//! This module tests the complete CSN-based replication system, including:
//! - CSN generation and tracking in changelog
//! - Cookie generation and parsing with CSN
//! - Provider streaming with CSN
//! - Consumer synchronization with CSN-based cookies
//! - Full end-to-end replication with CSN

use opendr::backend::{DirectoryBackend, DirectoryEntry};
use opendr::backend_changelog_wrapper::ChangelogBackendWrapper;
use opendr::replication::{ChangelogTracker, ChangelogProviderImpl};
use opendr::replication_provider_fsm::{ChangeType, ChangelogProvider};
use opendr::csn::{Csn, CsnGenerator};
use opendr::backend::MockBackend;
use std::sync::Arc;
use std::collections::HashMap;

/// Create a test entry with DN and basic attributes
fn create_test_entry(dn: &str, cn: &str) -> DirectoryEntry {
    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec![cn.to_string()]);
    attributes.insert("objectClass".to_string(), vec!["person".to_string()]);
    DirectoryEntry::new(dn, attributes)
}

#[tokio::test]
async fn test_csn_changelog_integration() {
    // Create changelog tracker with specific replica ID
    let changelog = Arc::new(ChangelogTracker::with_replica_id(5));
    
    // Record some changes
    let csn1 = changelog.record_change(
        ChangeType::Add,
        "cn=user1,dc=example,dc=org".to_string(),
        b"user1 data".to_vec(),
    );
    
    let csn2 = changelog.record_change(
        ChangeType::Modify,
        "cn=user2,dc=example,dc=org".to_string(),
        b"user2 data".to_vec(),
    );
    
    let csn3 = changelog.record_change(
        ChangeType::Delete,
        "cn=user3,dc=example,dc=org".to_string(),
        b"user3 data".to_vec(),
    );
    
    // Verify CSNs are properly generated
    assert_eq!(csn1.replica_id(), 5);
    assert_eq!(csn2.replica_id(), 5);
    assert_eq!(csn3.replica_id(), 5);
    
    // Verify CSNs are ordered
    assert!(csn2 > csn1);
    assert!(csn3 > csn2);
    
    // Verify all entries are in changelog
    let all_entries = changelog.get_all();
    assert_eq!(all_entries.len(), 3);
    assert_eq!(all_entries[0].csn, csn1);
    assert_eq!(all_entries[1].csn, csn2);
    assert_eq!(all_entries[2].csn, csn3);
}

#[tokio::test]
async fn test_csn_cookie_generation_and_parsing() {
    let changelog = Arc::new(ChangelogTracker::with_replica_id(1));
    
    // Record a change
    let csn = changelog.record_change(
        ChangeType::Add,
        "cn=test,dc=example,dc=org".to_string(),
        b"test data".to_vec(),
    );
    
    // Generate cookie from CSN
    let cookie = changelog.generate_cookie_from_csn(&csn);
    assert!(cookie.starts_with("csn-"));
    
    // Parse cookie back to CSN
    let parsed_csn = changelog.parse_cookie(&cookie);
    assert!(parsed_csn.is_some());
    assert_eq!(parsed_csn.unwrap(), csn);
    
    // Test context cookie
    let context_cookie = changelog.generate_context_cookie();
    assert!(context_cookie.starts_with("csn-"));
    
    // Parse context cookie
    let context_csn = changelog.parse_cookie(&context_cookie);
    assert!(context_csn.is_some());
}

#[tokio::test]
async fn test_get_since_csn() {
    let changelog = Arc::new(ChangelogTracker::with_replica_id(2));
    
    // Record multiple changes
    let csn1 = changelog.record_change(
        ChangeType::Add,
        "cn=user1,dc=example,dc=org".to_string(),
        b"user1".to_vec(),
    );
    
    let _csn2 = changelog.record_change(
        ChangeType::Modify,
        "cn=user2,dc=example,dc=org".to_string(),
        b"user2".to_vec(),
    );
    
    let csn3 = changelog.record_change(
        ChangeType::Delete,
        "cn=user3,dc=example,dc=org".to_string(),
        b"user3".to_vec(),
    );
    
    // Get entries since csn1 (should get csn2 and csn3)
    let entries_since_csn1 = changelog.get_since_csn(&csn1);
    assert_eq!(entries_since_csn1.len(), 2);
    
    // Get entries since csn3 (should be empty)
    let entries_since_csn3 = changelog.get_since_csn(&csn3);
    assert_eq!(entries_since_csn3.len(), 0);
}

#[tokio::test]
async fn test_backend_wrapper_csn_integration() {
    let backend = Arc::new(MockBackend::new());
    let changelog = Arc::new(ChangelogTracker::with_replica_id(3));
    let wrapper = ChangelogBackendWrapper::new(backend.clone(), Some(changelog.clone()));
    
    // Add entries through wrapper
    let entry1 = create_test_entry("cn=user1,dc=example,dc=org", "User 1");
    wrapper.add_entry(entry1, vec![]).await.unwrap();
    
    let entry2 = create_test_entry("cn=user2,dc=example,dc=org", "User 2");
    wrapper.add_entry(entry2, vec![]).await.unwrap();
    
    // Verify changelog has CSN-based entries
    let entries = changelog.get_all();
    assert_eq!(entries.len(), 2);
    
    // Verify CSNs are assigned
    assert_eq!(entries[0].csn.replica_id(), 3);
    assert_eq!(entries[1].csn.replica_id(), 3);
    
    // Verify CSNs are ordered
    assert!(entries[1].csn > entries[0].csn);
    
    // Verify contextCSN is updated
    let context_csn = changelog.get_context_csn();
    assert!(context_csn.is_some());
    assert_eq!(context_csn.unwrap(), entries[1].csn);
}

#[tokio::test]
async fn test_changelog_provider_with_csn() {
    let backend = Arc::new(MockBackend::new());
    let changelog = ChangelogTracker::with_replica_id(4);
    let provider = ChangelogProviderImpl::new(changelog.clone(), backend.clone());
    
    // Record some changes
    let csn1 = changelog.record_change(
        ChangeType::Add,
        "cn=user1,dc=example,dc=org".to_string(),
        b"user1 data".to_vec(),
    );
    
    let csn2 = changelog.record_change(
        ChangeType::Modify,
        "cn=user2,dc=example,dc=org".to_string(),
        b"user2 data".to_vec(),
    );
    
    // Get contextCSN from provider
    let context_csn = provider.get_context_csn().await.unwrap();
    assert!(context_csn.is_some());
    assert_eq!(context_csn.unwrap(), csn2);
    
    // Generate cookie from latest CSN
    let cookie = provider.generate_cookie(&csn2).await.unwrap();
    assert!(cookie.starts_with("csn-"));
    
    // Validate cookie
    assert!(provider.validate_cookie(&cookie).await.unwrap());
    
    // Get changelog since csn1
    let cookie1 = changelog.generate_cookie_from_csn(&csn1);
    let entries = provider.get_changelog_since(Some(&cookie1), 10).await.unwrap();
    assert_eq!(entries.len(), 1); // Should only get csn2
    assert_eq!(entries[0].csn, csn2);
}

#[tokio::test]
async fn test_csn_incremental_sync() {
    let backend = Arc::new(MockBackend::new());
    let changelog = ChangelogTracker::with_replica_id(6);
    let provider = ChangelogProviderImpl::new(changelog.clone(), backend.clone());
    
    // Initial batch of changes
    let csn1 = changelog.record_change(
        ChangeType::Add,
        "cn=user1,dc=example,dc=org".to_string(),
        b"user1".to_vec(),
    );
    
    let csn2 = changelog.record_change(
        ChangeType::Add,
        "cn=user2,dc=example,dc=org".to_string(),
        b"user2".to_vec(),
    );
    
    // Consumer gets initial sync
    let initial_cookie = "csn-empty";
    let initial_entries = provider.get_changelog_since(Some(initial_cookie), 100).await.unwrap();
    assert_eq!(initial_entries.len(), 2);
    
    // Save cookie from last CSN
    let last_cookie = changelog.generate_cookie_from_csn(&csn2);
    
    // Add more changes
    let csn3 = changelog.record_change(
        ChangeType::Modify,
        "cn=user1,dc=example,dc=org".to_string(),
        b"user1 modified".to_vec(),
    );
    
    let csn4 = changelog.record_change(
        ChangeType::Delete,
        "cn=user3,dc=example,dc=org".to_string(),
        b"user3".to_vec(),
    );
    
    // Consumer gets incremental sync
    let incremental_entries = provider.get_changelog_since(Some(&last_cookie), 100).await.unwrap();
    assert_eq!(incremental_entries.len(), 2); // Should get csn3 and csn4
    assert_eq!(incremental_entries[0].csn, csn3);
    assert_eq!(incremental_entries[1].csn, csn4);
}

#[tokio::test]
async fn test_csn_ordering_across_replicas() {
    // Simulate two replicas
    let gen1 = CsnGenerator::new(1);
    let gen2 = CsnGenerator::new(2);
    
    // Generate CSNs from both replicas
    let csn1_r1 = gen1.generate();
    tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
    let csn1_r2 = gen2.generate();
    tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
    let csn2_r1 = gen1.generate();
    
    // Verify time-based ordering
    assert!(csn1_r2 > csn1_r1); // R2's CSN should be after R1's due to time
    assert!(csn2_r1 > csn1_r2); // Later R1 CSN should be after earlier R2 CSN
}

#[tokio::test]
async fn test_context_csn_tracking() {
    let changelog = Arc::new(ChangelogTracker::with_replica_id(7));
    
    // Initially no contextCSN
    assert!(changelog.get_context_csn().is_none());
    
    // Record first change
    let csn1 = changelog.record_change(
        ChangeType::Add,
        "cn=user1,dc=example,dc=org".to_string(),
        b"user1".to_vec(),
    );
    
    // contextCSN should be csn1
    assert_eq!(changelog.get_context_csn(), Some(csn1.clone()));
    
    // Record second change
    let csn2 = changelog.record_change(
        ChangeType::Modify,
        "cn=user1,dc=example,dc=org".to_string(),
        b"user1 modified".to_vec(),
    );
    
    // contextCSN should be updated to csn2
    assert_eq!(changelog.get_context_csn(), Some(csn2));
}

#[tokio::test]
async fn test_csn_cookie_empty_state() {
    let changelog = Arc::new(ChangelogTracker::with_replica_id(8));
    
    // Generate context cookie when empty
    let empty_cookie = changelog.generate_context_cookie();
    assert_eq!(empty_cookie, "csn-empty");
    
    // Add a change
    let csn = changelog.record_change(
        ChangeType::Add,
        "cn=user1,dc=example,dc=org".to_string(),
        b"user1".to_vec(),
    );
    
    // Context cookie should now have CSN
    let cookie_with_csn = changelog.generate_context_cookie();
    assert_ne!(cookie_with_csn, "csn-empty");
    assert!(cookie_with_csn.contains(&csn.to_string()));
}

#[tokio::test]
async fn test_csn_changelog_pruning() {
    let changelog = Arc::new(ChangelogTracker::with_capacity_and_replica(3, 9));
    
    // Add 5 entries (more than capacity)
    for i in 1..=5 {
        changelog.record_change(
            ChangeType::Add,
            format!("cn=user{},dc=example,dc=org", i),
            format!("user{} data", i).into_bytes(),
        );
        // Small delay to ensure CSN ordering
        tokio::time::sleep(tokio::time::Duration::from_micros(10)).await;
    }
    
    // Should only keep last 3 entries
    let all_entries = changelog.get_all();
    assert!(all_entries.len() <= 3);
    
    // Verify contextCSN still tracks latest
    let context_csn = changelog.get_context_csn();
    assert!(context_csn.is_some());
}

//! Integration tests for operational attributes
//!
//! These tests validate that operational attributes (entryCSN, createTimestamp, etc.)
//! are correctly maintained and searchable.

use opendr::backend::{DirectoryBackend, DirectoryEntry, MockBackend, OperationalAttributes};
use opendr::csn::{Csn, CsnGenerator};
use std::collections::HashMap;
use std::sync::Arc;

#[tokio::test]
async fn test_operational_attributes_creation() {
    let csn = Csn::new(1);
    let op_attrs = OperationalAttributes::for_new_entry(csn.clone(), Some("cn=admin,dc=example,dc=org".to_string()));

    assert_eq!(op_attrs.entry_csn, Some(csn));
    assert!(op_attrs.create_timestamp.is_some());
    assert!(op_attrs.modify_timestamp.is_some());
    assert_eq!(op_attrs.creators_name, Some("cn=admin,dc=example,dc=org".to_string()));
    assert_eq!(op_attrs.modifiers_name, Some("cn=admin,dc=example,dc=org".to_string()));
}

#[tokio::test]
async fn test_operational_attributes_modification() {
    let csn1 = Csn::new(1);
    let mut op_attrs = OperationalAttributes::for_new_entry(csn1, Some("cn=admin,dc=example,dc=org".to_string()));
    
    // Wait a bit to ensure different timestamp
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    
    let csn2 = Csn::new(1);
    op_attrs.for_modified_entry(csn2.clone(), Some("cn=user,dc=example,dc=org".to_string()));

    assert_eq!(op_attrs.entry_csn, Some(csn2));
    assert_eq!(op_attrs.modifiers_name, Some("cn=user,dc=example,dc=org".to_string()));
    // Creators name should remain unchanged
    assert_eq!(op_attrs.creators_name, Some("cn=admin,dc=example,dc=org".to_string()));
}

#[tokio::test]
async fn test_operational_attributes_to_attributes() {
    let generator = CsnGenerator::new(1);
    let csn = generator.generate();
    let op_attrs = OperationalAttributes::for_new_entry(csn.clone(), Some("cn=admin,dc=example,dc=org".to_string()));
    
    let attrs = op_attrs.to_attributes();
    
    assert!(attrs.contains_key("entrycsn"));
    assert!(attrs.contains_key("createtimestamp"));
    assert!(attrs.contains_key("modifytimestamp"));
    assert!(attrs.contains_key("creatorsname"));
    assert!(attrs.contains_key("modifiersname"));
    
    assert_eq!(attrs["entrycsn"][0], csn.to_ldap_string());
}

#[tokio::test]
async fn test_is_operational_attribute() {
    assert!(OperationalAttributes::is_operational("entryCSN"));
    assert!(OperationalAttributes::is_operational("createTimestamp"));
    assert!(OperationalAttributes::is_operational("modifyTimestamp"));
    assert!(OperationalAttributes::is_operational("creatorsName"));
    assert!(OperationalAttributes::is_operational("modifiersName"));
    assert!(OperationalAttributes::is_operational("contextCSN"));
    
    // Not operational
    assert!(!OperationalAttributes::is_operational("cn"));
    assert!(!OperationalAttributes::is_operational("sn"));
    assert!(!OperationalAttributes::is_operational("objectClass"));
}

#[tokio::test]
async fn test_directory_entry_with_operational_attrs() {
    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["test".to_string()]);
    attributes.insert("sn".to_string(), vec!["user".to_string()]);
    
    let generator = CsnGenerator::new(1);
    let csn = generator.generate();
    let op_attrs = OperationalAttributes::for_new_entry(csn.clone(), Some("cn=admin,dc=example,dc=org".to_string()));
    
    let entry = DirectoryEntry::with_operational_attrs(
        "cn=test,dc=example,dc=org",
        attributes,
        op_attrs,
    );
    
    assert_eq!(entry.dn, "cn=test,dc=example,dc=org");
    assert_eq!(entry.operational_attributes.entry_csn, Some(csn));
    assert!(entry.operational_attributes.create_timestamp.is_some());
}

#[tokio::test]
async fn test_mockbackend_with_operational_attrs() {
    let backend = Arc::new(MockBackend::new());
    
    let generator = CsnGenerator::new(1);
    let csn = generator.generate();
    let op_attrs = OperationalAttributes::for_new_entry(csn.clone(), Some("cn=admin,dc=example,dc=org".to_string()));
    
    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["test".to_string()]);
    attributes.insert("sn".to_string(), vec!["user".to_string()]);
    attributes.insert("objectClass".to_string(), vec!["person".to_string()]);
    
    let entry = DirectoryEntry::with_operational_attrs(
        "cn=test,dc=example,dc=org",
        attributes,
        op_attrs.clone(),
    );
    
    backend.add_entry(entry.clone(), vec![]).await.unwrap();
    
    let retrieved = backend.get_entry("cn=test,dc=example,dc=org").await.unwrap().unwrap();
    
    // Verify operational attributes are preserved
    assert_eq!(retrieved.operational_attributes.entry_csn, Some(csn));
    assert!(retrieved.operational_attributes.create_timestamp.is_some());
}

#[tokio::test]
async fn test_csn_generator_for_entries() {
    let generator = CsnGenerator::new(5);
    
    let csn1 = generator.generate();
    let csn2 = generator.generate();
    let csn3 = generator.generate();
    
    // All CSNs should have the same replica ID
    assert_eq!(csn1.replica_id(), 5);
    assert_eq!(csn2.replica_id(), 5);
    assert_eq!(csn3.replica_id(), 5);
    
    // All CSNs should be in order
    assert!(csn2 > csn1);
    assert!(csn3 > csn2);
}

//! Integration tests for contextCSN tracking
//!
//! Tests that contextCSN is properly maintained across different backend operations
//! and persists correctly.

use opendr::backend::{DirectoryBackend, DirectoryEntry};
use opendr::backend_lmdb::LmdbBackend;
use opendr::csn::{Csn, CsnGenerator};
use std::collections::HashMap;
use tempfile::tempdir;

#[tokio::test]
async fn test_context_csn_with_mock_backend() {
    let backend = opendr::backend::MockBackend::new();

    // Initially no contextCSN
    let csn = backend.get_context_csn().await.unwrap();
    assert!(csn.is_none());

    // Set a CSN
    let test_csn = Csn::with_values(1696680896789012, 1, 0, 0);
    backend.set_context_csn(test_csn.clone()).await.unwrap();

    // Verify it's set
    let retrieved = backend.get_context_csn().await.unwrap();
    assert_eq!(retrieved, Some(test_csn));
}

#[tokio::test]
async fn test_context_csn_with_lmdb_backend() {
    let dir = tempdir().unwrap();
    let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

    // Initially no contextCSN
    let csn = backend.get_context_csn().await.unwrap();
    assert!(csn.is_none());

    // Set a CSN
    let test_csn = Csn::with_values(1696680896789012, 1, 0, 0);
    backend.set_context_csn(test_csn.clone()).await.unwrap();

    // Verify it's set
    let retrieved = backend.get_context_csn().await.unwrap();
    assert_eq!(retrieved, Some(test_csn));
}

#[tokio::test]
async fn test_context_csn_ordering() {
    let dir = tempdir().unwrap();
    let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

    // Create CSNs in order
    let csn1 = Csn::with_values(1696680896789012, 1, 0, 0);
    let csn2 = Csn::with_values(1696680896789013, 1, 0, 0);
    let csn3 = Csn::with_values(1696680896789014, 1, 0, 0);

    // Set in order and verify
    backend.set_context_csn(csn1.clone()).await.unwrap();
    assert_eq!(backend.get_context_csn().await.unwrap(), Some(csn1));

    backend.set_context_csn(csn2.clone()).await.unwrap();
    assert_eq!(backend.get_context_csn().await.unwrap(), Some(csn2));

    backend.set_context_csn(csn3.clone()).await.unwrap();
    assert_eq!(backend.get_context_csn().await.unwrap(), Some(csn3));
}

#[tokio::test]
async fn test_context_csn_with_generator() {
    let dir = tempdir().unwrap();
    let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

    // Create a CSN generator
    let generator = CsnGenerator::new(1);

    // Generate some CSNs
    let csn1 = generator.generate();
    backend.set_context_csn(csn1.clone()).await.unwrap();

    std::thread::sleep(std::time::Duration::from_millis(1));

    let csn2 = generator.generate();
    backend.set_context_csn(csn2.clone()).await.unwrap();

    // Verify latest CSN is stored
    let retrieved = backend.get_context_csn().await.unwrap();
    assert!(retrieved.is_some());
    let retrieved_csn = retrieved.unwrap();

    // Should be csn2 (the later one)
    assert_eq!(retrieved_csn, csn2);
    assert!(retrieved_csn > csn1);
}

#[tokio::test]
async fn test_context_csn_persistence_across_reopens() {
    let dir = tempdir().unwrap();
    let path = dir.path().to_path_buf();

    let generator = CsnGenerator::new(1);
    let test_csn = generator.generate();

    // First backend instance - set CSN
    {
        let backend = LmdbBackend::new(&path, 100, 1).unwrap();
        backend.set_context_csn(test_csn.clone()).await.unwrap();
    }

    // Second backend instance - verify persistence
    {
        let backend = LmdbBackend::new(&path, 100, 1).unwrap();
        let retrieved = backend.get_context_csn().await.unwrap();
        assert_eq!(retrieved, Some(test_csn));
    }
}

#[tokio::test]
async fn test_context_csn_with_concurrent_updates() {
    let dir = tempdir().unwrap();
    let backend = std::sync::Arc::new(LmdbBackend::new(dir.path(), 100, 1).unwrap());

    let generator = std::sync::Arc::new(CsnGenerator::new(1));

    // Spawn multiple tasks to update contextCSN concurrently
    let mut handles = vec![];
    for i in 0..10 {
        let backend_clone = backend.clone();
        let generator_clone = generator.clone();

        let handle = tokio::spawn(async move {
            // Small delay to spread out updates
            tokio::time::sleep(tokio::time::Duration::from_micros(i * 10)).await;

            let csn = generator_clone.generate();
            backend_clone.set_context_csn(csn.clone()).await.unwrap();
            csn
        });

        handles.push(handle);
    }

    // Collect all CSNs
    let mut csns = vec![];
    for handle in handles {
        csns.push(handle.await.unwrap());
    }

    // Find the maximum CSN
    let max_csn = csns.iter().max().unwrap();

    // Final contextCSN should be one of the generated CSNs
    let final_csn = backend.get_context_csn().await.unwrap();
    assert!(final_csn.is_some());

    // Final CSN should be less than or equal to max
    assert!(final_csn.unwrap() <= *max_csn);
}

#[tokio::test]
async fn test_context_csn_different_replicas() {
    let dir = tempdir().unwrap();
    let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

    // Create CSNs from different replicas
    let csn_replica1 = Csn::with_values(1696680896789012, 1, 0, 0);
    let csn_replica2 = Csn::with_values(1696680896789013, 2, 0, 0);

    // Set CSN from replica 1
    backend.set_context_csn(csn_replica1.clone()).await.unwrap();
    assert_eq!(backend.get_context_csn().await.unwrap(), Some(csn_replica1));

    // Set CSN from replica 2 (later timestamp)
    backend.set_context_csn(csn_replica2.clone()).await.unwrap();
    assert_eq!(backend.get_context_csn().await.unwrap(), Some(csn_replica2));
}

#[tokio::test]
async fn test_context_csn_serialization_format() {
    let dir = tempdir().unwrap();
    let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

    // Create a CSN with specific values
    let csn = Csn::with_values(1696680896789012, 123, 456, 789);
    backend.set_context_csn(csn.clone()).await.unwrap();

    // Retrieve and verify all components
    let retrieved = backend.get_context_csn().await.unwrap().unwrap();
    assert_eq!(retrieved.timestamp_us(), 1696680896789012);
    assert_eq!(retrieved.replica_id(), 123);
    assert_eq!(retrieved.sequence(), 456);
    assert_eq!(retrieved.mod_number(), 789);

    // Verify LDAP string format (with leading zeros for sequence and mod_number)
    let ldap_string = retrieved.to_ldap_string();
    assert_eq!(ldap_string, "1696680896789012#123#000456#000789");
}

#[tokio::test]
async fn test_context_csn_empty_database() {
    let dir = tempdir().unwrap();
    let backend = LmdbBackend::new(dir.path(), 100, 1).unwrap();

    // Adding an entry should advance contextCSN automatically.
    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["test".to_string()]);
    let entry = DirectoryEntry::new("cn=test,dc=example,dc=org", attributes);
    backend.add_entry(entry, vec![]).await.unwrap();

    // contextCSN should now reflect the write.
    let csn = backend.get_context_csn().await.unwrap();
    assert!(csn.is_some());
}

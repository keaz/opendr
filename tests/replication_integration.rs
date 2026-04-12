//! Replication Integration Tests
//!
//! This test suite validates the end-to-end replication functionality
//! between provider and consumer servers.

use async_trait::async_trait;
use opendr::backend::{DirectoryBackend, DirectoryEntry, MockBackend};
use opendr::backend_changelog_wrapper::ChangelogBackendWrapper;
use opendr::fsm::{
    ReplicationConsumerEvent, ReplicationConsumerFsm, ReplicationConsumerState, ReplicationPhase,
    ReplicationProviderEvent, ReplicationProviderFsm, ReplicationProviderState, StateMachine,
};
use opendr::replication::*;
use opendr::replication_consumer_fsm::*;
use opendr::replication_provider_fsm::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const LOCAL_PROVIDER_URL: &str = "in-memory://provider.example.com";

// Helper to create mock backend with test data
async fn create_test_backend() -> MockBackend {
    let backend = MockBackend::default();

    // Add test entries
    let mut attrs1 = HashMap::new();
    attrs1.insert("cn".to_string(), vec!["user1".to_string()]);
    attrs1.insert("objectclass".to_string(), vec!["person".to_string()]);
    let entry1 = DirectoryEntry::new("cn=user1,dc=example,dc=org", attrs1);
    let _ = backend.add_entry(entry1, b"password1".to_vec()).await;

    let mut attrs2 = HashMap::new();
    attrs2.insert("cn".to_string(), vec!["user2".to_string()]);
    attrs2.insert("objectclass".to_string(), vec!["person".to_string()]);
    let entry2 = DirectoryEntry::new("cn=user2,dc=example,dc=org", attrs2);
    let _ = backend.add_entry(entry2, b"password2".to_vec()).await;

    backend
}

// Helper to create provider FSM
fn create_provider_fsm(backend: Arc<dyn DirectoryBackend>) -> ReplicationProviderFsmImpl {
    create_provider_fsm_with_tracker(backend, ChangelogTracker::new())
}

fn create_provider_fsm_with_tracker(
    backend: Arc<dyn DirectoryBackend>,
    tracker: ChangelogTracker,
) -> ReplicationProviderFsmImpl {
    let changelog_provider = Box::new(ChangelogProviderImpl::new(tracker.clone(), backend));
    let consumer_registry = Box::new(ConsumerRegistryImpl::new());
    let streaming_manager = Box::new(StreamingManagerImpl::new());
    let sync_request_handler = Box::new(SyncRequestHandlerImpl::new());

    ReplicationProviderFsmImpl::new(
        changelog_provider,
        consumer_registry,
        streaming_manager,
        sync_request_handler,
    )
}

fn default_provider_request(consumer_id: &str) -> SyncRequest {
    SyncRequest::new(consumer_id.to_string(), "dc=example,dc=org".to_string())
        .with_sync_mode(SyncMode::RefreshAndPersist)
}

// Helper to create consumer FSM
fn unique_state_path() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir()
        .join(format!("opendr-repl-state-{}-{nanos}", std::process::id()))
        .to_string_lossy()
        .into_owned()
}

fn create_consumer_fsm(
    backend: Arc<dyn DirectoryBackend>,
    changelog_provider: Arc<dyn ChangelogProvider>,
) -> ReplicationConsumerFsmImpl {
    create_consumer_fsm_with_state_path(backend, changelog_provider, unique_state_path())
}

fn create_consumer_fsm_with_state_path(
    backend: Arc<dyn DirectoryBackend>,
    changelog_provider: Arc<dyn ChangelogProvider>,
    state_path: String,
) -> ReplicationConsumerFsmImpl {
    let provider_connection = Box::new(ProviderConnectionImpl::with_credentials_and_base(
        changelog_provider,
        None,
        None,
        "dc=example,dc=org".to_string(),
    ));
    let batch_processor = Box::new(BatchProcessorImpl::new(backend.clone()));
    let state_manager = Box::new(StateManagerImpl::new(state_path));
    let change_listener = Box::new(ChangeListenerImpl::new());

    ReplicationConsumerFsmImpl::new(
        provider_connection,
        batch_processor,
        state_manager,
        change_listener,
    )
}

fn encode_replication_change(change_type: ChangeType, dn: &str, change_data: &[u8]) -> Vec<u8> {
    let change_type = match change_type {
        ChangeType::Add => "add",
        ChangeType::Modify => "modify",
        ChangeType::Delete => "delete",
        ChangeType::Rename => "rename",
    };

    let header = format!("0|{change_type}|{dn}|{}|", change_data.len());
    let mut encoded = header.into_bytes();
    encoded.extend_from_slice(change_data);
    encoded
}

fn create_entry_with_password(dn: &str, cn: &str, password: &str) -> DirectoryEntry {
    DirectoryEntry::new(
        dn,
        HashMap::from([
            (
                "objectClass".to_string(),
                vec!["top".to_string(), "person".to_string()],
            ),
            ("cn".to_string(), vec![cn.to_string()]),
            ("sn".to_string(), vec!["Replication".to_string()]),
            ("userPassword".to_string(), vec![password.to_string()]),
        ]),
    )
}

fn encode_entry_change(entry: DirectoryEntry) -> Vec<u8> {
    serde_json::to_vec(&entry).expect("replication entry fixture should serialize")
}

struct DeleteFailingBackend {
    inner: MockBackend,
    fail_dn: String,
}

#[async_trait]
impl DirectoryBackend for DeleteFailingBackend {
    async fn authenticate(
        &self,
        dn: &str,
        password: &[u8],
    ) -> Result<bool, opendr::backend::BackendError> {
        self.inner.authenticate(dn, password).await
    }

    async fn get_entry(
        &self,
        dn: &str,
    ) -> Result<Option<DirectoryEntry>, opendr::backend::BackendError> {
        self.inner.get_entry(dn).await
    }

    async fn add_entry(
        &self,
        entry: DirectoryEntry,
        password: Vec<u8>,
    ) -> Result<(), opendr::backend::BackendError> {
        self.inner.add_entry(entry, password).await
    }

    async fn delete_entry(&self, dn: &str) -> Result<(), opendr::backend::BackendError> {
        if dn == self.fail_dn {
            Err(opendr::backend::BackendError::Storage(
                "forced delete failure".to_string(),
            ))
        } else {
            self.inner.delete_entry(dn).await
        }
    }

    async fn modify_entry(
        &self,
        dn: &str,
        modifications: Vec<opendr::backend::Modification>,
    ) -> Result<(), opendr::backend::BackendError> {
        self.inner.modify_entry(dn, modifications).await
    }

    async fn compare_attribute(
        &self,
        dn: &str,
        attribute: &str,
        value: &str,
    ) -> Result<bool, opendr::backend::BackendError> {
        self.inner.compare_attribute(dn, attribute, value).await
    }

    async fn rename_entry(
        &self,
        dn: &str,
        new_rdn: &str,
        delete_old: bool,
        new_superior: Option<String>,
    ) -> Result<(), opendr::backend::BackendError> {
        self.inner
            .rename_entry(dn, new_rdn, delete_old, new_superior)
            .await
    }

    async fn search_entries(
        &self,
        base_dn: &str,
        scope: ldap_parser::ldap::SearchScope,
    ) -> Result<Vec<DirectoryEntry>, opendr::backend::BackendError> {
        self.inner.search_entries(base_dn, scope).await
    }

    async fn get_context_csn(
        &self,
    ) -> Result<Option<opendr::csn::Csn>, opendr::backend::BackendError> {
        self.inner.get_context_csn().await
    }

    async fn set_context_csn(
        &self,
        csn: opendr::csn::Csn,
    ) -> Result<(), opendr::backend::BackendError> {
        self.inner.set_context_csn(csn).await
    }
}

#[tokio::test]
async fn test_changelog_tracker_records_changes() {
    let tracker = ChangelogTracker::new();

    // Record changes
    let csn1 = tracker.record_change(
        ChangeType::Add,
        "cn=user1,dc=example,dc=org".to_string(),
        b"entry data 1".to_vec(),
    );

    let csn2 = tracker.record_change(
        ChangeType::Modify,
        "cn=user1,dc=example,dc=org".to_string(),
        b"entry data 2".to_vec(),
    );

    let csn3 = tracker.record_change(
        ChangeType::Delete,
        "cn=user2,dc=example,dc=org".to_string(),
        b"entry data 3".to_vec(),
    );

    // Verify CSNs are unique and properly ordered
    assert!(csn2 > csn1);
    assert!(csn3 > csn2);

    // Verify context CSN is updated
    let context_csn = tracker.get_context_csn();
    assert_eq!(context_csn, Some(csn3.clone()));

    // Get changes since csn1
    let changes = tracker.get_since_csn(&csn1);
    assert_eq!(changes.len(), 2);
    assert!(changes[0].csn > csn1);
    assert!(changes[1].csn > changes[0].csn);
}

#[tokio::test]
async fn test_changelog_provider_get_all_entries() {
    let backend = Arc::new(create_test_backend().await);
    let tracker = ChangelogTracker::new();
    let provider = ChangelogProviderImpl::new(tracker, backend);

    let entries = provider
        .get_all_entries("dc=example,dc=org", None)
        .await
        .unwrap();

    // Should return all entries from backend (at least the 2 we added + admin)
    assert!(entries.len() >= 2);
    assert!(entries.iter().any(|e| e.dn == "cn=user1,dc=example,dc=org"));
    assert!(entries.iter().any(|e| e.dn == "cn=user2,dc=example,dc=org"));
}

#[tokio::test]
async fn test_changelog_provider_get_changelog_since() {
    let backend = Arc::new(create_test_backend().await);
    let tracker = ChangelogTracker::new();

    // Record some changes
    tracker.record_change(
        ChangeType::Add,
        "cn=user3,dc=example,dc=org".to_string(),
        b"data".to_vec(),
    );

    tracker.record_change(
        ChangeType::Modify,
        "cn=user4,dc=example,dc=org".to_string(),
        b"data".to_vec(),
    );

    let provider = ChangelogProviderImpl::new(tracker, backend);

    // Get changes since sequence 0
    let changes = provider.get_changelog_since(None, 100).await.unwrap();
    assert_eq!(changes.len(), 2);

    // Get changes with a CSN-based cookie
    let context_csn = provider.get_context_csn().await.unwrap().unwrap();
    let cookie = format!("csn-{}", context_csn);
    let changes = provider
        .get_changelog_since(Some(&cookie), 100)
        .await
        .unwrap();
    // Should return empty since we're asking for changes after the latest CSN
    assert_eq!(changes.len(), 0);
}

#[tokio::test]
async fn test_provider_fsm_start_sync_replication() {
    let backend = Arc::new(create_test_backend().await);
    let mut fsm = create_provider_fsm(backend);

    // Start sync replication
    let result = fsm
        .handle_event(ReplicationProviderEvent::StartSyncReplication {
            request: default_provider_request("consumer1"),
        })
        .await;

    assert!(result.is_ok());

    // Should return number of entries to sync (at least 2 from our test data + default admin)
    let count = result.unwrap();
    assert!(count.is_some());
    assert!(
        count.unwrap() >= 2,
        "Expected at least 2 entries, got {}",
        count.unwrap()
    );

    // FSM should be in Refresh state
    assert!(matches!(
        fsm.current_state(),
        ReplicationProviderState::Refresh { .. }
    ));

    // Should have 1 active consumer
    assert_eq!(fsm.active_consumers(), 1);
}

#[tokio::test]
async fn test_provider_fsm_complete_refresh_phase() {
    let backend = Arc::new(create_test_backend().await);
    let mut fsm = create_provider_fsm(backend);

    // Start sync replication
    fsm.handle_event(ReplicationProviderEvent::StartSyncReplication {
        request: default_provider_request("consumer1"),
    })
    .await
    .unwrap();

    // Complete refresh phase
    let result = fsm
        .handle_event(ReplicationProviderEvent::RefreshComplete {
            consumer_id: "consumer1".to_string(),
            entries_sent: 2,
        })
        .await;

    assert!(result.is_ok());

    // FSM should transition to Present state
    assert!(matches!(
        fsm.current_state(),
        ReplicationProviderState::Present { .. }
    ));

    // Should report 2 entries sent
    assert_eq!(fsm.entries_sent(), 2);
}

#[tokio::test]
async fn test_provider_fsm_complete_present_phase() {
    let backend = Arc::new(create_test_backend().await);
    let mut fsm = create_provider_fsm(backend);

    // Go through refresh phase
    fsm.handle_event(ReplicationProviderEvent::StartSyncReplication {
        request: default_provider_request("consumer1"),
    })
    .await
    .unwrap();

    fsm.handle_event(ReplicationProviderEvent::RefreshComplete {
        consumer_id: "consumer1".to_string(),
        entries_sent: 2,
    })
    .await
    .unwrap();

    // Complete present phase
    let result = fsm
        .handle_event(ReplicationProviderEvent::PresentComplete {
            consumer_id: "consumer1".to_string(),
            entries_streamed: 0,
        })
        .await;

    assert!(result.is_ok());

    // FSM should transition to Persist state
    assert!(matches!(
        fsm.current_state(),
        ReplicationProviderState::Persist { .. }
    ));

    // Should have a cookie
    assert!(fsm.cookie().is_some());
}

#[tokio::test]
async fn test_provider_fsm_stream_changelog_entries() {
    let backend = Arc::new(create_test_backend().await);
    let mut fsm = create_provider_fsm(backend);

    // Progress to present phase
    fsm.handle_event(ReplicationProviderEvent::StartSyncReplication {
        request: default_provider_request("consumer1"),
    })
    .await
    .unwrap();

    fsm.handle_event(ReplicationProviderEvent::RefreshComplete {
        consumer_id: "consumer1".to_string(),
        entries_sent: 2,
    })
    .await
    .unwrap();
    fsm.handle_event(ReplicationProviderEvent::PresentComplete {
        consumer_id: "consumer1".to_string(),
        entries_streamed: 0,
    })
    .await
    .unwrap();
    fsm.handle_event(ReplicationProviderEvent::CookiePersisted {
        consumer_id: "consumer1".to_string(),
        new_cookie: "stream-cookie".to_string(),
    })
    .await
    .unwrap();

    // Stream a changelog entry with CSN
    let csn_gen = opendr::csn::CsnGenerator::new(1);
    let csn = csn_gen.generate();
    let result = fsm
        .handle_event(ReplicationProviderEvent::ChangelogEntry {
            change: ChangelogEntry::new(
                csn,
                ChangeType::Modify,
                "cn=user1,dc=example,dc=org".to_string(),
                b"test entry data".to_vec(),
            ),
        })
        .await;

    assert!(result.is_ok());

    // FSM should transition to Streaming state
    assert!(matches!(
        fsm.current_state(),
        ReplicationProviderState::Streaming { .. }
    ));
    assert!(fsm.is_streaming());
}

#[tokio::test]
async fn test_provider_fsm_consumer_disconnect() {
    let backend = Arc::new(create_test_backend().await);
    let mut fsm = create_provider_fsm(backend);

    // Start replication
    fsm.handle_event(ReplicationProviderEvent::StartSyncReplication {
        request: default_provider_request("consumer1"),
    })
    .await
    .unwrap();

    assert_eq!(fsm.active_consumers(), 1);

    // Consumer disconnects
    let result = fsm
        .handle_event(ReplicationProviderEvent::ConsumerDisconnected {
            consumer_id: "consumer1".to_string(),
        })
        .await;

    assert!(result.is_ok());

    // FSM should transition to Completed state
    assert!(matches!(
        fsm.current_state(),
        ReplicationProviderState::Completed
    ));
    assert_eq!(fsm.active_consumers(), 0);
}

#[tokio::test]
async fn test_consumer_fsm_start_consumption() {
    let backend = Arc::new(create_test_backend().await);
    let tracker = ChangelogTracker::new();
    let changelog_provider = Arc::new(ChangelogProviderImpl::new(tracker, backend.clone()));

    let mut fsm = create_consumer_fsm(backend, changelog_provider);

    // Start consumption
    let result = fsm
        .handle_event(ReplicationConsumerEvent::StartConsumption {
            provider_url: LOCAL_PROVIDER_URL.to_string(),
            cookie: None,
        })
        .await;

    assert!(result.is_ok());
    assert!(result.unwrap().unwrap() >= 2);

    // The concrete in-memory consumer performs the initial request immediately and then
    // transitions to listening for live changes.
    assert!(matches!(
        fsm.current_state(),
        ReplicationConsumerState::Listening
    ));

    // Provider URL should be set
    assert_eq!(fsm.provider_url(), Some(LOCAL_PROVIDER_URL));
    assert!(fsm.current_cookie().is_some());
}

#[tokio::test]
async fn test_consumer_fsm_receive_and_apply_batch() {
    let backend = Arc::new(create_test_backend().await);
    let tracker = ChangelogTracker::new();
    let first_csn = tracker.record_change(
        ChangeType::Add,
        "cn=old1,dc=example,dc=org".to_string(),
        encode_entry_change(create_entry_with_password(
            "cn=old1,dc=example,dc=org",
            "old1",
            "old-secret",
        )),
    );
    tracker.record_change(
        ChangeType::Add,
        "cn=new1,dc=example,dc=org".to_string(),
        encode_entry_change(create_entry_with_password(
            "cn=new1,dc=example,dc=org",
            "new1",
            "new-secret",
        )),
    );
    let changelog_provider = Arc::new(ChangelogProviderImpl::new(tracker, backend.clone()));

    let mut fsm = create_consumer_fsm(backend, changelog_provider);

    // Start incremental consumption from the first recorded CSN.
    let result = fsm
        .handle_event(ReplicationConsumerEvent::StartConsumption {
            provider_url: LOCAL_PROVIDER_URL.to_string(),
            cookie: Some(format!("csn-{first_csn}")),
        })
        .await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Some(1));
    assert!(matches!(
        fsm.current_state(),
        ReplicationConsumerState::Listening
    ));
    assert!(fsm.current_cookie().is_some());
}

#[tokio::test]
async fn test_consumer_fsm_persist_state() {
    let backend = Arc::new(create_test_backend().await);
    let tracker = ChangelogTracker::new();
    let changelog_provider = Arc::new(ChangelogProviderImpl::new(tracker, backend.clone()));
    let state_path = unique_state_path();

    let mut first_fsm = create_consumer_fsm_with_state_path(
        backend,
        changelog_provider.clone(),
        state_path.clone(),
    );

    first_fsm
        .handle_event(ReplicationConsumerEvent::StartConsumption {
            provider_url: LOCAL_PROVIDER_URL.to_string(),
            cookie: None,
        })
        .await
        .unwrap();

    let persisted_cookie = first_fsm
        .current_cookie()
        .expect("initial sync should persist a cookie")
        .to_string();

    let second_backend = Arc::new(create_test_backend().await);
    let mut second_fsm =
        create_consumer_fsm_with_state_path(second_backend, changelog_provider, state_path);

    let result = second_fsm
        .handle_event(ReplicationConsumerEvent::StartConsumption {
            provider_url: LOCAL_PROVIDER_URL.to_string(),
            cookie: None,
        })
        .await;

    assert!(result.is_ok());
    assert!(matches!(
        second_fsm.current_state(),
        ReplicationConsumerState::Listening
    ));
    assert_eq!(second_fsm.current_cookie(), Some(persisted_cookie.as_str()));
}

#[tokio::test]
async fn test_consumer_fsm_receive_real_time_changes() {
    let backend = Arc::new(create_test_backend().await);
    let tracker = ChangelogTracker::new();
    let changelog_provider = Arc::new(ChangelogProviderImpl::new(tracker, backend.clone()));

    let mut fsm = create_consumer_fsm(backend, changelog_provider);

    fsm.handle_event(ReplicationConsumerEvent::StartConsumption {
        provider_url: LOCAL_PROVIDER_URL.to_string(),
        cookie: None,
    })
    .await
    .unwrap();

    // Receive real-time change
    let result = fsm
        .handle_event(ReplicationConsumerEvent::ChangeReceived(
            encode_replication_change(
                ChangeType::Add,
                "cn=live,dc=example,dc=org",
                &encode_entry_change(create_entry_with_password(
                    "cn=live,dc=example,dc=org",
                    "live",
                    "live-secret",
                )),
            ),
        ))
        .await;

    assert!(result.is_ok());

    // Should still be listening
    assert!(fsm.is_listening());

    // Entries applied count should increment
    assert_eq!(fsm.entries_applied(), 1);
    assert!(fsm.current_cookie().is_some());
}

#[tokio::test]
async fn test_consumer_fsm_conflicting_full_sync_add_reconciles_and_advances_cookie() {
    let provider_backend = Arc::new(create_test_backend().await);
    let changelog_provider = Arc::new(ChangelogProviderImpl::new(
        ChangelogTracker::new(),
        provider_backend,
    ));

    let consumer_backend = Arc::new(create_test_backend().await);
    consumer_backend
        .modify_entry(
            "cn=user1,dc=example,dc=org",
            vec![opendr::backend::Modification {
                operation: opendr::backend::ModifyOperation::Replace,
                attribute: "cn".to_string(),
                values: vec!["consumer-conflict".to_string()],
            }],
        )
        .await
        .unwrap();

    let state_path = unique_state_path();
    let cookie_path = std::path::Path::new(&state_path).join("replication_cookie.txt");
    let mut fsm = create_consumer_fsm_with_state_path(
        consumer_backend.clone(),
        changelog_provider,
        state_path,
    );

    let result = fsm
        .handle_event(ReplicationConsumerEvent::StartConsumption {
            provider_url: LOCAL_PROVIDER_URL.to_string(),
            cookie: None,
        })
        .await;

    assert!(result.is_ok());
    assert!(fsm.current_cookie().is_some());
    assert!(cookie_path.exists());
    let reconciled = consumer_backend
        .get_entry("cn=user1,dc=example,dc=org")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        reconciled.attributes.get("cn"),
        Some(&vec!["user1".to_string()])
    );
}

#[tokio::test]
async fn test_consumer_fsm_incremental_modify_failure_keeps_resume_cookie() {
    let tracker = ChangelogTracker::new();
    let resume_csn = tracker.record_change(
        ChangeType::Add,
        "cn=before,dc=example,dc=org".to_string(),
        b"before".to_vec(),
    );
    let desired_entry = DirectoryEntry::new(
        "cn=missing,dc=example,dc=org",
        HashMap::from([("cn".to_string(), vec!["missing".to_string()])]),
    );
    tracker.record_change(
        ChangeType::Modify,
        desired_entry.dn.clone(),
        serde_json::to_vec(&desired_entry).unwrap(),
    );

    let state_path = unique_state_path();
    let cookie_path = std::path::Path::new(&state_path).join("replication_cookie.txt");
    let changelog_provider = Arc::new(ChangelogProviderImpl::new(
        tracker,
        Arc::new(create_test_backend().await),
    ));
    let mut fsm = create_consumer_fsm_with_state_path(
        Arc::new(create_test_backend().await),
        changelog_provider,
        state_path,
    );
    let resume_cookie = format!("csn-{resume_csn}");

    let result = fsm
        .handle_event(ReplicationConsumerEvent::StartConsumption {
            provider_url: LOCAL_PROVIDER_URL.to_string(),
            cookie: Some(resume_cookie.clone()),
        })
        .await;

    assert!(result.is_err());
    assert_eq!(fsm.current_cookie(), Some(resume_cookie.as_str()));
    assert!(!cookie_path.exists());
}

#[tokio::test]
async fn test_consumer_fsm_incremental_delete_failure_keeps_resume_cookie() {
    let fail_dn = "cn=delete-me,dc=example,dc=org";
    let tracker = ChangelogTracker::new();
    let resume_csn = tracker.record_change(
        ChangeType::Add,
        "cn=before-delete,dc=example,dc=org".to_string(),
        b"before".to_vec(),
    );
    tracker.record_change(ChangeType::Delete, fail_dn.to_string(), Vec::new());

    let delete_backend = DeleteFailingBackend {
        inner: create_test_backend().await,
        fail_dn: fail_dn.to_string(),
    };
    delete_backend
        .inner
        .add_entry(
            DirectoryEntry::new(
                fail_dn,
                HashMap::from([("cn".to_string(), vec!["delete-me".to_string()])]),
            ),
            Vec::new(),
        )
        .await
        .unwrap();

    let state_path = unique_state_path();
    let cookie_path = std::path::Path::new(&state_path).join("replication_cookie.txt");
    let changelog_provider = Arc::new(ChangelogProviderImpl::new(
        tracker,
        Arc::new(create_test_backend().await),
    ));
    let mut fsm = create_consumer_fsm_with_state_path(
        Arc::new(delete_backend),
        changelog_provider,
        state_path,
    );
    let resume_cookie = format!("csn-{resume_csn}");

    let result = fsm
        .handle_event(ReplicationConsumerEvent::StartConsumption {
            provider_url: LOCAL_PROVIDER_URL.to_string(),
            cookie: Some(resume_cookie.clone()),
        })
        .await;

    assert!(result.is_err());
    assert_eq!(fsm.current_cookie(), Some(resume_cookie.as_str()));
    assert!(!cookie_path.exists());
}

#[tokio::test]
async fn test_consumer_fsm_save_failure_does_not_advance_cookie() {
    let provider_backend = Arc::new(create_test_backend().await);
    let changelog_provider = Arc::new(ChangelogProviderImpl::new(
        ChangelogTracker::new(),
        provider_backend,
    ));

    let invalid_path_dir = tempfile::tempdir().unwrap();
    let invalid_state_path = invalid_path_dir.path().join("state-file");
    std::fs::write(&invalid_state_path, "not-a-directory").unwrap();

    let mut fsm = create_consumer_fsm_with_state_path(
        Arc::new(MockBackend::new()),
        changelog_provider,
        invalid_state_path.to_string_lossy().into_owned(),
    );

    let result = fsm
        .handle_event(ReplicationConsumerEvent::StartConsumption {
            provider_url: LOCAL_PROVIDER_URL.to_string(),
            cookie: None,
        })
        .await;

    assert!(result.is_err());
    assert_eq!(fsm.current_cookie(), None);
}

#[tokio::test]
async fn test_batch_processor_replays_password_and_rename_semantics() {
    let provider_backend = Arc::new(MockBackend::new());
    let changelog = Arc::new(ChangelogTracker::new());
    let provider = ChangelogBackendWrapper::new(provider_backend, Some(changelog.clone()));
    let consumer_backend = Arc::new(MockBackend::new());
    let batch_processor = BatchProcessorImpl::new(consumer_backend.clone());

    let original_dn = "cn=replicated,dc=example,dc=org";
    let renamed_dn = "cn=replicated-renamed,dc=example,dc=org";
    let entry = create_entry_with_password(original_dn, "replicated", "initial-secret");
    provider
        .add_entry(entry, b"initial-secret".to_vec())
        .await
        .unwrap();

    let mut changes = changelog.get_all();
    let add_change = changes.remove(0);
    batch_processor
        .apply_entry(&encode_replication_change(
            add_change.change_type.clone(),
            &add_change.dn,
            &add_change.change_data,
        ))
        .await
        .unwrap();

    assert!(consumer_backend
        .authenticate(original_dn, b"initial-secret")
        .await
        .unwrap());

    provider
        .modify_entry(
            original_dn,
            vec![
                opendr::backend::Modification {
                    operation: opendr::backend::ModifyOperation::Replace,
                    attribute: "description".to_string(),
                    values: vec!["updated".to_string()],
                },
                opendr::backend::Modification {
                    operation: opendr::backend::ModifyOperation::Replace,
                    attribute: "userPassword".to_string(),
                    values: vec!["rotated-secret".to_string()],
                },
            ],
        )
        .await
        .unwrap();

    let modify_change = changelog.get_all().pop().unwrap();
    batch_processor
        .apply_entry(&encode_replication_change(
            modify_change.change_type.clone(),
            &modify_change.dn,
            &modify_change.change_data,
        ))
        .await
        .unwrap();

    assert!(!consumer_backend
        .authenticate(original_dn, b"initial-secret")
        .await
        .unwrap());
    assert!(consumer_backend
        .authenticate(original_dn, b"rotated-secret")
        .await
        .unwrap());

    provider
        .rename_entry(original_dn, "cn=replicated-renamed", true, None)
        .await
        .unwrap();

    let rename_change = changelog.get_all().pop().unwrap();
    batch_processor
        .apply_entry(&encode_replication_change(
            rename_change.change_type.clone(),
            &rename_change.dn,
            &rename_change.change_data,
        ))
        .await
        .unwrap();

    assert!(consumer_backend
        .get_entry(original_dn)
        .await
        .unwrap()
        .is_none());
    assert!(consumer_backend
        .get_entry(renamed_dn)
        .await
        .unwrap()
        .is_some());
    assert!(consumer_backend
        .authenticate(renamed_dn, b"rotated-secret")
        .await
        .unwrap());

    provider.delete_entry(renamed_dn).await.unwrap();

    let delete_change = changelog.get_all().pop().unwrap();
    batch_processor
        .apply_entry(&encode_replication_change(
            delete_change.change_type.clone(),
            &delete_change.dn,
            &delete_change.change_data,
        ))
        .await
        .unwrap();

    assert!(consumer_backend
        .get_entry(renamed_dn)
        .await
        .unwrap()
        .is_none());
    assert!(!consumer_backend
        .authenticate(renamed_dn, b"rotated-secret")
        .await
        .unwrap());
}

#[tokio::test]
async fn test_end_to_end_replication_flow() {
    // Setup provider
    let provider_backend = Arc::new(create_test_backend().await);
    let tracker = ChangelogTracker::new();

    // Record some changes in the changelog
    tracker.record_change(
        ChangeType::Add,
        "cn=user3,dc=example,dc=org".to_string(),
        encode_entry_change(create_entry_with_password(
            "cn=user3,dc=example,dc=org",
            "user3",
            "user3-secret",
        )),
    );

    tracker.record_change(
        ChangeType::Modify,
        "cn=user1,dc=example,dc=org".to_string(),
        encode_entry_change(DirectoryEntry::new(
            "cn=user1,dc=example,dc=org",
            HashMap::from([
                ("cn".to_string(), vec!["user1".to_string()]),
                ("objectclass".to_string(), vec!["person".to_string()]),
                ("description".to_string(), vec!["modified".to_string()]),
            ]),
        )),
    );

    let mut provider_fsm = create_provider_fsm(provider_backend.clone());

    // Setup consumer
    let consumer_backend = Arc::new(create_test_backend().await);
    let changelog_provider = Arc::new(ChangelogProviderImpl::new(
        tracker.clone(),
        provider_backend,
    ));
    let mut consumer_fsm = create_consumer_fsm(consumer_backend, changelog_provider);

    // Provider: Start sync replication
    let provider_result = provider_fsm
        .handle_event(ReplicationProviderEvent::StartSyncReplication {
            request: default_provider_request("consumer1"),
        })
        .await;
    assert!(provider_result.is_ok());
    let entry_count = provider_result.unwrap().unwrap();
    assert!(
        entry_count >= 2,
        "Expected at least 2 entries, got {}",
        entry_count
    );

    // Consumer: Start consumption
    let consumer_result = consumer_fsm
        .handle_event(ReplicationConsumerEvent::StartConsumption {
            provider_url: LOCAL_PROVIDER_URL.to_string(),
            cookie: None,
        })
        .await;
    assert!(consumer_result.is_ok());

    // Provider: Complete refresh
    provider_fsm
        .handle_event(ReplicationProviderEvent::RefreshComplete {
            consumer_id: "consumer1".to_string(),
            entries_sent: entry_count,
        })
        .await
        .unwrap();

    // Provider: Complete present
    provider_fsm
        .handle_event(ReplicationProviderEvent::PresentComplete {
            consumer_id: "consumer1".to_string(),
            entries_streamed: 2,
        })
        .await
        .unwrap();

    // Verify provider state
    assert!(matches!(
        provider_fsm.current_state(),
        ReplicationProviderState::Persist { .. }
    ));
    assert!(provider_fsm.cookie().is_some());

    // Consumer: Apply a live change after the initial sync session starts listening.
    consumer_fsm
        .handle_event(ReplicationConsumerEvent::ChangeReceived(
            encode_replication_change(
                ChangeType::Modify,
                "cn=user1,dc=example,dc=org",
                &encode_entry_change(DirectoryEntry::new(
                    "cn=user1,dc=example,dc=org",
                    HashMap::from([
                        ("cn".to_string(), vec!["user1".to_string()]),
                        ("objectclass".to_string(), vec!["person".to_string()]),
                        ("description".to_string(), vec!["modified".to_string()]),
                    ]),
                )),
            ),
        ))
        .await
        .unwrap();

    // Verify consumer state
    assert!(consumer_fsm.is_listening());
    assert!(consumer_fsm.current_cookie().is_some());

    // Provider sessions are only marked successful once the consumer disconnects.
    provider_fsm
        .handle_event(ReplicationProviderEvent::ConsumerDisconnected {
            consumer_id: "consumer1".to_string(),
        })
        .await
        .unwrap();

    // Verify replication stats
    let (provider_sessions, provider_successful, _, provider_entries, _) = provider_fsm.get_stats();
    assert_eq!(provider_sessions, 1);
    assert_eq!(provider_successful, 1);
    assert!(matches!(
        provider_fsm.current_state(),
        ReplicationProviderState::Completed
    ));
    // entry_count from refresh + 2 changelog entries from present
    assert!(
        provider_entries >= 4,
        "Expected at least 4 provider entries, got {}",
        provider_entries
    );

    let (consumer_sessions, _, _, consumer_entries, _) = consumer_fsm.get_stats();
    assert_eq!(consumer_sessions, 1);
    assert_eq!(consumer_entries, 1);
}

#[tokio::test]
async fn test_replication_with_existing_cookie() {
    let backend = Arc::new(create_test_backend().await);
    let tracker = ChangelogTracker::new();

    // Record changes with specific sequence numbers
    tracker.record_change(
        ChangeType::Add,
        "cn=old1,dc=example,dc=org".to_string(),
        b"old".to_vec(),
    );
    tracker.record_change(
        ChangeType::Add,
        "cn=old2,dc=example,dc=org".to_string(),
        b"old".to_vec(),
    );
    tracker.record_change(
        ChangeType::Add,
        "cn=new1,dc=example,dc=org".to_string(),
        b"new".to_vec(),
    );
    tracker.record_change(
        ChangeType::Add,
        "cn=new2,dc=example,dc=org".to_string(),
        b"new".to_vec(),
    );

    let changelog_provider = Arc::new(ChangelogProviderImpl::new(tracker.clone(), backend.clone()));

    // Get all changes
    let changes = changelog_provider
        .get_changelog_since(None, 100)
        .await
        .unwrap();

    // Should get all recorded changes
    assert_eq!(changes.len(), 4);

    // Verify CSNs are in order
    for i in 1..changes.len() {
        assert!(changes[i].csn > changes[i - 1].csn);
    }

    assert_eq!(changes[0].dn, "cn=old1,dc=example,dc=org");
    assert_eq!(changes[1].dn, "cn=old2,dc=example,dc=org");
    assert_eq!(changes[2].dn, "cn=new1,dc=example,dc=org");
    assert_eq!(changes[3].dn, "cn=new2,dc=example,dc=org");
}

#[tokio::test]
async fn test_provider_fsm_replays_only_newer_changes_for_valid_cookie() {
    let backend = Arc::new(create_test_backend().await);
    let tracker = ChangelogTracker::new();
    let first_csn = tracker.record_change(
        ChangeType::Add,
        "cn=old1,dc=example,dc=org".to_string(),
        b"old".to_vec(),
    );
    tracker.record_change(
        ChangeType::Modify,
        "cn=new1,dc=example,dc=org".to_string(),
        b"new-1".to_vec(),
    );
    tracker.record_change(
        ChangeType::Delete,
        "cn=new2,dc=example,dc=org".to_string(),
        b"new-2".to_vec(),
    );

    let mut fsm = create_provider_fsm_with_tracker(backend, tracker);
    let result = fsm
        .handle_event(ReplicationProviderEvent::StartSyncReplication {
            request: default_provider_request("consumer1")
                .with_sync_mode(SyncMode::PresentOnly)
                .with_cookie(format!("csn-{first_csn}")),
        })
        .await
        .unwrap();

    assert_eq!(result, Some(2));
    assert_eq!(
        fsm.get_session("consumer1")
            .map(|session| session.current_phase.clone()),
        Some(ReplicationPhase::Present)
    );
    assert_eq!(
        fsm.get_session("consumer1")
            .map(|session| session.pending_replay_count()),
        Some(2)
    );

    let replay_batch = fsm
        .next_replay_batch("consumer1")
        .await
        .unwrap()
        .expect("replay batch should be available");
    assert_eq!(
        replay_batch
            .iter()
            .map(|entry| entry.dn.as_str())
            .collect::<Vec<_>>(),
        vec!["cn=new1,dc=example,dc=org", "cn=new2,dc=example,dc=org",]
    );
    assert_eq!(
        replay_batch
            .iter()
            .map(|entry| entry.change_type.clone())
            .collect::<Vec<_>>(),
        vec![ChangeType::Modify, ChangeType::Delete]
    );
}

#[tokio::test]
async fn test_provider_fsm_refresh_batches_entries_from_backend() {
    let backend = Arc::new(create_test_backend().await);
    let changelog_provider = Box::new(ChangelogProviderImpl::new(ChangelogTracker::new(), backend));
    let consumer_registry = Box::new(ConsumerRegistryImpl::new());
    let streaming_manager = Box::new(StreamingManagerImpl::new());
    let sync_request_handler = Box::new(SyncRequestHandlerImpl::new());
    let config = ReplicationProviderConfig {
        refresh_batch_size: 1,
        ..Default::default()
    };

    let mut fsm = ReplicationProviderFsmImpl::with_config(
        changelog_provider,
        consumer_registry,
        streaming_manager,
        sync_request_handler,
        config,
    );

    fsm.handle_event(ReplicationProviderEvent::StartSyncReplication {
        request: default_provider_request("consumer1"),
    })
    .await
    .unwrap();

    let mut total_entries = 0usize;
    let mut batches = 0usize;
    while let Some(batch) = fsm.next_refresh_batch("consumer1").await.unwrap() {
        assert_eq!(batch.len(), 1);
        total_entries += batch.len();
        batches += 1;
    }

    assert_eq!(
        total_entries,
        fsm.get_session("consumer1")
            .expect("session should exist")
            .refresh_total_entries
    );
    assert!(batches >= 2);
}

#[tokio::test]
async fn test_provider_fsm_rejects_stale_cookie_explicitly() {
    let backend = Arc::new(create_test_backend().await);
    let tracker = ChangelogTracker::with_capacity(2);
    let stale_csn = tracker.record_change(
        ChangeType::Add,
        "cn=stale,dc=example,dc=org".to_string(),
        b"stale".to_vec(),
    );
    tracker.record_change(
        ChangeType::Modify,
        "cn=current1,dc=example,dc=org".to_string(),
        b"current-1".to_vec(),
    );
    tracker.record_change(
        ChangeType::Delete,
        "cn=current2,dc=example,dc=org".to_string(),
        b"current-2".to_vec(),
    );

    let mut fsm = create_provider_fsm_with_tracker(backend, tracker);
    let cookie = format!("csn-{stale_csn}");
    let err = fsm
        .handle_event(ReplicationProviderEvent::StartSyncReplication {
            request: default_provider_request("consumer1")
                .with_sync_mode(SyncMode::PresentOnly)
                .with_cookie(cookie.clone()),
        })
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        ReplicationProviderError::FullRefreshRequired { cookie: invalid }
        if invalid == cookie
    ));
    assert!(fsm.get_session("consumer1").is_none());
    assert_eq!(fsm.active_consumers(), 0);
}

#[tokio::test]
async fn test_provider_fsm_rejects_stale_cookie_after_tracker_restart() {
    let backend = Arc::new(create_test_backend().await);
    let state_dir = tempfile::tempdir().unwrap();
    let tracker = ChangelogTracker::with_capacity_replica_and_storage(2, 1, state_dir.path());
    let stale_csn = tracker.record_change(
        ChangeType::Add,
        "cn=stale,dc=example,dc=org".to_string(),
        b"stale".to_vec(),
    );
    tracker.record_change(
        ChangeType::Modify,
        "cn=current1,dc=example,dc=org".to_string(),
        b"current-1".to_vec(),
    );
    tracker.record_change(
        ChangeType::Delete,
        "cn=current2,dc=example,dc=org".to_string(),
        b"current-2".to_vec(),
    );

    let reloaded = ChangelogTracker::with_capacity_replica_and_storage(2, 1, state_dir.path());
    let mut fsm = create_provider_fsm_with_tracker(backend, reloaded);
    let cookie = format!("csn-{stale_csn}");
    let err = fsm
        .handle_event(ReplicationProviderEvent::StartSyncReplication {
            request: default_provider_request("consumer1")
                .with_sync_mode(SyncMode::PresentOnly)
                .with_cookie(cookie.clone()),
        })
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        ReplicationProviderError::FullRefreshRequired { cookie: invalid }
        if invalid == cookie
    ));
    assert!(fsm.get_session("consumer1").is_none());
    assert_eq!(fsm.active_consumers(), 0);
}

#[tokio::test]
async fn test_replication_error_handling() {
    let backend = Arc::new(create_test_backend().await);
    let mut fsm = create_provider_fsm(backend);

    // Try to complete refresh without starting sync
    let result = fsm
        .handle_event(ReplicationProviderEvent::RefreshComplete {
            consumer_id: "consumer1".to_string(),
            entries_sent: 2,
        })
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        ReplicationProviderError::ConsumerNotFound { .. }
    ));
}

#[tokio::test]
async fn test_consumer_registry() {
    let mut registry = ConsumerRegistryImpl::new();

    let connection = ConsumerConnection::new("consumer1".to_string());

    // Register consumer
    registry
        .register_consumer("consumer1", connection.clone())
        .await
        .unwrap();

    // Check if connected
    assert!(registry.is_consumer_connected("consumer1").await.unwrap());

    // Get active consumers
    let active = registry.get_active_consumers().await.unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0], "consumer1");

    // Unregister consumer
    let removed = registry.unregister_consumer("consumer1").await.unwrap();
    assert!(removed);

    // Should no longer be connected
    assert!(!registry.is_consumer_connected("consumer1").await.unwrap());
}

#[tokio::test]
async fn test_provider_fsm_isolates_concurrent_consumer_lifecycle() {
    let backend = Arc::new(create_test_backend().await);
    let tracker = ChangelogTracker::new();
    let consumer1_cookie = format!(
        "csn-{}",
        tracker.record_change(
            ChangeType::Add,
            "cn=resume1,dc=example,dc=org".to_string(),
            b"resume-1".to_vec(),
        )
    );
    let consumer2_cookie = format!(
        "csn-{}",
        tracker.record_change(
            ChangeType::Modify,
            "cn=resume2,dc=example,dc=org".to_string(),
            b"resume-2".to_vec(),
        )
    );
    let mut fsm = create_provider_fsm_with_tracker(backend, tracker);

    for (consumer_id, cookie) in [
        ("consumer1", consumer1_cookie.as_str()),
        ("consumer2", consumer2_cookie.as_str()),
    ] {
        fsm.handle_event(ReplicationProviderEvent::StartSyncReplication {
            request: default_provider_request(consumer_id).with_cookie(cookie.to_string()),
        })
        .await
        .unwrap();
    }

    assert_eq!(fsm.active_consumers(), 2);
    assert_eq!(
        fsm.get_session("consumer1")
            .and_then(|session| session.sync_request.as_ref())
            .and_then(|request| request.cookie.as_deref()),
        Some(consumer1_cookie.as_str())
    );
    assert_eq!(
        fsm.get_session("consumer2")
            .and_then(|session| session.sync_request.as_ref())
            .and_then(|request| request.cookie.as_deref()),
        Some(consumer2_cookie.as_str())
    );

    fsm.handle_event(ReplicationProviderEvent::RefreshComplete {
        consumer_id: "consumer1".to_string(),
        entries_sent: 2,
    })
    .await
    .unwrap();

    assert_eq!(
        fsm.get_session("consumer1")
            .map(|session| &session.current_phase),
        Some(&ReplicationPhase::Present)
    );
    assert_eq!(
        fsm.get_session("consumer2")
            .map(|session| &session.current_phase),
        Some(&ReplicationPhase::Refresh)
    );

    fsm.handle_event(ReplicationProviderEvent::RefreshComplete {
        consumer_id: "consumer2".to_string(),
        entries_sent: 2,
    })
    .await
    .unwrap();
    fsm.handle_event(ReplicationProviderEvent::PresentComplete {
        consumer_id: "consumer1".to_string(),
        entries_streamed: 1,
    })
    .await
    .unwrap();
    fsm.handle_event(ReplicationProviderEvent::PresentComplete {
        consumer_id: "consumer2".to_string(),
        entries_streamed: 0,
    })
    .await
    .unwrap();

    fsm.handle_event(ReplicationProviderEvent::CookiePersisted {
        consumer_id: "consumer1".to_string(),
        new_cookie: "persisted-1".to_string(),
    })
    .await
    .unwrap();

    assert_eq!(
        fsm.get_session("consumer1")
            .and_then(|session| session.last_cookie.as_deref()),
        Some("persisted-1")
    );
    assert_eq!(
        fsm.get_session("consumer1")
            .map(|session| &session.current_phase),
        Some(&ReplicationPhase::Stream)
    );
    assert_eq!(
        fsm.get_session("consumer2")
            .map(|session| &session.current_phase),
        Some(&ReplicationPhase::Persist)
    );

    fsm.handle_event(ReplicationProviderEvent::ConsumerDisconnected {
        consumer_id: "consumer1".to_string(),
    })
    .await
    .unwrap();

    assert_eq!(fsm.active_consumers(), 1);
    assert!(fsm.get_session("consumer1").is_none());
    assert_eq!(
        fsm.get_session("consumer2")
            .and_then(|session| session.last_cookie.as_deref()),
        Some(consumer2_cookie.as_str())
    );

    fsm.handle_event(ReplicationProviderEvent::CookiePersisted {
        consumer_id: "consumer2".to_string(),
        new_cookie: "persisted-2".to_string(),
    })
    .await
    .unwrap();

    assert_eq!(
        fsm.get_session("consumer2")
            .and_then(|session| session.last_cookie.as_deref()),
        Some("persisted-2")
    );
    assert_eq!(
        fsm.get_session("consumer2")
            .map(|session| &session.current_phase),
        Some(&ReplicationPhase::Stream)
    );
}

#[tokio::test]
async fn test_streaming_manager() {
    let mut manager = StreamingManagerImpl::new();

    // Start streaming
    manager.start_streaming("consumer1", None).await.unwrap();

    // Check if active
    assert!(manager.is_streaming_active("consumer1").await.unwrap());

    // Send entry with CSN
    let csn_gen = opendr::csn::CsnGenerator::new(1);
    let csn = csn_gen.generate();
    let entry = ChangelogEntry::new(
        csn,
        ChangeType::Add,
        "cn=test,dc=example,dc=org".to_string(),
        b"data".to_vec(),
    );
    manager.send_entry("consumer1", &entry).await.unwrap();

    // Get stats
    let stats = manager.get_streaming_stats("consumer1").await.unwrap();
    assert_eq!(stats.entries_streamed, 1);

    // Stop streaming
    manager.stop_streaming("consumer1").await.unwrap();
    assert!(!manager.is_streaming_active("consumer1").await.unwrap());
}

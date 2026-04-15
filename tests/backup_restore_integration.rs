use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use opendr::backend::{DirectoryBackend, DirectoryEntry};
use opendr::backend_changelog_wrapper::ChangelogBackendWrapper;
use opendr::backend_lmdb::LmdbBackend;
use opendr::backup::{
    BackupType, CheckpointSource, create_full_backup, create_incremental_backup,
    restore_backup_chain, verify_manifest_files,
};
use opendr::config::ServerConfig;
use opendr::replication::{ChangelogProviderImpl, ChangelogTracker};
use opendr::replication_provider_fsm::ChangelogProvider;
use tempfile::tempdir;

fn test_config(data_dir: &Path, state_dir: &Path) -> ServerConfig {
    let mut config = ServerConfig::default();
    config.backend.backend_type = "lmdb".to_string();
    config.backend.data_directory = data_dir.to_path_buf();
    config.backend.lmdb_max_size = 64 * 1024 * 1024;
    config.backend.lmdb_max_readers = 126;
    config.server.base_dn = "dc=example,dc=org".to_string();
    config.server.replica_id = 1;
    config.replication.state_storage_path = state_dir.to_path_buf();
    config
}

fn person_entry(cn: &str) -> DirectoryEntry {
    let mut attributes = HashMap::new();
    attributes.insert(
        "objectclass".to_string(),
        vec!["top".to_string(), "person".to_string()],
    );
    attributes.insert("cn".to_string(), vec![cn.to_string()]);
    attributes.insert("sn".to_string(), vec![cn.to_string()]);
    DirectoryEntry::new(format!("cn={cn},dc=example,dc=org"), attributes)
}

#[tokio::test]
async fn full_backup_restores_lmdb_data_directory() {
    let root = tempdir().unwrap();
    let source_data = root.path().join("source-data");
    let state_dir = root.path().join("state");
    let config = test_config(&source_data, &state_dir);
    let backend = LmdbBackend::new(&source_data, 64, 1).unwrap();
    backend
        .add_entry(person_entry("full"), b"secret".to_vec())
        .await
        .unwrap();

    let backup_dir = root.path().join("full-backup");
    let manifest = create_full_backup(&config, &backup_dir, false).unwrap();
    assert_eq!(manifest.backup_type, BackupType::Full);
    assert!(
        manifest
            .files
            .iter()
            .any(|file| file.path == "data/data.mdb")
    );
    verify_manifest_files(&backup_dir).unwrap();

    let restore_dir = root.path().join("restore-data");
    let report = restore_backup_chain(&backup_dir, &[], &restore_dir, false, false)
        .await
        .unwrap();
    assert_eq!(report.full_backup_id, manifest.backup_id);

    let restored = LmdbBackend::new(&restore_dir, 64, 1).unwrap();
    let entry = restored
        .get_entry("cn=full,dc=example,dc=org")
        .await
        .unwrap();
    assert!(entry.is_some());
}

#[tokio::test]
async fn backup_rejects_non_empty_target_directory() {
    let root = tempdir().unwrap();
    let source_data = root.path().join("source-data");
    let state_dir = root.path().join("state");
    let config = test_config(&source_data, &state_dir);
    let _backend = LmdbBackend::new(&source_data, 64, 1).unwrap();
    let backup_dir = root.path().join("backup");
    std::fs::create_dir_all(&backup_dir).unwrap();
    std::fs::write(backup_dir.join("existing"), b"not empty").unwrap();

    let error = create_full_backup(&config, &backup_dir, false).unwrap_err();
    assert!(error.to_string().contains("must be empty"));
}

#[tokio::test]
async fn incremental_backup_restores_changelog_entries_after_full_backup() {
    let root = tempdir().unwrap();
    let source_data = root.path().join("source-data");
    let state_dir = root.path().join("state");
    let config = test_config(&source_data, &state_dir);
    let raw_backend = Arc::new(LmdbBackend::new(&source_data, 64, 1).unwrap());
    let changelog = Arc::new(ChangelogTracker::with_capacity_replica_and_storage(
        100,
        1,
        state_dir.clone(),
    ));
    let backend = ChangelogBackendWrapper::new(raw_backend, Some(changelog));

    backend
        .add_entry(person_entry("before"), b"secret".to_vec())
        .await
        .unwrap();

    let full_dir = root.path().join("full-backup");
    let full_manifest = create_full_backup(&config, &full_dir, false).unwrap();
    assert_eq!(full_manifest.checkpoint.source, CheckpointSource::Changelog);

    backend
        .add_entry(person_entry("after"), b"secret".to_vec())
        .await
        .unwrap();

    let incremental_dir = root.path().join("incremental-backup");
    let incremental_manifest =
        create_incremental_backup(&config, &full_dir, &incremental_dir).unwrap();
    assert_eq!(incremental_manifest.backup_type, BackupType::Incremental);
    assert_eq!(
        incremental_manifest.parent_backup_id.as_deref(),
        Some(full_manifest.backup_id.as_str())
    );

    let restore_dir = root.path().join("restore-data");
    restore_backup_chain(
        &full_dir,
        std::slice::from_ref(&incremental_dir),
        &restore_dir,
        false,
        false,
    )
    .await
    .unwrap();

    let restored = LmdbBackend::new(&restore_dir, 64, 1).unwrap();
    assert!(
        restored
            .get_entry("cn=before,dc=example,dc=org")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        restored
            .get_entry("cn=after,dc=example,dc=org")
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn replicated_restore_requires_full_refresh_when_changelog_window_is_not_restored() {
    let root = tempdir().unwrap();
    let source_data = root.path().join("source-data");
    let state_dir = root.path().join("provider-state");
    let config = test_config(&source_data, &state_dir);
    let raw_backend = Arc::new(LmdbBackend::new(&source_data, 64, 1).unwrap());
    let changelog = Arc::new(ChangelogTracker::with_capacity_replica_and_storage(
        100,
        1,
        state_dir.clone(),
    ));
    let backend = ChangelogBackendWrapper::new(raw_backend, Some(changelog));

    backend
        .add_entry(person_entry("before-restore"), b"secret".to_vec())
        .await
        .unwrap();

    let full_dir = root.path().join("full-backup");
    let full_manifest = create_full_backup(&config, &full_dir, false).unwrap();
    let pre_restore_cookie = format!(
        "csn-{}",
        full_manifest
            .checkpoint
            .end_context_csn
            .as_ref()
            .expect("full backup should checkpoint provider contextCSN")
    );

    backend
        .add_entry(person_entry("after-restore"), b"secret".to_vec())
        .await
        .unwrap();

    let incremental_dir = root.path().join("incremental-backup");
    create_incremental_backup(&config, &full_dir, &incremental_dir).unwrap();

    let restore_dir = root.path().join("restore-data");
    restore_backup_chain(
        &full_dir,
        std::slice::from_ref(&incremental_dir),
        &restore_dir,
        false,
        false,
    )
    .await
    .unwrap();

    let restored_backend = Arc::new(LmdbBackend::new(&restore_dir, 64, 1).unwrap());
    let restored_provider = ChangelogProviderImpl::new(
        ChangelogTracker::with_capacity_replica_and_storage(
            100,
            1,
            root.path().join("restored-provider-state"),
        ),
        restored_backend,
    );

    let replay_error = restored_provider
        .get_changelog_since(Some(&pre_restore_cookie), 100)
        .await
        .unwrap_err();
    assert!(replay_error.contains("Stale replication cookie"));

    let refresh_entries = restored_provider
        .get_all_entries("dc=example,dc=org", None)
        .await
        .unwrap();
    let restored_dns = refresh_entries
        .iter()
        .map(|entry| entry.dn.as_str())
        .collect::<Vec<_>>();
    assert!(restored_dns.contains(&"cn=before-restore,dc=example,dc=org"));
    assert!(restored_dns.contains(&"cn=after-restore,dc=example,dc=org"));
}

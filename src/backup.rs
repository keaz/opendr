//! Backup and restore support for OpenDR LMDB deployments.

use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{SecondsFormat, Utc};
use ldap_parser::ldap::SearchScope;
use lmdb::{Environment, EnvironmentFlags, Transaction};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::backend::{DirectoryBackend, DirectoryEntry, OperationalAttributes};
use crate::backend_lmdb::{IndexConfig, LmdbBackend};
use crate::config::ServerConfig;
use crate::csn::Csn;
use crate::replication::BatchProcessorImpl;
use crate::replication_consumer_fsm::BatchProcessor;
use crate::replication_provider_fsm::ChangeType;

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;

pub const BACKUP_FORMAT_VERSION: u32 = 1;
pub const MANIFEST_FILE: &str = "manifest.json";
pub const DATA_DIR: &str = "data";
pub const CHANGES_FILE: &str = "changes.json";
pub const PROVIDER_CHANGELOG_FILE: &str = "provider_changelog.json";

const LMDB_MAX_DBS: u32 = 50;
const BYTES_PER_MIB: usize = 1024 * 1024;

pub type BackupResult<T> = Result<T, BackupError>;

#[derive(Debug, Error)]
pub enum BackupError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("LMDB error: {0}")]
    Lmdb(String),
    #[error("backend error: {0}")]
    Backend(#[from] crate::backend::BackendError),
    #[error("invalid backup: {0}")]
    InvalidBackup(String),
    #[error("restore processing error: {0}")]
    RestoreProcessing(String),
    #[error("unsupported backup operation: {0}")]
    Unsupported(String),
}

impl From<lmdb::Error> for BackupError {
    fn from(value: lmdb::Error) -> Self {
        Self::Lmdb(value.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupType {
    Full,
    Incremental,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointSource {
    BackendContext,
    Changelog,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupSource {
    pub backend_type: String,
    pub data_directory: String,
    pub base_dn: String,
    pub replica_id: u16,
    pub lmdb_map_size_bytes: usize,
    pub state_storage_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupCheckpoint {
    pub source: CheckpointSource,
    pub start_context_csn: Option<String>,
    pub end_context_csn: Option<String>,
    pub snapshot_context_csn: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupFile {
    pub path: String,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupManifest {
    pub format_version: u32,
    pub backup_id: String,
    pub backup_type: BackupType,
    pub parent_backup_id: Option<String>,
    pub created_at: String,
    pub opendr_version: String,
    pub source: BackupSource,
    pub checkpoint: BackupCheckpoint,
    pub files: Vec<BackupFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupChangeEntry {
    pub csn: Csn,
    pub change_type: ChangeType,
    pub dn: String,
    pub change_data: Vec<u8>,
    #[serde(default)]
    pub originator: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalChanges {
    pub entries: Vec<BackupChangeEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreReport {
    pub full_backup_id: String,
    pub applied_incremental_backup_ids: Vec<String>,
    pub target_data_directory: String,
    pub final_context_csn: Option<String>,
    pub dry_run: bool,
}

#[derive(Debug, Clone)]
struct ChangelogSnapshot {
    entries: Vec<BackupChangeEntry>,
}

#[derive(Debug, Deserialize)]
struct BackupStoredEntry {
    dn: String,
    attributes: HashMap<String, Vec<String>>,
    #[serde(rename = "created_at")]
    _created_at: u64,
    #[serde(rename = "modified_at")]
    _modified_at: u64,
    #[serde(default)]
    operational_attributes: OperationalAttributes,
}

#[derive(Debug, Deserialize)]
struct BackupStoredEntryV1 {
    dn: String,
    attributes: HashMap<String, Vec<String>>,
    #[serde(rename = "created_at")]
    _created_at: u64,
    #[serde(rename = "modified_at")]
    _modified_at: u64,
    #[serde(default)]
    operational_attributes: BackupOperationalAttributesV1,
}

#[derive(Debug, Default, Deserialize)]
struct BackupOperationalAttributesV1 {
    entry_csn: Option<Csn>,
    entry_uuid: Option<String>,
    create_timestamp: Option<String>,
    modify_timestamp: Option<String>,
    creators_name: Option<String>,
    modifiers_name: Option<String>,
}

impl From<BackupOperationalAttributesV1> for OperationalAttributes {
    fn from(value: BackupOperationalAttributesV1) -> Self {
        Self {
            entry_csn: value.entry_csn,
            entry_uuid: value.entry_uuid,
            create_timestamp: value.create_timestamp,
            modify_timestamp: value.modify_timestamp,
            creators_name: value.creators_name,
            modifiers_name: value.modifiers_name,
            last_successful_login: None,
            last_failed_login: None,
            failed_login_count: None,
        }
    }
}

impl From<BackupStoredEntryV1> for BackupStoredEntry {
    fn from(value: BackupStoredEntryV1) -> Self {
        Self {
            dn: value.dn,
            attributes: value.attributes,
            _created_at: value._created_at,
            _modified_at: value._modified_at,
            operational_attributes: value.operational_attributes.into(),
        }
    }
}

impl BackupStoredEntry {
    fn into_directory_entry(self) -> DirectoryEntry {
        DirectoryEntry::with_operational_attrs(
            self.dn,
            self.attributes,
            self.operational_attributes,
        )
    }
}

fn deserialize_backup_stored_entry(bytes: &[u8]) -> BackupResult<BackupStoredEntry> {
    match bincode::deserialize(bytes) {
        Ok(entry) => Ok(entry),
        Err(current_err) => bincode::deserialize::<BackupStoredEntryV1>(bytes)
            .map(BackupStoredEntry::from)
            .map_err(|legacy_err| {
                BackupError::InvalidBackup(format!(
                    "failed to deserialize stored LMDB entry: {current_err}; legacy decode failed: {legacy_err}"
                ))
            }),
    }
}

#[derive(Debug, Deserialize)]
struct PersistedChangelogSnapshot {
    entries: Vec<BackupChangeEntry>,
}

pub fn create_full_backup(
    config: &ServerConfig,
    target_dir: &Path,
    compact: bool,
) -> BackupResult<BackupManifest> {
    ensure_lmdb_backend(config)?;
    ensure_empty_dir(target_dir)?;

    let pre_copy_changelog_csn = read_provider_changelog(config)
        .ok()
        .and_then(|snapshot| snapshot.entries.last().map(|entry| entry.csn.to_string()));

    let data_target = target_dir.join(DATA_DIR);
    fs::create_dir_all(&data_target)?;
    copy_lmdb_environment(
        &config.backend.data_directory,
        &data_target,
        compact,
        config.backend.lmdb_max_readers,
    )?;

    let snapshot_context = read_lmdb_context_csn(&data_target, config.backend.lmdb_max_readers)?;
    let snapshot_context_string = snapshot_context.as_ref().map(ToString::to_string);
    let checkpoint_source = if pre_copy_changelog_csn.is_some() {
        CheckpointSource::Changelog
    } else {
        CheckpointSource::BackendContext
    };
    let end_context_csn = pre_copy_changelog_csn.or_else(|| snapshot_context_string.clone());

    let files = collect_backup_files(target_dir)?;
    let manifest = BackupManifest {
        format_version: BACKUP_FORMAT_VERSION,
        backup_id: Uuid::new_v4().to_string(),
        backup_type: BackupType::Full,
        parent_backup_id: None,
        created_at: timestamp_now(),
        opendr_version: env!("CARGO_PKG_VERSION").to_string(),
        source: source_from_config(config),
        checkpoint: BackupCheckpoint {
            source: checkpoint_source,
            start_context_csn: None,
            end_context_csn,
            snapshot_context_csn: snapshot_context_string,
        },
        files,
    };

    write_manifest(target_dir, &manifest)?;
    Ok(manifest)
}

pub fn create_incremental_backup(
    config: &ServerConfig,
    parent_manifest_path: &Path,
    target_dir: &Path,
) -> BackupResult<BackupManifest> {
    ensure_lmdb_backend(config)?;
    ensure_empty_dir(target_dir)?;

    let parent = read_manifest(parent_manifest_path)?;
    validate_manifest_shape(&parent)?;
    if parent.checkpoint.source != CheckpointSource::Changelog {
        return Err(BackupError::Unsupported(
            "incremental backup requires a parent with a changelog checkpoint".to_string(),
        ));
    }

    let parent_csn = parse_required_csn(parent.checkpoint.end_context_csn.as_deref(), "parent")?;
    let changelog = read_provider_changelog(config)?;
    let latest_changelog_csn = changelog.entries.last().map(|entry| entry.csn.clone());
    let source_context = read_lmdb_context_csn(
        &config.backend.data_directory,
        config.backend.lmdb_max_readers,
    )?;

    validate_changelog_window(&parent_csn, latest_changelog_csn.as_ref(), &changelog)?;
    if let (Some(source_context), Some(latest_changelog_csn)) =
        (source_context.as_ref(), latest_changelog_csn.as_ref())
        && source_context > latest_changelog_csn
    {
        return Err(BackupError::InvalidBackup(format!(
            "persisted changelog is behind backend contextCSN: backend={}, changelog={}",
            source_context, latest_changelog_csn
        )));
    }

    let mut incremental_entries: Vec<BackupChangeEntry> = changelog
        .entries
        .into_iter()
        .filter(|entry| entry.csn > parent_csn)
        .collect();
    hydrate_empty_change_data(config, &mut incremental_entries)?;
    let end_context_csn = incremental_entries
        .last()
        .map(|entry| entry.csn.to_string())
        .or_else(|| parent.checkpoint.end_context_csn.clone());

    let changes = IncrementalChanges {
        entries: incremental_entries,
    };
    write_json_pretty(&target_dir.join(CHANGES_FILE), &changes)?;

    let files = collect_backup_files(target_dir)?;
    let manifest = BackupManifest {
        format_version: BACKUP_FORMAT_VERSION,
        backup_id: Uuid::new_v4().to_string(),
        backup_type: BackupType::Incremental,
        parent_backup_id: Some(parent.backup_id),
        created_at: timestamp_now(),
        opendr_version: env!("CARGO_PKG_VERSION").to_string(),
        source: source_from_config(config),
        checkpoint: BackupCheckpoint {
            source: CheckpointSource::Changelog,
            start_context_csn: Some(parent_csn.to_string()),
            end_context_csn,
            snapshot_context_csn: source_context.map(|csn| csn.to_string()),
        },
        files,
    };

    write_manifest(target_dir, &manifest)?;
    Ok(manifest)
}

pub fn manifest_path(path: &Path) -> PathBuf {
    if path.is_dir() {
        path.join(MANIFEST_FILE)
    } else {
        path.to_path_buf()
    }
}

pub fn read_manifest(path: &Path) -> BackupResult<BackupManifest> {
    let manifest_path = manifest_path(path);
    let bytes = fs::read(&manifest_path)?;
    serde_json::from_slice(&bytes).map_err(BackupError::from)
}

pub fn verify_manifest_files(path: &Path) -> BackupResult<BackupManifest> {
    let manifest_path = manifest_path(path);
    let manifest = read_manifest(&manifest_path)?;
    validate_manifest_shape(&manifest)?;
    let root = manifest_path.parent().ok_or_else(|| {
        BackupError::InvalidBackup(format!(
            "manifest path has no parent: {}",
            manifest_path.display()
        ))
    })?;

    for file in &manifest.files {
        let path = root.join(&file.path);
        let actual = file_checksum(root, &path)?;
        if &actual != file {
            return Err(BackupError::InvalidBackup(format!(
                "backup file checksum mismatch for {}",
                file.path
            )));
        }
    }

    Ok(manifest)
}

pub async fn restore_backup_chain(
    full_backup: &Path,
    incremental_backups: &[PathBuf],
    target_data_dir: &Path,
    force: bool,
    dry_run: bool,
) -> BackupResult<RestoreReport> {
    let full_manifest_path = manifest_path(full_backup);
    let full_root = manifest_root(&full_manifest_path)?;
    let full_manifest = verify_manifest_files(&full_manifest_path)?;
    if full_manifest.backup_type != BackupType::Full {
        return Err(BackupError::InvalidBackup(
            "restore must start from a full backup".to_string(),
        ));
    }

    let mut previous_manifest = full_manifest.clone();
    let mut incremental_manifests = Vec::new();
    for path in incremental_backups {
        let manifest_path = manifest_path(path);
        let manifest = verify_manifest_files(&manifest_path)?;
        validate_next_incremental(&previous_manifest, &manifest)?;
        previous_manifest = manifest.clone();
        incremental_manifests.push((manifest_path, manifest));
    }

    let final_context_csn = previous_manifest.checkpoint.end_context_csn.clone();
    let report = RestoreReport {
        full_backup_id: full_manifest.backup_id.clone(),
        applied_incremental_backup_ids: incremental_manifests
            .iter()
            .map(|(_, manifest)| manifest.backup_id.clone())
            .collect(),
        target_data_directory: target_data_dir.display().to_string(),
        final_context_csn: final_context_csn.clone(),
        dry_run,
    };

    if dry_run {
        return Ok(report);
    }

    prepare_restore_target(target_data_dir, force)?;
    copy_dir_recursive(&full_root.join(DATA_DIR), target_data_dir)?;

    if !incremental_manifests.is_empty() {
        let backend = Arc::new(open_lmdb_backend_for_restore(
            target_data_dir,
            &full_manifest,
        )?);
        let processor = BatchProcessorImpl::new(backend.clone());
        for (manifest_path, _) in &incremental_manifests {
            let root = manifest_root(manifest_path)?;
            let changes = read_incremental_changes(&root.join(CHANGES_FILE))?;
            for change in changes.entries {
                processor
                    .apply_entry(&encode_change_entry(&change))
                    .await
                    .map_err(|err| BackupError::RestoreProcessing(err.to_string()))?;
            }
        }

        if let Some(csn) = final_context_csn.as_deref().map(parse_csn).transpose()? {
            backend.set_context_csn(csn).await?;
        }
    }

    validate_restored_backend(target_data_dir, &previous_manifest).await?;
    Ok(report)
}

fn ensure_lmdb_backend(config: &ServerConfig) -> BackupResult<()> {
    if config.backend.backend_type.to_lowercase() != "lmdb" {
        return Err(BackupError::Unsupported(format!(
            "backup only supports the lmdb backend, got {}",
            config.backend.backend_type
        )));
    }
    Ok(())
}

fn source_from_config(config: &ServerConfig) -> BackupSource {
    BackupSource {
        backend_type: config.backend.backend_type.clone(),
        data_directory: config.backend.data_directory.display().to_string(),
        base_dn: config.server.base_dn.clone(),
        replica_id: config.server.replica_id,
        lmdb_map_size_bytes: config.backend.lmdb_max_size,
        state_storage_path: Some(config.replication.state_storage_path.display().to_string()),
    }
}

fn ensure_empty_dir(path: &Path) -> BackupResult<()> {
    if path.exists() {
        if !path.is_dir() {
            return Err(BackupError::InvalidBackup(format!(
                "{} exists and is not a directory",
                path.display()
            )));
        }
        if fs::read_dir(path)?.next().is_some() {
            return Err(BackupError::InvalidBackup(format!(
                "{} must be empty",
                path.display()
            )));
        }
    } else {
        fs::create_dir_all(path)?;
    }
    Ok(())
}

fn prepare_restore_target(path: &Path, force: bool) -> BackupResult<()> {
    if path.exists() {
        if !path.is_dir() {
            return Err(BackupError::InvalidBackup(format!(
                "{} exists and is not a directory",
                path.display()
            )));
        }
        if fs::read_dir(path)?.next().is_some() {
            if !force {
                return Err(BackupError::InvalidBackup(format!(
                    "{} is not empty; pass --force to replace it",
                    path.display()
                )));
            }
            fs::remove_dir_all(path)?;
        }
    }
    fs::create_dir_all(path)?;
    Ok(())
}

fn copy_lmdb_environment(
    source_dir: &Path,
    target_dir: &Path,
    compact: bool,
    max_readers: u32,
) -> BackupResult<()> {
    let env = open_lmdb_readonly(source_dir, max_readers)?;
    let target = path_to_cstring(target_dir)?;
    let flags = if compact { lmdb_sys::MDB_CP_COMPACT } else { 0 };

    // SAFETY: the LMDB environment handle is opened by the safe lmdb crate and
    // lives for this call. The target path is a valid C string and points to an
    // existing empty directory, as required by mdb_env_copy2.
    let rc = unsafe { lmdb_sys::mdb_env_copy2(env.env(), target.as_ptr(), flags) };
    if rc != 0 {
        return Err(BackupError::Lmdb(
            lmdb::Error::from_err_code(rc).to_string(),
        ));
    }
    Ok(())
}

fn open_lmdb_readonly(source_dir: &Path, max_readers: u32) -> BackupResult<Environment> {
    Environment::new()
        .set_max_dbs(LMDB_MAX_DBS)
        .set_max_readers(max_readers)
        .set_flags(EnvironmentFlags::READ_ONLY)
        .open(source_dir)
        .map_err(BackupError::from)
}

pub fn read_lmdb_context_csn(data_dir: &Path, max_readers: u32) -> BackupResult<Option<Csn>> {
    let env = open_lmdb_readonly(data_dir, max_readers)?;
    let metadata_db = match env.open_db(Some("metadata")) {
        Ok(db) => db,
        Err(lmdb::Error::NotFound) => return Ok(None),
        Err(err) => return Err(BackupError::from(err)),
    };
    let txn = env.begin_ro_txn()?;
    match txn.get(metadata_db, &b"context_csn") {
        Ok(bytes) => {
            let csn = std::str::from_utf8(bytes)
                .map_err(|err| BackupError::InvalidBackup(err.to_string()))
                .and_then(parse_csn)?;
            Ok(Some(csn))
        }
        Err(lmdb::Error::NotFound) => Ok(None),
        Err(err) => Err(BackupError::from(err)),
    }
}

fn read_provider_changelog(config: &ServerConfig) -> BackupResult<ChangelogSnapshot> {
    let path = config
        .replication
        .state_storage_path
        .join(PROVIDER_CHANGELOG_FILE);
    let bytes = fs::read(&path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            BackupError::Unsupported(format!(
                "provider changelog not found at {}",
                path.display()
            ))
        } else {
            BackupError::Io(err)
        }
    })?;
    let snapshot: PersistedChangelogSnapshot = serde_json::from_slice(&bytes)?;
    let mut entries = snapshot.entries;
    entries.sort_by(|left, right| left.csn.cmp(&right.csn));
    Ok(ChangelogSnapshot { entries })
}

fn hydrate_empty_change_data(
    config: &ServerConfig,
    entries: &mut [BackupChangeEntry],
) -> BackupResult<()> {
    for entry in entries {
        if !entry.change_data.is_empty() {
            continue;
        }
        if !matches!(entry.change_type, ChangeType::Add | ChangeType::Modify) {
            continue;
        }
        let Some(directory_entry) = read_lmdb_entry_snapshot(
            &config.backend.data_directory,
            &entry.dn,
            config.backend.lmdb_max_readers,
        )?
        else {
            return Err(BackupError::InvalidBackup(format!(
                "changelog entry {} for {} has empty change_data and the entry is not present in LMDB",
                entry.csn, entry.dn
            )));
        };
        entry.change_data = serde_json::to_vec(&directory_entry)?;
    }
    Ok(())
}

fn read_lmdb_entry_snapshot(
    data_dir: &Path,
    dn: &str,
    max_readers: u32,
) -> BackupResult<Option<DirectoryEntry>> {
    let env = open_lmdb_readonly(data_dir, max_readers)?;
    let dn_index_db = match env.open_db(Some("dn_index")) {
        Ok(db) => db,
        Err(lmdb::Error::NotFound) => return Ok(None),
        Err(err) => return Err(BackupError::from(err)),
    };
    let entries_db = match env.open_db(Some("entries")) {
        Ok(db) => db,
        Err(lmdb::Error::NotFound) => return Ok(None),
        Err(err) => return Err(BackupError::from(err)),
    };
    let txn = env.begin_ro_txn()?;
    let normalized_dn = dn.to_lowercase().trim().to_string();
    let actual_dn = match txn.get(dn_index_db, &normalized_dn.as_bytes()) {
        Ok(bytes) => String::from_utf8_lossy(bytes).to_string(),
        Err(lmdb::Error::NotFound) => return Ok(None),
        Err(err) => return Err(BackupError::from(err)),
    };
    let entry_bytes = match txn.get(entries_db, &actual_dn.as_bytes()) {
        Ok(bytes) => bytes,
        Err(lmdb::Error::NotFound) => return Ok(None),
        Err(err) => return Err(BackupError::from(err)),
    };
    let stored = deserialize_backup_stored_entry(entry_bytes).map_err(|err| {
        BackupError::InvalidBackup(format!(
            "failed to deserialize stored LMDB entry {}: {}",
            actual_dn, err
        ))
    })?;
    Ok(Some(stored.into_directory_entry()))
}

fn validate_changelog_window(
    parent_csn: &Csn,
    latest_changelog_csn: Option<&Csn>,
    changelog: &ChangelogSnapshot,
) -> BackupResult<()> {
    let Some(latest_changelog_csn) = latest_changelog_csn else {
        return Ok(());
    };
    if latest_changelog_csn <= parent_csn {
        return Ok(());
    }
    let Some(first_retained_csn) = changelog.entries.first().map(|entry| &entry.csn) else {
        return Ok(());
    };
    if first_retained_csn > parent_csn {
        return Err(BackupError::InvalidBackup(format!(
            "provider changelog no longer contains the parent checkpoint {}; oldest retained CSN is {}",
            parent_csn, first_retained_csn
        )));
    }
    Ok(())
}

fn write_manifest(target_dir: &Path, manifest: &BackupManifest) -> BackupResult<()> {
    write_json_pretty(&target_dir.join(MANIFEST_FILE), manifest)
}

fn write_json_pretty<T: Serialize>(path: &Path, value: &T) -> BackupResult<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    fs::write(path, bytes)?;
    Ok(())
}

fn read_incremental_changes(path: &Path) -> BackupResult<IncrementalChanges> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(BackupError::from)
}

fn timestamp_now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn validate_manifest_shape(manifest: &BackupManifest) -> BackupResult<()> {
    if manifest.format_version != BACKUP_FORMAT_VERSION {
        return Err(BackupError::Unsupported(format!(
            "unsupported backup format version {}",
            manifest.format_version
        )));
    }
    if manifest.source.backend_type.to_lowercase() != "lmdb" {
        return Err(BackupError::Unsupported(format!(
            "unsupported backup backend {}",
            manifest.source.backend_type
        )));
    }
    Ok(())
}

fn validate_next_incremental(
    previous: &BackupManifest,
    incremental: &BackupManifest,
) -> BackupResult<()> {
    if incremental.backup_type != BackupType::Incremental {
        return Err(BackupError::InvalidBackup(format!(
            "expected incremental backup {}, got {:?}",
            incremental.backup_id, incremental.backup_type
        )));
    }
    if incremental.parent_backup_id.as_deref() != Some(previous.backup_id.as_str()) {
        return Err(BackupError::InvalidBackup(format!(
            "incremental {} does not reference parent {}",
            incremental.backup_id, previous.backup_id
        )));
    }
    if incremental.checkpoint.start_context_csn != previous.checkpoint.end_context_csn {
        return Err(BackupError::InvalidBackup(format!(
            "incremental {} does not continue previous checkpoint",
            incremental.backup_id
        )));
    }
    Ok(())
}

fn collect_backup_files(root: &Path) -> BackupResult<Vec<BackupFile>> {
    let mut files = Vec::new();
    collect_backup_files_inner(root, root, &mut files)?;
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(files)
}

fn collect_backup_files_inner(
    root: &Path,
    current: &Path,
    files: &mut Vec<BackupFile>,
) -> BackupResult<()> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        if path.file_name().and_then(|name| name.to_str()) == Some(MANIFEST_FILE) {
            continue;
        }
        if path.is_dir() {
            collect_backup_files_inner(root, &path, files)?;
        } else if path.is_file() {
            files.push(file_checksum(root, &path)?);
        }
    }
    Ok(())
}

fn file_checksum(root: &Path, path: &Path) -> BackupResult<BackupFile> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut size_bytes = 0_u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        size_bytes += read as u64;
        hasher.update(&buffer[..read]);
    }
    Ok(BackupFile {
        path: relative_path(root, path)?,
        size_bytes,
        sha256: hex::encode(hasher.finalize()),
    })
}

fn relative_path(root: &Path, path: &Path) -> BackupResult<String> {
    let relative = path.strip_prefix(root).map_err(|err| {
        BackupError::InvalidBackup(format!(
            "failed to relativize {} against {}: {}",
            path.display(),
            root.display(),
            err
        ))
    })?;
    Ok(relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/"))
}

fn copy_dir_recursive(source: &Path, target: &Path) -> BackupResult<()> {
    if !source.is_dir() {
        return Err(BackupError::InvalidBackup(format!(
            "backup data directory not found: {}",
            source.display()
        )));
    }
    fs::create_dir_all(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let target_path = target.join(entry.file_name());
        if source_path.is_dir() {
            copy_dir_recursive(&source_path, &target_path)?;
        } else if source_path.is_file() {
            fs::copy(&source_path, &target_path)?;
        }
    }
    Ok(())
}

fn manifest_root(manifest_path: &Path) -> BackupResult<PathBuf> {
    manifest_path
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            BackupError::InvalidBackup(format!(
                "manifest path has no parent: {}",
                manifest_path.display()
            ))
        })
}

fn open_lmdb_backend_for_restore(
    target_data_dir: &Path,
    manifest: &BackupManifest,
) -> BackupResult<LmdbBackend> {
    let max_size_mb = bytes_to_mib_ceil(manifest.source.lmdb_map_size_bytes);
    LmdbBackend::new_with_runtime_config(
        target_data_dir,
        max_size_mb,
        manifest.source.replica_id,
        IndexConfig::default(),
        126,
    )
    .map_err(BackupError::from)
}

async fn validate_restored_backend(
    target_data_dir: &Path,
    manifest: &BackupManifest,
) -> BackupResult<()> {
    let backend = open_lmdb_backend_for_restore(target_data_dir, manifest)?;
    let expected_checkpoint = if manifest.backup_type == BackupType::Incremental {
        manifest.checkpoint.end_context_csn.as_deref()
    } else {
        manifest
            .checkpoint
            .snapshot_context_csn
            .as_deref()
            .or(manifest.checkpoint.end_context_csn.as_deref())
    };
    if let Some(expected) = expected_checkpoint {
        let expected = parse_csn(expected)?;
        let actual = backend.get_context_csn().await?;
        if actual.as_ref() != Some(&expected) {
            return Err(BackupError::InvalidBackup(format!(
                "restored backend contextCSN mismatch: expected {}, got {:?}",
                expected, actual
            )));
        }
    }
    let _ = backend
        .count_entries(&manifest.source.base_dn, SearchScope::WholeSubtree)
        .await?;
    Ok(())
}

fn bytes_to_mib_ceil(bytes: usize) -> usize {
    bytes.saturating_add(BYTES_PER_MIB - 1) / BYTES_PER_MIB
}

fn parse_required_csn(value: Option<&str>, label: &str) -> BackupResult<Csn> {
    let value = value.ok_or_else(|| {
        BackupError::InvalidBackup(format!(
            "{} checkpoint is missing an end_context_csn",
            label
        ))
    })?;
    parse_csn(value)
}

fn parse_csn(value: &str) -> BackupResult<Csn> {
    Csn::parse(value).map_err(|err| BackupError::InvalidBackup(err.to_string()))
}

fn encode_change_entry(entry: &BackupChangeEntry) -> Vec<u8> {
    let change_type = match entry.change_type {
        ChangeType::Add => "add",
        ChangeType::Modify => "modify",
        ChangeType::Delete => "delete",
        ChangeType::Rename => "rename",
    };
    let header = format!(
        "0|{}|{}|{}|",
        change_type,
        entry.dn,
        entry.change_data.len()
    );
    let mut encoded = header.into_bytes();
    encoded.extend_from_slice(&entry.change_data);
    encoded
}

fn path_to_cstring(path: &Path) -> BackupResult<CString> {
    #[cfg(unix)]
    let bytes = path.as_os_str().as_bytes().to_vec();

    #[cfg(not(unix))]
    let bytes = path.as_os_str().to_string_lossy().as_bytes().to_vec();

    CString::new(bytes).map_err(|_| {
        BackupError::InvalidBackup(format!("path contains an interior NUL: {}", path.display()))
    })
}

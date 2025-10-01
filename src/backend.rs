use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use ldap_parser::ldap::SearchScope;
use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;

/// Representation of an LDAP directory entry used by storage backends.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryEntry {
    pub dn: String,
    pub attributes: HashMap<String, Vec<String>>,
}

impl DirectoryEntry {
    pub fn new(dn: impl Into<String>, attributes: HashMap<String, Vec<String>>) -> Self {
        let normalized_attributes = attributes
            .into_iter()
            .map(|(key, values)| (key.to_lowercase(), values))
            .collect();

        Self {
            dn: dn.into(),
            attributes: normalized_attributes,
        }
    }
}

/// Errors that can be emitted by [`DirectoryBackend`] implementations.
#[derive(Debug)]
pub enum BackendError {
    AlreadyExists,
    NotFound,
    Storage(String),
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackendError::AlreadyExists => write!(f, "entry already exists"),
            BackendError::NotFound => write!(f, "entry not found"),
            BackendError::Storage(reason) => write!(f, "storage error: {}", reason),
        }
    }
}

impl std::error::Error for BackendError {}

/// Trait describing the operations required from the directory data store.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait DirectoryBackend: Send + Sync {
    async fn authenticate(&self, dn: &str, password: &[u8]) -> Result<bool, BackendError>;

    async fn get_entry(&self, dn: &str) -> Result<Option<DirectoryEntry>, BackendError>;

    async fn add_entry(&self, entry: DirectoryEntry, password: Vec<u8>)
        -> Result<(), BackendError>;

    async fn delete_entry(&self, dn: &str) -> Result<(), BackendError>;

    async fn modify_entry(
        &self,
        dn: &str,
        modifications: Vec<Modification>,
    ) -> Result<(), BackendError>;

    async fn compare_attribute(
        &self,
        dn: &str,
        attribute: &str,
        value: &str,
    ) -> Result<bool, BackendError>;

    async fn rename_entry(
        &self,
        dn: &str,
        new_rdn: &str,
        delete_old: bool,
        new_superior: Option<String>,
    ) -> Result<(), BackendError>;

    async fn search_entries(
        &self,
        base_dn: &str,
        scope: SearchScope,
    ) -> Result<Vec<DirectoryEntry>, BackendError>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModifyOperation {
    Add,
    Delete,
    Replace,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Modification {
    pub operation: ModifyOperation,
    pub attribute: String,
    pub values: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredEntry {
    password: Vec<u8>,
    entry: DirectoryEntry,
}

/// Persistent backend implementation backed by a JSON file on disk.
///
/// The backend maintains all entries in memory for fast reads and flushes a snapshot to disk
/// after every mutating operation. This design keeps room for a future caching layer by
/// centralising the in-memory access patterns inside the backend implementation.
pub struct FileBackend {
    storage_path: PathBuf,
    entries: RwLock<HashMap<String, StoredEntry>>,
}

impl FileBackend {
    /// Creates a new [`FileBackend`] using `data_dir` as the storage directory. The backend loads
    /// an existing snapshot from disk when available and creates the directory structure if it does
    /// not yet exist.
    pub async fn new<P>(data_dir: P) -> Result<Self, BackendError>
    where
        P: AsRef<Path>,
    {
        let dir_path = data_dir.as_ref();
        fs::create_dir_all(dir_path).await.map_err(|err| {
            BackendError::Storage(format!("failed to create data directory: {}", err))
        })?;

        let storage_path = dir_path.join("directory.json");
        let entries = if fs::try_exists(&storage_path)
            .await
            .map_err(|err| BackendError::Storage(format!("failed to probe storage: {}", err)))?
        {
            let data = fs::read(&storage_path)
                .await
                .map_err(|err| BackendError::Storage(format!("failed to read storage: {}", err)))?;
            serde_json::from_slice::<HashMap<String, StoredEntry>>(&data).map_err(|err| {
                BackendError::Storage(format!("failed to decode storage snapshot: {}", err))
            })?
        } else {
            HashMap::new()
        };

        Ok(Self {
            storage_path,
            entries: RwLock::new(entries),
        })
    }

    async fn persist_snapshot(
        &self,
        snapshot: HashMap<String, StoredEntry>,
    ) -> Result<(), BackendError> {
        let data = serde_json::to_vec_pretty(&snapshot).map_err(|err| {
            BackendError::Storage(format!("failed to serialise snapshot: {}", err))
        })?;

        let tmp_path = self.storage_path.with_extension("json.tmp");
        let mut file = fs::File::create(&tmp_path)
            .await
            .map_err(|err| BackendError::Storage(format!("failed to create snapshot: {}", err)))?;
        file.write_all(&data)
            .await
            .map_err(|err| BackendError::Storage(format!("failed to write snapshot: {}", err)))?;
        file.sync_all()
            .await
            .map_err(|err| BackendError::Storage(format!("failed to sync snapshot: {}", err)))?;
        drop(file);

        fs::rename(&tmp_path, &self.storage_path)
            .await
            .map_err(|err| BackendError::Storage(format!("failed to commit snapshot: {}", err)))?;

        Ok(())
    }
}

/// In-memory mock backend useful during early development.
pub struct MockBackend {
    entries: RwLock<HashMap<String, StoredEntry>>,
}

impl MockBackend {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }

    pub fn from_credentials<I, D, P>(credentials: I) -> Self
    where
        I: IntoIterator<Item = (D, P)>,
        D: Into<String>,
        P: Into<Vec<u8>>,
    {
        let mut entries = HashMap::new();

        for (dn, password) in credentials {
            let dn_string = dn.into();
            entries.insert(
                dn_string.clone(),
                StoredEntry {
                    password: password.into(),
                    entry: DirectoryEntry {
                        dn: dn_string,
                        attributes: HashMap::new(),
                    },
                },
            );
        }

        Self {
            entries: RwLock::new(entries),
        }
    }
}

impl Default for MockBackend {
    fn default() -> Self {
        Self::from_credentials([(
            String::from("cn=admin,dc=example,dc=org"),
            b"secret".to_vec(),
        )])
    }
}

#[async_trait]
impl DirectoryBackend for MockBackend {
    async fn authenticate(&self, dn: &str, password: &[u8]) -> Result<bool, BackendError> {
        let entries = self.entries.read().await;
        Ok(entries
            .get(dn)
            .map(|entry| entry.password.as_slice() == password)
            .unwrap_or(false))
    }

    async fn get_entry(&self, dn: &str) -> Result<Option<DirectoryEntry>, BackendError> {
        let entries = self.entries.read().await;
        Ok(entries.get(dn).map(|entry| entry.entry.clone()))
    }

    async fn add_entry(
        &self,
        entry: DirectoryEntry,
        password: Vec<u8>,
    ) -> Result<(), BackendError> {
        let mut entries = self.entries.write().await;
        if entries.contains_key(&entry.dn) {
            return Err(BackendError::AlreadyExists);
        }

        entries.insert(entry.dn.clone(), StoredEntry { password, entry });

        Ok(())
    }

    async fn delete_entry(&self, dn: &str) -> Result<(), BackendError> {
        let mut entries = self.entries.write().await;
        entries.remove(dn).map(|_| ()).ok_or(BackendError::NotFound)
    }

    async fn modify_entry(
        &self,
        dn: &str,
        modifications: Vec<Modification>,
    ) -> Result<(), BackendError> {
        let mut entries = self.entries.write().await;
        let stored = entries.get_mut(dn).ok_or(BackendError::NotFound)?;

        for modification in modifications {
            apply_modification(&mut stored.entry, &mut stored.password, &modification);
        }

        Ok(())
    }

    async fn compare_attribute(
        &self,
        dn: &str,
        attribute: &str,
        value: &str,
    ) -> Result<bool, BackendError> {
        let entries = self.entries.read().await;
        let Some(stored) = entries.get(dn) else {
            return Err(BackendError::NotFound);
        };

        let attribute = attribute.to_lowercase();
        Ok(stored
            .entry
            .attributes
            .get(&attribute)
            .map(|values| values.iter().any(|candidate| candidate == value))
            .unwrap_or(false))
    }

    async fn rename_entry(
        &self,
        dn: &str,
        new_rdn: &str,
        delete_old: bool,
        new_superior: Option<String>,
    ) -> Result<(), BackendError> {
        let mut entries = self.entries.write().await;
        let Some(_) = entries.get(dn) else {
            return Err(BackendError::NotFound);
        };

        let target_dn = compute_new_dn(dn, new_rdn, new_superior.as_deref());

        if entries.contains_key(&target_dn) {
            return Err(BackendError::AlreadyExists);
        }

        let renames = plan_dn_renames(&*entries, dn, &target_dn)?;

        for (old_dn, new_dn) in renames {
            if let Some(mut stored) = entries.remove(&old_dn) {
                update_entry_for_rename(
                    &mut stored.entry,
                    &mut stored.password,
                    dn,
                    new_rdn,
                    &old_dn,
                    &new_dn,
                    delete_old,
                );
                stored.entry.dn = new_dn.clone();
                entries.insert(new_dn, stored);
            }
        }

        Ok(())
    }

    async fn search_entries(
        &self,
        base_dn: &str,
        scope: SearchScope,
    ) -> Result<Vec<DirectoryEntry>, BackendError> {
        let entries = self.entries.read().await;
        let mut results = Vec::new();
        let base_components = dn_components(base_dn);

        for stored in entries.values() {
            if entry_in_scope(&stored.entry.dn, &base_components, scope) {
                results.push(stored.entry.clone());
            }
        }

        Ok(results)
    }
}

#[async_trait]
impl DirectoryBackend for FileBackend {
    async fn authenticate(&self, dn: &str, password: &[u8]) -> Result<bool, BackendError> {
        let entries = self.entries.read().await;
        // A cache layer could provide fast-path credentials lookup here without acquiring the
        // read lock in the future.
        Ok(entries
            .get(dn)
            .map(|entry| entry.password.as_slice() == password)
            .unwrap_or(false))
    }

    async fn get_entry(&self, dn: &str) -> Result<Option<DirectoryEntry>, BackendError> {
        let entries = self.entries.read().await;
        Ok(entries.get(dn).map(|entry| entry.entry.clone()))
    }

    async fn add_entry(
        &self,
        entry: DirectoryEntry,
        password: Vec<u8>,
    ) -> Result<(), BackendError> {
        let snapshot = {
            let mut entries = self.entries.write().await;
            if entries.contains_key(&entry.dn) {
                return Err(BackendError::AlreadyExists);
            }

            entries.insert(entry.dn.clone(), StoredEntry { password, entry });

            entries.clone()
        };

        self.persist_snapshot(snapshot).await
    }

    async fn delete_entry(&self, dn: &str) -> Result<(), BackendError> {
        let snapshot = {
            let mut entries = self.entries.write().await;
            if entries.remove(dn).is_none() {
                return Err(BackendError::NotFound);
            }

            entries.clone()
        };

        self.persist_snapshot(snapshot).await
    }

    async fn modify_entry(
        &self,
        dn: &str,
        modifications: Vec<Modification>,
    ) -> Result<(), BackendError> {
        let snapshot = {
            let mut entries = self.entries.write().await;
            let stored = entries.get_mut(dn).ok_or(BackendError::NotFound)?;

            for modification in modifications {
                apply_modification(&mut stored.entry, &mut stored.password, &modification);
            }

            entries.clone()
        };

        self.persist_snapshot(snapshot).await
    }

    async fn compare_attribute(
        &self,
        dn: &str,
        attribute: &str,
        value: &str,
    ) -> Result<bool, BackendError> {
        let entries = self.entries.read().await;
        let Some(stored) = entries.get(dn) else {
            return Err(BackendError::NotFound);
        };

        let attribute = attribute.to_lowercase();
        Ok(stored
            .entry
            .attributes
            .get(&attribute)
            .map(|values| values.iter().any(|candidate| candidate == value))
            .unwrap_or(false))
    }

    async fn rename_entry(
        &self,
        dn: &str,
        new_rdn: &str,
        delete_old: bool,
        new_superior: Option<String>,
    ) -> Result<(), BackendError> {
        let snapshot = {
            let mut entries = self.entries.write().await;
            let Some(_) = entries.get(dn) else {
                return Err(BackendError::NotFound);
            };

            let target_dn = compute_new_dn(dn, new_rdn, new_superior.as_deref());

            if entries.contains_key(&target_dn) {
                return Err(BackendError::AlreadyExists);
            }

            let renames = plan_dn_renames(&*entries, dn, &target_dn)?;

            for (old_dn, new_dn) in renames {
                if let Some(mut stored) = entries.remove(&old_dn) {
                    update_entry_for_rename(
                        &mut stored.entry,
                        &mut stored.password,
                        dn,
                        new_rdn,
                        &old_dn,
                        &new_dn,
                        delete_old,
                    );
                    stored.entry.dn = new_dn.clone();
                    entries.insert(new_dn, stored);
                }
            }

            entries.clone()
        };

        self.persist_snapshot(snapshot).await
    }

    async fn search_entries(
        &self,
        base_dn: &str,
        scope: SearchScope,
    ) -> Result<Vec<DirectoryEntry>, BackendError> {
        let entries = self.entries.read().await;
        let mut results = Vec::new();
        let base_components = dn_components(base_dn);

        for stored in entries.values() {
            if entry_in_scope(&stored.entry.dn, &base_components, scope) {
                results.push(stored.entry.clone());
            }
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tokio::fs;
    use uuid::Uuid;

    fn temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!("opendr-backend-{}", Uuid::new_v4()))
    }

    #[tokio::test]
    async fn file_backend_persists_entries() {
        let dir = temp_dir();

        let backend = FileBackend::new(&dir).await.expect("backend created");
        let mut attributes = HashMap::new();
        attributes.insert("cn".to_string(), vec!["alice".to_string()]);
        attributes.insert("sn".to_string(), vec!["example".to_string()]);
        attributes.insert("userPassword".to_string(), vec!["secret".to_string()]);
        let entry = DirectoryEntry::new("cn=alice,dc=example,dc=org", attributes);

        backend
            .add_entry(entry.clone(), b"secret".to_vec())
            .await
            .expect("entry persisted");

        drop(backend);

        let backend = FileBackend::new(&dir).await.expect("backend reopened");

        assert!(backend
            .authenticate("cn=alice,dc=example,dc=org", b"secret")
            .await
            .expect("authentication succeeded"));

        let stored = backend
            .get_entry("cn=alice,dc=example,dc=org")
            .await
            .expect("lookup succeeds")
            .expect("entry returned");
        assert_eq!(stored, entry);

        fs::remove_dir_all(&dir).await.ok();
    }
}

fn apply_modification(
    entry: &mut DirectoryEntry,
    password: &mut Vec<u8>,
    modification: &Modification,
) {
    let attribute = modification.attribute.to_lowercase();
    let values = modification.values.clone();

    match modification.operation {
        ModifyOperation::Add => {
            let existing = entry.attributes.entry(attribute.clone()).or_default();
            for value in values {
                if !existing.contains(&value) {
                    existing.push(value.clone());
                }
            }
        }
        ModifyOperation::Delete => {
            if values.is_empty() {
                entry.attributes.remove(&attribute);
            } else if let Some(existing) = entry.attributes.get_mut(&attribute) {
                existing.retain(|candidate| !values.contains(candidate));
                if existing.is_empty() {
                    entry.attributes.remove(&attribute);
                }
            }
        }
        ModifyOperation::Replace => {
            if values.is_empty() {
                entry.attributes.remove(&attribute);
            } else {
                entry.attributes.insert(attribute.clone(), values);
            }
        }
    }

    if attribute == "userpassword" {
        if let Some(current) = entry
            .attributes
            .get(&attribute)
            .and_then(|vals| vals.first())
        {
            *password = current.as_bytes().to_vec();
        } else {
            password.clear();
        }
    }
}

fn compute_new_dn(dn: &str, new_rdn: &str, new_superior: Option<&str>) -> String {
    if let Some(superior) = new_superior {
        format!("{},{}", new_rdn, superior)
    } else if let Some((_, rest)) = dn.split_once(',') {
        if rest.is_empty() {
            new_rdn.to_string()
        } else {
            format!("{},{}", new_rdn, rest)
        }
    } else {
        new_rdn.to_string()
    }
}

fn plan_dn_renames(
    entries: &HashMap<String, StoredEntry>,
    old_dn: &str,
    new_dn: &str,
) -> Result<Vec<(String, String)>, BackendError> {
    let old_components = dn_components(old_dn);
    let new_components = dn_components(new_dn);
    let mut planned = Vec::new();

    for (current_dn, _) in entries.iter() {
        let current_components = dn_components(current_dn);
        if current_components.len() < old_components.len() {
            continue;
        }

        let suffix = &current_components[current_components.len() - old_components.len()..];
        if suffix
            .iter()
            .map(|component| component.to_lowercase())
            .eq(old_components
                .iter()
                .map(|component| component.to_lowercase()))
        {
            let mut updated =
                current_components[..current_components.len() - old_components.len()].to_vec();
            updated.extend(new_components.clone());
            let next_dn = updated.join(",");
            planned.push((current_dn.clone(), next_dn));
        }
    }

    planned.sort_by(|a, b| a.0.len().cmp(&b.0.len()));

    for (_, target) in &planned {
        if entries.contains_key(target) && !planned.iter().any(|(source, _)| source == target) {
            return Err(BackendError::AlreadyExists);
        }
    }

    Ok(planned)
}

fn update_entry_for_rename(
    entry: &mut DirectoryEntry,
    password: &mut Vec<u8>,
    original_dn: &str,
    new_rdn: &str,
    current_dn: &str,
    new_dn: &str,
    delete_old: bool,
) {
    if current_dn != original_dn {
        return;
    }

    if delete_old {
        let old_rdn = original_dn.split(',').next().unwrap_or("");
        for (attribute, value) in parse_rdn_components(old_rdn) {
            if let Some(existing) = entry.attributes.get_mut(&attribute) {
                existing.retain(|candidate| candidate != &value);
                if existing.is_empty() {
                    entry.attributes.remove(&attribute);
                }
            }
        }
    }

    for (attribute, value) in parse_rdn_components(new_rdn) {
        let values = entry.attributes.entry(attribute.clone()).or_default();
        if !values.contains(&value) {
            values.push(value.clone());
        }
    }

    if let Some(password_value) = entry
        .attributes
        .get("userpassword")
        .and_then(|vals| vals.first())
    {
        *password = password_value.as_bytes().to_vec();
    } else {
        password.clear();
    }

    entry.dn = new_dn.to_string();
}

fn dn_components(dn: &str) -> Vec<String> {
    dn.split(',')
        .map(|component| component.trim().to_string())
        .filter(|component| !component.is_empty())
        .collect()
}

fn parse_rdn_components(rdn: &str) -> Vec<(String, String)> {
    rdn.split('+')
        .filter_map(|part| {
            let (attr, value) = part.split_once('=')?;
            Some((attr.trim().to_lowercase(), value.trim().to_string()))
        })
        .collect()
}

fn entry_in_scope(dn: &str, base_components: &[String], scope: SearchScope) -> bool {
    let components = dn_components(dn);

    match scope {
        SearchScope(0) => components
            .iter()
            .map(|component| component.to_lowercase())
            .eq(base_components
                .iter()
                .map(|component| component.to_lowercase())),
        SearchScope(1) => {
            if components.len() != base_components.len() + 1 {
                return false;
            }
            components[1..]
                .iter()
                .map(|component| component.to_lowercase())
                .eq(base_components
                    .iter()
                    .map(|component| component.to_lowercase()))
        }
        SearchScope(2) => {
            if components.len() < base_components.len() {
                return false;
            }
            components[components.len() - base_components.len()..]
                .iter()
                .map(|component| component.to_lowercase())
                .eq(base_components
                    .iter()
                    .map(|component| component.to_lowercase()))
        }
        _ => false,
    }
}

use base64::Engine;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use ldap_parser::ldap::SearchScope;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use tokio::sync::{RwLock, mpsc};

use crate::csn::Csn;

/// Operational attributes for LDAP entries per RFC 4512
///
/// These attributes are maintained by the directory server and describe
/// operational information about the entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationalAttributes {
    /// entryCSN - Change Sequence Number for this entry (RFC 4533)
    pub entry_csn: Option<Csn>,
    /// entryUUID - Stable UUID for the entry
    pub entry_uuid: Option<String>,
    /// createTimestamp - When the entry was created (RFC 4512)
    pub create_timestamp: Option<String>,
    /// modifyTimestamp - When the entry was last modified (RFC 4512)
    pub modify_timestamp: Option<String>,
    /// creatorsName - DN of the user who created the entry (RFC 4512)
    pub creators_name: Option<String>,
    /// modifiersName - DN of the user who last modified the entry (RFC 4512)
    pub modifiers_name: Option<String>,
    /// lastSuccessfulLogin - Last successful account authentication timestamp
    #[serde(default)]
    pub last_successful_login: Option<String>,
    /// lastFailedLogin - Last failed account authentication timestamp
    #[serde(default)]
    pub last_failed_login: Option<String>,
    /// failedLoginCount - Consecutive failed authentication attempts
    #[serde(default)]
    pub failed_login_count: Option<u64>,
}

impl OperationalAttributes {
    /// Create empty operational attributes
    pub fn new() -> Self {
        Self {
            entry_csn: None,
            entry_uuid: None,
            create_timestamp: None,
            modify_timestamp: None,
            creators_name: None,
            modifiers_name: None,
            last_successful_login: None,
            last_failed_login: None,
            failed_login_count: None,
        }
    }

    /// Create operational attributes for a new entry
    pub fn for_new_entry(csn: Csn, creator_dn: Option<String>) -> Self {
        let timestamp = Self::current_timestamp();
        Self {
            entry_csn: Some(csn),
            entry_uuid: Some(uuid::Uuid::new_v4().to_string()),
            create_timestamp: Some(timestamp.clone()),
            modify_timestamp: Some(timestamp),
            creators_name: creator_dn.clone(),
            modifiers_name: creator_dn,
            last_successful_login: None,
            last_failed_login: None,
            failed_login_count: None,
        }
    }

    /// Update operational attributes for a modified entry
    pub fn for_modified_entry(&mut self, csn: Csn, modifier_dn: Option<String>) {
        self.entry_csn = Some(csn);
        self.modify_timestamp = Some(Self::current_timestamp());
        if let Some(modifier_dn) = modifier_dn {
            self.modifiers_name = Some(modifier_dn);
        }
    }

    /// Update server-managed account metadata after a successful authentication.
    pub fn record_successful_login(&mut self, csn: Csn) -> bool {
        let timestamp = Self::current_timestamp();
        self.record_successful_login_at(csn, timestamp)
    }

    fn record_successful_login_at(&mut self, csn: Csn, timestamp: String) -> bool {
        if self.last_successful_login.as_deref() == Some(timestamp.as_str())
            && self.failed_login_count == Some(0)
        {
            return false;
        }

        self.entry_csn = Some(csn);
        self.modify_timestamp = Some(timestamp.clone());
        self.last_successful_login = Some(timestamp);
        self.failed_login_count = Some(0);
        true
    }

    /// Update server-managed account metadata after a failed authentication.
    pub fn record_failed_login(&mut self, csn: Csn) -> bool {
        let timestamp = Self::current_timestamp();
        self.entry_csn = Some(csn);
        self.modify_timestamp = Some(timestamp.clone());
        self.last_failed_login = Some(timestamp);
        self.failed_login_count = Some(self.failed_login_count.unwrap_or(0).saturating_add(1));
        true
    }

    /// Get current timestamp in LDAP GeneralizedTime format (RFC 4517)
    /// Format: YYYYMMDDHHMMSSz
    fn current_timestamp() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System time before UNIX epoch");

        let secs = duration.as_secs();
        let tm = chrono::DateTime::from_timestamp(secs as i64, 0).expect("Invalid timestamp");
        tm.format("%Y%m%d%H%M%SZ").to_string()
    }

    /// Convert operational attributes to HashMap for LDAP responses
    pub fn to_attributes(&self) -> HashMap<String, Vec<String>> {
        let mut attrs = HashMap::new();

        if let Some(ref csn) = self.entry_csn {
            attrs.insert("entrycsn".to_string(), vec![csn.to_ldap_string()]);
        }
        if let Some(ref uuid) = self.entry_uuid {
            attrs.insert("entryuuid".to_string(), vec![uuid.clone()]);
        }
        if let Some(ref ts) = self.create_timestamp {
            attrs.insert("createtimestamp".to_string(), vec![ts.clone()]);
        }
        if let Some(ref ts) = self.modify_timestamp {
            attrs.insert("modifytimestamp".to_string(), vec![ts.clone()]);
        }
        if let Some(ref dn) = self.creators_name {
            attrs.insert("creatorsname".to_string(), vec![dn.clone()]);
        }
        if let Some(ref dn) = self.modifiers_name {
            attrs.insert("modifiersname".to_string(), vec![dn.clone()]);
        }
        if let Some(ref ts) = self.last_successful_login {
            attrs.insert("lastsuccessfullogin".to_string(), vec![ts.clone()]);
        }
        if let Some(ref ts) = self.last_failed_login {
            attrs.insert("lastfailedlogin".to_string(), vec![ts.clone()]);
        }
        if let Some(count) = self.failed_login_count {
            attrs.insert("failedlogincount".to_string(), vec![count.to_string()]);
        }

        attrs
    }

    /// Check if a given attribute name is an operational attribute
    pub fn is_operational(attr_name: &str) -> bool {
        attr_name.eq_ignore_ascii_case("entrycsn")
            || attr_name.eq_ignore_ascii_case("entryuuid")
            || attr_name.eq_ignore_ascii_case("createtimestamp")
            || attr_name.eq_ignore_ascii_case("modifytimestamp")
            || attr_name.eq_ignore_ascii_case("creatorsname")
            || attr_name.eq_ignore_ascii_case("modifiersname")
            || attr_name.eq_ignore_ascii_case("subschemasubentry")
            || attr_name.eq_ignore_ascii_case("hassubordinates")
            || attr_name.eq_ignore_ascii_case("numsubordinates")
            || attr_name.eq_ignore_ascii_case("structuralobjectclass")
            || attr_name.eq_ignore_ascii_case("pwdchangedtime")
            || attr_name.eq_ignore_ascii_case("pwdaccountlockedtime")
            || attr_name.eq_ignore_ascii_case("pwdfailuretime")
            || attr_name.eq_ignore_ascii_case("pwdhistory")
            || attr_name.eq_ignore_ascii_case("lastsuccessfullogin")
            || attr_name.eq_ignore_ascii_case("lastfailedlogin")
            || attr_name.eq_ignore_ascii_case("failedlogincount")
            || attr_name.eq_ignore_ascii_case("contextcsn")
    }
}

impl Default for OperationalAttributes {
    fn default() -> Self {
        Self::new()
    }
}

/// Representation of an LDAP directory entry used by storage backends.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryEntry {
    pub dn: String,
    pub attributes: HashMap<String, Vec<String>>,
    /// Operational attributes (not returned by default in searches)
    #[serde(default)]
    pub operational_attributes: OperationalAttributes,
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
            operational_attributes: OperationalAttributes::new(),
        }
    }

    /// Create a new entry with operational attributes
    pub fn with_operational_attrs(
        dn: impl Into<String>,
        attributes: HashMap<String, Vec<String>>,
        operational_attributes: OperationalAttributes,
    ) -> Self {
        let normalized_attributes = attributes
            .into_iter()
            .map(|(key, values)| (key.to_lowercase(), values))
            .collect();

        Self {
            dn: dn.into(),
            attributes: normalized_attributes,
            operational_attributes,
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

/// Errors from schema-validated native modify operations.
#[derive(Debug)]
pub enum NativeModifyError {
    Backend(BackendError),
    Schema(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationOutcome {
    Success,
    Failure,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationMetadataUpdate {
    pub dn: String,
    pub outcome: AuthenticationOutcome,
}

impl AuthenticationMetadataUpdate {
    pub fn new(dn: impl Into<String>, outcome: AuthenticationOutcome) -> Self {
        Self {
            dn: dn.into(),
            outcome,
        }
    }
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

impl NativeModifyError {
    pub fn schema_violation(message: impl Into<String>) -> Self {
        Self::Schema(message.into())
    }

    pub fn into_backend_error(self) -> BackendError {
        match self {
            Self::Backend(err) => err,
            Self::Schema(message) => BackendError::Storage(message),
        }
    }
}

impl fmt::Display for NativeModifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Backend(err) => write!(f, "{}", err),
            Self::Schema(message) => write!(f, "{}", message),
        }
    }
}

impl std::error::Error for NativeModifyError {}

impl From<BackendError> for NativeModifyError {
    fn from(err: BackendError) -> Self {
        Self::Backend(err)
    }
}

/// Trait describing the operations required from the directory data store.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait DirectoryBackend: Send + Sync {
    async fn authenticate(&self, dn: &str, password: &[u8]) -> Result<bool, BackendError>;

    async fn record_authentication_success(&self, dn: &str) -> Result<bool, BackendError> {
        let _ = dn;
        Ok(false)
    }

    async fn record_authentication_failure(&self, dn: &str) -> Result<bool, BackendError> {
        let _ = dn;
        Ok(false)
    }

    async fn record_authentication_updates(
        &self,
        updates: &[AuthenticationMetadataUpdate],
    ) -> Result<usize, BackendError> {
        let mut written = 0usize;
        for update in updates {
            let updated = match update.outcome {
                AuthenticationOutcome::Success => {
                    self.record_authentication_success(&update.dn).await?
                }
                AuthenticationOutcome::Failure => {
                    self.record_authentication_failure(&update.dn).await?
                }
            };
            if updated {
                written += 1;
            }
        }
        Ok(written)
    }

    async fn replace_operational_attributes(
        &self,
        dn: &str,
        operational_attributes: OperationalAttributes,
    ) -> Result<(), BackendError> {
        let _ = (dn, operational_attributes);
        Ok(())
    }

    async fn get_entry(&self, dn: &str) -> Result<Option<DirectoryEntry>, BackendError>;

    async fn add_entry(&self, entry: DirectoryEntry, password: Vec<u8>)
    -> Result<(), BackendError>;

    async fn add_entry_with_actor(
        &self,
        entry: DirectoryEntry,
        password: Vec<u8>,
        actor_dn: Option<String>,
    ) -> Result<(), BackendError> {
        let _ = actor_dn;
        self.add_entry(entry, password).await
    }

    async fn delete_entry(&self, dn: &str) -> Result<(), BackendError>;

    async fn delete_entry_with_actor(
        &self,
        dn: &str,
        actor_dn: Option<String>,
    ) -> Result<(), BackendError> {
        let _ = actor_dn;
        self.delete_entry(dn).await
    }

    async fn modify_entry(
        &self,
        dn: &str,
        modifications: Vec<Modification>,
    ) -> Result<(), BackendError>;

    async fn modify_entry_with_actor(
        &self,
        dn: &str,
        modifications: Vec<Modification>,
        actor_dn: Option<String>,
    ) -> Result<(), BackendError> {
        let _ = actor_dn;
        self.modify_entry(dn, modifications).await
    }

    /// Validate and apply a modify operation as one backend operation.
    ///
    /// Backends with transactional storage should override this method so the
    /// current entry is read inside the write transaction, schema validation is
    /// performed against the candidate attributes, and cache invalidation only
    /// happens after the write commits.
    async fn modify_entry_validated_with_actor(
        &self,
        dn: &str,
        modifications: Vec<Modification>,
        actor_dn: Option<String>,
        schema: &crate::schema::LdapSchema,
    ) -> Result<(), NativeModifyError> {
        let existing_entry = self
            .get_entry(dn)
            .await?
            .ok_or(NativeModifyError::Backend(BackendError::NotFound))?;
        let mut candidate_attributes = existing_entry.attributes.clone();
        apply_modifications_to_attributes(&mut candidate_attributes, &modifications);
        schema
            .validate_modified_entry(&existing_entry.attributes, &candidate_attributes)
            .map_err(|err| {
                NativeModifyError::schema_violation(format!("Schema validation failed: {}", err))
            })?;

        self.modify_entry_with_actor(dn, modifications, actor_dn)
            .await?;

        Ok(())
    }

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

    async fn rename_entry_with_actor(
        &self,
        dn: &str,
        new_rdn: &str,
        delete_old: bool,
        new_superior: Option<String>,
        actor_dn: Option<String>,
    ) -> Result<(), BackendError> {
        let _ = actor_dn;
        self.rename_entry(dn, new_rdn, delete_old, new_superior)
            .await
    }

    async fn search_entries(
        &self,
        base_dn: &str,
        scope: SearchScope,
    ) -> Result<Vec<DirectoryEntry>, BackendError>;

    async fn search_entries_with_hint(
        &self,
        base_dn: &str,
        scope: SearchScope,
        _hint: Option<SearchCandidateHint>,
    ) -> Result<Vec<DirectoryEntry>, BackendError> {
        self.search_entries(base_dn, scope).await
    }

    async fn search_entries_with_hint_report(
        &self,
        base_dn: &str,
        scope: SearchScope,
        hint: Option<SearchCandidateHint>,
    ) -> Result<SearchEntriesWithHintReport, BackendError> {
        let entries = self.search_entries_with_hint(base_dn, scope, hint).await?;
        Ok(SearchEntriesWithHintReport {
            entries,
            hint_covers_filter: false,
        })
    }

    fn supports_search_entry_streaming(&self) -> bool {
        false
    }

    async fn stream_search_entries_with_hint_report(
        &self,
        base_dn: &str,
        scope: SearchScope,
        hint: Option<SearchCandidateHint>,
    ) -> Result<SearchEntriesStreamReport, BackendError> {
        let report = self
            .search_entries_with_hint_report(base_dn, scope, hint)
            .await?;
        let (sender, entries) = mpsc::channel(64);
        tokio::spawn(async move {
            for entry in report.entries {
                if sender.send(Ok(entry)).await.is_err() {
                    break;
                }
            }
        });

        Ok(SearchEntriesStreamReport {
            entries,
            hint_covers_filter: report.hint_covers_filter,
        })
    }

    async fn search_entries_paginated(
        &self,
        base_dn: &str,
        scope: SearchScope,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<DirectoryEntry>, BackendError> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        Ok(self
            .search_entries(base_dn, scope)
            .await?
            .into_iter()
            .skip(offset)
            .take(limit)
            .collect())
    }

    async fn count_entries(
        &self,
        base_dn: &str,
        scope: SearchScope,
    ) -> Result<usize, BackendError> {
        Ok(self.search_entries(base_dn, scope).await?.len())
    }

    /// Get the current contextCSN for the database
    ///
    /// # Returns
    /// * `Ok(Some(Csn))` - The current contextCSN
    /// * `Ok(None)` - No contextCSN set yet (empty database)
    /// * `Err(BackendError)` - Error retrieving contextCSN
    async fn get_context_csn(&self) -> Result<Option<crate::csn::Csn>, BackendError>;

    /// Set the contextCSN for the database
    ///
    /// # Arguments
    /// * `csn` - The new contextCSN value
    ///
    /// # Returns
    /// * `Ok(())` - contextCSN updated successfully
    /// * `Err(BackendError)` - Error updating contextCSN
    async fn set_context_csn(&self, csn: crate::csn::Csn) -> Result<(), BackendError>;

    /// Return the changelog backing replication, if this backend exposes one.
    fn replication_changelog(&self) -> Option<Arc<crate::replication::ChangelogTracker>> {
        None
    }

    /// Subscribe to live replication changes, if this backend exposes them.
    fn subscribe_to_replication_changes(
        &self,
    ) -> Option<tokio::sync::broadcast::Receiver<crate::replication_provider_fsm::ChangelogEntry>>
    {
        None
    }

    /// Return provider lifecycle state for inbound replication streams, if available.
    fn replication_provider_lifecycle(
        &self,
    ) -> Option<Arc<crate::replication_service::ReplicationProviderLifecycle>> {
        None
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ModifyOperation {
    Add,
    Delete,
    Replace,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SearchCandidateHint {
    Equality {
        attribute: String,
        value: String,
    },
    Present {
        attribute: String,
    },
    Substring {
        attribute: String,
        parts: Vec<SearchSubstringPart>,
    },
    GreaterOrEqual {
        attribute: String,
        value: String,
    },
    LessOrEqual {
        attribute: String,
        value: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchEntriesWithHintReport {
    pub entries: Vec<DirectoryEntry>,
    pub hint_covers_filter: bool,
}

pub type SearchEntryStreamReceiver = mpsc::Receiver<Result<DirectoryEntry, BackendError>>;

pub struct SearchEntriesStreamReport {
    pub entries: SearchEntryStreamReceiver,
    pub hint_covers_filter: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SearchSubstringPart {
    Initial(String),
    Any(String),
    Final(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Modification {
    pub operation: ModifyOperation,
    pub attribute: String,
    pub values: Vec<String>,
}

pub fn apply_modifications_to_attributes(
    attributes: &mut HashMap<String, Vec<String>>,
    modifications: &[Modification],
) {
    for modification in modifications {
        let attribute = modification.attribute.to_lowercase();
        match modification.operation {
            ModifyOperation::Add => {
                let values = attributes.entry(attribute).or_default();
                for value in &modification.values {
                    if !values.contains(value) {
                        values.push(value.clone());
                    }
                }
            }
            ModifyOperation::Delete => {
                if modification.values.is_empty() {
                    attributes.remove(&attribute);
                } else if let Some(values) = attributes.get_mut(&attribute) {
                    values.retain(|value| !modification.values.contains(value));
                    if values.is_empty() {
                        attributes.remove(&attribute);
                    }
                }
            }
            ModifyOperation::Replace => {
                if modification.values.is_empty() {
                    attributes.remove(&attribute);
                } else {
                    attributes.insert(attribute, modification.values.clone());
                }
            }
        }
    }
}

struct StoredEntry {
    password: Vec<u8>,
    entry: DirectoryEntry,
}

/// In-memory mock backend useful during early development.
pub struct MockBackend {
    entries: RwLock<HashMap<String, StoredEntry>>,
    context_csn: RwLock<Option<crate::csn::Csn>>,
    csn_generator: Arc<crate::csn::CsnGenerator>,
}

impl MockBackend {
    pub fn new() -> Self {
        Self::with_replica_id(1)
    }

    pub fn with_replica_id(replica_id: u16) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            context_csn: RwLock::new(None),
            csn_generator: Arc::new(crate::csn::CsnGenerator::new(replica_id)),
        }
    }

    pub fn from_credentials<I, D, P>(credentials: I) -> Self
    where
        I: IntoIterator<Item = (D, P)>,
        D: Into<String>,
        P: Into<Vec<u8>>,
    {
        Self::from_credentials_with_replica_id(credentials, 1)
    }

    pub fn from_credentials_with_replica_id<I, D, P>(credentials: I, replica_id: u16) -> Self
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
                        operational_attributes: OperationalAttributes::new(),
                    },
                },
            );
        }

        Self {
            entries: RwLock::new(entries),
            context_csn: RwLock::new(None),
            csn_generator: Arc::new(crate::csn::CsnGenerator::new(replica_id)),
        }
    }

    async fn add_entry_internal(
        &self,
        mut entry: DirectoryEntry,
        password: Vec<u8>,
        actor_dn: Option<&str>,
    ) -> Result<(), BackendError> {
        let mut entries = self.entries.write().await;
        if entries.contains_key(&entry.dn) {
            return Err(BackendError::AlreadyExists);
        }

        let csn = self.csn_generator.generate();
        entry.operational_attributes =
            OperationalAttributes::for_new_entry(csn.clone(), actor_dn.map(str::to_string));

        let mut context_csn = self.context_csn.write().await;
        *context_csn = Some(csn);
        drop(context_csn);

        entries.insert(entry.dn.clone(), StoredEntry { password, entry });

        Ok(())
    }

    async fn modify_entry_internal(
        &self,
        dn: &str,
        modifications: Vec<Modification>,
        actor_dn: Option<&str>,
    ) -> Result<(), BackendError> {
        let mut entries = self.entries.write().await;
        let stored = entries.get_mut(dn).ok_or(BackendError::NotFound)?;

        let csn = self.csn_generator.generate();
        stored
            .entry
            .operational_attributes
            .for_modified_entry(csn.clone(), actor_dn.map(str::to_string));

        for modification in modifications {
            apply_modification(&mut stored.entry, &mut stored.password, &modification);
        }

        let mut context_csn = self.context_csn.write().await;
        *context_csn = Some(csn);

        Ok(())
    }

    async fn rename_entry_internal(
        &self,
        dn: &str,
        new_rdn: &str,
        delete_old: bool,
        new_superior: Option<String>,
        actor_dn: Option<&str>,
    ) -> Result<(), BackendError> {
        let mut entries = self.entries.write().await;
        let Some(_) = entries.get(dn) else {
            return Err(BackendError::NotFound);
        };

        let target_dn = compute_new_dn(dn, new_rdn, new_superior.as_deref());

        if entries.contains_key(&target_dn) {
            return Err(BackendError::AlreadyExists);
        }

        let renames = plan_dn_renames(&entries, dn, &target_dn)?;
        let csn = self.csn_generator.generate();

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
                stored
                    .entry
                    .operational_attributes
                    .for_modified_entry(csn.clone(), actor_dn.map(str::to_string));
                entries.insert(new_dn, stored);
            }
        }

        let mut context_csn = self.context_csn.write().await;
        *context_csn = Some(csn);

        Ok(())
    }

    async fn record_account_authentication<F>(
        &self,
        dn: &str,
        update: F,
    ) -> Result<bool, BackendError>
    where
        F: FnOnce(&mut OperationalAttributes, Csn) -> bool,
    {
        let mut entries = self.entries.write().await;
        let Some(stored) = entries.get_mut(dn) else {
            return Ok(false);
        };

        let csn = self.csn_generator.generate();
        if !update(&mut stored.entry.operational_attributes, csn.clone()) {
            return Ok(false);
        }

        let mut context_csn = self.context_csn.write().await;
        *context_csn = Some(csn);

        Ok(true)
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
            .map(|entry| password_matches(entry.password.as_slice(), password))
            .unwrap_or(false))
    }

    async fn record_authentication_success(&self, dn: &str) -> Result<bool, BackendError> {
        self.record_account_authentication(dn, |attrs, csn| attrs.record_successful_login(csn))
            .await
    }

    async fn record_authentication_failure(&self, dn: &str) -> Result<bool, BackendError> {
        self.record_account_authentication(dn, |attrs, csn| attrs.record_failed_login(csn))
            .await
    }

    async fn replace_operational_attributes(
        &self,
        dn: &str,
        operational_attributes: OperationalAttributes,
    ) -> Result<(), BackendError> {
        let mut entries = self.entries.write().await;
        let stored = entries.get_mut(dn).ok_or(BackendError::NotFound)?;
        stored.entry.operational_attributes = operational_attributes;

        Ok(())
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
        self.add_entry_internal(entry, password, None).await
    }

    async fn add_entry_with_actor(
        &self,
        entry: DirectoryEntry,
        password: Vec<u8>,
        actor_dn: Option<String>,
    ) -> Result<(), BackendError> {
        self.add_entry_internal(entry, password, actor_dn.as_deref())
            .await
    }

    async fn delete_entry(&self, dn: &str) -> Result<(), BackendError> {
        let mut entries = self.entries.write().await;
        entries.remove(dn).ok_or(BackendError::NotFound)?;

        // Update contextCSN after delete
        let csn = self.csn_generator.generate();
        let mut context_csn = self.context_csn.write().await;
        *context_csn = Some(csn);

        Ok(())
    }

    async fn modify_entry(
        &self,
        dn: &str,
        modifications: Vec<Modification>,
    ) -> Result<(), BackendError> {
        self.modify_entry_internal(dn, modifications, None).await
    }

    async fn modify_entry_with_actor(
        &self,
        dn: &str,
        modifications: Vec<Modification>,
        actor_dn: Option<String>,
    ) -> Result<(), BackendError> {
        self.modify_entry_internal(dn, modifications, actor_dn.as_deref())
            .await
    }

    async fn modify_entry_validated_with_actor(
        &self,
        dn: &str,
        modifications: Vec<Modification>,
        actor_dn: Option<String>,
        schema: &crate::schema::LdapSchema,
    ) -> Result<(), NativeModifyError> {
        let mut entries = self.entries.write().await;
        let stored = entries.get_mut(dn).ok_or(BackendError::NotFound)?;
        let mut candidate_attributes = stored.entry.attributes.clone();
        apply_modifications_to_attributes(&mut candidate_attributes, &modifications);
        schema
            .validate_modified_entry(&stored.entry.attributes, &candidate_attributes)
            .map_err(|err| {
                NativeModifyError::schema_violation(format!("Schema validation failed: {}", err))
            })?;

        let csn = self.csn_generator.generate();
        stored
            .entry
            .operational_attributes
            .for_modified_entry(csn.clone(), actor_dn.as_deref().map(str::to_string));

        for modification in &modifications {
            apply_modification(&mut stored.entry, &mut stored.password, modification);
        }

        let mut context_csn = self.context_csn.write().await;
        *context_csn = Some(csn);

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
        self.rename_entry_internal(dn, new_rdn, delete_old, new_superior, None)
            .await
    }

    async fn rename_entry_with_actor(
        &self,
        dn: &str,
        new_rdn: &str,
        delete_old: bool,
        new_superior: Option<String>,
        actor_dn: Option<String>,
    ) -> Result<(), BackendError> {
        self.rename_entry_internal(dn, new_rdn, delete_old, new_superior, actor_dn.as_deref())
            .await
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

    async fn search_entries_paginated(
        &self,
        base_dn: &str,
        scope: SearchScope,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<DirectoryEntry>, BackendError> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let entries = self.entries.read().await;
        let base_components = dn_components(base_dn);

        Ok(entries
            .values()
            .filter(|stored| entry_in_scope(&stored.entry.dn, &base_components, scope))
            .skip(offset)
            .take(limit)
            .map(|stored| stored.entry.clone())
            .collect())
    }

    async fn count_entries(
        &self,
        base_dn: &str,
        scope: SearchScope,
    ) -> Result<usize, BackendError> {
        let entries = self.entries.read().await;
        let base_components = dn_components(base_dn);

        Ok(entries
            .values()
            .filter(|stored| entry_in_scope(&stored.entry.dn, &base_components, scope))
            .count())
    }

    async fn get_context_csn(&self) -> Result<Option<crate::csn::Csn>, BackendError> {
        let context_csn = self.context_csn.read().await;
        Ok(context_csn.clone())
    }

    async fn set_context_csn(&self, csn: crate::csn::Csn) -> Result<(), BackendError> {
        let mut context_csn = self.context_csn.write().await;
        *context_csn = Some(csn);
        Ok(())
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

fn password_matches(stored_password: &[u8], candidate: &[u8]) -> bool {
    if stored_password == candidate {
        return true;
    }

    let Ok(stored_password) = std::str::from_utf8(stored_password) else {
        return false;
    };

    stored_password.starts_with("{SSHA512}") && verify_ssha512(candidate, stored_password)
}

fn verify_ssha512(password: &[u8], stored_hash: &str) -> bool {
    let hash_b64 = stored_hash.strip_prefix("{SSHA512}").unwrap_or(stored_hash);
    let decoded = match base64::engine::general_purpose::STANDARD.decode(hash_b64) {
        Ok(decoded) => decoded,
        Err(_) => return false,
    };

    if decoded.len() < 64 {
        return false;
    }

    let (stored_hash, salt) = decoded.split_at(64);
    let mut hasher = Sha512::new();
    hasher.update(password);
    hasher.update(salt);

    hasher.finalize().as_slice() == stored_hash
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

#[cfg(test)]
mod tests {
    use super::OperationalAttributes;
    use crate::csn::Csn;

    #[test]
    fn successful_login_noops_when_timestamp_and_failed_count_are_unchanged() {
        let mut attrs = OperationalAttributes::new();
        let timestamp = "20260414010203Z".to_string();

        assert!(attrs.record_successful_login_at(Csn::with_values(1, 1, 1, 0), timestamp.clone()));
        assert_eq!(
            attrs.last_successful_login.as_deref(),
            Some(timestamp.as_str())
        );
        assert_eq!(attrs.failed_login_count, Some(0));
        let entry_csn = attrs.entry_csn.clone();

        assert!(!attrs.record_successful_login_at(Csn::with_values(2, 1, 2, 0), timestamp));
        assert_eq!(attrs.entry_csn, entry_csn);
        assert_eq!(attrs.failed_login_count, Some(0));
    }

    #[test]
    fn successful_login_same_second_still_resets_failed_count() {
        let mut attrs = OperationalAttributes::new();
        let timestamp = "20260414010203Z".to_string();
        attrs.last_successful_login = Some(timestamp.clone());
        attrs.failed_login_count = Some(3);

        assert!(attrs.record_successful_login_at(Csn::with_values(1, 1, 1, 0), timestamp));
        assert_eq!(attrs.failed_login_count, Some(0));
    }
}

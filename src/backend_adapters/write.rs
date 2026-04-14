use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::time::Instant;

use crate::backend::{
    DirectoryBackend, DirectoryEntry, Modification as BackendMod, ModifyOperation,
    OperationalAttributes,
};
use crate::fsm::{WriteOperation, WriteResultCode};
use crate::metrics::{FsmType, MetricsCollector};
use crate::write_fsm::{
    AciChecker, Modification as WriteMod, SchemaValidator, WriteBackend, WriteEntry, WriteMetrics,
};

#[derive(Debug, Clone)]
enum PendingWriteOperation {
    Add {
        entry: Box<DirectoryEntry>,
        password: Vec<u8>,
    },
    Modify {
        dn: String,
        modifications: Vec<BackendMod>,
    },
    ModifyDn {
        dn: String,
        new_rdn: String,
        delete_old: bool,
        new_superior: Option<String>,
    },
    Delete {
        dn: String,
    },
}

#[derive(Debug, Clone)]
struct WriteTransactionRecord {
    actor_dn: Option<String>,
    _started_at: Instant,
    pending_operations: Vec<PendingWriteOperation>,
}

/// Adapter that implements `WriteBackend` using a `DirectoryBackend`.
pub struct WriteBackendAdapter {
    backend: Arc<dyn DirectoryBackend>,
    actor_dn: Option<String>,
    transactions: Arc<Mutex<HashMap<String, WriteTransactionRecord>>>,
}

impl WriteBackendAdapter {
    pub fn new(backend: Arc<dyn DirectoryBackend>) -> Self {
        Self {
            backend,
            actor_dn: None,
            transactions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Set the authenticated actor DN that should be attached to write operations.
    pub fn with_actor(mut self, actor_dn: Option<String>) -> Self {
        self.actor_dn = actor_dn;
        self
    }

    fn ensure_open_transaction(&self, txn_id: &str) -> Result<(), String> {
        let transactions = self.transactions.lock().unwrap();
        if transactions.contains_key(txn_id) {
            Ok(())
        } else {
            Err(format!("Unknown or closed transaction: {}", txn_id))
        }
    }

    fn queue_operation(
        &self,
        txn_id: &str,
        operation: PendingWriteOperation,
    ) -> Result<(), String> {
        let mut transactions = self.transactions.lock().unwrap();
        let record = transactions
            .get_mut(txn_id)
            .ok_or_else(|| format!("Unknown or closed transaction: {}", txn_id))?;
        record.pending_operations.push(operation);
        Ok(())
    }

    fn transaction_record(&self, txn_id: &str) -> Result<WriteTransactionRecord, String> {
        let transactions = self.transactions.lock().unwrap();
        transactions
            .get(txn_id)
            .cloned()
            .ok_or_else(|| format!("Unknown or closed transaction: {}", txn_id))
    }

    async fn apply_pending_operation(
        &self,
        actor_dn: Option<String>,
        operation: PendingWriteOperation,
    ) -> Result<(), String> {
        match operation {
            PendingWriteOperation::Add { entry, password } => self
                .backend
                .add_entry_with_actor(*entry, password, actor_dn)
                .await
                .map_err(|e| format!("Backend add_entry error: {}", e)),
            PendingWriteOperation::Modify { dn, modifications } => self
                .backend
                .modify_entry_with_actor(&dn, modifications, actor_dn)
                .await
                .map_err(|e| format!("Backend modify_entry error: {}", e)),
            PendingWriteOperation::ModifyDn {
                dn,
                new_rdn,
                delete_old,
                new_superior,
            } => self
                .backend
                .rename_entry_with_actor(&dn, &new_rdn, delete_old, new_superior, actor_dn)
                .await
                .map_err(|e| format!("Backend rename_entry error: {}", e)),
            PendingWriteOperation::Delete { dn } => self
                .backend
                .delete_entry_with_actor(&dn, actor_dn)
                .await
                .map_err(|e| format!("Backend delete_entry error: {}", e)),
        }
    }

    fn parse_ldif_entry(
        &self,
        dn: &str,
        entry: &[u8],
    ) -> Result<(DirectoryEntry, Vec<u8>), String> {
        let entry_str = String::from_utf8(entry.to_vec())
            .map_err(|err| format!("Invalid UTF-8 entry payload: {}", err))?;

        let mut attributes = HashMap::new();
        let mut password = Vec::new();
        for line in entry_str.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if line.starts_with("dn:") || line.starts_with("DN:") {
                continue;
            }

            let Some((key, value)) = line.split_once(':') else {
                return Err(format!("Invalid LDIF line: {}", line));
            };

            let key = key.trim().to_lowercase();
            if OperationalAttributes::is_operational(&key) {
                return Err(server_managed_operational_attribute_diagnostic(&key));
            }
            let value = value.trim().to_string();
            if key == "userpassword" && password.is_empty() {
                password = value.as_bytes().to_vec();
            }
            attributes.entry(key).or_insert_with(Vec::new).push(value);
        }

        Ok((DirectoryEntry::new(dn, attributes), password))
    }
}

fn server_managed_operational_attribute_diagnostic(attribute: &str) -> String {
    format!("operational attribute {attribute} is server-managed")
}

fn write_mod_attribute(modification: &WriteMod) -> &str {
    match modification {
        WriteMod::Add { name, .. }
        | WriteMod::Delete { name, .. }
        | WriteMod::Replace { name, .. } => name,
    }
}

/// Permissive schema validator used when the production server has already
/// applied any required schema checks before entering the native write FSM path.
#[derive(Debug, Default)]
pub struct PassthroughSchemaValidator;

#[async_trait]
impl SchemaValidator for PassthroughSchemaValidator {
    async fn validate_entry(&self, _entry: &WriteEntry) -> Result<(), String> {
        Ok(())
    }

    async fn validate_modifications(
        &self,
        _dn: &str,
        _modifications: &[WriteMod],
    ) -> Result<(), String> {
        Ok(())
    }
}

/// Access control is enforced by the production server request pipeline before
/// entering the native write FSM path.
#[derive(Debug, Default)]
pub struct AllowAllWriteAciChecker;

#[async_trait]
impl AciChecker for AllowAllWriteAciChecker {
    async fn check_write_permission(
        &self,
        _user_dn: Option<&str>,
        _operation: &WriteOperation,
    ) -> Result<(), String> {
        Ok(())
    }
}

/// Write FSM metrics adapter backed by the shared `MetricsCollector`.
pub struct ProductionWriteMetrics {
    metrics: Arc<MetricsCollector>,
}

impl ProductionWriteMetrics {
    pub fn new(metrics: Arc<MetricsCollector>) -> Self {
        Self { metrics }
    }
}

impl WriteMetrics for ProductionWriteMetrics {
    fn record_write_start(&self, user_dn: Option<&str>, operation: &WriteOperation) {
        self.metrics.record_fsm_state(FsmType::Write, "start");
        self.metrics.increment_counter("fsm_write_start_total", 1);
        self.metrics.increment_counter(
            &format!("fsm_write_start_{}_total", write_operation_name(operation)),
            1,
        );
        if user_dn.is_some() {
            self.metrics
                .increment_counter("fsm_write_authenticated_start_total", 1);
        }
    }

    fn record_validation_complete(&self, operation_type: &str, duration: Duration) {
        self.metrics
            .record_fsm_state(FsmType::Write, "validation_complete");
        self.metrics.increment_counter(
            &format!("fsm_write_validation_complete_{}_total", operation_type),
            1,
        );
        self.metrics.set_gauge(
            "fsm_write_last_validation_duration_ms",
            duration.as_millis() as u64,
        );
    }

    fn record_schema_check_complete(&self, operation_type: &str, duration: Duration) {
        self.metrics
            .record_fsm_state(FsmType::Write, "schema_check_complete");
        self.metrics.increment_counter(
            &format!("fsm_write_schema_check_complete_{}_total", operation_type),
            1,
        );
        self.metrics.set_gauge(
            "fsm_write_last_schema_check_duration_ms",
            duration.as_millis() as u64,
        );
    }

    fn record_aci_check_complete(&self, operation_type: &str, duration: Duration) {
        self.metrics
            .record_fsm_state(FsmType::Write, "aci_check_complete");
        self.metrics.increment_counter(
            &format!("fsm_write_aci_check_complete_{}_total", operation_type),
            1,
        );
        self.metrics.set_gauge(
            "fsm_write_last_aci_check_duration_ms",
            duration.as_millis() as u64,
        );
    }

    fn record_transaction_started(&self, _txn_id: &str) {
        self.metrics
            .record_fsm_state(FsmType::Write, "transaction_started");
        self.metrics
            .increment_counter("fsm_write_transaction_started_total", 1);
    }

    fn record_write_complete(
        &self,
        operation: &WriteOperation,
        result_code: &WriteResultCode,
        duration: Duration,
    ) {
        self.metrics.record_fsm_state(FsmType::Write, "completed");
        self.metrics
            .increment_counter("fsm_write_complete_total", 1);
        self.metrics.increment_counter(
            &format!(
                "fsm_write_complete_{}_total",
                write_operation_name(operation)
            ),
            1,
        );
        self.metrics.increment_counter(
            &format!("fsm_write_result_{:?}_total", result_code).to_lowercase(),
            1,
        );
        self.metrics.set_gauge(
            "fsm_write_last_total_duration_ms",
            duration.as_millis() as u64,
        );
    }

    fn record_write_rollback(&self, operation: &WriteOperation, reason: &str) {
        self.metrics.record_fsm_state(FsmType::Write, "rollback");
        self.metrics
            .increment_counter("fsm_write_rollback_total", 1);
        self.metrics.increment_counter(
            &format!(
                "fsm_write_rollback_{}_total",
                write_operation_name(operation)
            ),
            1,
        );
        self.metrics.increment_counter(
            &format!(
                "fsm_write_rollback_reason_{}_total",
                sanitize_metric_component(reason)
            ),
            1,
        );
    }
}

fn write_operation_name(operation: &WriteOperation) -> &'static str {
    match operation {
        WriteOperation::Add { .. } => "add",
        WriteOperation::Modify { .. } => "modify",
        WriteOperation::ModifyDn { .. } => "modifydn",
        WriteOperation::Delete { .. } => "delete",
    }
}

fn sanitize_metric_component(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

#[async_trait]
impl WriteBackend for WriteBackendAdapter {
    async fn begin_transaction(&self) -> Result<String, String> {
        let txn_id = uuid::Uuid::new_v4().to_string();
        let record = WriteTransactionRecord {
            actor_dn: self.actor_dn.clone(),
            _started_at: Instant::now(),
            pending_operations: Vec::new(),
        };

        self.transactions
            .lock()
            .unwrap()
            .insert(txn_id.clone(), record);
        Ok(txn_id)
    }

    async fn commit_transaction(&self, txn_id: &str) -> Result<(), String> {
        let record = self.transaction_record(txn_id)?;
        for operation in record.pending_operations {
            self.apply_pending_operation(record.actor_dn.clone(), operation)
                .await?;
        }

        self.transactions
            .lock()
            .unwrap()
            .remove(txn_id)
            .ok_or_else(|| format!("Unknown or closed transaction: {}", txn_id))?;
        Ok(())
    }

    async fn rollback_transaction(&self, txn_id: &str, _reason: &str) -> Result<(), String> {
        self.transactions
            .lock()
            .unwrap()
            .remove(txn_id)
            .ok_or_else(|| format!("Unknown or closed transaction: {}", txn_id))?;
        Ok(())
    }

    async fn validate_entry(&self, dn: &str, entry: &[u8]) -> Result<(), String> {
        let (parsed, _) = self.parse_ldif_entry(dn, entry)?;
        if parsed.dn.trim().is_empty() {
            return Err("Entry DN cannot be empty".to_string());
        }
        Ok(())
    }

    async fn add_entry(&self, txn_id: &str, dn: &str, entry: &[u8]) -> Result<(), String> {
        self.ensure_open_transaction(txn_id)?;
        let (dir_entry, password) = self.parse_ldif_entry(dn, entry)?;
        self.queue_operation(
            txn_id,
            PendingWriteOperation::Add {
                entry: Box::new(dir_entry),
                password,
            },
        )
    }

    async fn modify_entry(
        &self,
        txn_id: &str,
        dn: &str,
        modifications: &[WriteMod],
    ) -> Result<(), String> {
        self.ensure_open_transaction(txn_id)?;
        if let Some(attribute) = modifications
            .iter()
            .map(write_mod_attribute)
            .find(|attribute| OperationalAttributes::is_operational(attribute))
        {
            return Err(server_managed_operational_attribute_diagnostic(attribute));
        }

        let mods: Vec<BackendMod> = modifications
            .iter()
            .map(|modification| match modification {
                WriteMod::Add { name, values } => BackendMod {
                    operation: ModifyOperation::Add,
                    attribute: name.clone(),
                    values: values.clone(),
                },
                WriteMod::Delete { name, values } => BackendMod {
                    operation: ModifyOperation::Delete,
                    attribute: name.clone(),
                    values: values.clone(),
                },
                WriteMod::Replace { name, values } => BackendMod {
                    operation: ModifyOperation::Replace,
                    attribute: name.clone(),
                    values: values.clone(),
                },
            })
            .collect();

        self.queue_operation(
            txn_id,
            PendingWriteOperation::Modify {
                dn: dn.to_string(),
                modifications: mods,
            },
        )
    }

    async fn modify_dn(
        &self,
        txn_id: &str,
        dn: &str,
        new_rdn: &str,
        delete_old: bool,
        new_superior: Option<&str>,
    ) -> Result<(), String> {
        self.ensure_open_transaction(txn_id)?;
        self.queue_operation(
            txn_id,
            PendingWriteOperation::ModifyDn {
                dn: dn.to_string(),
                new_rdn: new_rdn.to_string(),
                delete_old,
                new_superior: new_superior.map(String::from),
            },
        )
    }

    async fn delete_entry(&self, txn_id: &str, dn: &str) -> Result<(), String> {
        self.ensure_open_transaction(txn_id)?;
        self.queue_operation(txn_id, PendingWriteOperation::Delete { dn: dn.to_string() })
    }

    async fn entry_exists(&self, dn: &str) -> Result<bool, String> {
        let entry = self
            .backend
            .get_entry(dn)
            .await
            .map_err(|e| format!("Backend entry_exists error: {}", e))?;
        Ok(entry.is_some())
    }

    fn validates_modify_target_existence_on_write(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{DirectoryBackend, MockBackend};
    use crate::metrics::MetricsCollector;

    #[tokio::test]
    async fn write_backend_adapter_uses_actor_context_for_mutations() {
        let backend = Arc::new(MockBackend::new());
        let actor = "cn=admin,dc=example,dc=org".to_string();
        let adapter = WriteBackendAdapter::new(backend.clone()).with_actor(Some(actor.clone()));

        let txn_id = adapter.begin_transaction().await.unwrap();
        adapter
            .add_entry(
                &txn_id,
                "cn=alice,dc=example,dc=org",
                b"dn: cn=alice,dc=example,dc=org\nobjectClass: person\ncn: alice\nsn: User\n",
            )
            .await
            .unwrap();
        adapter.commit_transaction(&txn_id).await.unwrap();

        let stored = backend
            .get_entry("cn=alice,dc=example,dc=org")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.operational_attributes.creators_name,
            Some(actor.clone())
        );
        assert_eq!(stored.operational_attributes.modifiers_name, Some(actor));
    }

    #[tokio::test]
    async fn write_backend_adapter_requires_open_transaction_for_mutations() {
        let backend = Arc::new(MockBackend::new());
        let adapter = WriteBackendAdapter::new(backend.clone());

        let txn_id = adapter.begin_transaction().await.unwrap();
        adapter
            .rollback_transaction(&txn_id, "test rollback")
            .await
            .unwrap();

        let result = adapter
            .add_entry(
                &txn_id,
                "cn=alice,dc=example,dc=org",
                b"dn: cn=alice,dc=example,dc=org\nobjectClass: person\ncn: alice\nsn: User\n",
            )
            .await;

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("Unknown or closed transaction")
        );
    }

    #[tokio::test]
    async fn write_backend_adapter_uses_actor_for_modify_and_modify_dn() {
        let backend = Arc::new(MockBackend::new());
        let actor = "cn=admin,dc=example,dc=org".to_string();
        let adapter = WriteBackendAdapter::new(backend.clone()).with_actor(Some(actor.clone()));

        let txn_id = adapter.begin_transaction().await.unwrap();
        adapter
            .add_entry(
                &txn_id,
                "cn=alice,dc=example,dc=org",
                b"dn: cn=alice,dc=example,dc=org\nobjectClass: person\ncn: alice\nsn: User\n",
            )
            .await
            .unwrap();
        adapter.commit_transaction(&txn_id).await.unwrap();

        let txn_id = adapter.begin_transaction().await.unwrap();
        adapter
            .modify_entry(
                &txn_id,
                "cn=alice,dc=example,dc=org",
                &[WriteMod::Replace {
                    name: "cn".to_string(),
                    values: vec!["alice-updated".to_string()],
                }],
            )
            .await
            .unwrap();
        adapter.commit_transaction(&txn_id).await.unwrap();

        let stored = backend
            .get_entry("cn=alice,dc=example,dc=org")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.operational_attributes.modifiers_name,
            Some(actor.clone())
        );

        let txn_id = adapter.begin_transaction().await.unwrap();
        adapter
            .modify_dn(
                &txn_id,
                "cn=alice,dc=example,dc=org",
                "cn=alice-renamed",
                true,
                None,
            )
            .await
            .unwrap();
        adapter.commit_transaction(&txn_id).await.unwrap();

        let stored = backend
            .get_entry("cn=alice-renamed,dc=example,dc=org")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.operational_attributes.modifiers_name, Some(actor));
    }

    #[tokio::test]
    async fn write_backend_adapter_stages_mutations_until_commit() {
        let backend = Arc::new(MockBackend::new());
        let adapter = WriteBackendAdapter::new(backend.clone());
        let entry_dn = "cn=staged,dc=example,dc=org";
        let entry_data =
            b"dn: cn=staged,dc=example,dc=org\nobjectClass: person\ncn: staged\nsn: User\n";

        let txn_id = adapter.begin_transaction().await.unwrap();
        adapter
            .add_entry(&txn_id, entry_dn, entry_data)
            .await
            .unwrap();

        assert!(!adapter.entry_exists(entry_dn).await.unwrap());

        adapter.commit_transaction(&txn_id).await.unwrap();
        assert!(adapter.entry_exists(entry_dn).await.unwrap());

        let txn_id = adapter.begin_transaction().await.unwrap();
        adapter.delete_entry(&txn_id, entry_dn).await.unwrap();

        assert!(adapter.entry_exists(entry_dn).await.unwrap());

        adapter.commit_transaction(&txn_id).await.unwrap();
        assert!(!adapter.entry_exists(entry_dn).await.unwrap());
    }

    #[tokio::test]
    async fn write_backend_adapter_rollback_discards_staged_mutations() {
        let backend = Arc::new(MockBackend::new());
        let adapter = WriteBackendAdapter::new(backend.clone());
        let entry_dn = "cn=rolledback,dc=example,dc=org";
        let entry_data =
            b"dn: cn=rolledback,dc=example,dc=org\nobjectClass: person\ncn: rolledback\nsn: User\n";

        let txn_id = adapter.begin_transaction().await.unwrap();
        adapter
            .add_entry(&txn_id, entry_dn, entry_data)
            .await
            .unwrap();
        adapter
            .rollback_transaction(&txn_id, "discard staged add")
            .await
            .unwrap();

        assert!(!adapter.entry_exists(entry_dn).await.unwrap());
    }

    #[test]
    fn production_write_metrics_records_delete_lifecycle() {
        let metrics = MetricsCollector::new();
        let adapter = ProductionWriteMetrics::new(metrics.clone());
        let operation = WriteOperation::Delete {
            dn: "cn=target,dc=example,dc=org".to_string(),
        };

        adapter.record_write_start(Some("cn=admin,dc=example,dc=org"), &operation);
        adapter.record_validation_complete("delete", Duration::from_millis(1));
        adapter.record_transaction_started("txn-delete");
        adapter.record_write_complete(
            &operation,
            &WriteResultCode::Success,
            Duration::from_millis(3),
        );

        assert_eq!(metrics.get_counter("fsm_write_start_total"), Some(1));
        assert_eq!(metrics.get_counter("fsm_write_start_delete_total"), Some(1));
        assert_eq!(
            metrics.get_counter("fsm_write_authenticated_start_total"),
            Some(1)
        );
        assert_eq!(
            metrics.get_counter("fsm_write_transaction_started_total"),
            Some(1)
        );
        assert_eq!(metrics.get_counter("fsm_write_complete_total"), Some(1));
        assert_eq!(
            metrics.get_counter("fsm_write_complete_delete_total"),
            Some(1)
        );
        assert_eq!(
            metrics.get_counter("fsm_write_result_success_total"),
            Some(1)
        );
    }
}

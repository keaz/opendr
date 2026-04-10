use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::backend::{
    DirectoryBackend, DirectoryEntry, Modification as BackendMod, ModifyOperation,
};
use crate::write_fsm::{Modification as WriteMod, WriteBackend};

#[derive(Debug, Clone)]
struct WriteTransactionRecord {
    actor_dn: Option<String>,
    _started_at: Instant,
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

    fn transaction_actor(&self, txn_id: &str) -> Result<Option<String>, String> {
        let transactions = self.transactions.lock().unwrap();
        transactions
            .get(txn_id)
            .map(|record| record.actor_dn.clone())
            .ok_or_else(|| format!("Unknown or closed transaction: {}", txn_id))
    }

    fn parse_ldif_entry(&self, dn: &str, entry: &[u8]) -> Result<DirectoryEntry, String> {
        let entry_str = String::from_utf8(entry.to_vec())
            .map_err(|err| format!("Invalid UTF-8 entry payload: {}", err))?;

        let mut attributes = HashMap::new();
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
            let value = value.trim().to_string();
            attributes.entry(key).or_insert_with(Vec::new).push(value);
        }

        Ok(DirectoryEntry::new(dn, attributes))
    }
}

#[async_trait]
impl WriteBackend for WriteBackendAdapter {
    async fn begin_transaction(&self) -> Result<String, String> {
        let txn_id = uuid::Uuid::new_v4().to_string();
        let record = WriteTransactionRecord {
            actor_dn: self.actor_dn.clone(),
            _started_at: Instant::now(),
        };

        self.transactions
            .lock()
            .unwrap()
            .insert(txn_id.clone(), record);
        Ok(txn_id)
    }

    async fn commit_transaction(&self, txn_id: &str) -> Result<(), String> {
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
        let parsed = self.parse_ldif_entry(dn, entry)?;
        if parsed.dn.trim().is_empty() {
            return Err("Entry DN cannot be empty".to_string());
        }
        Ok(())
    }

    async fn add_entry(&self, txn_id: &str, dn: &str, entry: &[u8]) -> Result<(), String> {
        self.ensure_open_transaction(txn_id)?;
        let actor_dn = self.transaction_actor(txn_id)?;
        let dir_entry = self.parse_ldif_entry(dn, entry)?;

        self.backend
            .add_entry_with_actor(dir_entry, Vec::new(), actor_dn)
            .await
            .map_err(|e| format!("Backend add_entry error: {}", e))
    }

    async fn modify_entry(
        &self,
        txn_id: &str,
        dn: &str,
        modifications: &[WriteMod],
    ) -> Result<(), String> {
        self.ensure_open_transaction(txn_id)?;
        let actor_dn = self.transaction_actor(txn_id)?;

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

        self.backend
            .modify_entry_with_actor(dn, mods, actor_dn)
            .await
            .map_err(|e| format!("Backend modify_entry error: {}", e))
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
        let actor_dn = self.transaction_actor(txn_id)?;

        self.backend
            .rename_entry_with_actor(
                dn,
                new_rdn,
                delete_old,
                new_superior.map(String::from),
                actor_dn,
            )
            .await
            .map_err(|e| format!("Backend rename_entry error: {}", e))
    }

    async fn delete_entry(&self, txn_id: &str, dn: &str) -> Result<(), String> {
        self.ensure_open_transaction(txn_id)?;
        self.backend
            .delete_entry(dn)
            .await
            .map_err(|e| format!("Backend delete_entry error: {}", e))
    }

    async fn entry_exists(&self, dn: &str) -> Result<bool, String> {
        let entry = self
            .backend
            .get_entry(dn)
            .await
            .map_err(|e| format!("Backend entry_exists error: {}", e))?;
        Ok(entry.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{DirectoryBackend, MockBackend};

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
        assert!(result
            .unwrap_err()
            .contains("Unknown or closed transaction"));
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
}

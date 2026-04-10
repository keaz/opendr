use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;

use crate::backend::DirectoryBackend;
use crate::compare_fsm::{CompareBackend, CompareEntry};

/// Adapter that implements `CompareBackend` using a `DirectoryBackend`.
pub struct CompareBackendAdapter {
    backend: Arc<dyn DirectoryBackend>,
}

impl CompareBackendAdapter {
    pub fn new(backend: Arc<dyn DirectoryBackend>) -> Self {
        Self { backend }
    }
}

#[async_trait]
impl CompareBackend for CompareBackendAdapter {
    async fn get_entry_attributes(
        &self,
        dn: &str,
        _attributes: &[String],
    ) -> Result<Option<CompareEntry>, String> {
        let entry = self
            .backend
            .get_entry(dn)
            .await
            .map_err(|e| format!("Backend get_entry error: {}", e))?;

        Ok(entry.map(|entry| {
            let binary_attrs: HashMap<String, Vec<Vec<u8>>> = entry
                .attributes
                .iter()
                .map(|(key, values)| {
                    (
                        key.clone(),
                        values
                            .iter()
                            .map(|value| value.as_bytes().to_vec())
                            .collect(),
                    )
                })
                .collect();

            CompareEntry {
                dn: entry.dn.clone(),
                attributes: binary_attrs,
                object_classes: entry
                    .attributes
                    .get("objectclass")
                    .cloned()
                    .unwrap_or_default(),
            }
        }))
    }

    async fn entry_exists(&self, dn: &str) -> Result<bool, String> {
        let entry = self
            .backend
            .get_entry(dn)
            .await
            .map_err(|e| format!("Backend entry_exists error: {}", e))?;
        Ok(entry.is_some())
    }

    async fn get_compare_stats(&self, _dn: &str) -> Result<(u64, u64), String> {
        Ok((0, 0))
    }
}

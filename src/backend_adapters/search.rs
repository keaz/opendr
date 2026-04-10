use async_trait::async_trait;
use ldap_parser::ldap::SearchScope;
use std::sync::Arc;

use crate::backend::DirectoryBackend;
use crate::operational_attrs::{
    filter_operational_attributes, filter_user_attributes, merge_attributes,
};
use crate::search_fsm::{SearchBackend, SearchEntry};

/// Adapter that implements `SearchBackend` using a `DirectoryBackend`.
pub struct SearchBackendAdapter {
    backend: Arc<dyn DirectoryBackend>,
}

impl SearchBackendAdapter {
    pub fn new(backend: Arc<dyn DirectoryBackend>) -> Self {
        Self { backend }
    }
}

#[async_trait]
impl SearchBackend for SearchBackendAdapter {
    async fn find_candidates(
        &self,
        base_dn: &str,
        scope: i32,
        _filter: &str,
    ) -> Result<Vec<String>, String> {
        let search_scope = SearchScope(scope as u32);

        let entries = self
            .backend
            .search_entries(base_dn, search_scope)
            .await
            .map_err(|e| format!("Backend search error: {}", e))?;

        Ok(entries.into_iter().map(|entry| entry.dn).collect())
    }

    async fn get_entry(
        &self,
        dn: &str,
        attributes: &[String],
    ) -> Result<Option<SearchEntry>, String> {
        let entry = self
            .backend
            .get_entry(dn)
            .await
            .map_err(|e| format!("Backend get_entry error: {}", e))?;

        Ok(entry.map(|entry| {
            let user_attrs = filter_user_attributes(&entry.attributes, attributes);
            let operational =
                filter_operational_attributes(&entry.operational_attributes, attributes);
            let combined_attrs = merge_attributes(user_attrs, operational);

            SearchEntry {
                dn: entry.dn.clone(),
                attributes: combined_attrs,
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

    async fn get_search_stats(&self, _base_dn: &str) -> Result<(usize, usize), String> {
        Ok((0, 0))
    }
}

use async_trait::async_trait;
use ldap_parser::ldap::SearchScope;
use std::sync::Arc;
use std::time::Duration;

use crate::backend::{DirectoryBackend, DirectoryEntry, OperationalAttributes};
use crate::fsm::SearchResultCode;
use crate::metrics::{FsmType, MetricsCollector, OperationType};
use crate::operational_attrs::parse_attribute_request;
use crate::parser::encode_search_entry_parts_with_controls;
use crate::search_fsm::{
    EntryFormatter, FilterMatcher, SearchBackend, SearchEntry, SearchFsmImpl, SearchMetrics,
};

/// Production search backend adapter backed by a `DirectoryBackend`.
pub struct ProductionSearchBackendAdapter {
    backend: Arc<dyn DirectoryBackend>,
}

impl ProductionSearchBackendAdapter {
    pub fn new(backend: Arc<dyn DirectoryBackend>) -> Self {
        Self { backend }
    }
}

#[async_trait]
impl SearchBackend for ProductionSearchBackendAdapter {
    async fn find_candidates(
        &self,
        base_dn: &str,
        scope: i32,
        filter: &str,
    ) -> Result<Vec<String>, String> {
        let search_scope = SearchScope(scope as u32);
        let hint = crate::ldap_filter_eval::extract_search_candidate_hint_from_str(filter);
        let entries = self
            .backend
            .search_entries_with_hint(base_dn, search_scope, hint)
            .await
            .map_err(|e| format!("backend search_entries_with_hint failed: {e}"))?;

        Ok(entries.into_iter().map(|entry| entry.dn).collect())
    }

    async fn get_entry(
        &self,
        dn: &str,
        _requested_attributes: &[String],
    ) -> Result<Option<SearchEntry>, String> {
        let entry = self
            .backend
            .get_entry(dn)
            .await
            .map_err(|e| format!("backend get_entry failed: {e}"))?;

        Ok(entry.map(|entry| directory_entry_to_search_entry(&entry)))
    }

    async fn entry_exists(&self, dn: &str) -> Result<bool, String> {
        self.backend
            .get_entry(dn)
            .await
            .map(|entry| entry.is_some())
            .map_err(|e| format!("backend entry_exists failed: {e}"))
    }

    async fn get_search_stats(&self, base_dn: &str) -> Result<(usize, usize), String> {
        let count = self
            .backend
            .count_entries(base_dn, SearchScope(2))
            .await
            .map_err(|e| format!("backend count_entries failed: {e}"))?;

        Ok((count, 1))
    }
}

/// Production filter matcher backed by the LDAP filter evaluator.
#[derive(Debug, Default)]
pub struct ProductionFilterMatcher;

impl ProductionFilterMatcher {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl FilterMatcher for ProductionFilterMatcher {
    async fn matches_filter(&self, entry: &SearchEntry, filter: &str) -> Result<bool, String> {
        crate::ldap_filter_eval::matches_search_entry_filter_string(entry, filter)
    }

    async fn validate_filter(&self, filter: &str) -> Result<(), String> {
        crate::ldap_filter_eval::compile_filter(filter).map(|_| ())
    }

    fn extract_indexed_attributes(&self, _filter: &str) -> Vec<String> {
        Vec::new()
    }
}

/// Production entry formatter backed by the LDAP encoder.
#[derive(Debug, Default)]
pub struct ProductionEntryFormatter {
    message_id: u32,
    types_only: bool,
}

impl ProductionEntryFormatter {
    pub fn new() -> Self {
        Self {
            message_id: 0,
            types_only: false,
        }
    }

    pub fn with_message_id(message_id: u32) -> Self {
        Self {
            message_id,
            types_only: false,
        }
    }

    pub fn with_request(message_id: u32, types_only: bool) -> Self {
        Self {
            message_id,
            types_only,
        }
    }
}

#[async_trait]
impl EntryFormatter for ProductionEntryFormatter {
    async fn format_entry(
        &self,
        entry: &SearchEntry,
        requested_attributes: &[String],
    ) -> Result<Vec<u8>, String> {
        let selected_attributes = project_search_entry_attributes(entry, requested_attributes);

        encode_search_entry_parts_with_controls(
            self.message_id,
            &entry.dn,
            &selected_attributes,
            self.types_only,
            &[],
        )
        .map_err(|e| format!("failed to encode search entry: {e:?}"))
    }
}

/// Production search metrics adapter backed by [`MetricsCollector`].
pub struct ProductionSearchMetrics {
    metrics: Arc<MetricsCollector>,
}

impl ProductionSearchMetrics {
    pub fn new(metrics: Arc<MetricsCollector>) -> Self {
        Self { metrics }
    }
}

impl SearchMetrics for ProductionSearchMetrics {
    fn record_search_start(&self, _params: &crate::fsm::SearchParams) {
        self.metrics
            .record_operation_start(OperationType::Search, "");
        self.metrics.record_fsm_state(FsmType::Search, "searching");
    }

    fn record_candidates_found(&self, count: usize) {
        self.metrics
            .increment_counter("ldap_search_candidates_found", count as u64);
    }

    fn record_entry_processed(&self, _dn: &str, matched: bool) {
        self.metrics
            .increment_counter("ldap_search_entries_seen", 1);
        if matched {
            self.metrics
                .increment_counter("ldap_search_entries_matched", 1);
        }
    }

    fn record_search_complete(
        &self,
        result_code: &SearchResultCode,
        entries_sent: usize,
        duration: Duration,
    ) {
        let success = matches!(result_code, SearchResultCode::Success);
        self.metrics
            .record_operation_complete(OperationType::Search, duration, success);
        self.metrics
            .set_gauge("ldap_search_entries_sent", entries_sent as u64);
        self.metrics.record_fsm_state(
            FsmType::Search,
            if success {
                "completed"
            } else {
                "completed_with_error"
            },
        );
    }

    fn record_search_abandoned(&self) {
        self.metrics.increment_counter("ldap_search_abandoned", 1);
        self.metrics.record_fsm_state(FsmType::Search, "abandoned");
    }
}

/// Build a production-ready `SearchFsmImpl` with real adapters.
pub fn build_production_search_fsm(
    backend: Arc<dyn DirectoryBackend>,
    metrics: Option<Arc<MetricsCollector>>,
) -> SearchFsmImpl {
    build_production_search_fsm_with_message_id(backend, metrics, 0)
}

/// Build a production-ready `SearchFsmImpl` for a specific LDAP request message id.
pub fn build_production_search_fsm_with_message_id(
    backend: Arc<dyn DirectoryBackend>,
    metrics: Option<Arc<MetricsCollector>>,
    message_id: u32,
) -> SearchFsmImpl {
    build_production_search_fsm_with_request(backend, metrics, message_id, false)
}

/// Build a production-ready `SearchFsmImpl` for a specific LDAP request.
pub fn build_production_search_fsm_with_request(
    backend: Arc<dyn DirectoryBackend>,
    metrics: Option<Arc<MetricsCollector>>,
    message_id: u32,
    types_only: bool,
) -> SearchFsmImpl {
    let backend = Box::new(ProductionSearchBackendAdapter::new(backend));
    let filter_matcher = Box::new(ProductionFilterMatcher::new());
    let entry_formatter = Box::new(ProductionEntryFormatter::with_request(
        message_id, types_only,
    ));

    let mut fsm = SearchFsmImpl::new(backend, filter_matcher, entry_formatter);
    if let Some(metrics) = metrics {
        fsm = fsm.with_metrics(Box::new(ProductionSearchMetrics::new(metrics)));
    }

    fsm
}

fn directory_entry_to_search_entry(entry: &DirectoryEntry) -> SearchEntry {
    let mut combined_attrs = entry.attributes.clone();
    combined_attrs.extend(entry.operational_attributes.to_attributes());

    SearchEntry {
        dn: entry.dn.clone(),
        attributes: combined_attrs,
        object_classes: entry
            .attributes
            .get("objectclass")
            .cloned()
            .unwrap_or_default(),
    }
}

fn project_search_entry_attributes(
    entry: &SearchEntry,
    requested_attributes: &[String],
) -> Vec<(String, Vec<String>)> {
    let (include_user, include_all_operational, specific_operational) =
        parse_attribute_request(requested_attributes);
    let requested_lower: Vec<String> = requested_attributes
        .iter()
        .map(|attribute| attribute.to_lowercase())
        .collect();

    entry
        .attributes
        .iter()
        .filter(|(name, _)| {
            let key = name.to_lowercase();
            let is_operational = OperationalAttributes::is_operational(&key);

            if is_operational {
                include_all_operational || specific_operational.contains(&key)
            } else if requested_attributes.is_empty()
                || requested_lower.iter().any(|attr| attr == "*")
            {
                include_user
            } else {
                include_user && requested_lower.contains(&key)
            }
        })
        .map(|(name, values)| (name.clone(), values.clone()))
        .collect()
}

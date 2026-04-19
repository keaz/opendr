use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::backend::DirectoryBackend;
use crate::compare_fsm::{
    AttributeComparator, CompareAccessControl, CompareBackend, CompareEntry, CompareMetrics,
};
use crate::fsm::CompareParams;
use crate::ldap_filter_eval::compare_attribute_with_schema;
use crate::metrics::{FsmType, MetricsCollector};
use crate::schema::LdapSchema;

/// Adapter that implements `CompareBackend` using a `DirectoryBackend`.
pub struct CompareBackendAdapter {
    backend: Arc<dyn DirectoryBackend>,
    schema: Option<LdapSchema>,
}

impl CompareBackendAdapter {
    pub fn new(backend: Arc<dyn DirectoryBackend>) -> Self {
        Self {
            backend,
            schema: None,
        }
    }

    pub fn with_schema(backend: Arc<dyn DirectoryBackend>, schema: LdapSchema) -> Self {
        Self {
            backend,
            schema: Some(schema),
        }
    }
}

/// Production comparator that mirrors the backend's current compare semantics:
/// attribute names are case-insensitive, while values are matched exactly.
#[derive(Debug, Default)]
pub struct ProductionAttributeComparator {
    schema: Option<LdapSchema>,
}

impl ProductionAttributeComparator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_schema(schema: LdapSchema) -> Self {
        Self {
            schema: Some(schema),
        }
    }
}

#[async_trait]
impl AttributeComparator for ProductionAttributeComparator {
    async fn compare_attribute(
        &self,
        entry: &CompareEntry,
        attr_name: &str,
        value: &[u8],
    ) -> Result<bool, String> {
        if let Some(schema) = self.schema.as_ref() {
            let attributes = entry
                .attributes
                .iter()
                .map(|(attribute, values)| {
                    (
                        attribute.clone(),
                        values
                            .iter()
                            .map(|value| String::from_utf8_lossy(value).to_string())
                            .collect::<Vec<_>>(),
                    )
                })
                .collect::<HashMap<_, _>>();
            let assertion = String::from_utf8_lossy(value).to_string();
            return compare_attribute_with_schema(
                schema,
                &entry.dn,
                &attributes,
                attr_name,
                &assertion,
            )
            .map_err(|err| err.to_string());
        }

        Ok(entry
            .get_attribute(attr_name)
            .map(|values| values.iter().any(|candidate| candidate.as_slice() == value))
            .unwrap_or(false))
    }
}

/// Access control is enforced in the production server request pipeline before
/// the native compare FSM runs, so the FSM can stay focused on compare logic.
#[derive(Debug, Default)]
pub struct AllowAllCompareAccessControl;

#[async_trait]
impl CompareAccessControl for AllowAllCompareAccessControl {
    async fn check_compare_permission(
        &self,
        _user_dn: Option<&str>,
        _entry_dn: &str,
        _attribute: &str,
    ) -> Result<(), String> {
        Ok(())
    }
}

/// Compare FSM metrics adapter backed by the shared `MetricsCollector`.
pub struct ProductionCompareMetrics {
    metrics: Arc<MetricsCollector>,
}

impl ProductionCompareMetrics {
    pub fn new(metrics: Arc<MetricsCollector>) -> Self {
        Self { metrics }
    }
}

impl CompareMetrics for ProductionCompareMetrics {
    fn record_compare_start(&self, params: &CompareParams, user_dn: Option<&str>) {
        self.metrics.record_fsm_state(FsmType::Compare, "start");
        self.metrics.increment_counter("fsm_compare_start_total", 1);
        if user_dn.is_some() {
            self.metrics
                .increment_counter("fsm_compare_authenticated_start_total", 1);
        }
        self.metrics.set_gauge(
            "fsm_compare_last_value_size_bytes",
            params.value.len() as u64,
        );
    }

    fn record_entry_read(&self, _dn: &str, found: bool, duration: Duration) {
        self.metrics
            .record_fsm_state(FsmType::Compare, "entry_read");
        self.metrics
            .increment_counter("fsm_compare_entry_read_total", 1);
        if !found {
            self.metrics
                .increment_counter("fsm_compare_entry_missing_total", 1);
        }
        self.metrics.set_gauge(
            "fsm_compare_last_entry_read_duration_ms",
            duration.as_millis() as u64,
        );
    }

    fn record_comparison_complete(&self, _attribute: &str, result: bool, duration: Duration) {
        self.metrics
            .record_fsm_state(FsmType::Compare, "comparison_complete");
        self.metrics
            .increment_counter("fsm_compare_comparison_complete_total", 1);
        self.metrics.increment_counter(
            if result {
                "fsm_compare_true_total"
            } else {
                "fsm_compare_false_total"
            },
            1,
        );
        self.metrics.set_gauge(
            "fsm_compare_last_comparison_duration_ms",
            duration.as_millis() as u64,
        );
    }

    fn record_compare_complete(&self, result: bool, duration: Duration) {
        self.metrics.record_fsm_state(FsmType::Compare, "completed");
        self.metrics
            .increment_counter("fsm_compare_complete_total", 1);
        if result {
            self.metrics
                .increment_counter("fsm_compare_complete_true_total", 1);
        }
        self.metrics.set_gauge(
            "fsm_compare_last_total_duration_ms",
            duration.as_millis() as u64,
        );
    }

    fn record_compare_error(&self, error_type: &str, duration: Duration) {
        self.metrics.record_fsm_state(FsmType::Compare, "error");
        self.metrics.increment_counter("fsm_compare_error_total", 1);
        self.metrics
            .increment_counter(&format!("fsm_compare_error_{}_total", error_type), 1);
        self.metrics.set_gauge(
            "fsm_compare_last_error_duration_ms",
            duration.as_millis() as u64,
        );
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

        let entry = match (entry, self.schema.as_ref()) {
            (Some(entry), Some(schema)) => Some(
                crate::collective_attrs::project_collective_attributes_for_entry(
                    self.backend.as_ref(),
                    schema,
                    entry,
                )
                .await
                .map_err(|e| format!("Backend collective projection error: {}", e))?,
            ),
            (entry, _) => entry,
        };

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::MetricsCollector;

    #[tokio::test]
    async fn production_attribute_comparator_matches_exact_values() {
        let mut entry = CompareEntry::new("cn=test,dc=example,dc=org".to_string());
        entry.add_attribute("cn".to_string(), vec![b"alice".to_vec(), b"bob".to_vec()]);

        let comparator = ProductionAttributeComparator::new();
        assert!(
            comparator
                .compare_attribute(&entry, "cn", b"alice")
                .await
                .unwrap()
        );
        assert!(
            !comparator
                .compare_attribute(&entry, "cn", b"ALICE")
                .await
                .unwrap()
        );
        assert!(
            !comparator
                .compare_attribute(&entry, "mail", b"alice@example.org")
                .await
                .unwrap()
        );
    }

    #[test]
    fn production_compare_metrics_records_counters() {
        let metrics = MetricsCollector::new();
        let adapter = ProductionCompareMetrics::new(metrics.clone());
        let params = CompareParams {
            dn: "cn=test,dc=example,dc=org".to_string(),
            attribute: "cn".to_string(),
            value: b"alice".to_vec(),
        };

        adapter.record_compare_start(&params, Some("cn=admin,dc=example,dc=org"));
        adapter.record_entry_read(&params.dn, true, Duration::from_millis(2));
        adapter.record_comparison_complete(&params.attribute, true, Duration::from_millis(1));
        adapter.record_compare_complete(true, Duration::from_millis(3));

        assert_eq!(metrics.get_counter("fsm_compare_start_total"), Some(1));
        assert_eq!(
            metrics.get_counter("fsm_compare_authenticated_start_total"),
            Some(1)
        );
        assert_eq!(
            metrics.get_counter("fsm_compare_comparison_complete_total"),
            Some(1)
        );
        assert_eq!(metrics.get_counter("fsm_compare_true_total"), Some(1));
        assert_eq!(metrics.get_counter("fsm_compare_complete_total"), Some(1));
        assert_eq!(
            metrics.get_counter("fsm_compare_complete_true_total"),
            Some(1)
        );
        assert_eq!(
            metrics.get_gauge("fsm_compare_last_total_duration_ms"),
            Some(3)
        );
    }
}

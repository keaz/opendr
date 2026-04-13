use ldap_parser::ldap::ProtocolOp;
use ldap_parser::parse_ldap_messages;
use opendr::backend::{DirectoryBackend, DirectoryEntry, MockBackend, OperationalAttributes};
use opendr::fsm::{SearchEvent, StateMachine};
use opendr::metrics::{MetricsCollector, OperationType};
use opendr::search_adapters::{
    ProductionEntryFormatter, ProductionFilterMatcher, ProductionSearchBackendAdapter,
    ProductionSearchMetrics, build_production_search_fsm,
    build_production_search_fsm_with_message_id,
};
use opendr::search_fsm::{
    EntryFormatter, FilterMatcher, SearchBackend, SearchEntry, SearchMetrics,
};
use std::collections::HashMap;
use std::sync::Arc;

fn test_directory_entry(dn: &str) -> DirectoryEntry {
    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["Alice".to_string()]);
    attributes.insert("mail".to_string(), vec!["alice@example.org".to_string()]);
    attributes.insert("objectclass".to_string(), vec!["person".to_string()]);

    let operational = OperationalAttributes::for_new_entry(
        opendr::csn::Csn::new(1),
        Some("cn=admin,dc=example,dc=org".to_string()),
    );

    DirectoryEntry::with_operational_attrs(dn, attributes, operational)
}

fn test_search_entry() -> SearchEntry {
    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["Alice".to_string()]);
    attributes.insert("mail".to_string(), vec!["alice@example.org".to_string()]);
    attributes.insert("objectclass".to_string(), vec!["person".to_string()]);
    attributes.insert(
        "entrycsn".to_string(),
        vec!["000001#000000#001#000000".to_string()],
    );

    SearchEntry {
        dn: "cn=alice,dc=example,dc=org".to_string(),
        attributes,
        object_classes: vec!["person".to_string()],
    }
}

#[tokio::test]
async fn production_search_backend_returns_full_entry_and_stats() {
    let backend = Arc::new(MockBackend::new());
    let entry = test_directory_entry("cn=alice,dc=example,dc=org");
    backend.add_entry(entry.clone(), Vec::new()).await.unwrap();

    let adapter = ProductionSearchBackendAdapter::new(backend);
    let search_entry = adapter
        .get_entry("cn=alice,dc=example,dc=org", &["+".to_string()])
        .await
        .unwrap()
        .expect("entry should exist");

    assert_eq!(search_entry.dn, entry.dn);
    assert!(search_entry.attributes.contains_key("cn"));
    assert!(search_entry.attributes.contains_key("mail"));
    assert!(search_entry.attributes.contains_key("entrycsn"));

    let stats = adapter.get_search_stats("dc=example,dc=org").await.unwrap();
    assert!(stats.0 >= 1);
}

#[tokio::test]
async fn production_filter_matcher_uses_real_filter_evaluation() {
    let mut matcher = ProductionFilterMatcher::new();
    let entry = test_search_entry();

    matcher
        .validate_filter("(&(objectClass=person)(cn=Alice))")
        .await
        .unwrap();

    assert!(
        matcher
            .matches_filter(&entry, "(&(objectClass=person)(cn=Alice))")
            .await
            .unwrap()
    );
    assert!(
        !matcher
            .matches_filter(&entry, "(&(objectClass=person)(cn=Bob))")
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn production_entry_formatter_projects_and_encodes_entries() {
    let mut formatter = ProductionEntryFormatter::with_message_id(41);
    let entry = test_search_entry();

    let encoded = formatter
        .format_entry(&entry, &["cn".to_string(), "+".to_string()])
        .await
        .unwrap();

    let (_, messages) = parse_ldap_messages(&encoded).unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].message_id.0, 41);

    match &messages[0].protocol_op {
        ProtocolOp::SearchResultEntry(response) => {
            assert_eq!(
                response.object_name.0.as_ref(),
                "cn=alice,dc=example,dc=org"
            );
            assert!(
                response
                    .attributes
                    .iter()
                    .any(|attr| attr.attr_type.0.as_ref() == "cn")
            );
            assert!(
                response
                    .attributes
                    .iter()
                    .any(|attr| attr.attr_type.0.as_ref() == "entrycsn")
            );
            assert!(
                !response
                    .attributes
                    .iter()
                    .any(|attr| attr.attr_type.0.as_ref() == "mail")
            );
        }
        other => panic!("unexpected protocol op: {:?}", other),
    }
}

#[tokio::test]
async fn production_search_metrics_update_metrics_collector() {
    let metrics = MetricsCollector::new();
    let adapter = ProductionSearchMetrics::new(metrics.clone());
    let params = opendr::fsm::SearchParams {
        base_dn: "dc=example,dc=org".to_string(),
        scope: 2,
        filter: "(cn=Alice)".to_string(),
        attributes: vec!["cn".to_string()],
        size_limit: 10,
        time_limit: 30,
    };

    adapter.record_search_start(&params);
    adapter.record_candidates_found(2);
    adapter.record_entry_processed("cn=alice,dc=example,dc=org", true);
    adapter.record_search_complete(
        &opendr::fsm::SearchResultCode::Success,
        1,
        std::time::Duration::from_millis(3),
    );
    adapter.record_search_abandoned();

    let stats = metrics.get_operation_stats(OperationType::Search).unwrap();
    assert_eq!(stats.count, 1);
    assert_eq!(stats.success, 1);
    assert_eq!(metrics.get_counter("ldap_search_candidates_found"), Some(2));
    assert_eq!(metrics.get_counter("ldap_search_entries_seen"), Some(1));
    assert_eq!(metrics.get_counter("ldap_search_entries_matched"), Some(1));
    assert_eq!(metrics.get_counter("ldap_search_abandoned"), Some(1));
}

#[tokio::test]
async fn production_search_fsm_executes_real_searches() {
    let backend = Arc::new(MockBackend::new());
    let entry = test_directory_entry("cn=alice,dc=example,dc=org");
    backend.add_entry(entry, Vec::new()).await.unwrap();

    let metrics = MetricsCollector::new();
    let mut fsm = build_production_search_fsm(backend, Some(metrics.clone()));

    let result = fsm
        .handle_event(SearchEvent::StartSearch {
            base_dn: "dc=example,dc=org".to_string(),
            scope: 2,
            filter: "(cn=Alice)".to_string(),
            attributes: vec!["cn".to_string(), "+".to_string()],
            size_limit: 10,
            time_limit: 30,
        })
        .await
        .unwrap()
        .expect("expected first search entry");

    let (_, messages) = parse_ldap_messages(&result).unwrap();
    assert_eq!(messages.len(), 1);
    match &messages[0].protocol_op {
        ProtocolOp::SearchResultEntry(response) => {
            assert_eq!(
                response.object_name.0.as_ref(),
                "cn=alice,dc=example,dc=org"
            );
        }
        other => panic!("unexpected protocol op: {:?}", other),
    }

    let next = fsm.handle_event(SearchEvent::EntryEmitted).await.unwrap();
    assert!(next.is_none());
    assert!(fsm.is_terminal());

    let stats = metrics.get_operation_stats(OperationType::Search).unwrap();
    assert_eq!(stats.count, 1);
    assert_eq!(stats.success, 1);
}

#[tokio::test]
async fn production_search_fsm_builder_uses_request_message_id() {
    let backend = Arc::new(MockBackend::new());
    let entry = test_directory_entry("cn=alice,dc=example,dc=org");
    backend.add_entry(entry, Vec::new()).await.unwrap();

    let mut fsm = build_production_search_fsm_with_message_id(backend, None, 73);
    let result = fsm
        .handle_event(SearchEvent::StartSearch {
            base_dn: "dc=example,dc=org".to_string(),
            scope: 2,
            filter: "(cn=Alice)".to_string(),
            attributes: vec!["cn".to_string()],
            size_limit: 10,
            time_limit: 30,
        })
        .await
        .unwrap()
        .expect("expected first search entry");

    let (_, messages) = parse_ldap_messages(&result).unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].message_id.0, 73);
}

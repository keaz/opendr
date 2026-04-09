use std::collections::HashMap;

use opendr::backend::{
    DirectoryBackend, DirectoryEntry, MockBackend, Modification, ModifyOperation,
};
use opendr::backend_lmdb::LmdbBackend;

fn person_entry(dn: &str, cn: &str) -> DirectoryEntry {
    DirectoryEntry::new(
        dn,
        HashMap::from([
            ("cn".to_string(), vec![cn.to_string()]),
            ("sn".to_string(), vec!["User".to_string()]),
            ("objectclass".to_string(), vec!["person".to_string()]),
        ]),
    )
}

#[tokio::test]
async fn authenticated_add_sets_actor_operational_attrs_on_mock_backend() {
    let backend = MockBackend::new();
    let actor = "cn=admin,dc=example,dc=org".to_string();

    backend
        .add_entry_with_actor(
            person_entry("cn=alice,dc=example,dc=org", "alice"),
            Vec::new(),
            Some(actor.clone()),
        )
        .await
        .unwrap();

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
async fn authenticated_add_sets_actor_operational_attrs_on_lmdb_backend() {
    let temp_dir = tempfile::tempdir().unwrap();
    let backend = LmdbBackend::new(temp_dir.path(), 100, 1).unwrap();
    let actor = "cn=admin,dc=example,dc=org".to_string();

    backend
        .add_entry_with_actor(
            person_entry("cn=alice,dc=example,dc=org", "alice"),
            Vec::new(),
            Some(actor.clone()),
        )
        .await
        .unwrap();

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
async fn authenticated_modify_preserves_creator_and_updates_modifier_on_lmdb_backend() {
    let temp_dir = tempfile::tempdir().unwrap();
    let backend = LmdbBackend::new(temp_dir.path(), 100, 1).unwrap();
    let creator = "cn=creator,dc=example,dc=org".to_string();
    let modifier = "cn=modifier,dc=example,dc=org".to_string();

    backend
        .add_entry_with_actor(
            person_entry("cn=alice,dc=example,dc=org", "alice"),
            Vec::new(),
            Some(creator.clone()),
        )
        .await
        .unwrap();

    backend
        .modify_entry_with_actor(
            "cn=alice,dc=example,dc=org",
            vec![Modification {
                operation: ModifyOperation::Replace,
                attribute: "cn".to_string(),
                values: vec!["alice-updated".to_string()],
            }],
            Some(modifier.clone()),
        )
        .await
        .unwrap();

    let stored = backend
        .get_entry("cn=alice,dc=example,dc=org")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.operational_attributes.creators_name, Some(creator));
    assert_eq!(stored.operational_attributes.modifiers_name, Some(modifier));
}

#[tokio::test]
async fn actorless_modify_preserves_existing_modifier() {
    let backend = MockBackend::new();
    let actor = "cn=admin,dc=example,dc=org".to_string();

    backend
        .add_entry_with_actor(
            person_entry("cn=alice,dc=example,dc=org", "alice"),
            Vec::new(),
            Some(actor.clone()),
        )
        .await
        .unwrap();

    backend
        .modify_entry_with_actor(
            "cn=alice,dc=example,dc=org",
            vec![Modification {
                operation: ModifyOperation::Replace,
                attribute: "cn".to_string(),
                values: vec!["alice-updated".to_string()],
            }],
            None,
        )
        .await
        .unwrap();

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

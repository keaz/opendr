//! Performance benchmarks for backend implementations
//!
//! This benchmark suite compares the performance of different backend
//! implementations, with a focus on read operations.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use opendr::backend::{
    DirectoryBackend, DirectoryEntry, MockBackend, Modification, ModifyOperation,
    SearchCandidateHint, SearchSubstringPart,
};
use opendr::backend_lmdb::{
    AttributeIndexConfig, IndexConfig, IndexType, LmdbAuthCacheBenchmarkHarness, LmdbBackend,
    LmdbEntryCacheBenchmarkHarness,
};
use opendr::schema::LdapSchema;
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::{TempDir, tempdir};

fn setup_mock_backend() -> Arc<MockBackend> {
    let backend = Arc::new(MockBackend::default());

    // Add test entries
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        for i in 0..1000 {
            let mut attributes = HashMap::new();
            attributes.insert("cn".to_string(), vec![format!("user{}", i)]);
            attributes.insert("uid".to_string(), vec![format!("user{}", i)]);
            attributes.insert("mail".to_string(), vec![format!("user{}@example.org", i)]);

            let entry = DirectoryEntry::new(
                format!("uid=user{},ou=people,dc=example,dc=org", i),
                attributes,
            );

            backend
                .add_entry(entry, format!("password{}", i).as_bytes().to_vec())
                .await
                .unwrap();
        }
    });

    backend
}

fn setup_lmdb_backend() -> Arc<LmdbBackend> {
    let dir = tempdir().unwrap();
    let backend = Arc::new(LmdbBackend::new(dir.path(), 100, 1).unwrap());

    // Add test entries
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        for i in 0..1000 {
            let mut attributes = HashMap::new();
            attributes.insert("cn".to_string(), vec![format!("user{}", i)]);
            attributes.insert("uid".to_string(), vec![format!("user{}", i)]);
            attributes.insert("mail".to_string(), vec![format!("user{}@example.org", i)]);

            let entry = DirectoryEntry::new(
                format!("uid=user{},ou=people,dc=example,dc=org", i),
                attributes,
            );

            backend
                .add_entry(entry, format!("password{}", i).as_bytes().to_vec())
                .await
                .unwrap();
        }
    });

    backend
}

fn setup_lmdb_indexed_backend() -> (TempDir, Arc<LmdbBackend>) {
    let dir = tempdir().unwrap();
    let mut schema = LdapSchema::with_core_schema();
    schema
        .load_ldif_str(
            "
dn: cn=schema
attributeTypes: ( 1.3.6.1.4.1.55555.250.1 NAME 'benchmarkOrder' DESC 'Benchmark integer ordering key' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
objectClasses: ( 1.3.6.1.4.1.55555.250.2 NAME 'benchmarkIndexedObject' DESC 'Benchmark auxiliary object class for index probes' SUP top AUXILIARY MAY benchmarkOrder )
",
        )
        .unwrap();
    let backend = Arc::new(
        LmdbBackend::new_with_schema_config(
            dir.path(),
            100,
            1,
            IndexConfig {
                indexed_attributes: vec!["uid".to_string(), "mail".to_string()],
                attribute_indexes: vec![
                    AttributeIndexConfig {
                        attribute: "description".to_string(),
                        index_types: vec![IndexType::Substring],
                    },
                    AttributeIndexConfig {
                        attribute: "benchmarkOrder".to_string(),
                        index_types: vec![IndexType::Ordering],
                    },
                ],
            },
            &schema,
        )
        .unwrap(),
    );

    tokio::runtime::Runtime::new().unwrap().block_on(async {
        for i in 0..1000 {
            let mut attributes = HashMap::new();
            attributes.insert(
                "objectclass".to_string(),
                vec![
                    "top".to_string(),
                    "person".to_string(),
                    "benchmarkIndexedObject".to_string(),
                ],
            );
            attributes.insert("cn".to_string(), vec![format!("Fixture User {i:06}")]);
            attributes.insert("sn".to_string(), vec![format!("User {i:06}")]);
            attributes.insert("uid".to_string(), vec![format!("perfbench-user-{i:06}")]);
            attributes.insert(
                "mail".to_string(),
                vec![format!("perfbench-user-{i:06}@example.org")],
            );
            attributes.insert(
                "description".to_string(),
                vec![format!("fixture user {i:06} indexed search benchmark")],
            );
            attributes.insert("benchmarkOrder".to_string(), vec![i.to_string()]);

            let entry = DirectoryEntry::new(
                format!("uid=perfbench-user-{i:06},ou=people,dc=example,dc=org"),
                attributes,
            );
            backend
                .add_entry(entry, format!("password{i}").as_bytes().to_vec())
                .await
                .unwrap();
        }
    });

    (dir, backend)
}

fn setup_lmdb_modify_backend() -> (TempDir, Arc<LmdbBackend>, Arc<LdapSchema>) {
    let dir = tempdir().unwrap();
    let schema = Arc::new(LdapSchema::with_core_schema());
    let backend = Arc::new(LmdbBackend::new(dir.path(), 100, 1).unwrap());

    tokio::runtime::Runtime::new().unwrap().block_on(async {
        for i in 0..100 {
            let mut attributes = HashMap::new();
            attributes.insert(
                "objectClass".to_string(),
                vec!["top".to_string(), "person".to_string()],
            );
            attributes.insert("cn".to_string(), vec![format!("modify user {i}")]);
            attributes.insert("sn".to_string(), vec![format!("user {i}")]);
            attributes.insert("telephoneNumber".to_string(), vec!["555-0100".to_string()]);

            let entry = DirectoryEntry::new(
                format!("cn=modify-user-{i},ou=people,dc=example,dc=org"),
                attributes,
            );
            backend
                .add_entry(entry, format!("password{i}").as_bytes().to_vec())
                .await
                .unwrap();
        }
    });

    (dir, backend, schema)
}

fn bench_read_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("backend_reads");
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Benchmark MockBackend reads
    let mock_backend = setup_mock_backend();
    group.bench_function("mock_backend_get_entry", |b| {
        b.iter(|| {
            let backend = mock_backend.clone();
            rt.block_on(async move {
                let _ = backend
                    .get_entry(black_box("uid=user500,ou=people,dc=example,dc=org"))
                    .await;
            })
        });
    });

    // Benchmark LmdbBackend reads
    let lmdb_backend = setup_lmdb_backend();
    group.bench_function("lmdb_backend_get_entry", |b| {
        b.iter(|| {
            let backend = lmdb_backend.clone();
            rt.block_on(async move {
                let _ = backend
                    .get_entry(black_box("uid=user500,ou=people,dc=example,dc=org"))
                    .await;
            })
        });
    });

    let lmdb_cached_backend = setup_lmdb_backend();
    rt.block_on(async {
        lmdb_cached_backend
            .get_entry("uid=user500,ou=people,dc=example,dc=org")
            .await
            .unwrap();
    });
    group.bench_function("lmdb_backend_get_entry_cache_hit", |b| {
        b.iter(|| {
            let backend = lmdb_cached_backend.clone();
            rt.block_on(async move {
                let _ = backend
                    .get_entry(black_box("uid=user500,ou=people,dc=example,dc=org"))
                    .await;
            })
        });
    });

    group.finish();
}

fn bench_authentication(c: &mut Criterion) {
    let mut group = c.benchmark_group("backend_auth");
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Benchmark MockBackend authentication
    let mock_backend = setup_mock_backend();
    group.bench_function("mock_backend_authenticate", |b| {
        b.iter(|| {
            let backend = mock_backend.clone();
            rt.block_on(async move {
                let _ = backend
                    .authenticate(
                        black_box("uid=user500,ou=people,dc=example,dc=org"),
                        black_box(b"password500"),
                    )
                    .await;
            })
        });
    });

    // Benchmark LmdbBackend authentication
    let lmdb_backend = setup_lmdb_backend();
    group.bench_function("lmdb_backend_authenticate", |b| {
        b.iter(|| {
            let backend = lmdb_backend.clone();
            rt.block_on(async move {
                let _ = backend
                    .authenticate(
                        black_box("uid=user500,ou=people,dc=example,dc=org"),
                        black_box(b"password500"),
                    )
                    .await;
            })
        });
    });

    let lmdb_cached_backend = setup_lmdb_backend();
    rt.block_on(async {
        lmdb_cached_backend
            .authenticate("uid=user500,ou=people,dc=example,dc=org", b"password500")
            .await
            .unwrap();
    });
    group.bench_function("lmdb_backend_authenticate_cache_hit", |b| {
        b.iter(|| {
            let backend = lmdb_cached_backend.clone();
            rt.block_on(async move {
                let _ = backend
                    .authenticate(
                        black_box("uid=user500,ou=people,dc=example,dc=org"),
                        black_box(b"password500"),
                    )
                    .await;
            })
        });
    });

    group.finish();
}

fn bench_lmdb_cache_internals(c: &mut Criterion) {
    let mut group = c.benchmark_group("lmdb_cache_internals");

    for capacity in [1_000_usize, 50_000, 500_000] {
        let entry_get = LmdbEntryCacheBenchmarkHarness::new(capacity);
        let mut index = 0usize;
        group.bench_function(format!("entry_get_hit_cap_{capacity}"), |b| {
            b.iter(|| {
                index = index.wrapping_add(1);
                black_box(entry_get.get_hit(black_box(index)));
            });
        });

        let entry_insert = LmdbEntryCacheBenchmarkHarness::new(capacity);
        let mut sequence = capacity;
        group.bench_function(format!("entry_insert_evict_cap_{capacity}"), |b| {
            b.iter(|| {
                sequence = sequence.wrapping_add(1);
                black_box(entry_insert.insert_new(black_box(sequence)));
            });
        });

        let entry_invalidate = LmdbEntryCacheBenchmarkHarness::new(capacity);
        let mut index = 0usize;
        group.bench_function(format!("entry_invalidate_reinsert_cap_{capacity}"), |b| {
            b.iter(|| {
                index = index.wrapping_add(1);
                black_box(entry_invalidate.invalidate_and_reinsert(black_box(index)));
            });
        });

        let auth_get = LmdbAuthCacheBenchmarkHarness::new(capacity);
        let mut index = 0usize;
        group.bench_function(format!("auth_get_hit_cap_{capacity}"), |b| {
            b.iter(|| {
                index = index.wrapping_add(1);
                black_box(auth_get.get_hit(black_box(index)));
            });
        });

        let auth_insert = LmdbAuthCacheBenchmarkHarness::new(capacity);
        let mut sequence = capacity;
        group.bench_function(format!("auth_insert_evict_cap_{capacity}"), |b| {
            b.iter(|| {
                sequence = sequence.wrapping_add(1);
                black_box(auth_insert.insert_new(black_box(sequence)));
            });
        });

        let auth_invalidate = LmdbAuthCacheBenchmarkHarness::new(capacity);
        let mut index = 0usize;
        group.bench_function(format!("auth_invalidate_reinsert_cap_{capacity}"), |b| {
            b.iter(|| {
                index = index.wrapping_add(1);
                black_box(auth_invalidate.invalidate_and_reinsert(black_box(index)));
            });
        });
    }

    group.finish();
}

fn bench_search_operations(c: &mut Criterion) {
    use ldap_parser::ldap::SearchScope;

    let mut group = c.benchmark_group("backend_search");
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Benchmark MockBackend search
    let mock_backend = setup_mock_backend();
    group.bench_function("mock_backend_search", |b| {
        b.iter(|| {
            let backend = mock_backend.clone();
            rt.block_on(async move {
                let _ = backend
                    .search_entries(
                        black_box("ou=people,dc=example,dc=org"),
                        black_box(SearchScope(2)),
                    )
                    .await;
            })
        });
    });

    // Benchmark LmdbBackend search (skip - too slow)
    // let lmdb_backend = setup_lmdb_backend();
    // group.bench_function("lmdb_backend_search", |b| {
    //     b.iter(|| {
    //         let backend = lmdb_backend.clone();
    //         rt.block_on(async move {
    //             let _ = backend.search_entries(
    //                 black_box("ou=people,dc=example,dc=org"),
    //                 black_box(SearchScope(2))
    //             ).await;
    //         })
    //     });
    // });

    group.finish();
}

fn bench_lmdb_indexed_search_hints(c: &mut Criterion) {
    use ldap_parser::ldap::SearchScope;

    let mut group = c.benchmark_group("lmdb_indexed_search_hints");
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (_dir, backend) = setup_lmdb_indexed_backend();
    let base_dn = "ou=people,dc=example,dc=org";
    let scope = SearchScope(2);

    let equality_hint = Some(SearchCandidateHint::Equality {
        attribute: "uid".to_string(),
        value: "perfbench-user-000500".to_string(),
    });
    group.bench_function("equality_uid", |b| {
        b.iter(|| {
            let backend = backend.clone();
            let hint = equality_hint.clone();
            rt.block_on(async move {
                let _ = backend
                    .search_entries_with_hint(black_box(base_dn), black_box(scope), hint)
                    .await;
            })
        });
    });

    let projected_attributes = vec![
        "uid".to_string(),
        "cn".to_string(),
        "sn".to_string(),
        "mail".to_string(),
    ];
    group.bench_function("projected_equality_uid", |b| {
        b.iter(|| {
            let backend = backend.clone();
            let hint = equality_hint.clone();
            let requested_attributes = projected_attributes.clone();
            rt.block_on(async move {
                let mut report = backend
                    .stream_projected_search_entries_with_hint_report(
                        black_box(base_dn),
                        black_box(scope),
                        hint,
                        requested_attributes,
                    )
                    .await
                    .unwrap();
                let mut entries = 0usize;
                while let Some(entry) = report.entries.recv().await {
                    black_box(entry.unwrap());
                    entries += 1;
                }
                black_box(entries);
            })
        });
    });

    let presence_hint = Some(SearchCandidateHint::Present {
        attribute: "mail".to_string(),
    });
    group.bench_function("presence_mail", |b| {
        b.iter(|| {
            let backend = backend.clone();
            let hint = presence_hint.clone();
            rt.block_on(async move {
                let _ = backend
                    .search_entries_with_hint(black_box(base_dn), black_box(scope), hint)
                    .await;
            })
        });
    });

    let substring_hint = Some(SearchCandidateHint::Substring {
        attribute: "description".to_string(),
        parts: vec![SearchSubstringPart::Any("fixture user 000500".to_string())],
    });
    group.bench_function("substring_description", |b| {
        b.iter(|| {
            let backend = backend.clone();
            let hint = substring_hint.clone();
            rt.block_on(async move {
                let _ = backend
                    .search_entries_with_hint(black_box(base_dn), black_box(scope), hint)
                    .await;
            })
        });
    });

    let ordering_hint = Some(SearchCandidateHint::GreaterOrEqual {
        attribute: "benchmarkOrder".to_string(),
        value: "500".to_string(),
    });
    group.bench_function("ordering_benchmark_order_ge", |b| {
        b.iter(|| {
            let backend = backend.clone();
            let hint = ordering_hint.clone();
            rt.block_on(async move {
                let _ = backend
                    .search_entries_with_hint(black_box(base_dn), black_box(scope), hint)
                    .await;
            })
        });
    });

    group.finish();
}

fn bench_lmdb_modify_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("lmdb_modify");
    let rt = tokio::runtime::Runtime::new().unwrap();

    let (_legacy_dir, legacy_backend, _) = setup_lmdb_modify_backend();
    group.bench_function("modify_entry_replace", |b| {
        b.iter(|| {
            let backend = legacy_backend.clone();
            rt.block_on(async move {
                backend
                    .modify_entry(
                        black_box("cn=modify-user-50,ou=people,dc=example,dc=org"),
                        vec![Modification {
                            operation: ModifyOperation::Replace,
                            attribute: "telephoneNumber".to_string(),
                            values: vec!["555-0199".to_string()],
                        }],
                    )
                    .await
                    .unwrap();
            })
        });
    });

    let (_native_dir, native_backend, schema) = setup_lmdb_modify_backend();
    group.bench_function("native_validated_modify_entry_replace", |b| {
        b.iter(|| {
            let backend = native_backend.clone();
            let schema = schema.clone();
            rt.block_on(async move {
                backend
                    .modify_entry_validated_with_actor(
                        black_box("cn=modify-user-50,ou=people,dc=example,dc=org"),
                        vec![Modification {
                            operation: ModifyOperation::Replace,
                            attribute: "telephoneNumber".to_string(),
                            values: vec!["555-0199".to_string()],
                        }],
                        None,
                        &schema,
                    )
                    .await
                    .unwrap();
            })
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_read_operations,
    bench_authentication,
    bench_lmdb_cache_internals,
    bench_search_operations,
    bench_lmdb_indexed_search_hints,
    bench_lmdb_modify_operations
);
criterion_main!(benches);

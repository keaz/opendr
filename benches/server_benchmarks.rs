//! Server Operation Performance Benchmarks
//!
//! This benchmark suite measures end-to-end performance of LDAP operations
//! through the full server request/response pipeline.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use opendr::backend::{DirectoryBackend, DirectoryEntry, MockBackend};
use opendr::schema::LdapSchema;
use std::collections::HashMap;
use std::sync::Arc;

/// Setup a mock backend with test data
fn setup_backend_with_data(num_entries: usize) -> Arc<MockBackend> {
    let backend = Arc::new(MockBackend::default());
    let rt = tokio::runtime::Runtime::new().unwrap();

    rt.block_on(async {
        // Add base DN
        let base_entry = DirectoryEntry::new(
            "dc=example,dc=com",
            HashMap::from([
                (
                    "objectClass".to_string(),
                    vec!["top".to_string(), "organization".to_string()],
                ),
                ("o".to_string(), vec!["Example Corp".to_string()]),
            ]),
        );
        backend.add_entry(base_entry, vec![]).await.unwrap();

        // Add organizational unit
        let ou_entry = DirectoryEntry::new(
            "ou=people,dc=example,dc=com",
            HashMap::from([
                (
                    "objectClass".to_string(),
                    vec!["top".to_string(), "organizationalUnit".to_string()],
                ),
                ("ou".to_string(), vec!["people".to_string()]),
            ]),
        );
        backend.add_entry(ou_entry, vec![]).await.unwrap();

        // Add user entries
        for i in 0..num_entries {
            let dn = format!("uid=user{},ou=people,dc=example,dc=com", i);
            let entry = DirectoryEntry::new(
                dn,
                HashMap::from([
                    (
                        "objectClass".to_string(),
                        vec![
                            "top".to_string(),
                            "person".to_string(),
                            "inetOrgPerson".to_string(),
                        ],
                    ),
                    ("cn".to_string(), vec![format!("User {}", i)]),
                    ("sn".to_string(), vec![format!("Surname{}", i)]),
                    ("uid".to_string(), vec![format!("user{}", i)]),
                    ("mail".to_string(), vec![format!("user{}@example.com", i)]),
                ]),
            );
            backend
                .add_entry(entry, format!("password{}", i).as_bytes().to_vec())
                .await
                .unwrap();
        }
    });

    backend
}

/// Benchmark: Backend operations with schema validation
fn bench_backend_with_schema(c: &mut Criterion) {
    let mut group = c.benchmark_group("backend_with_schema");
    let rt = tokio::runtime::Runtime::new().unwrap();

    let backend = Arc::new(MockBackend::default());
    let schema = LdapSchema::with_core_schema();

    // Benchmark: Add operation with schema validation
    group.bench_function("add_with_schema_validation", |b| {
        b.iter(|| {
            let backend = backend.clone();
            rt.block_on(async {
                let entry_attrs = HashMap::from([
                    (
                        "objectClass".to_string(),
                        vec!["top".to_string(), "person".to_string()],
                    ),
                    ("cn".to_string(), vec!["Test User".to_string()]),
                    ("sn".to_string(), vec!["User".to_string()]),
                ]);

                // Validate first
                if schema.validate_entry(black_box(&entry_attrs)).is_ok() {
                    let entry = DirectoryEntry::new(
                        black_box(format!(
                            "cn=test{},dc=example,dc=com",
                            rand::random::<u32>()
                        )),
                        entry_attrs,
                    );
                    let _ = backend.add_entry(entry, vec![]).await;
                }
            })
        });
    });

    // Benchmark: Add operation without schema validation (baseline)
    group.bench_function("add_without_schema_validation", |b| {
        b.iter(|| {
            let backend = backend.clone();
            rt.block_on(async {
                let entry = DirectoryEntry::new(
                    black_box(format!(
                        "cn=test{},dc=example,dc=com",
                        rand::random::<u32>()
                    )),
                    HashMap::from([
                        (
                            "objectClass".to_string(),
                            vec!["top".to_string(), "person".to_string()],
                        ),
                        ("cn".to_string(), vec!["Test User".to_string()]),
                        ("sn".to_string(), vec!["User".to_string()]),
                    ]),
                );
                let _ = backend.add_entry(entry, vec![]).await;
            })
        });
    });

    group.finish();
}

/// Benchmark: Authentication operations
fn bench_authentication(c: &mut Criterion) {
    let mut group = c.benchmark_group("authentication");
    let rt = tokio::runtime::Runtime::new().unwrap();

    let backend = setup_backend_with_data(100);

    // Benchmark: Successful authentication
    group.bench_function("successful_auth", |b| {
        b.iter(|| {
            let backend = backend.clone();
            rt.block_on(async {
                let result = backend
                    .authenticate(
                        black_box("uid=user50,ou=people,dc=example,dc=com"),
                        black_box(b"password50"),
                    )
                    .await;
                assert!(result.unwrap());
            })
        });
    });

    // Benchmark: Failed authentication (wrong password)
    group.bench_function("failed_auth_wrong_password", |b| {
        b.iter(|| {
            let backend = backend.clone();
            rt.block_on(async {
                let result = backend
                    .authenticate(
                        black_box("uid=user50,ou=people,dc=example,dc=com"),
                        black_box(b"wrongpassword"),
                    )
                    .await;
                assert!(!result.unwrap());
            })
        });
    });

    // Benchmark: Failed authentication (user not found)
    group.bench_function("failed_auth_user_not_found", |b| {
        b.iter(|| {
            let backend = backend.clone();
            rt.block_on(async {
                let _result = backend
                    .authenticate(
                        black_box("uid=nonexistent,ou=people,dc=example,dc=com"),
                        black_box(b"password"),
                    )
                    .await;
                // User not found
            })
        });
    });

    group.finish();
}

/// Benchmark: Search operations with varying result sizes
fn bench_search_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("search_operations");
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Test with different backend sizes
    for size in [10, 100, 1000].iter() {
        let backend = setup_backend_with_data(*size);

        group.bench_with_input(BenchmarkId::new("search_all_users", size), size, |b, _| {
            b.iter(|| {
                let backend = backend.clone();
                rt.block_on(async {
                    use ldap_parser::ldap::SearchScope;
                    let results = backend
                        .search_entries(
                            black_box("ou=people,dc=example,dc=com"),
                            black_box(SearchScope(2)), // Subtree
                        )
                        .await
                        .unwrap();
                    black_box(results);
                })
            });
        });

        group.bench_with_input(
            BenchmarkId::new("search_single_entry", size),
            size,
            |b, _| {
                b.iter(|| {
                    let backend = backend.clone();
                    rt.block_on(async {
                        let result = backend
                            .get_entry(black_box("uid=user50,ou=people,dc=example,dc=com"))
                            .await
                            .unwrap();
                        black_box(result);
                    })
                });
            },
        );
    }

    group.finish();
}

/// Benchmark: Modify operations
fn bench_modify_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("modify_operations");
    let rt = tokio::runtime::Runtime::new().unwrap();

    let backend = setup_backend_with_data(100);

    // Benchmark: Single attribute modification
    group.bench_function("modify_single_attribute", |b| {
        b.iter(|| {
            let backend = backend.clone();
            rt.block_on(async {
                use opendr::backend::{Modification, ModifyOperation};

                let modifications = vec![Modification {
                    operation: ModifyOperation::Replace,
                    attribute: "mail".to_string(),
                    values: vec![format!("newemail{}@example.com", rand::random::<u32>())],
                }];

                let _ = backend
                    .modify_entry(
                        black_box("uid=user50,ou=people,dc=example,dc=com"),
                        black_box(modifications),
                    )
                    .await;
            })
        });
    });

    // Benchmark: Multiple attribute modification
    group.bench_function("modify_multiple_attributes", |b| {
        b.iter(|| {
            let backend = backend.clone();
            rt.block_on(async {
                use opendr::backend::{Modification, ModifyOperation};

                let modifications = vec![
                    Modification {
                        operation: ModifyOperation::Replace,
                        attribute: "mail".to_string(),
                        values: vec![format!("newemail{}@example.com", rand::random::<u32>())],
                    },
                    Modification {
                        operation: ModifyOperation::Replace,
                        attribute: "cn".to_string(),
                        values: vec![format!("New Name {}", rand::random::<u32>())],
                    },
                    Modification {
                        operation: ModifyOperation::Add,
                        attribute: "description".to_string(),
                        values: vec!["Updated description".to_string()],
                    },
                ];

                let _ = backend
                    .modify_entry(
                        black_box("uid=user50,ou=people,dc=example,dc=com"),
                        black_box(modifications),
                    )
                    .await;
            })
        });
    });

    group.finish();
}

/// Benchmark: Delete operations
fn bench_delete_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("delete_operations");
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Benchmark: Delete entry
    group.bench_function("delete_entry", |b| {
        b.iter(|| {
            let backend = Arc::new(MockBackend::default());
            rt.block_on(async {
                // Add entry
                let entry = DirectoryEntry::new(
                    "cn=temp,dc=example,dc=com",
                    HashMap::from([
                        (
                            "objectClass".to_string(),
                            vec!["top".to_string(), "person".to_string()],
                        ),
                        ("cn".to_string(), vec!["Temp".to_string()]),
                        ("sn".to_string(), vec!["User".to_string()]),
                    ]),
                );
                backend.add_entry(entry, vec![]).await.unwrap();

                // Delete it
                let _ = backend
                    .delete_entry(black_box("cn=temp,dc=example,dc=com"))
                    .await;
            })
        });
    });

    group.finish();
}

/// Benchmark: Concurrent operations
fn bench_concurrent_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_operations");
    let rt = tokio::runtime::Runtime::new().unwrap();

    let backend = setup_backend_with_data(1000);

    // Benchmark: Concurrent reads
    group.bench_function("concurrent_reads_10", |b| {
        b.iter(|| {
            let backend = backend.clone();
            rt.block_on(async {
                let mut handles = vec![];
                for i in 0..10 {
                    let backend = backend.clone();
                    let handle = tokio::spawn(async move {
                        backend
                            .get_entry(&format!("uid=user{},ou=people,dc=example,dc=com", i * 10))
                            .await
                    });
                    handles.push(handle);
                }

                for handle in handles {
                    let _ = handle.await;
                }
            })
        });
    });

    // Benchmark: Concurrent authentications
    group.bench_function("concurrent_auth_10", |b| {
        b.iter(|| {
            let backend = backend.clone();
            rt.block_on(async {
                let mut handles = vec![];
                for i in 0..10 {
                    let backend = backend.clone();
                    let handle = tokio::spawn(async move {
                        backend
                            .authenticate(
                                &format!("uid=user{},ou=people,dc=example,dc=com", i * 10),
                                format!("password{}", i * 10).as_bytes(),
                            )
                            .await
                    });
                    handles.push(handle);
                }

                for handle in handles {
                    let _ = handle.await;
                }
            })
        });
    });

    group.finish();
}

/// Benchmark: Memory efficiency
fn bench_memory_efficiency(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_efficiency");

    // Benchmark: Schema instance size
    group.bench_function("schema_instance_size", |b| {
        b.iter(|| {
            let schema = LdapSchema::with_core_schema();
            black_box(schema);
        });
    });

    // Benchmark: Entry creation overhead
    group.bench_function("entry_creation", |b| {
        b.iter(|| {
            let entry = DirectoryEntry::new(
                black_box("cn=test,dc=example,dc=com"),
                HashMap::from([
                    (
                        "objectClass".to_string(),
                        vec!["top".to_string(), "person".to_string()],
                    ),
                    ("cn".to_string(), vec!["Test".to_string()]),
                    ("sn".to_string(), vec!["User".to_string()]),
                ]),
            );
            black_box(entry);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_backend_with_schema,
    bench_authentication,
    bench_search_operations,
    bench_modify_operations,
    bench_delete_operations,
    bench_concurrent_operations,
    bench_memory_efficiency
);
criterion_main!(benches);

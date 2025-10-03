//! Performance benchmarks for backend implementations
//!
//! This benchmark suite compares the performance of different backend
//! implementations, with a focus on read operations.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use opendr::backend::{DirectoryBackend, DirectoryEntry, MockBackend};
use opendr::backend_lmdb::LmdbBackend;
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::tempdir;

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

            backend.add_entry(entry, format!("password{}", i).as_bytes().to_vec())
                .await
                .unwrap();
        }
    });

    backend
}

fn setup_lmdb_backend() -> Arc<LmdbBackend> {
    let dir = tempdir().unwrap();
    let backend = Arc::new(LmdbBackend::new(dir.path(), 100).unwrap());

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

            backend.add_entry(entry, format!("password{}", i).as_bytes().to_vec())
                .await
                .unwrap();
        }
    });

    backend
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
                let _ = backend.get_entry(black_box("uid=user500,ou=people,dc=example,dc=org")).await;
            })
        });
    });

    // Benchmark LmdbBackend reads
    let lmdb_backend = setup_lmdb_backend();
    group.bench_function("lmdb_backend_get_entry", |b| {
        b.iter(|| {
            let backend = lmdb_backend.clone();
            rt.block_on(async move {
                let _ = backend.get_entry(black_box("uid=user500,ou=people,dc=example,dc=org")).await;
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
                let _ = backend.authenticate(
                    black_box("uid=user500,ou=people,dc=example,dc=org"),
                    black_box(b"password500")
                ).await;
            })
        });
    });

    // Benchmark LmdbBackend authentication
    let lmdb_backend = setup_lmdb_backend();
    group.bench_function("lmdb_backend_authenticate", |b| {
        b.iter(|| {
            let backend = lmdb_backend.clone();
            rt.block_on(async move {
                let _ = backend.authenticate(
                    black_box("uid=user500,ou=people,dc=example,dc=org"),
                    black_box(b"password500")
                ).await;
            })
        });
    });

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
                let _ = backend.search_entries(
                    black_box("ou=people,dc=example,dc=org"),
                    black_box(SearchScope(2))
                ).await;
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

criterion_group!(benches, bench_read_operations, bench_authentication, bench_search_operations);
criterion_main!(benches);

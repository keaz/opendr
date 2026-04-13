//! FSM Performance Benchmarks
//!
//! This benchmark suite measures the performance of FSM creation
//! and memory allocations.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use opendr::auth_fsm::AuthFsmImpl;
use opendr::ber_decoder_fsm::BerDecoderFsmImpl;
use opendr::connection_fsm::{ConnectionFsmImpl, NoOpTlsHandler};

/// Benchmark: FSM creation overhead
fn bench_fsm_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("fsm_creation");

    // Benchmark: ConnectionFsm creation
    group.bench_function("connection_fsm", |b| {
        b.iter(|| {
            let tls_handler = Box::new(NoOpTlsHandler);
            ConnectionFsmImpl::new(black_box("test-connection"), black_box(tls_handler))
        });
    });

    // Benchmark: AuthFsm creation
    group.bench_function("auth_fsm", |b| {
        b.iter(AuthFsmImpl::new);
    });

    // Benchmark: BerDecoderFsm creation
    group.bench_function("ber_decoder_fsm", |b| {
        b.iter(BerDecoderFsmImpl::new);
    });

    group.finish();
}

/// Benchmark: Multiple FSM creations (batch)
fn bench_fsm_batch_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("fsm_batch_creation");

    // Benchmark: Create 10 ConnectionFsm instances
    group.bench_function("10_connection_fsms", |b| {
        b.iter(|| {
            for _ in 0..10 {
                let tls_handler = Box::new(NoOpTlsHandler);
                black_box(ConnectionFsmImpl::new("test-connection", tls_handler));
            }
        });
    });

    // Benchmark: Create 10 AuthFsm instances
    group.bench_function("10_auth_fsms", |b| {
        b.iter(|| {
            for _ in 0..10 {
                black_box(AuthFsmImpl::new());
            }
        });
    });

    // Benchmark: Create 10 BerDecoderFsm instances
    group.bench_function("10_ber_decoder_fsms", |b| {
        b.iter(|| {
            for _ in 0..10 {
                black_box(BerDecoderFsmImpl::new());
            }
        });
    });

    group.finish();
}

criterion_group!(benches, bench_fsm_creation, bench_fsm_batch_creation);
criterion_main!(benches);

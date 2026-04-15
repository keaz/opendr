//! FSM Performance Benchmarks
//!
//! This benchmark suite measures the performance of FSM creation
//! and memory allocations.

use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use ldap_parser::parse_ldap_messages;
use opendr::auth_fsm::AuthFsmImpl;
use opendr::ber_decoder_fsm::BerDecoderFsmImpl;
use opendr::connection_fsm::{ConnectionFsmImpl, NoOpTlsHandler};
use rasn::der;
use rasn_ldap::{
    AuthenticationChoice as RasnAuthChoice, BindRequest as RasnBindRequest,
    LdapMessage as RasnLdapMessage, ProtocolOp as RasnProtocolOp,
};

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

fn encode_bind_request(message_id: u32) -> Vec<u8> {
    let bind_request = RasnBindRequest::new(
        3,
        b"cn=admin,dc=example,dc=org".to_vec().into(),
        RasnAuthChoice::Simple(b"secret".to_vec().into()),
    );
    let message = RasnLdapMessage::new(message_id, RasnProtocolOp::BindRequest(bind_request));
    der::encode(&message).expect("bind request should encode")
}

fn bench_ber_decode_read_path(c: &mut Criterion) {
    let mut group = c.benchmark_group("ber_decode_read_path");
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime should start");
    let single_bind = encode_bind_request(1);
    let coalesced_binds = (1..=8).flat_map(encode_bind_request).collect::<Vec<u8>>();

    group.bench_function("borrowed_slice_single_bind", |b| {
        b.iter_batched(
            BerDecoderFsmImpl::new,
            |mut decoder| {
                rt.block_on(async {
                    let messages = decoder
                        .decode_available_messages(black_box(single_bind.as_slice()))
                        .await
                        .expect("decode should succeed");
                    black_box(messages);
                })
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("borrowed_slice_decode_parse_8_binds", |b| {
        b.iter_batched(
            BerDecoderFsmImpl::new,
            |mut decoder| {
                rt.block_on(async {
                    let frames = decoder
                        .decode_available_messages(black_box(coalesced_binds.as_slice()))
                        .await
                        .expect("decode should succeed");
                    for frame in frames {
                        let (_, messages) =
                            parse_ldap_messages(black_box(&frame)).expect("LDAP parse succeeds");
                        black_box(messages);
                    }
                })
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("borrowed_slice_decode_into_parse_8_binds", |b| {
        b.iter_batched(
            || (BerDecoderFsmImpl::new(), Vec::with_capacity(8)),
            |(mut decoder, mut frames)| {
                rt.block_on(async {
                    decoder
                        .decode_available_messages_into(
                            black_box(coalesced_binds.as_slice()),
                            &mut frames,
                        )
                        .await
                        .expect("decode should succeed");
                    for frame in frames.drain(..) {
                        let (_, messages) =
                            parse_ldap_messages(black_box(&frame)).expect("LDAP parse succeeds");
                        black_box(messages);
                    }
                    black_box(frames.capacity());
                })
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_fsm_creation,
    bench_fsm_batch_creation,
    bench_ber_decode_read_path
);
criterion_main!(benches);

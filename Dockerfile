# syntax=docker/dockerfile:1.7

FROM rust:1.94-bookworm AS chef

RUN cargo install cargo-chef --version 0.1.71

WORKDIR /build

FROM chef AS planner

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY benches ./benches

RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder

WORKDIR /build
ARG CARGO_PROFILE=release
ARG RUSTFLAGS=""
ENV RUSTFLAGS=${RUSTFLAGS}

COPY --from=planner /build/recipe.json ./recipe.json

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target-cache \
    cargo chef cook --release --recipe-path recipe.json --target-dir /build/target-cache

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY benches ./benches

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target-cache \
    cargo build --profile "${CARGO_PROFILE}" --target-dir /build/target-cache --bin opendr --bin opendr-setup --bin ldap_perf_client --bin opendr_perf_fixture_loader \
    && install -D "/build/target-cache/${CARGO_PROFILE}/opendr" /build/target/release/opendr \
    && install -D "/build/target-cache/${CARGO_PROFILE}/opendr-setup" /build/target/release/opendr-setup \
    && install -D "/build/target-cache/${CARGO_PROFILE}/ldap_perf_client" /build/target/release/ldap_perf_client \
    && install -D "/build/target-cache/${CARGO_PROFILE}/opendr_perf_fixture_loader" /build/target/release/opendr_perf_fixture_loader

FROM debian:bookworm-slim AS perf-client

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates openssl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/ldap_perf_client /usr/local/bin/ldap_perf_client

ENTRYPOINT ["/usr/local/bin/ldap_perf_client"]

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates openssl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --create-home --home-dir /var/lib/opendr --shell /usr/sbin/nologin opendr

WORKDIR /var/lib/opendr

COPY --from=builder /build/target/release/opendr /usr/local/bin/opendr
COPY --from=builder /build/target/release/opendr-setup /usr/local/bin/opendr-setup
COPY --from=builder /build/target/release/opendr_perf_fixture_loader /usr/local/bin/opendr_perf_fixture_loader
COPY docker/opendr-entrypoint.sh /usr/local/bin/opendr-entrypoint.sh

RUN chmod +x /usr/local/bin/opendr-entrypoint.sh \
    && mkdir -p /var/lib/opendr/config /var/lib/opendr/certs /var/lib/opendr/data \
    && chown -R opendr:opendr /var/lib/opendr

USER opendr

EXPOSE 1389 1636

ENV OPENDR_BIND_ADDRESS=0.0.0.0 \
    OPENDR_LDAP_PORT=1389 \
    OPENDR_LDAPS_PORT=1636 \
    OPENDR_BASE_DN=dc=example,dc=com \
    OPENDR_ROOT_USER_DN=cn=admin \
    OPENDR_ORGANIZATION_NAME="OpenDR Docker" \
    OPENDR_LMDB_MAX_SIZE=1073741824 \
    OPENDR_LMDB_MAX_READERS=256 \
    OPENDR_MAX_CONNECTIONS=512 \
    OPENDR_MAX_CONNECTIONS_PER_IP=256 \
    OPENDR_MAX_OPERATIONS_PER_CONNECTION=200 \
    OPENDR_MAX_MEMORY_PER_CONNECTION=10485760 \
    OPENDR_MAX_TOTAL_MEMORY=2147483648 \
    OPENDR_CONNECTION_IDLE_TIMEOUT_SECS=600 \
    OPENDR_AUTH_METADATA_UPDATE_MODE=sync \
    OPENDR_AUTH_METADATA_QUEUE_CAPACITY=100000 \
    OPENDR_AUTH_METADATA_FLUSH_INTERVAL_MS=100 \
    OPENDR_AUTH_METADATA_BATCH_SIZE=1000 \
    OPENDR_AUTH_METADATA_OVERFLOW_POLICY=fallback_sync

VOLUME ["/var/lib/opendr/data"]

ENTRYPOINT ["/usr/local/bin/opendr-entrypoint.sh"]

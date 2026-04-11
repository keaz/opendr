# syntax=docker/dockerfile:1.7

FROM rust:1.86-bookworm AS chef

RUN cargo install cargo-chef --version 0.1.71

WORKDIR /build

FROM chef AS planner

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY benches ./benches

RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder

WORKDIR /build

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
    cargo build --release --target-dir /build/target-cache --bin opendr --bin opendr-setup --bin ldap_perf_client \
    && install -D /build/target-cache/release/opendr /build/target/release/opendr \
    && install -D /build/target-cache/release/opendr-setup /build/target/release/opendr-setup \
    && install -D /build/target-cache/release/ldap_perf_client /build/target/release/ldap_perf_client

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
    OPENDR_LMDB_MAX_READERS=126

VOLUME ["/var/lib/opendr/data"]

ENTRYPOINT ["/usr/local/bin/opendr-entrypoint.sh"]

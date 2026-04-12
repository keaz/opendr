# Docker LDAP Performance Comparison

This document captures the validated Dockerized LDAP benchmark results for OpenDR and OpenDJ. It now separates the older OpenDR legacy-runtime run from the newer OpenDR FSM-runtime run so runtime-to-runtime comparisons are explicit.

## Scope

- OpenDR was built from the local `Dockerfile` and configured to use the `lmdb` backend.
- OpenDJ was run from `openidentityplatform/opendj:5.0.4`.
- Both servers were capped at `2` CPU cores and `4 GiB` memory with Docker resource limits.
- StartTLS was enabled for both products.
- The accepted pre-remediation reference baseline remains `target/perf/docker-matrix-issue52-batched/`.
- The legacy runtime remediation run is `target/perf/docker-matrix-issue55-nodelay-full/`.
- The latest FSM runtime run is `target/perf/docker-matrix-fsm-auth-cache-final-full-20260411/`.
- The latest OpenDJ comparison run is `target/perf/docker-matrix-opendj-current-full-20260411/`.
- The latest concurrent-bind OpenDR tuned capacity run is `target/perf/docker-matrix-concurrent-bind-fsm-opendr-config-128-20260411/`.
- The concurrent-bind OpenDJ comparison run is `target/perf/docker-matrix-concurrent-bind-fsm-opendj-isolated-20260411/`.
- The latest index-type comparison run is `target/perf/docker-matrix-index-types-final-20260412/`.
- There is not yet a validated 10M-user benchmark artifact. The 10M+ section below uses the largest measured Docker profile plus the concurrent-bind capacity run as bounded proxies and calls out the required production-scale benchmark work.

## Reproduction

Legacy runtime remediation run:

```bash
DOCKER_BUILDKIT=1 ./scripts/perf_docker_matrix.sh \
  --profile-set full \
  --output-dir target/perf/docker-matrix-issue55-nodelay-full
```

FSM runtime current run:

```bash
./scripts/perf_docker_matrix.sh \
  --profile-set full \
  --products opendr \
  --opendr-runtime fsm \
  --perf-client-image opendr:docker-perf-client \
  --output-dir target/perf/docker-matrix-fsm-auth-cache-final-full-20260411
```

OpenDJ current comparison run:

```bash
./scripts/perf_docker_matrix.sh \
  --profile-set full \
  --products opendj \
  --perf-client-image opendr:docker-perf-client \
  --output-dir target/perf/docker-matrix-opendj-current-full-20260411
```

Concurrent bind baseline comparison run:

```bash
./scripts/perf_docker_matrix.sh \
  --profile-set concurrency \
  --products opendr,opendj \
  --opendr-runtime fsm \
  --benchmark-timeout 240 \
  --concurrent-bind-clients 1,4,8,10,12,16,32,64,128 \
  --concurrent-bind-iterations 20 \
  --concurrent-bind-warmup-iterations 1 \
  --concurrent-bind-operation-timeout-ms 5000 \
  --output-dir target/perf/docker-matrix-concurrent-bind-fsm-opendj-isolated-20260411
```

OpenDR tuned 128-client capacity run:

```bash
./scripts/perf_docker_matrix.sh \
  --profile-set concurrency \
  --products opendr \
  --opendr-runtime fsm \
  --benchmark-timeout 240 \
  --concurrent-bind-clients 1,4,8,10,12,16,32,64,128 \
  --concurrent-bind-iterations 20 \
  --concurrent-bind-warmup-iterations 1 \
  --concurrent-bind-operation-timeout-ms 5000 \
  --output-dir target/perf/docker-matrix-concurrent-bind-fsm-opendr-config-128-20260411
```

Index-type comparison run:

```bash
./scripts/perf_docker_matrix.sh \
  --profile-set index \
  --products opendr,opendj \
  --opendr-runtime fsm \
  --benchmark-timeout 240 \
  --concurrent-index-search-clients 1,4,8,16,32 \
  --concurrent-index-search-iterations 20 \
  --concurrent-index-search-warmup-iterations 1 \
  --concurrent-index-search-operation-timeout-ms 5000 \
  --output-dir target/perf/docker-matrix-index-types-final-20260412
```

## What Changed

Legacy runtime remediation:

- `#53`: retained the bounded exact-DN LMDB entry cache with lazy refill on reads and invalidation on writes.
- `#54`: added the exact-DN base-object server fast path so base searches no longer fall back to the generic candidate scan path.
- `#55`: enabled `TCP_NODELAY` on accepted LDAP and LDAPS sockets. This removed the dominant small-response latency penalty on single-entry search responses.

FSM runtime performance remediation:

- Batched FSM search result writes to avoid per-entry socket/TLS write stalls.
- Routed FSM searches through backend search candidate hints when equality/presence hints are available.
- Reduced redundant `DirectoryEntry` / `SearchEntry` conversion and per-candidate cloning.
- Removed unused FSM result-cache configuration and documented backend-only caching.
- Reduced remaining search hot-path allocations with shared `Arc<SearchEntry>` values, compiled-filter reuse, and per-request attribute projection caching.
- Added a bounded LMDB auth credential cache that stores decoded SSHA512 hash+salt records only, with invalidation/update coverage for password modify, delete, rename, and prehashed password updates.
- Fixed non-password modify operations so they no longer rewrite/delete password credentials.
- Added an `index` Docker profile that exercises equality, presence, substring, and ordering-style search filters, plus concurrent mixed index-search probes. The OpenDR run uses LMDB equality/presence defaults plus typed `description` substring and `sn` ordering indexes. The OpenDJ run uses matching `uid` equality, `mail` presence, `description` substring, and `sn` ordering backend index settings.

## Load Profiles

| Profile | Preloaded users | Read iterations | Write iterations | Warmup iterations |
|---|---:|---:|---:|---:|
| light | 100 | 50 | 25 | 5 |
| moderate | 500 | 10 | 10 | 2 |
| heavy | 1000 | 5 | 5 | 2 |
| stress | 2500 | 3 | 3 | 1 |
| auth-concurrency | 2500 | 3 | 3 | 1 |
| index | 1000 | 30 | 10 | 2 |

These profiles are not 10M-user scale. They are bounded Docker regression profiles intended to catch relative latency, storage, and resource regressions quickly under a repeatable 2 CPU / 4 GiB container envelope.

The earlier matrix already captured per-operation throughput, but it did not answer maximum sustainable concurrent bind clients or failure rate under the Docker configuration. The `auth-concurrency` profile now adds a concurrent simple-bind probe with configurable client levels, operation timeouts, successes, failures, failure rate, attempt throughput, and successful-throughput metrics.

The `index` profile adds search probes for:

- equality: `(uid=<fixture user>)`
- presence: `(mail=*)`
- substring: `(description=*fixture user 000000*)`
- ordering lower bound: `(sn>=BenchmarkUser000500)`
- ordering upper bound: `(sn<=BenchmarkUser000500)`

It also runs a concurrent mixed index-search probe over those filters at 1, 4, 8, 16, and 32 clients.

## Legacy Runtime Results

These are the older OpenDR legacy-runtime results from `target/perf/docker-matrix-issue55-nodelay-full/`, kept as the legacy runtime reference point.

| Product / runtime | Profile | Status | Total runtime ms | Records after setup | Avg CPU % | Avg memory | DB after | Subtree search mean ms | Add mean ms | Modify mean ms | Delete mean ms |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| OpenDR legacy | light | success | 385.351 | 109 | 10.75 | 4.02 MiB | 668.00 KiB | 1.094 | 0.561 | 0.746 | 0.538 |
| OpenDJ | light | success | 965.819 | 105 | 184.21 | 815.20 MiB | 1.08 MiB | 5.024 | 1.122 | 0.574 | 1.172 |
| OpenDR legacy | moderate | success | 518.151 | 509 | 10.69 | 4.17 MiB | 2.03 MiB | 4.384 | 0.655 | 0.615 | 0.625 |
| OpenDJ | moderate | success | 1296.574 | 505 | 200.45 | 804.80 MiB | 9.14 MiB | 22.638 | 1.313 | 0.524 | 1.675 |
| OpenDR legacy | heavy | success | 858.713 | 1009 | 5.68 | 5.05 MiB | 3.03 MiB | 6.597 | 0.715 | 0.638 | 0.640 |
| OpenDJ | heavy | success | 1891.080 | 1005 | 99.39 | 976.85 MiB | 29.14 MiB | 35.390 | 1.323 | 0.518 | 2.111 |
| OpenDR legacy | stress | success | 1978.444 | 2509 | 7.92 | 6.17 MiB | 7.04 MiB | 13.317 | 0.776 | 0.647 | 0.641 |
| OpenDJ | stress | success | 4913.137 | 2505 | 122.38 | 413.60 MiB | 176.95 MiB | 78.640 | 1.911 | 0.499 | 4.381 |

## FSM Runtime Results

These are the latest OpenDR FSM-runtime results after the FSM search performance work, compared against a fresh OpenDJ run under the same Docker perf harness.

| Product / runtime | Profile | Status | Total runtime ms | Records after setup | Avg CPU % | Avg memory | DB after | Subtree search mean ms | Add mean ms | Modify mean ms | ModifyDN mean ms | Delete mean ms | Password modify mean ms |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| OpenDR FSM | light | success | 297.105 | 109 | 10.28 | 2.87 MiB | 668.00 KiB | 0.813 | 0.414 | 0.365 | 0.470 | 0.406 | 0.359 |
| OpenDJ | light | success | 812.928 | 105 | 153.56 | 805.90 MiB | 1.08 MiB | 3.838 | 1.333 | 0.466 | 0.842 | 1.156 | 0.610 |
| OpenDR FSM | moderate | success | 426.724 | 509 | 13.89 | 4.17 MiB | 2.03 MiB | 3.271 | 0.483 | 0.426 | 0.525 | 0.430 | 0.461 |
| OpenDJ | moderate | success | 1133.903 | 505 | 193.31 | 805.40 MiB | 9.14 MiB | 14.073 | 0.920 | 0.487 | 0.978 | 1.519 | 0.760 |
| OpenDR FSM | heavy | success | 674.149 | 1009 | 20.19 | 5.67 MiB | 3.04 MiB | 6.244 | 0.526 | 0.472 | 0.602 | 0.460 | 0.503 |
| OpenDJ | heavy | success | 1755.398 | 1005 | 92.42 | 829.40 MiB | 29.14 MiB | 25.052 | 1.200 | 0.365 | 1.242 | 2.895 | 0.754 |
| OpenDR FSM | stress | success | 1562.885 | 2509 | 11.24 | 6.69 MiB | 7.03 MiB | 15.500 | 0.579 | 0.473 | 0.594 | 0.514 | 0.769 |
| OpenDJ | stress | success | 4232.527 | 2505 | 135.60 | 835.30 MiB | 176.89 MiB | 47.034 | 1.836 | 0.420 | 1.768 | 3.204 | 0.929 |

## FSM Versus OpenDJ

| Area | Light | Moderate | Heavy | Stress | Direction |
|---|---:|---:|---:|---:|---|
| Total runtime | 297.105 vs 812.928 | 426.724 vs 1133.903 | 674.149 vs 1755.398 | 1562.885 vs 4232.527 | FSM faster |
| Root DSE mean ms | 0.100 vs 0.563 | 0.101 vs 0.546 | 0.104 vs 0.460 | 0.105 vs 0.618 | FSM faster |
| Bind admin mean ms | 0.088 vs 0.327 | 0.088 vs 0.281 | 0.087 vs 0.249 | 0.089 vs 0.309 | FSM faster |
| Subtree search mean ms | 0.813 vs 3.838 | 3.271 vs 14.073 | 6.244 vs 25.052 | 15.500 vs 47.034 | FSM faster |
| Add mean ms | 0.414 vs 1.333 | 0.483 vs 0.920 | 0.526 vs 1.200 | 0.579 vs 1.836 | FSM faster |
| Modify mean ms | 0.365 vs 0.466 | 0.426 vs 0.487 | 0.472 vs 0.365 | 0.473 vs 0.420 | OpenDJ faster on heavy and stress |
| ModifyDN mean ms | 0.470 vs 0.842 | 0.525 vs 0.978 | 0.602 vs 1.242 | 0.594 vs 1.768 | FSM faster |
| Delete mean ms | 0.406 vs 1.156 | 0.430 vs 1.519 | 0.460 vs 2.895 | 0.514 vs 3.204 | FSM faster |
| Password modify mean ms | 0.359 vs 0.610 | 0.461 vs 0.760 | 0.503 vs 0.754 | 0.769 vs 0.929 | FSM faster |

## Index Type Results

These results are from `target/perf/docker-matrix-index-types-final-20260412/`. They use the same Docker limits as the main matrix: 2 CPU, 4 GiB memory, StartTLS enabled, 1,000 preloaded fixture users, 30 read iterations, 10 write iterations, and a 240 second timeout budget per product.

The compared index mappings are:

| Search probe | OpenDR LMDB index | OpenDJ backend index |
|---|---|---|
| `(uid=<fixture user>)` | equality on `uid` from legacy `indexed_attributes` defaults | equality on `uid` |
| `(mail=*)` | presence on `mail` from legacy `indexed_attributes` defaults | presence on `mail` |
| `(description=*fixture user 000000*)` | typed substring index on `description` | substring on `description` |
| `(sn>=BenchmarkUser000500)` | typed ordering index on `sn` | ordering on `sn` |
| `(sn<=BenchmarkUser000500)` | typed ordering index on `sn` | ordering on `sn` |

Top-line index-profile results:

| Product / runtime | Status | Total runtime ms | Records after setup | Avg CPU % | Avg memory | DB after | Subtree search mean ms | Add mean ms | Modify mean ms | Delete mean ms |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| OpenDR FSM | success | 5870.618 | 1009 | 66.45 | 10.26 MiB | 9.06 MiB | 6.966 | 1.270 | 1.528 | 1.568 |
| OpenDJ | success | 17674.334 | 1005 | 174.79 | 567.43 MiB | 9.14 MiB | 30.545 | 0.847 | 0.541 | 1.490 |

Index search latency:

| Product / runtime | Equality uid mean ms | Presence mail mean ms | Substring description mean ms | Ordering sn >= mean ms | Ordering sn <= mean ms |
|---|---:|---:|---:|---:|---:|
| OpenDR FSM | 0.265 | 8.177 | 3.894 | 5.207 | 4.893 |
| OpenDJ | 0.412 | 21.166 | 4.358 | 10.687 | 10.654 |

Concurrent mixed index-search results:

| Product / runtime | Max tested clients | Max 0% failure clients | Failure rate at max tested | Peak success ops/s | Clients at peak | Mean ms at peak | P95 ms at peak | P99 ms at peak |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| OpenDR FSM | 32 | 32 | 0.00% | 501.46 | 8 | 15.188 | 29.417 | 37.602 |
| OpenDJ | 32 | 32 | 0.00% | 136.71 | 8 | 56.440 | 111.219 | 185.933 |

Per-level concurrent mixed index-search results:

| Product / runtime | Concurrent clients | Successes / attempts | Failure % | Success ops/s | Mean ms | P95 ms | P99 ms |
|---|---:|---:|---:|---:|---:|---:|---:|
| OpenDR FSM | 1 | 20 / 20 | 0.00 | 221.49 | 4.510 | 8.845 | 9.851 |
| OpenDR FSM | 4 | 80 / 80 | 0.00 | 490.50 | 7.693 | 12.395 | 17.046 |
| OpenDR FSM | 8 | 160 / 160 | 0.00 | 501.46 | 15.188 | 29.417 | 37.602 |
| OpenDR FSM | 16 | 320 / 320 | 0.00 | 453.26 | 33.107 | 59.035 | 70.012 |
| OpenDR FSM | 32 | 640 / 640 | 0.00 | 343.13 | 90.384 | 160.057 | 176.579 |
| OpenDJ | 1 | 20 / 20 | 0.00 | 112.48 | 8.888 | 20.917 | 23.271 |
| OpenDJ | 4 | 80 / 80 | 0.00 | 115.37 | 33.389 | 90.414 | 112.192 |
| OpenDJ | 8 | 160 / 160 | 0.00 | 136.71 | 56.440 | 111.219 | 185.933 |
| OpenDJ | 16 | 320 / 320 | 0.00 | 96.82 | 158.670 | 380.841 | 490.146 |
| OpenDJ | 32 | 640 / 640 | 0.00 | 81.03 | 383.904 | 788.779 | 971.122 |

In this bounded profile, OpenDR FSM is faster on the indexed read probes and uses far less memory. OpenDJ is faster on the write-heavy rows in this particular index-profile run after its `mail` and `sn` index settings were changed for presence/order coverage. The result is still a 1,000-user Docker regression profile, not a production cardinality claim.

## 10M+ User Base Readiness

There is no completed 10M-user OpenDR-vs-OpenDJ benchmark artifact yet. The current largest measured Docker profile is `stress`, with roughly 2,500 preloaded users and 3 read/write iterations. The concurrent-bind run below also uses 2,500 preloaded users. Treat both tables as bounded proxies for directionality, not as production-scale 10M results.

At the largest measured profile, OpenDR FSM is still ahead of OpenDJ on the high-login path and most write paths:

| Area | OpenDR FSM stress | OpenDJ stress | Delta | Interpretation for 10M+ planning |
|---|---:|---:|---:|---|
| Bind admin mean ms | 0.089 | 0.309 | -71.20% | Current FSM bind path is faster in the bounded proxy. |
| Subtree search mean ms | 15.500 | 47.034 | -67.05% | FSM is faster in the bounded proxy, but this is not a full 10M subtree scan test. |
| Add mean ms | 0.579 | 1.836 | -68.46% | FSM is faster for generated-entry adds in this harness. |
| Modify mean ms | 0.473 | 0.420 | +12.62% | OpenDJ remains faster; this is the main OpenDJ-relative gap to investigate. |
| ModifyDN mean ms | 0.594 | 1.768 | -66.40% | FSM is faster in this harness. |
| Delete mean ms | 0.514 | 3.204 | -83.96% | FSM is faster in this harness. |
| Password modify mean ms | 0.769 | 0.929 | -17.22% | FSM is faster, but this profile has only 3 write iterations and should be rechecked with higher sample counts. |

A rough storage projection from the measured light-to-stress delta is favorable to OpenDR, but it is an estimate over the generated fixture schema, not a measured 10M load:

| Product / runtime | Incremental DB bytes per generated user | Linear 10M-user DB estimate | Caveat |
|---|---:|---:|---|
| OpenDR FSM | 2.72 KiB/user | 25.94 GiB | Estimate from `db_after_bytes` growth between the light and stress profiles. |
| OpenDJ | 75.02 KiB/user | 715.40 GiB | Estimate from `db_after_bytes` growth between the light and stress profiles. |

The concurrent-bind capacity runs give the missing failure-rate signal, but they are still 2,500-user Docker proxies:

| Product / runtime | Profile | Max tested concurrent bind clients | Max 0% failure concurrent bind clients | Failure rate at max tested | Peak successful bind throughput | CPU avg / max | Memory avg / max |
|---|---|---:|---:|---:|---:|---:|---:|
| OpenDR FSM pre-tuning | auth-concurrency | 128 | 10 | 92.19% | 21,519.35 ops/s | 2.11% / 13.72% | 12.05 MiB / 19.81 MiB |
| OpenDR FSM tuned server.toml | auth-concurrency | 128 | 128 | 0.00% | 30,915.94 ops/s | 36.44% / 63.43% | 12.50 MiB / 22.39 MiB |
| OpenDJ | auth-concurrency | 128 | 128 | 0.00% | 10,805.43 ops/s | 164.18% / 195.55% | 842.62 MiB / 871.60 MiB |

OpenDR tuned server.toml per-level concurrent bind results:

| Product / runtime | Concurrent clients | Successes / attempts | Failure % | Success ops/s | P95 ms | P99 ms |
|---|---:|---:|---:|---:|---:|---:|
| OpenDR FSM tuned server.toml | 1 | 20 / 20 | 0.00 | 4,116.71 | 0.271 | 0.334 |
| OpenDR FSM tuned server.toml | 4 | 80 / 80 | 0.00 | 10,122.95 | 1.001 | 1.215 |
| OpenDR FSM tuned server.toml | 8 | 160 / 160 | 0.00 | 14,687.88 | 1.319 | 1.463 |
| OpenDR FSM tuned server.toml | 10 | 200 / 200 | 0.00 | 17,028.52 | 1.230 | 1.464 |
| OpenDR FSM tuned server.toml | 12 | 240 / 240 | 0.00 | 20,466.54 | 1.182 | 1.379 |
| OpenDR FSM tuned server.toml | 16 | 320 / 320 | 0.00 | 24,156.64 | 1.190 | 1.423 |
| OpenDR FSM tuned server.toml | 32 | 640 / 640 | 0.00 | 30,915.94 | 1.432 | 2.021 |
| OpenDR FSM tuned server.toml | 64 | 1,280 / 1,280 | 0.00 | 30,013.72 | 2.621 | 3.094 |
| OpenDR FSM tuned server.toml | 128 | 2,560 / 2,560 | 0.00 | 27,099.43 | 5.394 | 5.766 |

Pre-tuning OpenDR and OpenDJ comparison per-level results:

| Product / runtime | Concurrent clients | Successes / attempts | Failure % | Success ops/s | P95 ms | P99 ms |
|---|---:|---:|---:|---:|---:|---:|
| OpenDR FSM | 1 | 20 / 20 | 0.00 | 3,972.82 | 0.277 | 0.286 |
| OpenDR FSM | 4 | 80 / 80 | 0.00 | 9,332.03 | 1.140 | 1.431 |
| OpenDR FSM | 8 | 160 / 160 | 0.00 | 13,614.17 | 1.285 | 1.462 |
| OpenDR FSM | 10 | 200 / 200 | 0.00 | 21,519.35 | 0.857 | 0.981 |
| OpenDR FSM | 12 | 200 / 240 | 16.67 | 10,668.37 | 1.660 | 1.909 |
| OpenDR FSM | 16 | 200 / 320 | 37.50 | 7,817.95 | 2.389 | 3.233 |
| OpenDR FSM | 32 | 200 / 640 | 68.75 | 9,279.83 | 2.121 | 2.619 |
| OpenDR FSM | 64 | 200 / 1,280 | 84.38 | 6,993.57 | 2.791 | 5.530 |
| OpenDR FSM | 128 | 200 / 2,560 | 92.19 | 11,088.04 | 1.410 | 1.779 |
| OpenDJ | 1 | 20 / 20 | 0.00 | 2,460.71 | 0.485 | 0.512 |
| OpenDJ | 4 | 80 / 80 | 0.00 | 6,980.80 | 0.917 | 1.049 |
| OpenDJ | 8 | 160 / 160 | 0.00 | 10,463.61 | 1.315 | 1.422 |
| OpenDJ | 10 | 200 / 200 | 0.00 | 10,805.43 | 1.670 | 1.990 |
| OpenDJ | 12 | 240 / 240 | 0.00 | 3,118.27 | 1.926 | 57.449 |
| OpenDJ | 16 | 320 / 320 | 0.00 | 3,641.49 | 3.821 | 64.547 |
| OpenDJ | 32 | 640 / 640 | 0.00 | 6,340.49 | 3.861 | 66.699 |
| OpenDJ | 64 | 1,280 / 1,280 | 0.00 | 6,279.05 | 72.312 | 76.798 |
| OpenDJ | 128 | 2,560 / 2,560 | 0.00 | 6,589.20 | 72.592 | 76.899 |

The pre-tuning OpenDR FSM zero-failure peak was faster than OpenDJ's zero-failure peak, but OpenDR failed beyond 10 concurrent bind clients because connections from the Docker bridge source IP were rejected by the server resource gate. The isolated probe runs immediately after fixture setup with the setup connection closed, so the 10-client zero-failure ceiling lined up with the former default same-source-IP connection limit. After tuning `server.toml` and the Docker entrypoint-generated `server.toml` to `resources.max_connections_per_ip = 256`, `resources.max_connections = 512`, and `backend.lmdb_max_readers = 256`, OpenDR FSM sustained the max tested 128 concurrent bind clients at 0% failure. The checked-in `server.toml` also raises the enabled rate-limit profile to avoid falling back to the conservative default `bind = 10` auth attempts/sec ceiling outside the Docker perf entrypoint. Under this harness, the original measured OpenDR limit was configuration-bound by connection policy, not CPU or memory saturation.

For a production 10M+ userbase with high login request volume, the remaining validation gap is now 10M-scale coverage and production-tuned connection limits, not just low-sample latency coverage. Issue `#74` should include the 10M+ preload path, p50/p95/p99 bind latency, auth-cache telemetry, wrong-password/unknown-DN traffic mix, multiple client source IPs, and a rerun with tuned `resources.max_connections_per_ip` / `resources.max_connections`. No 10M production-readiness claim should be made until that benchmark compares OpenDR FSM with OpenDJ under the same user cardinality, concurrency, TLS mode, CPU/memory limits, generated schema, and connection-limit policy.

## Improvement Versus Accepted Baseline

These deltas compare OpenDR legacy runtime in `target/perf/docker-matrix-issue55-nodelay-full/` against the accepted `target/perf/docker-matrix-issue52-batched/` baseline.

| Profile | Total runtime delta | Root DSE delta | Subtree search delta | Add delta | Modify delta | Delete delta |
|---|---:|---:|---:|---:|---:|---:|
| light | `-95.10%` | `-99.39%` | `-97.60%` | `-3.28%` | `+50.40%` | `+1.13%` |
| moderate | `-77.21%` | `-99.09%` | `-91.27%` | `-32.54%` | `-26.17%` | `-22.65%` |
| heavy | `-54.11%` | `-99.39%` | `-88.04%` | `-10.74%` | `-12.48%` | `-10.36%` |
| stress | `-24.22%` | `-99.40%` | `-75.32%` | `-8.06%` | `-2.27%` | `+0.79%` |

## Key Findings

- The old OpenDR rows in this document are legacy-runtime results, not FSM-runtime results.
- The latest OpenDR FSM runtime is faster than the fresh OpenDJ run on total runtime, Root DSE search, bind, subtree search, add, modifyDN, delete, password modify, memory footprint, and disk footprint.
- The only OpenDJ-relative regression in the latest FSM run is `modify` at larger profiles: `heavy` is `0.472 ms` for FSM vs `0.365 ms` for OpenDJ, and `stress` is `0.473 ms` for FSM vs `0.420 ms` for OpenDJ.
- In the index profile, OpenDR FSM is faster than OpenDJ on all measured indexed read probes and reaches higher mixed concurrent index-search throughput, with 0% failures through the max tested 32 concurrent clients. OpenDJ remains faster on `add`, `modify`, and `delete` in that same index-profile write sample.
- The remaining FSM search optimization target is no longer OpenDJ parity. It is OpenDR legacy-runtime parity: the latest FSM subtree search is still slower than the current OpenDR legacy baseline in the server-network harness.
- The dominant earlier legacy-runtime bottleneck was not LMDB lookup cost. It was response-path latency on small LDAP search replies. Enabling `TCP_NODELAY` removed that bottleneck immediately.
- The Docker perf harness now captures operation throughput, concurrent bind successes/failures, failure rate, and successful bind throughput. The pre-tuning OpenDR FSM run exposed a same-source-IP connection-limit gap at 10 clients; the tuned `server.toml` and Docker entrypoint-generated config now sustain the max tested 128 concurrent bind clients at 0% failure, and the checked-in `server.toml` rate-limit profile no longer uses the conservative default 10 bind/sec ceiling.
- A 10M+ userbase comparison is not yet measured. The current stress-profile proxy favors OpenDR FSM on bind latency and storage footprint, and the tuned concurrent-bind proxy confirms 128 same-IP bind clients, but issue `#74` must be completed before treating the result as a 10M production readiness benchmark.

## Interpretation

- `#53`, `#54`, and `#55` remain valid as the legacy-runtime read-path remediation baseline.
- The latest FSM runtime work makes FSM the stronger OpenDJ comparison point for the benchmark mix.
- The next OpenDJ-relative investigation should focus on the FSM modify path at `heavy` and `stress` profiles.
- The index profile should stay in the Docker regression matrix, but it is still a bounded 1,000-user profile. Future index work should scale the preloaded cardinality, add schema-aware ordering cases if needed, and keep OpenDR/OpenDJ index settings aligned before comparing latency.
- The next login-scale investigation should turn the concurrent-bind probe into a production-scale run: 10M+ generated users, tuned connection limits, multiple client source IPs, auth-cache telemetry, wrong-password/unknown-DN traffic, and p50/p95/p99 latency plus failure-rate thresholds.
- The next OpenDR-runtime-parity investigation should focus on deeper FSM search representation/backend streaming work so FSM avoids preloaded `DirectoryEntry -> SearchEntry` materialization for full-result subtree searches.

## Artifacts

- Accepted baseline summary: `target/perf/docker-matrix-issue52-batched/comparison-summary.md`
- Legacy runtime remediation summary: `target/perf/docker-matrix-issue55-nodelay-full/comparison-summary.md`
- Legacy runtime remediation CSV: `target/perf/docker-matrix-issue55-nodelay-full/comparison-summary.csv`
- FSM runtime current summary: `target/perf/docker-matrix-fsm-auth-cache-final-full-20260411/comparison-summary.md`
- FSM runtime current CSV: `target/perf/docker-matrix-fsm-auth-cache-final-full-20260411/comparison-summary.csv`
- OpenDJ current summary: `target/perf/docker-matrix-opendj-current-full-20260411/comparison-summary.md`
- OpenDJ current CSV: `target/perf/docker-matrix-opendj-current-full-20260411/comparison-summary.csv`
- Concurrent bind tuned OpenDR summary: `target/perf/docker-matrix-concurrent-bind-fsm-opendr-config-128-20260411/comparison-summary.md`
- Concurrent bind tuned OpenDR CSV: `target/perf/docker-matrix-concurrent-bind-fsm-opendr-config-128-20260411/comparison-summary.csv`
- Concurrent bind OpenDJ comparison summary: `target/perf/docker-matrix-concurrent-bind-fsm-opendj-isolated-20260411/comparison-summary.md`
- Concurrent bind OpenDJ comparison CSV: `target/perf/docker-matrix-concurrent-bind-fsm-opendj-isolated-20260411/comparison-summary.csv`
- Index type comparison summary: `target/perf/docker-matrix-index-types-final-20260412/comparison-summary.md`
- Index type comparison CSV: `target/perf/docker-matrix-index-types-final-20260412/comparison-summary.csv`
- FSM stress report: `target/perf/docker-matrix-fsm-auth-cache-final-full-20260411/opendr/stress/report.md`
- OpenDJ stress report: `target/perf/docker-matrix-opendj-current-full-20260411/opendj/stress/report.md`
- OpenDR FSM index report: `target/perf/docker-matrix-index-types-final-20260412/opendr/index/report.md`
- OpenDJ index report: `target/perf/docker-matrix-index-types-final-20260412/opendj/index/report.md`
- OpenDR FSM tuned concurrent bind report: `target/perf/docker-matrix-concurrent-bind-fsm-opendr-config-128-20260411/opendr/auth-concurrency/report.md`
- OpenDR FSM concurrent bind report: `target/perf/docker-matrix-concurrent-bind-fsm-opendj-isolated-20260411/opendr/auth-concurrency/report.md`
- OpenDJ concurrent bind report: `target/perf/docker-matrix-concurrent-bind-fsm-opendj-isolated-20260411/opendj/auth-concurrency/report.md`
- 10M+ benchmark tracking issue: `https://github.com/keaz/opendr/issues/74`

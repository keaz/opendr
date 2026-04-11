# Docker LDAP Performance Comparison

This document captures the validated Dockerized LDAP benchmark results for OpenDR and OpenDJ. It now separates the older OpenDR legacy-runtime run from the newer OpenDR FSM-runtime run so runtime-to-runtime comparisons are explicit.

## Scope

- OpenDR was built from the local `Dockerfile` and configured to use the `lmdb` backend.
- OpenDJ was run from `openidentityplatform/opendj:5.0.4`.
- Both servers were capped at `2` CPU cores and `4 GiB` memory with Docker resource limits.
- StartTLS was enabled for both products.
- The accepted pre-remediation reference baseline remains `target/perf/docker-matrix-issue52-batched/`.
- The legacy runtime remediation run is `target/perf/docker-matrix-issue55-nodelay-full/`.
- The latest FSM runtime run is `target/perf/docker-matrix-fsm-arc-filter-projection-full-20260411/`.
- The latest OpenDJ comparison run is `target/perf/docker-matrix-opendj-current-full-20260411/`.

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
  --output-dir target/perf/docker-matrix-fsm-arc-filter-projection-full-20260411
```

OpenDJ current comparison run:

```bash
./scripts/perf_docker_matrix.sh \
  --profile-set full \
  --products opendj \
  --perf-client-image opendr:docker-perf-client \
  --output-dir target/perf/docker-matrix-opendj-current-full-20260411
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

## Load Profiles

| Profile | Preloaded users | Read iterations | Write iterations | Warmup iterations |
|---|---:|---:|---:|---:|
| light | 100 | 50 | 25 | 5 |
| moderate | 500 | 10 | 10 | 2 |
| heavy | 1000 | 5 | 5 | 2 |
| stress | 2500 | 3 | 3 | 1 |

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
| OpenDR FSM | light | success | 305.360 | 109 | 10.74 | 2.87 MiB | 668.00 KiB | 0.860 | 0.464 | 0.383 | 0.486 | 0.408 | 0.406 |
| OpenDJ | light | success | 812.928 | 105 | 153.56 | 805.90 MiB | 1.08 MiB | 3.838 | 1.333 | 0.466 | 0.842 | 1.156 | 0.610 |
| OpenDR FSM | moderate | success | 458.915 | 509 | 10.25 | 4.28 MiB | 2.04 MiB | 3.503 | 0.511 | 0.441 | 0.522 | 0.448 | 0.458 |
| OpenDJ | moderate | success | 1133.903 | 505 | 193.31 | 805.40 MiB | 9.14 MiB | 14.073 | 0.920 | 0.487 | 0.978 | 1.519 | 0.760 |
| OpenDR FSM | heavy | success | 694.704 | 1009 | 21.04 | 5.78 MiB | 3.03 MiB | 6.353 | 0.548 | 0.516 | 0.590 | 0.481 | 0.522 |
| OpenDJ | heavy | success | 1755.398 | 1005 | 92.42 | 829.40 MiB | 29.14 MiB | 25.052 | 1.200 | 0.365 | 1.242 | 2.895 | 0.754 |
| OpenDR FSM | stress | success | 1595.992 | 2509 | 22.21 | 2.44 MiB | 7.03 MiB | 16.500 | 0.657 | 0.538 | 0.655 | 0.537 | 0.567 |
| OpenDJ | stress | success | 4232.527 | 2505 | 135.60 | 835.30 MiB | 176.89 MiB | 47.034 | 1.836 | 0.420 | 1.768 | 3.204 | 0.929 |

## FSM Versus OpenDJ

| Area | Light | Moderate | Heavy | Stress | Direction |
|---|---:|---:|---:|---:|---|
| Total runtime | 305.360 vs 812.928 | 458.915 vs 1133.903 | 694.704 vs 1755.398 | 1595.992 vs 4232.527 | FSM faster |
| Root DSE mean ms | 0.106 vs 0.563 | 0.104 vs 0.546 | 0.106 vs 0.460 | 0.114 vs 0.618 | FSM faster |
| Bind admin mean ms | 0.090 vs 0.327 | 0.091 vs 0.281 | 0.090 vs 0.249 | 0.096 vs 0.309 | FSM faster |
| Subtree search mean ms | 0.860 vs 3.838 | 3.503 vs 14.073 | 6.353 vs 25.052 | 16.500 vs 47.034 | FSM faster |
| Add mean ms | 0.464 vs 1.333 | 0.511 vs 0.920 | 0.548 vs 1.200 | 0.657 vs 1.836 | FSM faster |
| Modify mean ms | 0.383 vs 0.466 | 0.441 vs 0.487 | 0.516 vs 0.365 | 0.538 vs 0.420 | OpenDJ faster on heavy and stress |
| ModifyDN mean ms | 0.486 vs 0.842 | 0.522 vs 0.978 | 0.590 vs 1.242 | 0.655 vs 1.768 | FSM faster |
| Delete mean ms | 0.408 vs 1.156 | 0.448 vs 1.519 | 0.481 vs 2.895 | 0.537 vs 3.204 | FSM faster |
| Password modify mean ms | 0.406 vs 0.610 | 0.458 vs 0.760 | 0.522 vs 0.754 | 0.567 vs 0.929 | FSM faster |

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
- The only OpenDJ-relative regression in the latest FSM run is `modify` at larger profiles: `heavy` is `0.516 ms` for FSM vs `0.365 ms` for OpenDJ, and `stress` is `0.538 ms` for FSM vs `0.420 ms` for OpenDJ.
- The remaining FSM search optimization target is no longer OpenDJ parity. It is OpenDR legacy-runtime parity: the latest FSM subtree search is still slower than the current OpenDR legacy baseline in the server-network harness.
- The dominant earlier legacy-runtime bottleneck was not LMDB lookup cost. It was response-path latency on small LDAP search replies. Enabling `TCP_NODELAY` removed that bottleneck immediately.

## Interpretation

- `#53`, `#54`, and `#55` remain valid as the legacy-runtime read-path remediation baseline.
- The latest FSM runtime work makes FSM the stronger OpenDJ comparison point for the benchmark mix.
- The next OpenDJ-relative investigation should focus on the FSM modify path at `heavy` and `stress` profiles.
- The next OpenDR-runtime-parity investigation should focus on deeper FSM search representation/backend streaming work so FSM avoids preloaded `DirectoryEntry -> SearchEntry` materialization for full-result subtree searches.

## Artifacts

- Accepted baseline summary: `target/perf/docker-matrix-issue52-batched/comparison-summary.md`
- Legacy runtime remediation summary: `target/perf/docker-matrix-issue55-nodelay-full/comparison-summary.md`
- Legacy runtime remediation CSV: `target/perf/docker-matrix-issue55-nodelay-full/comparison-summary.csv`
- FSM runtime current summary: `target/perf/docker-matrix-fsm-arc-filter-projection-full-20260411/comparison-summary.md`
- FSM runtime current CSV: `target/perf/docker-matrix-fsm-arc-filter-projection-full-20260411/comparison-summary.csv`
- OpenDJ current summary: `target/perf/docker-matrix-opendj-current-full-20260411/comparison-summary.md`
- OpenDJ current CSV: `target/perf/docker-matrix-opendj-current-full-20260411/comparison-summary.csv`
- FSM stress report: `target/perf/docker-matrix-fsm-arc-filter-projection-full-20260411/opendr/stress/report.md`
- OpenDJ stress report: `target/perf/docker-matrix-opendj-current-full-20260411/opendj/stress/report.md`

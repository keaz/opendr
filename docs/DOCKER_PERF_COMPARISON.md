# Docker LDAP Performance Comparison

This document captures the validated Dockerized benchmark run executed on 2026-04-10 after the read-path remediation work for issues `#53`, `#54`, and `#55`.

## Scope

- OpenDR was built from the local `Dockerfile` and configured to use the `lmdb` backend.
- OpenDJ was run from `openidentityplatform/opendj:5.0.4`.
- Both servers were benchmarked with the same client: `target/release/ldap_perf_client`.
- Both servers were capped at `2` CPU cores and `4 GiB` memory with Docker resource limits.
- StartTLS was enabled for both products so the same bind/search/compare/modify/password-modify/add/modifyDN/delete flow could be exercised.
- The accepted reference baseline remains `target/perf/docker-matrix-issue52-batched/`.
- The validated remediation run is `target/perf/docker-matrix-issue55-nodelay-full/`.

Reproduction command:

```bash
DOCKER_BUILDKIT=1 ./scripts/perf_docker_matrix.sh \
  --profile-set full \
  --output-dir target/perf/docker-matrix-issue55-nodelay-full
```

## What Changed

- `#53`: retained the bounded exact-DN LMDB entry cache with lazy refill on reads and invalidation on writes.
- `#54`: added the exact-DN base-object server fast path so base searches no longer fall back to the generic candidate scan path.
- `#55`: enabled `TCP_NODELAY` on accepted LDAP and LDAPS sockets. This removed the dominant small-response latency penalty on single-entry search responses.

The decisive improvement came from `#55`. Before `TCP_NODELAY`, Root DSE and base-object searches consistently measured around `45-47 ms`, which matched delayed-ACK/Nagle behavior rather than backend lookup cost. After the socket change, those operations dropped to sub-millisecond latency.

## Load Profiles

| Profile | Preloaded users | Read iterations | Write iterations | Warmup iterations |
|---|---:|---:|---:|---:|
| light | 100 | 50 | 25 | 5 |
| moderate | 500 | 10 | 10 | 2 |
| heavy | 1000 | 5 | 5 | 2 |
| stress | 2500 | 3 | 3 | 1 |

## Validated Results

| Product | Profile | Status | Total runtime ms | Records after setup | Avg CPU % | Avg memory | DB after | Subtree search mean ms | Add mean ms | Modify mean ms | Delete mean ms |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| OpenDR | light | success | 385.351 | 109 | 10.75 | 4.02 MiB | 668.00 KiB | 1.094 | 0.561 | 0.746 | 0.538 |
| OpenDJ | light | success | 965.819 | 105 | 184.21 | 815.20 MiB | 1.08 MiB | 5.024 | 1.122 | 0.574 | 1.172 |
| OpenDR | moderate | success | 518.151 | 509 | 10.69 | 4.17 MiB | 2.03 MiB | 4.384 | 0.655 | 0.615 | 0.625 |
| OpenDJ | moderate | success | 1296.574 | 505 | 200.45 | 804.80 MiB | 9.14 MiB | 22.638 | 1.313 | 0.524 | 1.675 |
| OpenDR | heavy | success | 858.713 | 1009 | 5.68 | 5.05 MiB | 3.03 MiB | 6.597 | 0.715 | 0.638 | 0.640 |
| OpenDJ | heavy | success | 1891.080 | 1005 | 99.39 | 976.85 MiB | 29.14 MiB | 35.390 | 1.323 | 0.518 | 2.111 |
| OpenDR | stress | success | 1978.444 | 2509 | 7.92 | 6.17 MiB | 7.04 MiB | 13.317 | 0.776 | 0.647 | 0.641 |
| OpenDJ | stress | success | 4913.137 | 2505 | 122.38 | 413.60 MiB | 176.95 MiB | 78.640 | 1.911 | 0.499 | 4.381 |

## Improvement Versus Accepted Baseline

These deltas compare OpenDR in `target/perf/docker-matrix-issue55-nodelay-full/` against the accepted `target/perf/docker-matrix-issue52-batched/` baseline.

| Profile | Total runtime delta | Root DSE delta | Subtree search delta | Add delta | Modify delta | Delete delta |
|---|---:|---:|---:|---:|---:|---:|
| light | `-95.10%` | `-99.39%` | `-97.60%` | `-3.28%` | `+50.40%` | `+1.13%` |
| moderate | `-77.21%` | `-99.09%` | `-91.27%` | `-32.54%` | `-26.17%` | `-22.65%` |
| heavy | `-54.11%` | `-99.39%` | `-88.04%` | `-10.74%` | `-12.48%` | `-10.36%` |
| stress | `-24.22%` | `-99.40%` | `-75.32%` | `-8.06%` | `-2.27%` | `+0.79%` |

Notes:

- The one consistent residual regression is `modify` on the light profile.
- `delete` on the stress profile is effectively flat relative to the accepted baseline.
- Every profile now completed successfully, and the earlier single-entry search latency cliff is gone.

## Key Findings

- OpenDR is now faster than OpenDJ on subtree search across every validated load profile.
- OpenDR remains dramatically smaller in memory and on-disk footprint. At stress load it averaged `6.17 MiB` RSS with a `7.04 MiB` LMDB footprint, while OpenDJ averaged `413.60 MiB` RSS with a `176.95 MiB` database footprint.
- OpenDR remains clearly stronger on `add` and `delete`.
- OpenDJ still has the better `modify` latency in this benchmark mix.
- The dominant prior bottleneck was not LMDB lookup cost. It was response-path latency on small LDAP search replies. Enabling `TCP_NODELAY` removed that bottleneck immediately.

## Interpretation

- `#53`, `#54`, and `#55` are acceptable together because the combined branch now materially outperforms the accepted baseline and OpenDJ on read-heavy search workloads.
- The next performance investigation should focus on the remaining `modify` gap, especially the light-profile regression relative to the accepted baseline.

## Artifacts

- Accepted baseline summary: `target/perf/docker-matrix-issue52-batched/comparison-summary.md`
- Validated remediation summary: `target/perf/docker-matrix-issue55-nodelay-full/comparison-summary.md`
- Validated remediation CSV: `target/perf/docker-matrix-issue55-nodelay-full/comparison-summary.csv`
- OpenDR light report: `target/perf/docker-matrix-issue55-nodelay-full/opendr/light/report.md`
- OpenDR stress report: `target/perf/docker-matrix-issue55-nodelay-full/opendr/stress/report.md`
- OpenDJ stress report: `target/perf/docker-matrix-issue55-nodelay-full/opendj/stress/report.md`

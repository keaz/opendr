# Docker LDAP Performance Comparison

This document records the current Dockerized OpenDR and OpenDJ benchmark results after the Rust 2024 edition and dependency refresh. The runs use the local OpenDR Docker image built from this repository and OpenDJ `openidentityplatform/opendj:5.0.4`.

## Scope

- OpenDR was built from the local `Dockerfile` with `rust:1.94-bookworm` and configured for the `fsm` runtime with the LMDB backend.
- OpenDJ was run from `openidentityplatform/opendj:5.0.4`.
- Both servers were capped at `2` CPU cores and `4 GiB` memory.
- StartTLS was enabled for both products.
- The current OpenDR full-profile run used the host `target/release/ldap_perf_client`. The current OpenDR index run used `docker:opendr:docker-perf-client`. The current simple-bind concurrency and SASL rows use the latest clean release-local OpenDR artifacts. OpenDJ comparison rows remain from the earlier Docker comparison artifacts listed below.
- The measured profiles are bounded Docker regression profiles, not a 10M-user production benchmark.
- OpenDJ timed out in the index profile, including the 600 second rerun. Those rows are recorded as incomplete rather than estimated.

## Reproduction

Release CD runs the OpenDR Docker perf regression gate with the full,
simple-bind concurrency, index, and SASL PLAIN concurrency profiles. The gate
uses `scripts/validate_docker_perf_baseline.py` to compare the generated
`comparison-summary.csv` files against the OpenDR baseline values in this
document and fails when a lower-is-better latency/failure metric regresses by
more than 10%, or a higher-is-better throughput/capacity metric drops by more
than 10%.

Full latency run:

```bash
./scripts/perf_docker_matrix.sh \
  --profile-set full \
  --products opendr \
  --opendr-runtime fsm \
  --benchmark-timeout 240 \
  --output-dir target/perf/release-local-full-after-index-key-streaming-20260413-222254
```

Simple-bind concurrency run:

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
  --output-dir target/perf/release-local-after-perf-optimization-final-20260413-221126/concurrency
```

Index search run:

```bash
./scripts/perf_docker_matrix.sh \
  --profile-set index \
  --products opendr \
  --opendr-runtime fsm \
  --benchmark-timeout 240 \
  --concurrent-index-search-clients 1,4,8,16,32 \
  --concurrent-index-search-iterations 20 \
  --concurrent-index-search-warmup-iterations 1 \
  --concurrent-index-search-operation-timeout-ms 5000 \
  --perf-client-image opendr:docker-perf-client \
  --output-dir target/perf/release-local-index-after-index-key-streaming-20260413-222254
```

OpenDJ index timeout confirmation:

```bash
./scripts/perf_docker_matrix.sh \
  --profile-set index \
  --products opendj \
  --opendr-runtime fsm \
  --benchmark-timeout 600 \
  --concurrent-index-search-clients 1,4,8,16,32 \
  --concurrent-index-search-iterations 20 \
  --concurrent-index-search-warmup-iterations 1 \
  --concurrent-index-search-operation-timeout-ms 5000 \
  --perf-client-image opendr:docker-perf-client \
  --output-dir target/perf/docker-matrix-edition2024-index-opendj-600-20260413
```

SASL PLAIN concurrency run:

```bash
./scripts/perf_docker_matrix.sh \
  --profile-set sasl \
  --products opendr \
  --opendr-runtime fsm \
  --benchmark-timeout 240 \
  --concurrent-bind-clients 1,4,8,16,32,64,128 \
  --concurrent-bind-iterations 20 \
  --concurrent-bind-warmup-iterations 1 \
  --concurrent-bind-operation-timeout-ms 5000 \
  --sasl-plain-authcid-format rdn-value \
  --skip-sasl-plain-admin-benchmark \
  --perf-client-image opendr:docker-perf-client \
  --output-dir target/perf/release-local-after-perf-optimization-final-20260413-221126/sasl
```

## Load Profiles

| Profile | Preloaded users | Read iterations | Write iterations | Warmup iterations |
|---|---:|---:|---:|---:|
| light | 100 | 50 | 25 | 5 |
| moderate | 500 | 10 | 10 | 2 |
| heavy | 1000 | 5 | 5 | 2 |
| stress | 2500 | 3 | 3 | 1 |
| auth-concurrency | 2500 | 3 | 3 | 1 |
| index | 1000 | 30 | 10 | 1 |
| sasl-auth | 2500 | 3 | 3 | 1 |

## Full Profile Results

The OpenDR rows are from `target/perf/release-local-full-after-index-key-streaming-20260413-222254/`. This run uses the host `target/release/ldap_perf_client` and records the OpenDR tuning in `run-metadata.json`: `opendr_lmdb_max_readers = 256`, `opendr_max_connections = 512`, `opendr_max_connections_per_ip = 256`, and `opendr_max_operations_per_connection = 200`. The OpenDJ rows are retained from `target/perf/docker-matrix-edition2024-full-tuned-hostclient-20260413/`.

| Product / runtime | Profile | Status | Total runtime ms | Records after setup | Avg CPU % | Avg memory | DB after | Subtree search mean ms | Simple bind mean ms | Add mean ms | Modify mean ms | Delete mean ms | Password modify mean ms |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| OpenDR FSM | light | success | 394.921 | 109 | 11.38 | 3.95 MiB | 796.00 KiB | 0.855 | 0.239 | 0.810 | 0.510 | 0.698 | 0.443 |
| OpenDJ | light | success | 1026.660 | 105 | 187.00 | 955.90 MiB | 1.14 MiB | 6.050 | 0.548 | 1.145 | 0.556 | 1.258 | 0.798 |
| OpenDR FSM | moderate | success | 564.359 | 509 | 13.30 | 5.43 MiB | 2.04 MiB | 2.939 | 0.202 | 0.936 | 0.550 | 0.822 | 0.468 |
| OpenDJ | moderate | success | 1359.839 | 505 | 102.19 | 813.30 MiB | 10.14 MiB | 22.300 | 0.943 | 1.190 | 0.591 | 1.916 | 0.842 |
| OpenDR FSM | heavy | success | 999.223 | 1009 | 23.53 | 8.12 MiB | 4.03 MiB | 4.861 | 0.270 | 1.145 | 0.501 | 0.929 | 0.526 |
| OpenDJ | heavy | success | 2019.819 | 1005 | 101.55 | 804.90 MiB | 31.14 MiB | 38.378 | 0.385 | 1.436 | 0.526 | 2.212 | 0.881 |
| OpenDR FSM | stress | success | 2361.422 | 2509 | 16.18 | 6.35 MiB | 9.03 MiB | 12.605 | 0.256 | 0.909 | 0.403 | 0.678 | 0.452 |
| OpenDJ | stress | success | 4982.452 | 2505 | 118.31 | 849.00 MiB | 176.37 MiB | 84.331 | 0.445 | 2.121 | 0.525 | 4.083 | 1.189 |

OpenDR FSM was faster on every listed full-profile latency metric in these rows, while also using substantially less memory and disk.

## Simple Bind Concurrency

The dedicated OpenDR simple-bind concurrency run is `target/perf/release-local-after-perf-optimization-final-20260413-221126/concurrency/`. It uses the same explicit OpenDR tuning as the full run and the host `target/release/ldap_perf_client` benchmark client. The OpenDJ row is retained from `target/perf/docker-matrix-edition2024-concurrent-bind-tuned-hostclient-20260413/`.

| Product / runtime | Profile | Status | Timeout budget | Max tested clients | Max 0% failure clients | Failure rate at max tested | Peak success ops/s | CPU avg / max | Memory avg / max |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| OpenDR FSM | auth-concurrency | success | 240s | 128 | 128 | 0.00% | 53,486.97 | 36.52% / 54.86% | 11.51 MiB / 20.07 MiB |
| OpenDJ | auth-concurrency | success | 240s | 128 | 128 | 0.00% | 6,525.77 | 138.43% / 200.23% | 497.02 MiB / 805.50 MiB |

OpenDR simple-bind per-level results:

| Clients | Successes / attempts | Failure % | Success ops/s | Mean ms | P95 ms | P99 ms |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 20 / 20 | 0.00 | 4,112.65 | 0.239 | 0.256 | 0.264 |
| 4 | 80 / 80 | 0.00 | 11,610.89 | 0.339 | 0.369 | 1.198 |
| 8 | 160 / 160 | 0.00 | 15,012.14 | 0.528 | 1.206 | 1.496 |
| 10 | 200 / 200 | 0.00 | 19,262.10 | 0.495 | 1.142 | 1.345 |
| 12 | 240 / 240 | 0.00 | 17,552.95 | 0.637 | 1.607 | 1.831 |
| 16 | 320 / 320 | 0.00 | 21,062.62 | 0.640 | 1.272 | 1.426 |
| 32 | 640 / 640 | 0.00 | 35,698.52 | 0.808 | 1.564 | 1.808 |
| 64 | 1280 / 1280 | 0.00 | 47,366.69 | 1.203 | 1.802 | 2.233 |
| 128 | 2560 / 2560 | 0.00 | 53,486.97 | 2.057 | 3.638 | 4.025 |

## SASL PLAIN Results

OpenDJ accepts fixture-user SASL PLAIN binds when the SASL `authcid` is the fixture user's RDN value. The admin SASL probe is skipped for the OpenDR-vs-OpenDJ comparison because OpenDJ rejects the directory-manager/admin SASL PLAIN probe with invalid credentials in this harness.

Serial fixture-user SASL PLAIN bind latency from `target/perf/docker-matrix-edition2024-full-sasl-20260413-r2/`:

| Product / runtime | Light mean ms | Moderate mean ms | Heavy mean ms | Stress mean ms |
|---|---:|---:|---:|---:|
| OpenDR FSM | 0.061 | 0.064 | 0.062 | 0.063 |
| OpenDJ | 0.409 | 0.500 | 0.353 | 0.404 |

SASL PLAIN concurrent-bind summary from `target/perf/release-local-after-perf-optimization-final-20260413-221126/sasl/` for OpenDR. The OpenDJ row is retained from `target/perf/docker-matrix-edition2024-sasl-concurrency-20260413/`:

| Product / runtime | Max tested clients | Max 0% failure clients | Failure rate at max tested | Peak SASL success ops/s | Fixture-user mean ms | CPU avg / max | Memory avg / max |
|---|---:|---:|---:|---:|---:|---:|---:|
| OpenDR FSM | 128 | 128 | 0.00% | 179,621.80 | 0.070 | 3.80% / 31.00% | 11.26 MiB / 18.69 MiB |
| OpenDJ | 128 | 128 | 0.00% | 10,222.17 | 0.247 | 34.59% / 180.76% | 1020.59 MiB / 1.10 GiB |

Per-level concurrent SASL PLAIN fixture-user bind results:

| Product / runtime | Clients | Successes / attempts | Failure % | Success ops/s | Mean ms | P95 ms | P99 ms |
|---|---:|---:|---:|---:|---:|---:|---:|
| OpenDR FSM | 1 | 20 / 20 | 0.00 | 18,219.08 | 0.051 | 0.057 | 0.059 |
| OpenDR FSM | 4 | 80 / 80 | 0.00 | 59,642.12 | 0.061 | 0.084 | 0.115 |
| OpenDR FSM | 8 | 160 / 160 | 0.00 | 118,959.11 | 0.056 | 0.097 | 0.113 |
| OpenDR FSM | 16 | 320 / 320 | 0.00 | 173,316.51 | 0.074 | 0.124 | 0.191 |
| OpenDR FSM | 32 | 640 / 640 | 0.00 | 179,621.80 | 0.148 | 0.225 | 0.335 |
| OpenDR FSM | 64 | 1280 / 1280 | 0.00 | 157,515.04 | 0.335 | 0.616 | 1.035 |
| OpenDR FSM | 128 | 2560 / 2560 | 0.00 | 156,911.22 | 0.705 | 0.904 | 2.164 |
| OpenDJ | 1 | 20 / 20 | 0.00 | 3,751.11 | 0.263 | 0.358 | 0.446 |
| OpenDJ | 4 | 80 / 80 | 0.00 | 10,222.17 | 0.384 | 0.491 | 0.590 |
| OpenDJ | 8 | 160 / 160 | 0.00 | 3,330.12 | 2.345 | 1.158 | 38.906 |
| OpenDJ | 16 | 320 / 320 | 0.00 | 3,204.48 | 4.882 | 2.680 | 82.158 |
| OpenDJ | 32 | 640 / 640 | 0.00 | 5,114.10 | 6.029 | 7.167 | 87.953 |
| OpenDJ | 64 | 1280 / 1280 | 0.00 | 4,307.33 | 14.491 | 82.050 | 84.096 |
| OpenDJ | 128 | 2560 / 2560 | 0.00 | 4,306.59 | 29.230 | 90.648 | 98.056 |

The Docker-client `sasl-auth` run also completed simple-bind concurrency for OpenDR with client levels `1,4,8,16,32,64,128`. In that completed mixed profile, OpenDR peaked at `84,070.44` simple-bind successes/sec and reached 32 clients at 0% simple-bind failures. The dedicated tuned host-client simple-bind run above is the current 128-client capacity result.

## Index Type Results

The OpenDR index run is `target/perf/release-local-index-after-index-key-streaming-20260413-222254/`. OpenDR completed; OpenDJ timed out in the earlier comparison run at 240 seconds and again at 600 seconds in `target/perf/docker-matrix-edition2024-index-opendj-600-20260413/`.

The compared index mappings are:

| Search probe | OpenDR LMDB index | OpenDJ backend index |
|---|---|---|
| `(uid=<fixture user>)` | equality on `uid` from the default indexed attributes | equality on `uid` |
| `(mail=*)` | presence on `mail` from the default indexed attributes | presence on `mail` |
| `(description=*fixture user 000000*)` | typed substring index on `description` | substring on `description` |
| `(benchmarkOrder>=500)` | typed ordering index on the benchmark `benchmarkOrder` integer attribute | ordering on an equivalent benchmark integer attribute |
| `(benchmarkOrder<=500)` | typed ordering index on the benchmark `benchmarkOrder` integer attribute | ordering on an equivalent benchmark integer attribute |

Index-profile top line:

| Product / runtime | Profile | Status | Timeout budget | Total runtime ms | Records after setup | Avg CPU % | Avg memory | DB after | Subtree search mean ms | Add mean ms | Modify mean ms | Delete mean ms |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| OpenDR FSM | index | success | 240s | 10,281.588 | 1009 | 18.39 | 9.65 MiB | 9.05 MiB | 5.302 | 0.614 | 0.536 | 0.871 |
| OpenDJ | index | timeout | 240s | n/a | n/a | 15.28 | 824.23 MiB | 9.14 MiB | n/a | n/a | n/a | n/a |
| OpenDJ | index | timeout | 600s | n/a | n/a | 10.11 | 830.37 MiB | 9.14 MiB | n/a | n/a | n/a | n/a |

OpenDR indexed search latency:

| Search probe | Mean ms | P95 ms | P99 ms |
|---|---:|---:|---:|
| Equality `uid` | 0.090 | 0.106 | 0.106 |
| Presence `mail` | 6.305 | 6.917 | 7.070 |
| Substring `description` | 1.341 | 1.384 | 1.399 |
| Ordering `benchmarkOrder >=` | 3.394 | 3.445 | 3.502 |
| Ordering `benchmarkOrder <=` | 3.383 | 3.420 | 3.444 |

OpenDR mixed concurrent index-search results:

| Clients | Successes / attempts | Failure % | Success ops/s | Mean ms | P95 ms | P99 ms |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 20 / 20 | 0.00 | 346.29 | 2.875 | 6.375 | 6.548 |
| 4 | 80 / 80 | 0.00 | 793.13 | 4.701 | 9.324 | 12.089 |
| 8 | 160 / 160 | 0.00 | 816.26 | 9.453 | 18.129 | 22.536 |
| 16 | 320 / 320 | 0.00 | 830.96 | 18.300 | 32.324 | 39.131 |
| 32 | 640 / 640 | 0.00 | 837.94 | 36.318 | 64.665 | 73.285 |

## Criterion Benchmarks

`cargo bench` completed successfully after the edition and dependency update. Representative mean estimates from `target/criterion/*/new/estimates.json`:

| Benchmark | Mean |
|---|---:|
| `backend_reads/lmdb_backend_get_entry` | 664.93 ns |
| `backend_auth/lmdb_backend_authenticate` | 228.24 ns |
| `backend_search/mock_backend_search` | 523.90 us |
| `fsm_creation/connection_fsm` | 14.81 ns |
| `fsm_creation/auth_fsm` | 17.86 ns |
| `fsm_creation/ber_decoder_fsm` | 34.91 ns |
| `schema_creation/create_core_schema` | 5.17 us |
| `search_operations/search_all_users/1000` | 683.99 us |
| `memory_efficiency/entry_creation` | 297.35 ns |

## Key Findings

- The Rust 2024 Docker image update is required for this codebase because the edition migration and clippy fixes use stabilized let-chain syntax that the previous `rust:1.86-bookworm` image rejected.
- OpenDR FSM remains ahead of OpenDJ on the full-profile latency and footprint rows under this Docker harness.
- OpenDR SASL PLAIN fixture-user binds were faster than OpenDJ in every serial SASL row and reached about `17.57x` higher peak successful SASL PLAIN bind throughput in the `sasl-auth` profile.
- With `OPENDR_LMDB_MAX_READERS=256`, `OPENDR_MAX_CONNECTIONS=512`, `OPENDR_MAX_CONNECTIONS_PER_IP=256`, and `OPENDR_MAX_OPERATIONS_PER_CONNECTION=200`, OpenDR completed the dedicated simple-bind concurrency profile through 128 clients at 0% failure and peaked at `53,486.97` successful binds/sec.
- OpenDJ also completed the host-client simple-bind concurrency profile through 128 clients at 0% failure, peaking at `6,525.77` successful binds/sec.
- OpenDR completed the index profile and reached 0% failures through 32 mixed concurrent index-search clients, peaking at `837.94` successful mixed index searches/sec. OpenDJ did not produce complete benchmark JSON for the index profile at either 240 seconds or 600 seconds.
- There is still no completed 10M-user OpenDR-vs-OpenDJ benchmark artifact. The largest measured profile here is the 2,500-user `stress`/`sasl-auth` fixture set.

## Artifacts

- Full profile: `target/perf/release-local-full-after-index-key-streaming-20260413-222254/comparison-summary.md`
- Simple-bind concurrency profile: `target/perf/release-local-after-perf-optimization-final-20260413-221126/concurrency/comparison-summary.md`
- Index profile: `target/perf/release-local-index-after-index-key-streaming-20260413-222254/comparison-summary.md`
- OpenDJ 600s index timeout confirmation: `target/perf/docker-matrix-edition2024-index-opendj-600-20260413/comparison-summary.md`
- Serial SASL fixture-user bind artifact: `target/perf/docker-matrix-edition2024-full-sasl-20260413-r2/comparison-summary.md`
- SASL PLAIN concurrency profile: `target/perf/release-local-after-perf-optimization-final-20260413-221126/sasl/comparison-summary.md`
- Combined OpenDR baseline validation: `target/perf/release-local-after-index-key-streaming-20260413-222254/baseline-validation.md`
- OpenDR full-profile stress report: `target/perf/release-local-full-after-index-key-streaming-20260413-222254/opendr/stress/report.md`
- OpenDJ full-profile stress report: `target/perf/docker-matrix-edition2024-full-tuned-hostclient-20260413/opendj/stress/report.md`
- OpenDR simple-bind concurrency report: `target/perf/release-local-after-perf-optimization-final-20260413-221126/concurrency/opendr/auth-concurrency/report.md`
- OpenDJ simple-bind concurrency report: `target/perf/docker-matrix-edition2024-concurrent-bind-tuned-hostclient-20260413/opendj/auth-concurrency/report.md`
- OpenDR index report: `target/perf/release-local-index-after-index-key-streaming-20260413-222254/opendr/index/report.md`
- OpenDR SASL concurrency report: `target/perf/release-local-after-perf-optimization-final-20260413-221126/sasl/opendr/sasl-auth/report.md`
- OpenDJ SASL concurrency report: `target/perf/docker-matrix-edition2024-sasl-concurrency-20260413/opendj/sasl-auth/report.md`

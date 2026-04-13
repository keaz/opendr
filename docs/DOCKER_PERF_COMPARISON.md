# Docker LDAP Performance Comparison

This document records the current Dockerized OpenDR and OpenDJ benchmark results after the Rust 2024 edition and dependency refresh. The runs use the local OpenDR Docker image built from this repository and OpenDJ `openidentityplatform/opendj:5.0.4`.

## Scope

- OpenDR was built from the local `Dockerfile` with `rust:1.94-bookworm` and configured for the `fsm` runtime with the LMDB backend.
- OpenDJ was run from `openidentityplatform/opendj:5.0.4`.
- Both servers were capped at `2` CPU cores and `4 GiB` memory.
- StartTLS was enabled for both products.
- The current full-profile and simple-bind concurrency runs used the host `target/release/ldap_perf_client`. The SASL and index comparison artifacts below used `docker:opendr:docker-perf-client`.
- The measured profiles are bounded Docker regression profiles, not a 10M-user production benchmark.
- OpenDJ timed out in the index profile, including the 600 second rerun. Those rows are recorded as incomplete rather than estimated.

## Reproduction

Full latency run:

```bash
./scripts/perf_docker_matrix.sh \
  --profile-set full \
  --products opendr,opendj \
  --opendr-runtime fsm \
  --benchmark-timeout 240 \
  --output-dir target/perf/docker-matrix-edition2024-full-tuned-hostclient-20260413
```

Simple-bind concurrency run:

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
  --output-dir target/perf/docker-matrix-edition2024-concurrent-bind-tuned-hostclient-20260413
```

Index search run:

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
  --perf-client-image opendr:docker-perf-client \
  --output-dir target/perf/docker-matrix-edition2024-index-20260413
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
  --products opendr,opendj \
  --opendr-runtime fsm \
  --benchmark-timeout 240 \
  --concurrent-bind-clients 1,4,8,16,32,64,128 \
  --concurrent-bind-iterations 20 \
  --concurrent-bind-warmup-iterations 1 \
  --concurrent-bind-operation-timeout-ms 5000 \
  --sasl-plain-authcid-format rdn-value \
  --skip-sasl-plain-admin-benchmark \
  --perf-client-image opendr:docker-perf-client \
  --output-dir target/perf/docker-matrix-edition2024-sasl-concurrency-20260413
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

These results are from `target/perf/docker-matrix-edition2024-full-tuned-hostclient-20260413/`. This run uses the host `target/release/ldap_perf_client` and records the OpenDR tuning in `run-metadata.json`: `opendr_lmdb_max_readers = 256`, `opendr_max_connections = 512`, `opendr_max_connections_per_ip = 256`, and `opendr_max_operations_per_connection = 200`.

| Product / runtime | Profile | Status | Total runtime ms | Records after setup | Avg CPU % | Avg memory | DB after | Subtree search mean ms | Simple bind mean ms | Add mean ms | Modify mean ms | Delete mean ms | Password modify mean ms |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| OpenDR FSM | light | success | 403.261 | 109 | 0.00 | 4.06 MiB | 796.00 KiB | 1.138 | 0.291 | 0.744 | 0.611 | 0.657 | 0.598 |
| OpenDJ | light | success | 1026.660 | 105 | 187.00 | 955.90 MiB | 1.14 MiB | 6.050 | 0.548 | 1.145 | 0.556 | 1.258 | 0.798 |
| OpenDR FSM | moderate | success | 558.925 | 509 | 15.02 | 6.89 MiB | 2.03 MiB | 4.474 | 0.252 | 1.036 | 0.856 | 0.858 | 0.853 |
| OpenDJ | moderate | success | 1359.839 | 505 | 102.19 | 813.30 MiB | 10.14 MiB | 22.300 | 0.943 | 1.190 | 0.591 | 1.916 | 0.842 |
| OpenDR FSM | heavy | success | 955.953 | 1009 | 16.09 | 10.62 MiB | 4.03 MiB | 7.508 | 0.261 | 1.112 | 1.009 | 0.980 | 0.989 |
| OpenDJ | heavy | success | 2019.819 | 1005 | 101.55 | 804.90 MiB | 31.14 MiB | 38.378 | 0.385 | 1.436 | 0.526 | 2.212 | 0.881 |
| OpenDR FSM | stress | success | 2272.271 | 2509 | 16.06 | 11.48 MiB | 8.03 MiB | 15.799 | 0.282 | 1.032 | 0.998 | 0.858 | 1.089 |
| OpenDJ | stress | success | 4982.452 | 2505 | 118.31 | 849.00 MiB | 176.37 MiB | 84.331 | 0.445 | 2.121 | 0.525 | 4.083 | 1.189 |

OpenDR FSM was faster on total runtime, subtree search, simple bind, add, and delete in every full-profile row. OpenDJ remained faster on modify in every row and slightly faster on password modify in the moderate and heavy rows.

## Simple Bind Concurrency

The dedicated simple-bind concurrency run is `target/perf/docker-matrix-edition2024-concurrent-bind-tuned-hostclient-20260413/`. It uses the same explicit OpenDR tuning as the full run and the host `target/release/ldap_perf_client` benchmark client.

| Product / runtime | Profile | Status | Timeout budget | Max tested clients | Max 0% failure clients | Failure rate at max tested | Peak success ops/s | CPU avg / max | Memory avg / max |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| OpenDR FSM | auth-concurrency | success | 240s | 128 | 128 | 0.00% | 55,397.02 | 37.48% / 54.93% | 10.62 MiB / 18.30 MiB |
| OpenDJ | auth-concurrency | success | 240s | 128 | 128 | 0.00% | 6,525.77 | 138.43% / 200.23% | 497.02 MiB / 805.50 MiB |

OpenDR simple-bind per-level results:

| Clients | Successes / attempts | Failure % | Success ops/s | Mean ms | P95 ms | P99 ms |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 20 / 20 | 0.00 | 3,894.97 | 0.252 | 0.279 | 0.324 |
| 4 | 80 / 80 | 0.00 | 11,474.40 | 0.346 | 0.415 | 0.860 |
| 8 | 160 / 160 | 0.00 | 13,435.03 | 0.561 | 1.178 | 1.328 |
| 10 | 200 / 200 | 0.00 | 13,370.14 | 0.720 | 1.261 | 1.605 |
| 12 | 240 / 240 | 0.00 | 20,295.41 | 0.552 | 1.212 | 1.523 |
| 16 | 320 / 320 | 0.00 | 24,827.29 | 0.591 | 1.061 | 1.388 |
| 32 | 640 / 640 | 0.00 | 39,784.81 | 0.722 | 1.036 | 1.142 |
| 64 | 1280 / 1280 | 0.00 | 48,904.11 | 1.078 | 1.582 | 2.035 |
| 128 | 2560 / 2560 | 0.00 | 55,397.02 | 2.018 | 2.971 | 3.792 |

## SASL PLAIN Results

OpenDJ accepts fixture-user SASL PLAIN binds when the SASL `authcid` is the fixture user's RDN value. The admin SASL probe is skipped for the OpenDR-vs-OpenDJ comparison because OpenDJ rejects the directory-manager/admin SASL PLAIN probe with invalid credentials in this harness.

Serial fixture-user SASL PLAIN bind latency from `target/perf/docker-matrix-edition2024-full-sasl-20260413-r2/`:

| Product / runtime | Light mean ms | Moderate mean ms | Heavy mean ms | Stress mean ms |
|---|---:|---:|---:|---:|
| OpenDR FSM | 0.061 | 0.064 | 0.062 | 0.063 |
| OpenDJ | 0.409 | 0.500 | 0.353 | 0.404 |

SASL PLAIN concurrent-bind summary from `target/perf/docker-matrix-edition2024-sasl-concurrency-20260413/`:

| Product / runtime | Max tested clients | Max 0% failure clients | Failure rate at max tested | Peak SASL success ops/s | Fixture-user mean ms | CPU avg / max | Memory avg / max |
|---|---:|---:|---:|---:|---:|---:|---:|
| OpenDR FSM | 128 | 128 | 0.00% | 195,708.60 | 0.080 | 3.37% / 34.09% | 14.02 MiB / 18.23 MiB |
| OpenDJ | 128 | 128 | 0.00% | 10,222.17 | 0.247 | 34.59% / 180.76% | 1020.59 MiB / 1.10 GiB |

Per-level concurrent SASL PLAIN fixture-user bind results:

| Product / runtime | Clients | Successes / attempts | Failure % | Success ops/s | Mean ms | P95 ms | P99 ms |
|---|---:|---:|---:|---:|---:|---:|---:|
| OpenDR FSM | 1 | 20 / 20 | 0.00 | 18,687.22 | 0.050 | 0.057 | 0.062 |
| OpenDR FSM | 4 | 80 / 80 | 0.00 | 63,578.30 | 0.058 | 0.080 | 0.093 |
| OpenDR FSM | 8 | 160 / 160 | 0.00 | 124,416.80 | 0.049 | 0.081 | 0.165 |
| OpenDR FSM | 16 | 320 / 320 | 0.00 | 195,708.60 | 0.069 | 0.105 | 0.155 |
| OpenDR FSM | 32 | 640 / 640 | 0.00 | 187,191.54 | 0.138 | 0.205 | 0.326 |
| OpenDR FSM | 64 | 1280 / 1280 | 0.00 | 184,189.23 | 0.299 | 0.368 | 0.477 |
| OpenDR FSM | 128 | 2560 / 2560 | 0.00 | 158,421.57 | 0.687 | 0.984 | 2.189 |
| OpenDJ | 1 | 20 / 20 | 0.00 | 3,751.11 | 0.263 | 0.358 | 0.446 |
| OpenDJ | 4 | 80 / 80 | 0.00 | 10,222.17 | 0.384 | 0.491 | 0.590 |
| OpenDJ | 8 | 160 / 160 | 0.00 | 3,330.12 | 2.345 | 1.158 | 38.906 |
| OpenDJ | 16 | 320 / 320 | 0.00 | 3,204.48 | 4.882 | 2.680 | 82.158 |
| OpenDJ | 32 | 640 / 640 | 0.00 | 5,114.10 | 6.029 | 7.167 | 87.953 |
| OpenDJ | 64 | 1280 / 1280 | 0.00 | 4,307.33 | 14.491 | 82.050 | 84.096 |
| OpenDJ | 128 | 2560 / 2560 | 0.00 | 4,306.59 | 29.230 | 90.648 | 98.056 |

The Docker-client `sasl-auth` run also completed simple-bind concurrency for both products with client levels `1,4,8,16,32,64,128`. In that completed mixed profile, OpenDR peaked at `112,464.83` simple-bind successes/sec and OpenDJ peaked at `22,934.14` simple-bind successes/sec, with both products reaching 32 clients at 0% simple-bind failures. The dedicated tuned host-client simple-bind run above is the current 128-client capacity result.

## Index Type Results

The index run is `target/perf/docker-matrix-edition2024-index-20260413/`. OpenDR completed; OpenDJ timed out at 240 seconds and again at 600 seconds in `target/perf/docker-matrix-edition2024-index-opendj-600-20260413/`.

The compared index mappings are:

| Search probe | OpenDR LMDB index | OpenDJ backend index |
|---|---|---|
| `(uid=<fixture user>)` | equality on `uid` from the default indexed attributes | equality on `uid` |
| `(mail=*)` | presence on `mail` from the default indexed attributes | presence on `mail` |
| `(description=*fixture user 000000*)` | typed substring index on `description` | substring on `description` |
| `(sn>=BenchmarkUser000500)` | typed ordering index on `sn` | ordering on `sn` |
| `(sn<=BenchmarkUser000500)` | typed ordering index on `sn` | ordering on `sn` |

Index-profile top line:

| Product / runtime | Profile | Status | Timeout budget | Total runtime ms | Records after setup | Avg CPU % | Avg memory | DB after | Subtree search mean ms | Add mean ms | Modify mean ms | Delete mean ms |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| OpenDR FSM | index | success | 240s | 11,776.487 | 1009 | 32.65 | 10.16 MiB | 9.04 MiB | 6.076 | 0.662 | 0.920 | 0.923 |
| OpenDJ | index | timeout | 240s | n/a | n/a | 15.28 | 824.23 MiB | 9.14 MiB | n/a | n/a | n/a | n/a |
| OpenDJ | index | timeout | 600s | n/a | n/a | 10.11 | 830.37 MiB | 9.14 MiB | n/a | n/a | n/a | n/a |

OpenDR indexed search latency:

| Search probe | Mean ms | P95 ms | P99 ms |
|---|---:|---:|---:|
| Equality `uid` | 0.108 | 0.114 | 0.120 |
| Presence `mail` | 7.067 | 7.211 | 7.319 |
| Substring `description` | 3.900 | 3.953 | 3.957 |
| Ordering `sn >=` | 4.018 | 4.462 | 4.779 |
| Ordering `sn <=` | 3.977 | 4.014 | 4.061 |

OpenDR mixed concurrent index-search results:

| Clients | Successes / attempts | Failure % | Success ops/s | Mean ms | P95 ms | P99 ms |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 20 / 20 | 0.00 | 280.17 | 3.557 | 6.796 | 6.807 |
| 4 | 80 / 80 | 0.00 | 500.12 | 7.387 | 13.700 | 21.505 |
| 8 | 160 / 160 | 0.00 | 530.95 | 14.430 | 26.337 | 30.746 |
| 16 | 320 / 320 | 0.00 | 534.57 | 28.642 | 54.120 | 62.087 |
| 32 | 640 / 640 | 0.00 | 530.47 | 58.130 | 99.437 | 125.939 |

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
- OpenDJ remains faster on the full-profile modify operation in the moderate, heavy, and stress rows.
- OpenDR SASL PLAIN fixture-user binds were faster than OpenDJ in every serial SASL row and reached about `19.15x` higher peak successful SASL PLAIN bind throughput in the `sasl-auth` profile.
- With `OPENDR_LMDB_MAX_READERS=256`, `OPENDR_MAX_CONNECTIONS=512`, `OPENDR_MAX_CONNECTIONS_PER_IP=256`, and `OPENDR_MAX_OPERATIONS_PER_CONNECTION=200`, OpenDR completed the dedicated simple-bind concurrency profile through 128 clients at 0% failure and peaked at `55,397.02` successful binds/sec.
- OpenDJ also completed the host-client simple-bind concurrency profile through 128 clients at 0% failure, peaking at `6,525.77` successful binds/sec.
- OpenDR completed the index profile and reached 0% failures through 32 mixed concurrent index-search clients. OpenDJ did not produce complete benchmark JSON for the index profile at either 240 seconds or 600 seconds.
- There is still no completed 10M-user OpenDR-vs-OpenDJ benchmark artifact. The largest measured profile here is the 2,500-user `stress`/`sasl-auth` fixture set.

## Artifacts

- Full profile: `target/perf/docker-matrix-edition2024-full-tuned-hostclient-20260413/comparison-summary.md`
- Simple-bind concurrency profile: `target/perf/docker-matrix-edition2024-concurrent-bind-tuned-hostclient-20260413/comparison-summary.md`
- Index profile: `target/perf/docker-matrix-edition2024-index-20260413/comparison-summary.md`
- OpenDJ 600s index timeout confirmation: `target/perf/docker-matrix-edition2024-index-opendj-600-20260413/comparison-summary.md`
- Serial SASL fixture-user bind artifact: `target/perf/docker-matrix-edition2024-full-sasl-20260413-r2/comparison-summary.md`
- SASL PLAIN concurrency profile: `target/perf/docker-matrix-edition2024-sasl-concurrency-20260413/comparison-summary.md`
- OpenDR full-profile stress report: `target/perf/docker-matrix-edition2024-full-tuned-hostclient-20260413/opendr/stress/report.md`
- OpenDJ full-profile stress report: `target/perf/docker-matrix-edition2024-full-tuned-hostclient-20260413/opendj/stress/report.md`
- OpenDR simple-bind concurrency report: `target/perf/docker-matrix-edition2024-concurrent-bind-tuned-hostclient-20260413/opendr/auth-concurrency/report.md`
- OpenDJ simple-bind concurrency report: `target/perf/docker-matrix-edition2024-concurrent-bind-tuned-hostclient-20260413/opendj/auth-concurrency/report.md`
- OpenDR index report: `target/perf/docker-matrix-edition2024-index-20260413/opendr/index/report.md`
- OpenDR SASL concurrency report: `target/perf/docker-matrix-edition2024-sasl-concurrency-20260413/opendr/sasl-auth/report.md`
- OpenDJ SASL concurrency report: `target/perf/docker-matrix-edition2024-sasl-concurrency-20260413/opendj/sasl-auth/report.md`

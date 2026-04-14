# Docker LDAP Performance Comparison

This document records the current Dockerized OpenDR and OpenDJ benchmark baseline. The runs use the local OpenDR Docker image built from this repository and OpenDJ `openidentityplatform/opendj:5.0.4`.

## Scope

- OpenDR was built from the local `Dockerfile` with `rust:1.94-bookworm` and configured for the `fsm` runtime with the LMDB backend.
- OpenDJ was run from `openidentityplatform/opendj:5.0.4`.
- Both servers were capped at `2` CPU cores and `4 GiB` memory.
- StartTLS was enabled for both products.
- The current baseline rows are from the April 14, 2026 artifacts listed below.
- OpenDR used the Docker entrypoint default `performance.cache_size = 1000`, which currently sizes both the exact-DN entry cache and the authentication credential cache.
- Cache hit/miss metrics were not captured for these artifacts because the Docker perf harness disables the monitoring endpoint and samples container CPU/memory only.
- The 1M-user OpenDR run used a `16 GiB` LMDB map. The default `1 GiB` Docker map filled around 300k users.
- The 1M-user concurrency artifact covers simple-bind and SASL PLAIN auth concurrency. It does not include index-concurrency probes because the preserved 1M fixture was loaded without benchmark ordering attributes.
- There is still no completed 10M-user OpenDR-vs-OpenDJ benchmark artifact.

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
  --products opendr,opendj \
  --opendr-runtime fsm \
  --benchmark-timeout 240 \
  --output-dir target/perf/full-rerun-20260414-091948
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
  --output-dir target/perf/concurrency-coalesced-20260414-091023
```

Index search run:

```bash
./scripts/perf_docker_matrix.sh \
  --profile-set index \
  --products opendr,opendj \
  --opendr-runtime fsm \
  --benchmark-timeout 600 \
  --concurrent-index-search-clients 1,4,8,16,32 \
  --concurrent-index-search-iterations 20 \
  --concurrent-index-search-warmup-iterations 1 \
  --concurrent-index-search-operation-timeout-ms 5000 \
  --perf-client-image opendr:docker-perf-client \
  --output-dir target/perf/index-guarded-both-20260414-091425
```

SASL PLAIN concurrency run:

```bash
./scripts/perf_docker_matrix.sh \
  --profile-set sasl \
  --products opendr,opendj \
  --opendr-runtime fsm \
  --benchmark-timeout 600 \
  --concurrent-bind-clients 1,4,8,16,32,64,128 \
  --concurrent-bind-iterations 20 \
  --concurrent-bind-warmup-iterations 1 \
  --concurrent-bind-operation-timeout-ms 5000 \
  --sasl-plain-authcid-format rdn-value \
  --skip-sasl-plain-admin-benchmark \
  --perf-client-image opendr:docker-perf-client \
  --output-dir target/perf/sasl-guarded-20260414-090609
```

1M OpenDR preload run:

```bash
LDAP_PERF_PROGRESS=1 ./scripts/perf_docker_matrix.sh \
  --profile-set million \
  --products opendr \
  --opendr-runtime fsm \
  --opendr-lmdb-max-size 17179869184 \
  --benchmark-timeout 7200 \
  --sample-interval 5 \
  --perf-client-image opendr:docker-perf-client \
  --output-dir target/perf/opendr-million-16g-20260414-103048
```

The completed 1M serial and concurrency result artifacts reused that preserved fixture with `ldap_perf_client --reuse-fixture --skip-full-counts` after the client wrote benchmark JSON before best-effort unbind cleanup.

## Load Profiles

| Profile | Preloaded users | Read iterations | Write iterations | Warmup iterations |
|---|---:|---:|---:|---:|
| light | 100 | 50 | 25 | 5 |
| moderate | 500 | 10 | 10 | 2 |
| heavy | 1000 | 5 | 5 | 2 |
| stress | 2500 | 3 | 3 | 1 |
| auth-concurrency | 2500 | 3 | 3 | 1 |
| index | 1000 | 30 | 10 | 2 |
| sasl-auth | 2500 | 3 | 3 | 1 |
| million | 1000000 | 3 | 3 | 1 |

## Full Profile Results

Rows are from `target/perf/full-rerun-20260414-091948/`.

| Product / runtime | Profile | Status | Total runtime ms | Records after setup | Avg CPU % | Avg memory | DB after | Subtree search mean ms | Simple bind mean ms | Add mean ms | Modify mean ms | Delete mean ms | Password modify mean ms |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| OpenDR FSM | light | success | 371.562 | 109 | 9.33 | 3.34 MiB | 796.00 KiB | 0.592 | 0.080 | 0.688 | 0.293 | 0.634 | 0.299 |
| OpenDJ | light | success | 928.909 | 105 | 168.32 | 813.20 MiB | 1.14 MiB | 4.081 | 0.384 | 1.100 | 0.419 | 1.259 | 0.720 |
| OpenDR FSM | moderate | success | 541.610 | 509 | 13.96 | 4.09 MiB | 2.03 MiB | 2.538 | 0.075 | 0.639 | 0.301 | 0.608 | 0.311 |
| OpenDJ | moderate | success | 1,273.730 | 505 | 88.88 | 818.95 MiB | 10.14 MiB | 15.649 | 0.314 | 1.008 | 0.417 | 1.852 | 0.708 |
| OpenDR FSM | heavy | success | 876.780 | 1009 | 22.82 | 6.39 MiB | 4.04 MiB | 4.459 | 0.068 | 0.964 | 0.331 | 0.755 | 0.469 |
| OpenDJ | heavy | success | 1,781.491 | 1005 | 95.93 | 812.95 MiB | 31.14 MiB | 24.809 | 0.282 | 1.207 | 0.434 | 2.038 | 0.719 |
| OpenDR FSM | stress | success | 1,990.305 | 2509 | 13.88 | 7.72 MiB | 9.03 MiB | 10.488 | 0.109 | 0.949 | 0.322 | 0.914 | 0.471 |
| OpenDJ | stress | success | 4,399.629 | 2505 | 136.20 | 987.33 MiB | 176.27 MiB | 46.323 | 0.334 | 1.863 | 0.438 | 3.433 | 0.993 |

OpenDR FSM was faster on every listed full-profile latency metric in these rows, while also using substantially less memory and disk.

## Simple Bind Concurrency

Rows are from `target/perf/concurrency-coalesced-20260414-091023/`. Both products completed the guarded profile. The OpenDJ all-row peak happened in a high-failure row, so use the max 0% failure clients column when comparing sustained capacity.

| Product / runtime | Profile | Status | Timeout budget | Max tested clients | Max 0% failure clients | Failure rate at max tested | Peak success ops/s | CPU avg / max | Memory avg / max |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| OpenDR FSM | auth-concurrency | success | 240s | 128 | 32 | 72.656% | 45,826.68 | 2.39% / 24.30% | 10.02 MiB / 15.80 MiB |
| OpenDJ | auth-concurrency | success | 240s | 128 | 16 | 87.500% | 29,087.05 | 14.48% / 186.59% | 431.20 MiB / 802.10 MiB |

OpenDR simple-bind per-level results:

| Clients | Successes / attempts | Failure % | Success ops/s | Mean ms | P95 ms | P99 ms |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 20 / 20 | 0.00 | 13,873.23 | 0.064 | 0.073 | 0.075 |
| 4 | 80 / 80 | 0.00 | 45,826.68 | 0.065 | 0.152 | 0.254 |
| 8 | 160 / 160 | 0.00 | 20,506.36 | 0.319 | 0.656 | 0.761 |
| 10 | 200 / 200 | 0.00 | 17,869.24 | 0.511 | 0.674 | 0.798 |
| 12 | 240 / 240 | 0.00 | 17,527.20 | 0.627 | 0.948 | 1.063 |
| 16 | 320 / 320 | 0.00 | 17,060.87 | 0.870 | 1.345 | 1.538 |
| 32 | 640 / 640 | 0.00 | 18,276.40 | 1.619 | 2.010 | 2.867 |
| 64 | 840 / 1280 | 34.38 | 13,789.52 | 2.850 | 3.856 | 5.176 |
| 128 | 700 / 2560 | 72.66 | 15,635.99 | 2.081 | 3.035 | 3.899 |

## SASL PLAIN Results

Rows are from `target/perf/sasl-guarded-20260414-090609/`. OpenDJ accepts fixture-user SASL PLAIN binds when the SASL `authcid` is the fixture user's RDN value. The admin SASL probe is skipped for the OpenDR-vs-OpenDJ comparison because OpenDJ rejects the directory-manager/admin SASL PLAIN probe with invalid credentials in this harness.

| Product / runtime | Max tested clients | Max 0% failure clients | Failure rate at max tested | Peak SASL success ops/s | Fixture-user mean ms | CPU avg / max | Memory avg / max |
|---|---:|---:|---:|---:|---:|---:|---:|
| OpenDR FSM | 128 | 128 | 0.000% | 139,135.46 | 0.040 | 3.74% / 24.49% | 11.70 MiB / 19.34 MiB |
| OpenDJ | 128 | 128 | 0.000% | 16,600.31 | 0.226 | 13.71% / 201.01% | 425.41 MiB / 804.00 MiB |

Per-level concurrent SASL PLAIN fixture-user bind results:

| Product / runtime | Clients | Successes / attempts | Failure % | Success ops/s | Mean ms | P95 ms | P99 ms |
|---|---:|---:|---:|---:|---:|---:|---:|
| OpenDR FSM | 1 | 20 / 20 | 0.00 | 17,992.36 | 0.052 | 0.057 | 0.064 |
| OpenDR FSM | 4 | 80 / 80 | 0.00 | 78,508.34 | 0.046 | 0.076 | 0.086 |
| OpenDR FSM | 8 | 160 / 160 | 0.00 | 119,637.35 | 0.050 | 0.099 | 0.126 |
| OpenDR FSM | 16 | 320 / 320 | 0.00 | 139,135.46 | 0.092 | 0.137 | 0.222 |
| OpenDR FSM | 32 | 640 / 640 | 0.00 | 70,057.33 | 0.425 | 0.611 | 0.688 |
| OpenDR FSM | 64 | 1280 / 1280 | 0.00 | 87,448.62 | 0.652 | 0.834 | 1.306 |
| OpenDR FSM | 128 | 2560 / 2560 | 0.00 | 58,925.64 | 1.987 | 2.418 | 3.886 |
| OpenDJ | 1 | 20 / 20 | 0.00 | 2,874.68 | 0.344 | 0.426 | 0.514 |
| OpenDJ | 4 | 80 / 80 | 0.00 | 10,154.43 | 0.372 | 0.496 | 0.674 |
| OpenDJ | 8 | 160 / 160 | 0.00 | 16,600.31 | 0.448 | 0.693 | 0.751 |
| OpenDJ | 16 | 320 / 320 | 0.00 | 3,495.49 | 4.005 | 2.404 | 75.191 |
| OpenDJ | 32 | 640 / 640 | 0.00 | 3,315.29 | 8.710 | 80.709 | 82.397 |
| OpenDJ | 64 | 1280 / 1280 | 0.00 | 4,146.56 | 15.197 | 80.913 | 84.634 |
| OpenDJ | 128 | 2560 / 2560 | 0.00 | 4,456.78 | 27.506 | 83.667 | 86.681 |

## Index Type Results

Rows are from `target/perf/index-guarded-both-20260414-091425/`. Both products completed the scalar index probes. OpenDJ degraded at high mixed index-search concurrency; OpenDR stayed at 0% failures through 32 clients.

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
| OpenDR FSM | index | success | 240s | 9,486.183 | 1009 | 6.87 | 7.23 MiB | 9.05 MiB | 4.516 | 0.734 | 0.576 | 0.846 |
| OpenDJ | index | success | 240s | 252,324.714 | 1005 | 28.33 | 830.46 MiB | 16.14 MiB | 20.063 | 0.834 | 0.483 | 1.108 |

OpenDR indexed search latency:

| Search probe | Mean ms | P95 ms | P99 ms |
|---|---:|---:|---:|
| Equality `uid` | 0.103 | 0.110 | 0.111 |
| Presence `mail` | 5.944 | 6.067 | 6.090 |
| Substring `description` | 1.268 | 1.298 | 1.302 |
| Ordering `benchmarkOrder >=` | 3.187 | 3.241 | 3.280 |
| Ordering `benchmarkOrder <=` | 3.183 | 3.237 | 3.242 |

Scalar index comparison:

| Search probe | OpenDR mean ms | OpenDJ mean ms |
|---|---:|---:|
| Equality `uid` | 0.103 | 0.275 |
| Presence `mail` | 5.944 | 15.062 |
| Substring `description` | 1.268 | 4.228 |
| Ordering `benchmarkOrder >=` | 3.187 | 8.436 |
| Ordering `benchmarkOrder <=` | 3.183 | 8.548 |

OpenDR mixed concurrent index-search results:

| Clients | Successes / attempts | Failure % | Success ops/s | Mean ms | P95 ms | P99 ms |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 20 / 20 | 0.00 | 2,745.40 | 0.358 | 1.241 | 1.271 |
| 4 | 80 / 80 | 0.00 | 5,530.22 | 0.640 | 2.345 | 3.591 |
| 8 | 160 / 160 | 0.00 | 5,924.02 | 1.238 | 3.592 | 4.837 |
| 16 | 320 / 320 | 0.00 | 5,856.95 | 2.563 | 5.233 | 8.205 |
| 32 | 640 / 640 | 0.00 | 5,838.91 | 5.250 | 12.502 | 19.081 |

## 1M OpenDR Results

The 1M serial artifact is `target/perf/opendr-million-reuse-skipcounts-20260414-111120/opendr/million/`. It reused the preserved 1M fixture and skipped non-measured full-subtree setup/final count verification. The measured 1M subtree search still ran.

| Metric | Value |
|---|---:|
| Preloaded users | 1,000,000 |
| Records before setup | 1,000,005 |
| Records after setup | 1,000,005 |
| Records after benchmark | 1,000,005 |
| Total measured runtime | 41,194.111 ms |
| OpenDR cache size | 1,000 entries |
| LMDB data directory | 3.20 GiB |
| Sampled peak server memory | 3.63 GiB |
| Sampled peak server CPU | 97.18% |

1M serial operation results:

| Operation | Mean ms | P95 ms | Success ops/s | Failures |
|---|---:|---:|---:|---:|
| bind_admin | 0.255 | 0.275 | 3,926.92 | 0 |
| bind_fixture_user | 0.250 | 0.257 | 3,994.90 | 0 |
| search_base_fixture_user | 141.304 | 142.892 | 7.08 | 0 |
| search_subtree_fixture_users | 10,749.753 | 12,390.895 | 0.09 | 0 |
| compare_fixture_user_sn | 0.525 | 0.675 | 1,904.11 | 0 |
| password_modify_fixture_user | 0.665 | 1.095 | 1,503.13 | 0 |
| add_entries | 1.909 | 2.828 | 523.52 | 0 |
| modify_entries | 0.512 | 0.596 | 1,733.94 | 0 |
| modifydn_entries | 1.766 | 2.205 | 565.76 | 0 |
| delete_entries | 1.429 | 2.029 | 699.52 | 0 |

The 1M concurrency artifact is `target/perf/opendr-million-concurrency-20260414-113230/opendr/million-auth-concurrency/`. It reused the same 1M fixture and ran simple-bind plus SASL PLAIN concurrency at `1,4,8,16,32,64,128`.

| Metric | Value |
|---|---:|
| Total measured runtime | 43,763.272 ms |
| Simple-bind max tested clients | 128 |
| Simple-bind max 0% failure clients | 128 |
| Simple-bind peak success ops/s | 17,008.19 |
| SASL PLAIN max tested clients | 128 |
| SASL PLAIN max 0% failure clients | 128 |
| SASL PLAIN peak success ops/s | 48,469.70 |
| OpenDR cache size | 1,000 entries |
| Sampled peak server memory | 3.75 GiB |
| Sampled peak server CPU | 107.36% |

1M simple-bind concurrency:

| Clients | Successes / attempts | Failure % | Success ops/s | Mean ms | P95 ms | P99 ms |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 20 / 20 | 0.00 | 3,630.64 | 0.273 | 0.295 | 1.202 |
| 4 | 80 / 80 | 0.00 | 10,508.74 | 0.377 | 0.597 | 1.213 |
| 8 | 160 / 160 | 0.00 | 8,443.14 | 0.777 | 1.521 | 1.824 |
| 16 | 320 / 320 | 0.00 | 11,342.04 | 1.275 | 1.839 | 1.990 |
| 32 | 640 / 640 | 0.00 | 14,596.63 | 2.061 | 3.279 | 5.279 |
| 64 | 1280 / 1280 | 0.00 | 17,008.19 | 3.473 | 4.515 | 5.639 |
| 128 | 2560 / 2560 | 0.00 | 11,352.18 | 10.804 | 18.222 | 49.937 |

1M SASL PLAIN concurrency:

| Clients | Successes / attempts | Failure % | Success ops/s | Mean ms | P95 ms | P99 ms |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 20 / 20 | 0.00 | 4,804.37 | 0.206 | 0.241 | 0.246 |
| 4 | 80 / 80 | 0.00 | 9,942.31 | 0.400 | 0.928 | 1.167 |
| 8 | 160 / 160 | 0.00 | 15,359.94 | 0.494 | 1.048 | 1.130 |
| 16 | 320 / 320 | 0.00 | 23,266.66 | 0.626 | 1.178 | 1.273 |
| 32 | 640 / 640 | 0.00 | 36,511.79 | 0.806 | 1.244 | 1.434 |
| 64 | 1280 / 1280 | 0.00 | 48,469.70 | 1.172 | 1.689 | 2.045 |
| 128 | 2560 / 2560 | 0.00 | 37,998.50 | 3.025 | 6.701 | 16.695 |

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

- OpenDR FSM remains ahead of OpenDJ on the full-profile latency and footprint rows under this Docker harness.
- With `OPENDR_LMDB_MAX_READERS=256`, `OPENDR_MAX_CONNECTIONS=512`, `OPENDR_MAX_CONNECTIONS_PER_IP=256`, and `OPENDR_MAX_OPERATIONS_PER_CONNECTION=200`, OpenDR completed the dedicated simple-bind concurrency profile through 32 clients at 0% failure and peaked at `45,826.68` successful binds/sec.
- OpenDJ completed the guarded simple-bind concurrency profile through 16 clients at 0% failure. Its all-row successful-bind peak was `29,087.05` successes/sec, but that row had `87.50%` failed attempts.
- OpenDR SASL PLAIN fixture-user binds were faster than OpenDJ in the guarded serial row and reached about `8.38x` higher peak successful SASL PLAIN bind throughput in the `sasl-auth` profile.
- OpenDR completed the index profile and reached 0% failures through 32 mixed concurrent index-search clients, peaking at `5,924.02` successful mixed index searches/sec.
- OpenDJ completed the index scalar probes but fell to `81.25%` failures at 16 mixed concurrent index-search clients and `100%` failures at 32 clients.
- The OpenDR 1M fixture required a 16 GiB LMDB map and produced a 3.20 GiB data directory.
- The OpenDR 1M auth concurrency artifact reached 0% failures through 128 clients for both simple bind and SASL PLAIN, peaking at `17,008.19` simple binds/sec and `48,469.70` SASL PLAIN binds/sec.
- There is still no completed 10M-user OpenDR-vs-OpenDJ benchmark artifact. The largest measured fixture here is the OpenDR-only 1M-user set.

## Artifacts

- Full profile: `target/perf/full-rerun-20260414-091948/comparison-summary.md`
- Simple-bind concurrency profile: `target/perf/concurrency-coalesced-20260414-091023/comparison-summary.md`
- Index profile: `target/perf/index-guarded-both-20260414-091425/comparison-summary.md`
- SASL PLAIN concurrency profile: `target/perf/sasl-guarded-20260414-090609/comparison-summary.md`
- OpenDR 1M preload and serial run artifact: `target/perf/opendr-million-16g-20260414-103048/`
- OpenDR 1M serial result: `target/perf/opendr-million-reuse-skipcounts-20260414-111120/opendr/million/ldap-benchmark-results.json`
- OpenDR 1M auth concurrency result: `target/perf/opendr-million-concurrency-20260414-113230/opendr/million-auth-concurrency/ldap-benchmark-results.json`

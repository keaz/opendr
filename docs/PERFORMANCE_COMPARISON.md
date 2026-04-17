# LDAP Performance Comparison

This document records the current OpenDR performance baseline and historical
Dockerized OpenDR/OpenDJ comparison runs. Container runs use the local OpenDR
Docker image built from this repository and OpenDJ
`openidentityplatform/opendj:5.0.4`. Host runs use the same generated OpenDR
server configuration values as the Docker perf entrypoint, but execute the
optimized binaries directly on the physical machine.

## Scope

- OpenDR was built from the local `Dockerfile` with `rust:1.94-bookworm` and configured for the `fsm` runtime with the LMDB backend.
- OpenDJ was run from `openidentityplatform/opendj:5.0.4`.
- StartTLS was enabled for both products.
- The current baseline rows are from the April 14, 2026 artifacts listed below.
- OpenDR used the Docker entrypoint default `performance.cache_size = 1000`, which currently sizes both the exact-DN entry cache and the authentication credential cache.
- Cache hit/miss metrics were not captured for these artifacts because the Docker perf harness disables the monitoring endpoint and samples container CPU/memory only.
- The 1M-user OpenDR run used a `16 GiB` LMDB map. The default `1 GiB` Docker map filled around 300k users.
- The 1M-user concurrency artifact covers simple-bind and SASL PLAIN auth concurrency. It does not include index-concurrency probes because the preserved 1M fixture was loaded without benchmark ordering attributes.
- Completed OpenDR-only 10M-user LDAPCon-style artifacts are recorded below. The latest host OpenLDAP-shaped run is the current public comparison snapshot; the original synchronous-auth-metadata run remains the historical 10M baseline.
- There is still no completed 10M-user OpenDR-vs-OpenDJ benchmark artifact in this repository.

## Latest 10M Result Snapshot

The latest completed 10M OpenDR snapshot is the physical-machine
OpenLDAP-shaped LDAPCon-style run at:

`target/perf/opendr-local-dockerconfig-ldapcon-openldap-10m-idkey-20260415-212046/opendr/ldapcon-openldap-ten-million/ldapcon-iterations-10000-sampled-20260415-213007/`

This run reused a clean 10M fixture loaded on the host, executed OpenDR directly
on the physical machine with `12` OpenDR worker threads, `12` fixture preload
workers, `cache_size = 10000000`, `lmdb_max_readers = 4096`, async coalesced
auth metadata, and the optimized `perf` build profile with
`-C target-cpu=native`. It used the public LDAPCon 2013 OpenLDAP LMDB
load-generator shape where published: search `96` effective clients, auth `84`,
modify `8`, and mixed `96`. The benchmark used `10000` LDAPCon operations per
client and completed with `0` failures.

| Operation | OpenDR success ops/s | OpenLDAP LMDB 2013 ops/s | Difference | Failures |
|---|---:|---:|---:|---:|
| Search | 118,520.69 | 31,674.02 | +274.2% | 0 |
| Auth | 172,020.69 | 16,941.98 | +915.3% | 0 |
| Modify | 8,100.10 | 5,760.04 | +40.6% | 0 |
| Mixed search | 33,248.74 | 25,399.99 | +30.9% | 0 |
| Mixed modify | 8,312.19 | 1,652.35 | +403.0% | 0 |

All OpenLDAP-shaped operation families are now above the public single-server
OpenLDAP LMDB rows on the physical-machine hot-cache run. The same fixture was
also used for a higher-concurrency diagnostic run at search `192`, auth `168`,
modify `8`, and mixed `192`; that run stayed at `0` failures but reduced
throughput for search, modify, and mixed operations while raising mixed-write
tail latency, pointing to contention before full 12-core saturation.

## Physical-Machine 10M LDAPCon Runs

Artifact root:
`target/perf/opendr-local-dockerconfig-ldapcon-openldap-10m-idkey-20260415-212046/opendr/ldapcon-openldap-ten-million/`

These runs used the same OpenDR server configuration shape and values as the
Docker perf entrypoint for the latest 10M profile, but ran the optimized host
binaries directly on `Kasuns-MacBook-Pro.local`. The host reports `14` logical
CPUs; OpenDR was configured with `performance.worker_threads = 12`. The 10M
LMDB fixture was prewarmed through the host page cache before each benchmark.

Shared server configuration:

| Setting | Value |
|---|---:|
| Runtime | `fsm` |
| Fixture users | `10000000` |
| LMDB map size | `343597383680` bytes |
| LMDB max readers | `4096` |
| OpenDR worker threads | `12` |
| Fixture preload workers | `12` |
| OpenDR cache size | `10000000` |
| Max connections | `4096` |
| Max connections per IP | `4096` |
| Max operations per connection | `200` |
| Max memory per connection | `10485760` bytes |
| Max total tracked connection memory | `2147483648` bytes |
| Auth metadata mode | `async_coalesced` |
| Auth metadata queue capacity | `2000000` |
| Auth metadata flush interval | `50` ms |
| Auth metadata batch size | `5000` |
| Auth metadata overflow policy | `fallback_sync` |
| Build profile | `perf` |
| Build RUSTFLAGS | `-C target-cpu=native` |

Load and storage:

| Metric | Result |
|---|---:|
| Bulk fixture load time | `115` seconds |
| Clean `data.mdb` before first host benchmark | `17,739,038,720` bytes |
| `data.mdb` after high-concurrency run | `17,753,178,112` bytes |
| LMDB page size on host | `16,384` bytes |

The host LMDB footprint is smaller than the earlier Linux/Docker artifact
because this macOS LMDB build uses a `16 KiB` page size. The earlier Linux
Docker optimized layout generated about `20.68 GB` after the benchmark.

### OpenLDAP-Shaped Sustained Run

Artifact:
`target/perf/opendr-local-dockerconfig-ldapcon-openldap-10m-idkey-20260415-212046/opendr/ldapcon-openldap-ten-million/ldapcon-iterations-10000-sampled-20260415-213007/`

This run used the LDAPCon OpenLDAP-shaped concurrency values: search `96`, auth
`84`, modify `8`, and mixed `96`, with `10000` operations per client.

| Operation | Concurrency | Attempts | Failures | Success ops/s | Mean ms | P95 ms | P99 ms |
|---|---:|---:|---:|---:|---:|---:|---:|
| Search | 96 | 960,000 | 0 | 118,520.69 | 0.807 | 1.435 | 1.882 |
| Auth | 84 | 840,000 | 0 | 172,020.69 | 0.488 | 0.749 | 0.898 |
| Modify | 8 | 80,000 | 0 | 8,100.10 | 0.988 | 0.980 | 1.105 |
| Mixed search | 96 | 768,000 | 0 | 33,248.74 | 0.076 | 0.100 | 0.116 |
| Mixed modify | 96 | 192,000 | 0 | 8,312.19 | 11.239 | 12.486 | 12.935 |

Resource summary:

| Metric | Result |
|---|---:|
| Benchmark runtime | `46.34` seconds |
| Resource samples | `178` |
| OpenDR CPU avg / max | `370.10%` / `857.90%` |
| OpenDR RSS avg / max | `6.49 GiB` / `7.51 GiB` |
| `data.mdb` growth during run | about `754 KiB` |

### Higher-Concurrency Diagnostic Run

Artifact:
`target/perf/opendr-local-dockerconfig-ldapcon-openldap-10m-idkey-20260415-212046/opendr/ldapcon-openldap-ten-million/ldapcon-high-concurrency-iter10000-sampled-20260415-213457/`

This run doubled the search, auth, and mixed client counts while keeping modify
at `8`: search `192`, auth `168`, modify `8`, mixed `192`, with `10000`
operations per client.

| Operation | Concurrency | Attempts | Failures | Success ops/s | Mean ms | P95 ms | P99 ms |
|---|---:|---:|---:|---:|---:|---:|---:|
| Search | 192 | 1,920,000 | 0 | 114,359.60 | 1.674 | 3.341 | 4.418 |
| Auth | 168 | 1,680,000 | 0 | 172,343.45 | 0.973 | 1.477 | 1.784 |
| Modify | 8 | 80,000 | 0 | 5,793.40 | 1.381 | 0.982 | 36.623 |
| Mixed search | 192 | 1,536,000 | 0 | 22,171.45 | 0.076 | 0.101 | 0.118 |
| Mixed modify | 192 | 384,000 | 0 | 5,542.86 | 34.326 | 115.917 | 142.131 |

Resource summary:

| Metric | Result |
|---|---:|
| Benchmark runtime | `110.37` seconds |
| Resource samples | `421` |
| OpenDR CPU avg / max | `300.81%` / `854.50%` |
| OpenDR RSS avg / max | `8.67 GiB` / `9.87 GiB` |
| `data.mdb` growth during run | about `4.28 MiB` |

Interpretation:

- The `10000`-iteration OpenLDAP-shaped host run is the cleanest current 10M
  comparison row because its concurrency matches the published OpenLDAP LMDB
  load-generator shape and all operation families complete with `0` failures.
- Doubling search/auth/mixed concurrency did not increase sustained throughput.
  Auth stayed flat, search dipped slightly, and modify/mixed write latency
  worsened materially.
- The high-concurrency run peaked near `8.5` cores but averaged about `3`
  cores. The current bottleneck is therefore not simply the 12-worker-thread
  envelope; write-path lock contention, LMDB write serialization, or client
  scheduling overhead should be profiled next.

## Profiling And Regression Workflow

Use the `regression` Docker profile for CI-friendly perf gates. It loads a
100k-user fixture, enables indexed probes, and runs moderate concurrent bind and
index-search levels without requiring the 10M artifact or 30 GiB memory.

```bash
PERF_GATE_MODE=release \
PERF_GATE_BASELINE_JSON=target/perf/regression-baseline/opendr/regression-100k/ldap-benchmark-results.json \
PERF_GATE_OUTPUT_DIR=target/perf/regression-candidate \
./scripts/perf_regression_gate.sh
```

The wrapper runs `scripts/perf_docker_matrix.sh --products opendr --profile-set
regression`, requires a known-good baseline by default, then compares the new
run with:

```bash
python3 scripts/compare_perf_run.py \
  --baseline-json target/perf/regression-baseline/opendr/regression-100k/ldap-benchmark-results.json \
  --candidate-json target/perf/regression-candidate/opendr/regression-100k/ldap-benchmark-results.json \
  --threshold-percent 10 \
  --report-out target/perf/regression-candidate/perf-regression-report.md
```

The comparison gate checks `success_throughput_ops_per_sec`, `mean_ms`,
`p95_ms`, and `failure_rate_percent` for common operations and exits non-zero
when a metric regresses beyond the threshold. The perf client JSON now includes
`failure_reasons` buckets for concurrent and LDAPCon-style runs; for example
`ready_timeout`, `collect_timeout`, `worker_join_error`, and
`operation_failed`. These buckets should be reviewed first when c128, c256, or
c1000 rows have non-zero failure rates.

## Release Candidate Regression Evidence 2026-04-16

The v1.0.0 release-candidate performance gate was rerun in release mode with
the `regression-100k` Docker profile.

Artifact:
`target/perf/regression-candidate/20260416T073953Z/comparison-summary.md`

Result: passed as a candidate-only run. The retained baseline file was not
present at
`target/perf/regression-baseline/opendr/regression-100k/ldap-benchmark-results.json`,
so this evidence records the candidate profile output but is not a true
baseline-vs-candidate regression comparison.

| Metric | Result |
|---|---:|
| Runtime | `68.24` seconds |
| Preloaded users | `100,000` |
| Records after setup | `100,005` |
| DB size after setup | `252.38 MiB` |
| OpenDR CPU avg / max | `90.43%` / `177.18%` |
| OpenDR RSS avg / max | `175.87 MiB` / `268.50 MiB` |
| Subtree search mean | `807.100 ms` |
| Simple bind admin mean | `0.096 ms` |
| Add / modify / delete mean | `1.614 ms` / `0.454 ms` / `1.254 ms` |
| Peak concurrent bind success throughput | `18,833.41 ops/s` |
| Max concurrent bind failure rate at 128 clients | `9.38%` |
| Equality `uid` index mean | `0.182 ms` |
| Peak concurrent index-search success throughput | `34,063.16 ops/s` |
| Max concurrent index-search failure rate at 128 clients | `21.88%` |

For production regression enforcement, retain a known-good
`ldap-benchmark-results.json` baseline in the baseline path above and rerun the
wrapper so the threshold comparison can fail the gate on regressions.

For local macOS/Linux profiling without Docker, build optimized binaries and run
the server/client pair directly:

```bash
RUSTFLAGS="-C target-cpu=native" cargo build --profile perf \
  --bin opendr \
  --bin ldap_perf_client \
  --bin opendr_perf_fixture_loader

OPENDR_PERF_PROFILE_PHASES=1 \
RUST_LOG=opendr::perf_profile=info \
target/perf/opendr --config config/server.toml --log-config config/log4rs.yml

target/perf/ldap_perf_client \
  --url ldap://127.0.0.1:1389 \
  --bind-dn "cn=admin,dc=example,dc=com" \
  --password admin \
  --base-dn "dc=example,dc=com" \
  --preloaded-users 100000 \
  --index-benchmark \
  --concurrent-index-search-clients 8,32,128 \
  --concurrent-bind-clients 8,32,128 \
  --json-out target/perf/local-regression.json
```

`OPENDR_PERF_PROFILE_PHASES=1` enables low-overhead phase timing logs on the
server. The flag is disabled by default; when enabled, the server writes
`opendr::perf_profile` log rows such as `operation=bind phase=auth`,
`operation=search phase=total`, `operation=modify phase=backend_write`,
`operation=lmdb_get_entry phase=deserialize`, and
`operation=lmdb_authenticate phase=password_lookup`.

Search-plan guardrail counters are emitted when metrics are enabled. For the
10M hot path, expected indexed probes should increment
`ldap_search_plan_equality_index_total`, `ldap_search_plan_presence_index_total`,
`ldap_search_plan_substring_index_total`, or `ldap_search_plan_ordering_index_total`.
Unexpected growth in `ldap_search_plan_full_scan_total`,
`ldap_search_full_scan_missing_hint_total`, or
`ldap_search_full_scan_index_unavailable_total` means a benchmark probe fell back
to a full LMDB scan and should be fixed before comparing throughput.

Run the full 10M profile manually only when validating a completed perf issue or
release candidate. The expected resource envelope is 8 CPU cores, 30 GiB memory,
a large LMDB map, optimized `perf` build flags, and enough disk for a 10M LMDB
fixture:

```bash
scripts/perf_docker_matrix.sh \
  --products opendr \
  --profile-set ldapcon-ten-million \
  --output-dir target/perf/opendr-ldapcon-10m-candidate \
  --cpu 8 \
  --memory 30g \
  --benchmark-timeout 7200 \
  --opendr-lmdb-max-size 343597383680 \
  --opendr-lmdb-max-readers 4096 \
  --opendr-worker-threads 8 \
  --opendr-cache-size 10000000 \
  --opendr-build-profile perf \
  --opendr-build-rustflags "-C target-cpu=native" \
  --opendr-bulk-fixture-load
```

Compare 10M c8 rows against the public LDAPCon 2013 OpenLDAP LMDB rows when all
operation families complete with 0 failures. Treat c128/c256/c1000 rows as
saturation diagnostics until their `failure_rate_percent` is 0 and the
`failure_reasons` buckets are empty.

## Targeted 10M LDAPCon-Style Auth Metadata Run

Artifact root: `target/perf/opendr-auth-metadata-async-10m-8cpu-30g-20260415-102258/`

This run reused the existing 10M LDAPCon-style LMDB fixture and targeted the
issue #131 optimization: bind success/failure metadata is no longer written in
the bind hot path when `auth_metadata.update_mode = "async_coalesced"`. The
server still queues account metadata updates for a background writer; clean
shutdown drains the queue, while a forced container removal can lose in-memory
queued metadata events.

Configuration:

| Setting | Value |
|---|---:|
| Fixture users | `10000000` |
| Benchmark-record count after setup | `10000005` |
| CPU limit | `8` |
| Memory limit | `30g` |
| LMDB map size | `343597383680` bytes |
| LMDB max readers | `4096` |
| OpenDR runtime | `fsm` |
| Tokio worker threads | `8` |
| OpenDR cache size | `50000` |
| Max connections | `4096` |
| Max connections per IP | `4096` |
| Max operations per connection | `200` |
| Max total tracked connection memory | `30000000000` bytes |
| Auth metadata mode | `async_coalesced` |
| Auth metadata queue capacity | `2000000` |
| Auth metadata flush interval | `50` ms |
| Auth metadata batch size | `5000` |
| Auth metadata overflow policy | `fallback_sync` |
| Build profile | `perf` |
| Build RUSTFLAGS | `-C target-cpu=native` |
| Build profile flags | `opt-level = 3`, `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`, `strip = "symbols"`, `debug = false`, `incremental = false` |
| LDAPCon-style client levels | `8,128,256,1000` |
| Operations per client and operation family | `100` |
| Warmup operations per client | `5` |
| Per-operation timeout | `10000` ms |

Run summary:

| Metric | Result |
|---|---:|
| Total benchmark client runtime | `73,190.208` ms |
| Server CPU avg / max | `44.22%` / `207.11%` |
| Server memory avg / max | `310.50 MiB` / `395.30 MiB` |
| Server memory limit | `30.00 GiB` |

LDAPCon auth result:

| Auth row | Attempts | Successes | Failure % | Success ops/s | Mean ms | P95 ms | P99 ms |
|---|---:|---:|---:|---:|---:|---:|---:|
| `ldapcon_auth_c8` | 800 | 800 | 0.00% | 13,919.54 | 0.552 | 1.100 | 1.329 |
| `ldapcon_auth_c128` | 12,800 | 12,800 | 0.00% | 15,833.10 | 7.857 | 13.818 | 17.273 |
| `ldapcon_auth_c256` | 25,600 | 24,700 | 3.52% | 12,066.33 | 19.809 | 40.696 | 52.593 |
| `ldapcon_auth_c1000` | 100,000 | 24,700 | 75.30% | 11,445.83 | 21.197 | 32.708 | 35.250 |

Auth improvement versus the synchronous-auth-metadata 10M baseline:

| Auth row | Old mean ms | New mean ms | Mean speedup | Old success ops/s | New success ops/s | Success ops/s speedup | Old failure % | New failure % |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `ldapcon_auth_c8` | 4.950 | 0.552 | 8.97x | 1,605.49 | 13,919.54 | 8.67x | 0.00% | 0.00% |
| `ldapcon_auth_c128` | 71.027 | 7.857 | 9.04x | 1,596.99 | 15,833.10 | 9.91x | 10.94% | 0.00% |
| `ldapcon_auth_c256` | 63.512 | 19.809 | 3.21x | 1,284.70 | 12,066.33 | 9.39x | 67.97% | 3.52% |
| `ldapcon_auth_c1000` | 95.397 | 21.197 | 4.50x | 1,200.05 | 11,445.83 | 9.54x | 88.50% | 75.30% |

Comparison against the public LDAPCon 2013 OpenLDAP LMDB auth row:

| OpenDR row | OpenDR success ops/s | OpenLDAP LMDB public auth ops/s | Difference |
|---|---:|---:|---:|
| `ldapcon_auth_c8` | 13,919.54 | 16,942 | -17.8% |
| `ldapcon_auth_c128` | 15,833.10 | 16,942 | -6.5% |
| `ldapcon_auth_c256` | 12,066.33 | 16,942 | -28.8% |

Interpretation:

- The issue #131 path removes the LMDB metadata write from the bind response
  path and improves clean `c8` auth throughput by 8.67x.
- The clean `c128` auth row is now close to the public LDAPCon OpenLDAP LMDB
  auth row, but it is still 6.5% below that public result.
- The `c256` and `c1000` rows are saturation data, not clean sustained-capacity
  claims, because they still include failures under this harness.
- Modify rows remain write-bound and are not improved by this auth-specific
  change.

## Targeted 10M Credential-Index Auth Run

Artifact roots:

- `target/perf/opendr-credential-index-10m-c8-cache50k-rerun-8cpu-30g-20260415-132251/`
- `target/perf/opendr-credential-index-10m-c8-8cpu-30g-20260415-131632/`

This run targeted issue #139 after adding the first compact LMDB credential
index. The current storage layout supersedes that result with
`credentials_by_entry_id`, which is keyed by compact entry ID and stores decoded
SSHA512 hash/salt records. Fresh stores no longer populate the legacy
`passwords` or `credentials_by_normalized_dn` databases.

Both rows reused the existing 10M LDAPCon-style fixture after credential-index
backfill, used the `perf` profile with `-C target-cpu=native`, 8 CPUs, 30 GiB
memory, `lmdb_max_readers = 4096`, async coalesced auth metadata, and c8-only
LDAPCon-style probes.

| Cache capacity | Auth attempts | Auth failures | Auth mean ms | Auth p95 ms | Auth success ops/s | OpenLDAP LMDB public auth ops/s | Difference |
|---:|---:|---:|---:|---:|---:|---:|---:|
| `50000` | 800 | 0 | 0.571 | 1.307 | 13,777.79 | 16,942 | -18.7% |
| `10000000` | 800 | 0 | 0.970 | 2.675 | 7,694.81 | 16,942 | -54.6% |

Interpretation:

- The 50k-cache c8 auth row is effectively flat against the issue #131 baseline
  of 13,919.54 ops/s, so the compact normalized credential index removes work
  from the miss path but does not yet close the OpenLDAP LMDB gap in this
  10M random-user benchmark.
- The 10M-cache setting is not currently a throughput win for the c8 auth row.
  It raised container memory to about 17.56 GiB and reduced auth throughput,
  likely because cache preallocation and large-cache behavior dominate before
  the random-user working set becomes warm.
- Follow-up auth work should focus on reducing cache overhead for very large
  capacities, cache prewarming or lazy allocation strategy, and profiling the
  remaining TLS/client/server phases around simple bind.

## OpenLDAP-Like 10M LDAPCon-Style Run

Artifact root:
`target/perf/opendr-ldapcon-openldap-10m-12cpu-30g-20260415-150810/`

This run uses a clean 10M fixture and matches the public LDAPCon 2013
OpenLDAP LMDB concurrency shape where the slides publish it: search uses 8
SLAMD clients x 12 threads (`96` effective clients), auth uses 6 clients x 14
threads (`84` effective clients), and modify uses 8 clients x 1 thread (`8`
effective clients). The public mixed row does not publish a client/thread
split, so this OpenDR profile uses the search concurrency (`96`) for the mixed
read/write probe.

The OpenLDAP LMDB 2013 rows are single OpenLDAP server-instance results. The
published clients and threads are SLAMD load-generator settings, not multiple
LDAP server instances.

Configuration deltas from the general 10M profile:

| Setting | Value |
|---|---:|
| Profile set | `ldapcon-openldap-ten-million` |
| Fixture users | `10000000` |
| CPU limit | `12` |
| Memory limit | `30g` |
| OpenDR cache size | `10000000` |
| Build profile | `perf` |
| Build RUSTFLAGS | `-C target-cpu=native` |
| OpenDR worker threads | `12` |
| Fixture preload workers | `12` |
| LDAPCon search clients | `96` |
| LDAPCon auth clients | `84` |
| LDAPCon modify clients | `8` |
| LDAPCon mixed clients | `96` |
| Operations per client and operation family | `100` |
| Warmup operations per client | `5` |
| Mixed workload write share | `20%` modifies, `80%` searches |

OpenDR result:

| Operation | Concurrency | Attempts | Failures | Success ops/s | Mean ms | P95 ms | P99 ms |
|---|---:|---:|---:|---:|---:|---:|---:|
| Search | 96 | 9,600 | 0 | 39,281.55 | 2.352 | 4.060 | 10.141 |
| Auth | 84 | 8,400 | 0 | 41,680.21 | 1.945 | 6.129 | 9.200 |
| Modify | 8 | 800 | 0 | 1,852.72 | 4.300 | 4.579 | 4.986 |
| Mixed search | 96 | 7,680 | 0 | 4,332.81 | 0.420 | 0.822 | 1.180 |
| Mixed modify | 96 | 1,920 | 0 | 1,083.20 | 84.697 | 104.622 | 118.531 |

Comparison against the public LDAPCon 2013 OpenLDAP LMDB rows:

| Operation | OpenDR row | OpenDR success ops/s | OpenLDAP LMDB public ops/s | Difference |
|---|---|---:|---:|---:|
| Search | `ldapcon_search_c96` | 39,281.55 | 31,674.02 | +24.0% |
| Auth | `ldapcon_auth_c84` | 41,680.21 | 16,941.98 | +146.0% |
| Modify | `ldapcon_modify_c8` | 1,852.72 | 5,760.04 | -67.8% |
| Mixed search | `ldapcon_mixed_search_c96` | 4,332.81 | 25,399.99 | -82.9% |
| Mixed modify | `ldapcon_mixed_modify_c96` | 1,083.20 | 1,652.35 | -34.4% |

Interpretation:

- With operation-specific concurrency, OpenDR is above the public single-server
  OpenLDAP LMDB search and auth rows while staying at 0 failures.
- Increasing the CPU and worker-thread envelope to 12 improved auth over the
  earlier 10-core run, but search, modify, and mixed throughput regressed. The
  12-core setting is therefore not a broad throughput win for this workload.
- Modify and mixed workloads remain behind OpenLDAP LMDB. The modify gap is
  the clearest remaining single-operation target for this benchmark shape.
- The in-process cache was sized for 10M entries, but the sampled server memory
  remained far below the LMDB footprint. This validates the large cache
  capacity setting, not full resident cache coverage of all 10M entries during
  the measured probe.

## Completed 10M LDAPCon-Style OpenDR Run

Artifact root: `target/perf/opendr-ldapcon-10m-8cpu-30g-20260415-000605/`

This run used a 10M-user fixture shaped like the public LDAPCon 2013 benchmark data set: one base DN, benchmark organizational units, and generated `inetOrgPerson` users with unique `uid`, `cn`, `sn`, `mail`, `description`, and `userPassword` values. The LDAPCon-style probes cover indexed user search, user authorization/simple bind, modify, and mixed read/write operation families.

Configuration:

| Setting | Value |
|---|---:|
| Fixture users | `10000000` |
| Benchmark-record count after setup | `10000005` |
| CPU limit | `8` |
| Memory limit | `30g` |
| LMDB map size | `343597383680` bytes |
| LMDB max readers | `4096` |
| OpenDR runtime | `fsm` |
| Tokio worker threads | `8` |
| OpenDR cache size | `50000` |
| Max connections | `2000` |
| Max connections per IP | `2000` |
| Max operations per connection | `2000` |
| Max memory per connection | `67108864` bytes |
| Max total tracked connection memory | `26843545600` bytes |
| Build profile | `perf` |
| Build RUSTFLAGS | `-C target-cpu=native` |
| Build profile flags | `opt-level = 3`, `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`, `strip = "symbols"`, `debug = false`, `incremental = false` |
| Docker nofile ulimit | `1048576` |
| LDAPCon-style client levels | `8,128,256,1000` |
| Operations per client and operation family | `100` |
| Warmup operations per client | `5` |
| Per-operation timeout | `10000` ms |
| Mixed workload write share | `20%` modifies, `80%` searches |

Load and footprint:

| Metric | Result |
|---|---:|
| Bulk fixture load time | `222` seconds |
| LMDB data footprint before benchmark | `47.62 GiB` |
| LMDB data footprint after benchmark | `47.62 GiB` |
| Total benchmark client runtime | `481,968.921` ms |
| Server CPU avg / max | `5.73%` / `44.33%` |
| Server memory avg / max | `262.18 MiB` / `454.60 MiB` |

Important caveat: only the `c8` LDAPCon-style level completed with 0 failures. The requested `c128`, `c256`, and `c1000` levels are still useful saturation data, but they should be read as success-throughput plus failure-rate results, not as clean sustained-capacity results.

OpenDR per-level success throughput:

| Operation | c8 success ops/s / fail % | c128 success ops/s / fail % | c256 success ops/s / fail % | c1000 success ops/s / fail % |
|---|---:|---:|---:|---:|
| Search | 41,401.35 / 0.00% | 45,068.67 / 17.19% | 46,864.97 / 12.11% | 29,625.57 / 79.80% |
| Auth | 1,605.49 / 0.00% | 1,596.99 / 10.94% | 1,284.70 / 67.97% | 1,200.05 / 88.50% |
| Modify | 1,915.83 / 0.00% | 1,407.97 / 12.50% | 1,250.33 / 60.16% | 1,309.21 / 93.30% |
| Mixed search | 6,562.54 / 0.00% | 5,078.51 / 12.50% | 4,879.92 / 60.94% | 4,162.47 / 86.10% |
| Mixed modify | 1,640.63 / 0.00% | 1,269.63 / 12.50% | 1,219.98 / 60.94% | 1,040.62 / 86.10% |

OpenDR c8 0-failure latency baseline:

| Operation | Success ops/s | Mean ms | P95 ms | P99 ms | Failures |
|---|---:|---:|---:|---:|---:|
| Search | 41,401.35 | 0.164 | 0.261 | 2.437 | 0 / 800 |
| Auth | 1,605.49 | 4.950 | 15.319 | 21.232 | 0 / 800 |
| Modify | 1,915.83 | 4.148 | 5.782 | 23.501 | 0 / 800 |
| Mixed search | 6,562.54 | 0.091 | 0.110 | 0.431 | 0 / 640 |
| Mixed modify | 1,640.63 | 4.419 | 6.386 | 7.071 | 0 / 160 |

Comparison against the public LDAPCon 2013 10M results:

- Public source: [LDAPCon 2013 benchmark slides](https://www.slideshare.net/slideshow/benchmarks-on-ldap-directories/28486722).
- Public setup: 10M-entry directory, 32GB RAM, 512GB SSD, SLAMD 2.0.1.
- Public load-time comparisons are not apples-to-apples because this OpenDR run used an offline LMDB bulk loader, while LDAPCon load results were product ingestion runs.
- Throughput comparisons use OpenDR `c8`, because it is the only OpenDR level in this run with 0 failures.
- Search, auth, modify, and mixed throughput are higher-is-better. Load-time ratio is OpenDR/public, so lower is better. Disk ratio is OpenDR/public, so lower is smaller.

| Public LDAPCon 2013 product | Search | Auth | Modify | Mixed search | Mixed modify | Load time ratio | Disk ratio |
|---|---:|---:|---:|---:|---:|---:|---:|
| OpenLDAP LMDB | 41,401 vs 31,674 (+30.7%) | 1,605 vs 16,942 (-90.5%) | 1,916 vs 5,760 (-66.7%) | 6,563 vs 25,400 (-74.2%) | 1,641 vs 1,652 (-0.7%) | 0.10x | 2.83x |
| OpenDJ 2.4.6 | 41,401 vs 13,249 (+212.5%) | 1,605 vs 7,668 (-79.1%) | 1,916 vs 6,350 (-69.8%) | 6,563 vs 6,248 (+5.0%) | 1,641 vs 3,525 (-53.5%) | 0.01x | 3.81x |
| 389 DS 1.2.11.15 | 41,401 vs 11,182 (+270.3%) | 1,605 vs 3,763 (-57.3%) | 1,916 vs 823 (+132.7%) | 6,563 vs 2,311 (+183.9%) | 1,641 vs 719 (+128.2%) | 0.07x | 3.03x |
| ApacheDS 2.0.0-M13 | 41,401 vs 688 (+5,917.8%) | 1,605 vs 210 (+663.7%) | 1,916 vs 55 (+3,413.5%) | 6,563 vs 44 (+14,916.2%) | 1,641 vs 44 (+3,656.5%) | 0.01x | 1.19x |

Interpretation:

- OpenDR search throughput is above the public LDAPCon OpenLDAP LMDB, OpenDJ, 389 DS, and ApacheDS search rows at the 0-failure `c8` level.
- OpenDR auth throughput is materially below OpenLDAP LMDB, OpenDJ, and 389 DS in the LDAPCon table, but above ApacheDS.
- OpenDR modify throughput is below OpenLDAP LMDB and OpenDJ, but above 389 DS and ApacheDS.
- OpenDR mixed-search throughput is close to OpenDJ, above 389 DS and ApacheDS, and below OpenLDAP LMDB.
- OpenDR mixed-modify throughput is effectively tied with OpenLDAP LMDB in this comparison, below OpenDJ, and above 389 DS and ApacheDS.
- The high-concurrency `c128`, `c256`, and `c1000` levels show that OpenDR currently starts dropping whole worker batches under this harness. Before claiming sustained capacity at those levels, the server and/or harness need another pass on connection ramp-up, operation timeout behavior, and failure reason reporting.

## Stopped 10M OpenDR Attempt

This partial run was stopped on request on April 14, 2026 at 16:27:05 Asia/Colombo. It should not be used as a completed performance result because `ldap-benchmark-results.json` was not written before the stop.

What did complete:

- The OpenDR Docker image and perf-client image rebuilt successfully with Cargo profile `perf`.
- The bulk fixture loader completed `10000006` total entries: base entry, admin entry, benchmark root/users/moved/writes organizational units, and `10000000` fixture users.
- The LMDB `data.mdb` file reached about `102 GiB`.
- The rerun reused that fixture with an 8-core CPU limit and `30g` memory limit.
- The client reached `benchmark.concurrent_sasl_plain_bind_fixture_users.c1000`.

What did not complete:

- No final JSON metrics were emitted.
- No per-level bind, SASL PLAIN, or index-search throughput/latency numbers are available from this stopped run.
- The stopped run therefore cannot be compared numerically against LDAPCon, Oracle OID, OpenDJ, OpenLDAP, 389 DS, or ApacheDS public benchmarks.

Stopped-run configuration:

| Setting | Value |
|---|---:|
| Preloaded users | `10000000` |
| CPU limit | `8` |
| Memory limit | `30g` |
| LMDB map size | `343597383680` bytes |
| LMDB max readers | `4096` |
| OpenDR runtime | `fsm` |
| Tokio worker threads | `8` |
| OpenDR cache size | `50000` |
| Max connections | `2000` |
| Max connections per IP | `2000` |
| Max operations per connection | `2000` |
| Max memory per connection | `67108864` bytes |
| Max total tracked connection memory | `26843545600` bytes |
| Build profile | `perf` |
| Build RUSTFLAGS | `-C target-cpu=native` |
| Build profile flags | `opt-level = 3`, `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`, `strip = "symbols"`, `debug = false`, `incremental = false` |
| Docker nofile ulimit | `1048576` |
| Concurrent bind targets | `128,256,1000` |
| Concurrent SASL PLAIN bind targets | `128,256,1000` |
| Concurrent index-search targets | `128,256,1000` |
| Iterations per concurrency level | `100` |
| Warmup iterations per concurrency level | `5` |
| Operation timeout | `10000` ms |

Partial progress markers captured before stopping:

```text
progress: connect.setup
progress: fixture.count.before_setup.skipped
progress: fixture.reuse
progress: fixture.count.after_setup.skipped
progress: benchmark.concurrent_bind_fixture_users
progress: benchmark.concurrent_bind_fixture_users.c128
progress: benchmark.concurrent_bind_fixture_users.c256
progress: benchmark.concurrent_bind_fixture_users.c1000
progress: benchmark.concurrent_sasl_plain_bind_fixture_users
progress: benchmark.concurrent_sasl_plain_bind_fixture_users.c128
progress: benchmark.concurrent_sasl_plain_bind_fixture_users.c256
progress: benchmark.concurrent_sasl_plain_bind_fixture_users.c1000
```

Partial sampled server container stats from the short rerun before stop:

| Samples | Avg CPU % | Max CPU % | Avg memory | Max memory | Limit |
|---:|---:|---:|---:|---:|---:|
| 29 | 14.10 | 62.75 | 542.67 MiB | 1.04 GiB | 30.00 GiB |

Notes from the stopped attempts:

- The first completed fixture load exposed an expensive reused-fixture validation path: a base-scope control-user check used `(objectClass=inetOrgPerson)`, which could produce a 10M-candidate indexed scan before scope filtering. The client now uses the unique `uid` filter for that validation.
- A concurrent 10M index-search probe using the substring filter `(description=*fixture user 000000*)` was too broad for this fixture because the selected substring tokens were common across many generated descriptions. The concurrent index-search mix now uses selective `uid` equality and one-entry ordering-boundary probes.
- The harness now supports `--opendr-skip-bulk-fixture-load` to reuse a previously bulk-loaded LMDB fixture in the same run directory for interrupted 10M reruns.

Useful public 10M comparison points, with caveats:

| Source | Setup | Reported result |
|---|---|---|
| [LDAPCon 2013 benchmark slides](https://www.slideshare.net/slideshow/benchmarks-on-ldap-directories/28486722) | 10M-entry directory benchmarks on a VM with 32GB RAM and 512GB SSD. | Published read/auth tables include OpenLDAP mdb, 389 DS, OpenDJ, and ApacheDS. Example reported auth throughput: OpenLDAP mdb `16942/sec`, OpenDJ `7668/sec`, 389 DS `3763/sec`, ApacheDS `210/sec`. |
| [Oracle Internet Directory 11g benchmark PDF](https://www.oracle.com/docs/tech/middleware/oid-11116-exalogic-perf.pdf) | Oracle Exalogic, 10M users, OID 11.1.1.6, 6 OID nodes for high-concurrency and 1 OID node for low-latency runs. | Reported high-concurrency results include `1,703,123` random 1-attribute searches/sec and `648,113` random auth operations/sec across 6 nodes. Single-node low-latency results include `275,599` random 1-attribute searches/sec and `102,356` auth operations/sec. |
| [The HFT Guy OpenDJ 10M write-up](https://thehftguy.com/2015/10/23/10-millions-users-accounts-with-ldap-yes-we-can/) | OpenDJ 2.6 behind OpenAM, 4 directory nodes and 2 replication nodes, with OpenDJ JVM heap at 50GB and database cache at 80%. | Useful deployment context for OpenDJ at 10M scale, but it is not a direct LDAP-only single-node comparison to this stopped OpenDR run. |

## Reproduction

Release CD runs the OpenDR Docker perf regression gate with the full,
simple-bind concurrency, index, and SASL PLAIN concurrency profiles. The gate
uses `scripts/validate_docker_perf_baseline.py` to compare the generated
`comparison-summary.csv` files against the OpenDR baseline values in this
document and fails when a lower-is-better latency/failure metric regresses by
more than 10%, or a higher-is-better throughput/capacity metric drops by more
than 10%. The GitHub Actions run used for this baseline and the local comparison
commands both run with `--cpu 2 --memory 4g`.

Full latency run:

```bash
./scripts/perf_docker_matrix.sh \
  --profile-set full \
  --products opendr \
  --opendr-runtime fsm \
  --benchmark-timeout 240 \
  --cpu 2 \
  --memory 4g \
  --output-dir target/perf/release/full
```

Simple-bind concurrency run:

```bash
./scripts/perf_docker_matrix.sh \
  --profile-set concurrency \
  --products opendr \
  --opendr-runtime fsm \
  --benchmark-timeout 240 \
  --cpu 2 \
  --memory 4g \
  --concurrent-bind-clients 1,4,8,10,12,16,32,64,128 \
  --concurrent-bind-iterations 20 \
  --concurrent-bind-warmup-iterations 1 \
  --concurrent-bind-operation-timeout-ms 5000 \
  --output-dir target/perf/release/concurrency
```

Index search run:

```bash
./scripts/perf_docker_matrix.sh \
  --profile-set index \
  --products opendr \
  --opendr-runtime fsm \
  --benchmark-timeout 240 \
  --cpu 2 \
  --memory 4g \
  --concurrent-index-search-clients 1,4,8,16,32 \
  --concurrent-index-search-iterations 20 \
  --concurrent-index-search-warmup-iterations 1 \
  --concurrent-index-search-operation-timeout-ms 5000 \
  --perf-client-image opendr:docker-perf-client \
  --output-dir target/perf/release/index
```

SASL PLAIN concurrency run:

```bash
./scripts/perf_docker_matrix.sh \
  --profile-set sasl \
  --products opendr \
  --opendr-runtime fsm \
  --benchmark-timeout 240 \
  --cpu 2 \
  --memory 4g \
  --concurrent-bind-clients 1,4,8,16,32,64,128 \
  --concurrent-bind-iterations 20 \
  --concurrent-bind-warmup-iterations 1 \
  --concurrent-bind-operation-timeout-ms 5000 \
  --sasl-plain-authcid-format rdn-value \
  --skip-sasl-plain-admin-benchmark \
  --perf-client-image opendr:docker-perf-client \
  --output-dir target/perf/release/sasl
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

OpenDR rows are from GitHub Actions run `24546834381` at `target/perf/release/full/`.
OpenDJ rows are from the local comparison artifact `target/perf/local-opendj-2cpu-4g-20260417T031957Z/full/`.

| Product / runtime | Profile | Status | Total runtime ms | Records after setup | Avg CPU % | Avg memory | DB after | Subtree search mean ms | Simple bind mean ms | Add mean ms | Modify mean ms | Delete mean ms | Password modify mean ms |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| OpenDR FSM | light | success | 711.760 | 109 | 33.22 | 3.86 MiB | 412.00 KiB | 2.467 | 0.165 | 0.783 | 0.449 | 0.629 | 0.504 |
| OpenDJ | light | success | 922.100 | 105 | 172.35 | 1020.00 MiB | 1.14 MiB | 4.914 | 0.385 | 1.056 | 0.429 | 1.488 | 0.700 |
| OpenDR FSM | moderate | success | 1,079.653 | 509 | 44.48 | 3.96 MiB | 1.13 MiB | 10.421 | 0.157 | 1.090 | 0.436 | 0.771 | 0.418 |
| OpenDJ | moderate | success | 1,176.522 | 505 | 100.25 | 807.20 MiB | 10.14 MiB | 15.707 | 0.301 | 0.915 | 0.387 | 1.346 | 0.634 |
| OpenDR FSM | heavy | success | 1,818.704 | 1009 | 17.62 | 3.80 MiB | 1.87 MiB | 18.984 | 0.164 | 0.997 | 0.430 | 0.896 | 0.469 |
| OpenDJ | heavy | success | 1,732.826 | 1005 | 103.09 | 806.40 MiB | 31.14 MiB | 26.703 | 0.273 | 1.108 | 0.426 | 2.140 | 0.711 |
| OpenDR FSM | stress | success | 4,523.397 | 2509 | 34.21 | 3.68 MiB | 4.14 MiB | 45.689 | 0.179 | 1.155 | 0.451 | 1.171 | 0.431 |
| OpenDJ | stress | success | 4,294.361 | 2505 | 131.70 | 797.73 MiB | 176.77 MiB | 57.185 | 0.268 | 1.713 | 0.487 | 3.235 | 0.999 |

OpenDR FSM was faster on every listed full-profile latency metric in these rows, while also using substantially less memory and disk.

## Simple Bind Concurrency

OpenDR rows are from GitHub Actions run `24546834381` at `target/perf/release/concurrency/`.
The same OpenDJ profile at `target/perf/local-opendj-2cpu-4g-20260417T031957Z/concurrency/`
timed out under the same `--cpu 2 --memory 4g` Docker limits.

| Product / runtime | Profile | Status | Timeout budget | Max tested clients | Max 0% failure clients | Failure rate at max tested | Peak success ops/s | CPU avg / max | Memory avg / max |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| OpenDR FSM | auth-concurrency | success | 240s | 128 | 128 | 0.000% | 11,584.12 | 13.65% / 33.89% | 9.34 MiB / 15.58 MiB |
| OpenDJ | auth-concurrency | timeout | 240s | n/a | n/a | n/a | n/a | 11.66% / 199.47% | 859.77 MiB / 1005.00 MiB |

OpenDR simple-bind per-level results:

| Clients | Successes / attempts | Failure % | Success ops/s | Mean ms | P95 ms | P99 ms |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 20 / 20 | 0.00 | 5,672.30 | 0.162 | 0.173 | 0.230 |
| 4 | 80 / 80 | 0.00 | 9,861.43 | 0.260 | 0.494 | 2.190 |
| 8 | 160 / 160 | 0.00 | 9,231.89 | 0.664 | 1.111 | 2.128 |
| 10 | 200 / 200 | 0.00 | 8,872.92 | 0.916 | 1.299 | 1.843 |
| 12 | 240 / 240 | 0.00 | 11,584.12 | 0.733 | 1.343 | 2.178 |
| 16 | 320 / 320 | 0.00 | 8,477.33 | 1.475 | 2.169 | 4.861 |
| 32 | 640 / 640 | 0.00 | 8,944.34 | 2.738 | 3.630 | 6.645 |
| 64 | 1280 / 1280 | 0.00 | 8,558.13 | 5.763 | 6.808 | 17.986 |
| 128 | 2560 / 2560 | 0.00 | 8,382.59 | 11.252 | 13.601 | 27.003 |

## SASL PLAIN Results

OpenDR rows are from GitHub Actions run `24546834381` at `target/perf/release/sasl/`.
OpenDJ rows are from `target/perf/local-opendj-2cpu-4g-20260417T031957Z/sasl/`.
OpenDJ accepts fixture-user SASL PLAIN binds when the SASL `authcid` is the
fixture user's RDN value. The admin SASL probe is skipped for the OpenDR-vs-OpenDJ
comparison because OpenDJ rejects the directory-manager/admin SASL PLAIN probe
with invalid credentials in this harness.

| Product / runtime | Max tested clients | Max 0% failure clients | Failure rate at max tested | Peak SASL success ops/s | Fixture-user mean ms | CPU avg / max | Memory avg / max |
|---|---:|---:|---:|---:|---:|---:|---:|
| OpenDR FSM | 128 | 128 | 0.000% | 32,090.00 | 0.084 | 11.22% / 31.17% | 10.67 MiB / 18.84 MiB |
| OpenDJ | 128 | 128 | 0.000% | 13,492.43 | 0.215 | 48.98% / 183.65% | 842.24 MiB / 971.80 MiB |

Per-level concurrent SASL PLAIN fixture-user bind results:

| Product / runtime | Clients | Successes / attempts | Failure % | Success ops/s | Mean ms | P95 ms | P99 ms |
|---|---:|---:|---:|---:|---:|---:|---:|
| OpenDR FSM | 1 | 20 / 20 | 0.00 | 12,456.31 | 0.075 | 0.102 | 0.103 |
| OpenDR FSM | 4 | 80 / 80 | 0.00 | 22,627.58 | 0.091 | 0.129 | 0.235 |
| OpenDR FSM | 8 | 160 / 160 | 0.00 | 30,899.32 | 0.229 | 0.419 | 0.651 |
| OpenDR FSM | 16 | 320 / 320 | 0.00 | 29,047.64 | 0.495 | 0.794 | 0.987 |
| OpenDR FSM | 32 | 640 / 640 | 0.00 | 32,090.00 | 0.890 | 1.397 | 1.820 |
| OpenDR FSM | 64 | 1280 / 1280 | 0.00 | 28,361.15 | 2.075 | 2.540 | 2.758 |
| OpenDR FSM | 128 | 2560 / 2560 | 0.00 | 29,585.77 | 3.890 | 6.106 | 6.795 |
| OpenDJ | 1 | 20 / 20 | 0.00 | 3,339.83 | 0.295 | 0.381 | 0.471 |
| OpenDJ | 4 | 80 / 80 | 0.00 | 9,511.73 | 0.399 | 0.624 | 0.941 |
| OpenDJ | 8 | 160 / 160 | 0.00 | 13,492.43 | 0.550 | 1.139 | 1.955 |
| OpenDJ | 16 | 320 / 320 | 0.00 | 3,576.15 | 4.257 | 6.683 | 67.246 |
| OpenDJ | 32 | 500 / 640 | 21.88 | 5,938.64 | 3.079 | 10.624 | 45.596 |
| OpenDJ | 64 | 1280 / 1280 | 0.00 | 4,712.42 | 11.900 | 73.811 | 79.823 |
| OpenDJ | 128 | 2560 / 2560 | 0.00 | 6,788.31 | 18.171 | 68.099 | 72.624 |

## Index Type Results

OpenDR rows are from GitHub Actions run `24546834381` at `target/perf/release/index/`.
The same OpenDJ index profile at `target/perf/local-opendj-2cpu-4g-20260417T031957Z/index/`
timed out under the same `--cpu 2 --memory 4g` Docker limits and did not
produce complete scalar or mixed index-search benchmark JSON.

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
| OpenDR FSM | index | success | 240s | 8,090.759 | 1009 | 49.15 | 6.65 MiB | 3.28 MiB | 18.627 | 1.015 | 0.417 | 0.934 |
| OpenDJ | index | timeout | 240s | n/a | n/a | 15.62 | 413.63 MiB | 16.14 MiB | n/a | n/a | n/a | n/a |

OpenDR indexed search latency:

| Search probe | Mean ms | P95 ms | P99 ms |
|---|---:|---:|---:|
| Equality `uid` | 0.198 | 0.212 | 0.229 |
| Presence `mail` | 23.660 | 26.701 | 29.068 |
| Substring `description` | 11.543 | 12.288 | 12.426 |
| Ordering `benchmarkOrder >=` | 12.192 | 13.206 | 13.212 |
| Ordering `benchmarkOrder <=` | 12.852 | 14.135 | 14.440 |

Scalar index comparison:

| Search probe | OpenDR mean ms | OpenDJ mean ms |
|---|---:|---:|
| Equality `uid` | 0.198 | n/a |
| Presence `mail` | 23.660 | n/a |
| Substring `description` | 11.543 | n/a |
| Ordering `benchmarkOrder >=` | 12.192 | n/a |
| Ordering `benchmarkOrder <=` | 12.852 | n/a |

OpenDR mixed concurrent index-search results:

| Clients | Successes / attempts | Failure % | Success ops/s | Mean ms | P95 ms | P99 ms |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 20 / 20 | 0.00 | 4,787.44 | 0.194 | 0.240 | 0.246 |
| 4 | 80 / 80 | 0.00 | 6,691.65 | 0.509 | 0.852 | 1.308 |
| 8 | 160 / 160 | 0.00 | 9,810.09 | 0.615 | 1.196 | 1.883 |
| 16 | 320 / 320 | 0.00 | 12,251.69 | 0.980 | 1.717 | 4.019 |
| 32 | 640 / 640 | 0.00 | 11,272.71 | 2.137 | 4.340 | 6.515 |

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
- With the same `--cpu 2 --memory 4g` Docker limits used by the GitHub gate, OpenDR completed the dedicated simple-bind concurrency profile through 128 clients at 0% failure and peaked at `11,584.12` successful binds/sec.
- OpenDJ timed out in the dedicated simple-bind concurrency profile under the same `--cpu 2 --memory 4g` Docker limits.
- OpenDR SASL PLAIN fixture-user binds were faster than OpenDJ in the guarded serial row and reached about `2.38x` higher peak successful SASL PLAIN bind throughput in the `sasl-auth` profile.
- OpenDR completed the index profile and reached 0% failures through 32 mixed concurrent index-search clients, peaking at `12,251.69` successful mixed index searches/sec.
- OpenDJ timed out in the index profile under the same `--cpu 2 --memory 4g` Docker limits, so the latest local comparison did not produce complete OpenDJ scalar or mixed index-search metrics.
- The OpenDR 1M fixture required a 16 GiB LMDB map and produced a 3.20 GiB data directory.
- The OpenDR 1M auth concurrency artifact reached 0% failures through 128 clients for both simple bind and SASL PLAIN, peaking at `17,008.19` simple binds/sec and `48,469.70` SASL PLAIN binds/sec.
- There is still no completed 10M-user OpenDR-vs-OpenDJ benchmark artifact. The largest measured fixture here is the OpenDR-only 1M-user set.

## Artifacts

- OpenDR full profile: `target/perf/release/full/comparison-summary.md` from GitHub Actions run `24546834381`
- OpenDR simple-bind concurrency profile: `target/perf/release/concurrency/comparison-summary.md` from GitHub Actions run `24546834381`
- OpenDR index profile: `target/perf/release/index/comparison-summary.md` from GitHub Actions run `24546834381`
- OpenDR SASL PLAIN concurrency profile: `target/perf/release/sasl/comparison-summary.md` from GitHub Actions run `24546834381`
- OpenDJ comparison profiles: `target/perf/local-opendj-2cpu-4g-20260417T031957Z/`
- OpenDR 1M preload and serial run artifact: `target/perf/opendr-million-16g-20260414-103048/`
- OpenDR 1M serial result: `target/perf/opendr-million-reuse-skipcounts-20260414-111120/opendr/million/ldap-benchmark-results.json`
- OpenDR 1M auth concurrency result: `target/perf/opendr-million-concurrency-20260414-113230/opendr/million-auth-concurrency/ldap-benchmark-results.json`

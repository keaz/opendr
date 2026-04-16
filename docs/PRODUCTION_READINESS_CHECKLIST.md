# Production Readiness Checklist

This checklist defines the minimum evidence required before OpenDR is described
as production-ready. Passing unit tests alone is not enough; the release must
also prove protocol compatibility, malformed-input resilience, and sustained
operation behavior.

## Required Evidence

| Gate | Command | Pass criteria | Artifact |
| --- | --- | --- | --- |
| Rust formatting | `cargo fmt --check` | No formatting drift. | CI log |
| Rust tests | `cargo test --workspace --no-fail-fast` | All unit, integration, binary, and doctest-linked workspace targets pass. | CI log |
| Doctests | `cargo test --doc --quiet` | All doctests pass or remain explicitly ignored. | CI log |
| Clippy | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | No warnings. | CI log |
| RFC matrix review | Review `docs/LDAP_RFC_COMPLIANCE_MATRIX.md` and `docs/ROOT_DSE_CAPABILITIES.md` | Every advertised Root DSE capability has a supported or partial matrix row with coverage links. Unsupported rows are not advertised. | Release notes checklist |
| OpenLDAP CLI interoperability | `scripts/ldap_interop_gate.sh` | `ldapsearch`, `ldapadd`, `ldapmodify`, `ldapdelete`, `ldapcompare`, and `ldapmodrdn` cover Bind, StartTLS, Root DSE, Search, Add, Modify, Delete, ModifyDN, Compare, paged results, server-side sort, schema, and operational attributes. | Script log |
| Python client interoperability | `scripts/ldap_interop_gate.sh` | Python `ldap3` binds over StartTLS and reads Root DSE/schema data. | Script log |
| Rust client interoperability | `scripts/ldap_interop_gate.sh` | `ldap_ops_client` completes Bind, Root DSE, Search, Add, Modify, Delete, ModifyDN, Compare, WhoAmI, and Password Modify. | Script log |
| Security review | Review `docs/SECURITY_REVIEW_2026_04_16.md` and linked follow-up issues | No open High or Medium security review finding remains unless the release notes explicitly scope out the affected feature or deployment path. | Review report and linked issues |
| TLS certificate rotation | `TLS_ROTATION_ARTIFACT_DIR=target/tls-rotation-gate/release-candidate ./scripts/tls_rotation_gate.sh` | Restart-required certificate rotation is validated for LDAPS and StartTLS. Active trust succeeds, inactive and stale trust fail, file replacement without restart does not hot reload, and post-restart bind/search succeeds with the new trust anchor. | `target/tls-rotation-gate/release-candidate` |
| Referral and alias interoperability | `scripts/referral_alias_interop.sh` | `ldapsearch` and optional Python `ldap3` cover referral URL, ManageDsaIT, and alias dereference behavior against a prepared fixture. | Script log |
| Replication soak | `SOAK_DURATION_SECS=86400 SOAK_ARTIFACT_DIR=target/replication-soak/release-candidate ./e2e_tests/test_replication_soak.sh` | Two isolated OpenDR instances maintain provider-consumer convergence while repeated ADD, MODIFY, and DELETE operations run for the configured duration. | `target/replication-soak/release-candidate` |
| Replication failure drills | `FAILURE_DRILL_MODE=release FAILURE_DRILL_ARTIFACT_DIR=target/replication-failure-drills/release-candidate ./e2e_tests/test_replication_failure_drills.sh` | Provider restart, consumer restart, provider network interruption, stale cookie with truncated changelog, and operator full-refresh recovery all complete with visible diagnostics and convergence evidence. | `target/replication-failure-drills/release-candidate` |
| Replication audit evidence | Inspect provider and consumer audit logs from the replication soak and failure drills | Audit logs include provider session start/completion, consumer session start/completion/failure, stale-cookie or changelog-gap rejection, reconnect/disconnect records, replica IDs, sanitized provider URLs, cookie/CSN summaries, and no bind passwords or URL credentials. | Provider and consumer audit logs retained with replication drill artifacts |
| BER fuzzing | `FUZZ_GATE_MODE=release FUZZ_GATE_OUTPUT_DIR=target/fuzz-gate/release-candidate ./scripts/fuzz_gate.sh` | `ber_decoder` completes the release fuzz budget with no panic, crash, timeout, sanitizer finding, or unbounded memory growth. | `target/fuzz-gate/release-candidate` |
| Request-handler fuzzing | `FUZZ_GATE_MODE=release FUZZ_GATE_OUTPUT_DIR=target/fuzz-gate/release-candidate ./scripts/fuzz_gate.sh` | `ldap_request_handler` completes the release fuzz budget with no panic, crash, timeout, sanitizer finding, or unbounded memory growth. | `target/fuzz-gate/release-candidate` |
| Load/performance regression | `PERF_GATE_MODE=release PERF_GATE_BASELINE_JSON=target/perf/regression-baseline/opendr/regression-100k/ldap-benchmark-results.json PERF_GATE_OUTPUT_DIR=target/perf/regression-candidate ./scripts/perf_regression_gate.sh` | Regression profile exits 0 and baseline validation stays within the documented threshold. | `target/perf/regression-candidate` |
| Backup/restore drill | `BACKUP_DRILL_MODE=release BACKUP_DRILL_USERS=100000 BACKUP_DRILL_OUTPUT_DIR=target/backup-restore-drill/release-candidate ./scripts/backup_restore_drill.sh` | Production-like LMDB fixture is backed up, inspected, dry-run restored, restored into a clean data directory, and validated through LDAP binds, indexed searches, operational attributes, and contextCSN evidence. | `target/backup-restore-drill/release-candidate` |
| Deployment rollback drill | `DEPLOYMENT_DRILL_MODE=release DEPLOYMENT_DRILL_OUTPUT_DIR=target/deployment-rollback-drill/release-candidate ./scripts/deployment_rollback_drill.sh` | Isolated provider/consumer deployment, provider backup, failed deployment marker, provider restore, consumer rebootstrap, and post-rollback live replication all pass. | `target/deployment-rollback-drill/release-candidate` |

## Release Decision Rules

- A release may claim production readiness only for RFC rows marked `Supported`
  or for the documented subset of rows marked `Partial`.
- Any new Root DSE `supportedControl`, `supportedExtension`,
  `supportedFeatures`, or `supportedSASLMechanisms` value must update the RFC
  matrix and add an interop or protocol regression test before release.
- Unsupported controls and features must either be absent from Root DSE or have a
  documented intentional rejection path with tests for critical and non-critical
  behavior.
- A failed fuzz or interop gate blocks a production-ready release even when the
  Rust test suite passes.
- TLS certificate rotation must use the documented restart-required workflow in
  `docs/TLS_ROTATION.md`; hot reload must not be assumed until a reload API has
  its own tests and operator documentation.
- Open High or Medium findings from
  `docs/SECURITY_REVIEW_2026_04_16.md` block a full production-ready claim
  unless the release notes explicitly scope out that feature or deployment path.
- The deployment runbook in `docs/DEPLOYMENT_RUNBOOK.md` must be followed for
  release-candidate rollback evidence, and `summary.md` from the rollback drill
  must be retained with the release artifacts.
- Release notes must include the exact commands run, the commit SHA, and links
  to retained CI or local artifacts.

## CI Workflow

The manual GitHub workflow `Production Readiness Gate` is the CI entrypoint for
the release gate. It runs the CI-friendly subset directly and prints the longer
fuzz/load commands when those are not run in the same job. For tagged releases,
retain the workflow run, fuzz logs, and performance artifacts with the release
candidate.

The fuzz gate pins `nightly-2026-03-01` because the current ASN.1 dependency
stack is known to compile with that nightly. Revisit the pin when the `rasn`
dependency stack is upgraded or when newer sanitizer support is required. See
`docs/FUZZING.md` for smoke commands, release budgets, artifact retention, and
failure minimization.

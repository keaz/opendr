# LDAP RFC Compliance Matrix

This matrix is the release-tracking source for OpenDR LDAP RFC support. Status
values are:

- `Supported`: implemented, advertised when appropriate, and covered by tests.
- `Partial`: implemented for the documented subset; gaps are explicit.
- `Unsupported`: not implemented and not advertised.
- `Intentionally unsupported`: deliberately rejected or omitted for safety.
- `Untested`: behavior exists or is planned, but the release gate does not yet
  prove it.

Production releases must keep this file, `ROOT_DSE_CAPABILITIES.md`, and the
readiness checklist in sync with code changes.

## LDAPv3 Core RFCs

| RFC | Area | Status | Implementation and docs | Coverage and gate | Notes |
| --- | --- | --- | --- | --- | --- |
| RFC 4510 | LDAPv3 roadmap | Supported | This matrix links the RFC 4511-4519 rows that make up the LDAPv3 profile. | `cargo test --workspace --no-fail-fast`; `scripts/ldap_interop_gate.sh` | Roadmap RFC only; no protocol surface by itself. |
| RFC 4511 | Protocol operations, BER messages, controls, result codes | Partial | `src/server.rs`, `src/fsm_server.rs`, `src/ber_decoder_fsm.rs`, `src/parser.rs`, `docs/ROOT_DSE_CAPABILITIES.md` | `tests/ldap_ops_client_integration.rs`, `tests/paged_results_integration.rs`, `tests/server_side_sort_integration.rs`, `fuzz/fuzz_targets/ber_decoder.rs`, `fuzz/fuzz_targets/ldap_request_handler.rs` | Bind, Search, Add, Modify, Delete, ModifyDN, Compare, Abandon, Unbind, extended ops, and known controls are covered. Arbitrary client behavior still requires the interop and fuzz gates. |
| RFC 4512 | Directory information model, Root DSE, subschema | Partial | `src/schema.rs`, `src/search_protocol.rs`, `docs/schema_integration.md`, `docs/ROOT_DSE_CAPABILITIES.md` | `tests/schema_integration.rs`, `tests/schema_adapter_integration.rs`, `tests/operational_attrs_server_integration.rs`, `scripts/ldap_interop_gate.sh` | Core schema publication and validation are present; advanced schema elements outside the documented built-ins remain partial. |
| RFC 4513 | Authentication and security mechanisms | Partial | `src/auth_fsm.rs`, `src/sasl_mechanisms.rs`, `src/tls.rs`, `docs/PRODUCTION_SECURITY_PROFILE.md` | `tests/legacy_runtime_security_integration.rs`, `tests/tls_runtime_integration.rs`, `tests/security_integration.rs` | Simple bind, anonymous policy controls, StartTLS/LDAPS, and SASL PLAIN over confidential transports are covered. Broader SASL mechanism coverage is unsupported. |
| RFC 4514 | DN string representation | Supported | `src/dn.rs`, `docs/LDAP_REFERRAL_ALIAS_SUPPORT.md` | `dn::tests::*`, `tests/referral_integration.rs` | DN parsing and canonicalization are shared by scope matching, ACI, referrals, and ModifyDN validation. |
| RFC 4515 | Search filter string representation | Partial | `src/parser.rs`, `src/ldap_filter_eval.rs`, `src/search_adapters/` | `tests/search_adapters_integration.rs`, `tests/indexing_integration.rs`, `tests/real_time_propagation_tests.rs` | Common equality, presence, substring, ordering, and boolean filters are covered. Unsupported matching-rule variants must remain explicit in docs/tests before advertisement. |
| RFC 4516 | LDAP URL format | Supported | `src/ldap_url.rs`, `docs/LDAP_REFERRAL_ALIAS_SUPPORT.md` | `ldap_url::*` unit tests, `tests/referral_integration.rs`, `scripts/referral_alias_interop.sh` | LDAP and LDAPS URLs are parsed, validated, rendered, and used by referral handling. |
| RFC 4517 | Syntaxes and matching rules | Partial | `src/schema.rs`, `docs/LDAP_SYNTAX_MATCHING_SUPPORT.md` | `tests/schema_integration.rs`, `tests/config_integration.rs`, `tests/indexing_integration.rs` | DN, directory string, IA5 string, boolean, integer, generalized time, and binary handling are covered where documented. |
| RFC 4518 | Internationalized string preparation | Partial | `src/schema.rs`, `docs/LDAP_SYNTAX_MATCHING_SUPPORT.md` | `tests/schema_integration.rs`, `tests/indexing_integration.rs` | Case folding and normalization are implemented for documented matching rules; complete stringprep coverage remains partial. |
| RFC 4519 | User application schema | Partial | Built-in schema registry in `src/schema.rs`, `docs/schema_integration.md` | `tests/schema_integration.rs`, `tests/schema_adapter_integration.rs`, `e2e_tests/test_schema_management.sh` | Common user and organization classes are available; full RFC 4519 schema parity is tracked as partial until every class/attribute is covered. |

## Advertised Controls, Extensions, and Features

Every `Yes` row in `docs/ROOT_DSE_CAPABILITIES.md` must have a row here and a
release-gate test.

| RFC | Capability | OID | Root DSE attribute | Status | Implementation and docs | Coverage and gate |
| --- | --- | --- | --- | --- | --- | --- |
| RFC 2696 | Simple Paged Results request control | `1.2.840.113556.1.4.319` | `supportedControl` | Supported | `src/search_controls.rs`, `src/server.rs`, `src/fsm_server.rs`, `docs/ROOT_DSE_CAPABILITIES.md` | `tests/paged_results_integration.rs`, `server::tests::paged_search_*`, `scripts/ldap_interop_gate.sh` |
| RFC 2891 | Server-Side Sort request control | `1.2.840.113556.1.4.473` | `supportedControl` | Supported | `src/server.rs`, `src/fsm_server.rs`, `docs/ROOT_DSE_CAPABILITIES.md` | `tests/server_side_sort_integration.rs`, `scripts/ldap_interop_gate.sh` |
| RFC 3296 | ManageDsaIT request control | `2.16.840.1.113730.3.4.2` | `supportedControl` | Supported | `src/ldap_controls.rs`, `src/referral.rs`, `docs/LDAP_REFERRAL_ALIAS_SUPPORT.md` | `tests/referral_integration.rs`, `scripts/referral_alias_interop.sh` |
| RFC 3909 | Cancel extended operation | `1.3.6.1.1.8` | `supportedExtension` | Supported | `src/extended_ops.rs`, `src/server.rs`, `src/fsm_server.rs` | `tests/security_integration.rs`, `server::tests::cancel_*`, `fsm_server::tests::cancel_*` |
| RFC 4511 / RFC 4513 | StartTLS extended operation | `1.3.6.1.4.1.1466.20037` | `supportedExtension` | Supported | `src/tls.rs`, `src/server.rs`, `src/fsm_server.rs`, `docs/PRODUCTION_SECURITY_PROFILE.md` | `tests/tls_runtime_integration.rs`, `scripts/ldap_interop_gate.sh` |
| RFC 4525 | Modify-Increment feature | `1.3.6.1.1.14` | `supportedFeatures` | Supported | `src/backend.rs`, `src/backend_lmdb.rs`, `src/server.rs`, `src/fsm_server.rs`, `docs/LDAP_CONTROL_EXTENSION_COMPATIBILITY.md` | `server::tests::modify_increment_*`, `tests/backend_lmdb_integration.rs` |
| RFC 4527 | Pre-Read request control | `1.3.6.1.1.13.1` | `supportedControl` | Unsupported | `docs/LDAP_CONTROL_EXTENSION_COMPATIBILITY.md` | Critical/non-critical behavior covered by `server::tests::unsupported_expected_controls_follow_generic_criticality_semantics` |
| RFC 4527 | Post-Read request control | `1.3.6.1.1.13.2` | `supportedControl` | Unsupported | `docs/LDAP_CONTROL_EXTENSION_COMPATIBILITY.md` | Critical/non-critical behavior covered by `server::tests::unsupported_expected_controls_follow_generic_criticality_semantics` |
| RFC 4528 | Assertion request control | `1.3.6.1.1.12` | `supportedControl` | Unsupported | `docs/LDAP_CONTROL_EXTENSION_COMPATIBILITY.md` | Critical/non-critical behavior covered by `server::tests::unsupported_expected_controls_follow_generic_criticality_semantics` |
| RFC 4529 | Request attributes by object class | `1.3.6.1.4.1.4203.1.5.2` | `supportedFeatures` | Unsupported | `docs/LDAP_CONTROL_EXTENSION_COMPATIBILITY.md` | Root DSE tests ensure it is not advertised |
| RFC 4532 | WhoAmI extended operation | `1.3.6.1.4.1.4203.1.11.3` | `supportedExtension` | Supported | `src/extended_ops.rs`, `src/server.rs`, `src/fsm_server.rs` | `tests/ldap_ops_client_integration.rs`, `tests/legacy_runtime_security_integration.rs`, `tests/tls_runtime_integration.rs` |
| RFC 4533 | Content Sync request control | `1.3.6.1.4.1.4203.1.9.1.1` | `supportedControl` | Partial | `src/sync_controls.rs`, `src/replication_*`, `docs/REPLICATION_PRODUCTION_GUARANTEES.md` | `tests/replication_e2e.rs`, `tests/replication_integration.rs`, `tests/replication_consumer_integration.rs` |
| RFC 4533 | Content Sync state response control | `1.3.6.1.4.1.4203.1.9.1.2` | response-only | Supported for response encoding | `src/sync_controls.rs`, `src/server.rs`, `src/fsm_server.rs` | `tests/replication_e2e.rs`, sync-control unit tests |
| RFC 4533 | Content Sync done response control | `1.3.6.1.4.1.4203.1.9.1.3` | response-only | Supported for response encoding | `src/sync_controls.rs`, `src/server.rs`, `src/fsm_server.rs` | `tests/replication_e2e.rs`, sync-control unit tests |
| RFC 3062 | Password Modify extended operation | `1.3.6.1.4.1.4203.1.11.1` | `supportedExtension` | Supported | `src/extended_ops.rs`, `src/server.rs`, `src/fsm_server.rs`, `docs/PRODUCTION_SECURITY_PROFILE.md` | `tests/ldap_ops_client_integration.rs`, `tests/legacy_runtime_security_integration.rs` |

## Release Gate

A release can only claim production readiness for the supported rows above when
these gates pass and their artifacts are retained:

1. `cargo fmt --check`
2. `cargo clippy --workspace --all-targets --all-features -- -D warnings`
3. `cargo test --workspace --no-fail-fast`
4. `cargo test --doc --quiet`
5. `scripts/ldap_interop_gate.sh`
6. `scripts/referral_alias_interop.sh` against a fixture with referral and alias entries
7. `FUZZ_GATE_MODE=release FUZZ_GATE_OUTPUT_DIR=target/fuzz-gate/release-candidate ./scripts/fuzz_gate.sh`
8. Retain `target/fuzz-gate/release-candidate` logs, corpora, dictionaries, and crash artifacts
9. `PERF_GATE_MODE=release PERF_GATE_BASELINE_JSON=target/perf/regression-baseline/opendr/regression-100k/ldap-benchmark-results.json PERF_GATE_OUTPUT_DIR=target/perf/regression-candidate ./scripts/perf_regression_gate.sh`

The manual GitHub workflow `Production Readiness Gate` runs the CI-friendly
subset and documents the longer fuzz and soak commands that must be executed
before a production-ready release is cut.

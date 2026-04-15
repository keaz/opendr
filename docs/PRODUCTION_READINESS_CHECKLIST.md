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
| Referral and alias interoperability | `scripts/referral_alias_interop.sh` | `ldapsearch` and optional Python `ldap3` cover referral URL, ManageDsaIT, and alias dereference behavior against a prepared fixture. | Script log |
| BER fuzzing | `cargo +nightly-2026-03-01 fuzz run ber_decoder -- -runs=10000` | No panic, crash, timeout, or unbounded memory growth. | Fuzz corpus and log |
| Request-handler fuzzing | `cargo +nightly-2026-03-01 fuzz run ldap_request_handler -- -runs=10000` | No panic, crash, timeout, or unbounded memory growth in parser/server request handling. | Fuzz corpus and log |
| Load and soak | `scripts/perf_docker_matrix.sh --products opendr --profile-set regression --output-dir target/perf/regression-candidate` | Exit code 0 and baseline validation within the documented threshold. | `target/perf/regression-candidate` |

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
- Release notes must include the exact commands run, the commit SHA, and links
  to retained CI or local artifacts.

## CI Workflow

The manual GitHub workflow `Production Readiness Gate` is the CI entrypoint for
the release gate. It runs the CI-friendly subset directly and prints the longer
fuzz/load commands when those are not run in the same job. For tagged releases,
retain the workflow run, fuzz logs, and performance artifacts with the release
candidate.

The fuzz commands pin `nightly-2026-03-01` because the current `rasn` dependency
tree does not build with later nightly pointer-metadata checks. Revisit the pin
when the ASN.1 dependency stack is upgraded.

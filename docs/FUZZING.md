# Fuzzing Gate

OpenDR uses `cargo-fuzz` to exercise malformed LDAP BER input at two layers:

- `ber_decoder`: BER frame parsing and decoder FSM buffering.
- `ldap_request_handler`: LDAP message parsing plus server request handling on a
  bounded in-process TCP connection.

The production-readiness gate has two modes. Smoke mode proves both targets are
runnable in CI or on a developer workstation. Release mode is the long-running
gate that must be retained with release-candidate evidence.

## Toolchain

Use the pinned nightly toolchain:

```bash
rustup toolchain install nightly-2026-03-01 --profile minimal
cargo install cargo-fuzz --locked
```

The pin exists because the current ASN.1 dependency stack is known to compile
with `nightly-2026-03-01`. Revisit the pin when the `rasn` dependency stack is
upgraded or when a newer nightly is required for sanitizer support.

## Smoke Gate

Run the short gate before changing parser, request handling, controls, schema,
or replication code:

```bash
FUZZ_GATE_MODE=smoke \
FUZZ_GATE_OUTPUT_DIR=target/fuzz-gate/readiness-smoke \
./scripts/fuzz_gate.sh
```

Smoke mode defaults to 64 libFuzzer runs per target. Override it when needed:

```bash
FUZZ_GATE_MODE=smoke FUZZ_GATE_SMOKE_RUNS=16 ./scripts/fuzz_gate.sh
```

## Release Gate

Before a production-ready release candidate, run a long fuzz gate and retain the
entire output directory:

```bash
FUZZ_GATE_MODE=release \
FUZZ_GATE_RELEASE_MAX_TOTAL_TIME_SECS=21600 \
FUZZ_GATE_OUTPUT_DIR=target/fuzz-gate/release-candidate \
./scripts/fuzz_gate.sh
```

The default release profile runs each target for six hours. A release can use a
run-count budget instead or in addition:

```bash
FUZZ_GATE_MODE=release \
FUZZ_GATE_RELEASE_RUNS=1000000 \
FUZZ_GATE_RELEASE_MAX_TOTAL_TIME_SECS= \
FUZZ_GATE_OUTPUT_DIR=target/fuzz-gate/release-candidate \
./scripts/fuzz_gate.sh
```

For production readiness, each target must finish with no crash, panic, timeout,
or sanitizer finding.

## Artifacts

The wrapper writes:

- `summary.md`: command, status, artifact paths, and reproduction command on
  failure.
- `logs/<target>.log`: full libFuzzer output.
- `corpus/<target>/`: seed and generated corpus for follow-up runs.
- `artifacts/<target>/`: crash, timeout, leak, or oom inputs written by
  libFuzzer.
- `dictionaries/`: dictionary files used by the run.

Retain `target/fuzz-gate/release-candidate` with release evidence. If a smoke
or release run fails, keep the whole output directory until the fix and
regression run are merged.

## Failure Triage

The summary includes a reproduction command when libFuzzer writes an artifact:

```bash
cargo +nightly-2026-03-01 fuzz run ldap_request_handler target/fuzz-gate/.../artifacts/ldap_request_handler/crash-...
```

Minimize the input before debugging or filing a follow-up issue:

```bash
cargo +nightly-2026-03-01 fuzz tmin ldap_request_handler \
  target/fuzz-gate/.../artifacts/ldap_request_handler/crash-... \
  target/fuzz-gate/.../artifacts/ldap_request_handler/minimized-crash
```

If the failure is corpus-dependent, minimize the corpus:

```bash
cargo +nightly-2026-03-01 fuzz cmin ldap_request_handler \
  target/fuzz-gate/release-candidate/corpus/ldap_request_handler
```

After fixing the bug, add the minimized artifact to the relevant regression
test when it can be represented as a deterministic unit or integration test.
Promote useful non-sensitive corpus entries into the fuzz corpus only after
checking that they do not contain production data or secrets.

## Dictionary

`fuzz/dictionaries/ldap.dict` contains BER tags, LDAP operation bytes, common
attributes, DNs, and control OIDs. Update it when adding new controls,
extensions, request handlers, or schema-heavy parser behavior.

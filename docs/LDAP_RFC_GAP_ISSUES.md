# LDAP RFC Implementation Gap Issue Backlog

This backlog converts the current RFC gap analysis into actionable GitHub issues.
It is based on the codebase implementation surface (`src/`, `tests/`, `docs/`) and
current RFC statuses in `docs/LDAP_RFC_COMPLIANCE_MATRIX.md`.

## Scope and method

- Reviewed server architecture and protocol paths in `src/server.rs`,
  `src/fsm_server.rs`, `src/parser.rs`, `src/ldap_controls.rs`,
  `src/extended_ops.rs`, `src/search_controls.rs`, `src/schema.rs`,
  `src/operational_attrs.rs`, and replication modules.
- Mapped those implementation points to RFC support states already tracked in
  `docs/LDAP_RFC_COMPLIANCE_MATRIX.md` and Root DSE capability claims in
  `docs/ROOT_DSE_CAPABILITIES.md`.
- Cross-checked RFC currency/status against RFC Editor pages for the RFCs listed
  below (approved/current stream documents, excluding obsoleted predecessors).

---

## Issue 1: Complete RFC 4511 edge-case protocol compliance gate

**Type:** enhancement / compliance
**RFCs:** RFC 4511 (LDAP protocol)
**Gap summary:** Core operations are implemented, but compliance remains marked
`Partial` because release gating does not yet prove a full edge-case matrix for
message sequencing, malformed BER tolerance boundaries, and control interaction
semantics.

### Requirement
Expand protocol conformance to a release-gated, reproducible RFC 4511 edge-case
suite covering operation semantics and error behavior.

### Acceptance Criteria
- Add explicit test matrix mapping RFC 4511 sections to executable tests.
- Validate negative-path behavior for malformed PDUs and illegal message
  combinations with precise LDAP result codes.
- Validate abandon/cancel/unbind sequencing and message ID lifecycle behavior
  under concurrency.
- **Complete unit, integration, and e2e tests against RFC requirements** with a
  traceability table (RFC clause → test name).
- Update compliance matrix row from `Partial` to `Supported` only after tests
  pass in CI/release gate.

### Definition of Done
- Code and tests merged.
- Compliance docs updated.
- Release gate includes the new RFC 4511 test target.

---

## Issue 2: Close remaining RFC 4512 model/subschema interoperability gaps

**Type:** enhancement / compliance
**RFCs:** RFC 4512
**Gap summary:** Schema model and Root DSE/subschema support are strong but row
remains `Partial` pending broader interoperability and proof of complete surface
coverage.

### Requirement
Complete RFC 4512 interoperability behavior and validate all published model
constraints through interop-grade tests.

### Acceptance Criteria
- Add missing behavioral tests for model constraints and subschema discovery
  paths used by common LDAP clients.
- Validate DIT structure rule and name form enforcement across add/modify/rename
  lifecycles.
- Validate Root DSE/subschema entry consistency for all supported schema bundles.
- **Complete unit, integration, and e2e tests against RFC requirements** with
  clause-level mapping.
- Upgrade RFC 4512 matrix row to `Supported` only after gate coverage is green.

### Definition of Done
- Missing model behaviors implemented.
- New interop tests run in CI.
- Documentation updated to reflect final conformance status.

---

## Issue 3: Implement RFC 4526 absolute True/False filters

**Type:** feature / protocol
**RFCs:** RFC 4526 (absolute true/false filters), RFC 4511/4515 interaction
**Gap summary:** Filter parsing/evaluation exists, but absolute TRUE/FALSE
filters are currently unsupported.

### Requirement
Add parser, AST representation, evaluator logic, and protocol handling for RFC
4526 absolute true and false filters.

### Acceptance Criteria
- BER and string filter parsing accept RFC 4526 encodings.
- Evaluator semantics match RFC requirements for `TRUE` and `FALSE` assertions.
- Search behavior is validated for base/one/sub scopes and compound boolean
  expressions.
- Unsupported-client fallback behavior remains RFC-compliant.
- **Complete unit, integration, and e2e tests against RFC requirements**,
  including interop checks with ldapsearch-compatible clients.

### Definition of Done
- RFC 4526 marked `Supported` in matrix and capability docs where applicable.
- Regression coverage protects parser and evaluator paths.

---

## Issue 4: Add RFC 4528 Assertion request control

**Type:** feature / control
**RFCs:** RFC 4528
**Gap summary:** Assertion control OID is not implemented and not advertised.

### Requirement
Implement server-side evaluation of assertion request controls for write
operations with full criticality semantics.

### Acceptance Criteria
- OID `1.3.6.1.1.12` decoded and enforced for relevant operations.
- Criticality behavior matches RFC 4511 control-processing semantics.
- Assertion mismatch returns correct result codes without side effects.
- Root DSE `supportedControl` advertises only when fully implemented.
- **Complete unit, integration, and e2e tests against RFC requirements**,
  including malformed assertion filters and mixed-control requests.

### Definition of Done
- Control is production-ready and documented.
- Compatibility matrix and Root DSE capability docs updated.

---

## Issue 5: Finish RFC 3673 operational-attributes feature advertisement

**Type:** compliance / discovery
**RFCs:** RFC 3673
**Gap summary:** Operational attribute retrieval via `+` works, but RFC 3673
feature OID advertisement is incomplete (`Partial`).

### Requirement
Align operational attribute behavior and feature advertisement to full RFC 3673
expectations.

### Acceptance Criteria
- Ensure `supportedFeatures` includes RFC 3673 feature OID when behavior is
  enabled.
- Validate consistency between requested operational attrs, ACL filtering, and
  projection logic.
- Add startup/runtime checks preventing false advertisement.
- **Complete unit, integration, and e2e tests against RFC requirements** for
  feature discovery and behavior.

### Definition of Done
- RFC 3673 row moves to `Supported`.
- Root DSE capability tests enforce advertisement correctness.

---

## Issue 6: Complete RFC 4533 Content Sync protocol parity

**Type:** enhancement / replication
**RFCs:** RFC 4533
**Gap summary:** Core sync controls are implemented, but overall row is `Partial`
for full protocol parity and edge-case interoperability.

### Requirement
Close remaining RFC 4533 gaps around cookie/state handling, refresh modes,
error semantics, and interoperability.

### Acceptance Criteria
- Define and implement full RFC 4533 mode/transition matrix (refreshOnly,
  refreshAndPersist, present/delete phases, syncUUID/syncDone behavior).
- Harden cookie validity and restart semantics across provider/consumer restarts.
- Validate replication correctness under churn, deletes, moddn, and conflict
  scenarios.
- **Complete unit, integration, and e2e tests against RFC requirements**,
  including multi-node long-running e2e coverage.

### Definition of Done
- RFC 4533 marked `Supported` (or narrowed with explicit remaining clauses).
- Replication docs include protocol guarantees and non-goals.

---

## Issue 7: Implement RFC 3045 vendorName/vendorVersion Root DSE attributes

**Type:** feature / discovery
**RFCs:** RFC 3045
**Gap summary:** Root DSE does not currently publish vendor information.

### Requirement
Add configurable `vendorName` and `vendorVersion` publication in Root DSE with
safe defaults and deterministic formatting.

### Acceptance Criteria
- Root DSE supports RFC 3045 attributes when configured.
- Values are stable, documented, and do not leak sensitive build metadata.
- Compatibility tests validate presence/absence rules.
- **Complete unit, integration, and e2e tests against RFC requirements** for
  discovery behavior.

### Definition of Done
- RFC 3045 status updated to `Supported` (or documented as policy-disabled by
  default with explicit rationale).

---

## Issue 8: Implement RFC 3829 Authorization Identity request/response controls

**Type:** feature / control
**RFCs:** RFC 3829
**Gap summary:** WhoAmI is supported, but RFC 3829 authz identity controls are
unsupported.

### Requirement
Implement RFC 3829 controls with proper interaction rules alongside WhoAmI and
existing auth mechanisms.

### Acceptance Criteria
- Request and response controls are parsed, evaluated, and encoded per RFC 3829.
- Access-control and privacy constraints are applied to returned identities.
- Behavior with anonymous/simple/SASL binds is fully specified and tested.
- **Complete unit, integration, and e2e tests against RFC requirements**.

### Definition of Done
- Supported controls are advertised and documented.
- Security profile docs updated with control usage guidance.

---

## Issue 9: Implement RFC 3876 Matched Values request control

**Type:** feature / control
**RFCs:** RFC 3876
**Gap summary:** Server does not filter returned values via
`valuesReturnFilter`.

### Requirement
Add matched-values request control support to return only attribute values that
satisfy supplied filter constraints.

### Acceptance Criteria
- OID processing and control value parser implemented.
- Multi-valued attributes are filtered without altering stored data.
- Interactions with paging/sorting/subentries controls are RFC-compliant.
- **Complete unit, integration, and e2e tests against RFC requirements**,
  including performance regression checks on large value sets.

### Definition of Done
- Control advertised when implemented.
- Interop docs and control matrix updated.

---

## Issue 10: Implement RFC 4370 Proxied Authorization control

**Type:** feature / security
**RFCs:** RFC 4370
**Gap summary:** Per-operation authorization identity substitution is not
implemented.

### Requirement
Implement proxied authorization with strict policy enforcement, auditing, and
least-privilege defaults.

### Acceptance Criteria
- Proxy authz control parsing and identity switching implemented per operation.
- Authorization decisions combine caller rights, target identity validity, and
  ACI policy.
- Audit trail records actor, asserted identity, operation, and outcome.
- **Complete unit, integration, and e2e tests against RFC requirements**,
  including abuse and privilege-escalation scenarios.

### Definition of Done
- Security review sign-off completed.
- Control advertised only after policy-safe behavior is validated.

---

## Issue 11: Implement RFC 5805 LDAP Transactions extended operations

**Type:** feature / write semantics
**RFCs:** RFC 5805
**Gap summary:** Backend has internal transactionality, but RFC 5805
multi-operation client-visible transactions are unsupported.

### Requirement
Add LDAP transaction begin/end/abort semantics with isolation and rollback
behavior exposed via RFC 5805 extended operations.

### Acceptance Criteria
- Transaction extended operations implemented and validated.
- Multi-operation atomicity and rollback semantics are enforced across write
  types.
- Error cases (timeout, abandon, connection drop) produce RFC-compliant
  outcomes.
- **Complete unit, integration, and e2e tests against RFC requirements**,
  including restart/recovery scenarios.

### Definition of Done
- Docs explain transaction guarantees/limits.
- Capability matrix updated with supported extension OIDs.

---

## Issue 12: Implement RFC 6171 Don't Use Copy control

**Type:** feature / consistency
**RFCs:** RFC 6171
**Gap summary:** `dontUseCopy` control currently unsupported.

### Requirement
Implement `dontUseCopy` semantics for environments with replicated/partial data
sources, with deterministic fallback behavior.

### Acceptance Criteria
- Control parsing and request handling implemented.
- Server honors control by avoiding non-authoritative copies when required.
- Failure behavior and result codes match RFC definitions.
- **Complete unit, integration, and e2e tests against RFC requirements**.

### Definition of Done
- Control listed in compatibility docs and Root DSE only when semantics are
  enforceable.

---

## Issue 13: Add RFC 4530/RFC 5020 schema registration completeness

**Type:** compliance / schema
**RFCs:** RFC 4530 (`entryUUID`), RFC 5020 (`entryDN`)
**Gap summary:** Operational attributes are functionally exposed, but RFC-
specific syntax/matching-rule registration is incomplete.

### Requirement
Register and enforce RFC-defined syntax and matching rules for `entryUUID` and
`entryDN` as first-class schema elements.

### Acceptance Criteria
- Schema includes RFC-consistent attribute/matching-rule definitions.
- Search/compare/filter behavior uses the registered matching rules.
- Root DSE/subschema publication is accurate and stable.
- **Complete unit, integration, and e2e tests against RFC requirements**,
  including schema discovery and compare/filter assertions.

### Definition of Done
- RFC 4530 and RFC 5020 matrix rows updated from `Partial` to `Supported` if
  fully complete.

---

## Issue 14: Expand LDIF support from RFC 2849 subset to full change-record profile

**Type:** feature / import-export
**RFCs:** RFC 2849
**Gap summary:** Startup/schema LDIF support exists; full changerecord and URL
value handling remains partial.

### Requirement
Implement full RFC 2849 changerecord parsing/execution and URI value handling,
or explicitly scope unsupported parts with hard validation.

### Acceptance Criteria
- Parser supports changetype records and associated operation fields.
- URL values and folded/base64 cases handled per RFC rules.
- Error reporting includes source line and RFC-relevant reason.
- **Complete unit, integration, and e2e tests against RFC requirements**,
  including import idempotency and failure rollback behavior.

### Definition of Done
- Operational docs define supported LDIF profiles and migration notes.
- Compliance matrix row reflects final support level.

---

## Recommended rollout plan

1. **High-value protocol/compliance first:** Issues 1, 2, 3, 4, 6.
2. **Discovery/schema correctness:** Issues 5, 7, 13, 14.
3. **Advanced enterprise controls:** Issues 8, 9, 10, 11, 12.

## Suggested standard GitHub issue labels

- `rfc-compliance`
- `ldap-protocol`
- `ldap-control`
- `schema`
- `replication`
- `security`
- `tests-required`
- `needs-unit-tests`
- `needs-integration-tests`
- `needs-e2e-tests`

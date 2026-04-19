# LDAP Control and Extension Compatibility

This matrix records the OpenDR compatibility decision for commonly expected
LDAP controls and extensions from RFC 3672, RFC 4525, RFC 4527, RFC 4528, RFC
4529, RFC 4511, and RFC 4512.

The broader production release matrix is
[LDAP_RFC_COMPLIANCE_MATRIX.md](LDAP_RFC_COMPLIANCE_MATRIX.md).

## Compatibility Matrix

| RFC | Capability | OID | Root DSE attribute | Status | Behavior | Coverage |
| --- | --- | --- | --- | --- | --- | --- |
| RFC 4525 | Modify-Increment feature | `1.3.6.1.1.14` | `supportedFeatures` | Supported | LDAP Modify operation code `increment(3)` atomically increments existing integer attribute values. Invalid increment requests fail without mutating the entry. | `server::tests::modify_increment_updates_integer_attribute_atomically`, `server::tests::modify_increment_rejects_malformed_increment_without_mutating_entry`, `server::tests::convert_modifications_translates_operations_and_values` |
| RFC 3672 | Subentries control | `1.3.6.1.4.1.4203.1.10.1` | `supportedControl` | Supported | BER BOOLEAN TRUE returns subentries and hides normal entries. FALSE returns normal entries and hides subentries. Without the control, subtree and one-level searches hide subentries while base-object searches may return them. | `server::tests::subentries_*`, `tests/rfc_controls_extensions_integration.rs` |
| RFC 4527 | Pre-Read control | `1.3.6.1.1.13.1` | `supportedControl` | Supported | Advertised. Modify, delete, and ModifyDN may request a BER `AttributeSelection`; successful responses include a same-OID response control containing a BER `SearchResultEntry` for the pre-change target entry. Critical requests on other operations are rejected with `unavailableCriticalExtension`; non-critical requests on other operations are ignored. | `read_entry_controls::tests::*`, `server::tests::modify_with_pre_read_returns_prior_entry_control`, `server::tests::malformed_pre_read_modify_is_rejected_without_mutating_entry`, `tests/rfc_controls_extensions_integration.rs` |
| RFC 4527 | Post-Read control | `1.3.6.1.1.13.2` | `supportedControl` | Unsupported | Not advertised. Critical requests are rejected with `unavailableCriticalExtension`; non-critical requests are ignored by the shared control pipeline. | `server::tests::unsupported_expected_controls_follow_generic_criticality_semantics` |
| RFC 4528 | Assertion control | `1.3.6.1.1.12` | `supportedControl` | Unsupported | Not advertised. Critical requests are rejected with `unavailableCriticalExtension`; non-critical requests are ignored by the shared control pipeline. | `server::tests::unsupported_expected_controls_follow_generic_criticality_semantics` |
| RFC 4529 | Request attributes by object class | `1.3.6.1.4.1.4203.1.5.2` | `supportedFeatures` | Supported | Search attribute descriptions such as `@person` expand to the named object class's `MUST` and `MAY` attributes before response attribute selection. Unknown or optioned selectors remain ordinary requested attribute names. | `search_protocol::tests::expands_rfc4529_object_class_attribute_selectors`, `tests/server_handlers.rs`, `tests/rfc_controls_extensions_integration.rs` |

## Supported Behavior

### Modify-Increment

OpenDR supports RFC 4525 by accepting LDAP Modify changes whose operation value
is `3`. The operation is converted to `ModifyOperation::Increment` and applied
inside the backend write path before schema validation and commit.

Rules:

- The modification must carry exactly one increment value.
- The increment value and every existing target attribute value must be valid
  LDAP integer text.
- The target attribute must already exist and have at least one value.
- All existing target values are incremented.
- Overflow of OpenDR's supported integer range fails the modify request.
- Invalid increment requests fail before the stored entry is mutated.
- Unknown modify operation values other than `0`, `1`, `2`, and `3` return LDAP
  `protocolError`; they are not treated as replace.

Root DSE advertises `1.3.6.1.1.14` in `supportedFeatures`.

### Request Attributes by Object Class

OpenDR supports RFC 4529 object-class attribute selection in LDAP Search
requests. Attribute selectors with the form `@objectClassName` are resolved
against the active schema. The selected response attribute list is expanded with
the named object class's `MUST` and `MAY` attributes, including inherited
attributes, and duplicate attribute names are removed case-insensitively.

Rules:

- The feature OID `1.3.6.1.4.1.4203.1.5.2` is advertised in
  `supportedFeatures`.
- `@person` returns the attributes that are present on the result entry and are
  part of `person`'s required or optional attribute set.
- Unknown selectors and selectors with attribute options, such as
  `@person;lang-en`, are left as ordinary requested attribute names.
- The selector does not bypass normal search filtering, access control, or
  operational attribute selection rules.

### Subentries Control

OpenDR supports RFC 3672 by decoding the Subentries request control as a
required BER BOOLEAN. The control is valid only for Search requests through the
shared request-control registry. Root DSE advertises
`1.3.6.1.4.1.4203.1.10.1` in `supportedControl`.

### Pre-Read Control

OpenDR supports RFC 4527 Pre-Read request controls on modify, delete, and
ModifyDN operations. The request control value is decoded as a BER
`AttributeSelection`. On a successful update, OpenDR emits a response control
with OID `1.3.6.1.1.13.1` whose value is a BER `SearchResultEntry` containing
the target entry as it existed before the update.

Rules:

- Root DSE advertises `1.3.6.1.1.13.1` in `supportedControl`.
- Requested attributes follow the same projection rules as search responses,
  including `*`, `+`, and `1.1`.
- The response control is emitted only when the update succeeds.
- Malformed Pre-Read request values return LDAP `protocolError` before the
  entry is mutated.
- Critical Pre-Read requests on unsupported operations return
  `unavailableCriticalExtension`; non-critical Pre-Read requests on those
  operations are ignored.

## Unsupported Controls

The post-read and assertion controls are intentionally not registered as
supported request controls. This keeps Root DSE truthful and relies on RFC 4511
generic control semantics:

- Unknown non-critical request controls are ignored.
- Unknown critical request controls return `unavailableCriticalExtension`.

OpenDR does not emit post-read response controls and does not evaluate
assertion-control preconditions.

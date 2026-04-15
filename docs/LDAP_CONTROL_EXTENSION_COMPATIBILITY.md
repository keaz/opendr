# LDAP Control and Extension Compatibility

This matrix records the OpenDR compatibility decision for commonly expected
LDAP controls and extensions from RFC 4525, RFC 4527, RFC 4528, RFC 4529, RFC
4511, and RFC 4512.

## Compatibility Matrix

| RFC | Capability | OID | Root DSE attribute | Status | Behavior | Coverage |
| --- | --- | --- | --- | --- | --- | --- |
| RFC 4525 | Modify-Increment feature | `1.3.6.1.1.14` | `supportedFeatures` | Supported | LDAP Modify operation code `increment(3)` atomically increments existing integer attribute values. Invalid increment requests fail without mutating the entry. | `server::tests::modify_increment_updates_integer_attribute_atomically`, `server::tests::modify_increment_rejects_malformed_increment_without_mutating_entry`, `server::tests::convert_modifications_translates_operations_and_values` |
| RFC 4527 | Pre-Read control | `1.3.6.1.1.13.1` | `supportedControl` | Unsupported | Not advertised. Critical requests are rejected with `unavailableCriticalExtension`; non-critical requests are ignored by the shared control pipeline. | `server::tests::unsupported_expected_controls_follow_generic_criticality_semantics` |
| RFC 4527 | Post-Read control | `1.3.6.1.1.13.2` | `supportedControl` | Unsupported | Not advertised. Critical requests are rejected with `unavailableCriticalExtension`; non-critical requests are ignored by the shared control pipeline. | `server::tests::unsupported_expected_controls_follow_generic_criticality_semantics` |
| RFC 4528 | Assertion control | `1.3.6.1.1.12` | `supportedControl` | Unsupported | Not advertised. Critical requests are rejected with `unavailableCriticalExtension`; non-critical requests are ignored by the shared control pipeline. | `server::tests::unsupported_expected_controls_follow_generic_criticality_semantics` |
| RFC 4529 | Request attributes by object class | `1.3.6.1.4.1.4203.1.5.2` | `supportedFeatures` | Unsupported | Not advertised. Search attribute descriptions such as `@person` are treated as ordinary requested attribute names and do not expand to object-class attribute sets. | Root DSE capability tests ensure it is not advertised. |

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

## Unsupported Controls

The pre-read, post-read, and assertion controls are intentionally not registered
as supported request controls. This keeps Root DSE truthful and relies on RFC
4511 generic control semantics:

- Unknown non-critical request controls are ignored.
- Unknown critical request controls return `unavailableCriticalExtension`.

OpenDR does not emit pre-read or post-read response controls and does not
evaluate assertion-control preconditions.

## Deferred Feature

RFC 4529 object-class attribute selection is deferred. Root DSE does not publish
the RFC 4529 feature OID, and search requests using `@objectClassName` are not
expanded. Clients should request explicit attributes, `*`, or `+`.

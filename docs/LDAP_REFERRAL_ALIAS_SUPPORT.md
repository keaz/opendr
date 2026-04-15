# LDAP URL, Referral, Alias, and ManageDsaIT Support

This page defines the OpenDR behavior for LDAP URLs, referrals, aliases, and
the ManageDsaIT control. It is the support matrix for RFC 4511, RFC 4512, RFC
4516, and RFC 3296 behavior implemented by the active server runtime.

## Support Matrix

| Area | Status | OpenDR behavior |
| --- | --- | --- |
| RFC 4516 LDAP URL parsing | Supported | `ldap://` and `ldaps://` URLs are parsed with DN, attributes, scope, filter, and extensions. Percent-encoding is validated and decoded before use. |
| RFC 4516 LDAP URL rendering | Supported | URLs can be rendered back to a canonical form with URL-unsafe DN, filter, and extension bytes percent-encoded. |
| Referral result for base search | Supported | A base-object search that resolves to a referral object returns LDAP `referral` with the entry's `ref` URLs. |
| SearchResultReference for subtree/one-level search | Supported | Non-base searches return `SearchResultReference` messages for referral entries in scope. |
| Referral URL rewriting | Not supported | OpenDR preserves configured `ref` URLs exactly. Administrators must include the intended DN, attributes, scope, filter, and extensions in the referral URL. |
| Server-side chaining | Not enabled | The referral FSM has helper-level hop-limit enforcement, but the active server runtime returns referrals instead of chaining. |
| Transparent proxying | Not enabled | The referral FSM has helper-level proxy abstractions, but the active server runtime returns referrals instead of proxying. |
| Referral cycle handling | Bounded by unsupported chaining | Because the active runtime does not chase referrals, referral cycles are returned to clients as referral URLs. FSM helper chaining has a deterministic hop limit. |
| ManageDsaIT request control | Supported for search | `2.16.840.1.113730.3.4.2` is accepted as a request control with no control value. Referral objects are returned as normal entries. |
| ManageDsaIT control value | Rejected | Per RFC 3296, a ManageDsaIT control value is rejected with `protocolError`. |
| Alias deref: neverDerefAliases(0) | Supported | Alias entries are treated as ordinary entries. |
| Alias deref: derefInSearching(1) | Supported | Alias candidates found during search are dereferenced; the search base is not dereferenced. |
| Alias deref: derefFindingBaseObj(2) | Supported | An alias search base is dereferenced; candidates below the base are not dereferenced. |
| Alias deref: derefAlways(3) | Supported | Both search base aliases and in-scope alias candidates are dereferenced. |
| Alias cycle handling | Supported | Alias loops return LDAP `loopDetect`. Missing alias targets return `aliasDereferencingProblem`; malformed aliases return `aliasProblem`. |
| Unknown derefAliases values | Rejected | Values outside `0..=3` return LDAP `protocolError` and are not silently treated as no dereferencing. |

## LDAP URL Contract

Referral URLs stored in the `ref` attribute must be RFC 4516 LDAP URLs. OpenDR
validates the URL shape before returning a referral response or
`SearchResultReference`.

Supported URL components:

- Scheme: `ldap` and `ldaps`.
- Host and port: optional for URL validation; required when the resolver is
  asked to produce a connectable endpoint.
- DN: empty DN and percent-encoded DN bytes are supported.
- Attributes: comma-separated attribute descriptions.
- Scope: `base`, `one`, or `sub`.
- Filter: RFC 4515 filter text carried in the LDAP URL filter field. OpenDR
  validates that the field is parenthesized but does not execute a referral URL
  filter locally.
- Extensions: comma-separated LDAP URL extensions, including `!` critical
  markers and optional values.

OpenDR does not rewrite referral URLs to copy the incoming search request's
base, attributes, scope, or filter. That makes referral behavior deterministic:
the exact configured `ref` values are the exact values returned to clients.

## Interoperability Checks

Manual interoperability checks are documented in
[`scripts/referral_alias_interop.sh`](../scripts/referral_alias_interop.sh).
The script exercises:

- `ldapsearch` referral URL parsing with a base referral.
- `ldapsearch` ManageDsaIT behavior against a referral object.
- `ldapsearch` alias dereference modes.
- Python `ldap3` URL/client behavior when `python3` and `ldap3` are available.

The script assumes a running OpenDR instance with referral and alias fixtures
loaded. It is intentionally manual because it depends on external client tools
and local fixture data.

## Test Coverage

Automated coverage includes:

- RFC 4516 parser and renderer unit tests in `src/ldap_url.rs`.
- Referral URL validation and resolver tests in `tests/referral_integration.rs`.
- Server search tests for referral result responses, `SearchResultReference`,
  ManageDsaIT, all supported alias dereference modes, alias loops, and invalid
  `derefAliases` values in `src/server.rs`.
- Referral FSM tests for helper-level hop-limit behavior in
  `tests/referral_integration.rs`.

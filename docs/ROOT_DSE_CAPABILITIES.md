# Root DSE Capability Advertising

OpenDR Root DSE values describe client-usable capabilities for the current
connection state. Response-only protocol controls are registered internally for
encoding server responses, but they are not published as `supportedControl`
values.

## `supportedControl`

| Control | OID | RFC | Advertised |
| --- | --- | --- | --- |
| Simple Paged Results request | `1.2.840.113556.1.4.319` | RFC 2696 | Yes, request control. |
| Server-Side Sort request | `1.2.840.113556.1.4.473` | RFC 2891 | Yes, request control. |
| Server-Side Sort response | `1.2.840.113556.1.4.474` | RFC 2891 | No, response-only control. |
| ManageDsaIT | `2.16.840.1.113730.3.4.2` | RFC 3296 | Yes, request control. |
| Content Sync request | `1.3.6.1.4.1.4203.1.9.1.1` | RFC 4533 | Yes, request control. |
| Content Sync state | `1.3.6.1.4.1.4203.1.9.1.2` | RFC 4533 | No, response-only control. |
| Content Sync done | `1.3.6.1.4.1.4203.1.9.1.3` | RFC 4533 | No, response-only control. |
| Assertion | `1.3.6.1.1.12` | RFC 4528 | No, unsupported request control. |
| Pre-Read | `1.3.6.1.1.13.1` | RFC 4527 | No, unsupported request control. |
| Post-Read | `1.3.6.1.1.13.2` | RFC 4527 | No, unsupported request control. |

Unknown non-critical request controls are ignored. Unknown critical request
controls are rejected with LDAP `unavailableCriticalExtension` semantics.

## `supportedExtension`

| Extension | OID | Advertised |
| --- | --- | --- |
| StartTLS | `1.3.6.1.4.1.1466.20037` | Only when TLS support is configured and the current connection is not already secure. |
| Cancel | `1.3.6.1.1.8` | Yes. |
| Password Modify | `1.3.6.1.4.1.4203.1.11.1` | Yes. The operation still enforces confidentiality and authorization at request time. |
| WhoAmI | `1.3.6.1.4.1.4203.1.11.3` | Yes. |

## `supportedFeatures`

| Feature | OID | RFC | Advertised |
| --- | --- | --- | --- |
| Modify-Increment | `1.3.6.1.1.14` | RFC 4525 | Yes. |
| Request attributes by object class | `1.3.6.1.4.1.4203.1.5.2` | RFC 4529 | No, deferred. |

## `supportedSASLMechanisms`

`PLAIN` is advertised only on secure connections, because OpenDR rejects SASL
PLAIN on insecure transports. Plain LDAP connections should use StartTLS before
negotiating SASL PLAIN.

## `supportedLDAPVersion`

OpenDR advertises LDAP version `3`.

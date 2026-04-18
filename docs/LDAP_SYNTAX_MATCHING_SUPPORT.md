# LDAP Syntax and Matching Support

OpenDR validates values for every LDAP syntax it advertises in the generated
subschema. Attribute values using an advertised but unsupported syntax are
rejected during schema validation instead of being silently accepted.

## LDAP Syntaxes

| Syntax | OID | Status | Validation |
| --- | --- | --- | --- |
| Boolean | `1.3.6.1.4.1.1466.115.121.1.7` | Supported | Accepts only `TRUE` or `FALSE`. |
| DN | `1.3.6.1.4.1.1466.115.121.1.12` | Supported | Uses the shared RFC 4514 DN parser and canonicalizer. |
| Directory String | `1.3.6.1.4.1.1466.115.121.1.15` | Supported | Requires non-empty UTF-8, rejects control characters, maps whitespace for matching. |
| Generalized Time | `1.3.6.1.4.1.1466.115.121.1.24` | Supported | Accepts `YYYYMMDDHH[MM[SS]][.fraction](Z/+HHMM/-HHMM)` and validates date, time, fraction, and offset ranges. |
| IA5 String | `1.3.6.1.4.1.1466.115.121.1.26` | Supported | Requires ASCII and rejects control characters. |
| Integer | `1.3.6.1.4.1.1466.115.121.1.27` | Supported | Accepts RFC-style decimal integers without leading zeroes; values are normalized within the supported `i128` range. |
| JPEG | `1.3.6.1.4.1.1466.115.121.1.28` | Supported | Accepts stored JPEG bytes exposed through the server string boundary. |
| OID | `1.3.6.1.4.1.1466.115.121.1.38` | Supported | Accepts descriptors or numeric OIDs with valid first and second arcs. |
| Octet String | `1.3.6.1.4.1.1466.115.121.1.40` | Supported | Accepts arbitrary stored octets exposed through the server string boundary. |
| Postal Address | `1.3.6.1.4.1.1466.115.121.1.41` | Supported | Requires one or more non-empty Directory String lines separated by `$`. |
| Telephone Number | `1.3.6.1.4.1.1466.115.121.1.50` | Supported | Requires non-empty PrintableString characters. |

## Matching Rules

| Matching rule | OID | Status | Normalization and comparison |
| --- | --- | --- | --- |
| `objectIdentifierMatch` | `2.5.13.0` | Supported | Lowercases descriptors and validates descriptor or numeric OID syntax. |
| `distinguishedNameMatch` | `2.5.13.1` | Supported | Compares canonical RFC 4514 DNs. |
| `caseIgnoreMatch` | `2.5.13.2` | Supported | Applies whitespace normalization and Unicode-aware case folding for Directory String values. |
| `caseIgnoreSubstringsMatch` | `2.5.13.4` | Supported | Uses the same preparation as `caseIgnoreMatch` for substring fragments. |
| `caseExactMatch` | `2.5.13.5` | Supported | Applies whitespace normalization without case folding. |
| `caseExactSubstringsMatch` | `2.5.13.7` | Supported | Uses the same preparation as `caseExactMatch` for substring fragments. |
| `booleanMatch` | `2.5.13.13` | Supported | Compares exact `TRUE` or `FALSE` values. |
| `integerMatch` | `2.5.13.14` | Supported | Parses strict decimal integers and compares numeric value. |
| `integerOrderingMatch` | `2.5.13.15` | Supported | Uses fixed-width sortable numeric index keys. |
| `octetStringMatch` | `2.5.13.17` | Supported | Compares stored octet-string values exactly at the server string boundary. |
| `telephoneNumberMatch` | `2.5.13.20` | Supported | Ignores spaces and hyphens, then compares case-insensitively. |
| `telephoneNumberSubstringsMatch` | `2.5.13.21` | Supported | Uses telephone-number normalization for substring fragments. |
| `generalizedTimeMatch` | `2.5.13.27` | Supported | Normalizes offsets to UTC before comparison. |
| `generalizedTimeOrderingMatch` | `2.5.13.28` | Supported | Uses UTC fixed-fraction keys for ordering and indexes. |
| `caseExactIA5Match` | `1.3.6.1.4.1.1466.109.114.1` | Supported | Requires IA5 syntax and collapses whitespace without case folding. |
| `caseIgnoreIA5Match` | `1.3.6.1.4.1.1466.109.114.2` | Supported | Requires IA5 syntax, collapses whitespace, and lowercases ASCII. |
| `caseIgnoreIA5SubstringsMatch` | `1.3.6.1.4.1.1466.109.114.3` | Supported | Uses the same preparation as `caseIgnoreIA5Match` for substring fragments. |

Unsupported matching rules are rejected as inappropriate matching during filter
validation, compare validation, or index planning. Approximate matching is not
advertised as supported.

## Consistency Guarantees

Search filters, Compare operations, extensible matches, and LMDB typed index
keys all resolve matching rules through the same schema layer. An indexed
candidate lookup must therefore use the same normalized assertion value as the
non-indexed evaluator for the supported matching rules above.

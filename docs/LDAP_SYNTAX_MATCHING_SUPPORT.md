# LDAP Syntax and Matching Support

OpenDR validates values for every LDAP syntax it advertises in the generated
subschema. Attribute values using an advertised but unsupported syntax are
rejected during schema validation instead of being silently accepted.

The RFC 4517 syntax and matching-rule declarations are loaded from
`resources/schema/core/rfc4517.ldif`; Rust code owns the validators,
normalizers, ordering keys, and matching-rule execution.

## LDAP Syntaxes

| Syntax | OID | Status | Validation |
| --- | --- | --- | --- |
| Attribute Type Description | `1.3.6.1.4.1.1466.115.121.1.3` | Supported | Parses the RFC 4512 attribute type description grammar. |
| Binary | `1.3.6.1.4.1.1466.115.121.1.5` | Supported | Accepts arbitrary binary payloads exposed through the server string boundary. |
| Bit String | `1.3.6.1.4.1.1466.115.121.1.6` | Supported | Accepts only quoted bit strings such as `'1010'B`. |
| Boot Parameter | `1.3.6.1.1.1.0.1` | Supported | Validates RFC 2307 boot parameters in `key=server:path` form. |
| Boolean | `1.3.6.1.4.1.1466.115.121.1.7` | Supported | Accepts only `TRUE` or `FALSE`. |
| Certificate | `1.3.6.1.4.1.1466.115.121.1.8` | Supported | Parses X.509 certificate values as DER, PEM, or base64 DER at the schema boundary. |
| Country String | `1.3.6.1.4.1.1466.115.121.1.11` | Supported | Requires exactly two PrintableString characters. |
| DN | `1.3.6.1.4.1.1466.115.121.1.12` | Supported | Uses the shared RFC 4514 DN parser and canonicalizer. |
| Delivery Method | `1.3.6.1.4.1.1466.115.121.1.14` | Supported | Accepts the RFC delivery method keywords separated by `$`. |
| Directory String | `1.3.6.1.4.1.1466.115.121.1.15` | Supported | Requires non-empty UTF-8, rejects control characters, maps whitespace for matching. |
| DIT Content Rule Description | `1.3.6.1.4.1.1466.115.121.1.16` | Supported | Parses the RFC 4512 DIT content rule grammar. |
| DIT Structure Rule Description | `1.3.6.1.4.1.1466.115.121.1.17` | Supported | Parses the RFC 4512 DIT structure rule grammar. |
| Enhanced Guide | `1.3.6.1.4.1.1466.115.121.1.21` | Supported | Validates `objectClass#criteria#subset` with supported guide criteria and subsets. |
| Facsimile Telephone Number | `1.3.6.1.4.1.1466.115.121.1.22` | Supported | Validates the telephone number and known fax parameters. |
| Fax | `1.3.6.1.4.1.1466.115.121.1.23` | Supported | Accepts stored fax bytes exposed through the server string boundary. |
| Generalized Time | `1.3.6.1.4.1.1466.115.121.1.24` | Supported | Accepts `YYYYMMDDHH[MM[SS]][.fraction](Z/+HHMM/-HHMM)` and validates date, time, fraction, and offset ranges. |
| Guide | `1.3.6.1.4.1.1466.115.121.1.25` | Supported | Validates `objectClass#criteria` guide values. |
| IA5 String | `1.3.6.1.4.1.1466.115.121.1.26` | Supported | Requires ASCII and rejects control characters. |
| Integer | `1.3.6.1.4.1.1466.115.121.1.27` | Supported | Accepts RFC-style decimal integers without leading zeroes; values are normalized within the supported `i128` range. |
| JPEG | `1.3.6.1.4.1.1466.115.121.1.28` | Supported | Accepts stored JPEG bytes exposed through the server string boundary. |
| Matching Rule Description | `1.3.6.1.4.1.1466.115.121.1.30` | Supported | Parses the RFC 4512 matching rule description grammar. |
| Matching Rule Use Description | `1.3.6.1.4.1.1466.115.121.1.31` | Supported | Parses the RFC 4512 matching rule use grammar. |
| Name and Optional UID | `1.3.6.1.4.1.1466.115.121.1.34` | Supported | Validates a DN with an optional `#'bits'B` UID suffix. |
| Name Form Description | `1.3.6.1.4.1.1466.115.121.1.35` | Supported | Parses the RFC 4512 name form grammar. |
| NIS Netgroup Triple | `1.3.6.1.1.1.0.0` | Supported | Validates RFC 2307 triples in `(hostname,username,domainname)` form. |
| Numeric String | `1.3.6.1.4.1.1466.115.121.1.36` | Supported | Accepts only digits and spaces. |
| Object Class Description | `1.3.6.1.4.1.1466.115.121.1.37` | Supported | Parses the RFC 4512 object class description grammar. |
| OID | `1.3.6.1.4.1.1466.115.121.1.38` | Supported | Accepts descriptors or numeric OIDs with valid first and second arcs. |
| Other Mailbox | `1.3.6.1.4.1.1466.115.121.1.39` | Supported | Validates `mailbox-type$mailbox` with a PrintableString type and IA5 mailbox. |
| Octet String | `1.3.6.1.4.1.1466.115.121.1.40` | Supported | Accepts arbitrary stored octets exposed through the server string boundary. |
| Postal Address | `1.3.6.1.4.1.1466.115.121.1.41` | Supported | Requires one or more non-empty Directory String lines separated by `$`. |
| Printable String | `1.3.6.1.4.1.1466.115.121.1.44` | Supported | Accepts non-empty PrintableString characters. |
| Subtree Specification | `1.3.6.1.4.1.1466.115.121.1.45` | Supported | Validates RFC 3672 SubtreeSpecification values, including base, specific exclusions, minimum, maximum, and specification filters. |
| Telephone Number | `1.3.6.1.4.1.1466.115.121.1.50` | Supported | Requires non-empty PrintableString characters. |
| Teletex Terminal Identifier | `1.3.6.1.4.1.1466.115.121.1.51` | Supported | Validates terminal IDs and known `key:value` parameter names. |
| Telex Number | `1.3.6.1.4.1.1466.115.121.1.52` | Supported | Validates `number$country-code$answerback`. |
| UTC Time | `1.3.6.1.4.1.1466.115.121.1.53` | Supported | Accepts `YYMMDDHHMM[SS](Z/+HHMM/-HHMM)` and validates date, time, and offset ranges. |
| LDAP Syntax Description | `1.3.6.1.4.1.1466.115.121.1.54` | Supported | Parses the RFC 4512 LDAP syntax description grammar. |
| Substring Assertion | `1.3.6.1.4.1.1466.115.121.1.58` | Supported | Validates non-empty substring assertion fragments separated by `*`. |

RFC 4517 removed several older LDAP syntaxes such as Presentation Address and
related matching rules. OpenDR does not advertise those removed definitions as
RFC 4517 support. Broader certificate object classes, POSIX/NIS, and COSINE
schema work are tracked in the separate RFC rows that define those schema
elements.

## Matching Rules

String matching rules use RFC 4518/X.520 preparation before rule-specific
insignificant character handling. That preparation maps commonly ignored code
points to nothing, maps separator characters to spaces, applies Unicode Form KC
normalization, rejects prohibited output such as private-use and non-character
code points, and ignores bidirectional restrictions as specified for LDAP.

| Matching rule | OID | Status | Normalization and comparison |
| --- | --- | --- | --- |
| `objectIdentifierMatch` | `2.5.13.0` | Supported | Lowercases descriptors and validates descriptor or numeric OID syntax. |
| `distinguishedNameMatch` | `2.5.13.1` | Supported | Compares canonical RFC 4514 DNs. |
| `caseIgnoreMatch` | `2.5.13.2` | Supported | Applies RFC 4518 preparation, Unicode compatibility normalization, case folding, and insignificant space handling. |
| `caseIgnoreOrderingMatch` | `2.5.13.3` | Supported | Orders by the same normalized value used by `caseIgnoreMatch`. |
| `caseIgnoreSubstringsMatch` | `2.5.13.4` | Supported | Uses the same preparation as `caseIgnoreMatch` for substring fragments. |
| `caseExactMatch` | `2.5.13.5` | Supported | Applies RFC 4518 preparation and insignificant space handling without case folding. |
| `caseExactOrderingMatch` | `2.5.13.6` | Supported | Orders by the same normalized value used by `caseExactMatch`. |
| `caseExactSubstringsMatch` | `2.5.13.7` | Supported | Uses the same preparation as `caseExactMatch` for substring fragments. |
| `numericStringMatch` | `2.5.13.8` | Supported | Applies RFC 4518 preparation, then removes insignificant spaces and compares digit strings. |
| `numericStringOrderingMatch` | `2.5.13.9` | Supported | Orders by the normalized Numeric String value. |
| `numericStringSubstringsMatch` | `2.5.13.10` | Supported | Uses Numeric String normalization for substring fragments. |
| `caseIgnoreListMatch` | `2.5.13.11` | Supported | Applies case-ignore Directory String preparation to `$`-separated list components. |
| `caseIgnoreListSubstringsMatch` | `2.5.13.12` | Supported | Uses case-ignore list normalization for substring matching. |
| `booleanMatch` | `2.5.13.13` | Supported | Compares exact `TRUE` or `FALSE` values. |
| `integerMatch` | `2.5.13.14` | Supported | Parses strict decimal integers and compares numeric value. |
| `integerOrderingMatch` | `2.5.13.15` | Supported | Uses fixed-width sortable numeric index keys. |
| `bitStringMatch` | `2.5.13.16` | Supported | Compares normalized RFC 4517 Bit String values. |
| `octetStringMatch` | `2.5.13.17` | Supported | Compares stored octet-string values exactly at the server string boundary. |
| `octetStringOrderingMatch` | `2.5.13.18` | Supported | Orders stored octet-string values at the server string boundary. |
| `telephoneNumberMatch` | `2.5.13.20` | Supported | Applies RFC 4518 preparation, then removes insignificant spaces and RFC 4518 hyphen characters. |
| `telephoneNumberSubstringsMatch` | `2.5.13.21` | Supported | Uses telephone-number normalization for substring fragments. |
| `uniqueMemberMatch` | `2.5.13.23` | Supported | Compares a canonical DN with an optional normalized UID bit-string suffix. |
| `generalizedTimeMatch` | `2.5.13.27` | Supported | Normalizes offsets to UTC before comparison. |
| `generalizedTimeOrderingMatch` | `2.5.13.28` | Supported | Uses UTC fixed-fraction keys for ordering and indexes. |
| `integerFirstComponentMatch` | `2.5.13.29` | Supported | Extracts and compares an integer first component. |
| `objectIdentifierFirstComponentMatch` | `2.5.13.30` | Supported | Extracts and compares an OID or descriptor first component. |
| `directoryStringFirstComponentMatch` | `2.5.13.31` | Supported | Extracts and compares a Directory String first component using case-ignore preparation. |
| `wordMatch` | `2.5.13.32` | Supported | Matches an assertion against case-folded word tokens; token boundaries are implementation-defined as allowed by RFC 4517. |
| `keywordMatch` | `2.5.13.33` | Supported | Matches an assertion against comma, semicolon, or whitespace-separated keyword tokens; token boundaries are implementation-defined as allowed by RFC 4517. |
| `caseExactIA5Match` | `1.3.6.1.4.1.1466.109.114.1` | Supported | Requires IA5 syntax and collapses whitespace without case folding. |
| `caseIgnoreIA5Match` | `1.3.6.1.4.1.1466.109.114.2` | Supported | Requires IA5 syntax, collapses whitespace, and lowercases ASCII. |
| `caseIgnoreIA5SubstringsMatch` | `1.3.6.1.4.1.1466.109.114.3` | Supported | Uses the same preparation as `caseIgnoreIA5Match` for substring fragments. |
| `caseExactIA5SubstringsMatch` | `1.3.6.1.4.1.4203.1.2.1` | Supported | OpenLDAP-compatible RFC 2307 rule for case-sensitive IA5 substring fragments. |

Unsupported matching rules are rejected as inappropriate matching during filter
validation, compare validation, or index planning. Approximate matching is not
advertised as supported.

## Consistency Guarantees

Search filters, Compare operations, extensible matches, and LMDB typed index
keys all resolve matching rules through the same schema layer. An indexed
candidate lookup must therefore use the same normalized assertion value as the
non-indexed evaluator for the supported matching rules above.

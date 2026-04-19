# LDAP Schema Alignment Findings

OpenDR currently ships a built-in LDAP schema subset that covers common
directory shapes needed by users, containers, static groups, and optional POSIX
account/group data. It is not yet a complete OpenLDAP or OpenDJ schema bundle.

## Findings

OpenDR aligns with the common LDAP model in these areas:

- `organizationalUnit` is the right object class for containers such as
  `ou=people` and `ou=groups`.
- `groupOfNames` is the right object class for DN-valued static groups using
  the `member` attribute.
- `person`, `organizationalPerson`, and `inetOrgPerson` are available for user
  entries, including the full RFC 2798 `inetOrgPerson` attribute set.
- RFC 2307 POSIX/NIS account, group, shadow, host, network, service, protocol,
  RPC, netgroup, map, IEEE 802 device, and bootable device schema is available
  through the optional `posix` built-in schema bundle.
- RFC 4524 COSINE account, document, domain, room, friendly country, RFC 822
  local part, domain-related object, and simple security object schema is
  available through the optional `cosine` built-in schema bundle.
- RFC 4523 X.509 certificate, CRL, certificate pair, supported algorithm, PKI
  user, PKI CA, CRL distribution point, and X.521 security object schema is
  available through the optional `x509` built-in schema bundle. OpenDR validates
  DER-backed X.509 values and executes exact GSER assertion matching for
  certificate serial/issuer, CRL issuer/thisUpdate, certificate-pair issued-to
  and issued-by, and supported-algorithm OID equality rules. OpenDR also
  executes a component-matching subset for certificate serial, issuer, subject,
  key identifiers, validity, private-key validity, subject-public-key algorithm,
  key usage, subject alternative name type, certificate policy,
  certificate-pair component assertions, CRL issuer, CRL date, CRL-number
  ranges, CRL authority key identifier, reason flags, and full-name distribution
  points. Remaining RFC 4523 path-to-name, name-constraint, `otherName` value,
  X.400/EDI general-name, and name-relative-to-CRL-issuer components remain
  deferred.
- `entryDN` is synthesized as an operational attribute for OpenDJ-compatible
  clients that request it explicitly.
- Search responses preserve explicitly requested user attribute spelling, so a
  request for `objectClass` returns `objectClass` instead of the lower-case
  storage key.

For RFC 4519 user schema, OpenDR follows the standard `groupOfNames`
definition: static DN groups require both `cn` and at least one `member`.

Tracked follow-up work:

- GitHub issue #175: document schema alignment findings and compatibility plan.
- GitHub issue #176: expand RFC 4519 core schema coverage.
- GitHub issue #177: add `groupOfUniqueNames` and `uniqueMember`.
- GitHub issue #178: expand RFC 2798 `inetOrgPerson` coverage.
- GitHub issue #179: add RFC 2307 POSIX account and group schema.
- GitHub issue #180: add conformance fixtures, examples, and documentation.
- GitHub issue #190: completed advanced RFC 4512 schema rule enforcement.
- GitHub issue #191: completed RFC 4517 LDAP syntax and matching-rule registry
  support.
- GitHub issue #192: completed RFC 4518 internationalized string preparation
  for schema matching rules.
- GitHub issue #193: completed RFC 4519 user application schema coverage,
  including strict `groupOfNames`.
- GitHub issue #194: completed RFC 2798 `inetOrgPerson` schema coverage.
- GitHub issue #195: completed RFC 2307 POSIX/NIS schema coverage.
- GitHub issue #196: completed RFC 3671 collective attribute schema,
  validation, and search-time projection.
- GitHub issue #197: completed RFC 3672 LDAP subentries schema and search
  visibility behavior.
- GitHub issue #199: completed RFC 4524 COSINE LDAP/X.500 schema coverage.
- GitHub issue #198: partially completed RFC 4523 X.509 certificate schema
  coverage with file-backed definitions, DER-backed value validation, exact GSER
  assertion matching, and a component-matching subset; remaining work is the
  uncommon X.509 path-to-name, name-constraint, `otherName` value, X.400/EDI
  general-name, and name-relative-to-CRL-issuer components.
- GitHub issue #200: move all built-in standard schema definitions from Rust
  literals into bundled schema files while keeping only the schema engine and
  runtime behavior in Rust.

## Recommended DIT Shape

Use `organizationalUnit` entries as containers:

```ldif
dn: ou=people,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
ou: people
description: People

dn: ou=groups,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
ou: groups
description: Groups
```

Use `inetOrgPerson` for normal user entries:

```ldif
dn: uid=alice,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: Alice Example
sn: Example
uid: alice
mail: alice@example.com
userPassword: secret
```

Use `posixAccount` as an auxiliary class when the user must be visible to POSIX
or NSS clients:

```ldif
dn: uid=alice,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
objectClass: posixAccount
cn: Alice Example
sn: Example
uid: alice
uidNumber: 1001
gidNumber: 1000
homeDirectory: /home/alice
loginShell: /bin/zsh
```

Use `groupOfNames` for DN-valued static groups:

```ldif
dn: cn=developers,ou=groups,dc=example,dc=com
objectClass: top
objectClass: groupOfNames
cn: developers
description: Developers group
member: uid=alice,ou=people,dc=example,dc=com
```

Use `groupOfUniqueNames` when unique DN-valued membership is required:

```ldif
dn: cn=admins,ou=groups,dc=example,dc=com
objectClass: top
objectClass: groupOfUniqueNames
cn: admins
description: Administrators group
uniqueMember: uid=alice,ou=people,dc=example,dc=com
```

Use `posixGroup` when group membership should be expressed as login names:

```ldif
dn: cn=developers,ou=groups,dc=example,dc=com
objectClass: top
objectClass: posixGroup
cn: developers
gidNumber: 1000
memberUid: alice
memberUid: bob
```

## Group Model

| Model | Object class | Member attribute | Member value |
| --- | --- | --- | --- |
| Container | `organizationalUnit` | none | none |
| Static DN group | `groupOfNames` | `member` | Full DN |
| Unique static DN group | `groupOfUniqueNames` | `uniqueMember` | Full DN |
| POSIX group | `posixGroup` | `memberUid` | Username |

Do not put `member`, `uniqueMember`, or `memberUid` on an
`organizationalUnit`. A container is not a group.

See [schema_examples/standard-directory.ldif](schema_examples/standard-directory.ldif)
for a complete conformance example that uses `core` plus `posix`.

## Current Support Matrix

| Area | Current support | Notes |
| --- | --- | --- |
| RFC 4517 syntaxes and matching rules | Supported | The built-in subschema advertises the RFC 4517 registry and validates or executes the advertised syntax and matching-rule surface. |
| RFC 4518 string preparation | Supported | Directory String, Numeric String, Telephone Number, and related matching rules use X.520/RFC 4518 preparation before comparison and index key generation. |
| RFC 4519 user schema | Supported | RFC 4519 user attributes and object classes are registered and validated, including strict `groupOfNames`. |
| RFC 4519 `groupOfNames` | Supported | Both `cn` and `member` are required. |
| RFC 4519 `groupOfUniqueNames` | Supported | `uniqueMember` is required and validated with Name and Optional UID syntax. |
| RFC 2798 `inetOrgPerson` | Supported | Full RFC 2798 MAY attribute set is available, including audio/photo, binary/certificate attributes, and `preferredLanguage` validation. |
| RFC 2307 POSIX/NIS | Optional built-in bundle | Load with `load_builtin = ["core", "posix"]` for the full RFC 2307 object class and attribute set, including shadow accounts, hosts, networks, services, protocols, RPCs, netgroups, NIS maps, IEEE 802 devices, and bootable devices. |
| RFC 3671 collective attributes | Supported | The core bundle registers collective attribute subentries, `collectiveAttributeSubentries`, `collectiveExclusions`, and RFC collective attribute types. Values stored on collective subentries are projected virtually into matching search results, filters, and Compare operations, with per-entry exclusions. |
| RFC 3672 LDAP subentries | Supported | The core bundle registers `subentry`, `administrativeRole`, and `subtreeSpecification`, validates subtree specifications, advertises the Subentries request control, and applies RFC 3672 search visibility rules. |
| RFC 4523 X.509 certificate schema | Optional built-in bundle, partial runtime matching | Load with `load_builtin = ["core", "x509"]` for the RFC 4523 attribute, object class, syntax, and matching-rule definitions. Certificate, CRL, certificate-pair, and supported-algorithm values are validated as DER, PEM, or base64 DER. Exact GSER assertion equality rules are executed for certificate serial/issuer, CRL issuer/thisUpdate, certificate-pair issued-to and issued-by, and supported-algorithm OID matching. Component matching executes certificate serial, issuer, subject, key identifiers, validity, private-key validity, subject-public-key algorithm, key usage, subject alternative name type, certificate policy, certificate-pair component, CRL issuer, CRL date, CRL-number range, CRL authority key identifier, reason-flag, and full-name distribution point assertions; remaining component types are deferred. |
| RFC 4524 COSINE LDAP/X.500 | Optional built-in bundle | Load with `load_builtin = ["core", "cosine"]` for the full COSINE attribute and object class set, including account, document, domain, domain-related object, friendly country, RFC 822 local part, room, and simple security object entries. |

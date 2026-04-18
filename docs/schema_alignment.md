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
  entries, including common RFC 2798 employee and contact attributes.
- RFC 2307 `posixAccount` and `posixGroup` are available through the optional
  `posix` built-in schema bundle.
- `entryDN` is synthesized as an operational attribute for OpenDJ-compatible
  clients that request it explicitly.
- Search responses preserve explicitly requested user attribute spelling, so a
  request for `objectClass` returns `objectClass` instead of the lower-case
  storage key.

OpenDR intentionally differs from strict RFC 4519 in one area:

- Strict RFC 4519 `groupOfNames` requires both `cn` and `member`.
- OpenDR allows `groupOfNames` with only `cn` so empty groups can be created in
  the same style commonly used by OpenDJ-compatible clients.

Tracked follow-up work:

- GitHub issue #175: document schema alignment findings and compatibility plan.
- GitHub issue #176: expand RFC 4519 core schema coverage.
- GitHub issue #177: add `groupOfUniqueNames` and `uniqueMember`.
- GitHub issue #178: expand RFC 2798 `inetOrgPerson` coverage.
- GitHub issue #179: add RFC 2307 POSIX account and group schema.
- GitHub issue #180: add conformance fixtures, examples, and documentation.

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
| RFC 4519 containers | Partial, expanded core subset | `organization` and `organizationalUnit` include common contact attributes that OpenDR can validate. |
| RFC 4519 `groupOfNames` | Supported with compatibility relaxation | `member` is allowed but not required. |
| RFC 4519 `groupOfUniqueNames` | Supported | `uniqueMember` is required and validated as a DN. |
| RFC 2798 `inetOrgPerson` | Partial, expanded subset | Common employee/contact attributes are built in; certificate, bit-string, and uncommon telephony syntaxes remain outside the documented subset. |
| RFC 2307 POSIX/NIS | Optional built-in subset | Load with `load_builtin = ["core", "posix"]` for `posixAccount`, `posixGroup`, `uidNumber`, `gidNumber`, `homeDirectory`, `loginShell`, `gecos`, and `memberUid`. |

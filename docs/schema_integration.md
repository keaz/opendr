# LDAP Schema Integration Guide

## Overview

The LDAP schema integration provides schema publication and validation for LDAP write operations. It loads built-in schema definitions plus RFC-style external LDIF schema files, publishes the effective subschema entry, and validates add, modify, and ModifyDN requests against the active registry according to the LDAP schema model in RFC 4512.

## Architecture

### Components

1. **LdapSchema** (`src/schema.rs`)
   - Core schema registry and parser
   - Manages attribute types, object classes, LDAP syntaxes, matching rules, matching rule use, DIT content rules, name forms, and DIT structure rules
   - Validates entries and modified entries against schema rules

2. **LdapSchemaValidator** (`src/schema_adapter.rs`)
   - Adapter between `LdapSchema` and `SchemaValidator` trait
   - Implements validation for Write FSM
   - Handles LDIF parsing and attribute conversion

3. **Server runtime wiring** (`src/main.rs`, `src/server.rs`, `src/fsm_server.rs`)
   - Loads the configured registry once at startup
   - Shares the registry with legacy and FSM server paths
   - Publishes the registry through `cn=Subschema`

## Validation Flow

When a client sends an ADD request:

```
Client ADD Request
       ↓
WriteFsm receives request
       ↓
WriteFsm calls schema_validator.validate_entry(entry)
       ↓
LdapSchemaValidator converts WriteEntry to attributes
       ↓
LdapSchema.validate_entry(attributes) checks:
   - objectClass exists
   - Structural class present
   - Required attributes present
   - Attributes are allowed by MUST/MAY rules
   - Single-value constraints
   - Syntax constraints
       ↓
If valid: Continue to backend storage
If invalid: Return error to client with reason
```

## Usage

### Server Initialization

Schema loading is configured in `config/server.toml`:

```toml
[schema]
enabled = true
schema_dir = "config/schema"
load_builtin = ["core"]
strict_validation = true
allow_online_updates = false
```

The server loads built-in schema bundles before supported files from
`schema_dir` recursively in lexical path order. Supported built-ins are `core`,
the optional RFC 2307 `posix` bundle, the optional RFC 4524 `cosine` bundle,
and the optional RFC 4523 `x509` bundle. The `core` bundle includes the RFC
3672 LDAP subentry definitions from bundled LDIF. Supported file extensions are
`.ldif`, `.schema`, and `.conf`.

Enable POSIX/NIS schema when clients need RFC 2307 account, group, shadow,
host, network, service, protocol, RPC, netgroup, NIS map, IEEE 802 device, or
bootable device entries:

```toml
[schema]
load_builtin = ["core", "posix"]
```

Enable COSINE schema when clients need RFC 4524 account, document, domain,
room, friendly country, or simple security object entries:

```toml
[schema]
load_builtin = ["core", "cosine"]
```

Enable X.509 schema when clients need RFC 4523 certificate, CRL, certificate
pair, supported algorithm, PKI user, PKI CA, CRL distribution point, or X.521
security information entries:

```toml
[schema]
load_builtin = ["core", "x509"]
```

The example fixture
[schema_examples/standard-directory.ldif](schema_examples/standard-directory.ldif)
contains entries that validate against `load_builtin = ["core", "posix"]`.

Bundled schema files can also be generated into a configured schema directory
for inspection, packaging, or controlled customization:

```bash
opendr-setup --config-dir ./config generate-schema --bundle all --overwrite
```

This writes bundled schema files such as `config/schema/core/rfc4517.ldif`,
`config/schema/core/rfc4519.ldif`, `config/schema/core/rfc2798.ldif`,
`config/schema/core/rfc3672.ldif`, `config/schema/core/rfc3671.ldif`,
`config/schema/posix/rfc2307.ldif`, `config/schema/cosine/rfc4524.ldif`,
and `config/schema/x509/rfc4523.ldif`.
The generated files are the same LDIF that backs the built-in bundles. If both
`load_builtin` and generated files are enabled for the same bundle, compatible
duplicate standard definitions are merged idempotently.

### LDAP Subentries

The core schema registers RFC 3672 `subentry`, `administrativeRole`, and
`subtreeSpecification`. `subtreeSpecification` values are validated using the
RFC 3672 GSER-style grammar, including base, specific exclusions, minimum,
maximum, and specification filters.

Subentry entries must be subordinate to an administrative entry that carries
`administrativeRole`. The RFC 3672 Subentries request control
`1.3.6.1.4.1.4203.1.10.1` is advertised in Root DSE. Without the control,
one-level and subtree searches hide subentries while base-object searches can
return them. With a TRUE control value, search returns subentries and hides
normal entries; with FALSE, search returns normal entries and hides subentries.

### Collective Attributes

The core schema also registers RFC 3671 collective attributes from
`resources/schema/core/rfc3671.ldif`. A collective attribute subentry must be
stored below an administrative entry whose `administrativeRole` includes
`collectiveAttributeSpecificArea` or `collectiveAttributeInnerArea`, and the
subentry must include both `subentry` and `collectiveAttributeSubentry` object
classes.

Collective attribute values such as `c-l` are stored on the collective subentry.
At search time, OpenDR projects applicable collective values virtually onto
normal entries according to the subentry's `subtreeSpecification`. The projected
values can be returned in search results, used by search filters, and evaluated
by Compare operations, but they are not persisted on the target entries. Entries can opt out with
`collectiveExclusions`, including `excludeAllCollectiveAttributes` or a specific
collective attribute type such as `c-l`.

### External Schema Files

Create schema definitions as LDIF files under `schema_dir`. Use a private
numeric OID arc for local definitions; do not reuse standard OIDs or names from
the built-in schema. Keep files lexically ordered so dependencies are read
before definitions that use them, for example `10-example-employee.ldif` before
`20-example-groups.ldif`.

Each schema LDIF file should use `dn: cn=schema` and one or more supported
subschema attributes. Define attributes before object classes that reference
them. Define content rules, name forms, and structure rules after the object
classes they target.

```ldif
dn: cn=schema
matchingRules: ( 1.3.6.1.4.1.55555.20.7 NAME 'exampleEmployeeNumberMatch' DESC 'Example employee number equality' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )
matchingRuleUse: ( 1.3.6.1.4.1.55555.20.7 NAME 'exampleEmployeeNumberMatchUse' APPLIES exampleEmployeeNumber )
attributeTypes: ( 1.3.6.1.4.1.55555.20.1 NAME 'exampleEmployeeNumber' DESC 'Example employee number' EQUALITY exampleEmployeeNumberMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.55555.20.2 NAME 'exampleAccessCode' DESC 'Example access code' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.55555.20.3 NAME 'exampleStartTime' DESC 'Example start timestamp' EQUALITY generalizedTimeMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.55555.20.6 NAME 'exampleScore' DESC 'Example integer score' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.55555.20.8 NAME 'exampleExactCode' DESC 'Example case exact code' EQUALITY caseExactMatch SUBSTR caseExactSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
objectClasses: ( 1.3.6.1.4.1.55555.20.100 NAME 'exampleEmployee' DESC 'Example employee entry' SUP inetOrgPerson STRUCTURAL MUST ( exampleEmployeeNumber $ exampleAccessCode ) MAY ( exampleStartTime $ exampleScore $ exampleExactCode ) )
nameForms: ( 1.3.6.1.4.1.55555.20.101 NAME 'exampleEmployeeNameForm' OC exampleEmployee MUST cn )
dITStructureRules: ( 555201 NAME 'exampleEmployeeStructureRule' FORM exampleEmployeeNameForm )
```

Supported LDIF attributes: `attributeTypes`, `objectClasses`, `ldapSyntaxes`, `matchingRules`, `matchingRuleUse`, `dITContentRules`, `nameForms`, and `dITStructureRules`.

Schema load and online schema updates validate cross-element dependencies before
accepting the effective schema. This includes:

- `matchingRuleUse` values referencing known matching rules and known
  attributes in `APPLIES`.
- `dITContentRules` targeting a known structural object class and referencing
  known auxiliary object classes and attributes.
- `nameForms` targeting a known structural object class and referencing known
  naming attributes.
- `dITStructureRules` referencing known name forms and known superior structure
  rule IDs.

Validate definitions before starting or restarting a server:

```bash
cargo run --bin opendr -- --config config/server.toml schema validate
cargo run --bin opendr -- --config config/server.toml schema explain exampleEmployeeNumber
```

After the server loads the schema, clients may create entries that use the
defined object class and attributes:

```ldif
dn: cn=Schema Example One,ou=people,dc=example,dc=org
objectClass: top
objectClass: exampleEmployee
cn: Schema Example One
sn: One
uid: schemaexample1
mail: schemaexample1@example.org
exampleEmployeeNumber: 1001
exampleAccessCode: blue
exampleStartTime: 20260413010101Z
exampleScore: 010
exampleExactCode: CaseToken
```

Validation rejects entries that omit `exampleEmployeeNumber` or
`exampleAccessCode`, provide a non-integer `exampleEmployeeNumber`, write more
than one value for a `SINGLE-VALUE` attribute, or use attributes outside the
allowed object-class set. Search and compare filters are validated against the
same attribute definitions: equality filters use the equality matching rule,
substring filters use the substring matching rule, and ordering filters require
an ordering matching rule.

The RFC 4517 syntax validators and matching-rule normalizers advertised by the
generated subschema are listed in
[LDAP_SYNTAX_MATCHING_SUPPORT.md](LDAP_SYNTAX_MATCHING_SUPPORT.md).
String-based matching rules use RFC 4518/X.520 preparation before producing
comparison values or typed index keys.

### Online Schema Updates

Online updates are disabled by default. Enable them only for deployments that need authorized LDAP clients to update schema without restarting:

```toml
[schema]
allow_online_updates = true
```

When enabled, authenticated Modify requests against `cn=Subschema` may add, delete, or replace supported schema definition attributes. Accepted changes update the shared in-memory registry and are persisted atomically to `config/schema/99-online.ldif` or the same filename under the configured `schema_dir`.

Example online addition:

```ldif
dn: cn=Subschema
changetype: modify
add: attributeTypes
attributeTypes: ( 1.3.6.1.4.1.55555.21.1 NAME 'exampleContractorCode' DESC 'Example contractor code' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
-
add: objectClasses
objectClasses: ( 1.3.6.1.4.1.55555.21.2 NAME 'exampleContractor' DESC 'Example contractor entry' SUP inetOrgPerson STRUCTURAL MUST exampleContractorCode )
```

Safety rules:

- Anonymous schema modification is rejected.
- Normal modify authorization and attribute authorization are still evaluated.
- Deletes and replaces only manage definitions in the online schema store.
- The server rejects updates that break schema dependencies.
- The server rejects updates that would make existing entries invalid.
- Accepted changes survive restart because `99-online.ldif` is loaded with the rest of `schema_dir`.

### Schema CLI

The server binary includes schema administration commands:

```bash
cargo run --bin opendr -- --config config/server.toml schema validate
cargo run --bin opendr -- --config config/server.toml schema dump
cargo run --bin opendr -- --config config/server.toml schema explain employeeNumber
cargo run --bin opendr -- --config config/server.toml schema validate --schema-dir config/schema
```

`schema validate` loads configured built-ins and external files, validates schema dependencies, and validates configured backend indexes against the registry.

### Schema And Indexes

Matching rules and indexes are separate layers. The schema owns attribute
definitions and decides whether equality, substring, ordering, or extensible
matching is legal. The LMDB backend owns which configured attributes and index
types are materialized.

```toml
[[backend.indexes]]
attribute = "exampleScore"
types = ["equality", "ordering"]

[[backend.indexes]]
attribute = "exampleExactCode"
types = ["substring"]
```

When an index is enabled, startup resolves the attribute's matching rule for
the requested index type. Equality indexes store equality-rule normalized
values, substring indexes store 3-character windows from substring-rule
normalized values, and ordering indexes store ordering keys from ordering
matching rules. Startup backfills indexes if the configured type set or resolved
matching-rule OID changes.

## Supported Object Classes

### Core Object Classes

The schema includes these core object classes from RFC 4519:

- **top** (Abstract)
  - Base object class for all entries
  - Required attributes: objectClass

- **person** (Structural)
  - Superior: top
  - Required: cn, sn
  - Optional: userPassword, telephoneNumber, seeAlso, description

- **organizationalPerson** (Structural)
  - Superior: person
  - Optional: title, x121Address, registeredAddress, destinationIndicator, preferredDeliveryMethod, telexNumber, teletexTerminalIdentifier, telephoneNumber, internationalISDNNumber, facsimileTelephoneNumber, street, postOfficeBox, postalCode, postalAddress, physicalDeliveryOfficeName, ou, st, l

- **inetOrgPerson** (Structural)
  - Superior: organizationalPerson
  - Optional: audio, businessCategory, carLicense, departmentNumber, displayName, employeeNumber, employeeType, givenName, homePhone, homePostalAddress, initials, jpegPhoto, labeledURI, mail, manager, mobile, o, pager, photo, roomNumber, secretary, uid, userCertificate, x500UniqueIdentifier, preferredLanguage, userSMIMECertificate, userPKCS12

- **applicationProcess** (Structural)
  - Superior: top
  - Required: cn
  - Optional: seeAlso, ou, l, description

- **country** (Structural)
  - Superior: top
  - Required: c
  - Optional: searchGuide, description

- **dcObject** (Auxiliary)
  - Superior: top
  - Required: dc

- **device** (Structural)
  - Superior: top
  - Required: cn
  - Optional: serialNumber, seeAlso, owner, ou, o, l, description

- **locality** (Structural)
  - Superior: top
  - Optional: street, seeAlso, searchGuide, st, l, description

- **organization** (Structural)
  - Superior: top
  - Required: o
  - Optional: userPassword, searchGuide, seeAlso, businessCategory, x121Address, registeredAddress, destinationIndicator, preferredDeliveryMethod, telexNumber, teletexTerminalIdentifier, telephoneNumber, internationalISDNNumber, facsimileTelephoneNumber, street, postOfficeBox, postalCode, postalAddress, physicalDeliveryOfficeName, st, l, description

- **organizationalRole** (Structural)
  - Superior: top
  - Required: cn
  - Optional: x121Address, registeredAddress, destinationIndicator, preferredDeliveryMethod, telexNumber, teletexTerminalIdentifier, telephoneNumber, internationalISDNNumber, facsimileTelephoneNumber, seeAlso, roleOccupant, street, postOfficeBox, postalCode, postalAddress, physicalDeliveryOfficeName, ou, st, l, description

- **organizationalUnit** (Structural)
  - Superior: top
  - Required: ou
  - Optional: businessCategory, description, destinationIndicator, facsimileTelephoneNumber, internationalISDNNumber, l, physicalDeliveryOfficeName, postalAddress, postalCode, postOfficeBox, preferredDeliveryMethod, registeredAddress, searchGuide, seeAlso, st, street, telephoneNumber, teletexTerminalIdentifier, telexNumber, userPassword, x121Address

- **groupOfNames** (Structural)
  - Superior: top
  - Required: cn, member
  - Optional: businessCategory, seeAlso, owner, ou, o, description

- **groupOfUniqueNames** (Structural)
  - Superior: top
  - Required: cn, uniqueMember
  - Optional: businessCategory, seeAlso, owner, description, o, ou

- **residentialPerson** (Structural)
  - Superior: person
  - Required: l
  - Optional: businessCategory, x121Address, registeredAddress, destinationIndicator, preferredDeliveryMethod, telexNumber, teletexTerminalIdentifier, telephoneNumber, internationalISDNNumber, facsimileTelephoneNumber, street, postOfficeBox, postalCode, postalAddress, physicalDeliveryOfficeName, st, l

- **uidObject** (Auxiliary)
  - Superior: top
  - Required: uid

### POSIX Object Classes

The optional `posix` built-in bundle includes these RFC 2307 classes:

- **posixAccount** (Auxiliary)
  - Superior: top
  - Required: cn, uid, uidNumber, gidNumber, homeDirectory
  - Optional: userPassword, loginShell, gecos, description

- **shadowAccount** (Auxiliary)
  - Superior: top
  - Required: uid
  - Optional: userPassword, shadowLastChange, shadowMin, shadowMax, shadowWarning, shadowInactive, shadowExpire, shadowFlag, description

- **posixGroup** (Structural)
  - Superior: top
  - Required: cn, gidNumber
  - Optional: userPassword, memberUid, description

- **ipService** (Structural)
  - Superior: top
  - Required: cn, ipServicePort, ipServiceProtocol
  - Optional: description

- **ipProtocol** (Structural)
  - Superior: top
  - Required: cn, ipProtocolNumber, description
  - Optional: description

- **oncRpc** (Structural)
  - Superior: top
  - Required: cn, oncRpcNumber, description
  - Optional: description

- **ipHost** (Auxiliary)
  - Superior: top
  - Required: cn, ipHostNumber
  - Optional: l, description, manager

- **ipNetwork** (Structural)
  - Superior: top
  - Required: cn, ipNetworkNumber
  - Optional: ipNetmaskNumber, l, description, manager

- **nisNetgroup** (Structural)
  - Superior: top
  - Required: cn
  - Optional: nisNetgroupTriple, memberNisNetgroup, description

- **nisMap** (Structural)
  - Superior: top
  - Required: nisMapName
  - Optional: description

- **nisObject** (Structural)
  - Superior: top
  - Required: cn, nisMapEntry, nisMapName
  - Optional: description

- **ieee802Device** (Auxiliary)
  - Superior: top
  - Optional: macAddress

- **bootableDevice** (Auxiliary)
  - Superior: top
  - Optional: bootFile, bootParameter

### COSINE Object Classes

The optional `cosine` built-in bundle includes these RFC 4524 classes:

- **account** (Structural)
  - Superior: top
  - Required: uid
  - Optional: description, seeAlso, l, o, ou, host

- **document** (Structural)
  - Superior: top
  - Required: documentIdentifier
  - Optional: cn, description, seeAlso, l, o, ou, documentTitle, documentVersion, documentAuthor, documentLocation, documentPublisher

- **documentSeries** (Structural)
  - Superior: top
  - Required: cn
  - Optional: description, l, o, ou, seeAlso, telephoneNumber

- **domain** (Structural)
  - Superior: top
  - Required: dc
  - Optional: userPassword, searchGuide, seeAlso, businessCategory, x121Address, registeredAddress, destinationIndicator, preferredDeliveryMethod, telexNumber, teletexTerminalIdentifier, telephoneNumber, internationalISDNNumber, facsimileTelephoneNumber, street, postOfficeBox, postalCode, postalAddress, physicalDeliveryOfficeName, st, l, description, o, associatedName

- **domainRelatedObject** (Auxiliary)
  - Superior: top
  - Required: associatedDomain

- **friendlyCountry** (Structural)
  - Superior: country
  - Required: co

- **rFC822LocalPart** (Structural)
  - Superior: domain
  - Optional: cn, description, destinationIndicator, facsimileTelephoneNumber, internationalISDNNumber, physicalDeliveryOfficeName, postalAddress, postalCode, postOfficeBox, preferredDeliveryMethod, registeredAddress, seeAlso, sn, street, telephoneNumber, teletexTerminalIdentifier, telexNumber, x121Address

- **room** (Structural)
  - Superior: top
  - Required: cn
  - Optional: roomNumber, description, seeAlso, telephoneNumber

- **simpleSecurityObject** (Auxiliary)
  - Superior: top
  - Required: userPassword

### X.509 Object Classes

The optional `x509` built-in bundle registers the RFC 4523 certificate schema
definitions from `resources/schema/x509/rfc4523.ldif`.

- **pkiUser** (Auxiliary)
  - Superior: top
  - Optional: userCertificate

- **pkiCA** (Auxiliary)
  - Superior: top
  - Optional: cACertificate, certificateRevocationList, authorityRevocationList, crossCertificatePair

- **cRLDistributionPoint** (Structural)
  - Superior: top
  - Required: cn
  - Optional: certificateRevocationList, authorityRevocationList, deltaRevocationList

- **deltaCRL** (Auxiliary)
  - Superior: top
  - Optional: deltaRevocationList

- **strongAuthenticationUser** (Auxiliary)
  - Superior: top
  - Required: userCertificate

- **userSecurityInformation** (Auxiliary)
  - Superior: top
  - Optional: supportedAlgorithms

- **certificationAuthority** (Auxiliary)
  - Superior: top
  - Required: authorityRevocationList, certificateRevocationList, cACertificate
  - Optional: crossCertificatePair

- **certificationAuthority-V2** (Auxiliary)
  - Superior: certificationAuthority
  - Optional: deltaRevocationList

OpenDR validates DER, PEM, and base64 DER values for certificate,
certificate-list, certificate-pair, and supported-algorithm attributes. Exact
RFC 4523 GSER assertion equality rules are executed for `certificateExactMatch`,
`certificateListExactMatch`, `certificatePairExactMatch`, and
`algorithmIdentifierMatch`, so certificate-backed equality filters and Compare
operations can match by serial-number and issuer, CRL issuer and `thisUpdate`,
certificate-pair issued-to and issued-by certificates, and supported-algorithm
OID with absent or NULL parameters. Certificate-pair exact matching is not
eligible for LMDB equality indexes because RFC 4523 permits partial pair
assertions. Component matching rules `certificateMatch`, `certificateListMatch`,
and `certificatePairMatch` execute a standards-based subset: certificate
serial-number, issuer, subject, subject and authority key identifiers,
certificate-valid time, private-key-valid time, subject-public-key algorithm,
key usage, subject alternative name type, certificate policy, and
path-to-name checks against certificate NameConstraints, plus name-constraint
assertions including asserted GeneralSubtree minimum/maximum bounds and
`otherName` BOOLEAN, INTEGER, BIT STRING, NULL, object identifier, string, and
OCTET STRING values plus `ediPartyName` values in GeneralSubtree bases;
certificate pair issued-to and issued-by assertions that delegate to those
certificate components; and CRL issuer, date-and-time, CRL-number range,
authority key identifier, reason-flag, full-name distribution point, and
name-relative-to-CRL-issuer distribution point assertions. The remaining RFC
4523 components, including constructed or schema-specific open-type `otherName`
values and X.400 general names, are rejected explicitly until implemented.

### Core Attributes

- **objectClass**: Object class names
- **name**: Name supertype
- **cn** (commonName): Common name
- **sn** (surname): Surname
- **serialNumber**: Device serial number
- **c** (countryName): Two-letter country code, single-value
- **o** (organizationName): Organization name
- **ou** (organizationalUnitName): Organizational unit name
- **uid** (userid): User ID
- **dc** (domainComponent): DNS domain component, single-value
- **mail** (rfc822Mailbox): Email address
- **userPassword**: User password
- **member**: Group member DN
- **uniqueMember**: Unique group member DN with optional UID
- **seeAlso**: Related entry DN
- **owner**: Owner entry DN
- **roleOccupant**: Role occupant entry DN
- **description**: Description
- **businessCategory**: Business category
- **searchGuide**: Search guide
- **enhancedSearchGuide**: Enhanced search guide
- **distinguishedName**: Distinguished name supertype
- **dnQualifier**: DN qualifier
- **destinationIndicator**: Destination indicator
- **givenName**: Given name
- **generationQualifier**: Generation qualifier
- **title**: Title
- **displayName**: Display name
- **initials**: Initials
- **houseIdentifier**: House identifier
- **x500UniqueIdentifier**: X.500 unique identifier
- **carLicense**: Vehicle license or registration plate
- **departmentNumber**: Department number
- **employeeNumber**: Employee number, single-value
- **employeeType**: Employee type
- **homePhone**: Home telephone number
- **homePostalAddress**: Home postal address
- **audio**: Audio recording
- **jpegPhoto**: JPEG photograph
- **photo**: G3 fax encoded photograph
- **labeledURI**: Labeled URI
- **manager**: Manager entry DN
- **mobile**: Mobile telephone number
- **pager**: Pager telephone number
- **preferredLanguage**: Preferred language, single-value
- **userCertificate**: X.509 certificate; `;binary` attribute option is accepted
- **userSMIMECertificate**: S/MIME PKCS#7 SignedData; `;binary` attribute option is accepted
- **userPKCS12**: PKCS #12 PFX PDU; `;binary` attribute option is accepted
- **roomNumber**: Room number
- **secretary**: Secretary entry DN
- **l** (localityName): Locality name
- **st** (stateOrProvinceName): State or province name
- **street**: Street address
- **telephoneNumber**: Telephone number
- **facsimileTelephoneNumber**: Facsimile telephone number
- **telexNumber**: Telex number
- **teletexTerminalIdentifier**: Teletex terminal identifier
- **internationalISDNNumber**: International ISDN number
- **x121Address**: X.121 address
- **preferredDeliveryMethod**: Preferred delivery method, single-value
- **postalAddress**: Postal address
- **registeredAddress**: Registered address
- **postalCode**: Postal code
- **postOfficeBox**: Post office box
- **physicalDeliveryOfficeName**: Physical delivery office name

### POSIX Attributes

- **uidNumber**: Integer user ID, single-value
- **gidNumber**: Integer group ID, single-value
- **gecos**: POSIX GECOS field, IA5 single-value
- **homeDirectory**: Absolute home directory path, IA5 single-value
- **loginShell**: Login shell path, IA5 single-value
- **shadowLastChange**: Shadow password last-change day, integer single-value
- **shadowMin**: Shadow password minimum age, integer single-value
- **shadowMax**: Shadow password maximum age, integer single-value
- **shadowWarning**: Shadow password warning period, integer single-value
- **shadowInactive**: Shadow password inactive period, integer single-value
- **shadowExpire**: Shadow account expiry day, integer single-value
- **shadowFlag**: Reserved shadow password flag, integer single-value
- **memberUid**: POSIX group member login name, IA5 multi-value
- **memberNisNetgroup**: Nested NIS netgroup name, IA5 multi-value
- **nisNetgroupTriple**: NIS netgroup triple in `(host,user,domain)` form
- **ipServicePort**: Service port, integer single-value
- **ipServiceProtocol**: Service protocol name
- **ipProtocolNumber**: IP protocol number, integer single-value
- **oncRpcNumber**: ONC RPC program number, integer single-value
- **ipHostNumber**: IP host address, multi-value
- **ipNetworkNumber**: IP network address, single-value
- **ipNetmaskNumber**: IP netmask address, single-value
- **macAddress**: Colon-separated six-octet MAC address
- **bootParameter**: Boot parameter in `key=server:path` form
- **bootFile**: Boot image name
- **nisMapName**: NIS map name
- **nisMapEntry**: NIS map entry, IA5 single-value

## Validation Rules

### Object Class Validation

1. **Object Class Exists**: All objectClass values must be defined in schema
2. **Structural Class Required**: At least one structural object class must be present
3. **No Abstract-Only Entries**: Cannot have only abstract object classes
4. **Valid Inheritance Chain**: Multiple structural classes must form valid inheritance chain

### Attribute Validation

1. **Required Attributes**: All MUST attributes from object classes must be present.
2. **DIT Content Rules**: Applicable content rule MUST attributes are required, MAY attributes are allowed, NOT attributes are rejected, and auxiliary classes must be allowed by the content rule.
3. **Allowed Attributes**: Only MAY or MUST attributes from object classes and applicable DIT content rules are allowed.
4. **Single-Value Constraints**: Single-value attributes cannot have multiple values.
5. **Case Insensitive**: Attribute and object class names are case-insensitive.

### Modification Validation

1. **Full Entry Check**: The server applies modifications to the current entry image and validates the result
2. **Attribute Exists**: Modified attributes must be defined in schema
3. **Allowed Attributes**: New or retained attributes must be allowed by the resulting object classes
4. **Single-Value Check**: Add/Replace operations check single-value constraints
5. **No User Modification**: `NO-USER-MODIFICATION` attributes are rejected in user writes

### DN Modification Validation

1. **RDN Format**: New RDN must be in "attribute=value" format.
2. **Attribute Exists**: RDN attribute must be defined in schema.
3. **Name Form Check**: When name forms exist for the structural object class, every configured MUST naming attribute must appear in the RDN, every RDN attribute must be listed by the name form's MUST/MAY set, and every RDN value must be present in the candidate entry image.
4. **DIT Structure Rule Check**: When structure rules exist, Add and ModifyDN validate the candidate entry against the parent entry's applicable DIT structure rule before the write is committed.

## Error Handling

The schema validator returns descriptive errors:

- `ObjectClassNotFound`: Unknown object class in entry
- `AttributeNotFound`: Unknown attribute type
- `MissingRequiredAttribute`: Required attribute missing
- `AttributeNotAllowed`: Attribute is not allowed by object class rules
- `NoStructuralClass`: No structural object class defined
- `MultipleStructuralClasses`: Invalid structural class chain
- `SingleValueViolation`: Multiple values for single-value attribute
- `InvalidSyntax`: Attribute value doesn't match syntax
- `NoUserModification`: User attempted to modify a protected operational attribute
- `DitContentRuleViolation`: Entry violates an applicable DIT content rule
- `NamingViolation`: ModifyDN violates RDN or name-form rules
- `StructureRuleViolation`: Add or ModifyDN violates a configured DIT structure rule

Example error message:
```
"Missing required attribute: sn"
"Object class not found: unknownClass"
"Single-value violation for attribute: employeeNumber"
```

## Testing

### Integration Tests

Schema integration is thoroughly tested in:

- `tests/schema_integration.rs` - Core schema validation tests
- `tests/schema_adapter_integration.rs` - Schema adapter with WriteFSM tests
- `e2e_tests/test_schema_management.sh` - LDAP client e2e coverage for external schema loading, custom record creation, schema validation failures, subschema publication, online updates, and schema-aware index validation

Run tests:
```bash
# Run all schema tests
cargo test schema

# Run specific integration tests
cargo test --test schema_adapter_integration

# Run LDAP e2e schema management tests
./e2e_tests/test_schema_management.sh
```

### Test Examples

**Valid Person Entry**:
```rust
let mut attributes = HashMap::new();
attributes.insert("cn".to_string(), vec!["John Doe".to_string()]);
attributes.insert("sn".to_string(), vec!["Doe".to_string()]);

let entry = WriteEntry {
    dn: "cn=John Doe,ou=People,dc=example,dc=com".to_string(),
    attributes,
    object_classes: vec!["top".to_string(), "person".to_string()],
    binary_attributes: HashMap::new(),
};

assert!(validator.validate_entry(&entry).await.is_ok());
```

**Missing Required Attribute**:
```rust
let mut attributes = HashMap::new();
attributes.insert("cn".to_string(), vec!["John Doe".to_string()]);
// Missing 'sn' - should fail

let entry = WriteEntry {
    dn: "cn=John Doe,ou=People,dc=example,dc=com".to_string(),
    attributes,
    object_classes: vec!["top".to_string(), "person".to_string()],
    binary_attributes: HashMap::new(),
};

let result = validator.validate_entry(&entry).await;
assert!(result.is_err());
assert!(result.unwrap_err().contains("Missing required attribute"));
```

## Best Practices

### 1. Use External LDIF Files

Place custom schema in `config/schema` or another configured `schema_dir`. This keeps schema management outside the Rust code and lets deployments validate schema changes before server startup.

### 2. Test Custom Schemas

Always write tests for custom schema definitions:
```rust
#[tokio::test]
async fn test_custom_employee_class() {
    // Test custom schema validation
}
```

### 3. Document Schema Extensions

Document any custom object classes and attributes:
```rust
/// Custom employee object class
///
/// Extends inetOrgPerson with employment-specific attributes
/// Required: employeeNumber
/// Optional: department, manager
schema.add_object_class(ObjectClass {
    // ...
});
```

## Performance Considerations

- **Schema Caching**: Schema is loaded once and shared by the runtime
- **Case-Insensitive Lookups**: Uses lowercase keys for O(1) lookups
- **Minimal Overhead**: Validation is fast hash table lookups

## Future Enhancements

Potential improvements:

1. **Additional Syntax Validators**: Expand strict value checking beyond common RFC syntaxes
2. **Schema Replication Workflow**: Add an operational workflow for distributing externally managed schema files across replicated deployments

## References

- [RFC 4512: LDAP Directory Information Models](https://tools.ietf.org/html/rfc4512)
- [RFC 4519: LDAP Schema for User Applications](https://tools.ietf.org/html/rfc4519)
- [RFC 4523: LDAP Schema Definitions for X.509 Certificates](https://tools.ietf.org/html/rfc4523)
- [RFC 4524: LDAP: COSINE LDAP/X.500 Schema](https://tools.ietf.org/html/rfc4524)

## See Also

- [Write FSM Documentation](write_fsm.md)
- [Architecture Overview](architecture-overview.md)
- [Developer Operations Guide](./DEVELOPER_GUIDE.md)

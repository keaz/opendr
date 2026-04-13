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

The server loads supported files from `schema_dir` in lexical order. Supported extensions are `.ldif`, `.schema`, and `.conf`.

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
  - Optional: userPassword, description

- **organizationalPerson** (Structural)
  - Superior: person
  - Optional: ou, mail

- **inetOrgPerson** (Structural)
  - Superior: organizationalPerson
  - Optional: uid, givenName, mail

- **organization** (Structural)
  - Superior: top
  - Required: o
  - Optional: description

- **organizationalUnit** (Structural)
  - Superior: top
  - Required: ou
  - Optional: description

### Core Attributes

- **objectClass**: Object class names
- **cn** (commonName): Common name
- **sn** (surname): Surname
- **o** (organizationName): Organization name
- **ou** (organizationalUnitName): Organizational unit name
- **uid** (userid): User ID
- **mail** (rfc822Mailbox): Email address
- **userPassword**: User password
- **description**: Description
- **givenName**: Given name

## Validation Rules

### Object Class Validation

1. **Object Class Exists**: All objectClass values must be defined in schema
2. **Structural Class Required**: At least one structural object class must be present
3. **No Abstract-Only Entries**: Cannot have only abstract object classes
4. **Valid Inheritance Chain**: Multiple structural classes must form valid inheritance chain

### Attribute Validation

1. **Required Attributes**: All MUST attributes from object classes must be present
2. **Allowed Attributes**: Only MAY or MUST attributes from object classes are allowed
3. **Single-Value Constraints**: Single-value attributes cannot have multiple values
4. **Case Insensitive**: Attribute and object class names are case-insensitive

### Modification Validation

1. **Full Entry Check**: The server applies modifications to the current entry image and validates the result
2. **Attribute Exists**: Modified attributes must be defined in schema
3. **Allowed Attributes**: New or retained attributes must be allowed by the resulting object classes
4. **Single-Value Check**: Add/Replace operations check single-value constraints
5. **No User Modification**: `NO-USER-MODIFICATION` attributes are rejected in user writes

### DN Modification Validation

1. **RDN Format**: New RDN must be in "attribute=value" format
2. **Attribute Exists**: RDN attribute must be defined in schema
3. **Name Form Check**: When name forms exist for the structural object class, the RDN attribute must satisfy the configured MUST/MAY naming attributes

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
- `NamingViolation`: ModifyDN violates RDN or name-form rules

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
- [RFC 4524: LDAP: COSINE LDAP/X.500 Schema](https://tools.ietf.org/html/rfc4524)

## See Also

- [Write FSM Documentation](write_fsm.md)
- [Architecture Overview](architecture-overview.md)
- [Developer Operations Guide](./DEVELOPER_GUIDE.md)

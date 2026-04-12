# LDAP Schema Integration Guide

## Overview

The LDAP schema integration provides comprehensive schema validation for LDAP write operations. It ensures that all directory entries conform to the LDAP schema, validating object classes, attributes, and structural rules according to RFC 4512.

## Architecture

### Components

1. **LdapSchema** (`src/schema.rs`)
   - Core schema implementation
   - Manages attribute types and object classes
   - Validates entries against schema rules

2. **LdapSchemaValidator** (`src/schema_adapter.rs`)
   - Adapter between `LdapSchema` and `SchemaValidator` trait
   - Implements validation for Write FSM
   - Handles LDIF parsing and attribute conversion

3. **ConnectionFsmSet** (`src/fsm_runtime.rs`)
   - Holds shared schema validator instance
   - Provides schema validator to Write FSMs

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
   - No unknown attributes
   - Single-value constraints
       ↓
If valid: Continue to backend storage
If invalid: Return error to client with reason
```

## Usage

### Server Initialization

The schema validator is automatically integrated when using the FSM server:

```rust
use opendr::fsm_runtime::ConnectionFsmSet;
use opendr::schema_adapter::LdapSchemaValidator;
use std::sync::Arc;

// Create schema validator
let schema_validator = Arc::new(LdapSchemaValidator::new());

// Create connection FSM set with schema validator
let fsm_set = ConnectionFsmSet::new_with_schema_validator(
    stream,
    backend,
    None,  // TLS handler
    Some(schema_validator),
);
```

### Custom Schema

You can extend the core schema with custom object classes and attributes:

```rust
use opendr::schema::{LdapSchema, ObjectClass, AttributeType, ObjectClassKind};
use opendr::schema_adapter::LdapSchemaValidator;

// Create schema with core definitions
let mut schema = LdapSchema::with_core_schema();

// Add custom attribute type
schema.add_attribute_type(AttributeType {
    oid: "1.2.3.4.5".to_string(),
    names: vec!["employeeNumber".to_string()],
    description: Some("Employee number".to_string()),
    equality: Some("caseIgnoreMatch".to_string()),
    syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(),
    single_value: true,
});

// Add custom object class
schema.add_object_class(ObjectClass {
    oid: "1.2.3.4.6".to_string(),
    names: vec!["employee".to_string()],
    sup: vec!["inetOrgPerson".to_string()],
    kind: ObjectClassKind::Auxiliary,
    must: vec!["employeeNumber".to_string()],
    may: vec!["department".to_string()],
});

// Create validator with custom schema
let validator = LdapSchemaValidator::with_schema(schema);
```

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

1. **Attribute Exists**: Modified attributes must be defined in schema
2. **Single-Value Check**: Add/Replace operations check single-value constraints

### DN Modification Validation

1. **RDN Format**: New RDN must be in "attribute=value" format
2. **Attribute Exists**: RDN attribute must be defined in schema

## Error Handling

The schema validator returns descriptive errors:

- `ObjectClassNotFound`: Unknown object class in entry
- `AttributeNotFound`: Unknown attribute type
- `MissingRequiredAttribute`: Required attribute missing
- `NoStructuralClass`: No structural object class defined
- `MultipleStructuralClasses`: Invalid structural class chain
- `SingleValueViolation`: Multiple values for single-value attribute
- `InvalidSyntax`: Attribute value doesn't match syntax

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

Run tests:
```bash
# Run all schema tests
cargo test schema

# Run specific integration tests
cargo test --test schema_adapter_integration
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

### 1. Use Core Schema as Base

Always start with the core schema:
```rust
let mut schema = LdapSchema::with_core_schema();
```

### 2. Define Custom Schemas Early

Add custom object classes and attributes during server initialization:
```rust
// In main.rs or server initialization
let mut schema = LdapSchema::with_core_schema();
schema.add_attribute_type(custom_attr);
schema.add_object_class(custom_class);

let validator = Arc::new(LdapSchemaValidator::with_schema(schema));
```

### 3. Test Custom Schemas

Always write tests for custom schema definitions:
```rust
#[tokio::test]
async fn test_custom_employee_class() {
    // Test custom schema validation
}
```

### 4. Document Schema Extensions

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

- **Schema Caching**: Schema is loaded once and shared via Arc
- **Case-Insensitive Lookups**: Uses lowercase keys for O(1) lookups
- **No Dynamic Loading**: Schema is static after initialization
- **Minimal Overhead**: Validation is fast hash table lookups

## Future Enhancements

Potential improvements:

1. **Dynamic Schema Loading**: Load schema from LDIF files
2. **Schema Modification**: Runtime schema updates via LDAP
3. **Syntax Validation**: Validate attribute values against syntax rules
4. **Matching Rules**: Implement equality and ordering matching rules
5. **DIT Structure Rules**: Validate DIT structure constraints
6. **Name Forms**: Enforce naming constraints

## References

- [RFC 4512: LDAP Directory Information Models](https://tools.ietf.org/html/rfc4512)
- [RFC 4519: LDAP Schema for User Applications](https://tools.ietf.org/html/rfc4519)
- [RFC 4524: LDAP: COSINE LDAP/X.500 Schema](https://tools.ietf.org/html/rfc4524)

## See Also

- [Write FSM Documentation](write_fsm.md)
- [Architecture Overview](architecture-overview.md)
- [Developer Operations Guide](./DEVELOPER_GUIDE.md)

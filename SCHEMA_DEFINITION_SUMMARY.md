# Schema Definition Guide - Complete Summary

## Overview

This document summarizes the complete schema definition and management system for the opendr LDAP server, including where to put schemas, how to define them, and how to use them in your applications.

## What Was Created

### 1. ✅ Comprehensive Documentation

**[docs/SCHEMA_DEFINITION_GUIDE.md](docs/SCHEMA_DEFINITION_GUIDE.md)** - Complete guide
- Schema architecture and components
- File locations and directory structure
- Schema file format (RFC 4512)
- Step-by-step schema definition
- Code implementation
- Best practices
- Comprehensive examples

**[docs/SCHEMA_QUICK_START.md](docs/SCHEMA_QUICK_START.md)** - Quick reference
- 5-minute quick start
- Common tasks
- Quick examples
- Cheat sheets

### 2. ✅ Schema Directory Structure

Created organized schema directory:

```
opendr/
├── config/
│   ├── schema/                      # Schema definitions
│   │   ├── README.md               # Schema directory guide
│   │   ├── employee.schema         # Employee management schema
│   │   └── application.schema      # Application integration schema
│   ├── employees.ldif              # Example employee entries
│   ├── applications.ldif           # Example application entries
│   ├── base.ldif                   # Base DIT structure
│   └── server.toml                 # Server configuration
├── docs/
│   ├── SCHEMA_DEFINITION_GUIDE.md  # Complete guide
│   ├── SCHEMA_QUICK_START.md       # Quick start
│   └── README.md                   # Updated with schema docs
└── src/
    └── schema.rs                   # Schema implementation
```

### 3. ✅ Example Schema Files

**[config/schema/employee.schema](config/schema/employee.schema)** - Employee Management
- Attributes: employeeNumber, department, manager, title, startDate, employeeType, costCenter
- Object Classes: employee (structural), contractor (auxiliary)
- Complete with usage examples and documentation

**[config/schema/application.schema](config/schema/application.schema)** - Application Integration
- Attributes: appId, appSecret, apiKey, callbackUrl, allowedScopes, appType, rateLimit, appStatus
- Object Classes: application (structural), oauthClient (auxiliary), serviceAccount (structural)
- Complete with security notes and examples

**[config/schema/README.md](config/schema/README.md)** - Schema directory guide
- Overview of available schemas
- Usage instructions
- Testing guidelines
- References

### 4. ✅ Example LDIF Entries

**[config/employees.ldif](config/employees.ldif)** - 6 example employee entries
- Full-time employees
- Part-time employees
- Contractors
- Interns
- Demonstrates manager relationships
- Shows department assignments

**[config/applications.ldif](config/applications.ldif)** - 8 example application entries
- Web applications with OAuth
- Mobile applications (iOS/Android)
- Service accounts
- Third-party integrations
- Different statuses (active, disabled, pending)

## Schema File Locations

### Where to Put Schema Files

| File Type | Location | Purpose |
|-----------|----------|---------|
| **Schema Definitions** | `config/schema/*.schema` | LDAP schema files (RFC 4512 format) |
| **Schema Code** | `src/schema.rs` | Core schema implementation |
| **Schema Adapter** | `src/schema_adapter.rs` | Validator adapter for WriteFSM |
| **Example Entries** | `config/*.ldif` | Sample entries using schemas |
| **Documentation** | `docs/SCHEMA_*.md` | Schema guides and references |

### Recommended Directory Structure

```
config/schema/
├── README.md              # Schema directory guide
├── core.schema           # Core LDAP schema (DO NOT MODIFY)
├── employee.schema       # Employee management
├── application.schema    # Application integration
├── security.schema       # Security extensions
└── custom.schema         # Your custom schemas
```

## How to Define a Custom Schema

### Step 1: Create Schema File

Create `config/schema/myschema.schema`:

```ldap
# My Custom Schema
# OID Namespace: 1.2.3.4.X (EXAMPLE - Use your PEN)

# Attribute definition
attributetype ( 1.2.3.4.X.1.1 NAME 'myAttribute'
    DESC 'My custom attribute'
    EQUALITY caseIgnoreMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
    SINGLE-VALUE )

# Object class definition
objectclass ( 1.2.3.4.X.2.1 NAME 'myClass'
    DESC 'My custom object class'
    SUP top
    STRUCTURAL
    MUST ( myAttribute $ cn )
    MAY ( description ) )
```

### Step 2: Implement in Code

Add to `src/schema.rs`:

```rust
impl LdapSchema {
    pub fn with_custom_schema() -> Self {
        let mut schema = Self::with_core_schema();

        // Add attribute type
        schema.add_attribute_type(AttributeType {
            oid: "1.2.3.4.X.1.1".to_string(),
            names: vec!["myAttribute".to_string()],
            description: Some("My custom attribute".to_string()),
            equality: Some("caseIgnoreMatch".to_string()),
            syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(),
            single_value: true,
        });

        // Add object class
        schema.add_object_class(ObjectClass {
            oid: "1.2.3.4.X.2.1".to_string(),
            names: vec!["myClass".to_string()],
            sup: vec!["top".to_string()],
            kind: ObjectClassKind::Structural,
            must: vec!["myAttribute".to_string(), "cn".to_string()],
            may: vec!["description".to_string()],
        });

        schema
    }
}
```

### Step 3: Use in Application

```rust
// Create schema with custom extensions
let schema = LdapSchema::with_custom_schema();
let validator = Arc::new(LdapSchemaValidator::with_schema(schema));

// Use in server
let fsm_set = ConnectionFsmSet::new_with_schema_validator(
    stream,
    backend,
    None,
    Some(validator),
);
```

### Step 4: Create Entries

Create `config/myentries.ldif`:

```ldif
dn: cn=test,dc=example,dc=com
objectClass: top
objectClass: myClass
cn: Test Entry
myAttribute: custom-value-123
description: This uses my custom schema
```

## Key Concepts

### OID Management

**For Testing**: Use example OIDs `1.2.3.4.X.Y.Z`

**For Production**:
1. Register a Private Enterprise Number (PEN) at https://www.iana.org/assignments/enterprise-numbers
2. Use structure: `1.3.6.1.4.1.YOUR_PEN.1.X.Y`
3. Document your OID allocation

**Recommended OID Structure**:
```
1.3.6.1.4.1.YOUR_PEN
├── .1       - Attribute Types
│   ├── .1   - Person attributes
│   ├── .2   - Organization attributes
│   └── .3   - Application attributes
└── .2       - Object Classes
    ├── .1   - Person classes
    ├── .2   - Organization classes
    └── .3   - Application classes
```

### Schema File Format

Schema files use standard LDAP schema format (RFC 4512):

```ldap
attributetype ( OID NAME 'name'
    DESC 'Description'
    EQUALITY matchingRule
    SYNTAX syntaxOID
    [SINGLE-VALUE] )

objectclass ( OID NAME 'name'
    DESC 'Description'
    SUP superiorClass
    [STRUCTURAL|AUXILIARY|ABSTRACT]
    MUST ( attr1 $ attr2 )
    MAY ( attr3 $ attr4 ) )
```

### Common LDAP Syntax OIDs

| Type | OID | Use For |
|------|-----|---------|
| **Directory String** | 1.3.6.1.4.1.1466.115.121.1.15 | Text, names, descriptions |
| **Integer** | 1.3.6.1.4.1.1466.115.121.1.27 | Numbers, counters |
| **Boolean** | 1.3.6.1.4.1.1466.115.121.1.7 | TRUE/FALSE flags |
| **DN** | 1.3.6.1.4.1.1466.115.121.1.12 | Distinguished Names |
| **Octet String** | 1.3.6.1.4.1.1466.115.121.1.40 | Binary data |

## Examples

### Example 1: Employee Schema

**Attributes**:
- employeeNumber - Unique ID (required)
- department - Department name
- manager - DN of manager
- title - Job title

**Object Class**:
- employee (extends inetOrgPerson)

**Usage**:
```ldif
dn: uid=jdoe,ou=People,dc=example,dc=com
objectClass: employee
employeeNumber: EMP-12345
department: Engineering
title: Senior Software Engineer
manager: uid=msmith,ou=People,dc=example,dc=com
```

### Example 2: Application Schema

**Attributes**:
- appId - Application ID (required)
- appSecret - Hashed secret
- apiKey - Hashed API key
- callbackUrl - OAuth callback

**Object Classes**:
- application (structural)
- oauthClient (auxiliary)

**Usage**:
```ldif
dn: appId=web-app,ou=Applications,dc=example,dc=com
objectClass: application
objectClass: oauthClient
appId: web-app
cn: Web Application
appSecret: {SSHA512}hashed...
callbackUrl: https://example.com/oauth/callback
```

## Best Practices

### 1. OID Management
- ✅ Register a PEN for production use
- ✅ Document your OID namespace
- ✅ Use consistent OID structure
- ❌ Don't use example OIDs in production

### 2. Naming Conventions
- ✅ Use descriptive names (employeeNumber, not attr1)
- ✅ Use camelCase for attributes
- ✅ Keep names under 64 characters
- ❌ Avoid special characters

### 3. Schema Design
- ✅ Extend standard classes (SUP inetOrgPerson)
- ✅ Use auxiliary classes for optional features
- ✅ Keep schemas simple and focused
- ❌ Don't reinvent standard attributes

### 4. Documentation
- ✅ Document each attribute and class
- ✅ Provide usage examples
- ✅ Maintain changelog
- ✅ List dependencies

### 5. Security
- ✅ Store secrets hashed (appSecret, apiKey)
- ✅ Use HTTPS for callbacks
- ✅ Implement access controls
- ❌ Never store plain text secrets

## Testing Your Schema

### 1. Unit Tests

```rust
#[test]
fn test_my_schema() {
    let schema = LdapSchema::with_custom_schema();

    let mut attributes = HashMap::new();
    attributes.insert("objectClass".to_string(), vec!["myClass".to_string()]);
    attributes.insert("cn".to_string(), vec!["Test".to_string()]);
    attributes.insert("myAttribute".to_string(), vec!["value".to_string()]);

    assert!(schema.validate_entry(&attributes).is_ok());
}
```

### 2. Integration Tests

```bash
# Run schema validation demo
cargo run --example schema_validation_test

# Run all schema tests
cargo test schema
```

### 3. Manual Testing

```bash
# Add entry using LDAP tools
ldapadd -x -H ldap://localhost:3389 \
    -D "cn=admin,dc=example,dc=com" \
    -w admin123 \
    -f myentries.ldif
```

## Validation Rules

The schema validator enforces:

| Rule | Example Violation | Error Message |
|------|------------------|---------------|
| **Object classes exist** | unknownClass | "Object class not found: unknownClass" |
| **Required attributes present** | Missing 'sn' for person | "Missing required attribute: sn" |
| **Structural class required** | Only 'top' | "No structural object class defined" |
| **Only defined attributes** | Unknown attribute | "Unknown attribute type: foo" |
| **Single-value constraints** | Multiple values for single-value | "Single-value violation for attribute: uid" |

## Documentation Files

| Document | Purpose |
|----------|---------|
| **[SCHEMA_DEFINITION_GUIDE.md](docs/SCHEMA_DEFINITION_GUIDE.md)** | Complete schema guide (100+ pages) |
| **[SCHEMA_QUICK_START.md](docs/SCHEMA_QUICK_START.md)** | Quick reference (5-minute start) |
| **[config/schema/README.md](config/schema/README.md)** | Schema directory guide |
| **[schema_integration.md](docs/schema_integration.md)** | Schema validation integration |
| **[SCHEMA_VALIDATION_FIX_SUMMARY.md](SCHEMA_VALIDATION_FIX_SUMMARY.md)** | Validation fix details |

## Quick Reference

### File Locations Cheat Sheet

```bash
# Schema definitions
config/schema/*.schema

# Example entries
config/*.ldif

# Schema implementation
src/schema.rs

# Schema adapter
src/schema_adapter.rs

# Documentation
docs/SCHEMA_*.md
```

### Common Tasks Cheat Sheet

```bash
# View example schema
cat config/schema/employee.schema

# Run validation demo
cargo run --example schema_validation_test

# Run all schema tests
cargo test schema

# View quick start
cat docs/SCHEMA_QUICK_START.md

# View complete guide
cat docs/SCHEMA_DEFINITION_GUIDE.md
```

## Future Enhancements

Planned features:

- ⏳ **Runtime schema loading** - Load schemas from files at runtime
- ⏳ **Schema modification via LDAP** - Modify schema through LDAP operations
- ⏳ **Schema replication** - Replicate schemas across servers
- ⏳ **Automatic OID management** - Auto-assign OIDs
- ⏳ **Schema import/export** - Import/export tools
- ⏳ **Schema versioning** - Version control for schemas

## References

- [RFC 4512: LDAP Directory Information Models](https://tools.ietf.org/html/rfc4512)
- [RFC 4519: LDAP Schema for User Applications](https://tools.ietf.org/html/rfc4519)
- [RFC 4524: LDAP: COSINE LDAP/X.500 Schema](https://tools.ietf.org/html/rfc4524)
- [IANA Enterprise Numbers](https://www.iana.org/assignments/enterprise-numbers)

## Getting Started

1. **Read Quick Start**: [docs/SCHEMA_QUICK_START.md](docs/SCHEMA_QUICK_START.md)
2. **Review Examples**: [config/schema/](config/schema/)
3. **Run Demo**: `cargo run --example schema_validation_test`
4. **Read Full Guide**: [docs/SCHEMA_DEFINITION_GUIDE.md](docs/SCHEMA_DEFINITION_GUIDE.md)
5. **Define Your Schema**: Create custom schema file
6. **Implement**: Add to `src/schema.rs`
7. **Test**: Run validation tests
8. **Deploy**: Use in production

## Summary

✅ **Complete schema definition system** with:
- Comprehensive documentation (100+ pages)
- Example schemas (employee, application)
- Sample entries (14 examples)
- Quick start guide
- Best practices and guidelines
- Testing framework
- RFC 4512 compliance

**Everything you need to define and use custom LDAP schemas!** 🎉

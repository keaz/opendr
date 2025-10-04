# LDAP Schema Definition and Usage Guide

## Overview

This guide explains how to define custom LDAP schemas and use them in the opendr LDAP server. Custom schemas allow you to extend the standard LDAP schema with your own object classes and attribute types.

## Table of Contents

1. [Schema Architecture](#schema-architecture)
2. [Where to Put Schema Files](#where-to-put-schema-files)
3. [Schema File Format](#schema-file-format)
4. [Defining Custom Schemas](#defining-custom-schemas)
5. [Loading Schemas](#loading-schemas)
6. [Best Practices](#best-practices)
7. [Examples](#examples)

## Schema Architecture

The opendr server uses a multi-layered schema system:

```
Application Code
       ↓
LdapSchemaValidator (src/schema_adapter.rs)
       ↓
LdapSchema (src/schema.rs)
       ↓
Core Schema + Custom Extensions
```

### Components

1. **LdapSchema** - Core schema implementation
   - Manages object classes and attribute types
   - Validates entries against schema rules
   - Located in: [src/schema.rs](../src/schema.rs)

2. **LdapSchemaValidator** - Adapter for WriteFSM
   - Implements SchemaValidator trait
   - Integrates with Write operations
   - Located in: [src/schema_adapter.rs](../src/schema_adapter.rs)

3. **ConnectionFsmSet** - Runtime integration
   - Provides schema validator to operations
   - Located in: [src/fsm_runtime.rs](../src/fsm_runtime.rs)

## Where to Put Schema Files

### Recommended Directory Structure

```
opendr/
├── config/
│   ├── schema/                    # Schema definitions directory
│   │   ├── core.schema           # Core LDAP schema (DO NOT MODIFY)
│   │   ├── custom.schema         # Your custom schema
│   │   ├── employee.schema       # Domain-specific schemas
│   │   └── application.schema    # Application-specific schemas
│   ├── base.ldif                 # Base DIT structure
│   ├── admin.ldif                # Admin entries
│   └── server.toml               # Server configuration
├── src/
│   └── schema.rs                 # Schema implementation
└── docs/
    └── SCHEMA_DEFINITION_GUIDE.md # This guide
```

### File Locations

| File Type | Location | Purpose |
|-----------|----------|---------|
| **Schema Definitions** | `config/schema/*.schema` | LDAP schema files |
| **Schema Code** | `src/schema.rs` | Core schema implementation |
| **Schema Adapter** | `src/schema_adapter.rs` | Schema validator adapter |
| **Base Entries** | `config/base.ldif` | Initial DIT entries |
| **Custom Entries** | `config/*.ldif` | Additional entries |

## Schema File Format

### LDAP Schema Format (RFC 4512)

Schema files use the standard LDAP schema format:

```ldap
# Attribute Type Definition
attributetype ( 1.2.3.4.5.6.1 NAME 'employeeNumber'
    DESC 'Employee identification number'
    EQUALITY caseIgnoreMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
    SINGLE-VALUE )

# Object Class Definition
objectclass ( 1.2.3.4.5.6.2 NAME 'employee'
    DESC 'Employee object class'
    SUP inetOrgPerson
    STRUCTURAL
    MUST ( employeeNumber $ cn $ sn )
    MAY ( manager $ department $ title ) )
```

### Field Descriptions

#### Attribute Type Fields

| Field | Required | Description | Example |
|-------|----------|-------------|---------|
| **OID** | Yes | Unique identifier | `1.2.3.4.5.6.1` |
| **NAME** | Yes | Attribute name | `'employeeNumber'` |
| **DESC** | No | Description | `'Employee ID'` |
| **EQUALITY** | No | Equality matching rule | `caseIgnoreMatch` |
| **SYNTAX** | Yes | Value syntax OID | `1.3.6.1.4.1.1466.115.121.1.15` |
| **SINGLE-VALUE** | No | Single vs multi-value | `SINGLE-VALUE` |

#### Object Class Fields

| Field | Required | Description | Example |
|-------|----------|-------------|---------|
| **OID** | Yes | Unique identifier | `1.2.3.4.5.6.2` |
| **NAME** | Yes | Object class name | `'employee'` |
| **DESC** | No | Description | `'Employee class'` |
| **SUP** | No | Superior class | `inetOrgPerson` |
| **STRUCTURAL/AUXILIARY/ABSTRACT** | Yes | Class type | `STRUCTURAL` |
| **MUST** | No | Required attributes | `( cn $ sn )` |
| **MAY** | No | Optional attributes | `( mail $ phone )` |

### Common LDAP Syntax OIDs

| Syntax | OID | Description |
|--------|-----|-------------|
| **Directory String** | `1.3.6.1.4.1.1466.115.121.1.15` | UTF-8 string |
| **Integer** | `1.3.6.1.4.1.1466.115.121.1.27` | Integer number |
| **Boolean** | `1.3.6.1.4.1.1466.115.121.1.7` | TRUE or FALSE |
| **DN** | `1.3.6.1.4.1.1466.115.121.1.12` | Distinguished Name |
| **IA5 String** | `1.3.6.1.4.1.1466.115.121.1.26` | ASCII string |
| **Telephone Number** | `1.3.6.1.4.1.1466.115.121.1.50` | Phone number |

## Defining Custom Schemas

### Step 1: Choose Your OID Namespace

You need a unique OID namespace for your organization. Options:

**Option A: Private Enterprise Number (PEN)**
- Register at: https://www.iana.org/assignments/enterprise-numbers
- Format: `1.3.6.1.4.1.YOUR_PEN.1.1.1`
- Example: `1.3.6.1.4.1.12345.1.1.1` (if your PEN is 12345)

**Option B: Use Example OID (Testing Only)**
- Format: `1.2.3.4.5.X.Y` (for testing/development)
- **DO NOT use in production!**

### Step 2: Create Schema File

Create `config/schema/custom.schema`:

```ldap
# Custom Schema for Example Organization
# OID Namespace: 1.2.3.4.5 (EXAMPLE - Replace with your PEN)

################################################################################
# Attribute Type Definitions
################################################################################

# Employee Number - Unique identifier for employees
attributetype ( 1.2.3.4.5.1.1 NAME 'employeeNumber'
    DESC 'Unique employee identification number'
    EQUALITY caseIgnoreMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
    SINGLE-VALUE )

# Department - Employee department
attributetype ( 1.2.3.4.5.1.2 NAME 'department'
    DESC 'Organizational department'
    EQUALITY caseIgnoreMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )

# Manager DN - Reference to manager
attributetype ( 1.2.3.4.5.1.3 NAME 'manager'
    DESC 'Distinguished name of manager'
    EQUALITY distinguishedNameMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.12
    SINGLE-VALUE )

# Job Title
attributetype ( 1.2.3.4.5.1.4 NAME 'title'
    DESC 'Job title or position'
    EQUALITY caseIgnoreMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )

# Start Date
attributetype ( 1.2.3.4.5.1.5 NAME 'startDate'
    DESC 'Employment start date (YYYYMMDD)'
    EQUALITY caseIgnoreMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
    SINGLE-VALUE )

################################################################################
# Object Class Definitions
################################################################################

# Employee Object Class
objectclass ( 1.2.3.4.5.2.1 NAME 'employee'
    DESC 'Employee object class'
    SUP inetOrgPerson
    STRUCTURAL
    MUST ( employeeNumber $ cn $ sn )
    MAY ( manager $ department $ title $ startDate ) )

# Contractor Object Class
objectclass ( 1.2.3.4.5.2.2 NAME 'contractor'
    DESC 'Contractor object class'
    SUP person
    AUXILIARY
    MAY ( employeeNumber $ department $ title ) )
```

### Step 3: Implement in Code

Currently, schemas must be defined in code. Add to `src/schema.rs`:

```rust
impl LdapSchema {
    /// Create schema with core + custom definitions
    pub fn with_custom_schema() -> Self {
        let mut schema = Self::with_core_schema();

        // Add custom attribute types
        schema.add_attribute_type(AttributeType {
            oid: "1.2.3.4.5.1.1".to_string(),
            names: vec!["employeeNumber".to_string()],
            description: Some("Unique employee identification number".to_string()),
            equality: Some("caseIgnoreMatch".to_string()),
            syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(),
            single_value: true,
        });

        schema.add_attribute_type(AttributeType {
            oid: "1.2.3.4.5.1.2".to_string(),
            names: vec!["department".to_string()],
            description: Some("Organizational department".to_string()),
            equality: Some("caseIgnoreMatch".to_string()),
            syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(),
            single_value: false,
        });

        // Add custom object classes
        schema.add_object_class(ObjectClass {
            oid: "1.2.3.4.5.2.1".to_string(),
            names: vec!["employee".to_string()],
            sup: vec!["inetOrgPerson".to_string()],
            kind: ObjectClassKind::Structural,
            must: vec!["employeeNumber".to_string(), "cn".to_string(), "sn".to_string()],
            may: vec!["manager".to_string(), "department".to_string(), "title".to_string()],
        });

        schema
    }
}
```

### Step 4: Use Custom Schema

Update your server initialization to use custom schema:

```rust
use opendr::schema_adapter::LdapSchemaValidator;
use opendr::schema::LdapSchema;

// Create custom schema validator
let custom_schema = LdapSchema::with_custom_schema();
let schema_validator = Arc::new(LdapSchemaValidator::with_schema(custom_schema));

// Use in server
let fsm_set = ConnectionFsmSet::new_with_schema_validator(
    stream,
    backend,
    None,
    Some(schema_validator),
);
```

## Loading Schemas

### Current Implementation (Code-Based)

Currently, schemas are defined in `src/schema.rs` and loaded at compile time:

```rust
// In src/schema.rs
impl LdapSchema {
    /// Core schema from RFC 4519
    pub fn with_core_schema() -> Self {
        let mut schema = Self::new();
        // Add core object classes and attributes
        // ...
        schema
    }

    /// Custom schema extension
    pub fn with_custom_schema() -> Self {
        let mut schema = Self::with_core_schema();
        // Add custom definitions
        // ...
        schema
    }
}
```

### Future: File-Based Loading (Planned)

In the future, schemas will be loaded from files:

```rust
// Planned API
let schema = LdapSchema::from_file("config/schema/custom.schema")?;
let schema = LdapSchema::from_directory("config/schema/")?;
```

### Schema Initialization Flow

```
1. Server Startup
       ↓
2. Load Core Schema (RFC 4519)
       ↓
3. Load Custom Schema Extensions
   - Read schema files
   - Parse schema definitions
   - Validate schema consistency
       ↓
4. Create LdapSchemaValidator
       ↓
5. Attach to ConnectionFsmSet
       ↓
6. Schema Available for All Operations
```

## Best Practices

### OID Management

1. **Use Unique OIDs**
   - Register a Private Enterprise Number (PEN)
   - Structure: `1.3.6.1.4.1.YOUR_PEN.1.X.Y`
   - Document your OID namespace

2. **OID Allocation Strategy**
   ```
   1.3.6.1.4.1.YOUR_PEN.1     - Attribute types
   1.3.6.1.4.1.YOUR_PEN.1.1   - Person attributes
   1.3.6.1.4.1.YOUR_PEN.1.2   - Organization attributes
   1.3.6.1.4.1.YOUR_PEN.2     - Object classes
   1.3.6.1.4.1.YOUR_PEN.2.1   - Person classes
   1.3.6.1.4.1.YOUR_PEN.2.2   - Organization classes
   ```

### Naming Conventions

1. **Use Descriptive Names**
   - Good: `employeeNumber`, `departmentCode`
   - Bad: `attr1`, `field2`

2. **Follow LDAP Conventions**
   - Use camelCase: `givenName`, `employeeNumber`
   - Avoid special characters
   - Keep names under 64 characters

3. **Be Consistent**
   - Use same naming pattern across schema
   - Document naming conventions

### Schema Design

1. **Inherit from Standard Classes**
   ```ldap
   # Good: Extends standard class
   objectclass ( ... NAME 'employee'
       SUP inetOrgPerson
       STRUCTURAL
       MUST ( employeeNumber ) )

   # Bad: Reinvents the wheel
   objectclass ( ... NAME 'employee'
       SUP top
       STRUCTURAL
       MUST ( cn $ sn $ mail $ phone $ ... ) )
   ```

2. **Use Auxiliary Classes for Extensions**
   ```ldap
   # Use auxiliary for optional features
   objectclass ( ... NAME 'securityClearance'
       SUP top
       AUXILIARY
       MAY ( clearanceLevel $ expiryDate ) )
   ```

3. **Keep It Simple**
   - Don't add attributes you don't need
   - Use standard attributes when possible
   - Plan for future extensions

### Documentation

1. **Document Your Schema**
   ```ldap
   # Employee Management Schema
   # Version: 1.0
   # Author: Your Name
   # Date: 2025-01-04
   # OID Namespace: 1.3.6.1.4.1.YOUR_PEN

   # employeeNumber - Unique employee ID
   # Format: EMP-XXXXX where X is a digit
   # Example: EMP-12345
   attributetype ( ... )
   ```

2. **Maintain Changelog**
   ```ldap
   # Changelog:
   # 1.0 - 2025-01-04 - Initial release
   # 1.1 - 2025-02-01 - Added contractor object class
   ```

3. **Create Schema Documentation File**
   - Document each attribute and object class
   - Provide usage examples
   - List dependencies

## Examples

### Example 1: Employee Management Schema

**File**: `config/schema/employee.schema`

```ldap
# Employee Management Schema
# OID Namespace: 1.2.3.4.5 (EXAMPLE)

# Attributes
attributetype ( 1.2.3.4.5.1.1 NAME 'employeeNumber'
    DESC 'Unique employee ID (Format: EMP-XXXXX)'
    EQUALITY caseIgnoreMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
    SINGLE-VALUE )

attributetype ( 1.2.3.4.5.1.2 NAME 'department'
    DESC 'Department name or code'
    EQUALITY caseIgnoreMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )

attributetype ( 1.2.3.4.5.1.3 NAME 'manager'
    DESC 'DN of employee manager'
    EQUALITY distinguishedNameMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.12
    SINGLE-VALUE )

# Object Class
objectclass ( 1.2.3.4.5.2.1 NAME 'employee'
    DESC 'Employee entry'
    SUP inetOrgPerson
    STRUCTURAL
    MUST ( employeeNumber )
    MAY ( manager $ department ) )
```

**Usage Example**:

```ldif
dn: uid=jdoe,ou=People,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
objectClass: employee
cn: John Doe
sn: Doe
uid: jdoe
employeeNumber: EMP-12345
department: Engineering
manager: uid=msmith,ou=People,dc=example,dc=com
mail: jdoe@example.com
```

### Example 2: Application Integration Schema

**File**: `config/schema/application.schema`

```ldap
# Application Integration Schema
# OID Namespace: 1.2.3.4.6 (EXAMPLE)

# Attributes
attributetype ( 1.2.3.4.6.1.1 NAME 'appId'
    DESC 'Application identifier'
    EQUALITY caseIgnoreMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
    SINGLE-VALUE )

attributetype ( 1.2.3.4.6.1.2 NAME 'appSecret'
    DESC 'Application secret key (hashed)'
    EQUALITY octetStringMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.40
    SINGLE-VALUE )

attributetype ( 1.2.3.4.6.1.3 NAME 'callbackUrl'
    DESC 'OAuth callback URL'
    EQUALITY caseExactMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )

# Object Class
objectclass ( 1.2.3.4.6.2.1 NAME 'application'
    DESC 'Application registration entry'
    SUP top
    STRUCTURAL
    MUST ( appId $ cn )
    MAY ( appSecret $ callbackUrl $ description ) )
```

**Usage Example**:

```ldif
dn: appId=web-app-1,ou=Applications,dc=example,dc=com
objectClass: top
objectClass: application
appId: web-app-1
cn: Company Web Application
description: Main company website
callbackUrl: https://example.com/oauth/callback
```

### Example 3: Security Clearance (Auxiliary Class)

**File**: `config/schema/security.schema`

```ldap
# Security Clearance Schema
# OID Namespace: 1.2.3.4.7 (EXAMPLE)

# Attributes
attributetype ( 1.2.3.4.7.1.1 NAME 'clearanceLevel'
    DESC 'Security clearance level'
    EQUALITY caseIgnoreMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
    SINGLE-VALUE )

attributetype ( 1.2.3.4.7.1.2 NAME 'clearanceExpiry'
    DESC 'Clearance expiration date (YYYYMMDD)'
    EQUALITY caseIgnoreMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
    SINGLE-VALUE )

# Auxiliary Object Class
objectclass ( 1.2.3.4.7.2.1 NAME 'securityClearance'
    DESC 'Security clearance information'
    SUP top
    AUXILIARY
    MUST ( clearanceLevel )
    MAY ( clearanceExpiry ) )
```

**Usage Example**:

```ldif
dn: uid=jdoe,ou=People,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
objectClass: employee
objectClass: securityClearance
cn: John Doe
sn: Doe
uid: jdoe
employeeNumber: EMP-12345
clearanceLevel: Top Secret
clearanceExpiry: 20261231
```

## Testing Your Schema

### 1. Unit Tests

Create tests in `tests/custom_schema_integration.rs`:

```rust
#[test]
fn test_employee_schema() {
    let mut schema = LdapSchema::with_core_schema();

    // Add employee schema
    schema.add_attribute_type(AttributeType {
        oid: "1.2.3.4.5.1.1".to_string(),
        names: vec!["employeeNumber".to_string()],
        // ...
    });

    // Test validation
    let mut attributes = HashMap::new();
    attributes.insert("objectClass".to_string(), vec![
        "top".to_string(),
        "person".to_string(),
        "employee".to_string(),
    ]);
    attributes.insert("cn".to_string(), vec!["John Doe".to_string()]);
    attributes.insert("sn".to_string(), vec!["Doe".to_string()]);
    attributes.insert("employeeNumber".to_string(), vec!["EMP-12345".to_string()]);

    assert!(schema.validate_entry(&attributes).is_ok());
}
```

### 2. Integration Tests

Use the schema validation demo:

```bash
cargo run --example schema_validation_test
```

### 3. Manual Testing

Add entries using LDAP tools:

```bash
ldapadd -x -H ldap://localhost:3389 \
    -D "cn=admin,dc=example,dc=com" \
    -w admin123 \
    -f employee_entry.ldif
```

## Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| "Object class not found" | Custom class not loaded | Ensure schema is loaded in code |
| "Missing required attribute" | MUST attribute missing | Add all required attributes |
| "Unknown attribute type" | Attribute not defined | Define attribute in schema |
| "No structural class" | Only abstract/auxiliary | Add structural object class |
| "Single-value violation" | Multiple values for single-value attr | Use single value only |

### Debugging

Enable schema validation logging:

```rust
// In your schema validator
println!("Validating entry: {:?}", entry);
println!("Object classes: {:?}", entry.object_classes);
println!("Attributes: {:?}", entry.attributes);
```

## References

- [RFC 4512: LDAP Directory Information Models](https://tools.ietf.org/html/rfc4512)
- [RFC 4519: LDAP Schema for User Applications](https://tools.ietf.org/html/rfc4519)
- [RFC 4524: LDAP: COSINE LDAP/X.500 Schema](https://tools.ietf.org/html/rfc4524)
- [Schema Integration Guide](schema_integration.md)
- [IANA Enterprise Numbers](https://www.iana.org/assignments/enterprise-numbers)

## Next Steps

1. **Review Core Schema**: See [src/schema.rs](../src/schema.rs)
2. **Try Examples**: Run `cargo run --example schema_validation_test`
3. **Define Your Schema**: Create custom schema file
4. **Implement in Code**: Add to `src/schema.rs`
5. **Test**: Run tests and validation
6. **Deploy**: Use in production

For questions or issues, refer to the [Schema Validation Fix Summary](../SCHEMA_VALIDATION_FIX_SUMMARY.md).

# LDAP Schema Directory

This directory contains LDAP schema definitions for the opendr LDAP server.

## Directory Structure

```
config/schema/
├── README.md              # This file
├── employee.schema        # Employee management schema
└── application.schema     # Application integration schema
```

## Schema Files

### Core Schema

The core LDAP schema (RFC 4519) is built into the application code:
- **Location**: [src/schema.rs](../../src/schema.rs)
- **Includes**: person, inetOrgPerson, organization, organizationalUnit, etc.

### Custom Schemas

#### 1. employee.schema

Employee management schema for HR applications.

**Object Classes**:
- `employee` - Regular employees (extends inetOrgPerson)
- `contractor` - Contractors and temporary workers (auxiliary)

**Attributes**:
- `employeeNumber` - Unique employee ID
- `department` - Department name
- `manager` - DN of manager
- `title` - Job title
- `startDate` - Employment start date
- `employeeType` - Type of employment
- `costCenter` - Cost center code

**Example Entry**:
```ldif
dn: uid=jdoe,ou=People,dc=example,dc=com
objectClass: employee
employeeNumber: EMP-12345
department: Engineering
title: Senior Software Engineer
```

#### 2. application.schema

Application integration schema for API management and OAuth.

**Object Classes**:
- `application` - Application registration
- `oauthClient` - OAuth 2.0 client (auxiliary)
- `serviceAccount` - Service account for M2M auth

**Attributes**:
- `appId` - Unique application ID
- `appSecret` - Application secret (hashed)
- `apiKey` - API key (hashed)
- `callbackUrl` - OAuth callback URL
- `allowedScopes` - Permitted scopes
- `appType` - Application type
- `rateLimit` - Rate limit

**Example Entry**:
```ldif
dn: appId=web-app-1,ou=Applications,dc=example,dc=com
objectClass: application
appId: web-app-1
cn: Company Website
appType: web
```

## Current Implementation

⚠️ **Note**: Currently, schemas must be defined in code. File-based loading is planned for future releases.

### How to Use These Schemas

1. **Review the schema file** to understand the object classes and attributes
2. **Add definitions to code** in `src/schema.rs`
3. **Create custom schema function**:

```rust
impl LdapSchema {
    pub fn with_employee_schema() -> Self {
        let mut schema = Self::with_core_schema();

        // Add employeeNumber attribute
        schema.add_attribute_type(AttributeType {
            oid: "1.2.3.4.5.1.1".to_string(),
            names: vec!["employeeNumber".to_string()],
            // ... rest of definition
        });

        // Add employee object class
        schema.add_object_class(ObjectClass {
            oid: "1.2.3.4.5.2.1".to_string(),
            names: vec!["employee".to_string()],
            // ... rest of definition
        });

        schema
    }
}
```

4. **Use in server initialization**:

```rust
let custom_schema = LdapSchema::with_employee_schema();
let schema_validator = Arc::new(LdapSchemaValidator::with_schema(custom_schema));
```

## OID Namespaces

⚠️ **Important**: The OIDs in these example schemas use the prefix `1.2.3.4.X` which is for **EXAMPLES ONLY**.

For production use:
1. Register a Private Enterprise Number (PEN) at https://www.iana.org/assignments/enterprise-numbers
2. Use your PEN in the OID structure: `1.3.6.1.4.1.YOUR_PEN.1.X.Y`
3. Replace all example OIDs with your registered OIDs

### Recommended OID Structure

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

## Testing Your Schema

### 1. Run Schema Validation Tests

```bash
# Test with demo application
cargo run --example schema_validation_test

# Run all schema tests
cargo test schema
```

### 2. Validate Entries

Use the schema validator directly:

```rust
let schema = LdapSchema::with_employee_schema();
let validator = LdapSchemaValidator::with_schema(schema);

let entry = WriteEntry {
    dn: "uid=jdoe,ou=People,dc=example,dc=com".to_string(),
    attributes: /* ... */,
    object_classes: vec!["employee".to_string()],
    binary_attributes: HashMap::new(),
};

match validator.validate_entry(&entry).await {
    Ok(()) => println!("Valid entry"),
    Err(e) => println!("Invalid: {}", e),
}
```

## Schema File Format

These schema files follow the standard LDAP schema format (RFC 4512):

### Attribute Type Syntax

```
attributetype ( OID NAME 'attributeName'
    DESC 'Description'
    EQUALITY matchingRule
    SYNTAX syntaxOID
    [SINGLE-VALUE] )
```

### Object Class Syntax

```
objectclass ( OID NAME 'className'
    DESC 'Description'
    SUP superiorClass
    [STRUCTURAL|AUXILIARY|ABSTRACT]
    MUST ( attr1 $ attr2 )
    MAY ( attr3 $ attr4 ) )
```

## Common LDAP Syntax OIDs

| Type | OID | Description |
|------|-----|-------------|
| Directory String | 1.3.6.1.4.1.1466.115.121.1.15 | UTF-8 string |
| Integer | 1.3.6.1.4.1.1466.115.121.1.27 | Integer number |
| Boolean | 1.3.6.1.4.1.1466.115.121.1.7 | TRUE/FALSE |
| DN | 1.3.6.1.4.1.1466.115.121.1.12 | Distinguished Name |
| Octet String | 1.3.6.1.4.1.1466.115.121.1.40 | Binary data |

## Adding New Schemas

To add a new custom schema:

1. **Create schema file**:
   ```bash
   touch config/schema/yourschema.schema
   ```

2. **Define attributes and object classes** following the examples

3. **Document usage** with examples in comments

4. **Implement in code** (src/schema.rs)

5. **Test thoroughly** with validation tests

6. **Update this README** with new schema information

## References

- [Schema Definition Guide](../../docs/SCHEMA_DEFINITION_GUIDE.md) - Complete guide
- [Schema Integration Guide](../../docs/schema_integration.md) - Integration details
- [RFC 4512: LDAP Models](https://tools.ietf.org/html/rfc4512) - Schema specification
- [RFC 4519: LDAP Schema](https://tools.ietf.org/html/rfc4519) - Standard schema

## Future Enhancements

Planned features for schema management:

- [ ] Runtime schema file loading
- [ ] Schema modification via LDAP operations
- [ ] Schema replication across servers
- [ ] Schema validation UI/tools
- [ ] Automatic OID management
- [ ] Schema versioning support

## Support

For help with schema definition:
1. Read the [Schema Definition Guide](../../docs/SCHEMA_DEFINITION_GUIDE.md)
2. Review the example schemas in this directory
3. Check the [Schema Integration Guide](../../docs/schema_integration.md)
4. Run the validation demo: `cargo run --example schema_validation_test`

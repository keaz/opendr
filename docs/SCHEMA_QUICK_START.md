# Schema Definition - Quick Start Guide

## TL;DR

```bash
# 1. Check out example schemas
cat config/schema/employee.schema
cat config/schema/application.schema

# 2. View complete guide
cat docs/SCHEMA_DEFINITION_GUIDE.md

# 3. Test schema validation
cargo run --example schema_validation_test
```

## 5-Minute Quick Start

### Step 1: Understand Where Schemas Go

```
opendr/
├── config/schema/          ← Put schema definition files here
│   ├── employee.schema     ← Example: Employee management
│   └── application.schema  ← Example: Application integration
├── config/
│   ├── employees.ldif      ← Example entries using employee schema
│   └── applications.ldif   ← Example entries using app schema
└── src/schema.rs           ← Schema implementation (current method)
```

### Step 2: Review Example Schema

Look at [`config/schema/employee.schema`](../config/schema/employee.schema):

```ldap
# Define an attribute
attributetype ( 1.2.3.4.5.1.1 NAME 'employeeNumber'
    DESC 'Unique employee ID'
    EQUALITY caseIgnoreMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
    SINGLE-VALUE )

# Define an object class
objectclass ( 1.2.3.4.5.2.1 NAME 'employee'
    DESC 'Employee object class'
    SUP inetOrgPerson
    STRUCTURAL
    MUST ( employeeNumber )
    MAY ( manager $ department $ title ) )
```

### Step 3: Use the Schema (Current Method)

**Current Implementation**: The server uses the core schema by default. Custom schemas can be added to [`src/schema.rs`](../src/schema.rs) by creating methods like this:

```rust
impl LdapSchema {
    // Example: Adding employee schema (not yet implemented)
    pub fn with_employee_schema() -> Self {
        let mut schema = Self::with_core_schema();

        // Add attribute type
        schema.add_attribute_type(AttributeType {
            oid: "1.2.3.4.5.1.1".to_string(),
            names: vec!["employeeNumber".to_string()],
            description: Some("Unique employee ID".to_string()),
            equality: Some("caseIgnoreMatch".to_string()),
            syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(),
            single_value: true,
        });

        // Add object class
        schema.add_object_class(ObjectClass {
            oid: "1.2.3.4.5.2.1".to_string(),
            names: vec!["employee".to_string()],
            sup: vec!["inetOrgPerson".to_string()],
            kind: ObjectClassKind::Structural,
            must: vec!["employeeNumber".to_string()],
            may: vec!["manager".to_string(), "department".to_string()],
        });

        schema
    }
}
```

### Step 4: Use in Your Application

The server uses `LdapSchema::with_core_schema()` by default. To use custom schemas:

```rust
use opendr::schema::LdapSchema;
use opendr::schema_adapter::LdapSchemaValidator;

// Option 1: Use core schema (default)
let schema = LdapSchema::with_core_schema();
let validator = Arc::new(LdapSchemaValidator::with_schema(schema));

// Option 2: Use custom schema (if implemented)
// let schema = LdapSchema::with_employee_schema();
// let validator = Arc::new(LdapSchemaValidator::with_schema(schema));

// Use in server
let fsm_set = ConnectionFsmSet::new_with_schema_validator(
    stream,
    backend,
    None,
    Some(validator),
);
```

### Step 5: Test It

**Option 1: Run Automated Test Script** (Recommended)

```bash
# Run comprehensive schema validation test
./scripts/test_schema_validation.sh
```

This script will:
- Reset the server
- Test 10 scenarios (valid and invalid entries)
- Verify schema validation is working
- Show clear pass/fail results

**Option 2: Manual Testing**

Create an entry using LDAP tools:

```bash
# Start server
cargo run --bin opendr

# In another terminal, test valid entry
ldapadd -x -H ldap://localhost:3389 \
    -D "cn=admin,dc=example,dc=com" -w admin123 <<EOF
dn: cn=Test User,ou=People,dc=example,dc=com
objectClass: top
objectClass: person
cn: Test User
sn: User
EOF
```

**Option 3: Use Built-in Demo**

```bash
cargo run --example schema_validation_test
```

Validation will ensure:
- ✅ All object classes exist
- ✅ Required attributes are present
- ✅ Unknown attributes are rejected
- ✅ Structural class requirements met

## Key Files

| File | Purpose |
|------|---------|
| **[config/schema/](../config/schema/)** | Schema definition files |
| **[config/schema/README.md](../config/schema/README.md)** | Schema directory guide |
| **[config/employees.ldif](../config/employees.ldif)** | Example employee entries |
| **[config/applications.ldif](../config/applications.ldif)** | Example application entries |
| **[docs/SCHEMA_DEFINITION_GUIDE.md](SCHEMA_DEFINITION_GUIDE.md)** | Complete schema guide |
| **[src/schema.rs](../src/schema.rs)** | Schema implementation |

## Common Tasks

### Adding a New Attribute

1. **Choose OID**: `1.3.6.1.4.1.YOUR_PEN.1.X` (X = next number)
2. **Add to schema.rs**:
   ```rust
   schema.add_attribute_type(AttributeType {
       oid: "1.3.6.1.4.1.YOUR_PEN.1.X".to_string(),
       names: vec!["myAttribute".to_string()],
       description: Some("My custom attribute".to_string()),
       equality: Some("caseIgnoreMatch".to_string()),
       syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(), // String
       single_value: false,
   });
   ```
3. **Test**: Run schema validation tests

### Adding a New Object Class

1. **Choose OID**: `1.3.6.1.4.1.YOUR_PEN.2.Y` (Y = next number)
2. **Add to schema.rs**:
   ```rust
   schema.add_object_class(ObjectClass {
       oid: "1.3.6.1.4.1.YOUR_PEN.2.Y".to_string(),
       names: vec!["myClass".to_string()],
       sup: vec!["top".to_string()],
       kind: ObjectClassKind::Structural,
       must: vec!["cn".to_string()],
       may: vec!["description".to_string()],
   });
   ```
3. **Test**: Create test entries

### Extending Existing Class

Use auxiliary classes to extend:

```rust
schema.add_object_class(ObjectClass {
    oid: "1.3.6.1.4.1.YOUR_PEN.2.Z".to_string(),
    names: vec!["myExtension".to_string()],
    sup: vec!["top".to_string()],
    kind: ObjectClassKind::Auxiliary,  // ← AUXILIARY
    must: vec![],
    may: vec!["newAttribute".to_string()],
});
```

Then use both classes:
```ldif
objectClass: person
objectClass: myExtension
```

## Common LDAP Syntax OIDs

| Type | OID | Use For |
|------|-----|---------|
| **String** | 1.3.6.1.4.1.1466.115.121.1.15 | Names, descriptions, text |
| **Integer** | 1.3.6.1.4.1.1466.115.121.1.27 | Numbers, counters |
| **Boolean** | 1.3.6.1.4.1.1466.115.121.1.7 | TRUE/FALSE flags |
| **DN** | 1.3.6.1.4.1.1466.115.121.1.12 | References to other entries |
| **Binary** | 1.3.6.1.4.1.1466.115.121.1.40 | Binary data, hashes |

## OID Registration

### For Production

1. **Register PEN**: https://www.iana.org/assignments/enterprise-numbers
2. **Structure OIDs**:
   ```
   1.3.6.1.4.1.YOUR_PEN
   ├── .1       - Attributes
   │   ├── .1   - Person attributes
   │   └── .2   - Organization attributes
   └── .2       - Object Classes
       ├── .1   - Person classes
       └── .2   - Organization classes
   ```

### For Testing

Use example OIDs: `1.2.3.4.X.Y.Z`
- ⚠️ **DO NOT use in production!**

## Validation Rules

The schema validator enforces:

| Rule | Example | Error |
|------|---------|-------|
| Object classes must exist | `objectClass: person` | "Object class not found: unknownClass" |
| Required attributes must be present | person needs cn + sn | "Missing required attribute: sn" |
| Structural class required | Can't have only "top" | "No structural object class defined" |
| Only defined attributes allowed | No random attributes | "Unknown attribute type: foo" |

## Testing

```bash
# Run schema validation demo
cargo run --example schema_validation_test

# Run all schema tests
cargo test schema

# Expected output:
# ✓ Valid entries pass
# ✓ Invalid entries fail with clear errors
```

## Examples

### Example 1: Employee Entry

```ldif
dn: uid=jdoe,ou=People,dc=example,dc=com
objectClass: employee          # Custom class
employeeNumber: EMP-12345      # Custom attribute
department: Engineering        # Custom attribute
cn: John Doe
sn: Doe
```

### Example 2: Application Entry

```ldif
dn: appId=web-app,ou=Applications,dc=example,dc=com
objectClass: application       # Custom class
appId: web-app                # Custom attribute
appType: web                  # Custom attribute
cn: Web Application
```

## Need Help?

1. **Read the Guide**: [SCHEMA_DEFINITION_GUIDE.md](SCHEMA_DEFINITION_GUIDE.md)
2. **Check Examples**: [config/schema/](../config/schema/)
3. **Run Demo**: `cargo run --example schema_validation_test`
4. **Review Code**: [src/schema.rs](../src/schema.rs)

## Future Features

Coming soon:
- ⏳ Runtime schema file loading
- ⏳ Schema modification via LDAP
- ⏳ Automatic OID management
- ⏳ Schema import/export tools

## Next Steps

1. ✅ Review example schemas in `config/schema/`
2. ✅ Read complete guide: [SCHEMA_DEFINITION_GUIDE.md](SCHEMA_DEFINITION_GUIDE.md)
3. ✅ Define your custom schema
4. ✅ Implement in `src/schema.rs`
5. ✅ Test with validation demo
6. ✅ Deploy to production

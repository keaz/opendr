# Schema Validation Examples

This directory contains examples demonstrating LDAP schema validation in the opendr server.

## Examples

### 1. `schema_validation_test.rs` - Direct Schema Validation Test ✅

**Purpose**: Demonstrates schema validation by directly testing the WriteFSM with various entries.

**How to run**:
```bash
cargo run --example schema_validation_test
```

**What it does**:
- Tests 10 different entry scenarios (4 valid, 6 invalid)
- Shows how schema validation rejects invalid entries
- Displays clear error messages for each violation

**Test Cases**:

| Test | Entry Type | Expected | Result |
|------|-----------|----------|---------|
| 1 | Valid person entry | ✅ Pass | ✅ Pass |
| 2 | Person missing 'sn' | ❌ Fail | ❌ Fail: "Missing required attribute: sn" |
| 3 | Person missing 'cn' | ❌ Fail | ❌ Fail: "Missing required attribute: cn" |
| 4 | Unknown object class | ❌ Fail | ❌ Fail: "Object class not found: unknownClass" |
| 5 | Only abstract class | ❌ Fail | ❌ Fail: "No structural object class defined" |
| 6 | Valid inetOrgPerson | ✅ Pass | ✅ Pass |
| 7 | Valid organizationalUnit | ✅ Pass | ✅ Pass |
| 8 | Valid organization | ✅ Pass | ✅ Pass |
| 9 | Organization missing 'o' | ❌ Fail | ❌ Fail: "Missing required attribute: o" |
| 10 | OrganizationalUnit missing 'ou' | ❌ Fail | ❌ Fail: "Missing required attribute: ou" |

**Sample Output**:
```
TEST 1: Valid person entry
==========================
✓ SUCCESS: Entry passed schema validation
  State: CheckingAci

TEST 2: Person without required 'sn' attribute (SHOULD FAIL)
============================================================
✓ EXPECTED FAILURE: Schema validation rejected entry
  Error: Schema validation error: Missing required attribute: sn
  State: Failed { error: "Missing required attribute: sn" }
```

### 2. `schema_validation_demo.rs` - Full LDAP Client Demo

**Purpose**: Demonstrates schema validation using a real LDAP client connecting to the opendr server.

**Prerequisites**:
1. Server must be running: `cargo run --bin opendr`
2. LDAP3 client library must be available

**How to run**:
```bash
# Terminal 1: Start the server
cargo run --bin opendr

# Terminal 2: Run the demo
cargo run --example schema_validation_demo
```

**What it does**:
- Connects to running LDAP server
- Attempts to add 8 different entries (3 valid, 5 invalid)
- Shows server-side schema validation responses
- Verifies added entries with search
- Cleans up test data

## Schema Validation Rules

The schema validator enforces these rules according to RFC 4512:

### Object Class Rules
- ✅ All object classes must exist in schema
- ✅ At least one structural object class required
- ✅ Cannot have only abstract object classes
- ✅ Multiple structural classes must form valid inheritance chain

### Attribute Rules
- ✅ All MUST attributes from object classes must be present
- ✅ Only MAY or MUST attributes are allowed
- ✅ Single-value attributes cannot have multiple values
- ✅ Case-insensitive attribute and object class names

### Error Messages

The validator provides clear, specific error messages:

| Error | Meaning |
|-------|---------|
| `Missing required attribute: sn` | Required attribute is missing |
| `Object class not found: unknownClass` | Unknown object class |
| `No structural object class defined` | Only abstract classes present |
| `Unknown attribute type: foo` | Attribute not defined in schema |
| `Single-value violation for attribute: uid` | Multiple values for single-value attribute |

## Supported Object Classes

### Core Object Classes (RFC 4519)

- **top** (Abstract)
  - Base class for all entries
  - Required: objectClass

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

## Example Valid Entries

### Valid Person Entry
```ldif
dn: cn=John Doe,ou=People,dc=example,dc=com
objectClass: top
objectClass: person
cn: John Doe
sn: Doe
userPassword: secret123
description: Valid person entry
```

### Valid inetOrgPerson Entry
```ldif
dn: uid=ajohnson,ou=People,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: Alice Johnson
sn: Johnson
uid: ajohnson
mail: alice@example.com
givenName: Alice
```

### Valid OrganizationalUnit Entry
```ldif
dn: ou=Engineering,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
ou: Engineering
description: Engineering Department
```

## Example Invalid Entries

### Missing Required Attribute
```ldif
dn: cn=Jane Smith,ou=People,dc=example,dc=com
objectClass: top
objectClass: person
cn: Jane Smith
# Missing 'sn' - FAILS VALIDATION
```
**Error**: `Missing required attribute: sn`

### Unknown Object Class
```ldif
dn: cn=Test,dc=example,dc=com
objectClass: top
objectClass: unknownClass  # Unknown - FAILS VALIDATION
cn: Test
```
**Error**: `Object class not found: unknownClass`

### Only Abstract Class
```ldif
dn: cn=Test,dc=example,dc=com
objectClass: top  # Only abstract, no structural - FAILS VALIDATION
cn: Test
```
**Error**: `No structural object class defined`

## Integration with Server

The schema validation is automatically integrated into the WriteFSM:

```
Client Request
     ↓
WriteFsm (State: Validating)
     ↓
WriteFsm (State: CheckingSchema)
     ↓
Schema Validation
     ↓
✅ Valid → Continue to backend
❌ Invalid → Return error to client
```

The validation happens **before** any backend storage operations, ensuring data integrity at the earliest possible point.

## Configuration

Schema validation can be controlled via `WriteFsmConfig`:

```rust
let config = WriteFsmConfig {
    strict_schema_validation: true,  // Enable/disable validation
    ..Default::default()
};
```

- When `true` (default): Schema validation is enforced
- When `false`: Schema validation is skipped

## References

- [RFC 4512: LDAP Directory Information Models](https://tools.ietf.org/html/rfc4512)
- [RFC 4519: LDAP Schema for User Applications](https://tools.ietf.org/html/rfc4519)
- [Schema Integration Guide](../docs/schema_integration.md)
- [Schema Validation Fix Summary](../SCHEMA_VALIDATION_FIX_SUMMARY.md)

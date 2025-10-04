//! Direct Schema Validation Test
//!
//! This example demonstrates schema validation by directly testing the WriteFSM
//! with various entries that should pass or fail validation.

use opendr::write_fsm::{
    WriteFsmImpl, WriteFsmConfig, WriteBackend, SchemaValidator, AciChecker,
    WriteEntry, Modification, WriteFsmError,
};
use opendr::schema_adapter::LdapSchemaValidator;
use opendr::fsm::{StateMachine, WriteOperation, WriteEvent, WriteState};
use async_trait::async_trait;
use std::collections::HashMap;

/// Mock write backend for testing
#[derive(Debug)]
struct MockWriteBackend;

#[async_trait]
impl WriteBackend for MockWriteBackend {
    async fn begin_transaction(&self) -> Result<String, String> {
        Ok("txn-1".to_string())
    }

    async fn commit_transaction(&self, _txn_id: &str) -> Result<(), String> {
        Ok(())
    }

    async fn rollback_transaction(&self, _txn_id: &str, _reason: &str) -> Result<(), String> {
        Ok(())
    }

    async fn validate_entry(&self, _dn: &str, _entry: &[u8]) -> Result<(), String> {
        Ok(())
    }

    async fn add_entry(&self, _txn_id: &str, _dn: &str, _entry: &[u8]) -> Result<(), String> {
        Ok(())
    }

    async fn modify_entry(&self, _txn_id: &str, _dn: &str, _modifications: &[Modification]) -> Result<(), String> {
        Ok(())
    }

    async fn modify_dn(&self, _txn_id: &str, _dn: &str, _new_rdn: &str, _delete_old: bool, _new_superior: Option<&str>) -> Result<(), String> {
        Ok(())
    }

    async fn delete_entry(&self, _txn_id: &str, _dn: &str) -> Result<(), String> {
        Ok(())
    }

    async fn entry_exists(&self, _dn: &str) -> Result<bool, String> {
        Ok(false)
    }
}

/// Mock ACI checker for testing
#[derive(Debug)]
struct MockAciChecker;

#[async_trait]
impl AciChecker for MockAciChecker {
    async fn check_write_permission(&self, _user_dn: Option<&str>, _operation: &WriteOperation) -> Result<(), String> {
        Ok(())
    }
}

async fn test_entry(
    fsm: &mut WriteFsmImpl,
    test_name: &str,
    dn: &str,
    entry: &str,
    should_succeed: bool,
) {
    println!("{}", test_name);
    println!("{}", "=".repeat(test_name.len()));

    // Start write operation
    let result = fsm.handle_event(WriteEvent::StartWrite(WriteOperation::Add {
        dn: dn.to_string(),
        entry: entry.as_bytes().to_vec(),
    })).await;

    if result.is_err() {
        println!("✗ Failed to start write: {:?}", result.unwrap_err());
        println!();
        return;
    }

    // Trigger validation
    let result = fsm.handle_event(WriteEvent::ValidationComplete).await;

    match result {
        Ok(_) => {
            if should_succeed {
                println!("✓ SUCCESS: Entry passed schema validation");
                println!("  State: {:?}", fsm.current_state());
            } else {
                println!("✗ UNEXPECTED: Entry should have failed validation!");
                println!("  State: {:?}", fsm.current_state());
            }
        }
        Err(e) => {
            if !should_succeed {
                println!("✓ EXPECTED FAILURE: Schema validation rejected entry");
                println!("  Error: {}", e);
                println!("  State: {:?}", fsm.current_state());
            } else {
                println!("✗ UNEXPECTED FAILURE: Entry should have passed!");
                println!("  Error: {}", e);
                println!("  State: {:?}", fsm.current_state());
            }
        }
    }

    // Reset FSM for next test
    let _ = fsm.reset().await;
    println!();
}

#[tokio::main]
async fn main() {
    println!("=== LDAP Schema Validation Direct Test ===\n");

    // Create FSM with real schema validator
    let backend = Box::new(MockWriteBackend);
    let schema_validator: Box<dyn SchemaValidator> = Box::new(LdapSchemaValidator::new());
    let aci_checker = Box::new(MockAciChecker);

    let mut fsm = WriteFsmImpl::new(backend, schema_validator, aci_checker);

    // Test 1: Valid person entry (should succeed)
    let valid_person = r#"dn: cn=John Doe,ou=People,dc=example,dc=com
objectClass: top
objectClass: person
cn: John Doe
sn: Doe
userPassword: secret123
description: Valid person entry
"#;

    test_entry(
        &mut fsm,
        "TEST 1: Valid person entry",
        "cn=John Doe,ou=People,dc=example,dc=com",
        valid_person,
        true,
    ).await;

    // Test 2: Invalid - missing required 'sn' attribute (should fail)
    let missing_sn = r#"dn: cn=Jane Smith,ou=People,dc=example,dc=com
objectClass: top
objectClass: person
cn: Jane Smith
description: Missing required sn attribute
"#;

    test_entry(
        &mut fsm,
        "TEST 2: Person without required 'sn' attribute (SHOULD FAIL)",
        "cn=Jane Smith,ou=People,dc=example,dc=com",
        missing_sn,
        false,
    ).await;

    // Test 3: Invalid - missing required 'cn' attribute (should fail)
    let missing_cn = r#"dn: cn=Test,ou=People,dc=example,dc=com
objectClass: top
objectClass: person
sn: Johnson
description: Missing required cn attribute
"#;

    test_entry(
        &mut fsm,
        "TEST 3: Person without required 'cn' attribute (SHOULD FAIL)",
        "cn=Test,ou=People,dc=example,dc=com",
        missing_cn,
        false,
    ).await;

    // Test 4: Invalid - unknown object class (should fail)
    let unknown_class = r#"dn: cn=Test User,ou=People,dc=example,dc=com
objectClass: top
objectClass: unknownClass
cn: Test User
sn: User
"#;

    test_entry(
        &mut fsm,
        "TEST 4: Unknown object class (SHOULD FAIL)",
        "cn=Test User,ou=People,dc=example,dc=com",
        unknown_class,
        false,
    ).await;

    // Test 5: Invalid - only abstract object class (should fail)
    let only_abstract = r#"dn: cn=Abstract Only,ou=People,dc=example,dc=com
objectClass: top
cn: Abstract Only
"#;

    test_entry(
        &mut fsm,
        "TEST 5: Only abstract object class, no structural (SHOULD FAIL)",
        "cn=Abstract Only,ou=People,dc=example,dc=com",
        only_abstract,
        false,
    ).await;

    // Test 6: Valid inetOrgPerson entry (should succeed)
    let valid_inetorg = r#"dn: uid=ajohnson,ou=People,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: Alice Johnson
sn: Johnson
uid: ajohnson
mail: alice@example.com
givenName: Alice
"#;

    test_entry(
        &mut fsm,
        "TEST 6: Valid inetOrgPerson entry",
        "uid=ajohnson,ou=People,dc=example,dc=com",
        valid_inetorg,
        true,
    ).await;

    // Test 7: Valid organizationalUnit entry (should succeed)
    let valid_ou = r#"dn: ou=Engineering,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
ou: Engineering
description: Engineering Department
"#;

    test_entry(
        &mut fsm,
        "TEST 7: Valid organizationalUnit entry",
        "ou=Engineering,dc=example,dc=com",
        valid_ou,
        true,
    ).await;

    // Test 8: Valid organization entry (should succeed)
    let valid_org = r#"dn: o=Example Corp,dc=example,dc=com
objectClass: top
objectClass: organization
o: Example Corp
description: Example Corporation
"#;

    test_entry(
        &mut fsm,
        "TEST 8: Valid organization entry",
        "o=Example Corp,dc=example,dc=com",
        valid_org,
        true,
    ).await;

    // Test 9: Invalid - missing required 'o' for organization (should fail)
    let missing_o = r#"dn: o=Test Org,dc=example,dc=com
objectClass: top
objectClass: organization
description: Missing required o attribute
"#;

    test_entry(
        &mut fsm,
        "TEST 9: Organization without required 'o' attribute (SHOULD FAIL)",
        "o=Test Org,dc=example,dc=com",
        missing_o,
        false,
    ).await;

    // Test 10: Invalid - missing required 'ou' for organizationalUnit (should fail)
    let missing_ou = r#"dn: ou=Sales,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
description: Missing required ou attribute
"#;

    test_entry(
        &mut fsm,
        "TEST 10: OrganizationalUnit without required 'ou' attribute (SHOULD FAIL)",
        "ou=Sales,dc=example,dc=com",
        missing_ou,
        false,
    ).await;

    println!("=== Test Summary ===");
    println!();
    println!("Expected Results:");
    println!("  ✓ Tests 1, 6, 7, 8 should SUCCEED (valid entries)");
    println!("  ✓ Tests 2, 3, 4, 5, 9, 10 should FAIL (invalid entries)");
    println!();
    println!("Schema validation is working if:");
    println!("  1. Valid entries pass validation");
    println!("  2. Invalid entries are rejected with clear error messages");
    println!("  3. Error messages indicate the specific schema violation");
    println!();
    println!("=== Demo Complete ===");
}

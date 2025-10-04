//! Schema Validation Demo
//!
//! This example demonstrates LDAP schema validation by attempting to add
//! entries that both pass and fail schema validation.

use ldap3::{LdapConnAsync, Mod, Scope, SearchEntry};
use std::error::Error;
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("=== LDAP Schema Validation Demo ===\n");

    // Connect to LDAP server
    let (conn, mut ldap) = LdapConnAsync::new("ldap://localhost:3389").await?;
    ldap3::drive!(conn);

    // Bind as admin
    ldap.simple_bind("cn=admin,dc=example,dc=com", "admin123")
        .await?
        .success()?;

    println!("✓ Connected and authenticated as admin\n");

    // Test 1: Valid person entry (should succeed)
    println!("TEST 1: Adding valid person entry");
    println!("-----------------------------------");
    let valid_person = vec![
        ("objectClass", vec!["top", "person"]),
        ("cn", vec!["John Doe"]),
        ("sn", vec!["Doe"]),
        ("userPassword", vec!["secret123"]),
        ("description", vec!["Valid person entry"]),
    ];

    match ldap
        .add("cn=John Doe,ou=People,dc=example,dc=com", valid_person)
        .await
    {
        Ok(result) => {
            if result.rc == 0 {
                println!("✓ SUCCESS: Valid person entry was added");
            } else {
                println!("✗ FAILED: {:?}", result);
            }
        }
        Err(e) => println!("✗ ERROR: {:?}", e),
    }
    println!();

    // Test 2: Invalid entry - missing required 'sn' attribute (should fail)
    println!("TEST 2: Adding person without required 'sn' attribute");
    println!("------------------------------------------------------");
    let missing_sn = vec![
        ("objectClass", vec!["top", "person"]),
        ("cn", vec!["Jane Smith"]),
        // Missing 'sn' - this should fail schema validation
        ("description", vec!["Missing required sn attribute"]),
    ];

    match ldap
        .add("cn=Jane Smith,ou=People,dc=example,dc=com", missing_sn)
        .await
    {
        Ok(result) => {
            if result.rc == 0 {
                println!("✗ UNEXPECTED: Entry was added (should have failed!)");
            } else {
                println!("✓ EXPECTED FAILURE: Schema validation rejected entry");
                println!("   Result code: {}", result.rc);
                println!("   Message: {}", result.text);
            }
        }
        Err(e) => {
            println!("✓ EXPECTED FAILURE: {:?}", e);
        }
    }
    println!();

    // Test 3: Invalid entry - missing required 'cn' attribute (should fail)
    println!("TEST 3: Adding person without required 'cn' attribute");
    println!("------------------------------------------------------");
    let missing_cn = vec![
        ("objectClass", vec!["top", "person"]),
        ("sn", vec!["Johnson"]),
        // Missing 'cn' - this should fail schema validation
    ];

    match ldap
        .add("cn=Missing CN,ou=People,dc=example,dc=com", missing_cn)
        .await
    {
        Ok(result) => {
            if result.rc == 0 {
                println!("✗ UNEXPECTED: Entry was added (should have failed!)");
            } else {
                println!("✓ EXPECTED FAILURE: Schema validation rejected entry");
                println!("   Result code: {}", result.rc);
                println!("   Message: {}", result.text);
            }
        }
        Err(e) => {
            println!("✓ EXPECTED FAILURE: {:?}", e);
        }
    }
    println!();

    // Test 4: Invalid entry - unknown object class (should fail)
    println!("TEST 4: Adding entry with unknown object class");
    println!("-----------------------------------------------");
    let unknown_class = vec![
        ("objectClass", vec!["top", "unknownClass"]),
        ("cn", vec!["Test User"]),
        ("sn", vec!["User"]),
    ];

    match ldap
        .add("cn=Test User,ou=People,dc=example,dc=com", unknown_class)
        .await
    {
        Ok(result) => {
            if result.rc == 0 {
                println!("✗ UNEXPECTED: Entry was added (should have failed!)");
            } else {
                println!("✓ EXPECTED FAILURE: Schema validation rejected unknown object class");
                println!("   Result code: {}", result.rc);
                println!("   Message: {}", result.text);
            }
        }
        Err(e) => {
            println!("✓ EXPECTED FAILURE: {:?}", e);
        }
    }
    println!();

    // Test 5: Invalid entry - only abstract object class (should fail)
    println!("TEST 5: Adding entry with only abstract object class");
    println!("-----------------------------------------------------");
    let only_abstract = vec![
        ("objectClass", vec!["top"]), // Only abstract class, no structural class
        ("cn", vec!["Abstract Only"]),
    ];

    match ldap
        .add("cn=Abstract Only,ou=People,dc=example,dc=com", only_abstract)
        .await
    {
        Ok(result) => {
            if result.rc == 0 {
                println!("✗ UNEXPECTED: Entry was added (should have failed!)");
            } else {
                println!("✓ EXPECTED FAILURE: Schema validation requires structural class");
                println!("   Result code: {}", result.rc);
                println!("   Message: {}", result.text);
            }
        }
        Err(e) => {
            println!("✓ EXPECTED FAILURE: {:?}", e);
        }
    }
    println!();

    // Test 6: Valid inetOrgPerson entry (should succeed)
    println!("TEST 6: Adding valid inetOrgPerson entry");
    println!("-----------------------------------------");
    let valid_inetorg = vec![
        ("objectClass", vec!["top", "person", "organizationalPerson", "inetOrgPerson"]),
        ("cn", vec!["Alice Johnson"]),
        ("sn", vec!["Johnson"]),
        ("uid", vec!["ajohnson"]),
        ("mail", vec!["alice@example.com"]),
        ("givenName", vec!["Alice"]),
    ];

    match ldap
        .add("uid=ajohnson,ou=People,dc=example,dc=com", valid_inetorg)
        .await
    {
        Ok(result) => {
            if result.rc == 0 {
                println!("✓ SUCCESS: Valid inetOrgPerson entry was added");
            } else {
                println!("✗ FAILED: {:?}", result);
            }
        }
        Err(e) => println!("✗ ERROR: {:?}", e),
    }
    println!();

    // Test 7: Valid organizationalUnit entry (should succeed)
    println!("TEST 7: Adding valid organizationalUnit entry");
    println!("----------------------------------------------");
    let valid_ou = vec![
        ("objectClass", vec!["top", "organizationalUnit"]),
        ("ou", vec!["Engineering"]),
        ("description", vec!["Engineering Department"]),
    ];

    match ldap
        .add("ou=Engineering,dc=example,dc=com", valid_ou)
        .await
    {
        Ok(result) => {
            if result.rc == 0 {
                println!("✓ SUCCESS: Valid organizationalUnit entry was added");
            } else {
                println!("✗ FAILED: {:?}", result);
            }
        }
        Err(e) => println!("✗ ERROR: {:?}", e),
    }
    println!();

    // Test 8: Invalid entry - unknown attribute (should fail)
    println!("TEST 8: Adding entry with unknown attribute");
    println!("--------------------------------------------");
    let unknown_attr = vec![
        ("objectClass", vec!["top", "person"]),
        ("cn", vec!["Bob Brown"]),
        ("sn", vec!["Brown"]),
        ("unknownAttribute", vec!["invalid"]), // Unknown attribute
    ];

    match ldap
        .add("cn=Bob Brown,ou=People,dc=example,dc=com", unknown_attr)
        .await
    {
        Ok(result) => {
            if result.rc == 0 {
                println!("✗ UNEXPECTED: Entry was added (should have failed!)");
            } else {
                println!("✓ EXPECTED FAILURE: Schema validation rejected unknown attribute");
                println!("   Result code: {}", result.rc);
                println!("   Message: {}", result.text);
            }
        }
        Err(e) => {
            println!("✓ EXPECTED FAILURE: {:?}", e);
        }
    }
    println!();

    // Search for successfully added entries
    println!("=== Verification: Searching for successfully added entries ===");
    println!();

    let (rs, _res) = ldap
        .search(
            "dc=example,dc=com",
            Scope::Subtree,
            "(objectClass=person)",
            vec!["cn", "sn", "uid"],
        )
        .await?
        .success()?;

    println!("Found {} person entries:", rs.len());
    for entry in rs {
        let entry = SearchEntry::construct(entry);
        println!("  - DN: {}", entry.dn);
        if let Some(cn) = entry.attrs.get("cn") {
            println!("    CN: {}", cn.join(", "));
        }
    }
    println!();

    // Cleanup: Delete successfully added entries
    println!("=== Cleanup: Deleting test entries ===");
    println!();

    let entries_to_delete = vec![
        "cn=John Doe,ou=People,dc=example,dc=com",
        "uid=ajohnson,ou=People,dc=example,dc=com",
        "ou=Engineering,dc=example,dc=com",
    ];

    for dn in entries_to_delete {
        match ldap.delete(dn).await {
            Ok(result) => {
                if result.rc == 0 {
                    println!("✓ Deleted: {}", dn);
                }
            }
            Err(_) => {
                // Entry might not exist, that's okay
            }
        }
    }

    // Unbind
    ldap.unbind().await?;
    println!("\n=== Demo Complete ===");

    Ok(())
}

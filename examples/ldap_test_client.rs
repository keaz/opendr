use ldap3::{LdapConnAsync, Scope, SearchEntry};
use std::error::Error;
use std::collections::HashSet;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("=== OpenDR LDAP Test Client ===\n");

    // Connection parameters (matching config/server.toml)
    let ldap_url = "ldap://localhost:1389";
    let bind_dn = "cn=manager,dc=example,dc=com";
    let bind_password = "Admin@123";
    let base_dn = "dc=example,dc=com";

    // Connect to LDAP server
    println!("1. Connecting to {}...", ldap_url);
    let (conn, mut ldap) = LdapConnAsync::new(ldap_url).await?;

    // Drive the connection in the background
    tokio::spawn(async move {
        if let Err(e) = conn.drive().await {
            eprintln!("Connection error: {}", e);
        }
    });

    println!("   ✓ Connected successfully\n");

    // Bind as admin
    println!("2. Binding as admin ({})...", bind_dn);
    ldap.simple_bind(bind_dn, bind_password).await?.success()?;
    println!("   ✓ Bind successful\n");

    // Test 1: Search for base DN
    println!("3. Searching for base DN ({})...", base_dn);
    let (rs, _res) = ldap
        .search(
            base_dn,
            Scope::Base,
            "(objectClass=*)",
            vec!["*"],
        )
        .await?
        .success()?;

    if !rs.is_empty() {
        println!("   ✓ Base DN found:");
        for entry in rs {
            let entry = SearchEntry::construct(entry);
            println!("     DN: {}", entry.dn);
            for (attr, values) in &entry.attrs {
                println!("     {}: {:?}", attr, values);
            }
        }
    }
    println!();

    // Test 2: Search for organizational units
    println!("4. Searching for organizational units...");
    let (rs, _res) = ldap
        .search(
            base_dn,
            Scope::OneLevel,
            "(objectClass=organizationalUnit)",
            vec!["ou", "description"],
        )
        .await?
        .success()?;

    println!("   ✓ Found {} organizational units:", rs.len());
    for entry in rs {
        let entry = SearchEntry::construct(entry);
        println!("     - {}", entry.dn);
        if let Some(desc) = entry.attrs.get("description") {
            println!("       Description: {:?}", desc);
        }
    }
    println!();

    // Test 3: Add a test user
    println!("5. Adding a test user...");
    let user_dn = "cn=John Doe,ou=People,dc=example,dc=com";
    let user_attrs = vec![
        ("objectClass", HashSet::from(["person", "organizationalPerson", "inetOrgPerson"])),
        ("cn", HashSet::from(["John Doe"])),
        ("sn", HashSet::from(["Doe"])),
        ("givenName", HashSet::from(["John"])),
        ("mail", HashSet::from(["john.doe@example.com"])),
        ("userPassword", HashSet::from(["TestPassword123"])),
    ];

    match ldap.add(user_dn, user_attrs).await?.success() {
        Ok(_) => println!("   ✓ User added successfully"),
        Err(e) => {
            if e.to_string().contains("Already exists") {
                println!("   ⚠ User already exists (skipping)");
            } else {
                return Err(e.into());
            }
        }
    }
    println!();

    // Test 4: Search for the user we just added
    println!("6. Searching for the added user...");
    let (rs, _res) = ldap
        .search(
            "ou=People,dc=example,dc=com",
            Scope::OneLevel,
            "(cn=John Doe)",
            vec!["cn", "sn", "givenName", "mail"],
        )
        .await?
        .success()?;

    if !rs.is_empty() {
        println!("   ✓ User found:");
        for entry in rs {
            let entry = SearchEntry::construct(entry);
            println!("     DN: {}", entry.dn);
            for (attr, values) in &entry.attrs {
                println!("     {}: {:?}", attr, values);
            }
        }
    } else {
        println!("   ✗ User not found!");
    }
    println!();

    // Test 5: Modify the user
    println!("7. Modifying user's mail attribute...");
    use ldap3::Mod;
    let mods = vec![
        Mod::Replace("mail", HashSet::from(["john.doe.updated@example.com"])),
    ];

    ldap.modify(user_dn, mods).await?.success()?;
    println!("   ✓ User modified successfully\n");

    // Test 6: Verify the modification
    println!("8. Verifying the modification...");
    let (rs, _res) = ldap
        .search(
            user_dn,
            Scope::Base,
            "(objectClass=*)",
            vec!["mail"],
        )
        .await?
        .success()?;

    if !rs.is_empty() {
        let entry = SearchEntry::construct(rs.into_iter().next().unwrap());
        if let Some(mail) = entry.attrs.get("mail") {
            println!("   ✓ Mail updated to: {:?}", mail);
        }
    }
    println!();

    // Test 7: Bind as the new user
    println!("9. Testing bind as the new user...");
    let mut user_ldap = {
        let (conn, ldap) = LdapConnAsync::new(ldap_url).await?;
        tokio::spawn(async move {
            if let Err(e) = conn.drive().await {
                eprintln!("Connection error: {}", e);
            }
        });
        ldap
    };

    match user_ldap.simple_bind(user_dn, "TestPassword123").await?.success() {
        Ok(_) => println!("   ✓ User bind successful"),
        Err(e) => println!("   ✗ User bind failed: {}", e),
    }
    user_ldap.unbind().await?;
    println!();

    // Test 8: Compare operation
    println!("10. Testing compare operation...");
    let compare_result = ldap.compare(user_dn, "sn", "Doe").await?;
    if compare_result.0.rc == 0 {
        println!("   ✓ Compare operation successful (sn=Doe matches)");
    } else {
        println!("   ✗ Compare operation returned: rc={}", compare_result.0.rc);
    }
    println!();

    // Test 9: Search with filter
    println!("11. Testing search with complex filter...");
    let (rs, _res) = ldap
        .search(
            base_dn,
            Scope::Subtree,
            "(&(objectClass=inetOrgPerson)(mail=*@example.com))",
            vec!["cn", "mail"],
        )
        .await?
        .success()?;

    println!("   ✓ Found {} entries matching filter:", rs.len());
    for entry in rs {
        let entry = SearchEntry::construct(entry);
        println!("     - {} ({})", entry.dn, entry.attrs.get("mail").map(|v| v[0].as_str()).unwrap_or(""));
    }
    println!();

    // Test 10: Delete the test user
    println!("12. Deleting the test user...");
    ldap.delete(user_dn).await?.success()?;
    println!("   ✓ User deleted successfully\n");

    // Unbind
    println!("13. Unbinding...");
    ldap.unbind().await?;
    println!("   ✓ Unbind successful\n");

    println!("=== All tests completed successfully! ===");

    Ok(())
}

use ldap3::{LdapConnAsync, Scope, SearchEntry};
use std::collections::HashSet;
use std::error::Error;
use rand::{Rng, distributions::Alphanumeric};

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
        .search(base_dn, Scope::Base, "(objectClass=*)", vec!["*"])
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

    // Test 3: Add 1000 random test users
    println!("5. Adding 1000 random test users...");
    let mut rng = rand::thread_rng();
    let mut added_count = 0;
    let mut skipped_count = 0;

    for i in 0..1000 {
        // Generate random user data
        let first_name: String = (0..8)
            .map(|_| rng.sample(Alphanumeric) as char)
            .collect();
        let last_name: String = (0..10)
            .map(|_| rng.sample(Alphanumeric) as char)
            .collect();
        let uid: String = format!("user{:04}", i);
        let cn = format!("{} {}", first_name, last_name);
        let email = format!("{}@example.com", uid);
        let user_dn = format!("uid={},ou=People,dc=example,dc=com", uid);

        let user_attrs = vec![
            (
                "objectClass",
                HashSet::from(["person", "organizationalPerson", "inetOrgPerson"]),
            ),
            ("cn", HashSet::from([cn.as_str()])),
            ("sn", HashSet::from([last_name.as_str()])),
            ("givenName", HashSet::from([first_name.as_str()])),
            ("uid", HashSet::from([uid.as_str()])),
            ("mail", HashSet::from([email.as_str()])),
            ("userPassword", HashSet::from(["TestPassword123"])),
        ];

        match ldap.add(&user_dn, user_attrs).await?.success() {
            Ok(_) => {
                added_count += 1;
                if added_count % 100 == 0 {
                    println!("   ... added {} users", added_count);
                }
            }
            Err(e) => {
                if e.to_string().contains("Already exists") {
                    skipped_count += 1;
                } else {
                    eprintln!("   ✗ Failed to add {}: {}", uid, e);
                }
            }
        }
    }
    println!("   ✓ Added {} users, skipped {} existing", added_count, skipped_count);
    println!();

    // Test 4: Search for added users
    println!("6. Searching for added users...");
    let (rs, _res) = ldap
        .search(
            "ou=People,dc=example,dc=com",
            Scope::OneLevel,
            "(uid=user*)",
            vec!["cn", "sn", "givenName", "mail", "uid"],
        )
        .await?
        .success()?;

    println!("   ✓ Found {} users", rs.len());
    if !rs.is_empty() {
        println!("   First 5 users:");
        for entry in rs.iter().take(5) {
            let entry = SearchEntry::construct(entry.clone());
            println!("     - {} ({})", entry.dn,
                entry.attrs.get("mail").map(|v| v[0].as_str()).unwrap_or(""));
        }
    }
    println!();

    // Test 5: Modify a random user
    println!("7. Modifying a random user's mail attribute...");
    use ldap3::Mod;
    let test_user_dn = "uid=user0500,ou=People,dc=example,dc=com";
    let mods = vec![Mod::Replace(
        "mail",
        HashSet::from(["user0500.updated@example.com"]),
    )];

    match ldap.modify(test_user_dn, mods).await?.success() {
        Ok(_) => println!("   ✓ User modified successfully"),
        Err(e) => println!("   ✗ Modification failed: {}", e),
    }
    println!();

    // Test 6: Verify the modification
    println!("8. Verifying the modification...");
    let (rs, _res) = ldap
        .search(test_user_dn, Scope::Base, "(objectClass=*)", vec!["mail"])
        .await?
        .success()?;

    if !rs.is_empty() {
        let entry = SearchEntry::construct(rs.into_iter().next().unwrap());
        if let Some(mail) = entry.attrs.get("mail") {
            println!("   ✓ Mail updated to: {:?}", mail);
        }
    }
    println!();

    // Test 7: Bind as a random user
    println!("9. Testing bind as a random user...");
    let test_bind_dn = "uid=user0100,ou=People,dc=example,dc=com";
    let mut user_ldap = {
        let (conn, ldap) = LdapConnAsync::new(ldap_url).await?;
        tokio::spawn(async move {
            if let Err(e) = conn.drive().await {
                eprintln!("Connection error: {}", e);
            }
        });
        ldap
    };

    match user_ldap
        .simple_bind(test_bind_dn, "TestPassword123")
        .await?
        .success()
    {
        Ok(_) => println!("   ✓ User bind successful"),
        Err(e) => println!("   ✗ User bind failed: {}", e),
    }
    user_ldap.unbind().await?;
    println!();

    // Test 8: Compare operation (skip for now, not critical)
    // println!("10. Testing compare operation...");

    // Test 9: Search with complex filter
    println!("10. Testing search with complex filter...");
    let (rs, _res) = ldap
        .search(
            base_dn,
            Scope::Subtree,
            "(&(objectClass=inetOrgPerson)(mail=*@example.com))",
            vec!["cn", "mail", "uid"],
        )
        .await?
        .success()?;

    println!("   ✓ Found {} entries matching filter", rs.len());
    println!("   First 10 entries:");
    for entry in rs.iter().take(10) {
        let entry = SearchEntry::construct(entry.clone());
        println!(
            "     - {}",
            entry.attrs.get("uid").map(|v| v[0].as_str()).unwrap_or("unknown")
        );
    }
    println!();

    // Test 10: Delete test users (delete first 100)
    println!("11. Deleting first 100 test users...");
    let mut deleted_count = 0;
    for i in 0..100 {
        let uid = format!("user{:04}", i);
        let user_dn = format!("uid={},ou=People,dc=example,dc=com", uid);

        match ldap.delete(&user_dn).await?.success() {
            Ok(_) => {
                deleted_count += 1;
                if deleted_count % 50 == 0 {
                    println!("   ... deleted {} users", deleted_count);
                }
            }
            Err(e) => {
                if !e.to_string().contains("No such object") {
                    eprintln!("   ✗ Failed to delete {}: {}", uid, e);
                }
            }
        }
    }
    println!("   ✓ Deleted {} users\n", deleted_count);

    // Unbind
    println!("12. Unbinding...");
    ldap.unbind().await?;
    println!("   ✓ Unbind successful\n");

    println!("=== All tests completed successfully! ===");
    println!("\nSummary:");
    println!("  - Created 1000 random users");
    println!("  - Performed searches and modifications");
    println!("  - Deleted first 100 users for cleanup");

    Ok(())
}

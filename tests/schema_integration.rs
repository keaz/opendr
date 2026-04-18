// Integration tests for schema validation
use opendr::schema::{AttributeType, LdapSchema, ObjectClass, ObjectClassKind, SchemaError};
use std::collections::HashMap;

fn parse_simple_entry_ldif(contents: &str) -> Vec<HashMap<String, Vec<String>>> {
    contents
        .split("\n\n")
        .filter_map(|entry| {
            let mut attributes: HashMap<String, Vec<String>> = HashMap::new();
            for line in entry.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') || line.starts_with("dn:") {
                    continue;
                }
                let Some((name, value)) = line.split_once(':') else {
                    continue;
                };
                attributes
                    .entry(name.trim().to_string())
                    .or_default()
                    .push(value.trim_start().to_string());
            }
            if attributes.is_empty() {
                None
            } else {
                Some(attributes)
            }
        })
        .collect()
}

#[test]
fn test_full_person_entry_validation() {
    let schema = LdapSchema::with_core_schema();

    let mut attributes = HashMap::new();
    attributes.insert(
        "objectClass".to_string(),
        vec!["top".to_string(), "person".to_string()],
    );
    attributes.insert("cn".to_string(), vec!["Alice Johnson".to_string()]);
    attributes.insert("sn".to_string(), vec!["Johnson".to_string()]);
    attributes.insert(
        "userPassword".to_string(),
        vec!["{SSHA512}hashed...".to_string()],
    );
    attributes.insert(
        "description".to_string(),
        vec!["Software Engineer".to_string()],
    );

    let result = schema.validate_entry(&attributes);
    assert!(
        result.is_ok(),
        "Valid person entry should validate successfully"
    );
}

#[test]
fn test_rfc4517_core_syntax_validation() {
    let schema = LdapSchema::with_core_schema();

    let mut attributes = HashMap::new();
    attributes.insert(
        "objectClass".to_string(),
        vec![
            "top".to_string(),
            "person".to_string(),
            "organizationalPerson".to_string(),
            "inetOrgPerson".to_string(),
        ],
    );
    attributes.insert("cn".to_string(), vec!["Alice Johnson".to_string()]);
    attributes.insert("sn".to_string(), vec!["Johnson".to_string()]);
    attributes.insert("mail".to_string(), vec!["alice@example.org".to_string()]);
    attributes.insert(
        "telephoneNumber".to_string(),
        vec!["+1 555-0100".to_string()],
    );
    assert!(schema.validate_entry(&attributes).is_ok());

    attributes.insert("telephoneNumber".to_string(), vec!["+1_555".to_string()]);
    assert!(matches!(
        schema.validate_entry(&attributes),
        Err(SchemaError::InvalidSyntax(attribute, _)) if attribute == "telephoneNumber"
    ));

    attributes.insert(
        "telephoneNumber".to_string(),
        vec!["+1 555-0100".to_string()],
    );
    attributes.insert("mail".to_string(), vec!["alice@exámple.org".to_string()]);
    assert!(matches!(
        schema.validate_entry(&attributes),
        Err(SchemaError::InvalidSyntax(attribute, _)) if attribute == "mail"
    ));
}

#[test]
fn test_inet_org_person_full_attributes() {
    let schema = LdapSchema::with_core_schema();

    let mut attributes = HashMap::new();
    attributes.insert(
        "objectClass".to_string(),
        vec![
            "top".to_string(),
            "person".to_string(),
            "organizationalPerson".to_string(),
            "inetOrgPerson".to_string(),
        ],
    );
    attributes.insert("cn".to_string(), vec!["Bob Smith".to_string()]);
    attributes.insert("sn".to_string(), vec!["Smith".to_string()]);
    attributes.insert("givenName".to_string(), vec!["Bob".to_string()]);
    attributes.insert("uid".to_string(), vec!["bsmith".to_string()]);
    attributes.insert(
        "mail".to_string(),
        vec![
            "bob.smith@example.com".to_string(),
            "bsmith@corp.example.com".to_string(),
        ],
    );
    attributes.insert(
        "ou".to_string(),
        vec!["Engineering".to_string(), "Research".to_string()],
    );

    let result = schema.validate_entry(&attributes);
    assert!(
        result.is_ok(),
        "Valid inetOrgPerson with multiple values should validate"
    );
}

#[test]
fn test_inet_org_person_allows_expanded_rfc2798_attributes() {
    let schema = LdapSchema::with_core_schema();

    let mut attributes = HashMap::new();
    attributes.insert(
        "objectClass".to_string(),
        vec![
            "top".to_string(),
            "person".to_string(),
            "organizationalPerson".to_string(),
            "inetOrgPerson".to_string(),
        ],
    );
    attributes.insert("cn".to_string(), vec!["Carol Example".to_string()]);
    attributes.insert("sn".to_string(), vec!["Example".to_string()]);
    attributes.insert("uid".to_string(), vec!["carol".to_string()]);
    attributes.insert("givenName".to_string(), vec!["Carol".to_string()]);
    attributes.insert("displayName".to_string(), vec!["Carol Example".to_string()]);
    attributes.insert("initials".to_string(), vec!["CE".to_string()]);
    attributes.insert("businessCategory".to_string(), vec!["Research".to_string()]);
    attributes.insert("carLicense".to_string(), vec!["WP-1234".to_string()]);
    attributes.insert("departmentNumber".to_string(), vec!["RND".to_string()]);
    attributes.insert("employeeNumber".to_string(), vec!["1001".to_string()]);
    attributes.insert("employeeType".to_string(), vec!["Employee".to_string()]);
    attributes.insert("homePhone".to_string(), vec!["+1 555 0101".to_string()]);
    attributes.insert(
        "homePostalAddress".to_string(),
        vec!["10 Home Road$Colombo".to_string()],
    );
    attributes.insert("jpegPhoto".to_string(), vec!["jpeg bytes".to_string()]);
    attributes.insert(
        "labeledURI".to_string(),
        vec!["https://example.com Carol Example".to_string()],
    );
    attributes.insert(
        "manager".to_string(),
        vec!["uid=manager,ou=people,dc=example,dc=com".to_string()],
    );
    attributes.insert("mobile".to_string(), vec!["+1 555 0102".to_string()]);
    attributes.insert("o".to_string(), vec!["Example Corporation".to_string()]);
    attributes.insert("pager".to_string(), vec!["+1 555 0103".to_string()]);
    attributes.insert("preferredLanguage".to_string(), vec!["en-US".to_string()]);
    attributes.insert("roomNumber".to_string(), vec!["A-101".to_string()]);
    attributes.insert(
        "secretary".to_string(),
        vec!["uid=assistant,ou=people,dc=example,dc=com".to_string()],
    );
    attributes.insert("title".to_string(), vec!["Engineer".to_string()]);
    attributes.insert("l".to_string(), vec!["Colombo".to_string()]);
    attributes.insert("st".to_string(), vec!["Western Province".to_string()]);
    attributes.insert("street".to_string(), vec!["100 Main Street".to_string()]);
    attributes.insert("postalCode".to_string(), vec!["00100".to_string()]);
    attributes.insert(
        "postalAddress".to_string(),
        vec!["100 Main Street$Colombo".to_string()],
    );
    attributes.insert(
        "registeredAddress".to_string(),
        vec!["200 Registered Road$Colombo".to_string()],
    );
    attributes.insert(
        "physicalDeliveryOfficeName".to_string(),
        vec!["Head Office".to_string()],
    );

    assert!(
        schema.validate_entry(&attributes).is_ok(),
        "inetOrgPerson should allow common RFC2798 employee and contact attributes"
    );
}

#[test]
fn test_inet_org_person_manager_requires_dn_syntax() {
    let schema = LdapSchema::with_core_schema();

    let mut attributes = HashMap::new();
    attributes.insert(
        "objectClass".to_string(),
        vec![
            "top".to_string(),
            "person".to_string(),
            "organizationalPerson".to_string(),
            "inetOrgPerson".to_string(),
        ],
    );
    attributes.insert("cn".to_string(), vec!["Carol Example".to_string()]);
    attributes.insert("sn".to_string(), vec!["Example".to_string()]);
    attributes.insert("manager".to_string(), vec!["not a dn".to_string()]);

    assert!(matches!(
        schema.validate_entry(&attributes),
        Err(SchemaError::InvalidSyntax(attribute, _)) if attribute == "manager"
    ));
}

#[test]
fn test_inet_org_person_mobile_requires_telephone_syntax() {
    let schema = LdapSchema::with_core_schema();

    let mut attributes = HashMap::new();
    attributes.insert(
        "objectClass".to_string(),
        vec![
            "top".to_string(),
            "person".to_string(),
            "organizationalPerson".to_string(),
            "inetOrgPerson".to_string(),
        ],
    );
    attributes.insert("cn".to_string(), vec!["Carol Example".to_string()]);
    attributes.insert("sn".to_string(), vec!["Example".to_string()]);
    attributes.insert("mobile".to_string(), vec!["+1_555".to_string()]);

    assert!(matches!(
        schema.validate_entry(&attributes),
        Err(SchemaError::InvalidSyntax(attribute, _)) if attribute == "mobile"
    ));
}

#[test]
fn test_inet_org_person_employee_number_is_single_value() {
    let schema = LdapSchema::with_core_schema();

    let mut attributes = HashMap::new();
    attributes.insert(
        "objectClass".to_string(),
        vec![
            "top".to_string(),
            "person".to_string(),
            "organizationalPerson".to_string(),
            "inetOrgPerson".to_string(),
        ],
    );
    attributes.insert("cn".to_string(), vec!["Carol Example".to_string()]);
    attributes.insert("sn".to_string(), vec!["Example".to_string()]);
    attributes.insert(
        "employeeNumber".to_string(),
        vec!["1001".to_string(), "1002".to_string()],
    );

    assert!(matches!(
        schema.validate_entry(&attributes),
        Err(SchemaError::SingleValueViolation(attribute)) if attribute == "employeeNumber"
    ));
}

#[test]
fn test_organization_entry() {
    let schema = LdapSchema::with_core_schema();

    let mut attributes = HashMap::new();
    attributes.insert(
        "objectClass".to_string(),
        vec!["top".to_string(), "organization".to_string()],
    );
    attributes.insert("o".to_string(), vec!["Acme Corporation".to_string()]);
    attributes.insert(
        "description".to_string(),
        vec!["Leading provider of innovative solutions".to_string()],
    );

    let result = schema.validate_entry(&attributes);
    assert!(result.is_ok(), "Valid organization entry should validate");
}

#[test]
fn test_organization_allows_expanded_rfc4519_contact_attributes() {
    let schema = LdapSchema::with_core_schema();

    let mut attributes = HashMap::new();
    attributes.insert(
        "objectClass".to_string(),
        vec!["top".to_string(), "organization".to_string()],
    );
    attributes.insert("o".to_string(), vec!["Example Corporation".to_string()]);
    attributes.insert("l".to_string(), vec!["Colombo".to_string()]);
    attributes.insert("st".to_string(), vec!["Western Province".to_string()]);
    attributes.insert("street".to_string(), vec!["100 Main Street".to_string()]);
    attributes.insert("postalCode".to_string(), vec!["00100".to_string()]);
    attributes.insert("postOfficeBox".to_string(), vec!["PO Box 42".to_string()]);
    attributes.insert(
        "physicalDeliveryOfficeName".to_string(),
        vec!["Head Office".to_string()],
    );
    attributes.insert(
        "postalAddress".to_string(),
        vec!["100 Main Street$Colombo".to_string()],
    );
    attributes.insert(
        "registeredAddress".to_string(),
        vec!["200 Registered Road$Colombo".to_string()],
    );
    attributes.insert(
        "telephoneNumber".to_string(),
        vec!["+94 11 555 0100".to_string()],
    );
    attributes.insert(
        "seeAlso".to_string(),
        vec!["ou=people,dc=example,dc=com".to_string()],
    );
    attributes.insert(
        "businessCategory".to_string(),
        vec!["Technology".to_string()],
    );

    assert!(
        schema.validate_entry(&attributes).is_ok(),
        "Organization should allow common RFC4519 contact attributes"
    );
}

#[test]
fn test_organizational_unit_entry() {
    let schema = LdapSchema::with_core_schema();

    let mut attributes = HashMap::new();
    attributes.insert(
        "objectClass".to_string(),
        vec!["top".to_string(), "organizationalUnit".to_string()],
    );
    attributes.insert("ou".to_string(), vec!["Sales".to_string()]);
    attributes.insert(
        "description".to_string(),
        vec!["Sales Department".to_string()],
    );

    let result = schema.validate_entry(&attributes);
    assert!(
        result.is_ok(),
        "Valid organizationalUnit entry should validate"
    );
}

#[test]
fn test_organizational_unit_allows_expanded_rfc4519_contact_attributes() {
    let schema = LdapSchema::with_core_schema();

    let mut attributes = HashMap::new();
    attributes.insert(
        "objectClass".to_string(),
        vec!["top".to_string(), "organizationalUnit".to_string()],
    );
    attributes.insert("ou".to_string(), vec!["Groups".to_string()]);
    attributes.insert("l".to_string(), vec!["Colombo".to_string()]);
    attributes.insert("st".to_string(), vec!["Western Province".to_string()]);
    attributes.insert("street".to_string(), vec!["100 Main Street".to_string()]);
    attributes.insert("postalCode".to_string(), vec!["00100".to_string()]);
    attributes.insert(
        "postalAddress".to_string(),
        vec!["100 Main Street$Colombo".to_string()],
    );
    attributes.insert(
        "registeredAddress".to_string(),
        vec!["200 Registered Road$Colombo".to_string()],
    );
    attributes.insert(
        "telephoneNumber".to_string(),
        vec!["+94 11 555 0100".to_string()],
    );
    attributes.insert(
        "seeAlso".to_string(),
        vec!["ou=people,dc=example,dc=com".to_string()],
    );
    attributes.insert(
        "businessCategory".to_string(),
        vec!["Directory container".to_string()],
    );

    assert!(
        schema.validate_entry(&attributes).is_ok(),
        "Organizational units should allow common RFC4519 contact attributes"
    );
}

#[test]
fn test_group_of_names_allows_empty_open_dj_style_group() {
    let schema = LdapSchema::with_core_schema();

    let mut attributes = HashMap::new();
    attributes.insert(
        "objectClass".to_string(),
        vec!["top".to_string(), "groupOfNames".to_string()],
    );
    attributes.insert("cn".to_string(), vec!["empty-group".to_string()]);
    attributes.insert("ou".to_string(), vec!["dc=example,dc=com".to_string()]);
    attributes.insert("description".to_string(), vec!["Empty group".to_string()]);

    assert!(
        schema.validate_entry(&attributes).is_ok(),
        "OpenDJ-style empty groupOfNames entries should validate"
    );
}

#[test]
fn test_group_of_names_allows_standard_optional_attributes() {
    let schema = LdapSchema::with_core_schema();

    let mut attributes = HashMap::new();
    attributes.insert(
        "objectClass".to_string(),
        vec!["top".to_string(), "groupOfNames".to_string()],
    );
    attributes.insert("cn".to_string(), vec!["operators".to_string()]);
    attributes.insert(
        "member".to_string(),
        vec!["uid=user1,ou=people,dc=example,dc=com".to_string()],
    );
    attributes.insert(
        "owner".to_string(),
        vec!["uid=owner,ou=people,dc=example,dc=com".to_string()],
    );
    attributes.insert(
        "seeAlso".to_string(),
        vec!["cn=auditors,ou=groups,dc=example,dc=com".to_string()],
    );
    attributes.insert("businessCategory".to_string(), vec!["Access".to_string()]);
    attributes.insert("o".to_string(), vec!["Example Corporation".to_string()]);
    attributes.insert("ou".to_string(), vec!["Security".to_string()]);
    attributes.insert("description".to_string(), vec!["Operators".to_string()]);

    assert!(
        schema.validate_entry(&attributes).is_ok(),
        "groupOfNames should allow the standard optional attributes OpenDR supports"
    );
}

#[test]
fn test_group_of_names_allows_member_values() {
    let schema = LdapSchema::with_core_schema();

    let mut attributes = HashMap::new();
    attributes.insert(
        "objectClass".to_string(),
        vec!["top".to_string(), "groupOfNames".to_string()],
    );
    attributes.insert("cn".to_string(), vec!["users".to_string()]);
    attributes.insert(
        "member".to_string(),
        vec!["uid=user1,ou=people,dc=example,dc=com".to_string()],
    );

    assert!(
        schema.validate_entry(&attributes).is_ok(),
        "groupOfNames entries with members should still validate"
    );
}

#[test]
fn test_group_of_unique_names_entry() {
    let schema = LdapSchema::with_core_schema();

    let mut attributes = HashMap::new();
    attributes.insert(
        "objectClass".to_string(),
        vec!["top".to_string(), "groupOfUniqueNames".to_string()],
    );
    attributes.insert("cn".to_string(), vec!["admins".to_string()]);
    attributes.insert(
        "uniqueMember".to_string(),
        vec!["uid=alice,ou=people,dc=example,dc=com".to_string()],
    );
    attributes.insert(
        "owner".to_string(),
        vec!["uid=owner,ou=people,dc=example,dc=com".to_string()],
    );
    attributes.insert(
        "description".to_string(),
        vec!["Administrators".to_string()],
    );

    assert!(
        schema.validate_entry(&attributes).is_ok(),
        "groupOfUniqueNames should validate with DN-valued uniqueMember"
    );
}

#[test]
fn test_group_of_unique_names_requires_unique_member() {
    let schema = LdapSchema::with_core_schema();

    let mut attributes = HashMap::new();
    attributes.insert(
        "objectClass".to_string(),
        vec!["top".to_string(), "groupOfUniqueNames".to_string()],
    );
    attributes.insert("cn".to_string(), vec!["admins".to_string()]);

    assert!(matches!(
        schema.validate_entry(&attributes),
        Err(SchemaError::MissingRequiredAttribute(attribute)) if attribute == "uniqueMember"
    ));
}

#[test]
fn test_unique_member_requires_dn_syntax() {
    let schema = LdapSchema::with_core_schema();

    let mut attributes = HashMap::new();
    attributes.insert(
        "objectClass".to_string(),
        vec!["top".to_string(), "groupOfUniqueNames".to_string()],
    );
    attributes.insert("cn".to_string(), vec!["admins".to_string()]);
    attributes.insert("uniqueMember".to_string(), vec!["not a dn".to_string()]);

    assert!(matches!(
        schema.validate_entry(&attributes),
        Err(SchemaError::InvalidSyntax(attribute, _)) if attribute == "uniqueMember"
    ));
}

#[test]
fn test_posix_group_entry() {
    let mut schema = LdapSchema::with_core_schema();
    schema.load_builtin_schema("posix").unwrap();

    let mut attributes = HashMap::new();
    attributes.insert(
        "objectClass".to_string(),
        vec!["top".to_string(), "posixGroup".to_string()],
    );
    attributes.insert("cn".to_string(), vec!["developers".to_string()]);
    attributes.insert("gidNumber".to_string(), vec!["1000".to_string()]);
    attributes.insert(
        "memberUid".to_string(),
        vec!["alice".to_string(), "bob".to_string()],
    );
    attributes.insert("description".to_string(), vec!["Developers".to_string()]);

    assert!(
        schema.validate_entry(&attributes).is_ok(),
        "posixGroup should validate with login-name memberUid values"
    );
}

#[test]
fn test_posix_account_auxiliary_entry() {
    let mut schema = LdapSchema::with_core_schema();
    schema.load_builtin_schema("posix").unwrap();

    let mut attributes = HashMap::new();
    attributes.insert(
        "objectClass".to_string(),
        vec![
            "top".to_string(),
            "person".to_string(),
            "organizationalPerson".to_string(),
            "inetOrgPerson".to_string(),
            "posixAccount".to_string(),
        ],
    );
    attributes.insert("cn".to_string(), vec!["Alice Example".to_string()]);
    attributes.insert("sn".to_string(), vec!["Example".to_string()]);
    attributes.insert("uid".to_string(), vec!["alice".to_string()]);
    attributes.insert("uidNumber".to_string(), vec!["1001".to_string()]);
    attributes.insert("gidNumber".to_string(), vec!["1000".to_string()]);
    attributes.insert("homeDirectory".to_string(), vec!["/home/alice".to_string()]);
    attributes.insert("loginShell".to_string(), vec!["/bin/zsh".to_string()]);
    attributes.insert("gecos".to_string(), vec!["Alice Example".to_string()]);

    assert!(
        schema.validate_entry(&attributes).is_ok(),
        "posixAccount should work as an auxiliary class on a normal person entry"
    );
}

#[test]
fn test_posix_account_requires_integer_uid_number() {
    let mut schema = LdapSchema::with_core_schema();
    schema.load_builtin_schema("posix").unwrap();

    let mut attributes = HashMap::new();
    attributes.insert(
        "objectClass".to_string(),
        vec![
            "top".to_string(),
            "person".to_string(),
            "organizationalPerson".to_string(),
            "inetOrgPerson".to_string(),
            "posixAccount".to_string(),
        ],
    );
    attributes.insert("cn".to_string(), vec!["Alice Example".to_string()]);
    attributes.insert("sn".to_string(), vec!["Example".to_string()]);
    attributes.insert("uid".to_string(), vec!["alice".to_string()]);
    attributes.insert("uidNumber".to_string(), vec!["01001".to_string()]);
    attributes.insert("gidNumber".to_string(), vec!["1000".to_string()]);
    attributes.insert("homeDirectory".to_string(), vec!["/home/alice".to_string()]);

    assert!(matches!(
        schema.validate_entry(&attributes),
        Err(SchemaError::InvalidSyntax(attribute, _)) if attribute == "uidNumber"
    ));
}

#[test]
fn test_posix_account_requires_home_directory() {
    let mut schema = LdapSchema::with_core_schema();
    schema.load_builtin_schema("posix").unwrap();

    let mut attributes = HashMap::new();
    attributes.insert(
        "objectClass".to_string(),
        vec![
            "top".to_string(),
            "person".to_string(),
            "organizationalPerson".to_string(),
            "inetOrgPerson".to_string(),
            "posixAccount".to_string(),
        ],
    );
    attributes.insert("cn".to_string(), vec!["Alice Example".to_string()]);
    attributes.insert("sn".to_string(), vec!["Example".to_string()]);
    attributes.insert("uid".to_string(), vec!["alice".to_string()]);
    attributes.insert("uidNumber".to_string(), vec!["1001".to_string()]);
    attributes.insert("gidNumber".to_string(), vec!["1000".to_string()]);

    assert!(matches!(
        schema.validate_entry(&attributes),
        Err(SchemaError::MissingRequiredAttribute(attribute)) if attribute == "homeDirectory"
    ));
}

#[test]
fn test_posix_group_member_uid_is_not_a_dn() {
    let mut schema = LdapSchema::with_core_schema();
    schema.load_builtin_schema("posix").unwrap();

    let mut attributes = HashMap::new();
    attributes.insert(
        "objectClass".to_string(),
        vec!["top".to_string(), "posixGroup".to_string()],
    );
    attributes.insert("cn".to_string(), vec!["developers".to_string()]);
    attributes.insert("gidNumber".to_string(), vec!["1000".to_string()]);
    attributes.insert("memberUid".to_string(), vec!["alice".to_string()]);

    assert!(
        schema.validate_entry(&attributes).is_ok(),
        "memberUid should accept POSIX login names, not require DN syntax"
    );
}

#[test]
fn test_posix_group_member_uid_requires_ia5_syntax() {
    let mut schema = LdapSchema::with_core_schema();
    schema.load_builtin_schema("posix").unwrap();

    let mut attributes = HashMap::new();
    attributes.insert(
        "objectClass".to_string(),
        vec!["top".to_string(), "posixGroup".to_string()],
    );
    attributes.insert("cn".to_string(), vec!["developers".to_string()]);
    attributes.insert("gidNumber".to_string(), vec!["1000".to_string()]);
    attributes.insert("memberUid".to_string(), vec!["álîçé".to_string()]);

    assert!(matches!(
        schema.validate_entry(&attributes),
        Err(SchemaError::InvalidSyntax(attribute, _)) if attribute == "memberUid"
    ));
}

#[test]
fn test_standard_directory_ldif_fixture_validates() {
    let mut schema = LdapSchema::with_core_schema();
    schema.load_builtin_schema("posix").unwrap();

    let entries = parse_simple_entry_ldif(include_str!(
        "../docs/schema_examples/standard-directory.ldif"
    ));
    assert!(!entries.is_empty(), "fixture should contain entries");

    for (index, attributes) in entries.iter().enumerate() {
        assert!(
            schema.validate_entry(attributes).is_ok(),
            "fixture entry {} should validate: {:?}",
            index + 1,
            attributes
        );
    }
}

#[test]
fn test_missing_cn_for_person() {
    let schema = LdapSchema::with_core_schema();

    let mut attributes = HashMap::new();
    attributes.insert(
        "objectClass".to_string(),
        vec!["top".to_string(), "person".to_string()],
    );
    attributes.insert("sn".to_string(), vec!["Doe".to_string()]);
    // Missing cn

    let result = schema.validate_entry(&attributes);
    assert!(result.is_err(), "Person without cn should fail");
    assert!(matches!(
        result,
        Err(SchemaError::MissingRequiredAttribute(_))
    ));
}

#[test]
fn test_missing_sn_for_person() {
    let schema = LdapSchema::with_core_schema();

    let mut attributes = HashMap::new();
    attributes.insert(
        "objectClass".to_string(),
        vec!["top".to_string(), "person".to_string()],
    );
    attributes.insert("cn".to_string(), vec!["John Doe".to_string()]);
    // Missing sn

    let result = schema.validate_entry(&attributes);
    assert!(result.is_err(), "Person without sn should fail");
    assert!(matches!(
        result,
        Err(SchemaError::MissingRequiredAttribute(_))
    ));
}

#[test]
fn test_unknown_object_class() {
    let schema = LdapSchema::with_core_schema();

    let mut attributes = HashMap::new();
    attributes.insert(
        "objectClass".to_string(),
        vec!["top".to_string(), "mysteryClass".to_string()],
    );
    attributes.insert("cn".to_string(), vec!["Test".to_string()]);

    let result = schema.validate_entry(&attributes);
    assert!(result.is_err(), "Unknown object class should fail");
    assert!(matches!(result, Err(SchemaError::ObjectClassNotFound(_))));
}

#[test]
fn test_only_abstract_object_class() {
    let schema = LdapSchema::with_core_schema();

    let mut attributes = HashMap::new();
    attributes.insert("objectClass".to_string(), vec!["top".to_string()]);

    let result = schema.validate_entry(&attributes);
    assert!(result.is_err(), "Only abstract objectClass should fail");
    assert!(matches!(result, Err(SchemaError::NoStructuralClass)));
}

#[test]
fn test_custom_auxiliary_class() {
    let mut schema = LdapSchema::with_core_schema();

    // Add custom auxiliary class
    schema.add_object_class(ObjectClass {
        oid: "1.2.3.4.5".to_string(),
        names: vec!["customAux".to_string()],
        sup: vec!["top".to_string()],
        kind: ObjectClassKind::Auxiliary,
        must: vec!["description".to_string()],
        may: vec![],
    });

    let mut attributes = HashMap::new();
    attributes.insert(
        "objectClass".to_string(),
        vec![
            "top".to_string(),
            "person".to_string(),
            "customAux".to_string(),
        ],
    );
    attributes.insert("cn".to_string(), vec!["Test".to_string()]);
    attributes.insert("sn".to_string(), vec!["User".to_string()]);
    attributes.insert(
        "description".to_string(),
        vec!["Required by auxiliary".to_string()],
    );

    let result = schema.validate_entry(&attributes);
    assert!(result.is_ok(), "Structural + auxiliary should validate");
}

#[test]
fn test_single_value_constraint() {
    let mut schema = LdapSchema::with_core_schema();

    // Add single-value attribute
    schema.add_attribute_type(AttributeType {
        oid: "1.2.3.4.6".to_string(),
        names: vec!["employeeID".to_string()],
        description: Some("Employee ID number".to_string()),
        equality: Some("caseIgnoreMatch".to_string()),
        syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(),
        single_value: true,
    });

    // Add auxiliary class that allows employeeID
    schema.add_object_class(ObjectClass {
        oid: "1.2.3.4.7".to_string(),
        names: vec!["employee".to_string()],
        sup: vec!["top".to_string()],
        kind: ObjectClassKind::Auxiliary,
        must: vec![],
        may: vec!["employeeID".to_string()],
    });

    let mut attributes = HashMap::new();
    attributes.insert(
        "objectClass".to_string(),
        vec![
            "top".to_string(),
            "person".to_string(),
            "employee".to_string(),
        ],
    );
    attributes.insert("cn".to_string(), vec!["Worker".to_string()]);
    attributes.insert("sn".to_string(), vec!["Bee".to_string()]);
    attributes.insert(
        "employeeID".to_string(),
        vec!["E001".to_string(), "E002".to_string()],
    );

    let result = schema.validate_entry(&attributes);
    assert!(
        result.is_err(),
        "Multiple values for single-value attribute should fail"
    );
    assert!(matches!(result, Err(SchemaError::SingleValueViolation(_))));
}

#[test]
fn test_single_value_attribute_with_one_value() {
    let mut schema = LdapSchema::with_core_schema();

    schema.add_attribute_type(AttributeType {
        oid: "1.2.3.4.8".to_string(),
        names: vec!["serialNumber".to_string()],
        description: Some("Serial number".to_string()),
        equality: Some("caseIgnoreMatch".to_string()),
        syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(),
        single_value: true,
    });

    schema.add_object_class(ObjectClass {
        oid: "1.2.3.4.9".to_string(),
        names: vec!["device".to_string()],
        sup: vec!["top".to_string()],
        kind: ObjectClassKind::Structural,
        must: vec!["cn".to_string()],
        may: vec!["serialNumber".to_string()],
    });

    let mut attributes = HashMap::new();
    attributes.insert(
        "objectClass".to_string(),
        vec!["top".to_string(), "device".to_string()],
    );
    attributes.insert("cn".to_string(), vec!["Device1".to_string()]);
    attributes.insert("serialNumber".to_string(), vec!["SN12345".to_string()]);

    let result = schema.validate_entry(&attributes);
    assert!(
        result.is_ok(),
        "Single value for single-value attribute should validate"
    );
}

#[test]
fn test_case_insensitive_object_class_names() {
    let schema = LdapSchema::with_core_schema();

    let mut attributes = HashMap::new();
    attributes.insert(
        "objectClass".to_string(),
        vec!["TOP".to_string(), "Person".to_string()],
    );
    attributes.insert("CN".to_string(), vec!["Test User".to_string()]);
    attributes.insert("SN".to_string(), vec!["User".to_string()]);

    let result = schema.validate_entry(&attributes);
    assert!(
        result.is_ok(),
        "Case-insensitive objectClass names should work"
    );
}

#[test]
fn test_case_insensitive_attribute_names() {
    let schema = LdapSchema::with_core_schema();

    // Test attribute names with mixed case
    let mut attributes = HashMap::new();
    attributes.insert(
        "objectClass".to_string(),
        vec!["top".to_string(), "person".to_string()],
    );
    attributes.insert("Cn".to_string(), vec!["Mixed Case".to_string()]);
    attributes.insert("sN".to_string(), vec!["Test".to_string()]);

    let result = schema.validate_entry(&attributes);
    assert!(
        result.is_ok(),
        "Case-insensitive attribute names should work"
    );
}

#[test]
fn test_inheritance_chain_person_to_inetorgperson() {
    let schema = LdapSchema::with_core_schema();

    // Use only inetOrgPerson (most derived), should inherit all requirements
    let mut attributes = HashMap::new();
    attributes.insert(
        "objectClass".to_string(),
        vec![
            "top".to_string(),
            "person".to_string(),
            "organizationalPerson".to_string(),
            "inetOrgPerson".to_string(),
        ],
    );
    attributes.insert("cn".to_string(), vec!["Inherited Test".to_string()]);
    attributes.insert("sn".to_string(), vec!["Test".to_string()]);

    let result = schema.validate_entry(&attributes);
    assert!(result.is_ok(), "Full inheritance chain should validate");
}

#[test]
fn test_missing_intermediate_class_in_chain() {
    let schema = LdapSchema::with_core_schema();

    // Skip organizationalPerson in the chain
    let mut attributes = HashMap::new();
    attributes.insert(
        "objectClass".to_string(),
        vec![
            "top".to_string(),
            "person".to_string(),
            "inetOrgPerson".to_string(), // Skipped organizationalPerson
        ],
    );
    attributes.insert("cn".to_string(), vec!["Skip Test".to_string()]);
    attributes.insert("sn".to_string(), vec!["Test".to_string()]);

    // Should still work - intermediate classes are not required if attributes are met
    let result = schema.validate_entry(&attributes);
    assert!(
        result.is_ok(),
        "Skipping intermediate class should still validate if attrs are present"
    );
}

#[test]
fn test_multiple_values_for_multi_value_attribute() {
    let schema = LdapSchema::with_core_schema();

    let mut attributes = HashMap::new();
    attributes.insert(
        "objectClass".to_string(),
        vec!["top".to_string(), "person".to_string()],
    );
    attributes.insert(
        "cn".to_string(),
        vec![
            "Primary Name".to_string(),
            "Secondary Name".to_string(),
            "Alias Name".to_string(),
        ],
    );
    attributes.insert("sn".to_string(), vec!["Multi".to_string()]);

    let result = schema.validate_entry(&attributes);
    assert!(
        result.is_ok(),
        "Multiple values for multi-value attribute should be allowed"
    );
}

#[test]
fn test_complex_entry_with_all_features() {
    let mut schema = LdapSchema::with_core_schema();

    // Add custom attribute
    schema.add_attribute_type(AttributeType {
        oid: "1.2.3.10".to_string(),
        names: vec!["badge".to_string()],
        description: Some("Employee badge number".to_string()),
        equality: Some("caseIgnoreMatch".to_string()),
        syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(),
        single_value: true,
    });

    // Add custom auxiliary class
    schema.add_object_class(ObjectClass {
        oid: "1.2.3.11".to_string(),
        names: vec!["badgedEmployee".to_string()],
        sup: vec!["top".to_string()],
        kind: ObjectClassKind::Auxiliary,
        must: vec!["badge".to_string()],
        may: vec![],
    });

    let mut attributes = HashMap::new();
    attributes.insert(
        "objectClass".to_string(),
        vec![
            "top".to_string(),
            "person".to_string(),
            "organizationalPerson".to_string(),
            "inetOrgPerson".to_string(),
            "badgedEmployee".to_string(), // Auxiliary
        ],
    );
    attributes.insert(
        "cn".to_string(),
        vec!["Complex User".to_string(), "CU".to_string()],
    );
    attributes.insert("sn".to_string(), vec!["User".to_string()]);
    attributes.insert("givenName".to_string(), vec!["Complex".to_string()]);
    attributes.insert("uid".to_string(), vec!["cuser".to_string()]);
    attributes.insert(
        "mail".to_string(),
        vec![
            "complex@example.com".to_string(),
            "cu@example.com".to_string(),
        ],
    );
    attributes.insert("badge".to_string(), vec!["BADGE-001".to_string()]);
    attributes.insert(
        "description".to_string(),
        vec!["Complex test case".to_string()],
    );

    let result = schema.validate_entry(&attributes);
    assert!(
        result.is_ok(),
        "Complex entry with all features should validate"
    );
}

#[test]
fn test_empty_attributes_map() {
    let schema = LdapSchema::with_core_schema();

    let attributes = HashMap::new();

    let result = schema.validate_entry(&attributes);
    assert!(result.is_err(), "Empty attributes should fail");
    assert!(matches!(
        result,
        Err(SchemaError::MissingRequiredAttribute(_))
    ));
}

#[test]
fn test_schema_extension_with_new_object_class() {
    let mut schema = LdapSchema::new(); // Start empty

    // Manually add required base classes
    schema.add_object_class(ObjectClass {
        oid: "2.5.6.0".to_string(),
        names: vec!["top".to_string()],
        sup: vec![],
        kind: ObjectClassKind::Abstract,
        must: vec!["objectClass".to_string()],
        may: vec![],
    });

    schema.add_attribute_type(AttributeType {
        oid: "2.5.4.0".to_string(),
        names: vec!["objectClass".to_string()],
        description: Some("Object class".to_string()),
        equality: Some("objectIdentifierMatch".to_string()),
        syntax: "1.3.6.1.4.1.1466.115.121.1.38".to_string(),
        single_value: false,
    });

    schema.add_attribute_type(AttributeType {
        oid: "2.5.4.3".to_string(),
        names: vec!["cn".to_string()],
        description: Some("Common name".to_string()),
        equality: Some("caseIgnoreMatch".to_string()),
        syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(),
        single_value: false,
    });

    // Add custom structural class
    schema.add_object_class(ObjectClass {
        oid: "1.3.5.7".to_string(),
        names: vec!["customEntity".to_string()],
        sup: vec!["top".to_string()],
        kind: ObjectClassKind::Structural,
        must: vec!["cn".to_string()],
        may: vec![],
    });

    let mut attributes = HashMap::new();
    attributes.insert(
        "objectClass".to_string(),
        vec!["top".to_string(), "customEntity".to_string()],
    );
    attributes.insert("cn".to_string(), vec!["Custom1".to_string()]);

    let result = schema.validate_entry(&attributes);
    assert!(result.is_ok(), "Custom schema extension should work");
}

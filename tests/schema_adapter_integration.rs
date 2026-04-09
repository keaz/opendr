//! Integration tests for LdapSchemaValidator adapter with WriteFSM
//!
//! Tests the integration of the schema validator with the write FSM to ensure
//! proper validation of LDAP write operations.

use opendr::schema_adapter::LdapSchemaValidator;
use opendr::write_fsm::{Modification, SchemaValidator, WriteEntry};
use std::collections::HashMap;

#[tokio::test]
async fn test_schema_validator_valid_person_entry() {
    let validator = LdapSchemaValidator::new();

    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["John Doe".to_string()]);
    attributes.insert("sn".to_string(), vec!["Doe".to_string()]);

    let entry = WriteEntry {
        dn: "cn=John Doe,ou=People,dc=example,dc=com".to_string(),
        attributes,
        object_classes: vec!["top".to_string(), "person".to_string()],
        binary_attributes: HashMap::new(),
    };

    let result = validator.validate_entry(&entry).await;
    assert!(result.is_ok(), "Valid person entry should pass validation");
}

#[tokio::test]
async fn test_schema_validator_missing_required_attribute() {
    let validator = LdapSchemaValidator::new();

    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["John Doe".to_string()]);
    // Missing 'sn' which is required by person

    let entry = WriteEntry {
        dn: "cn=John Doe,ou=People,dc=example,dc=com".to_string(),
        attributes,
        object_classes: vec!["top".to_string(), "person".to_string()],
        binary_attributes: HashMap::new(),
    };

    let result = validator.validate_entry(&entry).await;
    assert!(
        result.is_err(),
        "Entry missing required attribute should fail"
    );
    assert!(result.unwrap_err().contains("Missing required attribute"));
}

#[tokio::test]
async fn test_schema_validator_unknown_object_class() {
    let validator = LdapSchemaValidator::new();

    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["Test".to_string()]);

    let entry = WriteEntry {
        dn: "cn=Test,dc=example,dc=com".to_string(),
        attributes,
        object_classes: vec!["unknownClass".to_string()],
        binary_attributes: HashMap::new(),
    };

    let result = validator.validate_entry(&entry).await;
    assert!(
        result.is_err(),
        "Unknown object class should fail validation"
    );
    assert!(result.unwrap_err().contains("Object class not found"));
}

#[tokio::test]
async fn test_schema_validator_inetorgperson_entry() {
    let validator = LdapSchemaValidator::new();

    let mut attributes = HashMap::new();
    attributes.insert("cn".to_string(), vec!["Jane Smith".to_string()]);
    attributes.insert("sn".to_string(), vec!["Smith".to_string()]);
    attributes.insert("uid".to_string(), vec!["jsmith".to_string()]);
    attributes.insert("mail".to_string(), vec!["jsmith@example.com".to_string()]);

    let entry = WriteEntry {
        dn: "uid=jsmith,ou=People,dc=example,dc=com".to_string(),
        attributes,
        object_classes: vec![
            "top".to_string(),
            "person".to_string(),
            "organizationalPerson".to_string(),
            "inetOrgPerson".to_string(),
        ],
        binary_attributes: HashMap::new(),
    };

    let result = validator.validate_entry(&entry).await;
    assert!(
        result.is_ok(),
        "Valid inetOrgPerson entry should pass validation"
    );
}

#[tokio::test]
async fn test_validate_modifications_valid() {
    let validator = LdapSchemaValidator::new();

    let modifications = vec![
        Modification::Add {
            name: "mail".to_string(),
            values: vec!["john@example.com".to_string()],
        },
        Modification::Replace {
            name: "description".to_string(),
            values: vec!["Updated description".to_string()],
        },
    ];

    let result = validator
        .validate_modifications("cn=John Doe,dc=example,dc=com", &modifications)
        .await;

    assert!(result.is_ok(), "Valid modifications should pass");
}

#[tokio::test]
async fn test_validate_modifications_unknown_attribute() {
    let validator = LdapSchemaValidator::new();

    let modifications = vec![Modification::Add {
        name: "unknownAttr".to_string(),
        values: vec!["value".to_string()],
    }];

    let result = validator
        .validate_modifications("cn=John Doe,dc=example,dc=com", &modifications)
        .await;

    assert!(
        result.is_err(),
        "Unknown attribute in modification should fail"
    );
    assert!(result.unwrap_err().contains("Unknown attribute type"));
}

#[tokio::test]
async fn test_validate_dn_modification_valid() {
    let validator = LdapSchemaValidator::new();

    let result = validator
        .validate_dn_modification("cn=John Doe,dc=example,dc=com", "cn=Jane Doe", None)
        .await;

    assert!(result.is_ok(), "Valid DN modification should pass");
}

#[tokio::test]
async fn test_validate_dn_modification_invalid_rdn() {
    let validator = LdapSchemaValidator::new();

    let result = validator
        .validate_dn_modification("cn=John Doe,dc=example,dc=com", "invalid_rdn", None)
        .await;

    assert!(result.is_err(), "Invalid RDN format should fail");
    assert!(result.unwrap_err().contains("Invalid RDN format"));
}

#[tokio::test]
async fn test_validate_dn_modification_unknown_attribute() {
    let validator = LdapSchemaValidator::new();

    let result = validator
        .validate_dn_modification("cn=John Doe,dc=example,dc=com", "unknownAttr=value", None)
        .await;

    assert!(result.is_err(), "Unknown attribute in RDN should fail");
    assert!(result.unwrap_err().contains("Unknown attribute type"));
}

#[tokio::test]
async fn test_is_object_class_defined() {
    let validator = LdapSchemaValidator::new();

    assert!(validator.is_object_class_defined("person"));
    assert!(validator.is_object_class_defined("inetOrgPerson"));
    assert!(validator.is_object_class_defined("organization"));
    assert!(!validator.is_object_class_defined("unknownClass"));
}

#[tokio::test]
async fn test_organizational_unit_entry() {
    let validator = LdapSchemaValidator::new();

    let mut attributes = HashMap::new();
    attributes.insert("ou".to_string(), vec!["Engineering".to_string()]);
    attributes.insert(
        "description".to_string(),
        vec!["Engineering Department".to_string()],
    );

    let entry = WriteEntry {
        dn: "ou=Engineering,dc=example,dc=com".to_string(),
        attributes,
        object_classes: vec!["top".to_string(), "organizationalUnit".to_string()],
        binary_attributes: HashMap::new(),
    };

    let result = validator.validate_entry(&entry).await;
    assert!(
        result.is_ok(),
        "Valid organizationalUnit entry should pass validation"
    );
}

#[tokio::test]
async fn test_organization_entry() {
    let validator = LdapSchemaValidator::new();

    let mut attributes = HashMap::new();
    attributes.insert("o".to_string(), vec!["Example Corp".to_string()]);
    attributes.insert(
        "description".to_string(),
        vec!["Example Corporation".to_string()],
    );

    let entry = WriteEntry {
        dn: "dc=example,dc=com".to_string(),
        attributes,
        object_classes: vec!["top".to_string(), "organization".to_string()],
        binary_attributes: HashMap::new(),
    };

    let result = validator.validate_entry(&entry).await;
    assert!(
        result.is_ok(),
        "Valid organization entry should pass validation"
    );
}

#[tokio::test]
async fn test_no_structural_class() {
    let validator = LdapSchemaValidator::new();

    let attributes = HashMap::new();

    let entry = WriteEntry {
        dn: "cn=Test,dc=example,dc=com".to_string(),
        attributes,
        object_classes: vec!["top".to_string()], // Only abstract class
        binary_attributes: HashMap::new(),
    };

    let result = validator.validate_entry(&entry).await;
    assert!(
        result.is_err(),
        "Entry with only abstract class should fail"
    );
    assert!(result.unwrap_err().contains("No structural"));
}

#[tokio::test]
async fn test_case_insensitive_validation() {
    let validator = LdapSchemaValidator::new();

    let mut attributes = HashMap::new();
    attributes.insert("CN".to_string(), vec!["Test User".to_string()]);
    attributes.insert("SN".to_string(), vec!["User".to_string()]);

    let entry = WriteEntry {
        dn: "cn=Test User,dc=example,dc=com".to_string(),
        attributes,
        object_classes: vec!["TOP".to_string(), "Person".to_string()],
        binary_attributes: HashMap::new(),
    };

    let result = validator.validate_entry(&entry).await;
    assert!(
        result.is_ok(),
        "Case-insensitive attribute names should work"
    );
}

#[tokio::test]
async fn test_multiple_modifications() {
    let validator = LdapSchemaValidator::new();

    let modifications = vec![
        Modification::Add {
            name: "mail".to_string(),
            values: vec!["user@example.com".to_string()],
        },
        Modification::Replace {
            name: "description".to_string(),
            values: vec!["New description".to_string()],
        },
        Modification::Delete {
            name: "userPassword".to_string(),
            values: vec![],
        },
    ];

    let result = validator
        .validate_modifications("cn=User,dc=example,dc=com", &modifications)
        .await;

    assert!(result.is_ok(), "Multiple valid modifications should pass");
}

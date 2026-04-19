use std::collections::HashMap;

use opendr::backend::{
    DirectoryAttributeProjection, DirectoryBackend, DirectoryEntry, MockBackend,
    OperationalAttributes,
};
use opendr::csn::Csn;
use opendr::fsm_request::active_fsm_control_registry;
use opendr::schema::{LdapSchema, SchemaError};
use opendr::search_controls::{
    PAGED_RESULTS_OID, SERVER_SIDE_SORT_REQUEST_OID, SUBENTRIES_CONTROL_OID,
};
use opendr::search_protocol::{
    MODIFY_INCREMENT_FEATURE_OID, REQUEST_ATTRIBUTES_BY_OBJECT_CLASS_FEATURE_OID,
    build_root_dse_attributes, build_subschema_attributes,
};
use opendr::sync_controls::{SYNC_DONE_OID, SYNC_REQUEST_OID, SYNC_STATE_OID};

const MANAGE_DSA_IT_OID: &str = "2.16.840.1.113730.3.4.2";
const START_TLS_OID: &str = "1.3.6.1.4.1.1466.20037";
const CANCEL_OID: &str = "1.3.6.1.1.8";
const PASSWORD_MODIFY_OID: &str = "1.3.6.1.4.1.4203.1.11.1";
const WHO_AM_I_OID: &str = "1.3.6.1.4.1.4203.1.11.3";
const SERVER_SIDE_SORT_RESPONSE_OID: &str = "1.2.840.113556.1.4.474";
const ASSERTION_CONTROL_OID: &str = "1.3.6.1.1.12";
const PRE_READ_CONTROL_OID: &str = "1.3.6.1.1.13.1";
const POST_READ_CONTROL_OID: &str = "1.3.6.1.1.13.2";

#[tokio::test]
async fn root_dse_base_attributes_follow_rfc_4512_and_truthful_advertising() {
    let backend = MockBackend::new();
    backend
        .set_context_csn(Csn::with_values(1696680896789012, 1, 1, 0))
        .await
        .unwrap();
    let registry = active_fsm_control_registry();

    let attributes = build_root_dse_attributes(
        &backend,
        &["dc=example,dc=org".to_string()],
        "cn=Subschema",
        false,
        true,
        &registry.root_dse_supported_control_oids(),
        &[],
    )
    .await
    .unwrap();
    let attributes = attributes.into_iter().collect::<HashMap<_, _>>();

    assert_eq!(
        attributes.get("supportedLDAPVersion").unwrap(),
        &vec!["3".to_string()]
    );
    assert_eq!(
        attributes.get("namingContexts").unwrap(),
        &vec!["dc=example,dc=org".to_string()]
    );
    assert_eq!(
        attributes.get("subschemaSubentry").unwrap(),
        &vec!["cn=Subschema".to_string()]
    );
    assert_eq!(
        attributes.get("contextCSN").unwrap(),
        &vec!["1696680896789012#001#000001#000000".to_string()]
    );

    let mut supported_controls = attributes.get("supportedControl").unwrap().clone();
    supported_controls.sort();
    let mut expected_controls = vec![
        MANAGE_DSA_IT_OID.to_string(),
        PAGED_RESULTS_OID.to_string(),
        SERVER_SIDE_SORT_REQUEST_OID.to_string(),
        SUBENTRIES_CONTROL_OID.to_string(),
        SYNC_REQUEST_OID.to_string(),
    ];
    expected_controls.sort();
    assert_eq!(supported_controls, expected_controls);
    for unsupported_or_response_only in [
        SERVER_SIDE_SORT_RESPONSE_OID,
        SYNC_STATE_OID,
        SYNC_DONE_OID,
        ASSERTION_CONTROL_OID,
        PRE_READ_CONTROL_OID,
        POST_READ_CONTROL_OID,
    ] {
        assert!(
            !supported_controls.contains(&unsupported_or_response_only.to_string()),
            "Root DSE must not advertise unsupported or response-only control {unsupported_or_response_only}"
        );
    }

    let mut supported_extensions = attributes.get("supportedExtension").unwrap().clone();
    supported_extensions.sort();
    let mut expected_extensions = vec![
        START_TLS_OID.to_string(),
        CANCEL_OID.to_string(),
        PASSWORD_MODIFY_OID.to_string(),
        WHO_AM_I_OID.to_string(),
    ];
    expected_extensions.sort();
    assert_eq!(supported_extensions, expected_extensions);

    let mut supported_features = attributes.get("supportedFeatures").unwrap().clone();
    supported_features.sort();
    assert_eq!(
        supported_features,
        vec![
            MODIFY_INCREMENT_FEATURE_OID.to_string(),
            REQUEST_ATTRIBUTES_BY_OBJECT_CLASS_FEATURE_OID.to_string(),
        ]
    );
}

#[test]
fn subschema_publication_contains_core_schema_and_posix_builtin_bundle() {
    let mut schema = LdapSchema::with_core_schema();
    schema.load_builtin_schema("posix").unwrap();

    let attributes = build_subschema_attributes(&schema)
        .into_iter()
        .collect::<HashMap<_, _>>();

    assert_eq!(
        attributes.get("objectClass").unwrap(),
        &vec![
            "top".to_string(),
            "subentry".to_string(),
            "subschema".to_string()
        ]
    );
    assert_eq!(
        attributes.get("cn").unwrap(),
        &vec!["Subschema".to_string()]
    );

    let attribute_types = attributes.get("attributeTypes").unwrap();
    assert_contains_schema_description(attribute_types, "NAME ( 'cn' 'commonName' )");
    assert_contains_schema_description(attribute_types, "NAME 'uidNumber'");
    assert_contains_schema_description(attribute_types, "NAME 'gidNumber'");
    assert_contains_schema_description(attribute_types, "NAME 'homeDirectory'");

    let object_classes = attributes.get("objectClasses").unwrap();
    assert_contains_schema_description(object_classes, "NAME 'person'");
    assert_contains_schema_description(object_classes, "NAME 'inetOrgPerson'");
    assert_contains_schema_description(object_classes, "NAME 'posixAccount'");
    assert_contains_schema_description(object_classes, "NAME 'posixGroup'");

    let ldap_syntaxes = attributes.get("ldapSyntaxes").unwrap();
    assert_contains_schema_description(ldap_syntaxes, "Directory String");
    assert_contains_schema_description(ldap_syntaxes, "Integer");

    let matching_rules = attributes.get("matchingRules").unwrap();
    assert_contains_schema_description(matching_rules, "caseIgnoreMatch");
    assert_contains_schema_description(matching_rules, "integerMatch");
}

#[test]
fn operational_attributes_are_returned_only_when_requested() {
    let entry = DirectoryEntry::with_operational_attrs(
        "cn=Alice,ou=people,dc=example,dc=org",
        HashMap::from([
            ("cn".to_string(), vec!["Alice".to_string()]),
            ("sn".to_string(), vec!["Example".to_string()]),
        ]),
        OperationalAttributes {
            entry_csn: Some(Csn::with_values(1696680896789012, 1, 1, 0)),
            entry_uuid: Some("f92f4cb2-e821-44a4-bb13-b8ebadf4ecc5".to_string()),
            create_timestamp: Some("20260418120000Z".to_string()),
            modify_timestamp: Some("20260418123000Z".to_string()),
            creators_name: Some("cn=admin,dc=example,dc=org".to_string()),
            modifiers_name: Some("cn=manager,dc=example,dc=org".to_string()),
            last_successful_login: None,
            last_failed_login: None,
            failed_login_count: None,
        },
    );

    let default_projection = DirectoryAttributeProjection::new(&[]);
    let default_attrs = attrs_to_map(default_projection.project_entry(&entry));
    assert!(default_attrs.contains_key("cn"));
    assert!(!default_attrs.contains_key("entryDN"));
    assert!(!default_attrs.contains_key("entrycsn"));
    assert!(!default_attrs.contains_key("modifytimestamp"));

    let all_operational_projection = DirectoryAttributeProjection::new(&["+".to_string()]);
    let all_operational_attrs = attrs_to_map(all_operational_projection.project_entry(&entry));
    assert!(!all_operational_attrs.contains_key("cn"));
    assert_eq!(
        all_operational_attrs.get("entryDN").unwrap(),
        &vec!["cn=Alice,ou=people,dc=example,dc=org".to_string()]
    );
    assert_eq!(
        all_operational_attrs.get("entrycsn").unwrap(),
        &vec!["1696680896789012#001#000001#000000".to_string()]
    );
    assert_eq!(
        all_operational_attrs.get("createtimestamp").unwrap(),
        &vec!["20260418120000Z".to_string()]
    );

    let mixed_projection =
        DirectoryAttributeProjection::new(&["cn".to_string(), "modifyTimestamp".to_string()]);
    let mixed_attrs = attrs_to_map(mixed_projection.project_entry(&entry));
    assert_eq!(mixed_attrs.get("cn"), Some(&vec!["Alice".to_string()]));
    assert_eq!(
        mixed_attrs.get("modifytimestamp"),
        Some(&vec!["20260418123000Z".to_string()])
    );
    assert!(!mixed_attrs.contains_key("entrycsn"));
}

#[test]
fn schema_enforces_structural_required_single_value_and_syntax_rules() {
    let schema = LdapSchema::with_core_schema();

    let missing_required = HashMap::from([
        (
            "objectClass".to_string(),
            vec!["top".to_string(), "person".to_string()],
        ),
        ("cn".to_string(), vec!["Alice".to_string()]),
    ]);
    assert!(matches!(
        schema.validate_entry(&missing_required),
        Err(SchemaError::MissingRequiredAttribute(attribute)) if attribute == "sn"
    ));

    let multiple_structural = HashMap::from([
        (
            "objectClass".to_string(),
            vec![
                "top".to_string(),
                "person".to_string(),
                "organization".to_string(),
            ],
        ),
        ("cn".to_string(), vec!["Alice".to_string()]),
        ("sn".to_string(), vec!["Example".to_string()]),
        ("o".to_string(), vec!["Example Org".to_string()]),
    ]);
    assert!(matches!(
        schema.validate_entry(&multiple_structural),
        Err(SchemaError::MultipleStructuralClasses)
    ));

    let mut posix_schema = LdapSchema::with_core_schema();
    posix_schema.load_builtin_schema("posix").unwrap();

    let invalid_integer_syntax = valid_posix_account_with(vec!["not-a-number".to_string()]);
    assert!(matches!(
        posix_schema.validate_entry(&invalid_integer_syntax),
        Err(SchemaError::InvalidSyntax(attribute, _)) if attribute == "uidNumber"
    ));

    let duplicate_single_value =
        valid_posix_account_with(vec!["1001".to_string(), "1002".to_string()]);
    assert!(matches!(
        posix_schema.validate_entry(&duplicate_single_value),
        Err(SchemaError::SingleValueViolation(attribute)) if attribute == "uidNumber"
    ));
}

#[test]
fn schema_enforces_name_forms_and_structure_rules_for_add_and_modifydn_candidates() {
    let mut schema = LdapSchema::with_core_schema();
    schema
        .load_ldif_str(
            "
dn: cn=schema
objectClasses: ( 1.3.6.1.4.1.55555.4512.40 NAME 'rfc4512IntegrationDepartment' SUP organizationalUnit STRUCTURAL )
objectClasses: ( 1.3.6.1.4.1.55555.4512.41 NAME 'rfc4512IntegrationPerson' SUP person STRUCTURAL )
nameForms: ( 1.3.6.1.4.1.55555.4512.42 NAME 'rfc4512IntegrationDepartmentForm' OC rfc4512IntegrationDepartment MUST ou )
nameForms: ( 1.3.6.1.4.1.55555.4512.43 NAME 'rfc4512IntegrationPersonForm' OC rfc4512IntegrationPerson MUST cn )
dITStructureRules: ( 451240 NAME 'rfc4512IntegrationDepartmentRule' FORM rfc4512IntegrationDepartmentForm )
dITStructureRules: ( 451241 NAME 'rfc4512IntegrationPersonRule' FORM rfc4512IntegrationPersonForm SUP 451240 )
",
        )
        .unwrap();

    let parent = HashMap::from([
        (
            "objectClass".to_string(),
            vec![
                "top".to_string(),
                "organizationalUnit".to_string(),
                "rfc4512IntegrationDepartment".to_string(),
            ],
        ),
        ("ou".to_string(), vec!["Engineering".to_string()]),
    ]);
    let child = HashMap::from([
        (
            "objectClass".to_string(),
            vec![
                "top".to_string(),
                "person".to_string(),
                "rfc4512IntegrationPerson".to_string(),
            ],
        ),
        ("cn".to_string(), vec!["Alice Example".to_string()]),
        ("sn".to_string(), vec!["Example".to_string()]),
    ]);

    assert!(
        schema
            .validate_entry_at_dn(
                "cn=Alice Example,ou=Engineering,dc=example,dc=org",
                &child,
                Some(&parent),
            )
            .is_ok(),
        "Add-style validation should accept an entry named by a valid name form under the permitted structure rule parent"
    );
    assert!(matches!(
        schema.validate_entry_at_dn(
            "uid=alice,ou=Engineering,dc=example,dc=org",
            &child,
            Some(&parent),
        ),
        Err(SchemaError::NamingViolation(_))
    ));
    assert!(
        schema
            .validate_renamed_entry(
                "cn=Alice Example,ou=Engineering,dc=example,dc=org",
                &child,
                "cn=Alice Renamed",
                true,
                Some(&parent),
            )
            .is_ok(),
        "ModifyDN validation should evaluate the candidate entry after adding the new RDN value"
    );
}

fn valid_posix_account_with(uid_number_values: Vec<String>) -> HashMap<String, Vec<String>> {
    HashMap::from([
        (
            "objectClass".to_string(),
            vec![
                "top".to_string(),
                "person".to_string(),
                "posixAccount".to_string(),
            ],
        ),
        ("cn".to_string(), vec!["Alice Example".to_string()]),
        ("sn".to_string(), vec!["Example".to_string()]),
        ("uid".to_string(), vec!["alice".to_string()]),
        ("uidNumber".to_string(), uid_number_values),
        ("gidNumber".to_string(), vec!["1000".to_string()]),
        ("homeDirectory".to_string(), vec!["/home/alice".to_string()]),
    ])
}

fn attrs_to_map(attributes: Vec<(String, Vec<String>)>) -> HashMap<String, Vec<String>> {
    attributes.into_iter().collect()
}

fn assert_contains_schema_description(values: &[String], needle: &str) {
    assert!(
        values.iter().any(|value| value.contains(needle)),
        "expected schema descriptions to contain `{needle}` in {values:#?}"
    );
}

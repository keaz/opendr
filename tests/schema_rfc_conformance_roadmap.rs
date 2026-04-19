use std::collections::HashMap;

use opendr::schema::{LdapSchema, MatchingRuleError, SchemaError};

#[test]
fn rfc_4512_dit_content_rule_may_attributes_extend_allowed_attribute_set() {
    let mut schema = LdapSchema::with_core_schema();
    schema
        .load_ldif_str(
            "
dn: cn=schema
attributeTypes: ( 1.3.6.1.4.1.55555.4512.1 NAME 'rfc4512Badge' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
objectClasses: ( 1.3.6.1.4.1.55555.4512.2 NAME 'rfc4512Employee' SUP top STRUCTURAL MUST cn )
dITContentRules: ( 1.3.6.1.4.1.55555.4512.2 NAME 'rfc4512EmployeeContent' MAY rfc4512Badge )
",
        )
        .unwrap();

    let attributes = attrs(&[
        ("objectClass", &["top", "rfc4512Employee"]),
        ("cn", &["Alice Example"]),
        ("rfc4512Badge", &["A-100"]),
    ]);

    assert!(
        schema.validate_entry(&attributes).is_ok(),
        "RFC 4512 dITContentRules MAY attributes must be accepted even when the structural object class does not list them"
    );
}

#[test]
fn rfc_4512_advanced_schema_elements_reject_missing_dependencies() {
    expect_missing_dependency(
        "
dn: cn=schema
matchingRuleUse: ( 1.3.6.1.4.1.55555.4512.10 NAME 'missingAppliesUse' APPLIES missingAttribute )
",
    );
    expect_missing_dependency(
        "
dn: cn=schema
dITContentRules: ( 2.5.6.6 NAME 'missingAuxRule' AUX missingAuxiliary )
",
    );
    expect_missing_dependency(
        "
dn: cn=schema
nameForms: ( 1.3.6.1.4.1.55555.4512.11 NAME 'missingObjectClassForm' OC missingObjectClass MUST cn )
",
    );
    expect_missing_dependency(
        "
dn: cn=schema
dITStructureRules: ( 5554512 NAME 'missingNameFormStructureRule' FORM missingNameForm )
",
    );
}

#[test]
fn rfc_4512_name_forms_require_all_must_rdn_attributes_and_entry_values() {
    let mut schema = LdapSchema::with_core_schema();
    schema
        .load_ldif_str(
            "
dn: cn=schema
objectClasses: ( 1.3.6.1.4.1.55555.4512.20 NAME 'rfc4512NamedPerson' SUP person STRUCTURAL )
nameForms: ( 1.3.6.1.4.1.55555.4512.21 NAME 'rfc4512NamedPersonForm' OC rfc4512NamedPerson MUST ( cn $ sn ) )
",
        )
        .unwrap();

    let attributes = attrs(&[
        ("objectClass", &["top", "person", "rfc4512NamedPerson"]),
        ("cn", &["Alice Example"]),
        ("sn", &["Example"]),
    ]);

    assert!(matches!(
        schema.validate_rdn_for_entry(&attributes, "cn=Alice Example"),
        Err(SchemaError::NamingViolation(_))
    ));
    assert!(
        schema
            .validate_rdn_for_entry(&attributes, "cn=Alice Example+sn=Example")
            .is_ok()
    );
    assert!(matches!(
        schema.validate_rdn_for_entry(&attributes, "cn=Wrong+sn=Example"),
        Err(SchemaError::NamingViolation(_))
    ));
}

#[test]
fn rfc_4512_dit_structure_rules_enforce_parent_structure_rules() {
    let mut schema = LdapSchema::with_core_schema();
    schema
        .load_ldif_str(
            "
dn: cn=schema
objectClasses: ( 1.3.6.1.4.1.55555.4512.30 NAME 'rfc4512Department' SUP organizationalUnit STRUCTURAL )
objectClasses: ( 1.3.6.1.4.1.55555.4512.31 NAME 'rfc4512DepartmentPerson' SUP person STRUCTURAL )
nameForms: ( 1.3.6.1.4.1.55555.4512.32 NAME 'rfc4512DepartmentForm' OC rfc4512Department MUST ou )
nameForms: ( 1.3.6.1.4.1.55555.4512.33 NAME 'rfc4512DepartmentPersonForm' OC rfc4512DepartmentPerson MUST cn )
dITStructureRules: ( 451230 NAME 'rfc4512DepartmentRule' FORM rfc4512DepartmentForm )
dITStructureRules: ( 451231 NAME 'rfc4512DepartmentPersonRule' FORM rfc4512DepartmentPersonForm SUP 451230 )
",
        )
        .unwrap();

    let parent = attrs(&[
        (
            "objectClass",
            &["top", "organizationalUnit", "rfc4512Department"],
        ),
        ("ou", &["Engineering"]),
    ]);
    let child = attrs(&[
        ("objectClass", &["top", "person", "rfc4512DepartmentPerson"]),
        ("cn", &["Alice Example"]),
        ("sn", &["Example"]),
    ]);
    let wrong_parent = attrs(&[
        ("objectClass", &["top", "person"]),
        ("cn", &["Bob Example"]),
        ("sn", &["Example"]),
    ]);

    assert!(
        schema
            .validate_dit_structure_for_entry(&child, Some(&parent))
            .is_ok()
    );
    assert!(matches!(
        schema.validate_dit_structure_for_entry(&child, Some(&wrong_parent)),
        Err(SchemaError::StructureRuleViolation(_))
    ));
    assert!(matches!(
        schema.validate_dit_structure_for_entry(&child, None),
        Err(SchemaError::StructureRuleViolation(_))
    ));
}

#[test]
fn rfc_4517_complete_standard_syntax_and_matching_rule_registry_is_available() {
    let schema = LdapSchema::with_core_schema();
    let syntax_descriptions = schema.ldap_syntax_descriptions_unique_sorted();
    let matching_rule_descriptions = schema.matching_rule_descriptions_unique_sorted();

    for oid in [
        "1.3.6.1.4.1.1466.115.121.1.3",
        "1.3.6.1.4.1.1466.115.121.1.5",
        "1.3.6.1.4.1.1466.115.121.1.6",
        "1.3.6.1.4.1.1466.115.121.1.8",
        "1.3.6.1.4.1.1466.115.121.1.11",
        "1.3.6.1.4.1.1466.115.121.1.14",
        "1.3.6.1.4.1.1466.115.121.1.16",
        "1.3.6.1.4.1.1466.115.121.1.17",
        "1.3.6.1.4.1.1466.115.121.1.21",
        "1.3.6.1.4.1.1466.115.121.1.22",
        "1.3.6.1.4.1.1466.115.121.1.23",
        "1.3.6.1.4.1.1466.115.121.1.25",
        "1.3.6.1.4.1.1466.115.121.1.30",
        "1.3.6.1.4.1.1466.115.121.1.31",
        "1.3.6.1.4.1.1466.115.121.1.34",
        "1.3.6.1.4.1.1466.115.121.1.35",
        "1.3.6.1.4.1.1466.115.121.1.36",
        "1.3.6.1.4.1.1466.115.121.1.37",
        "1.3.6.1.4.1.1466.115.121.1.39",
        "1.3.6.1.4.1.1466.115.121.1.44",
        "1.3.6.1.4.1.1466.115.121.1.51",
        "1.3.6.1.4.1.1466.115.121.1.52",
        "1.3.6.1.4.1.1466.115.121.1.53",
        "1.3.6.1.4.1.1466.115.121.1.54",
        "1.3.6.1.4.1.1466.115.121.1.58",
    ] {
        assert_schema_description_contains_oid(&syntax_descriptions, oid);
    }

    for oid in [
        "2.5.13.3",
        "2.5.13.6",
        "2.5.13.8",
        "2.5.13.9",
        "2.5.13.10",
        "2.5.13.11",
        "2.5.13.12",
        "2.5.13.16",
        "2.5.13.23",
        "2.5.13.29",
        "2.5.13.30",
        "2.5.13.31",
        "2.5.13.32",
        "2.5.13.33",
    ] {
        assert_schema_description_contains_oid(&matching_rule_descriptions, oid);
    }
}

#[test]
fn rfc_4518_stringprep_maps_to_nothing_and_applies_unicode_compatibility_normalization() {
    let schema = LdapSchema::with_core_schema();
    let case_ignore = schema.resolve_matching_rule("caseIgnoreMatch").unwrap();

    assert_eq!(
        case_ignore.normalize_value("foo\u{00AD}bar").unwrap(),
        "foobar",
        "RFC 4518 maps commonly-mapped-to-nothing code points such as SOFT HYPHEN"
    );
    assert!(
        case_ignore.values_equal("\u{2168}", "ix").unwrap(),
        "RFC 4518 applies Unicode compatibility normalization before case folding"
    );
    assert!(matches!(
        case_ignore.normalize_value("\u{E000}"),
        Err(MatchingRuleError::InvalidSyntax { .. }),
    ));
}

#[test]
fn rfc_4519_full_user_application_schema_is_available_and_strict_when_requested() {
    let schema = LdapSchema::with_core_schema();

    for attribute in [
        "businessCategory",
        "c",
        "cn",
        "dc",
        "description",
        "destinationIndicator",
        "distinguishedName",
        "dnQualifier",
        "enhancedSearchGuide",
        "facsimileTelephoneNumber",
        "generationQualifier",
        "givenName",
        "houseIdentifier",
        "initials",
        "internationalISDNNumber",
        "l",
        "member",
        "name",
        "o",
        "ou",
        "owner",
        "physicalDeliveryOfficeName",
        "postalAddress",
        "postalCode",
        "postOfficeBox",
        "preferredDeliveryMethod",
        "registeredAddress",
        "roleOccupant",
        "searchGuide",
        "seeAlso",
        "serialNumber",
        "sn",
        "st",
        "street",
        "telephoneNumber",
        "teletexTerminalIdentifier",
        "telexNumber",
        "title",
        "uid",
        "uniqueMember",
        "userPassword",
        "x121Address",
        "x500UniqueIdentifier",
    ] {
        assert!(
            schema.get_attribute_type(attribute).is_some(),
            "RFC 4519 attribute {attribute} should be defined"
        );
    }

    for object_class in [
        "applicationProcess",
        "country",
        "dcObject",
        "device",
        "groupOfNames",
        "groupOfUniqueNames",
        "locality",
        "organization",
        "organizationalPerson",
        "organizationalRole",
        "organizationalUnit",
        "person",
        "residentialPerson",
        "uidObject",
    ] {
        assert!(
            schema.get_object_class(object_class).is_some(),
            "RFC 4519 object class {object_class} should be defined"
        );
    }

    let empty_group = attrs(&[
        ("objectClass", &["top", "groupOfNames"]),
        ("cn", &["empty"]),
    ]);
    assert!(matches!(
        schema.validate_entry(&empty_group),
        Err(SchemaError::MissingRequiredAttribute(attribute)) if attribute == "member"
    ));
}

#[test]
fn rfc_2798_full_inet_org_person_attribute_set_is_available() {
    let schema = LdapSchema::with_core_schema();
    let inet_org_person = schema.get_object_class("inetOrgPerson").unwrap();

    for attribute in [
        "audio",
        "businessCategory",
        "carLicense",
        "departmentNumber",
        "displayName",
        "employeeNumber",
        "employeeType",
        "givenName",
        "homePhone",
        "homePostalAddress",
        "initials",
        "jpegPhoto",
        "labeledURI",
        "mail",
        "manager",
        "mobile",
        "o",
        "pager",
        "photo",
        "preferredLanguage",
        "roomNumber",
        "secretary",
        "uid",
        "userCertificate",
        "x500UniqueIdentifier",
        "userSMIMECertificate",
        "userPKCS12",
    ] {
        assert!(
            schema.get_attribute_type(attribute).is_some(),
            "RFC 2798 attribute {attribute} should be defined"
        );
        assert!(
            inet_org_person
                .may
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(attribute)),
            "inetOrgPerson should MAY {attribute}"
        );
    }
}

#[test]
fn rfc_2307_full_posix_nis_schema_bundle_is_available() {
    let mut schema = LdapSchema::with_core_schema();
    schema.load_builtin_schema("posix").unwrap();

    for attribute in [
        "uidNumber",
        "gidNumber",
        "gecos",
        "homeDirectory",
        "loginShell",
        "shadowLastChange",
        "shadowMin",
        "shadowMax",
        "shadowWarning",
        "shadowInactive",
        "shadowExpire",
        "shadowFlag",
        "memberUid",
        "memberNisNetgroup",
        "nisNetgroupTriple",
        "ipServicePort",
        "ipServiceProtocol",
        "ipProtocolNumber",
        "oncRpcNumber",
        "ipHostNumber",
        "ipNetworkNumber",
        "ipNetmaskNumber",
        "macAddress",
        "bootParameter",
        "bootFile",
        "nisMapName",
        "nisMapEntry",
    ] {
        assert!(
            schema.get_attribute_type(attribute).is_some(),
            "RFC 2307 attribute {attribute} should be available in the posix bundle"
        );
    }

    for object_class in [
        "posixAccount",
        "shadowAccount",
        "posixGroup",
        "ipHost",
        "ipNetwork",
        "ipProtocol",
        "ipService",
        "oncRpc",
        "nisNetgroup",
        "nisMap",
        "nisObject",
        "ieee802Device",
        "bootableDevice",
    ] {
        assert!(
            schema.get_object_class(object_class).is_some(),
            "RFC 2307 object class {object_class} should be available in the posix bundle"
        );
    }
}

#[test]
#[ignore = "RFC 3671 collective attributes are not implemented yet"]
fn rfc_3671_collective_attribute_schema_and_runtime_projection_are_available() {
    let schema = LdapSchema::with_core_schema();

    for attribute in [
        "collectiveAttributeSubentries",
        "collectiveExclusions",
        "c-l",
        "c-st",
        "c-street",
        "c-o",
        "c-ou",
        "c-PostalAddress",
        "c-PostalCode",
        "c-PostOfficeBox",
        "c-PhysicalDeliveryOfficeName",
        "c-TelephoneNumber",
        "c-TelexNumber",
        "c-FacsimileTelephoneNumber",
        "c-InternationalISDNNumber",
    ] {
        assert!(
            schema.get_attribute_type(attribute).is_some(),
            "RFC 3671 attribute {attribute} should be defined"
        );
    }
    assert!(
        schema
            .get_object_class("collectiveAttributeSubentry")
            .is_some()
    );
}

#[test]
fn rfc_3672_subentry_schema_control_and_subtree_specification_are_available() {
    let schema = LdapSchema::with_core_schema();

    assert!(schema.get_attribute_type("administrativeRole").is_some());
    assert!(schema.get_attribute_type("subtreeSpecification").is_some());
    assert!(schema.get_object_class("subentry").is_some());
    assert_schema_description_contains_oid(
        &schema.ldap_syntax_descriptions_unique_sorted(),
        "1.3.6.1.4.1.1466.115.121.1.45",
    );
}

#[test]
fn rfc_4523_x509_certificate_schema_is_available() {
    let mut schema = LdapSchema::with_core_schema();
    schema.load_builtin_schema("x509").unwrap();

    for attribute in [
        "userCertificate",
        "cACertificate",
        "authorityRevocationList",
        "certificateRevocationList",
        "crossCertificatePair",
        "supportedAlgorithms",
        "deltaRevocationList",
    ] {
        assert!(
            schema.get_attribute_type(attribute).is_some(),
            "RFC 4523 attribute {attribute} should be defined"
        );
    }

    for object_class in [
        "pkiUser",
        "pkiCA",
        "strongAuthenticationUser",
        "userSecurityInformation",
        "certificationAuthority",
        "certificationAuthority-V2",
        "cRLDistributionPoint",
        "deltaCRL",
    ] {
        assert!(
            schema.get_object_class(object_class).is_some(),
            "RFC 4523 object class {object_class} should be defined"
        );
    }
}

#[test]
fn rfc_4524_cosine_schema_is_available() {
    let mut schema = LdapSchema::with_core_schema();
    schema.load_builtin_schema("cosine").unwrap();

    for attribute in [
        "associatedDomain",
        "associatedName",
        "buildingName",
        "co",
        "documentIdentifier",
        "documentTitle",
        "documentVersion",
        "documentAuthor",
        "documentLocation",
        "documentPublisher",
        "drink",
        "friendlyCountryName",
        "host",
        "info",
        "mail",
        "manager",
        "mobile",
        "organizationalStatus",
        "pager",
        "personalTitle",
        "roomNumber",
        "secretary",
        "uniqueIdentifier",
        "userClass",
    ] {
        assert!(
            schema.get_attribute_type(attribute).is_some(),
            "RFC 4524 attribute {attribute} should be defined"
        );
    }

    for object_class in [
        "account",
        "document",
        "documentSeries",
        "domain",
        "domainRelatedObject",
        "friendlyCountry",
        "rFC822LocalPart",
        "room",
        "simpleSecurityObject",
    ] {
        assert!(
            schema.get_object_class(object_class).is_some(),
            "RFC 4524 object class {object_class} should be defined"
        );
    }
}

fn attrs(pairs: &[(&str, &[&str])]) -> HashMap<String, Vec<String>> {
    pairs
        .iter()
        .map(|(name, values)| {
            (
                (*name).to_string(),
                values.iter().map(|value| (*value).to_string()).collect(),
            )
        })
        .collect()
}

fn expect_missing_dependency(ldif: &str) {
    let mut schema = LdapSchema::with_core_schema();
    assert!(matches!(
        schema.load_ldif_str(ldif),
        Err(SchemaError::MissingDependency(_))
    ));
}

fn assert_schema_description_contains_oid(descriptions: &[String], oid: &str) {
    assert!(
        descriptions
            .iter()
            .any(|description| description.contains(&format!("( {oid} "))),
        "expected schema descriptions to contain OID {oid}: {descriptions:#?}"
    );
}

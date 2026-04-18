use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use opendr::schema::{LdapSchema, MatchingRuleError, SchemaError};

const SUPPORTED_SYNTAX_OIDS: &[&str] = &[
    "1.3.6.1.4.1.1466.115.121.1.7",
    "1.3.6.1.4.1.1466.115.121.1.12",
    "1.3.6.1.4.1.1466.115.121.1.15",
    "1.3.6.1.4.1.1466.115.121.1.24",
    "1.3.6.1.4.1.1466.115.121.1.26",
    "1.3.6.1.4.1.1466.115.121.1.27",
    "1.3.6.1.4.1.1466.115.121.1.28",
    "1.3.6.1.4.1.1466.115.121.1.38",
    "1.3.6.1.4.1.1466.115.121.1.40",
    "1.3.6.1.4.1.1466.115.121.1.41",
    "1.3.6.1.4.1.1466.115.121.1.50",
];

const SUPPORTED_MATCHING_RULES: &[(&str, &str)] = &[
    ("2.5.13.0", "objectIdentifierMatch"),
    ("2.5.13.1", "distinguishedNameMatch"),
    ("2.5.13.2", "caseIgnoreMatch"),
    ("2.5.13.4", "caseIgnoreSubstringsMatch"),
    ("2.5.13.5", "caseExactMatch"),
    ("2.5.13.7", "caseExactSubstringsMatch"),
    ("2.5.13.13", "booleanMatch"),
    ("2.5.13.14", "integerMatch"),
    ("2.5.13.15", "integerOrderingMatch"),
    ("2.5.13.17", "octetStringMatch"),
    ("2.5.13.20", "telephoneNumberMatch"),
    ("2.5.13.21", "telephoneNumberSubstringsMatch"),
    ("2.5.13.27", "generalizedTimeMatch"),
    ("2.5.13.28", "generalizedTimeOrderingMatch"),
    ("1.3.6.1.4.1.1466.109.114.1", "caseExactIA5Match"),
    ("1.3.6.1.4.1.1466.109.114.2", "caseIgnoreIA5Match"),
    ("1.3.6.1.4.1.1466.109.114.3", "caseIgnoreIA5SubstringsMatch"),
];

#[test]
fn advertised_ldap_syntaxes_have_public_validation_coverage() {
    let schema = syntax_test_schema();
    let advertised_oids = schema
        .ldap_syntax_descriptions_unique_sorted()
        .iter()
        .map(|description| schema_description_oid(description))
        .collect::<HashSet<_>>();
    assert_eq!(advertised_oids, string_set(SUPPORTED_SYNTAX_OIDS));

    for case in syntax_cases() {
        assert!(
            schema
                .validate_entry(&syntax_entry(case.attribute, case.valid))
                .is_ok(),
            "{} should accept valid value {:?}",
            case.attribute,
            case.valid
        );

        if let Some(invalid) = case.invalid {
            assert!(matches!(
                schema.validate_entry(&syntax_entry(case.attribute, invalid)),
                Err(SchemaError::InvalidSyntax(attribute, _)) if attribute == case.attribute
            ));
        }
    }
}

#[test]
fn advertised_matching_rules_have_public_normalization_and_comparison_coverage() {
    let schema = LdapSchema::with_core_schema();
    let advertised_oids = schema
        .matching_rule_descriptions_unique_sorted()
        .iter()
        .map(|description| schema_description_oid(description))
        .collect::<HashSet<_>>();
    let expected_oids = SUPPORTED_MATCHING_RULES
        .iter()
        .map(|(oid, _)| *oid)
        .collect::<Vec<_>>();
    assert_eq!(advertised_oids, string_set(&expected_oids));

    for (oid, name) in SUPPORTED_MATCHING_RULES {
        let rule = schema.resolve_matching_rule(name).unwrap();
        assert_eq!(&rule.oid, oid);
        assert!(rule.is_supported(), "{name} should be executable");
        assert_eq!(schema.resolve_matching_rule(oid).unwrap(), rule);
    }

    assert_eq!(
        schema
            .resolve_matching_rule("objectIdentifierMatch")
            .unwrap()
            .normalize_value("CN")
            .unwrap(),
        "cn"
    );
    assert!(
        schema
            .resolve_matching_rule("distinguishedNameMatch")
            .unwrap()
            .values_equal(
                " CN=Alice , OU=People, DC=Example ",
                "cn=alice,ou=people,dc=example"
            )
            .unwrap()
    );
    assert!(
        schema
            .resolve_matching_rule("caseIgnoreMatch")
            .unwrap()
            .values_equal("  Straße   Smith ", "strasse smith")
            .unwrap()
    );
    assert_eq!(
        schema
            .resolve_matching_rule("caseIgnoreSubstringsMatch")
            .unwrap()
            .normalize_substring_fragment("  ALICE   SMITH ")
            .unwrap(),
        "alice smith"
    );
    assert_eq!(
        schema
            .resolve_matching_rule("caseExactMatch")
            .unwrap()
            .normalize_value("  Alice   Smith ")
            .unwrap(),
        "Alice Smith"
    );
    assert_eq!(
        schema
            .resolve_matching_rule("caseExactSubstringsMatch")
            .unwrap()
            .normalize_substring_fragment("  Alice   Smith ")
            .unwrap(),
        "Alice Smith"
    );
    assert_eq!(
        schema
            .resolve_matching_rule("booleanMatch")
            .unwrap()
            .normalize_value("TRUE")
            .unwrap(),
        "TRUE"
    );
    assert!(matches!(
        schema
            .resolve_matching_rule("booleanMatch")
            .unwrap()
            .normalize_value("true"),
        Err(MatchingRuleError::InvalidSyntax { .. })
    ));
    assert!(
        schema
            .resolve_matching_rule("integerMatch")
            .unwrap()
            .values_equal("42", "42")
            .unwrap()
    );
    assert!(matches!(
        schema
            .resolve_matching_rule("integerMatch")
            .unwrap()
            .normalize_value("00042"),
        Err(MatchingRuleError::InvalidSyntax { .. })
    ));
    assert!(
        !schema
            .resolve_matching_rule("octetStringMatch")
            .unwrap()
            .values_equal("Secret", "secret")
            .unwrap()
    );
    assert!(
        schema
            .resolve_matching_rule("telephoneNumberMatch")
            .unwrap()
            .values_equal("+1 555-0100", "+1-5550100")
            .unwrap()
    );
    assert_eq!(
        schema
            .resolve_matching_rule("telephoneNumberSubstringsMatch")
            .unwrap()
            .normalize_substring_fragment("+1 555-0100")
            .unwrap(),
        "+15550100"
    );
    assert!(
        schema
            .resolve_matching_rule("generalizedTimeMatch")
            .unwrap()
            .values_equal("20260102030405+0530", "20260101213405Z")
            .unwrap()
    );
    assert!(
        !schema
            .resolve_matching_rule("caseExactIA5Match")
            .unwrap()
            .values_equal("User@Example.ORG", "user@example.org")
            .unwrap()
    );
    assert!(
        schema
            .resolve_matching_rule("caseIgnoreIA5Match")
            .unwrap()
            .values_equal(" USER@EXAMPLE.ORG ", "user@example.org")
            .unwrap()
    );
    assert_eq!(
        schema
            .resolve_matching_rule("caseIgnoreIA5SubstringsMatch")
            .unwrap()
            .normalize_substring_fragment(" USER@EXAMPLE.ORG ")
            .unwrap(),
        "user@example.org"
    );
}

#[test]
fn rfc_4518_string_preparation_maps_whitespace_casefolds_and_rejects_prohibited_codepoints() {
    let schema = LdapSchema::with_core_schema();
    let case_ignore = schema.resolve_matching_rule("caseIgnoreMatch").unwrap();

    assert_eq!(
        case_ignore
            .normalize_value("  Straße\u{00A0}\u{03C2} ")
            .unwrap(),
        "strasse σ"
    );
    assert!(matches!(
        case_ignore.normalize_value("Alice\u{0007}"),
        Err(MatchingRuleError::InvalidSyntax { .. })
    ));

    let ia5 = schema.resolve_matching_rule("caseIgnoreIA5Match").unwrap();
    assert!(matches!(
        ia5.normalize_value("josé@example.org"),
        Err(MatchingRuleError::InvalidSyntax { .. })
    ));
}

#[test]
fn ordering_rules_generate_stable_numeric_and_time_keys() {
    let schema = LdapSchema::with_core_schema();
    let integer_rule = schema
        .resolve_matching_rule("integerOrderingMatch")
        .unwrap();
    let time_rule = schema
        .resolve_matching_rule("generalizedTimeOrderingMatch")
        .unwrap();

    assert!(integer_rule.ordering_key("-1").unwrap() < integer_rule.ordering_key("2").unwrap());
    assert_eq!(
        integer_rule.compare_values("10", "2").unwrap(),
        Ordering::Greater
    );
    assert_eq!(
        time_rule.ordering_key("20260102030405Z").unwrap(),
        "20260102030405.000000000Z"
    );
    assert_eq!(
        time_rule.normalize_value("20260102030405+0530").unwrap(),
        "20260101213405Z"
    );
    assert_eq!(
        time_rule
            .compare_values("20250101000000Z", "20260101000000Z")
            .unwrap(),
        Ordering::Less
    );
}

#[test]
fn unsupported_syntaxes_and_matching_rules_are_rejected_explicitly() {
    let mut schema = syntax_test_schema();
    schema
        .load_ldif_str(
            "
dn: cn=schema
ldapSyntaxes: ( 1.3.6.1.4.1.55555.87.1 DESC 'Unsupported test syntax' )
attributeTypes: ( 1.3.6.1.4.1.55555.87.2 NAME 'testUnsupportedSyntax' SYNTAX 1.3.6.1.4.1.55555.87.1 )
objectClasses: ( 1.3.6.1.4.1.55555.87.3 NAME 'testUnsupportedSyntaxEntry' SUP top STRUCTURAL MUST cn MAY testUnsupportedSyntax )
matchingRules: ( 1.3.6.1.4.1.55555.87.4 NAME 'testUnsupportedMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
",
        )
        .unwrap();

    assert!(matches!(
        schema.validate_entry(&custom_entry(
            "testUnsupportedSyntaxEntry",
            "testUnsupportedSyntax",
            "anything"
        )),
        Err(SchemaError::InvalidSyntax(attribute, reason))
            if attribute == "testUnsupportedSyntax"
                && reason.contains("unsupported LDAP syntax")
    ));

    let unsupported_rule = schema
        .resolve_matching_rule("testUnsupportedMatch")
        .unwrap();
    assert!(matches!(
        unsupported_rule.normalize_value("anything"),
        Err(MatchingRuleError::UnsupportedRule(rule)) if rule == "testUnsupportedMatch"
    ));
}

struct SyntaxCase {
    attribute: &'static str,
    valid: &'static str,
    invalid: Option<&'static str>,
}

fn syntax_cases() -> Vec<SyntaxCase> {
    vec![
        SyntaxCase {
            attribute: "testBoolean",
            valid: "TRUE",
            invalid: Some("true"),
        },
        SyntaxCase {
            attribute: "testDn",
            valid: "cn=Alice,dc=example,dc=org",
            invalid: Some("not a dn"),
        },
        SyntaxCase {
            attribute: "testDirectoryString",
            valid: "Jorg",
            invalid: Some(""),
        },
        SyntaxCase {
            attribute: "testGeneralizedTime",
            valid: "20260102030405Z",
            invalid: Some("20260230030405Z"),
        },
        SyntaxCase {
            attribute: "testIa5",
            valid: "user@example.org",
            invalid: Some("josé@example.org"),
        },
        SyntaxCase {
            attribute: "testInteger",
            valid: "-42",
            invalid: Some("042"),
        },
        SyntaxCase {
            attribute: "testJpeg",
            valid: "jpeg bytes",
            invalid: None,
        },
        SyntaxCase {
            attribute: "testOid",
            valid: "2.5.4.3",
            invalid: Some("2.05"),
        },
        SyntaxCase {
            attribute: "testOctetString",
            valid: "\0",
            invalid: None,
        },
        SyntaxCase {
            attribute: "testPostalAddress",
            valid: "Line 1$Line 2",
            invalid: Some("Line 1$$Line 3"),
        },
        SyntaxCase {
            attribute: "testTelephoneNumber",
            valid: "+1 555-0100",
            invalid: Some("+1_555"),
        },
    ]
}

fn syntax_test_schema() -> LdapSchema {
    let mut schema = LdapSchema::with_core_schema();
    schema
        .load_ldif_str(
            "
dn: cn=schema
attributeTypes: ( 1.3.6.1.4.1.55555.86.1 NAME 'testBoolean' EQUALITY booleanMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.55555.86.2 NAME 'testDn' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.3 NAME 'testDirectoryString' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.4 NAME 'testGeneralizedTime' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.5 NAME 'testIa5' EQUALITY caseIgnoreIA5Match SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.6 NAME 'testInteger' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.7 NAME 'testJpeg' SYNTAX 1.3.6.1.4.1.1466.115.121.1.28 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.8 NAME 'testOid' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.9 NAME 'testOctetString' EQUALITY octetStringMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.10 NAME 'testPostalAddress' SYNTAX 1.3.6.1.4.1.1466.115.121.1.41 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.11 NAME 'testTelephoneNumber' EQUALITY telephoneNumberMatch SUBSTR telephoneNumberSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.50 )
objectClasses: ( 1.3.6.1.4.1.55555.86.12 NAME 'testSyntaxEntry' SUP top STRUCTURAL MUST cn MAY ( testBoolean $ testDn $ testDirectoryString $ testGeneralizedTime $ testIa5 $ testInteger $ testJpeg $ testOid $ testOctetString $ testPostalAddress $ testTelephoneNumber ) )
",
        )
        .unwrap();
    schema
}

fn syntax_entry(attribute: &str, value: &str) -> HashMap<String, Vec<String>> {
    custom_entry("testSyntaxEntry", attribute, value)
}

fn custom_entry(object_class: &str, attribute: &str, value: &str) -> HashMap<String, Vec<String>> {
    HashMap::from([
        (
            "objectClass".to_string(),
            vec!["top".to_string(), object_class.to_string()],
        ),
        ("cn".to_string(), vec!["Syntax Test".to_string()]),
        (attribute.to_string(), vec![value.to_string()]),
    ])
}

fn schema_description_oid(description: &str) -> String {
    description
        .trim()
        .trim_start_matches('(')
        .split_whitespace()
        .next()
        .expect("schema description oid")
        .to_string()
}

fn string_set(values: &[&str]) -> HashSet<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

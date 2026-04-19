use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use opendr::schema::{LdapSchema, MatchingRuleError, SchemaError};

const SUPPORTED_SYNTAX_OIDS: &[&str] = &[
    "1.3.6.1.4.1.1466.115.121.1.3",
    "1.3.6.1.4.1.1466.115.121.1.5",
    "1.3.6.1.4.1.1466.115.121.1.6",
    "1.3.6.1.4.1.1466.115.121.1.7",
    "1.3.6.1.4.1.1466.115.121.1.8",
    "1.3.6.1.4.1.1466.115.121.1.11",
    "1.3.6.1.4.1.1466.115.121.1.12",
    "1.3.6.1.4.1.1466.115.121.1.14",
    "1.3.6.1.4.1.1466.115.121.1.15",
    "1.3.6.1.4.1.1466.115.121.1.16",
    "1.3.6.1.4.1.1466.115.121.1.17",
    "1.3.6.1.4.1.1466.115.121.1.21",
    "1.3.6.1.4.1.1466.115.121.1.22",
    "1.3.6.1.4.1.1466.115.121.1.23",
    "1.3.6.1.4.1.1466.115.121.1.24",
    "1.3.6.1.4.1.1466.115.121.1.25",
    "1.3.6.1.4.1.1466.115.121.1.26",
    "1.3.6.1.4.1.1466.115.121.1.27",
    "1.3.6.1.4.1.1466.115.121.1.28",
    "1.3.6.1.4.1.1466.115.121.1.30",
    "1.3.6.1.4.1.1466.115.121.1.31",
    "1.3.6.1.4.1.1466.115.121.1.34",
    "1.3.6.1.4.1.1466.115.121.1.35",
    "1.3.6.1.4.1.1466.115.121.1.36",
    "1.3.6.1.4.1.1466.115.121.1.37",
    "1.3.6.1.4.1.1466.115.121.1.38",
    "1.3.6.1.4.1.1466.115.121.1.39",
    "1.3.6.1.4.1.1466.115.121.1.40",
    "1.3.6.1.4.1.1466.115.121.1.41",
    "1.3.6.1.4.1.1466.115.121.1.44",
    "1.3.6.1.4.1.1466.115.121.1.45",
    "1.3.6.1.4.1.1466.115.121.1.50",
    "1.3.6.1.4.1.1466.115.121.1.51",
    "1.3.6.1.4.1.1466.115.121.1.52",
    "1.3.6.1.4.1.1466.115.121.1.53",
    "1.3.6.1.4.1.1466.115.121.1.54",
    "1.3.6.1.4.1.1466.115.121.1.58",
];

const SUPPORTED_MATCHING_RULES: &[(&str, &str)] = &[
    ("2.5.13.0", "objectIdentifierMatch"),
    ("2.5.13.1", "distinguishedNameMatch"),
    ("2.5.13.2", "caseIgnoreMatch"),
    ("2.5.13.3", "caseIgnoreOrderingMatch"),
    ("2.5.13.4", "caseIgnoreSubstringsMatch"),
    ("2.5.13.5", "caseExactMatch"),
    ("2.5.13.6", "caseExactOrderingMatch"),
    ("2.5.13.7", "caseExactSubstringsMatch"),
    ("2.5.13.8", "numericStringMatch"),
    ("2.5.13.9", "numericStringOrderingMatch"),
    ("2.5.13.10", "numericStringSubstringsMatch"),
    ("2.5.13.11", "caseIgnoreListMatch"),
    ("2.5.13.12", "caseIgnoreListSubstringsMatch"),
    ("2.5.13.13", "booleanMatch"),
    ("2.5.13.14", "integerMatch"),
    ("2.5.13.15", "integerOrderingMatch"),
    ("2.5.13.16", "bitStringMatch"),
    ("2.5.13.17", "octetStringMatch"),
    ("2.5.13.18", "octetStringOrderingMatch"),
    ("2.5.13.20", "telephoneNumberMatch"),
    ("2.5.13.21", "telephoneNumberSubstringsMatch"),
    ("2.5.13.23", "uniqueMemberMatch"),
    ("2.5.13.27", "generalizedTimeMatch"),
    ("2.5.13.28", "generalizedTimeOrderingMatch"),
    ("2.5.13.29", "integerFirstComponentMatch"),
    ("2.5.13.30", "objectIdentifierFirstComponentMatch"),
    ("2.5.13.31", "directoryStringFirstComponentMatch"),
    ("2.5.13.32", "wordMatch"),
    ("2.5.13.33", "keywordMatch"),
    ("1.3.6.1.4.1.1466.109.114.1", "caseExactIA5Match"),
    ("1.3.6.1.4.1.1466.109.114.2", "caseIgnoreIA5Match"),
    ("1.3.6.1.4.1.1466.109.114.3", "caseIgnoreIA5SubstringsMatch"),
    ("1.3.6.1.4.1.4203.1.2.1", "caseExactIA5SubstringsMatch"),
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

    let rcgen::CertifiedKey { cert, .. } =
        rcgen::generate_simple_self_signed(vec!["alice.example.org".to_string()]).unwrap();
    let certificate_pem = cert.pem();
    assert!(
        schema
            .validate_entry(&syntax_entry("testCertificate", &certificate_pem))
            .is_ok(),
        "Certificate syntax should accept a parseable X.509 certificate"
    );
    assert!(matches!(
        schema.validate_entry(&syntax_entry("testCertificate", "not a certificate")),
        Err(SchemaError::InvalidSyntax(attribute, _)) if attribute == "testCertificate"
    ));
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
            .resolve_matching_rule("caseIgnoreOrderingMatch")
            .unwrap()
            .ordering_key("  Bob   Smith ")
            .unwrap(),
        "bob smith"
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
            .resolve_matching_rule("caseExactOrderingMatch")
            .unwrap()
            .ordering_key("  Alice   Smith ")
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
        schema
            .resolve_matching_rule("numericStringMatch")
            .unwrap()
            .values_equal("123 45", "12345")
            .unwrap()
    );
    assert_eq!(
        schema
            .resolve_matching_rule("numericStringOrderingMatch")
            .unwrap()
            .ordering_key("12 34")
            .unwrap(),
        "1234"
    );
    assert_eq!(
        schema
            .resolve_matching_rule("numericStringSubstringsMatch")
            .unwrap()
            .normalize_substring_fragment("12 3")
            .unwrap(),
        "123"
    );
    assert_eq!(
        schema
            .resolve_matching_rule("caseIgnoreListMatch")
            .unwrap()
            .normalize_value("Line One$Line Two")
            .unwrap(),
        "line one$line two"
    );
    assert!(
        schema
            .resolve_matching_rule("caseIgnoreListSubstringsMatch")
            .unwrap()
            .values_equal("Line One$Line Two", "line one$line two")
            .unwrap()
    );
    assert!(
        schema
            .resolve_matching_rule("bitStringMatch")
            .unwrap()
            .values_equal("'1010'B", "'1010'B")
            .unwrap()
    );
    assert!(
        !schema
            .resolve_matching_rule("octetStringMatch")
            .unwrap()
            .values_equal("Secret", "secret")
            .unwrap()
    );
    assert_eq!(
        schema
            .resolve_matching_rule("octetStringOrderingMatch")
            .unwrap()
            .compare_values("abc", "abd")
            .unwrap(),
        Ordering::Less
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
            .resolve_matching_rule("uniqueMemberMatch")
            .unwrap()
            .values_equal(
                "CN=Alice,OU=People,DC=Example#'1010'B",
                "cn=alice,ou=people,dc=example#'1010'B",
            )
            .unwrap()
    );
    assert!(
        schema
            .resolve_matching_rule("generalizedTimeMatch")
            .unwrap()
            .values_equal("20260102030405+0530", "20260101213405Z")
            .unwrap()
    );
    assert_eq!(
        schema
            .resolve_matching_rule("integerFirstComponentMatch")
            .unwrap()
            .normalize_value("( 42 NAME 'answer' )")
            .unwrap(),
        "42"
    );
    assert_eq!(
        schema
            .resolve_matching_rule("objectIdentifierFirstComponentMatch")
            .unwrap()
            .normalize_value("( 2.5.4.3 NAME 'cn' )")
            .unwrap(),
        "2.5.4.3"
    );
    assert!(
        schema
            .resolve_matching_rule("directoryStringFirstComponentMatch")
            .unwrap()
            .values_equal("Alice Example$ignored", "alice example")
            .unwrap()
    );
    assert!(
        schema
            .resolve_matching_rule("wordMatch")
            .unwrap()
            .values_equal("Alice Smith", "smith")
            .unwrap()
    );
    assert!(
        schema
            .resolve_matching_rule("keywordMatch")
            .unwrap()
            .values_equal("engineering, finance", "finance")
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
    assert_eq!(
        schema
            .resolve_matching_rule("caseExactIA5SubstringsMatch")
            .unwrap()
            .normalize_substring_fragment(" USER@EXAMPLE.ORG ")
            .unwrap(),
        "USER@EXAMPLE.ORG"
    );
    assert!(
        !schema
            .resolve_matching_rule("caseExactIA5SubstringsMatch")
            .unwrap()
            .values_equal("User@Example.ORG", "user@example.org")
            .unwrap()
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
    assert_eq!(
        case_ignore.normalize_value("foo\u{00AD}bar").unwrap(),
        "foobar"
    );
    assert!(case_ignore.values_equal("\u{2168}", "ix").unwrap());
    assert_eq!(
        case_ignore.normalize_value("Alice\u{0007}").unwrap(),
        "alice"
    );
    assert!(matches!(
        case_ignore.normalize_value("\u{E000}"),
        Err(MatchingRuleError::InvalidSyntax { .. })
    ));

    let ia5 = schema.resolve_matching_rule("caseIgnoreIA5Match").unwrap();
    assert!(matches!(
        ia5.normalize_value("josé@example.org"),
        Err(MatchingRuleError::InvalidSyntax { .. })
    ));

    assert_eq!(
        schema
            .resolve_matching_rule("telephoneNumberMatch")
            .unwrap()
            .normalize_value("+1\u{2011}555\u{00A0}0100")
            .unwrap(),
        "+15550100"
    );
    assert_eq!(
        schema
            .resolve_matching_rule("numericStringMatch")
            .unwrap()
            .normalize_value("12\u{00A0}3")
            .unwrap(),
        "123"
    );
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
            attribute: "testAttributeTypeDescription",
            valid: "( 1.3.6.1.4.1.55555.86.101 NAME 'syntaxAttr' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
            invalid: Some("( 2.05 NAME 'bad' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"),
        },
        SyntaxCase {
            attribute: "testBinary",
            valid: "binary bytes",
            invalid: None,
        },
        SyntaxCase {
            attribute: "testBitString",
            valid: "'1010'B",
            invalid: Some("1010"),
        },
        SyntaxCase {
            attribute: "testBoolean",
            valid: "TRUE",
            invalid: Some("true"),
        },
        SyntaxCase {
            attribute: "testCountryString",
            valid: "US",
            invalid: Some("USA"),
        },
        SyntaxCase {
            attribute: "testDeliveryMethod",
            valid: "any$telephone",
            invalid: Some("smtp"),
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
            attribute: "testDitContentRuleDescription",
            valid: "( 2.5.6.6 NAME 'content' MAY cn )",
            invalid: Some("( 2.5.6.6 NAME 'content' MAY cn "),
        },
        SyntaxCase {
            attribute: "testDitStructureRuleDescription",
            valid: "( 86 NAME 'structure' FORM testNameForm )",
            invalid: Some("( abc FORM testNameForm )"),
        },
        SyntaxCase {
            attribute: "testEnhancedGuide",
            valid: "person#(cn$eq&sn$substr)#wholeSubtree",
            invalid: Some("person#cn$bogus#subtree"),
        },
        SyntaxCase {
            attribute: "testFacsimileTelephoneNumber",
            valid: "+1 555-0100$fineResolution",
            invalid: Some("+1_555"),
        },
        SyntaxCase {
            attribute: "testFax",
            valid: "fax bytes",
            invalid: None,
        },
        SyntaxCase {
            attribute: "testGeneralizedTime",
            valid: "20260102030405Z",
            invalid: Some("20260230030405Z"),
        },
        SyntaxCase {
            attribute: "testGuide",
            valid: "person#(cn$eq|sn$substr)",
            invalid: Some("person#cn$bad"),
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
            attribute: "testLdapSyntaxDescription",
            valid: "( 1.3.6.1.4.1.55555.86.102 DESC 'A Syntax' )",
            invalid: Some("( 1.3.6.1.4.1.55555.86.102 UNKNOWN 'x' )"),
        },
        SyntaxCase {
            attribute: "testMatchingRuleDescription",
            valid: "( 1.3.6.1.4.1.55555.86.103 NAME 'syntaxRule' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
            invalid: Some("( 1.3.6.1.4.1.55555.86.103 NAME 'syntaxRule' )"),
        },
        SyntaxCase {
            attribute: "testMatchingRuleUseDescription",
            valid: "( 2.5.13.2 NAME 'syntaxRuleUse' APPLIES cn )",
            invalid: Some("( 2.5.13.2 NAME 'syntaxRuleUse' UNKNOWN cn )"),
        },
        SyntaxCase {
            attribute: "testNameAndOptionalUid",
            valid: "cn=Alice,dc=example,dc=org#'1010'B",
            invalid: Some("cn=Alice,dc=example,dc=org#1010"),
        },
        SyntaxCase {
            attribute: "testNameFormDescription",
            valid: "( 1.3.6.1.4.1.55555.86.104 NAME 'syntaxNameForm' OC person MUST cn )",
            invalid: Some("( 1.3.6.1.4.1.55555.86.104 NAME 'syntaxNameForm' MUST cn )"),
        },
        SyntaxCase {
            attribute: "testNumericString",
            valid: "123 45",
            invalid: Some("123A"),
        },
        SyntaxCase {
            attribute: "testObjectClassDescription",
            valid: "( 1.3.6.1.4.1.55555.86.105 NAME 'syntaxObject' SUP top STRUCTURAL MUST cn )",
            invalid: Some("( 2.05 NAME 'syntaxObject' SUP top STRUCTURAL MUST cn )"),
        },
        SyntaxCase {
            attribute: "testOid",
            valid: "2.5.4.3",
            invalid: Some("2.05"),
        },
        SyntaxCase {
            attribute: "testOtherMailbox",
            valid: "SMTP$user@example.org",
            invalid: Some("SMTP$josé@example.org"),
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
            attribute: "testPrintableString",
            valid: "ABC +42?",
            invalid: Some("café"),
        },
        SyntaxCase {
            attribute: "testSubstringAssertion",
            valid: "Alice*Smith",
            invalid: Some("Alice**Smith"),
        },
        SyntaxCase {
            attribute: "testSubtreeSpecification",
            valid: "{ base \"ou=People\", minimum 1, maximum 3, specificationFilter item:cn }",
            invalid: Some("{ minimum two }"),
        },
        SyntaxCase {
            attribute: "testTeletexTerminalIdentifier",
            valid: "terminal$graphic:abc\\24",
            invalid: Some("terminal$bogus:value"),
        },
        SyntaxCase {
            attribute: "testTelephoneNumber",
            valid: "+1 555-0100",
            invalid: Some("+1_555"),
        },
        SyntaxCase {
            attribute: "testTelexNumber",
            valid: "123$US$ABC",
            invalid: Some("123$US"),
        },
        SyntaxCase {
            attribute: "testUtcTime",
            valid: "260102030405Z",
            invalid: Some("260230030405Z"),
        },
    ]
}

fn syntax_test_schema() -> LdapSchema {
    let mut schema = LdapSchema::with_core_schema();
    schema
        .load_ldif_str(
            "
dn: cn=schema
attributeTypes: ( 1.3.6.1.4.1.55555.86.30 NAME 'testAttributeTypeDescription' SYNTAX 1.3.6.1.4.1.1466.115.121.1.3 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.53 NAME 'testBinary' SYNTAX 1.3.6.1.4.1.1466.115.121.1.5 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.31 NAME 'testBitString' EQUALITY bitStringMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.6 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.1 NAME 'testBoolean' EQUALITY booleanMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.55555.86.54 NAME 'testCertificate' SYNTAX 1.3.6.1.4.1.1466.115.121.1.8 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.32 NAME 'testCountryString' SYNTAX 1.3.6.1.4.1.1466.115.121.1.11 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.2 NAME 'testDn' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.33 NAME 'testDeliveryMethod' SYNTAX 1.3.6.1.4.1.1466.115.121.1.14 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.3 NAME 'testDirectoryString' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.34 NAME 'testDitContentRuleDescription' SYNTAX 1.3.6.1.4.1.1466.115.121.1.16 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.35 NAME 'testDitStructureRuleDescription' SYNTAX 1.3.6.1.4.1.1466.115.121.1.17 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.36 NAME 'testEnhancedGuide' SYNTAX 1.3.6.1.4.1.1466.115.121.1.21 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.37 NAME 'testFacsimileTelephoneNumber' SYNTAX 1.3.6.1.4.1.1466.115.121.1.22 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.38 NAME 'testFax' SYNTAX 1.3.6.1.4.1.1466.115.121.1.23 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.4 NAME 'testGeneralizedTime' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.39 NAME 'testGuide' SYNTAX 1.3.6.1.4.1.1466.115.121.1.25 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.5 NAME 'testIa5' EQUALITY caseIgnoreIA5Match SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.6 NAME 'testInteger' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.7 NAME 'testJpeg' SYNTAX 1.3.6.1.4.1.1466.115.121.1.28 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.40 NAME 'testMatchingRuleDescription' SYNTAX 1.3.6.1.4.1.1466.115.121.1.30 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.41 NAME 'testMatchingRuleUseDescription' SYNTAX 1.3.6.1.4.1.1466.115.121.1.31 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.42 NAME 'testNameAndOptionalUid' EQUALITY uniqueMemberMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.34 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.43 NAME 'testNameFormDescription' SYNTAX 1.3.6.1.4.1.1466.115.121.1.35 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.44 NAME 'testNumericString' EQUALITY numericStringMatch ORDERING numericStringOrderingMatch SUBSTR numericStringSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.36 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.45 NAME 'testObjectClassDescription' SYNTAX 1.3.6.1.4.1.1466.115.121.1.37 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.8 NAME 'testOid' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.46 NAME 'testOtherMailbox' SYNTAX 1.3.6.1.4.1.1466.115.121.1.39 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.9 NAME 'testOctetString' EQUALITY octetStringMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.10 NAME 'testPostalAddress' SYNTAX 1.3.6.1.4.1.1466.115.121.1.41 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.47 NAME 'testPrintableString' SYNTAX 1.3.6.1.4.1.1466.115.121.1.44 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.55 NAME 'testSubtreeSpecification' SYNTAX 1.3.6.1.4.1.1466.115.121.1.45 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.11 NAME 'testTelephoneNumber' EQUALITY telephoneNumberMatch SUBSTR telephoneNumberSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.50 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.48 NAME 'testTeletexTerminalIdentifier' SYNTAX 1.3.6.1.4.1.1466.115.121.1.51 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.49 NAME 'testTelexNumber' SYNTAX 1.3.6.1.4.1.1466.115.121.1.52 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.50 NAME 'testUtcTime' SYNTAX 1.3.6.1.4.1.1466.115.121.1.53 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.51 NAME 'testLdapSyntaxDescription' SYNTAX 1.3.6.1.4.1.1466.115.121.1.54 )
attributeTypes: ( 1.3.6.1.4.1.55555.86.52 NAME 'testSubstringAssertion' SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )
objectClasses: ( 1.3.6.1.4.1.55555.86.12 NAME 'testSyntaxEntry' SUP top STRUCTURAL MUST cn MAY ( testAttributeTypeDescription $ testBinary $ testBitString $ testBoolean $ testCertificate $ testCountryString $ testDeliveryMethod $ testDn $ testDirectoryString $ testDitContentRuleDescription $ testDitStructureRuleDescription $ testEnhancedGuide $ testFacsimileTelephoneNumber $ testFax $ testGeneralizedTime $ testGuide $ testIa5 $ testInteger $ testJpeg $ testMatchingRuleDescription $ testMatchingRuleUseDescription $ testNameAndOptionalUid $ testNameFormDescription $ testNumericString $ testObjectClassDescription $ testOid $ testOtherMailbox $ testOctetString $ testPostalAddress $ testPrintableString $ testSubtreeSpecification $ testTelephoneNumber $ testTeletexTerminalIdentifier $ testTelexNumber $ testUtcTime $ testLdapSyntaxDescription $ testSubstringAssertion ) )
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

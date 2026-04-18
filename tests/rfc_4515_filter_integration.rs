use opendr::schema::LdapSchema;
use opendr::search_adapters::ProductionFilterMatcher;
use opendr::search_fsm::{FilterMatcher, SearchEntry};

#[tokio::test]
async fn supported_rfc_4515_filters_match_with_schema_rules() {
    let mut matcher = ProductionFilterMatcher::with_schema(schema_with_posix());
    let entry = alice_entry("Alice Example");

    for filter in [
        "(cn=Alice Example)",
        "(mail=*)",
        "(cn=Ali*Exam*)",
        "(exampleNumber>=1000)",
        "(exampleNumber<=1001)",
        "(&(objectClass=person)(cn=Alice Example))",
        "(|(cn=Nobody)(uid=alice))",
        "(!(cn=Bob))",
        "(cn:caseIgnoreMatch:=ALICE EXAMPLE)",
    ] {
        assert!(
            matcher.matches_filter(&entry, filter).await.unwrap(),
            "expected RFC 4515 filter `{filter}` to match"
        );
    }
}

#[tokio::test]
async fn escaped_assertion_values_are_decoded_before_matching() {
    let mut matcher = ProductionFilterMatcher::with_schema(schema_with_posix());
    let entry = alice_entry("Alice (Admin)*");

    assert!(
        matcher
            .matches_filter(&entry, "(cn=Alice \\28Admin\\29\\2a)")
            .await
            .unwrap(),
        "escaped parentheses and asterisk should match their literal assertion bytes"
    );
}

#[tokio::test]
async fn invalid_filter_syntax_returns_errors_without_panicking() {
    let mut matcher = ProductionFilterMatcher::with_schema(schema_with_posix());

    for invalid_filter in ["", "(", "(cn=Alice", "(&(cn=Alice)"] {
        let result = matcher.validate_filter(invalid_filter).await;
        assert!(
            result.is_err(),
            "invalid RFC 4515 filter `{invalid_filter}` should be rejected"
        );
    }
}

#[tokio::test]
async fn unsupported_or_inapplicable_matching_is_rejected_predictably() {
    let mut matcher = ProductionFilterMatcher::with_schema(schema_with_posix());

    let approximate = matcher.validate_filter("(cn~=alice)").await.unwrap_err();
    assert!(
        approximate.contains("approximate matching is not supported"),
        "unexpected approximate-match error: {approximate}"
    );

    let unsupported_rule = matcher
        .validate_filter("(cn:1.3.6.1.4.1.55555.4515.1:=Alice)")
        .await
        .unwrap_err();
    assert!(
        unsupported_rule.contains("matching")
            || unsupported_rule.contains("inappropriate")
            || unsupported_rule.contains("not found"),
        "unexpected unsupported matching-rule error: {unsupported_rule}"
    );

    let undefined_attribute = matcher
        .validate_filter("(notDefined=Alice)")
        .await
        .unwrap_err();
    assert!(
        undefined_attribute.contains("undefined attribute type"),
        "unexpected undefined-attribute error: {undefined_attribute}"
    );
}

#[tokio::test]
async fn non_matching_filters_return_false() {
    let mut matcher = ProductionFilterMatcher::with_schema(schema_with_posix());
    let entry = alice_entry("Alice Example");

    for filter in [
        "(cn=Bob)",
        "(&(objectClass=person)(uid=bob))",
        "(exampleNumber>=1002)",
        "(exampleNumber<=999)",
        "(!(uid=alice))",
    ] {
        assert!(
            !matcher.matches_filter(&entry, filter).await.unwrap(),
            "expected RFC 4515 filter `{filter}` not to match"
        );
    }
}

fn schema_with_posix() -> LdapSchema {
    let mut schema = LdapSchema::with_core_schema();
    schema.load_builtin_schema("posix").unwrap();
    schema
        .load_ldif_str(
            "
dn: cn=schema
attributeTypes: ( 1.3.6.1.4.1.55555.4515.1 NAME 'exampleNumber' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
",
        )
        .unwrap();
    schema
}

fn alice_entry(cn: &str) -> SearchEntry {
    let mut entry = SearchEntry::new("uid=alice,ou=people,dc=example,dc=org".to_string());
    entry.set_object_classes(vec![
        "top".to_string(),
        "person".to_string(),
        "posixAccount".to_string(),
    ]);
    entry.add_attribute(
        "objectclass".to_string(),
        vec![
            "top".to_string(),
            "person".to_string(),
            "posixAccount".to_string(),
        ],
    );
    entry.add_attribute("cn".to_string(), vec![cn.to_string()]);
    entry.add_attribute("sn".to_string(), vec!["Example".to_string()]);
    entry.add_attribute("uid".to_string(), vec!["alice".to_string()]);
    entry.add_attribute("mail".to_string(), vec!["alice@example.org".to_string()]);
    entry.add_attribute("uidnumber".to_string(), vec!["1001".to_string()]);
    entry.add_attribute("examplenumber".to_string(), vec!["1001".to_string()]);
    entry.add_attribute("gidnumber".to_string(), vec!["1000".to_string()]);
    entry.add_attribute("homedirectory".to_string(), vec!["/home/alice".to_string()]);
    entry
}

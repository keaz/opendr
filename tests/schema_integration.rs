// Integration tests for schema validation
use base64::{Engine as _, engine::general_purpose};
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

const RSA_ENCRYPTION_ALGORITHM_IDENTIFIER: &[u8] = &[
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
];

fn test_der_wrap(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    output.push(tag);
    if content.len() < 128 {
        output.push(content.len() as u8);
    } else {
        let bytes = content.len().to_be_bytes();
        let first_non_zero = bytes
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(bytes.len() - 1);
        let length_bytes = &bytes[first_non_zero..];
        output.push(0x80 | length_bytes.len() as u8);
        output.extend_from_slice(length_bytes);
    }
    output.extend_from_slice(content);
    output
}

fn supported_algorithm_base64() -> String {
    general_purpose::STANDARD.encode(test_der_wrap(0x30, RSA_ENCRYPTION_ALGORITHM_IDENTIFIER))
}

fn gser_quote(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn der_from_pem(value: &str, label: &str) -> Vec<u8> {
    let (remainder, pem) = x509_parser::pem::parse_x509_pem(value.as_bytes()).unwrap();
    assert!(
        remainder.iter().all(u8::is_ascii_whitespace),
        "{label} PEM should not contain trailing data"
    );
    assert_eq!(pem.label, label);
    pem.contents
}

fn certificate_exact_assertion(cert_der: &[u8]) -> String {
    let (_, certificate) = x509_parser::parse_x509_certificate(cert_der).unwrap();
    format!(
        "{{ serialNumber {}, issuer rdnSequence:{} }}",
        certificate.tbs_certificate.serial,
        gser_quote(&certificate.issuer().to_string())
    )
}

fn certificate_list_exact_assertion(crl_der: &[u8]) -> String {
    let (_, certificate_list) = x509_parser::parse_x509_crl(crl_der).unwrap();
    format!(
        "{{ issuer rdnSequence:{}, thisUpdate generalizedTime:20240101000000Z }}",
        gser_quote(&certificate_list.issuer().to_string())
    )
}

fn certificate_pair_base64(cert_der: &[u8]) -> String {
    let issued_to_this_ca = test_der_wrap(0xa0, cert_der);
    general_purpose::STANDARD.encode(test_der_wrap(0x30, &issued_to_this_ca))
}

fn test_der_oid(arcs: &[u64]) -> Vec<u8> {
    assert!(arcs.len() >= 2);
    let mut content = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for arc in &arcs[2..] {
        let mut value = *arc;
        let mut encoded = vec![(value & 0x7f) as u8];
        value >>= 7;
        while value > 0 {
            encoded.push(((value & 0x7f) as u8) | 0x80);
            value >>= 7;
        }
        content.extend(encoded.into_iter().rev());
    }
    test_der_wrap(0x06, &content)
}

fn x509_name_der(rdns: &[(&[u64], &str)]) -> Vec<u8> {
    let mut name = Vec::new();
    for (oid, value) in rdns {
        let mut attribute = test_der_oid(oid);
        attribute.extend(test_der_wrap(0x0c, value.as_bytes()));
        name.extend(test_der_wrap(0x31, &test_der_wrap(0x30, &attribute)));
    }
    test_der_wrap(0x30, &name)
}

fn directory_name_general_name_der(rdns: &[(&[u64], &str)]) -> Vec<u8> {
    test_der_wrap(0xa4, &x509_name_der(rdns))
}

fn certificate_policy_extension_content(policy_oid: &[u64]) -> Vec<u8> {
    let policy_information = test_der_wrap(0x30, &test_der_oid(policy_oid));
    test_der_wrap(0x30, &policy_information)
}

fn private_key_usage_period_extension_content(not_before: &str, not_after: &str) -> Vec<u8> {
    let mut content = Vec::new();
    content.extend(test_der_wrap(0x80, not_before.as_bytes()));
    content.extend(test_der_wrap(0x81, not_after.as_bytes()));
    test_der_wrap(0x30, &content)
}

fn test_der_unsigned_integer_content(value: u8) -> Vec<u8> {
    if value & 0x80 == 0 {
        vec![value]
    } else {
        vec![0, value]
    }
}

fn general_subtree_der(base: Vec<u8>, minimum: Option<u8>, maximum: Option<u8>) -> Vec<u8> {
    let mut content = base;
    if let Some(minimum) = minimum {
        content.extend(test_der_wrap(
            0x80,
            &test_der_unsigned_integer_content(minimum),
        ));
    }
    if let Some(maximum) = maximum {
        content.extend(test_der_wrap(
            0x81,
            &test_der_unsigned_integer_content(maximum),
        ));
    }
    test_der_wrap(0x30, &content)
}

fn name_constraints_extension_content() -> Vec<u8> {
    let permitted = general_subtree_der(test_der_wrap(0x82, b"example.org"), Some(0), Some(3));
    let permitted_directory = general_subtree_der(
        directory_name_general_name_der(&[
            (&[2, 5, 4, 11], "Allowed"),
            (&[2, 5, 4, 10], "Example"),
        ]),
        Some(1),
        Some(2),
    );
    let excluded = general_subtree_der(test_der_wrap(0x81, b"blocked@example.org"), Some(1), None);
    let excluded_directory = general_subtree_der(
        directory_name_general_name_der(&[
            (&[2, 5, 4, 11], "Blocked"),
            (&[2, 5, 4, 10], "Example"),
        ]),
        None,
        None,
    );
    let mut content = Vec::new();
    let mut permitted_subtrees = permitted;
    permitted_subtrees.extend(permitted_directory);
    let mut excluded_subtrees = excluded;
    excluded_subtrees.extend(excluded_directory);
    content.extend(test_der_wrap(0xa0, &permitted_subtrees));
    content.extend(test_der_wrap(0xa1, &excluded_subtrees));
    test_der_wrap(0x30, &content)
}

fn test_component_certificate_pem() -> String {
    let issuer_key = rcgen::KeyPair::generate().unwrap();
    let mut issuer_params =
        rcgen::CertificateParams::new(vec!["ca.example.org".to_string()]).unwrap();
    issuer_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    issuer_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let issuer = rcgen::CertifiedIssuer::self_signed(issuer_params, issuer_key).unwrap();

    let cert_key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec![
        "cert.example.org".to_string(),
        "192.0.2.10".to_string(),
    ])
    .unwrap();
    params.is_ca = rcgen::IsCa::ExplicitNoCa;
    params.use_authority_key_identifier_extension = true;
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyEncipherment,
    ];
    params
        .custom_extensions
        .push(rcgen::CustomExtension::from_oid_content(
            &[2, 5, 29, 32],
            certificate_policy_extension_content(&[1, 2, 3, 4]),
        ));
    params
        .custom_extensions
        .push(rcgen::CustomExtension::from_oid_content(
            &[2, 5, 29, 30],
            name_constraints_extension_content(),
        ));
    params
        .custom_extensions
        .push(rcgen::CustomExtension::from_oid_content(
            &[2, 5, 29, 16],
            private_key_usage_period_extension_content("20240101000000Z", "20250101000000Z"),
        ));

    params.signed_by(&cert_key, &issuer).unwrap().pem()
}

fn certificate_subject_key_identifier(cert_der: &[u8]) -> Vec<u8> {
    let (_, certificate) = x509_parser::parse_x509_certificate(cert_der).unwrap();
    certificate
        .iter_extensions()
        .find_map(|extension| match extension.parsed_extension() {
            x509_parser::extensions::ParsedExtension::SubjectKeyIdentifier(key_identifier) => {
                Some(key_identifier.0.to_vec())
            }
            _ => None,
        })
        .expect("test certificate should contain a subjectKeyIdentifier extension")
}

fn certificate_authority_key_identifier(cert_der: &[u8]) -> Vec<u8> {
    let (_, certificate) = x509_parser::parse_x509_certificate(cert_der).unwrap();
    certificate
        .iter_extensions()
        .find_map(|extension| match extension.parsed_extension() {
            x509_parser::extensions::ParsedExtension::AuthorityKeyIdentifier(
                authority_key_identifier,
            ) => authority_key_identifier
                .key_identifier
                .as_ref()
                .map(|key_identifier| key_identifier.0.to_vec()),
            _ => None,
        })
        .expect("test certificate should contain an authorityKeyIdentifier extension")
}

fn crl_authority_key_identifier(crl_der: &[u8]) -> Vec<u8> {
    let (_, certificate_list) = x509_parser::parse_x509_crl(crl_der).unwrap();
    certificate_list
        .extensions()
        .iter()
        .find_map(|extension| match extension.parsed_extension() {
            x509_parser::extensions::ParsedExtension::AuthorityKeyIdentifier(
                authority_key_identifier,
            ) => authority_key_identifier
                .key_identifier
                .as_ref()
                .map(|key_identifier| key_identifier.0.to_vec()),
            _ => None,
        })
        .expect("test CRL should contain an authorityKeyIdentifier extension")
}

fn gser_hstring(bytes: &[u8]) -> String {
    format!("'{}'H", hex::encode_upper(bytes))
}

fn test_crl_pem() -> String {
    let signing_key = rcgen::KeyPair::generate().unwrap();
    let mut issuer_params =
        rcgen::CertificateParams::new(vec!["ca.example.org".to_string()]).unwrap();
    issuer_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    issuer_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let issuer = rcgen::CertifiedIssuer::self_signed(issuer_params, signing_key).unwrap();
    let crl = rcgen::CertificateRevocationListParams {
        this_update: rcgen::date_time_ymd(2024, 1, 1),
        next_update: rcgen::date_time_ymd(2025, 1, 1),
        crl_number: rcgen::SerialNumber::from(1),
        issuing_distribution_point: Some(rcgen::CrlIssuingDistributionPoint {
            distribution_point: rcgen::CrlDistributionPoint {
                uris: vec!["https://crl.example.org/root.crl".to_string()],
            },
            scope: None,
        }),
        revoked_certs: Vec::new(),
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    }
    .signed_by(&issuer)
    .unwrap();
    crl.pem().unwrap()
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
    let rcgen::CertifiedKey { cert, .. } =
        rcgen::generate_simple_self_signed(vec!["carol.example.org".to_string()]).unwrap();

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
    attributes.insert("audio".to_string(), vec!["audio bytes".to_string()]);
    attributes.insert("homePhone".to_string(), vec!["+1 555 0101".to_string()]);
    attributes.insert(
        "homePostalAddress".to_string(),
        vec!["10 Home Road$Colombo".to_string()],
    );
    attributes.insert("jpegPhoto".to_string(), vec!["jpeg bytes".to_string()]);
    attributes.insert("photo".to_string(), vec!["fax bytes".to_string()]);
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
    attributes.insert(
        "preferredLanguage".to_string(),
        vec!["fr, en-gb;q=0.8, en;q=0.7".to_string()],
    );
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
    attributes.insert(
        "x500UniqueIdentifier".to_string(),
        vec!["'1010'B".to_string()],
    );
    attributes.insert("userCertificate;binary".to_string(), vec![cert.pem()]);
    attributes.insert(
        "userSMIMECertificate;binary".to_string(),
        vec!["pkcs7 bytes".to_string()],
    );
    attributes.insert(
        "userPKCS12;binary".to_string(),
        vec!["pfx bytes".to_string()],
    );

    assert!(
        schema.validate_entry(&attributes).is_ok(),
        "inetOrgPerson should allow the full RFC2798 attribute set"
    );
}

#[test]
fn test_inet_org_person_rejects_invalid_rfc2798_syntaxes() {
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
        "preferredLanguage".to_string(),
        vec!["Accept-Language: en-US".to_string()],
    );
    assert!(matches!(
        schema.validate_entry(&attributes),
        Err(SchemaError::InvalidSyntax(attribute, _)) if attribute == "preferredLanguage"
    ));

    attributes.insert("preferredLanguage".to_string(), vec!["en-US".to_string()]);
    attributes.insert(
        "userCertificate;binary".to_string(),
        vec!["not a certificate".to_string()],
    );
    assert!(matches!(
        schema.validate_entry(&attributes),
        Err(SchemaError::InvalidSyntax(attribute, _)) if attribute == "userCertificate;binary"
    ));
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
fn test_group_of_names_requires_member_per_rfc4519() {
    let schema = LdapSchema::with_core_schema();

    let mut attributes = HashMap::new();
    attributes.insert(
        "objectClass".to_string(),
        vec!["top".to_string(), "groupOfNames".to_string()],
    );
    attributes.insert("cn".to_string(), vec!["empty-group".to_string()]);
    attributes.insert("ou".to_string(), vec!["dc=example,dc=com".to_string()]);
    attributes.insert("description".to_string(), vec!["Empty group".to_string()]);

    assert!(matches!(
        schema.validate_entry(&attributes),
        Err(SchemaError::MissingRequiredAttribute(attribute)) if attribute == "member"
    ));
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
fn test_rfc4519_user_schema_attributes_and_object_classes() {
    let schema = LdapSchema::with_core_schema();

    for attribute in [
        "name",
        "serialNumber",
        "c",
        "searchGuide",
        "destinationIndicator",
        "distinguishedName",
        "dnQualifier",
        "enhancedSearchGuide",
        "facsimileTelephoneNumber",
        "generationQualifier",
        "houseIdentifier",
        "internationalISDNNumber",
        "roleOccupant",
        "telexNumber",
        "teletexTerminalIdentifier",
        "x121Address",
        "x500UniqueIdentifier",
        "preferredDeliveryMethod",
    ] {
        assert!(
            schema.get_attribute_type(attribute).is_some(),
            "RFC 4519 attribute {attribute} should be registered"
        );
    }

    for object_class in [
        "applicationProcess",
        "country",
        "device",
        "locality",
        "organizationalRole",
        "residentialPerson",
        "uidObject",
    ] {
        assert!(
            schema.get_object_class(object_class).is_some(),
            "RFC 4519 object class {object_class} should be registered"
        );
    }
}

#[test]
fn test_rfc4519_user_schema_entries_validate() {
    let schema = LdapSchema::with_core_schema();

    let country = HashMap::from([
        (
            "objectClass".to_string(),
            vec!["top".to_string(), "country".to_string()],
        ),
        ("c".to_string(), vec!["US".to_string()]),
        ("searchGuide".to_string(), vec!["person#sn$EQ".to_string()]),
    ]);
    assert!(schema.validate_entry(&country).is_ok());

    let device = HashMap::from([
        (
            "objectClass".to_string(),
            vec!["top".to_string(), "device".to_string()],
        ),
        ("cn".to_string(), vec!["router-1".to_string()]),
        ("serialNumber".to_string(), vec!["WI-3005".to_string()]),
        (
            "owner".to_string(),
            vec!["uid=alice,ou=People,dc=example,dc=com".to_string()],
        ),
    ]);
    assert!(schema.validate_entry(&device).is_ok());

    let role = HashMap::from([
        (
            "objectClass".to_string(),
            vec!["top".to_string(), "organizationalRole".to_string()],
        ),
        (
            "cn".to_string(),
            vec!["Human Resources Director".to_string()],
        ),
        (
            "roleOccupant".to_string(),
            vec!["uid=alice,ou=People,dc=example,dc=com".to_string()],
        ),
        (
            "preferredDeliveryMethod".to_string(),
            vec!["mhs $ telephone".to_string()],
        ),
    ]);
    assert!(schema.validate_entry(&role).is_ok());

    let residential_person = HashMap::from([
        (
            "objectClass".to_string(),
            vec!["top".to_string(), "residentialPerson".to_string()],
        ),
        ("cn".to_string(), vec!["Alice Example".to_string()]),
        ("sn".to_string(), vec!["Example".to_string()]),
        ("l".to_string(), vec!["Colombo".to_string()]),
        (
            "x121Address".to_string(),
            vec!["36111222333444555".to_string()],
        ),
    ]);
    assert!(schema.validate_entry(&residential_person).is_ok());

    let uid_object_person = HashMap::from([
        (
            "objectClass".to_string(),
            vec![
                "top".to_string(),
                "person".to_string(),
                "uidObject".to_string(),
            ],
        ),
        ("cn".to_string(), vec!["Bob Example".to_string()]),
        ("sn".to_string(), vec!["Example".to_string()]),
        ("uid".to_string(), vec!["bexample".to_string()]),
    ]);
    assert!(schema.validate_entry(&uid_object_person).is_ok());
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
fn test_rfc2307_posix_bundle_defines_full_schema() {
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
            "RFC 2307 attribute {attribute} should be registered"
        );
    }

    for object_class in [
        "posixAccount",
        "shadowAccount",
        "posixGroup",
        "ipService",
        "ipProtocol",
        "oncRpc",
        "ipHost",
        "ipNetwork",
        "nisNetgroup",
        "nisMap",
        "nisObject",
        "ieee802Device",
        "bootableDevice",
    ] {
        assert!(
            schema.get_object_class(object_class).is_some(),
            "RFC 2307 object class {object_class} should be registered"
        );
    }
}

#[test]
fn test_rfc2307_posix_schema_loads_from_bundled_ldif_file() {
    let mut schema = LdapSchema::with_core_schema();
    schema
        .load_ldif_str(include_str!("../resources/schema/posix/rfc2307.ldif"))
        .unwrap();

    assert!(schema.get_attribute_type("nisNetgroupTriple").is_some());
    assert!(schema.get_attribute_type("bootParameter").is_some());
    assert!(schema.get_object_class("posixAccount").is_some());
    assert!(schema.get_object_class("bootableDevice").is_some());
}

#[test]
fn test_rfc4523_x509_bundle_defines_full_schema() {
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
            "RFC 4523 attribute {attribute} should be registered"
        );
    }

    for object_class in [
        "pkiUser",
        "pkiCA",
        "cRLDistributionPoint",
        "deltaCRL",
        "strongAuthenticationUser",
        "userSecurityInformation",
        "certificationAuthority",
        "certificationAuthority-V2",
    ] {
        assert!(
            schema.get_object_class(object_class).is_some(),
            "RFC 4523 object class {object_class} should be registered"
        );
    }

    for syntax_oid in [
        "1.3.6.1.4.1.1466.115.121.1.9",
        "1.3.6.1.4.1.1466.115.121.1.10",
        "1.3.6.1.4.1.1466.115.121.1.49",
        "1.3.6.1.1.15.1",
        "1.3.6.1.1.15.7",
    ] {
        assert!(
            schema
                .ldap_syntax_descriptions_unique_sorted()
                .iter()
                .any(|description| description.contains(syntax_oid)),
            "RFC 4523 syntax {syntax_oid} should be registered"
        );
    }

    for matching_rule in [
        "certificateExactMatch",
        "certificateMatch",
        "certificatePairExactMatch",
        "certificatePairMatch",
        "certificateListExactMatch",
        "certificateListMatch",
        "algorithmIdentifierMatch",
    ] {
        assert!(
            schema.get_matching_rule(matching_rule).is_some(),
            "RFC 4523 matching rule {matching_rule} should be registered"
        );
    }

    assert!(
        schema
            .resolve_matching_rule("certificateExactMatch")
            .unwrap()
            .is_supported()
    );
    assert!(
        schema
            .resolve_matching_rule("certificateListExactMatch")
            .unwrap()
            .is_supported()
    );
    assert!(
        schema
            .resolve_matching_rule("certificatePairExactMatch")
            .unwrap()
            .is_supported()
    );
    assert!(
        schema
            .resolve_matching_rule("algorithmIdentifierMatch")
            .unwrap()
            .is_supported()
    );
    assert!(
        schema
            .resolve_matching_rule("certificateMatch")
            .unwrap()
            .is_supported()
    );
    assert!(
        schema
            .resolve_matching_rule("certificateListMatch")
            .unwrap()
            .is_supported()
    );
    assert!(
        schema
            .resolve_matching_rule("certificatePairMatch")
            .unwrap()
            .is_supported()
    );
}

#[test]
fn test_rfc4523_x509_schema_loads_from_bundled_ldif_file() {
    let mut schema = LdapSchema::with_core_schema();
    schema
        .load_ldif_str(include_str!("../resources/schema/x509/rfc4523.ldif"))
        .unwrap();

    assert!(schema.get_attribute_type("cACertificate").is_some());
    assert!(
        schema
            .get_attribute_type("certificateRevocationList")
            .is_some()
    );
    assert!(schema.get_attribute_type("supportedAlgorithms").is_some());
    assert!(schema.get_object_class("pkiUser").is_some());
    assert!(schema.get_object_class("cRLDistributionPoint").is_some());
}

#[test]
fn test_rfc4523_x509_entries_validate() {
    let mut schema = LdapSchema::with_core_schema();
    schema.load_builtin_schema("x509").unwrap();
    let rcgen::CertifiedKey { cert, .. } =
        rcgen::generate_simple_self_signed(vec!["cert.example.org".to_string()]).unwrap();
    let cert_pem = cert.pem();
    let crl_pem = test_crl_pem();
    let supported_algorithm = supported_algorithm_base64();

    let valid_entries = vec![
        attrs(&[
            ("objectClass", &["top", "person", "pkiUser"]),
            ("cn", &["Carol Example"]),
            ("sn", &["Example"]),
            ("userCertificate;binary", &[cert_pem.as_str()]),
        ]),
        attrs(&[
            (
                "objectClass",
                &["top", "person", "strongAuthenticationUser"],
            ),
            ("cn", &["Strong User"]),
            ("sn", &["User"]),
            ("userCertificate;binary", &[cert_pem.as_str()]),
        ]),
        attrs(&[
            ("objectClass", &["top", "cRLDistributionPoint"]),
            ("cn", &["Example CRL"]),
            ("certificateRevocationList;binary", &[crl_pem.as_str()]),
            ("deltaRevocationList;binary", &[crl_pem.as_str()]),
        ]),
        attrs(&[
            ("objectClass", &["top", "person", "userSecurityInformation"]),
            ("cn", &["Security User"]),
            ("sn", &["User"]),
            (
                "supportedAlgorithms;binary",
                &[supported_algorithm.as_str()],
            ),
        ]),
        attrs(&[
            ("objectClass", &["top", "organization", "pkiCA"]),
            ("o", &["Example CA"]),
            ("cACertificate;binary", &[cert_pem.as_str()]),
            ("certificateRevocationList;binary", &[crl_pem.as_str()]),
        ]),
    ];

    for attributes in valid_entries {
        assert!(
            schema.validate_entry(&attributes).is_ok(),
            "RFC 4523 entry should validate: {attributes:?}"
        );
    }
}

#[test]
fn test_rfc4523_x509_entries_reject_invalid_values() {
    let mut schema = LdapSchema::with_core_schema();
    schema.load_builtin_schema("x509").unwrap();

    let invalid_entries = vec![
        (
            attrs(&[
                ("objectClass", &["top", "person", "pkiUser"]),
                ("cn", &["Carol Example"]),
                ("sn", &["Example"]),
                ("userCertificate;binary", &["not a certificate"]),
            ]),
            SchemaError::InvalidSyntax("userCertificate;binary".to_string(), String::new()),
        ),
        (
            attrs(&[
                ("objectClass", &["top", "cRLDistributionPoint"]),
                ("cn", &["Example CRL"]),
                ("certificateRevocationList;binary", &["not a crl"]),
            ]),
            SchemaError::InvalidSyntax(
                "certificateRevocationList;binary".to_string(),
                String::new(),
            ),
        ),
        (
            attrs(&[
                (
                    "objectClass",
                    &["top", "person", "strongAuthenticationUser"],
                ),
                ("cn", &["Strong User"]),
                ("sn", &["User"]),
            ]),
            SchemaError::MissingRequiredAttribute("userCertificate".to_string()),
        ),
        (
            attrs(&[
                ("objectClass", &["top", "person", "userSecurityInformation"]),
                ("cn", &["Security User"]),
                ("sn", &["User"]),
                ("supportedAlgorithms;binary", &["not an algorithm"]),
            ]),
            SchemaError::InvalidSyntax("supportedAlgorithms;binary".to_string(), String::new()),
        ),
    ];

    for (attributes, expected) in invalid_entries {
        let actual = schema.validate_entry(&attributes).unwrap_err();
        assert!(
            std::mem::discriminant(&actual) == std::mem::discriminant(&expected),
            "expected {expected:?} for RFC 4523 invalid entry {attributes:?}, got {actual:?}"
        );
    }
}

#[test]
fn test_rfc4523_x509_exact_matching_rules_execute_gser_assertions() {
    let mut schema = LdapSchema::with_core_schema();
    schema.load_builtin_schema("x509").unwrap();

    let cert_pem = test_component_certificate_pem();
    let cert_der = der_from_pem(&cert_pem, "CERTIFICATE");
    let certificate_assertion = certificate_exact_assertion(&cert_der);

    let certificate_rule = schema
        .equality_rule_for_attribute("userCertificate")
        .unwrap();
    assert!(
        certificate_rule
            .values_equal(&cert_pem, &certificate_assertion)
            .unwrap()
    );
    assert!(
        !certificate_rule
            .values_equal(
                &cert_pem,
                &certificate_assertion.replacen("serialNumber ", "serialNumber 999", 1)
            )
            .unwrap()
    );

    let (_, certificate) = x509_parser::parse_x509_certificate(&cert_der).unwrap();
    let subject = gser_quote(&certificate.subject().to_string());
    let valid_time = certificate.validity().not_before.to_datetime();
    let valid_time_assertion = format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}Z",
        valid_time.year(),
        u8::from(valid_time.month()),
        valid_time.day(),
        valid_time.hour(),
        valid_time.minute(),
        valid_time.second()
    );
    let subject_public_key_alg_id = certificate
        .tbs_certificate
        .subject_pki
        .algorithm
        .algorithm
        .to_id_string();
    let subject_key_identifier = gser_hstring(&certificate_subject_key_identifier(&cert_der));
    let authority_key_identifier = gser_hstring(&certificate_authority_key_identifier(&cert_der));
    let certificate_component_rule = schema.resolve_matching_rule("certificateMatch").unwrap();
    assert!(
        certificate_component_rule
            .values_equal(
                &cert_pem,
                &format!(
                    "{{ subject rdnSequence:{subject}, certificateValid generalizedTime:{valid_time_assertion}, privateKeyValid 20240601000000Z, subjectPublicKeyAlgID {subject_public_key_alg_id}, subjectKeyIdentifier {subject_key_identifier}, authorityKeyIdentifier {{ keyIdentifier {authority_key_identifier} }}, subjectAltName builtinNameForm:dNSName, policy {{ 1.2.3.4 }}, pathToName rdnSequence:{}, nameConstraints {{ permittedSubtrees {{ {{ base dNSName:{}, minimum 0, maximum 3 }} }}, excludedSubtrees {{ {{ base rfc822Name:{}, minimum 1 }} }} }} }}",
                    gser_quote("cn=Alice,ou=Allowed,o=Example"),
                    gser_quote("example.org"),
                    gser_quote("blocked@example.org")
                ),
            )
            .unwrap()
    );
    assert!(
        certificate_component_rule
            .values_equal(&cert_pem, "{ subjectAltName builtinNameForm:iPAddress }")
            .unwrap()
    );
    assert!(
        !certificate_component_rule
            .values_equal(&cert_pem, "{ serialNumber 999999999 }")
            .unwrap()
    );
    assert!(
        certificate_component_rule
            .values_equal(&cert_pem, &format!("{{ issuer rdnSequence:{subject} }}"))
            .unwrap()
    );
    assert!(
        !certificate_component_rule
            .values_equal(&cert_pem, "{ policy { 1.2.3.5 } }")
            .unwrap()
    );
    assert!(
        !certificate_component_rule
            .values_equal(&cert_pem, "{ privateKeyValid 20260101000000Z }")
            .unwrap()
    );
    assert!(
        !certificate_component_rule
            .values_equal(
                &cert_pem,
                &format!(
                    "{{ nameConstraints {{ permittedSubtrees {{ {{ base dNSName:{} }} }} }} }}",
                    gser_quote("other.org")
                )
            )
            .unwrap()
    );
    assert!(
        !certificate_component_rule
            .values_equal(
                &cert_pem,
                &format!(
                    "{{ nameConstraints {{ permittedSubtrees {{ {{ base dNSName:{}, maximum 4 }} }} }} }}",
                    gser_quote("example.org")
                )
            )
            .unwrap()
    );
    assert!(
        !certificate_component_rule
            .values_equal(
                &cert_pem,
                &format!(
                    "{{ pathToName rdnSequence:{} }}",
                    gser_quote("cn=Mallory,ou=Blocked,o=Example")
                )
            )
            .unwrap()
    );
    assert!(
        !certificate_component_rule
            .values_equal(
                &cert_pem,
                &format!(
                    "{{ pathToName rdnSequence:{} }}",
                    gser_quote("cn=Eve,ou=Other,o=Example")
                )
            )
            .unwrap()
    );
    assert!(
        !certificate_component_rule
            .values_equal(
                &cert_pem,
                &format!(
                    "{{ pathToName rdnSequence:{} }}",
                    gser_quote("ou=Allowed,o=Example")
                )
            )
            .unwrap()
    );

    let crl_pem = test_crl_pem();
    let crl_der = der_from_pem(&crl_pem, "X509 CRL");
    let certificate_list_rule = schema
        .equality_rule_for_attribute("certificateRevocationList")
        .unwrap();
    assert!(
        certificate_list_rule
            .values_equal(&crl_pem, &certificate_list_exact_assertion(&crl_der))
            .unwrap()
    );
    let (_, certificate_list) = x509_parser::parse_x509_crl(&crl_der).unwrap();
    let certificate_list_component_rule = schema
        .resolve_matching_rule("certificateListMatch")
        .unwrap();
    let crl_authority_key_identifier = gser_hstring(&crl_authority_key_identifier(&crl_der));
    assert!(
        certificate_list_component_rule
            .values_equal(
                &crl_pem,
                &format!(
                    "{{ issuer rdnSequence:{}, dateAndTime generalizedTime:20240101000000Z, authorityKeyIdentifier {{ keyIdentifier {crl_authority_key_identifier} }}, distributionPoint fullName:{{ uniformResourceIdentifier:{} }} }}",
                    gser_quote(&certificate_list.issuer().to_string()),
                    gser_quote("https://crl.example.org/root.crl")
                )
            )
            .unwrap()
    );
    assert!(
        !certificate_list_component_rule
            .values_equal(&crl_pem, "{ reasonFlags { keyCompromise } }")
            .unwrap()
    );

    let certificate_pair_rule = schema
        .equality_rule_for_attribute("crossCertificatePair")
        .unwrap();
    let certificate_pair_assertion = format!(
        "{{ issuedToThisCAAssertion {} }}",
        certificate_exact_assertion(&cert_der)
    );
    assert!(
        certificate_pair_rule
            .values_equal(
                &certificate_pair_base64(&cert_der),
                &certificate_pair_assertion
            )
            .unwrap()
    );
    let certificate_pair_component_rule = schema
        .resolve_matching_rule("certificatePairMatch")
        .unwrap();
    assert!(
        certificate_pair_component_rule
            .values_equal(
                &certificate_pair_base64(&cert_der),
                &format!("{{ issuedToThisCAAssertion {{ subject rdnSequence:{subject} }} }}"),
            )
            .unwrap()
    );

    let algorithm_rule = schema
        .equality_rule_for_attribute("supportedAlgorithms")
        .unwrap();
    assert!(
        algorithm_rule
            .values_equal(
                &supported_algorithm_base64(),
                "{ algorithm 1.2.840.113549.1.1.1, parameters NULL }"
            )
            .unwrap()
    );
    assert!(
        !algorithm_rule
            .values_equal(
                &supported_algorithm_base64(),
                "{ algorithm 1.2.840.113549.1.1.5, parameters NULL }"
            )
            .unwrap()
    );
}

#[test]
fn test_rfc4524_cosine_bundle_defines_full_schema() {
    let mut schema = LdapSchema::with_core_schema();
    schema.load_builtin_schema("cosine").unwrap();

    for attribute in [
        "associatedDomain",
        "associatedName",
        "buildingName",
        "co",
        "friendlyCountryName",
        "documentAuthor",
        "documentIdentifier",
        "documentLocation",
        "documentPublisher",
        "documentTitle",
        "documentVersion",
        "drink",
        "favouriteDrink",
        "homePhone",
        "homeTelephone",
        "homePostalAddress",
        "host",
        "info",
        "mail",
        "rfc822Mailbox",
        "manager",
        "mobile",
        "mobileTelephoneNumber",
        "organizationalStatus",
        "pager",
        "pagerTelephoneNumber",
        "personalTitle",
        "roomNumber",
        "secretary",
        "uniqueIdentifier",
        "userClass",
    ] {
        assert!(
            schema.get_attribute_type(attribute).is_some(),
            "RFC 4524 attribute {attribute} should be registered"
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
            "RFC 4524 object class {object_class} should be registered"
        );
    }

    let domain = schema.get_object_class("domain").unwrap();
    assert!(
        domain
            .may
            .iter()
            .any(|attribute| attribute.eq_ignore_ascii_case("associatedName")),
        "RFC 4524 should upgrade the partial core domain class with associatedName"
    );
}

#[test]
fn test_rfc4524_cosine_schema_loads_from_bundled_ldif_file() {
    let mut schema = LdapSchema::with_core_schema();
    schema
        .load_ldif_str(include_str!("../resources/schema/cosine/rfc4524.ldif"))
        .unwrap();

    assert!(schema.get_attribute_type("associatedDomain").is_some());
    assert!(schema.get_attribute_type("friendlyCountryName").is_some());
    assert!(schema.get_object_class("document").is_some());
    assert!(schema.get_object_class("simpleSecurityObject").is_some());
}

#[test]
fn test_rfc4524_cosine_entries_validate() {
    let mut schema = LdapSchema::with_core_schema();
    schema.load_builtin_schema("cosine").unwrap();

    let valid_entries = vec![
        attrs(&[
            ("objectClass", &["top", "account"]),
            ("uid", &["host-admin"]),
            ("host", &["ldap01.example.com"]),
            ("description", &["Computer account"]),
        ]),
        attrs(&[
            ("objectClass", &["top", "document"]),
            ("documentIdentifier", &["RFC 4524"]),
            ("documentTitle", &["COSINE LDAP/X.500 Schema"]),
            (
                "documentAuthor",
                &["cn=Kurt Zeilenga,ou=People,dc=example,dc=com"],
            ),
            ("documentPublisher", &["Internet Engineering Task Force"]),
        ]),
        attrs(&[
            ("objectClass", &["top", "documentSeries"]),
            ("cn", &["Request for Comments", "RFC"]),
            ("telephoneNumber", &["+1 775 555 1111"]),
        ]),
        attrs(&[
            ("objectClass", &["top", "domain"]),
            ("dc", &["example"]),
            (
                "associatedName",
                &["o=Example Organization,dc=example,dc=com"],
            ),
        ]),
        attrs(&[
            (
                "objectClass",
                &["top", "organization", "dcObject", "domainRelatedObject"],
            ),
            ("o", &["Example Organization"]),
            ("dc", &["example"]),
            ("associatedDomain", &["example.com"]),
        ]),
        attrs(&[
            ("objectClass", &["top", "country", "friendlyCountry"]),
            ("c", &["DE"]),
            ("friendlyCountryName", &["Germany"]),
        ]),
        attrs(&[
            ("objectClass", &["top", "domain", "rFC822LocalPart"]),
            ("dc", &["kdz"]),
            ("associatedName", &["cn=Kurt,ou=People,dc=example,dc=com"]),
            ("cn", &["kdz"]),
        ]),
        attrs(&[
            ("objectClass", &["top", "room"]),
            ("cn", &["conference room"]),
            ("roomNumber", &["1A"]),
            ("telephoneNumber", &["+1 775 555 1111"]),
        ]),
        attrs(&[
            ("objectClass", &["top", "account", "simpleSecurityObject"]),
            ("uid", &["service-account"]),
            ("userPassword", &["{SSHA512}hashed"]),
        ]),
    ];

    for attributes in valid_entries {
        assert!(
            schema.validate_entry(&attributes).is_ok(),
            "RFC 4524 entry should validate: {attributes:?}"
        );
    }
}

#[test]
fn test_rfc4524_cosine_entries_reject_invalid_values() {
    let mut schema = LdapSchema::with_core_schema();
    schema.load_builtin_schema("cosine").unwrap();

    let long_identifier = "x".repeat(257);

    let invalid_entries = vec![
        (
            attrs(&[
                (
                    "objectClass",
                    &["top", "organization", "dcObject", "domainRelatedObject"],
                ),
                ("o", &["Example Organization"]),
                ("dc", &["example"]),
                ("associatedDomain", &["exämple.com"]),
            ]),
            SchemaError::InvalidSyntax("associatedDomain".to_string(), String::new()),
        ),
        (
            attrs(&[
                ("objectClass", &["top", "domain"]),
                ("dc", &["example"]),
                ("associatedName", &["not a dn"]),
            ]),
            SchemaError::InvalidSyntax("associatedName".to_string(), String::new()),
        ),
        (
            {
                let mut attributes = attrs(&[
                    ("objectClass", &["top", "document"]),
                    ("documentTitle", &["Too long"]),
                ]);
                attributes.insert("documentIdentifier".to_string(), vec![long_identifier]);
                attributes
            },
            SchemaError::InvalidSyntax("documentIdentifier".to_string(), String::new()),
        ),
        (
            attrs(&[
                ("objectClass", &["top", "account", "simpleSecurityObject"]),
                ("uid", &["service-account"]),
            ]),
            SchemaError::MissingRequiredAttribute("userPassword".to_string()),
        ),
    ];

    for (attributes, expected) in invalid_entries {
        match (schema.validate_entry(&attributes), expected) {
            (
                Err(SchemaError::InvalidSyntax(attribute, _)),
                SchemaError::InvalidSyntax(expected_attribute, _),
            ) if attribute == expected_attribute => {}
            (
                Err(SchemaError::MissingRequiredAttribute(attribute)),
                SchemaError::MissingRequiredAttribute(expected_attribute),
            ) if attribute == expected_attribute => {}
            (actual, expected) => panic!(
                "expected {expected:?} for RFC 4524 invalid entry {attributes:?}, got {actual:?}"
            ),
        }
    }
}

#[test]
fn test_schema_dir_loads_nested_schema_files() {
    let temp_dir = tempfile::tempdir().unwrap();
    let posix_dir = temp_dir.path().join("posix");
    std::fs::create_dir_all(&posix_dir).unwrap();
    std::fs::write(
        posix_dir.join("rfc2307.ldif"),
        include_str!("../resources/schema/posix/rfc2307.ldif"),
    )
    .unwrap();

    let mut schema = LdapSchema::with_core_schema();
    schema.load_schema_dir(temp_dir.path()).unwrap();

    assert!(schema.get_object_class("nisObject").is_some());
    assert!(schema.get_attribute_type("nisMapEntry").is_some());
}

#[test]
fn test_rfc2307_posix_nis_entries_validate() {
    let mut schema = LdapSchema::with_core_schema();
    schema.load_builtin_schema("posix").unwrap();

    let valid_entries = vec![
        attrs(&[
            ("objectClass", &["top", "person", "shadowAccount"]),
            ("cn", &["Alice Example"]),
            ("sn", &["Example"]),
            ("uid", &["alice"]),
            ("userPassword", &["{crypt}X5/DBrWPOQQaI"]),
            ("shadowLastChange", &["19710"]),
            ("shadowMin", &["0"]),
            ("shadowMax", &["99999"]),
            ("shadowWarning", &["7"]),
            ("shadowInactive", &["30"]),
            ("shadowExpire", &["20000"]),
            ("shadowFlag", &["0"]),
        ]),
        attrs(&[
            ("objectClass", &["top", "ipService"]),
            ("cn", &["ssh"]),
            ("ipServicePort", &["22"]),
            ("ipServiceProtocol", &["tcp"]),
            ("description", &["Secure Shell"]),
        ]),
        attrs(&[
            ("objectClass", &["top", "ipProtocol"]),
            ("cn", &["tcp"]),
            ("ipProtocolNumber", &["6"]),
            ("description", &["Transmission Control Protocol"]),
        ]),
        attrs(&[
            ("objectClass", &["top", "oncRpc"]),
            ("cn", &["mountd"]),
            ("oncRpcNumber", &["100005"]),
            ("description", &["NFS mount daemon"]),
        ]),
        attrs(&[
            (
                "objectClass",
                &["top", "device", "ipHost", "ieee802Device", "bootableDevice"],
            ),
            ("cn", &["peg.aja.com", "www.aja.com"]),
            ("ipHostNumber", &["10.0.0.1"]),
            ("macAddress", &["00:00:92:90:ee:e2"]),
            ("bootFile", &["mach"]),
            ("bootParameter", &["root=fs:/nfsroot/peg"]),
        ]),
        attrs(&[
            ("objectClass", &["top", "ipNetwork"]),
            ("cn", &["engineering-net"]),
            ("ipNetworkNumber", &["192.168"]),
            ("ipNetmaskNumber", &["255.255.0.0"]),
            ("description", &["Engineering network"]),
        ]),
        attrs(&[
            ("objectClass", &["top", "nisNetgroup"]),
            ("cn", &["nightfly"]),
            (
                "nisNetgroupTriple",
                &["(peg,charlemagne,dunes.aja.com)", "(,lester,-)"],
            ),
            ("memberNisNetgroup", &["kamakiriad"]),
        ]),
        attrs(&[
            ("objectClass", &["top", "nisMap"]),
            ("nisMapName", &["tracks"]),
            ("description", &["Album track map"]),
        ]),
        attrs(&[
            ("objectClass", &["top", "nisObject"]),
            ("cn", &["Maxine"]),
            ("nisMapName", &["tracks"]),
            ("nisMapEntry", &["Nightfly$4"]),
        ]),
    ];

    for attributes in valid_entries {
        assert!(
            schema.validate_entry(&attributes).is_ok(),
            "RFC 2307 entry should validate: {attributes:?}"
        );
    }
}

#[test]
fn test_rfc2307_posix_nis_entries_reject_invalid_values() {
    let mut schema = LdapSchema::with_core_schema();
    schema.load_builtin_schema("posix").unwrap();

    let invalid_entries = vec![
        (
            attrs(&[
                ("objectClass", &["top", "person", "shadowAccount"]),
                ("cn", &["Alice Example"]),
                ("sn", &["Example"]),
                ("uid", &["alice"]),
                ("shadowLastChange", &["yesterday"]),
            ]),
            "shadowLastChange",
        ),
        (
            attrs(&[
                ("objectClass", &["top", "ipService"]),
                ("cn", &["ssh"]),
                ("ipServicePort", &["-1"]),
                ("ipServiceProtocol", &["tcp"]),
            ]),
            "ipServicePort",
        ),
        (
            attrs(&[
                ("objectClass", &["top", "ipProtocol"]),
                ("cn", &["badproto"]),
                ("ipProtocolNumber", &["999"]),
                ("description", &["Invalid protocol"]),
            ]),
            "ipProtocolNumber",
        ),
        (
            attrs(&[
                ("objectClass", &["top", "oncRpc"]),
                ("cn", &["badrpc"]),
                ("oncRpcNumber", &["-1"]),
                ("description", &["Invalid RPC"]),
            ]),
            "oncRpcNumber",
        ),
        (
            attrs(&[
                ("objectClass", &["top", "device", "ipHost"]),
                ("cn", &["badhost"]),
                ("ipHostNumber", &["10.0.0.999"]),
            ]),
            "ipHostNumber",
        ),
        (
            attrs(&[
                ("objectClass", &["top", "ipNetwork"]),
                ("cn", &["badnet"]),
                ("ipNetworkNumber", &["192.168.0.0"]),
            ]),
            "ipNetworkNumber",
        ),
        (
            attrs(&[
                ("objectClass", &["top", "device", "ieee802Device"]),
                ("cn", &["badmac"]),
                ("macAddress", &["00:00:92:90:ee"]),
            ]),
            "macAddress",
        ),
        (
            attrs(&[
                ("objectClass", &["top", "device", "bootableDevice"]),
                ("cn", &["badboot"]),
                ("bootParameter", &["root=fs"]),
            ]),
            "bootParameter",
        ),
        (
            attrs(&[
                ("objectClass", &["top", "nisNetgroup"]),
                ("cn", &["badnetgroup"]),
                ("nisNetgroupTriple", &["peg,charlemagne,dunes.aja.com"]),
            ]),
            "nisNetgroupTriple",
        ),
        (
            attrs(&[
                ("objectClass", &["top", "nisObject"]),
                ("cn", &["BadMap"]),
                ("nisMapName", &["tracks"]),
                ("nisMapEntry", &["café"]),
            ]),
            "nisMapEntry",
        ),
    ];

    for (attributes, expected_attribute) in invalid_entries {
        assert!(
            matches!(
                schema.validate_entry(&attributes),
                Err(SchemaError::InvalidSyntax(attribute, _)) if attribute == expected_attribute
            ),
            "expected invalid attribute {expected_attribute} for {attributes:?}"
        );
    }
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
        names: vec!["customSerialNumber".to_string()],
        description: Some("Custom serial number".to_string()),
        equality: Some("caseIgnoreMatch".to_string()),
        syntax: "1.3.6.1.4.1.1466.115.121.1.15".to_string(),
        single_value: true,
    });

    schema.add_object_class(ObjectClass {
        oid: "1.2.3.4.9".to_string(),
        names: vec!["customDevice".to_string()],
        sup: vec!["top".to_string()],
        kind: ObjectClassKind::Structural,
        must: vec!["cn".to_string()],
        may: vec!["customSerialNumber".to_string()],
    });

    let mut attributes = HashMap::new();
    attributes.insert(
        "objectClass".to_string(),
        vec!["top".to_string(), "customDevice".to_string()],
    );
    attributes.insert("cn".to_string(), vec!["Device1".to_string()]);
    attributes.insert(
        "customSerialNumber".to_string(),
        vec!["SN12345".to_string()],
    );

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

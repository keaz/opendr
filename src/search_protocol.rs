use crate::backend::{BackendError, DirectoryBackend};
use crate::schema::LdapSchema;

const START_TLS_OID: &str = "1.3.6.1.4.1.1466.20037";
const CANCEL_OID: &str = "1.3.6.1.1.8";
const PASSWORD_MODIFY_OID: &str = "1.3.6.1.4.1.4203.1.11.1";
const WHO_AM_I_OID: &str = "1.3.6.1.4.1.4203.1.11.3";

pub async fn build_root_dse_attributes(
    backend: &dyn DirectoryBackend,
    naming_contexts: &[String],
    subschema_dn: &str,
    connection_is_secure: bool,
    starttls_available: bool,
    supported_control_oids: &[String],
    supported_sasl_mechanisms: &[String],
) -> Result<Vec<(String, Vec<String>)>, BackendError> {
    let mut attributes = vec![("supportedLDAPVersion".to_string(), vec!["3".to_string()])];

    if !naming_contexts.is_empty() {
        attributes.push(("namingContexts".to_string(), naming_contexts.to_vec()));
    }

    attributes.push((
        "subschemaSubentry".to_string(),
        vec![subschema_dn.to_string()],
    ));

    let supported_extensions = supported_extensions(connection_is_secure, starttls_available);
    if !supported_extensions.is_empty() {
        attributes.push(("supportedExtension".to_string(), supported_extensions));
    }

    if !supported_control_oids.is_empty() {
        attributes.push((
            "supportedControl".to_string(),
            supported_control_oids.to_vec(),
        ));
    }

    if !supported_sasl_mechanisms.is_empty() {
        attributes.push((
            "supportedSASLMechanisms".to_string(),
            supported_sasl_mechanisms.to_vec(),
        ));
    }

    if let Some(context_csn) = backend.get_context_csn().await? {
        attributes.push(("contextCSN".to_string(), vec![context_csn.to_ldap_string()]));
    }

    Ok(attributes)
}

pub fn build_subschema_attributes(schema: &LdapSchema) -> Vec<(String, Vec<String>)> {
    let mut attributes = vec![
        (
            "objectClass".to_string(),
            vec![
                "top".to_string(),
                "subentry".to_string(),
                "subschema".to_string(),
            ],
        ),
        ("cn".to_string(), vec!["Subschema".to_string()]),
    ];

    let attribute_types = schema
        .attribute_types_unique_sorted()
        .into_iter()
        .map(|attribute| attribute.to_schema_description())
        .collect::<Vec<_>>();
    if !attribute_types.is_empty() {
        attributes.push(("attributeTypes".to_string(), attribute_types));
    }

    let object_classes = schema
        .object_classes_unique_sorted()
        .into_iter()
        .map(|object_class| object_class.to_schema_description())
        .collect::<Vec<_>>();
    if !object_classes.is_empty() {
        attributes.push(("objectClasses".to_string(), object_classes));
    }

    attributes
}

pub fn select_virtual_attributes(
    available_attributes: &[(String, Vec<String>)],
    requested_attributes: &[String],
) -> Vec<(String, Vec<String>)> {
    if requested_attributes
        .iter()
        .any(|attribute| attribute.eq_ignore_ascii_case("1.1"))
    {
        return Vec::new();
    }

    let include_all = requested_attributes.is_empty()
        || requested_attributes
            .iter()
            .any(|attribute| attribute == "*" || attribute == "+");

    available_attributes
        .iter()
        .filter(|(name, _)| {
            include_all
                || requested_attributes
                    .iter()
                    .any(|attribute| attribute.eq_ignore_ascii_case(name))
        })
        .cloned()
        .collect()
}

pub fn supported_extensions(connection_is_secure: bool, starttls_available: bool) -> Vec<String> {
    let mut supported = Vec::new();
    if starttls_available && !connection_is_secure {
        supported.push(START_TLS_OID.to_string());
    }
    supported.push(CANCEL_OID.to_string());
    supported.push(PASSWORD_MODIFY_OID.to_string());
    supported.push(WHO_AM_I_OID.to_string());
    supported
}

pub fn supported_sasl_mechanisms() -> Vec<String> {
    supported_legacy_sasl_mechanisms()
}

pub fn supported_legacy_sasl_mechanisms() -> Vec<String> {
    vec!["PLAIN".to_string()]
}

pub fn supported_fsm_sasl_mechanisms() -> Vec<String> {
    vec!["PLAIN".to_string()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{DirectoryBackend, MockBackend};
    use crate::csn::Csn;

    #[test]
    fn select_virtual_attributes_respects_requested_projection() {
        let available = vec![
            ("cn".to_string(), vec!["alice".to_string()]),
            ("supportedControl".to_string(), vec!["1.2.3".to_string()]),
            (
                "supportedSASLMechanisms".to_string(),
                vec!["PLAIN".to_string()],
            ),
        ];

        assert!(select_virtual_attributes(&available, &["1.1".to_string()]).is_empty());

        let all = select_virtual_attributes(&available, &["*".to_string()]);
        assert_eq!(all.len(), 3);

        let selected = select_virtual_attributes(
            &available,
            &["supportedControl".to_string(), "cn".to_string()],
        );
        assert_eq!(selected.len(), 2);
        assert!(selected.iter().any(|(name, _)| name == "cn"));
        assert!(selected.iter().any(|(name, _)| name == "supportedControl"));
    }

    #[test]
    fn supported_extensions_omits_starttls_when_secure() {
        let insecure = supported_extensions(false, true);
        assert!(insecure.contains(&START_TLS_OID.to_string()));

        let secure = supported_extensions(true, true);
        assert!(!secure.contains(&START_TLS_OID.to_string()));
        assert!(secure.contains(&CANCEL_OID.to_string()));
        assert!(secure.contains(&PASSWORD_MODIFY_OID.to_string()));
        assert!(secure.contains(&WHO_AM_I_OID.to_string()));
    }

    #[test]
    fn supported_sasl_mechanisms_are_explicit() {
        assert_eq!(
            supported_legacy_sasl_mechanisms(),
            vec!["PLAIN".to_string()]
        );
        assert_eq!(supported_fsm_sasl_mechanisms(), vec!["PLAIN".to_string()]);
    }

    #[tokio::test]
    async fn root_dse_attributes_include_capabilities_and_context_csn() {
        let backend = MockBackend::new();
        backend
            .set_context_csn(Csn::with_values(1696680896789012, 1, 1, 0))
            .await
            .unwrap();

        let attributes = build_root_dse_attributes(
            &backend,
            &["dc=example,dc=org".to_string()],
            "cn=Subschema",
            false,
            true,
            &["1.2.840.113556.1.4.319".to_string()],
            &supported_sasl_mechanisms(),
        )
        .await
        .unwrap();

        let as_map = attributes
            .into_iter()
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(
            as_map.get("supportedLDAPVersion").unwrap(),
            &vec!["3".to_string()]
        );
        assert_eq!(
            as_map.get("namingContexts").unwrap(),
            &vec!["dc=example,dc=org".to_string()]
        );
        assert_eq!(
            as_map.get("subschemaSubentry").unwrap(),
            &vec!["cn=Subschema".to_string()]
        );
        assert_eq!(
            as_map.get("supportedControl").unwrap(),
            &vec!["1.2.840.113556.1.4.319".to_string()]
        );
        assert_eq!(
            as_map.get("supportedSASLMechanisms").unwrap(),
            &vec!["PLAIN".to_string()]
        );
        assert_eq!(
            as_map.get("contextCSN").unwrap(),
            &vec!["1696680896789012#001#000001#000000".to_string()]
        );
        assert!(
            as_map
                .get("supportedExtension")
                .unwrap()
                .contains(&START_TLS_OID.to_string())
        );
    }

    #[tokio::test]
    async fn root_dse_attributes_omit_starttls_when_secure() {
        let backend = MockBackend::new();
        let attributes =
            build_root_dse_attributes(&backend, &[], "cn=Subschema", true, true, &[], &[])
                .await
                .unwrap();

        let as_map = attributes
            .into_iter()
            .collect::<std::collections::HashMap<_, _>>();
        let supported_extensions = as_map.get("supportedExtension").unwrap();
        assert!(!supported_extensions.contains(&START_TLS_OID.to_string()));
        assert!(supported_extensions.contains(&CANCEL_OID.to_string()));
        assert!(supported_extensions.contains(&PASSWORD_MODIFY_OID.to_string()));
        assert!(supported_extensions.contains(&WHO_AM_I_OID.to_string()));
        assert_eq!(
            as_map.get("supportedLDAPVersion").unwrap(),
            &vec!["3".to_string()]
        );
        assert_eq!(
            as_map.get("subschemaSubentry").unwrap(),
            &vec!["cn=Subschema".to_string()]
        );
    }

    #[test]
    fn subschema_attributes_include_schema_descriptions() {
        let schema = LdapSchema::with_core_schema();
        let attributes = build_subschema_attributes(&schema);
        let as_map = attributes
            .into_iter()
            .collect::<std::collections::HashMap<_, _>>();

        assert_eq!(
            as_map.get("objectClass").unwrap(),
            &vec![
                "top".to_string(),
                "subentry".to_string(),
                "subschema".to_string()
            ]
        );
        assert_eq!(as_map.get("cn").unwrap(), &vec!["Subschema".to_string()]);
        assert!(as_map.contains_key("attributeTypes"));
        assert!(as_map.contains_key("objectClasses"));
    }
}

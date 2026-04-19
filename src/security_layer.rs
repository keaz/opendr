use std::collections::HashMap;

use x509_parser::prelude::parse_x509_certificate;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveSecurityContext {
    confidential_transport: bool,
    client_certificate_authz_dn: Option<String>,
}

impl EffectiveSecurityContext {
    pub fn new(confidential_transport: bool, client_certificate_authz_dn: Option<String>) -> Self {
        Self {
            confidential_transport,
            client_certificate_authz_dn,
        }
    }

    pub fn confidential_transport(&self) -> bool {
        self.confidential_transport
    }

    pub fn client_certificate_authz_dn(&self) -> Option<&str> {
        self.client_certificate_authz_dn.as_deref()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SaslMechanismPolicy {
    pub allow_plain: bool,
    pub allow_external: bool,
}

impl Default for SaslMechanismPolicy {
    fn default() -> Self {
        Self {
            allow_plain: true,
            allow_external: true,
        }
    }
}

pub fn supported_sasl_mechanisms(
    context: &EffectiveSecurityContext,
    policy: SaslMechanismPolicy,
) -> Vec<String> {
    let mut mechanisms = Vec::new();

    if context.confidential_transport() && policy.allow_plain {
        mechanisms.push("PLAIN".to_string());
    }

    if context.confidential_transport()
        && context.client_certificate_authz_dn().is_some()
        && policy.allow_external
    {
        mechanisms.push("EXTERNAL".to_string());
    }

    mechanisms
}

pub fn client_certificate_subject_common_name(cert_der: &[u8]) -> Option<String> {
    let (_, cert) = parse_x509_certificate(cert_der).ok()?;
    cert.subject()
        .iter_common_name()
        .find_map(|cn| cn.as_str().ok().map(str::to_owned))
}

pub fn map_client_certificate_common_name_to_authz_dn(
    subject_cn: &str,
    configured_map: &HashMap<String, String>,
) -> Option<String> {
    if let Some((_, mapped_dn)) = configured_map
        .iter()
        .find(|(certificate_cn, _)| certificate_cn.eq_ignore_ascii_case(subject_cn))
    {
        return crate::dn::canonicalize_dn(mapped_dn).ok();
    }

    crate::dn::canonicalize_dn(subject_cn).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};

    #[test]
    fn supported_sasl_mechanisms_follow_effective_security_context() {
        let policy = SaslMechanismPolicy::default();

        assert!(
            supported_sasl_mechanisms(&EffectiveSecurityContext::new(false, None), policy)
                .is_empty()
        );
        assert_eq!(
            supported_sasl_mechanisms(&EffectiveSecurityContext::new(true, None), policy),
            vec!["PLAIN".to_string()]
        );
        assert_eq!(
            supported_sasl_mechanisms(
                &EffectiveSecurityContext::new(
                    true,
                    Some("cn=admin,dc=example,dc=org".to_string())
                ),
                policy
            ),
            vec!["PLAIN".to_string(), "EXTERNAL".to_string()]
        );
        assert_eq!(
            supported_sasl_mechanisms(
                &EffectiveSecurityContext::new(
                    true,
                    Some("cn=admin,dc=example,dc=org".to_string())
                ),
                SaslMechanismPolicy {
                    allow_plain: true,
                    allow_external: false,
                }
            ),
            vec!["PLAIN".to_string()]
        );
    }

    #[test]
    fn client_certificate_common_name_maps_to_configured_or_dn_identity() {
        let mut configured = HashMap::new();
        configured.insert(
            "opendr-client".to_string(),
            "CN=admin,DC=example,DC=org".to_string(),
        );

        assert_eq!(
            map_client_certificate_common_name_to_authz_dn("OpenDR-Client", &configured),
            Some("cn=admin,dc=example,dc=org".to_string())
        );
        assert_eq!(
            map_client_certificate_common_name_to_authz_dn(
                "CN=ops,DC=example,DC=org",
                &HashMap::new()
            ),
            Some("cn=ops,dc=example,dc=org".to_string())
        );
        assert_eq!(
            map_client_certificate_common_name_to_authz_dn("unmapped-client", &HashMap::new()),
            None
        );
    }

    #[test]
    fn client_certificate_subject_common_name_is_extracted_from_der() {
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "opendr-client");
        let key_pair = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();

        assert_eq!(
            client_certificate_subject_common_name(cert.der().as_ref()),
            Some("opendr-client".to_string())
        );
    }
}

use std::collections::{BTreeMap, BTreeSet};

use ldap_parser::ldap::Control as ParsedControl;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapControl {
    oid: String,
    criticality: bool,
    value: Option<Vec<u8>>,
}

impl LdapControl {
    pub fn new(oid: impl Into<String>, criticality: bool, value: Option<Vec<u8>>) -> Self {
        Self {
            oid: oid.into(),
            criticality,
            value,
        }
    }

    pub fn oid(&self) -> &str {
        &self.oid
    }

    pub fn criticality(&self) -> bool {
        self.criticality
    }

    pub fn value(&self) -> Option<&[u8]> {
        self.value.as_deref()
    }
}

impl<'a> From<&ParsedControl<'a>> for LdapControl {
    fn from(control: &ParsedControl<'a>) -> Self {
        Self::new(
            control.control_type.0.as_ref(),
            control.criticality,
            control.control_value.as_ref().map(|value| value.to_vec()),
        )
    }
}

impl From<LdapControl> for rasn_ldap::Control {
    fn from(control: LdapControl) -> Self {
        rasn_ldap::Control::new(
            control.oid.into_bytes().into(),
            control.criticality,
            control.value.map(Into::into),
        )
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestControls {
    controls: Vec<LdapControl>,
}

impl RequestControls {
    pub fn new(controls: Vec<LdapControl>) -> Self {
        Self { controls }
    }

    pub fn is_empty(&self) -> bool {
        self.controls.is_empty()
    }

    pub fn len(&self) -> usize {
        self.controls.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &LdapControl> {
        self.controls.iter()
    }

    pub fn as_slice(&self) -> &[LdapControl] {
        &self.controls
    }

    pub fn singleton(&self, oid: &str) -> Result<Option<&LdapControl>, ControlLookupError> {
        let mut matching = self
            .controls
            .iter()
            .filter(|control| control.oid.eq_ignore_ascii_case(oid));

        let first = matching.next();
        let duplicate_count = first.is_some() as usize + matching.count();
        if duplicate_count > 1 {
            return Err(ControlLookupError::DuplicateControl {
                oid: oid.to_string(),
                count: duplicate_count,
            });
        }

        Ok(first)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlLookupError {
    DuplicateControl { oid: String, count: usize },
}

impl std::fmt::Display for ControlLookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateControl { oid, count } => {
                write!(f, "control {} was provided {} times", oid, count)
            }
        }
    }
}

impl std::error::Error for ControlLookupError {}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValidatedRequestControls {
    accepted: RequestControls,
    ignored: Vec<LdapControl>,
}

impl ValidatedRequestControls {
    pub fn accepted(&self) -> &RequestControls {
        &self.accepted
    }

    pub fn into_accepted(self) -> RequestControls {
        self.accepted
    }

    pub fn ignored(&self) -> &[LdapControl] {
        &self.ignored
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlValidationError {
    UnknownCritical { oid: String },
}

impl std::fmt::Display for ControlValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownCritical { oid } => {
                write!(f, "unknown critical control {}", oid)
            }
        }
    }
}

impl std::error::Error for ControlValidationError {}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RegisteredControl {
    oid: String,
}

#[derive(Debug, Clone, Default)]
pub struct ControlRegistry {
    request_controls: BTreeMap<String, RegisteredControl>,
    response_controls: BTreeMap<String, RegisteredControl>,
}

impl ControlRegistry {
    pub fn register_request_control(&mut self, oid: impl Into<String>) -> &mut Self {
        let oid = oid.into();
        self.request_controls
            .insert(oid.clone(), RegisteredControl { oid });
        self
    }

    pub fn register_response_control(&mut self, oid: impl Into<String>) -> &mut Self {
        let oid = oid.into();
        self.response_controls
            .insert(oid.clone(), RegisteredControl { oid });
        self
    }

    pub fn supports_request_control(&self, oid: &str) -> bool {
        self.request_controls.contains_key(oid)
    }

    pub fn supported_control_oids(&self) -> Vec<String> {
        let mut oids = BTreeSet::new();
        oids.extend(
            self.request_controls
                .values()
                .map(|control| control.oid.clone()),
        );
        oids.extend(
            self.response_controls
                .values()
                .map(|control| control.oid.clone()),
        );
        oids.into_iter().collect()
    }

    pub fn validate_request_controls<'a>(
        &self,
        controls: Option<&[ParsedControl<'a>]>,
    ) -> Result<ValidatedRequestControls, ControlValidationError> {
        let Some(controls) = controls else {
            return Ok(ValidatedRequestControls::default());
        };

        let mut accepted = Vec::with_capacity(controls.len());
        let mut ignored = Vec::new();

        for control in controls {
            let control = LdapControl::from(control);
            if self.supports_request_control(control.oid()) {
                accepted.push(control);
            } else if control.criticality() {
                return Err(ControlValidationError::UnknownCritical {
                    oid: control.oid().to_string(),
                });
            } else {
                ignored.push(control);
            }
        }

        Ok(ValidatedRequestControls {
            accepted: RequestControls::new(accepted),
            ignored,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ldap_parser::ldap::LdapOID;
    use std::borrow::Cow;

    fn parsed_control(
        oid: &'static str,
        criticality: bool,
        value: Option<&'static [u8]>,
    ) -> ParsedControl<'static> {
        ParsedControl {
            control_type: LdapOID(Cow::Borrowed(oid)),
            criticality,
            control_value: value.map(Cow::Borrowed),
        }
    }

    #[test]
    fn rejects_unknown_critical_controls() {
        let registry = ControlRegistry::default();
        let controls = [parsed_control("1.2.3", true, None)];

        let err = registry
            .validate_request_controls(Some(&controls))
            .unwrap_err();

        assert_eq!(
            err,
            ControlValidationError::UnknownCritical {
                oid: "1.2.3".to_string(),
            }
        );
    }

    #[test]
    fn ignores_unknown_non_critical_controls() {
        let registry = ControlRegistry::default();
        let controls = [parsed_control("1.2.3", false, Some(b"abc"))];

        let result = registry.validate_request_controls(Some(&controls)).unwrap();

        assert!(result.accepted().is_empty());
        assert_eq!(result.ignored().len(), 1);
        assert_eq!(result.ignored()[0].oid(), "1.2.3");
        assert_eq!(result.ignored()[0].value(), Some(&b"abc"[..]));
    }

    #[test]
    fn singleton_lookup_rejects_duplicate_controls() {
        let controls = RequestControls::new(vec![
            LdapControl::new("1.2.3", false, None),
            LdapControl::new("1.2.3", false, Some(vec![1])),
        ]);

        let err = controls.singleton("1.2.3").unwrap_err();

        assert_eq!(
            err,
            ControlLookupError::DuplicateControl {
                oid: "1.2.3".to_string(),
                count: 2,
            }
        );
    }

    #[test]
    fn supported_control_oids_merge_request_and_response_registrations() {
        let mut registry = ControlRegistry::default();
        registry
            .register_request_control("1.2.3")
            .register_response_control("1.2.4")
            .register_response_control("1.2.3");

        assert_eq!(
            registry.supported_control_oids(),
            vec!["1.2.3".to_string(), "1.2.4".to_string()]
        );
    }
}

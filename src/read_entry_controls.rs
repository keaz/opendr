use std::fmt;

use rasn::error::EncodeError;

use crate::backend::{DirectoryEntry, OperationalAttributes};
use crate::ldap_controls::{ControlLookupError, LdapControl, RequestControls};
use crate::parser::encode_search_result_entry_value;

pub const PRE_READ_CONTROL_OID: &str = "1.3.6.1.1.13.1";
pub const POST_READ_CONTROL_OID: &str = "1.3.6.1.1.13.2";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadEntryRequest {
    attributes: Vec<String>,
    critical: bool,
}

impl ReadEntryRequest {
    pub fn attributes(&self) -> &[String] {
        &self.attributes
    }

    pub fn critical(&self) -> bool {
        self.critical
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadEntryControlError {
    DuplicateControl(String),
    MissingValue { oid: &'static str },
    InvalidValue { oid: &'static str, message: String },
}

impl fmt::Display for ReadEntryControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateControl(message) => f.write_str(message),
            Self::MissingValue { oid } => {
                write!(f, "read entry control {oid} requires a controlValue")
            }
            Self::InvalidValue { oid, message } => {
                write!(f, "malformed read entry control {oid}: {message}")
            }
        }
    }
}

impl std::error::Error for ReadEntryControlError {}

impl From<ControlLookupError> for ReadEntryControlError {
    fn from(error: ControlLookupError) -> Self {
        Self::DuplicateControl(error.to_string())
    }
}

pub fn decode_pre_read_request_control(
    request_controls: &RequestControls,
) -> Result<Option<ReadEntryRequest>, ReadEntryControlError> {
    decode_read_entry_request_control(request_controls, PRE_READ_CONTROL_OID)
}

pub fn decode_post_read_request_control(
    request_controls: &RequestControls,
) -> Result<Option<ReadEntryRequest>, ReadEntryControlError> {
    decode_read_entry_request_control(request_controls, POST_READ_CONTROL_OID)
}

fn decode_read_entry_request_control(
    request_controls: &RequestControls,
    oid: &'static str,
) -> Result<Option<ReadEntryRequest>, ReadEntryControlError> {
    let Some(control) = request_controls.singleton(oid)? else {
        return Ok(None);
    };

    let attributes = decode_attribute_selection(control.value(), oid)?;
    Ok(Some(ReadEntryRequest {
        attributes,
        critical: control.criticality(),
    }))
}

pub fn encode_attribute_selection(attributes: &[String]) -> Result<Vec<u8>, EncodeError> {
    let selection: rasn_ldap::AttributeSelection = attributes
        .iter()
        .map(|attribute| attribute.as_bytes().to_vec().into())
        .collect();
    rasn::ber::encode(&selection)
}

pub(crate) fn pre_read_response_control(
    entry: &DirectoryEntry,
    attributes: &[String],
) -> Result<LdapControl, EncodeError> {
    read_entry_response_control(PRE_READ_CONTROL_OID, entry, attributes)
}

pub(crate) fn post_read_response_control(
    entry: &DirectoryEntry,
    attributes: &[String],
) -> Result<LdapControl, EncodeError> {
    read_entry_response_control(POST_READ_CONTROL_OID, entry, attributes)
}

fn read_entry_response_control(
    oid: &'static str,
    entry: &DirectoryEntry,
    attributes: &[String],
) -> Result<LdapControl, EncodeError> {
    let selected = select_entry_attributes(entry, attributes);
    let value = encode_search_result_entry_value(&entry.dn, &selected, false)?;
    Ok(LdapControl::new(oid, false, Some(value)))
}

pub(crate) fn contains_critical_pre_read_control(request_controls: &RequestControls) -> bool {
    contains_critical_read_entry_control(request_controls, PRE_READ_CONTROL_OID)
}

pub(crate) fn contains_critical_post_read_control(request_controls: &RequestControls) -> bool {
    contains_critical_read_entry_control(request_controls, POST_READ_CONTROL_OID)
}

fn contains_critical_read_entry_control(
    request_controls: &RequestControls,
    oid: &'static str,
) -> bool {
    request_controls
        .iter()
        .any(|control| control.oid().eq_ignore_ascii_case(oid) && control.criticality())
}

pub(crate) fn select_entry_attributes(
    entry: &DirectoryEntry,
    requested: &[String],
) -> Vec<(String, Vec<String>)> {
    if requested
        .iter()
        .any(|attribute| attribute.eq_ignore_ascii_case("1.1"))
    {
        return Vec::new();
    }

    let include_all = requested.is_empty() || requested.iter().any(|attr| attr == "*");
    let include_all_operational = requested.iter().any(|attr| attr == "+");

    let mut selected = Vec::new();

    for (name, values) in &entry.attributes {
        if OperationalAttributes::is_operational(name) {
            continue;
        }
        if include_all
            || requested
                .iter()
                .any(|attribute| attribute.eq_ignore_ascii_case(name))
        {
            selected.push((
                crate::operational_attrs::response_user_attribute_name(name, requested),
                values.clone(),
            ));
        }
    }

    if include_all_operational
        || requested
            .iter()
            .any(|attr| OperationalAttributes::is_operational(attr))
    {
        let mut operational = entry.response_operational_attributes();
        for (name, values) in &entry.attributes {
            if OperationalAttributes::is_operational(name) {
                operational.insert(name.clone(), values.clone());
            }
        }
        operational.insert("entryDN".to_string(), vec![entry.dn.clone()]);

        for (name, values) in operational {
            if include_all_operational
                || requested
                    .iter()
                    .any(|attribute| attribute.eq_ignore_ascii_case(&name))
            {
                selected.push((name, values));
            }
        }
    }

    selected
}

fn decode_attribute_selection(
    value: Option<&[u8]>,
    oid: &'static str,
) -> Result<Vec<String>, ReadEntryControlError> {
    let value = value.ok_or(ReadEntryControlError::MissingValue { oid })?;
    let selection: rasn_ldap::AttributeSelection =
        rasn::ber::decode(value).map_err(|err| ReadEntryControlError::InvalidValue {
            oid,
            message: err.to_string(),
        })?;
    selection
        .into_iter()
        .map(|attribute| {
            String::from_utf8(attribute.to_vec()).map_err(|err| {
                ReadEntryControlError::InvalidValue {
                    oid,
                    message: format!("AttributeSelection contains invalid UTF-8: {err}"),
                }
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn pre_read_attribute_selection_round_trips() {
        let encoded =
            encode_attribute_selection(&["cn".to_string(), "+".to_string(), "1.1".to_string()])
                .unwrap();
        let controls = RequestControls::new(vec![LdapControl::new(
            PRE_READ_CONTROL_OID,
            true,
            Some(encoded),
        )]);

        let decoded = decode_pre_read_request_control(&controls).unwrap().unwrap();

        assert!(decoded.critical());
        assert_eq!(decoded.attributes(), &["cn", "+", "1.1"]);
    }

    #[test]
    fn pre_read_control_requires_value() {
        let controls =
            RequestControls::new(vec![LdapControl::new(PRE_READ_CONTROL_OID, false, None)]);

        assert!(matches!(
            decode_pre_read_request_control(&controls),
            Err(ReadEntryControlError::MissingValue {
                oid: PRE_READ_CONTROL_OID
            })
        ));
    }

    #[test]
    fn post_read_attribute_selection_round_trips() {
        let encoded = encode_attribute_selection(&["cn".to_string(), "entryDN".to_string()])
            .expect("attribute selection should encode");
        let controls = RequestControls::new(vec![LdapControl::new(
            POST_READ_CONTROL_OID,
            false,
            Some(encoded),
        )]);

        let decoded = decode_post_read_request_control(&controls)
            .unwrap()
            .unwrap();

        assert!(!decoded.critical());
        assert_eq!(decoded.attributes(), &["cn", "entryDN"]);
    }

    #[test]
    fn post_read_control_requires_value() {
        let controls =
            RequestControls::new(vec![LdapControl::new(POST_READ_CONTROL_OID, false, None)]);

        assert!(matches!(
            decode_post_read_request_control(&controls),
            Err(ReadEntryControlError::MissingValue {
                oid: POST_READ_CONTROL_OID
            })
        ));
    }

    #[test]
    fn post_read_response_control_uses_post_read_oid() {
        let entry = DirectoryEntry::new(
            "cn=Alice,dc=example,dc=org",
            HashMap::from([
                ("cn".to_string(), vec!["Alice".to_string()]),
                ("sn".to_string(), vec!["User".to_string()]),
                ("objectclass".to_string(), vec!["person".to_string()]),
            ]),
        );

        let control = post_read_response_control(&entry, &["cn".to_string()]).unwrap();

        assert_eq!(control.oid(), POST_READ_CONTROL_OID);
        assert!(!control.criticality());
        assert!(control.value().is_some());
    }

    #[test]
    fn read_entry_attribute_selection_matches_search_projection() {
        let entry = DirectoryEntry::new(
            "cn=Alice,dc=example,dc=org",
            HashMap::from([
                ("cn".to_string(), vec!["Alice".to_string()]),
                ("sn".to_string(), vec!["User".to_string()]),
                ("objectclass".to_string(), vec!["person".to_string()]),
            ]),
        );

        assert_eq!(
            select_entry_attributes(&entry, &["sn".to_string()]),
            vec![("sn".to_string(), vec!["User".to_string()])]
        );
        assert!(select_entry_attributes(&entry, &["1.1".to_string()]).is_empty());
    }
}

use rasn::error::EncodeError;
use rasn::types::{OctetString, SetOf};
use rasn::{AsnType, Decode, Encode};
use rasn::{ber, der};
use rasn_ldap::{ResultCode, SearchResultEntry};

use crate::backend::DirectoryEntry;
use crate::ldap_controls::LdapControl;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseOp {
    SearchDone,
    Modify,
    Add,
    Delete,
    ModifyDn,
    Compare,
    Extended,
}

#[derive(AsnType, Encode, Decode, Debug, Clone, Copy, PartialEq, Eq)]
#[rasn(enumerated)]
pub enum CustomResultCode {
    Success = 0,
    ProtocolError = 2,
    Busy = 51,
    Unavailable = 52,
    UnwillingToPerform = 53,
    Other = 80,
    Canceled = 118,
    NoSuchOperation = 119,
    TooLate = 120,
    CannotCancel = 121,
}

#[derive(AsnType, Encode, Decode)]
struct CustomLdapResult {
    result_code: CustomResultCode,
    matched_dn: OctetString,
    diagnostic_message: OctetString,
}

#[derive(AsnType, Encode, Decode)]
#[rasn(choice)]
enum CustomProtocolOp {
    #[rasn(tag(application, 5))]
    SearchResultDone(CustomLdapResult),
    #[rasn(tag(application, 24))]
    ExtendedResponse(CustomLdapResult),
}

#[derive(AsnType, Encode, Decode)]
struct CustomLdapMessage {
    message_id: i32,
    protocol_op: CustomProtocolOp,
}

pub fn encode_bind_response(
    message_id: u32,
    result_code: ResultCode,
    matched_dn: impl Into<String>,
    diagnostic_message: impl Into<String>,
) -> Result<Vec<u8>, EncodeError> {
    let bind_response = rasn_ldap::BindResponse::new(
        result_code,
        matched_dn.into().into_bytes().into(),
        diagnostic_message.into().into_bytes().into(),
        None,
        None,
    );

    encode_message(
        message_id,
        rasn_ldap::ProtocolOp::BindResponse(bind_response),
        &[],
    )
}

pub fn encode_result_response(
    message_id: u32,
    op: ResponseOp,
    result_code: ResultCode,
    matched_dn: impl Into<String>,
    diagnostic_message: impl Into<String>,
) -> Result<Vec<u8>, EncodeError> {
    encode_result_response_with_controls(
        message_id,
        op,
        result_code,
        matched_dn,
        diagnostic_message,
        &[],
    )
}

pub fn encode_result_response_with_controls(
    message_id: u32,
    op: ResponseOp,
    result_code: ResultCode,
    matched_dn: impl Into<String>,
    diagnostic_message: impl Into<String>,
    controls: &[LdapControl],
) -> Result<Vec<u8>, EncodeError> {
    let matched_dn = matched_dn.into();
    let diagnostic = diagnostic_message.into();
    let matched_dn_bytes = matched_dn.as_bytes().to_vec();
    let diagnostic_bytes = diagnostic.as_bytes().to_vec();
    let result = rasn_ldap::LdapResult::new(
        result_code,
        matched_dn_bytes.clone().into(),
        diagnostic_bytes.clone().into(),
    );

    let protocol_op = match op {
        ResponseOp::SearchDone => {
            rasn_ldap::ProtocolOp::SearchResDone(rasn_ldap::SearchResultDone(result))
        }
        ResponseOp::Modify => {
            rasn_ldap::ProtocolOp::ModifyResponse(rasn_ldap::ModifyResponse(result))
        }
        ResponseOp::Add => rasn_ldap::ProtocolOp::AddResponse(rasn_ldap::AddResponse(result)),
        ResponseOp::Delete => rasn_ldap::ProtocolOp::DelResponse(rasn_ldap::DelResponse(result)),
        ResponseOp::ModifyDn => {
            rasn_ldap::ProtocolOp::ModDnResponse(rasn_ldap::ModifyDnResponse(result))
        }
        ResponseOp::Compare => {
            rasn_ldap::ProtocolOp::CompareResponse(rasn_ldap::CompareResponse(result))
        }
        ResponseOp::Extended => {
            let response = rasn_ldap::ExtendedResponse {
                result_code,
                matched_dn: matched_dn_bytes.into(),
                diagnostic_message: diagnostic_bytes.into(),
                referral: None,
                response_name: None,
                response_value: None,
            };
            rasn_ldap::ProtocolOp::ExtendedResp(response)
        }
    };

    encode_message(message_id, protocol_op, controls)
}

pub fn encode_result_response_with_referrals(
    message_id: u32,
    op: ResponseOp,
    result_code: ResultCode,
    matched_dn: impl Into<String>,
    diagnostic_message: impl Into<String>,
    referrals: &[String],
    controls: &[LdapControl],
) -> Result<Vec<u8>, EncodeError> {
    let matched_dn_bytes = matched_dn.into().into_bytes();
    let diagnostic_bytes = diagnostic_message.into().into_bytes();
    let referral_values = (!referrals.is_empty()).then(|| {
        referrals
            .iter()
            .map(|referral| referral.as_bytes().to_vec().into())
            .collect()
    });

    let protocol_op = match op {
        ResponseOp::Extended => {
            let response = rasn_ldap::ExtendedResponse {
                result_code,
                matched_dn: matched_dn_bytes.into(),
                diagnostic_message: diagnostic_bytes.into(),
                referral: referral_values,
                response_name: None,
                response_value: None,
            };
            rasn_ldap::ProtocolOp::ExtendedResp(response)
        }
        _ => {
            let mut result = rasn_ldap::LdapResult::new(
                result_code,
                matched_dn_bytes.into(),
                diagnostic_bytes.into(),
            );
            result.referral = referral_values;
            match op {
                ResponseOp::SearchDone => {
                    rasn_ldap::ProtocolOp::SearchResDone(rasn_ldap::SearchResultDone(result))
                }
                ResponseOp::Modify => {
                    rasn_ldap::ProtocolOp::ModifyResponse(rasn_ldap::ModifyResponse(result))
                }
                ResponseOp::Add => {
                    rasn_ldap::ProtocolOp::AddResponse(rasn_ldap::AddResponse(result))
                }
                ResponseOp::Delete => {
                    rasn_ldap::ProtocolOp::DelResponse(rasn_ldap::DelResponse(result))
                }
                ResponseOp::ModifyDn => {
                    rasn_ldap::ProtocolOp::ModDnResponse(rasn_ldap::ModifyDnResponse(result))
                }
                ResponseOp::Compare => {
                    rasn_ldap::ProtocolOp::CompareResponse(rasn_ldap::CompareResponse(result))
                }
                ResponseOp::Extended => unreachable!("extended responses handled above"),
            }
        }
    };

    encode_message(message_id, protocol_op, controls)
}

pub fn encode_extended_response(
    message_id: u32,
    result_code: ResultCode,
    matched_dn: impl Into<String>,
    diagnostic_message: impl Into<String>,
    response_name: Option<String>,
    response_value: Option<Vec<u8>>,
) -> Result<Vec<u8>, EncodeError> {
    encode_extended_response_with_controls(
        message_id,
        result_code,
        matched_dn,
        diagnostic_message,
        response_name,
        response_value,
        &[],
    )
}

pub fn encode_extended_response_with_controls(
    message_id: u32,
    result_code: ResultCode,
    matched_dn: impl Into<String>,
    diagnostic_message: impl Into<String>,
    response_name: Option<String>,
    response_value: Option<Vec<u8>>,
    controls: &[LdapControl],
) -> Result<Vec<u8>, EncodeError> {
    let matched_dn = matched_dn.into();
    let diagnostic = diagnostic_message.into();
    let response = rasn_ldap::ExtendedResponse {
        result_code,
        matched_dn: matched_dn.into_bytes().into(),
        diagnostic_message: diagnostic.into_bytes().into(),
        referral: None,
        response_name: response_name.map(|name| name.into_bytes().into()),
        response_value: response_value.map(|value| value.into()),
    };

    encode_message(
        message_id,
        rasn_ldap::ProtocolOp::ExtendedResp(response),
        controls,
    )
}

pub fn encode_search_entry(
    message_id: u32,
    entry: &DirectoryEntry,
    attributes: &[(String, Vec<String>)],
    types_only: bool,
) -> Result<Vec<u8>, EncodeError> {
    encode_search_entry_with_controls(message_id, entry, attributes, types_only, &[])
}

pub fn encode_search_entry_with_controls(
    message_id: u32,
    entry: &DirectoryEntry,
    attributes: &[(String, Vec<String>)],
    types_only: bool,
    controls: &[LdapControl],
) -> Result<Vec<u8>, EncodeError> {
    encode_search_entry_parts_with_controls(message_id, &entry.dn, attributes, types_only, controls)
}

pub fn encode_search_entry_parts_with_controls(
    message_id: u32,
    dn: &str,
    attributes: &[(String, Vec<String>)],
    types_only: bool,
    controls: &[LdapControl],
) -> Result<Vec<u8>, EncodeError> {
    let search_entry = search_result_entry(dn, attributes, types_only);

    encode_message(
        message_id,
        rasn_ldap::ProtocolOp::SearchResEntry(search_entry),
        controls,
    )
}

pub fn encode_search_result_entry_value(
    dn: &str,
    attributes: &[(String, Vec<String>)],
    types_only: bool,
) -> Result<Vec<u8>, EncodeError> {
    ber::encode(&search_result_entry(dn, attributes, types_only))
}

fn search_result_entry(
    dn: &str,
    attributes: &[(String, Vec<String>)],
    types_only: bool,
) -> SearchResultEntry {
    let partial_attributes: Vec<rasn_ldap::PartialAttribute> = attributes
        .iter()
        .map(|(name, values)| {
            let vals: SetOf<rasn_ldap::AttributeValue> = if types_only {
                SetOf::default()
            } else {
                values
                    .iter()
                    .map(|value| value.as_bytes().to_vec().into())
                    .collect()
            };
            rasn_ldap::PartialAttribute::new(name.as_bytes().to_vec().into(), vals)
        })
        .collect();

    let attributes: rasn_ldap::PartialAttributeList = partial_attributes.into_iter().collect();

    SearchResultEntry::new(dn.as_bytes().to_vec().into(), attributes)
}

pub fn encode_search_reference_with_controls(
    message_id: u32,
    uris: &[String],
    controls: &[LdapControl],
) -> Result<Vec<u8>, EncodeError> {
    let references = uris
        .iter()
        .map(|uri| uri.as_bytes().to_vec().into())
        .collect();

    encode_message(
        message_id,
        rasn_ldap::ProtocolOp::SearchResRef(rasn_ldap::SearchResultReference(references)),
        controls,
    )
}

pub fn encode_intermediate_response(
    message_id: u32,
    response_name: Option<String>,
    response_value: Option<Vec<u8>>,
    controls: &[LdapControl],
) -> Result<Vec<u8>, EncodeError> {
    let response = rasn_ldap::IntermediateResponse {
        response_name: response_name.map(|name| name.into_bytes().into()),
        response_value: response_value.map(Into::into),
    };

    encode_message(
        message_id,
        rasn_ldap::ProtocolOp::IntermediateResponse(response),
        controls,
    )
}

pub fn encode_custom_search_result_done(
    message_id: u32,
    result_code: CustomResultCode,
    matched_dn: impl Into<String>,
    diagnostic_message: impl Into<String>,
) -> Result<Vec<u8>, EncodeError> {
    let result = CustomLdapResult {
        result_code,
        matched_dn: matched_dn.into().into_bytes().into(),
        diagnostic_message: diagnostic_message.into().into_bytes().into(),
    };
    der::encode(&CustomLdapMessage {
        message_id: message_id as i32,
        protocol_op: CustomProtocolOp::SearchResultDone(result),
    })
}

pub fn encode_custom_extended_response(
    message_id: u32,
    result_code: CustomResultCode,
    matched_dn: impl Into<String>,
    diagnostic_message: impl Into<String>,
) -> Result<Vec<u8>, EncodeError> {
    let result = CustomLdapResult {
        result_code,
        matched_dn: matched_dn.into().into_bytes().into(),
        diagnostic_message: diagnostic_message.into().into_bytes().into(),
    };
    der::encode(&CustomLdapMessage {
        message_id: message_id as i32,
        protocol_op: CustomProtocolOp::ExtendedResponse(result),
    })
}

fn encode_message(
    message_id: u32,
    protocol_op: rasn_ldap::ProtocolOp,
    controls: &[LdapControl],
) -> Result<Vec<u8>, EncodeError> {
    let mut message = rasn_ldap::LdapMessage::new(message_id, protocol_op);
    if !controls.is_empty() {
        message.controls = Some(
            controls
                .iter()
                .cloned()
                .map(rasn_ldap::Control::from)
                .collect(),
        );
    }
    der::encode(&message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ldap_controls::LdapControl;
    use ldap_parser::ldap::{ProtocolOp as ParserProtocolOp, ResultCode as ParserResultCode};
    use ldap_parser::parse_ldap_messages;
    use std::collections::HashMap;

    #[test]
    fn encode_result_response_round_trips_response_controls() {
        let control = LdapControl::new("1.2.3", false, Some(b"ok".to_vec()));

        let encoded = encode_result_response_with_controls(
            7,
            ResponseOp::SearchDone,
            ResultCode::Success,
            "",
            "",
            &[control],
        )
        .unwrap();

        let (_, messages) = parse_ldap_messages(&encoded).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].controls.as_ref().unwrap().len(), 1);
        assert_eq!(
            messages[0].controls.as_ref().unwrap()[0]
                .control_type
                .0
                .as_ref(),
            "1.2.3"
        );
        assert_eq!(
            messages[0].controls.as_ref().unwrap()[0]
                .control_value
                .as_ref()
                .unwrap()
                .as_ref(),
            b"ok"
        );
    }

    #[test]
    fn encode_search_entry_round_trips_response_controls() {
        let entry = DirectoryEntry::new(
            "cn=alice,dc=example,dc=org",
            HashMap::from([("cn".to_string(), vec!["alice".to_string()])]),
        );
        let control = LdapControl::new("1.2.840.113556.1.4.319", false, Some(vec![1, 2, 3]));

        let encoded = encode_search_entry_with_controls(
            8,
            &entry,
            &[("cn".to_string(), vec!["alice".to_string()])],
            false,
            &[control],
        )
        .unwrap();

        let (_, messages) = parse_ldap_messages(&encoded).unwrap();
        assert_eq!(messages.len(), 1);
        assert!(matches!(
            messages[0].protocol_op,
            ParserProtocolOp::SearchResultEntry(_)
        ));
        assert_eq!(messages[0].controls.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn encode_intermediate_response_round_trips_response_controls() {
        let control = LdapControl::new("1.2.3.4", true, None);

        let encoded = encode_intermediate_response(
            9,
            Some("1.3.6.1.4.1.example".to_string()),
            Some(b"payload".to_vec()),
            &[control],
        )
        .unwrap();

        let (_, messages) = parse_ldap_messages(&encoded).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].controls.as_ref().unwrap().len(), 1);
        assert!(matches!(
            messages[0].protocol_op,
            ParserProtocolOp::IntermediateResponse(_)
        ));
    }

    #[test]
    fn encode_custom_extended_response_supports_cancel_result_codes() {
        let encoded = encode_custom_extended_response(
            41,
            CustomResultCode::NoSuchOperation,
            "",
            "no such operation",
        )
        .unwrap();
        let (_, messages) = parse_ldap_messages(&encoded).unwrap();

        match &messages[0].protocol_op {
            ParserProtocolOp::ExtendedResponse(response) => {
                assert_eq!(response.result.result_code, ParserResultCode(119));
                assert_eq!(
                    response.result.diagnostic_message.0.as_ref(),
                    "no such operation"
                );
            }
            other => panic!("unexpected response: {:?}", other),
        }
    }

    #[test]
    fn encode_custom_search_result_done_supports_canceled_result_code() {
        let encoded = encode_custom_search_result_done(
            42,
            CustomResultCode::Canceled,
            "",
            "operation canceled",
        )
        .unwrap();
        let (_, messages) = parse_ldap_messages(&encoded).unwrap();

        match &messages[0].protocol_op {
            ParserProtocolOp::SearchResultDone(response) => {
                assert_eq!(response.result_code, ParserResultCode(118));
                assert_eq!(response.diagnostic_message.0.as_ref(), "operation canceled");
            }
            other => panic!("unexpected response: {:?}", other),
        }
    }
}

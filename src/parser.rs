use rasn::der;
use rasn::error::EncodeError;
use rasn::types::SetOf;
use rasn_ldap::{ResultCode, SearchResultEntry};

use crate::backend::DirectoryEntry;

pub enum ResponseOp {
    SearchDone,
    Modify,
    Add,
    Delete,
    ModifyDn,
    Compare,
    Extended,
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

    let message = rasn_ldap::LdapMessage::new(
        message_id,
        rasn_ldap::ProtocolOp::BindResponse(bind_response),
    );

    der::encode(&message)
}

pub fn encode_result_response(
    message_id: u32,
    op: ResponseOp,
    result_code: ResultCode,
    matched_dn: impl Into<String>,
    diagnostic_message: impl Into<String>,
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

    let message = rasn_ldap::LdapMessage::new(message_id, protocol_op);
    der::encode(&message)
}

pub fn encode_search_entry(
    message_id: u32,
    entry: &DirectoryEntry,
    attributes: &[(String, Vec<String>)],
    types_only: bool,
) -> Result<Vec<u8>, EncodeError> {
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

    let search_entry = SearchResultEntry::new(entry.dn.as_bytes().to_vec().into(), attributes);

    let message = rasn_ldap::LdapMessage::new(
        message_id,
        rasn_ldap::ProtocolOp::SearchResEntry(search_entry),
    );

    der::encode(&message)
}

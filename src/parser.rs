use rasn::error::EncodeError;
use rasn::{der, AsnType, Decode, Encode};
use rasn_ldap::{BindResponse, ResultCode};

pub fn handle_bind_response(message_id: u32) -> Result<Vec<u8>, EncodeError> {
    let bind_response = BindResponse::new(
        ResultCode::InvalidCredentials,
        "".into(),
        "".into(),
        None,
        None,
    );

    let message = rasn_ldap::LdapMessage::new(
        message_id,
        rasn_ldap::ProtocolOp::BindResponse(bind_response),
    );

    encode_ldap_message(&message)
}

fn encode_ldap_message(message: &rasn_ldap::LdapMessage) -> Result<Vec<u8>, EncodeError> {
    let encoded = der::encode(message)?;
    Ok(encoded)
}

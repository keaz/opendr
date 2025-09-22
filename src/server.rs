use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use ldap_parser::filter::{Filter, Substring, SubstringFilter};
use ldap_parser::ldap::{
    AddRequest, AuthenticationChoice, BindRequest, Change, CompareRequest, ExtendedRequest,
    ModDnRequest, ModifyRequest, ProtocolOp, SearchRequest,
};
use ldap_parser::parse_ldap_messages;
use log::{error, info, warn};
use rasn::error::EncodeError;
use rasn_ldap::ResultCode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::backend::{
    BackendError, DirectoryBackend, DirectoryEntry, Modification, ModifyOperation,
};
use crate::parser::{
    encode_bind_response, encode_result_response, encode_search_entry, ResponseOp,
};

#[derive(Debug)]
pub enum ServerError {
    Io(std::io::Error),
    Encode(EncodeError),
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServerError::Io(err) => write!(f, "I/O error: {}", err),
            ServerError::Encode(err) => write!(f, "encoding error: {:?}", err),
        }
    }
}

impl std::error::Error for ServerError {}

impl From<std::io::Error> for ServerError {
    fn from(err: std::io::Error) -> Self {
        ServerError::Io(err)
    }
}

impl From<EncodeError> for ServerError {
    fn from(err: EncodeError) -> Self {
        ServerError::Encode(err)
    }
}

pub async fn run(addr: &str, backend: Arc<dyn DirectoryBackend>) -> Result<(), ServerError> {
    let listener = TcpListener::bind(addr).await?;
    info!("LDAP server listening on {}", addr);

    loop {
        let (socket, addr) = listener.accept().await?;
        info!("Accepted connection from {:?}", addr);

        let backend = backend.clone();

        tokio::spawn(async move {
            handle_client(socket, backend).await;
            info!("Connection {:?} closed", addr);
        });
    }
}

pub async fn handle_client(mut socket: TcpStream, backend: Arc<dyn DirectoryBackend>) {
    let mut buffer = vec![0; 4096];

    loop {
        match socket.read(&mut buffer).await {
            Ok(0) => break,
            Ok(n) => {
                let payload = &buffer[..n];
                match parse_ldap_messages(payload) {
                    Ok((_, messages)) => {
                        for message in messages {
                            if let Err(err) =
                                process_message(&mut socket, backend.as_ref(), message).await
                            {
                                error!("Failed to process message: {}", err);
                                return;
                            }
                        }
                    }
                    Err(err) => {
                        error!("Failed to parse LDAP message: {:?}", err);
                        if let Err(write_err) = send_bind_response(
                            &mut socket,
                            0,
                            ResultCode::ProtocolError,
                            "invalid message",
                        )
                        .await
                        {
                            error!("Failed to write error response: {}", write_err);
                        }
                        return;
                    }
                }
            }
            Err(err) => {
                error!("Failed to read from socket: {}", err);
                return;
            }
        }
    }
}

pub async fn process_message(
    socket: &mut TcpStream,
    backend: &dyn DirectoryBackend,
    message: ldap_parser::ldap::LdapMessage<'_>,
) -> Result<(), ServerError> {
    let message_id = message.message_id.0;

    match message.protocol_op {
        ProtocolOp::BindRequest(bind_request) => {
            handle_bind_request(socket, backend, message_id, bind_request).await?;
        }
        ProtocolOp::SearchRequest(search_request) => {
            handle_search_request(socket, backend, message_id, search_request).await?;
        }
        ProtocolOp::ModifyRequest(modify_request) => {
            handle_modify_request(socket, backend, message_id, modify_request).await?;
        }
        ProtocolOp::AddRequest(add_request) => {
            handle_add_request(socket, backend, message_id, add_request).await?;
        }
        ProtocolOp::DelRequest(delete_request) => {
            handle_delete_request(socket, backend, message_id, delete_request).await?;
        }
        ProtocolOp::ModDnRequest(rename_request) => {
            handle_moddn_request(socket, backend, message_id, rename_request).await?;
        }
        ProtocolOp::CompareRequest(compare_request) => {
            handle_compare_request(socket, backend, message_id, compare_request).await?;
        }
        ProtocolOp::UnbindRequest => {
            info!("Received unbind request");
            return Ok(());
        }
        ProtocolOp::AbandonRequest(request_id) => {
            handle_abandon_request(request_id);
        }
        ProtocolOp::ExtendedRequest(request) => {
            handle_extended_request(socket, message_id, request).await?;
        }
        op => {
            warn!("Unsupported operation received: {:?}", op);
        }
    }

    Ok(())
}

pub async fn handle_bind_request(
    socket: &mut TcpStream,
    backend: &dyn DirectoryBackend,
    message_id: u32,
    request: BindRequest<'_>,
) -> Result<(), ServerError> {
    if request.version != 3 {
        send_bind_response(
            socket,
            message_id,
            ResultCode::ProtocolError,
            "unsupported LDAP version",
        )
        .await?;
        return Ok(());
    }

    match request.authentication {
        AuthenticationChoice::Simple(password) => {
            let dn = request.name.0.as_ref().trim().to_owned();
            match backend.authenticate(&dn, password.as_ref()).await {
                Ok(true) => send_bind_success(socket, message_id).await?,
                Ok(false) => {
                    send_bind_response(
                        socket,
                        message_id,
                        ResultCode::InvalidCredentials,
                        "invalid credentials",
                    )
                    .await?;
                }
                Err(err) => {
                    error!("Backend authentication error for {}: {}", dn, err);
                    send_bind_response(
                        socket,
                        message_id,
                        ResultCode::Unavailable,
                        "backend failure",
                    )
                    .await?;
                }
            }
        }
        AuthenticationChoice::Sasl(_) => {
            send_bind_response(
                socket,
                message_id,
                ResultCode::AuthMethodNotSupported,
                "SASL authentication is not supported",
            )
            .await?;
        }
    }

    Ok(())
}

async fn send_bind_success(socket: &mut TcpStream, message_id: u32) -> Result<(), ServerError> {
    send_bind_response(socket, message_id, ResultCode::Success, "").await
}

async fn send_bind_response(
    socket: &mut TcpStream,
    message_id: u32,
    result_code: ResultCode,
    diagnostic_message: impl Into<String>,
) -> Result<(), ServerError> {
    let encoded = encode_bind_response(message_id, result_code, "", diagnostic_message)?;
    socket.write_all(&encoded).await?;
    Ok(())
}

async fn send_result(
    socket: &mut TcpStream,
    message_id: u32,
    op: ResponseOp,
    result_code: ResultCode,
    matched_dn: impl Into<String>,
    diagnostic_message: impl Into<String>,
) -> Result<(), ServerError> {
    let encoded =
        encode_result_response(message_id, op, result_code, matched_dn, diagnostic_message)?;
    socket.write_all(&encoded).await?;
    Ok(())
}

fn map_backend_error(err: &BackendError) -> ResultCode {
    match err {
        BackendError::AlreadyExists => ResultCode::EntryAlreadyExists,
        BackendError::NotFound => ResultCode::NoSuchObject,
        BackendError::Storage(_) => ResultCode::Unavailable,
    }
}

fn diagnostic_for_error(err: &BackendError) -> &'static str {
    match err {
        BackendError::AlreadyExists => "entry already exists",
        BackendError::NotFound => "no such object",
        BackendError::Storage(_) => "backend failure",
    }
}

pub async fn handle_search_request(
    socket: &mut TcpStream,
    backend: &dyn DirectoryBackend,
    message_id: u32,
    request: SearchRequest<'_>,
) -> Result<(), ServerError> {
    let base_dn = request.base_object.0.as_ref().trim().to_owned();
    let attribute_selection: Vec<String> = request
        .attributes
        .iter()
        .map(|attribute| attribute.0.as_ref().trim().to_owned())
        .collect();

    let entries = match backend.search_entries(&base_dn, request.scope).await {
        Ok(entries) => entries,
        Err(err) => {
            error!("Search backend failure for {}: {}", base_dn, err);
            send_result(
                socket,
                message_id,
                ResponseOp::SearchDone,
                map_backend_error(&err),
                &base_dn,
                diagnostic_for_error(&err),
            )
            .await?;
            return Ok(());
        }
    };

    let mut returned = 0usize;
    let mut size_limit_hit = false;

    for entry in entries {
        if !entry_matches_filter(&entry, &request.filter) {
            continue;
        }

        if request.size_limit != 0 && returned >= request.size_limit as usize {
            size_limit_hit = true;
            break;
        }

        let attributes = select_attributes(&entry, &attribute_selection);
        let encoded = encode_search_entry(message_id, &entry, &attributes, request.types_only)?;
        socket.write_all(&encoded).await?;
        returned += 1;
    }

    let (result_code, diagnostic) = if size_limit_hit {
        (ResultCode::SizeLimitExceeded, "size limit exceeded")
    } else {
        (ResultCode::Success, "")
    };

    send_result(
        socket,
        message_id,
        ResponseOp::SearchDone,
        result_code,
        &base_dn,
        diagnostic,
    )
    .await?;

    Ok(())
}

pub async fn handle_modify_request(
    socket: &mut TcpStream,
    backend: &dyn DirectoryBackend,
    message_id: u32,
    request: ModifyRequest<'_>,
) -> Result<(), ServerError> {
    let dn = request.object.0.as_ref().trim().to_owned();
    let modifications = convert_modifications(request.changes);

    match backend.modify_entry(&dn, modifications).await {
        Ok(()) => {
            send_result(
                socket,
                message_id,
                ResponseOp::Modify,
                ResultCode::Success,
                &dn,
                "",
            )
            .await?;
        }
        Err(err) => {
            error!("Modify operation failed for {}: {}", dn, err);
            send_result(
                socket,
                message_id,
                ResponseOp::Modify,
                map_backend_error(&err),
                &dn,
                diagnostic_for_error(&err),
            )
            .await?;
        }
    }

    Ok(())
}

pub async fn handle_add_request(
    socket: &mut TcpStream,
    backend: &dyn DirectoryBackend,
    message_id: u32,
    request: AddRequest<'_>,
) -> Result<(), ServerError> {
    let dn = request.entry.0.as_ref().trim().to_owned();
    let (entry, password) = build_entry_from_add_request(&dn, request.attributes);

    match backend.add_entry(entry, password).await {
        Ok(()) => {
            send_result(
                socket,
                message_id,
                ResponseOp::Add,
                ResultCode::Success,
                &dn,
                "",
            )
            .await?;
        }
        Err(err) => {
            error!("Add operation failed for {}: {}", dn, err);
            send_result(
                socket,
                message_id,
                ResponseOp::Add,
                map_backend_error(&err),
                &dn,
                diagnostic_for_error(&err),
            )
            .await?;
        }
    }

    Ok(())
}

pub async fn handle_delete_request(
    socket: &mut TcpStream,
    backend: &dyn DirectoryBackend,
    message_id: u32,
    dn: ldap_parser::ldap::LdapDN<'_>,
) -> Result<(), ServerError> {
    let dn = dn.0.as_ref().trim().to_owned();

    match backend.delete_entry(&dn).await {
        Ok(()) => {
            send_result(
                socket,
                message_id,
                ResponseOp::Delete,
                ResultCode::Success,
                &dn,
                "",
            )
            .await?;
        }
        Err(err) => {
            error!("Delete operation failed for {}: {}", dn, err);
            send_result(
                socket,
                message_id,
                ResponseOp::Delete,
                map_backend_error(&err),
                &dn,
                diagnostic_for_error(&err),
            )
            .await?;
        }
    }

    Ok(())
}

pub async fn handle_moddn_request(
    socket: &mut TcpStream,
    backend: &dyn DirectoryBackend,
    message_id: u32,
    request: ModDnRequest<'_>,
) -> Result<(), ServerError> {
    let dn = request.entry.0.as_ref().trim().to_owned();
    let new_rdn = request.newrdn.0.as_ref().trim().to_owned();
    let delete_old = request.deleteoldrdn;
    let new_superior = request
        .newsuperior
        .map(|sup| sup.0.into_owned())
        .filter(|sup| !sup.is_empty());

    match backend
        .rename_entry(&dn, &new_rdn, delete_old, new_superior)
        .await
    {
        Ok(()) => {
            send_result(
                socket,
                message_id,
                ResponseOp::ModifyDn,
                ResultCode::Success,
                &dn,
                "",
            )
            .await?;
        }
        Err(err) => {
            error!("ModifyDN operation failed for {}: {}", dn, err);
            send_result(
                socket,
                message_id,
                ResponseOp::ModifyDn,
                map_backend_error(&err),
                &dn,
                diagnostic_for_error(&err),
            )
            .await?;
        }
    }

    Ok(())
}

pub async fn handle_compare_request(
    socket: &mut TcpStream,
    backend: &dyn DirectoryBackend,
    message_id: u32,
    request: CompareRequest<'_>,
) -> Result<(), ServerError> {
    let dn = request.entry.0.as_ref().trim().to_owned();
    let attribute = request.ava.attribute_desc.0.as_ref().trim().to_owned();
    let assertion = bytes_to_string(request.ava.assertion_value);

    match backend.compare_attribute(&dn, &attribute, &assertion).await {
        Ok(true) => {
            send_result(
                socket,
                message_id,
                ResponseOp::Compare,
                ResultCode::CompareTrue,
                &dn,
                "",
            )
            .await?;
        }
        Ok(false) => {
            send_result(
                socket,
                message_id,
                ResponseOp::Compare,
                ResultCode::CompareFalse,
                &dn,
                "",
            )
            .await?;
        }
        Err(err) => {
            error!("Compare operation failed for {}: {}", dn, err);
            send_result(
                socket,
                message_id,
                ResponseOp::Compare,
                map_backend_error(&err),
                &dn,
                diagnostic_for_error(&err),
            )
            .await?;
        }
    }

    Ok(())
}

fn handle_abandon_request(request_id: ldap_parser::ldap::MessageID) {
    info!("Received abandon request for message {}", request_id.0);
}

pub async fn handle_extended_request(
    socket: &mut TcpStream,
    message_id: u32,
    request: ExtendedRequest<'_>,
) -> Result<(), ServerError> {
    warn!(
        "Unsupported extended operation requested: {}",
        request.request_name.0.as_ref()
    );

    send_result(
        socket,
        message_id,
        ResponseOp::Extended,
        ResultCode::ProtocolError,
        "",
        "extended operations are not supported",
    )
    .await
}

fn select_attributes(entry: &DirectoryEntry, requested: &[String]) -> Vec<(String, Vec<String>)> {
    if requested
        .iter()
        .any(|attribute| attribute.eq_ignore_ascii_case("1.1"))
    {
        return Vec::new();
    }

    let include_all = requested.is_empty() || requested.iter().any(|attr| attr == "*");

    let mut selected = Vec::new();

    for (name, values) in &entry.attributes {
        if include_all
            || requested
                .iter()
                .any(|attribute| attribute.eq_ignore_ascii_case(name))
        {
            selected.push((name.clone(), values.clone()));
        }
    }

    selected
}

fn entry_matches_filter(entry: &DirectoryEntry, filter: &Filter<'_>) -> bool {
    match filter {
        Filter::And(filters) => filters.iter().all(|f| entry_matches_filter(entry, f)),
        Filter::Or(filters) => filters.iter().any(|f| entry_matches_filter(entry, f)),
        Filter::Not(filter) => !entry_matches_filter(entry, filter),
        Filter::EqualityMatch(ava) => attribute_values(entry, ava.attribute_desc.0.as_ref())
            .map(|values| {
                let assertion = bytes_to_string(ava.assertion_value);
                values.iter().any(|candidate| candidate == &assertion)
            })
            .unwrap_or(false),
        Filter::Substrings(substring) => attribute_values(entry, substring.filter_type.0.as_ref())
            .map(|values| matches_substrings(values, substring))
            .unwrap_or(false),
        Filter::GreaterOrEqual(ava) => attribute_values(entry, ava.attribute_desc.0.as_ref())
            .map(|values| {
                let assertion = bytes_to_string(ava.assertion_value);
                values.iter().any(|candidate| candidate >= &assertion)
            })
            .unwrap_or(false),
        Filter::LessOrEqual(ava) => attribute_values(entry, ava.attribute_desc.0.as_ref())
            .map(|values| {
                let assertion = bytes_to_string(ava.assertion_value);
                values.iter().any(|candidate| candidate <= &assertion)
            })
            .unwrap_or(false),
        Filter::Present(attribute) => attribute_values(entry, attribute.0.as_ref()).is_some(),
        Filter::ApproxMatch(ava) => attribute_values(entry, ava.attribute_desc.0.as_ref())
            .map(|values| {
                let assertion = bytes_to_string(ava.assertion_value);
                values
                    .iter()
                    .any(|candidate| candidate.eq_ignore_ascii_case(&assertion))
            })
            .unwrap_or(false),
        Filter::ExtensibleMatch(_) => false,
    }
}

fn matches_substrings(values: &[String], filter: &SubstringFilter<'_>) -> bool {
    if filter.substrings.is_empty() {
        return values.iter().any(|value| value.is_empty());
    }

    values
        .iter()
        .any(|value| substring_matches(value, &filter.substrings))
}

fn substring_matches(value: &str, substrings: &[Substring<'_>]) -> bool {
    let mut remainder = value;

    for substring in substrings {
        match substring {
            Substring::Initial(segment) => {
                let segment = bytes_to_string(segment.0.as_ref());
                if !remainder.starts_with(&segment) {
                    return false;
                }
                remainder = &remainder[segment.len()..];
            }
            Substring::Any(segment) => {
                let segment = bytes_to_string(segment.0.as_ref());
                if segment.is_empty() {
                    continue;
                }
                if let Some(index) = remainder.find(&segment) {
                    remainder = &remainder[index + segment.len()..];
                } else {
                    return false;
                }
            }
            Substring::Final(segment) => {
                let segment = bytes_to_string(segment.0.as_ref());
                return remainder.ends_with(&segment);
            }
        }
    }

    true
}

fn attribute_values<'a>(entry: &'a DirectoryEntry, attribute: &str) -> Option<&'a Vec<String>> {
    entry.attributes.get(&attribute.to_lowercase())
}

fn convert_modifications(changes: Vec<Change<'_>>) -> Vec<Modification> {
    changes
        .into_iter()
        .map(|change| {
            let operation = match change.operation.0 {
                0 => ModifyOperation::Add,
                1 => ModifyOperation::Delete,
                2 => ModifyOperation::Replace,
                _ => ModifyOperation::Replace,
            };

            let attribute = change.modification.attr_type.0.to_lowercase();

            let values = change
                .modification
                .attr_vals
                .iter()
                .map(|value| bytes_to_string(value.0.as_ref()))
                .collect();

            Modification {
                operation,
                attribute,
                values,
            }
        })
        .collect()
}

fn build_entry_from_add_request(
    dn: &str,
    attributes: Vec<ldap_parser::filter::Attribute<'_>>,
) -> (DirectoryEntry, Vec<u8>) {
    let mut attribute_map: HashMap<String, Vec<String>> = HashMap::new();
    let mut password = Vec::new();

    for attribute in attributes {
        let name = attribute.attr_type.0.into_owned().to_lowercase();
        let values: Vec<String> = attribute
            .attr_vals
            .iter()
            .map(|value| bytes_to_string(value.0.as_ref()))
            .collect();

        if name == "userpassword" {
            if let Some(first) = values.first() {
                password = first.as_bytes().to_vec();
            }
        }

        let entry_values = attribute_map.entry(name).or_default();
        for value in values {
            if !entry_values.contains(&value) {
                entry_values.push(value);
            }
        }
    }

    (DirectoryEntry::new(dn.to_owned(), attribute_map), password)
}

fn bytes_to_string(value: &[u8]) -> String {
    String::from_utf8_lossy(value).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ldap_parser::filter::{
        Attribute as FilterAttribute, AttributeValue, AttributeValueAssertion, Filter,
        PartialAttribute,
    };
    use ldap_parser::ldap::LdapString;
    use ldap_parser::ldap::{Change, Operation};
    use std::borrow::Cow;

    #[test]
    fn convert_modifications_translates_operations_and_values() {
        let changes = vec![
            Change {
                operation: Operation(0),
                modification: PartialAttribute {
                    attr_type: LdapString(Cow::Owned("cn".to_string())),
                    attr_vals: vec![AttributeValue(Cow::Owned(b"Alice".to_vec()))],
                },
            },
            Change {
                operation: Operation(1),
                modification: PartialAttribute {
                    attr_type: LdapString(Cow::Owned("sn".to_string())),
                    attr_vals: vec![AttributeValue(Cow::Owned(b"Smith".to_vec()))],
                },
            },
            Change {
                operation: Operation(2),
                modification: PartialAttribute {
                    attr_type: LdapString(Cow::Owned("mail".to_string())),
                    attr_vals: vec![AttributeValue(Cow::Owned(b"alice@example.org".to_vec()))],
                },
            },
        ];

        let modifications = convert_modifications(changes);
        assert_eq!(modifications.len(), 3);
        assert_eq!(modifications[0].operation, ModifyOperation::Add);
        assert_eq!(modifications[0].attribute, "cn");
        assert_eq!(modifications[0].values, vec!["Alice".to_string()]);
        assert_eq!(modifications[1].operation, ModifyOperation::Delete);
        assert_eq!(modifications[1].attribute, "sn");
        assert_eq!(modifications[1].values, vec!["Smith".to_string()]);
        assert_eq!(modifications[2].operation, ModifyOperation::Replace);
        assert_eq!(modifications[2].attribute, "mail");
        assert_eq!(
            modifications[2].values,
            vec!["alice@example.org".to_string()]
        );
    }

    #[test]
    fn build_entry_from_add_request_collects_attributes_and_password() {
        let attributes = vec![
            FilterAttribute {
                attr_type: LdapString(Cow::Owned("cn".to_string())),
                attr_vals: vec![AttributeValue(Cow::Owned(b"Alice".to_vec()))],
            },
            FilterAttribute {
                attr_type: LdapString(Cow::Owned("userPassword".to_string())),
                attr_vals: vec![AttributeValue(Cow::Owned(b"secret".to_vec()))],
            },
        ];

        let (entry, password) =
            build_entry_from_add_request("cn=Alice,dc=example,dc=org", attributes);

        assert_eq!(entry.dn, "cn=Alice,dc=example,dc=org");
        assert_eq!(
            entry.attributes.get("cn").unwrap(),
            &vec!["Alice".to_string()]
        );
        assert_eq!(
            entry.attributes.get("userpassword").unwrap(),
            &vec!["secret".to_string()]
        );
        assert_eq!(password, b"secret".to_vec());
    }

    #[test]
    fn entry_matches_filter_handles_basic_conditions() {
        let mut attributes = HashMap::new();
        attributes.insert("cn".to_string(), vec!["Alice".to_string()]);
        attributes.insert("sn".to_string(), vec!["Smith".to_string()]);
        let entry = DirectoryEntry::new("cn=Alice,dc=example,dc=org", attributes);

        let equality_filter = Filter::EqualityMatch(AttributeValueAssertion {
            attribute_desc: LdapString(Cow::Owned("cn".to_string())),
            assertion_value: b"Alice",
        });
        assert!(entry_matches_filter(&entry, &equality_filter));

        let present_filter = Filter::Present(LdapString(Cow::Owned("sn".to_string())));
        assert!(entry_matches_filter(&entry, &present_filter));

        let missing_filter = Filter::Present(LdapString(Cow::Owned("mail".to_string())));
        assert!(!entry_matches_filter(&entry, &missing_filter));
    }
}

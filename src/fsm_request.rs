use std::net::IpAddr;

use ldap_parser::ldap::{LdapMessage, ProtocolOp};
use rasn_ldap::ResultCode;

use crate::ldap_controls::{ControlRegistry, ControlValidationError, RequestControls};
use crate::parser::ResponseOp;
use crate::read_entry_controls::{PRE_READ_CONTROL_OID, contains_critical_pre_read_control};
use crate::search_controls::{
    PAGED_RESULTS_OID, SERVER_SIDE_SORT_REQUEST_OID, SERVER_SIDE_SORT_RESPONSE_OID,
    SUBENTRIES_CONTROL_OID,
};
use crate::sync_controls::{SYNC_DONE_OID, SYNC_REQUEST_OID, SYNC_STATE_OID};

const MANAGE_DSA_IT_OID: &str = "2.16.840.1.113730.3.4.2";

/// Connection-scoped request context derived before FSM dispatch.
#[derive(Debug, Clone)]
pub struct FsmRequestContext {
    pub connection_id: u64,
    pub message_id: i32,
    pub client_ip: Option<IpAddr>,
    pub request_kind: FsmRequestKind,
    pub response_kind: FsmResponseKind,
    pub authenticated_dn: Option<String>,
    pub is_secure: bool,
    pub request_controls: RequestControls,
}

impl FsmRequestContext {
    pub fn operation_name(&self) -> &'static str {
        self.request_kind.operation_name()
    }

    pub fn requires_operation_slot(&self) -> bool {
        self.request_kind.requires_operation_slot()
    }
}

/// High-level request kind used by the FSM dispatcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsmRequestKind {
    Bind,
    Search,
    Modify,
    Add,
    Delete,
    ModifyDn,
    Compare,
    Extended,
    Unbind,
    Abandon,
    Unsupported,
}

impl FsmRequestKind {
    pub fn operation_name(self) -> &'static str {
        match self {
            Self::Bind => "bind",
            Self::Search => "search",
            Self::Modify => "modify",
            Self::Add => "add",
            Self::Delete => "delete",
            Self::ModifyDn => "modifydn",
            Self::Compare => "compare",
            Self::Extended => "extended",
            Self::Unbind => "unbind",
            Self::Abandon => "abandon",
            Self::Unsupported => "unknown",
        }
    }

    pub fn response_kind(self) -> FsmResponseKind {
        match self {
            Self::Bind => FsmResponseKind::Bind,
            Self::Search => FsmResponseKind::Result(ResponseOp::SearchDone),
            Self::Modify => FsmResponseKind::Result(ResponseOp::Modify),
            Self::Add => FsmResponseKind::Result(ResponseOp::Add),
            Self::Delete => FsmResponseKind::Result(ResponseOp::Delete),
            Self::ModifyDn => FsmResponseKind::Result(ResponseOp::ModifyDn),
            Self::Compare => FsmResponseKind::Result(ResponseOp::Compare),
            Self::Extended => FsmResponseKind::Result(ResponseOp::Extended),
            Self::Unbind | Self::Abandon | Self::Unsupported => FsmResponseKind::None,
        }
    }

    pub fn requires_operation_slot(self) -> bool {
        matches!(
            self,
            Self::Search
                | Self::Modify
                | Self::Add
                | Self::Delete
                | Self::ModifyDn
                | Self::Compare
                | Self::Extended
        )
    }

    fn allows_pre_read_control(self) -> bool {
        matches!(self, Self::Modify | Self::Delete | Self::ModifyDn)
    }
}

/// Response kind used for early rejections before operation-specific FSMs run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsmResponseKind {
    Bind,
    Result(ResponseOp),
    None,
}

/// A request rejected during the shared request pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsmRequestRejection {
    pub response_kind: FsmResponseKind,
    pub result_code: ResultCode,
    pub diagnostic_message: String,
}

/// Build the default request-side control registry for the FSM runtime.
pub fn active_fsm_control_registry() -> ControlRegistry {
    let mut registry = ControlRegistry::default();
    registry
        .register_request_control(PAGED_RESULTS_OID)
        .register_response_control(PAGED_RESULTS_OID)
        .register_request_control(SERVER_SIDE_SORT_REQUEST_OID)
        .register_response_control(SERVER_SIDE_SORT_RESPONSE_OID)
        .register_request_control(SUBENTRIES_CONTROL_OID)
        .register_request_control(MANAGE_DSA_IT_OID)
        .register_request_control(PRE_READ_CONTROL_OID)
        .register_response_control(PRE_READ_CONTROL_OID)
        .register_request_control(SYNC_REQUEST_OID)
        .register_response_control(SYNC_STATE_OID)
        .register_response_control(SYNC_DONE_OID);
    registry
}

/// Validate controls and derive the dispatcher context for a single LDAP request.
pub fn build_request_context(
    message: &LdapMessage<'_>,
    connection_id: u64,
    client_ip: Option<IpAddr>,
    authenticated_dn: Option<&str>,
    is_secure: bool,
) -> Result<FsmRequestContext, FsmRequestRejection> {
    let request_kind = FsmRequestKind::from(&message.protocol_op);
    let response_kind = request_kind.response_kind();
    let registry = active_fsm_control_registry();
    let mut request_controls = registry
        .validate_request_controls(message.controls.as_deref())
        .map(|validated| validated.into_accepted())
        .map_err(|error| match error {
            ControlValidationError::UnknownCritical { oid } => FsmRequestRejection {
                response_kind,
                result_code: ResultCode::UnavailableCriticalExtension,
                diagnostic_message: format!("unsupported critical control {}", oid),
            },
        })?;
    if !request_kind.allows_pre_read_control() {
        if contains_critical_pre_read_control(&request_controls) {
            return Err(FsmRequestRejection {
                response_kind,
                result_code: ResultCode::UnavailableCriticalExtension,
                diagnostic_message:
                    "pre-read control is only appropriate for modify, delete, and modifyDN operations"
                        .to_string(),
            });
        }
        request_controls = request_controls.without_oid(PRE_READ_CONTROL_OID);
    }

    Ok(FsmRequestContext {
        connection_id,
        message_id: message.message_id.0 as i32,
        client_ip,
        request_kind,
        response_kind,
        authenticated_dn: authenticated_dn.map(str::to_owned),
        is_secure,
        request_controls,
    })
}

impl From<&ProtocolOp<'_>> for FsmRequestKind {
    fn from(protocol_op: &ProtocolOp<'_>) -> Self {
        match protocol_op {
            ProtocolOp::BindRequest(_) => Self::Bind,
            ProtocolOp::SearchRequest(_) => Self::Search,
            ProtocolOp::ModifyRequest(_) => Self::Modify,
            ProtocolOp::AddRequest(_) => Self::Add,
            ProtocolOp::DelRequest(_) => Self::Delete,
            ProtocolOp::ModDnRequest(_) => Self::ModifyDn,
            ProtocolOp::CompareRequest(_) => Self::Compare,
            ProtocolOp::ExtendedRequest(_) => Self::Extended,
            ProtocolOp::UnbindRequest => Self::Unbind,
            ProtocolOp::AbandonRequest(_) => Self::Abandon,
            _ => Self::Unsupported,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use ldap_parser::filter::{AttributeValueAssertion, Filter};
    use ldap_parser::ldap::{
        Control, DerefAliases, LdapDN, LdapOID, LdapString, MessageID, SearchRequest, SearchScope,
    };

    use super::*;

    fn parsed_control(
        oid: &'static str,
        criticality: bool,
        value: Option<&'static [u8]>,
    ) -> Control<'static> {
        Control {
            control_type: LdapOID(Cow::Borrowed(oid)),
            criticality,
            control_value: value.map(Cow::Borrowed),
        }
    }

    fn search_message_with_controls(
        controls: Option<Vec<Control<'static>>>,
    ) -> LdapMessage<'static> {
        LdapMessage {
            message_id: MessageID(7),
            protocol_op: ProtocolOp::SearchRequest(SearchRequest {
                base_object: LdapDN(Cow::Borrowed("dc=example,dc=org")),
                scope: SearchScope(2),
                deref_aliases: DerefAliases(0),
                size_limit: 0,
                time_limit: 0,
                types_only: false,
                filter: Filter::EqualityMatch(AttributeValueAssertion {
                    attribute_desc: LdapString(Cow::Borrowed("objectClass")),
                    assertion_value: Cow::Borrowed(b"*"),
                }),
                attributes: Vec::new(),
            }),
            controls: controls.map(|controls| controls.into_iter().collect()),
        }
    }

    #[test]
    fn build_request_context_maps_search_requests() {
        let message = search_message_with_controls(None);

        let context = build_request_context(&message, 11, None, Some("cn=admin"), true).unwrap();

        assert_eq!(context.connection_id, 11);
        assert_eq!(context.message_id, 7);
        assert_eq!(context.request_kind, FsmRequestKind::Search);
        assert_eq!(
            context.response_kind,
            FsmResponseKind::Result(ResponseOp::SearchDone)
        );
        assert_eq!(context.authenticated_dn.as_deref(), Some("cn=admin"));
        assert!(context.is_secure);
    }

    #[test]
    fn build_request_context_rejects_unknown_critical_controls() {
        let message = search_message_with_controls(Some(vec![parsed_control("1.2.3", true, None)]));

        let rejection = build_request_context(&message, 1, None, None, false).unwrap_err();

        assert_eq!(
            rejection.response_kind,
            FsmResponseKind::Result(ResponseOp::SearchDone)
        );
        assert_eq!(
            rejection.result_code,
            ResultCode::UnavailableCriticalExtension
        );
        assert!(
            rejection
                .diagnostic_message
                .contains("unsupported critical control 1.2.3")
        );
    }
}

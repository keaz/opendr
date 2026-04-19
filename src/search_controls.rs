use rasn::types::OctetString;
use rasn::{AsnType, Decode, Encode};

pub const PAGED_RESULTS_OID: &str = "1.2.840.113556.1.4.319";
pub const SERVER_SIDE_SORT_REQUEST_OID: &str = "1.2.840.113556.1.4.473";
pub const SERVER_SIDE_SORT_RESPONSE_OID: &str = "1.2.840.113556.1.4.474";
pub const SUBENTRIES_CONTROL_OID: &str = "1.3.6.1.4.1.4203.1.10.1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PagedResultsControl {
    pub size: u32,
    pub cookie: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PagedResultsControlError {
    MissingValue,
    InvalidAsn1(String),
}

impl std::fmt::Display for PagedResultsControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingValue => write!(f, "paged results control requires a controlValue"),
            Self::InvalidAsn1(err) => write!(f, "invalid paged results BER: {err}"),
        }
    }
}

impl std::error::Error for PagedResultsControlError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubentriesControl {
    pub visible: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubentriesControlError {
    MissingValue,
    InvalidAsn1(String),
}

impl std::fmt::Display for SubentriesControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingValue => write!(f, "subentries control requires a controlValue"),
            Self::InvalidAsn1(err) => write!(f, "invalid subentries control BER: {err}"),
        }
    }
}

impl std::error::Error for SubentriesControlError {}

#[derive(AsnType, Decode, Encode)]
struct RealPagedResultsControlValue {
    size: u32,
    cookie: OctetString,
}

pub fn decode_paged_results_control(
    value: Option<&[u8]>,
) -> Result<PagedResultsControl, PagedResultsControlError> {
    let value = value.ok_or(PagedResultsControlError::MissingValue)?;
    let decoded: RealPagedResultsControlValue = rasn::ber::decode(value)
        .map_err(|err| PagedResultsControlError::InvalidAsn1(err.to_string()))?;
    Ok(PagedResultsControl {
        size: decoded.size,
        cookie: decoded.cookie.to_vec(),
    })
}

pub fn encode_paged_results_control(
    size: u32,
    cookie: &[u8],
) -> Result<Vec<u8>, PagedResultsControlError> {
    rasn::ber::encode(&RealPagedResultsControlValue {
        size,
        cookie: cookie.to_vec().into(),
    })
    .map_err(|err| PagedResultsControlError::InvalidAsn1(err.to_string()))
}

pub fn decode_subentries_control(
    value: Option<&[u8]>,
) -> Result<SubentriesControl, SubentriesControlError> {
    let value = value.ok_or(SubentriesControlError::MissingValue)?;
    let visible: bool = rasn::ber::decode(value)
        .map_err(|err| SubentriesControlError::InvalidAsn1(err.to_string()))?;
    Ok(SubentriesControl { visible })
}

pub fn encode_subentries_control(visible: bool) -> Result<Vec<u8>, SubentriesControlError> {
    rasn::ber::encode(&visible).map_err(|err| SubentriesControlError::InvalidAsn1(err.to_string()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SortKey {
    pub attribute_type: String,
    pub ordering_rule: Option<String>,
    pub reverse_order: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSideSortRequestControl {
    pub keys: Vec<SortKey>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerSideSortResultCode {
    Success = 0,
    OperationsError = 1,
    TimeLimitExceeded = 3,
    StrongAuthRequired = 8,
    AdminLimitExceeded = 11,
    NoSuchAttribute = 16,
    InappropriateMatching = 18,
    InsufficientAccessRights = 50,
    Busy = 51,
    UnwillingToPerform = 53,
    Other = 80,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSideSortResponseControl {
    pub result: ServerSideSortResultCode,
    pub attribute_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerSideSortControlError {
    MissingValue,
    InvalidAsn1(String),
    EmptyKeyList,
}

impl std::fmt::Display for ServerSideSortControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingValue => write!(f, "server-side sort control requires a controlValue"),
            Self::InvalidAsn1(err) => write!(f, "invalid server-side sort BER: {err}"),
            Self::EmptyKeyList => write!(f, "server-side sort control requires at least one key"),
        }
    }
}

impl std::error::Error for ServerSideSortControlError {}

#[derive(AsnType, Decode, Encode)]
struct RealServerSideSortKey {
    attribute_type: OctetString,
    #[rasn(tag(context, 0))]
    ordering_rule: Option<OctetString>,
    #[rasn(tag(context, 1), default)]
    reverse_order: bool,
}

#[derive(AsnType, Decode, Encode, Debug, Clone, Copy, PartialEq, Eq)]
#[rasn(enumerated)]
enum RealServerSideSortResultCode {
    Success = 0,
    OperationsError = 1,
    TimeLimitExceeded = 3,
    StrongAuthRequired = 8,
    AdminLimitExceeded = 11,
    NoSuchAttribute = 16,
    InappropriateMatching = 18,
    InsufficientAccessRights = 50,
    Busy = 51,
    UnwillingToPerform = 53,
    Other = 80,
}

#[derive(AsnType, Decode, Encode)]
struct RealServerSideSortResponseControlValue {
    sort_result: RealServerSideSortResultCode,
    #[rasn(tag(context, 0))]
    attribute_type: Option<OctetString>,
}

impl From<RealServerSideSortResultCode> for ServerSideSortResultCode {
    fn from(value: RealServerSideSortResultCode) -> Self {
        match value {
            RealServerSideSortResultCode::Success => Self::Success,
            RealServerSideSortResultCode::OperationsError => Self::OperationsError,
            RealServerSideSortResultCode::TimeLimitExceeded => Self::TimeLimitExceeded,
            RealServerSideSortResultCode::StrongAuthRequired => Self::StrongAuthRequired,
            RealServerSideSortResultCode::AdminLimitExceeded => Self::AdminLimitExceeded,
            RealServerSideSortResultCode::NoSuchAttribute => Self::NoSuchAttribute,
            RealServerSideSortResultCode::InappropriateMatching => Self::InappropriateMatching,
            RealServerSideSortResultCode::InsufficientAccessRights => {
                Self::InsufficientAccessRights
            }
            RealServerSideSortResultCode::Busy => Self::Busy,
            RealServerSideSortResultCode::UnwillingToPerform => Self::UnwillingToPerform,
            RealServerSideSortResultCode::Other => Self::Other,
        }
    }
}

impl From<ServerSideSortResultCode> for RealServerSideSortResultCode {
    fn from(value: ServerSideSortResultCode) -> Self {
        match value {
            ServerSideSortResultCode::Success => Self::Success,
            ServerSideSortResultCode::OperationsError => Self::OperationsError,
            ServerSideSortResultCode::TimeLimitExceeded => Self::TimeLimitExceeded,
            ServerSideSortResultCode::StrongAuthRequired => Self::StrongAuthRequired,
            ServerSideSortResultCode::AdminLimitExceeded => Self::AdminLimitExceeded,
            ServerSideSortResultCode::NoSuchAttribute => Self::NoSuchAttribute,
            ServerSideSortResultCode::InappropriateMatching => Self::InappropriateMatching,
            ServerSideSortResultCode::InsufficientAccessRights => Self::InsufficientAccessRights,
            ServerSideSortResultCode::Busy => Self::Busy,
            ServerSideSortResultCode::UnwillingToPerform => Self::UnwillingToPerform,
            ServerSideSortResultCode::Other => Self::Other,
        }
    }
}

pub fn decode_server_side_sort_request_control(
    value: Option<&[u8]>,
) -> Result<ServerSideSortRequestControl, ServerSideSortControlError> {
    let value = value.ok_or(ServerSideSortControlError::MissingValue)?;
    let decoded: Vec<RealServerSideSortKey> = rasn::ber::decode(value)
        .map_err(|err| ServerSideSortControlError::InvalidAsn1(err.to_string()))?;
    if decoded.is_empty() {
        return Err(ServerSideSortControlError::EmptyKeyList);
    }

    Ok(ServerSideSortRequestControl {
        keys: decoded
            .into_iter()
            .map(|key| SortKey {
                attribute_type: String::from_utf8_lossy(key.attribute_type.as_ref()).to_string(),
                ordering_rule: key
                    .ordering_rule
                    .map(|rule| String::from_utf8_lossy(rule.as_ref()).to_string()),
                reverse_order: key.reverse_order,
            })
            .collect(),
    })
}

pub fn encode_server_side_sort_request_control(
    keys: &[SortKey],
) -> Result<Vec<u8>, ServerSideSortControlError> {
    if keys.is_empty() {
        return Err(ServerSideSortControlError::EmptyKeyList);
    }

    let real_keys = keys
        .iter()
        .map(|key| RealServerSideSortKey {
            attribute_type: key.attribute_type.as_bytes().to_vec().into(),
            ordering_rule: key
                .ordering_rule
                .as_ref()
                .map(|rule| rule.as_bytes().to_vec().into()),
            reverse_order: key.reverse_order,
        })
        .collect::<Vec<_>>();

    rasn::ber::encode(&real_keys)
        .map_err(|err| ServerSideSortControlError::InvalidAsn1(err.to_string()))
}

pub fn decode_server_side_sort_response_control(
    value: Option<&[u8]>,
) -> Result<ServerSideSortResponseControl, ServerSideSortControlError> {
    let value = value.ok_or(ServerSideSortControlError::MissingValue)?;
    let decoded: RealServerSideSortResponseControlValue = rasn::ber::decode(value)
        .map_err(|err| ServerSideSortControlError::InvalidAsn1(err.to_string()))?;
    Ok(ServerSideSortResponseControl {
        result: decoded.sort_result.into(),
        attribute_type: decoded
            .attribute_type
            .map(|attribute| String::from_utf8_lossy(attribute.as_ref()).to_string()),
    })
}

pub fn encode_server_side_sort_response_control(
    result: ServerSideSortResultCode,
    attribute_type: Option<&str>,
) -> Result<Vec<u8>, ServerSideSortControlError> {
    rasn::ber::encode(&RealServerSideSortResponseControlValue {
        sort_result: result.into(),
        attribute_type: attribute_type.map(|attribute| attribute.as_bytes().to_vec().into()),
    })
    .map_err(|err| ServerSideSortControlError::InvalidAsn1(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paged_results_control_round_trips() {
        let encoded = encode_paged_results_control(250, b"opaque-cookie").unwrap();
        let decoded = decode_paged_results_control(Some(&encoded)).unwrap();

        assert_eq!(
            decoded,
            PagedResultsControl {
                size: 250,
                cookie: b"opaque-cookie".to_vec(),
            }
        );
    }

    #[test]
    fn paged_results_control_requires_value() {
        let err = decode_paged_results_control(None).unwrap_err();
        assert_eq!(err, PagedResultsControlError::MissingValue);
    }

    #[test]
    fn subentries_control_round_trips_visibility_values() {
        let visible = encode_subentries_control(true).unwrap();
        let hidden = encode_subentries_control(false).unwrap();

        assert_eq!(
            decode_subentries_control(Some(&visible)).unwrap(),
            SubentriesControl { visible: true }
        );
        assert_eq!(
            decode_subentries_control(Some(&hidden)).unwrap(),
            SubentriesControl { visible: false }
        );
    }

    #[test]
    fn subentries_control_requires_value() {
        let err = decode_subentries_control(None).unwrap_err();
        assert_eq!(err, SubentriesControlError::MissingValue);
    }

    #[test]
    fn server_side_sort_request_round_trips_multi_key_values() {
        let encoded = encode_server_side_sort_request_control(&[
            SortKey {
                attribute_type: "sn".to_string(),
                ordering_rule: None,
                reverse_order: false,
            },
            SortKey {
                attribute_type: "givenName".to_string(),
                ordering_rule: Some("caseIgnoreOrderingMatch".to_string()),
                reverse_order: true,
            },
        ])
        .unwrap();
        let decoded = decode_server_side_sort_request_control(Some(&encoded)).unwrap();

        assert_eq!(
            decoded,
            ServerSideSortRequestControl {
                keys: vec![
                    SortKey {
                        attribute_type: "sn".to_string(),
                        ordering_rule: None,
                        reverse_order: false,
                    },
                    SortKey {
                        attribute_type: "givenName".to_string(),
                        ordering_rule: Some("caseIgnoreOrderingMatch".to_string()),
                        reverse_order: true,
                    },
                ],
            }
        );
    }

    #[test]
    fn server_side_sort_request_requires_at_least_one_key() {
        let err = encode_server_side_sort_request_control(&[]).unwrap_err();
        assert_eq!(err, ServerSideSortControlError::EmptyKeyList);
    }

    #[test]
    fn server_side_sort_response_round_trips() {
        let encoded = encode_server_side_sort_response_control(
            ServerSideSortResultCode::InappropriateMatching,
            Some("sn"),
        )
        .unwrap();
        let decoded = decode_server_side_sort_response_control(Some(&encoded)).unwrap();

        assert_eq!(
            decoded,
            ServerSideSortResponseControl {
                result: ServerSideSortResultCode::InappropriateMatching,
                attribute_type: Some("sn".to_string()),
            }
        );
    }
}

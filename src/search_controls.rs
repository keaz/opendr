use rasn::types::OctetString;
use rasn::{AsnType, Decode, Encode};

pub const PAGED_RESULTS_OID: &str = "1.2.840.113556.1.4.319";

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
}

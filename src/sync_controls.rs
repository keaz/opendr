use rasn::types::{OctetString, SetOf};
use rasn::{AsnType, Decode, Encode};
use uuid::Uuid;

pub const SYNC_REQUEST_OID: &str = "1.3.6.1.4.1.4203.1.9.1.1";
pub const SYNC_STATE_OID: &str = "1.3.6.1.4.1.4203.1.9.1.2";
pub const SYNC_DONE_OID: &str = "1.3.6.1.4.1.4203.1.9.1.3";
pub const SYNC_INFO_OID: &str = "1.3.6.1.4.1.4203.1.9.1.4";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncRefreshMode {
    RefreshOnly,
    RefreshAndPersist,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncRequestControl {
    pub mode: SyncRefreshMode,
    pub cookie: Option<Vec<u8>>,
    pub reload_hint: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncStateType {
    Present,
    Add,
    Modify,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncStateControl {
    pub state: SyncStateType,
    pub entry_uuid: Uuid,
    pub cookie: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncDoneControl {
    pub cookie: Option<Vec<u8>>,
    pub refresh_deletes: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncInfoValue {
    NewCookie(Vec<u8>),
    RefreshDelete {
        cookie: Option<Vec<u8>>,
        refresh_done: bool,
    },
    RefreshPresent {
        cookie: Option<Vec<u8>>,
        refresh_done: bool,
    },
    SyncIdSet {
        cookie: Option<Vec<u8>>,
        refresh_deletes: bool,
        sync_uuids: Vec<Uuid>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncControlError {
    MissingValue,
    InvalidAsn1(String),
    InvalidMode(i32),
    InvalidState(i32),
    InvalidUuidLength(usize),
}

impl std::fmt::Display for SyncControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingValue => write!(f, "sync control requires a controlValue"),
            Self::InvalidAsn1(err) => write!(f, "invalid sync BER: {err}"),
            Self::InvalidMode(mode) => write!(f, "invalid sync refresh mode {mode}"),
            Self::InvalidState(state) => write!(f, "invalid sync state {state}"),
            Self::InvalidUuidLength(length) => {
                write!(f, "sync entryUUID must be 16 bytes, got {length}")
            }
        }
    }
}

impl std::error::Error for SyncControlError {}

#[derive(AsnType, Decode, Encode, Debug, Clone, Copy, PartialEq, Eq)]
#[rasn(enumerated)]
enum RealSyncRefreshMode {
    RefreshOnly = 1,
    RefreshAndPersist = 3,
}

#[derive(AsnType, Decode, Encode)]
struct RealSyncRequestControl {
    mode: RealSyncRefreshMode,
    cookie: Option<OctetString>,
    #[rasn(default)]
    reload_hint: bool,
}

#[derive(AsnType, Decode, Encode, Debug, Clone, Copy, PartialEq, Eq)]
#[rasn(enumerated)]
enum RealSyncStateType {
    Present = 0,
    Add = 1,
    Modify = 2,
    Delete = 3,
}

#[derive(AsnType, Decode, Encode)]
struct RealSyncStateControl {
    state: RealSyncStateType,
    entry_uuid: OctetString,
    cookie: Option<OctetString>,
}

#[derive(AsnType, Decode, Encode)]
struct RealSyncDoneControl {
    cookie: Option<OctetString>,
    #[rasn(default)]
    refresh_deletes: bool,
}

#[derive(AsnType, Decode, Encode)]
struct RealRefreshInfo {
    cookie: Option<OctetString>,
    #[rasn(default = "default_true")]
    refresh_done: bool,
}

#[derive(AsnType, Decode, Encode)]
struct RealSyncIdSetInfo {
    cookie: Option<OctetString>,
    #[rasn(default)]
    refresh_deletes: bool,
    sync_uuids: SetOf<OctetString>,
}

#[derive(AsnType, Decode, Encode)]
#[rasn(choice)]
enum RealSyncInfoValue {
    #[rasn(tag(context, 0))]
    NewCookie(OctetString),
    #[rasn(tag(context, 1))]
    RefreshDelete(RealRefreshInfo),
    #[rasn(tag(context, 2))]
    RefreshPresent(RealRefreshInfo),
    #[rasn(tag(context, 3))]
    SyncIdSet(RealSyncIdSetInfo),
}

const fn default_true() -> bool {
    true
}

impl From<RealSyncRefreshMode> for SyncRefreshMode {
    fn from(value: RealSyncRefreshMode) -> Self {
        match value {
            RealSyncRefreshMode::RefreshOnly => Self::RefreshOnly,
            RealSyncRefreshMode::RefreshAndPersist => Self::RefreshAndPersist,
        }
    }
}

impl From<SyncRefreshMode> for RealSyncRefreshMode {
    fn from(value: SyncRefreshMode) -> Self {
        match value {
            SyncRefreshMode::RefreshOnly => Self::RefreshOnly,
            SyncRefreshMode::RefreshAndPersist => Self::RefreshAndPersist,
        }
    }
}

impl From<RealSyncStateType> for SyncStateType {
    fn from(value: RealSyncStateType) -> Self {
        match value {
            RealSyncStateType::Present => Self::Present,
            RealSyncStateType::Add => Self::Add,
            RealSyncStateType::Modify => Self::Modify,
            RealSyncStateType::Delete => Self::Delete,
        }
    }
}

impl From<SyncStateType> for RealSyncStateType {
    fn from(value: SyncStateType) -> Self {
        match value {
            SyncStateType::Present => Self::Present,
            SyncStateType::Add => Self::Add,
            SyncStateType::Modify => Self::Modify,
            SyncStateType::Delete => Self::Delete,
        }
    }
}

fn decode_uuid(bytes: &[u8]) -> Result<Uuid, SyncControlError> {
    Uuid::from_slice(bytes).map_err(|_| SyncControlError::InvalidUuidLength(bytes.len()))
}

pub fn decode_sync_request_control(
    value: Option<&[u8]>,
) -> Result<SyncRequestControl, SyncControlError> {
    let value = value.ok_or(SyncControlError::MissingValue)?;
    let decoded: RealSyncRequestControl =
        rasn::ber::decode(value).map_err(|err| SyncControlError::InvalidAsn1(err.to_string()))?;
    Ok(SyncRequestControl {
        mode: decoded.mode.into(),
        cookie: decoded.cookie.map(|cookie| cookie.as_ref().to_vec()),
        reload_hint: decoded.reload_hint,
    })
}

pub fn encode_sync_request_control(
    request: &SyncRequestControl,
) -> Result<Vec<u8>, SyncControlError> {
    rasn::ber::encode(&RealSyncRequestControl {
        mode: request.mode.into(),
        cookie: request.cookie.clone().map(Into::into),
        reload_hint: request.reload_hint,
    })
    .map_err(|err| SyncControlError::InvalidAsn1(err.to_string()))
}

pub fn decode_sync_state_control(
    value: Option<&[u8]>,
) -> Result<SyncStateControl, SyncControlError> {
    let value = value.ok_or(SyncControlError::MissingValue)?;
    let decoded: RealSyncStateControl =
        rasn::ber::decode(value).map_err(|err| SyncControlError::InvalidAsn1(err.to_string()))?;
    Ok(SyncStateControl {
        state: decoded.state.into(),
        entry_uuid: decode_uuid(decoded.entry_uuid.as_ref())?,
        cookie: decoded.cookie.map(|cookie| cookie.as_ref().to_vec()),
    })
}

pub fn encode_sync_state_control(state: &SyncStateControl) -> Result<Vec<u8>, SyncControlError> {
    rasn::ber::encode(&RealSyncStateControl {
        state: state.state.into(),
        entry_uuid: state.entry_uuid.as_bytes().to_vec().into(),
        cookie: state.cookie.clone().map(Into::into),
    })
    .map_err(|err| SyncControlError::InvalidAsn1(err.to_string()))
}

pub fn decode_sync_done_control(value: Option<&[u8]>) -> Result<SyncDoneControl, SyncControlError> {
    let value = value.ok_or(SyncControlError::MissingValue)?;
    let decoded: RealSyncDoneControl =
        rasn::ber::decode(value).map_err(|err| SyncControlError::InvalidAsn1(err.to_string()))?;
    Ok(SyncDoneControl {
        cookie: decoded.cookie.map(|cookie| cookie.as_ref().to_vec()),
        refresh_deletes: decoded.refresh_deletes,
    })
}

pub fn encode_sync_done_control(done: &SyncDoneControl) -> Result<Vec<u8>, SyncControlError> {
    rasn::ber::encode(&RealSyncDoneControl {
        cookie: done.cookie.clone().map(Into::into),
        refresh_deletes: done.refresh_deletes,
    })
    .map_err(|err| SyncControlError::InvalidAsn1(err.to_string()))
}

pub fn decode_sync_info_value(value: &[u8]) -> Result<SyncInfoValue, SyncControlError> {
    let decoded: RealSyncInfoValue =
        rasn::ber::decode(value).map_err(|err| SyncControlError::InvalidAsn1(err.to_string()))?;
    match decoded {
        RealSyncInfoValue::NewCookie(cookie) => {
            Ok(SyncInfoValue::NewCookie(cookie.as_ref().to_vec()))
        }
        RealSyncInfoValue::RefreshDelete(info) => Ok(SyncInfoValue::RefreshDelete {
            cookie: info.cookie.map(|cookie| cookie.as_ref().to_vec()),
            refresh_done: info.refresh_done,
        }),
        RealSyncInfoValue::RefreshPresent(info) => Ok(SyncInfoValue::RefreshPresent {
            cookie: info.cookie.map(|cookie| cookie.as_ref().to_vec()),
            refresh_done: info.refresh_done,
        }),
        RealSyncInfoValue::SyncIdSet(info) => Ok(SyncInfoValue::SyncIdSet {
            cookie: info.cookie.map(|cookie| cookie.as_ref().to_vec()),
            refresh_deletes: info.refresh_deletes,
            sync_uuids: info
                .sync_uuids
                .into_iter()
                .map(|uuid| decode_uuid(uuid.as_ref()))
                .collect::<Result<Vec<_>, _>>()?,
        }),
    }
}

pub fn encode_sync_info_value(info: &SyncInfoValue) -> Result<Vec<u8>, SyncControlError> {
    let real = match info {
        SyncInfoValue::NewCookie(cookie) => RealSyncInfoValue::NewCookie(cookie.clone().into()),
        SyncInfoValue::RefreshDelete {
            cookie,
            refresh_done,
        } => RealSyncInfoValue::RefreshDelete(RealRefreshInfo {
            cookie: cookie.clone().map(Into::into),
            refresh_done: *refresh_done,
        }),
        SyncInfoValue::RefreshPresent {
            cookie,
            refresh_done,
        } => RealSyncInfoValue::RefreshPresent(RealRefreshInfo {
            cookie: cookie.clone().map(Into::into),
            refresh_done: *refresh_done,
        }),
        SyncInfoValue::SyncIdSet {
            cookie,
            refresh_deletes,
            sync_uuids,
        } => RealSyncInfoValue::SyncIdSet(RealSyncIdSetInfo {
            cookie: cookie.clone().map(Into::into),
            refresh_deletes: *refresh_deletes,
            sync_uuids: sync_uuids
                .iter()
                .map(|uuid| uuid.as_bytes().to_vec().into())
                .collect(),
        }),
    };

    rasn::ber::encode(&real).map_err(|err| SyncControlError::InvalidAsn1(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_request_round_trips() {
        let control = SyncRequestControl {
            mode: SyncRefreshMode::RefreshAndPersist,
            cookie: Some(b"csn-1".to_vec()),
            reload_hint: true,
        };

        let encoded = encode_sync_request_control(&control).unwrap();
        let decoded = decode_sync_request_control(Some(&encoded)).unwrap();

        assert_eq!(decoded, control);
    }

    #[test]
    fn sync_state_round_trips() {
        let control = SyncStateControl {
            state: SyncStateType::Modify,
            entry_uuid: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            cookie: Some(b"csn-2".to_vec()),
        };

        let encoded = encode_sync_state_control(&control).unwrap();
        let decoded = decode_sync_state_control(Some(&encoded)).unwrap();

        assert_eq!(decoded, control);
    }

    #[test]
    fn sync_done_round_trips() {
        let control = SyncDoneControl {
            cookie: Some(b"csn-3".to_vec()),
            refresh_deletes: true,
        };

        let encoded = encode_sync_done_control(&control).unwrap();
        let decoded = decode_sync_done_control(Some(&encoded)).unwrap();

        assert_eq!(decoded, control);
    }

    #[test]
    fn sync_info_refresh_present_round_trips() {
        let value = SyncInfoValue::RefreshPresent {
            cookie: Some(b"csn-4".to_vec()),
            refresh_done: true,
        };

        let encoded = encode_sync_info_value(&value).unwrap();
        let decoded = decode_sync_info_value(&encoded).unwrap();

        assert_eq!(decoded, value);
    }

    #[test]
    fn sync_info_sync_id_set_round_trips() {
        let value = SyncInfoValue::SyncIdSet {
            cookie: Some(b"csn-5".to_vec()),
            refresh_deletes: false,
            sync_uuids: vec![
                Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
                Uuid::parse_str("550e8400-e29b-41d4-a716-446655440001").unwrap(),
            ],
        };

        let encoded = encode_sync_info_value(&value).unwrap();
        let decoded = decode_sync_info_value(&encoded).unwrap();

        assert_eq!(decoded, value);
    }
}

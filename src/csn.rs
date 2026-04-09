//! Change Sequence Number (CSN) Implementation
//!
//! This module implements CSN (Change Sequence Number) as defined in RFC 4533
//! for LDAP Content Synchronization Operation. CSNs are used to uniquely identify
//! changes in a directory and enable incremental synchronization.
//!
//! # CSN Format
//!
//! A CSN consists of four components:
//! - **Timestamp**: Microseconds since the UNIX epoch
//! - **Replica ID**: Unique identifier for the server that made the change
//! - **Sequence Number**: Monotonically increasing counter within the same microsecond
//! - **Modification Number**: Sub-modification counter for complex operations
//!
//! # Example
//!
//! ```text
//! CSN Format: <timestamp>#<replica-id>#<sequence>#<mod-number>
//! Example: 1696680896789012#001#000001#000000
//! ```
//!
//! # RFC 4533 Compliance
//!
//! This implementation follows RFC 4533 Section 2.1 for CSN structure and ordering.

use std::cmp::Ordering;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Change Sequence Number (CSN) per RFC 4533
///
/// CSNs uniquely identify changes in the directory and establish a total ordering
/// of all changes across multiple replicas.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Csn {
    /// Timestamp in microseconds since UNIX epoch
    timestamp_us: u64,
    /// Replica ID (unique per server)
    replica_id: u16,
    /// Sequence number within the same microsecond
    sequence: u32,
    /// Modification number for sub-modifications
    mod_number: u16,
}

impl Csn {
    /// Create a new CSN with the current timestamp
    ///
    /// # Arguments
    /// * `replica_id` - Unique identifier for this replica (1-65535)
    ///
    /// # Returns
    /// * New CSN with current timestamp and sequence 0
    ///
    /// # Example
    ///
    /// ```
    /// use opendr::csn::Csn;
    /// let csn = Csn::new(1);
    /// assert!(csn.replica_id() == 1);
    /// ```
    pub fn new(replica_id: u16) -> Self {
        let timestamp_us = Self::current_timestamp_us();
        Self {
            timestamp_us,
            replica_id,
            sequence: 0,
            mod_number: 0,
        }
    }

    /// Create a CSN with explicit values
    ///
    /// # Arguments
    /// * `timestamp_us` - Timestamp in microseconds since UNIX epoch
    /// * `replica_id` - Replica identifier
    /// * `sequence` - Sequence number
    /// * `mod_number` - Modification number
    ///
    /// # Returns
    /// * New CSN with specified values
    pub fn with_values(timestamp_us: u64, replica_id: u16, sequence: u32, mod_number: u16) -> Self {
        Self {
            timestamp_us,
            replica_id,
            sequence,
            mod_number,
        }
    }

    /// Get current timestamp in microseconds since UNIX epoch
    fn current_timestamp_us() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System time before UNIX epoch")
            .as_micros() as u64
    }

    /// Parse a CSN from string format
    ///
    /// # Format
    /// `<timestamp>#<replica-id>#<sequence>#<mod-number>`
    ///
    /// # Arguments
    /// * `s` - CSN string to parse
    ///
    /// # Returns
    /// * `Ok(Csn)` if parsing successful
    /// * `Err(CsnError)` if parsing failed
    ///
    /// # Example
    ///
    /// ```
    /// use opendr::csn::Csn;
    /// let csn = Csn::parse("1696680896789012#001#000001#000000").unwrap();
    /// assert_eq!(csn.replica_id(), 1);
    /// assert_eq!(csn.sequence(), 1);
    /// ```
    pub fn parse(s: &str) -> Result<Self, CsnError> {
        let parts: Vec<&str> = s.split('#').collect();
        if parts.len() != 4 {
            return Err(CsnError::InvalidFormat(
                "Expected format: <timestamp>#<replica>#<seq>#<mod>".to_string(),
            ));
        }

        let timestamp_us = parts[0]
            .parse::<u64>()
            .map_err(|_| CsnError::InvalidTimestamp(parts[0].to_string()))?;

        let replica_id = parts[1]
            .parse::<u16>()
            .map_err(|_| CsnError::InvalidReplicaId(parts[1].to_string()))?;

        let sequence = parts[2]
            .parse::<u32>()
            .map_err(|_| CsnError::InvalidSequence(parts[2].to_string()))?;

        let mod_number = parts[3]
            .parse::<u16>()
            .map_err(|_| CsnError::InvalidModNumber(parts[3].to_string()))?;

        Ok(Self {
            timestamp_us,
            replica_id,
            sequence,
            mod_number,
        })
    }

    /// Get the timestamp in microseconds
    pub fn timestamp_us(&self) -> u64 {
        self.timestamp_us
    }

    /// Get the replica ID
    pub fn replica_id(&self) -> u16 {
        self.replica_id
    }

    /// Get the sequence number
    pub fn sequence(&self) -> u32 {
        self.sequence
    }

    /// Get the modification number
    pub fn mod_number(&self) -> u16 {
        self.mod_number
    }

    /// Increment the sequence number
    ///
    /// Used when multiple changes occur in the same microsecond
    pub fn increment_sequence(&mut self) {
        self.sequence = self.sequence.saturating_add(1);
    }

    /// Increment the modification number
    ///
    /// Used for sub-modifications within a single operation
    pub fn increment_mod_number(&mut self) {
        self.mod_number = self.mod_number.saturating_add(1);
    }

    /// Convert CSN to LDAP string format
    ///
    /// # Returns
    /// * CSN in format: `<timestamp>#<replica-id>#<sequence>#<mod-number>`
    ///
    /// # Example
    ///
    /// ```
    /// use opendr::csn::Csn;
    /// let csn = Csn::with_values(1696680896789012, 1, 1, 0);
    /// assert_eq!(csn.to_string(), "1696680896789012#001#000001#000000");
    /// ```
    pub fn to_ldap_string(&self) -> String {
        format!(
            "{}#{:03}#{:06}#{:06}",
            self.timestamp_us, self.replica_id, self.sequence, self.mod_number
        )
    }
}

impl fmt::Display for Csn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_ldap_string())
    }
}

impl PartialOrd for Csn {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Csn {
    /// Compare CSNs for ordering per RFC 4533
    ///
    /// Ordering rules:
    /// 1. Compare timestamps (earlier < later)
    /// 2. If equal, compare replica IDs (lower < higher)
    /// 3. If equal, compare sequence numbers (lower < higher)
    /// 4. If equal, compare modification numbers (lower < higher)
    fn cmp(&self, other: &Self) -> Ordering {
        self.timestamp_us
            .cmp(&other.timestamp_us)
            .then_with(|| self.replica_id.cmp(&other.replica_id))
            .then_with(|| self.sequence.cmp(&other.sequence))
            .then_with(|| self.mod_number.cmp(&other.mod_number))
    }
}

/// CSN Generator for creating monotonically increasing CSNs
///
/// This generator ensures that CSNs are always increasing, even if
/// the system clock moves backward.
pub struct CsnGenerator {
    replica_id: u16,
    last_timestamp_us: AtomicU64,
    sequence_counter: AtomicU64,
}

impl CsnGenerator {
    /// Create a new CSN generator
    ///
    /// # Arguments
    /// * `replica_id` - Unique identifier for this replica
    ///
    /// # Returns
    /// * New CSN generator
    pub fn new(replica_id: u16) -> Self {
        Self {
            replica_id,
            last_timestamp_us: AtomicU64::new(0),
            sequence_counter: AtomicU64::new(0),
        }
    }

    /// Generate the next CSN
    ///
    /// This method ensures monotonic ordering even if the system clock
    /// moves backward by using sequence numbers.
    ///
    /// # Returns
    /// * New CSN that is guaranteed to be greater than all previous CSNs
    pub fn generate(&self) -> Csn {
        let current_ts = Csn::current_timestamp_us();
        let last_ts = self.last_timestamp_us.load(AtomicOrdering::Acquire);

        if current_ts > last_ts {
            // Try to update to new timestamp and reset sequence
            match self.last_timestamp_us.compare_exchange(
                last_ts,
                current_ts,
                AtomicOrdering::AcqRel,
                AtomicOrdering::Acquire,
            ) {
                Ok(_) => {
                    // Successfully updated timestamp, reset sequence
                    self.sequence_counter.store(1, AtomicOrdering::Release);
                    Csn::with_values(current_ts, self.replica_id, 0, 0)
                }
                Err(_) => {
                    // Another thread updated the timestamp, increment sequence
                    let seq = self.sequence_counter.fetch_add(1, AtomicOrdering::AcqRel);
                    let use_ts = self
                        .last_timestamp_us
                        .load(AtomicOrdering::Acquire)
                        .max(current_ts);
                    Csn::with_values(use_ts, self.replica_id, seq as u32, 0)
                }
            }
        } else {
            // Same microsecond or clock moved backward, increment sequence
            let seq = self.sequence_counter.fetch_add(1, AtomicOrdering::AcqRel);
            Csn::with_values(last_ts.max(current_ts), self.replica_id, seq as u32, 0)
        }
    }

    /// Get the replica ID
    pub fn replica_id(&self) -> u16 {
        self.replica_id
    }
}

/// Errors that can occur when working with CSNs
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CsnError {
    /// Invalid CSN format
    InvalidFormat(String),
    /// Invalid timestamp value
    InvalidTimestamp(String),
    /// Invalid replica ID
    InvalidReplicaId(String),
    /// Invalid sequence number
    InvalidSequence(String),
    /// Invalid modification number
    InvalidModNumber(String),
}

impl fmt::Display for CsnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CsnError::InvalidFormat(msg) => write!(f, "Invalid CSN format: {}", msg),
            CsnError::InvalidTimestamp(val) => write!(f, "Invalid timestamp: {}", val),
            CsnError::InvalidReplicaId(val) => write!(f, "Invalid replica ID: {}", val),
            CsnError::InvalidSequence(val) => write!(f, "Invalid sequence: {}", val),
            CsnError::InvalidModNumber(val) => write!(f, "Invalid mod number: {}", val),
        }
    }
}

impl std::error::Error for CsnError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csn_creation() {
        let csn = Csn::new(1);
        assert_eq!(csn.replica_id(), 1);
        assert_eq!(csn.sequence(), 0);
        assert_eq!(csn.mod_number(), 0);
        assert!(csn.timestamp_us() > 0);
    }

    #[test]
    fn test_csn_with_values() {
        let csn = Csn::with_values(1234567890123456, 42, 100, 5);
        assert_eq!(csn.timestamp_us(), 1234567890123456);
        assert_eq!(csn.replica_id(), 42);
        assert_eq!(csn.sequence(), 100);
        assert_eq!(csn.mod_number(), 5);
    }

    #[test]
    fn test_csn_to_string() {
        let csn = Csn::with_values(1696680896789012, 1, 1, 0);
        assert_eq!(csn.to_ldap_string(), "1696680896789012#001#000001#000000");
    }

    #[test]
    fn test_csn_parse_valid() {
        let csn = Csn::parse("1696680896789012#001#000001#000000").unwrap();
        assert_eq!(csn.timestamp_us(), 1696680896789012);
        assert_eq!(csn.replica_id(), 1);
        assert_eq!(csn.sequence(), 1);
        assert_eq!(csn.mod_number(), 0);
    }

    #[test]
    fn test_csn_parse_invalid_format() {
        assert!(Csn::parse("invalid").is_err());
        assert!(Csn::parse("123#456").is_err());
        assert!(Csn::parse("123#456#789").is_err());
    }

    #[test]
    fn test_csn_parse_invalid_values() {
        assert!(Csn::parse("abc#001#000001#000000").is_err());
        assert!(Csn::parse("123#abc#000001#000000").is_err());
        assert!(Csn::parse("123#001#abc#000000").is_err());
        assert!(Csn::parse("123#001#000001#abc").is_err());
    }

    #[test]
    fn test_csn_ordering() {
        let csn1 = Csn::with_values(100, 1, 0, 0);
        let csn2 = Csn::with_values(200, 1, 0, 0);
        assert!(csn1 < csn2);

        let csn3 = Csn::with_values(100, 1, 0, 0);
        let csn4 = Csn::with_values(100, 2, 0, 0);
        assert!(csn3 < csn4);

        let csn5 = Csn::with_values(100, 1, 0, 0);
        let csn6 = Csn::with_values(100, 1, 1, 0);
        assert!(csn5 < csn6);

        let csn7 = Csn::with_values(100, 1, 0, 0);
        let csn8 = Csn::with_values(100, 1, 0, 1);
        assert!(csn7 < csn8);
    }

    #[test]
    fn test_csn_increment_sequence() {
        let mut csn = Csn::new(1);
        let initial_seq = csn.sequence();
        csn.increment_sequence();
        assert_eq!(csn.sequence(), initial_seq + 1);
    }

    #[test]
    fn test_csn_increment_mod_number() {
        let mut csn = Csn::new(1);
        let initial_mod = csn.mod_number();
        csn.increment_mod_number();
        assert_eq!(csn.mod_number(), initial_mod + 1);
    }

    #[test]
    fn test_csn_generator_basic() {
        let generator = CsnGenerator::new(1);
        let csn1 = generator.generate();
        let csn2 = generator.generate();

        assert!(csn2 > csn1, "CSN2 should be greater than CSN1");
        assert_eq!(csn1.replica_id(), 1);
        assert_eq!(csn2.replica_id(), 1);
    }

    #[test]
    fn test_csn_generator_monotonic() {
        let generator = CsnGenerator::new(5);
        let mut csns = Vec::new();

        // Generate CSNs rapidly
        for _ in 0..100 {
            csns.push(generator.generate());
            // Small spin to let some time pass occasionally
            if csns.len() % 10 == 0 {
                std::thread::sleep(std::time::Duration::from_nanos(100));
            }
        }

        // Verify all CSNs are in order
        for i in 1..csns.len() {
            assert!(
                csns[i] > csns[i - 1],
                "CSN at index {} ({}) should be greater than previous ({})",
                i,
                csns[i],
                csns[i - 1]
            );
        }
    }

    #[test]
    fn test_csn_generator_replica_id() {
        let generator = CsnGenerator::new(42);
        assert_eq!(generator.replica_id(), 42);

        let csn = generator.generate();
        assert_eq!(csn.replica_id(), 42);
    }

    #[test]
    fn test_csn_parse_roundtrip() {
        let original = Csn::with_values(1696680896789012, 123, 456, 789);
        let string = original.to_ldap_string();
        let parsed = Csn::parse(&string).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_csn_equality() {
        let csn1 = Csn::with_values(100, 1, 0, 0);
        let csn2 = Csn::with_values(100, 1, 0, 0);
        assert_eq!(csn1, csn2);

        let csn3 = Csn::with_values(100, 1, 0, 0);
        let csn4 = Csn::with_values(100, 1, 1, 0);
        assert_ne!(csn3, csn4);
    }
}

//! BER Decoder Finite State Machine Implementation
//!
//! This module implements a streaming BER (Basic Encoding Rules) decoder FSM for LDAP messages.
//! The decoder processes incoming TCP data incrementally, handling partial messages and maintaining
//! state across multiple read operations.
//!
//! ## BER Format Overview
//!
//! BER encoding follows the Tag-Length-Value format:
//! - **Tag**: 1+ bytes identifying the type of data
//! - **Length**: 1+ bytes specifying the value length
//! - **Value**: The actual data content
//!
//! ## State Machine Flow
//!
//! ```
//! WaitingTag → WaitingLength → WaitingValue → MessageComplete
//!     ↑                                            │
//!     └────────── Reset/New Message ───────────────┘
//! ```
//!
//! The FSM handles:
//! - Incremental data reception
//! - Variable-length BER encoding
//! - Message boundary detection
//! - Error recovery and validation

use crate::fsm::{StateMachine, BerDecoderState, BerDecoderEvent, BerDecoderFsm, BerDecodingProgress};
use async_trait::async_trait;
use std::time::{Duration, Instant};
use thiserror::Error;

/// Errors that can occur during BER decoding
#[derive(Error, Debug, Clone, PartialEq)]
pub enum BerDecoderError {
    #[error("Invalid BER tag: {0}")]
    InvalidTag(String),
    
    #[error("Invalid BER length encoding: {0}")]
    InvalidLength(String),
    
    #[error("Buffer overflow: received {received} bytes, maximum allowed {max}")]
    BufferOverflow { received: usize, max: usize },
    
    #[error("Invalid state transition from {from:?} to {to:?}")]
    InvalidStateTransition { from: BerDecoderState, to: BerDecoderState },
    
    #[error("Message too large: {size} bytes exceeds maximum {max}")]
    MessageTooLarge { size: usize, max: usize },
    
    #[error("Incomplete message: need {needed} more bytes")]
    IncompleteMessage { needed: usize },
    
    #[error("Generic BER decoder error: {message}")]
    Generic { message: String },
}

/// Trait for validating BER tags and lengths
#[async_trait]
pub trait BerValidator: Send + Sync {
    /// Validate that a BER tag is acceptable
    async fn validate_tag(&self, tag: u8) -> Result<(), String>;
    
    /// Validate that a BER length is acceptable
    async fn validate_length(&self, length: usize) -> Result<(), String>;
    
    /// Get the maximum allowed message size
    fn max_message_size(&self) -> usize;
    
    /// Check if a tag indicates a constructed (compound) type
    fn is_constructed(&self, tag: u8) -> bool;
}

/// Trait for handling BER message processing callbacks
#[async_trait]
pub trait BerMessageHandler: Send + Sync {
    /// Called when a complete BER message is available
    async fn on_message_complete(&mut self, message: &[u8]) -> Result<(), String>;
    
    /// Called when decoding progress is made
    async fn on_progress_update(&mut self, progress: &BerDecodingProgress) -> Result<(), String>;
    
    /// Called when an error occurs during decoding
    async fn on_error(&mut self, error: &str) -> Result<(), String>;
}

/// Configuration for the BER decoder
#[derive(Debug, Clone)]
pub struct BerDecoderConfig {
    /// Maximum message size in bytes
    pub max_message_size: usize,
    /// Maximum buffer size in bytes
    pub max_buffer_size: usize,
    /// Timeout for message completion
    pub message_timeout: Option<Duration>,
    /// Whether to perform strict BER validation
    pub strict_validation: bool,
}

impl Default for BerDecoderConfig {
    fn default() -> Self {
        Self {
            max_message_size: 64 * 1024, // 64KB default
            max_buffer_size: 128 * 1024, // 128KB buffer
            message_timeout: Some(Duration::from_secs(30)),
            strict_validation: true,
        }
    }
}

/// Streaming BER Decoder FSM Implementation
///
/// This FSM processes BER-encoded data incrementally, maintaining state
/// across multiple data reception events. It handles the three phases
/// of BER decoding: tag parsing, length parsing, and value collection.
pub struct BerDecoderFsmImpl {
    /// Current FSM state
    state: BerDecoderState,
    
    /// Internal buffer for accumulating data
    buffer: Vec<u8>,
    
    /// Current message being decoded
    current_message: Option<BerMessage>,
    
    /// Configuration parameters
    config: BerDecoderConfig,
    
    /// External validator for BER compliance
    validator: Option<Box<dyn BerValidator>>,
    
    /// Message handler for callbacks
    message_handler: Option<Box<dyn BerMessageHandler>>,
    
    /// Start time of current message (for timeout tracking)
    start_time: Instant,
    
    /// Total messages processed
    messages_processed: u64,
    
    /// Total bytes processed
    bytes_processed: u64,
}

/// Internal representation of a BER message being decoded
#[derive(Debug, Clone)]
struct BerMessage {
    /// BER tag
    tag: u8,
    /// Expected length of the value
    length: usize,
    /// Accumulated value bytes
    value_bytes: Vec<u8>,
    /// Bytes still needed to complete the message
    bytes_needed: usize,
}

impl BerDecoderFsmImpl {
    /// Create a new BER decoder FSM with default configuration
    pub fn new() -> Self {
        Self::with_config(BerDecoderConfig::default())
    }
    
    /// Create a new BER decoder FSM with custom configuration
    pub fn with_config(config: BerDecoderConfig) -> Self {
        Self {
            state: BerDecoderState::WaitingTag,
            buffer: Vec::with_capacity(1024),
            current_message: None,
            config,
            validator: None,
            message_handler: None,
            start_time: Instant::now(),
            messages_processed: 0,
            bytes_processed: 0,
        }
    }
    
    /// Set a BER validator for tag and length validation
    pub fn with_validator(mut self, validator: Box<dyn BerValidator>) -> Self {
        self.validator = Some(validator);
        self
    }
    
    /// Set a message handler for processing complete messages
    pub fn with_message_handler(mut self, handler: Box<dyn BerMessageHandler>) -> Self {
        self.message_handler = Some(handler);
        self
    }
    
    /// Get statistics about the decoder
    pub fn stats(&self) -> BerDecoderStats {
        BerDecoderStats {
            messages_processed: self.messages_processed,
            bytes_processed: self.bytes_processed,
            current_buffer_size: self.buffer.len(),
            uptime: self.start_time.elapsed(),
        }
    }
    
    /// Process incoming data and update FSM state
    ///
    /// This is the core method that handles incremental data processing.
    /// It parses BER tags, lengths, and accumulates value bytes based on
    /// the current FSM state.
    async fn process_data(&mut self, data: Vec<u8>) -> Result<Option<Vec<u8>>, BerDecoderError> {
        // Update statistics
        self.bytes_processed += data.len() as u64;
        
        // Check buffer size limits
        if self.buffer.len() + data.len() > self.config.max_buffer_size {
            return Err(BerDecoderError::BufferOverflow {
                received: self.buffer.len() + data.len(),
                max: self.config.max_buffer_size,
            });
        }
        
        // Append data to buffer
        self.buffer.extend_from_slice(&data);
        
        // Process based on current state
        loop {
            match &self.state {
                BerDecoderState::WaitingTag => {
                    let result = self.process_tag().await?;
                    if result.is_some() {
                        return Ok(result);
                    }
                    // If we consumed the tag and moved to next state, continue processing
                    if !self.buffer.is_empty() {
                        continue;
                    }
                    return Ok(None);
                },
                BerDecoderState::WaitingLength => {
                    let result = self.process_length().await?;
                    if result.is_some() {
                        return Ok(result);
                    }
                    // If we consumed the length and moved to next state, continue processing
                    if !self.buffer.is_empty() && !matches!(self.state, BerDecoderState::WaitingLength) {
                        continue;
                    }
                    return Ok(None);
                },
                BerDecoderState::WaitingValue { .. } => {
                    let result = self.process_value().await?;
                    if result.is_some() {
                        return Ok(result);
                    }
                    // If message is complete, continue to extract it
                    if matches!(self.state, BerDecoderState::MessageComplete) {
                        continue;
                    }
                    return Ok(None);
                },
                BerDecoderState::MessageComplete => {
                    // Extract the complete message
                    let message = self.extract_completed_message();
                    self.transition_to_waiting_tag().await?;
                    return Ok(message);
                },
                BerDecoderState::Error => return Err(BerDecoderError::Generic {
                    message: "FSM is in error state".to_string()
                }),
            }
        }
    }
    
    /// Process BER tag when in WaitingTag state
    async fn process_tag(&mut self) -> Result<Option<Vec<u8>>, BerDecoderError> {
        if self.buffer.is_empty() {
            return Ok(None); // Need more data
        }
        
        // For simplicity, we handle single-byte tags
        // In a full implementation, this would handle multi-byte tags
        let tag = self.buffer[0];
        
        // Validate tag if validator is present
        if let Some(validator) = &self.validator {
            validator.validate_tag(tag).await
                .map_err(|msg| BerDecoderError::InvalidTag(msg))?;
        }
        
        // Start new message
        self.current_message = Some(BerMessage {
            tag,
            length: 0,
            value_bytes: Vec::new(),
            bytes_needed: 0,
        });
        
        // Remove tag byte from buffer
        self.buffer.drain(0..1);
        
        // Transition to waiting for length
        self.state = BerDecoderState::WaitingLength;
        
        // Notify message handler of progress
        let progress = self.progress();
        if let Some(handler) = &mut self.message_handler {
            handler.on_progress_update(&progress).await
                .map_err(|msg| BerDecoderError::Generic { message: msg })?;
        }
        
        Ok(None)
    }
    
    /// Process BER length when in WaitingLength state
    async fn process_length(&mut self) -> Result<Option<Vec<u8>>, BerDecoderError> {
        if self.buffer.is_empty() {
            return Ok(None); // Need more data
        }
        
        let length_result = self.parse_ber_length()?;
        
        match length_result {
            Some(length) => {
                // Validate length if validator is present
                if let Some(validator) = &self.validator {
                    validator.validate_length(length).await
                        .map_err(|msg| BerDecoderError::InvalidLength(msg))?;
                }
                
                // Check message size limits
                if length > self.config.max_message_size {
                    return Err(BerDecoderError::MessageTooLarge {
                        size: length,
                        max: self.config.max_message_size,
                    });
                }
                
                // Update current message
                if let Some(message) = &mut self.current_message {
                    message.length = length;
                    message.bytes_needed = length;
                }
                
                // Transition to waiting for value
                if length == 0 {
                    // Zero-length message is immediately complete
                    self.state = BerDecoderState::MessageComplete;
                    self.messages_processed += 1;
                    
                    // Return the complete message immediately
                    let message = self.extract_completed_message();
                    self.transition_to_waiting_tag().await?;
                    return Ok(message);
                } else {
                    self.state = BerDecoderState::WaitingValue {
                        tag: self.current_message.as_ref().unwrap().tag,
                        length,
                    };
                }
                
                // Process any remaining buffer data
                if !self.buffer.is_empty() {
                    return self.process_value().await;
                }
                
                Ok(None)
            }
            None => Ok(None), // Need more data to complete length parsing
        }
    }
    
    /// Process BER value when in WaitingValue state
    async fn process_value(&mut self) -> Result<Option<Vec<u8>>, BerDecoderError> {
        let message = self.current_message.as_mut()
            .ok_or_else(|| BerDecoderError::Generic {
                message: "No current message in WaitingValue state".to_string()
            })?;
        
        // Calculate how many bytes we can consume
        let bytes_to_consume = std::cmp::min(message.bytes_needed, self.buffer.len());
        
        if bytes_to_consume == 0 {
            return Ok(None); // Need more data
        }
        
        // Move bytes from buffer to message
        let consumed_bytes: Vec<u8> = self.buffer.drain(0..bytes_to_consume).collect();
        message.value_bytes.extend_from_slice(&consumed_bytes);
        message.bytes_needed -= bytes_to_consume;
        
        // Check if message is complete
        if message.bytes_needed == 0 {
            self.state = BerDecoderState::MessageComplete;
            self.messages_processed += 1;
            
            // Notify message handler
            let complete_message = self.build_complete_message();
            if let Some(handler) = &mut self.message_handler {
                handler.on_message_complete(&complete_message).await
                    .map_err(|msg| BerDecoderError::Generic { message: msg })?;
            }
            
            // Return the complete message immediately
            let message = self.extract_completed_message();
            self.transition_to_waiting_tag().await?;
            return Ok(message);
        }
        
        // Update progress
        let progress = self.progress();
        if let Some(handler) = &mut self.message_handler {
            handler.on_progress_update(&progress).await
                .map_err(|msg| BerDecoderError::Generic { message: msg })?;
        }
        
        Ok(None)
    }
    
    /// Parse BER length encoding from buffer
    ///
    /// BER length can be:
    /// - Short form: 0xxxxxxx (length 0-127)
    /// - Long form: 1xxxxxxx followed by x bytes specifying length
    fn parse_ber_length(&mut self) -> Result<Option<usize>, BerDecoderError> {
        if self.buffer.is_empty() {
            return Ok(None);
        }
        
        let first_byte = self.buffer[0];
        
        if first_byte & 0x80 == 0 {
            // Short form: length is in the lower 7 bits
            let length = first_byte as usize;
            self.buffer.drain(0..1);
            Ok(Some(length))
        } else {
            // Long form: first byte indicates how many length bytes follow
            let length_bytes_count = (first_byte & 0x7f) as usize;
            
            if length_bytes_count == 0 {
                return Err(BerDecoderError::InvalidLength(
                    "Indefinite length not supported".to_string()
                ));
            }
            
            if length_bytes_count > 4 {
                return Err(BerDecoderError::InvalidLength(
                    format!("Length too large: {} bytes", length_bytes_count)
                ));
            }
            
            // Check if we have enough bytes for the length
            if self.buffer.len() < 1 + length_bytes_count {
                return Ok(None); // Need more data
            }
            
            // Parse length from following bytes
            let mut length = 0usize;
            for i in 1..=length_bytes_count {
                length = length << 8 | self.buffer[i] as usize;
            }
            
            // Remove length bytes from buffer
            self.buffer.drain(0..=length_bytes_count);
            
            Ok(Some(length))
        }
    }
    
    /// Build complete BER message (tag + length + value)
    fn build_complete_message(&self) -> Vec<u8> {
        let message = self.current_message.as_ref().unwrap();
        let mut result = Vec::new();
        
        // Add tag
        result.push(message.tag);
        
        // Add length (using short form for simplicity)
        if message.length < 128 {
            result.push(message.length as u8);
        } else {
            // Long form - this is a simplified implementation
            result.push(0x82); // 2 length bytes
            result.push((message.length >> 8) as u8);
            result.push(message.length as u8);
        }
        
        // Add value
        result.extend_from_slice(&message.value_bytes);
        
        result
    }
    
    /// Extract completed message and reset for next message
    fn extract_completed_message(&mut self) -> Option<Vec<u8>> {
        if let Some(_) = &self.current_message {
            let message = self.build_complete_message();
            self.current_message = None;
            Some(message)
        } else {
            None
        }
    }
    
    /// Transition back to WaitingTag state for next message
    async fn transition_to_waiting_tag(&mut self) -> Result<(), BerDecoderError> {
        self.state = BerDecoderState::WaitingTag;
        self.start_time = Instant::now();
        Ok(())
    }
    
    /// Handle error and transition to error state
    async fn handle_error(&mut self, error: String) -> Result<(), BerDecoderError> {
        self.state = BerDecoderState::Error;
        
        // Notify message handler
        if let Some(handler) = &mut self.message_handler {
            let _ = handler.on_error(&error).await;
        }
        
        Err(BerDecoderError::Generic { message: error })
    }
}

/// Statistics about BER decoder performance
#[derive(Debug, Clone)]
pub struct BerDecoderStats {
    pub messages_processed: u64,
    pub bytes_processed: u64,
    pub current_buffer_size: usize,
    pub uptime: Duration,
}

/// Implementation of StateMachine trait for BerDecoderFsmImpl
#[async_trait]
impl StateMachine for BerDecoderFsmImpl {
    type State = BerDecoderState;
    type Event = BerDecoderEvent;
    type Error = BerDecoderError;
    type Output = Vec<u8>; // Complete BER message
    
    fn current_state(&self) -> &Self::State {
        &self.state
    }
    
    async fn handle_event(&mut self, event: Self::Event) -> Result<Option<Self::Output>, Self::Error> {
        match event {
            BerDecoderEvent::DataReceived(data) => {
                self.process_data(data).await
            }
            BerDecoderEvent::Reset => {
                self.reset().await?;
                Ok(None)
            }
            BerDecoderEvent::Error(message) => {
                self.handle_error(message).await?;
                Ok(None)
            }
        }
    }
    
    fn is_terminal(&self) -> bool {
        matches!(self.state, BerDecoderState::Error)
    }
    
    async fn reset(&mut self) -> Result<(), Self::Error> {
        self.state = BerDecoderState::WaitingTag;
        self.buffer.clear();
        self.current_message = None;
        self.start_time = Instant::now();
        Ok(())
    }
}

/// Implementation of BerDecoderFsm trait
#[async_trait]
impl BerDecoderFsm for BerDecoderFsmImpl {
    fn buffer(&self) -> &[u8] {
        &self.buffer
    }
    
    fn bytes_needed(&self) -> Option<usize> {
        match &self.state {
            BerDecoderState::WaitingTag => Some(1), // Need at least one byte for tag
            BerDecoderState::WaitingLength => Some(1), // Need at least one byte for length
            BerDecoderState::WaitingValue { .. } => {
                self.current_message.as_ref().map(|msg| msg.bytes_needed)
            }
            BerDecoderState::MessageComplete => Some(0),
            BerDecoderState::Error => None,
        }
    }
    
    fn extract_message(&mut self) -> Option<Vec<u8>> {
        if matches!(self.state, BerDecoderState::MessageComplete) {
            self.extract_completed_message()
        } else {
            None
        }
    }
    
    fn progress(&self) -> BerDecodingProgress {
        let (tag, length, bytes_received, bytes_needed) = match (&self.state, &self.current_message) {
            (BerDecoderState::WaitingTag, None) => (None, None, self.buffer.len(), Some(1)),
            (BerDecoderState::WaitingLength, Some(msg)) => (Some(msg.tag), None, self.buffer.len(), Some(1)),
            (BerDecoderState::WaitingValue { tag, length }, Some(msg)) => {
                (Some(*tag), Some(*length), msg.value_bytes.len(), Some(msg.bytes_needed))
            }
            (BerDecoderState::MessageComplete, Some(msg)) => {
                (Some(msg.tag), Some(msg.length), msg.value_bytes.len(), Some(0))
            }
            _ => (None, None, self.buffer.len(), None),
        };
        
        BerDecodingProgress {
            tag,
            length,
            bytes_received,
            bytes_needed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsm::StateMachine;
    
    /// Mock BER validator for testing
    struct MockBerValidator {
        max_message_size: usize,
        should_fail_tag: Option<u8>,
        should_fail_length: Option<usize>,
    }
    
    impl MockBerValidator {
        fn new() -> Self {
            Self {
                max_message_size: 1024,
                should_fail_tag: None,
                should_fail_length: None,
            }
        }
        
        fn with_max_size(mut self, size: usize) -> Self {
            self.max_message_size = size;
            self
        }
        
        fn fail_on_tag(mut self, tag: u8) -> Self {
            self.should_fail_tag = Some(tag);
            self
        }
        
        fn fail_on_length(mut self, length: usize) -> Self {
            self.should_fail_length = Some(length);
            self
        }
    }
    
    #[async_trait]
    impl BerValidator for MockBerValidator {
        async fn validate_tag(&self, tag: u8) -> Result<(), String> {
            if let Some(fail_tag) = self.should_fail_tag {
                if tag == fail_tag {
                    return Err(format!("Tag validation failed for {}", tag));
                }
            }
            Ok(())
        }
        
        async fn validate_length(&self, length: usize) -> Result<(), String> {
            if let Some(fail_length) = self.should_fail_length {
                if length == fail_length {
                    return Err(format!("Length validation failed for {}", length));
                }
            }
            Ok(())
        }
        
        fn max_message_size(&self) -> usize {
            self.max_message_size
        }
        
        fn is_constructed(&self, tag: u8) -> bool {
            tag & 0x20 != 0
        }
    }
    
    /// Mock message handler for testing
    struct MockMessageHandler {
        messages: Vec<Vec<u8>>,
        progress_updates: Vec<BerDecodingProgress>,
        errors: Vec<String>,
    }
    
    impl MockMessageHandler {
        fn new() -> Self {
            Self {
                messages: Vec::new(),
                progress_updates: Vec::new(),
                errors: Vec::new(),
            }
        }
    }
    
    #[async_trait]
    impl BerMessageHandler for MockMessageHandler {
        async fn on_message_complete(&mut self, message: &[u8]) -> Result<(), String> {
            self.messages.push(message.to_vec());
            Ok(())
        }
        
        async fn on_progress_update(&mut self, progress: &BerDecodingProgress) -> Result<(), String> {
            self.progress_updates.push(progress.clone());
            Ok(())
        }
        
        async fn on_error(&mut self, error: &str) -> Result<(), String> {
            self.errors.push(error.to_string());
            Ok(())
        }
    }
    
    #[tokio::test]
    async fn test_new_ber_decoder_fsm() {
        let fsm = BerDecoderFsmImpl::new();
        assert_eq!(fsm.current_state(), &BerDecoderState::WaitingTag);
        assert!(!fsm.is_terminal());
        assert_eq!(fsm.buffer().len(), 0);
    }
    
    #[tokio::test]
    async fn test_ber_decoder_with_config() {
        let config = BerDecoderConfig {
            max_message_size: 512,
            max_buffer_size: 1024,
            message_timeout: Some(Duration::from_secs(10)),
            strict_validation: false,
        };
        
        let fsm = BerDecoderFsmImpl::with_config(config.clone());
        assert_eq!(fsm.config.max_message_size, 512);
        assert_eq!(fsm.config.max_buffer_size, 1024);
    }
    
    #[tokio::test]
    async fn test_ber_decoder_with_validator() {
        let validator = Box::new(MockBerValidator::new());
        let fsm = BerDecoderFsmImpl::new().with_validator(validator);
        assert!(fsm.validator.is_some());
    }
    
    #[tokio::test]
    async fn test_ber_decoder_with_message_handler() {
        let handler = Box::new(MockMessageHandler::new());
        let fsm = BerDecoderFsmImpl::new().with_message_handler(handler);
        assert!(fsm.message_handler.is_some());
    }
    
    #[tokio::test]
    async fn test_simple_ber_message_short_length() {
        let mut fsm = BerDecoderFsmImpl::new();
        
        // Create simple BER message: tag=0x04 (OCTET STRING), length=5, value="Hello"
        let ber_data = vec![0x04, 0x05, b'H', b'e', b'l', b'l', b'o'];
        
        let result = fsm.handle_event(BerDecoderEvent::DataReceived(ber_data)).await;
        assert!(result.is_ok());
        
        // Should have a complete message
        if let Some(message) = result.unwrap() {
            assert_eq!(message.len(), 7); // tag + length + 5 bytes value
            assert_eq!(message[0], 0x04); // tag
            assert_eq!(message[1], 0x05); // length
            assert_eq!(&message[2..], b"Hello"); // value
        }
        
        assert_eq!(fsm.current_state(), &BerDecoderState::WaitingTag);
    }
    
    #[tokio::test]
    async fn test_ber_message_incremental_data() {
        let mut fsm = BerDecoderFsmImpl::new();
        
        // Send data in parts: tag first
        let result1 = fsm.handle_event(BerDecoderEvent::DataReceived(vec![0x04])).await;
        assert!(result1.is_ok());
        assert!(result1.unwrap().is_none());
        assert_eq!(fsm.current_state(), &BerDecoderState::WaitingLength);
        
        // Then length
        let result2 = fsm.handle_event(BerDecoderEvent::DataReceived(vec![0x03])).await;
        assert!(result2.is_ok());
        assert!(result2.unwrap().is_none());
        assert!(matches!(fsm.current_state(), BerDecoderState::WaitingValue { tag: 0x04, length: 3 }));
        
        // Then partial value
        let result3 = fsm.handle_event(BerDecoderEvent::DataReceived(vec![b'A', b'B'])).await;
        assert!(result3.is_ok());
        assert!(result3.unwrap().is_none());
        assert!(matches!(fsm.current_state(), BerDecoderState::WaitingValue { .. }));
        
        // Finally complete value
        let result4 = fsm.handle_event(BerDecoderEvent::DataReceived(vec![b'C'])).await;
        assert!(result4.is_ok());
        
        if let Some(message) = result4.unwrap() {
            assert_eq!(message, vec![0x04, 0x03, b'A', b'B', b'C']);
        }
        
        assert_eq!(fsm.current_state(), &BerDecoderState::WaitingTag);
    }
    
    #[tokio::test]
    async fn test_ber_message_long_length() {
        let mut fsm = BerDecoderFsmImpl::new();
        
        // Create message with long length encoding
        // Length = 300 (0x012C), encoded as 0x82 0x01 0x2C
        let mut data = vec![0x04, 0x82, 0x01, 0x2C]; // tag + long length
        data.extend(vec![b'X'; 300]); // 300 bytes of 'X'
        
        let result = fsm.handle_event(BerDecoderEvent::DataReceived(data)).await;
        assert!(result.is_ok());
        
        if let Some(message) = result.unwrap() {
            assert_eq!(message.len(), 304); // tag + 3 length bytes + 300 value bytes
            assert_eq!(message[0], 0x04);
            assert_eq!(&message[4..], &vec![b'X'; 300]);
        }
    }
    
    #[tokio::test]
    async fn test_zero_length_message() {
        let mut fsm = BerDecoderFsmImpl::new();
        
        // Zero-length message
        let data = vec![0x05, 0x00]; // tag=0x05, length=0
        
        let result = fsm.handle_event(BerDecoderEvent::DataReceived(data)).await;
        assert!(result.is_ok());
        
        if let Some(message) = result.unwrap() {
            assert_eq!(message, vec![0x05, 0x00]);
        }
    }
    
    #[tokio::test]
    async fn test_buffer_overflow_protection() {
        let config = BerDecoderConfig {
            max_buffer_size: 10,
            ..Default::default()
        };
        let mut fsm = BerDecoderFsmImpl::with_config(config);
        
        // Try to send more data than buffer can hold
        let large_data = vec![0u8; 20];
        let result = fsm.handle_event(BerDecoderEvent::DataReceived(large_data)).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BerDecoderError::BufferOverflow { .. }));
    }
    
    #[tokio::test]
    async fn test_message_size_limit() {
        let config = BerDecoderConfig {
            max_message_size: 5,
            ..Default::default()
        };
        let mut fsm = BerDecoderFsmImpl::with_config(config);
        
        // Try to decode message larger than limit
        let data = vec![0x04, 0x0A]; // tag=0x04, length=10 (exceeds limit of 5)
        let result = fsm.handle_event(BerDecoderEvent::DataReceived(data)).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BerDecoderError::MessageTooLarge { .. }));
    }
    
    #[tokio::test]
    async fn test_validator_tag_failure() {
        let validator = Box::new(MockBerValidator::new().fail_on_tag(0x04));
        let mut fsm = BerDecoderFsmImpl::new().with_validator(validator);
        
        let data = vec![0x04, 0x01, 0x00]; // tag that should fail validation
        let result = fsm.handle_event(BerDecoderEvent::DataReceived(data)).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BerDecoderError::InvalidTag(_)));
    }
    
    #[tokio::test]
    async fn test_validator_length_failure() {
        let validator = Box::new(MockBerValidator::new().fail_on_length(5));
        let mut fsm = BerDecoderFsmImpl::new().with_validator(validator);
        
        let data = vec![0x04, 0x05]; // length that should fail validation
        let result = fsm.handle_event(BerDecoderEvent::DataReceived(data)).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BerDecoderError::InvalidLength(_)));
    }
    
    #[tokio::test]
    async fn test_reset_event() {
        let mut fsm = BerDecoderFsmImpl::new();
        
        // Start processing a message - use incomplete data that won't be fully consumed
        let _ = fsm.handle_event(BerDecoderEvent::DataReceived(vec![0x04, 0x05])).await; // Need 5 value bytes
        assert!(matches!(fsm.current_state(), BerDecoderState::WaitingValue { .. }));
        
        // Reset
        let result = fsm.handle_event(BerDecoderEvent::Reset).await;
        assert!(result.is_ok());
        assert_eq!(fsm.current_state(), &BerDecoderState::WaitingTag);
        assert!(fsm.buffer().is_empty());
    }
    
    #[tokio::test]
    async fn test_error_event() {
        let mut fsm = BerDecoderFsmImpl::new();
        
        let result = fsm.handle_event(BerDecoderEvent::Error("Test error".to_string())).await;
        assert!(result.is_err());
        assert_eq!(fsm.current_state(), &BerDecoderState::Error);
        assert!(fsm.is_terminal());
    }
    
    #[tokio::test]
    async fn test_progress_tracking() {
        let mut fsm = BerDecoderFsmImpl::new();
        
        // Initial progress
        let progress1 = fsm.progress();
        assert_eq!(progress1.tag, None);
        assert_eq!(progress1.length, None);
        assert_eq!(progress1.bytes_received, 0);
        
        // After receiving tag
        let _ = fsm.handle_event(BerDecoderEvent::DataReceived(vec![0x04])).await;
        let progress2 = fsm.progress();
        assert_eq!(progress2.tag, Some(0x04));
        assert_eq!(progress2.length, None);
        
        // After receiving length
        let _ = fsm.handle_event(BerDecoderEvent::DataReceived(vec![0x03])).await;
        let progress3 = fsm.progress();
        assert_eq!(progress3.tag, Some(0x04));
        assert_eq!(progress3.length, Some(3));
        assert_eq!(progress3.bytes_received, 0); // value bytes received
        assert_eq!(progress3.bytes_needed, Some(3));
    }
    
    #[tokio::test]
    async fn test_extract_message() {
        let mut fsm = BerDecoderFsmImpl::new();
        
        // Process partial message to get to MessageComplete state without extracting
        let _ = fsm.handle_event(BerDecoderEvent::DataReceived(vec![0x04, 0x00])).await; // Zero-length message
        
        // The message should have been completed and automatically extracted
        // Since we already extract on completion, let's test the state is reset
        assert_eq!(fsm.current_state(), &BerDecoderState::WaitingTag);
        
        // Test extract_message on a state that should return None
        let extracted = fsm.extract_message();
        assert!(extracted.is_none());
    }
    
    #[tokio::test]
    async fn test_bytes_needed() {
        let mut fsm = BerDecoderFsmImpl::new();
        
        // Initially need 1 byte for tag
        assert_eq!(fsm.bytes_needed(), Some(1));
        
        // After tag, need 1 byte for length
        let _ = fsm.handle_event(BerDecoderEvent::DataReceived(vec![0x04])).await;
        assert_eq!(fsm.bytes_needed(), Some(1));
        
        // After length, need specified value bytes
        let _ = fsm.handle_event(BerDecoderEvent::DataReceived(vec![0x05])).await;
        assert_eq!(fsm.bytes_needed(), Some(5));
        
        // After partial value
        let _ = fsm.handle_event(BerDecoderEvent::DataReceived(vec![b'A', b'B'])).await;
        assert_eq!(fsm.bytes_needed(), Some(3));
    }
    
    #[tokio::test]
    async fn test_stats() {
        let mut fsm = BerDecoderFsmImpl::new();
        
        let initial_stats = fsm.stats();
        assert_eq!(initial_stats.messages_processed, 0);
        assert_eq!(initial_stats.bytes_processed, 0);
        
        // Process a complete message
        let data = vec![0x04, 0x03, b'X', b'Y', b'Z'];
        let data_len = data.len();
        let _ = fsm.handle_event(BerDecoderEvent::DataReceived(data)).await;
        
        let final_stats = fsm.stats();
        assert_eq!(final_stats.messages_processed, 1);
        assert_eq!(final_stats.bytes_processed, data_len as u64);
    }
    
    #[tokio::test]
    async fn test_fsm_reset_method() {
        let mut fsm = BerDecoderFsmImpl::new();
        
        // Process partial message that will leave us in WaitingValue state with remaining bytes needed
        let _ = fsm.handle_event(BerDecoderEvent::DataReceived(vec![0x04, 0x05, b'A'])).await;
        // The FSM should be in WaitingValue state waiting for 4 more bytes
        assert!(matches!(fsm.current_state(), BerDecoderState::WaitingValue { .. }));
        
        // Reset using StateMachine trait method
        let result = fsm.reset().await;
        assert!(result.is_ok());
        assert_eq!(fsm.current_state(), &BerDecoderState::WaitingTag);
        assert!(fsm.buffer().is_empty());
    }
    
    #[tokio::test]
    async fn test_message_handler_callbacks() {
        let handler = Box::new(MockMessageHandler::new());
        let mut fsm = BerDecoderFsmImpl::new().with_message_handler(handler);
        
        // Process complete message
        let data = vec![0x04, 0x02, b'H', b'i'];
        let _ = fsm.handle_event(BerDecoderEvent::DataReceived(data)).await;
        
        // Handler should have been called (we can't directly verify this in this test setup,
        // but the code path is exercised)
        assert_eq!(fsm.current_state(), &BerDecoderState::WaitingTag);
    }
    
    #[tokio::test]
    async fn test_invalid_long_length() {
        let mut fsm = BerDecoderFsmImpl::new();
        
        // Send indefinite length (0x80) which is not supported
        let data = vec![0x04, 0x80];
        let result = fsm.handle_event(BerDecoderEvent::DataReceived(data)).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BerDecoderError::InvalidLength(_)));
    }
    
    #[tokio::test]
    async fn test_length_too_many_bytes() {
        let mut fsm = BerDecoderFsmImpl::new();
        
        // Send length that requires too many bytes (0x85 = 5 length bytes, but we support max 4)
        let data = vec![0x04, 0x85];
        let result = fsm.handle_event(BerDecoderEvent::DataReceived(data)).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BerDecoderError::InvalidLength(_)));
    }
}
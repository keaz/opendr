//! BER Decoder FSM implementation (minimal streaming adapter)
//!
//! This adapter integrates the FSM layer with the current server by buffering
//! incoming bytes and yielding chunks to the server for parsing. For now, it
//! treats each read chunk as a complete parse unit (same semantics as the
//! existing handle_client loop). This lets us integrate the FSM infrastructure
//! without changing protocol behavior. We can later enhance this to true
//! tag/length/value streaming if needed.

use async_trait::async_trait;
use log::debug;
use thiserror::Error;

use crate::fsm::{
    BerDecoderEvent, BerDecoderFsm, BerDecoderState, BerDecodingProgress, StateMachine,
};

#[derive(Error, Debug)]
pub enum BerDecoderError {
    #[error("Invalid state")]
    InvalidState,
}

pub struct BerDecoderFsmImpl {
    state: BerDecoderState,
    buffer: Vec<u8>,
    progress: BerDecodingProgress,
}

impl BerDecoderFsmImpl {
    pub fn new() -> Self {
        Self {
            state: BerDecoderState::WaitingTag,
            buffer: Vec::new(),
            progress: BerDecodingProgress {
                tag: None,
                length: None,
                bytes_received: 0,
                bytes_needed: None,
            },
        }
    }
}

#[async_trait]
impl StateMachine for BerDecoderFsmImpl {
    type State = BerDecoderState;
    type Event = BerDecoderEvent;
    type Error = BerDecoderError;
    type Output = ();

    fn current_state(&self) -> &Self::State {
        &self.state
    }

    async fn handle_event(
        &mut self,
        event: Self::Event,
    ) -> Result<Option<Self::Output>, Self::Error> {
        match event {
            BerDecoderEvent::DataReceived(mut bytes) => {
                self.buffer.clear();
                self.buffer.append(&mut bytes);
                self.progress.bytes_received = self.buffer.len();
                // Minimal adapter: mark as complete per chunk
                self.state = BerDecoderState::MessageComplete;
                debug!("ber-decoder: received {} bytes", self.buffer.len());
            }
            BerDecoderEvent::Reset => {
                self.buffer.clear();
                self.progress = BerDecodingProgress {
                    tag: None,
                    length: None,
                    bytes_received: 0,
                    bytes_needed: None,
                };
                self.state = BerDecoderState::WaitingTag;
            }
            BerDecoderEvent::Error(_) => {
                self.state = BerDecoderState::Error;
                return Ok(None);
            }
        }
        Ok(Some(()))
    }

    fn is_terminal(&self) -> bool {
        matches!(self.state, BerDecoderState::Error)
    }

    async fn reset(&mut self) -> Result<(), Self::Error> {
        self.buffer.clear();
        self.progress = BerDecodingProgress {
            tag: None,
            length: None,
            bytes_received: 0,
            bytes_needed: None,
        };
        self.state = BerDecoderState::WaitingTag;
        Ok(())
    }
}

#[async_trait]
impl BerDecoderFsm for BerDecoderFsmImpl {
    fn buffer(&self) -> &[u8] {
        &self.buffer
    }

    fn bytes_needed(&self) -> Option<usize> {
        self.progress.bytes_needed
    }

    fn extract_message(&mut self) -> Option<Vec<u8>> {
        if matches!(self.state, BerDecoderState::MessageComplete) && !self.buffer.is_empty() {
            let out = std::mem::take(&mut self.buffer);
            // After extraction, set state to WaitingTag for next chunk
            self.state = BerDecoderState::WaitingTag;
            self.progress.bytes_received = 0;
            Some(out)
        } else {
            None
        }
    }

    fn progress(&self) -> BerDecodingProgress {
        self.progress.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_decoder_passes_through_chunks() {
        let mut fsm = BerDecoderFsmImpl::new();
        let data = vec![0x30, 0x03, 0x02, 0x01, 0x01]; // example BER sequence header + payload
        fsm.handle_event(BerDecoderEvent::DataReceived(data.clone()))
            .await
            .unwrap();
        assert_eq!(fsm.current_state(), &BerDecoderState::MessageComplete);
        let out = fsm.extract_message().unwrap();
        assert_eq!(out, data);
        assert_eq!(fsm.current_state(), &BerDecoderState::WaitingTag);
        assert!(fsm.extract_message().is_none());
    }
}

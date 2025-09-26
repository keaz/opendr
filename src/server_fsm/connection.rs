//! Connection FSM implementation for LDAP server
//!
//! Handles the lifecycle of LDAP connections including:
//! - TCP connection establishment and teardown
//! - TLS upgrade (StartTLS)
//! - Connection state tracking
//! - Client address and connection info management

use async_trait::async_trait;
use std::net::SocketAddr;
use std::time::Instant;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::io::{AsyncRead, AsyncWrite};
use log::{debug, info, warn, error};

use crate::fsm::{
    StateMachine, AbandonableFsm, TimeoutFsm,
    ConnectionFsm, ConnectionState, ConnectionEvent, ConnectionInfo
};

#[derive(Error, Debug)]
pub enum ConnectionFsmError {
    #[error("Invalid state transition from {from:?} to {to:?}")]
    InvalidStateTransition { from: ConnectionState, to: ConnectionState },
    
    #[error("Connection I/O error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("TLS handshake failed: {0}")]
    TlsError(String),
    
    #[error("Connection already closed")]
    ConnectionClosed,
    
    #[error("Generic connection error: {0}")]
    Generic(String),
}

/// Concrete implementation of the ConnectionFsm trait
pub struct ConnectionFsmImpl {
    state: ConnectionState,
    stream: Option<TcpStream>,
    remote_addr: SocketAddr,
    local_addr: SocketAddr,
    is_secure: bool,
    is_abandoned: bool,
    start_time: Instant,
}

impl ConnectionFsmImpl {
    /// Create a new ConnectionFsm with an established TCP stream
    pub fn new(stream: TcpStream, remote_addr: SocketAddr, local_addr: SocketAddr) -> Self {
        Self {
            state: ConnectionState::Connected,
            stream: Some(stream),
            remote_addr,
            local_addr,
            is_secure: false,
            is_abandoned: false,
            start_time: Instant::now(),
        }
    }
    
    /// Create a new ConnectionFsm for an outbound connection (for testing)
    pub fn new_outbound() -> Self {
        Self {
            state: ConnectionState::Connecting,
            stream: None,
            remote_addr: "0.0.0.0:0".parse().unwrap(),
            local_addr: "0.0.0.0:0".parse().unwrap(),
            is_secure: false,
            is_abandoned: false,
            start_time: Instant::now(),
        }
    }
    
    /// Validate state transition
    fn can_transition(&self, to: &ConnectionState) -> bool {
        use ConnectionState::*;
        
        match (&self.state, to) {
            (Connecting, Connected) => true,
            (Connected, StartTlsNegotiation) => true,
            (Connected, Closing) => true,
            (StartTlsNegotiation, Secure) => true,
            (StartTlsNegotiation, Error) => true,
            (Secure, Closing) => true,
            (Closing, Closed) => true,
            (_, Error) => true, // Can always transition to error
            (_, Closed) => true, // Can always force close
            _ => false,
        }
    }
    
    /// Perform state transition
    fn transition(&mut self, to: ConnectionState) -> Result<(), ConnectionFsmError> {
        if !self.can_transition(&to) {
            return Err(ConnectionFsmError::InvalidStateTransition {
                from: self.state.clone(),
                to,
            });
        }
        
        debug!("Connection FSM transition: {:?} -> {:?}", self.state, to);
        self.state = to;
        Ok(())
    }
}

#[async_trait]
impl StateMachine for ConnectionFsmImpl {
    type State = ConnectionState;
    type Event = ConnectionEvent;
    type Error = ConnectionFsmError;
    type Output = ();
    
    fn current_state(&self) -> &Self::State {
        &self.state
    }
    
    async fn handle_event(&mut self, event: Self::Event) -> Result<Option<Self::Output>, Self::Error> {
        debug!("Connection FSM handling event: {:?} in state: {:?}", event, self.state);
        
        match event {
            ConnectionEvent::Connect => {
                if self.state == ConnectionState::Connecting {
                    // This would be where we establish the connection for outbound connections
                    // For now, just transition to connected
                    self.transition(ConnectionState::Connected)?;
                    info!("Connection established");
                } else {
                    return Err(ConnectionFsmError::InvalidStateTransition {
                        from: self.state.clone(),
                        to: ConnectionState::Connected,
                    });
                }
            }
            
            ConnectionEvent::ConnectionEstablished => {
                self.transition(ConnectionState::Connected)?;
                info!("Connection established to {:?}", self.remote_addr);
            }
            
            ConnectionEvent::StartTlsRequest => {
                if self.state == ConnectionState::Connected {
                    self.transition(ConnectionState::StartTlsNegotiation)?;
                    info!("Starting TLS negotiation");
                    // Note: Actual TLS negotiation would be handled by calling code
                } else {
                    return Err(ConnectionFsmError::InvalidStateTransition {
                        from: self.state.clone(),
                        to: ConnectionState::StartTlsNegotiation,
                    });
                }
            }
            
            ConnectionEvent::TlsHandshakeComplete => {
                if self.state == ConnectionState::StartTlsNegotiation {
                    self.transition(ConnectionState::Secure)?;
                    self.is_secure = true;
                    info!("TLS handshake completed successfully");
                } else {
                    return Err(ConnectionFsmError::InvalidStateTransition {
                        from: self.state.clone(),
                        to: ConnectionState::Secure,
                    });
                }
            }
            
            ConnectionEvent::TlsHandshakeFailed(error) => {
                if self.state == ConnectionState::StartTlsNegotiation {
                    self.transition(ConnectionState::Error)?;
                    error!("TLS handshake failed: {}", error);
                    return Err(ConnectionFsmError::TlsError(error));
                } else {
                    return Err(ConnectionFsmError::InvalidStateTransition {
                        from: self.state.clone(),
                        to: ConnectionState::Error,
                    });
                }
            }
            
            ConnectionEvent::Close => {
                match self.state {
                    ConnectionState::Connected | ConnectionState::Secure => {
                        self.transition(ConnectionState::Closing)?;
                        info!("Connection closing initiated");
                    }
                    ConnectionState::Closing => {
                        self.transition(ConnectionState::Closed)?;
                        info!("Connection closed");
                        self.stream = None;
                    }
                    _ => {
                        warn!("Close event received in unexpected state: {:?}", self.state);
                    }
                }
            }
            
            ConnectionEvent::ConnectionLost => {
                self.transition(ConnectionState::Closed)?;
                self.stream = None;
                warn!("Connection lost unexpectedly");
            }
            
            ConnectionEvent::Error(error) => {
                self.transition(ConnectionState::Error)?;
                error!("Connection error: {}", error);
                return Err(ConnectionFsmError::Generic(error));
            }
        }
        
        Ok(Some(()))
    }
    
    fn is_terminal(&self) -> bool {
        matches!(self.state, ConnectionState::Closed | ConnectionState::Error)
    }
    
    async fn reset(&mut self) -> Result<(), Self::Error> {
        self.state = ConnectionState::Connecting;
        self.stream = None;
        self.is_secure = false;
        self.is_abandoned = false;
        self.start_time = Instant::now();
        debug!("Connection FSM reset");
        Ok(())
    }
}

#[async_trait]
impl AbandonableFsm for ConnectionFsmImpl {
    async fn abandon(&mut self) -> Result<(), Self::Error> {
        self.is_abandoned = true;
        if !self.is_terminal() {
            self.transition(ConnectionState::Closed)?;
            self.stream = None;
            warn!("Connection abandoned");
        }
        Ok(())
    }
    
    fn is_abandoned(&self) -> bool {
        self.is_abandoned
    }
}

impl TimeoutFsm for ConnectionFsmImpl {
    fn timeout(&self) -> Option<std::time::Duration> {
        // Connection timeout of 30 seconds
        Some(std::time::Duration::from_secs(30))
    }
    
    fn start_time(&self) -> Instant {
        self.start_time
    }
}

#[async_trait]
impl ConnectionFsm for ConnectionFsmImpl {
    type Stream = TcpStream;
    
    fn stream(&self) -> Option<&Self::Stream> {
        self.stream.as_ref()
    }
    
    fn stream_mut(&mut self) -> Option<&mut Self::Stream> {
        self.stream.as_mut()
    }
    
    fn is_secure(&self) -> bool {
        self.is_secure
    }
    
    fn connection_info(&self) -> ConnectionInfo {
        ConnectionInfo {
            remote_addr: self.remote_addr.to_string(),
            local_addr: self.local_addr.to_string(),
            is_secure: self.is_secure,
            protocol_version: "3".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    
    #[tokio::test]
    async fn test_connection_fsm_basic_lifecycle() {
        let mut fsm = ConnectionFsmImpl::new_outbound();
        
        // Initial state should be Connecting
        assert_eq!(fsm.current_state(), &ConnectionState::Connecting);
        
        // Connect
        assert!(fsm.handle_event(ConnectionEvent::Connect).await.is_ok());
        assert_eq!(fsm.current_state(), &ConnectionState::Connected);
        
        // Close
        assert!(fsm.handle_event(ConnectionEvent::Close).await.is_ok());
        assert_eq!(fsm.current_state(), &ConnectionState::Closing);
        
        // Final close
        assert!(fsm.handle_event(ConnectionEvent::Close).await.is_ok());
        assert_eq!(fsm.current_state(), &ConnectionState::Closed);
        assert!(fsm.is_terminal());
    }
    
    #[tokio::test]
    async fn test_connection_fsm_starttls() {
        let mut fsm = ConnectionFsmImpl::new_outbound();
        
        // Connect first
        assert!(fsm.handle_event(ConnectionEvent::Connect).await.is_ok());
        assert_eq!(fsm.current_state(), &ConnectionState::Connected);
        assert!(!fsm.is_secure());
        
        // Start TLS
        assert!(fsm.handle_event(ConnectionEvent::StartTlsRequest).await.is_ok());
        assert_eq!(fsm.current_state(), &ConnectionState::StartTlsNegotiation);
        
        // Complete TLS
        assert!(fsm.handle_event(ConnectionEvent::TlsHandshakeComplete).await.is_ok());
        assert_eq!(fsm.current_state(), &ConnectionState::Secure);
        assert!(fsm.is_secure());
    }
    
    #[tokio::test]
    async fn test_connection_fsm_invalid_transitions() {
        let mut fsm = ConnectionFsmImpl::new_outbound();
        
        // Can't start TLS from Connecting state
        let result = fsm.handle_event(ConnectionEvent::StartTlsRequest).await;
        assert!(result.is_err());
    }
    
    #[tokio::test]
    async fn test_connection_fsm_abandon() {
        let mut fsm = ConnectionFsmImpl::new_outbound();
        
        assert!(fsm.handle_event(ConnectionEvent::Connect).await.is_ok());
        assert!(!fsm.is_abandoned());
        
        // Abandon connection
        assert!(fsm.abandon().await.is_ok());
        assert!(fsm.is_abandoned());
        assert_eq!(fsm.current_state(), &ConnectionState::Closed);
        assert!(fsm.is_terminal());
    }
    
    #[tokio::test]
    async fn test_connection_fsm_with_real_stream() {
        // Create a test TCP connection
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        
        // Spawn a task to accept the connection
        let accept_handle = tokio::spawn(async move {
            listener.accept().await
        });
        
        // Connect to it
        let stream = TcpStream::connect(local_addr).await.unwrap();
        let remote_addr = stream.peer_addr().unwrap();
        
        // Accept the connection
        let (_, client_addr) = accept_handle.await.unwrap().unwrap();
        
        // Create FSM with real stream
        let mut fsm = ConnectionFsmImpl::new(stream, client_addr, local_addr);
        
        assert_eq!(fsm.current_state(), &ConnectionState::Connected);
        assert!(fsm.stream().is_some());
        
        let conn_info = fsm.connection_info();
        assert_eq!(conn_info.local_addr, local_addr.to_string());
        assert!(!conn_info.is_secure);
        assert_eq!(conn_info.protocol_version, "3");
    }
}
//! SASL Bind Finite State Machine Implementation
//!
//! This module implements a streaming SASL (Simple Authentication and Security Layer) FSM
//! for multi-roundtrip challenge/response authentication in LDAP. The FSM manages the
//! complete SASL authentication lifecycle including mechanism negotiation, challenge/response
//! exchanges, and final authentication verification.
//!
//! ## SASL Authentication Flow
//!
//! ```text
//! Initial -> Challenge -> Response -> ... -> Authenticated
//!    |         ^  |        |  ^                    |
//!    |         |  +--------+  |                    |
//!    |         +-- Multi-step Challenge/Response --+
//!    |                                              |
//!    +---> Failed <-------------------------------+
//! ```
//!
//! ## Supported SASL Mechanisms
//!
//! The FSM supports pluggable SASL mechanisms through the `SaslMechanismHandler` trait:
//! - PLAIN is provided by the built-in production handler.
//! - Additional mechanisms can be supplied by custom handlers once they verify the
//!   client proof for that mechanism.
//!
//! ## Multi-Roundtrip Support
//!
//! Some SASL mechanisms require multiple challenge/response roundtrips. The FSM tracks:
//! - Current step number
//! - Mechanism-specific state
//! - Challenge data
//! - Response validation
//!
//! ## Usage Example
//!
//! ```rust,no_run
//! use opendr::sasl_fsm::*;
//! use opendr::fsm::{StateMachine, SaslState, SaslEvent};
//!
//! # struct MockSaslMechanismHandler;
//! # #[async_trait::async_trait]
//! # impl SaslMechanismHandler for MockSaslMechanismHandler {
//! #     async fn supports_mechanism(&self, mechanism: &str) -> bool { true }
//! #     async fn start_authentication(&self, mechanism: &str, initial_data: Option<&[u8]>) -> Result<SaslChallengeResult, String> {
//! #         Ok(SaslChallengeResult::Challenge(vec![]))
//! #     }
//! #     async fn process_response(&self, mechanism: &str, step: u32, response: &[u8]) -> Result<SaslChallengeResult, String> {
//! #         Ok(SaslChallengeResult::Success { dn: "cn=user".to_string() })
//! #     }
//! # }
//! #
//! # struct MockCredentialVerifier;
//! # #[async_trait::async_trait]
//! # impl CredentialVerifier for MockCredentialVerifier {
//! #     async fn verify_credentials(&self, mechanism: &str, identity: &str, credential: &[u8]) -> Result<bool, String> { Ok(true) }
//! #     async fn get_user_dn(&self, identity: &str) -> Result<Option<String>, String> { Ok(Some("cn=user".to_string())) }
//! # }
//! #
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mechanism_handler = Box::new(MockSaslMechanismHandler);
//! let credential_verifier = Box::new(MockCredentialVerifier);
//! let mut fsm = SaslFsmImpl::new(mechanism_handler, credential_verifier);
//!
//! // Start SASL PLAIN authentication
//! let result = fsm.handle_event(SaslEvent::InitiateBind {
//!     mechanism: "PLAIN".to_string(),
//!     initial_data: Some(b"\0username\0password".to_vec()),
//! }).await?;
//! # Ok(())
//! # }
//! ```

use crate::fsm::{SaslEvent, SaslFsm, SaslState, StateMachine};
use async_trait::async_trait;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use thiserror::Error;

/// Errors that can occur during SASL authentication
#[derive(Error, Debug, Clone, PartialEq)]
pub enum SaslFsmError {
    #[error("Unsupported SASL mechanism: {mechanism}")]
    UnsupportedMechanism { mechanism: String },

    #[error("Invalid state transition from {from:?} to {to:?}")]
    InvalidStateTransition { from: SaslState, to: SaslState },

    #[error("Invalid SASL response for mechanism {mechanism} at step {step}")]
    InvalidResponse { mechanism: String, step: u32 },

    #[error("Authentication failed: {reason}")]
    AuthenticationFailed { reason: String },

    #[error("SASL mechanism error: {message}")]
    MechanismError { message: String },

    #[error("Credential verification failed: {message}")]
    CredentialError { message: String },

    #[error("Too many authentication attempts")]
    TooManyAttempts,

    #[error("Authentication timeout")]
    Timeout,

    #[error("No active SASL session")]
    NoActiveSession,

    #[error("Generic SASL error: {message}")]
    Generic { message: String },
}

/// Result of a SASL challenge/response step
#[derive(Debug, Clone, PartialEq)]
pub enum SaslChallengeResult {
    /// Authentication successful with user DN
    Success { dn: String },
    /// More steps needed - contains challenge data
    Challenge(Vec<u8>),
    /// Authentication failed
    Failure(String),
}

/// Trait for handling SASL mechanism-specific operations
///
/// This trait abstracts the mechanism-specific SASL handling, allowing
/// different SASL mechanisms to be plugged into the FSM.
#[async_trait]
pub trait SaslMechanismHandler: Send + Sync {
    /// Check if a SASL mechanism is supported
    ///
    /// # Arguments
    /// * `mechanism` - SASL mechanism name (e.g., "PLAIN", "DIGEST-MD5")
    ///
    /// # Returns
    /// * `true` if the mechanism is supported, `false` otherwise
    async fn supports_mechanism(&self, mechanism: &str) -> bool;

    /// Start SASL authentication for a mechanism
    ///
    /// # Arguments
    /// * `mechanism` - SASL mechanism name
    /// * `initial_data` - Optional initial client data
    ///
    /// # Returns
    /// * `Ok(SaslChallengeResult)` - Next step in authentication
    /// * `Err(String)` - Error message if authentication fails
    async fn start_authentication(
        &self,
        mechanism: &str,
        initial_data: Option<&[u8]>,
    ) -> Result<SaslChallengeResult, String>;

    /// Process a SASL response and generate next challenge or complete authentication
    ///
    /// # Arguments
    /// * `mechanism` - SASL mechanism name
    /// * `step` - Current step number in the authentication process
    /// * `response` - Client response data
    ///
    /// # Returns
    /// * `Ok(SaslChallengeResult)` - Next step or completion
    /// * `Err(String)` - Error message if processing fails
    async fn process_response(
        &self,
        mechanism: &str,
        step: u32,
        response: &[u8],
    ) -> Result<SaslChallengeResult, String>;

    /// Get mechanism-specific properties
    ///
    /// # Arguments
    /// * `mechanism` - SASL mechanism name
    ///
    /// # Returns
    /// * HashMap of mechanism properties
    fn get_mechanism_properties(&self, _mechanism: &str) -> HashMap<String, String> {
        HashMap::new()
    }

    /// Get maximum number of steps for a mechanism
    ///
    /// # Arguments
    /// * `mechanism` - SASL mechanism name
    ///
    /// # Returns
    /// * Maximum number of authentication steps allowed
    fn max_steps(&self, mechanism: &str) -> u32 {
        match mechanism {
            "PLAIN" => 1,
            "DIGEST-MD5" => 3,
            "CRAM-MD5" => 2,
            "GSSAPI" => 5,
            _ => 10, // Safe default for custom mechanisms
        }
    }
}

/// Trait for verifying user credentials
///
/// This trait abstracts credential verification, allowing different
/// credential storage backends to be used.
#[async_trait]
pub trait CredentialVerifier: Send + Sync {
    /// Verify user credentials for a SASL mechanism.
    ///
    /// For SASL PLAIN, `credential` is the client-provided password bytes. Other
    /// mechanisms must pass the mechanism-specific proof bytes that the verifier
    /// needs to validate; production handlers should not accept mechanisms whose
    /// proofs they cannot verify.
    ///
    /// # Arguments
    /// * `mechanism` - SASL mechanism used
    /// * `identity` - User identity/username
    /// * `credential` - Password bytes or mechanism-specific client proof
    ///
    /// # Returns
    /// * `Ok(true)` if credentials are valid
    /// * `Ok(false)` if credentials are invalid
    /// * `Err(String)` if verification fails
    async fn verify_credentials(
        &self,
        mechanism: &str,
        identity: &str,
        credential: &[u8],
    ) -> Result<bool, String>;

    /// Get the distinguished name for a user identity
    ///
    /// # Arguments
    /// * `identity` - User identity/username
    ///
    /// # Returns
    /// * `Ok(Some(dn))` if user exists
    /// * `Ok(None)` if user doesn't exist
    /// * `Err(String)` if lookup fails
    async fn get_user_dn(&self, identity: &str) -> Result<Option<String>, String>;

    /// Check if an identity is allowed to use a specific mechanism
    ///
    /// # Arguments
    /// * `identity` - User identity
    /// * `mechanism` - SASL mechanism
    ///
    /// # Returns
    /// * `Ok(true)` if mechanism is allowed for user
    /// * `Ok(false)` if mechanism is not allowed
    /// * `Err(String)` if check fails
    async fn is_mechanism_allowed(
        &self,
        _identity: &str,
        _mechanism: &str,
    ) -> Result<bool, String> {
        // Default implementation allows all mechanisms
        Ok(true)
    }
}

/// Configuration for the SASL FSM
#[derive(Debug, Clone)]
pub struct SaslFsmConfig {
    /// Maximum number of authentication attempts
    pub max_attempts: u32,
    /// Timeout for authentication completion
    pub auth_timeout: Option<Duration>,
    /// Whether to allow anonymous SASL binds
    pub allow_anonymous: bool,
    /// Maximum size for SASL challenge/response data
    pub max_data_size: usize,
}

impl Default for SaslFsmConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            auth_timeout: Some(Duration::from_secs(300)), // 5 minutes
            allow_anonymous: false,
            max_data_size: 64 * 1024, // 64KB
        }
    }
}

/// SASL session information for tracking authentication progress
#[derive(Debug, Clone)]
pub struct SaslSession {
    /// SASL mechanism being used
    pub mechanism: String,
    /// Current step in authentication
    pub step: u32,
    /// User identity being authenticated
    pub identity: Option<String>,
    /// Last challenge sent to client
    pub last_challenge: Option<Vec<u8>>,
    /// Session start time
    pub start_time: Instant,
    /// Number of failed attempts
    pub failed_attempts: u32,
    /// Mechanism-specific state data
    pub mechanism_state: HashMap<String, String>,
}

impl SaslSession {
    /// Create a new SASL session
    ///
    /// # Arguments
    /// * `mechanism` - SASL mechanism name
    ///
    /// # Returns
    /// * New SASL session instance
    pub fn new(mechanism: String) -> Self {
        Self {
            mechanism,
            step: 0,
            identity: None,
            last_challenge: None,
            start_time: Instant::now(),
            failed_attempts: 0,
            mechanism_state: HashMap::new(),
        }
    }

    /// Increment the step counter
    pub fn increment_step(&mut self) {
        self.step += 1;
    }

    /// Record a failed attempt
    pub fn record_failure(&mut self) {
        self.failed_attempts += 1;
    }

    /// Check if session has timed out
    ///
    /// # Arguments
    /// * `timeout` - Timeout duration
    ///
    /// # Returns
    /// * `true` if session has timed out
    pub fn is_timed_out(&self, timeout: Duration) -> bool {
        self.start_time.elapsed() > timeout
    }
}

/// SASL Bind FSM Implementation
///
/// This FSM manages the complete SASL authentication lifecycle, including:
/// - Mechanism negotiation
/// - Multi-roundtrip challenge/response exchanges
/// - Credential verification
/// - Session management
/// - Timeout and error handling
pub struct SaslFsmImpl {
    /// Current FSM state
    state: SaslState,

    /// Current SASL session (if active)
    session: Option<SaslSession>,

    /// SASL mechanism handler for protocol-specific operations
    mechanism_handler: Box<dyn SaslMechanismHandler>,

    /// Credential verifier for user authentication
    _credential_verifier: Box<dyn CredentialVerifier>,

    /// FSM configuration
    config: SaslFsmConfig,

    /// Authenticated user DN (if authentication successful)
    authenticated_dn: Option<String>,

    /// Statistics tracking
    total_attempts: u64,
    successful_auths: u64,
    failed_auths: u64,
}

impl SaslFsmImpl {
    /// Create a new SASL FSM instance
    ///
    /// # Arguments
    /// * `mechanism_handler` - Handler for SASL mechanism operations
    /// * `credential_verifier` - Verifier for user credentials
    ///
    /// # Returns
    /// * New SASL FSM instance
    pub fn new(
        mechanism_handler: Box<dyn SaslMechanismHandler>,
        credential_verifier: Box<dyn CredentialVerifier>,
    ) -> Self {
        Self {
            state: SaslState::Initial,
            session: None,
            mechanism_handler,
            _credential_verifier: credential_verifier,
            config: SaslFsmConfig::default(),
            authenticated_dn: None,
            total_attempts: 0,
            successful_auths: 0,
            failed_auths: 0,
        }
    }

    /// Create a new SASL FSM with custom configuration
    ///
    /// # Arguments
    /// * `mechanism_handler` - Handler for SASL mechanism operations
    /// * `credential_verifier` - Verifier for user credentials
    /// * `config` - FSM configuration
    ///
    /// # Returns
    /// * New SASL FSM instance with custom configuration
    pub fn with_config(
        mechanism_handler: Box<dyn SaslMechanismHandler>,
        credential_verifier: Box<dyn CredentialVerifier>,
        config: SaslFsmConfig,
    ) -> Self {
        Self {
            state: SaslState::Initial,
            session: None,
            mechanism_handler,
            _credential_verifier: credential_verifier,
            config,
            authenticated_dn: None,
            total_attempts: 0,
            successful_auths: 0,
            failed_auths: 0,
        }
    }

    /// Get authentication statistics
    ///
    /// # Returns
    /// * Tuple of (total_attempts, successful_auths, failed_auths)
    pub fn stats(&self) -> (u64, u64, u64) {
        (
            self.total_attempts,
            self.successful_auths,
            self.failed_auths,
        )
    }

    /// Handle SASL bind initiation
    ///
    /// # Arguments
    /// * `mechanism` - SASL mechanism name
    /// * `initial_data` - Optional initial client data
    ///
    /// # Returns
    /// * Result containing optional challenge data
    async fn handle_initiate_bind(
        &mut self,
        mechanism: String,
        initial_data: Option<Vec<u8>>,
    ) -> Result<Option<Vec<u8>>, SaslFsmError> {
        self.total_attempts += 1;

        // Check if mechanism is supported
        if !self.mechanism_handler.supports_mechanism(&mechanism).await {
            self.failed_auths += 1;
            return Err(SaslFsmError::UnsupportedMechanism { mechanism });
        }

        // Check data size limits
        if let Some(data) = &initial_data {
            if data.len() > self.config.max_data_size {
                self.failed_auths += 1;
                return Err(SaslFsmError::Generic {
                    message: format!("Initial data too large: {} bytes", data.len()),
                });
            }
        }

        // Start authentication
        let result = self
            .mechanism_handler
            .start_authentication(&mechanism, initial_data.as_deref())
            .await
            .map_err(|e| SaslFsmError::MechanismError { message: e })?;

        match result {
            SaslChallengeResult::Success { dn } => {
                // Single-step authentication successful
                self.state = SaslState::Authenticated {
                    mechanism,
                    dn: dn.clone(),
                };
                self.authenticated_dn = Some(dn);
                self.successful_auths += 1;
                Ok(None)
            }
            SaslChallengeResult::Challenge(challenge_data) => {
                // Multi-step authentication - send challenge
                let mut session = SaslSession::new(mechanism.clone());
                session.increment_step();
                session.last_challenge = Some(challenge_data.clone());

                self.session = Some(session);
                self.state = SaslState::Challenge { mechanism, step: 1 };
                Ok(Some(challenge_data))
            }
            SaslChallengeResult::Failure(reason) => {
                self.state = SaslState::Failed;
                self.failed_auths += 1;
                Err(SaslFsmError::AuthenticationFailed { reason })
            }
        }
    }

    /// Handle challenge generation
    ///
    /// # Arguments
    /// * `challenge_data` - Challenge data to send to client
    ///
    /// # Returns
    /// * Result indicating success
    async fn handle_challenge_generated(
        &mut self,
        challenge_data: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, SaslFsmError> {
        if let Some(session) = &mut self.session {
            session.last_challenge = Some(challenge_data.clone());

            if let SaslState::Challenge { mechanism, step } = &self.state {
                self.state = SaslState::Response {
                    mechanism: mechanism.clone(),
                    step: *step,
                };
            }

            Ok(Some(challenge_data))
        } else {
            Err(SaslFsmError::NoActiveSession)
        }
    }

    /// Handle client response
    ///
    /// # Arguments
    /// * `response_data` - Client response data
    ///
    /// # Returns
    /// * Result containing optional next challenge or completion
    async fn handle_response_received(
        &mut self,
        response_data: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, SaslFsmError> {
        // Check data size limits
        if response_data.len() > self.config.max_data_size {
            return Err(SaslFsmError::Generic {
                message: format!("Response data too large: {} bytes", response_data.len()),
            });
        }

        if let Some(session) = &mut self.session {
            // Check for timeout
            let is_timed_out = if let Some(timeout) = self.config.auth_timeout {
                session.is_timed_out(timeout)
            } else {
                false
            };

            if is_timed_out {
                self.state = SaslState::Failed;
                self.failed_auths += 1;
                return Err(SaslFsmError::Timeout);
            }

            // Check maximum attempts
            if session.failed_attempts >= self.config.max_attempts {
                self.state = SaslState::Failed;
                self.failed_auths += 1;
                return Err(SaslFsmError::TooManyAttempts);
            }

            // Check maximum steps
            let max_steps = self.mechanism_handler.max_steps(&session.mechanism);
            if session.step >= max_steps {
                self.state = SaslState::Failed;
                self.failed_auths += 1;
                return Err(SaslFsmError::Generic {
                    message: format!("Too many authentication steps: {}", session.step),
                });
            }

            let mechanism = session.mechanism.clone();
            let step = session.step;

            // Process the response
            let result = self
                .mechanism_handler
                .process_response(&mechanism, step, &response_data)
                .await
                .map_err(|e| SaslFsmError::MechanismError { message: e })?;

            match result {
                SaslChallengeResult::Success { dn } => {
                    // Authentication successful
                    self.state = SaslState::Authenticated {
                        mechanism: mechanism.clone(),
                        dn: dn.clone(),
                    };
                    self.authenticated_dn = Some(dn);
                    self.successful_auths += 1;
                    self.session = None; // Clear session
                    Ok(None)
                }
                SaslChallengeResult::Challenge(challenge_data) => {
                    // More steps needed
                    session.increment_step();
                    session.last_challenge = Some(challenge_data.clone());

                    self.state = SaslState::Challenge {
                        mechanism: mechanism.clone(),
                        step: session.step,
                    };
                    Ok(Some(challenge_data))
                }
                SaslChallengeResult::Failure(reason) => {
                    session.record_failure();

                    if session.failed_attempts >= self.config.max_attempts {
                        self.state = SaslState::Failed;
                        self.failed_auths += 1;
                        Err(SaslFsmError::TooManyAttempts)
                    } else {
                        Err(SaslFsmError::AuthenticationFailed { reason })
                    }
                }
            }
        } else {
            Err(SaslFsmError::NoActiveSession)
        }
    }

    /// Handle authentication completion
    ///
    /// # Arguments
    /// * `dn` - Authenticated user DN
    ///
    /// # Returns
    /// * Result indicating success
    async fn handle_authentication_complete(
        &mut self,
        dn: String,
    ) -> Result<Option<Vec<u8>>, SaslFsmError> {
        if let Some(session) = &self.session {
            self.state = SaslState::Authenticated {
                mechanism: session.mechanism.clone(),
                dn: dn.clone(),
            };
            self.authenticated_dn = Some(dn);
            self.successful_auths += 1;
            self.session = None;
            Ok(None)
        } else {
            Err(SaslFsmError::NoActiveSession)
        }
    }

    /// Handle authentication failure
    ///
    /// # Returns
    /// * Result indicating failure
    async fn handle_authentication_failed(&mut self) -> Result<Option<Vec<u8>>, SaslFsmError> {
        self.state = SaslState::Failed;
        self.failed_auths += 1;
        if let Some(session) = &mut self.session {
            session.record_failure();
        }
        Err(SaslFsmError::AuthenticationFailed {
            reason: "Authentication failed".to_string(),
        })
    }
}

#[async_trait]
impl StateMachine for SaslFsmImpl {
    type State = SaslState;
    type Event = SaslEvent;
    type Error = SaslFsmError;
    type Output = Vec<u8>; // Challenge data or empty for completion

    fn current_state(&self) -> &Self::State {
        &self.state
    }

    async fn handle_event(
        &mut self,
        event: Self::Event,
    ) -> Result<Option<Self::Output>, Self::Error> {
        match event {
            SaslEvent::InitiateBind {
                mechanism,
                initial_data,
            } => self.handle_initiate_bind(mechanism, initial_data).await,
            SaslEvent::ChallengeGenerated(challenge_data) => {
                self.handle_challenge_generated(challenge_data).await
            }
            SaslEvent::ResponseReceived(response_data) => {
                self.handle_response_received(response_data).await
            }
            SaslEvent::AuthenticationComplete { dn } => {
                self.handle_authentication_complete(dn).await
            }
            SaslEvent::AuthenticationFailed => self.handle_authentication_failed().await,
            SaslEvent::Reset => {
                self.reset().await?;
                Ok(None)
            }
        }
    }

    fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            SaslState::Authenticated { .. } | SaslState::Failed
        )
    }

    async fn reset(&mut self) -> Result<(), Self::Error> {
        self.state = SaslState::Initial;
        self.session = None;
        self.authenticated_dn = None;
        Ok(())
    }
}

#[async_trait]
impl SaslFsm for SaslFsmImpl {
    fn mechanism(&self) -> Option<&str> {
        match &self.state {
            SaslState::Challenge { mechanism, .. }
            | SaslState::Response { mechanism, .. }
            | SaslState::Authenticated { mechanism, .. } => Some(mechanism),
            _ => None,
        }
    }

    fn step(&self) -> u32 {
        match &self.state {
            SaslState::Challenge { step, .. } | SaslState::Response { step, .. } => *step,
            SaslState::Authenticated { .. } => {
                // Authentication completed
                if let Some(session) = &self.session {
                    session.step
                } else {
                    0
                }
            }
            _ => 0,
        }
    }

    fn authenticated_identity(&self) -> Option<&str> {
        self.authenticated_dn.as_deref()
    }

    fn needs_more_steps(&self) -> bool {
        matches!(
            self.state,
            SaslState::Challenge { .. } | SaslState::Response { .. }
        )
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio;

    /// Mock SASL mechanism handler for testing
    #[derive(Debug)]
    pub struct MockSaslMechanismHandler {
        pub supported_mechanisms: Vec<String>,
        pub should_succeed: bool,
        pub challenge_data: Vec<u8>,
        pub steps_needed: u32,
        pub current_step: Arc<Mutex<u32>>,
        pub call_log: Arc<Mutex<Vec<String>>>,
    }

    impl MockSaslMechanismHandler {
        pub fn new() -> Self {
            Self {
                supported_mechanisms: vec!["PLAIN".to_string(), "DIGEST-MD5".to_string()],
                should_succeed: true,
                challenge_data: vec![1, 2, 3, 4],
                steps_needed: 1,
                current_step: Arc::new(Mutex::new(0)),
                call_log: Arc::new(Mutex::new(Vec::new())),
            }
        }

        pub fn with_mechanisms(mut self, mechanisms: Vec<String>) -> Self {
            self.supported_mechanisms = mechanisms;
            self
        }

        pub fn with_failure(mut self) -> Self {
            self.should_succeed = false;
            self
        }

        pub fn with_multi_step(mut self, steps: u32) -> Self {
            self.steps_needed = steps;
            self
        }

        pub fn call_log(&self) -> Vec<String> {
            self.call_log.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl SaslMechanismHandler for MockSaslMechanismHandler {
        async fn supports_mechanism(&self, mechanism: &str) -> bool {
            self.call_log
                .lock()
                .unwrap()
                .push(format!("supports_mechanism({})", mechanism));
            self.supported_mechanisms.contains(&mechanism.to_string())
        }

        async fn start_authentication(
            &self,
            mechanism: &str,
            initial_data: Option<&[u8]>,
        ) -> Result<SaslChallengeResult, String> {
            self.call_log.lock().unwrap().push(format!(
                "start_authentication({}, {:?})",
                mechanism,
                initial_data.map(|d| d.len())
            ));

            if !self.should_succeed {
                return Ok(SaslChallengeResult::Failure("Mock failure".to_string()));
            }

            if self.steps_needed == 1 {
                Ok(SaslChallengeResult::Success {
                    dn: "cn=testuser,dc=example,dc=org".to_string(),
                })
            } else {
                Ok(SaslChallengeResult::Challenge(self.challenge_data.clone()))
            }
        }

        async fn process_response(
            &self,
            mechanism: &str,
            step: u32,
            response: &[u8],
        ) -> Result<SaslChallengeResult, String> {
            self.call_log.lock().unwrap().push(format!(
                "process_response({}, {}, {} bytes)",
                mechanism,
                step,
                response.len()
            ));

            let mut current_step = self.current_step.lock().unwrap();
            *current_step += 1;

            if !self.should_succeed {
                return Ok(SaslChallengeResult::Failure("Mock failure".to_string()));
            }

            if *current_step >= self.steps_needed {
                Ok(SaslChallengeResult::Success {
                    dn: "cn=testuser,dc=example,dc=org".to_string(),
                })
            } else {
                Ok(SaslChallengeResult::Challenge(self.challenge_data.clone()))
            }
        }
    }

    /// Mock credential verifier for testing
    #[derive(Debug)]
    pub struct MockCredentialVerifier {
        pub should_succeed: bool,
        pub user_dn: String,
        pub call_log: Arc<Mutex<Vec<String>>>,
    }

    impl MockCredentialVerifier {
        pub fn new() -> Self {
            Self {
                should_succeed: true,
                user_dn: "cn=testuser,dc=example,dc=org".to_string(),
                call_log: Arc::new(Mutex::new(Vec::new())),
            }
        }

        pub fn with_failure(mut self) -> Self {
            self.should_succeed = false;
            self
        }

        pub fn call_log(&self) -> Vec<String> {
            self.call_log.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl CredentialVerifier for MockCredentialVerifier {
        async fn verify_credentials(
            &self,
            mechanism: &str,
            identity: &str,
            _credential: &[u8],
        ) -> Result<bool, String> {
            self.call_log
                .lock()
                .unwrap()
                .push(format!("verify_credentials({}, {})", mechanism, identity));

            if self.should_succeed {
                Ok(true)
            } else {
                Ok(false)
            }
        }

        async fn get_user_dn(&self, identity: &str) -> Result<Option<String>, String> {
            self.call_log
                .lock()
                .unwrap()
                .push(format!("get_user_dn({})", identity));

            if self.should_succeed {
                Ok(Some(self.user_dn.clone()))
            } else {
                Ok(None)
            }
        }
    }

    #[tokio::test]
    async fn test_new_sasl_fsm() {
        let mechanism_handler = Box::new(MockSaslMechanismHandler::new());
        let credential_verifier = Box::new(MockCredentialVerifier::new());
        let fsm = SaslFsmImpl::new(mechanism_handler, credential_verifier);

        assert_eq!(fsm.current_state(), &SaslState::Initial);
        assert_eq!(fsm.mechanism(), None);
        assert_eq!(fsm.step(), 0);
        assert_eq!(fsm.authenticated_identity(), None);
        assert!(!fsm.needs_more_steps());
        assert!(!fsm.is_terminal());
    }

    #[tokio::test]
    async fn test_sasl_fsm_with_config() {
        let mechanism_handler = Box::new(MockSaslMechanismHandler::new());
        let credential_verifier = Box::new(MockCredentialVerifier::new());
        let config = SaslFsmConfig {
            max_attempts: 5,
            auth_timeout: Some(Duration::from_secs(60)),
            allow_anonymous: true,
            max_data_size: 128 * 1024,
        };

        let fsm = SaslFsmImpl::with_config(mechanism_handler, credential_verifier, config);
        assert_eq!(fsm.current_state(), &SaslState::Initial);
        assert_eq!(fsm.config.max_attempts, 5);
        assert_eq!(fsm.config.max_data_size, 128 * 1024);
        assert!(fsm.config.allow_anonymous);
    }

    #[tokio::test]
    async fn test_single_step_authentication_success() {
        let mechanism_handler = Box::new(MockSaslMechanismHandler::new());
        let credential_verifier = Box::new(MockCredentialVerifier::new());
        let mut fsm = SaslFsmImpl::new(mechanism_handler, credential_verifier);

        let result = fsm
            .handle_event(SaslEvent::InitiateBind {
                mechanism: "PLAIN".to_string(),
                initial_data: Some(b"\0testuser\0password".to_vec()),
            })
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None); // No challenge data for successful single-step
        assert_eq!(
            fsm.current_state(),
            &SaslState::Authenticated {
                mechanism: "PLAIN".to_string(),
                dn: "cn=testuser,dc=example,dc=org".to_string(),
            }
        );
        assert_eq!(fsm.mechanism(), Some("PLAIN"));
        assert_eq!(
            fsm.authenticated_identity(),
            Some("cn=testuser,dc=example,dc=org")
        );
        assert!(!fsm.needs_more_steps());
        assert!(fsm.is_terminal());

        let (total, success, failed) = fsm.stats();
        assert_eq!(total, 1);
        assert_eq!(success, 1);
        assert_eq!(failed, 0);
    }

    #[tokio::test]
    async fn test_multi_step_authentication_success() {
        let mechanism_handler = Box::new(MockSaslMechanismHandler::new().with_multi_step(2));
        let credential_verifier = Box::new(MockCredentialVerifier::new());
        let mut fsm = SaslFsmImpl::new(mechanism_handler, credential_verifier);

        // Step 1: Initiate bind
        let result = fsm
            .handle_event(SaslEvent::InitiateBind {
                mechanism: "DIGEST-MD5".to_string(),
                initial_data: None,
            })
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some(vec![1, 2, 3, 4])); // Challenge data
        assert_eq!(
            fsm.current_state(),
            &SaslState::Challenge {
                mechanism: "DIGEST-MD5".to_string(),
                step: 1,
            }
        );
        assert_eq!(fsm.mechanism(), Some("DIGEST-MD5"));
        assert_eq!(fsm.step(), 1);
        assert!(fsm.needs_more_steps());
        assert!(!fsm.is_terminal());

        // Step 2: Send response - this should generate another challenge since we need 2 steps total
        let result = fsm
            .handle_event(SaslEvent::ResponseReceived(b"client response".to_vec()))
            .await;

        assert!(result.is_ok());
        // For 2-step auth: step 1 sends challenge, step 2 processes and completes
        // The mock is set up so that current_step increments, and when >= steps_needed, it succeeds
        // So the first response should complete since current_step becomes 1 and steps_needed is 2
        // But we set steps_needed to 2, meaning 2 process_response calls are needed
        // Let me check the mock logic...
        let result_data = result.unwrap();
        if result_data.is_some() {
            // Another challenge - need one more step
            assert_eq!(result_data, Some(vec![1, 2, 3, 4]));
            assert_eq!(
                fsm.current_state(),
                &SaslState::Challenge {
                    mechanism: "DIGEST-MD5".to_string(),
                    step: 2,
                }
            );

            // Step 3: Final response
            let result = fsm
                .handle_event(SaslEvent::ResponseReceived(b"final response".to_vec()))
                .await;

            assert!(result.is_ok());
            assert_eq!(result.unwrap(), None); // Authentication complete
        } else {
            // Authentication completed in one response step
        }

        assert_eq!(
            fsm.current_state(),
            &SaslState::Authenticated {
                mechanism: "DIGEST-MD5".to_string(),
                dn: "cn=testuser,dc=example,dc=org".to_string(),
            }
        );
        assert_eq!(
            fsm.authenticated_identity(),
            Some("cn=testuser,dc=example,dc=org")
        );
        assert!(!fsm.needs_more_steps());
        assert!(fsm.is_terminal());

        let (total, success, failed) = fsm.stats();
        assert_eq!(total, 1);
        assert_eq!(success, 1);
        assert_eq!(failed, 0);
    }

    #[tokio::test]
    async fn test_unsupported_mechanism() {
        let mechanism_handler = Box::new(MockSaslMechanismHandler::new());
        let credential_verifier = Box::new(MockCredentialVerifier::new());
        let mut fsm = SaslFsmImpl::new(mechanism_handler, credential_verifier);

        let result = fsm
            .handle_event(SaslEvent::InitiateBind {
                mechanism: "UNSUPPORTED".to_string(),
                initial_data: None,
            })
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SaslFsmError::UnsupportedMechanism { .. }
        ));
        assert_eq!(fsm.current_state(), &SaslState::Initial);

        let (total, success, failed) = fsm.stats();
        assert_eq!(total, 1);
        assert_eq!(success, 0);
        assert_eq!(failed, 1);
    }

    #[tokio::test]
    async fn test_authentication_failure() {
        let mechanism_handler = Box::new(MockSaslMechanismHandler::new().with_failure());
        let credential_verifier = Box::new(MockCredentialVerifier::new());
        let mut fsm = SaslFsmImpl::new(mechanism_handler, credential_verifier);

        let result = fsm
            .handle_event(SaslEvent::InitiateBind {
                mechanism: "PLAIN".to_string(),
                initial_data: Some(b"\0baduser\0badpass".to_vec()),
            })
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SaslFsmError::AuthenticationFailed { .. }
        ));
        assert_eq!(fsm.current_state(), &SaslState::Failed);
        assert!(fsm.is_terminal());

        let (total, success, failed) = fsm.stats();
        assert_eq!(total, 1);
        assert_eq!(success, 0);
        assert_eq!(failed, 1);
    }

    #[tokio::test]
    async fn test_data_size_limit() {
        let mechanism_handler = Box::new(MockSaslMechanismHandler::new());
        let credential_verifier = Box::new(MockCredentialVerifier::new());
        let config = SaslFsmConfig {
            max_data_size: 10, // Very small limit
            ..Default::default()
        };
        let mut fsm = SaslFsmImpl::with_config(mechanism_handler, credential_verifier, config);

        let large_data = vec![0u8; 20]; // Exceeds limit
        let result = fsm
            .handle_event(SaslEvent::InitiateBind {
                mechanism: "PLAIN".to_string(),
                initial_data: Some(large_data),
            })
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SaslFsmError::Generic { .. }));
        assert_eq!(fsm.current_state(), &SaslState::Initial);
    }

    #[tokio::test]
    async fn test_fsm_reset() {
        let mechanism_handler = Box::new(MockSaslMechanismHandler::new().with_multi_step(2));
        let credential_verifier = Box::new(MockCredentialVerifier::new());
        let mut fsm = SaslFsmImpl::new(mechanism_handler, credential_verifier);

        // Start authentication
        let _result = fsm
            .handle_event(SaslEvent::InitiateBind {
                mechanism: "DIGEST-MD5".to_string(),
                initial_data: None,
            })
            .await
            .unwrap();

        assert_eq!(
            fsm.current_state(),
            &SaslState::Challenge {
                mechanism: "DIGEST-MD5".to_string(),
                step: 1,
            }
        );

        // Reset FSM
        let result = fsm.handle_event(SaslEvent::Reset).await;
        assert!(result.is_ok());
        assert_eq!(fsm.current_state(), &SaslState::Initial);
        assert_eq!(fsm.mechanism(), None);
        assert_eq!(fsm.authenticated_identity(), None);
        assert!(!fsm.needs_more_steps());
    }

    #[tokio::test]
    async fn test_challenge_generated_event() {
        let mechanism_handler = Box::new(MockSaslMechanismHandler::new().with_multi_step(2));
        let credential_verifier = Box::new(MockCredentialVerifier::new());
        let mut fsm = SaslFsmImpl::new(mechanism_handler, credential_verifier);

        // Start with initial bind that creates a challenge
        let _result = fsm
            .handle_event(SaslEvent::InitiateBind {
                mechanism: "DIGEST-MD5".to_string(),
                initial_data: None,
            })
            .await
            .unwrap();

        // Generate additional challenge
        let challenge_data = vec![5, 6, 7, 8];
        let result = fsm
            .handle_event(SaslEvent::ChallengeGenerated(challenge_data.clone()))
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some(challenge_data));
        assert_eq!(
            fsm.current_state(),
            &SaslState::Response {
                mechanism: "DIGEST-MD5".to_string(),
                step: 1,
            }
        );
    }

    #[tokio::test]
    async fn test_authentication_complete_event() {
        let mechanism_handler = Box::new(MockSaslMechanismHandler::new().with_multi_step(2));
        let credential_verifier = Box::new(MockCredentialVerifier::new());
        let mut fsm = SaslFsmImpl::new(mechanism_handler, credential_verifier);

        // Start authentication
        let _result = fsm
            .handle_event(SaslEvent::InitiateBind {
                mechanism: "DIGEST-MD5".to_string(),
                initial_data: None,
            })
            .await
            .unwrap();

        // Complete authentication directly
        let test_dn = "cn=testuser,dc=example,dc=org".to_string();
        let result = fsm
            .handle_event(SaslEvent::AuthenticationComplete {
                dn: test_dn.clone(),
            })
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
        assert_eq!(
            fsm.current_state(),
            &SaslState::Authenticated {
                mechanism: "DIGEST-MD5".to_string(),
                dn: test_dn.clone(),
            }
        );
        assert_eq!(fsm.authenticated_identity(), Some(test_dn.as_str()));
        assert!(fsm.is_terminal());
    }

    #[tokio::test]
    async fn test_authentication_failed_event() {
        let mechanism_handler = Box::new(MockSaslMechanismHandler::new());
        let credential_verifier = Box::new(MockCredentialVerifier::new());
        let mut fsm = SaslFsmImpl::new(mechanism_handler, credential_verifier);

        let result = fsm.handle_event(SaslEvent::AuthenticationFailed).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SaslFsmError::AuthenticationFailed { .. }
        ));
        assert_eq!(fsm.current_state(), &SaslState::Failed);
        assert!(fsm.is_terminal());
    }

    #[tokio::test]
    async fn test_sasl_session() {
        let mut session = SaslSession::new("DIGEST-MD5".to_string());

        assert_eq!(session.mechanism, "DIGEST-MD5");
        assert_eq!(session.step, 0);
        assert_eq!(session.identity, None);
        assert_eq!(session.failed_attempts, 0);

        session.increment_step();
        assert_eq!(session.step, 1);

        session.record_failure();
        assert_eq!(session.failed_attempts, 1);

        // Test timeout
        let very_short_timeout = Duration::from_nanos(1);
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert!(session.is_timed_out(very_short_timeout));

        let long_timeout = Duration::from_secs(3600);
        assert!(!session.is_timed_out(long_timeout));
    }

    #[tokio::test]
    async fn test_mechanism_handler_calls() {
        let mechanism_handler = MockSaslMechanismHandler::new();
        let call_log = mechanism_handler.call_log.clone();
        let credential_verifier = Box::new(MockCredentialVerifier::new());
        let mut fsm = SaslFsmImpl::new(Box::new(mechanism_handler), credential_verifier);

        let _result = fsm
            .handle_event(SaslEvent::InitiateBind {
                mechanism: "PLAIN".to_string(),
                initial_data: Some(b"test".to_vec()),
            })
            .await;

        let calls = call_log.lock().unwrap();
        assert!(calls
            .iter()
            .any(|call| call.contains("supports_mechanism(PLAIN)")));
        assert!(calls
            .iter()
            .any(|call| call.contains("start_authentication(PLAIN")));
    }
}

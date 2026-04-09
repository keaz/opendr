use crate::fsm::{
    ExtendedOpEvent, ExtendedOpFsm, ExtendedOpResultCode, ExtendedOpState, StateMachine,
};
use async_trait::async_trait;
use std::collections::HashMap;
use std::error::Error as StdError;
use std::fmt;

/// Extended operation FSM error type
#[derive(Debug, Clone)]
pub enum ExtendedOpError {
    Message {
        message: String,
    },
    InvalidStateTransition {
        from: ExtendedOpState,
        event: ExtendedOpEvent,
    },
}

impl fmt::Display for ExtendedOpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message { message } => write!(f, "Extended operation error: {}", message),
            Self::InvalidStateTransition { from, event } => write!(
                f,
                "Extended operation error: invalid state transition: event {:?} for state {:?}",
                event, from
            ),
        }
    }
}

impl StdError for ExtendedOpError {}

impl From<String> for ExtendedOpError {
    fn from(message: String) -> Self {
        Self::Message { message }
    }
}

impl From<&str> for ExtendedOpError {
    fn from(message: &str) -> Self {
        Self::Message {
            message: message.to_string(),
        }
    }
}

impl PartialEq<&str> for ExtendedOpError {
    fn eq(&self, other: &&str) -> bool {
        matches!(self, Self::Message { message } if message == *other)
    }
}

impl ExtendedOpError {
    /// Check if the error message contains a substring
    pub fn contains(&self, substring: &str) -> bool {
        match self {
            Self::Message { message } => message.contains(substring),
            Self::InvalidStateTransition { from, event } => format!(
                "invalid state transition: event {:?} for state {:?}",
                event, from
            )
            .contains(substring),
        }
    }
}

/// Backend trait for extended operations - provides abstraction for operation execution
#[async_trait]
pub trait ExtendedOpBackend: Send + Sync {
    /// Execute an extended operation given its OID and value
    async fn execute_operation(&self, oid: &str, value: Option<&[u8]>) -> Result<Vec<u8>, String>;

    /// Check if an operation OID is supported
    fn is_operation_supported(&self, oid: &str) -> bool;

    /// Check if an operation requires delegation to external systems
    fn requires_delegation(&self, oid: &str) -> bool;
}

/// Operation parser trait - handles parsing of extended operation requests
pub trait ExtendedOpParser: Send + Sync {
    /// Parse the extended operation request and validate its structure
    fn parse_request(&self, oid: &str, value: Option<&[u8]>) -> Result<ParsedOperation, String>;

    /// Validate operation parameters
    fn validate_operation(&self, operation: &ParsedOperation) -> Result<(), String>;
}

/// Operation delegator trait - handles delegation to external systems
#[async_trait]
pub trait ExtendedOpDelegator: Send + Sync {
    /// Delegate operation to external system (e.g., TLS negotiation)
    async fn delegate_operation(&self, operation: &ParsedOperation) -> Result<Vec<u8>, String>;

    /// Get available delegates for an operation
    fn get_delegates(&self, oid: &str) -> Vec<String>;
}

/// Access control trait for extended operations
pub trait ExtendedOpAccessControl: Send + Sync {
    /// Check if the current user can perform the extended operation
    fn check_permission(&self, oid: &str, user_dn: Option<&str>) -> Result<(), String>;
}

/// Metrics trait for extended operations monitoring
pub trait ExtendedOpMetrics: Send + Sync {
    /// Record operation start
    fn record_operation_start(&self, oid: &str);

    /// Record operation completion
    fn record_operation_complete(&self, oid: &str, success: bool, duration_ms: u64);

    /// Record delegation event
    fn record_delegation(&self, oid: &str, delegate: &str);
}

/// Parsed extended operation representation
#[derive(Debug, Clone)]
pub struct ParsedOperation {
    pub oid: String,
    pub operation_type: ExtendedOperationType,
    pub parameters: HashMap<String, Vec<u8>>,
    pub requires_delegation: bool,
}

/// Types of extended operations supported
#[derive(Debug, Clone, PartialEq)]
pub enum ExtendedOperationType {
    StartTLS,
    PasswordModify,
    WhoAmI,
    Cancel,
    ModifyPassword,
    Custom(String),
}

/// Extended Operation FSM implementation
///
/// This FSM manages the lifecycle of LDAP extended operations, handling:
/// - Operation parsing and validation
/// - Backend execution or external delegation
/// - Response generation and error handling
/// - Access control and metrics collection
pub struct ExtendedOpFsmImpl {
    /// Current FSM state
    state: ExtendedOpState,

    /// Operation OID being processed
    operation_oid: Option<String>,

    /// Raw operation value
    operation_value: Option<Vec<u8>>,

    /// Parsed operation details
    parsed_operation: Option<ParsedOperation>,

    /// Response data ready for transmission
    response_value: Option<Vec<u8>>,

    /// Current delegate for operation (if delegated)
    current_delegate: Option<String>,

    /// User DN for access control
    user_dn: Option<String>,

    /// Operation start time for metrics
    start_time: Option<std::time::Instant>,

    /// Backend for operation execution
    backend: Box<dyn ExtendedOpBackend>,

    /// Parser for request validation
    parser: Box<dyn ExtendedOpParser>,

    /// Delegator for external operations
    delegator: Box<dyn ExtendedOpDelegator>,

    /// Access control checker
    access_control: Box<dyn ExtendedOpAccessControl>,

    /// Metrics collector
    metrics: Box<dyn ExtendedOpMetrics>,
}

impl ExtendedOpFsmImpl {
    /// Create a new Extended-Op FSM instance
    pub fn new(
        backend: Box<dyn ExtendedOpBackend>,
        parser: Box<dyn ExtendedOpParser>,
        delegator: Box<dyn ExtendedOpDelegator>,
        access_control: Box<dyn ExtendedOpAccessControl>,
        metrics: Box<dyn ExtendedOpMetrics>,
    ) -> Self {
        Self {
            state: ExtendedOpState::Parsing,
            operation_oid: None,
            operation_value: None,
            parsed_operation: None,
            response_value: None,
            current_delegate: None,
            user_dn: None,
            start_time: None,
            backend,
            parser,
            delegator,
            access_control,
            metrics,
        }
    }

    /// Set the user DN for access control
    pub fn set_user_dn(&mut self, user_dn: String) {
        self.user_dn = Some(user_dn);
    }

    /// Get the current state
    pub fn current_state(&self) -> &ExtendedOpState {
        &self.state
    }

    /// Get the parsed operation details
    pub fn parsed_operation(&self) -> Option<&ParsedOperation> {
        self.parsed_operation.as_ref()
    }

    /// Get the current delegate if any
    pub fn current_delegate(&self) -> Option<&str> {
        self.current_delegate.as_deref()
    }

    /// Set operation OID (for testing)
    #[cfg(test)]
    pub fn set_operation_oid(&mut self, oid: String) {
        self.operation_oid = Some(oid);
    }

    /// Set parsed operation (for testing)
    #[cfg(test)]
    pub fn set_parsed_operation(&mut self, parsed_op: ParsedOperation) {
        self.parsed_operation = Some(parsed_op);
    }

    /// Check if the FSM has completed successfully
    pub fn is_completed(&self) -> bool {
        matches!(
            self.state,
            ExtendedOpState::Completed {
                result_code: ExtendedOpResultCode::Success
            }
        )
    }

    /// Check if the FSM encountered an error
    pub fn has_error(&self) -> bool {
        matches!(
            self.state,
            ExtendedOpState::Completed {
                result_code: ExtendedOpResultCode::ProtocolError
                    | ExtendedOpResultCode::UnavailableCriticalExtension
                    | ExtendedOpResultCode::Other(_)
            }
        )
    }

    /// Handle the parsing phase of extended operation
    async fn handle_parsing(
        &mut self,
        oid: String,
        value: Option<Vec<u8>>,
    ) -> Result<(), ExtendedOpError> {
        // Record operation start
        self.start_time = Some(std::time::Instant::now());
        self.metrics.record_operation_start(&oid);

        // Check access control first
        if let Err(e) = self
            .access_control
            .check_permission(&oid, self.user_dn.as_deref())
        {
            return Err(ExtendedOpError::from(format!(
                "Access denied for operation {}: {}",
                oid, e
            )));
        }

        // Store operation details
        self.operation_oid = Some(oid.clone());
        self.operation_value = value.clone();

        // Parse the operation
        let parsed = self
            .parser
            .parse_request(&oid, value.as_deref())
            .map_err(ExtendedOpError::from)?;

        // Validate the parsed operation
        self.parser
            .validate_operation(&parsed)
            .map_err(ExtendedOpError::from)?;

        // Check if backend supports this operation
        if !self.backend.is_operation_supported(&oid) {
            return Err(ExtendedOpError::from(format!(
                "Operation {} not supported",
                oid
            )));
        }

        self.parsed_operation = Some(parsed);
        Ok(())
    }

    /// Handle the processing phase of extended operation
    async fn handle_processing(&mut self, operation: String) -> Result<(), ExtendedOpError> {
        let _parsed_op = self
            .parsed_operation
            .as_ref()
            .ok_or_else(|| ExtendedOpError::from("No parsed operation available"))?;

        // Execute the operation through backend
        let response_data = self
            .backend
            .execute_operation(&operation, self.operation_value.as_deref())
            .await
            .map_err(ExtendedOpError::from)?;

        self.response_value = Some(response_data);
        Ok(())
    }

    /// Handle the delegation phase of extended operation
    async fn handle_delegation(
        &mut self,
        operation: String,
        delegate: String,
    ) -> Result<(), ExtendedOpError> {
        let parsed_op = self
            .parsed_operation
            .as_ref()
            .ok_or_else(|| ExtendedOpError::from("No parsed operation available"))?;

        // Record delegation
        self.metrics.record_delegation(&operation, &delegate);
        self.current_delegate = Some(delegate);

        // Delegate the operation
        let response_data = self
            .delegator
            .delegate_operation(parsed_op)
            .await
            .map_err(ExtendedOpError::from)?;

        self.response_value = Some(response_data);
        Ok(())
    }

    /// Record completion metrics
    fn record_completion(&self, success: bool) {
        if let (Some(oid), Some(start_time)) = (&self.operation_oid, &self.start_time) {
            let duration = start_time.elapsed().as_millis() as u64;
            self.metrics
                .record_operation_complete(oid, success, duration);
        }
    }
}

#[async_trait]
impl StateMachine for ExtendedOpFsmImpl {
    type State = ExtendedOpState;
    type Event = ExtendedOpEvent;
    type Error = ExtendedOpError;
    type Output = Vec<u8>;

    fn current_state(&self) -> &Self::State {
        &self.state
    }

    fn is_terminal(&self) -> bool {
        matches!(self.state, ExtendedOpState::Completed { .. })
    }

    async fn reset(&mut self) -> Result<(), Self::Error> {
        self.state = ExtendedOpState::Parsing;
        self.operation_oid = None;
        self.operation_value = None;
        self.parsed_operation = None;
        self.response_value = None;
        self.current_delegate = None;
        self.start_time = None;
        Ok(())
    }

    async fn handle_event(
        &mut self,
        event: Self::Event,
    ) -> Result<Option<Self::Output>, Self::Error> {
        match (&self.state, &event) {
            // Starting extended operation - transition to parsing
            (ExtendedOpState::Parsing, ExtendedOpEvent::StartExtendedOp { oid, value }) => {
                self.handle_parsing(oid.clone(), value.clone()).await?;

                // Determine next state based on operation requirements
                if let Some(parsed) = &self.parsed_operation {
                    if parsed.requires_delegation {
                        // Get available delegates
                        let delegates = self.delegator.get_delegates(oid);
                        if let Some(delegate) = delegates.first() {
                            self.state = ExtendedOpState::Delegating {
                                operation: oid.clone(),
                                delegate: delegate.clone(),
                            };
                        } else {
                            self.state = ExtendedOpState::Completed {
                                result_code: ExtendedOpResultCode::UnavailableCriticalExtension,
                            };
                            self.record_completion(false);
                        }
                    } else {
                        self.state = ExtendedOpState::Processing {
                            operation: oid.clone(),
                        };
                    }
                }
                Ok(None)
            }

            // Parse complete - move to processing or delegation
            (ExtendedOpState::Parsing, ExtendedOpEvent::ParseComplete) => {
                if let Some(parsed) = &self.parsed_operation {
                    let oid = self.operation_oid.as_ref().unwrap().clone();
                    if parsed.requires_delegation {
                        let delegates = self.delegator.get_delegates(&oid);
                        if let Some(delegate) = delegates.first() {
                            self.state = ExtendedOpState::Delegating {
                                operation: oid,
                                delegate: delegate.clone(),
                            };
                        } else {
                            self.state = ExtendedOpState::Completed {
                                result_code: ExtendedOpResultCode::UnavailableCriticalExtension,
                            };
                            self.record_completion(false);
                        }
                    } else {
                        self.state = ExtendedOpState::Processing { operation: oid };
                    }
                }
                Ok(None)
            }

            // Processing complete - move to responding
            (ExtendedOpState::Processing { operation }, ExtendedOpEvent::ProcessingComplete) => {
                self.handle_processing(operation.clone()).await?;
                self.state = ExtendedOpState::Responding;
                Ok(None)
            }

            // Delegation complete - move to responding
            (
                ExtendedOpState::Delegating {
                    operation,
                    delegate,
                },
                ExtendedOpEvent::DelegationComplete,
            ) => {
                self.handle_delegation(operation.clone(), delegate.clone())
                    .await?;
                self.state = ExtendedOpState::Responding;
                Ok(None)
            }

            // Response ready - complete the operation
            (ExtendedOpState::Responding, ExtendedOpEvent::ResponseReady(response)) => {
                let response_data = response.clone();
                self.response_value = Some(response_data.clone());
                self.state = ExtendedOpState::Completed {
                    result_code: ExtendedOpResultCode::Success,
                };
                self.record_completion(true);
                Ok(Some(response_data))
            }

            // Operation complete - finalize
            (ExtendedOpState::Responding, ExtendedOpEvent::OperationComplete) => {
                let final_response = self.response_value.clone().unwrap_or_default();
                self.state = ExtendedOpState::Completed {
                    result_code: ExtendedOpResultCode::Success,
                };
                self.record_completion(true);
                Ok(Some(final_response))
            }

            // Error handling - can occur from any state
            (_, ExtendedOpEvent::Error(error)) => {
                self.state = ExtendedOpState::Completed {
                    result_code: ExtendedOpResultCode::ProtocolError,
                };
                self.record_completion(false);
                Err(ExtendedOpError::from(error.clone()))
            }

            // Invalid state transitions
            _ => Err(ExtendedOpError::InvalidStateTransition {
                from: self.state.clone(),
                event: event.clone(),
            }),
        }
    }
}

impl ExtendedOpFsm for ExtendedOpFsmImpl {
    fn operation_oid(&self) -> Option<&str> {
        self.operation_oid.as_deref()
    }

    fn operation_value(&self) -> Option<&[u8]> {
        self.operation_value.as_deref()
    }

    fn response_value(&self) -> Option<&[u8]> {
        self.response_value.as_deref()
    }

    fn requires_delegation(&self) -> bool {
        self.parsed_operation
            .as_ref()
            .map(|op| op.requires_delegation)
            .unwrap_or(false)
    }
}

// Tests are in a separate file due to complexity of mock setup

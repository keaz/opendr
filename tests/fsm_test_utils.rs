//! FSM Testing Utilities - Phase 2.3
//!
//! Helper framework for testing complex FSM state graphs, providing:
//! - State transition assertion helpers
//! - FSM mock builders with fluent API
//! - Event sequence testing utilities
//! - State validation helpers
//! - Error scenario builders
//!
//! This module simplifies FSM testing by providing reusable utilities
//! for common testing patterns across all FSM implementations.

use std::collections::HashMap;
use std::fmt::Debug;
use std::time::Duration;

// ============================================================================
// State Transition Assertion Helpers
// ============================================================================

/// Assert that an FSM transitions from one state to another when given an event
#[macro_export]
macro_rules! assert_state_transition {
    ($fsm:expr, $from_state:pat, $event:expr, $to_state:pat) => {
        assert!(
            matches!($fsm.current_state(), $from_state),
            "FSM not in expected initial state"
        );
        $fsm.handle_event($event)
            .await
            .expect("Event handling failed");
        assert!(
            matches!($fsm.current_state(), $to_state),
            "FSM did not transition to expected state"
        );
    };
}

/// Assert that an FSM remains in the same state after an event
#[macro_export]
macro_rules! assert_state_unchanged {
    ($fsm:expr, $expected_state:pat, $event:expr) => {
        assert!(
            matches!($fsm.current_state(), $expected_state),
            "FSM not in expected state before event"
        );
        $fsm.handle_event($event)
            .await
            .expect("Event handling failed");
        assert!(
            matches!($fsm.current_state(), $expected_state),
            "FSM state unexpectedly changed"
        );
    };
}

/// Assert that an event causes an FSM to enter an error state
#[macro_export]
macro_rules! assert_error_state {
    ($fsm:expr, $event:expr) => {
        let result = $fsm.handle_event($event).await;
        assert!(
            result.is_err() || $fsm.is_error(),
            "FSM did not enter error state"
        );
    };
}

/// Assert that an FSM is in a terminal state
#[macro_export]
macro_rules! assert_terminal_state {
    ($fsm:expr) => {
        assert!($fsm.is_terminal(), "FSM is not in a terminal state");
    };
}

// ============================================================================
// FSM Mock Builder
// ============================================================================

/// Builder for creating mock FSMs with predefined behaviors
pub struct FsmMockBuilder<S>
where
    S: Clone + Debug + PartialEq + Eq + std::hash::Hash,
{
    initial_state: S,
    transitions: HashMap<(S, String), S>,
    error_events: Vec<String>,
    terminal_states: Vec<S>,
}

impl<S> FsmMockBuilder<S>
where
    S: Clone + Debug + PartialEq + Eq + std::hash::Hash,
{
    /// Create a new mock builder with an initial state
    pub fn new(initial_state: S) -> Self {
        Self {
            initial_state,
            transitions: HashMap::new(),
            error_events: Vec::new(),
            terminal_states: Vec::new(),
        }
    }

    /// Add a state transition rule
    pub fn add_transition(mut self, from: S, event: &str, to: S) -> Self {
        self.transitions.insert((from, event.to_string()), to);
        self
    }

    /// Mark an event as causing an error
    pub fn add_error_event(mut self, event: &str) -> Self {
        self.error_events.push(event.to_string());
        self
    }

    /// Mark a state as terminal
    pub fn add_terminal_state(mut self, state: S) -> Self {
        self.terminal_states.push(state);
        self
    }

    /// Build the mock FSM configuration
    pub fn build(self) -> FsmMockConfig<S> {
        FsmMockConfig {
            initial_state: self.initial_state,
            transitions: self.transitions,
            error_events: self.error_events,
            terminal_states: self.terminal_states,
        }
    }
}

/// Configuration for a mock FSM
#[derive(Clone)]
pub struct FsmMockConfig<S>
where
    S: Clone + Debug + PartialEq + Eq + std::hash::Hash,
{
    pub initial_state: S,
    pub transitions: HashMap<(S, String), S>,
    pub error_events: Vec<String>,
    pub terminal_states: Vec<S>,
}

// ============================================================================
// Event Sequence Testing
// ============================================================================

/// Represents a sequence of events to test
#[derive(Debug, Clone)]
pub struct EventSequence {
    events: Vec<String>,
    expected_states: Vec<String>,
    expected_errors: Vec<bool>,
}

impl EventSequence {
    /// Create a new event sequence
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            expected_states: Vec::new(),
            expected_errors: Vec::new(),
        }
    }

    /// Add an event that should succeed and transition to a state
    pub fn then_event(mut self, event: &str, expected_state: &str) -> Self {
        self.events.push(event.to_string());
        self.expected_states.push(expected_state.to_string());
        self.expected_errors.push(false);
        self
    }

    /// Add an event that should cause an error
    pub fn then_error(mut self, event: &str) -> Self {
        self.events.push(event.to_string());
        self.expected_states.push(String::new()); // Don't care about state
        self.expected_errors.push(true);
        self
    }

    /// Get the events in the sequence
    pub fn events(&self) -> &[String] {
        &self.events
    }

    /// Get the expected states
    pub fn expected_states(&self) -> &[String] {
        &self.expected_states
    }

    /// Get the error expectations
    pub fn expected_errors(&self) -> &[bool] {
        &self.expected_errors
    }

    /// Check if an event at index should error
    pub fn should_error(&self, index: usize) -> bool {
        self.expected_errors.get(index).copied().unwrap_or(false)
    }

    /// Get expected state at index
    pub fn expected_state(&self, index: usize) -> Option<&str> {
        self.expected_states.get(index).map(|s| s.as_str())
    }

    /// Get the length of the sequence
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Check if the sequence is empty
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

impl Default for EventSequence {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// State Validation Helpers
// ============================================================================

/// Validate that a state matches expected properties
pub struct StateValidator {
    name: String,
    is_terminal: bool,
    is_error: bool,
    properties: HashMap<String, String>,
}

impl StateValidator {
    /// Create a new state validator
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            is_terminal: false,
            is_error: false,
            properties: HashMap::new(),
        }
    }

    /// Mark that this state should be terminal
    pub fn terminal(mut self) -> Self {
        self.is_terminal = true;
        self
    }

    /// Mark that this state should be an error state
    pub fn error(mut self) -> Self {
        self.is_error = true;
        self
    }

    /// Add an expected property
    pub fn with_property(mut self, key: &str, value: &str) -> Self {
        self.properties.insert(key.to_string(), value.to_string());
        self
    }

    /// Get the state name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Check if state should be terminal
    pub fn should_be_terminal(&self) -> bool {
        self.is_terminal
    }

    /// Check if state should be error
    pub fn should_be_error(&self) -> bool {
        self.is_error
    }

    /// Get expected properties
    pub fn properties(&self) -> &HashMap<String, String> {
        &self.properties
    }
}

// ============================================================================
// Error Scenario Builders
// ============================================================================

/// Builder for common error scenarios
pub struct ErrorScenario {
    scenario_type: ErrorScenarioType,
    trigger_event: String,
    expected_error_message: Option<String>,
    recovery_events: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ErrorScenarioType {
    /// Invalid state transition
    InvalidTransition,
    /// Timeout occurred
    Timeout,
    /// Resource unavailable
    ResourceUnavailable,
    /// Authentication failed
    AuthenticationFailed,
    /// Protocol violation
    ProtocolViolation,
    /// Custom error scenario
    Custom(String),
}

impl ErrorScenario {
    /// Create a new error scenario
    pub fn new(scenario_type: ErrorScenarioType, trigger_event: &str) -> Self {
        Self {
            scenario_type,
            trigger_event: trigger_event.to_string(),
            expected_error_message: None,
            recovery_events: Vec::new(),
        }
    }

    /// Set expected error message
    pub fn expect_message(mut self, message: &str) -> Self {
        self.expected_error_message = Some(message.to_string());
        self
    }

    /// Add a recovery event
    pub fn with_recovery(mut self, event: &str) -> Self {
        self.recovery_events.push(event.to_string());
        self
    }

    /// Get the scenario type
    pub fn scenario_type(&self) -> &ErrorScenarioType {
        &self.scenario_type
    }

    /// Get the trigger event
    pub fn trigger_event(&self) -> &str {
        &self.trigger_event
    }

    /// Get expected error message if any
    pub fn expected_error_message(&self) -> Option<&str> {
        self.expected_error_message.as_deref()
    }

    /// Get recovery events
    pub fn recovery_events(&self) -> &[String] {
        &self.recovery_events
    }
}

// ============================================================================
// Timeout Testing Utilities
// ============================================================================

/// Helper for testing timeout scenarios
pub struct TimeoutTester {
    timeout_duration: Duration,
    grace_period: Duration,
}

impl TimeoutTester {
    /// Create a new timeout tester
    pub fn new(timeout_duration: Duration) -> Self {
        Self {
            timeout_duration,
            grace_period: Duration::from_millis(100),
        }
    }

    /// Set the grace period for timeout checks
    pub fn with_grace_period(mut self, grace_period: Duration) -> Self {
        self.grace_period = grace_period;
        self
    }

    /// Get the timeout duration
    pub fn timeout_duration(&self) -> Duration {
        self.timeout_duration
    }

    /// Get the grace period
    pub fn grace_period(&self) -> Duration {
        self.grace_period
    }

    /// Calculate wait time that should trigger timeout
    pub fn wait_for_timeout(&self) -> Duration {
        self.timeout_duration + self.grace_period
    }

    /// Calculate wait time that should not trigger timeout
    pub fn wait_within_timeout(&self) -> Duration {
        self.timeout_duration / 2
    }
}

// ============================================================================
// FSM Lifecycle Helpers
// ============================================================================

/// Helper for testing FSM lifecycle
pub struct LifecycleTest {
    stages: Vec<LifecycleStage>,
}

#[derive(Debug, Clone)]
pub struct LifecycleStage {
    pub name: String,
    pub events: Vec<String>,
    pub expected_final_state: String,
}

impl LifecycleTest {
    /// Create a new lifecycle test
    pub fn new() -> Self {
        Self { stages: Vec::new() }
    }

    /// Add a lifecycle stage
    pub fn add_stage(
        mut self,
        name: &str,
        events: Vec<String>,
        expected_final_state: &str,
    ) -> Self {
        self.stages.push(LifecycleStage {
            name: name.to_string(),
            events,
            expected_final_state: expected_final_state.to_string(),
        });
        self
    }

    /// Get all stages
    pub fn stages(&self) -> &[LifecycleStage] {
        &self.stages
    }

    /// Get number of stages
    pub fn stage_count(&self) -> usize {
        self.stages.len()
    }
}

impl Default for LifecycleTest {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Concurrent Testing Utilities
// ============================================================================

/// Helper for testing concurrent FSM operations
pub struct ConcurrentTest {
    operation_count: usize,
    operations: Vec<ConcurrentOperation>,
}

#[derive(Debug, Clone)]
pub struct ConcurrentOperation {
    pub id: usize,
    pub events: Vec<String>,
    pub expected_result: OperationResult,
}

#[derive(Debug, Clone, PartialEq)]
pub enum OperationResult {
    Success,
    Error,
    Timeout,
}

impl ConcurrentTest {
    /// Create a new concurrent test
    pub fn new(operation_count: usize) -> Self {
        Self {
            operation_count,
            operations: Vec::new(),
        }
    }

    /// Add an operation
    pub fn add_operation(
        mut self,
        id: usize,
        events: Vec<String>,
        expected_result: OperationResult,
    ) -> Self {
        self.operations.push(ConcurrentOperation {
            id,
            events,
            expected_result,
        });
        self
    }

    /// Get all operations
    pub fn operations(&self) -> &[ConcurrentOperation] {
        &self.operations
    }

    /// Get operation count
    pub fn operation_count(&self) -> usize {
        self.operation_count
    }
}

// ============================================================================
// State Graph Visualization Helpers
// ============================================================================

/// Helper for visualizing FSM state graphs (for debugging)
pub struct StateGraph {
    states: Vec<String>,
    transitions: Vec<(String, String, String)>, // (from, event, to)
}

impl StateGraph {
    /// Create a new state graph
    pub fn new() -> Self {
        Self {
            states: Vec::new(),
            transitions: Vec::new(),
        }
    }

    /// Add a state
    pub fn add_state(mut self, state: &str) -> Self {
        if !self.states.contains(&state.to_string()) {
            self.states.push(state.to_string());
        }
        self
    }

    /// Add a transition
    pub fn add_transition(mut self, from: &str, event: &str, to: &str) -> Self {
        self.transitions
            .push((from.to_string(), event.to_string(), to.to_string()));
        self.add_state(from).add_state(to)
    }

    /// Generate a simple text representation of the graph
    pub fn to_text(&self) -> String {
        let mut output = String::new();
        output.push_str("State Graph:\n");
        output.push_str("States:\n");
        for state in &self.states {
            output.push_str(&format!("  - {}\n", state));
        }
        output.push_str("\nTransitions:\n");
        for (from, event, to) in &self.transitions {
            output.push_str(&format!("  {} --[{}]--> {}\n", from, event, to));
        }
        output
    }

    /// Get all states
    pub fn states(&self) -> &[String] {
        &self.states
    }

    /// Get all transitions
    pub fn transitions(&self) -> &[(String, String, String)] {
        &self.transitions
    }
}

impl Default for StateGraph {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Test Data Builders
// ============================================================================

/// Builder for test LDAP entries
pub struct TestEntryBuilder {
    dn: String,
    attributes: HashMap<String, Vec<String>>,
}

impl TestEntryBuilder {
    /// Create a new test entry builder
    pub fn new(dn: &str) -> Self {
        Self {
            dn: dn.to_string(),
            attributes: HashMap::new(),
        }
    }

    /// Add a single-valued attribute
    pub fn with_attr(mut self, name: &str, value: &str) -> Self {
        self.attributes
            .insert(name.to_string(), vec![value.to_string()]);
        self
    }

    /// Add a multi-valued attribute
    pub fn with_multi_attr(mut self, name: &str, values: Vec<String>) -> Self {
        self.attributes.insert(name.to_string(), values);
        self
    }

    /// Get the DN
    pub fn dn(&self) -> &str {
        &self.dn
    }

    /// Get the attributes
    pub fn attributes(&self) -> &HashMap<String, Vec<String>> {
        &self.attributes
    }

    /// Build the entry as a HashMap
    pub fn build(self) -> (String, HashMap<String, Vec<String>>) {
        (self.dn, self.attributes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_sequence_builder() {
        let sequence = EventSequence::new()
            .then_event("start", "running")
            .then_event("process", "processing")
            .then_error("invalid")
            .then_event("reset", "idle");

        assert_eq!(sequence.len(), 4);
        assert_eq!(sequence.events()[0], "start");
        assert_eq!(sequence.expected_state(0), Some("running"));
        assert!(!sequence.should_error(0));
        assert!(sequence.should_error(2));
    }

    #[test]
    fn test_state_validator() {
        let validator = StateValidator::new("test_state")
            .terminal()
            .with_property("key", "value");

        assert_eq!(validator.name(), "test_state");
        assert!(validator.should_be_terminal());
        assert!(!validator.should_be_error());
        assert_eq!(
            validator.properties().get("key").map(|s| s.as_str()),
            Some("value")
        );
    }

    #[test]
    fn test_error_scenario() {
        let scenario = ErrorScenario::new(ErrorScenarioType::InvalidTransition, "bad_event")
            .expect_message("Invalid transition")
            .with_recovery("reset");

        assert_eq!(scenario.trigger_event(), "bad_event");
        assert_eq!(
            scenario.expected_error_message(),
            Some("Invalid transition")
        );
        assert_eq!(scenario.recovery_events().len(), 1);
    }

    #[test]
    fn test_timeout_tester() {
        let tester = TimeoutTester::new(Duration::from_secs(5))
            .with_grace_period(Duration::from_millis(200));

        assert!(tester.wait_for_timeout() > Duration::from_secs(5));
        assert!(tester.wait_within_timeout() < Duration::from_secs(5));
    }

    #[test]
    fn test_lifecycle_test() {
        let lifecycle = LifecycleTest::new()
            .add_stage("init", vec!["start".to_string()], "running")
            .add_stage("work", vec!["process".to_string()], "complete")
            .add_stage("cleanup", vec!["close".to_string()], "idle");

        assert_eq!(lifecycle.stage_count(), 3);
        assert_eq!(lifecycle.stages()[0].name, "init");
    }

    #[test]
    fn test_concurrent_test() {
        let test = ConcurrentTest::new(2)
            .add_operation(1, vec!["event1".to_string()], OperationResult::Success)
            .add_operation(2, vec!["event2".to_string()], OperationResult::Success);

        assert_eq!(test.operation_count(), 2);
        assert_eq!(test.operations().len(), 2);
    }

    #[test]
    fn test_state_graph() {
        let graph = StateGraph::new()
            .add_transition("idle", "start", "running")
            .add_transition("running", "stop", "idle");

        assert_eq!(graph.states().len(), 2);
        assert_eq!(graph.transitions().len(), 2);
        assert!(graph.to_text().contains("idle"));
    }

    #[test]
    fn test_entry_builder() {
        let (dn, attrs) = TestEntryBuilder::new("cn=test,dc=example,dc=com")
            .with_attr("cn", "test")
            .with_multi_attr("objectClass", vec!["top".to_string(), "person".to_string()])
            .build();

        assert_eq!(dn, "cn=test,dc=example,dc=com");
        assert_eq!(attrs.get("cn"), Some(&vec!["test".to_string()]));
        assert_eq!(attrs.get("objectClass").map(|v| v.len()), Some(2));
    }

    #[test]
    fn test_fsm_mock_builder() {
        let config = FsmMockBuilder::<String>::new("idle".to_string())
            .add_transition("idle".to_string(), "start", "running".to_string())
            .add_terminal_state("done".to_string())
            .add_error_event("invalid")
            .build();

        assert_eq!(config.initial_state, "idle");
        assert_eq!(config.transitions.len(), 1);
        assert_eq!(config.terminal_states.len(), 1);
        assert_eq!(config.error_events.len(), 1);
    }
}

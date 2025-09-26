//! Integration tests for the opendr LDAP server
//!
//! This module contains comprehensive integration tests for all FSM implementations,
//! testing their lifecycle, state transitions, concurrent operations, and error scenarios.

pub mod test_utils;
pub mod fsm_lifecycle;
pub mod fsm_concurrent;
pub mod fsm_errors;
pub mod ldap_operations;
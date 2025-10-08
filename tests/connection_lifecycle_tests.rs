//! Unit tests for Connection Lifecycle Management (Task 3.2)
//!
//! This test suite validates the connection lifecycle management implementation,
//! focusing on configuration, state management, statistics, and helper functions.
//! Full integration tests with persist mode manager are in separate files.

use opendr::connection_lifecycle::{
    can_reconnect, is_connection_active, is_terminal_state, ConnectionLifecycleState,
    LifecycleConfig, LifecycleStats,
};
use std::time::{Duration, Instant};

// ================================================================================================
// Configuration Tests
// ================================================================================================

#[tokio::test]
async fn test_lifecycle_config_creation() {
    let config = LifecycleConfig::default();
    assert_eq!(config.connection_timeout, Duration::from_secs(30));
    assert_eq!(config.operation_timeout, Duration::from_secs(60));
    assert_eq!(config.reconnect_base_delay, Duration::from_secs(1));
    assert_eq!(config.reconnect_max_delay, Duration::from_secs(60));
    assert_eq!(config.max_reconnect_attempts, 5);
    assert!(config.enable_exponential_backoff);
}

#[tokio::test]
async fn test_lifecycle_config_custom() {
    let config = LifecycleConfig {
        connection_timeout: Duration::from_secs(10),
        operation_timeout: Duration::from_secs(20),
        reconnect_base_delay: Duration::from_millis(500),
        reconnect_max_delay: Duration::from_secs(30),
        max_reconnect_attempts: 10,
        enable_exponential_backoff: false,
        backoff_multiplier: 1.5,
        enable_jitter: false,
        max_jitter_percent: 0.1,
    };

    assert_eq!(config.connection_timeout, Duration::from_secs(10));
    assert_eq!(config.max_reconnect_attempts, 10);
    assert!(!config.enable_exponential_backoff);
}

// ================================================================================================
// State Management Tests
// ================================================================================================

#[tokio::test]
async fn test_lifecycle_state_creation() {
    let state = ConnectionLifecycleState::Closed;
    assert_eq!(state, ConnectionLifecycleState::Closed);
}

#[tokio::test]
async fn test_lifecycle_state_transitions() {
    let mut state = ConnectionLifecycleState::Closed;
    assert_eq!(state, ConnectionLifecycleState::Closed);

    state = ConnectionLifecycleState::Connecting {
        attempt: 1,
        started_at: Instant::now(),
    };
    assert!(matches!(state, ConnectionLifecycleState::Connecting { .. }));

    state = ConnectionLifecycleState::Active {
        connected_at: Instant::now(),
    };
    assert!(matches!(state, ConnectionLifecycleState::Active { .. }));

    state = ConnectionLifecycleState::Failed {
        reason: "Test".to_string(),
        will_reconnect: true,
        next_attempt_at: None,
    };
    assert!(matches!(state, ConnectionLifecycleState::Failed { .. }));
}

#[tokio::test]
async fn test_lifecycle_state_helpers() {
    let active_state = ConnectionLifecycleState::Active {
        connected_at: Instant::now(),
    };
    assert!(is_connection_active(&active_state));
    assert!(!is_terminal_state(&active_state));
    assert!(!can_reconnect(&active_state));

    let failed_state = ConnectionLifecycleState::Failed {
        reason: "Test".to_string(),
        will_reconnect: true,
        next_attempt_at: None,
    };
    assert!(!is_connection_active(&failed_state));
    assert!(!is_terminal_state(&failed_state));
    assert!(can_reconnect(&failed_state));

    let terminated_state = ConnectionLifecycleState::Terminated {
        reason: "Test".to_string(),
        terminated_at: Instant::now(),
    };
    assert!(!is_connection_active(&terminated_state));
    assert!(is_terminal_state(&terminated_state));
    assert!(!can_reconnect(&terminated_state));
}

// ================================================================================================
// Statistics Tests
// ================================================================================================

#[tokio::test]
async fn test_lifecycle_stats_creation() {
    let stats = LifecycleStats::new();
    assert_eq!(stats.total_connection_attempts, 0);
    assert_eq!(stats.successful_connections, 0);
    assert_eq!(stats.failed_connection_attempts, 0);
    assert_eq!(stats.total_reconnections, 0);
    assert_eq!(stats.network_interruptions, 0);
    assert!(matches!(stats.state, ConnectionLifecycleState::Closed));
}

#[tokio::test]
async fn test_lifecycle_stats_success_rate() {
    let mut stats = LifecycleStats::new();
    assert_eq!(stats.success_rate(), 0.0);

    stats.total_connection_attempts = 10;
    stats.successful_connections = 7;
    assert_eq!(stats.success_rate(), 0.7);

    stats.successful_connections = 10;
    assert_eq!(stats.success_rate(), 1.0);
}

#[tokio::test]
async fn test_lifecycle_stats_reconnection_rate() {
    let mut stats = LifecycleStats::new();
    assert_eq!(stats.reconnection_success_rate(), 0.0);

    stats.total_reconnections = 5;
    stats.successful_reconnections = 4;
    assert_eq!(stats.reconnection_success_rate(), 0.8);
}

#[tokio::test]
async fn test_lifecycle_stats_uptime() {
    let mut stats = LifecycleStats::new();
    assert!(stats.current_uptime().is_none());

    stats.current_connection_start = Some(Instant::now());
    tokio::time::sleep(Duration::from_millis(100)).await;

    let uptime = stats.current_uptime();
    assert!(uptime.is_some());
    assert!(uptime.unwrap() >= Duration::from_millis(100));
}

// ================================================================================================
// Helper Function Tests
// ================================================================================================

#[tokio::test]
async fn test_is_connection_active_helper() {
    assert!(is_connection_active(&ConnectionLifecycleState::Active {
        connected_at: Instant::now()
    }));

    assert!(!is_connection_active(&ConnectionLifecycleState::Closed));

    assert!(!is_connection_active(
        &ConnectionLifecycleState::Connecting {
            attempt: 1,
            started_at: Instant::now()
        }
    ));

    assert!(!is_connection_active(&ConnectionLifecycleState::Failed {
        reason: "Test".to_string(),
        will_reconnect: true,
        next_attempt_at: None
    }));
}

#[tokio::test]
async fn test_is_terminal_state_helper() {
    assert!(is_terminal_state(&ConnectionLifecycleState::Terminated {
        reason: "Test".to_string(),
        terminated_at: Instant::now()
    }));

    assert!(!is_terminal_state(&ConnectionLifecycleState::Closed));
    assert!(!is_terminal_state(&ConnectionLifecycleState::Active {
        connected_at: Instant::now()
    }));
}

#[tokio::test]
async fn test_can_reconnect_helper() {
    assert!(can_reconnect(&ConnectionLifecycleState::Failed {
        reason: "Test".to_string(),
        will_reconnect: true,
        next_attempt_at: None
    }));

    assert!(can_reconnect(&ConnectionLifecycleState::Degraded {
        reason: "Test".to_string(),
        since: Instant::now()
    }));

    assert!(can_reconnect(&ConnectionLifecycleState::Closed));

    assert!(!can_reconnect(&ConnectionLifecycleState::Terminated {
        reason: "Test".to_string(),
        terminated_at: Instant::now()
    }));

    assert!(!can_reconnect(&ConnectionLifecycleState::Active {
        connected_at: Instant::now()
    }));
}

// ==================================================================================================
// Note: Full integration tests with ConnectionLifecycleManager are pending proper mock implementations
// These unit tests validate the core types, states, statistics, and helper functions
// Integration tests will be added once the full replication system is integrated
// ==================================================================================================

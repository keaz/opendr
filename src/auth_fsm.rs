//! Auth FSM Implementation for LDAP Simple Bind
//!
//! This module implements the authentication state machine for LDAP Simple Bind
//! operations. It handles the transition between anonymous and authenticated states
//! and manages the authentication lifecycle.

use crate::fsm::{AuthEvent, AuthFsm, AuthLevel, AuthState, StateMachine};
use async_trait::async_trait;
use std::time::{Duration, Instant};
use thiserror::Error;

/// Errors that can occur during authentication
#[derive(Error, Debug, Clone, PartialEq)]
pub enum AuthError {
    #[error("Invalid state transition from {from:?} to {to:?}")]
    InvalidStateTransition { from: AuthState, to: AuthState },

    #[error("Authentication failed: {reason}")]
    AuthenticationFailed { reason: String },

    #[error("Invalid credentials provided")]
    InvalidCredentials,

    #[error("Directory backend error: {message}")]
    DirectoryError { message: String },

    #[error("Generic auth error: {message}")]
    Generic { message: String },
}

/// Trait for authenticating users against a directory backend
#[async_trait]
pub trait AuthenticationBackend: Send + Sync {
    /// Authenticate a user with DN and password
    async fn authenticate(&self, dn: &str, password: &[u8]) -> Result<bool, String>;

    /// Check if a DN exists in the directory
    async fn dn_exists(&self, dn: &str) -> Result<bool, String>;

    /// Validate DN format
    fn validate_dn(&self, dn: &str) -> Result<(), String>;

    /// Get user attributes after successful authentication
    async fn get_user_info(&self, dn: &str) -> Result<AuthUserInfo, String>;
}

/// Information about authenticated user
#[derive(Debug, Clone)]
pub struct AuthUserInfo {
    pub dn: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub groups: Vec<String>,
    pub last_login: Option<Instant>,
}

/// Configuration for authentication FSM
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Allow anonymous binds
    pub allow_anonymous: bool,
    /// Require secure connection for authentication
    pub require_tls: bool,
    /// Maximum authentication attempts
    pub max_auth_attempts: u32,
    /// Authentication timeout
    pub auth_timeout: Duration,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            allow_anonymous: true,
            require_tls: false,
            max_auth_attempts: 3,
            auth_timeout: Duration::from_secs(30),
        }
    }
}

/// Authentication statistics and metrics
#[derive(Debug, Clone)]
pub struct AuthStats {
    pub successful_auths: u64,
    pub failed_auths: u64,
    pub anonymous_binds: u64,
    pub unbind_operations: u64,
    pub current_auth_attempts: u32,
    pub session_start_time: Instant,
}

/// Auth FSM Implementation for Simple Bind
///
/// This FSM manages the authentication state for LDAP connections,
/// handling transitions between anonymous and authenticated states.
pub struct AuthFsmImpl {
    /// Current FSM state
    state: AuthState,

    /// Authentication backend
    backend: Option<Box<dyn AuthenticationBackend>>,

    /// Configuration
    config: AuthConfig,

    /// Current user information (if authenticated)
    user_info: Option<AuthUserInfo>,

    /// Authentication statistics
    stats: AuthStats,

    /// Start time of current authentication attempt
    auth_start_time: Option<Instant>,
}

impl AuthFsmImpl {
    /// Create a new Auth FSM with default configuration
    pub fn new() -> Self {
        Self {
            state: AuthState::Anonymous,
            backend: None,
            config: AuthConfig::default(),
            user_info: None,
            stats: AuthStats {
                successful_auths: 0,
                failed_auths: 0,
                anonymous_binds: 0,
                unbind_operations: 0,
                current_auth_attempts: 0,
                session_start_time: Instant::now(),
            },
            auth_start_time: None,
        }
    }

    /// Create Auth FSM with custom configuration
    pub fn with_config(config: AuthConfig) -> Self {
        Self {
            config,
            ..Self::new()
        }
    }

    /// Set authentication backend
    pub fn with_backend(mut self, backend: Box<dyn AuthenticationBackend>) -> Self {
        self.backend = Some(backend);
        self
    }

    /// Get authentication statistics
    pub fn stats(&self) -> &AuthStats {
        &self.stats
    }

    /// Get current user information
    pub fn user_info(&self) -> Option<&AuthUserInfo> {
        self.user_info.as_ref()
    }

    /// Check if authentication timeout has been exceeded
    pub fn is_auth_timeout(&self) -> bool {
        if let Some(start_time) = self.auth_start_time {
            start_time.elapsed() > self.config.auth_timeout
        } else {
            false
        }
    }

    /// Handle bind request event
    async fn handle_bind_request(
        &mut self,
        dn: String,
        password: Vec<u8>,
    ) -> Result<Option<AuthUserInfo>, AuthError> {
        // Check if we're in a valid state to start authentication
        match &self.state {
            AuthState::Anonymous | AuthState::AuthenticationFailed => {
                // Valid states to start authentication
            }
            AuthState::Authenticating { .. } => {
                return Err(AuthError::InvalidStateTransition {
                    from: self.state.clone(),
                    to: AuthState::Authenticating { dn: dn.clone() },
                });
            }
            AuthState::SimpleBound { .. } => {
                // Already authenticated, this is a re-bind
                // Don't count as unbind operation - that's only for explicit Unbind events
            }
        }

        // Handle anonymous bind (empty DN and password)
        if dn.is_empty() && password.is_empty() {
            return self.handle_anonymous_bind().await;
        }

        // Check authentication attempts limit
        if self.stats.current_auth_attempts >= self.config.max_auth_attempts {
            self.state = AuthState::AuthenticationFailed;
            return Err(AuthError::AuthenticationFailed {
                reason: "Too many authentication attempts".to_string(),
            });
        }

        // Start authentication process
        self.state = AuthState::Authenticating { dn: dn.clone() };
        self.auth_start_time = Some(Instant::now());
        self.stats.current_auth_attempts += 1;

        // Validate DN format and perform authentication if backend is available
        if let Some(backend) = &self.backend {
            backend
                .validate_dn(&dn)
                .map_err(|e| AuthError::DirectoryError { message: e })?;

            // Perform authentication immediately
            let authenticated = backend
                .authenticate(&dn, &password)
                .await
                .map_err(|e| AuthError::DirectoryError { message: e })?;

            if authenticated {
                // Authentication succeeded
                return self.handle_auth_success().await;
            } else {
                // Authentication failed
                return self.handle_auth_failure().await;
            }
        }

        // No backend available - stay in Authenticating state
        Ok(None)
    }

    /// Handle an externally authenticated identity, such as SASL EXTERNAL over mTLS.
    async fn handle_external_bind(
        &mut self,
        dn: String,
    ) -> Result<Option<AuthUserInfo>, AuthError> {
        let count_success = !matches!(self.state, AuthState::SimpleBound { .. });
        match &self.state {
            AuthState::Anonymous
            | AuthState::AuthenticationFailed
            | AuthState::SimpleBound { .. } => {}
            AuthState::Authenticating { .. } => {
                return Err(AuthError::InvalidStateTransition {
                    from: self.state.clone(),
                    to: AuthState::SimpleBound { dn },
                });
            }
        }

        if let Some(backend) = &self.backend {
            backend
                .validate_dn(&dn)
                .map_err(|e| AuthError::DirectoryError { message: e })?;
            if !backend
                .dn_exists(&dn)
                .await
                .map_err(|e| AuthError::DirectoryError { message: e })?
            {
                self.state = AuthState::AuthenticationFailed;
                return Err(AuthError::AuthenticationFailed {
                    reason: "SASL EXTERNAL identity not found".to_string(),
                });
            }

            let user_info = backend
                .get_user_info(&dn)
                .await
                .map_err(|e| AuthError::DirectoryError { message: e })?;
            self.state = AuthState::SimpleBound { dn };
            self.user_info = Some(user_info.clone());
            if count_success {
                self.stats.successful_auths += 1;
            }
            self.stats.current_auth_attempts = 0;
            self.auth_start_time = None;
            return Ok(Some(user_info));
        }

        self.state = AuthState::SimpleBound { dn };
        self.user_info = None;
        if count_success {
            self.stats.successful_auths += 1;
        }
        self.stats.current_auth_attempts = 0;
        self.auth_start_time = None;
        Ok(None)
    }

    /// Handle anonymous bind
    async fn handle_anonymous_bind(&mut self) -> Result<Option<AuthUserInfo>, AuthError> {
        if !self.config.allow_anonymous {
            self.state = AuthState::AuthenticationFailed;
            return Err(AuthError::AuthenticationFailed {
                reason: "Anonymous binds not allowed".to_string(),
            });
        }

        self.state = AuthState::Anonymous;
        self.user_info = None;
        self.stats.anonymous_binds += 1;
        self.stats.current_auth_attempts = 0;
        self.auth_start_time = None;

        Ok(None)
    }

    /// Handle authentication success
    async fn handle_auth_success(&mut self) -> Result<Option<AuthUserInfo>, AuthError> {
        let dn = match &self.state {
            AuthState::Authenticating { dn } => dn.clone(),
            _ => {
                return Err(AuthError::InvalidStateTransition {
                    from: self.state.clone(),
                    to: AuthState::SimpleBound {
                        dn: "unknown".to_string(),
                    },
                });
            }
        };

        // Get user information from backend
        let user_info = if let Some(backend) = &self.backend {
            match backend.get_user_info(&dn).await {
                Ok(info) => Some(info),
                Err(e) => {
                    // Log error but continue with basic info
                    eprintln!("Failed to get user info: {}", e);
                    Some(AuthUserInfo {
                        dn: dn.clone(),
                        display_name: None,
                        email: None,
                        groups: Vec::new(),
                        last_login: Some(Instant::now()),
                    })
                }
            }
        } else {
            Some(AuthUserInfo {
                dn: dn.clone(),
                display_name: None,
                email: None,
                groups: Vec::new(),
                last_login: Some(Instant::now()),
            })
        };

        self.state = AuthState::SimpleBound { dn: dn.clone() };
        self.user_info = user_info.clone();
        self.stats.successful_auths += 1;
        self.stats.current_auth_attempts = 0;
        self.auth_start_time = None;

        Ok(user_info)
    }

    /// Handle authentication failure
    async fn handle_auth_failure(&mut self) -> Result<Option<AuthUserInfo>, AuthError> {
        self.state = AuthState::AuthenticationFailed;
        self.user_info = None;
        self.stats.failed_auths += 1;
        self.auth_start_time = None;

        Ok(None)
    }

    /// Handle unbind operation
    async fn handle_unbind(&mut self) -> Result<Option<AuthUserInfo>, AuthError> {
        self.state = AuthState::Anonymous;
        self.user_info = None;
        self.stats.unbind_operations += 1;
        self.stats.current_auth_attempts = 0;
        self.auth_start_time = None;

        Ok(None)
    }
}

impl Default for AuthFsmImpl {
    fn default() -> Self {
        Self::new()
    }
}

/// Implementation of StateMachine trait
#[async_trait]
impl StateMachine for AuthFsmImpl {
    type State = AuthState;
    type Event = AuthEvent;
    type Error = AuthError;
    type Output = AuthUserInfo;

    fn current_state(&self) -> &Self::State {
        &self.state
    }

    async fn handle_event(
        &mut self,
        event: Self::Event,
    ) -> Result<Option<Self::Output>, Self::Error> {
        match event {
            AuthEvent::BindRequest { dn, password } => self.handle_bind_request(dn, password).await,
            AuthEvent::ExternalBind { dn } => self.handle_external_bind(dn).await,
            AuthEvent::AuthenticationSuccess => self.handle_auth_success().await,
            AuthEvent::AuthenticationFailure => self.handle_auth_failure().await,
            AuthEvent::Unbind => self.handle_unbind().await,
            AuthEvent::Reset => {
                self.reset().await?;
                Ok(None)
            }
        }
    }

    fn is_terminal(&self) -> bool {
        false // Auth FSM can always transition to other states
    }

    async fn reset(&mut self) -> Result<(), Self::Error> {
        self.state = AuthState::Anonymous;
        self.user_info = None;
        self.stats.current_auth_attempts = 0;
        self.auth_start_time = None;
        Ok(())
    }
}

/// Implementation of AuthFsm trait
#[async_trait]
impl AuthFsm for AuthFsmImpl {
    fn authenticated_dn(&self) -> Option<&str> {
        match &self.state {
            AuthState::SimpleBound { dn } => Some(dn),
            _ => None,
        }
    }

    fn is_authenticated(&self) -> bool {
        matches!(self.state, AuthState::SimpleBound { .. })
    }

    fn auth_level(&self) -> AuthLevel {
        match &self.state {
            AuthState::SimpleBound { .. } => AuthLevel::Simple,
            _ => AuthLevel::Anonymous,
        }
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use super::*;
    use crate::fsm::StateMachine;

    /// Mock authentication backend for testing
    struct MockAuthBackend {
        valid_users: std::collections::HashMap<String, Vec<u8>>,
        should_fail: bool,
    }

    impl MockAuthBackend {
        fn new() -> Self {
            let mut valid_users = std::collections::HashMap::new();
            valid_users.insert("cn=admin,dc=example,dc=org".to_string(), b"secret".to_vec());
            valid_users.insert(
                "cn=user1,dc=example,dc=org".to_string(),
                b"password123".to_vec(),
            );

            Self {
                valid_users,
                should_fail: false,
            }
        }

        fn with_failure(mut self) -> Self {
            self.should_fail = true;
            self
        }
    }

    #[async_trait]
    impl AuthenticationBackend for MockAuthBackend {
        async fn authenticate(&self, dn: &str, password: &[u8]) -> Result<bool, String> {
            if self.should_fail {
                return Err("Backend failure".to_string());
            }

            if let Some(valid_password) = self.valid_users.get(dn) {
                Ok(password == valid_password)
            } else {
                Ok(false)
            }
        }

        async fn dn_exists(&self, dn: &str) -> Result<bool, String> {
            Ok(self.valid_users.contains_key(dn))
        }

        fn validate_dn(&self, dn: &str) -> Result<(), String> {
            if dn.is_empty() {
                return Err("Empty DN".to_string());
            }
            if !dn.contains("=") {
                return Err("Invalid DN format".to_string());
            }
            Ok(())
        }

        async fn get_user_info(&self, dn: &str) -> Result<AuthUserInfo, String> {
            if self.valid_users.contains_key(dn) {
                Ok(AuthUserInfo {
                    dn: dn.to_string(),
                    display_name: Some("Test User".to_string()),
                    email: Some("test@example.org".to_string()),
                    groups: vec!["users".to_string()],
                    last_login: Some(Instant::now()),
                })
            } else {
                Err("User not found".to_string())
            }
        }
    }

    #[tokio::test]
    async fn test_new_auth_fsm() {
        let fsm = AuthFsmImpl::new();
        assert_eq!(fsm.current_state(), &AuthState::Anonymous);
        assert!(!fsm.is_terminal());
        assert!(!fsm.is_authenticated());
        assert_eq!(fsm.auth_level(), AuthLevel::Anonymous);
    }

    #[tokio::test]
    async fn test_auth_fsm_with_config() {
        let config = AuthConfig {
            allow_anonymous: false,
            require_tls: true,
            max_auth_attempts: 5,
            auth_timeout: Duration::from_secs(60),
        };

        let fsm = AuthFsmImpl::with_config(config.clone());
        assert!(!fsm.config.allow_anonymous);
        assert_eq!(fsm.config.max_auth_attempts, 5);
    }

    #[tokio::test]
    async fn test_auth_fsm_with_backend() {
        let backend = Box::new(MockAuthBackend::new());
        let fsm = AuthFsmImpl::new().with_backend(backend);
        assert!(fsm.backend.is_some());
    }

    #[tokio::test]
    async fn test_anonymous_bind() {
        let mut fsm = AuthFsmImpl::new();

        let result = fsm
            .handle_event(AuthEvent::BindRequest {
                dn: "".to_string(),
                password: vec![],
            })
            .await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
        assert_eq!(fsm.current_state(), &AuthState::Anonymous);
        assert!(!fsm.is_authenticated());
        assert_eq!(fsm.stats().anonymous_binds, 1);
    }

    #[tokio::test]
    async fn test_anonymous_bind_not_allowed() {
        let config = AuthConfig {
            allow_anonymous: false,
            ..Default::default()
        };
        let mut fsm = AuthFsmImpl::with_config(config);

        let result = fsm
            .handle_event(AuthEvent::BindRequest {
                dn: "".to_string(),
                password: vec![],
            })
            .await;

        assert!(result.is_err());
        assert_eq!(fsm.current_state(), &AuthState::AuthenticationFailed);
        assert!(!fsm.is_authenticated());
    }

    #[tokio::test]
    async fn test_simple_bind_request() {
        let mut fsm = AuthFsmImpl::new();

        let result = fsm
            .handle_event(AuthEvent::BindRequest {
                dn: "cn=user,dc=example,dc=org".to_string(),
                password: b"password".to_vec(),
            })
            .await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
        assert!(matches!(
            fsm.current_state(),
            AuthState::Authenticating { .. }
        ));
        assert!(!fsm.is_authenticated());
    }

    #[tokio::test]
    async fn test_authentication_success() {
        let mut fsm = AuthFsmImpl::new();

        // Start authentication
        let _ = fsm
            .handle_event(AuthEvent::BindRequest {
                dn: "cn=user,dc=example,dc=org".to_string(),
                password: b"password".to_vec(),
            })
            .await;

        // Success
        let result = fsm.handle_event(AuthEvent::AuthenticationSuccess).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
        assert!(matches!(fsm.current_state(), AuthState::SimpleBound { .. }));
        assert!(fsm.is_authenticated());
        assert_eq!(fsm.auth_level(), AuthLevel::Simple);
        assert_eq!(fsm.authenticated_dn(), Some("cn=user,dc=example,dc=org"));
    }

    #[tokio::test]
    async fn test_authentication_failure() {
        let mut fsm = AuthFsmImpl::new();

        // Start authentication
        let _ = fsm
            .handle_event(AuthEvent::BindRequest {
                dn: "cn=user,dc=example,dc=org".to_string(),
                password: b"password".to_vec(),
            })
            .await;

        // Failure
        let result = fsm.handle_event(AuthEvent::AuthenticationFailure).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
        assert_eq!(fsm.current_state(), &AuthState::AuthenticationFailed);
        assert!(!fsm.is_authenticated());
        assert_eq!(fsm.stats().failed_auths, 1);
    }

    #[tokio::test]
    async fn test_unbind_operation() {
        let mut fsm = AuthFsmImpl::new();

        // Authenticate first
        let _ = fsm
            .handle_event(AuthEvent::BindRequest {
                dn: "cn=user,dc=example,dc=org".to_string(),
                password: b"password".to_vec(),
            })
            .await;
        let _ = fsm.handle_event(AuthEvent::AuthenticationSuccess).await;

        // Unbind
        let result = fsm.handle_event(AuthEvent::Unbind).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
        assert_eq!(fsm.current_state(), &AuthState::Anonymous);
        assert!(!fsm.is_authenticated());
        assert_eq!(fsm.stats().unbind_operations, 1);
    }

    #[tokio::test]
    async fn test_max_auth_attempts() {
        let config = AuthConfig {
            max_auth_attempts: 2,
            ..Default::default()
        };
        let mut fsm = AuthFsmImpl::with_config(config);

        // First attempt
        let _ = fsm
            .handle_event(AuthEvent::BindRequest {
                dn: "cn=user,dc=example,dc=org".to_string(),
                password: b"wrong".to_vec(),
            })
            .await;
        let _ = fsm.handle_event(AuthEvent::AuthenticationFailure).await;

        // Second attempt
        let _ = fsm
            .handle_event(AuthEvent::BindRequest {
                dn: "cn=user,dc=example,dc=org".to_string(),
                password: b"wrong".to_vec(),
            })
            .await;
        let _ = fsm.handle_event(AuthEvent::AuthenticationFailure).await;

        // Third attempt should fail
        let result = fsm
            .handle_event(AuthEvent::BindRequest {
                dn: "cn=user,dc=example,dc=org".to_string(),
                password: b"password".to_vec(),
            })
            .await;

        assert!(result.is_err());
        assert_eq!(fsm.current_state(), &AuthState::AuthenticationFailed);
    }

    #[tokio::test]
    async fn test_reset_functionality() {
        let mut fsm = AuthFsmImpl::new();

        // Authenticate
        let _ = fsm
            .handle_event(AuthEvent::BindRequest {
                dn: "cn=user,dc=example,dc=org".to_string(),
                password: b"password".to_vec(),
            })
            .await;
        let _ = fsm.handle_event(AuthEvent::AuthenticationSuccess).await;

        // Reset
        let result = fsm.handle_event(AuthEvent::Reset).await;
        assert!(result.is_ok());
        assert_eq!(fsm.current_state(), &AuthState::Anonymous);
        assert!(!fsm.is_authenticated());
        assert!(fsm.user_info().is_none());
    }

    #[tokio::test]
    async fn test_invalid_state_transitions() {
        let mut fsm = AuthFsmImpl::new();

        // Try to authenticate while already authenticating
        let _ = fsm
            .handle_event(AuthEvent::BindRequest {
                dn: "cn=user1,dc=example,dc=org".to_string(),
                password: b"password".to_vec(),
            })
            .await;

        // Try another bind request while authenticating
        let result = fsm
            .handle_event(AuthEvent::BindRequest {
                dn: "cn=user2,dc=example,dc=org".to_string(),
                password: b"password".to_vec(),
            })
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AuthError::InvalidStateTransition { .. }
        ));
    }

    #[tokio::test]
    async fn test_user_info_retrieval() {
        let mut fsm = AuthFsmImpl::new();

        // Authenticate
        let _ = fsm
            .handle_event(AuthEvent::BindRequest {
                dn: "cn=user,dc=example,dc=org".to_string(),
                password: b"password".to_vec(),
            })
            .await;
        let result = fsm.handle_event(AuthEvent::AuthenticationSuccess).await;

        assert!(result.is_ok());
        let user_info = result.unwrap();
        assert!(user_info.is_some());

        let info = user_info.unwrap();
        assert_eq!(info.dn, "cn=user,dc=example,dc=org");

        // Check FSM user info
        let fsm_info = fsm.user_info();
        assert!(fsm_info.is_some());
        assert_eq!(fsm_info.unwrap().dn, "cn=user,dc=example,dc=org");
    }

    #[tokio::test]
    async fn test_statistics_tracking() {
        let mut fsm = AuthFsmImpl::new();
        let initial_stats = fsm.stats().clone();

        // Anonymous bind
        let _ = fsm
            .handle_event(AuthEvent::BindRequest {
                dn: "".to_string(),
                password: vec![],
            })
            .await;
        assert_eq!(
            fsm.stats().anonymous_binds,
            initial_stats.anonymous_binds + 1
        );

        // Successful auth
        let _ = fsm
            .handle_event(AuthEvent::BindRequest {
                dn: "cn=user,dc=example,dc=org".to_string(),
                password: b"password".to_vec(),
            })
            .await;
        let _ = fsm.handle_event(AuthEvent::AuthenticationSuccess).await;
        assert_eq!(
            fsm.stats().successful_auths,
            initial_stats.successful_auths + 1
        );

        // Failed auth
        let _ = fsm
            .handle_event(AuthEvent::BindRequest {
                dn: "cn=user2,dc=example,dc=org".to_string(),
                password: b"wrong".to_vec(),
            })
            .await;
        let _ = fsm.handle_event(AuthEvent::AuthenticationFailure).await;
        assert_eq!(fsm.stats().failed_auths, initial_stats.failed_auths + 1);

        // Unbind
        let _ = fsm.handle_event(AuthEvent::Unbind).await;
        assert_eq!(
            fsm.stats().unbind_operations,
            initial_stats.unbind_operations + 1
        );
    }

    #[tokio::test]
    async fn test_authentication_timeout() {
        let config = AuthConfig {
            auth_timeout: Duration::from_millis(1),
            ..Default::default()
        };
        let mut fsm = AuthFsmImpl::with_config(config);

        // Start authentication
        let _ = fsm
            .handle_event(AuthEvent::BindRequest {
                dn: "cn=user,dc=example,dc=org".to_string(),
                password: b"password".to_vec(),
            })
            .await;

        // Wait for timeout
        tokio::time::sleep(Duration::from_millis(2)).await;

        assert!(fsm.is_auth_timeout());
    }

    #[tokio::test]
    async fn test_mock_backend_authentication() {
        let backend = Box::new(MockAuthBackend::new());
        let mut fsm = AuthFsmImpl::new().with_backend(backend);

        // Valid credentials
        let _ = fsm
            .handle_event(AuthEvent::BindRequest {
                dn: "cn=admin,dc=example,dc=org".to_string(),
                password: b"secret".to_vec(),
            })
            .await;

        // A configured backend authenticates the bind request immediately.
        assert!(matches!(fsm.current_state(), AuthState::SimpleBound { .. }));
        assert_eq!(fsm.stats().successful_auths, 1);
        assert_eq!(
            fsm.user_info().map(|info| info.dn.as_str()),
            Some("cn=admin,dc=example,dc=org")
        );
    }

    #[tokio::test]
    async fn test_mock_backend_validation() {
        let backend = MockAuthBackend::new();

        // Test DN validation
        assert!(backend.validate_dn("cn=user,dc=example,dc=org").is_ok());
        assert!(backend.validate_dn("").is_err());
        assert!(backend.validate_dn("invalid").is_err());

        // Test authentication
        let result = backend
            .authenticate("cn=admin,dc=example,dc=org", b"secret")
            .await;
        assert!(result.is_ok());
        assert!(result.unwrap());

        let result = backend
            .authenticate("cn=admin,dc=example,dc=org", b"wrong")
            .await;
        assert!(result.is_ok());
        assert!(!result.unwrap());

        // Test user info
        let info = backend.get_user_info("cn=admin,dc=example,dc=org").await;
        assert!(info.is_ok());
        let info = info.unwrap();
        assert_eq!(info.dn, "cn=admin,dc=example,dc=org");
        assert!(info.display_name.is_some());
    }
}

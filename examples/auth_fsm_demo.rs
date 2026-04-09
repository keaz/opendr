//! Authentication FSM Demo
//!
//! This example demonstrates how to use the Authentication FSM for LDAP
//! Simple Bind operations. It shows the complete authentication lifecycle
//! including anonymous binds, successful authentication, and failure handling.

use async_trait::async_trait;
use opendr::auth_fsm::{AuthConfig, AuthError, AuthFsmImpl, AuthUserInfo, AuthenticationBackend};
use opendr::fsm::{AuthEvent, AuthFsm, AuthState, StateMachine};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Example authentication backend that validates users against a simple in-memory store
pub struct ExampleAuthBackend {
    users: HashMap<String, UserRecord>,
}

/// User record containing authentication and profile information
#[derive(Debug, Clone)]
struct UserRecord {
    dn: String,
    password_hash: Vec<u8>, // In real usage, this would be a proper hash
    display_name: String,
    email: String,
    groups: Vec<String>,
}

impl ExampleAuthBackend {
    /// Create a new example backend with sample users
    pub fn new() -> Self {
        let mut users = HashMap::new();

        // Add sample users
        users.insert(
            "cn=admin,dc=example,dc=org".to_string(),
            UserRecord {
                dn: "cn=admin,dc=example,dc=org".to_string(),
                password_hash: b"admin_secret".to_vec(), // Simple password for demo
                display_name: "Administrator".to_string(),
                email: "admin@example.org".to_string(),
                groups: vec!["admins".to_string(), "users".to_string()],
            },
        );

        users.insert(
            "cn=alice,ou=people,dc=example,dc=org".to_string(),
            UserRecord {
                dn: "cn=alice,ou=people,dc=example,dc=org".to_string(),
                password_hash: b"alice_password".to_vec(),
                display_name: "Alice Smith".to_string(),
                email: "alice@example.org".to_string(),
                groups: vec!["users".to_string(), "developers".to_string()],
            },
        );

        users.insert(
            "cn=bob,ou=people,dc=example,dc=org".to_string(),
            UserRecord {
                dn: "cn=bob,ou=people,dc=example,dc=org".to_string(),
                password_hash: b"bob_password".to_vec(),
                display_name: "Bob Johnson".to_string(),
                email: "bob@example.org".to_string(),
                groups: vec!["users".to_string()],
            },
        );

        Self { users }
    }
}

impl Default for ExampleAuthBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AuthenticationBackend for ExampleAuthBackend {
    async fn authenticate(&self, dn: &str, password: &[u8]) -> Result<bool, String> {
        println!("🔐 Authenticating user: {}", dn);

        // Simulate processing delay
        tokio::time::sleep(Duration::from_millis(100)).await;

        if let Some(user_record) = self.users.get(dn) {
            let is_valid = password == user_record.password_hash;
            println!(
                "✅ Authentication {} for {}",
                if is_valid { "SUCCESS" } else { "FAILED" },
                dn
            );
            Ok(is_valid)
        } else {
            println!("❌ User not found: {}", dn);
            Ok(false)
        }
    }

    async fn dn_exists(&self, dn: &str) -> Result<bool, String> {
        Ok(self.users.contains_key(dn))
    }

    fn validate_dn(&self, dn: &str) -> Result<(), String> {
        if dn.is_empty() {
            return Err("DN cannot be empty".to_string());
        }

        if !dn.contains('=') || !dn.contains(',') {
            return Err("Invalid DN format".to_string());
        }

        println!("✓ DN format valid: {}", dn);
        Ok(())
    }

    async fn get_user_info(&self, dn: &str) -> Result<AuthUserInfo, String> {
        if let Some(user_record) = self.users.get(dn) {
            Ok(AuthUserInfo {
                dn: user_record.dn.clone(),
                display_name: Some(user_record.display_name.clone()),
                email: Some(user_record.email.clone()),
                groups: user_record.groups.clone(),
                last_login: Some(Instant::now()),
            })
        } else {
            Err(format!("User not found: {}", dn))
        }
    }
}

/// Demonstrate successful authentication flow
async fn demo_successful_authentication() -> Result<(), AuthError> {
    println!("\n🎯 === Successful Authentication Demo ===");

    let backend = Box::new(ExampleAuthBackend::new());
    let mut auth_fsm = AuthFsmImpl::new().with_backend(backend);

    println!("📊 Initial state: {:?}", auth_fsm.current_state());
    println!("🔒 Authenticated: {}", auth_fsm.is_authenticated());

    // Step 1: Start authentication
    println!("\n1️⃣ Starting bind request...");
    let _result = auth_fsm
        .handle_event(AuthEvent::BindRequest {
            dn: "cn=alice,ou=people,dc=example,dc=org".to_string(),
            password: b"alice_password".to_vec(),
        })
        .await?;

    println!(
        "📊 State after bind request: {:?}",
        auth_fsm.current_state()
    );
    assert!(matches!(
        auth_fsm.current_state(),
        AuthState::Authenticating { .. }
    ));

    // Step 2: Simulate successful authentication (in real usage, this would be triggered by backend)
    println!("\n2️⃣ Processing authentication success...");
    let result = auth_fsm
        .handle_event(AuthEvent::AuthenticationSuccess)
        .await?;

    println!("📊 Final state: {:?}", auth_fsm.current_state());
    println!("🔒 Authenticated: {}", auth_fsm.is_authenticated());
    println!("🎭 Auth Level: {:?}", auth_fsm.auth_level());

    if let Some(user_info) = result {
        println!("👤 User Info:");
        println!("   DN: {}", user_info.dn);
        println!("   Display Name: {:?}", user_info.display_name);
        println!("   Email: {:?}", user_info.email);
        println!("   Groups: {:?}", user_info.groups);
    }

    println!("📈 Statistics: {:?}", auth_fsm.stats());

    Ok(())
}

/// Demonstrate failed authentication flow
async fn demo_failed_authentication() -> Result<(), AuthError> {
    println!("\n❌ === Failed Authentication Demo ===");

    let backend = Box::new(ExampleAuthBackend::new());
    let mut auth_fsm = AuthFsmImpl::new().with_backend(backend);

    // Try with wrong password
    println!("1️⃣ Attempting bind with wrong password...");
    let _result = auth_fsm
        .handle_event(AuthEvent::BindRequest {
            dn: "cn=alice,ou=people,dc=example,dc=org".to_string(),
            password: b"wrong_password".to_vec(),
        })
        .await?;

    println!("📊 State: {:?}", auth_fsm.current_state());

    // Simulate authentication failure
    println!("\n2️⃣ Processing authentication failure...");
    let _result = auth_fsm
        .handle_event(AuthEvent::AuthenticationFailure)
        .await?;

    println!("📊 Final state: {:?}", auth_fsm.current_state());
    println!("🔒 Authenticated: {}", auth_fsm.is_authenticated());
    println!("📈 Statistics: {:?}", auth_fsm.stats());

    Ok(())
}

/// Demonstrate anonymous bind
async fn demo_anonymous_bind() -> Result<(), AuthError> {
    println!("\n👤 === Anonymous Bind Demo ===");

    let mut auth_fsm = AuthFsmImpl::new();

    println!("1️⃣ Performing anonymous bind...");
    let _result = auth_fsm
        .handle_event(AuthEvent::BindRequest {
            dn: "".to_string(),
            password: vec![],
        })
        .await?;

    println!("📊 State: {:?}", auth_fsm.current_state());
    println!("🔒 Authenticated: {}", auth_fsm.is_authenticated());
    println!("🎭 Auth Level: {:?}", auth_fsm.auth_level());
    println!("📈 Statistics: {:?}", auth_fsm.stats());

    Ok(())
}

/// Demonstrate authentication with rate limiting
async fn demo_rate_limiting() -> Result<(), AuthError> {
    println!("\n🚦 === Rate Limiting Demo ===");

    let config = AuthConfig {
        allow_anonymous: true,
        require_tls: false,
        max_auth_attempts: 2,
        auth_timeout: Duration::from_secs(30),
    };

    let backend = Box::new(ExampleAuthBackend::new());
    let mut auth_fsm = AuthFsmImpl::with_config(config).with_backend(backend);

    // First failed attempt
    println!("1️⃣ First failed attempt...");
    let _ = auth_fsm
        .handle_event(AuthEvent::BindRequest {
            dn: "cn=alice,ou=people,dc=example,dc=org".to_string(),
            password: b"wrong1".to_vec(),
        })
        .await?;
    let _ = auth_fsm
        .handle_event(AuthEvent::AuthenticationFailure)
        .await?;
    println!("📈 Attempts: {}", auth_fsm.stats().current_auth_attempts);

    // Second failed attempt
    println!("2️⃣ Second failed attempt...");
    let _ = auth_fsm
        .handle_event(AuthEvent::BindRequest {
            dn: "cn=alice,ou=people,dc=example,dc=org".to_string(),
            password: b"wrong2".to_vec(),
        })
        .await?;
    let _ = auth_fsm
        .handle_event(AuthEvent::AuthenticationFailure)
        .await?;
    println!("📈 Attempts: {}", auth_fsm.stats().current_auth_attempts);

    // Third attempt should be blocked
    println!("3️⃣ Third attempt (should be blocked)...");
    match auth_fsm
        .handle_event(AuthEvent::BindRequest {
            dn: "cn=alice,ou=people,dc=example,dc=org".to_string(),
            password: b"alice_password".to_vec(), // Even correct password is blocked
        })
        .await
    {
        Ok(_) => println!("❌ Unexpected: Third attempt was allowed!"),
        Err(AuthError::AuthenticationFailed { reason }) => {
            println!("✅ Third attempt blocked: {}", reason);
        }
        Err(e) => println!("❌ Unexpected error: {:?}", e),
    }

    println!("📊 Final state: {:?}", auth_fsm.current_state());
    println!("📈 Statistics: {:?}", auth_fsm.stats());

    Ok(())
}

/// Demonstrate complete authentication lifecycle
async fn demo_full_lifecycle() -> Result<(), AuthError> {
    println!("\n🔄 === Full Lifecycle Demo ===");

    let backend = Box::new(ExampleAuthBackend::new());
    let mut auth_fsm = AuthFsmImpl::new().with_backend(backend);

    // 1. Anonymous bind
    println!("1️⃣ Anonymous bind...");
    let _ = auth_fsm
        .handle_event(AuthEvent::BindRequest {
            dn: "".to_string(),
            password: vec![],
        })
        .await?;

    // 2. Authenticate as user
    println!("2️⃣ Authenticating as Alice...");
    let _ = auth_fsm
        .handle_event(AuthEvent::BindRequest {
            dn: "cn=alice,ou=people,dc=example,dc=org".to_string(),
            password: b"alice_password".to_vec(),
        })
        .await?;
    let _ = auth_fsm
        .handle_event(AuthEvent::AuthenticationSuccess)
        .await?;
    println!("   Authenticated as: {:?}", auth_fsm.authenticated_dn());

    // 3. Re-bind as different user
    println!("3️⃣ Re-binding as Admin...");
    let _ = auth_fsm
        .handle_event(AuthEvent::BindRequest {
            dn: "cn=admin,dc=example,dc=org".to_string(),
            password: b"admin_secret".to_vec(),
        })
        .await?;
    let user_info = auth_fsm
        .handle_event(AuthEvent::AuthenticationSuccess)
        .await?;
    println!("   Authenticated as: {:?}", auth_fsm.authenticated_dn());

    if let Some(info) = user_info {
        println!("   User groups: {:?}", info.groups);
    }

    // 4. Explicit unbind
    println!("4️⃣ Explicit unbind...");
    let _ = auth_fsm.handle_event(AuthEvent::Unbind).await?;
    println!("   State: {:?}", auth_fsm.current_state());
    println!("   Authenticated: {}", auth_fsm.is_authenticated());

    // 5. Reset FSM
    println!("5️⃣ Reset FSM...");
    let _ = auth_fsm.handle_event(AuthEvent::Reset).await?;
    println!("   State: {:?}", auth_fsm.current_state());

    println!("📈 Final Statistics:");
    let stats = auth_fsm.stats();
    println!("   Successful auths: {}", stats.successful_auths);
    println!("   Failed auths: {}", stats.failed_auths);
    println!("   Anonymous binds: {}", stats.anonymous_binds);
    println!("   Unbind operations: {}", stats.unbind_operations);
    println!(
        "   Session duration: {:?}",
        stats.session_start_time.elapsed()
    );

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🎪 Authentication FSM Demo");
    println!("=========================");

    // Run all demonstration scenarios
    demo_anonymous_bind().await?;
    demo_successful_authentication().await?;
    demo_failed_authentication().await?;
    demo_rate_limiting().await?;
    demo_full_lifecycle().await?;

    println!("\n✅ All demonstrations completed successfully!");
    println!("\n📝 Key Features Demonstrated:");
    println!("   • Anonymous bind support");
    println!("   • Simple bind authentication");
    println!("   • Authentication failure handling");
    println!("   • Rate limiting (max attempts)");
    println!("   • User information retrieval");
    println!("   • Statistics tracking");
    println!("   • State transitions");
    println!("   • FSM lifecycle management");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_example_backend() {
        let backend = ExampleAuthBackend::new();

        // Test valid authentication
        let result = backend
            .authenticate("cn=alice,ou=people,dc=example,dc=org", b"alice_password")
            .await;
        assert!(result.unwrap());

        // Test invalid password
        let result = backend
            .authenticate("cn=alice,ou=people,dc=example,dc=org", b"wrong")
            .await;
        assert!(!result.unwrap());

        // Test nonexistent user
        let result = backend
            .authenticate("cn=nobody,dc=example,dc=org", b"password")
            .await;
        assert!(!result.unwrap());

        // Test DN validation
        assert!(backend.validate_dn("cn=user,dc=example,dc=org").is_ok());
        assert!(backend.validate_dn("invalid").is_err());

        // Test user info retrieval
        let info = backend.get_user_info("cn=admin,dc=example,dc=org").await;
        assert!(info.is_ok());
        let info = info.unwrap();
        assert_eq!(info.display_name, Some("Administrator".to_string()));
        assert!(info.groups.contains(&"admins".to_string()));
    }

    #[tokio::test]
    async fn test_demo_functions() {
        // Test that demo functions don't panic and complete successfully
        assert!(demo_anonymous_bind().await.is_ok());
        assert!(demo_successful_authentication().await.is_ok());
        assert!(demo_failed_authentication().await.is_ok());
        assert!(demo_rate_limiting().await.is_ok());
        assert!(demo_full_lifecycle().await.is_ok());
    }
}

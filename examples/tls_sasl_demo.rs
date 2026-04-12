//! TLS and SASL Authentication Integration Demo
//!
//! This example demonstrates the integration of TLS (Transport Layer Security)
//! and SASL (Simple Authentication and Security Layer) authentication mechanisms
//! in the OpenDR LDAP server.
//!
//! ## Features Demonstrated
//!
//! 1. TLS Support:
//!    - TLS configuration with certificate and key loading
//!    - TLS version negotiation (TLS 1.2 and 1.3)
//!    - StartTLS operation support
//!    - TLS handler implementation with rustls
//!
//! 2. SASL Authentication:
//!    - Production-supported SASL PLAIN authentication over TLS
//!    - Credential verification
//!    - Unsupported mechanism rejection for challenge/response placeholders
//!    - FSM session management
//!
//! ## Usage
//!
//! ```bash
//! cargo run --example tls_sasl_demo
//! ```

use async_trait::async_trait;
use opendr::connection_fsm::TlsHandler;
use opendr::fsm::{SaslEvent, SaslFsm, StateMachine};
use opendr::sasl_fsm::{
    CredentialVerifier, SaslChallengeResult, SaslFsmConfig, SaslFsmImpl, SaslMechanismHandler,
};
use opendr::sasl_mechanisms::MultiMechanismHandler;
use opendr::tls::{RustlsTlsHandler, TlsConfig, TlsVersion};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// Mock credential verifier for demonstration purposes
#[derive(Debug, Clone)]
struct DemoCredentialVerifier {
    // In production, this would connect to a real user database
    users: HashMap<String, UserCredentials>,
}

#[derive(Debug, Clone)]
struct UserCredentials {
    dn: String,
    password: Vec<u8>,
}

impl DemoCredentialVerifier {
    fn new() -> Self {
        let mut users = HashMap::new();

        // Add demo users
        users.insert(
            "alice".to_string(),
            UserCredentials {
                dn: "cn=alice,ou=users,dc=example,dc=org".to_string(),
                password: b"password123".to_vec(),
            },
        );

        users.insert(
            "bob".to_string(),
            UserCredentials {
                dn: "cn=bob,ou=users,dc=example,dc=org".to_string(),
                password: b"password456".to_vec(),
            },
        );

        users.insert(
            "admin".to_string(),
            UserCredentials {
                dn: "cn=admin,dc=example,dc=org".to_string(),
                password: b"adminpass".to_vec(),
            },
        );

        Self { users }
    }
}

#[async_trait]
impl CredentialVerifier for DemoCredentialVerifier {
    async fn verify_credentials(
        &self,
        mechanism: &str,
        identity: &str,
        credential: &[u8],
    ) -> Result<bool, String> {
        println!(
            "  [CredentialVerifier] Verifying {} authentication for user: {}",
            mechanism, identity
        );

        if mechanism != "PLAIN" {
            return Ok(false);
        }

        // Demo only. Production verifiers should compare against a password hash.
        Ok(self
            .users
            .get(identity)
            .is_some_and(|creds| creds.password.as_slice() == credential))
    }

    async fn get_user_dn(&self, identity: &str) -> Result<Option<String>, String> {
        println!(
            "  [CredentialVerifier] Looking up DN for user: {}",
            identity
        );

        Ok(self.users.get(identity).map(|creds| creds.dn.clone()))
    }

    async fn is_mechanism_allowed(&self, identity: &str, mechanism: &str) -> Result<bool, String> {
        println!(
            "  [CredentialVerifier] Checking if {} can use {} mechanism",
            identity, mechanism
        );

        Ok(mechanism == "PLAIN" && self.users.contains_key(identity))
    }
}

/// Demonstrate TLS configuration and setup
async fn demo_tls_setup() {
    println!("\n=== TLS Configuration Demo ===\n");

    // 1. Create TLS configuration
    println!("1. Creating TLS configuration...");
    let tls_config = TlsConfig {
        cert_path: "certs/server.crt".to_string(),
        key_path: "certs/server.key".to_string(),
        ca_file: None,
        min_tls_version: TlsVersion::Tls12,
        max_tls_version: TlsVersion::Tls13,
        require_client_cert: false,
    };

    println!("   - Certificate path: {}", tls_config.cert_path);
    println!("   - Key path: {}", tls_config.key_path);
    println!(
        "   - Min TLS version: {}",
        tls_config.min_tls_version.as_str()
    );
    println!(
        "   - Max TLS version: {}",
        tls_config.max_tls_version.as_str()
    );
    println!(
        "   - Require client cert: {}",
        tls_config.require_client_cert
    );

    // 2. Create TLS handler (using test mode for demo without actual certs)
    println!("\n2. Creating TLS handler (test mode)...");
    match RustlsTlsHandler::new_test() {
        Ok(handler) => {
            println!("   ✓ TLS handler created successfully");
            println!("   - Supports TLS: {}", handler.supports_tls());
            println!("   - Protocol version: {}", handler.protocol_version());

            // 3. Demonstrate TLS capabilities
            println!("\n3. TLS Handler Capabilities:");
            println!("   - StartTLS support: YES");
            println!("   - LDAPS (LDAP over TLS) support: YES");
            println!("   - Cipher suites: Modern secure ciphers via rustls");
            println!("   - Certificate validation: Configurable");
        }
        Err(e) => {
            println!("   ✗ Failed to create TLS handler: {}", e);
        }
    }

    println!("\n4. TLS Integration Points:");
    println!("   - Connection FSM: TlsHandler trait integration");
    println!("   - StartTLS extended operation: RFC 4511 compliance");
    println!("   - Secure channel for SASL PLAIN mechanism");
    println!("   - Certificate-based client authentication (optional)");
}

/// Demonstrate SASL authentication with production-supported mechanisms
async fn demo_sasl_authentication() {
    println!("\n=== SASL Authentication Demo ===\n");

    // 1. Create credential verifier
    println!("1. Setting up credential verifier...");
    let credential_verifier = Arc::new(DemoCredentialVerifier::new());
    println!("   ✓ Credential verifier configured with demo users:");
    println!("     - alice (regular user)");
    println!("     - bob (regular user)");
    println!("     - admin (administrator)");

    // 2. Create SASL mechanism handler
    println!("\n2. Creating production-supported SASL handler...");
    let mechanism_handler = Arc::new(MultiMechanismHandler::new(credential_verifier.clone()));
    println!("   ✓ SASL handler created");
    println!("   Supported mechanisms:");

    for mechanism in &["PLAIN", "DIGEST-MD5", "CRAM-MD5", "GSSAPI"] {
        let supported = mechanism_handler.supports_mechanism(mechanism).await;
        println!(
            "     - {}: {}",
            mechanism,
            if supported { "✓" } else { "✗" }
        );

        if supported {
            let props = mechanism_handler.get_mechanism_properties(mechanism);
            for (key, value) in props.iter() {
                println!("       - {}: {}", key, value);
            }
        }
    }

    // 3. Demonstrate PLAIN authentication
    println!("\n3. Testing PLAIN mechanism (requires TLS)...");
    demo_plain_authentication(mechanism_handler.clone()).await;

    // 4. Confirm challenge/response placeholders are not production-enabled
    println!("\n4. Confirming unsupported challenge/response mechanisms...");
    demo_unsupported_sasl_mechanisms(mechanism_handler.clone()).await;

    // 5. Demonstrate SASL FSM with session management
    println!("\n5. Testing SASL FSM with full session lifecycle...");
    demo_sasl_fsm_lifecycle(mechanism_handler.clone(), credential_verifier.clone()).await;
}

/// Demonstrate PLAIN mechanism authentication
async fn demo_plain_authentication(handler: Arc<MultiMechanismHandler>) {
    println!("   [PLAIN] Starting authentication...");

    // PLAIN format: [authzid]\0authcid\0passwd
    let credentials = b"\0alice\0password123";

    match handler
        .start_authentication("PLAIN", Some(credentials))
        .await
    {
        Ok(SaslChallengeResult::Success { dn }) => {
            println!("   ✓ Authentication successful!");
            println!("     - Authenticated DN: {}", dn);
            println!("     - Steps required: 1 (single-step mechanism)");
        }
        Ok(SaslChallengeResult::Failure(reason)) => {
            println!("   ✗ Authentication failed: {}", reason);
        }
        Ok(SaslChallengeResult::Challenge(_)) => {
            println!("   ! Unexpected challenge (PLAIN should be single-step)");
        }
        Err(e) => {
            println!("   ✗ Error: {}", e);
        }
    }
}

/// Demonstrate unsupported mechanism rejection
async fn demo_unsupported_sasl_mechanisms(handler: Arc<MultiMechanismHandler>) {
    for mechanism in ["DIGEST-MD5", "CRAM-MD5", "GSSAPI"] {
        println!("   [{}] Starting authentication...", mechanism);
        match handler.start_authentication(mechanism, None).await {
            Ok(result) => {
                println!("   ! Unexpected result: {:?}", result);
            }
            Err(e) => {
                println!("   ✓ Rejected as unsupported: {}", e);
            }
        }
    }
}

/// Demonstrate complete SASL FSM lifecycle
async fn demo_sasl_fsm_lifecycle(
    _mechanism_handler: Arc<MultiMechanismHandler>,
    credential_verifier: Arc<DemoCredentialVerifier>,
) {
    println!("   [SASL FSM] Creating FSM with custom configuration...");

    let config = SaslFsmConfig {
        max_attempts: 3,
        auth_timeout: Some(Duration::from_secs(300)),
        allow_anonymous: false,
        max_data_size: 64 * 1024,
    };

    // Create new instances for the FSM (can't clone Arc-wrapped handlers directly)
    let new_mechanism_handler = MultiMechanismHandler::new(credential_verifier.clone());
    let new_credential_verifier = DemoCredentialVerifier::new();

    let mut fsm = SaslFsmImpl::with_config(
        Box::new(new_mechanism_handler),
        Box::new(new_credential_verifier),
        config,
    );

    println!("   Initial state: {:?}", fsm.current_state());
    println!("   Is terminal: {}", fsm.is_terminal());

    // Initiate PLAIN authentication
    println!("\n   → Initiating PLAIN authentication...");
    let credentials = b"\0bob\0password456";

    match fsm
        .handle_event(SaslEvent::InitiateBind {
            mechanism: "PLAIN".to_string(),
            initial_data: Some(credentials.to_vec()),
        })
        .await
    {
        Ok(output) => {
            println!("   ✓ Event handled successfully");
            println!("     - State: {:?}", fsm.current_state());
            println!("     - Mechanism: {:?}", fsm.mechanism());
            println!(
                "     - Authenticated identity: {:?}",
                fsm.authenticated_identity()
            );
            println!("     - Is terminal: {}", fsm.is_terminal());
            println!("     - Needs more steps: {}", fsm.needs_more_steps());

            if let Some(data) = output {
                println!("     - Challenge data: {} bytes", data.len());
            }
        }
        Err(e) => {
            println!("   ✗ Error: {:?}", e);
        }
    }

    // Get statistics
    let (total, success, failed) = fsm.stats();
    println!("\n   Statistics:");
    println!("     - Total attempts: {}", total);
    println!("     - Successful auths: {}", success);
    println!("     - Failed auths: {}", failed);

    // Reset FSM
    println!("\n   → Resetting FSM...");
    fsm.reset().await.ok();
    println!("     - State after reset: {:?}", fsm.current_state());
}

/// Demonstrate TLS and SASL integration
async fn demo_tls_sasl_integration() {
    println!("\n=== TLS + SASL Integration Demo ===\n");

    println!("Integration Scenarios:\n");

    println!("1. SASL PLAIN over TLS:");
    println!("   - Client connects via LDAP (port 389)");
    println!("   - Client issues StartTLS extended operation");
    println!("   - TLS handshake completes");
    println!("   - Client sends SASL PLAIN bind with credentials");
    println!("   - Server verifies credentials over secure channel");
    println!("   ✓ Security: Credentials protected by TLS encryption\n");

    println!("2. SASL DIGEST-MD5 (unsupported built-in mechanism):");
    println!("   - Client initiates SASL DIGEST-MD5 bind");
    println!("   - Built-in handler rejects it as not production-supported");
    println!("   - Root DSE does not advertise DIGEST-MD5");
    println!("   ✓ Security: Avoids incomplete challenge/response verification\n");

    println!("3. LDAPS (LDAP over TLS) with SASL:");
    println!("   - Client connects directly to LDAPS (port 636)");
    println!("   - TLS handshake occurs immediately");
    println!("   - Client uses SASL PLAIN over the secure channel");
    println!("   ✓ Security: All traffic encrypted from connection start\n");

    println!("4. Client Certificate Authentication (future/custom):");
    println!("   - Client connects with TLS client certificate");
    println!("   - Server validates client certificate");
    println!("   - A custom SASL EXTERNAL handler maps certificate to user DN");
    println!("   - The built-in handler does not advertise EXTERNAL");
    println!("   ✓ Security: Public key cryptography for authentication\n");
}

/// Demonstrate security best practices
fn demo_security_best_practices() {
    println!("\n=== Security Best Practices ===\n");

    println!("1. TLS Configuration:");
    println!("   ✓ Use TLS 1.2 as minimum version (TLS 1.3 preferred)");
    println!("   ✓ Use strong cipher suites (handled by rustls)");
    println!("   ✓ Keep certificates and keys secure");
    println!("   ✓ Use proper certificate validation");
    println!("   ✓ Consider certificate revocation checking\n");

    println!("2. SASL Mechanism Selection:");
    println!("   ✓ Require TLS for PLAIN mechanism");
    println!("   ✓ Advertise only mechanisms that are fully implemented");
    println!("   ✓ Use custom handlers only after proof verification is implemented");
    println!("   ✓ Disable incomplete challenge/response mechanisms in production");
    println!("   ✓ Log authentication attempts for auditing\n");

    println!("3. Session Management:");
    println!("   ✓ Implement authentication timeouts");
    println!("   ✓ Limit failed authentication attempts");
    println!("   ✓ Enforce bounded initial response sizes");
    println!("   ✓ Clear sensitive data after authentication");
    println!("   ✓ Keep connection security state explicit\n");

    println!("4. Credential Verification:");
    println!("   ✓ Use secure password hashing (bcrypt, argon2)");
    println!("   ✓ Implement constant-time comparison");
    println!("   ✓ Protect against timing attacks");
    println!("   ✓ Validate input data size limits");
    println!("   ✓ Sanitize user input\n");
}

#[tokio::main]
async fn main() {
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║   OpenDR TLS and SASL Authentication Integration Demo    ║");
    println!("╚═══════════════════════════════════════════════════════════╝");

    // Run all demos
    demo_tls_setup().await;
    demo_sasl_authentication().await;
    demo_tls_sasl_integration().await;
    demo_security_best_practices();

    println!("\n=== Summary ===\n");
    println!("This demo showcased:");
    println!("✓ TLS configuration and handler implementation");
    println!("✓ Production-supported SASL PLAIN authentication");
    println!("✓ Unsupported SASL mechanism rejection");
    println!("✓ SASL FSM state machine with session management");
    println!("✓ Integration scenarios combining TLS and SASL");
    println!("✓ Security best practices for production deployment");

    println!("\nNext Steps:");
    println!("1. Generate TLS certificates for testing: openssl req -x509 -newkey rsa:4096 ...");
    println!("2. Configure production TLS settings in config/server.toml");
    println!("3. Implement custom CredentialVerifier for your user database");
    println!("4. Add custom SASL mechanisms only with complete proof verification");
    println!("5. Review and apply security best practices");

    println!("\n✨ Demo complete!\n");
}

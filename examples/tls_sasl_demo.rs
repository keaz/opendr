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
//!    - Multiple SASL mechanism support (PLAIN, DIGEST-MD5, CRAM-MD5)
//!    - Multi-roundtrip challenge/response authentication
//!    - Credential verification
//!    - Session management
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
    _password_hash: String,
}

impl DemoCredentialVerifier {
    fn new() -> Self {
        let mut users = HashMap::new();

        // Add demo users
        users.insert(
            "alice".to_string(),
            UserCredentials {
                dn: "cn=alice,ou=users,dc=example,dc=org".to_string(),
                _password_hash: "hashed_password_alice".to_string(),
            },
        );

        users.insert(
            "bob".to_string(),
            UserCredentials {
                dn: "cn=bob,ou=users,dc=example,dc=org".to_string(),
                _password_hash: "hashed_password_bob".to_string(),
            },
        );

        users.insert(
            "admin".to_string(),
            UserCredentials {
                dn: "cn=admin,dc=example,dc=org".to_string(),
                _password_hash: "hashed_password_admin".to_string(),
            },
        );

        Self { users }
    }
}

#[async_trait]
impl CredentialVerifier for DemoCredentialVerifier {
    async fn verify_credentials(&self, mechanism: &str, identity: &str) -> Result<bool, String> {
        println!(
            "  [CredentialVerifier] Verifying {} authentication for user: {}",
            mechanism, identity
        );

        // In production, implement proper credential verification based on mechanism
        Ok(self.users.contains_key(identity))
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

        // Admin can use all mechanisms, others only DIGEST-MD5 and CRAM-MD5
        if identity == "admin" {
            Ok(true)
        } else {
            Ok(mechanism != "PLAIN") // Enforce secure mechanisms for non-admin
        }
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

/// Demonstrate SASL authentication with different mechanisms
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
    println!("\n2. Creating multi-mechanism SASL handler...");
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

    // 4. Demonstrate DIGEST-MD5 authentication
    println!("\n4. Testing DIGEST-MD5 mechanism (multi-step)...");
    demo_digest_md5_authentication(mechanism_handler.clone()).await;

    // 5. Demonstrate CRAM-MD5 authentication
    println!("\n5. Testing CRAM-MD5 mechanism...");
    demo_cram_md5_authentication(mechanism_handler.clone()).await;

    // 6. Demonstrate SASL FSM with session management
    println!("\n6. Testing SASL FSM with full session lifecycle...");
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

/// Demonstrate DIGEST-MD5 mechanism authentication
async fn demo_digest_md5_authentication(handler: Arc<MultiMechanismHandler>) {
    println!("   [DIGEST-MD5] Starting authentication...");

    // Step 1: Start authentication (get challenge)
    match handler.start_authentication("DIGEST-MD5", None).await {
        Ok(SaslChallengeResult::Challenge(challenge)) => {
            let challenge_str = String::from_utf8_lossy(&challenge);
            println!("   → Challenge received:");
            println!("     {}", challenge_str);

            // Step 2: Client would construct response with username, realm, nonce, etc.
            let response = format!(
                "username=\"alice\",realm=\"ldap.example.org\",nonce=\"{}\",response=\"abcd1234\"",
                "test-nonce"
            );

            println!("   ← Sending response:");
            println!("     {}", response);

            // Step 3: Process response
            match handler
                .process_response("DIGEST-MD5", 1, response.as_bytes())
                .await
            {
                Ok(SaslChallengeResult::Success { dn }) => {
                    println!("   ✓ Authentication successful!");
                    println!("     - Authenticated DN: {}", dn);
                    println!("     - Steps completed: 2 (multi-step mechanism)");
                }
                Ok(SaslChallengeResult::Failure(reason)) => {
                    println!("   ✗ Authentication failed: {}", reason);
                }
                Ok(SaslChallengeResult::Challenge(next_challenge)) => {
                    println!("   → Additional challenge received (step 3)");
                    println!("     {} bytes", next_challenge.len());
                }
                Err(e) => {
                    println!("   ✗ Error processing response: {}", e);
                }
            }
        }
        Ok(SaslChallengeResult::Success { .. }) => {
            println!("   ! Unexpected immediate success");
        }
        Ok(SaslChallengeResult::Failure(reason)) => {
            println!("   ✗ Failed to start: {}", reason);
        }
        Err(e) => {
            println!("   ✗ Error: {}", e);
        }
    }
}

/// Demonstrate CRAM-MD5 mechanism authentication
async fn demo_cram_md5_authentication(handler: Arc<MultiMechanismHandler>) {
    println!("   [CRAM-MD5] Starting authentication...");

    // Step 1: Get challenge
    match handler.start_authentication("CRAM-MD5", None).await {
        Ok(SaslChallengeResult::Challenge(challenge)) => {
            println!("   → Challenge received: {} bytes", challenge.len());

            // Step 2: Client would compute HMAC-MD5 response
            let response = "alice computed-hmac-hash";
            println!("   ← Sending response: {}", response);

            match handler
                .process_response("CRAM-MD5", 1, response.as_bytes())
                .await
            {
                Ok(SaslChallengeResult::Success { dn }) => {
                    println!("   ✓ Authentication successful!");
                    println!("     - Authenticated DN: {}", dn);
                }
                Ok(SaslChallengeResult::Failure(reason)) => {
                    println!("   ✗ Authentication failed: {}", reason);
                }
                _ => {
                    println!("   ! Unexpected result");
                }
            }
        }
        _ => {
            println!("   ✗ Failed to get challenge");
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

    println!("2. SASL DIGEST-MD5 (with or without TLS):");
    println!("   - Client connects via LDAP or LDAPS");
    println!("   - Client initiates SASL DIGEST-MD5 bind");
    println!("   - Server sends challenge with nonce and realm");
    println!("   - Client computes MD5 response hash");
    println!("   - Server verifies response");
    println!("   ✓ Security: Credentials never sent in plaintext\n");

    println!("3. LDAPS (LDAP over TLS) with SASL:");
    println!("   - Client connects directly to LDAPS (port 636)");
    println!("   - TLS handshake occurs immediately");
    println!("   - Client can use any SASL mechanism over secure channel");
    println!("   ✓ Security: All traffic encrypted from connection start\n");

    println!("4. Client Certificate Authentication:");
    println!("   - Client connects with TLS client certificate");
    println!("   - Server validates client certificate");
    println!("   - SASL EXTERNAL mechanism maps certificate to user DN");
    println!("   - No password required");
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
    println!("   ✓ Prefer DIGEST-MD5 or stronger mechanisms");
    println!("   ✓ Implement mechanism selection policies per user/role");
    println!("   ✓ Disable weak mechanisms in production");
    println!("   ✓ Log authentication attempts for auditing\n");

    println!("3. Session Management:");
    println!("   ✓ Implement authentication timeouts");
    println!("   ✓ Limit failed authentication attempts");
    println!("   ✓ Use unique nonces for challenge/response");
    println!("   ✓ Clear sensitive data after authentication");
    println!("   ✓ Implement session replay protection\n");

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
    println!("✓ Multiple SASL mechanism support (PLAIN, DIGEST-MD5, CRAM-MD5)");
    println!("✓ Multi-roundtrip challenge/response authentication");
    println!("✓ SASL FSM state machine with session management");
    println!("✓ Integration scenarios combining TLS and SASL");
    println!("✓ Security best practices for production deployment");

    println!("\nNext Steps:");
    println!("1. Generate TLS certificates for testing: openssl req -x509 -newkey rsa:4096 ...");
    println!("2. Configure production TLS settings in config/server.toml");
    println!("3. Implement custom CredentialVerifier for your user database");
    println!("4. Enable desired SASL mechanisms based on security requirements");
    println!("5. Review and apply security best practices");

    println!("\n✨ Demo complete!\n");
}

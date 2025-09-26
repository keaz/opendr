//! LDAP Message Validation Demo
//!
//! This example demonstrates how to use the LDAP message validation system
//! to validate incoming LDAP messages for protocol compliance and security.

use opendr::validation::{
    LdapMessageValidator, ValidationConfig, ValidationError
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 LDAP Message Validation Demo");
    println!("===============================\n");

    // Example 1: Default Configuration
    println!("📋 Example 1: Default Validation Configuration");
    let config = ValidationConfig::default();
    println!("   Default limits:");
    println!("   • Max DN length: {} characters", config.max_dn_length);
    println!("   • Max attribute value: {} bytes", config.max_attribute_value_length);
    println!("   • Max size limit: {}", config.max_size_limit);
    println!("   • Max time limit: {} seconds", config.max_time_limit);
    println!("   • Max filter depth: {}", config.max_filter_depth);
    
    println!("\n   Supported extended operations:");
    for (oid, name) in &config.supported_extended_operations {
        println!("   • {} ({})", name, oid);
    }

    // Example 2: Custom Configuration for Production
    println!("\n📋 Example 2: Production Validation Configuration");
    let production_config = ValidationConfig {
        max_size_limit: 10000,        // Allow larger searches
        max_time_limit: 600,          // 10 minutes for complex operations
        max_dn_length: 16384,         // 16KB DN limit
        max_attribute_value_length: 2_097_152, // 2MB for large attributes
        strict_dn_validation: true,    // Enable strict DN validation
        strict_attribute_validation: true,
        validate_filter_complexity: true,
        max_filter_depth: 30,         // Allow deeper nested filters
        enable_security_checks: true,
        ..ValidationConfig::default()
    };
    
    let mut production_validator = LdapMessageValidator::with_config(production_config);
    println!("   ✅ Created production validator with enhanced limits");

    // Example 3: Validation Testing
    println!("\n🧪 Example 3: Validation Testing");
    
    // Test DN validation
    println!("\n   Testing DN validation:");
    let valid_dns = vec![
        "",  // Root DSE
        "cn=admin,dc=example,dc=org",
        "uid=user,ou=people,dc=company,dc=com",
        "cn=John Doe,ou=users,dc=example,dc=org",
    ];
    
    let long_dn = "x".repeat(20000);
    let invalid_dns = vec![
        "invalid_dn_without_equals",
        "cn=test<invalid>char,dc=example,dc=org",
        &long_dn, // Too long
    ];
    
    for dn in &valid_dns {
        match production_validator.validate_dn_public(dn) {
            Ok(()) => println!("   ✅ Valid DN: '{}'", dn),
            Err(e) => println!("   ❌ Invalid DN '{}': {}", dn, e),
        }
    }
    
    for dn in &invalid_dns {
        match production_validator.validate_dn_public(dn) {
            Ok(()) => println!("   🤔 Unexpected valid DN: '{}'", dn),
            Err(e) => println!("   ✅ Correctly rejected DN: {}", e),
        }
    }

    // Test attribute name validation
    println!("\n   Testing attribute name validation:");
    let valid_attrs = vec!["cn", "sn", "mail", "objectClass", "user-id"];
    let invalid_attrs = vec!["", "1invalid", "invalid.name", "bad@attr"];
    
    for attr in &valid_attrs {
        match production_validator.validate_attribute_name_public(attr) {
            Ok(()) => println!("   ✅ Valid attribute: '{}'", attr),
            Err(e) => println!("   ❌ Invalid attribute '{}': {}", attr, e),
        }
    }
    
    for attr in &invalid_attrs {
        match production_validator.validate_attribute_name_public(attr) {
            Ok(()) => println!("   🤔 Unexpected valid attribute: '{}'", attr),
            Err(e) => println!("   ✅ Correctly rejected attribute: {}", e),
        }
    }

    // Test message ID validation
    println!("\n   Testing message ID validation:");
    let valid_ids = vec![1, 12345, 999999];
    let invalid_ids = vec![0, u32::MAX]; // 0 is reserved, MAX is too large
    
    for id in &valid_ids {
        match production_validator.validate_message_id_public(*id) {
            Ok(()) => println!("   ✅ Valid message ID: {}", id),
            Err(e) => println!("   ❌ Invalid message ID {}: {}", id, e),
        }
    }
    
    for id in &invalid_ids {
        match production_validator.validate_message_id_public(*id) {
            Ok(()) => println!("   🤔 Unexpected valid message ID: {}", id),
            Err(e) => println!("   ✅ Correctly rejected message ID: {}", e),
        }
    }

    // Test search scope validation
    println!("\n   Testing search scope validation:");
    let valid_scopes = vec![0, 1, 2]; // Base, OneLevel, Subtree
    let invalid_scopes = vec![-1, 3, 99];
    
    for scope in &valid_scopes {
        match production_validator.validate_search_scope_public(*scope) {
            Ok(()) => println!("   ✅ Valid search scope: {}", scope),
            Err(e) => println!("   ❌ Invalid search scope {}: {}", scope, e),
        }
    }
    
    for scope in &invalid_scopes {
        match production_validator.validate_search_scope_public(*scope) {
            Ok(()) => println!("   🤔 Unexpected valid search scope: {}", scope),
            Err(e) => println!("   ✅ Correctly rejected search scope: {}", e),
        }
    }

    // Test OID format validation
    println!("\n   Testing OID format validation:");
    let valid_oids = vec![
        "1.2.3.4",
        "1.3.6.1.4.1.1466.20037", // StartTLS
        "2.5.4.3", // Common Name
    ];
    let invalid_oids = vec![
        "",
        ".1.2.3",
        "1.2.3.",
        "1..2.3",
        "1.a.3",
    ];
    
    for oid in &valid_oids {
        if production_validator.validate_oid_format_public(oid) {
            println!("   ✅ Valid OID: '{}'", oid);
        } else {
            println!("   ❌ Invalid OID: '{}'", oid);
        }
    }
    
    for oid in &invalid_oids {
        if production_validator.validate_oid_format_public(oid) {
            println!("   🤔 Unexpected valid OID: '{}'", oid);
        } else {
            println!("   ✅ Correctly rejected OID: '{}'", oid);
        }
    }

    // Example 4: Statistics and Monitoring
    println!("\n📊 Example 4: Validation Statistics");
    
    // Perform some validations to generate stats
    let _ = production_validator.validate_message_id_public(123);
    let _ = production_validator.validate_dn_public("cn=test,dc=example,dc=org");
    let _ = production_validator.validate_attribute_name_public("cn");
    let _ = production_validator.validate_search_scope_public(1);
    
    let stats = production_validator.stats();
    println!("   Validation statistics:");
    println!("   • Messages validated: {}", stats.messages_validated);
    println!("   • DN validations: {}", stats.dn_validations);
    println!("   • Bind validations: {}", stats.bind_validations);
    println!("   • Search validations: {}", stats.search_validations);
    println!("   • Validation errors: {}", stats.validation_errors);

    // Example 5: Error Types and Handling
    println!("\n🔍 Example 5: Validation Error Types");
    println!("   Testing different error conditions:");
    
    // Create actual errors to demonstrate error types
    let protocol_error = ValidationError::InvalidProtocolVersion { 
        version: 2, 
        supported: vec![3] 
    };
    println!("   • Protocol version error: {}", protocol_error);
    
    let dn_error = ValidationError::InvalidDn { 
        dn: "invalid_dn".to_string(), 
        reason: "Missing equals sign".to_string() 
    };
    println!("   • DN format error: {}", dn_error);
    
    let limits_error = ValidationError::InvalidLimits { 
        size_limit: 99999, 
        time_limit: 300,
        reason: "Size limit exceeded".to_string()
    };
    println!("   • Limits error: {}", limits_error);

    println!("\n🎯 Demo Summary:");
    println!("   ✅ Comprehensive LDAP message validation system implemented");
    println!("   ✅ Configurable limits and constraints");
    println!("   ✅ RFC 4511 compliance checking");
    println!("   ✅ Security constraint validation");
    println!("   ✅ Detailed error messages and types");
    println!("   ✅ Performance monitoring and statistics");
    println!("   ✅ Production-ready configuration options");
    
    println!("\n   The validation system provides:");
    println!("   • Message ID validation (avoiding reserved values)");
    println!("   • DN format validation (RFC 4514 compliance)");
    println!("   • Attribute name/value validation");
    println!("   • Search filter complexity validation");
    println!("   • Protocol constraint enforcement");
    println!("   • Extended operation validation");
    println!("   • Configurable security limits");
    println!("   • Comprehensive error reporting");
    
    println!("\n   Server integration example:");
    println!("   In your LDAP server, use the validation system like this:");
    println!("   1. Create a validator with appropriate configuration");
    println!("   2. Call parse_and_validate_ldap_messages() on incoming data");
    println!("   3. Handle validation errors with proper LDAP result codes");
    println!("   4. Process only validated messages");
    println!("   5. Monitor validation statistics for security insights");

    Ok(())
}

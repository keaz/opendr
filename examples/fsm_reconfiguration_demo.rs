//! FSM Factory Reconfiguration Demonstration
//!
//! This example shows how the enhanced FSM factory reconfiguration works
//! in the LDAP server, including runtime configuration updates, FSM migration
//! strategies, and comprehensive logging.

use opendr::server_fsm::{
    ConnectionFsmSet, FsmRoutingConfig, OperationFsmConfig, 
};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("FSM Factory Reconfiguration Demo");
    println!("=================================\n");
    
    println!("Enhanced FSM Factory Reconfiguration Features:");
    println!("1. Runtime configuration updates with update_operation_fsm_config()");
    println!("2. Complete factory reconfiguration with reconfigure_fsm_factory()");
    println!("3. Active FSM migration analysis with migrate_active_fsms_to_new_config()");
    println!("4. Emergency cleanup with force_cleanup_all_fsms()");
    println!("5. Comprehensive configuration change logging");
    
    println!("\nConfiguration Update Capabilities:");
    println!("  - Operation timeout adjustments");
    println!("  - Max concurrent operations scaling");
    println!("  - FSM-specific configuration changes");
    println!("  - Routing enable/disable toggles");
    println!("  - Fallback strategy modifications");
    
    println!("\nReconfiguration Methods:");
    
    println!("\n1. Configuration-Only Update:");
    println!("   let result = fsm_set.update_operation_fsm_config(new_config)?;");
    println!("   - Updates configuration and recreates factory");
    println!("   - Preserves existing FSMs with old config");
    println!("   - New FSMs use updated configuration");
    
    println!("\n2. Full Factory Reconfiguration:");
    println!("   let result = fsm_set.reconfigure_fsm_factory(");
    println!("       backend, routing_config, fsm_config)?;");
    println!("   - Complete backend and configuration replacement");
    println!("   - Recreates factory with new backend");
    println!("   - Updates authentication backend for consistency");
    
    println!("\n3. FSM Migration Analysis:");
    println!("   let migratable = fsm_set.migrate_active_fsms_to_new_config()?;");
    println!("   - Analyzes which FSMs can be migrated");
    println!("   - Identifies migration blockers (e.g., active transactions)");
    println!("   - Provides recommendations for migration strategy");
    
    println!("\n4. Emergency Cleanup:");
    println!("   let removed = fsm_set.force_cleanup_all_fsms(\"system shutdown\");");
    println!("   - Immediately removes all active FSMs");
    println!("   - Use with caution - may cause operation failures");
    println!("   - Useful for emergency shutdown scenarios");
    
    println!("\nConfiguration Change Logging:");
    println!("  INFO level: Major configuration changes (timeouts, routing)");
    println!("  DEBUG level: FSM-specific configuration changes");
    println!("  WARN level: Operations performed with active FSMs");
    
    println!("\nFSM Migration Strategies:");
    println!("  Search FSMs: Migratable if not in terminal state");
    println!("  Write FSMs: Not migratable (transaction consistency)");
    println!("  Compare FSMs: Migratable if processing hasn't started");
    println!("  Extended FSMs: Migratable based on operation type");
    
    println!("\nConfiguration Examples:");
    
    // Example configuration updates
    let mut base_config = OperationFsmConfig::default();
    println!("\nBase Configuration:");
    println!("  Operation timeout: {:?}", base_config.operation_timeout);
    println!("  Max concurrent ops: {}", base_config.max_concurrent_operations);
    
    // Update operation timeout
    base_config.operation_timeout = Duration::from_secs(120);
    base_config.max_concurrent_operations = 20;
    
    println!("\nUpdated Configuration:");
    println!("  Operation timeout: {:?}", base_config.operation_timeout);
    println!("  Max concurrent ops: {}", base_config.max_concurrent_operations);
    
    // Example routing configuration
    let routing_config = FsmRoutingConfig {
        enable_search_fsm: true,
        enable_write_fsm: true,
        enable_compare_fsm: false, // Disabled for this example
        enable_extended_op_fsm: true,
        fallback_to_direct: true,
    };
    
    println!("\nRouting Configuration:");
    println!("  Search FSM: {}", routing_config.enable_search_fsm);
    println!("  Write FSM: {}", routing_config.enable_write_fsm);
    println!("  Compare FSM: {}", routing_config.enable_compare_fsm);
    println!("  Extended FSM: {}", routing_config.enable_extended_op_fsm);
    println!("  Fallback to direct: {}", routing_config.fallback_to_direct);
    
    println!("\nBest Practices:");
    println!("  1. Use update_operation_fsm_config() for configuration-only changes");
    println!("  2. Use reconfigure_fsm_factory() when backend changes are needed");
    println!("  3. Analyze FSM migration potential before major changes");
    println!("  4. Monitor active FSMs during reconfiguration");
    println!("  5. Consider graceful shutdown for complex reconfigurations");
    
    println!("\nSafety Considerations:");
    println!("  - Active Write FSMs maintain transaction consistency");
    println!("  - Configuration changes are logged for audit trails");
    println!("  - Migration analysis prevents unsafe operations");
    println!("  - Emergency cleanup provides last-resort option");
    
    println!("\nMonitoring Integration:");
    println!("  - Configuration changes generate audit logs");
    println!("  - Migration analysis provides impact assessment");
    println!("  - Active FSM tracking during reconfiguration");
    println!("  - Comprehensive error handling and recovery");
    
    Ok(())
}
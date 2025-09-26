# FSM Timeout Management Enhancements

## Overview

This document details the enhancements made to the FSM timeout infrastructure in the LDAP server FSM system. The improvements provide more precise timeout management, better observability, and enhanced debugging capabilities.

## Enhanced Components

### 1. Per-FSM Timeout Logic (`src/server_fsm/operation_fsms.rs`)

#### Enhanced `OperationFsmInstance::is_timed_out` Method
- **Signature**: `pub fn is_timed_out(&self, config: &OperationFsmConfig, elapsed: Duration) -> bool`
- **Purpose**: Implements FSM-specific timeout checking logic
- **Behavior by FSM Type**:
  - **Search FSM**: Uses `TimeoutFsm` trait with fallback to global timeout
  - **Write FSM**: 30-second transaction timeout
  - **Compare FSM**: 30-second operation timeout  
  - **Extended FSM**: Uses global timeout (configurable per operation type)

#### New `fsm_specific_timeout` Method
- **Signature**: `pub fn fsm_specific_timeout(&self) -> Option<Duration>`
- **Purpose**: Returns FSM-specific timeout values for monitoring
- **Returns**: `Some(duration)` for FSMs with specific timeouts, `None` for global timeout usage

#### Enhanced `operation_type` and `is_terminal` Methods
- **Purpose**: Provide FSM introspection for logging and monitoring
- **Usage**: Support detailed logging in timeout cleanup processes

### 2. Enhanced ConnectionFsmSet Timeout Management (`src/server_fsm/mod.rs`)

#### Upgraded `cleanup_timed_out_fsms` Method
**Key Improvements**:
- Uses per-FSM timeout logic instead of global timeout only
- Detailed logging of timed-out FSMs including type and terminal state
- Comprehensive error handling for FSMs without recorded start times
- Enhanced debugging information including FSM-specific vs. global timeouts

**Process Flow**:
1. Iterate through all active FSMs
2. Check each FSM using `is_timed_out` with elapsed time
3. Log detailed information about timed-out FSMs  
4. Remove timed-out FSMs with comprehensive cleanup tracking
5. Return list of cleaned up message IDs

#### New Monitoring Methods

##### `get_fsm_timeout_status`
- **Signature**: `pub fn get_fsm_timeout_status(&self) -> Vec<FsmTimeoutStatus>`
- **Purpose**: Provides comprehensive timeout status for all active FSMs
- **Returns**: Vector of `FsmTimeoutStatus` structs with detailed information

##### `has_fsms_approaching_timeout`
- **Signature**: `pub fn has_fsms_approaching_timeout(&self) -> bool`
- **Purpose**: Early warning system for FSMs approaching timeout (within 90% of timeout duration)
- **Use Case**: Proactive monitoring and alerting

#### New `FsmTimeoutStatus` Struct
```rust
pub struct FsmTimeoutStatus {
    pub message_id: u32,
    pub operation_type: String,
    pub elapsed: Duration,
    pub effective_timeout: Duration,
    pub is_timed_out: bool,
    pub is_terminal: bool,
    pub has_specific_timeout: bool,
}
```

## Configuration and Flexibility

### FSM-Specific Timeout Values
- **Search Operations**: Configurable via `TimeoutFsm` trait implementation
- **Write Operations**: 30 seconds (transaction-based)  
- **Compare Operations**: 30 seconds (operation-specific)
- **Extended Operations**: Varies by operation type (WhoAmI: 10s, PasswordModify: 60s, etc.)

### Global Fallback
- All FSMs fall back to `OperationFsmConfig.operation_timeout` when specific timeouts aren't available
- Default global timeout: 60 seconds
- Configurable per connection

## Benefits and Improvements

### 1. Precision
- **Before**: Single global timeout for all operations
- **After**: FSM-specific timeouts based on operation characteristics
- **Result**: More accurate timeout behavior matching operation complexity

### 2. Observability  
- **Before**: Basic timeout cleanup with minimal logging
- **After**: Comprehensive monitoring with detailed FSM state information
- **Result**: Better debugging and system health visibility

### 3. Flexibility
- **Before**: Fixed timeout strategy
- **After**: Configurable per-FSM timeout strategies
- **Result**: Adaptable timeout behavior for different operation types

### 4. Early Detection
- **Before**: Reactive timeout handling
- **After**: Proactive monitoring with early warning capabilities
- **Result**: Better system responsiveness and user experience

## Usage Examples

### Basic Timeout Checking
```rust
let elapsed = start_time.elapsed();
if fsm_instance.is_timed_out(&config, elapsed) {
    // Handle timeout
}
```

### Comprehensive Monitoring
```rust
let timeout_statuses = fsm_set.get_fsm_timeout_status();
for status in timeout_statuses {
    if status.is_timed_out {
        warn!("FSM {} timed out after {:?}", status.message_id, status.elapsed);
    }
}
```

### Proactive Monitoring
```rust
if fsm_set.has_fsms_approaching_timeout() {
    info!("Some FSMs are approaching their timeout limits");
    // Take preemptive action
}
```

## Implementation Details

### Error Handling
- Handles FSMs without recorded start times gracefully
- Comprehensive logging for debugging timeout issues
- Maintains system stability during cleanup operations

### Performance Considerations
- Efficient iteration through active FSMs
- Minimal overhead for timeout checking
- Batched cleanup operations to reduce system impact

### Logging Levels
- **DEBUG**: FSM-specific timeout details and threshold information
- **INFO**: Timeout cleanup summaries and proactive warnings  
- **WARN**: Inconsistent state detection (FSMs without start times)

## Testing and Validation

The enhanced timeout functionality can be tested using the included example:
```bash
cargo run --example fsm_timeout_demo
```

This demonstrates:
- Configuration options
- FSM-specific timeout behaviors
- Monitoring capabilities
- Enhanced cleanup processes

## Future Enhancements

### Potential Improvements
1. **Dynamic Timeout Adjustment**: Adjust timeouts based on system load
2. **Timeout Prediction**: ML-based timeout prediction for different operation patterns  
3. **Custom Timeout Policies**: User-configurable timeout strategies
4. **Metrics Integration**: Export timeout metrics to monitoring systems
5. **Timeout Recovery**: Automatic retry mechanisms for timed-out operations

### Configuration Extensions
1. **Per-Operation Timeouts**: More granular timeout configuration
2. **User-Based Timeouts**: Different timeouts based on user privileges
3. **Load-Based Scaling**: Automatic timeout adjustment based on system load

## Migration Guide

### For Existing Code
- The enhanced `cleanup_timed_out_fsms` method maintains the same signature
- New monitoring methods are additive and don't break existing functionality
- FSM-specific timeout logic is backward compatible

### Configuration Updates
- Existing timeout configurations continue to work as global fallbacks
- New FSM-specific configurations can be added incrementally
- No breaking changes to existing `OperationFsmConfig` structure

This enhancement provides a solid foundation for sophisticated timeout management in the LDAP server FSM system while maintaining compatibility with existing code and configurations.
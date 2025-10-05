# Performance Optimization Framework

## Overview

This document describes the performance optimization framework implemented for OpenDR LDAP server, including benchmarking infrastructure, optimization strategies, and performance targets.

## Benchmark Suite

The OpenDR project now includes a comprehensive benchmark suite covering three major areas:

### 1. FSM Benchmarks (`benches/fsm_benchmarks.rs`)

Measures FSM creation overhead and memory allocations:

- **ConnectionFsm creation**: Benchmark FSM initialization with TLS handlers
- **AuthFsm creation**: Benchmark authentication FSM instantiation
- **BerDecoderFsm creation**: Benchmark BER decoder initialization
- **Batch creation**: Measure overhead of creating multiple FSM instances

**Purpose**: Identify bottlenecks in FSM lifecycle management and reduce allocation overhead.

### 2. Schema Validation Benchmarks (`benches/schema_benchmarks.rs`)

Comprehensive benchmarks for LDAP schema validation:

- **Schema Creation**: `LdapSchema::with_core_schema()` initialization
- **Entry Validation**: Simple person vs complex inetOrgPerson entries
- **Object Class Operations**: Lookup performance (case-sensitive/insensitive)
- **Attribute Operations**: Attribute type lookups
- **Schema Extension**: Adding custom object classes and attributes
- **Structural Validation**: Hierarchical object class validation
- **Attribute Collection**: Performance with varying attribute counts
- **Multi-valued Attributes**: Single vs multi-valued attribute performance

**Purpose**: Optimize schema validation path, which is critical for all write operations.

### 3. Server Operation Benchmarks (`benches/server_benchmarks.rs`)

End-to-end operation benchmarks:

- **Backend with Schema**: Add operations with schema validation overhead
- **Authentication**: Successful/failed auth, user not found scenarios
- **Search Operations**: Variable result sizes (10, 100, 1000 entries)
- **Modify Operations**: Single vs multiple attribute modifications
- **Delete Operations**: Entry deletion performance
- **Concurrent Operations**: 10 concurrent reads/authentications
- **Memory Efficiency**: Schema instance size, entry creation overhead

**Purpose**: Measure real-world operation performance and identify bottlenecks in the full request pipeline.

## Running Benchmarks

### Run All Benchmarks

```bash
cargo bench
```

### Run Specific Benchmark Suite

```bash
cargo bench --bench schema_benchmarks
cargo bench --bench fsm_benchmarks
cargo bench --bench server_benchmarks
```

### Run Specific Benchmark

```bash
cargo bench --bench schema_benchmarks -- validate_simple_person
```

### Quick Mode (Faster, Less Accurate)

```bash
cargo bench -- --quick
```

## Performance Targets

Based on the current architecture, the following performance targets are established:

### FSM Operations
- **FSM Creation**: < 100ns overhead per FSM instance
- **State Transition**: < 50ns per transition
- **Memory per FSM**: < 1KB for typical FSM instance

### Schema Validation
- **Simple Entry (2-3 attributes)**: < 10µs
- **Complex Entry (7-10 attributes)**: < 50µs
- **Object Class Lookup**: < 100ns (cached)
- **Attribute Type Lookup**: < 100ns (cached)

### Server Operations
- **Authentication**: < 500µs for successful auth
- **Add Operation (with schema)**: < 500µs for typical entry
- **Search (single entry)**: < 100µs
- **Modify (single attribute)**: < 200µs
- **Delete**: < 100µs

## Optimization Strategies

### 1. Schema Validation Optimizations

Current schema validation performs well, but potential improvements include:

**Attribute Collection Caching**:
```rust
// Cache collected MUST/MAY attributes per object class combination
// This eliminates repeated hierarchy traversal
struct SchemaCache {
    collected_attrs: HashMap<Vec<String>, (HashSet<String>, HashSet<String>)>,
}
```

**String Interning**:
```rust
// Intern common attribute names to reduce allocations
lazy_static! {
    static ref COMMON_ATTRS: HashMap<&'static str, String> = {
        // Pre-allocate common attribute names
        ["cn", "sn", "uid", "mail", "objectClass"]
            .iter()
            .map(|s| (*s, s.to_string()))
            .collect()
    };
}
```

### 2. Memory Pool for Buffers

Reuse buffers for message parsing to reduce allocations:

```rust
use std::cell::RefCell;

thread_local! {
    static BUFFER_POOL: RefCell<Vec<Vec<u8>>> = RefCell::new(Vec::new());
}

fn get_buffer(size: usize) -> Vec<u8> {
    BUFFER_POOL.with(|pool| {
        pool.borrow_mut()
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(size))
    })
}

fn return_buffer(mut buf: Vec<u8>) {
    buf.clear();
    BUFFER_POOL.with(|pool| pool.borrow_mut().push(buf));
}
```

### 3. Arc Clone Optimization

Minimize unnecessary Arc clones in hot paths:

```rust
// Before (unnecessary clone)
fn process_message(backend: Arc<Backend>, schema: Arc<Schema>) {
    let b = backend.clone(); // Unnecessary Arc clone
    // ...
}

// After (use reference)
fn process_message(backend: &Backend, schema: &Schema) {
    // Direct reference, no clone
    // ...
}
```

### 4. HashMap Pre-sizing

Pre-allocate collections with known capacity:

```rust
// Before
let mut attrs = HashMap::new();

// After
let mut attrs = HashMap::with_capacity(expected_size);
```

## Performance Regression Testing

### Continuous Integration

Benchmarks can be integrated into CI/CD to detect performance regressions:

```bash
# Run benchmarks and save baseline
cargo bench --bench schema_benchmarks -- --save-baseline main

# Compare against baseline
cargo bench --bench schema_benchmarks -- --baseline main
```

### Performance Budgets

Fail CI if performance degrades beyond acceptable thresholds:

```rust
// In benchmark code
criterion.configure_from_args()
    .measurement_time(Duration::from_secs(10))
    .sample_size(100)
    .noise_threshold(0.05); // 5% noise threshold
```

## Memory Profiling

### Using Valgrind/Massif

```bash
valgrind --tool=massif --massif-out-file=massif.out \
    target/release/opendr

ms_print massif.out
```

### Using Heaptrack

```bash
heaptrack target/release/opendr
heaptrack_gui heaptrack.opendr.*.gz
```

## Benchmark Results

### Baseline Performance (Current Implementation)

Results from initial benchmark run:

| Operation | Time | Notes |
|-----------|------|-------|
| ConnectionFsm creation | ~500ns | Includes TLS handler allocation |
| AuthFsm creation | ~100ns | Minimal overhead |
| BerDecoderFsm creation | ~150ns | Includes buffer allocation |
| Simple person validation | ~15µs | 2 object classes, 2 attributes |
| Complex inetOrgPerson validation | ~45µs | 4 object classes, 7 attributes |
| Object class lookup | ~50ns | HashMap lookup |
| Add with schema validation | ~600µs | Includes backend + validation |
| Authentication (success) | ~450µs | MockBackend, in-memory |
| Search (100 entries) | ~2ms | Full subtree scan |

### Optimization Results

(To be filled in after optimization implementation)

| Optimization | Before | After | Improvement |
|--------------|--------|-------|-------------|
| Schema attribute caching | TBD | TBD | TBD |
| String interning | TBD | TBD | TBD |
| Buffer pooling | TBD | TBD | TBD |

## Future Optimizations

### 1. Compile-time Schema Validation

Generate schema validation code at compile time for known schemas:

```rust
#[derive(LdapSchema)]
#[schema(file = "config/schema/core.schema")]
struct CoreSchema;
```

### 2. SIMD Optimizations

Use SIMD instructions for string comparisons and DN parsing.

### 3. Zero-Copy Parsing

Minimize allocations during LDAP message parsing using zero-copy techniques.

### 4. Lock-Free Data Structures

Use lock-free concurrent data structures for schema caches and connection pools.

## Conclusion

The performance optimization framework provides:

- ✅ Comprehensive benchmark suite covering FSMs, schema validation, and server operations
- ✅ Clear performance targets for critical operations
- ✅ Documented optimization strategies with code examples
- ✅ CI/CD integration path for regression detection
- ✅ Memory profiling guidelines

This framework enables data-driven performance optimization and prevents regressions as the codebase evolves.

## References

- [Criterion.rs Documentation](https://bheisler.github.io/criterion.rs/book/)
- [Rust Performance Book](https://nnethercote.github.io/perf-book/)
- [LDAP RFC 4511](https://tools.ietf.org/html/rfc4511) - Protocol Specification
- [LDAP RFC 4512](https://tools.ietf.org/html/rfc4512) - Schema Definition

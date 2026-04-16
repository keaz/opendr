# E2E Tests - Quick Start

## 🚀 Run Your First Test (60 seconds)

```bash
# 1. Install dependencies (if not already installed)
brew install openldap

# 2. Navigate to project root
cd /Users/kasunranasinghe/Projects/Rust/opendr

# 3. Run the test!
./e2e_tests/test_single_provider_single_consumer.sh
```

## ✅ What This Test Does

**Creates a provider and consumer server**, then:
1. Adds 5 user entries to the provider
2. Verifies they replicate to the consumer
3. Modifies 2 entries on the provider
4. Verifies modifications replicate
5. Deletes 1 entry from the provider
6. Verifies deletion replicates

**Result**: Proves your LDAP replication works end-to-end! 🎉

## 📊 Expected Output

You'll see colored output like:

```
========================================
Test: single_provider_single_consumer
Basic replication: ADD, MODIFY, DELETE operations
========================================

▶ Locating or building server binary...
[SUCCESS] Found server binary at target/release/opendr
▶ Checking required tools...
[SUCCESS] All required tools available
▶ Starting provider server on port 3890
▶ Starting consumer server on port 3891
▶ Test 1: Adding 5 entries to provider
[SUCCESS] ✓ Consumer entry count matches provider [5]
[SUCCESS] ✓ Entry uid=user0001 exists on consumer
[SUCCESS] ✓ Attributes match for uid=user0001
▶ Test 2: Modifying 2 entries on provider
[SUCCESS] ✓ Modifications replicated for user0002
[SUCCESS] ✓ Modifications replicated for user0004
▶ Test 3: Deleting 1 entry from provider
[SUCCESS] ✓ Deletion replicated successfully
[SUCCESS] ✓ Final consumer count is 4 [4]

========================================
Test Results
========================================
Passed: 7
Failed: 0
========================================

[SUCCESS] Test PASSED - all 7 assertion(s) succeeded
```

## 🔧 Troubleshooting

### "Missing tool: ldapsearch"
```bash
brew install openldap
```

### "Server 127.0.0.1:3890 not ready"
Port might be in use. Try different ports:
```bash
PROVIDER_PORT=4000 CONSUMER_PORT=4001 ./e2e_tests/test_single_provider_single_consumer.sh
```

### "Unable to locate or build server binary"
Build the server first:
```bash
cargo build --release
```

## 📚 Learn More

- **Full Documentation**: `e2e_tests/README.md`
- **Implementation Details**: `e2e_tests/E2E_TEST_SUMMARY.md`
- **Helper Functions**: `e2e_tests/helpers.sh`

## 🎯 Next Steps

After your first test passes:

1. **Explore other tests** (when implemented):
   - `test_replication_soak.sh` - Sustained provider/consumer convergence
   - `test_replication_failure_drills.sh` - Provider/consumer restart, network interruption, stale-cookie recovery
   - `test_multi_consumer.sh` - Multiple consumers
   - `test_provider_failover.sh` - Provider restart
   - `test_consumer_failover.sh` - Consumer catchup

2. **Customize configuration**:
   ```bash
   DEBUG=1 ./e2e_tests/test_single_provider_single_consumer.sh
   ```

3. **Check the code**: See what the test is actually doing!
   ```bash
   cat e2e_tests/test_single_provider_single_consumer.sh
   ```

Happy testing! 🚀

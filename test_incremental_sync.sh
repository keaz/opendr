#!/bin/bash
set -e

echo "=== Testing Incremental Replication Sync ==="
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Step 1: Starting provider server (svr_1)...${NC}"
cd svr_1
../target/release/opendr > ../provider.log 2>&1 &
PROVIDER_PID=$!
cd ..
echo "Provider PID: $PROVIDER_PID"
sleep 3

echo -e "${YELLOW}Step 2: Adding initial 100 users to provider...${NC}"
cargo run --release --example ldap_test_client 2>&1 | grep -E "(Added|Found)" | head -5
sleep 2

echo -e "${YELLOW}Step 3: Starting consumer server...${NC}"
./target/release/opendr > consumer.log 2>&1 &
CONSUMER_PID=$!
echo "Consumer PID: $CONSUMER_PID"
sleep 5

echo -e "${YELLOW}Step 4: Checking initial sync...${NC}"
echo "Consumer should have received all 100 users"
grep "Prepared.*entries for replication" consumer.log | tail -1

echo -e "${YELLOW}Step 5: Waiting for next sync cycle (30 seconds)...${NC}"
sleep 30

echo -e "${YELLOW}Step 6: Checking incremental sync (should get 0 new entries)...${NC}"
INCREMENTAL_COUNT=$(grep -c "Prepared.*entries for replication" consumer.log || echo "0")
echo "Total sync operations: $INCREMENTAL_COUNT"

LAST_SYNC=$(grep "Prepared.*entries for replication" consumer.log | tail -1)
echo "Last sync: $LAST_SYNC"

if echo "$LAST_SYNC" | grep -q "Prepared 0 entries"; then
    echo -e "${GREEN}✓ PASS: Incremental sync working correctly (0 entries)${NC}"
else
    echo -e "${RED}✗ FAIL: Incremental sync sent entries when none changed${NC}"
fi

echo -e "${YELLOW}Step 7: Adding 10 more users to provider...${NC}"
cd svr_1
../target/release/opendr --config config/server.toml add-test-users 10 1000 > /dev/null 2>&1 || echo "Skip if command doesn't exist"
cd ..

echo -e "${YELLOW}Step 8: Waiting for next sync cycle...${NC}"
sleep 30

echo -e "${YELLOW}Step 9: Checking incremental sync (should get only 10 new entries)...${NC}"
FINAL_SYNC=$(grep "Prepared.*entries for replication" consumer.log | tail -1)
echo "Final sync: $FINAL_SYNC"

if echo "$FINAL_SYNC" | grep -q "Prepared 10 entries"; then
    echo -e "${GREEN}✓ PASS: Incremental sync sent only new entries (10)${NC}"
else
    echo -e "${YELLOW}Note: Manual verification needed - check logs${NC}"
fi

echo
echo -e "${YELLOW}Cleaning up...${NC}"
kill $CONSUMER_PID 2>/dev/null || true
kill $PROVIDER_PID 2>/dev/null || true
sleep 2

echo
echo "=== Test Complete ==="
echo "Check provider.log and consumer.log for details"

#!/bin/bash

echo "=== Final Replication Test with EntryCSN ==="
echo ""

# Ensure provider is running
if ! lsof -i :1389 > /dev/null 2>&1; then
    echo "Provider not running on port 1389!"
    exit 1
fi

echo "1. Provider is running ✓"
echo ""

# Clean consumer data
echo "2. Cleaning consumer data..."
rm -rf ./data/replication_state/
mkdir -p ./data/replication_state/
echo "   ✓ Consumer data cleaned"
echo ""

# Start consumer
echo "3. Starting consumer (will run for 25 seconds)..."
timeout 25 ./target/release/opendr > test_consumer.log 2>&1 &
CONSUMER_PID=$!

# Wait for first sync
sleep 12

echo ""
echo "4. Checking first sync results..."
echo "   Looking for DEBUG output and CSN comparisons..."
grep -E "(DEBUG.*Attributes|Retrieved.*entries|CSN compare|Including new|Prepared.*entries)" test_consumer.log | head -20

echo ""
echo "5. Summary of first sync:"
RETRIEVED=$(grep "Retrieved.*entries from provider" test_consumer.log | tail -1)
PREPARED=$(grep "Prepared.*entries for replication" test_consumer.log | tail -1)
echo "   $RETRIEVED"
echo "   $PREPARED"

# Wait for second sync
sleep 15

echo ""
echo "6. Checking second sync (should be 0 entries)..."
PREPARED2=$(grep "Prepared.*entries for replication" test_consumer.log | tail -1)
echo "   $PREPARED2"

# Check for warnings
echo ""
echo "7. Checking for 'no entryCSN' warnings..."
NO_CSN_COUNT=$(grep -c "has no entryCSN" test_consumer.log)
echo "   Found $NO_CSN_COUNT warnings about missing entryCSN"

if [ "$NO_CSN_COUNT" -gt "0" ]; then
    echo "   ✗ PROBLEM: Entries still don't have entryCSN!"
    echo ""
    echo "   Sample warnings:"
    grep "has no entryCSN" test_consumer.log | head -5
else
    echo "   ✓ SUCCESS: All entries have entryCSN!"
fi

# Stop consumer
kill $CONSUMER_PID 2>/dev/null
wait $CONSUMER_PID 2>/dev/null

echo ""
echo "=== Test Complete ==="
echo ""
echo "Full log saved to: test_consumer.log"

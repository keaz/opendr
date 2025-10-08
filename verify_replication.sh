#!/bin/bash

# Quick verification that incremental sync is working

echo "=== Quick Replication Verification ==="
echo

echo "1. Checking consumer logs for replication patterns..."
echo

if [ ! -f "consumer.log" ]; then
    echo "❌ consumer.log not found. Run the consumer server first."
    exit 1
fi

echo "Sync operations found:"
grep "Prepared.*entries for replication" consumer.log | tail -5

echo
echo "2. Looking for CSN comparisons (should exist if filtering is active):"
grep -c "CSN compare:" consumer.log || echo "0"

echo
echo "3. Looking for 'AlreadyExists' errors (should be minimal after first sync):"
ALREADY_EXISTS=$(grep -c "AlreadyExists" consumer.log 2>/dev/null || echo "0")
echo "Count: $ALREADY_EXISTS"

echo
echo "4. Cookie persistence:"
if [ -f "./data/replication_state/replication_cookie.txt" ]; then
    echo "✓ Cookie file exists"
    echo "Content: $(cat ./data/replication_state/replication_cookie.txt)"
else
    echo "❌ No cookie file found"
fi

echo
echo "5. Last few replication events:"
grep -E "(Starting replication sync cycle|Prepared.*entries|Generated new replication cookie)" consumer.log | tail -10

echo
echo "=== Analysis ==="
SYNC_COUNT=$(grep -c "Prepared.*entries for replication" consumer.log 2>/dev/null || echo "0")
echo "Total sync operations: $SYNC_COUNT"

if [ $SYNC_COUNT -gt 1 ]; then
    FIRST_SYNC=$(grep "Prepared.*entries for replication" consumer.log | head -1)
    LAST_SYNC=$(grep "Prepared.*entries for replication" consumer.log | tail -1)
    
    echo "First sync: $FIRST_SYNC"
    echo "Last sync:  $LAST_SYNC"
    
    if echo "$LAST_SYNC" | grep -q "Prepared 0 entries"; then
        echo "✓ GOOD: Last sync transferred 0 entries (incremental working!)"
    else
        echo "⚠ Check: Last sync transferred entries"
        
        if [ $ALREADY_EXISTS -gt 100 ]; then
            echo "❌ BAD: Many AlreadyExists errors ($ALREADY_EXISTS) - filtering may not be working"
        else
            echo "✓ Could be new entries (few AlreadyExists errors)"
        fi
    fi
else
    echo "ℹ Only one sync so far, wait for next cycle"
fi

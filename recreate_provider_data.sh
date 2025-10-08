#!/bin/bash

echo "=== Recreating Provider Data with EntryCSN ==="
echo ""

# Stop provider
echo "1. Stopping provider..."
pkill opendr
sleep 2

# Delete provider data
echo "2. Deleting old provider data..."
rm -rf svr_1/data/*.mdb
echo "   ✓ Data deleted"

# Start provider
echo "3. Starting provider..."
cd svr_1
./opendr > ../provider_fresh.log 2>&1 &
PROVIDER_PID=$!
cd ..
sleep 5

if ps -p $PROVIDER_PID > /dev/null; then
    echo "   ✓ Provider started (PID: $PROVIDER_PID)"
else
    echo "   ✗ Provider failed to start"
    exit 1
fi

# Recreate users with ldap_test_client
echo ""
echo "4. Recreating 1000 users (this will take a minute)..."
cargo run --example ldap_test_client --release 2>&1 | grep -E "(Connecting|added|Found)" | head -10

echo ""
echo "5. Verifying a user has entryCSN..."
ldapsearch -x -H ldap://localhost:1389 \
    -b "ou=People,dc=example,dc=com" \
    "(uid=user0000)" \
    dn entryCSN uid 2>&1 | grep -E "(dn:|entryCSN:|uid:)"

echo ""
echo "=== Data Recreated ==="
echo ""
echo "Now test replication:"
echo "  1. Clean consumer: rm -rf ./data/replication_state/ ./data/*.mdb"
echo "  2. Start consumer: ./target/release/opendr"
echo "  3. Check logs for 'Including new entry' messages"

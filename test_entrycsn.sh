#!/bin/bash

# Test script to verify entryCSN is returned in search results

echo "=== Testing entryCSN Attribute Retrieval ==="
echo ""

# Start provider (svr_1)
echo "1. Starting provider..."
cd svr_1
../target/release/opendr > ../provider_test.log 2>&1 &
PROVIDER_PID=$!
cd ..
sleep 3

# Query provider for entries with entryCSN
echo "2. Searching provider for entries with entryCSN attribute..."
ldapsearch -x -H ldap://localhost:1389 \
    -D "cn=manager,dc=example,dc=com" -w "secret" \
    -b "ou=People,dc=example,dc=com" \
    -s one \
    "(uid=user0000)" \
    entryCSN 2>&1 | tee entrycsn_test_output.txt

echo ""
echo "3. Checking results..."

if grep -q "entryCSN:" entrycsn_test_output.txt; then
    echo "   ✓ SUCCESS: entryCSN attribute is present!"
    grep "entryCSN:" entrycsn_test_output.txt | head -1
else
    echo "   ✗ FAILED: entryCSN attribute not found!"
fi

echo ""
echo "4. Testing with wildcard + entryCSN..."
ldapsearch -x -H ldap://localhost:1389 \
    -D "cn=manager,dc=example,dc=com" -w "secret" \
    -b "ou=People,dc=example,dc=com" \
    -s one \
    "(uid=user0001)" \
    "*" "entryCSN" 2>&1 | grep -E "(dn:|uid:|entryCSN:)" | head -5

echo ""
echo "5. Stopping provider..."
kill $PROVIDER_PID 2>/dev/null
wait $PROVIDER_PID 2>/dev/null

echo ""
echo "=== Test Complete ==="

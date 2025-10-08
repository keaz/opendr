#!/bin/bash

echo "=== Updating Provider Binary and Restarting ==="
echo ""

# Stop the provider
echo "1. Stopping provider (if running)..."
pkill -f "svr_1/opendr" || echo "   (no provider process found)"
sleep 2

# Copy new binary to svr_1
echo "2. Copying new binary to svr_1..."
cp target/release/opendr svr_1/
cp target/release/opendr-setup svr_1/
echo "   ✓ Binaries copied"

# Also copy to svr_2 if it exists
if [ -d "svr_2" ]; then
    echo "3. Copying new binary to svr_2..."
    cp target/release/opendr svr_2/
    cp target/release/opendr-setup svr_2/
    echo "   ✓ Binaries copied to svr_2"
fi

echo ""
echo "4. Binary timestamps:"
stat -f "   %Sm %N" svr_1/opendr target/release/opendr

echo ""
echo "5. Starting provider..."
cd svr_1
./opendr > ../provider.log 2>&1 &
PROVIDER_PID=$!
cd ..

sleep 3

if ps -p $PROVIDER_PID > /dev/null; then
    echo "   ✓ Provider started (PID: $PROVIDER_PID)"
    echo ""
    echo "6. Testing if operational attributes are now returned..."
    sleep 2
    
    # Try to search for entryCSN (using any auth that works)
    ldapsearch -x -H ldap://localhost:1389 \
        -b "dc=example,dc=com" \
        -s base \
        "(objectClass=*)" \
        dn entryCSN 2>&1 | head -10
    
else
    echo "   ✗ Provider failed to start!"
    tail -20 provider.log
fi

echo ""
echo "=== Update Complete ==="
echo ""
echo "Now you can:"
echo "  1. Clean consumer state: rm -rf ./data/replication_state/"
echo "  2. Start consumer: ./target/release/opendr"
echo "  3. Watch for: 'Including new entry' messages (should see entryCSN values)"

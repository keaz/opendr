#!/bin/bash
#
# Listener-based replication smoke test.
#
# This wrapper runs the maintained demo script, which starts two real OpenDR
# instances from separate working directories and verifies live LDAP
# replication through the listener path.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

exec "$SCRIPT_DIR/demo_replication.sh" "$@"

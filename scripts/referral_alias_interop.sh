#!/usr/bin/env bash
set -euo pipefail

# Manual interoperability checks for LDAP referrals, aliases, and ManageDsaIT.
#
# Required fixture assumptions:
# - OPENDR_LDAP_URL points to a running OpenDR server.
# - OPENDR_BASE_DN contains the naming context.
# - OPENDR_REFERRAL_DN points to a referral object with at least one ref URL.
# - OPENDR_ALIAS_DN points to an alias object.
#
# Optional authentication:
# - OPENDR_BIND_DN and OPENDR_BIND_PASSWORD can be set for simple bind.

LDAP_URL="${OPENDR_LDAP_URL:-ldap://127.0.0.1:1389}"
BASE_DN="${OPENDR_BASE_DN:-dc=example,dc=org}"
REFERRAL_DN="${OPENDR_REFERRAL_DN:-ou=remote,dc=example,dc=org}"
ALIAS_DN="${OPENDR_ALIAS_DN:-cn=alias,dc=example,dc=org}"
BIND_ARGS=(-x)

if [[ -n "${OPENDR_BIND_DN:-}" ]]; then
  BIND_ARGS+=(-D "$OPENDR_BIND_DN" -w "${OPENDR_BIND_PASSWORD:-}")
fi

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 127
  fi
}

require_command ldapsearch

echo "== ldapsearch: base referral returns configured RFC 4516 URL(s)"
ldapsearch "${BIND_ARGS[@]}" -H "$LDAP_URL" -b "$REFERRAL_DN" -s base "(objectClass=*)" ref

echo "== ldapsearch: ManageDsaIT treats referral object as an entry"
ldapsearch "${BIND_ARGS[@]}" -H "$LDAP_URL" -e manageDSAit -b "$REFERRAL_DN" -s base "(objectClass=*)" ref objectClass

echo "== ldapsearch: derefInSearching resolves alias candidates"
ldapsearch "${BIND_ARGS[@]}" -H "$LDAP_URL" -a search -b "$BASE_DN" -s sub "(objectClass=*)" dn

echo "== ldapsearch: derefFindingBaseObj resolves an alias search base"
ldapsearch "${BIND_ARGS[@]}" -H "$LDAP_URL" -a find -b "$ALIAS_DN" -s base "(objectClass=*)" dn

if command -v python3 >/dev/null 2>&1; then
  echo "== python ldap3: SDK client can bind and read Root DSE"
  python3 - "$LDAP_URL" "$BASE_DN" <<'PY'
import os
import sys
from urllib.parse import urlparse

try:
    from ldap3 import ALL, Connection, Server
except ImportError:
    print("python ldap3 is not installed; skipping SDK check")
    raise SystemExit(0)

url, base_dn = sys.argv[1], sys.argv[2]
parsed = urlparse(url)
host = parsed.hostname or url
port = parsed.port
use_ssl = parsed.scheme == "ldaps"
server = Server(host, port=port, use_ssl=use_ssl, get_info=ALL)
bind_dn = os.environ.get("OPENDR_BIND_DN")
bind_password = os.environ.get("OPENDR_BIND_PASSWORD")
if bind_dn:
    conn = Connection(server, user=bind_dn, password=bind_password, auto_bind=True)
else:
    conn = Connection(server, auto_bind=True)
conn.search("", "(objectClass=*)", search_scope="BASE", attributes=["supportedControl"])
assert conn.entries, "Root DSE search returned no entries"
conn.search(base_dn, "(objectClass=*)", attributes=["objectClass"], size_limit=1)
print("ldap3 checks completed")
conn.unbind()
PY
fi

echo "referral and alias interoperability checks completed"

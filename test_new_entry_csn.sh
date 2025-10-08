#!/bin/bash

echo "=== Testing if new entries get entryCSN ==="
echo ""

# Get provider credentials
ADMIN_DN="cn=manager,dc=example,dc=com"
ADMIN_PW=$(grep "root_password" svr_1/config/server.toml | cut -d'"' -f2)

echo "1. Adding a test entry..."
ldapadd -x -H ldap://localhost:1389 -D "$ADMIN_DN" -w "secret" <<EOF
dn: uid=test_csn_user,ou=People,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: top
uid: test_csn_user
cn: Test CSN User
sn: User
mail: test_csn@example.com
userPassword: testpass
EOF

echo ""
echo "2. Searching for the new entry with entryCSN..."
ldapsearch -x -H ldap://localhost:1389 \
    -D "$ADMIN_DN" -w "secret" \
    -b "ou=People,dc=example,dc=com" \
    "(uid=test_csn_user)" \
    dn entryCSN uid

echo ""
echo "3. Searching existing user0000 with entryCSN..."
ldapsearch -x -H ldap://localhost:1389 \
    -D "$ADMIN_DN" -w "secret" \
    -b "ou=People,dc=example,dc=com" \
    "(uid=user0000)" \
    dn entryCSN uid

echo ""
echo "=== Test Complete ==="

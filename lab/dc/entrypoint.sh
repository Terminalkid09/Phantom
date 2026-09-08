#!/bin/bash
set -e

REALM="${PHANTOM_AD_REALM:-CORP.LOCAL}"
DOMAIN="${PHANTOM_AD_DOMAIN:-CORP}"
ADMIN_PASS="${PHANTOM_ADMIN_PASS:-Admin!2024}"

mkdir -p /var/lib/samba/private /var/lib/samba/sysvol /var/run/samba /var/log/samba

if [ ! -f /var/lib/samba/private/sam.ldb ]; then
    echo "[dc] provisioning domain ${REALM} (${DOMAIN})..."
    samba-tool domain provision \
        --server-role=dc \
        --use-rfc2307 \
        --dns-backend=SAMBA_INTERNAL \
        --realm="${REALM}" \
        --domain="${DOMAIN}" \
        --adminpass="${ADMIN_PASS}" \
        --host-name=dc \
        --host-ip=172.28.0.30
fi

# krb5.conf pointing at the DC itself
printf '%s\n' \
    "[libdefaults]" \
    "    default_realm = ${REALM}" \
    "    dns_lookup_kdc = false" \
    "    dns_lookup_realm = false" \
    "[realms]" \
    "    ${REALM} = {" \
    "        kdc = 172.28.0.30" \
    "        admin_server = 172.28.0.30" \
    "    }" \
    "[domain_realm]" \
    "    .corp.local = ${REALM}" \
    "    corp.local = ${REALM}" \
    > /etc/krb5.conf

# A few realistic AD objects for the attacks:
#   svc_sql  -> SPN set (kerberoast target)
#   norep    -> DONT_REQUIRE_PREAUTH (AS-REP roast target)
#   adadmin  -> domain admin used for DCSync-style tests
if ! samba-tool user list 2>/dev/null | grep -q svc_sql; then
    samba-tool user create svc_sql 'Svc!2024Strong' --given-name=SQL --surname=Service
    samba-tool spn add 'HTTP/svc-sql.corp.local' svc_sql
    # No given/surname on purpose: samba then uses the username as CN, so the
    # ldbmodify DN below (CN=norep) matches the record.
    samba-tool user create norep 'NoRep!2024Strong'
    # AS-REP: disable preauth (DONT_REQUIRE_PREAUTH 0x400000 + normal 0x200)
    ldbmodify -H /var/lib/samba/private/sam.ldb <<'LDB'
dn: CN=norep,CN=Users,DC=corp,DC=local
changetype: modify
replace: userAccountControl
userAccountControl: 4194816
LDB
    samba-tool user create adadmin 'DAdmin!2024Strong' --given-name=AD --surname=Admin
    samba-tool group addmembers "Domain Admins" adadmin
fi

echo "[dc] starting samba..."
exec samba -i --no-process-group
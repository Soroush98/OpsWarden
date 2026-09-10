#!/bin/bash
# First boot: build the directory from LDIF, load the sudo schema, wire TLS, seed users/groups/
# sudo rules. Later boots: just run slapd against the persisted database.
set -euo pipefail

BASE_DN="${LDAP_BASE_DN:-dc=opswarden,dc=internal}"
DOMAIN="${LDAP_DOMAIN:-opswarden.internal}"
ORG="${LDAP_ORG:-OpsWarden Lab}"
ADMIN_DN="cn=admin,${BASE_DN}"
TLS_DIR="${LDAP_TLS_DIR:-/container/tls}"
SEED="/opt/openldap/seed"

: "${LDAP_ADMIN_PASSWORD:?LDAP_ADMIN_PASSWORD is required}"
: "${LDAP_SSSD_BIND_PASSWORD:?LDAP_SSSD_BIND_PASSWORD is required}"
: "${LDAP_SEED_USER_PASSWORD:?LDAP_SEED_USER_PASSWORD is required}"
: "${LDAP_SVC_BACKUP_PASSWORD:?LDAP_SVC_BACKUP_PASSWORD is required}"

hash() { slappasswd -h '{SSHA}' -s "$1"; }

start_bg() { pkill slapd 2>/dev/null || true; sleep 1; slapd -h "ldapi:///" -u openldap -g openldap; for i in $(seq 1 30); do ldapsearch -Q -Y EXTERNAL -H ldapi:/// -b "" -s base >/dev/null 2>&1 && return 0; sleep 1; done; echo "slapd did not come up" >&2; return 1; }
stop_bg() { local pid; pid=$(pidof slapd || true); [ -n "$pid" ] && { kill "$pid"; for i in $(seq 1 15); do pidof slapd >/dev/null || break; sleep 1; done; }; }

SENTINEL="/var/lib/ldap/.opswarden-seeded"
if [ ! -f "$SENTINEL" ]; then
  echo ">> first boot: initialising directory ${BASE_DN}"
  rm -rf /etc/ldap/slapd.d/* /var/lib/ldap/* 2>/dev/null || true

  debconf-set-selections <<SEL
slapd slapd/no_configuration boolean false
slapd slapd/domain string ${DOMAIN}
slapd shared/organization string ${ORG}
slapd slapd/password1 password ${LDAP_ADMIN_PASSWORD}
slapd slapd/password2 password ${LDAP_ADMIN_PASSWORD}
slapd slapd/backend select MDB
slapd slapd/purge_database boolean true
slapd slapd/move_old_database boolean true
slapd slapd/allow_ldap_v2 boolean false
SEL
  dpkg-reconfigure -f noninteractive slapd

  start_bg

  echo ">> loading sudo schema"
  ldapadd -Q -Y EXTERNAL -H ldapi:/// -f /opt/openldap/schema/sudo.ldif

  if [ -f "${TLS_DIR}/tls.crt" ] && [ -f "${TLS_DIR}/tls.key" ] && [ -f "${TLS_DIR}/ca.crt" ]; then
    echo ">> configuring TLS"
    ldapmodify -Q -Y EXTERNAL -H ldapi:/// <<TLS
dn: cn=config
changetype: modify
replace: olcTLSCACertificateFile
olcTLSCACertificateFile: ${TLS_DIR}/ca.crt
-
replace: olcTLSCertificateFile
olcTLSCertificateFile: ${TLS_DIR}/tls.crt
-
replace: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: ${TLS_DIR}/tls.key
TLS
  else
    echo ">> TLS material not found in ${TLS_DIR}; starting without LDAPS (dev only)"
  fi

  echo ">> seeding directory"
  tmp=$(mktemp -d)
  SSSD_BIND_HASH=$(hash "$LDAP_SSSD_BIND_PASSWORD")
  SEED_USER_HASH=$(hash "$LDAP_SEED_USER_PASSWORD")
  SVC_BACKUP_HASH=$(hash "$LDAP_SVC_BACKUP_PASSWORD")
  for f in 00-base 10-groups 20-people 30-services 40-sudoers; do
    sed -e "s|@@BASE_DN@@|${BASE_DN}|g" \
        -e "s|@@SSSD_BIND_HASH@@|${SSSD_BIND_HASH}|g" \
        -e "s|@@SEED_USER_HASH@@|${SEED_USER_HASH}|g" \
        -e "s|@@SVC_BACKUP_HASH@@|${SVC_BACKUP_HASH}|g" \
        "${SEED}/${f}.ldif" > "${tmp}/${f}.ldif"
    ldapadd -x -D "$ADMIN_DN" -w "$LDAP_ADMIN_PASSWORD" -H ldapi:/// -f "${tmp}/${f}.ldif"
  done
  rm -rf "$tmp"

  stop_bg
  touch "$SENTINEL"
  echo ">> initialisation complete"
fi

echo ">> starting slapd (foreground)"
exec slapd -h "ldap:/// ldaps:/// ldapi:///" -u openldap -g openldap -d 256

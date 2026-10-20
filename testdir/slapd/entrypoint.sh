#!/bin/sh
# Build cn=config and the data from scratch on first start, then run slapd.
set -eu
if [ ! -f /var/lib/ldap/.seeded ]; then
  rm -rf /etc/ldap/slapd.d/* /var/lib/ldap/*
  mkdir -p /etc/ldap/slapd.d /var/lib/ldap
  rootpw=$(slappasswd -s admin-secret)
  sed "s|@ROOTPW@|$rootpw|" /seed/config.ldif > /tmp/config.ldif
  slapadd -n0 -F /etc/ldap/slapd.d -l /tmp/config.ldif
  /seed/gen-data.sh > /tmp/data.ldif
  slapadd -n1 -F /etc/ldap/slapd.d -l /tmp/data.ldif
  touch /var/lib/ldap/.seeded
fi
mkdir -p /run/slapd
exec slapd -d "${SLAPD_DEBUG:-0}" -h "ldap:/// ldaps:/// ldapi:///" -F /etc/ldap/slapd.d

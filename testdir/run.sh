#!/usr/bin/env bash
# up | down | reset | logs | profiles
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"
case "${1:-up}" in
  up)
    ./make-certs.sh
    docker compose up -d --build --wait 2>/dev/null || docker compose up -d --build
    for _ in $(seq 1 150); do
      LDAPTLS_CACERT=certs/ca.pem ldapsearch -x -H ldaps://127.0.0.1:6360 -b "" -s base >/dev/null 2>&1 && { echo "slapd ready"; exit 0; }
      sleep 0.2
    done
    echo "slapd did not become ready; see: $0 logs" >&2; exit 1 ;;
  down) docker compose down -v ;;
  reset) docker compose down -v && "$here/run.sh" up ;;
  logs) docker compose logs --tail=100 ;;
  profiles)
    # Test profiles in an isolated config dir; use with: export LDAPM_CONFIG_DIR=...
    cfg="${LDAPM_CONFIG_DIR:-$here/.config}"
    export LDAPM_CONFIG_DIR="$cfg"
    bin="${LDAPM_BIN:-$here/../target/debug/ldapm}"
    rm -rf "$cfg"
    common=(--ca certs/ca.pem --bind-dn cn=ldapm-admin,dc=example,dc=org --base-dn dc=example,dc=org)
    "$bin" profile add test --host localhost --port 6360 "${common[@]}" --default
    "$bin" profile add test-starttls --host localhost --port 3890 --starttls "${common[@]}"
    ssh-keyscan -p 2222 127.0.0.1 2>/dev/null > certs/known_hosts
    "$bin" profile add test-tunnel --host ldap.test --port 636 "${common[@]}" \
      --ssh tunnel@127.0.0.1 --ssh-port 2222 --ssh-identity "$here/certs/bastion_ed25519" \
      --ssh-known-hosts "$here/certs/known_hosts"
    echo "export LDAPM_CONFIG_DIR=$cfg" ;;
  *) echo "usage: $0 up|down|reset|logs|profiles" >&2; exit 1 ;;
esac

#!/usr/bin/env bash
# Test PKI: a CA, a server cert for localhost/ldap.test/127.0.0.1, an
# unrelated CA for negative TLS tests, and an SSH key for the bastion.
set -euo pipefail
dir="$(cd "$(dirname "$0")" && pwd)/certs"
mkdir -p "$dir"; cd "$dir"
[ -f ca.pem ] && { echo "certs exist in $dir"; exit 0; }

openssl req -x509 -newkey rsa:3072 -nodes -days 3650 -subj "/CN=ldapm Test CA" \
  -keyout ca.key -out ca.pem \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

openssl req -newkey rsa:2048 -nodes -subj "/CN=ldap.test" -keyout server.key -out server.csr 2>/dev/null
cat > server.ext <<EXT
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:ldap.test,DNS:localhost,IP:127.0.0.1
EXT
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 825 \
  -extfile server.ext -out server.pem 2>/dev/null

openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=Unrelated CA" \
  -keyout other-ca.key -out other-ca.pem \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" 2>/dev/null

ssh-keygen -q -t ed25519 -N "" -C ldapm-test -f bastion_ed25519
chmod 600 bastion_ed25519 *.key
rm -f server.csr server.ext ca.srl
echo "certs written to $dir"

#!/bin/bash

set -xeuo pipefail

# Create a CA, then sign three certificates for the server, bridge, and client respectively.
mkdir -p creds/
pushd creds || exit

cat > openssl.cnf << EOF
[client_auth_ext]
keyUsage = digitalSignature
extendedKeyUsage = clientAuth,serverAuth
EOF

openssl genrsa -out ca-key.pem 2048
openssl genrsa -out server-key.pem 2048
openssl genrsa -out bridge-key.pem 2048
openssl genrsa -out client-key.pem 2048

openssl req -x509 -new -nodes -key ca-key.pem -days 3650 -sha256 -extensions v3_ca -subj "/CN=Sigul CA" -out ca-cert.pem
openssl req -config ./openssl.cnf -new -sha256 -extensions client_auth_ext -subj "/CN=sigul-server" -key server-key.pem -out server-cert.csr
openssl req -config ./openssl.cnf -new -sha256 -extensions client_auth_ext -subj "/CN=sigul-bridge" -key bridge-key.pem -out bridge-cert.csr
openssl req -config ./openssl.cnf -new -sha256 -extensions client_auth_ext -subj "/CN=sigul-client" -key client-key.pem -out client-cert.csr

openssl x509 -req -in server-cert.csr -extfile ./openssl.cnf -extensions client_auth_ext -CAkey ca-key.pem -CA ca-cert.pem -days 3650 -sha256 -out server-cert.pem
openssl x509 -req -in bridge-cert.csr -extfile ./openssl.cnf -extensions client_auth_ext -CAkey ca-key.pem -CA ca-cert.pem -days 3650 -sha256 -out bridge-cert.pem
openssl x509 -req -in client-cert.csr -extfile ./openssl.cnf -extensions client_auth_ext -CAkey ca-key.pem -CA ca-cert.pem -days 3650 -sha256 -out client-cert.pem

rm openssl.cnf ca-key.pem *.csr
mv bridge-cert.pem sigul.bridge.certificate.pem
mv bridge-key.pem sigul.bridge.private_key.pem
mv server-cert.pem sigul.server.certificate.pem
mv server-key.pem sigul.server.private_key.pem
mv client-cert.pem sigul.client.certificate.pem
mv client-key.pem sigul.client.private_key.pem
mv ca-cert.pem sigul.ca.certificate.pem

popd || exit

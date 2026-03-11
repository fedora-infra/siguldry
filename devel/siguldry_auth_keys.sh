#!/bin/bash

# This script accepts three or more arguments: the server commonName, the bridge commonName, and one
# or more client commonNames. For testing purposes, "sigul-server", "localhost", and "sigul-client"
# are recommended.

set -xeuo pipefail

SERVER_CN="${1}"
BRIDGE_CN="${2}"
if [[ $# -lt 3 ]]; then
    CLIENT_CNS=("")
else
    CLIENT_CNS=("${@:3}")
fi

# Create a CA, then sign three certificates for the server, bridge, and client respectively.
mkdir -p creds/
pushd creds

# Create a CA used to sign the client certificates as well as the server and bridge server certificates
openssl req -x509 -new -nodes -sha256 \
    -days 3650 \
    -extensions v3_ca \
    -subj "/CN=Siguldry CA" \
    -newkey rsa:2048 \
    -keyout siguldry.ca.private_key.pem \
    -out siguldry.ca_certificate.pem

# Create and sign a server certificate
openssl req -new -nodes -sha256 \
    -addext "subjectAltName = DNS:$SERVER_CN" \
    -addext "extendedKeyUsage = clientAuth,serverAuth" \
    -subj "/CN=$SERVER_CN" \
    -newkey rsa:2048 \
    -keyout siguldry.server.private_key.pem \
    -out server-cert.csr
openssl x509 -req -in server-cert.csr \
    -CAkey siguldry.ca.private_key.pem \
    -CA siguldry.ca_certificate.pem \
    -copy_extensions copyall \
    -days 3650 \
    -sha256 \
    -out siguldry.server.certificate.pem

# Create and sign a bridge certificate
openssl req -new -nodes -sha256 \
    -addext "subjectAltName = DNS:$BRIDGE_CN" \
    -addext "extendedKeyUsage = serverAuth" \
    -subj "/CN=$BRIDGE_CN" \
    -newkey rsa:2048 \
    -keyout siguldry.bridge.private_key.pem \
    -out bridge-cert.csr
openssl x509 -req -in bridge-cert.csr \
    -CAkey siguldry.ca.private_key.pem \
    -CA siguldry.ca_certificate.pem \
    -copy_extensions copyall \
    -days 3650 \
    -sha256 \
    -out siguldry.bridge.certificate.pem

# Create and sign client certificates
for CLIENT_CN in "${CLIENT_CNS[@]}"; do
    openssl req -new -nodes -sha256 \
        -addext "extendedKeyUsage = clientAuth" \
        -subj "/CN=$CLIENT_CN" \
        -newkey rsa:2048 \
        -keyout "siguldry.$CLIENT_CN.private_key.pem" \
        -out "siguldry.$CLIENT_CN.csr"
    openssl x509 -req -in "siguldry.$CLIENT_CN.csr" \
        -CAkey siguldry.ca.private_key.pem \
        -CA siguldry.ca_certificate.pem \
        -copy_extensions copyall \
        -days 3650 \
        -sha256 \
        -out "siguldry.$CLIENT_CN.certificate.pem"
done

rm -- siguldry.ca.private_key.pem *.csr

openssl verify -CAfile ./siguldry.ca_certificate.pem siguldry.server.certificate.pem
openssl verify -CAfile ./siguldry.ca_certificate.pem siguldry.bridge.certificate.pem
for CLIENT_CN in "${CLIENT_CNS[@]}"; do
    openssl verify -CAfile ./siguldry.ca_certificate.pem "siguldry.$CLIENT_CN.certificate.pem"
done

popd

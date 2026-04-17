#!/bin/bash

# If you already have a way to issue TLS certificates, it is recommended that
# you use that flow.
# 
# For reference, the following is how to generate a complete set of
# certificates.  Note that for production environments, care should be taken to
# encrypt and protect the private keys generated. The recommended approach is
# to use systemd-creds.
#
# This script accepts three or more arguments: the server commonName, the
# bridge commonName, and one or more client commonNames.
#
# For testing purposes, when all three services run on a single host,
# "siguldry-server", "localhost", and "siguldry-client" are recommended.

set -xeuo pipefail

SERVER_CN="${1}"
BRIDGE_CN="${2}"
if [[ $# -lt 3 ]]; then
    CLIENT_CNS=("")
else
    CLIENT_CNS=("${@:3}")
fi

mkdir -p creds/
pushd creds

# First, create a certificate authority which is used to sign all our certificates.
openssl req -x509 -new -nodes -sha256 \
    -days 3650 \
    -extensions v3_ca \
    -subj "/CN=Siguldry CA" \
    -newkey rsa:2048 \
    -keyout siguldry.ca.private_key.pem \
    -out siguldry.ca_certificate.pem

# Create and sign a server certificate
#
# The server uses its certificate both as a client connecting to the bridge, and
# as a server the client connects to via the bridge. The certificate for the
# server must have the `clientAuth` _and_ `serverAuth` extended key usage
# extensions.
# 
# Since the client only communicates through the bridge, and because the server
# initiates the connection to the bridge, the server's name does not need to
# resolve, but it does need to match what the client has been configured to
# accept.
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
#
# The bridge accepts connections from the server and the client. It needs the
# `serverAuth` extended key usage extension, and its name must resolve for both
# the client and server.
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
#
# Each client needs a certificate to authenticate with. The common name of the
# certificate must match the username that we create on the Siguldry server
# later.
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

#!/bin/bash

set -xeuo pipefail

# OpenSSL gets touchy about the CA generated via certutil, this is somehow easier
# than figuring out the right arguments to set all the proper certificate extensions.
#
# Generate a new NSS database and populate it with a set of keys for the server, bridge, and client.
# Two sets of keys for the bridge/server exist: one for using localhost and one for using the "sigul-bridge"
# and "sigul-server" hostnames.

NSS_DIR=$1

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

# Import everything into an NSS database
echo "my-nss-password" > nss_db_password
echo "not so random seed data for the NSS db" > seed_file
certutil -z ./seed_file -d "$NSS_DIR" -N -f nss_db_password
openssl pkcs12 -export -out sigul-ca.p12 -in ca-cert.pem -inkey ca-key.pem -name sigul-ca -passout file:./nss_db_password
openssl pkcs12 -export -out server.p12 -in server-cert.pem -inkey server-key.pem -name sigul-server-gh -passout file:./nss_db_password
openssl pkcs12 -export -out bridge.p12 -in bridge-cert.pem -inkey bridge-key.pem -name sigul-bridge-gh -passout file:./nss_db_password
openssl pkcs12 -export -out client.p12 -in client-cert.pem -inkey client-key.pem -name sigul-client -passout file:./nss_db_password

pk12util -i sigul-ca.p12 -k ./nss_db_password -w ./nss_db_password -d "$NSS_DIR"
certutil -z ./seed_file -d "$NSS_DIR" -f nss_db_password -M -n sigul-ca -t CT,,

# Convenient for local development where "sigul-server" and "sigul-bridge" don't resolve to your sigul services.
certutil -z ./seed_file -d "$NSS_DIR" -S -f nss_db_password -m 1 -n sigul-bridge-local -s 'CN=localhost' -c sigul-ca --extKeyUsage serverAuth,clientAuth -t u,, -u V -v 120
certutil -z ./seed_file -d "$NSS_DIR" -S -f nss_db_password -m 2 -n sigul-server-local -s 'CN=localhost' -c sigul-ca --extKeyUsage serverAuth,clientAuth -t u,, -u V -v 120

# Used for GitHub
certutil -z ./seed_file -d "$NSS_DIR" -S -f nss_db_password -m 3 -n sigul-bridge-gh -s 'CN=sigul-bridge' -c sigul-ca --extKeyUsage serverAuth,clientAuth -t u,, -u V -v 120
certutil -z ./seed_file -d "$NSS_DIR" -S -f nss_db_password -m 4 -n sigul-server-gh -s 'CN=sigul-server' -c sigul-ca --extKeyUsage serverAuth,clientAuth -t u,, -u V -v 120

# Tidy things up
rm ./*.p12
rm ./*.csr
rm openssl.cnf seed_file ca-key.pem bridge-cert.pem bridge-key.pem server-cert.pem server-key.pem nss_db_password
mv client-cert.pem sigul.client.certificate.pem
mv client-key.pem sigul.client.private_key.pem
mv ca-cert.pem sigul.ca_certificate.pem

popd || exit

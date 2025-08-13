#!/bin/bash

# Sets up a softhsm2 PKCS11 token for the CI image; this is designed to work with
# an EL9 system and does _not_ work with modern versions of openssl on Fedora, as
# the openssl engine API is disabled. Refer to local_hsm_test.sh for a more
# complete script which used the provider API, that works on Fedora (and EL10+)
# and demonstrates how to sign via pesign directly and via openssl dgst.
#
# In an EL9 environment:
#
# $ dnf install epel-release  # for sbsigntools
# $ dnf install softhsm opensc nss-tools openssl p11-kit openssl-pkcs11 sbsigntools

set -xeuo pipefail

HSM_PIN="abc123def"
HSM_SO_PIN="fed321cba"
TOKEN_LABEL="Sigul Token 0"

. /etc/os-release
case "$ID" in
    ubuntu)  HSM_MODULE="/usr/lib/softhsm/libsofthsm2.so" ;;
    *) HSM_MODULE="/usr/lib64/softhsm/libsofthsm.so" ;;
esac

mkdir -p creds/
pushd creds

# Initialize a token slot in softhsm
softhsm2-util \
	--init-token --slot 0 --label "$TOKEN_LABEL" \
	--pin "$HSM_PIN" --so-pin "$HSM_SO_PIN"
# Make a keypair for a CA and for code signing
pkcs11-tool --module "$HSM_MODULE" \
	--login --pin "$HSM_PIN" \
	--keypairgen --label="Secure Boot CA" \
	--key-type rsa:2048 --usage-sig --id 1
pkcs11-tool --module "$HSM_MODULE" \
	--login --pin "$HSM_PIN" \
	--keypairgen --label="Secure Boot Code Signing" \
	--key-type rsa:2048 --usage-sig --id 2

SLOT_URI=$(p11-kit list-modules | grep "^\s*uri:.*token=Sigul" | awk '{ print $2 }')
SIGNING_KEY_URI="${SLOT_URI};object=Secure%20Boot%20Code%20Signing;type=private"

# Generate certificates for the above key pairs
cat > openssl.cnf << EOF
[code_signing_exts]
keyUsage = digitalSignature
extendedKeyUsage = codeSigning
EOF
printf "%s\n" "$HSM_PIN" > hsm_pin
openssl req -passin file:./hsm_pin -new -x509 -days 3650 -sha256 -extensions v3_ca \
	-subj "/CN=Secure Boot CA" -engine pkcs11 -keyform engine \
	-key "${SLOT_URI};object=Secure%20Boot%20CA;type=private" \
	-out secure-boot-ca-cert.pem
openssl req -passin file:./hsm_pin -config ./openssl.cnf -new -sha256 -extensions code_signing_exts \
	-subj "/CN=Secure Boot Code Signing" -engine pkcs11 -keyform engine \
	-key "${SLOT_URI};object=Secure%20Boot%20Code%20Signing;type=private" \
	-out secure-boot-code-signing.csr
openssl x509 -passin file:./hsm_pin -req -engine pkcs11 -CAkeyform engine \
	-in secure-boot-code-signing.csr \
	-extfile openssl.cnf -extensions code_signing_exts \
	-CAkey "${SLOT_URI};object=Secure%20Boot%20CA;type=private" \
	-CA ./secure-boot-ca-cert.pem -days 365 -sha256 \
	-out secure-boot-code-signing-cert.pem

# Do they seem reasonable?
openssl verify -CAfile secure-boot-ca-cert.pem secure-boot-ca-cert.pem
openssl verify -CAfile secure-boot-ca-cert.pem secure-boot-code-signing-cert.pem

# Write the certificates to the token
pkcs11-tool --module "$HSM_MODULE" \
	--login --pin "$HSM_PIN" \
	--write-object secure-boot-ca-cert.pem \
	--type cert --label "Secure Boot CA Certificate" --id 1
pkcs11-tool --module "$HSM_MODULE" \
	--login --pin "$HSM_PIN" \
	--write-object secure-boot-code-signing-cert.pem \
	--type cert --label "Secure Boot Code Signing Certificate" --id 2

# The sigul user needs to be able to own the token
chown -R sigul:sigul /var/lib/softhsm/

echo "my-signing-password" > sigul.signing-key-passphrase
sigul_server_add_pkcs11_token --initial-key-admin sigul-client \
	--key-uri "${SIGNING_KEY_URI}" \
	--key-name "Sigul HSM Key" \
	--token-pin-file ./hsm_pin \
	--passphrase-file ./sigul.signing-key-passphrase

rm ./*.csr
rm ./hsm_pin
rm ./openssl.cnf
popd

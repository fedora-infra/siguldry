#!/bin/bash

# Create a new softhsm2 token, create some keys and certificates within the token
# and interact with them via NSS and openssl.
#
# In a Fedora 41 environment:
#
# $ dnf install softhsm opensc nss-tools openssl p11-kit pkcs11-provider sbsigntools
#
# Example:
#   $ pushd sample-uefi && cargo build && popd
#   $ ./devel/local_hsm_test.sh target/x86_64-unknown-uefi/debug/sample-uefi.efi

set -xeuo pipefail

UNSIGNED_EFI=$1

BASE_NAME=$(basename "$UNSIGNED_EFI")
TMPDIR=$(mktemp -d)
cp "$UNSIGNED_EFI" "$TMPDIR/$BASE_NAME"
UNSIGNED_EFI="$TMPDIR/$BASE_NAME"
pushd "$TMPDIR"

mkdir -p softhsm2/tokens/
cat > softhsm2/softhsm2.conf << EOF
# SoftHSM v2 configuration file
directories.tokendir = $PWD/softhsm2/tokens/
objectstore.backend = file
# ERROR, WARNING, INFO, DEBUG
log.level = INFO
# If CKF_REMOVABLE_DEVICE flag should be set
slots.removable = false
# Enable and disable PKCS#11 mechanisms using slots.mechanisms.
slots.mechanisms = ALL
# If the library should reset the state on fork
library.reset_on_fork = false
EOF
export SOFTHSM2_CONF="$PWD/softhsm2/softhsm2.conf"

HSM_PIN="abc123def"
HSM_SO_PIN="fed321cba"
NSS_DB_PASSWORD="secret"
TOKEN_LABEL="Sigul Token 0"

# Initialize a token slot in softhsm
softhsm2-util \
	--init-token --slot 0 --label "$TOKEN_LABEL" \
	--pin "$HSM_PIN" --so-pin "$HSM_SO_PIN"
SLOT_URI=$(p11-kit list-modules | grep "^\s*uri:.*token=Sigul" | awk '{ print $2 }')
# Make a keypair for a CA and for code signing
pkcs11-tool --module /usr/lib64/softhsm/libsofthsm.so \
	--login --pin "$HSM_PIN" \
	--keypairgen --label="Secure Boot CA" \
	--key-type rsa:2048 --usage-sig --id 1
pkcs11-tool --module /usr/lib64/softhsm/libsofthsm.so \
	--login --pin "$HSM_PIN" \
	--keypairgen --label="Secure Boot Code Signing" \
	--key-type rsa:2048 --usage-sig --id 2

# Generate certificates for the above key pairs
cat > openssl.cnf << EOF
[code_signing_exts]
keyUsage = digitalSignature
extendedKeyUsage = codeSigning
EOF
printf "%s\n" "$HSM_PIN" > hsm_pin
openssl req -passin file:./hsm_pin -new -x509 -days 3650 -sha256 -extensions v3_ca \
	-subj "/CN=Secure Boot CA" -provider pkcs11 \
	-key "${SLOT_URI};object=Secure%20Boot%20CA;type=private" \
	-out secure-boot-ca-cert.pem
openssl req -passin file:./hsm_pin -config ./openssl.cnf -new -sha256 -extensions code_signing_exts \
	-subj "/CN=Secure Boot Code Signing" -provider pkcs11 \
	-key "${SLOT_URI};object=Secure%20Boot%20Code%20Signing;type=private" \
	-out secure-boot-code-signing.csr
openssl x509 -passin file:./hsm_pin -req -provider pkcs11 -in secure-boot-code-signing.csr \
	-extfile openssl.cnf -extensions code_signing_exts \
	-CAkey "${SLOT_URI};object=Secure%20Boot%20CA;type=private" \
	-CA ./secure-boot-ca-cert.pem -days 365 -sha256 \
	-out secure-boot-code-signing-cert.pem

# Do they seem reasonable?
openssl verify -CAfile secure-boot-ca-cert.pem secure-boot-ca-cert.pem
openssl verify -CAfile secure-boot-ca-cert.pem secure-boot-code-signing-cert.pem

# Write the certificates to the token
pkcs11-tool --module /usr/lib64/softhsm/libsofthsm.so \
	--login --pin "$HSM_PIN" \
	--write-object secure-boot-ca-cert.pem \
	--type cert --label "Secure Boot CA Certificate" --id 1
pkcs11-tool --module /usr/lib64/softhsm/libsofthsm.so \
	--login --pin "$HSM_PIN" \
	--write-object secure-boot-code-signing-cert.pem \
	--type cert --label "Secure Boot Code Signing Certificate" --id 2

mkdir nss
printf "%s\n" "$NSS_DB_PASSWORD" > nss_pwfile
certutil -d nss -N -f ./nss_pwfile
# It knows about the SoftHSM token via p11-kit
certutil -d nss -U
# It knows about the keys and certificates
certutil -d nss -h "$TOKEN_LABEL" -f ./hsm_pin -L
certutil -d nss -h "$TOKEN_LABEL" -f ./hsm_pin -K

# This works
pesign -i "$UNSIGNED_EFI" -E sample-uefi.sattrs.bin
openssl dgst -passin file:./hsm_pin -sha256 \
	-sign "${SLOT_URI};object=Secure%20Boot%20Code%20Signing;type=private" \
	-provider pkcs11 -out sample-uefi.sattrs.sig sample-uefi.sattrs.bin
certutil -d nss -A -f ./nss_pwfile -n secure-boot-code-signer -t ,,u -i secure-boot-code-signing-cert.pem
pesign -n nss -c "secure-boot-code-signer" \
	-R sample-uefi.sattrs.sig -I sample-uefi.sattrs.bin \
	--pinfile=./nss_pwfile \
	-i "$UNSIGNED_EFI" \
	-o signed.efi
sbverify --cert secure-boot-code-signing-cert.pem signed.efi
sbverify --cert secure-boot-ca-cert.pem signed.efi

# So does this
pesign -n nss \
	-t "Sigul Token 0" \
	-c "Secure Boot Code Signing Certificate" \
	--pinfile=./hsm_pin \
	-s \
	-i "$UNSIGNED_EFI" \
	-o signed2.efi
sbverify --cert secure-boot-code-signing-cert.pem signed2.efi
sbverify --cert secure-boot-ca-cert.pem signed2.efi

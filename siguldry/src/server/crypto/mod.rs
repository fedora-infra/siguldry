// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! All the cryptography-related operations are in these modules.
//!
//! Sequoia is used for GPG signatures and for the symmetric encryption of keys managed by Siguldry.
//! OpenSSL is used for other signatures.

use openssl::{
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    rsa::Rsa,
    symm::Cipher,
};
use sequoia_openpgp::{
    Profile,
    cert::{CertBuilder, CipherSuite},
    crypto::Password,
    packet,
    serialize::MarshalInto,
    types::KeyFlags,
};

use crate::{protocol::KeyAlgorithm, server::config::Pkcs11Binding};

pub mod binding;
pub mod signing;
pub mod token;

pub(crate) fn generate_password() -> anyhow::Result<Password> {
    let mut buf = [0; 128];
    openssl::rand::rand_bytes(buf.as_mut_slice())?;
    Ok(Password::from(openssl::base64::encode_block(&buf)))
}

pub fn create_encrypted_key(
    bindings: &[Pkcs11Binding],
    user_password: Password,
    algorithm: KeyAlgorithm,
) -> anyhow::Result<(String, Vec<u8>, String, String)> {
    let key_password = generate_password()?;
    let key = match algorithm {
        KeyAlgorithm::Rsa4K => PKey::from_rsa(Rsa::generate(4096)?)?,
        KeyAlgorithm::P256 => PKey::from_ec_key(EcKey::generate(
            EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?.as_ref(),
        )?)?,
    };
    let public_key_pem = String::from_utf8(key.public_key_to_pem()?)?;
    let private_key_pem = key_password.map(|key_password| {
        key.private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), key_password)
    })?;
    let private_key_pem = String::from_utf8(private_key_pem)?;
    let encrypted_password = binding::encrypt_key_password(bindings, user_password, key_password)?;
    let handle = format!(
        "{:X?}",
        openssl::hash::hash(MessageDigest::sha256(), &key.public_key_to_der()?)?
    );

    Ok((handle, encrypted_password, private_key_pem, public_key_pem))
}

/// A GPG key.
#[derive(Debug, Clone, PartialEq)]
pub struct GpgKey {
    cert: sequoia_openpgp::Cert,
    encrypted_password: Vec<u8>,
}

impl GpgKey {
    /// Create a new GPG key bound to the server.
    pub fn new<U: Into<packet::UserID>>(
        bindings: &[Pkcs11Binding],
        user_id: U,
        user_password: Password,
        profile: Profile,
        cipher: CipherSuite,
    ) -> anyhow::Result<GpgKey> {
        let key_password = generate_password()?;
        let encrypted_password =
            binding::encrypt_key_password(bindings, user_password.clone(), key_password.clone())?;
        let (cert, _signature) = CertBuilder::new()
            .set_profile(profile)?
            .set_cipher_suite(cipher)
            .add_userid(user_id)
            .set_primary_key_flags(KeyFlags::signing())
            .set_password(Some(key_password))
            .generate()?;

        Ok(GpgKey {
            cert,
            encrypted_password,
        })
    }

    /// Get the encrypted, ASCII-armored private key.
    pub fn armored_key(&self) -> anyhow::Result<Vec<u8>> {
        self.cert.as_tsk().armored().to_vec()
    }

    pub fn public_key(&self) -> anyhow::Result<String> {
        Ok(String::from_utf8(
            self.cert
                .clone()
                .strip_secret_key_material()
                .armored()
                .to_vec()?,
        )?)
    }

    /// Get the hex GPG fingerprint.
    pub fn fingerprint(&self) -> String {
        self.cert.fingerprint().to_hex()
    }

    pub fn encrypted_password(&self) -> &[u8] {
        &self.encrypted_password
    }
}

// Shared test setup functions.
#[cfg(test)]
pub(crate) mod test_utils {
    use std::process::Command;

    use anyhow::Context;
    use cryptoki::{
        context::{CInitializeArgs, CInitializeFlags, Pkcs11},
        mechanism::Mechanism,
        object::Attribute,
        session::UserType,
        types::AuthPin,
    };
    use sequoia_openpgp::crypto::Password;
    use tempfile::TempDir;

    use crate::server::config::Pkcs11Binding;

    #[derive(Debug)]
    pub(crate) struct Hsm {
        pub directory: TempDir,
        pub bindings: Vec<Pkcs11Binding>,
        pub user_pin: AuthPin,
    }

    // Set up a temporary PKCS#11 token.
    //
    // Note that tests using this must alter their environment which is not thread safe.
    // Thus, you will see failures if you don't use nextest.
    pub(crate) fn setup_hsm() -> anyhow::Result<Hsm> {
        let hsm_dir = TempDir::new()?;
        let hsm_config_path = hsm_dir.path().join("kryoptic.toml");
        let hsm_db_path = hsm_dir.path().join("kryoptic.sql");
        std::fs::write(
            &hsm_config_path,
            format!(
                "[[slots]]\nslot = 1\ndbtype = \"sqlite\"\ndbargs = \"{}\"",
                hsm_db_path.display()
            ),
        )?;
        let module_path = "/usr/lib64/pkcs11/libkryoptic_pkcs11.so";
        // SAFETY:
        // These tests are required to run with nextest, which starts a new process for each test.
        // Using set_var is only safe if no other code is interacting with the environment variables,
        // which should be true under nextest. Refer to
        // https://nexte.st/docs/configuration/env-vars/#altering-the-environment-within-tests to ensure
        // this remains the case with current versions of Rust.
        unsafe {
            std::env::set_var("KRYOPTIC_CONF", &hsm_config_path);
            std::env::set_var("PKCS11_PROVIDER_MODULE", module_path);
        };
        let pkcs11 = Pkcs11::new(module_path).context("Install the kryoptic PKCS#11 module")?;
        pkcs11
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .context("Failed to initialized kryoptic PKCS#11 module")?;
        let slot = pkcs11
            .get_slots_with_token()?
            .pop()
            .expect("no slot available");
        let so_pin = AuthPin::new("12345678".into());
        let user_pin_str = "secret-password";
        let user_pin = AuthPin::new(user_pin_str.into());
        pkcs11
            .init_token(slot, &so_pin, "test-token")
            .context("Failed to initialize token")?;
        pkcs11
            .open_rw_session(slot)
            .and_then(|session| {
                session.login(UserType::So, Some(&so_pin))?;
                session.init_pin(&user_pin)?;

                session.generate_key_pair(
                    &Mechanism::RsaPkcsKeyPairGen,
                    &[
                        Attribute::Id(vec![1]),
                        Attribute::Label(b"binding-key".to_vec()),
                        Attribute::Token(true),
                        Attribute::Private(false),
                        Attribute::Verify(true),
                        Attribute::Encrypt(true),
                        Attribute::ModulusBits(4096.into()),
                    ],
                    &[
                        Attribute::Id(vec![1]),
                        Attribute::Label(b"binding-key".to_vec()),
                        Attribute::Token(true),
                        Attribute::Private(true),
                        Attribute::Sensitive(true),
                        Attribute::Sign(true),
                        Attribute::Decrypt(true),
                    ],
                )?;

                // Annoyingly it doesn't seem possible to convert a named curve Nid to ASN.1 in
                // OpenSSL, so we manually create it from the OID for NIST P-256.
                let p256_oid = asn1::oid!(1, 2, 840, 10045, 3, 1, 7);
                let p256_oid_bytes = asn1::write_single(&p256_oid).unwrap();
                session.generate_key_pair(
                    &Mechanism::EccKeyPairGen,
                    &[
                        Attribute::Id(vec![2]),
                        Attribute::Label(b"ecc-test-key".to_vec()),
                        Attribute::Token(true),
                        Attribute::Private(false),
                        Attribute::EcParams(p256_oid_bytes),
                        Attribute::Verify(true),
                    ],
                    &[
                        Attribute::Id(vec![2]),
                        Attribute::Label(b"ecc-test-key".to_vec()),
                        Attribute::Token(true),
                        Attribute::Private(true),
                        Attribute::Sensitive(true),
                        Attribute::Sign(true),
                    ],
                )?;

                // Add unsupported key
                session.generate_key_pair(
                    &Mechanism::RsaPkcsKeyPairGen,
                    &[
                        Attribute::Id(vec![3]),
                        Attribute::Label(b"unsupported-rsa-key".to_vec()),
                        Attribute::Token(true),
                        Attribute::Private(false),
                        Attribute::Verify(true),
                        Attribute::ModulusBits(1024.into()),
                    ],
                    &[
                        Attribute::Id(vec![3]),
                        Attribute::Label(b"unsupported-rsa-key".to_vec()),
                        Attribute::Token(true),
                        Attribute::Private(true),
                        Attribute::Sensitive(true),
                        Attribute::Sign(true),
                    ],
                )?;
                Ok(())
            })
            .context("Failed to initialize user pin")?;

        pkcs11.finalize()?;

        let rsa_key_uri = "pkcs11:model=v1;manufacturer=Kryoptic%20Project;token=test-token;id=%01;object=binding-key;type=private";
        let cert_file = hsm_dir.path().join("cert0");
        let mut command = Command::new("openssl");
        let output = command
            .env("KRYOPTIC_CONF", &hsm_config_path)
            .args([
                "req",
                "-x509",
                "-provider",
                "pkcs11",
                "-subj",
                "/CN=BindingKey",
            ])
            .arg("-passin")
            .arg(format!("pass:{}", user_pin_str))
            .arg("-key")
            .arg(rsa_key_uri)
            .arg("-out")
            .arg(&cert_file)
            .output()?;
        if !output.status.success() {
            panic!(
                "Failed to create x509 certificate:  {:?}",
                String::from_utf8_lossy(&output.stderr)
            )
        }

        let mut command = Command::new("pkcs11-tool");
        let output = command
            .env("KRYOPTIC_CONF", &hsm_config_path)
            .arg(format!("--module={}", module_path))
            .args([
                "--login",
                "--pin=secret-password",
                "--type=cert",
                "--label=self-signed-cert",
                "--id=1",
            ])
            .arg(format!("--write-object={}", cert_file.display()))
            .output()?;
        if !output.status.success() {
            panic!(
                "Failed to add cert to PKCS 11 token: {:?}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let binding = Pkcs11Binding {
            public_key: cert_file,
            private_key: Some(rsa_key_uri.to_string()),
            pin: Some(Password::from("secret-password")),
        };

        // Some other bindings we don't have keys for, but should still encrypt for.
        let mut bindings = vec![binding];
        for n in 1..5 {
            let pubkey_path = hsm_dir.path().join(format!("cert{}", n));
            let key_path = hsm_dir.path().join(format!("cert{}.key", n));
            let mut command = Command::new("openssl");
            command
                .args([
                    "req", "-x509", "-new", "-nodes", "-sha256", "-subj", "/CN=Test", "-days", "5",
                    "-newkey", "rsa:4096", "-keyout",
                ])
                .arg(&key_path)
                .arg("-out")
                .arg(&pubkey_path);
            let output = command.output()?;
            if !output.status.success() {
                panic!(
                    "Failed to create binding cert: {:?}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }

            bindings.push(Pkcs11Binding {
                public_key: pubkey_path,
                ..Default::default()
            });
        }

        Ok(Hsm {
            directory: hsm_dir,
            bindings,
            user_pin,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Generated passwords should be base64 encoded and 128 bytes of randomness.
    #[test]
    fn password_len() -> anyhow::Result<()> {
        let password = generate_password()?;
        let string = password.map(|p| String::from_utf8(p.to_vec()))?;
        let bytes = openssl::base64::decode_block(&string)?;
        assert_eq!(128, bytes.len());

        Ok(())
    }
}

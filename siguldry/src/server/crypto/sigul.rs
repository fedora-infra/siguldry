// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! This module contains functions for working with Sigul-bound keys.
//!
//! It should only be used when accessing a Sigul database for the purpose of
//! migrating it to Siguldry.

use std::num::NonZeroU32;

use anyhow::Context;
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::EcKey,
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Rsa,
};
use sequoia_openpgp::{
    crypto::{Password, mpi},
    parse::Parse,
    policy::StandardPolicy,
    serialize::SerializeInto,
};

use crate::{
    protocol::KeyAlgorithm,
    server::crypto::{KeyUsage, binding::bind_with_pkcs11},
};

/// This encrypts an OpenSSL private key.
///
/// This takes an existing, unencrypted private key and encrypts it to a PEM-encoded
/// PKCS#8 structure, which it then binds with the PKCS#11 bindings. It does _not_ bind
/// the password.
///
/// NOTE: This is only useful externally to the sigul import command; do not use it
/// for any other purpose; see [`siguldry::server::crypto::create_encrypted_key`].
pub fn encrypt_key(
    config: &crate::server::Config,
    key_password: Password,
    private_key: PKey<Private>,
) -> anyhow::Result<String> {
    let private_key_pem = super::encrypt_key(key_password, private_key)?;
    bind_with_pkcs11(&config.pkcs11_bindings, &private_key_pem)
}

pub struct ImportedPgpKey {
    pub handle: String,
    /// The private key, encrypted with the key password and possibly bound with certs
    pub key_material: String,
    pub public_key_pem: String,
    pub openpgp_cert: String,
    pub x509_cert: String,
    pub algorithm: KeyAlgorithm,
}

fn pgp_key_to_openssl(
    cert: &sequoia_openpgp::Cert,
    password: &Password,
) -> anyhow::Result<PKey<openssl::pkey::Private>> {
    let policy = &StandardPolicy::new();
    let key = cert
        .keys()
        .secret()
        .with_policy(policy, None)
        .supported()
        .for_signing()
        .next()
        .ok_or_else(|| anyhow::anyhow!("No signing-capable key found in certificate"))?
        .key()
        .clone()
        .decrypt_secret(password)?;
    let secret = match key.secret() {
        sequoia_openpgp::packet::key::SecretKeyMaterial::Unencrypted(unencrypted) => unencrypted,
        sequoia_openpgp::packet::key::SecretKeyMaterial::Encrypted(_) => {
            return Err(anyhow::anyhow!("OpenPGP wasn't decrypted"));
        }
    };

    let key = secret.map(|secret| {
        match (key.mpis(), secret) {
            (mpi::PublicKey::RSA { e, n }, mpi::SecretKeyMaterial::RSA { d, p, q, u: _ }) => {
                let e = BigNum::from_slice(e.value())?;
                let n = BigNum::from_slice(n.value())?;
                let d = BigNum::from_slice(d.value())?;
                let p = BigNum::from_slice(p.value())?;
                let q = BigNum::from_slice(q.value())?;
                let one = BigNum::from_u32(1)?;

                // https://en.wikipedia.org/wiki/RSA_cryptosystem#Using_the_Chinese_remainder_algorithm
                let mut context = BigNumContext::new_secure()?;
                let mut p_sub_1 = BigNum::new()?;
                p_sub_1.checked_sub(&p, &one)?;
                let mut dmp1 = BigNum::new()?;
                dmp1.checked_rem(&d, &p_sub_1, &mut context)?;

                let mut context = BigNumContext::new_secure()?;
                let mut q_sub_1 = BigNum::new()?;
                q_sub_1.checked_sub(&q, &one)?;
                let mut dmq1 = BigNum::new()?;
                dmq1.checked_rem(&d, &q_sub_1, &mut context)?;

                let mut context = BigNumContext::new_secure()?;
                let mut iqmp = BigNum::new()?;
                iqmp.mod_inverse(&q, &p, &mut context)?;

                let privkey = Rsa::from_private_components(n, e, d, p, q, dmp1, dmq1, iqmp)?;
                assert!(privkey.check_key()?);
                Ok(PKey::from_rsa(privkey)?)
            }
            (mpi::PublicKey::ECDSA { curve, q }, mpi::SecretKeyMaterial::ECDSA { scalar }) => {
                let curve = match curve {
                    sequoia_openpgp::types::Curve::NistP256 => Ok(Nid::X9_62_PRIME256V1),
                    _ => Err(anyhow::anyhow!(
                        "Only ECDSA keys using the NIST P-256 curve are supported"
                    )),
                }?;

                let group = openssl::ec::EcGroup::from_curve_name(curve)?;
                let scalar = BigNum::from_slice(scalar.value())?;
                let mut context = BigNumContext::new_secure()?;
                let public_key = openssl::ec::EcPoint::from_bytes(&group, q.value(), &mut context)?;
                let privkey = EcKey::from_private_components(&group, &scalar, &public_key)?;

                Ok(PKey::from_ec_key(privkey)?)
            }
            _unsupported => Err(anyhow::anyhow!(
                "No support for signing via OpenSSL with this OpenPGP key type"
            )),
        }
    })?;

    Ok(key)
}

pub fn convert_gpg_key(
    config: &crate::server::Config,
    key_name: &str,
    bytes: &[u8],
    key_password: Password,
) -> anyhow::Result<ImportedPgpKey> {
    let cert = sequoia_openpgp::Cert::from_bytes(bytes)
        .context("Failed to parse the exported OpenPGP secret key with Sequoia")?;

    // Check that there's a secret key we can decrypt that's marked for signing to ensure
    // we've unbound the key properly. We may need to tweak this policy if we import very
    // old keys from sigul.
    let policy = sequoia_openpgp::policy::StandardPolicy::new();
    cert.keys()
        .secret()
        .with_policy(&policy, None)
        .supported()
        .for_signing()
        .next()
        .ok_or_else(|| anyhow::anyhow!("No signing-capable secret key found in certificate"))?
        .key()
        .clone()
        .decrypt_secret(&key_password)?;

    let algorithm = match cert.primary_key().key().pk_algo() {
        sequoia_openpgp::types::PublicKeyAlgorithm::RSAEncryptSign => {
            let bits = cert.primary_key().key().mpis().bits().unwrap_or(0);
            match bits {
                4096 => KeyAlgorithm::Rsa4K,
                2048 => KeyAlgorithm::Rsa2K,
                other => {
                    tracing::warn!("RSA key found, but key size ({}) is unsupported", other);
                    return Err(anyhow::anyhow!("Unsupported RSA key size: {}", other));
                }
            }
        }
        other => {
            tracing::warn!(algorithm = ?other, "GPG key uses unsupported algorithm");
            return Err(anyhow::anyhow!("Unsupported key algorithm {:?}", other));
        }
    };

    let private_key = pgp_key_to_openssl(&cert, &key_password)?;
    let x509_cert = super::x509_certificate_for_key_private(
        PKey::public_key_from_der(&private_key.public_key_to_der()?)?,
        private_key.clone(),
        None,
        &config.certificate_subject,
        KeyUsage::CodeSigning,
        key_name,
        NonZeroU32::new(730).unwrap(),
    )?;
    let handle = hex::encode_upper(openssl::hash::hash(
        openssl::hash::MessageDigest::sha256(),
        &private_key.public_key_to_der()?,
    )?);
    let public_key_pem = String::from_utf8(private_key.public_key_to_pem()?)?;
    let key_material = encrypt_key(config, key_password, private_key)?;
    let openpgp_cert = String::from_utf8(cert.strip_secret_key_material().armored().to_vec()?)?;

    Ok(ImportedPgpKey {
        handle,
        key_material,
        public_key_pem,
        openpgp_cert,
        x509_cert,
        algorithm,
    })
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use sequoia_openpgp::{
        Profile,
        cert::{CertBuilder, CipherSuite},
        serialize::stream::{Message, Signer},
        types::KeyFlags,
    };

    use crate::server::crypto::generate_password;

    use super::*;

    /// Inverse of [`crate::server::crypto::pgp_key_to_openssl`].
    fn openssl_key_to_pgp(
        cert: &sequoia_openpgp::Cert,
        openssl_key: &PKey<openssl::pkey::Private>,
    ) -> anyhow::Result<sequoia_openpgp::Cert> {
        let policy = &StandardPolicy::new();
        let ka = cert
            .keys()
            .with_policy(policy, None)
            .supported()
            .for_signing()
            .next()
            .ok_or_else(|| anyhow::anyhow!("No signing-capable key found"))?;

        let key = ka.key();

        let secret = if let Ok(rsa) = openssl_key.rsa() {
            let d = mpi::ProtectedMPI::from(rsa.d().to_vec());
            let p = mpi::ProtectedMPI::from(rsa.p().unwrap().to_vec());
            let q = mpi::ProtectedMPI::from(rsa.q().unwrap().to_vec());

            // Inverse of p mod q.
            let mut context = BigNumContext::new_secure()?;
            let mut u = BigNum::new()?;
            u.mod_inverse(rsa.p().unwrap(), rsa.q().unwrap(), &mut context)?;
            let u = mpi::ProtectedMPI::from(u.to_vec());

            mpi::SecretKeyMaterial::RSA { d, p, q, u }
        } else if let Ok(ec) = openssl_key.ec_key() {
            let scalar = mpi::ProtectedMPI::from(ec.private_key().to_vec());
            mpi::SecretKeyMaterial::ECDSA { scalar }
        } else {
            return Err(anyhow::anyhow!("Unsupported key type"));
        };

        let (key_with_secret, _old) = key.clone().add_secret(secret.into());
        let key_with_secret = key_with_secret.role_into_primary();
        let key_packet = sequoia_openpgp::packet::Packet::SecretKey(key_with_secret);
        let (cert, _changed) = cert.clone().insert_packets(key_packet)?;

        Ok(cert)
    }

    #[test]
    fn roundtrip_rsa_pgp() -> anyhow::Result<()> {
        let key_password = generate_password()?;
        let (cert, _signature) = CertBuilder::new()
            .set_profile(Profile::RFC4880)?
            .set_cipher_suite(CipherSuite::RSA4k)
            .add_userid("User <user@example.com>")
            .set_primary_key_flags(KeyFlags::signing())
            .set_password(Some(key_password.clone()))
            .generate()?;
        let public_cert = cert.clone().strip_secret_key_material();

        let key = pgp_key_to_openssl(&cert, &key_password)?;
        let new_cert = openssl_key_to_pgp(&public_cert, &key)?;
        assert!(
            !public_cert.is_tsk(),
            "The public cert should not include secret materials"
        );
        assert!(new_cert.is_tsk(), "The secret key has been added back");
        assert_eq!(cert, new_cert);

        let policy = &StandardPolicy::new();
        let signing_key = new_cert
            .keys()
            .secret()
            .with_policy(policy, None)
            .supported()
            .for_signing()
            .next()
            .ok_or_else(|| anyhow::anyhow!("No signing-capable key found in certificate"))?
            .key()
            .clone()
            .into_keypair()?;

        let blob = "🦧📖".as_bytes();
        let signature = {
            let mut sink = vec![];
            let mut signer = Signer::new(Message::new(&mut sink), signing_key)?
                .detached()
                .build()?;
            signer.write_all(blob)?;
            signer.finalize()?;
            tracing::trace!("Successfully signed message");
            Ok::<_, anyhow::Error>(sink)
        }?;

        struct VerifyHelper<'a> {
            cert: &'a sequoia_openpgp::Cert,
        }

        impl sequoia_openpgp::parse::stream::VerificationHelper for VerifyHelper<'_> {
            fn get_certs(
                &mut self,
                _ids: &[sequoia_openpgp::KeyHandle],
            ) -> sequoia_openpgp::Result<Vec<sequoia_openpgp::Cert>> {
                Ok(vec![self.cert.clone()])
            }

            fn check(
                &mut self,
                structure: sequoia_openpgp::parse::stream::MessageStructure<'_>,
            ) -> sequoia_openpgp::Result<()> {
                for layer in structure {
                    match layer {
                        sequoia_openpgp::parse::stream::MessageLayer::SignatureGroup {
                            results,
                        } => {
                            for result in results {
                                match result {
                                Ok(_) => {}
                                Err(
                                    sequoia_openpgp::parse::stream::VerificationError::MissingKey {
                                        sig: _,
                                    },
                                ) => return Err(anyhow::anyhow!("it's no good".to_string())),
                                unexpected => panic!("Unexpected error: {:?}", unexpected),
                            }
                            }
                        }
                        _ => panic!("Unexpected message structure"),
                    }
                }
                Ok(())
            }
        }
        let helper = VerifyHelper { cert: &cert };
        let policy = &StandardPolicy::new();
        let mut verifier =
            sequoia_openpgp::parse::stream::DetachedVerifierBuilder::from_bytes(&signature)?
                .with_policy(policy, None, helper)?;
        verifier.verify_bytes(blob)?;

        let (different_cert, _signature) = CertBuilder::new()
            .set_profile(Profile::RFC4880)?
            .set_cipher_suite(CipherSuite::RSA4k)
            .add_userid("User <user@example.com>")
            .set_primary_key_flags(KeyFlags::signing())
            .set_password(Some(key_password.clone()))
            .generate()?;
        let helper = VerifyHelper {
            cert: &different_cert,
        };
        let policy = &StandardPolicy::new();
        let mut verifier =
            sequoia_openpgp::parse::stream::DetachedVerifierBuilder::from_bytes(&signature)?
                .with_policy(policy, None, helper)?;
        assert!(
            verifier.verify_bytes(blob).is_err(),
            "This certificate didn't sign the data"
        );

        Ok(())
    }
}

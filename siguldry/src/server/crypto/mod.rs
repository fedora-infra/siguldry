// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! All the cryptography-related operations are in these modules.
//!
//! Sequoia is used for OpenPGP signatures and for the symmetric encryption of keys managed by Siguldry.
//! OpenSSL is used for other signatures.

use std::num::NonZeroU32;

use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Rsa,
    symm::Cipher,
    x509,
};
use sequoia_openpgp::{
    Profile,
    crypto::{Password, mpi},
    packet,
    policy::StandardPolicy,
    serialize::MarshalInto,
    types::{KeyFlags, SignatureType},
};

use crate::{protocol::KeyAlgorithm, server::db};

pub mod binding;
pub mod signing;
pub mod token;

fn generate_password() -> anyhow::Result<Password> {
    let mut buf = [0; 128];
    openssl::rand::rand_bytes(buf.as_mut_slice())?;
    Ok(Password::from(openssl::base64::encode_block(&buf)))
}

/// This encrypts an OpenSSL private key.
///
/// This takes an existing, unencrypted private key and encrypts it to a PEM-encoded
/// PKCS#8 structure. It does _not_ bind the password.
fn encrypt_key(key_password: Password, private_key: PKey<Private>) -> anyhow::Result<String> {
    let encrypted_pem = key_password
        .map(|key_password| {
            private_key.private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), key_password)
        })
        .map(String::from_utf8)??;
    Ok(encrypted_pem)
}

#[derive(Clone)]
pub struct EncryptedKey {
    pub handle: String,
    pub encrypted_password: Vec<u8>,
    pub private_key_pem: String,
    pub public_key_pem: String,
    pub openpgp_certificate: String,
    pub x509_certificate: String,
}

/// Generate a "soft" key pair, OpenPGP certificate, and X509 certificate.
#[allow(clippy::too_many_arguments)]
pub fn create_encrypted_key(
    config: &crate::server::Config,
    user_password: Password,
    algorithm: KeyAlgorithm,
    openpgp_profile: Profile,
    key_usage: KeyUsage,
    x509_common_name: String,
    x509_validity: NonZeroU32,
    x509_ca: Option<(db::Key, Password, db::PublicKeyMaterial)>,
) -> anyhow::Result<EncryptedKey> {
    let key_password = generate_password()?;
    let key = match algorithm {
        KeyAlgorithm::Rsa2K => PKey::from_rsa(Rsa::generate(2048)?)?,
        KeyAlgorithm::Rsa4K => PKey::from_rsa(Rsa::generate(4096)?)?,
        KeyAlgorithm::P256 => PKey::from_ec_key(EcKey::generate(
            EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?.as_ref(),
        )?)?,
    };
    let (signing_key, issuer) = if let Some((ca_key, key_password, issuer)) = x509_ca {
        let signing_key = key_password.map(|passphrase| {
            PKey::private_key_from_pem_passphrase(ca_key.key_material.as_bytes(), passphrase)
        })?;
        let issuer = x509::X509::from_pem(issuer.data.as_bytes())?;
        (signing_key, Some(issuer))
    } else {
        (key.clone(), None)
    };
    // This seems silly but I can't find a better interface to get the public key variant.
    let pubkey = PKey::public_key_from_der(&key.public_key_to_der()?)?;
    let x509_certificate = x509_certificate_for_key_private(
        pubkey,
        signing_key,
        issuer,
        &config.certificate_subject,
        key_usage,
        &x509_common_name,
        x509_validity,
    )?;

    let openpgp_cert = openpgp_cert_for_key(
        &key,
        config.openpgp_user_id.clone().into(),
        openpgp_profile,
        sequoia_openpgp::types::HashAlgorithm::SHA512,
    )?;
    let openpgp_certificate = String::from_utf8(
        openpgp_cert
            .strip_secret_key_material()
            .armored()
            .to_vec()?,
    )?;
    let public_key_pem = String::from_utf8(key.public_key_to_pem()?)?;
    let handle = hex::encode_upper(openssl::hash::hash(
        openssl::hash::MessageDigest::sha256(),
        &key.public_key_to_der()?,
    )?);
    let private_key_pem = encrypt_key(key_password.clone(), key)?;
    let encrypted_password =
        binding::encrypt_key_password(&config.pkcs11_bindings, user_password, key_password)?;

    Ok(EncryptedKey {
        handle,
        encrypted_password,
        private_key_pem,
        public_key_pem,
        openpgp_certificate,
        x509_certificate,
    })
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

// TODO: Delete this when we yank out all the PGP signing stuff on the server side
pub(crate) fn openssl_key_to_pgp(
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

/// Build an OpenPGP certificate for an OpenSSL key.
///
/// Note that this will need adjustments to handle hybrid keys.
fn openpgp_cert_for_key(
    openssl_key: &PKey<Private>,
    user_id: packet::UserID,
    profile: Profile,
    hash_algorithm: sequoia_openpgp::types::HashAlgorithm,
) -> anyhow::Result<sequoia_openpgp::Cert> {
    let (public, secret, alorithm) = if let Ok(rsa) = openssl_key.rsa() {
        let p = rsa
            .p()
            .ok_or_else(|| anyhow::anyhow!("Generated RSA key is missing p"))?;
        let q = rsa
            .q()
            .ok_or_else(|| anyhow::anyhow!("Generated RSA key is missing q"))?;
        // Inverse of p mod q.
        let mut context = BigNumContext::new_secure()?;
        let mut u = BigNum::new()?;
        u.mod_inverse(p, q, &mut context)?;

        let u = mpi::ProtectedMPI::from(u.to_vec());
        let d = mpi::ProtectedMPI::from(rsa.d().to_vec());
        let p = mpi::ProtectedMPI::from(p.to_vec());
        let q = mpi::ProtectedMPI::from(q.to_vec());
        let secret = mpi::SecretKeyMaterial::RSA { d, p, q, u };
        let public = mpi::PublicKey::RSA {
            e: rsa.e().to_vec().into(),
            n: rsa.n().to_vec().into(),
        };

        (
            public,
            secret,
            sequoia_openpgp::types::PublicKeyAlgorithm::RSAEncryptSign,
        )
    } else if let Ok(ec) = openssl_key.ec_key() {
        let secret = mpi::SecretKeyMaterial::ECDSA {
            scalar: mpi::ProtectedMPI::from(ec.private_key().to_vec()),
        };
        let mut context = BigNumContext::new_secure()?;
        let public = ec.public_key().to_bytes(
            ec.group(),
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut context,
        )?;
        let public = mpi::PublicKey::ECDSA {
            curve: sequoia_openpgp::types::Curve::NistP256,
            q: mpi::MPI::from(public),
        };

        (
            public,
            secret,
            sequoia_openpgp::types::PublicKeyAlgorithm::ECDSA,
        )
    } else {
        return Err(anyhow::anyhow!("Unsupported key type"));
    };

    let creation_time = std::time::SystemTime::now();
    let key: packet::key::Key<packet::key::SecretParts, packet::key::PrimaryRole> = match profile {
        Profile::RFC9580 => {
            packet::key::Key6::with_secret(creation_time, alorithm, public, secret.into())?.into()
        }
        Profile::RFC4880 => {
            packet::key::Key4::with_secret(creation_time, alorithm, public, secret.into())?.into()
        }
        _ => return Err(anyhow::anyhow!("Unsupported OpenPGP profile")),
    };
    let key_packet = packet::Packet::SecretKey(key.clone());

    let builder = packet::signature::SignatureBuilder::new(SignatureType::DirectKey)
        .set_hash_algo(hash_algorithm)
        .set_signature_creation_time(creation_time)?
        .set_key_flags(KeyFlags::empty().set_signing().set_certification())?
        .set_features(sequoia_openpgp::types::Features::sequoia())?
        .set_preferred_hash_algorithms(vec![
            sequoia_openpgp::types::HashAlgorithm::SHA512,
            sequoia_openpgp::types::HashAlgorithm::SHA256,
        ])?
        .set_preferred_symmetric_algorithms(vec![
            sequoia_openpgp::types::SymmetricAlgorithm::AES256,
            sequoia_openpgp::types::SymmetricAlgorithm::AES128,
        ])?;
    let direct_key_signature =
        builder.sign_direct_key(&mut key.clone().into_keypair()?, key.parts_as_public())?;

    let builder = packet::signature::SignatureBuilder::new(SignatureType::PositiveCertification)
        .set_hash_algo(hash_algorithm)
        .set_signature_creation_time(creation_time)?
        .set_key_flags(KeyFlags::empty().set_signing().set_certification())?
        .set_features(sequoia_openpgp::types::Features::sequoia())?
        .set_preferred_hash_algorithms(vec![
            sequoia_openpgp::types::HashAlgorithm::SHA512,
            sequoia_openpgp::types::HashAlgorithm::SHA256,
        ])?
        .set_preferred_symmetric_algorithms(vec![
            sequoia_openpgp::types::SymmetricAlgorithm::AES256,
            sequoia_openpgp::types::SymmetricAlgorithm::AES128,
        ])?;
    let positive_cert_signature = user_id.bind(
        &mut key.clone().into_keypair()?,
        &sequoia_openpgp::Cert::try_from(key_packet.clone())?,
        builder,
    )?;

    let cert = sequoia_openpgp::Cert::try_from(vec![
        key_packet,
        packet::Packet::from(user_id),
        packet::Packet::from(direct_key_signature),
        packet::Packet::from(positive_cert_signature),
    ])?
    .strip_secret_key_material();
    assert!(!cert.is_tsk());

    Ok(cert)
}

/// This module contains functions for working with Sigul-bound keys.
///
/// It should only be used when accessing a Sigul database for the purpose of
/// migrating it to Siguldry.
pub mod sigul {
    use anyhow::Context;
    use openssl::pkey::{PKey, Private};
    use sequoia_openpgp::{crypto::Password, parse::Parse, serialize::SerializeInto};

    use crate::protocol::KeyAlgorithm;

    /// This encrypts an OpenSSL private key.
    ///
    /// This takes an existing, unencrypted private key and encrypts it to a PEM-encoded
    /// PKCS#8 structure. It does _not_ bind the password.
    ///
    /// NOTE: This is only useful externally to the sigul import command; do not use it
    /// for any other purpose; see [`siguldry::server::crypto::create_encrypted_key`].
    pub fn encrypt_key(
        key_password: Password,
        private_key: PKey<Private>,
    ) -> anyhow::Result<String> {
        super::encrypt_key(key_password, private_key)
    }

    pub struct ImportedPgpKey {
        pub handle: String,
        pub private_key_pem: String,
        pub public_key_pem: String,
        pub openpgp_cert: String,
        pub algorithm: KeyAlgorithm,
    }

    pub fn check_gpg_key(bytes: &[u8], key_password: Password) -> anyhow::Result<ImportedPgpKey> {
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

        let private_key = super::pgp_key_to_openssl(&cert, &key_password)?;
        let handle = hex::encode_upper(openssl::hash::hash(
            openssl::hash::MessageDigest::sha256(),
            &private_key.public_key_to_der()?,
        )?);
        let public_key_pem = String::from_utf8(private_key.public_key_to_pem()?)?;
        let private_key_pem = super::encrypt_key(key_password, private_key)?;
        let openpgp_cert = String::from_utf8(cert.strip_secret_key_material().armored().to_vec()?)?;

        Ok(ImportedPgpKey {
            handle,
            private_key_pem,
            public_key_pem,
            openpgp_cert,
            algorithm,
        })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[cfg_attr(feature = "cli", derive(clap::ValueEnum))]
#[non_exhaustive]
pub enum KeyUsage {
    #[default]
    CodeSigning,
    CertificateAuthority,
}

fn x509_certificate_for_key_private(
    pubkey: PKey<openssl::pkey::Public>,
    signing_key: PKey<Private>,
    issuer: Option<x509::X509>,
    subject_config: &crate::server::config::X509SubjectName,
    usage: KeyUsage,
    common_name: &str,
    validity_days: NonZeroU32,
) -> anyhow::Result<String> {
    let mut builder = x509::X509Builder::new()?;
    builder.set_pubkey(&pubkey)?;

    let mut serial_number = [0; 20];
    openssl::rand::rand_bytes(&mut serial_number)?;
    let mut serial_number = openssl::bn::BigNum::from_slice(&serial_number)?;
    serial_number.set_negative(false);
    builder.set_serial_number(openssl::asn1::Asn1Integer::from_bn(&serial_number)?.as_ref())?;

    let mut subject_name = x509::X509NameBuilder::new()?;
    subject_name.append_entry_by_nid(Nid::COUNTRYNAME, &subject_config.country)?;
    subject_name
        .append_entry_by_nid(Nid::STATEORPROVINCENAME, &subject_config.state_or_province)?;
    subject_name.append_entry_by_nid(Nid::LOCALITYNAME, &subject_config.locality)?;
    subject_name.append_entry_by_nid(Nid::ORGANIZATIONNAME, &subject_config.organization)?;
    subject_name.append_entry_by_nid(
        Nid::ORGANIZATIONALUNITNAME,
        &subject_config.organizational_unit,
    )?;
    subject_name.append_entry_by_nid(Nid::COMMONNAME, common_name)?;
    let subject_name = subject_name.build();
    builder.set_subject_name(&subject_name)?;

    let issuer_name = issuer
        .as_ref()
        .map_or(subject_name.as_ref(), |ca| ca.subject_name());
    builder.set_issuer_name(issuer_name)?;

    builder.set_not_before(openssl::asn1::Asn1Time::days_from_now(0)?.as_ref())?;
    builder.set_not_after(openssl::asn1::Asn1Time::days_from_now(validity_days.get())?.as_ref())?;

    let mut basic_constraints = x509::extension::BasicConstraints::new();
    basic_constraints.critical().pathlen(0);
    if let KeyUsage::CertificateAuthority = usage {
        basic_constraints.ca();
    }
    builder.append_extension(basic_constraints.build()?)?;

    match usage {
        KeyUsage::CodeSigning => {
            builder.append_extension(
                x509::extension::KeyUsage::new()
                    .critical()
                    .digital_signature()
                    .build()?,
            )?;
            builder.append_extension(
                x509::extension::ExtendedKeyUsage::new()
                    .code_signing()
                    .build()?,
            )?;
        }
        KeyUsage::CertificateAuthority => {
            builder.append_extension(
                x509::extension::KeyUsage::new()
                    .critical()
                    .key_cert_sign()
                    .crl_sign()
                    .build()?,
            )?;
        }
    };

    let subj_key_id = x509::extension::SubjectKeyIdentifier::new();
    let context = builder.x509v3_context(issuer.as_ref().map(|i| i.as_ref()), None);
    builder.append_extension(subj_key_id.build(&context)?)?;
    builder.sign(&signing_key, openssl::hash::MessageDigest::sha512())?;
    let certificate = String::from_utf8(builder.build().to_pem()?)?;

    Ok(certificate)
}

/// Generate an X509 certificate for the provided key.
///
/// If the `certificate_authority` is `None`, the certificate will be self-signed.
/// The `key_password` is for the _signing key_, so the certificate authority if it's Some,
/// or the key if this will be a self-signed certificate.
pub fn x509_certificate_for_key(
    key: db::Key,
    certificate_authority: Option<(db::Key, db::PublicKeyMaterial)>,
    key_password: Password,
    subject_config: &crate::server::config::X509SubjectName,
    usage: KeyUsage,
    common_name: &str,
    validity_days: NonZeroU32,
) -> anyhow::Result<String> {
    let (signing_key, issuer) = if let Some((key, cert)) = certificate_authority {
        let ca_cert = x509::X509::from_pem(cert.data.as_bytes())?;
        (key, Some(ca_cert))
    } else {
        (key.clone(), None)
    };

    let pubkey = openssl::pkey::PKey::public_key_from_pem(key.public_key.as_bytes())?;
    let signing_key = key_password.map(|passphrase| {
        openssl::pkey::PKey::private_key_from_pem_passphrase(
            signing_key.key_material.as_bytes(),
            passphrase,
        )
    })?;

    let certificate = x509_certificate_for_key_private(
        pubkey,
        signing_key,
        issuer,
        subject_config,
        usage,
        common_name,
        validity_days,
    )?;

    Ok(certificate)
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
            certificate: cert_file,
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
                certificate: pubkey_path,
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
    use std::io::Write;

    use sequoia_openpgp::{
        cert::{CertBuilder, CipherSuite},
        parse::Parse,
        serialize::stream::{Message, Signer},
    };

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

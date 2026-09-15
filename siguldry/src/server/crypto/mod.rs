// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! All the cryptography-related operations are in these modules.
//!
//! Sequoia is used for OpenPGP signatures and for the symmetric encryption of keys managed by Siguldry.
//! OpenSSL is used for other signatures.

use std::{num::NonZeroU32, time::Duration};

use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::{HasPrivate, HasPublic, KeyType as OpenSSLKeyType, PKey, Private},
    rsa::Rsa,
    symm::Cipher,
    x509,
};
use sequoia_openpgp::{
    Profile,
    crypto::{Password, mpi},
    packet,
    serialize::MarshalInto,
    types::{KeyFlags, SignatureType},
};

use crate::{protocol::KeyAlgorithm, server::db};

pub mod binding;
pub mod signing;
pub mod sigul;
pub mod token;

fn generate_password() -> anyhow::Result<Password> {
    let mut buf = [0; 128];
    openssl::rand::rand_priv_bytes(buf.as_mut_slice())?;
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
    pub key_material: String,
    pub public_key_pem: String,
    pub x509_certificate: Option<String>,
    pub openpgp_certificate: Option<String>,
}

#[derive(Default)]
pub struct KeyCertificateParameters {
    pub x509: Option<X509CertificateParameters>,
    pub openpgp: Option<OpenPgpCertificateParameters>,
}

pub struct X509CertificateParameters {
    pub usage: KeyUsage,
    pub common_name: String,
    pub validity_days: NonZeroU32,
}

pub struct OpenPgpCertificateParameters {
    pub user_id: packet::UserID,
    pub profile: Profile,
    pub hash_algorithm: sequoia_openpgp::types::HashAlgorithm,
    pub validity_days: u32,
}

fn create_key(algorithm: KeyAlgorithm) -> anyhow::Result<PKey<Private>> {
    let key = match algorithm {
        KeyAlgorithm::Rsa2K => PKey::from_rsa(Rsa::generate(2048)?)?,
        KeyAlgorithm::Rsa4K => PKey::from_rsa(Rsa::generate(4096)?)?,
        KeyAlgorithm::P256 => PKey::from_ec_key(EcKey::generate(
            EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?.as_ref(),
        )?)?,
        KeyAlgorithm::Ed25519 => PKey::generate_ed25519()?,
        KeyAlgorithm::Ed448 => PKey::generate_ed448()?,
        KeyAlgorithm::Mldsa65 => {
            let mut seed = [0; 32];
            openssl::rand::rand_priv_bytes(seed.as_mut_slice())?;
            PKey::private_key_from_seed(None, openssl::pkey::KeyType::ML_DSA_65, None, &seed)?
        }
        KeyAlgorithm::Mldsa87 => {
            let mut seed = [0; 32];
            openssl::rand::rand_priv_bytes(seed.as_mut_slice())?;
            PKey::private_key_from_seed(None, openssl::pkey::KeyType::ML_DSA_87, None, &seed)?
        }
    };

    Ok(key)
}

/// Generate an encrypted "soft" key pair.
pub fn create_encrypted_key(
    config: &crate::server::Config,
    user_password: Password,
    algorithm: KeyAlgorithm,
    hybrid_algorithm: Option<KeyAlgorithm>,
    x509_options: Option<X509CertificateParameters>,
    openpgp_options: Option<OpenPgpCertificateParameters>,
) -> anyhow::Result<(EncryptedKey, Option<EncryptedKey>)> {
    if hybrid_algorithm.is_some() && x509_options.is_some() {
        return Err(anyhow::anyhow!(
            "Hybrid keys don't support generating X.509 certificates during key creation"
        ));
    }

    let key = create_key(algorithm)?;
    let hybrid_key = hybrid_algorithm.map(create_key).transpose()?;

    let x509_certificate = x509_options
        .map(|parameters| {
            x509_certificate_for_key_private(
                &key,
                &key,
                None,
                &config.certificate_subject,
                parameters.usage,
                &parameters.common_name,
                parameters.validity_days,
            )
        })
        .transpose()?;
    let openpgp_certificate = openpgp_options
        .map(|parameters| {
            openpgp_cert_for_key_private(
                &key,
                hybrid_key.as_ref(),
                parameters.user_id.clone(),
                parameters.profile,
                parameters.hash_algorithm,
                parameters.validity_days,
            )
        })
        .transpose()?;

    let hybrid_key = hybrid_key
        .map(|key| {
            let public_key_pem = String::from_utf8(key.public_key_to_pem()?)?;
            let handle = hex::encode_upper(openssl::hash::hash(
                openssl::hash::MessageDigest::sha256(),
                &key.public_key_to_der()?,
            )?);
            let key_password = generate_password()?;
            let private_key_pem = encrypt_key(key_password.clone(), key)?;
            let key_material =
                binding::bind_with_pkcs11(&config.pkcs11_bindings, &private_key_pem)?;
            let encrypted_password = binding::encrypt_key_password(
                &config.pkcs11_bindings,
                user_password.clone(),
                key_password,
            )?;
            Ok::<_, anyhow::Error>(EncryptedKey {
                handle,
                encrypted_password,
                key_material,
                public_key_pem,
                openpgp_certificate: openpgp_certificate.clone(),
                x509_certificate: x509_certificate.clone(),
            })
        })
        .transpose()?;

    let public_key_pem = String::from_utf8(key.public_key_to_pem()?)?;
    let handle = hex::encode_upper(openssl::hash::hash(
        openssl::hash::MessageDigest::sha256(),
        &key.public_key_to_der()?,
    )?);
    let key_password = generate_password()?;
    let private_key_pem = encrypt_key(key_password.clone(), key)?;
    let key_material = binding::bind_with_pkcs11(&config.pkcs11_bindings, &private_key_pem)?;
    let encrypted_password =
        binding::encrypt_key_password(&config.pkcs11_bindings, user_password, key_password)?;

    Ok((
        EncryptedKey {
            handle,
            encrypted_password,
            key_material,
            public_key_pem,
            openpgp_certificate,
            x509_certificate,
        },
        hybrid_key,
    ))
}

fn openssl_keys_to_openpgp(
    openssl_key: &PKey<Private>,
    hybrid_key: Option<&PKey<Private>>,
    profile: Profile,
) -> anyhow::Result<(
    mpi::PublicKey,
    mpi::SecretKeyMaterial,
    sequoia_openpgp::types::PublicKeyAlgorithm,
)> {
    // Brace yourself for the most wild combination of unwieldy APIs.
    //
    // OpenSSL doesn't seem to have a way to get the key type so you have to do this
    // absurd probing with `is_a()`. Sequoia doesn't let us get the private key material
    // back or combine it into a hybrid key after building the individual keys so we have
    // to build a pontential hybrid pair up front, we can't just turn two OpenSSL keys to
    // Sequoia types and deal with the hybrid bit later.
    //
    // Please, save me.

    // First, figure out if the hybrid key is an acceptable type. "Acceptable" just means
    // it's a key pair that the OpenPGP RFC defines, which for now is ML-DSA-65+Ed25519,
    // or ML-DSA-87+Ed448.
    let (traditional_openssl_key, pqc_openssl_key) = if let Some(hybrid_key) = hybrid_key {
        let (traditional_key, maybe_pqc_key) = if openssl_key.is_a(OpenSSLKeyType::ED25519)
            || openssl_key.is_a(OpenSSLKeyType::ED448)
        {
            Ok((openssl_key, hybrid_key))
        } else if hybrid_key.is_a(OpenSSLKeyType::ED25519) || hybrid_key.is_a(OpenSSLKeyType::ED448)
        {
            Ok((hybrid_key, openssl_key))
        } else {
            Err(anyhow::anyhow!(
                "Hybrid pairs require one key to be either Ed25519 or Ed448"
            ))
        }?;

        if (traditional_key.is_a(OpenSSLKeyType::ED25519)
            && maybe_pqc_key.is_a(OpenSSLKeyType::ML_DSA_65))
            || (traditional_key.is_a(OpenSSLKeyType::ED448)
                && maybe_pqc_key.is_a(OpenSSLKeyType::ML_DSA_87))
        {
            Ok((traditional_key, Some(maybe_pqc_key)))
        } else {
            Err(anyhow::anyhow!(
                "The only valid hybrid key pair combinations are ML-DSA-65 with Ed25519, or ML-DSA-87 with Ed448"
            ))
        }
    } else {
        Ok((openssl_key, None))
    }?;

    if let Ok(rsa) = traditional_openssl_key.rsa() {
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

        Ok((
            public,
            secret,
            sequoia_openpgp::types::PublicKeyAlgorithm::RSAEncryptSign,
        ))
    } else if let Ok(ec) = traditional_openssl_key.ec_key() {
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

        Ok((
            public,
            secret,
            sequoia_openpgp::types::PublicKeyAlgorithm::ECDSA,
        ))
    } else if traditional_openssl_key.is_a(openssl::pkey::KeyType::ED25519) {
        if profile != Profile::RFC9580 {
            // RFC 4880 makes no mention of Ed25519, although GPG does support generating Curve 25519 keys
            // and Sequoia does have an EdDSA variant. We only care about these keys for hybrid key pairs,
            // though, so I don't think it matters much.
            return Err(anyhow::anyhow!(
                "Ed25519 OpenPGP keys are only supported with RFC 9580 profile"
            ));
        }

        let ed25519_public_key = traditional_openssl_key
            .raw_public_key()?
            .try_into()
            .map_err(|e: Vec<u8>| {
                anyhow::anyhow!(
                    "Expected a 32-byte Ed25519 public key, got {} bytes",
                    e.len()
                )
            })?;
        let ed25519_private_key = sequoia_openpgp::crypto::mem::Protected::from(
            traditional_openssl_key.raw_private_key()?,
        );

        if let Some(hybrid_key) = pqc_openssl_key {
            // We checked this above but this is all a mess so maybe we missed something.
            assert!(hybrid_key.is_a(openssl::pkey::KeyType::ML_DSA_65));
            let mut mldsa_private_key_seed = ossl::OsslSecret::new(32);
            let seed_length = hybrid_key.seed_into(&mut mldsa_private_key_seed)?;
            if seed_length != 32 {
                return Err(anyhow::anyhow!(
                    "Expected a 32-byte key seed, got {seed_length} bytes"
                ));
            }
            let mldsa_public_key: [u8; 1952] =
                hybrid_key
                    .raw_public_key()?
                    .try_into()
                    .map_err(|e: Vec<u8>| {
                        anyhow::anyhow!(
                            "ML-DSA-65 public key was expected to be 1952 bytes, was {}",
                            e.len()
                        )
                    })?;
            Ok((
                mpi::PublicKey::MLDSA65_Ed25519 {
                    eddsa: Box::new(ed25519_public_key),
                    mldsa: Box::new(mldsa_public_key),
                },
                mpi::SecretKeyMaterial::MLDSA65_Ed25519 {
                    eddsa: ed25519_private_key,
                    mldsa: mldsa_private_key_seed.into(),
                },
                sequoia_openpgp::types::PublicKeyAlgorithm::MLDSA65_Ed25519,
            ))
        } else {
            Ok((
                mpi::PublicKey::Ed25519 {
                    a: ed25519_public_key,
                },
                mpi::SecretKeyMaterial::Ed25519 {
                    x: ed25519_private_key,
                },
                sequoia_openpgp::types::PublicKeyAlgorithm::Ed25519,
            ))
        }
    } else if traditional_openssl_key.is_a(openssl::pkey::KeyType::ED448) {
        if profile != Profile::RFC9580 {
            return Err(anyhow::anyhow!(
                "Ed448 OpenPGP keys are only supported with RFC 9580 profile"
            ));
        }

        let ed448_public_key = traditional_openssl_key
            .raw_public_key()?
            .try_into()
            .map_err(|e: Vec<u8>| {
                anyhow::anyhow!("Expected a 57-byte Ed448 public key, got {} bytes", e.len())
            })?;
        let ed448_private_key = sequoia_openpgp::crypto::mem::Protected::from(
            traditional_openssl_key.raw_private_key()?,
        );

        if let Some(hybrid_key) = pqc_openssl_key {
            assert!(hybrid_key.is_a(openssl::pkey::KeyType::ML_DSA_87));
            let mut mldsa_private_key_seed = ossl::OsslSecret::new(32);
            let seed_length = hybrid_key.seed_into(&mut mldsa_private_key_seed)?;
            if seed_length != 32 {
                return Err(anyhow::anyhow!(
                    "Expected a 32-byte key seed, got {seed_length} bytes"
                ));
            }
            let mldsa_public_key =
                hybrid_key
                    .raw_public_key()?
                    .try_into()
                    .map_err(|e: Vec<u8>| {
                        anyhow::anyhow!(
                            "ML-DSA-87 public key was expected to be 2592 bytes, was {}",
                            e.len()
                        )
                    })?;
            Ok((
                mpi::PublicKey::MLDSA87_Ed448 {
                    eddsa: ed448_public_key,
                    mldsa: mldsa_public_key,
                },
                mpi::SecretKeyMaterial::MLDSA87_Ed448 {
                    eddsa: ed448_private_key,
                    mldsa: mldsa_private_key_seed.into(),
                },
                sequoia_openpgp::types::PublicKeyAlgorithm::MLDSA87_Ed448,
            ))
        } else {
            Ok((
                mpi::PublicKey::Ed448 {
                    a: ed448_public_key,
                },
                mpi::SecretKeyMaterial::Ed448 {
                    x: ed448_private_key,
                },
                sequoia_openpgp::types::PublicKeyAlgorithm::Ed448,
            ))
        }
    } else {
        Err(anyhow::anyhow!("Unsupported key type"))
    }
}

/// Convert an OpenSSL key object to a Sequoia OpenPGP key object.
fn openpgp_cert_for_key_private(
    openssl_key: &PKey<Private>,
    hybrid_key: Option<&PKey<Private>>,
    user_id: packet::UserID,
    profile: Profile,
    hash_algorithm: sequoia_openpgp::types::HashAlgorithm,
    validity_days: u32,
) -> anyhow::Result<String> {
    let (public, secret, algorithm) = openssl_keys_to_openpgp(openssl_key, hybrid_key, profile)?;
    let validity =
        (validity_days > 0).then(|| Duration::from_secs(u64::from(validity_days) * 24 * 60 * 60));
    let creation_time = std::time::SystemTime::now();
    let key: packet::key::Key<packet::key::SecretParts, packet::key::PrimaryRole> = match profile {
        Profile::RFC9580 => {
            packet::key::Key6::with_secret(creation_time, algorithm, public, secret.into())?.into()
        }
        Profile::RFC4880 => {
            packet::key::Key4::with_secret(creation_time, algorithm, public, secret.into())?.into()
        }
        _ => return Err(anyhow::anyhow!("Unsupported OpenPGP profile")),
    };
    let key_packet = packet::Packet::SecretKey(key.clone());

    let preferred_hashes = match profile {
        Profile::RFC9580 => vec![
            sequoia_openpgp::types::HashAlgorithm::SHA3_512,
            sequoia_openpgp::types::HashAlgorithm::SHA3_256,
            sequoia_openpgp::types::HashAlgorithm::SHA512,
            sequoia_openpgp::types::HashAlgorithm::SHA256,
        ],
        Profile::RFC4880 => vec![
            sequoia_openpgp::types::HashAlgorithm::SHA512,
            sequoia_openpgp::types::HashAlgorithm::SHA256,
        ],
        _ => return Err(anyhow::anyhow!("Unsupported OpenPGP profile")),
    };
    let preferred_symmetric_algorithms = vec![
        sequoia_openpgp::types::SymmetricAlgorithm::AES256,
        sequoia_openpgp::types::SymmetricAlgorithm::AES128,
    ];

    let builder = packet::signature::SignatureBuilder::new(SignatureType::DirectKey)
        .set_hash_algo(hash_algorithm)
        .set_signature_creation_time(creation_time)?
        .set_key_flags(KeyFlags::empty().set_signing().set_certification())?
        .set_features(sequoia_openpgp::types::Features::sequoia())?
        .set_key_validity_period(validity)?
        .set_preferred_hash_algorithms(preferred_hashes.clone())?
        .set_preferred_symmetric_algorithms(preferred_symmetric_algorithms.clone())?;
    let direct_key_signature =
        builder.sign_direct_key(&mut key.clone().into_keypair()?, key.parts_as_public())?;

    let builder = packet::signature::SignatureBuilder::new(SignatureType::PositiveCertification)
        .set_hash_algo(hash_algorithm)
        .set_signature_creation_time(creation_time)?
        .set_key_flags(KeyFlags::empty().set_signing().set_certification())?
        .set_features(sequoia_openpgp::types::Features::sequoia())?
        .set_key_validity_period(validity)?
        .set_preferred_hash_algorithms(preferred_hashes)?
        .set_preferred_symmetric_algorithms(preferred_symmetric_algorithms)?;
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

    Ok(String::from_utf8(cert.armored().to_vec()?)?)
}

/// Generate an OpenPGP certificate for the provided key.
pub fn openpgp_cert_for_key(
    config: &crate::server::Config,
    key_with_password: (&db::Key, Password),
    hybrid_key_with_password: Option<(&db::Key, Password)>,
    user_id: packet::UserID,
    profile: Profile,
    hash_algorithm: sequoia_openpgp::types::HashAlgorithm,
    validity_days: u32,
) -> anyhow::Result<String> {
    let (key, key_password) = key_with_password;
    let key_material = key
        .key_material
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("PKCS#11-backed OpenPGP keys aren't yet supported"))?;
    let key_pem = binding::unbind_with_pkcs11(&config.pkcs11_bindings, key_material)?;
    let openssl_key = key_password
        .map(|passphrase| PKey::private_key_from_pem_passphrase(key_pem.as_bytes(), passphrase))?;
    let openssl_hybrid_key = if let Some((key, key_password)) = hybrid_key_with_password {
        let key_material = key
            .key_material
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("PKCS#11-backed OpenPGP keys aren't yet supported"))?;
        let key_pem = binding::unbind_with_pkcs11(&config.pkcs11_bindings, key_material)?;
        let openssl_hybrid_key = key_password.map(|passphrase| {
            PKey::private_key_from_pem_passphrase(key_pem.as_bytes(), passphrase)
        })?;
        Some(openssl_hybrid_key)
    } else {
        None
    };

    openpgp_cert_for_key_private(
        &openssl_key,
        openssl_hybrid_key.as_ref(),
        user_id,
        profile,
        hash_algorithm,
        validity_days,
    )
}

/// The intended purpose for an X509 certificate.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[cfg_attr(feature = "cli", derive(clap::ValueEnum))]
#[non_exhaustive]
pub enum KeyUsage {
    #[default]
    CodeSigning,
    CertificateAuthority,
}

fn x509_certificate_for_key_private<P: HasPublic, S: HasPrivate>(
    pubkey: &PKey<P>,
    signing_key: &PKey<S>,
    issuer: Option<x509::X509>,
    subject_config: &crate::server::config::X509SubjectName,
    usage: KeyUsage,
    common_name: &str,
    validity_days: NonZeroU32,
) -> anyhow::Result<String> {
    let mut builder = x509::X509Builder::new()?;
    builder.set_pubkey(pubkey)?;

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
    // The digest is not selectable for these.
    let digest = if signing_key.is_a(OpenSSLKeyType::ED25519)
        || signing_key.is_a(OpenSSLKeyType::ED448)
        || signing_key.is_a(OpenSSLKeyType::ML_DSA_65)
        || signing_key.is_a(OpenSSLKeyType::ML_DSA_87)
    {
        openssl::hash::MessageDigest::null()
    } else {
        openssl::hash::MessageDigest::sha512()
    };
    builder.sign(signing_key, digest)?;
    let certificate = String::from_utf8(builder.build().to_pem()?)?;

    Ok(certificate)
}

/// Generate an X509 certificate for the provided key.
///
/// If the `certificate_authority` is `None`, the certificate will be self-signed.
/// The `key_password` is for the _signing key_, so the certificate authority if it's Some,
/// or the key if this will be a self-signed certificate.
pub fn x509_certificate_for_key(
    config: &crate::server::Config,
    key: db::Key,
    certificate_authority: Option<(db::Key, db::PublicKeyMaterial)>,
    key_password: Password,
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

    let key_material = if let Some(material) = &signing_key.key_material {
        material
    } else {
        return Err(anyhow::anyhow!(
            "CA keys in a PKCS#11 token aren't yet supported"
        ));
    };

    let pubkey = openssl::pkey::PKey::public_key_from_pem(key.public_key.as_bytes())?;
    let signing_key_pem = binding::unbind_with_pkcs11(&config.pkcs11_bindings, key_material)?;
    let signing_key = key_password.map(|passphrase| {
        openssl::pkey::PKey::private_key_from_pem_passphrase(signing_key_pem.as_bytes(), passphrase)
    })?;

    let certificate = x509_certificate_for_key_private(
        &pubkey,
        &signing_key,
        issuer,
        &config.certificate_subject,
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
        object::{Attribute, MlDsaParameterSetType},
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

                // Refer to https://www.rfc-editor.org/rfc/rfc8410.html#section-3
                let ed25519_oid = asn1::oid!(1, 3, 101, 112);
                let ed25519_oid_bytes = asn1::write_single(&ed25519_oid).unwrap();
                session.generate_key_pair(
                    &Mechanism::EccEdwardsKeyPairGen,
                    &[
                        Attribute::Id(vec![3]),
                        Attribute::Label(b"ed25519-test-key".to_vec()),
                        Attribute::Token(true),
                        Attribute::Private(false),
                        Attribute::EcParams(ed25519_oid_bytes),
                        Attribute::Verify(true),
                    ],
                    &[
                        Attribute::Id(vec![3]),
                        Attribute::Label(b"ed25519-test-key".to_vec()),
                        Attribute::Token(true),
                        Attribute::Private(true),
                        Attribute::Sensitive(true),
                        Attribute::Sign(true),
                    ],
                )?;

                // Refer to https://www.rfc-editor.org/rfc/rfc8410.html#section-3
                let ed448_oid = asn1::oid!(1, 3, 101, 113);
                let ed448_oid_bytes = asn1::write_single(&ed448_oid).unwrap();
                session.generate_key_pair(
                    &Mechanism::EccEdwardsKeyPairGen,
                    &[
                        Attribute::Id(vec![4]),
                        Attribute::Label(b"ed448-test-key".to_vec()),
                        Attribute::Token(true),
                        Attribute::Private(false),
                        Attribute::EcParams(ed448_oid_bytes),
                        Attribute::Verify(true),
                    ],
                    &[
                        Attribute::Id(vec![4]),
                        Attribute::Label(b"ed448-test-key".to_vec()),
                        Attribute::Token(true),
                        Attribute::Private(true),
                        Attribute::Sensitive(true),
                        Attribute::Sign(true),
                    ],
                )?;

                session.generate_key_pair(
                    &Mechanism::MlDsaKeyPairGen,
                    &[
                        Attribute::Id(vec![5]),
                        Attribute::Label(b"ml-dsa-65-test-key".to_vec()),
                        Attribute::Token(true),
                        Attribute::Private(false),
                        Attribute::ParameterSet(MlDsaParameterSetType::ML_DSA_65.into()),
                        Attribute::Verify(true),
                    ],
                    &[
                        Attribute::Id(vec![5]),
                        Attribute::Label(b"ml-dsa-65-test-key".to_vec()),
                        Attribute::Token(true),
                        Attribute::Private(true),
                        Attribute::Sensitive(true),
                        Attribute::Sign(true),
                    ],
                )?;

                session.generate_key_pair(
                    &Mechanism::MlDsaKeyPairGen,
                    &[
                        Attribute::Id(vec![6]),
                        Attribute::Label(b"ml-dsa-87-test-key".to_vec()),
                        Attribute::Token(true),
                        Attribute::Private(false),
                        Attribute::ParameterSet(MlDsaParameterSetType::ML_DSA_87.into()),
                        Attribute::Verify(true),
                    ],
                    &[
                        Attribute::Id(vec![6]),
                        Attribute::Label(b"ml-dsa-87-test-key".to_vec()),
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
                        Attribute::Id(vec![7]),
                        Attribute::Label(b"unsupported-rsa-key".to_vec()),
                        Attribute::Token(true),
                        Attribute::Private(false),
                        Attribute::Verify(true),
                        Attribute::ModulusBits(1024.into()),
                    ],
                    &[
                        Attribute::Id(vec![7]),
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
    use std::str::FromStr;

    use super::*;

    use openssl::pkey::KeyType;
    use sequoia_openpgp::types::PublicKeyAlgorithm;

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
    fn rsa_openpgp_certificate() -> anyhow::Result<()> {
        for bits in [2048, 4096] {
            let openssl_key = PKey::from_rsa(Rsa::generate(bits)?)?;

            let certificate = openpgp_cert_for_key_private(
                &openssl_key,
                None,
                "Someone <example.com>".into(),
                Profile::RFC4880,
                sequoia_openpgp::types::HashAlgorithm::SHA512,
                0,
            )?;
            let cert = sequoia_openpgp::cert::Cert::from_str(&certificate)?;
            assert!(!cert.is_tsk());
            assert!(cert.primary_key().key().pk_algo() == PublicKeyAlgorithm::RSAEncryptSign);
        }

        Ok(())
    }

    #[test]
    fn p256_openpgp_certificate() -> anyhow::Result<()> {
        let openssl_key = PKey::from_ec_key(EcKey::generate(
            EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?.as_ref(),
        )?)?;

        let certificate = openpgp_cert_for_key_private(
            &openssl_key,
            None,
            "Someone <example.com>".into(),
            Profile::RFC4880,
            sequoia_openpgp::types::HashAlgorithm::SHA512,
            0,
        )?;
        let cert = sequoia_openpgp::cert::Cert::from_str(&certificate)?;
        assert!(!cert.is_tsk());
        assert!(cert.primary_key().key().pk_algo() == PublicKeyAlgorithm::ECDSA);

        Ok(())
    }

    #[test]
    fn ed25519_openpgp_certificate() -> anyhow::Result<()> {
        let openssl_key = PKey::generate_ed25519()?;

        let certificate = openpgp_cert_for_key_private(
            &openssl_key,
            None,
            "Someone <example.com>".into(),
            Profile::RFC9580,
            sequoia_openpgp::types::HashAlgorithm::SHA512,
            0,
        )?;
        let cert = sequoia_openpgp::cert::Cert::from_str(&certificate)?;
        assert!(!cert.is_tsk());
        assert!(cert.primary_key().key().pk_algo() == PublicKeyAlgorithm::Ed25519);

        Ok(())
    }

    #[test]
    fn ed448_openpgp_certificate() -> anyhow::Result<()> {
        let openssl_key = PKey::generate_ed448()?;

        let certificate = openpgp_cert_for_key_private(
            &openssl_key,
            None,
            "Someone <example.com>".into(),
            Profile::RFC9580,
            sequoia_openpgp::types::HashAlgorithm::SHA512,
            0,
        )?;
        let cert = sequoia_openpgp::cert::Cert::from_str(&certificate)?;
        assert!(!cert.is_tsk());
        assert!(cert.primary_key().key().pk_algo() == PublicKeyAlgorithm::Ed448);

        Ok(())
    }

    #[test]
    fn mldsa65_ed25519_openpgp_certificate() -> anyhow::Result<()> {
        let openssl_key = PKey::generate_ed25519()?;
        let mut seed = [0; 32];
        openssl::rand::rand_priv_bytes(seed.as_mut_slice())?;
        let mldsa_key = PKey::private_key_from_seed(None, KeyType::ML_DSA_65, None, &seed)?;

        let certificate = openpgp_cert_for_key_private(
            &openssl_key,
            Some(&mldsa_key),
            "Someone <example.com>".into(),
            Profile::RFC9580,
            sequoia_openpgp::types::HashAlgorithm::SHA512,
            0,
        )?;
        let cert = sequoia_openpgp::cert::Cert::from_str(&certificate)?;
        assert!(!cert.is_tsk());
        assert!(cert.primary_key().key().pk_algo() == PublicKeyAlgorithm::MLDSA65_Ed25519);

        Ok(())
    }

    #[test]
    fn mldsa87_ed448_openpgp_certificate() -> anyhow::Result<()> {
        let openssl_key = PKey::generate_ed448()?;
        let mut seed = [0; 32];
        openssl::rand::rand_priv_bytes(seed.as_mut_slice())?;
        let mldsa_key = PKey::private_key_from_seed(None, KeyType::ML_DSA_87, None, &seed)?;

        let certificate = openpgp_cert_for_key_private(
            &openssl_key,
            Some(&mldsa_key),
            "Someone <example.com>".into(),
            Profile::RFC9580,
            sequoia_openpgp::types::HashAlgorithm::SHA512,
            0,
        )?;
        let cert = sequoia_openpgp::cert::Cert::from_str(&certificate)?;
        assert!(!cert.is_tsk());
        assert!(cert.primary_key().key().pk_algo() == PublicKeyAlgorithm::MLDSA87_Ed448);

        Ok(())
    }

    #[test]
    fn openssl_ed25519_to_openpgp_rfc4880_fails() -> anyhow::Result<()> {
        let openssl_key = PKey::generate_ed25519()?;

        let error = openssl_keys_to_openpgp(&openssl_key, None, Profile::RFC4880).unwrap_err();
        assert_eq!(
            error.to_string(),
            "Ed25519 OpenPGP keys are only supported with RFC 9580 profile"
        );

        Ok(())
    }

    #[test]
    fn openssl_ed25519_to_openpgp() -> anyhow::Result<()> {
        let openssl_key = PKey::generate_ed25519()?;

        let (_public_key, _private_key, algorithm) =
            openssl_keys_to_openpgp(&openssl_key, None, Profile::RFC9580).unwrap();
        assert!(algorithm == PublicKeyAlgorithm::Ed25519);

        Ok(())
    }

    #[test]
    fn openssl_ed448_to_openpgp_rfc4880_fails() -> anyhow::Result<()> {
        let openssl_key = PKey::generate_ed448()?;

        let error = openssl_keys_to_openpgp(&openssl_key, None, Profile::RFC4880).unwrap_err();
        assert_eq!(
            error.to_string(),
            "Ed448 OpenPGP keys are only supported with RFC 9580 profile"
        );

        Ok(())
    }

    #[test]
    fn openssl_ed448_to_openpgp() -> anyhow::Result<()> {
        let openssl_key = PKey::generate_ed448()?;

        let (_public_key, _private_key, algorithm) =
            openssl_keys_to_openpgp(&openssl_key, None, Profile::RFC9580).unwrap();
        assert!(algorithm == PublicKeyAlgorithm::Ed448);

        Ok(())
    }

    #[test]
    fn rsa_openpgp_cert_for_key() -> anyhow::Result<()> {
        let config = crate::server::Config::default();
        let key_password = Password::from("test-key-password");

        let openssl_key = PKey::from_rsa(Rsa::generate(4096)?)?;
        let public_key = String::from_utf8(openssl_key.public_key_to_pem()?)?;
        let encrypted_key = encrypt_key(key_password.clone(), openssl_key)?;
        let key = db::Key {
            id: 1,
            hybrid_pair_id: None,
            name: "test-rsa-key".to_string(),
            key_algorithm: KeyAlgorithm::Rsa4K,
            handle: "test-handle".to_string(),
            key_material: Some(binding::bind_with_pkcs11(&[], &encrypted_key)?),
            public_key,
            pkcs11_token_id: None,
            pkcs11_key_id: None,
        };

        let certificate = openpgp_cert_for_key(
            &config,
            (&key, key_password.clone()),
            None,
            "Someone <example.com>".into(),
            Profile::RFC9580,
            sequoia_openpgp::types::HashAlgorithm::SHA512,
            0,
        )?;
        let cert = sequoia_openpgp::cert::Cert::from_str(&certificate)?;
        assert!(!cert.is_tsk());
        assert!(cert.primary_key().key().pk_algo() == PublicKeyAlgorithm::RSAEncryptSign);

        Ok(())
    }

    #[test]
    fn mldsa65_ed25519_openpgp_cert_for_key() -> anyhow::Result<()> {
        let config = crate::server::Config::default();
        let key_password = Password::from("test-key-password");

        let openssl_key = PKey::generate_ed25519()?;
        let public_key = String::from_utf8(openssl_key.public_key_to_pem()?)?;
        let encrypted_key = encrypt_key(key_password.clone(), openssl_key)?;
        let key = db::Key {
            id: 1,
            hybrid_pair_id: None,
            name: "test-ed25519-key".to_string(),
            key_algorithm: KeyAlgorithm::Ed25519,
            handle: "test-handle".to_string(),
            key_material: Some(binding::bind_with_pkcs11(&[], &encrypted_key)?),
            public_key,
            pkcs11_token_id: None,
            pkcs11_key_id: None,
        };

        let mut seed = [0; 32];
        openssl::rand::rand_priv_bytes(seed.as_mut_slice())?;
        let mldsa_key = PKey::private_key_from_seed(None, KeyType::ML_DSA_65, None, &seed)?;
        let public_key = String::from_utf8(mldsa_key.public_key_to_pem()?)?;
        let encrypted_key = encrypt_key(key_password.clone(), mldsa_key)?;
        let pqc_key = db::Key {
            id: 2,
            hybrid_pair_id: Some(1),
            name: "test-mldsa-65-key".to_string(),
            key_algorithm: KeyAlgorithm::Mldsa65,
            handle: "test-handle".to_string(),
            key_material: Some(binding::bind_with_pkcs11(&[], &encrypted_key)?),
            public_key,
            pkcs11_token_id: None,
            pkcs11_key_id: None,
        };

        let user_id = packet::UserID::from("Test User <test@example.com>");

        let certificate = openpgp_cert_for_key(
            &config,
            (&key, key_password.clone()),
            Some((&pqc_key, key_password.clone())),
            user_id.clone(),
            Profile::RFC9580,
            sequoia_openpgp::types::HashAlgorithm::SHA512,
            0,
        )?;
        let cert = sequoia_openpgp::cert::Cert::from_str(&certificate)?;
        assert!(!cert.is_tsk());
        assert!(cert.primary_key().key().pk_algo() == PublicKeyAlgorithm::MLDSA65_Ed25519);

        Ok(())
    }
}

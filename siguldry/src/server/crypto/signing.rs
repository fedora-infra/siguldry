// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! Functions for signing content.
//!
//! This includes functions for signing using PGP, or using various key algorithms (RSA PKCS #1
//! v1.5, ECDSA, etc).

use anyhow::Context;
use asn1::{ObjectIdentifier, oid};
use cryptoki::{mechanism::Mechanism, session::Session};
use openssl::{ec::EcKey, pkey::PKey, pkey_ctx::PkeyCtx, rsa::Rsa};
use sequoia_openpgp::crypto::Password;

use crate::{
    protocol::{self, DigestAlgorithm, KeyAlgorithm, json::SignaturePayload},
    server::db,
};

// Algorithm identifiers for RSA PKCS v1.5 DigestInfo structures.
// SHA OID references: https://www.ietf.org/rfc/rfc4055.html#section-6
// SHA3 OID references: https://www.ietf.org/rfc/rfc9688.html#name-message-digest-algorithms
const OID_SHA256: ObjectIdentifier = oid!(2, 16, 840, 1, 101, 3, 4, 2, 1);
const OID_SHA512: ObjectIdentifier = oid!(2, 16, 840, 1, 101, 3, 4, 2, 3);
const OID_SHA3_256: ObjectIdentifier = oid!(2, 16, 840, 1, 101, 3, 4, 2, 8);
const OID_SHA3_512: ObjectIdentifier = oid!(2, 16, 840, 1, 101, 3, 4, 2, 10);

/// Used for RSA PKCS1 v1.5 signatures.
/// Reference: https://www.ietf.org/rfc/rfc8017.html#section-9.2
#[derive(asn1::Asn1Write, asn1::Asn1Read)]
struct DigestInfo<'a> {
    digest_algorithm: AlgorithmIdentifier,
    digest: &'a [u8],
}

#[derive(asn1::Asn1Write, asn1::Asn1Read)]
struct AlgorithmIdentifier {
    algorithm: ObjectIdentifier,
    parameters: (),
}

/// Encode a hash into DigestInfo structure for RSA PKCS#1 v1.5 signatures.
fn encode_digest_info(algorithm: DigestAlgorithm, hash: &[u8]) -> anyhow::Result<Vec<u8>> {
    let algorithm_oid = match algorithm {
        DigestAlgorithm::Sha256 => OID_SHA256,
        DigestAlgorithm::Sha512 => OID_SHA512,
        DigestAlgorithm::Sha3_256 => OID_SHA3_256,
        DigestAlgorithm::Sha3_512 => OID_SHA3_512,
    };

    let digest_info = DigestInfo {
        digest_algorithm: AlgorithmIdentifier {
            algorithm: algorithm_oid,
            parameters: (),
        },
        digest: hash,
    };

    asn1::write_single(&digest_info)
        .map_err(|e| anyhow::anyhow!("Failed to encode DigestInfo: {e}"))
}

/// Decode a DER-encoded DigestInfo structure into the digest algorithm and digest itself.
pub fn decode_digest_info(digest_info: &[u8]) -> anyhow::Result<(DigestAlgorithm, Vec<u8>)> {
    let digest_info = asn1::parse_single::<DigestInfo<'_>>(digest_info)?;
    let algorithm = match digest_info.digest_algorithm.algorithm {
        OID_SHA256 => DigestAlgorithm::Sha256,
        OID_SHA3_256 => DigestAlgorithm::Sha3_256,
        OID_SHA512 => DigestAlgorithm::Sha512,
        OID_SHA3_512 => DigestAlgorithm::Sha3_512,
        _ => return Err(anyhow::anyhow!("Unknown digest algorithm in DigestInfo")),
    };
    let hash = digest_info.digest.to_vec();
    Ok((algorithm, hash))
}

/// Sign a set of digests with a key stored in the database protected by a password.
pub fn sign_with_softkey(
    key: &db::Key,
    password: &Password,
    digests: Vec<(DigestAlgorithm, String)>,
) -> anyhow::Result<Vec<protocol::json::Signature>> {
    let pkey = match key.key_algorithm {
        KeyAlgorithm::Rsa4K | KeyAlgorithm::Rsa2K => password
            .map(|password| {
                Rsa::private_key_from_pem_passphrase(key.key_material.as_bytes(), password)
            })
            .and_then(PKey::from_rsa),
        KeyAlgorithm::P256 => password
            .map(|password| {
                EcKey::private_key_from_pem_passphrase(key.key_material.as_bytes(), password)
            })
            .and_then(PKey::from_ec_key),
    }?;

    let mut signatures = Vec::with_capacity(digests.len());
    for (algorithm, hex_hash) in digests {
        let hash = hex::decode(&hex_hash).context("The digest provided was not valid hex")?;
        if hash.len() != algorithm.size() {
            return Err(anyhow::anyhow!(
                "The specified digest algorithm is {} bytes; payload was {}",
                algorithm.size(),
                hash.len()
            ));
        }

        let mut ctx = PkeyCtx::new(&pkey)?;
        ctx.sign_init()?;
        ctx.set_signature_md(algorithm.into())?;
        if key.key_algorithm == KeyAlgorithm::Rsa4K {
            // PKCS #1 should be the default, but lets be explicit about it.
            ctx.set_rsa_padding(openssl::rsa::Padding::PKCS1)?;
        }
        let mut signature = vec![];
        ctx.sign_to_vec(&hash, &mut signature)?;
        let signature = match key.key_algorithm {
            KeyAlgorithm::Rsa2K | KeyAlgorithm::Rsa4K => {
                protocol::json::SignaturePayload::RSA(signature)
            }
            KeyAlgorithm::P256 => protocol::json::SignaturePayload::P256(signature),
        };
        signatures.push(protocol::json::Signature {
            signature,
            digest: algorithm,
            hash: hex_hash,
        });
    }

    Ok(signatures)
}

/// Sign a set of digests with a PKCS#11-backed key
pub fn sign_with_pkcs11(
    key: &db::Key,
    session: &Session,
    digests: Vec<(DigestAlgorithm, String)>,
) -> anyhow::Result<Vec<protocol::json::Signature>> {
    let private_key = key.get_pkcs11_private_key(session)?;

    let mut signatures = Vec::with_capacity(digests.len());
    for (algorithm, hex_hash) in digests {
        let hash = hex::decode(&hex_hash).context("The digest provided was not valid hex")?;
        if hash.len() != algorithm.size() {
            return Err(anyhow::anyhow!(
                "The specified digest algorithm is {} bytes; payload was {}",
                algorithm.size(),
                hash.len()
            ));
        }

        // Select the appropriate PKCS#11 mechanism and data format based on key type;
        // the input/output from PKCS#11 signing mechanisms don't match OpenSSL, so we
        // need to handle the differences here
        let (mechanism, data_to_sign) = match key.key_algorithm {
            KeyAlgorithm::Rsa4K | KeyAlgorithm::Rsa2K => {
                // For RSA PKCS#1 v1.5 with CKM_RSA_PKCS, we need to provide DigestInfo
                // structure (DER-encoded hash algorithm OID + hash value)
                let digest_info = encode_digest_info(algorithm, &hash)?;
                (Mechanism::RsaPkcs, digest_info)
            }
            KeyAlgorithm::P256 => {
                // ECDSA mechanism expects raw hash bytes
                (Mechanism::Ecdsa, hash)
            }
        };

        let signature = session
            .sign(&mechanism, private_key, &data_to_sign)
            .context("PKCS#11 signing operation failed")?;

        let signature = match key.key_algorithm {
            KeyAlgorithm::Rsa4K | KeyAlgorithm::Rsa2K => SignaturePayload::RSA(signature),
            KeyAlgorithm::P256 => {
                // Softkey signatures use OpenSSL, which return a DER-encoded signature, while PKCS #11
                // returns the raw r and s values (refer to https://www.ietf.org/rfc/rfc6979.html#appendix-A.1.3).
                // In order to be consistent, we'll always return the DER-encoded signature.
                let r = signature
                    .get(..32)
                    .map(openssl::bn::BigNum::from_slice)
                    .expect("A P256 signature should be 64 bytes")?;
                let s = signature
                    .get(32..)
                    .map(openssl::bn::BigNum::from_slice)
                    .expect("A P256 signature should be 64 bytes")?;
                let ecdsa_sig = openssl::ecdsa::EcdsaSig::from_private_components(r, s)?;
                SignaturePayload::P256(ecdsa_sig.to_der()?)
            }
        };

        signatures.push(protocol::json::Signature {
            signature,
            digest: algorithm,
            hash: hex_hash,
        });
    }

    Ok(signatures)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::process::Command;

    use anyhow::Result;
    use tempfile::TempDir;
    use zerocopy::IntoBytes;

    use super::*;
    use crate::protocol::DigestAlgorithm;
    use crate::server::crypto;
    use crate::server::crypto::test_utils::setup_hsm;
    use crate::server::crypto::token::import_pkcs11_token;

    #[test]
    fn encode_decode_digest_info() -> Result<()> {
        let algorithm = DigestAlgorithm::Sha256;
        let hash = openssl::hash::hash(algorithm.into(), b"data")?;
        let encoded = encode_digest_info(algorithm, &hash)?;
        let (decoded_algorithm, decoded_hash) = decode_digest_info(&encoded)?;

        assert_eq!(
            algorithm, decoded_algorithm,
            "Digest algorithm should match"
        );
        assert_eq!(hash.as_bytes(), &decoded_hash, "Digest should match");

        Ok(())
    }

    #[tokio::test]
    async fn sign_with_pkcs11_rsa_key() -> Result<()> {
        let hsm = setup_hsm()?;
        let db_pool = db::pool("sqlite::memory:", false).await?;
        db::migrate(&db_pool).await?;
        let mut conn = db_pool.begin().await?;

        let token = import_pkcs11_token(
            &mut conn,
            PathBuf::from("/usr/lib64/pkcs11/libkryoptic_pkcs11.so"),
            None,
            hsm.user_pin.clone(),
        )
        .await?;
        let pkcs11 = token.intialize()?;
        let session = token.pkcs11_session(&pkcs11, &hsm.user_pin)?;

        let keys = db::Key::list(&mut conn).await?;
        let rsa_key = keys
            .iter()
            .find(|k| k.key_algorithm == KeyAlgorithm::Rsa4K)
            .expect("Should have an RSA key");

        let data = b"test data";
        let digest = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), data)?;
        let hex_hash = hex::encode(digest);
        let signatures = super::sign_with_pkcs11(
            rsa_key,
            &session,
            vec![(DigestAlgorithm::Sha256, hex_hash.clone())],
        )?;
        pkcs11.finalize()?;
        assert_eq!(signatures.len(), 1);
        assert_eq!(signatures.first().unwrap().digest, DigestAlgorithm::Sha256);
        assert_eq!(signatures.first().unwrap().hash, hex_hash);
        assert!(!signatures.first().unwrap().signature.is_empty());

        // Verify the signature using the public key via OpenSSL Rust bindings
        let public_key = openssl::pkey::PKey::public_key_from_pem(rsa_key.public_key.as_bytes())?;
        let mut ctx = openssl::pkey_ctx::PkeyCtx::new(&public_key)?;
        ctx.verify_init()?;
        ctx.set_signature_md(openssl::md::Md::sha256())?;
        ctx.set_rsa_padding(openssl::rsa::Padding::PKCS1)?;
        let signature = signatures.first().unwrap().signature.as_ref();
        let result = ctx.verify(&digest, signature)?;
        assert!(result, "Signature should be valid (OpenSSL bindings)");

        // Also verify using the OpenSSL CLI in case I'm using the bindings wrong
        let data_path = hsm.directory.path().join("unsigned_data");
        let signature_path = hsm.directory.path().join("signature.bin");
        let pubkey_path = hsm.directory.path().join("pubkey.pem");
        std::fs::write(&data_path, data)?;
        std::fs::write(&signature_path, signature)?;
        std::fs::write(&pubkey_path, rsa_key.public_key.as_bytes())?;
        let output = Command::new("openssl")
            .args(["dgst", "-sha256", "-verify"])
            .arg(&pubkey_path)
            .arg("-signature")
            .arg(&signature_path)
            .arg(&data_path)
            .output()?;

        assert!(
            output.status.success(),
            "OpenSSL CLI verification failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        Ok(())
    }

    #[tokio::test]
    async fn sign_with_pkcs11_ecc_key() -> Result<()> {
        let hsm = setup_hsm()?;
        let db_pool = db::pool("sqlite::memory:", false).await?;
        db::migrate(&db_pool).await?;
        let mut conn = db_pool.begin().await?;

        let token = import_pkcs11_token(
            &mut conn,
            PathBuf::from("/usr/lib64/pkcs11/libkryoptic_pkcs11.so"),
            None,
            hsm.user_pin.clone(),
        )
        .await?;
        let pkcs11 = token.intialize()?;
        let session = token.pkcs11_session(&pkcs11, &hsm.user_pin)?;

        let keys = db::Key::list(&mut conn).await?;
        let ecc_key = keys
            .iter()
            .find(|k| k.key_algorithm == KeyAlgorithm::P256)
            .expect("Should have an ECC key");

        let data = b"test data";
        let digest = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), data)?;
        let hex_hash = hex::encode(digest);

        let signatures = super::sign_with_pkcs11(
            ecc_key,
            &session,
            vec![(DigestAlgorithm::Sha256, hex_hash.clone())],
        )?;
        pkcs11.finalize()?;

        assert_eq!(signatures.len(), 1);
        assert_eq!(signatures.first().unwrap().digest, DigestAlgorithm::Sha256);
        assert_eq!(signatures.first().unwrap().hash, hex_hash);
        assert!(!signatures.first().unwrap().signature.is_empty());

        let public_key = openssl::pkey::PKey::public_key_from_pem(ecc_key.public_key.as_bytes())?;
        let ec_key = public_key.ec_key()?;
        let signature = signatures.first().unwrap().signature.as_ref();
        let ecdsa_sig = openssl::ecdsa::EcdsaSig::from_der(signature)?;
        assert!(
            ecdsa_sig.verify(&digest, &ec_key)?,
            "ECDSA signature should be valid (OpenSSL bindings)"
        );

        // Also verify using the OpenSSL CLI in case I'm using the bindings wrong
        let data_path = hsm.directory.path().join("unsigned_data");
        let signature_path = hsm.directory.path().join("signature.bin");
        let pubkey_path = hsm.directory.path().join("pubkey.pem");
        std::fs::write(&data_path, data)?;
        std::fs::write(&signature_path, signature)?;
        std::fs::write(&pubkey_path, ecc_key.public_key.as_bytes())?;
        let output = Command::new("openssl")
            .args(["dgst", "-sha256", "-verify"])
            .arg(&pubkey_path)
            .arg("-signature")
            .arg(&signature_path)
            .arg(&data_path)
            .output()?;

        assert!(
            output.status.success(),
            "OpenSSL CLI verification failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        Ok(())
    }

    #[tokio::test]
    async fn sign_with_softkey_rsa() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let user_password = Password::from("test-key-password");

        let key_algorithm = KeyAlgorithm::Rsa4K;
        let (handle, key_access_password, key_material, public_key) =
            crypto::create_encrypted_key(&[], user_password.clone(), key_algorithm)?;
        let key_password =
            crypto::binding::decrypt_key_password(&[], user_password, &key_access_password).await?;
        let key = db::Key {
            id: 1,
            name: "test-rsa-softkey".to_string(),
            key_algorithm,
            key_purpose: db::KeyPurpose::Signing,
            handle,
            key_material,
            public_key,
            pkcs11_token_id: None,
            pkcs11_key_id: None,
        };

        let data = b"test data";
        let digest = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), data)?;
        let hex_hash = hex::encode(digest);

        let signatures = super::sign_with_softkey(
            &key,
            &key_password,
            vec![(DigestAlgorithm::Sha256, hex_hash.clone())],
        )?;

        assert_eq!(signatures.len(), 1);
        assert_eq!(signatures.first().unwrap().digest, DigestAlgorithm::Sha256);
        assert_eq!(signatures.first().unwrap().hash, hex_hash);
        assert!(!signatures.first().unwrap().signature.is_empty());

        // Verify the signature using OpenSSL Rust bindings
        let public_key = openssl::pkey::PKey::public_key_from_pem(key.public_key.as_bytes())?;
        let mut ctx = openssl::pkey_ctx::PkeyCtx::new(&public_key)?;
        ctx.verify_init()?;
        ctx.set_signature_md(openssl::md::Md::sha256())?;
        ctx.set_rsa_padding(openssl::rsa::Padding::PKCS1)?;
        let signature = signatures.first().unwrap().signature.as_ref();
        let result = ctx.verify(&digest, signature)?;
        assert!(result, "Signature should be valid (OpenSSL bindings)");

        // Also verify using the OpenSSL CLI in case I'm using the bindings wrong
        let data_path = temp_dir.path().join("unsigned_data");
        let signature_path = temp_dir.path().join("signature.bin");
        let pubkey_path = temp_dir.path().join("pubkey.pem");
        std::fs::write(&data_path, data)?;
        std::fs::write(&signature_path, signature)?;
        std::fs::write(&pubkey_path, key.public_key.as_bytes())?;
        let output = Command::new("openssl")
            .args(["dgst", "-sha256", "-verify"])
            .arg(&pubkey_path)
            .arg("-signature")
            .arg(&signature_path)
            .arg(&data_path)
            .output()?;

        assert!(
            output.status.success(),
            "OpenSSL CLI verification failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        Ok(())
    }

    #[tokio::test]
    async fn sign_with_softkey_ecc() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let user_password = Password::from("test-key-password");

        let key_algorithm = KeyAlgorithm::P256;
        let (handle, key_access_password, key_material, public_key) =
            crypto::create_encrypted_key(&[], user_password.clone(), key_algorithm)?;
        let key_password =
            crypto::binding::decrypt_key_password(&[], user_password, &key_access_password).await?;
        let key = db::Key {
            id: 1,
            name: "test-ecc-softkey".to_string(),
            key_algorithm,
            key_purpose: db::KeyPurpose::Signing,
            handle,
            key_material,
            public_key,
            pkcs11_token_id: None,
            pkcs11_key_id: None,
        };

        let data = b"test data for ECC softkey signing";
        let digest = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), data)?;
        let hex_hash = hex::encode(digest);

        let signatures = super::sign_with_softkey(
            &key,
            &key_password,
            vec![(DigestAlgorithm::Sha256, hex_hash.clone())],
        )?;

        assert_eq!(signatures.len(), 1);
        assert_eq!(signatures.first().unwrap().digest, DigestAlgorithm::Sha256);
        assert_eq!(signatures.first().unwrap().hash, hex_hash);
        assert!(!signatures.first().unwrap().signature.is_empty());

        let public_key = openssl::pkey::PKey::public_key_from_pem(key.public_key.as_bytes())?;
        let ec_key = public_key.ec_key()?;
        let signature = signatures.first().unwrap().signature.as_ref();
        let ecdsa_sig = openssl::ecdsa::EcdsaSig::from_der(signature)?;
        assert!(
            ecdsa_sig.verify(&digest, &ec_key)?,
            "ECDSA signature should be valid (OpenSSL bindings)"
        );

        // Also verify using the OpenSSL CLI in case I'm using the bindings wrong
        let data_path = temp_dir.path().join("unsigned_data");
        let signature_path = temp_dir.path().join("signature.bin");
        let pubkey_path = temp_dir.path().join("pubkey.pem");
        std::fs::write(&data_path, data)?;
        std::fs::write(&signature_path, signature)?;
        std::fs::write(&pubkey_path, key.public_key.as_bytes())?;
        let output = Command::new("openssl")
            .args(["dgst", "-sha256", "-verify"])
            .arg(&pubkey_path)
            .arg("-signature")
            .arg(&signature_path)
            .arg(&data_path)
            .output()?;

        assert!(
            output.status.success(),
            "OpenSSL CLI verification failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        Ok(())
    }
}

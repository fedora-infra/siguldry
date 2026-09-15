// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! Functions for signing content.
//!
//! This includes functions for signing using PGP, or using various key algorithms (RSA PKCS #1
//! v1.5, ECDSA, etc).

use anyhow::Context;
use cryptoki::{
    mechanism::{
        Mechanism,
        dsa::SignAdditionalContext,
        eddsa::{EddsaParams, EddsaSignatureScheme},
    },
    session::Session,
};
use openssl::{pkey::PKey, pkey_ctx::PkeyCtx};

use crate::{
    protocol::{self, DigestAlgorithm, KeyAlgorithm, SignaturePayload},
    server::db,
};

/// Sign a set of digests with a key stored in the database protected by a password.
pub fn sign_with_softkey(
    key: &db::Key,
    pkey: &PKey<openssl::pkey::Private>,
    digests: Vec<(DigestAlgorithm, String)>,
) -> anyhow::Result<Vec<protocol::Signature>> {
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

        let signature = match key.key_algorithm {
            KeyAlgorithm::Mldsa65 | KeyAlgorithm::Mldsa87 => {
                // Wonkiness ahead: the openssl crate does not yet expose an API for signing
                // with ML-DSA. The ossl crate, spun out from kryoptic does, so for now we use
                // that here. It's not ideal, and once the openssl crate does expose the APIs
                // we need we should probably switch.

                // Convert the key to ossl's object
                let mut seed = ossl::OsslSecret::new(32);
                let seed_length = pkey
                    .seed_into(&mut seed)
                    .context("Failed to extract the ML-DSA private key seed")?;
                assert!(seed_length == 32);
                let key_data = ossl::pkey::PkeyData::Mlkey(ossl::pkey::MlkeyData {
                    pubkey: None,
                    prikey: None,
                    seed: Some(seed),
                });
                let (key_type, signature_algorithm) = match key.key_algorithm {
                    KeyAlgorithm::Mldsa65 => (
                        ossl::pkey::EvpPkeyType::Mldsa65,
                        ossl::signature::SigAlg::Mldsa65,
                    ),
                    KeyAlgorithm::Mldsa87 => (
                        ossl::pkey::EvpPkeyType::Mldsa87,
                        ossl::signature::SigAlg::Mldsa87,
                    ),
                    _ => unreachable!(),
                };
                let context = ossl::OsslContext::new_lib_ctx();
                let mut pkey = ossl::pkey::EvpPkey::import(&context, key_type, key_data)
                    .context("Failed to import the ML-DSA private key")?;

                let mut parameters = ossl::OsslParamBuilder::with_capacity(2);
                // TODO add tunables for this
                parameters.add_owned_int(c"deterministic", 1)?;
                parameters.add_owned_int(c"mu", 1)?;
                let parameters = parameters.finalize();
                let mut signer = ossl::signature::OsslSignature::new(
                    &context,
                    ossl::signature::SigOp::Sign,
                    signature_algorithm,
                    &mut pkey,
                    Some(&parameters),
                )
                .context("Failed to initialize ML-DSA signing")?;
                let signature_length = signer.sign(&hash, None)?;
                let mut signature = vec![0; signature_length];
                let signature_length = signer.sign(&hash, Some(&mut signature))?;
                // the openssl crate truncates and notes the length you get from the initial probe may
                // not match the actual length?
                signature.truncate(signature_length);

                signature
            }
            KeyAlgorithm::Ed25519 | KeyAlgorithm::Ed448 => {
                let mut signer = openssl::sign::Signer::new_without_digest(pkey)?;
                signer.sign_oneshot_to_vec(&hash)?
            }
            _ => {
                let mut ctx = PkeyCtx::new(pkey)?;
                ctx.sign_init()?;
                ctx.set_signature_md(algorithm.into())?;
                if matches!(key.key_algorithm, KeyAlgorithm::Rsa2K | KeyAlgorithm::Rsa4K) {
                    // PKCS #1 should be the default, but lets be explicit about it.
                    ctx.set_rsa_padding(openssl::rsa::Padding::PKCS1)?;
                }
                let mut signature = vec![];
                ctx.sign_to_vec(&hash, &mut signature)?;
                signature
            }
        };
        let signature = match key.key_algorithm {
            KeyAlgorithm::Rsa2K | KeyAlgorithm::Rsa4K => protocol::SignaturePayload::RSA(signature),
            KeyAlgorithm::P256 => protocol::SignaturePayload::P256(signature),
            KeyAlgorithm::Ed25519 | KeyAlgorithm::Ed448 => {
                protocol::SignaturePayload::PureEdDSA(signature)
            }
            KeyAlgorithm::Mldsa65 | KeyAlgorithm::Mldsa87 => {
                protocol::SignaturePayload::PureMLDSA(signature)
            }
        };

        tracing::info!(digest_algorithm=%algorithm, digest=hex_hash, "Signature issued");
        signatures.push(protocol::Signature {
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
) -> anyhow::Result<Vec<protocol::Signature>> {
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
                let digest_info = crate::der::encode_digest_info(algorithm, &hash)?;
                (Mechanism::RsaPkcs, digest_info)
            }
            KeyAlgorithm::P256 => {
                // ECDSA mechanism expects raw hash bytes
                (Mechanism::Ecdsa, hash)
            }
            KeyAlgorithm::Ed25519 | KeyAlgorithm::Ed448 => (
                Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Pure)),
                hash,
            ),
            KeyAlgorithm::Mldsa65 | KeyAlgorithm::Mldsa87 => (
                // TODO: Allow hedge type to be configured somewhere
                Mechanism::MlDsa(SignAdditionalContext::new(Default::default(), None)),
                hash,
            ),
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
            KeyAlgorithm::Ed25519 | KeyAlgorithm::Ed448 => SignaturePayload::PureEdDSA(signature),
            KeyAlgorithm::Mldsa65 | KeyAlgorithm::Mldsa87 => SignaturePayload::PureMLDSA(signature),
        };

        tracing::info!(digest_algorithm=%algorithm, digest=hex_hash, "Signature issued");
        signatures.push(protocol::Signature {
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
    use ossl::OsslContext;
    use ossl::pkey::{EvpPkey, EvpPkeyType, MlkeyData, PkeyData};
    use ossl::signature::{OsslSignature, SigAlg, SigOp};
    use sequoia_openpgp::crypto::Password;
    use tempfile::TempDir;
    use zerocopy::IntoBytes;

    use super::*;
    use crate::der::{decode_digest_info, encode_digest_info};
    use crate::protocol::DigestAlgorithm;
    use crate::server::crypto;
    use crate::server::crypto::binding::decrypt_private_key;
    use crate::server::crypto::test_utils::setup_hsm;
    use crate::server::crypto::token::import_pkcs11_token;

    fn verify_mldsa_signature(
        key_algorithm: KeyAlgorithm,
        public_key_pem: &str,
        data: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        let (pkey_type, signature_algorithm) = match key_algorithm {
            KeyAlgorithm::Mldsa65 => (EvpPkeyType::Mldsa65, SigAlg::Mldsa65),
            KeyAlgorithm::Mldsa87 => (EvpPkeyType::Mldsa87, SigAlg::Mldsa87),
            _ => unreachable!("The test only verifies ML-DSA keys"),
        };
        let public_key = PKey::public_key_from_pem(public_key_pem.as_bytes())?;
        let key_data = PkeyData::Mlkey(MlkeyData {
            pubkey: Some(public_key.raw_public_key()?),
            prikey: None,
            seed: None,
        });
        let context = OsslContext::new_lib_ctx();
        let mut public_key = EvpPkey::import(&context, pkey_type, key_data)?;
        let parameters = ossl::signature::mldsa_params(false, None, false)?;
        let mut verifier = OsslSignature::new(
            &context,
            SigOp::Verify,
            signature_algorithm,
            &mut public_key,
            parameters.as_ref(),
        )?;
        verifier.verify(data, Some(signature))?;
        Ok(())
    }

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
        let slot = token.slot(&pkcs11)?;
        let session = pkcs11.open_ro_session(slot)?;
        session.login(cryptoki::session::UserType::User, Some(&hsm.user_pin))?;

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
        let slot = token.slot(&pkcs11)?;
        let session = pkcs11.open_ro_session(slot)?;
        session.login(cryptoki::session::UserType::User, Some(&hsm.user_pin))?;

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
    async fn sign_with_pkcs11_mldsa_keys() -> Result<()> {
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
        let slot = token.slot(&pkcs11)?;
        let session = pkcs11.open_ro_session(slot)?;
        session.login(cryptoki::session::UserType::User, Some(&hsm.user_pin))?;

        let data = b"test data for PKCS11 ML-DSA signing";
        let digest = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), data)?;
        let hex_hash = hex::encode(digest);
        let keys = db::Key::list(&mut conn).await?;
        for key_algorithm in [KeyAlgorithm::Mldsa65, KeyAlgorithm::Mldsa87] {
            let key = keys
                .iter()
                .find(|key| key.key_algorithm == key_algorithm)
                .expect("Should have an ML-DSA key");
            let signatures = super::sign_with_pkcs11(
                key,
                &session,
                vec![(DigestAlgorithm::Sha256, hex_hash.clone())],
            )?;
            let signature = signatures.first().unwrap().signature.as_ref();
            verify_mldsa_signature(key_algorithm, &key.public_key, &digest, signature)?;
        }
        pkcs11.finalize()?;

        Ok(())
    }

    #[tokio::test]
    async fn sign_with_softkey_rsa() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let user_password = Password::from("test-key-password");

        let key_algorithm = KeyAlgorithm::Rsa4K;
        let (encrypted_key, _) = crypto::create_encrypted_key(
            &crate::server::Config::default(),
            user_password.clone(),
            key_algorithm,
            None,
            Default::default(),
            Default::default(),
        )?;
        let key = db::Key {
            id: 1,
            hybrid_pair_id: None,
            name: "test-rsa-softkey".to_string(),
            key_algorithm,
            handle: encrypted_key.handle,
            key_material: Some(encrypted_key.key_material),
            public_key: encrypted_key.public_key_pem,
            pkcs11_token_id: None,
            pkcs11_key_id: None,
        };

        let data = b"test data";
        let digest = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), data)?;
        let hex_hash = hex::encode(digest);

        let pkey = decrypt_private_key(&key, &encrypted_key.encrypted_password, &[], user_password)
            .await?;
        let signatures = super::sign_with_softkey(
            &key,
            &pkey,
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
        let (encrypted_key, _) = crypto::create_encrypted_key(
            &crate::server::Config::default(),
            user_password.clone(),
            key_algorithm,
            None,
            Default::default(),
            Default::default(),
        )?;
        let key = db::Key {
            id: 1,
            hybrid_pair_id: None,
            name: "test-ecc-softkey".to_string(),
            key_algorithm,
            handle: encrypted_key.handle,
            key_material: Some(encrypted_key.key_material),
            public_key: encrypted_key.public_key_pem,
            pkcs11_token_id: None,
            pkcs11_key_id: None,
        };

        let data = b"test data for ECC softkey signing";
        let digest = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), data)?;
        let hex_hash = hex::encode(digest);

        let pkey = decrypt_private_key(&key, &encrypted_key.encrypted_password, &[], user_password)
            .await?;
        let signatures = super::sign_with_softkey(
            &key,
            &pkey,
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

    #[tokio::test]
    async fn sign_with_softkey_mldsa_keys() -> Result<()> {
        let data = b"test data for softkey ML-DSA signing";

        for key_algorithm in [KeyAlgorithm::Mldsa65, KeyAlgorithm::Mldsa87] {
            let key_type = match key_algorithm {
                KeyAlgorithm::Mldsa65 => openssl::pkey::KeyType::ML_DSA_65,
                KeyAlgorithm::Mldsa87 => openssl::pkey::KeyType::ML_DSA_87,
                _ => unreachable!(),
            };
            let mut seed = [0; 32];
            openssl::rand::rand_priv_bytes(&mut seed)?;
            let pkey = PKey::private_key_from_seed(None, key_type, None, &seed)?;
            let encrypted_pem = pkey.private_key_to_pem_pkcs8_passphrase(
                openssl::symm::Cipher::aes_256_cbc(),
                b"test-key-password",
            )?;
            let pkey = PKey::private_key_from_pem_passphrase(&encrypted_pem, b"test-key-password")?;
            let key = db::Key {
                id: 1,
                hybrid_pair_id: None,
                name: "test-mldsa-softkey".to_string(),
                key_algorithm,
                handle: "test-handle".to_string(),
                key_material: Some("test-key-material".to_string()),
                public_key: String::from_utf8(pkey.public_key_to_pem()?)?,
                pkcs11_token_id: None,
                pkcs11_key_id: None,
            };

            // TODO factor this into a helper, calculate mu
            let pubkey = openssl::pkey::PKey::public_key_from_pem(key.public_key.as_bytes())?;
            let mu_digest = crate::calculate_mu(&pubkey, data)?;
            let hex_hash = hex::encode(mu_digest);

            let signatures = super::sign_with_softkey(
                &key,
                &pkey,
                vec![(DigestAlgorithm::MldsaMu, hex_hash.clone())],
            )?;
            let signature = signatures.first().unwrap().signature.as_ref();
            verify_mldsa_signature(key_algorithm, &key.public_key, data, signature)?;
        }

        Ok(())
    }
}

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
        eddsa::{EddsaParams, EddsaSignatureScheme},
    },
    session::Session,
};
use foreign_types::ForeignTypeRef;
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
    for (digest_algorithm, hex_hash) in digests {
        let hash = hex::decode(&hex_hash).context("The digest provided was not valid hex")?;
        if hash.len() != digest_algorithm.size() {
            return Err(anyhow::anyhow!(
                "The specified digest algorithm is {} bytes; payload was {}",
                digest_algorithm.size(),
                hash.len()
            ));
        }

        let signature = match key.key_algorithm {
            KeyAlgorithm::Mldsa65 | KeyAlgorithm::Mldsa87 => {
                match digest_algorithm {
                    DigestAlgorithm::MldsaMu => {
                        let mut context = openssl::md_ctx::MdCtx::new()?;
                        let pkey_context = context.digest_sign_init(None, pkey)?;
                        let mut mu_flag: std::ffi::c_uint = 1;

                        // Safety:
                        //
                        // 1. Values provided to OSS_PARAM_construct_uint must outlive the subsequent
                        //    call to EVP_PKEY_CTX_set_params()
                        // 2. The parameters list is terminated with an OSSL_PARAM_END structure.
                        //
                        // The key is a C-style string with a static lifetime, and the remaining values
                        // live as long as the pkey_context.
                        let parameters = unsafe {
                            [
                                openssl_sys::OSSL_PARAM_construct_uint(
                                    c"mu".as_ptr(),
                                    &mut mu_flag,
                                ),
                                openssl_sys::OSSL_PARAM_construct_end(),
                            ]
                        };

                        // Safety:
                        //
                        // 1. pkey_context is a pointer to an initialized EVP_PKEY_CTX structure
                        // 2. parameters is a pointer to a list of OSSL_PARAM structures
                        //    terminated by an OSSL_PARAM_END structure, both of which outlive the
                        //    call to EVP_PKEY_CTX_set_params().
                        let result = unsafe {
                            openssl_sys::EVP_PKEY_CTX_set_params(
                                pkey_context.as_ptr(),
                                parameters.as_ptr(),
                            )
                        };
                        if result <= 0 {
                            return Err(openssl::error::ErrorStack::get().into());
                        }

                        let mut signature = vec![];
                        context.digest_sign_to_vec(&hash, &mut signature)?;

                        signature
                    }
                    _ => {
                        return Err(anyhow::anyhow!(
                            "ML-DSA keys only support signing Mu digests"
                        ));
                    }
                }
            }
            KeyAlgorithm::Ed25519 | KeyAlgorithm::Ed448 => {
                let mut signer = openssl::sign::Signer::new_without_digest(pkey)?;
                signer.sign_oneshot_to_vec(&hash)?
            }
            _ => {
                let md = match digest_algorithm {
                    DigestAlgorithm::Sha256 => Ok(openssl::md::Md::sha256()),
                    DigestAlgorithm::Sha512 => Ok(openssl::md::Md::sha512()),
                    DigestAlgorithm::Sha3_256 => Ok(openssl::md::Md::sha3_256()),
                    DigestAlgorithm::Sha3_512 => Ok(openssl::md::Md::sha3_512()),
                    DigestAlgorithm::MldsaMu => Err(anyhow::anyhow!(
                        "The MldsaMu digest is only supported with ML-DSA key signing"
                    )),
                }?;
                let mut ctx = PkeyCtx::new(pkey)?;
                ctx.sign_init()?;
                ctx.set_signature_md(md)?;
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

        tracing::info!(digest_algorithm=%digest_algorithm, digest=hex_hash, "Signature issued");
        signatures.push(protocol::Signature {
            signature,
            digest: digest_algorithm,
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
    for (digest_algorithm, hex_hash) in digests {
        let hash = hex::decode(&hex_hash).context("The digest provided was not valid hex")?;
        if hash.len() != digest_algorithm.size() {
            return Err(anyhow::anyhow!(
                "The specified digest algorithm is {} bytes; payload was {}",
                digest_algorithm.size(),
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
                let digest_info = crate::der::encode_digest_info(digest_algorithm, &hash)?;
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
            KeyAlgorithm::Mldsa65 | KeyAlgorithm::Mldsa87 => {
                match digest_algorithm {
                    DigestAlgorithm::MldsaMu => {
                        // Support for signing Mu values is supposed to arrive with PKCS#11 version 3.3. For the time
                        // being, we can't support signing with ML-DSA using PKCS#11-backed keys. In the future this
                        // can be replaced with something like:
                        //
                        // (Mechanism::MldsaMu(SignAdditionalContext::new(hedge_type, None)), hash)
                        return Err(anyhow::anyhow!(
                            "PKCS#11 version 3.2 does not support signing Mu values"
                        ));
                    }
                    _ => {
                        return Err(anyhow::anyhow!(
                            "ML-DSA keys only support signing Mu digests"
                        ));
                    }
                }
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
            KeyAlgorithm::Ed25519 | KeyAlgorithm::Ed448 => SignaturePayload::PureEdDSA(signature),
            KeyAlgorithm::Mldsa65 | KeyAlgorithm::Mldsa87 => SignaturePayload::PureMLDSA(signature),
        };

        tracing::info!(digest_algorithm=%digest_algorithm, digest=hex_hash, "Signature issued");
        signatures.push(protocol::Signature {
            signature,
            digest: digest_algorithm,
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

    async fn verify_signature(
        key_algorithm: KeyAlgorithm,
        digest: DigestAlgorithm,
        data: &[u8],
        pubkey_pem: &str,
        signature: &[u8],
    ) -> anyhow::Result<()> {
        let tempdir = tempfile::TempDir::new()?;
        let data_path = tempdir.path().join("data");
        tokio::fs::write(&data_path, data).await?;
        let pubkey_path = tempdir.path().join("pubkey");
        tokio::fs::write(&pubkey_path, pubkey_pem).await?;
        let sig_path = tempdir.path().join("signature");
        tokio::fs::write(&sig_path, signature).await?;

        let mut verify_command = tokio::process::Command::new("openssl");
        verify_command
            .arg("pkeyutl")
            .arg("-verify")
            .arg("-rawin")
            .arg("-in")
            .arg(data_path)
            .arg("-pubin")
            .arg("-inkey")
            .arg(pubkey_path)
            .arg("-sigfile")
            .arg(sig_path);
        if matches!(
            key_algorithm,
            KeyAlgorithm::Rsa2K | KeyAlgorithm::Rsa4K | KeyAlgorithm::P256
        ) {
            verify_command.arg("-digest").arg(digest.to_string());
        }
        let debug_cli = format!("verify command: '{:?}'", verify_command);
        let output = verify_command.output().await?;
        assert!(
            output.status.success(),
            "{} failed:\nstdout: {}\nstderr: {}",
            debug_cli,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        let stdout = String::from_utf8(output.stdout)?;
        assert_eq!("Signature Verified Successfully\n", stdout);

        Ok(())
    }

    #[test]
    fn encode_decode_digest_info() -> Result<()> {
        let algorithm = DigestAlgorithm::Sha256;
        let hash = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), b"data")?;
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
    async fn sign_with_pkcs11_mldsa_keys_unsupported() -> Result<()> {
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
        let keys = db::Key::list(&mut conn).await?;
        for key_algorithm in [KeyAlgorithm::Mldsa65, KeyAlgorithm::Mldsa87] {
            let key = keys
                .iter()
                .find(|key| key.key_algorithm == key_algorithm)
                .expect("Should have an ML-DSA key");

            let pubkey = openssl::pkey::PKey::public_key_from_pem(key.public_key.as_bytes())?;
            let mu = crate::calculate_mu(&pubkey, data)?;
            let hex_hash = hex::encode(mu);

            // Once PKCS#11 3.3 happens we should be able to support this and replace the assertion with:
            //
            // let signature = signatures.first().unwrap().signature.as_ref();
            // verify_signature(key_algorithm, DigestAlgorithm::MldsaMu, data, &key.public_key, signature).await?;
            let not_yet_supported = super::sign_with_pkcs11(
                key,
                &session,
                vec![(DigestAlgorithm::MldsaMu, hex_hash.clone())],
            )
            .unwrap_err();
            assert_eq!(
                not_yet_supported.to_string(),
                "PKCS#11 version 3.2 does not support signing Mu values"
            );
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
            let pkey = crypto::create_key(key_algorithm)?;
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

            let pubkey = openssl::pkey::PKey::public_key_from_pem(key.public_key.as_bytes())?;
            let mu_digest = crate::calculate_mu(&pubkey, data)?;
            let hex_hash = hex::encode(mu_digest);

            let signatures = super::sign_with_softkey(
                &key,
                &pkey,
                vec![(DigestAlgorithm::MldsaMu, hex_hash.clone())],
            )?;
            let signature = signatures.first().unwrap().signature.as_ref();
            verify_signature(
                key_algorithm,
                DigestAlgorithm::MldsaMu,
                data,
                &key.public_key,
                signature,
            )
            .await?;
        }

        Ok(())
    }
}

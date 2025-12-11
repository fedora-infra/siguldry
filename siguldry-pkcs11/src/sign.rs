// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use siguldry::protocol::DigestAlgorithm;
use tracing::instrument;

use cryptoki_sys::{
    CK_BYTE_PTR, CK_MECHANISM, CK_OBJECT_HANDLE, CK_RV, CK_SESSION_HANDLE, CK_ULONG, CKM_ECDSA,
    CKM_ECDSA_SHA3_256, CKM_ECDSA_SHA3_512, CKM_ECDSA_SHA256, CKM_ECDSA_SHA512, CKM_RSA_PKCS,
    CKM_SHA3_256_RSA_PKCS, CKM_SHA3_512_RSA_PKCS, CKM_SHA256_RSA_PKCS, CKM_SHA512_RSA_PKCS,
    CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR, CKR_KEY_HANDLE_INVALID, CKR_MECHANISM_INVALID, CKR_OK, CKR_OPERATION_ACTIVE,
    CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_HANDLE_INVALID,
};

use crate::objects::Object;
use crate::session::{Session, SigningState};
use crate::{CLIENT, SESSIONS};

#[instrument(ret)]
pub extern "C" fn C_SignInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: *mut CK_MECHANISM,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    let mut sessions = SESSIONS.lock().expect("session lock was poisoned");
    let session = if let Some(session) = sessions.get_mut(&hSession) {
        session
    } else {
        return CKR_SESSION_HANDLE_INVALID;
    };

    let mechanism = if pMechanism.is_null() {
        // The specification notes this can be used to terminate the active signature operation
        session.reset_signing_state();
        return CKR_OK;
    } else {
        unsafe { (*pMechanism).mechanism }
    };

    if hKey != Object::PRIVATE_KEY_HANDLE {
        return CKR_KEY_HANDLE_INVALID;
    }

    if session.signing_state.is_some() {
        return CKR_OPERATION_ACTIVE;
    }

    let key = session.key.clone();
    tracing::info!(key.name, hKey, mechanism, "Beginning signing with key");
    let digest_algorithm = match mechanism {
        CKM_ECDSA | CKM_RSA_PKCS => {
            // These mechanisms do _not_ hash the data; the caller is expected to do so
            session.signing_state = Some(SigningState {
                multipart: false,
                mechanism,
                hasher: None,
            });
            return CKR_OK;
        }
        CKM_SHA256_RSA_PKCS | CKM_ECDSA_SHA256 => openssl::hash::MessageDigest::sha256(),
        CKM_SHA512_RSA_PKCS | CKM_ECDSA_SHA512 => openssl::hash::MessageDigest::sha512(),
        CKM_SHA3_256_RSA_PKCS | CKM_ECDSA_SHA3_256 => openssl::hash::MessageDigest::sha3_256(),
        CKM_SHA3_512_RSA_PKCS | CKM_ECDSA_SHA3_512 => openssl::hash::MessageDigest::sha3_512(),
        mechanism => {
            tracing::error!(
                mechanism,
                "Mechanism is not supported by the sign operation"
            );
            return CKR_MECHANISM_INVALID;
        }
    };
    match openssl::hash::Hasher::new(digest_algorithm) {
        Ok(hasher) => {
            session.signing_state = Some(SigningState {
                multipart: false,
                mechanism,
                hasher: Some(hasher),
            });
            CKR_OK
        }
        Err(error) => {
            tracing::error!(?error, "Failed to initialize OpenSSL hasher");
            CKR_GENERAL_ERROR
        }
    }
}

/// Add more data to a signing operation.
///
/// Implementation is expected to match Section 5.13.3 of PKCS #11 version 3.2.
#[instrument(ret)]
pub extern "C" fn C_SignUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
) -> CK_RV {
    if pPart.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let mut sessions = SESSIONS.lock().expect("session lock was poisoned");
    let session = if let Some(session) = sessions.get_mut(&hSession) {
        session
    } else {
        return CKR_SESSION_HANDLE_INVALID;
    };

    let signing_state = if let Some(signing_state) = &mut session.signing_state {
        signing_state
    } else {
        return CKR_OPERATION_NOT_INITIALIZED;
    };
    // Mark the operation as multi-part, used to inform callers who incorrectly use C_Sign after
    // calling this function that they've messed up.
    signing_state.multipart = true;

    let data = unsafe { core::slice::from_raw_parts(pPart as *const u8, ulPartLen as usize) };
    if let Some(hasher) = signing_state.hasher.as_mut() {
        if let Err(error) = hasher.update(data) {
            tracing::error!(?error, "Failed to update the digest");
            session.reset_signing_state();
            return CKR_FUNCTION_FAILED;
        }
    } else {
        tracing::error!(
            mechanism = signing_state.mechanism,
            "Multi-part signing is not supported for this mechanism"
        );
        session.reset_signing_state();
        return CKR_ARGUMENTS_BAD;
    }

    CKR_OK
}

/// Complete a signing operation.
///
/// Implementation is expected to match Section 5.13.4 of PKCS #11 version 3.2.
#[instrument(ret)]
pub extern "C" fn C_SignFinal(
    hSession: CK_SESSION_HANDLE,
    pSignature: CK_BYTE_PTR,
    pulSignaturelen: *mut CK_ULONG,
) -> CK_RV {
    // pSignature is checked for NULL later; passing NULL as described in Section 5.2 of the
    // specification is how callers determine how much memory to allocate for the buffer.
    if pulSignaturelen.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let mut sessions = SESSIONS.lock().expect("session lock was poisoned");
    let session = if let Some(session) = sessions.get_mut(&hSession) {
        session
    } else {
        return CKR_SESSION_HANDLE_INVALID;
    };

    // In this case, we've already computed the signature and the caller did not provide a sufficiently
    // large buffer.
    if session.signature.is_some() {
        return return_signature(session, pSignature, pulSignaturelen);
    }

    let signing_state = if let Some(signing_state) = session.signing_state.as_mut() {
        signing_state
    } else {
        return CKR_OPERATION_NOT_INITIALIZED;
    };

    let hasher = if let Some(hasher) = &mut signing_state.hasher {
        hasher
    } else {
        tracing::error!("Multi-part signing is not supported for CKM_ECDSA");
        session.reset_signing_state();
        return CKR_ARGUMENTS_BAD;
    };
    let data_hex = match hasher.finish() {
        Ok(digest) => hex::encode(digest),
        Err(error) => {
            tracing::error!(?error, "Failed to finalize openssl hasher");
            session.reset_signing_state();
            return CKR_GENERAL_ERROR;
        }
    };

    let digest = match signing_state.mechanism {
        CKM_SHA256_RSA_PKCS | CKM_ECDSA_SHA256 => DigestAlgorithm::Sha256,
        CKM_SHA512_RSA_PKCS | CKM_ECDSA_SHA512 => DigestAlgorithm::Sha512,
        CKM_SHA3_256_RSA_PKCS | CKM_ECDSA_SHA3_256 => DigestAlgorithm::Sha3_256,
        CKM_SHA3_512_RSA_PKCS | CKM_ECDSA_SHA3_512 => DigestAlgorithm::Sha3_512,
        unsupported_mechanism => {
            tracing::error!(unsupported_mechanism, "Unsupported mechanism provided");
            session.reset_signing_state();
            return CKR_ARGUMENTS_BAD;
        }
    };

    let digests = vec![(digest, data_hex)];
    match CLIENT
        .lock()
        .expect("client lock poisoned")
        .as_mut()
        .map(|client| client.sign_prehashed(session.key.name.clone(), digests))
    {
        Some(Ok(mut signatures)) => {
            session.signature = signatures.pop().and_then(|s| s.pkcs11_value());
        }
        Some(Err(error)) => {
            session.reset_signing_state();
            tracing::error!(?error, "Failed to sign data");
            return CKR_FUNCTION_FAILED;
        }
        None => return CKR_CRYPTOKI_NOT_INITIALIZED,
    };

    return_signature(session, pSignature, pulSignaturelen)
}

#[instrument(ret)]
pub extern "C" fn C_Sign(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pSignature: CK_BYTE_PTR,
    pulSignaturelen: *mut CK_ULONG,
) -> CK_RV {
    let mut sessions = SESSIONS.lock().expect("session lock was poisoned");
    let session = if let Some(session) = sessions.get_mut(&hSession) {
        session
    } else {
        return CKR_SESSION_HANDLE_INVALID;
    };

    let signing_state = if let Some(signing_state) = &session.signing_state {
        signing_state
    } else {
        return CKR_OPERATION_NOT_INITIALIZED;
    };
    if signing_state.multipart {
        tracing::error!(
            "A call to C_Sign was made after using C_SignUpdate; pick one or the other"
        );
        session.reset_signing_state();
        return CKR_OPERATION_ACTIVE;
    }

    if pData.is_null() || pulSignaturelen.is_null() {
        session.reset_signing_state();
        return CKR_ARGUMENTS_BAD;
    }

    let data = unsafe { core::slice::from_raw_parts(pData as *const u8, ulDataLen as usize) };
    if session.signature.is_none() {
        let (digest_algorithm, data_hex) = if signing_state.mechanism == CKM_ECDSA {
            // For ECDSA we don't actually know what the digest algorithm was, if any. However, we restrict
            // the set of valid input from the specification here (sorry) since the server API expects the
            // digest algorithm at the moment.
            let digest_algorithm = match data.len() {
                32 => DigestAlgorithm::Sha256,
                64 => DigestAlgorithm::Sha512,
                len => {
                    tracing::error!(
                        len,
                        "Unsupported data length for ECDSA mechanism (hash your input)"
                    );
                    session.reset_signing_state();
                    return CKR_ARGUMENTS_BAD;
                }
            };
            (digest_algorithm, hex::encode(data))
        } else if signing_state.mechanism == CKM_RSA_PKCS {
            // For this mechanism, we don't compute message digest or encode it with a DigestInfo
            // structure. The maximum input size is the key modulus in bits minus 11, but we
            // introduce some restrictions here due to the current Siguldry API: the input _MUST_
            // be a DigestInfo structure which we unpack, send to the server, and repack.
            if let Ok((algorithm, digest)) =
                siguldry::server::crypto::signing::decode_digest_info(data)
            {
                (algorithm, hex::encode(digest))
            } else {
                tracing::error!("Failed to parse DigestInfo");
                session.reset_signing_state();
                return CKR_GENERAL_ERROR;
            }
        } else {
            let algorithm = match signing_state.mechanism {
                CKM_SHA256_RSA_PKCS | CKM_ECDSA_SHA256 => DigestAlgorithm::Sha256,
                CKM_SHA512_RSA_PKCS | CKM_ECDSA_SHA512 => DigestAlgorithm::Sha512,
                CKM_SHA3_256_RSA_PKCS | CKM_ECDSA_SHA3_256 => DigestAlgorithm::Sha3_256,
                CKM_SHA3_512_RSA_PKCS | CKM_ECDSA_SHA3_512 => DigestAlgorithm::Sha3_512,
                unsupported_mechanism => {
                    tracing::error!(unsupported_mechanism, "Unsupported mechanism provided");
                    session.reset_signing_state();
                    return CKR_MECHANISM_INVALID;
                }
            };

            let data_hex = match openssl::hash::hash(algorithm.into(), data) {
                Ok(digest) => hex::encode(digest),
                Err(error) => {
                    tracing::error!(?error, "Failed to finalize openssl hasher");
                    session.reset_signing_state();
                    return CKR_GENERAL_ERROR;
                }
            };
            (algorithm, data_hex)
        };

        let digests = vec![(digest_algorithm, data_hex)];
        match CLIENT
            .lock()
            .expect("client lock poisoned")
            .as_mut()
            .map(|client| client.sign_prehashed(session.key.name.clone(), digests))
        {
            Some(Ok(mut signatures)) => {
                session.signature = signatures.pop().and_then(|s| s.pkcs11_value());
            }
            Some(Err(error)) => {
                session.reset_signing_state();
                tracing::error!(?error, "Failed to sign data");
                return CKR_FUNCTION_FAILED;
            }
            None => return CKR_CRYPTOKI_NOT_INITIALIZED,
        };
    }

    return_signature(session, pSignature, pulSignaturelen)
}

/// Helper for dealing with the return process for C_Sign and C_SignFinal.
///
/// This implements the general convention described in Section 5.2 of the PKCS #11 specification.
fn return_signature(
    session: &mut Session,
    pSignature: CK_BYTE_PTR,
    pulSignaturelen: *mut CK_ULONG,
) -> CK_RV {
    let signature = if let Some(signature) = session.signature.as_ref() {
        signature
    } else {
        // Something went terribly wrong, reset the state.
        session.signing_state = None;
        return CKR_FUNCTION_FAILED;
    };

    if pSignature.is_null() {
        // In this case, we should let the caller know what buffer to allocate and return CKR_OK
        tracing::info!(
            signature_length = signature.len(),
            "Informing caller of signature length"
        );
        // Safety:
        // The pointer is non-NULL and according to Section 5.2 the function should
        // set the required size in the value pointed to by pulSignaturelen.
        unsafe { (*pulSignaturelen) = signature.len() as CK_ULONG };
        CKR_OK
    } else {
        // In this case, if the buffer is sufficient, we're done, otherwise we must let the
        // caller know the buffer is too small by setting the needed length and returning
        // CKR_BUFFER_TOO_SMALL.
        let buffer_size = unsafe { *pulSignaturelen };
        // Safety:
        // The pointer is non-NULL and according to Section 5.2 the function MUST
        // set the signature length to the exact number of bytes returned if the buffer
        // is large enough, or if the buffer is not large enough it must be set to an
        // appropriate value for future calls.
        unsafe { (*pulSignaturelen) = signature.len() as CK_ULONG };
        tracing::info!(
            signature_length = signature.len(),
            buffer_size,
            "Writing signature into buffer"
        );
        if buffer_size >= signature.len() as CK_ULONG {
            unsafe {
                pSignature
                    .cast::<u8>()
                    .copy_from(signature.as_ptr(), signature.len());
            };
            tracing::debug!(
                buffer_size,
                signature_length = signature.len(),
                "signature successful"
            );
            session.signature = None;
            session.signing_state = None;
            CKR_OK
        } else {
            tracing::info!(
                buffer_size,
                signature_length = signature.len(),
                "Signature length is greater than allocated buffer"
            );
            CKR_BUFFER_TOO_SMALL
        }
    }
}

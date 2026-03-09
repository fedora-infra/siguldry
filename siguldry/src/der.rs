// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! A few constants and utilities for encoding/decoding DER.

// asn1::Asn1Read results in large errors (~136 bytes). Worth checking dropping this allow
// on asn1 upgrades.
#![allow(clippy::result_large_err)]

use asn1::{ObjectIdentifier, oid};

use crate::protocol::DigestAlgorithm;

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
pub struct DigestInfo<'a> {
    digest_algorithm: AlgorithmIdentifier,
    digest: &'a [u8],
}

#[derive(asn1::Asn1Write, asn1::Asn1Read)]
pub struct AlgorithmIdentifier {
    algorithm: ObjectIdentifier,
    parameters: (),
}

/// Encode a hash into DigestInfo structure for RSA PKCS#1 v1.5 signatures.
pub(crate) fn encode_digest_info(
    algorithm: DigestAlgorithm,
    hash: &[u8],
) -> anyhow::Result<Vec<u8>> {
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

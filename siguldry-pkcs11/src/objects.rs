// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use core::slice;
use std::collections::HashMap;

use asn1::ObjectIdentifier;
use sequoia_openpgp::parse::Parse;
use siguldry::protocol::{Certificate, Key, KeyAlgorithm};

use cryptoki_sys::{
    CK_ATTRIBUTE, CK_ATTRIBUTE_TYPE, CK_BBOOL, CK_FALSE, CK_OBJECT_CLASS, CK_OBJECT_HANDLE, CK_RV,
    CK_TRUE, CK_ULONG, CK_UNAVAILABLE_INFORMATION, CKA_ALLOWED_MECHANISMS, CKA_ALWAYS_AUTHENTICATE,
    CKA_ALWAYS_SENSITIVE, CKA_CLASS, CKA_COPYABLE, CKA_DECRYPT, CKA_EC_PARAMS, CKA_EC_POINT,
    CKA_ENCRYPT, CKA_EXTRACTABLE, CKA_ID, CKA_KEY_TYPE, CKA_LABEL, CKA_MODULUS, CKA_MODULUS_BITS,
    CKA_NEVER_EXTRACTABLE, CKA_PUBLIC_EXPONENT, CKA_PUBLIC_KEY_INFO, CKA_SENSITIVE, CKA_SIGN,
    CKA_SIGN_RECOVER, CKA_TOKEN, CKA_TRUSTED, CKA_UNWRAP, CKA_VERIFY, CKA_WRAP, CKK_EC, CKK_RSA,
    CKO_CERTIFICATE, CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_BUFFER_TOO_SMALL, CKR_OK,
};

#[derive(Debug, Clone)]
pub(crate) struct Object {
    // Map of attribute type to attribute values for this object.
    attributes: HashMap<u64, Attribute>,
}

impl Object {
    pub(crate) const PRIVATE_KEY_HANDLE: CK_OBJECT_HANDLE = 1;
    pub(crate) const PUBLIC_KEY_HANDLE: CK_OBJECT_HANDLE = 2;
    pub(crate) const CERT_BASE_HANDLE: CK_OBJECT_HANDLE = 3;

    pub(crate) fn from_key(key: Key) -> anyhow::Result<HashMap<CK_OBJECT_HANDLE, Object>> {
        let mut objects = HashMap::new();
        objects.insert(
            Self::PRIVATE_KEY_HANDLE,
            Self {
                attributes: Attribute::from_private_key(&key)?,
            },
        );
        objects.insert(
            Self::PUBLIC_KEY_HANDLE,
            Self {
                attributes: Attribute::from_public_key(&key)?,
            },
        );

        for (i, cert) in key.certificates.iter().enumerate() {
            let handle = Self::CERT_BASE_HANDLE + i as u64;
            objects.insert(
                handle,
                Self {
                    attributes: Attribute::from_certificate(&key, cert)?,
                },
            );
        }

        Ok(objects)
    }

    pub(crate) fn matches(&self, attributes: &[Attribute]) -> bool {
        for attribute in attributes {
            if let Some(object_attr) = self.attributes.get(&attribute.attribute_type) {
                if object_attr != attribute {
                    return false;
                }
            } else {
                tracing::debug!(object=?self, ?attribute, "Attempted to match on unknown attribute");
                return false;
            }
        }

        true
    }

    pub(crate) fn set_attribute(&self, attribute: *mut CK_ATTRIBUTE) -> CK_RV {
        if attribute.is_null() {
            panic!("Caller must check attribute is a valid pointer")
        }

        let attribute_type = unsafe { (*attribute).type_ };
        let attribute_value = unsafe { (*attribute).pValue };
        let attribute_value_length = unsafe { (*attribute).ulValueLen };
        if let Some(self_attr) = self.attributes.get(&attribute_type) {
            unsafe { (*attribute).ulValueLen = self_attr.value.len() as u64 };
            if attribute_value.is_null() {
                // The caller may pass in NULL to discover the attribute size
                CKR_OK
            } else if attribute_value_length >= self_attr.value.len() as u64 {
                unsafe {
                    attribute_value
                        .cast::<u8>()
                        .copy_from(self_attr.value.as_ptr(), self_attr.value.len());
                };
                CKR_OK
            } else {
                unsafe { (*attribute).ulValueLen = CK_UNAVAILABLE_INFORMATION };
                CKR_BUFFER_TOO_SMALL
            }
        } else {
            unsafe { (*attribute).ulValueLen = CK_UNAVAILABLE_INFORMATION };
            CKR_ATTRIBUTE_TYPE_INVALID
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Attribute {
    attribute_type: CK_ATTRIBUTE_TYPE,
    value: Vec<u8>,
}

impl TryFrom<*mut CK_ATTRIBUTE> for Attribute {
    type Error = anyhow::Error;

    fn try_from(value: *mut CK_ATTRIBUTE) -> Result<Self, Self::Error> {
        if value.is_null() {
            Err(anyhow::anyhow!("Attribute pointer was NULL"))
        } else {
            let attribute_type = unsafe { (*value).type_ };
            let value_slice = unsafe {
                slice::from_raw_parts((*value).pValue as *const u8, (*value).ulValueLen as usize)
            };
            Ok(Self {
                attribute_type,
                value: Vec::from(value_slice),
            })
        }
    }
}

impl Attribute {
    fn from_private_key(key: &Key) -> anyhow::Result<HashMap<u64, Attribute>> {
        let mut attrs = Self::common_attributes(key)?;
        let class = (CKO_PRIVATE_KEY as CK_OBJECT_CLASS).to_ne_bytes().to_vec();
        attrs.insert(
            CKA_CLASS,
            Attribute {
                attribute_type: CKA_CLASS,
                value: class,
            },
        );
        attrs.insert(
            CKA_SIGN,
            Attribute {
                attribute_type: CKA_SIGN,
                value: vec![CK_TRUE as CK_BBOOL],
            },
        );
        attrs.insert(
            CKA_SENSITIVE,
            Attribute {
                attribute_type: CKA_SENSITIVE,
                value: vec![CK_TRUE as CK_BBOOL],
            },
        );
        attrs.insert(
            CKA_ALWAYS_SENSITIVE,
            Attribute {
                attribute_type: CKA_ALWAYS_SENSITIVE,
                value: vec![CK_TRUE as CK_BBOOL],
            },
        );
        attrs.insert(
            CKA_EXTRACTABLE,
            Attribute {
                attribute_type: CKA_EXTRACTABLE,
                value: vec![CK_FALSE as CK_BBOOL],
            },
        );
        attrs.insert(
            CKA_NEVER_EXTRACTABLE,
            Attribute {
                attribute_type: CKA_NEVER_EXTRACTABLE,
                value: vec![CK_TRUE as CK_BBOOL],
            },
        );
        attrs.insert(
            CKA_COPYABLE,
            Attribute {
                attribute_type: CKA_COPYABLE,
                value: vec![CK_FALSE as CK_BBOOL],
            },
        );

        Ok(attrs)
    }

    fn from_public_key(key: &Key) -> anyhow::Result<HashMap<u64, Attribute>> {
        let mut attrs = Self::common_attributes(key)?;
        let class = (CKO_PUBLIC_KEY as CK_OBJECT_CLASS).to_ne_bytes().to_vec();
        attrs.insert(
            CKA_CLASS,
            Attribute {
                attribute_type: CKA_CLASS,
                value: class,
            },
        );
        attrs.insert(
            CKA_VERIFY,
            Attribute {
                attribute_type: CKA_VERIFY,
                value: vec![CK_TRUE as CK_BBOOL],
            },
        );
        attrs.insert(
            CKA_WRAP,
            Attribute {
                attribute_type: CKA_WRAP,
                value: vec![CK_FALSE as CK_BBOOL],
            },
        );
        attrs.insert(
            CKA_ENCRYPT,
            Attribute {
                attribute_type: CKA_ENCRYPT,
                value: vec![CK_FALSE as CK_BBOOL],
            },
        );

        Ok(attrs)
    }

    fn from_certificate(key: &Key, _cert: &Certificate) -> anyhow::Result<HashMap<u64, Attribute>> {
        let mut attrs = Self::common_attributes(key)?;
        let class = (CKO_CERTIFICATE as CK_OBJECT_CLASS).to_ne_bytes().to_vec();
        attrs.insert(
            CKA_CLASS,
            Attribute {
                attribute_type: CKA_CLASS,
                value: class,
            },
        );
        attrs.insert(
            CKA_TRUSTED,
            Attribute {
                attribute_type: CKA_TRUSTED,
                value: vec![CK_FALSE as CK_BBOOL],
            },
        );

        Ok(attrs)
    }

    fn common_attributes(key: &Key) -> anyhow::Result<HashMap<u64, Attribute>> {
        let mut attrs = HashMap::new();

        match key.certificates.first() {
            Some(Certificate::Gpg {
                version,
                certificate,
                fingerprint,
            }) => {
                // sequioa-cryptoki uses the Id attribute to stash various OpenPGP parameters.
                // Reproduce those here so the cryptoki backend recognizes this as useable for
                // OpenPGP signatures.
                //
                // This format is from sequoia-cryptoki; it may be subject to change.
                // Id attribute needs to be a UTF-8 encoded string with the following format:
                //
                // pgp:v{6|6t|6pq|4|4t|4pq}:{key_algorithm}:{iso8601-1:2019 basic format creation time}
                //
                // The v<num> indicates the OpenPGP profile, and hybrid keys expose their traditional
                // and post-quantum pieces with the t or pq suffix respectively (we don't currently
                // support this).
                //
                // Finally, ECDSA keys are documented as needing the hash algorithm and symmetric encryption
                // algorithm after the key algorithm (separated by -, e.g. "rsa-sha256-aes128"), but we
                // don't support that currently either.
                let cert = sequoia_openpgp::Cert::from_bytes(certificate.as_bytes())?;
                let pgp_key = cert.primary_key().key();
                let key_algo = match key.key_algorithm {
                    KeyAlgorithm::Rsa2K | KeyAlgorithm::Rsa4K => "rsa",
                    KeyAlgorithm::P256 => "ecdsa",
                    _ => return Err(anyhow::anyhow!("Unsupported key algorithm")),
                };
                let creation_time = chrono::DateTime::<chrono::Utc>::from(pgp_key.creation_time())
                    .format("%Y%m%dT%H%M%SZ")
                    .to_string();
                let id = format!("pgp:v{version}:{key_algo}:{creation_time}:{}", &key.name);
                tracing::debug!(
                    fingerprint,
                    id,
                    "Exposing OpenPGP key for use via Sequoia's cryptoki backend"
                );
                attrs.insert(
                    CKA_ID,
                    Attribute {
                        attribute_type: CKA_ID,
                        value: id.as_bytes().to_vec(),
                    },
                );
            }
            _other => {
                attrs.insert(
                    CKA_ID,
                    Attribute {
                        attribute_type: CKA_ID,
                        value: vec![1_u8],
                    },
                );
            }
        }
        attrs.insert(
            CKA_LABEL,
            Attribute {
                attribute_type: CKA_LABEL,
                value: key.name.as_bytes().to_vec(),
            },
        );
        attrs.insert(
            CKA_TOKEN,
            Attribute {
                attribute_type: CKA_TOKEN,
                value: vec![CK_TRUE as CK_BBOOL],
            },
        );
        attrs.insert(
            CKA_SIGN_RECOVER,
            Attribute {
                attribute_type: CKA_SIGN_RECOVER,
                value: vec![CK_FALSE as CK_BBOOL],
            },
        );
        attrs.insert(
            CKA_UNWRAP,
            Attribute {
                attribute_type: CKA_UNWRAP,
                value: vec![CK_FALSE as CK_BBOOL],
            },
        );
        attrs.insert(
            CKA_DECRYPT,
            Attribute {
                attribute_type: CKA_DECRYPT,
                value: vec![CK_FALSE as CK_BBOOL],
            },
        );
        attrs.insert(
            CKA_ALWAYS_AUTHENTICATE,
            Attribute {
                attribute_type: CKA_ALWAYS_AUTHENTICATE,
                value: vec![CK_FALSE as CK_BBOOL],
            },
        );

        match key.key_algorithm {
            KeyAlgorithm::Rsa4K | KeyAlgorithm::Rsa2K => {
                attrs.insert(
                    CKA_KEY_TYPE,
                    Attribute {
                        attribute_type: CKA_KEY_TYPE,
                        value: CKK_RSA.to_ne_bytes().to_vec(),
                    },
                );
                if let Ok(cert) = sequoia_openpgp::Cert::from_bytes(key.public_key.as_bytes()) {
                    let pubkey = cert.primary_key().key().mpis();
                    match pubkey {
                        sequoia_openpgp::crypto::mpi::PublicKey::RSA { e, n } => {
                            attrs.insert(
                                CKA_MODULUS,
                                Attribute {
                                    attribute_type: CKA_MODULUS,
                                    value: n.value().to_vec(),
                                },
                            );
                            attrs.insert(
                                CKA_PUBLIC_EXPONENT,
                                Attribute {
                                    attribute_type: CKA_PUBLIC_EXPONENT,
                                    value: e.value().to_vec(),
                                },
                            );
                            attrs.insert(
                                CKA_MODULUS_BITS,
                                Attribute {
                                    attribute_type: CKA_MODULUS_BITS,
                                    value: (n.bits() as CK_ULONG).to_ne_bytes().to_vec(),
                                },
                            );
                        }
                        keytype => {
                            tracing::error!(
                                key_algorithm=?key.key_algorithm,
                                actual_algorithm=?keytype.algo(),
                                "The key algorithm reported by Siguldry doesn't match the he OpenPGP primary key algorithm"
                            );
                        }
                    }
                } else if let Ok(pubkey) =
                    openssl::rsa::Rsa::public_key_from_pem(key.public_key.as_bytes())
                {
                    attrs.insert(
                        CKA_MODULUS,
                        Attribute {
                            attribute_type: CKA_MODULUS,
                            value: pubkey.n().to_vec(),
                        },
                    );
                    attrs.insert(
                        CKA_PUBLIC_EXPONENT,
                        Attribute {
                            attribute_type: CKA_PUBLIC_EXPONENT,
                            value: pubkey.e().to_vec(),
                        },
                    );
                    attrs.insert(
                        CKA_MODULUS_BITS,
                        Attribute {
                            attribute_type: CKA_MODULUS_BITS,
                            value: pubkey.n().num_bits().to_ne_bytes().to_vec(),
                        },
                    );
                    attrs.insert(
                        CKA_PUBLIC_KEY_INFO,
                        Attribute {
                            attribute_type: CKA_PUBLIC_KEY_INFO,
                            value: pubkey.public_key_to_der()?,
                        },
                    );
                }
                let mechanisms = crate::RSA_PKCS_MECHANISMS
                    .into_iter()
                    .flat_map(|m| m.to_ne_bytes())
                    .collect();
                attrs.insert(
                    CKA_ALLOWED_MECHANISMS,
                    Attribute {
                        attribute_type: CKA_ALLOWED_MECHANISMS,
                        value: mechanisms,
                    },
                );
            }
            KeyAlgorithm::P256 => {
                attrs.insert(
                    CKA_KEY_TYPE,
                    Attribute {
                        attribute_type: CKA_KEY_TYPE,
                        value: CKK_EC.to_ne_bytes().to_vec(),
                    },
                );

                // For both public and private key objects
                // DER-encoding of an ANSI X9.62 Parameters value, where Parameters is:
                //
                // Parameters ::= CHOICE {
                //     ecParameters  ECParameters,
                //     oId           CURVES.&id({CurveNames}),
                //     implicitlyCA  NULL,
                //     curveName     PrintableString
                // }
                //
                // The specification recommends oId or curveName. See Section 6.3.3.
                let p256_oid = asn1::oid!(1, 2, 840, 10045, 3, 1, 7);
                let p256_oid_bytes = asn1::write_single(&p256_oid)?;
                attrs.insert(
                    CKA_EC_PARAMS,
                    Attribute {
                        attribute_type: CKA_EC_PARAMS,
                        value: p256_oid_bytes,
                    },
                );

                if let Ok(cert) = sequoia_openpgp::Cert::from_bytes(key.public_key.as_bytes()) {
                    match cert.primary_key().key().mpis() {
                        sequoia_openpgp::crypto::mpi::PublicKey::ECDSA { curve: _, q } => {
                            let octet_point = asn1::OctetStringEncoded::new(q.value());
                            let der_point = asn1::write_single(&octet_point)?;
                            attrs.insert(
                                CKA_EC_POINT,
                                Attribute {
                                    attribute_type: CKA_EC_POINT,
                                    value: der_point,
                                },
                            );

                            // See https://www.rfc-editor.org/rfc/rfc5480#section-2.1.1
                            let oid_ec_public_key = asn1::oid!(1, 2, 840, 10045, 2, 1);
                            #[derive(asn1::Asn1Write)]
                            struct AlgorithmIdentifier {
                                // The public key OID
                                algorithm: ObjectIdentifier,
                                // The namedCurve OID
                                parameters: ObjectIdentifier,
                            }
                            #[derive(asn1::Asn1Write)]
                            struct SubjectPublicKeyInfo<'a> {
                                algorithm: AlgorithmIdentifier,
                                subject_public_key: asn1::BitString<'a>,
                            }
                            let pubkey_der = asn1::write_single(&SubjectPublicKeyInfo {
                                algorithm: AlgorithmIdentifier {
                                    algorithm: oid_ec_public_key,
                                    parameters: p256_oid.clone(),
                                },
                                subject_public_key: asn1::BitString::new(q.value(), 0).ok_or_else(
                                    || anyhow::anyhow!("Failed to set subject_public_key"),
                                )?,
                            })?;
                            attrs.insert(
                                CKA_PUBLIC_KEY_INFO,
                                Attribute {
                                    attribute_type: CKA_PUBLIC_KEY_INFO,
                                    value: pubkey_der,
                                },
                            );
                        }
                        // There's a mismatch between the server-reported type and the actual type
                        keytype => {
                            tracing::error!(
                                key_algorithm=?key.key_algorithm,
                                actual_algorithm=?keytype.algo(),
                                "The key algorithm reported by Siguldry doesn't match the he OpenPGP primary key algorithm"
                            );
                        }
                    };
                } else if let Ok(pubkey) =
                    openssl::ec::EcKey::public_key_from_pem(key.public_key.as_bytes())
                {
                    attrs.insert(
                        CKA_PUBLIC_KEY_INFO,
                        Attribute {
                            attribute_type: CKA_PUBLIC_KEY_INFO,
                            value: pubkey.public_key_to_der()?,
                        },
                    );

                    // Private keys always include CKA_SENSITIVE = true and CKA_EXTRACTABLE = false
                    // so the CKA_VALUE attribute is never provided.

                    // For public key objects
                    // DER-encoding of ANSI X9.62 ECPoint value Q
                    //
                    // See Section 6.3.3.
                    let mut ctx = openssl::bn::BigNumContext::new()?;
                    let point = pubkey.public_key().to_bytes(
                        pubkey.group(),
                        openssl::ec::PointConversionForm::UNCOMPRESSED,
                        &mut ctx,
                    )?;
                    let octet_point = asn1::OctetStringEncoded::new(point.as_slice());
                    let der_point = asn1::write_single(&octet_point)?;
                    attrs.insert(
                        CKA_EC_POINT,
                        Attribute {
                            attribute_type: CKA_EC_POINT,
                            value: der_point,
                        },
                    );
                }
                let mechanisms = crate::ECDSA_MECHANISMS
                    .into_iter()
                    .flat_map(|m| m.to_ne_bytes())
                    .collect();
                attrs.insert(
                    CKA_ALLOWED_MECHANISMS,
                    Attribute {
                        attribute_type: CKA_ALLOWED_MECHANISMS,
                        value: mechanisms,
                    },
                );
            }
            unsupported => {
                tracing::error!(key_algorithm=?unsupported, "Unsupported key algorithm");
            }
        }

        Ok(attrs)
    }
}

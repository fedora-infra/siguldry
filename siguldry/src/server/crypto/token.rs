use std::path::PathBuf;

use anyhow::Context;
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    mechanism::{
        Mechanism,
        dsa::SignAdditionalContext,
        eddsa::{EddsaParams, EddsaSignatureScheme},
    },
    object::{Attribute, AttributeType, KeyType, MlDsaParameterSetType, ObjectClass},
    session::Session,
    types::AuthPin,
};
use openssl::{nid::Nid, x509};
use sqlx::SqliteConnection;

use crate::{protocol::KeyAlgorithm, server::db};

/// Swap an existing PKCS#11 token for a new one containing the same set of keys and certificates.
///
/// As part of the validation, the set of certificates and public keys are checked against the
/// versions in the database. Additionally, each private key will be used to sign a random 64 byte
/// value which is validated by the database's public key to ensure it's the same private key.
pub async fn swap_pkcs11_token(
    conn: &mut SqliteConnection,
    existing_token: &db::Pkcs11Token,
    module: PathBuf,
    slot_id: Option<u64>,
    token_user_pin: AuthPin,
) -> anyhow::Result<db::Pkcs11Token> {
    let pkcs11 = Pkcs11::new(&module).context("Failed to load the PKCS#11 module specified.")?;
    pkcs11
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .context("Failed to initialized the PKCS#11 module")?;
    let new_token = validate_pkcs11_swap(
        &pkcs11,
        conn,
        existing_token,
        module,
        slot_id,
        token_user_pin,
    )
    .await
    .context("Failed to validate the new token");
    pkcs11
        .finalize()
        .context("Failed to finalize the PKCS#11 module")?;
    let new_token = new_token?;
    new_token.update(conn).await?;

    Ok(new_token)
}

async fn validate_pkcs11_swap(
    pkcs11: &Pkcs11,
    conn: &mut SqliteConnection,
    existing_token: &db::Pkcs11Token,
    module: PathBuf,
    slot_id: Option<u64>,
    token_user_pin: AuthPin,
) -> anyhow::Result<db::Pkcs11Token> {
    let slot = if let Some(slot_id) = slot_id {
        pkcs11
            .get_slots_with_token()?
            .into_iter()
            .find(|s| s.id() == slot_id)
            .ok_or_else(|| {
                anyhow::anyhow!("The provided token didn't have a slot with id {}", slot_id)
            })?
    } else {
        pkcs11
            .get_slots_with_token()?
            .pop()
            .ok_or_else(|| anyhow::anyhow!("No slots with a token could be found"))?
    };

    let info = pkcs11
        .get_token_info(slot)
        .context("Unable to read replacement token information")?;
    if info.serial_number() == existing_token.serial_number {
        return Err(anyhow::anyhow!(
            "The new token has the same serial number as the existing token."
        ));
    }
    if info.label().is_empty() {
        return Err(anyhow::anyhow!(
            "The new token does not have a label, set one before importing it."
        ));
    }

    let session = pkcs11.open_ro_session(slot)?;
    session
        .login(cryptoki::session::UserType::User, Some(&token_user_pin))
        .context("Failed to log into the new token with the provided PIN")?;
    let existing_token_keys = db::Key::get_token_keys(conn, existing_token).await?;
    if existing_token_keys.is_empty() {
        return Err(anyhow::anyhow!(
            "The existing token does not have any keys associated with it."
        ));
    }

    for key in existing_token_keys {
        check_new_token_key(conn, &session, &key)
            .await
            .with_context(|| format!("New token has no match for key {}", key.name))?;
    }

    let mut new_token = existing_token.clone();
    new_token.module_path = module;
    new_token.label = info.label().to_string();
    new_token.manufacturer_id =
        (!info.manufacturer_id().is_empty()).then(|| info.manufacturer_id().to_string());
    new_token.model = (!info.model().is_empty()).then(|| info.model().to_string());
    new_token.serial_number = info.serial_number().to_string();

    Ok(new_token)
}

async fn check_new_token_key(
    conn: &mut SqliteConnection,
    session: &Session,
    existing_key: &db::Key,
) -> anyhow::Result<()> {
    let key_id = existing_key
        .pkcs11_key_id
        .as_ref()
        .context("Missing PKCS#11 key ID")?;

    // Check the X.509 certificates
    let mut new_token_certs = Vec::new();
    for object in session.find_objects(&[
        Attribute::Class(ObjectClass::CERTIFICATE),
        Attribute::Id(key_id.clone()),
    ])? {
        for attribute in session.get_attributes(object, &[AttributeType::Value])? {
            if let Attribute::Value(der) = attribute {
                new_token_certs.push(der);
            }
        }
    }
    for existing_token_cert in
        db::PublicKeyMaterial::list(conn, existing_key, db::PublicKeyMaterialType::X509).await?
    {
        let der = x509::X509::from_pem(existing_token_cert.data.as_bytes())?.to_der()?;
        if !new_token_certs.contains(&der) {
            return Err(anyhow::anyhow!(
                "The new token does not have a certificate that matches '{}' associated with the '{}' key",
                existing_token_cert.name,
                existing_key.name
            ));
        }
    }

    // Check the public key
    let public_keys = session.find_objects(&[
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::Id(key_id.clone()),
    ])?;
    let [public_key] = public_keys.as_slice() else {
        return Err(anyhow::anyhow!(
            "The new token returned {} public keys rather than the expected 1",
            public_keys.len()
        ));
    };
    let attributes = session.get_attributes(*public_key, &[AttributeType::PublicKeyInfo])?;
    let der = match attributes
        .into_iter()
        .find_map(|attribute| match attribute {
            Attribute::PublicKeyInfo(der) if !der.is_empty() => Some(der),
            _ => None,
        }) {
        Some(der) => der,
        None if matches!(
            existing_key.key_algorithm,
            KeyAlgorithm::Rsa2K | KeyAlgorithm::Rsa4K
        ) =>
        {
            let attributes = session.get_attributes(
                *public_key,
                &[AttributeType::Modulus, AttributeType::PublicExponent],
            )?;
            pkey_attributes_to_spki_rsa(&attributes)?
        }
        None => {
            return Err(anyhow::anyhow!(
                "The new token's public key has no SubjectPublicKeyInfo"
            ));
        }
    };
    let existing_public_key =
        openssl::pkey::PKey::public_key_from_pem(existing_key.public_key.as_bytes())?;
    let new_public_key = openssl::pkey::PKey::public_key_from_der(&der)?;
    if !existing_public_key.public_eq(&new_public_key) {
        return Err(anyhow::anyhow!(
            "The public key in the new token does not match the existing token's record"
        ));
    }

    // Finally check the private key by signing a message and checking the signature
    // with the database public key.
    let private_keys = session.find_objects(&[
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::Id(key_id.clone()),
    ])?;
    let [private_key] = private_keys.as_slice() else {
        return Err(anyhow::anyhow!(
            "The new token returned {} private keys rather than the expected 1",
            private_keys.len()
        ));
    };
    let mut message = [0; 64];
    openssl::rand::rand_bytes(&mut message)?;
    let (mechanism, data) = match existing_key.key_algorithm {
        KeyAlgorithm::Rsa2K | KeyAlgorithm::Rsa4K => (
            Mechanism::RsaPkcs,
            crate::der::encode_digest_info(
                crate::protocol::DigestAlgorithm::Sha256,
                &openssl::sha::sha256(&message),
            )?,
        ),
        KeyAlgorithm::P256 => (Mechanism::Ecdsa, openssl::sha::sha256(&message).to_vec()),
        KeyAlgorithm::Ed25519 => (
            Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Ed25519)),
            message.to_vec(),
        ),
        KeyAlgorithm::Ed448 => (
            Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Ed448(&[]))),
            message.to_vec(),
        ),
        KeyAlgorithm::Mldsa65 | KeyAlgorithm::Mldsa87 => (
            Mechanism::MlDsa(SignAdditionalContext::new(Default::default(), None)),
            message.to_vec(),
        ),
        _ => {
            return Err(anyhow::anyhow!(
                "Unsupported key algorithm {}",
                existing_key.key_algorithm
            ));
        }
    };
    let signature = session.sign(&mechanism, *private_key, &data)?;
    let signature = if existing_key.key_algorithm == KeyAlgorithm::P256 {
        let (component_r, component_s) = signature
            .split_at_checked(32)
            .context("Invalid P256 signature length")?;
        let component_r = openssl::bn::BigNum::from_slice(component_r)?;
        let component_s = openssl::bn::BigNum::from_slice(component_s)?;
        openssl::ecdsa::EcdsaSig::from_private_components(component_r, component_s)?.to_der()?
    } else {
        signature
    };

    let digest = match existing_key.key_algorithm {
        KeyAlgorithm::Rsa2K | KeyAlgorithm::Rsa4K | KeyAlgorithm::P256 => {
            Some(openssl::md::Md::sha256())
        }
        _ => None,
    };
    let mut context = openssl::md_ctx::MdCtx::new()?;
    context.digest_verify_init(digest, &existing_public_key)?;
    let verified = context
        .digest_verify(&message, &signature)
        .context("Failed to verify the signature produced from the new token")?;
    if !verified {
        return Err(anyhow::anyhow!(
            "The signature produced by the new token doesn't validate with the existing token's public key"
        ));
    }

    Ok(())
}

/// Import keys and certificates from a PKCS#11 token.
///
/// This creates records for the key pairs stored in a PKCS#11 module, along with any x509 certificates
/// associated with them. Since this creates database records and is fallible, the caller should ensure
/// the database transaction is rolled back on errors.
pub async fn import_pkcs11_token(
    conn: &mut SqliteConnection,
    module: PathBuf,
    slot: Option<u64>,
    token_user_pin: AuthPin,
) -> anyhow::Result<db::Pkcs11Token> {
    let pkcs11 = Pkcs11::new(&module).context("Failed to load the PKCS#11 module specified.")?;
    pkcs11
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .context("Failed to initialized the PKCS#11 module")?;
    let result = import_pkcs11_token_private(&pkcs11, conn, module, slot, token_user_pin).await;
    pkcs11.finalize()?;
    result
}

fn pkey_attributes_to_spki_rsa(attributes: &Vec<Attribute>) -> anyhow::Result<Vec<u8>> {
    let mut modulus = None;
    let mut public_exponent = None;

    for attr in attributes {
        match attr {
            Attribute::Modulus(m) if !m.is_empty() => modulus = Some(m),
            Attribute::PublicExponent(e) if !e.is_empty() => public_exponent = Some(e),
            _ => {}
        }
    }

    let n = openssl::bn::BigNum::from_slice(
        modulus.ok_or_else(|| anyhow::anyhow!("missing CKA_MODULUS"))?,
    )?;
    let e = openssl::bn::BigNum::from_slice(
        public_exponent.ok_or_else(|| anyhow::anyhow!("missing CKA_PUBLIC_EXPONENT"))?,
    )?;
    let key = openssl::rsa::Rsa::from_public_components(n, e)?;
    let pkey = openssl::pkey::PKey::from_rsa(key)?.public_key_to_der()?;
    Ok(pkey)
}

async fn import_pkcs11_token_private(
    pkcs11: &Pkcs11,
    conn: &mut SqliteConnection,
    module: PathBuf,
    slot_id: Option<u64>,
    token_user_pin: AuthPin,
) -> anyhow::Result<db::Pkcs11Token> {
    let slot = if let Some(slot_id) = slot_id {
        pkcs11
            .get_slots_with_token()?
            .into_iter()
            .find(|s| s.id() == slot_id)
            .ok_or_else(|| {
                anyhow::anyhow!("The provided token didn't have a slot with id {}", slot_id)
            })?
    } else {
        pkcs11
            .get_slots_with_token()?
            .pop()
            .ok_or_else(|| anyhow::anyhow!("The provided token didn't have any slots"))?
    };
    let token_info = pkcs11
        .get_token_info(slot)
        .context("Unable to read token information")?;
    let session = pkcs11
        .open_ro_session(slot)
        .context("Unable to open a read-only session with the token")?;
    session
        .login(cryptoki::session::UserType::User, Some(&token_user_pin))
        .context("Failed to login to the token with the provided user PIN")?;

    let manufacturer_id = if token_info.manufacturer_id().is_empty() {
        None
    } else {
        Some(token_info.manufacturer_id().to_string())
    };
    let model = if token_info.model().is_empty() {
        None
    } else {
        Some(token_info.model().to_string())
    };
    let label = if token_info.label().is_empty() {
        return Err(anyhow::anyhow!("PKCS #11 token needs to have a label"));
    } else {
        token_info.label().to_string()
    };
    let serial_number = if token_info.serial_number().is_empty() {
        return Err(anyhow::anyhow!(
            "PKCS #11 token needs to have a serial_number"
        ));
    } else {
        token_info.serial_number().to_string()
    };
    let token = db::Pkcs11Token::create(
        conn,
        module,
        label,
        manufacturer_id,
        model,
        serial_number,
        None,
    )
    .await?;

    // Look through the private keys, then match them up with related public key and certificates
    // using the Id attribute. Once all the bits are collect them, add them to the database.
    struct TokenKey {
        label: String,
        key_type: cryptoki::object::KeyType,
        parameter_set: Option<cryptoki::object::ParameterSetType>,
        public_key_der: Option<Vec<u8>>,
        // SN, PEM-encoded cert
        x509_certificate_pem: Option<(String, String)>,
    }
    let mut token_keys: std::collections::HashMap<Vec<u8>, TokenKey> =
        std::collections::HashMap::new();
    let private_key_attributes = [
        AttributeType::Id,
        AttributeType::Label,
        AttributeType::KeyType,
        AttributeType::ParameterSet,
        AttributeType::Class,
    ];
    for object in session
        .iter_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY)])
        .context("Failed to search private key objects")?
    {
        let object = object?;
        let attributes = session
            .get_attributes(object, &private_key_attributes)
            .context("Failed to query private key attributes")?;

        let mut key_id = None;
        let mut label = None;
        let mut key_type = None;
        let mut parameter_set = None;

        for attr in attributes {
            match attr {
                Attribute::Id(id) => key_id = Some(id),
                Attribute::Label(l) => {
                    label = String::from_utf8(l).ok();
                }
                Attribute::KeyType(kt) => key_type = Some(kt),
                Attribute::ParameterSet(ps) => parameter_set = Some(ps),
                _ => {}
            }
        }

        if let (Some(id), Some(label), Some(key_type)) = (key_id, label, key_type) {
            token_keys.insert(
                id,
                TokenKey {
                    label,
                    key_type,
                    parameter_set,
                    public_key_der: None,
                    x509_certificate_pem: None,
                },
            );
        }
    }

    // Some HSMs (observed on Utimaco CryptoServer) don't populate CKA_PUBLIC_KEY_INFO at all,
    // returning it as an empty/absent attribute rather than the SubjectPublicKeyInfo DER the
    // rest of this function expects. As a fallback for RSA keys, also request the raw modulus
    // and public exponent so we can reconstruct the SPKI DER ourselves when the vendor attribute
    // is missing.
    let public_key_attributes = [
        AttributeType::Id,
        AttributeType::PublicKeyInfo,
        AttributeType::KeyType,
        AttributeType::Modulus,
        AttributeType::PublicExponent,
    ];
    for object in session
        .iter_objects(&[Attribute::Class(ObjectClass::PUBLIC_KEY)])
        .context("Failed to search public key objects")?
    {
        let object = object?;
        let attributes = session
            .get_attributes(object, &public_key_attributes)
            .context("Failed to query public key attributes")?;

        let mut key_id = None;
        let mut public_key_info = None;
        let mut key_type = None;

        for attr in &attributes {
            match attr {
                Attribute::Id(id) => key_id = Some(id.clone()),
                Attribute::PublicKeyInfo(der) if !der.is_empty() => {
                    public_key_info = Some(der.clone());
                }
                Attribute::KeyType(kt) => key_type = Some(*kt),
                _ => {}
            }
        }

        // Prefer the vendor-provided SPKI DER; fall back to constructing it ourselves from
        // the raw key material if the HSM didn't populate CKA_PUBLIC_KEY_INFO.
        public_key_info = public_key_info.or_else(|| match key_type {
            Some(KeyType::RSA) => pkey_attributes_to_spki_rsa(&attributes).ok(),
            _ => None,
        });

        if let (Some(id), Some(der)) = (key_id, public_key_info)
            && let Some(entry) = token_keys.get_mut(&id)
        {
            entry.public_key_der = Some(der);
        }
    }

    // Pull out any certificates in the token for the key pairs we know about
    let certificate_attributes = [AttributeType::Id, AttributeType::Value];
    for object in session
        .iter_objects(&[Attribute::Class(ObjectClass::CERTIFICATE)])
        .context("Failed to search certificate objects")?
    {
        let object = object?;
        let attributes = session
            .get_attributes(object, &certificate_attributes)
            .context("Failed to query certificate attributes")?;

        let mut key_id = None;
        let mut cert_der = None;

        for attr in attributes {
            match attr {
                Attribute::Id(id) => key_id = Some(id),
                Attribute::Value(der) => cert_der = Some(der),
                _ => {}
            }
        }

        if let (Some(id), Some(der)) = (key_id, cert_der)
            && let Some(entry) = token_keys.get_mut(&id)
            && let Ok(cert) = x509::X509::from_der(&der)
        {
            let serial_number = cert
                .serial_number()
                .to_bn()
                .and_then(|bn| bn.to_hex_str())
                .map(|s| s.to_uppercase())
                .ok();
            let pem = cert
                .to_pem()
                .ok()
                .and_then(|pem_bytes| String::from_utf8(pem_bytes).ok());
            if let (Some(sn), Some(pem)) = (serial_number, pem) {
                entry.x509_certificate_pem = Some((sn, pem));
            }
        }
    }

    for (key_id, key_info) in &token_keys {
        if let Some(public_key) = key_info
            .public_key_der
            .as_deref()
            .map(openssl::pkey::PKey::public_key_from_der)
        {
            let public_key = public_key?;
            let key_algorithm = match key_info.key_type {
                cryptoki::object::KeyType::EC => {
                    let ecc_key = public_key.ec_key()?;
                    if ecc_key.group().curve_name() == Some(Nid::X9_62_PRIME256V1) {
                        KeyAlgorithm::P256
                    } else {
                        tracing::warn!(
                            label = key_info.label,
                            "Found unsupported ECC key; skipping"
                        );
                        continue;
                    }
                }
                cryptoki::object::KeyType::RSA => {
                    // Double check it's an RSA key
                    let _ = public_key.rsa()?;
                    match public_key.bits() {
                        4096 => KeyAlgorithm::Rsa4K,
                        2048 => KeyAlgorithm::Rsa2K,
                        other => {
                            tracing::warn!(
                                label = key_info.label,
                                "Found unsupported RSA key of size {}",
                                other
                            );
                            continue;
                        }
                    }
                }
                cryptoki::object::KeyType::EC_EDWARDS => {
                    if public_key.is_a(openssl::pkey::KeyType::ED25519) {
                        KeyAlgorithm::Ed25519
                    } else if public_key.is_a(openssl::pkey::KeyType::ED448) {
                        KeyAlgorithm::Ed448
                    } else {
                        tracing::warn!(
                            label = key_info.label,
                            "Found unsupported Edwards curve key; skipping"
                        );
                        continue;
                    }
                }
                cryptoki::object::KeyType::ML_DSA => {
                    match key_info.parameter_set.map(MlDsaParameterSetType::from) {
                        Some(MlDsaParameterSetType::ML_DSA_65) => KeyAlgorithm::Mldsa65,
                        Some(MlDsaParameterSetType::ML_DSA_87) => KeyAlgorithm::Mldsa87,
                        Some(unsupported) => {
                            tracing::warn!(
                                label = key_info.label,
                                %unsupported,
                                "Found unsupported ML-DSA key; skipping"
                            );
                            continue;
                        }
                        None => {
                            tracing::warn!(
                                label = key_info.label,
                                "ML-DSA key is missing parameter set; skipping"
                            );
                            continue;
                        }
                    }
                }
                unsupported => {
                    tracing::warn!(
                        label = key_info.label,
                        "Found unsupported key type {:?}",
                        unsupported
                    );
                    continue;
                }
            };

            let pubkey_pem = String::from_utf8(public_key.public_key_to_pem()?)?;
            let handle = hex::encode_upper(openssl::hash::hash(
                openssl::hash::MessageDigest::sha256(),
                &public_key.public_key_to_der()?,
            )?);
            let key = db::Key::create(
                conn,
                &key_info.label,
                &handle,
                key_algorithm,
                None,
                &pubkey_pem,
                Some(&token),
                Some(key_id.clone()),
            )
            .await?;
            if let Some((serial_number, pem_cert)) = key_info.x509_certificate_pem.clone() {
                db::PublicKeyMaterial::create(
                    conn,
                    &key,
                    serial_number,
                    db::PublicKeyMaterialType::X509,
                    pem_cert,
                )
                .await?;
            }
        }
    }

    Ok(token)
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use super::*;
    use crate::server::crypto::test_utils::setup_hsm;

    #[tokio::test]
    async fn swap_pkcs11_token_preserves_records() -> Result<()> {
        let hsm = setup_hsm()?;
        let db_pool = db::pool("sqlite::memory:", false).await?;
        db::migrate(&db_pool).await?;

        let mut conn = db_pool.begin().await?;
        let module = PathBuf::from("/usr/lib64/pkcs11/libkryoptic_pkcs11.so");
        let mut token =
            import_pkcs11_token(&mut conn, module.clone(), Some(1), hsm.user_pin.clone()).await?;
        // rather than make two tokens, just mess with the database records of the one we have
        // as this just updates database records.
        let new_token_serial = token.serial_number.clone();
        token.serial_number = "12345".to_string();
        token.label = "retired-token".to_string();
        token.update(&mut conn).await?;

        // Existing keys/certs/access records should not be touched.
        let keys = db::Key::get_token_keys(&mut conn, &token).await?;
        let user = db::User::create(&mut conn, "test-user").await?;
        let mut accesses = Vec::new();
        let mut certificates = Vec::new();
        for key in &keys {
            accesses.push(
                db::KeyAccess::create(&mut conn, key, &user, b"encrypted-pin".to_vec(), true)
                    .await?,
            );
            certificates.push(
                db::PublicKeyMaterial::list(&mut conn, key, db::PublicKeyMaterialType::X509)
                    .await?,
            );
        }
        let before_replacement = db::Pkcs11Token::get(&mut conn, token.id).await?;
        assert_eq!(before_replacement.serial_number, "12345");
        assert_eq!(before_replacement.label, "retired-token");

        swap_pkcs11_token(&mut conn, &token, module, Some(1), hsm.user_pin.clone()).await?;
        let replacement = db::Pkcs11Token::get(&mut conn, token.id).await?;
        assert_eq!(replacement.serial_number, new_token_serial);
        assert_eq!(replacement.label, "test-token");
        assert_eq!(
            db::Key::get_token_keys(&mut conn, &replacement).await?,
            keys
        );
        for ((key, access), certificates) in keys.iter().zip(accesses).zip(certificates) {
            assert_eq!(db::KeyAccess::get(&mut conn, key, &user).await?, access);
            assert_eq!(
                db::PublicKeyMaterial::list(&mut conn, key, db::PublicKeyMaterialType::X509)
                    .await?,
                certificates
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn swap_identical_token_is_rejected() -> Result<()> {
        let hsm = setup_hsm()?;
        let db_pool = db::pool("sqlite::memory:", false).await?;
        db::migrate(&db_pool).await?;
        let mut conn = db_pool.begin().await?;
        let module = PathBuf::from("/usr/lib64/pkcs11/libkryoptic_pkcs11.so");
        let token =
            import_pkcs11_token(&mut conn, module.clone(), Some(1), hsm.user_pin.clone()).await?;

        let error = swap_pkcs11_token(
            &mut conn,
            &token,
            module.clone(),
            None,
            hsm.user_pin.clone(),
        )
        .await
        .unwrap_err();
        assert!(
            format!("{error:?}")
                .contains("The new token has the same serial number as the existing token"),
            "{error:?}"
        );

        Ok(())
    }

    #[tokio::test]
    async fn swap_pkcs11_token_rejects_invalid_pin() -> Result<()> {
        let hsm = setup_hsm()?;
        let db_pool = db::pool("sqlite::memory:", false).await?;
        db::migrate(&db_pool).await?;
        let mut conn = db_pool.begin().await?;
        let module = PathBuf::from("/usr/lib64/pkcs11/libkryoptic_pkcs11.so");
        let mut token =
            import_pkcs11_token(&mut conn, module.clone(), Some(1), hsm.user_pin.clone()).await?;

        token.serial_number = "retired-token".to_string();
        token.update(&mut conn).await?;

        let error = swap_pkcs11_token(
            &mut conn,
            &token,
            module.clone(),
            Some(1),
            AuthPin::new("wrong-pin".into()),
        )
        .await
        .unwrap_err();
        assert!(
            format!("{error:?}").contains("Failed to log into the new token with the provided PIN"),
            "{error:?}"
        );

        Ok(())
    }

    #[tokio::test]
    async fn swap_pkcs11_token_fails_with_nonsense_slot() -> Result<()> {
        let hsm = setup_hsm()?;
        let db_pool = db::pool("sqlite::memory:", false).await?;
        db::migrate(&db_pool).await?;
        let mut conn = db_pool.begin().await?;
        let module = PathBuf::from("/usr/lib64/pkcs11/libkryoptic_pkcs11.so");
        let mut token =
            import_pkcs11_token(&mut conn, module.clone(), Some(1), hsm.user_pin.clone()).await?;

        token.serial_number = "retired-token".to_string();
        token.update(&mut conn).await?;

        let error = swap_pkcs11_token(
            &mut conn,
            &token,
            module.clone(),
            Some(42),
            hsm.user_pin.clone(),
        )
        .await
        .unwrap_err();
        assert!(
            format!("{error:?}").contains("The provided token didn't have a slot with id 42"),
            "{error:?}"
        );

        Ok(())
    }

    #[tokio::test]
    async fn swap_pkcs11_token_mismatched_pubkey() -> Result<()> {
        let hsm = setup_hsm()?;
        let db_pool = db::pool("sqlite::memory:", false).await?;
        db::migrate(&db_pool).await?;
        let mut conn = db_pool.begin().await?;
        let module = PathBuf::from("/usr/lib64/pkcs11/libkryoptic_pkcs11.so");
        let mut token =
            import_pkcs11_token(&mut conn, module.clone(), Some(1), hsm.user_pin.clone()).await?;
        token.serial_number = "retired-token".to_string();
        token.update(&mut conn).await?;

        let key = db::Key::get(&mut conn, "ecc-test-key").await?;
        let wrong_public_key = openssl::pkey::PKey::generate_ed25519()?.public_key_to_pem()?;
        sqlx::query("UPDATE keys SET public_key = ? WHERE id = ?")
            .bind(String::from_utf8(wrong_public_key)?)
            .bind(key.id)
            .execute(&mut *conn)
            .await?;
        let error = swap_pkcs11_token(
            &mut conn,
            &token,
            module.clone(),
            Some(1),
            hsm.user_pin.clone(),
        )
        .await
        .unwrap_err();

        assert!(
            format!("{error:?}")
                .contains("The public key in the new token does not match the existing token"),
            "{error:?}"
        );

        Ok(())
    }

    #[tokio::test]
    async fn swap_pkcs11_token_mismatched_privkey() -> Result<()> {
        let hsm = setup_hsm()?;
        let db_pool = db::pool("sqlite::memory:", false).await?;
        db::migrate(&db_pool).await?;
        let mut conn = db_pool.begin().await?;
        let module = PathBuf::from("/usr/lib64/pkcs11/libkryoptic_pkcs11.so");
        let mut token =
            import_pkcs11_token(&mut conn, module.clone(), Some(1), hsm.user_pin.clone()).await?;
        token.serial_number = "retired-token".to_string();
        token.update(&mut conn).await?;

        let key = db::Key::get(&mut conn, "ecc-test-key").await?;

        let pkcs11 = token.intialize()?;
        {
            let session = pkcs11.open_rw_session(1_u64.try_into()?)?;
            session.login(cryptoki::session::UserType::User, Some(&hsm.user_pin))?;
            let private_key = key.get_pkcs11_private_key(&session)?;
            session.destroy_object(private_key)?;
            session.generate_key_pair(
                &Mechanism::EccKeyPairGen,
                &[
                    // Since we left the old pubkey with the old id, this will make it
                    // new private key pair with the old public key.
                    Attribute::Id(vec![99]),
                    Attribute::Token(true),
                    Attribute::EcParams(asn1::write_single(&asn1::oid!(
                        1, 2, 840, 10045, 3, 1, 7
                    ))?),
                    Attribute::Verify(true),
                ],
                &[
                    Attribute::Id(key.pkcs11_key_id.clone().unwrap()),
                    Attribute::Token(true),
                    Attribute::Private(true),
                    Attribute::Sensitive(true),
                    Attribute::Sign(true),
                ],
            )?;
        }
        pkcs11.finalize()?;

        let error = swap_pkcs11_token(
            &mut conn,
            &token,
            module.clone(),
            Some(1),
            hsm.user_pin.clone(),
        )
        .await
        .unwrap_err();
        assert!(
            format!("{error:?}")
                .contains("Failed to verify the signature produced from the new token"),
            "{error:?}"
        );

        Ok(())
    }

    #[tokio::test]
    async fn swap_pkcs11_token_missing_privkey() -> Result<()> {
        let hsm = setup_hsm()?;
        let db_pool = db::pool("sqlite::memory:", false).await?;
        db::migrate(&db_pool).await?;
        let mut conn = db_pool.begin().await?;
        let module = PathBuf::from("/usr/lib64/pkcs11/libkryoptic_pkcs11.so");
        let mut token =
            import_pkcs11_token(&mut conn, module.clone(), Some(1), hsm.user_pin.clone()).await?;
        token.serial_number = "retired-token".to_string();
        token.update(&mut conn).await?;

        let key = db::Key::get(&mut conn, "ecc-test-key").await?;

        let pkcs11 = token.intialize()?;
        {
            let session = pkcs11.open_rw_session(1_u64.try_into()?)?;
            session.login(cryptoki::session::UserType::User, Some(&hsm.user_pin))?;
            let private_key = key.get_pkcs11_private_key(&session)?;
            session.destroy_object(private_key)?;
        }
        pkcs11.finalize()?;

        let error = swap_pkcs11_token(
            &mut conn,
            &token,
            module.clone(),
            Some(1),
            hsm.user_pin.clone(),
        )
        .await
        .unwrap_err();
        assert!(
            format!("{error:?}")
                .contains("The new token returned 0 private keys rather than the expected 1"),
            "{error:?}"
        );

        Ok(())
    }

    #[tokio::test]
    async fn swap_pkcs11_token_missing_cert() -> Result<()> {
        let hsm = setup_hsm()?;
        let db_pool = db::pool("sqlite::memory:", false).await?;
        db::migrate(&db_pool).await?;
        let mut conn = db_pool.begin().await?;
        let module = PathBuf::from("/usr/lib64/pkcs11/libkryoptic_pkcs11.so");
        let mut token =
            import_pkcs11_token(&mut conn, module.clone(), Some(1), hsm.user_pin.clone()).await?;
        token.serial_number = "retired-token".to_string();
        token.update(&mut conn).await?;

        // It does need to be a real cert so this is a convenient bit of test data.
        let certificate = std::fs::read_to_string(
            &hsm.bindings
                .get(1)
                .context("Missing fixture certificate")?
                .certificate,
        )?;
        let key = db::Key::get(&mut conn, "ecc-test-key").await?;
        db::PublicKeyMaterial::create(
            &mut conn,
            &key,
            "missing-certificate".to_string(),
            db::PublicKeyMaterialType::X509,
            certificate,
        )
        .await?;
        let error = swap_pkcs11_token(
            &mut conn,
            &token,
            module.clone(),
            Some(1),
            hsm.user_pin.clone(),
        )
        .await
        .unwrap_err();

        assert!(
            format!("{error:?}").contains(
                "The new token does not have a certificate that matches 'missing-certificate'"
            ),
            "{error:?}"
        );

        Ok(())
    }

    #[tokio::test]
    async fn import_pkcs11_keys() -> Result<()> {
        let hsm = setup_hsm()?;
        let db_pool = db::pool("sqlite::memory:", false).await?;
        db::migrate(&db_pool).await?;
        let mut conn = db_pool.begin().await?;

        super::import_pkcs11_token(
            &mut conn,
            PathBuf::from("/usr/lib64/pkcs11/libkryoptic_pkcs11.so"),
            None,
            hsm.user_pin.clone(),
        )
        .await?;

        let keys = db::Key::list(&mut conn).await?;
        assert_eq!(keys.len(), 6);
        assert!(keys.iter().any(|k| k.key_algorithm == KeyAlgorithm::P256));
        assert!(
            keys.iter()
                .any(|k| k.key_algorithm == KeyAlgorithm::Ed25519)
        );
        assert!(keys.iter().any(|k| k.key_algorithm == KeyAlgorithm::Ed448));
        assert!(
            keys.iter()
                .any(|k| k.key_algorithm == KeyAlgorithm::Mldsa65)
        );
        assert!(
            keys.iter()
                .any(|k| k.key_algorithm == KeyAlgorithm::Mldsa87)
        );
        for key in keys {
            if key.key_algorithm == KeyAlgorithm::Rsa4K {
                let certs =
                    db::PublicKeyMaterial::list(&mut conn, &key, db::PublicKeyMaterialType::X509)
                        .await?;
                assert_eq!(certs.len(), 1);
            } else {
                let certs =
                    db::PublicKeyMaterial::list(&mut conn, &key, db::PublicKeyMaterialType::X509)
                        .await?;
                assert_eq!(certs.len(), 0);
            }
        }

        Ok(())
    }
}

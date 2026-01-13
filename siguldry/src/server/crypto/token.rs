use std::path::PathBuf;

use anyhow::Context;
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    object::{Attribute, AttributeType, ObjectClass},
    types::AuthPin,
};
use openssl::{hash::MessageDigest, nid::Nid, x509};
use sqlx::SqliteConnection;

use crate::{protocol::KeyAlgorithm, server::db};

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
    let token =
        db::Pkcs11Token::create(conn, module, label, manufacturer_id, model, serial_number).await?;

    // Look through the private keys, then match them up with related public key and certificates
    // using the Id attribute. Once all the bits are collect them, add them to the database.
    struct TokenKey {
        label: String,
        key_type: cryptoki::object::KeyType,
        public_key_der: Option<Vec<u8>>,
        x509_certificate_pem: Option<String>,
    }
    let mut token_keys: std::collections::HashMap<Vec<u8>, TokenKey> =
        std::collections::HashMap::new();
    let private_key_attributes = [
        AttributeType::Id,
        AttributeType::Label,
        AttributeType::KeyType,
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

        for attr in attributes {
            match attr {
                Attribute::Id(id) => key_id = Some(id),
                Attribute::Label(l) => {
                    label = String::from_utf8(l).ok();
                }
                Attribute::KeyType(kt) => key_type = Some(kt),
                _ => {}
            }
        }

        if let (Some(id), Some(label), Some(key_type)) = (key_id, label, key_type) {
            token_keys.insert(
                id,
                TokenKey {
                    label,
                    key_type,
                    public_key_der: None,
                    x509_certificate_pem: None,
                },
            );
        }
    }

    let public_key_attributes = [AttributeType::Id, AttributeType::PublicKeyInfo];
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

        for attr in attributes {
            match attr {
                Attribute::Id(id) => key_id = Some(id),
                Attribute::PublicKeyInfo(der) => public_key_info = Some(der),
                _ => {}
            }
        }

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
        {
            let pem = x509::X509::from_der(&der)
                .and_then(|cert| cert.to_pem())
                .ok()
                .and_then(|pem_bytes| String::from_utf8(pem_bytes).ok());
            entry.x509_certificate_pem = pem;
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
            let handle = format!(
                "{:X?}",
                openssl::hash::hash(MessageDigest::sha256(), &public_key.public_key_to_der()?)?
            );
            let key_material = format!("{:X?}", key_id);
            let key = db::Key::create(
                conn,
                &key_info.label,
                &handle,
                key_algorithm,
                db::KeyPurpose::Signing,
                &key_material,
                &pubkey_pem,
                Some(&token),
                Some(key_id.clone()),
            )
            .await?;
            if let Some(data) = key_info.x509_certificate_pem.clone() {
                db::PublicKeyMaterial::create(conn, &key, db::PublicKeyMaterialType::X509, data)
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
        assert_eq!(keys.len(), 2);
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

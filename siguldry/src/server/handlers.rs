// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::io::Write;

use anyhow::Context;
use bytes::Bytes;
use sequoia_keystore::Keystore;
use sequoia_openpgp::{
    crypto::Password,
    parse::Parse,
    serialize::{
        stream::{LiteralWriter, Message, Signer},
        MarshalInto,
    },
    KeyHandle,
};
use sqlx::SqliteConnection;
use tracing::instrument;

use crate::{
    protocol::{json, GpgSignatureType, Response, ServerError},
    server::{
        crypto,
        db::{self, User},
        Config,
    },
};

#[instrument(skip_all, err)]
pub(crate) async fn who_am_i(user: &User) -> Result<Response, ServerError> {
    Ok(json::Response::WhoAmI {
        user: user.name.clone(),
    }
    .into())
}

#[instrument(skip_all, err)]
pub(crate) async fn list_users(conn: &mut SqliteConnection) -> Result<Response, ServerError> {
    let users = User::list(conn)
        .await?
        .into_iter()
        .map(|user| user.name)
        .collect();

    Ok(json::Response::ListUsers { users }.into())
}

#[instrument(skip_all, err, fields(key = key_name))]
pub(crate) async fn public_key(
    conn: &mut SqliteConnection,
    config: &Config,
    key_name: String,
) -> Result<Response, ServerError> {
    let key = db::Key::get(conn, &key_name).await?;
    let cert_path = config.gpg_keystore()?.join(format!("{}.asc", &key.handle));
    let cert_bytes = tokio::fs::read(&cert_path).await?;
    let cert = sequoia_openpgp::Cert::from_bytes(&cert_bytes)?;
    let version = cert.primary_key().key().version();
    let fingerprint = cert.fingerprint().to_hex();
    let public_key = cert.strip_secret_key_material().armored().to_vec()?;
    let public_key =
        String::from_utf8(public_key).context("The armored public key isn't valid UTF-8")?;

    Ok(json::Response::PublicKey {
        key: crate::protocol::Key::Gpg {
            version,
            public_key,
            fingerprint,
        },
    }
    .into())
}

#[instrument(skip_all, err, fields(key = key_name))]
pub(crate) async fn unlock(
    conn: &mut SqliteConnection,
    keystore: &mut Keystore,
    config: &Config,
    user: &User,
    key_name: String,
    user_password: Password,
) -> Result<Response, ServerError> {
    let key = db::Key::get(conn, &key_name).await?;
    let key_access = db::KeyAccess::get(conn, &key, user).await?;
    let cert_path = config.gpg_keystore()?.join(format!("{}.asc", &key.handle));
    let cert_bytes = tokio::fs::read(&cert_path).await?;
    let cert = sequoia_openpgp::Cert::from_bytes(&cert_bytes)?;

    // TODO based on key's storage location
    let mut softkey_backend = {
        let mut result = Err(anyhow::anyhow!("Must be compiled with softkey support"));
        for mut backend in keystore.backends_async().await? {
            if backend.id_async().await.is_ok_and(|id| id == "softkeys") {
                result = Ok(backend);
                break;
            }
        }
        result
    }?;
    let mut result = softkey_backend.import_async(&cert).await?;
    let (import_status, mut imported_key) = result.pop().ok_or_else(|| {
        anyhow::anyhow!(
            "Sequoia backend reported no keys were imported for {}",
            &key.handle
        )
    })?;
    let signing_capable = imported_key.signing_capable_async().await?;
    tracing::debug!(?import_status, signing_capable, handle=?imported_key.key_handle(), "Successfully imported PGP key");
    let password = crypto::decrypt_key_password(
        &config.pkcs11_bindings,
        user_password,
        &key_access.encrypted_passphrase,
    )
    .await?;
    imported_key.unlock_async(password).await?;
    tracing::info!(handle=?imported_key.key_handle(), "Successfully unlocked PGP key");

    Ok(json::Response::Unlock {}.into())
}

#[instrument(skip_all, err, fields(key = key_name))]
pub(crate) async fn gpg_sign(
    conn: &mut SqliteConnection,
    keystore: &mut Keystore,
    key_name: &str,
    signature_type: GpgSignatureType,
    blob: Bytes,
) -> Result<Response, ServerError> {
    let key = db::Key::get(conn, key_name).await?;
    let key_handle: KeyHandle = key.handle.parse()?;
    let key = keystore
        .find_key_async(key_handle.clone())
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("No key with handle {} available!", key_handle))?;
    tracing::debug!(handle=?key_handle, "keystore found key");

    // Unfortunately there's not an async interface for this yet.
    let span = tracing::Span::current();
    let signature = tokio::task::spawn_blocking(move || {
        let _guard = span.enter();
        let mut sink = vec![];
        {
            let signer = Signer::new(Message::new(&mut sink), key)?;
            let mut message = match signature_type {
                GpgSignatureType::Detached => signer.detached().build()?,
                GpgSignatureType::Cleartext => signer.cleartext().build()?,
                GpgSignatureType::Inline => LiteralWriter::new(signer.build()?).build()?,
            };

            message.write_all(&blob)?;
            message.finalize()?;
            tracing::trace!("Successfully signed message");
        }
        Ok::<_, anyhow::Error>(sink)
    })
    .await??;

    let response = Response {
        json: json::Response::GpgSign {},
        binary: Some(Bytes::from(signature)),
    };

    Ok(response)
}

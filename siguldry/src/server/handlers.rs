// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::{
    collections::HashMap,
    fs::Permissions,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Stdio,
};

use anyhow::{Context, anyhow};
use bytes::Bytes;
use sequoia_keystore::Keystore;
use sequoia_openpgp::{
    KeyHandle,
    crypto::Password,
    parse::Parse,
    serialize::stream::{LiteralWriter, Message, Signer},
};
use sqlx::SqliteConnection;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::instrument;

use crate::{
    protocol::{
        self, DigestAlgorithm, GpgSignatureType, KeyAlgorithm, Response, ServerError,
        json::{self, Signature},
    },
    server::{
        Config, crypto,
        db::{self, KeyLocation, User},
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

#[instrument(skip_all, err)]
pub(crate) async fn list_keys(conn: &mut SqliteConnection) -> Result<Response, ServerError> {
    let mut keys = vec![];
    for key in db::Key::list(conn).await? {
        let certificates = if key.key_location == KeyLocation::SequoiaSoftkey {
            let cert = sequoia_openpgp::Cert::from_bytes(&key.key_material.as_bytes())?;
            let version = cert.primary_key().key().version();
            let fingerprint = cert.fingerprint().to_hex();
            vec![crate::protocol::Certificate::Gpg {
                version,
                fingerprint,
                certificate: key.public_key.clone(),
            }]
        } else {
            db::PublicKeyMaterial::list(conn, &key, db::PublicKeyMaterialType::X509)
                .await?
                .into_iter()
                .map(|cert| crate::protocol::Certificate::X509 {
                    certificate: cert.data,
                })
                .collect()
        };
        keys.push(protocol::Key {
            name: key.name,
            key_algorithm: key.key_algorithm,
            handle: key.handle,
            public_key: key.public_key,
            certificates,
        });
    }

    Ok(json::Response::ListKeys { keys }.into())
}

#[instrument(skip_all, err, fields(key = key_name))]
pub(crate) async fn public_key(
    conn: &mut SqliteConnection,
    key_name: String,
) -> Result<Response, ServerError> {
    let key = db::Key::get(conn, &key_name).await?;
    let key = if key.key_location == KeyLocation::SequoiaSoftkey {
        let cert = sequoia_openpgp::Cert::from_bytes(&key.key_material.as_bytes())?;
        let version = cert.primary_key().key().version();
        let fingerprint = cert.fingerprint().to_hex();
        crate::protocol::Certificate::Gpg {
            version,
            fingerprint,
            certificate: key.public_key,
        }
    } else {
        let mut cert =
            db::PublicKeyMaterial::list(conn, &key, db::PublicKeyMaterialType::X509).await?;
        let cert = cert
            .pop()
            .ok_or_else(|| anyhow::anyhow!("No certificate for this key"))?;
        crate::protocol::Certificate::X509 {
            certificate: cert.data,
        }
    };

    Ok(json::Response::Certificates { keys: vec![key] }.into())
}

// TODO: Probably create a struct to hold common args and create a handler instance per connection
#[allow(clippy::too_many_arguments)]
#[instrument(skip_all, err, fields(key = key_name))]
pub(crate) async fn unlock(
    conn: &mut SqliteConnection,
    gpg_keystore: &mut Keystore,
    keystore_dir: &Path,
    key_passwords: &mut HashMap<String, (PathBuf, Password)>,
    config: &Config,
    user: &User,
    key_name: String,
    user_password: Password,
) -> Result<Response, ServerError> {
    let key = db::Key::get(conn, &key_name).await?;
    let key_access = db::KeyAccess::get(conn, &key, user).await?;
    let password = crypto::decrypt_key_password(
        &config.pkcs11_bindings,
        user_password,
        &key_access.encrypted_passphrase,
    )
    .await?;
    if key.key_location != KeyLocation::SequoiaSoftkey {
        let mut temp_builder = tempfile::Builder::new();
        let f = temp_builder
            .permissions(Permissions::from_mode(0o700))
            .rand_bytes(32)
            .suffix("privkey.pem")
            .disable_cleanup(true)
            .tempfile_in(keystore_dir)?;
        tokio::fs::write(f.path(), key.key_material).await?;
        key_passwords.insert(key.name, (f.path().to_path_buf(), password));
        return Ok(json::Response::Unlock {
            public_key: key.public_key,
        }
        .into());
    }

    let cert = sequoia_openpgp::Cert::from_bytes(&key.key_material)?;

    // TODO based on key's storage location
    let mut softkey_backend = {
        let mut result = Err(anyhow::anyhow!("Must be compiled with softkey support"));
        for mut backend in gpg_keystore.backends_async().await? {
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
    imported_key.unlock_async(password).await?;
    tracing::info!(handle=?imported_key.key_handle(), "Successfully unlocked PGP key");

    Ok(json::Response::Unlock {
        public_key: key.public_key,
    }
    .into())
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
        .ok_or_else(|| anyhow::anyhow!("No key with handle {key_handle} available!"))?;
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

async fn private_sign_prehashed(
    conn: &mut SqliteConnection,
    key_passwords: &mut HashMap<String, (PathBuf, Password)>,
    key_name: &str,
    digests: Vec<(DigestAlgorithm, String)>,
) -> anyhow::Result<Vec<Signature>> {
    let key = db::Key::get(conn, key_name).await?;
    let (key_path, key_password) = key_passwords
        .get(key_name)
        .ok_or_else(|| anyhow!("You need to unlock the key"))?;
    let key_path = match key.key_location {
        KeyLocation::Pkcs11 => Ok(key.handle),
        KeyLocation::Encrypted => key_path
            .to_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("Path isn't a UTF-8 string")),
        KeyLocation::SequoiaSoftkey => Err(anyhow!("Cannot use GPG keys with this command")),
    }?;

    let mut signatures = Vec::with_capacity(digests.len());
    for (algorithm, hex_hash) in digests {
        let hash = hex::decode(&hex_hash).context("The digest provided was not valid hex")?;
        if hash.len() != algorithm.size() {
            return Err(anyhow!(
                "The specified digest algorithm is {} bytes; payload was {}",
                algorithm.size(),
                hash.len()
            ));
        }

        // We shell out to OpenSSL since we may be signing via PKCS#11 and the library doesn't support
        // the provider API. Additionally, it keeps the decrypted key material out of our process.
        // This is super inefficient so probably I need to write an equivalent to sequoia-keyserver
        let mut signing_command = tokio::process::Command::new("openssl");
        signing_command
            .env_clear()
            .kill_on_drop(true)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .arg("pkeyutl")
            .arg("-sign")
            .arg("-inkey")
            .arg(&key_path)
            .arg("-passin")
            .arg("stdin")
            .arg("-provider")
            .arg("pkcs11")
            .arg("-pkeyopt")
            .arg(format!("digest:{algorithm}"));

        if key.key_algorithm == KeyAlgorithm::Rsa4K {
            // PKCS #1 should be the default, but lets be explicit about it.
            signing_command
                .arg("-pkeyopt")
                .arg("rsa_padding_mode:pkcs1");
        }
        let mut child = signing_command.spawn()?;
        let mut stdin = child
            .stdin
            .take()
            .expect("The child must configured stdin as a pipe");
        let mut stdout = child
            .stdout
            .take()
            .expect("The child must configured stdout as a pipe");
        let mut stderr = child
            .stderr
            .take()
            .expect("The child must configured stdout as a pipe");

        let password = key_password.to_owned();
        let writer = tokio::spawn(async move {
            // TODO not ideal but there's no way to map the password to an async write.
            // Maybe just convert to a std Command and spawn_blocking
            let p = password.map(|p| p.to_vec());
            stdin.write_all(&p).await?;
            stdin.write_all(b"\n").await?;
            stdin.write_all(&hash).await
        });
        let reader = tokio::spawn(async move {
            let mut signature = vec![];
            stdout.read_to_end(&mut signature).await?;
            Ok::<_, anyhow::Error>(signature)
        });
        writer.await??;
        let result = child.wait().await?;
        if !result.success() {
            let mut failure_message = String::new();
            stderr.read_to_string(&mut failure_message).await?;
            return Err(anyhow!(
                "OpenSSL failed to sign request ({result:?}): {failure_message}"
            ));
        }
        let signature = reader.await??;
        let signature = Signature {
            signature,
            digest: algorithm,
            hash: hex_hash,
        };
        signatures.push(signature);
    }

    Ok(signatures)
}

#[instrument(skip_all, err, fields(key = key_name))]
pub(crate) async fn sign(
    conn: &mut SqliteConnection,
    key_passwords: &mut HashMap<String, (PathBuf, Password)>,
    key_name: &str,
    digest: DigestAlgorithm,
    blob: Bytes,
) -> Result<Response, ServerError> {
    let mut hash =
        openssl::hash::Hasher::new(digest.into()).context("OpenSSL missing support for digest")?;
    hash.write_all(&blob)?;
    let hash = hex::encode(hash.finish().context("Unable to hash payload")?);
    let mut response =
        private_sign_prehashed(conn, key_passwords, key_name, vec![(digest, hash)]).await?;

    Ok(Response {
        json: json::Response::Sign {},
        binary: Some(Bytes::from(response.pop().unwrap().signature)),
    })
}

#[instrument(skip_all, err, fields(key = key_name))]
pub(crate) async fn sign_prehashed(
    conn: &mut SqliteConnection,
    key_passwords: &mut HashMap<String, (PathBuf, Password)>,
    key_name: &str,
    digests: Vec<(DigestAlgorithm, String)>,
) -> Result<Response, ServerError> {
    let signatures = private_sign_prehashed(conn, key_passwords, key_name, digests).await?;

    Ok(Response {
        json: json::Response::SignPrehashed { signatures },
        binary: None,
    })
}

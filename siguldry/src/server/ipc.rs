// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::path::PathBuf;
use std::{collections::HashMap, io::Write};

use bytes::Bytes;
use cryptoki::types::AuthPin;
use sequoia_openpgp::{
    KeyHandle,
    crypto::Password,
    parse::Parse,
    policy::StandardPolicy,
    serialize::stream::{LiteralWriter, Message, Signer as PgpSigner},
};
use serde::{Deserialize, Serialize};
use sqlx::SqliteConnection;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio_util::sync::CancellationToken;
use tracing::instrument;
use uuid::Uuid;

use crate::error::ServerError;
use crate::ipc_common::IpcClient;
use crate::protocol::{self, GpgSignatureType};
use crate::server::config::Pkcs11Binding;
use crate::{
    protocol::{DigestAlgorithm, json::Signature},
    server::{Config, crypto, db},
};

/// The PKCS#11 bindings required to access keys, along with the PINs provided at service startup.
/// This is redefined from [`Pkcs11Binding`] because it does need to serialize/deserialize the PIN.
#[derive(Serialize, Deserialize)]
#[allow(clippy::exhaustive_enums)]
#[doc(hidden)]
struct BindingWithPin {
    public_key: PathBuf,
    private_key: String,
    pin: String,
}

impl From<BindingWithPin> for Pkcs11Binding {
    fn from(value: BindingWithPin) -> Self {
        Pkcs11Binding {
            certificate: value.public_key,
            private_key: Some(value.private_key),
            pin: Some(Password::from(value.pin)),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[allow(clippy::exhaustive_enums)]
#[doc(hidden)]
enum Request {
    Config {
        user: String,
        database_path: String,
        session_id: Uuid,
        pkcs11_bindings: Vec<BindingWithPin>,
    },
    Unlock {
        key: String,
        password: String,
    },
    Sign {
        key: String,
        digests: Vec<(DigestAlgorithm, String)>,
    },
    PgpSign {
        key: String,
        signature_type: GpgSignatureType,
        payload_size: usize,
    },
}

#[derive(Serialize, Deserialize)]
#[allow(clippy::exhaustive_enums)]
#[doc(hidden)]
enum Response {
    Signatures { signatures: Vec<Signature> },
    PgpSign { payload_size: usize },
    Success {},
    Failure { reason: String },
}

pub(crate) struct Client {
    inner: IpcClient,
}

impl Client {
    pub(crate) async fn new(
        user: String,
        config: Config,
        session_id: Uuid,
    ) -> anyhow::Result<Self> {
        let inner = IpcClient::new(&config.signer_socket_path).await?;
        let mut client = Self { inner };

        tracing::trace!("requesting signing helper config");
        let mut bindings = vec![];
        for binding in config.pkcs11_bindings.iter() {
            if let (Some(private_key), Some(pin)) = (&binding.private_key, &binding.pin) {
                let pin = pin.map(|p| String::from_utf8(p.to_vec()))?;
                bindings.push(BindingWithPin {
                    public_key: binding.certificate.clone(),
                    private_key: private_key.clone(),
                    pin,
                });
            }
        }
        let database_path = config
            .database()
            .as_os_str()
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Database path isn't valid UTF8"))?
            .to_string();
        client
            .inner
            .request(
                &Request::Config {
                    user,
                    database_path,
                    session_id,
                    pkcs11_bindings: bindings,
                },
                None,
            )
            .await?;
        tracing::trace!("requested signing helper config");

        Ok(client)
    }

    #[instrument(skip_all, err, fields(key))]
    pub(crate) async fn unlock_request(
        &mut self,
        key: String,
        password: String,
    ) -> Result<protocol::Response, ServerError> {
        let response = self
            .inner
            .request(&Request::Unlock { key, password }, None)
            .await?;
        let response = serde_json::from_value(response).map_err(|error| {
            tracing::error!(?error, "helper returned invalid response");
            ServerError::Internal
        })?;

        match response {
            Response::Failure { reason } => {
                tracing::error!(reason, "Failed to unlock key");
                Err(ServerError::Internal)
            }
            Response::Success {} => Ok(protocol::json::Response::Unlock {}.into()),
            _ => {
                tracing::error!("helper returned invalid response");
                Err(ServerError::Internal)
            }
        }
    }

    #[instrument(skip_all, err, fields(key))]
    pub(crate) async fn sign_request(
        &mut self,
        key: String,
        digests: Vec<(DigestAlgorithm, String)>,
    ) -> Result<Vec<Signature>, ServerError> {
        let response = self
            .inner
            .request(&Request::Sign { key, digests }, None)
            .await?;
        let response = serde_json::from_value(response).map_err(|error| {
            tracing::error!(?error, "helper returned invalid response");
            ServerError::Internal
        })?;

        match response {
            Response::Signatures { signatures } => Ok(signatures),
            Response::Failure { reason } => {
                tracing::error!(reason, "Failed to unlock key");
                Err(ServerError::Internal)
            }
            _ => {
                tracing::error!("helper returned invalid response");
                Err(ServerError::Internal)
            }
        }
    }

    #[instrument(skip_all, err, fields(key, signature_type))]
    pub(crate) async fn pgp_sign_request(
        &mut self,
        key: String,
        signature_type: GpgSignatureType,
        blob: Bytes,
    ) -> anyhow::Result<protocol::Response> {
        let payload_size = blob.len();
        let response = self
            .inner
            .request(
                &Request::PgpSign {
                    key,
                    signature_type,
                    payload_size,
                },
                Some(&blob),
            )
            .await
            .map_err(|_| ServerError::Internal)?;
        let response: Response = serde_json::from_value(response)?;
        let payload_size = match response {
            Response::PgpSign { payload_size } => Ok(payload_size),
            Response::Failure { reason } => Err(anyhow::anyhow!("failed to unlock key: {reason}")),
            _ => Err(anyhow::anyhow!("helper returned invalid response")),
        }?;
        tracing::trace!(payload_size, "helper response received");
        let binary = self.inner.read_bytes(payload_size).await?;

        let response = protocol::Response {
            json: protocol::json::Response::GpgSign {},
            binary: Some(binary),
        };

        Ok(response)
    }

    /// Shut down the IPC client.
    pub(crate) async fn shutdown(self) -> anyhow::Result<()> {
        self.inner.shutdown().await?;
        Ok(())
    }
}

/// Start a siguldry-signer helper server.
#[instrument(name = "siguldry-signer", skip_all, fields(session_id = tracing::field::Empty))]
pub async fn serve<
    R: AsyncRead + Unpin + std::fmt::Debug,
    W: AsyncWrite + Unpin + std::fmt::Debug,
>(
    halt_token: CancellationToken,
    requests: R,
    mut responses: W,
) -> anyhow::Result<()> {
    tracing::info!("Handling requests");
    let mut requests = BufReader::new(requests).lines();

    // Keys that the client has unlocked are stored in this map of key names to key passwords.
    // A performance optimization might be to decrypt the key once; we should benchmark and
    // decide on that.
    let mut key_passwords: HashMap<String, Password> = HashMap::new();
    let (user, database_path, pkcs11_bindings) = tokio::select! {
        _ = halt_token.cancelled() => {
            tracing::info!("siguldry-helper received shut down signal");
            return Ok(())
        }
        request = requests.next_line() => {
            match request? {
                Some(request) => {
                    let request: Request = serde_json::from_str(&request)?;
                    match request {
                        Request::Config { user, database_path, session_id, pkcs11_bindings } => {
                            tracing::Span::current().record("session_id", session_id.to_string());
                            let mut response = serde_json::to_string(&Response::Success {  })?;
                            response.push('\n');
                            responses.write_all(response.as_bytes()).await?;
                            let bindings = pkcs11_bindings.into_iter().map(|b| b.into()).collect::<Vec<Pkcs11Binding>>();
                            (user, database_path, bindings)},
                        _ => return Err(anyhow::anyhow!("The first message must configure this helper"))
                    }
                },
                None => return Ok(())
            }
        }
    };

    let db_pool = db::pool(&database_path, true).await?;
    let mut db_conn = db_pool.acquire().await?;
    let user = db::User::get(&mut db_conn, &user).await?;
    drop(db_conn);
    tracing::debug!(user.name, "siguldry-signer is configured and ready to use");

    loop {
        let request = tokio::select! {
            _ = halt_token.cancelled() => {
                tracing::info!("siguldry-signer received shut down signal");
                break;
            }
            request = requests.next_line() => request,
        }?;
        tracing::debug!("siguldry-signer got request");

        let request = if let Some(request) = request {
            serde_json::from_str(&request)?
        } else {
            tracing::info!("siguldry-signer received EOF and is shutting down");
            break;
        };

        let response = match request {
            Request::Config {
                user: _,
                database_path: _,
                session_id: _,
                pkcs11_bindings: _,
            } => Response::Failure {
                reason: "helper cannot be configured twice".to_string(),
            },
            Request::Unlock { key, password } => {
                let mut conn = db_pool.begin().await?;
                match unlock(
                    &mut conn,
                    &mut key_passwords,
                    &pkcs11_bindings,
                    &user,
                    key,
                    Password::from(password),
                )
                .await
                {
                    Ok(_) => Response::Success {},
                    Err(error) => Response::Failure {
                        reason: error.to_string(),
                    },
                }
            }
            Request::Sign { key, digests } => {
                let mut conn = db_pool.begin().await?;
                match sign(&mut conn, &mut key_passwords, &key, digests).await {
                    Ok(signatures) => Response::Signatures { signatures },
                    Err(error) => Response::Failure {
                        reason: error.to_string(),
                    },
                }
            }
            Request::PgpSign {
                key,
                signature_type,
                payload_size,
            } => {
                let mut inner = requests.into_inner();
                let mut buffer = vec![0; payload_size];
                inner.read_exact(&mut buffer).await?;
                requests = inner.lines();

                let mut conn = db_pool.begin().await?;
                let (response, signature) =
                    pgp_sign(&mut conn, &key_passwords, &key, signature_type, buffer).await?;
                tracing::trace!("Finished signing request");

                let mut response = serde_json::to_string(&response)?;
                response.push('\n');
                responses.write_all(response.as_bytes()).await?;
                tracing::trace!("Finished writing pgp_sign json response");
                responses.write_all(&signature).await?;
                responses.flush().await?;
                tracing::trace!(
                    payload_len = signature.len(),
                    "Finished writing pgp_sign signature"
                );
                continue;
            }
        };
        tracing::trace!("About to write response");
        let mut response = serde_json::to_string(&response)?;
        response.push('\n');
        responses.write_all(response.as_bytes()).await?;
        tracing::trace!("Successfully wrote response");
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[instrument(skip_all, err, fields(key = key_name))]
async fn unlock(
    conn: &mut SqliteConnection,
    key_passwords: &mut HashMap<String, Password>,
    pkcs11_bindings: &[Pkcs11Binding],
    user: &db::User,
    key_name: String,
    user_password: Password,
) -> anyhow::Result<()> {
    let key = db::Key::get(conn, &key_name).await?;
    let key_access = db::KeyAccess::get(conn, &key, user).await?;
    let password = crypto::binding::decrypt_key_password(
        pkcs11_bindings,
        user_password,
        &key_access.encrypted_passphrase,
    )
    .await?;
    key_passwords.insert(key.name, password);
    return Ok(());
}

#[instrument(skip_all, err, fields(key = key_name))]
async fn sign(
    conn: &mut SqliteConnection,
    key_passwords: &mut HashMap<String, Password>,
    key_name: &str,
    digests: Vec<(DigestAlgorithm, String)>,
) -> anyhow::Result<Vec<Signature>> {
    let key = db::Key::get(conn, key_name).await?;
    let password = key_passwords
        .get(key_name)
        .ok_or_else(|| anyhow::anyhow!("You need to unlock the key"))?;

    let signatures = if let Some(token_id) = key.pkcs11_token_id {
        // For PKCS#11 keys, fetch the token information and use the configured PIN
        // TODO: don't initialize/uninitialize over and over, keep a session going
        let token = db::Pkcs11Token::get(conn, token_id).await?;
        let pkcs11 = token.intialize()?;
        let pin = password
            .map(|p| String::from_utf8(p.to_vec()))
            .map(AuthPin::from)?;
        let session = token.pkcs11_session(&pkcs11, &pin)?;
        let result = crypto::signing::sign_with_pkcs11(&key, &session, digests);
        pkcs11.finalize()?;
        result?
    } else {
        crypto::signing::sign_with_softkey(&key, password, digests)?
    };

    Ok(signatures)
}

#[instrument(skip_all, err, fields(key = key_name))]
async fn pgp_sign(
    conn: &mut SqliteConnection,
    keystore: &HashMap<String, Password>,
    key_name: &str,
    signature_type: GpgSignatureType,
    blob: Vec<u8>,
) -> anyhow::Result<(Response, Vec<u8>)> {
    let key = db::Key::get(conn, key_name).await?;
    let password = keystore
        .get(key_name)
        .ok_or_else(|| anyhow::anyhow!("Key must be unlocked before signing"))?;
    let cert = sequoia_openpgp::Cert::from_bytes(&key.key_material)?;
    let policy = &StandardPolicy::new();
    let signing_key = cert
        .keys()
        .secret()
        .with_policy(policy, None)
        .supported()
        .for_signing()
        .next()
        .ok_or_else(|| anyhow::anyhow!("No signing-capable key found in certificate"))?
        .key()
        .clone()
        .decrypt_secret(password)?
        .into_keypair()?;
    let key_handle: KeyHandle = key.handle.parse()?;
    tracing::debug!(handle=?key_handle, "keystore found key");

    let signature = {
        let mut sink = vec![];
        let signer = PgpSigner::new(Message::new(&mut sink), signing_key)?;
        let mut message = match signature_type {
            GpgSignatureType::Detached => signer.detached().build()?,
            GpgSignatureType::Cleartext => signer.cleartext().build()?,
            GpgSignatureType::Inline => LiteralWriter::new(signer.build()?).build()?,
        };

        message.write_all(&blob)?;
        message.finalize()?;
        tracing::trace!("Successfully signed message");
        Ok::<_, anyhow::Error>(sink)
    }?;

    let response = Response::PgpSign {
        payload_size: signature.len(),
    };

    Ok((response, signature))
}

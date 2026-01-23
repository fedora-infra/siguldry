// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
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
use tokio::io::{
    AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, Lines, ReadHalf, WriteHalf,
};
use tokio::net::UnixStream;
use tokio::process::{Child, ChildStdin, ChildStdout};
use tokio_util::sync::CancellationToken;
use tracing::instrument;
use uuid::Uuid;

use crate::error::ServerError;
use crate::protocol::{self, GpgSignatureType};
use crate::server::config::Pkcs11Binding;
use crate::signal_handler;
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
    inner: ClientInner,
}

/// The inner state depends on whether we're using socket activation or direct spawning.
enum ClientInner {
    /// Socket-activated mode: we connect to a Unix socket managed by systemd.
    Socket {
        writer: WriteHalf<UnixStream>,
        reader: Option<Lines<BufReader<ReadHalf<UnixStream>>>>,
    },
    /// Direct spawn mode: we spawn the signer process directly.
    Process {
        child: Box<Child>,
        writer: ChildStdin,
        reader: Option<Lines<BufReader<ChildStdout>>>,
    },
}

impl Client {
    pub(crate) async fn new(
        user: String,
        config: Config,
        session_id: Uuid,
    ) -> anyhow::Result<Self> {
        let inner = if let Some(executable) = config.signer_executable.as_ref() {
            // Direct spawn mode for testing
            Self::spawn_directly(executable, &session_id).await?
        } else {
            // Socket activation mode for production
            Self::connect_socket(&config.signer_socket_path, &session_id).await?
        };

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
            .request(&Request::Config {
                user,
                database_path,
                session_id,
                pkcs11_bindings: bindings,
            })
            .await?;
        tracing::trace!("requested signing helper config");

        Ok(client)
    }

    async fn connect_socket(
        socket_path: &std::path::Path,
        session_id: &Uuid,
    ) -> anyhow::Result<ClientInner> {
        tracing::debug!(
            ?socket_path,
            %session_id,
            "Connecting to socket-activated signer"
        );

        let stream = UnixStream::connect(&socket_path).await.map_err(|e| {
            anyhow::anyhow!(
                "Failed to connect to signer socket at {}: {}. \
                 Ensure siguldry-signer.socket is enabled and started.",
                socket_path.display(),
                e
            )
        })?;

        let (reader, writer) = tokio::io::split(stream);
        let reader = Some(BufReader::new(reader).lines());

        Ok(ClientInner::Socket { writer, reader })
    }

    async fn spawn_directly(
        executable: &std::path::Path,
        session_id: &Uuid,
    ) -> anyhow::Result<ClientInner> {
        tracing::debug!(
            ?executable,
            %session_id,
            "Spawning signer process directly"
        );

        let mut command = tokio::process::Command::new(executable);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        let mut child = command.spawn().map_err(|e| {
            anyhow::anyhow!(
                "Failed to spawn signer executable at {}: {}",
                executable.display(),
                e
            )
        })?;

        let writer = child.stdin.take().expect("stdin was piped");
        let stdout = child.stdout.take().expect("stdout was piped");
        let reader = Some(BufReader::new(stdout).lines());

        Ok(ClientInner::Process {
            child: Box::new(child),
            writer,
            reader,
        })
    }

    /// Write a request and read the response line.
    async fn request(&mut self, request: &Request) -> anyhow::Result<Response> {
        let mut request_str = serde_json::to_string(request)?;
        request_str.push('\n');

        let response = match &mut self.inner {
            ClientInner::Socket { writer, reader } => {
                writer.write_all(request_str.as_bytes()).await?;
                reader.as_mut().unwrap().next_line().await?
            }
            ClientInner::Process { writer, reader, .. } => {
                writer.write_all(request_str.as_bytes()).await?;
                reader.as_mut().unwrap().next_line().await?
            }
        };

        match response {
            Some(response) => Ok(serde_json::from_str(&response)?),
            None => Err(anyhow::anyhow!("IPC server returned EOF unexpectedly!")),
        }
    }

    #[instrument(skip_all, err, fields(key))]
    pub(crate) async fn unlock_request(
        &mut self,
        key: String,
        password: String,
    ) -> Result<protocol::Response, ServerError> {
        let response = self.request(&Request::Unlock { key, password }).await?;

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
        let response = self.request(&Request::Sign { key, digests }).await?;

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
        let mut request = serde_json::to_string(&Request::PgpSign {
            key,
            signature_type,
            payload_size,
        })?;
        request.push('\n');

        // Write request and binary payload
        match &mut self.inner {
            ClientInner::Socket { writer, .. } => {
                writer.write_all(request.as_bytes()).await?;
                writer.write_all(&blob).await?;
                writer.flush().await?;
            }
            ClientInner::Process { writer, .. } => {
                writer.write_all(request.as_bytes()).await?;
                writer.write_all(&blob).await?;
                writer.flush().await?;
            }
        }

        let response_line = match &mut self.inner {
            ClientInner::Socket { reader, .. } => reader.as_mut().unwrap().next_line().await,
            ClientInner::Process { reader, .. } => reader.as_mut().unwrap().next_line().await,
        }?;
        let payload_size = match response_line {
            Some(response) => {
                let response: Response = serde_json::from_str(&response)?;
                match response {
                    Response::PgpSign { payload_size } => Ok(payload_size),
                    Response::Failure { reason } => {
                        Err(anyhow::anyhow!("failed to unlock key: {reason}"))
                    }
                    _ => Err(anyhow::anyhow!("helper returned invalid response")),
                }
            }
            None => Err(anyhow::anyhow!(
                "siguldry-signer returned EOF unexpectedly!"
            )),
        }?;
        tracing::trace!(payload_size, "helper response received");

        let mut buffer = vec![0; payload_size];
        tracing::trace!(len = buffer.len(), "trying to read into buf");

        match &mut self.inner {
            ClientInner::Socket { reader, .. } => {
                let mut inner = reader.take().unwrap().into_inner();
                inner.read_exact(&mut buffer).await?;
                *reader = Some(inner.lines());
            }
            ClientInner::Process { reader, .. } => {
                let mut inner = reader.take().unwrap().into_inner();
                inner.read_exact(&mut buffer).await?;
                *reader = Some(inner.lines());
            }
        }
        tracing::trace!(payload_size, "signature read");

        let response = protocol::Response {
            json: protocol::json::Response::GpgSign {},
            binary: Some(Bytes::from(buffer)),
        };

        Ok(response)
    }

    /// Shut down the IPC client.
    pub(crate) async fn shutdown(self) -> anyhow::Result<()> {
        match self.inner {
            ClientInner::Socket { mut writer, .. } => {
                writer.shutdown().await?;
            }
            ClientInner::Process {
                mut child, writer, ..
            } => {
                drop(writer);
                // Wait for the process to exit gracefully
                let _ = tokio::time::timeout(Duration::from_secs(1), child.wait()).await;
            }
        }

        Ok(())
    }
}

/// Start a siguldry-signer helper server.
#[instrument(name = "siguldry-signer", fields(session_id = tracing::field::Empty))]
pub async fn serve() -> anyhow::Result<()> {
    tracing::info!("Handling requests");
    let mut requests = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();

    let halt_token = CancellationToken::new();
    tokio::spawn(signal_handler(halt_token.clone()));

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
                            stdout.write_all(response.as_bytes()).await?;
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
                stdout.write_all(response.as_bytes()).await?;
                tracing::trace!("Finished writing pgp_sign json response");
                stdout.write_all(&signature).await?;
                stdout.flush().await?;
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
        stdout.write_all(response.as_bytes()).await?;
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

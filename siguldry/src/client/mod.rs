// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! The Siguldry client.
//!
use std::collections::VecDeque;
use std::path::PathBuf;
use std::{sync::Arc, time::Duration};

use anyhow::Context;
use bytes::{BufMut, Bytes, BytesMut};
use sequoia_openpgp::crypto::Password;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio::sync::oneshot::Receiver;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{mpsc, oneshot},
};
use tracing::instrument;
use uuid::Uuid;
use zerocopy::{IntoBytes, TryFromBytes};

use crate::protocol::json::Signature;
use crate::protocol::{DigestAlgorithm, GpgSignatureType};
use crate::{
    config::Credentials,
    error::{ClientError, ConnectionError},
    nestls::Nestls,
    protocol::{
        self, Frame, Request, Role,
        json::{OuterRequest, OuterResponse, Response},
    },
};

mod proxy;

pub use proxy::{ProxyClient, proxy};

/// Configuration for the siguldry client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// The Siguldry server hostname. This is used to validate the server's TLS certificate.
    pub server_hostname: String,
    /// The Siguldry bridge hostname. This is used to validate the bridge's TLS certificate.
    pub bridge_hostname: String,
    /// The port on the Siguldry bridge to connect to; the default is 44334.
    pub bridge_port: u16,
    /// The amount of time to wait before giving up on a request and retrying.
    ///
    /// This covers both sending requests and receiving responses. In other words, the client
    /// will retry the request on a new connection if it cannot write the request to the socket
    /// within `request_timeout`, *and* it will retry if it fails to read a response to that
    /// request from the socket within `request_timeout`.
    pub request_timeout: Duration,
    /// The credentials to use when authenticating to the Siguldry bridge and server. Note that
    /// the certificate must have the `clientAuth` extended key usage extension.
    pub credentials: Credentials,

    /// A list of keys to unlock for the client.
    pub keys: Vec<Key>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_hostname: "server.example.com".to_string(),
            bridge_hostname: "bridge.example.com".to_string(),
            bridge_port: 44334,
            request_timeout: Duration::from_secs(30),
            credentials: Credentials {
                private_key: PathBuf::from("siguldry.client.private_key.pem"),
                certificate: PathBuf::from("siguldry.client.certificate.pem"),
                ca_certificate: PathBuf::from("siguldry.ca_certificate.pem"),
            },
            keys: vec![],
        }
    }
}

#[cfg(feature = "cli")]
impl std::fmt::Display for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            toml::ser::to_string_pretty(&self).unwrap_or_default()
        )
    }
}

/// A key to unlock for the client
#[derive(Debug, Clone, Serialize)]
pub struct Key {
    /// The name of the key in the Siguldry server.
    pub key_name: String,
    /// The systemd credential ID containing the passphrase.
    ///
    /// The passphrase inside the file must be entirely on the first line of
    /// the file and the file should be terminated with a newline. The default
    /// settings for `systemd-ask-password` will produce an acceptable file:
    ///
    /// ```bash
    /// systemd-ask-password | systemd-creds encrypt - /etc/credstore.encrypted/siguldry.my_key_password
    /// ```
    pub passphrase_path: PathBuf,
    #[serde(skip)]
    passphrase: Password,
}

impl<'de> Deserialize<'de> for Key {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct KeyHelper {
            key_name: String,
            passphrase_path: PathBuf,
        }

        let helper = KeyHelper::deserialize(deserializer)?;

        let passphrase = std::fs::read_to_string(&helper.passphrase_path)
            .map_err(|e| {
                serde::de::Error::custom(format!(
                    "Failed to read passphrase file {}: {}",
                    helper.passphrase_path.display(),
                    e
                ))
            })?
            .lines()
            .next()
            .and_then(|pass| {
                let pass = pass.trim();
                if !pass.is_empty() { Some(pass) } else { None }
            })
            .ok_or_else(|| {
                serde::de::Error::custom(format!(
                    "Passphrase file {} does not contain a password on the first line",
                    helper.passphrase_path.display()
                ))
            })?
            .to_string()
            .into();

        Ok(Key {
            key_name: helper.key_name,
            passphrase_path: helper.passphrase_path,
            passphrase,
        })
    }
}

impl Key {
    pub fn password(&self) -> String {
        self.passphrase
            .map(|p| String::from_utf8(p.to_vec()).expect("The password deserialized to a string"))
    }
}

/// A siguldry client.
#[derive(Clone, Debug)]
pub struct Client {
    config: Arc<Config>,
    // Keys to unlock on reconnection; this is a combination of keys from the config and those
    // unlocked manually via the Client::unlock call.
    keys: Arc<Mutex<Vec<Key>>>,
    inner: Arc<Mutex<Option<InnerClient>>>,
}

impl Client {
    /// Create a new client
    pub fn new(config: Config) -> Result<Self, ClientError> {
        let keys = config.keys.clone();
        Ok(Self {
            config: Arc::new(config),
            keys: Arc::new(Mutex::new(keys)),
            inner: Arc::new(Mutex::new(None)),
        })
    }

    /// Get the current client configuration
    pub fn config(&self) -> &Config {
        &self.config
    }

    // Send a request to the server, retrying if the connection fails.
    async fn reconnecting_send(&self, request: Request) -> Result<protocol::Response, ClientError> {
        loop {
            let mut service_lock = self.inner.lock().await;
            let response = if let Some(mut service) = service_lock.take() {
                match tokio::time::timeout(
                    self.config.request_timeout,
                    service.send(request.clone()),
                )
                .await
                {
                    Ok(Ok(response)) => {
                        *service_lock = Some(service);
                        Some(response)
                    }
                    Ok(Err(ClientError::Connection(ConnectionError::Io(error)))) => {
                        tracing::info!(
                            ?error,
                            "An I/O error occurred while connecting; retrying..."
                        );
                        tokio::time::sleep(Duration::from_secs(3)).await;
                        None
                    }
                    Ok(Err(error)) => break Err(error),
                    Err(_timeout_err) => {
                        tracing::warn!(
                            "Timed out while attempting to send request; restarting connection..."
                        );
                        None
                    }
                }
            } else {
                if let Some(client) = self.new_inner_client().await? {
                    *service_lock = Some(client);
                } else {
                    tracing::warn!(
                        "Timed out while attempting to connect with the server; retrying..."
                    );
                }
                None
            };

            // Don't hold the lock while we wait for a server response
            drop(service_lock);
            if let Some(response) = response {
                match tokio::time::timeout(self.config.request_timeout, response).await {
                    Ok(Ok(response)) => break Ok(response),
                    Ok(Err(_recv_error)) => {
                        // This case is when the task owning the connection halts before it sends us the server response
                        tracing::warn!("Connection failed before server responded; retrying...");
                    }
                    Err(_elapsed) => tracing::warn!(
                        "Request timed out without a response; retrying on a new connection..."
                    ),
                };
                self.inner.lock().await.take();
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        }
    }

    /// Create a new client connection and unlock any configured keys.
    async fn new_inner_client(&self) -> Result<Option<InnerClient>, ClientError> {
        let tls_config = self.config.credentials.ssl_connector()?;
        let bridge_ssl = tls_config
            .configure()?
            .into_ssl(&self.config.bridge_hostname)?;
        let server_ssl = tls_config
            .configure()?
            .into_ssl(&self.config.server_hostname)?;
        let conn = match tokio::time::timeout(
            Duration::from_secs(15),
            Nestls::builder(bridge_ssl, Role::Client).connect(
                format!(
                    "{}:{}",
                    &self.config.bridge_hostname, self.config.bridge_port
                ),
                server_ssl,
            ),
        )
        .await
        {
            Ok(conn) => conn,
            Err(_elapsed) => {
                tracing::warn!(
                    "Timed out while attempting to connect with the server; retrying..."
                );
                return Ok(None);
            }
        };
        let conn = conn?;
        let mut client = InnerClient::new(conn);
        let keys = self.keys.lock().await.clone();
        for key in keys {
            let request = Request {
                message: protocol::json::Request::Unlock {
                    key: key.key_name.clone(),
                    password: key.password(),
                },
                binary: None,
            };
            match tokio::time::timeout(self.config.request_timeout, client.send(request)).await {
                Ok(Ok(pending_response)) => {
                    let response = match tokio::time::timeout(
                        self.config.request_timeout,
                        pending_response,
                    )
                    .await
                    {
                        Ok(Ok(response)) => response,
                        Ok(Err(_error)) => {
                            tracing::warn!(
                                "Connection failed before server responded; retrying..."
                            );
                            return Ok(None);
                        }
                        Err(_elapsed) => {
                            tracing::warn!(
                                "Request timed out without a response; retrying on a new connection..."
                            );
                            return Ok(None);
                        }
                    };

                    match response.json {
                        Response::Unlock {} => {
                            tracing::debug!(key = key.key_name, "Successfully unlocked key");
                        }
                        Response::Error { reason } => return Err(reason.into()),
                        _other => {
                            return Err(anyhow::anyhow!("Unexpected response from server").into());
                        }
                    };
                }
                Ok(Err(ClientError::Connection(ConnectionError::Io(error)))) => {
                    tracing::info!(
                        ?error,
                        "An I/O error occurred while connecting; retrying..."
                    );
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    return Ok(None);
                }
                Ok(Err(error)) => {
                    tracing::error!(
                        ?error,
                        key = key.key_name,
                        "failed to unlock configured key"
                    );
                    return Err(error);
                }
                Err(_timeout_err) => {
                    tracing::warn!(
                        "Timed out while attempting to send request; restarting connection..."
                    );
                    return Ok(None);
                }
            }
        }

        Ok(Some(client))
    }

    /// Attempt to authenticate against the server.
    ///
    /// Returns the username you successfully authenticated as.
    pub async fn who_am_i(&self) -> Result<String, ClientError> {
        let request = protocol::json::Request::WhoAmI {};
        let request = Request {
            message: request,
            binary: None,
        };
        let response = self.reconnecting_send(request).await?;
        match response.json {
            Response::WhoAmI { user } => Ok(user),
            Response::Error { reason } => Err(reason.into()),
            _other => Err(anyhow::anyhow!("Unexpected response from server").into()),
        }
    }

    pub async fn list_users(&self) -> Result<Vec<String>, ClientError> {
        let request = Request {
            message: protocol::json::Request::ListUsers {},
            binary: None,
        };

        let response = self.reconnecting_send(request).await?;
        match response.json {
            Response::ListUsers { users } => Ok(users),
            Response::Error { reason } => Err(reason.into()),
            _other => Err(anyhow::anyhow!("Unexpected response from server").into()),
        }
    }

    pub async fn list_keys(&self) -> Result<Vec<protocol::Key>, ClientError> {
        let request = Request {
            message: protocol::json::Request::ListKeys {},
            binary: None,
        };

        let response = self.reconnecting_send(request).await?;
        match response.json {
            Response::ListKeys { keys } => Ok(keys),
            Response::Error { reason } => Err(reason.into()),
            _other => Err(anyhow::anyhow!("Unexpected response from server").into()),
        }
    }

    // TODO return opaque handle to provide to gpg_sign etc
    pub async fn unlock(&self, key: String, password: String) -> Result<(), ClientError> {
        // This key has already been unlocked
        let mut keys = self.keys.lock().await;
        if keys.iter().any(|k| k.key_name == key) {
            return Ok(());
        }

        // Ensure the key is unlocked again on reconnection.
        // If this is the first call issued it'll result in the call to unlock the key twice
        // since starting the connection pull the key list to unlock from this vec,
        // but that's not a huge deal.
        keys.push(Key {
            key_name: key.clone(),
            passphrase_path: PathBuf::new(),
            passphrase: password.clone().into(),
        });
        drop(keys);

        let request = Request {
            message: protocol::json::Request::Unlock { key, password },
            binary: None,
        };

        let response = self.reconnecting_send(request).await?;
        match response.json {
            Response::Unlock {} => Ok(()),
            Response::Error { reason } => Err(reason.into()),
            _other => Err(anyhow::anyhow!("Unexpected response from server").into()),
        }
    }

    pub async fn get_key(&self, key: String) -> Result<crate::protocol::Key, ClientError> {
        let request = Request {
            message: protocol::json::Request::GetKey { key },
            binary: None,
        };

        let response = self.reconnecting_send(request).await?;
        match response.json {
            Response::GetKey { key } => Ok(key),
            Response::Error { reason } => Err(reason.into()),
            _other => Err(anyhow::anyhow!("Unexpected response from server").into()),
        }
    }

    pub async fn gpg_sign(
        &self,
        key: String,
        signature_type: GpgSignatureType,
        data: Bytes,
    ) -> Result<Bytes, ClientError> {
        let request = Request {
            message: protocol::json::Request::GpgSign {
                key,
                signature_type,
            },
            binary: Some(data),
        };

        let response = self.reconnecting_send(request).await?;
        match response.json {
            Response::GpgSign {} => response.binary.ok_or_else(|| {
                anyhow::anyhow!("Server response didn't include a signature").into()
            }),
            Response::Error { reason } => Err(reason.into()),
            _other => Err(anyhow::anyhow!("Unexpected response from server").into()),
        }
    }

    pub async fn sign(
        &self,
        key: String,
        digest: DigestAlgorithm,
        data: Bytes,
    ) -> Result<Signature, ClientError> {
        let request = Request {
            message: protocol::json::Request::Sign { key, digest },
            binary: Some(data),
        };

        let response = self.reconnecting_send(request).await?;
        match response.json {
            Response::Sign { signature } => Ok(signature),
            Response::Error { reason } => Err(reason.into()),
            _other => Err(anyhow::anyhow!("Unexpected response from server").into()),
        }
    }

    /// Sign prehashed content.
    pub async fn sign_prehashed(
        &self,
        key: String,
        digests: Vec<(DigestAlgorithm, String)>,
    ) -> Result<Vec<Signature>, ClientError> {
        let request = Request {
            message: protocol::json::Request::SignPrehashed { key, digests },
            binary: None,
        };

        let response = self.reconnecting_send(request).await?;
        match response.json {
            Response::SignPrehashed { signatures } => Ok(signatures),
            Response::Error { reason } => Err(reason.into()),
            _other => Err(anyhow::anyhow!("Unexpected response from server").into()),
        }
    }

    pub async fn shutdown(self) {
        if let Some(client) = self.inner.lock().await.take() {
            client.shutdown().await;
        }
    }
}

// This structure maps to a single connection to the server.
#[derive(Debug)]
struct InnerClient {
    request_tx: mpsc::Sender<(Bytes, oneshot::Sender<protocol::Response>)>,
    session_id: Uuid,
    request_id: u64,
    handler_task: tokio::task::JoinHandle<Result<(), anyhow::Error>>,
}

impl InnerClient {
    fn new(connection: Nestls) -> Self {
        let (request_tx, request_rx) = mpsc::channel(128);
        let session_id = connection.session_id();
        let handler_task = tokio::spawn(Self::request_handler(connection, request_rx));
        Self {
            request_tx,
            session_id,
            request_id: 0,
            handler_task,
        }
    }

    // A task that handles the I/O for requests and responses on the socket.
    #[instrument(level = "debug", skip_all, err)]
    async fn request_handler(
        mut connection: Nestls,
        mut request_rx: mpsc::Receiver<(Bytes, oneshot::Sender<protocol::Response>)>,
    ) -> anyhow::Result<()> {
        // Buffers incoming reads before they're parsed out into frames
        let mut incoming_buffer = BytesMut::new();

        // The bytes backing the incoming frame
        let mut incoming_frame_bytes;
        let mut incoming_frame: Option<&Frame> = None;

        // Reference to the buffer containing the complete JSON portion of the current response.
        // This is only set to a value if the response includes a binary payload and it's not yet
        // arrived.
        let mut incoming_json: Option<Bytes> = None;

        // Tracks the responses we're expecting to receive from the server and where to send
        // them when they arrive.
        let mut pending_responses = VecDeque::new();

        // Indicates when we attempted to send the close signal to the server; used to time out
        // pending responses.
        let mut sent_close_frame = false;

        // Unfortunately, currently the stream provided by OpenSSL doesn't allow splitting into
        // read/write halves, so the implementation to read/write concurrently is trickier.
        //
        // Each loop, we either send a request or read in some (or all) of a response. Incoming
        // responses may span multiple loops as we need to use the `read_buf` API to ensure cancel
        // safety in the select! macro.
        //
        // Sending requests is handled entirely within the select! macro. Everything after that is
        // handling responses.
        loop {
            // Enforce a limit on the incoming data; we'll read at most 1MB at a time and
            // exit if we hit a total limit of 64MB. This is hugely more than any response
            // should be anyway, so it probably doesn't need to be configurable.
            if incoming_buffer.len() > 64 * 1024 * 1024 {
                tracing::error!(
                    buffer_size = incoming_buffer.len(),
                    "Huge response buffer with no response parsed out! Shutting down connection..."
                );
                break;
            }
            let mut limited_buffer = incoming_buffer.limit(1024 * 1024);

            tokio::select! {
                request = request_rx.recv() => {
                    if let Some((request, respond_to)) = request {
                        tracing::trace!("Request received");
                        connection.write_all(request.as_bytes()).await?;
                        pending_responses.push_back(respond_to);
                        tracing::debug!("Request sent to server");
                        incoming_buffer = limited_buffer.into_inner();
                        continue;
                    } else {
                        // The client holding the sending half of the channel has been dropped or explicitly closed.
                        // Don't exit until there's no more pending responses, unless reading from the socket stalls.
                        // The reconnecting client will retry those requests on a new connection.
                        if sent_close_frame && !pending_responses.is_empty() {
                            let bytes_read = tokio::time::timeout(Duration::from_secs(30), connection.read_buf(&mut limited_buffer)).await??;
                            if bytes_read == 0 {
                                tracing::warn!(pending_responses=pending_responses.len(), "Reading from the socket got 0 bytes; shutting down");
                                break;
                            }
                        } else if !sent_close_frame {
                            tracing::debug!("Sending empty frame to signal the end of the connection.");
                            sent_close_frame = true;
                            // Best effort goodbye; it may be the outgoing socket blocks for eternity and this is just to be polite.
                            _ = tokio::time::timeout(Duration::from_secs(5), connection.write_all(Frame::empty().as_bytes())).await;
                        } else {
                            // We've sent the closing frame and there's no pending responses.
                            break;
                        }
                    }
                }
                bytes_read = connection.read_buf(&mut limited_buffer) => {
                    let bytes_read = bytes_read?;
                    if bytes_read == 0 {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                    tracing::trace!(bytes_read, "Handling incoming response data");
                }
            }
            incoming_buffer = limited_buffer.into_inner();

            // First determine where we are in the frame processing.
            let current_frame = match incoming_frame {
                // We're not currently processing a frame, but we didn't get enough bytes to
                // figure out the next frame.
                None if std::mem::size_of::<Frame>() > incoming_buffer.len() => {
                    tracing::trace!("Waiting for more data to complete the response frame");
                    continue;
                }
                // We're at the start of a new frame and we have enough bytes to construct the
                // [`Frame`].
                None => {
                    incoming_frame_bytes = incoming_buffer
                        .split_to(std::mem::size_of::<Frame>())
                        .freeze();
                    let frame = Frame::try_ref_from_bytes(&incoming_frame_bytes)
                        .map_err(|e| anyhow::anyhow!(format!("{e:?}")))?;
                    incoming_frame = Some(frame);
                    tracing::debug!(
                        ?frame,
                        pending_responses = pending_responses.len(),
                        "Client received response frame from server"
                    );
                    frame
                }
                // We're part way through reading a frame
                Some(frame) => frame,
            };

            let json_size: usize = current_frame.json_size.get().try_into()?;
            let binary_size: usize = current_frame.binary_size.get().try_into()?;

            // Next, determine if we're done with the JSON section of the frame.
            match &incoming_json {
                None if json_size > incoming_buffer.len() => {
                    tracing::trace!("Waiting for more data to complete the JSON response");
                }
                // We've finished receiving the data for the JSON section, and it's possible
                // we've got everything we need for the response at this point.
                None => {
                    let json = incoming_buffer.split_to(json_size).freeze();
                    if binary_size > incoming_buffer.len() {
                        tracing::debug!("Received JSON response; awaiting binary payload");
                        incoming_json = Some(json);
                    } else {
                        let respond_to = pending_responses
                            .pop_front()
                            .ok_or_else(|| anyhow::anyhow!("Unexpected response received!"))?;
                        let json_response: OuterResponse = serde_json::from_slice(&json)?;
                        tracing::debug!(
                            request_id = json_response.request_id,
                            "Full server response received"
                        );
                        let mut response: protocol::Response = json_response.response.into();
                        if binary_size > 0 {
                            response.binary = Some(incoming_buffer.split_to(binary_size).freeze());
                        }
                        let _ = respond_to.send(response);
                        incoming_frame = None;
                    }
                }
                // We're done with the JSON, but we're waiting for some more bytes to complete the
                // binary section of the response.
                Some(_) if binary_size > incoming_buffer.len() => {
                    tracing::trace!("Waiting for more data to complete the binary response");
                }
                // We're definitely done at this point.
                Some(json) => {
                    let respond_to = pending_responses
                        .pop_front()
                        .ok_or_else(|| anyhow::anyhow!("Unexpected response received!"))?;
                    let json_response: OuterResponse = serde_json::from_slice(json)?;
                    tracing::debug!(
                        request_id = json_response.request_id,
                        "Full server response received"
                    );
                    let mut response: protocol::Response = json_response.response.into();
                    if binary_size > 0 {
                        response.binary = Some(incoming_buffer.split_to(binary_size).freeze());
                    }
                    let _ = respond_to.send(response);
                    incoming_json = None;
                    incoming_frame = None;
                }
            };
        }

        connection.shutdown().await?;
        Ok(())
    }

    #[instrument(skip_all, fields(session_id = self.session_id.to_string()))]
    async fn send(
        &mut self,
        request: Request,
    ) -> Result<Receiver<protocol::Response>, ClientError> {
        let json = OuterRequest {
            session_id: self.session_id,
            request_id: self.request_id,
            request: request.message,
        };
        self.request_id += 1;
        let json = serde_json::to_string(&json)?;
        let json = Bytes::from_owner(json);
        let binary = request.binary.unwrap_or_default();
        let json_size: u64 = json
            .as_bytes()
            .len()
            .try_into()
            .context("JSON payload larger than a u64")?;
        let binary_size: u64 = binary
            .as_bytes()
            .len()
            .try_into()
            .context("Binary payload larger than a u64")?;
        let request_frame = protocol::Frame::new(json_size, binary_size);
        let mut payload =
            BytesMut::with_capacity(request_frame.as_bytes().len() + json.len() + binary.len());
        payload.put(request_frame.as_bytes());
        payload.put(json);
        payload.put(binary);
        let payload = payload.freeze();

        let (response_tx, response_rx) = oneshot::channel();

        self.request_tx
            .send((payload, response_tx))
            .await
            // If the [`Self::request_handler`] shuts down (due to an I/O error on the connection)
            // we will fail to send this request.
            .map_err(|_send_error| {
                ClientError::Connection(ConnectionError::Io(std::io::Error::other(
                    anyhow::anyhow!("The connection is closed"),
                )))
            })?;
        Ok(response_rx)
    }

    #[instrument(skip_all, fields(session_id = self.session_id.to_string()))]
    async fn shutdown(self) {
        let handle = self.handler_task;
        drop(self.request_tx);
        match handle.await {
            Ok(Ok(())) => (),
            Ok(Err(error)) => tracing::warn!(?error, "Request task did not exit cleanly"),
            Err(error) => tracing::warn!(?error, "Failed to join tokio task"),
        };
    }
}

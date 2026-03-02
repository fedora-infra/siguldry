// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! The Siguldry client.

use std::path::PathBuf;
use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use tokio::sync::Mutex;

use crate::protocol::json::Signature;
use crate::protocol::{DigestAlgorithm, GpgSignatureType};
use crate::{
    error::{ClientError, ConnectionError},
    nestls::Nestls,
    protocol::{self, Request, Role, json::Response},
};

mod config;
mod inner;
mod proxy;

pub use config::{Config, Key};
pub use proxy::{ProxyClient, proxy};

/// A siguldry client.
#[derive(Clone, Debug)]
pub struct Client {
    config: Arc<Config>,
    // Keys to unlock on reconnection; this is a combination of keys from the config and those
    // unlocked manually via the Client::unlock call.
    keys: Arc<Mutex<Vec<Key>>>,
    inner: Arc<Mutex<Option<inner::Client>>>,
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
    async fn new_inner_client(&self) -> Result<Option<inner::Client>, ClientError> {
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
        let mut client = inner::Client::new(conn);
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

    /// Returns true if the key is unlocked.
    ///
    /// Note that if another thread has requested that the key be unlocked, but it has not yet
    /// succeeded, this will return false.
    pub async fn is_unlocked(&self, key: String) -> bool {
        self.keys.lock().await.iter().any(|k| k.key_name == key)
    }

    pub async fn unlock(&self, key: String, password: String) -> Result<(), ClientError> {
        // This key has already been unlocked
        if self.keys.lock().await.iter().any(|k| k.key_name == key) {
            return Ok(());
        }

        let request = Request {
            message: protocol::json::Request::Unlock {
                key: key.clone(),
                password: password.clone(),
            },
            binary: None,
        };

        let response = self.reconnecting_send(request).await?;
        match response.json {
            Response::Unlock {} => {
                // Ensure the key is unlocked again on reconnection.
                // We dropped the lock since reconnecting_send might need to access the key list.
                // We'll assume that in the race to reacquire the lock the password hasn't changed
                // so it doesn't matter if someone else added the key to the list.
                let mut keys = self.keys.lock().await;
                if !keys.iter().any(|k| k.key_name == key) {
                    keys.push(Key {
                        key_name: key,
                        passphrase_path: PathBuf::new(),
                        passphrase: password.into(),
                    });
                }

                Ok(())
            }
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

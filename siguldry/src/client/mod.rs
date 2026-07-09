// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! The Siguldry client.

use std::path::PathBuf;
use std::{sync::Arc, time::Duration};

use tokio::sync::Mutex;
use tokio::time::Instant;

use crate::error::ConnectionError;
use crate::protocol::DigestAlgorithm;
use crate::protocol::Signature;
use crate::{
    error::ClientError,
    nestls::Nestls,
    protocol::{self, Request, Response, Role},
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
    activity_tx: tokio::sync::watch::Sender<Instant>,
    // Keys to unlock on reconnection; this is a combination of keys from the config and those
    // unlocked manually via the Client::unlock call.
    keys: Arc<Mutex<Vec<Key>>>,
    inner: Arc<Mutex<Option<inner::Client>>>,
}

impl Client {
    /// Create a new client
    pub fn new(config: Config) -> Result<Self, ClientError> {
        let keys = config.keys.clone();
        let idle_timeout = Duration::from_secs(config.idle_timeout.get());
        let inner: Option<inner::Client> = None;
        let inner = Arc::new(Mutex::new(inner));

        let (activity_tx, mut activity_rx) = tokio::sync::watch::channel(Instant::now());
        let watchdog_inner = Arc::clone(&inner);
        tokio::spawn(async move {
            let mut last_activity = *activity_rx.borrow();
            let inner = watchdog_inner;

            loop {
                // Shutdown the active connection, if there is one, on the timeout. Exit when
                // the client holding the sender side of the activity channel is dropped.
                match tokio::time::timeout(idle_timeout, activity_rx.changed()).await {
                    Ok(Ok(_)) => {
                        last_activity = *activity_rx.borrow_and_update();
                        tracing::trace!("Client reported activity to the watchdog");
                    }
                    Ok(Err(_recv_error)) => {
                        tracing::debug!("Shutting down client watchdog");
                        break;
                    }
                    Err(_elapsed) => {
                        let mut lock_guard = inner.lock().await;
                        if let Ok(false) = activity_rx.has_changed()
                            && let Some(inner_client) = lock_guard.take()
                        {
                            drop(lock_guard);
                            tracing::info!(
                                "Shutting down idle connection to the server to conserve resources (idle {} seconds)",
                                last_activity.elapsed().as_secs()
                            );
                            let _ = tokio::time::timeout(
                                Duration::from_secs(5),
                                inner_client.shutdown(),
                            )
                            .await;
                        }
                    }
                }
            }
        });
        Ok(Self {
            config: Arc::new(config),
            keys: Arc::new(Mutex::new(keys)),
            activity_tx,
            inner,
        })
    }

    /// Get the current client configuration
    pub fn config(&self) -> &Config {
        &self.config
    }

    // Send a request to the server, retrying if the connection fails.
    async fn reconnecting_send(&self, request: Request) -> Result<protocol::Response, ClientError> {
        let request_timeout = Duration::from_secs(self.config.request_timeout.get());
        loop {
            let mut service_lock = self.inner.lock().await;
            self.activity_tx.send_replace(Instant::now());
            let response = if let Some(mut service) = service_lock.take() {
                match tokio::time::timeout(request_timeout, service.send(request.clone())).await {
                    Ok(Ok(response)) => {
                        *service_lock = Some(service);
                        Some(response)
                    }
                    Ok(Err(error)) => {
                        tracing::info!(
                            ?error,
                            "An error occurred while sending request; retrying..."
                        );
                        tokio::time::sleep(Duration::from_secs(3)).await;
                        None
                    }
                    Err(_timeout_err) => {
                        tracing::warn!(
                            "Timed out while attempting to send request; restarting connection..."
                        );
                        None
                    }
                }
            } else {
                match self.new_inner_client().await {
                    Ok(Some(client)) => {
                        *service_lock = Some(client);
                    }
                    Ok(None) => {
                        tracing::warn!(
                            "Timed out while attempting to connect with the server; retrying..."
                        );
                    }
                    Err(ClientError::Connection(ConnectionError::Protocol(error))) => {
                        tracing::error!(?error, "An unrecoverable protocol error occurred");
                        return Err(ConnectionError::Protocol(error).into());
                    }
                    Err(ClientError::Connection(ConnectionError::Ssl(error))) => {
                        match error
                            .ssl_error()
                            .map(|e| e.errors())
                            .and_then(|e| e.first())
                            .map(|e| (e.reason_code(), e.reason()))
                        {
                            Some((134, Some("certificate verify failed"))) => {
                                tracing::error!(
                                    "certificate verify failed; check the CA, bridge, and server certificates"
                                );
                                return Err(ClientError::CertificateVerifyFailed);
                            }
                            Some((1048, Some("tlsv1 alert unknown ca"))) => {
                                tracing::error!(
                                    "The client certificate is not signed by a CA the bridge accepts"
                                );
                                return Err(ClientError::InvalidClientCertificate);
                            }
                            Some((reason_code, reason)) => {
                                tracing::warn!(
                                    reason_code,
                                    ?reason,
                                    "A TLS error occurred; retrying connection..."
                                );
                            }
                            None => tracing::warn!(
                                ?error,
                                "A TLS error occurred without details, retrying..."
                            ),
                        }

                        // If it didn't match a fatal TLS error above, just try again.
                        tokio::time::sleep(Duration::from_secs(3)).await;
                    }
                    Err(error) => {
                        tracing::warn!(?error, "Connection to server failed; retrying...");
                        tokio::time::sleep(Duration::from_secs(3)).await;
                    }
                }
                None
            };

            // Don't hold the lock while we wait for a server response
            drop(service_lock);
            if let Some(response) = response {
                match tokio::time::timeout(request_timeout, response).await {
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
                    self.config.bridge_hostname, self.config.bridge_port
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
        let request_timeout = Duration::from_secs(self.config.request_timeout.get());
        let keys = self.keys.lock().await.clone();
        for key in keys {
            let request = protocol::Request::Unlock {
                key: key.key_name.clone(),
                password: key.password(),
            };
            match tokio::time::timeout(request_timeout, client.send(request)).await {
                Ok(Ok(pending_response)) => {
                    let response = match tokio::time::timeout(request_timeout, pending_response)
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

                    match response {
                        Response::Unlock {} => {
                            tracing::debug!(key = key.key_name, "Successfully unlocked key");
                        }
                        Response::Error { reason } => return Err(reason.into()),
                        _other => {
                            return Err(anyhow::anyhow!("Unexpected response from server").into());
                        }
                    };
                }
                Ok(Err(error)) => {
                    tracing::info!(
                        ?error,
                        "An error occurred while sending request; retrying..."
                    );
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    return Ok(None);
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
        let request = protocol::Request::WhoAmI {};
        let response = self.reconnecting_send(request).await?;
        match response {
            Response::WhoAmI { user } => Ok(user),
            Response::Error { reason } => Err(reason.into()),
            _other => Err(anyhow::anyhow!("Unexpected response from server").into()),
        }
    }

    /// List keys that are accessible to the authenticated user.
    pub async fn list_keys(&self) -> Result<Vec<protocol::Key>, ClientError> {
        let request = protocol::Request::ListKeys {};

        let response = self.reconnecting_send(request).await?;
        match response {
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

        let request = protocol::Request::Unlock {
            key: key.clone(),
            password: password.clone(),
        };

        let response = self.reconnecting_send(request).await?;
        match response {
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
        let request = protocol::Request::GetKey { key };

        let response = self.reconnecting_send(request).await?;
        match response {
            Response::GetKey { key } => Ok(key),
            Response::Error { reason } => Err(reason.into()),
            _other => Err(anyhow::anyhow!("Unexpected response from server").into()),
        }
    }

    pub async fn sign(
        &self,
        key: String,
        digest_algorithm: DigestAlgorithm,
        digest: String,
    ) -> Result<Signature, ClientError> {
        let request = protocol::Request::Sign {
            key,
            digest_algorithm,
            digest,
        };

        let response = self.reconnecting_send(request).await?;
        match response {
            Response::Sign { signature } => Ok(signature),
            Response::Error { reason } => Err(reason.into()),
            _other => Err(anyhow::anyhow!("Unexpected response from server").into()),
        }
    }

    /// Sign multiple digests in a single request
    pub async fn sign_all(
        &self,
        key: String,
        digests: Vec<(DigestAlgorithm, String)>,
    ) -> Result<Vec<Signature>, ClientError> {
        let request = protocol::Request::SignAll { key, digests };

        let response = self.reconnecting_send(request).await?;
        match response {
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

// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! This is a helper for the PKCS #11 module to avoid issues with openssl.
//!
//! The client CLI uses these utilities to offer a way to proxy requests
//! via IPC; the typical case is over stdio in combination with a systemd
//! socket.
//!
//! At this time the format of communication between the proxy client and
//! server is NOT stable and no tooling should interact with the
//! service provided by [`proxy`] except via [`ProxyClient`].

use std::path::PathBuf;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use tracing::instrument;

use crate::{
    client::Client,
    ipc_common::IpcClient,
    protocol::{self, DigestAlgorithm},
};

pub async fn proxy<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    client: Client,
    halt_token: CancellationToken,
    requests: R,
    mut responses: W,
) -> anyhow::Result<()> {
    tracing::info!("Handling requests");
    let mut requests = BufReader::new(requests).lines();

    loop {
        let line = tokio::select! {
            _ = halt_token.cancelled() => {
                tracing::info!("proxy halted; shutting down");
                return Ok(());
            }
            line = requests.next_line() => {
                if let Some(line) = line? { line } else {
                    tracing::debug!("EOF received for proxy");
                    return Ok(());
                }
            }
        };

        let request: protocol::json::Request = serde_json::from_str(&line)?;
        let response = match request {
            protocol::json::Request::WhoAmI {} => {
                let user = client.who_am_i().await?;
                protocol::json::Response::WhoAmI { user }
            }
            protocol::json::Request::ListUsers {} => {
                let users = client.list_users().await?;
                protocol::json::Response::ListUsers { users }
            }
            protocol::json::Request::ListKeys {} => {
                let keys = client.list_keys().await?;
                protocol::json::Response::ListKeys { keys }
            }
            protocol::json::Request::Unlock { key, password } => {
                client.unlock(key, password).await?;
                protocol::json::Response::Unlock {}
            }
            protocol::json::Request::SignPrehashed { key, digests } => {
                let signatures = client.sign_prehashed(key, digests).await?;
                protocol::json::Response::SignPrehashed { signatures }
            }
            protocol::json::Request::GetKey { key } => {
                let key = client.get_key(key).await?;
                protocol::json::Response::GetKey { key }
            }
            _other => protocol::json::Response::Unsupported,
        };
        let mut response = serde_json::to_string(&response)?;
        response.push('\n');
        responses.write_all(response.as_bytes()).await?;
    }
}

/// A client that proxies requests to the Siguldry server over a local Unix socket.
///
/// In cases where you wish to separate access to certificates used to authenticate
/// with Siguldry from the client making the signing requests, or for when you need
/// to interact with Siguldry in the context of an active OpenSSL call (for example,
/// if you are implementing a PKCS #11 module used by OpenSSL via its providers API),
/// this client provides a limited set interfaces to perform signing operations.
///
/// It is intended to be used exclusively with a socket being handled by the [`proxy`]
/// function, typically via the `siguldry-client` CLI.
pub struct ProxyClient {
    rt_thread: std::thread::JoinHandle<anyhow::Result<()>>,
    request_tx: UnboundedSender<ChannelRequest>,
}

type ChannelRequest = (
    protocol::json::Request,
    oneshot::Sender<anyhow::Result<serde_json::Value>>,
);

impl ProxyClient {
    #[instrument]
    pub fn new(socket_path: PathBuf) -> anyhow::Result<Self> {
        let (request_tx, mut request_rx) = tokio::sync::mpsc::unbounded_channel::<ChannelRequest>();
        let rt_thread = std::thread::Builder::new()
            .name("proxy-client-rt".to_string())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                runtime.block_on(async move {
                    let mut client = IpcClient::new(&socket_path).await?;
                    tracing::info!(?socket_path, "Proxy client connected");
                    while let Some((request, response_tx)) = request_rx.recv().await {
                        let response = client.request(&request, None).await;
                        let _ = response_tx.send(response);
                    }

                    tracing::info!("Proxy client runtime thread shutting down");
                    Ok::<_, anyhow::Error>(())
                })?;

                Ok::<_, anyhow::Error>(())
            })?;
        Ok(Self {
            rt_thread,
            request_tx,
        })
    }

    pub fn shutdown(self) -> anyhow::Result<()> {
        drop(self.request_tx);
        self.rt_thread
            .join()
            .map_err(|error| anyhow::anyhow!("Runtime thread panicked: {error:?}"))?
    }

    #[instrument(skip_all)]
    pub fn list_keys(&mut self) -> anyhow::Result<Vec<protocol::Key>> {
        let request = protocol::json::Request::ListKeys {};
        let (response_tx, response_rx) = oneshot::channel();
        self.request_tx.send((request, response_tx))?;
        let response = response_rx.blocking_recv()??;
        let response: protocol::json::Response = serde_json::from_value(response)?;

        match response {
            protocol::json::Response::ListKeys { keys } => Ok(keys),
            unexpected => Err(anyhow::anyhow!("Unexpected response: {:?}", unexpected)),
        }
    }

    #[instrument(skip_all)]
    pub fn unlock(&mut self, key: String, password: String) -> anyhow::Result<()> {
        let request = protocol::json::Request::Unlock { key, password };
        let (response_tx, response_rx) = oneshot::channel();
        self.request_tx.send((request, response_tx))?;
        let response = response_rx.blocking_recv()??;
        let response: protocol::json::Response = serde_json::from_value(response)?;

        match response {
            protocol::json::Response::Unlock {} => Ok(()),
            unexpected => Err(anyhow::anyhow!("Unexpected response: {:?}", unexpected)),
        }
    }

    #[instrument(skip_all)]
    pub fn sign_prehashed(
        &mut self,
        key: String,
        digests: Vec<(DigestAlgorithm, String)>,
    ) -> anyhow::Result<Vec<protocol::json::Signature>> {
        let request = protocol::json::Request::SignPrehashed { key, digests };
        let (response_tx, response_rx) = oneshot::channel();
        self.request_tx.send((request, response_tx))?;
        let response = response_rx.blocking_recv()??;
        let response: protocol::json::Response = serde_json::from_value(response)?;

        match response {
            protocol::json::Response::SignPrehashed { signatures } => Ok(signatures),
            unexpected => Err(anyhow::anyhow!("Unexpected response: {:?}", unexpected)),
        }
    }
}

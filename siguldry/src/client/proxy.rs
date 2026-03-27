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

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use tracing::instrument;

use crate::protocol::{Key, Signature};
use crate::{
    client::Client,
    ipc_common::IpcClient,
    protocol::{self, DigestAlgorithm},
};

const IPC_VERSION: u32 = 1;

/// Every connection starts with the client sending this header to the server,
/// indicating what version of the API it plans to speak. The server then responds
/// with its current IPC version. Old handlers should not be removed from the server.
///
/// This will allow for graceful migrations in scenarios where the client proxy server version
/// doesn't align with the client version (e.g. the PKCS #11 module inside a build environment
/// speaking to a socket from the builder host)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct IpcHeader {
    version: u32,
}

impl IpcHeader {
    fn new() -> Self {
        Self {
            version: IPC_VERSION,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Request {
    ListKeys {},
    Unlock {
        key: String,
        password: String,
    },
    IsUnlocked {
        key: String,
    },
    Sign {
        key: String,
        algorithm: DigestAlgorithm,
        digest: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Response {
    ListKeys {
        keys: Vec<Key>,
    },
    Unlock {},
    IsUnlocked {
        unlocked: bool,
    },
    Sign {
        signature: Signature,
    },
    /// Indicates the server doesn't implement the requested function.
    ///
    /// The client can expect this if the server half is running an older
    /// version and a command has been added. Be mindful to provide a graceful
    /// upgrade path for such scenarios.
    Unsupported {},
}

pub async fn proxy<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    client: Client,
    halt_token: CancellationToken,
    requests: R,
    mut responses: W,
) -> anyhow::Result<()> {
    tracing::info!("Handling requests");
    let mut requests = BufReader::new(requests).lines();

    let mut ipc_header: Option<IpcHeader> = None;
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

        // Currently unused, but if we need to break the API this is helpful to match against
        let _client_version = if let Some(ipc_header) = ipc_header.as_ref() {
            ipc_header.version
        } else {
            let header: IpcHeader = serde_json::from_str(&line)?;
            let version = header.version;
            if version > IPC_VERSION {
                tracing::error!(
                    client_version = version,
                    server_version = IPC_VERSION,
                    "The IPC client is requesting an unknown protocol version"
                );
                return Err(anyhow::anyhow!(
                    "Unknown protocol version {version} requested by client"
                ));
            }
            ipc_header = Some(header);
            let mut response = serde_json::to_string(&IpcHeader::new())?;
            response.push('\n');
            responses.write_all(response.as_bytes()).await?;
            continue;
        };

        let response = match serde_json::from_str::<Request>(&line) {
            Ok(request) => match request {
                Request::ListKeys {} => {
                    let keys = client.list_keys().await?;
                    Response::ListKeys { keys }
                }
                Request::Unlock { key, password } => {
                    client.unlock(key, password).await?;
                    Response::Unlock {}
                }
                Request::IsUnlocked { key } => Response::IsUnlocked {
                    unlocked: client.is_unlocked(key).await,
                },
                Request::Sign {
                    key,
                    algorithm,
                    digest,
                } => {
                    let signature = client.sign(key, algorithm, digest).await?;
                    Response::Sign { signature }
                }
            },
            Err(error) => {
                match error.classify() {
                    serde_json::error::Category::Io => {
                        tracing::error!("Failed to read bytes from input stream");
                        return Err(anyhow::anyhow!("Failed to read bytes from input stream"));
                    }
                    serde_json::error::Category::Syntax => {
                        tracing::error!(column = error.column(), "Client sent invalid JSON");
                        return Err(anyhow::anyhow!("Client sent invalid JSON"));
                    }
                    serde_json::error::Category::Eof => {
                        tracing::error!("Unexpected end-of-line when deserializing JSON!");
                        return Err(anyhow::anyhow!(
                            "Unexpected end-of-line when deserializing JSON!"
                        ));
                    }
                    serde_json::error::Category::Data => tracing::warn!(
                        "Client sent a request of a type the proxy is not aware of (version mismatch?)"
                    ),
                }
                tracing::warn!("Client sent an unknown request type or invalid JSON");
                Response::Unsupported {}
            }
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

type ChannelRequest = (Request, oneshot::Sender<anyhow::Result<Response>>);

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
                    // In the future when an version bump occurs we can use this to decide what to send
                    // and what to expect in response.
                    let server_ipc_version = client.request(&IpcHeader::new()).await?;
                    tracing::debug!(?server_ipc_version, "Server IPC header received");
                    while let Some((request, response_tx)) = request_rx.recv().await {
                        let response = client.request(&request).await.and_then(|v| {
                            serde_json::from_value(v)
                                .map_err(|_| anyhow::anyhow!("Can't deserialize proxy response"))
                        });
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
        let request = Request::ListKeys {};
        let (response_tx, response_rx) = oneshot::channel();
        self.request_tx.send((request, response_tx))?;
        let response = response_rx.blocking_recv()??;

        match response {
            Response::ListKeys { keys } => Ok(keys),
            unexpected => Err(anyhow::anyhow!("Unexpected response: {:?}", unexpected)),
        }
    }

    #[instrument(skip_all)]
    pub fn unlock(&mut self, key: String, password: String) -> anyhow::Result<()> {
        let request = Request::Unlock { key, password };
        let (response_tx, response_rx) = oneshot::channel();
        self.request_tx.send((request, response_tx))?;
        let response = response_rx.blocking_recv()??;

        match response {
            Response::Unlock {} => Ok(()),
            unexpected => Err(anyhow::anyhow!("Unexpected response: {:?}", unexpected)),
        }
    }

    #[instrument(skip_all)]
    pub fn is_unlocked(&mut self, key: String) -> anyhow::Result<bool> {
        let request = Request::IsUnlocked { key };
        let (response_tx, response_rx) = oneshot::channel();
        self.request_tx.send((request, response_tx))?;
        let response = response_rx.blocking_recv()??;

        match response {
            Response::IsUnlocked { unlocked } => Ok(unlocked),
            unexpected => Err(anyhow::anyhow!("Unexpected response: {:?}", unexpected)),
        }
    }

    #[instrument(skip_all)]
    pub fn sign(
        &mut self,
        key: String,
        algorithm: DigestAlgorithm,
        digest: String,
    ) -> anyhow::Result<Signature> {
        let request = Request::Sign {
            key,
            algorithm,
            digest,
        };
        let (response_tx, response_rx) = oneshot::channel();
        self.request_tx.send((request, response_tx))?;
        let response = response_rx.blocking_recv()??;

        match response {
            Response::Sign { signature } => Ok(signature),
            unexpected => Err(anyhow::anyhow!("Unexpected response: {:?}", unexpected)),
        }
    }
}

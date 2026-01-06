// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! The Siguldry bridge.

use std::{fmt::Debug, net::SocketAddr, pin::Pin, str::FromStr};

use anyhow::anyhow;
use openssl::ssl::Ssl;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use tokio_openssl::SslStream;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{Instrument, instrument};
use uuid::Uuid;
use zerocopy::{IntoBytes, TryFromBytes};

use crate::{
    config::Credentials,
    protocol::{self, BridgeStatus, ProtocolAck, Role, peer_common_name},
};

/// Configuration for the siguldry bridge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// The socket address to listen on for incoming connections from Siguldry servers.
    ///
    /// The default is to listen on all interfaces on port 44333.
    pub server_listening_address: SocketAddr,
    /// The socket address to listen on for incoming connections from Siguldry clients.
    ///
    /// The default is to listen on all interfaces on port 44334.
    pub client_listening_address: SocketAddr,
    /// The TLS credentials for the server and client listeners.
    pub credentials: Credentials,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_listening_address: SocketAddr::from_str("[::]:44333")
                .expect("the default should be valid"),
            client_listening_address: SocketAddr::from_str("[::]:44334")
                .expect("the default should be valid"),
            credentials: Credentials {
                private_key: "sigul.bridge.private_key.pem".into(),
                certificate: "sigul.bridge.certificate.pem".into(),
                ca_certificate: "sigul.ca_certificate.pem".into(),
            },
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

async fn accept_conn(
    tcp_listener: &TcpListener,
    ssl: Ssl,
    role: Role,
) -> anyhow::Result<(SslStream<TcpStream>, SocketAddr)> {
    let (tcp_stream, client_addr) = tcp_listener.accept().await?;
    tracing::debug!(listener=?tcp_listener.local_addr()?, ?client_addr, "New TCP connection established");

    let mut stream = tokio_openssl::SslStream::new(ssl, tcp_stream)?;
    Pin::new(&mut stream).accept().await?;
    tracing::debug!(listener=?tcp_listener.local_addr()?, ?client_addr, "TLS session established");

    let mut header_buf = [0_u8; std::mem::size_of::<protocol::ProtocolHeader>()];
    stream.read_exact(&mut header_buf).await?;
    let header = protocol::ProtocolHeader::try_ref_from_bytes(&header_buf)
        .map_err(|err| anyhow!("Failed to parse protocol header: {err}"))?;

    match header.check(role) {
        BridgeStatus::Ok => {
            tracing::trace!(header=?header, "Protocol header passed validation");
        }
        error => {
            let ack = ProtocolAck::new(error);
            stream.write_all(ack.as_bytes()).await?;
            return Err(anyhow::anyhow!(
                "Incoming connection sent an invalid header; dropping connection"
            ));
        }
    }

    let peer_name = peer_common_name(&stream);
    match &peer_name {
        Ok(username) => {
            // We defer acking good connections until we have both sides so that they can share a session id
            tracing::info!(username, ?role, "Sigul connection established");
        }
        Err(protocol::Error::MissingCommonName) => {
            tracing::warn!(
                "Incoming connection presented a client certificate without a common name; dropping connection"
            );
            let ack = protocol::ProtocolAck::new(protocol::BridgeStatus::MissingCommonName);
            stream.write_all(ack.as_bytes()).await?;
        }
        Err(error) => {
            tracing::warn!(?error, "Failed to parse the client certificate");
        }
    };
    peer_name?;

    Ok((stream, client_addr))
}

async fn inner_listen(
    config: Config,
    halt_token: CancellationToken,
    client_listener: TcpListener,
    server_listener: TcpListener,
) -> anyhow::Result<()> {
    let tls_config = config.credentials.ssl_acceptor()?;
    let request_tracker = TaskTracker::new();

    let (server_conns_tx, mut server_conns_rx) =
        mpsc::channel::<(SslStream<TcpStream>, SocketAddr)>(128);
    let (client_conns_tx, mut client_conns_rx) =
        mpsc::channel::<(SslStream<TcpStream>, SocketAddr)>(128);

    let server_acceptor_halt = halt_token.clone();
    let server_tls_config = tls_config.clone();
    let server_acceptor = tokio::spawn(async move {
        let tls_config = server_tls_config;
        loop {
            // `accept_conn` is not cancel safe, but we will never resume it if it is canceled, so
            // that's okay. However, we can't plop all these into a single select without
            // refactoring significantly to make accept_conn safe, so leave it like this for now
            tokio::select! {
                _ = server_acceptor_halt.cancelled() => {
                    tracing::info!("Shutdown requested, no new requests will be accepted");
                    break;
                },
                maybe_conn = accept_conn(&server_listener, Ssl::new(tls_config.context())?, Role::Server) => {
                    match maybe_conn {
                        Ok(conn) => server_conns_tx.send(conn).await?,
                        Err(error) => tracing::warn!(?error, "Failed to accept new server connection"),
                    }
                }
            }
        }
        Ok::<_, anyhow::Error>(())
    });
    let client_acceptor_halt = halt_token.clone();
    let client_acceptor = tokio::spawn(async move {
        loop {
            // `accept_conn` is not cancel safe, but we will never resume it if it is canceled, so
            // that's okay. However, we can't plop all these into a single select without
            // refactoring significantly to make accept_conn safe, so leave it like this for now
            tokio::select! {
                _ = client_acceptor_halt.cancelled() => {
                    tracing::info!("Shutdown requested, no new requests will be accepted");
                    break;
                },
                maybe_conn = accept_conn(&client_listener, Ssl::new(tls_config.context())?, Role::Client) => {
                    match maybe_conn {
                        Ok(conn) => client_conns_tx.send(conn).await?,
                        Err(error) => tracing::warn!(?error, "Failed to accept new client connection"),
                    }
                }
            }
        }
        Ok::<_, anyhow::Error>(())
    });

    'accept: loop {
        tokio::select! {
            _ = halt_token.cancelled() => {
                tracing::info!("Shutdown requested, no new requests will be bridged");
                break 'accept;
            },
            connections = async { tokio::join!(client_conns_rx.recv(), server_conns_rx.recv()) } => {
                if let (Some(client_conn), Some(server_conn)) = connections {
                    let ack = protocol::ProtocolAck::new(protocol::BridgeStatus::Ok);
                    request_tracker.spawn(
                        bridge(ack, client_conn, server_conn).instrument(tracing::Span::current()),
                    );

                } else {
                    tracing::info!("Channels for incoming connections closed; beginning shutdown");
                    break 'accept;

                }
            }
        }
    }

    while let Some((_conn, remote_addr)) = client_conns_rx.recv().await {
        tracing::trace!(?remote_addr, "Cancelling pending client connection");
    }
    while let Some((_conn, remote_addr)) = server_conns_rx.recv().await {
        tracing::trace!(?remote_addr, "Cancelling pending server connection");
    }

    request_tracker.close();
    request_tracker.wait().await;
    server_acceptor.await??;
    client_acceptor.await??;

    Ok(())
}

pub struct Listener {
    /// The socket address client connections are expected to arrive on. This is primarily
    /// useful for tests when binding to port 0.
    client_addr: SocketAddr,
    /// The socket address server connections are expected to arrive on. This is primarily
    /// useful for tests when binding to port 0.
    server_addr: SocketAddr,
    /// A task that is accepting incoming connections. Once the [`CancellationToken`] provided
    /// to the [`listen`] function has been cancelled, this task will complete once all existing
    /// connections complete.
    task: tokio::task::JoinHandle<Result<(), anyhow::Error>>,
    halt_token: CancellationToken,
}

impl Listener {
    /// Get the port number the bridge is listening on for client connections.
    pub fn client_port(&self) -> u16 {
        self.client_addr.port()
    }

    /// Get the port number the bridge is listening on for server connections.
    pub fn server_port(&self) -> u16 {
        self.server_addr.port()
    }

    /// Get a cancellation token which can be used to start the graceful shutdown of this
    /// listener.
    pub fn halt_token(&self) -> CancellationToken {
        self.halt_token.clone()
    }

    pub async fn wait_to_finish(self) -> anyhow::Result<()> {
        self.task.await?
    }

    /// Stop accepting new connections and wait for existing connections to complete.
    ///
    /// Existing connections can run for an arbitrarily long time, so users should wrap
    /// this call in a timeout if they don't have an arbitrarily long time to wait.
    pub async fn halt(self) -> anyhow::Result<()> {
        self.halt_token.cancel();
        self.task.await??;

        Ok(())
    }
}

/// Act as a Siguldry bridge on the provided socket addresses.
///
/// This function returns once the server and client TCP listeners have been established.
#[instrument(skip_all, err)]
pub async fn listen(config: Config) -> anyhow::Result<Listener> {
    let client_listener = TcpListener::bind(config.client_listening_address).await?;
    let server_listener = TcpListener::bind(config.server_listening_address).await?;
    let client_addr = client_listener.local_addr()?;
    let server_addr = server_listener.local_addr()?;
    let halt_token = CancellationToken::new();

    let task = tokio::spawn(
        inner_listen(config, halt_token.clone(), client_listener, server_listener)
            .instrument(tracing::Span::current()),
    );
    Ok(Listener {
        client_addr,
        server_addr,
        task,
        halt_token,
    })
}

#[instrument(
    skip_all,
    ret,
    err,
    fields(
        client_addr = ?client.1,
        server_addr = ?server.1,
        session_id = Uuid::from_u128(ack.session_id.get()).to_string()
    )
)]
async fn bridge(
    ack: ProtocolAck,
    client: (SslStream<TcpStream>, SocketAddr),
    server: (SslStream<TcpStream>, SocketAddr),
) -> anyhow::Result<()> {
    let (mut client_conn, _) = client;
    let (mut server_conn, _) = server;
    tokio::try_join!(
        client_conn.write_all(ack.as_bytes()),
        server_conn.write_all(ack.as_bytes())
    )?;
    tracing::info!("Bridging new connection");

    let size = 1024 * 64;
    match tokio::io::copy_bidirectional_with_sizes(&mut client_conn, &mut server_conn, size, size)
        .await
    {
        Ok((client_sent_bytes, server_sent_bytes)) => tracing::info!(
            client_sent_bytes,
            server_sent_bytes,
            "Connection bridge completed"
        ),
        Err(result) => tracing::info!(
            ?result,
            "Connection bridge completed; connection closed ungracefully"
        ),
    };

    Ok(())
}

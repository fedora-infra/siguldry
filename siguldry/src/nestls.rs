// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! A nested TLS connection.
//!
//! The Siguldry server is designed to accept no incoming network connections. Instead, it
//! communicates with Siguldry clients via a bridge, which proxies the communication back and forth
//! between the client and the server.
//!
//! In order to ensure the bridge has no visibility into the secrets being shared from the client,
//! such as passphrases to access signing keys, the client and server use TLS within the TLS
//! connection to the bridge.
//!
//! A [`Nestls`] connection is capable of behaving as a client or a server. It handles the handshake
//! by sending the [`ProtocolHeader`] and waiting for the [`ProtocolAck`] from the bridge before
//! starting the inner TLS session. Once that is complete, it's up to the user to implement the
//! particulars of the protocol.
//!
//!
//! The high-level connection flow is as follows:
//!
//! 1. A TLS connection to the Sigul bridge is made and both sides offer x509 certificates to be
//!    verified.
//!
//! 2. A protocol header is sent which is a magic number, a protocol version, and
//!    the role of this connection (server or client). The protocol version dictates
//!    what the wire format is for framing and commands and is the responsibility of
//!    the user of the [`Nestls`] to implement.
//!
//! 3a. If the connection is acting as a client, it begins a second TLS connection using
//!     the bridge TLS connection as the transport.
//!
//! 3b. If the connection is acting as a server, it accepts a second TLS connection using
//!     the bridge TLS connection as a transport.
//!
//! 4. The inner TLS connection also uses mutual TLS certificates for authentication, and
//!    if this succeeds the connection is ready to be used.

use std::pin::Pin;

use openssl::{nid::Nid, ssl::Ssl};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, ToSocketAddrs},
};
use tokio_openssl::SslStream;
use tracing::instrument;
use uuid::Uuid;
use zerocopy::IntoBytes;

use crate::{
    error::ConnectionError as Error,
    protocol::{ProtocolAck, ProtocolHeader, Role},
};

/// Build the configuration for a nested TLS session.
pub struct NestlsBuilder {
    bridge_ssl: Ssl,
    role: Role,
}

/// A nested TLS session.
///
/// Use [`AsyncRead`] and [`AsyncWrite`] to read and write to the inner TLS session.
pub struct Nestls {
    /// The TLS connection to the Sigul server.
    inner: SslStream<SslStream<TcpStream>>,
    /// A shared ID between the client and the server identifying this connection.
    session_id: Uuid,
}

impl Nestls {
    /// Get a [`NestlsBuilder`] to configure the connection details.
    ///
    /// Once the connection has been configured, you can create a [`Nestls`] instance by calling
    /// [`NestlsBuilder::connect`] or [`NestlsBuilder::accept`].
    pub fn builder(bridge_ssl: Ssl, role: Role) -> NestlsBuilder {
        NestlsBuilder::new(bridge_ssl, role)
    }

    /// Get the connection's session ID.
    ///
    /// This ID is shared between the client and the server and is primarily useful for logging.
    pub fn session_id(&self) -> Uuid {
        self.session_id
    }

    /// Get the remote connection's commonName from its certificate.
    pub fn peer_common_name(&self) -> Option<String> {
        self.inner
            .ssl()
            .peer_certificate()
            .and_then(|cert| {
                cert.subject_name()
                    .entries_by_nid(Nid::COMMONNAME)
                    .next()
                    .and_then(|entry| entry.data().as_utf8().ok())
            })
            .map(|common_name| common_name.to_string())
    }
}

impl AsyncRead for Nestls {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.as_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Nestls {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.as_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.as_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.as_mut().inner).poll_shutdown(cx)
    }
}

// TODO Things the connection should have config for:
//
// Optional timeout for connection to bridge vs the nested TLS session
// The protocol version being used

impl NestlsBuilder {
    /// Build a configuration for a [`Nestls`] connection.
    fn new(bridge_ssl: Ssl, role: Role) -> Self {
        Self { bridge_ssl, role }
    }

    /// Connect to the bridge and perform the protocol handshake.
    #[instrument(err, skip(bridge_addr, bridge_ssl), level = "debug")]
    async fn connect_to_bridge<A: ToSocketAddrs + std::fmt::Debug>(
        bridge_addr: A,
        bridge_ssl: Ssl,
        role: Role,
    ) -> Result<(SslStream<TcpStream>, Uuid), Error> {
        let outer_stream = TcpStream::connect(&bridge_addr).await?;
        tracing::debug!(?bridge_addr, "TCP connection to the bridge established");
        let mut outer_stream = tokio_openssl::SslStream::new(bridge_ssl, outer_stream)?;
        Pin::new(&mut outer_stream).connect().await?;
        let username = outer_stream
            .ssl()
            .certificate()
            .and_then(|cert| {
                cert.subject_name()
                    .entries_by_nid(Nid::COMMONNAME)
                    .next()
                    .and_then(|entry| entry.data().as_utf8().ok())
            })
            .map(|common_name| common_name.to_string());
        tracing::debug!(?username, "TLS session with the bridge established");

        let protocol_header: ProtocolHeader = role.into();
        let protocol_header = protocol_header.as_bytes();
        outer_stream.write_all(protocol_header).await?;
        tracing::debug!(
            bytes_sent = protocol_header.len(),
            "Protocol header sent to the bridge"
        );
        let session_id = ProtocolAck::check(&mut outer_stream).await?;

        tracing::info!(
            ?bridge_addr,
            ?session_id,
            "Connection to the bridge established."
        );
        Ok((outer_stream, session_id))
    }

    /// Connect to a nested TLS server.
    #[instrument(err, skip(self, server_ssl))]
    pub async fn connect<S: ToSocketAddrs + std::fmt::Debug>(
        self,
        bridge_addr: S,
        server_ssl: Ssl,
    ) -> Result<Nestls, Error> {
        let (outer_stream, session_id) =
            Self::connect_to_bridge(bridge_addr, self.bridge_ssl, self.role).await?;

        let mut inner = tokio_openssl::SslStream::new(server_ssl, outer_stream)?;
        Pin::new(&mut inner).connect().await?;
        tracing::debug!(?session_id, "Inner TLS session with the server established");

        Ok(Nestls { inner, session_id })
    }

    /// Accept a new incoming nested TLS connection.
    #[instrument(err, skip(self, ssl))]
    pub async fn accept<S: ToSocketAddrs + std::fmt::Debug>(
        self,
        bridge_addr: S,
        ssl: Ssl,
    ) -> Result<Nestls, Error> {
        let (outer_stream, session_id) =
            Self::connect_to_bridge(bridge_addr, self.bridge_ssl, self.role).await?;

        let mut inner = tokio_openssl::SslStream::new(ssl, outer_stream)?;
        Pin::new(&mut inner).accept().await?;
        tracing::debug!("Accepted new inner TLS connection from a client");

        Ok(Nestls { inner, session_id })
    }
}

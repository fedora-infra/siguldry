// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! Connect to a Sigul bridge and server.
//!
//! [`Connection`] is capable of connecting to a Sigul bridge and the Sigul server
//! behind that bridge.
//!
//! The high-level client connection flow is as follows:
//!
//! 1. A TLS connection to the Sigul bridge is made. The client authenticates via
//!    an x509 certificate.
//!
//! 2. A request is sent to the bridge. This is composed of a set of headers and an
//!    optional payload.
//!
//! 3. A second TLS connection is established within the connection started in 1.
//!    Instead of using the bridge hostname for TLS validation, however, the server's
//!    hostname is used.
//!
//! 4. Additional, sensitive parameters are sent to the Sigul service in this nested
//!    TLS session. These include HMAC keys, passphrases to access signing keys, etc.
//!    These parameters are serialized like the request headers to the bridge. There
//!    is no payload.
//!
//! 5. The inner TLS session is closed and communication resumes via the bridge. The
//!    response is validated using the HMAC keys shared with the server in step 4.
//!
//! 6. Depending on the request sent in step 2, the server may respond and the connection
//!    is closed, or a series of sub-request/sub-responses are sent across the bridge.
//!
//! ## Protocol Details
//!
//! In order to support multiple TLS session across a single TCP connection, the sigul
//! wire protocol works as follows:
//!
//! 1. _Any_ data written to the connection must be framed; a u32 (network byte order)
//!    is sent to indicate the size of the next frame, along with its destination. The
//!    highest bit is set to 1 if it is a chunk meant for the inner TLS session (e.g.
//!    the server), or to 0 if it is meant for the outer TLS session (e.g. the bridge).
//!
//! 2. Frames may be no larger than `(1 << 31) - 1`.
//!
//! 3. Each connection must start with the Sigul wire protocol version being used; note
//!    that this must be in a frame, so the first 4 bytes written should be the the size
//!    of the first frame followed immediately by the protocol version.
//!
//! 4. Each request/response to the Sigul bridge is made up of a set of headers and a
//!    payload. Sigul defines its own serialization format, which does not map to most
//!    Rust types.
//!
//! 5. After the headers are sent, the payload is sent by first sending a u64 (network
//!    byte order) to indicate the payload size, followed by as many frames as are
//!    necessary to transmit the payload. If the request/response does not use a payload
//!    a payload size of 0 must be sent.

use std::{collections::HashMap, pin::Pin, str};

use anyhow::Context;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use openssl::{
    hash::{DigestBytes, MessageDigest},
    ssl::Ssl,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, ToSocketAddrs},
};
use tokio_openssl::SslStream;
use tracing::instrument;

use crate::v1::client::Command;
use crate::v1::error::{ClientError, ConnectionError as Error};

/// The Sigul wire protocol version this implementation supports. This is the
/// latest version as of Sigul version 1.2.
pub const PROTOCOL_VERSION: u32 = 1;

/// When sending data meant for the inner TLS session, the payload size should
/// be OR'd with this mask.
pub(crate) const CHUNK_INNER_MASK: u32 = 1 << 31;

/// The maximum size of a data chunk when writing to the inner or outer TLS stream.
pub(crate) const MAX_CHUNK_SIZE: u32 = CHUNK_INNER_MASK - 1;

/// The maximum amount to read from a chunk in one go. In practice,
/// no inner chunks are more than a few KB, but outer chunks with payloads
/// can be ~2GB.
pub(crate) const MAX_READ_BUF: u64 = 1024 * 1024;

/// Keeps track of which stream incoming traffic belongs to.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Chunk {
    Unknown,
    Inner(u32),
    Outer(u32),
}

impl From<u32> for Chunk {
    fn from(value: u32) -> Self {
        if value & CHUNK_INNER_MASK == CHUNK_INNER_MASK {
            let payload = Self::Inner(value - CHUNK_INNER_MASK);
            tracing::debug!(?payload, "New inner payload detected");
            payload
        } else {
            let payload = Self::Outer(value);
            tracing::debug!(?payload, "New outer payload detected");
            payload
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Response {
    pub status_code: u32,
    pub fields: HashMap<String, Vec<u8>>,
}

/// A set of secret keys shared with the Sigul server via the inner TLS session;
/// this key is used to verify the integrity of messages passed to or from the
/// server using the outer TLS session.
///
/// The headers and payload as signed using different keys. Sigul v1.2 expects
/// 64 byte keys and uses SHA512 for the message digest algorithm.
struct HmacKeys {
    /// The secret key used for request/response header signing.
    header_key: [u8; 64],
    /// The secret key used for request/response payload signing.
    payload_key: [u8; 64],
}

impl core::fmt::Debug for HmacKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Manually implemented so keys aren't accidentally logged.
        f.debug_struct("HmacKeys")
            .field("header_key", &format!("{} bytes", self.header_key.len()))
            .field("payload_key", &format!("{} bytes", &self.payload_key.len()))
            .finish()
    }
}

impl HmacKeys {
    /// Create a new key pair request HMAC signing.
    fn new() -> Result<Self, Error> {
        let mut header_key = [0; 64];
        openssl::rand::rand_priv_bytes(&mut header_key)?;
        let mut payload_key = [0; 64];
        openssl::rand::rand_priv_bytes(&mut payload_key)?;

        Ok(Self {
            header_key,
            payload_key,
        })
    }

    /// Validate header data against the provided HMAC signature.
    fn validate_header(&self, data: &[u8], signature: &[u8]) -> Result<(), ClientError> {
        let key = openssl::pkey::PKey::hmac(&self.header_key)?;
        let mut signer = openssl::sign::Signer::new(MessageDigest::sha512(), &key)?;
        signer.update(data)?;
        let hmac = signer.sign_to_vec()?;
        if openssl::memcmp::eq(&hmac, signature) {
            tracing::debug!("HMAC signature validated on response headers");
            Ok(())
        } else {
            tracing::error!("HMAC signature on response headers failed!");
            Err(ClientError::InvalidSignature)
        }
    }

    /// Get a new signer instance to use when streaming the response payload.
    fn payload_signer(&self) -> Result<openssl::sign::Signer<'_>, Error> {
        let key = openssl::pkey::PKey::hmac(&self.payload_key)?;
        // TODO: really should just wrap this up in a type
        Ok(openssl::sign::Signer::new(MessageDigest::sha512(), &key)?)
    }

    /// Finish validating a payload that was streamed to the signer.
    fn validate_payload_signer(
        signer: openssl::sign::Signer<'_>,
        signature: &[u8],
    ) -> Result<(), ClientError> {
        let hmac = signer.sign_to_vec()?;
        if openssl::memcmp::eq(&hmac, signature) {
            tracing::debug!("HMAC signature validated on response payload");
            Ok(())
        } else {
            tracing::error!("HMAC signature on response payload failed!");
            Err(ClientError::InvalidSignature)
        }
    }
}

mod state {
    /// Used for connections to the bridge that have not communicated with the server.
    #[derive(Debug)]
    pub(crate) struct New;

    /// Used for connections that have sent their request to the server.
    #[derive(Debug)]
    pub(crate) struct InnerFinished;
}

pub(crate) struct Connection<State = state::New> {
    /// The TLS connection to the Sigul bridge.
    stream: SslStream<TcpStream>,
    /// A set of HMAC keys sent to the server to authenticate its responses.
    response_signing_keys: HmacKeys,
    /// Tracks if this connection has communicated with the Sigul server yet.
    state: std::marker::PhantomData<State>,
}

pub(crate) struct InnerConnection {
    /// The connection to the sigul bridge.
    stream: SslStream<TcpStream>,
    /// The digest of the the request headers sent to the bridge; this is sent
    /// to the server via the inner TLS session.
    outer_header_hash: DigestBytes,
    /// The digest of the the request payload sent to the bridge; this is sent
    /// to the server via the inner TLS session.
    payload_hash: DigestBytes,
    /// A set of HMAC keys sent to the server to authenticate its responses.
    response_signing_keys: HmacKeys,
}

impl Connection<state::New> {
    /// Open a new connection to the Sigul bridge.
    #[instrument(err, skip_all)]
    pub async fn connect<A: ToSocketAddrs + std::fmt::Debug>(
        addr: A,
        ssl: Ssl,
    ) -> Result<Self, Error> {
        let response_signing_keys = HmacKeys::new()?;
        let stream = TcpStream::connect(&addr).await?;
        tracing::info!(?addr, "TCP connection to the Sigul bridge established");
        let mut stream = tokio_openssl::SslStream::new(ssl, stream)?;
        Pin::new(&mut stream).connect().await?;
        tracing::info!("TLS session with the Sigul bridge established");

        Ok(Connection {
            stream,
            response_signing_keys,
            state: std::marker::PhantomData,
        })
    }
}

impl Connection<state::New> {
    /// Send the request and optional payload to the bridge, which will relay it to the server.
    #[instrument(err, skip_all)]
    pub async fn outer_request<P: AsyncRead + AsyncSeek + Unpin>(
        mut self,
        command: Command,
        mut payload: Option<P>,
    ) -> Result<InnerConnection, ClientError> {
        let operation_bytes = crate::serdes::to_bytes(&command)?;
        let mut outer_header_hash = openssl::hash::Hasher::new(MessageDigest::sha512())?;
        // The header digest must include the protocol version bytes.
        outer_header_hash.update(&PROTOCOL_VERSION.to_be_bytes())?;
        outer_header_hash.update(&operation_bytes)?;
        let outer_header_hash = outer_header_hash.finish()?;

        // The first chunk covers the protocol version, the op headers, and the payload size. Depending on
        // the payload size, we may need to send 0 or more chunks after this one to complete the request.
        let header_length =
            std::mem::size_of::<u32>() + operation_bytes.len() + std::mem::size_of::<u64>();
        self.stream
            .write_u32(
                header_length
                    .try_into()
                    .context("headers must be less than u32::MAX bytes")?,
            )
            .await?;
        tracing::trace!(header_length, "Sent initial chunk size");
        self.stream.write_u32(PROTOCOL_VERSION).await?;
        tracing::trace!(version = PROTOCOL_VERSION, "Sent protocol version header");
        self.stream.write_all(operation_bytes.as_slice()).await?;
        tracing::trace!(
            operation_header_length = operation_bytes.len(),
            "Sent command fields"
        );

        let payload_length = if let Some(payload) = &mut payload {
            let payload_length = payload.seek(std::io::SeekFrom::End(0)).await?;
            payload.rewind().await?;
            payload_length
        } else {
            0
        };
        self.stream
            .write_all(payload_length.to_be_bytes().as_slice())
            .await?;
        tracing::trace!(payload_length, "Sent payload length");

        let mut payload_hash = openssl::hash::Hasher::new(MessageDigest::sha512())?;
        if let Some(mut payload) = payload {
            let mut buf = BytesMut::with_capacity(MAX_READ_BUF.try_into().unwrap())
                .limit(MAX_READ_BUF.try_into().unwrap());
            let mut payload_bytes_sent = 0;

            loop {
                let bytes_read = payload.read_buf(&mut buf).await?;
                if bytes_read == 0 {
                    tracing::trace!("Payload stream reached EOF");
                    break;
                }

                let mut unlimited_buf = buf.into_inner();
                let chunk = unlimited_buf.split().freeze();
                buf = unlimited_buf.limit(MAX_READ_BUF.try_into().unwrap());
                tracing::trace!(
                    chunk_length = chunk.len(),
                    payload_bytes_sent,
                    "Sending payload chunk"
                );
                payload_hash.update(&chunk)?;
                self.stream.write_u32(chunk.len() as u32).await?;
                self.stream.write_all(&chunk).await?;
                payload_bytes_sent += chunk.len();
                tracing::trace!(
                    chunk_length = chunk.len(),
                    payload_bytes_sent,
                    "Finished sending payload chunk"
                );
            }
        }
        let payload_hash = payload_hash.finish()?;
        self.stream.flush().await?;
        tracing::info!(
            header_length,
            payload_length,
            ?command,
            "Sent request to Sigul bridge"
        );

        Ok(InnerConnection {
            stream: self.stream,
            outer_header_hash,
            payload_hash,
            response_signing_keys: self.response_signing_keys,
        })
    }
}

impl InnerConnection {
    /// Send a request to the Sigul server through the existing Sigul bridge connection.
    ///
    /// The request map should contain any command-specific parameters. This function handles
    /// sharing the header and payload HMAC keys and outer request digests.
    ///
    /// The provided [`Ssl`] object should be configured to authenticate the server hostname,
    /// _not_ the bridge.
    ///
    /// Once the request has completed, the returned [`Connection`] can be used to read the response.
    pub async fn inner_request(
        self,
        ssl: Ssl,
        mut request: HashMap<&str, &[u8]>,
    ) -> Result<Connection<state::InnerFinished>, ClientError> {
        // Include the outer request header and payload digests, along with a set of private keys used
        // for HMAC on server responses. Since the server responses in the outer TLS stream, these serve
        // to ensure the bridge is not meddling with the responses.
        let header_hash = &*self.outer_header_hash;
        let payload_hash = &*self.payload_hash;
        request.insert("header-auth-sha512", header_hash);
        request.insert("payload-auth-sha512", payload_hash);

        request.insert("header-auth-key", &self.response_signing_keys.header_key);
        request.insert("payload-auth-key", &self.response_signing_keys.payload_key);

        let payload = crate::serdes::to_bytes(&request)?;

        // To write to inner payload:
        // - Send size of inner bytes by sending a u32 of the size, OR'd with CHUNK_INNER_MASK.
        //   This also means MAX_CHUNK_SIZE = CHUNK_INNER_MASK - 1

        let mut nestls = crate::v1::nestls::Nestls::connect(self.stream, ssl).await?;
        let stream = nestls.inner_mut();

        stream.write_all(&payload).await?;
        tracing::debug!(
            payload_bytes = payload.len(),
            "Sigul server payload sent via inner TLS session"
        );
        stream.flush().await?;
        tracing::debug!("Inner TLS connection flushed");

        // We don't expect a response here.
        let mut buf = vec![];
        let response = stream.read_to_end(&mut buf).await?;
        tracing::debug!(
            response_size = response,
            ?buf,
            "Inner TLS session end-of-stream reached"
        );
        assert!(buf.is_empty());

        let outer_stream = nestls.into_outer().await?;

        Ok(Connection {
            stream: outer_stream,
            response_signing_keys: self.response_signing_keys,
            state: std::marker::PhantomData,
        })
    }
}

impl Connection<state::InnerFinished> {
    /// The length, in bytes, of the HMAC signature appended to the headers and payload.
    const SIGNATURE_LENGTH: usize = 64;

    /// Read the server response.
    ///
    /// The response payload is streamed to the given `payload`. However, the contents
    /// of this payload are not validated using the server's HMAC until this function
    /// returns. On failure, the contents of payload should be discarded.
    ///
    /// <div class="warning">
    ///
    /// Do not use the contents of the payload unless this function returns [`Result::Ok`]!
    ///
    /// </div>
    #[instrument(err, skip_all, level = "debug")]
    pub(crate) async fn response<P: AsyncWrite + AsyncWriteExt + Unpin>(
        mut self,
        mut payload: P,
    ) -> Result<Response, ClientError> {
        // Assumption: this chunk includes the entire response header.
        //
        // This is how Sigul 1.2 works, but there's nothing in the protocol that necessarily
        // requires it to be true. Refer to the `BridgeConnection.__forward_reply_headers`
        // function in Sigul 1.2's bridge.py for its implementation.
        let chunk_size = self.stream.read_u32().await?;
        assert_eq!(Chunk::from(chunk_size), Chunk::Outer(chunk_size));
        tracing::trace!(chunk_size=?Chunk::from(chunk_size), "Response chunk received");

        // Parse out the response header.
        //
        // The header format is as follows (network byte order):
        //
        //  -----------------------------------
        //  | u32 | request return code       |
        //  | u8  | number of response fields |
        //  | u8  | field 0 key length        |
        //  | var | field 0 key bytes         |
        //  | u8  | field 0 value length      |
        //  | var | field 0 value bytes       |
        //  | u8  | field 1 key length        |
        //  ...................................
        //  | 64 bytes | HMAC signature       |
        //  -----------------------------------
        //
        // The HMAC signature includes all prior header fields.
        let mut read_buffer = vec![
            0_u8;
            chunk_size
                .try_into()
                .context("header chunk exceeded platform usize")?
        ];
        self.stream.read_exact(&mut read_buffer).await?;
        tracing::trace!("Response headers received");
        let mut response_headers = Bytes::from(read_buffer);
        let response_headers_signature = response_headers.split_off(
            response_headers
                .len()
                .checked_sub(Self::SIGNATURE_LENGTH)
                .ok_or_else(|| {
                    anyhow::anyhow!("Response headers weren't long enough to include a signature")
                })?,
        );
        debug_assert_eq!(response_headers_signature.len(), Self::SIGNATURE_LENGTH);
        self.response_signing_keys
            .validate_header(&response_headers, &response_headers_signature)?;

        let status_code = response_headers.get_u32();
        tracing::info!(?status_code, "Sigul server returned status code");
        let fields = crate::serdes::from_bytes(&response_headers)?;

        // Parse out the response payload.
        //
        // The payload format is as follows:
        //
        // ----------------------------------
        // | u64 | The total payload length |
        // | u32 | The first chunk length   |
        // | var | The first chunk data     |
        // ..................................
        // | u32 | The final chunk length   |
        // | var | The final chunk data     |
        // ----------------------------------
        //
        // All the `var` fields add up to the total payload length. In the event that
        // the response has no payload, the total payload length of 0 is sent, and
        // no chunks of payload data follow.
        //
        // The Sigul 1.2 implemention _always_ writes the payload size in its own chunk. Rather than
        // attempt to write a generic chunk parser and all that, we'll do this manual read. Additionally,
        // the Sigul 1.2 implementation always aligns the payload to a chunk boundry so we don't attempt
        // to deal with that case, either.
        let chunk_size = self.stream.read_u32().await?;
        debug_assert_eq!(chunk_size as usize, std::mem::size_of::<u64>());
        let payload_length = self.stream.read_u64().await?;
        tracing::debug!(payload_length, "Sigul server is sending payload");

        // Currently the server always sends files in 4096 byte chunks; however we would
        // be wise to not blindly trust the server's chunk size (which can be up to 2GB)
        // is an amount we are okay reading at once. As such, a chunk may span several
        // iterations of the following read loop.
        let mut payload_hmac = self.response_signing_keys.payload_signer()?;
        if payload_length > 0 {
            let mut current_chunk = self.stream.read_u32().await?;
            let mut total_read = 0_u64;
            let mut read_buf = vec![];
            let mut stream = self.stream.take(MAX_READ_BUF.min(current_chunk.into()));
            loop {
                let bytes_read: u32 = stream
                    .read_to_end(&mut read_buf)
                    .await?
                    .try_into()
                    .context("read more than u32::MAX bytes")?;
                tracing::debug!(current_chunk, bytes_read, "Read payload chunk");

                payload_hmac.update(&read_buf)?;
                payload.write_all(&read_buf).await?;
                read_buf.clear();

                total_read = total_read
                    .checked_add(bytes_read.into())
                    .context("payload size overflowed a u64")?;
                current_chunk = current_chunk
                    .checked_sub(bytes_read)
                    .context("read across a chunk boundry")?;
                if total_read == payload_length {
                    tracing::info!(payload_length, "Sigul server payload received");
                    break;
                }
                if current_chunk == 0 {
                    stream.set_limit(4);
                    current_chunk = stream.read_u32().await?;
                    stream.set_limit(MAX_READ_BUF.min(current_chunk.into()));
                    tracing::debug!(current_chunk, "Awaiting next payload chunk");
                }
            }
            self.stream = stream.into_inner();
        }
        payload.shutdown().await?;

        // Finally, the Sigul 1.2 implementation always sends a 64 byte chunk after the payload
        // with the signature.
        let sig_chunk = self.stream.read_u32().await? as usize;
        assert_eq!(sig_chunk, 64);
        let mut payload_signature = vec![0_u8; sig_chunk];
        self.stream.read_exact(&mut payload_signature).await?;
        tracing::trace!("Read payload signature");
        HmacKeys::validate_payload_signer(payload_hmac, &payload_signature)?;

        // Bridge sends a EOF as a 0 u32
        if self.stream.read_u32().await? != 0 {
            panic!("Bug: response framing is incorrect!");
        }

        if status_code == 0 {
            Ok(Response {
                status_code,
                fields,
            })
        } else {
            Err(crate::v1::error::Sigul::from(status_code).into())
        }
    }
}

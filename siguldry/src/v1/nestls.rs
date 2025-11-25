// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! Nested TLS session support.
//!
//! This implemetation is compatible with [sigul][1] version 1.2.
//!
//! [1]: https://pagure.io/sigul

use std::pin::Pin;

use bytes::{Buf, Bytes, BytesMut};
use openssl::ssl::Ssl;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    net::TcpStream,
    task::JoinHandle,
};
use tokio_openssl::SslStream;
use tracing::{Instrument, instrument};

use crate::v1::connection::{CHUNK_INNER_MASK, Chunk, MAX_CHUNK_SIZE, MAX_READ_BUF};
use crate::v1::error::ConnectionError as Error;

/// Implements a nested ("inner") TLS session on top of an existing TLS session.
///
/// This implementation is particular to the Sigul bridge implementation, which
/// expects all data to be framed with a u32 that describes the size of the
/// incoming data as well as whether it belongs to the outer or inner stream.
#[derive(Debug)]
pub struct Nestls {
    inner_stream: SslStream<DuplexStream>,
    framing_task: JoinHandle<Result<SslStream<TcpStream>, Error>>,
}

impl Nestls {
    /// Connect to a server over an existing TLS session.
    ///
    /// This object takes ownership of the outer TLS session, and it is not possible to use
    /// the outer session while the inner session is active. Once you have finished with the
    /// inner session, use [`Nestls::into_outer`] to get the outer session back.
    #[instrument(err, skip_all, name = "inner_tls")]
    pub async fn connect(
        outer_stream: SslStream<TcpStream>,
        inner_ssl: Ssl,
    ) -> Result<Self, Error> {
        let (client_write_half, client_read_half) = tokio::io::duplex(1024 * 1024);
        let framing_task =
            tokio::spawn(Self::parser(outer_stream, client_read_half).in_current_span());

        let mut inner_stream = tokio_openssl::SslStream::new(inner_ssl, client_write_half)?;
        Pin::new(&mut inner_stream).connect().await?;
        tracing::debug!("Inner TLS connection established.");

        Ok(Self {
            inner_stream,
            framing_task,
        })
    }

    /// Get an mutable reference to the inner TLS stream.
    ///
    /// Use this to read and write to the inner TLS stream.
    pub fn inner_mut(&mut self) -> &mut SslStream<DuplexStream> {
        &mut self.inner_stream
    }

    /// Consume this inner TLS session and return the outer TLS session, along with any payloads
    /// received for the outer session.
    #[instrument(err, skip_all, level = "debug")]
    pub async fn into_outer(self) -> Result<SslStream<TcpStream>, Error> {
        // It's important to drop the inner stream before attempting to join with the framing task,
        // as this closes DuplexStream. Failing to do so causes the task to hang indefinitely.
        drop(self.inner_stream);
        let framing_task = self.framing_task;
        framing_task.await.map_err(|err| {
            Error::ProtocolViolation(format!("Sigul connection framing failed: {err:?}"))
        })?
    }

    /// This task takes ownership of the outer TLS session, which is what we write to
    /// to send data over the network, along with the receiving end of the inner TLS session.
    ///
    /// It intercepts the inner session in order to properly frame the data, which requires a
    /// u32 header indicating the payload size and whether or not its destined for the inner
    /// or outer stream.
    ///
    /// When we read data _from_ the outer stream, it can either be destined for the outer session
    /// or for the nested TLS session. However, the Sigul implementation seems to forbid interlacing
    /// inner and outer chunks, so this function returns an error if any outer chunks are recieved.
    ///
    /// The outer stream is returned when the inner TLS session ends; users can retrieve this via
    /// the [`Nestls::into_outer`] function.
    #[instrument(err, skip_all)]
    async fn parser(
        outer_stream: SslStream<TcpStream>,
        mut client_inner_tls: DuplexStream,
    ) -> Result<SslStream<TcpStream>, Error> {
        let mut inner_outgoing_buf = BytesMut::new();

        // Tracks how much data we expect and which channel it's for
        let mut incoming_chunk: Chunk = Chunk::Unknown;
        // Used to disable the branch that forwards to the bridge once the client sends an EOF.
        // Without this, calling `client_inner_tls.read_buf` would always immediately complete.
        let mut sent_inner_eof = false;
        // Buffer for incoming data; this should grow to no larger than [`MAX_READ_BUF`] as we
        // limit the stream to ensure we don't read past an incoming chunk boundry.
        let mut read_buffer = vec![];
        let mut outer_stream = outer_stream.take(MAX_CHUNK_SIZE.into());
        loop {
            // Calculate the limit to apply when reading from the stream to ensure we don't cross a
            // chunk boundry. This is important since we must return the stream at the start of an
            // outer TLS session chunk.
            //
            // This also ensures we maintain a reasonable buffer size, so we may read a chunk across
            // multiple iterations of this select loop.
            //
            // It would have been convenient to use [`AsyncReadExt::read_exact`], but it's not cancel-
            // safe and could result in partial reads to the buffer across `select!` invocations.
            let current_chunk_size = match incoming_chunk {
                Chunk::Unknown => {
                    outer_stream.set_limit(4);
                    0
                }
                Chunk::Inner(0) => {
                    tracing::info!("Sigul server signaled end of inner TLS stream");
                    break Ok::<_, Error>(());
                }
                Chunk::Inner(chunk_size) => {
                    // Return a buffer that ensures we don't read past the current chunk, and that
                    // also limits the amount we'll read in one go to something less than the max
                    // chunk size of ~2GB.
                    let size = MAX_READ_BUF.min(chunk_size.into());
                    outer_stream.set_limit(size);
                    chunk_size
                }
                Chunk::Outer(_) => {
                    // Based on Sigul 1.2, it appears that it is forbidden to send data to the outer
                    // stream while the inner stream is active. Therefore, if a chunk arrives for
                    // the outer stream, this will return a [`Error::ProtocolViolation`]. There's no
                    // technical reason this couldn't handle interlaced chunks, but as it does not
                    // appear to be required by the Python implementation, there's no reason to
                    // handle it here. It's also entirely possible the author misunderstood the
                    // Python implementation, in which case this must be adjusted to split out the
                    // traffic.
                    return Err(Error::ProtocolViolation(
                        "outer TLS data receieved while inner TLS session is active".to_string(),
                    ));
                }
            };

            tokio::select! {
                // Forward any bytes written to the inner TLS session
                total_bytes = client_inner_tls.read_buf(&mut inner_outgoing_buf), if !sent_inner_eof => {
                    // We expect to have completely written out the buffer each time.
                    let total_bytes = total_bytes?;
                    let to_write = inner_outgoing_buf.split().freeze();
                    debug_assert_eq!(total_bytes, to_write.len());
                    tracing::trace!(total_bytes, "Forwarding bytes client wrote to the inner TLS session");

                    // Unfortunately this is required since the limited stream doesn't seem to support
                    // the AsyncWriteExt trait. We re-wrap it after we've written everything.
                    let stream_limit = outer_stream.limit();
                    let mut unlimited_outer_stream = outer_stream.into_inner();

                    if total_bytes == 0 {
                        // Indicates an end-of-stream; to signal this to the bridge we send CHUNK_INNER_MASK
                        unlimited_outer_stream.write_u32(CHUNK_INNER_MASK).await?;
                        tracing::debug!("Sent EOF for inner TLS stream");
                        sent_inner_eof = true;
                    }

                    for chunk in to_write.chunks(MAX_CHUNK_SIZE.try_into().expect("platform with at least 4 byte usize needed")) {
                        let chunk_size = chunk.len();
                        tracing::trace!(
                            chunk_size,
                            total_bytes,
                            "Sending chunk to the server via the inner TLS stream"
                        );
                        unlimited_outer_stream
                            .write_u32(chunk_size as u32 | CHUNK_INNER_MASK)
                            .await?;
                        unlimited_outer_stream.write_all(chunk).await?;
                    }

                    outer_stream = unlimited_outer_stream.take(stream_limit);
                },

                // Read bytes from the bridge.
                //
                // Note that `outer_stream` has a limit placed on it, so when we
                // read to the end, it's not _really_ the end of the stream. We
                // detect an end-of-stream event at the start of the loop.
                num_bytes = outer_stream.read_to_end(&mut read_buffer) => {
                    let num_bytes: u32 = num_bytes?.try_into().expect("read more than CHUNK_SIZE_MAX bytes from stream");
                    tracing::trace!(num_bytes, ?incoming_chunk, "Received bytes from the Sigul bridge");
                    if incoming_chunk == Chunk::Unknown {
                        if read_buffer.is_empty() {
                            let message = "Sigul sent EOF during inner TLS session; the sigul server might not be reachable".to_string();
                            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, message).into());
                        }
                        debug_assert_eq!(read_buffer.len(), 4);
                        incoming_chunk = Bytes::from(read_buffer.clone()).get_u32().into();
                        tracing::debug!(?incoming_chunk, "Received chunk during inner TLS session");
                    } else {
                        client_inner_tls.write_all(&read_buffer).await?;
                        let remaining_bytes = current_chunk_size - num_bytes;
                        tracing::trace!(num_bytes, remaining_bytes, "Wrote bytes to inner stream");
                        if remaining_bytes > 0 {
                            incoming_chunk = Chunk::Inner(remaining_bytes);
                        } else {
                            incoming_chunk = Chunk::Unknown;
                        }
                    }
                    read_buffer.clear();
                },
            }
        }?;

        Ok(outer_stream.into_inner())
    }
}

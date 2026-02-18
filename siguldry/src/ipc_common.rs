// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! Provide some common utilities for doing IPC for various helpers.
//!
//! This is primarily used in combination with systemd socket activation.

use std::path::Path;

use anyhow::Context;
use bytes::Bytes;
use tokio::io::{
    AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, Lines, ReadHalf, WriteHalf,
};
use tokio::net::UnixStream;
use tracing::{Level, instrument};

pub struct IpcClient {
    writer: WriteHalf<UnixStream>,
    reader: Option<Lines<BufReader<ReadHalf<UnixStream>>>>,
}

impl IpcClient {
    pub async fn new(socket_path: &Path) -> anyhow::Result<Self> {
        let stream = UnixStream::connect(socket_path)
            .await
            .with_context(|| format!("Failed to connect to socket at {}", socket_path.display()))?;
        let (reader, writer) = tokio::io::split(stream);
        Ok(Self {
            writer,
            reader: Some(BufReader::new(reader).lines()),
        })
    }

    /// Send a request to the IPC server.
    ///
    /// The bytes argument exists just because Sequioa doesn't support signing from a digest
    /// (easily, anyway). Don't use it for anything else, and delete it if signing via PKCS#11
    /// for PGP is good enough.
    #[instrument(skip_all, level = Level::DEBUG)]
    pub async fn request<R: ?Sized + serde::Serialize>(
        &mut self,
        request: &R,
        bytes: Option<&[u8]>,
    ) -> anyhow::Result<serde_json::Value> {
        let mut request = serde_json::to_string(request)?;
        request.push('\n');

        self.writer.write_all(request.as_bytes()).await?;
        if let Some(bytes) = bytes {
            self.writer.write_all(bytes).await?;
        }
        self.writer.flush().await?;

        let mut reader = self
            .reader
            .take()
            .expect("Programmer error: replace read half");
        let response = match reader.next_line().await {
            Ok(Some(response)) => serde_json::from_str(&response)
                .map_err(|error| anyhow::anyhow!("Failed to deserialize response: {error:?}")),
            Ok(None) => Err(anyhow::anyhow!("Unexpected EOF from IPC server")),
            Err(error) => Err(anyhow::anyhow!(
                "Unexpected error reading from IPC server: {error:?}"
            )),
        };
        self.reader = Some(reader);

        response
    }

    /// Only use this for PGP signing to read the payload back after the response.
    ///
    /// Delete this if we can use PKCS#11 client-side for all signing.
    #[instrument(skip(self), level = Level::DEBUG)]
    pub async fn read_bytes(&mut self, payload_size: usize) -> std::io::Result<Bytes> {
        let mut reader = self
            .reader
            .take()
            .expect("Programmer error: replace read half")
            .into_inner();
        let mut buffer = vec![0; payload_size];
        tracing::trace!(len = buffer.len(), "trying to read into buf");
        let result = reader.read_exact(&mut buffer).await;
        self.reader = Some(reader.lines());
        result?;

        Ok(Bytes::from(buffer))
    }

    pub async fn shutdown(mut self) -> std::io::Result<()> {
        self.writer.shutdown().await
    }
}

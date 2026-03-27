// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! Provide some common utilities for doing IPC for various helpers.
//!
//! This is primarily used in combination with systemd socket activation.

use std::path::Path;

use anyhow::Context;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines, ReadHalf, WriteHalf};
use tokio::net::UnixStream;
use tracing::{Level, instrument};

pub struct IpcClient {
    writer: WriteHalf<UnixStream>,
    reader: Lines<BufReader<ReadHalf<UnixStream>>>,
}

impl IpcClient {
    pub async fn new(socket_path: &Path) -> anyhow::Result<Self> {
        let stream = UnixStream::connect(socket_path)
            .await
            .with_context(|| format!("Failed to connect to socket at {}", socket_path.display()))?;
        let (reader, writer) = tokio::io::split(stream);
        Ok(Self {
            writer,
            reader: BufReader::new(reader).lines(),
        })
    }

    /// Send a request to the IPC server.
    ///
    /// The bytes argument exists just because Sequioa doesn't support signing from a digest
    /// (easily, anyway). Don't use it for anything else, and delete it if signing via PKCS#11
    /// for OpenPGP is good enough.
    #[instrument(skip_all, level = Level::DEBUG)]
    pub async fn request<R: ?Sized + serde::Serialize>(
        &mut self,
        request: &R,
    ) -> anyhow::Result<serde_json::Value> {
        let mut request = serde_json::to_string(request)?;
        request.push('\n');

        self.writer.write_all(request.as_bytes()).await?;
        self.writer.flush().await?;

        match self.reader.next_line().await {
            Ok(Some(response)) => serde_json::from_str(&response)
                .map_err(|error| anyhow::anyhow!("Failed to deserialize response: {error:?}")),
            Ok(None) => Err(anyhow::anyhow!("Unexpected EOF from IPC server")),
            Err(error) => Err(anyhow::anyhow!(
                "Unexpected error reading from IPC server: {error:?}"
            )),
        }
    }

    pub async fn shutdown(mut self) -> std::io::Result<()> {
        self.writer.shutdown().await
    }
}

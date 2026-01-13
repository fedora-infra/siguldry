// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! The Siguldry server.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use bytes::{BufMut, BytesMut};
use openssl::ssl::{Ssl, SslAcceptor, SslConnector};
use sqlx::{Pool, Sqlite};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinSet,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{Instrument, instrument};
use zerocopy::{IntoBytes, TryFromBytes};

use crate::{
    error::ConnectionError,
    nestls::Nestls,
    protocol::{self, Role, json::Request},
    server::{config::Config, db, handlers},
};

// These should both be configurable and 100MB is probably too big as a default.
const MAX_JSON_SIZE: usize = 1024 * 32;
const MAX_BINARY_SIZE: usize = 1024 * 1024 * 100;

/// A sigul server.
pub struct Server {
    config: Arc<Config>,
    db_pool: Pool<Sqlite>,
    client_tls_config: SslConnector,
    server_tls_config: SslAcceptor,
}

pub struct Listener {
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
    halt_token: CancellationToken,
}

impl Listener {
    /// Stop accepting new connections and wait for existing connections to complete.
    ///
    /// Existing connections can run for an arbitrarily long time, so users should wrap
    /// this call in a timeout if they don't have an arbitrarily long time to wait.
    pub async fn halt(self) -> anyhow::Result<()> {
        self.halt_token.cancel();
        self.task.await??;

        Ok(())
    }

    /// Get a cancellation token which can be used to start the graceful shutdown of this
    /// listener.
    pub fn halt_token(&self) -> CancellationToken {
        self.halt_token.clone()
    }

    pub async fn wait_to_finish(self) -> anyhow::Result<()> {
        self.task.await??;
        Ok(())
    }
}

impl Server {
    /// Create a new server.
    pub async fn new(config: Config) -> anyhow::Result<Self> {
        let client_tls_config = config.credentials.ssl_connector()?;
        let server_tls_config = config.credentials.ssl_acceptor()?;
        let db_pool = db::pool(
            config
                .database()
                .as_os_str()
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("Database path isn't valid UTF8"))?,
            true,
        )
        .await?;
        Ok(Self {
            config: Arc::new(config),
            db_pool,
            client_tls_config,
            server_tls_config,
        })
    }

    /// Run the server.
    #[instrument(skip_all, name = "server")]
    pub fn run(self) -> Listener {
        let halt_token = CancellationToken::new();
        let server_halt_token = halt_token.clone();
        let task = tokio::spawn(async move {
            let request_tracker = TaskTracker::new();
            let mut connection_pool = JoinSet::new();
            for _ in 0..self.config.connection_pool_size {
                self.accept(&mut connection_pool)?;
            }

            'accept: loop {
                let conn = tokio::select! {
                    _ = server_halt_token.cancelled() => {
                        tracing::info!("Shutdown requested, no new requests will be accepted");
                        connection_pool.abort_all();
                        tracing::debug!("Aborted all connections in the pool");
                        break 'accept;
                    },
                    conn = connection_pool.join_next() => conn,
                };

                match conn {
                    Some(Ok(Ok(conn))) => {
                        tracing::info!("New request accepted");
                        while connection_pool.len() < self.config.connection_pool_size {
                            self.accept(&mut connection_pool)?;
                        }
                        request_tracker.spawn(
                            handle(self.config.clone(), self.db_pool.clone(), conn)
                                .instrument(tracing::Span::current()),
                        );
                    }
                    Some(Ok(Err(error))) => {
                        tracing::error!(?error, "Failed to accept incoming client connection");
                    }
                    Some(Err(error)) => {
                        tracing::error!(?error, "Connection pool failed to yield a connection");
                    }
                    None => {
                        // This occurs when connections aren't being successfully established
                        tracing::error!("Connection pool exhausted; trying again in 15 seconds...");
                        let delay = tokio::time::sleep(Duration::from_secs(15));
                        tokio::select! {
                            _ = server_halt_token.cancelled() => {
                                tracing::info!("Shutdown requested, no new requests will be accepted");
                                connection_pool.abort_all();
                                tracing::debug!("Aborted all connections in the pool");
                                break 'accept;
                            },
                            _ = delay => {},
                        }
                        self.accept(&mut connection_pool)?;
                    }
                }
            }

            tracing::debug!("Beginning shutdown");
            request_tracker.close();
            tracing::debug!("Request tracker closed");
            connection_pool.shutdown().await;
            tracing::debug!("Connection pool shutdown");
            request_tracker.wait().await;
            tracing::info!("All pending requests are now complete");

            Ok::<_, anyhow::Error>(())
        });

        Listener { task, halt_token }
    }

    fn accept(
        &self,
        connection_pool: &mut JoinSet<Result<Nestls, ConnectionError>>,
    ) -> anyhow::Result<()> {
        let bridge_addr = format!(
            "{}:{}",
            &self.config.bridge_hostname, self.config.bridge_port
        );
        let ssl = Ssl::new(self.server_tls_config.context())?;
        let builder = Nestls::builder(
            self.client_tls_config
                .configure()?
                .into_ssl(&self.config.bridge_hostname)?,
            Role::Server,
        );
        connection_pool.spawn(builder.accept(bridge_addr, ssl));

        Ok(())
    }
}

#[instrument(skip_all, err, fields(session_id = conn.session_id().to_string(), client = conn.peer_common_name()))]
async fn handle(
    config: Arc<Config>,
    db: Pool<Sqlite>,
    mut conn: Nestls,
) -> Result<(), anyhow::Error> {
    let user = conn
        .peer_common_name()
        .ok_or(protocol::Error::MissingCommonName)?;
    let mut db_conn = db.acquire().await?;
    let user = db::User::get(&mut db_conn, &user).await?;
    tracing::info!(user.name, "User authenticated");
    drop(db_conn);

    let mut request_handler =
        handlers::Handler::new(config.clone(), user.clone(), conn.session_id()).await?;
    loop {
        let mut frame_buffer = [0_u8; std::mem::size_of::<protocol::Frame>()];
        conn.read_exact(&mut frame_buffer).await?;
        let frame = protocol::Frame::try_ref_from_bytes(&frame_buffer)
            .map_err(|e| protocol::Error::Framing(format!("Invalid frame: {e:?}")))?;
        if frame.is_empty() {
            tracing::info!("Connection sent empty frame indicating it is done; closing connection");
            break;
        } else {
            tracing::debug!(?frame, "New request frame received");
        }

        let json_size: usize = frame
            .json_size
            .get()
            .try_into()
            .context("frame size must fit in usize")?;
        // TODO: configurable size limits
        if json_size > MAX_JSON_SIZE {
            return Err(anyhow::anyhow!(
                "JSON payload larger than {MAX_JSON_SIZE} bytes"
            ));
        }
        let binary_size: usize = frame
            .binary_size
            .get()
            .try_into()
            .context("frame size must fit in usize")?;
        if binary_size > MAX_BINARY_SIZE {
            return Err(anyhow::anyhow!(
                "BINARY payload larger than {MAX_BINARY_SIZE} bytes"
            ));
        }
        let frame_size = json_size + binary_size;
        let mut request_buffer = BytesMut::with_capacity(frame_size).limit(frame_size);
        while request_buffer.remaining_mut() != 0 {
            conn.read_buf(&mut request_buffer).await?;
        }
        let mut request_bytes = request_buffer.into_inner().freeze();

        let binary_bytes = request_bytes.split_off(json_size);
        let request_value = serde_json::from_slice::<serde_json::Value>(&request_bytes)?;
        let outer_request =
            match serde_json::from_value::<protocol::json::OuterRequest>(request_value) {
                Ok(request) => request,
                Err(error) => {
                    tracing::error!(
                        ?error,
                        "Client request is valid JSON, but is not a supported request"
                    );
                    let request_value =
                        serde_json::from_slice::<serde_json::Value>(&request_bytes)?;
                    let json_response = protocol::json::OuterResponse {
                        session_id: conn.session_id(),
                        request_id: request_value
                            .get("request_id")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0),
                        response: protocol::json::Response::Unsupported,
                    };
                    let json_response = serde_json::to_string(&json_response)?;
                    let response_frame = protocol::Frame::new(json_response.len().try_into()?, 0);
                    conn.write_all(response_frame.as_bytes()).await?;
                    conn.write_all(json_response.as_bytes()).await?;
                    continue;
                }
            };

        let mut db_transaction = db.begin().await?;
        let response = match outer_request.request {
            Request::WhoAmI {} => request_handler.who_am_i(),
            Request::ListUsers {} => request_handler.list_users(&mut db_transaction).await,
            Request::ListKeys {} => request_handler.list_keys(&mut db_transaction).await,
            Request::Unlock { key, password } => request_handler.unlock(key, password).await,
            Request::GpgSign {
                key,
                signature_type,
            } => {
                request_handler
                    .pgp_sign(key, signature_type, binary_bytes)
                    .await
            }
            Request::Sign { key, digest } => request_handler.sign(&key, digest, binary_bytes).await,
            Request::SignPrehashed { key, digests } => {
                request_handler.sign_prehashed(&key, digests).await
            }
            Request::GetKey { key } => request_handler.public_key(&mut db_transaction, key).await,
        };

        match response {
            Ok(response) => {
                db_transaction.commit().await?;
                let json_response = protocol::json::OuterResponse {
                    session_id: outer_request.session_id,
                    request_id: outer_request.request_id,
                    response: response.json,
                };
                let json_response = serde_json::to_string(&json_response)?;
                let binary_size = response.binary.as_ref().map_or(0, |b| b.len());

                let response_frame =
                    protocol::Frame::new(json_response.len().try_into()?, binary_size.try_into()?);
                conn.write_all(response_frame.as_bytes()).await?;
                conn.write_all(json_response.as_bytes()).await?;
                if let Some(binary) = &response.binary {
                    conn.write_all(binary).await?;
                }
            }
            Err(reason) => {
                db_transaction.rollback().await?;
                let json_response = protocol::json::OuterResponse {
                    session_id: outer_request.session_id,
                    request_id: outer_request.request_id,
                    response: protocol::json::Response::Error { reason },
                };
                let json_response = serde_json::to_string(&json_response)?;
                let response_frame = protocol::Frame::new(json_response.len().try_into()?, 0);
                conn.write_all(response_frame.as_bytes()).await?;
                conn.write_all(json_response.as_bytes()).await?;
            }
        }
    }
    request_handler.shutdown().await?;
    conn.shutdown().await?;
    Ok(())
}

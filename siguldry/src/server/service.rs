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
    time::Instant,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{Instrument, Span, instrument};
use zerocopy::{IntoBytes, TryFromBytes};

use crate::{
    error::ConnectionError,
    nestls::Nestls,
    protocol::{self, Request, Role},
    server::{config::Config, db, handlers},
};

// The maximum request size; this should be configurable.
const MAX_JSON_SIZE: usize = 1024 * 32;

/// A server instance.
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
                        tracing::info!("New connection accepted");
                        while connection_pool.len() < self.config.connection_pool_size {
                            self.accept(&mut connection_pool)?;
                        }
                        let config = self.config.clone();
                        let db_pool = self.db_pool.clone();

                        // Each connection has an idle timeout, but in the event that something
                        // after the request hangs, this watchdog will kick in (by default) after 3
                        // hours, which is much longer than the client idle timeout and much longer
                        // than any request should ever take to process.
                        let timeout = Duration::from_secs(self.config.connection_watchdog_timeout.get());
                        request_tracker.spawn( async move {
                            let (watcher_tx, mut watcher_rx) = tokio::sync::watch::channel(Instant::now());
                            let handler = handle(config, watcher_tx, db_pool, conn);
                            tokio::pin!(handler);

                            let mut last_activity = Instant::now();
                            let sleep = tokio::time::sleep_until(last_activity + timeout);
                            tokio::pin!(sleep);
                            loop {
                                tokio::select! {
                                    result = &mut handler => {
                                        break result;
                                    }
                                    _ = watcher_rx.changed() => {
                                        last_activity = *watcher_rx.borrow_and_update();
                                        sleep.as_mut().reset(last_activity + timeout);
                                        tracing::trace!("Reset watchdog timeout");
                                    }
                                    _ = &mut sleep => {
                                        tracing::error!("BUG: Shutting down client connection that hasn't shut down as expected!");
                                        break Ok(());
                                    }
                                }
                            }
                        }.instrument(tracing::Span::current()));
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
            if !request_tracker.is_empty() {
                tracing::info!("Waiting for {} pending requests to complete", request_tracker.len());
            }
            request_tracker.wait().await;
            tracing::info!("All pending requests are now complete");

            Ok::<_, anyhow::Error>(())
        }.instrument(Span::current()));

        Listener { task, halt_token }
    }

    fn accept(
        &self,
        connection_pool: &mut JoinSet<Result<Nestls, ConnectionError>>,
    ) -> anyhow::Result<()> {
        let bridge_addr = format!(
            "{}:{}",
            self.config.bridge_hostname, self.config.bridge_port
        );
        let ssl = Ssl::new(self.server_tls_config.context())?;
        let builder = Nestls::builder(
            self.client_tls_config
                .configure()?
                .into_ssl(&self.config.bridge_hostname)?,
            Role::Server,
        );
        connection_pool.spawn(builder.accept(bridge_addr, ssl).instrument(Span::current()));

        Ok(())
    }
}

#[instrument(skip_all, err, fields(session_id = %conn.session_id(), user = conn.peer_common_name()))]
async fn handle(
    config: Arc<Config>,
    watchdog: tokio::sync::watch::Sender<Instant>,
    db: Pool<Sqlite>,
    mut conn: Nestls,
) -> Result<(), anyhow::Error> {
    let user = conn
        .peer_common_name()
        .ok_or(protocol::Error::MissingCommonName)?;
    let mut db_conn = db.acquire().await?;
    let user = db::User::get(&mut db_conn, &user)
        .await
        .with_context(|| format!("Failed to look up user '{user}"))?;
    tracing::info!("User authenticated");
    drop(db_conn);

    let idle_timeout = Duration::from_secs(config.idle_client_timeout.get());
    let mut request_handler =
        handlers::Handler::new(config.clone(), user.clone(), conn.session_id()).await?;
    loop {
        let request_bytes = match tokio::time::timeout(idle_timeout, read_frame(&mut conn)).await {
            Ok(frame) => {
                if let Some(bytes) = frame.context("Failed to read incoming request frame")? {
                    watchdog.send_replace(Instant::now());
                    bytes
                } else {
                    break;
                }
            }
            Err(_elapsed) => {
                tracing::warn!(
                    "Shutting down client connection that has been idle for {} seconds",
                    idle_timeout.as_secs()
                );
                let _ = request_handler.shutdown().await;
                let _ = tokio::time::timeout(Duration::from_secs(5), conn.shutdown()).await;
                return Ok(());
            }
        };

        let request_value = serde_json::from_slice::<serde_json::Value>(&request_bytes)?;
        let outer_request = match serde_json::from_value::<protocol::OuterRequest>(request_value) {
            Ok(request) => request,
            Err(error) => {
                tracing::error!(
                    ?error,
                    "Client request is valid JSON, but is not a supported request"
                );
                let request_value = serde_json::from_slice::<serde_json::Value>(&request_bytes)?;
                let json_response = protocol::OuterResponse {
                    session_id: conn.session_id(),
                    request_id: request_value
                        .get("request_id")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0),
                    response: protocol::Response::Unsupported,
                };
                let json_response = serde_json::to_string(&json_response)?;
                let response_frame = protocol::Frame::new(json_response.len().try_into()?);
                conn.write_all(response_frame.as_bytes()).await?;
                conn.write_all(json_response.as_bytes()).await?;
                continue;
            }
        };

        let response = match outer_request.request {
            Request::WhoAmI {} => request_handler.who_am_i(),
            Request::ListKeys {} => {
                let mut db_conn = db.acquire().await?;
                request_handler.list_keys(&mut db_conn, &user).await
            }
            Request::Unlock { key, password } => request_handler.unlock(key, password).await,
            Request::Sign {
                key,
                digest_algorithm,
                digest,
            } => request_handler.sign(&key, digest_algorithm, digest).await,
            Request::SignAll { key, digests } => request_handler.sign_all(&key, digests).await,
            Request::GetKey { key } => {
                let mut db_conn = db.acquire().await?;
                request_handler.public_key(&mut db_conn, key).await
            }
        };

        match response {
            Ok(response) => {
                let json_response = protocol::OuterResponse {
                    session_id: outer_request.session_id,
                    request_id: outer_request.request_id,
                    response,
                };
                let json_response = serde_json::to_string(&json_response)?;

                let response_frame = protocol::Frame::new(json_response.len().try_into()?);
                conn.write_all(response_frame.as_bytes()).await?;
                conn.write_all(json_response.as_bytes()).await?;
            }
            Err(reason) => {
                let json_response = protocol::OuterResponse {
                    session_id: outer_request.session_id,
                    request_id: outer_request.request_id,
                    response: protocol::Response::Error { reason },
                };
                let json_response = serde_json::to_string(&json_response)?;
                let response_frame = protocol::Frame::new(json_response.len().try_into()?);
                conn.write_all(response_frame.as_bytes()).await?;
                conn.write_all(json_response.as_bytes()).await?;
            }
        }
    }
    request_handler.shutdown().await?;

    // At this point the client shouldn't send it anything else, but we need to poll
    // the connection to gracefully shut down the TLS session.
    tokio::time::timeout(Duration::from_secs(15), async {
        tracing::debug!("Waiting for EOF from client");
        let mut buf = [0u8; 1024];
        while let Ok(n) = conn.read(&mut buf).await {
            if n == 0 {
                tracing::debug!("Client sent EOF");
                break;
            } else {
                tracing::warn!("Client unexpectedly sent us {} bytes of data", n);
            }
        }
        conn.shutdown()
            .await
            .context("Failed to shutdown connection to client")?;
        tracing::info!("Connection completed successfully");

        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("Timed out waiting for connection to close")??;

    Ok(())
}

async fn read_frame(conn: &mut Nestls) -> anyhow::Result<Option<bytes::Bytes>> {
    let mut frame_buffer = [0_u8; std::mem::size_of::<protocol::Frame>()];
    conn.read_exact(&mut frame_buffer).await?;
    let frame = protocol::Frame::try_ref_from_bytes(&frame_buffer)
        .map_err(|e| protocol::Error::Framing(format!("Invalid frame: {e:?}")))?;
    if frame.is_empty() {
        tracing::debug!("Connection sent empty frame indicating it is done; closing connection");
        return Ok(None);
    } else {
        tracing::debug!(?frame, "New request frame received");
    }

    let frame_size: usize = frame
        .json_size
        .get()
        .try_into()
        .context("frame size must fit in usize")?;
    // TODO: configurable size limits
    if frame_size > MAX_JSON_SIZE {
        return Err(anyhow::anyhow!(
            "JSON payload larger than {MAX_JSON_SIZE} bytes"
        ));
    }
    let mut request_buffer = BytesMut::with_capacity(frame_size).limit(frame_size);
    while request_buffer.remaining_mut() != 0 {
        conn.read_buf(&mut request_buffer).await?;
    }

    Ok(Some(request_buffer.into_inner().freeze()))
}

// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

/*!
# Siguldry

Siguldry is (currently) an experimental replacement for Fedora's software signing service,
[Sigul][1]. It is heavily inspired by Sigul, but includes a few protocol changes based on how
Sigul is currently used in Fedora, which is significantly different from how it was originally
envisioned when Sigul was designed.

The key differences are that unlike Sigul, all client-server communication happens in the nested TLS
session, and as such, it is no longer possible to mix traffic to the inner and outer TLS sessions:
after the protocol header is sent to the bridge, all traffic must be sent via the inner session.

In addition to the protocol level change, Siguldry also supports a slightly different set of
commands.

## Components

The service includes three components. The first part, the server, is responsible for keeping the
signing keys safe and for servicing client requests for signatures. The server is designed such
that the host firewall can drop all incoming traffic (assuming there's out-of-band management
available). It does this by connecting to the second component, the bridge.

The bridge is a proxy. It accepts connections from servers and clients, which are both
authenticated using mutual TLS certificates, and then ferries client and server traffic between the
two connections. This ensures only clients with valid TLS certificates can even initialize a
connection to the server.

The final component is the client which lets users request signatures from the server. It is
intended to be used in a larger application which handles content-specific details, like extracting
RPM package headers for signing.

Additionally, this crate provides a legacy [Sigul][1] client that is compatible with version
1.2+.

<div class="warning">This crate is still under active development and there will be several more
rounds API-breaking changes before a 1.0 release is made.</div>

## Crate features

By default, the server, bridge, and client for Siguldry along with their CLIs is built.

* **cli** -
  Include the experimental Siguldry CLIs. This is a default feature.

* **server** -
  Include the experimental Siguldry server APIs. This is a default feature.

* **sigul-client** -
  Include the client compatible with Sigul 1.2. This is not enabled by default.

[1]: https://pagure.io/sigul
*/

#[cfg(feature = "server")]
use tokio::signal::unix::{SignalKind, signal};
use tokio_util::sync::CancellationToken;

#[cfg(feature = "sigul-client")]
mod serdes;
#[cfg(feature = "sigul-client")]
pub mod v1;

pub mod bridge;
pub mod client;
pub mod config;
pub mod error;
mod ipc_common;
pub(crate) mod nestls;
pub mod protocol;
#[cfg(feature = "server")]
pub mod server;

/// Install and manage signal handlers for the process.
///
/// # SIGTERM and SIGINT
///
/// Sending SIGTERM or SIGINT to the process will cause it to stop accepting new
/// signing requests. Existing signing requests will be allowed to complete
/// before the process shuts down.
#[doc(hidden)]
#[cfg(feature = "server")]
pub async fn signal_handler(halt_token: CancellationToken) -> Result<(), anyhow::Error> {
    let mut sigterm_stream = signal(SignalKind::terminate()).inspect_err(|error| {
        tracing::error!(?error, "Failed to register a SIGTERM signal handler");
    })?;
    let mut sigint_stream = signal(SignalKind::interrupt()).inspect_err(|error| {
        tracing::error!(?error, "Failed to register a SIGINT signal handler");
    })?;

    loop {
        tokio::select! {
            _ = sigterm_stream.recv() => {
                tracing::info!("SIGTERM received, beginning service shutdown");
                halt_token.cancel();
            }
            _ = sigint_stream.recv() => {
                tracing::info!("SIGINT received, beginning service shutdown");
                halt_token.cancel();
            }
        }
    }
}

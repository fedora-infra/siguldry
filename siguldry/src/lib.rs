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

#[cfg(feature = "sigul-client")]
mod serdes;
#[cfg(feature = "sigul-client")]
pub mod v1;

pub mod bridge;
pub mod client;
pub mod config;
pub mod error;
pub(crate) mod nestls;
pub mod protocol;
#[cfg(feature = "server")]
pub mod server;

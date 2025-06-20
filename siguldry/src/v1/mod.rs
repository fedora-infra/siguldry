/*!
# v1

This crate provides a client for the [Sigul][1] service. In particular, it works with version
1.2.

The implementation includes a client with full support for Sigul server management commands as
well as signing PE applications. It does not contain support for signing RPMs or other artifacts
at this time.

[1]: https://pagure.io/sigul
*/

pub mod client;
mod connection;
pub mod error;
mod nestls;

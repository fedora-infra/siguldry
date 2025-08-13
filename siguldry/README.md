[![Crates.io][crates-badge]][crates-url]
[![Documentation][docs-badge]][docs-url]
[![MIT licensed][mit-badge]][mit-url]
[![Build Status][actions-badge]][actions-url]

[crates-badge]: https://img.shields.io/crates/v/siguldry.svg
[crates-url]: https://crates.io/crates/siguldry
[docs-badge]: https://docs.rs/siguldry/badge.svg
[docs-url]: https://docs.rs/siguldry
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: LICENSE
[actions-badge]: https://github.com/fedora-infra/siguldry/workflows/CI/badge.svg
[actions-url]:https://github.com/fedora-infra/siguldry/actions?query=workflow%3ACI

# Siguldry

A library for interacting with a [Sigul](https://pagure.io/sigul) server.

## siguldry-client

In addition to the client library, a command-line application that provides a subset of commands supported
by Sigul is also available. To build the CLI, enable the `siguldry-client` Cargo feature.

## siguldry-server

### Test dependencies

To run the test suite, you will need the `pkcs11-tool` (provided by the `opensc` package on Fedora) and `softhsm2-util` (provided by `softhsm` on Fedora) binaries.
